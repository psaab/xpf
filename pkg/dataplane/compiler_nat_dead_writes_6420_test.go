package dataplane

// #6420: the NAT compiler must not write eBPF NAT map records any more.
//
// compileNAT / compileStaticNAT / compileNAT64 used to build SNATValue,
// DNATValue, NATPoolConfig, SNATEgressValue, static-NAT and NAT64 records and
// hand them to the DataPlane. Every one of those writes landed nowhere: the
// only production compile path is Manager.CompileUserspaceShim, whose
// userspaceShimCompileDataplane implements each NAT setter and each stale-NAT
// deleter as a bare `return nil` (loader.go), and the AF_XDP helper receives
// NAT policy through the config snapshot instead. The construction was deleted;
// the identifiers it was fused with -- pool IDs, per-rule counter IDs, the
// implicit SNAT-match address IDs -- were kept.
//
// This binds the deletion from the side a counter cannot: a counter observes a
// call that HAPPENS, so it can only ever confirm the writes are still there.
// The tripwire below makes every NAT writer FAIL, then requires the compile to
// succeed. A reintroduced write does not merely get counted -- it propagates
// its error out of the phase and reds here, naming the method.

import (
	"errors"
	"fmt"
	"testing"
)

// errNATWriteTripwire is what every retired NAT writer returns. Any surviving
// call site propagates it: all of them were `if err := dp.SetX(...); err != nil
// { return fmt.Errorf(...) }`.
var errNATWriteTripwire = errors.New("retired eBPF NAT map writer was called (#6420)")

// natWriteTripwireDP is the pre-pass shim with every RETIRED NAT writer armed.
//
// #7268 armed SetNPTv6Rule / DeleteStaleNPTv6 too. They were held out of #6420
// because compileNPTv6 still wrote the legacy nptv6_rules surface, so arming
// them would have red on live code. That write is gone, and arming them here is
// what replaces the write-COUNT assertions the NPTv6 tests used to carry: a
// count can only observe a call that happens, so once the call is deleted a
// count-based guard is vacuous by construction rather than merely weaker. The
// tripwire inverts it — a restored write propagates its error out of the phase
// and reds, naming the method.
//
// GetPersistentNAT is likewise not armed: it is the one dataplane call in
// compiler_nat.go that is NOT a shim no-op on the live userspace path (the
// persistent-NAT table backs `show security nat source persistent-nat-table`),
// so it is part of the KEPT half.
type natWriteTripwireDP struct {
	discardingDataPlane
	validationPass bool
	calls          []string
}

// xpfValidationPass shadows the embedded discardingDataPlane marker so the same
// tripwire can drive both the #4960 pre-pass (marker true) and a real pass
// (marker false, i.e. the `!isValidationPass(dp)` branches taken).
func (d *natWriteTripwireDP) xpfValidationPass() bool { return d.validationPass }

func (d *natWriteTripwireDP) trip(method string) error {
	d.calls = append(d.calls, method)
	return fmt.Errorf("%s: %w", method, errNATWriteTripwire)
}

func (d *natWriteTripwireDP) record(method string) { d.calls = append(d.calls, method) }

func (d *natWriteTripwireDP) SetSNATRule(uint16, uint16, uint16, SNATValue) error {
	return d.trip("SetSNATRule")
}

func (d *natWriteTripwireDP) SetSNATRuleV6(uint16, uint16, uint16, SNATValueV6) error {
	return d.trip("SetSNATRuleV6")
}

func (d *natWriteTripwireDP) SetSNATEgressIP(SNATEgressKey, SNATEgressValue) error {
	return d.trip("SetSNATEgressIP")
}

func (d *natWriteTripwireDP) ClearSNATEgressIPs() error { return d.trip("ClearSNATEgressIPs") }

func (d *natWriteTripwireDP) SetNATPoolConfig(uint32, NATPoolConfig) error {
	return d.trip("SetNATPoolConfig")
}

func (d *natWriteTripwireDP) SetNATPoolIPV4(uint32, uint32, uint32) error {
	return d.trip("SetNATPoolIPV4")
}

func (d *natWriteTripwireDP) SetNATPoolIPV6(uint32, uint32, [16]byte) error {
	return d.trip("SetNATPoolIPV6")
}

func (d *natWriteTripwireDP) SetDNATEntry(DNATKey, DNATValue) error {
	return d.trip("SetDNATEntry")
}

func (d *natWriteTripwireDP) SetDNATEntryV6(DNATKeyV6, DNATValueV6) error {
	return d.trip("SetDNATEntryV6")
}

func (d *natWriteTripwireDP) SetStaticNATEntryV4(uint32, uint8, uint32) error {
	return d.trip("SetStaticNATEntryV4")
}

func (d *natWriteTripwireDP) SetStaticNATEntryV6([16]byte, uint8, [16]byte) error {
	return d.trip("SetStaticNATEntryV6")
}

func (d *natWriteTripwireDP) SetNAT64Config(uint32, NAT64Config) error {
	return d.trip("SetNAT64Config")
}

func (d *natWriteTripwireDP) SetNAT64Count(uint32) error { return d.trip("SetNAT64Count") }

// The stale-entry sweepers return nothing, so they cannot fail the compile.
// They are recorded instead: a reintroduced sweep is still a record the
// userspace runtime does not read, and `calls` is asserted EMPTY below.
func (d *natWriteTripwireDP) SetNPTv6Rule(NPTv6Key, NPTv6Value) error {
	return d.trip("SetNPTv6Rule")
}

func (d *natWriteTripwireDP) DeleteStaleNPTv6(map[NPTv6Key]bool) {
	d.record("DeleteStaleNPTv6")
}

func (d *natWriteTripwireDP) DeleteStaleSNATRules(map[SNATKey]bool) {
	d.record("DeleteStaleSNATRules")
}

func (d *natWriteTripwireDP) DeleteStaleSNATRulesV6(map[SNATKey]bool) {
	d.record("DeleteStaleSNATRulesV6")
}

func (d *natWriteTripwireDP) DeleteStaleDNATStatic(map[DNATKey]bool) {
	d.record("DeleteStaleDNATStatic")
}

func (d *natWriteTripwireDP) DeleteStaleDNATStaticV6(map[DNATKeyV6]bool) {
	d.record("DeleteStaleDNATStaticV6")
}

func (d *natWriteTripwireDP) DeleteStaleStaticNAT(map[StaticNATKeyV4]bool, map[StaticNATKeyV6]bool) {
	d.record("DeleteStaleStaticNAT")
}

// TestNATWriteTripwireIsArmed_6420 is the tripwire's own non-vacuity control.
// Without it, a tripwire whose overrides silently stopped shadowing the
// embedded shim (a signature drift promotes the call to discardingDataPlane's
// `return nil`) would make every assertion below pass for the wrong reason.
func TestNATWriteTripwireIsArmed_6420(t *testing.T) {
	dp := &natWriteTripwireDP{}
	if err := dp.SetSNATRule(1, 1, 0, SNATValue{}); !errors.Is(err, errNATWriteTripwire) {
		t.Fatalf("SetSNATRule on the tripwire = %v, want the tripwire error — the "+
			"override no longer shadows discardingDataPlane's no-op, so every "+
			"assertion in this file would pass vacuously", err)
	}
	dp.DeleteStaleSNATRules(nil)
	if len(dp.calls) != 2 {
		t.Fatalf("the tripwire recorded %v, want both the failing and the "+
			"recording arm", dp.calls)
	}
}

// TestNATCompilerCallsNoDataplaneNATWriter_6420 is the deletion's fail-on-revert
// guard.
//
// RED-on-revert: restore any `dp.SetSNATRule` / `dp.SetDNATEntry` /
// `dp.SetNATPoolConfig` / `dp.SetSNATEgressIP` / `dp.SetStaticNATEntryV4` /
// `dp.SetNAT64Config` (or their siblings) in compiler_nat.go and the row fails
// with `validate nat: ... SetSNATRule: retired eBPF NAT map writer was called`.
//
// Both marker arms are driven because `!isValidationPass(dp)` gates only the
// log records, not the writes: a write reintroduced inside a gated block would
// be invisible to the pre-pass arm alone.
func TestNATCompilerCallsNoDataplaneNATWriter_6420(t *testing.T) {
	for _, tc := range []struct {
		name           string
		validationPass bool
	}{
		{"pre-pass", true},
		{"real-pass", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// logProbeConfig is the richest NAT fixture in the package: pool-mode
			// SNAT (v4 and v6-only), interface-mode SNAT that resolves an egress
			// address AND one that resolves none, the no-NAT exemption branch, a
			// persistent-NAT pool, destination NAT v4 and v6, static NAT v4 and
			// v6, and a NAT64 rule-set whose source pool is auto-assigned.
			cfg := logProbeConfig()
			dp := &natWriteTripwireDP{validationPass: tc.validationPass}
			// seededEgressResult, not newValidationResult: compileNAT's
			// interface-SNAT branch resolves its egress member through
			// result.cachedInterfaceByName and soft-skips on a miss, so without
			// the seed that whole branch is never entered and the arm covering
			// its retired writes would be vacuous (#6894 r3 F1 uses the same
			// seed for the same reason).
			result := seededEgressResult()

			if tc.validationPass {
				// Drive the PRODUCTION pre-pass entry point so the wrapping is
				// bound too, not just the row bodies.
				if err := validateBeforeMutateWithResult(dp, cfg, result); err != nil {
					t.Fatalf("the NAT compiler still calls a retired eBPF NAT map "+
						"writer — the #6420 deletion was reverted, and the record "+
						"it builds is discarded by userspaceShimCompileDataplane on "+
						"every production apply: %v", err)
				}
			} else {
				// validateBeforeMutateWithResult refuses an unmarked dp by
				// design, so the real-pass arm drives the same rows directly.
				assignZoneIDs(result, cfg)
				assignScreenIDs(result, cfg)
				for _, phase := range validationPhases(dp, cfg, result) {
					if err := phase.run(); err != nil {
						t.Fatalf("row %q: the NAT compiler still calls a retired "+
							"eBPF NAT map writer on the real pass — the #6420 "+
							"deletion was reverted inside an `!isValidationPass(dp)` "+
							"block, which the pre-pass arm cannot see: %v",
							phase.name, err)
					}
				}
			}

			if len(dp.calls) != 0 {
				t.Errorf("the NAT compiler called %v — every one of these is a "+
					"`return nil` on the only production compile path "+
					"(userspaceShimCompileDataplane, loader.go), so the record it "+
					"is handed is built and dropped (#6420)", dp.calls)
			}

			// NON-VACUITY, and the KEPT half in one assertion set. A compile that
			// never entered the NAT phases would satisfy the check above for the
			// wrong reason, and these are exactly the values the deletion had to
			// preserve: each escapes compileNAT and is read by an operator
			// surface or a later phase.
			//
			//   PoolIDs        -> ApplyResult -> `show security nat source pool`,
			//                     the REST/gRPC pool views, the pool metrics; and
			//                     pool-nat64 proves compileNAT64's auto-assign
			//                     branch ran off result.NextPoolID.
			//   NATCounterIDs  -> the userspace config snapshot's per-rule
			//                     translation hit counter IDs, read back by every
			//                     operator NAT surface. Both SNAT and static-NAT
			//                     keys, i.e. compileNAT AND compileStaticNAT.
			//   AddrIDs        -> resolveSNATMatchAddr's implicit address-book
			//                     entry for an SNAT match CIDR.
			for _, want := range []string{"pool-a", "pool-b", "pool-v6", "pool-nat64"} {
				if _, ok := result.PoolIDs[want]; !ok {
					t.Errorf("NAT pool %q is absent from result.PoolIDs — either the "+
						"fixture stopped reaching the NAT phases (making the "+
						"tripwire assertion above vacuous) or the deletion took the "+
						"pool numbering with it", want)
				}
			}
			for _, want := range []string{
				NATCounterKey(NATCounterTypeSource, "rs-trust-untrust", "r-web"),
				NATCounterKey(NATCounterTypeDest, "rs-dnat", "d-v4"),
				NATCounterKey(NATCounterTypeStatic, "rs-static", "s-v4"),
			} {
				if id, ok := result.NATCounterIDs[want]; !ok || id == 0 {
					t.Errorf("NAT counter key %q resolved to (%d, %v) — the per-rule "+
						"translation hit counter ID the userspace snapshot is stamped "+
						"with is part of the KEPT half of #6420", want, id, ok)
				}
			}
			if _, ok := result.AddrIDs["_snat_match_10.1.0.0/16"]; !ok {
				t.Error("the implicit \"_snat_match_10.1.0.0/16\" address-book entry " +
					"is absent — resolveSNATMatchAddr's contribution to " +
					"result.AddrIDs is part of the KEPT half of #6420")
			}
		})
	}
}
