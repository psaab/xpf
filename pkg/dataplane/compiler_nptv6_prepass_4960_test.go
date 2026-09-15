package dataplane

// #6894 r9 F1 / #4960: the pre-pass must not ACCEPT a config the enforcement
// plane REJECTS after the mutation point.
//
// The pre-pass's whole claim is "a config destined to fail the apply is
// rejected before any partial mutation lands". NPTv6 was a live counterexample
// and it is the sharpest possible one, because `nptv6` is an explicit row in
// `validationPhases` -- so the file's downstream-failure carve-out (which names
// preflightCheckIfindexCaps, attachUserspaceShimXDP and the snapshot builders)
// did not cover it. The row ran, passed, and the apply failed anyway:
//
//	Match = "2001:db8:9::/48"
//	Then  = "not-a-prefix"
//
//	pkg/config lenient validation   -> RETAINS with a warning (#1960 no-brick)
//	pkg/dataplane compileNPTv6      -> warned, `continue`d, returned nil
//	userspace buildNptv6Snapshots   -> copied both strings through verbatim
//	Rust Nptv6State::try_from_snapshots -> rejects the WHOLE snapshot
//	publishSnapshotFailClosedLocked -> error, AFTER compileZones mutated the
//	                                   host, with no rollback
//
// The exact strings above are the ones userspace-dp/src/nptv6_tests.rs already
// drives through `try_from_snapshots` (rule "bad-parse"), so the far end of the
// chain is bound in the Rust suite rather than asserted here.

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nptv6ProbeConfig is failLaterPhaseConfig with its application reference made
// resolvable -- so the `applications` row, which sits FIVE rows ahead of
// `nptv6`, cannot be what fails -- plus one NPTv6 rule carrying the prefixes
// under test.
//
// The zone still carries a VLAN sub-interface, which is what makes the
// host-mutation assertion meaningful: absent an early rejection, compileZones
// would create a real VLAN device before the NPTv6 fault is reached.
func nptv6ProbeConfig(match, then string) *config.Config {
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-npt-4960", FromZone: "untrust",
			Rules: []*config.StaticNATRule{
				{Name: "r-npt-4960", IsNPTv6: true, Match: match, Then: then},
			},
		},
	}
	return cfg
}

// assertRejectedByTheNPTv6Row asserts CompileConfig failed on the pre-pass's
// nptv6 row with nothing mutated.
//
// Order matters and is the same ordering TestNoHostMutationWhenALaterPhaseFails
// uses for the same reason: on a revert of the production change the compile
// still returns an error (the recordingDP tripwire), so an error-TEXT assertion
// placed first would fire and bury the finding that actually matters -- that
// compileZones ran.
func assertRejectedByTheNPTv6Row(t *testing.T, dp *recordingDP, err error, wantReason string) {
	t.Helper()
	if err == nil {
		t.Fatal("CompileConfig accepted an NPTv6 rule the userspace helper " +
			"rejects — the fixture no longer reaches compileNPTv6 at all")
	}
	assertNoHostMutation(t, dp)
	if errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("the compile reached compileZones and stopped on the tripwire "+
			"instead of being rejected by the pre-pass: %v", err)
	}
	// `validate nptv6: ` is the prefix validateBeforeMutateWithResult wraps a
	// failing row in. Pinning the ROW NAME, not merely "an error mentioning
	// nptv6", is what distinguishes a pre-pass rejection from the real pass's
	// post-mutation one — the real pass's error carries no `validate ` prefix.
	if !strings.HasPrefix(err.Error(), "validate nptv6: ") {
		t.Errorf("want the failure attributed to the pre-pass's `nptv6` row "+
			"(prefix %q), got: %v", "validate nptv6: ", err)
	}
	if !strings.Contains(err.Error(), wantReason) {
		t.Errorf("want the error to name the reason %q so an operator can fix "+
			"the rule, got: %v", wantReason, err)
	}
	if !strings.Contains(err.Error(), "r-npt-4960") {
		t.Errorf("want the error to name the offending rule, got: %v", err)
	}
}

// TestNPTv6UnparseablePrefixRejectedBeforeHostMutation_4960 is the
// fail-on-revert guard: Codex's exact counterexample.
//
// RED-on-revert: restore compileNPTv6's `slog.Warn(...); continue` for the
// unparseable-prefix branch and this fails inside assertNoHostMutation with
// "compileZones RAN before the failing phase was caught (1 SetZoneConfig
// calls)" — an ASSERTION, not a build break: the revert removes no symbol this
// file names.
func TestNPTv6UnparseablePrefixRejectedBeforeHostMutation_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6ProbeConfig("2001:db8:9::/48", "not-a-prefix")

	_, err := CompileConfig(dp, cfg, false)
	assertRejectedByTheNPTv6Row(t, dp, err, "invalid nptv6-prefix")
}

// TestNPTv6HostBitsRejectedBeforeHostMutation_4960 covers the same divergence
// one string away.
//
// Go's compileNPTv6 truncates to the prefix BYTES, which silently masks host
// bits; the helper's parse_prefix fails CLOSED on them (#4519) precisely so the
// masked, WIDER prefix is never installed. Without the host-bits check the
// unparseable-prefix fix would close the class Codex demonstrated and leave an
// identically-shaped one open.
//
// "2001:db8:0:2::/48" is the internal prefix userspace-dp's
// host_bits_snapshot_rejected_fail_closed drives through try_from_snapshots as
// rule "host-bits-internal", so the far end is bound over there.
func TestNPTv6HostBitsRejectedBeforeHostMutation_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6ProbeConfig("2602:fd41:70::/48", "2001:db8:0:2::/48")

	_, err := CompileConfig(dp, cfg, false)
	assertRejectedByTheNPTv6Row(t, dp, err, "host bits set beyond the prefix length")
}

// TestNPTv6MismatchedPrefixLengthsRejectedBeforeHostMutation_4960 covers the
// third member of the class: try_from_snapshots rejects `iwords != ewords`
// after both prefixes parse individually, so a compiler that validated only
// "does it parse" would still hand the helper a rule it refuses.
func TestNPTv6MismatchedPrefixLengthsRejectedBeforeHostMutation_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6ProbeConfig("2001:db8:9:2::/64", "fd00:9::/48")

	_, err := CompileConfig(dp, cfg, false)
	assertRejectedByTheNPTv6Row(t, dp, err, "prefix lengths must match")
}

// ---------------------------------------------------------------------------
// OVER-REACH GUARDS. Both stay GREEN under the revert above; each fails only if
// the rejection is WIDER than the set the helper actually refuses.
// ---------------------------------------------------------------------------

// TestNPTv6ScopeExcludedRuleWithBadPrefixStillCompiles_4960 is the guard that
// makes the fix safe rather than merely present.
//
// `buildNptv6Snapshots` DROPS a rule carrying an unsupported match scope
// (#5818) -- it never reaches the helper, and today's apply SUCCEEDS with the
// rule simply not installed. Hard-erroring on it would therefore fail an apply
// that works, on the tolerant load / peer-sync path that #1960 exists to keep
// working. So the SAME malformed prefix that reds the three tests above must be
// a warn-and-skip here.
//
// This is the arm that distinguishes `config.NPTv6ScopeUnsupported(rs, rule)`
// from `true`: delete the `installed` gate in compileNPTv6 and this test reds
// while every test above stays green.
func TestNPTv6ScopeExcludedRuleWithBadPrefixStillCompiles_4960(t *testing.T) {
	// One case per dimension the snapshot builder excludes on. A single case
	// would bind one field and leave the other four able to drift.
	for _, tc := range []struct {
		name  string
		scope func(*config.StaticNATRuleSet, *config.StaticNATRule)
	}{
		{"from-interface", func(rs *config.StaticNATRuleSet, _ *config.StaticNATRule) {
			rs.FromInterface = "xpft4960b.0"
		}},
		{"from-routing-instance", func(rs *config.StaticNATRuleSet, _ *config.StaticNATRule) {
			rs.FromRoutingInstance = "vrf-4960"
		}},
		{"source-addresses", func(_ *config.StaticNATRuleSet, r *config.StaticNATRule) {
			r.SourceAddresses = []string{"2001:db8:c::/64"}
		}},
		{"source-address", func(_ *config.StaticNATRuleSet, r *config.StaticNATRule) {
			r.SourceAddress = "2001:db8:c::/64"
		}},
		{"match-destination-port", func(_ *config.StaticNATRuleSet, r *config.StaticNATRule) {
			r.MatchDestinationPort = 8080
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := &recordingDP{}
			cfg := nptv6ProbeConfig("2001:db8:9::/48", "not-a-prefix")
			tc.scope(cfg.Security.NAT.Static[0], cfg.Security.NAT.Static[0].Rules[0])

			_, err := CompileConfig(dp, cfg, false)
			if !errors.Is(err, errStopBeforeHostReconcile) {
				t.Fatalf("an NPTv6 rule the snapshot builder EXCLUDES (%s) was "+
					"rejected by the compiler. That rule never reaches "+
					"Nptv6State::try_from_snapshots, so today's apply succeeds "+
					"with it simply not installed — failing the compile turns a "+
					"working tolerant-load / peer-sync config into a failed apply "+
					"(#5818 / #1960). Gate the hard error on "+
					"config.NPTv6ScopeUnsupported.\n  got: %v", tc.name, err)
			}
		})
	}
}

// TestValidNPTv6RuleStillReachesZoneCompile_4960 is the non-vacuity control for
// all three rejection tests: without it they are satisfied by a compiler that
// rejects every config carrying an NPTv6 rule at all.
//
// Both prefixes are /48, equal length, and host-bits clean — the shape
// try_from_snapshots accepts.
func TestValidNPTv6RuleStillReachesZoneCompile_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6ProbeConfig("2001:db8:48::/48", "fd00:48::/48")

	_, err := CompileConfig(dp, cfg, false)
	if !errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("a VALID NPTv6 rule no longer reaches compileZones — the "+
			"rejection is wider than the set the helper refuses, so ordinary "+
			"NPTv6 configs would stop applying. want the SetZoneConfig tripwire, "+
			"got: %v", err)
	}
	if dp.zoneConfigCalls != 1 {
		t.Errorf("want exactly 1 SetZoneConfig call (the tripwire fires on the "+
			"first zone), got %d", dp.zoneConfigCalls)
	}
}

// TestNPTv6ScopeUnsupportedNilArgsReportExcluded_4960 pins the ONE branch of
// config.NPTv6ScopeUnsupported that the behavioural tests above cannot reach.
//
// The five real dimensions are bound behaviourally, through the compiler, by
// TestNPTv6ScopeExcludedRuleWithBadPrefixStillCompiles_4960 -- restating them
// as a hand-written truth table here would compare two artifacts written in the
// same round and could only catch a typo. The AGREEMENT that matters, between
// this predicate and the snapshot builder that actually drops the rule, is
// derived by running the real builder in
// pkg/dataplane/userspace.TestNptv6BuilderDropSetMatchesScopePredicate_4960
// (that package can import both; this one cannot import it -- userspace imports
// dataplane).
//
// Both compile-path callers skip nils before asking, so this arm is unreachable
// from production. Assert it anyway: "excluded" is the only direction that
// cannot turn a working config into a failed apply, and a future caller could
// rely on it.
func TestNPTv6ScopeUnsupportedNilArgsReportExcluded_4960(t *testing.T) {
	if !config.NPTv6ScopeUnsupported(nil, &config.StaticNATRule{}) ||
		!config.NPTv6ScopeUnsupported(&config.StaticNATRuleSet{}, nil) {
		t.Error("a nil rule-set or rule must report EXCLUDED — reporting " +
			"INCLUDED would let compileNPTv6 hard-error on a shape it cannot " +
			"inspect")
	}
}

// TestNPTv6UnknownLeavesExcludedRuleWithBadPrefixStillCompiles_9877 is the
// #9877 twin of the scope-exclusion guard above: buildNptv6Snapshots DROPS a
// rule carrying unknown match leaves, so it never reaches the helper and a
// malformed prefix on it must be warn-and-skip — not a whole-apply hard
// error. RED-on-revert: drop the StaticNATRuleExcludedReason consult in
// compileNPTv6 and the pre-pass rejects with "invalid nptv6-prefix" instead
// of reaching the tripwire.
func TestNPTv6UnknownLeavesExcludedRuleWithBadPrefixStillCompiles_9877(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6ProbeConfig("2001:db8:9::/48", "not-a-prefix")
	cfg.Security.NAT.Static[0].Rules[0].UnknownMatchLeaves = []string{"soruce-address"}

	_, err := CompileConfig(dp, cfg, false)
	if !errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("an NPTv6 rule the snapshot builder EXCLUDES (unknown match "+
			"leaves) was rejected by the compiler. That rule never reaches "+
			"Nptv6State::try_from_snapshots, so today's apply succeeds "+
			"with it simply not installed — failing the compile turns a "+
			"working tolerant-load / peer-sync config into a failed apply "+
			"(#9877 / #1960). Gate the hard error on "+
			"config.StaticNATRuleExcludedReason.\n  got: %v", err)
	}
}
