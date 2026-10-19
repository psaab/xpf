package dataplane

// #4960 binding test: a config that passes config-compile and fails a LATER
// dataplane phase must leave the host UNMUTATED.

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// errStopBeforeHostReconcile is a #5268-style tripwire (the idiom is
// documented at compiler_rxvlan_failclosed_5268_test.go): a sentinel returned
// by recordingDP.SetZoneConfig AFTER the probe has counted the call. It is
// what makes the control test below safe to run.
//
// compileZones cannot be driven to completion in a unit test. Its tail calls
// stripUnmanagedInterfaces (compiler_iface.go), which enumerates the REAL host
// via net.Interfaces() and, for every link that is not `lo`, not in this config
// and not daemon-owned, runs netlink.AddrDel then netlink.LinkSetDown -- and
// netlink.LinkDel outright for a bond. Measured, not inferred: an instrumented
// panic at compiler_iface.go, stripUnmanagedInterfaces fired on `eno2` through
// TestValidConfigStillReachesZoneCompile_4960 -> CompileConfig -> compileZones,
// with 50+ further links behind it. Unprivileged those netlink calls fail with
// EPERM; as ROOT the test black-holes the host's networking (#6894 r2 F1).
//
// programZoneMaps calls SetZoneConfig once per zone BEFORE iterating that
// zone's interfaces, so failing the FIRST call halts the compile after the
// probe has recorded "compileZones was entered" and before mapZoneInterface --
// therefore before ensureVLANSubInterface, reconcileInterfaceAddresses, the
// ethtool/procfs writes, and the stripUnmanagedInterfaces tail. That is
// strictly stronger than the euid+name skip it replaces, which guarded only
// the two fixture interface names while the hazard was every OTHER link on the
// host.
var errStopBeforeHostReconcile = errors.New(
	"recordingDP tripwire: compileZones was entered (SetZoneConfig reached)")

// recordingDP counts the dataplane calls that mark how far CompileConfig got.
// SetZoneConfig is the probe for host mutation: programZoneMaps calls it once
// per zone BEFORE it iterates that zone's interfaces, and mapZoneInterface --
// the only caller of ensureVLANSubInterface / reconcileInterfaceAddresses, the
// only destructive netlink in the whole compile -- runs inside that iteration.
// So zero SetZoneConfig calls proves compileZones never started, which proves
// no host mutation occurred; one call proves it started and then stopped on the
// tripwire.
//
// zoneConfigCalls is the counter that BINDS the tripwire, and saying so
// plainly is a correction: r2 claimed the two inner counters below "turn the
// safety property into a runtime assertion instead of a structural argument",
// and they do not (#6894 r3 F2). Measured by driving programZoneMaps directly
// with the tripwire neutralised -- which is safe, because
// stripUnmanagedInterfaces is in compileZones (compiler_iface.go, compileZones' stripUnmanagedInterfaces call), not in
// programZoneMaps:
//
//	WITH tripwire:    zoneConfigCalls=1 vlanIfaceInfoCall=0 ifaceSetupCalls=0
//	WITHOUT tripwire: zoneConfigCalls=2 vlanIfaceInfoCall=0 ifaceSetupCalls=0
//
// So zoneConfigCalls distinguishes and the inner two do not. What actually
// holds the control test together is `errors.Is(err, errStopBeforeHostReconcile)`
// -- the tripwire arrived at all -- plus `zoneConfigCalls == 1`, which pins
// that it halted on the FIRST zone rather than walking every zone.
//
// vlanIfaceInfoCall and ifaceSetupCalls are DEFENCE IN DEPTH. Each is reached
// only from inside mapZoneInterface (SetVlanIfaceInfo right after a successful
// ensureVLANSubInterface, SetZone/AddTxPort during the one-time per-phys host
// setup), and mapZoneInterface returns early at compiler_iface.go, mapZoneInterface's early return when
// cachedInterfaceByName misses -- which it always does here, because
// xpft4960a/xpft4960b exist on no host. They would therefore fire only if this
// fixture's interface names ever started resolving. Keep them, and do NOT
// "make them live" by switching to real interface names: that is precisely the
// r2 F1 host hazard, since a resolving name puts reconcileInterfaceAddresses on
// a real link.
type recordingDP struct {
	discardingDataPlane
	zoneConfigCalls   int
	vlanIfaceInfoCall int
	ifaceSetupCalls   int
}

// #7754: recordingDP presents as the REAL pass. Stated explicitly rather than
// inherited: it embeds discardingDataPlane, which carries
// `xpfValidationPass() -> true`, and Go embedding is transitive — so without
// this override every CompileConfig(&recordingDP{}, ...) in the package runs
// the real pass against a DataPlane the compiler believes is the discarded
// validation pre-pass.
//
// Measured before changing: adding this override moves NOTHING in the package
// (full `go test ./pkg/dataplane/` green, zero FAILs). The existing recordingDP
// tests assert on host mutation — SetZoneConfig call counts and the tripwire
// error — not on anything isValidationPass gates, so the fixture was simply
// mis-marked rather than depending on the wrong classification.
func (*recordingDP) xpfValidationPass() bool { return false }

func (r *recordingDP) SetZoneConfig(zoneID uint16, zc ZoneConfig) error {
	r.zoneConfigCalls++
	return errStopBeforeHostReconcile
}

func (r *recordingDP) SetVlanIfaceInfo(subIfindex, parentIfindex int, vlanID uint16) error {
	r.vlanIfaceInfoCall++
	return nil
}

// failLaterPhaseConfig is accepted by the pure pkg/config compiler (the one
// `commit check` runs) but hard-errors in a LATER dataplane phase. The zone
// carries a VLAN sub-interface so that, absent the pre-pass, compileZones would
// create a real VLAN device before the failure is reached.
//
// The failure is compileApplications': a security policy references an
// application name that does not resolve, which returns
// `application %q not found`. That is the class userspace/flow.go documents as
// hard-erroring and aborting the apply -- i.e. the live, reachable input.
func failLaterPhaseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"xpft4960a.50"}},
		"untrust": {Name: "untrust", Interfaces: []string{"xpft4960b.0"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpft4960a": {Name: "xpft4960a", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"192.0.2.1/24"}},
		}},
		"xpft4960b": {Name: "xpft4960b", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
		}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name: "p-bad-app",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"no-such-application-4960"},
					},
					Action: config.PolicyPermit,
				},
			},
		},
	}
	return cfg
}

// The property: no host mutation until every validated phase has passed.
func TestNoHostMutationWhenALaterPhaseFails_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := failLaterPhaseConfig()

	_, err := CompileConfig(dp, cfg, false)
	if err == nil {
		t.Fatal("expected the unresolvable application reference to fail the " +
			"compile — the fixture no longer exercises a later-phase failure")
	}
	// Checked BEFORE the error identity: on a revert the tripwire changes the
	// error text, so the identity assertion would fire first and bury the
	// finding that actually matters.
	assertNoHostMutation(t, dp)
	if !strings.Contains(err.Error(), "no-such-application-4960") {
		t.Fatalf("failed for the wrong reason, so this test would not bind the "+
			"property: %v", err)
	}
}

// assertNoHostMutation asserts that CompileConfig never entered compileZones.
// Zero SetZoneConfig calls is the proof (compileZones never started); the two
// inner counters are defence in depth, asserted alongside so a future change
// that makes the tripwire fire later still reports which half was reached.
// They do not distinguish the tripwire on today's fixture — see recordingDP.
func assertNoHostMutation(t *testing.T, dp *recordingDP) {
	t.Helper()
	if dp.zoneConfigCalls != 0 {
		t.Errorf("compileZones RAN before the failing phase was caught "+
			"(%d SetZoneConfig calls) — the host was mutated before a later "+
			"phase failed, which is #4960", dp.zoneConfigCalls)
	}
	if dp.vlanIfaceInfoCall != 0 {
		t.Errorf("a VLAN sub-interface was created before the failing phase was "+
			"caught (%d SetVlanIfaceInfo calls) — destructive netlink ran and "+
			"has no undo path (#4960)", dp.vlanIfaceInfoCall)
	}
	if dp.ifaceSetupCalls != 0 {
		t.Errorf("per-interface host setup RAN before the failing phase was "+
			"caught (%d SetZone/AddTxPort calls) — mapZoneInterface reconciles "+
			"addresses and writes ethtool/procfs from there (#4960)",
			dp.ifaceSetupCalls)
	}
}

// Control: a VALID config must still reach compileZones. Without this the test
// above is satisfied by a pre-pass that rejects everything, or by CompileConfig
// failing before it does any work at all.
//
// It reaches compileZones and stops there, on the SetZoneConfig tripwire; see
// errStopBeforeHostReconcile for why running the phase to completion is not an
// option. The control is still live: the tripwire is reachable only after
// validateBeforeMutate has passed the config, so a pre-pass that rejected good
// configs would surface a `validate ...` error here instead, and a phase
// reorder that moved compileZones ahead of the pre-pass would too.
func TestValidConfigStillReachesZoneCompile_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"} // now resolvable

	_, err := CompileConfig(dp, cfg, false)
	if !errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("a VALID config did not reach compileZones — the pre-pass is "+
			"rejecting good configs, or the phase order changed. want the "+
			"SetZoneConfig tripwire, got: %v", err)
	}
	// This is the counter that binds the tripwire: without it the compile
	// walks every zone and this reads 2 (measured -- see recordingDP).
	if dp.zoneConfigCalls != 1 {
		t.Errorf("want exactly 1 SetZoneConfig call (the tripwire fires on the "+
			"first zone), got %d", dp.zoneConfigCalls)
	}
	// Defence in depth, NOT the proof. Both counters read 0 with and without
	// the tripwire, because mapZoneInterface soft-skips this fixture's
	// interface names before reaching either of them (#6894 r3 F2). They fire
	// only if those names ever start resolving on the host running the test --
	// which is exactly when the r2 F1 hazard would come back.
	if dp.vlanIfaceInfoCall != 0 || dp.ifaceSetupCalls != 0 {
		t.Errorf("the tripwire did NOT halt before per-interface host work "+
			"(%d SetVlanIfaceInfo, %d SetZone/AddTxPort) — mapZoneInterface ran, "+
			"so compileZones' host-mutating tail is reachable from this unit "+
			"test and it would take a root host's interfaces DOWN (#6894 r2 F1)",
			dp.vlanIfaceInfoCall, dp.ifaceSetupCalls)
	}
}

// The pre-pass shim deliberately nil-panics on any method it does not
// override, so it cannot carry a CompileConfig run that enters compileZones.
// These stubs cover the rest of the compiler's dataplane surface for that
// purpose only.
//
// AddTxPort and SetZone are NOT inert here: both are reached only from inside
// mapZoneInterface, so they double as the "execution passed the tripwire"
// counter the control test asserts is zero — a defence-in-depth counter, not
// the one that binds the tripwire (see recordingDP, #6894 r3 F2).
func (r *recordingDP) AddTxPort(ifindex int) error { r.ifaceSetupCalls++; return nil }
func (r *recordingDP) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	r.ifaceSetupCalls++
	return nil
}
func (*recordingDP) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error { return nil }
func (*recordingDP) ClearMirrorConfigs() error                                         { return nil }
func (*recordingDP) SetIfaceFilter(key IfaceFilterKey, filterID uint32) error          { return nil }
func (*recordingDP) SetFilterConfig(filterID uint32, cfg FilterConfig) error           { return nil }
func (*recordingDP) SetFilterRule(index uint32, rule FilterRule) error                 { return nil }
func (*recordingDP) SetPolicerConfig(id uint32, cfg PolicerConfig) error               { return nil }
func (*recordingDP) BumpFIBGeneration() (uint32, error)                                { return 0, nil }
func (*recordingDP) DeleteStaleIfaceZone(written map[IfaceZoneKey]bool)                {}
func (*recordingDP) DeleteStaleVlanIface(written map[uint32]bool)                      {}
func (*recordingDP) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool)            {}
func (*recordingDP) ZeroStaleFilterConfigs(startID uint32)                             {}

// #6894 r1 F4 introduced a euid+name belt here (skipIfCouldMutateAHost): as
// root, skip if either FIXTURE interface name resolved to a live link, on the
// theory that mapZoneInterface would then reconfigure a real interface. It was
// removed in r2 because it was aimed at the wrong hazard and covered a
// vanishing slice of it. Once compileZones runs at all, its tail strips EVERY
// unmanaged link on the box, so the two fixture names were never the exposure
// -- the host's other 50 were. errStopBeforeHostReconcile replaces it: the
// tripwire halts before mapZoneInterface unconditionally, at any euid, for any
// host interface inventory, and the control test ASSERTS that it did.
//
// The fixture still deliberately uses names outside the vSRX scheme
// (config.LinuxIfName only maps "/"->"-", so "ge-0-0-0.50" would be
// byte-identical to a real interface on the standalone VM and on loss cluster
// node 0). That is now defence in depth rather than the only belt.

// #6894 r1 F1: a SECOND binding fixture, from a DIFFERENT phase. The
// application fixture pins exactly one row of the phase table; with only that
// test, ten of the eleven original rows could be deleted and the whole package
// suite stayed green. This one fails in compileNAT instead, so the two together
// bind opposite ends of the table.
func failLaterNATPhaseConfig() *config.Config {
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"} // app phase now clean
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r1", Match: config.NATMatch{SourceAddress: "10.0.0.0/8"},
					Then: config.NATThen{Type: config.NATSource, PoolName: "no-such-pool-4960"}},
			},
		},
	}
	return cfg
}

func TestNoHostMutationWhenNATPhaseFails_4960(t *testing.T) {
	dp := &recordingDP{}

	_, err := CompileConfig(dp, failLaterNATPhaseConfig(), false)
	if err == nil {
		t.Fatal("expected the unresolvable NAT pool to fail the compile")
	}
	assertNoHostMutation(t, dp)
	if !strings.Contains(err.Error(), "no-such-pool-4960") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
	// #15002: the same dangling pool is warn-and-skip on the
	// validation pass (the userspace builder ships the rule
	// pool_unusable=missing_pool), so the pre-pass alone must
	// accept this fixture — the rejection above is the REAL
	// pass's, reached only because CompileConfig runs it after
	// the pre-pass.
	if err := validateBeforeMutate(failLaterNATPhaseConfig()); err != nil {
		t.Fatalf("the #15002 validation pass must warn-and-skip a "+
			"dangling SNAT pool, got: %v", err)
	}
}

// #6894 r1 F1: assert over the TABLE ITSELF. The call site being bound proves
// the pre-pass RUNS; it says nothing about whether the table still covers what
// the doc comment claims. Deleting rows is invisible to every behavioural test
// that does not happen to exercise the deleted phase, so the coverage sentence
// is pinned here directly.
//
// SCOPE, because this test's claim was overstated at r1 (#6894 r2 F3): it
// asserts on got[i].name and NOTHING else, so it binds INDEX -> NAME. Replacing
// the BODY of a row with `func() error { return nil }`, leaving names and order
// intact, was measured to keep the whole package GREEN for ten of the thirteen
// rows. TestEachValidationPhaseRowRunsItsOwnCompiler_4960 below is what binds
// NAME -> BODY; neither test substitutes for the other.
func TestValidationPhaseTableMatchesDocumentedCoverage_4960(t *testing.T) {
	// #6894 r5 F5: "zone screen references" leads, because compileZones is
	// CompileConfig's first phase and validateZoneScreenReferences is the first
	// thing inside it. It used to sit eighth, which broke the property the whole
	// ordering exists for — and this list could not detect that, because it is a
	// hand-written copy compared against another hand-written list. Anyone
	// reordering here must check CompileConfig, not just make the two lists
	// agree again.
	want := []string{
		"zone screen references",
		"address book", "applications", "policies", "nat", "static nat",
		"nat64", "nptv6", "screen profiles",
		"default policy", "flow timeouts",
		"firewall filter protocols", "flow config",
	}
	got := validationPhases(discardingDataPlane{}, &config.Config{}, newValidationResult())

	if len(got) != len(want) {
		t.Fatalf("the pre-pass covers %d phases but the documented coverage is "+
			"%d — a row was added or removed without updating the doc comment "+
			"in compiler_validate_4960.go and this test (#6894 r1 F1)",
			len(got), len(want))
	}
	for i, w := range want {
		if got[i].name != w {
			t.Errorf("phase %d is %q, documented as %q — the table order must "+
				"match CompileConfig so a multi-phase failure reports the same "+
				"phase it would post-mutation", i, got[i].name, w)
		}
	}
}

// The pre-pass shim leaves the embedded DataPlane nil, so any method it does
// not override panics. Nothing enforces completeness at compile time, so this
// exercises the pre-pass over a config that reaches every covered phase: a
// newly-called dp method shows up as a panic here rather than in production.
//
// Reaching every PHASE is not the same as reaching every phase's WRITE
// SURFACE, and at r2 this test reached only 28 of the 40 overrides (#6894 r3
// F1). idProbeConfig carries a destination-NAT rule-set, static NAT v4 and v6,
// an NPTv6 rule, a NAT64 rule-set, an IPv6 source pool with its v6 SNAT rule,
// an interface-SNAT rule and a security policy so every covered phase is
// entered on every branch it has.
//
// #6420 deleted the eBPF NAT record construction, so the NAT setters are no
// longer CALLED by the compiler and their overrides here are defensive. The
// per-method counting leg that used to bind SetSNATEgressIP is replaced by
// TestNATCompilerCallsNoDataplaneNATWriter_6420, which drives the same rows
// against a dataplane that ERRORS from every NAT writer and requires a clean
// validate. That binds the ABSENCE of the calls, which a counter cannot: a
// counter can only observe a call that happens.
//
// The seeded-ifCache leg stays, and is load-bearing for that replacement: it
// is what makes compileNAT's interface-SNAT branch resolve its egress member
// instead of soft-skipping, so the branch is executed rather than
// short-circuited. Naming a REAL link instead would work on this host and is
// exactly what must not be done -- a fixture that resolves to a live interface
// is one CompileConfig call away from reconciling that interface's addresses
// (#6894 r2 F1).
func TestPrePassShimCoversTheCalledSurface_4960(t *testing.T) {
	cfg := idProbeConfig()

	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("rich config must validate clean: %v", err)
	}

	// The PLAIN shim with the egress interface resolvable: a method the
	// compiler calls but the shim does not override nil-panics here.
	if err := validateBeforeMutateWithResult(
		discardingDataPlane{}, cfg, seededEgressResult()); err != nil {
		t.Fatalf("rich config must validate clean with the egress interface "+
			"resolvable: %v", err)
	}
}

// seededEgressResult is a fresh pre-pass CompileResult whose interface cache
// already answers for idProbeConfig's egress-zone member, so compileNAT's
// interface-SNAT branch resolves it instead of soft-skipping. A fresh result
// per run: each pass writes into the one it is given.
func seededEgressResult() *CompileResult {
	result := newValidationResult()
	result.ifCache[idProbeEgressIface] = &net.Interface{
		Index: 4960, Name: idProbeEgressIface,
	}
	return result
}

// notAValidationDP is a DataPlane that reports FALSE for the pre-pass marker.
//
// It shadows the embedded shim's xpfValidationPass rather than being written
// from scratch, which is deliberate: inheriting all 40 no-op overrides means a
// pre-pass that wrongly accepted it would run to completion instead of
// nil-panicking part way, so removing the guard fails the assertions below
// rather than crashing the test. What it models is a caller handing
// validateBeforeMutateWith a REAL dataplane — the one input the marker exists
// to refuse, and the one a unit test cannot construct.
type notAValidationDP struct {
	discardingDataPlane
	writes int
}

func (*notAValidationDP) xpfValidationPass() bool { return false }

func (d *notAValidationDP) SetAddressBookEntry(cidr string, addressID uint32) error {
	d.writes++
	return nil
}

// #6894 r3 F4: "any dp passed here MUST embed discardingDataPlane" was a note
// in the doc comment with nothing enforcing it. The pre-pass compiles the
// config and throws the result away, so running it against a dataplane that
// actually writes would program the live tables from a discarded compile —
// the inverse of the property this whole file exists to establish.
func TestPrePassRejectsADataPlaneWithoutTheMarker_4960(t *testing.T) {
	dp := &notAValidationDP{}

	err := validateBeforeMutateWith(dp, idProbeConfig())
	if err == nil {
		t.Fatal("the pre-pass accepted a dataplane that does not carry the " +
			"discardingDataPlane marker — a real dataplane would have been " +
			"programmed from a compile whose result is discarded (#6894 r3 F4)")
	}
	if !strings.Contains(err.Error(), "does not carry the discardingDataPlane marker") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
	// The guard has to fire BEFORE the first phase, not merely somewhere: a
	// check placed after the phase loop would return this same error having
	// already written the whole address book.
	if dp.writes != 0 {
		t.Errorf("the pre-pass wrote %d address-book entries to a non-marker "+
			"dataplane before rejecting it — the guard must precede the phase "+
			"loop", dp.writes)
	}

	// Positive control: the real shim is still accepted, so the guard rejects
	// the marker's absence rather than everything.
	if err := validateBeforeMutate(idProbeConfig()); err != nil {
		t.Fatalf("the guard rejected the production shim: %v", err)
	}
}

// errPhaseBodyProbe is the sentinel failOneDP hands back from whichever single
// dataplane method a case names.
var errPhaseBodyProbe = errors.New("phase-body probe: this dp method was called")

// failOneDP fails EXACTLY ONE dataplane method and succeeds at everything else.
//
// It exists for the five rows that have no config-shaped hard error at all --
// nptv6, screen profiles, default policy, flow timeouts, flow config. Read
// their compilers: every bad input inside them is `slog.Warn(...); continue`
// (compileNPTv6 soft-skips an unparseable prefix, a length mismatch and a
// non-/48-or-/64 length alike), and the ONLY `return err` in each is the
// dataplane call. Handing that call a failure is therefore the sole way to make
// those rows produce an error, and without it they cannot be bound to their
// bodies by any config whatsoever.
//
// Each of the five methods below has exactly one caller in the compiler
// (verified by grep over pkg/dataplane), so the row a failure surfaces at is
// unambiguous.
type failOneDP struct {
	discardingDataPlane
	fail string
}

// #7754: failOneDP presents as the PRE-PASS, which is correct — it exists to
// probe the pre-pass's own phase bodies. Declared explicitly anyway, because an
// inherited classification is indistinguishable from an unconsidered one, and
// the census below requires every embedder to say which pass it is.
func (failOneDP) xpfValidationPass() bool { return true }

func (d failOneDP) errIf(method string) error {
	if d.fail == method {
		return errPhaseBodyProbe
	}
	return nil
}

func (d failOneDP) SetNPTv6Rule(NPTv6Key, NPTv6Value) error    { return d.errIf("SetNPTv6Rule") }
func (d failOneDP) SetScreenConfig(uint32, ScreenConfig) error { return d.errIf("SetScreenConfig") }
func (d failOneDP) SetDefaultPolicy(uint8) error               { return d.errIf("SetDefaultPolicy") }
func (d failOneDP) SetFlowTimeout(idx, seconds uint32) error   { return d.errIf("SetFlowTimeout") }
func (d failOneDP) SetFlowConfig(FlowConfigValue) error        { return d.errIf("SetFlowConfig") }

// emptyCfgWith returns a config that is empty except for what fn sets. Every
// phase is a no-op over an empty config, so a per-row fixture reaches its own
// row without tripping an earlier one.
func emptyCfgWith(fn func(*config.Config)) *config.Config {
	cfg := &config.Config{}
	fn(cfg)
	return cfg
}

// #6894 r2 F3: bind NAME -> BODY for every row.
//
// TestValidationPhaseTableMatchesDocumentedCoverage_4960 asserts only
// got[i].name, so it protects the LABEL. Measured at r2: replacing the BODY of
// the ten rows with no behavioural fixture with `func() error { return nil }`,
// names and order untouched, left the entire package GREEN — address book,
// policies, static nat, nat64, nptv6, screen profiles, default policy, flow
// timeouts, firewall filter protocols and flow config could all silently stop
// validating.
//
// Each case here drives the REAL pre-pass over an input the row's own compiler
// rejects and requires the error back prefixed `validate <that row's name>: `.
// A gutted body returns nil and reds; a body swapped with a sibling's surfaces
// under the sibling's name and reds on the prefix. The prefix comes from
// production (validateBeforeMutateWith), not from a reimplementation here, so
// the wrapping is bound too.
func TestEachValidationPhaseRowRunsItsOwnCompiler_4960(t *testing.T) {
	cases := []struct {
		phase string    // must equal the row's name in validationPhases
		dp    DataPlane // discardingDataPlane{} unless the row needs a dp failure
		cfg   *config.Config
		want  string // substring identifying the phase's OWN rejection
		// realPassOnly marks a row whose fault #15002 moved to
		// warn-and-skip on the validation pass: the pre-pass must
		// ACCEPT it, and the row stays bound by driving the real
		// pass (recordingDP) which must still reject it before
		// compileZones.
		realPassOnly bool
	}{
		{
			phase: "address book",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.AddressBook = &config.AddressBook{
					Addresses: map[string]*config.Address{},
					AddressSets: map[string]*config.AddressSet{
						"srv": {Name: "srv", Addresses: []string{"no-such-address-6894"}},
					},
				}
			}),
			want: "no-such-address-6894",
		},
		{
			phase: "applications",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.Policies = []*config.ZonePairPolicies{{
					FromZone: "trust", ToZone: "untrust",
					Policies: []*config.Policy{{
						Name:   "p",
						Match:  config.PolicyMatch{Applications: []string{"no-such-application-6894"}},
						Action: config.PolicyPermit,
					}},
				}}
			}),
			want: "no-such-application-6894",
		},
		{
			// #15002: an undefined policy zone is no longer a pre-pass
			// rejection — the tolerant path warns and the helper
			// rejects the snapshot whole (#9410). The row stays bound
			// through the REAL pass instead: recordingDP presents as
			// the real pass (#7754), so CompileConfig must still
			// reject before compileZones. Driven below, not through
			// validateBeforeMutateWith.
			phase: "policies",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.Policies = []*config.ZonePairPolicies{{
					FromZone: "no-such-zone-6894", ToZone: "untrust",
					Policies: []*config.Policy{{
						Name:   "p",
						Match:  config.PolicyMatch{Applications: []string{"any"}},
						Action: config.PolicyPermit,
					}},
				}}
			}),
			want:         "no-such-zone-6894",
			realPassOnly: true,
		},
		{
			phase: "nat",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.NAT.Source = []*config.NATRuleSet{{
					Name: "rs", FromZone: "no-such-nat-zone-6894", ToZone: "untrust",
					Rules: []*config.NATRule{{
						Name:  "r1",
						Match: config.NATMatch{SourceAddress: "10.0.0.0/8"},
						Then:  config.NATThen{Type: config.NATSource, Interface: true},
					}},
				}}
			}),
			want: "no-such-nat-zone-6894",
		},
		{
			// #15002: a mixed-family static rule warn-and-skips in
			// the pre-pass (the Rust table never matches it); the
			// row stays bound through the real pass below.
			phase: "static nat",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.NAT.Static = []*config.StaticNATRuleSet{{
					Name: "rs-static",
					Rules: []*config.StaticNATRule{{
						Name: "r-mixed-6894", Match: "192.0.2.50", Then: "2001:db8::1",
					}},
				}}
			}),
			want:         "r-mixed-6894",
			realPassOnly: true,
		},
		{
			// #15002: a non-/96 NAT64 prefix warn-and-skips in the
			// pre-pass (the Rust loader skips it, #3888); the row
			// stays bound through the real pass below.
			phase: "nat64",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.NAT.NAT64 = []*config.NAT64RuleSet{
					{Name: "rs64-6894", Prefix: "64:ff9b::/64"},
				}
			}),
			want:         "rs64-6894",
			realPassOnly: true,
		},
		{
			// #7268 rebound this row. It used to bind NAME->BODY by faulting a
			// DATAPLANE call (failOneDP{fail: "SetNPTv6Rule"}) on an otherwise
			// VALID rule, but compileNPTv6 no longer writes the eBPF
			// nptv6_rules surface, so there is no dataplane call left to fault
			// and that binding would have gone vacuous — the row would pass
			// whether or not the `nptv6` name still ran the nptv6 body.
			//
			// It now binds through the row's OWN error instead: a config-shaped
			// fault (a nptv6-prefix the helper refuses) that only compileNPTv6
			// can produce. compileStaticNAT skips IsNPTv6 rules, so no other row
			// can claim this config, which is what makes the attribution
			// discriminating. Same hard-error path
			// TestHelperRefusedNPTv6PrefixStillHardErrors_7077 exercises
			// (#6894 r9 / #7077). Named, not numbered (#6894 r8 F5).
			phase: "nptv6",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.NAT.Static = []*config.StaticNATRuleSet{{
					Name: "rs-npt",
					Rules: []*config.StaticNATRule{{
						Name: "npt", IsNPTv6: true,
						Match: "2001:db8:1::/48", Then: "not-a-prefix",
					}},
				}}
			}),
			want: "invalid nptv6-prefix",
		},
		{
			phase: "screen profiles",
			dp:    failOneDP{fail: "SetScreenConfig"},
			cfg: emptyCfgWith(func(c *config.Config) {
				// The pre-pass prelude assigns ScreenIDs, so the profile is
				// resolvable and compileScreenProfiles reaches SetScreenConfig.
				c.Security.Screen = map[string]*config.ScreenProfile{
					"sp-6894": {Name: "sp-6894"},
				}
			}),
			want: "set screen config sp-6894",
		},
		{
			// #6894 r5. Distinct from the row above on purpose: the profile SET
			// here is empty and VALID (compileScreenProfiles passes over it), and
			// what rejects is a ZONE naming a profile that does not exist. That
			// is the reference compileZones used to resolve mid-loop, after an
			// earlier zone had already mutated the host.
			phase: "zone screen references",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Security.Zones = map[string]*config.ZoneConfig{
					"trust": {Name: "trust", ScreenProfile: "no-such-screen-6894"},
				}
			}),
			want: "no-such-screen-6894",
		},
		{
			phase: "default policy",
			dp:    failOneDP{fail: "SetDefaultPolicy"},
			cfg:   emptyCfgWith(func(*config.Config) {}), // called unconditionally
			want:  "set default policy",
		},
		{
			phase: "flow timeouts",
			dp:    failOneDP{fail: "SetFlowTimeout"},
			cfg:   emptyCfgWith(func(*config.Config) {}), // called unconditionally
			want:  "set flow timeout",
		},
		{
			phase: "firewall filter protocols",
			dp:    discardingDataPlane{},
			cfg: emptyCfgWith(func(c *config.Config) {
				c.Firewall.FiltersInet = map[string]*config.FirewallFilter{
					"f": {Name: "f", Terms: []*config.FirewallFilterTerm{
						{Name: "t", Protocols: []string{"bogus-proto-6894"}},
					}},
				}
			}),
			want: "bogus-proto-6894",
		},
		{
			phase: "flow config",
			dp:    failOneDP{fail: "SetFlowConfig"},
			cfg:   emptyCfgWith(func(*config.Config) {}), // called unconditionally
			want:  errPhaseBodyProbe.Error(),             // compileFlowConfig returns the dp error unwrapped
		},
	}

	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			if tc.realPassOnly {
				// #15002: the pre-pass must ACCEPT this fault
				// (warn-and-skip), and the REAL pass must still
				// reject it before compileZones — that pair is
				// what binds the row's body now.
				if err := validateBeforeMutateWith(tc.dp, tc.cfg); err != nil {
					t.Fatalf("row %q: the #15002 validation pass must "+
						"warn-and-skip this fault, got: %v", tc.phase, err)
				}
				dp := &recordingDP{}
				_, err := CompileConfig(dp, tc.cfg, false)
				if err == nil {
					t.Fatalf("row %q accepted an input its own compiler "+
						"rejects on the real pass — the row's BODY no "+
						"longer validates anything (#6894 r2 F3, #15002)",
						tc.phase)
				}
				assertNoHostMutation(t, dp)
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("row %q real-pass rejection must contain %q, got: %v",
						tc.phase, tc.want, err)
				}
				return
			}
			err := validateBeforeMutateWith(tc.dp, tc.cfg)
			if err == nil {
				t.Fatalf("row %q accepted an input its own compiler rejects — "+
					"the row's BODY no longer validates anything (#6894 r2 F3)",
					tc.phase)
			}
			if prefix := "validate " + tc.phase + ": "; !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("row %q rejected under the wrong name: want prefix %q, "+
					"got %q — a row's name and body have come apart, or the row "+
					"moved behind a phase that now rejects first",
					tc.phase, prefix, err.Error())
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("row %q rejected for the wrong reason: want a message "+
					"containing %q, got %q — the fixture may no longer reach the "+
					"rejection it was written for", tc.phase, tc.want, err.Error())
			}
		})
	}

	// Completeness: a row added to validationPhases without a rejection case
	// here would otherwise be name-bound only, which is the gap this test
	// exists to close.
	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.phase] = true
	}
	for _, p := range validationPhases(discardingDataPlane{}, &config.Config{}, newValidationResult()) {
		if !covered[p.name] {
			t.Errorf("phase %q has no rejection case in this test, so its BODY "+
				"is unbound: it could be replaced with `func() error { return nil }` "+
				"and the suite would stay green (#6894 r2 F3)", p.name)
		}
	}
}

// #12224 F1: the all-value disabled-AppID catalog makes tolerant NAT list
// references visible to the production pre-pass. Pin the newly widened apply
// abort for both a dangling second DNAT app and a broken second SNAT set.
func TestTolerantNATApplicationListErrorsArePinned12224(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string
	}{
		{
			name: "dangling second DNAT app",
			cmds: []string{
				"set security zones security-zone untrust",
				"set security nat destination pool web1 address 10.0.30.100",
				"set security nat destination rule-set rs1 from zone untrust",
				"set security nat destination rule-set rs1 rule r1 match destination-address 50.0.0.1/32",
				"set security nat destination rule-set rs1 rule r1 match application [ junos-http no-such-app ]",
				"set security nat destination rule-set rs1 rule r1 then destination-nat pool web1",
			},
			want: []string{`application "no-such-app" not found`},
		},
		{
			name: "broken second SNAT set",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set applications application-set broken application ghost",
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
				"set security nat source rule-set rs1 rule r1 match application [ junos-http broken ]",
				"set security nat source rule-set rs1 rule r1 then source-nat interface",
			},
			want: []string{`expand application-set "broken"`, `member "ghost" not found`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, cmd := range tc.cmds {
				path, err := config.ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant config load rejected the fixture: %v", err)
			}

			err = validateBeforeMutate(cfg)
			if err == nil {
				t.Fatal("validateBeforeMutate accepted a later invalid NAT application-list value")
			}
			if !strings.HasPrefix(err.Error(), "validate applications: ") {
				t.Fatalf("pre-pass error = %q, want validate applications phase", err)
			}
			for _, fragment := range tc.want {
				if !strings.Contains(err.Error(), fragment) {
					t.Fatalf("pre-pass error = %q, want fragment %q", err, fragment)
				}
			}
		})
	}
}
