package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

// #5789: hostInboundEnforced=true only proves SOME protecting table loaded at
// SOME earlier generation — NOT that the retained (atomic-untouched) generation
// covers the CURRENT desired destination set. When a new local address appears
// and the next real render fails, the retained generation has no deny for it, so
// the day-2 retention branch (which skips the cold-boot fence on the enforced=true
// premise) leaves the new address FAIL-OPEN. The fix tracks the covered
// destination set and, on a failed rerender with uncovered destinations, installs
// an ADDITIVE xpf_hostinbound_gap fence (a separate input-hook table) that denies
// only the uncovered addresses WITHOUT replacing the retained table. These are the
// fail-on-revert proofs; the nft-apply seam (nftApplyPayload) is the same
// package-level fake the #5644 cold-boot tests use, and realHostInboundPayload /
// hostInboundTestConfig are defined in host_inbound_coldboot_fence_5644_test.go /
// host_inbound_nft_test.go.

// TestHostInboundCoverageGapFencesNewAddressAfterFailedRerender_5789 is the
// primary fail-on-revert proof AND the "distinguish coverage from mere table
// existence" crux (issue path 1): an enforceable config installs a real table
// (enforced=true, covered={old addrs}); the zone then GAINS a new address and the
// real rerender FAILS. hostInboundEnforced is still true (the table exists), but
// its coverage is STALE — so an additive gap fence must deny the NEW address
// without touching the retained table. Reverting the day-2 coverage-gap branch
// leaves the new address fail-open (no gap payload) → RED.
func TestHostInboundCoverageGapFencesNewAddressAfterFailedRerender_5789(t *testing.T) {
	orig := nftInstaller
	defer func() { nftInstaller = orig }()

	// Step 1: enforceable config with wan addrs 172.16.50.8 / 2001:db8:50::8 —
	// real install succeeds → coverage recorded.
	nftInstaller = &fakeNftInstaller{} // all succeed
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("step 1 (install): %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: hostInboundEnforced must be true after a successful real install")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "172.16.50.8")]; !ok {
		t.Fatalf("step 1: covered set must include 172.16.50.8, got %v", d.hostInboundCoveredAddrs)
	}

	// Step 2: the wan zone GAINS a new v4 address; the real rerender FAILS.
	cfg2 := hostInboundTestConfig()
	cfg2.Interfaces.Interfaces["reth0"].Units[50].Addresses = []string{
		"172.16.50.8/24", "172.16.50.9/24", "2001:db8:50::8/64",
	}
	injected := errors.New("nftables: rerender failed")
	var realCalls, gapCalls int
	var gapSpec xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { realCalls++; return injected }, // real ruleset fails
		gapFence:    func(spec xnft.GapFenceSpec) error { gapCalls++; gapSpec = spec; return nil },
	}

	err := d.applyHostInboundFilter(cfg2)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 2: the failed rerender must surface the netlink error, got %v", err)
	}
	// CRUX: the table still exists (enforced=true) but coverage was stale.
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 2: hostInboundEnforced must remain true (the retained real table is untouched)")
	}
	if gapCalls != 1 {
		t.Fatalf("step 2 (#5789 FAIL-OPEN): a new address appeared and the rerender failed, but no "+
			"additive gap fence was installed — the stale-coverage-but-enforced case took the day-2 "+
			"retention branch and left 172.16.50.9 fail-open (gap installs=%d)", gapCalls)
	}
	if !sliceContains(gapSpec.RetainedV4, "172.16.50.8") || !sliceContains(gapSpec.RetainedV6, "2001:db8:50::8") {
		t.Errorf("gap backstop must preserve valid retained addresses by family: v4=%v v6=%v", gapSpec.RetainedV4, gapSpec.RetainedV6)
	}
	// The gap denies the NEW address...
	if !sliceContains(gapSpec.UncoveredV4, "172.16.50.9") {
		t.Errorf("gap fence must deny the newly-appeared address 172.16.50.9:\n%+v", gapSpec)
	}
	// ...WITHOUT re-fencing the already-covered address (the retained table still
	// serves 172.16.50.8's accepts — not weakened). A GapFenceSpec structurally
	// carries no service accept.
	if sliceContains(gapSpec.UncoveredV4, "172.16.50.8") {
		t.Errorf("gap fence must NOT re-fence the already-covered 172.16.50.8 (retained table serves it):\n%+v", gapSpec)
	}
	// Coverage is unchanged: the retained real generation still covers only its
	// original set; the gap-only address is NOT recorded as real-covered.
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "172.16.50.9")]; ok {
		t.Error("covered set must NOT include the gap-only address 172.16.50.9 (retained real table does not cover it)")
	}
	if realCalls != 1 {
		t.Errorf("step 2: expected exactly one real install attempt, got %d", realCalls)
	}
}

// TestVRFLeaseWindowBoundedByGapAfterFailedRerender10751 is the #10751
// BLOCKING-5 VRF-lease-window bound. VRF-enslaved unzoned DHCP units are
// SKIPPED by the unleased backstop (their LOCAL_IN identity is the shared
// master, where an iifname DROP would shadow addressed siblings), so their
// only convergence is the lease-callback recompile installing destination
// DROPs (the predicate half is pinned by
// TestDHCPLeaseChangeRequiresRecompile_VRFEnslavedNonLifeline10751). This
// cell pins the failure half: when that recompile's real transaction FAILS
// (injected), the SAME apply must install the additive gap DROP for the
// VRF lease with no new event — the window stays bounded by the apply
// instead of stretching to the next trigger. The distinct double-failure
// case (gap install also fails) is now retried by the scoped #11497 owner;
// see TestDoubleNftFailAutoConverges11497.
func TestVRFLeaseWindowBoundedByGapAfterFailedRerender10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "data", Interfaces: []string{"ge-0/0/9.0"}}}

	// Step 1: sibling zoned+addressed (enforcement on), VRF unit unleased.
	var specs []xnft.HostInboundSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error { specs = append(specs, spec); return nil },
	}
	uni := int(netlink.SCOPE_UNIVERSE)
	sib := scriptedSnap10751("ge-0/0/0.0", "trust", scriptedAddr10751("inet", "10.0.0.1/24", uni))
	vrfDown := scriptedSnap10751("ge-0/0/9.0", "")
	vrfDown.RoutingInstance = "data"
	s1 := []dpuserspace.InterfaceSnapshot{sib, vrfDown}
	scriptSnapshotTransition10751(t, s1, s1)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("step 1 (install): %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: hostInboundEnforced must be true after a successful real install")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "10.0.0.1")]; !ok {
		t.Fatalf("step 1: covered set must include 10.0.0.1, got %v", d.hostInboundCoveredAddrs)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("step 1: first apply must hand off (step 2 runs day-2, with no barrier standing behind the gap)")
	}
	if len(specs) != 1 {
		t.Fatalf("step 1: real specs = %d, want 1", len(specs))
	}
	// No backstop covers the VRF unit: the exclusion premise this bound
	// relies on. (An unenslaved unzoned DHCP unit WOULD appear here —
	// R7-B pins that positive — so this assert fails if VRF disengages.)
	for _, a := range specs[0].UnleasedV4 {
		if a == "ge-0-0-9" {
			t.Fatalf("step 1: VRF-enslaved ge-0/0/9.0 must be skipped by the unleased backstop, got %v", specs[0].UnleasedV4)
		}
	}
	for _, a := range specs[0].UnleasedV6 {
		if a == "ge-0-0-9" {
			t.Fatalf("step 1: VRF-enslaved ge-0/0/9.0 must be skipped by the unleased backstop, got %v", specs[0].UnleasedV6)
		}
	}
	// Positive control: the SAME unit without RI membership WOULD be
	// backstopped — proving the skip above is caused by VRF enslavement
	// (not by fixture shape) and the loops are non-vacuous.
	plainCfg := *cfg
	plainCfg.RoutingInstances = nil
	plainV4, plainV6 := dpuserspace.BuildUnzonedDHCPUnleasedNetdevs(&plainCfg, s1)
	if !sliceContains(plainV4, "ge-0-0-9") || !sliceContains(plainV6, "ge-0-0-9") {
		t.Fatalf("control: unenslaved ge-0/0/9.0 must be backstopped, got %v/%v (fixture shape wrong?)", plainV4, plainV6)
	}

	// Step 2: the VRF lease lands (v4+v6) and the real rerender FAILS.
	injected := errors.New("nftables: VRF-lease rerender failed")
	var realCalls, gapCalls int
	var gapSpec xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { realCalls++; return injected },
		gapFence:    func(spec xnft.GapFenceSpec) error { gapCalls++; gapSpec = spec; return nil },
	}
	vrfUp := scriptedSnap10751("ge-0/0/9.0", "",
		scriptedAddr10751("inet", "203.0.113.9/24", uni),
		scriptedAddr10751("inet6", "2001:db8:9::9/64", uni))
	vrfUp.RoutingInstance = "data"
	s2 := []dpuserspace.InterfaceSnapshot{sib, vrfUp}
	scriptSnapshotTransition10751(t, s2, s2)
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 2: the failed rerender must surface the netlink error, got %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 2: hostInboundEnforced must remain true (the retained real table is untouched)")
	}
	if realCalls != 1 {
		t.Fatalf("step 2: real attempts = %d, want exactly 1 (no retry storm, no new event)", realCalls)
	}
	if gapCalls != 1 {
		t.Fatalf("step 2 (VRF-LEASE-WINDOW): the VRF lease appeared and the rerender failed, but no "+
			"additive gap fence was installed — no backstop covers VRF-enslaved units, so the lease "+
			"is fail-open until the next trigger (gap installs=%d)", gapCalls)
	}
	if !sliceContains(gapSpec.UncoveredV4, "203.0.113.9") {
		t.Errorf("gap fence must deny the VRF lease 203.0.113.9:\n%+v", gapSpec)
	}
	if !sliceContains(gapSpec.UncoveredV6, "2001:db8:9::9") {
		t.Errorf("gap fence must deny the VRF lease 2001:db8:9::9:\n%+v", gapSpec)
	}
	if sliceContains(gapSpec.UncoveredV4, "10.0.0.1") {
		t.Errorf("gap fence must NOT re-fence the already-covered 10.0.0.1 (retained table serves it):\n%+v", gapSpec)
	}
	if len(gapSpec.SharedV4) != 0 || len(gapSpec.SharedV6) != 0 {
		t.Errorf("gap shared = %v/%v, want empty/empty (the VRF lease is nobody's lifeline-shared value: bare DROP, no exception)",
			gapSpec.SharedV4, gapSpec.SharedV6)
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('4', "203.0.113.9")]; ok {
		t.Error("covered set must NOT include the gap-only VRF lease (retained real table does not cover it)")
	}
	if _, ok := d.hostInboundCoveredAddrs[hostInboundDropAddrKey('6', "2001:db8:9::9")]; ok {
		t.Error("covered set must NOT include the gap-only VRF lease (retained real table does not cover it)")
	}
	if owed, failures, _ := d.HostInboundGapDebt(); owed || failures != 0 {
		t.Fatalf("single real-install failure with a successful gap fence must not owe the double-failure retry (owed=%v failures=%d)", owed, failures)
	}

}

// TestHostInboundProgramOnlyThenAddressGapFence_5789 is issue path 2: a successful
// addressless program-only install stores enforced=true with ZERO covered
// addresses. When an address later appears and the rerender fails, the retained
// program-only table has no destination-scoped deny for it — so an additive gap
// fence must protect the new address. This is the case the sticky boolean cannot
// distinguish (enforced=true, but covered={}).
func TestHostInboundProgramOnlyThenAddressGapFence_5789(t *testing.T) {
	orig := nftInstaller
	defer func() { nftInstaller = orig }()

	unit := &config.InterfaceUnit{Number: 0, DHCP: true} // addressless initially
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf5789wan": {Name: "xpf5789wan", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf5789wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"bad-host": {Name: "bad-host", Value: "10.0.0.5/32"},
	}}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*config.Policy{{
			Name:   "block-bad-host",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses: []string{"bad-host"},
				Applications:    []string{"any"},
			},
		}},
	}}

	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true, "fab0": true, "em0": true})

	// Step 1: program-only real install (no address drops) succeeds → enforced
	// true, covered EMPTY.
	nftInstaller = &fakeNftInstaller{} // all succeed
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("step 1 (program-only install): %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("step 1: a successful program-only real install must set hostInboundEnforced true")
	}
	if len(d.hostInboundCoveredAddrs) != 0 {
		t.Fatalf("step 1: program-only install covers NO address; covered=%v", d.hostInboundCoveredAddrs)
	}

	// Step 2: an address appears on the interface; the rerender FAILS.
	unit.Addresses = []string{"198.51.100.57/24"}
	injected := errors.New("nftables: issue 5789 program-then-address failure")
	var gapCalls int
	var gapSpec xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return injected }, // real ruleset fails
		gapFence:    func(spec xnft.GapFenceSpec) error { gapCalls++; gapSpec = spec; return nil },
	}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("step 2: failed rerender must surface the netlink error, got %v", err)
	}
	if gapCalls != 1 {
		t.Fatalf("step 2 (#5789 path 2 FAIL-OPEN): an address appeared on a program-only-covered "+
			"interface and the rerender failed; the enforced=true/covered-empty case must install a "+
			"gap fence for the new address, got %d gap installs", gapCalls)
	}
	// The gap denies the appeared address, via the separate additive gap table
	// (InstallGapFence, xpf_hostinbound_gap), not a whole-table replace.
	if !sliceContains(gapSpec.UncoveredV4, "198.51.100.57") {
		t.Errorf("gap fence must deny the newly-appeared address 198.51.100.57:\n%+v", gapSpec)
	}
}

// TestHostInboundFullyCoveredFailedRerenderNoGap_5789 is the no-regression guard:
// when the retained generation ALREADY covers every desired destination, a failed
// rerender must NOT install a gap fence — it takes the existing day-2 retention
// (the atomic-untouched table still protects everything). If the coverage check
// were wrong (always treating enforced as stale) this would spuriously fence.
func TestHostInboundFullyCoveredFailedRerenderNoGap_5789(t *testing.T) {
	orig := nftInstaller
	defer func() { nftInstaller = orig }()

	// Install once (coverage = the wan addrs).
	nftInstaller = &fakeNftInstaller{} // all succeed
	d := &Daemon{}
	cfg := hostInboundTestConfig()
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("install: %v", err)
	}

	// Same config, real rerender fails, but coverage is COMPLETE → no gap.
	injected := errors.New("nftables: transient failure, same address set")
	var realCalls, gapCalls int
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { realCalls++; return injected },
		gapFence: func(xnft.GapFenceSpec) error {
			gapCalls++
			t.Error("a fully-covered failed rerender must NOT install a gap fence (day-2 retention holds)")
			return nil
		},
	}
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, injected) {
		t.Fatalf("rerender must surface the netlink error, got %v", err)
	}
	if gapCalls != 0 {
		t.Errorf("fully-covered failed rerender must install no gap fence, got %d", gapCalls)
	}
	if realCalls != 1 {
		t.Errorf("fully-covered failed rerender must attempt exactly one real install, got %d", realCalls)
	}
}

// TestHostInboundTeardownClearsCoverageAndGap_5789 composes with #5790: a
// successful no-enforcement teardown must clear the coverage set AND delete the
// gap table, so a later enforceable generation whose first real load fails takes
// the cold-boot fence (there is no retained table to cover anything).
func TestHostInboundTeardownClearsCoverageAndGap_5789(t *testing.T) {
	orig := nftInstaller
	deleted := map[string]bool{}
	nftInstaller = &fakeNftInstaller{
		del: func(name string) error { deleted[name] = true; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(d.hostInboundCoveredAddrs) == 0 {
		t.Fatal("install must populate the coverage set")
	}

	// Non-enforceable config → teardown.
	if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if d.hostInboundCoveredAddrs != nil {
		t.Errorf("teardown must clear the coverage set, got %v", d.hostInboundCoveredAddrs)
	}
	if d.hostInboundEnforced.Load() {
		t.Error("teardown must clear hostInboundEnforced (#5790)")
	}
	if !deleted[xnft.HostInboundTableName] || !deleted[xnft.HostInboundGapTableName] {
		t.Errorf("teardown must delete BOTH the main and gap tables, deleted=%v", deleted)
	}
}

// TestHostInboundGapFenceMirrorsColdBootAdmits_5789 guards that the additive gap
// fence and the whole-table cold-boot fence keep an IDENTICAL scope-independent
// mandatory L3 posture. Per-zone WG admits are separately destination-scoped by
// each fence's zone data.
func TestHostInboundGapFenceMirrorsColdBootAdmits_5789(t *testing.T) {
	views := buildAndCheckViews(t, hostInboundTestConfig())
	coldBoot := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	gap := buildHostInboundGapFencePayload(views, []string{"172.16.50.9"}, nil, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	for _, admit := range hostInboundFenceMandatoryAdmits() {
		if !strings.Contains(coldBoot, admit) {
			t.Errorf("cold-boot fence missing shared admit %q", strings.TrimSpace(admit))
		}
		if !strings.Contains(gap, admit) {
			t.Errorf("gap fence missing shared admit %q", strings.TrimSpace(admit))
		}
	}
}

func TestHostInboundCoveredFamilyAddrsValidatesKeys11577(t *testing.T) {
	v4, v6 := hostInboundCoveredFamilyAddrs(map[string]struct{}{
		"4|192.0.2.2":              {},
		"4|192.0.2.1":              {},
		"4|2001:db8::4":            {},
		"4|not-an-address":         {},
		"4|::ffff:192.0.2.4":       {},
		"6|2001:0db8::2":           {},
		"6|2001:db8::2":            {},
		"6|192.0.2.3":              {},
		"6|2001:db8::3/128":        {},
		"6|fe80::1%ge-0-0-1":       {},
		"7|198.51.100.1":           {},
		"missing-family-separator": {},
	})
	if got, want := strings.Join(v4, ","), "192.0.2.1,192.0.2.2"; got != want {
		t.Fatalf("valid covered IPv4 addresses = %q, want %q", got, want)
	}
	if got, want := strings.Join(v6, ","), "2001:0db8::2,2001:db8::2"; got != want {
		t.Fatalf("valid covered IPv6 addresses = %q, want %q", got, want)
	}
}

func TestHostInboundGapBackstopExcludesRetainedAddresses11577(t *testing.T) {
	uncoveredV4 := []string{"192.0.2.3"}
	uncoveredV6 := []string{"2001:db8::3"}
	retainedV4 := []string{"192.0.2.2"}
	retainedV6 := []string{"2001:db8::2"}
	regular := []string{"ge-0-0-1"}
	vrfSlave := []string{"ge-0-0-5"}
	backstop := dhcpBackstopLists{v4: vrfSlave, v6: vrfSlave}
	build := func(gapV4, gapV6 []string) string {
		return buildHostInboundGapFencePayload(
			nil, gapV4, gapV6, nil, nil, regular, regular, nil, nil, nil,
			backstop, retainedV4, retainedV6,
		)
	}
	payload := build(uncoveredV4, uncoveredV6)
	for _, rule := range []string{
		`iifname "ge-0-0-1" meta nfproto ipv4 fib daddr type { local, anycast } ip daddr != 192.0.2.2 drop`,
		`meta sdifname "ge-0-0-5" meta nfproto ipv4 fib daddr type { local, anycast } ip daddr != 192.0.2.2 drop`,
		`iifname "ge-0-0-1" meta nfproto ipv6 fib daddr type { local, anycast } ip6 daddr != 2001:db8::2 drop`,
		`meta sdifname "ge-0-0-5" meta nfproto ipv6 fib daddr type { local, anycast } ip6 daddr != 2001:db8::2 drop`,
	} {
		if !strings.Contains(payload, rule) {
			t.Errorf("gap fence lacks retained-address-scoped backstop %q:\n%s", rule, payload)
		}
	}
	for _, family := range []struct {
		drop, backstop string
	}{
		{drop: "ip daddr " + nftAddrSet(uncoveredV4) + " drop", backstop: `iifname "ge-0-0-1" meta nfproto ipv4 fib daddr type { local, anycast } ip daddr !=`},
		{drop: "ip6 daddr " + nftAddrSet(uncoveredV6) + " drop", backstop: `iifname "ge-0-0-1" meta nfproto ipv6 fib daddr type { local, anycast } ip6 daddr !=`},
	} {
		dropAt, backstopAt := strings.Index(payload, family.drop), strings.Index(payload, family.backstop)
		if dropAt < 0 || backstopAt <= dropAt {
			t.Errorf("explicit uncovered destination drop must precede the conditional backstop: drop=%d backstop=%d\n%s", dropAt, backstopAt, payload)
		}
	}

	v6Only := build(nil, uncoveredV6)
	if !strings.Contains(v6Only, `iifname "ge-0-0-1" meta nfproto ipv4 fib daddr type { local, anycast } ip daddr != 192.0.2.2 drop`) {
		t.Fatalf("IPv6-only gap omitted the IPv4 retained-address exclusion:\n%s", v6Only)
	}
	if strings.Contains(v6Only, "ip daddr "+nftAddrSet(uncoveredV4)+" drop") {
		t.Fatalf("IPv6-only gap emitted an explicit IPv4 uncovered drop:\n%s", v6Only)
	}
}
