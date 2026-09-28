package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
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
// fence and the whole-table cold-boot fence keep an IDENTICAL mandatory-admit
// posture (they share hostInboundFenceMandatoryAdmits). If one grows an admit the
// other lacks, a fenced address could black-hole return/ND traffic on one path
// but not the other.
func TestHostInboundGapFenceMirrorsColdBootAdmits_5789(t *testing.T) {
	wg := []uint16{51820}
	coldBoot := buildHostInboundFencePayload(buildAndCheckViews(t, hostInboundTestConfig()), nil, nil, wg, nil, nil)
	gap := buildHostInboundGapFencePayload([]string{"172.16.50.9"}, nil, wg, nil, nil, nil, nil, nil)
	for _, admit := range hostInboundFenceMandatoryAdmits(wg) {
		if !strings.Contains(coldBoot, admit) {
			t.Errorf("cold-boot fence missing shared admit %q", strings.TrimSpace(admit))
		}
		if !strings.Contains(gap, admit) {
			t.Errorf("gap fence missing shared admit %q", strings.TrimSpace(admit))
		}
	}
}
