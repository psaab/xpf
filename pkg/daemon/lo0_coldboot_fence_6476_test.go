package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #6476: the lo0 RE-protection filter had no cold-boot fence. On COLD BOOT no
// prior xpf_lo0 table exists to retain, so a failed real InstallLo0 (the boot
// apply only logs+discards the error) left the host input path OPEN with only a
// WARN, while host services / VIP / HA-ready were published — the same fail-open
// #5644 closed for the host-inbound table. The fix mirrors installHostInbound
// ColdBootFence for lo0: when the real lo0 install fails and no REAL filter is
// currently loaded (lo0Enforced false), a fail-closed fence that denies
// host-bound traffic to the firewall-local addresses (minus lifelines) is
// installed instead of proceeding open. A fence is NOT a real filter, so it leaves
// lo0Enforced false and a later failed install re-fences from the current
// snapshot (#6489). These are the fail-on-revert proofs: neutralize the fence
// (drop the installLo0ColdBootFence call, or route it to the wrong table) and the
// cold-boot assertions go RED.

// lo0FenceTestConfig returns hostInboundTestConfig augmented with a bound lo0
// input filter for both families, so applyLo0Filter takes the INSTALL path and
// the cold-boot fence renders from the SAME firewall-local address snapshot the
// host-inbound fence uses (wan reth0.50 172.16.50.8 / 2001:db8:50::8; em0/fxp0
// lifelines are excluded by the view builders).
func lo0FenceTestConfig() *config.Config {
	cfg := hostInboundTestConfig()
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.System.Lo0FilterInputV6 = "protect-re6"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "allow-ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "accept"},
			{Name: "deny-rest", Action: "discard"},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"protect-re6": {Name: "protect-re6", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest6", Action: "discard"},
		}},
	}
	return cfg
}

// TestColdBootLo0InstallFailureInstallsFence is the primary #6476 fail-on-revert
// proof: at cold boot, when the real lo0 install fails and no xpf_lo0 table has
// ever loaded this boot, a fail-closed fence MUST be installed via the lo0 table
// seam so the RE-protection input path stays fenced. It also asserts the commit
// still fails (the error is surfaced) so the retry/re-render path is driven.
// Reverting the fence makes the fence-installed assertion RED.
func TestColdBootLo0InstallFailureInstallsFence(t *testing.T) {
	cfg := lo0FenceTestConfig()

	injected := errors.New("nftables: lo0 rule load failed")
	var lo0Calls, fenceCalls int
	var fenceSpec xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error {
			lo0Calls++
			return injected // real lo0 ruleset install fails (injected cold-boot failure)
		},
		lo0ColdBootFence: func(spec xnft.FenceSpec) error {
			fenceCalls++
			fenceSpec = spec
			return nil // the fence installs
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	// Cold boot: no real lo0 filter is loaded.
	if d.lo0Enforced.Load() {
		t.Fatal("precondition: lo0Enforced must start false (cold boot)")
	}

	err := d.applyLo0Filter(cfg)

	// The commit must still fail closed (the real ruleset did not load).
	if err == nil {
		t.Fatal("cold-boot lo0 install failure must be surfaced as an error, got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink failure, got %v", err)
	}

	// A fence must have been installed through the lo0 table seam (exactly once).
	// Routing the fence to the host-inbound table seam instead would leave this 0.
	if fenceCalls != 1 {
		t.Fatalf("cold-boot lo0 install failure must install exactly one fail-closed lo0 fence, got %d", fenceCalls)
	}
	if lo0Calls != 1 {
		t.Errorf("expected exactly one real lo0 install attempt, got %d", lo0Calls)
	}

	// A fence is NOT a real filter, so lo0Enforced must stay FALSE — this is
	// the #6489 correctness core: it keeps the day-2 gate open so a later failed real
	// install RE-FENCES from the then-current snapshot (covering a new address)
	// rather than retaining this stale snapshot fence. The pre-fix code set the gate
	// true here (conflating fence-loaded with real-filter-loaded), the fail-open.
	if d.lo0Enforced.Load() {
		t.Error("a cold-boot fence must NOT set lo0Enforced (a fence is not a real filter); doing so re-opens the #6489 stale-fence fail-open")
	}

	// The fence must DENY host services to the enforced wan address (both
	// families). A FenceSpec structurally carries NO per-service accept, so the
	// "fence must not accept a service" fail-open is guaranteed by the type; the
	// exact drop-rule rendering is pinned by the shared netlink builder + parity CI.
	if !sliceContains(fenceViewAddrs(fenceSpec, false), "172.16.50.8") {
		t.Errorf("lo0 fence must fence the enforced wan v4 address 172.16.50.8:\n%+v", fenceSpec)
	}
	if !sliceContains(fenceViewAddrs(fenceSpec, true), "2001:db8:50::8") {
		t.Errorf("lo0 fence must fence the enforced wan v6 address 2001:db8:50::8:\n%+v", fenceSpec)
	}
}

// TestColdBootLo0FenceIsLifelineSafe proves the lo0 cold-boot fence renders the
// xpf_lo0 table at the lo0 filter priority (0), never denies a management /
// cluster-control lifeline address (em0), and does deny the enforced wan address.
// A fence that dropped a lifeline could strand management or break HA; a fence at
// the wrong priority/table would not stand in for the real lo0 filter. Reverting
// the lifeline exclusion, the table, or the priority makes this RED.
func TestColdBootLo0FenceIsLifelineSafe(t *testing.T) {
	cfg := lo0FenceTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	fence := buildLo0FencePayload(views, unzonedV4, unzonedV6, nil)

	// The fence occupies the xpf_lo0 slot (the real RE-protection filter's table),
	// at the lo0 filter priority so a successful InstallLo0 atomically replaces it.
	if !strings.Contains(fence, "table inet xpf_lo0 {") {
		t.Errorf("lo0 fence must render the xpf_lo0 table:\n%s", fence)
	}
	if !strings.Contains(fence, "type filter hook input priority 0;") {
		t.Errorf("lo0 fence must occupy the lo0 filter priority (0):\n%s", fence)
	}
	// em0's cluster-control address must never be fenced (lifeline).
	if strings.Contains(fence, "10.99.0.1") {
		t.Errorf("lo0 fence must not deny the em0 cluster-control lifeline address:\n%s", fence)
	}
	// The enforced wan address must be fenced.
	if !strings.Contains(fence, "ip daddr 172.16.50.8 drop") {
		t.Errorf("lo0 fence must deny the enforced wan address:\n%s", fence)
	}
}

// TestColdBootLo0FenceAdmitsMandatoryL3 proves the lo0 fence still admits return
// traffic and mandatory L3 control plus the configured WG port on the serving
// zone's address scope, so the deny-all fence does not black-hole core operation.
func TestColdBootLo0FenceAdmitsMandatoryL3(t *testing.T) {
	cfg := lo0FenceTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	wgZonePorts := map[string][]uint16{"wan": {51820}}
	fence := buildLo0FencePayload(views, unzonedV4, unzonedV6, wgZonePorts)

	for _, want := range []string{
		"ct state established,related accept",
		"meta l4proto { 50, 51 } accept",
		"icmpv6 type { 133, 134, 135, 136, 137 } accept",
		"icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
		"ip daddr 172.16.50.8 udp dport 51820 accept",
		"ip6 daddr 2001:db8:50::8 udp dport 51820 accept",
	} {
		if !strings.Contains(fence, want) {
			t.Errorf("lo0 fence missing scoped mandatory admit %q\n---\n%s", want, fence)
		}
	}
}

// TestDay2Lo0InstallFailureNoFence proves the intended divergence holds when a
// REAL filter is the live table: once a real lo0 filter has installed
// (lo0Enforced == true), a LATER failed install must NOT install a fence —
// the atomic replaceTable already retains the prior real filter (fail-closed by
// retention), and unlike the address-scoped host-inbound table the operator's lo0
// filter still governs every local address, so there is no day-2 coverage gap to
// fence. This is the no-regression guard: a fence here would clobber the retained
// real filter with a deny-all, so this goes RED. (Contrast
// TestColdBootLo0FenceThenNewAddressReFences, where the retained table is a FENCE,
// not a real filter, and a day-2 failure MUST re-fence.)
func TestDay2Lo0InstallFailureNoFence(t *testing.T) {
	cfg := lo0FenceTestConfig()

	// First apply: real install succeeds → a real filter is now loaded.
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{} // all succeed
	d := &Daemon{}
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("first (successful) apply: %v", err)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("lo0Enforced must be true after a successful real install")
	}

	// Second apply: real install fails. The prior table is retained by the atomic
	// load, so NO fence must be installed.
	injected := errors.New("nftables: transient failure")
	var lo0Calls, fenceCalls int
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { lo0Calls++; return injected },
		lo0ColdBootFence: func(xnft.FenceSpec) error {
			fenceCalls++
			t.Errorf("day-2 lo0 failure must NOT install a cold-boot fence")
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("day-2 lo0 install failure must still be surfaced as an error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink failure, got %v", err)
	}
	if lo0Calls != 1 {
		t.Errorf("day-2 failure must attempt exactly one real install, got %d", lo0Calls)
	}
	if fenceCalls != 0 {
		t.Errorf("day-2 failure must install no fence, got %d", fenceCalls)
	}
}

// TestColdBootLo0FenceCatastrophicFailureSurfaced proves that when the real lo0
// install AND the fence both fail (nft itself broken), both errors are surfaced
// so the commit fails closed and lo0Enforced stays false (no real filter).
func TestColdBootLo0FenceCatastrophicFailureSurfaced(t *testing.T) {
	cfg := lo0FenceTestConfig()

	realErr := errors.New("nftables: lo0 rule load failed")
	fenceErr := errors.New("nftables: kernel refused lo0 fence")
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { return realErr },
		lo0ColdBootFence: func(xnft.FenceSpec) error { return fenceErr },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("catastrophic cold-boot lo0 failure must be surfaced as an error")
	}
	if !errors.Is(err, realErr) || !errors.Is(err, fenceErr) {
		t.Errorf("error must join both the real and fence failures, got %v", err)
	}
	// The fence never loaded, so no real filter is loaded either.
	if d.lo0Enforced.Load() {
		t.Error("lo0Enforced must stay false when the fence also fails")
	}
}

// TestColdBootLo0ZeroDropFenceLeavesEnforcedFalse proves that a cold-boot
// fence rendered from a snapshot with no local addresses is a zero-drop shell
// for lo0, even when an addressless host-inbound ingress makes the host-inbound
// enforcement predicate true. It also leaves lo0Enforced false, so a later
// failed real invocation re-fences from a possibly-now-addressed snapshot.
func TestColdBootLo0ZeroDropFenceLeavesEnforcedFalse(t *testing.T) {
	// The host-inbound catalog fence has an addressless ingress scope, but the lo0
	// fence emits only destination-address drops and therefore remains zero-drop.
	cfg := hostInboundTestConfig()
	for _, iface := range cfg.Interfaces.Interfaces {
		for _, unit := range iface.Units {
			unit.Addresses = nil
		}
	}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: "discard"},
		}},
	}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !hostInboundHasEnforceableView(views) {
		t.Fatal("precondition: addressless ingress must be enforceable for host-inbound")
	}
	for _, view := range views {
		if len(view.V4Addrs) > 0 || len(view.V6Addrs) > 0 {
			t.Fatalf("precondition: lo0 snapshot has no firewall-local addresses: %+v", view)
		}
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	injected := errors.New("nftables: lo0 zero-drop cold boot")
	var fenceCalls int
	var fenceSpec xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return injected },
		lo0ColdBootFence: func(spec xnft.FenceSpec) error {
			fenceCalls++
			fenceSpec = spec
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	err := d.applyLo0Filter(cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("error = %v, want wrapped injected", err)
	}
	if fenceCalls != 1 {
		t.Fatalf("zero-drop cold boot must still attempt exactly one fence, got %d", fenceCalls)
	}
	if len(fenceViewAddrs(fenceSpec, false)) != 0 || len(fenceViewAddrs(fenceSpec, true)) != 0 {
		t.Fatalf("fence must be zero-drop (no firewall-local addresses):\n%+v", fenceSpec)
	}
	if d.lo0Enforced.Load() {
		t.Error("zero-drop fence must leave lo0Enforced false (re-fence on next failure)")
	}
	logged := logs.String()
	if !strings.Contains(logged, "installed a zero-drop fence shell") {
		t.Fatalf("addressless ingress must be reported as a zero-drop lo0 fence:\n%s", logged)
	}
	if strings.Contains(logged, "installed an address-scoped fail-closed fence") {
		t.Fatalf("lo0 must not report an address-scoped fence without local addresses:\n%s", logged)
	}
}

// TestLo0TeardownClearsEnforced proves a successful no-filter teardown
// clears the lo0Enforced gate, so a later cold-boot failure fences rather
// than assuming a retained table (the #5790 teardown-clears-state parity for lo0).
func TestLo0TeardownClearsEnforced(t *testing.T) {
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{} // all succeed
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	// Load a real filter with a successful real install.
	if err := d.applyLo0Filter(lo0FenceTestConfig()); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("lo0Enforced must be true after a successful real install")
	}
	// A successful teardown (no lo0 filter configured) clears the gate.
	if err := d.applyLo0Filter(&config.Config{}); err != nil {
		t.Fatalf("teardown apply: %v", err)
	}
	if d.lo0Enforced.Load() {
		t.Error("successful teardown must clear lo0Enforced (no table retained)")
	}
}

// TestColdBootLo0FenceThenNewAddressReFences is the #6489 fail-on-revert proof for
// the stale-fence fail-open. Sequence: cold-boot real install FAILS → a fence is
// installed for snapshot A (address 172.16.50.8); then a NEW firewall-local
// address B (10.0.61.1) appears and the real install FAILS again. Because the live
// table is a FENCE (policy accept + drops for A only), NOT a real filter, the
// day-2 gate MUST re-fence from the current snapshot so B is covered — otherwise B
// falls through the stale fence's `policy accept` (fail-open).
//
// PARENT-RED: make the cold-boot fence Store lo0Enforced TRUE (the pre-fix
// conflation) and this test goes RED — the second apply's gate sees "real filter
// loaded", skips the fence (fenceCalls stays 1), and B is left uncovered.
func TestColdBootLo0FenceThenNewAddressReFences(t *testing.T) {
	// One zoned interface with address A; B is added to the same unit later.
	unit := &config.InterfaceUnit{Number: 0, Addresses: []string{"172.16.50.8/24"}}
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: "discard"},
		}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	injected := errors.New("nftables: lo0 real load failure")
	var fenceSpecs []xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return injected }, // real install always fails
		lo0ColdBootFence: func(spec xnft.FenceSpec) error {
			fenceSpecs = append(fenceSpecs, spec)
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}

	// Apply 1 (cold boot): real install fails → fence for snapshot A.
	if err := d.applyLo0Filter(cfg); !errors.Is(err, injected) {
		t.Fatalf("apply 1 error = %v, want wrapped injected", err)
	}
	if len(fenceSpecs) != 1 {
		t.Fatalf("apply 1 must install exactly one fence, got %d", len(fenceSpecs))
	}
	if !sliceContains(fenceViewAddrs(fenceSpecs[0], false), "172.16.50.8") {
		t.Fatalf("apply-1 fence must cover address A 172.16.50.8:\n%+v", fenceSpecs[0])
	}

	// A new firewall-local address B appears on the same unit.
	unit.Addresses = []string{"172.16.50.8/24", "10.0.61.1/24"}

	// Apply 2 (day-2): real install fails again over a RETAINED FENCE. The gate must
	// re-fence from the current snapshot so B is covered.
	if err := d.applyLo0Filter(cfg); !errors.Is(err, injected) {
		t.Fatalf("apply 2 error = %v, want wrapped injected", err)
	}
	if len(fenceSpecs) != 2 {
		t.Fatalf("day-2 failure over a retained FENCE must RE-FENCE (got %d fence installs, want 2); "+
			"the stale snapshot-A fence is policy-accept and does not cover the new address", len(fenceSpecs))
	}
	// The re-rendered fence must cover BOTH A and the newly-appeared B.
	got := fenceViewAddrs(fenceSpecs[1], false)
	if !sliceContains(got, "172.16.50.8") || !sliceContains(got, "10.0.61.1") {
		t.Fatalf("re-rendered fence must cover both A (172.16.50.8) and new B (10.0.61.1), got %v:\n%+v", got, fenceSpecs[1])
	}
}
