package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #6492 fail-on-revert proofs for the SHARED cold-boot fence builder. Both
// findings are exercised through the PRODUCTION call path
// applyLo0Filter -> installLo0ColdBootFence -> InstallLo0ColdBootFence(spec),
// which is the path a cold-boot lo0 install failure actually takes (the boot
// apply logs+discards the error, so the fence is the only remaining protection).
// Revert dpuserspace.BuildFenceAddrSets out of applyLo0Filter — back to
// `BuildZoneHostInboundViews` + `BuildUnzonedHostInboundAddrs` — and both tests
// go RED.

// fenceScopeInstaller wires a failing real lo0 install to a capturing fence
// installer and returns the captured spec plus the fence call count.
func fenceScopeInstaller(t *testing.T, cfg *config.Config) (xnft.FenceSpec, int) {
	t.Helper()
	injected := errors.New("nftables: injected cold-boot lo0 failure")
	var spec xnft.FenceSpec
	calls := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { return injected },
		lo0ColdBootFence: func(s xnft.FenceSpec) error { spec = s; calls++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if d.lo0Enforced.Load() {
		t.Fatal("precondition: cold boot means lo0Enforced false")
	}
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("the real lo0 install failed; applyLo0Filter must surface an error")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected failure, got %v", err)
	}
	return spec, calls
}

// TestFenceWithholdsLifelineSharedAddress6492 is the Finding A proof. A
// management address configured on BOTH fxp0.0 (a lifeline) and a zoned data
// interface is a topology xpf explicitly accepts. The fence strips every
// per-service ACCEPT and its drop rule carries no `iifname`, so fencing that
// address renders `ip daddr 172.16.50.8 drop` — every NEW management connection
// to it dies for the whole fence window. The fence must WITHHOLD it.
//
// The second half is the anti-over-fix assertion: the REAL ruleset's views must
// still carry the address, because the real table's per-service accepts precede
// its catch-all DROP and admit the management session. A "fix" that subtracted
// the address inside BuildZoneHostInboundViews would relax the real table's
// default-deny (a fail-open) and makes that half RED.
func TestFenceWithholdsLifelineSharedAddress6492(t *testing.T) {
	cfg := lo0FenceTestConfig()
	// The mgmt zone's fxp0 now carries the SAME address as the wan zone's
	// reth0.50 (172.16.50.8). fxp0 is a lifeline; reth0.50 is not.
	cfg.Interfaces.Interfaces["fxp0"].Units[0] = &config.InterfaceUnit{
		Number:    0,
		Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"},
	}

	// The REAL ruleset still denies the shared address (its accepts protect it).
	realViews := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !viewsContainAddr(realViews, "172.16.50.8") {
		t.Fatal("the REAL host-inbound views must still scope the shared address; " +
			"withholding it there would relax the real table's default-deny (fail-open)")
	}

	spec, calls := fenceScopeInstaller(t, cfg)
	if calls != 1 {
		t.Fatalf("cold-boot fence install count = %d, want 1", calls)
	}
	if got := fenceViewAddrs(spec, false); sliceContains(got, "172.16.50.8") {
		t.Fatalf("FENCE must not drop 172.16.50.8: it is also configured on the fxp0 "+
			"lifeline, and the fence has no per-service accept to let management back "+
			"in. Fenced v4 = %v", got)
	}
	if got := fenceViewAddrs(spec, true); sliceContains(got, "2001:db8:50::8") {
		t.Fatalf("FENCE must not drop 2001:db8:50::8 (shared with the fxp0 lifeline). "+
			"Fenced v6 = %v", got)
	}
	// The fence must still be doing its job for the addresses that are NOT
	// shared — otherwise "withhold" degenerated into "fence nothing".
	if got := fenceViewAddrs(spec, false); !sliceContains(got, "10.0.61.1") {
		t.Fatalf("FENCE must still drop the unshared lan address 10.0.61.1, got %v", got)
	}
}

// TestFenceCoversZonelessRouter6492 proves the fail-closed cold-boot fence also
// covers a valid lo0-filter config with no security zones. The zone-view builder
// is empty, but #11068 keeps the addressed non-lifeline interfaces in the
// unzoned default-deny set, so the fence still gets real drops.
func TestFenceCoversZonelessRouter6492(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24", "2001:db8:6492::1/64"}},
		}},
		// A lifeline keeps its exemption with or without zones.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.10.10.10/24"}},
		}},
	}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: "discard"},
		}},
	}

	// Precondition: this really is the zone-less shape the finding describes.
	if len(cfg.Security.Zones) != 0 {
		t.Fatal("precondition: the config must declare no security zone")
	}
	if v := dpuserspace.BuildZoneHostInboundViews(cfg); len(v) != 0 {
		t.Fatalf("precondition: the zone-model builder yields nothing without zones, got %+v", v)
	}
	if v4, v6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg); !sliceContains(v4, "192.0.2.1") ||
		!sliceContains(v6, "2001:db8:6492::1") {
		t.Fatalf("the unzoned builder must include both zoneless firewall-local addresses, got %v %v", v4, v6)
	}

	spec, calls := fenceScopeInstaller(t, cfg)
	if calls != 1 {
		t.Fatalf("cold-boot fence install count = %d, want 1", calls)
	}
	gotV4 := fenceViewAddrs(spec, false)
	if !sliceContains(gotV4, "192.0.2.1") {
		t.Fatalf("FENCE on a zone-less router must drop the firewall-local address "+
			"192.0.2.1; a zero-drop `policy accept` shell is the fail-open this fence "+
			"exists to prevent. Fenced v4 = %v", gotV4)
	}
	if got := fenceViewAddrs(spec, true); !sliceContains(got, "2001:db8:6492::1") {
		t.Fatalf("FENCE on a zone-less router must drop 2001:db8:6492::1, got %v", got)
	}
	if sliceContains(gotV4, "10.10.10.10") {
		t.Fatalf("FENCE must never drop a lifeline (fxp0) address, got %v", gotV4)
	}
}

// viewsContainAddr reports whether any view scopes addr in either family.
func viewsContainAddr(views []dpuserspace.ZoneHostInboundView, addr string) bool {
	for _, v := range views {
		if sliceContains(v.V4Addrs, addr) || sliceContains(v.V6Addrs, addr) {
			return true
		}
	}
	return false
}

// TestStickyReRenderNeverFencesLifelineShared6492 answers #6492 Finding C.
//
// C is the #6489 whole-table RE-RENDER at installLo0ColdBootFence: while no real
// filter is loaded, EVERY failed install re-renders the fence from a fresh
// snapshot. That is not a defect — it is the #6489 fix, and it is what covers an
// address that appears after an earlier fence. What C does is AMPLIFY Finding A:
// a lockout of a lifeline-shared management address would not be a brief window,
// it would last for as long as the box stays degraded.
//
// This test pins that the amplification has nothing left to amplify, and pins it
// structurally rather than by inspection. The withholding lives inside
// BuildFenceAddrSets, which applyLo0Filter calls FRESH on each fence install, so
// stickiness cannot outlive or escape it: the shared address is absent from EVERY
// render, not just the first.
//
// The second half is what stops the first half passing vacuously. A "fix" that
// neutered the re-render — stopping after one fence, or fencing nothing — would
// also keep the shared address out of every spec. So the test also asserts that
// the re-render really happens (one fence per failed install) and that an address
// appearing BETWEEN renders is picked up by the later one, which is exactly the
// #6489 property C exists to provide.
func TestStickyReRenderNeverFencesLifelineShared6492(t *testing.T) {
	cfg := lo0FenceTestConfig()
	// 172.16.50.8 / 2001:db8:50::8 live on both the wan zone's reth0.50 and the
	// fxp0 lifeline — the Finding A topology.
	cfg.Interfaces.Interfaces["fxp0"].Units[0] = &config.InterfaceUnit{
		Number:    0,
		Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"},
	}

	injected := errors.New("nftables: persistent lo0 install failure (degraded boot)")
	var specs []xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { return injected },
		lo0ColdBootFence: func(s xnft.FenceSpec) error { specs = append(specs, s); return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	const rounds = 4
	for i := 0; i < rounds; i++ {
		if i == 2 {
			// A new firewall-local address appears mid-degradation, on a
			// non-lifeline interface. The #6489 re-render must pick it up.
			cfg.Interfaces.Interfaces["reth1"].Units[0].Addresses = append(
				cfg.Interfaces.Interfaces["reth1"].Units[0].Addresses, "10.0.62.7/24")
		}
		if err := d.applyLo0Filter(cfg); err == nil {
			t.Fatalf("round %d: the real install failed; applyLo0Filter must surface an error", i)
		}
	}

	// The re-render really happened — one fence per failed install. Without this
	// the "absent from every spec" assertion below could pass on an inert fence.
	if len(specs) != rounds {
		t.Fatalf("#6489 re-render: want one fence install per failed real install (%d), got %d",
			rounds, len(specs))
	}
	// Finding C amplifies Finding A and A is gone: the lifeline-shared address is
	// absent from EVERY render, not merely the first.
	for i, spec := range specs {
		if got := fenceViewAddrs(spec, false); sliceContains(got, "172.16.50.8") {
			t.Fatalf("render %d fenced the lifeline-shared address 172.16.50.8; a sticky fence "+
				"would make that lockout last the whole degraded period. Fenced v4 = %v", i, got)
		}
		if got := fenceViewAddrs(spec, true); sliceContains(got, "2001:db8:50::8") {
			t.Fatalf("render %d fenced the lifeline-shared v6 address; Fenced v6 = %v", i, got)
		}
	}
	// And the re-render still does its #6489 job: the address that appeared at
	// round 2 is covered from round 2 onward, and was not covered before it
	// existed. A fence that had gone inert would fail this.
	if got := fenceViewAddrs(specs[0], false); sliceContains(got, "10.0.62.7") {
		t.Fatalf("render 0 predates the address; it must not be fenced. Fenced v4 = %v", got)
	}
	if got := fenceViewAddrs(specs[rounds-1], false); !sliceContains(got, "10.0.62.7") {
		t.Fatalf("the #6489 re-render must pick up an address that appeared mid-degradation; "+
			"final fenced v4 = %v", got)
	}
}
