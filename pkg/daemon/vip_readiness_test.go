package daemon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/vrrp"
)

// takeoverReadyDP is a minimal userspace dataplane stand-in that reports
// takeover-ready.
//
// #6782 moved the two TakeoverReadinessForRG fixtures' RETH from
// redundancy-group 0 to 1, because a reth in RG0 no longer commits (RG0 is the
// chassis-cluster control-plane group — see cluster.Manager.DataGroupIDs — so a
// reth assigned to it reads as NON-redundant downstream and its address lands on
// both nodes). That renumbering matters to the fixture: userspaceRGConfigured
// exempts `rgID <= 0`, so the old RG0 fixtures never reached the userspace
// takeover gate at all, while a real DATA redundancy group does. Publishing a
// ready backend here keeps each test isolating the property it actually names —
// that takeover readiness does not consult cluster sync readiness — rather than
// reporting not-ready for an unrelated absent backend.
type takeoverReadyDP struct{ *dataplane.Manager }

func newTakeoverReadyDP() *takeoverReadyDP {
	return &takeoverReadyDP{Manager: dataplane.New()}
}

// Mode reports a forwarding-capable userspace mode so the blackhole-route
// helpers take their early return and the test never touches netlink.
func (r *takeoverReadyDP) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceCompat
}

func (r *takeoverReadyDP) TakeoverReady() (bool, []string) { return true, nil }

// testLink implements netlink.Link for testing.
type testLink struct {
	attrs netlink.LinkAttrs
}

func (l *testLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *testLink) Type() string              { return "test" }

// mockLinkByName returns a function that resolves interfaces from a map.
func mockLinkByName(links map[string]*testLink) func(string) (netlink.Link, error) {
	return func(name string) (netlink.Link, error) {
		if l, ok := links[name]; ok {
			return l, nil
		}
		return nil, fmt.Errorf("link not found: %s", name)
	}
}

func newTestLink(name string, up bool) *testLink {
	var state netlink.LinkOperState = netlink.OperDown
	if up {
		state = netlink.OperUp
	}
	return &testLink{
		attrs: netlink.LinkAttrs{Name: name, OperState: state},
	}
}

func TestCheckVIPReadiness_AllUp(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", true),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceDown(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", false),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready with interface down")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "down") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_InterfaceNotFound(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	// Empty links map — interface not found.
	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if ready {
		t.Error("should NOT be ready when interface is missing")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "not found") {
		t.Errorf("unexpected reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_NoVIPs(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					// No RedundancyGroup, no RETH.
				},
			},
		},
	}

	links := map[string]*testLink{}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready with no VIPs, got reasons: %v", reasons)
	}
}

func TestCheckVIPReadiness_WrongRG(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1, // RG 1, not 0
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{}

	// Query RG 0 — reth0 is in RG 1, so no VIPs for RG 0.
	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Errorf("should be ready for unrelated RG, got reasons: %v", reasons)
	}
}

// rethVIPConfig returns a minimal RG-0 config whose only VIP interface
// resolves (via RethToPhysical + LinuxIfName) to "ge-0-0-0".
func rethVIPConfig() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}
}

// TestCheckVIPReadiness_CarrierAware locks #2090: readiness is decided
// from the operational carrier state (IFLA_OPERSTATE via
// cluster.LinkAttrsUp), NOT the administrative IFF_UP flag. xpfd admin-ups
// every managed interface, so IFF_UP stays set after a cable pull — the
// pre-#2090 disjunction (OperUp || IFF_UP) wrongly judged a carrier-down
// VIP interface ready. The "admin-up carrier-down -> NOT ready" case below
// is non-tautological: the pre-fix code returns ready for OperDown+FlagUp,
// so this test fails against pre-fix code.
func TestCheckVIPReadiness_CarrierAware(t *testing.T) {
	tests := []struct {
		name      string
		operState netlink.LinkOperState
		flags     net.Flags
		wantReady bool
	}{
		{
			// Cable pulled: admin-up (IFF_UP set) but no carrier. The
			// pre-#2090 bug reported this as ready (black-hole takeover).
			name:      "admin-up carrier-down -> NOT ready",
			operState: netlink.OperDown,
			flags:     net.FlagUp,
			wantReady: false,
		},
		{
			// Peer link down: kernel reports lower-layer-down, IFF_UP
			// still set.
			name:      "admin-up lower-layer-down -> NOT ready",
			operState: netlink.OperLowerLayerDown,
			flags:     net.FlagUp,
			wantReady: false,
		},
		{
			name:      "admin-up carrier-up -> ready",
			operState: netlink.OperUp,
			flags:     net.FlagUp,
			wantReady: true,
		},
		{
			// Admin-down: IFF_UP clear, must be not ready.
			name:      "admin-down -> NOT ready",
			operState: netlink.OperDown,
			flags:     0,
			wantReady: false,
		},
		{
			// VLAN sub-interface / virtual device with no independent
			// carrier reporting: OperUnknown falls back to the admin flag
			// (matches cluster.LinkAttrsUp / pkg/vrrp.linkAttrsUp). This is
			// load-bearing — RethVIPsForRG keys on VLAN sub-interface names
			// which commonly report OperUnknown.
			name:      "operunknown admin-up -> ready",
			operState: netlink.OperUnknown,
			flags:     net.FlagUp,
			wantReady: true,
		},
		{
			name:      "operunknown admin-down -> NOT ready",
			operState: netlink.OperUnknown,
			flags:     0,
			wantReady: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			links := map[string]*testLink{
				"ge-0-0-0": {attrs: netlink.LinkAttrs{
					Name:      "ge-0-0-0",
					OperState: tc.operState,
					Flags:     tc.flags,
				}},
			}
			ready, reasons := checkVIPReadinessForConfig(rethVIPConfig(), 0, mockLinkByName(links))
			if ready != tc.wantReady {
				t.Errorf("ready = %v, want %v (reasons: %v)", ready, tc.wantReady, reasons)
			}
			if !tc.wantReady {
				if len(reasons) != 1 || !strings.Contains(reasons[0], "down") {
					t.Errorf("expected one 'down' reason, got: %v", reasons)
				}
			} else if len(reasons) != 0 {
				t.Errorf("expected no reasons when ready, got: %v", reasons)
			}
		})
	}
}

func TestCheckNoRethTakeoverReadiness_UsesVIPReadinessOnly(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 0,
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
			},
		},
	}

	links := map[string]*testLink{
		"ge-0-0-0": newTestLink("ge-0-0-0", true),
	}

	ready, reasons := checkVIPReadinessForConfig(cfg, 0, mockLinkByName(links))
	if !ready {
		t.Fatalf("should be ready, got reasons: %v", reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

func testStoreWithSetConfig(t *testing.T, lines []string) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

// TestTakeoverReadinessForRG_NoRethIgnoresClusterSyncReady pins that in
// no-reth-vrrp mode the RG takeover gate does NOT consult cluster sync
// readiness. Together with the private-rg-election sibling below it is the
// binding for cluster.Manager.SetSyncReady's doc comment, which used to assert
// the opposite (#7102): the gate that read IsSyncReady() here was deleted in
// 0781f7a60 and takeover readiness is now VIP ownership alone. #110 tracks
// whether it should return — if it does, this test and its sibling red, which
// is the point.
//
// #7162 UPDATE: takeover readiness here is NO LONGER "VIP ownership alone" — a
// bounded startup hold (Daemon.armNoRethSyncHold) is now a term in
// checkNoRethTakeoverReadiness. This test and its sibling still pass, and still
// pin something true and load-bearing: the gate is the HOLD, never this FLAG.
// The distinction is the whole of #110 — the hold is bounded, the flag is not,
// and a flag-based conjunct would block promotion indefinitely with sync down.
// These fixtures never arm the hold, so they isolate the flag, which is exactly
// what makes them the right guard for that claim. The sentence above about this
// test redding if the gate returns is therefore superseded: it reds if the FLAG
// becomes a gate, which is still the thing to prevent.
func TestTakeoverReadinessForRG_NoRethIgnoresClusterSyncReady(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set chassis cluster no-reth-vrrp",
		// #18053: complete control link for the #16746 gate. Private-
		// rg-election stays the compiler default, so this fixture keeps
		// BOTH flags as the sibling comment below describes; inert for
		// the sync-ready assertion (hold never armed, RG state driven
		// via the manager).
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		// #6782: the RETH sits in redundancy-group 1, not 0. RG0 is reserved for
		// control-plane ownership (see cluster.Manager.DataGroupIDs), so a RETH in
		// group 0 reads as NON-redundant everywhere downstream and its address is
		// configured on both nodes — that now hard-rejects at commit. The group
		// NUMBER is incidental to what this test pins (takeover readiness does not
		// consult cluster sync readiness); do not renumber it back to 0.
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm.Start(ctx)

	d := &Daemon{
		rgStates:     make(map[int]*rgStateMachine),
		cluster:      cm,
		store:        store,
		vrrpMgr:      vrrp.NewManager(),
		linkByNameFn: mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
	}

	if d.cluster.IsSyncReady() {
		t.Fatal("sync should start not ready for this regression test")
	}
	d.setDataplane(newTakeoverReadyDP())

	d.reconcileRGState()

	state := d.cluster.GroupState(1)
	if state == nil {
		t.Fatal("expected RG 1 state")
	}
	if !state.Ready {
		t.Fatalf("expected RG 1 ready, got reasons: %v", state.ReadinessReasons)
	}
	for _, reason := range state.ReadinessReasons {
		if strings.Contains(reason, "session sync not ready") {
			t.Fatalf("unexpected session sync gating reason: %v", state.ReadinessReasons)
		}
	}
}

// TestTakeoverReadinessForRG_PrivateRGElectionIgnoresClusterSyncReady_7102 is
// the same property reached through the OTHER spelling of the branch.
//
// The sibling above authors `no-reth-vrrp`, and because private-rg-election is
// the compiler default (compiler_system.go sets PrivateRGElection unless
// `no-private-rg-election` is present) that fixture has BOTH flags set — so it
// cannot tell you which one selected the no-RETH takeover path. The comment
// this binds names private-rg-election specifically, so this fixture sets
// private-rg-election with NoRethVRRP left FALSE: the branch at
// daemon_ha.go (`cc.NoRethVRRP || cc.PrivateRGElection`) is then taken solely
// on the private-rg-election term, and the RG still reaches Ready with session
// sync NOT ready and no "session sync not ready" reason.
func TestTakeoverReadinessForRG_PrivateRGElectionIgnoresClusterSyncReady_7102(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-7102",
		"set chassis cluster node 0",
		"set chassis cluster private-rg-election",
		// #18053: this cell's subject IS private-rg-election, so it
		// must NOT take the no-private-rg-election opt-out (that would
		// vacate the fixture assertions below). It instead carries the
		// complete control link the #16746 gate requires. Inert for
		// the sync-ready assertion: no heartbeat is started here, RG
		// state is driven via the manager.
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		// #6782: the RETH sits in redundancy-group 1, not 0. RG0 is reserved for
		// control-plane ownership (see cluster.Manager.DataGroupIDs), so a RETH in
		// group 0 reads as NON-redundant everywhere downstream and its address is
		// configured on both nodes — that now hard-rejects at commit. The group
		// NUMBER is incidental to what this test pins (takeover readiness does not
		// consult cluster sync readiness); do not renumber it back to 0.
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
	})

	cc := store.ActiveConfig().Chassis.Cluster
	if cc == nil || !cc.PrivateRGElection {
		t.Fatalf("fixture must compile to PrivateRGElection=true, got %+v", cc)
	}
	if cc.NoRethVRRP {
		t.Fatal("fixture must leave NoRethVRRP false so private-rg-election is the " +
			"only term selecting the no-RETH takeover path")
	}

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm.Start(ctx)

	d := &Daemon{
		rgStates:     make(map[int]*rgStateMachine),
		cluster:      cm,
		store:        store,
		vrrpMgr:      vrrp.NewManager(),
		linkByNameFn: mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
	}

	if d.cluster.IsSyncReady() {
		t.Fatal("sync must start NOT ready for this test to mean anything")
	}
	d.setDataplane(newTakeoverReadyDP())

	d.reconcileRGState()

	state := d.cluster.GroupState(1)
	if state == nil {
		t.Fatal("expected RG 1 state")
	}
	if !state.Ready {
		t.Fatalf("RG 1 not ready with session sync not ready: %v — promotion in "+
			"private-rg-election mode is NOT sync-gated at HEAD (the gate was deleted "+
			"in 0781f7a60). If this now reds because #110 restored the gate, update "+
			"cluster.SetSyncReady's doc comment, the Manager.syncReady field comment "+
			"and the daemon_run_bringup.go note with it", state.ReadinessReasons)
	}
	for _, reason := range state.ReadinessReasons {
		if strings.Contains(reason, "session sync not ready") {
			t.Fatalf("takeover readiness reported a sync reason %q; the readiness "+
				"conjunction has no sync term (#7102)", state.ReadinessReasons)
		}
	}
}

func TestUserspaceRGConfigured(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{
			DataplaneType: "",
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
				},
			},
		},
	}

	if !userspaceRGConfigured(cfg, 1) {
		t.Fatal("expected RG 1 configured")
	}
	if !userspaceRGConfigured(cfg, 2) {
		t.Fatal("expected RG 2 configured")
	}
	if userspaceRGConfigured(cfg, 3) {
		t.Fatal("expected RG 3 not configured")
	}
	if userspaceRGConfigured(cfg, 0) {
		t.Fatal("expected RG 0 not configured")
	}
	if userspaceRGConfigured(nil, 1) {
		t.Fatal("expected nil config not configured")
	}

	cfg.System.DataplaneType = dataplane.TypeEBPF
	if userspaceRGConfigured(cfg, 1) {
		t.Fatal("expected explicit legacy eBPF config not configured for userspace RG")
	}
}
