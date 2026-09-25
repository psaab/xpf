package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

func newTestDaemon() *Daemon {
	return &Daemon{
		rgStates: make(map[int]*rgStateMachine),
	}
}

func TestRethMasterState_SingleInstance(t *testing.T) {
	d := newTestDaemon()

	// No instances → not master.
	if d.isRethMasterState(1) {
		t.Error("empty map should not be master")
	}
	if d.isAnyRethInstanceMaster(1) {
		t.Error("empty map should not have any master")
	}

	// Set single instance MASTER via state machine.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	if !d.isRethMasterState(1) {
		t.Error("single MASTER instance should be master")
	}
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("single MASTER instance should have any master")
	}

	// Set it BACKUP.
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	if d.isRethMasterState(1) {
		t.Error("single BACKUP instance should not be master")
	}
	if d.isAnyRethInstanceMaster(1) {
		t.Error("single BACKUP instance should not have any master")
	}
}

func TestRethMasterState_MultiInstance(t *testing.T) {
	d := newTestDaemon()

	// Two instances, both BACKUP initially.
	s := d.getOrCreateRGState(1)
	s.SetVRRP("reth1", false)
	s.SetVRRP("reth1.50", false)
	if d.isRethMasterState(1) {
		t.Error("all BACKUP should not be master")
	}
	if d.isAnyRethInstanceMaster(1) {
		t.Error("all BACKUP should not have any master")
	}

	// First instance goes MASTER.
	s.SetVRRP("reth1", true)
	if d.isRethMasterState(1) {
		t.Error("partial MASTER should not be all-master")
	}
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("partial MASTER should have any master")
	}

	// Second instance goes MASTER — now all MASTER.
	s.SetVRRP("reth1.50", true)
	if !d.isRethMasterState(1) {
		t.Error("all MASTER should be master")
	}
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("all MASTER should have any master")
	}

	// One instance goes BACKUP — not all MASTER anymore.
	s.SetVRRP("reth1", false)
	if d.isRethMasterState(1) {
		t.Error("partial BACKUP should not be all-master")
	}
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("partial BACKUP should still have any master")
	}
}

func TestRethMasterState_MultiRG(t *testing.T) {
	d := newTestDaemon()

	// RG 0 with one instance, RG 1 with two instances.
	d.getOrCreateRGState(0).SetVRRP("reth0", true)
	s1 := d.getOrCreateRGState(1)
	s1.SetVRRP("reth1", true)
	s1.SetVRRP("reth1.50", false)

	if !d.isRethMasterState(0) {
		t.Error("RG 0 should be master")
	}
	if d.isRethMasterState(1) {
		t.Error("RG 1 should not be all-master (reth1.50 is BACKUP)")
	}
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("RG 1 should have any master (reth1 is MASTER)")
	}
}

func TestStrictVIPOwnershipByDefault_DefaultUserspaceKeepsVRRPLoose(t *testing.T) {
	cc := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg := &config.Config{}

	if strictVIPOwnershipByDefault(cc, cfg) {
		t.Fatal("expected strict VIP ownership off for default userspace dataplane")
	}
}

func TestStrictVIPOwnershipByDefault_EnabledInLegacyEBPFVRRPMode(t *testing.T) {
	cc := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeEBPF

	if !strictVIPOwnershipByDefault(cc, cfg) {
		t.Fatal("expected strict VIP ownership on for explicit legacy eBPF VRRP mode")
	}
}

func TestStrictVIPOwnershipByDefault_DisabledInNoRethVRRPMode(t *testing.T) {
	cc := &config.ClusterConfig{
		NoRethVRRP:       true,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg := &config.Config{}

	if strictVIPOwnershipByDefault(cc, cfg) {
		t.Fatal("expected strict VIP ownership to stay off in no-reth-vrrp mode")
	}
}

func TestStrictVIPOwnershipByDefault_DisabledInPrivateRGElectionMode(t *testing.T) {
	cc := &config.ClusterConfig{
		PrivateRGElection: true,
		RedundancyGroups:  []*config.RedundancyGroup{{ID: 1}},
	}
	cfg := &config.Config{}

	if strictVIPOwnershipByDefault(cc, cfg) {
		t.Fatal("expected strict VIP ownership to stay off in private-rg-election mode")
	}
}

func TestSnapshotRethMasterState(t *testing.T) {
	d := newTestDaemon()

	d.getOrCreateRGState(0).SetVRRP("reth0", true)
	s1 := d.getOrCreateRGState(1)
	s1.SetVRRP("reth1", true)
	s1.SetVRRP("reth1.50", true)

	snap := d.snapshotRethMasterState()
	if !snap[0] {
		t.Error("snapshot: RG 0 should be master")
	}
	if !snap[1] {
		t.Error("snapshot: RG 1 should be master (all instances MASTER)")
	}

	// Make RG 1 partial BACKUP.
	s1.SetVRRP("reth1.50", false)
	snap = d.snapshotRethMasterState()
	if snap[1] {
		t.Error("snapshot: RG 1 should not be master (partial BACKUP)")
	}
	if !snap[0] {
		t.Error("snapshot: RG 0 should still be master")
	}
}

func TestRethMasterState_LastEventWinsBug(t *testing.T) {
	// Regression test: the old code used map[int]bool, so setting
	// one interface to BACKUP would clobber another interface's MASTER.
	d := newTestDaemon()
	s := d.getOrCreateRGState(1)

	// Simulate: reth1 goes MASTER, then reth1.50 goes BACKUP.
	s.SetVRRP("reth1", true)
	s.SetVRRP("reth1.50", false)

	// Old code: rethMasterState[1] = false (last event wins = BUG).
	// New code: reth1 is still MASTER.
	if !d.isAnyRethInstanceMaster(1) {
		t.Error("reth1 should still be MASTER despite reth1.50 going BACKUP")
	}
}

func TestRgIDFromVRID(t *testing.T) {
	tests := []struct {
		vrid int
		want int
	}{
		{100, 0},
		{101, 1},
		{102, 2},
		{110, 10},
	}
	for _, tt := range tests {
		got := rgIDFromVRID(tt.vrid)
		if got != tt.want {
			t.Errorf("rgIDFromVRID(%d) = %d, want %d", tt.vrid, got, tt.want)
		}
	}
}

func TestIsRethVRID(t *testing.T) {
	tests := []struct {
		vrid int
		want bool
	}{
		{0, false},  // standalone
		{1, false},  // standalone
		{50, false}, // standalone
		{99, false}, // standalone
		{100, true}, // RETH RG 0
		{101, true}, // RETH RG 1
		{200, true}, // RETH RG 100
	}
	for _, tt := range tests {
		got := isRethVRID(tt.vrid)
		if got != tt.want {
			t.Errorf("isRethVRID(%d) = %v, want %v", tt.vrid, got, tt.want)
		}
	}
}

func TestIsRethVRRPEvent_RequiresImplicitEmptyFamily(t *testing.T) {
	tests := []struct {
		name  string
		event vrrp.VRRPEvent
		want  bool
	}{
		{name: "implicit RETH", event: vrrp.VRRPEvent{GroupID: 101}, want: true},
		{name: "standalone low VRID", event: vrrp.VRRPEvent{Family: "inet", GroupID: 5}, want: false},
		{name: "standalone IPv4 collides numerically with RG", event: vrrp.VRRPEvent{Family: "inet", GroupID: 101}, want: false},
		{name: "standalone IPv6 collides numerically with RG", event: vrrp.VRRPEvent{Family: "inet6", GroupID: 101}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRethVRRPEvent(tt.event); got != tt.want {
				t.Fatalf("isRethVRRPEvent(%+v)=%v, want %v", tt.event, got, tt.want)
			}
		})
	}
}

func TestNonRethVRRPDoesNotPollute(t *testing.T) {
	d := newTestDaemon()

	// Standalone VRRP with GroupID < rethVRIDBase should NOT create
	// rgStates entries or produce valid RG IDs.
	standaloneVRID := 50

	// Verify isRethVRID blocks it.
	if isRethVRID(standaloneVRID) {
		t.Fatal("standalone VRID 50 should not be treated as RETH")
	}

	// Verify no phantom RG state was created.
	d.rgStatesMu.RLock()
	_, exists := d.rgStates[standaloneVRID-rethVRIDBase]
	d.rgStatesMu.RUnlock()
	if exists {
		t.Error("standalone VRRP should not create rgStates entry")
	}

	// RETH VRRP with GroupID >= rethVRIDBase should create entries.
	rethVRID := 100 // RG 0
	if !isRethVRID(rethVRID) {
		t.Fatal("RETH VRID 100 should be treated as RETH")
	}
	rgID := rgIDFromVRID(rethVRID)
	d.getOrCreateRGState(rgID).SetVRRP("reth0", true)

	d.rgStatesMu.RLock()
	_, exists = d.rgStates[0]
	d.rgStatesMu.RUnlock()
	if !exists {
		t.Error("RETH VRRP event should create rgStates entry for RG 0")
	}
	if !d.isRethMasterState(0) {
		t.Error("RG 0 should be master after RETH VRRP MASTER event")
	}
}

func TestBuildZoneRGMap(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust", Interfaces: []string{"reth0.0"}},
				"untrust": {Name: "untrust", Interfaces: []string{"reth1.0"}},
				"dmz":     {Name: "dmz", Interfaces: []string{"ge-0/0/2"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 2},
				"ge-0/0/2": {Name: "ge-0/0/2"}, // no RG
			},
		},
	}

	zoneIDs := map[string]uint16{
		"dmz":     1,
		"trust":   2,
		"untrust": 3,
	}

	m := buildZoneRGMap(cfg, zoneIDs)

	// trust (zone 2) → reth0 → RG 1
	if rgs, ok := m[2]; !ok || len(rgs) != 1 || rgs[0] != 1 {
		t.Errorf("zone 'trust' (ID 2): expected RG set [1], got %v (ok=%v)", rgs, ok)
	}

	// untrust (zone 3) → reth1 → RG 2
	if rgs, ok := m[3]; !ok || len(rgs) != 1 || rgs[0] != 2 {
		t.Errorf("zone 'untrust' (ID 3): expected RG set [2], got %v (ok=%v)", rgs, ok)
	}

	// dmz (zone 1) → ge-0/0/2 → no RG → not in map
	if _, ok := m[1]; ok {
		t.Error("zone 'dmz' (ID 1): should not be in zone RG map (no RG)")
	}
}
func TestBuildZoneFoldRGMapResolvesEachIngressGroup11012(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
		"reth1": {Name: "reth1", RedundancyGroup: 2},
	}}}
	foldRG := buildZoneFoldRGMap(cfg)
	for name, want := range map[string]int{"reth0": 1, "reth1": 2} {
		fold := config.StableIfaceID(name)
		if got, ok := foldRG[fold]; !ok || got != want {
			t.Errorf("fold-to-RG map[%q/%#x] = (%d, %v), want (%d, true)", name, fold, got, ok, want)
		}
	}
}


// TestBuildZoneRGMapSkipsNilZones asserts that a nil zone value in
// cfg.Security.Zones (reachable on the tolerant/programmatic/HA-peer-sync
// config path, the same nil-slot invariant the dataplane SSOT defends) does
// NOT panic the per-RG session-sync apply path. Reverting the `zone == nil`
// guard in buildZoneRGMap makes this test panic (RED-on-revert).
func TestBuildZoneRGMapSkipsNilZones(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1},
			},
		},
	}
	// Inject a nil zone slot post-construction, mirroring the reachable
	// nil-slot invariant exercised by the other nil-safety tests.
	cfg.Security.Zones["bogus"] = nil

	zoneIDs := map[string]uint16{
		"trust": 2,
		"bogus": 9,
	}

	// Must not panic on the nil "bogus" zone.
	m := buildZoneRGMap(cfg, zoneIDs)

	// The healthy zone is still mapped: trust (zone 2) → reth0 → RG 1.
	if rgs, ok := m[2]; !ok || len(rgs) != 1 || rgs[0] != 1 {
		t.Errorf("zone 'trust' (ID 2): expected RG set [1], got %v (ok=%v)", rgs, ok)
	}
	// The nil zone contributes nothing.
	if _, ok := m[9]; ok {
		t.Error("nil zone 'bogus' (ID 9): should not be in zone RG map")
	}
}

// TestBuildZoneRGMapSkipsNilInterfaceValue asserts that a nil interface VALUE
// in cfg.Interfaces.Interfaces (a `(nil, true)` map entry — the comma-ok in
// buildZoneRGMap checks key-presence, not value-non-nil) does NOT panic.
// Reverting the `ifc != nil` clause makes this test panic (RED-on-revert).
func TestBuildZoneRGMapSkipsNilInterfaceValue(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
				"bad":   {Name: "bad", Interfaces: []string{"reth9.0"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1},
				"reth9": nil, // (nil, true) map entry
			},
		},
	}

	zoneIDs := map[string]uint16{"trust": 2, "bad": 5}

	// Must not panic on the nil "reth9" interface value.
	m := buildZoneRGMap(cfg, zoneIDs)

	if rgs, ok := m[2]; !ok || len(rgs) != 1 || rgs[0] != 1 {
		t.Errorf("zone 'trust' (ID 2): expected RG set [1], got %v (ok=%v)", rgs, ok)
	}
	if _, ok := m[5]; ok {
		t.Error("zone 'bad' (ID 5): nil interface value should contribute no RG")
	}
}

// TestRgHasRETHSkipsNilInterfaceValue asserts that a nil interface VALUE in
// cfg.Interfaces.Interfaces does NOT panic rgHasRETH. Reverting the
// `if ifc == nil { continue }` guard makes this test panic (RED-on-revert).
func TestRgHasRETHSkipsNilInterfaceValue(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", RedundancyGroup: 1},
				"nilif": nil, // (nil) map value
			},
		},
	}

	// Must not panic on the nil "nilif" interface value.
	if !rgHasRETH(cfg, 1) {
		t.Error("rgHasRETH(cfg, 1): expected true (reth0 in RG 1)")
	}
	if rgHasRETH(cfg, 2) {
		t.Error("rgHasRETH(cfg, 2): expected false (no interface in RG 2)")
	}
}

func TestBuildZoneRGMapEmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	m := buildZoneRGMap(cfg, nil)
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestRethInterfacesForRG(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 1,
					Units:           map[int]*config.InterfaceUnit{0: {}},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 2,
					Units:           map[int]*config.InterfaceUnit{0: {VlanID: 50}},
				},
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
				},
				"ge-0/0/1": {
					Name:            "ge-0/0/1",
					RedundantParent: "reth1",
				},
			},
		},
	}

	// RG 1 should resolve reth0 → ge-0/0/0 → ge0
	ifaces := rethInterfacesForRG(cfg, 1)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface for RG 1, got %d: %v", len(ifaces), ifaces)
	}

	// RG 2 should resolve reth1 → ge-0/0/1 → ge1.50 (VLAN)
	ifaces2 := rethInterfacesForRG(cfg, 2)
	if len(ifaces2) != 1 {
		t.Fatalf("expected 1 interface for RG 2, got %d: %v", len(ifaces2), ifaces2)
	}

	// RG 3 should return nothing
	ifaces3 := rethInterfacesForRG(cfg, 3)
	if len(ifaces3) != 0 {
		t.Fatalf("expected 0 interfaces for RG 3, got %d", len(ifaces3))
	}
}

func TestReconcileDiscoversClusterGroups(t *testing.T) {
	// Verify that reconcileRGState() discovers RGs from cluster state
	// that haven't yet been created in d.rgStates by VRRP events.
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 100}},
		},
	})

	vm := vrrp.NewManager()

	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		vrrpMgr:  vm,
	}

	// Before reconciliation: no rgStates entries.
	d.rgStatesMu.RLock()
	if len(d.rgStates) != 0 {
		t.Fatalf("expected 0 rgStates entries initially, got %d", len(d.rgStates))
	}
	d.rgStatesMu.RUnlock()

	// Run reconciliation — should discover RG 0 and RG 1 from cluster.
	d.reconcileRGState()

	d.rgStatesMu.RLock()
	if len(d.rgStates) != 2 {
		t.Fatalf("expected 2 rgStates entries after reconciliation, got %d", len(d.rgStates))
	}
	_, hasRG0 := d.rgStates[0]
	_, hasRG1 := d.rgStates[1]
	d.rgStatesMu.RUnlock()

	if !hasRG0 {
		t.Error("reconciliation should have created rgStates entry for RG 0")
	}
	if !hasRG1 {
		t.Error("reconciliation should have created rgStates entry for RG 1")
	}
}

func TestReconcileDiscoversVRRPInstances(t *testing.T) {
	// Verify that reconcileRGState() discovers RGs from VRRP instance
	// states even when cluster hasn't reported that group yet.
	cm := cluster.NewManager(0, 1)
	// No cluster groups configured — but RG 0 should still be
	// discovered from VRRP instance state via the rgVRRP map.

	vm := vrrp.NewManager()

	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		vrrpMgr:  vm,
	}

	// Manually create a RETH VRRP state entry via the event path.
	// GroupID = 100 (= RG 0).
	d.getOrCreateRGState(0).SetVRRP("reth0", true)

	// Verify RG 0 exists in rgStates.
	d.rgStatesMu.RLock()
	if len(d.rgStates) != 1 {
		t.Fatalf("expected 1 rgStates entry, got %d", len(d.rgStates))
	}
	d.rgStatesMu.RUnlock()

	// Add another cluster group that rgStates doesn't have.
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 2, NodePriorities: map[int]int{0: 150}},
		},
	})

	// Reconcile — should discover RG 2 from cluster, keep RG 0.
	d.reconcileRGState()

	d.rgStatesMu.RLock()
	count := len(d.rgStates)
	_, hasRG0 := d.rgStates[0]
	_, hasRG2 := d.rgStates[2]
	d.rgStatesMu.RUnlock()

	if count != 2 {
		t.Fatalf("expected 2 rgStates entries, got %d", count)
	}
	if !hasRG0 {
		t.Error("should have RG 0 from VRRP event")
	}
	if !hasRG2 {
		t.Error("should have RG 2 from cluster discovery")
	}
}
func TestBuildZoneRGMapResolvesRedundantParent11012(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"member-zone": {Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0":     {Name: "reth0", RedundancyGroup: 2},
			"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
		}},
	}
	got := buildZoneRGMap(cfg, map[string]uint16{"member-zone": 9})
	if rgs := got[9]; len(rgs) != 1 || rgs[0] != 2 {
		t.Fatalf("member-backed zone RG set = %v, want [2]", rgs)
	}
}
