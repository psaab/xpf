package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14964: rebuild paths preserve both full-build quarantines.
//
// Refresh and the apply-time rebuild copy a retained snapshot whose
// Zones/Policies/SourceNAT are already reduced by the full build. Rebuilding
// Interface rows from configuration revalidates the live ifindex and addresses,
// so both rebuilds must re-apply zone quarantine and SNAT overlap quarantine
// before publishing. Otherwise a recreated interface can resurrect a
// quarantined zone or un-quarantine an overlapping SNAT pool.

func snatQuarantineConfig14964(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{overlapEgress + "/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/2.0"}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"P": {Name: "P", Addresses: []string{overlapEgress}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs-iface", FromZone: "lan", ToZone: "wan", Rules: []*config.NATRule{{
			Name: "iface-snat",
			Then: config.NATThen{Type: config.NATSource, Interface: true},
		}}},
		{Name: "rs-pool", FromZone: "lan", ToZone: "wan", Rules: []*config.NATRule{{
			Name: "pool-snat",
			Then: config.NATThen{Type: config.NATSource, PoolName: "P"},
		}}},
	}
	return cfg
}

func poolRule14964(t *testing.T, snap *ConfigSnapshot) *SourceNATRuleSnapshot {
	t.Helper()
	for i := range snap.SourceNAT {
		if !snap.SourceNAT[i].InterfaceMode && snap.SourceNAT[i].PoolName == "P" {
			return &snap.SourceNAT[i]
		}
	}
	t.Fatal("snapshot has no pool-snat rule")
	return nil
}

func TestInterfaceLinkRefreshPreservesSNATOverlapQuarantine14964(t *testing.T) {
	cfg := snatQuarantineConfig14964(t)
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-2", 17, 1500)
	if !poolRule14964(t, m.lastSnapshot).PoolUnusable {
		t.Fatal("premise: full-built seed must already quarantine the overlapping SNAT pool")
	}
	// Simulate the pre-fix publication defect: the retained SourceNAT slice
	// has lost its quarantine. Refresh must restore it on the fresh snapshot.
	for i := range m.lastSnapshot.SourceNAT {
		m.lastSnapshot.SourceNAT[i].PoolUnusable = false
		m.lastSnapshot.SourceNAT[i].PoolUnusableReason = ""
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-2")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	pool := poolRule14964(t, m.lastSnapshot)
	if !pool.PoolUnusable || pool.PoolUnusableReason != poolUnusableReasonIfaceOverlap {
		t.Fatalf("pool quarantine = (%t, %q), want (%t, %q)", pool.PoolUnusable, pool.PoolUnusableReason, true, poolUnusableReasonIfaceOverlap)
	}
}

func TestRebuildDerivedSectionsPreservesSNATOverlapQuarantine14964(t *testing.T) {
	cfg := snatQuarantineConfig14964(t)
	defer stubLinkSnapshot5619(t, map[string]int{"ge-0-0-2": 17})()
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	if !poolRule14964(t, snap).PoolUnusable {
		t.Fatal("premise: full-built snapshot must already quarantine the overlapping SNAT pool")
	}
	// A publish copy may have lost the quarantine while retaining the same
	// NAT shape. Moving the interface forces the derived-section rebuild.
	for i := range snap.SourceNAT {
		snap.SourceNAT[i].PoolUnusable = false
		snap.SourceNAT[i].PoolUnusableReason = ""
	}
	for i := range snap.Interfaces {
		if snap.Interfaces[i].Ifindex == 17 {
			snap.Interfaces[i].Ifindex = 99
		}
	}
	// A retained slice must not be mutated by the publish copy's reporter.
	retainedBefore := append([]SourceNATRuleSnapshot(nil), snap.SourceNAT...)
	m := New()
	m.prepareSnapshotForApply(snap)
	if !poolRule14964(t, snap).PoolUnusable {
		t.Fatal("apply-time rebuild lost the #7717 SNAT pool overlap quarantine")
	}
	for i := range retainedBefore {
		if retainedBefore[i].PoolUnusable {
			t.Fatalf("apply-time rebuild mutated retained pool row %+v", retainedBefore[i])
		}
	}
}

func TestInterfaceLinkRefreshZoneQuarantineControl14964(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide")
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {},
			"ge-0/0/1": {},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"z174": {Name: "z174", Interfaces: []string{"ge-0/0/0"}},
			"z214": {Name: "z214", Interfaces: []string{"ge-0/0/1"}},
		}},
	}
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-1", 17, 1500)
	// Pre-quarantine retained shape: both zones present and validated.
	m.lastSnapshot.Zones = []ZoneSnapshot{
		{Name: "z174", ID: config.StableZoneID("z174")},
		{Name: "z214", ID: config.StableZoneID("z214")},
	}
	m.lastSnapshot.zoneIDCollisions = nil
	m.lastSnapshot.ZoneSetValidated = true
	if hash, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = hash
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-1")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	if len(m.lastSnapshot.zoneIDCollisions) != 1 || m.lastSnapshot.zoneIDCollisions[0].Quarantined != "z214" {
		t.Fatalf("zone collisions = %+v, want z214 quarantined", m.lastSnapshot.zoneIDCollisions)
	}
	if m.lastSnapshot.ZoneSetValidated {
		t.Fatal("ZoneSetValidated must be false while a zone is quarantined")
	}
	for _, z := range m.lastSnapshot.Zones {
		if z.Name == "z214" {
			t.Fatalf("quarantined zone z214 still published: %+v", m.lastSnapshot.Zones)
		}
	}
	for _, row := range m.lastSnapshot.Interfaces {
		if row.Zone == "z214" {
			t.Fatalf("interface %q remains bound to quarantined zone z214", row.Name)
		}
	}
}

func TestInterfaceLinkRefreshPreservesPriorZoneQuarantine14964(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	m.lastSnapshot.zoneIDCollisions = []ZoneIDCollision{{ID: config.StableZoneID("z214"), Survivor: "z174", Quarantined: "z214"}}
	m.lastSnapshot.ZoneSetValidated = false
	if hash, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = hash
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	if m.lastSnapshot.ZoneSetValidated {
		t.Fatal("ZoneSetValidated flipped true on an already-reduced quarantined snapshot (#14964)")
	}
	if len(m.lastSnapshot.zoneIDCollisions) != 1 || m.lastSnapshot.zoneIDCollisions[0].Quarantined != "z214" {
		t.Fatalf("zone collisions cleared: %+v", m.lastSnapshot.zoneIDCollisions)
	}
}

func TestInterfaceLinkRefreshCleanZoneStaysValidated14964(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	if !m.lastSnapshot.ZoneSetValidated {
		t.Fatal("premise: clean seed must be validated")
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	if !m.lastSnapshot.ZoneSetValidated || len(m.lastSnapshot.zoneIDCollisions) != 0 {
		t.Fatalf("clean refresh validated=%t collisions=%+v, want validated with no collisions", m.lastSnapshot.ZoneSetValidated, m.lastSnapshot.zoneIDCollisions)
	}
	for _, row := range m.lastSnapshot.Interfaces {
		if row.Ifindex == 29 && row.Zone != "trust" {
			t.Fatalf("clean recreated row zone = %q, want trust", row.Zone)
		}
	}
}
