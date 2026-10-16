package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestInterfaceLinkRefreshQuarantinesRecreatedRow14133 pins the quarantine
// half of #14133: RefreshInterfaceRowsForLink rebuilds interface rows from
// cfg WITHOUT the full build's quarantineCollidingZones scrub, so a link
// recreated inside a StableZoneID-colliding zone is published zoned again.
//
// Fixture uses the verified colliding pair z174/z214 (z214 is the
// later-sorting loser). The seed is hand-built in the PRE-quarantine shape
// the defect needs: both zones published, the z214 interface zoned, and the
// z214 policy present — exactly what a snapshot retained from before a
// quarantine existed (or hand-built by another partial path) can carry.
// A mis-scoped hand-built seed is precisely the reachable state: the full
// build would never publish it, but Refresh copies *current and rebuilds
// only Interfaces/Routes/Fabrics/TunnelEndpoints/Mirrors, so without the
// scrub the rebuilt z214 row stays zoned and the reduced sets stay
// inconsistent (ZoneSetValidated left stale).
//
// FAIL-ON-REVERT: removing the quarantineCollidingZones call from
// RefreshInterfaceRowsForLink leaves the recreated row Zone="z214" with
// z214 absent... or present-but-merged — either way the assertions below
// on the unzoned row and the collision record go RED.
func TestInterfaceLinkRefreshQuarantinesRecreatedRow14133(t *testing.T) {
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
	// linux names default to the Junos name with '-' substituted; the
	// fixture's buildLinkSnapshot seam keys on that name.
	m, requestCount, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-1", 17, 1500)
	_ = requestCount
	// Overwrite the seed with the pre-quarantine shape (see header): both
	// zones, z214 row zoned, no collision recorded.
	m.lastSnapshot.Zones = []ZoneSnapshot{
		{Name: "z174", ID: config.StableZoneID("z174")},
		{Name: "z214", ID: config.StableZoneID("z214")},
	}
	m.lastSnapshot.zoneIDCollisions = nil
	m.lastSnapshot.ZoneSetValidated = true
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}

	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-1")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	for _, row := range m.lastSnapshot.Interfaces {
		if row.Zone == "z214" {
			t.Fatalf("recreated row %q still zoned to quarantined z214: %+v (#14133)", row.Name, row)
		}
		if row.LinuxName == "ge-0-0-1" && row.Zone != "" {
			t.Fatalf("recreated ge-0-0-1 row zone = %q, want unzoned (fail-closed)", row.Zone)
		}
	}
	if len(m.lastSnapshot.zoneIDCollisions) != 1 || m.lastSnapshot.zoneIDCollisions[0].Quarantined != "z214" {
		t.Fatalf("zoneIDCollisions = %+v, want z214 quarantined", m.lastSnapshot.zoneIDCollisions)
	}
	if m.lastSnapshot.ZoneSetValidated {
		t.Fatal("ZoneSetValidated must be false after quarantine")
	}
	for _, z := range m.lastSnapshot.Zones {
		if z.Name == "z214" {
			t.Fatalf("quarantined zone z214 still in published Zones: %+v", m.lastSnapshot.Zones)
		}
	}
}

// TestInterfaceLinkRefreshStampsFreshXfrmDumpFailed14133 pins the second
// half: the refresh sampled liveXfrm with `liveXfrm, _ :=`, retaining the
// previous snapshot's xfrmDumpFailed. UserspaceBoundLinuxInterfaces reads
// that flag off a FRESH build, but the retained snapshot's copy is what
// other snapshot consumers see; a stale false after a failed dump would
// claim kernel evidence the build never had.
//
// FAIL-ON-REVERT: restoring `liveXfrm, _ :=` leaves next.xfrmDumpFailed
// at the seed's false and this goes RED.
func TestInterfaceLinkRefreshStampsFreshXfrmDumpFailed14133(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	if m.lastSnapshot.xfrmDumpFailed {
		t.Fatal("premise: seed must start with xfrmDumpFailed=false")
	}
	prev := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = prev })
	liveXfrmNetdevs = func() (map[string]bool, error) {
		return map[string]bool{}, errors.New("RTM_GETLINK: injected dump failure 14133")
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	if !m.lastSnapshot.xfrmDumpFailed {
		t.Fatal("retained snapshot lost the fresh xfrm dump failure status (#14133)")
	}
}

// TestInterfaceLinkRefreshAttachesRecreatedIfindex14133 pins the third
// half: an ifindex change publishes a row with no XDP shim attached,
// because only Compile's CompileUserspaceShim attaches and the Rust
// helper never does. The refresh must attempt AttachXDP for the new
// ifindex before publishing.
//
// FAIL-ON-REVERT: removing reconcileInterfaceAttachmentsForRefreshLocked
// leaves attaches empty and this goes RED. The hook replaces
// bpfShim.AttachXDP (unloaded in tests, would error "not loaded").
func TestInterfaceLinkRefreshAttachesRecreatedIfindex14133(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	var attaches []int
	m.attachInterfaceXDPHook = func(ifindex int, forceGeneric bool) error {
		attaches = append(attaches, ifindex)
		return nil
	}
	setLink(29, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh = (%t, %v), want publish", published, err)
	}
	found := false
	for _, idx := range attaches {
		if idx == 29 {
			found = true
		}
		if idx == 17 {
			t.Fatalf("attach attempted for the OLD ifindex 17; want only the recreated 29: %v", attaches)
		}
	}
	if !found {
		t.Fatalf("no AttachXDP attempt for recreated ifindex 29; attaches=%v (#14133)", attaches)
	}
	// Control: an unchanged refresh must not re-attach.
	attaches = nil
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil {
		t.Fatalf("unchanged refresh err = %v", err)
	}
	_ = published
	if len(attaches) != 0 {
		t.Fatalf("unchanged refresh re-attached: %v", attaches)
	}
}
