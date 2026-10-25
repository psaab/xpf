package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

// TestInterfaceLinkRefreshQuarantinesRecreatedRow14133 pins the quarantine
// half of #14133: RefreshInterfaceRowsForLink rebuilds interface rows from
// cfg WITHOUT the full build's quarantineCollidingZones scrub, so a link
// recreated inside a StableZoneID-colliding zone is published zoned again.
//
// Fixture uses the verified colliding pair zzq17760/zzq8100 (zzq8100 is the
// later-sorting loser). The seed is hand-built in the PRE-quarantine shape
// the defect needs: both zones published, the zzq8100 interface zoned, and the
// zzq8100 policy present — exactly what a snapshot retained from before a
// quarantine existed (or hand-built by another partial path) can carry.
// A mis-scoped hand-built seed is precisely the reachable state: the full
// build would never publish it, but Refresh copies *current and rebuilds
// only Interfaces/Routes/Fabrics/TunnelEndpoints/Mirrors, so without the
// scrub the rebuilt zzq8100 row stays zoned and the reduced sets stay
// inconsistent (ZoneSetValidated left stale).
//
// FAIL-ON-REVERT: removing the quarantineCollidingZones call from
// RefreshInterfaceRowsForLink leaves the recreated row Zone="zzq8100" with
// zzq8100 absent... or present-but-merged — either way the assertions below
// on the unzoned row and the collision record go RED.
func TestInterfaceLinkRefreshQuarantinesRecreatedRow14133(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {},
			"ge-0/0/1": {},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"zzq17760": {Name: "zzq17760", Interfaces: []string{"ge-0/0/0"}},
			"zzq8100":  {Name: "zzq8100", Interfaces: []string{"ge-0/0/1"}},
		}},
	}
	// linux names default to the Junos name with '-' substituted; the
	// fixture's buildLinkSnapshot seam keys on that name.
	m, requestCount, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-1", 17, 1500)
	_ = requestCount
	// Overwrite the seed with the pre-quarantine shape (see header): both
	// zones, zzq8100 row zoned, no collision recorded.
	m.lastSnapshot.Zones = []ZoneSnapshot{
		{Name: "zzq17760", ID: config.StableZoneID("zzq17760")},
		{Name: "zzq8100", ID: config.StableZoneID("zzq8100")},
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
		if row.Zone == "zzq8100" {
			t.Fatalf("recreated row %q still zoned to quarantined zzq8100: %+v (#14133)", row.Name, row)
		}
		if row.LinuxName == "ge-0-0-1" && row.Zone != "" {
			t.Fatalf("recreated ge-0-0-1 row zone = %q, want unzoned (fail-closed)", row.Zone)
		}
	}
	if len(m.lastSnapshot.zoneIDCollisions) != 1 || m.lastSnapshot.zoneIDCollisions[0].Quarantined != "zzq8100" {
		t.Fatalf("zoneIDCollisions = %+v, want zzq8100 quarantined", m.lastSnapshot.zoneIDCollisions)
	}
	if m.lastSnapshot.ZoneSetValidated {
		t.Fatal("ZoneSetValidated must be false after quarantine")
	}
	for _, z := range m.lastSnapshot.Zones {
		if z.Name == "zzq8100" {
			t.Fatalf("quarantined zone zzq8100 still in published Zones: %+v", m.lastSnapshot.Zones)
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
	// Control (#15042): an unchanged refresh must not re-attach. The
	// hook now simulates the production tracked state by reporting the
	// ifindex already attached, which reconcile treats as attached —
	// a second successful attach (e.g. if the pre-dedup reconcile ran
	// twice) would record a duplicate here via the closure below.
	attaches = nil
	m.attachInterfaceXDPHook = func(ifindex int, forceGeneric bool) error {
		if ifindex == 29 {
			return errAlreadyAttachedForTest15042
		}
		attaches = append(attaches, ifindex)
		return nil
	}
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil {
		t.Fatalf("unchanged refresh err = %v", err)
	}
	if published {
		t.Fatalf("unchanged refresh published; want dedup no-publish (#15042)")
	}
	if len(attaches) != 0 {
		t.Fatalf("unchanged refresh re-attached: %v", attaches)
	}
}

// TestRefreshAttachAdmission16637 pins #16637: the refresh/revalidate
// reconcile must admit exactly what Compile admits. Before the fix it
// attached the shim to every untracked ingress ifindex — the raw-L3
// wgN TUN compileZones' #8279 gate refuses, administratively disabled
// interfaces, and non-tunnel VLAN children attachUserspaceShimXDP skips.
//
// FAIL-ON-REVERT: dropping refreshAttachAdmission from the reconcile
// (or any arm of it) lets the matching refused ifindex below attach and
// this goes RED. The positive controls (plain Ethernet owner, disabled
// unit-0 sibling on an enabled base, unresolvable link, VLAN tunnel)
// must still attach — a predicate that refuses everything would pass
// the refusals and fail these.
func TestRefreshAttachAdmission16637(t *testing.T) {
	prevLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = prevLookup })
	encapByName := map[string]string{
		"ge-0-0-0": "ether",
		"wg1408":   "none",
		"ge-0-0-2": "ether",
		"ge-0-0-3": "ether",
		"ge-0-0-5": "ether",
	}
	linkByNameFn = func(name string) (netlink.Link, error) {
		encap, ok := encapByName[name]
		if !ok {
			return nil, errors.New("no such link")
		}
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, EncapType: encap}}, nil
	}

	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", LinuxName: "ge-0-0-0", Ifindex: 10, Zone: "trust"},
		{Name: "wg1408", LinuxName: "wg1408", Ifindex: 40, Zone: "trust"},
		{Name: "wg1408.0", LinuxName: "wg1408", Ifindex: 40, ParentIfindex: 40, Zone: "trust", Tunnel: true, IsUnit: true},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Ifindex: 13, Zone: "trust", AdminDisabled: true},
		{Name: "ge-0/0/3.100", LinuxName: "ge-0-0-3.100", Ifindex: 31, ParentIfindex: 30, ParentLinuxName: "ge-0-0-3", VLANID: 100, Zone: "trust", IsUnit: true},
		{Name: "ge-0/0/3", LinuxName: "ge-0-0-3", Ifindex: 30, Zone: "trust"},
		{Name: "ge-0/0/5", LinuxName: "ge-0-0-5", Ifindex: 50, Zone: "trust"},
		{Name: "ge-0/0/5.0", LinuxName: "ge-0-0-5", Ifindex: 50, ParentIfindex: 50, Zone: "trust", AdminDisabled: true, IsUnit: true},
		{Name: "ge-0/0/9", LinuxName: "ge-0-0-9", Ifindex: 90, Zone: "trust"},
	}}
	m := New()
	var attaches []int
	m.attachInterfaceXDPHook = func(ifindex int, forceGeneric bool) error {
		attaches = append(attaches, ifindex)
		return nil
	}
	m.reconcileInterfaceAttachmentsForRefreshLocked(snap)
	attached := map[int]bool{}
	for _, idx := range attaches {
		attached[idx] = true
	}
	for _, refused := range []int{40, 13, 31} {
		if attached[refused] {
			t.Errorf("ifindex %d attached but must be refused (#16637); attaches=%v", refused, attaches)
		}
	}
	for _, want := range []int{10, 30, 50, 90} {
		if !attached[want] {
			t.Errorf("ifindex %d not attached but must be admitted (#16637); attaches=%v", want, attaches)
		}
	}
	if !dataplane.ShimAttachRefused(&netlink.Device{LinkAttrs: netlink.LinkAttrs{EncapType: "none"}}, nil) {
		t.Error("ShimAttachRefused(none) = false, want true (#8279/#16637)")
	}
	if dataplane.ShimAttachRefused(&netlink.Device{LinkAttrs: netlink.LinkAttrs{EncapType: "ether"}}, nil) {
		t.Error("ShimAttachRefused(ether) = true, want false")
	}
	if dataplane.ShimAttachRefused(nil, errors.New("lookup failed")) {
		t.Error("ShimAttachRefused(unresolvable) = true, want false (unknown keeps prior behaviour)")
	}
}
