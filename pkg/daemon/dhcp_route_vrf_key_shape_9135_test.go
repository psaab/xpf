package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #9135: dhcpRouteVRFMap is the PRODUCER side of the #8963 remedy, and it keyed
// on the routing instance's `interface` list VERBATIM — i.e. the Junos SLASH
// spelling the compiler stores (`ge-0/0/1.0`). The CONSUMER looks the map up by
// `lease.Interface`, which is `config.DHCPLeaseIfName` = LinuxIfName, i.e. the
// DASH spelling (`ge-0-0-1`). So the #8963 fix was INERT for the canonical Junos
// spelling: every VRF-attached DHCP route fell back to `vrf == ""` and was
// emitted in the DEFAULT context — precisely the behaviour #8963 was filed
// against.
//
// WHY THE #8963 TEST DID NOT SEE THIS: it lives in pkg/frr and hand-builds
// `frr.DHCPRoute{VRF: "vrf1"}` literals, so it exercises the RENDERER with the
// map's answer already supplied. The map is upstream of its first line. The
// fixture's shape is the reason the defect survived the fix, so these cells
// drive collectDHCPRoutes — the real producer/consumer pair — and never
// construct a DHCPRoute.
func TestDHCPRouteVRFMapKeyShape9135(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		// Subject: canonical Junos SLASH spelling in the instance member list.
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
		// Control 1: a default-context DHCP interface must stay in the
		// default context. Without it, a fix that stamped an instance name
		// unconditionally would pass the subject and break every WAN box.
		"set interfaces ge-0/0/2 unit 0 family inet dhcp",
		// Subject 2: a TAGGED unit. The lease is keyed `ge-0-0-3.50` (VLAN ID,
		// not unit number — config.DHCPLeaseIfName), so stripping the unit off
		// `ge-0/0/3.50` is not enough on its own.
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 50 vlan-id 50",
		"set interfaces ge-0/0/3 unit 50 family inet dhcp",
		"set routing-instances tenant-b instance-type virtual-router",
		"set routing-instances tenant-b interface ge-0/0/3.50",
		// Control 2: the DASH spelling was the ONLY spelling the map resolved
		// before this fix. It must keep resolving — both spellings are legal
		// (#8829), and a fix that canonicalised in the other direction would
		// trade one miss for another.
		"set interfaces ge-0/0/4 unit 0 family inet dhcp",
		"set routing-instances tenant-c instance-type virtual-router",
		"set routing-instances tenant-c interface ge-0-0-4.0",
		// Subject 3 (#9063 reading): the member names the WHOLE DEVICE, so it
		// claims every unit on it. The tagged unit's lease is keyed by VLAN ID,
		// a spelling the device name alone cannot produce.
		"set interfaces ge-0/0/5 vlan-tagging",
		"set interfaces ge-0/0/5 unit 60 vlan-id 60",
		"set interfaces ge-0/0/5 unit 60 family inet dhcp",
		"set routing-instances tenant-d instance-type virtual-router",
		"set routing-instances tenant-d interface ge-0/0/5",
		// Subject 4: the `interfaces` stanza and the instance member list are
		// authored in DIFFERENT spellings — both are legal (#8829) and nothing
		// makes them agree. The unit (and so the VLAN ID) must still be found.
		"set interfaces ge-0/0/6 vlan-tagging",
		"set interfaces ge-0/0/6 unit 70 vlan-id 70",
		"set interfaces ge-0/0/6 unit 70 family inet dhcp",
		"set routing-instances tenant-e instance-type virtual-router",
		"set routing-instances tenant-e interface ge-0-0-6.70",
		// Subject 5: a whole-device member with NO `interfaces` stanza. Legal
		// (bindRoutingInstanceMembers tolerates a member absent on this
		// chassis) and also the transient shape between deleting the stanza
		// and the DHCP client reconcile retiring the lease — so a lease can
		// still be present while no unit is knowable.
		"set routing-instances tenant-f instance-type virtual-router",
		"set routing-instances tenant-f interface ge-0/0/7",
	})

	mgr := dhcp.NewManagerForTesting(nil)
	seed := func(iface, gw string) {
		mgr.SeedLeaseForTesting(iface, dhcp.AFInet, &dhcp.Lease{
			Interface: iface,
			Family:    dhcp.AFInet,
			Address:   netip.MustParsePrefix("10.0.0.2/24"),
			Gateway:   netip.MustParseAddr(gw),
		})
	}
	seed("ge-0-0-1", "10.0.1.1")
	seed("ge-0-0-2", "10.0.2.1")
	seed("ge-0-0-3.50", "10.0.3.1")
	seed("ge-0-0-4", "10.0.4.1")
	seed("ge-0-0-5.60", "10.0.5.1")
	seed("ge-0-0-6.70", "10.0.6.1")
	seed("ge-0-0-7", "10.0.7.1")

	d := &Daemon{store: store, dhcp: mgr}
	routes := d.collectDHCPRoutes()
	if len(routes) != 7 {
		t.Fatalf("NON-VACUITY: expected 7 DHCP routes (one per seeded lease), got %d: %+v\n"+
			"Every assertion below is about the VRF field of a route that must exist; "+
			"with routes missing, a green run would prove nothing.", len(routes), routes)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[r.Interface] = r.VRF
	}

	for _, tc := range []struct {
		iface, wantVRF, why string
	}{
		{"ge-0-0-1", "tenant-a",
			"SUBJECT: the instance names its member in the canonical Junos slash " +
				"spelling `ge-0/0/1.0`; the lease is keyed `ge-0-0-1`. Keying the map " +
				"on the raw member makes the #8963 remedy inert for that spelling."},
		{"ge-0-0-3.50", "tenant-b",
			"SUBJECT: a TAGGED unit. The lease key carries the VLAN ID " +
				"(config.DHCPLeaseIfName), so the map must offer `ge-0-0-3.50` and not " +
				"only the unit-stripped base."},
		{"ge-0-0-2", "",
			"CONTROL: a DHCP interface in no routing instance must render in the " +
				"DEFAULT context."},
		{"ge-0-0-4", "tenant-c",
			"CONTROL: the DASH spelling resolved before this fix and must keep " +
				"resolving — both spellings are legal (#8829)."},
		{"ge-0-0-5.60", "tenant-d",
			"SUBJECT: the member names the WHOLE DEVICE `ge-0/0/5`, which claims " +
				"every unit on it; the tagged unit's lease is keyed `ge-0-0-5.60`."},
		{"ge-0-0-7", "tenant-f",
			"SUBJECT: a whole-device member whose `interfaces` stanza is absent. " +
				"No unit is knowable, so the device name is the only key a lease " +
				"can present and it must still be offered."},
		{"ge-0-0-6.70", "tenant-e",
			"SUBJECT: `interfaces ge-0/0/6` (slash) vs `interface ge-0-0-6.70` " +
				"(dash) in the instance. The unit lookup must match across " +
				"spellings or the VLAN-ID suffix is lost and the key misses."},
	} {
		if got[tc.iface] != tc.wantVRF {
			t.Errorf("#9135 %s\n  collectDHCPRoutes VRF for %s = %q, want %q",
				tc.why, tc.iface, got[tc.iface], tc.wantVRF)
		}
	}
}

// WIRING BIND. The cell above drives collectDHCPRoutes directly, which says
// nothing about whether its answer reaches FRR. Measured while fixing #9135:
// replacing `DHCPRoutes: d.collectDHCPRoutes()` in assembleFRRConfig with
// `nil` killed ZERO tests in this package — the whole DHCP-route contribution
// could be severed and the Go suite stayed green. The renderer-side cells live
// in pkg/frr and hand-build DHCPRoute literals, so they are upstream-blind by
// construction; this is the only place the seam can be observed.
//
// It asserts the ROUTE and its VRF, not just a non-empty slice: a fix that
// turns MISSING into EMPTY would satisfy a length check while inverting the
// failure from detectable to plausible.
func TestAssembleFRRConfigCarriesDHCPRoutes9135(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
	})
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedLeaseForTesting("ge-0-0-1", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-1",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("10.0.1.2/24"),
		Gateway:   netip.MustParseAddr("10.0.1.1"),
	})
	d := &Daemon{store: store, dhcp: mgr}
	fc := d.assembleFRRConfig(store.ActiveConfig(), nil)
	if fc == nil {
		t.Fatal("assembleFRRConfig returned nil")
	}
	found := false
	for _, dr := range fc.DHCPRoutes {
		if dr.Interface == "ge-0-0-1" && dr.Gateway == "10.0.1.1" {
			found = true
			if dr.VRF != "tenant-a" {
				t.Errorf("the DHCP route reached FullConfig but lost its instance: "+
					"VRF = %q, want %q", dr.VRF, "tenant-a")
			}
		}
	}
	if !found {
		t.Errorf("assembleFRRConfig did not carry the DHCP-learned route into "+
			"FullConfig.DHCPRoutes, so nothing the daemon learned by DHCP reaches "+
			"the managed frr.conf at all.\n  got %d routes: %+v",
			len(fc.DHCPRoutes), fc.DHCPRoutes)
	}
}
