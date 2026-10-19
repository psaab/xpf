package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15763: a logical-unit `disable` must not hold the #10751 early
// host-input barrier (HostInboundPendingIntent). Config-walking loops
// checked only iface.Disable, so a zone whose only enforcement-relevant
// units are unit-disabled (one addressed, one DHCP, one VRRP) was still
// reported addressless-pending forever, and disabled-unit VIPs leaked
// into host-inbound deny scope.
func TestUnitDisableDoesNotHoldHostInboundPendingIntent(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0, Disable: true, Addresses: []string{"10.0.0.1/24"}},
						1: {Number: 1, Disable: true, VlanID: 10, DHCP: true},
						2: {Number: 2, VlanID: 20, Addresses: []string{"10.0.20.1/24"}},
						3: {Number: 3, Disable: true, VlanID: 30, Addresses: []string{"10.0.30.1/24"}, VRRPGroups: map[string]*config.VRRPGroup{"10.0.30.1/24": {ID: 30, VirtualAddresses: []string{"10.0.30.254"}}}},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"disabled-zone": {
					Name:       "disabled-zone",
					Interfaces: []string{"ge-0/0/0.0"},
					HostInboundTraffic: &config.HostInboundTraffic{
						SystemServices: []string{"ping"},
					},
				},
				"disabled-vip-zone": {
					Name:       "disabled-vip-zone",
					Interfaces: []string{"ge-0/0/0.3"},
					HostInboundTraffic: &config.HostInboundTraffic{
						SystemServices: []string{"ping"},
					},
				},
				"active-zone": {
					Name:       "active-zone",
					Interfaces: []string{"ge-0/0/0.1", "ge-0/0/0.2"},
					HostInboundTraffic: &config.HostInboundTraffic{
						SystemServices: []string{"ping"},
					},
				},
			},
		},
	}
	snaps := buildInterfaceSnapshots(cfg)
	if HostInboundPendingIntentFromSnapshots(cfg, snaps) {
		t.Errorf("pending intent held by unit-disabled units only; want false")
	}
	if got := addresslessEnforcingZonesFromSnapshots(cfg, snaps); len(got) != 0 {
		t.Errorf("addresslessEnforcingZones = %+v, want none (disabled zones/units excluded)", got)
	}
	if got := addresslessEnforcingInterfacesFromSnapshots(cfg, snaps); len(got) != 0 {
		t.Errorf("addresslessEnforcingInterfaces = %+v, want none (unit 1 DHCP is disabled)", got)
	}
	// Disabled units must contribute no host-inbound deny scope: neither
	// the disabled-zone static address nor disabled-unit VRRP VIPs,
	// while the enabled sibling still scopes.
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	for _, v := range views {
		for _, a := range v.V4Addrs {
			switch a {
			case "10.0.0.1", "10.0.30.1", "10.0.30.254":
				t.Errorf("disabled-unit address/VIP %s leaked into zone %s view: %v", a, v.Zone, v.V4Addrs)
			}
		}
	}
	uv4, _ := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	for _, a := range uv4 {
		if a == "10.0.30.254" {
			t.Errorf("disabled unit 3 VIP leaked into unzoned addresses: %v", uv4)
		}
	}
	foundActive := false
	for _, v := range views {
		if v.Zone != "active-zone" {
			continue
		}
		for _, a := range v.V4Addrs {
			if a == "10.0.20.1" {
				foundActive = true
			}
		}
	}
	if !foundActive {
		t.Errorf("active-zone should retain enabled unit 2 address 10.0.20.1: %+v", views)
	}
	// DHCP backstops for the disabled DHCP unit must not be emitted.
	bs := BuildDHCPHostInboundBackstopNetdevs(cfg, snaps)
	if len(bs.V4)+len(bs.V6)+len(bs.VRFSlavesV4)+len(bs.VRFSlavesV6) != 0 {
		t.Errorf("DHCP backstops = %+v, want none (only DHCP is on disabled unit 1)", bs)
	}

	// Control: re-enabling the DHCP unit must restore pending intent.
	cfg.Interfaces.Interfaces["ge-0/0/0"].Units[1].Disable = false
	snaps = buildInterfaceSnapshots(cfg)
	if !HostInboundPendingIntentFromSnapshots(cfg, snaps) {
		t.Errorf("pending intent = false after re-enabling DHCP unit 1, want true")
	}
	bs = BuildDHCPHostInboundBackstopNetdevs(cfg, snaps)
	if len(bs.V4) == 0 {
		t.Errorf("DHCP backstops after re-enable = %+v, want V4 backstop for unit 1", bs)
	}
}
