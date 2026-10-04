package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestZonedDHCPBackstopSurvivesLeaseTransition11577 repros #11577: a DHCP
// address can appear before the debounced reapply, while a zone has no
// address-scoped drop in its published rules. The interface backstop must
// therefore be present both before and after the lease becomes resolvable.
// FAIL-ON-REVERT: restoring the old unzoned-only builder leaves both lists
// empty for this enforcing zoned DHCP unit.
func TestZonedDHCPBackstopSurvivesLeaseTransition11577(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
	}
	leased := []InterfaceSnapshot{{
		Name: "ge-0-0-1.0", Zone: "wan", IsUnit: true, LinuxName: "ge-0-0-1",
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.7/24"},
			{Family: "inet6", Address: "2001:db8::7/64"},
		},
	}}

	for _, tc := range []struct {
		name  string
		snaps []InterfaceSnapshot
	}{
		{name: "addressless before first lease"},
		{name: "lease visible while debounce is pending", snaps: leased},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backstops := BuildDHCPHostInboundBackstopNetdevs(cfg, tc.snaps)
			if !containsString(backstops.V4, "ge-0-0-1") || !containsString(backstops.V6, "ge-0-0-1") {
				t.Fatalf("DHCP backstop v4/v6 = %v/%v, want ge-0-0-1 in both families throughout lease transition", backstops.V4, backstops.V6)
			}
		})
	}
}

// TestZonedDHCPBackstopScopesOnlyEnforcingFamilies11577 keeps the persistent
// guard narrow: any-service and lifeline interfaces remain excluded, while a
// DHCP family in a restricted zone (including a VRF slave) stays protected.
func TestZonedDHCPBackstopScopesOnlyEnforcingFamilies11577(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
		"ge-0-0-3": {Name: "ge-0-0-3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"ge-0-0-4": {Name: "ge-0-0-4", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"ge-0-0-6": {Name: "ge-0-0-6", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"ge-0-0-5": {Name: "ge-0-0-5", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true},
		}},
		"ge-0-0-7": {Name: "ge-0-0-7", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name: "wan",
			Interfaces: []string{
				"ge-0-0-1.0", "ge-0-0-3.0", "ge-0-0-4.0",
				"ge-0-0-5.0", "ge-0-0-6.0", "ge-0-0-7.0", "fxp0.0",
			},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0-0-3.0": {SystemServices: []string{"any-service"}},
			},
		},
		"open": {
			Name: "open", Interfaces: []string{"ge-0-0-2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"any-service"}},
		},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "tenant", InstanceType: "virtual-router", Interfaces: []string{"ge-0-0-5.0", "ge-0-0-7.0"}},
		{Name: "tenant-overlap", InstanceType: "virtual-router", Interfaces: []string{"ge-0-0-5.0"}},
		{Name: "forwarding", InstanceType: "forwarding", Interfaces: []string{"ge-0-0-6.0"}},
	}

	backstops := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(backstops.V4, []string{"ge-0-0-1", "ge-0-0-4", "ge-0-0-6", "ge-0-0-7"}) {
		t.Errorf("DHCPv4 backstop = %v, want restricted DHCP units including non-VRF forwarding member", backstops.V4)
	}
	if !reflect.DeepEqual(backstops.V6, []string{"ge-0-0-1", "ge-0-0-5"}) {
		t.Errorf("DHCPv6 backstop = %v, want restricted zone plus its VRF slave", backstops.V6)
	}
	if !reflect.DeepEqual(backstops.VRFSlavesV4, []string{"ge-0-0-7"}) || len(backstops.VRFSlavesV6) != 0 {
		t.Errorf("configured VRF DHCP subset = %v/%v, want [ge-0-0-7]/[]; the conflicted device must be excluded", backstops.VRFSlavesV4, backstops.VRFSlavesV6)
	}
}

// TestZonedDHCPBackstopFansDownBareMemberVLAN11577 uses the complete RI
// device-key fan-down that drives the production binder. The VLAN ID differs
// from the logical unit number so a raw-key or unit-number lookup cannot pass.
func TestZonedDHCPBackstopFansDownBareMemberVLAN11577(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, VlanID: 200, DHCP: true, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/1.100"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/1"}},
	}
	leased := []InterfaceSnapshot{{
		Name: "ge-0/0/1.100", Zone: "wan", IsUnit: true, LinuxName: "ge-0-0-1.200",
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.7/24"},
			{Family: "inet6", Address: "2001:db8::7/64"},
		},
	}}
	for _, snaps := range [][]InterfaceSnapshot{nil, leased} {
		backstops := BuildDHCPHostInboundBackstopNetdevs(cfg, snaps)
		if !containsString(backstops.VRFSlavesV4, "ge-0-0-1.200") ||
			!containsString(backstops.VRFSlavesV6, "ge-0-0-1.200") {
			t.Errorf("VRF DHCP backstops v4/v6 = %v/%v, want VLAN child before and after address appearance", backstops.VRFSlavesV4, backstops.VRFSlavesV6)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
