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

// TestDHCPv6ReplyAdmitsFollowEffectivePolicy12127 ensures a no-address
// DHCPv6 interface gets a server-reply exception only when its policy permits
// dhcpv6. The unzoned lease-acquisition path remains admitted, while an
// ssh-only zone retains its deny.
func TestDHCPv6ReplyAdmitsFollowEffectivePolicy12127(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
		"ge-0-0-3": {Name: "ge-0-0-3", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"restricted": {
			Name: "restricted", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"dhcp": {
			Name: "dhcp", Interfaces: []string{"ge-0-0-2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"dhcpv6"}},
		},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "virtual-router", Interfaces: []string{"ge-0-0-2.0"}},
	}

	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.V6, []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3"}) {
		t.Fatalf("DHCPv6 backstops = %v, want all restricted and pending unzoned clients", got.V6)
	}
	if !reflect.DeepEqual(got.AdmitV6, []string{"ge-0-0-2", "ge-0-0-3"}) {
		t.Errorf("DHCPv6 reply admits = %v, want permitted zone plus unzoned client only", got.AdmitV6)
	}
	if !reflect.DeepEqual(got.VRFSlavesV6, []string{"ge-0-0-2"}) ||
		!reflect.DeepEqual(got.AdmitVRFSlavesV6, []string{"ge-0-0-2"}) {
		t.Errorf("VRF DHCPv6 backstop/admit = %v/%v, want ge-0-0-2 in both", got.VRFSlavesV6, got.AdmitVRFSlavesV6)
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

// TestZonedDHCPBackstopIncludesNonLifelineManagementVRF11577 covers the
// management binder's fxp*/fab*/em* ownership without a routing-instance stanza.
// Explicit cluster lifelines and fxp0 remain excluded from enforcement.
func TestZonedDHCPBackstopIncludesNonLifelineManagementVRF11577(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0", FabricInterface: "fab0"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
		"fxp1": {Name: "fxp1", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
		"em0":  {Name: "em0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
		"fab0": {Name: "fab0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name: "wan", Interfaces: []string{"fxp0.0", "fxp1.0", "em0.0", "fab0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.V4, []string{"fxp1"}) ||
		!reflect.DeepEqual(got.VRFSlavesV4, []string{"fxp1"}) {
		t.Errorf("management DHCPv4 backstop = %+v, want only enforcing non-lifeline fxp1", got)
	}
	if !reflect.DeepEqual(got.V6, []string{"fxp1"}) ||
		!reflect.DeepEqual(got.VRFSlavesV6, []string{"fxp1"}) {
		t.Errorf("management DHCPv6 backstop = %+v, want only enforcing non-lifeline fxp1", got)
	}
}

// TestZonedDHCPBackstopIncludesTunnelManagerVRF11577 covers a stanza-owned
// tunnel: the tunnel manager binds it, independently of RI interface lists.
func TestZonedDHCPBackstopIncludesTunnelManagerVRF11577(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/1": {
			Name:   "gr-0/0/1",
			Tunnel: &config.TunnelConfig{Name: "gr-0-0-1", RoutingInstance: "blue"},
			Units:  map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name: "wan", Interfaces: []string{"gr-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "virtual-router"}}

	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.V4, []string{"gr-0-0-1"}) ||
		!reflect.DeepEqual(got.VRFSlavesV4, []string{"gr-0-0-1"}) {
		t.Fatalf("tunnel DHCPv4 backstop = %+v, want tunnel manager's VRF-bound device", got)
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
