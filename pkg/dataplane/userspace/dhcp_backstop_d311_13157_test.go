package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Regression #13157 (D3-11): VRF-enslaved unzoned/quarantined DHCP units must
// get sdifname backstop+admit; shared-netdev zoned-deny must suppress unzoned
// admit; disabled interfaces must emit nothing.

func mk13157(units map[string]*config.InterfaceUnit, zones map[string]*config.ZoneConfig, ris []*config.RoutingInstanceConfig) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = make(map[string]*config.InterfaceConfig)
	for name, u := range units {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{Name: name, Units: map[int]*config.InterfaceUnit{0: u}}
	}
	cfg.Security.Zones = zones
	cfg.RoutingInstances = ris
	return cfg
}

func TestD311_13157_VRFUnzoned(t *testing.T) {
	cfg := mk13157(nil, nil, []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/0.0"}}})
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.VRFSlavesV4, []string{"ge-0-0-0"}) {
		t.Errorf("VRFSlavesV4=%v want [ge-0-0-0]", got.VRFSlavesV4)
	}
	if !reflect.DeepEqual(got.VRFSlavesV6, []string{"ge-0-0-0"}) || !reflect.DeepEqual(got.AdmitVRFSlavesV6, []string{"ge-0-0-0"}) {
		t.Errorf("VRFSlavesV6/AdmitVRF=%v/%v want both [ge-0-0-0]", got.VRFSlavesV6, got.AdmitVRFSlavesV6)
	}
	if len(got.V4) != 0 || len(got.V6) != 0 {
		t.Errorf("main V4/V6=%v/%v want empty for VRF slave", got.V4, got.V6)
	}
}

func TestD311_13157_QuarantinedVRF(t *testing.T) {
	cfg := mk13157(nil, map[string]*config.ZoneConfig{
		"junos-global": {Name: "junos-global", Interfaces: []string{"ge-0/0/0.0"}},
	}, []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/0.0"}}})
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.VRFSlavesV4, []string{"ge-0-0-0"}) ||
		!reflect.DeepEqual(got.VRFSlavesV6, []string{"ge-0-0-0"}) ||
		!reflect.DeepEqual(got.AdmitVRFSlavesV6, []string{"ge-0-0-0"}) {
		t.Fatalf("quarantined VRF DHCP backstops = %+v, want ge-0-0-0 in v4, v6, and admit sets", got)
	}
}

func TestD311_13157_SharedDenySuppressesAdmit(t *testing.T) {
	cfg := mk13157(nil, nil, nil)
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true},
			1: {Number: 1, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"lan": {Name: "lan", Interfaces: []string{"ge-0/0/0.1"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"dhcpv6"}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if containsString(got.AdmitV6, "ge-0-0-0") {
		t.Errorf("AdmitV6=%v must not contain ge-0-0-0 (wan denies dhcpv6 on shared netdev)", got.AdmitV6)
	}
	if !containsString(got.V6, "ge-0-0-0") {
		t.Errorf("V6 drop backstop=%v want ge-0-0-0", got.V6)
	}
}

func TestD311_13412_VRFSharedDenySuppressesAdmit(t *testing.T) {
	cfg := mk13157(nil, nil, []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/0.0", "ge-0-0-0.0"}}})
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"lan": {Name: "lan", Interfaces: []string{"ge-0-0-0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"dhcpv6"}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if containsString(got.AdmitVRFSlavesV6, "ge-0-0-0") {
		t.Errorf("AdmitVRFSlavesV6=%v must not contain ge-0-0-0 (wan denies dhcpv6 on shared VRF netdev)", got.AdmitVRFSlavesV6)
	}
	if containsString(got.AdmitV6, "ge-0-0-0") {
		t.Errorf("AdmitV6=%v must not contain ge-0-0-0 (wan denies dhcpv6 on shared netdev)", got.AdmitV6)
	}
	if !containsString(got.VRFSlavesV6, "ge-0-0-0") {
		t.Errorf("VRFSlavesV6 drop backstop=%v want ge-0-0-0", got.VRFSlavesV6)
	}
	if !containsString(got.V6, "ge-0-0-0") {
		t.Errorf("V6 drop backstop=%v want ge-0-0-0", got.V6)
	}
}

func TestD311_13157_UnzonedOnlyAdmit(t *testing.T) {
	cfg := mk13157(nil, nil, nil)
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if !reflect.DeepEqual(got.AdmitV6, []string{"ge-0-0-0"}) || !reflect.DeepEqual(got.V6, []string{"ge-0-0-0"}) {
		t.Errorf("unzoned AdmitV6/V6=%v/%v want [ge-0-0-0]/[ge-0-0-0]", got.AdmitV6, got.V6)
	}
}

func TestD311_13157_DisabledSkipped(t *testing.T) {
	cfg := mk13157(nil, nil, nil)
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Disable: true, Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0/0/0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"dhcpv6"}}},
	}
	got := BuildDHCPHostInboundBackstopNetdevs(cfg, nil)
	if containsString(got.V4, "ge-0-0-0") || containsString(got.V6, "ge-0-0-0") || containsString(got.AdmitV6, "ge-0-0-0") {
		t.Errorf("disabled interface leaked into %+v", got)
	}
	if !containsString(got.AdmitV6, "ge-0-0-1") {
		t.Errorf("control unzoned ge-0-0-1 missing from AdmitV6=%v", got.AdmitV6)
	}
}
