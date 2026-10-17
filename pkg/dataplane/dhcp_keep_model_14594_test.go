package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #14594: buildInterfaceNetworkdModels must tell pkg/networkd which
// DHCPv6 clients own an address on the interface itself. A bare
// `family inet6 { dhcpv6; }` unit (DHCPv6Client == nil) and a stateful
// dhcpv6-client with ia-na own an IA_NA lease; a stateless client and a
// PD-only client do not (their addresses, if any, live on other
// interfaces). Without this, the generated .network either strips the
// IA_NA lease on reconfigure or needlessly preserves foreign addresses.
//
// FAIL-ON-REVERT: stop populating DHCPv6Stateless/DHCPv6IATypes (or
// derive them from the bare DHCPv6 bool alone) and the stateless /
// PD-only cells go RED; drop the VLAN-subinterface arm and the tagged
// cells go RED.
func TestDHCPKeepModelFlags14594(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// Non-VLAN: bare dhcpv6, stateless, PD-only, IA-NA.
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateless"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{
				ClientType: "stateful", ClientIATypes: []string{"ia-pd"}}},
		}},
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6Client: &config.DHCPv6ClientConfig{
				ClientType: "stateful", ClientIATypes: []string{"ia-na", "ia-pd"}}},
		}},
		// VLAN-tagged DHCP rows live on the sub-interface model.
		"ge-0/0/4": {Name: "ge-0/0/4", VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VlanID: 100, DHCP: true},
			1: {Number: 1, VlanID: 200, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateless"}},
		}},
		// Secure-tunnel unit with a DHCPv6 client.
		"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateless"}},
		}},
	}
	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-0": {Index: 10, Name: "ge-0-0-0", HardwareAddr: mac},
		"ge-0-0-1": {Index: 11, Name: "ge-0-0-1", HardwareAddr: mac},
		"ge-0-0-2": {Index: 12, Name: "ge-0-0-2", HardwareAddr: mac},
		"ge-0-0-3": {Index: 13, Name: "ge-0-0-3", HardwareAddr: mac},
		"ge-0-0-4": {Index: 14, Name: "ge-0-0-4", HardwareAddr: mac},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})

	models := make(map[string]networkd.InterfaceConfig, len(result.ManagedInterfaces))
	for _, mi := range result.ManagedInterfaces {
		models[mi.Name] = mi
	}

	type want struct {
		dhcpv4, dhcpv6, stateless bool
		iaTypes                   []string
	}
	cases := map[string]want{
		"ge-0-0-0":     {dhcpv6: true},
		"ge-0-0-1":     {dhcpv6: true, stateless: true},
		"ge-0-0-2":     {dhcpv6: true, iaTypes: []string{"ia-pd"}},
		"ge-0-0-3":     {dhcpv6: true, iaTypes: []string{"ia-na", "ia-pd"}},
		"ge-0-0-4.100": {dhcpv4: true},
		"ge-0-0-4.200": {dhcpv6: true, stateless: true},
	}
	for name, w := range cases {
		mi, ok := models[name]
		if !ok {
			t.Errorf("no ManagedInterfaces entry for %s", name)
			continue
		}
		if mi.DHCPv4 != w.dhcpv4 || mi.DHCPv6 != w.dhcpv6 {
			t.Errorf("%s: DHCPv4=%v DHCPv6=%v, want %v/%v", name, mi.DHCPv4, mi.DHCPv6, w.dhcpv4, w.dhcpv6)
		}
		if mi.DHCPv6Stateless != w.stateless {
			t.Errorf("%s: DHCPv6Stateless=%v, want %v", name, mi.DHCPv6Stateless, w.stateless)
		}
		if len(mi.DHCPv6IATypes) != len(w.iaTypes) {
			t.Errorf("%s: DHCPv6IATypes=%v, want %v", name, mi.DHCPv6IATypes, w.iaTypes)
			continue
		}
		for i := range w.iaTypes {
			if mi.DHCPv6IATypes[i] != w.iaTypes[i] {
				t.Errorf("%s: DHCPv6IATypes=%v, want %v", name, mi.DHCPv6IATypes, w.iaTypes)
				break
			}
		}
	}
	// The VLAN parent itself carries no DHCP client.
	if parent, ok := models["ge-0-0-4"]; ok && (parent.DHCPv4 || parent.DHCPv6) {
		t.Errorf("VLAN parent ge-0-0-4 carries DHCP flags; clients live on sub-interfaces: %+v", parent)
	}
}
