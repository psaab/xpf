package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// pdOnlyPendingConfig16785 builds a zoned DHCPv6 WAN (iaType selects the
// client shape) beside an addressed LAN unit.
func pdOnlyPendingConfig16785(iaTypes []string, clientType string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{
				ClientType: clientType, ClientIATypes: iaTypes,
			}},
		}},
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	return cfg
}

// TestPendingIntentPDOnlyNotPending16785 pins #16785 at the predicate
// level: a PD-only (or stateless) zoned DHCPv6 unit with only its
// automatic link-local is NOT pending — no WAN address ever arrives.
// FAIL-ON-REVERT: dropping the address-expectation gate makes the
// ia-pd and stateless rows pending again.
func TestPendingIntentPDOnlyNotPending16785(t *testing.T) {
	llOnly := []InterfaceSnapshot{
		{
			Name: "ge-0-0-1.0", Zone: "untrust", IsUnit: true, LinuxName: "ge-0-0-1",
			Addresses: []InterfaceAddressSnapshot{
				// Scope 253 = RT_SCOPE_LINK: the kernel's automatic fe80::/64,
				// which never satisfies lease intent (#10751 R4-1).
				{Family: "inet6", Address: "fe80::1/64", Scope: 253},
			},
		},
		{
			Name: "ge-0-0-2.0", Zone: "trust", IsUnit: true, LinuxName: "ge-0-0-2",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.9.0.1/24"},
			},
		},
	}
	for _, tc := range []struct {
		name       string
		iaTypes    []string
		clientType string
		wantPend   bool
	}{
		{"pd only", []string{"ia-pd"}, "stateful", false},
		{"stateless", nil, "stateless", false},
		{"ia-na control", []string{"ia-na"}, "stateful", true},
		{"ia-na plus ia-pd control", []string{"ia-na", "ia-pd"}, "stateful", true},
		{"no ia types defaults to ia-na", nil, "stateful", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pdOnlyPendingConfig16785(tc.iaTypes, tc.clientType)
			if got := HostInboundPendingIntentFromSnapshots(cfg, llOnly); got != tc.wantPend {
				t.Errorf("pending = %v, want %v", got, tc.wantPend)
			}
			ifaces := AddresslessEnforcingInterfacesFromSnapshots(cfg, llOnly)
			if tc.wantPend && len(ifaces) == 0 {
				t.Error("pending control reported no addressless interface")
			}
			if !tc.wantPend && len(ifaces) != 0 {
				t.Errorf("non-pending shape reported addressless interfaces %+v", ifaces)
			}
			// No v6 backstop drop for non-address-expecting clients.
			backstops := BuildDHCPHostInboundBackstopNetdevs(cfg, llOnly)
			hasV6 := containsString(backstops.V6, "ge-0-0-1")
			if tc.wantPend && !hasV6 {
				t.Error("address-expecting control lost its v6 backstop")
			}
			if !tc.wantPend && hasV6 {
				t.Errorf("PD-only/stateless shape kept v6 backstop %v", backstops.V6)
			}
		})
	}
}
