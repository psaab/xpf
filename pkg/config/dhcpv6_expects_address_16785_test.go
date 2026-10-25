package config

import "testing"

// TestDHCPv6ExpectsAddress16785 pins which DHCPv6 client shapes can
// install a routable address on their own unit (#16785). PD-only and
// stateless clients never do; every other shape defaults to IA_NA.
func TestDHCPv6ExpectsAddress16785(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *DHCPv6ClientConfig
		want bool
	}{
		{"nil client (bare dhcpv6)", nil, true},
		{"empty client", &DHCPv6ClientConfig{}, true},
		{"stateful no ia types", &DHCPv6ClientConfig{ClientType: "stateful"}, true},
		{"ia-na", &DHCPv6ClientConfig{ClientIATypes: []string{"ia-na"}}, true},
		{"ia-na plus ia-pd", &DHCPv6ClientConfig{ClientIATypes: []string{"ia-pd", "ia-na"}}, true},
		{"pd only", &DHCPv6ClientConfig{ClientIATypes: []string{"ia-pd"}}, false},
		{"stateless", &DHCPv6ClientConfig{ClientType: "stateless"}, false},
		{"stateless with ia-na leaf", &DHCPv6ClientConfig{ClientType: "stateless", ClientIATypes: []string{"ia-na"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.DHCPv6ExpectsAddress(); got != tc.want {
				t.Errorf("DHCPv6ExpectsAddress(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
			unit := &InterfaceUnit{DHCPv6: true, DHCPv6Client: tc.cfg}
			if got := unit.UnitDHCPv6ExpectsAddress(); got != tc.want {
				t.Errorf("UnitDHCPv6ExpectsAddress(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
	var nilUnit *InterfaceUnit
	if !nilUnit.UnitDHCPv6ExpectsAddress() {
		t.Error("nil unit must report address-expecting (no pending lease)")
	}
}
