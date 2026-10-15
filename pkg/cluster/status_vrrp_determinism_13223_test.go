package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Regression #13223 (D4-05): deterministic ordering + malformed unit must not wildcard.
func TestFormatVRRPConfigRowsDeterministicAndMalformedUnit_13223(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/0.0", "ge-0/0/0.bad"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/0.100"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.0.1/24": {ID: 1, Priority: 100, VirtualAddresses: []string{"10.0.0.10"}},
				"10.0.1.1/24": {ID: 2, Priority: 110, VirtualAddresses: []string{"10.0.1.10"}},
			}},
			100: {Number: 100, VRRPGroups: map[string]*config.VRRPGroup{
				"192.168.0.1/24": {ID: 3, Priority: 90, VirtualAddresses: []string{"192.168.0.10"}},
			}},
		}},
	}
	first := FormatVRRPConfigRows(cfg)
	for range 50 {
		if got := FormatVRRPConfigRows(cfg); got != first {
			t.Fatalf("non-deterministic output:\nfirst:\n%s\ngot:\n%s", first, got)
		}
	}
	// Expected sorted: trust (ge-0/0/0.0 only; .bad matches nothing) then untrust (.100)
	want := "VRRP on ge-0/0/0.0: configured: group 1, priority 100, VIP 10.0.0.10, address 10.0.0.1/24\n" +
		"VRRP on ge-0/0/0.0: configured: group 2, priority 110, VIP 10.0.1.10, address 10.0.1.1/24\n" +
		"VRRP on ge-0/0/0.100: configured: group 3, priority 90, VIP 192.168.0.10, address 192.168.0.1/24\n"
	if first != want {
		t.Fatalf("output mismatch:\ngot:\n%s\nwant:\n%s", first, want)
	}
	if strings.Count(first, "VRRP on") != 3 {
		t.Fatalf("malformed .bad wildcard matched units: %q", first)
	}
	// A negative unit suffix is not a unit wildcard either.
	cfg.Security.Zones["trust"].Interfaces = []string{"ge-0/0/0.-1"}
	got := FormatVRRPConfigRows(cfg)
	if strings.Count(got, "VRRP on") != 1 || !strings.Contains(got, "ge-0/0/0.100:") {
		t.Fatalf("negative unit should match none, got %q", got)
	}
}
