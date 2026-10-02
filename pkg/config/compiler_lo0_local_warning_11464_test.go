package config

import (
	"strings"
	"testing"
)

func TestLo0AddressWarning11464(t *testing.T) {
	configWithAddress := func() *Config {
		return &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"lo0": {Name: "lo0", Units: map[int]*InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.255.0.1/32", "2001:db8::1/128"}},
			}},
		}}}
	}
	containsLo0Warning := func(cfg *Config) bool {
		for _, warning := range ValidateConfig(cfg) {
			if strings.Contains(warning, "lo0") && strings.Contains(warning, "not locally delivered") {
				return true
			}
		}
		return false
	}

	if !containsLo0Warning(configWithAddress()) {
		t.Fatalf("configured lo0 addresses must warn that Linux lo0 is not locally delivered")
	}

	withoutAddresses := configWithAddress()
	withoutAddresses.Interfaces.Interfaces["lo0"].Units[0].Addresses = nil
	if containsLo0Warning(withoutAddresses) {
		t.Fatal("lo0 without configured addresses must not warn")
	}

	tunnel := configWithAddress()
	tunnel.Interfaces.Interfaces["lo0"].Tunnel = &TunnelConfig{Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"}
	if containsLo0Warning(tunnel) {
		t.Fatal("lo0 backed by a configured tunnel netdev must not warn")
	}
}
