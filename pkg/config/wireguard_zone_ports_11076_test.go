package config

import (
	"reflect"
	"testing"
)

func wgZoneTestConfig() *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51820}},
			1: {Number: 1, Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51821}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51820}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Tunnel: &TunnelConfig{Mode: "wireguard", WgListenPort: 51822}},
		}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/0.0", "ge-0/0/0.1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/1.0"}},
	}
	return cfg
}

func TestWireGuardListenPorts11076(t *testing.T) {
	got := wgZoneTestConfig().WireGuardListenPorts()
	want := []uint16{51820, 51821, 51822}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WireGuardListenPorts() = %v, want %v", got, want)
	}
}

func TestWireGuardSourceLessInterfaces12119(t *testing.T) {
	cfg := wgZoneTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Tunnel.Source = "198.51.100.1"
	got := cfg.WireGuardSourceLessInterfaces()
	want := []string{"ge-0/0/0.1", "ge-0/0/1.0", "ge-0/0/2.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WireGuardSourceLessInterfaces() = %v, want %v", got, want)
	}
}

func TestWireGuardUnzonedListenerWithOwnedSourceIsNotWarned11076(t *testing.T) {
	cfg := wgZoneTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses = []string{"198.51.100.1/24"}
	cfg.Interfaces.Interfaces["ge-0/0/2"].Units[0].Tunnel.Source = "198.51.100.1"
	if got := cfg.WireGuardUnzonedInterfaces(); len(got) != 0 {
		t.Fatalf("unique source owner must admit the unzoned tunnel listener; unzoned warnings = %v", got)
	}
}

func TestWireGuardInvalidSourceInterfaces12119(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		setup  func(*Config)
	}{
		{name: "malformed", source: "not-an-ip"},
		{name: "unowned", source: "203.0.113.200"},
		{
			name:   "ambiguous",
			source: "198.51.100.1",
			setup: func(cfg *Config) {
				cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Addresses = []string{"198.51.100.1/24"}
				cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses = []string{"198.51.100.1/24"}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := wgZoneTestConfig()
			cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].Tunnel.Source = tc.source
			if tc.setup != nil {
				tc.setup(cfg)
			}
			got := cfg.WireGuardInvalidSourceInterfaces()
			want := []string{"ge-0/0/0.0"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("WireGuardInvalidSourceInterfaces() = %v, want %v", got, want)
			}
		})
	}
}

func TestWireGuardUnzonedInterfaces11076(t *testing.T) {
	got := wgZoneTestConfig().WireGuardUnzonedInterfaces()
	want := []string{"ge-0/0/2.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WireGuardUnzonedInterfaces() = %v, want %v", got, want)
	}
	if got := (&Config{}).WireGuardListenPorts(); len(got) != 0 {
		t.Fatalf("empty config must yield no listener ports, got %v", got)
	}
}
