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

func TestWireGuardZonePorts11076(t *testing.T) {
	got := wgZoneTestConfig().WireGuardZonePorts()
	want := map[string][]uint16{
		"trust":   {51820, 51821},
		"untrust": {51820},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WireGuardZonePorts() = %v, want %v", got, want)
	}
}

func TestWireGuardUnzonedInterfaces11076(t *testing.T) {
	got := wgZoneTestConfig().WireGuardUnzonedInterfaces()
	want := []string{"ge-0/0/2.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WireGuardUnzonedInterfaces() = %v, want %v", got, want)
	}
	if n := len((&Config{}).WireGuardZonePorts()); n != 0 {
		t.Fatalf("empty config must yield no zone ports, got %d zones", n)
	}
}
