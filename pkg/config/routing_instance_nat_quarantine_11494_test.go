package config

import (
	"testing"
)

func TestInterfaceSNATEgressDiagnosticSkipsDualClaimedInterface11494(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/0": {
				Name: "ge-0/0/0",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
				},
			},
		}},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "blue", Interfaces: []string{"ge-0/0/0.0"}},
			{Name: "red", Interfaces: []string{"ge-0/0/0.0"}},
		},
		Security: SecurityConfig{NAT: NATConfig{Source: []*NATRuleSet{{
			Name:              "blue-interface-snat",
			ToRoutingInstance: "blue",
			Rules:             []*NATRule{{Then: NATThen{Interface: true}}},
		}}}},
	}

	if got := RoutingInstanceMemberDeviceConflicts(cfg, cfg.TunnelNameMap()); len(got) != 1 || got[0].LinuxName != "ge-0-0-0" {
		t.Fatalf("test setup conflict = %+v, want ge-0-0-0", got)
	}
	if got := interfaceSNATEgressAddresses(cfg); len(got) != 0 {
		t.Fatalf("compile-time NAT diagnostic used a dual-claimed interface as blue egress: %v", got)
	}

	// Once ownership is unambiguous, the same interface-SNAT rule must still
	// contribute its address; the quarantine filter is not a general suppression.
	cfg.RoutingInstances = cfg.RoutingInstances[:1]
	got := interfaceSNATEgressAddresses(cfg)
	if got["192.0.2.1"] == "" || len(got) != 1 {
		t.Fatalf("unambiguous interface-SNAT egress diagnostic = %v, want 192.0.2.1", got)
	}
}

func TestInterfaceSNATEgressDiagnosticProjectsPartialQuarantine11494(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/0": {
				Name: "ge-0/0/0",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
					1: {Number: 1, Addresses: []string{"198.51.100.1/24"}},
				},
			},
		}},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "blue", Interfaces: []string{"ge-0/0/0"}},
			{Name: "zz", Interfaces: []string{"ge-0/0/0.1"}},
		},
		Security: SecurityConfig{NAT: NATConfig{Source: []*NATRuleSet{{
			Name:              "zz-interface-snat",
			ToRoutingInstance: "zz",
			Rules:             []*NATRule{{Then: NATThen{Interface: true}}},
		}}}},
	}
	conflicts := RoutingInstanceMemberDeviceConflicts(cfg, cfg.TunnelNameMap())
	if len(conflicts) != 1 || conflicts[0].LinuxName != "ge-0-0-0.1" {
		t.Fatalf("test setup conflicts = %+v, want only unit 1", conflicts)
	}
	if got := interfaceSNATEgressAddresses(cfg); len(got) != 0 {
		t.Fatalf("compile-time NAT diagnostic attributed contested unit 1 to zz: %v", got)
	}

	// Mirror the post-sanitization shape: unit 1 is recorded as quarantined,
	// while the surviving explicit unit and its typed primary claim belong to blue.
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "blue", Interfaces: []string{"ge-0/0/0.0"}},
	}
	cfg.QuarantinedRIMemberDeviceConflicts = conflicts
	cfg.QuarantinedRIMemberPrimaryClaims = []RoutingInstanceMemberPrimaryClaim{{
		Instance: "blue", InterfaceKey: "ge-0/0/0", LinuxName: "ge-0-0-0",
	}}
	cfg.Security.NAT.Source[0].ToRoutingInstance = "blue"
	riByIface, noBareFallback := routingInstanceByInterface(cfg)
	if riByIface["ge-0/0/0"] != "blue" {
		t.Fatalf("typed primary claim missing from NAT index: %v", riByIface)
	}
	if _, blocked := noBareFallback["ge-0/0/0"]; !blocked {
		t.Fatalf("typed primary claim did not disable widening bare fallback: %v", noBareFallback)
	}
	got := interfaceSNATEgressAddresses(cfg)
	if got["192.0.2.1"] == "" || len(got) != 1 {
		t.Fatalf("post-quarantine NAT egress diagnostic = %v, want only surviving unit 0", got)
	}
}
