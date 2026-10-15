package config

import (
	"strings"
	"testing"
)

func TestManagedRoutingMismatch13142(t *testing.T) {
	contains := func(w []string, s string) bool {
		for _, x := range w {
			if strings.Contains(x, s) {
				return true
			}
		}
		return false
	}
	mkZone := func(iface string, protos []string) *ZoneConfig {
		z := &ZoneConfig{Interfaces: []string{iface}}
		if protos != nil {
			z.HostInboundTraffic = &HostInboundTraffic{Protocols: protos}
		}
		return z
	}
	ospfOn := func(iface string) *OSPFConfig {
		return &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: iface}}}}}
	}

	t.Run("lifeline-fxp0-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"mgmt": mkZone("fxp0.0", nil)}
		cfg.Protocols.OSPF = ospfOn("fxp0.0")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("lifeline must be exempt, got %v", w)
		}
	})
	t.Run("lifeline-rip-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"mgmt": mkZone("fxp0.0", nil)}
		cfg.Protocols.RIP = &RIPConfig{Interfaces: []string{"fxp0.0"}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("lifeline rip must be exempt, got %v", w)
		}
	})
	t.Run("bare-protocol-ref-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", nil)}
		cfg.Protocols.OSPF = ospfOn("ge-0/0/1")
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `omits "ospf"`) || !contains(w, `"trust"`) {
			t.Fatalf("bare ref must warn, got %v", w)
		}
	})
	t.Run("bare-protocol-ref-admitted-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", []string{"ospf"})}
		cfg.Protocols.OSPF = ospfOn("ge-0/0/1")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("admitted bare ref must be silent, got %v", w)
		}
	})
	t.Run("interface-all-warns-per-zoned-unit", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", nil)}
		cfg.Protocols.OSPF = ospfOn("all")
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `omits "ospf"`) || !contains(w, `ge-0/0/1.0`) {
			t.Fatalf("interface all must warn for zoned unit, got %v", w)
		}
	})
	t.Run("bare-without-zone-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", nil)}
		cfg.Protocols.OSPF = ospfOn("ge-9/9/9")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("out of zone bare must be silent, got %v", w)
		}
	})
	t.Run("quarantined-reserved-zone-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{
			"junos-global": mkZone("ge-0/0/1.0", nil),
			"trust":        mkZone("ge-0/0/2.0", []string{"ospf"}),
		}
		cfg.Protocols.OSPF = ospfOn("ge-0/0/1.0")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("quarantined reserved zone must be silent (ForConfig), got %v", w)
		}
	})
	t.Run("config-level-strict-lifeline-allows", func(t *testing.T) {
		lines := []string{
			"set interfaces fxp0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone mgmt interfaces fxp0.0",
			"set security zones security-zone mgmt host-inbound-traffic system-services ssh",
			"set protocols ospf area 0.0.0.0 interface fxp0.0",
		}
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("lifeline strict compile must allow: %v", err)
		}
	})
	t.Run("config-level-strict-bare-rejects", func(t *testing.T) {
		lines := []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/1.0",
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1",
		}
		_, err := CompileConfig(buildTree(t, lines))
		if err == nil || !strings.Contains(err.Error(), `omits "ospf"`) {
			t.Fatalf("bare ref strict compile must reject, got %v", err)
		}
	})
}
