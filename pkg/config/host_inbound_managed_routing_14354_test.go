package config

import (
	"strings"
	"testing"
)

// TestManagedRoutingMismatchUnitOverrideAndVRFAllScoping is the #14354
// regression: (1) a bare zone member with a per-unit host-inbound override
// admitting ospf must not be false-rejected on the synthetic bare parent
// key when `protocols ospf ... interface all` runs on unit 0; (2) a
// routing-instance `interface all` must scope to that instance's interfaces
// only (and a global `interface all` to the default instance only), never
// demanding admission on another instance's zoned interfaces.
func TestManagedRoutingMismatchUnitOverrideAndVRFAllScoping(t *testing.T) {
	contains := func(w []string, s string) bool {
		for _, x := range w {
			if strings.Contains(x, s) {
				return true
			}
		}
		return false
	}

	// (1) Bare zone member + unit-0 override admitting ospf, global all.
	t.Run("bare-member-unit-override-global-all-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
		}
		z := &ZoneConfig{Interfaces: []string{"ge-0/0/0"}}
		z.InterfaceHostInbound = map[string]*HostInboundTraffic{
			"ge-0/0/0.0": {Protocols: []string{"ospf"}},
		}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": z}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "all"}}}}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("unit override admits ospf; bare-parent key must not false-reject, got %v", w)
		}
	})

	// (1b) Same shape through the strict compile gate (the operator-visible
	// hard reject), authored in Junos syntax.
	t.Run("bare-member-unit-override-global-all-strict-compiles", func(t *testing.T) {
		lines := []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0",
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf",
			"set protocols ospf area 0.0.0.0 interface all",
		}
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("strict commit must accept unit-override ospf admission, got %v", err)
		}
	})

	// (1c) Fail-closed preserved: bare member whose unit 0 does NOT admit
	// ospf still warns — on the logical unit, not the bare parent.
	t.Run("bare-member-without-admission-warns-on-unit", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
		}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": {Interfaces: []string{"ge-0/0/0"}}}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "all"}}}}}
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `on interface "ge-0/0/0.0" (security zone "trust")`) || !contains(w, `omits "ospf"`) {
			t.Fatalf("unadmitted unit 0 must warn on the logical unit, got %v", w)
		}
		if contains(w, `on interface "ge-0/0/0" (security zone`) {
			t.Fatalf("must not warn on the synthetic bare parent key, got %v", w)
		}
	})

	// (2) Routing-instance `interface all` scopes to that instance only:
	// MAIN's unadmitted zoned interface must not be demanded.
	t.Run("vrf-all-scoped-to-own-instance", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}},
		}
		trust := &ZoneConfig{Interfaces: []string{"ge-0/0/0.0"}}
		trust.InterfaceHostInbound = map[string]*HostInboundTraffic{
			"ge-0/0/0.0": {Protocols: []string{"ospf"}},
		}
		untrust := &ZoneConfig{Interfaces: []string{"ge-0/0/1.0"}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": trust, "untrust": untrust}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name:       "tenant",
			Interfaces: []string{"ge-0/0/0.0"},
			OSPF:       &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "all"}}}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("tenant VRF all must not demand ospf on MAIN untrust interface, got %v", w)
		}
	})

	// (2b) Fail-closed inside the VRF: its own unadmitted interface still warns.
	t.Run("vrf-all-warns-on-own-unadmitted", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}},
		}
		cfg.Security.Zones = map[string]*ZoneConfig{
			"trust":   {Interfaces: []string{"ge-0/0/0.0"}},
			"untrust": {Interfaces: []string{"ge-0/0/1.0"}},
		}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name:       "tenant",
			Interfaces: []string{"ge-0/0/0.0"},
			OSPF:       &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "all"}}}}},
		}}
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `on interface "ge-0/0/0.0" (security zone "trust")`) {
			t.Fatalf("tenant VRF all must warn on its own unadmitted interface, got %v", w)
		}
		if contains(w, "ge-0/0/1") {
			t.Fatalf("tenant VRF all must not warn on MAIN interface, got %v", w)
		}
	})

	// (2c) Reverse direction: global `interface all` must not demand admission
	// on a tenant-VRF interface.
	t.Run("global-all-skips-vrf-interface", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {}}},
		}
		trust := &ZoneConfig{Interfaces: []string{"ge-0/0/0.0"}}
		trust.InterfaceHostInbound = map[string]*HostInboundTraffic{
			"ge-0/0/0.0": {Protocols: []string{"ospf"}},
		}
		untrust := &ZoneConfig{Interfaces: []string{"ge-0/0/1.0"}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": trust, "untrust": untrust}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name:       "tenant",
			Interfaces: []string{"ge-0/0/1.0"},
		}}
		cfg.Protocols.OSPF = &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "all"}}}}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("global all must not demand ospf on tenant VRF interface, got %v", w)
		}
	})

	// (2d) Same VRF scoping through the strict compile gate.
	t.Run("vrf-all-strict-compiles", func(t *testing.T) {
		lines := []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf",
			"set security zones security-zone untrust interfaces ge-0/0/1.0",
			"set routing-instances tenant instance-type virtual-router",
			"set routing-instances tenant interface ge-0/0/0.0",
			"set routing-instances tenant protocols ospf area 0.0.0.0 interface all",
		}
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("strict commit must accept tenant-scoped all, got %v", err)
		}
	})

	// Explicit (non-all) RI interface refs keep working unchanged.
	t.Run("vrf-explicit-ref-still-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": {Interfaces: []string{"ge-0/0/0.0"}}}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name: "tenant",
			OSPF: &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: "ge-0/0/0.0"}}}}},
		}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf"`) {
			t.Fatalf("explicit RI ospf ref must still warn, got %v", w)
		}
	})
}
