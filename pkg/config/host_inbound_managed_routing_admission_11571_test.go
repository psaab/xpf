package config

import (
	"strings"
	"testing"
)

func containsManagedAdmissionDiagnostic11571(diagnostics []string) bool {
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic, `omits "ospf"`) {
			return true
		}
	}
	return false
}

func managedOSPFHostInboundConfig11571(protocols string, override string) []string {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	}
	if protocols != "" {
		lines = append(lines, "set security zones security-zone trust host-inbound-traffic protocols "+protocols)
	}
	if override != "" {
		lines = append(lines, "set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols "+override)
	}
	return lines
}

// TestManagedRoutingHostInboundAdmissionCommitGate11571 exercises the
// migration boundary: commits reject managed multicast without effective zone
// admission, tolerant loads boot with a warning, and explicit/effective tokens
// allow the configuration.
func TestManagedRoutingHostInboundAdmissionCommitGate11571(t *testing.T) {
	t.Run("strict-commit-rejects-missing-token", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, managedOSPFHostInboundConfig11571("", "")))
		if err == nil || !strings.Contains(err.Error(), `omits "ospf"`) {
			t.Fatalf("strict commit error = %v, want missing ospf admission", err)
		}
	})

	t.Run("tolerant-load-warns-and-boots", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTree(t, managedOSPFHostInboundConfig11571("", "")))
		if err != nil {
			t.Fatalf("tolerant load must preserve bootability: %v", err)
		}
		if !containsManagedAdmissionDiagnostic11571(cfg.Warnings) {
			t.Fatalf("tolerant load warnings = %v, want missing ospf admission", cfg.Warnings)
		}
	})

	for _, tc := range []struct {
		name      string
		protocols string
		override  string
	}{
		{name: "zone-token", protocols: "ospf"},
		{name: "all-expansion", protocols: "all"},
		{name: "interface-override-token", protocols: "bgp", override: "ospf"},
	} {
		t.Run(tc.name+"-allows-commit", func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, managedOSPFHostInboundConfig11571(tc.protocols, tc.override)))
			if err != nil {
				t.Fatalf("effective ospf admission must allow commit: %v", err)
			}
			if containsManagedAdmissionDiagnostic11571(cfg.Warnings) {
				t.Fatalf("effective ospf admission produced mismatch warning: %v", cfg.Warnings)
			}
		})
	}

	t.Run("interface-override-replaces-zone-token", func(t *testing.T) {
		_, err := CompileConfig(buildTree(t, managedOSPFHostInboundConfig11571("ospf", "bgp")))
		if err == nil || !strings.Contains(err.Error(), `omits "ospf"`) {
			t.Fatalf("strict commit error = %v, want effective override mismatch", err)
		}
	})
}

// TestManagedRoutingMismatchSurvivingBranches11571 re-pins the #4455 Component
// B direct-helper cases whose logic #11571 preserved (same collector,
// same bare-member expansion, same effective-set resolution — only the
// diagnostic text changed and the call moved from ValidateConfig to the
// strict/tolerant tail gate). Admission cases (missing-token strict-reject /
// tolerant-warn, zone-token/all/override silence) live in
// TestManagedRoutingHostInboundAdmissionCommitGate11571 above; the old (h)
// ValidateConfig-registration pin is obsolete by design, with end-to-end
// registration pinned by those strict/tolerant compile cases.
func TestManagedRoutingMismatchSurvivingBranches11571(t *testing.T) {
	mkZone := func(iface string, zoneProtocols []string) *ZoneConfig {
		z := &ZoneConfig{Interfaces: []string{iface}}
		if zoneProtocols != nil {
			z.HostInboundTraffic = &HostInboundTraffic{Protocols: zoneProtocols}
		}
		return z
	}
	ospfOn := func(iface string) *OSPFConfig {
		return &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: iface}}}}}
	}
	contains := func(warnings []string, substr string) bool {
		for _, w := range warnings {
			if strings.Contains(w, substr) {
				return true
			}
		}
		return false
	}

	// (d) RIP + OSPFv3 families warn on missing tokens.
	t.Run("rip-and-ospf3-warn", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
		cfg.Protocols.RIP = &RIPConfig{Interfaces: []string{"ge-0/0/0.0"}}
		cfg.Protocols.OSPFv3 = &OSPFv3Config{Areas: []*OSPFv3Area{{Interfaces: []*OSPFv3Interface{{Name: "ge-0/0/0.0"}}}}}
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `omits "rip"`) || !contains(w, `omits "ospf3"`) {
			t.Fatalf("expected RIP + OSPFv3 omission diagnostics, got %v", w)
		}
	})

	// (e) no managed routing → no warning.
	t.Run("no-managed-routing-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("expected no warning without managed routing, got %v", w)
		}
	})

	// (f) OSPF on an interface NOT in any zone → no warning.
	t.Run("out-of-zone-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/1.0", nil)}
		cfg.Protocols.OSPF = ospfOn("ge-0/0/0.0")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("expected no warning for interface not in any zone, got %v", w)
		}
	})

	// (g) a routing-instance's OSPF is also checked.
	t.Run("routing-instance-ospf-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{Name: "vr1", OSPF: ospfOn("ge-0/0/0.0")}}
		if w := validateHostInboundManagedRoutingMismatch(cfg); !contains(w, `omits "ospf"`) {
			t.Fatalf("expected routing-instance OSPF diagnostic, got %v", w)
		}
	})

	// (i) A bare zone member claims configured units: zone lists physical reth0,
	// OSPF runs on reth0.10 — in-zone at runtime, so a missing token must warn.
	t.Run("bare-member-unit-warns", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{10: {}}}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": {Interfaces: []string{"reth0"}}}
		cfg.Protocols.OSPF = ospfOn("reth0.10")
		w := validateHostInboundManagedRoutingMismatch(cfg)
		if !contains(w, `on interface "reth0.10" (security zone "trust")`) || !contains(w, `omits "ospf"`) {
			t.Fatalf("expected warning for OSPF unit under a bare zone member, got %v", w)
		}
	})

	// (j) A physical-parent override admitting ospf covers unit reth0.10.
	t.Run("parent-override-inheritance-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{10: {}}}}
		z := &ZoneConfig{Interfaces: []string{"reth0"}}
		z.InterfaceHostInbound = map[string]*HostInboundTraffic{"reth0": {Protocols: []string{"ospf"}}}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": z}
		cfg.Protocols.OSPF = ospfOn("reth0.10")
		if w := validateHostInboundManagedRoutingMismatch(cfg); len(w) != 0 {
			t.Fatalf("expected no warning: parent override admits ospf (inherited by the unit), got %v", w)
		}
	})
}
