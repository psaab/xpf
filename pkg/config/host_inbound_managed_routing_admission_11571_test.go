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
