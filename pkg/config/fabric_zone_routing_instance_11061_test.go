package config

import (
	"strings"
	"testing"
)

func crossRIFabricZoneTree11061(t *testing.T) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
		"set security zones security-zone shared interfaces ge-0/0/1.0",
		"set security zones security-zone shared interfaces ge-0/0/2.0",
	})
}

// Fail-on-revert: removing the uniform-gate dispatch for
// validateFabricZoneRoutingInstanceAmbiguityStrict lets the strict compile
// succeed and removes the tolerant-load warning.
func TestFabricZoneSpanningRoutingInstancesRejectedStrictly11061(t *testing.T) {
	tree := crossRIFabricZoneTree11061(t)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a security zone spanning two routing instances")
	} else {
		for _, want := range []string{"security zone \"shared\"", "RI-A", "ge-0/0/1.0", "RI-B", "ge-0/0/2.0"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("strict error %q does not identify %q", err, want)
			}
		}
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected an existing cross-RI zone: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "fabric zone routing-domain ambiguity") {
			for _, want := range []string{"shared", "RI-A", "ge-0/0/1.0", "RI-B", "ge-0/0/2.0"} {
				if !strings.Contains(warning, want) {
					t.Errorf("tolerant warning %q does not identify %q", warning, want)
				}
			}
			return
		}
	}
	t.Fatalf("tolerant compile omitted the cross-RI zone warning: %v", cfg.Warnings)
}

func TestFabricZoneSpanningMainAndRoutingInstanceRejectedStrictly11061(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set security zones security-zone shared interfaces ge-0/0/1.0",
		"set security zones security-zone shared interfaces ge-0/0/2.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted a zone spanning RI-A and MAIN")
	}
	for _, want := range []string{"shared", "RI-A", "ge-0/0/1.0", "MAIN (default instance)", "ge-0/0/2.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("strict error %q does not identify %q", err, want)
		}
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected a legacy RI/MAIN zone: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "fabric zone routing-domain ambiguity") {
			for _, want := range []string{"shared", "RI-A", "ge-0/0/1.0", "MAIN (default instance)", "ge-0/0/2.0"} {
				if !strings.Contains(warning, want) {
					t.Errorf("tolerant warning %q does not identify %q", warning, want)
				}
			}
			return
		}
	}
	t.Fatalf("tolerant compile omitted the RI/MAIN zone warning: %v", cfg.Warnings)
}

func TestFabricZonesEachWithinSingleRoutingInstanceCompile11061(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
		"set security zones security-zone zone-a interfaces ge-0/0/1.0",
		"set security zones security-zone zone-b interfaces ge-0/0/2.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected zones each confined to one RI: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "fabric zone routing-domain ambiguity") {
			t.Fatalf("single-RI zones emitted a cross-RI warning: %q", warning)
		}
	}
}
