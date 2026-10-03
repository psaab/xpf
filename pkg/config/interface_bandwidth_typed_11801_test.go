package config

import (
	"strings"
	"testing"
)

func TestInterfaceBandwidthStrict11801(t *testing.T) {
	for _, token := range []string{"", "asd", "10mm", "-5", "0"} {
		t.Run("reject_"+token, func(t *testing.T) {
			tree := flatTreeFromSets(t, "set interfaces wan0 bandwidth "+token)
			err := SchemaValidate(tree, nil)
			if err == nil || !strings.Contains(err.Error(), "interfaces wan0 bandwidth") {
				t.Fatalf("SchemaValidate error = %v, want leaf-naming rejection", err)
			}
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "interfaces wan0 bandwidth") {
				t.Fatalf("CompileConfig error = %v, want leaf-naming rejection", err)
			}
		})
	}
}

func TestInterfaceBandwidthLenientLoadPreservesBoot11801(t *testing.T) {
	tree := flatTreeFromSets(t, "set interfaces wan0 bandwidth asd")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected persisted malformed bandwidth: %v", err)
	}
	if cfg.Interfaces.Interfaces["wan0"].Bandwidth != 0 {
		t.Fatalf("lenient load should leave malformed bandwidth unset, got %d",
			cfg.Interfaces.Interfaces["wan0"].Bandwidth)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "interfaces wan0 bandwidth") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load did not warn with the bandwidth leaf path: %v", cfg.Warnings)
	}
}

func TestInterfaceBandwidthBracedAndCompactParity11801(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{name: "braced", tree: hierTree(t, `interfaces { wan0 { bandwidth 1g; } }`)},
		{name: "compact", tree: hierTree(t, `interfaces { wan0 bandwidth 1g; }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SchemaValidate(tc.tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid interface bandwidth: %v", err)
			}
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid interface bandwidth: %v", err)
			}
			if cfg.Interfaces.Interfaces["wan0"] == nil {
				t.Fatal("compiled interface bandwidth config has no wan0 interface")
			}
			if got := cfg.Interfaces.Interfaces["wan0"].Bandwidth; got != 1_000_000_000 {
				t.Fatalf("compiled bandwidth = %d, want 1000000000", got)
			}
		})
	}
}

func TestInterfaceBandwidthValidValuesUnchanged11801(t *testing.T) {
	for _, tc := range []struct {
		token string
		want  uint64
	}{
		{token: "1g", want: 1_000_000_000},
		{token: "100m", want: 100_000_000},
		{token: "10000", want: 10_000},
	} {
		t.Run(tc.token, func(t *testing.T) {
			tree := flatTreeFromSets(t, "set interfaces wan0 bandwidth "+tc.token)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid bandwidth %q: %v", tc.token, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid bandwidth %q: %v", tc.token, err)
			}
			if got := cfg.Interfaces.Interfaces["wan0"].Bandwidth; got != tc.want {
				t.Fatalf("bandwidth %q compiled to %d, want unchanged value %d",
					tc.token, got, tc.want)
			}
		})
	}
}
