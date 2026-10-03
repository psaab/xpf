package config

import (
	"strings"
	"testing"
)

func interfaceSpeedTree11797(t *testing.T, value string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set interfaces ge-0/0/0 speed " + value)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

func TestInterfaceSpeedTypedLeafAndLineRate11797(t *testing.T) {
	for _, tc := range []struct {
		value string
		mbps  uint64
	}{
		{"10m", 10},
		{"100m", 100},
		{"1g", 1000},
		{"2.5g", 2500},
		{"5g", 5000},
		{"10g", 10000},
		{"25g", 25000},
		{"40g", 40000},
		{"100g", 100000},
		{"auto", 0},
		{"1G", 1000}, // Existing consumers accepted case-insensitive notation.
	} {
		t.Run(tc.value, func(t *testing.T) {
			tree := interfaceSpeedTree11797(t, tc.value)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid speed %q: %v", tc.value, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid speed %q: %v", tc.value, err)
			}
			want := strings.ToLower(tc.value)
			if got := cfg.Interfaces.Interfaces["ge-0/0/0"].Speed; got != want {
				t.Fatalf("compiled speed = %q, want normalized %q", got, want)
			}
			lineRate := coSInterfaceLineRateBytes(cfg, "ge-0/0/0")
			wantRate := tc.mbps * 1_000_000 / 8
			if lineRate != wantRate {
				t.Fatalf("CoS line rate for %q = %d bytes/s, want %d", tc.value, lineRate, wantRate)
			}
		})
	}
}

func TestInterfaceSpeedInvalidStrictRejectsAndLenientWarns11797(t *testing.T) {
	for _, value := range []string{"1000", "1000m", "1.5g", "bogus", "autofoo"} {
		t.Run(value, func(t *testing.T) {
			tree := interfaceSpeedTree11797(t, value)
			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "speed") {
				t.Fatalf("SchemaValidate(%q) = %v, want a speed rejection", value, err)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "speed") {
				t.Fatalf("CompileConfig(%q) = %v, want a speed rejection", value, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient(%q): %v", value, err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0/0/0"].Speed; got != "" {
				t.Fatalf("lenient compile retained invalid speed %q", got)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "interfaces ge-0/0/0 speed") {
				t.Fatalf("lenient compile did not warn naming invalid speed: %v", cfg.Warnings)
			}
		})
	}
}

func TestCoSInterfaceLineRateSpeedConversion11797(t *testing.T) {
	for _, tc := range []struct {
		speed string
		want  uint64
	}{
		{"10m", 1_250_000},
		{"100m", 12_500_000},
		{"1g", 125_000_000},
		{"2.5g", 312_500_000},
		{"5g", 625_000_000},
		{"10g", 1_250_000_000},
		{"25g", 3_125_000_000},
		{"40g", 5_000_000_000},
		{"100g", 12_500_000_000},
		{"auto", 0},
		{"bogus", 0},
	} {
		t.Run(tc.speed, func(t *testing.T) {
			cfg := &Config{}
			cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
				"ge-0/0/0": {Speed: tc.speed},
			}
			if got := coSInterfaceLineRateBytes(cfg, "ge-0/0/0"); got != tc.want {
				t.Fatalf("CoS line rate for %q = %d, want %d", tc.speed, got, tc.want)
			}
		})
	}
}
