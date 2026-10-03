package config

import (
	"strings"
	"testing"
)

func TestPerInstanceInterfaceRoutesRibGroupUndefined11790(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family, func(t *testing.T) {
			lines := []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue routing-options interface-routes rib-group " + family + " typo-group",
			}

			_, err := CompileConfig(buildTree(t, lines))
			if err == nil {
				t.Fatal("strict compile accepted an undefined per-instance rib-group")
			}
			for _, want := range []string{"routing-instance", "blue", family, "typo-group", "undefined rib-group"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("strict error %q does not name %q", err, want)
				}
			}

			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatalf("tolerant compile rejected a dangling reference: %v", err)
			}
			matchingWarnings := 0
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "undefined rib-group") {
					matchingWarnings++
					for _, want := range []string{"routing-instance", "blue", family, "typo-group"} {
						if !strings.Contains(warning, want) {
							t.Fatalf("tolerant warning %q does not name %q", warning, want)
						}
					}
				}
			}
			if matchingWarnings != 1 {
				t.Fatalf("got %d undefined-reference warnings, want one: %v", matchingWarnings, cfg.Warnings)
			}
		})
	}
}

func TestPerInstanceInterfaceRoutesRibGroupDefined11790(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue routing-options interface-routes rib-group inet valid-group",
		"set routing-options rib-groups valid-group import-rib inet.0",
	}))
	if err != nil {
		t.Fatalf("defined per-instance rib-group must commit: %v", err)
	}
	if warningsContain(cfg.Warnings, "valid-group") {
		t.Fatalf("defined per-instance rib-group must not warn about its name: %v", cfg.Warnings)
	}
}
