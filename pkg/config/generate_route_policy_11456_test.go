package config

import (
	"strings"
	"testing"
)

func TestGenerateRoutePolicyRejectedAndWarned11456(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/8 policy contributors",
	})

	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "generate route") ||
		!strings.Contains(err.Error(), "policy") {
		t.Fatalf("strict compile error = %v, want generate-route policy rejection", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected persisted generate-route policy: %v", err)
	}
	if len(cfg.RoutingOptions.GenerateRoutes) != 1 ||
		cfg.RoutingOptions.GenerateRoutes[0].Policy != "contributors" {
		t.Fatalf("tolerant compile did not preserve generate route: %+v", cfg.RoutingOptions.GenerateRoutes)
	}
	warningCount := func(warnings []string) int {
		count := 0
		for _, warning := range warnings {
			if strings.Contains(warning, "generate route") &&
				strings.Contains(warning, "contributors") &&
				strings.Contains(warning, "NOT INSTALLED") {
				count++
			}
		}
		return count
	}
	if count := warningCount(cfg.Warnings); count != 1 {
		t.Fatalf("tolerant compile warning count = %d, want one NOT INSTALLED warning: %v", count, cfg.Warnings)
	}
	if count := warningCount(ValidateConfig(cfg)); count != 1 {
		t.Fatalf("ValidateConfig warning count = %d, want one NOT INSTALLED alarm: %v", count, ValidateConfig(cfg))
	}
}

func TestGenerateRoutePolicyAddRemove11456(t *testing.T) {
	withoutPolicy := buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/8",
	})
	if _, err := CompileConfig(withoutPolicy); err != nil {
		t.Fatalf("strict compile rejected generate route after policy removal: %v", err)
	}

	withPolicy := buildTree(t, []string{
		"set routing-options generate route 10.0.0.0/8 policy contributors",
	})
	if _, err := CompileConfig(withPolicy); err == nil {
		t.Fatal("strict compile accepted newly added generate-route policy")
	}
}
