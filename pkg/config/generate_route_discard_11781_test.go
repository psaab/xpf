package config

import (
	"strings"
	"testing"
)

func TestGenerateRouteWithoutDiscardWarnsAboutBlackhole11781(t *testing.T) {
	strictTree := buildTree(t, []string{
		"set routing-options generate route 192.0.2.0/24",
	})
	strictCfg, err := CompileConfig(strictTree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var commitWarnings []string
	for _, warning := range strictCfg.Warnings {
		if strings.Contains(warning, "has no discard action") {
			commitWarnings = append(commitWarnings, warning)
		}
	}
	if len(commitWarnings) != 1 ||
		!strings.Contains(commitWarnings[0], "192.0.2.0/24") ||
		!strings.Contains(commitWarnings[0], "blackhole") {
		t.Fatalf("strict compile warnings do not report the rendered blackhole: %v", strictCfg.Warnings)
	}

	tree := buildTree(t, []string{
		"set routing-options generate route 192.0.2.0/24",
		"set routing-options generate route 198.51.100.0/24 discard",
		"set routing-options generate route 203.0.113.0/24 policy contributors",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	var loadWarnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "has no discard action") {
			loadWarnings = append(loadWarnings, warning)
		}
	}
	if len(loadWarnings) != 1 || !strings.Contains(loadWarnings[0], "192.0.2.0/24") {
		t.Fatalf("tolerant compile warnings do not name the no-discard route: %v", cfg.Warnings)
	}

	var warnings []string
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, "generate route") && strings.Contains(warning, "does not") {
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) != 1 {
		t.Fatalf("generate-route discard warning count = %d, want one: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "192.0.2.0/24") ||
		!strings.Contains(warnings[0], "blackhole") ||
		!strings.Contains(warnings[0], "primary contributing route") {
		t.Fatalf("generate-route warning does not explain the unsupported inheritance: %q", warnings[0])
	}
}
