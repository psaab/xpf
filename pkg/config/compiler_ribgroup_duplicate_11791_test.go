package config

import (
	"reflect"
	"strings"
	"testing"
)

const duplicateRibGroup11791 = `routing-instances {
    blue { instance-type virtual-router; }
}
routing-options {
    rib-groups {
        leak { import-rib inet.0; }
        leak { import-rib blue.inet.0; }
    }
}`

func compileRibGroup11791(t *testing.T, input string) *Config {
	t.Helper()
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse error: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestDuplicateRibGroupDefinitionsMerge11791(t *testing.T) {
	cfg := compileRibGroup11791(t, duplicateRibGroup11791)
	got := cfg.RoutingOptions.RibGroups["leak"].ImportRibs
	want := []string{"inet.0", "blue.inet.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate rib-group ImportRibs = %v, want merged declaration order %v", got, want)
	}
}

func TestDuplicateRibGroupDefinitionsMatchFlatSet11791(t *testing.T) {
	want := compileRibGroup11791(t, `routing-instances {
    blue { instance-type virtual-router; }
}
routing-options { rib-groups { leak { import-rib inet.0; import-rib blue.inet.0; } } }`)
	wantRibs := want.RoutingOptions.RibGroups["leak"].ImportRibs
	tree := buildTree(t, []string{
		"set routing-instances blue instance-type virtual-router",
		"set routing-options rib-groups leak import-rib inet.0",
		"set routing-options rib-groups leak import-rib blue.inet.0",
	})
	flat, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat-set compile: %v", err)
	}
	got := flat.RoutingOptions.RibGroups["leak"].ImportRibs
	if !reflect.DeepEqual(got, wantRibs) {
		t.Fatalf("flat-set ImportRibs = %v, hierarchical merged ImportRibs = %v", got, wantRibs)
	}
}

func TestDuplicateRibGroupDefinitionsAcrossRootsMerge11791(t *testing.T) {
	cfg := compileRibGroup11791(t, `routing-instances {
    blue { instance-type virtual-router; }
}
routing-options { rib-groups { leak { import-rib inet.0; } } }
routing-options { rib-groups { leak { import-rib blue.inet.0; } } }`)
	got := cfg.RoutingOptions.RibGroups["leak"].ImportRibs
	want := []string{"inet.0", "blue.inet.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cross-root ImportRibs = %v, want merged declaration order %v", got, want)
	}
	if !warningsContain(cfg.Warnings, "duplicate rib-group definition") || !warningsContain(cfg.Warnings, "leak") {
		t.Fatalf("cross-root merge lacks a named warning: %v", cfg.Warnings)
	}
}

func TestDuplicateRibGroupContainersMerge11791(t *testing.T) {
	cfg := compileRibGroup11791(t, `routing-instances {
    blue { instance-type virtual-router; }
}
routing-options {
    rib-groups { leak { import-rib inet.0; } }
    rib-groups { leak { import-rib blue.inet.0; } }
}`)
	got := cfg.RoutingOptions.RibGroups["leak"].ImportRibs
	want := []string{"inet.0", "blue.inet.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sibling rib-groups containers yielded %v, want merged %v", got, want)
	}
	count := 0
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate rib-group definition") && strings.Contains(warning, "leak") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("got %d duplicate rib-group warnings, want one naming leak: %v", count, cfg.Warnings)
	}
}

func TestDuplicateRibGroupDefinitionsAreAnnounced11791(t *testing.T) {
	tree, parseErrs := NewParser(duplicateRibGroup11791).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse error: %v", parseErrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	count := 0
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate rib-group definition") && strings.Contains(warning, "leak") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("got %d duplicate rib-group warnings, want one naming leak: %v", count, cfg.Warnings)
	}
}

func TestSingleRibGroupDefinitionUnchanged11791(t *testing.T) {
	cfg := compileRibGroup11791(t, `routing-instances {
    blue { instance-type virtual-router; }
}
routing-options { rib-groups { leak { import-rib inet.0; } } }`)
	got := cfg.RoutingOptions.RibGroups["leak"].ImportRibs
	if !reflect.DeepEqual(got, []string{"inet.0"}) {
		t.Fatalf("single rib-group ImportRibs = %v, want [inet.0]", got)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "duplicate rib-group definition") {
			t.Fatalf("single definition produced duplicate warning: %s", warning)
		}
	}
}
