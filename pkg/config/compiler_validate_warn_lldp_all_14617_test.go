package config

import (
	"strings"
	"testing"
)

// #14617 commit-time advisory for `interface all disable`, plus a
// compile pin that plain `interface all` compiles verbatim (expansion
// happens at daemon apply time, not in the typed config, so the
// authored stanza survives for show / sync).

func TestLLDPAllDisableWarns14617(t *testing.T) {
	tree, perrs := NewParser("protocols { lldp { interface all { disable; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Premise: compiler stores the wildcard entry verbatim.
	if len(cfg.Protocols.LLDP.Interfaces) != 1 || cfg.Protocols.LLDP.Interfaces[0].Name != "all" || !cfg.Protocols.LLDP.Interfaces[0].Disable {
		t.Fatalf("compiled LLDP = %+v, want [{all true}]", cfg.Protocols.LLDP.Interfaces)
	}
	var found []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#14617") {
			found = append(found, w)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], "interface all disable") {
		t.Fatalf("want one #14617 advisory for all+disable, got %v (all warnings: %v)", found, ValidateConfig(cfg))
	}

	// Enabled `all` must NOT warn: it is supported (expanded at apply).
	tree2, _ := NewParser("protocols { lldp { interface all; interface fxp0 { disable; } } }").Parse()
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile2: %v", err)
	}
	for _, w := range ValidateConfig(cfg2) {
		if strings.Contains(w, "#14617") {
			t.Fatalf("enabled all+per-interface disable must not warn, got %q", w)
		}
	}
	// Case-sensitivity: `All` is not the wildcard.
	cfg3 := &Config{}
	cfg3.Protocols.LLDP = &LLDPConfig{Interfaces: []LLDPInterface{{Name: "All", Disable: true}}}
	if got := validateLLDPAllDisableWarning(cfg3); len(got) != 0 {
		t.Fatalf("All (capital) must not trigger wildcard advisory, got %v", got)
	}
	if got := validateLLDPAllDisableWarning(nil); len(got) != 0 {
		t.Fatalf("nil cfg must be silent, got %v", got)
	}
}
