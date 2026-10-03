package config

import (
	"strings"
	"testing"
)

func TestFilterDistinctRoutingInstanceTargetsConflict11814(t *testing.T) {
	tree, parseErrors := NewParser(`
routing-instances {
    blue { instance-type forwarding; }
    red { instance-type forwarding; }
}
firewall { family inet { filter f { term t {
    then { routing-instance blue; }
    then { routing-instance red; }
} } } }
`).Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse distinct then blocks: %v", parseErrors)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted two different routing-instance targets in one filter term")
	} else {
		for _, part := range []string{`filter "f"`, `term "t"`, "routing-instance blue", "routing-instance red"} {
			if !strings.Contains(err.Error(), part) {
				t.Fatalf("strict error %q does not identify conflict component %q", err, part)
			}
		}
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile hard-failed on persisted RI target conflict: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if term.routingInstanceTargetFirst != "blue" || term.routingInstanceTargetConflict != "red" {
		t.Fatalf("lenient term lost RI target conflict record: first=%q conflict=%q",
			term.routingInstanceTargetFirst, term.routingInstanceTargetConflict)
	}
	if term.RoutingInstance != "red" || term.Action != "" {
		t.Fatalf("lenient compile changed effective last target: routing-instance=%q action=%q", term.RoutingInstance, term.Action)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "firewall filter routing-instance conflict") &&
			strings.Contains(warning, "routing-instance blue") &&
			strings.Contains(warning, "routing-instance red") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("lenient path omitted named RI target conflict warning: %v", cfg.Warnings)
	}
}

func TestFilterSameRoutingInstanceTargetDuplicateAllowed11814(t *testing.T) {
	tree, parseErrors := NewParser(`
routing-instances { blue { instance-type forwarding; } }
firewall { family inet { filter f { term t {
    then { routing-instance blue; }
    then { routing-instance blue; }
} } } }
`).Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse duplicate then blocks: %v", parseErrors)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected duplicate same-target routing-instance actions: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if term.RoutingInstance != "blue" || term.Action != "" {
		t.Fatalf("same-target duplicate changed effective FBF action: routing-instance=%q action=%q", term.RoutingInstance, term.Action)
	}
	if term.routingInstanceTargetFirst != "blue" || term.routingInstanceTargetConflict != "" {
		t.Fatalf("identical routing-instance targets were marked conflicting: first=%q conflict=%q",
			term.routingInstanceTargetFirst, term.routingInstanceTargetConflict)
	}
}

func TestFilterSingleRoutingInstanceActionUnchanged11814(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances blue instance-type forwarding",
		"set firewall family inet filter f term t then routing-instance blue",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("single-target FBF compile failed: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if term.RoutingInstance != "blue" || term.Action != "" || term.NextTerm {
		t.Fatalf("single-target FBF action changed: routing-instance=%q action=%q next-term=%t", term.RoutingInstance, term.Action, term.NextTerm)
	}
	if term.routingInstanceTargetFirst != "blue" || term.routingInstanceTargetConflict != "" {
		t.Fatalf("single-target routing-instance record changed: first=%q conflict=%q",
			term.routingInstanceTargetFirst, term.routingInstanceTargetConflict)
	}
}
