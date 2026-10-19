package config

import (
	"strings"
	"testing"
)

// Tests for #3079 / #3096: a NAT rule-set whose `from`/`to` clause scopes
// traffic by `interface` or `routing-instance` (in addition to the already-
// enforced `zone`). #3079 used to SILENTLY discard the scope and widen the
// rule-set to match-any; #3095 made that an interim reject-at-commit; #3096
// now CAPTURES the scope on the typed config and ENFORCES it in the dataplane
// match path, so the rule-set commits cleanly and the scope survives onto the
// typed NATRuleSet / StaticNATRuleSet.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildNATScopeTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	cmds = prependNATZoneDefs15001(cmds)
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestNATRuleSetScopeCommitsAndIsCaptured proves the #3095 interim reject is
// LIFTED (#3096): an interface- or routing-instance-scoped from/to clause now
// COMMITS for source, destination, AND static NAT, and the scope is captured
// on the typed config instead of being discarded. Reverting the compiler
// scope capture (collectNATScopes/applyNAT*Scope) so the scope is dropped
// turns the field assertions RED.
func TestNATRuleSetScopeCommitsAndIsCaptured(t *testing.T) {
	t.Run("source from interface", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from interface ge-0/0/0.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected interface-scoped source NAT: %v", err)
		}
		if len(cfg.Security.NAT.Source) != 1 {
			t.Fatalf("got %d source rule-sets, want 1", len(cfg.Security.NAT.Source))
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.FromInterface != "ge-0/0/0.0" {
			t.Fatalf("FromInterface = %q, want ge-0/0/0.0", rs.FromInterface)
		}
		if rs.FromZone != "" {
			t.Fatalf("FromZone = %q, want empty (interface-scoped)", rs.FromZone)
		}
	})

	t.Run("source from routing-instance", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from routing-instance blue",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected RI-scoped source NAT: %v", err)
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.FromRoutingInstance != "blue" {
			t.Fatalf("FromRoutingInstance = %q, want blue", rs.FromRoutingInstance)
		}
	})

	t.Run("source to interface", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS to interface ge-0/0/1.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected to-interface source NAT: %v", err)
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.ToInterface != "ge-0/0/1.0" {
			t.Fatalf("ToInterface = %q, want ge-0/0/1.0", rs.ToInterface)
		}
	})

	t.Run("source to routing-instance", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS to routing-instance red",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected to-RI source NAT: %v", err)
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.ToRoutingInstance != "red" {
			t.Fatalf("ToRoutingInstance = %q, want red", rs.ToRoutingInstance)
		}
	})

	t.Run("destination from interface", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			// #5626: the referenced DNAT pool must be defined or the strict
			// pool-reference gate rejects — this test asserts SCOPE capture, so
			// define P1 to keep the config well-formed.
			"set security nat destination pool P1 address 10.0.0.5/32",
			"set security nat destination rule-set RD from interface ge-0/0/0.0",
			"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.5/32",
			"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected interface-scoped destination NAT: %v", err)
		}
		if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) != 1 {
			t.Fatalf("destination rule-sets not compiled")
		}
		rs := cfg.Security.NAT.Destination.RuleSets[0]
		if rs.FromInterface != "ge-0/0/0.0" {
			t.Fatalf("FromInterface = %q, want ge-0/0/0.0", rs.FromInterface)
		}
	})

	t.Run("destination from routing-instance", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			// #5626: define the referenced DNAT pool so the strict pool-reference
			// gate does not reject; this subtest asserts RI-scope capture.
			"set security nat destination pool P1 address 10.0.0.5/32",
			"set security nat destination rule-set RD from routing-instance blue",
			"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.5/32",
			"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected RI-scoped destination NAT: %v", err)
		}
		rs := cfg.Security.NAT.Destination.RuleSets[0]
		if rs.FromRoutingInstance != "blue" {
			t.Fatalf("FromRoutingInstance = %q, want blue", rs.FromRoutingInstance)
		}
	})

	t.Run("static from interface", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat static rule-set RT from interface ge-0/0/0.0",
			"set security nat static rule-set RT rule R1 match destination-address 198.51.100.5/32",
			"set security nat static rule-set RT rule R1 then static-nat prefix 10.0.0.5/32",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected interface-scoped static NAT: %v", err)
		}
		if len(cfg.Security.NAT.Static) != 1 {
			t.Fatalf("got %d static rule-sets, want 1", len(cfg.Security.NAT.Static))
		}
		rs := cfg.Security.NAT.Static[0]
		if rs.FromInterface != "ge-0/0/0.0" {
			t.Fatalf("FromInterface = %q, want ge-0/0/0.0", rs.FromInterface)
		}
	})

	t.Run("static from routing-instance", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat static rule-set RT from routing-instance blue",
			"set security nat static rule-set RT rule R1 match destination-address 198.51.100.5/32",
			"set security nat static rule-set RT rule R1 then static-nat prefix 10.0.0.5/32",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected RI-scoped static NAT: %v", err)
		}
		rs := cfg.Security.NAT.Static[0]
		if rs.FromRoutingInstance != "blue" {
			t.Fatalf("FromRoutingInstance = %q, want blue", rs.FromRoutingInstance)
		}
	})
}

// TestNATRuleSetZoneScopeStillCommits proves the `from zone` / `to zone`
// scope, and a rule-set with NO from/to clause (the legitimate global case),
// still commit cleanly and populate the zone fields (no regression).
func TestNATRuleSetZoneScopeStillCommits(t *testing.T) {
	t.Run("from/to zone", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS to zone untrust",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected a zone-scoped NAT rule-set: %v", err)
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.FromZone != "trust" || rs.ToZone != "untrust" {
			t.Fatalf("zone scope = (%q,%q), want (trust,untrust)", rs.FromZone, rs.ToZone)
		}
		if rs.FromInterface != "" || rs.ToInterface != "" || rs.FromRoutingInstance != "" || rs.ToRoutingInstance != "" {
			t.Fatalf("zone-scoped rule-set leaked interface/RI scope: %+v", rs)
		}
	})
	t.Run("global (no from/to)", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected a global (no from/to) NAT rule-set: %v", err)
		}
		rs := cfg.Security.NAT.Source[0]
		if rs.FromZone != "" || rs.ToZone != "" || rs.FromInterface != "" || rs.ToInterface != "" {
			t.Fatalf("global rule-set carried a scope: %+v", rs)
		}
	})
}

// TestNATRuleSetScopeLenientCommits proves the tolerant load/peer-sync path
// (CompileConfigLenient) also accepts and captures an interface/RI scope —
// the #3079 reject/warn is gone (#3096), the scope is enforced now.
func TestNATRuleSetScopeLenientCommits(t *testing.T) {
	tree := buildNATScopeTree(t,
		"set security nat source rule-set RS from interface ge-0/0/0.0",
		"set security nat source rule-set RS rule R1 then source-nat interface",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on interface-scoped NAT: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromInterface != "ge-0/0/0.0" {
		t.Fatalf("FromInterface = %q, want ge-0/0/0.0", rs.FromInterface)
	}
	// The #3079 reject is lifted: no scope-rejection warning should be emitted.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3079") {
			t.Fatalf("unexpected #3079 scope warning after enforcement landed: %q", w)
		}
	}
}
