package config

import (
	"strings"
	"testing"
)

// compiler_nat_mixed_scope_4881_test.go: #4881 — a single NAT rule-set `from`
// (or source-`to`, or static-`from`) clause that mixes scope KINDS (zone +
// interface + routing-instance) was accepted and OR-expanded by the #3096
// Cartesian product into multiple typed rule-sets, matching EITHER scope —
// WIDER than the operator's intent and contrary to Junos' one-kind-per-clause
// rule. The strict compile gate now rejects the mixed-kind clause at commit /
// commit-check and warns on the tolerant load / peer-sync path. Reverting the
// validateNATRuleSetMixedScopeAST wiring makes the "reject" subtests accept the
// widened config — RED.

func TestValidateNATRuleSetMixedScope(t *testing.T) {
	// Reject: two different scope KINDS in one source-NAT `from` clause. This is
	// the exact reproduction from the issue.
	t.Run("source from zone+interface rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS from interface ge-0/0/1.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject a source-NAT from clause mixing zone + interface")
		}
		msg := err.Error()
		for _, want := range []string{"source", "RS", "from", "zone", "interface"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("error should mention %q, got: %v", want, err)
			}
		}
	})

	t.Run("source from zone+routing-instance rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS from routing-instance blue",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a source-NAT from clause mixing zone + routing-instance")
		}
	})

	t.Run("source from interface+routing-instance rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from interface ge-0/0/1.0",
			"set security nat source rule-set RS from routing-instance blue",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a source-NAT from clause mixing interface + routing-instance")
		}
	})

	// The source-NAT `to` clause is also scoped by one kind.
	t.Run("source to zone+interface rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS to zone untrust",
			"set security nat source rule-set RS to interface ge-0/0/2.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		msgErr := func() error { _, e := CompileConfig(tree); return e }()
		if msgErr == nil {
			t.Fatal("CompileConfig should reject a source-NAT to clause mixing zone + interface")
		}
		if !strings.Contains(msgErr.Error(), "`to`") {
			t.Fatalf("error should name the `to` clause, got: %v", msgErr)
		}
	})

	// Destination NAT: from clause only (a DNAT `to` is separately rejected).
	t.Run("destination from zone+interface rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat destination rule-set RD from zone trust",
			"set security nat destination rule-set RD from interface ge-0/0/1.0",
			"set security nat destination rule-set RD rule R1 then destination-nat off",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a destination-NAT from clause mixing zone + interface")
		}
	})

	// Static NAT: from clause only.
	t.Run("static from zone+interface rejected", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat static rule-set RT from zone trust",
			"set security nat static rule-set RT from interface ge-0/0/1.0",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("CompileConfig should reject a static-NAT from clause mixing zone + interface")
		}
	})

	// No false positives: a single-kind `from` plus a single-kind `to` (each a
	// distinct clause, one kind apiece) is valid Junos and must compile clean.
	t.Run("source from zone + to interface compiles", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS to interface ge-0/0/2.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("single-kind from + single-kind to should compile, got: %v", err)
		}
	})

	// No false positives: multiple VALUES of the SAME kind (a zone list) is a
	// legitimate OR and must compile clean.
	t.Run("source from two zones compiles", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS from zone dmz",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("same-kind zone list should compile, got: %v", err)
		}
	})

	// Tolerant load / peer-sync: a persisted mixed-kind clause must not brick
	// the load — it downgrades to a warning.
	t.Run("lenient load downgrades mixed clause to warning", func(t *testing.T) {
		tree := buildNATScopeTree(t,
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS from interface ge-0/0/1.0",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should not fail on a mixed-kind clause, got: %v", err)
		}
		var found bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "scope kinds") && strings.Contains(w, "RS") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile should record a mixed-scope warning, warnings=%v", cfg.Warnings)
		}
	})
}
