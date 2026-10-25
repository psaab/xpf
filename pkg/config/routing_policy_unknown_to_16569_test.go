package config

import (
	"strings"
	"testing"
)

// #16569: policy-statement `to` match conditions and unmodelled `then`
// action keywords were dropped with only the #10707 advisory, widening the
// term (BGP import `to neighbor X` ≡ Junos `from neighbor X`).

func policyToTree16569(t *testing.T, shape string) *ConfigTree {
	t.Helper()
	switch shape {
	case "to block":
		src := `policy-options {
 policy-statement P {
  term T {
   from { route-filter 10.10.0.0/16 exact; }
   to { neighbor 192.0.2.1; }
   then accept;
  }
 }
}`
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	case "to leaf":
		src := `policy-options {
 policy-statement P {
  term T {
   from { route-filter 10.10.0.0/16 exact; }
   to neighbor 192.0.2.1;
   then accept;
  }
 }
}`
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	case "packed term":
		src := `policy-options {
 policy-statement P {
  term T from route-filter 10.10.0.0/16 exact to neighbor 192.0.2.1 then accept;
 }
}`
		tree, errs := NewParser(src).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	case "flat set":
		return buildTreeFromSet(t, []string{
			"set policy-options policy-statement P term T from route-filter 10.10.0.0/16 exact",
			"set policy-options policy-statement P term T to neighbor 192.0.2.1",
			"set policy-options policy-statement P term T then accept",
		})
	default:
		t.Fatalf("unknown shape %q", shape)
		return nil
	}
}

// FAIL-ON-REVERT: removing the `to` recorder or the gate makes every shape
// compile as a route-filter-only accept (the va05 import widening).
func TestRoutingPolicyUnknownToRejected16569(t *testing.T) {
	for _, shape := range []string{"to block", "to leaf", "packed term", "flat set"} {
		t.Run(shape, func(t *testing.T) {
			_, err := CompileConfig(policyToTree16569(t, shape))
			if err == nil || !strings.Contains(err.Error(), "`to neighbor`") || !strings.Contains(err.Error(), "#16569") {
				t.Fatalf("`to neighbor` in %s: err=%v, want #16569 strict reject", shape, err)
			}
		})
	}
	// Other `to` predicates Junos scopes the same way.
	for _, tc := range []struct{ leaf, value string }{
		{"protocol", "bgp"}, {"level", "1"}, {"neighbor", "192.0.2.1"},
	} {
		tree := buildTreeFromSet(t, []string{
			"set policy-options policy-statement P term T from protocol bgp",
			"set policy-options policy-statement P term T to " + tc.leaf + " " + tc.value,
			"set policy-options policy-statement P term T then accept",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("`to %s %s` compiled clean", tc.leaf, tc.value)
		}
	}
}

// FAIL-ON-REVERT: tolerant load must retain UnknownTo and force reject, not
// publish the widened permit.
func TestRoutingPolicyUnknownToFailsClosedOnTolerantLoad16569(t *testing.T) {
	for _, shape := range []string{"to block", "to leaf", "packed term", "flat set"} {
		t.Run(shape, func(t *testing.T) {
			cfg, err := CompileConfigLenient(policyToTree16569(t, shape))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if len(term.UnknownTo) != 1 || term.UnknownTo[0] != "neighbor" {
				t.Fatalf("UnknownTo = %v, want [neighbor]", term.UnknownTo)
			}
			if term.Action != "reject" || term.NextPolicy {
				t.Fatalf("did not fail closed: Action=%q NextPolicy=%v", term.Action, term.NextPolicy)
			}
			if len(term.RouteFilters) != 1 {
				t.Fatalf("route-filter must survive: %+v", term.RouteFilters)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "neighbor") {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings omit neighbor: %v", cfg.Warnings)
			}
		})
	}
}

// FAIL-ON-REVERT: statement-level `to` (no term scoping) must strict-reject
// and tolerant-force the default plus every term to reject.
func TestRoutingPolicyStatementLevelToFailsClosed16569(t *testing.T) {
	for _, shape := range []string{"hier", "flat"} {
		t.Run(shape, func(t *testing.T) {
			var tree *ConfigTree
			if shape == "hier" {
				src := `policy-options {
 policy-statement P {
  to neighbor 192.0.2.1;
  then accept;
  term T { from { protocol bgp; } then accept; }
 }
}`
				tr, errs := NewParser(src).Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				tree = tr
			} else {
				tree = buildTreeFromSet(t, []string{
					"set policy-options policy-statement P to neighbor 192.0.2.1",
					"set policy-options policy-statement P then accept",
					"set policy-options policy-statement P term T from protocol bgp",
					"set policy-options policy-statement P term T then accept",
				})
			}
			if _, err := CompileConfig(tree.Clone()); err == nil || !strings.Contains(err.Error(), "policy-level `to neighbor`") {
				t.Fatalf("strict: err=%v, want policy-level to reject", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant: %v", err)
			}
			stmt := cfg.PolicyOptions.PolicyStatements["P"]
			if len(stmt.UnknownTo) != 1 || stmt.UnknownTo[0] != "neighbor" || stmt.DefaultAction != "reject" {
				t.Fatalf("statement did not fail closed: %+v", stmt)
			}
			if len(stmt.Terms) != 1 || stmt.Terms[0].Action != "reject" || stmt.Terms[0].NextPolicy {
				t.Fatalf("terms did not fail closed: %+v", stmt.Terms)
			}
		})
	}
}

// FAIL-ON-REVERT: an unmodelled `then` action keyword in the child/flat
// spellings (previously only #10707) must strict-reject and tolerant-reject.
// The packed term-line spelling already rejected via #12517 and stays so.
func TestRoutingPolicyUnknownThenRejected16569(t *testing.T) {
	shapes := map[string]*ConfigTree{
		"hier": buildTreeFromSet(t, []string{
			"set policy-options policy-statement P term T from protocol bgp",
			"set policy-options policy-statement P term T then preference 5",
			"set policy-options policy-statement P term T then accept",
		}),
	}
	// hierarchical braced then block
	src := `policy-options {
 policy-statement P {
  term T {
   from { protocol bgp; }
   then { preference 5; accept; }
  }
 }
}`
	tr, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	shapes["braced"] = tr
	for name, tree := range shapes {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(tree.Clone()); err == nil || !strings.Contains(err.Error(), "`then preference`") {
				t.Fatalf("strict: err=%v, want then preference reject", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if len(term.UnknownThen) != 1 || term.UnknownThen[0] != "preference" {
				t.Fatalf("UnknownThen = %v, want [preference]", term.UnknownThen)
			}
			if term.Action != "reject" || term.NextPolicy {
				t.Fatalf("did not fail closed: Action=%q NextPolicy=%v", term.Action, term.NextPolicy)
			}
		})
	}
	// Packed control: still rejected (via #12517 unknown action).
	packed := buildTreeFromSet(t, []string{
		"set policy-options policy-statement P term T from protocol bgp",
	})
	_ = packed
	src2 := `policy-options {
 policy-statement P {
  term T from protocol bgp then preference 5 accept;
 }
}`
	tr2, errs := NewParser(src2).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse packed: %v", errs)
	}
	if _, err := CompileConfig(tr2); err == nil {
		t.Fatal("packed `then preference` compiled clean")
	}
}

// Positive control: supported terms carry no UnknownTo/UnknownThen.
func TestRoutingPolicySupportedToThenRemainClean16569(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement P term T from protocol bgp",
		"set policy-options policy-statement P term T then local-preference 200",
		"set policy-options policy-statement P term T then accept",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("supported term rejected: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.UnknownTo) != 0 || len(term.UnknownThen) != 0 || len(term.UnknownFrom) != 0 {
		t.Fatalf("supported term marked unknown: to=%v then=%v from=%v", term.UnknownTo, term.UnknownThen, term.UnknownFrom)
	}
	if term.Action != "accept" || !term.HasLocalPreference || term.LocalPreference != 200 {
		t.Fatalf("supported term changed: %+v", term)
	}
}
