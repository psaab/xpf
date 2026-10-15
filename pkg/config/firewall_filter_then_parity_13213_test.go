package config

import (
	"strings"
	"testing"
)

// #13213 (D3-07): compileFilterThen must match the #9882 policer-then parity:
// block-form values are shielded before flattening, node.Keys[1:] is read even
// when the then node also carries children, and a bare valueless value-taking
// modifier records "<action> (missing value)" instead of silently no-opping.
//
// FAIL ON REVERT: restore `node.IsLeaf &&`, drop the shield, or drop the
// missing-value arms and the block-form / bare subtests go RED.

func filterThenTerm13213(t *testing.T, text string) (*Config, *FirewallFilterTerm, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 || tree == nil {
		t.Fatalf("parse errors = %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		return cfg, nil, err
	}
	return cfg, firstInetTerm(t, cfg, "f1"), nil
}

func TestCompileFilterThenBlockFormAndMissingValueParity13213(t *testing.T) {
	block := []struct {
		name  string
		body  string
		check func(*FirewallFilterTerm) (string, bool)
	}{
		{"policer", "policer { p1; } accept;", func(tm *FirewallFilterTerm) (string, bool) {
			return tm.Policer, tm.Policer == "p1" && tm.Action == "accept"
		}},
		{"count", "count { c1; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.Count, tm.Count == "c1" }},
		{"forwarding-class", "forwarding-class { af11; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.ForwardingClass, tm.ForwardingClass == "af11" }},
		{"loss-priority", "loss-priority { high; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.LossPriority, tm.LossPriority == "high" }},
		{"dscp", "dscp { ef; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.DSCPRewrite, tm.DSCPRewrite == "ef" }},
		{"traffic-class", "traffic-class { ef; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.DSCPRewrite, tm.DSCPRewrite == "ef" }},
		{"routing-instance", "routing-instance { ri1; } accept;", func(tm *FirewallFilterTerm) (string, bool) { return tm.RoutingInstance, tm.RoutingInstance == "ri1" }},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			text := "routing-instances { ri1 { instance-type forwarding; } }\n" +
				"firewall { policer p1 { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then discard; } " +
				"family inet { filter f1 { term t1 { then { " + tc.body + " } } } } }"
			cfg, term, err := filterThenTerm13213(t, text)
			if err != nil {
				t.Fatalf("block-form %s must compile cleanly, got %v (UnknownActions=%v)", tc.name, err, func() []string {
					if cfg != nil {
						return firstInetTerm(t, cfg, "f1").UnknownActions
					}
					return nil
				}())
			}
			if got, ok := tc.check(term); !ok {
				t.Fatalf("block-form %s: got %q, term=%+v UnknownActions=%v", tc.name, got, term, term.UnknownActions)
			}
			if len(term.UnknownActions) != 0 {
				t.Fatalf("block-form %s: UnknownActions=%v, want empty", tc.name, term.UnknownActions)
			}
		})
	}

	bare := []string{"policer", "count", "routing-instance", "forwarding-class", "loss-priority", "dscp", "traffic-class"}
	for _, action := range bare {
		t.Run("bare/"+action, func(t *testing.T) {
			text := "firewall { family inet { filter f1 { term t1 { then " + action + "; } } } }"
			tree, errs := NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs)
			}
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), action+" (missing value)") {
				t.Fatalf("bare %s: strict err=%v, want rejection naming %q", action, err, action+" (missing value)")
			}
			lenient, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("bare %s: lenient must boot: %v", action, lerr)
			}
			term := firstInetTerm(t, lenient, "f1")
			found := false
			for _, u := range term.UnknownActions {
				if u == action+" (missing value)" {
					found = true
				}
			}
			if !found {
				t.Fatalf("bare %s: UnknownActions=%v, want %q", action, term.UnknownActions, action+" (missing value)")
			}
			if term.Action != "discard" {
				t.Fatalf("bare %s: lenient Action=%q, want discard (fail-closed)", action, term.Action)
			}
		})
		// Flat-set spelling reaches the leaf arm: `then policer` with no value.
		t.Run("bare-flatset/"+action, func(t *testing.T) {
			tree := buildFilterTree(t,
				"set firewall family inet filter f1 term t1 then "+action)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), action+" (missing value)") {
				t.Fatalf("flat-set bare %s: strict err=%v, want rejection naming %q", action, err, action+" (missing value)")
			}
		})
	}

	// Mixed packed-key + braced body: Keys tail must be read even when
	// !IsLeaf (policer sibling GPT-3 shape).
	t.Run("mixed-keys-and-children", func(t *testing.T) {
		text := "firewall { family inet { filter f1 { term t1 { then count c1 { discard; } } } } }"
		_, term, err := filterThenTerm13213(t, text)
		if err != nil {
			t.Fatalf("mixed shape: %v", err)
		}
		if term.Count != "c1" {
			t.Fatalf("mixed shape: Count=%q, want c1 (Keys[1:] dropped when !IsLeaf)", term.Count)
		}
		if term.Action != "discard" {
			t.Fatalf("mixed shape: Action=%q, want discard from braced child", term.Action)
		}
	})
}
