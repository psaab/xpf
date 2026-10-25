package config

import (
	"strings"
	"testing"
)

// #16577: the #7121 `from protocol` gate had no tolerant downgrade — a
// persisted or peer-synced config carrying a Junos token FRR cannot emit
// (aggregate/local/access-internal, or a plain typo) failed Store.Load
// (bootstrap/lifeline, no forwarding config) and HA SyncApply. The tolerant
// path must warn and poison the offending term to reject instead, while
// Junos ospf3/ospf2 alias through the SSOT and strict-commit as OSPFv3/v2.

func routingProtocolTree16577(t *testing.T, protos ...string) *ConfigTree {
	t.Helper()
	cmds := make([]string, 0, len(protos)+1)
	for _, p := range protos {
		cmds = append(cmds, "set policy-options policy-statement P term T from protocol "+p)
	}
	cmds = append(cmds, "set policy-options policy-statement P term T then accept")
	return buildTreeFromSet(t, cmds)
}

func TestRoutingPolicyProtocolStrictCommitAliases16577(t *testing.T) {
	for _, tc := range []struct{ proto, keyword string }{
		{"ospf3", "ospf6"},
		{"ospf2", "ospf"},
	} {
		t.Run(tc.proto, func(t *testing.T) {
			cfg, err := CompileConfig(routingProtocolTree16577(t, tc.proto))
			if err != nil {
				t.Fatalf("strict commit of `from protocol %s` must succeed as %s: %v", tc.proto, tc.keyword, err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "accept" {
				t.Fatalf("aliased term Action = %q, want accept (no poison)", term.Action)
			}
			if got := CanonicalSourceProtocol(term.FromProtocols[0]); got != tc.keyword {
				t.Fatalf("CanonicalSourceProtocol(%q) = %q, want %q", term.FromProtocols[0], got, tc.keyword)
			}
		})
	}
}

func TestRoutingPolicyProtocolUnknownStrictRejects16577(t *testing.T) {
	for _, proto := range []string{"aggregate", "local", "access-internal", "ospv"} {
		t.Run(proto, func(t *testing.T) {
			_, err := CompileConfig(routingProtocolTree16577(t, proto))
			if err == nil {
				t.Fatalf("strict commit of `from protocol %s` compiled clean; it would render an FRR-rejected source-protocol", proto)
			}
			for _, want := range []string{"P", "T", proto} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection does not name %q: %v", want, err)
				}
			}
		})
	}
}

// FAIL-ON-REVERT: without the lenient branch in runEarlyStrictAndFolds the
// tolerant compile returns the #7121 error and every case bricks.
func TestRoutingPolicyProtocolUnknownTolerantPoisons16577(t *testing.T) {
	for _, proto := range []string{"aggregate", "local", "access-internal", "ospv"} {
		t.Run(proto, func(t *testing.T) {
			cfg, err := CompileConfigLenient(routingProtocolTree16577(t, proto))
			if err != nil {
				t.Fatalf("tolerant compile of `from protocol %s` must warn, not brick (#1960): %v", proto, err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "reject" || term.NextPolicy {
				t.Fatalf("offending term not poisoned: Action=%q NextPolicy=%v, want reject/false", term.Action, term.NextPolicy)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "routing policy protocol") && strings.Contains(w, proto) {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("tolerant warnings %v do not name the downgraded protocol %q", cfg.Warnings, proto)
			}
		})
	}
}

// A mixed term (one resolvable, one unknown protocol) poisons as a whole:
// rendering only the resolvable OR-branch would widen the term to a match
// Junos never authored for those routes.
func TestRoutingPolicyProtocolMixedTermPoisons16577(t *testing.T) {
	cfg, err := CompileConfigLenient(routingProtocolTree16577(t, "direct", "local"))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "reject" {
		t.Fatalf("mixed term Action = %q, want reject", term.Action)
	}
}

// Sibling terms in the same statement keep their authored action: the
// poison is per-term, not per-statement.
func TestRoutingPolicyProtocolPoisonIsPerTerm16577(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement P term BAD from protocol aggregate",
		"set policy-options policy-statement P term BAD then accept",
		"set policy-options policy-statement P term GOOD from protocol static",
		"set policy-options policy-statement P term GOOD then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	terms := cfg.PolicyOptions.PolicyStatements["P"].Terms
	if len(terms) != 2 {
		t.Fatalf("terms = %d, want 2", len(terms))
	}
	byName := map[string]*PolicyTerm{}
	for _, term := range terms {
		byName[term.Name] = term
	}
	if byName["BAD"].Action != "reject" {
		t.Errorf("BAD term Action = %q, want reject", byName["BAD"].Action)
	}
	if byName["GOOD"].Action != "accept" {
		t.Errorf("GOOD term Action = %q, want accept (poison leaked across terms)", byName["GOOD"].Action)
	}
}
