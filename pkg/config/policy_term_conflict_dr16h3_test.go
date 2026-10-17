package config

import (
	"strings"
	"testing"
)

// #14425 (DR16-H3): a routing policy-statement term whose merged `then`
// carries BOTH accept and reject must strict-reject (or lenient warn+drop).
// Before the gate, parsePolicyTermChildren / parsePolicyTermInlineKeys
// assigned term.Action unconditionally per arm, so group children sorting
// after inline made the group's action win silently.
//
// FAIL-ON-REVERT: remove TerminalActions accumulation or the
// validateRoutingTermTerminalConflictStrict gate and the strict cells go
// RED — CompileConfig accepts the contradictory term.

func dr16h3Term(t *testing.T, cfg *Config) *PolicyTerm {
	t.Helper()
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing: %+v", cfg.PolicyOptions.PolicyStatements)
	}
	for _, term := range ps.Terms {
		if term != nil && term.Name == "t1" {
			return term
		}
	}
	t.Fatalf("term t1 missing in P: %+v", ps.Terms)
	return nil
}

// Group (braced) supplies accept, inline (braced) supplies reject.
// apply-groups sits inside the policy-statement, per the DR16-H3 fixture.
const dr16h3GroupBraced = `groups {
    G {
        policy-options {
            policy-statement P {
                term t1 {
                    from { protocol ospf; }
                    then accept;
                }
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then reject;
        }
        apply-groups G;
    }
}`

// Same conflict, packed group term (then-first packed leaf).
const dr16h3GroupPacked = `groups {
    G {
        policy-options {
            policy-statement P {
                term t1 then accept;
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then reject;
        }
        apply-groups G;
    }
}`

// From-first packed group term: match + terminal in one leaf. Its merge
// runs through the generic packed-term path (#12537), not the bare
// terminal adoption — the conflict must still reach the gate.
const dr16h3GroupFromPacked = `groups {
    G {
        policy-options {
            policy-statement P {
                term t1 from protocol ospf then accept;
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then reject;
        }
        apply-groups G;
    }
}`

// Hand-authored duplicate braced then in one term (no groups).
const dr16h3BracedTwin = `policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then { accept; reject; }
        }
    }
}`

// Flat-set twin: two then lines for same term.
func dr16h3FlatTree(t *testing.T) *ConfigTree {
	t.Helper()
	return buildTreeFromSet(t, []string{
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then reject",
		"set policy-options policy-statement P term t1 then accept",
	})
}

func TestRoutingTermConflictingThenStrictReject14425(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"group-braced-accept-vs-inline-reject", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3GroupBraced) }},
		{"group-packed-accept-vs-inline-reject", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3GroupPacked) }},
		{"group-from-packed-accept-vs-inline-reject", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3GroupFromPacked) }},
		{"braced-twin", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3BracedTwin) }},
		{"flat-set-twin", dr16h3FlatTree},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree(t))
			if err == nil {
				t.Fatalf("conflicting accept+reject term compiled clean; group/last action would silently win")
			}
			if !strings.Contains(err.Error(), "P") || !strings.Contains(err.Error(), "t1") {
				t.Fatalf("error %q must name policy-statement P and term t1", err)
			}
			if !strings.Contains(err.Error(), "accept") || !strings.Contains(err.Error(), "reject") {
				t.Fatalf("error %q must name both conflicting actions", err)
			}
		})
	}
}

func TestRoutingTermConflictingThenLenientFailsClosed14425(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"group-braced", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3GroupBraced) }},
		{"group-from-packed", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3GroupFromPacked) }},
		{"braced-twin", func(t *testing.T) *ConfigTree { return hierTree(t, dr16h3BracedTwin) }},
		{"flat-set-twin", dr16h3FlatTree},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must boot (#1960): %v", err)
			}
			term := dr16h3Term(t, cfg)
			if term.Action == "accept" {
				t.Fatalf("lenient conflicting term kept accept (fail-open): TerminalActions=%v Action=%q", term.TerminalActions, term.Action)
			}
			if term.Action != "reject" {
				t.Fatalf("lenient conflicting term Action=%q, want fail-closed reject", term.Action)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "t1") && strings.Contains(w, "accept") && strings.Contains(w, "reject") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient warnings %v omit conflicting-action warning for t1", cfg.Warnings)
			}
		})
	}
}

func TestRoutingTermSingleActionControls14425(t *testing.T) {
	// Same action on both sides: redundancy, not conflict.
	sameReject := `groups {
    G { policy-options { policy-statement P { term t1 { from { protocol ospf; } then reject; } } } }
}
policy-options {
    policy-statement P { term t1 { from { protocol bgp; } then reject; } apply-groups G; }
}`
	cfg, err := CompileConfig(hierTree(t, sameReject))
	if err != nil {
		t.Fatalf("same-action merged term rejected: %v", err)
	}
	if term := dr16h3Term(t, cfg); term.Action != "reject" {
		t.Fatalf("same-reject term Action=%q, want reject", term.Action)
	}

	// Single accept with non-terminal modifiers coexists.
	acceptMods := `policy-options {
    policy-statement P {
        term t1 { from { protocol bgp; } then { local-preference 200; accept; } }
        term t2 { from { protocol ospf; } then reject; }
    }
}`
	cfg, err = CompileConfig(hierTree(t, acceptMods))
	if err != nil {
		t.Fatalf("single-action terms rejected: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	var t1, t2 *PolicyTerm
	for _, term := range ps.Terms {
		switch term.Name {
		case "t1":
			t1 = term
		case "t2":
			t2 = term
		}
	}
	if t1 == nil || t1.Action != "accept" || !t1.HasLocalPreference || t1.LocalPreference != 200 {
		t.Fatalf("t1 = %+v, want accept with local-preference 200", t1)
	}
	if t2 == nil || t2.Action != "reject" {
		t.Fatalf("t2 = %+v, want reject", t2)
	}

	// No-policy / modifier-only term unchanged.
	modifierOnly := `policy-options {
    policy-statement P {
        term t1 { from { protocol bgp; } then { local-preference 200; } }
    }
}`
	cfg, err = CompileConfig(hierTree(t, modifierOnly))
	if err != nil {
		t.Fatalf("modifier-only term rejected: %v", err)
	}
	if term := dr16h3Term(t, cfg); term.Action != "" {
		t.Fatalf("modifier-only term Action=%q, want empty", term.Action)
	}
}
