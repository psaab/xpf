package config

import (
	"strings"
	"testing"
)

// #14433 (DR17-H4): a statement-level `then` carrying BOTH accept and reject
// must not silently resolve last-wins. Producers:
//   - group `then accept` merged beside inline `then reject` (and reverse)
//   - hand-authored duplicate `then` blocks in one statement
//   - packed / flat spellings of the same pair
// Strict commit rejects; tolerant load warns and fails closed (reject).
// Single / repeated-same / no default are unchanged.

func parse14433(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, err := NewParser(text).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tree
}

const groupConflict14433 = `groups {
    G {
        policy-options {
            policy-statement P {
                term t1 {
                    from { protocol bgp; }
                    then accept;
                }
                then accept;
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then accept;
        }
        then reject;
    }
}
apply-groups G;
`

const groupConflictNested14433 = `groups {
    G {
        policy-options {
            policy-statement P {
                then accept;
            }
        }
    }
}
policy-options {
    apply-groups G;
    policy-statement P {
        then reject;
    }
}
`
const groupConflictReverse14433 = `groups {
    G {
        policy-options {
            policy-statement P {
                term t1 {
                    from { protocol bgp; }
                    then accept;
                }
                then reject;
            }
        }
    }
}
policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then accept;
        }
        then accept;
    }
}
apply-groups G;
`

const duplicateThen14433 = `policy-options {
    policy-statement P {
        term t1 {
            from { protocol bgp; }
            then accept;
        }
        then accept;
        then reject;
    }
}
`

func assertStrictRejects14433(t *testing.T, text string) {
	t.Helper()
	_, err := CompileConfig(parse14433(t, text))
	if err == nil {
		t.Fatalf("strict CompileConfig accepted conflicting statement-level defaults; want rejection (#14433)")
	}
	if !strings.Contains(err.Error(), `"P"`) || !strings.Contains(err.Error(), "conflicting") ||
		!strings.Contains(err.Error(), "accept") || !strings.Contains(err.Error(), "reject") {
		t.Fatalf("strict error must name statement P and both actions, got: %v", err)
	}
}

func assertLenientFailsClosed14433(t *testing.T, text string) {
	t.Helper()
	cfg, err := CompileConfigLenient(parse14433(t, text))
	if err != nil {
		t.Fatalf("lenient compile must not brick (#1960): %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing")
	}
	if ps.DefaultAction != "reject" {
		t.Fatalf("lenient conflicting default must fail closed to reject, got %q", ps.DefaultAction)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "conflicting") && strings.Contains(w, "P") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn about the conflict, warnings=%v", cfg.Warnings)
	}
}

func TestPolicyStatementDefaultConflictGroupMerged14433(t *testing.T) {
	assertStrictRejects14433(t, groupConflict14433)
	assertLenientFailsClosed14433(t, groupConflict14433)
}

func TestPolicyStatementDefaultConflictGroupReverse14433(t *testing.T) {
	assertStrictRejects14433(t, groupConflictReverse14433)
	assertLenientFailsClosed14433(t, groupConflictReverse14433)
}

func TestPolicyStatementDefaultConflictDuplicateThen14433(t *testing.T) {
	assertStrictRejects14433(t, duplicateThen14433)
	assertLenientFailsClosed14433(t, duplicateThen14433)
}

func TestPolicyStatementDefaultGroupSingleControls14433(t *testing.T) {
	cfg, err := CompileConfig(parse14433(t, "groups { G { policy-options { policy-statement P { then accept; } } } }\npolicy-options { policy-statement P { term t1 { then accept; } } }\napply-groups G;"))
	if err != nil {
		t.Fatalf("group-only default must compile: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].DefaultAction; got != "accept" {
		t.Fatalf("group-only default = %q, want accept", got)
	}
	cfg, err = CompileConfig(parse14433(t, "groups { G { policy-options { policy-statement P { then accept; } } } }\npolicy-options { policy-statement P { then accept; } }\napply-groups G;"))
	if err != nil {
		t.Fatalf("same-action group+inline default must compile: %v", err)
	}
	if got := cfg.PolicyOptions.PolicyStatements["P"].DefaultAction; got != "accept" {
		t.Fatalf("same-action default = %q, want accept", got)
	}
}

func TestPolicyStatementDefaultConflictFlat14433(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}
	// Split spelling.
	if _, err := CompileConfig(build(t,
		"set policy-options policy-statement P then accept",
		"set policy-options policy-statement P then reject")); err == nil {
		t.Fatalf("strict split accept+reject must reject (#14433)")
	}
	// Packed spelling.
	if _, err := CompileConfig(build(t,
		"set policy-options policy-statement P then accept reject")); err == nil {
		t.Fatalf("strict packed accept reject must reject (#14433)")
	}
	// Lenient: both spellings fail closed identically (#8939 agreement).
	for _, cmds := range [][]string{
		{"set policy-options policy-statement P then accept", "set policy-options policy-statement P then reject"},
		{"set policy-options policy-statement P then accept reject"},
	} {
		cfg, err := CompileConfigLenient(build(t, cmds...))
		if err != nil {
			t.Fatalf("lenient %v: %v", cmds, err)
		}
		ps := cfg.PolicyOptions.PolicyStatements["P"]
		if ps == nil || ps.DefaultAction != "reject" {
			t.Fatalf("lenient %v must fail closed to reject, got %+v", cmds, ps)
		}
	}
}

func TestPolicyStatementDefaultSingleControls14433(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"single accept", "policy-options { policy-statement P { then accept; } }", "accept"},
		{"single reject", "policy-options { policy-statement P { then reject; } }", "reject"},
		{"no default", "policy-options { policy-statement P { term t1 { then accept; } } }", ""},
		{"repeated same accept", "policy-options { policy-statement P { then accept; then accept; } }", "accept"},
		{"repeated same reject", "policy-options { policy-statement P { then reject; then reject; } }", "reject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(parse14433(t, tc.text))
			if err != nil {
				t.Fatalf("single/repeated-same default must compile: %v", err)
			}
			ps := cfg.PolicyOptions.PolicyStatements["P"]
			if ps == nil || ps.DefaultAction != tc.want {
				t.Fatalf("DefaultAction=%v want %q", ps, tc.want)
			}
		})
	}
	// Isolation: different statements each with a single different default
	// must not leak into a conflict.
	cfg, err := CompileConfig(parse14433(t, `policy-options {
        policy-statement P { then accept; }
        policy-statement Q { then reject; }
    }`))
	if err != nil {
		t.Fatalf("distinct statements must not conflict: %v", err)
	}
	if cfg.PolicyOptions.PolicyStatements["P"].DefaultAction != "accept" ||
		cfg.PolicyOptions.PolicyStatements["Q"].DefaultAction != "reject" {
		t.Fatalf("per-statement defaults leaked: P=%q Q=%q",
			cfg.PolicyOptions.PolicyStatements["P"].DefaultAction,
			cfg.PolicyOptions.PolicyStatements["Q"].DefaultAction)
	}
}
