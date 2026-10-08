package config

import (
	"strings"
	"testing"
)

// RED for #12092: a hierarchical NAMELESS term — `term { then discard; }`
// (the literal remedy the #3295 no-catch-all advisory prints), `term { then
// reject; }`, `term { foo bar; }`, `term { foo; }` — passes strict commit and
// compiles to a fall-through term with empty action. The #10294 gate must
// inspect each instance's tail and reject nameless term instances, including
// tails of both namedInstances AST shapes. Named controls still ACCEPT with
// action "discard".

// namelessTermHier12092 builds the one-key `term` node shape: namedInstances
// turns each CHILD into an instance named by its own first key, so `then
// discard` becomes a term named `then` whose node Keys=[then, discard].
func namelessTermHier12092(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return hierTree(t, `firewall {
    family inet {
        filter f1 {
            term {
                `+body+`
            }
        }
    }
}`)
}

func TestFirewallNamelessTermRejectedHier12092(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"then-discard", "then discard;", "then"},
		{"then-reject", "then reject;", "then"},
		{"foo-bar", "foo bar;", "foo"},
		{"bare-foo", "foo;", "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(namelessTermHier12092(t, tc.body))
			if err == nil {
				t.Fatalf("nameless `term { %s }` committed cleanly, want strict reject", tc.body)
			}
			if !strings.Contains(err.Error(), "#10294") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want #10294 diagnostic naming %q", err, tc.want)
			}
		})
	}
}

// Flat-set terms with an unrecognized child must remain rejected as well.
// `term foo` on its own is a named empty term in this syntax, not the
// nameless hierarchical `term { foo; }` shape above.
func TestFirewallFlatUnknownTermTailsStillRejected12092(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{"then-discard", []string{"set firewall family inet filter f1 term then discard"}, "then"},
		{"then-reject", []string{"set firewall family inet filter f1 term then reject"}, "then"},
		{"foo-bar", []string{"set firewall family inet filter f1 term foo bar"}, "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(flatTreeFromSets(t, tc.sets...))
			if err == nil {
				t.Fatalf("flat term %q committed cleanly, want strict reject", tc.sets)
			}
			if !strings.Contains(err.Error(), "#10294") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want #10294 diagnostic naming %q", err, tc.want)
			}
		})
	}
}

func TestFirewallCompactTermTailStillRejected12092(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"then-discard", "then discard;", "discard"},
		{"then-reject", "then reject;", "reject"},
		{"foo-bar", "foo bar;", "bar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The compact spelling puts the term instance name and tail on
			// the same node (Keys=["term", name, tail...]); the hierarchical
			// nameless cases above exercise the sub-node shape
			// (Keys=[name, tail...]).
			tree := hierTree(t, `firewall {
    family inet {
        filter f1 {
            term `+tc.body+`
        }
    }
}`)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("compact term tail %q committed cleanly, want #10294 reject", tc.body)
			}
			if !strings.Contains(err.Error(), "#10294") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want #10294 diagnostic naming %q", err, tc.want)
			}
		})
	}
}

func TestFirewallNamedTermStillCommits12092(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, `firewall {
    family inet {
        filter f1 {
            term last {
                then {
                    discard;
                }
            }
        }
    }
}`)
		}},
		{"packed", func(t *testing.T) *ConfigTree {
			return hierTree(t, `firewall {
    family inet {
        filter f1 {
            term last then discard;
        }
    }
}`)
		}},
		{"flat", func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t,
				"set firewall family inet filter f1 term last then discard",
			)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree(t))
			if err != nil {
				t.Fatalf("named control was rejected: %v", err)
			}
			term := cfg.Firewall.FiltersInet["f1"].Terms[0]
			if term.Name != "last" || term.Action != "discard" {
				t.Fatalf("named control compiled to name=%q action=%q, want last/discard", term.Name, term.Action)
			}
			if len(term.unknownChildren) != 0 {
				t.Fatalf("named control recorded unknown children: %v", term.unknownChildren)
			}
		})
	}
}

func TestFirewallNamelessTermLenientWarns12092(t *testing.T) {
	tree := namelessTermHier12092(t, "then discard;")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "#10294") || !strings.Contains(warnings, "then") {
		t.Fatalf("warnings = %q, want #10294 naming then", warnings)
	}
}

// RED for #12092 (advisory half): the #3295 warning prints the nameless
// `term { then discard; }` remedy — the very spelling the gate must reject.
// The advisory must name the term, and the printed remedy (with a name
// substituted) must silence the advisory.
func TestNoCatchAllAdvisoryNamesTheTerm12092(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter protect-re term allow-ssh from destination-port 22",
		"set firewall family inet filter protect-re term allow-ssh then accept",
		"set interfaces ge-0-0-0 unit 0 family inet filter input protect-re",
	})
	got := hasNoCatchAllWarn(ValidateConfig(cfg), "protect-re")
	if got == "" {
		t.Fatalf("expected a no-catch-all warning for attached allowlist filter, got: %v", ValidateConfig(cfg))
	}
	if !strings.Contains(got, "term <name> { then discard; }") {
		t.Fatalf("advisory does not name the term: %q", got)
	}
}

func TestNoCatchAllPrintedRemedySilencesAdvisory12092(t *testing.T) {
	// The printed remedy, `term <name> { then discard; }`, with `last`
	// substituted and pasted as hierarchical config, must silence the warning.
	tree := hierTree(t, `system {
    dataplane-type userspace;
}
firewall {
    family inet {
        filter protect-re {
            term allow-ssh {
                from { destination-port 22; }
                then { accept; }
            }
            term last { then discard; }
        }
    }
}
interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                filter { input protect-re; }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical printed remedy was rejected: %v", err)
	}
	if got := hasNoCatchAllWarn(ValidateConfig(cfg), "protect-re"); got != "" {
		t.Fatalf("printed remedy did not silence the advisory: %q", got)
	}
}
