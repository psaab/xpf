package config

import (
	"strings"
	"testing"
)

func parse16607(t *testing.T, src string) *ConfigTree {
	t.Helper()
	return parseHierText(t, injectHierNATZones15001(src))
}

// #16607: two differently-named source-NAT rule-sets with the same normalised
// the userspace snapshot stable-sorts by scope tier (equal), so the later
// rule-set's rules — including a `source-nat off` exemption — are unreachable
// behind the earlier catch-all. Junos refuses: "You cannot specify the same
// source and destination conditions for source NAT rule sets."
// validateSourceNATDuplicateContextAST rejects strict, warns lenient (#1960).
//
// RED-on-revert: neutralize the gate (skip recording, e.g. guard the `seen[key]`
// lookup with `&& false`); the strict cases then compile clean and go RED.

const snatCtx16607 = `security {
    nat {
        source {
            rule-set EXEMPT {
                from zone trust;
                to zone untrust;
                rule NO-NAT {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { off; } }
                }
            }
            rule-set CATCHALL {
                from zone trust;
                to zone untrust;
                rule NAT-ALL {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}`

// TestSourceNATDuplicateContextRejected16607 is the acceptance probe: the
// later exemption rule-set is shadowed behind the earlier catch-all.
func TestSourceNATDuplicateContextRejected16607(t *testing.T) {
	// Order in fixture: EXEMPT first, CATCHALL second — either order the
	// duplicate context must reject, naming BOTH rule-sets.
	_, err := CompileConfig(parse16607(t, snatCtx16607))
	if err == nil {
		t.Fatal("strict CompileConfig must reject two source rule-sets with identical from/to context")
	}
	for _, want := range []string{"EXEMPT", "CATCHALL", "16607", "source-nat off"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestSourceNATDuplicateContextBracketSetEqual16607: bracket order and
// repeated-clause spelling normalise to the same scope set.
func TestSourceNATDuplicateContextBracketSetEqual16607(t *testing.T) {
	cfgText := `security {
    nat {
        source {
            rule-set A {
                from zone [ trust dmz ];
                to zone untrust;
                rule R1 { then { source-nat { interface; } } }
            }
            rule-set B {
                from zone dmz;
                from zone trust;
                to zone untrust;
                rule R2 { then { source-nat { off; } } }
            }
        }
    }
}`
	_, err := CompileConfig(parse16607(t, cfgText))
	if err == nil {
		t.Fatal("bracket-list and repeated clauses with same scope set must reject")
	}
	if !strings.Contains(err.Error(), "\"A\"") || !strings.Contains(err.Error(), "\"B\"") {
		t.Fatalf("error must name both rule-sets, got: %v", err)
	}
}

// TestSourceNATDuplicateContextUnscopedEqual16607: absent from/to (match-any)
// on both rule-sets is the same context.
func TestSourceNATDuplicateContextUnscopedEqual16607(t *testing.T) {
	cfgText := `security {
    nat {
        source {
            rule-set A { rule R1 { then { source-nat { interface; } } } }
            rule-set B { rule R2 { then { source-nat { off; } } } }
        }
    }
}`
	if _, err := CompileConfig(parse16607(t, cfgText)); err == nil {
		t.Fatal("two unscoped source rule-sets must reject as duplicate context")
	}
}

// TestSourceNATDuplicateContextDistinctAccepted16607: distinct contexts and
// single rule-sets still commit. The interfaces-prefixed fixture puts a
// top-level interfaces block before security; injectHierNATZones still
// finds the security block. Same-name pairs are #6454 (not this gate),
func TestSourceNATDuplicateContextDistinctAccepted16607(t *testing.T) {
	cases := []struct{ name, cfg string }{
		{
			name: "distinct from zone",
			cfg: `security { nat { source {
                rule-set A { from zone trust; to zone untrust; rule R1 { then { source-nat { interface; } } } }
                rule-set B { from zone dmz; to zone untrust; rule R2 { then { source-nat { off; } } } }
            } } }`,
		},
		{
			name: "distinct to zone",
			cfg: `security { nat { source {
                rule-set A { from zone trust; to zone untrust; rule R1 { then { source-nat { interface; } } } }
                rule-set B { from zone trust; to zone dmz; rule R2 { then { source-nat { off; } } } }
            } } }`,
		},
		{
			name: "distinct scope kind",
			cfg: `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { nat { source {
                rule-set A { from zone trust; to zone untrust; rule R1 { then { source-nat { interface; } } } }
                rule-set B { from interface ge-0/0/0.0; to zone untrust; rule R2 { then { source-nat { off; } } } }
            } } }`,
		},
		{
			name: "single bracket-list rule-set (#3096)",
			cfg: `security { nat { source {
                rule-set A { from zone [ trust dmz ]; to zone untrust; rule R1 { then { source-nat { interface; } } } }
            } } }`,
		},
		{
			name: "overlapping but not equal scope sets",
			cfg: `security { nat { source {
                rule-set A { from zone [ trust dmz ]; to zone untrust; rule R1 { then { source-nat { interface; } } } }
                rule-set B { from zone trust; to zone untrust; rule R2 { then { source-nat { off; } } } }
            } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(parse16607(t, tc.cfg)); err != nil {
				t.Fatalf("distinct contexts must commit, got: %v", err)
			}
		})
	}
}

// TestSourceNATDuplicateContextLenientWarns16607: tolerant path warns, boots.
func TestSourceNATDuplicateContextLenientWarns16607(t *testing.T) {
	cfg, err := CompileConfigLenient(parse16607(t, snatCtx16607))
	if err != nil {
		t.Fatalf("lenient must not hard-fail, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "16607") && strings.Contains(w, "EXEMPT") && strings.Contains(w, "CATCHALL") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming both rule-sets + #16607, warnings: %v", cfg.Warnings)
	}
	// Both rule-sets survive on lenient path (historical concatenation).
	if len(cfg.Security.NAT.Source) != 2 {
		t.Fatalf("lenient must keep both rule-sets, got %d", len(cfg.Security.NAT.Source))
	}
}

// TestSourceNATDuplicateContextGroupAuthored16607: duplicate context authored
// entirely inside an applied group is caught via the expanded scanner.
func TestSourceNATDuplicateContextGroupAuthored16607(t *testing.T) {
	cfgText := `groups { G { security { nat { source {
        rule-set GA { from zone trust; to zone untrust; rule R1 { then { source-nat { interface; } } } }
        rule-set GB { from zone trust; to zone untrust; rule R2 { then { source-nat { off; } } } }
    } } } } }
apply-groups G;`
	_, err := CompileConfig(parse16607(t, cfgText))
	if err == nil {
		t.Fatal("group-authored duplicate source context must reject")
	}
	if !strings.Contains(err.Error(), "16607") {
		t.Fatalf("group-authored error must carry #16607, got: %v", err)
	}
}
