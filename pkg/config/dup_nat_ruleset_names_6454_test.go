package config

import (
	"strings"
	"testing"
)

// #6454 (C181-M18 sibling): two rule-SETS with the SAME name within one NAT
// type (source/destination/static/nat64) BOTH survive — compileNATSource /
// compileNATDestination / compileNATStatic / compileNAT64 each APPEND the
// rule-set (they never merge by name), so both compile as separate first-match
// tables sharing one name. The operator authored what they read as one
// rule-set; it compiles to two, evaluated in sequence, and the CLI
// named-rule-set show lookup (showNATSourceRuleSet, pkg/cli/cli_show_nat.go)
// returns on the FIRST name match — so the second same-named rule-set and its
// rules are invisible on that surface and the operator cannot disambiguate the
// two. This is NOT a per-rule counter merge: NATCounterKey includes the rule
// name, so the disjoint rules this gate uniquely catches get distinct counter
// keys (a SAME rule name in both is caught first by the #5649 rule-NAME gate).
// validateDuplicateNATRuleSetNamesAST rejects this at strict commit and warns on
// the tolerant load path (#1960).
//
// This is the rule-SET axis one level above the #5649 rule-NAME gate. The reject
// fixtures use DISJOINT rule names inside each duplicate rule-set so the #5649
// gate (which runs first, keyed by (natType, ruleSet, rule)) does NOT fire —
// control reaches THIS gate.
//
// Both the reject AND the accept tests drive the PUBLIC compile entry points
// (CompileConfig / CompileConfigLenient), not the private validator, so the
// false-positive guarantee (a #3096 bracket-list-scoped rule-set, a cross-type
// name reuse, a flat-set merge) is bound through the REAL commit path — a future
// change to the compile-path expansion that reintroduced a false-positive would
// turn an accept test RED.
//
// RED-on-revert: neutralize the gate so it never records a duplicate (guard the
// `seen[key]` detection with `&& false`, keeping the fmt/sort references and
// therefore the imports live — a clean assertion RED, not a build break). The
// strict sub-tests then no longer see a #6454 error and go RED; the accept
// sub-tests still compile cleanly (the gate never fired for them either way).

// parseHier6454 parses a hierarchical (brace-delimited) config via NewParser —
// the correct tool for a hierarchical duplicate block. Flat `set` MERGES a
// repeated rule-set onto one node (see the equivalence sub-test), so only the
// hierarchical shape can express the duplicate this gate targets.
func parseHier6454(t *testing.T, input string) *ConfigTree {
	t.Helper()
	input = injectHierNATZones15001(input)
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func setTree6454(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	cmds = prependNATZoneDefs15001(cmds)
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// countSourceRuleSets6454 returns how many compiled source NAT rule-sets carry
// the given name (a single authored rule-set may legitimately Cartesian-expand
// into several same-named entries via #3096 scope lists).
func countSourceRuleSets6454(cfg *Config, name string) int {
	n := 0
	for _, rs := range cfg.Security.NAT.Source {
		if rs.Name == name {
			n++
		}
	}
	return n
}

// TestDuplicateNATRuleSetNameRejected is the #6454 RED-on-revert proof: strict
// commit (CompileConfig, the stable public entrypoint) hard-rejects a duplicate
// rule-SET name in each of source / destination / static / nat64. The gate runs
// pre-expansion and returns before zone/policy validation, so a NAT-only fixture
// reaches exactly this error.
func TestDuplicateNATRuleSetNameRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{
			name: "source",
			cfg: `security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
            rule-set RS {
                from zone dmz;
                to zone untrust;
                rule R2 {
                    match { source-address 10.0.1.0/24; }
                    then { source-nat { off; } }
                }
            }
        }
    }
}`,
		},
		{
			name: "destination",
			cfg: `security {
    nat {
        destination {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat off; }
                }
            }
            rule-set RS {
                from zone untrust;
                rule R2 {
                    match { destination-address 203.0.113.11/32; }
                    then { destination-nat off; }
                }
            }
        }
    }
}`,
		},
		{
			name: "static",
			cfg: `security {
    nat {
        static {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { static-nat { prefix 10.0.0.10/32; } }
                }
            }
            rule-set RS {
                from zone untrust;
                rule R2 {
                    match { destination-address 203.0.113.11/32; }
                    then { static-nat { prefix 10.0.0.11/32; } }
                }
            }
        }
    }
}`,
		},
		{
			// nat64 rule-sets carry prefix / source-pool and NO `rule` nodes, so
			// the #5649 rule-name gate correctly excludes them — but a duplicate
			// nat64 rule-set NAME is its own fail-open this gate closes. Both
			// prefixes are valid /96 so the ONLY defect is the duplicate name.
			name: "nat64",
			cfg: `security {
    nat {
        nat64 {
            rule-set RS { prefix 64:ff9b::/96; }
            rule-set RS { prefix 64:ff9b::/96; }
        }
    }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier6454(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig must reject a duplicate NAT %s rule-set name", tc.name)
			}
			// Bind the exact natType phrase, not just the bare word, plus the
			// rule-set name and the issue tag.
			for _, want := range []string{"NAT " + tc.name + " rule-set", "RS", "6454"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestDuplicateNATRuleSetNameNat64NotCounter binds the type-agnostic-diagnostic
// contract for the counter-less nat64 case: a nat64 rule-set has no per-rule
// counter (NATCounterKey is only assigned for source/destination/static rules),
// so the #6454 diagnostic must NOT claim a per-rule counter for it. Mirrors the
// #5649 NPTv6 counter-less fold.
func TestDuplicateNATRuleSetNameNat64NotCounter(t *testing.T) {
	tree := parseHier6454(t, `security {
    nat {
        nat64 {
            rule-set RS { prefix 64:ff9b::/96; }
            rule-set RS { prefix 64:ff9b::/96; }
        }
    }
}`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig must reject a duplicate nat64 rule-set name")
	}
	msg := err.Error()
	for _, want := range []string{"NAT nat64 rule-set", "RS", "6454"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("nat64 duplicate error should mention %q, got: %v", want, err)
		}
	}
	// The type-agnostic diagnostic must not claim a per-rule counter (false for
	// a counter-less nat64 rule-set).
	if strings.Contains(msg, "counter") {
		t.Fatalf("nat64 duplicate diagnostic must NOT claim a per-rule counter, got: %v", err)
	}
}

// TestDuplicateNATRuleSetNameLenientWarns proves the tolerant path (Load /
// peer-sync) downgrades the reject to a warning so an already-persisted or
// peer-synced config still boots through (#1960 class). Both halves drive the
// public entry points: CompileConfig (strict → hard error) and
// CompileConfigLenient (tolerant → no hard error + the #6454 warning surfaced).
func TestDuplicateNATRuleSetNameLenientWarns(t *testing.T) {
	const cfg = `security {
    nat {
        source {
            rule-set RS {
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
            }
            rule-set RS {
                rule R2 {
                    match { source-address 10.0.1.0/24; }
                    then { source-nat { off; } }
                }
            }
        }
    }
}`

	// Strict public path: hard error naming the rule-set and #6454.
	if _, err := CompileConfig(parseHier6454(t, cfg)); err == nil {
		t.Fatal("strict CompileConfig must reject the duplicate rule-set name")
	}

	// Tolerant public path: no hard error, and the #6454 warning is surfaced on
	// cfg.Warnings (the runtime keeps the historical two-table behavior).
	lenientCfg, err := CompileConfigLenient(parseHier6454(t, cfg))
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on a duplicate rule-set name, got: %v", err)
	}
	found := false
	for _, w := range lenientCfg.Warnings {
		if strings.Contains(w, "rule-set") && strings.Contains(w, "RS") && strings.Contains(w, "6454") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn naming the duplicate rule-set + #6454, warnings: %v", lenientCfg.Warnings)
	}
}

// TestDuplicateNATRuleSetNameNoFalsePositive guards the gate's scope through the
// PUBLIC compile path (CompileConfig, strict): distinct rule-set names, the SAME
// rule-set name in two DIFFERENT nat types (a distinct natType namespace — the
// counter key is prefixed by natType), a single rule-set carrying a bracket list
// of from-scopes that Cartesian-expands into multiple same-named NATRuleSet
// objects downstream (#3096, one AST instance — NOT a duplicate), and the
// flat-set form (which MERGES a repeated rule-set onto one node) must all commit
// cleanly with the expected rule-sets present.
func TestDuplicateNATRuleSetNameNoFalsePositive(t *testing.T) {
	t.Run("distinct rule-set names in one nat type", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier6454(t, `security {
    nat {
        source {
            rule-set RS_A { rule R1 { then { source-nat { interface; } } } }
            rule-set RS_B { rule R1 { then { source-nat { off; } } } }
        }
    }
}`))
		if err != nil {
			t.Fatalf("distinct rule-set names must commit, got: %v", err)
		}
		if got := countSourceRuleSets6454(cfg, "RS_A"); got != 1 {
			t.Fatalf("want 1 source rule-set RS_A, got %d", got)
		}
		if got := countSourceRuleSets6454(cfg, "RS_B"); got != 1 {
			t.Fatalf("want 1 source rule-set RS_B, got %d", got)
		}
	})

	t.Run("same rule-set name in two different nat types", func(t *testing.T) {
		// source RS and static RS are distinct namespaces (the counter key is
		// natType-prefixed), so both must commit — one entry in each slice.
		cfg, err := CompileConfig(parseHier6454(t, `security {
    nat {
        source {
            rule-set RS { rule R1 { then { source-nat { interface; } } } }
        }
        static {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 203.0.113.10/32; }
                    then { static-nat { prefix 10.0.0.10/32; } }
                }
            }
        }
    }
}`))
		if err != nil {
			t.Fatalf("same rule-set name across different nat types must commit, got: %v", err)
		}
		if got := countSourceRuleSets6454(cfg, "RS"); got != 1 {
			t.Fatalf("want 1 source rule-set RS, got %d", got)
		}
		staticRS := 0
		for _, rs := range cfg.Security.NAT.Static {
			if rs.Name == "RS" {
				staticRS++
			}
		}
		if staticRS != 1 {
			t.Fatalf("want 1 static rule-set RS, got %d", staticRS)
		}
	})

	t.Run("bracket-list from-scope expands one authored rule-set (#3096)", func(t *testing.T) {
		// ONE authored `rule-set RS` with a bracket list of from-zones
		// Cartesian-expands into TWO same-named NATRuleSet objects in
		// compileNATSource — but that is one AST rule-set instance, not a
		// duplicate. Dedup at the compiled level would false-positive here; the
		// gate dedups at the AST instance level, so this commits, and the two
		// expanded entries (from trust + from dmz) are BOTH present.
		cfg, err := CompileConfig(parseHier6454(t, `security {
    nat {
        source {
            rule-set RS {
                from zone [ trust dmz ];
                to zone untrust;
                rule R1 { then { source-nat { interface; } } }
            }
        }
    }
}`))
		if err != nil {
			t.Fatalf("a single bracket-list-scoped rule-set must commit (one AST instance), got: %v", err)
		}
		if got := countSourceRuleSets6454(cfg, "RS"); got != 2 {
			t.Fatalf("want 2 same-named source rule-sets from the #3096 from-zone expansion, got %d", got)
		}
		fromZones := map[string]bool{}
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "RS" {
				fromZones[rs.FromZone] = true
			}
		}
		if !fromZones["trust"] || !fromZones["dmz"] {
			t.Fatalf("expanded rule-sets must cover from-zones {trust, dmz}, got: %v", fromZones)
		}
	})

	t.Run("flat-set repeated rule-set merges (dual-AST equivalence)", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6454(t, []string{
			"set security nat source rule-set RS from zone trust",
			"set security nat source rule-set RS rule R1 then source-nat interface",
			"set security nat source rule-set RS rule R2 then source-nat off",
		}))
		if err != nil {
			t.Fatalf("flat-set repeated rule-set statements merge onto one node and must commit, got: %v", err)
		}
		if got := countSourceRuleSets6454(cfg, "RS"); got != 1 {
			t.Fatalf("flat-set merge must yield exactly 1 source rule-set RS, got %d", got)
		}
		// The merged rule-set carries BOTH rules (R1, R2) — proof it is one
		// rule-set, not two.
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name != "RS" {
				continue
			}
			if len(rs.Rules) != 2 {
				t.Fatalf("merged rule-set RS must carry 2 rules, got %d", len(rs.Rules))
			}
		}
	})
}
