package config

import (
	"strings"
	"testing"
)

// #5649 (C181-M18): two rules with the SAME name in one NAT rule-set both
// compile as separate first-match entries sharing one operational identity (the
// rule name). A NAT rule-set is keyed by rule name, so the duplicate is a config
// error regardless of NAT type — counted rows on the shared natType/ruleset/rule
// hit counter for source/destination/ordinary-static, two snapshots for a
// counter-less NPTv6 static rule. validateDuplicateNATRuleNamesAST rejects this
// at strict commit and warns on the tolerant load path.
//
// RED-on-revert: neutralize the gate by making validateDuplicateNATRuleNamesAST
// return `nil, nil` at the top (a clean assertion RED, not a build break) — the
// strict sub-tests then no longer see a #5649 error and go RED.

// Hierarchical trees are built via parseHierText (#16139 kit, NewParser) —
// the correct tool for hierarchical duplicate blocks. Flat `set` MERGES a
// repeated rule onto one node (see the equivalence sub-test), so only the
// hierarchical shape can express the duplicate this gate targets.

func setTree5649(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
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

// TestDuplicateNATRuleNameRejected is the #5649 RED-on-revert proof: strict
// commit (CompileConfig, the stable public entrypoint) hard-rejects a duplicate
// rule name in each of the source / destination / static NAT rule-sets. The
// gate runs pre-expansion and returns before zone/policy validation, so a
// NAT-only fixture reaches exactly this error.
func TestDuplicateNATRuleNameRejected(t *testing.T) {
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
                rule R1 {
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
                rule R1 {
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
                rule R1 {
                    match { destination-address 203.0.113.11/32; }
                    then { static-nat { prefix 10.0.0.11/32; } }
                }
            }
        }
    }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.cfg)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig must reject a duplicate NAT %s rule name", tc.name)
			}
			// Bind the exact natType phrase, not just the bare word, plus the
			// rule / rule-set names and the issue tag.
			for _, want := range []string{"NAT " + tc.name + " rule", "R1", "RS", "5649"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestDuplicateNATRuleNameNPTv6Counterless binds the #6452 review fold. NPTv6
// (RFC 6296) static rules are COUNTER-LESS: compileStaticNAT skips rule.IsNPTv6
// before assignNATCounterID, and buildNptv6Snapshots appends each as its own
// snapshot. The #2241 NPTv6 overlap gate deliberately SKIPS same-(rule-set,
// rule) pairs (#4339, so a multi-from-scope rule is not flagged against
// itself), so it never compares two same-named NPTv6 rules — this gate is the
// only one that catches them. A duplicate NPTv6 rule name is therefore still
// rejected (a duplicate name is always invalid), but the type-agnostic
// diagnostic must NOT claim a per-rule counter the NPTv6 rule does not have.
//
// RED-on-revert of a counter-specific message (e.g. reintroducing "share the
// one natType/ruleset/rule counter identity"): the "must NOT mention counter"
// assertion goes RED. RED-on-revert of the gate itself (return nil, nil):
// CompileConfig no longer rejects and the first assertion goes RED.
func TestDuplicateNATRuleNameNPTv6Counterless(t *testing.T) {
	// Two same-named NPTv6 rules with DIFFERENT, non-overlapping prefixes — the
	// overlap gate would not flag them even if it compared them, so this gate is
	// the sole catcher.
	tree := parseHierText(t, `security {
    nat {
        static {
            rule-set RS {
                from zone untrust;
                rule R1 {
                    match { destination-address 2001:db8:1::/48; }
                    then { static-nat { nptv6-prefix { 2001:db8:2::/48; } } }
                }
                rule R1 {
                    match { destination-address 2001:db8:3::/48; }
                    then { static-nat { nptv6-prefix { 2001:db8:4::/48; } } }
                }
            }
        }
    }
}`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig must still reject a duplicate NPTv6 static rule name")
	}
	msg := err.Error()
	for _, want := range []string{"NAT static rule", "R1", "RS", "5649"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("NPTv6 duplicate error should mention %q, got: %v", want, err)
		}
	}
	// The rule is counter-less; the type-agnostic diagnostic must not claim any
	// per-rule counter.
	if strings.Contains(msg, "counter") {
		t.Fatalf("NPTv6 duplicate diagnostic must NOT claim a per-rule counter, got: %v", err)
	}
}

// TestDuplicateNATRuleNameLenientWarns proves the tolerant path (Load /
// peer-sync) downgrades the reject to a warning so an already-persisted or
// peer-synced config still boots through (#1960 class).
func TestDuplicateNATRuleNameLenientWarns(t *testing.T) {
	tree := parseHierText(t, `security {
    nat {
        source {
            rule-set RS {
                rule R1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { interface; } }
                }
                rule R1 {
                    match { source-address 10.0.1.0/24; }
                    then { source-nat { off; } }
                }
            }
        }
    }
}`)

	// Strict: hard error.
	if _, err := validateDuplicateNATRuleNamesAST(tree, false); err == nil {
		t.Fatal("strict validator must reject the duplicate rule name")
	}

	// Lenient: no error, one warning that names the rule and references #5649.
	warnings, err := validateDuplicateNATRuleNamesAST(tree, true)
	if err != nil {
		t.Fatalf("lenient validator must not error, got: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("lenient validator must emit exactly one warning, got %d: %v", len(warnings), warnings)
	}
	for _, want := range []string{"R1", "RS", "5649"} {
		if !strings.Contains(warnings[0], want) {
			t.Fatalf("warning should mention %q, got: %v", want, warnings[0])
		}
	}
}

// TestDuplicateNATRuleNameNoFalsePositive guards the gate's scope: distinct
// rule names, the same rule name in two DIFFERENT rule-sets (a different
// natType/ruleset/rule identity), and the flat-set form (which MERGES a
// repeated rule onto one node) must all pass strict.
func TestDuplicateNATRuleNameNoFalsePositive(t *testing.T) {
	t.Run("distinct rule names in one rule-set", func(t *testing.T) {
		tree := parseHierText(t, `security {
    nat {
        source {
            rule-set RS {
                rule R1 { then { source-nat { interface; } } }
                rule R2 { then { source-nat { off; } } }
            }
        }
    }
}`)
		if _, err := validateDuplicateNATRuleNamesAST(tree, false); err != nil {
			t.Fatalf("distinct rule names must pass, got: %v", err)
		}
	})

	t.Run("same rule name in two different rule-sets", func(t *testing.T) {
		tree := parseHierText(t, `security {
    nat {
        source {
            rule-set RS_A {
                rule R1 { then { source-nat { interface; } } }
            }
            rule-set RS_B {
                rule R1 { then { source-nat { off; } } }
            }
        }
    }
}`)
		if _, err := validateDuplicateNATRuleNamesAST(tree, false); err != nil {
			t.Fatalf("same rule name in different rule-sets is a distinct identity and must pass, got: %v", err)
		}
	})

	t.Run("flat-set repeated rule merges (dual-AST equivalence)", func(t *testing.T) {
		tree := setTree5649(t, []string{
			"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
			"set security nat source rule-set RS rule R1 then source-nat interface",
		})
		if _, err := validateDuplicateNATRuleNamesAST(tree, false); err != nil {
			t.Fatalf("flat-set repeated rule statements merge onto one node and must pass, got: %v", err)
		}
	})
}
