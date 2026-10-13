package config

import (
	"strings"
	"testing"
)

// #12640: duplicate `to-zone {}` blocks under one from-zone source-zone
// block are separate AST siblings (the parser appends, it does not merge).
// compilePolicies used FindChild("to-zone") and so compiled only the FIRST
// pair; the second `to-zone { C { policy ... then deny } }` block was
// silently dropped. Junos merges the blocks, so both pairs must compile.

const dupToZoneText12640 = `
security {
    zones { security-zone A; security-zone B; security-zone C; }
    policies {
        from-zone {
            A {
                to-zone {
                    B {
                        policy p-ab {
                            match {
                                source-address any;
                                destination-address any;
                                application any;
                            }
                            then {
                                permit;
                            }
                        }
                    }
                }
                to-zone {
                    C {
                        policy p-ac {
                            match {
                                source-address any;
                                destination-address any;
                                application any;
                            }
                            then {
                                deny;
                            }
                        }
                    }
                }
            }
        }
    }
}
`

func compileDupToZone12640(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(dupToZoneText12640).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse duplicate to-zone tree: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile duplicate to-zone tree: %v", err)
	}
	return cfg
}

// MUTANT-KILLER: reverting FindChildren back to FindChild("to-zone") in
// compilePolicies drops the A->C pair and this test fails.
func TestDuplicateToZoneBlocksBothCompile12640(t *testing.T) {
	cfg := compileDupToZone12640(t)
	if len(cfg.Security.Policies) != 2 {
		t.Fatalf("compiled %d zone pairs, want 2 (A->B and A->C): %+v", len(cfg.Security.Policies), cfg.Security.Policies)
	}
	// Order must follow declaration order.
	first, second := cfg.Security.Policies[0], cfg.Security.Policies[1]
	if first.FromZone != "A" || first.ToZone != "B" {
		t.Fatalf("first pair = %s->%s, want A->B", first.FromZone, first.ToZone)
	}
	if second.FromZone != "A" || second.ToZone != "C" {
		t.Fatalf("second pair = %s->%s, want A->C", second.FromZone, second.ToZone)
	}
	if len(second.Policies) != 1 || second.Policies[0].Name != "p-ac" {
		t.Fatalf("A->C policies = %+v, want [p-ac]", second.Policies)
	}
	if second.Policies[0].Action != PolicyDeny {
		t.Fatalf("A->C p-ac action = %v, want deny (the dropped restrictive pair)", second.Policies[0].Action)
	}
}

// Control: with the blocks swapped the deny pair is first — the compiled set
// must be invariant to declaration order (a FindChild fix would flip which
// pair is dropped).
func TestDuplicateToZoneBlocksCompileOrderInvariant12640(t *testing.T) {
	const swapped = `
security {
    zones { security-zone A; security-zone B; security-zone C; }
    policies {
        from-zone {
            A {
                to-zone {
                    C {
                        policy p-ac {
                            match {
                                source-address any;
                                destination-address any;
                                application any;
                            }
                            then {
                                deny;
                            }
                        }
                    }
                }
                to-zone {
                    B {
                        policy p-ab {
                            match {
                                source-address any;
                                destination-address any;
                                application any;
                            }
                            then {
                                permit;
                            }
                        }
                    }
                }
            }
        }
    }
}
`
	tree, errs := NewParser(swapped).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse swapped duplicate to-zone tree: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile swapped duplicate to-zone tree: %v", err)
	}
	if len(cfg.Security.Policies) != 2 {
		t.Fatalf("compiled %d zone pairs, want 2", len(cfg.Security.Policies))
	}
	seen := map[string]PolicyAction{}
	for _, zp := range cfg.Security.Policies {
		if len(zp.Policies) != 1 {
			t.Fatalf("pair %s->%s has %d policies", zp.FromZone, zp.ToZone, len(zp.Policies))
		}
		seen[zp.FromZone+"->"+zp.ToZone] = zp.Policies[0].Action
	}
	if seen["A->B"] != PolicyPermit || seen["A->C"] != PolicyDeny {
		t.Fatalf("actions = %v, want A->B=permit A->C=deny", seen)
	}
}

// A compiled second pair must also pass through strict policy gates. Otherwise
// compilePolicies would now retain its policy while malformed enforcement
// content in that block could bypass the matching validator.
func TestDuplicateToZoneSecondPairRunsStrictPolicyGates12640(t *testing.T) {
	const unsupportedPermit = "permit { application-services idp; }"
	text := strings.Replace(dupToZoneText12640, "deny;", unsupportedPermit, 1)
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse second-pair unsupported policy: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted unsupported then-permit content in the second to-zone pair")
	}
	if !strings.Contains(err.Error(), `from-zone A to-zone C policy "p-ac" then permit "application-services"`) ||
		!strings.Contains(err.Error(), "#3114") {
		t.Fatalf("strict error = %q, want second-pair #3114 rejection", err)
	}
}
