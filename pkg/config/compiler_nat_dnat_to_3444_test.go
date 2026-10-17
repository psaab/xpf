package config

import (
	"strings"
	"testing"
)

// Tests for #3444: a destination-NAT rule-set `to` scope. Junos DNAT
// rule-sets have only a `from` clause — the destination is translated on
// inbound, so there is no egress context. xpf briefly advertised a `to`
// scope under `security nat destination rule-set` and Cartesian-expanded it
// onto each NATRuleSet, but the userspace snapshot builder and the Rust DNAT
// runtime model ONLY the `from` clause, so the `to` scope was silently
// dropped and the translation applied regardless of it. The #3444 fix
// rejects a DNAT `to` scope at strict commit (validateDNATRuleSetToScopeAST)
// and warns on the tolerant load / peer-sync path (#1960); #14391 closes the
// lenient residual: the warned rule-set is OMITTED from the tolerant load
// (never installed scope-less), in both the nested-child spelling and the
// packed rule-set-header spelling (R15-01).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildDNATToTree(t *testing.T, scope string) *ConfigTree {
	t.Helper()
	return buildNATScopeTree(t,
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD "+scope,
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
}

// TestDNATRuleSetToScopeRejectedAtCommit proves the strict commit path hard-
// rejects a DNAT rule-set `to` scope for every scope kind (zone | interface |
// routing-instance). Reverting the gate (validateDNATRuleSetToScopeAST) makes
// CompileConfig accept the config and these assertions go RED.
func TestDNATRuleSetToScopeRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name  string
		scope string
	}{
		{"to zone", "to zone trust"},
		{"to interface", "to interface ge-0/0/1.0"},
		{"to routing-instance", "to routing-instance red"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildDNATToTree(t, tc.scope)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a DNAT rule-set %q scope; want a strict reject", tc.scope)
			}
			// The error must name the offending rule-set so the operator can
			// find it, and cite the issue tag.
			if !strings.Contains(err.Error(), "RD") || !strings.Contains(err.Error(), "#3444") {
				t.Fatalf("reject error %q does not name the rule-set (RD) and #3444", err.Error())
			}
			if !strings.Contains(err.Error(), "destination") || !strings.Contains(err.Error(), "to") {
				t.Fatalf("reject error %q does not identify a destination-NAT `to` scope", err.Error())
			}
		})
	}
}

// TestDNATRuleSetToScopeLenientWarns proves the tolerant load / peer-sync path
// (CompileConfigLenient) does NOT hard-fail on a DNAT `to` scope (so an
// already-persisted config still boots, #1960), emits the #3444 warning, and
// OMITS the offending rule-set entirely (#14391): installing it scope-less
// would apply the translation regardless of the authored egress context.
// This is the lenientNATEmptyScope posture — a rule-set whose scope cannot
// be enforced is omitted (zero emissions), never widened. A sibling DNAT
// rule-set without a `to` scope in the same config still compiles.
func TestDNATRuleSetToScopeLenientWarns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
	}{
		{"to zone", "to zone trust"},
		{"to interface", "to interface ge-0/0/1.0"},
		{"to routing-instance", "to routing-instance red"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildDNATToTree(t, tc.scope)
			// Sibling control: a from-only DNAT rule-set must survive.
			for _, cmd := range []string{
				"set security nat destination rule-set OK from zone untrust",
				"set security nat destination rule-set OK rule R9 match destination-address 198.51.100.9/32",
				"set security nat destination rule-set OK rule R9 then destination-nat pool P1",
			} {
				if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-failed on a DNAT `to` scope: %v", err)
			}
			var warnCount int
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#3444") && strings.Contains(w, `"RD"`) {
					warnCount++
				}
			}
			if warnCount != 1 {
				t.Fatalf("CompileConfigLenient emitted %d #3444 warnings for RD, want exactly 1; warnings=%v", warnCount, cfg.Warnings)
			}
			if cfg.Security.NAT.Destination == nil {
				t.Fatalf("destination NAT did not compile under lenient load")
			}
			for _, rs := range cfg.Security.NAT.Destination.RuleSets {
				if rs.Name == "RD" {
					t.Fatalf("lenient load installed DNAT rule-set RD with its %q scope silently dropped (#14391): %+v", tc.scope, rs)
				}
			}
			var ok *NATRuleSet
			for _, rs := range cfg.Security.NAT.Destination.RuleSets {
				if rs.Name == "OK" {
					ok = rs
				}
			}
			if ok == nil {
				t.Fatalf("sibling from-only DNAT rule-set OK was dropped with the offending RD; rule-sets=%v", cfg.Security.NAT.Destination.RuleSets)
			}
			if ok.FromZone != "untrust" {
				t.Fatalf("sibling OK FromZone = %q, want untrust", ok.FromZone)
			}
		})
	}
}

// buildDNATPackedToTree builds the PACKED hierarchical spelling: the `to`
// scope rides on the rule-set header line itself
// (`rule-set RD to zone trust { ... }`), so the rule-set node carries Keys
// [rule-set RD to zone trust] and has NO `to` child. It is the R15-01
// spelling of the same #14391 root cause: a gate/builder that reads only
// FindChild("to") never sees it.
func buildDNATPackedToTree(t *testing.T) *ConfigTree {
	t.Helper()
	cfgText := `
security {
    nat {
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD to zone trust {
                from zone untrust;
                rule R1 {
                    match {
                        destination-address 198.51.100.5/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
            rule-set OK {
                from zone untrust;
                rule R9 {
                    match {
                        destination-address 198.51.100.9/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	// Premise: the packed header must put `to` on the rule-set node's own
	// Keys with no `to` child, and the sibling OK rule-set must be present.
	var rd, ok *Node
	for _, sec := range tree.Children {
		for _, nat := range sec.FindChildren("nat") {
			for _, dst := range nat.FindChildren("destination") {
				for _, inst := range namedInstances(dst.FindChildren("rule-set")) {
					switch inst.name {
					case "RD":
						rd = inst.node
					case "OK":
						ok = inst.node
					}
				}
			}
		}
	}
	if rd == nil || ok == nil {
		t.Fatalf("packed premise: RD=%v OK=%v, want both rule-sets parsed", rd != nil, ok != nil)
	}
	if rd.FindChild("to") != nil {
		t.Fatalf("packed premise: RD unexpectedly has a `to` child (Keys=%v); not the packed shape", rd.Keys)
	}
	return tree
}

// TestDNATRuleSetPackedToScopeRejectedAtCommit proves strict commit rejects
// the packed-header `to` spelling with the #3444 error naming the rule-set
// (previously the FindChild-only gate missed it entirely).
func TestDNATRuleSetPackedToScopeRejectedAtCommit(t *testing.T) {
	tree := buildDNATPackedToTree(t)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a packed DNAT rule-set `to` scope; want a strict #3444 reject")
	}
	if !strings.Contains(err.Error(), "RD") || !strings.Contains(err.Error(), "#3444") {
		t.Fatalf("reject error %q does not name the rule-set (RD) and #3444", err.Error())
	}
}

// TestDNATRuleSetPackedToScopeLenientOmits proves the lenient path warns
// (#3444, naming RD) and omits the packed-`to` rule-set while the sibling
// from-only rule-set still compiles.
func TestDNATRuleSetPackedToScopeLenientOmits(t *testing.T) {
	tree := buildDNATPackedToTree(t)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-failed on a packed DNAT `to` scope: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3444") && strings.Contains(w, `"RD"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CompileConfigLenient emitted no #3444 warning for packed RD; warnings=%v", cfg.Warnings)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatalf("destination NAT did not compile under lenient load")
	}
	var okSeen bool
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		if rs.Name == "RD" {
			t.Fatalf("lenient load installed packed-`to` DNAT rule-set RD scope-less (#14391): %+v", rs)
		}
		if rs.Name == "OK" {
			okSeen = true
		}
	}
	if !okSeen {
		t.Fatalf("sibling from-only DNAT rule-set OK was dropped with packed RD; rule-sets=%v", cfg.Security.NAT.Destination.RuleSets)
	}
}

// TestDNATRuleSetToScopeRejectedAcrossDuplicateSecurityBlocks proves the gate
// inspects EVERY top-level `security` node, not just the first match. The
// hierarchical parser (parseStatements) APPENDS a repeated top-level block
// instead of merging it, and the compiler processes every `security` root, so
// a config with two `security {}` blocks where only the SECOND carries the
// DNAT `to` would bypass a first-match-only walk and silently drop+compile the
// `to` (the original #3444 bug). This is reachable via LoadOverride, which
// parses hierarchical input directly through NewParser
// (configstore/store_command.go). NewParser is the CORRECT builder here — this
// tests the hierarchical / LoadOverride path, not flat-set. Reverting the gate
// to first-`security`-only makes strict CompileConfig compile this clean,
// turning the assertion RED.
func TestDNATRuleSetToScopeRejectedAcrossDuplicateSecurityBlocks(t *testing.T) {
	cfgText := `
security {
    zones {
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
security {
    nat {
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD {
                from zone untrust;
                to zone trust;
                rule R1 {
                    match {
                        destination-address 198.51.100.5/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	// Sanity: the parser must have produced TWO top-level `security` nodes
	// (the bypass premise). If a future parser merges them, the bypass is
	// gone and this guard documents why.
	var secCount int
	for _, n := range tree.Children {
		if n.Name() == "security" {
			secCount++
		}
	}
	if secCount < 2 {
		t.Fatalf("expected 2 top-level security blocks (the bypass premise), got %d", secCount)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a DNAT `to` scope in the SECOND of two security blocks; want a strict reject (#3444 bypass)")
	}
	if !strings.Contains(err.Error(), "RD") || !strings.Contains(err.Error(), "#3444") {
		t.Fatalf("reject error %q does not name the rule-set (RD) and #3444", err.Error())
	}
}

// TestDNATRuleSetToScopeRejectedAcrossDuplicateNATBlocks proves the gate
// iterates EVERY `nat` sibling under a security root, not just the first.
// compileSecurity compiles every `nat` child (compiler_security.go), and the
// parser APPENDS a repeated `nat {}` block as a sibling (parseStatements), so
// ONE security root with a benign first `nat {}` plus a second `nat {
// destination { rule-set RD ... to zone trust } }` would bypass a first-`nat`
// walk while the compiler still compiled the second nat's rule-set with the
// `to` silently dropped (the #3444 bypass, one level deeper). Reverting the
// nat-level forEachChild back to FindChild-first makes strict CompileConfig
// compile this clean → RED.
func TestDNATRuleSetToScopeRejectedAcrossDuplicateNATBlocks(t *testing.T) {
	cfgText := `
security {
    nat {
        source {
            rule-set RS {
                from zone trust;
                rule R0 {
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
    nat {
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD {
                from zone untrust;
                to zone trust;
                rule R1 {
                    match {
                        destination-address 198.51.100.5/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	// Sanity: the single security root must carry TWO `nat` siblings (the
	// bypass premise).
	var natCount int
	for _, n := range tree.Children {
		if n.Name() == "security" {
			for _, c := range n.Children {
				if c.Name() == "nat" {
					natCount++
				}
			}
		}
	}
	if natCount < 2 {
		t.Fatalf("expected 2 `nat` siblings under one security root (the bypass premise), got %d", natCount)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a DNAT `to` scope in the SECOND of two nat blocks; want a strict reject (#3444 bypass)")
	}
	if !strings.Contains(err.Error(), "RD") || !strings.Contains(err.Error(), "#3444") {
		t.Fatalf("reject error %q does not name the rule-set (RD) and #3444", err.Error())
	}
}

// TestDNATRuleSetToScopeRejectedAcrossDuplicateDestinationBlocks proves the
// gate also iterates every `destination` sibling within a `nat` block.
// compileNAT itself reads only the FIRST `destination`, so a duplicate
// `destination` within one `nat` is not currently compiler-reachable for the
// silent drop — but the walk rejects it anyway (fail-closed: an operator who
// authored a DNAT `to` is told it is unsupported, and the gate is defensive
// against a future compiler that iterates destinations). Reverting the
// destination-level forEachChild to FindChild-first makes strict CompileConfig
// compile this clean → RED.
func TestDNATRuleSetToScopeRejectedAcrossDuplicateDestinationBlocks(t *testing.T) {
	cfgText := `
security {
    nat {
        destination {
            pool P0 {
                address 10.0.30.99;
            }
            rule-set RBENIGN {
                from zone untrust;
                rule R0 {
                    match {
                        destination-address 198.51.100.1/32;
                    }
                    then {
                        destination-nat pool P0;
                    }
                }
            }
        }
        destination {
            pool P1 {
                address 10.0.30.100;
            }
            rule-set RD {
                from zone untrust;
                to zone trust;
                rule R1 {
                    match {
                        destination-address 198.51.100.5/32;
                    }
                    then {
                        destination-nat pool P1;
                    }
                }
            }
        }
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a DNAT `to` scope in the SECOND of two destination blocks; want a strict reject (#3444 bypass)")
	}
	if !strings.Contains(err.Error(), "RD") || !strings.Contains(err.Error(), "#3444") {
		t.Fatalf("reject error %q does not name the rule-set (RD) and #3444", err.Error())
	}
}

// TestDNATRuleSetFromOnlyStillCommits proves the no-regression case: a DNAT
// rule-set with only a `from` clause (the legitimate Junos shape) commits
// cleanly with no #3444 warning and the `from` scope survives.
func TestDNATRuleSetFromOnlyStillCommits(t *testing.T) {
	tree := buildNATScopeTree(t,
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a from-only DNAT rule-set: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3444") {
			t.Fatalf("unexpected #3444 warning on a from-only DNAT rule-set: %q", w)
		}
	}
	if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("from-only DNAT rule-set did not compile")
	}
	rs := cfg.Security.NAT.Destination.RuleSets[0]
	if rs.FromZone != "untrust" {
		t.Fatalf("FromZone = %q, want untrust", rs.FromZone)
	}
}
