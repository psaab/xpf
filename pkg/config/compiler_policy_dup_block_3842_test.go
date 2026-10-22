package config

// #3842: a security policy term with DUPLICATE inner `match {}` or `then {}`
// blocks — the shape produced by `load merge` / `load override` (and by a
// hierarchical config that authors two blocks), since parseStatements APPENDS
// a repeated block rather than merging it — had the SECOND block silently
// dropped. compilePolicy (compiler_security.go) read only the first block via
// FindChild("match")/FindChild("then"), and the six strict policy gates
// (validatePolicyMatchLeavesStrict #3113, validatePolicyRequiredMatchStrict
// #3044, validatePolicyThenPermitStrict #3114, validatePolicyThenRejectStrict
// #3115, validatePolicyThenDenyStrict #3141 — plus the compiler itself) all
// used the same FindChild-first read, so the second block was neither enforced
// nor validated. Net: an L7 application constraint, an address constraint, or a
// deny/reject in a duplicated block was discarded and the policy WIDENED with a
// clean commit — a HIGH security fail-open. #3562/#3377 fixed top-level
// duplicate `security`/`policies` blocks and duplicate action NODES within one
// then block, but NOT duplicate inner match/then BLOCKS under one term.
//
// The fix accumulates across ALL match/then blocks (policyMatchChildren /
// policyThenChildren / policyThenActionNodes) in both the compiler and every
// gate, so the second block is enforced AND validated. Where two blocks carry
// conflicting terminal actions the #3043 conflicting-terminal-action gate
// rejects the commit (the fail-closed floor) instead of the compiler silently
// dropping one into a fail-open permit.
//
// These tests build the DUPLICATE-BLOCK hierarchical shape with NewParser (a
// genuine brace config, not flat-set — the CLAUDE.md "use SetPath, never
// NewParser" rule targets flat-set syntax; a hierarchical duplicate-block
// config is exactly what load merge/override yields and cannot be produced via
// SetPath, which merges blocks). Each test asserts a precondition that the
// parse really produced two blocks, so it proves the bypass, not a merged node
// the old read already handled. Reverting the accumulate fix turns each RED.

import (
	"strings"
	"testing"
)

// Hierarchical trees are built via parseHierText (#16139 kit).

// zonePairPolicyNode locates the from-zone trust to-zone untrust policy `name`
// AST node so a test can assert the duplicate-block precondition.
func zonePairPolicyNode(t *testing.T, tree *ConfigTree, name string) *Node {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatal("no security node")
	}
	pols := sec.FindChild("policies")
	if pols == nil {
		t.Fatal("no policies node")
	}
	fz := pols.FindChild("from-zone")
	if fz == nil {
		t.Fatal("no from-zone node")
	}
	for _, p := range fz.FindChildren("policy") {
		if len(p.Keys) >= 2 && p.Keys[1] == name {
			return p
		}
	}
	t.Fatalf("policy %q not found", name)
	return nil
}

// TestPolicyDupMatchBlockAccumulated_3842 is the compiler-accumulate proof: a
// deny policy whose `application` constraint is split across TWO `match {}`
// blocks (junos-http in the first, junos-https in a second block) must deny
// BOTH. Dropping the second block (FindChild-first) leaves junos-https
// un-denied — a fail-open. Reverting compilePolicy's match read to
// FindChild-first turns Applications into [junos-http] only and this goes RED.
func TestPolicyDupMatchBlockAccumulated_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    deny;
                }
                match {
                    application junos-https;
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	polNode := zonePairPolicyNode(t, tree, "p")
	if n := len(polNode.FindChildren("match")); n != 2 {
		t.Fatalf("precondition: expected 2 match blocks (the #3842 dup-block shape), got %d", n)
	}

	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := findZonePairPolicy(t, c, "trust", "untrust", "p")

	if !containsStr(pol.Match.Applications, "junos-http") ||
		!containsStr(pol.Match.Applications, "junos-https") {
		t.Fatalf("Match.Applications = %v, want BOTH junos-http and junos-https "+
			"(second match block dropped — the #3842 fail-open widening)",
			pol.Match.Applications)
	}
	if pol.Action != PolicyDeny {
		t.Fatalf("Action = %v, want deny", pol.Action)
	}
}

// TestPolicyDupThenBlockConflictRejected_3842 proves two `then {}` blocks with
// CONFLICTING terminal actions (permit in the first, reject in a second block)
// are rejected at commit via the #3043 conflicting-terminal-action gate — the
// fail-closed floor. Reverting compilePolicy's then read to FindChild-first
// sees only the first `then { permit }`, so the commit SUCCEEDS as an
// unconditional permit (the reject silently dropped — a fail-open) and this
// goes RED.
func TestPolicyDupThenBlockConflictRejected_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
                then {
                    reject;
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	polNode := zonePairPolicyNode(t, tree, "p")
	if n := len(polNode.FindChildren("then")); n != 2 {
		t.Fatalf("precondition: expected 2 then blocks (the #3842 dup-block shape), got %d", n)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("compile accepted two conflicting then blocks; want commit rejection " +
			"(second then block silently dropped into a fail-open permit — #3842)")
	}
	if !strings.Contains(err.Error(), "conflicting terminal actions") {
		t.Fatalf("error = %q, want conflicting-terminal-actions rejection", err.Error())
	}
	if !strings.Contains(err.Error(), "permit") || !strings.Contains(err.Error(), "reject") {
		t.Fatalf("error = %q, want both permit and reject named", err.Error())
	}
}

// TestPolicyDupMatchBlockUnsupportedLeafRejected_3842 proves the #3113
// unsupported-match-leaf gate inspects the SECOND `match {}` block: an
// unsupported `dynamic-application` leaf carried only by a duplicate match
// block is rejected at commit. Reverting the gate's match read to
// FindChild-first sees only the first (valid) block, the compiler drops the
// unsupported leaf silently, the commit SUCCEEDS, and this goes RED.
func TestPolicyDupMatchBlockUnsupportedLeafRejected_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
                match {
                    dynamic-application junos:FTP;
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	polNode := zonePairPolicyNode(t, tree, "p")
	if n := len(polNode.FindChildren("match")); n != 2 {
		t.Fatalf("precondition: expected 2 match blocks, got %d", n)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("compile accepted an unsupported match leaf in a second match block; " +
			"want #3113 rejection (leaf silently dropped/widened — #3842)")
	}
	if !strings.Contains(err.Error(), "#3113") ||
		!strings.Contains(err.Error(), "dynamic-application") {
		t.Fatalf("error = %q, want #3113 dynamic-application rejection", err.Error())
	}

	// Lenient (load / peer-sync) path: the gate must WARN about the second
	// block, not silently boot — proving the accumulate fix also covers the
	// #1960 fail-closed-on-load surface.
	lc, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile returned hard error (should warn + boot): %v", lerr)
	}
	if !containsSub(lc.Warnings, "dynamic-application") {
		t.Fatalf("lenient warnings = %v, want a dynamic-application warning "+
			"for the second match block", lc.Warnings)
	}
}

// TestPolicyDupThenBlockUnsupportedModifierRejected_3842 proves the #3114
// then-permit gate inspects a permit modifier carried by a SECOND `then {}`
// block. A bare `then { permit }` plus a second `then { permit
// application-services ... }` is rejected at commit with the specific #3114
// diagnostic. Reverting the gate's then read to FindChild-first sees only the
// first bare permit and misses the modifier; on revert the compiler also reads
// only the first then block, so no conflict and no #3114 — RED.
func TestPolicyDupThenBlockUnsupportedModifierRejected_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
                then {
                    permit {
                        application-services {
                            utm-policy strict-web;
                        }
                    }
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	polNode := zonePairPolicyNode(t, tree, "p")
	if n := len(polNode.FindChildren("then")); n != 2 {
		t.Fatalf("precondition: expected 2 then blocks, got %d", n)
	}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("compile accepted an unsupported then-permit modifier in a second " +
			"then block; want #3114 rejection (#3842)")
	}
	if !strings.Contains(err.Error(), "#3114") ||
		!strings.Contains(err.Error(), "application-services") {
		t.Fatalf("error = %q, want #3114 application-services rejection", err.Error())
	}
}

// TestPolicyDupMatchBlockSplitDimensionsAccepted_3842 proves the #3044
// required-match gate UNIONS the required dimensions across blocks: a policy
// whose source/destination-address live in one block and application in a
// second (as a load merge would split them) is COMPLETE once merged and
// commits. Reverting the gate's match read to FindChild-first sees only the
// first block, reports `application` missing, and spuriously REJECTS — so this
// goes RED (a hard error) on revert.
func TestPolicyDupMatchBlockSplitDimensionsAccepted_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                }
                then {
                    permit;
                }
                match {
                    application junos-http;
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	polNode := zonePairPolicyNode(t, tree, "p")
	if n := len(polNode.FindChildren("match")); n != 2 {
		t.Fatalf("precondition: expected 2 match blocks, got %d", n)
	}

	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile rejected a policy whose required dimensions are split "+
			"across two match blocks (should merge to complete — #3842): %v", err)
	}
	pol := findZonePairPolicy(t, c, "trust", "untrust", "p")
	if !containsStr(pol.Match.Applications, "junos-http") {
		t.Fatalf("Match.Applications = %v, want junos-http (from second match block)",
			pol.Match.Applications)
	}
}

// TestPolicySingleMatchThenBlockUnchanged_3842 is the regression guard: the
// common single-block policy compiles bit-identically after the accumulate
// change (FindChildren over one block == the old FindChild read).
func TestPolicySingleMatchThenBlockUnchanged_3842(t *testing.T) {
	cfg := `security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                }
            }
        }
    }
}`
	tree := parseHierText(t, cfg)
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := findZonePairPolicy(t, c, "trust", "untrust", "p")
	if pol.Action != PolicyPermit {
		t.Fatalf("Action = %v, want permit", pol.Action)
	}
	if len(pol.Match.Applications) != 1 || pol.Match.Applications[0] != "junos-http" {
		t.Fatalf("Match.Applications = %v, want [junos-http]", pol.Match.Applications)
	}
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "any" {
		t.Fatalf("Match.SourceAddresses = %v, want [any]", pol.Match.SourceAddresses)
	}
}

// containsStr reports whether s is in xs.
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
