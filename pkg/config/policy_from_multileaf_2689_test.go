package config

import "testing"

// #2689: the policy-statement `from community` and `from prefix-list` match
// readers in parsePolicyTermChildren read a `multi: true` leaf via only
// nodeVal(fc) = child.Keys[1] (no Keys[1:] slice, no child.Children
// iteration). A bracketed list `[ c1 c2 ]` collapses onto a single leaf's
// Keys in BOTH AST shapes (#2419), so those readers silently kept only the
// FIRST value — `from community [ c1 c2 ]` matched only c1, and
// `from prefix-list [ p1 p2 ]` matched only p1.
//
// This is the same class fixed for the protocol export/import/community-members
// readers in #2587 (PR #2687) and #2630 (PR #2685). The fix routes both
// readers through the shared firewallMatchValues SSOT (Keys[1:] + each child
// leaf). The schema leaves were already multi:true (schema_routing.go ~105/107),
// so only the compiler readers changed.
//
// #2642 added the []string OR/cartesian model for these from-* fields by
// accumulating repeated SIBLING statements; it did NOT cover the bracket-list
// collapse for these two readers. The fix below COMPOSES with #2642: a term
// carrying BOTH a bracket list AND a repeated sibling must keep every value.
//
// These are fail-on-revert guards: each asserts ALL values survive on BOTH the
// flat-set bracket-list shape (via ParseSetCommand + SetPath, the
// CLAUDE.md-mandated harness for flat-set) and the hierarchical block shape.
// Reverting either reader to the single-nodeVal form drops the trailing values
// and fails the len/element assertions.

// --- from community ---

func TestPolicyFromCommunityBracketFlatSet_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		// Communities must be defined (#2881) or the from-community
		// cross-reference gate rejects the term before this assertion runs.
		"set policy-options community c1 members 65000:1",
		"set policy-options community c2 members 65000:2",
		"set policy-options policy-statement P term T from community [ c1 c2 ]",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"c1", "c2"}
	if !equalStrs(term.FromCommunity, want) {
		t.Errorf("FromCommunity = %v, want %v (trailing community dropped without firewallMatchValues)", term.FromCommunity, want)
	}
}

func TestPolicyFromCommunityBracketHierarchical_2689(t *testing.T) {
	src := `policy-options {
    community c1 members 65000:1;
    community c2 members 65000:2;
    policy-statement P {
        term T {
            from {
                community [ c1 c2 ];
            }
            then accept;
        }
    }
}`
	cfg := mustCompile(t, src)
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"c1", "c2"}
	if !equalStrs(term.FromCommunity, want) {
		t.Errorf("FromCommunity = %v, want %v", term.FromCommunity, want)
	}
}

// Composition with #2642's repeated-sibling append: a bracket list plus a
// separate `from community c3` statement must yield [c1 c2 c3] — the bracket
// values accumulate, then the sibling appends, neither overwriting the other.
func TestPolicyFromCommunityBracketPlusSibling_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set policy-options community c1 members 65000:1",
		"set policy-options community c2 members 65000:2",
		"set policy-options community c3 members 65000:3",
		"set policy-options policy-statement P term T from community [ c1 c2 ]",
		"set policy-options policy-statement P term T from community c3",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"c1", "c2", "c3"}
	if !equalStrs(term.FromCommunity, want) {
		t.Errorf("FromCommunity = %v, want %v (bracket+sibling composition)", term.FromCommunity, want)
	}
}

// --- from prefix-list ---

func TestPolicyFromPrefixListBracketFlatSet_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set policy-options policy-statement P term T from prefix-list [ p1 p2 ]",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"p1", "p2"}
	if !equalStrs(term.PrefixList, want) {
		t.Errorf("PrefixList = %v, want %v (trailing prefix-list dropped without firewallMatchValues)", term.PrefixList, want)
	}
}

func TestPolicyFromPrefixListBracketHierarchical_2689(t *testing.T) {
	src := `policy-options {
    policy-statement P {
        term T {
            from {
                prefix-list [ p1 p2 ];
            }
            then accept;
        }
    }
}`
	cfg := mustCompile(t, src)
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"p1", "p2"}
	if !equalStrs(term.PrefixList, want) {
		t.Errorf("PrefixList = %v, want %v", term.PrefixList, want)
	}
}

func TestPolicyFromPrefixListBracketPlusSibling_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set policy-options policy-statement P term T from prefix-list [ p1 p2 ]",
		"set policy-options policy-statement P term T from prefix-list p3",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"p1", "p2", "p3"}
	if !equalStrs(term.PrefixList, want) {
		t.Errorf("PrefixList = %v, want %v (bracket+sibling composition)", term.PrefixList, want)
	}
}

// --- from as-path (review fold: sibling reader in the same function) ---

func TestPolicyFromASPathBracketFlatSet_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		// #7471: `from as-path` is definedness-gated now. Define the members so
		// this test keeps BRACKET-LIST RETENTION as its subject.
		`set policy-options as-path a1 "^65000 "`,
		`set policy-options as-path a2 "^65001 "`,
		"set policy-options policy-statement P term T from as-path [ a1 a2 ]",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"a1", "a2"}
	if !equalStrs(term.FromASPath, want) {
		t.Errorf("FromASPath = %v, want %v (trailing as-path dropped without firewallMatchValues)", term.FromASPath, want)
	}
}

func TestPolicyFromASPathBracketHierarchical_2689(t *testing.T) {
	// #7471: `from as-path` is definedness-gated now; define the members so
	// this test keeps bracket-list retention as its subject.
	src := `policy-options {
    as-path a1 "^65000 ";
    as-path a2 "^65001 ";
    policy-statement P {
        term T {
            from {
                as-path [ a1 a2 ];
            }
            then accept;
        }
    }
}`
	cfg := mustCompile(t, src)
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"a1", "a2"}
	if !equalStrs(term.FromASPath, want) {
		t.Errorf("FromASPath = %v, want %v", term.FromASPath, want)
	}
}

func TestPolicyFromASPathBracketPlusSibling_2689(t *testing.T) {
	cfg, err := compileSet(t, []string{
		// #7471: definedness-gated; define all three members.
		`set policy-options as-path a1 "^65000 "`,
		`set policy-options as-path a2 "^65001 "`,
		`set policy-options as-path a3 "^65002 "`,
		"set policy-options policy-statement P term T from as-path [ a1 a2 ]",
		"set policy-options policy-statement P term T from as-path a3",
		"set policy-options policy-statement P term T then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	want := []string{"a1", "a2", "a3"}
	if !equalStrs(term.FromASPath, want) {
		t.Errorf("FromASPath = %v, want %v (bracket+sibling composition)", term.FromASPath, want)
	}
}
