package config

import (
	"strings"
	"testing"
)

// #4562: the shared path walker previously descended into only the FIRST
// same-prefix / same-keyword sibling's children. When a hand-authored
// HIERARCHICAL config carries duplicate context blocks and a path selector
// continues deeper, the second block's statements disappeared from a
// path-scoped `show configuration <path>` and its `| display set` — a scoped
// display-set backup could silently lose them on restore. This is the
// intermediate-descent twin of the #3980 terminal read-all-siblings fix
// (same #3842 / #2419 class). `navigatePathWidth` drives display, while
// `navigateRenderedMatches` drives authz pricing; both now share
// `navigateWalk`. The compiler still reads the full AST directly, so the
// original symptom was a display / scoped-backup gap, not a forwarding bypass.
//
// These are fail-on-revert guards: reverting the intermediate descent to
// `matched[0].Children` / first-`n.Children` drops the second block and
// fails the both-blocks assertions below.

// buildDupPolicyContext builds two identical 4-key
// `from-zone untrust to-zone trust` sibling nodes holding distinct policies A
// and B, exercising the shared navigateWalk multi-key intermediate descent.
func buildDupPolicyContext(t *testing.T) *ConfigTree {
	t.Helper()
	src := `security {
    policies {
        from-zone untrust to-zone trust {
            policy A {
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
        from-zone untrust to-zone trust {
            policy B {
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
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return tree
}

// TestShowConfigDupContextMultiKeyDescent covers the multi-key intermediate
// descent: a display path that descends PAST the duplicated 4-key
// `from-zone untrust to-zone trust` context must see policies from BOTH
// duplicate blocks.
func TestShowConfigDupContextMultiKeyDescent(t *testing.T) {
	tree := buildDupPolicyContext(t)
	ctx := []string{"security", "policies", "from-zone", "untrust", "to-zone", "trust"}

	// `show configuration ... trust policy` (bare `policy`, descends past
	// the 4-key context, terminates on a repeated keyword) must list BOTH
	// policy A and policy B. RED on revert: only policy A (block A's
	// children).
	hier := tree.FormatPath(append(append([]string{}, ctx...), "policy"))
	if !strings.Contains(hier, "policy A") {
		t.Errorf("FormatPath([...trust policy]) missing policy A; got:\n%s", hier)
	}
	if !strings.Contains(hier, "policy B") {
		t.Errorf("FormatPath([...trust policy]) missing policy B (dropped second duplicate-context block); got:\n%s", hier)
	}
	if n := strings.Count(hier, "policy "); n != 2 {
		t.Errorf("FormatPath([...trust policy]) rendered %d policies, want 2; got:\n%s", n, hier)
	}

	// Naming the SECOND block's policy directly (`... policy B`) must resolve
	// to it. RED on revert: navigateWalk descends into block A's children,
	// never finds B → empty output.
	setB := tree.FormatPathSet(append(append([]string{}, ctx...), "policy", "B"))
	if !strings.Contains(setB, "policy B") || !strings.Contains(setB, "then deny") {
		t.Errorf("FormatPathSet([...trust policy B]) did not resolve policy B; got:\n%s", setB)
	}
	if strings.Contains(setB, "policy A") {
		t.Errorf("FormatPathSet([...trust policy B]) leaked policy A; got:\n%s", setB)
	}

	// Control: naming the FIRST block's policy is unchanged.
	setA := tree.FormatPathSet(append(append([]string{}, ctx...), "policy", "A"))
	if !strings.Contains(setA, "policy A") || !strings.Contains(setA, "then permit") {
		t.Errorf("FormatPathSet([...trust policy A]) did not resolve policy A; got:\n%s", setA)
	}
	if strings.Contains(setA, "policy B") {
		t.Errorf("FormatPathSet([...trust policy A]) leaked policy B; got:\n%s", setA)
	}
}

// TestShowConfigDupContextSingleKeyDescent covers the shared navigateWalk
// single-key intermediate-descent branch: two identical single-key
// `interfaces { ge-0-0-0 { ... } }` blocks holding distinct leaves. The
// display path descends through the duplicated single-key `interfaces`
// and `ge-0-0-0` levels before terminating — so both branch descents are
// exercised.
func TestShowConfigDupContextSingleKeyDescent(t *testing.T) {
	src := `interfaces {
    ge-0-0-0 {
        mtu 1500;
    }
}
interfaces {
    ge-0-0-0 {
        mtu 9000;
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}

	// `show configuration interfaces ge-0-0-0 mtu` must list BOTH mtu
	// leaves. RED on revert: single-key descent walks only the first
	// `interfaces` block → only mtu 1500.
	hier := tree.FormatPath([]string{"interfaces", "ge-0-0-0", "mtu"})
	if !strings.Contains(hier, "mtu 1500") {
		t.Errorf("FormatPath([interfaces ge-0-0-0 mtu]) missing mtu 1500; got:\n%s", hier)
	}
	if !strings.Contains(hier, "mtu 9000") {
		t.Errorf("FormatPath([interfaces ge-0-0-0 mtu]) missing mtu 9000 (dropped second duplicate single-key block); got:\n%s", hier)
	}
	if n := strings.Count(hier, "mtu "); n != 2 {
		t.Errorf("FormatPath([interfaces ge-0-0-0 mtu]) rendered %d mtu leaves, want 2; got:\n%s", n, hier)
	}

	set := tree.FormatPathSet([]string{"interfaces", "ge-0-0-0", "mtu"})
	if !strings.Contains(set, "set interfaces ge-0-0-0 mtu 1500") ||
		!strings.Contains(set, "set interfaces ge-0-0-0 mtu 9000") {
		t.Errorf("FormatPathSet([interfaces ge-0-0-0 mtu]) missing a duplicate-block mtu; got:\n%s", set)
	}
}

// TestShowConfigSingleContextDescentUnchanged is the over-broadening guard:
// a config with a SINGLE (non-duplicated) context renders a scoped descent
// identically — exactly one policy, no leak from the fix.
func TestShowConfigSingleContextDescentUnchanged(t *testing.T) {
	src := `security {
    policies {
        from-zone untrust to-zone trust {
            policy A {
                then {
                    permit;
                }
            }
        }
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	ctx := []string{"security", "policies", "from-zone", "untrust", "to-zone", "trust"}

	hier := tree.FormatPath(append(append([]string{}, ctx...), "policy"))
	if n := strings.Count(hier, "policy "); n != 1 {
		t.Errorf("single-context FormatPath([...trust policy]) rendered %d policies, want 1; got:\n%s", n, hier)
	}
	if !strings.Contains(hier, "policy A") {
		t.Errorf("single-context FormatPath([...trust policy]) missing policy A; got:\n%s", hier)
	}

	setA := tree.FormatPathSet(append(append([]string{}, ctx...), "policy", "A"))
	if !strings.Contains(setA, "policy A") {
		t.Errorf("single-context FormatPathSet([...trust policy A]) missing policy A; got:\n%s", setA)
	}
}
