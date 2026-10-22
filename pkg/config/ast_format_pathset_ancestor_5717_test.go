package config

import (
	"strings"
	"testing"
)

// #5717 / codex-182 A3-b00-C001 (display half): a path-scoped
// `show configuration <path> | display set` (FormatPathSet) reconstructed the
// parent prefix by searching the display path for the FIRST token equal to the
// matched node's first key and stopping there. When an ANCESTOR argument equals
// that key — e.g. a security zone NAMED "interfaces" that holds an `interfaces`
// stanza, or a policy/term whose name equals a child keyword — the prefix was
// truncated at the ancestor and the emitted set line dropped the ancestor token,
// producing a malformed, NON-round-trippable line that pointed at a different
// object if replayed.
//
// The copy half of the same cohort (CopyPath first-keyword insertNode) was
// already repaired by #5822; this guards the display half.
//
// RED-on-revert: restore the left-to-right "stop at first token == firstKey"
// prefix derivation in FormatPathSet and these round-trip assertions fail — the
// ancestor "interfaces"/"trust" token disappears from the emitted set line.

func TestFormatPathSetAncestorEqualsKey_5717(t *testing.T) {
	// A security zone whose NAME equals the child keyword `interfaces`.
	src := `security {
    zones {
        security-zone interfaces {
            interfaces {
                ge-0/0/9.0;
            }
        }
    }
}`
	tree := parseHierText(t, src)
	path := []string{"security", "zones", "security-zone", "interfaces", "interfaces"}
	got := strings.TrimSpace(tree.FormatPathSet(path))

	// The correct, round-trippable line retains BOTH the zone-name token and the
	// `interfaces` stanza keyword.
	want := "set security zones security-zone interfaces interfaces ge-0/0/9.0"
	if got != want {
		t.Fatalf("FormatPathSet dropped the ancestor token:\n got: %q\nwant: %q", got, want)
	}

	// The emitted set line must round-trip: re-parsing it (flat-set path, via
	// ParseSetCommand + SetPath per the project's flat-set testing rule) and
	// re-rendering reproduces the same statement (proves it is not malformed).
	rtTree := buildTreeFromSet(t, []string{got})
	if back := strings.TrimSpace(rtTree.FormatPathSet(path)); back != want {
		t.Fatalf("round-trip diverged:\n got: %q\nwant: %q", back, want)
	}
}

// The multi-key repeated-key case (codex-182 fold): a firewall filter NAMED
// `term` holding a term NAMED `term`. The full render is
// `set firewall family inet filter term term term then accept`. Scoping to
// `... filter term term` matches the `term term` node by only its FIRST key (a
// single-key bare-keyword terminal, true consumed width 1), but the path's last
// TWO tokens `["term","term"]` also equal the node's whole Keys — so the first
// #5717 cut (suffix-align the node's keys against the path) over-stripped and
// dropped an ancestor `term`. The width-based reconstruction uses navigatePath's
// TRUE consumed width and keeps every token. Both `filter <name>` and
// `term <name>` accept `term` as a legal name (schema_cos.go).
//
// RED-on-revert: replace the width-based parentPrefix with the suffix-align
// heuristic and the `... filter term term` scope drops a `term`.
func TestFormatPathSetRepeatedMultiKey_5717(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set firewall family inet filter term term term then accept",
	})
	full := "set firewall family inet filter term term term then accept"

	// Every scoped depth into the repeated-`term` chain must render the full,
	// round-trippable statement — none may drop a `term`.
	scopes := [][]string{
		{"firewall", "family", "inet", "filter", "term"},                         // the filter named term
		{"firewall", "family", "inet", "filter", "term", "term"},                 // + the term named term (single-key terminal, width 1)
		{"firewall", "family", "inet", "filter", "term", "term", "term"},         // full term identity (multi-key terminal, width 2)
		{"firewall", "family", "inet", "filter", "term", "term", "term", "then"}, // the then action
	}
	for _, path := range scopes {
		got := strings.TrimSpace(tree.FormatPathSet(path))
		if got != full {
			t.Fatalf("FormatPathSet(%v) dropped a token:\n got: %q\nwant: %q", path, got, full)
		}
		// Round-trip the emitted line.
		rt := buildTreeFromSet(t, []string{got})
		if back := strings.TrimSpace(rt.FormatPathSet(scopes[len(scopes)-1])); back != full {
			t.Fatalf("round-trip of %v diverged:\n got: %q\nwant: %q", path, back, full)
		}
	}
}

// A second shape: an ancestor policy NAMED after a descendant keyword. Here the
// term is named "match" (a legal Junos name) and the matched leaf keyword is
// also reachable such that a naive first-key search truncates the prefix.
func TestFormatPathSetPolicyNameEqualsKey_5717(t *testing.T) {
	// Policy NAMED "then" holding a `then permit` action: the matched node's
	// first key `then` also appears earlier as the policy name.
	src := `security {
    policies {
        from-zone trust to-zone untrust {
            policy then {
                then {
                    permit;
                }
            }
        }
    }
}`
	tree := parseHierText(t, src)
	path := []string{
		"security", "policies", "from-zone", "trust", "to-zone", "untrust",
		"policy", "then", "then",
	}
	got := strings.TrimSpace(tree.FormatPathSet(path))
	want := "set security policies from-zone trust to-zone untrust policy then then permit"
	if got != want {
		t.Fatalf("FormatPathSet dropped the policy-name token:\n got: %q\nwant: %q", got, want)
	}
}
