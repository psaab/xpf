package config

import (
	"strings"
	"testing"
)

// #6455 Finding 1 — group-authored duplicate names.
//
// The three pre-expansion gates scan top-level stanzas only, so a duplicate
// authored ENTIRELY inside an applied group body reached the compiled config
// with both instances alive, while the byte-identical inline duplicate was
// hard-rejected. Same config, same compiled shape, opposite verdict, decided by
// where the operator happened to write it.
//
// The accept-side control for this gate is the PRE-EXISTING
// TestDup6455GroupFragmentCoalescingAccepted: fragments of one named object
// authored across repeated group roots must still commit. That test is what a
// per-group-body scan failed, and it must keep passing here — the post-expansion
// view sees them already coalesced into one node. This file adds the reject side
// plus the controls specific to running post-expansion.

// dupExpandedGroupNATRule is the issue's verbatim repro: two same-named rules
// inside one group-authored rule-set, with no inline peer.
const dupExpandedGroupNATRule = `groups {
    G {
        security {
            nat {
                source {
                    rule-set RS {
                        rule R { then { source-nat { interface; } } }
                        rule R { then { source-nat { off; } } }
                    }
                }
            }
        }
    }
}
apply-groups G;`

// TestDupExpanded6455GroupAuthoredNATRuleRejected is the RED-on-revert proof.
//
// Measured on `52f51200e` before this gate: this config compiled CLEAN and
// produced rule-set "RS" holding TWO rules both named "R".
//
// The error must carry BOTH tags: #5649 because that is the defect (a NAT
// rule-set is keyed by rule name), and #6455 because the reason the operator's
// commit-check did not catch it earlier is the group authoring — an error that
// named only the duplicate would send them looking at a top-level stanza that
// does not contain it.
func TestDupExpanded6455GroupAuthoredNATRuleRejected(t *testing.T) {
	_, err := CompileConfig(parseHierText(t, dupExpandedGroupNATRule))
	if err == nil {
		t.Fatal("a duplicate NAT rule authored entirely inside an applied group compiled clean; " +
			"both instances survive expansion as separate first-match entries sharing one name")
	}
	for _, want := range []string{"duplicate NAT source rule", `"R"`, `"RS"`, "#5649", "#6455", "applied group"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q so the operator can find the duplicate AND learn why "+
				"the top-level gate missed it; got: %v", want, err)
		}
	}
}

// TestDupExpanded6455EachScannerIsWired runs one fixture per member of
// dupNameScannersExpanded, each detectable ONLY by that scanner. Dropping any
// single scanner from the slice reds exactly one subtest, so the failure
// LOCALISES to the scanner that was dropped rather than one compound red that
// masks which member is missing.
func TestDupExpanded6455EachScannerIsWired(t *testing.T) {
	cases := []struct {
		name    string
		scanner string
		cfg     string
		want    string
	}{
		{
			name:    "named block (#5180) — interfaces",
			scanner: "validateDuplicateNamedBlockAST",
			cfg: `groups { G { interfaces {
    ge-0/0/0 { description first; }
    ge-0/0/0 { description second; }
} } }
apply-groups G;`,
			want: "ge-0/0/0",
		},
		{
			name:    "NAT rule name (#5649)",
			scanner: "validateDuplicateNATRuleNamesAST",
			cfg:     dupExpandedGroupNATRule,
			want:    "duplicate NAT source rule",
		},
		{
			name:    "NAT rule-set name (#6454)",
			scanner: "validateDuplicateNATRuleSetNamesAST",
			cfg: `groups { G { security { nat { source {
    rule-set RS { rule R1 { then { source-nat { interface; } } } }
    rule-set RS { rule R2 { then { source-nat { off; } } } }
} } } } }
apply-groups G;`,
			want: "rule-set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, tc.cfg))
			if err == nil {
				t.Fatalf("%s is not reached through the expanded gate: a group-authored duplicate "+
					"it owns compiled clean", tc.scanner)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q from %s, got: %v", tc.want, tc.scanner, err)
			}
			if !strings.Contains(err.Error(), "#6455") {
				t.Errorf("the group-authored context tag is missing: %v", err)
			}
		})
	}
}

// TestDupExpanded6455PeerOnlyNodeGroupCaught is the both-node union proof. A
// duplicate authored in `groups node1` and selected by `apply-groups "${node}"`
// is invisible to the ACTIVE node's own expansion — the real path resolves
// `${node}` to node0 and never materializes the node1 body. Without the union
// this commits green on node0 and reaches the standby only through the tolerant
// sync path, where it merely warns.
//
// RED-on-revert: drop node1 from effectiveNodeViews and this compiles clean.
func TestDupExpanded6455PeerOnlyNodeGroupCaught(t *testing.T) {
	cfg := `groups {
    node1 {
        security { nat { source { rule-set PRS {
            rule PR { then { source-nat { interface; } } }
            rule PR { then { source-nat { off; } } }
        } } } }
    }
}
apply-groups "${node}";`
	_, err := CompileConfig(parseHierText(t, cfg))
	if err == nil {
		t.Fatal("a duplicate that only the PEER's ${node} expansion selects compiled clean on a " +
			"generic compile; it would commit green here and only warn on the standby")
	}
	if !strings.Contains(err.Error(), `"PR"`) {
		t.Errorf("want the node1-only duplicate named, got: %v", err)
	}
}

// TestDupExpanded6455InlineDuplicateReportedOnce is the dedup control. An inline
// top-level duplicate is present in the EXPANDED tree too, so without the
// preWarnings subtraction the lenient path would report it twice — once from the
// pre-expansion gate and once from this one — and an operator reading a
// peer-sync warning list would believe there were two defects.
//
// The strict path cannot double-report (the pre-expansion gate returns its error
// immediately), so lenient is where this has to be proven.
func TestDupExpanded6455InlineDuplicateReportedOnce(t *testing.T) {
	cfg := `security { nat { source { rule-set RS {
    rule R { then { source-nat { interface; } } }
    rule R { then { source-nat { off; } } }
} } } }`
	c, err := CompileConfigLenient(parseHierText(t, cfg))
	if err != nil {
		t.Fatalf("the tolerant path must not brick on a persisted duplicate (#1960): %v", err)
	}
	n := 0
	for _, w := range c.Warnings {
		if strings.Contains(w, "duplicate NAT source rule") && strings.Contains(w, `"R"`) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("inline duplicate reported %d times, want exactly 1; the post-expansion gate must "+
			"subtract what the pre-expansion gate already warned about. warnings=%v", n, c.Warnings)
	}
}

// TestDupExpanded6455LenientWarnsNotBricks holds the #1960 line for the
// group-authored case specifically: a config carrying one is already persisted
// on some boxes and arrives over peer-sync, so the tolerant path must warn and
// boot, not refuse.
func TestDupExpanded6455LenientWarnsNotBricks(t *testing.T) {
	c, err := CompileConfigLenient(parseHierText(t, dupExpandedGroupNATRule))
	if err != nil {
		t.Fatalf("tolerant load must not brick on a group-authored duplicate (#1960): %v", err)
	}
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, `"R"`) && strings.Contains(w, "#6455") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tolerant path must still WARN about the group-authored duplicate — silence "+
			"would leave the operator with two rules sharing one name and no signal. warnings=%v",
			c.Warnings)
	}
}

// TestDupExpanded6455InlineAndGroupPeerStillMerges is the accept-side control
// for the ORIGINAL reason the pre-expansion gates are top-level-only:
// apply-groups DEEP-MERGES a group-provided named block onto its inline
// top-level peer. That is one object, not two, and must commit.
//
// It is the case a naive "scan the group body too" fix breaks, and it is
// distinct from the fragment cases in TestDup6455GroupFragmentCoalescingAccepted
// (there the peer is another GROUP root; here it is the INLINE stanza).
func TestDupExpanded6455InlineAndGroupPeerStillMerges(t *testing.T) {
	cfg := `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
groups { G { interfaces { ge-0/0/0 { description "from group"; } } } }
apply-groups G;`
	c, err := CompileConfig(parseHierText(t, cfg))
	if err != nil {
		t.Fatalf("an inline interface deep-merged with a group-provided body of the same name is "+
			"ONE object and must commit: %v", err)
	}
	ge := c.Interfaces.Interfaces["ge-0/0/0"]
	if ge == nil {
		t.Fatal("ge-0/0/0 missing after the merge")
	}
	if ge.Description != "from group" || len(ge.Units) != 1 {
		t.Fatalf("want one merged ge-0/0/0 carrying both the inline unit and the group description, "+
			"got description=%q units=%d", ge.Description, len(ge.Units))
	}
}
