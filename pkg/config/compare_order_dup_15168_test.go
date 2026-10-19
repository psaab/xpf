package config

import (
	"strings"
	"testing"
)

// #15168 (B24-01): every compare surface was order-blind and duplicate-blind.
// diffNodes keyed siblings by KeyPath into a map (last duplicate wins) and
// nodesEqual matched children through a map without comparing order, so an
// `insert` that reorders first-match policies rendered as [no changes], and
// with repeated containers the removed stanza shown was the wrong policy.

const compare15168PolicyPair = `security {
    policies {
        from-zone trust to-zone untrust {
            policy deny-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application junos-ssh;
                }
                then {
                    deny;
                }
            }
            policy allow-all {
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
`

const compare15168PolicyPairReordered = `security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
            policy deny-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application junos-ssh;
                }
                then {
                    deny;
                }
            }
        }
    }
}
`

// TestFormatCompareReorder15168: swapping first-match policy order is a
// semantic change (deny-ssh now loses to allow-all). The compare must show
// deny-ssh moved as a -/+ pair, not [no changes] (empty diff).
func TestFormatCompareReorder15168(t *testing.T) {
	oldTree := mustParse(t, compare15168PolicyPair)
	newTree := mustParse(t, compare15168PolicyPairReordered)
	diff := FormatCompare(oldTree, newTree)
	if diff == "" {
		t.Fatalf("reordered first-match policies rendered as no changes; want deny-ssh moved")
	}
	if !strings.Contains(diff, "-") || !strings.Contains(diff, "+") {
		t.Fatalf("reorder diff must contain -/+ arms:\n%s", diff)
	}
	if !strings.Contains(diff, "deny-ssh") {
		t.Fatalf("reorder diff must name deny-ssh:\n%s", diff)
	}
	// Reverse direction must also be visible.
	rev := FormatCompare(newTree, oldTree)
	if rev == "" || !strings.Contains(rev, "deny-ssh") {
		t.Fatalf("reverse reorder diff must name deny-ssh:\n%s", rev)
	}
}

// TestFormatCompareIdenticalOrderControl15168: identical trees (same order)
// must still render no changes — the order-aware diff must not invent moves.
func TestFormatCompareIdenticalOrderControl15168(t *testing.T) {
	a := mustParse(t, compare15168PolicyPair)
	b := mustParse(t, compare15168PolicyPair)
	if diff := FormatCompare(a, b); diff != "" {
		t.Fatalf("identical trees rendered a diff:\n%s", diff)
	}
}

// TestFormatCompareDuplicateContainerRemoval15168: with repeated
// `from-zone trust to-zone untrust` containers, removing the deny-ssh policy
// from the first container must show `- policy deny-ssh` and must NOT show
// allow-all (from the surviving container) as removed.
func TestFormatCompareDuplicateContainerRemoval15168(t *testing.T) {
	oldTree := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy deny-ssh {
                match {
                    source-address any;
                    destination-address any;
                    application junos-ssh;
                }
                then {
                    deny;
                }
            }
        }
        from-zone trust to-zone untrust {
            policy allow-all {
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
`)
	newTree := mustParse(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
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
`)
	diff := FormatCompare(oldTree, newTree)
	if diff == "" {
		t.Fatalf("removing deny-ssh from repeated containers rendered as no changes")
	}
	if !strings.Contains(diff, "-") || !strings.Contains(diff, "deny-ssh") {
		t.Fatalf("diff must show '- policy deny-ssh' removed:\n%s", diff)
	}
	// allow-all survives in the candidate; it must never appear on a removed arm.
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-") && strings.Contains(line, "allow-all") {
			t.Fatalf("diff wrongly shows surviving allow-all as removed:\n%s", diff)
		}
	}
}

// TestFormatCompareNodesEqualOrder15168: nodesEqual must be order-sensitive
// for ordered sibling lists and duplicate-aware.
func TestFormatCompareNodesEqualOrder15168(t *testing.T) {
	a := mustParse(t, compare15168PolicyPair)
	b := mustParse(t, compare15168PolicyPairReordered)
	pa := a.FindChild("security").FindChild("policies")
	pb := b.FindChild("security").FindChild("policies")
	if pa == nil || pb == nil {
		t.Fatal("fixture did not parse policies container")
	}
	if nodesEqual(pa, pb) {
		t.Fatal("nodesEqual treated reordered first-match policies as equal")
	}
	c := mustParse(t, compare15168PolicyPair)
	pc := c.FindChild("security").FindChild("policies")
	if !nodesEqual(pa, pc) {
		t.Fatal("nodesEqual treated identically-ordered policies as unequal")
	}
}
