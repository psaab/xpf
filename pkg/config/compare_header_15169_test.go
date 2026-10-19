package config

import (
	"strings"
	"testing"
)

// Regression tests for #15169 (B24-02) — `show | compare` header
// misattribution.
//
// Before the fix diffNodes printed its [edit <path>] header exactly once,
// before its rendering loop. Two defects rode on that:
//
//  1. When a modified child was recursed into (the child prints its own,
//     deeper [edit ...] header), the parent loop continued with following
//     +/-/unchanged lines at the parent level WITHOUT re-emitting the
//     parent header — so a removed/added stanza directly after a recursed
//     sibling rendered under the unrelated deeper header (e.g. a deleted
//     policy shown inside another policy's match).
//  2. At the root (empty editPath) no [edit] header was printed at all,
//     so top-level +/- lines had no context header.
func TestCompareReEmitsHeaderAfterRecursedSibling15169(t *testing.T) {
	oldTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
            policy deny-x {
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
`)
	// Remove deny-x entirely and change keep's nested `then` so the keep
	// policy is recursed into (printing a deeper header) BEFORE the
	// removed deny-x stanza is rendered at the parent level.
	newTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    reject;
                }
            }
        }
    }
}
`)
	out := FormatCompare(oldTree, newTree)
	t.Logf("compare output:\n%s", out)

	// deny-x's removal must be governed by the policies-level header:
	// the nearest preceding [edit ...] header before the deny-x line
	// must be [edit security policies from-zone trust to-zone untrust],
	// wherever the removal renders relative to the recursed sibling.
	// (Pre-fix on the pre-#15168 base the removal rendered AFTER the
	// recursed keep block, inheriting its deeper header; the #15168
	// renderer prints removals first, and this assertion pins the
	// attribution contract under either ordering.)
	if !strings.Contains(out, "-    policy deny-x {") {
		t.Errorf("removed deny-x stanza missing:\n%s", out)
	}
	if !strings.Contains(out, "[edit security policies from-zone trust to-zone untrust policy keep then]") {
		t.Errorf("recursed sibling lost its deeper [edit ... policy keep then] header:\n%s", out)
	}
	idxDeny := strings.Index(out, "-    policy deny-x {")
	if idxDeny >= 0 {
		lastHeader := strings.LastIndex(out[:idxDeny], "[edit ")
		governing := out[lastHeader:strings.Index(out[lastHeader:], "\n")+lastHeader]
		if governing != "[edit security policies from-zone trust to-zone untrust]" {
			t.Errorf("deny-x removal governed by %q, want the policies-level header:\n%s", governing, out)
		}
	}
	// The recursed keep change must likewise be governed by its own
	// deeper header, not the parent's.
	idxReject := strings.Index(out, "+    reject;")
	if idxReject >= 0 {
		lastHeader := strings.LastIndex(out[:idxReject], "[edit ")
		governing := out[lastHeader:strings.Index(out[lastHeader:], "\n")+lastHeader]
		if governing != "[edit security policies from-zone trust to-zone untrust policy keep then]" {
			t.Errorf("keep's reject governed by %q, want the deeper policy keep then header:\n%s", governing, out)
		}
	}
}

// The surviving leg of the original probe: a parent-level line that
// renders AFTER a recursed sibling. A pure addition is not a removal,
// so the #15168 removals-first ordering does not move it ahead of the
// recursion — pre-fix it inherited the deeper header outright.
func TestCompareAddedSiblingAfterRecursedSibling15169(t *testing.T) {
	oldTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
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
	newTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    reject;
                }
            }
            policy new-x {
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
	out := FormatCompare(oldTree, newTree)
	t.Logf("compare output:\n%s", out)
	if !strings.Contains(out, "+    policy new-x {") {
		t.Fatalf("added new-x stanza missing:\n%s", out)
	}
	idxNew := strings.Index(out, "+    policy new-x {")
	if idxDeep := strings.LastIndex(out[:idxNew],
		"[edit security policies from-zone trust to-zone untrust policy keep then]"); idxDeep < 0 {
		t.Fatalf("fixture premise broken: recursed keep block does not precede the addition:\n%s", out)
	}
	lastHeader := strings.LastIndex(out[:idxNew], "[edit ")
	governing := out[lastHeader:strings.Index(out[lastHeader:], "\n")+lastHeader]
	if governing != "[edit security policies from-zone trust to-zone untrust]" {
		t.Errorf("added new-x governed by %q, want the re-emitted policies-level header:\n%s", governing, out)
	}
}

// Root-level probe: a top-level addition must be preceded by a bare
// [edit] header (the pre-fix root printed no header at all).
func TestCompareRootHeader15169(t *testing.T) {
	oldTree := mustParse15169(t, `system {
    host-name alpha;
}
`)
	newTree := mustParse15169(t, `system {
    host-name alpha;
}
security {
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
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
	out := FormatCompare(oldTree, newTree)
	t.Logf("compare output:\n%s", out)
	if !strings.HasPrefix(out, "[edit]\n") {
		t.Errorf("root-level compare must open with a bare [edit] header, got:\n%s", out)
	}
	// The added stanza's governing (and only) header must be the root
	// [edit]; the unchanged sibling context line sits between them.
	if !strings.Contains(out, "+    security {") {
		t.Errorf("top-level addition missing:\n%s", out)
	}
	if got := strings.Count(out, "[edit"); got != 1 {
		t.Errorf("expected exactly one header (the root [edit]), got %d:\n%s", got, out)
	}
}

// Control: a plain leaf change inside one container renders exactly one
// header for that level and no root [edit] header — the re-emission must
// not add spurious headers when nothing was recursed into first.
func TestCompareSingleHeaderControl15169(t *testing.T) {
	oldTree := mustParse15169(t, `system {
    host-name alpha;
}
`)
	newTree := mustParse15169(t, `system {
    host-name beta;
}
`)
	out := FormatCompare(oldTree, newTree)
	if got := strings.Count(out, "[edit system]"); got != 1 {
		t.Errorf("expected exactly one [edit system] header, got %d:\n%s", got, out)
	}
	if strings.Contains(out, "[edit]\n") {
		t.Errorf("deep-only change must not gain a root [edit] header:\n%s", out)
	}
	if !strings.Contains(out, "-    host-name alpha;") || !strings.Contains(out, "+    host-name beta;") {
		t.Errorf("leaf change lines missing:\n%s", out)
	}
}

// Control: when a level's own lines all precede any recursion, the header
// appears once at the top of the level and is not duplicated.
func TestCompareNoDuplicateHeaderWithoutFollowingSiblings15169(t *testing.T) {
	oldTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
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
	newTree := mustParse15169(t, `security {
    policies {
        from-zone trust to-zone untrust {
            policy keep {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    reject;
                }
            }
        }
    }
}
`)
	out := FormatCompare(oldTree, newTree)
	if got := strings.Count(out, "[edit security policies from-zone trust to-zone untrust policy keep then]"); got != 1 {
		t.Errorf("expected exactly one deep header, got %d:\n%s", got, out)
	}
	// No parent-level +/- lines exist, so the parent header must not be
	// emitted with nothing under it.
	if strings.Contains(out, "[edit security policies from-zone trust to-zone untrust]\n") {
		t.Errorf("parent header emitted with no lines under it:\n%s", out)
	}
}

func mustParse15169(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}
