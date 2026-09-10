package config

import (
	"strconv"
	"strings"
	"testing"
)

// #6766 (opus-review-001 R23): a single-valued `icmp-type` / `icmp-code` leaf
// repeated with a CONFLICTING value inside one inline application `term` was
// last-writer-wins with no commit error. parseApplicationTerms tracked
// conflicting repeats for destination-port / source-port / timeout / alg (the
// #3366 framework) but declared no set flags for the ICMP leaves, so each
// repeat silently overwrote the pointer; the term subtree is opaque to
// SchemaValidate (`term` is args:1, children:nil), and the strict structure
// gate only sees Application.DuplicateTermLeaves — which the inline parser
// never populated for ICMP. A referenced DENY application therefore enforced
// only the LAST type/code: a deny authored `icmp-type 8` then `icmp-type 3`
// denied only type 3, and echo traffic fell through to a later permit or the
// default permit (a silent narrowing of the deny match). The direct-body path
// already tracks ICMP conflicts (#5574); this is the inline-term analogue.
//
// Shapes: packed flat-set (flatTreeFromSets — one `set` line carrying the
// repeat), hierarchical (hierTree — sibling repeats), and apply-groups (a
// group-authored packed term merged into the stanza). All three reassemble to
// the same parseApplicationTerms token stream via applicationTermKeys.

// #6814: the leaf name is matched in its QUOTED form at every site in this file
// that asserts WHICH leaf was flagged. The rejection message ends with a STATIC
// enumeration of every trackable leaf — "(destination-port / source-port /
// inactivity-timeout / timeout / alg / icmp-type / icmp-code)" — so a bare
// substring check for the leaf name is satisfied by that boilerplate no matter
// which leaf actually conflicted, and a swapped label sails through. Only the
// identifying occurrence is quoted (`conflicting duplicate "icmp-type" inside`,
// rendered by the `%q` of DuplicateTermLeaves[0] in
// compiler_validate_strict_application.go — the enumeration beside it is
// unquoted), so the quotes are what make "the error names the leaf" an
// assertion rather than a coincidence.
//
// There are FIVE such sites, and the count is stated so this claim stays
// checkable: four rejection assertions — the three table-driven ones plus
// ReferencedDeny_StrictRejects_LenientNarrows, which hardcodes its leaf name
// instead of taking it from a case table — and one tolerant-path warning
// assertion in Lenient_DowngradesToWarning. The first three were quoted before
// the other two, because a grep for the table-driven `c.leaf` form structurally
// cannot find a hardcoded string literal; the swapped-label mutation finds
// every shape.
//
// Proven by swapping the two recorded labels in parseApplicationTerms: with the
// quoted form all five sites RED, with the bare form all five PASS. The
// positive controls stay GREEN under that mutation — they author no conflict,
// so they have no label to swap, which is what shows the mutation is scoped to
// the leaf-identity path rather than breaking the package.
//
// Core fail-on-revert, packed flat-set shape: a conflicting icmp-type /
// icmp-code repeat inside one inline term must be REJECTED at commit, with the
// error naming the leaf. Revert the duplicate tracking and the second value
// silently overwrites the first (last-writer-wins), CompileConfig succeeds, and
// this assertion goes RED.
func TestApplicationTermICMPDup_FlatSet_Rejected(t *testing.T) {
	cases := []struct {
		name string
		term string
		leaf string
	}{
		{"icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 0", "icmp-type"},
		{"icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("dup", c.term)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT conflicting duplicate %q inside a term", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"`+c.leaf+`"`) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}

	// Positive control (#6766 fold). A rejection test alone cannot distinguish
	// "rejects the conflicting repeat" from "rejects this whole shape": a
	// regression that refused every packed flat-set ICMP term would satisfy
	// every assertion above. These shape-matched VALID terms — same packed
	// one-line flat-set form, non-conflicting values — must still commit.
	t.Run("positive control: valid packed flat-set terms still commit", func(t *testing.T) {
		for _, c := range []struct {
			name     string
			term     string
			wantType uint8
			wantCode *uint8
		}{
			{"single icmp-type", "term t1 protocol icmp icmp-type 8", 8, nil},
			{"icmp-type plus icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1", 3, u8p(1)},
		} {
			t.Run(c.name, func(t *testing.T) {
				tree := flatTreeFromSets(t, unrefAppOnly("okapp", c.term)...)
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("a NON-conflicting packed flat-set ICMP term must COMMIT — "+
						"the gate rejects a conflicting repeat, not the shape: %v", err)
				}
				assertTermICMP(t, cfg, "okapp-t1", c.wantType, c.wantCode)
			})
		}
	})
}

// Hierarchical shape: the same conflict authored as sibling statements inside a
// brace-block term must reject too (the compiler reassembles both AST shapes
// through applicationTermKeys).
func TestApplicationTermICMPDup_Hierarchical_Rejected(t *testing.T) {
	cases := []struct {
		name string
		body string
		leaf string
	}{
		{"icmp-type", "term t1 { protocol icmp; icmp-type 8; icmp-type 0; }", "icmp-type"},
		{"icmp-code", "term t1 { protocol icmp; icmp-type 3; icmp-code 1; icmp-code 2; }", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := hierTree(t, "applications {\n    application dup {\n        "+c.body+"\n    }\n}\n")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT conflicting duplicate %q inside a hierarchical term", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"`+c.leaf+`"`) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}

	// Positive control (#6766 fold). Without this, a shape-specific regression
	// that rejected EVERY brace-block term — e.g. a reassembly change that
	// mistook each sibling statement for a repeat of its predecessor — would
	// pass the rejection assertions above while breaking all hierarchical ICMP
	// terms. The valid sibling forms must still commit.
	t.Run("positive control: valid hierarchical terms still commit", func(t *testing.T) {
		for _, c := range []struct {
			name     string
			body     string
			wantType uint8
			wantCode *uint8
		}{
			{"single icmp-type", "term t1 { protocol icmp; icmp-type 8; }", 8, nil},
			{"icmp-type plus icmp-code", "term t1 { protocol icmp; icmp-type 3; icmp-code 1; }", 3, u8p(1)},
		} {
			t.Run(c.name, func(t *testing.T) {
				tree := hierTree(t, "applications {\n    application okapp {\n        "+c.body+"\n    }\n}\n")
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("a NON-conflicting hierarchical ICMP term must COMMIT — the "+
						"gate rejects a conflicting repeat, not sibling statements: %v", err)
				}
				assertTermICMP(t, cfg, "okapp-t1", c.wantType, c.wantCode)
			})
		}
	})
}

// apply-groups shape: a group-authored term carrying the conflicting repeat is
// cloned into the applications stanza by ExpandGroups; the merged config must
// reject exactly like a directly-authored one (apply-groups is one of the load
// paths that produces duplicate term leaves in practice).
func TestApplicationTermICMPDup_ApplyGroups_Rejected(t *testing.T) {
	cases := []struct {
		name string
		term string
		leaf string
	}{
		{"icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 0", "icmp-type"},
		{"icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set groups g applications application dup "+c.term,
				"set apply-groups g")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT an apply-groups term with conflicting %q", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"`+c.leaf+`"`) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}

	// Positive control 1 (#6766 fold): a group-authored term with NO conflict
	// must still be cloned in and commit. The rejection cases above carry both
	// conflicting values inside the group, so on their own they cannot tell
	// "rejects the conflict" from "rejects anything arriving via apply-groups".
	t.Run("positive control: valid group-authored term still commits", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set groups g applications application okapp term t1 protocol icmp icmp-type 3 icmp-code 1",
			"set apply-groups g")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("a NON-conflicting group-authored ICMP term must COMMIT: %v", err)
		}
		assertTermICMP(t, cfg, "okapp-t1", 3, u8p(1))
	})

	// Positive control 2 (#6766 fold) — the CROSS-SOURCE case the rejection
	// tests never reach. A group value restated locally is not a duplicate: it
	// is the documented apply-groups override, where the group supplies a
	// default and the local stanza wins. The local `term t1` REPLACES the
	// group's outright, so the group's icmp-code must not leak into the merged
	// term either. An edit that folded the two sources into one token stream
	// would both reject this (spurious duplicate) and surface icmp-code 5, and
	// nothing else in this file would notice.
	t.Run("positive control: local term overrides a group term without a false duplicate", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set groups g applications application ovr term t1 protocol icmp icmp-type 8 icmp-code 5",
			"set apply-groups g",
			// The local value is deliberately 0 (echo-reply), the SCALAR ZERO of
			// the compiled uint8 (#6814 gate). assertTermICMP rejects a nil
			// ICMPType outright, so "committed the local 0" and "compiled
			// nothing" cannot be confused here — the nil check carries the
			// weight a non-zero value would otherwise have to. That makes this
			// control bind the zero value itself: a compiler that dropped the
			// local statement, or that let the group's 8 win, is caught, and so
			// is one that treats a committed 0 as "unset".
			"set applications application ovr term t1 protocol icmp icmp-type 0")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("a local term restating a group-inherited icmp-type is an apply-groups "+
				"OVERRIDE, not a conflicting repeat, and must COMMIT: %v", err)
		}
		// Local wins; the group's icmp-code does not survive the replacement.
		assertTermICMP(t, cfg, "ovr-t1", 0, nil)
	})
}

// Fail-on-revert (security-adjacent): a REFERENCED deny application whose
// inline term carries conflicting `icmp-type` values must be rejected at
// commit. Revert the fix and the term silently keeps only the LAST value
// (type 3), so the deny no longer covers echo (type 8).
//
// Scope of what this test proves (#6766 fold, narrowed in #6814): (1) strict
// CompileConfig rejects; (2) on the lenient path — which still compiles,
// downgrading the reject to a warning — the compiled Application carries ONLY
// the last authored value.
//
// For icmp-TYPE only. This test's config authors a single conflicting leaf
// (`icmp-type 8` then `icmp-type 3`), so it says nothing about icmp-code; an
// earlier version of this comment claimed both, which a code-only keep-first
// edit on the CODE arm would have satisfied. The icmp-code half is bound by
// TestApplicationTermICMPDup_LenientKeepsLastCode below, and both leaves are
// bound at the verdict in
// pkg/policymatch/app_inline_term_icmp_dup_6766_test.go. The property is
// covered; it is just not covered HERE, which is what the claim got wrong.
//
// It asserts on the COMPILED STRUCT, not on a policy decision. It does not
// exercise either matcher, so it says nothing about what the tolerant path
// enforces for this application. That is proven separately, at the verdict,
// in pkg/policymatch/app_inline_term_icmp_dup_6766_test.go, which drives
// policymatch.Match. Keep this comment's claim and that file's in
// sync — do not restate the enforcement conclusion here.
func TestApplicationTermICMPDup_ReferencedDeny_StrictRejects_LenientNarrows(t *testing.T) {
	src := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy blockit {
                match {
                    source-address any;
                    destination-address any;
                    application badapp;
                }
                then {
                    deny;
                }
            }
        }
        default-policy {
            permit-all;
        }
    }
}
applications {
    application badapp {
        term t1 {
            protocol icmp;
            icmp-type 8;
            icmp-type 3;
        }
    }
}
`
	tree := hierTree(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a referenced deny app with a conflicting inline icmp-type")
	} else if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"icmp-type"`) {
		t.Fatalf("error should flag the conflicting icmp-type duplicate, got: %v", err)
	}

	// Characterize the underlying keep-last narrowing the gate protects against:
	// the lenient path still compiles (no-brick), and the compiled term carries
	// ONLY the last value.
	//
	// #6814: this reads the compiled STRUCT and never invokes a matcher, so it
	// cannot show what happens to echo (type 8) on the wire. An earlier version
	// of this comment said echo "falls through to the default permit" — which
	// contradicted this function's own header two dozen lines up, and the
	// header was the correct half. A matcher edit that ignored ICMPType
	// entirely would leave every assertion below green.
	//
	// That is worth naming rather than quietly rewording: it is the exact
	// defect class this PR exists to fix — a claim that a check discriminates
	// something it never reaches — turned inward on the PR's own test file. What the
	// tolerant path enforces is proven, at the verdict, by
	// pkg/policymatch/app_inline_term_icmp_dup_6766_test.go.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must NOT brick on a conflicting inline icmp-type: %v", lerr)
	}
	app := cfg.Applications.Applications["badapp-t1"]
	if app == nil {
		t.Fatalf("term application badapp-t1 missing on lenient path; have %v", appNames(cfg))
	}
	if app.ICMPType == nil || *app.ICMPType != 3 {
		got := "nil"
		if app.ICMPType != nil {
			got = strconv.Itoa(int(*app.ICMPType))
		}
		t.Fatalf("keep-last narrowing characterization: want ICMPType=3 (the silently-retained "+
			"last value), got %s", got)
	}
}

// The icmp-CODE analogue of the characterization above (#6766 fold). Before
// this, conflicting `icmp-code` was exercised ONLY on strict rejection paths:
// every test asserted that a conflict is refused, none asserted which value
// survives when it is TOLERATED. A production edit that retained the FIRST
// conflicting code instead of the last therefore passed the entire file while
// changing which traffic a referenced deny covers. This pins the surviving
// value; the matching verdict-level guard is in
// pkg/policymatch/app_inline_term_icmp_dup_6766_test.go.
func TestApplicationTermICMPDup_LenientKeepsLastCode(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("dup",
		"term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2")...)

	// Strict still refuses the conflict.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict commit must REJECT a conflicting inline icmp-code")
	}

	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must NOT brick on a conflicting inline icmp-code: %v", lerr)
	}
	app := cfg.Applications.Applications["dup-t1"]
	if app == nil {
		t.Fatalf("term application dup-t1 missing on lenient path; have %v", appNames(cfg))
	}
	if app.ICMPCode == nil || *app.ICMPCode != 2 {
		got := "nil"
		if app.ICMPCode != nil {
			got = strconv.Itoa(int(*app.ICMPCode))
		}
		t.Fatalf("keep-last narrowing characterization: want ICMPCode=2 (the silently-retained "+
			"LAST value), got %s — a keep-FIRST regression reports 1 here and silently "+
			"changes which ICMP code the compiled term carries", got)
	}
	// The type is untouched by the code conflict.
	if app.ICMPType == nil || *app.ICMPType != 3 {
		t.Fatalf("ICMPType = %v, want 3 (unaffected by the icmp-code conflict)", app.ICMPType)
	}
}

// Guard against over-rejection of the value-aware idempotent path: an ICMP leaf
// repeated with the SAME value is harmless (no value is silently lost) and must
// COMMIT — only a CONFLICTING (different-value) repeat is rejected. Flip the
// duplicate detection to value-blind (reject any repeat regardless of value)
// and this assertion goes RED.
func TestApplicationTermICMPDup_Idempotent_Accepted(t *testing.T) {
	cases := []struct {
		name     string
		term     string
		wantType uint8
		wantCode *uint8
	}{
		{"same-icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 8", 8, nil},
		{"same-icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 1", 3, u8p(1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("idem", c.term)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("an idempotent same-value repeat must COMMIT (only a "+
					"conflicting different-value repeat is rejected), got: %v", err)
			}
			app := cfg.Applications.Applications["idem-t1"]
			if app == nil {
				t.Fatalf("term application idem-t1 missing; have %v", appNames(cfg))
			}
			if app.ICMPType == nil || *app.ICMPType != c.wantType {
				t.Fatalf("the single icmp-type value must survive, want %d got %v", c.wantType, app.ICMPType)
			}
			if c.wantCode == nil {
				if app.ICMPCode != nil {
					t.Fatalf("no icmp-code authored, want nil got %d", *app.ICMPCode)
				}
			} else if app.ICMPCode == nil || *app.ICMPCode != *c.wantCode {
				t.Fatalf("the single icmp-code value must survive, want %d got %v", *c.wantCode, app.ICMPCode)
			}
		})
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on a
// conflicting inline-term ICMP repeat an older binary persisted — it downgrades
// the reject to a warning so the daemon still boots (#1960 no-brick). Revert
// the lenient downgrade and this goes RED.
func TestApplicationTermICMPDup_Lenient_DowngradesToWarning(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("dup",
		"term t1 protocol icmp icmp-type 8 icmp-type 0")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT fail on a conflicting inline icmp-type (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application structure") && strings.Contains(w, "duplicate") &&
			strings.Contains(w, `"icmp-type"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must record a downgrade warning naming icmp-type; warnings: %v", cfg.Warnings)
	}
}

// assertTermICMP checks the compiled inline-term application's ICMP constraints.
// wantCode == nil asserts the term left icmp-code unconstrained.
func assertTermICMP(t *testing.T, cfg *Config, appName string, wantType uint8, wantCode *uint8) {
	t.Helper()
	app := cfg.Applications.Applications[appName]
	if app == nil {
		t.Fatalf("term application %s missing; have %v", appName, appNames(cfg))
	}
	if app.ICMPType == nil || *app.ICMPType != wantType {
		t.Fatalf("%s ICMPType = %v, want %d", appName, app.ICMPType, wantType)
	}
	if wantCode == nil {
		if app.ICMPCode != nil {
			t.Fatalf("%s ICMPCode = %d, want unconstrained (nil)", appName, *app.ICMPCode)
		}
		return
	}
	if app.ICMPCode == nil || *app.ICMPCode != *wantCode {
		t.Fatalf("%s ICMPCode = %v, want %d", appName, app.ICMPCode, *wantCode)
	}
}
