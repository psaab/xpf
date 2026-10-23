package config

// #5823: a firewall-filter term may name at most ONE flexible-match-range range
// (the wire matcher supports one). The pre-fix compiler iterated every named
// range, kept only the FIRST, and `break`ed — silently dropping every later
// range. An `accept` term then OVER-PERMITTED (the dropped ranges' packets were
// no longer required to match) and a `discard`/`reject` term OVER-DROPPED. This
// is the same #1960 strict/lenient discipline as #3203/#3205/#5832/#5833:
//   - STRICT commit (CompileConfig): hard-REJECT a term with cardinality > 1,
//     naming the filter/term/ranges, BEFORE the dataplane apply.
//   - LENIENT load / peer-sync (CompileConfigLenient): do NOT silently first-win
//     — downgrade to a WARNING and mark the term (FlexMatchRangeNames) so the
//     userspace snapshot builder poisons it to match NOTHING (fail-closed).
//   - A single range compiles exactly as before.
//
// FAIL-ON-REVERT: removing the cardinality gate in validateFilterFlexMatchStrict
// (or the FlexMatchRangeNames aggregation in compileFilterFrom) makes the
// two-range config commit — the strict-reject and lenient-mark assertions go RED.

import (
	"strings"
	"testing"
)

// twoRangeHierarchical is a hierarchical config whose single term names TWO
// individually-VALID ranges in ONE flexible-match-range block. Every token is
// well-formed, so a rejection can only be the cardinality gate, not a parse
// error (UnknownFlexMatch stays empty).
const twoRangeHierarchical = `firewall {
    family inet {
        filter fmr {
            term t {
                from {
                    flexible-match-range {
                        range r1 {
                            match-start layer-3;
                            byte-offset 9;
                            bit-length 8;
                            match-value 0x11;
                            match-mask 0xFF;
                        }
                        range r2 {
                            match-start layer-3;
                            byte-offset 20;
                            bit-length 8;
                            match-value 0x22;
                            match-mask 0xFF;
                        }
                    }
                }
                then accept;
            }
        }
    }
}
`

// Acceptance 1 + 3 (accept term) + 4: a hierarchical term with two valid ranges
// is hard-rejected at commit (CompileConfig, which runs BEFORE the dataplane
// apply), and the error names the family/filter/term and BOTH ranges.
func TestFlexMatchMultiRangeHierarchicalRejected_5823(t *testing.T) {
	tree, err := NewParser(twoRangeHierarchical).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, cerr := CompileConfig(tree)
	if cerr == nil {
		t.Fatal("a term naming two flexible-match-range ranges must be REJECTED at " +
			"commit (#5823): the pre-fix compiler kept only the first, over-permitting")
	}
	for _, want := range []string{"inet", `filter "fmr"`, `term "t"`, "r1", "r2", "at most one range"} {
		if !strings.Contains(cerr.Error(), want) {
			t.Fatalf("reject error %q must contain %q (name the offending filter/term/ranges)", cerr, want)
		}
	}
	// Prove it is a CARDINALITY rejection, not a parse-validation one: every
	// token is valid, so UnknownFlexMatch must be empty on the lenient compile.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", lerr)
	}
	term := cfg.Firewall.FiltersInet["fmr"].Terms[0]
	if len(term.UnknownFlexMatch) != 0 {
		t.Fatalf("both ranges are individually valid; UnknownFlexMatch must be empty "+
			"(the rejection is cardinality, not a parse error): %v", term.UnknownFlexMatch)
	}
	if len(term.FlexMatchRangeNames) != 2 {
		t.Fatalf("FlexMatchRangeNames must aggregate BOTH ranges, got %v", term.FlexMatchRangeNames)
	}
}

// Acceptance 2: the cardinality count AGGREGATES across repeated flat-set
// flexible-match-range blocks, duplicate names, AND a `from` group expansion —
// not just the ranges in a single block. Flat-set fixtures use
// ParseSetCommand + SetPath (never NewParser).
func TestFlexMatchMultiRangeFlatSetAndGroupCounted_5823(t *testing.T) {
	// A group contributes a range rg; the term also names r1 directly. After
	// ExpandGroups (run inside CompileConfig*), the term carries BOTH.
	// One well-formed leaf per range keeps the flat-set path unambiguous (a
	// single set command carries ONE leaf; #2419 dual-shape gotcha).
	tree := buildFilterTree(t,
		"set groups G firewall family inet filter f term t from flexible-match-range range rg byte-offset 0",
		"set apply-groups G",
		"set firewall family inet filter f term t from flexible-match-range range r1 byte-offset 9",
		"set firewall family inet filter f term t then accept",
	)
	// Strict: rejected (cardinality > 1 after group expansion).
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("a flat-set term whose own range plus a group-expanded range total two " +
			"must be rejected (#5823 cardinality aggregates across group expansion)")
	}
	// Lenient: both counted on the compiled term.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", lerr)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if len(term.FlexMatchRangeNames) != 2 {
		t.Fatalf("cardinality must aggregate the direct range AND the group-expanded range, got %v",
			term.FlexMatchRangeNames)
	}
	names := strings.Join(term.FlexMatchRangeNames, ",")
	if !strings.Contains(names, "r1") || !strings.Contains(names, "rg") {
		t.Fatalf("FlexMatchRangeNames must contain both r1 and rg, got %v", term.FlexMatchRangeNames)
	}
}

// Acceptance 3 (discard term): the over-drop direction. Both ranges are valid,
// so a discard term that would OVER-DROP is rejected on cardinality alone.
func TestFlexMatchMultiRangeDiscardRejected_5823(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter d term t from flexible-match-range range a byte-offset 0",
		"set firewall family inet filter d term t from flexible-match-range range b byte-offset 9",
		"set firewall family inet filter d term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a discard term naming two ranges must be rejected (#5823): keeping only " +
			"the first range OVER-DROPS the traffic the second range scoped")
	}
	if !strings.Contains(err.Error(), `filter "d"`) || !strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("reject error %q must name the filter/term", err)
	}
}

// Acceptance 5: the tolerant / peer-sync path fails CLOSED — the term is MARKED
// (FlexMatchRangeNames > 1, which the userspace snapshot builder poisons to
// match nothing) AND an operator-visible WARNING is emitted. It must NOT
// hard-fail (a persisted/peer-synced config still boots, #1960).
func TestFlexMatchMultiRangeLenientMarkedAndWarned_5823(t *testing.T) {
	tree, err := NewParser(twoRangeHierarchical).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must not hard-fail on a multi-range term (#1960 no-brick): %v", lerr)
	}
	term := cfg.Firewall.FiltersInet["fmr"].Terms[0]
	if len(term.FlexMatchRangeNames) <= 1 {
		t.Fatalf("the term must be MARKED with all ranges so the wire fails it closed, got %v",
			term.FlexMatchRangeNames)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "flexible-match-range") && strings.Contains(w, "at most one range") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("a multi-range term on the tolerant path must emit an operator-visible "+
			"cardinality WARNING, got warnings: %v", cfg.Warnings)
	}
}

// Acceptance 6: a SINGLE range is unchanged — it compiles cleanly (strict), its
// FlexMatch fields are exactly as authored, and FlexMatchRangeNames has one
// entry (never triggers the gate).
func TestFlexMatchSingleRangeUnchanged_5823(t *testing.T) {
	// Hierarchical single range — every field nests cleanly, so this pins the
	// compiled FlexMatch byte-for-byte against the pre-#5823 behavior.
	const single = `firewall {
    family inet {
        filter ok {
            term t {
                from {
                    flexible-match-range {
                        range only {
                            match-start layer-3;
                            byte-offset 9;
                            bit-length 8;
                            match-value 0x11;
                            match-mask 0xFF;
                        }
                    }
                }
                then accept;
            }
        }
    }
}
`
	tree, err := NewParser(single).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("a single-range term must compile cleanly (no regression): %v", cerr)
	}
	term := cfg.Firewall.FiltersInet["ok"].Terms[0]
	if len(term.FlexMatchRangeNames) != 1 {
		t.Fatalf("a single range must record exactly one name, got %v", term.FlexMatchRangeNames)
	}
	fm := term.FlexMatch
	if fm == nil {
		t.Fatal("single-range FlexMatch must be set")
	}
	if fm.MatchStart != "layer-3" || fm.ByteOffset != 9 || fm.BitLength != 8 || fm.Value != 0x11 || fm.Mask != 0xFF {
		t.Fatalf("single-range FlexMatch fields changed: %+v", fm)
	}

	// Flat-set single range also compiles and counts exactly one.
	ftree := buildFilterTree(t,
		"set firewall family inet filter okflat term t from flexible-match-range range only byte-offset 9",
		"set firewall family inet filter okflat term t from flexible-match-range range only match-value 0x11",
		"set firewall family inet filter okflat term t then accept",
	)
	fcfg, ferr := CompileConfig(ftree)
	if ferr != nil {
		t.Fatalf("flat-set single-range term must compile cleanly: %v", ferr)
	}
	if got := fcfg.Firewall.FiltersInet["okflat"].Terms[0].FlexMatchRangeNames; len(got) != 1 {
		t.Fatalf("flat-set single range must record exactly one name, got %v", got)
	}
}
