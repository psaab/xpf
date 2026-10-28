package config

// schema_spelling_forms_shared_17191_test.go — #17191: the two spelling
// gates must enumerate ONE spelling table, and the verdict matrix must
// be computed once per (leaf, value pair) per package run.
//
// Before #17191 the differential gate kept gateSpellingsMulti /
// gateSpellingsScalar plus a forms map inside spellingVerdicts, while
// the slot-escape sweep rebuilt A–E in its own path convention
// (slotEscapeForms) — F-hier-mixed existed only in the differential, so
// the slot-escape gate was silently blind to the mixed shape, and
// gateLeafCompared re-implemented the differential's comparison-set
// selection and recomputed spellingVerdicts per leaf and pair.
//
// This file pins the consolidation:
//   - both gates enumerate the same form names (differential set plus
//     the explicit per-gate exclusions: G is slotEscapeOnly, no form is
//     differentialOnly today);
//   - the differential's scalar set is exactly the multi set minus the
//     repeated forms, and a modifier-block site drops exactly F;
//   - spellingVerdicts computes each (leaf, pair) once (counter), and
//     gateLeafCompared's verdict agrees with the differential's
//     >=2-usable-verdicts condition over the same memoised matrix.

import (
	"sort"
	"testing"
)

func TestGateSpellingFormsShared17191(t *testing.T) {
	shared := gateSpellingNames()
	// Pin the expected table so adding a row is a deliberate edit here
	// too — the two gates then cannot drift apart by editing one side.
	want := []string{
		"A-hier-bracket", "B-hier-block", "C-hier-repeat",
		"D-set-bracket", "E-set-repeat", "F-hier-mixed",
		"G-hier-one-child-multi-token",
	}
	if len(shared) != len(want) {
		t.Fatalf("shared spelling table = %v, want %v", shared, want)
	}
	for i := range want {
		if shared[i] != want[i] {
			t.Fatalf("shared spelling table = %v, want %v", shared, want)
		}
	}

	// Slot-escape enumerates exactly the shared names: no second table.
	var escapeNames []string
	for _, f := range slotEscapeForms() {
		escapeNames = append(escapeNames, f.name)
		if f.run == nil {
			t.Errorf("slot-escape form %q has no run author", f.name)
		}
	}
	if len(escapeNames) != len(shared) {
		t.Fatalf("slotEscapeForms = %v, shared table = %v — the gates enumerate different spellings", escapeNames, shared)
	}
	for i := range shared {
		if escapeNames[i] != shared[i] {
			t.Fatalf("slotEscapeForms = %v, shared table = %v — the gates enumerate different spellings", escapeNames, shared)
		}
	}

	// The differential's sets are parameters of the same table:
	// scalar = multi minus the repeated forms (C/E).
	multi := gateComparisonSpellings(gateLeaf{multi: true})
	scalar := gateComparisonSpellings(gateLeaf{multi: false})
	if len(multi) != 6 {
		t.Errorf("multi comparison set = %v, want the 6 differential spellings (G is slotEscapeOnly)", multi)
	}
	// Scalar set is the pre-#17191 {A,B,D}: C/E via `repeated`, F via
	// `scalarExempt`. Pinning this is a baseline ratchet — the
	// differential was green on exactly this set, so adding a form
	// to the scalar set is a deliberate, reviewed widening, not a
	// side effect of adding a row to the shared table.
	wantScalar := []string{"A-hier-bracket", "B-hier-block", "D-set-bracket"}
	if len(scalar) != len(wantScalar) {
		t.Fatalf("scalar comparison set = %v, want %v", scalar, wantScalar)
	}
	for i := range wantScalar {
		if scalar[i] != wantScalar[i] {
			t.Fatalf("scalar comparison set = %v, want %v", scalar, wantScalar)
		}
	}

	// F-hier-mixed — the form that existed only in the differential
	// before #17191 — must be in BOTH gates' enumerations.
	foundDiff, foundEscape := false, false
	for _, n := range multi {
		if n == "F-hier-mixed" {
			foundDiff = true
		}
	}
	for _, n := range escapeNames {
		if n == "F-hier-mixed" {
			foundEscape = true
		}
	}
	if !foundDiff || !foundEscape {
		t.Errorf("F-hier-mixed: differential=%v slot-escape=%v; both gates must enumerate it", foundDiff, foundEscape)
	}

	// The slot-escape exemption bucket is consistent with the
	// differential's: exactly the F row carries it, and it names
	// exactly the mixedChildIsAModifierBlock sites.
	for _, f := range gateSpellingForms() {
		if len(f.slotEscapeExemptSites) == 0 {
			continue
		}
		if f.name != "F-hier-mixed" {
			t.Errorf("spelling %q carries slot-escape exempt sites %v; only F may (its child slot is the modifier position)", f.name, f.slotEscapeExemptSites)
		}
		if len(f.slotEscapeExemptSites) != len(mixedChildIsAModifierBlock) {
			t.Errorf("F slot-escape exempt sites = %v, mixedChildIsAModifierBlock = %v — the two modifier buckets must name the same sites", f.slotEscapeExemptSites, mixedChildIsAModifierBlock)
		}
		for site := range f.slotEscapeExemptSites {
			if _, ok := mixedChildIsAModifierBlock[site]; !ok {
				t.Errorf("F slot-escape exempt site %q is not a mixedChildIsAModifierBlock site", site)
			}
			// And it must actually exempt: gateSlotEscapeSpellings for
			// that site omits F while other forms remain.
			found := false
			for _, gf := range gateSlotEscapeSpellings(gateLeaf{path: []string{"system", "archival", "configuration"}, leaf: "archive-sites", multi: true}) {
				if gf.name == "F-hier-mixed" {
					found = true
				}
			}
			if found {
				t.Errorf("gateSlotEscapeSpellings still probes F at exempt site %q", site)
			}
		}
	}

	// A modifier-block site drops exactly F from the differential set.
	var modifierLeaf *gateLeaf
	for _, g := range enumerateGateLeaves() {
		if _, ok := mixedChildIsAModifierBlock[g.siteKey()]; ok {
			gg := g
			modifierLeaf = &gg
			break
		}
	}
	if modifierLeaf == nil {
		t.Fatalf("no mixedChildIsAModifierBlock site enumerated; the F-exclusion parameter is unexercised")
	}
	withF := gateComparisonSpellings(gateLeaf{multi: true})
	withoutF := gateComparisonSpellings(*modifierLeaf)
	if !modifierLeaf.multi {
		// The recorded site is scalar in today's schema; compare against
		// the scalar set instead so the check follows the site's arity.
		withF = gateComparisonSpellings(gateLeaf{multi: false})
	}
	if len(withoutF) != len(withF)-1 {
		t.Fatalf("modifier site comparison set = %v, want %v minus exactly F-hier-mixed", withoutF, withF)
	}
	for _, n := range withoutF {
		if n == "F-hier-mixed" {
			t.Errorf("modifier site %q still compares F-hier-mixed", modifierLeaf.siteKey())
		}
	}

	// Every differential form has a verdict author, every slot-escape
	// form has an escape author, and no name is duplicated.
	seen := map[string]bool{}
	for _, f := range gateSpellingForms() {
		if seen[f.name] {
			t.Errorf("duplicate spelling name %q in the shared table", f.name)
		}
		seen[f.name] = true
		if f.slotEscapeOnly && f.verdict != nil {
			t.Errorf("spelling %q is slotEscapeOnly but carries a verdict author", f.name)
		}
		if !f.slotEscapeOnly && f.verdict == nil {
			t.Errorf("spelling %q has no verdict author; the differential would score a phantom verdict", f.name)
		}
		if f.differentialOnly && f.escape != nil {
			t.Errorf("spelling %q is differentialOnly but carries an escape author", f.name)
		}
		if !f.differentialOnly && f.escape == nil {
			t.Errorf("spelling %q has no escape author; the slot-escape sweep cannot probe it", f.name)
		}
	}

	// Comparison-set membership is exactly the table minus the
	// documented per-gate parameters — sorted equality, so a future
	// row cannot appear in one gate's set without the other's.
	var tableDiff []string
	for _, f := range gateSpellingForms() {
		if !f.slotEscapeOnly {
			tableDiff = append(tableDiff, f.name)
		}
	}
	sort.Strings(tableDiff)
	sortedMulti := append([]string{}, multi...)
	sort.Strings(sortedMulti)
	if len(sortedMulti) != len(tableDiff) {
		t.Fatalf("multi set %v != shared differential names %v", multi, tableDiff)
	}
	for i := range tableDiff {
		if sortedMulti[i] != tableDiff[i] {
			t.Fatalf("multi set %v != shared differential names %v", multi, tableDiff)
		}
	}
}

// TestSpellingVerdictsComputedOnce17191 asserts the #17191 counter
// criterion: spellingVerdicts runs once per (leaf, pair) per package
// run, however many gates ask for it.
func TestSpellingVerdictsComputedOnce17191(t *testing.T) {
	resetSpellingVerdictCacheForTest()
	leaves := enumerateGateLeaves()
	if len(leaves) == 0 {
		t.Fatal("no gate leaves enumerated")
	}
	// Pick the first leaf that gateLeafCompared actually compares, so
	// both the differential-style direct calls and the coverage-style
	// gateLeafCompared calls below exercise a real verdict matrix.
	// gateLeafCompared computes EVERY pair for an uncompared leaf but
	// short-circuits at the first compared pair — so probe with the
	// FIRST pair explicitly and warm every pair before measuring.
	var probe *gateLeaf
	for i := range leaves {
		if gateLeafCompared(leaves[i]) {
			probe = &leaves[i]
			break
		}
	}
	if probe == nil {
		t.Fatal("no compared leaf found; cannot probe the verdict cache")
	}
	pairs := gateValuePairsForLeaf(*probe)
	if len(pairs) == 0 {
		t.Fatal("probe leaf has no value pairs")
	}
	// Warm every pair (gateLeafCompared may have stopped early), then
	// re-asking — directly and via gateLeafCompared — must compute
	// NOTHING new: exactly once per (leaf, pair) per package run.
	for _, vp := range pairs {
		_ = spellingVerdicts(*probe, vp.v1, vp.v2)
	}
	before := spellingVerdictComputationCount()
	if before == 0 {
		t.Fatal("gateLeafCompared computed no verdicts; the cache counter is not wired")
	}
	if before > len(pairs)*4 {
		// Very loose sanity bound: the probe walk visited at most a
		// few leaves before finding a compared one. The exact-once
		// property is asserted by the delta below, not this bound.
		t.Logf("probe walk computed %d verdict maps before the probe leaf", before)
	}
	for _, vp := range pairs {
		a := spellingVerdicts(*probe, vp.v1, vp.v2)
		b := spellingVerdicts(*probe, vp.v1, vp.v2)
		if len(a) == 0 {
			t.Fatalf("empty verdict map for %q pair %s", probe.siteKey(), vp.name)
		}
		for k, va := range a {
			if vb, ok := b[k]; !ok || vb != va {
				t.Fatalf("repeat spellingVerdicts for %q pair %s changed %q: %q vs %q", probe.siteKey(), vp.name, k, va, vb)
			}
		}
		// Differential-style: usable-verdict counting over the shared
		// comparison set must agree with gateLeafCompared's inputs.
		usable := 0
		for _, name := range gateComparisonSpellings(*probe) {
			switch a[name] {
			case "keep", "drop":
				usable++
			}
		}
		if usable < 2 && gateLeafCompared(*probe) {
			// Another pair may carry the leaf; only flag if NO pair does.
			anyUsable := false
			for _, vp2 := range pairs {
				s := spellingVerdicts(*probe, vp2.v1, vp2.v2)
				u := 0
				for _, name := range gateComparisonSpellings(*probe) {
					switch s[name] {
					case "keep", "drop":
						u++
					}
				}
				if u >= 2 {
					anyUsable = true
				}
			}
			if !anyUsable {
				t.Errorf("gateLeafCompared(%q) = true but no pair has >=2 usable verdicts", probe.siteKey())
			}
		}
	}
	_ = gateLeafCompared(*probe)
	if after := spellingVerdictComputationCount(); after != before {
		t.Errorf("spellingVerdicts recomputed: %d computations before repeat queries, %d after — want once per (leaf, pair)", before, after)
	}
}
