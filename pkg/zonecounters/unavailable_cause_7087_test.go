package zonecounters

import (
	"strings"
	"testing"
)

// #7087: the four per-zone counter wire fields had no Go reader, so every
// "not available" rendering collapsed three distinct causes into one sentence.
//
// This file's own doc used to say those causes were "genuinely indistinguishable
// at this layer and naming one would be a guess". That was true only because the
// layout version was never read. It carries the answer, and with it all three
// causes are KNOWN — none is a guess.
//
// The table is total over the (layoutVersion, overflowActive) product actually
// reachable, and every row asserts a DISTINCT sentence. Asserting only that the
// right cause appears would pass against a function that returned the same
// string for everything and happened to contain every keyword.
func TestUnavailableLineNamesTheCause_7087(t *testing.T) {
	for _, tc := range []struct {
		name          string
		layoutVersion uint32
		overflow      bool
		wantSubstr    string
	}{
		{"old helper, no overflow bit", 0, false, "predates per-zone accounting"},
		// ORDER GUARD. An old helper publishes no overflow bit either, so if the
		// overflow check ran first this row would render "slot capacity
		// EXHAUSTED" — a WRONG and ACTIONABLE diagnosis, which is worse than an
		// ambiguous one. It is the row most likely to be broken by a later edit
		// that reorders the switch for readability.
		{"old helper AND overflow set", 0, true, "predates per-zone accounting"},
		{"current helper, slots exhausted", 2, true, "EXHAUSTED"},
		{"current helper, room, nothing recorded", 2, false, "the zone is idle"},
		// The caller that CANNOT read a status at all — cmd/cli, which is
		// dependency-free of pkg/dataplane by design. It must get the ambiguous
		// line, because for it the three causes really are indistinguishable.
		{"no status readable", LayoutVersionUnknown, false, "helper predates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := UnavailableLineFor(tc.layoutVersion, tc.overflow)
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("layoutVersion=%d overflow=%v rendered the wrong cause.\n got: %s\nwant substring: %q",
					tc.layoutVersion, tc.overflow, got, tc.wantSubstr)
			}
		})
	}

	// DISTINCTNESS. The point of the change is that an operator can tell the
	// causes apart, so the four reachable renderings must be four different
	// strings. Without this, a refactor that collapsed two arms would satisfy
	// every row above that happens to share a keyword.
	seen := map[string]string{}
	for _, c := range []struct {
		label string
		line  string
	}{
		{"pre-dating helper", UnavailableLineFor(0, false)},
		{"overflow", UnavailableLineFor(2, true)},
		{"idle", UnavailableLineFor(2, false)},
		{"unknown/no status", UnavailableLineFor(LayoutVersionUnknown, false)},
	} {
		if prev, dup := seen[c.line]; dup {
			t.Errorf("%q and %q render the SAME sentence, so an operator cannot "+
				"tell them apart — which is the whole of #7087:\n  %s", prev, c.label, c.line)
		}
		seen[c.line] = c.label
	}
}

// The sentinel must NOT be a value the wire can carry. 0 means "pre-#3651
// helper"; if LayoutVersionUnknown were 0, a caller that merely failed to read a
// status would be reported as running an old helper — a confident wrong answer
// manufactured by the shim, and the exact conflation this issue is about.
func TestLayoutVersionUnknownIsNotAWireValue_7087(t *testing.T) {
	if LayoutVersionUnknown == 0 {
		t.Fatal("LayoutVersionUnknown is 0, which is a MEANINGFUL wire value " +
			"(absent field = pre-#3651 helper). A caller that could not read a status " +
			"would then be indistinguishable from one reporting an old helper")
	}
	if UnavailableLineFor(LayoutVersionUnknown, false) == UnavailableLineFor(0, false) {
		t.Error("a caller with NO status renders the same sentence as one reporting a " +
			"pre-#3651 helper; those are different states and the operator is told the " +
			"same thing about both")
	}
}

// The pre-#7087 entry point must keep compiling and must keep its old meaning
// for callers that have only the overflow bit — otherwise this change is a
// silent behaviour edit at every call site that was not updated.
func TestUnavailableLineDelegatesUnchanged_7087(t *testing.T) {
	if UnavailableLine(true) != UnavailableLineFor(LayoutVersionUnknown, true) {
		t.Error("UnavailableLine(true) no longer matches its delegation target")
	}
	if !strings.Contains(UnavailableLine(true), "EXHAUSTED") {
		t.Error("UnavailableLine(true) lost the #6845 overflow specialisation")
	}
	if !strings.Contains(UnavailableLine(false), "helper predates") {
		t.Error("UnavailableLine(false) lost the generic three-cause line")
	}
}

// #14619: the decisive Go half. A CURRENT helper (layout version 1, the
// ZONE_COUNTER_LAYOUT_VERSION the Rust helper stamps) with no row for a
// zone and no overflow must render the IDLE line — never "upgrade the
// helper". Pre-fix the Rust publisher stamped 0 in exactly this state, so
// this row was unreachable from a current helper; it pins the contract
// the publisher now honours.
func TestUnavailableLineForCurrentVersionNoRowIsIdle_14619(t *testing.T) {
	got := UnavailableLineFor(1, false)
	if !strings.Contains(got, "the zone is idle") {
		t.Errorf("current-version, no-row, no-overflow rendered %q; want the idle line", got)
	}
	if strings.Contains(got, "upgrade the helper") {
		t.Errorf("current-version helper told to upgrade itself: %q (#14619)", got)
	}
	// Overflow with a current version stays the actionable overflow line,
	// distinct from idle (per-zone slotted refinement is #14619 follow-up
	// scope documented in zonecounters.go; the global bit must not regress
	// to idle or to the upgrade line).
	ov := UnavailableLineFor(1, true)
	if !strings.Contains(ov, "EXHAUSTED") || strings.Contains(ov, "upgrade the helper") {
		t.Errorf("current-version overflow rendered %q; want EXHAUSTED, not upgrade", ov)
	}
}

// #14619 overflow refinement: with >63 configured zones the global
// overflow bit is set, but a SLOTTED zone with no row is idle — it must
// not be told it is "not being counted at all". Only a non-slotted zone
// under overflow gets the EXHAUSTED line.
func TestUnavailableLineForZoneSplitsSlottedIdleFromOverflow_14619(t *testing.T) {
	slottedIdle := UnavailableLineForZone(1, true, true)
	if !strings.Contains(slottedIdle, "the zone is idle") {
		t.Errorf("slotted zone under overflow rendered %q; want idle", slottedIdle)
	}
	if strings.Contains(slottedIdle, "not being counted") {
		t.Errorf("slotted zone told it is uncounted: %q (#14619)", slottedIdle)
	}
	unslotted := UnavailableLineForZone(1, true, false)
	if !strings.Contains(unslotted, "EXHAUSTED") {
		t.Errorf("unslotted zone under overflow rendered %q; want EXHAUSTED", unslotted)
	}
	// No overflow, not slotted (e.g. pre-#14619 helper omits the set):
	// idle, never a manufactured "uncounted".
	noOverflow := UnavailableLineForZone(1, false, false)
	if !strings.Contains(noOverflow, "the zone is idle") {
		t.Errorf("no-overflow unslotted rendered %q; want idle", noOverflow)
	}
	// Version still wins over slot claims from a stale/mixed status.
	if got := UnavailableLineForZone(0, true, true); !strings.Contains(got, "predates per-zone accounting") {
		t.Errorf("version-0 with slotted=true rendered %q; want pre-dating helper", got)
	}
	// Unknown (no status) delegates exactly, ignoring the slot claim.
	if got := UnavailableLineForZone(LayoutVersionUnknown, false, true); got != UnavailableLineFor(LayoutVersionUnknown, false) {
		t.Errorf("unknown-version slotted rendered %q; want generic delegation", got)
	}
}
