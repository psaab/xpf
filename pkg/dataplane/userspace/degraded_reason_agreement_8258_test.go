package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #8258 point 2 — the drop/permit verdict pair, asserted as an AGREEMENT.
//
// THE PAIR. The retained AF_XDP shim decides a degraded-path disposition and
// records it by INDEX into a per-CPU array (`USERSPACE_FALLBACK_REASON_*`,
// userspace-xdp/src/lib.rs). Go reads that array and renders each slot's count
// under a name from `degradedPathReasonNames`. Three of those slots are
// literally drop/permit verdicts — `transit_drop`, `strict_drop`,
// `pass_to_kernel` — so an operator diagnosing "why is traffic disappearing"
// reads this mapping and nothing else.
//
// The two sides are joined by an INDEX, and the only thing asserting they agree
// was a comment: "Must stay in sync with USERSPACE_FALLBACK_REASON_* in
// userspace-xdp/src/lib.rs".
//
// WHY THE EXISTING GUARD CANNOT SEE A DIVERGENCE.
// `TestDegradedPathReasonNamesCoverRetainedShimActions` pins the GO side to a
// hand-written list of twelve names and a length of 17. It never reads the
// shim. So it is green through both failures that actually happen:
//
//   1. a reason ADDED in Rust (index 17, MAX -> 18) leaves the Go array at 17,
//      the length check still passes against its own literal 17, and
//      `readDegradedPathStatsLocked` — which loops to `len(...)` — never reads
//      the new counter at all. The disposition exists, is counted in the
//      kernel, and is invisible;
//   2. a reason INSERTED in the middle renumbers every constant above it. The
//      Go array keeps the old order, all twelve names are still present, the
//      length is still 17, no slot is empty — and every reason above the
//      insertion point is now rendered under the WRONG NAME. An operator
//      reading `transit_drop` is shown `strict_drop`'s count.
//
// The second is the dangerous one, and it is exactly the #6534 shape: a surface
// presenting a value it did not compute, with no way to notice it is presenting
// someone else's.
//
// THE PREDICATE, per #8258: assert the AGREEMENT, never pin either surface to a
// heuristic. A heuristic encodes which side is trusted, and the failure being
// guarded is precisely that the sides disagreed. So this reads the shim's
// constants and requires the Go table to match them index for index — which is
// also SELF-MAINTAINING in the direction that matters: adding a reason in Rust
// enrols it here automatically, and the build stays red until Go carries it.
//
// This extracts a CONSTANT LIST, which is a syntactic fact, and does not model
// the shim's behaviour — the distinction the #4555 parity corpus draws after
// five successive models leaked. There is nothing here to get subtly wrong: a
// `const NAME: u32 = N;` either is present with that value or is not.

var shimFallbackReasonRe = regexp.MustCompile(
	`(?m)^const USERSPACE_FALLBACK_REASON_([A-Z0-9_]+): u32 = (\d+);`)

// shimFallbackReasons returns reason name (lowercased, no prefix) by index,
// plus the value of the _MAX bound.
func shimFallbackReasons(t *testing.T) (map[int]string, int) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shim source at %s: %v", path, err)
	}
	byIndex := map[int]string{}
	max := -1
	for _, m := range shimFallbackReasonRe.FindAllStringSubmatch(string(src), -1) {
		name, valueText := m[1], m[2]
		value, err := strconv.Atoi(valueText)
		if err != nil {
			t.Fatalf("reason %s has a non-numeric value %q", name, valueText)
		}
		if name == "MAX" {
			max = value
			continue
		}
		if prior, dup := byIndex[value]; dup {
			t.Fatalf("the shim assigns index %d to BOTH %s and %s — two "+
				"dispositions counting into one slot, so their totals are "+
				"indistinguishable at every surface", value, prior, strings.ToLower(name))
		}
		byIndex[value] = strings.ToLower(name)
	}
	return byIndex, max
}

// The agreement itself.
func TestDegradedPathReasonNamesAgreeWithTheShim_8258(t *testing.T) {
	byIndex, max := shimFallbackReasons(t)

	// POSITIVE CONTROL, first. A regex that has stopped matching finds nothing,
	// compares nothing to nothing, and passes forever — which is the failure
	// mode a census is least able to notice about itself, because the census is
	// what you would consult to find it.
	if len(byIndex) < 10 {
		t.Fatalf("the shim scan found only %d reason constants (%v). The "+
			"pattern has rotted or the file moved: this test is asserting "+
			"agreement between the Go table and an empty set", len(byIndex), byIndex)
	}
	if max <= 0 {
		t.Fatalf("USERSPACE_FALLBACK_REASON_MAX was not found in the shim " +
			"source, so the array-length agreement below is unanchored")
	}

	if got := len(degradedPathReasonNames); got != max {
		t.Fatalf("degradedPathReasonNames has %d slots but the shim's "+
			"USERSPACE_FALLBACK_REASON_MAX is %d.\n"+
			"The Go side sizes the per-CPU array read AND the render loop from "+
			"len(degradedPathReasonNames), so a shim with more reasons than Go "+
			"has slots means the extra dispositions are counted in the kernel "+
			"and never read — a drop reason that exists, fires, and is "+
			"invisible at every operator surface (#8258)", got, max)
	}

	for index, want := range byIndex {
		if index >= len(degradedPathReasonNames) {
			t.Errorf("the shim defines reason %q at index %d, beyond the Go "+
				"table's %d slots", want, index, len(degradedPathReasonNames))
			continue
		}
		if got := degradedPathReasonNames[index]; got != want {
			t.Errorf("index %d: the shim calls this %q, Go renders it as %q.\n"+
				"The two sides are joined by INDEX, so a renumbering on one "+
				"side does not fail loudly — it re-labels every slot above it, "+
				"and an operator reading a drop reason is shown a different "+
				"disposition's count (#8258/#6534)", index, want, got)
		}
	}

	for index, name := range degradedPathReasonNames {
		if _, ok := byIndex[index]; !ok {
			t.Errorf("Go renders index %d as %q but the shim defines no reason "+
				"there — the slot's count is whatever the kernel left in it, "+
				"presented under a name nothing produces", index, name)
		}
	}
}

// The sibling that the agreement above makes possible: every reason the shim
// DEFINES must also be USED, or the table carries a row for a disposition that
// cannot occur.
//
// Deliberately a separate cell. An unused constant is a much weaker fault than a
// mislabelled one — `readDegradedPathStatsLocked` omits zero-count entries, so a
// dead reason never actually reaches an operator, and stating otherwise would
// overclaim. What it misleads is the READER of the table, who reasonably
// concludes the shim has a disposition it does not. Folding the two cells
// together would mean one failure could not be told from the other.
//
// TWO ACCEPTED ENTRIES, with reasons — the shape #8258 asks for where a pair
// genuinely cannot agree, rather than a silent omission. Both are residue: the
// constant outlived the code that passed it.
//
//   - `icmp` — the shim's ICMP fallback was removed by `13241e75e`
//     ("remove ICMP fallback from XDP shim and create outer GRE sessions");
//   - `no_session` — removed by `324d6b9d1` ("eliminate nearly all eBPF
//     fallbacks from userspace dataplane").
//
// They are left in place rather than deleted on purpose: removing them
// renumbers every constant above, which is precisely the hazard the agreement
// cell above exists to catch. That is a deliberate change someone should make
// with the guard in place, not a tidy-up folded into the guard's own landing.
//
// The allowlist carries its own DEAD-ENTRY CHECK, because an allowlist entry is
// a claim and owes a test: if one of these is wired up again, the entry is stale
// and this cell reds rather than silently excusing a live reason from the
// coverage it now belongs in.
func TestEveryShimFallbackReasonIsActuallyReachable_8258(t *testing.T) {
	knownUnused := map[string]string{
		"icmp":       "ICMP fallback removed by 13241e75e; constant outlived its use",
		"no_session": "session fallback removed by 324d6b9d1; constant outlived its use",
	}

	byIndex, _ := shimFallbackReasons(t)
	path := filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shim source: %v", err)
	}
	text := string(src)

	for index, name := range byIndex {
		constName := "USERSPACE_FALLBACK_REASON_" + strings.ToUpper(name)
		// One occurrence is the declaration itself; a reason never passed to
		// anything has exactly that one.
		used := strings.Count(text, constName) >= 2
		reason, excused := knownUnused[name]

		if !used && !excused {
			t.Errorf("reason %q (index %d) is declared and never used, so the "+
				"Go table carries a row for a disposition this shim cannot "+
				"produce. Either wire it up or record it in knownUnused with "+
				"the commit that removed its use", name, index)
		}
		if used && excused {
			t.Errorf("reason %q is in knownUnused (%q) but IS used in the shim. "+
				"The entry is stale, and while it stands this reason is "+
				"excused from a coverage check it now belongs in — an "+
				"allowlist entry is a claim and this is the test it owes",
				name, reason)
		}
	}

	// The allowlist must not name reasons the shim no longer defines at all: a
	// stale key would sit here forever excusing nothing and reading as though
	// the population were larger than it is.
	defined := map[string]bool{}
	for _, name := range byIndex {
		defined[name] = true
	}
	for name := range knownUnused {
		if !defined[name] {
			t.Errorf("knownUnused names %q, which the shim does not define. "+
				"Remove the entry — it excuses nothing and overstates the "+
				"population this cell measures", name)
		}
	}
}
