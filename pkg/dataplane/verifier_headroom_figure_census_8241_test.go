package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #8241: a verifier-headroom figure must carry either the COMMIT it was measured
// at or the FLOOR it is measured against. Bare figures satisfying neither rot
// silently, and this has now recurred three times independently:
//
//   - #7494's table read 777,901 / 22.21% measured at 9e28d1c25, while the object
//     was 801,448 / 19.86%;
//   - verify_userspace_shim.go and README.md carried 784,175 / 21.58%, stale by
//     17,273;
//   - docs/log/6886.md corrected ITSELF the same day: "the slack figure first
//     recorded here was stale on arrival. #7720 raised the floor to 15% while this
//     work was in flight and I merged master in without re-reading my own sentence."
//
// THE MEASUREMENT WAS NEVER MISSING. docs/log/6886.md:31 has recorded
// 784,175 -> 801,448 all along. The failure is that the measurement did not
// PROPAGATE out of the log, which is why this is a census and not a campaign of
// corrected sentences: the correct sentence already existed one directory over.
//
// WHY A DATE IS NOT ENOUGH, and it is not hypothetical. README.md's #6884 block
// said "Re-measured 2026-08-27" and gave 784,175 / 21.58%. Commit eaf589bac landed
// the SAME DAY and moved the object to 801,448 / 19.86%. So that date names two
// different budgets and a reader cannot tell which. It now cites 3cfca758e.
//
// SCOPE. Deliberately narrow, and NOT by the word "headroom". A census over bare
// "headroom" is disproportionate and fires on unrelated senses that are numerous
// and correct -- ECN/WRED buffer headroom, CPU headroom, latency-budget headroom,
// pkg/ddns's protocol margin. Measured: a naive scan flagged 47 sites, almost all
// session-count caps, bps conversions and review archives. This walks the NORMATIVE
// texts only -- the ones a reader consults to learn the CURRENT budget. Archives
// (docs/log, docs/reviews, docs/pr, docs/research, _Log.md) are dated by
// construction and are records of the past, not claims about now.

var headroomCensusFiles = []string{
	"pkg/dataplane/verify_userspace_shim.go",
	"pkg/dataplane/README.md",
	"cmd/shimverify/main.go",
	"userspace-xdp/src/lib.rs",
	"docs/afxdp-packet-processing.md",
	"docs/userspace-dataplane-architecture.md",
	"scripts/build-userspace-xdp.sh",
	"Makefile",
	"CLAUDE.md",
}

var (
	// Processed-instruction counts for THIS object: 700,000-999,999, written
	// with or without a comma, plus approximate `~NNNk` shorthand. Narrow on purpose
	// -- it is the range the shim has occupied, so a session cap or bps conversion
	// does not match. Deliberately exclude 1,000,000 and 1,000,001: those are the
	// kernel cap and reject boundary, constants rather than measurements of our
	// object. Including them flagged a #7494 matrix row that records WHICH SHAPES
	// the verifier rejected. A constant cannot rot.
	headroomInsnFigure = regexp.MustCompile(`\b(?:7|8|9)\d{2},?\d{3}\b|~\d{3}k`)
	headroomPctFigure  = regexp.MustCompile(`\b\d{1,2}\.\d{1,2}%|\b\d{1,2}%`)
	// Deliberately does NOT include a bare "headroom": that is the over-scoping the
	// issue warns about, and the control cell below proves it — an ECN/WRED line
	// reading "keeps 12% headroom before WRED engages" was flagged by the first
	// version of this pattern. The marker has to be VERIFIER-specific.
	headroomContext   = regexp.MustCompile(`(?i)processed insn|\binsns\b|shimverify|verifier|#1864|#4555|1,000,000|1,000,001|850,000`)
	headroomCommitSha = regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)
	// "floor", or 850,000 -- the install-blocking ceiling stated absolutely. A
	// figure that names it IS measured against the floor; requiring the word as
	// well would reject the one paragraph that explains what the floor is.
	headroomFloorWord = regexp.MustCompile(`(?i)floor|850,000`)
)

// headroomCensusAccepted maps a distinctive SUBSTRING of an accepted line to the
// reason it is exempt. Keyed on content rather than on file:line BECAUSE LINE
// NUMBERS ROT EXACTLY LIKE THE FIGURES THIS CENSUS EXISTS TO CATCH -- pinning them
// would reproduce the defect inside the guard.
//
// Every entry is a claim and owes its reason here. All of these are correctly
// HISTORICAL: they record what a past tree cost, and are supposed to be a number
// from the past.
var headroomCensusAccepted = map[string]string{
	// Keyed WITHOUT the trailing word: cmd/shimverify writes it inside a Go format
	// string as "0.92%%", so "0.92% headroom" matched the prose sites and missed
	// the two code ones.
	"0.92%": "#4555's motivating history -- master sat here with every gate green, " +
		"which is the whole reason the floor exists. A number from the past, on purpose.",
	"990,796": "pre-#4555 master, the same motivating history as 0.92%.",
	// Keyed on the table's ROW SHAPE rather than on any one number, so a new row
	// of the same experiment is covered without another content pin — the thing
	// this census exists to discourage.
	"| PASS |": "a row of the #4555 bound-experiment series. The table's own preamble " +
		"says its absolute counts are a snapshot of a tree that has since moved by " +
		"~206k insns and that only its COUPLINGS still hold, so every row is " +
		"provenance-bearing by construction.",
	"5.3% headroom": "the wide-set outcome of that same #4555 bound experiment.",
	"947,188 insns with and without it": "a DIFFERENTIAL, not a level. The claim is that " +
		"the facts section costs zero budget, proven by both sides being equal; the " +
		"absolute is incidental and the claim cannot rot, because zero stays zero.",
	"~186k": "the 3% floor's historical slack delta in verify_userspace_shim.go and " +
		"README.md, not an absolute measurement of the object's verifier cost.",
	"~206k insns": "the README's historical #4555 tree-to-tree movement; it is a " +
		"differential explaining that the absolute table values are stale.",
	"3.8-6.1%": "historical guest-kernel versus build-host verifier charge variation " +
		"from #15645/#15854, not a headroom verdict for this object.",
	"773,966": "docs/userspace-dataplane-architecture.md, scoped to what #304 cost. " +
		"Past-tense by construction -- the model this census holds everything else to.",
}

func headroomRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}

// headroomCensusViolations returns one entry per undated, unfloored, unaccepted
// verifier-headroom figure in the normative texts.
//
// EXTRACTED so the guard is itself testable -- a census that has only ever run
// against the current tree is indistinguishable from one that always returns nil.
func headroomCensusViolations(root string, accepted map[string]string) (viol []string, matchedAccepted map[string]bool, scanned int) {
	matchedAccepted = map[string]bool{}
	for _, rel := range headroomCensusFiles {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a renamed normative text is caught by the coverage cell below
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			lowerLine := strings.ToLower(line)
			hasHeadroom := strings.Contains(lowerLine, "headroom")
			// The word can wrap onto the line immediately before or after the
			// percentage; treat each adjacent pair as a two-line window.
			if !hasHeadroom && i > 0 {
				hasHeadroom = strings.Contains(strings.ToLower(lines[i-1]), "headroom")
			}
			if !hasHeadroom && i+1 < len(lines) {
				hasHeadroom = strings.Contains(strings.ToLower(lines[i+1]), "headroom")
			}
			isFigure := headroomInsnFigure.MatchString(line) ||
				(headroomPctFigure.MatchString(line) && hasHeadroom)
			if !isFigure {
				continue
			}
			near := strings.Join(lines[max0(i-4):min0(i+5, len(lines))], "\n")
			if !headroomContext.MatchString(near) {
				continue
			}
			scanned++
			// A markdown sentence wraps, so the distinctive substring can sit on the
			// line above or below the figure. Match over a one-line window.
			window := strings.Join(lines[max0(i-1):min0(i+2, len(lines))], "\n")
			var acceptedBy string
			for sub := range accepted {
				if strings.Contains(window, sub) {
					acceptedBy = sub
					break
				}
			}
			if acceptedBy != "" {
				matchedAccepted[acceptedBy] = true
				continue
			}
			// TIGHT window, and the mutation is why. At +-8 lines the census PASSED
			// the exact site #8241 names: verify_userspace_shim.go's block DISCUSSES
			// the 15% floor at length ("a floor set too high is an announced detour"),
			// so the bare figure inherited a "floor" from prose eight lines away and
			// the guard reported healthy on the defect it was written for.
			//
			// The property is that the figure carries the commit it was measured at
			// or the floor it is measured AGAINST — an attribute of the figure, not of
			// the paragraph. So the evidence must sit with the figure: same line, or
			// the wrapped continuation either side of it.
			ctx := strings.Join(lines[max0(i-1):min0(i+2, len(lines))], "\n")
			if headroomCommitSha.MatchString(ctx) || headroomFloorWord.MatchString(ctx) {
				continue
			}
			viol = append(viol, fmt.Sprintf("%s:%d: %q carries neither a commit nor a named floor",
				rel, i+1, strings.TrimSpace(line)))
		}
	}
	return viol, matchedAccepted, scanned
}

func max0(i int) int {
	if i < 0 {
		return 0
	}
	return i
}
func min0(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestVerifierHeadroomFiguresCarryACommitOrAFloor_8241(t *testing.T) {
	root := headroomRepoRoot(t)
	viol, matched, scanned := headroomCensusViolations(root, headroomCensusAccepted)

	// Degeneracy guard: FAIL, do not skip. A census that scanned nothing looks
	// identical to one that found nothing, and the second is the answer we want.
	if scanned == 0 {
		t.Fatal("the census matched no verifier-headroom figure at all — the normative " +
			"file list or the figure pattern has stopped matching, so this cell measured nothing")
	}
	t.Logf("#8241 census: %d verifier-headroom figures in %d normative texts, "+
		"%d accepted entries matched", scanned, len(headroomCensusFiles), len(matched))

	if len(viol) > 0 {
		t.Errorf("verifier-headroom figures that will rot silently (%d):\n  %s\n\n"+
			"Each must carry EITHER the commit it was measured at (a dated record that "+
			"cannot rot) OR the floor it is measured against (so the reader computes "+
			"against the ceiling that actually blocks an install — 15%%, i.e. ~850,000 — "+
			"rather than the 1,000,000 kernel cap). A shape that fits under the cap can "+
			"still be unshippable. If the figure is legitimately historical, add it to "+
			"headroomCensusAccepted WITH ITS REASON.",
			len(viol), strings.Join(viol, "\n  "))
	}

	// DEAD-ENTRY REJECTION: the accepted list is a queue, not a permission slip.
	// An entry that no longer matches a real line is a claim about code that has
	// moved on, and it must fail rather than sit there granting nothing.
	for sub := range headroomCensusAccepted {
		if !matched[sub] {
			t.Errorf("accepted-list entry %q matches no line in the normative texts — "+
				"the site it exempted has been changed or removed, so the exemption is "+
				"stale. Delete the entry.", sub)
		}
	}
}

// The census must be able to fail, and on the shape that actually recurs: a fresh
// bare figure, correct on the day it is written.
func TestHeadroomCensusDetectsABareFigure_8241(t *testing.T) {
	dir := t.TempDir()
	writeAt := func(rel, body string) {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A bare figure with neither a commit nor a floor: the recurrence shape.
	writeAt("pkg/dataplane/README.md",
		"# x\n\nThe shim sits at 801,448 processed insns, 19.86% headroom.\n")
	viol, _, scanned := headroomCensusViolations(dir, map[string]string{})
	if scanned == 0 {
		t.Fatal("the synthetic fixture matched no figure — the cell is testing nothing")
	}
	if len(viol) == 0 {
		t.Fatal("the census passed a BARE figure with neither a commit nor a floor — " +
			"the exact shape that has rotted three times")
	}

	// The same figure with a commit must pass...
	writeAt("pkg/dataplane/README.md",
		"# x\n\nAt 3cfca758e the shim sat at 801,448 processed insns, 19.86% headroom.\n")
	if v, _, _ := headroomCensusViolations(dir, map[string]string{}); len(v) != 0 {
		t.Errorf("the census rejected a figure that DOES carry its commit, so a real "+
			"violation could not be told from a false alarm: %v", v)
	}

	// ...and so must the same figure against a named floor.
	writeAt("pkg/dataplane/README.md",
		"# x\n\nThe shim sits at 801,448 insns, 19.86% headroom against the 15.0% floor.\n")
	if v, _, _ := headroomCensusViolations(dir, map[string]string{}); len(v) != 0 {
		t.Errorf("the census rejected a figure measured against a named floor: %v", v)
	}
}

func writeHeadroomCensusREADME(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg", "dataplane", "README.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestHeadroomCensusDetectsUncommaedFigure_17245(t *testing.T) {
	dir := writeHeadroomCensusREADME(t, "# x\n\nThe verifier reported 963340 processed insns.\n")
	viol, _, scanned := headroomCensusViolations(dir, map[string]string{})
	if scanned == 0 {
		t.Fatal("the uncommaed verifier figure was not scanned")
	}
	if len(viol) == 0 {
		t.Fatal("the census passed an unfloored, uncommitted uncommaed verifier figure")
	}
}

func TestHeadroomCensusDetectsPercentWithWrappedHeadroom_17245(t *testing.T) {
	dir := writeHeadroomCensusREADME(t, "# x\n\nThe verifier reported 3.67%\nheadroom.\n")
	viol, _, scanned := headroomCensusViolations(dir, map[string]string{})
	if scanned == 0 {
		t.Fatal("the percentage with wrapped headroom was not scanned")
	}
	if len(viol) == 0 {
		t.Fatal("the census passed a percent figure whose headroom marker is on the next line")
	}
}

func TestHeadroomCensusDetectsApproximateFigure_17245(t *testing.T) {
	dir := writeHeadroomCensusREADME(t, "# x\n\nThe verifier measured ~816k processed insns.\n")
	viol, _, scanned := headroomCensusViolations(dir, map[string]string{})
	if scanned == 0 {
		t.Fatal("the approximate verifier figure was not scanned")
	}
	if len(viol) == 0 {
		t.Fatal("the census passed an unfloored, uncommitted approximate verifier figure")
	}
}

func TestHeadroomCensusAcceptsHistoricalDeltas_17245(t *testing.T) {
	for _, tc := range []struct {
		name, body, accepted string
	}{
		{
			"floor-sensitivity delta",
			"# x\n\nAt 21.58% the old constant admitted ~186k insns.\n",
			"~186k",
		},
		{
			"tree-to-tree delta",
			"# x\n\nThe table is a snapshot of a tree moved by ~206k insns.\n",
			"~206k insns",
		},
		{
			"kernel charge variation",
			"# x\n\nThe verifier on guest kernels charges 3.8-6.1% more than the build host; " +
				"that can overstate deploy headroom.\n",
			"3.8-6.1%",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeHeadroomCensusREADME(t, tc.body)
			accepted := map[string]string{tc.accepted: headroomCensusAccepted[tc.accepted]}
			viol, matched, scanned := headroomCensusViolations(dir, accepted)
			if scanned == 0 {
				t.Fatal("the historical figure was not scanned")
			}
			if len(viol) != 0 || !matched[tc.accepted] {
				t.Fatalf("historical figure was not accepted by %q: violations=%v matched=%v",
					tc.accepted, viol, matched)
			}
		})
	}
}

// Control cells for the exclusions. An allowlist entry is a claim and owes a test,
// so each exclusion appears here as a green cell rather than as a silent skip.
func TestHeadroomCensusExcludesUnrelatedSenses_8241(t *testing.T) {
	dir := t.TempDir()
	mk := func(body string) []string {
		p := filepath.Join(dir, "pkg", "dataplane")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "README.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		v, _, _ := headroomCensusViolations(dir, map[string]string{})
		return v
	}
	for _, tc := range []struct{ name, body string }{
		{"ECN/WRED buffer headroom", "# x\n\nThe queue keeps 12% headroom before WRED engages.\n"},
		{"a session-count cap", "# x\n\n`defaultSessionCountCap` = 1,000,000 matching rows.\n"},
		{"a bps conversion", "# x\n\n\"1m\" = 1,000,000 bps = 125,000 bytes/s.\n"},
	} {
		if v := mk(tc.body); len(v) != 0 {
			t.Errorf("%s was flagged as a verifier-headroom figure — the census is "+
				"over-scoped and will be switched off: %v", tc.name, v)
		}
	}
}
