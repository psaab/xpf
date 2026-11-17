package refactoraudit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

// This file holds the HARD half of the #7253 split: a file THE PR TOUCHES
// crossed a modularity threshold.
//
// The property it gates is local and non-perishable. Its verdict is a
// function of (the branch's changed set, each changed file's LOC at the
// merge base, its LOC in the working tree) and NOTHING else — in
// particular not docs/refactoring-audit-current.txt, which is a snapshot
// of a repo-global quantity that any unrelated file can invalidate. So a
// red here names a file the author grew, is reproducible from the
// branch's own diff, and stays true however many sibling PRs land in the
// meantime.
//
// The freshness half — "the committed global snapshot disagrees with the
// tree" — is demoted to TestGlobalHeatmapFreshnessAdvisory (reports, does
// not fail) plus scripts/refactoring-audit-refresh.sh (converges it
// without interrupting anyone). audit_canary_test.go carries the
// measurements that forced the split.

// touchedFile is one audit-eligible path the branch changed, with its LOC
// on both sides of the branch's merge base. It is the parsed form of one
// scripts/refactoring-audit-touched.sh row.
type touchedFile struct {
	path    string
	baseLOC int  // LOC at the merge base; meaningless when isNew
	headLOC int  // LOC in the working tree
	isNew   bool // the branch added the file (absent at the merge base)
}

// crossing is one modularity threshold one touched file crossed.
type crossing struct {
	path    string
	baseLOC int
	headLOC int
	floor   int
	tier    string
}

// thresholdCrossings is the gate's whole decision, as a pure function.
//
// A file crosses when it was BELOW a floor at the branch's merge base and
// is AT OR ABOVE it in the working tree. Both halves matter and each is
// load-bearing in the opposite direction:
//
//   - dropping the base test turns this into "you touched a big file",
//     which reds every PR that edits one line of an existing 2400-line
//     module — the file did not grow past anything, and its author cannot
//     act on the news;
//   - dropping the head test turns it into "you touched a file", full
//     stop.
//
// A file added by the branch is measured from 0, so a new 1600-line file
// crosses (that is the tcp_segmentation.rs case, which was a correct and
// useful catch and is deliberately kept).
//
// Only the HIGHEST floor crossed is reported: 1400 -> 2100 is a
// [REFACTOR] crossing, not a [WATCH] crossing plus a [REFACTOR] one.
// Growth WITHIN a band is not a crossing — "adds >100 LOC to a
// [REFACTOR]-tier file: split before landing" is a real project rule
// (docs/refactoring-audit.md) but it is a review judgement, not this
// gate's business, and #7253 is explicitly about not interrupting people
// with things they cannot act on.
func thresholdCrossings(files []touchedFile) []crossing {
	bands := []struct {
		floor int
		tier  string
	}{
		{refactorFloor, tierRefactor},
		{auditFloor, tierWatch},
	}
	var out []crossing
	for _, f := range files {
		base := f.baseLOC
		if f.isNew {
			base = 0
		}
		for _, band := range bands {
			if base < band.floor && f.headLOC >= band.floor {
				out = append(out, crossing{
					path:    f.path,
					baseLOC: base,
					headLOC: f.headLOC,
					floor:   band.floor,
					tier:    band.tier,
				})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// parseTouched parses scripts/refactoring-audit-touched.sh output:
//
//	<base-LOC|-> <head-LOC> <path>
//
// Fail-closed, like parseHeatmap: any line the script could not have
// produced is a hard failure rather than a skipped row. A skipped row
// reads as "this file did not cross", which is the one answer a broken
// parse must never invent. This is also what turns an audited path
// containing whitespace — which would arrive as four fields — into a loud
// failure instead of a silent mis-parse.
func parseTouched(t *testing.T, what, text string) []touchedFile {
	t.Helper()
	var out []touchedFile
	for i, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s line %d: want 3 fields (baseLOC headLOC path), got %d: %q", what, i+1, len(fields), line)
		}
		f := touchedFile{path: fields[2]}
		if fields[0] == "-" {
			f.isNew = true
		} else {
			n, err := strconv.Atoi(fields[0])
			if err != nil {
				t.Fatalf("%s line %d: base LOC %q is neither an integer nor %q: %v", what, i+1, fields[0], "-", err)
			}
			f.baseLOC = n
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("%s line %d: head LOC %q is not an integer: %v", what, i+1, fields[1], err)
		}
		f.headLOC = n
		out = append(out, f)
	}
	return out
}

// acceptedCrossing is one hand-written entry in
// docs/refactoring-audit-accepted.txt.
type acceptedCrossing struct {
	tier   string
	path   string
	reason string
}

// parseAccepted parses the acknowledgement file. Fail-closed for the same
// reason as everything else here: a line that does not parse must not
// silently become "no acknowledgement" (which would red an author who did
// record their decision) or "acknowledged" (which would silently disarm
// the gate).
func parseAccepted(t *testing.T, what, text string) []acceptedCrossing {
	t.Helper()
	var out []acceptedCrossing
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			t.Fatalf("%s line %d: want '<tier> <path> <reason...>', got %q", what, i+1, line)
		}
		if fields[0] != tierRefactor && fields[0] != tierWatch {
			t.Fatalf("%s line %d: unknown tier tag %q (want %q or %q)", what, i+1, fields[0], tierRefactor, tierWatch)
		}
		out = append(out, acceptedCrossing{
			tier:   fields[0],
			path:   fields[1],
			reason: strings.Join(fields[2:], " "),
		})
	}
	return out
}

// isAccepted reports whether a crossing carries a written acknowledgement.
// A [REFACTOR] acknowledgement implies the [WATCH] one: a file whose
// author accepted it living above 2000 has necessarily accepted it living
// above 1500.
func isAccepted(c crossing, accepted []acceptedCrossing) bool {
	for _, a := range accepted {
		if a.path != c.path {
			continue
		}
		if a.tier == c.tier || a.tier == tierRefactor {
			return true
		}
	}
	return false
}

// readAccepted loads the committed acknowledgement file.
func readAccepted(t *testing.T, root string) []acceptedCrossing {
	t.Helper()
	path := filepath.Join(root, "docs", "refactoring-audit-accepted.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return parseAccepted(t, "docs/refactoring-audit-accepted.txt", string(b))
}

// TestTouchedFileCrossedModularityThreshold is the hard gate.
//
// It asks scripts/refactoring-audit-touched.sh for every audit-eligible
// file this branch changed, with that file's LOC at the branch's merge
// base and in the working tree, and fails naming any file the branch
// itself grew past 1500 or 2000 LOC.
//
// On master the changed set is empty (merge-base(origin/master, HEAD) ==
// HEAD), so this is structurally silent there. That is the point: nobody
// merging is interrupted by it. The author who caused the growth is.
//
// FAIL-ON-REVERT: TestThresholdCrossingCases pins the decision, and
// TestTouchedSetIsLocalToTheBranch pins the changed set the decision runs
// on — with a fixture repo whose committed heatmap is deliberately stale
// on a file the branch never touched, which is the exact situation that
// used to red an innocent author.
//
// If the script cannot determine the changed set (no origin/master, a
// shallow clone, no git at all) it exits non-zero and runScript t.Fatals.
// It must never pass by printing an empty set — see
// TestUndeterminableBaseFailsLoudly.
func TestTouchedFileCrossedModularityThreshold(t *testing.T) {
	root := repoRoot(t)
	testguard.RequireGitCheckout(t, root)
	touched := parseTouched(t, "scripts/refactoring-audit-touched.sh",
		runScript(t, root, "scripts/refactoring-audit-touched.sh"))
	crossings := thresholdCrossings(touched)
	if len(crossings) == 0 {
		return
	}
	accepted := readAccepted(t, root)

	var unacknowledged []crossing
	for _, c := range crossings {
		if !isAccepted(c, accepted) {
			unacknowledged = append(unacknowledged, c)
		}
	}
	if len(unacknowledged) == 0 {
		return
	}

	var msg strings.Builder
	msg.WriteString("this branch grew a file it TOUCHES past a modularity threshold:\n")
	for _, c := range unacknowledged {
		from := strconv.Itoa(c.baseLOC)
		if c.baseLOC == 0 {
			from = "new"
		}
		fmt.Fprintf(&msg, "\n  %s\n      %s -> %d LOC, crossed the %d LOC %s floor\n",
			c.path, from, c.headLOC, c.floor, c.tier)
	}
	msg.WriteString("\nSplit the file before landing (docs/engineering-style.md, " +
		"\"Modularity discipline\"),\nor — if this is one of the documented " +
		"\"When NOT to refactor\" cases — record the\ndecision and its reason in " +
		"docs/refactoring-audit-accepted.txt:\n\n")
	for _, c := range unacknowledged {
		fmt.Fprintf(&msg, "  %s %s <why this file stays whole>\n", c.tier, c.path)
	}
	msg.WriteString("\nThis is measured from YOUR diff against the merge base, not from\n" +
		"docs/refactoring-audit-current.txt. Regenerating that artifact will not\n" +
		"silence this, and it is not your job to regenerate it (#7253).")
	t.Fatal(msg.String())
}

// TestThresholdCrossingCases is the fail-on-revert pin for the hard
// half's decision. Every case is a synthetic touchedFile, so it tests the
// PREDICATE rather than whatever this repo's tree happens to look like
// today.
//
// Each case names the mutation it catches. The boundary pair is the
// sharpest: 1499 -> 1500 must cross and 1500 -> 1501 must not, so
// relaxing `>=` to `>` on the head side, or `<` to `<=` on the base side,
// reds exactly one of them.
func TestThresholdCrossingCases(t *testing.T) {
	cases := []struct {
		name  string
		file  touchedFile
		want  string // "" = no crossing, else the expected tier
		floor int
	}{
		{
			name: "far below the floor on both sides",
			file: touchedFile{path: "a.go", baseLOC: 200, headLOC: 900},
		},
		{
			name:  "grew across the WATCH floor",
			file:  touchedFile{path: "a.go", baseLOC: 1400, headLOC: 1600},
			want:  tierWatch,
			floor: auditFloor,
		},
		{
			name:  "grew across the WATCH floor by exactly one line",
			file:  touchedFile{path: "a.go", baseLOC: 1499, headLOC: 1500},
			want:  tierWatch,
			floor: auditFloor,
			// pkg/dataplane/types.go crossed at exactly 1501 LOC and
			// flipped the OLD global gate for every unrelated author on
			// the board. Under this gate the same event reds exactly one
			// PR: the one that added the line.
		},
		{
			name: "already at the WATCH floor, grew inside the band",
			file: touchedFile{path: "a.go", baseLOC: 1500, headLOC: 1501},
			// catches dropping the base-side test, which would turn this
			// gate into "you touched a big file".
		},
		{
			name:  "grew across the REFACTOR floor",
			file:  touchedFile{path: "a.go", baseLOC: 1999, headLOC: 2000},
			want:  tierRefactor,
			floor: refactorFloor,
		},
		{
			name: "already over REFACTOR, grew a lot",
			file: touchedFile{path: "a.go", baseLOC: 2119, headLOC: 2448},
			// loop_body/mod.rs's real drift. In-band growth is a review
			// judgement, not this gate's business.
		},
		{
			name:  "crossed both floors at once reports the higher one",
			file:  touchedFile{path: "a.go", baseLOC: 1400, headLOC: 2100},
			want:  tierRefactor,
			floor: refactorFloor,
			// catches dropping the `break`: two crossings for one file
			// would report a [WATCH] one nobody needs to act on.
		},
		{
			name:  "a new file lands over the floor",
			file:  touchedFile{path: "a.rs", isNew: true, headLOC: 1582},
			want:  tierWatch,
			floor: auditFloor,
			// tcp_segmentation.rs entering the audit at 1582.
		},
		{
			name: "a new file lands under the floor",
			file: touchedFile{path: "a.rs", isNew: true, headLOC: 900},
		},
		{
			name: "shrank back under the floor",
			file: touchedFile{path: "a.go", baseLOC: 1600, headLOC: 1400},
			// a split PR must not be red for the file it just cut down.
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := thresholdCrossings([]touchedFile{tc.file})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no crossing for base=%d head=%d new=%v, got %+v",
						tc.file.baseLOC, tc.file.headLOC, tc.file.isNew, got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want exactly 1 crossing for base=%d head=%d new=%v, got %d: %+v",
					tc.file.baseLOC, tc.file.headLOC, tc.file.isNew, len(got), got)
			}
			if got[0].tier != tc.want || got[0].floor != tc.floor {
				t.Fatalf("want %s at the %d floor, got %s at %d",
					tc.want, tc.floor, got[0].tier, got[0].floor)
			}
		})
	}
}

// TestCrossingsAreSortedByPath pins the reporting order, so a multi-file
// red reads the same way twice and a reviewer can diff two runs.
func TestCrossingsAreSortedByPath(t *testing.T) {
	got := thresholdCrossings([]touchedFile{
		{path: "z.go", baseLOC: 1400, headLOC: 1600},
		{path: "a.go", baseLOC: 1400, headLOC: 1600},
		{path: "m.go", baseLOC: 1400, headLOC: 1600},
	})
	var paths []string
	for _, c := range got {
		paths = append(paths, c.path)
	}
	want := []string{"a.go", "m.go", "z.go"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("crossings not sorted by path: got %v, want %v", paths, want)
	}
}

// TestTouchedGateIsNotASnapshotCompare is the deliverable that makes the
// #7253 split real rather than cosmetic.
//
// The failure this fixes was ONE assertion answering two questions. If
// the new hard gate were "the old snapshot compare, restricted to touched
// files", the old shape would survive inside the new one and would drift
// back the first time someone widened the restriction. So the gate has to
// be a DIFFERENT predicate, and the proof is that it disagrees with the
// snapshot compare in BOTH directions on the same input:
//
//	world A: the committed snapshot is stale on a file the branch never
//	touched. Snapshot compare: RED. Touched gate: green. => the touched
//	gate is not a snapshot compare AND is not implied by one.
//
//	world B: the committed snapshot is perfectly fresh, and the branch
//	grew a file it touches across a floor with the artifact already
//	recording the new tier. Snapshot compare: GREEN. Touched gate: RED.
//	=> the touched gate is not derivable from any snapshot compare, not
//	even a restricted one: there is no drift to restrict.
//
// World B is the decisive half. A snapshot compare cannot produce that
// red at all, because the artifact and the tree agree; only the branch's
// own diff carries the fact that the growth was this author's.
//
// The rival mechanism here is heatmapDrift, the actual function
// TestGlobalHeatmapFreshnessAdvisory runs against the real artifact — not
// a strawman written for this test.
func TestTouchedGateIsNotASnapshotCompare(t *testing.T) {
	const (
		untouched = "pkg/somebody/else.go" // grown by a sibling PR
		mine      = "pkg/mine/grew.go"     // grown by this branch
	)

	t.Run("stale snapshot on an untouched file reds only the snapshot compare", func(t *testing.T) {
		// The tree audits both files; the committed artifact predates the
		// sibling's growth and knows only about `mine`.
		committed := map[string]string{mine: tierWatch}
		generated := map[string]string{mine: tierWatch, untouched: tierWatch}

		drift := heatmapDrift(committed, generated)
		if drift.empty() {
			t.Fatal("fixture is wrong: the snapshot compare must be RED here, " +
				"otherwise this proves nothing about the two mechanisms disagreeing")
		}

		// This branch's own diff: it touched `mine` and moved it 20 lines
		// inside its band. It never touched `untouched`.
		crossings := thresholdCrossings([]touchedFile{
			{path: mine, baseLOC: 1600, headLOC: 1620},
		})
		if len(crossings) != 0 {
			t.Fatalf("the touched gate must be silent when the stale row belongs to a file "+
				"this branch never touched; got %+v", crossings)
		}
	})

	t.Run("fresh snapshot cannot see a crossing the branch caused", func(t *testing.T) {
		// The artifact is perfectly fresh: it already records `mine` at
		// [WATCH], exactly as a regeneration at this tree would emit.
		committed := map[string]string{mine: tierWatch}
		generated := map[string]string{mine: tierWatch}

		drift := heatmapDrift(committed, generated)
		if !drift.empty() {
			t.Fatalf("fixture is wrong: the snapshot compare must be GREEN here; got %+v", drift)
		}

		// The same tree, seen through the branch's diff: this author took
		// the file from 1400 to 1600.
		crossings := thresholdCrossings([]touchedFile{
			{path: mine, baseLOC: 1400, headLOC: 1600},
		})
		if len(crossings) != 1 || crossings[0].path != mine {
			t.Fatalf("the touched gate must RED on a crossing the branch caused, "+
				"even against a perfectly fresh artifact; got %+v", crossings)
		}
	})
}

// TestAcceptedCrossingIsTheOnlyEscape pins the acknowledgement filter: an
// entry silences its own file at its own tier and nothing else. Without
// this the escape hatch could widen into "any entry silences everything",
// which is how gates die quietly.
func TestAcceptedCrossingIsTheOnlyEscape(t *testing.T) {
	watchCross := crossing{path: "pkg/a/big.go", floor: auditFloor, tier: tierWatch}
	refactorCross := crossing{path: "pkg/a/big.go", floor: refactorFloor, tier: tierRefactor}
	other := crossing{path: "pkg/b/other.go", floor: auditFloor, tier: tierWatch}

	accepted := parseAccepted(t, "fixture", strings.Join([]string{
		"# a comment",
		"",
		"[WATCH] pkg/a/big.go one cohesive generated schema, splitting it buys nothing",
	}, "\n"))
	if len(accepted) != 1 {
		t.Fatalf("want 1 parsed entry (comments and blanks skipped), got %d: %+v", len(accepted), accepted)
	}
	if accepted[0].reason == "" {
		t.Fatal("the reason is the point of the file and must be parsed")
	}
	if !isAccepted(watchCross, accepted) {
		t.Fatal("a [WATCH] entry must accept its own file's [WATCH] crossing")
	}
	if isAccepted(refactorCross, accepted) {
		t.Fatal("a [WATCH] entry must NOT accept the same file crossing 2000; " +
			"accepting 1500 is not accepting 2000")
	}
	if isAccepted(other, accepted) {
		t.Fatal("an entry must not accept a crossing in a different file")
	}

	refactorAccepted := parseAccepted(t, "fixture", "[REFACTOR] pkg/a/big.go replaced by the #9999 rewrite")
	if !isAccepted(refactorCross, refactorAccepted) || !isAccepted(watchCross, refactorAccepted) {
		t.Fatal("a [REFACTOR] entry must accept both tiers for its own file")
	}
}

// TestAcceptedFileWellFormed keeps the committed acknowledgement file
// honest: every entry names an audit-eligible path and carries a reason.
// A path the audit would never measure is a typo, and a typo'd
// acknowledgement silences nothing while looking like it does.
func TestAcceptedFileWellFormed(t *testing.T) {
	root := repoRoot(t)
	accepted := readAccepted(t, root)
	seen := map[string]bool{}
	for _, a := range accepted {
		if strings.TrimSpace(a.reason) == "" {
			t.Errorf("%s: entry has no reason", a.path)
		}
		if seen[a.path+a.tier] {
			t.Errorf("%s: duplicate %s entry", a.path, a.tier)
		}
		seen[a.path+a.tier] = true
		out := runScript(t, root, "scripts/refactoring-audit-classify.sh", "audited", a.path)
		if strings.TrimSpace(out) != "AUDITED "+a.path {
			t.Errorf("%s: not an audited path (%s); the audit would never measure it, "+
				"so this entry silences nothing", a.path, strings.TrimSpace(out))
		}
	}
}

// TestAuditedPathPredicateAgreesWithGenerator binds the two users of the
// audited-path decision. scripts/refactoring-audit.sh finds files by
// walking roots; scripts/refactoring-audit-touched.sh asks
// audit_is_audited_path about a path out of `git diff`. They read the
// same $AUDIT_ROOTS_* / $AUDIT_SKIP_RE now, and this pins the agreement
// behaviourally so a future edit to one cannot quietly narrow it: every
// path the generator actually emitted must be AUDITED, and a curated set
// of near-misses must not be.
func TestAuditedPathPredicateAgreesWithGenerator(t *testing.T) {
	root := repoRoot(t)
	testguard.RequireGitCheckout(t, root)
	rows := parseHeatmap(t, "freshly generated heatmap", generatedHeatmap(t))

	var paths []string
	for _, r := range rows {
		paths = append(paths, r.path)
	}
	args := append([]string{"scripts/refactoring-audit-classify.sh", "audited"}, paths...)
	for _, line := range strings.Split(strings.TrimSpace(runScript(t, root, args...)), "\n") {
		if !strings.HasPrefix(line, "AUDITED ") {
			t.Errorf("the generator emitted a row for %q but audit_is_audited_path disagrees; "+
				"the touched-file gate would be blind to that file", line)
		}
	}

	notAudited := []string{
		"pkg/foo/bar_test.go",                    // Go test
		"pkg/x/y.pb.go",                          // generated
		"userspace-dp/src/foo/tests.rs",          // Rust test module
		"userspace-dp/src/nat/tests_pool.rs",     // Rust test module (#6232)
		"userspace-dp/tests/integration.rs",      // outside the audited root
		"userspace-dp/src/x.go",                  // right root, wrong language
		"pkg/x.rs",                               // right root, wrong language
		"docs/refactoring-audit.md",              // not source
		"Makefile",                               // not source
		"scripts/refactoring-audit-touched.sh",   // not source
		"test/incus/cluster-setup.sh",            // not source
		"userspace-dp/target/debug/build/gen.rs", // build artifact
	}
	args = append([]string{"scripts/refactoring-audit-classify.sh", "audited"}, notAudited...)
	for _, line := range strings.Split(strings.TrimSpace(runScript(t, root, args...)), "\n") {
		if !strings.HasPrefix(line, "NOT-AUDITED ") {
			t.Errorf("audit_is_audited_path claims %q is audited; the generator does not measure it, "+
				"so the touched-file gate would gate on a file the heatmap will never show", line)
		}
	}
}

// TestShellFloorsMatchGoConstants pins the two spellings of 1500/2000
// together. The shell side decides which files the generator prints; the
// Go side decides which growth reds an author. If they drift, a file can
// cross the gate's floor without ever appearing in the heatmap (or the
// reverse), and the operator-facing message would name a number the tool
// does not use.
func TestShellFloorsMatchGoConstants(t *testing.T) {
	root := repoRoot(t)
	out := runScript(t, root, "-c",
		". scripts/refactoring-audit-lib.sh && printf '%s %s\\n' \"$AUDIT_FLOOR\" \"$AUDIT_REFACTOR_FLOOR\"")
	want := fmt.Sprintf("%d %d", auditFloor, refactorFloor)
	if got := strings.TrimSpace(out); got != want {
		t.Fatalf("scripts/refactoring-audit-lib.sh floors are %q, Go constants are %q", got, want)
	}
}
