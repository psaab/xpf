package refactoraudit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

// Tier tags and thresholds, mirroring scripts/refactoring-audit.sh.
// `categorize` there pads the WATCH tag for column alignment; the tag
// itself is the unpadded token these constants hold.
const (
	tierRefactor = "[REFACTOR]"
	tierWatch    = "[WATCH]"

	// auditFloor is the LOC at which a file enters the heatmap at all;
	// refactorFloor is the LOC at which it is promoted to [REFACTOR].
	auditFloor    = 1500
	refactorFloor = 2000
)

// auditRow is one parsed heatmap row, e.g.
//
//	[REFACTOR]   2448  userspace-dp/src/afxdp/worker/loop_body/mod.rs
type auditRow struct {
	tier string
	loc  int
	path string
}

// parseHeatmap parses heatmap text into rows. It fails closed: any line
// the generator could not have produced (wrong field count, unknown tier
// tag, non-numeric LOC) is a hard failure rather than a skipped row, so a
// corrupted or hand-mangled artifact can never read as "no drift".
func parseHeatmap(t *testing.T, what, text string) []auditRow {
	t.Helper()
	var rows []auditRow
	for i, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s line %d: want 3 fields (tier LOC path), got %d: %q", what, i+1, len(fields), line)
		}
		if fields[0] != tierRefactor && fields[0] != tierWatch {
			t.Fatalf("%s line %d: unknown tier tag %q (want %q or %q)", what, i+1, fields[0], tierRefactor, tierWatch)
		}
		loc, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("%s line %d: LOC field %q is not an integer: %v", what, i+1, fields[1], err)
		}
		rows = append(rows, auditRow{tier: fields[0], loc: loc, path: fields[2]})
	}
	if len(rows) == 0 {
		t.Fatalf("%s parsed to zero rows; this repo always has >=1500 LOC files, so an empty audit means the generator or the artifact is broken", what)
	}
	return rows
}

// tierByPath projects rows onto the audit's *content*: which files are
// audited, and at which tier. This is the merge-stable part of the
// heatmap — it moves only when a file really crosses 1500 or 2000 LOC —
// but "merge-stable" is not "merge-proof", which is what #7253 measured
// and why the compare over this projection is no longer a gate. See
// TestGlobalHeatmapFreshnessAdvisory.
func tierByPath(rows []auditRow) map[string]string {
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		m[r.path] = r.tier
	}
	return m
}

// repoRoot walks up from this test file's directory until it finds
// go.mod, so the canary works regardless of the test's cwd (go test runs
// each package with cwd = the package dir) and regardless of whether it
// runs in the main checkout or a git worktree.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate repo root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("walked to filesystem root from %s without finding go.mod", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

// runScript runs a repo script under bash from the repo root and returns
// its stdout. The canary fails closed: a missing bash/script or a
// non-zero exit is a divergence, not a skip.
func runScript(t *testing.T, root string, args ...string) string {
	t.Helper()
	out, stderr, err := runScriptErr(root, args...)
	if err != nil {
		t.Fatalf("bash %s: %v\nstderr:\n%s", strings.Join(args, " "), err, stderr)
	}
	return out
}

// runScriptErr is runScript without the testing.T, so a memoised caller
// can record a failure once and report it to every test that asks.
func runScriptErr(root string, args ...string) (string, string, error) {
	cmd := exec.Command("bash", args...)
	cmd.Dir = root
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return string(out), stderr.String(), err
}

var (
	generatedOnce   sync.Once
	generatedText   string
	generatedStderr string
	generatedErr    error
)

// generatedHeatmap returns the heatmap generated from the working tree,
// memoised for the whole package run.
//
// The generator spawns one `wc -l` per audited file, which makes it by
// far the most expensive thing here, and two tests want the same answer
// from the same unchanged tree. TestGeneratorDeterministic deliberately
// does NOT use this — running it twice for real is its entire point.
//
// The failure is recorded rather than fatalled inside the sync.Once, so
// every caller reports the generator's own stderr instead of the second
// caller seeing a mysterious empty artifact.
func generatedHeatmap(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	generatedOnce.Do(func() {
		generatedText, generatedStderr, generatedErr = runScriptErr(root, "scripts/refactoring-audit.sh")
	})
	if generatedErr != nil {
		t.Fatalf("bash scripts/refactoring-audit.sh: %v\nstderr:\n%s", generatedErr, generatedStderr)
	}
	return generatedText
}

// heatmapDriftReport is the outcome of the repo-GLOBAL snapshot
// compare: which audited files the committed artifact and a fresh
// generation disagree about, and how.
type heatmapDriftReport struct {
	entered  []string // audited now, absent from the committed artifact
	left     []string // in the committed artifact, no longer audited
	retiered []string // audited by both, at different tiers
}

func (d heatmapDriftReport) empty() bool {
	return len(d.entered)+len(d.left)+len(d.retiered) == 0
}

// heatmapDrift compares the committed artifact's (path -> tier)
// projection against a fresh generation's. This is the WHOLE of what the
// old fatal TestHeatmapNotStale asserted, kept as a function because two
// callers need it and neither is a gate:
//
//   - TestGlobalHeatmapFreshnessAdvisory reports it and does not fail;
//   - TestTouchedGateIsNotASnapshotCompare uses it as the rival
//     mechanism it has to disagree with, in both directions. That proof
//     is only worth anything if this really is the snapshot compare and
//     not a strawman, which is why the advisory test keeps it bound to
//     the real artifact and the real generator.
func heatmapDrift(committed, generated map[string]string) heatmapDriftReport {
	var d heatmapDriftReport
	for path, tier := range generated {
		old, ok := committed[path]
		switch {
		case !ok:
			d.entered = append(d.entered, fmt.Sprintf("  %-10s %s", tier, path))
		case old != tier:
			d.retiered = append(d.retiered, fmt.Sprintf("  %s: %s -> %s", path, old, tier))
		}
	}
	for path, tier := range committed {
		if _, ok := generated[path]; !ok {
			d.left = append(d.left, fmt.Sprintf("  %-10s %s", tier, path))
		}
	}
	sort.Strings(d.entered)
	sort.Strings(d.left)
	sort.Strings(d.retiered)
	return d
}

// TestGlobalHeatmapFreshnessAdvisory reports global snapshot drift and
// DOES NOT FAIL ON IT. It is the demoted half of the old
// TestHeatmapNotStale (#7253).
//
// # Why the fatal came off
//
// TestHeatmapNotStale fused two different properties into one assertion:
//
//	modularity — "this file is growing past the point where it should be
//	split". Aimed at the author of the growth, actionable by them, and
//	worth interrupting them for.
//
//	freshness — "the committed global snapshot disagrees with the tree".
//	Aimed at whoever merges next, not actionable by them, and not worth
//	interrupting anyone for.
//
// Only the first is a gate. The second could not even stay true between
// authoring and merge: the artifact is a snapshot of a repo-GLOBAL
// property, so any file crossing 1500 or 2000 LOC anywhere in the tree
// flips it for everyone. #7235, #7252 and #7254 each regenerated it
// inside one hour for different files, and #7252 was ALREADY STALE when
// it merged — it was merged, master re-tested, and was still red on the
// same two files. A PR whose entire content was "make the artifact match
// the tree" could not survive its own review latency.
//
// #6617 had already narrowed this class once, byte-compare ->
// content-compare, after measuring master byte-stale in 26 of 40
// first-parent commits and after #6602 and #6613 both regenerated at
// their own base and both still landed red on pkg/snmp/agent.go, a file
// neither had touched. (Precise sequence, preserved from that comment:
// #6602 regenerated at 1737 LOC in b5a524b2e, and its sync merge
// aac0d60dd then incorporated #6596's 1823-line file WITHOUT refreshing
// the artifact. The 26-of-40 count is over the first-parent commits
// ending at b4605ea9d and is reproducible by regenerating at each one.)
// Its own comment states the principle this test now obeys: a gate that
// reds when the author did everything right is noise. The content compare was a real improvement but kept the shape;
// pkg/dataplane/types.go crossing the floor at exactly 1501 lines flipped
// the gate for every unrelated author on the board.
//
// The modularity signal is NOT deleted — tcp_segmentation.rs entering the
// audit at 1582 was a correct and useful catch. It moved to
// TestTouchedFileCrossedModularityThreshold, which derives its verdict
// from the PR's own diff and therefore cannot be invalidated by an
// unrelated file. Global freshness converges through
// scripts/refactoring-audit-refresh.sh instead of through a human.
//
// # What still has teeth here
//
// Staleness does not fail. Corruption does: parseHeatmap is fail-closed,
// so a malformed committed artifact, a malformed generation, or a
// generator that emits nothing at all is still a hard failure on both
// sides of this compare. The advisory part is the DIFFERENCE between two
// well-formed inputs.
func TestGlobalHeatmapFreshnessAdvisory(t *testing.T) {
	root := repoRoot(t)
	testguard.RequireGitCheckout(t, root)
	committedPath := filepath.Join(root, "docs", "refactoring-audit-current.txt")
	b, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed heatmap %s: %v", committedPath, err)
	}
	committed := tierByPath(parseHeatmap(t, "committed docs/refactoring-audit-current.txt", string(b)))
	generated := tierByPath(parseHeatmap(t, "freshly generated heatmap", generatedHeatmap(t)))

	d := heatmapDrift(committed, generated)
	if d.empty() {
		t.Log("docs/refactoring-audit-current.txt matches the tree")
		return
	}
	var msg strings.Builder
	msg.WriteString("ADVISORY (not a failure): docs/refactoring-audit-current.txt is behind the tree.\n")
	for _, section := range []struct {
		title string
		rows  []string
	}{
		{fmt.Sprintf("entered the audit (now >=%d LOC)", auditFloor), d.entered},
		{fmt.Sprintf("left the audit (now <%d LOC, or renamed/deleted)", auditFloor), d.left},
		{fmt.Sprintf("changed tier (crossed %d LOC)", refactorFloor), d.retiered},
	} {
		if len(section.rows) == 0 {
			continue
		}
		fmt.Fprintf(&msg, "\n%s:\n%s\n", section.title, strings.Join(section.rows, "\n"))
	}
	msg.WriteString("\nThe refresh job converges this without interrupting anyone:\n" +
		"  bash scripts/refactoring-audit-refresh.sh\n" +
		"You are NOT expected to regenerate it in your PR. If one of the files\n" +
		"above is one YOU grew past a threshold,\n" +
		"TestTouchedFileCrossedModularityThreshold is the test that says so.")
	t.Log(msg.String())
}

// TestHeatmapArtifactWellFormed pins the committed artifact's internal
// coherence, which is what the artifact still guarantees now that its
// freshness is advisory (#7253). Every row must record a LOC at or above
// the audit floor whose value agrees with its own tier tag, and the rows
// must still be in generator order. So a row can never carry a number
// that contradicts the tier it is filed under.
//
// This bounds INCOHERENCE, not staleness. Before #7253 the tier gate
// forced a regeneration on every band crossing, which refreshed every
// number and bounded LOC lag to a tier band; nothing forces that now, so
// a row's LOC may be arbitrarily old. It cannot be arbitrarily WRONG in
// the one way that would mislead a reader — a [WATCH] row can never
// record 2400 — because such a row could only come from a hand edit, and
// that is what this test catches.
//
// These are hand-edit detectors, not drift detectors. The artifact is
// only ever produced wholesale by scripts/refactoring-audit.sh, which
// emits rows sorted and self-consistent by construction, so ordinary
// staleness — the tree moving on while the artifact keeps its old
// numbers — leaves every check here green. A row whose LOC contradicts
// its tag, or a row out of sort position, means someone edited the
// generated file by hand.
func TestHeatmapArtifactWellFormed(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read committed heatmap: %v", err)
	}
	rows := parseHeatmap(t, "committed docs/refactoring-audit-current.txt", string(b))

	for _, r := range rows {
		if r.loc < auditFloor {
			t.Errorf("row %s records %d LOC, below the %d LOC audit floor — it should not be in the heatmap at all",
				r.path, r.loc, auditFloor)
		}
		want := tierWatch
		if r.loc >= refactorFloor {
			want = tierRefactor
		}
		if r.tier != want {
			t.Errorf("row %s: %d LOC is tagged %s, want %s (>=%d LOC is %s, %d-%d is %s)",
				r.path, r.loc, r.tier, want, refactorFloor, tierRefactor, auditFloor, refactorFloor-1, tierWatch)
		}
	}

	// #6627: each path appears AT MOST ONCE.
	//
	// A duplicated row passed every other check here, which is why it needed
	// its own. The staleness comparison builds a tierByPath map, so a second
	// row for the same path collapses onto the first and compares equal; the
	// order check below permits equal-adjacent rows, so a duplicate does not
	// break ordering; and the band check above passes because the duplicate
	// carries the same valid LOC and tier.
	//
	// This is the existence-vs-coverage shape: every check asked "is there a
	// row for this path", none asked "how many". The generator cannot produce
	// a duplicate, so this is a hand-edit detector — the same class the
	// surrounding tests already cover for retagging, deletion, phantom rows
	// and reordering, and the one gap in that set.
	seenPath := make(map[string]int, len(rows))
	for i, r := range rows {
		if first, dup := seenPath[r.path]; dup {
			t.Errorf("#6627: path %s appears twice in the committed heatmap (rows %d and %d) — "+
				"a duplicate row is invisible to every other check here (tierByPath collapses it, "+
				"equal-adjacent rows are validly ordered, and the band check sees the same valid "+
				"LOC and tier), so it must be rejected explicitly",
				r.path, first+1, i+1)
			continue
		}
		seenPath[r.path] = i
	}

	// Generator order: LOC descending, path ascending on ties
	// (LC_ALL=C sort -k2,2nr -k3,3 in scripts/refactoring-audit.sh).
	for i := 1; i < len(rows); i++ {
		prev, cur := rows[i-1], rows[i]
		if prev.loc < cur.loc || (prev.loc == cur.loc && prev.path > cur.path) {
			t.Errorf("rows %d/%d are out of generator order (LOC desc, path asc): %s (%d) precedes %s (%d)",
				i, i+1, prev.path, prev.loc, cur.path, cur.loc)
		}
	}
}

// TestGeneratorDeterministic asserts two consecutive generations are
// byte-identical (#6617 acceptance criterion). Everything downstream is
// only as trustworthy as the generator underneath it: an unstable
// generator — unsorted `find` order leaking through, a timestamp, a
// locale-dependent tie-break — would make the refresh job commit a new
// artifact on every run and the advisory report cry drift on an unchanged
// tree, re-creating the ignore-this-signal failure #6617 is about.
func TestGeneratorDeterministic(t *testing.T) {
	root := repoRoot(t)
	testguard.RequireGitCheckout(t, root)
	first := runScript(t, root, "scripts/refactoring-audit.sh")
	second := runScript(t, root, "scripts/refactoring-audit.sh")
	if first != second {
		t.Fatalf("scripts/refactoring-audit.sh is NOT deterministic: two consecutive runs on an\n"+
			"unchanged tree differ. The heatmap gate cannot be trusted until this is fixed.\n\n--- run 1 ---\n%s\n--- run 2 ---\n%s",
			first, second)
	}
}

// TestClassifierFilenameShapes pins the exclusion classifier through the
// same thin CLI the generator uses, so the two cannot drift. Every Rust
// test-only filename shape (#6232) must be excluded, every generated/Go
// test shape must be excluded, and — critically — a production file
// whose name merely CONTAINS "test" must stay counted (anchoring
// regression guard).
func TestClassifierFilenameShapes(t *testing.T) {
	root := repoRoot(t)

	// Paths that MUST be excluded (SKIP).
	skip := []string{
		"userspace-dp/src/nat/tests_pool.rs",        // tests_*.rs sibling split
		"userspace-dp/src/afxdp/tests_support.rs",   // tests_*.rs support module
		"userspace-dp/src/afxdp/test_fixtures.rs",   // test_*.rs fixtures
		"userspace-dp/src/afxdp/tx/test_support.rs", // test_*.rs support
		"userspace-dp/src/test_alloc.rs",            // test_*.rs top-level
		"userspace-dp/src/test_zone_ids.rs",         // test_*.rs top-level
		"userspace-dp/src/foo/tests.rs",             // exact tests.rs
		"userspace-dp/src/bar_tests.rs",             // *_tests.rs suffix
		"pkg/foo/bar_test.go",                       // Go test
		"pkg/foo/baz_bpfel.go",                      // bpf2go generated
		"pkg/x/y.pb.go",                             // protobuf generated
		"pkg/x/y_grpc.pb.go",                        // gRPC generated
		"vendor/x/y.go",                             // vendored
		"userspace-dp/target/debug/foo.rs",          // build artifact
	}
	// Paths that MUST be counted (SOURCE). The last three contain the
	// substring "test" but are NOT test files — they guard against an
	// unanchored pattern eating production code.
	source := []string{
		"userspace-dp/src/afxdp/poll_descriptor/mod.rs",
		"pkg/config/compiler.go",
		"userspace-dp/src/policy.rs",
		"userspace-dp/src/attestation.rs",
		"userspace-dp/src/latest_state.rs",
		"userspace-dp/src/contest.rs",
	}

	classify := func(paths []string) map[string]string {
		args := append([]string{"scripts/refactoring-audit-classify.sh", "classify"}, paths...)
		out := runScript(t, root, args...)
		got := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				t.Fatalf("unexpected classify line %q", line)
			}
			got[fields[1]] = fields[0]
		}
		return got
	}

	for p, verdict := range classify(skip) {
		if verdict != "SKIP" {
			t.Errorf("classifier: %s => %s, want SKIP (test/generated/vendored must be excluded)", p, verdict)
		}
	}
	for p, verdict := range classify(source) {
		if verdict != "SOURCE" {
			t.Errorf("classifier: %s => %s, want SOURCE (production must be counted)", p, verdict)
		}
	}
}

// TestProductionSentinelVisible asserts the negative fixture from the
// #6232 acceptance criteria: a real >=2000 LOC production module stays
// visible in the committed heatmap, and no excluded Rust test file is
// present. If the classifier ever over-excludes and hides real
// production code, or under-excludes and re-admits a test warehouse,
// this fails.
func TestProductionSentinelVisible(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "refactoring-audit-current.txt"))
	if err != nil {
		t.Fatalf("read committed heatmap: %v", err)
	}
	heatmap := string(b)

	const sentinel = "userspace-dp/src/afxdp/poll_descriptor/mod.rs"
	if !strings.Contains(heatmap, sentinel) {
		t.Errorf("production sentinel %s is missing from the heatmap; the classifier may be over-excluding real production code", sentinel)
	}
	// The sentinel must be a [REFACTOR] (>=2000 LOC) row.
	for _, line := range strings.Split(heatmap, "\n") {
		if strings.HasSuffix(line, sentinel) && !strings.HasPrefix(line, "[REFACTOR]") {
			t.Errorf("sentinel row is not [REFACTOR] tier: %q", line)
		}
	}

	// PER-LANGUAGE FLOOR. The sentinel above is a single Rust path, so it
	// survives the Go leg of the generator being broken entirely: drop
	// audit_go(), regenerate, and the Go rows go 25 -> 0 while every test
	// here — and `make audit-check` — still reports success, because each
	// remaining check is satisfied by a Rust-only artifact. A whole language
	// silently leaving the audit is exactly the failure this file exists to
	// catch, so require at least one row from each side.
	var goRows, rustRows int
	for _, line := range strings.Split(heatmap, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		switch path := fields[2]; {
		case strings.HasPrefix(path, "pkg/"), strings.HasPrefix(path, "cmd/"):
			goRows++
		case strings.HasPrefix(path, "userspace-dp/"), strings.HasPrefix(path, "userspace-xdp/"):
			rustRows++
		}
	}
	if goRows == 0 {
		t.Error("no pkg/ or cmd/ rows in the heatmap: the Go leg of the audit " +
			"produced nothing. This repo always has >=1500 LOC Go files, so an " +
			"all-Rust artifact means the generator's Go half is broken, not that " +
			"the Go tree got small.")
	}
	if rustRows == 0 {
		t.Error("no userspace-dp/ or userspace-xdp/ rows in the heatmap: the Rust " +
			"leg of the audit produced nothing.")
	}

	// No excluded test file may reappear.
	for _, bad := range []string{
		"tests_pool.rs", "tests_support.rs", "tests_destination.rs",
		"test_fixtures.rs", "test_support.rs", "/tests.rs", "_tests.rs",
	} {
		if strings.Contains(heatmap, bad) {
			t.Errorf("excluded test file %q leaked into the heatmap", bad)
		}
	}
}

// TestInlineTestBlockNotStripped pins the historical parser-failure
// regression (docs/refactoring-audit.md): the audit measures RAW file
// LOC and must NOT strip an inline `#[cfg(test)] mod tests { ... }`
// block — an earlier awk range-stripper silently erased production code
// that FOLLOWED the test block. A fixture file with production code
// after an inline test block must report its full line count.
func TestInlineTestBlockNotStripped(t *testing.T) {
	root := repoRoot(t)
	fixture := "// production line 1\n" +
		"pub fn before() {}\n" +
		"#[cfg(test)]\n" +
		"mod tests {\n" +
		"    #[test]\n" +
		"    fn t() { assert!(true); }\n" +
		"}\n" +
		"// production line AFTER the inline test block — must be counted\n" +
		"pub fn after() {}\n"
	wantLOC := strings.Count(fixture, "\n") // 9 lines, all newline-terminated

	dir := t.TempDir()
	path := filepath.Join(dir, "inline_fixture.rs")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out := runScript(t, root, "scripts/refactoring-audit-classify.sh", "loc", path)
	got := strings.TrimSpace(out)
	want := strconv.Itoa(wantLOC)
	if got != want {
		t.Fatalf("audit_loc stripped or miscounted an inline-test fixture: got %q, want %q\n"+
			"the measurement must count RAW LOC so a stripper cannot erase production code following a test block", got, want)
	}
}

// TestMakefileRunsAuditPackageUncached binds the #6626 fix to the wiring that
// makes it live.
//
// The hard gate measures the branch's own diff by shelling out to
// scripts/refactoring-audit-touched.sh. Neither the working tree nor that
// script is a `go test` cache input, so a REAL threshold crossing changes
// nothing the cache hashes and a plain `go test ./...` returns "ok (cached)" —
// the gate passes without running. Demonstrated on this package: a new
// 2004-LOC production file (a genuine [REFACTOR] crossing) returned
// "ok (cached)" and FAILED under -count=1.
//
// Nothing inside Go can detect that from within a cached run, so the fix lives
// in the Makefile and this test guards the Makefile. Without it, deleting the
// invocation silently restores a gate that can pass without running — and every
// test in this package would still be green, because they would simply be
// served from cache.
//
// FAIL-ON-REVERT: drop `-count=1` from the pkg/refactoraudit invocation in the
// test-go target, or delete the invocation.
func TestMakefileRunsAuditPackageUncached(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := string(b)

	// #8231: the property, not one spelling of it.
	//
	// This used to pin the literal `$(GO) test -count=1 ./pkg/refactoraudit/`.
	// That worked until the leg was routed through scripts/go-test-json.sh so
	// the gate can emit a machine-readable stream, at which point the guard
	// went red on a change that preserved everything it protects — a literal
	// encodes which SPELLING is trusted rather than what must be true.
	//
	// The property is: inside the test-go target there is a RECIPE line naming
	// this package, and that same line carries -count=1. Matching the two
	// TOGETHER is still the point: an invocation without -count=1 is the
	// cached-pass bug wearing the shape of a fix.
	//
	// Strictly stronger than the literal it replaces, which could be satisfied
	// by the string appearing anywhere in the Makefile — including in a comment
	// or in a target nothing runs.
	idx := strings.Index(mk, "test-go:")
	if idx < 0 {
		t.Fatal("#6626: no test-go target found in the Makefile — this guard is bound to it " +
			"by name and must be re-pointed if the target is renamed")
	}
	body := mk[idx:]
	if e := strings.Index(body, "\n\n"); e > 0 {
		body = body[:e]
	}

	var found, uncached bool
	for _, line := range strings.Split(body, "\n") {
		// Recipe lines only: a comment mentioning the package proves nothing,
		// and the literal check this replaces could be satisfied by one.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(line, "./pkg/refactoraudit/") {
			continue
		}
		found = true
		if strings.Contains(line, "-count=1") {
			uncached = true
		}
	}

	if !found {
		t.Fatalf("#6626: the test-go target has no recipe line naming ./pkg/refactoraudit/.\n\n"+
			"Without one, a real threshold crossing returns \"ok (cached)\" on the path CI and "+
			"developers actually take, so the modularity gate passes without ever running. Every "+
			"test in this package stays green in that state, which is exactly why this has to be "+
			"checked here.\n\ntest-go target body:\n%s", body)
	}
	if !uncached {
		t.Fatalf("#6626: the test-go target runs ./pkg/refactoraudit/ but WITHOUT -count=1, which "+
			"is the cached-pass bug wearing the shape of a fix: the invocation exists, the target "+
			"looks correct, and the gate is served from cache.\n\ntest-go target body:\n%s", body)
	}
}
