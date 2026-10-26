package stagedgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeStaged builds a staged tree with one file per managed binary, each
// carrying the given tag so a published generation's contents are
// distinguishable.
func writeStaged(t *testing.T, dir, tag string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range ManagedNames() {
		p := filepath.Join(dir, b)
		if err := os.WriteFile(p, []byte("binary-"+b+"-"+tag), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func newConfig(t *testing.T, staged string) Config {
	t.Helper()
	return Config{
		StagedDir: staged,
		Dir:       filepath.Join(t.TempDir(), "staged-gen"),
		Logf:      func(f string, a ...any) { t.Logf("stagedgen: "+f, a...) },
	}
}

func TestPublishRecordsPackageVersion(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	c.PackageVersion = "0.0.420+g0123456789ab"

	genid, err := c.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(c.GenDir(genid), PackageVersionFile))
	if err != nil {
		t.Fatalf("read package-version metadata: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != c.PackageVersion {
		t.Fatalf("package-version metadata = %q, want %q", got, c.PackageVersion)
	}
}

func TestPublishAndResolve(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	genid, err := c.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !ValidGenID(genid) {
		t.Fatalf("Publish returned an invalid genid %q", genid)
	}

	// current-gen resolves to the published genid.
	got, err := c.ResolveCurrent()
	if err != nil {
		t.Fatalf("ResolveCurrent: %v", err)
	}
	if got != genid {
		t.Fatalf("ResolveCurrent = %q, want %q", got, genid)
	}

	// The generation dir holds every managed binary with the v1 tag.
	for _, b := range ManagedNames() {
		data, rerr := os.ReadFile(filepath.Join(c.GenDir(genid), b))
		if rerr != nil {
			t.Fatalf("read published %s: %v", b, rerr)
		}
		if string(data) != "binary-"+b+"-v1" {
			t.Fatalf("published %s = %q, want v1 tag", b, data)
		}
	}
	// No .partial leaked.
	assertNoPartials(t, c.Dir)
}

func TestResolveCurrentAbsent(t *testing.T) {
	c := newConfig(t, t.TempDir())
	got, err := c.ResolveCurrent()
	if err != nil {
		t.Fatalf("ResolveCurrent on absent: %v", err)
	}
	if got != "" {
		t.Fatalf("ResolveCurrent on absent = %q, want empty", got)
	}
}

func TestPublishDistinctGenerations(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	g1, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	// Re-publish the SAME staged bytes: a same-version reinstall must still
	// yield a DISTINCT generation (B-P5 random suffix), and current-gen must
	// advance to it.
	g2, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	if g1 == g2 {
		t.Fatalf("two publishes produced the same genid %q", g1)
	}
	cur, _ := c.ResolveCurrent()
	if cur != g2 {
		t.Fatalf("current-gen = %q after second publish, want %q", cur, g2)
	}
	// Both generation dirs survive (retention N=2 keeps current + 1 prior).
	for _, g := range []string{g1, g2} {
		if fi, err := os.Stat(c.GenDir(g)); err != nil || !fi.IsDir() {
			t.Fatalf("generation dir %s missing after two publishes", g)
		}
	}
}

// TestPublishIsImmutableSource is the crux of #1981: a published generation is
// a SNAPSHOT. Mutating live staged/ AFTER a publish must NOT change the
// published generation's bytes — the cut reads the snapshot, not the live tree.
func TestPublishIsImmutableSource(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "clean")
	c := newConfig(t, staged)

	genid, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}

	// Tear the live staged tree: replace one binary with a "torn" payload, as
	// dpkg would mid-unpack.
	torn := filepath.Join(staged, "xpf-userspace-dp")
	if err := os.WriteFile(torn, []byte("TORN-half-unpacked"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The published generation is unchanged.
	data, err := os.ReadFile(filepath.Join(c.GenDir(genid), "xpf-userspace-dp"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "binary-xpf-userspace-dp-clean" {
		t.Fatalf("published generation was mutated by a live staged/ change: %q", data)
	}
}

// TestResolveCurrentRejectsPathEscape pins the Copilot r4 hardening: a
// current-gen symlink whose target carries path components (../<genid>,
// /abs/<genid>) is rejected, not silently base-named into an in-tree genid.
func TestResolveCurrentRejectsPathEscape(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	genid, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../" + genid, "/tmp/" + genid, "sub/" + genid} {
		// Repoint current-gen at a path-bearing target.
		link := filepath.Join(c.Dir, CurrentGenLink)
		_ = os.Remove(link)
		if err := os.Symlink(bad, link); err != nil {
			t.Fatal(err)
		}
		if _, rerr := c.ResolveCurrent(); rerr == nil {
			t.Errorf("ResolveCurrent accepted a path-escaping current-gen target %q", bad)
		}
	}
}

func TestResolveCurrentDanglingIsError(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	genid, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	// Remove the gen dir but leave current-gen dangling — a corrupt layout.
	if err := os.RemoveAll(c.GenDir(genid)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveCurrent(); err == nil {
		t.Fatal("ResolveCurrent on a dangling current-gen should error")
	}
}

// TestCrashBeforeCurrentGenRepoint simulates a publish crash after the gen dir
// rename but before the current-gen repoint: the PRIOR current-gen stays
// valid, and a re-publish converges.
func TestCrashBeforeCurrentGenRepoint(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	g1, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a crashed second publish: a complete-but-unreferenced gen dir
	// exists, but current-gen still names g1.
	orphan := filepath.Join(c.Dir, GenID())
	if err := copyTreeFsync(staged, orphan); err != nil {
		t.Fatal(err)
	}
	// current-gen must still resolve to g1 (prior generation valid).
	cur, err := c.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if cur != g1 {
		t.Fatalf("current-gen = %q, want the prior valid generation %q", cur, g1)
	}
	// A re-publish converges current-gen to a fresh generation.
	g3, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	cur, _ = c.ResolveCurrent()
	if cur != g3 {
		t.Fatalf("current-gen = %q after re-publish, want %q", cur, g3)
	}
}

func TestSweepPartialsOnPublish(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	if _, err := c.Publish(); err != nil {
		t.Fatal(err)
	}
	// Drop a stale .partial as a crashed prior publish would.
	stale := filepath.Join(c.Dir, GenID()+partialSuffix)
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "junk"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The next publish pre-sweeps it.
	if _, err := c.Publish(); err != nil {
		t.Fatal(err)
	}
	assertNoPartials(t, c.Dir)
}

func TestGCRetainsCurrentPlusOne(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	var gens []string
	for i := 0; i < 4; i++ {
		g, err := c.Publish()
		if err != nil {
			t.Fatal(err)
		}
		gens = append(gens, g)
		// Bump the mtime so the sort order is unambiguous (publishes can land
		// in the same coarse mtime tick).
		bumpMtime(t, c.GenDir(g), int64(i+1))
	}
	if err := c.GC(nil); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// Newest two survive (current + 1 prior); the older two are gone.
	for i, g := range gens {
		_, err := os.Stat(c.GenDir(g))
		surviving := i >= len(gens)-RetainGenerations
		if surviving && err != nil {
			t.Errorf("generation %s should survive GC but is gone", g)
		}
		if !surviving && err == nil {
			t.Errorf("generation %s should be GC'd but survives", g)
		}
	}
}

// TestGCProtectsJournalReferencedGen pins the GC-vs-resume race (plan §7.7): a
// generation an in-flight cut still references must NOT be GC'd even when it is
// older than the retention window.
func TestGCProtectsJournalReferencedGen(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	// g0 is the cut's pinned source; publish three newer generations so g0
	// would normally fall outside the N=2 window.
	g0, err := c.Publish()
	if err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, c.GenDir(g0), 1)
	for i := 0; i < 3; i++ {
		g, err := c.Publish()
		if err != nil {
			t.Fatal(err)
		}
		bumpMtime(t, c.GenDir(g), int64(i+2))
	}
	// Protect g0 as a journal-referenced generation.
	if err := c.GC(map[string]bool{g0: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.GenDir(g0)); err != nil {
		t.Fatalf("GC removed a journal-referenced generation %s: %v", g0, err)
	}

	// Counter-factual: WITHOUT the protection, g0 is reaped.
	if err := c.GC(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.GenDir(g0)); err == nil {
		t.Fatalf("g0 survived an unprotected GC — the protection test is tautological")
	}
}

// TestGCProtectedDoesNotConsumeRetentionWindow pins the Copilot fix: a
// protected (journal-pinned) OLD generation must NOT consume a retention slot,
// so the immediate-prior-to-current generation still survives.
func TestGCProtectedDoesNotConsumeRetentionWindow(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	// Publish g0 (oldest), g1, g2 (newest = current-gen). Protect the OLDEST.
	g0, _ := c.Publish()
	bumpMtime(t, c.GenDir(g0), 1)
	g1, _ := c.Publish()
	bumpMtime(t, c.GenDir(g1), 2)
	g2, _ := c.Publish()
	bumpMtime(t, c.GenDir(g2), 3)

	if err := c.GC(map[string]bool{g0: true}); err != nil {
		t.Fatal(err)
	}
	// current-gen g2 always kept; g0 protected; AND g1 (the immediate prior to
	// current) must survive because g0's protection did NOT eat its slot.
	for _, g := range []string{g0, g1, g2} {
		if _, err := os.Stat(c.GenDir(g)); err != nil {
			t.Errorf("generation %s should survive (protected g0 must not push g1 out of the window): %v", g, err)
		}
	}
}

// TestGCIgnoresNonGenerationDirs pins the Copilot fix: a stray non-genid
// directory in the staged-gen root is neither counted toward retention nor
// deleted by GC.
func TestGCIgnoresNonGenerationDirs(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	g0, _ := c.Publish()
	g1, _ := c.Publish()
	g2, _ := c.Publish() // current-gen
	// A stray foreign directory (not a valid genid).
	stray := filepath.Join(c.Dir, "operator-scratch")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := c.GC(nil); err != nil {
		t.Fatal(err)
	}
	// The stray dir is untouched (not counted, not deleted).
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("GC deleted a non-generation directory: %v", err)
	}
	// Retention is computed over generations only: newest 2 (g2,g1) survive,
	// g0 reaped — the stray did NOT consume a slot that would save g0.
	if _, err := os.Stat(c.GenDir(g0)); err == nil {
		t.Errorf("g0 survived — a stray dir wrongly consumed a retention slot")
	}
	for _, g := range []string{g1, g2} {
		if _, err := os.Stat(c.GenDir(g)); err != nil {
			t.Errorf("in-window generation %s wrongly GC'd: %v", g, err)
		}
	}
}

// TestGCProtectsCurrentGenEvenIfNotNewest pins the Copilot fix: current-gen is
// resolved EXPLICITLY and protected additively, so it survives GC even if it
// is NOT the lexicographically-newest generation (e.g. current-gen was
// repointed back to an older generation).
func TestGCProtectsCurrentGenEvenIfNotNewest(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)

	g0, _ := c.Publish() // oldest
	c.Publish()          // g1
	c.Publish()          // g2 (newest, current-gen now)
	// Repoint current-gen back to the OLDEST generation g0 (atypical, but the
	// GC must protect whatever current-gen names).
	if err := atomicRelSymlink(filepath.Join(c.Dir, CurrentGenLink), g0); err != nil {
		t.Fatal(err)
	}

	if err := c.GC(nil); err != nil {
		t.Fatal(err)
	}
	// g0 is current-gen — must survive even though it is the oldest (outside
	// the newest-2 name window).
	if _, err := os.Stat(c.GenDir(g0)); err != nil {
		t.Fatalf("GC deleted current-gen (g0) because it was not the newest: %v", err)
	}
}

func TestRemoveAll(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	if _, err := c.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Dir); !os.IsNotExist(err) {
		t.Fatalf("RemoveAll left %s present", c.Dir)
	}
	// Idempotent on an absent root.
	if err := c.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll on absent root: %v", err)
	}
}

func TestValidGenID(t *testing.T) {
	if !ValidGenID(GenID()) {
		t.Fatal("GenID produced an invalid id")
	}
	bad := []string{
		"", "current-gen", "..", "../escape", "a/b", ".hidden",
		"00000000000000000000-aabb-ccdd", // two dashes
		"00000000000000000000-XYZ",       // uppercase / non-hex
		"00000000000000000000",           // no dash
	}
	for _, s := range bad {
		if ValidGenID(s) {
			t.Errorf("ValidGenID(%q) = true, want false", s)
		}
	}
}

func assertNoPartials(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == partialSuffix {
			t.Errorf("leftover partial %s", e.Name())
		}
	}
}

func bumpMtime(t *testing.T, path string, secs int64) {
	t.Helper()
	base := int64(1_700_000_000)
	mt := time.Unix(base+secs, 0)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

// #6763 — GC discarded ResolveCurrent's error and proceeded to destructive
// deletion with the live generation unprotected.
//
// The old line was `if cur, rerr := c.ResolveCurrent(); rerr == nil && cur !=
// ""` — rerr was tested only for nil-ness and then dropped. Every one of
// ResolveCurrent's error paths means "I cannot establish which generation is
// live": a readlink failure, a symlink with path components that would escape
// the staged-gen root, a target that is not a valid genid, and a DANGLING
// current-gen whose directory is missing. In each, GC then reaped whatever fell
// outside the retention window — including the live generation.
//
// The rule applied here is not new. publish-generation already refuses to run
// GC when the OTHER half of the protection set is unknown (#4876: an unreadable
// or malformed journal means "GC is SKIPPED rather than run with an empty
// protection set"). current-gen was the half that never got it.

// gcFixtureBeyondWindow publishes RetainGenerations+1 generations and returns
// them oldest-first. The oldest is outside the retention window, so it is what
// an unprotected GC deletes — which makes it the observable for these tests.
func gcFixtureBeyondWindow(t *testing.T) (Config, []string) {
	t.Helper()
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	writeStaged(t, staged, "v1")
	c := newConfig(t, staged)
	var gens []string
	for i := 0; i < RetainGenerations+1; i++ {
		g, err := c.Publish()
		if err != nil {
			t.Fatal(err)
		}
		gens = append(gens, g)
	}
	return c, gens
}

func TestGCRefusesWhenCurrentGenIsDangling_6763(t *testing.T) {
	c, gens := gcFixtureBeyondWindow(t)
	oldest := gens[0]

	// A DANGLING current-gen: the link names a generation whose directory is
	// gone. ResolveCurrent calls this a corrupt layout and errors — and a
	// corrupt layout is exactly when the live generation most needs protecting.
	missing := "00000000000000000001-000000000000dead"
	if err := atomicRelSymlink(filepath.Join(c.Dir, CurrentGenLink), missing); err != nil {
		t.Fatal(err)
	}

	err := c.GC(nil)
	if err == nil {
		t.Fatalf("GC returned nil with an unresolvable current-gen — it proceeded to " +
			"destructive deletion without knowing which generation is live (#6763)")
	}
	if !strings.Contains(err.Error(), "current") {
		t.Errorf("the error must name the cause so an operator can act on it, got: %v", err)
	}
	// Nothing may have been deleted: the refusal is the whole point.
	for _, g := range gens {
		if _, serr := os.Stat(c.GenDir(g)); serr != nil {
			t.Errorf("GC deleted generation %s despite refusing: %v", g, serr)
		}
	}
	_ = oldest
}

func TestGCRefusesWhenCurrentGenEscapesTheRoot_6763(t *testing.T) {
	c, gens := gcFixtureBeyondWindow(t)
	// A hand-edited symlink with a path component. ResolveCurrent rejects it
	// BEFORE deriving a genid precisely so it cannot escape the root; GC must
	// treat that rejection as "unknown", not "no current generation".
	if err := atomicRelSymlink(filepath.Join(c.Dir, CurrentGenLink), "../"+gens[len(gens)-1]); err != nil {
		t.Fatal(err)
	}
	if err := c.GC(nil); err == nil {
		t.Fatalf("GC proceeded with a current-gen symlink that escapes the staged-gen root")
	}
	for _, g := range gens {
		if _, serr := os.Stat(c.GenDir(g)); serr != nil {
			t.Errorf("GC deleted generation %s despite an unresolvable current-gen: %v", g, serr)
		}
	}
}

// TestGCStillRunsWhenThereIsNoCurrentGen_6763 is the OVER-BLOCKING control, and
// it is the cell that separates this fix from "abort whenever ResolveCurrent
// returns anything unusual".
//
// ResolveCurrent distinguishes the benign case deliberately: NO current-gen link
// returns ("", nil), not an error. Absence is determinate — there is nothing to
// protect — so GC must still reap. An implementation that aborted here would
// leave a never-published root accumulating generations forever while passing
// both refusal tests above.
func TestGCStillRunsWhenThereIsNoCurrentGen_6763(t *testing.T) {
	c, gens := gcFixtureBeyondWindow(t)
	if err := os.Remove(filepath.Join(c.Dir, CurrentGenLink)); err != nil {
		t.Fatal(err)
	}
	if err := c.GC(nil); err != nil {
		t.Fatalf("GC refused with NO current-gen link: absence is determinate and must "+
			"not block reclamation: %v", err)
	}
	if _, serr := os.Stat(c.GenDir(gens[0])); !os.IsNotExist(serr) {
		t.Errorf("the oldest generation survived a GC that should have reaped it "+
			"(err=%v) — the retention window was not applied", serr)
	}
}

// TestGCProtectsResolvableCurrentGen_6763 is the green control: when current-gen
// resolves, the pre-existing protection must still hold. Without it, "refuse on
// error" could be satisfied by an implementation that also stopped protecting
// on success.
func TestGCProtectsResolvableCurrentGen_6763(t *testing.T) {
	c, gens := gcFixtureBeyondWindow(t)
	oldest := gens[0]
	if err := atomicRelSymlink(filepath.Join(c.Dir, CurrentGenLink), oldest); err != nil {
		t.Fatal(err)
	}
	if err := c.GC(nil); err != nil {
		t.Fatalf("GC failed with a perfectly resolvable current-gen: %v", err)
	}
	if _, serr := os.Stat(c.GenDir(oldest)); serr != nil {
		t.Errorf("GC deleted the resolvable current-gen %s: %v", oldest, serr)
	}
}
