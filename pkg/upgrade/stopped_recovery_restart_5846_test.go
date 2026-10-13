package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// #5846: when a superseded STOPPED cut is recovered (its journaled target A
// differs from a newly-staged B), Run restarts the still-current KNOWN-GOOD
// daemon (the stopped cut never flipped `current`) before starting fresh. The
// pre-#5846 code only LOGGED a StartUnit failure, then removeAllPartials + reset
// the journal and proceeded into a fresh cut to B — so the new cut used a
// rollback target (PreviousVersion, read from `current`) that JUST FAILED TO
// RESTART, while the control plane was DOWN, and the stale-recovery evidence was
// destroyed. The fix aborts fail-closed: it returns the error and PRESERVES the
// stale journal + partials.

// seedStaleStoppedSupersede sets up the resume-vs-fresh recovery scenario: a
// stale STOPPED journal pinned to 2.0.0 (target A, current still 1.0.0), then a
// newer 3.0.0 (target B) staged + published so the version compare supersedes
// the stale cut and drives recovery. It also drops a partial version dir so a
// test can prove removeAllPartials did / did not run. Returns the runner, cfg,
// and the seeded partial dir path.
func seedStaleStoppedSupersede(t *testing.T, fs *fakeSystem) (*Runner, Config, string) {
	t.Helper()
	r, cfg := testEnv(t, fs) // publishes gen of fs.stagedVersion (2.0.0)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	sg := r.stagedGenConfig()
	gOld, _ := sg.ResolveCurrent()

	// A STOPPED journal pinned to the OLD 2.0.0 generation: the cut stopped the
	// daemon but never flipped `current` (still 1.0.0).
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := os.WriteFile(filepath.Join(verDir, stagedgen.SrcGenFile), []byte(gOld+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jStale := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		State: StateStopped, SourceGeneration: gOld}
	if err := r.saveJournal(jStale); err != nil {
		t.Fatal(err)
	}
	// The cut stopped the unit before the interruption. (A restarted old daemon
	// would report its kernel-resolved versions/1.0.0/xpfd executable, never
	// the sbin symlink testEnv seeds as the running path.)
	fs.unitRunning = false
	fs.runningUnitExe = ""

	// Partial-dir evidence that removeAllPartials would sweep.
	partial := filepath.Join(cfg.VersionsDir, partialPrefix+"stale-cut"+partialSuffix)
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatal(err)
	}

	// A newer apt install stages + publishes a NEW-version generation (3.0.0).
	fs.stagedVersion = "3.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-3.0.0")
	}
	if _, err := sg.Publish(); err != nil {
		t.Fatal(err)
	}
	return r, cfg, partial
}

// TestCut_StaleStoppedRecoveryRestartFailsAborts_5846 pins the fail-closed
// contract: if the known-good daemon restart FAILS during stale-STOPPED
// recovery, Run aborts (returns the error) and does NOT proceed into a fresh cut
// to B, and the stale journal + partials are preserved.
//
// FAIL-ON-REVERT: revert to swallowing the StartUnit error (log + fall through)
// and this goes RED — Run proceeds to a successful 3.0.0 cut (current becomes
// 3.0.0), returns nil, and the journal/partial are gone.
func TestCut_StaleStoppedRecoveryRestartFailsAborts_5846(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg, partial := seedStaleStoppedSupersede(t, fs)

	// The known-good restart during recovery FAILS.
	fs.startFailOnce = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("recovery must abort when the known-good daemon restart fails; got nil " +
			"(the #5846 fail-open: a fresh cut with an unverified rollback target while down)")
	}
	if !strings.Contains(err.Error(), "control plane is down") ||
		!strings.Contains(err.Error(), "unverified rollback target") {
		t.Fatalf("abort error must explain the unverified-rollback-while-down refusal, got %v", err)
	}

	// The fresh cut to 3.0.0 must NOT have run: `current` unchanged, and no cut
	// steps (verify / dropin / stop) for 3.0.0 fired after the failed restart.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "1.0.0" {
		t.Fatalf("current = %q; the fresh cut must not have flipped — want 1.0.0 (known-good)", cur)
	}
	for _, step := range []string{"verify", "dropin"} {
		for _, c := range fs.calls {
			if c == step {
				t.Fatalf("fresh cut step %q fired after the failed restart; recovery must abort BEFORE the new cut (calls=%v)", step, fs.calls)
			}
		}
	}

	// The stale journal must be PRESERVED (not reset), so the next boot / operator
	// re-runs recovery.
	j, jerr := r.loadJournal()
	if jerr != nil {
		t.Fatalf("stale journal must be preserved for recovery; loadJournal: %v", jerr)
	}
	if j.State != StateStopped || j.TargetVersion != "2.0.0" {
		t.Fatalf("stale journal = {State:%v Target:%s}; must be preserved as {Stopped 2.0.0}", j.State, j.TargetVersion)
	}

	// Partials must be PRESERVED (removeAllPartials must not have run).
	if _, serr := os.Stat(partial); serr != nil {
		t.Fatalf("partial dir was swept despite the aborted recovery: %v", serr)
	}
}

// TestCut_StaleStoppedRecoveryRestartSucceedsProceeds_5846 pins the unchanged
// happy path: when the known-good restart SUCCEEDS, recovery proceeds to the
// fresh cut to B exactly as before (current flips to 3.0.0, no error).
func TestCut_StaleStoppedRecoveryRestartSucceedsProceeds_5846(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg, partial := seedStaleStoppedSupersede(t, fs)

	// startFailOnce unset: the known-good restart SUCCEEDS, so recovery proceeds.
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("recovery with a successful known-good restart must proceed to the fresh cut, got %v", err)
	}
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "3.0.0" {
		t.Fatalf("current = %q after a successful-restart recovery, want 3.0.0 (fresh cut proceeded)", cur)
	}
	// The fresh cut swept the stale partial.
	if _, serr := os.Stat(partial); serr == nil {
		t.Errorf("partial dir survived a successful recovery+cut; removeAllPartials should have swept it")
	}
}
