package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// injectCurrentReadlinkFailure replaces the `current` symlink lookup with a
// NON-ENOENT failure (EIO/EINVAL-class: the directory mutation/read of the
// versions tree still works, but resolving `current` is indeterminate) and
// restores the production seam on cleanup. This is the decisive fixture from
// #14166: an indeterminate live-version lookup must never be collapsed to
// "no live version, therefore deletable".
func injectCurrentReadlinkFailure(t *testing.T, err error) {
	t.Helper()
	orig := readlinkCurrent
	readlinkCurrent = func(string) (string, error) { return "", err }
	t.Cleanup(func() { readlinkCurrent = orig })
}

// TestGC_IndeterminateCurrentDefersDeletion_14166 proves that GC fails closed
// when the live (`current`) version cannot be determined: it must return an
// error and delete NOTHING — in particular not the version `current` actually
// points at, even when that version lies past the N=3 retention window and
// is named by neither TargetVersion nor PreviousVersion.
//
// FAIL-ON-REVERT: revert gc to `cur, _ := r.readCurrentVersion()` and the
// unprotected 1.0.0 (the real live version, oldest by committed stamp) is
// removed by retention and gc returns nil — both assertions go RED.
func TestGC_IndeterminateCurrentDefersDeletion_14166(t *testing.T) {
	fs := newFakeSystem(t, "5.0.0")
	r, cfg := testEnv(t, fs)
	fx := &rollbackFixture{r: r, cfg: cfg}
	// Five committed versions; 1.0.0 is oldest.
	for i := 1; i <= 5; i++ {
		ver := fmt.Sprintf("%d.0.0", i)
		writeCompleteVersionDir(t, cfg, ver)
		predecessor := ""
		if i > 1 {
			predecessor = fmt.Sprintf("%d.0.0", i-1)
		}
		stampCommittedForTest(t, fx, ver, predecessor, int64(i*100))
	}
	// The LIVE version is 1.0.0 (e.g. an old daemon never cut over from, or
	// rolled back outside this journal). The journal in play names only the
	// newest pair, so 1.0.0 is protected SOLELY by the `current` resolution —
	// and it sits past the N=3 retention window.
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected EIO reading current symlink")
	injectCurrentReadlinkFailure(t, injected)

	err := r.gc(&Journal{TargetVersion: "5.0.0", PreviousVersion: "4.0.0"})
	if err == nil {
		t.Fatal("gc succeeded with an indeterminate `current`; want an error surfacing the failed live-version lookup")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("gc error = %v, want it to wrap the injected lookup failure", err)
	}
	// Nothing may be deleted while the live version is unknown — neither the
	// actual live dir past retention, nor any other dir (deletion is deferred
	// wholesale, not merely re-targeted).
	for i := 1; i <= 5; i++ {
		ver := fmt.Sprintf("%d.0.0", i)
		if _, serr := os.Stat(filepath.Join(cfg.VersionsDir, ver, "xpfd")); serr != nil {
			t.Errorf("version %s deleted by GC with indeterminate `current`: %v", ver, serr)
		}
	}

	// Control: with the lookup restored, the same GC succeeds and retention
	// prunes the unprotected old versions — proving the failure above was the
	// injected indeterminacy, not fixture breakage, and that 1.0.0 is now
	// protected by the healthy `current` read.
	readlinkCurrent = os.Readlink
	if err := r.gc(&Journal{TargetVersion: "5.0.0", PreviousVersion: "4.0.0"}); err != nil {
		t.Fatalf("gc with healthy `current` read: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")); serr != nil {
		t.Errorf("live version 1.0.0 not retained with healthy `current`: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(cfg.VersionsDir, "2.0.0")); !os.IsNotExist(serr) {
		t.Errorf("unprotected old version 2.0.0 survived healthy GC (stat err=%v)", serr)
	}
}

// TestVerifyFailCleanup_IndeterminateCurrentKeepsLiveTarget_14166 proves the
// verify-failure cleanup twin: when the target IS the live version but
// differs from PreviousVersion, and the `current` lookup fails with a
// non-ENOENT error, cleanup must NOT delete the target dir. It must still
// rewind the journal so a retry re-enters cleanly.
//
// FAIL-ON-REVERT: revert cleanupFailedVerifyCopy to `cur, _ := ...` and the
// live 2.0.0 dir is RemoveAll'd (2.0.0 != PreviousVersion 1.0.0, cur lost) —
// the survival assertion goes RED.
func TestVerifyFailCleanup_IndeterminateCurrentKeepsLiveTarget_14166(t *testing.T) {
	fs := newFakeSystem(t, "3.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)

	// Live version is 2.0.0; build versions/3.0.0 as the just-copied target.
	// (Also the subject below once `current` is repointed at it.)
	seedInitialCurrent(t, r, cfg, "2.0.0")
	targetDir := filepath.Join(cfg.VersionsDir, "3.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(targetDir, b), "binary-"+b+"-3.0.0")
	}
	// Repoint `current` at 3.0.0 so the target IS the live version, distinct
	// from PreviousVersion (1.0.0): deletion then hinges solely on the
	// (about-to-fail) `current` resolution.
	if err := os.Remove(currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("3.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	injectCurrentReadlinkFailure(t, errors.New("injected EIO reading current symlink"))

	var logs []string
	origLogf := r.cfg.Logf
	r.cfg.Logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
		origLogf(format, args...)
	}

	j := &Journal{State: StateCopied, TargetVersion: "3.0.0", PreviousVersion: "1.0.0"}
	r.cleanupFailedVerifyCopy(j)

	// The live target dir must survive intact.
	if _, err := os.Stat(filepath.Join(targetDir, "xpfd")); err != nil {
		t.Fatalf("live target dir deleted by verify-fail cleanup with indeterminate `current`: %v", err)
	}
	// The skip must be surfaced (logged), not silent.
	surfaced := false
	for _, l := range logs {
		if strings.Contains(l, "verify-fail cleanup SKIPPED") {
			surfaced = true
		}
	}
	if !surfaced {
		t.Errorf("indeterminate-`current` cleanup skip was not logged; logs=%v", logs)
	}
	// The journal must still be rewound to INIT so the retry re-runs copy
	// + verify once the lookup recovers.
	if j.State != StateInit {
		t.Errorf("journal state = %s after indeterminate cleanup, want INIT (rewound for retry)", j.State)
	}
	persisted, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != StateInit {
		t.Errorf("persisted journal state = %s, want INIT", persisted.State)
	}
}

// TestGC_AbsentCurrentStillRuns_14166 pins the tolerated/strict boundary:
// a GENUINELY ABSENT `current` (readCurrentVersion returns ("", nil)) is not
// indeterminate — GC must proceed with journal-protected retention exactly
// as before, not fail closed on a legitimate first-install tree.
func TestGC_AbsentCurrentStillRuns_14166(t *testing.T) {
	fs := newFakeSystem(t, "5.0.0")
	r, cfg := testEnv(t, fs)
	fx := &rollbackFixture{r: r, cfg: cfg}
	for i := 1; i <= 5; i++ {
		ver := fmt.Sprintf("%d.0.0", i)
		writeCompleteVersionDir(t, cfg, ver)
		predecessor := ""
		if i > 1 {
			predecessor = fmt.Sprintf("%d.0.0", i-1)
		}
		stampCommittedForTest(t, fx, ver, predecessor, int64(i*100))
	}
	// No `current` symlink at all.
	if _, err := os.Lstat(currentLinkPath(cfg)); !os.IsNotExist(err) {
		t.Fatalf("premise: `current` should be absent, lstat err=%v", err)
	}
	if err := r.gc(&Journal{TargetVersion: "5.0.0", PreviousVersion: "4.0.0"}); err != nil {
		t.Fatalf("gc with genuinely absent `current`: %v", err)
	}
	for _, ver := range []string{"3.0.0", "4.0.0", "5.0.0"} {
		if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ver)); err != nil {
			t.Errorf("retained version %s missing after absent-current GC: %v", ver, err)
		}
	}
	for _, ver := range []string{"1.0.0", "2.0.0"} {
		if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ver)); !os.IsNotExist(err) {
			t.Errorf("old version %s survived absent-current GC (stat err=%v)", ver, err)
		}
	}
}
