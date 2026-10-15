package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedStaleFlipped13543 stages a healthy stale FLIPPED half-cut to 2.0.0
// (superseded by the staged 3.0.0) on top of a 1.0.0 live install.
func seedStaleFlipped13543(t *testing.T) (*fakeSystem, *Runner, Config) {
	t.Helper()
	fs := newFakeSystem(t, "3.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := r.flip("2.0.0"); err != nil {
		t.Fatal(err)
	}
	j := &Journal{State: StateFlipped, TargetVersion: "2.0.0", PreviousVersion: "1.0.0"}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	return fs, r, cfg
}

// TestStaleHalfCutFinishRecordsCommittedCut13543: finishing a healthy stale
// half-cut during a superseding Run is a real commit of that version, so it
// must record the same CommittedCut evidence as the COMMIT and
// already-committed paths (the #7431 downgrade-floor / status-clear gate
// consumes LastCommittedCut). Fail the subsequent fresh cut at PREFLIGHT so
// LastCommittedCut still describes the stale 2.0.0 finish.
func TestStaleHalfCutFinishRecordsCommittedCut13543(t *testing.T) {
	fs, r, _ := seedStaleFlipped13543(t)
	fs.healthHook = func() {
		// This runs only after the stale half-cut's health confirmation.
		fs.readerErr = errors.New("injected fresh preflight failure")
	}
	if err := r.Run(Options{}); err == nil || !strings.Contains(err.Error(), "injected fresh preflight failure") {
		t.Fatalf("stale finish + injected fresh cut failure = %v; want preflight failure", err)
	}
	if proof := r.LastCommittedCut(); !proof.healthConfirmed || proof.version != "2.0.0" {
		t.Fatalf("committed cut after stale finish = %+v; want health-confirmed 2.0.0", proof)
	}
}

// TestStaleHalfCutFinishClearJournalErrorSurfaces13543: a journal that
// cannot be removed after a healthy stale finish must fail the Run (as the
// COMMIT and already-committed paths do), not be discarded while the fresh
// cut proceeds on top of a lingering journal.
func TestStaleHalfCutFinishClearJournalErrorSurfaces13543(t *testing.T) {
	fs, r, cfg := seedStaleFlipped13543(t)

	replaced := false
	fs.healthHook = func() {
		if replaced {
			return
		}
		replaced = true
		// Replace the journal with a non-empty directory so
		// clearJournal's os.Remove fails deterministically.
		if err := os.Remove(cfg.JournalPath); err != nil {
			t.Fatalf("remove journal: %v", err)
		}
		if err := os.MkdirAll(cfg.JournalPath, 0o755); err != nil {
			t.Fatalf("mkdir journal path: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cfg.JournalPath, "occupant"), []byte("x"), 0o644); err != nil {
			t.Fatalf("occupy journal dir: %v", err)
		}
	}
	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "remove upgrade journal") {
		t.Fatalf("Run error = %v; want surfaced stale-cut journal-clear failure", err)
	}
	// The fresh cut must not have proceeded past the failed cleanup.
	for _, c := range fs.calls {
		if c == "health:3.0.0" {
			t.Fatalf("fresh cut proceeded after stale journal-clear failure; calls=%v", fs.calls)
		}
	}
	if proof := r.LastCommittedCut(); proof.healthConfirmed || proof.version != "" {
		t.Fatalf("failed stale finish exposed commit evidence %+v", proof)
	}
}
