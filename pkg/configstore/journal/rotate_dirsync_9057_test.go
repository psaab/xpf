package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9057: the NAMESPACE fsync must run on the rotation path EVEN WHEN the
// preceding file sync failed.
//
// This is the shape an outcome-only assertion cannot see. An fsync leaves no
// artifact — you cannot look at the filesystem afterwards and tell whether the
// directory was synced — so the only way to assert it ran is to observe the
// call. Hence the syncDir seam, mirroring the syncFile one beside it.
//
// The defect was control flow, not a missing helper: journal.go KNEW about
// fsatomic.SyncDir and called it, but the call sat after an early `return` on
// a sync(f) failure. So a data-sync failure silently also skipped the
// namespace fsync — and those are independent durability facts. The rotation
// renamed x -> x.1; losing that entry across an unclean shutdown is a
// different loss from losing the tail of the file.
func TestJournalRotateSyncsDirEvenWhenFileSyncFails9057(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.journal")
	// One byte forces a rotation on every append after the first.
	j := New(path, WithMaxSegmentBytes(1))

	// Seed one entry so a segment exists to rotate.
	mustLogJournal9057(t, j)

	errFileSync := errors.New("injected file-sync failure")
	var dirSyncs []string
	j.syncFile = func(*os.File) error { return errFileSync }
	j.syncDir = func(d string) error {
		dirSyncs = append(dirSyncs, d)
		return nil
	}

	err := j.Log(&Entry{Action: "commit", Detail: "rotates"})
	if err == nil {
		t.Fatal("#9057: Log returned nil despite an injected file-sync failure; " +
			"the fixture is not reaching the sync path at all")
	}
	if !errors.Is(err, errFileSync) {
		t.Errorf("#9057: error = %v, want it to still carry the file-sync failure. "+
			"Running the directory fsync must not SWALLOW the data-sync error — "+
			"both are reported or the caller learns the wrong thing.", err)
	}
	if len(dirSyncs) == 0 {
		t.Fatal("#9057: the directory fsync did NOT run after a failed file sync. " +
			"The rotation renamed the segment, so the namespace change is unsynced " +
			"and an unclean shutdown can lose which generation a name points at — " +
			"a loss independent of the file-sync failure that preempted it.")
	}
	if got, want := dirSyncs[0], filepath.Dir(path); got != want {
		t.Errorf("#9057: synced %q, want the journal's own directory %q", got, want)
	}
}

// The control: with a HEALTHY file sync the directory fsync still runs, and
// its failure is reported. Without this, a fix that ran the dir sync only on
// the error path would satisfy the cell above while breaking the normal path.
func TestJournalRotateReportsDirSyncFailure9057(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.journal")
	j := New(path, WithMaxSegmentBytes(1))
	mustLogJournal9057(t, j)

	errDirSync := errors.New("injected dir-sync failure")
	j.syncDir = func(string) error { return errDirSync }

	err := j.Log(&Entry{Action: "commit", Detail: "rotates"})
	if !errors.Is(err, errDirSync) {
		t.Fatalf("#9057: error = %v, want the directory-fsync failure surfaced on the "+
			"HEALTHY file-sync path. If it is not, the dir sync is only reached when "+
			"the file sync fails, which is the mirror image of the original defect.", err)
	}
	if strings.Contains(err.Error(), "injected file-sync") {
		t.Errorf("#9057: the error mentions a file-sync failure that did not happen: %v", err)
	}
}

// TestJournalRotationSyncSurvivesPostRotateOpenFailure10723 pins the failure
// after namespace mutation: a failed append must not discard the rotated fact
// or defer the directory barrier until a later append.
func TestJournalRotationSyncSurvivesPostRotateOpenFailure10723(t *testing.T) {
	// RED-on-revert: losing the rotated fact skips the only directory sync after
	// an open failure, leaving the renamed segment vulnerable across a crash.
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.journal")
	j := New(path, WithMaxSegmentBytes(1))
	mustLogJournal9057(t, j)

	openErr := errors.New("injected post-rotation open failure")
	j.openFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, openErr
	}
	var synced []string
	j.syncDir = func(d string) error {
		synced = append(synced, d)
		return nil
	}

	err := j.Log(&Entry{Action: "commit", Detail: "must rotate"})
	if !errors.Is(err, openErr) {
		t.Fatalf("Log error = %v, want the injected append-open failure", err)
	}
	if len(synced) != 1 || synced[0] != filepath.Dir(path) {
		t.Fatalf("post-rotation append failure synced dirs %v, want [%q]",
			synced, filepath.Dir(path))
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotation did not leave segment .1: %v", err)
	}
}


func mustLogJournal9057(t *testing.T, j *Journal) {
	t.Helper()
	if err := j.Log(&Entry{Action: "commit", Detail: "seed"}); err != nil {
		t.Fatalf("seed Log: %v", err)
	}
}
