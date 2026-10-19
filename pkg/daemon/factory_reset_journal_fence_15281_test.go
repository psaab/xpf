package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15281 D08-03 (daemon wiring): factoryReset must fence the audit
// journal BEFORE the wipe, alongside QuiesceRescueWrites/QuiesceArchival.
// After a completed reset erased .config.journal, a reboot/halt/power-off
// SystemAction in the stop window (LogSystemActionAs -> journalLog)
// recreated it with the prior tenant's principal. This test drives the
// real factoryReset transaction with a real store: a successful reset
// leaves the journal fenced (a later SystemAction recreates nothing),
// and a failed reset resumes journaling (the box stays up).
//
// RED on revert: drop d.store.QuiesceJournal() from factoryReset and the
// post-wipe LogSystemActionAs below recreates .config.journal.
func TestFactoryResetFencesJournal_15281(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)

	dir := t.TempDir()
	store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	journalPath := filepath.Join(dir, ".config.journal")
	principal := "source=grpc;uid=1000;user=prior-tenant;class=super-user;session=sha256:0123456789abcdef"

	store.LogSystemActionAs("reboot", principal)
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("pre-reset journal missing: %v", err)
	}

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	wipe := func() error {
		if err := os.Remove(journalPath); err != nil {
			return err
		}
		return fakePendingWipe(t)()
	}
	if err := d.factoryReset(context.Background(), wipe); err != nil {
		t.Fatalf("factoryReset: %v", err)
	}
	if !d.isResetting() {
		t.Fatal("successful reset must enter the terminal reset generation")
	}

	// Stop-window power action: the journal must NOT be recreated.
	store.LogSystemActionAs("reboot", principal)
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf(".config.journal recreated after factory reset (stat err=%v); prior-tenant principal leaked", err)
	}
}

// TestFactoryResetFailedWipeResumesJournal_15281 pins the recoverable
// path: a failed wipe exits the reset generation and ResumeJournal
// restores journaling, so a still-running daemon keeps its audit trail.
func TestFactoryResetFailedWipeResumesJournal_15281(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)

	dir := t.TempDir()
	store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	journalPath := filepath.Join(dir, ".config.journal")

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
	wantErr := errors.New("wipe boom")
	if err := d.factoryReset(context.Background(), func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wantErr)
	}
	if d.isResetting() {
		t.Fatal("failed wipe must exit the reset generation")
	}

	store.LogSystemActionAs("reboot", "source=grpc;uid=1000;user=ops;class=super-user;session=none")
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("journal not resumed after failed reset: %v", err)
	}
}
