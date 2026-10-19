package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #15281 D08-03: the audit journal was the one store writer the factory
// reset did not fence. After a completed zeroize erased .config.journal,
// a reboot/halt/power-off SystemAction in the daemon's stop window called
// LogSystemActionAs -> journalLog -> journal.Log (O_CREATE|O_APPEND) and
// RECREATED .config.journal with the prior tenant's principal (username,
// UID, login class, session, action — audit-only, no secrets).
//
// This test models the daemon sequence at the store boundary:
// QuiesceJournal (what daemon.factoryReset now calls before the wipe),
// then the wipe erasing .config.journal, then a SystemAction journal
// attempt. Post-fix the file must NOT be recreated. The control proves
// the same call DOES create the file without the fence, and that
// ResumeJournal (the failed-wipe path) restores journaling.
//
// RED on revert: drop the journalFenced check in journalLog (or the
// Fence check in journal.appendLocked) and the post-wipe
// LogSystemActionAs below recreates .config.journal — the stat trips.
func TestJournalFencePreventsRecreationAfterZeroize_15281(t *testing.T) {
	s := newTestStore(t)
	journalPath := filepath.Join(filepath.Dir(s.filePath), ".config.journal")
	principal := "source=grpc;uid=1000;user=prior-tenant;class=super-user;session=sha256:0123456789abcdef"

	// Pre-reset: a normal SystemAction journals durably (control that the
	// fixture path really writes .config.journal).
	s.LogSystemActionAs("reboot", principal)
	if _, err := os.Stat(journalPath); err != nil {
		t.Fatalf("pre-reset journal missing: %v", err)
	}

	// Daemon factory-reset sequence: fence BEFORE the wipe (as
	// daemon.factoryReset now does), then the wipe erases the journal.
	s.QuiesceJournal()
	if err := os.Remove(journalPath); err != nil {
		t.Fatalf("wipe journal: %v", err)
	}

	// Stop-window power action: must NOT recreate the journal.
	s.LogSystemActionAs("reboot", principal)
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf(".config.journal recreated after zeroize wipe (stat err=%v); prior-tenant principal leaked", err)
	}

	// Any other journal writer is fenced too, not just SystemAction:
	// journalLog is the single chokepoint every store audit write crosses.
	s.journalLog(&JournalEntry{Action: "commit", Detail: "post-reset", Principal: principal})
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf(".config.journal recreated by journalLog after fence (stat err=%v)", err)
	}

	// Failed-wipe resume: ResumeJournal must restore journaling, or a
	// failed zeroize would permanently silence the audit trail.
	s.ResumeJournal()
	s.LogSystemActionAs("reboot", principal)
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("journal not restored after ResumeJournal: %v", err)
	}
	if !strings.Contains(string(data), "system_action") || !strings.Contains(string(data), "prior-tenant") {
		t.Fatalf("resumed journal missing system_action entry: %q", data)
	}
}

// TestJournalFenceControl_15281 is the positive control: WITHOUT the
// fence, the identical post-wipe SystemAction DOES recreate the journal.
// This proves the fixture exercises the recreation mechanism, so the
// fenced test above cannot pass vacuously (e.g. if LogSystemActionAs
// were broken for an unrelated reason).
func TestJournalFenceControl_15281(t *testing.T) {
	s := newTestStore(t)
	journalPath := filepath.Join(filepath.Dir(s.filePath), ".config.journal")
	principal := "source=grpc;uid=1000;user=prior-tenant;class=super-user;session=sha256:0123456789abcdef"

	s.LogSystemActionAs("reboot", principal)
	if err := os.Remove(journalPath); err != nil {
		t.Fatalf("wipe journal: %v", err)
	}
	// No QuiesceJournal: the stop-window action recreates the file —
	// the exact #15281 D08-03 residue.
	s.LogSystemActionAs("reboot", principal)
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatalf("control: journal not recreated without fence: %v", err)
	}
	if !strings.Contains(string(data), "prior-tenant") {
		t.Fatalf("control: recreated journal missing prior-tenant principal: %q", data)
	}
}
