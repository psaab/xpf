package journal

import (
	"os"
	"path/filepath"
	"testing"
)

// #15281 D08-03 (journal layer): Fence must make Log a silent no-op that
// neither appends nor recreates the file, so a post-wipe SystemAction
// cannot resurrect .config.journal with the prior tenant's principal.
// Unfence (the failed-wipe path) must restore appending.
//
// RED on revert: drop the fenced check in appendLocked and the fenced
// Log below recreates the erased file — the stat trips.
func TestJournalFence_15281(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".config.journal")
	j := New(path)

	if err := j.Log(&Entry{Action: "system_action", Detail: "reboot", Principal: "user=prior-tenant"}); err != nil {
		t.Fatalf("pre-fence Log: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("pre-fence journal missing: %v", err)
	}

	j.Fence()
	if !j.Fenced() {
		t.Fatal("Fenced() = false after Fence()")
	}
	// Model the wipe, then the stop-window power action.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := j.Log(&Entry{Action: "system_action", Detail: "reboot", Principal: "user=prior-tenant"}); err != nil {
		t.Fatalf("fenced Log must be a silent no-op, got error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("fenced Log recreated the journal (stat err=%v)", err)
	}

	j.Unfence()
	if j.Fenced() {
		t.Fatal("Fenced() = true after Unfence()")
	}
	if err := j.Log(&Entry{Action: "system_action", Detail: "reboot", Principal: "user=prior-tenant"}); err != nil {
		t.Fatalf("post-Unfence Log: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("post-Unfence journal missing: %v", err)
	}
}
