package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16721: the in-process CLI `show system commit history` must render
// most-recent-first with rollback-slot labels, the confirming
// principal on commit_confirm rows, and <rollback pending> while a
// commit-confirmed window is armed.
//
// RED on revert: restoring the oldest-first loop-index loop in
// handleShowSystem flips the row order/labels and drops the pending
// line, failing every assertion below.
func TestShowSystemCommitHistory16721(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	c := &CLI{store: store}
	commit := func(host, desc string) {
		t.Helper()
		if _, err := store.LoadSet("set system host-name " + host); err != nil {
			t.Fatal(err)
		}
		if desc != "" {
			if err := c.handleCommit([]string{"comment", desc}); err != nil {
				t.Fatalf("commit %s: %v", desc, err)
			}
			return
		}
		if err := c.handleCommit(nil); err != nil {
			t.Fatalf("commit %s: %v", host, err)
		}
	}
	commit("one", "set-one")
	commit("two", "set-two")
	commit("three", "set-three")

	var runErr error
	out := captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"commit", "history"})
	})
	if runErr != nil {
		t.Fatalf("handleShowSystem(commit history): %v", runErr)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("history lines = %d, want 3: %q", len(lines), out)
	}
	// Most-recent-first: set-three (label 0, live) first; set-one
	// last with label 2 (rollback 2 stages the tree set-one's
	// successor displaced — positional Junos labelling, see
	// configstore.ListCommitHistoryRows).
	if !strings.Contains(lines[0], "set-three") || !strings.HasPrefix(lines[0], "   0  ") {
		t.Errorf("first row must be slot 0 set-three, got %q", lines[0])
	}
	if !strings.Contains(lines[2], "set-one") || !strings.HasPrefix(lines[2], "   2  ") {
		t.Errorf("last row must be label 2 set-one, got %q", lines[2])
	}
	if strings.Contains(out, "<rollback pending>") {
		t.Errorf("no window pending, must not show <rollback pending>: %q", out)
	}

	// Arm a window: pending marker appears; confirm it: a
	// commit_confirm row appears and the marker disappears.
	if _, err := store.LoadSet("set system host-name four"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit([]string{"confirmed", "5"}); err != nil {
		t.Fatalf("commit confirmed: %v", err)
	}
	defer store.CancelConfirmTimerForTesting()
	out = captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"commit", "history"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(out, "<rollback pending>") {
		t.Errorf("pending window must render <rollback pending>: %q", out)
	}

	// Bare commit with clean candidate = pure confirmation (#4000 path).
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("confirming bare commit: %v", err)
	}
	out = captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"commit", "history"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if strings.Contains(out, "<rollback pending>") {
		t.Errorf("confirmed window must not render <rollback pending>: %q", out)
	}
	if !strings.Contains(out, "commit_confirm") {
		t.Errorf("history must show the commit_confirm row: %q", out)
	}
	// The confirm row has no rollback slot (blank label). Match the
	// exact action token (commit_confirmed rows also contain the
	// substring "commit_confirm").
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.Contains(line, "  commit_confirm  ") && !strings.HasPrefix(line, "     ") {
			t.Errorf("commit_confirm row must have blank slot label, got %q", line)
		}
	}
}
