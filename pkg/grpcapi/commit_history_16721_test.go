package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16721: the gRPC ShowText `show system commit history` renderer must
// match the CLI surface: most-recent-first, rollback-slot labels, and
// <rollback pending> while a commit-confirmed window is armed.
//
// RED on revert: restoring the oldest-first loop-index loop in
// showCommitHistory flips the order/labels and drops the pending line.
func TestShowCommitHistory16721(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ host, desc string }{
		{"one", "set-one"}, {"two", "set-two"}, {"three", "set-three"},
	} {
		if err := store.SetFromInput("system host-name " + tc.host); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CommitWithDescription(tc.desc); err != nil {
			t.Fatal(err)
		}
	}
	srv := &Server{store: store}
	var buf strings.Builder
	if err := srv.showCommitHistory(&buf); err != nil {
		t.Fatalf("showCommitHistory: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("history lines = %d, want 3: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "set-three") || !strings.HasPrefix(lines[0], "   0  ") {
		t.Errorf("first row must be slot 0 set-three, got %q", lines[0])
	}
	if !strings.Contains(lines[2], "set-one") || !strings.HasPrefix(lines[2], "   2  ") {
		t.Errorf("last row must be label 2 set-one, got %q", lines[2])
	}
	if strings.Contains(out, "<rollback pending>") {
		t.Errorf("no window pending, must not show <rollback pending>: %q", out)
	}

	if err := store.SetFromInput("system host-name four"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	defer store.CancelConfirmTimerForTesting()
	buf.Reset()
	if err := srv.showCommitHistory(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<rollback pending>") {
		t.Errorf("pending window must render <rollback pending>: %q", buf.String())
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := srv.showCommitHistory(&buf); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	if strings.Contains(out, "<rollback pending>") {
		t.Errorf("confirmed window must not render <rollback pending>: %q", out)
	}
	if !strings.Contains(out, "commit_confirm") {
		t.Errorf("history must show the commit_confirm row: %q", out)
	}
}
