package configstore

import (
	"strings"
	"testing"
)

// #15144 (B01-03): a commit description carrying control characters was
// accepted verbatim and later printed raw by `show system commit history`,
// forging history rows and injecting terminal escapes. The store boundary
// must reject it before persist/promote, exactly like the #4891 length cap.
//
// FAIL-ON-REVERT: drop the control-character check in
// commitWithDescriptionLocked and every hostile description below commits
// successfully and lands in history/journal.

func TestCommitWithDescriptionRejectsControlChars15144(t *testing.T) {
	hostile := []string{
		"ok\n  9  2000-01-01 00:00:00  commit  forged row",
		"ok\rforged",
		"ok\x1b[31mred\x1b]52;c;AAAA\x07",
		"ok\x00nul",
		"ok\x7fdel",
		"ok\x85c1",
		"ok\u2028forged",
		"ok\u2029forged",
		"ok\xffinvalid-utf8",
		"ok\ttab",
	}
	for _, desc := range hostile {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24"); err != nil {
			t.Fatalf("SetFromInput: %v", err)
		}
		cfg, err := s.CommitWithDescription(desc)
		if err == nil {
			t.Fatalf("CommitWithDescription(%q) accepted — must reject control characters (#15144)", desc)
		}
		if cfg != nil {
			t.Errorf("rejected commit %q returned non-nil config", desc)
		}
		if !strings.Contains(err.Error(), "control") {
			t.Errorf("error for %q = %q, want mention of control characters", desc, err)
		}
		if h := s.ListHistory(); len(h) != 0 {
			t.Errorf("rejected commit %q pushed %d history entries, want 0", desc, len(h))
		}
		entries, err := s.ListCommitHistory(10)
		if err != nil {
			t.Fatalf("ListCommitHistory: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("rejected commit %q wrote %d journal entries, want 0", desc, len(entries))
		}
	}

	// Control: legitimate descriptions (including multibyte UTF-8 and
	// punctuation) still commit and are recorded verbatim.
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("interfaces eth0 unit 0 family inet address 10.0.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	const legit = "rotated vpn psk — café 2026 (site A)"
	if _, err := s.CommitWithDescription(legit); err != nil {
		t.Fatalf("CommitWithDescription(legit) = %v, want success", err)
	}
	entries, err := s.ListCommitHistory(10)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	if len(entries) != 1 || entries[0].Detail != legit {
		t.Fatalf("journal entries = %+v, want one entry with Detail %q", entries, legit)
	}
}
