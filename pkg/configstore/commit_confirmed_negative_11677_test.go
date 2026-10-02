package configstore

import "testing"

func TestCommitConfirmedRejectsNegativeMinutes_11677(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Candidate"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CommitConfirmed(-1); err == nil {
		t.Fatal("CommitConfirmed(-1) accepted; want rejection")
	}
	if s.IsConfirmPending() {
		t.Fatal("a negative timeout must not arm a confirm window")
	}
	if !s.IsDirty() {
		t.Fatal("a negative timeout must not promote the candidate")
	}

	// Zero is the existing "use the 10-minute default" value, unlike a
	// negative timeout.
	if _, err := s.CommitConfirmed(0); err != nil {
		t.Fatalf("CommitConfirmed(0) default should remain accepted: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("CommitConfirmed(0) should arm the default confirm window")
	}
}
