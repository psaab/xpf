package configstore

import (
	"path/filepath"
	"testing"
	"time"
)

// #10967: a nested no-op re-arm (candidate identical to active) writes a
// provisional record with GuardedHash == PreviousHash. A crash between the
// provisional write and the active write must recover against the EXPIRED
// prior deadline (roll back to Base), not re-arm the expired window on the
// candidate's future deadline. Pre-fix the alias branch required
// GuardedHash != activeHash, which the equal-hash shape defeats by equality.
func TestEqualHashNestedRearmCrashRecoversExpiredPriorDeadline_10967(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("SetFromInput baseline: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}
	// Arm a Pending window, then let its deadline expire without confirming.
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput pending: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed arm: %v", err)
	}
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}
	s.confirmDeadline = time.Now().Add(-time.Minute)

	// Stage an UNCHANGED candidate (no-op vs active) and crash at the
	// provisional-record write of the nested re-arm.
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput no-op candidate: %v", err)
	}
	crashCommitConfirmedAtStage(t, s, commitConfirmedStageRecord)
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load after simulated crash: %v", err)
	}
	got := restarted.ActiveConfig()
	if got == nil {
		t.Fatal("recovered active config is nil")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("equal-hash re-arm crash recovered %q; want Base (expired prior window must roll back)", got.System.HostName)
	}
	if restarted.IsConfirmPending() {
		t.Fatal("expired prior window was re-armed instead of rolling back")
	}
}
