package dhcpserver

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #9601: a burst of MASTER-edge applies restarted kea-dhcp4-server often
// enough to hit its systemd start limit. Every later restart, including the
// #6535 converger's retry, was refused with "start of the service was attempted
// too often", and Kea stayed down on the node that should serve.

// startLimitedSystemd models a unit already past its start limit: a restart is
// refused until reset-failed clears the failed state. With alwaysFail the unit
// is broken for another reason and a restart fails even after the reset.
type startLimitedSystemd struct {
	limited    bool
	alwaysFail bool
	calls      []string
}

func (s *startLimitedSystemd) run(args ...string) error {
	c := strings.Join(args, " ")
	s.calls = append(s.calls, c)
	switch {
	case args[0] == "reset-failed":
		s.limited = false
		return nil
	case args[0] == "restart" && (s.limited || s.alwaysFail):
		return fmt.Errorf("systemctl %s: exit status 1: Job for %s.service failed because "+
			"start of the service was attempted too often", c, args[1])
	}
	return nil
}

func startLimitedManager(t *testing.T, sd *startLimitedSystemd) *Manager {
	t.Helper()
	dir := t.TempDir()
	return NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		sd.run,
		func(string) bool { return false },
	)
}

// TestApplyRecoversAUnitPastItsStartLimit_9601 is the measured failure: the
// unit refuses restarts, and the apply must reset it and bring it up rather
// than return the refusal.
func TestApplyRecoversAUnitPastItsStartLimit_9601(t *testing.T) {
	sd := &startLimitedSystemd{limited: true}
	m := startLimitedManager(t, sd)
	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply returned the start-limit refusal instead of recovering the unit: %v (calls %v)", err, sd.calls)
	}
	want := []string{"restart " + kea4Svc, "reset-failed " + kea4Svc, "restart " + kea4Svc}
	if strings.Join(sd.calls, "|") != strings.Join(want, "|") {
		t.Errorf("systemctl calls = %v, want %v", sd.calls, want)
	}
	if m.ClaimApplyRetry(time.Now()) {
		t.Error("a recovered apply must not leave a converger retry pending")
	}
}

// TestApplyStillFailsForAUnitBrokenForAnotherReason_9601 bounds the recovery:
// one reset and one extra restart, then the failure is returned and stays
// retryable. A reset must not hide a genuinely broken Kea.
func TestApplyStillFailsForAUnitBrokenForAnotherReason_9601(t *testing.T) {
	sd := &startLimitedSystemd{alwaysFail: true}
	m := startLimitedManager(t, sd)
	err := m.Apply(v4Config("ge-0-0-0"))
	if err == nil {
		t.Fatal("Apply must fail when the unit cannot start even after reset-failed")
	}
	if !strings.Contains(err.Error(), "after reset-failed") || !strings.Contains(err.Error(), kea4Svc) {
		t.Errorf("error must name the unit and the post-reset attempt: %v", err)
	}
	restarts, resets := 0, 0
	for _, c := range sd.calls {
		switch c {
		case "restart " + kea4Svc:
			restarts++
		case "reset-failed " + kea4Svc:
			resets++
		}
	}
	if restarts != 2 || resets != 1 {
		t.Errorf("want exactly 2 restarts and 1 reset-failed, got %d and %d (%v)", restarts, resets, sd.calls)
	}
	if !m.ClaimApplyRetry(time.Now()) {
		t.Error("a failed apply must stay claimable by the converger")
	}
}

// TestHealthyRestartDoesNotResetFailedState_9601 is the negative control: a
// restart that succeeds issues no reset-failed.
func TestHealthyRestartDoesNotResetFailedState_9601(t *testing.T) {
	sd := &startLimitedSystemd{}
	m := startLimitedManager(t, sd)
	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, c := range sd.calls {
		if strings.HasPrefix(c, "reset-failed") {
			t.Fatalf("a healthy restart issued %q (calls %v)", c, sd.calls)
		}
	}
}

// TestClusterCommitRecoversAnActiveUnitPastItsStartLimit_9601 covers the other
// measured symptom: a commit whose apply found the unit active but could not
// restart it failed with the start-limit error.
func TestClusterCommitRecoversAnActiveUnitPastItsStartLimit_9601(t *testing.T) {
	sd := &startLimitedSystemd{limited: true}
	dir := t.TempDir()
	m := NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		sd.run,
		func(unit string) bool { return unit == kea4Svc },
	)
	if err := m.ApplyClusterCommit(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("cluster commit failed on a start-limited unit: %v (calls %v)", err, sd.calls)
	}
}
