package grpcapi

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// Reset stop-monitor cells (#10769) stayed with the gRPC handler: the
// monitor (resetStopMonitor + its seams) lives in
// server_diag_system_action.go, not in the extracted pkg/factoryreset
// wipe (#16138).

func stubStopMonitor(t *testing.T, stopErr error, activeSeq []bool) {
	t.Helper()
	oldGrace, oldBudget, oldPoll := zeroizeStopGrace, zeroizeStopVerifyBudget, zeroizeStopVerifyPoll
	oldStop, oldActive := zeroizeStopDaemonUnit, zeroizeDaemonUnitActive
	oldFlag := configstore.ResetHandoffPath
	t.Cleanup(func() {
		zeroizeStopGrace, zeroizeStopVerifyBudget, zeroizeStopVerifyPoll = oldGrace, oldBudget, oldPoll
		zeroizeStopDaemonUnit, zeroizeDaemonUnitActive = oldStop, oldActive
		configstore.ResetHandoffPath = oldFlag
	})
	zeroizeStopGrace = 0
	zeroizeStopVerifyBudget = 50 * time.Millisecond
	zeroizeStopVerifyPoll = time.Millisecond
	zeroizeStopDaemonUnit = func() error { return stopErr }
	calls := 0
	zeroizeDaemonUnitActive = func() bool {
		if calls < len(activeSeq) {
			active := activeSeq[calls]
			calls++
			return active
		}
		return activeSeq[len(activeSeq)-1]
	}
	configstore.ResetHandoffPath = filepath.Join(t.TempDir(), ".reset-handoff")
}

func TestResetStopMonitorVerifiesStop10769(t *testing.T) {
	stubStopMonitor(t, nil, []bool{true, false})
	if err := resetStopMonitor(); err != nil {
		t.Fatalf("verified stop must be clean: %v", err)
	}
	if _, _, _, present, _ := configstore.ReadResetHandoff(); present {
		t.Fatal("verified stop must not write the handoff flag")
	}
}

func TestResetStopMonitorFlagsUnverifiedStop10769(t *testing.T) {
	t.Run("stop error", func(t *testing.T) {
		stubStopMonitor(t, errors.New("systemctl: connection refused"), []bool{false})
		// A nil return means the dirty condition was recorded, not that
		// the stop succeeded: the flag below is the signal.
		if err := resetStopMonitor(); err != nil {
			t.Fatalf("dirty marking must succeed: %v", err)
		}
		_, dirty, _, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || !strings.Contains(dirty, "stop failed") {
			t.Fatalf("stop error must mark dirty: present=%v dirty=%q err=%v", present, dirty, err)
		}
	})
	t.Run("still active past budget", func(t *testing.T) {
		stubStopMonitor(t, nil, []bool{true})
		if err := resetStopMonitor(); err != nil {
			t.Fatalf("dirty marking must succeed: %v", err)
		}
		_, dirty, _, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || !strings.Contains(dirty, "still active") {
			t.Fatalf("unverified stop must mark dirty: present=%v dirty=%q err=%v", present, dirty, err)
		}
	})
}
