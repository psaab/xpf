package cluster

import (
	"testing"
	"time"
)

// #18597: a restart that follows a control-link VRF move loses a 5-30 ms race
// with networkd re-adding the address after the enslave cycle. With a flat 1s
// retry that cost a 1.6s heartbeat gap at the peer on the tcp cluster, above
// the lab's 1s threshold. The schedule must retry within the first 100ms, and
// keep the total window the restart grace is sized to.
//
// FAIL-ON-REVERT: restore a flat heartbeatRestartRetryDelay pause and the
// first-pause bound reds; shorten the schedule and the window bound reds.
func TestHeartbeatRestartRetriesEarlyAndKeepsTheWindow18597(t *testing.T) {
	if got := heartbeatRestartRetryPause(0); got > 100*time.Millisecond {
		t.Fatalf("first retry pause = %v, want <= 100ms: the address networkd re-adds after a VRF "+
			"enslave cycle is back within ~30ms, and a 1s first pause becomes a heartbeat gap above "+
			"the peer's threshold", got)
	}
	var total time.Duration
	for i := range len(heartbeatRestartRetrySchedule) {
		p := heartbeatRestartRetryPause(i)
		if p <= 0 || p > time.Second {
			t.Fatalf("retry pause %d = %v, want within (0, 1s]", i, p)
		}
		total += p
	}
	if total < 4500*time.Millisecond || total > heartbeatRestartGrace {
		t.Fatalf("retry window = %v, want about 5s and no longer than the %v restart grace", total, heartbeatRestartGrace)
	}
	old := heartbeatRestartRetryDelay
	heartbeatRestartRetryDelay = time.Millisecond
	defer func() { heartbeatRestartRetryDelay = old }()
	for i := range len(heartbeatRestartRetrySchedule) {
		if p := heartbeatRestartRetryPause(i); p != time.Millisecond {
			t.Fatalf("pause %d = %v with the test cap set, want the 1ms cap (the #9751 cells rely on it)", i, p)
		}
	}
}

// The restart loop must actually use the schedule: a first bind that fails
// (here: a VRF device that does not exist) and a second that succeeds must
// complete in well under the old flat 1s pause.
func TestHeartbeatRestartRecoversFromAFirstBindFailureQuickly18597(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)
	var attempts int
	m.SetHeartbeatVRFDeviceFunc(func(string) string {
		attempts++
		if attempts == 1 {
			return "r18597-novrf" // SO_BINDTODEVICE fails: no such device
		}
		return ""
	})
	start := time.Now()
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat failed")
	}
	elapsed := time.Since(start)
	if attempts != 2 {
		t.Fatalf("precondition: %d bind attempts, want 2 (first must fail, second succeed)", attempts)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("restart after one failed bind took %v, want < 500ms: the heartbeat is silent for "+
			"that long, and the old flat 1s pause pushed it past the peer's threshold", elapsed)
	}
}
