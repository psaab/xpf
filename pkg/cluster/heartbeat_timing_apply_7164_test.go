package cluster

import (
	"testing"
	"time"
)

// #7164: a committed heartbeat interval/threshold must reach the RUNNING
// heartbeat.
//
// StartHeartbeat snapshots m.hbInterval/m.hbThreshold into the sender and
// receiver; UpdateConfig rewrites the manager fields on every commit; and
// RestartHeartbeat had exactly ONE production caller — the VRF-rebind path. So
// `set chassis cluster heartbeat-interval` updated the manager and never
// reached the wire, and peers declared death too early or too late relative to
// the committed configuration until some unrelated event rebuilt the heartbeat.
//
// WHAT THE FIXTURE HAS TO SEPARATE. liveHeartbeatTimingLocked FALLS BACK to the
// desired values when no receiver exists, so `live == desired` is true both when
// the timing is already correct AND when there is no heartbeat running at all.
// A test that only checked "does it restart when they differ" would be satisfied
// by an implementation that restarted on every commit, and one that only checked
// the no-op case would be satisfied by an implementation that never restarted.
// Both states are therefore exercised explicitly, with a running receiver
// present in exactly the cells that need one.

// installReceiverWithTiming fakes a RUNNING heartbeat whose live timing is the
// given pair. Only the timing fields are read by the predicate under test, so no
// socket or goroutine is needed — which also keeps the cell free of the bind
// races a real StartHeartbeat would introduce.
func installReceiverWithTiming(m *Manager, interval time.Duration, threshold int) {
	m.mu.Lock()
	m.hbReceiver = &heartbeatReceiver{interval: interval, threshold: threshold}
	m.mu.Unlock()
}

func TestCommittedHeartbeatTimingIsAppliedToARunningHeartbeat7164(t *testing.T) {
	cases := []struct {
		name                       string
		running                    bool
		liveInterval, wantInterval time.Duration
		liveThreshold, wantThresh  int
		expectRestartAttempt       bool
		why                        string
	}{
		{
			name: "interval_changed_restarts", running: true,
			liveInterval: 200 * time.Millisecond, wantInterval: 50 * time.Millisecond,
			liveThreshold: 5, wantThresh: 5,
			expectRestartAttempt: true,
			why:                  "a committed interval that differs from the live one must reach the wire",
		},
		{
			name: "threshold_changed_restarts", running: true,
			liveInterval: 200 * time.Millisecond, wantInterval: 200 * time.Millisecond,
			liveThreshold: 5, wantThresh: 3,
			expectRestartAttempt: true,
			why:                  "threshold is snapshotted into the receiver too, so it must also re-time",
		},
		{
			// The no-op cell. Without it, restarting on EVERY commit passes the
			// two cells above — and a heartbeat restart per commit is a
			// recurring socket teardown window for no reason.
			name: "unchanged_is_a_no_op", running: true,
			liveInterval: 200 * time.Millisecond, wantInterval: 200 * time.Millisecond,
			liveThreshold: 5, wantThresh: 5,
			expectRestartAttempt: false,
			why:                  "an unrelated commit must not restart a correctly-timed heartbeat",
		},
		{
			// The cell the fallback makes necessary: with no receiver,
			// liveHeartbeatTimingLocked RETURNS the desired values, so a naive
			// comparison sees no difference for the wrong reason. Asserting
			// no-restart here pins that "not running" is handled explicitly
			// rather than by that coincidence.
			name: "not_running_is_a_no_op", running: false,
			liveInterval: 0, wantInterval: 50 * time.Millisecond,
			liveThreshold: 0, wantThresh: 3,
			expectRestartAttempt: false,
			why: "with no heartbeat running there is nothing to re-time; the next " +
				"StartHeartbeat adopts the committed values on its own",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{}
			m.hbInterval = tc.wantInterval
			m.hbThreshold = tc.wantThresh
			if tc.running {
				installReceiverWithTiming(m, tc.liveInterval, tc.liveThreshold)
			}

			// RestartHeartbeat needs a bound heartbeat to actually restart; with
			// none it returns false. What this cell observes is whether the
			// predicate DECIDED to restart, which is exactly the #7164 property
			// — the restart mechanism itself is already covered by the
			// VRF-rebind path's own tests.
			m.mu.RLock()
			restarted := m.heartbeatTimingDivergedLocked()
			m.mu.RUnlock()
			if restarted != tc.expectRestartAttempt {
				t.Errorf("timing-diverged = %v, want %v — %s",
					restarted, tc.expectRestartAttempt, tc.why)
			}
		})
	}
}

// ApplyCommittedHeartbeatTiming must be safe to call when nothing is running,
// which is every standalone node and every pre-bringup commit. A panic here
// would turn an ordinary commit into a daemon crash on a non-clustered box.
func TestApplyCommittedHeartbeatTimingIsSafeWithNoHeartbeat7164(t *testing.T) {
	m := &Manager{hbInterval: 50 * time.Millisecond, hbThreshold: 3}
	if m.ApplyCommittedHeartbeatTiming() {
		t.Error("with no heartbeat running there is nothing to restart")
	}
}
