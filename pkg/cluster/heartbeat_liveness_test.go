package cluster

import (
	"sync/atomic"
	"testing"
	"time"
)

// #1792: peer-liveness decisions must be made in the CLOCK_MONOTONIC
// domain. These tests inject timestamps directly into the decision
// helpers, simulating forward/backward wall-clock steps: because the
// helpers take explicit monotonic readings, a wall-clock step cannot
// influence the outcome by construction — the tests pin the arithmetic
// so a regression back to wall-clock round-trips (which would need
// time.Now().UnixNano() inputs) is caught at review and the boundary
// semantics stay fixed.

func TestMonotonicNanos(t *testing.T) {
	a := MonotonicNanos()
	if a <= 0 {
		t.Fatalf("MonotonicNanos() = %d, want > 0", a)
	}
	b := MonotonicNanos()
	if b < a {
		t.Fatalf("MonotonicNanos went backwards: %d then %d", a, b)
	}
	// Same clock as monotonicSeconds (CLOCK_MONOTONIC), nanos vs seconds.
	secs := int64(monotonicSeconds())
	if diff := a/int64(time.Second) - secs; diff < -1 || diff > 1 {
		t.Fatalf("MonotonicNanos (%d s) and monotonicSeconds (%d s) disagree", a/int64(time.Second), secs)
	}
}

func TestHeartbeatStale(t *testing.T) {
	const timeout = 500 * time.Millisecond
	base := int64(1_000_000_000_000) // arbitrary monotonic reading

	cases := []struct {
		name string
		last int64
		now  int64
		want bool
	}{
		{"fresh", base, base + (100 * time.Millisecond).Nanoseconds(), false},
		{"exactly timeout", base, base + timeout.Nanoseconds(), false},
		{"just past timeout", base, base + timeout.Nanoseconds() + 1, true},
		{"long silent", base, base + (10 * time.Second).Nanoseconds(), true},
		// A wall-clock forward step does not move CLOCK_MONOTONIC, so a
		// heartbeat received 100ms ago stays fresh regardless of any
		// wall-clock jump between store and check.
		{"forward wall step is invisible", base, base + (100 * time.Millisecond).Nanoseconds(), false},
		// now < last cannot happen on a correct monotonic clock; the
		// helper tolerates it as not-stale rather than firing a timeout.
		{"negative age tolerated", base, base - time.Second.Nanoseconds(), false},
	}
	for _, tc := range cases {
		if got := heartbeatStale(tc.last, tc.now, timeout); got != tc.want {
			t.Errorf("%s: heartbeatStale(%d, %d, %v) = %v, want %v",
				tc.name, tc.last, tc.now, timeout, got, tc.want)
		}
	}
}

func TestLastPeerReceiveAgeMonotonic(t *testing.T) {
	s := &SessionSync{}

	if _, ok := s.LastPeerReceiveAge(); ok {
		t.Fatal("expected no age before any peer traffic")
	}

	// 500ms-old monotonic timestamp reports an age near 500ms.
	s.lastPeerRxMono.Store(MonotonicNanos() - (500 * time.Millisecond).Nanoseconds())
	age, ok := s.LastPeerReceiveAge()
	if !ok {
		t.Fatal("expected age to be reported")
	}
	if age < 500*time.Millisecond || age > 2*time.Second {
		t.Fatalf("age = %v, want ~500ms", age)
	}

	// A stored reading ahead of now (impossible on a correct monotonic
	// clock, but the documented contract) clamps to 0 instead of going
	// negative — a negative age would defeat recency guards.
	s.lastPeerRxMono.Store(MonotonicNanos() + time.Minute.Nanoseconds())
	age, ok = s.LastPeerReceiveAge()
	if !ok {
		t.Fatal("expected age to be reported")
	}
	if age != 0 {
		t.Fatalf("age = %v, want clamp to 0", age)
	}
}

// TestRestartHeartbeatSeedsLastSeenAndRearmsGrace exercises the #1792
// restart protections: the notify hook fires before teardown, the
// replacement receiver inherits the pre-restart lastSeen (so a peer that
// dies during the restart window is still detected), and startedAt re-arms.
// Since #9722 the grace measured from that startedAt is the short
// heartbeatRestartGrace, not the cold-boot one; see
// heartbeat_restart_grace_9722_test.go.
func TestRestartHeartbeatSeedsLastSeenAndRearmsGrace(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	m.mu.RLock()
	oldRecv := m.hbReceiver
	m.mu.RUnlock()
	if oldRecv == nil {
		t.Fatal("no receiver after StartHeartbeat")
	}

	// Simulate a previously seen peer heartbeat.
	seed := MonotonicNanos() - (250 * time.Millisecond).Nanoseconds()
	oldRecv.lastSeen.Store(seed)

	var notifyCalls atomic.Int64
	m.SetHeartbeatRestartNotifyFunc(func() { notifyCalls.Add(1) })

	beforeRestart := time.Now()
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned false while running")
	}

	m.mu.RLock()
	newRecv := m.hbReceiver
	m.mu.RUnlock()
	if newRecv == nil {
		t.Fatal("no receiver after RestartHeartbeat")
	}
	if newRecv == oldRecv {
		t.Fatal("receiver was not replaced by RestartHeartbeat")
	}
	if got := newRecv.lastSeen.Load(); got != seed {
		t.Errorf("lastSeen seed = %d, want %d (pre-restart timestamp must carry over)", got, seed)
	}
	if n := notifyCalls.Load(); n < 1 {
		t.Errorf("restart notify hook called %d times, want >= 1", n)
	}
	if newRecv.startedAt.Before(beforeRestart) {
		t.Errorf("startedAt = %v not re-armed (before restart at %v)", newRecv.startedAt, beforeRestart)
	}
}

func TestRestartHeartbeatNotRunning(t *testing.T) {
	m := NewManager(0, 1)
	var notifyCalls atomic.Int64
	m.SetHeartbeatRestartNotifyFunc(func() { notifyCalls.Add(1) })
	if m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned true with no heartbeat running")
	}
	if notifyCalls.Load() != 0 {
		t.Fatal("notify hook fired for a no-op restart")
	}
}
