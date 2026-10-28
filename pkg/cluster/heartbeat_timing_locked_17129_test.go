package cluster

import (
	"testing"
	"time"
)

// #17129: heartbeatTimingDivergedLocked acquired m.mu itself, contradicting
// the package's *Locked "caller holds m.mu" convention. A caller that obeys
// the name — holding m.mu, as UpdateConfig does — self-deadlocks: Go's
// RWMutex is not re-entrant against a held write lock.
//
// Pre-fix this cell times out (the inner RLock blocks forever against the
// held Lock); post-fix the predicate is lock-free under the caller's hold
// and returns promptly.
func TestHeartbeatTimingDivergedLockedWithMuHeld17129(t *testing.T) {
	m := &Manager{hbInterval: 50 * time.Millisecond, hbThreshold: 3}
	installReceiverWithTiming(m, 200*time.Millisecond, 5)

	done := make(chan bool, 1)
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		done <- m.heartbeatTimingDivergedLocked()
	}()

	select {
	case diverged := <-done:
		if !diverged {
			t.Error("live 200ms/5 vs committed 50ms/3 with m.mu held must diverge")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeatTimingDivergedLocked deadlocked when called with m.mu held — " +
			"*Locked caller-holds contract violated (#17129)")
	}
}
