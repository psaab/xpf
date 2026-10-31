package cluster

import (
	"testing"
	"time"
)

// #18561: the receiver evaluates peer staleness four times per heartbeat
// interval, so a dead peer is declared within threshold + interval/4 instead
// of threshold + up to one full interval. The staleness rule is unchanged.

func TestTimeoutCheckIntervalIsAQuarterInterval18561(t *testing.T) {
	cases := []struct{ interval, want time.Duration }{
		{200 * time.Millisecond, 50 * time.Millisecond}, // lab 200 ms x 5
		{100 * time.Millisecond, 25 * time.Millisecond}, // runtime default
		{time.Second, 250 * time.Millisecond},
		{20 * time.Millisecond, 10 * time.Millisecond}, // floor
		{8 * time.Millisecond, 8 * time.Millisecond},   // never longer than the interval
	}
	for _, c := range cases {
		if got := timeoutCheckInterval(c.interval); got != c.want {
			t.Errorf("timeoutCheckInterval(%v) = %v, want %v", c.interval, got, c.want)
		}
	}
}

// The loop must actually run at that cadence: it asks the ticker seam for
// timeoutCheckInterval(interval), and each tick runs one real checkTimeout.
func TestTimeoutLoopRunsAtQuarterIntervalCadence18561(t *testing.T) {
	ticks := make(chan time.Time)
	var asked time.Duration
	prev := newTimeoutTicker
	newTimeoutTicker = func(d time.Duration) (<-chan time.Time, func()) {
		asked = d
		return ticks, func() {}
	}
	defer func() { newTimeoutTicker = prev }()

	interval := 200 * time.Millisecond
	m := NewManager(0, 1)
	r := newHeartbeatReceiver(m, nil, 5, interval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.hbReceiver = r
	m.mu.Unlock()
	// Stale by one millisecond past the 1 s threshold.
	r.lastSeen.Store(MonotonicNanos() - (5*interval + time.Millisecond).Nanoseconds())

	r.wg.Add(1)
	go r.timeoutLoop()
	defer func() { close(r.stopCh); r.wg.Wait() }()

	select {
	case ticks <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("the timeout loop never read the ticker seam: it is not running on timeoutCheckInterval's cadence")
	}
	if asked != 50*time.Millisecond {
		t.Fatalf("timeout loop ticker period = %v, want 50ms (a quarter of the 200ms interval)", asked)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		alive := m.peerAlive
		m.mu.RUnlock()
		if !alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("one tick past the threshold did not declare the peer lost")
		}
		time.Sleep(time.Millisecond)
	}
}
