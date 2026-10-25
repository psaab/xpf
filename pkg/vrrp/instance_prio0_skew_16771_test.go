package vrrp

import (
	"net"
	"testing"
	"time"
)

// Tests for #16771: a priority-0 resign must arm Skew_Time (RFC 5798
// §6.4.2) on standalone vrrp-groups instead of the unconditional 1 ms
// fast path, so with three or more routers the highest-priority backup
// promotes first. RETH instances (Family == "") keep the 1 ms arm.
//
// The fire-time assertions measure the real masterDownTimer armed by
// handleBackupRx: on revert (1 ms for every instance) the standalone
// cases fire ~1 ms in and fail their lower bound, and the skew-helper
// unit assertions pin the exact RFC values.

// newSkew16771Instance builds a BACKUP instance of the given family
// ("" = RETH, "inet" = standalone) and effective priority.
func newSkew16771Instance(t *testing.T, family string, priority int) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:         "eth0",
		Family:            family,
		GroupID:           101,
		Priority:          priority,
		Preempt:           true,
		AdvertiseInterval: 1000,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	installFakeVIPNetlink(vi)
	vi.setState(StateBackup)
	return vi
}

func feedResign16771(t *testing.T, vi *vrrpInstance) (masterDown, preemptHold *time.Timer) {
	t.Helper()
	masterDown = time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	preemptHold = time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: net.IPv4(10, 0, 0, 9)}, masterDown, preemptHold)
	return masterDown, preemptHold
}

// TestPrio0Standalone250_SkewFire: standalone priority 250, 1 s interval
// (local fallback, no learned interval): Skew = (256-250)*1000/256 =
// 23.4375 ms. Must NOT fire within 10 ms, must fire by 500 ms.
func TestPrio0Standalone250_SkewFire(t *testing.T) {
	vi := newSkew16771Instance(t, "inet", 250)
	masterDown, _ := feedResign16771(t, vi)
	select {
	case <-masterDown.C:
		t.Fatal("standalone priority-250 backup fired within 10ms of priority-0 resign; want Skew_Time ~23ms (#16771)")
	case <-time.After(10 * time.Millisecond):
	}
	select {
	case <-masterDown.C:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("standalone priority-250 backup did not fire within 500ms; want Skew_Time ~23ms")
	}
}

// TestPrio0Standalone50_SkewFire: standalone priority 50, 1 s interval:
// Skew = (256-50)*1000/256 = 804.6875 ms. Must NOT fire within 400 ms,
// must fire by 2 s.
func TestPrio0Standalone50_SkewFire(t *testing.T) {
	vi := newSkew16771Instance(t, "inet", 50)
	masterDown, _ := feedResign16771(t, vi)
	select {
	case <-masterDown.C:
		t.Fatal("standalone priority-50 backup fired within 400ms of priority-0 resign; want Skew_Time ~805ms (#16771)")
	case <-time.After(400 * time.Millisecond):
	}
	select {
	case <-masterDown.C:
	case <-time.After(1600 * time.Millisecond):
		t.Fatal("standalone priority-50 backup did not fire within 2s; want Skew_Time ~805ms")
	}
}

// TestPrio0Reth_Keeps1ms: RETH (Family == "") priority 250 keeps the
// 1 ms fast path.
func TestPrio0Reth_Keeps1ms(t *testing.T) {
	vi := newSkew16771Instance(t, "", 250)
	masterDown, _ := feedResign16771(t, vi)
	select {
	case <-masterDown.C:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("RETH priority-250 backup did not fire within 100ms; want 1ms fast path preserved")
	}
}

// TestPrio0Standalone_Ordering: a 250 backup fires before a 50 backup on
// the same resign, proving deterministic single-successor ordering.
func TestPrio0Standalone_Ordering(t *testing.T) {
	hi := newSkew16771Instance(t, "inet", 250)
	lo := newSkew16771Instance(t, "inet", 50)
	hiDown, _ := feedResign16771(t, hi)
	loDown, _ := feedResign16771(t, lo)
	select {
	case <-hiDown.C:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("priority-250 backup did not fire first within 500ms")
	}
	select {
	case <-loDown.C:
		t.Fatal("priority-50 backup fired together with priority-250; want skew separation ~23ms vs ~805ms")
	case <-time.After(100 * time.Millisecond):
	}
	// Drain lo so its cleanup is trivial (timer still pending is fine).
	_ = loDown
}

// TestSkewTimeLocked_ExactValues pins skewTimeLocked directly,
// including the learned-interval leg: with a learned 1000 ms interval
// and local 30 ms, priority 100 skew must use the learned cadence.
func TestSkewTimeLocked_ExactValues(t *testing.T) {
	cases := []struct {
		name     string
		priority int
		localMS  int
		learned  time.Duration
		want     time.Duration
	}{
		{"p250 local 1s", 250, 1000, 0, time.Duration(256-250) * 1000 * time.Millisecond / 256},
		{"p50 local 1s", 50, 1000, 0, time.Duration(256-50) * 1000 * time.Millisecond / 256},
		{"p100 learned 1s over local 30ms", 100, 30, 1000 * time.Millisecond, time.Duration(256-100) * 1000 * time.Millisecond / 256},
		{"p255 owner", 255, 1000, 0, time.Duration(256-255) * 1000 * time.Millisecond / 256},
		{"p1", 1, 1000, 0, time.Duration(256-1) * 1000 * time.Millisecond / 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vi := newSkew16771Instance(t, "inet", tc.priority)
			vi.mu.Lock()
			vi.cfg.AdvertiseInterval = tc.localMS
			vi.masterAdverInterval = tc.learned
			got := vi.skewTimeLocked()
			vi.mu.Unlock()
			if got != tc.want {
				t.Fatalf("skewTimeLocked() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSkewTimeLocked_TrackDemotion: while the tracked link is down the
// skew uses the demoted effective priority, matching armMasterDownTimer.
func TestSkewTimeLocked_TrackDemotion(t *testing.T) {
	vi := newSkew16771Instance(t, "inet", 100)
	vi.mu.Lock()
	vi.cfg.TrackInterface = "eth1"
	vi.cfg.TrackPriorityCost = 60
	vi.trackDown = true
	got := vi.skewTimeLocked()
	vi.mu.Unlock()
	// Effective 40: (256-40)*1000/256.
	want := time.Duration(256-40) * 1000 * time.Millisecond / 256
	if got != want {
		t.Fatalf("skewTimeLocked() with track demotion = %v, want %v (effective priority 40)", got, want)
	}
	if got := vi.getPriority(); got != 40 {
		t.Fatalf("getPriority() = %d, want 40 (fixture broken)", got)
	}
}
