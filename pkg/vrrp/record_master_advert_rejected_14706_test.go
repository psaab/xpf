package vrrp

import (
	"net"
	"testing"
	"time"
)

// #14706: recordMasterAdvert must only learn priority/source/interval from
// an advert the state machine accepts as the current master. A rejected
// lower-priority advert from a different source must not clobber the
// observed higher master that shouldPreemptObservedMaster compares
// against, must not refresh its liveness, must not replace the #10719
// known-master source, and must not inflate the learned interval.

func observedMaster14706(t *testing.T, vi *vrrpInstance) (int, net.IP, time.Duration, time.Time) {
	t.Helper()
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	src := append(net.IP(nil), vi.lastMasterIPv4[:]...)
	return vi.lastMasterPriority, src, vi.masterAdverInterval, vi.lastMasterSeen
}

func TestRejectedLowerAdvertDoesNotClobberObservedMaster14706(t *testing.T) {
	vi := newGateTestInstance(t, 100, true)
	masterDown, _, preemptHold := longTimers(t)
	realIP := net.IPv4(10, 0, 0, 2)
	rogueIP := net.IPv4(10, 0, 0, 3)

	vi.handleBackupRx(&VRRPPacket{Priority: 200, MaxAdvertInt: 100, SrcIP: realIP}, masterDown, preemptHold)
	// Age the real master's record but keep it well inside its
	// master-down horizon (learned 1s -> ~3.6s), so it is still live.
	vi.mu.Lock()
	seededSeen := time.Now().Add(-500 * time.Millisecond)
	vi.lastMasterSeen = seededSeen
	vi.mu.Unlock()

	vi.handleBackupRx(&VRRPPacket{Priority: 100, MaxAdvertInt: 4095, SrcIP: rogueIP}, masterDown, preemptHold)

	pri, src, interval, seen := observedMaster14706(t, vi)
	if pri != 200 {
		t.Errorf("lastMasterPriority = %d, want 200 (rejected lower advert must not lower the observed master)", pri)
	}
	if !src.Equal(realIP) {
		t.Errorf("learned master source = %v, want %v (rejected advert must not replace known master)", src, realIP)
	}
	if interval != 1000*time.Millisecond {
		t.Errorf("masterAdverInterval = %v, want 1s from the accepted 200 master, not the rogue 40.95s", interval)
	}
	if !seen.Equal(seededSeen) {
		t.Errorf("lastMasterSeen = %v, want unchanged %v (rejected advert must not refresh liveness)", seen, seededSeen)
	}
	if vi.shouldPreemptObservedMaster() {
		t.Error("shouldPreemptObservedMaster() = true, want false: local 100 must not preempt the live observed 200 master after a rogue 100 advert")
	}
}

func TestRejectedLowerAdvertDoesNotPrimeUnknownSourceDetector14706(t *testing.T) {
	warnings := installWarningCounter10719(t)
	vi := newGateTestInstance(t, 100, true)
	masterDown, _, preemptHold := longTimers(t)
	realIP := net.IPv4(10, 0, 0, 2)
	rogueIP := net.IPv4(10, 0, 0, 3)

	vi.handleBackupRx(&VRRPPacket{Priority: 200, SrcIP: realIP}, masterDown, preemptHold)
	// Rogue ordinary advert: rejected as master, must not become the
	// learned identity the #10719 detector trusts.
	vi.handleBackupRx(&VRRPPacket{Priority: 1, SrcIP: rogueIP}, masterDown, preemptHold)
	// Follow-up owner advert from the same rogue source must still warn.
	vi.handleBackupRx(&VRRPPacket{Priority: 255, SrcIP: rogueIP}, masterDown, preemptHold)

	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("unrecognized master advert count = %d, want 1 (rogue priority-1 advert must not prime the detector off)", got)
	}
	if got := warnings.count.Load(); got != 1 {
		t.Fatalf("warning count = %d, want 1", got)
	}
}

func TestRejectedLowerAdvertDoesNotClobberObservedMasterMasterRx14706(t *testing.T) {
	vi := newGateTestInstance(t, 200, true)
	vi.setState(StateMaster)
	masterDown, advert, _ := longTimers(t)
	realIP := net.IPv4(10, 0, 0, 2)
	rogueIP := net.IPv4(10, 0, 0, 3)

	vi.recordMasterAdvert(&VRRPPacket{Priority: 200, MaxAdvertInt: 100, SrcIP: realIP})
	vi.handleMasterRx(&VRRPPacket{Priority: 100, MaxAdvertInt: 4095, SrcIP: rogueIP}, masterDown, advert)

	pri, src, interval, _ := observedMaster14706(t, vi)
	if pri != 200 || !src.Equal(realIP) || interval != 1000*time.Millisecond {
		t.Errorf("observed master = pri %d src %v interval %v, want 200/%v/1s preserved against rejected lower MasterRx advert", pri, src, interval, realIP)
	}
	if got := vi.getState(); got != StateMaster {
		t.Errorf("state = %s, want MASTER (lower advert still loses)", got)
	}
}

// Controls: learning that must be preserved.

func TestAcceptedMasterLearningPreserved14706(t *testing.T) {
	realIP := net.IPv4(10, 0, 0, 2)
	otherIP := net.IPv4(10, 0, 0, 3)

	// A first lower-than-local master is the current master (preempt /
	// hold-time path): it must be recorded.
	t.Run("first lower master", func(t *testing.T) {
		vi := newGateTestInstance(t, 200, true)
		vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: 100, SrcIP: realIP})
		pri, src, interval, _ := observedMaster14706(t, vi)
		if pri != 100 || !src.Equal(realIP) || interval != 1000*time.Millisecond {
			t.Fatalf("observed = %d/%v/%v, want 100/%v/1s", pri, src, interval, realIP)
		}
		if !vi.preemptingLiveLowerMaster() {
			t.Error("preemptingLiveLowerMaster() = false, want true for live lower first master")
		}
	})

	// Same source advertising a lower priority is that master's own
	// demotion (e.g. track cost), not a different rejected master.
	t.Run("same source demotion", func(t *testing.T) {
		vi := newGateTestInstance(t, 100, true)
		vi.recordMasterAdvert(&VRRPPacket{Priority: 200, MaxAdvertInt: 100, SrcIP: realIP})
		vi.recordMasterAdvert(&VRRPPacket{Priority: 120, MaxAdvertInt: 200, SrcIP: realIP})
		pri, _, interval, _ := observedMaster14706(t, vi)
		if pri != 120 || interval != 2000*time.Millisecond {
			t.Fatalf("observed = %d/%v, want 120/2s from same-source demotion", pri, interval)
		}
	})

	// A higher advert from a new source is an accepted new master.
	t.Run("higher new master", func(t *testing.T) {
		vi := newGateTestInstance(t, 100, true)
		vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: 100, SrcIP: realIP})
		vi.recordMasterAdvert(&VRRPPacket{Priority: 200, MaxAdvertInt: 200, SrcIP: otherIP})
		pri, src, interval, _ := observedMaster14706(t, vi)
		if pri != 200 || !src.Equal(otherIP) || interval != 2000*time.Millisecond {
			t.Fatalf("observed = %d/%v/%v, want 200/%v/2s", pri, src, interval, otherIP)
		}
	})

	// Once the old record is stale, a lower advert from a new source is
	// the replacement master after silent death.
	t.Run("stale replacement", func(t *testing.T) {
		vi := newMasterIntervalTestInstance(t, 100, 30)
		vi.recordMasterAdvert(&VRRPPacket{Priority: 200, MaxAdvertInt: 100, SrcIP: realIP})
		vi.mu.Lock()
		vi.lastMasterSeen = time.Now().Add(-time.Hour)
		vi.mu.Unlock()
		vi.recordMasterAdvert(&VRRPPacket{Priority: 100, MaxAdvertInt: 300, SrcIP: otherIP})
		pri, src, interval, _ := observedMaster14706(t, vi)
		if pri != 100 || !src.Equal(otherIP) || interval != 3000*time.Millisecond {
			t.Fatalf("observed = %d/%v/%v, want 100/%v/3s after stale master", pri, src, interval, otherIP)
		}
	})
}
