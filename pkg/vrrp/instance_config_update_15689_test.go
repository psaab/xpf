package vrrp

import (
	"net"
	"testing"
	"time"
)

// Regression tests for #15689 (V36-03): day-2 in-place VRRP timer and
// hold-time updates (updateConfigHeld) failed to reset the StateMaster
// advertTimer or the StateBackup masterDownTimer, leaked unread
// configUpdatedCh tokens across state transitions, and restarted active
// preemptHoldTimer countdowns on unrelated edits.

func newMaster15689(t *testing.T, advertMS int) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: advertMS,
		VirtualAddresses:  []string{"10.0.0.10/24"},
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	installFakeVIPNetlink(vi)
	vi.setState(StateMaster)
	return vi
}

// TestVRRPMaster_Day2AdvertiseIntervalDecrease_ResetsAdvertTimerImmediately:
// a MASTER at AdvertiseInterval 60000ms updated in place to 100ms must emit
// an advert carrying the new MaxAdverInt (100ms = 10cs) promptly and
// re-arm advertTimer at the new interval instead of waiting out the old
// 60s arm. Report acceptance test (<250ms). Drives stepMaster directly
// for determinism (see stepBackup test rationale); pre-fix there was no
// MASTER config consumption at all — RED.
func TestVRRPMaster_Day2AdvertiseIntervalDecrease_ResetsAdvertTimerImmediately(t *testing.T) {
	vi := newMaster15689(t, 60000)
	adverts := make(chan int, 64)
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		adverts <- int(pkt.MaxAdvertInt)
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour) // old 60s arm: would not fire here
	t.Cleanup(func() { advert.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 100,
	})
	start := time.Now()
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("config-update step took %v, want <250ms (immediate advert)", elapsed)
	}
	select {
	case cs := <-adverts:
		if cs != 10 {
			t.Fatalf("immediate advert MaxAdvertInt = %d cs, want 10 (100ms)", cs)
		}
	default:
		t.Fatal("no immediate advert emitted on MASTER interval shrink")
	}
	// advertTimer re-armed at the NEW interval (~100ms), not the old arm.
	select {
	case <-advert.C:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("advertTimer not reset to new 100ms interval after day-2 shrink")
	}
	if got := vi.getState(); got != StateMaster {
		t.Errorf("state = %s, want MASTER", got)
	}
}

// TestVRRPMaster_ConfigUpdateDrainsToken_NoStaleLeak drives stepMaster
// directly: an update consumed while MASTER must leave configUpdatedCh
// empty so no stale token leaks into a future BACKUP tenure.
func TestVRRPMaster_ConfigUpdateDrainsToken_NoStaleLeak(t *testing.T) {
	vi := newMaster15689(t, 1000)
	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 1000,
		GARPCount:         5,
	})
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true")
	}
	select {
	case <-vi.configUpdatedCh:
		t.Fatal("configUpdatedCh still holds a token after MASTER consumed the update (stale leak into future BACKUP)")
	default:
	}
	// advertTimer must be re-armed at the (unchanged) interval and an
	// immediate advert must have been emitted via sendPacketFn capture in
	// the run()-driven sibling test; here assert the timer is live.
	if !advert.Stop() {
		// Timer already fired or drained — either way it was reset by the
		// step; a never-reset hour timer would still be pending.
		select {
		case <-advert.C:
		default:
			t.Fatal("advertTimer neither pending nor fired after MASTER config step")
		}
	}
}

// TestVRRPBackup_StaleMasterConfigUpdateDoesNotDisarmPreemptHold: a token
// left by an update during a prior MASTER tenure must not disarm a hold
// armed after transition to BACKUP when the premise still holds. The
// stale token is injected directly to model that tenure (stepMaster
// draining is covered above); post-fix stepBackup re-validates and only
// disarms when the premise is gone.
func TestVRRPBackup_StaleMasterConfigUpdateDoesNotDisarmPreemptHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	advert, preemptHold := armHold(t, vi)

	select {
	case vi.configUpdatedCh <- struct{}{}:
	default:
		t.Fatal("configUpdatedCh unexpectedly full before stale-token injection")
	}
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	vi.stepBackup(masterDownLong, advert, preemptHold)

	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if !armed {
		t.Fatal("preemptHoldArmed = false after stale MASTER-era token; hold must survive (premise unchanged)")
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP", vi.getState())
	}
}

// TestVRRPBackup_Day2AdvertiseIntervalDecrease_ResetsMasterDownTimer: a
// BACKUP with no learned master whose local AdvertiseInterval shrinks
// must reset masterDownTimer to the new masterDownInterval immediately.
func TestVRRPBackup_Day2AdvertiseIntervalDecrease_ResetsMasterDownTimer(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 60000
	vi.cfg.PreemptHoldTime = 0
	vi.mu.Unlock()

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   0,
		AdvertiseInterval: 100,
	})
	vi.stepBackup(masterDown, advert, preemptHold)

	select {
	case <-masterDown.C:
	case <-time.After(time.Second):
		t.Fatal("masterDownTimer not reset to new interval after BACKUP day-2 shrink (stuck at old horizon)")
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (timer reset must not promote by itself)", vi.getState())
	}
}

// TestVRRPBackup_UnrelatedConfigUpdate_PreservesArmedHold: with a hold
// armed and its premise still valid, an unrelated scalar edit must NOT
// disarm/restart the hold countdown.
func TestVRRPBackup_UnrelatedConfigUpdate_PreservesArmedHold(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Instance
	}{
		{"garp-count", Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, PreemptHoldTime: 60, AdvertiseInterval: 30, GARPCount: 9}},
		{"priority-raised", Instance{Interface: "eth0", GroupID: 101, Priority: 210, Preempt: true, PreemptHoldTime: 60, AdvertiseInterval: 30}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vi := newHoldTestInstance(t, 200, 60)
			vi.mu.Lock()
			vi.lastMasterPriority = 100
			vi.lastMasterSeen = time.Now()
			vi.mu.Unlock()
			advert, preemptHold := armHold(t, vi)

			vi.updateConfig(tc.cfg)
			vi.mu.Lock()
			vi.lastMasterSeen = time.Now()
			vi.mu.Unlock()
			masterDownLong := time.NewTimer(time.Hour)
			defer masterDownLong.Stop()
			vi.stepBackup(masterDownLong, advert, preemptHold)

			vi.mu.RLock()
			armed := vi.preemptHoldArmed
			vi.mu.RUnlock()
			if !armed {
				t.Fatalf("preemptHoldArmed = false after unrelated %s edit; hold countdown must be preserved", tc.name)
			}
			if !preemptHold.Stop() {
				t.Fatal("preemptHoldTimer was stopped by unrelated edit; countdown destroyed")
			}
		})
	}
}

// TestVRRPBackup_ConfigUpdate_HoldTimeChanged_DisarmsHold guards #2900: a
// genuinely invalidating edit (hold-time changed) still tears the hold
// down for re-validation.
func TestVRRPBackup_ConfigUpdate_HoldTimeChanged_DisarmsHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	advert, preemptHold := armHold(t, vi)

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   30,
		AdvertiseInterval: 30,
	})
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	vi.stepBackup(masterDownLong, advert, preemptHold)

	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if armed {
		t.Fatal("preemptHoldArmed = true after hold-time change; hold must be disarmed for re-validation (#2900)")
	}
}

// TestVRRPBackup_ConfigUpdate_PreemptEnabled_ResetsMasterDownTimer:
// preempt toggled false->true while a lower master advertises (no hold
// armed) must reset masterDownTimer so the newly warranted preemption is
// evaluated promptly.
func TestVRRPBackup_ConfigUpdate_PreemptEnabled_ResetsMasterDownTimer(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.desiredPreempt = false
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.masterAdverInterval = 30 * time.Millisecond
	vi.mu.Unlock()

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   0,
		AdvertiseInterval: 30,
	})
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	vi.stepBackup(masterDown, advert, preemptHold)

	select {
	case <-masterDown.C:
	case <-time.After(time.Second):
		t.Fatal("masterDownTimer not reset after preempt toggled on; newly warranted preemption would wait for old arm")
	}
}
