package vrrp

import (
	"testing"
	"time"
)

// Regression tests for #15920 (retro-review O-F3 / codex finding 3):
// coalesced VRRP config updates overwrote the only record that a running
// timer needed re-arming. updateConfigHeld signalled a capacity-one
// channel and recorded only the most recent adjacent before/after delta,
// so an interval (or hold-time, or effective-priority) change followed by
// an unrelated edit before the run loop consumed the pending token left
// the consumer comparing equal values: MASTER never sent an immediate
// advert nor re-armed its advertiser timer, BACKUP never re-armed a
// cold master-down timer, and an armed preempt hold kept the old
// hold-time's countdown. The fix accumulates the pending record —
// oldest unconsumed baseline per field, newest desired value — so the
// single consumption still observes every timer-relevant change, while
// a change-then-revert nets to no change and preserves the armed timers.

func captureAdverts15920(t *testing.T) chan int {
	t.Helper()
	adverts := make(chan int, 64)
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		adverts <- int(pkt.MaxAdvertInt)
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })
	return adverts
}

// TestVRRPMaster_CoalescedIntervalThenGARPOnly_ResetsAdvertTimer is the
// decisive O-F3 check: interval 60000->100, then a GARP-only edit that
// retains 100, both before one stepMaster consumption. Pre-fix the
// second update overwrote the pending record with 100->100, so no
// immediate advert was sent and the 60s-armed advertTimer was never
// re-armed — RED. Post-fix the accumulated record still reads
// 60000->100 and the MASTER advertises/re-arms immediately.
func TestVRRPMaster_CoalescedIntervalThenGARPOnly_ResetsAdvertTimer(t *testing.T) {
	vi := newMaster15689(t, 60000)
	adverts := captureAdverts15920(t)

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
	// Unrelated second commit lands before the run loop wakes.
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 100,
		GARPCount:         9,
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
		t.Fatal("no immediate advert emitted after coalesced interval change (pending record lost the 60000->100 delta)")
	}
	select {
	case <-advert.C:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("advertTimer not reset to new 100ms interval after coalesced interval shrink")
	}
	if got := vi.getState(); got != StateMaster {
		t.Errorf("state = %s, want MASTER", got)
	}
}

// TestVRRPMaster_CoalescedPriorityThenGARPOnly_AdvertisesImmediately:
// a priority change (200->150) followed by a GARP-only edit before one
// consumption must still trigger the immediate advert with the new
// priority; pre-fix the overwritten 150->150 record suppressed it.
func TestVRRPMaster_CoalescedPriorityThenGARPOnly_AdvertisesImmediately(t *testing.T) {
	vi := newMaster15689(t, 1000)
	adverts := captureAdverts15920(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          150,
		Preempt:           true,
		AdvertiseInterval: 1000,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          150,
		Preempt:           true,
		AdvertiseInterval: 1000,
		GARPCount:         9,
	})
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	select {
	case <-adverts:
	default:
		t.Fatal("no immediate advert after coalesced priority change (pending record lost the 200->150 delta)")
	}
}

// TestVRRPMaster_CoalescedIntervalChangeThenRevert_PreservesAdvertTimer:
// 60000->100->60000 before one consumption nets to no change against the
// configuration the advert timer was armed under, so the consumption
// must NOT send an advert nor disturb the running arm. Guards against
// an over-eager accumulation that treats any intermediate value as a
// change.
func TestVRRPMaster_CoalescedIntervalChangeThenRevert_PreservesAdvertTimer(t *testing.T) {
	vi := newMaster15689(t, 60000)
	adverts := captureAdverts15920(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 100,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 60000,
	})
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	select {
	case cs := <-adverts:
		t.Fatalf("unexpected immediate advert (MaxAdvertInt %d cs) after change-then-revert coalescing; armed timer already matches cfg", cs)
	default:
	}
	if !advert.Stop() {
		t.Fatal("advertTimer disturbed by change-then-revert coalescing; the original arm must be preserved")
	}
}

// TestVRRPMaster_FourCoalescedUpdates_IntervalStillApplies: several
// updates under one pending token — interval shrink first, then only
// edits that keep the interval — must still surface the interval
// change in the single consumption. The timer-relevant edit is
// deliberately FIRST: pre-fix each later update overwrote the record,
// ending at {100->100}, so no advert/re-arm happened. A
// timer-relevant edit in final position already worked pre-fix and
// would not discriminate. Priority is left untouched here (its
// coalescing is covered separately): any intermediate priority value
// would leave oldEffectivePrio != newEffectivePrio in the pre-fix
// adjacent record and trigger the advert for the wrong reason.
func TestVRRPMaster_FourCoalescedUpdates_IntervalStillApplies(t *testing.T) {
	vi := newMaster15689(t, 60000)
	adverts := captureAdverts15920(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })

	base := Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, AdvertiseInterval: 60000}
	shrunk := base
	shrunk.AdvertiseInterval = 100
	garp9 := shrunk
	garp9.GARPCount = 9
	garp3 := garp9
	garp3.GARPCount = 3
	trackCost := garp3
	trackCost.TrackPriorityCost = 10

	vi.updateConfig(shrunk)
	vi.updateConfig(garp9)
	vi.updateConfig(garp3)
	vi.updateConfig(trackCost)

	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	select {
	case cs := <-adverts:
		if cs != 10 {
			t.Fatalf("immediate advert MaxAdvertInt = %d cs, want 10 (100ms)", cs)
		}
	default:
		t.Fatal("no immediate advert after three coalesced updates")
	}
	select {
	case <-advert.C:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("advertTimer not reset to new 100ms interval after three coalesced updates")
	}
}

// TestVRRPBackup_CoalescedHoldChangeThenGARPOnly_DisarmsHold: an armed
// preempt hold whose hold-time changes 60s->1s, followed by a GARP-only
// edit before one stepBackup consumption, must still disarm the hold
// for re-validation (#2900). Pre-fix the second update overwrote the
// record with 1->1 and the 60s-armed countdown survived — RED.
func TestVRRPBackup_CoalescedHoldChangeThenGARPOnly_DisarmsHold(t *testing.T) {
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
		PreemptHoldTime:   1,
		AdvertiseInterval: 30,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   1,
		AdvertiseInterval: 30,
		GARPCount:         9,
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
		t.Fatal("preemptHoldArmed = true after coalesced hold-time change + GARP-only edit; hold must be disarmed for re-validation (#2900, #15920)")
	}
}

// TestVRRPBackup_CoalescedHoldChangeThenRevert_PreservesHold:
// hold-time 60s->30s->60s before one consumption nets to the armed
// value, so the running countdown must be preserved (the mirror of the
// single-update unrelated-edit preservation guarantee, #15689).
func TestVRRPBackup_CoalescedHoldChangeThenRevert_PreservesHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	advert, preemptHold := armHold(t, vi)

	base := Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, PreemptHoldTime: 60, AdvertiseInterval: 30}
	changed := base
	changed.PreemptHoldTime = 30
	vi.updateConfig(changed)
	vi.updateConfig(base)

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
		t.Fatal("preemptHoldArmed = false after hold-time change-then-revert; countdown must be preserved")
	}
	if !preemptHold.Stop() {
		t.Fatal("preemptHoldTimer was stopped by hold-time change-then-revert; countdown destroyed")
	}
}

// TestVRRPBackup_CoalescedIntervalThenGARPOnly_ResetsMasterDownTimer:
// a cold BACKUP (no learned master) whose local interval shrinks
// 60000->100, followed by a GARP-only edit before one consumption, must
// still re-arm masterDownTimer at the new horizon. Pre-fix the
// overwritten 100->100 record failed the shrink check — RED.
// stepBackup also resets masterDownTimer whenever preemption is newly
// warranted, so this test disables preempt and plants a live lower
// master: only the recorded interval shrink can trigger the reset.
// (With preempt enabled and no master observed, the warranted leg
// fires regardless of the record and the test cannot discriminate.)
func TestVRRPBackup_CoalescedIntervalThenGARPOnly_ResetsMasterDownTimer(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 60000
	vi.cfg.PreemptHoldTime = 0
	vi.cfg.Preempt = false
	vi.desiredPreempt = false
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	preemptHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })

	shrunk := Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           false,
		PreemptHoldTime:   0,
		AdvertiseInterval: 100,
	}
	vi.updateConfig(shrunk)
	garpOnly := shrunk
	garpOnly.GARPCount = 9
	vi.updateConfig(garpOnly)
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	vi.stepBackup(masterDown, advert, preemptHold)

	select {
	case <-masterDown.C:
	case <-time.After(time.Second):
		t.Fatal("masterDownTimer not reset after coalesced BACKUP interval shrink (stuck at old horizon)")
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP (timer reset must not promote by itself)", vi.getState())
	}
}

// TestVRRPBackup_CoalescedIntervalGrowThenGARPOnly_PreservesMasterDownTimer
// is the negative control for the shrink-only cold-BACKUP rule: an
// interval GROWTH (100->60000) coalesced with a GARP-only edit must not
// re-arm masterDownTimer (only a shrink risks promotion delay; growing
// re-arms would needlessly extend an already-valid horizon). The live
// master advertises below our priority, so shouldPreemptObservedMaster
// stays false because preempt starts disabled here — newHoldTestInstance
// enables preempt, so disable it to isolate the interval leg.
func TestVRRPBackup_CoalescedIntervalGrowThenGARPOnly_PreservesMasterDownTimer(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 0)
	vi.mu.Lock()
	vi.cfg.AdvertiseInterval = 100
	vi.cfg.PreemptHoldTime = 0
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
		Preempt:           false,
		PreemptHoldTime:   0,
		AdvertiseInterval: 60000,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           false,
		PreemptHoldTime:   0,
		AdvertiseInterval: 60000,
		GARPCount:         9,
	})
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	vi.stepBackup(masterDown, advert, preemptHold)

	if !masterDown.Stop() {
		t.Fatal("masterDownTimer disturbed by coalesced interval growth; cold-BACKUP re-arm is shrink-only")
	}
}

// TestUpdateConfigHeld_CoalescedPendingRecordAccumulates pins the
// record semantics directly: two updates before consumption keep the
// first update's baselines and the second's desired values; a
// change-then-revert nets old == new on every field; after consumption
// the next update starts a fresh baseline.
func TestUpdateConfigHeld_CoalescedPendingRecordAccumulates(t *testing.T) {
	vi := newMaster15689(t, 60000)
	// Seed an armed-hold-relevant baseline: hold 60s, priority 200.
	vi.mu.Lock()
	vi.cfg.PreemptHoldTime = 60
	vi.mu.Unlock()

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          150,
		Preempt:           true,
		PreemptHoldTime:   10,
		AdvertiseInterval: 100,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          150,
		Preempt:           true,
		PreemptHoldTime:   10,
		AdvertiseInterval: 100,
		GARPCount:         9,
	})

	vi.mu.RLock()
	pending := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !pending.valid {
		t.Fatal("pendingConfigChange invalid after two updates")
	}
	if pending.oldAdvertiseMS != 60000 || pending.newAdvertiseMS != 100 {
		t.Errorf("advertise delta = %d->%d, want 60000->100 (oldest baseline, newest desired)", pending.oldAdvertiseMS, pending.newAdvertiseMS)
	}
	if pending.oldEffectivePrio != 200 || pending.newEffectivePrio != 150 {
		t.Errorf("priority delta = %d->%d, want 200->150", pending.oldEffectivePrio, pending.newEffectivePrio)
	}
	if pending.oldHoldSec != 60 || pending.newHoldSec != 10 {
		t.Errorf("hold delta = %d->%d, want 60->10", pending.oldHoldSec, pending.newHoldSec)
	}

	// Consume, then a change-then-revert against the now-current config
	// (interval 100, priority 150, hold 10) must net old == new.
	_ = vi.takePendingConfigChange()
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   60,
		AdvertiseInterval: 60000,
	})
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          150,
		Preempt:           true,
		PreemptHoldTime:   10,
		AdvertiseInterval: 100,
		GARPCount:         3,
	})
	vi.mu.RLock()
	pending = vi.pendingConfigChange
	vi.mu.RUnlock()
	if pending.oldAdvertiseMS != pending.newAdvertiseMS ||
		pending.oldEffectivePrio != pending.newEffectivePrio ||
		pending.oldHoldSec != pending.newHoldSec {
		t.Errorf("change-then-revert pending = %+v, want old == new on every field", pending)
	}
	// Exactly one coalesced token for all four updates.
	select {
	case <-vi.configUpdatedCh:
	default:
		t.Fatal("configUpdatedCh empty after coalesced updates; want exactly one pending token")
	}
	select {
	case <-vi.configUpdatedCh:
		t.Fatal("configUpdatedCh holds a second token; updates must coalesce to one")
	default:
	}
}
