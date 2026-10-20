package vrrp

import (
	"net"
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

// --- Timer-applies-intermediate interleavings (triple-review of the
// first #15920 head, codex P1 x2 / opus MATERIAL) ---
//
// The accumulation above is only sound if old* keeps meaning "the cfg
// the live timers were last armed under". A timer/RX event serviced
// between two coalesced updates arms from the intermediate cfg; a later
// revert then nets old==new against the PRE-update baseline and would
// suppress the correction. noteTimerApplied re-baselines old* at every
// such arm. The tests below drive that exact ordering through the
// production step functions.

// armHoldInterleaved arms the preempt hold via the masterDownTimer
// expiry while a config token is still pending in configUpdatedCh.
// stepBackup's select would race the two ready cases, so the token is
// temporarily drained and restored afterwards: the step is then
// deterministically the master-down case, but the pending record and
// (restored) token are exactly what the racing run loop would face.
func armHoldInterleaved(t *testing.T, vi *vrrpInstance) (advert, preemptHold *time.Timer) {
	t.Helper()
	select {
	case <-vi.configUpdatedCh:
	case <-time.After(time.Second):
		t.Fatal("configUpdatedCh token missing before interleaved hold arm")
	}
	masterDown, advert, preemptHold := expiredMasterDown(t)
	vi.stepBackup(masterDown, advert, preemptHold)
	if vi.getState() != StateBackup {
		t.Fatalf("state = %s, want BACKUP (hold armed)", vi.getState())
	}
	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if !armed {
		t.Fatal("preemptHoldArmed = false, want true after interleaved hold arm")
	}
	select {
	case vi.configUpdatedCh <- struct{}{}:
	default:
		t.Fatal("configUpdatedCh unexpectedly full when restoring the pending token")
	}
	return advert, preemptHold
}

// TestVRRPMaster_TimerAppliesIntermediateThenRevert_ReArmsAdvertTimer
// is the opus/codex reproduction: MASTER at 100ms, expired advert
// timer; the timer-triggered send's callback first commits 100->60000
// (the realistic manager-during-send interleave), so the timer case
// re-arms at 60000ms. A revert to 100ms lands before the config token
// is consumed. The config consumption must still emit a correction
// advert and re-arm at 100ms. On the first #15920 head the pending
// record collapsed to 100->100 and both were suppressed — RED there;
// on the pre-#15920 parent the adjacent 60000->100 delta happened to
// correct it.
func TestVRRPMaster_TimerAppliesIntermediateThenRevert_ReArmsAdvertTimer(t *testing.T) {
	vi := newMaster15689(t, 100)
	base := Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, AdvertiseInterval: 100}
	grown := base
	grown.AdvertiseInterval = 60000

	var intervals []int
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		intervals = append(intervals, int(pkt.MaxAdvertInt))
		if len(intervals) == 1 {
			// Manager commits the growth while the timer case is
			// between sendAdvert and advertTimer.Reset — the Reset
			// therefore arms 60000ms and noteTimerApplied re-baselines.
			vi.updateConfig(grown)
		}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(0)
	t.Cleanup(func() { advert.Stop() })
	time.Sleep(2 * time.Millisecond) // let the advert timer fire

	// Only advertTimer.C is ready: periodic advert at the OLD 100ms
	// cadence (10cs), then the trailing Reset arms the intermediate.
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on advert timer")
	}
	if len(intervals) != 1 || intervals[0] != 10 {
		t.Fatalf("timer advert MaxAdvertInt = %v, want [10] (100ms)", intervals)
	}

	// Revert before the queued config token is consumed.
	vi.updateConfig(base)
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	if len(intervals) != 2 || intervals[1] != 10 {
		t.Fatalf("adverts = %v, want [10 10]: revert after intermediate timer arm must emit a correction advert at final cfg", intervals)
	}
	select {
	case <-advert.C:
	case <-time.After(time.Second):
		t.Fatal("advertTimer still armed for intermediate 60000ms despite final 100ms cfg")
	}
}

// TestVRRPMaster_TimerAppliesIntermediateNoRevert_NoCorrectionAdvert
// is the negative control for the re-baselining: the timer case applies
// the intermediate (and final) cfg, and NO revert follows. The pending
// consumption must stay silent — re-baselining old* to the applied cfg
// makes old==new — rather than emitting a redundant correction advert
// or touching the correctly armed timer.
func TestVRRPMaster_TimerAppliesIntermediateNoRevert_NoCorrectionAdvert(t *testing.T) {
	vi := newMaster15689(t, 100)
	grown := Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, AdvertiseInterval: 60000}

	var intervals []int
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		intervals = append(intervals, int(pkt.MaxAdvertInt))
		if len(intervals) == 1 {
			vi.updateConfig(grown)
		}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(0)
	t.Cleanup(func() { advert.Stop() })
	time.Sleep(2 * time.Millisecond)

	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on advert timer")
	}
	// Consume the queued token: timer already armed at final cfg.
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	if len(intervals) != 1 {
		t.Fatalf("adverts = %v, want exactly the one timer advert; config consumption must not re-advertise an already-applied cfg", intervals)
	}
	if !advert.Stop() {
		t.Fatal("advertTimer disturbed by config consumption although it was already armed at final cfg")
	}
}

// TestVRRPBackup_HoldArmedAtIntermediateThenRevert_DisarmsHold is the
// codex P1 hold interleaving: BACKUP with hold 60s observing a live
// lower master; commit 60->1, let the expired masterDownTimer win the
// select (arming a 1s preempt hold at the intermediate cfg), then
// revert to 60 before the config token is consumed. The consumption
// must disarm the 1s hold for re-validation — preserving it would
// promote ~59s early against the live master. On the first #15920
// head the record collapsed to 60->60 and the 1s hold survived — RED
// there.
func TestVRRPBackup_HoldArmedAtIntermediateThenRevert_DisarmsHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	// Commit the intermediate hold-time; token stays unconsumed.
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   1,
		AdvertiseInterval: 30,
	})
	// Refresh the observed master AFTER the commit, as the pre-existing
	// hold fixtures do right before their single step: with a 30ms
	// interval the liveness horizon is ~97ms, and this interleaving has
	// an extra commit between the seeding and armHold's internal sleep.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	// masterDownTimer expiry wins over the config token and arms the
	// hold at the intermediate 1s (armPreemptHold re-baselines old*).
	advert, preemptHold := armHoldInterleaved(t, vi)

	// Revert to 60s before consuming the token; keep the master fresh
	// so only the hold-time delta can disarm.
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   60,
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
		t.Fatal("preemptHoldArmed = true: 1s hold armed at intermediate cfg survived a revert to 60s; promotion would fire ~59s early")
	}
	if vi.getState() != StateBackup {
		t.Errorf("state = %s, want BACKUP", vi.getState())
	}
}

// TestVRRPBackup_HoldArmedAtIntermediateNoRevert_PreservesHold is the
// negative control: the hold is armed at the intermediate cfg and that
// cfg remains final when the token is consumed. The consumption must
// preserve the running countdown (old* was re-baselined to the arm, so
// old==new), not disarm it as if the hold-time had changed again.
func TestVRRPBackup_HoldArmedAtIntermediateNoRevert_PreservesHold(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 60)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		PreemptHoldTime:   1,
		AdvertiseInterval: 30,
	})
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	advert, preemptHold := armHoldInterleaved(t, vi)

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
		t.Fatal("preemptHoldArmed = false: hold armed at final cfg must be preserved by the pending consumption")
	}
	if !preemptHold.Stop() {
		t.Fatal("preemptHoldTimer was stopped although the armed hold matches final cfg")
	}
}

// --- Round-2 fold: VIP announce must not baseline; arms are atomic ---

// TestVRRPMaster_IntervalShrinkPlusVIPEdit_ConfigStillReArms is the
// Opus2/Codex2 interval+VIP interleaving (review proof overlay,
// adapted): MASTER armed at 60000ms, commit interval 60000->100
// (token pending), then a VIP-set edit whose MASTER announce sends an
// advert carrying 100ms but does NOT reset advertTimer. The config
// consumption must still treat the shrink as unapplied: send its
// correction advert and re-arm at 100ms. On head 7d08d595 the
// updateVIPs announce called noteTimerApplied and baselined old* to
// 100, so the consumer suppressed both — RED there.
func TestVRRPMaster_IntervalShrinkPlusVIPEdit_ConfigStillReArms(t *testing.T) {
	vi := newMaster15689(t, 60000)
	vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }
	adverts := captureAdverts15920(t)

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour) // 60s arm would not fire here
	t.Cleanup(func() { advert.Stop() })

	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 100,
	})
	if err := vi.updateVIPs([]string{"10.0.0.10/24", "10.0.0.11/24"}); err != nil {
		t.Fatalf("updateVIPs: %v", err)
	}
	// The VIP announce itself carries the new interval (10cs)...
	select {
	case cs := <-adverts:
		if cs != 10 {
			t.Fatalf("VIP announce MaxAdvertInt = %d cs, want 10 (100ms)", cs)
		}
	default:
		t.Fatal("VIP-set announce sent no advert")
	}
	// ...but it must not have baselined the pending record: consuming
	// the token re-advertises and re-arms the still-60s timer.
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on config update")
	}
	select {
	case cs := <-adverts:
		if cs != 10 {
			t.Fatalf("correction advert MaxAdvertInt = %d cs, want 10", cs)
		}
	default:
		t.Fatal("no correction advert: VIP announce falsely baselined the interval shrink")
	}
	select {
	case <-advert.C:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("advertTimer left on 60s arm after interval+VIP co-edit")
	}
}

// TestVRRPMaster_ConfigHandlerArmBetweenUpdates_ThenRevert is the
// Opus2 round-3 interleaving: the config consumer itself arms the
// timer. MASTER at 10000ms (advertTimer armed at 10000ms); commit A:
// 10000->100; consume the token — the consumer's correction advert
// callback commits B: 100->10000, so the consumer's trailing
// armAdvertTimer uses B's 10000ms and must baseline old*:=10000
// atomically with that arm. Commit C then reverts B, back to A's
// 100ms. Consuming the queued token must STILL emit a second
// correction advert and re-arm at 100ms: against the armed 10000ms
// baseline, 100 is a change.
//
// Why C reverts to A's 100 (Codex3): the consumer's trailing arm is
// at B (10000ms, the pre-A value). At head, armAdvertTimer notes
// old:=10000 (armed) while new is still B's 10000, so the record
// captured between the consumptions reads {10000->10000} — B fully
// applied. C then refreshes new:=100 and the second consumption
// sees {10000->100}: second correction advert (10cs) and a 100ms
// deadline, asserted below. Fold-reverted (consumer arm without
// note, via a shim armAdvertTimer), that mid-test record instead
// reads {100->10000} — baseline still at A's old value, B recorded
// only as desired — and the test fails there (verified by overlay).
// The earlier committed encoding (C back to the pre-A value) let
// the fold-reverted record read old != new at the second
// consumption, so it passed vacuously; reverting to A's value plus
// the mid-test record assertion is what discriminates.
func TestVRRPMaster_ConfigHandlerArmBetweenUpdates_ThenRevert(t *testing.T) {
	vi := newMaster15689(t, 10000)
	base := Instance{Interface: "eth0", GroupID: 101, Priority: 200, Preempt: true, AdvertiseInterval: 10000}
	toA := base
	toA.AdvertiseInterval = 100
	toB := base // B == pre-A value 10000, committed mid-consumer

	var intervals []int
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		intervals = append(intervals, int(pkt.MaxAdvertInt))
		if len(intervals) == 1 {
			vi.updateConfig(toB) // commit B mid-consumer
		}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })

	vi.updateConfig(toA)
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on first consumption")
	}
	if len(intervals) != 1 || intervals[0] != 10 {
		t.Fatalf("first correction advert = %v cs, want [10] (100ms)", intervals)
	}
	// The trailing arm used B (10000ms); B's token is still queued.
	// At head the pending record must already read baseline == armed
	// B (old == new == 10000): B is fully applied by the arm.
	vi.mu.RLock()
	mid := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !mid.valid || mid.oldAdvertiseMS != 10000 || mid.newAdvertiseMS != 10000 {
		t.Fatalf("pending after consumer arm = %+v, want old==new==10000 (baseline = armed B)", mid)
	}
	// Revert B by re-committing A's 100ms before consuming it.
	vi.updateConfig(toA)
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on revert consumption")
	}
	if len(intervals) != 2 || intervals[1] != 10 {
		t.Fatalf("adverts = %v cs, want [10 10]: revert to A after consumer armed at B must correct a second time", intervals)
	}
	select {
	case <-advert.C:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("advertTimer still armed at B's 10000ms after final revert to A's 100ms")
	}
}

// TestArmAdvertTimer_BaselinesToArmedCfg pins the atomic arm+note
// invariant at the helper level: with a growth committed (cfg 60000)
// and no consumption yet, an arm applies that cfg; the pending
// baseline must move to exactly the armed cfg (old == new == 60000),
// so the queued consumption is a correct no-op — and never names a
// value the timer was not armed under.
func TestArmAdvertTimer_BaselinesToArmedCfg(t *testing.T) {
	vi := newMaster15689(t, 100)
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 60000,
	})
	advert := time.NewTimer(time.Hour)
	t.Cleanup(func() { advert.Stop() })
	vi.armAdvertTimer(advert)
	vi.mu.RLock()
	p := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !p.valid {
		t.Fatal("pending record lost by arm")
	}
	if p.oldAdvertiseMS != 60000 || p.newAdvertiseMS != 60000 {
		t.Fatalf("pending after atomic arm = %d->%d, want 60000->60000 (baseline = armed cfg)", p.oldAdvertiseMS, p.newAdvertiseMS)
	}
	if !advert.Stop() {
		t.Fatal("advertTimer not pending after armAdvertTimer at 60000ms")
	}
}

// TestArmPreemptHold_CommitBetweenSnapshotAndArm_DisarmsStaleArm is
// the Codex2 snapshot/arm atomicity case (review proof overlay,
// adapted): stepBackup snapshots hold=1s; a commit to 60s lands
// before armPreemptHold runs. The arm uses the 1s snapshot, so the
// baseline must NOT be advanced to 60s; when the config token is then
// consumed, the 1s hold must be disarmed. On head 7d08d595,
// noteTimerApplied re-read cfg (60s) as the baseline, the record
// netted 60->60, and the 1s hold survived — RED there.
func TestArmPreemptHold_CommitBetweenSnapshotAndArm_DisarmsStaleArm(t *testing.T) {
	vi := newHoldTestInstance(t, 200, 1)
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()

	priorHold := vi.preemptHoldDuration() // stepBackup's snapshot
	if priorHold != time.Second {
		t.Fatalf("snapshot hold = %v, want 1s", priorHold)
	}
	// Commit lands between snapshot and arm.
	vi.updateConfig(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 30,
		PreemptHoldTime:   60,
	})

	masterDown := time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop() })
	preemptHold := time.NewTimer(time.Hour)
	t.Cleanup(func() { preemptHold.Stop() })
	vi.armPreemptHold(masterDown, preemptHold, priorHold)

	vi.mu.RLock()
	armedAfterArm := vi.preemptHoldArmed
	p := vi.pendingConfigChange
	vi.mu.RUnlock()
	if !armedAfterArm {
		t.Fatal("hold not armed by armPreemptHold")
	}
	if p.valid && p.oldHoldSec == p.newHoldSec {
		t.Fatalf("pending hold baseline falsely netted %d->%d although the timer was armed at the 1s snapshot", p.oldHoldSec, p.newHoldSec)
	}

	vi.mu.Lock()
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	masterDownLong := time.NewTimer(time.Hour)
	defer masterDownLong.Stop()
	advert := time.NewTimer(time.Hour)
	defer advert.Stop()
	vi.stepBackup(masterDownLong, advert, preemptHold)

	vi.mu.RLock()
	armed := vi.preemptHoldArmed
	vi.mu.RUnlock()
	if armed {
		t.Fatal("1s hold survived a config update to 60s; live lower master could be preempted 59s early")
	}
}
