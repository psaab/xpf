package vrrp

import (
	"net"
	"testing"
	"time"
)

// #16766: a preemptNowCh token posted while an instance is MASTER is
// never drained — stepMaster does not select on preemptNowCh — so after
// the next forced resignation the first stepBackup consumes the stale
// token and re-promotes the just-resigned node at priority 0.
//
// The primary test drives the exact probe sequence from the finding
// with real stepMaster/stepBackup and the sendPacketFn seam:
//
//	sync-hold release while MASTER (token parked) -> ResignRG
//	(beginResign + triggerResign) -> stepMaster resignCh (becomeBackup,
//	stashed 0 applied, 3x priority-0 burst) -> first stepBackup.
//
// Acceptance: the subject reads [BACKUP] after the resign with 0 extra
// priority-0 adverts beyond the 3-frame resign burst, and the control
// (BACKUP at release, token drained by stepBackup) is unchanged.

// capturePriorities16766 records every wire advert priority.
func capturePriorities16766(t *testing.T) chan int {
	t.Helper()
	adverts := make(chan int, 64)
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		select {
		case adverts <- int(pkt.Priority):
		default:
		}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })
	return adverts
}

func drainAdverts16766(ch chan int) []int {
	var out []int
	for {
		select {
		case p := <-ch:
			out = append(out, p)
		default:
			return out
		}
	}
}

// runStepBackup16766 runs one stepBackup in a goroutine. Post-fix a
// drained token leaves no select case ready (all timers 1h), so the
// call blocks — the test observes state/adverts for a bounded window
// instead. Pre-fix the stale-token case returns promptly as MASTER.
// Cleanup closes stopCh to release the blocked select.
func runStepBackup16766(t *testing.T, vi *vrrpInstance, masterDown, advert, preemptHold *time.Timer) {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- vi.stepBackup(masterDown, advert, preemptHold) }()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		close(vi.stopCh)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("stepBackup did not exit on stopCh")
		}
	})
	// Give a stale-token promotion (prompt pre-fix) time to land.
	time.Sleep(300 * time.Millisecond)
}

func newStaleTokenInstance16766(t *testing.T) (*vrrpInstance, chan VRRPEvent) {
	t.Helper()
	eventCh := make(chan VRRPEvent, 32)
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.0.10/24"},
	}, &net.Interface{Name: "eth0"}, eventCh, nil)
	vi.setLocalIP(net.IPv4(10, 0, 0, 1))
	vi.suppressGARP.Store(true)
	installFakeVIPNetlink(vi)
	return vi, eventCh
}

func drainEvents16766(ch chan VRRPEvent) []VRRPState {
	var out []VRRPState
	for {
		select {
		case e := <-ch:
			out = append(out, e.State)
		default:
			return out
		}
	}
}

// TestStalePreemptToken16766_SubjectReleaseWhileMaster is the finding's
// subject row. Pre-fix it reads [BACKUP MASTER BACKUP] (the last BACKUP
// is the test's own becomeMaster-failure revert / stop) with extra
// priority-0 adverts beyond the resign burst; post-fix it must read
// [BACKUP] with exactly the 3-frame burst and nothing more.
func TestStalePreemptToken16766_SubjectReleaseWhileMaster(t *testing.T) {
	vi, eventCh := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)

	// Boot promoted by master-down while under sync hold, then hold
	// released while MASTER: the release kick is posted to a MASTER.
	vi.setState(StateMaster)
	vi.triggerPreemptNow()
	// The kick must not park: either gated at post time (MASTER) or
	// drained; assert no token survives into the MASTER tenure.
	if n := len(vi.preemptNowCh); n != 0 {
		t.Fatalf("preemptNowCh holds %d token(s) posted while MASTER, want 0 (#16766)", n)
	}

	// Forced resignation (manual failover / weight drop): ResignRG's
	// per-instance steps — stash priority 0, then signal resignCh.
	vi.beginResign()
	vi.triggerResign()

	masterDown, advert, preemptHold := longTimers(t)
	// stepMaster's resign edge re-arms masterDownTimer to the 3x
	// safety interval (12s at the 1s test interval); it is reset to
	// 1h below so the first BACKUP iteration can only fire on a
	// queued token/channel case, never on timer expiry.
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on resign")
	}
	// Undo the 12s safety arm so stepBackup blocks on channels only.
	stopAndDrainTimer(masterDown)
	masterDown.Reset(time.Hour)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after resign = %s, want BACKUP", got)
	}
	burst := drainAdverts16766(adverts)
	if len(burst) != 3 {
		t.Fatalf("resign burst = %v, want exactly 3 priority-0 frames", burst)
	}
	for _, p := range burst {
		if p != 0 {
			t.Fatalf("resign burst = %v, want all priority 0", burst)
		}
	}

	// First BACKUP iteration: pre-fix the stale token fires here and
	// re-promotes at priority 0. It must stay BACKUP and send nothing.
	// Post-fix no case is ready, so stepBackup blocks; run it async
	// and assert stasis over a window (see runStepBackup16766).
	runStepBackup16766(t, vi, masterDown, advert, preemptHold)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after first BACKUP iteration = %s, want BACKUP (stale preempt token re-promoted the resigned node, #16766)", got)
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("extra adverts beyond the 3-frame resign burst = %v, want none (#16766)", extra)
	}
	// Events published after the resign must be [BACKUP] only — no
	// spurious MASTER/BACKUP pair.
	for _, s := range drainEvents16766(eventCh) {
		if s == StateMaster {
			t.Fatalf("spurious MASTER event after resign (#16766)")
		}
	}
}

// TestStalePreemptToken16766_ControlBackupReleaseUnchanged is the
// control row: release while BACKUP with preempt and no observed master
// still promotes on the kick (the #2082 shortcut is preserved).
func TestStalePreemptToken16766_ControlBackupReleaseUnchanged(t *testing.T) {
	vi, _ := newStaleTokenInstance16766(t)
	vi.setState(StateBackup)

	vi.triggerPreemptNow()
	if n := len(vi.preemptNowCh); n != 1 {
		t.Fatalf("preemptNowCh holds %d token(s) for BACKUP, want 1", n)
	}
	masterDown, advert, preemptHold := longTimers(t)
	if stop := vi.stepBackup(masterDown, advert, preemptHold); stop {
		t.Fatal("stepBackup returned stop=true on release kick")
	}
	if got := vi.getState(); got != StateMaster {
		t.Fatalf("state = %s, want MASTER (BACKUP release kick must still preempt, #2082)", got)
	}
}

// TestStalePreemptToken16766_TokenDuringMasterTenureDrainedAtResign
// covers a token/force that lands DURING a MASTER tenure (bypassing the
// post-time gate, e.g. ForceRGMaster raced past its non-MASTER filter
// and wrote forcePreemptOnce directly): the resign edge must drain
// both so the first BACKUP iteration cannot consume them.
func TestStalePreemptToken16766_TokenDuringMasterTenureDrainedAtResign(t *testing.T) {
	vi, _ := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)
	vi.setState(StateMaster)

	// Race the kick past the gate: raw channel post + raw force flag,
	// modelling ForceRGMaster's check-then-set window.
	vi.preemptNowCh <- struct{}{}
	vi.mu.Lock()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()

	vi.beginResign()
	vi.triggerResign()
	masterDown, advert, preemptHold := longTimers(t)
	if stop := vi.stepMaster(masterDown, advert); stop {
		t.Fatal("stepMaster returned stop=true on resign")
	}
	stopAndDrainTimer(masterDown)
	masterDown.Reset(time.Hour)
	if n := len(vi.preemptNowCh); n != 0 {
		t.Fatalf("preemptNowCh holds %d token(s) after resign, want 0 drained (#16766)", n)
	}
	vi.mu.RLock()
	force := vi.forcePreemptOnce
	vi.mu.RUnlock()
	if force {
		t.Fatal("forcePreemptOnce still set after resign, want cleared (#16766)")
	}
	_ = drainAdverts16766(adverts)

	runStepBackup16766(t, vi, masterDown, advert, preemptHold)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %s, want BACKUP (force/token leaked across resign, #16766)", got)
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("extra adverts beyond resign burst = %v, want none (#16766)", extra)
	}
}

// TestStalePreemptToken16766_BecomeMasterDrainsQueuedKick: a kick
// legitimately queued while BACKUP (e.g. release raced a master-down
// promotion) is drained on MASTER entry, so it cannot leak into the
// next BACKUP tenure even without a resign.
func TestStalePreemptToken16766_BecomeMasterDrainsQueuedKick(t *testing.T) {
	vi, _ := newStaleTokenInstance16766(t)
	vi.setState(StateBackup)
	vi.triggerPreemptNow()
	vi.mu.Lock()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()
	if n := len(vi.preemptNowCh); n != 1 {
		t.Fatalf("preemptNowCh holds %d token(s), want 1 queued while BACKUP", n)
	}
	if !vi.becomeMaster() {
		t.Fatal("becomeMaster returned false")
	}
	if n := len(vi.preemptNowCh); n != 0 {
		t.Fatalf("preemptNowCh holds %d token(s) after becomeMaster, want 0 drained (#16766)", n)
	}
	vi.mu.RLock()
	force := vi.forcePreemptOnce
	vi.mu.RUnlock()
	if force {
		t.Fatal("forcePreemptOnce still set after becomeMaster, want cleared (#16766)")
	}
}

// TestStalePreemptToken16766_ReleaseSyncHoldWhileMasterPostsNothing
// exercises the manager release path itself: ReleaseSyncHold on a
// MASTER instance restores preempt but posts no surviving token.
func TestStalePreemptToken16766_ReleaseSyncHoldWhileMasterPostsNothing(t *testing.T) {
	m := NewManager()
	vi, _ := newStaleTokenInstance16766(t)
	vi.setState(StateMaster)
	vi.suppressPreempt()
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.SetSyncHold(time.Hour)
	m.ReleaseSyncHold()

	if !vi.getPreempt() {
		t.Fatal("preempt not restored after ReleaseSyncHold")
	}
	if n := len(vi.preemptNowCh); n != 0 {
		t.Fatalf("preemptNowCh holds %d token(s) after release while MASTER, want 0 (#16766)", n)
	}
}

// TestPreemptEnqueueSerializedWithStateTransition17827 pins the actual
// check/send gap from #17827. The poster is held after it samples BACKUP
// but before it can enqueue. A concurrent transition through
// becomeMaster plus forced resignation must cross both drains only
// after that poster is ordered before the state edge. The first BACKUP
// iteration must stay BACKUP with no extra priority-0 adverts or MASTER
// event; the BACKUP kick control remains covered by
// TestStalePreemptToken16766_ControlBackupReleaseUnchanged.
func TestPreemptEnqueueSerializedWithStateTransition17827(t *testing.T) {
	vi, eventCh := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)
	vi.setState(StateBackup)

	entered := make(chan struct{})
	release := make(chan struct{})
	posterDone := make(chan struct{})
	previousHook := preemptNowEnqueueHook
	preemptNowEnqueueHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() {
		preemptNowEnqueueHook = previousHook
		select {
		case <-release:
		default:
			close(release)
		}
	})

	go func() {
		vi.triggerPreemptNow()
		close(posterDone)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("preempt poster did not reach the state-check/send barrier")
	}

	masterDown, advert, preemptHold := longTimers(t)
	transitionStarted := make(chan struct{})
	transitionDone := make(chan struct{})
	go func() {
		close(transitionStarted)
		if !vi.becomeMaster() {
			t.Error("becomeMaster returned false")
		}
		vi.beginResign()
		vi.triggerResign()
		if stop := vi.stepMaster(masterDown, advert); stop {
			t.Error("stepMaster returned stop=true on forced resignation")
		}
		close(transitionDone)
	}()
	<-transitionStarted

	// With the old unlock-before-send ordering, the transition can cross
	// both drains while the poster is parked here. With the serialized
	// implementation, the MASTER transition is blocked behind vi.mu.
	select {
	case <-transitionDone:
		t.Error("state transition crossed both drains while preempt poster was paused before enqueue (#17827)")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-posterDone:
	case <-time.After(time.Second):
		t.Fatal("preempt poster did not finish after barrier release")
	}
	select {
	case <-transitionDone:
	case <-time.After(time.Second):
		t.Fatal("forced-resignation transition did not finish")
	}

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after forced resignation = %s, want BACKUP", got)
	}
	burst := drainAdverts16766(adverts)
	if len(burst) != 4 {
		t.Fatalf("promotion + resign adverts = %v, want priority 200 then three priority-0 frames", burst)
	}
	if burst[0] != 200 {
		t.Fatalf("promotion advert priority = %d, want 200", burst[0])
	}
	for _, priority := range burst[1:] {
		if priority != 0 {
			t.Fatalf("resign burst = %v, want three priority-0 frames", burst[1:])
		}
	}
	if events := drainEvents16766(eventCh); len(events) != 2 || events[0] != StateMaster || events[1] != StateBackup {
		t.Fatalf("events through promotion and resignation = %v, want [MASTER BACKUP]", events)
	}
	runStepBackup16766(t, vi, masterDown, advert, preemptHold)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after first BACKUP iteration = %s, want BACKUP (stale preempt kick survived resignation, #17827)", got)
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("extra adverts beyond the resign burst = %v, want none (#17827)", extra)
	}
	for _, state := range drainEvents16766(eventCh) {
		if state == StateMaster {
			t.Fatal("spurious MASTER event after forced resignation (#17827)")
		}
	}
}
