package vrrp

import (
	"net"
	"testing"
	"time"
)

// #17842: directly injected one-shot preempt token/force state is drained
// not only on MASTER entry and forced resignation (#16766), but also on
// peer demotion. The first stepBackup must not consume the request and
// re-promote the just-demoted node with force=true, bypassing the priority
// gate against the very master that demoted it.
//
// These tests drive the real receive path (handleMasterRx) end to end
// with sendPacketFn capture. The instance under test has priority 200
// (newStaleTokenInstance16766); the demoting peer advert carries
// priority 250 from an unlearned source, which admitAndRecord accepts
// (no prior master observed).

// TestStalePreemptToken17842_SubjectPeerDemotionDrainsTenureToken is the
// finding's subject row: tenure token+force pending -> higher-priority
// peer advert demotes MASTER to BACKUP -> token/force gone -> first
// BACKUP iteration does NOT re-promote and sends no advert.
func TestStalePreemptToken17842_SubjectPeerDemotionDrainsTenureToken(t *testing.T) {
	vi, eventCh := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)
	vi.setState(StateMaster)

	// Deliberately inject a token and force flag directly while MASTER
	// to retain coverage for the drain's defensive behavior. The real
	// ForceRGMaster path now serializes check/set/enqueue with transitions.
	vi.preemptNowCh <- struct{}{}
	vi.mu.Lock()
	vi.forcePreemptOnce = true
	vi.mu.Unlock()

	// Peer demotion via the real rx path: priority 250 > ours 200.
	masterDown, advert, preemptHold := longTimers(t)
	vi.handleMasterRx(&VRRPPacket{Priority: 250, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, advert)

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after peer demotion = %s, want BACKUP", got)
	}
	// The tenure token/force must not survive the demotion edge.
	if n := len(vi.preemptNowCh); n != 0 {
		t.Fatalf("preemptNowCh holds %d token(s) after peer demotion, want 0 drained (#17842)", n)
	}
	vi.mu.RLock()
	force := vi.forcePreemptOnce
	vi.mu.RUnlock()
	if force {
		t.Fatal("forcePreemptOnce still set after peer demotion, want cleared (#17842)")
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("adverts sent on demotion = %v, want none (becomeBackup sends nothing)", extra)
	}

	// First BACKUP iteration: pre-fix the stale token fires here and
	// re-promotes (force bypasses the priority gate against the live
	// 250 master). It must stay BACKUP and send nothing.
	runStepBackup16766(t, vi, masterDown, advert, preemptHold)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after first BACKUP iteration = %s, want BACKUP (stale preempt token re-promoted the just-demoted node, #17842)", got)
	}
	if extra := drainAdverts16766(adverts); len(extra) != 0 {
		t.Fatalf("extra adverts after demotion = %v, want none (#17842)", extra)
	}
	for _, s := range drainEvents16766(eventCh) {
		if s == StateMaster {
			t.Fatal("spurious MASTER event after peer demotion (#17842)")
		}
	}
}

// TestStalePreemptToken17842_ControlPostDemotionBackupKickStillPreempts
// is the control row: a kick legitimately posted AFTER the demotion,
// while BACKUP, survives and promotes (the #2082 shortcut is not
// broken by the demotion drain — it fires for a fresh tenure signal,
// not a stale MASTER-tenure one).
func TestStalePreemptToken17842_ControlPostDemotionBackupKickStillPreempts(t *testing.T) {
	vi, _ := newStaleTokenInstance16766(t)
	adverts := capturePriorities16766(t)
	vi.setState(StateMaster)

	// Demote with NO tenure token pending.
	masterDown, advert, preemptHold := longTimers(t)
	vi.handleMasterRx(&VRRPPacket{Priority: 250, SrcIP: net.IPv4(10, 0, 0, 2)}, masterDown, advert)
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state after peer demotion = %s, want BACKUP", got)
	}
	// Age out the just-learned master (priority 250) so the control
	// exercises the #2082 no-live-master shortcut rather than the
	// priority gate; the 12s master-down safety horizon is untouched.
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-time.Hour)
	vi.mu.Unlock()
	_ = drainAdverts16766(adverts)

	// Legitimate BACKUP kick (sync-hold release).
	vi.triggerPreemptNow()
	if n := len(vi.preemptNowCh); n != 1 {
		t.Fatalf("preemptNowCh holds %d token(s) for BACKUP, want 1", n)
	}
	if stop := vi.stepBackup(masterDown, advert, preemptHold); stop {
		t.Fatal("stepBackup returned stop=true on release kick")
	}
	if got := vi.getState(); got != StateMaster {
		t.Fatalf("state = %s, want MASTER (BACKUP kick after demotion must still preempt, #2082)", got)
	}
}
