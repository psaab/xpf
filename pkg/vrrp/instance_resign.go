package vrrp

import (
	"fmt"
)

// vrrpInstance resign path: the operator-triggered resign, its acknowledgement
// barrier, and the stale-VIP error the acknowledgement can carry.
// Split out of instance.go for the #8090 modularity floor. Pure move.

// triggerResign signals the run loop to resign from MASTER by sending
// priority-0 adverts and transitioning to BACKUP. Non-blocking.
func (vi *vrrpInstance) triggerResign() {
	select {
	case vi.resignCh <- struct{}{}:
	default:
	}
}

// beginResign records a pending forced resignation (#15213 A25-06):
// priority 0 is stashed, NOT written to cfg.Priority, so the routine
// MASTER advert path keeps advertising the pre-resign priority until
// becomeBackup applies the stash. Returns false when a resign is
// already pending (the queued token already covers it).
func (vi *vrrpInstance) beginResign() bool {
	vi.resignMu.Lock()
	defer vi.resignMu.Unlock()
	if vi.resignPending {
		return false
	}
	vi.resignPending = true
	vi.resignPriority = 0
	return true
}

// applyPendingResign installs the stashed resigning priority into
// cfg.Priority. Called by becomeBackup once the VIP release has been
// actuated, so priority 0 never reaches a routine advert while this
// node still holds its VIPs. No-op when no resign is pending.
func (vi *vrrpInstance) applyPendingResign() {
	vi.resignMu.Lock()
	if !vi.resignPending {
		vi.resignMu.Unlock()
		return
	}
	pri := vi.resignPriority
	vi.resignPending = false
	vi.resignMu.Unlock()
	vi.mu.Lock()
	vi.cfg.Priority = pri
	vi.mu.Unlock()
}

// resignIsPending reports whether a forced resignation is queued but
// not yet actuated by becomeBackup.
func (vi *vrrpInstance) resignIsPending() bool {
	vi.resignMu.Lock()
	defer vi.resignMu.Unlock()
	return vi.resignPending
}

// armResignAck registers b as a waiter for this instance's next VIP release.
// The manager calls it BEFORE triggerResign so the run loop cannot complete the
// release between the arm and the trigger and leave the waiter unreported.
func (vi *vrrpInstance) armResignAck(b *ResignBarrier) {
	if b == nil {
		return
	}
	vi.resignAckMu.Lock()
	vi.resignAcks = append(vi.resignAcks, b)
	vi.resignAckMu.Unlock()
}

// notifyResigned reports outcome err to every barrier armed on this instance
// and clears the list, so each registration is reported exactly once and a
// later release cannot double-report an already-completed barrier. err is the
// VIP-removal outcome: nil means the addresses are off the wire.
func (vi *vrrpInstance) notifyResigned(err error) {
	vi.resignAckMu.Lock()
	waiters := vi.resignAcks
	vi.resignAcks = nil
	vi.resignAckMu.Unlock()
	for _, b := range waiters {
		b.report(err)
	}
}

// staleVIPResignErr converts a lingering VIP divergence (#5482) into a resign
// verdict. An instance that is already BACKUP has no VIP tenure to tear down —
// unless a previous removal FAILED and its async reconcile has not yet cleared
// the address, in which case this node may still be answering ARP for the VIP
// and must not report a clean release to a two-owner fence (#6177 item 1).
func (vi *vrrpInstance) staleVIPResignErr() error {
	if vi.vipDiverged.Load() {
		return fmt.Errorf("%w: instance %s", ErrStaleVIPOnBackup, vi.key())
	}
	return nil
}
