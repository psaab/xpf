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

// pendingResign is one extracted forced resignation: the stashed priority
// to install plus the resignEpoch observed at extraction (#17859).
type pendingResign struct {
	priority int
	epoch    uint64
}

// applyPendingResign installs the stashed resigning priority into
// cfg.Priority. Called by becomeBackup once the VIP release has been
// actuated, and by the stepBackup resign arm for an already-BACKUP
// instance (whose VIPs are already off the wire), so priority 0 never
// reaches a routine advert while this node still holds its VIPs.
// No-op when no resign is pending.
//
// #17859: split into two phases. extractPendingResign snapshots the
// stash and clears the pending flag under resignMu; commitPendingResign
// installs it under mu. A cluster-authoritative priority restore
// (UpdateRGPriority, updateConfig) can complete between the phases —
// in that window the pending flag is already false, so the flag alone
// cannot cancel the extracted value. commitPendingResign therefore
// re-checks resignEpoch under mu and drops a superseded extraction
// instead of overwriting the restored priority.
func (vi *vrrpInstance) applyPendingResign() {
	r, ok := vi.extractPendingResign()
	if !ok {
		return
	}
	vi.commitPendingResign(r)
}

// extractPendingResign is phase 1 of applyPendingResign: snapshot the
// stashed priority and clear the pending flag. The phases are split so
// the #17859 regression test can interleave a priority restore inside
// the real window (extracted, not yet installed); production code uses
// applyPendingResign, which runs the phases back to back.
func (vi *vrrpInstance) extractPendingResign() (pendingResign, bool) {
	vi.resignMu.Lock()
	if !vi.resignPending {
		vi.resignMu.Unlock()
		return pendingResign{}, false
	}
	r := pendingResign{priority: vi.resignPriority, epoch: vi.resignEpoch}
	vi.resignPending = false
	vi.resignMu.Unlock()
	return r, true
}

// commitPendingResign is phase 2 of applyPendingResign: install the
// extracted priority unless a discard superseded it while this
// goroutine waited for mu (#17859). Every discard site bumps
// resignEpoch while holding mu, and the check plus the write happen
// under one mu hold, so mu ordering alone decides the outcome: discard
// first drops this install; commit first lets the completed restore
// overwrite the 0 afterwards. Either way the cluster-authoritative
// restored priority survives.
func (vi *vrrpInstance) commitPendingResign(r pendingResign) {
	vi.mu.Lock()
	vi.resignMu.Lock()
	superseded := vi.resignEpoch != r.epoch
	vi.resignMu.Unlock()
	if !superseded {
		vi.cfg.Priority = r.priority
	}
	vi.mu.Unlock()
}

// discardPendingResignLocked drops a pending resignation WITHOUT
// installing its stashed priority (#16821). A superseding priority
// assignment (UpdateRGPriority, updateConfig) is cluster-authoritative:
// the RG has been driven back to Primary (or reconfigured) before
// becomeBackup actuated the resign, so the stashed 0 must not survive
// to be installed by a later, unrelated step-down. The caller has
// already written the replacement priority to cfg.Priority.
//
// #17859: the caller MUST hold mu — the same critical section that
// wrote the replacement priority (hence the Locked suffix, like
// removeVIPsLocked). Discarding bumps resignEpoch, which
// commitPendingResign re-checks under mu; a discard racing outside
// that critical section can complete after a commit already installed
// the stale 0, and nothing would repair cfg.Priority until reconcile.
func (vi *vrrpInstance) discardPendingResignLocked() {
	vi.resignMu.Lock()
	defer vi.resignMu.Unlock()
	vi.resignPending = false
	vi.resignEpoch++
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
