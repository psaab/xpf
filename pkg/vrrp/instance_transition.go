package vrrp

import (
	"log/slog"
	"net"
	"strings"
	"time"
)

// vrrpInstance state transitions: the state accessors, become-master and
// become-backup, the retry re-arm, and the VIP family predicates they consult.
//
// becomeMaster is load-bearing beyond its size: its critical path is
// addVIPs -> sendAdvert -> emitEvent SYNCHRONOUSLY, then go sendGARP(false)
// asynchronously, and the #2081 GARP suppression gates (garpEpoch/lastGARPEpoch
// dedup plus the 500ms lastGARPTime dampener) interact with ReconcileVIPs
// calling sendGARP(true) after a MAC change. Moving it is safe; REORDERING
// anything inside it is not.
//
// Split out of instance.go for the #8090 modularity floor. Pure move.

func (vi *vrrpInstance) getState() VRRPState {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.state
}

func (vi *vrrpInstance) setState(s VRRPState) {
	vi.mu.Lock()
	changed := vi.state != s
	vi.state = s
	vi.mu.Unlock()
	// A real state change starts a new ownership tenure. Bump the generation
	// so any in-flight VIP actuation (becomeMaster/ReconcileVIPs) that captured
	// the prior generation revalidates as stale and rolls back instead of
	// advertising/GARPing for a tenure we have left (#5082). ownerGen is atomic
	// and independent of vi.mu, so a concurrent ReconcileVIPs holding vipMu
	// still observes this bump when it rechecks after its netlink add.
	if changed {
		vi.ownerGen.Add(1)
	}
}

// hasIPv4VIP reports whether this instance advertises at least one IPv4 virtual
// address (dual-stack or IPv4-only). It anchors the equal-priority MASTER-MASTER
// tie-break to the v4 family so both nodes decide off the same ordering (#4376).
// cfg.VirtualAddresses is immutable per instance (VIP changes rebuild the
// instance), so no lock is needed — same rationale as vipAddrSet.
func (vi *vrrpInstance) hasIPv4VIP() bool {
	hasIPv4, _ := vi.vipFamilies()
	return hasIPv4
}

// vipFamilies reports which IP families have at least one parseable virtual
// address. Instance VIPs are immutable after construction, so callers may use
// it without locking.
func (vi *vrrpInstance) vipFamilies() (hasIPv4, hasIPv6 bool) {
	for _, vip := range vi.cfg.VirtualAddresses {
		addr := vip
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if ip := net.ParseIP(addr); ip != nil {
			if ip.To4() != nil {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}
	}
	return hasIPv4, hasIPv6
}

// becomeMaster transitions to Master state: add VIPs, and — only if the
// required VIP set actually actuated in the kernel — send advert, emit event,
// then send GARP/NA asynchronously. The critical path is addVIPs (kernel needs
// VIP addresses for bpf_fib_lookup) + sendAdvert (tells peer to step down).
// GARP only updates L2 switch/router MAC tables and runs in the background.
//
// Fail-closed ownership (#5082): a transient netlink failure must NOT let the
// peer and dependent services trust an owner that cannot receive VIP traffic.
// addVIPs now returns a structured result; if any required VIP failed to
// actuate (or a concurrent demotion superseded this tenure), becomeMaster rolls
// back any partial adds, reverts to BACKUP, and returns false WITHOUT
// advertising or emitting a MASTER event. The caller re-arms the master-down
// timer so the election retries on the next horizon. On the clean success path
// nothing is added versus before (the vipMu lock is uncontended), so the ~60ms
// failover timing is preserved.
//
// Returns true iff ownership was claimed (VIP set actuated and advert/event
// published).
func (vi *vrrpInstance) becomeMaster() bool {
	// #6779: refuse ownership we cannot advertise — #5082's "do not claim what
	// you cannot back" applied to the advert. Before setState/addVIPs so there
	// is nothing to roll back. Rationale + log-rate note: advert_capacity.go.
	if vi.advertCapacityErr != nil {
		slog.Debug("vrrp: cannot build a legal advertisement, not claiming ownership (fail-closed)",
			"key", vi.key(), "err", vi.advertCapacityErr)
		return false
	}
	pri := vi.getPriority()
	slog.Info("vrrp: transitioning to MASTER",
		"key", vi.key(), "priority", pri)
	vi.setState(StateMaster)
	gen := vi.ownerGen.Load()

	vi.vipMu.Lock()
	res := vi.addVIPsLocked()
	superseded := vi.ownerGen.Load() != gen
	if !res.ok() || superseded {
		// Fail-closed: the required VIP set did not actuate, or a newer
		// transition superseded this one while we were in netlink. Roll back
		// any partially-added VIPs, revert to a BACKUP tenure, and do NOT claim
		// ownership. Reverting to StateBackup (an existing state) integrates
		// with the run-loop's masterDownTimer retry — no parallel state system.
		// (superseded is captured before the setState bump below so the log
		// reflects the true reason, not the revert's own generation bump.)
		// #9509: a failed rollback leaves a VIP on a node that is about to publish
		// BACKUP, a duplicate-address hazard against the peer. Nothing else sweeps
		// it: the master-down retry never fires while a healthy peer adverts. It is
		// surfaced below exactly as becomeBackup surfaces its removal: after BACKUP
		// is set (the reconcile's generation fence names this tenure) and vipMu is
		// released (the reconcile takes it). The Error log's applied/failed lists
		// describe the ADD, not this removal, so they could never report it.
		rollbackErr := vi.removeVIPsLocked(res.applied)
		vi.setState(StateBackup)
		vi.vipMu.Unlock()
		slog.Error("vrrp: VIP actuation failed, not claiming ownership (fail-closed)",
			"key", vi.key(), "failed", res.failed, "applied", res.applied,
			"link_err", res.linkErr, "superseded", superseded, "rollback_err", rollbackErr)
		// Unconditional, like becomeBackup: a clean rollback clears a divergence
		// flag an earlier, now-superseded reconcile could no longer clear.
		vi.surfaceStaleVIP(rollbackErr, "becomeMaster-rollback")
		// Publish the honest BACKUP state so dependent services never trust an
		// ownership we could not back.
		vi.emitEvent()
		return false
	}
	vi.vipMu.Unlock()

	vi.sendAdvert(pri)
	vi.emitEvent()
	vi.garpEpoch.Add(1)
	if !vi.suppressGARP.Load() {
		// Non-forced: a routine MASTER transition is rate-limited by the
		// 500ms dampener (the epoch dedup still guarantees one burst per
		// transition). Post-MAC-change reconcile uses the forced path.
		go vi.sendGARP(false)
	} else {
		slog.Info("vrrp: GARP suppressed (strict-vip-ownership)",
			"key", vi.key())
	}
	return true
}

// rearmForRetry re-arms the master-down timer after a failed Master promotion
// (VIP actuation failure in becomeMaster reverted us to BACKUP) so the election
// retries on the next master-down horizon instead of leaving the instance idle.
// Used by the run-loop's becomeMaster call sites (#5082).
func (vi *vrrpInstance) rearmForRetry(masterDownTimer *time.Timer) {
	stopAndDrainTimer(masterDownTimer)
	masterDownTimer.Reset(vi.masterDownInterval())
}

// becomeBackup transitions to Backup state: remove VIPs, reset timers.
//
// Verified BACKUP ownership (#5482): the BACKUP-side symmetry of the #5082
// fail-closed MASTER path. We ARE stepping down (a superior/equal master is
// taking over), so publishing BACKUP is the honest role — refusing to emit would
// risk split-brain. But the pre-#5482 code called the VOID removeVIPs and emitted
// BACKUP unconditionally, so a swallowed netlink removal failure left this
// now-BACKUP node still answering ARP for the VIP (duplicate-address hazard vs
// the new master). surfaceStaleVIP records the divergence loudly and schedules an
// async reconcile so the stale VIP clears without a silent hazard, while
// emitEvent still publishes the true BACKUP state.
func (vi *vrrpInstance) becomeBackup(masterDownTimer, advertTimer *time.Timer) {
	slog.Info("vrrp: transitioning to BACKUP",
		"key", vi.key())
	vi.setState(StateBackup)
	removeErr := vi.removeVIPs()
	vi.surfaceStaleVIP(removeErr, "becomeBackup")
	advertTimer.Stop()
	masterDownTimer.Reset(vi.masterDownInterval())
	// A MASTER stepping down to a worthy higher/tie-break master begins a
	// fresh BACKUP tenure with no pending resign decision — clear the
	// one-shot preempt-hold bypass so a stale flag from an earlier resign
	// cannot leak into the next masterDownTimer expiry (#2850).
	vi.mu.Lock()
	vi.skipNextPreemptHold = false
	vi.mu.Unlock()
	vi.emitEvent()
	// #6177 item 1: the VIPs are now physically off the interface (or
	// removeErr says why they are not). Report to every resign barrier armed
	// on this instance so a fenced remote failover releases its applied-ack on
	// VIP REMOVAL, not merely on "resignation signalled + priority 0". This is
	// the last statement in the function on purpose: a waiter that observes the
	// completion must not be able to observe it before the removal ran.
	vi.notifyResigned(removeErr)
}
