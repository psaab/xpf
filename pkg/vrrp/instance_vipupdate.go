package vrrp

import (
	"fmt"
	"log/slog"
)

// In-place VIP-set update (#10780).
//
// A commit that changes a RETH unit's address set used to rebuild the VRRP
// instance: UpdateInstances built a replacement and stopped the old one with
// vi.stop(). On a MASTER that teardown resigns — 3x priority-0 adverts plus
// VIP removal — so the peer takes over in ~1ms (handleBackupRx) and the RG
// bounces out and back (via preempt or the 2s posture reconcile) on an
// ordinary day-2 edit, with a dual-rg_active window (single-unit) or a
// split-RG window (multi-unit VLAN). updateVIPs applies the delta to the
// RUNNING instance instead: the MASTER arm is never stopped, no priority-0 is
// ever sent, and only the delta VIPs are actuated and announced.

// vipsSnapshot returns a deep copy of the instance's configured VIP set.
//
// The VIP set is MUTABLE: UpdateInstances applies address-set commits in
// place via updateVIPs instead of rebuilding the instance, so every reader
// outside the manager's m.mu critical section snapshots under vi.mu.RLock.
// The copy keeps advert construction, VIP actuation, GARP, and emitted events
// off a stable slice even if a commit swaps the configured set mid-read. Lock
// order is vipMu → mu (never the reverse): the low-level actuation helpers
// snapshot through here while holding vipMu, and updateVIPs takes vipMu
// before mu.
func (vi *vrrpInstance) vipsSnapshot() []string {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return append([]string(nil), vi.cfg.VirtualAddresses...)
}

// getAdvertCapacityErr reports whether the CURRENT configured VIP set can
// produce a legal VRRPv3 advertisement (#6779). Mu-guarded: updateVIPs
// recomputes it on every in-place VIP-set change; becomeMaster consults it
// before claiming ownership.
func (vi *vrrpInstance) getAdvertCapacityErr() error {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.advertCapacityErr
}

// vipSetDelta partitions a desired VIP set against the current one into added
// (in want, not in old, in want order) and removed (in old, not in want, in
// old order). Set semantics: an order-only difference yields an empty delta,
// so a reordered-but-identical set never touches the kernel or the wire.
func vipSetDelta(old, want []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(old))
	for _, vip := range old {
		oldSet[vip] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, vip := range want {
		wantSet[vip] = struct{}{}
	}
	for _, vip := range want {
		if _, ok := oldSet[vip]; !ok {
			added = append(added, vip)
		}
	}
	for _, vip := range old {
		if _, ok := wantSet[vip]; !ok {
			removed = append(removed, vip)
		}
	}
	return added, removed
}

// updateVIPs applies a new VIP set to a RUNNING instance without restarting
// it. Called on the manager goroutine (which holds m.mu) from the in-place
// arm of UpdateInstances. The instance keeps its sockets, its timers, and its
// state: a MASTER stays MASTER throughout, so no priority-0 resignation and
// no takeover window.
//
// Actuation rules:
//   - MASTER: add the added VIPs (first, so a subnet change never opens a gap
//     with neither address present), remove the removed VIPs, then announce:
//     one immediate advert carrying the new set plus a forced GARP/NA burst
//     for the added VIPs only. Surviving VIPs are never withdrawn or
//     re-announced — no MAC/GARP flap for the untouched set.
//   - BACKUP (or INIT): a backup holds no VIPs, so added VIPs need no
//     actuation (a later promotion adds the full stored set); removed VIPs
//     are swept best-effort in case a stale address lingers. No advert, no
//     GARP — a backup never announces.
//
// Failure semantics are kernel-truth (#5082 fail-closed doctrine): a VIP
// whose add failed is EXCLUDED from the stored set (we must not advertise
// what we cannot back), a VIP whose remove failed is KEPT (it is still on the
// wire). Either way the next ~2s reconcile observes desired != stored and
// retries the remainder, so a transient netlink failure self-heals exactly
// like the #2156 re-drive. The returned error is for the manager's warn log;
// the commit itself still succeeds.
//
// Locking: vipMu is held across the state read, the delta actuation, and the
// snapshot swap, so a demotion either completes fully before this section (we
// see BACKUP and add nothing) or after it (it removes the new configured
// set). Socket I/O (advert, GARP) and the state event run AFTER the unlock,
// matching becomeMaster.
func (vi *vrrpInstance) updateVIPs(desired []string) error {
	want := append([]string(nil), desired...)

	vi.vipMu.Lock()

	vi.mu.Lock()
	old := append([]string(nil), vi.cfg.VirtualAddresses...)
	state := vi.state
	gen := vi.ownerGen.Load()
	vi.mu.Unlock()

	added, removed := vipSetDelta(old, want)
	if len(added) == 0 && len(removed) == 0 {
		// Order-only difference: adopt the desired order so the next
		// reconcile converges, without touching the kernel or the wire.
		vi.mu.Lock()
		if !vipsEqual(old, want) {
			vi.cfg.VirtualAddresses = want
		}
		vi.mu.Unlock()
		vi.vipMu.Unlock()
		vi.emitEvent()
		return nil
	}

	var addRes vipActuationResult
	if state == StateMaster && len(added) > 0 {
		addRes = vi.addVIPsListLocked(added)
	}
	var removeErr error
	var removedFailed map[string]struct{}
	if len(removed) > 0 {
		var failed []string
		failed, removeErr = vi.removeVIPsResultLocked(removed)
		if len(failed) > 0 {
			removedFailed = make(map[string]struct{}, len(failed))
			for _, vip := range failed {
				removedFailed[vip] = struct{}{}
			}
		}
	}

	// Build the stored set in want order, minus failed adds, plus failed
	// removes (kept: still on the wire). On BACKUP nothing was added, so
	// addedOK stays empty and no GARP is ever emitted for this path.
	failedAdd := make(map[string]struct{}, len(addRes.failed))
	for _, vip := range addRes.failed {
		failedAdd[vip] = struct{}{}
	}
	var addedOK []string
	if state == StateMaster {
		for _, vip := range added {
			if _, bad := failedAdd[vip]; !bad {
				addedOK = append(addedOK, vip)
			}
		}
	}
	vi.mu.Lock()
	newSet := make([]string, 0, len(want)+len(removedFailed))
	for _, vip := range want {
		if _, bad := failedAdd[vip]; !bad {
			newSet = append(newSet, vip)
		}
	}
	for _, vip := range removed {
		if _, bad := removedFailed[vip]; bad {
			newSet = append(newSet, vip)
		}
	}
	vi.cfg.VirtualAddresses = newSet
	capErr := checkAdvertCapacity(newSet)
	vi.advertCapacityErr = capErr
	// Ownership revalidation, mirroring reconcileVIP (#5082): becomeMaster
	// publishes MASTER (setState, bumping ownerGen) BEFORE taking vipMu, so
	// vipMu alone does not serialize ownership transitions. A superseding
	// transition rolls back exactly the VIPs this update added and
	// suppresses the announcement. (Unreachable on the MASTER branch today
	// — becomeBackup publishes BACKUP inside vipMu — but the tenure
	// protocol's ordering hazard is exactly what this guards.)
	curState := vi.state
	curGen := vi.ownerGen.Load()
	vi.mu.Unlock()

	announce := state == StateMaster
	if announce && (curState != StateMaster || curGen != gen) {
		// #9509 rationale, same as the superseded-reconcile path: the only
		// transition that can supersede an update holding vipMu is
		// becomeBackup, which removes the full configured set behind this
		// rollback — so a failed rollback here is logged, not surfaced.
		if rbErr := vi.removeVIPsLocked(addedOK); rbErr != nil {
			slog.Warn("vrrp: VIP set update superseded by demotion; rollback incomplete, covered by becomeBackup sweep",
				"key", vi.key(), "rolled_back", addedOK, "rollback_err", rbErr)
		} else {
			slog.Info("vrrp: VIP set update superseded by demotion; rolled back added VIPs, announcement suppressed",
				"key", vi.key(), "rolled_back", addedOK)
		}
		announce = false
	}
	vi.vipMu.Unlock()

	if capErr != nil {
		// Same operator-facing Error as construction (#6779): the stored
		// set cannot advertise, so this instance will not claim MASTER
		// until a later update repairs it. Unreachable via UpdateInstances
		// (the manager refuses to route an over-capacity desired set to
		// this path), but updateVIPs stays fail-closed for any caller.
		slog.Error("vrrp: updated virtual addresses cannot produce a legal "+
			"advertisement; this instance will not claim MASTER (fail-closed)",
			"key", vi.key(), "vip_count", len(newSet), "err", capErr)
	}

	// A new VIP can coincide with the cached advert source (e.g. the VIP
	// set grows over the former primary): re-resolve the send source and
	// the self-check sets against the new exclusion set now, rather than
	// waiting for the addr-watcher's async event, so the immediate advert
	// below already leaves from a valid non-VIP source.
	vi.reresolveLocalAddrs()

	// Announce only for a surviving MASTER tenure: re-check state after the
	// unlock so a demotion that completed behind us suppresses the
	// announcement. The residual check-to-send window matches becomeMaster's
	// inherent exposure (one stale advert/GARP at most, superseded by the
	// demotion's own resignation).
	if announce && vi.getState() == StateMaster {
		vi.sendAdvert(vi.getPriority())
		if len(addedOK) > 0 && !vi.suppressGARP.Load() {
			// Bump garpEpoch so the epoch-dedup does not block this send
			// (same as ReconcileVIPs), and force past the 500ms dampener:
			// a newly-claimed VIP must be announced NOW, not when a
			// routine burst happens to be due.
			vi.garpEpoch.Add(1)
			vi.sendGARPFor(addedOK, true)
		}
	}
	vi.emitEvent()

	if len(addRes.failed) > 0 || addRes.linkErr != nil || removeErr != nil {
		return fmt.Errorf("vrrp: VIP set update incomplete on %s: %d/%d adds failed (link_err=%v) remove_err=%v; stored set holds kernel truth, reconcile will retry",
			vi.key(), len(addRes.failed), len(added), addRes.linkErr, removeErr)
	}
	return nil
}
