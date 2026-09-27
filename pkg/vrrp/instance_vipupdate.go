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
//   - MASTER: normally add the added VIPs first, then remove the removed VIPs.
//     If the old+added union exceeds advert capacity, remove first and defer
//     additions until every removal succeeds; a failed delete therefore leaves
//     the old legal set rather than an unadvertisable union. Then announce the
//     stored set and GARP/NA only newly added VIPs. Membership changes advance
//     the burst epoch, invalidating callbacks for withdrawn addresses.
//   - BACKUP (or INIT): added VIPs need no actuation (promotion adds the stored
//     set); removed VIPs are swept best-effort in case a stale address lingers.
//     If a failed removal would make the stored union over-capacity, defer the
//     new set until removal succeeds.
//
// Failure semantics are kernel-truth (#5082 fail-closed doctrine): a VIP
// whose add failed or was deferred is EXCLUDED from the stored set, and a VIP
// whose remove failed is KEPT (it remains on the wire). The next ~2s reconcile
// observes desired != stored and retries. Incomplete deltas are surfaced on
// the instance and gate RGVRRPReady until a successful retry.
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

	// If the old+added union cannot fit on the wire, delete first. A failed
	// removal then leaves a legal subset of the old set and defers additions;
	// no address-owning MASTER is published with an over-capacity union.
	union := make([]string, 0, len(old)+len(added))
	union = append(union, old...)
	union = append(union, added...)
	deleteFirst := checkAdvertCapacity(union) != nil

	var addRes vipActuationResult
	var removeErr error
	var removedFailed map[string]struct{}
	remove := func() {
		if len(removed) == 0 {
			return
		}
		failed, err := vi.removeVIPsResultLocked(removed)
		removeErr = err
		if len(failed) > 0 {
			removedFailed = make(map[string]struct{}, len(failed))
			for _, vip := range failed {
				removedFailed[vip] = struct{}{}
			}
		}
	}
	add := func() {
		if state == StateMaster && len(added) > 0 {
			addRes = vi.addVIPsListLocked(added)
		}
	}
	if deleteFirst {
		remove()
		if len(removed) > 0 && removeErr == nil {
			add()
		} else if len(added) > 0 {
			// These additions were not attempted. Mark them unapplied so the
			// stored kernel-truth set remains within the old legal capacity.
			addRes.failed = append(addRes.failed, added...)
		}
	} else {
		add()
		remove()
	}

	// Build the stored set in want order, minus failed/deferred adds, plus
	// failed removes (kept: still on the wire). On BACKUP, added VIPs are
	// configured but not actuated unless an over-capacity failed removal
	// requires deferring them to keep the stored set advertisable.
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
	addedSet, removedSet := vipSetDelta(old, newSet)
	updateGarpEpoch := vi.garpEpoch.Load()
	if len(addedSet) > 0 || len(removedSet) > 0 {
		updateGarpEpoch = vi.garpEpoch.Add(1)
	}
	actuationIncomplete := len(addRes.failed) > 0 || addRes.linkErr != nil || removeErr != nil
	if actuationIncomplete || capErr != nil {
		vi.vipUpdateFailures.Add(1)
		vi.vipUpdateDiverged.Store(true)
	} else {
		vi.vipUpdateDiverged.Store(false)
	}
	curState := vi.state
	curGen := vi.ownerGen.Load()
	vi.mu.Unlock()

	var capCleanupErr error
	if capErr != nil && state == StateMaster {
		// Defensive fail-closed path. The capacity-aware ordering above keeps
		// every validated old/new transition legal, but a future bypass must
		// never leave an address-owning MASTER that cannot serialize adverts.
		vi.setState(StateBackup)
		capCleanupErr = vi.removeVIPsLocked(nil)
		curState = vi.getState()
		curGen = vi.ownerGen.Load()
	}

	announce := state == StateMaster && capErr == nil
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
		slog.Error("vrrp: updated virtual addresses cannot produce a legal "+
			"advertisement; refusing MASTER ownership and withdrawing VIPs",
			"key", vi.key(), "vip_count", len(newSet), "err", capErr)
		if state == StateMaster {
			vi.surfaceStaleVIP(capCleanupErr, "update-capacity-fail-closed")
		}
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
			// updateGarpEpoch names the published VIP membership. sendGARPFor
			// validates it under vipMu so an older full-set snapshot cannot
			// satisfy the added-only announcement's epoch.
			vi.sendGARPFor(addedOK, updateGarpEpoch, gen, true)
		}
	}
	vi.emitEvent()

	if actuationIncomplete || capErr != nil || capCleanupErr != nil {
		return fmt.Errorf("vrrp: VIP set update incomplete on %s: %d/%d adds failed/deferred (link_err=%v) remove_err=%v capacity_err=%v cleanup_err=%v; stored set holds kernel truth, reconcile will retry",
			vi.key(), len(addRes.failed), len(added), addRes.linkErr, removeErr, capErr, capCleanupErr)
	}
	return nil
}
