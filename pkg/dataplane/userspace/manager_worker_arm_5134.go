package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// RecordDeferredWorkerArmDebt marks that the MANDATORY deferred-MAC re-apply
// failed to publish (#5134). After a live RETH virtual-MAC change with no link
// cycle, the daemon issues a second ApplyConfig to arm the AF_XDP workers with
// the now-correct MAC (the first apply published a workerless
// DeferWorkers=true snapshot). When that re-apply's apply_snapshot fails, the
// manager retains the workerless snapshot as lastSnapshot/publishedSnapshot and
// the commit still reports success — a silent forwarding outage on that node.
//
// The daemon calls this instead of swallowing the ApplyConfig error. The status
// reconcile loop (retryDeferredWorkerArmLocked) then republishes the snapshot
// with DeferWorkers=false on every tick until the workers bind, self-healing a
// transient helper / control-socket error without failing the commit.
func (m *Manager) RecordDeferredWorkerArmDebt() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingWorkerArm = true
}

// retryDeferredWorkerArmLocked settles the #5134 deferred-worker arm debt from
// the status loop. m.mu is held by the caller.
//
// The retained lastSnapshot still carries DeferWorkers=true (the failed
// re-apply never advanced it). The config did not change between the initial
// deferred apply and the failed re-apply, so republish the SAME snapshot
// content with DeferWorkers=false and a bumped generation to arm the workers —
// this is lighter than a full re-compile and mirrors the republish bookkeeping
// used by UpdatePolicyScheduleState / syncSnapshotLocked. On success the debt
// is cleared; a still-failing publish leaves the debt set for the next tick.
func (m *Manager) retryDeferredWorkerArmLocked() error {
	if !m.pendingWorkerArm {
		return nil
	}
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		// Helper not running / nothing published yet: there is no live
		// workerless snapshot to re-arm. A helper (re)start replays through
		// the normal apply path, which arms workers itself. Drop the debt so
		// the reconcile loop does not spin.
		m.pendingWorkerArm = false
		return nil
	}
	if !m.lastSnapshot.DeferWorkers {
		// A later full apply already published a DeferWorkers=false snapshot
		// (workers armed). The debt is settled.
		m.pendingWorkerArm = false
		return nil
	}

	// Compute the next generation locally and commit m.generation ONLY after
	// the publish succeeds (mirrors UpdatePolicyScheduleState). A failed
	// apply_snapshot must not permanently advance m.generation — otherwise
	// each failed retry tick would burn a generation while the debt persists.
	nextGeneration := m.generation + 1
	next := *m.lastSnapshot
	next.DeferWorkers = false
	next.Generation = nextGeneration
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	resampled := m.resampleUnresolvedSectionsLocked(&next) // #9684

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	if err := m.ensureRequiredSnapshotProtocolLocked(&publishSnap); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			return errors.Join(err, disarmErr)
		}
		return err
	}
	if err := m.disarmBeforeUnsupportedPublishLocked(&publishSnap); err != nil {
		return err
	}
	var status ProcessStatus
	if err := m.requestApplySnapshotLocked(&publishSnap, &status); err != nil {
		// Debt stays set — the status loop retries on the next tick.
		return fmt.Errorf("re-arm deferred workers: %w", err)
	}
	m.logWgEndpointSetTransitionLocked(&publishSnap, "deferred-worker-arm")
	// Publish succeeded — commit the generation it carried (#9520: a
	// content-conflict republish moves it past nextGeneration).
	m.adoptPublishedGenerationLocked(&next, publishSnap.Generation)
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
		m.lastSnapshotHash = h
	}
	m.pendingWorkerArm = false
	m.resolvePartialOutcomesLocked(resampled)
	slog.Info("userspace: armed deferred AF_XDP workers after deferred-MAC re-apply retry",
		"generation", next.Generation)
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return fmt.Errorf("sync helper status after deferred-worker arm: %w", err)
	}
	return nil
}
