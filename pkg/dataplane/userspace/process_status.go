package userspace

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

func (m *Manager) syncSnapshotLocked() error {
	if m.proc == nil || m.proc.Process == nil || m.lastSnapshot == nil {
		return nil
	}
	planKey := snapshotBindingPlanKey(m.lastSnapshot)
	if m.publishedSnapshot >= m.lastSnapshot.Generation {
		return nil
	}
	// #8597 K82: the catch-up below presupposes the helper is holding a snapshot
	// THIS Manager published. `m.generation` is per-incarnation and lives only
	// in memory (manager.go), so a generation number from a helper that
	// outlived a daemon restart is not comparable to this incarnation's at all:
	// a retained helper (process.go returns without restarting when the config
	// is equal and the ping succeeds) keeps reporting the OLD incarnation's
	// LastSnapshotGeneration, which is >= this Manager's first snapshot for any
	// prior value. The branch would then mark that first snapshot published AND
	// applied without ever sending it, and suppress the publish until the next
	// commit moved the generation past the stale one.
	//
	// `publishedSnapshot != 0` is the evidence the branch was always missing:
	// until this Manager has published something, no generation the helper
	// reports says anything about what it holds. A fresh Manager therefore
	// falls through to the publish path below, which is what the fresh-Manager
	// path in manager_compile.go already does unconditionally.
	// #9520: a generation proves nothing about content while an earlier apply's
	// outcome is unknown, so the catch-up stands down and the publish below runs.
	// #9684: nor while a partial update's outcome is.
	if m.publishedSnapshot != 0 && m.lastStatus.LastSnapshotGeneration >= m.lastSnapshot.Generation &&
		!m.applySnapshotOutcomeUnknown && m.partialOutcomeUnknown == 0 {
		// #1197 v7 (Codex code-review v6): status-loop catch-up
		// path. Helper has the snapshot; mirror the FULL
		// successful-apply_snapshot bookkeeping, otherwise
		// downstream paths see stale publishedPlanKey /
		// lastSnapshotHash and may force unnecessary refreshes
		// or break the same-plan-during-XSK-startup exception.
		hash, hashOK := snapshotContentHash(m.lastSnapshot)
		m.publishedSnapshot = m.lastSnapshot.Generation
		m.publishedPlanKey = planKey
		// #2079: the helper already reports this generation as applied
		// (status.LastSnapshotGeneration >= m.lastSnapshot.Generation
		// gated this branch), so it IS the applied snapshot.
		m.markAppliedSnapshotLocked()
		if hashOK {
			m.lastSnapshotHash = hash
		}
		m.rebuildNeighborIndex()
		m.rebuildMonitoredIfindexes()
		return nil
	}
	// Publish the initial snapshot immediately so the helper can plan its
	// bindings. After that, defer newer snapshots until the first XSK
	// liveness outcome is known. HA startup can emit several snapshots in
	// quick succession as VIPs and routes converge; pushing every one of
	// them forces back-to-back full AF_XDP reconciles and self-collides.
	//
	// EXCEPTION: allow same-plan refreshes (FIB-only updates) through even
	// during XSK startup. These don't trigger XSK rebinding — they only
	// update routes and neighbors. Blocking them creates a deadlock: XSK
	// liveness needs RX traffic, but transit traffic needs FIB data that
	// hasn't been published yet.
	xskStartup := m.publishedSnapshot != 0 && !m.xskLivenessProven && !m.xskLivenessFailed
	if xskStartup && (m.publishedPlanKey == "" || m.publishedPlanKey != planKey) {
		return nil
	}
	// #9684: re-sample any section a lost partial update left unknown, only once
	// the gate above lets this publish proceed. A deferred tick then costs no
	// kernel sample, which matters because the probe extends while a link is idle
	// and that window has no bound. A re-sample never moves the binding plan
	// (resampleUnresolvedSectionsLocked keeps the fabric rows' plan half), so the
	// gate's decision holds for the copy that will be sent.
	retained := *m.lastSnapshot
	resampled := m.resampleUnresolvedSectionsLocked(&retained)
	if xskStartup {
		slog.Info("userspace: publishing deferred same-plan snapshot during XSK startup",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
			"published", m.publishedSnapshot)
	}
	if m.publishedSnapshot != 0 && m.publishedPlanKey != "" && m.publishedPlanKey != planKey {
		slog.Info(
			"userspace: restarting helper for binding plan change",
			"generation", m.lastSnapshot.Generation,
			"fib_generation", m.lastSnapshot.FIBGeneration,
		)
		cfg := m.cfg
		m.stopLocked()
		if err := m.ensureProcessLocked(cfg); err != nil {
			return fmt.Errorf("restart userspace helper for binding plan change: %w", err)
		}
	}
	// Content-hash dedup: skip the control socket publish if the snapshot's
	// forwarding-relevant content hasn't changed since the last publish.
	// This eliminates redundant publishes during route convergence where
	// BumpFIBGeneration fires repeatedly but routes/neighbors are unchanged.
	hash, hashOK := snapshotContentHash(&retained)
	// #9520 / #9684: not while an earlier apply's or partial update's outcome is
	// unknown; see the catch-up above.
	if hashOK && hash == m.lastSnapshotHash && m.publishedSnapshot != 0 && !m.applySnapshotOutcomeUnknown &&
		m.partialOutcomeUnknown == 0 {
		// Still update the published generation so subsequent checks pass.
		m.publishedSnapshot = m.lastSnapshot.Generation
		return nil
	}
	// #1197 v5 (Codex code-review v4 #2): publishable-only filter
	// for parity with update_neighbors path.
	publishSnap := retained
	publishSnap.Neighbors = filterPublishableNeighbors(retained.Neighbors)
	// #5488 (F7): mapsMutatedInPlace is unconditionally true here for the same
	// reason the publishSnapshotFailClosedLocked call below passes true — the
	// only producer of an unpublished lastSnapshot is Compile's pendingXSKStartup
	// branch, which ALWAYS mutated the classifier maps in place first. So a
	// failed disarm here must also drive ctrl to 0 rather than leave the shim
	// running maps a generation ahead of the applied snapshot.
	if err := m.ensureRequiredSnapshotProtocolLocked(&publishSnap); err != nil {
		return m.disarmSnapshotProtocolFailClosedLocked(&publishSnap, err, true)
	}
	// #2124: this is the XSK-startup deferred same-plan publish path, which
	// publishes apply_snapshot independently of Compile(). Disarm before
	// publishing an unsupported-config snapshot here too, so an old
	// same-protocol-version helper that drops the `__unsupported__` sentinel
	// cannot process the resulting match-any rule while still armed.
	if err := m.disarmBeforeUnsupportedPublishLocked(&publishSnap); err != nil {
		return err
	}
	var status ProcessStatus
	// #4959: this deferred-publish resume path only ever publishes an
	// m.lastSnapshot that the pendingXSKStartup branch of Compile left ahead of
	// m.publishedSnapshot — and that branch ALWAYS mutated the ingress/local/
	// interface-NAT classifier BPF maps IN PLACE first
	// (syncUserspaceClassifierMapsFailClosedLocked(snap)) with ctrl still
	// enabled. It is the sole producer of an unpublished lastSnapshot: every
	// other publish site (Compile normal path, route-overlay, policy-scheduler,
	// deferred-worker-arm) advances m.publishedSnapshot only AFTER a successful
	// publish, so none can strand a same-plan refresh here. An address-only
	// commit landing during the XSK-startup liveness-probe window (ctrl flipped
	// to Enabled=1 to probe) is exactly that case. Therefore mapsMutatedInPlace
	// is unconditionally true here: if the helper REJECTS this publish it keeps
	// enforcing the previous-good snapshot, so leaving ctrl enabled would run
	// the shim against classifier maps a generation ahead of the applied Rust
	// snapshot (fail OPEN). publishSnapshotFailClosedLocked disables ctrl on a
	// rejection so transit drops to the kernel-only fail-closed posture.
	if err := m.publishSnapshotFailClosedLocked(&publishSnap, &status, true); err != nil {
		return err
	}
	// #1197 v5 (Codex code-review v4 #1): rebuild listener
	// caches AFTER successful publish on the deferred-publish
	// path too. Compile() defers when XSK is starting up; this
	// is where the snapshot actually lands in userspace-dp.
	m.logWgEndpointSetTransitionLocked(&publishSnap, "deferred-sync")
	if resampled != 0 {
		// #9684: record the re-sampled sections the helper now holds. hash and
		// planKey were already taken from this copy.
		m.lastSnapshot.Neighbors = retained.Neighbors
		m.lastSnapshot.Fabrics = retained.Fabrics
		m.resolvePartialOutcomesLocked(resampled)
	}
	// #9520: a content-conflict republish moves the snapshot to a fresh generation.
	m.adoptPublishedGenerationLocked(m.lastSnapshot, publishSnap.Generation)
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = m.lastSnapshot.Generation
	m.publishedPlanKey = planKey
	// #2079: deferred full apply_snapshot succeeded — record applied.
	m.markAppliedSnapshotLocked()
	if hashOK {
		m.lastSnapshotHash = hash
	}
	if err := m.applyHelperStatusLocked(&status); err != nil {
		return fmt.Errorf("sync helper status: %w", err)
	}
	return nil
}

func (m *Manager) ensureStatusLoopLocked() {
	if m.syncCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.syncCancel = cancel
	go m.statusLoop(ctx)
}

// statusLoopInterval is the reconcile-tick period. It is a package var, not a
// literal, purely so a concurrency test can drive many real ticks against a real
// link cycle in a fraction of a second instead of one tick per wall-clock second
// (#6871). Production never reassigns it; the value is the 1s the control-socket
// contention budget in CLAUDE.md is written against. Mirrors the
// linkCycleRebindSleep seam in process_linkcycle.go.
var statusLoopInterval = time.Second

func (m *Manager) statusLoop(ctx context.Context) {
	ticker := time.NewTicker(statusLoopInterval)
	defer ticker.Stop()
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.proc == nil {
				m.mu.Unlock()
				return
			}
			// #6871: a RETH MAC link cycle owns the dataplane between
			// PrepareLinkCycle and NotifyLinkCycle, and this tick is the busiest
			// producer in that window. Skip the WHOLE body, not one publish:
			// four separate paths below restart the workers PrepareLinkCycle
			// just joined, and a fifth re-enables ctrl on XSK sockets whose
			// queues the cycle is destroying —
			//
			//   - syncSnapshotLocked's plan-key branch stopLocked()s and
			//     respawns the helper PROCESS;
			//   - retryDeferredWorkerArmLocked republishes DeferWorkers=false;
			//   - maybeAutoRebindBusyBindingsLocked sends "rebind" directly;
			//   - verifyBindingsMapLocked repopulates the very binding rows a
			//     fail-closed ctrl disable may have just cleared;
			//   - applyHelperStatusLocked writes the ctrl gate.
			//
			// Nothing is lost by skipping: every action in this body is
			// LEVEL-triggered on persistent manager state (publishedSnapshot vs
			// lastSnapshot.Generation, pendingWorkerArm, pendingHAStateClear,
			// lastStatus.ForwardingArmed vs desired), so the next tick after the
			// lease ends re-evaluates the same conditions and services whatever
			// is still outstanding. The one per-tick value, prevActiveSig, is
			// only ever consulted alongside helperActiveSig, which is read fresh
			// from the helper's own status.
			if m.linkCycleInFlight() {
				m.mu.Unlock()
				slog.Debug("userspace: status tick skipped; RETH MAC link cycle in flight")
				continue
			}
			prevActiveSig := activeHAGroupSignature(m.haGroups)
			var status ProcessStatus
			if err := m.requestLocked(ControlRequest{Type: "status"}, &status); err == nil {
				// #9651: an answered poll resets the wedge count.
				m.noteStatusPollResultLocked(nil, time.Now())
				// #6034: the helper's replace-generation fence can outlive this
				// Manager (for example across a future reconnect/ISSU). Resume from
				// its applied generation before any reconciliation on this tick can
				// publish another neighbor replace. m.mu is held for the whole poll.
				m.seedNeighborReplaceGenerationLocked(status.ManagerNeighborGeneration)
				if err := m.applyHelperStatusLocked(&status); err != nil {
					slog.Warn("userspace dataplane status sync failed", "err", err)
				} else {
					// Bindings watchdog (#473): verify the BPF map matches
					// the helper's reported state. Only run after a successful
					// status update — stale m.lastStatus could cause incorrect
					// repairs.
					repaired := m.verifyBindingsMapLocked()
					m.maybeAutoRebindBusyBindingsLocked(time.Now(), repaired)
				}
				if m.lastSnapshot != nil && m.publishedSnapshot < m.lastSnapshot.Generation {
					if err := m.syncSnapshotLocked(); err != nil {
						slog.Warn("userspace dataplane snapshot sync failed", "err", err)
					}
				}
				// #5134: settle a deferred-MAC worker-arm debt. A live RETH
				// virtual-MAC change with no link cycle publishes a workerless
				// DeferWorkers=true snapshot; the daemon's mandatory re-apply
				// arms the workers. If that re-apply failed, the daemon recorded
				// generation debt here — retry the DeferWorkers=false publish
				// until the workers bind, instead of leaving a non-forwarding
				// snapshot with the commit reported successful.
				if m.pendingWorkerArm {
					if err := m.retryDeferredWorkerArmLocked(); err != nil {
						slog.Warn("userspace: deferred-worker arm retry failed; will retry", "err", err)
					}
				}
				// #5487: settle a stranded standalone HA-state clear. The
				// clusterHA-gated HA sync below never retries the empty
				// update_ha_state on a standalone node, so a transient failure
				// during a cluster->standalone reconfig would leave stale helper
				// HA groups that keep owner-RG-0 transit HAInactive (drop). Retry
				// the idempotent clear here (ungated by clusterHA, but only while
				// standalone) until it succeeds.
				m.retryPendingHAStateClearLocked()
				helperActiveSig := activeHAGroupSignatureSlice(status.HAGroups)
				if m.clusterHA {
					_ = m.refreshHAStateFromMapsLocked()
				}
				newActiveSig := activeHAGroupSignature(m.haGroups)
				if m.clusterHA && newActiveSig != "" && time.Since(m.lastRGActivateTime) >= 2*time.Second {
					// Only sync watchdog updates to the helper from the poll.
					// Do NOT sync active/inactive transitions here — that's
					// handled by UpdateRGActive which must be the sole source
					// of demotion/activation deltas. If the poll syncs first,
					// the helper sees no delta and skips FlushFlowCaches.
					// Skip entirely for 2s after UpdateRGActive to avoid
					// control socket contention during post-transition work.
					if helperActiveSig != newActiveSig || newActiveSig != prevActiveSig {
						// Sync watchdog timestamps only (HA state update
						// without active/inactive change detection).
						// Throttle to every 5s to avoid control socket
						// contention with session installs during bulk sync.
						if time.Since(m.lastHASyncTime) >= 5*time.Second {
							if err := m.syncHAWatchdogOnlyLocked(); err != nil {
								slog.Warn("userspace dataplane HA watchdog sync failed", "err", err)
							}
							m.lastHASyncTime = time.Now()
						}
					}
					// Do not bootstrap NAPI queues or kick neighbor repair on
					// HA ownership changes. By the time UpdateRGActive runs, the
					// standby must already be forwarding-ready; otherwise
					// TakeoverReady() should have blocked the handoff earlier.
				}
				if err := m.syncDesiredForwardingStateLocked(); err != nil {
					slog.Warn("userspace dataplane forwarding sync failed", "err", err)
				}
			} else {
				slog.Warn("userspace dataplane status poll failed", "err", err)
				// #9651: a helper that answers nothing for long enough is killed,
				// and the supervisor fails closed and restarts it.
				if now := time.Now(); m.noteStatusPollResultLocked(err, now) {
					m.killWedgedHelperLocked(now)
				}
			}
			// Keep the targeted kernel prewarm during initial startup. After
			// startup, continue a throttled standby-only neighbor prewarm so HA
			// standby nodes already have WAN next-hop resolution before the
			// first redirected packets arrive.
			now := time.Now()
			if now.Sub(startTime) < 60*time.Second && m.lastSnapshot != nil && m.lastSnapshot.Config != nil {
				m.proactiveNeighborResolveAsyncLocked()
			} else if m.shouldStandbyNeighborPrewarmLocked(now) {
				m.lastStandbyNeighResolve = now
				m.proactiveNeighborResolveAsyncLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) shouldStandbyNeighborPrewarmLocked(now time.Time) bool {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return false
	}
	if !m.clusterHA || !m.configHasDataRGLocked() || m.hasActiveDataRGLocked() {
		return false
	}
	if m.proc == nil || m.proc.Process == nil {
		return false
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false
	}
	if !m.lastStandbyNeighResolve.IsZero() && now.Sub(m.lastStandbyNeighResolve) < 10*time.Second {
		return false
	}
	return true
}
