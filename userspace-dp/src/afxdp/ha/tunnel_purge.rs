// This submodule references shared types only through fully-qualified
// `crate::` paths, so it needs no `use crate::afxdp::*` glob.
impl crate::afxdp::Coordinator {
    /// #1873 R-D: purge every session whose stored tunnel_endpoint_id
    /// was REMAPPED by a snapshot apply — the id is absent from the
    /// new forwarding state, or it now belongs to a DIFFERENT logical
    /// tunnel name (temporal hash reuse, or the one-time
    /// positional->hash upgrade re-id). Without the purge a live
    /// session would re-resolve its stored id into the WRONG tunnel
    /// (cross-tunnel encap) or permanently dead-end on the R-C gate.
    ///
    /// Each purged forward session goes through delete_synced_session
    /// (shared maps + indexes + kernel session map + reverse companion
    /// + worker DeleteSynced broadcast) and emits a Close delta on the
    /// event stream so the Go shadow conntrack and the HA peer
    /// delete-sync stay coherent (the standby additionally runs its
    /// own purge when IT applies the snapshot).
    ///
    /// #8138: `release_against` is the forwarding state whose allocators and
    /// source-NAT rules the purged sessions' reservations must be released
    /// against — NOT `self.forwarding`.
    ///
    /// This is a parameter rather than a read of `self.forwarding` because the
    /// two production callers hold DIFFERENT states at this point, and one of
    /// them holds nothing:
    ///
    ///   - `coordinator/reconcile/snapshot.rs` — `stop_inner(false)` has already
    ///     DEFAULTED `coord.forwarding`, so it carries no rules and no
    ///     allocators. Releasing against it frees nothing while looking like a
    ///     repair.
    ///   - `coordinator/snapshot_refresh.rs` — the purge runs BEFORE
    ///     `self.forwarding = new_forwarding`, so `self.forwarding` is the live
    ///     previous state.
    ///
    /// Both pass `&new_forwarding`, which is correct for both because
    /// `forwarding_build` carries `iface_nat_allocators` across a rebuild by
    /// `Arc::clone` — the new state's allocators ARE the objects the import-time
    /// reservation was taken against.
    pub(crate) fn purge_remapped_tunnel_sessions(
        &self,
        purge_ids: &[u16],
        release_against: &crate::afxdp::types::ForwardingState,
    ) -> usize {
        if purge_ids.is_empty() {
            return 0;
        }
        // #17144: candidates carry their Close delta / reservation alongside
        // the key, so a refused delete can drop both without a second lookup.
        // `delta`/`reservation` are Some only for forward entries.
        struct PurgeCandidate {
            key: crate::session::SessionKey,
            delta: Option<crate::session::SessionDelta>,
            reservation: Option<crate::nat::NatDecision>,
        }
        let mut candidates: Vec<PurgeCandidate> = Vec::new();
        {
            // #6653 sweep: RECOVERING lock. `let Ok(..) else { return 0 }`
            // made the #1873 R-D purge SILENTLY DO NOTHING on a poisoned
            // mutex -- and this purge is what stops a live session
            // re-resolving a remapped tunnel_endpoint_id into the WRONG
            // tunnel (cross-tunnel encap) or dead-ending on the R-C gate.
            // Not named by #6652/#6653/#6654; found by sweeping the predicate
            // rather than the three cited sites.
            let sessions = crate::afxdp::shared_ops::lock_shared_recover(&self.sessions.synced);
            for entry in sessions.values() {
                let id = entry.decision.resolution.tunnel_endpoint_id;
                if id == 0 || !purge_ids.contains(&id) {
                    continue;
                }
                // Reverse entries are purged too: in an asymmetric
                // topology the REVERSE resolution can be the
                // tunnel-marked one while the forward entry is not in
                // the purge set, so relying on the forward pass's
                // companion removal alone would leave the reverse
                // entry dangling on the remapped id (Claude SMR code
                // review r1). delete_synced_session handles a reverse
                // key as a standalone removal. Close deltas are
                // emitted for FORWARD entries only (matching
                // emit_close_delta_with_origin's is_reverse skip — the
                // Go shadow keys off the forward delta).
                let is_forward = !entry.metadata.is_reverse;
                candidates.push(PurgeCandidate {
                    key: entry.key.clone(),
                    delta: None,
                    reservation: None,
                });
                if is_forward {
                    let cand = candidates.last_mut().expect("candidate just pushed");
                    cand.reservation = Some(entry.decision.nat);
                    // #17122: the entry->delta mapping lives once in
                    // `SessionDelta::from_shared`. The two overrides
                    // below are the purge's deliberate divergences,
                    // kept visible here: a Close for a session being
                    // deleted must not re-advertise its source-NAT
                    // provenance (G40-03). The fabric flag override is
                    // struct-level only: `close_flags` also ORs
                    // `disposition == FabricRedirect`, so a
                    // FabricRedirect-disposition row still encodes
                    // FLAG_FABRIC_REDIRECT on the Close frame.
                    // Counters stay as `from_shared` carries them:
                    // this path uses push_delta_lossless (NOT
                    // emit_session_close_rt_flow), so the counts are
                    // never rendered as RT_FLOW volume (#2501).
                    cand.delta = Some(crate::session::SessionDelta {
                        source_nat_static: None,
                        fabric_redirect_sync: false,
                        ..crate::session::SessionDelta::from_shared(
                            entry,
                            crate::session::SessionDeltaKind::Close,
                        )
                    });
                }
            }
        }
        // #17144: only Applied | PartialCompanion removed the shared entry.
        // Every other outcome is a refusal: keep the session, emit no Close,
        // release no reservation and do not count it as purged. It will be
        // retried by the next purge or reaped by GC.
        let mut deltas: Vec<crate::session::SessionDelta> = Vec::new();
        let mut reservations: Vec<(crate::session::SessionKey, crate::nat::NatDecision)> =
            Vec::new();
        let mut purged = 0usize;
        let mut refused = 0usize;
        for cand in candidates {
            let outcome = self
                .session_domain
                .delete_synced_session(cand.key.clone(), false);
            if matches!(
                outcome,
                crate::afxdp::SyncedDeleteOutcome::Applied
                    | crate::afxdp::SyncedDeleteOutcome::PartialCompanion
            ) {
                purged += 1;
                if let Some(delta) = cand.delta {
                    deltas.push(delta);
                }
                if let Some(nat) = cand.reservation {
                    reservations.push((cand.key, nat));
                }
            } else {
                refused += 1;
            }
        }
        if refused > 0 {
            self.sessions
                .tunnel_purge_delete_refused
                .fetch_add(refused as u64, std::sync::atomic::Ordering::Relaxed);
        }
        // #8138: release the coordinator's import-time reservation.
        //
        // `reserve_synced_translation` takes it as `NatHolder::Untracked`
        // (`ha/session_import.rs`), which contributes no holder bit — so the
        // teardown sweeps, which CLEAR bits, free nothing against it, and
        // `delete_synced_session` frees it only on the #6979 F4 dropped-command
        // route with a worker id. A session purged here before any worker
        // adopted the reservation therefore strands a `(pool_addr, port)` for
        // the life of the allocator. Measured before this change:
        // `purged = 1`, `occupied_after_purge = true`.
        //
        // `NatHolder::Untracked` is the CORRECT holder and cannot over-release.
        // `drop_holder_locked` returns early — keeping the record — whenever any
        // holder bit remains, and `Untracked.bit()` is 0, so a reservation a
        // worker HAS adopted is left for that worker's own teardown to free.
        // Only a record with `holders == 0` (one no worker ever claimed) is
        // freed here. That is the direction the allocator documents as
        // deliberate: an under-release leaks a bounded, observable pool port,
        // an over-release hands a live worker's port to a new flow.
        let now_ns = crate::afxdp::wg::counters::monotonic_now_ns();
        for (key, nat) in &reservations {
            // #14961 (D26-05): release BOTH allocator families. Before this
            // fix only the source-NAT leg ran, so a purged NAT64 session
            // stranded its translated `(pool v4, port)` for the life of the
            // NAT64 allocator. Each helper is self-gated (SNAT on
            // `rewrite_src`, NAT64 on `nat.nat64`), so a session in only
            // one family no-ops in the other. The counter increments once
            // per reservation actually freed in EITHER family — never per
            // attempt (#8124 honesty rule).
            let snat_freed = crate::nat::release_synced_source_nat_allocation_untracked(
                &release_against.iface_nat_allocators,
                &release_against.source_nat_rules,
                key,
                *nat,
                false,
                now_ns,
            );
            let nat64_freed = crate::nat64::release_synced_nat64_allocation_untracked_for_purge(
                &release_against.nat64,
                key,
                *nat,
                false,
                now_ns,
            );
            if snat_freed || nat64_freed {
                // Counted only on an ACTUAL free. #8124's removed repair
                // incremented unconditionally, which reported a repair that did
                // not happen — the specific dishonesty this counter must not
                // reproduce.
                self.sessions
                    .tunnel_purge_reservations_released
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if let Some(es) = self.event_stream.as_ref() {
            let handle = es.worker_handle();
            // #2880: push the close deltas through the LOSSLESS producer and
            // RECORD any that cannot be queued (event stream disconnected /
            // saturated) instead of silently swallowing the error with the old
            // `let _ =`. This is error HYGIENE, not a leak fix: the purge is
            // CLEANUP, not a correctness boundary. Re-resolution and the encap
            // builders refuse a tunnel id whose owning netdev ifindex differs
            // from the one stored in the session's resolution (see the
            // call-site comments in coordinator/snapshot_refresh.rs and
            // coordinator/reconcile/snapshot.rs), so a surviving stale entry
            // can never mis-encapsulate; it self-heals — the standby runs its
            // OWN snapshot-apply purge and idle GC reaps it. A full owner-RG
            // re-export would NOT recover an undelivered close anyway: the
            // userspace cold-sync ships sessions as incremental Opens with
            // EMPTY bulk markers, and the peer's reconcileStaleSessions
            // short-circuits on an empty bulk (pkg/cluster/sync_bulk.go,
            // pkg/cluster/sync.go) — re-emitting Opens cannot convey a delete.
            // A disconnected stream additionally triggers a fresh resync on
            // reconnect (#2874) independently. So the honest minimal fix is to
            // surface the drop in the event-stream drop metric + a one-shot
            // log, not to drive a heavy resync.
            let _dropped = self.push_purge_close_deltas(&handle, &deltas);
        }
        if purged > 0 {
            eprintln!(
                "xpf-userspace-dp: purged {} session(s) on tunnel-endpoint id remap (ids {:?}) (#1873)",
                purged,
                purge_ids
            );
        }
        if refused > 0 {
            eprintln!(
                "xpf-userspace-dp: tunnel purge refused {} session delete(s) on id remap (ids {:?}); sessions retained for next purge (#17144)",
                refused,
                purge_ids
            );
        }
        purged
    }

    /// #2880: push the tunnel-remap purge Close deltas through the LOSSLESS
    /// event-stream producer, returning the number that could NOT be queued.
    /// Each undelivered delta is recorded in the event-stream dropped-frames
    /// metric (`record_dropped_frames`) so a disconnected / saturated stream
    /// surfaces in observability instead of being silently swallowed by the
    /// old `let _ =`. Stops on the first failure — a disconnected stream fails
    /// every subsequent push immediately, and a saturated one would otherwise
    /// burn one lossless-queue timeout per remaining delta — and counts the
    /// undelivered remainder. Cleanup-only error hygiene: it does NOT trigger a
    /// resync (the caller comment explains why a re-export cannot recover a
    /// missed close, and why the surviving entry is harmless + self-healing).
    pub(crate) fn push_purge_close_deltas(
        &self,
        handle: &crate::event_stream::EventStreamWorkerHandle,
        deltas: &[crate::session::SessionDelta],
    ) -> usize {
        let zone_name_to_id = &self.forwarding.zone_name_to_id;
        // #17122 fold: test-only capture of the exact deltas this seam
        // receives (compiled out of production builds).
        #[cfg(test)]
        PURGE_CLOSE_DELTAS_FOR_TEST.with(|slot| {
            if let Some(captured) = slot.borrow_mut().as_mut() {
                captured.extend(deltas.iter().cloned());
            }
        });
        for (delivered, delta) in deltas.iter().enumerate() {
            if let Err(err) = handle.push_delta_lossless(delta, zone_name_to_id) {
                let dropped = deltas.len() - delivered;
                handle.record_dropped_frames(dropped as u64);
                eprintln!(
                    "xpf-userspace-dp: tunnel-remap purge could not queue {dropped}/{} close delta(s) losslessly ({err}); recorded as dropped frames — surviving peer/Go-shadow entries are harmless (encap ifindex guard) and self-heal via the standby snapshot-apply purge + idle GC (#2880)",
                    deltas.len()
                );
                return dropped;
            }
        }
        0
    }
}

#[cfg(test)]
thread_local! {
    /// #17122 fold: thread-local capture of the Close deltas handed to
    /// `push_purge_close_deltas`. Thread-local so concurrent tests stay
    /// isolated; compiled out of production builds entirely.
    static PURGE_CLOSE_DELTAS_FOR_TEST: std::cell::RefCell<
        Option<Vec<crate::session::SessionDelta>>,
    > = const { std::cell::RefCell::new(None) };
}

/// #17122 fold: guard returned by
/// [`PurgeCloseDeltaCaptureForTest::start`]; dropping it disarms the
/// capture even on panic, so a failed cell cannot leak armed state
/// into a later test on the same thread.
#[cfg(test)]
pub(crate) struct PurgeCloseDeltaCaptureForTest;

#[cfg(test)]
impl PurgeCloseDeltaCaptureForTest {
    pub(crate) fn start() -> Self {
        PURGE_CLOSE_DELTAS_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        Self
    }

    pub(crate) fn take(self) -> Vec<crate::session::SessionDelta> {
        PURGE_CLOSE_DELTAS_FOR_TEST.with(|slot| slot.borrow_mut().take().unwrap_or_default())
    }
}

#[cfg(test)]
impl Drop for PurgeCloseDeltaCaptureForTest {
    fn drop(&mut self) {
        PURGE_CLOSE_DELTAS_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
    }
}
