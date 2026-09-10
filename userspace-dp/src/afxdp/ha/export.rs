use crate::afxdp::*;

impl crate::afxdp::Coordinator {
    /// Phase 1 of the owner-RG session export (#2962): enqueue the export
    /// command to every worker and capture the lock-free handles the
    /// ack-wait needs, then RETURN immediately. The blocking ack-wait runs
    /// in [`OwnerRgExportWait::wait_and_collect`] AFTER the caller releases
    /// the global `ServerState` mutex, so a slow/stalled worker can no
    /// longer freeze the whole control plane (status poll, session
    /// installs, snapshot/FIB bumps, HA state updates) for up to 15 s.
    ///
    /// This method MUST be called under the `ServerState` lock: it reads
    /// `workers.records` / `workers.live` and bumps `export_seq`. Those
    /// collections are only mutated by other control-socket handlers, which
    /// all hold the same lock, so snapshotting the per-worker ack atomics
    /// (`Arc<AtomicU64>`) and the per-binding delta buffers
    /// (`Arc<BindingLiveState>`) here is equivalent to re-reading them live:
    /// the worker SET cannot change while the export waits lock-free
    /// (no TOCTOU). The worker THREADS only bump their ack atomics and push
    /// into their delta buffers — both `Arc`-shared and lock-free — so the
    /// wait observes their progress without the global lock.
    /// #9344: `continuation` requests the REMAINDER of a window an earlier
    /// capped call already produced. It kicks nothing, consumes no export
    /// sequence and captures no ack atomics, so `wait_and_collect` goes
    /// straight to the drain — every page of one window therefore comes from
    /// the single phase 1 that opened it. Re-kicking instead would produce a
    /// second full set on top of the remainder and the caller would assemble a
    /// window out of two different instants.
    pub fn kick_owner_rg_export(
        &self,
        owner_rgs: &[i32],
        max: usize,
        continuation: bool,
    ) -> OwnerRgExportWait {
        // Snapshot the per-binding delta buffers (same Arcs as
        // `drain_session_deltas` iterates) so the post-lock drain reads
        // exactly the buffers that existed at kick time.
        let live: Vec<Arc<BindingLiveState>> = self.workers.live.values().cloned().collect();
        if continuation {
            // Empty `ack_atomics` makes the wait's `.all()` trivially true, so
            // the drain runs immediately. `skip` stays false because there IS
            // something to drain — the remainder of the open window.
            return OwnerRgExportWait {
                sequence: 0,
                max,
                skip: false,
                ack_atomics: Vec::new(),
                live,
            };
        }
        if owner_rgs.is_empty() {
            // Preserve the pre-split early return: no export is kicked and
            // no sequence is consumed, and the wait drains nothing.
            return OwnerRgExportWait {
                sequence: 0,
                max,
                skip: true,
                ack_atomics: Vec::new(),
                live,
            };
        }
        let sequence = self
            .sessions
            .export_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut ack_atomics = Vec::with_capacity(self.workers.records().len());
        // #6242: enqueue the export command + collect the ack atomic via each
        // worker's runtime record.
        for rec in self.workers.records().values() {
            let handle = &rec.handle;
            // #1790/#1807: recover, don't early-return — one dead worker's
            // poisoned queue must not block session export for every
            // HEALTHY worker (the export-ack timeout handles dead workers
            // in the wait). Same policy as update_ha_state above.
            let mut pending = worker_queue::lock_recover(&handle.commands);
            // #6929: bounded. A dropped export request means this worker
            // never acks, which the export-ack timeout in the wait below
            // already handles — so the return is ignored here rather than
            // inventing a second failure channel for a case that has one.
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::ExportOwnerRGSessions {
                    sequence,
                    owner_rgs: owner_rgs.to_vec(),
                },
            );
            drop(pending);
            ack_atomics.push(handle.session_export_ack.clone());
        }
        OwnerRgExportWait {
            sequence,
            max,
            skip: false,
            ack_atomics,
            live,
        }
    }

    /// Snapshot all locally-owned forward sessions for a bulk HA export
    /// WITHOUT pushing them (#4054).
    ///
    /// Called on peer connect instead of the old BulkSync path. Iterates the
    /// shared session table once under a BRIEF `sessions.synced` lock, copies
    /// each qualifying session into an Open [`SessionDelta`], and captures the
    /// (Arc-cheap) event-stream handle plus an OWNED clone of the zone-name→id
    /// map. The returned [`AllSessionsExport`] carries everything the push loop
    /// needs, so the caller can run the potentially-blocking
    /// `push_delta_lossless` serialization with the global `ServerState` lock
    /// RELEASED — mirroring the owner-RG two-phase split (#2962). Before #4054
    /// the whole export (iteration + serialization + up to a 5 s per-delta
    /// lossless-queue backpressure wait) ran under the global lock, so a large
    /// bulk export at failover could starve the status poll / trip the control
    /// plane's liveness deadline and self-inflict a needless helper restart.
    ///
    /// The exported set is a consistent point-in-time snapshot: the delta
    /// vector is built under the `sessions.synced` lock, and the zone map is
    /// cloned within the same locked dispatcher phase, so a session or zone
    /// mutation racing the subsequent push is simply not reflected in THIS bulk
    /// export (it rides the incremental delta stream instead) — identical
    /// semantics to the pre-#4054 code, which likewise snapshotted the deltas
    /// under the same lock before serializing. Event-stream ordering is still
    /// governed by `producer_seq_lock` inside `push_delta_lossless`, not the
    /// `ServerState` lock, so releasing the latter does not affect the lossless
    /// seq contract (#2874 / #3878).
    pub fn snapshot_all_sessions_export(&self) -> Result<AllSessionsExport, String> {
        let es = self
            .event_stream
            .as_ref()
            .ok_or_else(|| "event stream not started".to_string())?;
        let handle = es.worker_handle();

        // Clone the zone map so the push loop can run off the global lock:
        // `push_delta_lossless` borrows it, and a borrow of `self.forwarding`
        // would otherwise pin coordinator state across the (blocking) push.
        let zone_name_to_id = self.forwarding.zone_name_to_id.clone();

        // #6654: RECOVERING lock. This returned "shared sessions lock
        // poisoned", so whether bulk export was REFUSED depended purely on
        // which thread reached the mutex first: every other shared-session
        // path (publish, lookup, remove, prewarm) CLEARS the poison, so the
        // window closes the instant any of them runs. A guard that fires on
        // thread interleaving is not a guard. End-to-end loss was bounded --
        // pkg/daemon/daemon_ha_sync.go falls back to the authoritative
        // BulkSync -- so the defect was the nondeterministic refusal itself.
        let sessions = lock_shared_recover(&self.sessions.synced);

        let ha_state = self.ha.rg_runtime.load();
        let mut deltas = Vec::new();
        for entry in sessions.values() {
            // Only forward (non-reverse), locally-originated sessions.
            if entry.metadata.is_reverse {
                continue;
            }
            if entry.origin.is_peer_synced() {
                continue;
            }
            // Skip fabric-ingress sessions (same exclusion as export_forward_sessions_for_owner_rgs).
            if entry.metadata.fabric_ingress {
                continue;
            }
            // Only export for active RGs. Missing HA state entry = inactive.
            let rg_active = entry.metadata.owner_rg_id > 0
                && ha_state
                    .get(&entry.metadata.owner_rg_id)
                    .map(|r| r.active)
                    .unwrap_or(false);
            if !rg_active && entry.metadata.owner_rg_id > 0 {
                continue;
            }
            // Only exportable dispositions.
            if !matches!(
                entry.decision.resolution.disposition,
                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
            ) {
                continue;
            }

            deltas.push(crate::session::SessionDelta {
                kind: crate::session::SessionDeltaKind::Open,
                key: entry.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
                origin: entry.origin,
                fabric_redirect_sync: true,
                // #2465: Open delta from the HA bulk export — the synced entry
                // carries no creation instant. The SESSION_CREATE frame reports
                // no duration, so 0/unknown is correct here.
                created_ns: 0,
                last_seen_ns: 0,
                // #2501: HA bulk-export Open delta; no volume yet (and the
                // synced entry carries no per-direction counters).
                counters: crate::session::SessionCounters::default(),
                // #2749: HA bulk-export Open delta; no observed ToS / TCP
                // flags (and not routed through the RT_FLOW close exporter).
                observed_tos: 0,
                observed_tcp_flags: 0,
                // #4915: HA bulk-export Open delta — feeds the session-sync
                // dispatcher, NOT the RT_FLOW exporter, and the SyncedSessionEntry
                // carries no session id. 0 (unknown).
                session_id: 0,
                bulk_resync: false,
                // #9412: carry the synced entry's close class on the bulk export.
                tcp_close_class: entry.tcp_close_class,
            });
        }
        drop(sessions);

        Ok(AllSessionsExport {
            handle,
            zone_name_to_id,
            deltas,
        })
    }
}

/// A prepared bulk session export captured by
/// [`Coordinator::snapshot_all_sessions_export`] under the global
/// `ServerState` lock, so the (potentially blocking) lossless push loop can
/// run with that lock RELEASED (#4054). Mirrors [`OwnerRgExportWait`]'s
/// off-lock design (#2962): everything the push needs — the Arc-cheap
/// event-stream worker handle, an OWNED zone-name→id map, and the point-in-time
/// session-delta snapshot — is captured by value, so no coordinator borrow is
/// held across `push`.
pub struct AllSessionsExport {
    handle: crate::event_stream::EventStreamWorkerHandle,
    zone_name_to_id: FxHashMap<String, u16>,
    deltas: Vec<crate::session::SessionDelta>,
}

impl AllSessionsExport {
    /// Push the snapshotted Open deltas through the lossless event-stream
    /// producer. Runs WITHOUT the global `ServerState` lock (#4054), so a large
    /// or backpressured bulk export (each `push_delta_lossless` retries up to
    /// the 5 s lossless-queue timeout) can no longer freeze status polls,
    /// session installs, or HA state updates on that lock. Returns the number
    /// of sessions pushed on success.
    pub fn push(self) -> Result<usize, String> {
        let count = self.deltas.len();
        for delta in &self.deltas {
            self.handle
                .push_delta_lossless(delta, &self.zone_name_to_id)?;
        }
        eprintln!("xpf-ha: exported {count} sessions to event stream for bulk sync");
        Ok(count)
    }
}

/// Lock-free handle returned by [`Coordinator::kick_owner_rg_export`] so
/// the control-socket dispatcher can release the global `ServerState`
/// mutex BEFORE blocking on the per-worker export ack-wait (#2962).
///
/// At construction the export command has already been enqueued to every
/// worker; the only state the wait still needs is the per-worker ack
/// atomics (`ack_atomics`) and the per-binding delta buffers (`live`),
/// all `Arc`-shared and advanced by the worker threads without the global
/// lock. Holding these `Arc` clones lets the wait + drain run entirely
/// off the `ServerState` lock.
pub struct OwnerRgExportWait {
    sequence: u64,
    max: usize,
    /// `true` when no export was kicked (empty owner-RG set):
    /// `wait_and_collect` returns an empty delta set without touching the
    /// per-binding buffers, byte-identical to the pre-split early return.
    skip: bool,
    /// Per-worker `session_export_ack` atomics captured at kick time. The
    /// worker SET is stable for the lock-free wait window (every mutator
    /// holds the `ServerState` lock), so this snapshot is equivalent to
    /// re-reading `workers.records` live.
    ack_atomics: Vec<Arc<AtomicU64>>,
    /// Per-binding delta buffers (`workers.live` values) captured at kick
    /// time; drained after all workers ack.
    live: Vec<Arc<BindingLiveState>>,
}

/// How long phase 2 of the owner-RG export waits for every worker to ack the
/// export sequence before giving up (#2962).
///
/// #9344 NAMED this (it was a bare `Duration::from_secs(15)`) because the Go
/// caller has to size its control-socket round-trip deadline against it, and
/// `controlRoundtripDeadline` sizes off the REQUEST BODY — which for this verb
/// is ~60 bytes, so the verb got the 3 s small-request base while the helper
/// could legitimately spend 15 s here before writing its first byte. That is
/// #4036's failure shape ("Go timed out and reported failure while the helper
/// was doing the work") moved from the request-size axis to the WORK axis.
/// `pkg/dataplane/userspace` reads this constant out of this file rather than
/// restating the number, so the two cannot drift.
pub(crate) const OWNER_RG_EXPORT_ACK_WAIT: Duration = Duration::from_secs(15);

impl OwnerRgExportWait {
    /// Phase 2 of the owner-RG export (#2962): block up to 15 s for every
    /// worker to ack the export sequence, then drain the produced session
    /// deltas. Runs WITHOUT the global `ServerState` lock, so concurrent
    /// control RPCs (status poll, session installs, snapshot/FIB bumps, HA
    /// state updates) stay responsive while one export drains. Preserves
    /// the original 15 s deadline and timeout error.
    /// Returns the drained deltas and, as the second element, whether the
    /// per-binding buffers STILL hold deltas from this window because `max`
    /// capped the drain (#9344). That bit is not newly computed here —
    /// `drain_session_deltas_fair` has always returned it and the owner-RG call
    /// site discarded it into `_overflow`.
    pub fn wait_and_collect(self) -> Result<(Vec<SessionDeltaInfo>, bool), String> {
        if self.skip {
            return Ok((Vec::new(), false));
        }
        let deadline = std::time::Instant::now() + OWNER_RG_EXPORT_ACK_WAIT;
        loop {
            if self
                .ack_atomics
                .iter()
                .all(|ack| ack.load(Ordering::Acquire) >= self.sequence)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for session export ack seq={}",
                    self.sequence
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let mut out = Vec::new();
        let mut remaining = if self.max == 0 { usize::MAX } else { self.max.max(1) };
        // #5290: thread the fair-drain cursor across the batched export so a
        // low-slot binding cannot hog every 1024-batch and starve higher-slot
        // bindings within one capped export.
        let mut cursor = 0usize;
        // #9344: only the LAST batch's verdict is the answer. An intermediate
        // 1024-batch reports overflow whenever anything is still buffered,
        // which is true on every batch of a large drain and says nothing about
        // the state after the loop finishes.
        let mut more = false;
        while remaining > 0 {
            let batch_size = remaining.min(1024);
            let (drained, next_cursor, overflow) =
                drain_session_deltas_from_live(&self.live, batch_size, cursor);
            cursor = next_cursor;
            if drained.is_empty() {
                // A full fair pass drained nothing, so every buffer is empty
                // and nothing was left behind — regardless of what the last
                // capped batch reported.
                more = false;
                break;
            }
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
            more = overflow;
        }
        Ok((out, more))
    }
}

/// Drain up to `max` session deltas across the captured per-binding buffers,
/// starting the fair round-robin at `start_cursor` and returning the cursor to
/// resume from. Mirrors `Coordinator::drain_session_deltas`'s fair rotating
/// drain (#5290), but over an owned snapshot of the `Arc<BindingLiveState>`
/// values so it needs no `&Coordinator` (and therefore no `ServerState` lock).
///
/// Unlike the steady-state fallback drain, this bulk owner-RG export path does
/// NOT arm the overflow loss-of-sync latch: this export IS the resync/snapshot
/// mechanism, and its completeness is governed by the caller-supplied `max`
/// (the outer `wait_and_collect` loop drains to empty when `max == 0`). Arming
/// a worker resync from inside a resync export would be circular.
///
/// #9344: the third element is `drain_session_deltas_fair`'s overflow bit —
/// "the budget capped this drain AND a binding still holds deltas". It used to
/// be discarded here into `_overflow`, which is the whole reason the owner-RG
/// export had no terminating bound: without it the caller cannot tell a
/// complete capped answer from a truncated one, so the only safe request was
/// `max = 0`, and `max = 0` is what crosses the 64 MiB response cap.
pub(crate) fn drain_session_deltas_from_live(
    live: &[Arc<BindingLiveState>],
    max: usize,
    start_cursor: usize,
) -> (Vec<SessionDeltaInfo>, usize, bool) {
    let bindings: Vec<&BindingLiveState> = live.iter().map(|b| b.as_ref()).collect();
    crate::afxdp::session_delta::drain_session_deltas_fair(&bindings, max, start_cursor)
}
