use crate::afxdp::coordinator::SessionManager;
use crate::afxdp::*;

impl crate::afxdp::Coordinator {
    /// Phase 1 of the owner-RG session export (#2962): enqueue the export
    /// command to every worker and capture the lock-free handles the
    /// collect needs, then RETURN immediately. The blocking
    /// drain-while-polling collection runs in
    /// [`OwnerRgExportWait::wait_and_collect`] AFTER the caller releases
    /// the global `ServerState` mutex, so a slow/stalled worker can no
    /// longer freeze the whole control plane (status poll, session
    /// installs, snapshot/FIB bumps, HA state updates) for up to 15 s.
    ///
    /// This method MUST be called under the `ServerState` lock: it reads
    /// `workers.records`, bumps `export_seq`, and mutates the open-window
    /// guard. Those are only mutated by other control-socket handlers, which
    /// all hold the same lock, so snapshotting the per-worker ack atomics
    /// (`Arc<AtomicU64>`) and the per-worker export buffers here is
    /// equivalent to re-reading them live: the worker SET cannot change
    /// while the export waits lock-free (no TOCTOU). The worker THREADS
    /// only bump their ack atomics and push into their export buffers —
    /// both `Arc`-shared and lock-free — so the wait observes their
    /// progress without the global lock.
    /// #9344: `continuation` requests the REMAINDER of a window an earlier
    /// capped call already produced. It kicks nothing, consumes no export
    /// sequence and captures no ack atomics; it binds to THE open window
    /// (global-single-export) and collection starts draining immediately —
    /// every page of one window therefore comes from the single phase 1
    /// that opened it. Re-kicking instead would produce a second full set
    /// on top of the remainder and the caller would assemble a window out
    /// of two different instants.
    /// #9856: fallible — a fresh kick while a non-idle window is open gets
    /// BUSY (no sequence consumed); a continuation with no open window gets
    /// a re-kick error. Both fail the FullResync un-ACKed for retry.
    /// Legacy/internal entry point retained for direct Rust callers. The
    /// control-socket handler uses `kick_owner_rg_export_v2`, which validates
    /// the request marker and opaque continuation token before reaching this
    /// implementation.
    pub fn kick_owner_rg_export(
        &self,
        owner_rgs: &[i32],
        max: usize,
        continuation: bool,
    ) -> Result<OwnerRgExportWait, String> {
        self.kick_owner_rg_export_inner(owner_rgs, max, continuation, None)
    }

    /// #9856: v2 control-socket entry point. Every request carries the
    /// protocol marker; continuations additionally carry the helper
    /// incarnation and sequence from the preceding page.
    pub fn kick_owner_rg_export_v2(
        &self,
        owner_rgs: &[i32],
        max: usize,
        continuation: bool,
        protocol_version: i32,
        continuation_incarnation: u64,
        continuation_sequence: u64,
    ) -> Result<OwnerRgExportWait, String> {
        if protocol_version != crate::protocol::SESSION_EXPORT_PAGING_PROTOCOL_VERSION {
            return Err(format!(
                "owner-RG export protocol version {protocol_version} is unsupported; want {}",
                crate::protocol::SESSION_EXPORT_PAGING_PROTOCOL_VERSION
            ));
        }
        let token = if continuation {
            if continuation_incarnation == 0 || continuation_sequence == 0 {
                return Err(
                    "owner-RG export continuation requires nonzero incarnation and sequence"
                        .to_string(),
                );
            }
            Some((continuation_incarnation, continuation_sequence))
        } else {
            if continuation_incarnation != 0 || continuation_sequence != 0 {
                return Err(
                    "owner-RG export page 1 must not carry a continuation token".to_string(),
                );
            }
            None
        };
        self.kick_owner_rg_export_inner(owner_rgs, max, continuation, token)
    }

    fn kick_owner_rg_export_inner(
        &self,
        owner_rgs: &[i32],
        max: usize,
        continuation: bool,
        expected_token: Option<(u64, u64)>,
    ) -> Result<OwnerRgExportWait, String> {
        // Per-worker export buffers (same Arcs the workers produce into).
        // Worker-keyed, not binding-keyed: binding-less workers still
        // export (W-F10).
        let now_ns = crate::afxdp::neighbor::monotonic_nanos();
        if continuation {
            // Bind to THE open window: adopt its sequence + token + buffers +
            // acks atomically. No open window (expired/abandoned) fails:
            // resuming blind would mix instants.
            let Some((
                sequence,
                incarnation,
                export_buffers,
                ack_atomics,
                dropped_at_begin,
                shed,
            )) = self.sessions.open_export_adopt(now_ns)
            else {
                return Err("owner-RG export continuation with no open window \
                    (expired or never kicked); re-kick fresh"
                    .to_string());
            };
            if let Some((expected_incarnation, expected_sequence)) = expected_token {
                if incarnation != expected_incarnation || sequence != expected_sequence {
                    return Err(format!(
                        "owner-RG export continuation token mismatch: got ({expected_incarnation},{expected_sequence}), current ({incarnation},{sequence})"
                    ));
                }
            }
            return Ok(OwnerRgExportWait {
                sequence,
                incarnation,
                max,
                skip: false,
                shed,
                dropped_at_begin,
                ack_atomics,
                export_buffers,
                sessions: self.sessions.clone(),
            });
        }
        if owner_rgs.is_empty() {
            // Preserve the pre-split early return: no export is kicked and
            // no sequence is consumed, and the wait drains nothing.
            return Ok(OwnerRgExportWait {
                sequence: 0,
                incarnation: self.sessions.export_incarnation(),
                max,
                skip: true,
                shed: 0,
                dropped_at_begin: Vec::new(),
                ack_atomics: Vec::new(),
                export_buffers: Vec::new(),
                sessions: self.sessions.clone(),
            });
        }
        // #9856: global-single-export. A second fresh kick while a non-idle
        // window is open gets BUSY (the Go FullResync fails un-ACKed and
        // retries on the #9767 backoff) instead of stacking a second window
        // whose pages would interleave.
        if let Some(open_seq) = self.sessions.open_export_busy(now_ns) {
            return Err(format!(
                "owner-RG export busy (window {open_seq} open); retry with backoff"
            ));
        }
        let sequence = self
            .sessions
            .export_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut ack_atomics = Vec::with_capacity(self.workers.records().len());
        let mut export_buffers = Vec::with_capacity(self.workers.records().len());
        let mut shed = 0u32;
        for rec in self.workers.records().values() {
            if rec.shed_if_dead(1) {
                shed += 1;
                continue;
            }
            let handle = &rec.handle;
            let mut pending = worker_queue::lock_recover(&handle.commands);
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::ExportOwnerRGSessions {
                    sequence,
                    owner_rgs: owner_rgs.to_vec(),
                },
            );
            drop(pending);
            ack_atomics.push(handle.session_export_ack.clone());
            export_buffers.push(rec.export_buffer.clone());
        }
        let incarnation = self.sessions.export_incarnation();
        let dropped_at_begin = export_buffers.iter().map(|b| b.export_dropped()).collect();
        self.sessions
            .open_export_begin(sequence, now_ns, &export_buffers, &ack_atomics, shed);
        Ok(OwnerRgExportWait {
            sequence,
            incarnation,
            max,
            skip: false,
            shed,
            dropped_at_begin,
            ack_atomics,
            export_buffers,
            sessions: self.sessions.clone(),
        })
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
                provenance: crate::session::ExportProvenance::Incremental,
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
                purge_retirement: false,
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
    /// #9856: per-process helper incarnation echoed on every page.
    incarnation: u64,
    max: usize,
    /// `true` when no export was kicked (empty owner-RG set):
    /// `wait_and_collect` returns an empty delta set without touching any
    /// buffer, byte-identical to the pre-split early return.
    skip: bool,
    /// Per-worker `session_export_ack` atomics captured at kick time. The
    /// worker SET is stable for the lock-free wait window (every mutator
    /// holds the `ServerState` lock), so this snapshot is equivalent to
    /// re-reading `workers.records` live. Continuations adopt (never
    /// re-snapshot): a reconcile between pages must not drop torn-down
    /// workers' buffers or add a new worker into this window.
    ack_atomics: Vec<Arc<AtomicU64>>,
    /// #9900 F-093 (GPT-3): workers shed as dead at kick time. Their
    /// sessions are missing from the drain, so a nonzero count fails
    /// `wait_and_collect` — promptly, without the 15 s ack wait — instead
    /// of returning an export the Go receiver would publish as complete.
    shed: u32,
    /// #9856: cumulative tombstone-drop baselines captured when this
    /// window opened. The collector compares the live counters against
    /// these values so a drop in this window cannot be hidden by an
    /// earlier window's metric value.
    dropped_at_begin: Vec<u64>,
    /// Per-worker export buffers captured at kick time; drained
    /// incrementally while workers produce (worker-keyed, W-F10).
    export_buffers: Vec<Arc<crate::afxdp::binding_state::ExportBufferState>>,
    /// Session state for the open-window guard: the wait refreshes activity
    /// per page and clears-if-ours on terminal pages and error paths.
    sessions: Arc<SessionManager>,
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
    /// Phase 2 of the owner-RG export (#2962): drain worker export buffers
    /// while polling completion, and return one page. Runs WITHOUT the global
    /// `ServerState` lock, so concurrent control RPCs (status poll, session
    /// installs, snapshot/FIB bumps, HA state updates) stay responsive while
    /// one export drains. Preserves the original 15 s deadline and timeout
    /// error (now PER COLLECT CALL: a minutes-long export spans many
    /// fast-returning pages, so only a stalled worker trips it).
    /// Returns the drained deltas and, as the second element, whether MORE
    /// pages remain: true when `max` capped this page, false at the terminal
    /// page (every worker acked AND a re-drain found nothing new).
    pub fn wait_and_collect(&self) -> Result<(Vec<SessionDeltaInfo>, bool), String> {
        if self.skip {
            return Ok((Vec::new(), false));
        }
        // #9900 F-093 (GPT-3): shed workers' sessions are missing from the
        // drain. Fail promptly — without the 15 s wait — instead of
        // returning a window the Go receiver would publish as complete
        // (missing sessions read as deletions there). Same outcome class as
        // the pre-shed ack timeout (no publish), minus the stall.
        if self.shed > 0 {
            self.clear_window_if_ours();
            return Err(format!(
                "owner-RG export incomplete: {} dead worker(s) shed at kick; refusing rather than publishing a partial window",
                self.shed
            ));
        }
        // #9856: drain WHILE polling completion. Ack-first would deadlock:
        // a worker paused on a full 8192-entry buffer while control waits
        // for its ack. Terminal = every worker acked AND a re-drain found
        // nothing new (the re-drain closes the drain-then-load race: an
        // entry pushed between our drain and our ack load is visible then).
        let deadline = std::time::Instant::now() + OWNER_RG_EXPORT_ACK_WAIT;
        let target = if self.max == 0 {
            usize::MAX
        } else {
            self.max.max(1)
        };
        let mut out = Vec::new();
        let mut cursor = 0usize;
        loop {
            if out.len() >= target {
                if self.export_dropped_in_window() {
                    self.clear_window_if_ours();
                    return Err(format!(
                        "owner-RG export incomplete: tombstone dropped for seq={}",
                        self.sequence
                    ));
                }
                self.refresh_window();
                return Ok((out, true));
            }
            let (round, next_cursor) = drain_export_deltas_from_workers(
                &self.export_buffers,
                self.sequence,
                target.saturating_sub(out.len()).min(1024),
                cursor,
            );
            cursor = next_cursor;
            let round_n = round.len();
            out.extend(round);
            let done = self
                .ack_atomics
                .iter()
                .all(|ack| ack.load(Ordering::Acquire) >= self.sequence);
            if self.export_dropped_in_window() {
                self.clear_window_if_ours();
                return Err(format!(
                    "owner-RG export incomplete: tombstone dropped for seq={}",
                    self.sequence
                ));
            }
            // Terminal (checked BEFORE the cap verdict so exact-fit pages
            // report `more=false`): every worker acked AND no entry tagged
            // for this window remains buffered. The probe runs after the
            // ack load: worker push-then-ack (Release) ordering plus mutex
            // ordering guarantees an entry pushed before its ack is visible
            // here, so done + no-pending is airtight (no drain race, no
            // over-drain past `max`).
            if done
                && !self
                    .export_buffers
                    .iter()
                    .any(|b| b.has_pending_export_for(self.sequence))
            {
                self.clear_window_if_ours();
                return Ok((out, false));
            }
            if out.len() >= target {
                self.refresh_window();
                return Ok((out, true));
            }
            if std::time::Instant::now() >= deadline {
                self.clear_window_if_ours();
                return Err(format!(
                    "timed out waiting for session export ack seq={}",
                    self.sequence
                ));
            }
            if round_n == 0 {
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    /// True when a tombstone was refused by a full dedicated buffer after
    /// this window opened. The baseline is per worker because the buffer
    /// counters are intentionally cumulative telemetry.
    fn export_dropped_in_window(&self) -> bool {
        self.export_buffers
            .iter()
            .zip(self.dropped_at_begin.iter())
            .any(|(buffer, baseline)| buffer.export_dropped() > *baseline)
    }
    pub(crate) fn token(&self) -> (u64, u64) {
        (self.incarnation, self.sequence)
    }

    pub(crate) fn dropped_count(&self) -> u64 {
        self.export_buffers
            .iter()
            .zip(self.dropped_at_begin.iter())
            .map(|(buffer, baseline)| buffer.export_dropped().saturating_sub(*baseline))
            .sum()
    }

    /// Refresh the open-window activity stamp (called per page). Proves this
    /// window is being collected, so the idle-expiry can never fire under a
    /// healthy paged export no matter how many pages it spans.
    fn refresh_window(&self) {
        self.sessions
            .open_export_refresh_if(self.sequence, crate::afxdp::neighbor::monotonic_nanos());
    }

    /// Clear the open window iff it is still ours (terminal pages and error
    /// paths). Single-waiter-per-window + kick-under-lock: the sequence
    /// match means this can never clear a newer window.
    fn clear_window_if_ours(&self) {
        self.sessions.open_export_clear_if(self.sequence);
    }
}

/// #9856: fair rotating-cursor drain over per-worker export buffers.
/// Same shape as the retired `drain_session_deltas_from_live` (per-buffer
/// quanta, persistent cursor), but token-filtered at the source: each
/// buffer skips its stale (foreign-token) prefix without charging the
/// quantum, so a superseded window's leftovers can neither starve the
/// current window's page nor fake an empty round. Returns (collected,
/// next-cursor); the caller decides `more`.
pub(crate) fn drain_export_deltas_from_workers(
    buffers: &[Arc<crate::afxdp::binding_state::ExportBufferState>],
    token: u64,
    max: usize,
    start_cursor: usize,
) -> (Vec<SessionDeltaInfo>, usize) {
    let mut out = Vec::new();
    let n = buffers.len();
    if n == 0 || max == 0 {
        return (out, start_cursor);
    }
    let quantum = max.div_ceil(n).max(1);
    let mut cursor = if start_cursor >= n { 0 } else { start_cursor };
    for _ in 0..n {
        let remaining = max.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        out.extend(buffers[cursor].drain_export_skipping_foreign(token, quantum.min(remaining)));
        cursor = (cursor + 1) % n;
    }
    (out, cursor)
}
