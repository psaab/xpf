// #13075 (D4-12) — per-tick session housekeeping, extracted from
// `worker_loop` in loop_body/mod.rs (pure code motion).
//
// One call per worker tick: build the #2120 standby-retention HA context,
// expire stale sessions, forget expired PPTP control channels (#11053),
// count create-counted local expiries (#2428), retire missing-neighbor
// seeds (#10419), reap expired sessions, and drain/flush the resulting
// close deltas (including the #10309 overflow suffix) before any packet
// or control work runs. Returns `true` when the old in-loop `continue`
// sites fired (deferred cleanup): the caller skips the rest of the tick.
// #19026: that skip is bounded by `ClosePermitBarrier` — a close that cannot
// take its tuple permit holds RX for at most `CLOSE_PERMIT_BARRIER_NS`, then
// the tick polls RX while the close keeps retrying first on every tick.
//
// This is an ordinary out-of-line fn, NOT a hot-path call boundary in the
// #1776 sense: the per-tick packet path is `poll_binding`
// (worker/lifecycle.rs), which this fn never touches, and the expiry/GC
// work was never inlined into it. `#[inline(never)]` pins that separation
// so the expiry drain cannot be folded back into `worker_loop`'s frame.
// The flush itself stays in the loop: `flush_drained_session_deltas!` is
// a loop-local `macro_rules!` in mod.rs and is passed in as `flush_deltas`,
// so the #5468 lossless-wedge latch and #2874 delta-loss latch keep their
// exact loop semantics.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::*;

/// #19026: the longest one worker may withhold its RX poll while a requeued
/// Close waits for its tuple install permit. Before #19026 that barrier was
/// unbounded: `run_session_housekeeping` returned "skip the tick" on every
/// pass, the loop `continue`d before `poll_binding`, and because the
/// heartbeat is stored before housekeeping the worker stayed "healthy" while
/// it black-holed every flow it serves. (#19026's 111 s single-flow black-hole
/// on udp fits that shape — the outage began before any Close was logged —
/// but was not reproduced live; the starvation itself is pinned hermetically
/// in `housekeeping_rx_starvation_19026_tests.rs`.) 1 ms matches the idle path's own `INTERRUPT_POLL_TIMEOUT_MS` block: a
/// barrier this short keeps the #10419/#10512 teardown-before-poll ordering
/// for ordinary permit contention (permits are held for microseconds), while
/// a permit that does not come back can cost one tuple's ordering, never the
/// worker's RX.
pub(super) const CLOSE_PERMIT_BARRIER_NS: u64 = 1_000_000;

/// #19026: process-wide rate limit for the expired-barrier journal line (one
/// line per interval across ALL workers, the #1760 CAS-throttle pattern), so a
/// recurring permit stall cannot flood journald. Suppressed episodes are
/// counted and reported on the next emitted line.
const CLOSE_PERMIT_BARRIER_WARN_INTERVAL_NS: u64 = 10_000_000_000;
static CLOSE_PERMIT_BARRIER_WARN_LAST_NS: AtomicU64 = AtomicU64::new(0);
static CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

fn try_claim_close_permit_barrier_warn(now_ns: u64) -> bool {
    let last = CLOSE_PERMIT_BARRIER_WARN_LAST_NS.load(Ordering::Acquire);
    if last != 0 && now_ns.saturating_sub(last) < CLOSE_PERMIT_BARRIER_WARN_INTERVAL_NS {
        return false;
    }
    CLOSE_PERMIT_BARRIER_WARN_LAST_NS
        .compare_exchange(last, now_ns.max(1), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// #19026: per-worker state of the close-permit barrier (worker-loop local).
#[derive(Debug, Default)]
pub(super) struct ClosePermitBarrier {
    /// Loop time the current blocked episode began; 0 = no blocked close.
    since_ns: u64,
    /// The episode outlived `CLOSE_PERMIT_BARRIER_NS`; RX polls resumed.
    expired: bool,
    /// This episode's expiry line was emitted (so its end is logged too).
    logged: bool,
    /// Episodes that outlived the barrier (diagnostic).
    pub(super) expired_episodes: u64,
}

impl ClosePermitBarrier {
    /// A queued Close is waiting for its permit at `now_ns`. Returns whether
    /// this tick may still withhold RX (`true` = skip the rest of the tick).
    /// The Close itself stays queued and is retried before RX on every tick;
    /// only the RX hold is bounded.
    pub(super) fn hold_rx(
        &mut self,
        sessions: &crate::session::SessionTable,
        worker_id: u32,
        now_ns: u64,
    ) -> bool {
        if self.since_ns == 0 {
            self.since_ns = now_ns.max(1);
        }
        if now_ns.saturating_sub(self.since_ns) < CLOSE_PERMIT_BARRIER_NS {
            return true;
        }
        if !self.expired {
            self.expired = true;
            self.expired_episodes = self.expired_episodes.saturating_add(1);
            if try_claim_close_permit_barrier_warn(now_ns) {
                self.logged = true;
                log_close_permit_barrier_expired(
                    sessions,
                    worker_id,
                    now_ns.saturating_sub(self.since_ns),
                    CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED.swap(0, Ordering::Relaxed),
                );
            } else {
                CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        false
    }

    /// No queued Close is waiting: end the episode, if any.
    pub(super) fn clear(&mut self, worker_id: u32, now_ns: u64) {
        if self.since_ns == 0 {
            return;
        }
        if self.logged {
            eprintln!(
                "xpf-dp: w{worker_id}: #19026 blocked session close drained after {} ms",
                now_ns.saturating_sub(self.since_ns) / 1_000_000
            );
        }
        self.since_ns = 0;
        self.expired = false;
        self.logged = false;
    }
}

/// #19026: once per expired episode, rate-limited process-wide (cold): name
/// the blocked Close's tuple and the tuple gate's holder class, so a permit
/// that never returns has an owner in the journal instead of an anonymous
/// black-hole.
#[cold]
#[inline(never)]
fn log_close_permit_barrier_expired(
    sessions: &crate::session::SessionTable,
    worker_id: u32,
    held_ns: u64,
    suppressed: u64,
) {
    let Some(delta) = sessions.front_pending_delta() else {
        return;
    };
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    let [forward, reverse] = crate::afxdp::session_delta::close_install_keys(delta);
    let probe_forward = gate.probe(&forward);
    let probe_reverse = gate.probe(&reverse);
    eprintln!(
        "xpf-dp: w{worker_id}: #19026 session close waiting {} us for its tuple permit; \
         RX polling continues. close proto={} {}:{} -> {}:{} id={:#x} origin={} \
         gate fwd={:?} rev={:?} queued={} (other episodes since last line: {})",
        held_ns / 1_000,
        delta.key.protocol,
        delta.key.src_ip,
        delta.key.src_port,
        delta.key.dst_ip,
        delta.key.dst_port,
        delta.session_id,
        delta.origin.as_str(),
        probe_forward,
        probe_reverse,
        sessions.pending_delta_count(),
        suppressed,
    );
}

#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
#[inline(never)]
pub(super) fn run_session_housekeeping(
    mut sessions: &mut crate::session::SessionTable,
    mut bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
    loop_now_ns: u64,
    loop_now_secs: u64,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_id: u32,
    worker_command_queues: &crate::afxdp::types::WorkerCommandQueues,
    pptp_control: &crate::session::pptp_control::PptpControlInbox,
    worker_commands_by_id: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    shared_runtime: &RuntimeViewReader,
    worker_lossless_wedged: &mut bool,
    mut shared_recycles: &mut Vec<(u32, u64)>,
    deferred_expiry_overflow_deltas: &mut Vec<SessionDelta>,
    close_barrier: &mut ClosePermitBarrier,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    // #2120: build the standby retention context so the wheel HOLDS
    // peer-synced sessions this node does not forward (restoring the
    // dead Go-GC `IsLocalPrimary` contract), self-heals them on RG
    // promotion (edge via rg_epochs), and reaps them at a bounded
    // ceiling if a primary delete is lost. The HA-forwarding logic
    // stays here (HAGroupRuntime's lease predicate is afxdp-private);
    // the session wheel only sees the closures + node_active.
    let ha_map = ha_runtime;
    let rg_epochs_for_gate = &rg_epochs;
    // node_active: does this node forward at least one RG right now?
    // Excludes a standalone node (empty/all-inactive map) from ever
    // holding (mirrors session_glue's forwards-any pattern).
    let node_active = ha_map
        .values()
        .any(|group| group.is_forwarding_active(loop_now_secs));
    let forwards_rg = |rg: i32| -> bool {
        if rg > 0 {
            ha_map
                .get(&rg)
                .map(|group| group.is_forwarding_active(loop_now_secs))
                .unwrap_or(false)
        } else {
            // owner_rg_id <= 0 (fabric / unresolved-owner reverse):
            // "forwards here" == the node forwards anything.
            node_active
        }
    };
    let epoch_of = |rg: i32| -> u32 {
        // A valid per-RG index uses rg_epochs[rg]; everything else
        // (rg <= 0 or out of range) uses the node-level rg_epochs[0]
        // activation edge. As of #2466 the flow-cache consumer guard
        // (flow_cache::rg_epoch_index) applies the SAME fallback, so the
        // two gates agree: an out-of-range owner RG (>= MAX_RG_EPOCHS) and
        // owner_rg_id == 0 (fabric / unresolved-owner reverse) both
        // self-heal on the node-level rg_epochs[0] edge rather than never.
        rg_epochs_for_gate[crate::afxdp::flow_cache::rg_epoch_index(rg)].load(Ordering::Relaxed)
    };
    // #16223: node-level served evidence for the expiry retention arm:
    // the shared synced map's Established wire for the tuple (the
    // counter half is merged from this table's own serving stamps
    // inside the expire pass). #18663 keeps alias resolution keyed and
    // maintains its index with primary publish/remove.
    let shared_evidence_max_cadence_ns =
        crate::session::NODE_SERVED_EVIDENCE_DEFAULT_CADENCE_NS.max(
            super::slice_pacing::shared_evidence_max_cadence_ns(sessions.ct_refresh_slab_len()),
        );
    let node_served = |key: &crate::session::SessionKey| {
        let mut evidence =
            crate::afxdp::shared_ops::shared_node_served_evidence(
                shared_sessions,
                shared_owner_rg_indexes,
                key,
            );
        evidence.shared_evidence_max_cadence_ns = Some(shared_evidence_max_cadence_ns);
        evidence
    };
    // #19026: the restore close fence's keyed shared-row read.
    let shared_row = |key: &crate::session::SessionKey| {
        crate::afxdp::shared_ops::shared_row_identity(shared_sessions, key)
    };
    let ha_ctx = crate::session::ExpireHaContext {
        node_active,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
        shared_row: &shared_row,
    };
    let mut deferred_delta_cleanup = false;
    retry_deferred_pressure_sheds(
        &mut sessions,
        &mut bindings,
        forwarding,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        worker_id,
        &peer_worker_commands,
        worker_command_queues,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        loop_now_ns,
    );
    retry_deferred_conntrack_deletes(
        &mut sessions,
        conntrack_v4_fd,
        conntrack_v6_fd,
        shared_sessions,
        shared_owner_rg_indexes,
    );
    let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));
    // #11053: if the control TCP session idles out, forget its PPTP calls
    // and replicate the exact control tuple to peer workers. The delete
    // command also clears a peer's channel even if this worker's call rows
    // already expired on their independent data-idle clock.
    for expired in &expired_entries {
        let key = &expired.key;
        // #19026: a close-fenced restored copy is not the end of the session
        // (it is served, closed or replaced elsewhere), so it must not forget
        // the control channel the serving copy still carries.
        if expired.close_fenced {
            continue;
        }
        if key.protocol == crate::ip_proto::PROTO_TCP
            && (key.src_port == crate::session::pptp_control::PPTP_CONTROL_PORT
                || key.dst_port == crate::session::pptp_control::PPTP_CONTROL_PORT)
        {
            crate::afxdp::poll_descriptor::forget_pptp_control_channel(
                &mut sessions,
                &pptp_control,
                worker_commands_by_id,
                &peer_worker_commands,
                key,
                loop_now_ns,
            );
        }
    }
    // #2428: the "Current sessions" gauge Go derives as
    // (session_creates - session_expires) is a LOCAL-forwarding gauge.
    // `session_creates` is bumped ONLY on the four local poll-descriptor
    // install paths (ForwardFlow / ReverseFlow / LocalMiss /
    // MissingNeighborSeed). Every synced-derived origin (SyncImport /
    // SharedMaterialize / WorkerLocalImport / SharedPromote) is never
    // create-counted, so counting its expiry drives session_expires past
    // session_creates, wrapping the unsigned Go subtraction to ~1.8e19.
    // count_local_session_expiries (exhaustive match, no wildcard) counts
    // only the create-counted locals so accounting is balanced on the
    // SAME node and the standby gauge stays 0.
    let local_expired = count_local_session_expiries(expired_entries.iter().map(|e| e.origin));
    retire_expired_missing_neighbor_seeds(
        &expired_entries,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
    );
    let deferred_conntrack_deletes = reap_expired_sessions(
        bindings,
        &expired_entries,
        forwarding,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        loop_now_ns,
        worker_id,
        shared_sessions,
    );
    sessions.defer_conntrack_deletes(deferred_conntrack_deletes);
    if local_expired > 0 {
        if let Some(binding) = bindings.first() {
            binding
                .live
                .session_expires
                .fetch_add(local_expired, Ordering::Relaxed);
        }
    }
    // #10419: expire the local row and its shared/conntrack teardown
    // before polling another packet. Otherwise a lookup can miss the
    // removed local row, rematerialize the still-published shared copy,
    // and forward one more packet on an expired session.
    if !expired_entries.is_empty() {
        let _ = drain_and_flush_all_impl(
            &mut *sessions,
            &mut *bindings,
            binding_lookup,
            &mut *shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &mut deferred_delta_cleanup,
            worker_lossless_wedged,
            &mut *flush_deltas,
        );
    }
    // #10309: the expiry walk must remain all-in-one-call. A full ring
    // may have accepted the first Close deltas and returned the suffix
    // that did not fit on their `ExpiredSession` records. Drain the
    // pre-existing ring first (preserving Open -> Close order), then
    // flush the returned suffix in fixed-size chunks before processing
    // another packet or control event. No shared entry can remain
    // honoured merely because its Close missed the 4096-slot ring.
    let mut expiry_overflow_deltas = std::mem::take(deferred_expiry_overflow_deltas);
    expiry_overflow_deltas.extend(
        expired_entries
            .into_iter()
            .filter_map(|entry| entry.overflow_close),
    );
    if deferred_delta_cleanup {
        deferred_expiry_overflow_deltas.extend(expiry_overflow_deltas.iter().cloned());
        return close_barrier.hold_rx(sessions, worker_id, loop_now_ns);
    }
    if !expiry_overflow_deltas.is_empty() {
        let _ = drain_and_flush_all_impl(
            &mut *sessions,
            &mut *bindings,
            binding_lookup,
            &mut *shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &mut deferred_delta_cleanup,
            worker_lossless_wedged,
            &mut *flush_deltas,
        );
        if deferred_delta_cleanup {
            deferred_expiry_overflow_deltas.extend(expiry_overflow_deltas.iter().cloned());
            return close_barrier.hold_rx(sessions, worker_id, loop_now_ns);
        }
        let mut overflow_chunks = expiry_overflow_deltas.chunks(256);
        while let Some(deltas) = overflow_chunks.next() {
            let handled = purge_queued_flows_for_closed_deltas(
                bindings,
                &binding_lookup,
                &mut shared_recycles,
                &shared_runtime,
                &shared_sessions,
                &shared_owner_rg_indexes,
                deltas,
                Some(&mut sessions),
            );
            flush_deltas(
                sessions,
                bindings,
                worker_lossless_wedged,
                &deltas[..handled],
            );
            if handled < deltas.len() {
                deferred_expiry_overflow_deltas.extend_from_slice(&deltas[handled..]);
                for suffix in overflow_chunks {
                    deferred_expiry_overflow_deltas.extend_from_slice(suffix);
                }
                deferred_delta_cleanup = true;
                break;
            }
        }
        if deferred_delta_cleanup {
            return close_barrier.hold_rx(sessions, worker_id, loop_now_ns);
        }
    }
    // A requeued close from an earlier drain is a teardown barrier: retry
    // it before command/control work or the next AF_XDP poll. This keeps
    // queued packets from forwarding while their close cleanup waits for
    // the tuple permit. #19026: the barrier is BOUNDED
    // (`CLOSE_PERMIT_BARRIER_NS`): the close is retried here before RX on
    // every tick, but once it has waited past the bound the tick goes on to
    // poll RX instead of starving every flow this worker serves.
    if sessions.has_pending_deltas() {
        let _ = drain_and_flush_all_impl(
            &mut *sessions,
            &mut *bindings,
            binding_lookup,
            &mut *shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &mut deferred_delta_cleanup,
            worker_lossless_wedged,
            &mut *flush_deltas,
        );
        if deferred_delta_cleanup {
            return close_barrier.hold_rx(sessions, worker_id, loop_now_ns);
        }
    }
    close_barrier.clear(worker_id, loop_now_ns);
    false
}

// #13075: the loop's `drain_and_flush_all!` macro as a fn (shared with
// the export slice via the loop's closure). See the macro in mod.rs for
// the #2669 unconditional-flush rationale.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn drain_and_flush_all_impl(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    deferred_delta_cleanup: &mut bool,
    worker_lossless_wedged: &mut bool,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    while sessions.has_pending_deltas() {
        let queued_before = sessions.pending_delta_count();
        let deltas = sessions.drain_deltas(256);
        let handled = purge_queued_flows_for_closed_deltas(
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &deltas,
            Some(&mut *sessions),
        );
        if handled < deltas.len() {
            flush_deltas(
                sessions,
                bindings,
                worker_lossless_wedged,
                &deltas[..handled],
            );
            sessions.requeue_deltas_front(&deltas[handled..]);
            *deferred_delta_cleanup = true;
            break;
        }
        // #2669: flush UNCONDITIONALLY (see mod.rs macro for rationale).
        flush_deltas(sessions, bindings, worker_lossless_wedged, &deltas);
        // #19026: the flush takes the close permits again and, when one is
        // busy, requeues the suffix it could not retire. A pass that left the
        // queue no shorter made no progress: yield to the caller's bounded
        // barrier instead of re-draining the same busy close in this loop,
        // which spun with neither RX nor a heartbeat until the permit freed.
        if sessions.pending_delta_count() >= queued_before {
            *deferred_delta_cleanup = true;
            break;
        }
    }
    !*deferred_delta_cleanup
}
