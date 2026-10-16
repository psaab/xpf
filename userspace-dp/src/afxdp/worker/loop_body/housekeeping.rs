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

#[allow(clippy::too_many_arguments)]
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
    dnat_fds: &crate::afxdp::checksum::DnatTableFds,
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
    let ha_ctx = crate::session::ExpireHaContext {
        node_active,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
    };
    let mut deferred_delta_cleanup = false;
    // #13075: the loop-local `drain_and_flush_all!` macro, as a nested fn
    // taking the drain state explicitly (a closure would capture `sessions`
    // / `bindings` for its whole lifetime and block the expiry walk between
    // calls). `flush_deltas` is the caller's expansion of
    // `flush_drained_session_deltas!` (a loop-local macro_rules in mod.rs,
    // not nameable across modules), passed in so the flush semantics —
    // including the #5468 lossless-wedge latch and the #2874 delta-loss
    // latch — stay exactly the loop's.
    macro_rules! drain_and_flush_all {
        () => {
            drain_and_flush_all_impl(
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
            )
        };
    }
    retry_deferred_pressure_sheds(
        &mut sessions,
        &mut bindings,
        forwarding,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        dnat_fds,
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
    );
    let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));
    // #11053: if the control TCP session idles out, forget its PPTP calls
    // and replicate the exact control tuple to peer workers. The delete
    // command also clears a peer's channel even if this worker's call rows
    // already expired on their independent data-idle clock.
    for expired in &expired_entries {
        let key = &expired.key;
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
        return true;
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
            return true;
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
            return true;
        }
    }
    // A requeued close from an earlier drain is a teardown barrier: retry
    // it before command/control work or the next AF_XDP poll. This keeps
    // queued packets from forwarding while their close cleanup waits for
    // the tuple permit.
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
            return true;
        }
    }
    false
}

// #13075: the loop's `drain_and_flush_all!` macro as a fn (shared with
// the export slice via the loop's closure). See the macro in mod.rs for
// the #2669 unconditional-flush rationale.
#[allow(clippy::too_many_arguments)]
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
    }
    !*deferred_delta_cleanup
}
