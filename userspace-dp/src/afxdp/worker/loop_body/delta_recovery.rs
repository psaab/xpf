// #13075 (D4-12) — per-tick delta-loss recovery + stale-session sweeps,
// extracted from `worker_loop` in loop_body/mod.rs (pure code motion; see
// housekeeping.rs for the shared rationale).
//
// Per tick: fold per-binding RPC-fallback loss latches (#5290), drive the
// #2442 loss-of-sync resync (drain-as-you-export owner-RG re-emit), run
// one budgeted slice of the #8586/#9327 delete-drop sweep and the #9752
// installing-table purge. Returns `true` when the old in-loop `continue`
// fired (deferred cleanup during the resync drain): skip the rest of the
// tick. `validation` is read for its fib generation (purge arming) — the
// caller passes the live validation state by value (Copy).
//
// The loop-local `drain_and_flush_all!` macro arrives as the
// `drain_and_flush_all` closure over `drain_and_flush_all_impl`, and the
// flush as `flush_deltas` over `flush_session_deltas_loop` (mod.rs), so
// the #5468/#2874 latches keep loop semantics. `#[inline(never)]`.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::*;

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn run_delta_recovery(
    mut sessions: &mut crate::session::SessionTable,
    mut bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    validation_fib_generation: u32,
    worker_id: u32,
    loop_now_ns: u64,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_export_is_none: bool,
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    last_delete_drop_epoch: &mut u64,
    delete_drop_sweep: &mut crate::afxdp::session_glue::DeleteDropSweep,
    install_table_purge: &mut crate::afxdp::session_glue::InstallTablePurge,
    mut shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    worker_lossless_wedged: &mut bool,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    // #2442: loss-of-sync resync. If `push_delta` dropped any delta since
    // the last drain, the in-worker session-delta ring overflowed and the
    // downstream session-sync consumer missed HA-relevant open/close
    // events — its view may have silently diverged from the table truth.
    // Re-emit an open delta for every owned forward session (the same
    // table-truth walk `ExportOwnerRGSessions` performs) so the peer
    // re-derives a complete snapshot.
    //
    // DRAIN-AS-YOU-EXPORT: a worker can own up to DEFAULT_MAX_SESSIONS
    // (131072) forward sessions — 32× the 4096-slot delta ring. A naive
    // "drain then push all N" overflows the ring at delta 4097, drops
    // sessions 4097..N, re-latches the loss, and never converges (a
    // permanent per-cycle resync storm). Instead, collect the candidates
    // once, then emit them in ring-sized chunks, draining+flushing each
    // chunk to the peer before emitting the next. The ring is empty before
    // every chunk and a chunk is < cap, so push_delta NEVER overflows
    // during a resync — the complete snapshot ships and the latch is not
    // spuriously re-armed. A genuinely new drop after the resync still
    // re-arms a fresh episode on a later cycle.
    //
    // Emit at most this many open deltas before draining. Comfortably
    // under MAX_SESSION_DELTAS (4096) so a freshly-emptied ring never
    // overflows mid-chunk. Shared by the #2442 loss-of-sync resync and the
    // #2653 single-shot `ExportOwnerRGSessions` command path.
    const RESYNC_EXPORT_CHUNK: usize = 2048;
    // Chunked drain-as-you-export: collect the owned forward candidates
    // for `$owner_rgs` once, then emit them in ring-sized chunks, draining
    // and flushing each chunk to the peer before emitting the next. The
    // ring is empty before every chunk and a chunk is < cap, so
    // `push_delta` NEVER overflows during the export — the complete
    // snapshot ships and the loss latch is not spuriously re-armed. A
    // worker can own up to DEFAULT_MAX_SESSIONS (131072) forward sessions
    // — 32x the 4096-slot delta ring — so a naive "emit all N then drain
    // once" drops sessions 4097..N (the #2653 command-path bug, sibling of
    // #2442's worker-loop bug).
    macro_rules! chunked_drain_as_you_export {
        ($owner_rgs:expr, $flag:ident) => {{
            let owner_rgs = $owner_rgs;
            if !owner_rgs.is_empty() {
                // #9856 M2c: LossResync keeps this unfiltered full-rescan
                // (`u64::MAX` preserves today's re-announce-everything
                // behavior); CommandExport moved to the accept-captured
                // kick_epoch + multi-pass cursor in the branch below. M4
                // forks the two legs (provenance) properly.
                let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(
                    &sessions,
                    &owner_rgs,
                    u64::MAX,
                );
                for chunk in candidates.chunks(RESYNC_EXPORT_CHUNK) {
                    for (key, decision, metadata, origin) in chunk.iter().cloned() {
                        sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
                    }
                    if !crate::afxdp::worker::loop_body::housekeeping::drain_and_flush_all_impl(
                        sessions,
                        bindings,
                        binding_lookup,
                        shared_recycles,
                        shared_runtime,
                        shared_sessions,
                        shared_owner_rg_indexes,
                        &mut $flag,
                        worker_lossless_wedged,
                        flush_deltas,
                    ) {
                        break;
                    }
                }
            }
        }};
    }
    // #5290: fold the per-binding RPC-fallback loss-of-sync latch into the
    // SessionTable latch. The control-thread fair drain
    // (`Coordinator::drain_session_deltas`) arms `BindingLiveState`'s latch
    // when the caller-wide budget overflowed and left this worker's deltas
    // undrained, and `push_session_delta` arms it when the per-binding
    // fallback buffer overflowed and dropped a delta. Either way the standby
    // missed HA-relevant open/close events, so drive the SAME #2442 owner-RG
    // resync below (table-truth rescan) — deliver-or-resync, never a silent
    // drop. A single AtomicBool per binding, so a burst raises exactly one
    // resync (debounced by the swap in `take_delta_loss`).
    for binding in bindings.iter() {
        if binding.live.take_delta_loss() {
            sessions.set_delta_loss();
        }
    }
    // #8586: a cross-worker `DeleteSynced` for THIS worker was refused by a
    // full queue, so this worker never learned the session is gone. Its NAT
    // holder bit was already released on its behalf (#8576); what is left is
    // its own local table entry and its per-binding flow-cache slots, which
    // only this loop can reach — and the signal could not travel through the
    // queue that refused the command, hence the out-of-band epoch.
    //
    // KEYED ON THE DELETE DROP, NOT ON QUEUE PRESSURE, and that distinction
    // is measured rather than assumed: ordinary session establishment pins
    // the queue at the 4096 cap and discards 85,668 commands over 32,768
    // creates while dropping ZERO deletes (#8586). A trigger on queue depth
    // would run this walk continuously through normal traffic and reconcile
    // nothing.
    //
    // One relaxed load per pass. A burst raises exactly ONE reconcile per
    // pass however many refusals it caused, because the epoch is compared,
    // not counted down.
    let delete_drop_epoch = crate::afxdp::session_glue::session_delete_drop_epoch(worker_id);
    if delete_drop_epoch != *last_delete_drop_epoch {
        *last_delete_drop_epoch = delete_drop_epoch;
        // #9327: ARM the sweep; do not run it here. The whole-table walk
        // measured 6.47 ms at 60k sessions even when it finds NOTHING, and
        // 39 ms when everything is stale — against a ~1.97 ms RX-ring fill.
        // The epoch gate bounds how often this fires, not what one firing
        // costs, and one refused cross-worker DeleteSynced arms it.
        delete_drop_sweep.arm();
    }
    // Step the sweep every pass while it is running, bounded by
    // DELETE_DROP_SWEEP_BUDGET slab slots. A no-op with no sweep armed.
    {
        let mut evicted_keys: Vec<crate::session::SessionKey> = Vec::new();
        let reconciled = delete_drop_sweep.step_with_nat(
            &mut sessions,
            &shared_sessions,
            session_map,
            &forwarding,
            loop_now_ns,
            worker_id,
            &mut evicted_keys,
        );
        if reconciled > 0 {
            crate::afxdp::worker::invalidate_flow_cache_slots_for_keys(bindings, &evicted_keys);
            debug_log!(
                "DELETE_DROP_RECONCILE: worker={} epoch={} swept={}",
                worker_id,
                delete_drop_epoch,
                reconciled,
            );
        }
    }
    // #9752: purge sessions whose installing table is unresolvable. The
    // flag is set by re-resolve terminal observations (cold); the walk is
    // paced like the sweep above (never whole-table in one pass) and
    // restarts on generation change inside `step`.
    if crate::afxdp::session_glue::take_install_table_purge_flag(worker_id) {
        install_table_purge.arm(validation_fib_generation);
    }
    {
        let mut evicted_keys: Vec<crate::session::SessionKey> = Vec::new();
        let purged = install_table_purge.step(
            &mut sessions,
            session_map,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &shared_runtime,
            validation_fib_generation,
            loop_now_ns,
            worker_id,
            &mut evicted_keys,
        );
        if purged > 0 {
            crate::afxdp::worker::invalidate_flow_cache_slots_for_keys(bindings, &evicted_keys);
            debug_log!(
                "INSTALL_TABLE_PURGE: worker={} purged={}",
                worker_id,
                purged,
            );
        }
    }
    // #9856: defer while a CommandExport window is open — the export
    // slice owns this pass's drain/emit budget, and the short-circuit
    // leaves the latch armed so the resync runs once it completes.
    if worker_export_is_none && sessions.take_delta_loss() {
        // #2442 loss-of-sync resync. If `push_delta` dropped any delta
        // since the last drain, the in-worker session-delta ring
        // overflowed and the downstream session-sync consumer missed
        // HA-relevant open/close events — its view may have silently
        // diverged from the table truth. Re-emit an open delta for every
        // owned forward session so the peer re-derives a complete snapshot.
        //
        // Drain the existing backlog so the ring starts empty.
        let mut deferred_delta_cleanup = false;
        if !crate::afxdp::worker::loop_body::housekeeping::drain_and_flush_all_impl(
            sessions,
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &mut deferred_delta_cleanup,
            worker_lossless_wedged,
            flush_deltas,
        ) {
            sessions.set_delta_loss();
            return true;
        }
        chunked_drain_as_you_export!(sessions.all_owner_rg_ids(), deferred_delta_cleanup);
        if deferred_delta_cleanup {
            sessions.set_delta_loss();
            return true;
        }
        // #8593: that claim was TRUE OF ONE RING AND FALSE OF THE OTHER,
        // and #5290 widened its scope without re-checking it. An earlier
        // revision read: "The export drained to empty without overflowing,
        // so any latch set during this resync was a genuinely-new local
        // drop, not the export re-flooding itself."
        //
        // `chunked_drain_as_you_export!` does keep the SessionTable ring
        // (`sessions.push_delta`) under its cap — that half is right. But
        // every chunk is then flushed through `flush_session_deltas` into
        // the PER-BINDING RPC-fallback buffer, which the chunking does not
        // drain and which the Go side polls on the ~5 s
        // `DrainSessionDeltas` cadence. #5290 later made THAT buffer's
        // overflow arm this same latch, so the export re-armed the trigger
        // that produced it.
        //
        // Measured on `loss:xpf-userspace-fw0`: 125,780 session creates
        // produced 25.26M deltas of which 23.29M (92%) were dropped, and
        // with the generator stopped and `active_flow_count = 0` the helper
        // kept generating ~149k deltas/s for ~90 s, ending only as the
        // owned sessions aged out. 32.68M dropped session-CREATE deltas
        // against 52k dropped closes, from 32,768 real creates — the
        // signature of re-exported opens, not of traffic.
        //
        // The export's own deltas now carry `SessionDelta::bulk_resync`
        // (set by their sole producer, `emit_open_delta_with_origin`), and
        // `flush_session_deltas` routes those to
        // `push_session_delta_bulk_export`, which counts a drop but does not
        // arm. The marker is on the DELTA rather than passed at this call
        // site on purpose: a future drain site that passed the flag wrongly
        // would SUPPRESS a genuine arm, silently, and here it does not
        // choose. So the claim above is true again, and for both rings: any
        // latch set from here on is a genuinely-new incremental drop.
    }
    false
}
