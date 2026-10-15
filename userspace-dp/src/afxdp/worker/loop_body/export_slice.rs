// #13075 (D4-12) — #9856 multi-pass CommandExport slice + steady-state
// delta drain, extracted from `worker_loop` in loop_body/mod.rs (pure code
// motion; see housekeeping.rs for the shared rationale).
//
// One budgeted slice per tick: adopt newly kicked export sequences into
// the resumable `WorkerExportState` window, drain-first, walk one slice,
// flush the echo batch; otherwise drain one steady-state 256-delta batch.
// Returns `true` when the old in-loop `continue` sites fired (a requeued
// suffix must retry before the next poll): the caller skips the rest of
// the tick. `did_work` is returned via the second tuple element — the
// export slice marks the tick as work exactly where the in-loop code set
// `did_work = true`.
//
// The loop-local macros (`drain_and_flush_all!`,
// `flush_drained_session_deltas!`) arrive as the `drain_and_flush_all` /
// `flush_deltas` closures over their fn equivalents in mod.rs, so the
// #5468 lossless-wedge and #2874 delta-loss latches keep loop semantics.
// `#[inline(never)]`: per-tick control work, never the packet path.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::*;

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn run_export_slice(
    mut sessions: &mut crate::session::SessionTable,
    mut bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    worker_export: &mut Option<WorkerExportState>,
    exported_sequences: Vec<u64>,
    export_owner_rgs: Vec<i32>,
    export_kick_epoch: Option<u64>,
    export_buffer: &crate::afxdp::binding_state::ExportBufferState,
    export_echo_scratch: &mut Vec<(
        crate::session::SessionKey,
        crate::session::SessionDecision,
        crate::session::SessionMetadata,
        crate::session::SessionOrigin,
    )>,
    mut shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    session_export_ack: &Arc<AtomicU64>,
    worker_id: u32,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
    worker_lossless_wedged: &mut bool,
) -> (bool, bool) {
    let mut did_work = false;
    // #9856 slice pacing (moved verbatim from worker_loop's declarations).
    const EXPORT_SLICE_BUDGET: usize = 1024; // max slab slots scanned per slice
    const EXPORT_SLICE_EMITS: usize = 256; // max sessions converted per slice
    const EXPORT_SLICE_DEADLINE_NS: u64 = 500_000; // 500us slice cap
    if !exported_sequences.is_empty() || worker_export.is_some() {
        // Adopt: a timeout-then-rekick overwrites with purge-foreign (a
        // superseded window's leftovers must not poison the new one).
        if !exported_sequences.is_empty() {
            if let Some(token) = exported_sequences.iter().copied().max() {
                // M2c: the window token IS the kicked command sequence
                // (M3 replaces this with the opaque continuation token).
                export_buffer.purge_foreign(token);
                *worker_export = Some(WorkerExportState {
                    cursor: 0,
                    kick_epoch: export_kick_epoch.unwrap_or(u64::MAX),
                    owner_rgs: export_owner_rgs.clone(),
                    sequences: exported_sequences.clone(),
                    token,
                });
            }
        }
        // Drain-first ALWAYS: the ring starts empty before echo emits.
        if !{
            let mut deferred = false;
            crate::afxdp::worker::loop_body::housekeeping::drain_and_flush_all_impl(
                sessions,
                bindings,
                binding_lookup,
                shared_recycles,
                shared_runtime,
                shared_sessions,
                shared_owner_rg_indexes,
                &mut deferred,
                worker_lossless_wedged,
                flush_deltas,
            )
        } {
            return (true, did_work);
        }
        let mut export_done = false;
        if let Some(state) = worker_export.as_mut() {
            use crate::session::ExportWalkOutcome::{Complete, ResumeAt};
            let old_cursor = state.cursor;
            let token = state.token;
            let kick = state.kick_epoch;
            // Ident: the first binding's, else synthesized (mirrors the
            // flush macro's no-binding arm — binding-less workers export
            // too).
            let export_ident = match bindings.first() {
                Some(binding) => binding.identity(),
                None => BindingIdentity {
                    slot: 0,
                    queue_id: 0,
                    worker_id,
                    interface: Arc::<str>::from(""),
                    ifindex: -1,
                },
            };
            let zone_names = &forwarding.zone_id_to_name;
            let slice_start_ns = monotonic_nanos();
            let mut emitted: usize = 0;
            export_echo_scratch.clear();
            let tombstone_drops = sessions.take_tombstone_drops_for_export();
            if tombstone_drops != 0 {
                export_buffer.note_export_tombstone_drops(tombstone_drops);
            }
            let tombstones_complete =
                sessions.take_tombstones_for_export(kick, &state.owner_rgs, |tombstone| {
                    let info =
                        crate::afxdp::export_close_direct(&export_ident, zone_names, tombstone);
                    export_buffer.push_export_tombstone(token, info).is_ok()
                });
            // A full export buffer leaves the tombstone queued and
            // pauses the cursor. Do not re-walk completed open slots
            // until the close repair has been admitted.
            let outcome = if tombstones_complete {
                sessions.iter_export_budgeted(
                    state.cursor,
                    EXPORT_SLICE_BUDGET,
                    kick,
                    &state.owner_rgs,
                    |key, decision, metadata, origin| {
                        // Emit cap FIRST: never exceed the slice, even once.
                        if emitted >= EXPORT_SLICE_EMITS {
                            return false;
                        }
                        // Slice deadline, sampled every 64 emits (vdso-cheap).
                        if emitted > 0
                            && emitted & 63 == 0
                            && monotonic_nanos().saturating_sub(slice_start_ns)
                                > EXPORT_SLICE_DEADLINE_NS
                        {
                            return false;
                        }
                        let Some(info) = crate::afxdp::export_open_direct(
                            &sessions,
                            &export_ident,
                            zone_names,
                            key.clone(),
                            decision,
                            metadata.clone(),
                            origin,
                            crate::session::ExportProvenance::CommandExport(token),
                        ) else {
                            // Reverse (unreachable: the walk predicate skips
                            // them) — skip, never pause (pausing would
                            // livelock on one slot forever).
                            return false;
                        };
                        // Full: pause, retry this slot next pass — never a drop.
                        if export_buffer.push_export_open(token, info).is_err() {
                            return false;
                        }
                        emitted += 1;
                        export_echo_scratch.push((key.clone(), decision, metadata.clone(), origin));
                        true
                    },
                )
            } else {
                ResumeAt(state.cursor)
            };
            // Echo leg: the SAME visited opens through the ring+flush path
            // (binding/recent consumers identical); the event-stream echo
            // is suppressed for CommandExport provenance (#9630).
            for (key, decision, metadata, origin) in export_echo_scratch.drain(..) {
                sessions.emit_open_delta_with_provenance(
                    key,
                    decision,
                    metadata,
                    origin,
                    true,
                    crate::session::ExportProvenance::CommandExport(token),
                );
            }
            if !{
                let mut deferred = false;
                crate::afxdp::worker::loop_body::housekeeping::drain_and_flush_all_impl(
                    sessions,
                    bindings,
                    binding_lookup,
                    shared_recycles,
                    shared_runtime,
                    shared_sessions,
                    shared_owner_rg_indexes,
                    &mut deferred,
                    worker_lossless_wedged,
                    flush_deltas,
                )
            } {
                return (true, did_work);
            }
            match outcome {
                Complete => {
                    // Ack only after the complete export has shipped.
                    if let Some(sequence) = state.sequences.iter().copied().max() {
                        session_export_ack.store(sequence, Ordering::Release);
                    }
                    export_done = true;
                    did_work = true;
                }
                ResumeAt(cursor) => {
                    if emitted > 0 || cursor != old_cursor {
                        did_work = true;
                    }
                    state.cursor = cursor;
                }
            }
        }
        if export_done {
            *worker_export = None;
        }
    } else if sessions.has_pending_deltas() {
        let deltas = sessions.drain_deltas(256);
        let handled = purge_queued_flows_for_closed_deltas(
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            &shared_sessions,
            &shared_owner_rg_indexes,
            &deltas,
            Some(&mut *sessions),
        );
        if handled < deltas.len() {
            sessions.requeue_deltas_front(&deltas[handled..]);
            return (true, did_work);
        }
        // #2669: flush unconditionally — see flush_drained_session_deltas!.
        flush_deltas(sessions, bindings, worker_lossless_wedged, &deltas);
    }
    (false, did_work)
}
