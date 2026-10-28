// HA session-delta RPC-fallback buffer: the bounded
// `pending_session_deltas` FIFO, its generated/dropped/drained
// counters, and the #5290 per-binding loss-of-sync latch
// (`delta_loss_pending`) that forces a full owner-RG resync when the
// fallback stream goes lossy. Extracted from `umem/mod.rs` (#6436).

use super::*;

impl BindingLiveState {
    /// Push an INCREMENTAL session delta into the RPC-fallback buffer. A drop
    /// arms the loss-of-sync latch, which drives the #2442 owner-RG resync.
    pub(in crate::afxdp) fn push_session_delta(&self, delta: SessionDeltaInfo) {
        self.push_session_delta_inner(delta, false);
    }

    /// #8593: push a delta that is ITSELF part of a bulk owner-RG export. A
    /// drop is counted but does NOT arm the loss-of-sync latch.
    ///
    /// The latch exists to trigger the owner-RG resync. A resync delta that
    /// arms it triggers ANOTHER resync, whose export re-fills the same buffer,
    /// which arms it again — a feedback loop, and one that outlives the traffic
    /// that started it. Measured on `loss:xpf-userspace-fw0` (#8593): 125,780
    /// session creates produced 25.26M deltas of which 23.29M (92%) were
    /// dropped, and with the generator stopped and `active_flow_count = 0` the
    /// helper kept generating ~149k deltas/s and dropping ~136k/s for ~90 s,
    /// ending only as the owned sessions aged out. The signature was decisive:
    /// 32.68M dropped session-CREATE deltas against 52k dropped closes, from
    /// 32,768 real creates — re-exported opens, not traffic.
    ///
    /// Why not-arming is also the CORRECT answer and not merely the loop-safe
    /// one: the recovery for a dropped delta is an OPEN-ONLY snapshot of the
    /// owned set. It cannot restore a dropped CLOSE however many times it runs,
    /// and every OPEN it could restore is already in the snapshot being shipped.
    /// Re-running it on its own overflow recovers nothing.
    ///
    /// This does NOT suppress a genuinely-new incremental drop, and that is a
    /// property of WHERE the marker lives rather than of timing: it is set by
    /// the delta's producer (`SessionTable::emit_open_delta_with_origin`, whose
    /// only production caller is the worker loop's chunked owner-RG export), so
    /// an incremental open/close interleaved with the export is unmarked and
    /// still arms. An earlier revision of this fix passed the flag at the flush
    /// CALL SITE and had to argue the worker loop's single-threadedness to reach
    /// the same conclusion; that form is also the one where a future drain site
    /// passing the wrong flag silently suppresses a real arm.
    pub(in crate::afxdp) fn push_session_delta_bulk_export(&self, delta: SessionDeltaInfo) {
        self.push_session_delta_inner(delta, true);
    }

    fn push_session_delta_inner(&self, delta: SessionDeltaInfo, bulk_export: bool) {
        self.session_delta_generated.fetch_add(1, Ordering::Relaxed);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                if pending.len() >= MAX_PENDING_SESSION_DELTAS {
                    self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                    // #5290: a dropped RPC-fallback delta is a HA-relevant
                    // open/close the standby will never observe — the fallback
                    // stream just went lossy. Latch loss-of-sync so the owning
                    // worker forces a full owner-RG resync (table-truth rescan),
                    // mirroring `SessionTable::push_delta`'s #2442 behavior.
                    //
                    // #8593: NOT when the dropped delta is itself part of that
                    // resync's export — see `push_session_delta_bulk_export`.
                    if !bulk_export {
                        self.delta_loss_pending.store(true, Ordering::Relaxed);
                    }
                    return;
                }
                pending.push_back((delta, bulk_export));
                // #8108: record how FULL the buffer got, not how full it is.
                //
                // The acceptance measurement this issue asks for -- "a measured
                // ring-occupancy figure from a revocation burst" -- could not be
                // taken: `len()` was read only for the cap check above and
                // nothing retained it, and `delta_loss_pending` is a BOOLEAN
                // that says "we overflowed at least once", never "we reached
                // 90%". So there was no way to distinguish a buffer that is
                // comfortable from one that survives on luck.
                //
                // A HIGH-WATER MARK rather than a depth gauge, and that is the
                // whole point. This buffer DRAINS; a depth sampled at 1 Hz sees
                // a burst only if the sample lands inside it, and misses it
                // otherwise -- reporting a healthy-looking small number for
                // exactly the event being measured. A high-water mark cannot
                // miss a burst it observed.
                let depth = pending.len();
                self.session_delta_high_water
                    .fetch_max(depth as u64, Ordering::Relaxed);
            }
            Err(_) => {
                self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                // A POISONED lock is not the #8593 self-arming case: the export
                // did not cause it and a resync is the right response, so this
                // arm is unconditional.
                self.delta_loss_pending.store(true, Ordering::Relaxed);
            }
        }
    }

    /// #5290: true if the RPC-fallback buffer still holds undrained deltas.
    /// Used by the fair-drain overflow scan to arm loss-of-sync only on the
    /// bindings that actually fell behind. A poisoned lock is treated as "not
    /// pending" — the separate poison path in `push_session_delta` already
    /// latched loss-of-sync, so this avoids double-counting.
    pub(in crate::afxdp) fn has_pending_session_deltas(&self) -> bool {
        // #17201: recover the committed buffer on poison instead of
        // reading poison as "not pending".
        !crate::sync_util::lock_tolerant(&self.pending_session_deltas).is_empty()
    }

    /// #16630: true if the RPC-fallback buffer still holds an undrained
    /// INCREMENTAL delta. Bulk-export entries do not count: they are the
    /// resync's own output, and arming on their residue re-runs the resync
    /// that produced them (#8593's drain-side residual). A poisoned lock is
    /// treated as "not pending" — the poison path already latched
    /// loss-of-sync unconditionally.
    pub(in crate::afxdp) fn has_pending_incremental_session_deltas(&self) -> bool {
        // #17201: recover the committed buffer on poison (see above).
        crate::sync_util::lock_tolerant(&self.pending_session_deltas)
            .iter()
            .any(|(_, bulk)| !*bulk)
    }

    /// #5290: arm the per-binding loss-of-sync latch. Called by the control-
    /// thread fair drain when the caller budget overflowed and left this
    /// binding's deltas undrained. Mirror of `SessionTable::set_delta_loss`.
    pub(in crate::afxdp) fn set_delta_loss(&self) {
        self.delta_loss_pending.store(true, Ordering::Relaxed);
    }

    /// #5290: consume the per-binding loss-of-sync latch. Called once per drain
    /// cycle by the owning worker loop, which folds a true result into
    /// `SessionTable::set_delta_loss` to drive the existing owner-RG resync.
    /// Single bool swap, so a burst that armed it repeatedly before this read
    /// raises exactly one resync (debounce by construction).
    pub(in crate::afxdp) fn take_delta_loss(&self) -> bool {
        self.delta_loss_pending.swap(false, Ordering::Relaxed)
    }

    pub(in crate::afxdp) fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let drain = max.max(1);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                let count = drain.min(pending.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some((delta, _bulk)) = pending.pop_front() {
                        out.push(delta);
                    }
                }
                self.session_delta_drained
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                out
            }
            Err(_) => Vec::new(),
        }
    }
}
