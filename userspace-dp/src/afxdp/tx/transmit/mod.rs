// XSK TX-ring submit + per-frame recycle. Single-writer (owner
// worker); atomic ops use `Ordering::Relaxed`.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{apply_dscp_rewrite_to_frame, decode_frame_summary, frame_has_tcp_rst};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{FastMap, FastSet, PreparedTxRecycle, PreparedTxRequest, TxRequest};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{MIRROR_TX_FRAME_RESERVE, TX_BATCH_SIZE, tx_frame_capacity};
use crate::xsk_ffi::xdp::XdpDesc;

use super::rings::{maybe_wake_tx, reap_tx_completions};
use super::stats::stamp_submits;

/// TX submit outcome error (#4971). Both payloads are `Copy` C-like
/// reason codes, NOT `String`s: the expected-backpressure retry path
/// recurs every drain pass under ring pressure, so allocating a fresh
/// `String` there violated the hot-path no-allocation discipline.
/// `Retry` is the expected-congestion path (allocation-free + surfaced
/// lock-free via `BindingLiveState::last_tx_retry_status`); `Drop` is
/// the exceptional capacity/slice-fault path (rare — it may still
/// render a message via `set_error` on the exceptional branch).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum TxError {
    Retry(TxRetryReason),
    Drop(TxDropReason),
}

/// Copyable classification of an expected TX backpressure retry
/// (#4971). Each variant maps 1:1 to a former allocated retry string;
/// `as_str()` renders the exact legacy operator-facing text so status
/// and log scraping are unchanged. `#[repr(u8)]` with explicit
/// discriminants backs the lock-free `BindingLiveState`
/// `last_tx_retry_status` atomic (0 = none).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::afxdp) enum TxRetryReason {
    NoFreeTxFrame = 1,
    NoPreparedTxFrame = 2,
    TxRingInsertFailed = 3,
    PreparedTxRingInsertFailed = 4,
}

impl TxRetryReason {
    /// The exact legacy operator-facing message for this retry reason.
    /// Kept byte-identical to the pre-#4971 `TxError::Retry(String)`
    /// text so `show`/status/log scraping is unaffected.
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            TxRetryReason::NoFreeTxFrame => "no free TX frame available",
            TxRetryReason::NoPreparedTxFrame => "no prepared TX frame available",
            TxRetryReason::TxRingInsertFailed => "tx ring insert failed",
            TxRetryReason::PreparedTxRingInsertFailed => "prepared tx ring insert failed",
        }
    }

    /// Reverse of the `#[repr(u8)]` discriminant used by the
    /// lock-free `last_tx_retry_status` atomic. `0` (or any unknown
    /// code) → `None` (no retry recorded yet).
    pub(in crate::afxdp) fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(TxRetryReason::NoFreeTxFrame),
            2 => Some(TxRetryReason::NoPreparedTxFrame),
            3 => Some(TxRetryReason::TxRingInsertFailed),
            4 => Some(TxRetryReason::PreparedTxRingInsertFailed),
            _ => None,
        }
    }
}

/// Copyable classification of an exceptional TX drop (#4971). Unlike
/// `TxRetryReason` this is NOT the expected-backpressure hot path — it
/// fires only on capacity or slice-bounds faults. It still carries the
/// offending geometry so the operator-facing message rendered on the
/// (rare) drop branch via `set_error` is byte-identical to the former
/// allocated `format!` strings. `Copy` because every field is a scalar
/// — constructing the error never allocates; only the exceptional
/// `message()` render does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum TxDropReason {
    LocalFrameExceedsCapacity { len: usize, cap: usize },
    LocalSliceOutOfRange { offset: u64, len: usize },
    PreparedFrameExceedsCapacity { len: u32, cap: usize },
    PreparedSliceOutOfRange { offset: u64, len: u32 },
}

impl TxDropReason {
    /// Render the operator-facing message. Only called on the rare
    /// exceptional drop branch (capacity / slice fault), so the
    /// `format!` allocation here is acceptable — the hot expected-retry
    /// path never constructs a `String`. Text is byte-identical to the
    /// pre-#4971 `TxError::Drop(String)` messages.
    pub(in crate::afxdp) fn message(self) -> String {
        match self {
            TxDropReason::LocalFrameExceedsCapacity { len, cap } => {
                format!("local tx frame exceeds UMEM frame capacity: len={len} cap={cap}")
            }
            TxDropReason::LocalSliceOutOfRange { offset, len } => {
                format!("tx frame slice out of range: offset={offset} len={len}")
            }
            TxDropReason::PreparedFrameExceedsCapacity { len, cap } => {
                format!("prepared tx frame exceeds UMEM frame capacity: len={len} cap={cap}")
            }
            TxDropReason::PreparedSliceOutOfRange { offset, len } => {
                format!("prepared tx frame slice out of range: offset={offset} len={len}")
            }
        }
    }
}

pub(in crate::afxdp) fn recycle_cancelled_prepared_offset_with_shared(
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
    slot: u32,
    recycle: PreparedTxRecycle,
    offset: u64,
) {
    let recycle_offset = recycle.recycle_offset(offset);
    match recycle {
        PreparedTxRecycle::FreeTxFrame => free_tx_frames.push_back(recycle_offset),
        PreparedTxRecycle::FillOnSlot(fill_slot)
        | PreparedTxRecycle::FillOnSlotWithOffset {
            slot: fill_slot, ..
        } if fill_slot == slot => {
            pending_fill_frames.push_back(recycle_offset);
        }
        PreparedTxRecycle::FillOnSlot(_) | PreparedTxRecycle::FillOnSlotWithOffset { .. } => {
            if let Some(shared_recycles) = shared_recycles.as_deref_mut() {
                if let Some(fill_slot) = recycle.fill_slot() {
                    shared_recycles.push((fill_slot, recycle_offset));
                    return;
                }
            }
            // #9900 F-092: no shared sink for a cross-slot Fill recycle — the
            // frame parks in the LOCAL free pool (an RX→TX migration, as
            // before), but masked to its frame BASE. The stored recycle offset
            // is a post-headroom RX addr (base + 512); planting it verbatim
            // would submit unaligned TX descs that the completion path must
            // then drop as invalid, leaking the frame. Masking keeps the pool
            // aligned-only, which is what the reap check requires.
            free_tx_frames
                .push_back(recycle_offset & !((crate::afxdp::UMEM_FRAME_SIZE as u64) - 1));
        }
    }
}

pub(in crate::afxdp) fn recycle_prepared_immediately_with_shared(
    binding: &mut BindingWorker,
    req: &PreparedTxRequest,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    recycle_cancelled_prepared_offset_with_shared(
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.tx_pipeline.pending_fill_frames,
        shared_recycles,
        binding.slot,
        req.recycle,
        req.offset,
    );
}

pub(in crate::afxdp) fn remember_prepared_recycle(
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    in_flight_untracked_tx: &mut FastSet<u64>,
    req: &PreparedTxRequest,
) {
    if req.recycle.fill_slot().is_some() {
        in_flight_prepared_recycles.insert(req.offset, req.recycle);
    } else {
        // #9900 F-092 (GPT-2): a `FreeTxFrame` submit has no tracked recycle
        // entry — record it in the untracked ownership set instead, so its
        // completion (and ONLY a first completion for it) recycles.
        in_flight_untracked_tx.insert(req.offset);
    }
}

pub(in crate::afxdp) fn transmit_batch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    // #5157: this batch's committed identity is rebuilt from scratch on
    // every call. Cleared HERE (before any early return) so an
    // `Ok((0, 0))` short-circuit — empty `pending`, or an all-dropped
    // mirror batch below — leaves the committed set empty rather than
    // stale, and `submit_local` never charges a prior batch's flows.
    binding.scratch.scratch_committed_orig_idx.clear();
    if pending.is_empty() {
        return Ok((0, 0));
    }
    if binding.tx_pipeline.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let batch_size = pending
        .len()
        .min(binding.tx_pipeline.free_tx_frames.len())
        .min(TX_BATCH_SIZE);
    if batch_size == 0 {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry(TxRetryReason::NoFreeTxFrame));
    }

    binding.scratch.scratch_local_tx.clear();
    let mut dropped_mirror_reserve = false;
    // #5157: original-`pending` position of each STAGED entry, indexed
    // by its stage position in `scratch_local_tx`. `orig_idx` counts
    // EVERY pop (staged AND mirror-dropped), so it stays aligned with
    // the caller's per-item sidecar, which is built in unfiltered input
    // order. Only staged entries record into `staged_orig_idx`; a
    // mid-batch mirror drop just advances the counter, breaking the
    // prefix relationship the old count-only accounting assumed.
    let mut staged_orig_idx = [0u16; TX_BATCH_SIZE];
    let mut orig_idx: u16 = 0;
    while binding.scratch.scratch_local_tx.len() < batch_size {
        let Some(mut req) = pending.pop_front() else {
            break;
        };
        if req.mirror_clone && binding.tx_pipeline.free_tx_frames.len() <= MIRROR_TX_FRAME_RESERVE {
            binding
                .live
                .mirror_drops_tx_frame_reserve
                .fetch_add(1, Ordering::Relaxed);
            dropped_mirror_reserve = true;
            orig_idx = orig_idx.saturating_add(1);
            continue;
        }
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            // #hb166 T-6(d): unwind already-prepared entries before
            // returning. Drain in REVERSE so the successive push_front
            // calls restore the ORIGINAL front-to-back order at the head of
            // `pending`; a forward drain reverses the staged prefix and
            // reorders same-flow (e.g. in-order TCP) segments on this error
            // path. free_tx_frames are fungible, so their order is moot.
            for (off, r) in binding.scratch.scratch_local_tx.drain(..).rev() {
                binding.tx_pipeline.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(TxDropReason::LocalFrameExceedsCapacity {
                len: req.bytes.len(),
                cap: tx_frame_capacity(),
            }));
        }
        let Some(offset) = binding.tx_pipeline.free_tx_frames.pop_front() else {
            pending.push_front(req);
            break;
        };
        let Some(frame) = (unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, req.bytes.len())
        }) else {
            binding.tx_pipeline.free_tx_frames.push_front(offset);
            // #hb166 T-6(d): reverse-drain unwind (see the capacity-drop
            // site above) so the staged prefix keeps its original order at
            // the head of `pending`.
            for (off, r) in binding.scratch.scratch_local_tx.drain(..).rev() {
                binding.tx_pipeline.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(TxDropReason::LocalSliceOutOfRange {
                offset,
                len: req.bytes.len(),
            }));
        };
        frame.copy_from_slice(&req.bytes);
        // RST detection: log when we're about to transmit a TCP RST
        if cfg!(feature = "debug-log") {
            if frame_has_tcp_rst(&req.bytes) {
                binding.telemetry.dbg_tx_tcp_rst += 1;
                thread_local! {
                    static TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                TX_RST_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 50 {
                        c.set(n + 1);
                        let summary = decode_frame_summary(&req.bytes);
                        eprintln!(
                            "RST_DETECT TX[{}]: slot={} len={} {}",
                            n,
                            binding.slot,
                            req.bytes.len(),
                            summary,
                        );
                        if n < 5 {
                            let hex_len = req.bytes.len().min(80);
                            let hex: String = req.bytes[..hex_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("RST_DETECT TX_HEX[{n}]: {hex}");
                        }
                    }
                });
            }
        }
        // #5157: this entry's stage position is the pre-push length;
        // record its original-input position so the settle loop below
        // can report the committed identities to `submit_local`.
        let stage_pos = binding.scratch.scratch_local_tx.len();
        if stage_pos < TX_BATCH_SIZE {
            staged_orig_idx[stage_pos] = orig_idx;
        }
        orig_idx = orig_idx.saturating_add(1);
        binding.scratch.scratch_local_tx.push((offset, req));
    }

    if binding.scratch.scratch_local_tx.is_empty() {
        if dropped_mirror_reserve {
            return Ok((0, 0));
        }
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry(TxRetryReason::NoPreparedTxFrame));
    }

    let mut writer = binding
        .xsk
        .tx
        .transmit(binding.scratch.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);
    // #940: NO V_min publish here. transmit_batch is the post-CoS
    // backup path; it operates on `pending: VecDeque<TxRequest>`
    // directly (never touches a CoSQueueRuntime), so there is no
    // queue_vtime to publish. V_min applies only to traffic that
    // flowed through a shared_exact CoS queue.
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the post-CoS backup transmit_batch
    // variant for local requests). Post-commit stamping prevents a
    // scheduler preemption window between insert and ring submission
    // from inflating the observed latency.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_pipeline.tx_submit_ns,
        binding
            .scratch
            .scratch_local_tx
            .iter()
            .take(inserted as usize)
            .map(|(offset, _)| *offset),
        ts_submit,
    );

    if inserted == 0 {
        binding.telemetry.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some((offset, req)) = binding.scratch.scratch_local_tx.pop() {
            binding.tx_pipeline.free_tx_frames.push_front(offset);
            pending.push_front(req);
        }
        return Err(TxError::Retry(TxRetryReason::TxRingInsertFailed));
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    // #4971: reverse-pop the staged scratch instead of collecting the
    // un-inserted tail into a fresh `Vec` per drain pass. `pop()`
    // yields the highest staged index first; after each pop the
    // scratch's new `len()` equals the popped item's index, so we can
    // split sent-prefix from retry-tail without a side buffer. Pushing
    // the tail with `push_front` in this reverse order restores the
    // ORIGINAL front-to-back FIFO at the head of `pending` (t3 then t4
    // → [t3, t4, ...]) — same ordering the prior `retry_tail` +
    // `.rev()` produced, now allocation-free. free_tx_frames order is
    // fungible.
    while let Some((offset, mut req)) = binding.scratch.scratch_local_tx.pop() {
        let idx = binding.scratch.scratch_local_tx.len();
        if idx < inserted as usize {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
            if let Some(mut admissions) = req.overlap_admissions.take() {
                admissions.commit();
            }
            // #9900 F-092 (GPT-2): the kernel accepted this desc — record
            // ownership so its completion (and ONLY a first completion for
            // it) can return the frame to the free pool.
            binding.tx_pipeline.in_flight_untracked_tx.insert(offset);
            // #5157: record the committed item's ORIGINAL-input position
            // (identity), not just a count. Reverse-pop order does not
            // matter — the caller's per-flow accounting is a set-sum over
            // these indices.
            binding
                .scratch
                .scratch_committed_orig_idx
                .push(staged_orig_idx[idx]);
        } else {
            binding.tx_pipeline.free_tx_frames.push_front(offset);
            pending.push_front(req);
        }
    }

    // Latency-sensitive reply traffic can stall indefinitely on otherwise idle zerocopy
    // bindings unless we explicitly kick TX after committing descriptors.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

pub(super) fn transmit_prepared_batch(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    let mut pending = core::mem::take(&mut binding.tx_pipeline.pending_tx_prepared);
    let result = transmit_prepared_queue(binding, &mut pending, now_ns, shared_recycles);
    binding.tx_pipeline.pending_tx_prepared = pending;
    result
}

/// Orchestrator: walks the prepared TX queue through six phases —
/// stage → DSCP rewrite → UMEM slice re-verify → optional RST log →
/// reserve+write+commit+stamp → finalise (success accounting / retry
/// recovery / TX kick). See `transmit/{stage,rewrite,verify,write,
/// finalise}.rs` for each phase's invariants. Pure code motion of
/// the prior monolithic body (#1354); semantics, ordering, and drop
/// accounting are byte-identical to the pre-split function.
pub(in crate::afxdp) fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    stage::stage_batch_into_scratch(binding, pending, shared_recycles)?;
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    rewrite::apply_dscp_rewrites_to_staged(binding, shared_recycles)?;
    verify::verify_umem_slices_for_staged(binding, shared_recycles)?;
    if cfg!(feature = "debug-log") {
        log_rst_frames_prepared(binding);
    }
    let inserted = write::reserve_and_write_descriptors(binding);
    finalise::finalise_prepared(binding, pending, now_ns, inserted)
}

/// Diagnostic-only: scan staged prepared frames for TCP RST and emit
/// throttled RST_DETECT log lines. Behind `cfg!(feature = "debug-log")`
/// at the call site; kept as an out-of-line helper so the per-batch
/// orchestrator stays compact when debug-log is enabled.
#[inline]
fn log_rst_frames_prepared(binding: &mut BindingWorker) {
    for req in &binding.scratch.scratch_prepared_tx {
        if let Some(frame_data) = binding
            .umem
            .area()
            .slice(req.offset as usize, req.len as usize)
        {
            if frame_has_tcp_rst(frame_data) {
                binding.telemetry.dbg_tx_tcp_rst += 1;
                thread_local! {
                    static PREP_TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                PREP_TX_RST_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 50 {
                        c.set(n + 1);
                        let summary = decode_frame_summary(frame_data);
                        eprintln!(
                            "RST_DETECT PREP_TX[{}]: if={} q={} len={} {}",
                            n,
                            binding.identity().ifindex,
                            binding.identity().queue_id,
                            req.len,
                            summary,
                        );
                        if n < 5 {
                            let hex_len = (req.len as usize).min(frame_data.len()).min(80);
                            let hex: String = frame_data[..hex_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("RST_DETECT PREP_TX_HEX[{n}]: {hex}");
                        }
                    }
                });
            }
        }
    }
}

mod finalise;
mod rewrite;
mod stage;
mod verify;
mod write;

#[cfg(test)]
#[path = "../transmit_tests.rs"]
mod tests;
