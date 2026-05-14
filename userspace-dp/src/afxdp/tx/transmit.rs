// XSK TX-ring submit + per-frame recycle. Single-writer (owner
// worker); atomic ops use `Ordering::Relaxed`.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{apply_dscp_rewrite_to_frame, decode_frame_summary, frame_has_tcp_rst};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{FastMap, PreparedTxRecycle, PreparedTxRequest, TxRequest};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{TX_BATCH_SIZE, tx_frame_capacity};
use crate::xsk_ffi::xdp::XdpDesc;

use super::rings::{maybe_wake_tx, reap_tx_completions};
use super::stats::stamp_submits;

pub(in crate::afxdp) enum TxError {
    Retry(String),
    Drop(String),
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
            free_tx_frames.push_back(recycle_offset);
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
    req: &PreparedTxRequest,
) {
    if req.recycle.fill_slot().is_some() {
        in_flight_prepared_recycles.insert(req.offset, req.recycle);
    }
}

pub(in crate::afxdp) fn transmit_batch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
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
        return Err(TxError::Retry("no free TX frame available".to_string()));
    }

    binding.scratch.scratch_local_tx.clear();
    while binding.scratch.scratch_local_tx.len() < batch_size {
        let Some(mut req) = pending.pop_front() else {
            break;
        };
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            // Unwind already-prepared entries before returning.
            for (off, r) in binding.scratch.scratch_local_tx.drain(..) {
                binding.tx_pipeline.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(format!(
                "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.bytes.len(),
                tx_frame_capacity()
            )));
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
            // Unwind already-prepared entries before returning.
            for (off, r) in binding.scratch.scratch_local_tx.drain(..) {
                binding.tx_pipeline.free_tx_frames.push_back(off);
                pending.push_front(r);
            }
            return Err(TxError::Drop(format!(
                "tx frame slice out of range: offset={offset} len={}",
                req.bytes.len()
            )));
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
        binding.scratch.scratch_local_tx.push((offset, req));
    }

    if binding.scratch.scratch_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry("no prepared TX frame available".to_string()));
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
        return Err(TxError::Retry("tx ring insert failed".to_string()));
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, (offset, req)) in binding.scratch.scratch_local_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
        } else {
            binding.tx_pipeline.free_tx_frames.push_front(offset);
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
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

pub(in crate::afxdp) fn transmit_prepared_queue(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    let batch_size = pending.len().min(TX_BATCH_SIZE);
    binding.scratch.scratch_prepared_tx.clear();
    while binding.scratch.scratch_prepared_tx.len() < batch_size {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if req.len as usize > tx_frame_capacity() {
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            recycle_prepared_immediately_with_shared(binding, &req, Some(shared_recycles));
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: each orphan is a silently-recycled packet that will
            // not reach the TX ring. The caller's post-return `+= 1`
            // covers the offender (`req`); this accounts for the
            // orphans so `tx_submit_error_drops` matches the actual
            // packet count lost on this Drop return.
            if !orphaned.is_empty() {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphaned.len() as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.len,
                tx_frame_capacity()
            )));
        }
        binding.scratch.scratch_prepared_tx.push(req);
    }
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    for req in &binding.scratch.scratch_prepared_tx {
        let Some(dscp_rewrite) = req.dscp_rewrite else {
            continue;
        };
        let Some(frame) = (unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(req.offset as usize, req.len as usize)
        }) else {
            let err_offset = req.offset;
            let err_len = req.len;
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: each orphan is a silently-recycled packet. Caller
            // will `+= 1` for the offender; this accounts for the rest.
            let orphan_count = orphaned.len();
            if orphan_count > 0 {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        };
        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
    }
    for req in &binding.scratch.scratch_prepared_tx {
        if binding
            .umem
            .area()
            .slice(req.offset as usize, req.len as usize)
            .is_none()
        {
            let err_offset = req.offset;
            let err_len = req.len;
            let orphaned: Vec<_> = binding.scratch.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_prepared_immediately_with_shared(binding, r, Some(shared_recycles));
            }
            // #710: same shape as the slice_mut_unchecked site above —
            // `orphaned` drains EVERY entry including the offender.
            // Caller adds 1 for the offender; we add (len-1) for the
            // rest so `tx_submit_error_drops` matches the actual count.
            let orphan_count = orphaned.len();
            if orphan_count > 0 {
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
                binding
                    .live
                    .tx_errors
                    .fetch_add(orphan_count.saturating_sub(1) as u64, Ordering::Relaxed);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        }
    }

    // RST detection on prepared TX path: check UMEM frames before submitting to TX ring
    if cfg!(feature = "debug-log") {
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

    let mut writer = binding
        .xsk
        .tx
        .transmit(binding.scratch.scratch_prepared_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch
            .scratch_prepared_tx
            .iter()
            .map(|req| XdpDesc {
                addr: req.offset,
                len: req.len,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);
    // #940: NO V_min publish here. transmit_prepared_queue is the
    // post-CoS backup path; operates on
    // `pending: VecDeque<PreparedTxRequest>` directly, never
    // advances any queue_vtime. V_min applies only to traffic
    // that flowed through a shared_exact CoS queue.
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the transmit_prepared_queue
    // continuation variant). Post-commit stamping ensures we measure
    // kernel-visible submit time, not the pre-submit planning window.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_pipeline.tx_submit_ns,
        binding
            .scratch
            .scratch_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );

    if inserted == 0 {
        binding.telemetry.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some(req) = binding.scratch.scratch_prepared_tx.pop() {
            pending.push_front(req);
        }
        return Err(TxError::Retry("prepared tx ring insert failed".to_string()));
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, req) in binding.scratch.scratch_prepared_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            remember_prepared_recycle(&mut binding.tx_pipeline.in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += req.len as u64;
        } else {
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
    }

    // Prepared cross-binding forwards need the same explicit TX kick.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

#[cfg(test)]
#[path = "transmit_tests.rs"]
mod tests;
