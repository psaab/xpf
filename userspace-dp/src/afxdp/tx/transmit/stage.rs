// #1354 phase split: STAGE — pop up to TX_BATCH_SIZE prepared TX
// requests from `pending` into `binding.scratch.scratch_prepared_tx`,
// dropping any whose `req.len` exceeds the UMEM frame capacity.
//
// #15786: drop semantics on an oversized request are PER-FRAME — the
// offender alone is recycled + counted via `record_prepared_drop`
// (which also records its ORIGINAL `pending` position for the CoS
// pop-snapshot unwind) and staging CONTINUES with the remaining
// requests. The pre-fix code drained + recycled every already-staged
// valid entry and returned `Err(Drop)`, collaterally destroying up to
// TX_BATCH_SIZE-1 valid packets and orphaning their CoS pop snapshots.
//
// Original positions: `scratch_prepared_tx_orig_idx[i]` is the
// ORIGINAL `pending` position of `scratch_prepared_tx[i]`. An interior
// drop breaks the prefix identity, so later phases index accounting
// through this sidecar (mirrors `transmit_batch`'s `staged_orig_idx`).

use std::collections::VecDeque;

use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::PreparedTxRequest;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::TX_BATCH_SIZE;

use super::{record_prepared_drop, TxDropReason};

#[inline]
pub(super) fn stage_batch_into_scratch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<PreparedTxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    binding.scratch.scratch_prepared_tx_orig_idx = [0; TX_BATCH_SIZE];
    let batch_size = pending.len().min(TX_BATCH_SIZE);
    binding.scratch.scratch_prepared_tx.clear();
    let mut orig_idx: u16 = 0;
    while orig_idx < batch_size as u16 {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if req.len as usize > tx_frame_capacity() {
            record_prepared_drop(
                binding,
                &req,
                orig_idx,
                TxDropReason::PreparedFrameExceedsCapacity {
                    len: req.len,
                    cap: tx_frame_capacity(),
                },
                shared_recycles,
            );
            orig_idx = orig_idx.saturating_add(1);
            continue;
        }
        let stage_pos = binding.scratch.scratch_prepared_tx.len();
        binding.scratch.scratch_prepared_tx_orig_idx[stage_pos] = orig_idx;
        binding.scratch.scratch_prepared_tx.push(req);
        orig_idx = orig_idx.saturating_add(1);
    }
}
