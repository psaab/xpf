// #1354 phase split: REWRITE — iterate `scratch_prepared_tx` and
// apply per-frame DSCP rewrite mutations to the UMEM frame slice.
//
// #15786: drop semantics on slice-out-of-range are PER-FRAME — the
// offender alone is removed from the staged batch, recycled + counted
// via `record_prepared_drop` (recording its ORIGINAL position from
// `scratch_prepared_tx_orig_idx` for the CoS pop-snapshot unwind), and
// the valid survivors continue to verify/write. The pre-fix code
// drained + recycled EVERY staged entry and returned `Err(Drop)`.

use crate::afxdp::frame::apply_dscp_rewrite_to_frame;
use crate::afxdp::worker::BindingWorker;

use super::{record_prepared_drop, TxDropReason};

#[inline]
pub(super) fn apply_dscp_rewrites_to_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    let mut idx = 0usize;
    while idx < binding.scratch.scratch_prepared_tx.len() {
        let req = &binding.scratch.scratch_prepared_tx[idx];
        let Some(dscp_rewrite) = req.dscp_rewrite else {
            idx += 1;
            continue;
        };
        let req_offset = req.offset;
        let req_len = req.len;
        let frame = unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(req_offset as usize, req_len as usize)
        };
        let Some(frame) = frame else {
            let orig_idx = binding.scratch.scratch_prepared_tx_orig_idx[idx];
            let req = binding.scratch.scratch_prepared_tx.remove(idx);
            let staged_len = binding.scratch.scratch_prepared_tx.len();
            binding
                .scratch
                .scratch_prepared_tx_orig_idx
                .copy_within(idx + 1..=staged_len, idx);
            record_prepared_drop(
                binding,
                &req,
                orig_idx,
                TxDropReason::PreparedSliceOutOfRange {
                    offset: req_offset,
                    len: req_len,
                },
                shared_recycles,
            );
            continue;
        };
        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
        idx += 1;
    }
}
