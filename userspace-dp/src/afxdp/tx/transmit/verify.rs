// #1354 phase split: VERIFY — re-validate every staged frame's UMEM
// slice via the shared (read-only) accessor before reservation. This
// guards against any window where a previous phase mutated state in a
// way that could invalidate the slice bounds.
//
// #15786: drop semantics are PER-FRAME, matching REWRITE — the
// offender alone is removed, recycled + counted via
// `record_prepared_drop` (recording its ORIGINAL position from
// `scratch_prepared_tx_orig_idx` for the CoS pop-snapshot unwind), and
// the valid survivors continue to the ring. The pre-fix code drained
// + recycled EVERY staged entry and returned `Err(Drop)`.

use crate::afxdp::worker::BindingWorker;

use super::{record_prepared_drop, TxDropReason};

#[inline]
pub(super) fn verify_umem_slices_for_staged(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    let mut idx = 0usize;
    while idx < binding.scratch.scratch_prepared_tx.len() {
        let req = &binding.scratch.scratch_prepared_tx[idx];
        let req_offset = req.offset;
        let req_len = req.len;
        if binding
            .umem
            .area()
            .slice(req_offset as usize, req_len as usize)
            .is_none()
        {
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
        }
        idx += 1;
    }
}
