// #1354 phase split: WRITE — reserve XSK ring slots, populate XdpDesc
// from staged scratch, commit writer, drop writer, then stamp
// `tx_submit_ns` POST-COMMIT (#812 Codex round-1 HIGH #1 invariant).
// Returns the number of descriptors successfully inserted into and
// committed to the TX ring. Note: this is the ring-level "submitted"
// count, NOT a kernel completion-ring acknowledgement — kernel ack
// arrives later via `reap_tx_completions` against the CQ.
//
// Keeping reserve+write+commit+stamp inside a single function
// preserves the post-commit stamping invariant — the orchestrator
// never gets a chance to drop the live writer borrow at the wrong
// time.

use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::worker::BindingWorker;
use crate::xsk_ffi::xdp::XdpDesc;

use super::super::stats::stamp_submits;

#[inline]
pub(super) fn reserve_and_write_descriptors(binding: &mut BindingWorker) -> u32 {
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
    // #16242: descriptors-per-commit sample for this ring commit.
    crate::afxdp::tx::record_tx_commit(binding, inserted);
    inserted
}
