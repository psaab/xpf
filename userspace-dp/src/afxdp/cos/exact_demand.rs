// #9365: the one fold from exact guarantee queues to an exact-demand mask, and
// the one consumer that turns a mask back into a reserved rate.
//
// Two call sites reserve best-effort surplus for exact demand (#hb166 T-6(b)):
// the non-exact batch build in `queue_service` and the send-result settlement
// in `tx_completion`. Each ORs its own mask with the one peer workers publish
// through `SharedCoSExactBacklog`. Before #9365 each file carried its own copy
// of both functions over a `u64`, with the same broken past-index-63 arms; see
// `ExactDemandQueueMask` for that defect and for the overflow policy.

use crate::afxdp::types::{CoSInterfaceRuntime, ExactDemandQueueMask};

use super::queue_ops::cos_exact_queue_demands_reservation;

/// Mask of the exact guarantee queues that DEMAND their reserved rate:
/// backlogged, with their own token bucket covering the head
/// (`cos_exact_queue_demands_reservation`). A queue limited by itself (empty,
/// parked on its own queue tokens, or v8-starved) releases its rate to
/// best-effort (#hb166 T-6(b)); a queue short only of ROOT tokens, including
/// one parked on root, keeps it (#18748), because the root is what the
/// reservation protects and dropping it there starved the exact class and the
/// non-exact queue on its worker. Used for the local reservation and published
/// for peer workers by `publish_cos_exact_backlog`.
#[inline]
pub(in crate::afxdp) fn local_exact_demand_mask(
    root: &CoSInterfaceRuntime,
) -> ExactDemandQueueMask {
    root.queues
        .iter()
        .enumerate()
        .filter(|(_, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && cos_exact_queue_demands_reservation(queue)
        })
        .fold(ExactDemandQueueMask::EMPTY, |mask, (queue_idx, _)| {
            mask.with_queue(queue_idx)
        })
}

/// Sum of the guarantee rates of the exact queues `mask` counts.
#[inline]
pub(in crate::afxdp) fn exact_demand_rate_bytes_for_mask(
    root: &CoSInterfaceRuntime,
    mask: ExactDemandQueueMask,
) -> u64 {
    if mask.is_empty() {
        return 0;
    }
    root.queues
        .iter()
        .enumerate()
        .filter(|(queue_idx, queue)| {
            queue.config.exact && queue.config.guarantee_enabled && mask.counts(*queue_idx)
        })
        .fold(0u64, |acc, (_, queue)| {
            acc.saturating_add(queue.transmit_rate_bytes())
        })
}
