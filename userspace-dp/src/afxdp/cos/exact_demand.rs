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

use super::queue_ops::cos_exact_queue_serviceable;

/// Mask of the exact guarantee queues that are SERVICEABLE right now: runnable,
/// non-empty, and with root and queue tokens covering the head. A v8-starved or
/// token-parked exact class ships zero bytes and must release its reserved rate
/// to best-effort, so non-emptiness alone does not count. Used for the local
/// reservation and published for peer workers by `publish_cos_exact_backlog`.
#[inline]
pub(in crate::afxdp) fn serviceable_exact_demand_mask(
    root: &CoSInterfaceRuntime,
) -> ExactDemandQueueMask {
    let root_tokens = root.tokens;
    root.queues
        .iter()
        .enumerate()
        .filter(|(_, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && cos_exact_queue_serviceable(root_tokens, queue)
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
