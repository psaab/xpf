// Tests for afxdp/cos/queue_service/mod.rs. Split from a single 4384-line
// tests.rs into per-concern sibling submodules (#4665) to keep each file
// under the modularity-discipline LOC threshold. Pure test-code motion: no
// production code and no test logic changed. Shared imports, the epoch
// constant, and the cross-concern `waterfill_guarantee_rate_root` fixture
// live here and reach every submodule via `use super::*`.
//
// Submodules by concern (see each file's header):
//   selector  drain  wakeup  waterfill  sojourn  refund  submit
//   demand_mask_9365 (the exact-demand mask past queue index 64)

use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::FastMap;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::cos::queue_ops::cos_queue_push_back;
use crate::afxdp::cos::tx_completion::COS_TIMER_WHEEL_TICK_NS;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{
    CoSQueueWaterfillCounters, ExactDemandQueueMask, SharedCoSExactBacklog, SharedCoSQueueLease,
    SharedCoSRootLease, V8RateMode, WorkerCoSInterfaceFastPath,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{PROTO_TCP, UMEM_FRAME_SHIFT};
use std::sync::Arc;
// Relocated from a mid-file `use` that sat beside the drain TX-progress
// tests in the pre-split tests.rs (verbatim).
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSQueueConfig, CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing,
};

const TEST_EPOCH_DURATION_NS: u64 = 200_000;

/// Build a GuaranteeRate root with the ascending-by-rate vec populated
/// and every exact queue given abundant per-queue tokens so the only
/// gate is the Phase-1 byte budget.
fn waterfill_guarantee_rate_root(frac: f64) -> CoSInterfaceRuntime {
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = frac;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    root
}

mod selector;
mod drain;
mod wakeup;
mod waterfill;
mod sojourn;
mod refund;
mod submit;
mod demand_mask_9365;
