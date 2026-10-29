// Tests for afxdp/cos/queue_ops/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::PROTO_TCP;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::cos::queue_service::ExactCoSScratchBuild;
use crate::afxdp::cos::queue_service::{
    drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair,
    drain_exact_prepared_fifo_items_to_scratch,
    settle_exact_local_fifo_submission, settle_exact_local_scratch_submission_flow_fair,
    settle_exact_prepared_fifo_submission,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::cos_classify::cos_queue_accepts_prepared;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSInterfaceRuntime, CoSQueueConfig, FastMap, FlowRrRing,
    PreparedTxRecycle, PreparedTxRequest, TxRequest,
};
use crate::afxdp::umem::MmapArea;

mod admission;
mod bookkeeping;
mod flow_fair_enable;
mod bench;
mod promotion;
mod cap_aware;
