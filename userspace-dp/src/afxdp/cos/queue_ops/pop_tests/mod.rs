// Tests for afxdp/cos/queue_ops/pop.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep pop.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "pop_tests.rs"]` from pop.rs.

// MQFQ + flow-fair ordering tests colocated with pop.rs.
// pop_front_inner is the heart of MQFQ ordering (per-flow finish-
// time tracking, bucket draining, snapshot stack management);
// these tests pin its invariants. Moved here from queue_ops/mod.rs
// per #1034 P5.
use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::cos::admission::{
    cos_flow_aware_buffer_limit, cos_queue_flow_share_limit,
};
use crate::afxdp::cos::queue_ops::{
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all, cos_queue_pop_front, cos_queue_push_back, cos_queue_push_front,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::CoSQueueConfig;

mod ordering;
mod rollback;
mod snapshot_stack;
