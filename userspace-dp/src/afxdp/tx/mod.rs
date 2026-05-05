use super::*;

pub(super) mod stats;
pub(in crate::afxdp) use stats::stamp_submits;
#[cfg(test)]
pub(in crate::afxdp) use stats::{record_kick_latency, record_tx_completions_with_stamp};

pub(super) mod rings;
pub(in crate::afxdp) use rings::{maybe_wake_tx, reap_tx_completions};
pub(super) use rings::{drain_pending_fill, maybe_wake_rx};

pub(super) mod transmit;
pub(in crate::afxdp) use transmit::{
    recycle_cancelled_prepared_offset, recycle_prepared_immediately, remember_prepared_recycle,
    transmit_batch, transmit_prepared_queue, TxError,
};
use transmit::transmit_prepared_batch;

pub(super) mod drain;
pub(super) use drain::{
    bound_pending_tx_local, bound_pending_tx_prepared, drain_pending_tx,
    drain_pending_tx_local_owner, pending_tx_capacity,
};
pub(in crate::afxdp) use drain::{
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES, COS_GUARANTEE_VISIT_NS,
    COS_SURPLUS_ROUND_QUANTUM_BYTES,
};

pub(super) mod cos_classify;
pub(super) mod dispatch;
pub(super) mod tcp_segmentation;
pub(super) use cos_classify::{
    enqueue_local_into_cos, resolve_cached_cos_tx_selection, resolve_cos_queue_id,
    resolve_cos_tx_selection, CoSTxSelection,
};
pub(in crate::afxdp) use cos_classify::cos_queue_dscp_rewrite;
// Private use, not a re-export: a `pub(super) use` of a `pub(super)`
// item triggers E0364. drain.rs reaches this through `use super::*;`.
use cos_classify::enqueue_prepared_into_cos;

#[cfg(test)]
pub(in crate::afxdp) mod test_support;

use super::cos::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit, cos_flow_bucket_index,
    cos_item_flow_key, cos_queue_drain_all, cos_queue_flow_share_limit, cos_queue_is_empty,
    cos_queue_push_back, cos_queue_restore_front, drain_shaped_tx, ensure_cos_interface_runtime,
    mark_cos_queue_runnable, publish_committed_queue_vtime, redirect_prepared_cos_request_to_owner,
    redirect_prepared_cos_request_to_owner_binding, resolve_local_routing_decision,
    LocalRoutingDecision, Step1Action,
};
#[cfg(test)]
use super::cos::COS_MIN_BURST_BYTES;
