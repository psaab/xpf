// Cross-binding redirect: routes a TX request to the owner binding
// of the egress (or hands off via MPSC inbox) for both Local and
// Prepared variants.
//
// Back-edge to `tx::recycle_prepared_immediately_with_shared`: prepared
// redirects copy the frame into the owner binding and then release
// the source UMEM frame on this binding.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::afxdp::tx::recycle_prepared_immediately_with_shared;
use crate::afxdp::types::{
    PreparedTxRequest, TxRequest, WorkerCommand, WorkerCoSInterfaceFastPath,
    WorkerCoSQueueFastPath,
};
use crate::afxdp::umem::BindingLiveState;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::FastMap;

/// #780: Step 1 action variants. Mirrors the action taken inside
/// `redirect_local_cos_request_to_owner` after the bail checks
/// have been passed.
#[derive(Clone)]
pub(in crate::afxdp) enum Step1Action {
    /// The owner worker's owner_live arc is directly addressable
    /// (fast path).
    Arc(Arc<BindingLiveState>),
    /// Fall back to the per-worker command channel (slow path).
    Command(u32),
}

/// #780: routing-decision cache value. Carries BOTH Step 1 and
/// Step 2 options so the dispatch in `ingest_cos_pending_tx_with_provenance`
/// can fall through Step 1 → Step 2 → Step 3 (EnqueueLocal) on
/// Err at each boundary — exact cascade semantics of the
/// pre-#780 three-function chain. Codex review round 2 flagged
/// the previous revision's lack of fallthrough as a HIGH
/// semantic regression.
#[derive(Clone)]
pub(in crate::afxdp) struct LocalRoutingDecision {
    /// `None` when Step 1 bails (queue absent, shared_exact-with-
    /// owner, or owner_worker_id == current_worker_id). Present
    /// when Step 1 would route.
    pub(in crate::afxdp) step1: Option<Step1Action>,
    /// `None` when Step 2 bails (iface absent, no tx_owner_live,
    /// or ptr_eq(tx_owner_live, current_live)). Present when
    /// Step 2 would route.
    pub(in crate::afxdp) step2: Option<Arc<BindingLiveState>>,
}

/// #780: resolve the routing decision for a (iface, queue) pair.
/// Preserves the exact pre-#780 cascade semantics. Moved out of
/// the closure so it can be unit-tested independently. Carries
/// BOTH step options in the returned decision so dispatch can
/// walk the same fallthrough as the original cascade when an
/// earlier step's enqueue returns Err.
#[inline]
pub(in crate::afxdp) fn resolve_local_routing_decision(
    iface_fast_opt: Option<&WorkerCoSInterfaceFastPath>,
    cos_queue_id: Option<u8>,
    current_worker_id: u32,
    current_live: &Arc<BindingLiveState>,
) -> LocalRoutingDecision {
    let mut step1: Option<Step1Action> = None;
    let mut step2: Option<Arc<BindingLiveState>> = None;
    if let Some(iface_fast) = iface_fast_opt {
        // Step 1 (mirrors redirect_local_cos_request_to_owner):
        if let Some(queue_fast) = iface_fast.queue_fast_path(cos_queue_id) {
            let step1_bail = (queue_fast.shared_exact && iface_fast.tx_owner_live.is_some())
                || queue_fast.owner_worker_id == current_worker_id;
            if !step1_bail {
                step1 = Some(match queue_fast.owner_live.as_ref() {
                    Some(arc) => Step1Action::Arc(arc.clone()),
                    None => Step1Action::Command(queue_fast.owner_worker_id),
                });
            }
        }
        // Step 2 (mirrors redirect_local_cos_request_to_owner_binding):
        // ALWAYS evaluated — the old cascade ran Step 2 after Step 1
        // returned Err, so Step 2 is reachable whether or not Step 1
        // also routes. We cache both here; the dispatch loop walks
        // Step 1 first, falling through to Step 2 on Err.
        if let Some(owner_live) = iface_fast.tx_owner_live.as_ref() {
            if !Arc::ptr_eq(owner_live, current_live) {
                step2 = Some(owner_live.clone());
            }
        }
    }
    LocalRoutingDecision { step1, step2 }
}

#[inline]
pub(in crate::afxdp) fn cos_fast_interface<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
) -> Option<&'a WorkerCoSInterfaceFastPath> {
    cos_fast_interfaces.get(&egress_ifindex)
}

#[inline]
pub(in crate::afxdp) fn cos_fast_queue<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<(&'a WorkerCoSInterfaceFastPath, &'a WorkerCoSQueueFastPath)> {
    let iface = cos_fast_interface(cos_fast_interfaces, egress_ifindex)?;
    let queue = iface.queue_fast_path(requested_queue_id)?;
    Some((iface, queue))
}

#[inline]
pub(in crate::afxdp) fn redirect_local_cos_request_to_owner(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    req: TxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> Result<(), TxRequest> {
    let Some((iface_fast, queue_fast)) =
        cos_fast_queue(cos_fast_interfaces, req.egress_ifindex, req.cos_queue_id)
    else {
        return Err(req);
    };
    if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() {
        return Err(req);
    }
    let owner_worker_id = queue_fast.owner_worker_id;
    if owner_worker_id == current_worker_id {
        return Err(req);
    }
    if let Some(owner_live) = queue_fast.owner_live.as_ref() {
        return owner_live.enqueue_tx_owned(req);
    }
    let Some(commands) = worker_commands_by_id.get(&owner_worker_id) else {
        return Err(req);
    };
    if let Ok(mut pending) = commands.lock() {
        pending.push_back(WorkerCommand::EnqueueShapedLocal(req));
        return Ok(());
    }
    Err(req)
}
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn redirect_local_cos_request_to_owner_binding(
    current_live: &Arc<BindingLiveState>,
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    req: TxRequest,
) -> Result<(), TxRequest> {
    // Caller ordering matters: shared exact queues that already have a local TX
    // path were filtered out in redirect_local_cos_request_to_owner().
    let Some(iface_fast) = cos_fast_interface(cos_fast_interfaces, req.egress_ifindex) else {
        return Err(req);
    };
    let Some(owner_live) = iface_fast.tx_owner_live.as_ref() else {
        return Err(req);
    };
    if Arc::ptr_eq(owner_live, current_live) {
        return Err(req);
    }
    owner_live.enqueue_tx_owned(req)
}

#[inline]
pub(in crate::afxdp) fn prepared_cos_request_stays_on_current_tx_binding(
    binding_ifindex: i32,
    iface_fast: &WorkerCoSInterfaceFastPath,
    queue_fast: &WorkerCoSQueueFastPath,
) -> bool {
    binding_ifindex == iface_fast.tx_ifindex && queue_fast.shared_exact
}

#[inline]
pub(in crate::afxdp) fn redirect_prepared_cos_request_to_owner(
    binding: &mut BindingWorker,
    req: PreparedTxRequest,
    current_worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), PreparedTxRequest> {
    let Some((iface_fast, queue_fast)) = cos_fast_queue(
        &binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) else {
        return Err(req);
    };
    if queue_fast.shared_exact && iface_fast.tx_owner_live.is_some() {
        return Err(req);
    }
    let owner_worker_id = queue_fast.owner_worker_id;
    if owner_worker_id == current_worker_id {
        return Err(req);
    }
    let Some(frame) = binding
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .map(|frame| frame.to_vec())
    else {
        return Err(req);
    };
    let local_req = TxRequest {
        bytes: frame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key.clone(),
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
        mirror_clone: false,
    };
    if redirect_local_cos_request_to_owner(
        &binding.cos.cos_fast_interfaces,
        local_req,
        current_worker_id,
        worker_commands_by_id,
    )
    .is_ok()
    {
        recycle_prepared_immediately_with_shared(binding, &req, shared_recycles);
        return Ok(());
    }
    Err(req)
}

#[inline]
pub(in crate::afxdp) fn redirect_prepared_cos_request_to_owner_binding(
    binding: &mut BindingWorker,
    req: PreparedTxRequest,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), PreparedTxRequest> {
    let Some((iface_fast, queue_fast)) = cos_fast_queue(
        &binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) else {
        return Err(req);
    };
    // Keep shared exact traffic on the current binding when it already sits on
    // the resolved TX path; redirecting it sideways would force a copy back
    // into local TX instead of preserving the prepared path.
    if prepared_cos_request_stays_on_current_tx_binding(binding.ifindex, iface_fast, queue_fast) {
        return Err(req);
    }
    let Some(owner_live) = iface_fast.tx_owner_live.as_ref() else {
        return Err(req);
    };
    if Arc::ptr_eq(owner_live, &binding.live) {
        return Err(req);
    }
    let Some(frame) = binding
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .map(|frame| frame.to_vec())
    else {
        return Err(req);
    };
    let local_req = TxRequest {
        bytes: frame,
        expected_ports: req.expected_ports,
        expected_addr_family: req.expected_addr_family,
        expected_protocol: req.expected_protocol,
        flow_key: req.flow_key.clone(),
        egress_ifindex: req.egress_ifindex,
        cos_queue_id: req.cos_queue_id,
        dscp_rewrite: req.dscp_rewrite,
        mirror_clone: false,
    };
    if owner_live.enqueue_tx(local_req).is_ok() {
        recycle_prepared_immediately_with_shared(binding, &req, shared_recycles);
        return Ok(());
    }
    Err(req)
}

#[cfg(test)]
#[path = "cross_binding_tests.rs"]
mod tests;
