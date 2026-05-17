// CoS classification: maps a packet's policy/filter/classifier
// signals to a CoS queue id and an optional DSCP rewrite, then
// enqueues onto the chosen queue. Single-writer (owner worker);
// atomic ops use `Ordering::Relaxed`.

use super::*;
use crate::afxdp::mirror::MIRROR_TX_FRAME_RESERVE;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSTxSelection {
    pub(in crate::afxdp) queue_id: Option<u8>,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    pub(in crate::afxdp) drop: bool,
}

fn map_cached_forwarding_class_queue(
    iface: &CoSInterfaceConfig,
    forwarding_class: Option<&Arc<str>>,
) -> Option<u8> {
    forwarding_class.and_then(|class| iface.queue_by_forwarding_class.get(class.as_ref()).copied())
}

pub(in crate::afxdp) fn resolve_cached_cos_tx_selection(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: UserspaceDpMeta,
    flow_key: Option<&SessionKey>,
) -> CachedTxSelectionDescriptor {
    let iface = forwarding.cos.interfaces.get(&egress_ifindex);
    let Some(flow_key) = flow_key else {
        return CachedTxSelectionDescriptor {
            queue_id: iface.map(|iface| iface.default_queue),
            dscp_rewrite: None,
            filter_counter: None,
            three_color_policers: Vec::new(),
        };
    };

    let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
    let has_output_tx_eval = crate::filter::interface_output_filter_needs_tx_eval(
        &forwarding.filter_state,
        egress_ifindex,
        is_v6,
    );
    let has_input_tx_selection =
        crate::filter::filter_state_has_input_tx_selection(&forwarding.filter_state, is_v6);
    let has_input_three_color_policer =
        crate::filter::filter_state_has_input_three_color_policer(&forwarding.filter_state, is_v6);
    if iface.is_none()
        && !has_output_tx_eval
        && !has_input_tx_selection
        && !has_input_three_color_policer
    {
        return CachedTxSelectionDescriptor::default();
    }
    let output_filter = if has_output_tx_eval {
        if is_v6 {
            forwarding
                .filter_state
                .iface_filter_out_v6_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_out_v4_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        }
    } else {
        None
    };
    let output_result = output_filter
        .filter(|filter| {
            filter.affects_tx_selection
                || filter.has_counter_terms
                || filter.has_three_color_policer_terms
        })
        .map(|filter| {
            crate::filter::evaluate_filter_ref_tx_selection_cached(
                filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
            )
        })
        .unwrap_or_default();

    let mut effective_dscp_rewrite = output_result.dscp_rewrite;
    let mut forwarding_class = output_result.forwarding_class.clone();
    let mut filter_counter = output_result.counter.clone();
    let mut three_color_policers = output_result.three_color_policers;

    if (output_filter.is_none() && has_input_tx_selection) || has_input_three_color_policer {
        let ingress_ifindex = resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        let ingress_filter = if is_v6 {
            forwarding
                .filter_state
                .iface_filter_v6_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_v4_fast
                .get(&ingress_ifindex)
                .map(Arc::as_ref)
        };
        if let Some(ingress_filter) = ingress_filter.filter(|filter| {
            (output_filter.is_none() && filter.affects_tx_selection)
                || filter.has_three_color_policer_terms
        }) {
            let ingress_result = crate::filter::evaluate_filter_ref_tx_selection_cached(
                ingress_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
            );
            effective_dscp_rewrite = effective_dscp_rewrite.or(ingress_result.dscp_rewrite);
            if output_filter.is_none() {
                forwarding_class = ingress_result.forwarding_class;
                filter_counter = ingress_result.counter;
            }
            three_color_policers.extend(ingress_result.three_color_policers);
        }
    }

    let queue_id = iface.and_then(|iface| {
        map_cached_forwarding_class_queue(iface, forwarding_class.as_ref())
            .or_else(|| resolve_cos_dscp_classifier_queue_id(iface, meta.dscp))
            .or_else(|| {
                resolve_cos_ieee8021_classifier_queue_id(
                    iface,
                    meta.ingress_pcp,
                    meta.ingress_vlan_present != 0,
                )
            })
            .or(Some(iface.default_queue))
    });

    CachedTxSelectionDescriptor {
        queue_id,
        dscp_rewrite: effective_dscp_rewrite,
        filter_counter,
        three_color_policers,
    }
}

pub(in crate::afxdp) fn resolve_cos_queue_id(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cos_tx_selection(forwarding, egress_ifindex, meta, flow_key).queue_id
}

pub(in crate::afxdp) fn resolve_cos_tx_selection(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
) -> CoSTxSelection {
    resolve_cos_tx_selection_internal(forwarding, egress_ifindex, meta, flow_key, None)
}

pub(in crate::afxdp) fn resolve_cos_tx_selection_at(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
    now_ns: u64,
) -> CoSTxSelection {
    resolve_cos_tx_selection_internal(forwarding, egress_ifindex, meta, flow_key, Some(now_ns))
}

fn resolve_cos_tx_selection_internal(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    meta: impl Into<ForwardPacketMeta>,
    flow_key: Option<&SessionKey>,
    now_ns: Option<u64>,
) -> CoSTxSelection {
    let meta = meta.into();
    let tx_selection_enabled = if meta.addr_family as i32 == libc::AF_INET6 {
        forwarding.tx_selection_enabled_v6
    } else {
        forwarding.tx_selection_enabled_v4
    };
    if !tx_selection_enabled {
        return CoSTxSelection::default();
    }
    let iface = forwarding.cos.interfaces.get(&egress_ifindex);
    let Some(flow_key) = flow_key else {
        return CoSTxSelection {
            queue_id: iface.map(|iface| iface.default_queue),
            dscp_rewrite: None,
            drop: false,
        };
    };
    let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
    let has_output_tx_eval = crate::filter::interface_output_filter_needs_tx_eval(
        &forwarding.filter_state,
        egress_ifindex,
        is_v6,
    );
    let has_input_tx_selection =
        crate::filter::filter_state_has_input_tx_selection(&forwarding.filter_state, is_v6);
    let has_input_three_color_policer =
        crate::filter::filter_state_has_input_three_color_policer(&forwarding.filter_state, is_v6);
    if iface.is_none()
        && !has_output_tx_eval
        && !has_input_tx_selection
        && !has_input_three_color_policer
    {
        return CoSTxSelection {
            queue_id: None,
            dscp_rewrite: None,
            drop: false,
        };
    }
    let output_filter = if has_output_tx_eval {
        if is_v6 {
            forwarding
                .filter_state
                .iface_filter_out_v6_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        } else {
            forwarding
                .filter_state
                .iface_filter_out_v4_fast
                .get(&egress_ifindex)
                .map(Arc::as_ref)
        }
    } else {
        None
    };
    let has_output_filter = output_filter.is_some();
    let ingress_ifindex =
        if (!has_output_filter && has_input_tx_selection) || has_input_three_color_policer {
            resolve_ingress_logical_ifindex(
                forwarding,
                meta.ingress_ifindex as i32,
                meta.ingress_vlan_id,
            )
            .unwrap_or(meta.ingress_ifindex as i32)
        } else {
            0
        };
    let ingress_filter =
        if (!has_output_filter && has_input_tx_selection) || has_input_three_color_policer {
            if is_v6 {
                forwarding
                    .filter_state
                    .iface_filter_v6_fast
                    .get(&ingress_ifindex)
                    .map(Arc::as_ref)
            } else {
                forwarding
                    .filter_state
                    .iface_filter_v4_fast
                    .get(&ingress_ifindex)
                    .map(Arc::as_ref)
            }
        } else {
            None
        };
    let output_result = if let Some(output_filter) = output_filter.filter(|filter| {
        filter.affects_tx_selection
            || filter.has_counter_terms
            || filter.has_three_color_policer_terms
    }) {
        if let Some(now_ns) = now_ns {
            crate::filter::evaluate_filter_ref_tx_selection_runtime_counted(
                output_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
                meta.pkt_len as u64,
                now_ns,
            )
        } else {
            crate::filter::evaluate_filter_ref_tx_selection_counted(
                output_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
                meta.pkt_len as u64,
            )
        }
    } else {
        crate::filter::TxSelectionFilterResult::default()
    };
    let mut effective_dscp_rewrite = output_result.dscp_rewrite;
    let mut policer_drop = output_result.policer_drop;
    let mut ingress_forwarding_class = None;
    if let Some(ingress_filter) = ingress_filter.filter(|filter| {
        (!has_output_filter && filter.affects_tx_selection) || filter.has_three_color_policer_terms
    }) {
        let ingress_result = if let Some(now_ns) = now_ns {
            crate::filter::evaluate_filter_ref_tx_selection_runtime_counted(
                ingress_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
                meta.pkt_len as u64,
                now_ns,
            )
        } else {
            crate::filter::evaluate_filter_ref_tx_selection_counted(
                ingress_filter,
                flow_key.src_ip,
                flow_key.dst_ip,
                flow_key.protocol,
                flow_key.src_port,
                flow_key.dst_port,
                meta.dscp,
                meta.pkt_len as u64,
            )
        };
        effective_dscp_rewrite = effective_dscp_rewrite.or(ingress_result.dscp_rewrite);
        policer_drop |= ingress_result.policer_drop;
        if !has_output_filter {
            ingress_forwarding_class = ingress_result.forwarding_class;
        }
    }
    let Some(iface) = iface else {
        return CoSTxSelection {
            queue_id: None,
            dscp_rewrite: effective_dscp_rewrite,
            drop: policer_drop,
        };
    };
    if let Some(forwarding_class) = output_result.forwarding_class {
        if let Some(queue_id) = iface.queue_by_forwarding_class.get(forwarding_class) {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
                drop: policer_drop,
            };
        }
    }
    if let Some(forwarding_class) = ingress_forwarding_class {
        if let Some(queue_id) = iface.queue_by_forwarding_class.get(forwarding_class) {
            return CoSTxSelection {
                queue_id: Some(*queue_id),
                dscp_rewrite: effective_dscp_rewrite,
                drop: policer_drop,
            };
        }
    }
    if let Some(queue_id) = resolve_cos_dscp_classifier_queue_id(iface, meta.dscp) {
        return CoSTxSelection {
            queue_id: Some(queue_id),
            dscp_rewrite: effective_dscp_rewrite,
            drop: policer_drop,
        };
    }
    if let Some(queue_id) = resolve_cos_ieee8021_classifier_queue_id(
        iface,
        meta.ingress_pcp,
        meta.ingress_vlan_present != 0,
    ) {
        return CoSTxSelection {
            queue_id: Some(queue_id),
            dscp_rewrite: effective_dscp_rewrite,
            drop: policer_drop,
        };
    }
    CoSTxSelection {
        queue_id: Some(iface.default_queue),
        dscp_rewrite: effective_dscp_rewrite,
        drop: policer_drop,
    }
}

fn resolve_cos_dscp_classifier_queue_id(iface: &CoSInterfaceConfig, dscp: u8) -> Option<u8> {
    let queue_id = iface.dscp_queue_by_dscp[usize::from(dscp & 0x3f)];
    (queue_id != u8::MAX).then_some(queue_id)
}

fn resolve_cos_ieee8021_classifier_queue_id(
    iface: &CoSInterfaceConfig,
    pcp: u8,
    vlan_present: bool,
) -> Option<u8> {
    if !vlan_present {
        return None;
    }
    let queue_id = iface.ieee8021_queue_by_pcp[usize::from(pcp.min(7))];
    (queue_id != u8::MAX).then_some(queue_id)
}

pub(in crate::afxdp) fn enqueue_local_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: TxRequest,
    now_ns: u64,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), TxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding
        .cos
        .cos_interfaces
        .get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        match prepare_local_request_for_cos(
            binding.umem.area(),
            &mut binding.tx_pipeline.free_tx_frames,
            req,
        ) {
            Ok(prepared_req) => {
                let item_len = prepared_req.len as u64;
                match enqueue_cos_item(
                    binding,
                    egress_ifindex,
                    prepared_req.cos_queue_id,
                    item_len,
                    CoSPendingTxItem::Prepared(prepared_req),
                    shared_recycles.as_deref_mut(),
                ) {
                    Ok(()) => return Ok(()),
                    Err(CoSPendingTxItem::Prepared(prepared_req)) => {
                        let req =
                            clone_prepared_request_for_cos(binding.umem.area(), &prepared_req)
                                .expect("prepared CoS fallback clone");
                        recycle_prepared_immediately_with_shared(
                            binding,
                            &prepared_req,
                            shared_recycles.as_deref_mut(),
                        );
                        let item_len = req.bytes.len() as u64;
                        return match enqueue_cos_item(
                            binding,
                            egress_ifindex,
                            req.cos_queue_id,
                            item_len,
                            CoSPendingTxItem::Local(req),
                            shared_recycles.as_deref_mut(),
                        ) {
                            Ok(()) => Ok(()),
                            Err(CoSPendingTxItem::Local(req)) => Err(req),
                            Err(CoSPendingTxItem::Prepared(_)) => {
                                unreachable!("local request returned prepared item")
                            }
                        };
                    }
                    Err(CoSPendingTxItem::Local(_)) => {
                        unreachable!("local request prepared into prepared item")
                    }
                }
            }
            Err(req) => {
                // Fall through to the local CoS path when no TX frame is
                // available or the request cannot be materialized safely.
                let area = binding.umem.area();
                let slot = binding.slot;
                if let Some(root) = binding.cos.cos_interfaces.get_mut(&egress_ifindex) {
                    let _ = demote_prepared_cos_queue_to_local(
                        area,
                        &mut binding.tx_pipeline.free_tx_frames,
                        &mut binding.tx_pipeline.pending_fill_frames,
                        slot,
                        root,
                        req.cos_queue_id,
                        shared_recycles.as_deref_mut(),
                    );
                }
                let req = req;
                let item_len = req.bytes.len() as u64;
                return match enqueue_cos_item(
                    binding,
                    egress_ifindex,
                    req.cos_queue_id,
                    item_len,
                    CoSPendingTxItem::Local(req),
                    shared_recycles.as_deref_mut(),
                ) {
                    Ok(()) => Ok(()),
                    Err(CoSPendingTxItem::Local(req)) => Err(req),
                    Err(CoSPendingTxItem::Prepared(_)) => {
                        unreachable!("local request returned prepared item")
                    }
                };
            }
        }
    }
    let item_len = req.bytes.len() as u64;
    match enqueue_cos_item(
        binding,
        egress_ifindex,
        req.cos_queue_id,
        item_len,
        CoSPendingTxItem::Local(req),
        shared_recycles.as_deref_mut(),
    ) {
        Ok(()) => Ok(()),
        Err(CoSPendingTxItem::Local(req)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => unreachable!("local request returned prepared item"),
    }
}

pub(super) fn prepare_local_request_for_cos(
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    req: TxRequest,
) -> Result<PreparedTxRequest, TxRequest> {
    if req.bytes.len() > tx_frame_capacity() {
        return Err(req);
    }
    if req.mirror_clone && free_tx_frames.len() <= MIRROR_TX_FRAME_RESERVE {
        return Err(req);
    }
    let Some(offset) = free_tx_frames.pop_front() else {
        return Err(req);
    };
    let Some(frame) = (unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) })
    else {
        free_tx_frames.push_front(offset);
        return Err(req);
    };
    frame.copy_from_slice(&req.bytes);
    Ok(req.into_prepared_request(offset, PreparedTxRecycle::FreeTxFrame))
}

pub(super) fn enqueue_prepared_into_cos(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    req: PreparedTxRequest,
    now_ns: u64,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), PreparedTxRequest> {
    let egress_ifindex = req.egress_ifindex;
    if !ensure_cos_interface_runtime(binding, forwarding, egress_ifindex, now_ns) {
        return Err(req);
    }
    if binding
        .cos
        .cos_interfaces
        .get(&egress_ifindex)
        .is_some_and(|root| cos_queue_accepts_prepared(root, req.cos_queue_id))
    {
        let item_len = req.len as u64;
        match enqueue_cos_item(
            binding,
            egress_ifindex,
            req.cos_queue_id,
            item_len,
            CoSPendingTxItem::Prepared(req),
            shared_recycles.as_deref_mut(),
        ) {
            Ok(()) => return Ok(()),
            Err(CoSPendingTxItem::Prepared(req)) => return Err(req),
            Err(CoSPendingTxItem::Local(_)) => unreachable!("prepared request returned local item"),
        }
    }

    let Some(local_req) = clone_prepared_request_for_cos(binding.umem.area(), &req) else {
        return Err(req);
    };
    // Keep prepared/direct frames in CoS while a queue stays prepared-only.
    // Once any copied local item enters that queue, later prepared frames must
    // fall back to local copies until the queue drains empty again; otherwise a
    // local head item can block behind prepared frames that are holding every
    // free TX frame on the owner binding.
    let item_len = local_req.bytes.len() as u64;
    match enqueue_cos_item(
        binding,
        egress_ifindex,
        local_req.cos_queue_id,
        item_len,
        CoSPendingTxItem::Local(local_req),
        shared_recycles.as_deref_mut(),
    ) {
        Ok(()) => {
            recycle_prepared_immediately_with_shared(binding, &req, shared_recycles.as_deref_mut());
            Ok(())
        }
        Err(CoSPendingTxItem::Local(_)) => Err(req),
        Err(CoSPendingTxItem::Prepared(_)) => {
            unreachable!("prepared queueing converted to local request")
        }
    }
}

pub(super) fn clone_prepared_request_for_cos(
    area: &MmapArea,
    req: &PreparedTxRequest,
) -> Option<TxRequest> {
    let frame = area.slice(req.offset as usize, req.len as usize)?.to_vec();
    Some(req.to_local_request(frame))
}

pub(super) fn resolve_cos_queue_idx(
    root: &CoSInterfaceRuntime,
    requested_queue: Option<u8>,
) -> Option<usize> {
    if root.queues.is_empty() {
        return None;
    }
    if let Some(queue_id) = requested_queue {
        return root
            .queues
            .iter()
            .position(|queue| queue.queue_id() == queue_id);
    }
    root.queues
        .iter()
        .position(|queue| queue.queue_id() == root.default_queue)
        .or_else(|| (!root.queues.is_empty()).then_some(0))
}

pub(in crate::afxdp) fn demote_prepared_cos_queue_to_local(
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    root: &mut CoSInterfaceRuntime,
    requested_queue: Option<u8>,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> bool {
    let Some(queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
        return false;
    };
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return false;
    };
    if !queue.config.exact || cos_queue_is_empty(queue) {
        return false;
    }
    // #926: snapshot MQFQ frontier state BEFORE drain_all so we
    // can restore on the success path. cos_queue_drain_all uses
    // the no-snapshot pop variant (aggregate-bytes vtime advance:
    // queue_vtime += bytes per pop) which inflates queue_vtime
    // by the entire drained backlog. cos_queue_push_back then
    // re-anchors finish-times against the inflated vtime
    // (max(tail, queue_vtime) + bytes), letting any new flow Y
    // enqueued immediately after demotion jump ahead of the
    // demoted backlog — the temporal-inversion bug class #911 /
    // #913 was supposed to prevent. The failure-rollback path
    // (cos_queue_restore_front) is round-trip neutral per #913
    // §3.7 and stays correct without snapshot/restore.
    //
    // Single-worker invariant (Gemini R2): demote and pop run
    // in the same worker thread, and any in-flight pop's
    // snapshot is cleared by cos_queue_drain_all below
    // (cos_queue_drain_all). So no cross-batch pop_snapshot_stack
    // entries can be live at this point — restoring vtime +
    // head/tail finish-times can't race with a concurrent
    // pop's snapshot interpretation.
    //
    // Footprint: 64 KB stack memcpy of two [u64; COS_FLOW_FAIR_BUCKETS]
    // arrays (32 KB each at 4096 buckets — the #785 fairness
    // bump from 1024). Both are already cache-resident in the queue;
    // demote is a rare TX-frame-exhaustion fallback called from
    // tx/cos_classify.rs::enqueue_local_into_cos, not a hot-path operation.
    let saved_flow_fair_frontier = queue.flow_fair_state.as_ref().map(|ff| {
        (
            ff.queue_vtime,
            ff.flow_bucket_head_finish_bytes,
            ff.flow_bucket_tail_finish_bytes,
        )
    });

    let drained = cos_queue_drain_all(queue);
    let mut local_items = VecDeque::with_capacity(drained.len());
    let mut recycles = Vec::with_capacity(drained.len());
    for item in &drained {
        let CoSPendingTxItem::Prepared(req) = item else {
            cos_queue_restore_front(queue, drained);
            return false;
        };
        let Some(local_req) = clone_prepared_request_for_cos(area, req) else {
            cos_queue_restore_front(queue, drained);
            return false;
        };
        local_items.push_back(CoSPendingTxItem::Local(local_req));
        recycles.push((req.recycle, req.offset));
    }
    for item in local_items {
        cos_queue_push_back(queue, item);
    }
    for (recycle, offset) in recycles {
        recycle_cancelled_prepared_offset_with_shared(
            free_tx_frames,
            pending_fill_frames,
            shared_recycles.as_deref_mut(),
            slot,
            recycle,
            offset,
        );
    }

    // #926: restore MQFQ frontier on the success path. Same
    // flow_keys → same cos_flow_bucket_index → same buckets,
    // so the saved per-bucket head/tail finish-times still
    // apply. Restoring queue_vtime alongside keeps the three
    // values internally consistent.
    if let (Some(ff), Some((saved_queue_vtime, saved_head_finish, saved_tail_finish))) =
        (queue.flow_fair_state.as_mut(), saved_flow_fair_frontier)
    {
        ff.queue_vtime = saved_queue_vtime;
        ff.flow_bucket_head_finish_bytes = saved_head_finish;
        ff.flow_bucket_tail_finish_bytes = saved_tail_finish;
    }

    // #940: explicit V_min publish after the demote restore. The
    // pop-time publish was removed in #940; without this hook,
    // peers would never see the post-demote state — the slot stays
    // at whatever was published BEFORE this demote ran. Publishing
    // the saved (== restored) vtime is correct and idempotent
    // (matches the value peers saw before demote).
    //
    // Sequencing invariant (Gemini review): demote runs from
    // `enqueue_local_into_cos` on the rx/producer path BEFORE any
    // post-settle publish for THIS queue in this worker iteration.
    // The saved `queue_vtime` (line 5512 area) therefore equals the
    // value that the previous iteration's post-settle publish
    // broadcast to this slot. drain_all inflates `queue_vtime`
    // locally; restore at lines 5582-5584 puts it back to the saved
    // value; this publish broadcasts the same value again. Net
    // effect on peers: slot-value unchanged. No "rewind" possible
    // because the worker's per-iteration rx-then-tx ordering
    // serializes demote (rx path) before the in-flight tx batch's
    // settle.
    publish_committed_queue_vtime(Some(&*queue));

    true
}

/// #774: O(1) check replacing the prior O(n) scan. Profiled at
/// 3.25% CPU on the hot path at line rate before this fix.
/// `local_item_count` is maintained at every push/pop site in
/// `cos_queue_push_*` / `cos_queue_pop_front`. Single-writer
/// (owner worker), same discipline as `queued_bytes` — no atomic
/// needed.
#[inline]
pub(in crate::afxdp) fn cos_queue_accepts_prepared(
    root: &CoSInterfaceRuntime,
    requested_queue: Option<u8>,
) -> bool {
    let Some(queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
        return false;
    };
    let Some(queue) = root.queues.get(queue_idx) else {
        return false;
    };
    queue.hot.local_item_count == 0
}

pub(in crate::afxdp) fn cos_queue_dscp_rewrite(
    binding: &BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
) -> Option<u8> {
    binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|queue| queue.config.dscp_rewrite)
}

fn enqueue_cos_item(
    binding: &mut BindingWorker,
    egress_ifindex: i32,
    requested_queue: Option<u8>,
    item_len: u64,
    mut item: CoSPendingTxItem,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) -> Result<(), CoSPendingTxItem> {
    let mut root_became_nonempty = false;
    let mut accepted_exact = false;
    let (accepted, queue_id, recycle) = {
        // Split-borrow: `umem` sits alongside `cos_interfaces` on
        // `BindingWorker`, so we can take a shared borrow on the umem
        // field while holding `&mut binding.cos.cos_interfaces` for the
        // admission-gate block. The Prepared-variant ECN marker
        // (#727) needs this to mutate frame bytes in the UMEM
        // in-place; the admission gate runs strictly before the
        // frame is enqueued, so nothing else in the system observes
        // the bytes concurrently. Both fields are borrowed explicitly
        // here so the borrow checker keeps us honest.
        let umem = binding.umem.area();
        let Some(root) = binding.cos.cos_interfaces.get_mut(&egress_ifindex) else {
            return Err(item);
        };
        let Some(mut queue_idx) = resolve_cos_queue_idx(root, requested_queue) else {
            return Err(item);
        };
        if queue_idx >= root.queues.len() {
            queue_idx = 0;
        }
        let root_was_empty = root.nonempty_queues == 0;
        let queue = &mut root.queues[queue_idx];
        // #707: aggregate cap scales with prospective-active flow count
        // so the per-flow fast-retransmit floor can be satisfied, and
        // the aggregate gate uses the same denominator as the per-flow
        // clamp — otherwise the first packet of a new flow can get
        // stuck at the boundary even when the per-flow path is trying
        // to admit it. Compute `flow_bucket` once so both gates key off
        // the same queue state snapshot.
        let flow_bucket = if queue.flow_fair() {
            let ff = queue
                .flow_fair_state
                .as_ref()
                .expect("flow_fair queue missing FlowFairState");
            cos_flow_bucket_index(ff.flow_hash_seed, cos_item_flow_key(&item))
        } else {
            0
        };
        let buffer_limit = cos_flow_aware_buffer_limit(queue, flow_bucket);
        let flow_share_exceeded = if queue.flow_fair() {
            let ff = queue
                .flow_fair_state
                .as_ref()
                .expect("flow_fair queue missing FlowFairState");
            ff.flow_bucket_bytes[flow_bucket].saturating_add(item_len)
                > cos_queue_flow_share_limit(queue, buffer_limit, flow_bucket)
        } else {
            false
        };
        let buffer_exceeded = queue.hot.queued_bytes.saturating_add(item_len) > buffer_limit;
        // #718 + #722: ECN CE-mark above threshold so ECN-negotiated
        // TCP flows back off smoothly rather than tail-dropping into
        // RTO. Non-ECT packets are untouched — they fall back to the
        // existing admission drop path below. Mark only when the
        // packet will actually be admitted: a marked-and-then-dropped
        // packet wastes both the mark and the bandwidth the mark was
        // trying to steer. `flow_bucket` is the same index the
        // per-flow admission gate keyed off, so both gates see the
        // same queue snapshot.
        let _ = apply_cos_admission_ecn_policy(
            queue,
            buffer_limit,
            flow_bucket,
            flow_share_exceeded,
            buffer_exceeded,
            &mut item,
            umem,
        );
        if flow_share_exceeded || buffer_exceeded {
            // #710: attribute the drop to the specific admission-path
            // reason. `flow_share_exceeded` is checked first so that
            // when both caps trip simultaneously, the root cause
            // (per-flow bucket saturation under SFQ collision / cap
            // undersizing) is counted rather than the buffer cap — the
            // buffer-cap hit is a symptom downstream of flow-share
            // admission failing to throttle the flow.
            if flow_share_exceeded {
                queue.telemetry.drop_counters.admission_flow_share_drops = queue
                    .telemetry
                    .drop_counters
                    .admission_flow_share_drops
                    .wrapping_add(1);
            } else {
                queue.telemetry.drop_counters.admission_buffer_drops = queue
                    .telemetry
                    .drop_counters
                    .admission_buffer_drops
                    .wrapping_add(1);
            }
            let recycle = match &item {
                CoSPendingTxItem::Prepared(req) => Some((req.recycle, req.offset)),
                CoSPendingTxItem::Local(_) => None,
            };
            (false, queue.queue_id(), recycle)
        } else {
            let queue_was_empty = cos_queue_is_empty(queue);
            queue.hot.queued_bytes = queue.hot.queued_bytes.saturating_add(item_len);
            cos_queue_push_back(queue, item);
            accepted_exact = queue.config.exact;
            if queue_was_empty {
                root.nonempty_queues = root.nonempty_queues.saturating_add(1);
                root_became_nonempty = root_was_empty;
            }
            if !queue.hot.parked && !queue.hot.runnable {
                root.runnable_queues = root.runnable_queues.saturating_add(1);
            }
            if !queue.hot.parked {
                mark_cos_queue_runnable(queue);
            }
            (true, queue.queue_id(), None)
        }
    };
    if root_became_nonempty {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_add(1);
    }
    if accepted {
        if accepted_exact {
            publish_cos_exact_backlog(binding, egress_ifindex);
        }
        return Ok(());
    }
    if let Some((recycle, offset)) = recycle {
        recycle_cancelled_prepared_offset_with_shared(
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.tx_pipeline.pending_fill_frames,
            shared_recycles.as_deref_mut(),
            binding.slot,
            recycle,
            offset,
        );
    }
    // #804: CoS admission overflow — NOT bound-pending. Pre-#804 this
    // site incremented `dbg_pending_overflow` which conflated it with
    // the bound-pending FIFO evict sites; the two are now tracked on
    // separate counters so operators can disambiguate CoS shaping
    // pressure from bound-pending pressure.
    binding.telemetry.dbg_cos_queue_overflow += 1;
    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
    binding.live.set_error(format!(
        "class-of-service queue overflow on ifindex {} queue {}",
        egress_ifindex, queue_id
    ));
    Ok(())
}

#[cfg(test)]
#[path = "cos_classify_tests.rs"]
mod tests;
