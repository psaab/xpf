use super::*;

use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;

fn cos_queue_fast_path_for_request<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<&'a WorkerCoSQueueFastPath> {
    let iface = cos_fast_interfaces.get(&egress_ifindex)?;
    iface.queue_fast_path(requested_queue_id)
}

fn cos_owner_live_for_request(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<Arc<BindingLiveState>> {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .and_then(|queue_fast| queue_fast.owner_live.clone())
}

fn request_uses_shared_exact_queue_lease(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> bool {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .is_some_and(|queue_fast| queue_fast.shared_queue_lease.is_some())
}

fn enqueue_local_request_to_target_or_owner(
    target_binding: &mut BindingWorker,
    req: TxRequest,
) -> Result<(), TxRequest> {
    if request_uses_shared_exact_queue_lease(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) {
        target_binding.tx_pipeline.pending_tx_local.push_back(req);
        bound_pending_tx_local(target_binding);
        return Ok(());
    }
    let owner_live = cos_owner_live_for_request(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    );
    if let Some(owner_live) = owner_live {
        if !Arc::ptr_eq(&owner_live, &target_binding.live) {
            return owner_live.enqueue_tx_owned(req);
        }
    }
    target_binding.tx_pipeline.pending_tx_local.push_back(req);
    bound_pending_tx_local(target_binding);
    Ok(())
}

#[inline]
fn recycle_ingress_frame(ingress_binding: &mut BindingWorker, source_offset: u64, now_ns: u64) {
    ingress_binding.tx_pipeline.pending_fill_frames.push_back(source_offset);
    if ingress_binding.tx_pipeline.pending_fill_frames.len() >= FILL_BATCH_SIZE {
        let _ = drain_pending_fill(ingress_binding, now_ns);
    }
}

pub(in crate::afxdp) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) {
    if pending_forwards.is_empty() {
        return;
    }
    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    let tx_selection_enabled_v4 = forwarding.tx_selection_enabled_v4;
    let tx_selection_enabled_v6 = forwarding.tx_selection_enabled_v6;
    post_recycles.clear();
    // Walk the scratch vector in place. Moving large PendingForwardRequest
    // values through the iterator path was still forcing per-request memcpy
    // traffic before any forwarding work started.
    for request in pending_forwards.iter_mut() {
        let source_offset = request.desc.addr;
        let ingress_slot = ingress_binding.slot;
        let tx_selection_enabled = if request.meta.addr_family as i32 == libc::AF_INET6 {
            tx_selection_enabled_v6
        } else {
            tx_selection_enabled_v4
        };
        if tx_selection_enabled && request.cos_queue_id.is_none() && request.dscp_rewrite.is_none()
        {
            let cos = resolve_pending_forward_cos_tx_selection(forwarding, &request);
            request.cos_queue_id = cos.queue_id;
            request.dscp_rewrite = cos.dscp_rewrite;
        }
        let target_binding_index = request.target_binding_index.or_else(|| {
            binding_lookup.target_index(
                ingress_index,
                ingress_binding.ifindex,
                request.ingress_queue_id,
                request.target_ifindex,
            )
        });

        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
        // The frame is already fully rewritten — just enqueue for TX.
        if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
            let Some(target_binding) = resolve_pending_forward_target_binding(
                left,
                ingress_index,
                ingress_binding,
                request.ingress_queue_id,
                right,
                binding_lookup,
                target_binding_index,
                request.target_ifindex,
            ) else {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            };
            let frame_len = prebuilt.len();
            let req = TxRequest {
                bytes: core::mem::take(prebuilt),
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: None,
                egress_ifindex: request.decision.resolution.egress_ifindex,
                cos_queue_id: request.cos_queue_id,
                dscp_rewrite: request.dscp_rewrite,
            };
            if enqueue_local_request_to_target_or_owner(target_binding, req).is_err() {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            target_binding.tx_counters.pending_copy_tx_packets += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        }

        // Read source frame directly from ingress UMEM — no heap copy needed.
        // The frame is safe to read: RX ring released but frame not yet returned
        // to fill ring (that happens after this function completes).
        let source_frame = match &request.frame {
            PendingForwardFrame::Owned(frame) => frame.as_slice(),
            PendingForwardFrame::Live => {
                if let Some(frame) = (unsafe { &*ingress_area })
                    .slice(request.desc.addr as usize, request.desc.len as usize)
                {
                    frame
                } else {
                    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                    continue;
                }
            }
            PendingForwardFrame::Prebuilt(_) => unreachable!(),
        };
        let expected_ports = request.expected_ports;
        let ingress_umem_ptr = ingress_binding.umem.allocation_ptr();
        let Some(target_binding) = resolve_pending_forward_target_binding(
            left,
            ingress_index,
            ingress_binding,
            request.ingress_queue_id,
            right,
            binding_lookup,
            target_binding_index,
            request.target_ifindex,
        ) else {
            // No XSK binding for the target interface.  Normally fabric
            // parents have bindings; this is a safety-net fallback in case
            // the binding is not yet ready or bind() failed.
            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                if matches!(request.frame, PendingForwardFrame::Owned(_)) {
                    maybe_reinject_slow_path_from_frame(
                        ingress_ident,
                        ingress_live,
                        slow_path,
                        local_tunnel_deliveries,
                        source_frame,
                        request.meta,
                        request.decision,
                        recent_exceptions,
                        "slow_path",
                        forwarding,
                    );
                } else {
                    maybe_reinject_slow_path(
                        ingress_ident,
                        ingress_live,
                        slow_path,
                        local_tunnel_deliveries,
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        request.decision,
                        recent_exceptions,
                        forwarding,
                    );
                }
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.no_egress_binding += 1;
            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {
                debug_log!(
                    "DBG NO_EGRESS_BINDING: target_ifindex={} ingress_if={} ingress_q={}",
                    request.target_ifindex,
                    ingress_ident.ifindex,
                    request.ingress_queue_id,
                );
            }
            record_exception(
                recent_exceptions,
                ingress_ident,
                "missing_egress_binding",
                request.desc.len,
                None,
                None,
            forwarding,
            );
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        };
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        let mut flow_key = request.flow_key.take();
        {
            if forwarded_tcp_may_need_segmentation(
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
            ) {
                if let Some((segments, bytes, max_frame)) =
                    segment_forwarded_tcp_frames_into_prepared(
                        target_binding,
                        source_frame,
                        request.meta,
                        &request.decision,
                        forwarding,
                        request.apply_nat_on_fabric,
                        expected_ports,
                        flow_key.clone(),
                        request.cos_queue_id,
                        request.dscp_rewrite,
                        now_ns,
                        post_recycles,
                        worker_id,
                        worker_commands_by_id,
                        cos_owner_worker_by_queue,
                        cos_owner_live_by_queue,
                    )
                {
                    dbg.enqueue_ok += segments as u64;
                    dbg.enqueue_direct += segments as u64;
                    target_binding.tx_counters.pending_direct_tx_packets += segments as u64;
                    dbg.tx_bytes_total += bytes;
                    if max_frame > dbg.tx_max_frame {
                        dbg.tx_max_frame = max_frame;
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
                            cos_owner_live_by_queue,
                        );
                    }
                } else if let Some(segmented) = segment_forwarded_tcp_frames_from_frame(
                    source_frame,
                    request.meta,
                    &request.decision,
                    forwarding,
                    request.apply_nat_on_fabric,
                    expected_ports,
                ) {
                    for frame in segmented {
                        if cfg!(feature = "debug-log") {
                            if let Some(reason) = forward_tuple_mismatch_reason(
                                live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                expected_ports,
                                live_frame_ports_bytes(
                                    &frame,
                                    request.meta.addr_family,
                                    request.meta.protocol,
                                ),
                            ) {
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    &reason,
                                    frame.len() as u32,
                                    Some(request.meta.into()),
                                    None,
                                forwarding,
                                );
                                build_failed = true;
                                break;
                            }
                        }
                        let seg_frame_len = frame.len();
                        target_binding.tx_pipeline.pending_tx_local.push_back(TxRequest {
                            bytes: frame,
                            expected_ports,
                            expected_addr_family: request.meta.addr_family,
                            expected_protocol: request.meta.protocol,
                            flow_key: flow_key.clone(),
                            egress_ifindex: request.decision.resolution.egress_ifindex,
                            cos_queue_id: request.cos_queue_id,
                            dscp_rewrite: request.dscp_rewrite,
                        });
                        bound_pending_tx_local(target_binding);
                        dbg.enqueue_ok += 1;
                        dbg.enqueue_copy += 1;
                        target_binding.tx_counters.pending_copy_tx_packets += 1;
                        dbg.tx_bytes_total += seg_frame_len as u64;
                        if (seg_frame_len as u32) > dbg.tx_max_frame {
                            dbg.tx_max_frame = seg_frame_len as u32;
                        }
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
                            cos_owner_live_by_queue,
                        );
                    }
                }
            }
            // Track when segmentation was needed but returned None
            if !copied_source_frame && source_frame.len() > 1514 {
                dbg.seg_needed_but_none += 1;
                thread_local! {
                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                SEG_MISS_LOG.with(|c| {
                    let n = c.get();
                    if n < 20 {
                        c.set(n + 1);
                        let egress_mtu = forwarding
                            .egress
                            .get(&request.decision.resolution.egress_ifindex)
                            .or_else(|| forwarding.egress.get(&request.decision.resolution.tx_ifindex))
                            .map(|e| e.mtu);
                        eprintln!("DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} \
                             target_if={} src_frame_bytes={}",
                            n, source_frame.len(), request.meta.protocol,
                            request.decision.resolution.egress_ifindex,
                            request.decision.resolution.tx_ifindex,
                            egress_mtu, request.target_ifindex,
                            source_frame.len(),
                        );
                    }
                });
            }
            if !copied_source_frame {
                // NAT64: header size changes prevent in-place rewrite.
                // Always use copy path with NAT64-specific frame builder.
                let is_nat64 = request.decision.nat.nat64;
                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;
                let owner_matches_target = request_uses_shared_exact_queue_lease(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                ) || cos_owner_live_for_request(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                )
                .as_ref()
                .is_none_or(|live| Arc::ptr_eq(live, &target_binding.live));

                /*
                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
                 * and submit it to the target binding's TX ring without copying.
                 * This is valid whenever ingress and egress bindings share the same
                 * UMEM allocation. That includes same-binding hairpin and the narrow
                 * same-device shared-UMEM prototype.
                 */
                let can_rewrite_in_place = target_binding.umem.allocation_ptr() == ingress_umem_ptr
                    && !is_nat64
                    && !uses_native_tunnel
                    && owner_matches_target
                    && matches!(request.frame, PendingForwardFrame::Live);
                if can_rewrite_in_place {
                    match rewrite_forwarded_frame_in_place(
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        &request.decision,
                        request.apply_nat_on_fabric,
                        expected_ports,
                    ) {
                        Some(frame_len) => {
                            target_binding
                                .tx_pipeline.pending_tx_prepared
                                .push_back(PreparedTxRequest {
                                    offset: source_offset,
                                    len: frame_len,
                                    recycle: PreparedTxRecycle::FillOnSlot(ingress_slot),
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                });
                            bound_pending_tx_prepared(target_binding);
                            target_binding.tx_counters.pending_in_place_tx_packets += 1;
                            dbg.enqueue_ok += 1;
                            dbg.enqueue_inplace += 1;
                            dbg.tx_bytes_total += frame_len as u64;
                            if frame_len > dbg.tx_max_frame {
                                dbg.tx_max_frame = frame_len;
                            }
                            retained_source_frame = true;
                        }
                        None => match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_from_meta_bytes(
                                            source_frame,
                                            request.meta,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta.into()),
                                            None,
                                        forwarding,
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp1_len = frame.len();
                                if cp1_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp1_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                    forwarding,
                                    );
                                    continue;
                                }
                                let req = TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                };
                                if enqueue_local_request_to_target_or_owner(target_binding, req)
                                    .is_err()
                                {
                                    build_failed = true;
                                    fallback_to_slow_path = true;
                                    continue;
                                }
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                target_binding.tx_counters.pending_copy_tx_packets += 1;
                                dbg.tx_bytes_total += cp1_len as u64;
                                if (cp1_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp1_len as u32;
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        },
                    }
                } else {
                    enum DirectTxFallbackReason {
                        NoFreeTxFrame,
                        BuildReturnedNone,
                        DisallowedByRewriteMode,
                    }
                    // Direct TX build: write the forwarded frame directly into
                    // the target binding's UMEM TX frame, eliminating the
                    // intermediate Vec allocation and one memcpy.
                    // NAT64 cannot use direct TX (header size changes), so
                    // it falls through to the copy path below.
                    let mut direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
                    if direct_tx_offset.is_none()
                        && (target_binding.tx_pipeline.outstanding_tx > 0
                            || !target_binding.tx_pipeline.pending_tx_prepared.is_empty()
                            || !target_binding.tx_pipeline.pending_tx_local.is_empty())
                    {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                            cos_owner_worker_by_queue,
                            cos_owner_live_by_queue,
                        );
                        direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
                    }
                    let mut direct_tx_fallback_reason = None;
                    let direct_built = if is_nat64 || uses_native_tunnel {
                        // NAT64 can't use direct TX — return the frame if we popped one.
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if !owner_matches_target {
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        // A prepared/direct frame on a non-owner binding would be
                        // cloned back into a local Vec during CoS owner redirection.
                        // Skip that waste and fall back to the single-copy local path.
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if let Some(tx_offset) = direct_tx_offset {
                        let target_area = target_binding.umem.area();
                        // Prefetch target frame to warm cache before copy.
                        #[cfg(target_arch = "x86_64")]
                        if let Some(pf) = target_area.slice(tx_offset as usize, 64) {
                            unsafe {
                                core::arch::x86_64::_mm_prefetch(
                                    pf.as_ptr() as *const i8,
                                    core::arch::x86_64::_MM_HINT_T0,
                                );
                            }
                        }
                        let written = unsafe {
                            target_area.slice_mut_unchecked(tx_offset as usize, tx_frame_capacity())
                        }
                        .and_then(|out| {
                            build_forwarded_frame_into_from_frame(
                                out,
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        });
                        if let Some(written) = written {
                            // Debug-only: validate built frame ports match expected.
                            // enforce_expected_ports() in build_forwarded_frame_into_from_frame
                            // already ensures correctness; this catches builder bugs.
                            if cfg!(feature = "debug-log") {
                                let built_ports = unsafe {
                                    target_area.slice_mut_unchecked(tx_offset as usize, written)
                                }
                                .and_then(|f| {
                                    live_frame_ports_bytes(
                                        f,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    )
                                });
                                if let Some(reason) = forward_tuple_mismatch_reason(
                                    live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                    expected_ports,
                                    built_ports,
                                ) {
                                    target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        &reason,
                                        written as u32,
                                        Some(request.meta.into()),
                                        None,
                                    forwarding,
                                    );
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
                                true
                            } else if written > tx_frame_capacity() {
                                target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    "oversized_forward_frame",
                                    written as u32,
                                    Some(request.meta.into()),
                                    None,
                                forwarding,
                                );
                                true
                            } else {
                                target_binding
                                    .tx_pipeline.pending_tx_prepared
                                    .push_back(PreparedTxRequest {
                                        offset: tx_offset,
                                        len: written as u32,
                                        recycle: PreparedTxRecycle::FreeTxFrame,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: flow_key.take(),
                                        egress_ifindex: request.decision.resolution.egress_ifindex,
                                        cos_queue_id: request.cos_queue_id,
                                        dscp_rewrite: request.dscp_rewrite,
                                    });
                                bound_pending_tx_prepared(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_direct += 1;
                                target_binding.tx_counters.pending_direct_tx_packets += 1;
                                dbg.tx_bytes_total += written as u64;
                                if (written as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = written as u32;
                                }
                                true
                            }
                        } else {
                            target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
                            direct_tx_fallback_reason =
                                Some(DirectTxFallbackReason::BuildReturnedNone);
                            false
                        }
                    } else {
                        direct_tx_fallback_reason = Some(DirectTxFallbackReason::NoFreeTxFrame);
                        false
                    };
                    // Fallback: Vec copy path when direct build unavailable.
                    if !direct_built {
                        match direct_tx_fallback_reason {
                            Some(DirectTxFallbackReason::NoFreeTxFrame) => {
                                target_binding.tx_counters.pending_direct_tx_no_frame_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::BuildReturnedNone) => {
                                target_binding.tx_counters.pending_direct_tx_build_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode) => {
                                target_binding.tx_counters.pending_direct_tx_disallowed_fallback_packets += 1;
                            }
                            None => {}
                        }
                        match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_from_meta_bytes(
                                            source_frame,
                                            request.meta,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta.into()),
                                            None,
                                        forwarding,
                                        );
                                        // Don't continue — the frame was built successfully,
                                        // forward it anyway. Mismatch is diagnostic only.
                                    }
                                }
                                let cp2_len = frame.len();
                                if cp2_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp2_len as u32,
                                        Some(request.meta.into()),
                                        None,
                                    forwarding,
                                    );
                                    continue;
                                }
                                let req = TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                };
                                if enqueue_local_request_to_target_or_owner(target_binding, req)
                                    .is_err()
                                {
                                    build_failed = true;
                                    fallback_to_slow_path = true;
                                    continue;
                                }
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                target_binding.tx_counters.pending_copy_tx_packets += 1;
                                dbg.tx_bytes_total += cp2_len as u64;
                                if (cp2_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp2_len as u32;
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        }
                    }
                }
            }
            if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE
                || target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE
            {
                let _ = drain_pending_tx_local_owner(
                    target_binding,
                    now_ns,
                    post_recycles,
                    forwarding,
                    worker_id,
                    worker_commands_by_id,
                    cos_owner_worker_by_queue,
                    cos_owner_live_by_queue,
                );
            }
        }
        if !post_recycles.is_empty() {
            apply_shared_recycles(
                left,
                ingress_index,
                ingress_binding,
                right,
                binding_lookup,
                post_recycles,
            );
        }
        if build_failed {
            handle_forward_build_failure(
                ingress_ident,
                ingress_live,
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                dbg,
                request.target_ifindex,
                request.desc.len,
                source_frame,
                request.meta,
                request.decision,
                fallback_to_slow_path,
                forwarding,
            );
            if !retained_source_frame {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            }
            continue;
        }
        if !retained_source_frame {
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
        }
    }
    while !ingress_binding.tx_pipeline.pending_fill_frames.is_empty() {
        let pending_before = ingress_binding.tx_pipeline.pending_fill_frames.len();
        let _ = drain_pending_fill(ingress_binding, now_ns);
        if ingress_binding.tx_pipeline.pending_fill_frames.len() >= pending_before {
            break;
        }
    }
    update_binding_debug_state(ingress_binding);
    pending_forwards.clear();
}

fn resolve_pending_forward_target_binding<'a>(
    left: &'a mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    target_binding_index: Option<usize>,
    target_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    if let Some(target_index) = target_binding_index {
        return binding_by_index_mut(left, ingress_index, ingress_binding, right, target_index);
    }
    find_target_binding_mut(
        left,
        ingress_index,
        ingress_binding,
        ingress_queue_id,
        right,
        binding_lookup,
        target_ifindex,
    )
}

pub(in crate::afxdp) fn handle_forward_build_failure(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    _target_ifindex: i32,
    packet_length: u32,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    fallback_to_slow_path: bool,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    dbg.build_fail += 1;
    #[cfg(feature = "debug-log")]
    if dbg.build_fail <= 3 {
        debug_log!(
            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
            _target_ifindex,
            packet_length,
            fallback_to_slow_path,
        );
    }
    record_exception(
        recent_exceptions,
        binding,
        "forward_build_failed",
        packet_length,
        Some(meta),
        None,
    forwarding,
    );
    if fallback_to_slow_path {
        maybe_reinject_slow_path_from_frame(
            binding,
            live,
            slow_path,
            local_tunnel_deliveries,
            frame,
            meta,
            decision,
            recent_exceptions,
            "forward_build_slow_path",
            forwarding,
        );
    }
}

pub(in crate::afxdp) fn apply_shared_recycles(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    for (slot, offset) in shared_recycles.drain(..) {
        if let Some(target_index) = binding_lookup.slot_index(slot)
            && let Some(binding) =
                binding_by_index_mut(left, current_index, current, right, target_index)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
            continue;
        }
        current.tx_pipeline.pending_fill_frames.push_back(offset);
    }
}

pub(in crate::afxdp) fn resolve_tx_binding_ifindex(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    if let Some(fabric) = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex == egress_ifindex)
    {
        return fabric.parent_ifindex;
    }
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.bind_ifindex)
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(egress_ifindex)
}

fn resolve_pending_forward_cos_tx_selection(
    forwarding: &ForwardingState,
    request: &PendingForwardRequest,
) -> CoSTxSelection {
    resolve_cos_tx_selection(
        forwarding,
        request.decision.resolution.egress_ifindex,
        request.meta,
        request.flow_key.as_ref(),
    )
}

pub(in crate::afxdp) fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    if !matches!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
            | ForwardingDisposition::NoRoute
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::NextTableUnsupported
    ) {
        return;
    }
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_extract_failed",
            desc.len as u32,
            Some(meta),
            None,
        forwarding,
        );
        return;
    };
    maybe_reinject_slow_path_from_frame(
        binding,
        live,
        slow_path,
        local_tunnel_deliveries,
        frame,
        meta,
        decision,
        recent_exceptions,
        "slow_path",
        forwarding,
    );
}

pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    reason: &str,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_prepare_failed",
            frame.len() as u32,
            Some(meta),
            None,
        forwarding,
        );
        return;
    };
    let packet_len = packet.len() as u64;
    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.local_ifindex > 0
    {
        local_tunnel_deliveries
            .load()
            .get(&decision.resolution.local_ifindex)
            .cloned()
    } else {
        None
    };
    if let Some(delivery) = tunnel_delivery {
        match delivery.try_send(packet) {
            Ok(()) => {
                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_queue_full",
                    frame.len() as u32,
                    Some(meta),
                    None,
                forwarding,
                );
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_unavailable",
                    frame.len() as u32,
                    Some(meta),
                    None,
                forwarding,
                );
            }
        }
        return;
    }
    let selected_path = slow_path.cloned();
    let Some(slow_path) = selected_path else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_unavailable",
            frame.len() as u32,
            Some(meta),
            None,
        forwarding,
        );
        return;
    };
    match slow_path.enqueue(packet) {
        Ok(EnqueueOutcome::Accepted) => {
            live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
        }
        Ok(EnqueueOutcome::RateLimited) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_rate_limited"),
                frame.len() as u32,
                Some(meta),
                None,
            forwarding,
            );
        }
        Ok(EnqueueOutcome::QueueFull) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_queue_full"),
                frame.len() as u32,
                Some(meta),
                None,
            forwarding,
            );
        }
        Err(err) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.set_error(err);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_enqueue_failed"),
                frame.len() as u32,
                Some(meta),
                None,
            forwarding,
            );
        }
    }
}

#[allow(dead_code)]
pub(super) fn extract_l3_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    extract_l3_packet_from_frame(frame, meta)
}

pub(super) fn extract_l3_packet_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

pub(in crate::afxdp) fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat)?,
        libc::AF_INET6 => apply_nat_ipv6(&mut packet, meta.protocol, nat)?,
        _ => return None,
    }
    Some(packet)
}


#[inline(always)]
fn forwarded_tcp_may_need_segmentation(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> bool {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
        return false;
    }
    let mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default()
        .max(1280);
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => match frame_l3_offset(frame) {
            Some(offset) => offset,
            None => return false,
        },
    };
    l3 < frame.len() && frame.len().saturating_sub(l3) > mtu
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;

