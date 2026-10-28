use super::*;

// Service stage of the worker CoS service pipeline. The four fns
// here orchestrate the per-queue token-gate / drain / TX-submit /
// settle handshake for the four (local|prepared) × (FIFO|MQFQ flow-fair)
// combinations of exact-queue servicing. They sit between the
// `select_*` fns (in queue_service/mod.rs) which pick a batch and
// the `drain_*` fns (in queue_service/drain.rs) which move items
// into worker scratch buffers.

#[inline]
pub(super) fn service_exact_local_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> ExactServiceOutcome {
    let flow_fair = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair())
        .unwrap_or(false);
    if flow_fair {
        return service_exact_local_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
            shared_recycles,
        );
    }
    if binding.tx_pipeline.free_tx_frames.is_empty() {
        let _ = reap_tx_completions_fields(
            binding.slot,
            binding.ifindex,
            binding.queue_id,
            (binding.umem.total_frames() as u64) * (crate::afxdp::UMEM_FRAME_SIZE as u64),
            &mut binding.xsk,
            &mut binding.telemetry,
            &mut binding.scratch,
            &mut binding.tx_pipeline,
            &binding.live,
            shared_recycles,
            &mut binding.timers,
            &mut binding.tx_counters,
            &mut binding.flow.flow_cache,
            &mut binding.cos.cos_interfaces,
        );
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    binding.scratch.scratch_exact_local_tx.clear();
    let root_budget = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return ExactServiceOutcome::NoProgress,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return ExactServiceOutcome::NoProgress,
        };
        drain_exact_local_fifo_items_to_scratch(
            queue,
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.scratch.scratch_exact_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::VMinSkipped => unreachable!("FIFO queues have no V_min brake"),
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_local_scratch_frames(
                &mut binding.tx_pipeline.free_tx_frames,
                &mut binding.scratch.scratch_exact_local_tx,
            );
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return ExactServiceOutcome::NoProgress;
        }
        ExactCoSScratchBuild::MirrorTxFrameReserve { dropped_bytes } => {
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding
                .live
                .mirror_drops_tx_frame_reserve
                .fetch_add(1, Ordering::Relaxed);
            return ExactServiceOutcome::NoProgress;
        }
    }
    if binding.scratch.scratch_exact_local_tx.is_empty() {
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::NoFreeTxFrame);
        return ExactServiceOutcome::NoProgress;
    }

    let mut writer = binding
        .xsk
        .tx
        .transmit(binding.scratch.scratch_exact_local_tx.len() as u32);
    let inserted =
        writer.insert(
            binding
                .scratch
                .scratch_exact_local_tx
                .iter()
                .map(|req| XdpDesc {
                    addr: req.offset,
                    len: req.len,
                    options: 0,
                }),
        );
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: sample the submit stamp AFTER
    // `writer.commit()` so a scheduler preemption between `insert`
    // and the ring submit does NOT inflate the measured latency.
    // Pre-commit stamping attributed the preemption window to the
    // kernel (submit→completion), which is exactly the opposite of
    // what we want to observe. A reused caller `now_ns` would still
    // leak up to ~1 ms of worker-loop staleness, so we take a fresh
    // `monotonic_nanos()` here rather than re-using one from the
    // outer scope. Only the accepted prefix (`.take(inserted as
    // usize)`) is stamped — the retry tail returns to
    // `free_tx_frames` and MUST NOT be stamped.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_pipeline.tx_submit_ns,
        binding
            .scratch
            .scratch_exact_local_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );
    // #16242: descriptors-per-commit sample for this ring commit.
    crate::afxdp::tx::record_tx_commit_fields(&binding.live, &mut binding.tx_pipeline, inserted);

    if inserted == 0 {
        let dropped = binding.scratch.scratch_exact_local_tx.len() as u64;
        binding.telemetry.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall_on_interfaces(
            &mut binding.cos.cos_interfaces,
            root_ifindex,
            queue_idx,
            dropped,
        );
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        release_exact_local_scratch_frames(
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.scratch.scratch_exact_local_tx,
        );
        refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::TxRingInsertFailed);
        return ExactServiceOutcome::NoProgress;
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let Some(queue) = binding
        .cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .and_then(|root| root.queues.get_mut(queue_idx))
    else {
        // #17186 settle-miss: queue resolved at build above; disappearance
        // here is unreachable in production (single &mut BindingWorker per
        // pass), but if it ever happens the kernel already owns the
        // `inserted` prefix. Record that prefix in the untracked tracker,
        // clear the scratch (suffix offsets are NOT recycled — the FIFO
        // scratch holds only copies and its suffix was never popped from
        // a queue; see settle.rs queue-gone helpers), and do NOT roll
        // `outstanding_tx` back: the reap path drains kernel-owned frames
        // and a subtract here would double-subtract on later completions.
        settle_exact_local_fifo_submission_queue_gone(
            &mut binding.scratch.scratch_exact_local_tx,
            &mut binding.tx_pipeline.in_flight_untracked_tx,
            inserted as usize,
        );
        publish_cos_exact_backlog_on_cos(&binding.cos, binding.slot, root_ifindex);
        return ExactServiceOutcome::NoProgress;
    };
    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        queue,
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.scratch.scratch_exact_local_tx,
        &mut binding.tx_pipeline.in_flight_untracked_tx,
        inserted as usize,
    );
    // #940: post-settle V_min publish. FIFO queues currently have
    // vtime_floor=None so this is a no-op; kept for uniformity and
    // to shield future flow_fair-FIFO adoption.
    publish_committed_queue_vtime(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result_fields(
        &binding.live,
        &mut binding.cos,
        binding.slot,
        root_ifindex,
        queue_idx,
        sent_packets,
        sent_bytes,
    );
    maybe_wake_tx_fields(
        &binding.live,
        &binding.xsk,
        &mut binding.timers,
        &mut binding.telemetry,
        &mut binding.tx_pipeline,
        true,
        now_ns,
    );
    (sent_packets > 0 || sent_bytes > 0).into()
}

#[inline]
fn service_exact_local_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> ExactServiceOutcome {
    if binding.tx_pipeline.free_tx_frames.is_empty() {
        let _ = reap_tx_completions_fields(
            binding.slot,
            binding.ifindex,
            binding.queue_id,
            (binding.umem.total_frames() as u64) * (crate::afxdp::UMEM_FRAME_SIZE as u64),
            &mut binding.xsk,
            &mut binding.telemetry,
            &mut binding.scratch,
            &mut binding.tx_pipeline,
            &binding.live,
            shared_recycles,
            &mut binding.timers,
            &mut binding.tx_counters,
            &mut binding.flow.flow_cache,
            &mut binding.cos.cos_interfaces,
        );
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    binding.scratch.scratch_local_tx.clear();
    let root_budget = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return ExactServiceOutcome::NoProgress,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return ExactServiceOutcome::NoProgress,
        };
        drain_exact_local_items_to_scratch_flow_fair(
            queue,
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.scratch.scratch_local_tx,
            binding.umem.area(),
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::VMinSkipped => return ExactServiceOutcome::VMinSkipped,
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            // Restore scratch offsets even on a (unreachable) queue miss:
            // the popped TxRequests' UMEM offsets leak if we return first.
            if let Some(queue) = binding
                .cos
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx))
            {
                restore_exact_local_scratch_to_queue_head_flow_fair(
                    queue,
                    &mut binding.tx_pipeline.free_tx_frames,
                    &mut binding.scratch.scratch_local_tx,
                );
            } else {
                restore_exact_local_scratch_to_queue_head_flow_fair_queue_gone(
                    &mut binding.tx_pipeline.free_tx_frames,
                    &mut binding.scratch.scratch_local_tx,
                );
            }
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return ExactServiceOutcome::NoProgress;
        }
        ExactCoSScratchBuild::MirrorTxFrameReserve { dropped_bytes } => {
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding
                .live
                .mirror_drops_tx_frame_reserve
                .fetch_add(1, Ordering::Relaxed);
            return ExactServiceOutcome::NoProgress;
        }
    }
    if binding.scratch.scratch_local_tx.is_empty() {
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::NoFreeTxFrame);
        return ExactServiceOutcome::NoProgress;
    }

    let mut writer = binding
        .xsk
        .tx
        .transmit(binding.scratch.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — see plan
    // §3.1 submit-site table (this is the
    // service_exact_local_queue_direct_flow_fair variant). Stamping
    // post-commit prevents a preemption window between `insert` and
    // ring submit from being attributed to submit→completion latency.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_pipeline.tx_submit_ns,
        binding
            .scratch
            .scratch_local_tx
            .iter()
            .take(inserted as usize)
            .map(|(offset, _)| *offset),
        ts_submit,
    );
    // #16242: descriptors-per-commit sample for this ring commit.
    crate::afxdp::tx::record_tx_commit_fields(&binding.live, &mut binding.tx_pipeline, inserted);

    if inserted == 0 {
        let dropped = binding.scratch.scratch_local_tx.len() as u64;
        binding.telemetry.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall_on_interfaces(
            &mut binding.cos.cos_interfaces,
            root_ifindex,
            queue_idx,
            dropped,
        );
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        if let Some(queue) = binding
            .cos
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx))
        {
            restore_exact_local_scratch_to_queue_head_flow_fair(
                queue,
                &mut binding.tx_pipeline.free_tx_frames,
                &mut binding.scratch.scratch_local_tx,
            );
        } else {
            restore_exact_local_scratch_to_queue_head_flow_fair_queue_gone(
                &mut binding.tx_pipeline.free_tx_frames,
                &mut binding.scratch.scratch_local_tx,
            );
        }
        refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::TxRingInsertFailed);
        return ExactServiceOutcome::NoProgress;
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let Some(queue) = binding
        .cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .and_then(|root| root.queues.get_mut(queue_idx))
    else {
        // #17186 settle-miss (flow-fair local): kernel owns the inserted
        // prefix — record it, recycle the uninserted suffix offsets, and
        // leave `outstanding_tx` for the reap path (see FIFO arm above).
        settle_exact_local_scratch_submission_flow_fair_queue_gone(
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.scratch.scratch_local_tx,
            &mut binding.tx_pipeline.in_flight_untracked_tx,
            inserted as usize,
        );
        publish_cos_exact_backlog_on_cos(&binding.cos, binding.slot, root_ifindex);
        return ExactServiceOutcome::NoProgress;
    };
    let (sent_packets, sent_bytes) = settle_exact_local_scratch_submission_flow_fair(
        queue,
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.scratch.scratch_local_tx,
        &mut binding.tx_pipeline.in_flight_untracked_tx,
        inserted as usize,
        now_ns,
    );
    // #940: post-settle V_min publish. Settle has already applied
    // any partial-rollback push_fronts (which republished via the
    // rollback hook), so the queue's flow-fair vtime now reflects only the
    // actually-shipped frames.
    publish_committed_queue_vtime(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result_fields(
        &binding.live,
        &mut binding.cos,
        binding.slot,
        root_ifindex,
        queue_idx,
        sent_packets,
        sent_bytes,
    );
    maybe_wake_tx_fields(
        &binding.live,
        &binding.xsk,
        &mut binding.timers,
        &mut binding.telemetry,
        &mut binding.tx_pipeline,
        true,
        now_ns,
    );
    (sent_packets > 0 || sent_bytes > 0).into()
}

#[inline]
pub(super) fn service_exact_prepared_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> ExactServiceOutcome {
    let flow_fair = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| queue.flow_fair())
        .unwrap_or(false);
    if flow_fair {
        return service_exact_prepared_queue_direct_flow_fair(
            binding,
            root_ifindex,
            queue_idx,
            secondary_budget,
            now_ns,
            shared_recycles,
        );
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    binding.scratch.scratch_exact_prepared_tx.clear();
    let root_budget = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return ExactServiceOutcome::NoProgress,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return ExactServiceOutcome::NoProgress,
        };
        drain_exact_prepared_fifo_items_to_scratch(
            queue,
            &mut binding.scratch.scratch_exact_prepared_tx,
            binding.umem.area(),
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.tx_pipeline.pending_fill_frames,
            binding.slot,
            shared_recycles,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::VMinSkipped => unreachable!("FIFO queues have no V_min brake"),
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            release_exact_prepared_scratch(&mut binding.scratch.scratch_exact_prepared_tx);
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return ExactServiceOutcome::NoProgress;
        }
        ExactCoSScratchBuild::MirrorTxFrameReserve { .. } => {
            unreachable!("prepared CoS queues do not drain local mirror clones")
        }
    }
    if binding.scratch.scratch_exact_prepared_tx.is_empty() {
        return ExactServiceOutcome::NoProgress;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch.scratch_exact_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.telemetry.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

    let mut writer = binding
        .xsk
        .tx
        .transmit(binding.scratch.scratch_exact_prepared_tx.len() as u32);
    let inserted =
        writer.insert(
            binding
                .scratch
                .scratch_exact_prepared_tx
                .iter()
                .map(|req| XdpDesc {
                    addr: req.offset,
                    len: req.len,
                    options: 0,
                }),
        );
    writer.commit();
    drop(writer);
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the service_exact_prepared_queue_direct
    // variant). Post-commit stamping ensures the measurement reflects
    // the moment the ring submission actually landed in the kernel,
    // not the moment before a potential preemption window.
    let ts_submit = monotonic_nanos();
    stamp_submits(
        &mut binding.tx_pipeline.tx_submit_ns,
        binding
            .scratch
            .scratch_exact_prepared_tx
            .iter()
            .take(inserted as usize)
            .map(|req| req.offset),
        ts_submit,
    );
    // #16242: descriptors-per-commit sample for this ring commit.
    crate::afxdp::tx::record_tx_commit_fields(&binding.live, &mut binding.tx_pipeline, inserted);

    if inserted == 0 {
        let dropped = binding.scratch.scratch_exact_prepared_tx.len() as u64;
        binding.telemetry.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall_on_interfaces(
            &mut binding.cos.cos_interfaces,
            root_ifindex,
            queue_idx,
            dropped,
        );
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        release_exact_prepared_scratch(&mut binding.scratch.scratch_exact_prepared_tx);
        refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::PreparedTxRingInsertFailed);
        return ExactServiceOutcome::NoProgress;
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let Some(queue) = binding
        .cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .and_then(|root| root.queues.get_mut(queue_idx))
    else {
        // #17186 settle-miss (prepared FIFO): the scratch holds only
        // (offset,len) copies; the popped requests' recycles were consumed
        // by the queue pops that cannot run here, so there is no suffix to
        // recycle and no recycle to remember. Clear the scratch and leave
        // `outstanding_tx` for the reap path (see FIFO arm above).
        settle_exact_prepared_fifo_submission_queue_gone(
            &mut binding.scratch.scratch_exact_prepared_tx,
            inserted as usize,
        );
        publish_cos_exact_backlog_on_cos(&binding.cos, binding.slot, root_ifindex);
        return ExactServiceOutcome::NoProgress;
    };
    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        queue,
        &mut binding.scratch.scratch_exact_prepared_tx,
        &mut binding.tx_pipeline.in_flight_prepared_recycles,
        &mut binding.tx_pipeline.in_flight_untracked_tx,
        inserted as usize,
    );
    // #940: post-settle V_min publish. FIFO queues have
    // vtime_floor=None today; no-op shield for future adoption.
    publish_committed_queue_vtime(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result_fields(
        &binding.live,
        &mut binding.cos,
        binding.slot,
        root_ifindex,
        queue_idx,
        sent_packets,
        sent_bytes,
    );
    maybe_wake_tx_fields(
        &binding.live,
        &binding.xsk,
        &mut binding.timers,
        &mut binding.telemetry,
        &mut binding.tx_pipeline,
        true,
        now_ns,
    );
    (sent_packets > 0 || sent_bytes > 0).into()
}

#[inline]
fn service_exact_prepared_queue_direct_flow_fair(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> ExactServiceOutcome {
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    binding.scratch.scratch_prepared_tx.clear();
    let root_budget = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = {
        let root = match binding.cos.cos_interfaces.get_mut(&root_ifindex) {
            Some(root) => root,
            None => return ExactServiceOutcome::NoProgress,
        };
        let queue = match root.queues.get_mut(queue_idx) {
            Some(queue) => queue,
            None => return ExactServiceOutcome::NoProgress,
        };
        drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut binding.scratch.scratch_prepared_tx,
            binding.umem.area(),
            &mut binding.tx_pipeline.free_tx_frames,
            &mut binding.tx_pipeline.pending_fill_frames,
            binding.slot,
            shared_recycles,
            root_budget,
            secondary_budget,
            queue_dscp_rewrite,
        )
    };
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::VMinSkipped => return ExactServiceOutcome::VMinSkipped,
        ExactCoSScratchBuild::Drop {
            error,
            dropped_bytes,
        } => {
            if let Some(queue) = binding
                .cos
                .cos_interfaces
                .get_mut(&root_ifindex)
                .and_then(|root| root.queues.get_mut(queue_idx))
            {
                restore_exact_prepared_scratch_to_queue_head_flow_fair(
                    queue,
                    &mut binding.scratch.scratch_prepared_tx,
                );
            } else {
                // Queue gone: the popped PreparedTxRequests cannot be
                // re-queued; drop them (their recycles die with them, as
                // in the parent None arm's `.clear()`).
                binding.scratch.scratch_prepared_tx.clear();
            }
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(
                    &mut binding.cos.cos_interfaces,
                    root_ifindex,
                    queue_idx,
                    dropped_bytes,
                );
            }
            refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: the scratch-build fell through `ExactCoSScratchBuild::Drop`
            // with a frame-level error (capacity or slice). Subset of
            // tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return ExactServiceOutcome::NoProgress;
        }
        ExactCoSScratchBuild::MirrorTxFrameReserve { .. } => {
            unreachable!("prepared CoS queues do not drain local mirror clones")
        }
    }
    if binding.scratch.scratch_prepared_tx.is_empty() {
        return ExactServiceOutcome::NoProgress;
    }

    if cfg!(feature = "debug-log") {
        for req in &binding.scratch.scratch_prepared_tx {
            if let Some(frame_data) = binding
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
            {
                if frame_has_tcp_rst(frame_data) {
                    binding.telemetry.dbg_tx_tcp_rst += 1;
                }
            }
        }
    }

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
    // #812 Codex round-1 HIGH #1: submit stamp AFTER commit — plan
    // §3.1 submit-site table (the
    // service_exact_prepared_queue_direct_flow_fair variant). See the
    // exact_local variant above for the preemption-window rationale.
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
    crate::afxdp::tx::record_tx_commit_fields(&binding.live, &mut binding.tx_pipeline, inserted);

    if inserted == 0 {
        let dropped = binding.scratch.scratch_prepared_tx.len() as u64;
        binding.telemetry.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall_on_interfaces(
            &mut binding.cos.cos_interfaces,
            root_ifindex,
            queue_idx,
            dropped,
        );
        maybe_wake_tx_fields(
            &binding.live,
            &binding.xsk,
            &mut binding.timers,
            &mut binding.telemetry,
            &mut binding.tx_pipeline,
            true,
            now_ns,
        );
        if let Some(queue) = binding
            .cos
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx))
        {
            restore_exact_prepared_scratch_to_queue_head_flow_fair(
                queue,
                &mut binding.scratch.scratch_prepared_tx,
            );
        } else {
            binding.scratch.scratch_prepared_tx.clear();
        }
        refresh_cos_interface_activity_on_cos(&mut binding.cos, root_ifindex, Some(binding.slot));
        // #4971: expected TX backpressure — lock-free status, no mutex.
        binding
            .live
            .set_tx_retry_status(TxRetryReason::PreparedTxRingInsertFailed);
        return ExactServiceOutcome::NoProgress;
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx =
        binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let Some(queue) = binding
        .cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .and_then(|root| root.queues.get_mut(queue_idx))
    else {
        // #17186 settle-miss (flow-fair prepared): the scratch holds the
        // popped requests themselves — remember the kernel-owned prefix's
        // recycles exactly as the Some-path settle does, drop the
        // uninserted suffix without remembering, and leave
        // `outstanding_tx` for the reap path (see FIFO arm above).
        settle_exact_prepared_scratch_submission_flow_fair_queue_gone(
            &mut binding.scratch.scratch_prepared_tx,
            &mut binding.tx_pipeline.in_flight_prepared_recycles,
            &mut binding.tx_pipeline.in_flight_untracked_tx,
            inserted as usize,
        );
        publish_cos_exact_backlog_on_cos(&binding.cos, binding.slot, root_ifindex);
        return ExactServiceOutcome::NoProgress;
    };
    let (sent_packets, sent_bytes) = settle_exact_prepared_scratch_submission_flow_fair(
        queue,
        &mut binding.scratch.scratch_prepared_tx,
        &mut binding.tx_pipeline.in_flight_prepared_recycles,
        &mut binding.tx_pipeline.in_flight_untracked_tx,
        inserted as usize,
        now_ns,
    );
    // #940: post-settle V_min publish. Settle has applied any
    // partial-rollback push_fronts via the rollback hook;
    // the queue's flow-fair vtime now reflects only actually-shipped frames.
    publish_committed_queue_vtime(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result_fields(
        &binding.live,
        &mut binding.cos,
        binding.slot,
        root_ifindex,
        queue_idx,
        sent_packets,
        sent_bytes,
    );
    maybe_wake_tx_fields(
        &binding.live,
        &binding.xsk,
        &mut binding.timers,
        &mut binding.telemetry,
        &mut binding.tx_pipeline,
        true,
        now_ns,
    );
    (sent_packets > 0 || sent_bytes > 0).into()
}
