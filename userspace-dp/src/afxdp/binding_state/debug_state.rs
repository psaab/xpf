// Per-binding debug-state publishing. Extracted from `umem/mod.rs`
// (#1351) to separate the telemetry flush path from UMEM frame-
// management code.
//
// The hot-path callers (`tx/rings`, `tx/drain`, `tx/dispatch`,
// `worker/lifecycle`, `worker/mod`, `session_glue`) invoke
// `update_binding_debug_state` per poll-tick. That wrapper does one
// `wrapping_add(1)` + mask + branch and short-circuits 65535 out of
// 65536 ticks. The actual publish path
// (`publish_binding_debug_state`) runs at the masked cadence (~65ms
// wall-clock) and renders pending TX-counter scratchpads, the flow
// cache active-flow snapshot, and the per-queue V_min throttle
// counters out into `BindingLiveState`'s atomics.
//
// `update_binding_idle_debug_state` augments the hot-path mask with
// a wall-clock idle cadence so RX-empty bindings still publish their
// active-flow snapshot at ~65ms intervals (#1294).
//
// `flush_v_min_scratches_into` is extracted as a standalone free fn
// so unit tests can exercise the per-queue scratch flush without
// constructing a full `BindingWorker` (#941 D, #943).

use super::*;
use crate::afxdp::worker::WorkerTimers;

pub(in crate::afxdp) const DEBUG_STATE_PUBLISH_MASK: u32 = 0xFFFF;
pub(in crate::afxdp) const IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS: u64 = 65_000_000;

pub(in crate::afxdp) fn advance_debug_state_publish_counter(timers: &mut WorkerTimers) -> bool {
    timers.debug_state_counter = timers.debug_state_counter.wrapping_add(1);
    timers.debug_state_counter & DEBUG_STATE_PUBLISH_MASK == 0
}

pub(in crate::afxdp) fn idle_debug_state_publish_due(timers: &mut WorkerTimers, now_ns: u64) -> bool {
    if now_ns.saturating_sub(timers.last_idle_debug_publish_ns)
        < IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS
    {
        return false;
    }
    timers.last_idle_debug_publish_ns = now_ns;
    true
}

pub(in crate::afxdp) fn update_binding_debug_state(binding: &mut BindingWorker) {
    // Use a simple modular counter to avoid repeated atomic stores on every
    // hot-path call. At ~1M calls/sec, checking every 65536 calls ~= every 65ms.
    if !advance_debug_state_publish_counter(&mut binding.timers) {
        return;
    }
    publish_binding_debug_state(binding);
}

pub(in crate::afxdp) fn update_binding_idle_debug_state(binding: &mut BindingWorker, now_ns: u64) {
    // #1294: the hot-path counter's ~65ms assumption only holds while a
    // binding is polling hot. In interrupt/idle loops, 65536 empty polls can
    // take seconds to minutes, leaving stale active-flow snapshots visible
    // long after traffic stops. The RX-empty path already has `now_ns`, so
    // use a wall-clock-equivalent cadence there without adding per-packet
    // clock reads or atomics to active forwarding.
    let regular_publish = advance_debug_state_publish_counter(&mut binding.timers);
    let idle_publish = idle_debug_state_publish_due(&mut binding.timers, now_ns);
    if !(regular_publish || idle_publish) {
        return;
    }
    publish_binding_debug_state(binding);
}

fn publish_binding_debug_state(binding: &mut BindingWorker) {
    // #1771 §2.6: gauge snapshots of the per-binding neighbor maps.
    // `pending_neigh` is keyed per (egress_ifindex, next_hop) since
    // #1779 §2.2, so len() == distinct unresolved next-hops. The
    // negative-cache len carries the lazy-TTL caveat documented on
    // `BindingLiveState::neg_neigh_keys`. Two Relaxed stores at the
    // existing ~65ms publish cadence — no per-packet work.
    binding
        .live
        .pending_neigh_keys
        .store(binding.pending_neigh.len() as u64, Ordering::Relaxed);
    binding
        .live
        .neg_neigh_keys
        .store(binding.neg_neigh_cache.len() as u64, Ordering::Relaxed);
    if binding.tx_counters.pending_direct_tx_packets != 0 {
        binding.live.direct_tx_packets.fetch_add(
            binding.tx_counters.pending_direct_tx_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_direct_tx_packets = 0;
    }
    if binding.tx_counters.pending_copy_tx_packets != 0 {
        binding.live.copy_tx_packets.fetch_add(
            binding.tx_counters.pending_copy_tx_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_copy_tx_packets = 0;
    }
    if binding.tx_counters.pending_in_place_tx_packets != 0 {
        binding.live.in_place_tx_packets.fetch_add(
            binding.tx_counters.pending_in_place_tx_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_in_place_tx_packets = 0;
    }
    if binding.tx_counters.pending_in_place_vlan_push_desc_packets != 0 {
        binding.live.in_place_vlan_push_desc_packets.fetch_add(
            binding.tx_counters.pending_in_place_vlan_push_desc_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_in_place_vlan_push_desc_packets = 0;
    }
    if binding.tx_counters.pending_in_place_vlan_pop_desc_packets != 0 {
        binding.live.in_place_vlan_pop_desc_packets.fetch_add(
            binding.tx_counters.pending_in_place_vlan_pop_desc_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_in_place_vlan_pop_desc_packets = 0;
    }
    if binding
        .tx_counters
        .pending_in_place_vlan_push_no_headroom_packets
        != 0
    {
        binding
            .live
            .in_place_vlan_push_no_headroom_packets
            .fetch_add(
                binding
                    .tx_counters
                    .pending_in_place_vlan_push_no_headroom_packets,
                Ordering::Relaxed,
            );
        binding
            .tx_counters
            .pending_in_place_vlan_push_no_headroom_packets = 0;
    }
    if binding
        .tx_counters
        .pending_in_place_l2_memmove_fallback_packets
        != 0
    {
        binding.live.in_place_l2_memmove_fallback_packets.fetch_add(
            binding
                .tx_counters
                .pending_in_place_l2_memmove_fallback_packets,
            Ordering::Relaxed,
        );
        binding
            .tx_counters
            .pending_in_place_l2_memmove_fallback_packets = 0;
    }
    if binding
        .tx_counters
        .pending_direct_tx_no_frame_fallback_packets
        != 0
    {
        binding.live.direct_tx_no_frame_fallback_packets.fetch_add(
            binding
                .tx_counters
                .pending_direct_tx_no_frame_fallback_packets,
            Ordering::Relaxed,
        );
        binding
            .tx_counters
            .pending_direct_tx_no_frame_fallback_packets = 0;
    }
    if binding.tx_counters.pending_direct_tx_build_fallback_packets != 0 {
        binding.live.direct_tx_build_fallback_packets.fetch_add(
            binding.tx_counters.pending_direct_tx_build_fallback_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_direct_tx_build_fallback_packets = 0;
    }
    if binding
        .tx_counters
        .pending_direct_tx_disallowed_fallback_packets
        != 0
    {
        binding
            .live
            .direct_tx_disallowed_fallback_packets
            .fetch_add(
                binding
                    .tx_counters
                    .pending_direct_tx_disallowed_fallback_packets,
                Ordering::Relaxed,
            );
        binding
            .tx_counters
            .pending_direct_tx_disallowed_fallback_packets = 0;
    }
    if binding.flow.flow_cache.hits != 0 {
        binding
            .live
            .flow_cache_hits
            .fetch_add(binding.flow.flow_cache.hits, Ordering::Relaxed);
        binding.flow.flow_cache.hits = 0;
    }
    if binding.flow.flow_cache.misses != 0 {
        binding
            .live
            .flow_cache_misses
            .fetch_add(binding.flow.flow_cache.misses, Ordering::Relaxed);
        binding.flow.flow_cache.misses = 0;
    }
    if binding.flow.flow_cache.evictions != 0 {
        binding
            .live
            .flow_cache_evictions
            .fetch_add(binding.flow.flow_cache.evictions, Ordering::Relaxed);
        binding.flow.flow_cache.evictions = 0;
    }
    // #16220: fold the per-arm breakdown alongside the aggregate so the
    // operator surface can name the eviction arm.
    for (arm, slot) in binding.flow.flow_cache.evictions_by_arm.iter_mut().enumerate() {
        if *slot != 0 {
            binding.live.flow_cache_evictions_by_arm[arm].fetch_add(*slot, Ordering::Relaxed);
            *slot = 0;
        }
    }
    // #918: surface collision-driven evictions distinctly from
    // stale-on-lookup evictions so the post-merge acceptance gate
    // (`collision_evictions / hits < 1 %` under 100E100M load) is
    // observable from the standard binding-counter snapshot.
    if binding.flow.flow_cache.collision_evictions != 0 {
        binding.live.flow_cache_collision_evictions.fetch_add(
            binding.flow.flow_cache.collision_evictions,
            Ordering::Relaxed,
        );
        binding.flow.flow_cache.collision_evictions = 0;
    }
    // #1219/#1294: advance the flow_cache active-flow epoch and publish
    // the count for the harness's structural CoV gate. Hot polling uses the
    // debug counter; RX-empty idle polling uses the wall-clock cadence in
    // `update_binding_idle_debug_state`. With ACTIVE_WINDOW_EPOCHS = 10 the
    // active-flow window is ~650ms. u16 epoch wraparound occurs at 65536
    // ticks × 65ms ≈ 71 minutes; epoch 0 is reserved as the "never touched"
    // sentinel and skipped by tick_advance_epoch.
    binding.flow.flow_cache.tick_advance_epoch();
    let (active_flow_count, flow_debug_entries, cos_counts, flow_map_truncated) = binding
        .flow
        .flow_cache
        .active_flow_debug_entries(FLOW_WORKER_MAP_MAX_PER_BINDING);
    binding
        .live
        .active_flow_count
        .store(active_flow_count, Ordering::Relaxed);
    let interface = binding.interface.clone();
    binding.live.publish_flow_worker_map(
        flow_debug_entries
            .into_iter()
            .map(|entry| crate::protocol::FlowWorkerStatus {
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: interface.clone(),
                ifindex: binding.ifindex,
                ingress_ifindex: entry.ingress_ifindex,
                egress_ifindex: entry.egress_ifindex,
                tx_ifindex: entry.tx_ifindex,
                session_key: entry.session_key,
                forward_wire_key: entry.forward_wire_key,
                reverse_canonical_key: entry.reverse_canonical_key,
                cos_queue_id: entry.cos_queue_id,
                dscp_rewrite: entry.dscp_rewrite,
                age_epochs: entry.age_epochs,
                observed_bytes: entry.observed_bytes,
            })
            .collect(),
        flow_map_truncated,
    );
    binding.live.publish_cos_active_flow_counts(
        cos_counts
            .into_iter()
            .map(|entry| crate::protocol::CoSActiveFlowCountStatus {
                ifindex: entry.ifindex,
                queue_id: entry.queue_id,
                worker_id: binding.worker_id,
                active_flow_count: entry.active_flow_count,
            })
            .collect(),
    );
    // #941 Work item D + #943 + #hb166 T-6(a): flush each queue's
    // per-queue scratch counters (hard-cap overrides, regular V_min
    // throttles, AND suspended-batch count) into the binding-wide
    // AtomicU64s. Mirrors the flow_cache_collision_evictions pattern.
    // Single-writer (worker thread) on both ends, so no atomicity issue.
    // The body is in `flush_v_min_scratches_into` so it's directly
    // unit-testable without needing to construct a full `BindingWorker`.
    flush_v_min_scratches_into(
        binding.cos.cos_interfaces.values_mut(),
        &binding.live.v_min_throttle_hard_cap_overrides,
        &binding.live.v_min_throttles,
        &binding.live.v_min_suspended_batches,
    );
}

/// Flush each queue's per-queue V_min scratch counters
/// (`v_min_hard_cap_overrides_scratch` + `v_min_throttles_scratch` +
/// `v_min_suspended_batches_scratch`) into the binding-wide `AtomicU64`s
/// and zero the scratches. Single pass over `roots`, single-writer
/// discipline. Extracted from `update_binding_debug_state` so the flush
/// is testable without constructing a `BindingWorker` (which has ~40
/// fields).
pub(in crate::afxdp) fn flush_v_min_scratches_into<'a, I>(
    roots: I,
    hard_cap_target: &AtomicU64,
    throttles_target: &AtomicU64,
    suspended_batches_target: &AtomicU64,
) where
    I: IntoIterator<Item = &'a mut crate::afxdp::types::CoSInterfaceRuntime>,
{
    let mut hard_cap_overrides_total = 0u64;
    let mut throttles_total = 0u64;
    let mut suspended_batches_total = 0u64;
    for root in roots {
        for queue in &mut root.queues {
            if queue.v_min.v_min_hard_cap_overrides_scratch != 0 {
                hard_cap_overrides_total = hard_cap_overrides_total
                    .saturating_add(u64::from(queue.v_min.v_min_hard_cap_overrides_scratch));
                queue.v_min.v_min_hard_cap_overrides_scratch = 0;
            }
            if queue.v_min.v_min_throttles_scratch != 0 {
                throttles_total =
                    throttles_total.saturating_add(u64::from(queue.v_min.v_min_throttles_scratch));
                queue.v_min.v_min_throttles_scratch = 0;
            }
            // #hb166 T-6(a): flush the suspended-batch scratch too.
            if queue.v_min.v_min_suspended_batches_scratch != 0 {
                suspended_batches_total = suspended_batches_total
                    .saturating_add(u64::from(queue.v_min.v_min_suspended_batches_scratch));
                queue.v_min.v_min_suspended_batches_scratch = 0;
            }
        }
    }
    if hard_cap_overrides_total != 0 {
        hard_cap_target.fetch_add(hard_cap_overrides_total, Ordering::Relaxed);
    }
    if throttles_total != 0 {
        throttles_target.fetch_add(throttles_total, Ordering::Relaxed);
    }
    if suspended_batches_total != 0 {
        suspended_batches_target.fetch_add(suspended_batches_total, Ordering::Relaxed);
    }
}
