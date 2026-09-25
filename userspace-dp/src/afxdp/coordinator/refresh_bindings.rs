//! #1328 Phase 2 — `refresh_bindings` dispatcher + per-branch
//! helpers.
//!
//! Splits the pre-#1328 326-LOC `Coordinator::refresh_bindings`
//! into:
//!   - `copy_live_snapshot(binding, snap)` — bound-slot branch.
//!     Takes `BindingLiveSnapshot` BY VALUE (it owns `String`
//!     fields). The two latency histogram `Vec<u64>` are resized
//!     in place via `.resize() + .copy_from_slice()` so the
//!     existing backing storage on `BindingStatus` is reused —
//!     no per-status-poll allocation.
//!   - `zero_unbound_slot(binding)` — unbound-slot branch, pure
//!     code motion of the field zero-out.
//!
//! The public `Coordinator::refresh_bindings(bindings)` method
//! lives in this file as a thin dispatcher and calls
//! `refresh_cos_owner_worker_map_from_binding_statuses` at the
//! tail, preserving the pre-#1328 contract.
//!
//! #8558 adds ONE exception to the unbound-slot branch: after
//! `zero_unbound_slot` has zeroed the slot, the dispatcher restores
//! `last_error` from `Coordinator::last_bind_failures` if the last
//! fail-closed bring-up recorded a TERMINAL bind cause for that slot.
//! Without it the `"Device or resource busy"` a bind returned was
//! erased before any status left the helper — and since
//! `hasBusyBindingsWedgeLocked`'s `busyErr` term is a substring match
//! on exactly that field, auto-rebind recovery could never fire for
//! the fault it exists for. The restore lives HERE, in the dispatcher,
//! rather than inside `zero_unbound_slot`, because this function runs
//! on EVERY control response: a cause restored anywhere else is erased
//! by the next ~1 Hz status poll, well inside the 5s dwell the Go
//! predicate requires before it acts.
// Use the coordinator's afxdp scope (super::* from coordinator
// pulls in all afxdp items; we re-use the same pattern here).
use super::*;
use super::super::*;

impl Coordinator {
    pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.workers.live.get(&binding.slot) {
                let snap = live.snapshot();
                copy_live_snapshot(binding, snap);
            } else {
                zero_unbound_slot(binding);
                // #8558: re-publish the TERMINAL bind-failure cause for this
                // slot, if the last fail-closed bring-up recorded one.
                //
                // `zero_unbound_slot` ends with `last_error.clear()`, which is
                // right for a slot that is unbound because forwarding is
                // disarmed or the config was cleared — and destructive for the
                // one case where the cause is the whole point. This runs on
                // EVERY control response, so restoring the cause anywhere else
                // would be erased within one ~1 Hz status poll, well inside the
                // 5s dwell the Go wedge predicate requires before it acts.
                //
                // Restoring AFTER the zero-out rather than teaching
                // `zero_unbound_slot` to skip the field keeps that helper's
                // contract intact ("this slot has no worker: zero its runtime")
                // and makes the exception explicit at the one call site that
                // has the map. `clear()` + `push_str` rather than an owned
                // clone so the existing `String` allocation is reused, matching
                // the rest of the refresh.
                if let Some(reason) = self.last_bind_failures.get(&binding.slot) {
                    binding.last_error.clear();
                    binding.last_error.push_str(reason);
                }
            }
        }
        self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
    }
}

/// Copy a freshly-taken `BindingLiveSnapshot` into the
/// operator-facing `BindingStatus`. Pre-#1328 this was the
/// `if let Some(live) = ...` branch inside `refresh_bindings`;
/// the field-for-field assignment list is preserved verbatim.
///
/// Takes the snapshot by VALUE — it owns `String` fields
/// (`xsk_bind_mode`, `shared_umem_*`, `last_error`) so passing
/// by reference would force per-poll clones. The latency
/// histograms are copied via `.resize() + .copy_from_slice()`
/// against the existing `Vec<u64>` storage in `BindingStatus`
/// to avoid reallocating when capacity already matches.
fn copy_live_snapshot(binding: &mut BindingStatus, snap: BindingLiveSnapshot) {
    if snap.bound && !binding.bound {
        eprintln!(
            "refresh_bindings: slot={} transitioning bound=false->true fd={}",
            binding.slot, snap.socket_fd
        );
    }
    binding.bound = snap.bound;
    binding.xsk_registered = snap.xsk_registered;
    binding.xsk_bind_mode = snap.xsk_bind_mode;
    binding.zero_copy = snap.zero_copy;
    binding.socket_fd = snap.socket_fd;
    binding.socket_ifindex = snap.socket_ifindex;
    binding.socket_queue_id = snap.socket_queue_id;
    binding.socket_bind_flags = snap.socket_bind_flags;
    binding.shared_umem_mode = snap.shared_umem_mode;
    binding.shared_umem_group = snap.shared_umem_group;
    binding.shared_umem_socket_role = snap.shared_umem_socket_role;
    binding.shared_umem_disabled_reason = snap.shared_umem_disabled_reason;
    binding.rx_packets = snap.rx_packets;
    binding.rx_bytes = snap.rx_bytes;
    binding.rx_batches = snap.rx_batches;
    binding.rx_wakeups = snap.rx_wakeups;
    binding.metadata_packets = snap.metadata_packets;
    binding.metadata_errors = snap.metadata_errors;
    binding.validated_packets = snap.validated_packets;
    binding.validated_bytes = snap.validated_bytes;
    binding.local_delivery_packets = snap.local_delivery_packets;
    binding.forward_candidate_packets = snap.forward_candidate_packets;
    binding.flowless_forward_packets = snap.flowless_forward_packets;
    binding.flowless_forward_bytes = snap.flowless_forward_bytes;
    binding.route_miss_packets = snap.route_miss_packets;
    binding.martian_dropped = snap.martian_dropped;
    binding.ipv6_ext_header_dropped = snap.ipv6_ext_header_dropped;
    binding.v4_mapped_ipv6_dropped = snap.v4_mapped_ipv6_dropped;
    binding.umem_slice_dropped = snap.umem_slice_dropped;
    binding.unknown_vlan_dropped = snap.unknown_vlan_dropped;
    binding.dst_mac_dropped = snap.dst_mac_dropped;
    binding.neighbor_miss_packets = snap.neighbor_miss_packets;
    binding.discard_route_packets = snap.discard_route_packets;
    binding.next_table_packets = snap.next_table_packets;
    binding.table_unavailable_packets = snap.table_unavailable_packets;
    binding.exception_packets = snap.exception_packets;
    binding.config_gen_mismatches = snap.config_gen_mismatches;
    binding.fib_gen_mismatches = snap.fib_gen_mismatches;
    binding.unsupported_packets = snap.unsupported_packets;
    binding.flow_cache_hits = snap.flow_cache_hits;
    binding.flow_cache_misses = snap.flow_cache_misses;
    binding.flow_cache_evictions = snap.flow_cache_evictions;
    binding.flow_cache_collision_evictions = snap.flow_cache_collision_evictions;
    // #1219: bridge active_flow_count from BindingLiveSnapshot
    // into BindingStatus so it reaches the wire-visible status.
    binding.active_flow_count = snap.active_flow_count;
    binding.flow_cache_capacity = snap.flow_cache_capacity;
    // #941 Work item D / #943: bridge V_min counters from
    // BindingLiveSnapshot through to BindingStatus so the
    // wire surface (BindingCountersSnapshot) sees them.
    binding.v_min_throttle_hard_cap_overrides = snap.v_min_throttle_hard_cap_overrides;
    binding.v_min_throttles = snap.v_min_throttles;
    binding.v_min_suspended_batches = snap.v_min_suspended_batches;
    binding.session_hits = snap.session_hits;
    binding.session_misses = snap.session_misses;
    binding.session_creates = snap.session_creates;
    binding.session_expires = snap.session_expires;
    binding.session_delta_pending = snap.session_delta_pending;
    binding.session_delta_generated = snap.session_delta_generated;
    binding.session_delta_dropped = snap.session_delta_dropped;
    binding.session_delta_high_water = snap.session_delta_high_water;
    binding.session_delta_drained = snap.session_delta_drained;
    binding.policy_denied_packets = snap.policy_denied_packets;
    binding.host_inbound_denied_packets = snap.host_inbound_denied_packets;
    binding.screen_drops = snap.screen_drops;
    binding.screen_reason_drops = snap.screen_reason_drops;
    binding.syn_cookie_challenges = snap.syn_cookie_challenges;
    binding.syn_cookie_secret_unavailable = snap.syn_cookie_secret_unavailable;
    binding.syn_cookie_syn_ack_sent = snap.syn_cookie_syn_ack_sent;
    binding.syn_cookie_ack_rst_sent = snap.syn_cookie_ack_rst_sent;
    binding.syn_cookie_reply_budget_drops = snap.syn_cookie_reply_budget_drops;
    binding.syn_cookie_ack_valid = snap.syn_cookie_ack_valid;
    binding.syn_cookie_ack_invalid = snap.syn_cookie_ack_invalid;
    binding.syn_cookie_bypass = snap.syn_cookie_bypass;
    binding.policy_reject_sent = snap.policy_reject_sent;
    binding.filter_reject_sent = snap.filter_reject_sent;
    binding.policy_reject_reply_budget_drops = snap.policy_reject_reply_budget_drops;
    binding.filter_reject_reply_budget_drops = snap.filter_reject_reply_budget_drops;
    binding.policy_reject_rate_limit_drops = snap.policy_reject_rate_limit_drops;
    binding.filter_reject_rate_limit_drops = snap.filter_reject_rate_limit_drops;
    binding.time_exceeded_output_filter_drops = snap.time_exceeded_output_filter_drops;
    binding.policy_reject_output_filter_drops = snap.policy_reject_output_filter_drops;
    binding.filter_reject_output_filter_drops = snap.filter_reject_output_filter_drops;
    binding.syn_cookie_output_filter_drops = snap.syn_cookie_output_filter_drops;
    binding.ptb_output_filter_drops = snap.ptb_output_filter_drops;
    binding.generated_reply_classify_parse_errors = snap.generated_reply_classify_parse_errors;
    binding.snat_packets = snap.snat_packets;
    binding.dnat_packets = snap.dnat_packets;
    binding.nat64_translations = snap.nat64_translations;
    binding.nat64_no_source_pool = snap.nat64_no_source_pool;
    binding.nat64_pool_exhausted = snap.nat64_pool_exhausted;
    binding.nat64_frag_dropped = snap.nat64_frag_dropped;
    binding.nat64_frag_assoc_evicted = snap.nat64_frag_assoc_evicted;
    binding.nat64_ineligible_source = snap.nat64_ineligible_source;
    binding.nat64_ineligible_dest = snap.nat64_ineligible_dest;
    binding.nat64_exthdr_ineligible = snap.nat64_exthdr_ineligible;
    binding.nat64_tunnel_encap_unsupported = snap.nat64_tunnel_encap_unsupported;
    binding.nat64_ineligible_protocol = snap.nat64_ineligible_protocol;
    binding.nat_alloc_fail = snap.nat_alloc_fail;
    binding.nat_frag_untranslated_dropped = snap.nat_frag_untranslated_dropped;
    binding.frag_overlap_dropped = snap.frag_overlap_dropped;
    binding.frag_overlap_overflow_dropped = snap.frag_overlap_overflow_dropped;
    binding.frag_overlap_shard_full_dropped = snap.frag_overlap_shard_full_dropped;
    binding.frag_overlap_post_nat_dropped = snap.frag_overlap_post_nat_dropped;
    binding.frag_overlap_max_lifetime_evictions = snap.frag_overlap_max_lifetime_evictions;
    binding.slow_path_packets = snap.slow_path_packets;
    binding.slow_path_bytes = snap.slow_path_bytes;
    binding.slow_path_local_delivery_packets = snap.slow_path_local_delivery_packets;
    binding.slow_path_missing_neighbor_packets = snap.slow_path_missing_neighbor_packets;
    binding.slow_path_no_route_packets = snap.slow_path_no_route_packets;
    binding.slow_path_next_table_packets = snap.slow_path_next_table_packets;
    binding.next_table_unsupported_drops = snap.next_table_unsupported_drops;
    binding.table_unavailable_drops = snap.table_unavailable_drops;
    binding.slow_path_forward_build_packets = snap.slow_path_forward_build_packets;
    binding.slow_path_drops = snap.slow_path_drops;
    binding.slow_path_rate_limited = snap.slow_path_rate_limited;
    binding.tunnel_encap_unresolved_drops = snap.tunnel_encap_unresolved_drops;
    binding.fabric_redirect_unsendable_drops = snap.fabric_redirect_unsendable_drops;
    binding.kernel_rx_dropped = snap.kernel_rx_dropped;
    binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
    binding.tx_packets = snap.tx_packets;
    binding.tx_bytes = snap.tx_bytes;
    binding.tx_completions = snap.tx_completions;
    binding.tx_errors = snap.tx_errors;
    binding.tx_shared_recycle_unknown_slot_drops = snap.tx_shared_recycle_unknown_slot_drops;
    binding.tx_shared_recycle_unknown_slot_rescued = snap.tx_shared_recycle_unknown_slot_rescued;
    binding.redirect_inbox_overflow_drops = snap.redirect_inbox_overflow_drops;
    binding.pending_tx_local_overflow_drops = snap.pending_tx_local_overflow_drops;
    binding.tx_submit_error_drops = snap.tx_submit_error_drops;
    binding.mirrored_packets = snap.mirrored_packets;
    binding.mirrored_bytes = snap.mirrored_bytes;
    binding.mirror_drops_no_frame = snap.mirror_drops_no_frame;
    binding.mirror_drops_tx_frame_reserve = snap.mirror_drops_tx_frame_reserve;
    binding.mirror_drops_no_binding = snap.mirror_drops_no_binding;
    binding.mirror_drops_queue_full = snap.mirror_drops_queue_full;
    binding.mirror_drops_queue_full_same_worker = snap.mirror_drops_queue_full_same_worker;
    binding.mirror_drops_queue_full_cross_worker = snap.mirror_drops_queue_full_cross_worker;
    binding.post_drain_backup_bytes = snap.post_drain_backup_bytes;
    binding.drain_sent_bytes_shaped_unconditional = snap.drain_sent_bytes_shaped_unconditional;
    binding.post_drain_backup_cos_drops = snap.post_drain_backup_cos_drops;
    binding.post_drain_backup_cos_drop_bytes = snap.post_drain_backup_cos_drop_bytes;
    // #710: `snap.no_owner_binding_drops` is not copied into
    // per-binding status — it is summed across all bindings
    // into `ProcessStatus::cos_no_owner_binding_drops_total`
    // at the refresh_status callsite, which is the correct
    // operator-facing scope for this counter.
    binding.direct_tx_packets = snap.direct_tx_packets;
    binding.copy_tx_packets = snap.copy_tx_packets;
    binding.in_place_tx_packets = snap.in_place_tx_packets;
    binding.in_place_vlan_push_desc_packets = snap.in_place_vlan_push_desc_packets;
    binding.in_place_vlan_pop_desc_packets = snap.in_place_vlan_pop_desc_packets;
    binding.in_place_vlan_push_no_headroom_packets = snap.in_place_vlan_push_no_headroom_packets;
    binding.in_place_l2_memmove_fallback_packets = snap.in_place_l2_memmove_fallback_packets;
    binding.direct_tx_no_frame_fallback_packets = snap.direct_tx_no_frame_fallback_packets;
    binding.direct_tx_build_fallback_packets = snap.direct_tx_build_fallback_packets;
    binding.direct_tx_disallowed_fallback_packets = snap.direct_tx_disallowed_fallback_packets;
    binding.debug_pending_fill_frames = snap.debug_pending_fill_frames;
    binding.debug_spare_fill_frames = 0;
    binding.debug_free_tx_frames = snap.debug_free_tx_frames;
    binding.debug_pending_tx_prepared = snap.debug_pending_tx_prepared;
    binding.debug_pending_tx_local = snap.debug_pending_tx_local;
    binding.debug_outstanding_tx = snap.debug_outstanding_tx;
    binding.tx_completion_ring_available = snap.tx_completion_ring_available;
    binding.tx_completion_ring_available_max = snap.tx_completion_ring_available_max;
    binding.debug_in_flight_recycles = snap.debug_in_flight_recycles;
    // #878: per-binding capacities + in-flight gauge flow
    // into BindingStatus so the daemon's fwdstatus
    // Buffer% can compute UMEM and TX-ring fill ratios.
    binding.umem_total_frames = snap.umem_total_frames;
    binding.tx_ring_capacity = snap.tx_ring_capacity;
    binding.umem_inflight_frames = snap.umem_inflight_frames;
    // #802: ring-pressure counters — atomic mirrors of
    // worker-local counters, published on the worker's
    // per-second debug tick. `outstanding_tx` aliases
    // `debug_outstanding_tx` for the operator-facing name.
    binding.dbg_tx_ring_full = snap.dbg_tx_ring_full;
    binding.dbg_sendto_enobufs = snap.dbg_sendto_enobufs;
    // #804: split counters — bound-pending FIFO vs CoS
    // queue admission. Pre-#804 a single `dbg_pending_overflow`
    // was published; the wire name was removed because
    // the semantics were ambiguous for operators.
    binding.dbg_bound_pending_overflow = snap.dbg_bound_pending_overflow;
    binding.dbg_cos_queue_overflow = snap.dbg_cos_queue_overflow;
    binding.rx_fill_ring_empty_descs = snap.rx_fill_ring_empty_descs;
    binding.outstanding_tx = snap.debug_outstanding_tx;
    // #812: per-queue TX submit→completion latency
    // telemetry. Materialize the fixed-cap snapshot
    // array into a freshly-owned Vec<u64> on the wire
    // boundary — reuses the buffer in-place to avoid
    // allocator churn when the BindingStatus entry is
    // refreshed on the ~1s poll cadence.
    binding
        .tx_submit_latency_hist
        .resize(snap.tx_submit_latency_hist.len(), 0);
    binding
        .tx_submit_latency_hist
        .copy_from_slice(&snap.tx_submit_latency_hist);
    binding.tx_submit_latency_count = snap.tx_submit_latency_count;
    binding.tx_submit_latency_sum_ns = snap.tx_submit_latency_sum_ns;
    // #825: per-kick `sendto` latency telemetry mirrors
    // the #812 submit-latency copy path above. Resize
    // the operator-facing Vec<u64> to match the
    // snapshot's fixed-cap array, then copy bucket
    // counts and scalars. `tx_kick_retry_count` is the
    // EAGAIN/EWOULDBLOCK tally (T1 ring-pushback).
    binding
        .tx_kick_latency_hist
        .resize(snap.tx_kick_latency_hist.len(), 0);
    binding
        .tx_kick_latency_hist
        .copy_from_slice(&snap.tx_kick_latency_hist);
    binding.tx_kick_latency_count = snap.tx_kick_latency_count;
    binding.tx_kick_latency_sum_ns = snap.tx_kick_latency_sum_ns;
    binding.tx_kick_retry_count = snap.tx_kick_retry_count;
    binding.last_heartbeat = snap.last_heartbeat;
    binding.last_error = snap.last_error;
    // #2332: gate readiness on the monotonic-clock freshness verdict
    // (`snap.heartbeat_fresh`), computed at snapshot time from
    // CLOCK_MONOTONIC readings. NEVER re-derive freshness from the
    // wall-clock `snap.last_heartbeat` here — that re-introduces the
    // clock-step bug (a forward CLOCK_REALTIME step between snapshot and
    // this check would falsely mark a healthy binding unready → spurious
    // failover). Rust sibling of the Go fix in #1792.
    binding.ready =
        binding.registered && binding.bound && binding.xsk_registered && snap.heartbeat_fresh;
}

/// Zero out a `BindingStatus` whose slot has no live worker
/// (unregistered or stopped). Pure code motion of the
/// `else` branch from pre-#1328 `refresh_bindings`. Uses
/// `.clear()` on `Vec`/`String` fields to retain capacity —
/// avoids per-poll allocation when the same slot transitions
/// back to bound.
fn zero_unbound_slot(binding: &mut BindingStatus) {
    binding.bound = false;
    binding.xsk_registered = false;
    binding.xsk_bind_mode.clear();
    binding.zero_copy = false;
    binding.socket_fd = 0;
    binding.socket_ifindex = 0;
    binding.socket_queue_id = 0;
    binding.socket_bind_flags = 0;
    // #5190 (A1-b8-F6): the shared-UMEM descriptors are COPIED by
    // `copy_live_snapshot` above but were never reset here, so an
    // unbound slot kept advertising the last worker's shared-UMEM
    // mode/group/socket-role/disabled-reason — operator-visible state
    // describing a socket that no longer exists. `.clear()` (not
    // `= String::new()`) retains the allocation, matching the
    // `xsk_bind_mode` treatment two lines up.
    binding.shared_umem_mode.clear();
    binding.shared_umem_group.clear();
    binding.shared_umem_socket_role.clear();
    binding.shared_umem_disabled_reason.clear();
    binding.rx_packets = 0;
    binding.rx_bytes = 0;
    binding.rx_batches = 0;
    binding.rx_wakeups = 0;
    binding.metadata_packets = 0;
    binding.metadata_errors = 0;
    binding.validated_packets = 0;
    binding.validated_bytes = 0;
    binding.local_delivery_packets = 0;
    binding.forward_candidate_packets = 0;
    binding.flowless_forward_packets = 0;
    binding.flowless_forward_bytes = 0;
    binding.route_miss_packets = 0;
    // #5190 (A1-b8-F6): both drop counters are copied by
    // `copy_live_snapshot` but were missed here when they were added, so
    // an unbound slot reported a frozen non-zero drop count alongside
    // rx_packets == 0 — an inconsistency an operator reads as "this
    // dead slot is still dropping traffic".
    binding.martian_dropped = 0;
    binding.ipv6_ext_header_dropped = 0;
    binding.v4_mapped_ipv6_dropped = 0;
    binding.umem_slice_dropped = 0;
    binding.unknown_vlan_dropped = 0;
    binding.dst_mac_dropped = 0;
    binding.neighbor_miss_packets = 0;
    binding.discard_route_packets = 0;
    binding.next_table_packets = 0;
    binding.table_unavailable_packets = 0;
    binding.exception_packets = 0;
    binding.config_gen_mismatches = 0;
    binding.fib_gen_mismatches = 0;
    binding.unsupported_packets = 0;
    binding.flow_cache_hits = 0;
    binding.flow_cache_misses = 0;
    binding.flow_cache_evictions = 0;
    binding.flow_cache_collision_evictions = 0;
    binding.active_flow_count = 0;
    binding.flow_cache_capacity = 0;
    binding.v_min_throttle_hard_cap_overrides = 0;
    binding.v_min_throttles = 0;
    binding.v_min_suspended_batches = 0;
    binding.session_hits = 0;
    binding.session_misses = 0;
    binding.session_creates = 0;
    binding.session_expires = 0;
    binding.session_delta_pending = 0;
    binding.session_delta_generated = 0;
    binding.session_delta_dropped = 0;
    binding.session_delta_high_water = 0;
    binding.session_delta_drained = 0;
    binding.policy_denied_packets = 0;
    binding.host_inbound_denied_packets = 0;
    binding.screen_drops = 0;
    binding.screen_reason_drops = [0; crate::screen::SCREEN_REASON_DROP_COUNT];
    binding.syn_cookie_challenges = 0;
    binding.syn_cookie_secret_unavailable = 0;
    binding.syn_cookie_syn_ack_sent = 0;
    binding.syn_cookie_ack_rst_sent = 0;
    binding.syn_cookie_reply_budget_drops = 0;
    binding.syn_cookie_ack_valid = 0;
    binding.syn_cookie_ack_invalid = 0;
    binding.syn_cookie_bypass = 0;
    binding.policy_reject_sent = 0;
    binding.filter_reject_sent = 0;
    binding.policy_reject_reply_budget_drops = 0;
    binding.filter_reject_reply_budget_drops = 0;
    binding.policy_reject_rate_limit_drops = 0;
    binding.filter_reject_rate_limit_drops = 0;
    binding.time_exceeded_output_filter_drops = 0;
    binding.policy_reject_output_filter_drops = 0;
    binding.filter_reject_output_filter_drops = 0;
    binding.syn_cookie_output_filter_drops = 0;
    binding.ptb_output_filter_drops = 0;
    binding.generated_reply_classify_parse_errors = 0;
    binding.snat_packets = 0;
    binding.dnat_packets = 0;
    binding.nat64_translations = 0;
    binding.nat64_no_source_pool = 0;
    binding.nat64_pool_exhausted = 0;
    binding.nat64_frag_dropped = 0;
    binding.nat64_frag_assoc_evicted = 0;
    binding.nat64_ineligible_source = 0;
    binding.nat64_ineligible_dest = 0;
    binding.nat64_exthdr_ineligible = 0;
    binding.nat64_tunnel_encap_unsupported = 0;
    binding.nat64_ineligible_protocol = 0;
    binding.nat_alloc_fail = 0;
    binding.nat_frag_untranslated_dropped = 0;
    binding.frag_overlap_dropped = 0;
    binding.frag_overlap_overflow_dropped = 0;
    binding.frag_overlap_shard_full_dropped = 0;
    binding.frag_overlap_post_nat_dropped = 0;
    binding.frag_overlap_max_lifetime_evictions = 0;
    binding.slow_path_packets = 0;
    binding.slow_path_bytes = 0;
    binding.slow_path_local_delivery_packets = 0;
    binding.slow_path_missing_neighbor_packets = 0;
    binding.slow_path_no_route_packets = 0;
    binding.slow_path_next_table_packets = 0;
    binding.next_table_unsupported_drops = 0;
    binding.table_unavailable_drops = 0;
    binding.slow_path_forward_build_packets = 0;
    binding.slow_path_drops = 0;
    binding.slow_path_rate_limited = 0;
    binding.tunnel_encap_unresolved_drops = 0;
    binding.fabric_redirect_unsendable_drops = 0;
    binding.kernel_rx_dropped = 0;
    binding.kernel_rx_invalid_descs = 0;
    binding.tx_packets = 0;
    binding.tx_bytes = 0;
    binding.tx_completions = 0;
    binding.tx_errors = 0;
    binding.tx_shared_recycle_unknown_slot_drops = 0;
    binding.tx_shared_recycle_unknown_slot_rescued = 0;
    // Copilot finding (PR #1570): these three are subsets of
    // `tx_errors`. The pre-#1328 master `refresh_bindings` else-branch
    // also did not zero them, but leaving them stale when a slot
    // transitions to unbound produces inconsistent operator-visible
    // status (subset > 0 while `tx_errors == 0`). Adding the zeros
    // here as a consistency fix on top of pure code motion.
    binding.redirect_inbox_overflow_drops = 0;
    binding.pending_tx_local_overflow_drops = 0;
    binding.tx_submit_error_drops = 0;
    binding.mirrored_packets = 0;
    binding.mirrored_bytes = 0;
    binding.mirror_drops_no_frame = 0;
    binding.mirror_drops_tx_frame_reserve = 0;
    binding.mirror_drops_no_binding = 0;
    binding.mirror_drops_queue_full = 0;
    binding.mirror_drops_queue_full_same_worker = 0;
    binding.mirror_drops_queue_full_cross_worker = 0;
    binding.post_drain_backup_bytes = 0;
    binding.drain_sent_bytes_shaped_unconditional = 0;
    binding.post_drain_backup_cos_drops = 0;
    binding.post_drain_backup_cos_drop_bytes = 0;
    binding.direct_tx_packets = 0;
    binding.copy_tx_packets = 0;
    binding.in_place_tx_packets = 0;
    binding.in_place_vlan_push_desc_packets = 0;
    binding.in_place_vlan_pop_desc_packets = 0;
    binding.in_place_vlan_push_no_headroom_packets = 0;
    binding.in_place_l2_memmove_fallback_packets = 0;
    binding.direct_tx_no_frame_fallback_packets = 0;
    binding.direct_tx_build_fallback_packets = 0;
    binding.direct_tx_disallowed_fallback_packets = 0;
    binding.debug_pending_fill_frames = 0;
    binding.debug_spare_fill_frames = 0;
    binding.debug_free_tx_frames = 0;
    binding.debug_pending_tx_prepared = 0;
    binding.debug_pending_tx_local = 0;
    binding.debug_outstanding_tx = 0;
    binding.tx_completion_ring_available = 0;
    binding.tx_completion_ring_available_max = 0;
    binding.debug_in_flight_recycles = 0;
    // #878: capacities + in-flight gauge zero when the
    // binding has no live state (slot unregistered). The
    // daemon treats zero umem_total_frames as "unknown"
    // and falls back to the legacy Buffer% display.
    binding.umem_total_frames = 0;
    binding.tx_ring_capacity = 0;
    binding.umem_inflight_frames = 0;
    // #802: ring-pressure counters — zero when the binding
    // has no live state (unregistered slot).
    binding.dbg_tx_ring_full = 0;
    binding.dbg_sendto_enobufs = 0;
    binding.dbg_bound_pending_overflow = 0;
    binding.dbg_cos_queue_overflow = 0;
    binding.rx_fill_ring_empty_descs = 0;
    binding.outstanding_tx = 0;
    // #812: zero the submit-latency histogram when the
    // binding has no live state (unregistered slot).
    binding.tx_submit_latency_hist.clear();
    binding.tx_submit_latency_count = 0;
    binding.tx_submit_latency_sum_ns = 0;
    // #825: zero the kick-latency histogram + retry
    // counter when the binding has no live state.
    binding.tx_kick_latency_hist.clear();
    binding.tx_kick_latency_count = 0;
    binding.tx_kick_latency_sum_ns = 0;
    binding.tx_kick_retry_count = 0;
    binding.last_heartbeat = None;
    binding.last_error.clear();
    binding.ready = false;
}

// #9956 F-051: the flowless counter round-trip cell.
#[cfg(test)]
#[path = "refresh_bindings_9956_tests.rs"]
mod refresh_bindings_9956_tests;
