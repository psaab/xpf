//! #1328 Phase 2 — binding counter zero-pass.
//!
//! Pure code motion of the per-binding field-reset loop from the
//! pre-#1328 monolithic `Coordinator::reconcile` body (lines
//! 342–394 of the old `mod.rs`). Touches only counter fields and
//! `bound`/`xsk_registered`/`ready`/`last_error`/`socket_fd`.
use crate::protocol::BindingStatus;

pub(super) fn reset_binding_counters(bindings: &mut [BindingStatus]) {
    for binding in bindings.iter_mut() {
        binding.bound = false;
        binding.xsk_registered = false;
        binding.socket_fd = 0;
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
        binding.martian_dropped = 0;
        binding.ipv6_ext_header_dropped = 0;
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
        binding.v_min_throttle_hard_cap_overrides = 0;
        binding.v_min_throttles = 0;
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
        binding.last_error.clear();
        binding.ready = false;
    }
}

#[cfg(test)]
mod reset_9956_tests {
    use super::*;

    #[test]
    fn reset_binding_counters_clears_the_flowless_family_9956() {
        // #9956 F-051: companion to the round-trip cell in
        // `refresh_bindings_9956_tests.rs` (which cannot name this
        // `pub(super)`-scoped zero-pass). Neither reset half has a census;
        // an omitted field here would report a frozen flowless count on a
        // rebound slot.
        let mut binding = BindingStatus::default();
        binding.flowless_forward_packets = 9;
        binding.flowless_forward_bytes = 900;
        reset_binding_counters(std::slice::from_mut(&mut binding));
        assert_eq!(
            (
                binding.flowless_forward_packets,
                binding.flowless_forward_bytes
            ),
            (0, 0),
            "reset_binding_counters must clear the flowless family"
        );
    }
}
