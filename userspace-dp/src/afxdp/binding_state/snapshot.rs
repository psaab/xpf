// Telemetry snapshot rendering for `BindingLiveState`. Extracted from
// `umem/mod.rs` (#1351) to separate operator-facing observability
// rendering from the UMEM frame-management hot path.
//
// `snapshot()` runs on operator-driven gRPC scrapes (≤1/s) via
// `coordinator::refresh_bindings` and the `Status` RPC path. The
// 270-LOC body assembles a `BindingLiveSnapshot` struct literal of
// ~120 `Relaxed`-load atomics in a single pass. Read-side tearing
// on the owner-profile histograms is acceptable per the §3.6 R2
// bounded-skew contract documented inline below.

use super::*;

impl BindingLiveState {
    pub(in crate::afxdp) fn snapshot(&self) -> BindingLiveSnapshot {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let session_delta_pending = self
            .pending_session_deltas
            .lock()
            .map(|pending| pending.len() as u64)
            .unwrap_or(0);
        let shared_umem_status = self
            .shared_umem_status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_default();
        // #6898 (A1-b5-F1): ONE load, both fields derived from it. These two
        // fields are two spellings of the same value -- the mode's name and
        // whether that mode is zero-copy -- so reading the atomic twice lets a
        // concurrent rebind land between them and publish a snapshot whose
        // `xsk_bind_mode` and `zero_copy` describe DIFFERENT modes. That is a
        // torn pair in an operator-facing status surface: `show` would report a
        // copy-mode bind as zero-copy, or the reverse, and the disagreement is
        // internal to one snapshot so nothing downstream can detect it.
        //
        // Relaxed remains correct -- the fields are independent status values,
        // not a release/acquire handshake -- but they must come from a single
        // observation of the atomic, not two.
        let bind_mode = XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed));
        BindingLiveSnapshot {
            bound: self.bound.load(Ordering::Relaxed),
            xsk_registered: self.xsk_registered.load(Ordering::Relaxed),
            xsk_bind_mode: bind_mode.as_str().to_string(),
            zero_copy: bind_mode.is_zerocopy(),
            socket_fd: self.socket_fd.load(Ordering::Relaxed),
            socket_ifindex: self.socket_ifindex.load(Ordering::Relaxed),
            socket_queue_id: self.socket_queue_id.load(Ordering::Relaxed),
            socket_bind_flags: self.socket_bind_flags.load(Ordering::Relaxed),
            shared_umem_mode: shared_umem_status.mode,
            shared_umem_group: shared_umem_status.group,
            shared_umem_socket_role: shared_umem_status.socket_role,
            shared_umem_disabled_reason: shared_umem_status.disabled_reason,
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_batches: self.rx_batches.load(Ordering::Relaxed),
            rx_wakeups: self.rx_wakeups.load(Ordering::Relaxed),
            metadata_packets: self.metadata_packets.load(Ordering::Relaxed),
            metadata_errors: self.metadata_errors.load(Ordering::Relaxed),
            validated_packets: self.validated_packets.load(Ordering::Relaxed),
            validated_bytes: self.validated_bytes.load(Ordering::Relaxed),
            local_delivery_packets: self.local_delivery_packets.load(Ordering::Relaxed),
            forward_candidate_packets: self.forward_candidate_packets.load(Ordering::Relaxed),
            flowless_forward_packets: self.flowless_forward_packets.load(Ordering::Relaxed),
            flowless_forward_bytes: self.flowless_forward_bytes.load(Ordering::Relaxed),
            route_miss_packets: self.route_miss_packets.load(Ordering::Relaxed),
            martian_dropped: self.martian_dropped.load(Ordering::Relaxed),
            ipv6_ext_header_dropped: self.ipv6_ext_header_dropped.load(Ordering::Relaxed),
            v4_mapped_ipv6_dropped: self.v4_mapped_ipv6_dropped.load(Ordering::Relaxed),
            umem_slice_dropped: self.umem_slice_dropped.load(Ordering::Relaxed),
            unknown_vlan_dropped: self.unknown_vlan_dropped.load(Ordering::Relaxed),
            dst_mac_dropped: self.dst_mac_dropped.load(Ordering::Relaxed),
            neighbor_miss_packets: self.neighbor_miss_packets.load(Ordering::Relaxed),
            discard_route_packets: self.discard_route_packets.load(Ordering::Relaxed),
            next_table_packets: self.next_table_packets.load(Ordering::Relaxed),
            table_unavailable_packets: self.table_unavailable_packets.load(Ordering::Relaxed),
            exception_packets: self.exception_packets.load(Ordering::Relaxed),
            config_gen_mismatches: self.config_gen_mismatches.load(Ordering::Relaxed),
            fib_gen_mismatches: self.fib_gen_mismatches.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            flow_cache_hits: self.flow_cache_hits.load(Ordering::Relaxed),
            flow_cache_misses: self.flow_cache_misses.load(Ordering::Relaxed),
            flow_cache_evictions: self.flow_cache_evictions.load(Ordering::Relaxed),
            flow_cache_collision_evictions: self
                .flow_cache_collision_evictions
                .load(Ordering::Relaxed),
            active_flow_count: self.active_flow_count.load(Ordering::Relaxed),
            flow_cache_capacity: self.flow_cache_capacity.load(Ordering::Relaxed),
            v_min_throttle_hard_cap_overrides: self
                .v_min_throttle_hard_cap_overrides
                .load(Ordering::Relaxed),
            v_min_throttles: self.v_min_throttles.load(Ordering::Relaxed),
            v_min_suspended_batches: self.v_min_suspended_batches.load(Ordering::Relaxed),
            session_hits: self.session_hits.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            session_creates: self.session_creates.load(Ordering::Relaxed),
            session_expires: self.session_expires.load(Ordering::Relaxed),
            session_delta_pending,
            session_delta_generated: self.session_delta_generated.load(Ordering::Relaxed),
            session_delta_dropped: self.session_delta_dropped.load(Ordering::Relaxed),
            session_delta_high_water: self.session_delta_high_water.load(Ordering::Relaxed),
            session_delta_drained: self.session_delta_drained.load(Ordering::Relaxed),
            policy_denied_packets: self.policy_denied_packets.load(Ordering::Relaxed),
            host_inbound_denied_packets: self
                .host_inbound_denied_packets
                .load(Ordering::Relaxed),
            screen_drops: self.screen_drops.load(Ordering::Relaxed),
            // #3343: snapshot each per-reason screen-drop atomic.
            screen_reason_drops: std::array::from_fn(|i| {
                self.screen_reason_drops[i].load(Ordering::Relaxed)
            }),
            syn_cookie_challenges: self.syn_cookie_challenges.load(Ordering::Relaxed),
            syn_cookie_secret_unavailable: self
                .syn_cookie_secret_unavailable
                .load(Ordering::Relaxed),
            syn_cookie_syn_ack_sent: self.syn_cookie_syn_ack_sent.load(Ordering::Relaxed),
            syn_cookie_ack_rst_sent: self.syn_cookie_ack_rst_sent.load(Ordering::Relaxed),
            syn_cookie_reply_budget_drops: self
                .syn_cookie_reply_budget_drops
                .load(Ordering::Relaxed),
            syn_cookie_ack_valid: self.syn_cookie_ack_valid.load(Ordering::Relaxed),
            syn_cookie_ack_invalid: self.syn_cookie_ack_invalid.load(Ordering::Relaxed),
            syn_cookie_bypass: self.syn_cookie_bypass.load(Ordering::Relaxed),
            policy_reject_sent: self.policy_reject_sent.load(Ordering::Relaxed),
            filter_reject_sent: self.filter_reject_sent.load(Ordering::Relaxed),
            policy_reject_reply_budget_drops: self
                .policy_reject_reply_budget_drops
                .load(Ordering::Relaxed),
            filter_reject_reply_budget_drops: self
                .filter_reject_reply_budget_drops
                .load(Ordering::Relaxed),
            policy_reject_rate_limit_drops: self
                .policy_reject_rate_limit_drops
                .load(Ordering::Relaxed),
            filter_reject_rate_limit_drops: self
                .filter_reject_rate_limit_drops
                .load(Ordering::Relaxed),
            time_exceeded_output_filter_drops: self
                .time_exceeded_output_filter_drops
                .load(Ordering::Relaxed),
            policy_reject_output_filter_drops: self
                .policy_reject_output_filter_drops
                .load(Ordering::Relaxed),
            filter_reject_output_filter_drops: self
                .filter_reject_output_filter_drops
                .load(Ordering::Relaxed),
            syn_cookie_output_filter_drops: self
                .syn_cookie_output_filter_drops
                .load(Ordering::Relaxed),
            ptb_output_filter_drops: self.ptb_output_filter_drops.load(Ordering::Relaxed),
            generated_reply_classify_parse_errors: self
                .generated_reply_classify_parse_errors
                .load(Ordering::Relaxed),
            snat_packets: self.snat_packets.load(Ordering::Relaxed),
            dnat_packets: self.dnat_packets.load(Ordering::Relaxed),
            nat64_translations: self.nat64_translations.load(Ordering::Relaxed),
            nat64_no_source_pool: self.nat64_no_source_pool.load(Ordering::Relaxed),
            nat64_pool_exhausted: self.nat64_pool_exhausted.load(Ordering::Relaxed),
            nat64_frag_dropped: self.nat64_frag_dropped.load(Ordering::Relaxed),
            nat64_frag_assoc_evicted: self.nat64_frag_assoc_evicted.load(Ordering::Relaxed),
            nat64_ineligible_source: self.nat64_ineligible_source.load(Ordering::Relaxed),
            nat64_ineligible_dest: self.nat64_ineligible_dest.load(Ordering::Relaxed),
            nat64_exthdr_ineligible: self.nat64_exthdr_ineligible.load(Ordering::Relaxed),
            nat64_tunnel_encap_unsupported: self
                .nat64_tunnel_encap_unsupported
                .load(Ordering::Relaxed),
            nat64_ineligible_protocol: self.nat64_ineligible_protocol.load(Ordering::Relaxed),
            nat_alloc_fail: self.nat_alloc_fail.load(Ordering::Relaxed),
            nat_frag_untranslated_dropped: self
                .nat_frag_untranslated_dropped
                .load(Ordering::Relaxed),
            frag_overlap_dropped: self.frag_overlap_dropped.load(Ordering::Relaxed),
            frag_overlap_overflow_dropped: self
                .frag_overlap_overflow_dropped
                .load(Ordering::Relaxed),
            frag_overlap_shard_full_dropped: self
                .frag_overlap_shard_full_dropped
                .load(Ordering::Relaxed),
            frag_overlap_post_nat_dropped: self
                .frag_overlap_post_nat_dropped
                .load(Ordering::Relaxed),
            frag_overlap_max_lifetime_evictions: self
                .frag_overlap_max_lifetime_evictions
                .load(Ordering::Relaxed),
            slow_path_packets: self.slow_path_packets.load(Ordering::Relaxed),
            slow_path_bytes: self.slow_path_bytes.load(Ordering::Relaxed),
            slow_path_local_delivery_packets: self
                .slow_path_local_delivery_packets
                .load(Ordering::Relaxed),
            slow_path_missing_neighbor_packets: self
                .slow_path_missing_neighbor_packets
                .load(Ordering::Relaxed),
            slow_path_no_route_packets: self.slow_path_no_route_packets.load(Ordering::Relaxed),
            slow_path_next_table_packets: self.slow_path_next_table_packets.load(Ordering::Relaxed),
            next_table_unsupported_drops: self.next_table_unsupported_drops.load(Ordering::Relaxed),
            table_unavailable_drops: self.table_unavailable_drops.load(Ordering::Relaxed),
            slow_path_forward_build_packets: self
                .slow_path_forward_build_packets
                .load(Ordering::Relaxed),
            slow_path_drops: self.slow_path_drops.load(Ordering::Relaxed),
            slow_path_rate_limited: self.slow_path_rate_limited.load(Ordering::Relaxed),
            tunnel_encap_unresolved_drops: self
                .tunnel_encap_unresolved_drops
                .load(Ordering::Relaxed),
            fabric_redirect_unsendable_drops: self
                .fabric_redirect_unsendable_drops
                .load(Ordering::Relaxed),
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_completions: self.tx_completions.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            tx_shared_recycle_unknown_slot_drops: self
                .tx_shared_recycle_unknown_slot_drops
                .load(Ordering::Relaxed),
            tx_shared_recycle_unknown_slot_rescued: self
                .tx_shared_recycle_unknown_slot_rescued
                .load(Ordering::Relaxed),
            redirect_inbox_overflow_drops: self
                .redirect_inbox_overflow_drops
                .load(Ordering::Relaxed),
            pending_tx_local_overflow_drops: self
                .pending_tx_local_overflow_drops
                .load(Ordering::Relaxed),
            tx_submit_error_drops: self.tx_submit_error_drops.load(Ordering::Relaxed),
            mirrored_packets: self.mirrored_packets.load(Ordering::Relaxed),
            mirrored_bytes: self.mirrored_bytes.load(Ordering::Relaxed),
            mirror_drops_no_frame: self.mirror_drops_no_frame.load(Ordering::Relaxed),
            mirror_drops_tx_frame_reserve: self
                .mirror_drops_tx_frame_reserve
                .load(Ordering::Relaxed),
            mirror_drops_no_binding: self.mirror_drops_no_binding.load(Ordering::Relaxed),
            mirror_drops_queue_full: self.mirror_drops_queue_full.load(Ordering::Relaxed),
            mirror_drops_queue_full_same_worker: self
                .mirror_drops_queue_full_same_worker
                .load(Ordering::Relaxed),
            mirror_drops_queue_full_cross_worker: self
                .mirror_drops_queue_full_cross_worker
                .load(Ordering::Relaxed),
            post_drain_backup_bytes: self
                .owner_profile_owner
                .post_drain_backup_bytes
                .load(Ordering::Relaxed),
            drain_sent_bytes_shaped_unconditional: self
                .owner_profile_owner
                .drain_sent_bytes_shaped_unconditional
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drops: self
                .owner_profile_owner
                .post_drain_backup_cos_drops
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drop_bytes: self
                .owner_profile_owner
                .post_drain_backup_cos_drop_bytes
                .load(Ordering::Relaxed),
            // Compile-time check: these four counters live on the
            // owner-only cacheline-isolated block to avoid ping-
            // pong with multi-writer overflow counters.
            // `no_owner_binding_drops` is read directly from the atomic
            // by `Coordinator::cos_no_owner_binding_drops_total()` — not
            // snapshotted here because it is not exposed per-binding.
            direct_tx_packets: self.direct_tx_packets.load(Ordering::Relaxed),
            copy_tx_packets: self.copy_tx_packets.load(Ordering::Relaxed),
            in_place_tx_packets: self.in_place_tx_packets.load(Ordering::Relaxed),
            in_place_vlan_push_desc_packets: self
                .in_place_vlan_push_desc_packets
                .load(Ordering::Relaxed),
            in_place_vlan_pop_desc_packets: self
                .in_place_vlan_pop_desc_packets
                .load(Ordering::Relaxed),
            in_place_vlan_push_no_headroom_packets: self
                .in_place_vlan_push_no_headroom_packets
                .load(Ordering::Relaxed),
            in_place_l2_memmove_fallback_packets: self
                .in_place_l2_memmove_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_no_frame_fallback_packets: self
                .direct_tx_no_frame_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_build_fallback_packets: self
                .direct_tx_build_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_disallowed_fallback_packets: self
                .direct_tx_disallowed_fallback_packets
                .load(Ordering::Relaxed),
            debug_pending_fill_frames: self.debug_pending_fill_frames.load(Ordering::Relaxed),
            debug_spare_fill_frames: self.debug_spare_fill_frames.load(Ordering::Relaxed),
            debug_free_tx_frames: self.debug_free_tx_frames.load(Ordering::Relaxed),
            debug_pending_tx_prepared: self.debug_pending_tx_prepared.load(Ordering::Relaxed),
            debug_pending_tx_local: self.debug_pending_tx_local.load(Ordering::Relaxed),
            debug_outstanding_tx: self.debug_outstanding_tx.load(Ordering::Relaxed),
            tx_completion_ring_available: self.tx_completion_ring_available.load(Ordering::Relaxed),
            tx_completion_ring_available_max: self
                .tx_completion_ring_available_max
                .load(Ordering::Relaxed),
            debug_in_flight_recycles: self.debug_in_flight_recycles.load(Ordering::Relaxed),
            // #878: per-binding UMEM/TX-ring capacities (set once at
            // worker startup) and current in-flight frames
            // (republished each per-second debug tick from the
            // worker thread). Zero on umem_total_frames means "not
            // yet published".
            umem_total_frames: self.umem_total_frames.load(Ordering::Relaxed),
            tx_ring_capacity: self.tx_ring_capacity.load(Ordering::Relaxed),
            umem_inflight_frames: self.umem_inflight_frames.load(Ordering::Relaxed),
            // #802: ring-pressure counters published from the worker's
            // periodic debug tick. Relaxed load is sufficient — these
            // are monotonic diagnostic counters, not part of any
            // load-bearing synchronization.
            dbg_tx_ring_full: self.dbg_tx_ring_full.load(Ordering::Relaxed),
            dbg_sendto_enobufs: self.dbg_sendto_enobufs.load(Ordering::Relaxed),
            dbg_bound_pending_overflow: self.dbg_bound_pending_overflow.load(Ordering::Relaxed),
            dbg_cos_queue_overflow: self.dbg_cos_queue_overflow.load(Ordering::Relaxed),
            rx_fill_ring_empty_descs: self.rx_fill_ring_empty_descs.load(Ordering::Relaxed),
            last_heartbeat: monotonic_timestamp_to_datetime(
                self.last_heartbeat.load(Ordering::Relaxed),
                now_mono,
                now_wall,
            ),
            // #2332: the load-bearing HA-liveness verdict is computed here,
            // in the CLOCK_MONOTONIC domain, from the worker-stamped
            // monotonic heartbeat (`last_heartbeat`, a `monotonic_nanos()`
            // value) and this snapshot's own monotonic `now_mono`. The
            // `last_heartbeat` DateTime<Utc> field above is back-projected
            // onto the wall clock for operator display ONLY — it must never
            // drive the freshness decision, because a wall-clock step would
            // poison it (Rust sibling of #1792).
            heartbeat_fresh: crate::afxdp::bpf_map::heartbeat_fresh_mono(
                self.last_heartbeat.load(Ordering::Relaxed),
                now_mono,
            ),
            // #4971 / #6145: `last_error` precedence — a genuine error
            // STRING (the mutex, written by the exceptional
            // drop / bind / reconcile paths via `set_error`) OUTRANKS
            // the lock-free expected-TX-retry hint. Only when the mutex
            // string is EMPTY do we fall back to the
            // `last_tx_retry_status` atomic, so an expected backpressure
            // reason stays visible in `show` output without the send hot
            // path ever taking the mutex.
            //
            // #6145 — intentional stale-masking: a prior exceptional
            // `TxError::Drop` (capacity / slice fault) leaves `last_error`
            // non-empty and is NOT cleared by the ongoing expected-retry
            // path (which only writes the atomic). So while a Drop error
            // is latched, sustained retries afterward keep surfacing that
            // Drop string, NOT the current retry reason, until the binding
            // rebinds and `clear_error()` wipes BOTH. This precedence is
            // DELIBERATE: a `TxError::Drop` is rarer and more severe than
            // expected backpressure (it flags a real capacity /
            // slice-bounds fault an operator must see), so the
            // more-severe latched error must not be masked by a flood of
            // routine retry hints. `clear_error()` (rebind / successful
            // reconcile) is the single reset point; a fresh retry recorded
            // AFTER the clear then renders normally. Pinned by
            // `tx_status_drop_error_outranks_retry_hint_until_rebind_6145`.
            last_error: {
                let err = self
                    .last_error
                    .lock()
                    .map(|v| v.clone())
                    .unwrap_or_default();
                if err.is_empty() {
                    crate::afxdp::tx::TxRetryReason::from_u8(
                        self.last_tx_retry_status.load(Ordering::Relaxed),
                    )
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_default()
                } else {
                    err
                }
            },
            // #709 / #746: owner-profile telemetry snapshot.
            // Histograms are copied bucket-by-bucket under `Relaxed`
            // through the cacheline-isolated owner/peer structs.
            // Read-side tearing is acceptable — these are diagnostic
            // counters, not a load-bearing arithmetic invariant; the
            // only "invariant" (sum of buckets ≈ drain_invocations)
            // holds within a single-thread read only in steady-state,
            // which is how operators consume the values anyway.
            drain_latency_hist: Self::snapshot_hist(&self.owner_profile_owner.drain_latency_hist),
            drain_invocations: self
                .owner_profile_owner
                .drain_invocations
                .load(Ordering::Relaxed),
            drain_noop_invocations: self
                .owner_profile_owner
                .drain_noop_invocations
                .load(Ordering::Relaxed),
            redirect_acquire_hist: Self::snapshot_hist(
                &self.owner_profile_peer.redirect_acquire_hist,
            ),
            owner_pps: self.owner_profile_owner.owner_pps.load(Ordering::Relaxed),
            peer_pps: self.owner_profile_peer.peer_pps.load(Ordering::Relaxed),
            // #812: owner-written TX submit-latency telemetry.
            // Copied bucket-by-bucket under Relaxed; read-side
            // tearing acceptable per the §3.6 R2 bounded-skew
            // semantics and the drain-histogram precedent earlier
            // in this same `snapshot()` body (see `drain_latency_hist`
            // a few lines above). The count/sum scalars are loaded
            // immediately after the bucket sweep so the snapshot
            // read window is tight (single owner cacheline).
            tx_submit_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_submit_latency_hist,
            ),
            tx_submit_latency_count: self
                .owner_profile_owner
                .tx_submit_latency_count
                .load(Ordering::Relaxed),
            tx_submit_latency_sum_ns: self
                .owner_profile_owner
                .tx_submit_latency_sum_ns
                .load(Ordering::Relaxed),
            // #825: owner-written TX kick-latency telemetry. Same
            // single-writer / Relaxed-load discipline as the #812
            // submit-latency block above; bounded-read-skew
            // semantics per plan §4. Load scalars immediately after
            // the bucket sweep so the snapshot window is tight.
            tx_kick_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_kick_latency_hist,
            ),
            tx_kick_latency_count: self
                .owner_profile_owner
                .tx_kick_latency_count
                .load(Ordering::Relaxed),
            tx_kick_latency_sum_ns: self
                .owner_profile_owner
                .tx_kick_latency_sum_ns
                .load(Ordering::Relaxed),
            tx_kick_retry_count: self
                .owner_profile_owner
                .tx_kick_retry_count
                .load(Ordering::Relaxed),
        }
    }

    /// #709: copy a histogram bucket array under `Relaxed`. Inline to
    /// keep the fixed-size array on the caller's stack — no `Vec`.
    #[inline]
    fn snapshot_hist(hist: &[AtomicU64; DRAIN_HIST_BUCKETS]) -> [u64; DRAIN_HIST_BUCKETS] {
        std::array::from_fn(|i| hist[i].load(Ordering::Relaxed))
    }
}
