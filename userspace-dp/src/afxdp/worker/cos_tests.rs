// Tests for afxdp/worker/cos.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep cos.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "cos_tests.rs"]` from cos.rs.

use super::*;
use crate::test_zone_ids::*;

// Rates used to force owner-local vs shared-exact classification in
// the owner-profile export tests. Defined relative to the boundary
// constant so the tests remain valid if `COS_SHARED_EXACT_MIN_RATE_BYTES`
// moves, and so `CoSQueueConfig.transmit_rate_bytes` stays identical
// to `CoSQueueRuntime.transmit_rate_bytes` by construction (no
// config/runtime drift, per #753 Copilot review finding).
const OWNER_LOCAL_EXACT_RATE: u64 = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
const SHARED_EXACT_RATE: u64 = COS_SHARED_EXACT_MIN_RATE_BYTES;

fn test_tx_request(ifindex: i32) -> TxRequest {
    TxRequest {
        bytes: vec![0; 128],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: ifindex,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
    }
}

#[test]
fn build_worker_cos_statuses_aggregates_runtime_by_interface_and_queue() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_875_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "bandwidth-10mb".to_string(),
                priority: 1,
                transmit_rate_bytes: 1_250_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
            }],
        },
    );

    let make_root =
        |queued_bytes, runnable, parked, wake_tick, drop_counters| CoSInterfaceRuntime {
            shaping_rate_bytes: 1_875_000,
            burst_bytes: 64 * 1024,
            tokens: 0,
            default_queue: 0,
            nonempty_queues: 1,
            runnable_queues: usize::from(runnable),
            exact_guarantee_rr: 0,
            nonexact_guarantee_rr: 0,
            #[cfg(test)]
            legacy_guarantee_rr: 0,
            queues: vec![CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: 1_250_000,
                exact: false,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 512,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable,
                parked,
                next_wakeup_tick: wake_tick,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::from([CoSPendingTxItem::Local(test_tx_request(80))]),
                local_item_count: 1,

                vtime_floor: None,

                worker_id: 0,
                drop_counters,
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            }],
            queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
            rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
            timer_wheel: CoSTimerWheelRuntime {
                current_tick: 0,
                level0: std::array::from_fn(|idx| if idx == 3 { vec![0] } else { Vec::new() }),
                level1: std::array::from_fn(|idx| if idx == 1 { vec![0] } else { Vec::new() }),
            },
        };

    // #710 regression pin: worker-level aggregation must sum every
    // drop-reason counter across runtime instances. Use distinct
    // non-zero values per runtime and assert the sum, not a bool,
    // so a silent re-attribution between counters is caught.
    let counters_a = CoSQueueDropCounters {
        admission_flow_share_drops: 3,
        admission_buffer_drops: 1,
        admission_ecn_marked: 37,
        root_token_starvation_parks: 5,
        queue_token_starvation_parks: 7,
        tx_ring_full_submit_stalls: 11,
    };
    let counters_b = CoSQueueDropCounters {
        admission_flow_share_drops: 13,
        admission_buffer_drops: 17,
        admission_ecn_marked: 41,
        root_token_starvation_parks: 19,
        queue_token_starvation_parks: 23,
        tx_ring_full_submit_stalls: 29,
    };

    let mut first = FastMap::default();
    first.insert(80, make_root(1024, true, false, 0, counters_a));
    let mut second = FastMap::default();
    second.insert(80, make_root(2048, false, true, 77, counters_b));

    let statuses =
        build_worker_cos_statuses_from_maps([(&first, None), (&second, None)], &forwarding);
    assert_eq!(statuses.len(), 1);
    let iface = &statuses[0];
    assert_eq!(iface.interface_name, "reth0.80");
    assert_eq!(iface.worker_instances, 2);
    assert_eq!(iface.timer_level0_sleepers, 2);
    assert_eq!(iface.timer_level1_sleepers, 2);
    assert_eq!(iface.nonempty_queues, 1);
    assert_eq!(iface.runnable_queues, 1);
    assert_eq!(iface.queues.len(), 1);
    let queue = &iface.queues[0];
    assert_eq!(queue.queue_id, 4);
    assert_eq!(queue.forwarding_class, "bandwidth-10mb");
    assert_eq!(queue.queued_packets, 2);
    assert_eq!(queue.queued_bytes, 3072);
    assert_eq!(queue.runnable_instances, 1);
    assert_eq!(queue.parked_instances, 1);
    assert_eq!(queue.next_wakeup_tick, 77);
    assert_eq!(queue.surplus_deficit_bytes, 1024);
    // Drop-reason aggregation across workers — this is the layer
    // that the live bug in #710 review occurred in.
    assert_eq!(queue.admission_flow_share_drops, 3 + 13);
    assert_eq!(queue.admission_buffer_drops, 1 + 17);
    assert_eq!(queue.admission_ecn_marked, 37 + 41);
    assert_eq!(queue.root_token_starvation_parks, 5 + 19);
    assert_eq!(queue.queue_token_starvation_parks, 7 + 23);
    assert_eq!(queue.tx_ring_full_submit_stalls, 11 + 29);
}

#[test]
fn build_worker_cos_statuses_sums_owner_profile_without_breaking_hist_invariant() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_250_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".to_string(),
                priority: 1,
                transmit_rate_bytes: 1_250_000,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
            }],
        },
    );

    let make_root = || CoSInterfaceRuntime {
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 256 * 1024,
        tokens: 0,
        default_queue: 0,
        nonempty_queues: 1,
        runnable_queues: 1,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: vec![CoSQueueRuntime {
            queue_id: 4,
            priority: 1,
            transmit_rate_bytes: 1_250_000,
            exact: true,
            surplus_sharing: false,
            flow_fair: false,
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: 32 * 1024,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: true,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,

            vtime_floor: None,

            worker_id: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
        }],
        queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: 0,
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    };

    let live_a = BindingLiveState::new();
    // binding-scoped fields (unchanged by #751): redirect_acquire
    // histogram, owner_pps, peer_pps, drain_noop_invocations.
    live_a.owner_profile_peer.redirect_acquire_hist[1].store(3, Ordering::Relaxed);
    live_a
        .owner_profile_owner
        .drain_noop_invocations
        .store(1, Ordering::Relaxed);
    live_a
        .owner_profile_owner
        .owner_pps
        .store(100, Ordering::Relaxed);
    live_a
        .owner_profile_peer
        .peer_pps
        .store(40, Ordering::Relaxed);

    let live_b = BindingLiveState::new();
    live_b.owner_profile_peer.redirect_acquire_hist[2].store(13, Ordering::Relaxed);
    live_b
        .owner_profile_owner
        .drain_noop_invocations
        .store(2, Ordering::Relaxed);
    live_b
        .owner_profile_owner
        .owner_pps
        .store(200, Ordering::Relaxed);
    live_b
        .owner_profile_peer
        .peer_pps
        .store(50, Ordering::Relaxed);

    let mut first = FastMap::default();
    first.insert(80, make_root());
    // #751: seed per-queue drain stats directly on the first
    // worker's queue runtime. This is what the TX drain loop
    // writes in production (tx.rs line ~250); tests pin the
    // aggregated value rather than the old binding-wide rollup.
    first.get_mut(&80).unwrap().queues[0]
        .owner_profile
        .drain_latency_hist[0]
        .store(5, Ordering::Relaxed);
    first.get_mut(&80).unwrap().queues[0]
        .owner_profile
        .drain_invocations
        .store(5, Ordering::Relaxed);

    let mut second = FastMap::default();
    second.insert(80, make_root());
    second.get_mut(&80).unwrap().queues[0]
        .owner_profile
        .drain_latency_hist[7]
        .store(11, Ordering::Relaxed);
    second.get_mut(&80).unwrap().queues[0]
        .owner_profile
        .drain_invocations
        .store(11, Ordering::Relaxed);

    let statuses = build_worker_cos_statuses_from_maps(
        [(&first, Some(&live_a)), (&second, Some(&live_b))],
        &forwarding,
    );
    let queue = &statuses[0].queues[0];

    // #751: drain_latency_hist + drain_invocations come from
    // per-queue atomics, summed across workers servicing the
    // same (ifindex, queue_id).
    assert_eq!(queue.drain_latency_hist[0], 5);
    assert_eq!(queue.drain_latency_hist[7], 11);
    assert_eq!(queue.drain_invocations, 16);
    assert_eq!(
        queue.drain_latency_hist.iter().copied().sum::<u64>(),
        queue.drain_invocations,
        "per-queue histogram must stay coherent with invocation count",
    );

    // Binding-scoped fields still attributed to the eligible
    // queue (there's only one in this fixture) and summed
    // across workers.
    assert_eq!(queue.redirect_acquire_hist[1], 3);
    assert_eq!(queue.redirect_acquire_hist[2], 13);
    assert_eq!(queue.drain_noop_invocations, 3);
    assert_eq!(queue.owner_pps, 300);
    assert_eq!(queue.peer_pps, 90);
}

#[test]
fn build_worker_cos_statuses_owner_profile_only_surfaces_on_unambiguous_owner_local_exact_queue() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".to_string(),
                    priority: 1,
                    transmit_rate_bytes: 100_000_000 / 8,
                    exact: false,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 32 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".to_string(),
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".to_string(),
                    priority: 1,
                    transmit_rate_bytes: SHARED_EXACT_RATE,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );

    let root = CoSInterfaceRuntime {
        shaping_rate_bytes: 10_000_000_000 / 8,
        burst_bytes: 256 * 1024,
        tokens: 0,
        default_queue: 0,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: vec![
            CoSQueueRuntime {
                queue_id: 0,
                priority: 1,
                transmit_rate_bytes: 100_000_000 / 8,
                exact: false,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 32 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
            CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
            CoSQueueRuntime {
                queue_id: 5,
                priority: 1,
                transmit_rate_bytes: SHARED_EXACT_RATE,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
        ],
        queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: 0,
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    };

    let live = BindingLiveState::new();
    // Binding-scoped fields (unchanged by #751).
    live.owner_profile_owner
        .drain_noop_invocations
        .store(1, Ordering::Relaxed);
    live.owner_profile_peer.redirect_acquire_hist[4].store(7, Ordering::Relaxed);
    live.owner_profile_owner
        .owner_pps
        .store(123, Ordering::Relaxed);
    live.owner_profile_peer
        .peer_pps
        .store(45, Ordering::Relaxed);

    let mut cos_map = FastMap::default();
    cos_map.insert(80, root);
    // #751: seed per-queue drain stats on queue_id=4 only
    // (the owner-local exact queue in this fixture).
    {
        let runtime = cos_map.get_mut(&80).unwrap();
        let q4 = runtime.queues.iter_mut().find(|q| q.queue_id == 4).unwrap();
        q4.owner_profile.drain_latency_hist[2].store(9, Ordering::Relaxed);
        q4.owner_profile
            .drain_invocations
            .store(9, Ordering::Relaxed);
    }

    let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
    let queues = &statuses[0].queues;
    let q0 = queues.iter().find(|q| q.queue_id == 0).unwrap();
    let q4 = queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q5 = queues.iter().find(|q| q.queue_id == 5).unwrap();

    // q0 is non-exact: no per-queue drain stats seeded and not
    // the eligible row for binding-scoped fields.
    assert_eq!(q0.drain_invocations, 0);
    assert_eq!(q0.owner_pps, 0);

    // q4 is the owner-local exact queue: it gets BOTH its own
    // per-queue drain stats (seeded on the runtime) AND the
    // binding-scoped fields (redirect_acquire, owner_pps,
    // peer_pps, drain_noop) because it's the unambiguous row.
    assert_eq!(q4.drain_latency_hist[2], 9);
    assert_eq!(q4.drain_invocations, 9);
    assert_eq!(q4.redirect_acquire_hist[4], 7);
    assert_eq!(q4.owner_pps, 123);
    assert_eq!(q4.peer_pps, 45);
    assert_eq!(q4.drain_noop_invocations, 1);

    // q5 is shared-exact (via SHARED_EXACT_RATE fixture): no
    // per-queue drain stats seeded, and it's not the eligible
    // row for binding-scoped fields.
    assert_eq!(q5.drain_invocations, 0);
    assert_eq!(q5.owner_pps, 0);
}

#[test]
fn build_worker_cos_statuses_owner_profile_stays_zero_for_ambiguous_multi_exact_binding() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 4,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".to_string(),
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 6,
                    forwarding_class: "iperf-c".to_string(),
                    priority: 1,
                    // Also owner-local-exact — any rate < boundary works;
                    // differ from queue 4 only for readability.
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );

    let root = CoSInterfaceRuntime {
        shaping_rate_bytes: 10_000_000_000 / 8,
        burst_bytes: 256 * 1024,
        tokens: 0,
        default_queue: 4,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: vec![
            CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
            CoSQueueRuntime {
                queue_id: 6,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
        ],
        queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: 0,
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    };

    let live = BindingLiveState::new();
    live.owner_profile_owner.drain_latency_hist[1].store(5, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_invocations
        .store(5, Ordering::Relaxed);
    live.owner_profile_owner
        .owner_pps
        .store(77, Ordering::Relaxed);

    let mut cos_map = FastMap::default();
    cos_map.insert(80, root);

    let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
    for queue in &statuses[0].queues {
        assert_eq!(
            queue.drain_invocations, 0,
            "ambiguous binding-scoped profile must stay zero on queue {}",
            queue.queue_id
        );
        assert!(queue.drain_latency_hist.is_empty());
        assert_eq!(queue.owner_pps, 0);
    }
}

/// #753 Copilot review: the first revision of the export gate scoped
/// uniqueness per-interface, which missed the case where a binding
/// drains multiple interfaces each with exactly one owner-local
/// exact queue — the binding-level attribution is still ambiguous,
/// but the per-interface gate would stamp the same snapshot onto
/// both queue rows. This test drives that exact shape (two
/// interfaces, one owner-local exact queue each, same binding) and
/// asserts every queue stays zero.
#[test]
fn build_worker_cos_statuses_owner_profile_stays_zero_for_ambiguous_multi_interface_binding() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(81, "reth0.81".to_string());

    // Two interfaces on the same binding, each carrying one
    // owner-local exact queue. Each interface on its own would
    // satisfy the old per-interface gate (single owner-local
    // exact). Together they're ambiguous at the binding level.
    let make_iface_config = || CoSInterfaceConfig {
        shaping_rate_bytes: SHARED_EXACT_RATE,
        burst_bytes: 256 * 1024,
        default_queue: 4,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: [u8::MAX; 8],
        queue_by_forwarding_class: FastMap::default(),
        queues: vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".to_string(),
            priority: 1,
            transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 64 * 1024,
            dscp_rewrite: None,
        }],
    };
    forwarding.cos.interfaces.insert(80, make_iface_config());
    forwarding.cos.interfaces.insert(81, make_iface_config());

    let make_runtime = || CoSInterfaceRuntime {
        shaping_rate_bytes: SHARED_EXACT_RATE,
        burst_bytes: 256 * 1024,
        tokens: 0,
        default_queue: 4,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: vec![CoSQueueRuntime {
            queue_id: 4,
            priority: 1,
            transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
            exact: true,
            surplus_sharing: false,
            flow_fair: false,
            shared_exact: false,
            flow_hash_seed: 0,
            surplus_weight: 1,
            surplus_deficit: 0,
            buffer_bytes: 64 * 1024,
            dscp_rewrite: None,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            active_flow_buckets: 0,
            active_flow_buckets_peak: 0,
            flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
            queue_vtime: 0,
            pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
            flow_rr_buckets: FlowRrRing::default(),
            flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,

            vtime_floor: None,

            worker_id: 0,
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
        }],
        queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: 0,
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    };

    let live = BindingLiveState::new();
    live.owner_profile_owner.drain_latency_hist[2].store(11, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_invocations
        .store(11, Ordering::Relaxed);
    live.owner_profile_owner
        .owner_pps
        .store(222, Ordering::Relaxed);
    live.owner_profile_peer
        .peer_pps
        .store(88, Ordering::Relaxed);

    let mut cos_map = FastMap::default();
    cos_map.insert(80, make_runtime());
    cos_map.insert(81, make_runtime());

    let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
    assert_eq!(statuses.len(), 2, "both interfaces should appear in output");
    for iface in &statuses {
        for queue in &iface.queues {
            assert_eq!(
                queue.drain_invocations, 0,
                "binding drains multiple interfaces with owner-local exact queues \
                 — attribution is ambiguous at the binding level, export must stay \
                 zero on {}:{}",
                iface.interface_name, queue.queue_id,
            );
            assert!(queue.drain_latency_hist.is_empty());
            assert_eq!(queue.owner_pps, 0);
            assert_eq!(queue.peer_pps, 0);
        }
    }

    // Counter-factual: the pre-#753-Copilot-review per-interface
    // gate would have returned `Some(4)` for each interface
    // independently and stamped the snapshot onto both queue rows.
    // Pinning the NEW behaviour: the binding-wide scan returns
    // None because the eligible slot gets .replace()'d on the
    // second interface's queue 4.
    let row = unique_owner_profile_row(&cos_map, &forwarding);
    assert!(
        row.is_none(),
        "unique_owner_profile_row must return None when the binding has \
         multiple owner-local exact queues across interfaces; got {:?}",
        row
    );
}

/// #751 / #732: per-queue drain telemetry.
///
/// Pre-#751 (symptom of #732): the same drain_latency_hist /
/// drain_invocations read from BindingLiveState and stamped under
/// every queue row of a multi-queue binding. The on-wire status
/// repeated identical values on each queue even when the owner
/// worker was draining two queues with wildly different latency
/// profiles — e.g. a low-rate "iperf-a" queue with ~8 µs drains
/// and a high-rate "iperf-b" queue with ~1 µs drains collapsed
/// into a single flat shape.
///
/// Post-#751: each queue carries its own per-queue atomics
/// (CoSQueueRuntime::owner_profile). The snapshot reads from the
/// queue itself; distinct queues report distinct distributions.
///
/// This test pins that behaviour by seeding two owner-local
/// exact queues on the same binding with disjoint latency
/// histograms (non-overlapping bucket sets) and invocation
/// counts, running the snapshot path, and asserting the two
/// on-wire queue rows carry different values. The counter-factual
/// pre-#751 behaviour (both queues showing the same profile)
/// would fail the disjoint-bucket assertion loudly.
#[test]
fn build_worker_cos_statuses_surfaces_distinct_per_queue_drain_telemetry() {
    let mut forwarding = ForwardingState::default();
    forwarding
        .ifindex_to_config_name
        .insert(80, "reth0.80".to_string());
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 1,
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 6,
                    forwarding_class: "iperf-c".into(),
                    priority: 1,
                    // Also owner-local-exact — same shape as the
                    // ambiguous-multi-exact fixture above.
                    transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );

    let mut root = CoSInterfaceRuntime {
        shaping_rate_bytes: 10_000_000_000 / 8,
        burst_bytes: 256 * 1024,
        tokens: 0,
        default_queue: 0,
        nonempty_queues: 0,
        runnable_queues: 0,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: vec![
            CoSQueueRuntime {
                queue_id: 4,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
            CoSQueueRuntime {
                queue_id: 6,
                priority: 1,
                transmit_rate_bytes: OWNER_LOCAL_EXACT_RATE / 2,
                exact: true,
                surplus_sharing: false,
                flow_fair: false,
                shared_exact: false,
                flow_hash_seed: 0,
                surplus_weight: 1,
                surplus_deficit: 0,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                tokens: 0,
                last_refill_ns: 0,
                queued_bytes: 0,
                active_flow_buckets: 0,
                active_flow_buckets_peak: 0,
                flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
                queue_vtime: 0,
                pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
                flow_rr_buckets: FlowRrRing::default(),
                flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
                runnable: false,
                parked: false,
                next_wakeup_tick: 0,
                wheel_level: 0,
                wheel_slot: 0,
                items: VecDeque::new(),
                local_item_count: 0,

                vtime_floor: None,

                worker_id: 0,
                drop_counters: CoSQueueDropCounters::default(),
                owner_profile: CoSQueueOwnerProfile::new(),
                consecutive_v_min_skips: 0,
                v_min_suspended_remaining: 0,
                v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
            },
        ],
        queue_indices_by_priority: std::array::from_fn(|_| Vec::new()),
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: 0,
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
        },
    };

    // Queue 4: "slow drain" profile — landings in high bucket.
    {
        let q = root.queues.iter_mut().find(|q| q.queue_id == 4).unwrap();
        q.owner_profile.drain_latency_hist[12].store(7, Ordering::Relaxed);
        q.owner_profile
            .drain_invocations
            .store(7, Ordering::Relaxed);
    }
    // Queue 6: "fast drain" profile — landings in low bucket.
    // Disjoint from queue 4's bucket so a regression that collapses
    // to a single profile fails the per-queue distinctness check.
    {
        let q = root.queues.iter_mut().find(|q| q.queue_id == 6).unwrap();
        q.owner_profile.drain_latency_hist[2].store(23, Ordering::Relaxed);
        q.owner_profile
            .drain_invocations
            .store(23, Ordering::Relaxed);
    }

    // Binding-scoped fields: ambiguous shape (two owner-local
    // exact queues), so these stay at zero on all queues
    // regardless of what we seed — the test does NOT seed
    // BindingLiveState to make that invariant explicit.
    let live = BindingLiveState::new();
    let mut cos_map = FastMap::default();
    cos_map.insert(80, root);

    let statuses = build_worker_cos_statuses_from_maps([(&cos_map, Some(&live))], &forwarding);
    let queues = &statuses[0].queues;
    let q4 = queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q6 = queues.iter().find(|q| q.queue_id == 6).unwrap();

    // Per-queue distinctness.
    assert_eq!(q4.drain_invocations, 7);
    assert_eq!(q4.drain_latency_hist[12], 7);
    assert_eq!(q4.drain_latency_hist[2], 0);

    assert_eq!(q6.drain_invocations, 23);
    assert_eq!(q6.drain_latency_hist[2], 23);
    assert_eq!(q6.drain_latency_hist[12], 0);

    // Counter-factual: if the snapshot collapsed both queues to
    // a shared profile (the pre-#751 / #732 behaviour), q4 would
    // carry q6's bucket[2] count and vice versa. Assert both
    // hists are disjoint in their non-zero buckets.
    assert!(
        q4.drain_latency_hist[12] > 0
            && q4.drain_latency_hist[2] == 0
            && q6.drain_latency_hist[2] > 0
            && q6.drain_latency_hist[12] == 0,
        "queues must surface their own per-queue hist, not share a \
         binding-wide rollup (pre-#751 regression)",
    );

    // Binding-scoped fields stay at zero on ambiguous shapes.
    assert_eq!(q4.owner_pps, 0);
    assert_eq!(q6.owner_pps, 0);
    assert_eq!(q4.peer_pps, 0);
    assert_eq!(q6.peer_pps, 0);
    assert_eq!(q4.drain_noop_invocations, 0);
    assert_eq!(q6.drain_noop_invocations, 0);
}

#[test]
fn build_worker_cos_owner_live_by_tx_ifindex_prefers_first_binding_per_tx_ifindex() {
    let live_a = Arc::new(BindingLiveState::new());
    let live_b = Arc::new(BindingLiveState::new());
    let live_c = Arc::new(BindingLiveState::new());
    let owners = build_worker_cos_owner_live_by_tx_ifindex([
        (12, live_a.clone()),
        (12, live_b.clone()),
        (13, live_c.clone()),
    ]);

    assert!(Arc::ptr_eq(owners.get(&12).unwrap(), &live_a));
    assert!(Arc::ptr_eq(owners.get(&13).unwrap(), &live_c));
}

#[test]
fn build_worker_cos_fast_interfaces_flattens_owner_and_lease_state() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 25_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 5,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: false,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let tx_owner_live = Arc::new(BindingLiveState::new());
    let queue_owner_live = Arc::new(BindingLiveState::new());
    let root_lease = Arc::new(SharedCoSRootLease::new(25_000_000_000 / 8, 256 * 1024, 4));
    let queue_lease = Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 128 * 1024, 4));

    let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
    let owner_worker_by_queue = BTreeMap::from([((80, 5), 7)]);
    let owner_live_by_queue = BTreeMap::from([((80, 5), queue_owner_live.clone())]);
    let shared_root_leases = BTreeMap::from([(80, root_lease.clone())]);
    let shared_queue_leases = BTreeMap::from([((80, 5), queue_lease.clone())]);

    let fast = build_worker_cos_fast_interfaces(
        &forwarding,
        3,
        &tx_owner_live_by_tx_ifindex,
        &owner_worker_by_queue,
        &owner_live_by_queue,
        &shared_root_leases,
        &shared_queue_leases,
        &BTreeMap::new(),
    );

    let iface = fast.get(&80).expect("fast cos interface");
    assert_eq!(iface.tx_ifindex, 12);
    assert_eq!(iface.default_queue_index, 1);
    assert!(Arc::ptr_eq(
        iface.tx_owner_live.as_ref().expect("tx owner live"),
        &tx_owner_live
    ));
    assert!(Arc::ptr_eq(
        iface.shared_root_lease.as_ref().expect("shared root lease"),
        &root_lease
    ));

    let queue4 = iface.queue_fast_path(Some(4)).expect("queue 4");
    assert!(!queue4.shared_exact);
    assert_eq!(queue4.owner_worker_id, 3);
    assert!(queue4.owner_live.is_none());
    assert!(queue4.shared_queue_lease.is_none());

    let queue5 = iface.queue_fast_path(Some(5)).expect("queue 5");
    assert!(queue5.shared_exact);
    assert_eq!(queue5.owner_worker_id, 7);
    assert!(Arc::ptr_eq(
        queue5.owner_live.as_ref().expect("queue owner live"),
        &queue_owner_live
    ));
    assert!(Arc::ptr_eq(
        queue5
            .shared_queue_lease
            .as_ref()
            .expect("shared queue lease"),
        &queue_lease
    ));
    assert!(std::ptr::eq(
        iface.queue_fast_path(None).expect("default queue"),
        queue5
    ));
}

#[test]
fn build_worker_cos_fast_interfaces_keeps_low_rate_exact_queue_owner_local() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 25_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 4,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let queue4_owner_live = Arc::new(BindingLiveState::new());
    let queue5_owner_live = Arc::new(BindingLiveState::new());
    let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, queue4_owner_live.clone())]);
    let owner_worker_by_queue = BTreeMap::from([((80, 4), 4), ((80, 5), 7)]);
    let owner_live_by_queue = BTreeMap::from([
        ((80, 4), queue4_owner_live.clone()),
        ((80, 5), queue5_owner_live.clone()),
    ]);
    let shared_root_leases = BTreeMap::from([(
        80,
        Arc::new(SharedCoSRootLease::new(25_000_000_000 / 8, 256 * 1024, 4)),
    )]);
    let shared_queue_leases = BTreeMap::from([
        (
            (80, 4),
            Arc::new(SharedCoSQueueLease::new(1_000_000_000 / 8, 128 * 1024, 4)),
        ),
        (
            (80, 5),
            Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 128 * 1024, 4)),
        ),
    ]);

    let fast = build_worker_cos_fast_interfaces(
        &forwarding,
        3,
        &tx_owner_live_by_tx_ifindex,
        &owner_worker_by_queue,
        &owner_live_by_queue,
        &shared_root_leases,
        &shared_queue_leases,
        &BTreeMap::new(),
    );

    let iface = fast.get(&80).expect("fast cos interface");
    let queue4 = iface.queue_fast_path(Some(4)).expect("queue 4");
    assert!(!queue4.shared_exact);
    assert_eq!(queue4.owner_worker_id, 4);
    assert!(queue4.shared_queue_lease.is_some());

    let queue5 = iface.queue_fast_path(Some(5)).expect("queue 5");
    assert!(queue5.shared_exact);
    assert_eq!(queue5.owner_worker_id, 7);
    assert!(queue5.shared_queue_lease.is_some());
}

#[test]
fn build_worker_cos_fast_interfaces_high_iface_rate_shards_mid_rate_exact_queue() {
    // #697 regression: a mid-rate exact queue on a >10g iface must end
    // up on the shared-worker path end-to-end. The helper predicate is
    // tested directly elsewhere in this module, but the runtime effect
    // of this PR lands in `build_worker_cos_fast_interfaces` and is
    // later consumed by `ensure_cos_interface_runtime` to set
    // `flow_fair` and by the dispatch path to pick shared vs owner-
    // local service. Pin the assembled output for the new regime
    // (`iface_rate / 4 > MIN`) so a future refactor of either the
    // predicate or the assembly cannot quietly re-introduce the
    // PR #680 collapse shape.
    //
    // Shape: 100g iface, 5g exact queue on queue_id=6. Under the
    // pre-fix policy the threshold was 25g and a 5g exact queue would
    // have assembled with `shared_exact=false` and `shared_queue_lease
    // = None`. Under the fix the 5g queue crosses the 2.5g absolute
    // floor and assembles as shared.
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000_000 / 8,
            burst_bytes: 1 * 1024 * 1024,
            default_queue: 6,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 6,
                forwarding_class: "mid-rate".into(),
                priority: 5,
                transmit_rate_bytes: 5_000_000_000 / 8,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 256 * 1024,
                dscp_rewrite: None,
            }],
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let queue_owner_live = Arc::new(BindingLiveState::new());
    let tx_owner_live = Arc::new(BindingLiveState::new());
    let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
    let owner_worker_by_queue = BTreeMap::from([((80, 6), 5)]);
    let owner_live_by_queue = BTreeMap::from([((80, 6), queue_owner_live.clone())]);
    let shared_root_leases = BTreeMap::from([(
        80,
        Arc::new(SharedCoSRootLease::new(
            100_000_000_000 / 8,
            1 * 1024 * 1024,
            4,
        )),
    )]);
    let queue_lease = Arc::new(SharedCoSQueueLease::new(5_000_000_000 / 8, 256 * 1024, 4));
    let shared_queue_leases = BTreeMap::from([((80, 6), queue_lease.clone())]);

    let fast = build_worker_cos_fast_interfaces(
        &forwarding,
        3,
        &tx_owner_live_by_tx_ifindex,
        &owner_worker_by_queue,
        &owner_live_by_queue,
        &shared_root_leases,
        &shared_queue_leases,
        &BTreeMap::new(),
    );

    let iface = fast.get(&80).expect("fast cos interface");
    let queue6 = iface.queue_fast_path(Some(6)).expect("queue 6");
    assert!(
        queue6.shared_exact,
        "5g exact queue on 100g iface must be classified as shared after #697"
    );
    assert!(
        queue6.shared_queue_lease.is_some(),
        "shared queue lease must be wired up for a sharded exact queue"
    );
    assert_eq!(queue6.owner_worker_id, 5);
}

#[test]
fn build_worker_cos_fast_interfaces_matches_live_loss_ha_3_queue_shape() {
    // #698 regression: end-to-end dispatch coverage for the exact
    // live loss HA CoS config every other PR in this series has
    // validated against. Prior predicate tests pin the
    // `queue_uses_shared_exact_service` output; the earlier 2-queue
    // assembly test pins the shared-lease plumbing for one mixed
    // case. Neither exercises all three production queues in
    // their production interface shape at once.
    //
    // Wiring matches what the coordinator actually produces.
    // `build_shared_cos_queue_leases_reusing_existing` creates a
    // `SharedCoSQueueLease` for *every* exact queue with a nonzero
    // rate — regardless of whether `shared_exact` is true. So on
    // the live path, owner-local exact queues (queues 0 and 4 here)
    // carry a shared queue lease *object* that simply isn't used
    // by their dispatch path. That's the real contract this test
    // pins: `shared_exact` flips the *execution* policy, not the
    // *lease presence*.
    //
    // Shape:
    //   reth0.80 shaper 10g
    //     queue 0  best-effort  100m exact
    //                  -> shared_exact=false (owner-local service)
    //                  -> shared_queue_lease=Some(_)  (coordinator always wires)
    //     queue 4  iperf-a      1g   exact
    //                  -> shared_exact=false (owner-local service)
    //                  -> shared_queue_lease=Some(_)
    //     queue 5  iperf-b      10g  exact
    //                  -> shared_exact=true  (sharded service)
    //                  -> shared_queue_lease=Some(_)
    //
    // Threshold on a 10g iface = `COS_SHARED_EXACT_MIN_RATE_BYTES`
    // = 2.5 Gbps. queues 0 and 4 are below; queue 5 is at 10g.
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 10_000_000_000 / 8,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 100_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                },
                CoSQueueConfig {
                    queue_id: 5,
                    forwarding_class: "iperf-b".into(),
                    priority: 5,
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    exact: true,
                    surplus_sharing: false,
                    surplus_weight: 1,
                    buffer_bytes: 256 * 1024,
                    dscp_rewrite: None,
                },
            ],
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let tx_owner_live = Arc::new(BindingLiveState::new());
    let q0_owner_live = Arc::new(BindingLiveState::new());
    let q4_owner_live = Arc::new(BindingLiveState::new());
    let q5_owner_live = Arc::new(BindingLiveState::new());

    let tx_owner_live_by_tx_ifindex = FastMap::from_iter([(12, tx_owner_live.clone())]);
    let owner_worker_by_queue = BTreeMap::from([((80, 0), 2), ((80, 4), 4), ((80, 5), 7)]);
    let owner_live_by_queue = BTreeMap::from([
        ((80, 0), q0_owner_live.clone()),
        ((80, 4), q4_owner_live.clone()),
        ((80, 5), q5_owner_live.clone()),
    ]);
    let shared_root_leases = BTreeMap::from([(
        80,
        Arc::new(SharedCoSRootLease::new(10_000_000_000 / 8, 256 * 1024, 4)),
    )]);
    // Coordinator wires a shared queue lease for every non-zero-rate
    // exact queue, not only the shared ones. Mirror that here so the
    // test exercises the live shape rather than a hand-pruned one.
    let q0_shared_queue_lease = Arc::new(SharedCoSQueueLease::new(100_000_000 / 8, 64 * 1024, 4));
    let q4_shared_queue_lease =
        Arc::new(SharedCoSQueueLease::new(1_000_000_000 / 8, 128 * 1024, 4));
    let q5_shared_queue_lease =
        Arc::new(SharedCoSQueueLease::new(10_000_000_000 / 8, 256 * 1024, 4));
    let shared_queue_leases = BTreeMap::from([
        ((80, 0), q0_shared_queue_lease.clone()),
        ((80, 4), q4_shared_queue_lease.clone()),
        ((80, 5), q5_shared_queue_lease.clone()),
    ]);

    let fast = build_worker_cos_fast_interfaces(
        &forwarding,
        3,
        &tx_owner_live_by_tx_ifindex,
        &owner_worker_by_queue,
        &owner_live_by_queue,
        &shared_root_leases,
        &shared_queue_leases,
        &BTreeMap::new(),
    );

    let iface = fast.get(&80).expect("fast cos interface");
    assert_eq!(iface.tx_ifindex, 12);

    let q0 = iface.queue_fast_path(Some(0)).expect("queue 0");
    assert!(
        !q0.shared_exact,
        "best-effort 100m exact must be owner-local (single-owner service) on 10g iface"
    );
    assert_eq!(q0.owner_worker_id, 2);
    assert!(Arc::ptr_eq(
        q0.owner_live.as_ref().expect("q0 owner live"),
        &q0_owner_live,
    ));
    assert!(
        Arc::ptr_eq(
            q0.shared_queue_lease
                .as_ref()
                .expect("q0 shared queue lease"),
            &q0_shared_queue_lease,
        ),
        "coordinator wires a shared queue lease for every non-zero-rate exact queue, \
         including owner-local ones; the lease object must survive fast-path assembly"
    );

    let q4 = iface.queue_fast_path(Some(4)).expect("queue 4");
    assert!(
        !q4.shared_exact,
        "iperf-a 1g exact must be owner-local (single-owner service) on 10g iface"
    );
    assert_eq!(q4.owner_worker_id, 4);
    assert!(Arc::ptr_eq(
        q4.owner_live.as_ref().expect("q4 owner live"),
        &q4_owner_live,
    ));
    assert!(Arc::ptr_eq(
        q4.shared_queue_lease
            .as_ref()
            .expect("q4 shared queue lease"),
        &q4_shared_queue_lease,
    ));

    let q5 = iface.queue_fast_path(Some(5)).expect("queue 5");
    assert!(
        q5.shared_exact,
        "iperf-b 10g exact must be sharded on 10g iface"
    );
    assert_eq!(q5.owner_worker_id, 7);
    assert!(Arc::ptr_eq(
        q5.owner_live.as_ref().expect("q5 owner live"),
        &q5_owner_live,
    ));
    assert!(Arc::ptr_eq(
        q5.shared_queue_lease
            .as_ref()
            .expect("q5 shared queue lease"),
        &q5_shared_queue_lease
    ));
}

fn test_cos_iface_with_rate(shaping_bits: u64) -> CoSInterfaceConfig {
    CoSInterfaceConfig {
        shaping_rate_bytes: shaping_bits / 8,
        burst_bytes: 64 * 1024,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: [u8::MAX; 8],
        queue_by_forwarding_class: FastMap::default(),
        queues: Vec::new(),
    }
}

fn test_exact_queue_at_rate(queue_id: u8, rate_bits: u64) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: format!("q{queue_id}"),
        priority: 5,
        transmit_rate_bytes: rate_bits / 8,
        exact: true,
        surplus_sharing: false,
        surplus_weight: 1,
        buffer_bytes: 64 * 1024,
        dscp_rewrite: None,
    }
}

#[test]
fn queue_uses_shared_exact_service_rejects_non_exact_queue() {
    let iface = test_cos_iface_with_rate(10_000_000_000);
    let mut q = test_exact_queue_at_rate(4, 10_000_000_000);
    q.exact = false;
    assert!(!queue_uses_shared_exact_service(&iface, &q));
}

#[test]
fn queue_uses_shared_exact_service_10g_iface_pins_5201_config_policy() {
    // Mirrors the live loss HA CoS config:
    //   reth0.80 shaper 10g
    //   best-effort 100m exact  -> single owner
    //   iperf-a     1.0g exact  -> single owner  (this is 5201)
    //   iperf-b     10.0g exact -> shared
    // Threshold is the absolute per-worker ceiling (2.5g) on any iface.
    let iface = test_cos_iface_with_rate(10_000_000_000);
    let be = test_exact_queue_at_rate(0, 100_000_000);
    let iperf_a = test_exact_queue_at_rate(4, 1_000_000_000);
    let iperf_b = test_exact_queue_at_rate(5, 10_000_000_000);
    assert!(!queue_uses_shared_exact_service(&iface, &be));
    assert!(!queue_uses_shared_exact_service(&iface, &iperf_a));
    assert!(queue_uses_shared_exact_service(&iface, &iperf_b));
}

#[test]
fn queue_uses_shared_exact_service_threshold_is_exactly_inclusive() {
    // Threshold = COS_SHARED_EXACT_MIN_RATE_BYTES (2.5 Gbps =
    // 312_500_000 bytes/s). Exactly at threshold selects the shared
    // path; one byte below stays single-owner. The boundary must be
    // deterministic — a fairness fix that accidentally flips
    // classification for a queue at the stated threshold will silently
    // regress 5201 or 5202. Pinned across a slow and a fast iface so
    // the boundary cannot re-gain an iface-dependent term without
    // being caught.
    for iface_bits in [1_000_000_000u64, 10_000_000_000, 100_000_000_000] {
        let iface = test_cos_iface_with_rate(iface_bits);
        let mut q = test_exact_queue_at_rate(4, 0);
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
        assert!(
            !queue_uses_shared_exact_service(&iface, &q),
            "iface {iface_bits}: one byte below threshold must stay single-owner"
        );
        q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
        assert!(
            queue_uses_shared_exact_service(&iface, &q),
            "iface {iface_bits}: at threshold must be shared"
        );
    }
}

#[test]
fn queue_uses_shared_exact_service_slow_iface_below_threshold_is_single_owner() {
    // 1g iface, every exact queue is below the 2.5g ceiling → single
    // owner. Documents that the predicate does not depend on the
    // queue/iface ratio, only on the queue's absolute rate.
    let iface = test_cos_iface_with_rate(1_000_000_000);
    let q_100m = test_exact_queue_at_rate(0, 100_000_000);
    let q_1g = test_exact_queue_at_rate(4, 1_000_000_000);
    assert!(!queue_uses_shared_exact_service(&iface, &q_100m));
    assert!(!queue_uses_shared_exact_service(&iface, &q_1g));
}

#[test]
fn queue_uses_shared_exact_service_zero_rate_exact_queue_is_single_owner() {
    // Config validation should normally reject a 0-rate exact queue,
    // but if one ever reaches the predicate (race during reload, test
    // fixture, malformed journal replay) the policy is "single owner":
    // a queue with no budget cannot justify burning a shared-lease
    // slot, and the threshold is strictly positive.
    let iface_10g = test_cos_iface_with_rate(10_000_000_000);
    let iface_100g = test_cos_iface_with_rate(100_000_000_000);
    let mut q = test_exact_queue_at_rate(4, 0);
    q.transmit_rate_bytes = 0;
    assert!(!queue_uses_shared_exact_service(&iface_10g, &q));
    assert!(!queue_uses_shared_exact_service(&iface_100g, &q));
}

#[test]
fn queue_uses_shared_exact_service_threshold_does_not_scale_with_iface_rate() {
    // #697: the pre-fix policy was `max(iface_rate / 4, MIN)` which
    // scaled the threshold up with iface rate. A 10g exact queue on a
    // 100g iface got classified as single-owner (threshold was 25g),
    // routing a genuinely high-rate queue straight into PR #680's
    // throughput-collapse shape. The fix removes the `/ 4` term; the
    // threshold is now the absolute per-worker ceiling regardless of
    // iface rate. Exercise that: a 10g exact queue must be shared on
    // every realistic iface rate, not just on a 10g iface.
    let q_10g = test_exact_queue_at_rate(5, 10_000_000_000);
    for iface_bits in [10u64, 25, 40, 50, 100, 200, 400].map(|g| g * 1_000_000_000) {
        let iface = test_cos_iface_with_rate(iface_bits);
        assert!(
            queue_uses_shared_exact_service(&iface, &q_10g),
            "iface {iface_bits}: 10g exact queue must be shared — single-owner would \
             reintroduce the PR #680 throughput collapse"
        );
    }
}

#[test]
fn queue_uses_shared_exact_service_high_iface_rate_shards_mid_rate_queues() {
    // Same shape as the scale-invariance test but pinned byte-precise
    // at the threshold for a specific fast iface. On a 100g iface a
    // 2.5g exact queue must shard (it crosses the per-worker ceiling),
    // and a 2.5g-minus-one-byte queue must not. Under the pre-fix
    // policy this iface had threshold 25g and both of these would have
    // been single-owner.
    let iface = test_cos_iface_with_rate(100_000_000_000);
    let mut q = test_exact_queue_at_rate(4, 0);
    q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES - 1;
    assert!(!queue_uses_shared_exact_service(&iface, &q));
    q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
    assert!(queue_uses_shared_exact_service(&iface, &q));
    q.transmit_rate_bytes = 5_000_000_000 / 8; // 5 Gbps
    assert!(queue_uses_shared_exact_service(&iface, &q));
}

#[test]
fn queue_uses_shared_exact_service_zero_iface_rate_uses_absolute_threshold() {
    // Bootstrap / pathological case: iface shaper is 0 (unconfigured).
    // Predicate is iface-rate-independent, so this is just the absolute
    // threshold applied to the queue rate. Verifies there is no
    // divide-by-zero or underflow on any code path the previous
    // `saturating_div(4)` branch used to guard.
    let iface = test_cos_iface_with_rate(0);
    let q_2g = test_exact_queue_at_rate(4, 2_000_000_000);
    let q_3g = test_exact_queue_at_rate(5, 3_000_000_000);
    assert!(!queue_uses_shared_exact_service(&iface, &q_2g));
    assert!(queue_uses_shared_exact_service(&iface, &q_3g));
}

#[test]
fn queue_uses_shared_exact_service_queue_rate_above_iface_rate_uses_queue_rate() {
    // #698 misconfig pin. Junos config validation does not cap the
    // queue's `transmit-rate` at the iface `shaping-rate`, so a
    // 10g exact queue can appear on a 1g iface. The predicate does
    // not read iface rate, so classification is a function of the
    // queue's absolute rate only — in this case 10g ≥ 2.5g → shared.
    // Whether such a queue can actually achieve 10g on a 1g iface
    // is a separate shaper question; the predicate's job is to
    // produce a deterministic classification even under
    // malformed config, not to reject the config.
    let iface = test_cos_iface_with_rate(1_000_000_000);
    let q_10g = test_exact_queue_at_rate(5, 10_000_000_000);
    assert!(
        queue_uses_shared_exact_service(&iface, &q_10g),
        "a 10g exact queue on a 1g iface must classify on its own rate (shared), \
         not on queue/iface ratio"
    );
    // Same logic holds at the exact threshold — nothing about the
    // iface rate influences the decision.
    let mut q = test_exact_queue_at_rate(6, 0);
    q.transmit_rate_bytes = COS_SHARED_EXACT_MIN_RATE_BYTES;
    assert!(queue_uses_shared_exact_service(&iface, &q));
}

#[test]
fn cos_runtime_config_changed_detects_queue_rate_change() {
    let iface = CoSInterfaceConfig {
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 1_000_000,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: [u8::MAX; 8],
        queue_by_forwarding_class: [("iperf-b".to_string(), 5)].into_iter().collect(),
        queues: vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 1_250_000_000,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 1_000_000,
            dscp_rewrite: None,
        }],
    };
    let mut current = ForwardingState::default();
    current.cos.interfaces.insert(12, iface.clone());

    let mut next = current.clone();
    next.cos
        .interfaces
        .get_mut(&12)
        .expect("cos interface")
        .queues[0]
        .transmit_rate_bytes = 1_875_000_000;

    assert!(cos_runtime_config_changed(&current, &next));
    assert!(!cos_runtime_config_changed(&current, &current));
}
