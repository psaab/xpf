// #943 debug-state publishing tests: v_min scratch flush + idle
// debug-state cadence / active-flow aging (with local fixtures).
// Split from umem/tests.rs (#4667).

use super::*;

/// #943: pin the flush-into-atomic semantics. The two scratch
/// counters on each `CoSQueueRuntime` accumulate per-pop V_min
/// throttle decisions; once per drain (via `update_binding_debug_state`)
/// they flush into the binding-wide atomics and reset. This test
/// covers the flush body in isolation (extracted as
/// `flush_v_min_scratches_into` so the unit test doesn't need a full
/// `BindingWorker`).
#[test]
fn flush_v_min_scratches_sums_and_zeros_per_queue_counters() {
    use crate::afxdp::cos::builders::build_cos_interface_runtime;
    use crate::afxdp::types::CoSInterfaceConfig;

    // Two queues so we exercise the per-queue iteration.
    let cfg = CoSInterfaceConfig {
        shaping_rate_bytes: 10_000_000,
        burst_bytes: 1024 * 1024,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [0u8; 64],
        ieee8021_queue_by_pcp: [0u8; 8],
        queue_by_forwarding_class: Default::default(),
        queues: vec![
            crate::afxdp::types::CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "be".into(),
                priority: 0,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            crate::afxdp::types::CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 5_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
    oversubscription_guarantee_fraction: 0.0,
    priority_low_min_share_bytes: 0,
    inet_precedence_classifier: String::new(),
    inet_precedence_queue_by_prec: [u8::MAX; 8],
    };
    let mut runtime = build_cos_interface_runtime(&cfg, 0);

    // Manually populate scratches as if v_min check fired.
    runtime.queues[0].v_min.v_min_hard_cap_overrides_scratch = 3;
    runtime.queues[0].v_min.v_min_throttles_scratch = 17;
    // #hb166 T-6(a): suspended-batch scratch flushes alongside.
    runtime.queues[0].v_min.v_min_suspended_batches_scratch = 100;
    runtime.queues[1].v_min.v_min_hard_cap_overrides_scratch = 5;
    runtime.queues[1].v_min.v_min_throttles_scratch = 23;
    runtime.queues[1].v_min.v_min_suspended_batches_scratch = 200;

    let hard_cap = std::sync::atomic::AtomicU64::new(0);
    let throttles = std::sync::atomic::AtomicU64::new(0);
    let suspended = std::sync::atomic::AtomicU64::new(0);
    let mut interfaces = std::collections::BTreeMap::new();
    interfaces.insert(1, runtime);

    crate::afxdp::binding_state::flush_v_min_scratches_into(
        interfaces.values_mut(),
        &hard_cap,
        &throttles,
        &suspended,
    );

    // Atomics carry the sums.
    assert_eq!(
        hard_cap.load(std::sync::atomic::Ordering::Relaxed),
        3 + 5,
        "hard_cap atomic must equal sum across queues",
    );
    assert_eq!(
        throttles.load(std::sync::atomic::Ordering::Relaxed),
        17 + 23,
        "throttles atomic must equal sum across queues",
    );
    // FAIL-ON-REVERT for T-6(a): the suspended-batch atomic must equal
    // the sum of the per-queue scratches.
    assert_eq!(
        suspended.load(std::sync::atomic::Ordering::Relaxed),
        100 + 200,
        "suspended-batches atomic must equal sum across queues",
    );

    // Per-queue scratches reset to 0.
    let r = interfaces.get(&1).unwrap();
    assert_eq!(r.queues[0].v_min.v_min_hard_cap_overrides_scratch, 0);
    assert_eq!(r.queues[0].v_min.v_min_throttles_scratch, 0);
    assert_eq!(r.queues[0].v_min.v_min_suspended_batches_scratch, 0);
    assert_eq!(r.queues[1].v_min.v_min_hard_cap_overrides_scratch, 0);
    assert_eq!(r.queues[1].v_min.v_min_throttles_scratch, 0);
    assert_eq!(r.queues[1].v_min.v_min_suspended_batches_scratch, 0);
}

/// #943: a second flush call with all scratches zero must NOT bump
/// the atomics — the flush is a no-op in steady state when no
/// throttling occurred since the last update_binding_debug_state.
#[test]
fn flush_v_min_scratches_no_op_when_all_zero() {
    use crate::afxdp::cos::builders::build_cos_interface_runtime;
    use crate::afxdp::types::CoSInterfaceConfig;

    let cfg = CoSInterfaceConfig {
        shaping_rate_bytes: 10_000_000,
        burst_bytes: 1024 * 1024,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [0u8; 64],
        ieee8021_queue_by_pcp: [0u8; 8],
        queue_by_forwarding_class: Default::default(),
        queues: vec![crate::afxdp::types::CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "be".into(),
            priority: 0,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 64 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
        oversubscription_policy: crate::afxdp::types::CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
    };
    let runtime = build_cos_interface_runtime(&cfg, 0);
    // Pre-load atomics with non-zero values to verify the flush
    // doesn't accidentally store-zero.
    let hard_cap = std::sync::atomic::AtomicU64::new(42);
    let throttles = std::sync::atomic::AtomicU64::new(99);
    let suspended = std::sync::atomic::AtomicU64::new(7);
    let mut interfaces = std::collections::BTreeMap::new();
    interfaces.insert(1, runtime);

    crate::afxdp::binding_state::flush_v_min_scratches_into(
        interfaces.values_mut(),
        &hard_cap,
        &throttles,
        &suspended,
    );

    // Atomics unchanged — the no-zero-scratch path skips the fetch_add.
    assert_eq!(hard_cap.load(std::sync::atomic::Ordering::Relaxed), 42);
    assert_eq!(throttles.load(std::sync::atomic::Ordering::Relaxed), 99);
    assert_eq!(suspended.load(std::sync::atomic::Ordering::Relaxed), 7);
}

fn debug_state_test_timers() -> WorkerTimers {
    WorkerTimers {
        last_heartbeat_update_ns: 0,
        debug_state_counter: 0,
        last_idle_debug_publish_ns: 0,
        last_rx_wake_ns: 0,
        last_tx_wake_ns: 0,
        empty_rx_polls: 0,
    }
}

fn active_flow_debug_test_queue_config(queue_id: u8) -> crate::afxdp::types::CoSQueueConfig {
    crate::afxdp::types::CoSQueueConfig {
        queue_id,
        forwarding_class: format!("test-q{queue_id}"),
        priority: 5,
        transmit_rate_bytes: 1_000_000,
        guarantee_enabled: true,
        exact: true,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: 64 * 1024,
        dscp_rewrite: None,
    codel_target_ns: 0,
    }
}

fn active_flow_debug_test_binding() -> BindingWorker {
    use crate::afxdp::tx::test_support::{
        test_cos_fast_interfaces, test_cos_runtime_with_queues, test_queue_fast_path,
    };

    let root_ifindex = 14;
    let worker_id = 3;
    let root = test_cos_runtime_with_queues(
        1_000_000,
        vec![
            active_flow_debug_test_queue_config(0),
            active_flow_debug_test_queue_config(2),
        ],
    );
    let fast_interfaces = test_cos_fast_interfaces(
        root_ifindex,
        root_ifindex,
        0,
        vec![
            (0, test_queue_fast_path(false, worker_id, None, None)),
            (2, test_queue_fast_path(false, worker_id, None, None)),
        ],
        None,
        None,
    );
    let fast_path = fast_interfaces
        .get(&root_ifindex)
        .expect("test fast path")
        .clone();

    BindingWorker::new_for_cos_drain_test(5, worker_id, root_ifindex, root, fast_path)
}

fn active_flow_debug_test_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 5205,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn active_flow_debug_test_entry(
    key: crate::session::SessionKey,
    stamp: FlowCacheStamp,
) -> FlowCacheEntry {
    use crate::test_zone_ids::{TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID};

    FlowCacheEntry {
        key,
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        descriptor: RewriteDescriptor {
            dst_mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            fabric_redirect: false,
            tx_vlan_id: 80,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 14,
            tx_ifindex: 14,
            target_binding_index: None,
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor {
                queue_id: Some(2),
                dscp_rewrite: Some(46),
                drop: false,
                reject: false,
                reject_message: crate::filter::RejectMessage::ADMIN_PROHIBITED,
                filter_counters: crate::filter::CachedFilterCounters::default(),
                three_color_policers: crate::filter::CachedThreeColorPolicers::default(),
                filter_log: None,
                ba_reclassify: false,
            },
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 14,
            tx_ifindex: 14,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 80,
        }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 },
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        stamp,
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        // #5147: no dynamic-neighbor dependency in this test entry.
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    }
}

fn active_flow_debug_snapshot(binding: &BindingWorker) -> (u32, usize, usize) {
    let (flow_rows, flow_rows_truncated) = binding.live.flow_worker_map_snapshot();
    assert!(
        !flow_rows_truncated,
        "single-flow regression fixture must not truncate flow-worker rows"
    );
    (
        binding
            .live
            .active_flow_count
            .load(std::sync::atomic::Ordering::Relaxed),
        flow_rows.len(),
        binding.live.cos_active_flow_counts_snapshot().len(),
    )
}

#[test]
fn idle_debug_state_publish_cadence_is_wall_clock_based() {
    let mut timers = debug_state_test_timers();

    assert!(
        !idle_debug_state_publish_due(&mut timers, IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS - 1),
        "idle cadence should not publish before the 65ms boundary"
    );
    assert_eq!(
        timers.last_idle_debug_publish_ns, 0,
        "non-publish must leave the last-publish timestamp unchanged"
    );

    assert!(
        idle_debug_state_publish_due(&mut timers, IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS),
        "idle cadence must publish on the 65ms boundary"
    );
    assert_eq!(
        timers.last_idle_debug_publish_ns,
        IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS
    );
    assert!(
        !idle_debug_state_publish_due(&mut timers, IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS * 2 - 1),
        "subsequent idle publishes must also respect the interval"
    );
}

#[test]
fn non_idle_debug_state_keeps_hot_counter_cadence() {
    let mut timers = debug_state_test_timers();

    for _ in 0..DEBUG_STATE_PUBLISH_MASK {
        assert!(
            !advance_debug_state_publish_counter(&mut timers),
            "hot cadence should not publish before the 65536-call boundary"
        );
    }

    assert!(advance_debug_state_publish_counter(&mut timers));
    assert_eq!(timers.debug_state_counter, DEBUG_STATE_PUBLISH_MASK + 1);
    assert_eq!(timers.last_idle_debug_publish_ns, 0);
}

#[test]
fn idle_debug_updater_ages_active_flow_snapshots() {
    let mut binding = active_flow_debug_test_binding();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = active_flow_debug_test_key();
    binding
        .flow
        .flow_cache
        .insert(active_flow_debug_test_entry(key.clone(), stamp));
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(
        binding
            .flow
            .flow_cache
            .lookup_counted(&key, lookup, 0, &rg_epochs, 1500)
            .is_some(),
        "fixture flow must be active before idle-only aging starts"
    );

    let mut now_ns = binding.timers.last_idle_debug_publish_ns;
    now_ns = now_ns.saturating_add(IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS);
    update_binding_idle_debug_state(&mut binding, now_ns);

    assert_eq!(
        active_flow_debug_snapshot(&binding),
        (1, 1, 1),
        "first idle publish must surface the active binding, flow-map, and CoS snapshots"
    );
    let cos_rows = binding.live.cos_active_flow_counts_snapshot();
    assert_eq!(cos_rows[0].ifindex, 14);
    assert_eq!(cos_rows[0].queue_id, 2);
    assert_eq!(cos_rows[0].worker_id, 3);
    assert_eq!(cos_rows[0].active_flow_count, 1);

    for _ in 0..ACTIVE_WINDOW_EPOCHS.saturating_sub(1) {
        now_ns = now_ns.saturating_add(IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS);
        update_binding_idle_debug_state(&mut binding, now_ns);
    }

    assert_eq!(
        active_flow_debug_snapshot(&binding),
        (0, 0, 0),
        "idle wall-clock publishes must age stale active-flow telemetry out without packet RX"
    );
    assert_eq!(
        binding.live.snapshot().active_flow_count,
        0,
        "operator binding snapshot must observe the aged-out active-flow count"
    );
}
