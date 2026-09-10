use super::*;
use crate::afxdp::types::V8RateMode;
use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

#[test]
fn equal_flow_overlay_skips_non_equal_flow_v8_leases() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let leases = BTreeMap::from([(
        (80, 4),
        Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1)),
    )]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(!queue.equal_flow_enforcement);
    assert!(queue.equal_flow_fail_open_reason.is_empty());
}

#[test]
fn claim_flow_overlay_populates_every_v8_lease() {
    // #1863 Step-0: the per-worker claim-flow vectors are populated
    // for ANY v8 lease — including non-equal-flow ones the
    // equal-flow gate below skips.
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1));
    lease.rehydrate_worker_active_count(0, 1);
    let granted = lease.acquire_v8(0, 200_000, 512);
    assert!(granted > 0, "test premise: the ask grants");
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert_eq!(queue.lease_v8_worker_requested_bytes, vec![512, 0]);
    assert_eq!(queue.lease_v8_worker_granted_bytes[0], granted);
    assert!(!queue.equal_flow_enforcement, "equal-flow gate untouched");
}

#[test]
fn equal_flow_overlay_populates_active_equal_flow_leases() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    ));
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(queue.equal_flow_enforcement);
    assert_eq!(queue.equal_flow_fail_open_reason, "disabled");
    assert_eq!(queue.equal_flow_stale_or_tag_mismatch_events, 0);
    // #1746: default-policy lease surfaces the "slowest" label.
    assert_eq!(queue.equal_flow_target_policy, "slowest");
}

/// #1746: a Mean-policy lease surfaces "mean" on the status row,
/// and non-equal-flow leases leave the field empty (wire
/// byte-identical for non-equal-flow queues).
#[test]
fn equal_flow_overlay_populates_target_policy_label() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
        crate::afxdp::types::EqualFlowTargetPolicy::Mean,
    ));
    let leases = BTreeMap::from([((80, 4), lease)]);

    overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

    let queue = &statuses[0].queues[0];
    assert!(queue.equal_flow_enforcement);
    assert_eq!(queue.equal_flow_target_policy, "mean");
}

/// #1830 (g): the flow-count overlay writes only matching
/// (ifindex, queue) rows and leaves non-matching rows at the serde
/// default 0 (idle / no flow-cache rows), never touching
/// flow_fair_buckets_occupied (the worker-snapshot half).
#[test]
fn flow_fair_flow_count_overlay_targets_matching_queue_rows() {
    let mut statuses = vec![CoSInterfaceStatus {
        ifindex: 80,
        queues: vec![
            CoSQueueStatus {
                queue_id: 4,
                flow_fair_buckets_occupied: 6,
                ..Default::default()
            },
            CoSQueueStatus {
                queue_id: 5,
                ..Default::default()
            },
        ],
        ..Default::default()
    }];
    // Sums across workers were pre-aggregated by the caller.
    let flow_counts = BTreeMap::from([((80, 4u8), 12u64), ((81, 4u8), 99u64)]);

    overlay_cos_flow_fair_flow_counts(&mut statuses, &flow_counts);

    let q4 = &statuses[0].queues[0];
    assert_eq!(q4.flow_fair_flows_active, 12);
    assert_eq!(
        q4.flow_fair_buckets_occupied, 6,
        "overlay must not disturb the worker-snapshot bucket half"
    );
    let q5 = &statuses[0].queues[1];
    assert_eq!(
        q5.flow_fair_flows_active, 0,
        "queue with no flow-cache rows stays at the serde default"
    );
}

// -------------------------------------------------------------
// #5290: fair, rotating-cursor RPC-fallback session-delta drain.
// -------------------------------------------------------------

/// Insert `n` live bindings (slots `0..n`) into `coord`, each pre-loaded with
/// `per_binding` pending session deltas, and return the Arcs so a test can
/// inspect their residual state after a drain.
fn seed_pending_delta_bindings(
    coord: &mut Coordinator,
    n: u32,
    per_binding: usize,
) -> Vec<Arc<BindingLiveState>> {
    let mut out = Vec::new();
    for slot in 0..n {
        let live = Arc::new(BindingLiveState::new());
        for _ in 0..per_binding {
            live.push_session_delta(SessionDeltaInfo::default());
        }
        coord.workers.live.insert(slot, live.clone());
        out.push(live);
    }
    out
}

#[test]
fn drain_session_deltas_serves_every_worker_and_arms_overflow() {
    // #5290 fail-on-revert: a budget strictly below the aggregate pending count
    // must be spread FAIRLY across every live binding (each gets budget/N),
    // never handed whole to the first slot. Reverting to the old
    // whole-budget-first-slot drain would drain all 40 from binding 0 and leave
    // bindings 1..4 untouched — failing both the per-binding fairness assertion
    // AND the overflow loss-of-sync arming (the old code armed nothing).
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 4, 50); // 200 total

    let drained = coord.drain_session_deltas(40); // 40 < 200, quantum = 10
    assert_eq!(drained.len(), 40, "drain must return exactly the budget");

    // FAIRNESS: every binding was served its 10-delta quantum, so each has
    // exactly 40 left. The old whole-budget-first drain would leave binding 0
    // with 10 and bindings 1..4 with 50.
    for (i, live) in bindings.iter().enumerate() {
        let residual = live.drain_session_deltas(usize::MAX).len();
        assert_eq!(
            residual, 40,
            "binding {i} must have been served an equal 10-delta quantum \
             (fair drain), leaving 40 — a whole-budget-first drain would not"
        );
    }
}

#[test]
fn drain_session_deltas_overflow_arms_loss_of_sync_latch() {
    // #5290: when the budget cannot drain everything, the residual bindings
    // must be latched loss-of-sync so the owning worker's `take_delta_loss`
    // resync recovers the undrained deltas (never a silent drop). The old drain
    // armed no latch at all.
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 20); // 60 total

    let _ = coord.drain_session_deltas(9); // 9 < 60 => overflow

    for (i, live) in bindings.iter().enumerate() {
        assert!(
            live.take_delta_loss(),
            "binding {i} still holds undrained deltas after a budget overflow, \
             so its loss-of-sync latch must be armed for a resync"
        );
    }
}

#[test]
fn drain_session_deltas_cursor_rotates_so_no_worker_is_starved() {
    // #5290 fail-on-revert: with a tiny budget (< N) only some bindings are
    // served per drain, but the rotating cursor resumes at the next binding, so
    // across successive drains EVERY binding is served. Reverting to the old
    // no-cursor whole-budget-first drain would serve only binding 0 every drain,
    // starving bindings 1 and 2 indefinitely.
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 10); // 30 total

    // budget 2 < 3 bindings => quantum 1, two bindings served per drain.
    for _ in 0..3 {
        let _ = coord.drain_session_deltas(2);
    }

    for (i, live) in bindings.iter().enumerate() {
        let residual = live.drain_session_deltas(usize::MAX).len();
        assert!(
            residual < 10,
            "binding {i} must have been served at least once across three \
             cursor-rotated drains (residual {residual} < 10) — a no-cursor \
             drain would starve every binding but slot 0"
        );
    }
}

#[test]
fn drain_session_deltas_no_overflow_leaves_latch_clear() {
    // A budget >= aggregate pending drains everything and must NOT arm a
    // spurious resync (no thundering-resync when the fallback keeps up).
    let mut coord = Coordinator::new();
    let bindings = seed_pending_delta_bindings(&mut coord, 3, 5); // 15 total

    let drained = coord.drain_session_deltas(100); // 100 >= 15
    assert_eq!(drained.len(), 15, "generous budget drains everything");

    for (i, live) in bindings.iter().enumerate() {
        assert!(
            !live.has_pending_session_deltas(),
            "binding {i} fully drained"
        );
        assert!(
            !live.take_delta_loss(),
            "binding {i} fully drained — no overflow, latch must stay clear"
        );
    }
}

// #6101 (item 2): cross-worker exception-ring MERGE + bringup/teardown
// wiring. `Coordinator::recent_exceptions()` drains the control-thread ring
// plus EVERY per-worker ring, sorts by monotonic timestamp, and caps at the
// historical ring depth; `last_resolution()` picks the newest across the
// control slot and every per-worker slot. #6242: the per-worker rings +
// last-resolution slots now live on each worker's `WorkerRuntimeRecord`
// (`workers.records`), registered as one op at bring-up
// (`reconcile/bringup.rs`) and dropped when the record is removed on
// teardown (a failed spawn never registers a record). Prior coverage
// exercised only the single-ring POD/sampler/reconstruction path; these lock
// the cross-worker merge/sort/cap + the record-drop teardown.
mod exception_ring_merge_6101 {
    use super::*;
    use crate::afxdp::disposition::{ExceptionEvent, ResolutionEvent};
    use std::time::{Duration, Instant};

    /// #6242: a bare dummy `WorkerHandle`. These tests exercise the merge/sort
    /// of the per-worker EXCEPTION RING / LAST-RESOLUTION slots, not the
    /// handle, so the handle is inert.
    fn dummy_handle() -> WorkerHandle {
        WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: Arc::new(Mutex::new(VecDeque::new())),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        }
    }

    /// #6242: register a worker whose runtime record carries the given
    /// exception ring (the field under test) and default everything else.
    fn insert_worker_with_exception_ring(
        coord: &mut Coordinator,
        worker_id: u32,
        exception_ring: Arc<Mutex<ExceptionEventRing>>,
    ) {
        let mut rec = WorkerRuntimeRecord::for_test(dummy_handle());
        rec.exception_ring = exception_ring;
        coord.workers.register(worker_id, rec, None);
    }

    /// #6242: register a worker whose runtime record carries the given
    /// last-resolution slot (the field under test) and default everything else.
    fn insert_worker_with_last_resolution(
        coord: &mut Coordinator,
        worker_id: u32,
        last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    ) {
        let mut rec = WorkerRuntimeRecord::for_test(dummy_handle());
        rec.last_resolution = last_resolution;
        coord.workers.register(worker_id, rec, None);
    }

    #[test]
    fn recent_exceptions_merges_and_sorts_across_workers_and_control_ring() {
        let mut coord = Coordinator::new();
        let base = Instant::now();

        // Control-thread ring: one event at t+30ms.
        coord.recent_exceptions.lock().expect("control ring").push(
            ExceptionEvent::for_test(base + Duration::from_millis(30), "control_ev", "ctl"),
        );

        // Worker 0 ring: events at t+10ms and t+50ms.
        let w0 = Arc::new(Mutex::new(ExceptionEventRing::new()));
        {
            let mut g = w0.lock().expect("w0");
            g.push(ExceptionEvent::for_test(base + Duration::from_millis(10), "w0_a", "w0"));
            g.push(ExceptionEvent::for_test(base + Duration::from_millis(50), "w0_b", "w0"));
        }
        insert_worker_with_exception_ring(&mut coord, 0, w0);

        // Worker 1 ring: events at t+20ms and t+40ms.
        let w1 = Arc::new(Mutex::new(ExceptionEventRing::new()));
        {
            let mut g = w1.lock().expect("w1");
            g.push(ExceptionEvent::for_test(base + Duration::from_millis(20), "w1_a", "w1"));
            g.push(ExceptionEvent::for_test(base + Duration::from_millis(40), "w1_b", "w1"));
        }
        insert_worker_with_exception_ring(&mut coord, 1, w1);

        // Merge: all 5 events from 2 workers + the control ring, ordered by
        // monotonic timestamp (the read-side contract: oldest-first among the
        // newest CAP). A no-op or unsorted merge fails this exact ordering.
        let merged = coord.recent_exceptions();
        let reasons: Vec<&str> = merged.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(
            reasons,
            vec!["w0_a", "w1_a", "control_ev", "w1_b", "w0_b"],
            "events from 2 workers + the control ring merge sorted by monotonic timestamp"
        );

        // Teardown: removing worker 0's record (#6242: the whole runtime
        // record, which drops its exception ring with it) drops its events from
        // the drain; worker 1 + control remain, still sorted.
        coord.workers.remove_record_for_test(0);
        let after: Vec<String> = coord
            .recent_exceptions()
            .into_iter()
            .map(|s| s.reason)
            .collect();
        assert_eq!(
            after,
            vec!["w1_a", "control_ev", "w1_b"],
            "a removed worker's ring is no longer drained"
        );
    }

    #[test]
    fn recent_exceptions_caps_merged_output_at_ring_capacity() {
        let mut coord = Coordinator::new();
        let base = Instant::now();

        // Two workers, 20 events each (each under the per-ring cap), 40 total
        // — more than EXCEPTION_RING_CAPACITY (32). Worker 1's timestamps are
        // strictly newer than worker 0's.
        for (wid, offset, reason) in [(0u32, 0u64, "w0_ev"), (1u32, 1_000u64, "w1_ev")] {
            let ring = Arc::new(Mutex::new(ExceptionEventRing::new()));
            {
                let mut g = ring.lock().expect("ring");
                for i in 0..20u64 {
                    g.push(ExceptionEvent::for_test(
                        base + Duration::from_millis(offset + i),
                        reason,
                        "w",
                    ));
                }
            }
            insert_worker_with_exception_ring(&mut coord, wid, ring);
        }

        let merged = coord.recent_exceptions();
        assert_eq!(
            merged.len(),
            EXCEPTION_RING_CAPACITY,
            "merged output is capped at the historical ring depth"
        );
        // The newest CAP survive: all 20 of worker 1 (newest) + the newest 12
        // of worker 0; the 8 oldest worker-0 events are dropped by the cap.
        let w1_count = merged.iter().filter(|s| s.reason == "w1_ev").count();
        let w0_count = merged.iter().filter(|s| s.reason == "w0_ev").count();
        assert_eq!(w1_count, 20, "all 20 newest (worker 1) events survive the cap");
        assert_eq!(
            w0_count,
            EXCEPTION_RING_CAPACITY - 20,
            "only the newest 12 worker-0 events survive; the 8 oldest are dropped"
        );
    }

    #[test]
    fn last_resolution_picks_newest_across_workers_and_survives_teardown() {
        let mut coord = Coordinator::new();
        let base = Instant::now();

        // Control slot: t+10ms, egress 10.
        *coord.last_resolution.lock().expect("control") =
            Some(ResolutionEvent::for_test(base + Duration::from_millis(10), 10));
        // Worker 0 slot: t+30ms, egress 30 (the newest).
        insert_worker_with_last_resolution(
            &mut coord,
            0,
            Arc::new(Mutex::new(Some(ResolutionEvent::for_test(
                base + Duration::from_millis(30),
                30,
            )))),
        );
        // Worker 1 slot: t+20ms, egress 20.
        insert_worker_with_last_resolution(
            &mut coord,
            1,
            Arc::new(Mutex::new(Some(ResolutionEvent::for_test(
                base + Duration::from_millis(20),
                20,
            )))),
        );

        let newest = coord.last_resolution().expect("resolution");
        assert_eq!(
            newest.egress_ifindex, 30,
            "the newest-by-monotonic slot wins (worker 0)"
        );

        // Teardown of the newest slot → the next-newest (worker 1, t+20) wins.
        // #6242: removing worker 0's record drops its last-resolution slot.
        coord.workers.remove_record_for_test(0);
        let after = coord.last_resolution().expect("resolution");
        assert_eq!(
            after.egress_ifindex, 20,
            "after teardown of the newest slot, the next-newest wins"
        );
    }
}

/// #7936 THE PUBLICATION PATH — the thing this change is actually about.
///
/// Every other #7936 test drives a hand-built `WgTunnelStatus` or
/// `ProcessStatus`: the wire round-trip, the Go mirror, the Prometheus series,
/// the detail renderer. All of them stayed GREEN when the coordinator was made
/// to ignore the telemetry entirely, and when the row was made to hard-code
/// `endpoint_family_mismatch: 0` — both found by mutation, both the same
/// failure as #7172 cut 6's m6: the surfaces AROUND the wiring were tested and
/// the wiring was not.
///
/// This drives the real builder against a real `WgControlEntry`, so the two
/// hops the counters actually take — resolver -> coordinator Arc, coordinator
/// Arc -> wire row — are the subject rather than the assumption.
#[test]
fn wg_tunnel_status_carries_endpoint_resolver_counters_7936() {
    use crate::afxdp::types::TunnelEndpoint;
    use crate::afxdp::types::WgControlEntry;
    use crate::afxdp::wg::endpoint_resolver::WgEndpointResolverTelemetry;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    const ID: u16 = 3;
    let mut coord = Coordinator::new();
    coord.forwarding.tunnel_endpoints.insert(
        ID,
        TunnelEndpoint {
            id: ID,
            logical_ifindex: 41,
            interface_label: "wg0".into(),
            interface: "wg0.0".into(),
            redundancy_group: 0,
            mode: "wireguard".into(),
            outer_family: libc::AF_INET,
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            key: 0,
            ttl: 64,
            transport_table: String::new(),
            wg_listen_port: 51820,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        },
    );
    coord.forwarding.wg_engines.insert(
        ID,
        std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
            crate::afxdp::wg::WgEngineConfig {
                local_private_key: [7u8; 32].into(),
                listen_port: 51820,
                peers: Vec::new(),
            },
        )),
    );

    let telemetry = std::sync::Arc::new(WgEndpointResolverTelemetry::default());
    telemetry.counters.resolve_ok.store(11, Ordering::Relaxed);
    telemetry.counters.resolve_fail.store(12, Ordering::Relaxed);
    telemetry.counters.family_mismatch.store(13, Ordering::Relaxed);
    telemetry.counters.endpoint_changed.store(14, Ordering::Relaxed);
    *telemetry.last_error.lock().expect("last_error") =
        Some("vpn.example.com: no AAAA for a v6 socket".to_string());

    coord.wg_control_threads.insert(
        ID,
        WgControlEntry {
            handle: None,
            engine_ptr: 0,
            spawned_ifindex: 41,
            spawned_tunnel_name: "wg0".into(),
            spawned_outer_mtu: 1420,
            spawned_per_peer_outer_mtu: std::collections::HashMap::new(),
            last_spawn_attempt_ns: 0,
            spawned_kernel_transport: crate::afxdp::types::WgKernelTransport::Deliver,
            resolver_telemetry: Some(std::sync::Arc::clone(&telemetry)),
        },
    );

    let rows = coord.wg_tunnel_statuses();
    assert_eq!(rows.len(), 1, "one wireguard endpoint, one row");
    let r = &rows[0];
    // DISTINCT values per field: an implementation that read one counter and
    // fanned it out, or that transposed two, would pass an all-equal fixture.
    assert_eq!(r.endpoint_resolve_ok, 11);
    assert_eq!(r.endpoint_resolve_fail, 12);
    assert_eq!(r.endpoint_family_mismatch, 13);
    assert_eq!(r.endpoint_changed, 14);
    assert_eq!(
        r.endpoint_last_error, "vpn.example.com: no AAAA for a v6 socket",
        "the retained error text is what makes family_mismatch a diagnosis \
         rather than a number"
    );
}

/// The complement, and the reason the builder tolerates a missing entry: a
/// tunnel of IP literals starts no resolver at all (#7158), so zeros are the
/// TRUE answer rather than a fallback hiding a lookup failure.
#[test]
fn wg_tunnel_status_reports_zeros_without_a_resolver_7936() {
    use crate::afxdp::types::TunnelEndpoint;
    use std::net::{IpAddr, Ipv4Addr};

    const ID: u16 = 4;
    let mut coord = Coordinator::new();
    coord.forwarding.tunnel_endpoints.insert(
        ID,
        TunnelEndpoint {
            id: ID,
            logical_ifindex: 42,
            interface_label: "wg1".into(),
            interface: "wg1.0".into(),
            redundancy_group: 0,
            mode: "wireguard".into(),
            outer_family: libc::AF_INET,
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            key: 0,
            ttl: 64,
            transport_table: String::new(),
            wg_listen_port: 51821,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        },
    );
    coord.forwarding.wg_engines.insert(
        ID,
        std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
            crate::afxdp::wg::WgEngineConfig {
                local_private_key: [8u8; 32].into(),
                listen_port: 51821,
                peers: Vec::new(),
            },
        )),
    );
    // No wg_control_threads entry at all.
    let rows = coord.wg_tunnel_statuses();
    assert_eq!(rows.len(), 1, "a row is never dropped for missing telemetry");
    assert_eq!(rows[0].endpoint_resolve_ok, 0);
    assert_eq!(rows[0].endpoint_family_mismatch, 0);
    assert!(rows[0].endpoint_last_error.is_empty());
}
