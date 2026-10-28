// Tests for `afxdp::tx::drain` — relocated from inline
// `#[cfg(test)] mod tests` to keep `drain/mod.rs` under the
// modularity-discipline LOC threshold. Loaded as a sibling
// submodule via `#[cfg(test)] mod tests;` from `drain/mod.rs`
// (no `#[path]` needed — `tests.rs` is a sibling of `mod.rs`
// inside `drain/`).

use super::*;
use crate::afxdp::tx::test_support::*;

/// #784 Codex review regression pin: mixed-head deque scan.
///
/// The first revision of `drop_cos_bound_local_leftovers` did
/// a head-peek fast-exit: if the deque's front item had
/// `cos_queue_id.is_none()`, the function returned before
/// scanning. That let CoS-bound items LATER in the deque
/// escape to the unshaped `transmit_batch` backup path,
/// bypassing the CoS cap — the exact #760 bypass this filter
/// was designed to close.
///
/// This test constructs a mixed-head deque
/// `[non-cos, cos-bound, non-cos, cos-bound]` and verifies
/// every cos-bound item is either rescued or dropped (NEVER
/// left in the deque), while non-cos items are preserved for
/// the downstream backup transmit path.
///
/// If this test ever relaxes to allow cos-bound items in the
/// survivor set, the #760 cap bypass returns. Adversarial
/// reviewers MUST reject PRs that weaken this.
#[test]
fn partition_cos_bound_local_scans_mixed_head_deque() {
    // Build a pending deque with a NON-CoS head followed by
    // a mix of CoS-bound and non-CoS items. Codex flagged
    // the pre-refactor head-peek as HIGH severity — this is
    // the regression pin.
    let non_cos = |payload: u8| TxRequest {
        bytes: vec![payload; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 99,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let cos_bound = |payload: u8| TxRequest {
        bytes: vec![payload; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 14,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let mut pending: VecDeque<TxRequest> = VecDeque::from([
        non_cos(1),
        cos_bound(2),
        non_cos(3),
        cos_bound(4),
        non_cos(5),
    ]);
    // Rescue stub: always fails (returns Err) so every
    // cos-bound item falls through to drop. Verifies the
    // scan covers the WHOLE deque, not just the head.
    let (dropped, dropped_bytes) =
        partition_cos_bound_local_with_rescue(&mut pending, |req| req.cos_queue_id.is_some(), Err);
    assert_eq!(
        dropped, 2,
        "both cos-bound items must be dropped (scan covers tail)"
    );
    assert_eq!(dropped_bytes, 128, "2 × 64 bytes dropped");
    // Survivors: only the 3 non-CoS items, in original order.
    let survivors: Vec<u8> = pending.iter().map(|r| r.bytes[0]).collect();
    assert_eq!(survivors, vec![1, 3, 5]);
}

/// #784 companion: rescue path pins. When `try_rescue` returns
/// Ok, items are consumed (rescued) — they must NOT remain in
/// the survivor set. Only items that actually fail rescue
/// count toward the drop.
#[test]
fn partition_cos_bound_local_rescues_when_try_rescue_ok() {
    let non_cos = TxRequest {
        bytes: vec![0xAA; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 99,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let cos_bound = TxRequest {
        bytes: vec![0xBB; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 14,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let mut pending: VecDeque<TxRequest> = VecDeque::from([non_cos, cos_bound]);
    // Rescue always succeeds — CoS items must NOT count as drops.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(
        &mut pending,
        |req| req.cos_queue_id.is_some(),
        |_| Ok(()),
    );
    assert_eq!(dropped, 0);
    assert_eq!(dropped_bytes, 0);
    // Survivor set: only the non-CoS item (rescued CoS item
    // was consumed by try_rescue closure).
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes[0], 0xAA);
}

#[test]
fn partition_cos_bound_local_treats_default_queue_on_cos_interface_as_bound() {
    let mut pending: VecDeque<TxRequest> = VecDeque::from([
        TxRequest {
            bytes: vec![0x11; 64].into(),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 14,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
        TxRequest {
            bytes: vec![0x22; 64].into(),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 99,
            cos_queue_id: None,
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
    ]);

    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(
        &mut pending,
        |req| req.egress_ifindex == 14 || req.cos_queue_id.is_some(),
        Err,
    );

    assert_eq!(dropped, 1);
    assert_eq!(dropped_bytes, 64);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].egress_ifindex, 99);
}

#[test]
fn process_pending_queue_in_place_preserves_failed_item_order() {
    let mut pending = VecDeque::from([1u8, 2, 3, 4]);

    process_pending_queue_in_place(&mut pending, |item| match item {
        1 | 3 => Ok(()),
        other => Err(other),
    });

    assert_eq!(pending.into_iter().collect::<Vec<_>>(), vec![2, 4]);
}

#[test]
fn shaped_drain_entry_guard_skips_configured_idle_binding() {
    assert!(
        !has_queued_cos_work(0, 4),
        "configured-but-idle bindings must not enter drain_shaped_tx"
    );
}

#[test]
fn shaped_drain_entry_guard_preserves_nonempty_service_path() {
    assert!(
        has_queued_cos_work(1, 4),
        "queued CoS work must still enter drain_shaped_tx for service and lease progress"
    );
}

#[test]
fn shaped_drain_entry_guard_requires_interface_order() {
    assert!(
        !has_queued_cos_work(1, 0),
        "bindings without an interface order cannot make shaped-drain progress"
    );
}

/// #7204 (A1-b6-F4): the backup drain must not drop either deque's allocation.
///
/// This binds the PROPERTY, not the path, and that is deliberate. The item is a
/// discipline violation, not a wrong result: the drain transmits the same
/// packets before and after the fix, so a test that merely exercises it passes
/// either way and would tell the next reader the discipline is enforced when it
/// is not. Capacity is the observable that separates them — a re-allocated
/// `VecDeque::new()` has capacity 0, and the whole point of the fix is that the
/// deques come back with theirs.
#[test]
fn park_drained_deques_keeps_both_allocations_7204() {
    use std::collections::VecDeque;

    let mut pipeline = crate::afxdp::worker::WorkerTxPipeline::empty_for_test();

    // FULL SUCCESS: retry drained empty. `pending` is empty but carries the
    // allocation the drain took out of `pending_tx_local`.
    let mut pending: VecDeque<TxRequest> = VecDeque::with_capacity(64);
    let retry: VecDeque<TxRequest> = VecDeque::with_capacity(32);
    assert!(pending.capacity() >= 64 && retry.capacity() >= 32, "fixture");
    pending.clear();

    let restored = pipeline.park_drained_deques(pending, retry);
    assert!(
        restored.capacity() >= 64,
        "full success must hand the PENDING allocation back to pending_tx_local; \
         a fresh VecDeque would have capacity 0 and the producer would regrow it \
         on the warmed TX path"
    );
    assert!(
        pipeline.backup_retry_scratch.capacity() >= 32,
        "...and must park the retry deque so the next batch does not allocate one"
    );

    // RETRY PATH: the deque holding items is the one that goes back, or
    // untransmitted requests end up BEHIND newly-arrived ones.
    let mut pipeline2 = crate::afxdp::worker::WorkerTxPipeline::empty_for_test();
    let pending2: VecDeque<TxRequest> = VecDeque::with_capacity(64);
    let mut retry2: VecDeque<TxRequest> = VecDeque::with_capacity(32);
    retry2.push_back(TxRequest {
        bytes: Vec::new().into(),
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 0,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    let restored2 = pipeline2.park_drained_deques(pending2, retry2);
    assert_eq!(
        restored2.len(),
        1,
        "the deque still holding items must be the one restored — FIFO order \
         depends on it, not just its allocation"
    );
    assert!(
        pipeline2.backup_retry_scratch.capacity() >= 64,
        "...and the emptied pending deque becomes the next batch's scratch"
    );
}

/// #10310 (F6): a Step 1 Command enqueue refused by a FULL owner queue must
/// fall through to Step 2 — not report `Ok` and discard the request.
///
/// RED on base: the Step 1 arm ignores `push_bounded`'s refusal and returns
/// `Ok`, so the request is consumed-into-void: neither queued on the owner
/// nor attempted on Step 2/3.
#[test]
fn ingest_cos_pending_tx_step1_refusal_falls_through_to_step2_10310() {
    use crate::afxdp::binding_state::BindingLiveState;
    use crate::afxdp::worker_queue::{MAX_PENDING_WORKER_COMMANDS, push_bounded};

    // Owner worker 7's command queue is exactly at capacity.
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut pending = commands.lock().unwrap();
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            assert!(
                push_bounded(&mut pending, WorkerCommand::VacateAllSharedExactSlots),
                "fill below the cap must be accepted"
            );
        }
    }
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    // Step 2 target: a live state distinct from the test binding's own.
    let step2_live = Arc::new(BindingLiveState::new());
    let fast_path = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(step2_live.clone()),
        None,
    )
    .remove(&80)
    .expect("fast path");
    let root = test_cos_runtime_with_exact(false);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 2, 80, root, fast_path);
    binding.tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes: vec![7, 7, 7].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        crate::afxdp::types::CoSInterfaceConfig {
            queue_id_bitmap: [1, 0, 0, 0],
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: crate::afxdp::FastMap::default(),
            queues: vec![crate::afxdp::types::CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy:
                    crate::afxdp::types::EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy:
                crate::afxdp::types::CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
            inet_precedence_classifier: String::new(),
            inet_precedence_queue_by_prec: [u8::MAX; 8],
        },
    );
    let mut shared_recycles = Vec::new();
    ingest_cos_pending_tx_with_provenance(
        &mut binding,
        &forwarding,
        1_000_000_000,
        2,
        &worker_commands_by_id,
        false,
        &mut shared_recycles,
    );
    // The request must be OBSERVABLE on Step 2 — not swallowed by a false Ok.
    let mut step2_queued = VecDeque::new();
    unsafe { step2_live.take_pending_tx_into(&mut step2_queued) };
    assert_eq!(
        step2_queued.len(),
        1,
        "a Step 1 refusal must fall through to Step 2 (#10310)"
    );
    let req = step2_queued.front().expect("step2 request");
    assert_eq!(req.bytes, vec![7, 7, 7]);
    assert_eq!(req.egress_ifindex, 80);
    assert_eq!(
        commands.lock().unwrap().len(),
        MAX_PENDING_WORKER_COMMANDS,
        "a refused push must not grow the queue past the cap"
    );
    assert!(
        binding.tx_pipeline.pending_tx_local.is_empty(),
        "a Step 2-accepted request must not linger in pending"
    );
}

// #17151 test helpers -----------------------------------------------

fn noop_count_17151(binding: &BindingWorker) -> u64 {
    binding
        .live
        .owner_profile_owner
        .drain_noop_invocations
        .load(Ordering::Relaxed)
}

fn shaped_serviced_counts_17151(binding: &BindingWorker, root_ifindex: i32) -> (usize, u64) {
    let root = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .expect("cos root");
    let queue = &root.queues[0];
    let lat: u64 = queue
        .telemetry
        .owner_profile
        .drain_latency_hist
        .iter()
        .map(|b| b.load(Ordering::Relaxed))
        .sum();
    let inv = queue
        .telemetry
        .owner_profile
        .drain_invocations
        .load(Ordering::Relaxed);
    assert_eq!(lat, inv, "hist buckets must sum to drain_invocations");
    (queue.hot.items.len(), inv)
}

fn token_starved_binding_17151() -> BindingWorker {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.last_refill_ns = u64::MAX - 1_500;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let fast_path = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    )
    .remove(&42)
    .expect("fast path");
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    binding.tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes: vec![0u8; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    binding
}

fn forwarding_with_cos_17151() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        42,
        crate::afxdp::types::CoSInterfaceConfig {
            queue_id_bitmap: [0; 4],
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: crate::afxdp::FastMap::default(),
            queues: vec![crate::afxdp::types::CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy:
                    crate::afxdp::types::EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy:
                crate::afxdp::types::CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
            inet_precedence_classifier: String::new(),
            inet_precedence_queue_by_prec: [u8::MAX; 8],
        },
    );
    forwarding
}

/// #17151: the shared shaped step counts its terminating noop once,
/// and does NOT count when the entry guard admits no drain at all.
/// Removing the helper's noop arm makes the first assertion red;
/// removing the guard makes the second red.
#[test]
fn drain_pending_tx_counts_initial_noop_and_idle_guard_17151() {
    let mut binding = token_starved_binding_17151();
    let forwarding = forwarding_with_cos_17151();
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        BTreeMap::new();
    let mut shared = Vec::new();
    assert!(drain_pending_tx(
        &mut binding,
        1_000_000_000,
        &mut shared,
        &forwarding,
        0,
        &worker_commands_by_id,
    ));
    assert_eq!(
        noop_count_17151(&binding),
        1,
        "initial pass: exactly its terminating None must count once (#17151)"
    );
    assert_eq!(
        shaped_serviced_counts_17151(&binding, 42),
        (2, 0),
        "token-starved queue must stay queued; the noop serviced nothing \
         (1 seeded item + the ingested pending item)"
    );
    assert!(
        binding.tx_pipeline.pending_tx_local.is_empty(),
        "the initial ingest must consume the pending item into the queue"
    );

    // Guard half: fabricate a drain_pending_tx-style context (via the
    // production DrainCtx shape) and drive the shared helper directly
    // on an idle binding — no drain call happens, so no noop counts.
    let root = test_cos_interface_runtime(0);
    let fast_path = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    )
    .remove(&42)
    .expect("fast path");
    let mut idle = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    idle.cos.cos_nonempty_interfaces = 0;
    let ctx = DrainCtx {
        forwarding: &forwarding,
        worker_id: 0,
        worker_commands_by_id: &worker_commands_by_id,
        now_ns: 1_000_000_000,
    };
    let mut did_work = false;
    let mut shared2 = Vec::new();
    assert!(!service_shaped_until_noop(
        &mut idle,
        &ctx,
        &mut shared2,
        &mut did_work
    ));
    assert!(!did_work);
    assert_eq!(
        noop_count_17151(&idle),
        0,
        "idle binding: entry guard admits no drain, so no noop may count (#1318/#17151)"
    );
}

/// #17151: attribution/guard pin for the shared step — this cell
/// produces NO terminating `None` of its own. It pins that the helper
/// attributes each serviced drain exactly once (hist buckets sum to
/// `drain_invocations`), that a pass which drains its queue dry exits
/// via the entry guard (counting nothing extra), and that a later
/// idle pass also counts nothing. The terminating-`None` counting
/// itself is pinned by the two `drain_pending_tx_counts_*` cells.
#[test]
fn service_shaped_until_noop_attributes_and_guards_17151() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 100_000;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let fast_path = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    )
    .remove(&42)
    .expect("fast path");
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let forwarding = forwarding_with_cos_17151();
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        BTreeMap::new();
    let ctx = DrainCtx {
        forwarding: &forwarding,
        worker_id: 0,
        worker_commands_by_id: &worker_commands_by_id,
        now_ns: 1_000_000_000,
    };
    let mut shared = Vec::new();

    // Pass 1: drains the queued item dry.
    let mut did_work = false;
    assert!(service_shaped_until_noop(
        &mut binding,
        &ctx,
        &mut shared,
        &mut did_work
    ));
    assert!(did_work, "the queued item must be serviced");
    assert_eq!(
        shaped_serviced_counts_17151(&binding, 42),
        (0, 1),
        "one item drained, attributed exactly once"
    );
    assert_eq!(
        noop_count_17151(&binding),
        0,
        "a pass that drains dry exits via the guard, not a None drain"
    );

    // Re-arm the queue (as a re-ingest would) and drain again.
    {
        let root = binding.cos.cos_interfaces.get_mut(&42).expect("cos root");
        root.tokens = 100_000;
        root.queues[0].hot.tokens = 1500;
        root.queues[0].hot.last_refill_ns = 1;
        root.queues[0].hot.items.push_back(test_cos_item(1500));
        root.queues[0].hot.queued_bytes = 1500;
        root.queues[0].hot.runnable = true;
        root.nonempty_queues = 1;
        root.runnable_queues = 1;
    }
    binding.cos.cos_nonempty_interfaces = 1;
    let mut did_work2 = false;
    assert!(service_shaped_until_noop(
        &mut binding,
        &ctx,
        &mut shared,
        &mut did_work2
    ));
    assert!(did_work2);
    assert_eq!(
        shaped_serviced_counts_17151(&binding, 42),
        (0, 2),
        "the re-armed queue drains again"
    );
    assert_eq!(noop_count_17151(&binding), 0, "still no None drain occurred");

    // Pass 3 over the drained queue: the guard admits no drain.
    let mut did_work3 = false;
    assert!(!service_shaped_until_noop(
        &mut binding,
        &ctx,
        &mut shared,
        &mut did_work3
    ));
    assert!(!did_work3);
    assert_eq!(
        noop_count_17151(&binding),
        0,
        "idle pass adds no noop (#1318/#17151)"
    );
}
/// #17151: the re-ingest pass counts its terminating noop too —
/// ATTRIBUTABLE by construction: the initial pass counts 0 and the
/// peer arrival is injected between the initial and re-ingest passes.
///
/// PRODUCTION PATH: `drain_pending_tx` is the ONLY caller of the
/// re-ingest budget, so this drives it directly. The binding starts
/// with an EMPTY CoS queue, so the initial shaped pass admits no
/// drain at all (entry guard, #1318) and counts 0. The
/// `AFTER_INITIAL_DRAIN_HOOK` seam then enqueues the peer arrival
/// into the redirect inbox — after the initial pass, before the
/// re-ingest budget — mirroring a peer worker pushing work DURING
/// the shaped drain. The re-ingest ingest admits it into the
/// token-starved queue (`hot.tokens == 0`,
/// `last_refill_ns == u64::MAX - 1_500`, so no refill can rescue it
/// at `now_ns`), and the re-ingest service call's terminating `None`
/// is the ONLY drain that can count. Stubbing that service call (or
/// removing the helper's noop arm) therefore leaves the count at 0
/// -> RED; in the pre-fold cell the same stub stayed green because
/// the initial pass had already counted 1.
#[test]
fn drain_pending_tx_counts_reingest_noop_17151() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.last_refill_ns = u64::MAX - 1_500;
    let fast_path = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    )
    .remove(&42)
    .expect("fast path");
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    assert_eq!(
        binding.cos.cos_nonempty_interfaces, 0,
        "precondition: empty queue, so the initial pass admits no drain"
    );
    // Seed pending work so `drain_pending_tx` enters at all
    // (`binding_has_pending_tx_work`). The item is non-CoS: the
    // initial ingest leaves it for the backup path, the initial
    // shaped pass still admits no drain over the empty queue, and
    // the item is transmitted unshaped after the re-ingest pass.
    binding.tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes: vec![9u8; 64].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 99,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    AFTER_INITIAL_DRAIN_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|binding: &mut BindingWorker| {
            binding
                .live
                .enqueue_tx_owned(TxRequest {
                    bytes: vec![3u8; 64].into(),
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 42,
                    cos_queue_id: Some(0),
                    dscp_rewrite: None,
                    mirror_clone: false,
                    overlap_admissions: None,
                    enqueue_ns: 0,
                })
                .expect("fresh inbox accepts the late peer arrival");
        }));
    });
    let forwarding = forwarding_with_cos_17151();
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        BTreeMap::new();
    let mut shared = Vec::new();
    assert!(drain_pending_tx(
        &mut binding,
        1_000_000_000,
        &mut shared,
        &forwarding,
        0,
        &worker_commands_by_id,
    ));
    assert_eq!(
        noop_count_17151(&binding),
        1,
        "exactly one terminating None may count, and only the re-ingest \
         pass can have produced it: the initial pass counted 0 over the \
         empty queue (#17151)"
    );
    assert_eq!(
        shaped_serviced_counts_17151(&binding, 42),
        (1, 0),
        "the re-ingest-admitted peer item stays queued (starved); \
         no drain serviced it"
    );
    assert!(
        binding.tx_pipeline.pending_tx_local.is_empty(),
        "the re-ingest ingest must consume the inbox item into the queue"
    );
}

/// #17166 guard: the pre-split line anchors, the pure alias, the
/// misleading phase-6 name, and the 4-variant `BackupOutcome`
/// debug-update split must not recur. This test pins the source
/// shape so a future phase split cannot silently re-introduce
/// names or anchors describing a deleted file. The retired
/// spellings are assembled from fragments below so this guard
/// does not itself trip the repo-wide acceptance grep.
#[test]
fn drain_phase_names_and_anchors_stay_current_17166() {
    let sources: [(&str, &str); 6] = [
        ("mod.rs", include_str!("mod.rs")),
        ("phase_backup.rs", include_str!("phase_backup.rs")),
        ("phase_shaped.rs", include_str!("phase_shaped.rs")),
        ("phase_trivial.rs", include_str!("phase_trivial.rs")),
        ("tx/mod.rs", include_str!("../mod.rs")),
        ("binding.rs", include_str!("../../../protocol/binding.rs")),
    ];
    let alias = ["drain_pending_tx_", "local_owner"].concat();
    let phase6 = ["submit_", "and_wake"].concat();
    let anchor = ["drain", ".rs:"].concat();
    let anchor_colon = ["drain", ".rs::"].concat();
    for (name, src) in sources {
        for banned in [
            anchor.as_str(),
            anchor_colon.as_str(),
            alias.as_str(),
            phase6.as_str(),
            "EarlyReturnRetry",
            "EarlyReturnAfterDebugUpdate",
            "EarlyReturnNoDebugUpdate",
        ] {
            assert!(
                !src.contains(banned),
                "{name} must not contain retired drain reference {banned:?} (#17166)"
            );
        }
    }
    // BackupOutcome collapsed to exactly {Continue, Return(bool)}:
    // reject any third variant, payload change, or rename.
    let backup = include_str!("phase_backup.rs");
    let enum_start = backup
        .find("pub(super) enum BackupOutcome")
        .expect("BackupOutcome enum present");
    let enum_body = &backup[enum_start..backup[enum_start..].find('}').map(|i| enum_start + i).expect("enum closes")];
    let variants: Vec<&str> = enum_body
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("//") && !line.contains("enum BackupOutcome")
        })
        .collect();
    assert_eq!(
        variants,
        ["Continue,", "Return(bool),"],
        "BackupOutcome must have exactly the Continue and Return(bool) variants (#17166)"
    );
    // Callers repointed directly at drain_pending_tx.
    for (name, src) in [
        ("dispatch/mod.rs", include_str!("../dispatch/mod.rs")),
        ("tcp_segmentation.rs", include_str!("../tcp_segmentation.rs")),
    ] {
        assert!(
            src.contains("drain_pending_tx("),
            "{name} must call drain_pending_tx directly (#17166)"
        );
    }
    // Rename present.
    assert!(
        include_str!("phase_trivial.rs").contains("fn drain_phase_finish"),
        "phase 6 must be named drain_phase_finish (#17166)"
    );
}
