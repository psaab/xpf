// Tests for afxdp/cos/cross_binding.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep cross_binding.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "cross_binding_tests.rs"]` from cross_binding.rs.

use super::*;
use crate::afxdp::PROTO_TCP;
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{PreparedTxRecycle, PreparedTxRequest, SharedCoSQueueLease};

fn test_prepared_mirror_request(offset: u64, len: u32) -> PreparedTxRequest {
    PreparedTxRequest {
        offset,
        len,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: true,
        overlap_admissions: None,
        enqueue_ns: 0,
    }
}

fn test_prepared_request(offset: u64, len: u32) -> PreparedTxRequest {
    PreparedTxRequest {
        mirror_clone: false,
        ..test_prepared_mirror_request(offset, len)
    }
}

#[test]
fn redirect_local_cos_request_to_owner_pushes_worker_command() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_ok());
    let pending = commands.lock().unwrap();
    assert_eq!(pending.len(), 1);
    match pending.front() {
        Some(WorkerCommand::EnqueueShapedLocal(req)) => {
            assert_eq!(req.egress_ifindex, 80);
            assert_eq!(req.cos_queue_id, Some(4));
        }
        other => panic!("unexpected command queued: {other:?}"),
    }
}

#[test]
fn redirect_local_cos_request_to_owner_uses_interface_default_queue_owner_when_unset() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        5,
        vec![(5, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_ok());
    let pending = commands.lock().unwrap();
    assert_eq!(pending.len(), 1);
}

#[test]
fn redirect_local_cos_request_to_owner_rejects_explicit_queue_miss() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        5,
        vec![(5, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_err());
    assert!(commands.lock().unwrap().is_empty());
}

#[test]
fn redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let tx_owner_live = Arc::new(BindingLiveState::new());
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(
                true,
                7,
                None,
                Some(Arc::new(SharedCoSQueueLease::new(
                    1_000_000,
                    COS_MIN_BURST_BYTES,
                    2,
                ))),
            ),
        )],
        Some(tx_owner_live),
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_err());
    assert!(commands.lock().unwrap().is_empty());
}

/// #780 / Codex adversarial review: verify the decision DAG
/// inside `resolve_local_routing_decision` exactly mirrors
/// the pre-#780 three-step cascade across every quadrant
/// flagged. The decision now carries BOTH Step 1 and Step 2
/// independently so the ingest loop can fall through on Err.
#[test]
fn resolve_local_routing_decision_step1_routes_via_arc() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
        )],
        None,
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    match decision.step1 {
        Some(Step1Action::Arc(ref arc)) => {
            assert!(Arc::ptr_eq(arc, &owner_live));
        }
        _ => panic!("expected Step1 Arc"),
    }
    assert!(decision.step2.is_none());
}

#[test]
fn resolve_local_routing_decision_step1_routes_via_command_when_no_arc() {
    let current_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    match decision.step1 {
        Some(Step1Action::Command(w)) => assert_eq!(w, 7),
        _ => panic!("expected Step1 Command"),
    }
    assert!(decision.step2.is_none());
}

/// Codex round 2 missing-test flag: Step1Command path where
/// iface has tx_owner_live set but queue is not shared_exact
/// and owner_live is None. Step 1 must route via command
/// (because queue's own owner_live is None), AND Step 2
/// should ALSO be set so the cascade falls through on Err.
#[test]
fn resolve_local_routing_decision_step1_command_with_iface_tx_owner_live_populates_both_steps() {
    let current_live = Arc::new(BindingLiveState::new());
    let iface_owner_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(iface_owner_live.clone()),
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    match decision.step1 {
        Some(Step1Action::Command(w)) => assert_eq!(w, 7),
        _ => panic!("expected Step1 Command"),
    }
    // Step 2 must also be populated — cascade fallthrough.
    match decision.step2 {
        Some(ref arc) => assert!(Arc::ptr_eq(arc, &iface_owner_live)),
        None => panic!("expected Step2 populated for cascade fallthrough"),
    }
}

#[test]
fn resolve_local_routing_decision_step2_routes_when_owner_worker_is_current() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(false, 3, Some(owner_live.clone()), None),
        )],
        Some(owner_live.clone()),
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    // Step 1 bails (owner == current), Step 2 routes.
    assert!(decision.step1.is_none());
    match decision.step2 {
        Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
        None => panic!("expected Step2 Arc"),
    }
}

#[test]
fn resolve_local_routing_decision_step2_routes_when_shared_exact_bails_step1() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(
                true,
                3,
                None,
                Some(Arc::new(SharedCoSQueueLease::new(
                    1_000_000,
                    COS_MIN_BURST_BYTES,
                    2,
                ))),
            ),
        )],
        Some(owner_live.clone()),
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    assert!(decision.step1.is_none());
    match decision.step2 {
        Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
        None => panic!("expected Step2 Arc"),
    }
}

#[test]
fn resolve_local_routing_decision_enqueue_local_when_both_bail() {
    let current_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(false, 3, Some(current_live.clone()), None),
        )],
        Some(current_live.clone()),
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    assert!(decision.step1.is_none());
    assert!(decision.step2.is_none());
}

#[test]
fn resolve_local_routing_decision_step2_routes_when_queue_absent() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let ifaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(owner_live.clone()),
        None,
    );
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(99), 3, &current_live);
    assert!(decision.step1.is_none());
    match decision.step2 {
        Some(ref arc) => assert!(Arc::ptr_eq(arc, &owner_live)),
        None => panic!("expected Step2 Arc"),
    }
}

#[test]
fn resolve_local_routing_decision_enqueue_local_when_iface_absent() {
    let current_live = Arc::new(BindingLiveState::new());
    let ifaces: FastMap<i32, WorkerCoSInterfaceFastPath> = FastMap::default();
    let decision = resolve_local_routing_decision(ifaces.get(&80), Some(4), 3, &current_live);
    assert!(decision.step1.is_none());
    assert!(decision.step2.is_none());
}

#[test]
fn redirect_local_cos_request_to_owner_binding_pushes_owner_live_queue() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(owner_live.clone()),
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner_binding(&current_live, &cos_fast_interfaces, req);

    assert!(redirected.is_ok());
    let mut queued = VecDeque::new();
    owner_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
    let mut current_queued = VecDeque::new();
    current_live.take_pending_tx_into(&mut current_queued);
    assert!(current_queued.is_empty());
}

#[test]
fn prepared_cos_request_stays_on_current_tx_binding_for_exact_queue() {
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        5,
        vec![(
            5,
            test_queue_fast_path(
                true,
                7,
                None,
                Some(Arc::new(SharedCoSQueueLease::new(
                    1_000_000,
                    COS_MIN_BURST_BYTES,
                    2,
                ))),
            ),
        )],
        Some(Arc::new(BindingLiveState::new())),
        None,
    );
    let iface_fast = cos_fast_interfaces.get(&80).unwrap();
    let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

    assert!(prepared_cos_request_stays_on_current_tx_binding(
        12, iface_fast, queue_fast,
    ));
    assert!(!prepared_cos_request_stays_on_current_tx_binding(
        13, iface_fast, queue_fast,
    ));
}

#[test]
fn prepared_cos_request_stays_on_current_tx_binding_only_for_exact_queue() {
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        5,
        vec![(5, test_queue_fast_path(false, 7, None, None))],
        Some(Arc::new(BindingLiveState::new())),
        None,
    );
    let iface_fast = cos_fast_interfaces.get(&80).unwrap();
    let queue_fast = iface_fast.queue_fast_path(Some(5)).unwrap();

    assert!(!prepared_cos_request_stays_on_current_tx_binding(
        12, iface_fast, queue_fast,
    ));
}

#[test]
fn redirect_local_cos_request_to_owner_uses_owner_live_queue_when_available() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let owner_live = Arc::new(BindingLiveState::new());
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(false, 7, Some(owner_live.clone()), None),
        )],
        None,
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_ok());
    assert!(commands.lock().unwrap().is_empty());
    let mut queued = VecDeque::new();
    owner_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
    assert_eq!(queued.front().map(|req| req.cos_queue_id), Some(Some(4)));
}

#[test]
fn redirect_local_cos_request_to_owner_redirects_low_rate_exact_queue() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(
                false,
                7,
                None,
                Some(Arc::new(SharedCoSQueueLease::new(
                    1_000_000_000 / 8,
                    COS_MIN_BURST_BYTES,
                    4,
                ))),
            ),
        )],
        Some(Arc::new(BindingLiveState::new())),
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    assert!(redirected.is_ok());
    let pending = commands.lock().unwrap();
    assert_eq!(pending.len(), 1);
    match pending.front() {
        Some(WorkerCommand::EnqueueShapedLocal(req)) => {
            assert_eq!(req.egress_ifindex, 80);
            assert_eq!(req.cos_queue_id, Some(4));
        }
        other => panic!("unexpected command queued: {other:?}"),
    }
}

#[test]
fn redirect_local_exact_cos_request_to_owner_binding_pushes_owner_live_queue() {
    let current_live = Arc::new(BindingLiveState::new());
    let owner_live = Arc::new(BindingLiveState::new());
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(
            4,
            test_queue_fast_path(
                true,
                7,
                None,
                Some(Arc::new(SharedCoSQueueLease::new(
                    1_000_000,
                    COS_MIN_BURST_BYTES,
                    2,
                ))),
            ),
        )],
        Some(owner_live.clone()),
        None,
    );
    let req = TxRequest {
        bytes: vec![1, 2, 3],
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
    };

    let redirected =
        redirect_local_cos_request_to_owner_binding(&current_live, &cos_fast_interfaces, req);

    assert!(redirected.is_ok());
    let mut queued = VecDeque::new();
    owner_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued.front().map(|req| req.egress_ifindex), Some(80));
    let mut current_queued = VecDeque::new();
    current_live.take_pending_tx_into(&mut current_queued);
    assert!(current_queued.is_empty());
}

#[test]
fn redirect_prepared_cos_request_to_owner_preserves_mirror_clone_on_worker_command() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let fast_path = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    )
    .remove(&80)
    .expect("fast path");
    let root = test_cos_runtime_with_exact(false);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 2, 80, root, fast_path);
    unsafe { binding.umem.area().slice_mut_unchecked(128, 3) }
        .expect("source frame")
        .copy_from_slice(&[1, 2, 3]);

    let req = test_prepared_mirror_request(128, 3);
    let redirected =
        redirect_prepared_cos_request_to_owner(&mut binding, req, 2, &worker_commands_by_id, None);

    assert!(redirected.is_ok());
    let pending = commands.lock().unwrap();
    assert_eq!(pending.len(), 1);
    match pending.front() {
        Some(WorkerCommand::EnqueueShapedLocal(req)) => {
            assert!(
                req.mirror_clone,
                "mirror identity must survive worker redirect"
            );
            assert_eq!(req.bytes, vec![1, 2, 3]);
            assert_eq!(req.egress_ifindex, 80);
            assert_eq!(req.cos_queue_id, Some(4));
        }
        other => panic!("unexpected command queued: {other:?}"),
    }
}

#[test]
fn redirect_prepared_cos_request_to_owner_binding_preserves_mirror_clone_on_live_queue() {
    let owner_live = Arc::new(BindingLiveState::new());
    let fast_path = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(owner_live.clone()),
        None,
    )
    .remove(&80)
    .expect("fast path");
    let root = test_cos_runtime_with_exact(false);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 2, 80, root, fast_path);
    unsafe { binding.umem.area().slice_mut_unchecked(128, 3) }
        .expect("source frame")
        .copy_from_slice(&[4, 5, 6]);

    let req = test_prepared_mirror_request(128, 3);
    let redirected = redirect_prepared_cos_request_to_owner_binding(&mut binding, req, None);

    assert!(redirected.is_ok());
    let mut queued = VecDeque::new();
    owner_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1);
    let req = queued.front().expect("queued local request");
    assert!(
        req.mirror_clone,
        "mirror identity must survive owner-live redirect"
    );
    assert_eq!(req.bytes, vec![4, 5, 6]);
    assert_eq!(req.egress_ifindex, 80);
    assert_eq!(req.cos_queue_id, Some(4));
}

// #6310 FAIL-ON-REVERT merge gate: the cross-worker prepared-redirect
// copy must be allocation-free on the WARMED path (a pooled buffer is
// available). Reverting either `frame.to_vec()` site in cross_binding.rs
// makes the measured redirect allocate, so the `allocs == 0` assertion
// goes RED as an ASSERTION FAILURE (not a build break — `to_vec()` and
// `redirect_pool::checkout` both yield a `Vec<u8>`, so the test compiles
// against both). The byte-identity assertion additionally guarantees the
// buffer reuse never corrupts the redirected frame.
#[test]
fn cos_cross_worker_redirect_is_allocation_free_6310() {
    use crate::afxdp::cos::redirect_pool;

    // Isolate the per-thread pool from any residue (single-threaded test
    // runs share a thread-local across tests).
    redirect_pool::clear_for_test();

    let owner_live = Arc::new(BindingLiveState::new());
    let fast_path = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        Some(owner_live.clone()),
        None,
    )
    .remove(&80)
    .expect("fast path");
    let root = test_cos_runtime_with_exact(false);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 2, 80, root, fast_path);

    // A realistic multi-byte source frame at UMEM offset 128.
    let payload: Vec<u8> = (0..64u16).map(|i| (i & 0xff) as u8).collect();
    let len = payload.len() as u32;
    unsafe { binding.umem.area().slice_mut_unchecked(128, payload.len()) }
        .expect("source frame")
        .copy_from_slice(&payload);

    // Pre-reserve the recycle deque so its push_back never reallocates
    // during the measured pass.
    binding.tx_pipeline.free_tx_frames.reserve(16);

    // Warm pass: the first redirect checks out from an EMPTY pool (it
    // allocates a correctly-sized buffer) and warms the free-frame deque
    // and inbox. Drain the owner and recycle the buffer back into the
    // pool, mirroring the production replenish path where the owner
    // recycles the buffer at exact-Local settle.
    let warm_req = test_prepared_request(128, len);
    assert!(
        redirect_prepared_cos_request_to_owner_binding(&mut binding, warm_req, None).is_ok(),
        "warm redirect must route to the owner-live queue",
    );
    let mut warm_drained = VecDeque::new();
    owner_live.take_pending_tx_into(&mut warm_drained);
    let warm_bytes = warm_drained
        .pop_front()
        .expect("warm request queued")
        .bytes;
    assert_eq!(warm_bytes, payload, "warm redirect copied the frame verbatim");
    redirect_pool::recycle(warm_bytes);
    assert_eq!(
        redirect_pool::len_for_test(),
        1,
        "committed buffer returned to the per-worker pool",
    );

    // Measured pass: the redirect must REUSE the pooled buffer and
    // perform ZERO heap allocations.
    let measured_req = test_prepared_request(128, len);
    let (res, allocs) = crate::test_alloc::count_allocs(|| {
        redirect_prepared_cos_request_to_owner_binding(&mut binding, measured_req, None)
    });
    assert!(
        res.is_ok(),
        "measured redirect must route to the owner-live queue",
    );
    assert_eq!(
        allocs, 0,
        "#6310: the warmed cross-worker prepared-redirect copy must be \
         allocation-free (reverting to `frame.to_vec()` makes this > 0)",
    );

    // Byte-identity: buffer reuse must not corrupt the redirected frame.
    let mut measured_drained = VecDeque::new();
    owner_live.take_pending_tx_into(&mut measured_drained);
    let measured = measured_drained
        .pop_front()
        .expect("measured request queued");
    assert_eq!(
        measured.bytes, payload,
        "buffer reuse must preserve the redirected bytes byte-for-byte",
    );
    assert_eq!(measured.egress_ifindex, 80);
    assert_eq!(measured.cos_queue_id, Some(4));
}

// #6310 FAIL-ON-REVERT merge gate — SIBLING SITE. The test above gates the
// `frame.to_vec()` site in `redirect_prepared_cos_request_to_owner_binding`;
// this one gates the OTHER site, in `redirect_prepared_cos_request_to_owner`
// (the queue-owner_live Step-1 redirect arm). Together the two tests gate
// BOTH `to_vec()` sites enumerated in #6310: reverting EITHER makes its
// respective test allocate (`allocs == 0` → RED as an ASSERTION, not a build
// break — `to_vec()` and `redirect_pool::checkout` both yield `Vec<u8>`).
#[test]
fn cos_cross_worker_redirect_to_owner_is_allocation_free_6310() {
    use crate::afxdp::cos::redirect_pool;

    redirect_pool::clear_for_test();

    // owner_live path: the queue's own owner_live routes via
    // `enqueue_tx_owned` (no worker-command channel needed).
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let owner_live = Arc::new(BindingLiveState::new());
    let fast_path = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, Some(owner_live.clone()), None))],
        None,
        None,
    )
    .remove(&80)
    .expect("fast path");
    let root = test_cos_runtime_with_exact(false);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 2, 80, root, fast_path);

    let payload: Vec<u8> = (0..64u16).map(|i| (i & 0xff) as u8).collect();
    let len = payload.len() as u32;
    unsafe { binding.umem.area().slice_mut_unchecked(128, payload.len()) }
        .expect("source frame")
        .copy_from_slice(&payload);
    binding.tx_pipeline.free_tx_frames.reserve(16);

    // Warm pass: checkout from an empty pool (allocates), then recycle the
    // committed buffer back — mirrors the owner-worker settle replenish.
    let warm_req = test_prepared_request(128, len);
    assert!(
        redirect_prepared_cos_request_to_owner(
            &mut binding,
            warm_req,
            2,
            &worker_commands_by_id,
            None,
        )
        .is_ok(),
        "warm redirect must route to the owner-live queue",
    );
    let mut warm_drained = VecDeque::new();
    owner_live.take_pending_tx_into(&mut warm_drained);
    let warm_bytes = warm_drained
        .pop_front()
        .expect("warm request queued")
        .bytes;
    assert_eq!(warm_bytes, payload, "warm redirect copied the frame verbatim");
    redirect_pool::recycle(warm_bytes);
    assert_eq!(
        redirect_pool::len_for_test(),
        1,
        "committed buffer returned to the per-worker pool",
    );

    // Measured pass: reuse the pooled buffer — ZERO heap allocations.
    let measured_req = test_prepared_request(128, len);
    let (res, allocs) = crate::test_alloc::count_allocs(|| {
        redirect_prepared_cos_request_to_owner(
            &mut binding,
            measured_req,
            2,
            &worker_commands_by_id,
            None,
        )
    });
    assert!(
        res.is_ok(),
        "measured redirect must route to the owner-live queue",
    );
    assert_eq!(
        allocs, 0,
        "#6310: the warmed cross-worker redirect_prepared_cos_request_to_owner \
         copy must be allocation-free (reverting to `frame.to_vec()` makes this > 0)",
    );

    let mut measured_drained = VecDeque::new();
    owner_live.take_pending_tx_into(&mut measured_drained);
    let measured = measured_drained
        .pop_front()
        .expect("measured request queued");
    assert_eq!(
        measured.bytes, payload,
        "buffer reuse must preserve the redirected bytes byte-for-byte",
    );
    assert_eq!(measured.egress_ifindex, 80);
    assert_eq!(measured.cos_queue_id, Some(4));
}

/// #10310 (F6): a cross-worker shaped-local redirect refused by a FULL owner
/// queue must come back as `Err(req)` — never `Ok(())`.
///
/// RED on base: the redirect ignores `push_bounded`'s refusal and returns
/// `Ok`, so the drain cascade treats the request as consumed and the shaped
/// frame is discarded with only the aggregate drop counter as a trace.
#[test]
fn redirect_local_cos_request_to_owner_refused_at_capacity_returns_err_10310() {
    use crate::afxdp::worker_queue::{
        MAX_PENDING_WORKER_COMMANDS, WORKER_COMMAND_QUEUE_DROPS, push_bounded,
    };
    use std::sync::atomic::Ordering;

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
    assert_eq!(commands.lock().unwrap().len(), MAX_PENDING_WORKER_COMMANDS);
    let worker_commands_by_id = BTreeMap::from([(7, commands.clone())]);
    let cos_fast_interfaces = test_cos_fast_interfaces(
        80,
        12,
        4,
        vec![(4, test_queue_fast_path(false, 7, None, None))],
        None,
        None,
    );
    let req = TxRequest {
        bytes: vec![9, 9, 9],
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
    };

    let drops_before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);
    let redirected =
        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);

    match redirected {
        Err(req) => {
            assert_eq!(req.egress_ifindex, 80);
            assert_eq!(req.cos_queue_id, Some(4));
            assert_eq!(req.bytes, vec![9, 9, 9]);
        }
        Ok(()) => panic!(
            "refused redirect reported Ok — the shaped request is discarded \
             without a caller-visible failure (#10310)"
        ),
    }
    assert_eq!(
        commands.lock().unwrap().len(),
        MAX_PENDING_WORKER_COMMANDS,
        "a refused push must not grow the queue past the cap"
    );
    assert!(
        WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed) >= drops_before + 1,
        "the refusal must still bump the aggregate drop counter"
    );
}
