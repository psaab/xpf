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
