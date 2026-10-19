// #12192: dead-worker wiring tests for 'spawn_workers', kept out of bringup.rs so the file stays under the 1500-LOC [WATCH] floor.
use super::*;
use std::sync::atomic::Ordering;

fn session_entry() -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
            nat_scope_ifindex: None,
        },
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        pptp_call_ids: 0,
        source_nat_static: None,
    }
}

fn launch(coord: &mut Coordinator, ids: &[u32]) -> Arc<WorkerCommandQueues> {
    let queues = Arc::new(WorkerCommandQueues::new(
        ids.iter()
            .map(|&id| (id, Arc::new(Mutex::new(VecDeque::new()))))
            .collect(),
    ));
    let workers: BTreeMap<u32, Vec<BindingPlan>> = ids.iter().map(|&id| (id, Vec::new())).collect();
    let (tx, _rx) = mpsc::channel::<WorkerStartupReport>();
    coord.force_worker_healthy_stub = true;
    let outcome = spawn_workers(
        coord,
        workers,
        0,
        Arc::clone(&queues),
        &[],
        DnatTableFds::default(),
        &tx,
    );
    assert!(
        matches!(outcome, LaunchOutcome::AllSpawned { .. }),
        "fixture: every stub worker must spawn"
    );
    queues
}

fn peer_queues(
    queues: &WorkerCommandQueues,
    worker_id: u32,
) -> Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> {
    queues
        .iter()
        .filter(|(id, _)| **id != worker_id)
        .map(|(_, queue)| queue.clone())
        .collect()
}

fn assert_exact_shed(queues: &WorkerCommandQueues, victim: u32, survivors: &[u32]) {
    let shed_before =
        crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_SHED_TOTAL.load(Ordering::Relaxed);
    let drops_before =
        crate::afxdp::worker_queue::current_thread_worker_command_queue_drops_for_test();
    for &worker_id in survivors {
        crate::afxdp::session_glue::replicate_session_upsert(
            &peer_queues(queues, worker_id),
            queues,
            &session_entry(),
        );
    }
    assert!(
        queues
            .get(&victim)
            .expect("victim queue")
            .lock()
            .expect("victim queue")
            .is_empty(),
        "the dead worker's exact queue must receive nothing"
    );
    for &worker_id in survivors {
        assert_eq!(
            queues
                .get(&worker_id)
                .expect("survivor queue")
                .lock()
                .expect("survivor queue")
                .len(),
            survivors.len() - 1,
            "survivor {worker_id} must still receive every other survivor's replica"
        );
    }
    assert_eq!(
        crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_SHED_TOTAL.load(Ordering::Relaxed),
        shed_before + survivors.len() as u64,
        "one shed per survivor fan-out leg aimed at the dead worker"
    );
    assert_eq!(
        crate::afxdp::worker_queue::current_thread_worker_command_queue_drops_for_test(),
        drops_before,
        "a dead-worker shed must not be a generic drop"
    );
}

/// The record and supervisor must share the projection atomics for this
/// queue; a real supervisor panic on that Arc must shed only that queue.
#[test]
fn rv7_record_supervisor_panic_sheds_exact_queue_12192() {
    let _counter_guard = crate::afxdp::counter_test_lock::counter_reader_guard();
    let _shed_lock = crate::afxdp::worker_queue::SHED_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut coord = Coordinator::new();
    let queues = launch(&mut coord, &[0, 1, 2]);
    let records = coord.workers.records_snapshot();
    let victim = Arc::clone(records.get(&1).expect("victim record"));
    assert!(
        Arc::ptr_eq(
            &victim.handle.runtime_atomics,
            queues
                .runtime_atomics_for_queue(&victim.handle.commands)
                .expect("victim queue paired in the generation projection"),
        ),
        "spawn_workers must hand the supervisor/record the projection's atomics"
    );
    let join = spawn_supervised_worker(
        1,
        Arc::clone(&victim.handle.runtime_atomics),
        Arc::clone(&victim.panic),
        || panic!("#12192 test supervisor panic"),
    )
    .expect("spawn panicking supervised thread");
    join.join().expect("supervisor must catch the panic");
    assert!(victim.is_dead(), "supervisor must mark the record dead");
    assert_exact_shed(&queues, 1, &[0, 2]);
    coord.stop();
}
