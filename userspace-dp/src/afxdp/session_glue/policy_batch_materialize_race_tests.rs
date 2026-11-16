//! Repro: a worker's materialize-on-miss restores a session that a
//! commit-time policy-delete batch (#6948 / #10512) is revoking.
//!
//! `delete_policy_batch` leases every key (Finalizing), pushes
//! `DeletePolicyBatch` to the workers and waits for their acks, and only
//! THEN removes the shared rows. The lease serializes installs that take a
//! tuple-gate permit. Materialize-on-miss takes none: nothing on the
//! lookup -> resolve -> materialize path touches the gate. So a worker that
//! has applied its delete and acked can take the flow's next packet, miss
//! its table, find the shared row the coordinator has not removed yet, and
//! materialize the deleted incarnation again. No second worker delete is
//! sent, and the batch's probe then finds the restored entry.
//!
//! The cell makes the interleaving deterministic. The mock worker runs the
//! REAL `handle_delete_policy_batch` with a private ack counter, then
//! materializes the flow's next packet through the REAL
//! `materialize_shared_session_hit`, and only then acks the coordinator. In
//! production the ack comes first and the packet races the coordinator's
//! shared removal; ordering the materialize before the ack is the same
//! state at the moment the coordinator removes the shared rows.
//!
//! The assertion is the correct property (the worker must not hold the
//! revoked incarnation after the batch), so on the base commit it FAILS.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtOrd};

const FORWARD_ID: u64 = 0xF1_0001;
const REVERSE_ID: u64 = 0xF1_0002;

fn shared_entry(key: SessionKey, id: u64, reverse: bool) -> SyncedSessionEntry {
    let mut metadata = crate::afxdp::testfx::test_metadata();
    metadata.is_reverse = reverse;
    SyncedSessionEntry {
        sibling_last_seen_ns: 0,
        last_served_ns: 0,
        key,
        decision: SessionDecision {
            resolution: crate::afxdp::testfx::test_resolution(),
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        leak_incarnation: 0,
        origin: if reverse {
            SessionOrigin::ReverseFlow
        } else {
            SessionOrigin::SyncImport
        },
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: id,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

/// The flow's next packet on this worker: a table miss, then the shared
/// lookup and materialize the poll path runs. Returns whether it installed.
fn materialize_next_packet(
    sessions: &mut SessionTable,
    shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    forwarding: &ForwardingState,
    now_ns: u64,
) -> Option<bool> {
    let entry = crate::afxdp::shared_ops::lookup_shared_session(shared, key)?;
    let mut resolved = crate::afxdp::shared_ops::ResolvedSessionLookup {
        key: crate::afxdp::shared_ops::ResolvedSessionKey::QueryKey,
        lookup: crate::session::SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata.clone(),
            forwarding_generation: ForwardingGenerationStamp::default(),
            aux: crate::session::SessionLookupAux::unknown(),
        },
        origin: entry.origin,
        shared_entry: Some(entry),
        authority_deferred: false,
    };
    let (_, install_failed) =
        materialize_shared_session_hit(sessions, &mut resolved, forwarding, now_ns, 0x10);
    Some(!install_failed)
}

#[derive(Debug, Default)]
struct WorkerObservations {
    installed_before_batch: bool,
    deleted_by_the_batch: bool,
    rematerialized: Option<bool>,
    probe_found_forward: Option<bool>,
    forward_id_at_end: u64,
}

#[test]
fn a_materialize_after_a_policy_batch_worker_delete_does_not_outlive_the_batch() {
    // A TEST-NET tuple of its own: the tuple gate is process-global.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 241)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 241)),
        src_port: 41_241,
        dst_port: 51_241,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse_key = reverse_session_key(&forward_key, NatDecision::default());

    let mut coordinator = crate::afxdp::coordinator::Coordinator::new();
    for entry in [
        shared_entry(forward_key.clone(), FORWARD_ID, false),
        shared_entry(reverse_key.clone(), REVERSE_ID, true),
    ] {
        crate::afxdp::shared_ops::publish_shared_session(
            &coordinator.sessions.synced,
            &coordinator.sessions.nat,
            &coordinator.sessions.forward_wire,
            &coordinator.sessions.owner_rg_indexes,
            &entry,
        );
    }
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: Arc::clone(&commands),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(
                crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new(),
            ),
            cold_path_atomics: Arc::new(
                crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new(),
            ),
        }),
        None,
    );

    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let worker = {
        let (commands, stop, ready) = (Arc::clone(&commands), Arc::clone(&stop), Arc::clone(&ready));
        let shared = Arc::clone(&coordinator.sessions.synced);
        let key = forward_key.clone();
        std::thread::spawn(move || {
            let forwarding = ForwardingState::default();
            let mut sessions = SessionTable::new();
            let mut seen = WorkerObservations::default();
            // The active flow: materialized on this worker from the shared
            // map (its first packet after a failover).
            seen.installed_before_batch =
                materialize_next_packet(&mut sessions, &shared, &key, &forwarding, 1_000_000)
                    == Some(true)
                    && sessions.session_id_for(&key) == FORWARD_ID;
            ready.store(true, AtOrd::Release);
            while !stop.load(AtOrd::Acquire) {
                let drained: Vec<WorkerCommand> =
                    { commands.lock().expect("commands").drain(..).collect() };
                for cmd in drained {
                    match cmd {
                        WorkerCommand::DeletePolicyBatch {
                            items,
                            applied,
                            pending,
                            report,
                            intents,
                        } => {
                            // The real phase-1 handler, acking a private
                            // counter so the coordinator's ack comes after
                            // the next packet below.
                            let private_ack = AtomicUsize::new(1);
                            let mut deleted = Vec::new();
                            let mut pptp = Vec::new();
                            super::commands::handle_delete_policy_batch(
                                &mut sessions,
                                SteeringMap::unshared_for_test(-1),
                                &forwarding,
                                &BTreeMap::new(),
                                items,
                                applied,
                                &private_ack,
                                report,
                                intents,
                                2_000_000,
                                2,
                                &mut deleted,
                                0,
                                &mut pptp,
                            );
                            seen.deleted_by_the_batch = sessions.session_id_for(&key) == 0;
                            // The flow's next packet: a miss, then the
                            // shared row the coordinator has not removed.
                            seen.rematerialized = materialize_next_packet(
                                &mut sessions,
                                &shared,
                                &key,
                                &forwarding,
                                2_000_100,
                            );
                            pending.fetch_sub(1, AtOrd::AcqRel);
                        }
                        WorkerCommand::ProbePolicyBatch {
                            bares,
                            found,
                            pending,
                        } => {
                            super::commands::handle_probe_policy_tuples(
                                &sessions,
                                &bares,
                                found.as_ref(),
                            );
                            seen.probe_found_forward = Some(
                                found
                                    .lock()
                                    .expect("found")
                                    .iter()
                                    .flatten()
                                    .any(|entry| entry.session_id == FORWARD_ID),
                            );
                            pending.fetch_sub(1, AtOrd::AcqRel);
                        }
                        _ => {}
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            seen.forward_id_at_end = sessions.session_id_for(&key);
            seen
        })
    };
    while !ready.load(AtOrd::Acquire) {
        std::thread::yield_now();
    }

    let items = vec![crate::afxdp::PolicyDeleteItem {
        key: forward_key.clone(),
        session_id: FORWARD_ID,
        forward_only: false,
        companion_session_id: REVERSE_ID,
        captured_companion: Some(reverse_key.clone()),
    }];
    let (outcomes, complete, errors) =
        coordinator.session_domain().delete_policy_batch(&items);
    stop.store(true, AtOrd::Release);
    let seen = worker.join().expect("mock worker");

    assert!(
        seen.installed_before_batch,
        "FIXTURE: the flow must be materialized on the worker before the batch ({seen:?})"
    );
    assert!(
        seen.deleted_by_the_batch,
        "FIXTURE: the real DeletePolicyBatch handler must remove it ({seen:?}; \
         outcomes={outcomes:?} complete={complete} errors={errors:?})"
    );
    {
        let shared = coordinator.sessions.synced.lock().expect("shared");
        assert!(
            !shared.contains_key(&forward_key) && !shared.contains_key(&reverse_key),
            "FIXTURE: the batch must have removed both shared rows ({seen:?}; errors={errors:?})"
        );
    }
    assert_ne!(
        seen.forward_id_at_end, FORWARD_ID,
        "the policy-deleted incarnation must not survive the batch on the worker: the next \
         packet re-materialized it from the shared row the coordinator removes only after the \
         acks ({seen:?}; outcomes={outcomes:?} complete={complete} errors={errors:?})"
    );
}
