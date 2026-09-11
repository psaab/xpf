// Tests for afxdp/ha.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep ha.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "ha_tests.rs"]` from ha.rs.

use super::*;
use crate::test_zone_ids::*;

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

#[test]
fn demoted_owner_rgs_detects_active_to_inactive_transitions() {
    let previous = BTreeMap::from([(1, active_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, inactive_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(demoted_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn activated_owner_rgs_detects_inactive_to_active_transitions() {
    let previous = BTreeMap::from([(1, inactive_ha_runtime(11)), (2, active_ha_runtime(12))]);
    let current = BTreeMap::from([(1, active_ha_runtime(21)), (2, active_ha_runtime(22))]);

    assert_eq!(activated_owner_rgs(&previous, &current), vec![1]);
}

#[test]
fn update_ha_state_seeds_lease_for_active_group_without_watchdog() {
    let coordinator = Coordinator::new();
    let before = monotonic_nanos() / 1_000_000_000;

    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: true,
            watchdog_timestamp: 0,
            ..HAGroupStatus::default()
        }])
        .expect("update ha state");

    let after = monotonic_nanos() / 1_000_000_000;
    let state = coordinator.ha.rg_runtime.load();
    let group = state.get(&1).expect("ha group");
    assert!(group.active);
    assert_eq!(group.watchdog_timestamp, 0);
    assert!(matches!(group.lease, HAForwardingLease::ActiveUntil(until)
            if until >= before + HA_WATCHDOG_STALE_AFTER_SECS
                && until <= after + HA_WATCHDOG_STALE_AFTER_SECS));
    assert!(group.is_forwarding_active(after));
}

#[test]
fn ha_groups_reports_forwarding_lease_status() {
    let coordinator = Coordinator::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, inactive_ha_runtime(0)),
    ])));

    let groups = coordinator.ha_groups();

    assert!(groups.iter().any(|group| {
        group.rg_id == 1
            && group.active
            && group.forwarding_active
            && group.lease_state == "active"
            && group.lease_until >= now_secs
    }));
    assert!(groups.iter().any(|group| {
        group.rg_id == 2
            && !group.active
            && !group.forwarding_active
            && group.lease_state == "inactive"
            && group.lease_until == 0
    }));
}

#[test]
fn immediate_synced_bpf_programming_skips_locally_active_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 1, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_skips_unknown_owner_when_any_rg_is_active() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    assert!(!synced_entry_allows_local_replace(&state, 0, now_secs));
}

#[test]
fn immediate_synced_bpf_programming_allows_inactive_owner_rg() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);

    assert!(synced_entry_allows_local_replace(&state, 1, now_secs));
}

fn test_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }
}

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
}

fn test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: true,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("sfmix".to_string(), 2);
    forwarding.zone_name_to_id.insert("wan".to_string(), 3);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding
}

fn test_forwarding_state_split_rgs() -> ForwardingState {
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn test_worker_handle(commands: Arc<Mutex<VecDeque<WorkerCommand>>>) -> WorkerHandle {
    WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands,
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(super::cold_path_hist::WorkerColdPathAtomics::new()),
    }
}

#[test]
fn update_ha_state_prewarms_split_rg_reverse_sessions_on_activation() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(worker_commands.clone())),
        None,
    );

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions,
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        None,
        Some(&entry),
    );

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: false,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("seed initial HA state");
    worker_commands.lock().expect("commands").clear();

    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: true,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate rg1");

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    let commands = worker_commands.lock().expect("commands");
    assert_eq!(commands.len(), 3);
    assert!(matches!(
        commands.front(),
        Some(WorkerCommand::RefreshOwnerRGS { owner_rgs }) if owner_rgs == &vec![1]
    ));
    assert!(commands.iter().any(|command| matches!(
        command,
        WorkerCommand::UpsertSynced(session)
            if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
    )));
}

#[test]
fn update_ha_state_demotion_recovers_from_poisoned_worker_command_mutex() {
    // #1790 regression: update_ha_state publishes the new HA state via
    // rg_runtime.store BEFORE propagating demotion side effects. The
    // demote loop used to `?`-return on a poisoned worker command mutex,
    // so a retry diffed against the already-stored state (empty
    // demoted_rgs) and the demotion was permanently lost — partial
    // worker delivery, no demote_shared_owner_rgs, no epoch bump.
    // Poison one of three worker command mutexes and assert the SAME
    // call still completes ALL propagation and returns Ok.
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_with_fabric());
    let worker_queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..3u32)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    for (worker_id, queue) in worker_queues.iter().enumerate() {
        coordinator.workers.register(
            worker_id as u32,
            WorkerRuntimeRecord::for_test(test_worker_handle(queue.clone())),
            None,
        );
    }

    // Locally-owned (non-peer-synced) shared session in RG 1. The
    // demotion must flip its origin to a peer-synced one via
    // demote_shared_owner_rgs.
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );

    // Previous state: RG 1 locally owned (active).
    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: true,
            ..HAGroupStatus::default()
        }])
        .expect("seed active HA state");
    for queue in &worker_queues {
        queue.lock().expect("commands").clear();
    }

    // Poison one worker's command mutex deterministically: a thread
    // panics while holding the lock, and join() observes the panic, so
    // the mutex is poisoned before update_ha_state runs.
    let to_poison = worker_queues[1].clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        worker_queues[1].lock().is_err(),
        "worker 1 command mutex must be poisoned"
    );

    let epoch_before = coordinator.rg_epochs[1].load(Ordering::Acquire);

    // New state: RG 1 demoted. Must return Ok (no early return) and
    // apply every side effect despite the poisoned mutex.
    coordinator
        .update_ha_state(&[HAGroupStatus {
            rg_id: 1,
            active: false,
            ..HAGroupStatus::default()
        }])
        .expect("update_ha_state must recover from poisoned worker mutex");

    // ALL workers — the poisoned one included (recovered via
    // into_inner) — received both demote commands.
    for (worker_id, queue) in worker_queues.iter().enumerate() {
        let pending = queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            pending.iter().any(|command| matches!(
                command,
                WorkerCommand::DemoteOwnerRGS { owner_rgs } if owner_rgs == &vec![1]
            )),
            "worker {worker_id} missing DemoteOwnerRGS for RG 1"
        );
        assert!(
            pending
                .iter()
                .any(|command| matches!(command, WorkerCommand::VacateAllSharedExactSlots)),
            "worker {worker_id} missing VacateAllSharedExactSlots"
        );
    }

    // demote_shared_owner_rgs ran: the locally-owned RG 1 entry was
    // marked peer-synced.
    let demoted = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(&entry.key)
        .cloned()
        .expect("shared entry survives demotion");
    assert!(
        demoted.origin.is_peer_synced(),
        "demotion must mark the shared entry peer-synced"
    );

    // The demoted RG's flow-cache epoch was bumped exactly once.
    assert_eq!(
        coordinator.rg_epochs[1].load(Ordering::Acquire),
        epoch_before + 1,
        "rg_epochs[1] must be bumped by the demotion"
    );
}

#[test]
fn prewarm_recovers_from_poisoned_shared_session_mutex() {
    // #2402 regression: the activation prewarm path acquired the shared
    // session mutex with `.lock().map(..).unwrap_or_default()`. If a
    // worker thread had panicked while holding that lock, `lock()` returns
    // Err, the `.map(..)` closure is SKIPPED, and `unwrap_or_default()`
    // substitutes EMPTY (forward_entries, reverse_entries) — so RG
    // activation proceeded as if there were NO sessions to promote and
    // silently dropped every active synced session at the moment of
    // failover. The fix recovers the poisoned guard
    // (`lock_shared_recover` / `into_inner`) and promotes the EXISTING
    // sessions. This test populates a shared session, poisons the mutex,
    // runs prewarm, and asserts the reverse companion is still
    // synthesized + published (with the old code it would be absent).
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions,
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        None,
        Some(&entry),
    );

    // Poison the shared session mutex deterministically: a thread panics
    // while holding the lock, and join() observes the panic.
    let to_poison = coordinator.sessions.synced.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison shared session mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        coordinator.sessions.synced.lock().is_err(),
        "shared session mutex must be poisoned"
    );

    let recoveries_before =
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed);

    let ha_state = BTreeMap::from([(1, active_ha_runtime(1_000)), (2, active_ha_runtime(1_000))]);
    prewarm_reverse_synced_sessions_for_owner_rgs(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        std::slice::from_ref(&worker_commands),
        -1,
        &coordinator.forwarding,
        &ha_state,
        coordinator.dynamic_neighbors_ref(),
        &[1, 2],
        1_000,
    );

    // The poisoned guard was recovered, not swallowed.
    assert!(
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed)
            > recoveries_before,
        "prewarm must recover (count) the poisoned shared session lock"
    );

    // Fail-on-revert: with the old `.unwrap_or_default()`, the poisoned
    // lock yields empty entries and the reverse companion is NEVER
    // published — this lookup returns None and the assert fails.
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = coordinator
        .sessions
        .synced
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&reverse_key)
        .cloned()
        .expect("reverse companion must survive a poisoned shared lock");
    assert!(reverse.metadata.is_reverse);

    // The worker also received the reverse UpsertSynced (promotion was not
    // silently dropped).
    let commands = worker_commands
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        commands.iter().any(|command| matches!(
            command,
            WorkerCommand::UpsertSynced(session) if session.metadata.is_reverse
        )),
        "worker must receive the recovered reverse UpsertSynced"
    );
}

// --- #4069 RG-activation prewarm dedup is O(N+M), not O(N·M) --------------

#[test]
fn merge_owner_rg_candidate_keys_preserves_order_and_dedups() {
    // The merge must be a stable, deduplicated union: forward keys in their
    // original order, then each reverse key not already present in first-seen
    // order, with duplicates (cross-list AND repeated within reverse) removed.
    // This is the exact semantic contract the O(N+M) hash-set rewrite must
    // preserve versus the former O(N·M) `Vec::contains` dedup.
    let key = |port: u16| SessionKey {
        src_port: port,
        ..test_key()
    };
    let forward = vec![key(1), key(2), key(3)];
    // reverse: key(2) is already in forward (drop), key(10)/key(11) are new,
    // the second key(10) is a within-reverse duplicate (drop).
    let reverse = vec![key(2), key(10), key(11), key(10)];

    let merged = merge_owner_rg_candidate_keys(forward, reverse);

    assert_eq!(
        merged,
        vec![key(1), key(2), key(3), key(10), key(11)],
        "merge must keep forward order then append new reverse keys, deduped"
    );
}

#[test]
fn merge_owner_rg_candidate_keys_scales_linearly_not_quadratically() {
    // RED-on-revert: the former O(N·M) `Vec::contains` dedup re-scanned the
    // growing forward Vec once per reverse key. At N = M = 200_000 that is on
    // the order of 4e10 SessionKey comparisons — tens of seconds to minutes.
    // The O(N+M) hash-set merge completes in well under a second, so this
    // generous 5s budget passes on the fix and blows out (RED) on a quadratic
    // regression. Every key is distinct, so nothing is deduped and the merge
    // performs the full N+M of work (worst case for the old linear scan too,
    // which never finds a match and walks the entire forward Vec each time).
    const N: u32 = 200_000;
    let distinct_key = |i: u32| SessionKey {
        // 10.x.x.x — encode i into the low 24 bits so every key is unique.
        src_ip: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (i & 0x00ff_ffff))),
        ..test_key()
    };
    let forward: Vec<SessionKey> = (0..N).map(distinct_key).collect();
    let reverse: Vec<SessionKey> = (N..2 * N).map(distinct_key).collect();

    let start = std::time::Instant::now();
    let merged = merge_owner_rg_candidate_keys(forward, reverse);
    let elapsed = start.elapsed();

    assert_eq!(
        merged.len() as u32,
        2 * N,
        "all keys are distinct — the union must contain every one"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "O(N+M) prewarm merge took {elapsed:?} for N=M={N}; a quadratic \
         Vec::contains regression (O(N·M)) would blow this 5s budget"
    );
}

// --- #2170 install-generation guard (helper-side belt-and-suspenders) -----

fn synced_entry_with_generation(generation: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation,
        session_id: 0,
        tcp_close_class: 0,
    }
}

fn synced_generation(coordinator: &Coordinator, key: &SessionKey) -> Option<u64> {
    coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .get(key)
        .map(|entry| entry.generation)
}

// #6819 R3: the property the whole counter-scoping change exists to establish,
// bound DETERMINISTICALLY.
//
// Every other assertion on these three counters is a DELTA capture (`let before
// = ...` then `before + 1` or `== before`). A process-global satisfies every one
// of them identically whenever tests do not interleave — and the sanctioned gate
// (`make test-rust`) pins `-- --test-threads=1`, so WITHOUT this test, reverting
// any of the three fields to a `static` leaves the entire gated suite GREEN.
// That is measured, not assumed: reverting `import_cap_drops` reds 24 of 60
// PARALLEL runs and 0 of 12 single-threaded ones; reverting both stale counters
// reds 43 of 60 parallel and 0 of 5 single-threaded.
//
// This test does not depend on interleaving at all, so it reds at ANY thread
// count including the gate's. It drives one refusal of each kind on a BUSY
// coordinator and asserts that an IDLE coordinator, alive in the same process,
// observed none of them. Under a process-global the idle instance reads the busy
// instance's increments and every assertion in the final block fails.
#[test]
fn refusal_counters_are_per_coordinator_not_process_global() {
    let mut busy = Coordinator::new();
    let idle = Coordinator::new();

    // Both instances start clean. (Also the reason the `== before` captures
    // elsewhere in this file are now always `0 == 0` — see the note on
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`.)
    //
    // These carry the SAME diagnostic as the payload assertions at the bottom,
    // because under the sanctioned gate they are what actually fires. libtest
    // runs alphabetically at `--test-threads=1`, so `current_generation_…` (c),
    // `delete_synced_session_gen_…` (d) and `over_ceiling_import_…` (o) all
    // execute BEFORE `refusal_counters_…` (r) and would have already bumped a
    // restored global. A bare `assert_eq!(x, 0)` here reports `left: 1,
    // right: 0` with no explanation, forty lines above the sentence that
    // explains it — and the payload assertions below are reachable only when
    // this test is run in isolation, which is not how `make test-rust` runs it.
    assert_eq!(
        idle.session_install_stale_ignored_total(),
        0,
        "precondition: a fresh Coordinator must read zero stale-install \
         refusals — a nonzero value here means an EARLIER test's refusal leaked \
         in, i.e. `install_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.session_delete_stale_ignored_total(),
        0,
        "precondition: a fresh Coordinator must read zero stale-delete \
         refusals — a nonzero value here means an EARLIER test's refusal leaked \
         in, i.e. `delete_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.synced_import_cap_drops_total(),
        0,
        "precondition: a fresh Coordinator must read zero cap drops — a nonzero \
         value here means an EARLIER test's refusal leaked in, i.e. \
         `import_cap_drops` is process-global again (#6819)"
    );

    // Entry cap = 2 (logical override 1, doubled for the synthesized reverse).
    busy.synced_import_cap_override
        .store(1, std::sync::atomic::Ordering::Relaxed);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    busy.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    let key = test_key();
    busy.upsert_synced_session(synced_entry_with_generation(2));
    // (a) stale install — refused, counted.
    busy.upsert_synced_session(synced_entry_with_generation(1));
    // (b) stale delete — refused, counted; the entry survives.
    busy.delete_synced_session_gen(key.clone(), 1);
    // (c) over-ceiling NEW forward — the map already holds the forward + its
    // synthesized reverse, so it is at the entry cap. Refused, counted.
    busy.upsert_synced_session(synced_entry_port(2000, 0));

    assert_eq!(
        busy.session_install_stale_ignored_total(),
        1,
        "setup: the busy coordinator must have refused exactly one stale install"
    );
    assert_eq!(
        busy.session_delete_stale_ignored_total(),
        1,
        "setup: the busy coordinator must have refused exactly one stale delete"
    );
    assert_eq!(
        busy.synced_import_cap_drops_total(),
        1,
        "setup: the busy coordinator must have refused exactly one over-ceiling \
         import"
    );

    // THE BINDING ASSERTIONS. A process-global would have leaked all three of
    // the refusals above into this second, untouched Coordinator.
    assert_eq!(
        idle.session_install_stale_ignored_total(),
        0,
        "a second Coordinator observed another instance's stale-install \
         refusal — `install_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.session_delete_stale_ignored_total(),
        0,
        "a second Coordinator observed another instance's stale-delete \
         refusal — `delete_stale_ignored` is process-global again (#6819)"
    );
    assert_eq!(
        idle.synced_import_cap_drops_total(),
        0,
        "a second Coordinator observed another instance's over-ceiling import \
         refusal — `import_cap_drops` is process-global again (#6819)"
    );
}

// A stale-generation upsert (gen=1 after gen=2 is stored) must be refused so
// the per-key stored generation never regresses (the delayed-stale-install
// variant, SMR C3). Mirrors the Go install guard.
#[test]
fn upsert_synced_session_refuses_stale_generation_install() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_install_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation(&coordinator, &key), Some(2));

    // Delayed stale install (gen=1) — must be refused, stored gen stays 2.
    coordinator.upsert_synced_session(synced_entry_with_generation(1));
    assert_eq!(
        synced_generation(&coordinator, &key),
        Some(2),
        "stale-generation install rolled the stored generation back"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "stale install should be counted"
    );

    // #6819 §7 positive control. Without this leg the test accepts a guard
    // that refuses EVERY generation-1 install, or every install whose
    // generation differs from the stored one — rejecting the whole category
    // still yields "stored stays 2, counter +1". Pin that the refusal is
    // SELECTIVE, so the test carries its own control rather than depending on
    // `upsert_synced_session_applies_equal_and_newer_generation` being read
    // alongside it.
    coordinator.upsert_synced_session(synced_entry_with_generation(3));
    assert_eq!(
        synced_generation(&coordinator, &key),
        Some(3),
        "a NEWER-generation install must still apply — the guard refuses only \
         strictly-older generations, not every generation change"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "a legitimate newer install must not bump the stale-refusal counter"
    );
}

// ── #5674: synced-import aggregate admission bound (coordinator) ──────
//
// Peer-synced sessions were imported with NO cap and fanned out to EVERY
// worker command queue+table, so a peer under session-table pressure — or a
// malicious/compromised peer — could drive this node PAST its own aggregate
// session ceiling and multiply that state across all workers (the
// availability/DoS root of #5674). `upsert_synced_session` now bounds the
// shared synced map at `2 * worker_count * DEFAULT_MAX_SESSIONS` and drop-
// newest-rejects an over-ceiling NEW FORWARD key. The 2× matters: each
// admitted forward logical session publishes TWO entries into `sessions.synced`
// (the forward key + a synthesized reverse companion), so a full symmetric
// peer holding N logical sessions arrives as 2N entries. Sizing the cap to the
// LOGICAL ceiling N while counting ENTRIES (the pre-fix bug) rejected ~half of
// a legitimate full-peer import above ~50% peer load; the entry cap is 2N so a
// full logical set EXACTLY fits.
//
// This test pins: (a) a FULL symmetric-peer logical set (LOGICAL_CEILING
// forward sessions = 2×LOGICAL_CEILING entries) ALL admit with ZERO drops —
// the regression the review found (a >50% silent under-sync); (b) the NEXT
// forward, EXCEEDING the logical ceiling, is drop-newest REJECTED and never
// fanned out to the worker command queue (the per-worker multiplication is
// bounded); (c) a REPLACE of an admitted key still applies at the ceiling (the
// cap is scoped to NEW forward keys, not a blanket block).
//
// PARENT-RED recipe: neutralize the single reject in the
// `upsert_synced_session` gate (`ha.rs`, the
// `if synced_cap != 0 && synced_len >= synced_cap { ...; return; }` — e.g.
// delete the `return;` so the over-ceiling forward falls through and is
// admitted). The over-ceiling key then lands in the shared map + the worker
// queue, so the `is_none()` / not-enqueued reject assertions below fail as
// clean assertions. Target-count = 1 gate site.
fn synced_entry_port(port: u16, generation: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: SessionKey {
            src_port: port,
            ..test_key()
        },
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation,
        session_id: 0,
        tcp_close_class: 0,
    }
}

#[test]
fn upsert_synced_session_rejects_over_ceiling_import_and_does_not_fan_out() {
    let mut coordinator = Coordinator::new();
    // The override expresses a LOGICAL session ceiling; `synced_import_cap()`
    // doubles it to the ENTRY cap (2×LOGICAL_CEILING) because each admitted
    // forward logical session publishes a forward AND a synthesized reverse
    // companion into the shared `synced` map. Choose a small logical ceiling so
    // the boundary is reachable without inserting DEFAULT_MAX_SESSIONS (131072)
    // sessions. In production the logical ceiling is
    // `worker_count * DEFAULT_MAX_SESSIONS` and the entry cap is 2× that.
    const LOGICAL_CEILING: u16 = 3;
    coordinator
        .synced_import_cap_override
        .store(LOGICAL_CEILING as usize, std::sync::atomic::Ordering::Relaxed);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    let before = coordinator.synced_import_cap_drops_total();

    // (a) A FULL symmetric-peer logical set — LOGICAL_CEILING forward sessions,
    // each publishing a forward + synthesized reverse = 2×LOGICAL_CEILING
    // entries — must ALL admit with ZERO drops. This is the #5674 dual-entry
    // regression the review found: sizing the cap to the LOGICAL ceiling while
    // counting ENTRIES silently dropped ~half of a legitimate full-peer import
    // above ~50% peer load. Every forward here is a NEW key at/below the logical
    // ceiling, so none may be rejected. Under the pre-fix (non-2×) cap the third
    // forward would find synced_len == 4 >= cap 3 and be dropped — this loop
    // REDs it.
    let mut admitted_keys = Vec::new();
    for i in 0..LOGICAL_CEILING {
        let entry = synced_entry_port(1000 + i, 0);
        let key = entry.key.clone();
        coordinator.upsert_synced_session(entry);
        assert!(
            synced_generation(&coordinator, &key).is_some(),
            "forward logical session {i} within the ceiling must be admitted — \
             a full symmetric-peer set of {LOGICAL_CEILING} logical sessions \
             ({} entries) must all fit the 2× entry cap (#5674)",
            2 * LOGICAL_CEILING
        );
        admitted_keys.push(key);
    }
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before,
        "a full symmetric-peer logical set must import with NO cap drop — a \
         nonzero count here is the #5674 >50% silent under-sync regression"
    );

    // (b) BEYOND the logical ceiling: the next NEW forward key (a peer
    // exceeding its OWN logical ceiling) is drop-newest rejected.
    let rejected = synced_entry_port(2000, 0);
    let rejected_key = rejected.key.clone();
    coordinator.upsert_synced_session(rejected);
    assert!(
        synced_generation(&coordinator, &rejected_key).is_none(),
        "an over-ceiling synced FORWARD import must be REJECTED, not admitted \
         past the aggregate cap (#5674 admission bound)"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before + 1,
        "the rejected over-ceiling import must bump synced_import_cap_drops"
    );

    // The rejected import must NOT be fanned out to the worker command queue —
    // the per-worker queue multiplication is bounded (#5674 second half). The
    // admitted sessions did fan out (the gate is scoped, not a blanket drop of
    // all fan-out).
    {
        let pending = commands.lock().expect("commands");
        let rejected_enqueued = pending.iter().any(
            |cmd| matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == rejected_key),
        );
        assert!(
            !rejected_enqueued,
            "a rejected over-ceiling synced import must not be fanned out to \
             any worker command queue (#5674 queue-multiplication bound)"
        );
        let admitted_enqueued = pending.iter().any(|cmd| {
            matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == admitted_keys[0])
        });
        assert!(
            admitted_enqueued,
            "the admitted within-ceiling sessions must still fan out to the worker"
        );
    }

    // (c) A REPLACE of an already-admitted key is NOT subject to the cap (it
    // does not grow the map) — an in-flight synced session keeps refreshing at
    // the ceiling. A newer-generation upsert of an admitted key applies even
    // though the shared map is at the entry cap, and it is NOT counted as a
    // drop.
    let drops_after_reject = coordinator.synced_import_cap_drops_total();
    coordinator.upsert_synced_session(synced_entry_port(1000, 7));
    assert_eq!(
        synced_generation(&coordinator, &admitted_keys[0]),
        Some(7),
        "a REPLACE of an existing synced key must apply at the ceiling (the \
         cap gates NEW forward keys, never a refresh) — else a legitimate \
         failover session-refresh would be dropped"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        drops_after_reject,
        "a replace at the ceiling must NOT count as a cap drop"
    );
}

// #5154: the #5674 ceiling read must RECOVER poison too. The test above
// exercises the ceiling on a HEALTHY mutex, so it cannot see the fail-open:
// `upsert_synced_session` read the map length with
// `.lock().map(|s| s.len()).unwrap_or(0)`, which on a poisoned mutex yields
// 0 — and `0 >= synced_cap` is false for ANY nonzero cap, so the aggregate
// admission bound was skipped entirely and the over-ceiling import was
// admitted AND fanned out to every worker queue. Identical fail-open shape to
// the two generation guards, in the same critical section, reached by the
// same contained worker panic.
//
// PARENT-RED recipe: revert ONLY the length read to
// `.lock().map(|s| s.len()).unwrap_or(0)`, ORDERED BEFORE the recovered
// stored-entry read. The ordering is load-bearing: `lock_shared_recover`
// calls `clear_poison()`, so a swallowing read placed AFTER it observes a
// healthy mutex and the mutation is invisible. Target-count = 1 read site.
#[test]
fn over_ceiling_import_rejected_on_poisoned_shared_mutex() {
    let mut coordinator = Coordinator::new();
    const LOGICAL_CEILING: u16 = 3;
    coordinator
        .synced_import_cap_override
        .store(LOGICAL_CEILING as usize, std::sync::atomic::Ordering::Relaxed);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // Fill to the ENTRY cap (2×LOGICAL_CEILING): each admitted forward
    // publishes a forward key AND a synthesized reverse companion.
    for i in 0..LOGICAL_CEILING {
        let entry = synced_entry_port(1000 + i, 0);
        let key = entry.key.clone();
        coordinator.upsert_synced_session(entry);
        assert!(
            synced_generation_recovered(&coordinator, &key).is_some(),
            "setup: forward logical session {i} within the ceiling must be \
             admitted before the map is at its entry cap"
        );
    }

    let before = coordinator.synced_import_cap_drops_total();

    poison_shared_synced(&coordinator);

    // A NEW forward key beyond the ceiling, arriving while the mutex is
    // poisoned, must still be drop-newest REJECTED.
    let rejected = synced_entry_port(2000, 0);
    let rejected_key = rejected.key.clone();
    coordinator.upsert_synced_session(rejected);

    assert!(
        synced_generation_recovered(&coordinator, &rejected_key).is_none(),
        "a poisoned shared mutex let an over-ceiling synced import through — \
         the #5674 admission bound read the map length as 0 via the \
         non-recovering read, so the ceiling never evaluated while the \
         recovering write published the entry anyway"
    );
    assert_eq!(
        coordinator.synced_import_cap_drops_total(),
        before + 1,
        "the over-ceiling import must be REFUSED and counted on a poisoned \
         mutex, exactly as on a healthy one"
    );

    // And it must not reach any worker queue — the #5674 per-worker
    // multiplication bound has to hold on the poisoned path too.
    let pending = commands.lock().expect("commands");
    assert!(
        !pending.iter().any(|cmd| {
            matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == rejected_key)
        }),
        "a rejected over-ceiling import must not be fanned out to any worker \
         command queue, even when the shared mutex was poisoned"
    );
}

// #6819 §7: both admission tests above set `synced_import_cap_override`, which
// returns from the `#[cfg(test)]` branch of `synced_import_cap` BEFORE the
// production expression runs. That test-only seam SHADOWS the production
// formula: with only those two tests, deleting the trailing
// `.saturating_mul(2)` from the production path leaves every cap assertion
// green, because no test ever evaluates it. This test leaves the override at
// its default 0 so the production arithmetic is the thing under test.
//
// The 2x is the property being pinned, not an implementation detail: the cap
// counts ENTRIES while the ceiling it must express is LOGICAL sessions, and
// each admitted forward publishes a forward key AND a synthesized reverse
// companion. A cap sized to the logical ceiling rejects ~half of a legitimate
// full-peer failover import above ~50% peer load (the #5674 dual-entry
// regression).
#[test]
fn synced_import_cap_production_formula_is_twice_the_logical_ceiling() {
    let mut coordinator = Coordinator::new();
    assert_eq!(
        coordinator
            .synced_import_cap_override
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "this test must exercise the PRODUCTION formula — a nonzero override \
         short-circuits `synced_import_cap` before it is reached"
    );
    // A per-worker ceiling of zero would make the 2x assertion below vacuous
    // (0 == 2*0), so pin that the multiplicand is real first.
    let per_worker = crate::session::default_max_sessions();
    assert!(
        per_worker > 0,
        "DEFAULT_MAX_SESSIONS must be positive or the ceiling assertions below \
         cannot distinguish the logical ceiling from twice it"
    );

    // No workers registered (early boot / teardown): a zero ceiling DISABLES
    // the bound, so a transient window never rejects legitimate imports.
    assert_eq!(
        coordinator.synced_import_cap_for(&coordinator.workers.records()),
        0,
        "an unregistered-worker coordinator must report a zero (disabled) \
         ceiling, not a nonzero cap that would reject during early boot"
    );

    const WORKERS: usize = 3;
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    for worker in 0..WORKERS {
        coordinator.workers.register(
            worker as u32,
            WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
            None,
        );
    }

    let logical_ceiling = WORKERS * per_worker;
    assert_eq!(
        coordinator.synced_import_cap_for(&coordinator.workers.records()),
        2 * logical_ceiling,
        "the production ENTRY cap must be TWICE the logical ceiling \
         (worker_count * DEFAULT_MAX_SESSIONS), because each admitted forward \
         logical session publishes a forward key AND a synthesized reverse"
    );
    // Stated separately and explicitly: dropping the trailing 2x is the #5674
    // regression, and it yields exactly the logical ceiling.
    assert_ne!(
        coordinator.synced_import_cap_for(&coordinator.workers.records()),
        logical_ceiling,
        "the ENTRY cap must not equal the LOGICAL ceiling — that is the \
         pre-#5674 sizing that silently under-syncs a peer above ~50% load"
    );
}

// An equal- or newer-generation upsert must apply (equality is NOT refusal).
#[test]
fn upsert_synced_session_applies_equal_and_newer_generation() {
    let coordinator = Coordinator::new();
    let key = test_key();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    coordinator.upsert_synced_session(synced_entry_with_generation(2)); // equal — applies
    assert_eq!(synced_generation(&coordinator, &key), Some(2));
    coordinator.upsert_synced_session(synced_entry_with_generation(5)); // newer — applies
    assert_eq!(synced_generation(&coordinator, &key), Some(5));
}

// A gen-0 (legacy/local) install must apply unconditionally — the guard only
// acts when BOTH the stored and incoming generations are non-zero.
#[test]
fn upsert_synced_session_legacy_zero_generation_applies() {
    let coordinator = Coordinator::new();
    let key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(5));
    coordinator.upsert_synced_session(synced_entry_with_generation(0)); // legacy — applies
    assert!(
        synced_generation(&coordinator, &key).is_some(),
        "a legacy gen-0 install must apply (it overwrites the stored entry)"
    );
}

// delete_synced_session_gen refuses a strictly-older-generation delete and
// applies an equal/newer/zero one (belt-and-suspenders for helper-side
// generation-aware deletes).
#[test]
fn delete_synced_session_gen_refuses_stale_generation() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_delete_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));

    // Stale delete (gen=1) — refused, entry survives.
    coordinator.delete_synced_session_gen(key.clone(), 1);
    assert!(
        synced_generation(&coordinator, &key).is_some(),
        "stale-generation delete wrongly removed the live entry"
    );
    assert_eq!(coordinator.session_delete_stale_ignored_total(), before + 1);

    // Equal-generation delete (gen=2) — applies. This is the positive control:
    // without it the test accepts a guard that refuses EVERY generation-aware
    // delete.
    coordinator.delete_synced_session_gen(key.clone(), 2);
    assert!(
        synced_generation(&coordinator, &key).is_none(),
        "equal-generation delete should remove the entry"
    );
    // #6819 §7: and the legitimate delete must not be counted either —
    // otherwise "refuse everything, count once" still satisfies the pair above.
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        before + 1,
        "an applied equal-generation delete must not bump the stale-refusal \
         counter"
    );
}

// The plain delete_synced_session (delete_gen=0) is unconditional — helper-
// local purges must always remove the entry regardless of its generation.
#[test]
fn delete_synced_session_zero_generation_is_unconditional() {
    let coordinator = Coordinator::new();
    let key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(9));
    coordinator.delete_synced_session(key.clone());
    assert!(
        synced_generation(&coordinator, &key).is_none(),
        "a gen-0 (unconditional) delete must remove the entry"
    );
}

// ── #5154: the generation guards must survive a poisoned shared mutex ──
//
// `upsert_synced_session` read the stored entry with `.lock().ok()` and the
// map length with `.lock().map(..).unwrap_or(0)`;
// `delete_synced_session_gen` read with `.lock().ok()`. After a CONTAINED
// worker panic (#925 supervisor) poisoned `sessions.synced`, all three reads
// silently yielded "nothing stored / empty map" — so the #2170 generation
// guards never evaluated — while the WRITE half (`publish_shared_session` /
// `remove_shared_session`) went through `lock_shared_recover`, which
// `clear_poison()`s and mutates anyway. Validation and mutation applied
// OPPOSITE poison policies, so a delayed stale-generation install regressed
// the stored generation and a stale delete removed a newer live entry.
//
// The fix makes the reads RECOVER too (the #2402 / #1807 module policy), so
// the guards always evaluate against the committed map.
//
// PARENT-RED recipe: restore either read to its swallowing form — e.g.
// `let (previous_entry, synced_len) = self.sessions.synced.lock().ok()
//  .map(|s| (s.get(&entry.key).cloned(), s.len())).unwrap_or((None, 0));`
// in `upsert_synced_session`, or `.lock().ok().and_then(|s|
// s.get(&key).cloned())` in `delete_synced_session_gen`
// (userspace-dp/src/afxdp/ha/session_import.rs). Target-count = 2 read sites.

// Poison `sessions.synced` deterministically: a scoped thread panics while
// holding the lock and `join()` observes the panic (the panic is CONTAINED —
// it never unwinds into the test thread), mirroring a worker panic under the
// #925 supervisor. Every `lock_shared_recover` CLEARS poison, so each
// operation under test must be freshly poisoned.
fn poison_shared_synced(coordinator: &Coordinator) {
    let to_poison = coordinator.sessions.synced.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison shared session mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(
        coordinator.sessions.synced.lock().is_err(),
        "shared session mutex must be poisoned"
    );
}

// Read the stored generation WITHOUT `expect()` so a still-poisoned mutex
// yields a clean assertion failure below rather than a panic in the reader.
fn synced_generation_recovered(coordinator: &Coordinator, key: &SessionKey) -> Option<u64> {
    coordinator
        .sessions
        .synced
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .map(|entry| entry.generation)
}

#[test]
fn stale_generation_install_refused_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_install_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation_recovered(&coordinator, &key), Some(2));

    poison_shared_synced(&coordinator);

    // Delayed stale install (gen=1) against stored gen=2. Pre-fix the poisoned
    // read returned None, the guard was skipped, and `publish_shared_session`
    // recovered the poison and OVERWROTE the entry — rolling the stored
    // generation back to 1.
    coordinator.upsert_synced_session(synced_entry_with_generation(1));
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(2),
        "a poisoned shared mutex let a stale-generation install roll the \
         stored generation back — the #2170 guard was skipped by the \
         non-recovering read while the recovering write committed it"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        before + 1,
        "the stale install must be REFUSED and counted, not silently applied"
    );
    // #6819 §7 scope note: this test alone accepts a build that refuses EVERY
    // nonzero-generation install once the mutex has been poisoned — rejecting
    // the whole category also leaves the stored generation at 2 with the
    // counter at +1. The selectivity is controlled by
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`,
    // which asserts that newer/equal operations still APPLY across poisoning
    // AND that stale ones are still refused. The two are a pair: deleting that
    // control silently widens what this test accepts.
}

#[test]
fn stale_generation_delete_refused_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let before = coordinator.session_delete_stale_ignored_total();

    coordinator.upsert_synced_session(synced_entry_with_generation(2));
    assert_eq!(synced_generation_recovered(&coordinator, &key), Some(2));

    poison_shared_synced(&coordinator);

    // Stale delete (gen=1) against stored gen=2. Pre-fix the poisoned read
    // returned None, so the delete-side guard never evaluated and
    // `remove_shared_session` recovered the poison and removed the entry —
    // a stale delete killing a newer same-key replacement.
    coordinator.delete_synced_session_gen(key.clone(), 1);
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(2),
        "a poisoned shared mutex let a stale-generation delete remove a \
         NEWER live entry — the #2170 delete guard was skipped by the \
         non-recovering read while the recovering remove committed it"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        before + 1,
        "the stale delete must be REFUSED and counted, not silently applied"
    );
    // #6819 §7 scope note: as with the install variant, this test alone accepts
    // a build that refuses EVERY nonzero-generation delete after poisoning. The
    // selectivity is controlled by
    // `current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex`;
    // deleting that control silently widens what this test accepts.
}

// NEGATIVE CONTROL: the fix must RECOVER the poison and keep evaluating the
// guard — not refuse everything it sees on a poisoned mutex. A current/newer
// install and an equal-generation delete must still APPLY across poisoning,
// so HA session sync keeps working after a contained worker panic. (This is
// also what rules out the "refuse the write on poison" alternative: it would
// fail every assertion here.)
#[test]
fn current_generation_install_and_delete_still_apply_on_poisoned_shared_mutex() {
    let coordinator = Coordinator::new();
    let key = test_key();
    let stale_installs_before = coordinator.session_install_stale_ignored_total();
    let stale_deletes_before = coordinator.session_delete_stale_ignored_total();
    let recoveries_before =
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed);

    coordinator.upsert_synced_session(synced_entry_with_generation(2));

    // Newer-generation install on a poisoned mutex — must APPLY.
    poison_shared_synced(&coordinator);
    coordinator.upsert_synced_session(synced_entry_with_generation(3));
    assert_eq!(
        synced_generation_recovered(&coordinator, &key),
        Some(3),
        "a newer-generation install must still apply after poison recovery"
    );

    // Equal-generation delete on a (re-)poisoned mutex — must APPLY.
    poison_shared_synced(&coordinator);
    coordinator.delete_synced_session_gen(key.clone(), 3);
    assert!(
        synced_generation_recovered(&coordinator, &key).is_none(),
        "an equal-generation delete must still remove the entry after \
         poison recovery"
    );

    // Neither legitimate operation was counted as a stale refusal.
    //
    // #6819 note on what the per-instance scoping COST here: `..._before` is now
    // always 0, because each `#[test]` owns its Coordinator. Under the previous
    // process-global scheme these were genuine moving-baseline deltas — another
    // test's refusals could make `stale_installs_before` nonzero — whereas now
    // the two assertions immediately below are literally `0 == 0`, which is also
    // what a never-incremented counter reads. Deleting the `fetch_add` bumps
    // outright leaves THIS test passing in isolation. That is determinism bought
    // at the cost of these two assertions' independence, and it is an acceptable
    // trade only because the same mutation reds four other tests in this file
    // (the two non-poison rejection tests, the two poison ones) plus
    // `refusal_counters_are_per_coordinator_not_process_global`. The family is
    // bound; this negative control is individually weak, which is normal for a
    // negative control but should not be mistaken for coverage.
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        stale_installs_before,
        "a legitimate install must not be counted as a stale refusal"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        stale_deletes_before,
        "a legitimate delete must not be counted as a stale refusal"
    );

    // #6819 §7: the legs above only exercise NEWER/EQUAL operations, so on
    // their own they accept DELETING the generation guard outright — a build
    // that recovers the poison and then applies everything satisfies every
    // assertion so far, and both stale-counter expectations are just the
    // per-instance zero baseline. A negative control that accepts the removal
    // of the thing it is controlling for is not controlling anything, so the
    // selectivity of the recovery is asserted here directly: recovery must
    // keep EVALUATING the guard, not bypass it.
    let stale_key = test_key();
    coordinator.upsert_synced_session(synced_entry_with_generation(9));
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "setup: the re-seeded entry must be stored before the stale probes"
    );

    poison_shared_synced(&coordinator);
    coordinator.upsert_synced_session(synced_entry_with_generation(8));
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "poison recovery must not turn into accept-everything: a STALE \
         install is still refused after the mutex is recovered"
    );
    assert_eq!(
        coordinator.session_install_stale_ignored_total(),
        stale_installs_before + 1,
        "the stale install refused after recovery must be counted exactly once"
    );

    poison_shared_synced(&coordinator);
    coordinator.delete_synced_session_gen(stale_key.clone(), 8);
    assert_eq!(
        synced_generation_recovered(&coordinator, &stale_key),
        Some(9),
        "poison recovery must not turn into accept-everything: a STALE \
         delete is still refused after the mutex is recovered"
    );
    assert_eq!(
        coordinator.session_delete_stale_ignored_total(),
        stale_deletes_before + 1,
        "the stale delete refused after recovery must be counted exactly once"
    );

    // The panic that poisoned the mutex is OBSERVABLE: each recovery bumps
    // the shared counter and emits a journald line. Pre-fix the two guard
    // reads recovered nothing and logged nothing.
    //
    // This bound is >= rather than == on purpose, and it is the ONE assertion
    // in this file that is still measured against a process-global
    // (`SHARED_SESSION_POISON_RECOVERIES`, shared_ops.rs — bumped inside
    // `lock_shared_recover`, which takes only the mutex and so has no
    // per-Coordinator home to move to under #6819). A concurrent test's
    // recovery can only push the observed value UP, so a lower bound cannot
    // false-FAIL; an equality could. It can be satisfied by another test's
    // bumps, which is why the precise claims above ride on the per-instance
    // stale counters instead. `+ 4` is the number of poisonings this test
    // performs: `> before` alone passed even if a single recovery served all
    // of them.
    const POISONINGS: u64 = 4;
    assert!(
        super::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed)
            >= recoveries_before + POISONINGS,
        "each poisoning must be recovered and counted so the underlying worker \
         panic is not silently self-healed"
    );
}

// --- #4393 peer-synced SNAT reverse-NAT dnat_table publish/delete wiring ----

fn synced_snat_entry() -> SyncedSessionEntry {
    let mut decision = test_decision();
    // Forward SNAT: the client source is rewritten to the WAN pool
    // (addr, port) — exactly what the primary published into dnat_table.
    decision.nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    };
    SyncedSessionEntry {
        key: test_key(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

/// #4393 FAIL-ON-REVERT: installing a peer-synced forward SNAT session on the
/// standby must publish the reverse-SNAT `dnat_table` entry (the embedded-ICMP
/// steering map), and deleting the session must release it. Without the publish
/// the standby has no reverse-NAT steering entry, so after failover an inbound
/// embedded-ICMP error (PMTUD Too-Big / traceroute Time-Exceeded) quoting the
/// NATed inner packet is not steered to the helper and is never reverse-NAT'd
/// back to the original client (PMTUD blackhole).
///
/// Real BPF maps cannot be created under `cargo test` (the host runs with
/// `kernel.unprivileged_bpf_disabled`), so the publish/delete are observed via
/// the test-only `DNAT_PUBLISH_ATTEMPTS` / `DNAT_DELETE_ATTEMPTS` counters bumped
/// inside `publish_dnat_table_entry` / `delete_dnat_table_entry` whenever a
/// keyed syscall is issued. The fd is `-1` (EBADF after the keyed attempt is
/// counted). RED on revert: remove the publish from `upsert_synced_session` and
/// the SNAT publish assertion fails; remove the delete from
/// `delete_synced_session_gen` and the SNAT delete assertion fails. The
/// non-SNAT control guards against publishing/deleting for flows that carry no
/// source rewrite.
#[test]
fn synced_snat_install_publishes_and_delete_releases_dnat_table_entry() {
    use crate::afxdp::checksum::{DNAT_DELETE_ATTEMPTS, DNAT_PUBLISH_ATTEMPTS};

    // #6872: the SHARED guard, not a function-local one. A `static` declared in
    // a function body is unnameable elsewhere, so the guard this used to hold
    // excluded nobody — including the identically-named guard in
    // session_glue/tests.rs.
    let _g = crate::afxdp::checksum::dnat_counter_guard();

    let mut coordinator = Coordinator::new();
    // A live v4 dnat_table fd so the publish/delete path is reached; -1 makes
    // the syscall a harmless EBADF after the keyed attempt is counted.
    // #7209: the descriptor set is published as a whole, so a test seeds it
    // with one store rather than assigning a field.
    coordinator.bpf_maps.store(std::sync::Arc::new(crate::afxdp::coordinator::BpfMaps {
        dnat_table_fd: Some(OwnedFd { fd: -1 }),
        ..Default::default()
    }));
    let key = test_key();

    // Forward SNAT synced install must publish the reverse-SNAT entry.
    let before_pub = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_snat_entry());
    let after_pub = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_pub - before_pub,
        1,
        "peer-synced forward SNAT install must publish the reverse-SNAT dnat_table entry \
         (#4393); got {} attempts",
        after_pub - before_pub
    );

    // Deleting the synced SNAT session must release the reverse-SNAT entry.
    let before_del = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(key.clone());
    let after_del = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_del - before_del,
        1,
        "deleting the synced SNAT session must release its reverse-SNAT dnat_table entry \
         (#4393); got {} attempts",
        after_del - before_del
    );

    // Non-SNAT control: a plain synced session (test_decision -> no source
    // rewrite) publishes and deletes nothing.
    let before_pub2 = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_entry_with_generation(0));
    let after_pub2 = DNAT_PUBLISH_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_pub2 - before_pub2,
        0,
        "a non-SNAT synced install must not publish a dnat_table entry"
    );
    let before_del2 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(key);
    let after_del2 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_del2 - before_del2,
        0,
        "deleting a non-SNAT synced session must not attempt a dnat_table delete"
    );
}

// #2962: kicking an export for an EMPTY owner-RG set is a no-op — it must
// not consume an export sequence and the wait must drain nothing, preserving
// the pre-split early return semantics.
#[test]
fn kick_owner_rg_export_empty_set_is_noop_and_consumes_no_sequence() {
    let coordinator = Coordinator::new();
    let before = coordinator.sessions.export_seq.load(Ordering::Relaxed);
    let wait = coordinator.kick_owner_rg_export(&[], 0, false);
    assert_eq!(
        coordinator.sessions.export_seq.load(Ordering::Relaxed),
        before,
        "empty owner-RG export must not consume a sequence"
    );
    assert!(
        wait.wait_and_collect().expect("empty export").0.is_empty(),
        "empty owner-RG export must drain no deltas"
    );
}

// #2962: the locked KICK phase enqueues the export command (with the bumped
// sequence) to every worker and returns immediately; the lock-free wait
// completes once the worker acks. This isolates the blocking ack-wait into
// `OwnerRgExportWait::wait_and_collect`, off the global ServerState lock.
#[test]
fn kick_owner_rg_export_enqueues_command_then_wait_completes_on_ack() {
    let mut coordinator = Coordinator::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let handle = test_worker_handle(commands.clone());
    let ack = handle.session_export_ack.clone();
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(handle), None);

    let wait = coordinator.kick_owner_rg_export(&[1, 2], 0, false);

    {
        let pending = commands.lock().expect("commands");
        assert_eq!(pending.len(), 1, "exactly one export command enqueued");
        match pending.front().expect("front") {
            WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs,
            } => {
                assert_eq!(*sequence, 1, "first export bumps the sequence to 1");
                assert_eq!(owner_rgs, &vec![1, 2], "owner-RG set propagated verbatim");
            }
            other => panic!("expected ExportOwnerRGSessions, got {other:?}"),
        }
    }

    // No real bindings, so the drain yields an empty set once the worker acks.
    ack.store(1, Ordering::Release);
    assert!(
        wait.wait_and_collect()
            .expect("export after ack")
            .0
            .is_empty(),
        "no bindings means no deltas to drain"
    );
}

// ---------------------------------------------------------------------------
// #2880: purge_remapped_tunnel_sessions must not silently swallow a failed
// lossless close-delta push. On a disconnected/saturated event stream the
// close delta cannot be queued — the local sessions are still deleted, and the
// undelivered delta MUST be recorded in the event-stream dropped-frames metric
// (error hygiene), not discarded by the old `let _ =`. The purge is
// CLEANUP-only (not a correctness boundary): a surviving stale entry is
// harmless (encap ifindex guard) and self-heals via the standby's own
// snapshot-apply purge + idle GC, so no resync is forced.
// ---------------------------------------------------------------------------

/// Install one forward synced session whose resolution carries
/// `tunnel_endpoint_id`, returning the coordinator + the session key. The
/// session is in the shared `synced` table (publish_shared_session), so the
/// purge finds it and `delete_synced_session` can remove it.
fn coordinator_with_tunnel_session(tunnel_endpoint_id: u16) -> (Coordinator, SessionKey) {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(ForwardingState::default());
    let mut decision = test_decision();
    decision.resolution.tunnel_endpoint_id = tunnel_endpoint_id;
    let key = test_key();
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(), // is_reverse = false -> emits a close delta
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );
    (coordinator, key)
}

#[test]
fn purge_remapped_tunnel_sessions_records_drop_on_lossless_failure() {
    let (mut coordinator, key) = coordinator_with_tunnel_session(7);

    // Disconnected event stream: push_delta_lossless fails immediately
    // (connected = false), like a wedged/disconnected consumer. Keep `_rx`
    // alive so the channel does not also report Disconnected for an unrelated
    // reason.
    let (sender, _rx) = crate::event_stream::EventStreamSender::test_sender(false, 16);
    coordinator.event_stream = Some(sender);

    let purged = coordinator.purge_remapped_tunnel_sessions(&[7], &ForwardingState::default());

    // The local delete still happened and the count is accurate for the local
    // purge (the count is purely local; propagation failure is recorded
    // separately, not conflated).
    assert_eq!(purged, 1, "the local session is purged regardless of push");
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&key)
            .is_none(),
        "the remapped tunnel session must be deleted locally"
    );

    // FAIL-ON-REVERT: restoring `let _ = handle.push_delta_lossless(...)` (the
    // silent swallow) stops recording the drop, so this assertion goes RED —
    // the undelivered close is once again invisible (#2880).
    let dropped = coordinator
        .event_stream
        .as_ref()
        .expect("event stream")
        .stats()
        .dropped;
    assert_eq!(
        dropped, 1,
        "an undelivered lossless close delta must be recorded in the \
         event-stream dropped-frames metric, not silently swallowed"
    );
}

#[test]
fn purge_remapped_tunnel_sessions_no_drop_on_lossless_success() {
    let (mut coordinator, key) = coordinator_with_tunnel_session(7);

    // Connected event stream with a live receiver and ample capacity: the
    // lossless close-delta push SUCCEEDS, so nothing is recorded as dropped.
    let (sender, rx) = crate::event_stream::EventStreamSender::test_sender(true, 16);
    coordinator.event_stream = Some(sender);

    let purged = coordinator.purge_remapped_tunnel_sessions(&[7], &ForwardingState::default());

    assert_eq!(
        purged, 1,
        "the local session is purged and the count is correct"
    );
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&key)
            .is_none(),
        "the remapped tunnel session must be deleted locally"
    );
    // The close delta reached the consumer and nothing was dropped.
    assert!(
        rx.try_recv().is_ok(),
        "a close delta must be queued to the connected consumer"
    );
    let stats = coordinator
        .event_stream
        .as_ref()
        .expect("event stream")
        .stats();
    assert_eq!(stats.sent, 1, "the close delta must be counted as sent");
    assert_eq!(
        stats.dropped, 0,
        "no drop must be recorded when the close delta was queued losslessly"
    );
}

#[test]
fn drain_session_deltas_from_live_is_fair_across_bindings() {
    // #5290: the owner-RG bulk-export mirror of `Coordinator::drain_session_deltas`
    // must share the same fair rotating-cursor drain — a capped export budget
    // below the aggregate pending count is spread across every binding, not
    // handed whole to the first. Reverting to whole-budget-first would drain all
    // 30 from binding 0 and leave bindings 1..3 untouched.
    let live: Vec<Arc<BindingLiveState>> = (0..3)
        .map(|_| {
            let b = Arc::new(BindingLiveState::new());
            for _ in 0..40 {
                b.push_session_delta(SessionDeltaInfo::default());
            }
            b
        })
        .collect();

    let (drained, cursor, more) = drain_session_deltas_from_live(&live, 30, 0); // quantum 10
    assert_eq!(
        drained.len(),
        30,
        "capped export returns exactly the budget"
    );
    // #9344: the bit this call site used to discard. 120 deltas were queued and
    // 30 drained, so the answer is CAPPED and the remainder is still buffered.
    assert!(
        more,
        "a capped drain that left 90 deltas behind must report more=true — \
         without it a truncated answer and a complete one are indistinguishable"
    );
    // Cursor wrapped back to 0 after serving all three (10 each).
    assert_eq!(cursor % 3, 0, "cursor rotated through every binding");

    for (i, b) in live.iter().enumerate() {
        let residual = b.drain_session_deltas(usize::MAX).len();
        assert_eq!(
            residual, 30,
            "binding {i} must have been served an equal 10-delta quantum, \
             leaving 30 — a whole-budget-first export would not"
        );
    }
}

// ---------------------------------------------------------------------------
// #6652 / #6653 / #6654 — non-recovering locks on the shared-session surfaces.
//
// The module policy is to RECOVER from poison: `lock_shared_recover` keeps the
// committed map, clears the poison, counts and logs. Publish, lookup, remove
// and prewarm all follow it. Six production sites did not, and each applied
// the opposite policy in its own way:
//
//   coordinator/mod.rs  snapshot_shared_session_entries  -> empty vec  (#6652)
//   coordinator/mod.rs  teardown clears x3               -> skip       (#6653)
//   types/mod.rs        owner-RG index clears x4         -> skip       (#6653)
//   ha/export.rs        bulk export                      -> refuse     (#6654)
//   ha/tunnel_purge.rs  #1873 R-D remap purge            -> return 0   (sweep)
//   ha/state.rs         RG-activation log line           -> report 0   (sweep)
//
// The last two are NOT named by any of the three issues. They were found by
// sweeping the PREDICATE ("every production access to a shared-session surface
// recovers") rather than the three cited call sites, and the tunnel-purge one
// is arguably the most severe of the six: on poison the #1873 R-D purge
// silently does nothing, leaving a live session to re-resolve a remapped
// tunnel_endpoint_id into the WRONG tunnel.
//
// What makes these bugs rather than style is the NONDETERMINISM. Every
// recovering path CLEARS the poison, so the poisoned window closes the instant
// any of them runs. Whether a reconcile preserved state, a teardown left a
// surface populated, or an export was refused therefore depended on which
// thread happened to lock first.

// poison_mutex poisons any shared mutex the same way poison_shared_synced does
// — a scoped thread panics while holding it, and join() contains the panic —
// so the teardown probe can poison the sibling maps and the owner-RG indexes,
// not just `synced`.
fn poison_mutex<T: Send + 'static>(m: &Arc<Mutex<T>>) {
    let to_poison = m.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison shared mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(m.lock().is_err(), "mutex must be poisoned");
}

// #6652: the reconcile snapshot read `.lock().map(..).unwrap_or_default()`, so
// a poisoned mutex yielded an EMPTY vector that the reconcile path then
// preserved as "the sessions to bring back". stop_inner(false) replaced the
// workers and bring-up replayed nothing, while the shared map still held them.
//
// RED-on-revert: restore
//   self.sessions.synced.lock().map(|s| s.values().cloned().collect()).unwrap_or_default()
// in snapshot_shared_session_entries and this reads 0 entries.
#[test]
fn reconcile_snapshot_replays_sessions_on_poisoned_shared_mutex_6652() {
    let coordinator = Coordinator::new();
    coordinator.upsert_synced_session(synced_entry_with_generation(1));

    let committed = coordinator.snapshot_shared_session_entries().len();
    assert!(
        committed > 0,
        "fixture broken: nothing committed to the shared map, so a poisoned \
         read returning 0 would be indistinguishable from a correct one"
    );

    poison_shared_synced(&coordinator);

    let snapshot = coordinator.snapshot_shared_session_entries();
    assert_eq!(
        snapshot.len(),
        committed,
        "a poisoned shared mutex made the reconcile snapshot yield ZERO sessions \
         to replay. The map still holds them, so bring-up would rebuild the worker \
         tables empty and silently lose every synced session across a reconcile \
         that crossed a contained worker panic (#6652)"
    );
}

// #6653: teardown skipped a poisoned surface, so it left some maps/indexes
// full and others empty. The asymmetry is what makes it worse than a leak:
// teardown is supposed to leave EVERY surface empty, and poison made it leave
// them inconsistently empty — a state no later code is written to expect. On
// the next start lookups resolve stale sessions, and the survivors still count
// toward the #5674 aggregate admission ceiling, refusing legitimate imports.
//
// Every surface is poisoned, so the probe cannot pass by having recovered only
// the one the fixture happened to touch first.
//
// RED-on-revert: restore any `if let Ok(mut x) = <surface>.lock() { x.clear() }`
// in stop_inner or SharedSessionOwnerRgIndexes::clear and that surface is named.
#[test]
fn full_teardown_clears_every_shared_surface_on_poisoned_mutexes_6653() {
    let mut coordinator = Coordinator::new();
    let key = test_key();
    let entry = synced_entry_with_generation(1);

    // Seed all three maps and all four indexes DIRECTLY rather than through an
    // install API: the property under test is teardown's, and routing through
    // whichever API happens to populate which surface would make the coverage
    // depend on that API rather than on teardown.
    for map in [
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
    ] {
        map.lock()
            .expect("seed map")
            .insert(key.clone(), entry.clone());
    }
    let indexes = &coordinator.sessions.owner_rg_indexes;
    for index in [
        &indexes.sessions,
        &indexes.nat_sessions,
        &indexes.forward_wire_sessions,
        &indexes.reverse_prewarm_sessions,
    ] {
        index
            .lock()
            .expect("seed index")
            .entry(1)
            .or_default()
            .insert(key.clone());
    }

    poison_mutex(&coordinator.sessions.synced);
    poison_mutex(&coordinator.sessions.nat);
    poison_mutex(&coordinator.sessions.forward_wire);
    poison_mutex(&indexes.sessions);
    poison_mutex(&indexes.nat_sessions);
    poison_mutex(&indexes.forward_wire_sessions);
    poison_mutex(&indexes.reverse_prewarm_sessions);

    coordinator.stop_inner(true);

    let indexes = &coordinator.sessions.owner_rg_indexes;
    for (name, len) in [
        (
            "sessions.synced",
            recovered_len(&coordinator.sessions.synced),
        ),
        ("sessions.nat", recovered_len(&coordinator.sessions.nat)),
        (
            "sessions.forward_wire",
            recovered_len(&coordinator.sessions.forward_wire),
        ),
        (
            "owner_rg_indexes.sessions",
            recovered_len(&indexes.sessions),
        ),
        (
            "owner_rg_indexes.nat_sessions",
            recovered_len(&indexes.nat_sessions),
        ),
        (
            "owner_rg_indexes.forward_wire_sessions",
            recovered_len(&indexes.forward_wire_sessions),
        ),
        (
            "owner_rg_indexes.reverse_prewarm_sessions",
            recovered_len(&indexes.reverse_prewarm_sessions),
        ),
    ] {
        assert_eq!(
            len, 0,
            "full teardown left {name} populated because its mutex was poisoned. \
             Teardown must empty EVERY shared surface — a poisoned one that \
             survives leaves the maps and the indexes that mirror them torn \
             apart, so the next start resolves stale sessions and they consume \
             the #5674 admission ceiling (#6653)"
        );
    }
}

// recovered_len reads a length WITHOUT expect() so a still-poisoned mutex
// yields a clean assertion failure rather than panicking inside the reader.
fn recovered_len<K, V>(m: &Arc<Mutex<FastMap<K, V>>>) -> usize {
    m.lock().unwrap_or_else(|p| p.into_inner()).len()
}

// #6654: bulk export returned Err("shared sessions lock poisoned") instead of
// recovering, so the refusal fired purely on interleaving. End-to-end loss was
// bounded (pkg/daemon/daemon_ha_sync.go falls back to the authoritative
// BulkSync), which is why it is the nondeterministic refusal itself that is
// the defect, not a loss of sync.
//
// RED-on-revert: restore `.lock().map_err(|_| "shared sessions lock poisoned")`
// in snapshot_all_sessions_export and this gets that Err back.
#[test]
fn bulk_export_succeeds_on_poisoned_shared_mutex_6654() {
    let mut coordinator = Coordinator::new();
    coordinator.upsert_synced_session(synced_entry_with_generation(1));

    // An event stream must exist or the export short-circuits on "event stream
    // not started" BEFORE reaching the lock — the fixture would then pass
    // against the unfixed code for the wrong reason.
    let (sender, _rx) = crate::event_stream::EventStreamSender::test_sender(false, 16);
    coordinator.event_stream = Some(sender);
    assert!(
        coordinator.snapshot_all_sessions_export().is_ok(),
        "fixture broken: the export already fails before the poisoned lock is reached"
    );

    poison_shared_synced(&coordinator);

    match coordinator.snapshot_all_sessions_export() {
        Ok(_) => {}
        Err(e) => panic!(
            "bulk session export REFUSED on a poisoned shared mutex: {e}. Every \
             other shared-session path clears the poison, so this refusal fires \
             or does not fire purely on which thread locked first — a guard whose \
             firing depends on scheduling is not a guard (#6654)"
        ),
    }
}

// Sweep extra, not named by #6652/#6653/#6654: the #1873 R-D remap purge bailed
// with `return 0` on a poisoned mutex. That purge is what stops a live session
// re-resolving a remapped tunnel_endpoint_id into the WRONG tunnel
// (cross-tunnel encap) or dead-ending on the R-C gate, so silently doing
// nothing is the most consequential of the six sites.
//
// RED-on-revert: restore `let Ok(sessions) = self.sessions.synced.lock() else
// { return 0; };` in purge_remapped_tunnel_sessions and this purges 0.
#[test]
fn tunnel_remap_purge_still_purges_on_poisoned_shared_mutex_6653_sweep() {
    let (mut coordinator, key) = coordinator_with_tunnel_session(7);
    let (sender, _rx) = crate::event_stream::EventStreamSender::test_sender(false, 16);
    coordinator.event_stream = Some(sender);

    poison_shared_synced(&coordinator);

    let purged = coordinator.purge_remapped_tunnel_sessions(&[7], &ForwardingState::default());
    assert_eq!(
        purged, 1,
        "the #1873 R-D remapped-tunnel purge silently did NOTHING on a poisoned \
         shared mutex, leaving the session to re-resolve its stale \
         tunnel_endpoint_id into the wrong tunnel"
    );
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .is_none(),
        "the purged session is still in the shared map"
    );
}

// The armed tripwire, and the part of this change that survives it.
//
// Six sites drifted from the module's poison policy across five separate
// issues (#2402, #1807, #6643, and the three fixed here), which says the
// policy was carried by convention and convention lost. This asserts the
// PREDICATE directly: no production file under src/afxdp/ may take a
// shared-session surface with a bare `.lock()`.
//
// It is deliberately narrow. The needles are the exact field paths of the
// three maps and the four owner-RG indexes, so it cannot red on unrelated
// mutexes — the failure mode that got an AST-shaped guard rejected in #7294.
// It is also WRAP-INSENSITIVE: whitespace is collapsed before searching,
// because the #6652 site was spelled across four lines
// (`self\n.sessions\n.synced\n.lock()`) and a line-oriented grep would have
// walked straight past the very bug this file exists for.
#[test]
fn every_shared_session_lock_in_production_recovers_from_poison_6653() {
    use std::path::Path;

    // Exact spellings of a bare lock on a shared-session surface.
    const NEEDLES: &[&str] = &[
        "sessions.synced.lock()",
        "sessions.nat.lock()",
        "sessions.forward_wire.lock()",
        ".nat_sessions.lock()",
        ".forward_wire_sessions.lock()",
        ".reverse_prewarm_sessions.lock()",
    ];

    fn is_test_file(name: &str) -> bool {
        name.contains("test")
    }

    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if name != "tests" {
                    walk(&path, out);
                }
                continue;
            }
            if !name.ends_with(".rs") || is_test_file(&name) {
                continue;
            }
            // shared_ops.rs OWNS the policy: lock_shared_recover and
            // lock_shared_publish are where a raw lock is the implementation.
            if name == "shared_ops.rs" {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read file");
            out.push((path.display().to_string(), src));
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 20,
        "scanned only {} production files under src/afxdp — the walk is \
         vacuous, so a green here proves nothing",
        files.len()
    );

    let mut offenders = Vec::new();
    for (path, src) in &files {
        // Collapse ALL whitespace so a call broken across lines by rustfmt is
        // still one contiguous string.
        let flat: String = src.split_whitespace().collect::<Vec<_>>().join("");
        for needle in NEEDLES {
            let flat_needle: String = needle.split_whitespace().collect::<Vec<_>>().join("");
            if flat.contains(&flat_needle) {
                offenders.push(format!("{path}: {needle}"));
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "non-recovering lock on a shared-session surface in production code:\n  {}\n\
         Use lock_shared_recover: every other shared-session path CLEARS the \
         poison, so a bare lock here fires or does not fire purely on which \
         thread locked first (#6652/#6653/#6654).",
        offenders.join("\n  ")
    );
}

// --- #6600: reserve-before-publish -----------------------------------------

/// A single-address pool source-NAT rule, so a synced translation names a real
/// pool port that a local flow can contend for.
fn reserve6600_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..crate::SourceNATRuleSnapshot::default()
    }]);
    forwarding
}

/// A peer-synced forward entry whose NAT decision names `pool_port` on the
/// single-address pool above.
/// #7209: register one worker so `reserve_synced_translation` actually runs.
///
/// Not boilerplate. `upsert_synced_session` gates the whole coordinator-side
/// reservation on `!self.workers.records().is_empty()` — with no worker nothing
/// polls, so there is no racing local allocation to guard against and the
/// reserve is deliberately skipped. A fixture without a worker therefore never
/// reaches the code under test, and every leg below would pass by never
/// executing anything. That is how the first draft of this test failed, and it
/// failed in the right direction: leg A red because the counter stayed 0.
fn register_test_worker_7209(coordinator: &mut Coordinator) {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands)),
        None,
    );
}

/// #7209: the degraded-import counter must move EXACTLY when an unresolved
/// zone pair actually costs something, and not otherwise.
///
/// The counter exists because the degradation is otherwise silent: the zone
/// pair fails to resolve, #6211's narrowing is skipped, the pre-#6211 fallback
/// books the reservation, and nothing anywhere says so.
///
/// Three legs, because a counter has two ways to be useless and only one of
/// them is "never fires":
///
///   A. unresolved AND source-NAT present -> counts. The empty
///      `zone_id_to_name` here is not contrived: it is exactly an HA standby's
///      first sync, before any snapshot has been applied.
///   B. resolvable -> does NOT count. Without this leg a counter bumped on
///      every import passes leg A, and the metric would climb on a healthy
///      cluster until an operator learned to ignore it.
///   C. unresolved but NO source-NAT rewrite -> does NOT count. The reservation
///      early-returns on `rewrite_src == None`, so the zone pair is never
///      consulted and nothing is lost. This is the leg that makes the metric
///      mean "something was degraded" rather than "some zone lookup missed".
///
/// Each leg asserts the zone pair's actual resolution state first, so a fixture
/// that stopped exercising the intended case fails loudly instead of passing
/// vacuously.
#[test]
fn synced_import_zone_unresolved_counts_only_real_degradation_7209() {
    // --- Leg A: unresolved, with a source-NAT rewrite to lose. -------------
    let mut unresolved = Coordinator::new();
    register_test_worker_7209(&mut unresolved);
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &unresolved.forwarding,
            &test_metadata(),
        )
        .is_none(),
        "fixture no longer exercises the UNRESOLVED case — a fresh Coordinator's \
         zone_id_to_name must be empty, or leg A proves nothing"
    );
    let before = unresolved.synced_import_zone_unresolved_total();
    unresolved.upsert_synced_session(reserve6600_entry(41000, 21000));
    assert_eq!(
        unresolved.synced_import_zone_unresolved_total(),
        before + 1,
        "an import whose zone pair did not resolve, on a session that DOES carry \
         a source-NAT rewrite, must be counted — otherwise the #6211 narrowing \
         is skipped and nothing tells an operator it happened (#7209)"
    );

    // --- Leg B: resolvable -> must NOT count. ------------------------------
    let mut resolved = Coordinator::new();
    register_test_worker_7209(&mut resolved);
    let mut forwarding = ForwardingState::default();
    forwarding
        .zone_id_to_name
        .insert(TEST_LAN_ZONE_ID, "lan".to_string());
    forwarding
        .zone_id_to_name
        .insert(TEST_WAN_ZONE_ID, "wan".to_string());
    resolved.set_forwarding_for_test(forwarding);
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &resolved.forwarding,
            &test_metadata(),
        )
        .is_some(),
        "fixture no longer exercises the RESOLVED case — leg B would then be a \
         second copy of leg A and could not detect an unconditional bump"
    );
    let before_b = resolved.synced_import_zone_unresolved_total();
    resolved.upsert_synced_session(reserve6600_entry(41001, 21001));
    assert_eq!(
        resolved.synced_import_zone_unresolved_total(),
        before_b,
        "an import whose zone pair RESOLVED was counted as degraded; the metric \
         then climbs on a healthy cluster and stops meaning anything (#7209)"
    );

    // --- Leg C: unresolved but nothing to lose -> must NOT count. ----------
    let mut no_nat = Coordinator::new();
    register_test_worker_7209(&mut no_nat);
    let mut entry = reserve6600_entry(41002, 0);
    entry.decision.nat = NatDecision::default(); // no rewrite_src
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &no_nat.forwarding,
            &entry.metadata,
        )
        .is_none(),
        "leg C must still be an UNRESOLVED case, or it cannot distinguish the \
         source-NAT condition from the zone condition"
    );
    let before_c = no_nat.synced_import_zone_unresolved_total();
    no_nat.upsert_synced_session(entry);
    assert_eq!(
        no_nat.synced_import_zone_unresolved_total(),
        before_c,
        "an import with NO source-NAT rewrite was counted as degraded. The \
         reservation early-returns on rewrite_src == None, so the zone pair is \
         never consulted and nothing was lost — counting it makes the metric a \
         function of how much non-NAT traffic the peer syncs (#7209)"
    );
}

fn reserve6600_entry(src_port: u16, pool_port: u16) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: SessionKey {
            src_port,
            ..test_key()
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                rewrite_src_port: Some(pool_port),
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

/// #6600 fail-on-revert gate: an import whose translated NAT port is already
/// owned by a LOCAL flow must be REFUSED — not published, not fanned out — and
/// counted.
///
/// Before this, `upsert_synced_session` published the shared entry (visible at
/// once on `synced`, `nat` and `forward_wire`) and only THEN enqueued the worker
/// commands. The reservation lived solely inside the worker-local upsert, and
/// `reserve_flow` refuses to steal a port a different live allocation holds —
/// with the refusal returned by nothing, counted by nothing and logged by
/// nothing. A worker that sampled an empty command queue just before the push
/// proceeds into `poll_binding` with the entry already live, and
/// `materialize_shared_session_hit` forwards on `replica.decision.nat` without
/// reserving anything. The session then advertised a translation this node did
/// not own.
///
/// Reverting the pre-publish reservation in `upsert_synced_session` makes case
/// (b) go red: the entry is published and fanned out with the port unreserved.
#[test]
fn upsert_synced_session_refuses_import_whose_nat_port_is_locally_owned_6600() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(reserve6600_forwarding());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // (a) POSITIVE CONTROL FIRST. Without it a coordinator that refused every
    // import would satisfy (b) completely.
    let free = reserve6600_entry(40001, 50001);
    let free_key = free.key.clone();
    coordinator.upsert_synced_session(free);
    assert!(
        synced6600_contains(&coordinator, &free_key),
        "an import whose translated port is FREE must still be admitted"
    );
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        0,
        "an admissible import must not be counted as a reservation refusal"
    );

    // A LOCAL flow now owns pool port 50000 — the port the next import names.
    // This is the racing allocation the publish/enqueue window admits.
    let contended: u16 = 50000;
    let local_flow = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 200)),
        src_port: 44444,
        ..test_key()
    };
    // Occupied through the PUBLIC reservation entry point rather than the
    // allocator's private mint, so the test drives the same code the production
    // paths do. A different flow holding the same translated identity is
    // exactly the "different live allocation" `reserve_flow` refuses to steal
    // from.
    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &coordinator.forwarding.iface_nat_allocators,
            &coordinator.forwarding.source_nat_rules,
            &local_flow,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                rewrite_src_port: Some(contended),
                ..NatDecision::default()
            },
            false,
            None,
            1_000,
        ),
        "setup: the local flow must end up holding the exact port the import names, \
         or the case below is not exercising the collision at all"
    );

    let before = coordinator.synced_import_reserve_refused_total();

    // (b) THE CASE. An import naming the locally-owned port must be refused.
    let clashing = reserve6600_entry(40002, contended);
    let clashing_key = clashing.key.clone();
    coordinator.upsert_synced_session(clashing);

    assert!(
        !synced6600_contains(&coordinator, &clashing_key),
        "an import whose translated NAT port is owned by a LOCAL flow was PUBLISHED; \
         every packet forwarded on that shared-backed decision uses a port this node \
         does not own"
    );
    {
        let pending = commands.lock().expect("commands");
        assert!(
            !pending.iter().any(|cmd| matches!(
                cmd,
                WorkerCommand::UpsertSynced(entry) if entry.key == clashing_key
            )),
            "a refused import must not be fanned out to any worker command queue"
        );
    }
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        before + 1,
        "a refused import must be COUNTED — a silent drop trades one invisible \
         failure for another"
    );
}

/// #6600: with NO worker registered the pre-publish reservation is skipped.
///
/// Nothing polls, so there is no racing local allocation to guard against, and
/// an `Untracked` reservation that no worker ever adopts has no one to release
/// it. Making the coordinator reserve unconditionally would leak a pool port on
/// every early-boot / teardown import.
#[test]
fn upsert_synced_session_skips_pre_publish_reserve_with_no_workers_6600() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(reserve6600_forwarding());

    let entry = reserve6600_entry(40003, 50002);
    let key = entry.key.clone();
    coordinator.upsert_synced_session(entry);

    assert!(
        synced6600_contains(&coordinator, &key),
        "with no workers registered the import must still be admitted"
    );
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        0,
        "the zero-worker path must not refuse imports"
    );
    // And it must have taken NO reservation. A DIFFERENT flow reserving the
    // same translated port proves the port is free: had the coordinator
    // reserved it, the occupancy CAS would refuse this. That is the assertion
    // that binds the guard — without it, deleting the zero-worker carve-out
    // leaves every case green while every early-boot import leaks a pool port
    // with holders == 0 and no worker to release it.
    let unrelated = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 210)),
        src_port: 44446,
        ..test_key()
    };
    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &coordinator.forwarding.iface_nat_allocators,
            &coordinator.forwarding.source_nat_rules,
            &unrelated,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                rewrite_src_port: Some(50002),
                ..NatDecision::default()
            },
            false,
            None,
            1_000,
        ),
        "the zero-worker path must take NO reservation — the port it would have \
         held has no worker to release it"
    );
}

/// #6600: a half-taken reservation must be ROLLED BACK.
///
/// A NAT64 decision carries BOTH a v4 pool source (the source-NAT allocator)
/// and a translated `(pool v4, port)` (the per-prefix allocator), so a session
/// can be admissible to one and not the other. Without the rollback, a
/// source-NAT reservation taken moments before a NAT64 refusal is left behind
/// holding a pool port that NO worker will ever release — the import is not
/// published, so there is no session to reap.
///
/// Deleting the `release_source_nat_allocation` call in
/// `reserve_synced_translation` makes this go red.
#[test]
fn upsert_synced_session_rolls_back_source_nat_when_nat64_refuses_6600() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(reserve6600_forwarding());
    coordinator.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[
        crate::NAT64RuleSnapshot {
            name: "nat64-wkp".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            pool_addresses: vec!["203.0.113.1".to_string()],
            no_v6_frag_header: false,
            ..Default::default()
        },
    ]);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // A NAT64 decision naming pool port 51000 on 203.0.113.1.
    let nat64_port: u16 = 51000;
    let mk = |src_port: u16| SyncedSessionEntry {
        key: SessionKey {
            src_port,
            ..test_key()
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                rewrite_src_port: Some(nat64_port),
                nat64: true,
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    // Occupy the NAT64 translated identity with a DIFFERENT flow, so the
    // import's NAT64 leg refuses while its source-NAT leg succeeds.
    let squatter = mk(40010);
    assert!(
        crate::nat64::reserve_synced_nat64_allocation(
            &coordinator.forwarding.nat64,
            &squatter.key,
            squatter.decision.nat,
            false,
            1_000,
        ),
        "setup: the squatter must take the NAT64 identity"
    );

    let entry = mk(40011);
    let key = entry.key.clone();
    let before = coordinator.synced_import_reserve_refused_total();
    coordinator.upsert_synced_session(entry);

    assert!(
        !synced6600_contains(&coordinator, &key),
        "setup: the import must be refused, or the rollback is not exercised"
    );
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        before + 1,
        "setup: the refusal must be counted"
    );

    // THE ASSERTION: the source-NAT port the refused import briefly held must
    // be free again. An unrelated flow reserving it proves the rollback ran.
    let unrelated = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 211)),
        src_port: 44447,
        ..test_key()
    };
    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &coordinator.forwarding.iface_nat_allocators,
            &coordinator.forwarding.source_nat_rules,
            &unrelated,
            NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                rewrite_src_port: Some(nat64_port),
                ..NatDecision::default()
            },
            false,
            None,
            1_000,
        ),
        "the source-NAT reservation taken before the NAT64 refusal was NOT rolled \
         back — it holds a pool port no worker will ever release, because no \
         session was published to reap"
    );
}

/// #6600: the coordinator's `Untracked` reservation must be ABSORBED by the
/// per-worker reservations rather than doubling them, so the last worker's
/// release still frees the port.
///
/// This is the composability claim the whole design rests on: `reserve_flow`
/// finds the identical `(flow, translated)` already live and takes its
/// idempotent early return, OR-ing the worker's bit into a mask that started
/// EMPTY (`NatHolder::Untracked` contributes no bit). If the coordinator's
/// reservation instead made the worker's reserve REFUSE, no holder bit would
/// ever be recorded and the port would leak.
#[test]
fn coordinator_pre_publish_reserve_is_absorbed_by_worker_reserve_6600() {
    let forwarding = reserve6600_forwarding();
    let entry = reserve6600_entry(40004, 50003);
    let now_ns = 1_000;

    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            None,
            now_ns,
        ),
        "the coordinator's reservation must succeed on a free port"
    );
    // Two workers then reserve the SAME translation, exactly as the fan-out
    // produces. Both must SUCCEED — a refusal here is the failure mode that
    // would leak the port.
    for worker_id in 0..2u32 {
        assert!(
            crate::nat::reserve_synced_source_nat_allocation_for_worker(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
                None,
                now_ns,
                worker_id,
            ),
            "worker {worker_id}'s reservation must be ABSORBED by the coordinator's, \
             not refused — a refusal records no holder bit and the port leaks"
        );
    }
    // The last worker's release frees it: the port is allocatable again by an
    // unrelated flow.
    for worker_id in 0..2u32 {
        crate::nat::release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            now_ns,
            worker_id,
        );
    }
    let other = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 201)),
        src_port: 44445,
        ..test_key()
    };
    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &other,
            entry.decision.nat,
            false,
            None,
            now_ns,
        ),
        "after the LAST worker released, the port must be reservable again by an \
         unrelated flow — an un-absorbed coordinator reservation would hold it forever"
    );
}

/// Read through the shared synced map's lock. `sessions.synced` is an
/// `Arc<Mutex<..>>`, so a bare `contains_key` does not compile.
fn synced6600_contains(coordinator: &Coordinator, key: &SessionKey) -> bool {
    coordinator
        .sessions
        .synced
        .lock()
        .expect("synced map")
        .contains_key(key)
}

/// #6600: the coordinator's pre-publish reservation must resolve the synced
/// zone pair through the SAME helper the worker-side upsert uses.
///
/// This matters only when two source-NAT rules share a pool address — the #6211
/// case. The zone pair narrows PASS 1 to the rule the ACTIVE node actually
/// matched; without it the reservation falls through to PASS 2, "the first rule
/// whose pool contains the address", which can be a DIFFERENT allocator. The
/// coordinator would then reserve a port in one allocator while the workers
/// reserve in another: the coordinator's check passes, the port the session
/// actually names stays unreserved, and the defect is back wearing a new shape
/// — plus a leaked port in the allocator nobody will reap from.
///
/// Replacing the shared call with a bare `None` makes this go red.
#[test]
fn coordinator_pre_publish_reserve_uses_the_workers_zone_pair_6600() {
    let mut coordinator = Coordinator::new();
    // TWO rules over the SAME pool address. Rule 0 is a decoy in a different
    // zone pair and is what PASS 2 would pick; rule 1 is the one the entry's
    // metadata names, and is what PASS 1 picks when zones resolve.
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "decoy".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "p-decoy".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "real".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "p-real".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding
        .zone_id_to_name
        .insert(TEST_LAN_ZONE_ID, "lan".to_string());
    forwarding
        .zone_id_to_name
        .insert(TEST_WAN_ZONE_ID, "wan".to_string());
    coordinator.set_forwarding_for_test(forwarding);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // Non-vacuity: the zone pair must actually RESOLVE, or both the fix and the
    // mutation see `None` and this test proves nothing.
    let meta = test_metadata();
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(&coordinator.forwarding, &meta)
            .is_some(),
        "setup: the zone pair must resolve, or the discriminator does not vary"
    );

    let port: u16 = 52000;
    let entry = reserve6600_entry(40020, port);
    let key = entry.key.clone();
    coordinator.upsert_synced_session(entry);
    assert!(
        synced6600_contains(&coordinator, &key),
        "setup: the import must be admitted"
    );

    let unrelated = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 220)),
        src_port: 44448,
        ..test_key()
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    };
    // The ZONE-MATCHED rule's allocator must hold the port.
    assert!(
        !crate::nat::reserve_synced_source_nat_allocation_untracked(
            &coordinator.forwarding.iface_nat_allocators,
            &coordinator.forwarding.source_nat_rules[1..2],
            &unrelated,
            nat,
            false,
            None,
            1_000,
        ),
        "the coordinator did not reserve in the ZONE-MATCHED rule's allocator — it \
         resolved a different zone pair than the worker will, so the port the \
         session names stays unreserved"
    );
    // And the decoy's must NOT — otherwise the coordinator reserved in the
    // fall-through allocator, leaking a port nobody reaps from.
    assert!(
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &coordinator.forwarding.iface_nat_allocators,
            &coordinator.forwarding.source_nat_rules[0..1],
            &unrelated,
            nat,
            false,
            None,
            1_000,
        ),
        "the coordinator reserved in the DECOY rule's allocator (the PASS 2 \
         fall-through), which no worker will ever release"
    );
}

// #6785: `upsert_synced_session` used to return `()`. Its three SEMANTIC refusal
// paths each bumped a counter and returned silently, so the control handler
// answered `ok = true`, Go recorded a success, and Go's BPF mirror row stayed
// behind for a session this helper never took — the split truth #5305's
// transactional install already knows how to compensate but could not, because
// the only failure it could observe was an IPC error.
//
// These cells bind the OUTCOME, not the side effects. The existing tests already
// assert "the entry was not stored" and "the counter went up"; an implementation
// that keeps both of those and still returns `Applied` passes every one of them
// and reproduces the bug exactly. Each cell here therefore pairs a refusal with
// the SUCCESS case on the same coordinator, so "returns a refusal" cannot be
// satisfied by returning a refusal unconditionally.
#[test]
fn upsert_synced_session_reports_stale_generation_refusal_6785() {
    let coordinator = Coordinator::new();

    assert_eq!(
        coordinator.upsert_synced_session(synced_entry_with_generation(2)),
        SyncedImportOutcome::Applied,
        "a first install must report Applied"
    );
    assert_eq!(
        coordinator.upsert_synced_session(synced_entry_with_generation(1)),
        SyncedImportOutcome::RejectedStaleGeneration,
        "a strictly-older generation is refused (#2170) and the caller must be \
         told, or Go keeps a BPF row for a session this helper did not take"
    );
    // Positive control on the SAME coordinator: the refusal is selective, not a
    // blanket "reject everything after the first install".
    assert_eq!(
        coordinator.upsert_synced_session(synced_entry_with_generation(3)),
        SyncedImportOutcome::Applied,
        "a NEWER generation must still report Applied"
    );
}

#[test]
fn upsert_synced_session_reports_capacity_refusal_6785() {
    let mut coordinator = Coordinator::new();
    const LOGICAL_CEILING: u16 = 2;
    coordinator
        .synced_import_cap_override
        .store(LOGICAL_CEILING as usize, std::sync::atomic::Ordering::Relaxed);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // A full symmetric-peer logical set fits and must all report Applied — the
    // control that stops this cell from passing on "always RejectedCapacity".
    for i in 0..LOGICAL_CEILING {
        assert_eq!(
            coordinator.upsert_synced_session(synced_entry_port(1000 + i, 0)),
            SyncedImportOutcome::Applied,
            "forward session {i} is within the ceiling and must report Applied"
        );
    }
    assert_eq!(
        coordinator.upsert_synced_session(synced_entry_port(2000, 0)),
        SyncedImportOutcome::RejectedCapacity,
        "a NEW forward past the entry ceiling is drop-newest rejected (#5674) \
         and the caller must be told — otherwise the peer's session count and \
         this node's diverge with nothing reporting it"
    );
    // A REPLACE of an already-admitted key does not grow the map and must still
    // be accepted at the ceiling, so the refusal is bounded to what it claims.
    assert_eq!(
        coordinator.upsert_synced_session(synced_entry_port(1000, 0)),
        SyncedImportOutcome::Applied,
        "a REPLACE at the ceiling must still report Applied — refusing it would \
         stop an in-flight synced session from refreshing"
    );
}

// The refusal REASON tokens are part of the control-plane contract: Go strips
// the prefix and surfaces the remainder to the operator, and it is the only way
// to tell a capacity problem from a stale peer. Bind that Applied carries no
// token and that the three refusals carry distinct ones — collapsing them to a
// single token would compile, pass every behavioural cell above, and leave an
// operator unable to tell which of three very different conditions they are in.
#[test]
fn synced_import_outcome_reason_tokens_are_distinct_6785() {
    assert_eq!(SyncedImportOutcome::Applied.refusal_reason(), None);
    let tokens = [
        SyncedImportOutcome::RejectedStaleGeneration
            .refusal_reason()
            .expect("stale generation is a refusal"),
        SyncedImportOutcome::RejectedCapacity
            .refusal_reason()
            .expect("capacity is a refusal"),
        SyncedImportOutcome::RejectedReserve
            .refusal_reason()
            .expect("reserve is a refusal"),
    ];
    for (i, a) in tokens.iter().enumerate() {
        assert!(!a.is_empty(), "token {i} is empty");
        for (j, b) in tokens.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "refusal tokens {i} and {j} collide: {a}");
            }
        }
    }
}

/// #6979 F1: the same two overlapping pools as `reserve6600_forwarding`, plus a
/// SECOND rule whose pool owns the identical address. Zones resolve, so PASS 1
/// actually runs — without that the reserve takes the `synced_zones == None`
/// path and never reaches the code under test.
fn f1_overlapping_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-a".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "snat-b".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-b".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding
        .zone_id_to_name
        .insert(TEST_LAN_ZONE_ID, "lan".to_string());
    forwarding
        .zone_id_to_name
        .insert(TEST_WAN_ZONE_ID, "wan".to_string());
    forwarding
}

/// #6979 F1: THE REFUSAL MUST BE VISIBLE.
///
/// The ruling trades a reservation for a refusal, and that trade is only the
/// better half because the refusal is OBSERVABLE — #8101 surfaced
/// `xpf_userspace_synced_import_reserve_refused_total` with help text saying
/// those flows will not survive a failover. If the refusal path did not reach
/// that counter, the reasoning the whole change rests on would be false while
/// every unit-level cell still passed. So it is bound here rather than assumed.
///
/// A positive control runs first: without it a coordinator that refused every
/// import would satisfy the refusal leg completely.
#[test]
fn a_pass1_refused_import_is_counted_and_not_published_6979_f1() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(f1_overlapping_forwarding());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &coordinator.forwarding,
            &test_metadata(),
        )
        .is_some(),
        "fixture: the zone pair MUST resolve, or PASS 1 is skipped entirely and \
         this cell never reaches the code under test"
    );

    // POSITIVE CONTROL: a free identity is still admitted.
    let free = reserve6600_entry(40001, 50001);
    let free_key = free.key.clone();
    coordinator.upsert_synced_session(free);
    assert!(
        synced6600_contains(&coordinator, &free_key),
        "an import whose translated identity is FREE must still be admitted"
    );
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        0,
        "an admissible import must not be counted as a refusal"
    );

    // A local flow takes the identity in rule A's allocator ONLY. Rule B's pool
    // owns the same address and is still free — that is the sibling PASS 1 used
    // to fall through to.
    let contended: u16 = 50000;
    let local_flow = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 200)),
        src_port: 44444,
        ..test_key()
    };
    assert!(
        coordinator.forwarding.source_nat_rules[0]
            .pool_allocator
            .reserve_flow(
                crate::nat::SourceNatFlowKey {
                    protocol: PROTO_TCP,
                    src_ip: local_flow.src_ip,
                    dst_ip: local_flow.dst_ip,
                    src_port: local_flow.src_port,
                    dst_port: local_flow.dst_port,
                    routing_scope: 0,
                },
                crate::nat::TranslatedTuple {
                    ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    port: contended,
                },
                0,
                false,
                1_000,
                crate::nat::NatHolder::Untracked,
            ),
        "fixture: rule A must hold the contended identity, and rule B must not"
    );
    assert!(
        !coordinator.forwarding.source_nat_rules[1]
            .pool_allocator
            .debug_is_port_occupied(0, contended),
        "fixture: rule B must be FREE, or there is no sibling to fall through to \
         and the cell cannot distinguish the fix from its absence"
    );

    let before = coordinator.synced_import_reserve_refused_total();
    let clashing = reserve6600_entry(40002, contended);
    let clashing_key = clashing.key.clone();
    coordinator.upsert_synced_session(clashing);

    assert!(
        !synced6600_contains(&coordinator, &clashing_key),
        "the import was PUBLISHED after PASS 1's rule refused. PASS 1 fell through \
         to the overlapping sibling, which accepted, so the session went live with \
         its reservation in an allocator the ACTIVE never used (#6979 F1)"
    );
    assert!(
        !coordinator.forwarding.source_nat_rules[1]
            .pool_allocator
            .debug_is_port_occupied(0, contended),
        "rule B booked the reservation for a flow the ACTIVE translated under rule \
         A — the latent half, which only detonates at failover when A re-issues \
         the identity it never learned about"
    );
    assert_eq!(
        coordinator.synced_import_reserve_refused_total(),
        before + 1,
        "the refusal was NOT counted. The whole trade — a refused import instead of \
         a wrong-allocator reservation — rests on the refusal being visible in \
         xpf_userspace_synced_import_reserve_refused_total (#8101). An increment \
         that does not happen makes the reasoning false while every unit cell \
         still passes"
    );
    {
        let pending = commands.lock().expect("commands");
        assert!(
            !pending.iter().any(|cmd| matches!(
                cmd,
                WorkerCommand::UpsertSynced(entry) if entry.key == clashing_key
            )),
            "a refused import must not be fanned out to any worker command queue"
        );
    }
}

/// #7209: `synced_import_unpublished` must count the GAP — an import the
/// local-replace guard ADMITTED but which had no kernel session map to publish
/// into — and must not count the ownership decision that used to share its
/// `if`.
///
/// The two were one conjunction:
///
/// ```ignore
/// if synced_entry_allows_local_replace(..) && let Some(fd) = ..session_map_fd
/// ```
///
/// and they mean opposite things. The FIRST operand failing is correct
/// behaviour: the peer owns the redundancy group, so this node must not take
/// the redirect. The SECOND failing is a gap: the entry is recorded in the
/// shared map and answered to Go as installed, while no kernel row exists. A
/// counter that fired on "did not publish" would sit permanently nonzero on a
/// healthy standby and report nothing, so the conjunction had to be split
/// before either could be measured.
///
/// Three legs, and B and C are the ones that earn the metric:
///
///   A. admitted, no map -> COUNTS. A fresh `Coordinator` has
///      `bpf_maps.session_map_fd == None`, which is not contrived: it is an HA
///      standby taking bulk sync before its first snapshot apply, and the
///      interval between `stop_inner` and the next `reconcile::bringup`.
///   B. peer owns the RG, no map -> does NOT count. Without this leg the
///      counter is a rename of "did not publish" and climbs on every healthy
///      peer-owned import.
///   C. admitted, map PRESENT -> does NOT count. `fd: -1` is a real descriptor
///      that is not a map, so the publish is attempted and fails; that failure
///      belongs to the #1789 publish-error counter, not to this one. Without
///      leg C a counter bumped on every ADMITTED import passes both A and B.
///
/// Each leg asserts the guard's actual verdict first, so a fixture that stopped
/// exercising its intended case fails loudly rather than passing vacuously.
#[test]
fn synced_import_unpublished_counts_the_absent_map_not_the_owner_decision_7209() {
    let now_secs = monotonic_nanos() / 1_000_000_000;

    // --- Leg A: admitted, and there is no map to publish into. -------------
    let mut no_map = Coordinator::new();
    register_test_worker_7209(&mut no_map);
    assert!(
        no_map.bpf_maps.load().session_map_fd.is_none(),
        "fixture no longer exercises the ABSENT-MAP case — a fresh Coordinator \
         must have no session map fd, or leg A proves nothing"
    );
    assert!(
        crate::afxdp::session_glue::synced_entry_allows_local_replace(
            &no_map.ha.rg_runtime.load(),
            test_metadata().owner_rg_id,
            now_secs,
        ),
        "fixture no longer exercises the ADMITTED case — with the local-replace \
         guard refusing, leg A would count nothing for the wrong reason"
    );
    let before_a = no_map.synced_import_unpublished_total();
    no_map.upsert_synced_session(reserve6600_entry(42000, 22000));
    assert!(
        no_map.synced_import_unpublished_total() > before_a,
        "an import the local-replace guard ADMITTED, with no kernel session map \
         to publish into, was not counted. That import is recorded in the shared \
         map and answered to Go as installed while no kernel row exists; today \
         the next reconcile's capture-and-replay covers it, but once #7209 takes \
         sync_session off the snapshot-wide mutex an import in the \
         capture-to-replay window is neither published nor replayed and there is \
         no signal at all"
    );

    // --- Leg B: the PEER owns the RG -> not publishing is correct. ---------
    let mut peer_owned = Coordinator::new();
    register_test_worker_7209(&mut peer_owned);
    peer_owned
        .update_ha_state(&[HAGroupStatus {
            rg_id: test_metadata().owner_rg_id,
            active: true,
            watchdog_timestamp: now_secs,
            ..HAGroupStatus::default()
        }])
        .expect("update ha state");
    assert!(
        !crate::afxdp::session_glue::synced_entry_allows_local_replace(
            &peer_owned.ha.rg_runtime.load(),
            test_metadata().owner_rg_id,
            monotonic_nanos() / 1_000_000_000,
        ),
        "fixture no longer exercises the OWNER-DECLINED case — leg B would then \
         be a second copy of leg A and could not detect a counter that fires on \
         every non-publish"
    );
    assert!(
        peer_owned.bpf_maps.load().session_map_fd.is_none(),
        "leg B must ALSO have no map, so the only difference from leg A is the \
         owner decision"
    );
    let before_b = peer_owned.synced_import_unpublished_total();
    peer_owned.upsert_synced_session(reserve6600_entry(42001, 22001));
    assert_eq!(
        peer_owned.synced_import_unpublished_total(),
        before_b,
        "an import this node correctly declined to publish because the PEER owns \
         the redundancy group was counted as an unpublished gap. The metric then \
         climbs on every healthy peer-owned import and stops meaning anything \
         (#7209)"
    );

    // --- Leg C: a map IS present -> the gap counter must stay still. -------
    let mut with_map = Coordinator::new();
    register_test_worker_7209(&mut with_map);
    with_map.bpf_maps.store(std::sync::Arc::new(crate::afxdp::coordinator::BpfMaps {
        session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd { fd: -1 }),
        ..Default::default()
    }));
    let before_c = with_map.synced_import_unpublished_total();
    with_map.upsert_synced_session(reserve6600_entry(42002, 22002));
    assert_eq!(
        with_map.synced_import_unpublished_total(),
        before_c,
        "an import that HAD a session map was counted as having none. fd -1 is \
         not a map, so the publish is attempted and FAILS — that failure is the \
         #1789 publish-error counter's, and folding it in here would make this \
         metric fire on every publish error too (#7209)"
    );
}

/// #7209: the worker-set gate is what keeps a peer-synced import OFF the
/// reservation path when no worker is registered, and it is load-bearing in a
/// way it did not used to be.
///
/// The gate is one operand of a short-circuiting conjunction
/// (`ha/session_import.rs`):
///
/// ```ignore
/// if entry.origin.is_peer_synced()
///     && !entry.metadata.is_reverse
///     && !self.workers.records().is_empty()          // <-- this one
///     && !self.reserve_synced_translation(&entry)
/// ```
///
/// `reserve_synced_translation` is the ONLY reader of `forwarding` on the
/// import path. `stop_inner` clears `workers.records` in the same teardown that
/// sets `self.forwarding` to `ForwardingState::default()`, so the gate is why an
/// import arriving mid-reconcile never resolves against the empty table — and
/// why the "give the import path a last-good forwarding view" design was
/// measured to be inert and dropped.
///
/// TODAY the gate reads as an optimisation, and its in-tree comment justifies it
/// as one: "nothing polls, so there is no racing local allocation to guard
/// against, and an `Untracked` reservation that no worker ever adopts has no one
/// to release it". AFTER #7209 takes `sync_session` off the snapshot-wide mutex
/// it becomes part of why a concurrent import is SAFE. A refactor that hoists
/// the reservation out of the conjunction, or reorders the operand after it,
/// would silently reintroduce a read this issue proved impossible — with every
/// other test still green, because nothing else observes it.
///
/// So: two legs whose ONLY difference is whether a worker is registered.
///
/// FAIL-ON-REVERT: delete `&& !self.workers.records().is_empty()`, or move it
/// after the `reserve_synced_translation` call, and leg A reds — the no-worker
/// import reaches the reservation, fails to resolve its zone pair against the
/// fresh Coordinator's empty forwarding, and bumps the counter.
#[test]
fn no_worker_registered_keeps_a_synced_import_off_the_reservation_path_7209() {
    // --- Leg A: NO worker -> the reservation must not run at all. ----------
    let mut no_worker = Coordinator::new();
    assert!(
        no_worker.workers.records().is_empty(),
        "fixture broken: a fresh Coordinator must have no worker records, or \
         leg A is not exercising the gate"
    );
    assert!(
        crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &no_worker.forwarding,
            &test_metadata(),
        )
        .is_none(),
        "fixture broken: the zone pair must be UNRESOLVABLE against a fresh \
         Coordinator's empty forwarding, or reaching the reservation would bump \
         nothing and leg A could not tell the two paths apart"
    );

    let before = no_worker.synced_import_zone_unresolved_total();
    no_worker.upsert_synced_session(reserve6600_entry(43000, 23000));
    assert_eq!(
        no_worker.synced_import_zone_unresolved_total(),
        before,
        "a peer-synced import reached the source-NAT reservation with NO worker \
         registered. The worker-set gate short-circuits that conjunction, and it \
         is what keeps an import arriving mid-reconcile — when stop_inner has \
         cleared the workers AND emptied the forwarding table — from resolving \
         against an empty table. Hoisting the reservation out of the \
         conjunction reintroduces exactly that read (#7209)"
    );

    // --- Leg B: a worker IS registered -> the reservation runs. ------------
    // Without this leg, leg A passes on a build where the reservation never
    // runs for ANY import, and the gate would not be what it measures.
    let mut with_worker = Coordinator::new();
    register_test_worker_7209(&mut with_worker);
    let before_b = with_worker.synced_import_zone_unresolved_total();
    with_worker.upsert_synced_session(reserve6600_entry(43001, 23001));
    assert!(
        with_worker.synced_import_zone_unresolved_total() > before_b,
        "with a worker registered the same import must REACH the reservation \
         and count its unresolved zone pair; if it does not, leg A proves \
         nothing about the gate because the reservation is unreachable either \
         way"
    );
}

/// #7209: a reader holding the loaded descriptor set keeps those descriptors
/// OPEN across a teardown that replaces them. The refcount is the guarantee.
///
/// `BpfMaps` holds `Option<OwnedFd>`, and `OwnedFd::drop` calls `close(2)`. A
/// reader that took a raw `fd` out of a plain field could have it closed
/// underneath it by a concurrent `stop_inner` — a use-after-close, which is a
/// LIFETIME failure and not a stale read, so republishing a "current" value
/// cannot fix it. Publishing the set behind an `ArcSwap` fixes it because the
/// old set is dropped only when the last holder releases.
///
/// Safe Rust prevents the race today: every mutator takes `&mut self`, so no
/// `&self` reader can run concurrently. #7209 removes that guarantee by putting
/// the Coordinator behind an `Arc`, and this field is what replaces it. The
/// cell therefore binds the PROPERTY rather than driving the race — it holds a
/// loaded guard across the teardown and asserts the descriptor it names is
/// still open, which is exactly what a concurrent reader would depend on.
///
/// Liveness is checked with `fcntl(F_GETFD)` on the real descriptor rather than
/// by inspecting the `Option`: an assertion on the struct would pass just as
/// well if the fd had been closed, since the `Option` would still be `Some`.
/// The question is whether the KERNEL still has it.
///
/// FAIL-ON-REVERT: make `stop_inner` drop the previous set in place (or make
/// `bpf_maps` a plain field again) and the post-teardown `F_GETFD` returns
/// `EBADF`.
#[test]
fn a_held_bpf_map_set_stays_open_across_teardown_7209() {
    // A real descriptor, so `close` is observable. `dup(0)` gives one this
    // process owns without opening a file.
    let raw = unsafe { libc::dup(0) };
    assert!(raw >= 0, "fixture: dup(0) failed, errno {}", unsafe {
        *libc::__errno_location()
    });

    let mut coordinator = Coordinator::new();
    coordinator
        .bpf_maps
        .store(std::sync::Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd { fd: raw }),
            ..Default::default()
        }));

    // The reader's guard, taken BEFORE the teardown — this is the whole point.
    let held = coordinator.bpf_maps.load_full();
    assert_eq!(
        held.session_map_fd.as_ref().map(|fd| fd.fd),
        Some(raw),
        "fixture: the held set must name the descriptor under test"
    );

    // The teardown replaces the whole set. Without the refcount this is where
    // `raw` would be closed.
    coordinator.stop_inner(false);
    assert!(
        coordinator.bpf_maps.load().session_map_fd.is_none(),
        "fixture: stop_inner must have replaced the published set, or the \
         assertion below passes because no teardown happened"
    );

    // Still open, because `held` is still alive.
    let alive = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    assert!(
        alive >= 0,
        "the descriptor was CLOSED while a reader still held the set that owns \
         it — F_GETFD returned {} (errno {}). That is a use-after-close for any \
         concurrent reader, which is what #7209 makes possible by putting the \
         Coordinator behind an Arc; the refcount, not the swap, is what \
         prevents it",
        alive,
        unsafe { *libc::__errno_location() }
    );

    // Releasing the last holder closes it — the other half of the contract, and
    // what keeps this from passing on an implementation that simply leaks.
    drop(held);
    let after = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    assert!(
        after < 0,
        "the descriptor is STILL open after the last holder was dropped, so the \
         published set is leaking descriptors rather than deferring their close"
    );
}

/// #7209: a synced session's key must leave the reverse-prewarm index when the
/// session is deleted, even if the forwarding table changed while it was live.
///
/// THE HARM, not the shape. `reverse_prewarm_owner_rg_candidates` derives one
/// of an entry's two index buckets from the FIB — the RG that owns the egress
/// interface a reply to `key.src_ip` would leave by. The insert files the key
/// under the buckets computed against the forwarding live AT INSERT; the remove
/// recomputes them against the forwarding live AT REMOVE. Those are the same
/// set only while nothing moved the route, which the snapshot-wide `ServerState`
/// mutex made true incidentally for a single import — and never made true
/// across an entry's LIFETIME, because a commit that re-homes an interface sits
/// between the two.
///
/// So a route that moves between RGs strands the key in the bucket it was filed
/// under. Nothing ever removes it: the session is gone, so no later remove
/// carries it, and the bucket is only read — never rebuilt — by
/// `prewarm_reverse_synced_sessions_for_owner_rgs` on RG ACTIVATION, which is
/// the failover critical path (#4069 rewrote its key merge from O(N*M) to
/// O(N+M) precisely because its size measurably slowed a newly-primary node).
/// The leak is unbounded in the number of such sessions and permanent for the
/// life of the process.
#[test]
fn a_deleted_synced_session_leaves_no_reverse_prewarm_key_after_a_route_moves_7209() {
    let mut coordinator = Coordinator::new();
    // AT INSERT: ifindex 6 (the reply path to 10.0.61.102) belongs to RG 2,
    // while the entry's own metadata names RG 1 — two distinct buckets, which
    // is what makes the asymmetry observable at all.
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied,
        "the fixture must actually import, or nothing below is under test"
    );
    {
        let index = coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index");
        assert!(
            index.get(&1).is_some_and(|keys| keys.contains(&entry.key)),
            "fixture no longer files the key under its metadata RG"
        );
        assert!(
            index.get(&2).is_some_and(|keys| keys.contains(&entry.key)),
            "fixture no longer files the key under the FIB-derived RG — without \
             that second bucket this cell cannot see the asymmetry it exists for"
        );
    }

    // A commit re-homes ifindex 6 from RG 2 to RG 1. Ordinary operator work;
    // the synced session is untouched and still live.
    coordinator.set_forwarding_for_test(test_forwarding_state_with_fabric());

    coordinator.delete_synced_session(entry.key.clone());

    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&entry.key)
            .is_none(),
        "the delete did not remove the session itself; the index assertion \
         below would then be measuring the wrong thing"
    );
    let index = coordinator
        .sessions
        .owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    let stranded: Vec<i32> = index
        .iter()
        .filter(|(_, keys)| keys.contains(&entry.key))
        .map(|(rg, _)| *rg)
        .collect();
    assert!(
        stranded.is_empty(),
        "a DELETED synced session is still indexed for reverse prewarm under \
         RG(s) {stranded:?}. The remove recomputed the entry's buckets against \
         the CURRENT forwarding, so the bucket it was INSERTED under is never \
         cleared once a route moves between RGs. Every RG activation then walks \
         a key set that only grows, on the failover critical path (#7209)"
    );
}

/// #7209: the accept side of the cell above — clearing one key's buckets must
/// not evict anyone else's.
///
/// The removal now walks EVERY owner-RG bucket instead of a recomputed pair, so
/// the failure this guards is the mirror image of the leak: a bucket sweep that
/// takes the whole set with it. That direction is far worse than the leak it
/// replaces — a session missing from the reverse-prewarm index is a session the
/// newly-primary node does not pre-resolve at RG activation, i.e. dropped reply
/// traffic at exactly the failover the index exists to serve, whereas a
/// stranded key only costs memory and scan time.
///
/// Without this cell a mutant that empties the index on every delete passes the
/// leak cell perfectly.
#[test]
fn deleting_one_synced_session_leaves_its_neighbours_in_the_reverse_prewarm_index_7209() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());

    let doomed = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    // Same source, different port: a distinct key that lands in the SAME two
    // buckets, which is the only arrangement in which an over-broad sweep is
    // observable at all.
    let mut survivor = doomed.clone();
    survivor.key.src_port = doomed.key.src_port.wrapping_add(1);
    assert_ne!(doomed.key, survivor.key);

    assert_eq!(
        coordinator.upsert_synced_session(doomed.clone()),
        SyncedImportOutcome::Applied
    );
    assert_eq!(
        coordinator.upsert_synced_session(survivor.clone()),
        SyncedImportOutcome::Applied
    );
    // BOTH keys, not just the survivor: the message below claims both are
    // filed, and a precondition that checks only one of them would let the
    // fixture drift into a shape where the two sessions do NOT share buckets —
    // in which case an over-broad sweep is invisible and this cell passes
    // without exercising anything.
    for rg in [1, 2] {
        for (name, key) in [("doomed", &doomed.key), ("survivor", &survivor.key)] {
            assert!(
                coordinator
                    .sessions
                    .owner_rg_indexes
                    .reverse_prewarm_sessions
                    .lock()
                    .expect("prewarm index")
                    .get(&rg)
                    .is_some_and(|keys| keys.contains(key)),
                "fixture no longer files the {name} session under RG {rg}; the \
                 two sessions must share BOTH buckets or an over-broad sweep is \
                 invisible here"
            );
        }
    }

    coordinator.delete_synced_session(doomed.key.clone());

    let index = coordinator
        .sessions
        .owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    for rg in [1, 2] {
        assert!(
            index
                .get(&rg)
                .is_some_and(|keys| keys.contains(&survivor.key)),
            "deleting one synced session removed a DIFFERENT live session's key \
             from RG {rg}'s reverse-prewarm bucket. That session is then not \
             pre-resolved when the RG activates, so its reply traffic drops at \
             the failover the index exists to serve (#7209)"
        );
        assert!(
            !index.get(&rg).is_some_and(|keys| keys.contains(&doomed.key)),
            "the deleted session is still in RG {rg}'s bucket"
        );
    }
}

/// #7209: a route move ADDS the new RG's filing, and the residue it leaves is
/// bounded — the authoritative un-file at delete is what bounds it.
///
/// REPLACES a cell that asserted the opposite and was wrong. That cell required
/// a replace to NARROW the filing to `candidates(now)`, which is precisely the
/// behaviour that let a refresh taken in a blind-FIB window drop a bucket
/// nothing could restore (see
/// `a_refresh_never_drops_a_prewarm_filing_the_current_fib_cannot_rederive_7209`).
/// It is recorded rather than quietly deleted because it is the reason the
/// regression shipped: it was written to pin "no accumulation", the strongest
/// available statement, without asking what the consumer does with an extra
/// bucket versus a missing one. The consumer discards extras and never looks
/// for missing ones, so the strongest statement was the wrong one.
///
/// What is worth binding is what the old cell was reaching for: accumulation
/// must not be unbounded. It is not — a live entry accrues at most one bucket
/// per RG its reply path has ever resolved to, and the delete clears every one
/// of them.
#[test]
fn a_route_move_adds_the_new_prewarm_filing_and_delete_clears_all_of_them_7209() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );
    assert!(
        filed_under_7209(&coordinator, &entry.key).contains(&2),
        "fixture no longer files under the FIB-derived RG 2"
    );

    // ifindex 6 is genuinely RE-HOMED from RG 2 to RG 1 — the FIB can answer,
    // it just answers differently. Distinct from the blind-FIB case, and the
    // distinction is the whole reason both cells exist.
    coordinator.set_forwarding_for_test(test_forwarding_state_with_fabric());
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied,
        "the replace must be ADMITTED, or the refile below never runs"
    );
    let after_move = filed_under_7209(&coordinator, &entry.key);
    assert!(
        after_move.contains(&1),
        "the replace did not file the key under the RG its reply path now \
         resolves to, so an activation of RG 1 would not pre-resolve it"
    );
    assert!(
        after_move.len() <= 8,
        "the filing set grew past any plausible RG count ({after_move:?}); \
         accumulation is supposed to be bounded by the RGs this key's reply \
         path has resolved to, not open-ended"
    );

    // The bound that makes the residue acceptable: the delete takes ALL of it,
    // whichever forwarding is live at the time.
    coordinator.delete_synced_session(entry.key.clone());
    let after_delete = filed_under_7209(&coordinator, &entry.key);
    assert!(
        after_delete.is_empty(),
        "a DELETED synced session is still filed under RG(s) {after_delete:?}. \
         The residue a route move leaves is only acceptable because the delete \
         clears it; without that it is the unbounded strand again (#7209)"
    );
}

/// #7209: a session removed through a path that is NOT the coordinator's delete
/// verb must also leave the reverse-prewarm index — whatever origin the stored
/// entry carries by then.
///
/// `purge_translated_synced_hit` and the LocalDelivery replacement after
/// `take_synced_local` both drop a peer-synced forward entry via
/// `remove_shared_session` and neither calls
/// `refresh_reverse_prewarm_owner_rg_indexes`. A later coordinator delete then
/// finds no stored entry and refreshes with `(None, None)`, so nothing ever
/// names the filing again — an unbounded strand with no session behind it,
/// reached without any route move at all. This drives `remove_shared_session`
/// directly, which is the choke point all of those paths share.
///
/// TWO LEGS, and the second is the one that carries the property. The delete
/// verb ALSO un-files (`delete_synced_session_gen` refreshes with
/// `(Some(removed), None)`), so a single-leg cell using a peer-synced origin is
/// green whether or not `remove_shared_session` does anything at all — the
/// mechanism it names is masked by the other one. Leg B removes an entry whose
/// stored origin is `SharedPromote`, which is exactly what
/// `purge_translated_synced_hit` finds after `maybe_promote_synced_session`
/// republished the key, and it isolates this mechanism: an implementation that
/// gates the un-file on the stored entry being peer-synced passes leg A and
/// reds leg B. Measured — that mutant survived the whole suite before this leg
/// existed.
#[test]
fn a_removal_outside_the_delete_verb_still_unfiles_the_prewarm_key_7209() {
    for (leg, origin) in [
        ("A: still peer-synced", SessionOrigin::SyncImport),
        ("B: promoted before removal", SessionOrigin::SharedPromote),
    ] {
        let mut coordinator = Coordinator::new();
        coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        };
        assert_eq!(
            coordinator.upsert_synced_session(entry.clone()),
            SyncedImportOutcome::Applied
        );
        assert!(
            !filed_under_7209(&coordinator, &entry.key).is_empty(),
            "leg {leg}: fixture filed nothing, so the removal below would prove \
             nothing"
        );
        if origin != SessionOrigin::SyncImport {
            // What `maybe_promote_synced_session` leaves behind: the same key,
            // republished with a promoted origin, index untouched.
            let mut promoted = entry.clone();
            promoted.origin = origin;
            assert!(
                !promoted.origin.is_peer_synced(),
                "leg {leg}: fixture no longer uses a NON-peer-synced origin, so \
                 it cannot isolate the un-file from an origin gate"
            );
            publish_shared_session(
                &coordinator.sessions.synced,
                &coordinator.sessions.nat,
                &coordinator.sessions.forward_wire,
                &coordinator.sessions.owner_rg_indexes,
                &promoted,
            );
        }

        remove_shared_session(
            &coordinator.sessions.synced,
            &coordinator.sessions.nat,
            &coordinator.sessions.forward_wire,
            &coordinator.sessions.owner_rg_indexes,
            &entry.key,
        );

        let stranded = filed_under_7209(&coordinator, &entry.key);
        assert!(
            stranded.is_empty(),
            "leg {leg}: a session removed through `remove_shared_session` — the \
             path `purge_translated_synced_hit` and the LocalDelivery \
             replacement both take — is still filed for reverse prewarm under \
             RG(s) {stranded:?}, with no entry behind it. Nothing ever names \
             that filing again (#7209)"
        );
    }
}

/// #7209: a PROMOTED session's filing must survive promotion and be cleared by
/// its eventual removal.
///
/// `maybe_promote_synced_session` republishes an imported key with
/// `SessionOrigin::SharedPromote` and does NOT refresh this index, so the
/// filing made at `SyncImport` time stands — deliberately, since the activation
/// prewarm accepts `SharedPromote`. But `reverse_prewarm_owner_rg_candidates`
/// returns EMPTY for a non-peer-synced origin, so any un-file derived from the
/// stored entry computes nothing once the origin has changed. Promote, then
/// delete, and the key stranded — with no route move involved.
///
/// This is the cell that makes the un-file's unconditionality load-bearing
/// rather than incidental: an implementation that gates the sweep on
/// `previous.origin.is_peer_synced()` passes every other cell here and reds
/// this one.
#[test]
fn a_promoted_then_deleted_synced_session_leaves_no_prewarm_key_7209() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );
    assert!(
        !filed_under_7209(&coordinator, &entry.key).is_empty(),
        "fixture filed nothing before the promotion"
    );

    // What `maybe_promote_synced_session` does to the shared entry: republish
    // the same key with a promoted origin, no index refresh.
    let mut promoted = entry.clone();
    promoted.origin = SessionOrigin::SharedPromote;
    assert!(
        !promoted.origin.is_peer_synced(),
        "fixture no longer exercises a NON-peer-synced origin, which is the \
         only arrangement in which a candidates-derived un-file computes empty"
    );
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &promoted,
    );

    coordinator.delete_synced_session(entry.key.clone());

    let stranded = filed_under_7209(&coordinator, &entry.key);
    assert!(
        stranded.is_empty(),
        "a PROMOTED-then-deleted synced session is still filed for reverse \
         prewarm under RG(s) {stranded:?}. The stored entry's origin is \
         SharedPromote by then, for which the candidate set is EMPTY, so any \
         un-file derived from it removes nothing — no route move required \
         (#7209)"
    );
}

/// The RGs `key` is currently filed under for reverse prewarm.
fn filed_under_7209(coordinator: &Coordinator, key: &SessionKey) -> Vec<i32> {
    let index = coordinator
        .sessions
        .owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    let mut rgs: Vec<i32> = index
        .iter()
        .filter(|(_, keys)| keys.contains(key))
        .map(|(rg, _)| *rg)
        .collect();
    rgs.sort_unstable();
    rgs
}

/// #7209: a refresh must never DROP a reverse-prewarm filing it cannot
/// re-derive.
///
/// This is the regression PR #8479 introduced and the reason the removal is no
/// longer unconditional. That change made every refresh un-file the key from
/// EVERY bucket and then re-file only what the CURRENT forwarding could name.
/// When the FIB is momentarily blind to the reply path — a RETH member down and
/// the route not yet re-homed, or `stop_inner` having emptied `forwarding`
/// between a failed reconcile and its retry — "what the current forwarding can
/// name" is a strict SUBSET of the truth, so an ordinary peer refresh landing in
/// that window silently narrowed the filing and nothing ever restored it.
///
/// The direction matters and it is the worse one. An EXTRA bucket costs a
/// re-synthesis that `prewarm_reverse_synced_sessions_for_owner_rgs` then
/// discards, because it re-derives the reverse companion under live tables and
/// re-checks `owner_rg_set.contains(..)` before keeping anything. A MISSING
/// bucket is not checked at all — the key never enters the candidate set, so the
/// session is not pre-resolved when that RG activates. Over-filing is absorbed
/// by the consumer; under-filing is invisible to it.
///
/// So the index is add-only across a live entry's transitions, and un-filing
/// happens exactly once, when the entry is authoritatively REMOVED (which is
/// what bounds it — see the delete cell).
#[test]
fn a_refresh_never_drops_a_prewarm_filing_the_current_fib_cannot_rederive_7209() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );
    assert!(
        coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index")
            .get(&2)
            .is_some_and(|keys| keys.contains(&entry.key)),
        "fixture no longer files the key under the FIB-derived RG 2, so the \
         drop this cell exists to catch could not be observed"
    );

    // The reply path goes BLIND: ifindex 6 leaves the egress table (member
    // down, or `stop_inner` emptied forwarding after a failed reconcile). The
    // route has NOT been re-homed to another RG — the FIB simply cannot answer
    // the question right now.
    coordinator.forwarding.egress.remove(&6);
    assert_eq!(
        reverse_prewarm_owner_rg_candidates_for_test(&coordinator, &entry)
            .contains(&2),
        false,
        "fixture no longer makes the FIB BLIND to RG 2 — with RG 2 still \
         derivable this cell would pass without exercising anything"
    );

    // An ordinary peer refresh of the same live session lands in that window.
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );

    assert!(
        coordinator
            .sessions
            .owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index")
            .get(&2)
            .is_some_and(|keys| keys.contains(&entry.key)),
        "a peer refresh taken while the FIB could not resolve the reply path \
         DROPPED the key's RG 2 filing, and nothing restores it. If RG 2 \
         activates before this key is refreshed again the session never enters \
         the prewarm candidate set, so its reply path is not pre-resolved at \
         the failover — the failure mode the un-filing sweep was supposed to \
         avoid, inverted (#7209)"
    );
}

#[cfg(test)]
fn reverse_prewarm_owner_rg_candidates_for_test(
    coordinator: &Coordinator,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    super::shared_ops::reverse_prewarm_owner_rg_candidates_for_test(
        &coordinator.forwarding,
        coordinator.dynamic_neighbors_ref(),
        entry,
    )
}

// ---------------------------------------------------------------------------
// #7209 scope item 2 — the four blocking calls off the `ServerState` lock.
//
// PREMISE RESULT, and it is a NEGATIVE one worth having in executable form:
// scope item 2 is NOT independent of the derived-state work item 1 needs. It
// was scoped as the route that needs no `forwarding` sharing, which is true —
// and it still cannot be taken naively, for a different reason.
//
// Every one of the four blocking calls (the 10 s worker-readiness barrier, the
// 500 ms mlx5 teardown quiesce, the unbounded worker `join()`, the map-pin
// opens) runs INSIDE `Coordinator::reconcile`. Taking any of them off the lock
// means dropping the `ServerState` guard partway through that transaction, and
// the quiesce — a pure `thread::sleep` touching no coordinator state, so the
// most obviously safe of the four — sits immediately AFTER `stop_inner(false)`,
// which sets `self.forwarding = ForwardingState::default()`.
//
// So the window a released lock opens is precisely a window in which
// `Coordinator.forwarding` is EMPTY, and `sync_session` dispatches through
// that same mutex. An import landing there synthesizes its reverse companion
// against the empty table.
//
// The cells below establish the two halves of why that matters, both green
// today, both derived from running code rather than from the lock graph:
//
//   1. the companion IS built and published from an empty forwarding table
//      (`synthesized_synced_reverse_entry` has exactly one early return, on
//      `is_reverse`, so there is no forwarding-dependent `None` arm), and
//   2. the reconcile's own replay does NOT repair it — `replay_synced_sessions`
//      publishes `entry.decision` verbatim and re-queues the entry; it never
//      re-synthesizes.
//
// Today that pair is LATENT rather than live: the only path that reaches this
// state without a lock move is a standby taking bulk sync before its first
// apply, and RG activation re-derives the companion through
// `prewarm_reverse_synced_sessions_for_owner_rgs` before it can matter
// (measured: NoRoute/ifindex 0/owner 0 before, ForwardCandidate/ifindex 6/
// owner 2 after). A mid-life `apply_snapshot` on an already-ACTIVE node
// reaches no activation, so once a lock release puts an import in this window
// there is nothing left to repair it.
//
// These are characterization cells: they pin what the code does now, so
// whoever changes it gets a red rather than a paragraph. When item 1 lands —
// either refusing the companion when its inputs are absent, or deferring the
// synthesis to the replay — cell 2 is the one that must flip, and flipping it
// is the signal that item 2 became safe.

/// #7209 item 2: a synced import taken while `forwarding` is empty publishes a
/// reverse companion whose reply path resolves to NOTHING.
///
/// The control leg is what makes this a statement about the empty table rather
/// than about the fixture: the same entry, imported against a populated table,
/// resolves to a real egress.
#[test]
fn an_import_under_an_emptied_forwarding_table_publishes_a_dead_reverse_companion_7209() {
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);

    // CONTROL: a populated table resolves the companion's reply path.
    let mut healthy = Coordinator::new();
    healthy.set_forwarding_for_test(test_forwarding_state_split_rgs());
    // HA state BEFORE the import, and it is load-bearing rather than setup:
    // `owner_rg_for_resolution` only names an RG for a resolution the node can
    // actually forward. With no RG locally active the reply path resolves to
    // `FabricRedirect` and the companion's owner RG is 0 — the same value the
    // empty-table leg produces, for a completely different reason. Without
    // this the control could not distinguish "resolved to a real owner" from
    // "resolved to nothing", which is the whole contrast.
    healthy.update_ha_state(&[
        HAGroupStatus {
            rg_id: 1,
            active: true,
            ..HAGroupStatus::default()
        },
        HAGroupStatus {
            rg_id: 2,
            active: true,
            ..HAGroupStatus::default()
        },
    ]);
    assert_eq!(
        healthy.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );
    let resolved = healthy
        .sessions
        .synced
        .lock()
        .expect("synced")
        .get(&reverse_key)
        .cloned()
        .expect("CONTROL: the companion must exist at all");
    // NOT pinned to a specific disposition: with this fixture's split RGs and
    // `fabric_ingress` metadata the reply path resolves to `FabricRedirect`
    // rather than `ForwardCandidate`, and either is a REAL resolution. What
    // the control has to establish is that a populated table produces one at
    // all — pinning the variant would be pinning the fixture's topology.
    assert_ne!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "CONTROL: with a populated forwarding table the companion must resolve \
         to SOMETHING. If it does not, the fixture — not the empty table — is \
         what the main leg below is measuring"
    );
    assert!(
        resolved.metadata.owner_rg_id > 0,
        "CONTROL: the companion must take a real owner RG from the populated \
         table, or the owner-RG assertion in the main leg proves nothing"
    );

    // THE WINDOW: exactly what `stop_inner(false)` leaves behind, which is the
    // state a released lock would expose during the 500 ms mlx5 quiesce.
    let mut torn_down = Coordinator::new();
    torn_down.set_forwarding_for_test(ForwardingState::default());
    assert_eq!(
        torn_down.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied,
        "the import must be ADMITTED in this window — a refusal here would be a \
         different (and better) outcome than the one this cell describes"
    );
    let dead = torn_down
        .sessions
        .synced
        .lock()
        .expect("synced")
        .get(&reverse_key)
        .cloned()
        .expect(
            "the companion was NOT published from an empty forwarding table. \
             That would mean `synthesized_synced_reverse_entry` grew a \
             forwarding-dependent None arm — the #7209 item-1 fix — and this \
             cell has become the wrong description",
        );
    assert_eq!(
        dead.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "the companion's reply path resolved to something other than NoRoute \
         from an EMPTY forwarding table. Either the fixture is not exercising \
         the window, or the synthesis grew an input this cell does not model"
    );
    assert_eq!(
        dead.metadata.owner_rg_id, 0,
        "the companion carries a real owner RG despite no forwarding state to \
         derive one from"
    );
    assert_eq!(
        dead.decision.resolution.egress_ifindex, 0,
        "the companion carries a real egress ifindex despite an empty table"
    );
}

/// #7209 item 1 (shape ii): the reconcile's replay RE-DERIVES a reverse
/// companion under the live tables, repairing one that was synthesized from a
/// forwarding table which could not resolve the reply path.
///
/// REPLACES a characterization cell that asserted the opposite. That one pinned
/// the pre-fix behaviour — the replay republished `entry.decision` verbatim —
/// so that the blocker on scope item 2 was a red rather than a paragraph. It
/// did its job: it went red the moment the repair landed, and its failure
/// message carried the instruction for this rewrite.
///
/// Three assertions, and the third is the one that keeps the metric honest:
///
///   1. the replayed companion resolves under the LIVE table;
///   2. the SHARED MAP is repaired too, not just the replayed copy — that map
///      is the authority a later prewarm, export or replay reads, so fixing
///      only one of the two would leave the stale value to be re-adopted;
///   3. a steady-state replay, where the stored companion already agrees with
///      what the table resolves, does NOT bump the counter. Without that leg a
///      counter bumped on every replayed companion passes the first two and
///      becomes a function of how often the box reconciles rather than of how
///      often a companion was built from a table that could not answer.
#[test]
fn the_reconcile_replay_rederives_a_dead_reverse_companion_7209() {
    let mut coordinator = Coordinator::new();
    // The window: torn-down forwarding, exactly as `stop_inner(false)` leaves.
    coordinator.set_forwarding_for_test(ForwardingState::default());
    // HA state goes in FIRST, and the ordering is load-bearing rather than
    // setup. `update_ha_state` runs `prewarm_reverse_synced_sessions_for_owner_
    // rgs` on an RG ACTIVATION, which re-synthesizes every companion — so
    // calling it after the import would repair the companion before the replay
    // ever ran, and this cell would pass its disposition assertions for the
    // prewarm's reason rather than the replay's. Measured: it did, and only the
    // counter assertion caught it. Activating here, with no sessions yet, makes
    // the prewarm a no-op and leaves the replay as the only repair path.
    coordinator.update_ha_state(&[
        HAGroupStatus {
            rg_id: 1,
            active: true,
            ..HAGroupStatus::default()
        },
        HAGroupStatus {
            rg_id: 2,
            active: true,
            ..HAGroupStatus::default()
        },
    ]);
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );
    assert_eq!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .get(&reverse_key)
            .expect("companion")
            .decision
            .resolution
            .disposition,
        ForwardingDisposition::NoRoute,
        "the fixture must start from a DEAD companion, or the repair below has \
         nothing to repair and this cell passes vacuously"
    );

    // The reconcile now completes: `apply_snapshot` installs the new table
    // BEFORE `bring_up_workers` reaches the replay, which is what makes the
    // replay a repair point at all.
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    let replay_entries = coordinator.snapshot_shared_session_entries();
    assert!(
        replay_entries.iter().any(|e| e.key == reverse_key),
        "the companion must be IN the replay set, or this cell asserts a repair \
         of something the replay never saw"
    );
    let queues: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        BTreeMap::from([(0u32, Arc::new(Mutex::new(VecDeque::new())))]);
    let before = coordinator.synced_reverse_rederived_total();
    let replayed = coordinator.replay_synced_sessions(&replay_entries, &queues, -1);
    assert!(replayed > 0, "the replay processed nothing");

    // (2) the SHARED MAP — the authority — is what must be repaired.
    let after = coordinator
        .sessions
        .synced
        .lock()
        .expect("synced")
        .get(&reverse_key)
        .cloned()
        .expect("companion after replay");
    assert_ne!(
        after.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "the replay left the companion resolving to NOTHING. It was synthesized \
         from an empty forwarding table and the reconcile that reinstalled the \
         table is the only thing that ever re-derives it on a node that does \
         not subsequently fail over (#7209)"
    );
    assert!(
        after.metadata.owner_rg_id > 0,
        "the repaired companion still carries owner RG 0, so it was not \
         re-derived under the live table"
    );
    // The OTHER surface, and it was unbound until a mutation said so. Repairing
    // the shared map alone leaves the kernel session map and every worker's
    // SessionTable holding the dead row — arguably the worse half, since that
    // is the copy packets are actually matched against. Measured: a mutant that
    // repaired the shared map and replayed the stale entry passed the whole
    // suite before this assertion existed.
    let queued = queues
        .get(&0)
        .expect("worker 0 queue")
        .lock()
        .expect("queue")
        .iter()
        .find_map(|cmd| match cmd {
            WorkerCommand::UpsertSynced(e) if e.key == reverse_key => Some(e.clone()),
            _ => None,
        })
        .expect("the companion must be fanned out to the worker at all");
    assert_ne!(
        queued.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "the worker was handed the DEAD companion even though the shared map \
         was repaired. The shared map is the authority a later prewarm reads, \
         but this is the copy that reaches the kernel session map and the \
         worker SessionTables — repairing one without the other leaves packets \
         matched against the row the repair was for (#7209)"
    );

    assert_eq!(
        coordinator.synced_reverse_rederived_total(),
        before + 1,
        "the repair must be COUNTED — it is the instrument that makes the \
         import-under-an-unanswerable-table window measurable rather than \
         argued from the lock graph (#7209)"
    );

    // (3) CONTROL: replaying again, with nothing changed, must be inert.
    let steady_entries = coordinator.snapshot_shared_session_entries();
    let steady_before = coordinator.synced_reverse_rederived_total();
    coordinator.replay_synced_sessions(&steady_entries, &queues, -1);
    assert_eq!(
        coordinator.synced_reverse_rederived_total(),
        steady_before,
        "a steady-state replay, whose stored companion already agrees with the \
         live table, was counted as a repair. The metric then climbs with \
         reconcile frequency and stops meaning 'a companion was built from a \
         table that could not answer' (#7209)"
    );
}

/// #7209 item 2: `stop_inner(false)` leaves `forwarding` EMPTY — which is what
/// makes the two cells above a statement about a real window rather than a
/// contrived one.
///
/// The three cells together are the whole argument for why two of the four
/// blocking calls cannot be taken off the lock until item 1 lands:
///
///   1. `stop_inner(false)` empties `forwarding`            (this cell)
///   2. an import in that state builds a dead companion     (the cell above)
///   3. the reconcile's replay does not repair it           (the cell above)
///
/// and the quiesce + the worker `join()` both run INSIDE that window
/// (`teardown::tear_down` calls `stop_inner(false)` and only then sleeps; the
/// joins happen within `stop_inner` itself), so a lock released around either
/// exposes exactly the state leg 2 measures.
///
/// The other two do NOT. `preflight_map_fds` runs BEFORE `tear_down`, with the
/// previous table still installed; and the 10 s readiness barrier runs inside
/// `bring_up_workers`, which `reconcile` calls AFTER `snapshot::apply_snapshot`
/// has assigned `coord.forwarding = new_forwarding`. Both of those windows have
/// a populated table, so neither is blocked by item 1 — which matters because
/// the barrier is the one that blows the Go side's 3 s round-trip budget.
///
/// `clear_synced_state = false` is the reconcile's argument, and it is the
/// interesting one: the shared synced map SURVIVES, which is why an import
/// landing in the window is still there for the replay to find (#8171) — and
/// therefore why the dead companion it built survives too.
#[test]
fn stop_inner_empties_the_forwarding_table_that_a_released_lock_would_expose_7209() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    assert!(
        !coordinator.forwarding.egress.is_empty(),
        "fixture starts with an EMPTY table, so it cannot show that stop_inner \
         is what empties it"
    );
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    assert_eq!(
        coordinator.upsert_synced_session(entry.clone()),
        SyncedImportOutcome::Applied
    );

    coordinator.stop_inner(false);

    assert!(
        coordinator.forwarding.egress.is_empty()
            && coordinator.forwarding.connected_v4.is_empty(),
        "stop_inner(false) no longer empties the forwarding table. If that is \
         now true the window this issue's item 2 is blocked on has closed, and \
         the two cells above describe a state that can no longer be reached — \
         re-derive the sequencing before trusting either (#7209)"
    );
    assert!(
        coordinator
            .sessions
            .synced
            .lock()
            .expect("synced")
            .contains_key(&entry.key),
        "stop_inner(false) must NOT clear the shared synced map — the replay \
         reads it live (#8171), and an import that landed in the window is only \
         reachable afterwards because this map survives"
    );
}


// ===== #8138: the tunnel-remap purge must release the import-time reservation

/// A snapshot carrying the pool-SNAT rule, optionally owning tunnel id 7.
///
/// Both states are built by the PRODUCTION builder from these snapshots, so the
/// allocator carryover (`Arc::clone` in `forwarding_build`) is the real one —
/// which is the whole reason a release against the NEW state reaches the
/// reservation the OLD state minted.
fn purge8138_snapshot(with_tunnel: bool) -> ConfigSnapshot {
    use crate::ConfigSnapshot;
    use crate::protocol::snapshot::TunnelEndpointSnapshot;
    let mut snap = ConfigSnapshot::default();
    snap.source_nat_rules = vec![crate::SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..crate::SourceNATRuleSnapshot::default()
    }];
    if with_tunnel {
        snap.tunnel_endpoints = vec![TunnelEndpointSnapshot {
            id: 7,
            interface: "gr-0/0/0.0".to_string(),
            ifindex: 77,
            mode: "gre".to_string(),
            outer_family: "inet".to_string(),
            source: "10.1.1.1".to_string(),
            destination: "10.1.1.2".to_string(),
            ..Default::default()
        }];
    }
    snap
}

fn purge8138_entry(src_port: u16, pool_port: u16, tunnel_id: u16) -> SyncedSessionEntry {
    let mut e = reserve6600_entry(src_port, pool_port);
    e.decision.resolution.tunnel_endpoint_id = tunnel_id;
    e
}

/// True when `pool_port` is still held: a DIFFERENT flow naming the same
/// translated tuple cannot reserve it.
fn purge8138_port_held(
    allocs: &std::sync::Arc<crate::nat::InterfaceNatAllocators>,
    rules: &[crate::nat::SourceNatRule],
    src_port: u16,
    pool_port: u16,
    now_ns: u64,
) -> bool {
    let probe = purge8138_entry(src_port, pool_port, 7);
    !crate::nat::reserve_synced_source_nat_allocation_untracked(
        allocs,
        rules,
        &probe.key,
        probe.decision.nat,
        probe.metadata.is_reverse,
        None,
        now_ns,
    )
}

/// #8138 on the REAL refresh path: a tunnel-remap purge must free the pool port
/// the coordinator reserved when it imported the session.
///
/// This drives `refresh_runtime_snapshot` — a production entry point — rather
/// than calling the purge with a hand-picked forwarding. That distinction is the
/// point of the test: #8124's removed repair worked in a fixture and freed
/// nothing in production, because the state its caller actually held was never
/// checked. Here the argument the purge receives is chosen by the production
/// code, so a call site that reverts to a state holding no allocators reds this.
#[test]
fn tunnel_remap_purge_releases_untracked_reservation_on_refresh_8138() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(crate::afxdp::forwarding_build::build_forwarding_state(&purge8138_snapshot(true)));
    coordinator.validation.snapshot_installed = true;
    assert!(
        coordinator.forwarding.tunnel_endpoints.contains_key(&7),
        "precondition: the prior forwarding must OWN tunnel id 7, or the refresh \
         has no remap to purge and every assertion below passes vacuously. This \
         fired on the first draft: the snapshot row was dropped by the builder \
         for want of a parseable source/destination."
    );
    register_test_worker_7209(&mut coordinator);

    let allocs = std::sync::Arc::clone(&coordinator.forwarding.iface_nat_allocators);
    let rules = coordinator.forwarding.source_nat_rules.clone();

    let entry = purge8138_entry(41000, 50100, 7);
    let key = entry.key.clone();
    coordinator.upsert_synced_session(entry);

    assert!(
        purge8138_port_held(&allocs, &rules, 41001, 50100, 1_000),
        "precondition: the import must have taken the reservation — without it \
         every assertion below passes by never exercising anything"
    );
    assert_eq!(
        coordinator.tunnel_purge_reservations_released_total(),
        0,
        "nothing has been purged yet"
    );

    // The remap: the same config, tunnel id 7 gone. The pool rule SURVIVES, as
    // it does in the field — a tunnel remap does not delete the NAT pool.
    coordinator
        .refresh_runtime_snapshot(&purge8138_snapshot(false))
        .expect("refresh must succeed");

    assert!(
        !synced6600_contains(&coordinator, &key),
        "the remapped session must be purged"
    );
    assert!(
        !purge8138_port_held(&allocs, &rules, 41002, 50100, 2_000),
        "#8138: the purge must RELEASE the import-time reservation. It is taken \
         as NatHolder::Untracked, which contributes no holder bit, so the \
         teardown sweeps -- which clear BITS -- free nothing against it and the \
         (pool_addr, port) is held for the life of the allocator."
    );
    assert_eq!(
        coordinator.tunnel_purge_reservations_released_total(),
        1,
        "exactly one reservation was stranded and exactly one was released"
    );
}

/// The #8124 trap, made executable: releasing against the forwarding the
/// RECONCILE caller holds frees nothing, and must therefore count nothing.
///
/// `coordinator/reconcile/snapshot.rs` runs the purge after `stop_inner(false)`
/// has DEFAULTED `coord.forwarding` — no rules, no allocators. #8124 originally
/// drove the release there; it freed nothing AND incremented the repair counter,
/// reporting a repair that did not happen. It was removed before merge rather
/// than shipped.
///
/// This cell is the negative control for that counter. It pins BOTH halves: the
/// port stays held (so the caller cannot claim the leak is closed) and the
/// counter stays 0 (so it cannot claim a repair). A counter incremented on
/// attempt rather than on outcome passes the first half and fails here.
#[test]
fn purge_release_against_defaulted_forwarding_frees_nothing_and_counts_nothing_8138() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(crate::afxdp::forwarding_build::build_forwarding_state(&purge8138_snapshot(true)));
    register_test_worker_7209(&mut coordinator);

    let allocs = std::sync::Arc::clone(&coordinator.forwarding.iface_nat_allocators);
    let rules = coordinator.forwarding.source_nat_rules.clone();

    coordinator.upsert_synced_session(purge8138_entry(41010, 50110, 7));
    assert!(
        purge8138_port_held(&allocs, &rules, 41011, 50110, 1_000),
        "precondition: the reservation must be held"
    );

    // Exactly what the reconcile caller would pass if it read `self.forwarding`.
    let purged = coordinator.purge_remapped_tunnel_sessions(&[7], &ForwardingState::default());

    assert_eq!(purged, 1, "the session is still purged — this is about the port");
    assert!(
        purge8138_port_held(&allocs, &rules, 41012, 50110, 2_000),
        "a release against a DEFAULTED forwarding has no allocators to free from"
    );
    assert_eq!(
        coordinator.tunnel_purge_reservations_released_total(),
        0,
        "#8138/#8124: a repair that freed nothing must not be COUNTED. An \
         operator reading a non-zero repair count here would conclude the leak \
         is being handled while every port stayed held."
    );
}

/// Negative control: a purged session that never took a reservation must not
/// move the counter. Without this, a counter incremented once per purged
/// session — rather than once per actual free — passes every cell above.
#[test]
fn purge_of_a_session_without_snat_counts_no_release_8138() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(crate::afxdp::forwarding_build::build_forwarding_state(&purge8138_snapshot(true)));
    register_test_worker_7209(&mut coordinator);

    // Same session shape, but no source-NAT rewrite: nothing was ever reserved.
    let mut entry = purge8138_entry(41020, 50120, 7);
    entry.decision.nat.rewrite_src = None;
    entry.decision.nat.rewrite_src_port = None;
    coordinator.upsert_synced_session(entry);

    let purged = coordinator.purge_remapped_tunnel_sessions(
        &[7],
        &coordinator.forwarding.clone(),
    );

    assert_eq!(purged, 1, "the session is purged");
    assert_eq!(
        coordinator.tunnel_purge_reservations_released_total(),
        0,
        "a session with no NAT rewrite reserved nothing, so there is nothing to \
         release and nothing to count"
    );
}

/// Bind the ARGUMENT both production call sites pass.
///
/// The cells above drive `refresh_runtime_snapshot`, which is one of the two
/// call sites. The other — `coordinator/reconcile/snapshot.rs` — runs after
/// worker teardown and cannot be stood up in a unit test, so nothing executable
/// covers it. That is exactly the site where the argument matters most:
/// `stop_inner(false)` has defaulted `coord.forwarding`, so reverting this
/// argument to `&coord.forwarding` restores the #8124 behaviour (frees nothing)
/// while every executable cell stays green.
///
/// A source assertion is the honest instrument available. It is keyed on the
/// ARGUMENT, not on the call being present, and it carries a positive control:
/// if the function name itself stops appearing, the pattern is wrong rather than
/// the argument missing.
#[test]
fn both_purge_call_sites_release_against_new_forwarding_8138() {
    for (path, src) in [
        (
            "coordinator/reconcile/snapshot.rs",
            include_str!("coordinator/reconcile/snapshot.rs"),
        ),
        (
            "coordinator/snapshot_refresh.rs",
            include_str!("coordinator/snapshot_refresh.rs"),
        ),
    ] {
        // POSITIVE CONTROL first: a file that no longer calls the purge at all
        // would satisfy the argument assertion vacuously.
        assert!(
            src.contains("purge_remapped_tunnel_sessions("),
            "positive control failed: {path} no longer calls \
             purge_remapped_tunnel_sessions at all, so this cell is checking \
             nothing. The call moved or was renamed — fix the pattern, do not \
             delete the assertion."
        );
        assert!(
            src.contains("purge_remapped_tunnel_sessions(&tunnel_purge_ids, &new_forwarding)"),
            "#8138: {path} must release against `new_forwarding`. Releasing \
             against `coord.forwarding`/`self.forwarding` is the #8124 defect: \
             at the reconcile call site `stop_inner(false)` has already \
             DEFAULTED it, so the release frees nothing while looking like a \
             repair. `new_forwarding` carries the same allocators by Arc::clone, \
             which is why it reaches the reservation."
        );
    }
}

// ── #8015: a standalone reverse import is refused ────────────────────────
//
// A reverse entry is DERIVED state. Every legitimate reverse companion in the
// shared `synced` map is produced by `synthesized_synced_reverse_entry` riding
// with the forward it was derived from, so an entry that arrives already
// flagged `is_reverse` is either a redundant duplicate of one this node builds
// better, or — if its own forward was refused — a permit with nothing anchoring
// it, which a later delete of that forward cannot remove
// (`delete_synced_session_gen` derives the companion from the STORED forward,
// and there is none).
//
// WHAT MAKES THIS A MEASUREMENT AND NOT AN ASSERTION OF THE OBVIOUS. Leg (a)
// is the control and it carries the load: it re-measures the fact the whole
// simplification rests on — a FORWARD-only import leaves a COMPLETE PAIR, two
// entries, because the helper synthesizes and publishes the companion itself.
// Without leg (a) a refusal of every import at all would satisfy leg (b), and
// the cell would be green for a helper that had stopped importing sessions.
//
// PARENT-RED recipe: delete the `if entry.metadata.is_reverse { return ... }`
// early return in `upsert_synced_session`. Leg (b)'s outcome assertion fails
// (`Applied`, not `RejectedStandaloneReverse`) and its publish assertion fails
// with the lone reverse in the shared map. Target-count = 1 gate site.
#[test]
fn upsert_synced_session_refuses_standalone_reverse_8015() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_with_fabric());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // (a) CONTROL — a forward-only import leaves a COMPLETE PAIR.
    let forward = synced_entry_port(1000, 0);
    let forward_key = forward.key.clone();
    let companion_key = reverse_session_key(&forward.key, forward.decision.nat);
    assert_eq!(
        coordinator.upsert_synced_session(forward),
        SyncedImportOutcome::Applied,
        "an ordinary forward import must apply"
    );
    {
        let synced = coordinator.sessions.synced.lock().expect("shared sessions");
        assert_eq!(
            synced.len(),
            2,
            "a FORWARD-only import must leave TWO entries — the forward and the \
             companion the helper synthesizes for it. This is the fact the Go-side \
             deletion of the explicit reverse rests on, and it is also why the \
             #5674 entry cap is sized at 2x the logical ceiling (#8015)"
        );
        assert!(
            synced.contains_key(&forward_key),
            "the forward key must be published"
        );
        let companion = synced
            .get(&companion_key)
            .expect("the synthesized reverse companion must be published with its forward");
        assert!(
            companion.metadata.is_reverse,
            "the synthesized companion must carry is_reverse"
        );
    }

    // (b) SUBJECT — the same shape, arriving pre-flagged as a reverse, is
    // refused: not published, not fanned out, and reported with its own reason
    // token so the caller can tell it from a transport failure.
    let mut standalone = synced_entry_port(2000, 0);
    standalone.metadata.is_reverse = true;
    let standalone_key = standalone.key.clone();
    assert_eq!(
        coordinator.upsert_synced_session(standalone),
        SyncedImportOutcome::RejectedStandaloneReverse,
        "an import that arrives already flagged is_reverse has no forward to be \
         derived from and must be refused (#8015)"
    );
    assert_eq!(
        SyncedImportOutcome::RejectedStandaloneReverse.refusal_reason(),
        Some("standalone-reverse"),
        "the refusal must carry a stable reason token — Go discriminates a \
         SEMANTIC refusal from a transport failure on the token, and a transport \
         failure gates HA takeover-readiness (#5247)"
    );
    {
        let synced = coordinator.sessions.synced.lock().expect("shared sessions");
        assert!(
            !synced.contains_key(&standalone_key),
            "a refused standalone reverse must not be published; publishing it is \
             precisely the reverse-only orphan #8015 removes (#8015)"
        );
        assert_eq!(
            synced.len(),
            2,
            "the refusal must leave the map exactly as leg (a) left it"
        );
    }
    let pending = commands.lock().expect("commands");
    assert!(
        !pending.iter().any(
            |cmd| matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == standalone_key),
        ),
        "a refused standalone reverse must not be fanned out to any worker queue"
    );
    // The control's fan-out DID happen — the refusal is selective, not a blanket
    // block on the whole fan-out path.
    assert!(
        pending.iter().any(
            |cmd| matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == forward_key),
        ),
        "the admitted forward must still reach the worker queue — without this the \
         cell would pass for a helper that stopped fanning out entirely"
    );
    // #310, the invariant the deleted Go pre-install was added for: the worker
    // must hold the COMPANION before RG activation. No `update_ha_state` has run
    // in this cell, so the queue entry below is the companion arriving at import
    // — strictly earlier than the pre-install could deliver it.
    assert!(
        pending.iter().any(
            |cmd| matches!(cmd, WorkerCommand::UpsertSynced(entry) if entry.key == companion_key),
        ),
        "the synthesized companion must be fanned out to the worker WITH its \
         forward, at import and before any RG activation — that is the #310 \
         invariant the deleted Go pre-install existed to provide (#8015)"
    );
}

// #8015: the historical orphan scenario, driven end to end.
//
// A cap-rejected FORWARD followed by its separate `is_reverse=1` companion is
// exactly the sequence that used to leave a reverse-only entry: the cap gate is
// forward-only, so the companion skipped it and published with nothing to anchor
// it, and a later delete of that forward removed nothing because
// `delete_synced_session_gen` derives the companion from the STORED forward.
// Both halves are now refused, so the map is unchanged by the pair.
//
// The final leg re-measures the third fact the refiling rested on and that no
// later pass re-checked: a forward DELETE takes its synthesized companion with
// it, leaving zero.
//
// PARENT-RED recipe: delete the `is_reverse` early return in
// `upsert_synced_session`. The over-ceiling companion then publishes and the
// `synced_len_after == synced_len_before` assertion fails by exactly one entry —
// the "+1 orphan" by name.
#[test]
fn cap_rejected_forward_leaves_no_orphan_reverse_8015() {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_with_fabric());
    const LOGICAL_CEILING: u16 = 1;
    coordinator
        .synced_import_cap_override
        .store(LOGICAL_CEILING as usize, std::sync::atomic::Ordering::Relaxed);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );

    // Fill the map to its 2N ENTRY cap with one admitted forward (which brings
    // its companion, so 2 entries == the cap for LOGICAL_CEILING = 1).
    let seed = synced_entry_port(1000, 0);
    let seed_key = seed.key.clone();
    let seed_companion = reverse_session_key(&seed.key, seed.decision.nat);
    assert_eq!(
        coordinator.upsert_synced_session(seed),
        SyncedImportOutcome::Applied
    );
    let synced_len_before = coordinator
        .sessions
        .synced
        .lock()
        .expect("shared sessions")
        .len();
    assert_eq!(
        synced_len_before, 2,
        "the seed forward must have filled the 2N entry cap with its companion"
    );

    // The orphaning sequence: a NEW forward is cap-rejected, then the companion
    // the old Go mirror would have sent right behind it.
    let over = synced_entry_port(2000, 0);
    let over_key = over.key.clone();
    assert_eq!(
        coordinator.upsert_synced_session(over),
        SyncedImportOutcome::RejectedCapacity,
        "the over-ceiling forward must be cap-rejected — otherwise this cell is \
         not driving the scenario it is named for"
    );
    let mut trailing_reverse = synced_entry_port(2000, 0);
    trailing_reverse.key = reverse_session_key(&over_key, trailing_reverse.decision.nat);
    trailing_reverse.metadata.is_reverse = true;
    let trailing_key = trailing_reverse.key.clone();
    assert_eq!(
        coordinator.upsert_synced_session(trailing_reverse),
        SyncedImportOutcome::RejectedStandaloneReverse
    );

    {
        let synced = coordinator.sessions.synced.lock().expect("shared sessions");
        assert!(
            !synced.contains_key(&trailing_key),
            "the trailing companion of a cap-rejected forward must not publish — \
             it is the '+1 orphan' this change removes (#8015)"
        );
        assert_eq!(
            synced.len(),
            synced_len_before,
            "a cap-rejected forward and its trailing companion must leave the \
             shared map EXACTLY as they found it"
        );
    }

    // Fact 3, re-measured: a forward delete takes its synthesized companion.
    coordinator.delete_synced_session(seed_key.clone());
    let synced = coordinator.sessions.synced.lock().expect("shared sessions");
    assert!(
        !synced.contains_key(&seed_key),
        "the forward must be removed by its own delete"
    );
    assert!(
        !synced.contains_key(&seed_companion),
        "a forward delete must take the synthesized companion with it — \
         `delete_synced_session_gen` derives it from the stored forward (#8015)"
    );
    assert_eq!(
        synced.len(),
        0,
        "forward delete must leave ZERO entries: the pair is complete on the way \
         in and on the way out"
    );
}

// ---------------------------------------------------------------------------
// #9344: the owner-RG export's terminating bound.
//
// `max = 0` was the only COMPLETE request a caller could make, and it answers
// with the unbounded owner-RG session set — which crosses the Go control
// socket's 64 MiB response cap at roughly 7.8k sessions/worker on a six-worker
// box, so the HA cold prime fails permanently on a busy cluster.
//
// Paging is what replaces it, and before this change nothing here drove
// `max > 0` on this verb at all — which is how the primitive
// (`drain_session_deltas_fair`'s overflow bit) could be computed and thrown
// away into `_overflow` without a cell noticing.

/// A capped export must report that the window is INCOMPLETE, and a
/// CONTINUATION must drain the remainder of that same window without kicking
/// the workers again.
///
/// The two halves are one cell on purpose. `more = true` alone is a bit nobody
/// can act on if the only way to ask for the rest is a fresh export: a second
/// ordinary call runs phase 1 again and stacks ANOTHER full set on top of the
/// remainder, so the caller would assemble a window out of two different
/// instants. Since #5085 the receiver reconciles authoritatively against the
/// delimited window, so that is not a smaller bug than truncation, it is a
/// different one.
#[test]
fn owner_rg_export_pages_a_capped_window_without_rekicking_the_workers() {
    let mut coordinator = Coordinator::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let handle = test_worker_handle(commands.clone());
    let ack = handle.session_export_ack.clone();
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(handle), None);

    // One live binding holding 5 deltas.
    let live = Arc::new(BindingLiveState::new());
    for _ in 0..5 {
        live.push_session_delta(SessionDeltaInfo::default());
    }
    coordinator.workers.live.insert(0, live.clone());

    // PAGE 1: an ordinary capped export. Kicks phase 1, waits for the ack.
    let wait = coordinator.kick_owner_rg_export(&[1], 3, false);
    assert_eq!(
        commands.lock().expect("commands").len(),
        1,
        "the first page must kick the workers — it is what PRODUCES the window"
    );
    let seq_after_page1 = coordinator.sessions.export_seq.load(Ordering::Relaxed);
    ack.store(seq_after_page1, Ordering::Release);
    let (page1, more1) = wait.wait_and_collect().expect("page 1");
    assert_eq!(page1.len(), 3, "page 1 returns exactly the cap");
    assert!(
        more1,
        "5 deltas were produced and 3 drained, so the window is INCOMPLETE. \
         Without this bit the caller cannot tell a complete capped answer from \
         a truncated one, which is why max=0 was the only safe request"
    );

    // PAGE 2: a CONTINUATION. It must kick nothing, consume no sequence, and
    // not block on an ack that will never come.
    let wait2 = coordinator.kick_owner_rg_export(&[1], 3, true);
    assert_eq!(
        commands.lock().expect("commands").len(),
        1,
        "a continuation must enqueue NO new export command — a second kick \
         produces a whole new set on top of the remainder and the caller ends up \
         with a window spanning two instants"
    );
    assert_eq!(
        coordinator.sessions.export_seq.load(Ordering::Relaxed),
        seq_after_page1,
        "a continuation must consume no export sequence"
    );
    let (page2, more2) = wait2.wait_and_collect().expect("page 2");
    assert_eq!(
        page2.len(),
        2,
        "the continuation drains the REMAINDER of the window page 1 opened"
    );
    assert!(
        !more2,
        "the buffers are empty, so the window is complete and the caller stops"
    );

    // The two pages ADD UP to the window. A paging protocol that loses or
    // duplicates across the seam is worse than no paging at all.
    assert_eq!(
        page1.len() + page2.len(),
        5,
        "the pages must partition the window exactly"
    );
    assert!(
        !live.has_pending_session_deltas(),
        "nothing may be left behind once the caller has seen more=false"
    );
}

/// An UNCAPPED export drains everything and reports no remainder, which is the
/// pre-#9344 behaviour and the fallback for a Go caller talking to a helper
/// that predates the paging contract.
#[test]
fn owner_rg_export_uncapped_drains_everything_and_reports_no_more() {
    let mut coordinator = Coordinator::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let handle = test_worker_handle(commands.clone());
    let ack = handle.session_export_ack.clone();
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(handle), None);

    let live = Arc::new(BindingLiveState::new());
    for _ in 0..2500 {
        live.push_session_delta(SessionDeltaInfo::default());
    }
    coordinator.workers.live.insert(0, live.clone());

    let wait = coordinator.kick_owner_rg_export(&[1], 0, false);
    ack.store(
        coordinator.sessions.export_seq.load(Ordering::Relaxed),
        Ordering::Release,
    );
    let (all, more) = wait.wait_and_collect().expect("uncapped export");
    assert_eq!(all.len(), 2500, "an uncapped export drains every delta");
    assert!(
        !more,
        "an uncapped export leaves nothing behind, so it must never report more \
         — the count is drained across several internal 1024-batches and an \
         INTERMEDIATE batch's overflow bit is true on every one of them, which \
         is the reading this must not take"
    );
}

/// A capped export whose cap happens to consume the window EXACTLY must report
/// no remainder.
///
/// This is the boundary the paging loop terminates on, and getting it wrong in
/// the safe-looking direction (report more) costs an extra round trip, while
/// getting it wrong in the other direction truncates. Neither is observable
/// from the two cells above, which cap strictly below and strictly above.
#[test]
fn owner_rg_export_exact_fit_reports_no_more() {
    let mut coordinator = Coordinator::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let handle = test_worker_handle(commands.clone());
    let ack = handle.session_export_ack.clone();
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(handle), None);

    let live = Arc::new(BindingLiveState::new());
    for _ in 0..4 {
        live.push_session_delta(SessionDeltaInfo::default());
    }
    coordinator.workers.live.insert(0, live.clone());

    let wait = coordinator.kick_owner_rg_export(&[1], 4, false);
    ack.store(
        coordinator.sessions.export_seq.load(Ordering::Relaxed),
        Ordering::Release,
    );
    let (page, more) = wait.wait_and_collect().expect("exact-fit export");
    assert_eq!(page.len(), 4, "the cap consumed the whole window");
    assert!(
        !more,
        "the buffers are empty, so there is no remainder to page for"
    );
}

// ---------------------------------------------------------------------------
// #9514 — an HA same-key replacement with a CHANGED NAT decision must not strand
// the old decision's reverse-NAT steering holder.
//
// Two written claims contradicted each other about byte-identical code: #9514
// said the old holder is stranded and later refuses row reclamation; a validated
// external report recorded "FIXED: synchronized same-key NAT replacement cleanup
// releases prior steering holders". Measured through the production import path
// at 5fafce23f, before this fix: the A->B holder survived the replacement AND the
// delete (a_after_delete=1), and a later session on row A had its map delete
// refused (later_row_a_deletes=0). The report was wrong about this code.
//
// THE FIXTURE MUST MOVE THE STEERING ROW. A holder row is keyed on
// `(protocol, SNAT source address, SNAT source port)` only, so a replacement
// that keeps the same SNAT tuple re-acquires the very holder a release would
// drop and cannot distinguish the claims. A and B differ in `rewrite_src_port`.
//
// Rows are unique to these cells (203.0.113.95, ports 49514-49519): the holder
// registry is process-global, and #8291 is the history of cells trampling each
// other's rows.
//
// Observable: the holder accounting plus the test-only DNAT_DELETE_ATTEMPTS
// counter, bumped immediately before the `bpf_map_delete_elem` syscall. Real BPF
// maps cannot be created under `cargo test`; the refusal being pinned happens in
// the accounting, before that syscall.
// ---------------------------------------------------------------------------

fn snat_row_9514(port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 95))),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

fn synced_with_nat_9514(key: SessionKey, nat: NatDecision, generation: u64) -> SyncedSessionEntry {
    let mut e = synced_entry_with_generation(generation);
    e.key = key;
    e.decision.nat = nat;
    e
}

fn coordinator_with_dnat_fd_9514() -> Coordinator {
    let coordinator = Coordinator::new();
    coordinator.bpf_maps.store(std::sync::Arc::new(crate::afxdp::coordinator::BpfMaps {
        dnat_table_fd: Some(OwnedFd { fd: -1 }),
        ..Default::default()
    }));
    coordinator
}

/// A second session on the SAME steering row as `key`: the row carries no
/// remote endpoint, so differing only in the remote lands on it.
fn same_row_sibling_9514(key: &SessionKey) -> SessionKey {
    let mut k2 = key.clone();
    k2.dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 95));
    k2
}

/// FAIL-ON-REVERT: A -> B (different rows), delete, then a later session on row A.
/// Before the fix: a_after_replace=1, a_after_delete=1, later_row_a_deletes=0.
#[test]
fn ha_same_key_replace_changing_the_snat_row_releases_the_old_holder_9514() {
    use crate::afxdp::checksum::{dnat_steering_holder_count, DNAT_DELETE_ATTEMPTS};
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    let coordinator = coordinator_with_dnat_fd_9514();
    let key = test_key();
    let (a, b) = (snat_row_9514(49514), snat_row_9514(49515));
    assert_ne!(
        crate::afxdp::checksum::dnat_steering_key(&key, a),
        crate::afxdp::checksum::dnat_steering_key(&key, b),
        "precondition: A and B must be DIFFERENT steering rows, or this cell cannot \
         distinguish a released holder from a re-acquired one"
    );
    assert_eq!(dnat_steering_holder_count(&key, a), 0, "row A must start empty");

    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), a, 1));
    assert_eq!(dnat_steering_holder_count(&key, a), 1, "precondition: import holds row A");

    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), b, 2));
    let a_after_replace = dnat_steering_holder_count(&key, a);
    let b_after_replace = dnat_steering_holder_count(&key, b);
    assert_eq!(b_after_replace, 1, "precondition: the replacement landed and holds row B");

    coordinator.delete_synced_session(key.clone());
    let a_after_delete = dnat_steering_holder_count(&key, a);
    let b_after_delete = dnat_steering_holder_count(&key, b);

    // A later, unrelated session lands on row A and closes.
    let k2 = same_row_sibling_9514(&key);
    coordinator.upsert_synced_session(synced_with_nat_9514(k2.clone(), a, 1));
    let d1 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(k2.clone());
    let later_row_a_deletes = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d1;

    assert!(
        a_after_replace == 0 && a_after_delete == 0 && b_after_delete == 0 && later_row_a_deletes == 1,
        "#9514: a same-key HA replacement that MOVES the steering row must release the old \
         row's holder. Measured: a_after_replace={a_after_replace} a_after_delete={a_after_delete} \
         b_after_delete={b_after_delete} later_row_a_deletes={later_row_a_deletes} (1 = a later \
         session on row A reclaims it; 0 = the stranded holder refuses the map delete)"
    );
}

/// DOUBLE-RELEASE CONTROL: A -> A. It cannot distinguish the #9514 claims (the
/// replacement re-acquires the holder a release would drop), and that is why the
/// fix is gated on the row changing: releasing here would drop a LIVE session's
/// hold and delete its row.
#[test]
fn ha_same_key_replace_with_the_same_snat_row_holds_exactly_once_9514() {
    use crate::afxdp::checksum::{dnat_steering_holder_count, DNAT_DELETE_ATTEMPTS};
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    let coordinator = coordinator_with_dnat_fd_9514();
    let key = test_key();
    let a = snat_row_9514(49516);
    assert_eq!(dnat_steering_holder_count(&key, a), 0, "row must start empty");

    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), a, 1));
    let d0 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), a, 2));
    let deletes_on_refresh = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d0;
    let after_refresh = dnat_steering_holder_count(&key, a);
    let d1 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(key.clone());
    let deletes_on_delete = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d1;
    let after_delete = dnat_steering_holder_count(&key, a);
    assert_eq!(
        (after_refresh, deletes_on_refresh),
        (1, 0),
        "#9514: a same-row refresh must keep its single hold and delete NOTHING; releasing \
         it would blackhole a live session's return traffic until it republished"
    );
    assert_eq!(after_delete, 0, "the delete must release the single hold");
    assert_eq!(deletes_on_delete, 1, "the last holder's delete must issue exactly one map delete");
}

/// OVER-RELEASE CONTROL: migrating K off a SHARED row must leave the sibling's
/// hold intact. The migration releases through the holder accounting, never with
/// a raw map delete, so row A survives while K2 still steers through it.
#[test]
fn ha_replace_migrating_off_a_shared_row_keeps_the_siblings_hold_9514() {
    use crate::afxdp::checksum::{dnat_steering_holder_count, DNAT_DELETE_ATTEMPTS};
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    let coordinator = coordinator_with_dnat_fd_9514();
    let key = test_key();
    let k2 = same_row_sibling_9514(&key);
    let (a, b) = (snat_row_9514(49517), snat_row_9514(49518));
    assert_eq!(dnat_steering_holder_count(&key, a), 0, "row A must start empty");

    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), a, 1));
    coordinator.upsert_synced_session(synced_with_nat_9514(k2.clone(), a, 1));
    assert_eq!(dnat_steering_holder_count(&key, a), 2, "precondition: both sessions hold row A");

    let d0 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), b, 2));
    let deletes_on_migrate = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d0;
    let row_a_after_migrate = dnat_steering_holder_count(&k2, a);
    assert_eq!(
        (row_a_after_migrate, deletes_on_migrate),
        (1, 0),
        "#9514: K migrating off shared row A must release only K's hold and must NOT delete \
         the row -- K2 still steers through it (#6745)"
    );

    let d1 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(k2.clone());
    assert_eq!(
        DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d1,
        1,
        "once the sibling closes, row A is nobody's and must be deleted"
    );
    assert_eq!(dnat_steering_holder_count(&k2, a), 0);
    coordinator.delete_synced_session(key.clone());
    assert_eq!(dnat_steering_holder_count(&key, b), 0, "K's close releases row B");
}

/// The migration also covers a replacement that DROPS the source rewrite: the
/// new decision publishes no row at all, so the old one must be released.
#[test]
fn ha_same_key_replace_dropping_snat_releases_the_old_row_9514() {
    use crate::afxdp::checksum::{dnat_steering_holder_count, DNAT_DELETE_ATTEMPTS};
    let _g = crate::afxdp::checksum::dnat_counter_guard();
    let coordinator = coordinator_with_dnat_fd_9514();
    let key = test_key();
    let a = snat_row_9514(49519);
    assert_eq!(dnat_steering_holder_count(&key, a), 0, "row A must start empty");

    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), a, 1));
    let d0 = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    coordinator.upsert_synced_session(synced_with_nat_9514(key.clone(), NatDecision::default(), 2));
    let deletes_on_replace = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed) - d0;
    assert_eq!(
        (dnat_steering_holder_count(&key, a), deletes_on_replace),
        (0, 1),
        "#9514: a replacement that drops SNAT must release the old row and delete it -- \
         nothing will ever close under decision A again"
    );
}

// #9678: a peer-synced upsert for a flow this node forwards as a LOCAL session,
// while the owner RG is locally forwarding-active, must not touch the allocator
// or the shared maps. The worker refuses that replace; before the fix the
// coordinator's pre-publish reservation had already evicted the local flow's
// live allocation.
const RG_9678: i32 = 1;
const LOCAL_PORT_9678: u16 = 50010;
const PEER_PORT_9678: u16 = 50020;
const FLOW_SRC_PORT_9678: u16 = 40100;

fn snat_9678(port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

/// True when a DIFFERENT flow can reserve `pool_port`, i.e. nothing live holds
/// it. A successful probe takes the port, so each probe uses its own flow and is
/// the last word on that port in its cell.
fn port_is_free_9678(coordinator: &Coordinator, probe_src_port: u16, pool_port: u16) -> bool {
    let probe = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 201)),
        src_port: probe_src_port,
        ..test_key()
    };
    crate::nat::reserve_synced_source_nat_allocation_untracked(
        &coordinator.forwarding.iface_nat_allocators,
        &coordinator.forwarding.source_nat_rules,
        &probe,
        snat_9678(pool_port),
        false,
        None,
        2_000,
    )
}

fn peer_entry_9678() -> SyncedSessionEntry {
    let mut entry = reserve6600_entry(FLOW_SRC_PORT_9678, PEER_PORT_9678);
    entry.metadata.owner_rg_id = RG_9678;
    entry
}

/// A coordinator with one worker, RG_9678 locally active or not, and (when
/// `local_flow`) flow F forwarded locally on LOCAL_PORT_9678: allocated and
/// published to the shared maps as a local-origin session.
fn coordinator_9678(
    rg_active: bool,
    local_flow: bool,
) -> (Coordinator, Arc<Mutex<VecDeque<WorkerCommand>>>, SessionKey) {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(reserve6600_forwarding());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let rg = if rg_active {
        active_ha_runtime(now_secs)
    } else {
        inactive_ha_runtime(0)
    };
    coordinator
        .ha
        .rg_runtime
        .store(Arc::new(BTreeMap::from([(RG_9678, rg)])));
    let key = peer_entry_9678().key;
    if local_flow {
        let mut local = reserve6600_entry(FLOW_SRC_PORT_9678, LOCAL_PORT_9678);
        local.origin = SessionOrigin::ForwardFlow;
        local.metadata.owner_rg_id = RG_9678;
        assert!(
            crate::nat::reserve_synced_source_nat_allocation_untracked(
                &coordinator.forwarding.iface_nat_allocators,
                &coordinator.forwarding.source_nat_rules,
                &local.key,
                local.decision.nat,
                false,
                None,
                1_000,
            ),
            "setup: the local flow must hold LOCAL_PORT_9678"
        );
        crate::afxdp::shared_ops::publish_shared_session(
            &coordinator.sessions.synced,
            &coordinator.sessions.nat,
            &coordinator.sessions.forward_wire,
            &coordinator.sessions.owner_rg_indexes,
            &local,
        );
    }
    (coordinator, commands, key)
}

fn shared_origin_9678(coordinator: &Coordinator, key: &SessionKey) -> Option<(SessionOrigin, NatDecision)> {
    coordinator
        .sessions
        .synced
        .lock()
        .expect("synced map")
        .get(key)
        .map(|entry| (entry.origin, entry.decision.nat))
}

fn queued_upsert_9678(commands: &Arc<Mutex<VecDeque<WorkerCommand>>>, key: &SessionKey) -> bool {
    commands
        .lock()
        .expect("commands")
        .iter()
        .any(|cmd| matches!(cmd, WorkerCommand::UpsertSynced(entry) if &entry.key == key))
}

#[test]
fn peer_upsert_keeps_a_locally_owned_flows_allocation_9678() {
    let (coordinator, commands, key) = coordinator_9678(true, true);
    coordinator.upsert_synced_session(peer_entry_9678());
    assert!(
        !port_is_free_9678(&coordinator, 40200, LOCAL_PORT_9678),
        "the peer upsert evicted the live local allocation: the locally forwarded flow's \
         translated port is free to be handed to another flow"
    );
    assert!(
        port_is_free_9678(&coordinator, 40201, PEER_PORT_9678),
        "the peer upsert left an Untracked reservation on its own port for a session no \
         worker will install"
    );
    assert_eq!(
        shared_origin_9678(&coordinator, &key),
        Some((SessionOrigin::ForwardFlow, snat_9678(LOCAL_PORT_9678))),
        "the shared maps must keep naming the local session, not the peer's decision"
    );
    assert!(
        !queued_upsert_9678(&commands, &key),
        "a peer upsert the worker must refuse is not fanned out"
    );
}

#[test]
fn peer_upsert_naming_an_occupied_port_keeps_the_local_allocation_9678() {
    let (coordinator, _commands, _key) = coordinator_9678(true, true);
    // Another flow already holds the port the peer names, so the reserve would
    // refuse; the eviction used to happen before that refusal.
    let other = SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 202)),
        src_port: 40300,
        ..test_key()
    };
    assert!(crate::nat::reserve_synced_source_nat_allocation_untracked(
        &coordinator.forwarding.iface_nat_allocators,
        &coordinator.forwarding.source_nat_rules,
        &other,
        snat_9678(PEER_PORT_9678),
        false,
        None,
        1_500,
    ));
    coordinator.upsert_synced_session(peer_entry_9678());
    assert!(
        !port_is_free_9678(&coordinator, 40202, LOCAL_PORT_9678),
        "a peer upsert whose reservation is refused still freed the local flow's port"
    );
}

#[test]
fn peer_upsert_replaces_and_reserves_when_the_rg_is_not_locally_active_9678() {
    // Control: the gate is ownership, not "never reserve over a local entry".
    let (coordinator, commands, key) = coordinator_9678(false, true);
    coordinator.upsert_synced_session(peer_entry_9678());
    assert_eq!(
        shared_origin_9678(&coordinator, &key),
        Some((SessionOrigin::SyncImport, snat_9678(PEER_PORT_9678))),
        "with the RG not locally active the peer's session must replace the local one"
    );
    assert!(queued_upsert_9678(&commands, &key), "the replace must be fanned out");
    assert!(
        !port_is_free_9678(&coordinator, 40203, PEER_PORT_9678),
        "the replacing import must reserve its translated port"
    );
}

#[test]
fn peer_upsert_still_reserves_on_an_active_node_with_no_local_flow_9678() {
    // Control: an active RG alone must not skip the #6600 pre-publish reservation.
    let (coordinator, commands, key) = coordinator_9678(true, false);
    coordinator.upsert_synced_session(peer_entry_9678());
    assert!(queued_upsert_9678(&commands, &key), "the import must be fanned out");
    assert!(
        !port_is_free_9678(&coordinator, 40204, PEER_PORT_9678),
        "an import with no local session must still reserve before it publishes (#6600)"
    );
}

