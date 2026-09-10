// #9526 follow-up: the id-0 purge, driven through the REAL worker loop.
//
// The first version bound the worker-loop wiring with a source-text check, on
// the premise that the rotation block had no unit harness. A source-text check
// proves the call is present, not that it is reached, and the premise did not
// survive measurement:
//
//   - `worker_loop` binds nothing when its plan is empty. Every map fd is -1,
//     and `PollMode::BusyPoll` never blocks.
//   - The rotation block (`refresh_runtime_view`, then
//     `if let Some(new_forwarding)`) runs at the top level of every iteration,
//     not under a bindings-gated branch.
//   - `WorkerCommand::UpsertLocal` installs a session's metadata unchanged,
//     bound rule handle included.
//   - The purge's teardown (`delete_terminal_half`) removes the key from the
//     coordinator's shared HA map, which the test holds.
//
// So these cells publish a real forwarding rotation into a running worker and
// observe the purge. Loaded from loop_body/mod.rs via `#[path]`.
use super::*;
use crate::policy::{parse_policy_state_with_counters, PolicyCounterStore, PolicyRuleCounter, PolicyState};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn rule(name: &str, policy_id: u32) -> crate::PolicyRuleSnapshot {
    crate::PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec![format!("app-{name}")],
        application_terms: vec![crate::PolicyApplicationSnapshot {
            name: format!("app-{name}"),
            protocol: "tcp".to_string(),
            source_port: String::new(),
            destination_port: String::new(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "permit".to_string(),
        ..Default::default()
    }
}

fn policy(rules: &[crate::PolicyRuleSnapshot]) -> PolicyState {
    let zones: FxHashMap<String, u16> = [("lan".to_string(), 1u16), ("wan".to_string(), 2u16)]
        .into_iter()
        .collect();
    parse_policy_state_with_counters("deny", rules, &zones, &[], &PolicyCounterStore::default())
        .expect("fixture policy must parse")
}

// The view is built for THIS file's test-local channel and never reaches the
// coordinator's. The #6592 canary reads each file standalone, so it cannot see
// the `#[cfg(test)]` on this module's `mod` line in loop_body/mod.rs. The
// redundant attribute puts the construction in the file's test half, where
// its marker is honoured.
#[cfg(test)]
fn view(generation: u64, rules: &[crate::PolicyRuleSnapshot]) -> (Arc<RuntimeView>, Arc<ForwardingState>) {
    let mut forwarding = ForwardingState::default();
    forwarding.policy = policy(rules);
    let forwarding = Arc::new(forwarding);
    let view = Arc::new(RuntimeView::new( // runtime-view-canary: test-local
        ValidationState {
            snapshot_installed: true,
            config_generation: generation,
            fib_generation: generation as u32,
        },
        forwarding.clone(),
    ));
    (view, forwarding)
}

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn entry(key: SessionKey, is_reverse: bool, counter: Option<Arc<PolicyRuleCounter>>) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key,
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: Some([6, 7, 8, 9, 10, 11]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: counter,
        },
        // `UpsertLocal` requires a sync-family origin; the purge does not look
        // at origin, only at the forward half's bound rule handle.
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

/// Waits until the worker has completed `n` more loop iterations (the loop
/// stores a fresh timestamp in `heartbeat` once per iteration).
fn wait_for_iterations(heartbeat: &AtomicU64, n: usize) {
    for _ in 0..n {
        let before = heartbeat.load(Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(30);
        while heartbeat.load(Ordering::Relaxed) == before {
            assert!(Instant::now() < deadline, "the worker loop stopped iterating");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

struct Presence {
    first_forward: bool,
    first_reverse: bool,
    unbound: bool,
}

/// Starts a real worker on generation 1 (`p-first` at policy_id 0, `p-web` at
/// 1), installs a session pair bound to `p-first` plus an unbound id-0 session,
/// publishes generation 2 with `new_rules`, and reports which keys are still in
/// the coordinator's shared HA map.
fn rotate(new_rules: &[crate::PolicyRuleSnapshot]) -> Presence {
    let coord = Coordinator::new();
    let channel = RuntimeViewChannel::default();
    let (old_view, old_forwarding) = view(1, &[rule("p-first", 0), rule("p-web", 1)]);
    let first_counter = old_forwarding.policy.hit_counter_by_idx(1).cloned();
    assert_eq!(
        first_counter.as_ref().map(|c| c.rule_id()),
        Some("lan->wan/p-first"),
        "fixture: counter idx 1 is the first rule's handle"
    );
    channel.publish(old_view);

    let mut shared = WorkerSharedDataplane::from_coord(&coord);
    shared.runtime = channel.reader();
    let synced = shared.sessions.synced.clone();
    let commands: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let heartbeat = Arc::new(AtomicU64::new(0));
    let (startup_tx, _startup_rx) = std::sync::mpsc::channel();
    let control = WorkerControlChannels::new(
        commands.clone(),
        Vec::new(),
        Arc::new(BTreeMap::new()),
        stop.clone(),
        heartbeat.clone(),
        Arc::new(AtomicU64::new(0)),
        None,
        startup_tx,
    );
    let plan = WorkerLaunchPlan::new(0, 0, Vec::new(), crate::PollMode::BusyPoll, DnatTableFds::default());
    let cos = WorkerCoSState::from_coord(&coord);
    let telemetry = WorkerPublishedTelemetry::new(
        Arc::new(Mutex::new(ExceptionEventRing::new())),
        Arc::new(Mutex::new(VecDeque::new())),
        Arc::new(Mutex::new(None)),
        Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
        Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    );
    let worker = std::thread::spawn(move || worker_loop(plan, shared, control, cos, telemetry));
    wait_for_iterations(&heartbeat, 2);

    let first_forward = key(40001);
    let first_reverse = reverse_session_key(&first_forward, NatDecision::default());
    let unbound = key(40003);
    let entries = [
        entry(first_forward.clone(), false, first_counter.clone()),
        entry(first_reverse.clone(), true, first_counter),
        entry(unbound.clone(), false, None),
    ];
    {
        let mut map = synced.lock().expect("shared synced map");
        for e in &entries {
            map.insert(e.key.clone(), e.clone());
        }
    }
    {
        let mut queue = commands.lock().expect("worker command queue");
        for e in entries {
            queue.push_back(WorkerCommand::UpsertLocal(e));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !commands.lock().expect("worker command queue").is_empty() {
        assert!(Instant::now() < deadline, "the worker never drained its command queue");
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_for_iterations(&heartbeat, 2);

    let (new_view, _new_forwarding) = view(2, new_rules);
    channel.publish(new_view);
    wait_for_iterations(&heartbeat, 3);

    let presence = {
        let map = synced.lock().expect("shared synced map");
        Presence {
            first_forward: map.contains_key(&first_forward),
            first_reverse: map.contains_key(&first_reverse),
            unbound: map.contains_key(&unbound),
        }
    };
    stop.store(true, Ordering::Relaxed);
    worker.join().expect("the worker loop exits cleanly on stop");
    presence
}

#[test]
fn worker_loop_rotation_purges_the_deleted_first_policys_sessions_9526() {
    let deleted = rotate(&[rule("p-web", 0)]);
    assert!(
        !deleted.first_forward,
        "the deleted first policy's forward session survived a real worker rotation"
    );
    assert!(
        !deleted.first_reverse,
        "its REVERSE half survived: a one-way reverse flow keeps transiting (#9526)"
    );
    assert!(
        deleted.unbound,
        "an unbound id-0 session (host-local / fabric / tunnel / peer-synced) was purged"
    );

    let renamed = rotate(&[rule("p-first-v2", 0), rule("p-web", 1)]);
    assert!(
        !renamed.first_forward && !renamed.first_reverse,
        "a rename is delete + add by stable id, so it purges the old policy's sessions"
    );
    assert!(renamed.unbound, "a rename must not touch unbound id-0 sessions");
}

/// The control that makes the purge cell above mean something: the same
/// worker, the same installed sessions, and a real rotation (a new forwarding
/// allocation) that KEEPS the first policy. If the install never happened, or
/// if a rotation alone dropped shared entries, this cell reds instead of the
/// purge cell passing for the wrong reason.
#[test]
fn worker_loop_rotation_keeps_the_first_policys_sessions_when_it_survives_9526() {
    let kept = rotate(&[rule("p-first", 0), rule("p-web", 1)]);
    assert!(
        kept.first_forward && kept.first_reverse && kept.unbound,
        "a rotation that keeps the first policy must purge nothing \
         (forward={} reverse={} unbound={})",
        kept.first_forward,
        kept.first_reverse,
        kept.unbound
    );
}
