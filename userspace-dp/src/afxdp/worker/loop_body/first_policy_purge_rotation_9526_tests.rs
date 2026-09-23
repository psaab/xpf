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
use crate::policy::{
    PolicyCounterStore, PolicyRuleCounter, PolicyState, parse_policy_state_with_counters,
};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn rule(name: &str, policy_id: u32) -> crate::PolicyRuleSnapshot {
    rule_with_zones(name, policy_id, "lan", "wan")
}

fn rule_with_zones(
    name: &str,
    policy_id: u32,
    from_zone: &str,
    to_zone: &str,
) -> crate::PolicyRuleSnapshot {
    crate::PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
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
    let zones: FxHashMap<String, u16> = [
        ("lan".to_string(), 1u16),
        ("wan".to_string(), 2u16),
        ("dmz".to_string(), 3u16),
    ]
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
fn view_with_policy_metadata(
    generation: u64,
    rules: &[crate::PolicyRuleSnapshot],
    policy_rematch_extensive: bool,
    policy_rename_ancestry: Vec<crate::protocol::PolicyRenameAncestry>,
) -> (Arc<RuntimeView>, Arc<ForwardingState>) {
    let mut forwarding = ForwardingState::default();
    forwarding.policy = policy(rules);
    forwarding.policy_rematch_extensive = policy_rematch_extensive;
    forwarding.policy_rename_ancestry = policy_rename_ancestry;
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.zone_name_to_id.insert("dmz".to_string(), 3);
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.zone_set_validated = true;
    forwarding.ingress_logical_ifindex.insert((11, 0), 11);
    let ingress_zone = rules
        .first()
        .and_then(|rule| forwarding.zone_name_to_id.get(&rule.from_zone))
        .copied()
        .unwrap_or(0);
    forwarding.ifindex_to_zone_id.insert(11, ingress_zone);
    let forwarding = Arc::new(forwarding);
    let view = Arc::new(RuntimeView::new(
        // runtime-view-canary: test-local
        ValidationState {
            snapshot_installed: true,
            config_generation: generation,
            fib_generation: generation as u32,
        },
        forwarding.clone(),
    ));
    (view, forwarding)
}

#[cfg(test)]
fn view_with_removed_zone_metadata(
    generation: u64,
    rules: &[crate::PolicyRuleSnapshot],
    policy_rematch_extensive: bool,
    policy_rename_ancestry: Vec<crate::protocol::PolicyRenameAncestry>,
    removed_zone_id: u16,
) -> (Arc<RuntimeView>, Arc<ForwardingState>) {
    let (base_view, base_forwarding) = view_with_policy_metadata(
        generation,
        rules,
        policy_rematch_extensive,
        policy_rename_ancestry,
    );
    let mut forwarding = (*base_forwarding).clone();
    forwarding.zone_id_to_name.remove(&removed_zone_id);
    let forwarding = Arc::new(forwarding);
    let view = Arc::new(RuntimeView::new(base_view.validation(), forwarding.clone())); // runtime-view-canary: test-local
    (view, forwarding)
}

#[cfg(test)]
fn view(
    generation: u64,
    rules: &[crate::PolicyRuleSnapshot],
) -> (Arc<RuntimeView>, Arc<ForwardingState>) {
    view_with_policy_metadata(generation, rules, false, Vec::new())
}

#[cfg(test)]
fn extensive_view(
    generation: u64,
    rules: &[crate::PolicyRuleSnapshot],
    ancestry: Vec<crate::protocol::PolicyRenameAncestry>,
) -> (Arc<RuntimeView>, Arc<ForwardingState>) {
    view_with_policy_metadata(generation, rules, true, ancestry)
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

fn entry(
    key: SessionKey,
    is_reverse: bool,
    counter: Option<Arc<PolicyRuleCounter>>,
) -> SyncedSessionEntry {
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
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 11,
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
        leak_incarnation: 0,
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
            assert!(
                Instant::now() < deadline,
                "the worker loop stopped iterating"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

struct Presence {
    first_forward: bool,
    first_reverse: bool,
    unbound: bool,
    first_forward_entry: Option<SyncedSessionEntry>,
    first_reverse_entry: Option<SyncedSessionEntry>,
    old_first_counter: Option<Arc<PolicyRuleCounter>>,
}
/// Starts a real worker on generation 1 (`p-first` at policy_id 0, `p-web` at
/// 1), installs a session pair bound to `p-first` plus an unbound id-0 session,
/// publishes generation 2 with `new_rules`, and reports which keys are still in
/// the coordinator's shared HA map.
fn rotate(new_rules: &[crate::PolicyRuleSnapshot]) -> Presence {
    rotate_with_metadata(new_rules, false, &[], None)
}

/// Live-worker harness behind `rotate_with_metadata`, split into start,
/// publish, and presence steps so T1→T2 tests can publish two successive
/// generations into the same worker. `rotate_with_metadata` is the
/// single-rotation specialization; its behavior is unchanged.
struct RotationHarness {
    channel: RuntimeViewChannel,
    synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    worker: Option<std::thread::JoinHandle<()>>,
    first_forward: SessionKey,
    first_reverse: SessionKey,
    unbound: SessionKey,
    old_first_counter: Option<Arc<PolicyRuleCounter>>,
}

impl RotationHarness {
    /// Starts a real worker on generation 1 (`p-first` at policy_id 0,
    /// `p-web` at 1) and installs a session pair bound to `p-first` plus an
    /// unbound id-0 session — the setup half of `rotate_with_metadata`.
    fn start() -> Self {
        Self::start_with_extra(&[])
    }

    /// Starts the same worker fixture with the unbound victim carrying the
    /// requested origin. The failover-before-rename joint starts it as a
    /// `SyncImport`, then promotes it through the worker's real
    /// `UpsertSynced` command path before rotating the forwarding view.
    fn start_with_unbound_origin(
        extra: &[SyncedSessionEntry],
        unbound_origin: SessionOrigin,
    ) -> Self {
        Self::start_with_extra_and_origin(extra, unbound_origin)
    }

    /// Starts the fixture with an initial `SyncImport` victim so the joint can
    /// exercise the failover retag instead of beginning with the post-failover
    /// `SharedPromote` fixture used by the single-leg cells.
    fn start_for_failover(extra: &[SyncedSessionEntry]) -> Self {
        Self::start_with_unbound_origin(extra, SessionOrigin::SyncImport)
    }

    /// `start` plus additional caller-supplied rows, installed through the
    /// same shared-map + command-queue path (SharedPromote rows via
    /// UpsertSynced, all others via UpsertLocal). Selectivity cells use this
    /// to install rows the rotation must NOT purge.
    fn start_with_extra(extra: &[SyncedSessionEntry]) -> Self {
        Self::start_with_extra_and_origin(extra, SessionOrigin::SharedPromote)
    }

    fn start_with_extra_and_origin(
        extra: &[SyncedSessionEntry],
        unbound_origin: SessionOrigin,
    ) -> Self {
        let coord = Coordinator::new();
        let channel = RuntimeViewChannel::default();
        let (old_view, old_forwarding) = view(1, &[rule("p-first", 0), rule("p-web", 1)]);
        let first_counter = old_forwarding.policy.hit_counter_by_idx(1).cloned();
        let old_first_counter = first_counter.clone();
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
            Arc::new(crate::afxdp::binding_state::ExportBufferState::new()),
            None,
            startup_tx,
        );
        let plan = WorkerLaunchPlan::new(
            0,
            0,
            Vec::new(),
            crate::PollMode::BusyPoll,
            DnatTableFds::default(),
        );
        let cos = WorkerCoSState::from_coord(&coord);
        let runtime_atomics = Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
        let telemetry = WorkerPublishedTelemetry::new(
            Arc::new(Mutex::new(ExceptionEventRing::new())),
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(Mutex::new(None)),
            Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            runtime_atomics.clone(),
            Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        );
        let worker = std::thread::spawn(move || worker_loop(plan, shared, control, cos, telemetry));
        wait_for_iterations(&heartbeat, 2);
        let first_forward = key(40001);
        let first_reverse = reverse_session_key(&first_forward, NatDecision::default());
        let unbound = key(40003);
        let mut unbound_entry = entry(unbound.clone(), false, None);
        unbound_entry.metadata.ingress_zone = 3;
        unbound_entry.origin = unbound_origin;
        let mut entries = vec![
            entry(first_forward.clone(), false, first_counter.clone()),
            entry(first_reverse.clone(), true, first_counter),
            unbound_entry,
        ];
        entries.extend(extra.iter().cloned());
        {
            let mut map = synced.lock().expect("shared synced map");
            for e in &entries {
                map.insert(e.key.clone(), e.clone());
            }
        }
        {
            let mut queue = commands.lock().expect("worker command queue");
            for e in entries {
                if e.origin == SessionOrigin::SharedPromote {
                    queue.push_back(WorkerCommand::UpsertSynced(e));
                } else {
                    queue.push_back(WorkerCommand::UpsertLocal(e));
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while !commands.lock().expect("worker command queue").is_empty() {
            assert!(
                Instant::now() < deadline,
                "the worker never drained its command queue"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Queue emptiness only proves the commands moved out of the shared deque;
        // let the worker finish its local scratch batch before any caller rotates
        // the view. This synchronization is required by every existing rotation
        // cell, not just the failover-before-rename joint.
        wait_for_iterations(&heartbeat, 2);
        Self {
            channel,
            synced,
            commands,
            stop,
            heartbeat,
            runtime_atomics,
            worker: Some(worker),
            first_forward,
            first_reverse,
            unbound,
            old_first_counter,
        }
    }

    fn publish(
        &self,
        generation: u64,
        new_rules: &[crate::PolicyRuleSnapshot],
        policy_rematch_extensive: bool,
        policy_rename_ancestry: &[crate::protocol::PolicyRenameAncestry],
        removed_zone_id: Option<u16>,
    ) {
        let (new_view, _new_forwarding) = if let Some(removed_zone_id) = removed_zone_id {
            view_with_removed_zone_metadata(
                generation,
                new_rules,
                policy_rematch_extensive,
                policy_rename_ancestry.to_vec(),
                removed_zone_id,
            )
        } else {
            view_with_policy_metadata(
                generation,
                new_rules,
                policy_rematch_extensive,
                policy_rename_ancestry.to_vec(),
            )
        };
        self.channel.publish(new_view);
        wait_for_iterations(&self.heartbeat, 3);
    }

    /// Re-publish the victim through the same shared-map + worker-command path
    /// used by a failover promotion. The real packet-side promoter is not
    /// reachable from this empty-binding worker fixture; this is its queue
    /// contract: the authoritative shared row is retagged first, then the
    /// worker receives the SharedPromote upsert.
    fn promote_unbound_for_failover(&self) {
        let mut promoted = self
            .synced
            .lock()
            .expect("shared synced map")
            .get(&self.unbound)
            .cloned()
            .expect("failover victim must be in the shared map");
        assert_eq!(
            promoted.origin,
            SessionOrigin::SyncImport,
            "joint setup must begin with a peer-synced victim"
        );
        promoted.origin = SessionOrigin::SharedPromote;
        self.synced
            .lock()
            .expect("shared synced map")
            .insert(self.unbound.clone(), promoted.clone());
        self.commands
            .lock()
            .expect("worker command queue")
            .push_back(WorkerCommand::UpsertSynced(promoted));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self
            .commands
            .lock()
            .expect("worker command queue")
            .is_empty()
        {
            assert!(
                Instant::now() < deadline,
                "the worker never drained the failover promotion command"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        wait_for_iterations(&self.heartbeat, 2);
    }

    /// Queue a diagnostic read against the real worker-local SessionTable.
    /// `counter_query_replica` distinguishes the pre-failover SyncImport from
    /// the post-failover SharedPromote origin because SharedPromote is
    /// intentionally excluded from `is_peer_synced`.
    fn query_worker_presence(&self, key: &SessionKey, sequence: u64) -> (bool, bool) {
        self.commands
            .lock()
            .expect("worker command queue")
            .push_back(WorkerCommand::QuerySessionCounters {
                sequence,
                key: key.clone(),
            });
        let deadline = Instant::now() + Duration::from_secs(30);
        while self
            .runtime_atomics
            .counter_query_seq
            .load(Ordering::Acquire)
            != sequence
        {
            assert!(
                Instant::now() < deadline,
                "the worker never answered the session presence query"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        (
            self.runtime_atomics
                .counter_query_found
                .load(Ordering::Acquire)
                != 0,
            self.runtime_atomics
                .counter_query_replica
                .load(Ordering::Acquire)
                != 0,
        )
    }

    /// Model a late bulk/incremental replay: reinsert the stale authoritative
    /// row into the shared map and enqueue its worker import, exactly as the
    /// fixture setup does. Keeping both sides observable prevents a
    /// shared-map-only assertion from passing while the worker resurrects it.
    fn replay_unbound(&self, stale: SyncedSessionEntry) {
        self.synced
            .lock()
            .expect("shared synced map")
            .insert(stale.key.clone(), stale.clone());
        self.commands
            .lock()
            .expect("worker command queue")
            .push_back(WorkerCommand::UpsertSynced(stale));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self
            .commands
            .lock()
            .expect("worker command queue")
            .is_empty()
        {
            assert!(
                Instant::now() < deadline,
                "the worker never drained the stale replay command"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        wait_for_iterations(&self.heartbeat, 2);
    }

    fn presence(&self) -> Presence {
        let map = self.synced.lock().expect("shared synced map");
        let first_forward_entry = map.get(&self.first_forward).cloned();
        let first_reverse_entry = map.get(&self.first_reverse).cloned();
        Presence {
            first_forward: first_forward_entry.is_some(),
            first_reverse: first_reverse_entry.is_some(),
            unbound: map.contains_key(&self.unbound),
            first_forward_entry,
            first_reverse_entry,
            old_first_counter: self.old_first_counter.clone(),
        }
    }

    /// Stops the worker and joins it. A panicked worker fails loudly here —
    /// a silently dead worker would make every purge assertion vacuous.
    fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .expect("the worker loop exits cleanly on stop");
        }
    }
}

impl Drop for RotationHarness {
    /// Backstop for assertion panics mid-test: signal the BusyPoll loop to
    /// exit so a failed test does not leak a spinning worker. No join here —
    /// joining in Drop would abort on a worker panic; `shutdown` owns that.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn rotate_with_metadata(
    new_rules: &[crate::PolicyRuleSnapshot],
    policy_rematch_extensive: bool,
    policy_rename_ancestry: &[crate::protocol::PolicyRenameAncestry],
    removed_zone_id: Option<u16>,
) -> Presence {
    let harness = RotationHarness::start();
    harness.publish(
        2,
        new_rules,
        policy_rematch_extensive,
        policy_rename_ancestry,
        removed_zone_id,
    );
    let presence = harness.presence();
    harness.shutdown();
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
    assert!(
        renamed.unbound,
        "a rename must not touch unbound id-0 sessions"
    );
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

#[test]
fn extensive_rotation_rebinds_both_halves_with_new_policy_counter_and_zones_10511() {
    let ancestry = crate::protocol::PolicyRenameAncestry {
        source_rule_id: "lan->wan/p-first".to_string(),
        destination_rule_id: "dmz->wan/p-new".to_string(),
        source_from_zone: "lan".to_string(),
        source_to_zone: "wan".to_string(),
        destination_from_zone: "dmz".to_string(),
        destination_to_zone: "wan".to_string(),
        source_from_zone_id: 1,
        source_to_zone_id: 2,
        destination_from_zone_id: 3,
        destination_to_zone_id: 2,
        source_from_zone_any: false,
        source_to_zone_any: false,
        destination_from_zone_any: false,
        destination_to_zone_any: false,
    };
    let retained = rotate_with_metadata(
        &[rule_with_zones("p-new", 0, "dmz", "wan"), rule("p-web", 1)],
        true,
        &[ancestry],
        None,
    );
    let forward = retained
        .first_forward_entry
        .as_ref()
        .expect("extensive rematch must retain the forward half");
    let reverse = retained
        .first_reverse_entry
        .as_ref()
        .expect("extensive rematch must retain the reverse half");
    assert_eq!(forward.metadata.policy_id, 0);
    assert_eq!(reverse.metadata.policy_id, 0);
    assert_eq!(forward.metadata.policy_counter_idx, 1);
    assert_eq!(reverse.metadata.policy_counter_idx, 1);
    let forward_counter = forward
        .metadata
        .policy_counter
        .as_ref()
        .expect("forward half must carry the new counter Arc");
    let reverse_counter = reverse
        .metadata
        .policy_counter
        .as_ref()
        .expect("reverse half must carry the new counter Arc");
    assert_eq!(forward_counter.rule_id(), "dmz->wan/p-new");
    assert_eq!(reverse_counter.rule_id(), "dmz->wan/p-new");
    assert!(Arc::ptr_eq(forward_counter, reverse_counter));
    assert!(
        !Arc::ptr_eq(
            forward_counter,
            retained
                .old_first_counter
                .as_ref()
                .expect("fixture must expose the old counter"),
        ),
        "the rebind must replace, not reuse, the old policy counter Arc"
    );
    assert_eq!(forward.metadata.ingress_zone, 3);
    assert_eq!(reverse.metadata.ingress_zone, 2);
    assert_eq!(forward.metadata.egress_zone, 2);
    assert_eq!(reverse.metadata.egress_zone, 3);
}
/// A valid ancestry descriptor is not enough to retain policy id 0 when the
/// extensive rematch gate is disabled. Generic/default rematch keeps the
/// existing delete behavior, including both halves of the first-policy pair.
#[test]
fn non_extensive_ancestry_does_not_retain_first_policy_id_zero_10511() {
    let ancestry = crate::protocol::PolicyRenameAncestry {
        source_rule_id: "lan->wan/p-first".to_string(),
        destination_rule_id: "dmz->wan/p-new".to_string(),
        source_from_zone: "lan".to_string(),
        source_to_zone: "wan".to_string(),
        destination_from_zone: "dmz".to_string(),
        destination_to_zone: "wan".to_string(),
        source_from_zone_id: 1,
        source_to_zone_id: 2,
        destination_from_zone_id: 3,
        destination_to_zone_id: 2,
        source_from_zone_any: false,
        source_to_zone_any: false,
        destination_from_zone_any: false,
        destination_to_zone_any: false,
    };
    let purged = rotate_with_metadata(
        &[rule_with_zones("p-new", 0, "dmz", "wan"), rule("p-web", 1)],
        false,
        &[ancestry],
        None,
    );
    assert!(
        purged.first_forward_entry.is_none() && purged.first_reverse_entry.is_none(),
        "plain rematch must purge id-0 first-policy halves even when ancestry is present"
    );
    assert!(
        purged.unbound,
        "the unrelated SharedPromote id-0 row must remain outside bound-policy teardown"
    );
}

#[test]
fn extensive_rotation_deleting_destination_rule_purges_both_halves_10511() {
    let ancestry = crate::protocol::PolicyRenameAncestry {
        source_rule_id: "lan->wan/p-first".to_string(),
        destination_rule_id: "lan->wan/p-new".to_string(),
        source_from_zone: "lan".to_string(),
        source_to_zone: "wan".to_string(),
        destination_from_zone: "lan".to_string(),
        destination_to_zone: "wan".to_string(),
        source_from_zone_id: 1,
        source_to_zone_id: 2,
        destination_from_zone_id: 1,
        destination_to_zone_id: 2,
        source_from_zone_any: false,
        source_to_zone_any: false,
        destination_from_zone_any: false,
        destination_to_zone_any: false,
    };
    let purged = rotate_with_metadata(
        &[rule_with_zones("p-other", 0, "lan", "wan")],
        true,
        &[ancestry],
        None,
    );
    assert!(
        purged.first_forward_entry.is_none() && purged.first_reverse_entry.is_none(),
        "missing destination rule must purge the pair atomically"
    );
}

#[test]
fn rotation_purges_shared_promote_id_zero_when_zone_vanishes_10510() {
    let purged = rotate_with_metadata(&[rule("p-first", 0), rule("p-web", 1)], false, &[], Some(3));
    assert!(
        purged.first_forward && purged.first_reverse,
        "a bound policy session must survive when its policy remains"
    );
    assert!(
        !purged.unbound,
        "a SharedPromote unbound id-0 session stamped with the vanished zone must purge"
    );
}

/// T1→T2 (round-1 A-(d)6): retain at T1 via extensive rematch + ancestry,
/// then delete the destination rule at T2 with no ancestry — both halves
/// must purge. A single-rotation test cannot distinguish "retained, then
/// correctly purged" from "never retained" or "retained forever", and the
/// single-rotation missing-destination cell above only covers a destination
/// that never existed.
#[test]
fn extensive_retain_then_delete_purges_both_halves_t1_t2_10511() {
    let ancestry = crate::protocol::PolicyRenameAncestry {
        source_rule_id: "lan->wan/p-first".to_string(),
        destination_rule_id: "dmz->wan/p-new".to_string(),
        source_from_zone: "lan".to_string(),
        source_to_zone: "wan".to_string(),
        destination_from_zone: "dmz".to_string(),
        destination_to_zone: "wan".to_string(),
        source_from_zone_id: 1,
        source_to_zone_id: 2,
        destination_from_zone_id: 3,
        destination_to_zone_id: 2,
        source_from_zone_any: false,
        source_to_zone_any: false,
        destination_from_zone_any: false,
        destination_to_zone_any: false,
    };
    let harness = RotationHarness::start();
    harness.publish(
        2,
        &[rule_with_zones("p-new", 0, "dmz", "wan"), rule("p-web", 1)],
        true,
        &[ancestry],
        None,
    );
    let retained = harness.presence();
    // T1 must rebind with the full new identity (same assertions as the
    // single-rotation extensive cell): presence alone would also pass if the
    // pair survived un-rebound with stale counters and zones.
    let forward = retained
        .first_forward_entry
        .as_ref()
        .expect("T1 must retain the forward half via the extensive rebind");
    let reverse = retained
        .first_reverse_entry
        .as_ref()
        .expect("T1 must retain the reverse half via the extensive rebind");
    assert_eq!(forward.metadata.policy_id, 0);
    assert_eq!(reverse.metadata.policy_id, 0);
    assert_eq!(forward.metadata.policy_counter_idx, 1);
    assert_eq!(reverse.metadata.policy_counter_idx, 1);
    let forward_counter = forward
        .metadata
        .policy_counter
        .as_ref()
        .expect("T1 forward half must carry the new counter Arc");
    let reverse_counter = reverse
        .metadata
        .policy_counter
        .as_ref()
        .expect("T1 reverse half must carry the new counter Arc");
    assert_eq!(forward_counter.rule_id(), "dmz->wan/p-new");
    assert_eq!(reverse_counter.rule_id(), "dmz->wan/p-new");
    assert!(Arc::ptr_eq(forward_counter, reverse_counter));
    assert!(
        !Arc::ptr_eq(
            forward_counter,
            retained
                .old_first_counter
                .as_ref()
                .expect("fixture must expose the old counter"),
        ),
        "T1 must replace, not reuse, the old policy counter Arc"
    );
    assert_eq!(forward.metadata.ingress_zone, 3);
    assert_eq!(reverse.metadata.ingress_zone, 2);
    assert_eq!(forward.metadata.egress_zone, 2);
    assert_eq!(reverse.metadata.egress_zone, 3);
    // T2 drops the ancestry along with the destination rule: there is no
    // provenance to honor, so the T1-retained pair must tear down rather
    // than linger as an orphan bound to a deleted rule.
    harness.publish(3, &[rule("p-web", 0)], true, &[], None);
    let purged = harness.presence();
    assert!(
        purged.first_forward_entry.is_none() && purged.first_reverse_entry.is_none(),
        "T2 deleting the destination rule must purge the T1-retained pair atomically"
    );
    assert!(
        purged.unbound,
        "T2 must not touch the unrelated unbound id-0 row"
    );
    harness.shutdown();
}

/// Selectivity control for the removed-zone purge: with zone 3 removed, the
/// zone-3 unbound id-0 row purges while an otherwise identical unbound id-0
/// row stamped with surviving zones 1/2 is retained. Without the zone-set
/// predicate the purge would take both; without the purge it would take
/// neither.
#[test]
fn rotation_purge_keeps_unbound_id_zero_outside_the_removed_set_10510() {
    let survivor_key = key(40005);
    let mut survivor = entry(survivor_key.clone(), false, None);
    survivor.metadata.ingress_zone = 1;
    survivor.metadata.egress_zone = 2;
    survivor.origin = SessionOrigin::SharedPromote;
    let harness = RotationHarness::start_with_extra(std::slice::from_ref(&survivor));
    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    let purged = harness.presence();
    assert!(
        !purged.unbound,
        "the removed-zone unbound id-0 row must purge"
    );
    assert!(
        harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&survivor_key),
        "an unbound id-0 row outside the removed set must survive the purge"
    );
    harness.shutdown();
}

/// #10588 (N1): the nonzero-policy arm. A forward, unbound, SharedPromote row
/// stamped with the removed zone 3 must SURVIVE the purge when its policy_id
/// is nonzero — only the `policy_id != 0` exemption saves it (Z=true, S=true,
/// R=false, B=false). The zone-3 unbound id-0 control must still purge, so
/// the cell cannot pass vacuously when the purge is omitted.
#[test]
fn rotation_purge_keeps_nonzero_policy_id_when_zone_vanishes_10588() {
    let survivor_key = key(40006);
    let mut survivor = entry(survivor_key.clone(), false, None);
    survivor.metadata.policy_id = 1;
    survivor.metadata.ingress_zone = 3;
    survivor.metadata.egress_zone = 2;
    survivor.origin = SessionOrigin::SharedPromote;
    let harness = RotationHarness::start_with_extra(std::slice::from_ref(&survivor));
    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    let purged = harness.presence();
    assert!(
        !purged.unbound,
        "the removed-zone unbound id-0 row must purge"
    );
    assert!(
        purged.first_forward && purged.first_reverse,
        "a bound policy session must survive when its policy remains"
    );
    assert!(
        harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&survivor_key),
        "a nonzero-policy row stamped with the removed zone must survive the purge"
    );
    harness.shutdown();
}

/// #10588 (R1): the reverse arm. A reverse, unbound, id-0, SharedPromote row
/// stamped with the removed zone 3 must SURVIVE the purge — only the
/// `is_reverse` exemption saves it (Z=true, S=true, N=false, B=false).
/// Forward owns the pair; the purge must never take a reverse half directly.
#[test]
fn rotation_purge_keeps_reverse_when_zone_vanishes_10588() {
    let survivor_key = key(40007);
    let mut survivor = entry(survivor_key.clone(), true, None);
    survivor.metadata.policy_id = 0;
    survivor.metadata.ingress_zone = 3;
    survivor.metadata.egress_zone = 2;
    survivor.origin = SessionOrigin::SharedPromote;
    let harness = RotationHarness::start_with_extra(std::slice::from_ref(&survivor));
    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    let purged = harness.presence();
    assert!(
        !purged.unbound,
        "the removed-zone unbound id-0 row must purge"
    );
    assert!(
        purged.first_forward && purged.first_reverse,
        "a bound policy session must survive when its policy remains"
    );
    assert!(
        harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&survivor_key),
        "a reverse row stamped with the removed zone must survive the purge"
    );
    harness.shutdown();
}

/// #10588 (B1): the bound arm. A forward, bound (`policy_counter.is_some()`),
/// id-0, peer-synced row stamped with the removed zone 3 must SURVIVE the
/// purge — only the bound exemption saves it (Z=true, S=true, N=false,
/// R=false). This pins the rebind/purge disjointness: rebind owns bound
/// rows, the removed-zone purge owns unbound id-0 rows.
#[test]
fn rotation_purge_keeps_bound_when_zone_vanishes_10588() {
    let survivor_key = key(40008);
    let fixture = policy(&[rule("p-first", 0), rule("p-web", 1)]);
    let counter = fixture
        .hit_counter_by_idx(1)
        .cloned()
        .expect("fixture policy must expose the first rule counter");
    let mut survivor = entry(survivor_key.clone(), false, Some(counter));
    survivor.metadata.policy_id = 0;
    survivor.metadata.ingress_zone = 3;
    survivor.metadata.egress_zone = 2;
    survivor.origin = SessionOrigin::SyncImport;
    let harness = RotationHarness::start_with_extra(std::slice::from_ref(&survivor));
    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    let purged = harness.presence();
    assert!(
        !purged.unbound,
        "the removed-zone unbound id-0 row must purge"
    );
    assert!(
        purged.first_forward && purged.first_reverse,
        "a bound policy session must survive when its policy remains"
    );
    let map = harness.synced.lock().expect("shared synced map");
    let kept = map
        .get(&survivor_key)
        .expect("a bound row stamped with the removed zone must survive the purge");
    assert!(
        kept.metadata.policy_counter.is_some(),
        "the surviving bound row must still carry its policy counter"
    );
    drop(map);
    harness.shutdown();
}
/// #10589 joint: bind the demoted-owner CLOSE precondition to a real
/// failover-before-rename worker rotation. Leg A's paired Go cell proves that
/// the demoted owner emits no CLOSE delete; this shared helper drives the
/// receiver's independent leg through failover, rename, and purge. The normal
/// #10589 test below runs Steps 1-2 green; the #10612 repro runs only
/// the post-purge stale replay (un-ignored by the #10612 fix).
struct JointRotationSetup {
    harness: RotationHarness,
    stale_victim: SyncedSessionEntry,
}

fn setup_failover_before_rename_joint_10589() -> JointRotationSetup {
    let survivor_key = key(40009);
    let mut survivor = entry(survivor_key.clone(), false, None);
    survivor.metadata.ingress_zone = 1;
    survivor.metadata.egress_zone = 2;
    survivor.origin = SessionOrigin::SharedPromote;

    let bound_key = key(40010);
    let bound_counter = policy(&[rule("p-first", 0), rule("p-web", 1)])
        .hit_counter_by_idx(1)
        .cloned()
        .expect("fixture policy must expose the first-rule counter");
    let mut bound = entry(bound_key.clone(), false, Some(bound_counter));
    bound.metadata.ingress_zone = 3;
    bound.metadata.egress_zone = 2;
    bound.origin = SessionOrigin::SyncImport;

    let harness = RotationHarness::start_for_failover(&[survivor, bound]);
    let stale_victim = harness
        .synced
        .lock()
        .expect("shared synced map")
        .get(&harness.unbound)
        .cloned()
        .expect("joint victim must be installed");
    assert_eq!(stale_victim.origin, SessionOrigin::SyncImport);
    let (found, replica) = harness.query_worker_presence(&harness.unbound, 1);
    assert!(found, "failover victim must be present before promotion");
    assert!(replica, "pre-failover victim must remain peer-synced");

    // FAILOVER before the rename: the queue-driven republish is the
    // harness's fallback for the production packet-side promoter.
    harness.promote_unbound_for_failover();
    let (found, replica) = harness.query_worker_presence(&harness.unbound, 2);
    assert!(found, "failover promotion must retain the victim");
    assert!(
        !replica,
        "promoted victim must be SharedPromote, not peer-synced"
    );
    let promoted = harness
        .synced
        .lock()
        .expect("shared synced map")
        .get(&harness.unbound)
        .cloned()
        .expect("promoted victim must remain authoritative");
    assert_eq!(promoted.origin, SessionOrigin::SharedPromote);
    assert!(
        promoted.metadata.policy_counter.is_none(),
        "failover victim must remain unbound"
    );
    assert_eq!(promoted.metadata.policy_id, 0);
    assert_eq!(promoted.metadata.ingress_zone, 3);
    assert_eq!(promoted.metadata.egress_zone, 2);

    assert!(
        harness.channel.load().forwarding().zone_set_validated,
        "joint setup must begin with a validated old zone set"
    );

    // RENAME rotation: p-first survives, but zone 3 disappears. Both the old
    // fixture generation and this new generation are explicitly validated;
    // the positive removed-set contract must not be silently weakened.
    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    let current_view = harness.channel.load();
    assert!(
        current_view.forwarding().zone_set_validated,
        "joint rotation must publish a validated new zone set"
    );
    assert!(
        !current_view.forwarding().zone_id_to_name.contains_key(&3),
        "joint rename must remove zone 3 from the new generation"
    );
    let rotated = harness.presence();
    assert!(
        !rotated.unbound,
        "the failover-promoted, owner-absent id-0 victim must purge"
    );
    assert!(
        rotated.first_forward && rotated.first_reverse,
        "the bound first-policy pair must survive the zone purge"
    );
    let map = harness.synced.lock().expect("shared synced map");
    assert!(
        map.contains_key(&survivor_key),
        "the unbound id-0 survivor outside the removed set must remain"
    );
    let kept_bound = map
        .get(&bound_key)
        .expect("the bound control stamped with zone 3 must survive");
    assert!(
        kept_bound.metadata.policy_counter.is_some(),
        "the bound control must retain its policy counter"
    );
    drop(map);
    let (found, _) = harness.query_worker_presence(&harness.unbound, 3);
    assert!(
        !found,
        "the receiver worker must remove the purged victim, not only its shared row"
    );

    JointRotationSetup {
        harness,
        stale_victim,
    }
}

/// #10589 GREEN cell: failover-before-rename purges the promoted, unbound
/// id-0 row while retaining the outside-set and bound controls.
#[test]
fn failover_before_rename_joint_purges_10589() {
    let setup = setup_failover_before_rename_joint_10589();
    setup.harness.shutdown();
}

/// #10612 repro pin (UN-IGNORED by the fix): `replay_unbound` reinserts the
/// purged victim into the shared map and queues
/// `WorkerCommand::UpsertSynced` after rotation; the stale-replay fence must
/// refuse it on both authorities. Fails pre-fix (resurrection), green post-fix.
#[test]
fn failover_before_rename_joint_stale_replay_does_not_resurrect_10612() {
    let setup = setup_failover_before_rename_joint_10589();
    let harness = setup.harness;

    // NO-RESURRECTION replay: model a late stale import through both
    // authoritative shared state and the worker command queue. The delete
    // contract requires the purged key to remain absent after the replay.
    harness.replay_unbound(setup.stale_victim);
    let (found, _) = harness.query_worker_presence(&harness.unbound, 4);
    assert!(
        !found,
        "a stale replay must not resurrect the removed-zone victim"
    );
    assert!(
        !harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&harness.unbound),
        "a stale replay must not restore shared authority for the purged victim"
    );
    harness.shutdown();
}

/// #10612: a pre-rotation shared snapshot replayed after the real zone purge
/// must not restore either authority. This is intentionally an independent
/// reproduction complementing the joint repro cell: it drives the real worker
/// loop but re-publishes the stale row itself through the shared map and queue.
///
/// FAIL-ON-REVERT: removing the worker fence leaves `found=true`; removing the
/// conditional shared eviction leaves the shared-map assertion fail.
#[test]
fn stale_removed_zone_replay_does_not_resurrect_10612() {
    let harness = RotationHarness::start();
    let stale = harness
        .synced
        .lock()
        .expect("shared synced map")
        .get(&harness.unbound)
        .cloned()
        .expect("the pre-rotation victim must be installed");

    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    assert!(
        !harness.presence().unbound,
        "the rotation purge must remove the old removed-zone victim first"
    );

    harness.replay_unbound(stale);
    assert!(
        !harness.query_worker_presence(&harness.unbound, 10612).0,
        "a stale post-purge replay must not resurrect the worker row"
    );
    assert!(
        !harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&harness.unbound),
        "a stale post-purge replay must not restore shared authority"
    );
    harness.shutdown();
}

/// #10612 (N4): a stale REVERSE replay must not resurrect either authority.
/// The predicate judges reverses by zone membership (no exemption); this cell
/// pins the worker-level integrated behavior for the reverse half (the
/// forward half is pinned above; unit + filter levels pin the parts).
/// Fails pre-M2 (standalone stale reverse installed).
#[test]
fn stale_removed_zone_reverse_replay_does_not_resurrect_10612() {
    let harness = RotationHarness::start();
    let stale = harness
        .synced
        .lock()
        .expect("shared synced map")
        .get(&harness.unbound)
        .cloned()
        .expect("the pre-rotation victim must be installed");

    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    assert!(
        !harness.presence().unbound,
        "the rotation purge must remove the old removed-zone victim first"
    );

    let reverse_key =
        crate::session::reverse_session_key(&harness.unbound, stale.decision.nat);
    let mut reversed = stale;
    reversed.key = reverse_key.clone();
    reversed.metadata.is_reverse = true;
    harness.replay_unbound(reversed);
    assert!(
        !harness.query_worker_presence(&reverse_key, 10614).0,
        "a stale post-purge reverse replay must not resurrect the worker row"
    );
    assert!(
        !harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&reverse_key),
        "a stale post-purge reverse replay must not restore shared authority"
    );
    harness.shutdown();
}

/// #10612 live pin: an unbound id-0 replay whose zones are still current
/// must install through BOTH authorities — the fence drops only the
/// removed-zone shape, never live rows or rotation survivors.
///
/// FAIL-ON-REVERT (inverted): a mis-scoped fence (e.g. dropping every
/// unbound id-0 replay) evicts this row from shared authority and the
/// worker table alike.
#[test]
fn live_unbound_replay_still_installs_after_rotation_10612() {
    let live_key = key(40005);
    let live = entry(live_key.clone(), false, None);
    let harness = RotationHarness::start_with_extra(std::slice::from_ref(&live));

    harness.publish(
        2,
        &[rule("p-first", 0), rule("p-web", 1)],
        false,
        &[],
        Some(3),
    );
    assert!(
        harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&live_key),
        "the current-zone unbound row must survive the rotation purge"
    );

    let replay = harness
        .synced
        .lock()
        .expect("shared synced map")
        .get(&live_key)
        .cloned()
        .expect("the surviving row must be replayable");
    harness.replay_unbound(replay);
    assert!(
        harness.query_worker_presence(&live_key, 10613).0,
        "a current-zone replay must keep the worker row installed"
    );
    assert!(
        harness
            .synced
            .lock()
            .expect("shared synced map")
            .contains_key(&live_key),
        "a current-zone replay must keep shared authority"
    );
    harness.shutdown();
}
