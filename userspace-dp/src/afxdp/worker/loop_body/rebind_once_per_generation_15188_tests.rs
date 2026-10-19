// #15188 (C08-02): a worker must consume a generation's single-use
// `policy_session_rebinds` exactly once. Helper-internal republishes
// (neighbor push, HA fabric refresh) rotate the worker-visible forwarding
// Arc without advancing the config generation; before the fix the worker's
// rotation branch re-ran `rebind_policy_sessions_from_snapshot` over the
// full record list on every such rotation — an unbudgeted per-record
// restamp walk (two BPF conntrack restamps plus shared-table restamps per
// record) with no generation check.
//
// These cells drive the REAL worker loop (empty plan, BusyPoll, every map
// fd -1, so restamps report success and state stays observable in the
// shared map), exactly like the #9526 rotation harness:
//
//   gen 7  — worker starts on the pre-rename policy (`p-first` bound pair).
//   gen 8  — full apply: renamed rule + one rebind record for the pair.
//            The pair must rebind to the new rule (control).
//   gen 8' — helper republish: SAME config generation, same rebind record
//            still carried (the pre-fix helper shape). The worker rotates
//            but must NOT re-apply the record: the pair keeps the identity
//            the first consumption installed. RED on pre-fix code: the
//            second rotation restamps the pair again — observable because
//            the fixture rewrites the record's zones between the two
//            publishes, so a re-application moves the pair's zones.
//   gen 9  — next full apply with a fresh record: consumed normally.
//
// The zone-rewrite probe is what makes "applied exactly once" observable
// without a BPF map: `rebind_policy_pair` restamps zones from the record,
// so a second application with different zones is directly visible on the
// shared-map entries.
use super::*;
use crate::afxdp::bpf_map::clear_restamp_attempts;
use crate::policy::{PolicyCounterStore, PolicyState, parse_policy_state_with_counters};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn rule(name: &str, policy_id: u32, from_zone: &str, to_zone: &str) -> crate::PolicyRuleSnapshot {
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

fn forwarding(
    generation: u64,
    rules: &[crate::PolicyRuleSnapshot],
    rebinds: Vec<crate::protocol::PolicySessionRebind>,
) -> Arc<ForwardingState> {
    let mut forwarding = ForwardingState::default();
    forwarding.config_generation = generation;
    forwarding.policy = policy(rules);
    forwarding.policy_rematch_extensive = true;
    forwarding.policy_rename_ancestry = vec![crate::protocol::PolicyRenameAncestry {
        source_rule_id: "lan->wan/p-first".to_string(),
        destination_rule_id: "dmz->wan/p-new".to_string(),
        source_from_zone: "lan".to_string(),
        source_to_zone: "wan".to_string(),
        destination_from_zone: "lan".to_string(),
        destination_to_zone: "wan".to_string(),
        source_from_zone_id: 1,
        source_to_zone_id: 2,
        destination_from_zone_id: 1,
        destination_to_zone_id: 2,
        ..Default::default()
    }];
    forwarding.policy_session_rebinds = rebinds;
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.zone_name_to_id.insert("dmz".to_string(), 3);
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.zone_set_validated = true;
    forwarding.ingress_logical_ifindex.insert((11, 0), 11);
    forwarding.ifindex_to_zone_id.insert(11, 1);
    forwarding.ifindex_to_zone_id.insert(12, 2);
    Arc::new(forwarding)
}

fn view(generation: u64, forwarding: Arc<ForwardingState>) -> Arc<RuntimeView> {
    Arc::new(RuntimeView::new(
        // runtime-view-canary: test-local
        ValidationState {
            snapshot_installed: true,
            config_generation: generation,
            fib_generation: generation as u32,
        },
        forwarding,
    ))
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

fn entry(key: SessionKey, is_reverse: bool, counter: Option<Arc<crate::policy::PolicyRuleCounter>>) -> SyncedSessionEntry {
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
            ingress_ifindex: 11,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
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
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        pptp_call_ids: 0,
        source_nat_static: None,
    }
}

fn record(ingress_zone: u16, egress_zone: u16) -> crate::protocol::PolicySessionRebind {
    let fwd = key(40001);
    crate::protocol::PolicySessionRebind {
        family: "v4".to_string(),
        src_ip: fwd.src_ip.to_string(),
        dst_ip: fwd.dst_ip.to_string(),
        src_port: fwd.src_port,
        dst_port: fwd.dst_port,
        protocol: fwd.protocol,
        routing_domain: 0,
        policy_id: 0,
        rule_id: "dmz->wan/p-new".to_string(),
        ingress_zone,
        egress_zone,
        tunnel_discriminator: 0,
    }
}

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

struct Harness {
    channel: RuntimeViewChannel,
    synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
    fwd: SessionKey,
    rev: SessionKey,
}

impl Harness {
    fn start() -> Self {
        clear_restamp_attempts();
        let coord = Coordinator::new();
        let channel = RuntimeViewChannel::default();
        let old_rules = [rule("p-first", 0, "lan", "wan"), rule("p-web", 1, "lan", "wan")];
        let old_forwarding = forwarding(7, &old_rules, Vec::new());
        let first_counter = old_forwarding.policy.hit_counter_by_idx(1).cloned();
        assert_eq!(
            first_counter.as_ref().map(|c| c.rule_id()),
            Some("lan->wan/p-first"),
            "fixture: counter idx 1 is the first rule's handle"
        );
        channel.publish(view(7, old_forwarding));

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
            Arc::new(WorkerCommandQueues::new(BTreeMap::new())),
            stop.clone(),
            heartbeat.clone(),
            Arc::new(AtomicU64::new(0)),
            Arc::new(crate::afxdp::binding_state::ExportBufferState::new()),
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

        let fwd = key(40001);
        let rev = reverse_session_key(&fwd, NatDecision::default());
        let entries = vec![
            entry(fwd.clone(), false, first_counter.clone()),
            entry(rev.clone(), true, first_counter),
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
        Self { channel, synced, stop, heartbeat, worker: Some(worker), fwd, rev }
    }

    fn publish(&self, generation: u64, fwd: Arc<ForwardingState>) {
        self.channel.publish(view(generation, fwd));
        wait_for_iterations(&self.heartbeat, 3);
    }

    fn zones(&self) -> ((u16, u16), (u16, u16)) {
        let map = self.synced.lock().expect("shared synced map");
        let f = map.get(&self.fwd).expect("forward half must survive every rotation");
        let r = map.get(&self.rev).expect("reverse half must survive every rotation");
        (
            (f.metadata.ingress_zone, f.metadata.egress_zone),
            (r.metadata.ingress_zone, r.metadata.egress_zone),
        )
    }

    fn counter_rule_id(&self) -> Option<String> {
        let map = self.synced.lock().expect("shared synced map");
        map.get(&self.fwd)
            .and_then(|e| e.metadata.policy_counter.as_ref().map(|c| c.rule_id().to_string()))
    }

    fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("the worker loop exits cleanly on stop");
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[test]
fn rebind_record_applied_exactly_once_per_generation_15188() {
    let harness = Harness::start();
    let new_rules = [rule("p-new", 0, "dmz", "wan"), rule("p-web", 1, "lan", "wan")];

    // Full apply (gen 8): the record rebinds the pair to dmz->wan/p-new.
    harness.publish(8, forwarding(8, &new_rules, vec![record(3, 2)]));
    assert_eq!(harness.counter_rule_id().as_deref(), Some("dmz->wan/p-new"), "control: the full apply's record must rebind the pair");
    assert_eq!(harness.zones(), ((3, 2), (2, 3)), "control: first consumption stamps the record's zones");

    // Helper republish (still gen 8, record still carried — the pre-fix
    // shape — but with different zones as the re-application probe). The
    // worker rotates to a new forwarding Arc; it must NOT re-apply.
    harness.publish(8, forwarding(8, &new_rules, vec![record(1, 2)]));
    assert_eq!(
        harness.zones(),
        ((3, 2), (2, 3)),
        "#15188: a same-generation republish must not re-apply the single-use rebind record"
    );
    assert_eq!(harness.counter_rule_id().as_deref(), Some("dmz->wan/p-new"));

    // Next full apply (gen 9) with a fresh record: consumed normally.
    harness.publish(9, forwarding(9, &new_rules, vec![record(1, 2)]));
    assert_eq!(
        harness.zones(),
        ((1, 2), (2, 1)),
        "control: the next generation's fresh record must be consumed"
    );
    harness.shutdown();
}
