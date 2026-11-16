// #18552: a worker promotion and a late peer import of the same 5-tuple must
// serialize on the tuple gate.
//
// The coordinator's #9678 gate (`upsert_synced_session_with_policy_inner`)
// stops a peer import that would replace a LOCAL row while the owner RG is
// locally forwarding-active. It reads only the SHARED row. A worker promotion
// (`promote_synced_session_with_conntrack`) flips its own table row to
// `SharedPromote` first and publishes the shared row afterwards, so an import
// that runs in between still sees the older peer row and proceeds:
//
// * `reserve_flow` retires the flow's live allocation T1, because the late row
//   names a different translation, while the worker keeps forwarding on T1;
// * the late row's synthesized reverse companion is published and installed,
//   so a reply tuple no live session owns is steered;
// * the stale-companion retirement deletes the promoted session's own reply
//   companion.
//
// The fix holds the worker install permit (`try_acquire_installs`) across the
// promotion's flip and shared publish, the way the new-flow install does.
//
// Fixture realism (docs/log/18552.md has the reachability argument). The T1
// reservation is seeded through the production import and worker drain, not
// by hand. The late row is a LATER send from the same peer: generation 9 over
// the stored 7, so the #2170 stale-generation refusal does not apply (the peer
// stamps every send from one climbing counter). It also carries a different
// RT_FLOW session id and a different translated port, as a new incarnation of
// a reused 5-tuple on the old owner would.

use super::*;
use crate::afxdp::bpf_map::{
    CONNTRACK_TEST_MAP_FD, ConntrackPublishRecord, ConntrackPublishResult, RECORDER_ONLY_MAP_FD,
    SteeringMap, adopt_tuple_gate_for_test, clear_conntrack_rows_for_test,
    clear_session_map_writes, conntrack_row_for_test, global_tuple_gate,
    insert_conntrack_test_row, session_map_writes,
};
use crate::afxdp::session_glue::{
    ConntrackFds, SessionHitVerdict, SharedSessionRefs, Tick,
    maybe_promote_synced_session_with_conntrack, set_promote_after_flip_hook_for_test,
    set_promote_before_fanout_hook_for_test,
};
use crate::afxdp::testfx::{test_forwarding_state, test_metadata, test_resolution};
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

const RG: i32 = 1;
/// T1: the translation of the incarnation this node holds and promotes.
const LOCAL_PORT: u16 = 40_002;
/// T2: the late peer row's different translation.
const LATE_PORT: u16 = 40_001;
const SEED_GENERATION: u64 = 7;
const LATE_GENERATION: u64 = 9;
const SEED_SESSION_ID: u64 = 0x1855_2001;
const LATE_SESSION_ID: u64 = 0x1855_2002;
/// Bounds the cross-thread rendezvous so a broken fixture fails loudly
/// instead of hanging the suite. Never a pass criterion.
const RENDEZVOUS_BOUND: Duration = Duration::from_secs(10);

fn active_rg(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn pool_v4() -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, 1)
}

fn pool_v6() -> Ipv6Addr {
    "2001:db8:1855:2::1".parse().expect("pool v6")
}

/// The #18550 LAN/WAN topology (RG 1 owns both egress rows) plus one
/// single-address source-NAT pool per family, so the allocator tracks the
/// translation and a freed T1 is observable.
fn forwarding() -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    if let Some(wan) = forwarding.egress.get_mut(&12) {
        wan.primary_v6 = Some("2001:559:8585:80::8".parse().expect("wan v6"));
    }
    if let Some(lan) = forwarding.egress.get_mut(&6) {
        lan.primary_v6 = Some("2001:559:8585:ef00::1".parse().expect("lan v6"));
    }
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "pool-snat-v4".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "p4".to_string(),
            pool_addresses: vec![format!("{}/32", pool_v4())],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "pool-snat-v6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            pool_name: "p6".to_string(),
            pool_addresses: vec![format!("{}/128", pool_v6())],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding
}

fn snat(v6: bool, port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some(if v6 { IpAddr::V6(pool_v6()) } else { IpAddr::V4(pool_v4()) }),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

fn flow_key(v6: bool, client_host: u8, src_port: u16) -> SessionKey {
    let (family, src, dst) = if v6 {
        (
            libc::AF_INET6 as u8,
            IpAddr::V6(format!("2001:559:8585:ef00::{client_host:x}").parse().expect("client v6")),
            IpAddr::V6("2001:559:8585:80::200".parse().expect("server v6")),
        )
    } else {
        (
            libc::AF_INET as u8,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, client_host)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        )
    };
    SessionKey {
        addr_family: family,
        protocol: PROTO_TCP,
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A peer-synced forward row for the client flow, pool-SNAT'd on `snat_port`.
fn peer_row(v6: bool, snat_port: u16, generation: u64, session_id: u64) -> SyncedSessionEntry {
    let mut metadata = test_metadata();
    metadata.owner_rg_id = RG;
    SyncedSessionEntry {
        sibling_last_seen_ns: 0,
        last_served_ns: 0,
        key: flow_key(v6, 102, 55_068),
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: snat(v6, snat_port),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

struct Fixture {
    v6: bool,
    coordinator: Coordinator,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    /// A sibling worker's command queue, handed to the promotion as its
    /// fan-out target (review F4b): `replicate_session_upsert` pushes the
    /// promoted row here, so a cell can observe whether and when it did.
    sibling: Arc<Mutex<VecDeque<WorkerCommand>>>,
    worker_sessions: crate::session::SessionTable,
    ha_state: BTreeMap<i32, HAGroupRuntime>,
    /// The incarnation this node holds (T1 = LOCAL_PORT).
    original: SyncedSessionEntry,
    /// The later peer send for the same 5-tuple (T2 = LATE_PORT).
    late: SyncedSessionEntry,
}

impl Fixture {
    fn key(&self) -> SessionKey {
        self.original.key.clone()
    }

    /// The promoted session's own reply companion.
    fn local_reply(&self) -> SessionKey {
        reverse_session_key(&self.original.key, self.original.decision.nat)
    }

    /// The reply tuple only the late row's translation names.
    fn late_reply(&self) -> SessionKey {
        reverse_session_key(&self.late.key, self.late.decision.nat)
    }

    fn shared(&self, key: &SessionKey) -> Option<SyncedSessionEntry> {
        crate::afxdp::shared_ops::lock_shared_recover(&self.coordinator.sessions.synced)
            .get(key)
            .cloned()
    }

    fn worker_origin(&self, key: &SessionKey) -> Option<(NatDecision, SessionOrigin)> {
        self.worker_sessions
            .entry_with_origin(key)
            .map(|(decision, _, origin)| (decision.nat, origin))
    }

    fn drain_worker(&mut self) {
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut scratch = VecDeque::new();
        let _ = crate::afxdp::session_glue::apply_worker_commands(
            &self.commands,
            &mut self.worker_sessions,
            SteeringMap::unshared_for_test(RECORDER_ONLY_MAP_FD),
            -1,
            -1,
            &self.coordinator.forwarding,
            &self.ha_state,
            &dynamic_neighbors,
            0,
            &mut scratch,
        );
    }

    /// True when a DIFFERENT flow can reserve `pool_port`, i.e. nothing live
    /// holds it. A successful probe takes the port, so each probe uses its
    /// own client and is the last word on that port in its cell.
    fn port_is_free(&self, probe_host: u8, pool_port: u16) -> bool {
        crate::nat::reserve_synced_source_nat_allocation_untracked(
            &self.coordinator.forwarding.iface_nat_allocators,
            &self.coordinator.forwarding.source_nat_rules,
            &flow_key(self.v6, probe_host, 41_000),
            snat(self.v6, pool_port),
            false,
            None,
            monotonic_nanos(),
            crate::nat::SyncedSourceNatDomains::default(),
        )
    }

    fn conntrack_peer_synced(&self) -> Option<bool> {
        conntrack_row_for_test(&self.key()).map(|row| row.cluster_synced)
    }

    /// One owner-verdict packet hit on the promotable row: the deferred
    /// promotion `resolve.rs` arms on every non-transient synced hit, applied
    /// through the production entry point with the conntrack test map wired.
    fn promote_on_hit(&mut self) {
        let row = self.original.clone();
        let forwarding = self.coordinator.forwarding.clone();
        self.promote_row_on_hit(&row, &forwarding);
    }

    /// As `promote_on_hit`, for the worker's row of `row`'s incarnation, under
    /// `forwarding`. The promotion fans out to the sibling queue.
    fn promote_row_on_hit(&mut self, row: &SyncedSessionEntry, forwarding: &ForwardingState) {
        let now_ns = monotonic_nanos();
        let key = row.key.clone();
        let decision = row.decision;
        let metadata = row.metadata.clone();
        let mut resolved = ResolvedFlowSessionDecision {
            key: key.clone(),
            session_id: row.session_id,
            timeout_secs: 300,
            decision,
            source_nat_static: None,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            source_nat_validation_key: None,
            created: false,
            install_failed: false,
            authority_deferred: false,
            deferred_forwarding_revalidation: None,
            promotion_deferred: false,
            deferred_synced_promotion: Some(DeferredSyncedPromotion {
                key,
                decision,
                metadata,
                origin: SessionOrigin::SyncImport,
                fabric_ingress: false,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
                now_ns,
                ack: None,
            }),
            deferred_shared_materialization: None,
            deferred_synced_purge: None,
            fabric_adopted: false,
        };
        let siblings = vec![Arc::clone(&self.sibling)];
        maybe_promote_synced_session_with_conntrack(
            &mut self.worker_sessions,
            SteeringMap::unshared_for_test(RECORDER_ONLY_MAP_FD),
            SharedSessionRefs {
                sessions: &self.coordinator.sessions.synced,
                nat_sessions: &self.coordinator.sessions.nat,
                forward_wire_sessions: &self.coordinator.sessions.forward_wire,
                owner_rg_indexes: &self.coordinator.sessions.owner_rg_indexes,
                peer_worker_commands: &siblings,
                worker_commands_by_id: empty_worker_commands_by_id(),
                conntrack: ConntrackFds {
                    v4: CONNTRACK_TEST_MAP_FD,
                    v6: CONNTRACK_TEST_MAP_FD,
                },
                tick: Tick::from_ns(now_ns),
            },
            forwarding,
            &self.ha_state,
            0x10,
            0,
            SessionHitVerdict::Owner,
            &mut resolved,
            &mut Vec::new(),
        );
    }

    /// One owner-verdict REPLY hit on the promotable reverse companion of the
    /// original incarnation. The owner reply re-resolves to the client's local
    /// LAN egress (ifindex 6), as `resolve.rs` does before arming the deferred
    /// promotion; the promotion then runs under `self.ha_state`.
    fn promote_reply_on_hit(&mut self) {
        let reply = self.local_reply();
        let mut row = self
            .worker_sessions
            .synced_entry_for(&reply)
            .expect("premise: the worker holds the reply companion");
        assert!(row.metadata.is_reverse, "premise: the reply row is the reverse companion");
        row.decision.resolution = ForwardingResolution {
            egress_ifindex: 6,
            tx_ifindex: 6,
            next_hop: Some(self.original.key.src_ip),
            ..test_resolution()
        };
        let forwarding = self.coordinator.forwarding.clone();
        self.promote_row_on_hit(&row, &forwarding);
    }

    /// Worker F, worker R, shared F and shared R origins of the original pair.
    fn pair_origins(&self) -> [Option<SessionOrigin>; 4] {
        let (forward, reply) = (self.key(), self.local_reply());
        [
            self.worker_origin(&forward).map(|(_, origin)| origin),
            self.worker_origin(&reply).map(|(_, origin)| origin),
            self.shared(&forward).map(|entry| entry.origin),
            self.shared(&reply).map(|entry| entry.origin),
        ]
    }

    /// The (session id, NAT, origin) the shared row for `key` names.
    fn shared_identity(&self, key: &SessionKey) -> Option<(u64, NatDecision, SessionOrigin)> {
        self.shared(key)
            .map(|entry| (entry.session_id, entry.decision.nat, entry.origin))
    }

    fn sibling_commands(&self) -> usize {
        self.sibling.lock().expect("sibling queue").len()
    }
}

/// Report every broken leg together, so a red run names each one.
fn assert_legs(cell: &str, legs: &[(bool, &str)]) {
    let failed: Vec<&str> = legs
        .iter()
        .filter(|(held, _)| !held)
        .map(|(_, leg)| *leg)
        .collect();
    assert!(failed.is_empty(), "{cell}: broken legs: {failed:#?}");
}

/// One worker, RG 1 forwarding-active on the coordinator and in the worker's
/// HA view, and the original incarnation imported through the production path
/// and drained into the worker: the coordinator's `Untracked` T1 plus the
/// worker's holder bit, the shared forward row and its reverse companion, and
/// a cluster-synced conntrack row (what the Go mirror write leaves).
fn seeded_fixture(v6: bool) -> Fixture {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(RG, active_rg(now_secs))]);
    assert!(
        !crate::afxdp::session_glue::synced_entry_allows_local_replace(&ha_state, RG, now_secs),
        "premise: the fixture must model an ACTIVE owner, where the #9678 gate applies"
    );
    seeded_fixture_in(v6, forwarding(), ha_state)
}

/// As `seeded_fixture`, under `forwarding` and the HA view `ha_state` (the
/// coordinator's and the worker's).
fn seeded_fixture_in(
    v6: bool,
    forwarding: ForwardingState,
    ha_state: BTreeMap<i32, HAGroupRuntime>,
) -> Fixture {
    clear_session_map_writes();
    clear_conntrack_rows_for_test();
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding);
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        crate::afxdp::coordinator::WorkerRuntimeRecord::for_test(WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: commands.clone(),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(super::cold_path_hist::WorkerColdPathAtomics::new()),
        }),
        None,
    );
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    coordinator.ha.rg_runtime.store(Arc::new(ha_state.clone()));
    let original = peer_row(v6, LOCAL_PORT, SEED_GENERATION, SEED_SESSION_ID);
    let late = peer_row(v6, LATE_PORT, LATE_GENERATION, LATE_SESSION_ID);
    let mut fx = Fixture {
        v6,
        coordinator,
        commands,
        sibling: Arc::new(Mutex::new(VecDeque::new())),
        worker_sessions: crate::session::SessionTable::new(),
        ha_state,
        original,
        late,
    };

    assert_eq!(
        fx.coordinator.upsert_synced_session(fx.original.clone()),
        SyncedImportOutcome::Applied,
        "premise: the original incarnation imports"
    );
    fx.drain_worker();
    let key = fx.key();
    assert_eq!(
        fx.worker_origin(&key),
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport)),
        "premise (v6={v6}): the worker holds the original incarnation as a promotable peer row"
    );
    assert!(
        fx.worker_origin(&fx.local_reply()).is_some() && fx.shared(&fx.local_reply()).is_some(),
        "premise (v6={v6}): the original's reply companion is installed and shared"
    );
    assert!(
        !fx.port_is_free(201, LOCAL_PORT),
        "premise (v6={v6}): the import and worker drain must hold T1, or no cell below can \
         observe it being freed"
    );
    assert_ne!(
        fx.late_reply(),
        fx.local_reply(),
        "premise: the late row must name a different translation"
    );
    insert_conntrack_test_row(ConntrackPublishRecord {
        key: key.clone(),
        nat: fx.original.decision.nat,
        is_reverse: false,
        ingress_ifindex: 6,
        ingress_vlan_id: 0,
        ingress_zone: fx.original.metadata.ingress_zone,
        egress_zone: fx.original.metadata.egress_zone,
        app_id: 0,
        session_id: SEED_SESSION_ID,
        cluster_synced: true,
        timeout_secs: 300,
        result: Some(ConntrackPublishResult::Written),
    });
    clear_session_map_writes();
    fx
}

/// The state every window cell owes once the promotion and the late import
/// have both run, whichever way the race went, followed by the peer's retry of
/// the late row and a worker drain. Every leg is checked and the failures are
/// reported together, so a red run names each broken leg, not just the first.
/// Legs 1-7 are the race's consequences. Leg 8 is the `_under_permit` trap:
/// it is green without the permit and red only if the origin RMW goes through
/// `with_publish` under the promotion's own permit.
fn assert_promoted_flow_intact(fx: &Fixture, cell: &str) {
    let v6 = fx.v6;
    let key = fx.key();
    assert_eq!(
        fx.worker_origin(&key),
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
        "{cell} (v6={v6}): premise: the worker forwards the flow as the promoted local session on T1"
    );
    let late_reply = fx.late_reply();
    let local_reply = fx.local_reply();
    let legs = [
        (
            !fx.port_is_free(202, LOCAL_PORT),
            "1: the late import freed T1 while the worker forwards the promoted session on it: \
             the port can be handed to another flow",
        ),
        (
            fx.port_is_free(203, LATE_PORT),
            "2: the late import reserved T2 for a translation no live session uses",
        ),
        (
            fx.shared(&late_reply).is_none(),
            "3: shared authority carries the late row's reverse companion, a reply tuple no \
             live session owns",
        ),
        (
            fx.worker_origin(&late_reply).is_none(),
            "4: the worker installed the late row's reverse companion",
        ),
        (
            !session_map_writes().iter().any(|write| write.key == late_reply),
            "5: the worker steered the late row's reply tuple",
        ),
        (
            fx.shared(&local_reply).is_some(),
            "6: the late import retired the promoted session's reply companion from shared \
             authority",
        ),
        (
            fx.worker_origin(&local_reply).is_some(),
            "7: the late import retired the promoted session's reply companion from the worker",
        ),
        (
            fx.conntrack_peer_synced() == Some(false),
            "8: the promotion left the conntrack row marked peer-synced (an origin RMW through \
             `with_publish` declines under the promotion's own permit)",
        ),
        // Review F4a: shared authority itself names the promoted incarnation.
        (
            fx.shared_identity(&key)
                == Some((SEED_SESSION_ID, snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
            "9: the shared forward row is not the promoted session (origin SharedPromote, \
             translation T1, the original RT_FLOW session id)",
        ),
    ];
    let failed: Vec<&str> = legs
        .iter()
        .filter(|(held, _)| !held)
        .map(|(_, leg)| *leg)
        .collect();
    assert!(failed.is_empty(), "{cell} (v6={v6}): broken legs: {failed:#?}");
}

/// (a) The late import runs INSIDE the promotion's flip..publish window, on the
/// promoting thread, after T1 was seeded through the production path. Without
/// the permit it completes there and frees T1. With it, its lease cannot
/// drain the promotion's install permit and it is refused (`RejectedGateBusy`)
/// within its acquire budget; the peer's retry then meets the published
/// `SharedPromote` row and the #9678 gate.
///
/// Review r23 P3-4: the fix-side outcome here is a same-thread artefact. The
/// import runs on the thread that holds the permit, so it can never drain it
/// and always spends its whole 100 ms budget before `RejectedGateBusy`. No
/// production import runs on a promoting worker. Cell (b) is the real
/// cross-thread interleaving; this cell stays because it is the deterministic
/// master-red form of the window.
fn assert_late_import_inside_window_keeps_t1(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let domain = fx.coordinator.session_domain().clone();
    let late = fx.late.clone();
    let in_window: Rc<RefCell<Option<SyncedImportOutcome>>> = Rc::new(RefCell::new(None));
    let in_window_slot = Rc::clone(&in_window);
    set_promote_after_flip_hook_for_test(move || {
        *in_window_slot.borrow_mut() = Some(domain.upsert_synced_session(late));
    });

    fx.promote_on_hit();

    let in_window = in_window.borrow_mut().take();
    assert!(
        in_window.is_some(),
        "premise (v6={v6}): the promotion never reached its flip..publish window, so the late \
         import never ran inside it"
    );
    // The peer retries a refused import; an applied one is a no-op the second time.
    let _ = fx.coordinator.upsert_synced_session(fx.late.clone());
    fx.drain_worker();
    assert_promoted_flow_intact(&fx, &format!("in-window import (outcome {in_window:?})"));
}

#[test]
fn late_import_inside_promotion_window_keeps_t1_v4_18552() {
    assert_late_import_inside_window_keeps_t1(false);
}

#[test]
fn late_import_inside_promotion_window_keeps_t1_v6_18552() {
    assert_late_import_inside_window_keeps_t1(true);
}

/// (b) The late import runs on ANOTHER thread, started inside the promotion's
/// window. The hook releases the promotion only once the import has either
/// finished (no permit: it ran straight through the window) or is observed
/// parked on the promotion's install permit (`draining` with an install
/// claim held). Both are observed states, not timings, so the interleaving is
/// deterministic. The import thread adopts the promoting thread's tuple gate:
/// under `cfg(test)` each thread otherwise owns its own (#18834).
fn assert_concurrent_import_waits_for_promotion(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let domain = fx.coordinator.session_domain().clone();
    let late = fx.late.clone();
    let key = fx.key();
    let importer: Rc<RefCell<Option<std::thread::JoinHandle<SyncedImportOutcome>>>> =
        Rc::new(RefCell::new(None));
    let parked_on_permit = Rc::new(std::cell::Cell::new(false));
    let importer_slot = Rc::clone(&importer);
    let parked_slot = Rc::clone(&parked_on_permit);
    set_promote_after_flip_hook_for_test(move || {
        let gate = global_tuple_gate();
        let import_gate = Arc::clone(&gate);
        let handle = std::thread::spawn(move || {
            adopt_tuple_gate_for_test(import_gate);
            domain.upsert_synced_session(late)
        });
        let deadline = Instant::now() + RENDEZVOUS_BOUND;
        loop {
            if handle.is_finished() {
                break;
            }
            let probe = gate.probe(&key);
            if probe.state == "draining" && probe.installs > 0 {
                parked_slot.set(true);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the late import neither finished nor parked on the promotion's permit: {probe:?}"
            );
            std::thread::yield_now();
        }
        *importer_slot.borrow_mut() = Some(handle);
    });

    fx.promote_on_hit();

    let handle = importer.borrow_mut().take().expect(
        "premise: the promotion never reached its flip..publish window, so no import raced it",
    );
    let outcome = handle.join().expect("late import thread");
    let _ = fx.coordinator.upsert_synced_session(fx.late.clone());
    fx.drain_worker();
    assert_promoted_flow_intact(
        &fx,
        &format!(
            "concurrent import (outcome {outcome:?}, parked on permit: {})",
            parked_on_permit.get()
        ),
    );
    // Interleaving witness: the legs above hold because the import waited for
    // the promotion, not because it never overlapped it. Under the permit the
    // import can only finish inside the window by exhausting its acquire budget.
    assert!(
        parked_on_permit.get() || outcome == SyncedImportOutcome::RejectedGateBusy,
        "v6={v6}: the late import ran to completion inside the promotion's window \
         (outcome {outcome:?})"
    );
}

#[test]
fn concurrent_late_import_waits_for_promotion_permit_v4_18552() {
    assert_concurrent_import_waits_for_promotion(false);
}

#[test]
fn concurrent_late_import_waits_for_promotion_permit_v6_18552() {
    assert_concurrent_import_waits_for_promotion(true);
}

/// (c) The converse order: a coordinator import (or delete) holds its tuple
/// lease when a packet hits the promotable row. The promotion must not flip
/// the worker row under that lease; it is skipped for this packet, the row
/// stays promotable, and the next hit after the lease drops promotes.
fn assert_promotion_defers_to_import_lease(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let lease = global_tuple_gate()
        .acquire_lease([key.clone(), fx.local_reply()])
        .expect("premise: an idle tuple leases");

    fx.promote_on_hit();

    let (_, origin) = fx.worker_origin(&key).expect("worker row");
    let shared_origin = fx.shared(&key).map(|entry| entry.origin);
    let legs = [
        (
            origin.is_promotable_synced(),
            "1: the promotion flipped the worker row while an import held the tuple lease, the \
             window in which the #9678 gate cannot see it",
        ),
        (
            shared_origin == Some(SessionOrigin::SyncImport),
            "2: the promotion published shared authority under an import's tuple lease",
        ),
    ];
    let failed: Vec<&str> = legs
        .iter()
        .filter(|(held, _)| !held)
        .map(|(_, leg)| *leg)
        .collect();
    assert!(
        failed.is_empty(),
        "v6={v6}: under a held lease (worker {origin:?}, shared {shared_origin:?}): broken legs: \
         {failed:#?}"
    );
    drop(lease);

    fx.promote_on_hit();

    assert_eq!(
        fx.worker_origin(&key),
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
        "v6={v6}: the next hit after the lease dropped must promote"
    );
    assert_eq!(
        fx.shared(&key).map(|entry| entry.origin),
        Some(SessionOrigin::SharedPromote),
        "v6={v6}: the retried promotion must publish shared authority"
    );
    assert_eq!(
        fx.conntrack_peer_synced(),
        Some(false),
        "v6={v6}: the retried promotion must clear the conntrack peer-synced origin bit"
    );
}

#[test]
fn promotion_defers_to_import_lease_and_retries_v4_18552() {
    assert_promotion_defers_to_import_lease(false);
}

#[test]
fn promotion_defers_to_import_lease_and_retries_v6_18552() {
    assert_promotion_defers_to_import_lease(true);
}

// ---------------------------------------------------------------------------
// Review cycle 1 (Codex P1-1..P1-3, r23 P3-1..P3-4, r24 P2-1(b)/P3-1/P3-4).
// ---------------------------------------------------------------------------

/// The state a skipped promotion owes: nothing it would have written changed.
/// The worker row keeps `worker`, the shared forward keeps `shared`, the
/// conntrack origin bit is not cleared, the forward tuple is not re-steered,
/// and nothing is fanned out to the sibling.
fn skipped_promotion_legs(
    fx: &Fixture,
    worker: Option<(NatDecision, SessionOrigin)>,
    shared: Option<(u64, NatDecision, SessionOrigin)>,
) -> Vec<(bool, &'static str)> {
    let key = fx.key();
    vec![
        (
            fx.worker_origin(&key) == worker,
            "worker: the promotion flipped (or replaced) the worker row",
        ),
        (
            fx.shared_identity(&key) == shared,
            "shared: the promotion rewrote the shared forward row",
        ),
        (
            fx.conntrack_peer_synced() != Some(false),
            "conntrack: the promotion cleared the conntrack peer-synced origin bit",
        ),
        (
            !session_map_writes().iter().any(|write| write.key == key),
            "steering: the promotion re-published the forward tuple's steering row",
        ),
        (
            fx.sibling_commands() == 0,
            "fan-out: the promotion replicated a row to the sibling worker",
        ),
    ]
}

/// F2 (Codex P1-2), import shape. A late import of a new incarnation (T1 ->
/// T2: generation 7 -> 9, a different session id and translation) COMPLETES
/// before the worker takes its permit: shared names T2, the import retired T1
/// and reserved T2, and the worker's `UpsertSynced(T2)` is still queued. The
/// worker then promotes its stale T1 row. Without the incarnation check it
/// overwrites shared with T1 and the queued T2 upsert is later refused as a
/// local-ownership clobber, so the node forwards on a T1 nothing reserves.
fn assert_completed_import_supersedes_stale_promotion(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    assert_eq!(
        fx.coordinator.upsert_synced_session(fx.late.clone()),
        SyncedImportOutcome::Applied,
        "premise (v6={v6}): the late import completes before the promotion"
    );
    let t2 = Some((LATE_SESSION_ID, snat(v6, LATE_PORT), SessionOrigin::SyncImport));
    assert_eq!(fx.shared_identity(&key), t2, "premise (v6={v6}): shared names T2");
    let stale_worker = Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport));
    assert_eq!(
        fx.worker_origin(&key),
        stale_worker,
        "premise (v6={v6}): the worker has not drained the queued T2 upsert"
    );
    clear_session_map_writes();

    fx.promote_on_hit();

    let mut legs = skipped_promotion_legs(&fx, stale_worker, t2);
    legs.push((
        fx.port_is_free(204, LOCAL_PORT),
        "allocator: the stale promotion re-reserved T1",
    ));
    assert_legs(&format!("completed import (v6={v6})"), &legs);

    // The queued repair lands, and the next hit promotes the CURRENT incarnation.
    fx.drain_worker();
    assert_eq!(
        fx.worker_origin(&key),
        Some((snat(v6, LATE_PORT), SessionOrigin::SyncImport)),
        "v6={v6}: the queued T2 upsert must replace the unpromoted T1 row"
    );
    let late = fx.late.clone();
    let forwarding = fx.coordinator.forwarding.clone();
    fx.promote_row_on_hit(&late, &forwarding);
    assert_eq!(
        (fx.worker_origin(&key), fx.shared_identity(&key)),
        (
            Some((snat(v6, LATE_PORT), SessionOrigin::SharedPromote)),
            Some((LATE_SESSION_ID, snat(v6, LATE_PORT), SessionOrigin::SharedPromote)),
        ),
        "v6={v6}: a hit after the repair must promote T2 (a resend with a bumped \
         generation is the same incarnation)"
    );
    assert!(
        !fx.port_is_free(205, LATE_PORT),
        "v6={v6}: T2 stays reserved for the promoted session"
    );
}

#[test]
fn completed_import_supersedes_stale_promotion_v4_18552() {
    assert_completed_import_supersedes_stale_promotion(false);
}

#[test]
fn completed_import_supersedes_stale_promotion_v6_18552() {
    assert_completed_import_supersedes_stale_promotion(true);
}

/// F2 (Codex P1-2), delete shape. A peer delete COMPLETES before the worker
/// takes its permit: the shared forward and its companion are gone and the
/// worker's `DeleteSynced` is queued. Promoting the worker's row then would
/// resurrect the deleted shared forward without its companion.
fn assert_completed_peer_delete_blocks_stale_promotion(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let local_reply = fx.local_reply();
    let outcome = fx
        .coordinator
        .session_domain()
        .delete_synced(key.clone(), SyncedDeleteMode::PEER, false);
    assert_eq!(
        outcome,
        SyncedDeleteOutcome::Applied,
        "premise (v6={v6}): a peer delete of a peer-synced row applies"
    );
    assert!(
        fx.shared(&key).is_none() && fx.shared(&local_reply).is_none(),
        "premise (v6={v6}): the delete removed the shared forward and its companion"
    );
    let stale_worker = Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport));
    assert_eq!(
        fx.worker_origin(&key),
        stale_worker,
        "premise (v6={v6}): the worker has not drained the queued delete"
    );
    clear_session_map_writes();

    fx.promote_on_hit();

    let mut legs = skipped_promotion_legs(&fx, stale_worker, None);
    legs.push((
        fx.shared(&local_reply).is_none(),
        "companion: the promotion resurrected the deleted reply companion",
    ));
    assert_legs(&format!("completed peer delete (v6={v6})"), &legs);
    fx.drain_worker();
    assert_eq!(
        fx.worker_origin(&key),
        None,
        "v6={v6}: the queued delete must remove the unpromoted row"
    );
}

#[test]
fn completed_peer_delete_blocks_stale_promotion_v4_18552() {
    assert_completed_peer_delete_blocks_stale_promotion(false);
}

#[test]
fn completed_peer_delete_blocks_stale_promotion_v6_18552() {
    assert_completed_peer_delete_blocks_stale_promotion(true);
}

/// R1 (r24 P2-1(b)): the #10612 stale-replay fence used to return AFTER the
/// worker-row flip, leaving the worker `SharedPromote` and the shared row
/// peer-synced: the window the #9678 gate cannot see, held open until a purge.
/// Now it flips nothing. (The other post-flip return, `synced_entry_for`
/// finding no row, cannot follow a flip that applied: the flip refreshes the
/// row in place and nothing between them removes it. No cell can reach it.)
fn assert_stale_replay_fence_flips_nothing(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let mut zones_vanished = fx.coordinator.forwarding.clone();
    // A validated zone set that still names the row's ingress zone but no
    // longer its egress zone (a commit removed it).
    zones_vanished.zone_set_validated = true;
    zones_vanished.zone_id_to_name.clear();
    zones_vanished
        .zone_id_to_name
        .insert(fx.original.metadata.ingress_zone, "lan".to_string());
    let mut promoted_metadata = fx.original.metadata.clone();
    promoted_metadata.owner_rg_id = RG;
    assert!(
        crate::afxdp::session_glue::synced_entry_is_stale_replay(
            SessionOrigin::SharedPromote,
            &promoted_metadata,
            &zones_vanished,
        ),
        "premise: the row's egress zone vanished, so the #10612 fence applies"
    );
    let shared_before = fx.shared_identity(&key);
    clear_session_map_writes();

    let row = fx.original.clone();
    fx.promote_row_on_hit(&row, &zones_vanished);

    let legs = skipped_promotion_legs(
        &fx,
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport)),
        shared_before,
    );
    assert_legs(&format!("stale-replay fence (v6={v6})"), &legs);
}

#[test]
fn stale_replay_fence_flips_nothing_v4_18552() {
    assert_stale_replay_fence_flips_nothing(false);
}

#[test]
fn stale_replay_fence_flips_nothing_v6_18552() {
    assert_stale_replay_fence_flips_nothing(true);
}

/// F3 (Codex P1-3). The importer loads its HA view (RG inactive), the RG then
/// activates, and an owner packet promotes T1 while the import waits on the
/// promotion's permit. The import's lease then re-reads a `SharedPromote` row,
/// whose generation is 0, so the #2170 check cannot stop it. Judged with the
/// pre-lease view, the #9678 gate reads the row as replaceable and the import
/// frees T1. Every ownership decision after the lease must use a view loaded
/// after it.
///
/// Both rendezvous are on observed states, not timings: the importer's own
/// after-snapshot hook hands control back once its view is loaded, and the
/// promotion's after-flip hook returns once the importer is parked on the
/// permit (`draining` with an install claim held).
fn assert_import_rereads_ha_after_lease(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let inactive = HAGroupRuntime {
        active: false,
        watchdog_timestamp: now_secs,
        lease: HAForwardingLease::Inactive,
    };
    let inactive_view = BTreeMap::from([(RG, inactive)]);
    assert!(
        crate::afxdp::session_glue::synced_entry_allows_local_replace(&inactive_view, RG, now_secs),
        "premise: with the RG inactive, the #9678 gate lets a peer row replace a local one"
    );
    fx.coordinator.ha.rg_runtime.store(Arc::new(inactive_view));

    let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let gate = global_tuple_gate();
    let import_gate = Arc::clone(&gate);
    let domain = fx.coordinator.session_domain().clone();
    let late = fx.late.clone();
    let importer = std::thread::spawn(move || {
        adopt_tuple_gate_for_test(import_gate);
        domain.set_synced_upsert_after_snapshot_hook_for_test(move |_domain, _key| {
            snapshot_tx.send(()).expect("snapshot rendezvous");
            go_rx
                .recv_timeout(RENDEZVOUS_BOUND)
                .expect("the promotion never released the importer");
        });
        domain.upsert_synced_session(late)
    });
    snapshot_rx
        .recv_timeout(RENDEZVOUS_BOUND)
        .expect("premise: the importer never loaded its HA view");
    // The RG activates; the worker's hit resolves against the active view.
    fx.coordinator.ha.rg_runtime.store(Arc::new(fx.ha_state.clone()));

    let parked = Rc::new(std::cell::Cell::new(false));
    let parked_slot = Rc::clone(&parked);
    let probe_key = key.clone();
    set_promote_after_flip_hook_for_test(move || {
        go_tx.send(()).expect("release the importer");
        let deadline = Instant::now() + RENDEZVOUS_BOUND;
        loop {
            let probe = gate.probe(&probe_key);
            if probe.state == "draining" && probe.installs > 0 {
                parked_slot.set(true);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            std::thread::yield_now();
        }
    });

    fx.promote_on_hit();

    let outcome = importer.join().expect("importer thread");
    assert!(
        parked.get(),
        "premise (v6={v6}): the import never parked on the promotion's permit \
         (outcome {outcome:?})"
    );
    fx.drain_worker();
    assert_promoted_flow_intact(&fx, &format!("activation before the lease (outcome {outcome:?})"));
}

#[test]
fn import_rereads_ha_view_after_lease_v4_18552() {
    assert_import_rereads_ha_after_lease(false);
}

#[test]
fn import_rereads_ha_view_after_lease_v6_18552() {
    assert_import_rereads_ha_after_lease(true);
}

/// F4b: the permit spans the sibling fan-out, not only the shared publish.
/// The promotion's before-fan-out hook probes the gate: both permit keys must
/// still carry the install claim while `replicate_session_upsert` is queued,
/// and the claim must be gone after. (A schedule that turns a release here
/// into damage needs an import or delete that #9678/#9714 would not already
/// stop on the published row, so the cell pins the lifetime directly.)
fn assert_permit_spans_sibling_fanout(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let reply = fx.local_reply();
    let gate = global_tuple_gate();
    let seen: Rc<RefCell<Option<(usize, usize, usize)>>> = Rc::new(RefCell::new(None));
    let seen_slot = Rc::clone(&seen);
    let sibling = Arc::clone(&fx.sibling);
    let (probe_key, probe_reply, probe_gate) = (key.clone(), reply.clone(), Arc::clone(&gate));
    set_promote_before_fanout_hook_for_test(move || {
        *seen_slot.borrow_mut() = Some((
            probe_gate.probe(&probe_key).installs,
            probe_gate.probe(&probe_reply).installs,
            sibling.lock().expect("sibling queue").len(),
        ));
    });

    fx.promote_on_hit();

    let seen = seen.borrow_mut().take();
    assert_eq!(
        seen,
        Some((1, 1, 0)),
        "v6={v6}: at the fan-out the install claim must still hold the forward and \
         the reply tuple (installs per key, then sibling queue depth)"
    );
    // `replicate_session_upsert` queues the sibling's replica origin of the
    // promoted row (`SharedPromote` replicates as `WorkerLocalImport`).
    let replica_origin = SessionOrigin::SharedPromote.worker_replica_origin();
    let queued = fx.sibling.lock().expect("sibling queue").clone();
    assert!(
        queued.len() == 1
            && queued.iter().all(|command| matches!(
                command,
                WorkerCommand::UpsertSynced(entry) | WorkerCommand::UpsertLocal(entry)
                    if entry.key == key && entry.origin == replica_origin
            )),
        "v6={v6}: the fan-out must queue the promoted row's replica for the sibling, \
         got {queued:?}"
    );
    assert_eq!(
        (gate.probe(&key).state, gate.probe(&reply).state),
        ("absent", "absent"),
        "v6={v6}: the permit is released once the fan-out is queued"
    );
}

#[test]
fn permit_spans_sibling_fanout_v4_18552() {
    assert_permit_spans_sibling_fanout(false);
}

#[test]
fn permit_spans_sibling_fanout_v6_18552() {
    assert_permit_spans_sibling_fanout(true);
}

/// F4c (r23 P3-2): a racing lease that covers only the REPLY tuple (a peer
/// import or delete keyed on the reverse row) must also refuse the promotion,
/// so the permit has to claim the reply tuple, not only `key`.
fn assert_reply_only_lease_refuses_promotion(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let shared_before = fx.shared_identity(&key);
    let lease = global_tuple_gate()
        .acquire_lease([fx.local_reply()])
        .expect("premise: the idle reply tuple leases");
    clear_session_map_writes();

    fx.promote_on_hit();

    let legs = skipped_promotion_legs(
        &fx,
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport)),
        shared_before,
    );
    assert_legs(&format!("reply-only lease (v6={v6})"), &legs);
    drop(lease);
    fx.promote_on_hit();
    assert_eq!(
        fx.worker_origin(&key),
        Some((snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
        "v6={v6}: the next hit after the reply lease dropped must promote"
    );
}

#[test]
fn reply_only_lease_refuses_promotion_v4_18552() {
    assert_reply_only_lease_refuses_promotion(false);
}

#[test]
fn reply_only_lease_refuses_promotion_v6_18552() {
    assert_reply_only_lease_refuses_promotion(true);
}

/// R4 (r24 P3-4): a PEER delete that arrives inside the promotion's window
/// waits for the permit, re-reads a `SharedPromote` row under its removal lock
/// and is refused by #9714. Its candidate snapshot predates the lease and was
/// still peer-synced, so the early #9714 check passes and the refusal comes
/// from the under-lock re-check: `RefusedConcurrentLocalOwned`, not the early
/// arm's `RefusedLocalOwned` (session_import.rs, the `remove_shared_session_if`
/// predicate). Before #18552 the delete applied in the window and the
/// promotion's publish then resurrected the shared row.
fn assert_in_window_peer_delete_is_refused(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let local_reply = fx.local_reply();
    let domain = fx.coordinator.session_domain().clone();
    let deleter: Rc<RefCell<Option<std::thread::JoinHandle<SyncedDeleteOutcome>>>> =
        Rc::new(RefCell::new(None));
    let parked = Rc::new(std::cell::Cell::new(false));
    let deleter_slot = Rc::clone(&deleter);
    let parked_slot = Rc::clone(&parked);
    let probe_key = key.clone();
    set_promote_after_flip_hook_for_test(move || {
        let gate = global_tuple_gate();
        let delete_gate = Arc::clone(&gate);
        let delete_key = probe_key.clone();
        let handle = std::thread::spawn(move || {
            adopt_tuple_gate_for_test(delete_gate);
            domain.delete_synced(delete_key, SyncedDeleteMode::PEER, false)
        });
        let deadline = Instant::now() + RENDEZVOUS_BOUND;
        loop {
            if handle.is_finished() {
                break;
            }
            let probe = gate.probe(&probe_key);
            if probe.state == "draining" && probe.installs > 0 {
                parked_slot.set(true);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the peer delete neither finished nor parked on the promotion's permit: {probe:?}"
            );
            std::thread::yield_now();
        }
        *deleter_slot.borrow_mut() = Some(handle);
    });

    fx.promote_on_hit();

    let outcome = deleter
        .borrow_mut()
        .take()
        .expect("premise: the promotion never reached its window")
        .join()
        .expect("delete thread");
    fx.drain_worker();
    assert_legs(
        &format!("in-window peer delete (v6={v6}, outcome {outcome:?}, parked {})", parked.get()),
        &[
            (parked.get(), "witness: the delete never parked on the promotion's permit"),
            (
                outcome == SyncedDeleteOutcome::RefusedConcurrentLocalOwned,
                "outcome: the delete was not refused as locally owned under its removal \
                 lock (#9714)",
            ),
            (
                fx.worker_origin(&key)
                    == Some((snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
                "worker: the promoted forward row did not survive",
            ),
            (
                fx.shared_identity(&key)
                    == Some((SEED_SESSION_ID, snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
                "shared: the promoted shared forward did not survive",
            ),
            (
                fx.shared(&local_reply).is_some() && fx.worker_origin(&local_reply).is_some(),
                "companion: the reply companion was deleted",
            ),
        ],
    );
}

#[test]
fn in_window_peer_delete_is_refused_v4_18552() {
    assert_in_window_peer_delete_is_refused(false);
}

#[test]
fn in_window_peer_delete_is_refused_v6_18552() {
    assert_in_window_peer_delete_is_refused(true);
}

// ---------------------------------------------------------------------------
// F1 (Codex P1-1 = r23 P2-1): the REAL poll pipeline and flow cache.
//
// A promotion that is skipped for this packet must keep the packet out of the
// flow cache. Cache hits (`flow_cache_hit.rs`) never promote and forwarding
// entries never TTL-expire, so a seeded packet would leave the owned flow
// peer-synced, and open to the #18552 race, for its whole life. The harness is
// the #18531 one (captured loss fw1 snapshot, fw1 owning both RGs, the
// production poll body), with two differences: the bindings, and so the flow
// cache, persist across packets, and the shared maps hold the imported pair,
// as the HA import publishes it.
// ---------------------------------------------------------------------------

use super::tests_split_rg_failback_18531 as rg;
use super::tests_support::{
    build_txn_tcp_syn_frame_v4, txn_meta_v4, txn_run_multi_binding_with_shared_maps,
};

struct PollFixture {
    forwarding: ForwardingState,
    ha: BTreeMap<i32, HAGroupRuntime>,
    sessions: crate::session::SessionTable,
    bindings: Vec<BindingWorker>,
    shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_indexes: SharedSessionOwnerRgIndexes,
    forward: SyncedSessionEntry,
    reverse: SyncedSessionEntry,
}

/// What one LAN -> WAN ACK did on the LAN binding.
#[derive(Debug)]
struct PollStep {
    /// Slow-path session hits (0 when the flow cache served the packet).
    session_hit: u64,
    /// Flow-cache hits on the LAN binding during this packet.
    cache_hits: u64,
    /// Packets sent out the WAN binding during this packet.
    tx_wan: u64,
}

impl PollFixture {
    /// fw1 after the crash takeover: it owns both RGs, and its worker and
    /// shared maps hold the fw0-originated pair as the HA import left it
    /// (`SyncImport`, reverse from production reverse synthesis).
    fn imported() -> Self {
        let forwarding = rg::fw1_owner_forwarding();
        let now_ns = monotonic_nanos();
        let now_secs = now_ns / 1_000_000_000;
        let ha = rg::owner_ha(now_secs);
        let forward =
            rg::imported_pair_entry(&forwarding, rg::forward_key(), IpAddr::V4(rg::SNAT_IP));
        let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &forwarding,
            &ha,
            &Arc::new(ShardedNeighborMap::default()),
            &forward,
            now_secs,
        )
        .expect("production reverse synthesis must produce the companion");
        let mut sessions = crate::session::SessionTable::new();
        for entry in [&forward, &reverse] {
            assert!(
                sessions.upsert_synced_with_origin(
                    crate::session::SessionInstall {
                        key: entry.key.clone(),
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
                        source_nat_static: entry.source_nat_static,
                        origin: SessionOrigin::SyncImport,
                        now_ns,
                        protocol: PROTO_TCP,
                        tcp_flags: rg::TCP_ACK,
                        session_id: entry.session_id,
                        tcp_close_class: 0,
                        tcp_handshake_state: entry.tcp_handshake_state,
                        persistent_lease_hold: None,
                        fwd_packets: entry.fwd_packets,
                        rev_packets: entry.rev_packets,
                    },
                    false,
                ),
                "fixture: the HA import must install {:?}",
                entry.key
            );
        }
        sessions.set_forwarding_revalidation_gen(7, 9);
        let fx = Self {
            forwarding,
            ha,
            sessions,
            bindings: rg::bindings(),
            shared: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            shared_indexes: SharedSessionOwnerRgIndexes::default(),
            forward,
            reverse,
        };
        for entry in [&fx.forward, &fx.reverse] {
            fx.publish(entry);
        }
        fx
    }

    fn publish(&self, entry: &SyncedSessionEntry) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.shared,
            &self.shared_nat,
            &self.shared_wire,
            &self.shared_indexes,
            entry,
        );
    }

    /// One mid-stream LAN -> WAN ACK through the production poll body.
    fn lan_ack(&mut self) -> PollStep {
        let frame = build_txn_tcp_syn_frame_v4(
            rg::LAN_HOST,
            rg::WAN_HOST,
            rg::SPORT,
            rg::DPORT,
            rg::TCP_ACK,
            [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
        );
        let mut meta = txn_meta_v4(rg::LAN_IFINDEX as u32, rg::TCP_ACK, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&rg::LAN_HOST.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&rg::WAN_HOST.octets());
        meta.flow_src_port = rg::SPORT;
        meta.flow_dst_port = rg::DPORT;
        meta.config_generation = 7;
        let tx_before = self.bindings[rg::WAN]
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed);
        let hits_before = self.bindings[rg::LAN].flow.flow_cache.hits;
        let (_batch, dbg, _egress) = txn_run_multi_binding_with_shared_maps(
            &mut self.bindings,
            rg::LAN,
            &mut self.sessions,
            &self.forwarding,
            &self.ha,
            &frame,
            meta,
            &self.shared,
            &self.shared_nat,
            &self.shared_wire,
            &self.shared_indexes,
            7,
            0,
        );
        assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor must reach the poll body");
        PollStep {
            session_hit: dbg.session_hit,
            cache_hits: self.bindings[rg::LAN].flow.flow_cache.hits - hits_before,
            tx_wan: self.bindings[rg::WAN]
                .live
                .tx_packets
                .load(std::sync::atomic::Ordering::Relaxed)
                - tx_before,
        }
    }

    fn cached(&self) -> bool {
        let key = rg::forward_key();
        self.bindings[rg::LAN]
            .flow
            .flow_cache
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.key == key)
    }

    fn worker_origin(&self) -> Option<SessionOrigin> {
        self.sessions
            .entry_with_origin(&rg::forward_key())
            .map(|(_, _, origin)| origin)
    }

    fn shared_origin(&self) -> Option<SessionOrigin> {
        crate::afxdp::shared_ops::lock_shared_recover(&self.shared)
            .get(&rg::forward_key())
            .map(|entry| entry.origin)
    }

    /// Owner packets until one promotes, bounded. Returns the packet count.
    fn ack_until_promoted(&mut self, bound: usize) -> Option<usize> {
        (1..=bound).find(|_| {
            let _ = self.lan_ack();
            self.worker_origin() == Some(SessionOrigin::SharedPromote)
        })
    }
}

/// F1: the first owner packet after the takeover meets a held tuple lease (an
/// HA import or delete of the flow), so its promotion is refused. The packet
/// still forwards, but it must not seed the flow cache; once the lease drops,
/// a later owner packet takes the slow path again and promotes.
#[test]
fn refused_promotion_does_not_seed_flow_cache_and_retries_18552() {
    let mut fx = PollFixture::imported();
    let lease = global_tuple_gate()
        .acquire_lease([fx.forward.key.clone(), fx.reverse.key.clone()])
        .expect("premise: the idle pair leases");

    let refused = fx.lan_ack();
    let after_refusal = (fx.worker_origin(), fx.shared_origin(), fx.cached());
    drop(lease);
    let promoted_after = fx.ack_until_promoted(4);
    let follow_up = fx.lan_ack();

    assert_legs(
        &format!(
            "refused promotion (first packet {refused:?}; after it worker/shared/cached \
             {after_refusal:?}; promoted after {promoted_after:?} more packets; then {follow_up:?})"
        ),
        &[
            (
                refused.session_hit == 1 && refused.tx_wan == 1,
                "premise: the refused packet must hit the session and forward out the WAN",
            ),
            (
                after_refusal.0 == Some(SessionOrigin::SyncImport)
                    && after_refusal.1 == Some(SessionOrigin::SyncImport),
                "refusal: the promotion was not refused under the held lease",
            ),
            (
                !after_refusal.2,
                "seed: the refused packet seeded the flow cache, so no later packet resolves \
                 and the promotion is never retried",
            ),
            (
                promoted_after.is_some(),
                "retry: no later owner packet promoted the row after the lease dropped",
            ),
            (
                fx.shared_origin() == Some(SessionOrigin::SharedPromote),
                "retry: shared authority was not republished as SharedPromote",
            ),
            (
                follow_up.cache_hits == 1 && follow_up.session_hit == 0,
                "cache: once promoted, the flow must ride the flow cache again",
            ),
        ],
    );
}

/// F1 x F2: the shared row was superseded (a completed import of a new
/// incarnation of the reused 5-tuple: a different RT_FLOW session id; interface
/// SNAT keeps the translation) while this worker still holds the old row and
/// its `UpsertSynced` is queued. The promotion must skip AND keep the packet
/// out of the flow cache, so that once the queued upsert lands, the next packet
/// resolves the current row and promotes it.
#[test]
fn superseded_promotion_does_not_seed_flow_cache_18552() {
    let mut fx = PollFixture::imported();
    let mut successor = fx.forward.clone();
    successor.session_id = fx.forward.session_id + 1;
    successor.generation = fx.forward.generation + 2;
    fx.publish(&successor);

    let skipped = fx.lan_ack();
    let after_skip = (fx.worker_origin(), fx.shared_origin(), fx.cached());
    let shared_id_after_skip = crate::afxdp::shared_ops::lock_shared_recover(&fx.shared)
        .get(&rg::forward_key())
        .map(|entry| entry.session_id);
    // The queued repair lands at the worker's next command drain.
    rg::apply_commands(
        &mut fx.sessions,
        &fx.forwarding,
        &fx.ha,
        vec![WorkerCommand::UpsertSynced(successor.clone())],
    );
    let promoted_after = fx.ack_until_promoted(4);
    let promoted_id = fx.sessions.session_id_for(&rg::forward_key());

    assert_legs(
        &format!(
            "superseded promotion (first packet {skipped:?}; after it worker/shared/cached \
             {after_skip:?}, shared id {shared_id_after_skip:?}; promoted after \
             {promoted_after:?} more packets, id {promoted_id:#x})"
        ),
        &[
            (
                skipped.session_hit == 1 && skipped.tx_wan == 1,
                "premise: the packet must hit the session and forward out the WAN",
            ),
            (
                after_skip.0 == Some(SessionOrigin::SyncImport),
                "worker: the superseded row was promoted",
            ),
            (
                after_skip.1 == Some(SessionOrigin::SyncImport)
                    && shared_id_after_skip == Some(successor.session_id),
                "shared: the superseded row overwrote the successor in shared authority",
            ),
            (
                !after_skip.2,
                "seed: the skipped packet seeded the flow cache from the superseded row",
            ),
            (
                promoted_after.is_some() && promoted_id == successor.session_id,
                "retry: the successor was not promoted once its upsert landed",
            ),
        ],
    );
}

// ---------------------------------------------------------------------------
// Fold 2, B1 (Codex P1-4 = r24 P2-1(a), the lead's Option B): a REPLY-first
// promotion. The #9678 import gate and the #9714 peer-delete guard read only
// the FORWARD row, so a reverse companion R promoted alone left F `SyncImport`
// and both gates blind. A reverse hit now promotes F with R, under the same
// permit, when F is present, promotable, current, and its owner RG is locally
// active in the hit's HA view.
// ---------------------------------------------------------------------------

const PAIR_PROMOTED: [Option<SessionOrigin>; 4] = [Some(SessionOrigin::SharedPromote); 4];

/// B1, import. After a reply-first promotion a late different-translation
/// import of F meets the #9678 gate: T1 stays, T2 is never reserved, and
/// nothing is published or steered.
fn assert_reply_first_promotion_stops_late_import(v6: bool) {
    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    fx.promote_reply_on_hit();
    let after_promotion = fx.pair_origins();
    clear_session_map_writes();
    let outcome = fx.coordinator.upsert_synced_session(fx.late.clone());
    fx.drain_worker();
    let late_reply = fx.late_reply();
    assert_legs(
        &format!(
            "reply-first vs import (v6={v6}; after the reply hit worker F/R, shared F/R = \
             {after_promotion:?}; import {outcome:?})"
        ),
        &[
            (
                after_promotion == PAIR_PROMOTED,
                "pair: the reply hit did not promote F with R in the worker and in shared",
            ),
            (
                outcome == SyncedImportOutcome::Applied,
                "outcome: the #9678 refusal reports Applied (deliberately silent)",
            ),
            (
                fx.shared_identity(&key)
                    == Some((SEED_SESSION_ID, snat(v6, LOCAL_PORT), SessionOrigin::SharedPromote)),
                "shared: the late import replaced the promoted forward",
            ),
            (!fx.port_is_free(206, LOCAL_PORT), "allocator: the late import freed T1"),
            (fx.port_is_free(207, LATE_PORT), "allocator: the late import reserved T2"),
            (
                fx.shared(&late_reply).is_none() && fx.worker_origin(&late_reply).is_none(),
                "companion: the late row's reverse companion was published or installed",
            ),
            (
                session_map_writes().is_empty(),
                "steering: the refused import steered a tuple",
            ),
            (
                fx.pair_origins() == PAIR_PROMOTED,
                "pair: the promoted pair did not survive the late import",
            ),
        ],
    );
}

#[test]
fn reply_first_promotion_stops_late_import_v4_18552() {
    assert_reply_first_promotion_stops_late_import(false);
}

#[test]
fn reply_first_promotion_stops_late_import_v6_18552() {
    assert_reply_first_promotion_stops_late_import(true);
}

/// B1, delete. After a reply-first promotion a peer delete of F reads the
/// promoted shared forward before its lease and is refused by the early #9714
/// check (`RefusedLocalOwned`); both rows survive, in the worker and in shared.
fn assert_reply_first_promotion_refuses_peer_delete(v6: bool) {
    let mut fx = seeded_fixture(v6);
    fx.promote_reply_on_hit();
    let after_promotion = fx.pair_origins();
    let outcome = fx
        .coordinator
        .session_domain()
        .delete_synced(fx.key(), SyncedDeleteMode::PEER, false);
    fx.drain_worker();
    assert_legs(
        &format!(
            "reply-first vs peer delete (v6={v6}; after the reply hit worker F/R, shared F/R = \
             {after_promotion:?}; delete {outcome:?}; then {:?})",
            fx.pair_origins()
        ),
        &[
            (
                after_promotion == PAIR_PROMOTED,
                "pair: the reply hit did not promote F with R in the worker and in shared",
            ),
            (
                outcome == SyncedDeleteOutcome::RefusedLocalOwned,
                "outcome: the peer delete of F was not refused as locally owned (#9714)",
            ),
            (
                fx.pair_origins() == PAIR_PROMOTED,
                "pair: the peer delete removed or demoted F or R",
            ),
        ],
    );
}

#[test]
fn reply_first_promotion_refuses_peer_delete_v4_18552() {
    assert_reply_first_promotion_refuses_peer_delete(false);
}

#[test]
fn reply_first_promotion_refuses_peer_delete_v6_18552() {
    assert_reply_first_promotion_refuses_peer_delete(true);
}

/// B1, split RG. F's owner RG (1, the WAN egress that holds the SNAT
/// allocation) is NOT active here; R's reply egress (the LAN row, moved to RG 2)
/// is. The reply hit promotes R only: F's owner stays authoritative for the
/// pair, so its import of a new translation legitimately applies to F.
fn assert_split_rg_reply_first_promotes_reply_only(v6: bool) {
    let mut forwarding = forwarding();
    forwarding
        .egress
        .get_mut(&6)
        .expect("LAN egress row")
        .redundancy_group = 2;
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let inactive = HAGroupRuntime {
        active: false,
        watchdog_timestamp: now_secs,
        lease: HAForwardingLease::Inactive,
    };
    let split_view = BTreeMap::from([(RG, inactive), (2, active_rg(now_secs))]);
    assert!(
        !crate::afxdp::session_glue::owner_rg_is_locally_active(&split_view, RG, now_secs)
            && crate::afxdp::session_glue::owner_rg_is_locally_active(&split_view, 2, now_secs),
        "premise: F's owner RG 1 is inactive here and the reply's RG 2 is active"
    );
    let mut fx = seeded_fixture_in(v6, forwarding, split_view);
    let key = fx.key();
    assert_eq!(
        fx.worker_sessions
            .entry_with_origin(&key)
            .map(|(_, metadata, _)| metadata.owner_rg_id),
        Some(RG),
        "premise: F is owned by RG 1"
    );
    fx.promote_reply_on_hit();
    let after_promotion = fx.pair_origins();
    let outcome = fx.coordinator.upsert_synced_session(fx.late.clone());
    fx.drain_worker();
    assert_legs(
        &format!(
            "split-RG reply-first (v6={v6}; after the reply hit worker F/R, shared F/R = \
             {after_promotion:?}; import {outcome:?})"
        ),
        &[
            (
                after_promotion
                    == [
                        Some(SessionOrigin::SyncImport),
                        Some(SessionOrigin::SharedPromote),
                        Some(SessionOrigin::SyncImport),
                        Some(SessionOrigin::SharedPromote),
                    ],
                "pair: the reply hit must promote R only and leave F synced (F's owner RG is \
                 not active here)",
            ),
            (
                outcome == SyncedImportOutcome::Applied
                    && fx.shared_identity(&key)
                        == Some((LATE_SESSION_ID, snat(v6, LATE_PORT), SessionOrigin::SyncImport)),
                "import: F's owner's import of T2 must apply and be published",
            ),
        ],
    );
}

#[test]
fn split_rg_reply_first_promotes_reply_only_v4_18552() {
    assert_split_rg_reply_first_promotes_reply_only(false);
}

#[test]
fn split_rg_reply_first_promotes_reply_only_v6_18552() {
    assert_split_rg_reply_first_promotes_reply_only(true);
}

/// B1, F not current. The reply hit lands while F's shared row already names a
/// successor (a new session id; same translation, so R's key and its own
/// shared row are unchanged). R alone is promoted, and F (worker row, shared
/// row, origin bit, steering) is untouched: the successor's queued upsert
/// repairs F. The TRUE twin runs first: the same hit with F current promotes
/// the pair, so the cell discriminates on F's incarnation alone.
fn assert_reply_first_skips_superseded_forward(v6: bool) {
    let mut control = seeded_fixture(v6);
    control.promote_reply_on_hit();
    let control_pair = control.pair_origins();

    let mut fx = seeded_fixture(v6);
    let key = fx.key();
    let mut successor = fx.original.clone();
    successor.session_id = LATE_SESSION_ID;
    successor.generation = LATE_GENERATION;
    crate::afxdp::shared_ops::publish_shared_session(
        &fx.coordinator.sessions.synced,
        &fx.coordinator.sessions.nat,
        &fx.coordinator.sessions.forward_wire,
        &fx.coordinator.sessions.owner_rg_indexes,
        &successor,
    );
    let successor_identity =
        Some((LATE_SESSION_ID, snat(v6, LOCAL_PORT), SessionOrigin::SyncImport));
    assert_eq!(fx.shared_identity(&key), successor_identity, "premise: shared F is superseded");
    clear_session_map_writes();

    fx.promote_reply_on_hit();

    assert_legs(
        &format!(
            "reply-first, F not current (v6={v6}; control pair {control_pair:?}; worker F/R, \
             shared F/R = {:?})",
            fx.pair_origins()
        ),
        &[
            (
                control_pair == PAIR_PROMOTED,
                "twin: with F current, the reply hit did not promote the pair",
            ),
            (
                fx.worker_origin(&fx.local_reply()).map(|(_, origin)| origin)
                    == Some(SessionOrigin::SharedPromote),
                "reply: R was not promoted",
            ),
            (
                fx.worker_origin(&key) == Some((snat(v6, LOCAL_PORT), SessionOrigin::SyncImport)),
                "forward: the superseded worker F was flipped",
            ),
            (
                fx.shared_identity(&key) == successor_identity,
                "forward: shared F (the successor) was overwritten",
            ),
            (
                fx.conntrack_peer_synced() == Some(true),
                "forward: F's conntrack origin bit was cleared",
            ),
            (
                !session_map_writes().iter().any(|write| write.key == key),
                "forward: F's steering row was re-published",
            ),
        ],
    );
}

#[test]
fn reply_first_skips_superseded_forward_v4_18552() {
    assert_reply_first_skips_superseded_forward(false);
}

#[test]
fn reply_first_skips_superseded_forward_v6_18552() {
    assert_reply_first_skips_superseded_forward(true);
}
