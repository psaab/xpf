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
        let now_ns = monotonic_nanos();
        let key = self.key();
        let decision = self.original.decision;
        let metadata = self.original.metadata.clone();
        let mut resolved = ResolvedFlowSessionDecision {
            key: key.clone(),
            session_id: SEED_SESSION_ID,
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
        let no_peers: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        maybe_promote_synced_session_with_conntrack(
            &mut self.worker_sessions,
            SteeringMap::unshared_for_test(RECORDER_ONLY_MAP_FD),
            SharedSessionRefs {
                sessions: &self.coordinator.sessions.synced,
                nat_sessions: &self.coordinator.sessions.nat,
                forward_wire_sessions: &self.coordinator.sessions.forward_wire,
                owner_rg_indexes: &self.coordinator.sessions.owner_rg_indexes,
                peer_worker_commands: &no_peers,
                worker_commands_by_id: empty_worker_commands_by_id(),
                conntrack: ConntrackFds {
                    v4: CONNTRACK_TEST_MAP_FD,
                    v6: CONNTRACK_TEST_MAP_FD,
                },
                tick: Tick::from_ns(now_ns),
            },
            &self.coordinator.forwarding,
            0x10,
            0,
            SessionHitVerdict::Owner,
            &mut resolved,
            &mut Vec::new(),
        );
    }
}

/// One worker, RG 1 forwarding-active on the coordinator and in the worker's
/// HA view, and the original incarnation imported through the production path
/// and drained into the worker: the coordinator's `Untracked` T1 plus the
/// worker's holder bit, the shared forward row and its reverse companion, and
/// a cluster-synced conntrack row (what the Go mirror write leaves).
fn seeded_fixture(v6: bool) -> Fixture {
    clear_session_map_writes();
    clear_conntrack_rows_for_test();
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding());
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
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(RG, active_rg(now_secs))]);
    coordinator.ha.rg_runtime.store(Arc::new(ha_state.clone()));
    assert!(
        !crate::afxdp::session_glue::synced_entry_allows_local_replace(&ha_state, RG, now_secs),
        "premise: the fixture must model an ACTIVE owner, where the #9678 gate applies"
    );
    let original = peer_row(v6, LOCAL_PORT, SEED_GENERATION, SEED_SESSION_ID);
    let late = peer_row(v6, LATE_PORT, LATE_GENERATION, LATE_SESSION_ID);
    let mut fx = Fixture {
        v6,
        coordinator,
        commands,
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
