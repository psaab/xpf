//! #18520: a TCP flow whose handshake is split across two workers of ONE
//! node must reach Established in BOTH worker tables.
//!
//! Live shape (loss cluster, `iperf3 -P 8`, SNAT): the SYN lands on worker A
//! (LAN RX queue) and installs the authoritative forward + reverse pair,
//! fanning `UpsertSynced` replicas to every sibling. The SNAT'd SYN-ACK hashes
//! to worker B (WAN RX queue), which promotes only ITS replica pair. The
//! completing ACK and all client data return to A, whose forward row is still
//! pure Opening (`established=false, handshake_pending=false`): the classic
//! completion needs `handshake_pending`, and the #16223 companion arm refuses
//! a pure Opening hit unless node-level evidence proves completion — evidence
//! that lives only in B's table. No worker ever sees the whole handshake, so
//! A stays on the 20 s opening window and pays the #16223 evidence scan on
//! every cached data packet.
//!
//! The fixture drives the production calls each worker makes for each
//! segment: the new-flow install + `replicate_session_upsert` fan-out, the
//! slow-path authority-deferred lookup + Owner replay + post-filter sequence
//! note + forward-build accounting, the flow-cache deferring probe +
//! TX-admission emit, and one worker loop pass (`pump`) between segments that
//! runs the loop-level relay fan-out and `apply_worker_commands` exactly as
//! `worker_loop` does. Times are offsets from the real monotonic clock
//! because `apply_worker_commands` stamps installs with it.

use super::*;
use crate::afxdp::testfx::{test_forwarding_state, test_key, test_metadata, test_resolution};
use crate::session::{
    ExpireHaContext, HandshakeRelay, HandshakeRelayStage, SessionDeltaKind, TcpHandshakeState,
    SESSION_KEY_HASHES_FOR_TEST, STALE_SYNCED_CEILING_ABS_NS, STALE_SYNCED_CEILING_MULT,
};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::net::{IpAddr, Ipv4Addr};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;
const CLIENT_ISN: u32 = 0x1000_0000;
const SERVER_ISN: u32 = 0x5000_0000;
const SNAT_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
const SNAT_PORT: u16 = 40_001;
const MSS: u32 = 1448;
const TCP_PSH: u8 = crate::tcp_flags::TCP_PSH;
const TCP_FLAG_ACK: u8 = crate::tcp_flags::TCP_ACK;
const TCP_FLAG_SYN: u8 = crate::tcp_flags::TCP_SYN;

struct Worker {
    id: u32,
    table: SessionTable,
    queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
}

impl Worker {
    fn new(id: u32) -> Self {
        let mut table = SessionTable::new();
        table.set_session_id_namespace(0, id);
        Self {
            id,
            table,
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

struct Node {
    t0: u64,
    a: Worker,
    b: Worker,
    forwarding: ForwardingState,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    forward_key: SessionKey,
    reverse_key: SessionKey,
    decision: SessionDecision,
    reverse_decision: SessionDecision,
}

fn snat_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(SNAT_IP)),
            rewrite_src_port: Some(SNAT_PORT),
            ..NatDecision::default()
        },
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn reverse_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_WAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        is_reverse: true,
        ..test_metadata()
    }
}

fn fresh_node() -> Node {
    let decision = snat_decision();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, decision.nat);
    let reverse_decision = SessionDecision {
        nat: decision.nat.reverse(
            forward_key.src_ip,
            forward_key.dst_ip,
            forward_key.src_port,
            forward_key.dst_port,
        ),
        ..decision
    };
    assert_eq!(
        reverse_session_key(&reverse_key, reverse_decision.nat),
        forward_key,
        "fixture: the reverse half must navigate back to the forward tuple"
    );
    Node {
        t0: crate::afxdp::monotonic_nanos(),
        a: Worker::new(0),
        b: Worker::new(1),
        forwarding: test_forwarding_state(),
        dynamic_neighbors: Arc::new(ShardedNeighborMap::new()),
        forward_key,
        reverse_key,
        decision,
        reverse_decision,
    }
}

/// One worker-loop pass on every worker: the loop-level relay fan-out the
/// worker runs after its binding sweep, then the command drain the next
/// pass starts with.
fn pump(node: &mut Node) {
    let mut scratch = Vec::new();
    let (queue_a, queue_b) = (Arc::clone(&node.a.queue), Arc::clone(&node.b.queue));
    for (sender, peer) in [(&mut node.a, &queue_b), (&mut node.b, &queue_a)] {
        fan_out_handshake_relays(
            &mut sender.table,
            std::slice::from_ref(peer),
            crate::afxdp::empty_worker_commands_by_id(),
            &mut scratch,
        );
    }
    for worker in [&mut node.a, &mut node.b] {
        apply_worker_commands(
            &worker.queue,
            &mut worker.table,
            crate::afxdp::bpf_map::SteeringMap::unshared_for_test(
                crate::afxdp::bpf_map::RECORDER_ONLY_MAP_FD,
            ),
            -1,
            -1,
            &node.forwarding,
            &BTreeMap::new(),
            &node.dynamic_neighbors,
            worker.id,
            &mut VecDeque::new(),
        );
    }
}

fn reverse_synced_entry(node: &Node, origin: SessionOrigin, handshake: u8, session_id: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: node.reverse_key.clone(),
        decision: node.reverse_decision,
        metadata: reverse_metadata(),
        leak_incarnation: 0,
        origin,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: handshake,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

/// The SYN on worker A: the poll new-flow install (forward, ISN seed,
/// reverse) plus the publish-side `replicate_session_upsert` fan-out of both
/// halves to the sibling, then one loop pass so B holds its replicas.
fn syn_on_a() -> Node {
    let mut node = fresh_node();
    let (forward_key, reverse_key) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    let a = &mut node.a.table;
    assert!(a.install_with_protocol_with_origin_and_source_nat(
        forward_key.clone(),
        node.decision,
        test_metadata(),
        SessionOrigin::ForwardFlow,
        t0,
        PROTO_TCP,
        TCP_FLAG_SYN,
        None,
    ));
    a.seed_tcp_isn(&forward_key, CLIENT_ISN, 0, TCP_FLAG_SYN);
    let info = a
        .installed_session_info(&forward_key)
        .expect("fixture: forward installed");
    assert!(a.install_with_protocol_with_origin(
        reverse_key.clone(),
        node.reverse_decision,
        reverse_metadata(),
        SessionOrigin::ReverseFlow,
        t0,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    let forward_entry = forward_synced_entry(
        a,
        forward_key.clone(),
        node.decision,
        test_metadata(),
        None,
        None,
        SessionOrigin::ForwardFlow,
        PROTO_TCP,
        TCP_FLAG_SYN,
        info.session_id,
        info.handshake_state_wire,
    );
    let reverse_entry =
        reverse_synced_entry(&node, SessionOrigin::ReverseFlow, info.handshake_state_wire, 0);
    for entry in [&forward_entry, &reverse_entry] {
        replicate_session_upsert(
            std::slice::from_ref(&node.b.queue),
            crate::afxdp::empty_worker_commands_by_id(),
            entry,
        );
    }
    pump(&mut node);
    for key in [&node.forward_key, &node.reverse_key] {
        let (_, _, origin) = node
            .b
            .table
            .entry_with_origin(key)
            .expect("fixture: B must hold the replica pair");
        assert_eq!(origin, SessionOrigin::WorkerLocalImport);
        assert_eq!(
            node.b.table.handshake_state_wire_for(key),
            TcpHandshakeState::Opening.to_wire()
        );
    }
    let _ = node.a.table.drain_deltas(64);
    let _ = node.b.table.drain_deltas(64);
    node
}

/// A slow-path session hit as `poll_descriptor` drives it: the read-only
/// authority-deferred probe, the Owner replay carrying the parsed ack, the
/// post-input-filter sequence note, then the forward-build accounting.
fn slow_hit(table: &mut SessionTable, key: &SessionKey, now: u64, flags: u8, payload: u32, seq: u32, ack: u32) {
    assert!(
        matches!(
            table.lookup_with_origin_deferring_authority_with_payload(key, now, flags, payload),
            crate::session::SessionExpiryProbe::Live(_)
        ),
        "fixture: slow-path hit must find a live session"
    );
    table.apply_deferred_owner_hit_with_ack(key, now, flags, payload, Some(ack));
    table.note_tcp_seq_scaled(key, seq, ack, 65_535, None, payload, flags, 0);
    table.account_packet(key, u64::from(payload) + 52, flags, 0);
}

/// A flow-cache hit as `flow_cache_hit.rs` drives it: the deferring fused
/// probe, then (packet admitted) the withheld HA emit and the stage
/// transition consume. Returns whether the backing session was live.
fn cache_hit(table: &mut SessionTable, key: &SessionKey, now: u64, flags: u8, payload: u32, ack: u32) -> bool {
    if !table.probe_hit_deferring_state_update_with_ack(
        key,
        now,
        u64::from(payload) + 52,
        flags,
        payload,
        0,
        Some(ack),
    ) {
        return false;
    }
    table.emit_probe_hit_state_update(key);
    let _ = table.take_probe_stage_transition(key);
    true
}

fn established_secs() -> u32 {
    (crate::session::SessionTimeouts::default().tcp_established_ns / SEC) as u32
}

fn opening_secs() -> u32 {
    (crate::session::SessionTimeouts::default().tcp_opening_ns / SEC) as u32
}

fn assert_pair_established(table: &SessionTable, node: &Node, who: &str) {
    for key in [&node.forward_key, &node.reverse_key] {
        assert_eq!(
            table.handshake_state_wire_for(key),
            TcpHandshakeState::Established.to_wire(),
            "#18520: {who} {key:?} must reach Established (wire {}), not stay on the opening window",
            table.handshake_state_wire_for(key)
        );
        assert_eq!(
            table.timeout_secs_for(key),
            established_secs(),
            "#18520: {who} {key:?} must carry the established timeout"
        );
    }
}

fn update_wires(table: &mut SessionTable, key: &SessionKey) -> Vec<u8> {
    table
        .drain_deltas(256)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update && d.key == *key)
        .map(|d| d.tcp_handshake_state)
        .collect()
}

/// Upload (`iperf3 -c`) through completion.
fn upload_established() -> Node {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    // SYN-ACK on B (WAN queue), acking the client SYN.
    slow_hit(&mut node.b.table, &rev, t0 + MS, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, SERVER_ISN, CLIENT_ISN + 1);
    assert_eq!(
        node.b.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::HandshakePending.to_wire(),
        "premise: B's replica pair is promoted by the SYN-ACK"
    );
    pump(&mut node);
    // Completing ACK on A (LAN queue), slow path.
    slow_hit(&mut node.a.table, &fwd, t0 + 2 * MS, TCP_FLAG_ACK, 0, CLIENT_ISN + 1, SERVER_ISN + 1);
    pump(&mut node);
    // Client data on A served from the flow cache; server bare ACKs on B.
    let mut sent = 0u32;
    for i in 0..8u64 {
        let now = t0 + (3 + i) * MS;
        assert!(cache_hit(&mut node.a.table, &fwd, now, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1));
        sent += MSS;
        assert!(cache_hit(&mut node.b.table, &rev, now, TCP_FLAG_ACK, 0, CLIENT_ISN + 1 + sent));
        pump(&mut node);
    }
    node
}

/// Upload: SYN on A, SYN-ACK on B, completing ACK + client data on A, server
/// bare ACKs on B. Pre-fix neither worker ever completes: A never saw the
/// SYN-ACK, B only sees reverse bare ACKs (a reverse ACK does not complete a
/// SYN-first handshake, #4109).
#[test]
fn split_handshake_upload_establishes_both_workers_18520() {
    let mut node = upload_established();
    let fwd = node.forward_key.clone();
    assert_pair_established(&node.a.table, &node, "worker A (authoritative forward)");
    assert_pair_established(&node.b.table, &node, "worker B (SYN-ACK worker replicas)");
    // The HA/synced view: A's authoritative forward row announces the
    // completion to the peer.
    assert!(
        update_wires(&mut node.a.table, &fwd).contains(&TcpHandshakeState::Established.to_wire()),
        "#18520: A must emit an Established HA Update for the forward row"
    );
}

/// Download (`iperf3 -R`): server data rides B, client bare ACKs ride A.
/// B completes its own replica pair (pending + reverse payload); A, which
/// only ever sees bare ACKs, must learn the completion from B.
#[test]
fn split_handshake_download_establishes_both_workers_18520() {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    slow_hit(&mut node.b.table, &rev, t0 + MS, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, SERVER_ISN, CLIENT_ISN + 1);
    // The completing ACK reaches A BEFORE B's relay is applied (lost race):
    // A cannot complete on it, and every later client ACK carries an
    // advanced ack the #16042 exact check refuses.
    slow_hit(&mut node.a.table, &fwd, t0 + 2 * MS, TCP_FLAG_ACK, 0, CLIENT_ISN + 1, SERVER_ISN + 1);
    pump(&mut node);
    let mut received = 0u32;
    for i in 0..8u64 {
        let now = t0 + (3 + i) * MS;
        assert!(cache_hit(&mut node.b.table, &rev, now, TCP_FLAG_ACK | TCP_PSH, MSS, CLIENT_ISN + 1));
        received += MSS;
        assert!(cache_hit(&mut node.a.table, &fwd, now, TCP_FLAG_ACK, 0, SERVER_ISN + 1 + received));
        pump(&mut node);
    }
    assert_pair_established(&node.b.table, &node, "worker B (SYN-ACK worker replicas)");
    assert_pair_established(&node.a.table, &node, "worker A (authoritative forward)");
    assert!(
        update_wires(&mut node.a.table, &fwd).contains(&TcpHandshakeState::Established.to_wire()),
        "#18520: A must emit an Established HA Update for the forward row"
    );
    // B completed on a DEFERRED (flow-cache) reverse hit through the #16223
    // companion arm; its Update must be published on TX admission (its
    // replica carries the installer's id, so it announces, #9582).
    assert!(
        update_wires(&mut node.b.table, &fwd).contains(&TcpHandshakeState::Established.to_wire()),
        "#18520: B's deferred cache-hit completion must publish its Established Update"
    );
}

/// #16042 across workers: B's replica cannot validate the SYN-ACK ack (the
/// replica carries no client ISN) and promotes on any ack. The relay carries
/// the ack and A — which seeded the client ISN at install — must refuse a
/// wrong one exactly as it would had the SYN-ACK landed on A; the client's
/// ACK and data then leave A on the opening window.
#[test]
fn relayed_synack_with_wrong_ack_does_not_promote_the_authoritative_pair_16042_18520() {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    slow_hit(&mut node.b.table, &rev, t0 + MS, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, SERVER_ISN, CLIENT_ISN + 777);
    assert_eq!(
        node.b.table.handshake_state_wire_for(&rev),
        TcpHandshakeState::HandshakePending.to_wire(),
        "premise: the replica (no client ISN) fails open and promotes, so a relay IS sent"
    );
    pump(&mut node);
    assert_eq!(
        node.a.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Opening.to_wire(),
        "#16042: a relayed SYN-ACK with a wrong ack must not promote A"
    );
    slow_hit(&mut node.a.table, &fwd, t0 + 2 * MS, TCP_FLAG_ACK, 0, CLIENT_ISN + 1, SERVER_ISN + 1);
    pump(&mut node);
    for i in 0..4u64 {
        assert!(cache_hit(&mut node.a.table, &fwd, t0 + (3 + i) * MS, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1));
        pump(&mut node);
    }
    for key in [&fwd, &rev] {
        assert_ne!(
            node.a.table.handshake_state_wire_for(key),
            TcpHandshakeState::Established.to_wire(),
            "#16042: no validated SYN-ACK reached A, so A must not establish"
        );
        assert_eq!(node.a.table.timeout_secs_for(key), opening_secs());
    }
}

/// #6752/#13679 + incarnation fence, driven at the consumer: a pure Opening
/// pair (no SYN-ACK anywhere) is never established by a `Completed` relay or
/// by payload alone, a relay for another incarnation is ignored, and an idle
/// replica pair is left on its opening-window reap.
#[test]
fn relay_consumer_refuses_pure_opening_completion_and_foreign_incarnation_18520() {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    let session_id = node.a.table.session_id_for(&fwd);
    let completed = HandshakeRelay {
        forward_key: fwd.clone(),
        session_id,
        stage: HandshakeRelayStage::Completed,
        synack_ack: None,
        server_ack_end: None,
    };
    assert!(
        !node.a.table.apply_handshake_relay(&completed, t0 + MS),
        "#6752/#13679: a Completed relay must not establish a pure Opening pair"
    );
    let promoted = HandshakeRelay {
        forward_key: fwd.clone(),
        session_id,
        stage: HandshakeRelayStage::Promoted,
        synack_ack: Some(CLIENT_ISN + 1),
        server_ack_end: Some(SERVER_ISN + 1),
    };
    let foreign = HandshakeRelay {
        session_id: session_id.wrapping_add(1),
        ..promoted.clone()
    };
    assert!(
        !node.a.table.apply_handshake_relay(&foreign, t0 + MS),
        "a relay naming another incarnation must be ignored"
    );
    // Payload alone (no SYN-ACK observed or relayed) keeps the pair Opening.
    for i in 0..4u64 {
        assert!(cache_hit(&mut node.a.table, &fwd, t0 + (2 + i) * MS, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1));
        pump(&mut node);
    }
    for key in [&fwd, &rev] {
        assert_eq!(
            node.a.table.handshake_state_wire_for(key),
            TcpHandshakeState::Opening.to_wire()
        );
    }
    // B's replicas never served a packet, so even a matching Promoted relay
    // must leave them on the opening-window reap.
    assert!(
        !node.b.table.apply_handshake_relay(&promoted, t0 + MS),
        "an idle replica pair must not be advanced by a relay"
    );
    assert!(
        node.a.table.apply_handshake_relay(&promoted, t0 + MS),
        "control: the serving author applies the same relay"
    );
    assert_eq!(
        node.a.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::HandshakePending.to_wire(),
        "#6752: a promotion keeps the pair in the opening class until its completing ACK"
    );
    assert_eq!(node.a.table.timeout_secs_for(&fwd), opening_secs());
}

/// Steady state (#16217 / hot path): once A's pair is Established a cached
/// data hit never reaches the #16223 evidence helpers and queues no relay.
/// Prints the SessionKey hashes one cached forward data packet costs.
#[test]
fn established_cache_hit_skips_handshake_evidence_scan_18520() {
    let mut node = upload_established();
    let fwd = node.forward_key.clone();
    assert_pair_established(&node.a.table, &node, "worker A");
    let probes_before = node.a.table.handshake_progress_probe_count_for_test();
    let hashes_before = SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get());
    const HITS: u64 = 64;
    for i in 0..HITS {
        assert!(cache_hit(&mut node.a.table, &fwd, node.t0 + (20 + i) * MS, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1));
    }
    let hashes = SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get()) - hashes_before;
    eprintln!(
        "#18520: established cached forward data hit = {} SessionKey hashes/packet ({} over {} hits)",
        hashes as f64 / HITS as f64,
        hashes,
        HITS
    );
    assert_eq!(
        node.a.table.handshake_progress_probe_count_for_test(),
        probes_before,
        "#18520: an established hit must return before cache_hit_handshake_progress/node_served_evidence"
    );
    assert!(
        !node.a.table.has_pending_handshake_relays(),
        "#18520: steady-state hits must queue no relay"
    );
}

/// Measurement twin of the stuck pre-fix shape: a pure Opening pair taking
/// cached data hits (what A looked like before #18520) still pays the #16223
/// evidence scan — once per packet now that the dead second call is gone.
#[test]
fn opening_cache_hit_pays_one_evidence_scan_18520() {
    let mut node = syn_on_a();
    let fwd = node.forward_key.clone();
    let probes_before = node.a.table.handshake_progress_probe_count_for_test();
    let hashes_before = SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get());
    const HITS: u64 = 64;
    for i in 0..HITS {
        assert!(cache_hit(&mut node.a.table, &fwd, node.t0 + (2 + i) * MS, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1));
    }
    let hashes = SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get()) - hashes_before;
    let probes = node.a.table.handshake_progress_probe_count_for_test() - probes_before;
    eprintln!(
        "#18520: pure-Opening cached forward data hit = {} SessionKey hashes/packet, {} evidence-helper calls/packet",
        hashes as f64 / HITS as f64,
        probes as f64 / HITS as f64
    );
    // One `cache_hit_handshake_progress` + its `node_served_evidence`.
    assert_eq!(probes, 2 * HITS, "exactly one evidence scan per non-established payload hit");
}

/// Coordinator follow-up (tcp-cluster failover, #18503 shape): the new owner
/// holds a session HA sync imported as Opening on every worker (`SyncImport`)
/// and serves it mid-stream with no SYN — forward data on A, reverse data on
/// B. Neither serving row may reap on the opening window: a reaped row turns
/// the next segment into a session miss (no SYN, so a deny). Runs the
/// production expiry pass with the production HA context shape, including
/// the shared-map `node_served` probe, across 60 s of traffic.
#[test]
fn imported_opening_session_served_mid_stream_survives_opening_window_18520() {
    let mut node = fresh_node();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    // HA import as the coordinator applies it: shared authority + a
    // SyncImport replica on every worker, both halves Opening.
    let peer_id = (1u64 << 63) | 0x42;
    let forward_entry = SyncedSessionEntry {
        key: fwd.clone(),
        decision: node.decision,
        metadata: test_metadata(),
        tcp_handshake_state: TcpHandshakeState::Opening.to_wire(),
        session_id: peer_id,
        ..reverse_synced_entry(&node, SessionOrigin::SyncImport, 0, 0)
    };
    let reverse_entry = reverse_synced_entry(
        &node,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        crate::session::synthesized_companion_session_id(peer_id),
    );
    let queues = [Arc::clone(&node.a.queue), Arc::clone(&node.b.queue)];
    for entry in [&forward_entry, &reverse_entry] {
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
        replicate_session_upsert(&queues, crate::afxdp::empty_worker_commands_by_id(), entry);
    }
    pump(&mut node);
    for (worker, key) in [(&node.a, &fwd), (&node.b, &rev)] {
        assert_eq!(
            worker.table.handshake_state_wire_for(key),
            TcpHandshakeState::Opening.to_wire(),
            "premise: imported Opening"
        );
    }
    let node_served = |key: &SessionKey| {
        crate::afxdp::shared_ops::shared_node_served_evidence(&shared_sessions, key)
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    // 60 s of mid-stream service, 250 ms apart, with a GC pass every second.
    let mut sent = 0u32;
    let mut received = 0u32;
    for step in 1..=240u64 {
        let now = t0 + step * 250 * MS;
        assert!(
            cache_hit(&mut node.a.table, &fwd, now, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1 + received),
            "imported forward row reaped on the serving worker at +{} ms (opening window {} s)",
            step * 250,
            opening_secs()
        );
        sent += MSS;
        assert!(
            cache_hit(&mut node.b.table, &rev, now, TCP_FLAG_ACK | TCP_PSH, MSS, CLIENT_ISN + 1 + sent),
            "imported reverse row reaped on the serving worker at +{} ms (opening window {} s)",
            step * 250,
            opening_secs()
        );
        received += MSS;
        pump(&mut node);
        if step % 4 == 0 {
            let _ = node.a.table.expire_stale_entries_ha(now, Some(&ha));
            let _ = node.b.table.expire_stale_entries_ha(now, Some(&ha));
        }
    }
}

/// The same shape with the failover in it: the session is imported Opening
/// while this node is STANDBY for its RG (periodic same-incarnation
/// re-imports, the #2120 HOLD keeps the replicas), then the RG fails over to
/// this node — the activation `RefreshOwnerRGS` re-stamps every forwarding
/// row (`refresh_for_ha_transition`, as `handle_refresh_owner_rgs` applies
/// it) and the GC sees the epoch edge — and both directions are served on
/// two workers for 60 s with no SYN. No serving row may reap. Simulated time
/// throughout (the import and activation are applied directly, not through
/// `apply_worker_commands`, whose real clock would run behind it).
#[test]
fn imported_opening_session_held_on_standby_survives_takeover_service_18520() {
    let node = fresh_node();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = 1_000 * SEC;
    let peer_id = (1u64 << 63) | 0x43;
    let rows = [
        (fwd.clone(), node.decision, test_metadata(), peer_id),
        (
            rev.clone(),
            node.reverse_decision,
            reverse_metadata(),
            crate::session::synthesized_companion_session_id(peer_id),
        ),
    ];
    let mut a = SessionTable::new();
    a.set_session_id_namespace(0, 0);
    let mut b = SessionTable::new();
    b.set_session_id_namespace(0, 1);
    let import = |table: &mut SessionTable, now: u64| {
        for (key, decision, metadata, session_id) in &rows {
            assert!(table.upsert_synced_with_origin(
                crate::session::SessionInstall {
                    key: key.clone(),
                    decision: *decision,
                    metadata: metadata.clone(),
                    source_nat_static: None,
                    origin: SessionOrigin::SyncImport,
                    now_ns: now,
                    protocol: PROTO_TCP,
                    tcp_flags: 0,
                    session_id: *session_id,
                    tcp_close_class: 0,
                    tcp_handshake_state: TcpHandshakeState::Opening.to_wire(),
                    persistent_lease_hold: None,
                    fwd_packets: 0,
                    rev_packets: 0,
                },
                false,
            ));
        }
    };
    import(&mut a, t0);
    import(&mut b, t0);
    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let forwarding_here = std::cell::Cell::new(false);
    let rg_epoch = std::cell::Cell::new(0u32);
    let node_served = |key: &SessionKey| {
        crate::afxdp::shared_ops::shared_node_served_evidence(&shared_sessions, key)
    };
    let forwards = |_: i32| forwarding_here.get();
    let epoch = |_: i32| rg_epoch.get();
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    // Standby for 30 s: the owner re-sends the same Opening snapshot every
    // 5 s (anchor-preserving same-id re-imports), GC every second.
    for sec in 1..=30u64 {
        let now = t0 + sec * SEC;
        if sec % 5 == 0 {
            import(&mut a, now);
            import(&mut b, now);
        }
        let _ = a.expire_stale_entries_ha(now, Some(&ha));
        let _ = b.expire_stale_entries_ha(now, Some(&ha));
    }
    for (table, key) in [(&a, &fwd), (&b, &rev)] {
        assert!(
            table.entry_with_origin(key).is_some(),
            "premise: the standby HOLD retains the imported Opening row"
        );
    }
    // Failover: this node now forwards the RG.
    let takeover = t0 + 30 * SEC + 100 * MS;
    forwarding_here.set(true);
    rg_epoch.set(1);
    for table in [&mut a, &mut b] {
        for (key, decision, metadata, _) in &rows {
            assert!(table.refresh_for_ha_transition(key, *decision, metadata.clone(), takeover));
        }
    }
    let mut sent = 0u32;
    let mut received = 0u32;
    for step in 1..=240u64 {
        let now = takeover + step * 250 * MS;
        assert!(
            cache_hit(&mut a, &fwd, now, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1 + received),
            "imported forward row reaped on the new owner {} ms after takeover",
            step * 250
        );
        sent += MSS;
        assert!(
            cache_hit(&mut b, &rev, now, TCP_FLAG_ACK | TCP_PSH, MSS, CLIENT_ISN + 1 + sent),
            "imported reverse row reaped on the new owner {} ms after takeover",
            step * 250
        );
        received += MSS;
        if step % 4 == 0 {
            let _ = a.expire_stale_entries_ha(now, Some(&ha));
            let _ = b.expire_stale_entries_ha(now, Some(&ha));
        }
    }
}

/// #16042 for the completing segment: after B's relayed promotion, A holds
/// the server SYN end the relay carried, so a client ACK with the wrong ack
/// must not complete A (before #18520 A's reverse half held no expectation
/// at all and would fail open); the right ack then completes it.
#[test]
fn relayed_promotion_validates_the_completing_ack_16042_18520() {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    slow_hit(&mut node.b.table, &rev, t0 + MS, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, SERVER_ISN, CLIENT_ISN + 1);
    pump(&mut node);
    assert_eq!(
        node.a.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::HandshakePending.to_wire(),
        "premise: the relayed promotion reached A"
    );
    slow_hit(&mut node.a.table, &fwd, t0 + 2 * MS, TCP_FLAG_ACK, 0, CLIENT_ISN + 1, SERVER_ISN + 999);
    assert!(cache_hit(&mut node.a.table, &fwd, t0 + 3 * MS, TCP_FLAG_ACK, 0, SERVER_ISN + 999));
    assert_eq!(
        node.a.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::HandshakePending.to_wire(),
        "#16042: a completing ACK with the wrong ack must not complete the relayed pair"
    );
    slow_hit(&mut node.a.table, &fwd, t0 + 4 * MS, TCP_FLAG_ACK, 0, CLIENT_ISN + 1, SERVER_ISN + 1);
    assert_eq!(
        node.a.table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Established.to_wire(),
        "control: the correct completing ACK completes it"
    );
}

/// Install one HA-imported (`SyncImport`) row of the test flow on `table`,
/// as the worker's `UpsertSynced` applies an Open/Update/bulk row.
fn import_synced(table: &mut SessionTable, node: &Node, forward: bool, handshake: TcpHandshakeState, session_id: u64, now: u64) {
    let (key, decision, metadata) = if forward {
        (node.forward_key.clone(), node.decision, test_metadata())
    } else {
        (node.reverse_key.clone(), node.reverse_decision, reverse_metadata())
    };
    assert!(table.upsert_synced_with_origin(
        crate::session::SessionInstall {
            key,
            decision,
            metadata,
            source_nat_static: None,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id,
            tcp_close_class: 0,
            tcp_handshake_state: handshake.to_wire(),
            persistent_lease_hold: None,
            fwd_packets: 0,
            rev_packets: 0,
        },
        false,
    ));
}

/// Coordinator follow-up (failback shape): the standby imports the flow's
/// Established Update, then a stale same-incarnation bulk/export Open that
/// still reads Opening (the sender's shared row is restamped only by its
/// 10 s ct-slice). The coordinator fans the RAW row to the workers, so the
/// replica regressed to the 20 s opening window. It must stay Established,
/// be retained (not even idle) through 60 s on standby with no hits, and
/// serve the first post-failback packet.
#[test]
fn established_replica_is_not_regressed_and_survives_standby_until_failback_18520() {
    let node = fresh_node();
    let fwd = node.forward_key.clone();
    let t0 = 1_000 * SEC;
    let peer_id = (1u64 << 63) | 0x44;
    let mut standby = SessionTable::new();
    import_synced(&mut standby, &node, true, TcpHandshakeState::Established, peer_id, t0);
    import_synced(&mut standby, &node, true, TcpHandshakeState::Opening, peer_id, t0 + SEC);
    assert_eq!(
        standby.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Established.to_wire(),
        "#18520: a stale same-incarnation Opening import must not regress an Established replica"
    );
    assert_eq!(standby.timeout_secs_for(&fwd), established_secs());
    // A NEW incarnation (different id) still takes the incoming state.
    let mut reincarnated = SessionTable::new();
    import_synced(&mut reincarnated, &node, true, TcpHandshakeState::Established, peer_id, t0);
    import_synced(&mut reincarnated, &node, true, TcpHandshakeState::Opening, peer_id + 1, t0 + SEC);
    assert_eq!(
        reincarnated.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Opening.to_wire(),
        "control: a new incarnation is not merged"
    );
    let forwarding_here = std::cell::Cell::new(false);
    let forwards = |_: i32| forwarding_here.get();
    let epoch = |_: i32| 0u32;
    let node_served = |_: &SessionKey| crate::session::NodeServedEvidence::default();
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    for sec in 2..=61u64 {
        let _ = standby.expire_stale_entries_ha(t0 + sec * SEC, Some(&ha));
    }
    assert!(
        standby.session_is_live_at(&fwd, t0 + 61 * SEC),
        "#18520: the Established replica must be retained and live after 60 s on standby"
    );
    forwarding_here.set(true);
    assert!(
        cache_hit(&mut standby, &fwd, t0 + 61 * SEC + 100 * MS, TCP_FLAG_ACK | TCP_PSH, MSS, SERVER_ISN + 1),
        "#18520: the first post-failback packet must hit the retained replica"
    );
}

/// Retention ceiling, Opening vs Established (characterization, no hits,
/// no re-imports, standby): an Opening replica idle-crosses at 20 s and is
/// then held, but the packet path already refuses an idle-crossed row (a
/// failback packet misses until the activation re-stamp), and the HOLD
/// ceiling (`STALE_SYNCED_CEILING_MULT` x 20 s from the first hold) reaps it
/// at about 80 s. An Established replica is live throughout (its idle window
/// is 1800 s; its ceiling is 3 x 1800 s of hold).
#[test]
fn standby_retention_ceiling_opening_vs_established_18520() {
    let node = fresh_node();
    let fwd = node.forward_key.clone();
    let t0 = 1_000 * SEC;
    let mut opening = SessionTable::new();
    import_synced(&mut opening, &node, true, TcpHandshakeState::Opening, (1u64 << 63) | 0x45, t0);
    let mut established = SessionTable::new();
    import_synced(&mut established, &node, true, TcpHandshakeState::Established, (1u64 << 63) | 0x46, t0);
    let forwards = |_: i32| false;
    let epoch = |_: i32| 0u32;
    let node_served = |_: &SessionKey| crate::session::NodeServedEvidence::default();
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    let mut opening_reaped_at = None;
    for sec in 1..=120u64 {
        let now = t0 + sec * SEC;
        let _ = opening.expire_stale_entries_ha(now, Some(&ha));
        let _ = established.expire_stale_entries_ha(now, Some(&ha));
        if sec == 60 {
            assert!(opening.entry_with_origin(&fwd).is_some(), "Opening replica is still HELD at 60 s");
            assert!(
                !opening.session_is_live_at(&fwd, now),
                "but it is idle-crossed: a packet arriving now misses"
            );
        }
        if opening_reaped_at.is_none() && opening.entry_with_origin(&fwd).is_none() {
            opening_reaped_at = Some(sec);
        }
        assert!(
            established.session_is_live_at(&fwd, now),
            "Established replica must stay live on standby (t+{sec} s)"
        );
    }
    let reaped = opening_reaped_at.expect("the Opening replica reaps at its hold ceiling");
    let opening_window = opening_secs() as u64;
    let ceiling = STALE_SYNCED_CEILING_MULT * opening_window;
    eprintln!("#18520: standby Opening replica reaped at t+{reaped} s (window {opening_window} s + ceiling {ceiling} s)");
    assert!(
        reaped > opening_window + ceiling && reaped <= opening_window + ceiling + 3,
        "Opening hold ceiling = window + {STALE_SYNCED_CEILING_MULT} x window (reaped at {reaped} s)"
    );
}

/// The completing ACK served from A's flow cache (deferred probe) must
/// publish A's Established HA Update on TX admission and relay the
/// completion, like the slow-path completion does.
#[test]
fn split_handshake_cache_served_completing_ack_publishes_update_18520() {
    let mut node = syn_on_a();
    let (fwd, rev) = (node.forward_key.clone(), node.reverse_key.clone());
    let t0 = node.t0;
    slow_hit(&mut node.b.table, &rev, t0 + MS, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, SERVER_ISN, CLIENT_ISN + 1);
    pump(&mut node);
    let _ = node.a.table.drain_deltas(64);
    assert!(cache_hit(&mut node.a.table, &fwd, t0 + 2 * MS, TCP_FLAG_ACK, 0, SERVER_ISN + 1));
    assert!(
        update_wires(&mut node.a.table, &fwd).contains(&TcpHandshakeState::Established.to_wire()),
        "#18520: the deferred cache-hit completion must publish A's Established Update after admission"
    );
    pump(&mut node);
    assert_pair_established(&node.a.table, &node, "worker A");
    assert_pair_established(&node.b.table, &node, "worker B");
}
