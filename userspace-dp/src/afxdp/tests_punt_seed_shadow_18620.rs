// #18620: a fabric punt seed must not shadow the flow once this node owns the
// seed's egress RG again.
//
// Live shape (loss, trap on master 6cb57a1cff). A demotion-window
// StaleSourceNat revocation removed the flow's rows on the old owner. The
// revocation came from a FIB snapshot that withdrew the RG's connected rows
// before the helper learned the RG was inactive; the Go half of #18620 fixes
// that ordering. The next LAN packet, now with the egress RG on the peer,
// minted a #7770 FabricPuntSeed on the landing worker. Sibling workers kept
// replicas.
//
// When the RG came back, every forward packet hit the seed first: NAT-free,
// FabricRedirect, refreshed by the very traffic it was shadowing. The flow
// stayed silent until the RG moved away again (timeline: node0 w1 L(5/0) ->
// L(56/37) -> L(759/37) -> L(911/80) while the replies stopped).
//
// The cells drive the production poll pipeline on the captured fw1 split
// snapshot (shared with the #18531 cells). They use one table per worker, plus
// the node's shared map.
use super::tests_split_rg_failback_18531::*;
use super::tests_support::*;
use super::*;

const TCP_SYN: u8 = crate::tcp_flags::TCP_SYN;

/// One LAN -> WAN TCP segment on the LAN binding against `shared`, returning
/// the transmit counts (wan, fabric, lan) and the first egress frame.
fn lan_segment(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    shared: &Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
    tcp_flags: u8,
) -> ([u64; 3], Option<Vec<u8>>) {
    lan_segment_to(sessions, forwarding, ha, shared, WAN_HOST, tcp_flags)
}

/// As `lan_segment`, toward `dst`.
fn lan_segment_to(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    shared: &Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
    dst: Ipv4Addr,
    tcp_flags: u8,
) -> ([u64; 3], Option<Vec<u8>>) {
    let frame = build_txn_tcp_syn_frame_v4(
        LAN_HOST,
        dst,
        SPORT,
        DPORT,
        tcp_flags,
        [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
    );
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, tcp_flags, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&LAN_HOST.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    meta.flow_src_port = SPORT;
    meta.flow_dst_port = DPORT;
    meta.config_generation = 7;
    let mut bindings = bindings();
    let (_batch, dbg, egress) = txn_run_multi_binding_at_generations(
        &mut bindings,
        LAN,
        sessions,
        forwarding,
        ha,
        &frame,
        meta,
        shared,
        7,
        0,
    );
    assert_eq!(
        dbg.rx, 1,
        "anti-vacuity: the segment must reach the poll body"
    );
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    (
        [
            tx(&bindings[WAN]),
            tx(&bindings[FABRIC]),
            tx(&bindings[LAN]),
        ],
        egress,
    )
}

/// The IPv4 source of an Ethernet frame, 802.1Q tag or not.
fn ipv4_source(frame: &[u8]) -> Ipv4Addr {
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let l3 = if ethertype == 0x8100 { 18 } else { 14 };
    Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    )
}

fn origin_of(sessions: &SessionTable) -> Option<SessionOrigin> {
    sessions
        .entry_with_origin(&forward_key())
        .map(|(_, _, origin)| origin)
}

/// The flow's first packet during the split (WAN RG on the peer) mints a punt
/// seed on the landing worker: the production #7770 path.
fn seeded_worker(forwarding: &ForwardingState, now_secs: u64) -> SessionTable {
    let mut worker = SessionTable::new();
    worker.set_forwarding_revalidation_gen(7, 9);
    let empty = Arc::new(Mutex::new(FastMap::default()));
    let (tx, _) = lan_segment(
        &mut worker,
        forwarding,
        &split_ha(now_secs),
        &empty,
        TCP_SYN,
    );
    assert_eq!(
        tx,
        [0, 1, 0],
        "fixture: the split-window SYN must be punted over the fabric"
    );
    let (decision, metadata, origin) = worker
        .entry_with_origin(&forward_key())
        .expect("fixture: the punted SYN must leave a seed");
    assert_eq!(
        origin,
        SessionOrigin::FabricPuntSeed,
        "fixture: the row must be a #7770 punt seed"
    );
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert!(
        decision.nat.rewrite_src.is_none(),
        "fixture: a punt seed is NAT-free"
    );
    // The already-redirected arm stamps the fabric parent's RG (none). That is
    // the arm this flow takes, and the retirement must not depend on the stamp.
    assert_eq!(
        metadata.owner_rg_id, 0,
        "fixture: this seed names no egress RG"
    );
    worker
}

/// The peer's authoritative session for the flow, as the HA import publishes
/// it to this node's shared map and to every other worker.
fn peer_session() -> (
    SyncedSessionEntry,
    Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
) {
    let forwarding = fw1_owner_forwarding();
    let entry = imported_pair_entry(&forwarding, forward_key(), IpAddr::V4(SNAT_IP));
    let shared = Arc::new(Mutex::new(FastMap::default()));
    shared
        .lock()
        .expect("shared")
        .insert(entry.key.clone(), entry.clone());
    (entry, shared)
}

/// RED without the #18620 retirement: the RG comes back, and the landing
/// worker's seed is hit before the node's synced session. The packet leaves
/// NAT-free on the WAN (or over the fabric to a peer that no longer forwards
/// the RG). It must instead be served by the synced session, SNATed out the
/// WAN, with the seed gone.
#[test]
fn punt_seed_does_not_shadow_synced_flow_after_rg_returns_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut landing = seeded_worker(&forwarding, now_secs);
    let (entry, shared) = peer_session();

    // A sibling worker holds the replica the import fanned out: the shape of
    // the live timeline (workers 0,3,4,5 R while worker 1 held the seed).
    let mut sibling = SessionTable::new();
    sibling.set_forwarding_revalidation_gen(7, 9);
    apply_commands(
        &mut sibling,
        &forwarding,
        &split_ha(now_secs),
        vec![WorkerCommand::UpsertSynced(entry.clone())],
    );
    assert_eq!(
        origin_of(&sibling),
        Some(SessionOrigin::SyncImport),
        "fixture: the sibling worker holds the peer's session"
    );

    let seed_id = landing.session_id_for(&forward_key());
    let (tx, egress) = lan_segment(
        &mut landing,
        &forwarding,
        &owner_ha(now_secs),
        &shared,
        TCP_ACK,
    );
    assert_eq!(
        tx,
        [1, 0, 0],
        "with the WAN RG back on this node the LAN segment must leave on the WAN \
         (tx wan/fabric/lan), not over the fabric to the demoted peer"
    );
    let egress = egress.expect("the forwarded segment's frame");
    assert_eq!(
        ipv4_source(&egress),
        SNAT_IP,
        "the segment must carry the flow's source NAT; a NAT-free seed would \
         send the LAN address to the WAN"
    );
    let origin = origin_of(&landing).expect("the landing worker serves the flow");
    assert_ne!(
        origin,
        SessionOrigin::FabricPuntSeed,
        "the seed must be retired once its egress RG is local"
    );
    assert_ne!(
        landing.session_id_for(&forward_key()),
        seed_id,
        "the row serving the flow must not be the seed's incarnation"
    );
}

/// Control: while the peer still owns the egress RG (the split the seed was
/// minted for), the seed keeps doing its job. The retirement is keyed on the
/// seed's egress RG being local, not on the seed existing.
#[test]
fn punt_seed_kept_while_peer_owns_egress_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut landing = seeded_worker(&forwarding, now_secs);
    let seed_id = landing.session_id_for(&forward_key());
    let empty = Arc::new(Mutex::new(FastMap::default()));
    let (tx, _) = lan_segment(
        &mut landing,
        &forwarding,
        &split_ha(now_secs),
        &empty,
        TCP_ACK,
    );
    assert_eq!(
        tx,
        [0, 1, 0],
        "mid-split, the flow must still be punted over the fabric"
    );
    assert_eq!(
        origin_of(&landing),
        Some(SessionOrigin::FabricPuntSeed),
        "mid-split, the seed must survive its own flow's traffic"
    );
    // Identity, not just origin: "retired and re-minted on every packet"
    // would also leave a seed here, at the cost of per-packet churn.
    assert_eq!(
        landing.session_id_for(&forward_key()),
        seed_id,
        "mid-split, the seed must be the SAME incarnation, not a re-minted one"
    );
}

/// A seed carrying the HA-inactive arm's STAMP of its would-be egress RG.
/// The retirement asks the FIB and the HA state, not the stamp. Mid-split the
/// owner FIB already names the WAN egress, but RG1 is the peer's, so the seed
/// is kept as the same incarnation. Once RG1 is back it is retired and the
/// flow is served SNATed. (#10507 Cell 7b pins the converse: a stamped seed
/// whose RG is active but whose flow is unroutable is kept.)
#[test]
fn stamped_punt_seed_kept_mid_split_retired_on_return_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut landing = seeded_worker(&forwarding, now_secs);
    let (decision, mut metadata, _) = landing
        .entry_with_origin(&forward_key())
        .expect("fixture: seed present");
    metadata.owner_rg_id = 1;
    assert!(
        landing.refresh_for_ha_transition(&forward_key(), decision, metadata, monotonic_nanos()),
        "fixture: stamp the seed's egress RG in place"
    );
    let (_, stamped, origin) = landing
        .entry_with_origin(&forward_key())
        .expect("fixture: seed present after the stamp");
    assert_eq!(
        (origin, stamped.owner_rg_id),
        (SessionOrigin::FabricPuntSeed, 1),
        "fixture: a stamped punt seed"
    );
    let seed_id = landing.session_id_for(&forward_key());

    let empty = Arc::new(Mutex::new(FastMap::default()));
    let (tx, _) = lan_segment(
        &mut landing,
        &forwarding,
        &split_ha(now_secs),
        &empty,
        TCP_ACK,
    );
    assert_eq!(
        tx,
        [0, 1, 0],
        "mid-split, the stamped seed's flow must still be punted"
    );
    assert_eq!(
        landing.session_id_for(&forward_key()),
        seed_id,
        "mid-split, the stamped seed must be kept as the same incarnation"
    );

    let (_, shared) = peer_session();
    let (tx, egress) = lan_segment(
        &mut landing,
        &forwarding,
        &owner_ha(now_secs),
        &shared,
        TCP_ACK,
    );
    assert_eq!(
        tx,
        [1, 0, 0],
        "with the WAN RG back the segment must leave on the WAN"
    );
    assert_eq!(
        ipv4_source(&egress.expect("the forwarded segment's frame")),
        SNAT_IP,
        "the segment must carry the flow's source NAT, not the seed's NAT-free decision"
    );
    assert_ne!(
        origin_of(&landing),
        Some(SessionOrigin::FabricPuntSeed),
        "the stamped seed must be retired once its egress is local"
    );
}

/// The retirement is scoped to `FabricPuntSeed`. A MissingNeighborSeed is
/// minted by the egress owner itself while its next hop resolves. Its egress is
/// local by construction, and it is its own authority, so it must survive its
/// own flow's next packet.
#[test]
fn missing_neighbor_seed_is_not_retired_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // An on-link WAN address with no neighbor entry.
    let unresolved = Ipv4Addr::new(172, 16, 80, 77);
    let key = crate::session::SessionKey {
        dst_ip: IpAddr::V4(unresolved),
        ..forward_key()
    };
    let mut owner = SessionTable::new();
    owner.set_forwarding_revalidation_gen(7, 9);
    let empty = Arc::new(Mutex::new(FastMap::default()));
    let _ = lan_segment_to(
        &mut owner,
        &forwarding,
        &owner_ha(now_secs),
        &empty,
        unresolved,
        TCP_SYN,
    );
    let origin = owner.entry_with_origin(&key).map(|(_, _, origin)| origin);
    assert_eq!(
        origin,
        Some(SessionOrigin::MissingNeighborSeed),
        "fixture: a SYN to an unresolved on-link address must mint a missing-neighbor seed"
    );
    // An ACK: it can only hit the pending seed or, if the seed were retired,
    // miss and be dropped by the SYN-first guard, leaving no row. (The
    // pending-neighbor path re-mints the seed's incarnation on its own, so the
    // row's ORIGIN is the observable here, not its session id.)
    let _ = lan_segment_to(
        &mut owner,
        &forwarding,
        &owner_ha(now_secs),
        &empty,
        unresolved,
        TCP_ACK,
    );
    assert_eq!(
        owner.entry_with_origin(&key).map(|(_, _, origin)| origin),
        Some(SessionOrigin::MissingNeighborSeed),
        "the missing-neighbor seed must survive its flow's next packet"
    );
}

/// A peer import of the flow replaces the seed even where this node already
/// forwards the egress RG. The guard that refuses to clobber locally owned
/// rows must not count a seed as locally owned.
#[test]
fn peer_import_replaces_punt_seed_on_owner_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut landing = seeded_worker(&forwarding, now_secs);
    let (entry, _) = peer_session();
    apply_commands(
        &mut landing,
        &forwarding,
        &owner_ha(now_secs),
        vec![WorkerCommand::UpsertSynced(entry)],
    );
    assert_eq!(
        origin_of(&landing),
        Some(SessionOrigin::SyncImport),
        "the peer's session must replace the seed"
    );
}

/// A peer delete of the flow removes the seed on the owner; an authored row in
/// the same place still refuses it (#9048/#9714 are unchanged for authority).
#[test]
fn peer_delete_removes_punt_seed_but_not_authored_row_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut landing = seeded_worker(&forwarding, now_secs);
    apply_commands(
        &mut landing,
        &forwarding,
        &owner_ha(now_secs),
        vec![WorkerCommand::DeleteSynced(forward_key())],
    );
    assert_eq!(
        origin_of(&landing),
        None,
        "the peer's delete must remove the seed"
    );

    // Control: the same flow as a locally served session on the owner.
    let (entry, shared) = peer_session();
    let mut authored = SessionTable::new();
    authored.set_forwarding_revalidation_gen(7, 9);
    let (tx, _) = lan_segment(
        &mut authored,
        &forwarding,
        &owner_ha(now_secs),
        &shared,
        TCP_ACK,
    );
    assert_eq!(
        tx,
        [1, 0, 0],
        "fixture: the owner serves the flow from the shared session"
    );
    let served = origin_of(&authored).expect("fixture: the owner materialized the flow");
    assert!(
        !served.yields_to_peer(),
        "fixture: the served row ({served:?}) must be an authored origin"
    );
    let _ = entry;
    let refused_before =
        crate::afxdp::PEER_DELETE_REFUSED_LOCAL_OWNED.load(std::sync::atomic::Ordering::Relaxed);
    apply_commands(
        &mut authored,
        &forwarding,
        &owner_ha(now_secs),
        vec![WorkerCommand::DeleteSynced(forward_key())],
    );
    assert_eq!(
        origin_of(&authored),
        Some(served),
        "an authored row on the owner must still refuse the peer's delete"
    );
    assert!(
        crate::afxdp::PEER_DELETE_REFUSED_LOCAL_OWNED.load(std::sync::atomic::Ordering::Relaxed)
            > refused_before,
        "the refusal must still be counted"
    );
}

/// Review of #18638 (seat V): the retirement must cost nothing on a packet
/// that does not hit a seed. Exploratory timing cell, IGNORED (it gates
/// nothing; read the printed numbers). It times the slow-path session resolve
/// of an ordinary locally-served SNAT flow (`ForwardFlow`):
///   - `hit`: the resolve alone, which is the current head. A non-seed hit pays
///     one origin compare.
///   - `hit+probe`: the resolve plus one `entry_with_origin` probe, the
///     per-packet cost the first #18638 revision paid (an extra table probe and
///     a `SessionMetadata` clone).
///
/// Run: cargo test --release --bin xpf-userspace-dp -- --ignored --exact
///      afxdp::tests_punt_seed_shadow_18620::bench_resolve_non_seed_hit_18620 --nocapture
#[test]
#[ignore]
fn bench_resolve_non_seed_hit_18620() {
    let forwarding = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let ha = owner_ha(now_secs);
    let entry = imported_pair_entry(&forwarding, forward_key(), IpAddr::V4(SNAT_IP));
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    assert!(sessions.install_with_protocol_with_origin(
        entry.key.clone(),
        entry.decision,
        entry.metadata.clone(),
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        TCP_ACK,
    ));
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let nat = Arc::new(Mutex::new(FastMap::default()));
    let wire = Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let peers: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let neighbors = Arc::new(ShardedNeighborMap::default());
    let flow = SessionFlow {
        src_ip: entry.key.src_ip,
        dst_ip: entry.key.dst_ip,
        forward_key: entry.key.clone(),
    };
    let key = entry.key.clone();
    let one = |sessions: &mut SessionTable, probe: bool| {
        if probe {
            std::hint::black_box(sessions.entry_with_origin(&key));
        }
        let refs = crate::afxdp::session_glue::SharedSessionRefs::detached(
            &shared,
            &nat,
            &wire,
            &indexes,
            &peers,
            empty_worker_commands_by_id(),
        )
        .with_conntrack_tick(
            crate::afxdp::session_glue::ConntrackFds { v4: -1, v6: -1 },
            crate::afxdp::session_glue::Tick::from_ns(now_ns),
        );
        let resolved =
            crate::afxdp::session_glue::resolve_flow_session_decision_with_conntrack_and_payload_and_ack(
                sessions,
                crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
                refs,
                &forwarding,
                &ha,
                &neighbors,
                &flow,
                PROTO_TCP,
                TCP_ACK,
                0,
                LAN_IFINDEX,
                0,
                false,
                false,
                0,
                0,
                None,
                None,
                false,
                None,
            );
        assert!(
            std::hint::black_box(resolved).is_some(),
            "the ForwardFlow must hit"
        );
    };
    const N: u32 = 200_000;
    for (label, probe) in [
        ("hit", false),
        ("hit+probe", true),
        ("hit", false),
        ("hit+probe", true),
    ] {
        let mut rounds = Vec::new();
        for _ in 0..7 {
            let start = std::time::Instant::now();
            for _ in 0..N {
                one(&mut sessions, probe);
            }
            rounds.push(start.elapsed().as_nanos() as f64 / f64::from(N));
        }
        rounds.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        eprintln!(
            "#18620 bench {label:>10}: median {:.1} ns/op (min {:.1}, max {:.1}) over 7 x {N}",
            rounds[3], rounds[0], rounds[6]
        );
    }
    // The removed per-packet work on its own: one probe and its metadata clone.
    let mut rounds = Vec::new();
    for _ in 0..7 {
        let start = std::time::Instant::now();
        for _ in 0..N {
            std::hint::black_box(sessions.entry_with_origin(std::hint::black_box(&key)));
        }
        rounds.push(start.elapsed().as_nanos() as f64 / f64::from(N));
    }
    rounds.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    eprintln!(
        "#18620 bench {:>10}: median {:.1} ns/op (min {:.1}, max {:.1}) over 7 x {N}",
        "probe", rounds[3], rounds[0], rounds[6]
    );
}
