// Probe: a fresh SNAT flow whose FIRST reply is polled by a worker that does
// not hold the forward row.
//
// Live (#18683 run 3, tcp, 0.0.29548): on the owner of every RG, in steady
// state, `xpf_userspace_snat_revoked_sessions_total` rose by one within a
// second of test-failover opening its pool-mode SNAT flows (10.0.62.240 ->
// :5210), with no Close logged. A revocation without a Close fits the
// canonical-less reverse arm of the first-hit source-NAT revalidation: no
// local forward companion, so the reply is judged sessionlessly and dropped.
//
// RSS hashes the reply tuple independently of the forward tuple, so a fresh
// flow's first reply lands on another worker most of the time. These cells
// create the flow on worker A and poll its first reply on worker B, which
// shares A's shared session maps but holds no rows of its own.
use super::tests_split_rg_failback_18531::*;
use super::tests_support::*;
use super::*;

const POOL_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 241);
const IFACE_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SYN: u8 = crate::tcp_flags::TCP_SYN;
const SYN_ACK: u8 = crate::tcp_flags::TCP_SYN | crate::tcp_flags::TCP_ACK;

struct Shared {
    sessions: Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
    nat: Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
    wire: Arc<Mutex<FastMap<crate::session::SessionKey, SyncedSessionEntry>>>,
    owner_rg: SharedSessionOwnerRgIndexes,
}

impl Shared {
    fn new() -> Self {
        Shared {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            wire: Arc::new(Mutex::new(FastMap::default())),
            owner_rg: SharedSessionOwnerRgIndexes::default(),
        }
    }
}

struct Poll {
    missing_neigh: u64,
    session_hit: u64,
    session_miss: u64,
    snat_revoked: u64,
    tx: [u64; 3],
    closes: usize,
}

fn poll(
    sessions: &mut SessionTable,
    shared: &Shared,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    ingress: usize,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Poll {
    poll_at(sessions, shared, forwarding, ha, ingress, frame, meta, 7)
}

#[expect(clippy::too_many_arguments, reason = "test harness")]
fn poll_at(
    sessions: &mut SessionTable,
    shared: &Shared,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    ingress: usize,
    frame: &[u8],
    mut meta: UserspaceDpMeta,
    config_generation: u64,
) -> Poll {
    meta.config_generation = config_generation;
    let mut bindings = bindings();
    let (_batch, dbg, _egress) = txn_run_multi_binding_with_shared_maps(
        &mut bindings,
        ingress,
        sessions,
        forwarding,
        ha,
        frame,
        meta,
        &shared.sessions,
        &shared.nat,
        &shared.wire,
        &shared.owner_rg,
        config_generation,
        1,
    );
    assert_eq!(
        dbg.rx, 1,
        "anti-vacuity: the descriptor must reach the poll body"
    );
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    let closes = sessions
        .drain_deltas(64)
        .iter()
        .filter(|d| d.kind == crate::session::SessionDeltaKind::Close)
        .count();
    Poll {
        missing_neigh: dbg.missing_neigh,
        session_hit: dbg.session_hit,
        session_miss: dbg.session_miss,
        snat_revoked: dbg.snat_revoked_sessions,
        tx: [
            tx(&bindings[WAN]),
            tx(&bindings[FABRIC]),
            tx(&bindings[LAN]),
        ],
        closes,
    }
}

fn lan_syn(client: Ipv4Addr) -> (Vec<u8>, UserspaceDpMeta) {
    let frame = build_txn_tcp_syn_frame_v4(
        client,
        WAN_HOST,
        SPORT,
        5210,
        SYN,
        [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
    );
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, SYN, frame.len() as u16);
    set_flow(
        &mut meta,
        IpAddr::V4(client),
        IpAddr::V4(WAN_HOST),
        SPORT,
        5210,
    );
    (frame, meta)
}

fn wan_syn_ack(translated: Ipv4Addr, port: u16) -> (Vec<u8>, UserspaceDpMeta) {
    let frame = build_txn_tcp_syn_frame_v4(
        WAN_HOST,
        translated,
        5210,
        port,
        SYN_ACK,
        [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01],
    );
    let mut meta = txn_meta_v4(WAN_UNIT_IFINDEX as u32, SYN_ACK, frame.len() as u16);
    meta.ingress_vlan_id = 80;
    set_flow(
        &mut meta,
        IpAddr::V4(WAN_HOST),
        IpAddr::V4(translated),
        5210,
        port,
    );
    (frame, meta)
}

/// Create the flow on worker A (the SYN), then poll its first reply on
/// worker A or worker B. Returns (A's create poll, the reply poll,
/// translated address/port).
fn first_reply(client: Ipv4Addr, reply_on_b: bool) -> (Poll, Poll, Ipv4Addr, u16) {
    first_reply_with(client, reply_on_b, |_, _| {})
}

/// As `first_reply`, with `tamper` applied to the shared session map (and
/// the forward key) after the flow is created and before its reply.
fn first_reply_with(
    client: Ipv4Addr,
    reply_on_b: bool,
    tamper: impl FnOnce(
        &mut FastMap<crate::session::SessionKey, SyncedSessionEntry>,
        &crate::session::SessionKey,
    ),
) -> (Poll, Poll, Ipv4Addr, u16) {
    let mut forwarding = fw1_owner_forwarding();
    // The captured snapshot learned no neighbor for the pool clients
    // (10.0.61.240/28); give the client one so a delivered reply is visible
    // end to end (without it the reply stops at MissingNeighbor, a harness
    // artefact, not part of #18710).
    forwarding
        .neighbors
        .entry((LAN_IFINDEX, IpAddr::V4(client)))
        .or_insert(NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c],
        });
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = owner_ha(now_secs);
    let shared = Shared::new();
    let mut a = SessionTable::new();
    a.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = lan_syn(client);
    let created = poll(&mut a, &shared, &forwarding, &ha, LAN, &frame, meta);
    let mut key = forward_key();
    key.src_ip = IpAddr::V4(client);
    key.dst_port = 5210;
    let (decision, _, _) = a
        .entry_with_origin(&key)
        .unwrap_or_else(|| panic!("fixture: worker A created the forward row ({client})"));
    let IpAddr::V4(translated) = decision
        .nat
        .rewrite_src
        .expect("fixture: source-translated")
    else {
        panic!("v4")
    };
    let port = decision.nat.rewrite_src_port.unwrap_or(SPORT);
    assert!(
        shared.sessions.lock().unwrap().contains_key(&key),
        "premise: the creating worker published the forward row to the shared map"
    );
    tamper(&mut shared.sessions.lock().unwrap(), &key);
    let mut b = SessionTable::new();
    b.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = wan_syn_ack(translated, port);
    let reply = if reply_on_b {
        poll(&mut b, &shared, &forwarding, &ha, WAN, &frame, meta)
    } else {
        poll(&mut a, &shared, &forwarding, &ha, WAN, &frame, meta)
    };
    (created, reply, translated, port)
}

/// Control: the first reply polled by the worker that created the flow is
/// judged against its local forward row and delivered (interface SNAT).
#[test]
fn first_reply_on_the_creating_worker_is_delivered_18710() {
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        let (created, reply, _, _) = first_reply(client, false);
        assert_eq!(created.session_miss, 1, "{label}: the SYN creates the flow");
        assert_eq!(
            reply.session_hit, 1,
            "{label}: the reply hits the reverse row"
        );
        assert_eq!((reply.snat_revoked, reply.closes), (0, 0), "{label}");
        assert_eq!(reply.tx, [0, 0, 1], "{label}: delivered to the LAN host");
    }
}

/// #18710: the first reply polled by a worker that does not hold the forward
/// row yet (it has not drained the creating worker's replica) must not be
/// dropped by the canonical-less reverse arm. RED today for interface and
/// pool SNAT: `snat_revoked = 1`, no Close, nothing transmitted.
#[test]
fn first_reply_on_another_worker_is_not_revoked_18710() {
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        let (_, reply, _, _) = first_reply(client, true);
        assert_eq!(
            reply.session_hit, 1,
            "{label}: the reply hits the shared reverse row"
        );
        assert_eq!(
            (reply.snat_revoked, reply.closes),
            (0, 0),
            "{label}: a forward row not materialized yet is no ground to revoke"
        );
    }
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        let (_, reply, _, _) = first_reply(client, true);
        assert_eq!(reply.tx, [0, 0, 1], "{label}: delivered to the LAN host");
    }
}

/// The live reply resolver can synthesize a missing reverse row from a shared
/// forward NAT match. That row must retain the owner's complete session ID,
/// not allocate in the replying worker's namespace.
#[test]
fn live_reply_reverse_synthesis_preserves_full_forward_id_18718() {
    let mut forwarding = fw1_owner_forwarding();
    forwarding
        .neighbors
        .entry((LAN_IFINDEX, IpAddr::V4(POOL_CLIENT)))
        .or_insert(NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c],
        });
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = owner_ha(now_secs);
    let shared = Shared::new();
    let mut a = SessionTable::new();
    a.set_session_id_namespace(0, 0);
    a.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = lan_syn(POOL_CLIENT);
    let created = poll(&mut a, &shared, &forwarding, &ha, LAN, &frame, meta);
    assert_eq!(created.session_miss, 1, "A creates the pool-SNAT forward");

    let mut forward_key = forward_key();
    forward_key.src_ip = IpAddr::V4(POOL_CLIENT);
    forward_key.dst_port = 5210;
    let (decision, _, _) = a
        .entry_with_origin(&forward_key)
        .expect("fixture: A owns the forward row");
    let forward_id = a.session_id_for(&forward_key);
    assert_ne!(forward_id, 0, "fixture: owner forward has a stable ID");
    let IpAddr::V4(translated) = decision.nat.rewrite_src.expect("pool SNAT address") else {
        panic!("fixture: IPv4 pool SNAT")
    };
    let translated_port = decision.nat.rewrite_src_port.unwrap_or(SPORT);
    let reverse_key = crate::session::reverse_session_key(&forward_key, decision.nat);
    let removed = shared
        .sessions
        .lock()
        .expect("shared sessions")
        .remove(&reverse_key)
        .expect("fixture: remove only the published reverse row");
    assert_eq!(
        removed.session_id, forward_id,
        "owner reverse already carries the full forward identity"
    );

    let mut b = SessionTable::new();
    b.set_session_id_namespace(0, 1);
    b.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = wan_syn_ack(translated, translated_port);
    let reply = poll(&mut b, &shared, &forwarding, &ha, WAN, &frame, meta);
    assert_eq!(reply.tx, [0, 0, 1], "B serves the real reply");
    assert_eq!((reply.snat_revoked, reply.closes), (0, 0));
    assert_eq!(
        b.session_id_for(&reverse_key),
        forward_id,
        "B's live-synthesized reverse adopts the owner's full ID"
    );
    let shared_reverse_id = shared
        .sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .map(|entry| entry.session_id)
        .expect("B republishes the synthesized reverse");
    assert_eq!(shared_reverse_id, forward_id);
}

/// Control: a reply whose forward companion is genuinely absent (no local
/// row and no shared row) still fails closed, as before.
#[test]
fn first_reply_with_no_companion_anywhere_still_revokes_18710() {
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        let (_, reply, _, _) = first_reply_with(client, true, |shared, key| {
            shared.remove(key);
        });
        assert_eq!(
            reply.session_hit, 1,
            "{label}: the reply hits the shared reverse row"
        );
        assert_eq!(
            reply.snat_revoked, 1,
            "{label}: no companion anywhere keeps the fail-closed arm"
        );
        assert_eq!(reply.tx, [0, 0, 0], "{label}: dropped");
    }
}

/// Control: a PEER-SYNCED shared companion carries the peer's line, so the
/// shared judgment does not apply to it and the sessionless arm decides, as
/// before.
#[test]
fn first_reply_with_a_peer_synced_shared_companion_keeps_the_old_arm_18710() {
    let (_, reply, _, _) = first_reply_with(IFACE_CLIENT, true, |shared, key| {
        if let Some(entry) = shared.get_mut(key) {
            entry.origin = SessionOrigin::SyncImport;
        }
    });
    assert_eq!(
        reply.session_hit, 1,
        "the reply hits the shared reverse row"
    );
    assert_eq!(
        reply.snat_revoked, 1,
        "the peer-synced companion is not judged from the shared map"
    );
}

/// Characterization (printed, not asserted): the outcome matrix the #18710
/// issue quotes.
#[test]
fn fresh_flow_first_reply_probe() {
    for (label, client) in [("pool", POOL_CLIENT), ("interface", IFACE_CLIENT)] {
        for reply_on_b in [false, true] {
            let (created, reply, translated, port) = first_reply(client, reply_on_b);
            eprintln!(
                "PROBE {label} reply_on_{}: create miss={} tx={:?}; translated {translated}:{port}; \
                 reply hit={} miss={} snat_revoked={} closes={} tx={:?} missing_neigh={}",
                if reply_on_b { "B" } else { "A" },
                created.session_miss,
                created.tx,
                reply.session_hit,
                reply.session_miss,
                reply.snat_revoked,
                reply.closes,
                reply.tx,
                reply.missing_neigh
            );
        }
    }
}

/// Positive control: a translation the live config no longer produces (the
/// SNAT rules were withdrawn by a commit after the flow was created) still
/// revokes on the first reply. On the creating worker the local pair is torn
/// down (one Close); on a worker that judges the shared row the reply is
/// dropped and nothing local is torn down.
#[test]
fn withdrawn_translation_still_revokes_on_either_worker_18710() {
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        for reply_on_b in [false, true] {
            let mut forwarding = fw1_owner_forwarding();
            forwarding
                .neighbors
                .entry((LAN_IFINDEX, IpAddr::V4(client)))
                .or_insert(NeighborEntry { mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c] });
            let mut withdrawn = fw1_owner_forwarding();
            withdrawn
                .neighbors
                .entry((LAN_IFINDEX, IpAddr::V4(client)))
                .or_insert(NeighborEntry { mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c] });
            withdrawn.source_nat_rules.clear();
            let now_secs = monotonic_nanos() / 1_000_000_000;
            let ha = owner_ha(now_secs);
            let shared = Shared::new();
            let mut a = SessionTable::new();
            a.set_forwarding_revalidation_gen(7, 9);
            let (frame, meta) = lan_syn(client);
            poll(&mut a, &shared, &forwarding, &ha, LAN, &frame, meta);
            let mut key = forward_key();
            key.src_ip = IpAddr::V4(client);
            key.dst_port = 5210;
            let (decision, _, _) = a.entry_with_origin(&key).expect("fixture: forward row");
            let IpAddr::V4(translated) = decision.nat.rewrite_src.expect("translated") else {
                panic!("v4")
            };
            let port = decision.nat.rewrite_src_port.unwrap_or(SPORT);
            let mut b = SessionTable::new();
            b.set_forwarding_revalidation_gen(8, 9);
            a.set_forwarding_revalidation_gen(8, 9);
            let (frame, meta) = wan_syn_ack(translated, port);
            let table = if reply_on_b { &mut b } else { &mut a };
            let reply = poll_at(table, &shared, &withdrawn, &ha, WAN, &frame, meta, 8);
            let on = if reply_on_b { "B" } else { "A" };
            assert_eq!(reply.snat_revoked, 1, "{label} on {on}: a withdrawn translation revokes");
            assert_eq!(reply.tx, [0, 0, 0], "{label} on {on}: the reply is dropped");
            if reply_on_b {
                assert_eq!(reply.closes, 0, "{label} on B: nothing local to tear down");
            } else {
                assert_eq!(
                    (reply.closes, a.len()),
                    (1, 0),
                    "{label} on A: the local pair is torn down"
                );
            }
        }
    }
}

/// Review fold (AC #1, flow identity): the shared row at the original tuple
/// can belong to a NEWER flow on the same client tuple with a different
/// translation. A reply for the OLDER translation must not be validated by
/// it: the shared judgment applies only when the shared row's own
/// translation maps back to this reply's reverse key; otherwise the
/// sessionless arm decides, as before.
#[test]
fn first_reply_for_another_flows_translation_keeps_the_old_arm_18710() {
    for (label, client) in [("interface", IFACE_CLIENT), ("pool", POOL_CLIENT)] {
        let (_, reply, _, _) = first_reply_with(client, true, |shared, key| {
            let entry = shared.get_mut(key).expect("fixture: shared forward row");
            let port = entry.decision.nat.rewrite_src_port.unwrap_or(SPORT);
            entry.decision.nat.rewrite_src_port = Some(port.wrapping_add(1));
        });
        assert_eq!(
            reply.session_hit, 1,
            "{label}: the reply hits the shared reverse row"
        );
        assert_eq!(
            reply.snat_revoked, 1,
            "{label}: a shared row of another translation is not this flow's companion"
        );
        assert_eq!(reply.tx, [0, 0, 0], "{label}: dropped");
    }
}

/// #18718: B retains worker 0's reverse half of a dynamic flow while A's
/// worker 1 replaces the same original tuple with a static mapping to the
/// exact same translated tuple. B must not validate its old reverse
/// incarnation using the new forward row's static provenance, even when
/// both workers' counters start at the same value.
#[test]
fn old_dynamic_reverse_does_not_borrow_same_tuple_static_forward_18710() {
    let mut dynamic_forwarding = fw1_owner_forwarding();
    dynamic_forwarding
        .neighbors
        .entry((LAN_IFINDEX, IpAddr::V4(POOL_CLIENT)))
        .or_insert(NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c],
        });
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = owner_ha(now_secs);
    let shared = Shared::new();
    let mut a0 = SessionTable::new();
    a0.set_session_id_namespace(0, 0);
    a0.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = lan_syn(POOL_CLIENT);
    let old_create = poll(&mut a0, &shared, &dynamic_forwarding, &ha, LAN, &frame, meta);
    assert_eq!(old_create.session_miss, 1, "old dynamic flow is polled");

    let mut key = forward_key();
    key.src_ip = IpAddr::V4(POOL_CLIENT);
    key.dst_port = 5210;
    let (old_decision, _, _) = a0
        .entry_with_origin(&key)
        .expect("fixture: worker 0 created the old dynamic forward row");
    let old_nat = old_decision.nat;
    let old_reverse_key = crate::session::reverse_session_key(&key, old_nat);
    let (old_reverse, old_forward_id, old_forward_static) = {
        let map = shared.sessions.lock().expect("shared sessions");
        let old_forward = map.get(&key).expect("old forward row is shared");
        (
            map.get(&old_reverse_key)
                .cloned()
                .expect("old reverse row is shared"),
            old_forward.session_id,
            old_forward.source_nat_static,
        )
    };
    assert_eq!(old_reverse.origin, SessionOrigin::ReverseFlow);
    assert_eq!(
        a0.session_id_for(&old_reverse_key),
        old_reverse.session_id,
        "worker 0's local and published reverse identities agree"
    );
    assert_eq!(
        old_reverse.session_id, old_forward_id,
        "the old reverse carries worker 0's full forward incarnation"
    );
    assert_eq!(old_forward_static, Some(false), "old flow is dynamic SNAT");
    // B has drained the old reverse replica, but not the old forward row.
    let mut b = SessionTable::new();
    b.set_forwarding_revalidation_gen(7, 9);
    apply_commands(
        &mut b,
        &dynamic_forwarding,
        &ha,
        vec![WorkerCommand::UpsertSynced(
            crate::afxdp::shared_ops::synced_replica_entry(&old_reverse),
        )],
    );
    let old_b_reverse_id = b.session_id_for(&old_reverse_key);
    assert_ne!(old_b_reverse_id, 0, "B materialized the old reverse row");
    assert_eq!(
        old_b_reverse_id,
        old_reverse.session_id,
        "B adopts the published reverse identity"
    );

    // Retire A's old pair and its shared rows, preserving B's already-drained
    // reverse. The next real poll creates a replacement with the exact same
    // original tuple.
    a0.delete(&key);
    a0.delete(&old_reverse_key);
    let _ = crate::afxdp::shared_ops::remove_shared_session_if(
        &shared.sessions,
        &shared.nat,
        &shared.wire,
        &shared.owner_rg,
        &key,
        |entry| entry.session_id == old_forward_id,
    );
    let _ = crate::afxdp::shared_ops::remove_shared_session_if(
        &shared.sessions,
        &shared.nat,
        &shared.wire,
        &shared.owner_rg,
        &old_reverse_key,
        |entry| entry.session_id == old_reverse.session_id,
    );

    let IpAddr::V4(translated) = old_nat.rewrite_src.expect("dynamic SNAT address") else {
        panic!("fixture: IPv4 dynamic SNAT")
    };
    let translated_port = old_nat.rewrite_src_port.unwrap_or(SPORT);
    let mut static_forwarding = dynamic_forwarding.clone();
    static_forwarding.static_nat = crate::nat::StaticNatTable::from_snapshots(
        &[crate::StaticNATRuleSnapshot {
            name: "same-tuple-static-replacement".to_string(),
            from_zone: "wan".to_string(),
            external_ip: translated.to_string(),
            internal_ip: POOL_CLIENT.to_string(),
            match_destination_port: translated_port,
            mapped_port: SPORT,
            ..Default::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let scope = crate::afxdp::forwarding::nat_scope_ctx_for_flow(
        &static_forwarding,
        LAN_IFINDEX,
        0,
        None,
        WAN_UNIT_IFINDEX,
        key.routing_domain,
    );
    let (static_nat, _) = static_forwarding
        .static_nat
        .match_snat_with_counter_scoped(
            key.src_ip,
            key.src_port,
            Some(key.protocol),
            Some(key.dst_ip),
            "wan",
            scope.egress_ifname,
            scope.egress_routing_instance,
        )
        .expect("fixture: static SNAT matches the same original tuple");
    assert_eq!(static_nat.rewrite_src, Some(IpAddr::V4(translated)));
    assert_eq!(
        static_nat.rewrite_src_port,
        old_nat.rewrite_src_port,
        "fixture: static SNAT preserves the dynamic translated port"
    );
    let mut a1 = SessionTable::new();
    a1.set_session_id_namespace(0, 1);
    a1.set_forwarding_revalidation_gen(8, 9);
    let (frame, meta) = lan_syn(POOL_CLIENT);
    let new_create = poll_at(
        &mut a1,
        &shared,
        &static_forwarding,
        &ha,
        LAN,
        &frame,
        meta,
        8,
    );
    assert_eq!(new_create.session_miss, 1, "replacement is created by the poll path");
    let new_forward = shared
        .sessions
        .lock()
        .expect("shared sessions")
        .get(&key)
        .cloned()
        .expect("static replacement is shared");
    assert_ne!(new_forward.session_id, old_forward_id, "the forward incarnation changed");
    assert_eq!(
        old_forward_id & 0x0000_FFFF_FFFF_FFFF,
        new_forward.session_id & 0x0000_FFFF_FFFF_FFFF,
        "fixture: worker counters overlap"
    );
    assert_ne!(
        old_forward_id >> 48,
        new_forward.session_id >> 48,
        "fixture: forward IDs differ only by worker namespace"
    );
    assert_eq!(new_forward.source_nat_static, Some(true), "the replacement is static SNAT");
    let new_reverse_key =
        crate::session::reverse_session_key(&key, new_forward.decision.nat);
    let new_reverse = shared
        .sessions
        .lock()
        .expect("shared sessions")
        .get(&new_reverse_key)
        .cloned()
        .expect("static replacement reverse is shared");
    assert_eq!(
        new_reverse.session_id, new_forward.session_id,
        "the new reverse carries worker 1's full forward incarnation"
    );
    assert_ne!(
        new_reverse.session_id, old_reverse.session_id,
        "same low counter with a different worker namespace is a new incarnation"
    );
    assert_eq!(
        a1.session_id_for(&new_reverse_key),
        new_reverse.session_id,
        "worker 1's local and shared replacement reverse identities agree"
    );
    assert_eq!(new_forward.decision.nat.rewrite_src, Some(IpAddr::V4(translated)));
    assert_eq!(
        new_forward.decision.nat.rewrite_src_port.unwrap_or(SPORT),
        translated_port,
        "the replacement has the exact old translated tuple"
    );

    let (frame, meta) = wan_syn_ack(translated, translated_port);
    let reply = poll_at(
        &mut b,
        &shared,
        &static_forwarding,
        &ha,
        WAN,
        &frame,
        meta,
        8,
    );
    assert_eq!(reply.session_hit, 1, "B's retained old reverse row is hit");
    assert_eq!(reply.snat_revoked, 1, "the new static row cannot authorize old dynamic state");
    assert_eq!(reply.tx, [0, 0, 0], "B drops the stale reply");
}

/// Review fold (AC #2, predicate breadth): only a forward row this node
/// CREATED is judged from the shared map — `ForwardFlow` or
/// `MissingNeighborSeed`. Every other origin, and a reverse row, keeps the
/// sessionless arm.
#[test]
fn first_reply_judges_only_creating_flow_origins_18710() {
    let cases: [(&str, SessionOrigin, bool, u64); 8] = [
        ("forward_flow", SessionOrigin::ForwardFlow, false, 0),
        ("missing_neighbor_seed", SessionOrigin::MissingNeighborSeed, false, 0),
        ("shared_promote", SessionOrigin::SharedPromote, false, 1),
        ("fabric_punt_seed", SessionOrigin::FabricPuntSeed, false, 1),
        ("local_miss", SessionOrigin::LocalMiss, false, 1),
        ("tun_origin", SessionOrigin::TunOrigin, false, 1),
        ("reverse_flow", SessionOrigin::ReverseFlow, false, 1),
        ("forward_flow marked reverse", SessionOrigin::ForwardFlow, true, 1),
    ];
    for (label, origin, is_reverse, revoked) in cases {
        let (_, reply, _, _) = first_reply_with(IFACE_CLIENT, true, |shared, key| {
            let entry = shared.get_mut(key).expect("fixture: shared forward row");
            entry.origin = origin;
            entry.metadata.is_reverse = is_reverse;
        });
        assert_eq!(reply.session_hit, 1, "{label}: the reply hits");
        assert_eq!(reply.snat_revoked, revoked, "{label}");
        let delivered = if revoked == 0 { 1 } else { 0 };
        assert_eq!(reply.tx, [0, 0, delivered], "{label}");
    }
}

/// Review fold (AC #3a): the creating worker's replica reaches worker B
/// AFTER B already judged and delivered a reply from the shared row. The
/// late replica must not double the pair or tear anything down, and the
/// next reply hits B's own pair.
#[test]
fn replica_after_a_shared_judged_reply_leaves_one_pair_18710() {
    let mut forwarding = fw1_owner_forwarding();
    forwarding
        .neighbors
        .entry((LAN_IFINDEX, IpAddr::V4(IFACE_CLIENT)))
        .or_insert(NeighborEntry { mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c] });
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = owner_ha(now_secs);
    let shared = Shared::new();
    let mut a = SessionTable::new();
    a.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = lan_syn(IFACE_CLIENT);
    poll(&mut a, &shared, &forwarding, &ha, LAN, &frame, meta);
    let mut key = forward_key();
    key.src_ip = IpAddr::V4(IFACE_CLIENT);
    key.dst_port = 5210;
    let (decision, _, _) = a.entry_with_origin(&key).expect("fixture: forward row");
    let IpAddr::V4(translated) = decision.nat.rewrite_src.expect("translated") else {
        panic!("v4")
    };
    let port = decision.nat.rewrite_src_port.unwrap_or(SPORT);
    let reverse_key = crate::session::reverse_session_key(&key, decision.nat);
    let mut b = SessionTable::new();
    b.set_forwarding_revalidation_gen(7, 9);
    let (frame, meta) = wan_syn_ack(translated, port);
    let first = poll(&mut b, &shared, &forwarding, &ha, WAN, &frame, meta);
    assert_eq!(
        (first.snat_revoked, first.closes, first.tx),
        (0, 0, [0, 0, 1]),
        "premise: B judged the first reply from the shared row and delivered it"
    );
    // The creating worker's replica commands, drained late on B.
    let (forward_entry, reverse_entry) = {
        let map = shared.sessions.lock().unwrap();
        (
            map.get(&key).cloned().expect("shared forward row"),
            map.get(&reverse_key).cloned().expect("shared reverse row"),
        )
    };
    apply_commands(
        &mut b,
        &forwarding,
        &ha,
        vec![
            WorkerCommand::UpsertSynced(crate::afxdp::shared_ops::synced_replica_entry(&forward_entry)),
            WorkerCommand::UpsertSynced(crate::afxdp::shared_ops::synced_replica_entry(&reverse_entry)),
        ],
    );
    let late_closes = b
        .drain_deltas(64)
        .iter()
        .filter(|d| d.kind == crate::session::SessionDeltaKind::Close)
        .count();
    assert_eq!(late_closes, 0, "the late replica tears nothing down");
    assert!(
        b.last_seen_ns(&key).is_some() && b.last_seen_ns(&reverse_key).is_some(),
        "B now holds the pair"
    );
    assert_eq!(b.len(), 2, "one pair on B, not two");
    let (frame, meta) = wan_syn_ack(translated, port);
    let second = poll(&mut b, &shared, &forwarding, &ha, WAN, &frame, meta);
    assert_eq!(
        (second.session_hit, second.snat_revoked, second.closes, second.tx),
        (1, 0, 0, [0, 0, 1]),
        "the next reply hits B's own pair and is delivered"
    );
}

/// An ICMPv4 echo frame of `icmp_type` (8 request, 0 reply) with identifier
/// `id`, untagged.
fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: u8, id: u16, dst_mac: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, dst_mac, [0x00, 0x25, 0x90, 0x12, 0x34, 0x56], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    let id = id.to_be_bytes();
    frame.extend_from_slice(&[icmp_type, 0, 0x00, 0x00, id[0], id[1], 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

fn icmp_meta(ingress_ifindex: i32, frame_len: usize, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> UserspaceDpMeta {
    let mut meta = txn_meta_v4(ingress_ifindex as u32, 0, frame_len as u16);
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    set_flow(&mut meta, IpAddr::V4(src), IpAddr::V4(dst), sport, dport);
    meta
}

/// Review fold (AC #3b): an ICMP echo. One of the two live increments in
/// #18683 run 3 was a new ICMP session's first reply. The echo request is
/// created on worker A; its reply is polled on A and on B.
#[test]
fn first_icmp_echo_reply_on_another_worker_is_not_revoked_18710() {
    for reply_on_b in [false, true] {
        let mut forwarding = fw1_owner_forwarding();
        forwarding
            .neighbors
            .entry((LAN_IFINDEX, IpAddr::V4(IFACE_CLIENT)))
            .or_insert(NeighborEntry { mac: [0x10, 0x66, 0x6a, 0xfd, 0x4b, 0x5c] });
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha = owner_ha(now_secs);
        let shared = Shared::new();
        let mut a = SessionTable::new();
        a.set_forwarding_revalidation_gen(7, 9);
        let id = 0x1234u16;
        let frame = icmp_echo(IFACE_CLIENT, WAN_HOST, 8, id, [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03]);
        let meta = icmp_meta(LAN_IFINDEX, frame.len(), IFACE_CLIENT, WAN_HOST, id, 0);
        let created = poll(&mut a, &shared, &forwarding, &ha, LAN, &frame, meta);
        assert_eq!(created.tx, [1, 0, 0], "premise: the echo request is forwarded to the WAN");
        let key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(IFACE_CLIENT),
            dst_ip: IpAddr::V4(WAN_HOST),
            src_port: id,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let (decision, _, _) = a
            .entry_with_origin(&key)
            .expect("fixture: worker A created the ICMP forward row");
        let IpAddr::V4(translated) = decision.nat.rewrite_src.expect("source-translated") else {
            panic!("v4")
        };
        // The reply's flow, computed by hand rather than by the session
        // layer's own `reverse_session_key` (an oracle that shares the code
        // under test cannot catch it): addresses swapped, the translated
        // identifier in the source-port slot, and the destination-port slot
        // unchanged (0 for an echo). The ICMP key convention keeps ports
        // unswapped; `icmp_echo_reverse_key_from_first_principles_18710`
        // pins it independently.
        let reply_id = decision.nat.rewrite_src_port.unwrap_or(id);
        let mut b = SessionTable::new();
        b.set_forwarding_revalidation_gen(7, 9);
        let frame = icmp_echo(WAN_HOST, translated, 0, reply_id, [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01]);
        let mut meta = icmp_meta(WAN_UNIT_IFINDEX, frame.len(), WAN_HOST, translated, reply_id, 0);
        meta.ingress_vlan_id = 80;
        let table = if reply_on_b { &mut b } else { &mut a };
        let reply = poll(table, &shared, &forwarding, &ha, WAN, &frame, meta);
        let on = if reply_on_b { "B" } else { "A" };
        assert_eq!(reply.session_hit, 1, "on {on}: the echo reply hits");
        assert_eq!((reply.snat_revoked, reply.closes), (0, 0), "on {on}: not revoked");
        assert_eq!(reply.tx, [0, 0, 1], "on {on}: delivered to the LAN host");
    }
}

/// Review fold (independent oracle for the ICMP cell): the reverse key of an
/// ICMP echo flow, written down from first principles and compared against
/// `reverse_session_key`. The echo reply (type 0) answers the request (type
/// 8) with the same identifier, from the request's destination to its
/// (translated) source. The ICMP key keeps the identifier in the source-port
/// slot in BOTH directions (it is not swapped like TCP/UDP ports), so the
/// reverse key is (WAN host -> translated address, src_port = translated
/// identifier, dst_port = the forward dst_port, 0 for an echo).
#[test]
fn icmp_echo_reverse_key_from_first_principles_18710() {
    let translated = Ipv4Addr::new(172, 16, 80, 8);
    let forward = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(IFACE_CLIENT),
        dst_ip: IpAddr::V4(WAN_HOST),
        src_port: 0x1234,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    for (label, rewrite_src_port, want_id) in [
        ("identifier translated", Some(0x4321u16), 0x4321u16),
        ("identifier preserved", None, 0x1234u16),
    ] {
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(translated)),
            rewrite_src_port,
            ..NatDecision::default()
        };
        let want = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(WAN_HOST),
            dst_ip: IpAddr::V4(translated),
            src_port: want_id,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        assert_eq!(
            crate::session::reverse_session_key(&forward, nat),
            want,
            "{label}: the echo reply's key"
        );
    }
}
