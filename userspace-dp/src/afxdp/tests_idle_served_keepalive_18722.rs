//! #18722, production evidence chain. The session-level cells
//! (`session/idle_served_keepalive_18722_tests.rs`) model the HA context
//! with a closure. This cell wires the closure production builds
//! (`housekeeping.rs`: `shared_node_served_evidence` over the shared
//! synced map) and drives the shared row's counts through the batch
//! restamp the serving worker's ct-slice runs once per refresh cycle
//! (`run_shared_evidence_leg` -> `restamp_shared_packet_counts_batch`).
//!
//! It pins that the recency proof the expiry pass reads is the one
//! production actually moves: while the serving pair forwards, the
//! restamps advance `shared_served` and the opening replica survives;
//! once they stop, the replica reaps within two of its windows. A
//! `shared_node_served_evidence` that dropped the counts (the pre-#18722
//! shape) leaves `shared_served` absent, so the replica reaps on its first
//! crossed window even while served: the survival half reds.

use super::*;
use crate::afxdp::testfx::{test_key, test_metadata, test_resolution};
use crate::session::{
    ExpireHaContext, STALE_SYNCED_CEILING_ABS_NS, STALE_SYNCED_CEILING_MULT, SessionDecision,
    TcpHandshakeState,
};
use crate::tcp_flags::TCP_SYN;
use std::net::Ipv4Addr;

const SEC: u64 = 1_000_000_000;
/// `slice_pacing::CT_REFRESH_WINDOW_NS`: the shared-evidence leg's cadence.
const RESTAMP_EVERY: u64 = 10 * SEC;

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

/// The serving pair's canonical shared row: Established, counts as the
/// ct-slice last restamped them (0 until the first restamp).
fn serving_row(key: &SessionKey) -> SyncedSessionEntry {
    SyncedSessionEntry {
        sibling_last_seen_ns: 0,
        key: key.clone(),
        decision: decision(),
        metadata: test_metadata(),
        source_nat_static: None,
        leak_incarnation: 0,
        origin: crate::session::SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0x18722,
        tcp_close_class: 0,
        tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
    }
}

#[test]
fn shared_restamps_keep_an_opening_replica_only_while_they_advance_18722() {
    let forward = test_key();
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let t0 = 1_000 * SEC;
    // This worker's replica pair: pure Opening, never answered here.
    let mut table = SessionTable::new();
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        test_metadata(),
        t0,
        PROTO_TCP,
        TCP_SYN
    ));
    let mut reverse_metadata = test_metadata();
    reverse_metadata.is_reverse = true;
    assert!(table.install_with_protocol(
        reverse.clone(),
        decision(),
        reverse_metadata,
        t0,
        PROTO_TCP,
        TCP_SYN
    ));
    let window = 20 * SEC;
    assert_eq!(
        table.timeout_secs_for(&forward),
        20,
        "premise: opening window"
    );

    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    shared_sessions
        .lock()
        .expect("shared")
        .insert(forward.clone(), serving_row(&forward));
    let reverse_alias_index = std::cell::OnceCell::new();
    // The production closure (`housekeeping.rs`).
    let node_served = |key: &SessionKey| {
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared_sessions,
            &shared_nat_sessions,
            &reverse_alias_index,
            key,
        )
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

    // The serving worker forwards 100 packets each way per second; its
    // ct-slice restamps the live counts every refresh cycle.
    let source_namespace = table.session_id_namespace();
    let restamp = |now: u64| {
        let elapsed = (now - t0) / SEC;
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &shared_sessions,
            &shared_forward_wire_sessions,
            source_namespace,
            &[(
                forward.clone(),
                crate::nat::NatDecision::default(),
                100 * elapsed,
                100 * elapsed,
                now,
            )],
        );
    };
    let quiet_at = t0 + 4 * window;
    let mut now = t0;
    while now < quiet_at {
        now += SEC;
        if (now - t0) % RESTAMP_EVERY == 0 {
            restamp(now);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared_sessions,
            &shared_nat_sessions,
            &reverse_alias_index,
            &forward,
        )
            .shared_served
            .is_some_and(|served| served > 0),
        "premise: the production evidence carries the restamped counts"
    );
    assert!(
        table.entry_with_origin(&forward).is_some() && table.entry_with_origin(&reverse).is_some(),
        "#16223/#18722: the replica survives four windows while the serving pair's \
         restamped counts advance"
    );
    // The client dies without a FIN: no more packets, no more advance. The
    // last restamp was at +80 s; crossed checks fall at +84 s and +105 s.
    // Exact contract: the window-1 check (+84 s) still sees that restamp and
    // KEEPS the replica, the window-2 check (+105 s) REAPS it.
    let mut events: Vec<(&'static str, u64)> = Vec::new();
    while now < quiet_at + 10 * window {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            events.push(("kept", now));
        }
        if table.entry_with_origin(&forward).is_none()
            && table.entry_with_origin(&reverse).is_none()
        {
            events.push(("reaped", now));
            break;
        }
    }
    let rel: Vec<_> = events
        .iter()
        .map(|(e, t)| (*e, (t - quiet_at) / SEC))
        .collect();
    assert_eq!(
        events.len(),
        2,
        "#18722: expected [kept at the window-1 check, reaped at the window-2 check] after the \
         last restamp, got {rel:?} (seconds after it)"
    );
    assert_eq!(
        events[0].0, "kept",
        "#18722: the window-1 check must KEEP, got {rel:?}"
    );
    assert_eq!(
        events[1].0, "reaped",
        "#18722: the window-2 check must REAP, got {rel:?}"
    );
    assert!(
        events[0].1 <= quiet_at + window + 2 * SEC,
        "#18722: the keep must be the first crossed check after the last restamp, got {rel:?}"
    );
    assert!(
        events[1].1 > events[0].1 + window && events[1].1 <= events[0].1 + window + 2 * SEC,
        "#18722: the reap must be the next crossed check, one window after the keep, got {rel:?}"
    );
}

/// #18742 Sol: reverse replicas on two SNAT flows to the SAME server port
/// must not borrow one another's shared liveness evidence. The old
/// `snat_reverse` predicate compared only the derived source endpoint and
/// server port, so flow A could falsely mark flow B's reverse key Established
/// and served whenever their server port matched.
#[test]
fn shared_evidence_does_not_cross_snat_flows_sharing_server_port_18722() {
    let mut flow_a = test_key();
    flow_a.dst_ip = "198.51.100.80".parse().expect("server");
    flow_a.dst_port = 443;
    let mut flow_b = flow_a.clone();
    flow_b.src_ip = "10.0.61.103".parse().expect("client B");
    flow_b.src_port = 55069;
    let nat_a = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("public address")),
        rewrite_src_port: Some(40_000),
        ..crate::nat::NatDecision::default()
    };
    let nat_b = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("public address")),
        rewrite_src_port: Some(40_001),
        ..crate::nat::NatDecision::default()
    };
    let reverse_b = crate::session::reverse_session_key(&flow_b, nat_b);
    assert_eq!(flow_a.dst_port, flow_b.dst_port, "premise: same server port");
    assert_ne!(flow_a, flow_b, "premise: distinct client tuples");
    assert_ne!(
        crate::session::reverse_session_key(&flow_a, nat_a),
        reverse_b,
        "premise: the translated reverse tuples differ"
    );

    let mut a = serving_row(&flow_a);
    a.decision.nat = nat_a;
    a.session_id = 0x18722_A;
    a.fwd_packets = 100;
    a.rev_packets = 200;
    let mut b = serving_row(&flow_b);
    b.decision.nat = nat_b;
    b.session_id = 0x18722_B;
    b.tcp_handshake_state = TcpHandshakeState::Opening.to_wire();
    b.fwd_packets = 500;
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let reverse_a = crate::session::reverse_session_key(&flow_a, nat_a);
    {
        let mut sessions = shared.lock().expect("shared");
        sessions.insert(flow_a.clone(), a.clone());
        sessions.insert(flow_b.clone(), b.clone());
    }
    {
        let mut aliases = shared_nat_sessions.lock().expect("shared NAT aliases");
        aliases.insert(reverse_a.clone(), a);
        aliases.insert(reverse_b.clone(), b);
    }

    let reverse_alias_index = std::cell::OnceCell::new();
    let own_evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
        &shared,
        &shared_nat_sessions,
        &reverse_alias_index,
        &reverse_a,
    );

    assert_eq!(own_evidence.shared_served, Some(300));
    assert_eq!(own_evidence.shared_incarnation, Some((0x18722_A, 0)));
    let evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
        &shared,
        &shared_nat_sessions,
        &reverse_alias_index,
        &reverse_b,
    );
    assert!(
        !evidence.shared_established && evidence.shared_served.is_none(),
        "#18742: flow A must not supply Established/served evidence for flow B's same-server-port \
         reverse tuple, got {evidence:?}"
    );
}

fn unique_served_key(index: u32) -> SessionKey {
    let mut key = test_key();
    key.src_ip = Ipv4Addr::from(0x0a00_0000u32 + index + 1).into();
    key
}

fn served_work_since(before: (u64, u64)) -> (u64, u64) {
    crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| {
        let after = stats.get();
        (after.0 - before.0, after.1 - before.1)
    })
}


fn served_index_work_since(before: (u64, u64)) -> (u64, u64) {
    crate::afxdp::shared_ops::NODE_SERVED_INDEX_WORK_18663.with(|stats| {
        let after = stats.get();
        (after.0 - before.0, after.1 - before.1)
    })
}
#[test]
fn shared_node_served_evidence_finds_direct_reverse_and_nat_alias_18663() {
    let direct = unique_served_key(1);
    let reverse_forward = unique_served_key(2);
    let nat_forward = unique_served_key(3);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_000),
        ..crate::nat::NatDecision::default()
    };
    let nat_reverse = crate::session::reverse_session_key(&nat_forward, nat);

    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let mut direct_row = serving_row(&direct);
    direct_row.fwd_packets = 11;
    let mut reverse_row = serving_row(&reverse_forward);
    reverse_row.fwd_packets = 22;
    let mut nat_row = serving_row(&nat_forward);
    nat_row.decision.nat = nat;
    nat_row.fwd_packets = 33;
    nat_row.rev_packets = 4;
    {
        let mut sessions = shared.lock().expect("shared sessions");
        sessions.insert(direct.clone(), direct_row);
        sessions.insert(reverse_forward.clone(), reverse_row);
        sessions.insert(nat_forward.clone(), nat_row.clone());
    }
    aliases
        .lock()
        .expect("shared NAT aliases")
        .insert(nat_reverse.clone(), nat_row);
    let reverse_alias_index = std::cell::OnceCell::new();

    let reverse = crate::session::reverse_session_key(
        &reverse_forward,
        crate::nat::NatDecision::default(),
    );
    let probes = [
        (&direct, 11, "direct"),
        (&reverse, 22, "reverse"),
        (&nat_reverse, 37, "NAT reverse alias"),
    ];
    for (key, served, shape) in probes {
        let before =
            crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
        let evidence =
            crate::afxdp::shared_ops::shared_node_served_evidence(
                &shared,
                &aliases,
                &reverse_alias_index,
                key,
            );
        let (calls, work) = served_work_since(before);
        assert_eq!(calls, 1, "{shape}: one evidence call");
        assert!(
            work <= 4,
            "{shape}: expected bounded keyed lookups, observed {work} work units"
        );
        assert_eq!(
            evidence.shared_served,
            Some(served),
            "{shape}: served evidence"
        );
        assert!(evidence.shared_established, "{shape}: Established evidence");
    }

    let unrelated = unique_served_key(4);
    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let absent =
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared,
            &aliases,
            &reverse_alias_index,
            &unrelated,
        );
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one negative evidence call");
    assert!(work <= 4, "negative probe work must be bounded, got {work}");
    assert!(
        !absent.shared_established && absent.shared_served.is_none(),
        "unmatched key must have no shared served evidence, got {absent:?}"
    );

    // A stale alias must not resurrect evidence after its primary row is gone.
    shared
        .lock()
        .expect("shared sessions")
        .remove(&nat_forward);
    let missing =
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared,
            &aliases,
            &reverse_alias_index,
            &nat_reverse,
        );
    assert!(
        !missing.shared_established && missing.shared_served.is_none(),
        "removed primary row must fail closed, got {missing:?}"
    );
}

#[test]
fn shared_node_served_evidence_work_is_bounded_for_64k_rows_18663() {
    const ROWS: u32 = 64 * 1024;
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let mut filler = serving_row(&test_key());
    filler.tcp_handshake_state = TcpHandshakeState::Opening.to_wire();
    let forward = unique_served_key(ROWS);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_000),
        ..crate::nat::NatDecision::default()
    };
    let mut target = serving_row(&forward);
    target.decision.nat = nat;
    target.fwd_packets = 100;
    target.rev_packets = 200;
    let reverse = crate::session::reverse_session_key(&forward, nat);
    {
        let mut sessions = shared.lock().expect("shared sessions");
        for index in 0..ROWS {
            let key = unique_served_key(index);
            let mut entry = filler.clone();
            entry.key = key.clone();
            sessions.insert(key, entry);
        }
        sessions.insert(forward.clone(), target.clone());
        assert_eq!(sessions.len(), ROWS as usize + 1);
    }
    aliases
        .lock()
        .expect("shared NAT aliases")
        .insert(reverse.clone(), target);
    let reverse_alias_index = std::cell::OnceCell::new();
    let before_index =
        crate::afxdp::shared_ops::NODE_SERVED_INDEX_WORK_18663.with(|stats| stats.get());

    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let evidence =
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared,
            &aliases,
            &reverse_alias_index,
            &reverse,
        );
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one evidence call");
    assert!(
        work <= 4,
        "64k shared rows must not change keyed work, observed {work} units"
    );
    assert_eq!(evidence.shared_served, Some(300));
    assert!(evidence.shared_established);
    let absent_key = unique_served_key(ROWS + 1);
    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let absent =
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared,
            &aliases,
            &reverse_alias_index,
            &absent_key,
        );
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one large-table miss call");
    assert!(
        work <= 4,
        "64k shared rows must not change miss work, observed {work} units"
    );
    assert!(
        !absent.shared_established && absent.shared_served.is_none(),
        "unmatched 64k-table key must have no evidence, got {absent:?}"
    );
    let (builds, rows_visited) = served_index_work_since(before_index);
    assert_eq!((builds, rows_visited), (1, ROWS as u64 + 1));
}

#[test]
fn shared_node_served_reverse_alias_index_builds_once_per_pass_18663() {
    const ROWS: u32 = 32;
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    {
        let mut sessions = shared.lock().expect("shared sessions");
        for index in 0..ROWS {
            let key = unique_served_key(10_000 + index);
            sessions.insert(key.clone(), serving_row(&key));
        }
    }
    let candidates: Vec<_> = (0..8).map(|i| unique_served_key(20_000 + i)).collect();

    for candidate_count in [1usize, 8] {
        let reverse_alias_index = std::cell::OnceCell::new();
        let before_index =
            crate::afxdp::shared_ops::NODE_SERVED_INDEX_WORK_18663.with(|stats| stats.get());
        let before_work =
            crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
        for key in candidates.iter().take(candidate_count) {
            let evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
                &shared,
                &aliases,
                &reverse_alias_index,
                key,
            );
            assert!(
                !evidence.shared_established && evidence.shared_served.is_none(),
                "unmatched candidate must have no served evidence: {evidence:?}"
            );
        }
        let (builds, rows_visited) = served_index_work_since(before_index);
        assert_eq!(
            builds, 1,
            "{candidate_count} candidates in one pass must build one index"
        );
        assert_eq!(
            rows_visited, ROWS as u64,
            "one index build must visit the primary map once"
        );
        let (calls, work) = served_work_since(before_work);
        assert_eq!(calls, candidate_count as u64);
        assert!(
            work <= 4 * candidate_count as u64,
            "each candidate must use bounded keyed work, got {work} units"
        );
    }
}

#[test]
fn shared_node_served_evidence_finds_reverse_only_established_nat_alias_18663() {
    let forward = unique_served_key(30_001);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_001),
        ..crate::nat::NatDecision::default()
    };
    let reverse_row_key = crate::session::reverse_session_key(&forward, nat);
    let reverse_nat = nat.reverse(
        forward.src_ip,
        forward.dst_ip,
        forward.src_port,
        forward.dst_port,
    );
    assert_eq!(
        crate::session::reverse_session_key(&reverse_row_key, reverse_nat),
        forward,
        "premise: reverse row's NAT companion is the original forward key"
    );
    let mut reverse_row = serving_row(&reverse_row_key);
    reverse_row.metadata.is_reverse = true;
    reverse_row.decision.nat = reverse_nat;
    reverse_row.fwd_packets = 17;
    reverse_row.rev_packets = 23;
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::from_iter([(
            reverse_row_key.clone(),
            reverse_row,
        )])));
    let aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    assert!(
        !shared.lock().expect("shared sessions").contains_key(&forward),
        "premise: forward canonical row is absent"
    );
    assert!(
        !aliases.lock().expect("shared NAT aliases").contains_key(&forward),
        "premise: reverse-only alias is not in the forward-row NAT map"
    );

    let reverse_alias_index = std::cell::OnceCell::new();
    let before_work =
        crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let before_index =
        crate::afxdp::shared_ops::NODE_SERVED_INDEX_WORK_18663.with(|stats| stats.get());
    let evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
        &shared,
        &aliases,
        &reverse_alias_index,
        &forward,
    );
    let (calls, work) = served_work_since(before_work);
    let (builds, rows_visited) = served_index_work_since(before_index);
    assert_eq!(calls, 1);
    assert!(
        work <= 6,
        "reverse-only alias should use bounded keyed work, got {work} units"
    );
    assert_eq!((builds, rows_visited), (1, 1));
    assert_eq!(evidence.shared_served, Some(40));
    assert!(evidence.shared_established);
    assert_eq!(
        evidence.shared_incarnation,
        Some((0x18722, 0)),
        "without the canonical row, retain the reverse row's own incarnation"
    );
}

#[test]
fn shared_node_served_forward_alias_precedes_reverse_alias_collision_18663() {
    let forward = unique_served_key(40_001);
    let forward_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("forward SNAT address")),
        rewrite_src_port: Some(40_002),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&forward, forward_nat);
    let competing_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("reverse-row SNAT address")),
        rewrite_src_port: Some(40_003),
        ..crate::nat::NatDecision::default()
    };
    let reverse_row_key = crate::session::reverse_session_key(&alias, competing_nat);
    let reverse_row_nat = competing_nat.reverse(
        alias.src_ip,
        alias.dst_ip,
        alias.src_port,
        alias.dst_port,
    );
    assert_eq!(
        crate::session::reverse_session_key(&reverse_row_key, reverse_row_nat),
        alias,
        "premise: reverse-only row claims the same alias"
    );

    let mut forward_row = serving_row(&forward);
    forward_row.decision.nat = forward_nat;
    forward_row.fwd_packets = 100;
    forward_row.session_id = 0x18_663_A;
    let mut reverse_row = serving_row(&reverse_row_key);
    reverse_row.metadata.is_reverse = true;
    reverse_row.decision.nat = reverse_row_nat;
    reverse_row.fwd_packets = 999;
    reverse_row.session_id = 0x18_663_B;

    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    {
        let mut sessions = shared.lock().expect("shared sessions");
        sessions.insert(forward.clone(), forward_row.clone());
        sessions.insert(reverse_row_key, reverse_row);
    }
    let aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::from_iter([(alias.clone(), forward_row)])));
    let reverse_alias_index = std::cell::OnceCell::new();
    let before_index =
        crate::afxdp::shared_ops::NODE_SERVED_INDEX_WORK_18663.with(|stats| stats.get());

    let evidence = crate::afxdp::shared_ops::shared_node_served_evidence(
        &shared,
        &aliases,
        &reverse_alias_index,
        &alias,
    );
    let (builds, rows_visited) = served_index_work_since(before_index);
    assert_eq!((builds, rows_visited), (0, 0));
    assert_eq!(evidence.shared_served, Some(100));
    assert_eq!(
        evidence.shared_incarnation,
        Some((0x18_663_A, 0)),
        "forward NAT alias retains precedence over a reverse-row alias collision"
    );
}
