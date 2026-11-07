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
    let shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    shared_sessions
        .lock()
        .expect("shared")
        .insert(forward.clone(), serving_row(&forward));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    // The production closure (`housekeeping.rs`).
    let node_served = |key: &SessionKey| {
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &shared_sessions,
            &shared_owner_rg_indexes,
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
            &shared_owner_rg_indexes,
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
    let reverse_a = crate::session::reverse_session_key(&flow_a, nat_a);
    let reverse_b = crate::session::reverse_session_key(&flow_b, nat_b);
    assert_eq!(flow_a.dst_port, flow_b.dst_port, "premise: same server port");
    assert_ne!(flow_a, flow_b, "premise: distinct client tuples");
    assert_ne!(
        reverse_a, reverse_b,
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
    let store = SharedServedStore::new();
    store.publish(&a);
    store.publish(&b);

    let own_evidence = store.evidence(&reverse_a);
    assert_eq!(own_evidence.shared_served, Some(300));
    assert_eq!(own_evidence.shared_incarnation, Some((0x18722_A, 0)));
    let evidence = store.evidence(&reverse_b);
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

struct SharedServedStore {
    sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    nat_aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_wire_aliases: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_indexes: SharedSessionOwnerRgIndexes,
}

impl SharedServedStore {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_aliases: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_aliases: Arc::new(Mutex::new(FastMap::default())),
            owner_indexes: SharedSessionOwnerRgIndexes::default(),
        }
    }

    fn publish(&self, entry: &SyncedSessionEntry) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.sessions,
            &self.nat_aliases,
            &self.forward_wire_aliases,
            &self.owner_indexes,
            entry,
        );
    }

    fn evidence(&self, key: &SessionKey) -> crate::session::NodeServedEvidence {
        crate::afxdp::shared_ops::shared_node_served_evidence(
            &self.sessions,
            &self.owner_indexes,
            key,
        )
    }

    fn remove(&self, key: &SessionKey) -> crate::afxdp::shared_ops::SharedRemoval {
        crate::afxdp::shared_ops::remove_shared_session_if(
            &self.sessions,
            &self.nat_aliases,
            &self.forward_wire_aliases,
            &self.owner_indexes,
            key,
            |_| true,
        )
    }
}

fn served_work_since(before: (u64, u64)) -> (u64, u64) {
    crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| {
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
    let store = SharedServedStore::new();

    let mut direct_row = serving_row(&direct);
    direct_row.fwd_packets = 11;
    let mut reverse_row = serving_row(&reverse_forward);
    reverse_row.fwd_packets = 22;
    let mut nat_row = serving_row(&nat_forward);
    nat_row.decision.nat = nat;
    nat_row.fwd_packets = 33;
    nat_row.rev_packets = 4;
    store.publish(&direct_row);
    store.publish(&reverse_row);
    store.publish(&nat_row);

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
        let evidence = store.evidence(key);
        let (calls, work) = served_work_since(before);
        assert_eq!(calls, 1, "{shape}: one evidence call");
        assert!(
            work <= 5,
            "{shape}: expected bounded keyed lookups, observed {work} work units"
        );
        assert_eq!(evidence.shared_served, Some(served), "{shape}: served evidence");
        assert!(evidence.shared_established, "{shape}: Established evidence");
    }

    let unrelated = unique_served_key(4);
    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let absent = store.evidence(&unrelated);
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one negative evidence call");
    assert!(work <= 5, "negative probe work must be bounded, got {work}");
    assert!(
        !absent.shared_established && absent.shared_served.is_none(),
        "unmatched key must have no shared served evidence, got {absent:?}"
    );

    // An alias owner is only a hint: a primary row removed outside the normal
    // remover still cannot be resurrected by a stale keyed alias record.
    store.sessions.lock().expect("shared sessions").remove(&nat_forward);
    let missing = store.evidence(&nat_reverse);
    assert!(
        !missing.shared_established && missing.shared_served.is_none(),
        "removed primary row must fail closed, got {missing:?}"
    );
}

#[test]
fn shared_served_alias_is_visible_with_published_primary_18663() {
    let forward = unique_served_key(5);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.11".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_005),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&forward, nat);
    let mut row = serving_row(&forward);
    row.decision.nat = nat;
    row.fwd_packets = 9;
    let store = Arc::new(SharedServedStore::new());
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));

    let publish_store = Arc::clone(&store);
    let publish_entered = Arc::clone(&entered);
    let publish_release = Arc::clone(&release);
    let publisher = std::thread::spawn(move || {
        crate::afxdp::shared_ops::SHARED_ALIAS_PRIMARY_LOCK_HOOK_18663.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                publish_entered.wait();
                publish_release.wait();
            }));
        });
        publish_store.publish(&row);
    });
    entered.wait();

    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let (evidence_tx, evidence_rx) = std::sync::mpsc::channel();
    let query_store = Arc::clone(&store);
    let query_alias = alias.clone();
    let query = std::thread::spawn(move || {
        let blocked = matches!(
            query_store.sessions.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        );
        blocked_tx.send(blocked).expect("send lock observation");
        evidence_tx
            .send(query_store.evidence(&query_alias))
            .expect("send evidence");
    });
    let query_blocked_on_primary = blocked_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("query attempted during primary publish");
    let probe_waited_for_publish = matches!(
        evidence_rx.recv_timeout(std::time::Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    );

    release.wait();
    publisher.join().expect("publisher completes");
    let evidence = evidence_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("probe resumes after alias publication");
    query.join().expect("query completes");
    assert!(
        query_blocked_on_primary,
        "the primary lock remains held between primary insertion and alias update"
    );
    assert!(
        probe_waited_for_publish,
        "probe must wait for the atomic primary-plus-alias publication"
    );
    assert_eq!(evidence.shared_served, Some(9));

}

#[test]
fn shared_node_served_evidence_work_is_bounded_for_64k_rows_18663() {
    const ROWS: u32 = 64 * 1024;
    let store = SharedServedStore::new();
    let mut filler = serving_row(&test_key());
    filler.tcp_handshake_state = TcpHandshakeState::Opening.to_wire();
    {
        let mut sessions = store.sessions.lock().expect("shared sessions");
        for index in 0..ROWS {
            let key = unique_served_key(index);
            let mut entry = filler.clone();
            entry.key = key.clone();
            sessions.insert(key, entry);
        }
    }
    let forward = unique_served_key(ROWS + 1);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.9".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_000),
        ..crate::nat::NatDecision::default()
    };
    let mut target = serving_row(&forward);
    target.decision.nat = nat;
    target.fwd_packets = 100;
    target.rev_packets = 200;
    store.publish(&target);
    assert_eq!(store.sessions.lock().expect("shared sessions").len(), ROWS as usize + 1);

    let reverse = crate::session::reverse_session_key(&forward, nat);
    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let evidence = store.evidence(&reverse);
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one evidence call");
    assert!(
        work <= 5,
        "64k shared rows must not change keyed work, observed {work} units"
    );
    assert_eq!(evidence.shared_served, Some(300));
    assert!(evidence.shared_established);

    let absent_key = unique_served_key(ROWS + 2);
    let before = crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let absent = store.evidence(&absent_key);
    let (calls, work) = served_work_since(before);
    assert_eq!(calls, 1, "one large-table miss call");
    assert!(
        work <= 5,
        "64k shared rows must not change miss work, observed {work} units"
    );
    assert!(
        !absent.shared_established && absent.shared_served.is_none(),
        "unmatched 64k-table key must have no evidence, got {absent:?}"
    );
}

#[test]
fn shared_node_served_alias_sees_late_publish_after_prior_miss_18663() {
    let store = SharedServedStore::new();
    let unrelated = unique_served_key(60_001);
    assert!(
        !store.evidence(&unrelated).shared_established,
        "premise: initial unrelated miss does not vouch"
    );

    let forward = unique_served_key(60_002);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.12".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_006),
        ..crate::nat::NatDecision::default()
    };
    let reverse_row_key = crate::session::reverse_session_key(&forward, nat);
    let reverse_nat = nat.reverse(
        forward.src_ip,
        forward.dst_ip,
        forward.src_port,
        forward.dst_port,
    );
    let mut reverse_row = serving_row(&reverse_row_key);
    reverse_row.metadata.is_reverse = true;
    reverse_row.decision.nat = reverse_nat;
    reverse_row.fwd_packets = 17;
    reverse_row.rev_packets = 23;
    store.publish(&reverse_row);

    let evidence = store.evidence(&forward);
    assert!(evidence.shared_established, "late-published reverse alias is found");
    assert_eq!(evidence.shared_served, Some(40));
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
    let store = SharedServedStore::new();
    store.publish(&reverse_row);
    assert!(
        !store.sessions.lock().expect("shared sessions").contains_key(&forward),
        "premise: forward canonical row is absent"
    );
    assert!(
        !store.nat_aliases.lock().expect("shared NAT aliases").contains_key(&forward),
        "premise: reverse-only alias is not in the forward-row NAT map"
    );

    let before_work =
        crate::afxdp::shared_ops::NODE_SERVED_WORK_18663.with(|stats| stats.get());
    let evidence = store.evidence(&forward);
    let (calls, work) = served_work_since(before_work);
    assert_eq!(calls, 1);
    assert!(
        work <= 5,
        "reverse-only alias should use bounded keyed work, got {work} units"
    );
    assert_eq!(evidence.shared_served, Some(40));
    assert!(evidence.shared_established);
    assert_eq!(
        evidence.shared_incarnation,
        Some((0x18722, 0)),
        "without the canonical row, retain the reverse row's own incarnation"
    );
}

#[test]
fn shared_node_served_forward_nat_alias_collisions_fail_closed_in_both_publish_orders_18663() {
    let flow_a = unique_served_key(40_001);
    let mut flow_b = flow_a.clone();
    flow_b.src_ip = Ipv4Addr::new(10, 0, 61, 199).into();
    flow_b.src_port = flow_a.src_port.saturating_add(1);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.13".parse().expect("shared SNAT address")),
        rewrite_src_port: Some(40_007),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&flow_a, nat);
    assert_eq!(crate::session::reverse_session_key(&flow_b, nat), alias);

    for b_stage in [
        TcpHandshakeState::Opening,
        TcpHandshakeState::Established,
    ] {
        for b_publishes_last in [false, true] {
            let mut a = serving_row(&flow_a);
            a.decision.nat = nat;
            a.fwd_packets = 111;
            a.session_id = 0x18_663_A;
            let mut b = serving_row(&flow_b);
            b.decision.nat = nat;
            b.tcp_handshake_state = b_stage.to_wire();
            b.fwd_packets = 999;
            b.session_id = 0x18_663_B;
            let store = SharedServedStore::new();
            if b_publishes_last {
                store.publish(&a);
                store.publish(&b);
            } else {
                store.publish(&b);
                store.publish(&a);
            }

            let evidence = store.evidence(&alias);
            assert!(
                !evidence.shared_established && evidence.shared_served.is_none(),
                "NAT alias collision must fail closed for B stage {b_stage:?}, \
                 B publishes last={b_publishes_last}: {evidence:?}"
            );
        }
    }
}

#[test]
fn shared_node_served_forward_reverse_alias_collision_fails_closed_18663() {
    let forward = unique_served_key(40_101);
    let forward_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.14".parse().expect("forward SNAT address")),
        rewrite_src_port: Some(40_008),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&forward, forward_nat);
    let competing_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.15".parse().expect("reverse-row SNAT address")),
        rewrite_src_port: Some(40_009),
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
        "premise: reverse-only row claims the forward NAT alias"
    );

    let mut forward_row = serving_row(&forward);
    forward_row.decision.nat = forward_nat;
    forward_row.fwd_packets = 100;
    let mut reverse_row = serving_row(&reverse_row_key);
    reverse_row.metadata.is_reverse = true;
    reverse_row.decision.nat = reverse_row_nat;
    reverse_row.fwd_packets = 999;
    let store = SharedServedStore::new();
    store.publish(&forward_row);
    store.publish(&reverse_row);

    let evidence = store.evidence(&alias);
    assert!(
        !evidence.shared_established && evidence.shared_served.is_none(),
        "ambiguous forward/reverse alias must fail closed, got {evidence:?}"
    );
}

#[test]
fn shared_node_served_alias_removal_forgets_primary_owner_18663() {
    let forward = unique_served_key(50_101);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.16".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_010),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&forward, nat);
    let mut row = serving_row(&forward);
    row.decision.nat = nat;
    let store = SharedServedStore::new();
    store.publish(&row);
    assert!(store.evidence(&alias).shared_established);

    assert!(matches!(
        store.remove(&forward),
        crate::afxdp::shared_ops::SharedRemoval::Removed(_)
    ));
    let evidence = store.evidence(&alias);
    assert!(
        !evidence.shared_established && evidence.shared_served.is_none(),
        "the production remove path must unfile every alias owner, got {evidence:?}"
    );
}

#[test]
fn shared_node_served_primary_replacement_reindexes_aliases_18663() {
    let forward = unique_served_key(50_201);
    let first_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.17".parse().expect("first SNAT address")),
        rewrite_src_port: Some(40_011),
        ..crate::nat::NatDecision::default()
    };
    let second_nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.18".parse().expect("second SNAT address")),
        rewrite_src_port: Some(40_012),
        ..crate::nat::NatDecision::default()
    };
    let first_alias = crate::session::reverse_session_key(&forward, first_nat);
    let second_alias = crate::session::reverse_session_key(&forward, second_nat);
    let mut row = serving_row(&forward);
    row.decision.nat = first_nat;
    row.fwd_packets = 10;
    let store = SharedServedStore::new();
    store.publish(&row);
    assert!(store.evidence(&first_alias).shared_established);

    row.decision.nat = second_nat;
    row.fwd_packets = 20;
    store.publish(&row);
    let old = store.evidence(&first_alias);
    assert!(
        !old.shared_established && old.shared_served.is_none(),
        "replaced primary must no longer claim its old alias, got {old:?}"
    );
    assert_eq!(store.evidence(&second_alias).shared_served, Some(20));
}

#[test]
fn shared_node_served_clear_unfiles_alias_index_18663() {
    let forward = unique_served_key(50_301);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some("203.0.113.19".parse().expect("SNAT address")),
        rewrite_src_port: Some(40_013),
        ..crate::nat::NatDecision::default()
    };
    let alias = crate::session::reverse_session_key(&forward, nat);
    let mut row = serving_row(&forward);
    row.decision.nat = nat;
    let store = SharedServedStore::new();
    store.publish(&row);
    assert!(store.evidence(&alias).shared_established);

    store.owner_indexes.clear(&store.sessions);
    let evidence = store.evidence(&alias);
    assert!(
        !evidence.shared_established && evidence.shared_served.is_none(),
        "clear must retire primary rows and their served aliases, got {evidence:?}"
    );
}
