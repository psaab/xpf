//! #18658: `publish_shared_session` and `remove_shared_session_if` must take
//! the forward-wire map and `wire_ambiguities` in ONE order: the map first.
//!
//! On master the publish took the index first, and the removal took the map
//! first (inside `shared_sessions`). A publish holding `wire_ambiguities`
//! while waiting for the map deadlocked against a removal holding the map
//! while waiting for the index. On both tcp and loss, after a 16000-session
//! burst, every worker and the coordinator then sat in `futex_wait` until
//! xpfd was restarted.
//!
//! The cell forces exactly that interleaving with two test-only pause points
//! placed between each path's first and second wire lock.
//! - The PUBLISH pauses after its FIRST wire lock. With the fix that is the
//!   map; with the inverted order it is the index.
//! - The REMOVAL is started while the publish is paused. If it can take the
//!   map, it reports that at its own pause point (holding the map) and then
//!   waits for the index. That only happens on the inverted order, where it
//!   then waits on the index the paused publish holds.
//! - The publish is released. With the fix it takes the index, finishes, and
//!   frees the map, so the removal finishes too. With the inverted order it
//!   waits for the map the removal holds, and both threads hang.
//!
//! The verdict is a bounded `recv_timeout`, never a hang. A deadlocked run
//! leaks its two threads; they hold only this test's own maps.

use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Condvar, mpsc};
use std::time::{Duration, Instant};

struct PauseState {
    armed: Option<(SessionKey, SessionKey)>,
    publish_reached: bool,
    publish_go: bool,
    removal_reached: bool,
}

static PAUSE: Mutex<PauseState> = Mutex::new(PauseState {
    armed: None,
    publish_reached: false,
    publish_go: false,
    removal_reached: false,
});
static PAUSE_CV: Condvar = Condvar::new();

fn pause_state() -> std::sync::MutexGuard<'static, PauseState> {
    PAUSE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Called by `publish_shared_session` between its two wire locks. A no-op
/// unless this cell armed it for `wire_key`, so no other test is affected.
pub(in crate::afxdp) fn publish_between_wire_locks(wire_key: &SessionKey) {
    let mut state = pause_state();
    if !matches!(&state.armed, Some((publish, _)) if publish == wire_key) {
        return;
    }
    state.publish_reached = true;
    PAUSE_CV.notify_all();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !state.publish_go {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        state = PAUSE_CV
            .wait_timeout(state, deadline - now)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
}

/// Called by `remove_shared_session_if` between its two wire locks.
pub(in crate::afxdp) fn removal_between_wire_locks(wire_key: &SessionKey) {
    let mut state = pause_state();
    if !matches!(&state.armed, Some((_, removal)) if removal == wire_key) {
        return;
    }
    state.removal_reached = true;
    PAUSE_CV.notify_all();
}

fn wait_for(timeout: Duration, ready: impl Fn(&PauseState) -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    let mut state = pause_state();
    while !ready(&state) {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        state = PAUSE_CV
            .wait_timeout(state, deadline - now)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
    true
}

fn key(src_last: u8, src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, src_last)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5211,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn snat(port: u16) -> crate::nat::NatDecision {
    crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(port),
        ..crate::nat::NatDecision::default()
    }
}

fn row(key: &SessionKey, nat: crate::nat::NatDecision, session_id: u64) -> SyncedSessionEntry {
    let metadata = crate::session::SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    };
    SyncedSessionEntry {
        key: key.clone(),
        decision: crate::session::SessionDecision {
            resolution: crate::afxdp::ForwardingResolution {
                disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        persistent_lease_hold: None,
        source_nat_static: None,
        leak_incarnation: 0,
        origin: crate::session::SessionOrigin::ForwardFlow,
        protocol: crate::ip_proto::PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(),
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
    }
}

type Maps = (
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    SharedSessionOwnerRgIndexes,
);

fn maps() -> Maps {
    (
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        SharedSessionOwnerRgIndexes::default(),
    )
}

#[test]
fn publish_and_removal_take_the_wire_locks_in_one_order_18658() {
    let (shared, nat_map, wire_map, indexes) = maps();
    // The session the removal tears down: a NAT'd forward row, so its removal
    // walks the wire-alias branch (map, then index).
    let doomed = key(103, 40001);
    let doomed_nat = snat(50001);
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&doomed, doomed_nat, 1));
    // The session the publish installs: another NAT'd forward row.
    let fresh = key(104, 40002);
    let fresh_nat = snat(50002);
    let publish_wire = crate::session::forward_wire_key(&fresh, fresh_nat);
    let removal_wire = crate::session::forward_wire_key(&doomed, doomed_nat);
    assert_ne!(publish_wire, fresh, "fixture: the publish must have a wire alias");
    assert_ne!(removal_wire, doomed, "fixture: the removal must have a wire alias");
    {
        let mut state = pause_state();
        state.armed = Some((publish_wire.clone(), removal_wire.clone()));
        state.publish_reached = false;
        state.publish_go = false;
        state.removal_reached = false;
    }

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    {
        let (shared, nat_map, wire_map, indexes) =
            (shared.clone(), nat_map.clone(), wire_map.clone(), indexes.clone());
        let done = done_tx.clone();
        std::thread::spawn(move || {
            publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&fresh, fresh_nat, 2));
            let _ = done.send("publish");
        });
    }
    assert!(
        wait_for(Duration::from_secs(5), |s| s.publish_reached),
        "fixture: the publish never reached its pause point between the two wire locks"
    );
    {
        let (shared, nat_map, wire_map, indexes) =
            (shared.clone(), nat_map.clone(), wire_map.clone(), indexes.clone());
        let done = done_tx.clone();
        std::thread::spawn(move || {
            remove_shared_session(&shared, &nat_map, &wire_map, &indexes, &doomed);
            let _ = done.send("removal");
        });
    }
    // On the inverted order the removal takes the map (the paused publish
    // holds only the index) and reports at its pause point. On the fixed
    // order it blocks on the map the publish holds and cannot report.
    let removal_took_map_first = wait_for(Duration::from_millis(500), |s| s.removal_reached);
    {
        let mut state = pause_state();
        state.publish_go = true;
        PAUSE_CV.notify_all();
    }
    let mut finished = Vec::new();
    for _ in 0..2 {
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(which) => finished.push(which),
            Err(_) => panic!(
                "#18658: publish and removal deadlocked on the forward-wire map and \
                 `wire_ambiguities` (finished: {finished:?}; the removal took the map while \
                 the paused publish held its first wire lock: {removal_took_map_first}). \
                 Both paths must take the map BEFORE the index."
            ),
        }
    }
    pause_state().armed = None;
    assert!(
        !removal_took_map_first,
        "#18658: while the publish was paused after its first wire lock, the removal \
         could still take the map, so that first lock was not the map"
    );
    // The work itself completed: the fresh alias is published and owned, and
    // the doomed one is gone.
    let wires = lock_shared_recover(&wire_map);
    assert_eq!(wires.get(&publish_wire).map(|e| e.key.clone()), Some(key(104, 40002)));
    assert!(!wires.contains_key(&removal_wire), "the removal must drop its own alias");
}
