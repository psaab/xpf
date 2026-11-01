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
//! Two cells, sharing test-only hooks placed in both paths between their
//! first and second wire lock (and, for the removal, just before its first).
//!
//! - `..._take_the_wire_map_first_18658` is the DETECTOR, and it involves no
//!   timing at all. It runs each path on one thread with the hooks in probe
//!   mode. At its between-locks point each path's hook `try_lock`s both wire
//!   locks of this cell's own maps. With no other thread able to hold them,
//!   `WouldBlock` means the calling path holds that lock, so the probe names
//!   the path's FIRST wire lock exactly. Both paths must name the map.
//! - `..._take_the_wire_locks_in_one_order_18658` reproduces the deadlock
//!   interleaving with real threads. The publish parks after its first wire
//!   lock. The removal is started and parks just BEFORE its first wire lock,
//!   so that when it is released, the only thing between it and its
//!   between-locks hook is one uncontended (inverted order) or contended
//!   (correct order) lock. Its verdict is a bounded `recv_timeout`, never a
//!   hang. It demonstrates the deadlock; it is not the only detector, because
//!   a removal scheduled very late can still miss the window under load, and
//!   that would fail toward green.
//!
//! A deadlocked run leaks its two threads; they hold only this cell's maps.

use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Condvar, TryLockError, mpsc};
use std::time::{Duration, Instant};

/// Which wire lock(s) the calling path held at its between-locks hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldWireLocks {
    TheMap,
    TheIndex,
    Neither,
    Both,
}

impl HeldWireLocks {
    fn name(self) -> &'static str {
        match self {
            Self::TheMap => "the forward-wire map",
            Self::TheIndex => "`wire_ambiguities`",
            Self::Neither => "neither wire lock",
            Self::Both => "both wire locks",
        }
    }
}

struct PauseState {
    /// (publish wire key, removal wire key) this cell armed the hooks for.
    armed: Option<(SessionKey, SessionKey)>,
    /// Probe mode: record what each path holds, never park.
    probe: bool,
    publish_held: Option<HeldWireLocks>,
    removal_held: Option<HeldWireLocks>,
    publish_reached: bool,
    publish_go: bool,
    removal_ready: bool,
    removal_go: bool,
    removal_reached: bool,
}

static PAUSE: Mutex<PauseState> = Mutex::new(PauseState {
    armed: None,
    probe: false,
    publish_held: None,
    removal_held: None,
    publish_reached: false,
    publish_go: false,
    removal_ready: false,
    removal_go: false,
    removal_reached: false,
});
static PAUSE_CV: Condvar = Condvar::new();
/// The two cells share `PAUSE`; this keeps them from running at once.
static CELL: Mutex<()> = Mutex::new(());

fn pause_state() -> std::sync::MutexGuard<'static, PauseState> {
    PAUSE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn arm(publish: SessionKey, removal: SessionKey, probe: bool) {
    let mut state = pause_state();
    *state = PauseState {
        armed: Some((publish, removal)),
        probe,
        publish_held: None,
        removal_held: None,
        publish_reached: false,
        publish_go: false,
        removal_ready: false,
        removal_go: false,
        removal_reached: false,
    };
}

/// `WouldBlock` from `try_lock` means SOMEONE holds the lock. Only the probe
/// cell reads this, on one thread and on its own maps, so that someone is
/// the calling path.
fn held<T>(lock: &Mutex<T>) -> bool {
    matches!(lock.try_lock(), Err(TryLockError::WouldBlock))
}

fn probe<A, B>(map: &Mutex<A>, index: &Mutex<B>) -> HeldWireLocks {
    match (held(map), held(index)) {
        (true, false) => HeldWireLocks::TheMap,
        (false, true) => HeldWireLocks::TheIndex,
        (false, false) => HeldWireLocks::Neither,
        (true, true) => HeldWireLocks::Both,
    }
}

fn wait_on(
    mut state: std::sync::MutexGuard<'static, PauseState>,
    timeout: Duration,
    ready: impl Fn(&PauseState) -> bool,
) -> (std::sync::MutexGuard<'static, PauseState>, bool) {
    let deadline = Instant::now() + timeout;
    while !ready(&state) {
        let now = Instant::now();
        if now >= deadline {
            return (state, false);
        }
        state = PAUSE_CV
            .wait_timeout(state, deadline - now)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
    (state, true)
}

fn wait_for(timeout: Duration, ready: impl Fn(&PauseState) -> bool) -> bool {
    wait_on(pause_state(), timeout, ready).1
}

/// Called by `publish_shared_session` between its two wire locks. A no-op
/// unless a cell armed it for `wire_key`, so no other test is affected.
pub(in crate::afxdp) fn publish_between_wire_locks<A, B>(
    wire_key: &SessionKey,
    map: &Mutex<A>,
    index: &Mutex<B>,
) {
    let mut state = pause_state();
    if !matches!(&state.armed, Some((publish, _)) if publish == wire_key) {
        return;
    }
    if state.probe {
        state.publish_held = Some(probe(map, index));
        return;
    }
    state.publish_reached = true;
    PAUSE_CV.notify_all();
    let _ = wait_on(state, Duration::from_secs(10), |s| s.publish_go);
}

/// Called by `remove_shared_session_if` just before its first wire lock.
pub(in crate::afxdp) fn removal_before_wire_locks(wire_key: &SessionKey) {
    let mut state = pause_state();
    if state.probe || !matches!(&state.armed, Some((_, removal)) if removal == wire_key) {
        return;
    }
    state.removal_ready = true;
    PAUSE_CV.notify_all();
    let _ = wait_on(state, Duration::from_secs(10), |s| s.removal_go);
}

/// Called by `remove_shared_session_if` between its two wire locks.
pub(in crate::afxdp) fn removal_between_wire_locks<A, B>(
    wire_key: &SessionKey,
    map: &Mutex<A>,
    index: &Mutex<B>,
) {
    let mut state = pause_state();
    if !matches!(&state.armed, Some((_, removal)) if removal == wire_key) {
        return;
    }
    if state.probe {
        state.removal_held = Some(probe(map, index));
        return;
    }
    state.removal_reached = true;
    PAUSE_CV.notify_all();
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

fn fixture(
    maps: &Maps,
    doomed: SessionKey,
    doomed_port: u16,
    fresh: SessionKey,
    fresh_port: u16,
) -> (SessionKey, SessionKey, crate::nat::NatDecision) {
    let (shared, nat_map, wire_map, indexes) = maps;
    // The session the removal tears down: a NAT'd forward row, so its removal
    // walks the wire-alias branch (both wire locks).
    let doomed_nat = snat(doomed_port);
    publish_shared_session(
        shared,
        nat_map,
        wire_map,
        indexes,
        &row(&doomed, doomed_nat, 1),
    );
    let fresh_nat = snat(fresh_port);
    let publish_wire = crate::session::forward_wire_key(&fresh, fresh_nat);
    let removal_wire = crate::session::forward_wire_key(&doomed, doomed_nat);
    assert_ne!(
        publish_wire, fresh,
        "fixture: the publish must have a wire alias"
    );
    assert_ne!(
        removal_wire, doomed,
        "fixture: the removal must have a wire alias"
    );
    (publish_wire, removal_wire, fresh_nat)
}

fn held_name(held: Option<HeldWireLocks>) -> &'static str {
    held.map_or("nothing: its hook never ran", HeldWireLocks::name)
}

#[test]
fn publish_and_removal_take_the_wire_map_first_18658() {
    let _cell = CELL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let maps = maps();
    let (doomed, fresh) = (key(105, 40003), key(106, 40004));
    let (publish_wire, removal_wire, fresh_nat) =
        fixture(&maps, doomed.clone(), 50003, fresh.clone(), 50004);
    let (shared, nat_map, wire_map, indexes) = &maps;
    arm(publish_wire, removal_wire, true);
    publish_shared_session(
        shared,
        nat_map,
        wire_map,
        indexes,
        &row(&fresh, fresh_nat, 2),
    );
    remove_shared_session(shared, nat_map, wire_map, indexes, &doomed);
    let (publish_held, removal_held) = {
        let mut state = pause_state();
        state.armed = None;
        (state.publish_held, state.removal_held)
    };
    assert_eq!(
        publish_held,
        Some(HeldWireLocks::TheMap),
        "#18658: between its two wire locks publish_shared_session held {}. It must take \
         the forward-wire map first, then `wire_ambiguities`.",
        held_name(publish_held)
    );
    assert_eq!(
        removal_held,
        Some(HeldWireLocks::TheMap),
        "#18658: between its two wire locks remove_shared_session_if held {}. It must take \
         the forward-wire map first, then `wire_ambiguities`.",
        held_name(removal_held)
    );
}

#[test]
fn publish_and_removal_take_the_wire_locks_in_one_order_18658() {
    let _cell = CELL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let maps = maps();
    let (doomed, fresh) = (key(103, 40001), key(104, 40002));
    let (publish_wire, removal_wire, fresh_nat) =
        fixture(&maps, doomed.clone(), 50001, fresh.clone(), 50002);
    arm(publish_wire.clone(), removal_wire.clone(), false);

    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    {
        let (shared, nat_map, wire_map, indexes) = maps.clone();
        let done = done_tx.clone();
        let fresh = fresh.clone();
        std::thread::spawn(move || {
            publish_shared_session(
                &shared,
                &nat_map,
                &wire_map,
                &indexes,
                &row(&fresh, fresh_nat, 2),
            );
            let _ = done.send("publish");
        });
    }
    assert!(
        wait_for(Duration::from_secs(5), |s| s.publish_reached),
        "fixture: the publish never reached its hook between the two wire locks"
    );
    {
        let (shared, nat_map, wire_map, indexes) = maps.clone();
        let done = done_tx.clone();
        let doomed = doomed.clone();
        std::thread::spawn(move || {
            remove_shared_session(&shared, &nat_map, &wire_map, &indexes, &doomed);
            let _ = done.send("removal");
        });
    }
    assert!(
        wait_for(Duration::from_secs(5), |s| s.removal_ready),
        "fixture: the removal never reached its hook before its first wire lock"
    );
    {
        let mut state = pause_state();
        state.removal_go = true;
        PAUSE_CV.notify_all();
    }
    // Correct order: the removal's first wire lock is the map, which the parked
    // publish holds, so it cannot reach its between-locks hook. Inverted: its
    // first wire lock is free, so it gets there at once.
    let removal_passed_first_lock = wait_for(Duration::from_millis(500), |s| s.removal_reached);
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
                 `wire_ambiguities` (finished: {finished:?}; the removal acquired its first \
                 wire lock while the parked publish held its own: {removal_passed_first_lock}). \
                 Both paths must take the map BEFORE the index; \
                 publish_and_removal_take_the_wire_map_first_18658 names which path differs."
            ),
        }
    }
    pause_state().armed = None;
    assert!(
        !removal_passed_first_lock,
        "#18658: while the publish was parked after its first wire lock, the removal acquired \
         its own first wire lock, so the two paths' first wire locks differ \
         (publish_and_removal_take_the_wire_map_first_18658 names them)"
    );
    // The work itself completed: the fresh alias is published and owned, and
    // the doomed one is gone.
    let wires = lock_shared_recover(&maps.2);
    assert_eq!(wires.get(&publish_wire).map(|e| e.key.clone()), Some(fresh));
    assert!(
        !wires.contains_key(&removal_wire),
        "the removal must drop its own alias"
    );
}
