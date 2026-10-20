//! Mutex / RwLock poison-recovery regressions for the WireGuard engine
//! (#6422).
//!
//! Every lock inside `wg/` used to be taken with `.lock().unwrap()` /
//! `.read().unwrap()` / `.write().unwrap()`. `std` marks a lock POISONED
//! once a thread panics while holding its (exclusive) guard, and every
//! subsequent acquisition then returns `Err` — so `.unwrap()` turned one
//! contained panic into a panic on EVERY later acquisition of that lock.
//! Under the #925 worker supervisor that is a permanent tunnel outage:
//! the supervisor restarts the worker, the restarted worker touches the
//! same `Arc`-shared lock, and panics again.
//!
//! The remedy adopted here is the tree-wide idiom
//! (`nat::allocator`, `event_stream`, `sharded_neighbor`,
//! `afxdp::icmp_ratelimit`, …): `unwrap_or_else(|e| e.into_inner())`,
//! which keeps the committed contents of the guarded state and carries
//! on. These tests poison a real engine lock and assert the production
//! entry point still completes — each one reds (panics) if its site is
//! reverted to `.unwrap()`.

use super::session::WgSession;
use super::tests::{established_pair, keypair};
use super::{WgEngine, WgEngineConfig, WgPeerConfig};
use std::net::Ipv4Addr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, RwLock};

/// Poison `m` by panicking while its guard is live.
///
/// In-thread (`catch_unwind`) rather than the spawn-and-join shape used
/// by `worker_queue_tests::poison`, because the locks under test are
/// fields reached through `&WgEngine` / `&Arc<Peer>` and an in-thread
/// poison needs no `Send` bound on the owner. The unwind still drops the
/// guard, which is what sets the poison flag.
pub(in crate::afxdp::wg) fn poison_mutex<T>(m: &Mutex<T>) {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = m.lock().expect("lock must be healthy before poisoning");
        panic!("#6422 test: intentional poison");
    }));
    assert!(res.is_err(), "the poisoning closure must panic");
    assert!(m.is_poisoned(), "mutex must be poisoned");
}

/// Poison `l`. NOTE: an `RwLock` is poisoned only by a panic under an
/// EXCLUSIVE guard — a panic while a read guard is held leaves it clean
/// — so this must take `write()`. Once poisoned, `read()` fails too,
/// which is what makes the read-side sites in `wg/` reachable by these
/// tests.
pub(in crate::afxdp::wg) fn poison_rwlock<T>(l: &RwLock<T>) {
    let res = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = l.write().expect("lock must be healthy before poisoning");
        panic!("#6422 test: intentional poison");
    }));
    assert!(res.is_err(), "the poisoning closure must panic");
    assert!(l.is_poisoned(), "rwlock must be poisoned");
}

/// Two engines that know each other, plus a completed Noise IK transport
/// pair — enough to hand `install_session` a genuine fresh session.
fn fresh_session_for(
    engine: &WgEngine,
    peer_pub: [u8; 32],
    peer_engine: &WgEngine,
    local_index: u32,
    peer_index: u32,
) -> Arc<WgSession> {
    let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
    let mut resp_hs = peer_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let xport = init_hs.into_stateless_transport_mode().unwrap();
    Arc::new(WgSession::new(xport, local_index, peer_index, peer_pub))
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p
}

fn single_peer_engine(private_key: [u8; 32], peer_pub: [u8; 32], cidr: &str) -> WgEngine {
    WgEngine::new(WgEngineConfig {
        local_private_key: private_key.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            endpoint_host: None,
            persistent_keepalive: 0,
            allowed_ips: vec![cidr.parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    })
}

/// `install_session` holds `reconcile_lock` for its whole body. A panic
/// anywhere under that guard (the peer-table walk, the demux-map edit)
/// poisons it permanently, and with `.unwrap()` every subsequent
/// handshake completion for EVERY peer on the tunnel panicked — the
/// session install path is the one both the initiator and the responder
/// finish a handshake through.
#[test]
fn install_session_recovers_poisoned_reconcile_lock_6422() {
    let (init_priv, init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = single_peer_engine(init_priv, peer_pub, "10.0.0.0/24");
    let peer_engine = single_peer_engine(peer_priv, init_pub, "10.0.1.0/24");

    poison_mutex(&engine.reconcile_lock);

    let session = fresh_session_for(&engine, peer_pub, &peer_engine, 0xdead_0001, 7);
    engine
        .install_session(&peer_pub, session)
        .expect("install must succeed through a poisoned reconcile_lock");
    assert!(
        engine
            .sessions_by_local_index
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&0xdead_0001),
        "the installed session must be demuxable after poison recovery"
    );
}

/// The demux map itself. Recovering it is what keeps EXISTING sessions
/// visible: the alternative policies (skip on `Err`, or substitute an
/// empty map) silently drop every live session, which is the same defect
/// #2402 fixed on the HA shared-session maps.
#[test]
fn install_session_recovers_poisoned_demux_map_6422() {
    let (init_priv, init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = single_peer_engine(init_priv, peer_pub, "10.0.0.0/24");
    let peer_engine = single_peer_engine(peer_priv, init_pub, "10.0.1.0/24");

    let first = fresh_session_for(&engine, peer_pub, &peer_engine, 0xbeef_0001, 7);
    engine.install_session(&peer_pub, first).unwrap();

    poison_rwlock(&engine.sessions_by_local_index);

    let second = fresh_session_for(&engine, peer_pub, &peer_engine, 0xbeef_0002, 8);
    engine
        .install_session(&peer_pub, second)
        .expect("install must succeed through a poisoned demux map");
    let by_index = engine
        .sessions_by_local_index
        .read()
        .unwrap_or_else(|e| e.into_inner());
    assert!(
        by_index.contains_key(&0xbeef_0001) && by_index.contains_key(&0xbeef_0002),
        "recovery must preserve the committed entries, not start from empty"
    );
}

/// Egress. `encap_inner` reads the peer's `current` keypair slot on
/// every outbound packet; a poisoned slot used to panic the worker for
/// the life of the peer.
#[test]
fn encap_recovers_poisoned_peer_current_slot_6422() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.0.0/24".parse().unwrap()],
        vec!["10.0.1.0/24".parse().unwrap()],
    );
    let peer = init_engine.peer_arc(&resp_pub).expect("peer is configured");
    poison_rwlock(&peer.current);

    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 1, 5), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("encap must succeed through a poisoned current-keypair slot");
    assert!(enc.len > inner.len(), "a real WG record must be emitted");
}

/// Ingress, the hottest lock in the subsystem: the anti-replay window is
/// taken twice per inbound data record. Recovery is the right policy
/// here too — `ReplayState::check_and_update` is a pure, panic-free
/// counter+bitmap update, so a recovered window is always a well-formed
/// one, whereas `.unwrap()` blackholed the session forever.
#[test]
fn decap_recovers_poisoned_replay_window_6422() {
    let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
        vec!["10.0.0.0/24".parse().unwrap()],
        vec!["10.0.1.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 1, 5), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();

    // Poison the responder-side session's replay window.
    let session = resp_engine
        .sessions_by_local_index
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .next()
        .cloned()
        .expect("responder holds a live session");
    poison_mutex(&session.replay);

    let mut plain = [0u8; 2048];
    let dec = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .expect("decap must succeed through a poisoned replay window");
    assert_eq!(dec.peer_pubkey, init_pub);
    assert_eq!(&plain[..dec.len], &inner[..]);
}

/// Responder handshake anti-replay. Recovery is strictly SAFER than
/// panicking here: the guarded value is a 12-byte high-water mark
/// updated by an infallible compare-and-copy, so `into_inner` always
/// yields a real previously-accepted timestamp, whereas a panic loop
/// under the supervisor risks the peer coming back with the mark reset.
#[test]
fn tai64n_high_water_recovers_poisoned_lock_6422() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.0.0/24".parse().unwrap()],
        vec!["10.0.1.0/24".parse().unwrap()],
    );
    let peer = init_engine.peer_arc(&resp_pub).expect("peer is configured");
    assert!(peer.check_and_update_tai64n(&[0x40; 12]));

    poison_mutex(&peer.greatest_tai64n);

    assert!(
        !peer.check_and_update_tai64n(&[0x40; 12]),
        "recovery must expose the COMMITTED high-water mark, so the \
         replayed timestamp is still rejected"
    );
    assert!(
        peer.check_and_update_tai64n(&[0x41; 12]),
        "a strictly newer timestamp must still be accepted after recovery"
    );
    assert_eq!(peer.greatest_tai64n(), [0x41; 12]);
}

/// Initiator handshake build. `reserve_pending` → `reserve_pending_locked`
/// touches `reconcile_lock`, `sessions_by_local_index`, `pending` and
/// `pending_by_peer` in one sequence; poisoning `pending` alone pins the
/// handshake_session.rs conversions.
#[test]
fn create_initiation_recovers_poisoned_pending_map_6422() {
    let (init_priv, init_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let engine = single_peer_engine(init_priv, peer_pub, "10.0.0.0/24");
    let _ = init_pub;

    poison_rwlock(&engine.pending);

    let mut out = [0u8; super::WG_MSG_INIT_LEN];
    let idx = engine
        .create_initiation(&peer_pub, &mut out)
        .expect("initiation must be built through a poisoned pending map");
    assert!(
        engine
            .pending
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&idx),
        "the reservation must be recorded after poison recovery"
    );
}

/// The periodic timer pass. `expire_sessions` takes `reconcile_lock`
/// every tick; with `.unwrap()` a single poisoning panic stopped session
/// expiry for the life of the process, so dead keypairs were never
/// reaped and REJECT_AFTER_TIME stopped being enforced.
#[test]
fn expire_sessions_recovers_poisoned_reconcile_lock_6422() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.0.0/24".parse().unwrap()],
        vec!["10.0.1.0/24".parse().unwrap()],
    );
    poison_mutex(&init_engine.reconcile_lock);

    // Far past REJECT_AFTER_TIME: the installed session must be reaped.
    let expired = init_engine.expire_sessions(u64::MAX / 2);
    assert_eq!(
        expired, 1,
        "the timer pass must still expire the live session after recovery"
    );
    assert!(
        !init_engine.peer_has_usable_session(&resp_pub, u64::MAX / 2),
        "the expired session must be gone"
    );
}
