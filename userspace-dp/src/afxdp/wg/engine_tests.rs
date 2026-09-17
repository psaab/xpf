// Internal unit tests for the WireGuard engine.
//
// Relocated verbatim from engine.rs (#2158 file-split, #1046 pattern):
// loaded via `#[cfg(test)] #[path = "engine_tests.rs"] mod
// engine_internal_tests;` so `#[path]` keeps this a child of
// `wg::engine` and `use super::*;` reaches the prod-file private
// items unchanged. Pure code-motion: bodies are byte-identical to the
// former inline module modulo a uniform 4-space dedent.

use super::*;
use std::str::FromStr;
use std::sync::atomic::Ordering;

/// #6157: shared serialization guard for the parallel-sensitive WG engine
/// tests that spawn busy-spinning worker threads
/// (`install_session_serializes_with_reconcile_removal`,
/// `reconcile_peers_snapshot_is_atomic_under_concurrent_load`). Each of those
/// tests runs an installer/writer thread against a reconciler/reader thread
/// that spins on `thread::yield_now()` until the finite side finishes. Running
/// two such tests at once under the default parallel `cargo test` oversubscribes
/// the scheduler; combined with leaked neighbor-monitor threads from sibling
/// suites it wedged a full-suite run in a futex deadlock for >100min (#6157).
///
/// Holding this guard for the WHOLE test body serializes the heavy engine
/// tests: while one runs (and busy-spins), the other PARKS on the mutex (futex
/// wait, no CPU burn) instead of compounding the oversubscription. Poison-
/// tolerant (`into_inner`) so a panicking guarded test cannot deadlock the
/// rest of the suite. Mirrors the `icmp_ratelimit::global_bucket_test_lock`
/// precedent. `make test-rust` already forces `--test-threads=1`; this guard
/// makes a plain parallel `cargo test --release` safe too.
fn wg_engine_test_serial() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// #6157 fail-on-revert: `wg_engine_test_serial` must grant EXCLUSIVE access —
/// two threads holding it must never be inside the guarded region at once.
/// That exclusivity is what lets the second heavy engine test PARK on the
/// mutex while the first busy-spins, instead of both oversubscribing the
/// scheduler into the >100min futex deadlock (#6157).
///
/// Two threads, released together from a barrier, repeatedly take the guard
/// and enter a region protected by `IN_CRITICAL`: each swaps it true on entry
/// and asserts it was false (nobody else inside), yields to widen the window,
/// then clears it. With the guard held the swap never observes a concurrent
/// occupant. Removing the `wg_engine_test_serial()` acquisition (reverting the
/// fix) lets both threads enter concurrently, the swap observes `true`, the
/// worker panics, and the join below fails. That revert-red is
/// scheduler-dependent (a degenerate fully-serial schedule could miss the
/// overlap), but the barrier + 2000 iterations + the `yield_now()`-widened
/// window make a collision effectively certain. NOTE: this pins the guard
/// PRIMITIVE's exclusivity, not that the two heavy engine tests actually TAKE
/// it — that application is verified by inspection (both call
/// `wg_engine_test_serial()` at entry), since a deterministic test for the
/// application would reduce to the underlying flake itself.
#[test]
fn wg_engine_test_serial_grants_exclusive_access() {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    use std::sync::{Arc, Barrier};
    use std::thread;
    static IN_CRITICAL: AtomicBool = AtomicBool::new(false);
    IN_CRITICAL.store(false, AOrd::SeqCst);
    const ITERS: u32 = 2_000;
    let start = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let start = start.clone();
        handles.push(thread::spawn(move || {
            start.wait();
            for _ in 0..ITERS {
                let _serial = wg_engine_test_serial();
                let already_inside = IN_CRITICAL.swap(true, AOrd::SeqCst);
                assert!(
                    !already_inside,
                    "two threads entered the guarded region at once — \
                     wg_engine_test_serial did not serialize"
                );
                // Widen the critical window so a missing guard reliably
                // interleaves rather than racing past unobserved.
                thread::yield_now();
                IN_CRITICAL.store(false, AOrd::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join()
            .expect("guarded worker panicked — serialization guard failed");
    }
}

fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    priv_k.copy_from_slice(&kp.private);
    pub_k.copy_from_slice(&kp.public);
    (priv_k, pub_k)
}

#[test]
fn inner_src_ip_v4() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(
        inner_src_ip(&pkt),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
}

#[test]
fn inner_src_ip_v6() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60;
    pkt[8] = 0xfe;
    pkt[9] = 0x80;
    let got = inner_src_ip(&pkt).unwrap();
    match got {
        IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0xfe80),
        _ => panic!("expected v6"),
    }
}

#[test]
fn inner_src_ip_rejects_short() {
    assert!(inner_src_ip(&[0x45u8; 10]).is_none());
    assert!(inner_src_ip(&[0x60u8; 20]).is_none());
    assert!(inner_src_ip(&[]).is_none());
}

#[test]
fn inner_src_ip_rejects_unknown_version() {
    assert!(inner_src_ip(&[0x05u8; 40]).is_none()); // bogus version 0
}

/// Drive a real IK handshake between two engines and return the
/// initiator-side transport session. Helper used by the
/// install_session unit tests below — going through snow is
/// cheaper than a separate mock and keeps the test honest.
fn make_session_for(
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

/// Same-peer same-local-index collision must be refused. Letting
/// it through would move the existing current session into
/// `previous`, but rewrite its demux entry to point at the new
/// session — in-flight ciphertexts addressed to the previous
/// session (which legitimately still decode against its key
/// during the rotation grace window) would demux to the new
/// session, fail AEAD, and drop silently. Codex r4 finding 1 /
/// Gemini r4 finding B. r3's test (now removed) blessed this
/// wrong behavior.
#[test]
fn install_session_same_peer_same_local_index_is_collision() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    let s1_ptr = Arc::as_ptr(&s1);
    engine.install_session(&peer_pub, s1).unwrap();
    // Re-handshake with the SAME local_index for the SAME peer
    // must be rejected with LocalIndexCollision.
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 3);
    let err = engine.install_session(&peer_pub, s2).unwrap_err();
    assert_eq!(err, InstallSessionError::LocalIndexCollision);
    // The original session must still be the demux target.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert_eq!(
        Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()),
        s1_ptr,
        "collision must NOT overwrite the existing same-peer session"
    );
}

/// Successful same-peer rekey on a FRESH `local_index` must:
///   (a) succeed,
///   (b) leave the new session as the demux target for the new
///       index,
///   (c) leave the old session still demuxable on its old index
///       (it has rotated to `previous` and continues to receive
///       in-flight ciphertexts until the next rotation).
#[test]
fn install_session_fresh_index_rekey_preserves_previous_demux() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    let s1_ptr = Arc::as_ptr(&s1);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    let s2_ptr = Arc::as_ptr(&s2);
    engine.install_session(&peer_pub, s2).unwrap();
    let by_index = engine.sessions_by_local_index.read().unwrap();
    // New session is demuxable on the new index.
    assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0002).unwrap()), s2_ptr);
    // Old session is still demuxable on the old index (rotated
    // to `previous`, not dropped yet).
    assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()), s1_ptr);
}

/// A second rekey (s3 on a third fresh index) drops s1 out of
/// (current, previous). The engine must then remove s1's demux
/// entry so its index can be reused for future handshakes.
#[test]
fn install_session_second_rekey_evicts_dropped_session() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    engine.install_session(&peer_pub, s2).unwrap();
    let s3 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0003, 4);
    engine.install_session(&peer_pub, s3).unwrap();
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        by_index.get(&0xaaaa_0001).is_none(),
        "s1 must be evicted from demux after second rotation drops it"
    );
    assert!(by_index.get(&0xaaaa_0002).is_some());
    assert!(by_index.get(&0xaaaa_0003).is_some());
}

/// Collision detection: installing two distinct sessions with the
/// same `local_index` for DIFFERENT peers (or stale handshake
/// race) must return LocalIndexCollision rather than silently
/// overwriting the existing entry.
#[test]
fn install_session_rejects_local_index_collision_across_peers() {
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    let peer_a_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_b_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let sa = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0x1234_5678, 2);
    let sa_ptr = Arc::as_ptr(&sa);
    engine.install_session(&peer_a_pub, sa).unwrap();
    let sb = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0x1234_5678, 3);
    let err = engine.install_session(&peer_b_pub, sb).unwrap_err();
    assert_eq!(err, InstallSessionError::LocalIndexCollision);
    // Peer A's session must still be the one in the demux map.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert_eq!(
        Arc::as_ptr(by_index.get(&0x1234_5678).unwrap()),
        sa_ptr,
        "collision must NOT overwrite the existing session"
    );
}

#[test]
fn encap_rejects_after_message_limit() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let resp = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
    let mut resp_hs = resp.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let session = Arc::new(WgSession::new(
        init_hs.into_stateless_transport_mode().unwrap(),
        1,
        2,
        peer_pub,
    ));
    session.tx_counter.store(
        super::super::session::REJECT_AFTER_MESSAGES,
        Ordering::Relaxed,
    );
    engine.install_session(&peer_pub, session).unwrap();
    let inner = [
        0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let mut out = [0u8; 128];
    let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
    assert_eq!(err, EncapError::RekeyRequired);
}

/// r5 regression: when `reconcile_peers` drops a peer whose
/// pubkey is absent in the new config, the peer's
/// `(current, previous)` session entries MUST be drained from
/// `sessions_by_local_index`. Codex r5 finding: without the
/// drain, every config refresh that removes a peer leaks that
/// peer's session Arcs in the demux map forever (until engine
/// drop). The Arcs also keep `WgSession` (transport key
/// material) alive past peer removal, which violates the
/// expectation that removing a peer immediately revokes its
/// session material from the live state.
#[test]
fn reconcile_peers_drains_dropped_peer_sessions_from_demux() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    // Install two sessions on the peer (current + previous).
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    engine.install_session(&peer_pub, s2).unwrap();
    // Both indices must be in the demux pre-reconcile.
    {
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(by_index.contains_key(&0xaaaa_0001));
        assert!(by_index.contains_key(&0xaaaa_0002));
    }
    // Reconcile with the peer removed.
    engine.reconcile_peers(&[]);
    // Both demux entries must now be gone — the leak is fixed.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        !by_index.contains_key(&0xaaaa_0001),
        "dropped peer's `previous` session must be drained from demux"
    );
    assert!(
        !by_index.contains_key(&0xaaaa_0002),
        "dropped peer's `current` session must be drained from demux"
    );
    assert!(
        by_index.is_empty(),
        "no stray demux entries should remain after peer removal"
    );
}

/// r5 regression: peer removal must NOT touch unrelated peers'
/// sessions. A reconcile that drops peer A while keeping peer B
/// must drain A's demux entries and leave B's intact.
#[test]
fn reconcile_peers_leaves_kept_peer_sessions_intact() {
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    let peer_a_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_b_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s_a = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_a_pub, s_a).unwrap();
    let s_b = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0xbbbb_0001, 4);
    engine.install_session(&peer_b_pub, s_b).unwrap();
    // Reconcile dropping only peer A.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_b_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }]);
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        !by_index.contains_key(&0xaaaa_0001),
        "peer A's session must be drained"
    );
    assert!(
        by_index.contains_key(&0xbbbb_0001),
        "peer B's session must remain — unrelated peer reconcile must not touch it"
    );
}

/// #4362 regression: `reconcile_peers` must drain a removed peer's
/// per-pubkey `cookie_gen` (initiator cookie state, #4094 PR-B) and
/// leave a kept peer's entry intact. `cookie_gen` is keyed by peer
/// pubkey and lives OUTSIDE the atomically-swapped `PeerTable`, so
/// without an explicit drain (matching `pending_by_peer`) a removed
/// peer leaks a stale `InitiatorCookie` until process restart. RED on
/// revert: dropping the `cookie_gen.remove` block leaves peer A's
/// entry present after reconcile.
#[test]
fn reconcile_peers_drains_dropped_peer_cookie_gen() {
    let (init_priv, _init_pub) = keypair();
    let (_peer_a_priv, peer_a_pub) = keypair();
    let (_peer_b_priv, peer_b_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    // Seed initiator-cookie state for both peers, as `add_initiator_macs`
    // / `consume_cookie_reply` would after a real cookie-reply exchange.
    {
        let mut cg = engine.cookie_gen.lock().unwrap();
        cg.insert(peer_a_pub, crate::afxdp::wg::cookie::InitiatorCookie::new());
        cg.insert(peer_b_pub, crate::afxdp::wg::cookie::InitiatorCookie::new());
        assert!(cg.contains_key(&peer_a_pub));
        assert!(cg.contains_key(&peer_b_pub));
    }
    // Reconcile dropping only peer A.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_b_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }]);
    let cg = engine.cookie_gen.lock().unwrap();
    assert!(
        !cg.contains_key(&peer_a_pub),
        "dropped peer's cookie_gen entry must be drained on reconcile (#4362)"
    );
    assert!(
        cg.contains_key(&peer_b_pub),
        "kept peer's cookie_gen entry must survive an unrelated peer removal"
    );
}

/// r5 regression: hot-path readers must observe a torn-free
/// snapshot across `reconcile_peers`. A concurrent
/// reconcile/hot-read interleaving where the reader sees
/// `peer_index_by_pubkey` from the new snapshot but `peers`
/// from the old (or vice versa) would route to the wrong peer.
/// We hammer reconcile in one thread and assert internal
/// consistency from another.
///
/// Invariant verified: every snapshot returned by `load_table()`
/// is internally consistent — for every (pubkey, idx) entry in
/// `peer_index_by_pubkey`, `peers[idx].pubkey == pubkey`. The
/// invariant would fail under torn snapshots if reconcile
/// published the index map and peer vec via separate stores.
#[test]
fn reconcile_peers_snapshot_is_atomic_under_concurrent_load() {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    use std::thread;
    // #6157: serialize the heavy busy-spin engine tests (held for the whole
    // body) so a parallel `cargo test` cannot run two at once and wedge the
    // scheduler. See `wg_engine_test_serial`.
    let _serial = wg_engine_test_serial();
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let (_peer_c_priv, peer_c_pub) = keypair();
    let _ = (peer_a_priv, peer_b_priv);
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_a_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let config_alt = vec![
        WgPeerConfig {
            pubkey: peer_b_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        },
        WgPeerConfig {
            pubkey: peer_c_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.2.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        },
    ];
    let config_orig = vec![WgPeerConfig {
        pubkey: peer_a_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    let writer = {
        let engine = engine.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            for i in 0..2000 {
                if i % 2 == 0 {
                    engine.reconcile_peers(&config_alt);
                } else {
                    engine.reconcile_peers(&config_orig);
                }
            }
            stop.store(true, AOrd::Relaxed);
        })
    };
    let reader = {
        let engine = engine.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut observed = 0u64;
            // #3457: take at least one snapshot BEFORE consulting `stop`
            // (do-while). Under heavy CPU oversubscription the writer can
            // finish all 2000 reconciles and store `stop=true` before this
            // thread is first scheduled; a leading `while !stop` would then
            // observe zero snapshots and fail the `n >= 1` sanity check —
            // a scheduler artifact, not an atomicity violation. The
            // torn-snapshot invariant below still runs on every real
            // snapshot, so the safety check is unchanged; only the
            // reader-starvation flake is removed.
            loop {
                let snapshot = engine.load_table();
                // The invariant: every (pubkey, idx) pair in
                // the index map must map to a peer in `peers`
                // whose pubkey matches. A torn snapshot would
                // pair an old-config pubkey with a new-config
                // peer slot (or vice versa) — different pubkey.
                for (pubkey, idx) in snapshot.peer_index_by_pubkey.iter() {
                    let peer = snapshot
                        .peers
                        .get(*idx as usize)
                        .expect("idx must be in bounds within a snapshot");
                    assert_eq!(
                        &peer.peer.pubkey, pubkey,
                        "torn snapshot: index map and peer vec disagree"
                    );
                }
                observed += 1;
                if stop.load(AOrd::Relaxed) {
                    break;
                }
            }
            observed
        })
    };
    writer.join().unwrap();
    let n = reader.join().unwrap();
    // Sanity: the reader must have done at least one full pass. The
    // do-while above guarantees this deterministically (#3457).
    assert!(n >= 1, "reader thread observed no snapshots");
}

/// #6633: drive remove/re-add churn until `stop`, completing at least ONE full
/// cycle FIRST (do-while) — the same shape, and for the same reason, as the
/// `#3457` do-while in the reader thread of
/// `reconcile_peers_snapshot_is_atomic_under_concurrent_load` above.
///
/// The bounded installer thread it races is finite. Under CPU oversubscription
/// (a loaded machine, or a parallel `cargo test`) the installer can complete
/// all of its attempts, and the main thread can then set `stop`, before this
/// thread is scheduled even once. A leading `while !stop` would then return
/// ZERO cycles and trip the "made progress on both sides" precondition its
/// caller asserts — a scheduler artifact, not a regression in the lock the
/// test exists to pin.
///
/// #6633's fix was the loop SHAPE rather than the rendezvous it had proposed
/// (the reconciler publishing a cycle count the installer blocks on). A
/// rendezvous makes the bounded thread WAIT on the unbounded one, adding a
/// blocking dependency between two test threads in a module whose other open
/// defect was a futex wedge; trading a false red for a possible hang was the
/// wrong trade at the time. The do-while establishes the precondition with no
/// new blocking edge, and it holds by CONSTRUCTION, which is what lets
/// `reconcile_churn_completes_a_cycle_even_when_already_stopped_6633` bind it
/// deterministically. That part stands and the shape below is unchanged.
///
/// **#6989 REVISED the rendezvous half of that judgement — read the two
/// paragraphs together, not the older one alone.** Holding by construction
/// made the caller's guard unfalsifiable in BOTH directions: `>= 1` is also
/// satisfied by a reconciler that ran its one cycle entirely after the
/// installer joined, i.e. zero overlap. So a rendezvous is now added ON TOP of
/// the do-while, under two conditions that did not hold when #6633 declined it
/// — no cycle in the wait-for graph, and a bounded poll that panics BY NAME
/// rather than a block. The futex wedge that grounded the original objection
/// (#6952) closed in #7809. Full reasoning at `wait_for_first_reconcile_cycle`.
///
/// #6989/#6985/#6945: `cycles` publishes the same count LIVE, after every
/// completed cycle, so the installer thread can wait on the reconciler's
/// PROGRESS rather than on the scheduler. The do-while above is retained
/// unchanged — it is what makes the count non-zero by construction; the
/// counter is what makes the count OBSERVABLE while the loop is still
/// running, which is the part the do-while cannot supply. `reconcile_iters`
/// (the return value) and the final `cycles` value are the same number by
/// construction, and the caller asserts that equality so the counter cannot
/// silently stop tracking the loop it is supposed to report.
fn reconcile_churn_until(
    engine: &WgEngine,
    cfg: &[WgPeerConfig],
    stop: &std::sync::atomic::AtomicBool,
    cycles: &std::sync::atomic::AtomicU32,
) -> u32 {
    let mut iters = 0u32;
    loop {
        engine.reconcile_peers(&[]);
        engine.reconcile_peers(cfg);
        iters += 1;
        // Release: the installer thread that observes this count must also
        // observe the peer re-add that closed the cycle.
        cycles.store(iters, Ordering::Release);
        if stop.load(Ordering::Relaxed) {
            return iters;
        }
        std::thread::yield_now();
    }
}

/// #6989/#6985/#6945: the liveness backstop for
/// `wait_for_first_reconcile_cycle`.
///
/// Deliberately enormous relative to the healthy path (the reconciler
/// publishes its first cycle in microseconds). It is a BACKSTOP, not a timing
/// assertion: no correct build can approach it, and no amount of CPU
/// contention should either, because the thread being waited on is unbounded
/// and holds no dependency on the waiter. A red here means the reconcile loop
/// stopped making progress, which is a real defect worth a red.
///
/// This project has been bitten before by "fixing" a wall-clock flake with a
/// TIGHT bounded wait, which only moves the wall-clock sample: a 5s bound
/// reddened master twice. Sixty seconds against a microsecond operation is
/// six orders of magnitude of headroom. If a future red lands here, do not
/// raise this constant — go find the stall.
const RECONCILE_CYCLE_LIVENESS_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(60);

/// #6989/#6985/#6945: block until the reconciler thread has published at least
/// one COMPLETED remove/re-add cycle, and return the count observed.
///
/// This exists because `install_session_serializes_with_reconcile_removal`'s
/// non-vacuity guard was reporting on the wrong thing. Its claim is "both
/// sides made progress, so the race window was actually exercised" — but the
/// quantity it checked (`reconcile_iters >= 1`) is satisfied by a reconciler
/// that ran its single do-while cycle entirely AFTER the installer had already
/// joined. That is zero overlap: the exact case the guard was written to
/// catch, reported as healthy. Before #6633 the same quantity failed the other
/// way, as a scheduling artifact, which is the flake #6989/#6985/#6945 filed.
///
/// Waiting on the OBSERVABLE fixes both directions at once. The installer does
/// not start until the reconciler has demonstrably completed a full cycle, so
/// every install below races live churn — established, not hoped for — and the
/// wait itself cannot flake, because it is bounded by progress rather than by
/// elapsed time.
///
/// **Why this rendezvous is safe where #6633 judged one unsafe.** #6633
/// rejected a rendezvous on two grounds: it makes the bounded thread WAIT on
/// the unbounded one, and the module had an open futex wedge (#6952), so it
/// traded a false red for a possible hang. Both grounds are addressed:
///
///  - There is no cycle in the wait-for graph. The reconciler loops until
///    `stop`, which the MAIN thread sets only after joining the installer, and
///    it acquires no lock the waiting installer holds (the installer holds
///    none while waiting). So the thread being waited on is always runnable.
///  - This is not a futex block. It is a bounded poll that PANICS BY NAME on
///    `RECONCILE_CYCLE_LIVENESS_DEADLINE`, the same idiom `run_bounded` uses
///    for the #6952 sweep. A wedge here becomes a named assertion failure,
///    never an rc=124 wedge — which was #6952's whole complaint about
///    uninterpretable cells.
///
/// The deadline is a parameter rather than a hardcoded constant so that the
/// two fail-on-revert tests below can pin both halves at 50ms — in particular
/// `wait_for_first_reconcile_cycle_reds_by_name_when_progress_stalls`, which
/// would otherwise take 60s to exercise the liveness path. Production callers
/// pass `RECONCILE_CYCLE_LIVENESS_DEADLINE`.
fn wait_for_first_reconcile_cycle(
    cycles: &std::sync::atomic::AtomicU32,
    deadline: std::time::Duration,
) -> u32 {
    let start = std::time::Instant::now();
    loop {
        let seen = cycles.load(Ordering::Acquire);
        if seen >= 1 {
            return seen;
        }
        assert!(
            start.elapsed() < deadline,
            "the reconcile loop never advanced within {:?} — this is a \
             LIVENESS failure, not a timing one. The reconciler thread runs an \
             unbounded loop, depends on no lock this thread holds, and \
             publishes its first completed cycle in microseconds on a healthy \
             build, so no amount of CPU contention reaches this deadline. Do \
             NOT raise the deadline to make this green: it is a backstop, not \
             a timing assertion (#6989/#6985/#6945).",
            deadline
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// #6989 fail-on-revert, positive half: the wait is bounded by PROGRESS, not
/// by elapsed time, and it reports the count it observed.
///
/// The deadline passed here is `Duration::ZERO`, which is the whole point:
/// with the observable already satisfied, a correct helper loads, returns, and
/// never consults the deadline at all, so ZERO passes. Hoist the deadline
/// assertion above the `seen >= 1` check — the natural way to get the ordering
/// wrong — and `start.elapsed() < ZERO` is false on the first iteration and
/// this reds, on every machine, every time.
///
/// It deliberately does NOT assert on `Instant::elapsed`. An earlier draft
/// asserted the call returned within 50ms, which is a wall-clock assertion of
/// exactly the kind this whole change exists to remove: a preemption between
/// `Instant::now()` and the load would have reddened it on a loaded box, and
/// the flake would have been introduced by the flake fix. A zero deadline
/// binds the same property — "does not wait when it does not have to" — as a
/// structural fact rather than a timing measurement.
#[test]
fn wait_for_first_reconcile_cycle_returns_the_observed_count() {
    use std::sync::atomic::AtomicU32;
    let cycles = AtomicU32::new(7);
    let seen = wait_for_first_reconcile_cycle(&cycles, std::time::Duration::ZERO);
    assert_eq!(
        seen, 7,
        "the wait must report the count the reconciler published, not a \
         constant — the caller's overlap guard reads this number"
    );
}

/// #6989 fail-on-revert, negative half: a reconciler that never advances must
/// red BY NAME on the liveness backstop rather than hanging.
///
/// This is the cell that makes the 60s production deadline safe to ship. A
/// bounded wait whose failure path parks the thread would turn a stalled
/// reconciler into an rc=124 wedge, which is the uninterpretable outcome
/// #6952 was filed over. Counter pinned at zero + a 50ms deadline makes the
/// liveness path deterministic and fast; deleting the `assert!` inside the
/// loop hangs this test instead of passing it, so the cell cannot go green on
/// a revert.
#[test]
#[should_panic(expected = "LIVENESS failure")]
fn wait_for_first_reconcile_cycle_reds_by_name_when_progress_stalls() {
    use std::sync::atomic::AtomicU32;
    let never = AtomicU32::new(0);
    wait_for_first_reconcile_cycle(&never, std::time::Duration::from_millis(50));
}

/// #6633 fail-on-revert for `reconcile_churn_until`'s do-while shape.
///
/// Calling it with `stop` ALREADY set is the deterministic model of the
/// starvation that flaked `install_session_serializes_with_reconcile_removal`:
/// the reconciler thread is scheduled only after the installer finished and
/// the main thread stored `stop`. The contract is that it still completes one
/// full remove/re-add cycle, so its caller's `reconcile_iters >= 1` holds by
/// construction. Reverting the do-while to a leading `while !stop` returns 0
/// here and reds — with no dependence on the scheduler, which is precisely
/// what the original assertion lacked.
///
/// It takes no `wg_engine_test_serial()` guard on purpose: it is
/// single-threaded and spawns nothing, so it is not one of the heavy
/// busy-spin bodies #6157 serializes.
#[test]
fn reconcile_churn_completes_a_cycle_even_when_already_stopped_6633() {
    use std::sync::atomic::AtomicBool;
    let (init_priv, _init_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let cfg = vec![WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: cfg.clone(),
    });
    let stop = AtomicBool::new(true);
    let cycles = std::sync::atomic::AtomicU32::new(0);
    let iters = reconcile_churn_until(&engine, &cfg, &stop, &cycles);
    assert_eq!(
        iters, 1,
        "reconcile_churn_until must complete one full remove/re-add cycle even \
         when stop is already set (#6633); a leading `while !stop` returns 0 and \
         leaves install_session_serializes_with_reconcile_removal asserting a \
         scheduling outcome its harness never arranged"
    );
    // #6989: the LIVE counter the installer's rendezvous waits on must track
    // the same cycles the return value reports. Dropping the `cycles.store`
    // in `reconcile_churn_until` leaves `iters` correct and this zero, and
    // the rendezvous would then wait out its full 60s backstop on every run.
    assert_eq!(
        cycles.load(Ordering::Acquire),
        iters,
        "the published cycle counter must equal the cycles actually completed \
         (#6989); a counter that stops tracking the loop turns the installer's \
         overlap rendezvous into a 60s stall"
    );
    // The cycle really ran: the churn ends on the re-add, so the peer is
    // published. Without this the assertion above would pass on a helper that
    // merely counted without touching the engine.
    assert!(
        engine
            .table_for_test()
            .peer_index_by_pubkey
            .contains_key(&peer_pub),
        "the completed cycle must have re-added the peer"
    );
}

/// #6952: run `f` on a worker thread and fail — BY NAME, in bounded time — if
/// it does not finish.
///
/// The bodies this wraps can SELF-DEADLOCK a single thread (see
/// `assert_no_orphan_demux_entries`). Without this wrapper such a deadlock
/// parks a libtest worker forever: the run never completes, `cargo test` is
/// killed at its timeout, and the exit code is 124 — which is neither "the
/// assertion held" nor "the assertion failed". #6952 was filed because a
/// mutation cell that lands on that outcome is uninterpretable, and scoring it
/// as either polarity manufactures evidence. A named assertion failure is
/// always readable; a wedge never is.
///
/// The deadline is deliberately loose (30s against a body that takes
/// microseconds when healthy) — it is a liveness backstop, not a timing
/// assertion, so a loaded machine cannot turn it into a flake. On the deadlock
/// path the worker thread stays parked; that is intentional and harmless,
/// because libtest exits the process rather than joining detached threads.
///
/// #6989: a body that PANICS is a different outcome from a body that parks,
/// and the two must not report the same way. The wait therefore watches the
/// join handle as well as the flag: once the worker has finished without
/// setting `done`, its panic is resumed on the calling thread verbatim. Found
/// while mutation-testing #6989 — removing `reconcile_lock` from
/// `install_session` makes the sweep's orphan assertion fire ("found 126"),
/// and the flag-only shape reported that 30 seconds later as a "same-thread
/// RwLock self-deadlock". That is the wrong defect at 60x the cost, and a
/// mutation cell scored on the named message would have attributed a real
/// serialization regression to #6952.
fn run_bounded<F>(what: &str, f: F)
where
    F: FnOnce() + Send + 'static,
{
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
    let done = Arc::new(AtomicBool::new(false));
    let handle = {
        let done = done.clone();
        thread::spawn(move || {
            f();
            done.store(true, AOrd::SeqCst);
        })
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done.load(AOrd::SeqCst) {
        // Finished but `done` unset: the body panicked. Re-raise ITS panic so
        // the failure names the assertion that actually fired.
        if handle.is_finished() {
            match handle.join() {
                Ok(()) => return,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        assert!(
            Instant::now() < deadline,
            "{what} did not finish within 30s — the worker thread is parked, \
             which for this body means a same-thread RwLock self-deadlock \
             (#6952). It did NOT merely run slowly: the healthy path is \
             microseconds, and a body that panicked would have been re-raised \
             above instead of reaching this deadline."
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// #6952: the orphan-demux post-condition sweep, shared by
/// `install_session_serializes_with_reconcile_removal` (where it is the real
/// post-condition) and by
/// `orphan_demux_sweep_does_not_self_deadlock_6952` (where it is the subject).
///
/// THE SCOPE AROUND THE FIRST READ GUARD IS LOAD-BEARING. `reconcile_peers`
/// takes the WRITE guard on `sessions_by_local_index` whenever the peer it is
/// removing still owns a live `current`/`previous`/`next` session, and
/// `std::sync::RwLock` is not reentrant — so a read guard still alive at the
/// `reconcile_peers(&[])` below deadlocks the calling thread outright.
///
/// The shipped defect was subtler than a plain double-lock: the second
/// `let by_index = ...` SHADOWS the first binding but does NOT drop its guard.
/// A shadowed value lives to the end of the enclosing block, so the first
/// guard was still held across the reconcile. Only the explicit scope ends it.
///
/// It was INTERMITTENT because the write is conditional: `reconcile_peers`
/// takes it only when `dropped_indices` is non-empty, i.e. only when the
/// removed peer still owns a live session. In the racing caller that needs a
/// narrow window. `reconcile_churn_until` always ends its cycle on the RE-ADD,
/// and a removal drops the `Arc<Peer>` (a later re-add builds a fresh one, see
/// the `existing` branch of `reconcile_peers`), so a reconciler that runs even
/// one more full cycle after the installer's last successful install leaves a
/// SESSIONLESS peer and the sweep never reaches the write. The deadlock needs
/// the reconciler to observe `stop` with ZERO further cycles, while the peer it
/// last re-added still carries the install. CPU contention deschedules the
/// reconciler and widens that window, which is why the wedge tracked machine
/// load. `--test-threads=1` does not remove the hazard — the two racing threads
/// are spawned by the test, not by libtest — it only shifts the odds.
fn assert_no_orphan_demux_entries(engine: &WgEngine, cfg_with_peer: &[WgPeerConfig]) {
    engine.reconcile_peers(cfg_with_peer);
    let table = engine.load_table();
    {
        let by_index = engine.sessions_by_local_index.read().unwrap();
        for (local_index, session) in by_index.iter() {
            assert!(
                table.peer_index_by_pubkey.contains_key(&session.peer_pubkey),
                "demux entry {local_index:#x} references unknown peer pubkey \
                 — orphan from install/reconcile race"
            );
        }
    }
    // Now flip the peer out one more time. Reconcile's drain
    // path must remove every session belonging to that peer; any
    // surviving entry would prove the orphan slipped through.
    engine.reconcile_peers(&[]);
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        by_index.is_empty(),
        "after removing the only peer, no demux entries should remain; \
         found {} — install/reconcile race left orphans",
        by_index.len()
    );
}

/// #6952 FAIL-ON-REVERT for the scope around the first read guard in
/// `assert_no_orphan_demux_entries`.
///
/// `install_session_serializes_with_reconcile_removal` reaches the deadlock
/// only on the subset of schedules that leave a live session on the surviving
/// peer, so it cannot pin the hazard: on most runs its `reconcile_peers(&[])`
/// finds `dropped_indices` empty, never takes the demux write lock, and passes
/// with the bug fully present. This test arranges the deciding precondition
/// DETERMINISTICALLY instead of racing for it — install one session on the only
/// peer, assert the demux map is non-empty, and only then run the sweep — so
/// removing the scope reds it on every run rather than one in six.
///
/// Deleting the braces in `assert_no_orphan_demux_entries` restores the shipped
/// shadowing shape, and this test then fails by name on the 30s liveness
/// backstop in `run_bounded`.
#[test]
fn orphan_demux_sweep_does_not_self_deadlock_6952() {
    use std::sync::Arc;
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let cfg_with_peer = vec![WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: cfg_with_peer.clone(),
    }));
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let session = make_session_for(&engine, peer_pub, &peer_engine, 0x6952_0001, 6952);
    engine
        .install_session(&peer_pub, session)
        .expect("install must succeed against the configured peer");
    // The DECIDING precondition, asserted rather than hoped for: the peer owns
    // a live session, so the sweep's `reconcile_peers(&[])` WILL find
    // `dropped_indices` non-empty and WILL take the demux write lock. Without
    // this the sweep never reaches the write and the test would pass on the
    // reverted code — a green that proves nothing.
    assert_eq!(
        engine.sessions_by_local_index.read().unwrap().len(),
        1,
        "precondition: the peer must own a live demux entry, or the sweep \
         never takes the write lock this test exists to cross"
    );
    let cfg = cfg_with_peer.clone();
    let e = engine.clone();
    run_bounded("orphan demux sweep", move || {
        assert_no_orphan_demux_entries(&e, &cfg)
    });
}

/// r6 regression: `install_session` and `reconcile_peers` must
/// serialize so a removed peer cannot orphan a freshly-installed
/// demux entry.
///
/// Race (pre-fix):
///   1. install_session(P) loads `peer` via `peer_arc(P)` from
///      `PeerTable_v1` and drops the snapshot reference.
///   2. reconcile_peers(&[]) publishes `PeerTable_v2` without P.
///      Its drain loop reads `peer.current.read()` and
///      `peer.previous.read()` — both `None` because step (1)
///      hasn't called `rotate_session` yet.
///   3. install_session continues against the orphan Arc<Peer>,
///      inserts the demux entry, and calls rotate_session. The
///      demux entry now references a peer pubkey absent from
///      every future `peer_index_by_pubkey`, so subsequent
///      reconciles cannot drain it.
///
/// Fix: `install_session` takes `reconcile_lock` for the entire
/// critical region. The lookup-then-mutate sequence is then
/// serialized against any concurrent `reconcile_peers`, and if
/// the peer is removed before the install acquires the lock, the
/// `peer_arc(pubkey)` lookup returns None and the install fails
/// with `UnknownPeer` — no demux mutation occurs.
///
/// Invariant verified across the race: every entry in
/// `sessions_by_local_index` has its `session.peer_pubkey`
/// present in the currently published `peer_index_by_pubkey`.
/// Under the pre-fix code path, this invariant would fail
/// whenever the orphan interleaving fires.
#[test]
fn install_session_serializes_with_reconcile_removal() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AOrd};
    use std::thread;
    // #6157: serialize the heavy busy-spin engine tests (held for the whole
    // body) so a parallel `cargo test` cannot run two at once and wedge the
    // scheduler. See `wg_engine_test_serial`.
    let _serial = wg_engine_test_serial();
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let cfg_with_peer = vec![WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    // Pre-build a batch of sessions off the hot path. Each one
    // gets a fresh local_index so installs never collide on the
    // demux map for the wrong reason.
    let iterations = 400u32;
    let mut sessions: Vec<Arc<WgSession>> = Vec::with_capacity(iterations as usize);
    for i in 0..iterations {
        sessions.push(make_session_for(
            &engine,
            peer_pub,
            &peer_engine,
            0xcafe_0000 + i,
            100 + i,
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    // #6989/#6985/#6945: the reconciler's LIVE cycle count. Thread A waits on
    // this before its first install, which is what turns "the two threads
    // probably overlapped" into an established precondition. See
    // `wait_for_first_reconcile_cycle`.
    let cycles = Arc::new(AtomicU32::new(0));
    // Thread A: install_session in a tight loop, alternating
    // with reconciles that re-add the peer so installs can
    // succeed sometimes.
    let installer = {
        let engine = engine.clone();
        let cycles = cycles.clone();
        thread::spawn(move || {
            // Do not begin installing until the reconciler has demonstrably
            // completed a full remove/re-add cycle. Every install below then
            // races LIVE churn. Bounded by the reconciler's progress, not by
            // elapsed time; on a stall it panics HERE, and the join below
            // re-raises that panic so this test fails by name with the
            // liveness message rather than an opaque `Any { .. }`.
            let saw_cycles =
                wait_for_first_reconcile_cycle(&cycles, RECONCILE_CYCLE_LIVENESS_DEADLINE);
            let mut ok = 0u32;
            let mut unknown = 0u32;
            let mut collision = 0u32;
            for s in sessions {
                match engine.install_session(&peer_pub, s) {
                    Ok(()) => ok += 1,
                    Err(InstallSessionError::UnknownPeer) => unknown += 1,
                    Err(InstallSessionError::LocalIndexCollision) => collision += 1,
                }
                thread::yield_now();
            }
            (ok, unknown, collision, saw_cycles)
        })
    };
    // Thread B: alternate removing and re-adding the peer.
    let reconciler = {
        let engine = engine.clone();
        let stop = stop.clone();
        let cfg = cfg_with_peer.clone();
        let cycles = cycles.clone();
        thread::spawn(move || reconcile_churn_until(&engine, &cfg, &stop, &cycles))
    };
    // Re-raise the installer's own panic rather than `unwrap()`-ing it into an
    // opaque `Any { .. }`: the rendezvous above fails BY MESSAGE on its
    // liveness backstop, and that message is the diagnosis.
    let (ok, unknown, collision, saw_cycles) = installer
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
    stop.store(true, AOrd::Relaxed);
    let reconcile_iters = reconciler.join().unwrap();
    assert!(
        ok + unknown + collision == iterations,
        "every install attempt accounted for"
    );
    // #6989 wiring bind: the counter the rendezvous waited on must be the same
    // count the churn loop actually completed. If `reconcile_churn_until` ever
    // stops publishing (or publishes something other than its cycle count),
    // the rendezvous above is guarding a number that is not the reconciler's
    // progress, and this equality is what catches that rather than a silent
    // 60s stall.
    assert_eq!(
        reconcile_iters,
        cycles.load(AOrd::Acquire),
        "the published cycle count must equal the cycles reconcile_churn_until \
         completed (published={}, completed={reconcile_iters}) — the installer's \
         overlap rendezvous reads the published one",
        cycles.load(AOrd::Acquire)
    );
    // The non-vacuity guard, restated as the property it always CLAIMED.
    //
    // This used to read `reconcile_iters >= 1`, whose message said "we made
    // progress on both sides — otherwise the test is not actually exercising
    // the race window". That number never established overlap. Before #6633 it
    // could be 0 purely because the scheduler had not run thread B yet
    // (#6989/#6985/#6945: 1-of-20 under CPU contention, always a false red);
    // after #6633's do-while it is >= 1 by construction, including on the
    // schedule where thread B ran its one cycle entirely AFTER thread A had
    // finished — zero overlap, reported as healthy. Both directions are the
    // same defect: the quantity is a PRECONDITION GUARD, and it was measuring
    // the scheduler instead of the precondition.
    //
    // `saw_cycles` is the reconciler's cycle count as observed by thread A
    // BEFORE its first install, so `>= 1` here means completed churn preceded
    // every install in the loop. It cannot be a scheduling artifact: the
    // rendezvous either observes progress or fails by name on a 60s liveness
    // backstop. It is not vacuous either — replacing the bounded wait with a
    // bare `cycles.load()` snapshot (the obvious wrong simplification) reds
    // here on exactly the schedules the old assertion mis-reported.
    assert!(
        saw_cycles >= 1,
        "the installer must have observed at least one COMPLETED reconcile \
         cycle before its first install (saw_cycles={saw_cycles}); without \
         that, the installs did not race live churn and the serialization \
         property below is not on the test trajectory"
    );
    // r7 Codex hostile finding: a tautological pass shape exists
    // if the reconciler always wins the lock — every install
    // returns UnknownPeer, demux stays empty, and the post-loop
    // invariants are trivially satisfied even with the lock
    // removed. Require at least one Ok install so the lock-
    // protected path (peer_arc-then-rotate_session under the
    // same guard) is actually exercised. With 400 iterations and
    // reconcile alternating add/remove on a separate thread, the
    // installer typically lands 50-300 Ok results in practice;
    // requiring just `ok > 0` is conservative against schedule
    // skew while keeping the gate non-vacuous.
    assert!(
        ok > 0,
        "race regression must exercise at least one successful install \
         (ok={ok}, unknown={unknown}, collision={collision}); without an \
         Ok the lock-protected demux insert path is not on the test \
         trajectory and the gate is tautological"
    );
    // Post-condition invariant: every entry in
    // `sessions_by_local_index` must reference a peer pubkey
    // that is present in the currently published table. An
    // orphan demux entry (the race the fix closes) would have a
    // `session.peer_pubkey` that is not in the index map of any
    // future snapshot — and we can detect it by re-reconciling
    // the peer back in and checking the index map directly.
    //
    // #6952: run the sweep through `run_bounded` so a reintroduced
    // self-deadlock inside it fails THIS test by name instead of parking the
    // thread forever and wedging the whole binary at rc=124.
    let cfg = cfg_with_peer.clone();
    run_bounded(
        "install_session_serializes_with_reconcile_removal orphan sweep",
        move || assert_no_orphan_demux_entries(&engine, &cfg),
    );
}

/// r6 regression for the MINOR Codex finding: `try_encap` must
/// not consume a tx counter (or write the WG header) when it
/// returns `BufferTooSmall` because the inner IP would overflow
/// the PADDED_PLAINTEXT_MAX staging buffer.
///
/// Pre-fix sequence at engine.rs:
///   1. `out.len() < required` check (fires for small `out`).
///   2. `next_tx_counter()` — counter advances.
///   3. `encode_data_header(out, ...)` — 16 bytes written.
///   4. `padded_len > PADDED_PLAINTEXT_MAX` check — fires here.
/// Result on the failure path: counter consumed, header dirty,
/// and the caller sees BufferTooSmall but cannot rely on
/// "Err leaves state untouched".
///
/// Post-fix: the PADDED_PLAINTEXT_MAX guard is hoisted above
/// `next_tx_counter()` (and above the header write), so the
/// failure path leaves both the counter and `out` untouched.
#[test]
fn encap_padded_plaintext_overflow_leaves_counter_and_buffer_untouched() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let session = make_session_for(&engine, peer_pub, &peer_engine, 0xdead_0001, 2);
    engine.install_session(&peer_pub, session).unwrap();
    // inner_ip = 4097 bytes → pad_to_16(4097) = 4112 >
    // PADDED_PLAINTEXT_MAX (4096). `out` is sized large enough to
    // hold header + 4112 + 16 so it cleanly passes the
    // `out.len() < required` guard and only the staging guard
    // can fire.
    let inner = vec![0x45u8; 4097];
    let mut out = vec![0xa5u8; WG_DATA_HEADER_LEN + 4112 + POLY1305_TAG_LEN];
    // Snapshot the per-session counter pre-encap.
    let counter_before = session_tx_counter(&engine, &peer_pub);
    let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
    assert_eq!(err, EncapError::BufferTooSmall);
    let counter_after = session_tx_counter(&engine, &peer_pub);
    assert_eq!(
        counter_before, counter_after,
        "BufferTooSmall on PADDED_PLAINTEXT_MAX overflow must NOT advance tx counter"
    );
    // First 16 bytes of `out` must remain the 0xa5 sentinel — no
    // partial header write on the failure path.
    assert!(
        out[..WG_DATA_HEADER_LEN].iter().all(|&b| b == 0xa5),
        "BufferTooSmall must NOT write the WG header into `out`"
    );
}

/// Helper for the BufferTooSmall counter-leak test: read the
/// `current` session's tx_counter for `pubkey`.
fn session_tx_counter(engine: &WgEngine, pubkey: &[u8; 32]) -> u64 {
    let table = engine.load_table();
    let idx = *table.peer_index_by_pubkey.get(pubkey).unwrap();
    let peer = table.peers[idx as usize].peer.clone();
    let cur = peer.current.read().unwrap().clone().unwrap();
    cur.tx_counter.load(Ordering::Relaxed)
}

// === #1434 multi-peer tests ===

/// #1434 B1b: the encap-side cryptokey-routing lookup must select the
/// peer whose AllowedIPs cover the inner DESTINATION (longest-prefix
/// match), returning that peer's pubkey + endpoint. A dst no peer claims
/// returns None (the frame is dropped — nowhere to send it).
#[test]
fn peer_for_dest_lpm_selects_owning_peer() {
    let (local_priv, _local_pub) = keypair();
    let (_a_priv, a_pub) = keypair();
    let (_b_priv, b_pub) = keypair();
    let a_ep: std::net::SocketAddr = "203.0.113.1:51820".parse().unwrap();
    let b_ep: std::net::SocketAddr = "198.51.100.7:51820".parse().unwrap();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: local_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: a_pub,
                endpoint: Some(a_ep),
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.1.0.0/16").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: b_pub,
                endpoint: Some(b_ep),
                persistent_keepalive: 0,
                // A more-specific /24 inside A would still resolve to B for
                // that /24 (global LPM), proving longest-prefix wins.
                allowed_ips: vec![
                    ipnet::IpNet::from_str("10.2.0.0/16").unwrap(),
                    ipnet::IpNet::from_str("10.1.5.0/24").unwrap(),
                ],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    // 10.1.9.9 → A's /16.
    let (pk, ep) = engine
        .peer_for_dest("10.1.9.9".parse().unwrap())
        .expect("A covers 10.1.9.9");
    assert_eq!(pk, a_pub, "10.1.9.9 routes to peer A");
    assert_eq!(ep, Some(a_ep));
    // 10.2.3.4 → B's /16.
    let (pk, ep) = engine
        .peer_for_dest("10.2.3.4".parse().unwrap())
        .expect("B covers 10.2.3.4");
    assert_eq!(pk, b_pub, "10.2.3.4 routes to peer B");
    assert_eq!(ep, Some(b_ep));
    // 10.1.5.7 → B's MORE-SPECIFIC /24 even though A's /16 also covers it.
    let (pk, _ep) = engine
        .peer_for_dest("10.1.5.7".parse().unwrap())
        .expect("B's /24 covers 10.1.5.7");
    assert_eq!(pk, b_pub, "longest-prefix /24 wins over the covering /16");
    // 192.0.2.1 → no peer.
    assert!(
        engine.peer_for_dest("192.0.2.1".parse().unwrap()).is_none(),
        "an unclaimed dst selects no peer"
    );
}

/// #1434 B2: a per-peer preshared key must round-trip through a real
/// handshake — matching PSKs complete, a mismatched PSK fails the AEAD
/// in msg2. Exercises the initiator (build-time PSK) and responder
/// (set_psk-after-msg1) paths together.
#[test]
fn per_peer_psk_handshake_roundtrip() {
    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();
    let psk = [0x5au8; 32];

    let make = |local_priv: [u8; 32], peer_pub, peer_psk: [u8; 32]| {
        WgEngine::new(WgEngineConfig {
            local_private_key: local_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: peer_psk.into(),
            }],
        })
    };

    // Matching PSK on both sides → full handshake completes.
    {
        let init = make(init_priv, resp_pub, psk);
        let resp = make(resp_priv, init_pub, psk);
        let mut init_hs = init.build_initiator_handshake(&resp_pub).unwrap();
        let mut msg1 = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut msg1).unwrap();
        // Responder side: build, read msg1, set the peer's PSK, write msg2.
        let mut resp_hs = resp.build_responder_handshake().unwrap();
        resp_hs.read_message(&msg1[..n1], &mut sink).unwrap();
        let rs = resp_hs.get_remote_static().unwrap();
        assert_eq!(rs, init_pub, "responder recovers the initiator pubkey");
        resp_hs.set_psk(2, &psk).unwrap();
        let mut msg2 = [0u8; 1024];
        let n2 = resp_hs.write_message(&[], &mut msg2).unwrap();
        // Initiator reads msg2 (PSK was set at build via build_initiator).
        init_hs
            .read_message(&msg2[..n2], &mut sink)
            .expect("matching PSK must complete the handshake");
        assert!(init_hs.is_handshake_finished());
    }

    // Mismatched PSK (initiator zero, responder real) → msg2 AEAD fails.
    {
        let init = make(init_priv, resp_pub, [0u8; 32]); // no PSK
        let resp = make(resp_priv, init_pub, psk); // real PSK
        let mut init_hs = init.build_initiator_handshake(&resp_pub).unwrap();
        let mut msg1 = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut msg1).unwrap();
        let mut resp_hs = resp.build_responder_handshake().unwrap();
        resp_hs.read_message(&msg1[..n1], &mut sink).unwrap();
        resp_hs.set_psk(2, &psk).unwrap();
        let mut msg2 = [0u8; 1024];
        let n2 = resp_hs.write_message(&[], &mut msg2).unwrap();
        assert!(
            init_hs.read_message(&msg2[..n2], &mut sink).is_err(),
            "a PSK mismatch must fail the msg2 AEAD"
        );
    }
}

#[test]
fn wg_config_secret_carriers_are_zeroizing() {
    // #4103 F12: the config carriers for the X25519 private key and the
    // per-peer PSK must be `Zeroizing<[u8; 32]>` (matching the runtime
    // copies — the engine's `local_private_key` and `PeerConfig`'s PSK) so
    // a cloned/dropped WG config does not leave plaintext key material in
    // freed heap/stack. Reverting either field back to a plain `[u8; 32]`
    // makes these type-annotated bindings fail to compile (RED).
    let cfg = WgEngineConfig {
        local_private_key: [1u8; 32].into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [2u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [3u8; 32].into(),
        }],
    };
    let priv_ref: &zeroize::Zeroizing<[u8; 32]> = &cfg.local_private_key;
    let psk_ref: &zeroize::Zeroizing<[u8; 32]> = &cfg.peers[0].preshared_key;
    assert_eq!(**priv_ref, [1u8; 32]);
    assert_eq!(**psk_ref, [3u8; 32]);
    // Clone preserves the Zeroizing wrapper (no plaintext copy escapes).
    let cloned: zeroize::Zeroizing<[u8; 32]> = cfg.local_private_key.clone();
    assert_eq!(*cloned, [1u8; 32]);
}

// ===================================================================
// #4094 PR-A: responder under-load cookie / MAC2 anti-flood gate.
// classify_initiation is the DoS-mitigation seam that decides whether
// an inbound type-1 initiation reaches the expensive Noise handshake.
// ===================================================================

/// Build an engine whose responder static pubkey is known to the test,
/// plus a synthetic VALID-MAC1 initiation toward it (MAC2 = zeros, as a
/// not-yet-challenged initiator sends). The Noise body is a fixed pattern
/// — classify_initiation never runs snow, it only inspects MAC1/MAC2, so a
/// real snow body is unnecessary here (the handshake path itself is
/// covered by the interop tests).
fn under_load_fixture() -> (WgEngine, [u8; 32], [u8; super::super::WG_MSG_INIT_LEN]) {
    let (priv_k, _pub_k) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: priv_k.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0x99u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let our_pub = engine.local_public_key();
    let noise = [0x3Cu8; crate::afxdp::wg::handshake::MSG_INIT_NOISE_LEN];
    let mut init = [0u8; super::super::WG_MSG_INIT_LEN];
    crate::afxdp::wg::handshake::build_initiation(&mut init, 0xCAFE_1234, &noise, &our_pub)
        .unwrap();
    (engine, our_pub, init)
}

/// RED-on-revert: under a simulated initiation flood the responder MUST
/// answer a spoofed/unprimed initiation (valid MAC1, no valid MAC2) with a
/// cookie challenge and NOT run the Noise handshake. On revert (no cookie
/// gate) classify_initiation would return `Process` for every initiation —
/// the CPU-exhaustion DoS. An initiation that echoes a valid MAC2 (derived
/// from the cookie the responder issued to its real source) IS processed,
/// and a peer that never crossed the load threshold is processed with no
/// challenge (no regression on the normal path).
#[test]
fn classify_initiation_under_load_requires_mac2() {
    use crate::afxdp::wg::cookie::{
        CookieChecker, INITIATIONS_UNDER_LOAD_THRESHOLD, stamp_initiation_mac2,
    };
    use std::net::SocketAddr;

    let (engine, our_pub, init) = under_load_fixture();
    let now = 10_000_000_000u64; // 10 s (nonzero: engages the mock clock)
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // Normal load: a valid initiation is processed WITHOUT a challenge —
    // the not-under-load path is byte-identical to today (skip-verify).
    assert_eq!(
        engine.classify_initiation(&init, from, &mut out, now),
        InitiationAction::Process,
        "under threshold, a normal initiation must proceed with no cookie"
    );

    // Drive the arrival rate past the threshold within the same 1 s window,
    // each arrival from a DISTINCT source so the #4332 per-source reply bucket
    // is not the limiting factor here — this test isolates the MAC2 requirement
    // (a single source's own budget is covered by the cookie.rs unit tests and
    // `classify_initiation_per_source_budget_isolation`). `from` itself is not
    // used in the flood, so its per-source bucket stays full for the assertions
    // below.
    for i in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        let s: SocketAddr = format!("192.0.2.{}:51820", (i % 250) + 1).parse().unwrap();
        engine.classify_initiation(&init, s, &mut out, now);
    }

    // Under load, an initiation with NO valid MAC2 is cookie-challenged and
    // DROPPED — the Noise handshake is never spent. This is the RED-on-
    // revert assertion (reverting the gate makes this `Process`).
    let action = engine.classify_initiation(&init, from, &mut out, now);
    let cookie_len = match action {
        InitiationAction::SendCookie(len) => len,
        other => panic!("under-load init without MAC2 must be cookie-challenged, got {other:?}"),
    };
    assert_eq!(cookie_len, crate::afxdp::wg::cookie::WG_MSG_COOKIE_LEN);
    assert_eq!(out[0], crate::afxdp::wg::WG_TYPE_COOKIE);

    // A real initiator decrypts the cookie (PR-B mirror) using our pubkey +
    // the initiation's MAC1 as AAD, then stamps a valid MAC2 over the same
    // source. That initiation IS processed under load.
    let aad_mac1 = &init[116..132];
    let cookie = CookieChecker::decrypt_cookie_reply(&out[..cookie_len], &our_pub, aad_mac1)
        .expect("cookie reply must decrypt");
    let mut primed = init;
    stamp_initiation_mac2(&mut primed, &cookie);
    assert_eq!(
        engine.classify_initiation(&primed, from, &mut out, now),
        InitiationAction::Process,
        "under load, an initiation with a VALID MAC2 must reach the handshake"
    );

    // The SAME MAC2 replayed from a DIFFERENT source is still challenged:
    // the cookie binds to the source that received the reply, so a spoofed
    // source cannot borrow another endpoint's MAC2.
    let spoof: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    assert!(
        matches!(
            engine.classify_initiation(&primed, spoof, &mut out, now),
            InitiationAction::SendCookie(_)
        ),
        "a stolen MAC2 must not authorize a handshake from a different source"
    );

    // The DoS-mitigation counters moved.
    let c = engine.counters();
    assert!(
        c.hs_cookie_replies_sent.load(Ordering::Relaxed) >= 2,
        "cookie replies issued for the unprimed + spoofed initiations"
    );
    assert!(
        c.hs_rx_under_load_mac2_ok.load(Ordering::Relaxed) >= 1,
        "the primed initiation counted as an under-load MAC2 pass"
    );
    assert!(c.hs_rx_under_load_no_mac2.load(Ordering::Relaxed) >= 2);
}

/// #4332 RED-on-revert: the cookie-reply budget is isolated PER SOURCE, so a
/// valid-MAC1 flood from ONE source cannot drain the GLOBAL per-window budget
/// away from a legit peer at a DIFFERENT source. Source A floods far past
/// `COOKIE_REPLY_BUDGET_PER_WINDOW`; without the per-source layer A would
/// consume every global cookie-reply slot and B's FIRST challenge would be
/// budget-suppressed (Drop). With the per-source bucket A is throttled after
/// its own burst — consuming only a handful of the global slots — so B still
/// gets its cookie challenge. Reverting the `source_reply_allowed` gate in
/// `classify_initiation` makes B's assertion fail (the shared budget is drained
/// by A's flood).
#[test]
fn classify_initiation_per_source_budget_isolation() {
    use crate::afxdp::wg::cookie::{COOKIE_REPLY_BUDGET_PER_WINDOW, INITIATIONS_UNDER_LOAD_THRESHOLD};
    use std::net::SocketAddr;

    let (engine, _our_pub, init) = under_load_fixture();
    let now = 10_000_000_000u64; // frozen: A's bucket never refills mid-flood
    engine.set_mock_now_ns(now);
    let mut out = [0u8; 256];

    let flood: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let legit: SocketAddr = "198.51.100.7:51820".parse().unwrap();

    // Trip under-load, then flood source A well past the GLOBAL budget. The
    // first INITIATIONS_UNDER_LOAD_THRESHOLD arrivals just build load (Process);
    // the remainder are valid-MAC1 / no-MAC2 under-load challenges. On revert
    // these would consume every one of COOKIE_REPLY_BUDGET_PER_WINDOW slots.
    let shots = INITIATIONS_UNDER_LOAD_THRESHOLD + COOKIE_REPLY_BUDGET_PER_WINDOW + 20;
    for _ in 0..shots {
        engine.classify_initiation(&init, flood, &mut out, now);
    }

    // A legit peer at a DIFFERENT source is still challenged — its first cookie
    // is NOT starved by A's flood (the #4332 per-source isolation).
    let action = engine.classify_initiation(&init, legit, &mut out, now);
    assert!(
        matches!(action, InitiationAction::SendCookie(_)),
        "a legit source must still be cookie-challenged despite a flood from \
         another source (per-source budget isolation), got {action:?}"
    );
}

/// A bad-MAC1 initiation under load is NOT reflected: it returns `Process`
/// so the consume path drops it cheaply (before any crypto) with the
/// mac1_mismatch counter, and NO cookie reply is emitted — a random /
/// bad-MAC1 flood cannot turn the responder into a reflector.
#[test]
fn classify_initiation_bad_mac1_under_load_no_reflection() {
    use crate::afxdp::wg::cookie::INITIATIONS_UNDER_LOAD_THRESHOLD;
    use std::net::SocketAddr;

    let (engine, _our_pub, good) = under_load_fixture();
    let now = 20_000_000_000u64;
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // Corrupt the MAC1 field (msg[116..132]) so parse_initiation rejects it.
    let mut bad = good;
    bad[116] ^= 0xFF;

    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        engine.classify_initiation(&good, from, &mut out, now);
    }
    let before = engine
        .counters()
        .hs_cookie_replies_sent
        .load(Ordering::Relaxed);
    // Under load, a bad-MAC1 init falls through to the cheap consume drop.
    assert_eq!(
        engine.classify_initiation(&bad, from, &mut out, now),
        InitiationAction::Process,
        "bad-MAC1 under load must not be challenged (no reflection)"
    );
    assert_eq!(
        engine
            .counters()
            .hs_cookie_replies_sent
            .load(Ordering::Relaxed),
        before,
        "no cookie reply is emitted for a bad-MAC1 initiation"
    );
}
/// #9918 F-144: under load, MAC1 is checked BEFORE MAC2.
/// A bad-MAC1 initiation carrying a VALID MAC2 for that bad MAC1 (crafted
/// with the responder's own secret via test hooks) must NOT bump
/// `hs_rx_under_load_mac2_ok`: MAC1 fails first so MAC2 is never verified.
/// On base (MAC2-first) this bumps mac2_ok. Proves the 2-3x flood-path cut:
/// junk costs ~1 keyed hash (precomputed MAC1 key), not 4-6.
#[test]
fn classify_skips_mac2_for_bad_mac1_9918() {
    use crate::afxdp::wg::cookie::{
        INITIATIONS_UNDER_LOAD_THRESHOLD, stamp_initiation_mac2,
    };
    use std::net::SocketAddr;
    let (engine, _our_pub, good) = under_load_fixture();
    let now = 22_000_000_000u64;
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];
    // Trip under-load with good initiations (same pinned now_ns: no
    // rotation skew between cookie mint and classify).
    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        engine.classify_initiation(&good, from, &mut out, now);
    }
    // Craft bad-MAC1 then stamp a VALID MAC2 over it using the
    // responder's own current cookie for `from`.
    let mut bad = good;
    bad[116] ^= 0xFF;
    let cookie = engine.cookie.cookie_for_test(from, now);
    stamp_initiation_mac2(&mut bad, &cookie);
    let before = engine
        .counters()
        .hs_rx_under_load_mac2_ok
        .load(Ordering::Relaxed);
    assert_eq!(
        engine.classify_initiation(&bad, from, &mut out, now),
        InitiationAction::Process,
        "bad-MAC1 still falls through to the cheap consume drop"
    );
    assert_eq!(
        engine
            .counters()
            .hs_rx_under_load_mac2_ok
            .load(Ordering::Relaxed),
        before,
        "MAC1-first: a bad-MAC1 packet must never verify MAC2"
    );
}

/// #4094 Copilot BUG-2 (engine level): if the OS CSPRNG is unavailable the
/// under-load gate must FAIL CLOSED — drop the initiation with NO cookie
/// reply — rather than ship a predictable cookie (which a spoofed source
/// could reproduce to forge a valid MAC2 and defeat the mitigation) or
/// process the flood. A valid-MAC1, no-MAC2 initiation under load with
/// randomness broken must yield Drop, not SendCookie and not Process.
#[test]
fn classify_initiation_fails_closed_without_secure_randomness() {
    use crate::afxdp::wg::cookie::INITIATIONS_UNDER_LOAD_THRESHOLD;
    use std::net::SocketAddr;

    let (engine, _our_pub, init) = under_load_fixture();
    let now = 30_000_000_000u64;
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // Go under load with healthy randomness.
    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        engine.classify_initiation(&init, from, &mut out, now);
    }
    // Simulate a persistent getrandom failure.
    engine.cookie.set_rng_fail_for_test(true);

    let replies_before = engine
        .counters()
        .hs_cookie_replies_sent
        .load(Ordering::Relaxed);
    let action = engine.classify_initiation(&init, from, &mut out, now);
    assert_eq!(
        action,
        InitiationAction::Drop,
        "no secure randomness → fail closed (Drop), never SendCookie or Process"
    );
    assert_eq!(
        engine
            .counters()
            .hs_cookie_replies_sent
            .load(Ordering::Relaxed),
        replies_before,
        "no cookie reply (weak or otherwise) is emitted without secure randomness"
    );
    assert!(
        engine
            .counters()
            .hs_cookie_reply_budget_drops
            .load(Ordering::Relaxed)
            >= 1,
        "the fail-closed drop is counted"
    );
}

/// #4094 PR-B end-to-end interop through the wired engine paths: an
/// INITIATOR (this PR) whose first initiation is cookie-challenged by a
/// RESPONDER under load (PR-A) consumes the cookie-reply and, on its RETRY
/// via `create_initiation`, stamps a valid MAC2 that the responder's
/// `classify_initiation` accepts (`Process`) — the two halves complete a
/// full cookie handshake. RED on revert: without the PR-B consume+stamp the
/// retry carries a zero MAC2 and the responder re-challenges it
/// (`SendCookie`) forever.
#[test]
fn initiator_consume_completes_handshake_under_load() {
    use crate::afxdp::wg::cookie::INITIATIONS_UNDER_LOAD_THRESHOLD;
    use std::net::SocketAddr;
    use std::str::FromStr;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();
    let i_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let r_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let now = 10_000_000_000u64;
    i_engine.set_mock_now_ns(now);
    r_engine.set_mock_now_ns(now);
    // The initiator's source as the responder observes it.
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // 1. Initiator builds its FIRST real initiation toward the responder.
    //    No cookie held yet → MAC2 is zero.
    let mut init_buf = [0u8; 256];
    i_engine.create_initiation(&resp_pub, &mut init_buf).unwrap();
    let init = init_buf[..crate::afxdp::wg::WG_MSG_INIT_LEN].to_vec();
    assert_eq!(
        &init[132..148],
        &[0u8; 16],
        "the first initiation carries a zero MAC2"
    );

    // 2. Drive the responder under load with filler valid-MAC1 initiations
    //    from DISTINCT sources (so the per-source reply bucket is not the
    //    limiter), then challenge the initiator's real initiation.
    let noise = [0x3Cu8; crate::afxdp::wg::handshake::MSG_INIT_NOISE_LEN];
    let mut filler = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    crate::afxdp::wg::handshake::build_initiation(&mut filler, 0x1234_5678, &noise, &resp_pub)
        .unwrap();
    for i in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        let s: SocketAddr = format!("192.0.2.{}:51820", (i % 250) + 1).parse().unwrap();
        r_engine.classify_initiation(&filler, s, &mut out, now);
    }

    // 3. The responder challenges the initiator's initiation → cookie-reply.
    let action = r_engine.classify_initiation(&init, from, &mut out, now);
    let len = match action {
        InitiationAction::SendCookie(l) => l,
        other => panic!("expected a cookie challenge, got {other:?}"),
    };
    let reply = out[..len].to_vec();
    assert_eq!(reply[0], crate::afxdp::wg::WG_TYPE_COOKIE);

    // 4. Initiator consumes the cookie-reply (wired path).
    assert!(
        i_engine.consume_cookie_reply(&reply, now),
        "the initiator must consume the responder's cookie-reply"
    );
    assert_eq!(
        i_engine
            .counters()
            .hs_rx_cookie_consumed
            .load(Ordering::Relaxed),
        1,
        "a consumed cookie-reply is counted"
    );

    // 5. Initiator RETRIES — create_initiation now stamps a NON-ZERO MAC2.
    let mut retry_buf = [0u8; 256];
    i_engine
        .create_initiation(&resp_pub, &mut retry_buf)
        .unwrap();
    let retry = retry_buf[..crate::afxdp::wg::WG_MSG_INIT_LEN].to_vec();
    assert_ne!(
        &retry[132..148],
        &[0u8; 16],
        "after consuming a cookie the retried initiation carries a MAC2"
    );

    // 6. The responder, still under load, ACCEPTS the retried initiation —
    //    the cookie-derived MAC2 verifies against its own recomputation.
    assert_eq!(
        r_engine.classify_initiation(&retry, from, &mut out, now),
        InitiationAction::Process,
        "the responder must admit the initiator's cookie-derived MAC2 (full \
         cookie handshake completes under load)"
    );
    assert!(
        r_engine
            .counters()
            .hs_rx_under_load_mac2_ok
            .load(Ordering::Relaxed)
            >= 1,
        "the primed retry counts as an under-load MAC2 pass on the responder"
    );

    // Control: the SAME retried MAC2 replayed from a DIFFERENT source is
    // still challenged — the cookie binds to the source that received it.
    let spoof: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    assert!(
        matches!(
            r_engine.classify_initiation(&retry, spoof, &mut out, now),
            InitiationAction::SendCookie(_)
        ),
        "a cookie-derived MAC2 must not authorize a handshake from a different source"
    );
}

// ===================================================================
// #9908: per-source bound on valid-MAC2 handshake ADMISSIONS. A
// non-spoofed host that obtained a cookie replays valid-MAC2 bytes; on
// base every replay classifies Process and pays a full responder Noise
// DH BEFORE the #4092 TAI64N replay drop, inline on the per-tunnel
// control thread. The fix gates under-load Process admissions per
// source BEFORE the Noise read (fail-closed Drop + counter). These
// cells pin: flood bounded (RED on base), legit cross-source completion
// during a flood (control), retransmit tolerance + preserved TAI64N
// semantics (control).
// ===================================================================

/// #9908 fixture: initiator + responder engines with REAL keys (mutual
/// single-peer config) so `consume_initiation_create_response` pays the
/// real snow responder DH — the cost the admission bound must gate.
fn admit_9908_engine_pair() -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();
    let i_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let r_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    (i_engine, r_engine, init_pub, resp_pub)
}

/// #9908 helper: trip the responder's under-load gate with synthetic
/// valid-MAC1 filler from DISTINCT sources (never the flood/legit
/// addrs), so the flood source's own admission bucket starts full.
fn trip_9908_under_load(r_engine: &WgEngine, resp_pub: &[u8; 32], now: u64) {
    use crate::afxdp::wg::cookie::INITIATIONS_UNDER_LOAD_THRESHOLD;
    use std::net::SocketAddr;
    let noise = [0x3Cu8; crate::afxdp::wg::handshake::MSG_INIT_NOISE_LEN];
    let mut filler = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    crate::afxdp::wg::handshake::build_initiation(&mut filler, 0x9908, &noise, resp_pub).unwrap();
    let mut out = [0u8; 256];
    for i in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        let s: SocketAddr = format!("192.0.2.{}:51820", (i % 250) + 1).parse().unwrap();
        r_engine.classify_initiation(&filler, s, &mut out, now);
    }
}

/// #9908 helper: build a REAL initiation and prime it with the cookie
/// the responder would have issued to `from` (the attacker's
/// legitimately obtained cookie, or a challenged peer's).
fn prime_9908_initiation(
    i_engine: &WgEngine,
    r_engine: &WgEngine,
    resp_pub: &[u8; 32],
    from: std::net::SocketAddr,
    now: u64,
) -> [u8; crate::afxdp::wg::WG_MSG_INIT_LEN] {
    use crate::afxdp::wg::cookie::stamp_initiation_mac2;
    let mut buf = [0u8; 256];
    i_engine.create_initiation(resp_pub, &mut buf).unwrap();
    let mut msg = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    msg.copy_from_slice(&buf[..crate::afxdp::wg::WG_MSG_INIT_LEN]);
    let cookie = r_engine.cookie.cookie_for_test(from, now);
    stamp_initiation_mac2(&mut msg, &cookie);
    msg
}

/// #9908 RED-on-revert: replaying ONE valid-MAC2 initiation N times from
/// one source must cost at most K expensive handshakes (the per-source
/// admission burst at a frozen clock), with the rest dropped BEFORE the
/// Noise read and counted. On base (no gate) all N classify Process and
/// each pays the responder DH before the TAI64N drop — the CPU-exhaustion
/// loop this issue closes. The eprintln line is the STEP-0/GREEN DH-cost
/// measurement (run with --nocapture).
#[test]
fn handshake_admission_9908_replay_flood_bounded_and_counted() {
    use std::net::SocketAddr;

    const N: usize = 100;
    // Per-source admission burst at a frozen clock (no refill). A literal,
    // not the const: it pins the security-relevant bound this cell exists
    // for — retuning the limiter must consciously update this cell.
    const BURST: usize = 5;

    let (i_engine, r_engine, _init_pub, resp_pub) = admit_9908_engine_pair();
    let now = 10_000_000_000u64;
    i_engine.set_mock_now_ns(now);
    r_engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    trip_9908_under_load(&r_engine, &resp_pub, now);

    // One REAL initiation, primed with the cookie issued to `from`.
    let primed = prime_9908_initiation(&i_engine, &r_engine, &resp_pub, from, now);
    let mut out = [0u8; 256];
    let mut resp_buf = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];
    let mut processed = 0usize;
    let mut dropped = 0usize;
    let t0 = std::time::Instant::now();
    for _ in 0..N {
        match r_engine.classify_initiation(&primed, from, &mut out, now) {
            InitiationAction::Process => {
                processed += 1;
                // The dispatch path consumes every Process arm inline.
                let _ = r_engine.consume_initiation_create_response(&primed, &mut resp_buf);
            }
            InitiationAction::Drop => dropped += 1,
            InitiationAction::SendCookie(_) => {
                panic!("a valid-MAC2 replay from its bound source must never be re-challenged")
            }
        }
    }
    let elapsed = t0.elapsed();
    let c = r_engine.counters();
    eprintln!(
        "9908 flood: N={N} admitted={processed} dh_paid={processed} dropped={dropped} \
         responses={} replayed={} mac2_ok={} elapsed_ms={}",
        c.hs_responses_created.load(Ordering::Relaxed),
        c.hs_rx_drops_replayed_init.load(Ordering::Relaxed),
        c.hs_rx_under_load_mac2_ok.load(Ordering::Relaxed),
        elapsed.as_millis(),
    );
    assert_eq!(processed + dropped, N, "every replay is admitted or dropped");
    assert!(
        processed >= 1,
        "a fresh source's first primed initiation must always be admitted"
    );
    assert!(
        processed <= BURST,
        "replay flood must be admission-bounded per source: {processed}/{N} reached the Noise DH \
         (base admits all N before the TAI64N drop)"
    );
    assert_eq!(
        c.hs_responses_created.load(Ordering::Relaxed),
        1,
        "exactly one replay installs a session"
    );
    assert_eq!(
        c.hs_rx_drops_replayed_init.load(Ordering::Relaxed),
        (processed - 1) as u64,
        "every admitted replay after the first still pays DH, then TAI64N-drops (bounded residual)"
    );
    assert_eq!(
        c.hs_rx_under_load_mac2_ok.load(Ordering::Relaxed),
        processed as u64,
        "mac2_ok counts admissions that reached the handshake"
    );
}

/// #9908 control: while attacker A replays a primed initiation (exhausting
/// A's OWN admission bucket), a FRESH initiation from source B still
/// classifies Process and completes — per-source isolation (the issue's
/// acceptance: "a fresh initiation from another source still completes
/// under load"). Passes on base too (base admits everything); pins the
/// fix must not throttle across sources.
#[test]
fn handshake_admission_9908_legit_source_completes_during_flood() {
    use std::net::SocketAddr;

    let (i_engine, r_engine, _init_pub, resp_pub) = admit_9908_engine_pair();
    let now = 10_000_000_000u64;
    i_engine.set_mock_now_ns(now);
    r_engine.set_mock_now_ns(now);
    let flood_from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let legit_from: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    trip_9908_under_load(&r_engine, &resp_pub, now);

    let mut out = [0u8; 256];
    let mut resp_buf = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];

    // Attacker A: one cookie, replayed past its burst.
    let replay = prime_9908_initiation(&i_engine, &r_engine, &resp_pub, flood_from, now);
    let mut admitted_a = 0usize;
    for _ in 0..20 {
        if r_engine.classify_initiation(&replay, flood_from, &mut out, now)
            == InitiationAction::Process
        {
            admitted_a += 1;
            let _ = r_engine.consume_initiation_create_response(&replay, &mut resp_buf);
        }
    }
    eprintln!("9908 isolation: attacker admitted {admitted_a}/20 from its own source");

    // Legit fresh initiation (newer TAI64N) from source B with B's cookie.
    let fresh = prime_9908_initiation(&i_engine, &r_engine, &resp_pub, legit_from, now);
    assert_eq!(
        r_engine.classify_initiation(&fresh, legit_from, &mut out, now),
        InitiationAction::Process,
        "a fresh initiation from an unflooded source must be admitted during another source's flood"
    );
    assert!(
        r_engine
            .consume_initiation_create_response(&fresh, &mut resp_buf)
            .is_ok(),
        "the admitted fresh initiation must complete the responder handshake"
    );
    assert_eq!(
        r_engine.counters().hs_responses_created.load(Ordering::Relaxed),
        2,
        "attacker's first replay + legit fresh handshake both complete"
    );
}

/// #9908 control: a legitimate retransmit — a FRESH initiation (new
/// ephemeral, strictly-greater TAI64N; the WG initiator mints a new
/// initiation on every retransmit fire, it does not resend bytes) from
/// the SAME source in quick succession — is admitted, not throttled. And
/// an identical-byte redelivery (network duplicate) is still admitted by
/// the LIMITER within burst while the #4092 TAI64N layer keeps rejecting
/// it after DH — replay semantics otherwise identical. Passes on base;
/// fails on a naive burst-1/dedup "fix".
#[test]
fn handshake_admission_9908_retransmit_tolerated_and_replay_preserved() {
    use crate::afxdp::wg::handshake_session::HandshakeError;
    use std::net::SocketAddr;

    let (i_engine, r_engine, _init_pub, resp_pub) = admit_9908_engine_pair();
    let now = 10_000_000_000u64;
    i_engine.set_mock_now_ns(now);
    r_engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    trip_9908_under_load(&r_engine, &resp_pub, now);

    let mut out = [0u8; 256];
    let mut resp_buf = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];

    // First attempt.
    let msg1a = prime_9908_initiation(&i_engine, &r_engine, &resp_pub, from, now);
    assert_eq!(
        r_engine.classify_initiation(&msg1a, from, &mut out, now),
        InitiationAction::Process
    );
    assert!(
        r_engine
            .consume_initiation_create_response(&msg1a, &mut resp_buf)
            .is_ok(),
        "the first primed initiation must complete"
    );

    // Retransmit: fresh initiation, same source, immediately after.
    let msg1b = prime_9908_initiation(&i_engine, &r_engine, &resp_pub, from, now);
    assert_eq!(
        r_engine.classify_initiation(&msg1b, from, &mut out, now),
        InitiationAction::Process,
        "a legitimate same-source retransmit (fresh TAI64N) must be admitted, not throttled"
    );
    assert!(
        r_engine
            .consume_initiation_create_response(&msg1b, &mut resp_buf)
            .is_ok(),
        "the retransmitted fresh initiation must complete (strictly-newer TAI64N)"
    );

    // Identical-byte redelivery: admitted by the limiter (within burst)
    // but still rejected by the TAI64N replay layer after DH.
    assert_eq!(
        r_engine.classify_initiation(&msg1a, from, &mut out, now),
        InitiationAction::Process,
        "the limiter must not dedup: a within-burst redelivery reaches the replay layer"
    );
    assert_eq!(
        r_engine.consume_initiation_create_response(&msg1a, &mut resp_buf),
        Err(HandshakeError::ReplayedInitiation),
        "#4092 TAI64N replay semantics preserved under the admission bound"
    );
}
