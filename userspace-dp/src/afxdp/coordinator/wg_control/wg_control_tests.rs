use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// #1736 S2b regression: a v4-mapped learned endpoint must unmap to
/// canonical V4 so the encap MTU guard charges IPv4 outer overhead.
#[test]
fn canonicalize_endpoint_unmaps_v4_mapped() {
    let mapped: SocketAddr = "[::ffff:10.0.61.103]:51820".parse().unwrap();
    let got = canonicalize_endpoint(mapped);
    assert_eq!(
        got,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 103)), 51820)
    );
    assert!(!got.is_ipv6());
}

/// Native v6 and native v4 endpoints pass through untouched.
#[test]
fn canonicalize_endpoint_passthrough() {
    let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    assert_eq!(canonicalize_endpoint(v6), v6);
    let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    assert_eq!(canonicalize_endpoint(v4), v4);
    // A non-mapped v6 with an embedded v4-looking tail stays v6.
    let nat64: SocketAddr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x3d67)),
        51820,
    );
    assert_eq!(canonicalize_endpoint(nat64), nat64);
}

/// #1736 S2b regression (strace-proven live): a v4 target on the
/// dual-stack AF_INET6 socket must be sent as its V4-MAPPED form —
/// Linux returns EINVAL for an AF_INET destination sockaddr on an
/// AF_INET6 socket, which silently killed every initiation toward
/// the configured v4 endpoint. Loopback round-trip proves the
/// mapped send actually lands.
#[test]
fn wg_send_to_maps_v4_target_on_v6_socket() {
    let (rx, rx_is_v6) = bind_wg_socket(0).expect("bind rx");
    if !rx_is_v6 {
        // Production supports the v4-fallback socket on hosts
        // without dual-stack v6; the mapped-send regression is
        // untestable there (covered by the v4 round-trip below).
        return;
    }
    let rx_port = rx.local_addr().unwrap().port();
    let (tx, tx_is_v6) = bind_wg_socket(0).expect("bind tx");
    // The plain V4 loopback target — the failing live shape.
    let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
    wg_send_to(&tx, tx_is_v6, b"wg-test", target, None).expect("mapped v4 send must succeed");
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 16];
    let (n, _) = rx.recv_from(&mut buf).expect("datagram must arrive");
    assert_eq!(&buf[..n], b"wg-test");
    // Direct unmapped send documents WHY the helper exists; accept
    // either kernel behavior (EINVAL on Linux mainline) without
    // asserting it so the test stays portable.
    let _ = tx.send_to(b"raw", target);
}

/// The v4-fallback socket path: native v4 sends must pass through
/// wg_send_to UNMAPPED (socket_is_v6=false) and round-trip.
#[test]
fn wg_send_to_native_v4_socket_roundtrip() {
    let rx = UdpSocket::bind("127.0.0.1:0").expect("bind v4 rx");
    let rx_port = rx.local_addr().unwrap().port();
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind v4 tx");
    let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
    wg_send_to(&tx, false, b"wg-v4", target, None).expect("native v4 send");
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 16];
    let (n, _) = rx.recv_from(&mut buf).expect("datagram must arrive");
    assert_eq!(&buf[..n], b"wg-v4");
}

/// Build a `recvmsg`-shaped `sockaddr_storage` for an AF_INET6 peer
/// with an explicit interface scope, mirroring what the kernel writes
/// into `msg_name` for a datagram received from a link-local source.
fn make_sin6_storage(
    ip: Ipv6Addr,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let sin6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: flowinfo,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: scope_id,
    };
    // SAFETY: sockaddr_storage is large enough for sockaddr_in6 and we
    // only read back the populated prefix via the conversion under test.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &sin6 as *const libc::sockaddr_in6 as *const u8,
            &mut storage as *mut libc::sockaddr_storage as *mut u8,
            std::mem::size_of::<libc::sockaddr_in6>(),
        );
    }
    (
        storage,
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    )
}

/// #2995 fail-on-revert: a link-local (`fe80::/10`) WG peer endpoint
/// learned from `recvmsg` MUST carry the receiving interface scope
/// (`sin6_scope_id` = ifindex) through `sockaddr_storage_to_socketaddr`.
/// If the conversion reverts to `SocketAddr::new(...)` the scope is
/// dropped to 0 and `wg_send_to` toward the endpoint is rejected with
/// EINVAL/ENODEV, so the tunnel never establishes. This asserts the
/// scope (and `sin6_flowinfo`) survive; it goes RED if scope_id == 0.
#[test]
fn sockaddr_storage_to_socketaddr_preserves_link_local_scope() {
    let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
    let ifindex: u32 = 7;
    let flowinfo: u32 = 0x0001_2345;
    let (storage, len) = make_sin6_storage(ll, 51820, flowinfo, ifindex);
    let got = sockaddr_storage_to_socketaddr(&storage, len).expect("AF_INET6 storage must convert");
    match got {
        SocketAddr::V6(v6) => {
            assert_eq!(*v6.ip(), ll);
            assert_eq!(v6.port(), 51820);
            assert_eq!(
                v6.scope_id(),
                ifindex,
                "link-local scope_id must equal the receiving ifindex \
                     (reverting to SocketAddr::new drops it to 0)"
            );
            assert_eq!(v6.flowinfo(), flowinfo, "flowinfo must survive");
        }
        other => panic!("expected V6, got {other:?}"),
    }
}

/// A global v6 endpoint carries scope_id 0 from the kernel; the
/// conversion must preserve that 0 unchanged (the fix is a no-op for
/// global addresses — it only matters for link-local).
#[test]
fn sockaddr_storage_to_socketaddr_global_v6_scope_zero() {
    let g = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
    let (storage, len) = make_sin6_storage(g, 51820, 0, 0);
    let got = sockaddr_storage_to_socketaddr(&storage, len).expect("convert");
    match got {
        SocketAddr::V6(v6) => {
            assert_eq!(*v6.ip(), g);
            assert_eq!(v6.scope_id(), 0);
        }
        other => panic!("expected V6, got {other:?}"),
    }
}

// =======================================================================
// #1889: poll(2) loop tests on pre-opened fds (run_wg_control_loop —
// a pipe read-end stands in for the TUN; no real device needed).
// =======================================================================

fn poll_loop_fixture() -> (
    std::sync::Arc<crate::afxdp::wg::WgEngine>,
    UdpSocket,
    std::fs::File, // tun stand-in (pipe read end)
    std::fs::File, // pipe write end (keep open!)
    std::sync::Arc<Mutex<ExceptionEventRing>>,
    std::sync::Arc<AtomicBool>,
) {
    use std::os::fd::FromRawFd;
    let engine = std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
        crate::afxdp::wg::WgEngineConfig {
            local_private_key: [7u8; 32].into(),
            listen_port: 0,
            peers: vec![crate::afxdp::wg::WgPeerConfig {
                pubkey: [9u8; 32],
                endpoint: None, // responder-only: no bring-up sends
                persistent_keepalive: 0,
                allowed_ips: vec![],
                preshared_key: [0u8; 32].into(),
            }],
        },
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.set_nonblocking(true).unwrap();
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);
    set_fd_nonblocking(read_fd).unwrap();
    let tun = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let pipe_w = unsafe { std::fs::File::from_raw_fd(write_fd) };
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    (engine, socket, tun, pipe_w, exceptions, stop)
}

fn spawn_poll_loop(
    engine: std::sync::Arc<crate::afxdp::wg::WgEngine>,
    socket: UdpSocket,
    tun: std::fs::File,
    exceptions: std::sync::Arc<Mutex<ExceptionEventRing>>,
    stop: std::sync::Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        run_wg_control_loop(
            "wg-test",
            &engine,
            &socket,
            false,
            tun,
            WG_DEFAULT_OUTER_MTU,
            // #5291: no per-peer overrides in the idle poll-loop tests —
            // every peer falls back to the scalar (WG_DEFAULT_OUTER_MTU).
            &std::collections::HashMap::new(),
            // #7158: no hostname endpoints in these fixtures, so no resolver.
            // `None` is also the production shape for every literal-only
            // tunnel, so these tests keep exercising the unchanged path.
            None,
            &exceptions,
            &stop,
            crate::afxdp::types::WgKernelTransport::Deliver,
        );
    })
}

/// #1889 constraint 1: an idle-blocked loop must stop+join within
/// the poll cap budget (no eventfd — the 100ms cap bounds it).
#[test]
fn poll_loop_stop_joins_promptly_while_idle_blocked() {
    let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
    let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
    // Let the loop settle into its idle poll.
    std::thread::sleep(Duration::from_millis(150));
    let started = std::time::Instant::now();
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("join");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "stop->join took {:?} (budget 500ms; cap is 100ms)",
        started.elapsed()
    );
}

/// #1889 constraint 2: a datagram arriving while idle-blocked wakes
/// the loop and is processed promptly (no 1s timer wait). A non-WG
/// type byte lands in rx_unknown_type deterministically.
#[test]
fn poll_loop_wakes_on_socket_readiness() {
    let (engine, socket, tun, _pipe_w, exceptions, stop) = poll_loop_fixture();
    let target = socket.local_addr().unwrap();
    let counters_engine = engine.clone();
    let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
    std::thread::sleep(Duration::from_millis(120)); // reach idle poll
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(&[0xee, 1, 2, 3], target).unwrap();
    let mut seen = false;
    for _ in 0..30 {
        if counters_engine
            .counters()
            .rx_unknown_type
            .load(Ordering::Relaxed)
            == 1
        {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("join");
    assert!(seen, "datagram not processed within 300ms of arrival");
}

/// Fatal-fd guard: destroying the TUN under the loop (pipe write
/// end dropped => POLLHUP on the read end) exits the thread
/// cleanly WITHOUT the stop flag — the #1872 tombstone respawn is
/// the recovery path. No busy-spin, no hang.
#[test]
fn poll_loop_exits_on_tun_teardown() {
    let (engine, socket, tun, pipe_w, exceptions, stop) = poll_loop_fixture();
    let handle = spawn_poll_loop(engine, socket, tun, exceptions, stop.clone());
    std::thread::sleep(Duration::from_millis(120));
    drop(pipe_w); // TUN "destroyed": POLLHUP forever
    let started = std::time::Instant::now();
    // Join must complete without stop ever being set.
    handle.join().expect("join");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "fatal-TUN exit took {:?}",
        started.elapsed()
    );
    assert!(!stop.load(Ordering::Relaxed));
}

/// #5291 fail-on-revert: TUN-origin egress to a NON-first peer must
/// size the encap MTU guard against THAT peer's underlay, not the
/// first-peer scalar. This mirrors the AF_XDP transit path, which
/// already resolves the outer MTU per peer (#2845/#3219,
/// `wg_endpoint_physical_outer_mtu`/`wg_peer_outer_dst`); before this
/// fix the control thread captured ONE first-peer scalar at spawn and
/// applied it to every peer.
///
/// Scenario: a multi-peer WG tunnel with asymmetric underlays — peer A
/// @1500 (the first-peer scalar), peer B @1400. An inner packet
/// destined into peer B's AllowedIPs (`10.72.0.5`), sized so its
/// WG-encapped wire size (1468B: pad_to_16(1400)=1408 + 16 data-hdr +
/// 16 tag + 20 outer-IP + 8 UDP) FITS 1500 but EXCEEDS 1400, must be
/// dropped by the per-peer guard (`encap_mtu_drops` bumps). Reverting
/// the TUN-origin path to the first-peer 1500 scalar would ADMIT it
/// (`encap_mtu_drops` stays 0, and it falls through to the NoSession
/// handshake request), so the per-peer lookup is load-bearing here.
#[test]
fn wg_tun_origin_egress_uses_per_peer_outer_mtu_5291() {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::sync::atomic::Ordering as AtomicOrdering;

    // Two peers, distinct AllowedIPs + configured v4 endpoints. Peer A
    // is the first endpoint-bearing peer (its underlay 1500 becomes the
    // scalar passed below); peer B rides a smaller 1400 underlay.
    let pk_a = [0xA1u8; 32];
    let pk_b = [0xB2u8; 32];
    let ep_a: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let ep_b: SocketAddr = "127.0.0.1:40002".parse().unwrap();
    let engine = std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
        crate::afxdp::wg::WgEngineConfig {
            local_private_key: [7u8; 32].into(),
            listen_port: 0,
            peers: vec![
                crate::afxdp::wg::WgPeerConfig {
                    pubkey: pk_a,
                    endpoint: Some(ep_a),
                    persistent_keepalive: 0,
                    allowed_ips: vec!["10.71.0.0/24".parse().unwrap()],
                    preshared_key: [0u8; 32].into(),
                },
                crate::afxdp::wg::WgPeerConfig {
                    pubkey: pk_b,
                    endpoint: Some(ep_b),
                    persistent_keepalive: 0,
                    allowed_ips: vec!["10.72.0.0/24".parse().unwrap()],
                    preshared_key: [0u8; 32].into(),
                },
            ],
        },
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.set_nonblocking(true).unwrap();
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);
    set_fd_nonblocking(read_fd).unwrap();
    let tun = unsafe { std::fs::File::from_raw_fd(read_fd) };
    let mut pipe_w = unsafe { std::fs::File::from_raw_fd(write_fd) };
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));

    // First-peer scalar = peer A's underlay (1500) — what a revert would
    // apply to EVERY peer. The per-peer map carries ONLY peer B's smaller
    // underlay (1400); a peer absent from the map falls back to the
    // scalar (the pre-#5291 behaviour for that peer).
    let outer_mtu = 1500usize;
    let mut per_peer: std::collections::HashMap<[u8; 32], usize> =
        std::collections::HashMap::new();
    per_peer.insert(pk_b, 1400);

    let counters_engine = engine.clone();
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        run_wg_control_loop(
            "wg-test-5291",
            &engine,
            &socket,
            false,
            tun,
            outer_mtu,
            &per_peer,
            // #7158: no hostname endpoints in these fixtures, so no resolver.
            // `None` is also the production shape for every literal-only
            // tunnel, so these tests keep exercising the unchanged path.
            None,
            &exceptions,
            &stop_thread,
            crate::afxdp::types::WgKernelTransport::Deliver,
        );
    });
    std::thread::sleep(Duration::from_millis(120)); // reach the idle poll

    // Inner IPv4 packet destined into peer B's AllowedIPs. Byte 0 = 0x45
    // (IPv4, IHL 5); dst octets 16..20 = 10.72.0.5. 1400 payload bytes.
    let mut inner = vec![0u8; 1400];
    inner[0] = 0x45;
    inner[16..20].copy_from_slice(&[10, 72, 0, 5]);
    pipe_w.write_all(&inner).expect("write inner packet to TUN pipe");

    let mut dropped = 0u64;
    for _ in 0..50 {
        dropped = counters_engine
            .counters()
            .encap_mtu_drops
            .load(AtomicOrdering::Relaxed);
        if dropped >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, AtomicOrdering::Relaxed);
    handle.join().expect("join");
    assert_eq!(
        dropped, 1,
        "TUN-origin egress to peer B must size against peer B's 1400 \
         underlay MTU and DROP the 1468B encap; reverting to the \
         first-peer 1500 scalar would admit it (encap_mtu_drops == 0)"
    );
}

/// Codex code-r1 BLOCKER regression: a T5 give-up must NOT
/// evaluate the (pre-cleanup) TimerActions in the same pass — a T7
/// DeadPeer trigger captured before the cleanup would resurrect a
/// fresh 90s window immediately, bypassing the give-up boundary.
#[test]
fn attempt_give_up_ignores_same_pass_stale_actions() {
    use crate::afxdp::wg::session::REKEY_ATTEMPT_TIME_NS;
    use crate::afxdp::wg::timers::{InitiateReason, TimerActions, WG_NO_DEADLINE_NS};
    let (engine, socket, _tun, _pipe_w, exceptions, _stop) = poll_loop_fixture();
    let pk = engine.first_peer_pubkey().unwrap();
    let ep: SocketAddr = "127.0.0.1:39999".parse().unwrap();
    let mut encap_buf = vec![0u8; 2048];
    let now = 200_000_000_000u64;
    let mut attempt = Some(HandshakeAttempt {
        started_ns: now - REKEY_ATTEMPT_TIME_NS - 1,
        last_tx_ns: now - 1_000_000_000,
        baseline_session: None,
    });
    // Stale actions captured BEFORE the give-up cleanup, carrying a
    // due T7 trigger.
    let stale_actions = TimerActions {
        initiate: Some(InitiateReason::DeadPeer),
        send_keepalive: None,
        next_deadline_ns: WG_NO_DEADLINE_NS,
    };
    let deadline = drive_attempt_machine(
        &engine,
        &socket,
        false,
        &pk,
        Some(ep),
        &stale_actions,
        now,
        &mut attempt,
        &mut encap_buf,
        "wg-test",
        &exceptions,
    );
    assert!(
        attempt.is_none(),
        "give-up must not resurrect an attempt from stale same-pass actions"
    );
    assert_eq!(deadline, WG_NO_DEADLINE_NS);
    assert_eq!(
        engine
            .counters()
            .rekeys_initiated_dead_peer
            .load(Ordering::Relaxed),
        0,
        "no DeadPeer attempt may start in the give-up pass"
    );
}

/// Build a poll-loop fixture engine whose single peer has a
/// persistent-keepalive of `keepalive_secs`. Mirrors
/// `poll_loop_fixture` but parameterizes the keepalive so the T8
/// pacing path can be exercised.
fn keepalive_engine(keepalive_secs: u16) -> std::sync::Arc<crate::afxdp::wg::WgEngine> {
    std::sync::Arc::new(crate::afxdp::wg::WgEngine::new(
        crate::afxdp::wg::WgEngineConfig {
            local_private_key: [7u8; 32].into(),
            listen_port: 0,
            peers: vec![crate::afxdp::wg::WgPeerConfig {
                pubkey: [9u8; 32],
                endpoint: None,
                persistent_keepalive: keepalive_secs,
                allowed_ips: vec![],
                preshared_key: [0u8; 32].into(),
            }],
        },
    ))
}

/// #2961: a persistent-keepalive peer whose handshake can NEVER
/// complete must NOT enter a zero-cooldown 90s handshake storm. After
/// the attempt machine GIVES UP at T+90, the next KeepaliveNoSession
/// initiation must be gated until give_up_time + keepalive_interval —
/// one keepalive interval of cooldown — not fired on the next ~1s
/// tick.
///
/// Fail-on-revert: delete the `engine.note_t8_attempt(...)` call in
/// the give-up branch and the `at give-up: gated` assertion goes RED
/// (the un-advanced anchor makes T8 perpetually due, re-firing every
/// tick).
#[test]
fn giveup_paces_keepalive_no_session_by_one_interval() {
    use crate::afxdp::wg::session::REKEY_ATTEMPT_TIME_NS;
    use crate::afxdp::wg::timers::{InitiateReason, TimerActions, WG_NO_DEADLINE_NS};
    let keepalive_secs: u16 = 25;
    let interval_ns = u64::from(keepalive_secs) * 1_000_000_000;
    let engine = keepalive_engine(keepalive_secs);
    let pk = engine.first_peer_pubkey().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let ep: SocketAddr = "127.0.0.1:39998".parse().unwrap();
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let mut encap_buf = vec![0u8; 2048];

    // An attempt that has run the full 90s window — the next
    // drive_attempt_machine pass takes the GIVE-UP branch. No real
    // sends occurred (last_send_any/last_recv_any stay 0), so the only
    // thing that can pace T8 across the boundary is the give-up
    // anchor advance under test.
    let give_up = 200_000_000_000u64;
    let mut attempt = Some(HandshakeAttempt {
        started_ns: give_up - REKEY_ATTEMPT_TIME_NS,
        last_tx_ns: give_up - 1_000_000_000,
        baseline_session: None,
    });
    let idle_actions = TimerActions {
        initiate: None,
        send_keepalive: None,
        next_deadline_ns: WG_NO_DEADLINE_NS,
    };
    let deadline = drive_attempt_machine(
        &engine,
        &socket,
        false,
        &pk,
        Some(ep),
        &idle_actions,
        give_up,
        &mut attempt,
        &mut encap_buf,
        "wg-test",
        &exceptions,
    );
    assert!(attempt.is_none(), "give-up must clear the attempt");
    assert_eq!(deadline, WG_NO_DEADLINE_NS);

    // At give-up time the next attempt must be GATED (cooldown just
    // started). This is the assertion that goes RED without the fix:
    // an un-advanced anchor (0) makes due = 0 + interval, already
    // past at give_up=200s → KeepaliveNoSession fires immediately.
    let at_giveup = engine.timer_pass_for_peer(&pk, give_up, true);
    assert_eq!(
        at_giveup.initiate, None,
        "give-up must start a keepalive cooldown, not re-fire immediately"
    );
    assert_eq!(
        at_giveup.next_deadline_ns,
        give_up + interval_ns,
        "next KeepaliveNoSession due is one keepalive interval after give-up"
    );

    // One nanosecond before the cooldown elapses: still gated.
    let just_before = engine.timer_pass_for_peer(&pk, give_up + interval_ns - 1, true);
    assert_eq!(
        just_before.initiate, None,
        "must stay gated until the full keepalive interval elapses"
    );

    // At give_up + interval: the next attempt is finally due.
    let at_due = engine.timer_pass_for_peer(&pk, give_up + interval_ns, true);
    assert_eq!(
        at_due.initiate,
        Some(InitiateReason::KeepaliveNoSession),
        "after the cooldown a fresh KeepaliveNoSession attempt may start"
    );
}

/// #2961: the give-up cooldown is a FLOOR, not a ceiling — a peer
/// that comes back to life (authenticated traffic resumes / a
/// handshake succeeds) re-anchors T8 on the fresh traffic and is NOT
/// held back by a prior give-up's cooldown. Proves the give-up anchor
/// advance does not regress the live/successful peer: the T8 anchor is
/// max(last_send_any, last_recv_any, t8_last_attempt), so newer
/// traffic wins.
#[test]
fn live_peer_paces_on_fresh_traffic_not_giveup_cooldown() {
    let keepalive_secs: u16 = 25;
    let interval_ns = u64::from(keepalive_secs) * 1_000_000_000;
    let engine = keepalive_engine(keepalive_secs);
    let pk = engine.first_peer_pubkey().unwrap();

    // Simulate a give-up cooldown stamped at T.
    let give_up = 200_000_000_000u64;
    engine.note_t8_attempt(&pk, give_up);

    // Authenticated traffic resumes 5s later (e.g. a handshake
    // finally completed and data flows) — advances last_send_any.
    let traffic = give_up + 5_000_000_000;
    engine.note_handshake_sent(&pk, traffic);

    // T8 must now pace off the FRESH traffic anchor (traffic +
    // interval), NOT the older give-up cooldown (give_up + interval).
    let actions = engine.timer_pass_for_peer(&pk, traffic + interval_ns - 1, true);
    assert_eq!(
        actions.initiate, None,
        "a live peer is paced off fresh traffic, not the give-up cooldown"
    );
    assert_eq!(
        actions.next_deadline_ns,
        traffic + interval_ns,
        "the anchor follows the most recent authenticated traversal"
    );
}

/// AGY r3 G3: the ns->ms conversion clamps to the cap and never
/// yields a negative/zero-spin timeout for future deadlines.
#[test]
fn poll_timeout_ms_clamps_and_converts() {
    let now = 1_000_000_000u64;
    // Far-future deadline: capped.
    assert_eq!(poll_timeout_ms(u64::MAX, now), WG_POLL_CAP_MS);
    // 7ms out: exact conversion.
    assert_eq!(poll_timeout_ms(now + 7_000_000, now), 7);
    // Past deadline: 0 (the timer arm runs it on the next
    // iteration via the now >= next_deadline condition).
    assert_eq!(poll_timeout_ms(now - 1, now), 0);
}

/// The guard math this protects: at the v4/v6 boundary the same
/// padded inner either fits (v4 outer) or exceeds (v6 outer) the
/// 1500 outer MTU — the live-blackhole window.
#[test]
fn encapped_size_v4_vs_v6_window() {
    // inner 1409 pads to 1424: v4 outer = 1484 (fits), v6 = 1504 (drops).
    assert!(wg_encapped_size(1409, false) <= WG_DEFAULT_OUTER_MTU);
    assert!(wg_encapped_size(1409, true) > WG_DEFAULT_OUTER_MTU);
    // inner 1408 fits either way (the pre-fix observable cutoff).
    assert!(wg_encapped_size(1408, true) <= WG_DEFAULT_OUTER_MTU);
}

/// #2300: the egress guard uses the THREADED outer MTU, not the
/// 1500 constant. A 1409-byte inner (v4 outer, encapped 1484) fits a
/// 1500 link but MUST be dropped on a 1450 underlay (PPPoE-class) —
/// the topology-dependent bug the old hardcode created.
#[test]
fn guard_uses_threaded_outer_mtu_not_constant() {
    // 1500 link: 1409 fits.
    assert!(wg_inner_fits_outer_mtu(1409, false, 1500));
    // 1450 link: 1484 > 1450, dropped. Fail-on-revert: a hardcoded
    // 1500 guard would have let this through and forced the underlay
    // to fragment or drop.
    assert!(!wg_inner_fits_outer_mtu(1409, false, 1450));
    // 1492 link (PPPoE): 1484 still fits.
    assert!(wg_inner_fits_outer_mtu(1409, false, 1492));
    // Jumbo 9000 link: a 5000-byte inner (encapped ~5044) fits —
    // the old constant would have capped this at 1500.
    assert!(wg_inner_fits_outer_mtu(5000, false, 9000));
    assert!(!wg_inner_fits_outer_mtu(5000, false, 1500));
}

// =======================================================================
// #2317: recvmsg / cmsg outer-ECN capture + RFC 6040 §4.2 WG decap
// combine. The cmsg-parse tests build a synthetic control buffer with
// the real libc CMSG_* macros and feed it to the same
// `parse_outer_ecn_from_cmsg` the recv path uses, so the alignment +
// walk logic is exercised exactly as in production.
// =======================================================================

/// Build a `msghdr` whose msg_control holds a single cmsg of
/// `(level, ctype)` carrying the one-byte DS payload `ds`, and return
/// the parsed outer ECN. The cmsg buffer is a stack `CmsgBuf`
/// (8-byte-aligned, #2334) that the msghdr borrows for the duration
/// of the parse.
fn parse_ecn_with_cmsg(level: libc::c_int, ctype: libc::c_int, ds: u8) -> Option<u8> {
    unsafe {
        // CMSG_SPACE(1) bytes hold a header + 1 padded payload byte.
        // Back the control buffer with the same 8-byte-aligned `CmsgBuf`
        // the production recv path uses (#2334) so the synthetic cmsg
        // header-field writes/reads here are aligned exactly as in
        // `wg_recvmsg` — a bare `vec![0u8; _]` would be align-1.
        let space = libc::CMSG_SPACE(1) as usize;
        assert!(space <= 256, "CMSG_SPACE(1) exceeds CmsgBuf storage");
        let mut buf = CmsgBuf([0u8; 256]);
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_control = buf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null(), "CMSG_FIRSTHDR null");
        (*cmsg).cmsg_level = level;
        (*cmsg).cmsg_type = ctype;
        (*cmsg).cmsg_len = libc::CMSG_LEN(1) as _;
        *libc::CMSG_DATA(cmsg) = ds;
        // msg_controllen must reflect the actual bytes written for the
        // walk to terminate correctly.
        msg.msg_controllen = libc::CMSG_SPACE(1) as _;
        parse_outer_ecn_from_cmsg(&msg)
    }
}

#[test]
fn cmsg_parse_v4_ip_tos_extracts_ecn() {
    // IPv4 IP_TOS cmsg: DS byte 0xB8 = EF (DSCP 46) + Not-ECT(00).
    assert_eq!(
        parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0xB8),
        Some(0b00)
    );
    // DS byte with ECT(0) low bits: DSCP 0 + ECT(0)=0b10.
    assert_eq!(
        parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0b10),
        Some(0b10)
    );
    // DS byte with CE low bits: AF41 (DSCP 34 << 2 = 0x88) | CE(0b11).
    assert_eq!(
        parse_ecn_with_cmsg(libc::IPPROTO_IP, libc::IP_TOS, 0x88 | 0b11),
        Some(0b11)
    );
}

#[test]
fn cmsg_parse_v6_tclass_extracts_ecn() {
    // IPv6 IPV6_TCLASS cmsg: Traffic Class byte with ECT(1) low bits.
    assert_eq!(
        parse_ecn_with_cmsg(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0b01),
        Some(0b01)
    );
    // CE in the low 2 bits.
    assert_eq!(
        parse_ecn_with_cmsg(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0xFF),
        Some(0b11)
    );
}

#[test]
fn cmsg_parse_ignores_unrelated_cmsg() {
    // A non-TOS cmsg (e.g. SOL_SOCKET / SO_TIMESTAMP-shaped) yields no
    // ECN — only IP_TOS / IPV6_TCLASS are honored.
    assert_eq!(
        parse_ecn_with_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, 0xFF),
        None
    );
}

#[test]
fn cmsg_parse_empty_control_yields_none() {
    // No control buffer at all (kernel ignored the sockopt) → None,
    // and the decap combine is skipped.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        assert_eq!(parse_outer_ecn_from_cmsg(&msg), None);
    }
}

/// The WG decap site reuses the shared `apply_decap_ecn_combine`: an
/// outer CE over an ECN-capable IPv4 inner upgrades the inner to CE
/// and recomputes the IPv4 header checksum, and a LEGAL upgrade does
/// NOT touch the (per-tunnel) illegal-drop counter. A test-local
/// `AtomicU64` stands in for the counter so the strict delta is
/// deterministic regardless of concurrent tests touching the
/// process-global GRE/WG statics.
#[test]
fn wg_apply_combine_sets_ipv4_ce_and_recomputes_checksum() {
    use crate::afxdp::gre::apply_decap_ecn_combine;
    // Minimal 20-byte IPv4 header, DSCP 0 + ECT(0), valid checksum.
    let mut inner = vec![0u8; 20];
    inner[0] = 0x45; // version 4, IHL 5
    inner[1] = 0b10; // DSCP 0, ECT(0)
    inner[9] = PROTO_TCP;
    let cs = crate::afxdp::frame::checksum16(&inner[..20]);
    inner[10..12].copy_from_slice(&cs.to_be_bytes());
    assert_eq!(crate::afxdp::frame::checksum16(&inner[..20]), 0);

    let counter = AtomicU64::new(0);
    let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, 0b11, &counter);
    assert!(forward, "ECT inner + outer CE forwards after CE upgrade");
    assert_eq!(inner[1] & 0x03, 0b11, "inner ECN upgraded to CE");
    assert_eq!(inner[1] >> 2, 0, "inner DSCP untouched");
    assert_eq!(
        crate::afxdp::frame::checksum16(&inner[..20]),
        0,
        "IPv4 header checksum recomputed after the TOS change"
    );
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "a legal CE upgrade must not bump the illegal-drop counter"
    );
}

/// The illegal §4.2 combo (outer CE over a Not-ECT inner) DROPS and
/// bumps the passed counter exactly once. The WG production wiring
/// passes `WG_DECAP_ECN_ILLEGAL_DROPS` (asserted separately below with
/// a concurrency-tolerant `>=` check); the strict +1 is verified on a
/// test-local atomic so it is deterministic under parallel tests.
#[test]
fn wg_apply_combine_drops_illegal_combo_and_counts() {
    use crate::afxdp::gre::{WG_DECAP_ECN_ILLEGAL_DROPS, apply_decap_ecn_combine};
    let mut inner = vec![0u8; 20];
    inner[0] = 0x45;
    inner[1] = 0x88; // AF41 (DSCP 34), ECN Not-ECT(00)

    // Strict +1 on an isolated counter — deterministic.
    let counter = AtomicU64::new(0);
    let forward = apply_decap_ecn_combine(&mut inner, libc::AF_INET as u8, 0b11, &counter);
    assert!(!forward, "outer CE over a Not-ECT inner must DROP (§4.2)");
    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "the illegal combo must bump the passed counter exactly once"
    );

    // Production wiring: the WG global advances (>= because other
    // parallel tests may also bump it). Proves the WG path routes to
    // the WG counter, not just an arbitrary one.
    let wg_before = WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed);
    let mut inner2 = vec![0u8; 20];
    inner2[0] = 0x45;
    inner2[1] = 0x88;
    assert!(!apply_decap_ecn_combine(
        &mut inner2,
        libc::AF_INET as u8,
        0b11,
        &WG_DECAP_ECN_ILLEGAL_DROPS,
    ));
    assert!(
        WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed) >= wg_before + 1,
        "the WG global illegal-drop counter must advance on the WG path"
    );
}

// ---------------------------------------------------------------------------
// #7758: RFC 6040 §4.1 ingress on the HOST-ORIGINATED encap path.
//
// WireGuard has TWO encap paths. The transit one (`frame/wg.rs`) has copied the
// inner DS byte onto the outer header since #2303, exactly as GRE does. The
// host-originated one (`encap_and_send`, inner read from the wgN TUN) did not,
// so the SAME inner marking produced a DIFFERENT outer DSCP depending on which
// path a packet took — an internal routing detail no operator can see, visible
// to every downstream classifier.
//
// These cells assert on the DS byte AS RECEIVED ON THE WIRE rather than on the
// helper's return value. The helper was never the missing part; the wiring was,
// and a cell that called `inner_tos_byte` directly would have stayed green
// through the entire defect.
//
// Reading the outer DS back also verifies something this code cannot assume:
// which cmsg family a v4-mapped destination on the dual-stack AF_INET6 socket
// takes. The send path picks `IP_TOS` by the destination's WIRE family; if that
// choice is wrong the kernel silently sends unmarked and these cells red.
// ---------------------------------------------------------------------------

/// Read the full DS byte the kernel reports for the next datagram. Deliberately
/// a SECOND cmsg parser rather than production's `parse_outer_ecn_from_cmsg`:
/// that one masks to the 2 ECN bits, and DSCP is six of the eight bits under
/// test here. An independent reader also cannot inherit a bug from the parser
/// it is checking.
fn recv_outer_ds_byte(sock: &UdpSocket, payload: &mut [u8]) -> Option<u8> {
    let mut cbuf = CmsgBuf([0u8; 256]);
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // SAFETY: msghdr fully populated; iov/control buffers outlive the call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.0.len() as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return None;
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;
            if (level == libc::IPPROTO_IP && ctype == libc::IP_TOS)
                || (level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_TCLASS)
            {
                return Some(*libc::CMSG_DATA(cmsg));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    None
}

/// An IPv4 packet carrying an explicit DS byte, addressed so the peer's
/// AllowedIPs cover it.
fn inner_v4_with_ds(ds: u8) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45; // v4, IHL 5
    p[1] = ds;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 5).octets());
    p[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 1, 5).octets());
    p
}

fn rx_socket_with_tos() -> Option<(UdpSocket, u16)> {
    let (rx, rx_is_v6) = bind_wg_socket(0).ok()?;
    set_recv_tos_options(rx.as_raw_fd(), rx_is_v6);
    rx.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let port = rx.local_addr().ok()?.port();
    Some((rx, port))
}

/// The copy, end to end through `encap_and_send`, asserted on the wire.
///
/// RED on revert: pass `None` for `outer_tos` at the `wg_send_to` call in
/// `encap_and_send` — which is the pre-#7758 tree — and the received DS byte
/// falls to 0.
///
/// The second assertion is the one the issue is actually about: the byte on the
/// wire must equal what the TRANSIT path's own helper derives from the same
/// inner packet. Pinning a literal would let the two paths drift apart while
/// this stayed green; asserting the agreement cannot.
#[test]
fn host_encap_copies_inner_ds_onto_the_outer_7758() {
    let Some((rx, rx_port)) = rx_socket_with_tos() else {
        return; // no usable UDP socket in this sandbox
    };
    let (tx, tx_is_v6) = bind_wg_socket(0).expect("bind tx");
    let (init_engine, _resp_engine, _init_pub, resp_pub) =
        crate::afxdp::wg::tests::established_pair(
            vec!["10.0.0.0/24".parse().unwrap()],
            vec!["10.0.1.0/24".parse().unwrap()],
        );

    // DSCP EF (46) with Not-ECT: 46 << 2 = 0xB8. A value with bits in BOTH
    // halves of the byte, so a mask error in either direction is visible.
    const DS: u8 = 0xB8;
    let inner = inner_v4_with_ds(DS);
    let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let mut out = vec![0u8; 2048];

    encap_and_send(
        &init_engine,
        &tx,
        tx_is_v6,
        &resp_pub,
        target,
        &inner,
        &mut out,
        1500,
        "wg0",
        &exceptions,
    );

    let mut payload = [0u8; 2048];
    let got = recv_outer_ds_byte(&rx, &mut payload)
        .expect("the encapped datagram must arrive with a TOS cmsg");
    assert_eq!(
        got, DS,
        "the outer DS byte must carry the inner marking (RFC 6040 §4.1 ingress + \
         uniform DSCP); 0 here is the pre-#7758 behaviour where the host-originated \
         path sent unmarked while the transit path copied"
    );
    assert_eq!(
        got,
        crate::afxdp::gre::inner_tos_byte(&inner, libc::AF_INET as u8),
        "the two WG encap paths must agree on the outer DS for one inner packet — \
         this asserts the AGREEMENT rather than a literal, so it still fails if \
         either path later changes what it means by the inner DS byte"
    );
}

/// The exemption. A keepalive carries NO inner IP packet, so there is nothing
/// for RFC 6040 §4.1 to propagate and it must go out unmarked.
///
/// This drives the real `send_keepalive` rather than `wg_send_to` directly,
/// because the claim is about the CALL SITE's choice. A cell that only checked
/// data packets could not see a change that started stamping keepalives — and a
/// keepalive inheriting some previous packet's DSCP is precisely the bug a
/// per-datagram cmsg exists to avoid.
#[test]
fn keepalives_are_not_marked_7758() {
    let Some((rx, rx_port)) = rx_socket_with_tos() else {
        return;
    };
    let (tx, tx_is_v6) = bind_wg_socket(0).expect("bind tx");
    let (init_engine, _resp_engine, _init_pub, resp_pub) =
        crate::afxdp::wg::tests::established_pair(
            vec!["10.0.0.0/24".parse().unwrap()],
            vec!["10.0.1.0/24".parse().unwrap()],
        );
    let target: SocketAddr = format!("127.0.0.1:{rx_port}").parse().unwrap();
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let mut encap_buf = vec![0u8; 2048];

    send_keepalive(
        &init_engine,
        &tx,
        tx_is_v6,
        &resp_pub,
        target,
        crate::afxdp::wg::timers::KeepaliveKind::Passive,
        1,
        &mut encap_buf,
        "wg0",
        &exceptions,
    );

    let mut payload = [0u8; 2048];
    let got = recv_outer_ds_byte(&rx, &mut payload).unwrap_or(0);
    assert_eq!(
        got, 0,
        "a keepalive has no inner packet, so its outer DS must stay 0; a non-zero \
         value means a send site grew a TOS copy it has no source for"
    );
}

// =======================================================================
// #9521: an UNSTEERED listen port's kernel-path transport plaintext is
// dropped, not written to the wgN TUN.
// =======================================================================

struct LoopObservation9521 {
    delivered: Option<Vec<u8>>,
    unsteered_drops: u64,
    decap_packets: u64,
}

/// Run the real control loop with `kernel_transport`, send it ONE authenticated
/// transport record over IPv4 or IPv6, and report what happened to it.
fn observe_one_record_9521(
    kernel_transport: crate::afxdp::types::WgKernelTransport,
    outer_v6: bool,
    inner: &[u8],
) -> LoopObservation9521 {
    use std::sync::atomic::Ordering;
    let allowed: Vec<ipnet::IpNet> =
        vec!["10.95.21.0/24".parse().unwrap(), "fd95:21::/64".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) =
        crate::afxdp::wg::tests::established_pair(allowed.clone(), allowed);
    let resp = std::sync::Arc::new(resp);
    let loopback = if outer_v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let socket = UdpSocket::bind(loopback).expect("bind the control socket");
    socket.set_nonblocking(true).unwrap();
    let dst = socket.local_addr().unwrap();
    let (tun, tun_test_end) = super::tun_standin_pair_9521();
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (engine_t, stop_t, exc_t) = (resp.clone(), stop.clone(), exceptions.clone());
    let handle = std::thread::spawn(move || {
        run_wg_control_loop(
            "wg-test-9521",
            &engine_t,
            &socket,
            outer_v6,
            tun,
            WG_DEFAULT_OUTER_MTU,
            &std::collections::HashMap::new(),
            None,
            &exc_t,
            &stop_t,
            kernel_transport,
        );
    });

    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, inner, &mut wire).expect("initiator encap");
    let sender = UdpSocket::bind(loopback).unwrap();
    sender.send_to(&wire[..enc.len], dst).unwrap();

    // Wait until the record is ACCOUNTED FOR one way or the other. Silence alone
    // is not an observation: a record that never arrived also writes nothing.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut delivered = None;
    while std::time::Instant::now() < deadline {
        if let Some(bytes) = super::tun_standin_recv_9521(&tun_test_end) {
            delivered = Some(bytes);
            break;
        }
        if resp.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed) > 0 {
            // A write racing the counter would land here.
            std::thread::sleep(Duration::from_millis(50));
            delivered = super::tun_standin_recv_9521(&tun_test_end);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("control loop thread");
    LoopObservation9521 {
        delivered,
        unsteered_drops: resp.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed),
        decap_packets: resp.counters().decap_packets.load(Ordering::Relaxed),
    }
}

/// #9521: the control thread is where an unsteered port's plaintext left the
/// dataplane. The shim claims transport data for one listen port only, so a
/// record for any other port reaches this socket on every path, and the loop
/// used to decrypt it straight onto the wgN TUN for the kernel to forward with
/// no zone policy. Now it authenticates the record and drops the plaintext.
///
/// Both outer families, because the socket is dual-stack and a v4-only cell
/// would say nothing about the v6 path an operator's peers may use. The steered
/// run is the positive control in each family: the same record through the same
/// loop DOES reach the TUN, so the unsteered run's silence is the gate and not
/// a broken fixture — and the drop counter plus `decap_packets` prove the record
/// arrived and authenticated before it was dropped.
#[test]
fn unsteered_port_kernel_transport_is_dropped_not_written_9521() {
    use crate::afxdp::types::WgKernelTransport;
    for (outer_v6, inner) in [(false, super::inner_v4_9521()), (true, super::inner_v6_9521())] {
        let family = if outer_v6 { "IPv6" } else { "IPv4" };

        let steered = observe_one_record_9521(WgKernelTransport::Deliver, outer_v6, &inner);
        assert_eq!(
            steered.delivered.as_deref(),
            Some(&inner[..]),
            "{family}: the STEERED port's control thread must still deliver kernel-path \
             transport plaintext — #8274 kept that path for ingress the shim does not cover"
        );
        assert_eq!(steered.unsteered_drops, 0, "{family}: the steered port counted an unsteered drop");

        let unsteered = observe_one_record_9521(WgKernelTransport::DropUnsteered, outer_v6, &inner);
        assert_eq!(
            unsteered.decap_packets, 1,
            "{family}: the unsteered record never authenticated, so this run observed nothing"
        );
        assert_eq!(
            unsteered.unsteered_drops, 1,
            "{family}: an authenticated record on an unsteered port must be counted as an \
             unsteered-port drop"
        );
        assert!(
            unsteered.delivered.is_none(),
            "{family}: an UNSTEERED port's plaintext reached the wgN TUN, where the kernel \
             forwards it with no zone policy (#9521): {:?}",
            unsteered.delivered
        );
    }
}

/// #9521: a snapshot that names no steered port delivers for NO endpoint.
#[test]
fn kernel_transport_decision_fails_closed_9521() {
    use crate::afxdp::types::WgKernelTransport;
    assert_eq!(WgKernelTransport::for_listen_port(51820, 51820), WgKernelTransport::Deliver);
    assert_eq!(WgKernelTransport::for_listen_port(51821, 51820), WgKernelTransport::DropUnsteered);
    assert_eq!(
        WgKernelTransport::for_listen_port(51820, 0),
        WgKernelTransport::DropUnsteered,
        "no steered port named must fail closed, not deliver for every port"
    );
    assert_eq!(WgKernelTransport::for_listen_port(0, 0), WgKernelTransport::DropUnsteered);
}

// =======================================================================
// #9594: the STEERED port's kernel-path transport gets the XDP shim's own
// degraded posture when it arrives on an ingress the shim adjudicates.
// =======================================================================

struct FixedKernelPathView9594 {
    ingress: super::kernel_path::WgKernelPathIngress,
    local: std::collections::HashSet<std::net::IpAddr>,
    asked: Mutex<Vec<Option<u32>>>,
}

impl super::kernel_path::WgKernelPathView for FixedKernelPathView9594 {
    fn ingress(&self, ifindex: Option<u32>) -> super::kernel_path::WgKernelPathIngress {
        self.asked.lock().unwrap_or_else(|e| e.into_inner()).push(ifindex);
        self.ingress
    }
    fn destination_is_local(&self, dst: std::net::IpAddr) -> bool {
        self.local.contains(&dst)
    }
}

struct LoopObservation9594 {
    delivered: Option<Vec<u8>>,
    degraded_drops: u64,
    unsteered_drops: u64,
    decap_packets: u64,
    asked: Vec<Option<u32>>,
}

/// `observe_one_record_9521` with a posture view: run the real loop, send ONE
/// authenticated transport record over loopback, report what happened to it.
fn observe_one_record_9594(
    kernel_transport: crate::afxdp::types::WgKernelTransport,
    ingress: super::kernel_path::WgKernelPathIngress,
    inner_is_local: bool,
    outer_v6: bool,
    inner: &[u8],
) -> LoopObservation9594 {
    use std::sync::atomic::Ordering;
    let allowed: Vec<ipnet::IpNet> =
        vec!["10.95.21.0/24".parse().unwrap(), "fd95:21::/64".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) =
        crate::afxdp::wg::tests::established_pair(allowed.clone(), allowed);
    let resp = std::sync::Arc::new(resp);
    let mut local = std::collections::HashSet::new();
    if inner_is_local {
        local.insert(super::kernel_path::inner_destination(inner).expect("parseable inner"));
    }
    let view = std::sync::Arc::new(FixedKernelPathView9594 {
        ingress,
        local,
        asked: Mutex::new(Vec::new()),
    });
    let loopback = if outer_v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let socket = UdpSocket::bind(loopback).expect("bind the control socket");
    socket.set_nonblocking(true).unwrap();
    let dst = socket.local_addr().unwrap();
    let (tun, tun_test_end) = super::tun_standin_pair_9521();
    let exceptions = std::sync::Arc::new(Mutex::new(ExceptionEventRing::new()));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let raw_fd = socket.as_raw_fd();
    let (engine_t, stop_t, exc_t, view_t) = (resp.clone(), stop.clone(), exceptions.clone(), view.clone());
    let handle = std::thread::spawn(move || {
        run_wg_control_loop_with_kernel_path(
            "wg-test-9594",
            &engine_t,
            &socket,
            outer_v6,
            tun,
            WG_DEFAULT_OUTER_MTU,
            &std::collections::HashMap::new(),
            None,
            &exc_t,
            &stop_t,
            kernel_transport,
            &*view_t,
        );
    });
    // The loop enables pktinfo on its first line, and a datagram queued before
    // that carries no receiving interface. Observed under load: the send won the
    // race and the ingress assertion saw `None` for a reason that had nothing to do
    // with the code under test. Wait (bounded) until the option is on, so that
    // assertion observes the loop and not the race. If the loop never sets it, the
    // wait expires and the assertion fails exactly as it should.
    let (opt_level, opt_name) = if outer_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    let armed_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < armed_deadline {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                raw_fd,
                opt_level,
                opt_name,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 && val != 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let mut wire = vec![0u8; 2048];
    let enc = init.try_encap(&resp_pub, inner, &mut wire).expect("initiator encap");
    let sender = UdpSocket::bind(loopback).unwrap();
    sender.send_to(&wire[..enc.len], dst).unwrap();

    let counted = |r: &crate::afxdp::wg::WgEngine| {
        r.counters().rx_degraded_transit_drops.load(Ordering::Relaxed)
            + r.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed)
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut delivered = None;
    while std::time::Instant::now() < deadline {
        if let Some(bytes) = super::tun_standin_recv_9521(&tun_test_end) {
            delivered = Some(bytes);
            break;
        }
        if counted(&resp) > 0 {
            std::thread::sleep(Duration::from_millis(50));
            delivered = super::tun_standin_recv_9521(&tun_test_end);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("control loop thread");
    let asked = view.asked.lock().unwrap_or_else(|e| e.into_inner()).clone();
    LoopObservation9594 {
        delivered,
        degraded_drops: resp.counters().rx_degraded_transit_drops.load(Ordering::Relaxed),
        unsteered_drops: resp.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed),
        decap_packets: resp.counters().decap_packets.load(Ordering::Relaxed),
        asked,
    }
}

/// #9594: while the dataplane is degraded the shim passes a steered-port record
/// addressed to the firewall up to the kernel, and the steered port's thread
/// used to write its plaintext to the wgN TUN whatever it was — so inner TRANSIT
/// rode the kernel's open forward hook while every other transit packet was
/// being dropped. On an ingress the shim adjudicates, the thread now applies the
/// shim's own degraded posture to the decapsulated packet.
///
/// Every arm runs in both outer families, and three controls sit beside the
/// refusal: the #8274 uncovered-ingress record is still delivered (positive
/// control), a covered record addressed to the firewall is still delivered (the
/// posture is not a blanket drop), and the record's REAL receiving interface —
/// the loopback ifindex, from the kernel's pktinfo cmsg through `wg_recvmsg` —
/// is what the posture was asked about, so the decision is not being made on a
/// value the loop never learned.
#[test]
fn steered_port_kernel_transport_gets_the_degraded_posture_on_covered_ingress_9594() {
    use super::kernel_path::WgKernelPathIngress::{Covered, Uncovered, Unknown};
    use crate::afxdp::types::WgKernelTransport::Deliver;
    let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert!(lo > 0, "setup: the loopback interface has no ifindex");
    for (outer_v6, inner) in [(false, super::inner_v4_9521()), (true, super::inner_v6_9521())] {
        let family = if outer_v6 { "IPv6" } else { "IPv4" };

        let uncovered = observe_one_record_9594(Deliver, Uncovered, false, outer_v6, &inner);
        assert_eq!(
            uncovered.delivered.as_deref(),
            Some(&inner[..]),
            "{family}: an UNCOVERED ingress must still deliver the steered port's plaintext — \
             #8274 kept that path because it is the only one there (positive control)"
        );
        assert_eq!(uncovered.degraded_drops, 0, "{family}: uncovered ingress counted a degraded drop");
        assert_eq!(
            uncovered.asked,
            vec![Some(lo)],
            "{family}: the posture must be asked about the record's real receiving interface \
             (the kernel's pktinfo cmsg for loopback). Anything else means the loop is deciding \
             on a value it never learned — no pktinfo option, a dropped cmsg parse, or a \
             dispatch that does not pass the ifindex through"
        );

        let transit = observe_one_record_9594(Deliver, Covered, false, outer_v6, &inner);
        assert_eq!(
            transit.decap_packets, 1,
            "{family}: the covered-ingress record never authenticated, so this run observed nothing"
        );
        assert_eq!(
            transit.degraded_drops, 1,
            "{family}: transit on a covered ingress must be counted as a degraded-transit drop"
        );
        assert!(
            transit.delivered.is_none(),
            "{family}: the steered port wrote degraded-window TRANSIT plaintext to the wgN TUN, \
             where the kernel forwards it with no zone policy (#9594): {:?}",
            transit.delivered
        );

        let host_inbound = observe_one_record_9594(Deliver, Covered, true, outer_v6, &inner);
        assert_eq!(
            host_inbound.delivered.as_deref(),
            Some(&inner[..]),
            "{family}: a covered-ingress record addressed to the firewall must still be delivered — \
             the shim's degraded posture passes local traffic, and a blanket drop would cut \
             management over the VPN during a failover"
        );
        assert_eq!(host_inbound.degraded_drops, 0, "{family}: host-inbound counted a degraded drop");

        let unknown = observe_one_record_9594(Deliver, Unknown, false, outer_v6, &inner);
        assert_eq!(unknown.degraded_drops, 1, "{family}: an unplaceable ingress must fail closed for transit");
        assert!(unknown.delivered.is_none(), "{family}: unplaceable-ingress transit reached the TUN");
    }
}

/// #9594: an UNSTEERED port is refused by #9521 before the degraded posture is
/// consulted, and is counted as #9521 counts it — not double-counted, and not
/// relabelled as a degraded drop.
#[test]
fn unsteered_port_is_refused_before_the_degraded_posture_is_consulted_9594() {
    use super::kernel_path::WgKernelPathIngress::Covered;
    use crate::afxdp::types::WgKernelTransport::DropUnsteered;
    let inner = super::inner_v4_9521();
    let obs = observe_one_record_9594(DropUnsteered, Covered, false, false, &inner);
    assert_eq!(obs.unsteered_drops, 1, "the unsteered record must be counted by #9521");
    assert_eq!(obs.degraded_drops, 0, "an unsteered record was counted as a degraded drop");
    assert!(obs.asked.is_empty(), "the posture was consulted for an unsteered port: {:?}", obs.asked);
    assert!(obs.delivered.is_none(), "unsteered plaintext reached the TUN");
}

/// #9594: the production socket must already be asking for the receiving
/// interface when `bind_wg_socket` returns — before the control loop's first line
/// runs. Otherwise a record queued in between reads as an unplaceable ingress and
/// is counted as a degraded-transit drop on a healthy box at every control-thread
/// spawn under traffic.
#[test]
fn bind_wg_socket_requests_pktinfo_before_any_datagram_9594() {
    let (socket, is_v6) = bind_wg_socket(0).expect("bind an ephemeral WireGuard socket");
    let (level, name) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &mut val as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt failed: {}", std::io::Error::last_os_error());
    assert_ne!(
        val, 0,
        "bind_wg_socket returned a socket that does not yet request the receiving interface \
         (v6={is_v6}): records queued before the loop enables it would be counted as \
         degraded-transit drops on a healthy box"
    );
}
