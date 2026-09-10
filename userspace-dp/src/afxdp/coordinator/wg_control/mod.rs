//! WireGuard control thread (#1432 S2a).
//!
//! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
//! modeled on `spawn_local_tunnel_sources` (the GRE local-origin
//! template). The thread owns three handles:
//!
//!   - `Arc<WgEngine>` — the S1 wire-compliant engine (shared with the
//!     dataplane workers via `ForwardingState.wg_engines`).
//!   - a `UdpSocket` bound on `wg_listen_port` (outer transport, RX+TX).
//!   - the persistent `wgN` **TUN** (inner). The kernel routes inner
//!     traffic to/from it; xpf does not re-implement inner routing or
//!     policy in S2a.
//!
//! ## RX model — kernel socket, ESP/IPsec precedent (plan §3.4)
//!
//! WG-to-firewall is local-destination UDP. The XDP shim passes
//! local-destination UDP to the kernel via `cpumap_or_pass` (the same
//! path ESP rides), and a dedicated shim early-return steers WG-port
//! local-destination UDP to the kernel deterministically, so this kernel
//! `UdpSocket` receives ALL inbound WG datagrams — handshake AND
//! transport. There is no AF_XDP hot-path decap stage and no
//! worker→control packet channel in S2a; the only worker→control
//! coupling is the relaxed-atomic NoSession handshake-request edge that
//! `WgEngine::request_handshake` records and this thread consumes.
//!
//! That was S2a. Since #8274 the shim claims TRANSPORT-DATA records for the
//! steered listen port and the worker decapsulates them in the pipeline, so on
//! a shim-covered ingress this socket sees that port's handshake and cookie
//! records only. It still sees every record for any OTHER configured listen
//! port, because the shim steers exactly one (#9521, `WgKernelTransport`).
//!
//! ## Directions
//!
//!   - **Inbound** (kernel socket → engine → TUN): dispatch on the WG
//!     type byte. type 1 → `consume_initiation_create_response` + send
//!     the response; type 2 → `consume_response`; type 3 (cookie) →
//!     drop+count (S7); type 4 (transport) → `try_decap` (the engine
//!     AllowedIPs-gates the inner src) → write the plaintext inner IP to
//!     the `wgN` TUN, where the kernel routes it — ONLY on the steered
//!     port's thread. Any other port's thread drops the authenticated
//!     record and counts `rx_unsteered_transport_drops` (#9521), because
//!     the kernel would forward that plaintext with no zone policy.
//!   - **Egress** (TUN → engine → kernel socket): inner IP packets the
//!     kernel routes onto `wgN` are read, `try_encap`'d, and sent to the
//!     peer endpoint. The transit AF_XDP egress is the other encap site
//!     (frame/mod.rs).
//!
//! ## Timers + idle wait (#1888 S5 / #1889)
//!
//! The loop blocks in poll(2) over {socket, TUN} POLLIN when idle
//! (timeout = min(next timer deadline, 100ms cap) — the cap bounds
//! stop/join and worker-edge latency) and runs a 1s-granularity timer
//! arm: session expiry (REJECT_AFTER_TIME teardown), the pure
//! `WgEngine::timer_pass` (passive/persistent keepalives, no-reply
//! reinit), and the handshake ATTEMPT machine (5s retransmit pacing,
//! 90s give-up window, identity-based success). Per-use T1/T2/T3 age
//! enforcement lives in the engine's encap/decap paths; this loop owns
//! all sends. Design of record:
//! `docs/research/1888-wg-timers/plan.md` (plan v9, 3/3 PLAN-READY).
//!
//! ## Layout (#6438)
//!
//! `mod.rs` keeps the thread entry (`wg_control_loop`) and the
//! orchestrating `run_wg_control_loop` (RX bursts → TUN burst → timer
//! arm → idle poll). The fused layers live in submodules:
//!
//!   - `mtu` — the pad-aware encapped-size formula + outer-MTU guard.
//!   - `sock` — socket bind/options, the v4-mapped send shim, the #2317
//!     outer-TOS cmsg codec, and the poll(2) wait layer.
//!   - `attempt` — the #1888 S5 handshake attempt machine + keepalive
//!     emit/pace helpers.
//!   - `dispatch` — inbound type-byte dispatch (`InboundOutcome`
//!     auth-before-roam contract) + the TUN-read encap-and-send.

use super::*;
use crate::afxdp::wg::counters::WgCounters;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

mod attempt;
mod dispatch;
pub(super) mod kernel_path;
mod mtu;
mod sock;

use attempt::{
    AttemptTrigger, HandshakeAttempt, drive_attempt_machine, pace_keepalive_skip, send_keepalive,
    start_attempt,
};
use dispatch::{InboundOutcome, dispatch_inbound, encap_and_send};
use sock::{
    PollWait, WgRecv, bind_wg_socket, canonicalize_endpoint, poll_timeout_ms, set_recv_tos_options,
    wg_poll_wait, wg_recvmsg,
};

// tunnel_supervision.rs names the last-resort outer-MTU fallback at
// `wg_control::WG_DEFAULT_OUTER_MTU` — re-export at the historical path
// with its pre-split coordinator-tree visibility.
pub(super) use mtu::WG_DEFAULT_OUTER_MTU;

// Test-only seams named only by wg_control_tests.rs — cfg-gated so
// non-test builds carry no unused imports (the #6436 gating precedent).
#[cfg(test)]
use mtu::{wg_encapped_size, wg_inner_fits_outer_mtu};
#[cfg(test)]
use sock::{
    CmsgBuf, WG_POLL_CAP_MS, parse_outer_ecn_from_cmsg, sockaddr_storage_to_socketaddr, wg_send_to,
};

/// Socket/TUN read budget per poll tick — drains a bounded burst before
/// yielding so a flood cannot starve the TUN-read direction (and vice
/// versa).
const WG_RX_BURST: usize = 64;

/// Timer decision pass granularity (#1888 S5): expiry, T6/T7/T8, and
/// the handshake attempt machine run at most once per tick — plus
/// whenever a computed deadline is due (a mid-tick deadline gated on
/// the tick alone would saturate the poll timeout to 0 and busy-spin).
const WG_TIMER_TICK_NS: u64 = 1_000_000_000;

/// Consecutive fatal (non-WouldBlock) TUN read errors before the
/// thread exits (the TUN device was destroyed under us — poll returns
/// instantly forever, reads keep failing; exiting hands recovery to
/// the #1872 tombstone + backoff respawn machinery).
const WG_TUN_FATAL_READ_LIMIT: u32 = 8;

#[allow(clippy::too_many_arguments)]
pub(super) fn wg_control_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    engine: Arc<crate::afxdp::wg::WgEngine>,
    listen_port: u16,
    // #9521: may a transport record's plaintext received on this socket be
    // written to the TUN? Decided by the coordinator at spawn.
    kernel_transport: crate::afxdp::types::WgKernelTransport,
    // #9594: the worker-visible runtime view, so the kernel-path posture can ask
    // whether a record's ingress is a configured interface.
    shared_runtime: crate::afxdp::types::RuntimeViewReader,
    outer_mtu: usize,
    per_peer_outer_mtu: std::collections::HashMap<[u8; 32], usize>,
    // #7158: peers whose endpoint was authored as a DNS hostname, as
    // (pubkey, authored `host:port`). Empty for a tunnel of IP literals,
    // which starts no resolver thread at all.
    endpoint_hosts: Vec<([u8; 32], String)>,
    // #7936: coordinator-owned resolver telemetry. Passed in rather than
    // created here for the same reason `recent_exceptions` is: this thread
    // writes it and the 1 Hz status path reads it, and the reader must not
    // depend on the writer still being alive.
    resolver_telemetry: Arc<crate::afxdp::wg::endpoint_resolver::WgEndpointResolverTelemetry>,
    recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    stop: Arc<AtomicBool>,
) {
    // Bind the UDP socket. v6 dual-stack ([::]:port) accepts both v4 and
    // v6 peers where the kernel allows it; fall back to v4 if the v6
    // bind fails. EADDRINUSE here means a host kernel wgX claims the port
    // (mutually exclusive with userspace-WG — surface a clear error).
    let (socket, socket_is_v6) = match bind_wg_socket(listen_port) {
        Ok(pair) => pair,
        Err(err) => {
            record_local_tunnel_exception(
                &recent_exceptions,
                &tunnel_name,
                format!("wg_bind_listen_port:{listen_port}:{err}"),
            );
            eprintln!(
                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: bind :{listen_port} failed: {err}"
            );
            return;
        }
    };
    if let Err(err) = socket.set_nonblocking(true) {
        record_local_tunnel_exception(
            &recent_exceptions,
            &tunnel_name,
            format!("wg_socket_nonblocking:{err}"),
        );
        eprintln!(
            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: set_nonblocking failed: {err}"
        );
        return;
    }
    // #2317: request the outer IP TOS / Traffic Class as ancillary data so
    // the RFC 6040 §4.2 decap ECN combine has the outer ECN to fold into
    // the decrypted inner packet. The kernel UDP socket strips the outer
    // IP header before the WG record reaches userspace, so `IP_RECVTOS`
    // (v4 / v4-mapped) and `IPV6_RECVTCLASS` (v6) are the only way to see
    // it. Best-effort: a kernel that rejects the option just leaves the
    // outer ECN unseen and the combine is skipped (the pre-#2317
    // behavior) — never fatal to the tunnel.
    set_recv_tos_options(socket.as_raw_fd(), socket_is_v6);

    // Attach to the persistent wgN TUN (Go pre-created it; open_tun
    // attaches to the existing device by name). Non-blocking.
    let mut tun = match open_wg_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            eprintln!(
                "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: open_tun failed: {err}"
            );
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        eprintln!(
            "xpf-userspace-dp: WG control thread exiting tun={tunnel_name}: tun set_nonblocking failed: {err}"
        );
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    // #7158: spawn the endpoint resolver HERE rather than at the supervisor,
    // because it needs `socket_is_v6` to filter answers to the family this
    // interface's single UDP socket can actually send from — and that is only
    // known once the bind above has chosen it (the v6 bind falls back to v4).
    //
    // Dropped when this function returns, which joins the thread, so the
    // resolver's lifetime is exactly the control thread's.
    let endpoint_resolver = crate::afxdp::wg::endpoint_resolver::WgEndpointResolver::spawn(
        &tunnel_name,
        endpoint_hosts,
        socket_is_v6,
        // #7936: the telemetry object is the COORDINATOR's, cloned in here.
        // The resolver is a local of this thread and dies with it, which is
        // why #7158's counters never reached the status wire; handing it an
        // Arc the coordinator already holds is the same shape
        // `recent_exceptions` uses, and it keeps the counters continuous
        // across a control-thread restart instead of resetting them.
        resolver_telemetry,
    );

    // #9594: the production kernel-path posture — the XDP shim's own pinned
    // ingress and local-address maps. Built here, on the control thread that
    // uses it.
    let kernel_path_view =
        kernel_path::ShimMapsKernelPathView::new(tunnel_name.clone(), shared_runtime);
    run_wg_control_loop_with_kernel_path(
        &tunnel_name,
        &engine,
        &socket,
        socket_is_v6,
        tun,
        outer_mtu,
        &per_peer_outer_mtu,
        endpoint_resolver.as_ref(),
        &recent_exceptions,
        &stop,
        kernel_transport,
        &kernel_path_view,
    );
    // #1866 D3: clean stop-flag exit (teardown) — rare, one line.
    eprintln!("xpf-userspace-dp: WG control thread stopped tun={tunnel_name}");
    let _ = tunnel_endpoint_id;
}

/// #9594: the loop with NO kernel-path posture view — every kernel-path record
/// is handled as arriving on an UNCOVERED ingress, which is the pre-#9594
/// behavior the older loop cells were written against. Test-only by
/// construction: a production caller would be a silent fail-open, so it does not
/// exist outside `cfg(test)`; `wg_control_loop` passes the shim-map view.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_wg_control_loop(
    tunnel_name: &str,
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    tun: std::fs::File,
    outer_mtu: usize,
    per_peer_outer_mtu: &std::collections::HashMap<[u8; 32], usize>,
    endpoint_resolver: Option<&crate::afxdp::wg::endpoint_resolver::WgEndpointResolver>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    stop: &AtomicBool,
    kernel_transport: crate::afxdp::types::WgKernelTransport,
) {
    run_wg_control_loop_with_kernel_path(
        tunnel_name,
        engine,
        socket,
        socket_is_v6,
        tun,
        outer_mtu,
        per_peer_outer_mtu,
        endpoint_resolver,
        recent_exceptions,
        stop,
        kernel_transport,
        &kernel_path::UncoveredKernelPathView,
    );
}

/// #9521 test seam: pre-opened stand-ins for the wgN TUN, keyed by tunnel name.
///
/// A test cannot create a TUN device without CAP_NET_ADMIN, so a control thread
/// spawned by the real coordinator path exits at `open_tun` — which left every
/// hop between the spawn decision and the TUN write unobservable. A test that
/// registers a stand-in here (a datagram socketpair keeps TUN packet boundaries)
/// drives the whole path, spawn included. Compiled out of production builds.
#[cfg(test)]
pub(super) static TEST_WG_TUN_STANDINS: Mutex<Vec<(String, std::fs::File)>> = Mutex::new(Vec::new());

fn open_wg_tun(tunnel_name: &str) -> Result<(std::fs::File, String), String> {
    #[cfg(test)]
    {
        let mut standins = TEST_WG_TUN_STANDINS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = standins.iter().position(|(name, _)| name == tunnel_name) {
            let (name, file) = standins.remove(pos);
            return Ok((file, name));
        }
    }
    open_tun(tunnel_name)
}

/// #9521 test helper: a datagram socketpair standing in for the wgN TUN, as
/// (thread end, test end). SOCK_DGRAM keeps packet boundaries the way a TUN
/// does. Both ends are non-blocking: the production caller makes the real TUN
/// non-blocking before the loop runs, and a blocking stand-in hangs the loop in
/// its TUN read.
#[cfg(test)]
pub(super) fn tun_standin_pair_9521() -> (std::fs::File, std::fs::File) {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
    };
    assert_eq!(rc, 0, "socketpair");
    set_fd_nonblocking(fds[0]).expect("thread end non-blocking");
    set_fd_nonblocking(fds[1]).expect("test end non-blocking");
    unsafe { (std::fs::File::from_raw_fd(fds[0]), std::fs::File::from_raw_fd(fds[1])) }
}

/// #9521 test helper: register a stand-in for `tunnel_name` so a thread the
/// coordinator spawns gets it instead of a real TUN; returns the test end.
#[cfg(test)]
pub(super) fn register_tun_standin_9521(tunnel_name: &str) -> std::fs::File {
    let (thread_end, test_end) = tun_standin_pair_9521();
    TEST_WG_TUN_STANDINS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((tunnel_name.to_string(), thread_end));
    test_end
}

/// #9521 test helper: one datagram from a stand-in's test end, if any.
#[cfg(test)]
pub(super) fn tun_standin_recv_9521(test_end: &std::fs::File) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65_535];
    let n = unsafe {
        libc::recv(
            test_end.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// #9521 test helper: an inner IPv4 UDP packet 10.95.21.7 -> 10.95.21.1.
#[cfg(test)]
pub(super) fn inner_v4_9521() -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 95, 21, 7]);
    p[16..20].copy_from_slice(&[10, 95, 21, 1]);
    p[24..26].copy_from_slice(&8u16.to_be_bytes());
    p
}

/// #9521 test helper: an inner IPv6 UDP packet fd95:21::7 -> fd95:21::1.
#[cfg(test)]
pub(super) fn inner_v6_9521() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&8u16.to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    let src: std::net::Ipv6Addr = "fd95:21::7".parse().unwrap();
    let dst: std::net::Ipv6Addr = "fd95:21::1".parse().unwrap();
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[44..46].copy_from_slice(&8u16.to_be_bytes());
    p
}

/// The per-tunnel control loop proper, on pre-opened fds so the loop
/// logic is unit-testable without a real TUN device (the production
/// caller binds the socket and attaches the persistent wgN TUN above).
#[allow(clippy::too_many_arguments)]
fn run_wg_control_loop_with_kernel_path(
    tunnel_name: &str,
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    mut tun: std::fs::File,
    outer_mtu: usize,
    per_peer_outer_mtu: &std::collections::HashMap<[u8; 32], usize>,
    endpoint_resolver: Option<&crate::afxdp::wg::endpoint_resolver::WgEndpointResolver>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    stop: &AtomicBool,
    kernel_transport: crate::afxdp::types::WgKernelTransport,
    kernel_path_view: &dyn kernel_path::WgKernelPathView,
) {
    use std::collections::HashMap;
    // #9594: ask the kernel for each datagram's receiving interface. Set HERE,
    // inside the loop, rather than beside `set_recv_tos_options` in
    // `wg_control_loop`, so every path that runs the loop — including the cells
    // that drive it directly — exercises the option the posture depends on.
    sock::set_recv_pktinfo_options(socket.as_raw_fd(), socket_is_v6);
    // #1434 multi-peer: the control loop tracks PER-PEER state. The
    // effective endpoint (configured initiator endpoint, or the source
    // LEARNED from an authenticated inbound datagram for a responder-only
    // peer — WG endpoint roaming) is per-peer, as is the handshake
    // attempt window. Egress TUN packets are LPM-routed to the peer that
    // owns the inner destination's AllowedIPs (cryptokey routing); each
    // peer drives its own keepalive/rekey timers.
    let peer_pubkeys: Vec<[u8; 32]> = engine.peer_pubkeys();
    let mut effective_endpoints: HashMap<[u8; 32], SocketAddr> = HashMap::new();
    // #7158: last authenticated inbound datagram per peer, for the DNS/roam
    // precedence rule. Empty means "never heard from", which is exactly the
    // state in which a resolved address should be adopted immediately.
    let mut last_authenticated_rx: HashMap<[u8; 32], u64> = HashMap::new();
    for (pk, ep) in engine.peer_endpoints() {
        if let Some(ep) = ep {
            effective_endpoints.insert(pk, ep);
        }
    }
    // 64 KiB scratch for both directions (max IP packet; WG records are
    // smaller). Single allocation at thread start — no per-packet alloc.
    let mut sock_buf = vec![0u8; 65_535];
    let mut tun_buf = vec![0u8; 65_535];
    let mut decap_buf = vec![0u8; 65_535];
    let mut encap_buf = vec![0u8; 65_535];

    let socket_fd = socket.as_raw_fd();
    let tun_fd = tun.as_raw_fd();

    // #1888 S5 / #1434 per-peer timer state. `next_deadline` starts at 0
    // so the FIRST iteration always runs a timer pass and computes real
    // deadlines (u64::MAX = no deadline; never a stale past value).
    let mut attempts: HashMap<[u8; 32], HandshakeAttempt> = HashMap::new();
    let mut next_deadline: u64 = 0;
    let mut last_timer_pass_ns: u64 = 0;
    let mut tun_fatal_reads: u32 = 0;

    // Initial initiator bring-up: every peer with a configured endpoint
    // starts a real attempt window (BringUp class) so the REKEY_TIMEOUT/
    // REKEY_ATTEMPT_TIME discipline applies from packet one and boot does
    // not double-fire.
    for pk in &peer_pubkeys {
        if let Some(&ep) = effective_endpoints.get(pk) {
            if let Some(att) = start_attempt(
                engine,
                socket,
                socket_is_v6,
                pk,
                ep,
                AttemptTrigger::BringUp,
                monotonic_nanos(),
                &mut encap_buf,
                tunnel_name,
                recent_exceptions,
            ) {
                attempts.insert(*pk, att);
            }
        }
    }

    while !stop.load(Ordering::Relaxed) {
        let mut did_work = false;

        // --- Inbound: kernel socket → engine → TUN ---
        for _ in 0..WG_RX_BURST {
            // #2317: recvmsg (not recv_from) so the outer IP TOS /
            // Traffic Class arrives as ancillary data — the only way to
            // see the outer ECN the kernel UDP stack stripped with the
            // outer IP header. `outer_ecn` is None when no TOS cmsg
            // arrived (kernel ignored the sockopt); the decap combine is
            // then skipped.
            match wg_recvmsg(socket, &mut sock_buf) {
                Ok(WgRecv {
                    len,
                    from,
                    outer_ecn,
                    ingress_ifindex,
                }) if len > 0 => {
                    did_work = true;
                    // Learn / refresh the peer endpoint from `from` ONLY
                    // after the datagram cryptographically authenticates
                    // (Codex r3 MAJOR): updating on any inbound packet
                    // would let a spoofed source redirect our encrypted
                    // egress.
                    let outcome = dispatch_inbound(
                        engine,
                        socket,
                        socket_is_v6,
                        &mut tun,
                        &sock_buf[..len],
                        from,
                        outer_ecn,
                        &mut decap_buf,
                        &mut encap_buf,
                        tunnel_name,
                        recent_exceptions,
                        kernel_transport,
                        ingress_ifindex,
                        kernel_path_view,
                    );
                    // #1434: learn THIS peer's endpoint from `from` (WG
                    // endpoint roaming is per-peer). Only the
                    // authenticated peer's egress target is updated — a
                    // spoofed source for one peer cannot redirect another
                    // peer's traffic.
                    if let Some(peer) = outcome.peer() {
                        effective_endpoints.insert(peer, canonicalize_endpoint(from));
                        // #7158: stamp WHEN this peer was last heard from,
                        // authenticated. The endpoint resolver uses it to stay
                        // out of the way of a live roam — see
                        // `apply_resolved_endpoints`.
                        last_authenticated_rx.insert(peer, monotonic_nanos());
                    }
                    // Completion-site cleanup (plan v9, Codex r5/r6):
                    // a handshake completion obsoletes any request
                    // edges armed by during-attempt egress on the old
                    // session — drain them HERE, before this
                    // iteration's TUN burst, so post-completion egress
                    // can legitimately re-arm them. (The stale T7 arm
                    // was already cleared inside the engine completion
                    // path — a valid msg1/msg2 is an authenticated
                    // receive.)
                    match outcome {
                        InboundOutcome::CompletedInitiator(peer) => {
                            // #5164: drain only THIS completed peer's edges.
                            let _ = engine.take_rekey_request(&peer);
                            let _ = engine.take_handshake_request(&peer);
                            // Post-msg2 key-confirmation keepalive
                            // (Codex r2 C4, Linux receive.c parity):
                            // the peer's responder-role session is
                            // unconfirmed until it authenticates our
                            // first transport record. Send one
                            // keepalive now so a handshake we
                            // initiated with nothing to send does not
                            // leave the peer's egress blackholed.
                            send_keepalive(
                                engine,
                                socket,
                                socket_is_v6,
                                &peer,
                                canonicalize_endpoint(from),
                                crate::afxdp::wg::timers::KeepaliveKind::Passive,
                                monotonic_nanos(),
                                &mut encap_buf,
                                tunnel_name,
                                recent_exceptions,
                            );
                        }
                        InboundOutcome::CompletedResponder(peer) => {
                            // #5164: drain only THIS completed peer's edges.
                            let _ = engine.take_rekey_request(&peer);
                            let _ = engine.take_handshake_request(&peer);
                        }
                        _ => {}
                    }
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_socket_recv:{e}"),
                    );
                    break;
                }
            }
        }

        // --- Egress: TUN → engine → kernel socket ---
        // #1434 cryptokey routing: each inner packet read off the TUN is
        // routed to the peer whose AllowedIPs cover its DESTINATION
        // (longest-prefix match), then encapped toward THAT peer's
        // effective endpoint. A packet whose dst no peer claims, or whose
        // peer has no known endpoint yet (responder-only, pre-handshake),
        // is dropped (counted) — there is nowhere to send it.
        for _ in 0..WG_RX_BURST {
            match tun.read(&mut tun_buf) {
                Ok(len) if len > 0 => {
                    did_work = true;
                    tun_fatal_reads = 0;
                    let inner = &tun_buf[..len];
                    // The TUN delivers a bare inner IP packet (no L2).
                    // Sniff the family from the version nibble.
                    let af = match inner.first().map(|b| b >> 4) {
                        Some(4) => libc::AF_INET as u8,
                        Some(6) => libc::AF_INET6 as u8,
                        _ => {
                            WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                            continue;
                        }
                    };
                    let Some(dst) = crate::afxdp::gre::inner_dst_ip(inner, af) else {
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    let Some((pk, _ep)) = engine.peer_for_dest(dst) else {
                        // No peer owns this destination's AllowedIPs.
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    let Some(&ep) = effective_endpoints.get(&pk) else {
                        // The owning peer has no known endpoint yet
                        // (responder-only, learned at runtime). Drop —
                        // the reply path opens once the peer is heard
                        // from (#1865 endpoint-learning, now per-peer).
                        WgCounters::bump(&engine.counters().tun_rx_drops_no_endpoint);
                        continue;
                    };
                    // #5291: size THIS peer's encap against ITS OWN
                    // underlay MTU (cryptokey routing picked `pk`/`ep`
                    // for the inner dst), mirroring the AF_XDP transit
                    // path's per-peer resolution (#2845/#3219). A peer
                    // whose per-peer MTU was unresolvable at spawn
                    // (learned/roamed endpoint) falls back to the
                    // interface-level scalar — the pre-#5291 behaviour.
                    let peer_outer_mtu = per_peer_outer_mtu.get(&pk).copied().unwrap_or(outer_mtu);
                    encap_and_send(
                        engine,
                        socket,
                        socket_is_v6,
                        &pk,
                        ep,
                        inner,
                        &mut encap_buf,
                        peer_outer_mtu,
                        tunnel_name,
                        recent_exceptions,
                    );
                }
                Ok(_) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tun_fatal_reads += 1;
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_tun_read:{e}"),
                    );
                    break;
                }
            }
        }
        if tun_fatal_reads >= WG_TUN_FATAL_READ_LIMIT {
            // Device destroyed/downed under us: poll would report the
            // TUN ready forever while reads fail — exit cleanly and
            // let the #1872 tombstone + backoff respawn recover.
            record_local_tunnel_exception(
                recent_exceptions,
                tunnel_name,
                "wg_tun_fatal_reads:exiting".to_string(),
            );
            return;
        }

        // --- #1888 S5 timer arm (replaces the 1s re-init check) ---
        // Runs when the 1s tick elapses OR a computed deadline is due
        // (gating on the tick alone lets a mid-tick deadline saturate
        // the poll timeout to 0 and busy-spin until the tick boundary).
        let now = monotonic_nanos();
        let tick_due = now.saturating_sub(last_timer_pass_ns) >= WG_TIMER_TICK_NS;
        if tick_due || now >= next_deadline {
            next_deadline = crate::afxdp::wg::timers::WG_NO_DEADLINE_NS;
            // Session expiry is engine-wide (sweeps every peer's
            // sessions); run it once per pass, not per peer.
            engine.expire_sessions(now);
            // #7158: adopt freshly-resolved hostname endpoints before driving
            // the per-peer timers, so an initiation this pass uses the newest
            // address rather than the previous one.
            apply_resolved_endpoints(
                endpoint_resolver,
                &peer_pubkeys,
                &mut effective_endpoints,
                &last_authenticated_rx,
                now,
                tunnel_name,
            );
            // #1434: drive each peer's keepalive/rekey timers and
            // attempt machine independently. The earliest deadline
            // across ALL peers gates the poll timeout.
            for pk in &peer_pubkeys {
                // #8274 step 3: adopt an endpoint a WORKER observed on an
                // authenticated transport-data record.
                //
                // Moving type-4 decap into the AF_XDP worker took this thread's
                // dominant endpoint-learning signal off its socket — it learns
                // from authenticated datagrams, and data records are most of
                // them. Without this drain, learning degrades to
                // handshake/keepalive cadence and a roaming peer's keepalives
                // and handshake initiations keep going to the stale address.
                //
                // Adopted with the SAME canonicalisation and into the SAME map
                // as the socket path's own learning below, so a worker-observed
                // roam and a socket-observed roam are indistinguishable
                // afterwards — one representation of "where this peer is",
                // not two that can disagree.
                if let Some(observed) = engine.take_worker_observed_endpoint(pk) {
                    effective_endpoints.insert(*pk, canonicalize_endpoint(observed));
                    last_authenticated_rx.insert(*pk, monotonic_nanos());
                }
                let effective_endpoint = effective_endpoints.get(pk).copied();
                let endpoint_known = effective_endpoint.is_some();
                let actions = engine.timer_pass_for_peer(pk, now, endpoint_known);
                if let Some(kind) = actions.send_keepalive {
                    if let Some(ep) = effective_endpoint {
                        send_keepalive(
                            engine,
                            socket,
                            socket_is_v6,
                            pk,
                            ep,
                            kind,
                            now,
                            &mut encap_buf,
                            tunnel_name,
                            recent_exceptions,
                        );
                    } else {
                        pace_keepalive_skip(engine, pk, kind, now);
                    }
                }
                let mut attempt = attempts.remove(pk);
                let attempt_deadline = drive_attempt_machine(
                    engine,
                    socket,
                    socket_is_v6,
                    pk,
                    effective_endpoint,
                    &actions,
                    now,
                    &mut attempt,
                    &mut encap_buf,
                    tunnel_name,
                    recent_exceptions,
                );
                if let Some(att) = attempt {
                    attempts.insert(*pk, att);
                }
                next_deadline = next_deadline
                    .min(actions.next_deadline_ns)
                    .min(attempt_deadline);
            }
            if tick_due {
                // Only tick-condition runs advance the 1s anchor —
                // frequent sub-second deadline runs must not starve
                // the periodic tick work (expiry).
                last_timer_pass_ns = now;
            }
        }

        if !did_work {
            match wg_poll_wait(socket_fd, tun_fd, poll_timeout_ms(next_deadline, now)) {
                PollWait::Idle | PollWait::Ready => {}
                PollWait::Fatal(reason) => {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_poll_fatal:{reason}"),
                    );
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "wg_control_tests.rs"]
mod tests;

/// #7158: how long an authenticated datagram pins a peer's endpoint against a
/// DNS re-resolution.
///
/// One full handshake attempt window (`REKEY_ATTEMPT_TIME`, 90 s). While a peer
/// is actually talking to us, DNS must not move it: the authenticated source
/// address is where the peer REALLY is, including whatever NAT it is behind,
/// whereas a DNS answer is only where it CLAIMS to be reachable. Overwriting a
/// working roamed endpoint with an A record would break a tunnel that is
/// carrying traffic, which is the opposite of the point.
///
/// Once the peer has been silent for longer than a whole attempt window, the
/// learned address has stopped being evidence of anything — an attempt window
/// has already elapsed without it producing a handshake — and the DNS answer
/// takes over. That is the case this feature exists for: the peer's dynamic WAN
/// address changed, so the old learned address is dead and the new one is only
/// discoverable through the name.
const WG_ENDPOINT_ROAM_HOLD_NS: u64 = crate::afxdp::wg::session::REKEY_ATTEMPT_TIME_NS;

/// Adopt resolver answers into `effective_endpoints`, subject to the roam-hold
/// rule above. Never blocks: `latest` is a map read, never a lookup.
fn apply_resolved_endpoints(
    resolver: Option<&crate::afxdp::wg::endpoint_resolver::WgEndpointResolver>,
    peer_pubkeys: &[[u8; 32]],
    effective_endpoints: &mut std::collections::HashMap<[u8; 32], SocketAddr>,
    last_authenticated_rx: &std::collections::HashMap<[u8; 32], u64>,
    now_ns: u64,
    tunnel_name: &str,
) {
    let Some(resolver) = resolver else {
        return;
    };
    for pk in peer_pubkeys {
        let Some(resolved) = resolver.latest(pk) else {
            continue;
        };
        if effective_endpoints.get(pk) == Some(&resolved) {
            continue;
        }
        // Roam hold: a peer heard from recently keeps the address it is
        // actually reachable at.
        if let Some(&heard) = last_authenticated_rx.get(pk) {
            if now_ns.saturating_sub(heard) < WG_ENDPOINT_ROAM_HOLD_NS {
                continue;
            }
        }
        let prior = effective_endpoints.insert(*pk, resolved);
        // Rare by construction (a DDNS move, or first resolution at bring-up),
        // so this is not a hot-path log. It is the operator's account of WHY a
        // peer's endpoint moved without a commit.
        eprintln!(
            "xpf-userspace-dp: wg {tunnel_name}: peer endpoint resolved to {resolved}{}",
            match prior {
                Some(p) => format!(" (was {p})"),
                None => String::new(),
            }
        );
    }
}

#[cfg(test)]
mod endpoint_adoption_7158_tests {
    use super::*;
    use crate::afxdp::wg::endpoint_resolver::WgEndpointResolver;
    use std::collections::HashMap;

    const PK: [u8; 32] = [7u8; 32];
    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address")
    }

    /// #7158 acceptance 2/3: a resolved address is adopted, so a peer whose
    /// DDNS name moved is reached without a commit or a daemon restart.
    #[test]
    fn a_resolved_endpoint_is_adopted_when_the_peer_is_silent_7158() {
        let resolver =
            WgEndpointResolver::with_resolved_for_test(&[(PK, addr("203.0.113.9:51820"))]);
        let mut effective: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        effective.insert(PK, addr("198.51.100.1:51820"));
        // Never heard from: no roam to protect.
        let heard: HashMap<[u8; 32], u64> = HashMap::new();

        apply_resolved_endpoints(Some(&resolver), &[PK], &mut effective, &heard, 1_000, "wg0");

        assert_eq!(
            effective.get(&PK).copied(),
            Some(addr("203.0.113.9:51820")),
            "a peer we have never heard from must take the resolved address; \
             this is the DDNS move the feature exists for (#7158)"
        );
    }

    /// #7158: a peer we are CURRENTLY hearing from keeps the address it is
    /// actually reachable at.
    ///
    /// The authenticated source is where the peer really is, including whatever
    /// NAT it sits behind; a DNS answer is only where it claims to be
    /// reachable. Letting a re-resolve overwrite a live roamed endpoint would
    /// break a tunnel that is carrying traffic — the feature actively harming
    /// the case that already worked.
    ///
    /// FAIL-ON-REVERT: delete the roam-hold branch in
    /// `apply_resolved_endpoints` and the roamed address is clobbered.
    #[test]
    fn a_live_roam_is_not_clobbered_by_dns_7158() {
        let resolver =
            WgEndpointResolver::with_resolved_for_test(&[(PK, addr("203.0.113.9:51820"))]);
        let mut effective: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        // The roamed address: learned from an authenticated datagram.
        effective.insert(PK, addr("198.51.100.77:33445"));
        let mut heard: HashMap<[u8; 32], u64> = HashMap::new();
        let now = 10 * WG_ENDPOINT_ROAM_HOLD_NS;
        // Heard from one nanosecond ago.
        heard.insert(PK, now - 1);

        apply_resolved_endpoints(Some(&resolver), &[PK], &mut effective, &heard, now, "wg0");

        assert_eq!(
            effective.get(&PK).copied(),
            Some(addr("198.51.100.77:33445")),
            "DNS must not move a peer we are actively hearing from"
        );
    }

    /// #7158: once the peer has been silent for longer than a whole handshake
    /// attempt window, the learned address has stopped being evidence and DNS
    /// takes over.
    ///
    /// This is the boundary that makes the hold a HOLD rather than a permanent
    /// veto: without it, a peer that ever roamed could never be recovered
    /// through its name after its dynamic address changed — the exact topology
    /// #7158 is for.
    #[test]
    fn a_stale_roam_yields_to_dns_7158() {
        let resolver =
            WgEndpointResolver::with_resolved_for_test(&[(PK, addr("203.0.113.9:51820"))]);
        let mut effective: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        effective.insert(PK, addr("198.51.100.77:33445"));
        let mut heard: HashMap<[u8; 32], u64> = HashMap::new();
        let now = 10 * WG_ENDPOINT_ROAM_HOLD_NS;
        // Silent for exactly the hold: the boundary is inclusive-yields.
        heard.insert(PK, now - WG_ENDPOINT_ROAM_HOLD_NS);

        apply_resolved_endpoints(Some(&resolver), &[PK], &mut effective, &heard, now, "wg0");

        assert_eq!(
            effective.get(&PK).copied(),
            Some(addr("203.0.113.9:51820")),
            "after a full attempt window of silence the learned address has \
             already failed to produce a handshake; DNS must be allowed to \
             recover the peer"
        );
    }

    /// #7158 acceptance 6: with no resolver — every tunnel of IP literals —
    /// adoption is a no-op.
    #[test]
    fn no_resolver_means_no_change_7158() {
        let mut effective: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        effective.insert(PK, addr("198.51.100.1:51820"));
        let heard: HashMap<[u8; 32], u64> = HashMap::new();
        apply_resolved_endpoints(None, &[PK], &mut effective, &heard, 1_000, "wg0");
        assert_eq!(
            effective.get(&PK).copied(),
            Some(addr("198.51.100.1:51820"))
        );
    }
}
