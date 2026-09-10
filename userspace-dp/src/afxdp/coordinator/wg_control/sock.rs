//! WG control-thread socket layer (#1432 S2a): the dual-stack listen
//! socket bind, the v4-mapped send shim, the #2317 outer-TOS cmsg
//! codec (`recvmsg` + `IP_RECVTOS` / `IPV6_RECVTCLASS` parse feeding
//! the RFC 6040 §4.2 decap ECN combine), and the poll(2) wait layer
//! the control loop blocks on when both directions are idle (#1889).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// poll(2) timeout cap when both directions are idle (#1889). Bounds
/// stop/join latency and worker-edge (relaxed atomic) pickup latency at
/// ~100ms; idle wakeups drop from 1,000/s (the prior 1ms sleep) to
/// ~10/s per tunnel. With every timer deadline >= 1s out the idle
/// timeout is effectively this constant — the deadline term only
/// becomes load-bearing if the cap is ever raised.
pub(super) const WG_POLL_CAP_MS: i32 = 100;

/// poll(2) wait disposition.
pub(super) enum PollWait {
    /// Timed out — run the timer arm and loop.
    Idle,
    /// At least one fd is readable (or EINTR — treat as a wakeup).
    Ready,
    /// Unrecoverable fd state — exit the thread (tombstone respawn is
    /// the recovery path).
    Fatal(&'static str),
}

/// Block in poll(2) on {socket, tun} POLLIN with `timeout_ms`.
/// Fatal-exit policy (plan v6/v9): the TUN's POLLERR/POLLHUP/POLLNVAL
/// are fatal (device destroyed/downed under us — poll would return
/// instantly forever); the UDP socket's POLLNVAL is fatal (fd invalid);
/// UDP POLLERR/POLLHUP are NOT fatal (ICMP errors are normal and are
/// drained via the recv_from error arm).
pub(super) fn wg_poll_wait(socket_fd: i32, tun_fd: i32, timeout_ms: i32) -> PollWait {
    let mut fds = [
        libc::pollfd {
            fd: socket_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return PollWait::Ready; // spurious wakeup — re-run the loop
        }
        return PollWait::Fatal("poll_failed");
    }
    if rc == 0 {
        return PollWait::Idle;
    }
    if fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return PollWait::Fatal("tun_revents");
    }
    if fds[0].revents & libc::POLLNVAL != 0 {
        return PollWait::Fatal("socket_pollnval");
    }
    PollWait::Ready
}

/// Clamp the next timer deadline into a poll(2) timeout in ms
/// (explicit ns->ms conversion, capped at WG_POLL_CAP_MS).
pub(super) fn poll_timeout_ms(next_deadline_ns: u64, now_ns: u64) -> i32 {
    ((next_deadline_ns.saturating_sub(now_ns) / 1_000_000).min(WG_POLL_CAP_MS as u64)) as i32
}

/// Bind the WG listen socket./// Bind the WG listen socket. Prefer a v6 dual-stack bind so a single
/// socket serves both v4-mapped and v6 peers; fall back to a v4 bind if
/// the v6 bind fails.
///
/// Codex MAJOR: a bare `[::]` bind is v6-ONLY on hosts where
/// `net.ipv6.bindv6only=1`, silently black-holing v4 peers. We clear
/// `IPV6_V6ONLY` on the fd before returning so the dual-stack guarantee
/// holds regardless of the sysctl default. If clearing it fails (e.g. a
/// hardened kernel forbids it), fall back to a v4 bind so v4 peers — the
/// common case — are never left unserved.
///
/// VRF/routing-instance note (Codex BLOCKER, S2a known limitation): this
/// socket binds the wildcard address in the MAIN routing table. A WG
/// tunnel placed inside a routing-instance whose peer route lives only in
/// that VRF is NOT yet supported — SO_BINDTODEVICE/VRF-fd binding is
/// owned by the S6 multi-instance work (#1434). S2a single-tunnel scope
/// is the default table.
///
/// IPV6_V6ONLY must be cleared BEFORE bind (Linux rejects it post-bind
/// with EINVAL — Codex r3 MAJOR), so the v6 socket is created with raw
/// libc, the option is set, then bind() is called. On any v6 failure we
/// fall back to a plain v4 bind so v4 peers (the common case) work.
/// Returns the socket plus whether it is the AF_INET6 dual-stack one
/// (v4 send targets must then be v4-mapped — see `wg_send_to`).
pub(super) fn bind_wg_socket(port: u16) -> io::Result<(UdpSocket, bool)> {
    match bind_dual_stack_v6(port) {
        Ok(sock) => Ok((sock, true)),
        Err(_) => UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).map(|s| (s, false)),
    }
}

/// Create a `[::]:port` UDP socket with IPV6_V6ONLY cleared before bind.
pub(super) fn bind_dual_stack_v6(port: u16) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Own the fd immediately so any early return closes it.
    let sock = unsafe { UdpSocket::from_raw_fd(fd) };
    // Clear IPV6_V6ONLY BEFORE bind.
    let off: libc::c_int = 0;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // bind([::]:port)
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
        sin6_scope_id: 0,
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Canonicalize a learned peer endpoint: the dual-stack `[::]` socket
/// reports IPv4 peers as V4-MAPPED IPv6 (`::ffff:a.b.c.d`), and a
/// mapped address answers `is_ipv6() == true`, which made the exact
/// pad-aware encap MTU guard charge the 40-byte IPv6 outer overhead
/// for what is really a 20-byte IPv4 outer. Found live in #1736 S2b:
/// after the first authenticated inbound replaced the configured v4
/// endpoint with its mapped form, every inner packet in the
/// (pad-aware) 1409..=1425 window was silently dropped by the guard —
/// pings passed, but full-MSS forward TCP moved ZERO bytes (the
/// kernel-wg peer's iperf3 stalled at cwnd 1.34 KB) while reverse
/// traffic was fine. Unmap to the canonical V4 form so overhead math,
/// logs, and configured-endpoint comparisons all see the real family.
pub(super) fn canonicalize_endpoint(addr: SocketAddr) -> SocketAddr {
    crate::afxdp::wg::canonicalize_endpoint(addr)
}

/// Send a WG datagram to `target`, mapping an IPv4 target to its
/// V4-MAPPED IPv6 form when the local socket is the dual-stack
/// AF_INET6 one. Linux REJECTS an `AF_INET` destination sockaddr on an
/// AF_INET6 socket — found live in #1736 S2b as a silent
/// `sendto = EINVAL` once per initiator tick (strace-proven): the
/// configured v4 `wg_endpoint` could never be initiated to AT ALL on
/// the dual-stack socket, while the logical/canonical V4 form is still
/// what the MTU guard and endpoint-learning must see
/// (`canonicalize_endpoint` above is the mirror direction). The
/// fallback v4-bound socket sends to V4 targets natively (mapping only
/// applies when `socket_is_v6`).
pub(super) fn wg_send_to(
    socket: &UdpSocket,
    socket_is_v6: bool,
    buf: &[u8],
    target: SocketAddr,
    outer_tos: Option<u8>,
) -> io::Result<usize> {
    let wire_target = match target {
        SocketAddr::V4(v4) if socket_is_v6 => SocketAddr::new(
            std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()),
            v4.port(),
        ),
        other => other,
    };
    // #7758: `None` is the pre-existing path, byte-for-byte. Every send that
    // carries no inner IP packet -- handshake initiation, handshake response,
    // cookie reply, keepalive -- passes it, because there is no inner DS byte
    // to propagate and RFC 6040 §4.1 has nothing to say about them. The
    // parameter is explicit rather than defaulted so a NEW send site has to
    // decide which it is instead of silently inheriting either answer.
    let Some(tos) = outer_tos else {
        return socket.send_to(buf, wire_target);
    };
    send_to_with_tos(socket, buf, wire_target, tos)
}

/// #7758: `sendmsg` one datagram with the outer DS byte set per-datagram via
/// `IP_TOS` / `IPV6_TCLASS` ancillary data.
///
/// Per-datagram ancillary data rather than `setsockopt`: the value is the
/// INNER packet's DS byte and therefore varies packet to packet, so a socket
/// option would both be wrong and race between the control thread's sends.
///
/// The cmsg level follows the WIRE family of the destination, not the socket
/// family. A v4-mapped destination on the dual-stack AF_INET6 socket emits an
/// IPv4 datagram and takes `IPPROTO_IP` / `IP_TOS` -- the same split the
/// RECEIVE side already documents, where `IP_RECVTOS` "governs both native v4
/// and the v4-mapped datagrams the dual-stack v6 socket delivers". The
/// loopback round-trip tests assert this rather than trusting it.
///
/// An error is returned rather than retried without the cmsg. The caller
/// already counts `transport_send_errors` and records a tunnel exception
/// carrying the errno, so a rejecting kernel is diagnosable as
/// `wg_socket_send:EINVAL`; a silent fall back to an unmarked send would be a
/// safety net that no test can reach, which is worse than a loud failure on a
/// path whose sockopts have been stable for two decades and whose kernel floor
/// is 6.18.
fn send_to_with_tos(
    socket: &UdpSocket,
    buf: &[u8],
    wire_target: SocketAddr,
    tos: u8,
) -> io::Result<usize> {
    let (storage, addr_len) = socketaddr_to_storage(wire_target);
    // Choose the option family from the datagram that will actually go out.
    let (level, ctype) = match wire_target {
        SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TOS),
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
            (libc::IPPROTO_IP, libc::IP_TOS)
        }
        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
    };
    // Linux's `ip_cmsg_send` / `ip6_datagram_send_ctl` both read this payload
    // as a C `int`; the DS byte is the low-order octet.
    let tos_val = tos as libc::c_int;
    let mut cbuf = CmsgBuf([0u8; 256]);
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: `msg` is zeroed then fully populated below. `msg_name` points at
    // `storage`, which outlives the call and is described by `addr_len`.
    // `msg_control` points at `cbuf`, which is `cmsghdr`-aligned (#2334) and
    // large enough for one `int` cmsg -- CMSG_SPACE(4) is 24 bytes against a
    // 256-byte buffer. The single CMSG_DATA write below is bounded by that
    // space, and `msg_controllen` is then trimmed to exactly what was written.
    let n = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &storage as *const _ as *mut libc::c_void;
        msg.msg_namelen = addr_len;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("wg send: no room for TOS cmsg"));
        }
        (*cmsg).cmsg_level = level;
        (*cmsg).cmsg_type = ctype;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &tos_val as *const libc::c_int as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<libc::c_int>(),
        );
        libc::sendmsg(socket.as_raw_fd(), &msg, 0)
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// #7758: render a `SocketAddr` into the `sockaddr_storage` + length pair
/// `sendmsg` needs for `msg_name`. The v4/v6 mapping decision was already made
/// by the caller; this only serialises it.
fn socketaddr_to_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: `sockaddr_storage` is a plain byte aggregate with no invalid bit
    // patterns; zeroing it is the documented way to build one, and only the
    // family-appropriate prefix is written below.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: `storage` is at least as large and as aligned as
            // `sockaddr_in` (that is the type's purpose).
            unsafe {
                let sin = &raw mut storage as *mut libc::sockaddr_in;
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = v4.port().to_be();
                // `octets()` is already network order and `s_addr` is a
                // network-order u32, so this is a NATIVE-endian reinterpret of
                // bytes that are already correct -- not a byte swap. Same rule
                // as the BPF `__be32` fields (see CLAUDE.md).
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            // SAFETY: as above, for `sockaddr_in6`.
            unsafe {
                let sin6 = &raw mut storage as *mut libc::sockaddr_in6;
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_flowinfo = v6.flowinfo();
                // Scope id is load-bearing for link-local peers.
                (*sin6).sin6_scope_id = v6.scope_id();
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// #2317: enable receiving the outer IP TOS / Traffic Class as ancillary
/// data on the WG listen socket so the RFC 6040 §4.2 decap ECN combine
/// can fold the outer ECN into the decrypted inner packet (the kernel
/// UDP socket strips the outer IP header before the WG record reaches
/// userspace). Sets `IP_RECVTOS` on every socket (it governs both native
/// v4 and the v4-mapped datagrams the dual-stack v6 socket delivers) and
/// additionally `IPV6_RECVTCLASS` on the dual-stack v6 socket for native
/// v6 peers. Best-effort: a failure is logged via the return value being
/// ignored by the caller — the combine is simply skipped when no cmsg
/// arrives, which is the pre-#2317 behavior, so this is never fatal.
/// #2317: enable outer-TOS ancillary delivery (`IP_RECVTOS` /
/// `IPV6_RECVTCLASS`) on a WG UDP socket so the decap ECN combine can see
/// the outer DS byte the kernel UDP stack otherwise strips. Best-effort:
/// a kernel that rejects the sockopt (very old, or a restricted sandbox)
/// simply delivers no TOS cmsg and the combine is skipped (outer_ecn =
/// None). A failure is logged once here — this runs only at socket
/// creation, never on the packet path — so an operator can see why ECN
/// propagation is inactive.
pub(super) fn set_recv_tos_options(fd: i32, socket_is_v6: bool) {
    let on: libc::c_int = 1;
    // IP_RECVTOS — outer IPv4 TOS (also delivered for v4-mapped peers on
    // the dual-stack socket).
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        eprintln!(
            "xpf-wg: IP_RECVTOS not enabled (fd {fd}): {} — decap ECN combine inactive for v4",
            io::Error::last_os_error()
        );
    }
    if socket_is_v6 {
        // IPV6_RECVTCLASS — outer IPv6 Traffic Class for native v6 peers.
        let rc6 = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc6 != 0 {
            eprintln!(
                "xpf-wg: IPV6_RECVTCLASS not enabled (fd {fd}): {} — decap ECN combine inactive for v6",
                io::Error::last_os_error()
            );
        }
    }
}

/// #9594: enable ingress-interface ancillary delivery (`IP_PKTINFO`, which also
/// covers the v4-mapped datagrams a dual-stack v6 socket delivers, and
/// `IPV6_RECVPKTINFO` for native v6 peers) so a kernel-path transport record can
/// be placed relative to the XDP shim's adjudicated ingress set. Called from the
/// control loop itself, so every path that runs the loop receives it.
///
/// A kernel that rejects the option delivers no pktinfo cmsg; the record's
/// ingress is then unknown, which the posture treats as covered — fail closed
/// for transit, host-inbound still delivered. Logged once per socket.
pub(super) fn set_recv_pktinfo_options(fd: i32, socket_is_v6: bool) {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        eprintln!(
            "xpf-wg: IP_PKTINFO not enabled (fd {fd}): {} — v4 kernel-path ingress is unknown, \
             so its transit is refused while delivered host-inbound is kept (#9594)",
            io::Error::last_os_error()
        );
    }
    if socket_is_v6 {
        let rc6 = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc6 != 0 {
            eprintln!(
                "xpf-wg: IPV6_RECVPKTINFO not enabled (fd {fd}): {} — v6 kernel-path ingress is \
                 unknown, so its transit is refused while delivered host-inbound is kept (#9594)",
                io::Error::last_os_error()
            );
        }
    }
}

/// #9594: the receiving interface from an `IP_PKTINFO` / `IPV6_PKTINFO` cmsg,
/// or `None` when none is present (or its payload is short). The payload is read
/// with `read_unaligned`: `CMSG_DATA` is aligned for the header, not for
/// `in6_pktinfo`'s `u32` field.
pub(super) fn parse_ingress_ifindex_from_cmsg(msg: &libc::msghdr) -> Option<u32> {
    // SAFETY: as `parse_outer_ecn_from_cmsg` — a recvmsg-populated msghdr over the
    // 8-byte-aligned `CmsgBuf` (#2334); every payload read is guarded by
    // `cmsg_len` covering the whole struct.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;
            let data = libc::CMSG_DATA(cmsg);
            let data_off = data as usize - cmsg as usize;
            let cmsg_len = (*cmsg).cmsg_len as usize;
            if level == libc::IPPROTO_IP && ctype == libc::IP_PKTINFO {
                if cmsg_len >= data_off + std::mem::size_of::<libc::in_pktinfo>() {
                    let info = std::ptr::read_unaligned(data as *const libc::in_pktinfo);
                    if info.ipi_ifindex > 0 {
                        return Some(info.ipi_ifindex as u32);
                    }
                }
            } else if level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_PKTINFO {
                if cmsg_len >= data_off + std::mem::size_of::<libc::in6_pktinfo>() {
                    let info = std::ptr::read_unaligned(data as *const libc::in6_pktinfo);
                    if info.ipi6_ifindex > 0 {
                        return Some(info.ipi6_ifindex);
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// #2317: outcome of a single `recvmsg` on the WG socket — the datagram
/// length plus the 2-bit outer ECN parsed from the `IP_RECVTOS` /
/// `IPV6_RECVTCLASS` ancillary data (None when no TOS cmsg arrived, e.g.
/// the kernel did not honor the sockopt, in which case the decap combine
/// is skipped).
pub(super) struct WgRecv {
    pub(super) len: usize,
    pub(super) from: SocketAddr,
    pub(super) outer_ecn: Option<u8>,
    /// #9594: the interface the kernel received the datagram on (`IP_PKTINFO` /
    /// `IPV6_PKTINFO`), or `None` when no pktinfo cmsg arrived. Decides whether a
    /// kernel-path record entered on an ingress the shim adjudicates
    /// (`kernel_path.rs`).
    pub(super) ingress_ifindex: Option<u32>,
}

/// #2334: 256-byte recvmsg control buffer, over-aligned to 8 bytes so the
/// `cmsghdr` header-field reads the `CMSG_*` macros perform through a
/// `*const cmsghdr` pointing into this storage are naturally aligned.
///
/// A bare `[u8; N]` has alignment 1; `cmsghdr` (containing a `size_t`
/// `cmsg_len` plus two `c_int`s on LP64) has alignment 8. `CMSG_FIRSTHDR`
/// returns the buffer base and `parse_outer_ecn_from_cmsg` then reads the
/// multi-byte `cmsg_len` / `cmsg_level` / `cmsg_type` fields through that
/// pointer — an unaligned dereference (UB in Rust, a SIGBUS / alignment-
/// trap risk on strict-alignment targets such as ARMv8) unless the base
/// is `cmsghdr`-aligned. `align(8)` covers `align_of::<cmsghdr>()`; the
/// static assertion below fails to compile if that ever regresses.
#[repr(C, align(8))]
pub(super) struct CmsgBuf(pub(super) [u8; 256]);

// Fail-on-revert sentinel: the control buffer MUST be at least as aligned
// as `cmsghdr`, or the header-field reads in `parse_outer_ecn_from_cmsg`
// become unaligned dereferences (#2334). A future change that drops the
// `#[repr(align(8))]` (or replaces the wrapper with a bare `[u8; N]`)
// breaks compilation here rather than reintroducing latent UB.
const _: () = assert!(
    std::mem::align_of::<CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>(),
    "CmsgBuf must be at least cmsghdr-aligned (see #2334)"
);

/// #2317: receive one WG datagram via `recvmsg`, capturing the outer IP
/// TOS / Traffic Class from the ancillary `IP_RECVTOS` /
/// `IPV6_RECVTCLASS` control message. Replaces `recv_from` so the outer
/// ECN — stripped by the kernel UDP stack with the outer IP header —
/// reaches the RFC 6040 §4.2 decap combine.
///
/// The cmsg buffer is a fixed 256-byte stack array (a single TOS cmsg is
/// ~16-20 bytes; 256 covers both the v4 and v6 TOS cmsgs with margin and
/// never allocates on the hot path). It is wrapped in the 8-byte-aligned
/// `CmsgBuf` so the `cmsghdr` header-field reads are aligned (#2334).
/// `MSG_TRUNC`/`MSG_CTRUNC` are not requested — the data buffer is the
/// loop's 64 KiB scratch (max IP datagram) so transport records never
/// truncate, and a truncated cmsg only loses the (best-effort) ECN, not
/// the datagram.
pub(super) fn wg_recvmsg(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<WgRecv> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_space = CmsgBuf([0u8; 256]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_space.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space.0.len() as _;

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = n as usize;
    let from = sockaddr_storage_to_socketaddr(&storage, msg.msg_namelen)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recvmsg bad sockaddr"))?;
    // If the kernel truncated the ancillary data (MSG_CTRUNC), the cmsg
    // chain may be incomplete — don't trust it for the best-effort ECN.
    // The 256-byte control buffer is sized so this never triggers for a
    // single ~20-byte TOS cmsg, but skip defensively rather than walk a
    // partial chain (worst case: the decap combine is skipped this once).
    // #9594: the same truncation rule covers the ingress interface. A partial
    // chain yields `None`, which the kernel-path posture treats as an ingress it
    // cannot place (fail closed for transit) — never as an uncovered one.
    let (outer_ecn, ingress_ifindex) = if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        (None, None)
    } else {
        (parse_outer_ecn_from_cmsg(&msg), parse_ingress_ifindex_from_cmsg(&msg))
    };
    Ok(WgRecv {
        len,
        from,
        outer_ecn,
        ingress_ifindex,
    })
}

/// #2317: walk the control-message chain of a populated `msghdr` and
/// return the 2-bit ECN (low 2 bits of the DS byte) from the first
/// `IP_RECVTOS` / `IPV6_TCLASS` cmsg found. `IP_RECVTOS` delivers the
/// IPv4 TOS as a single byte (some kernels pad it into an `int`-sized
/// payload); `IPV6_TCLASS` delivers the Traffic Class as an `int`. We
/// read the FIRST payload byte in both cases — the DS byte is the
/// low-order byte on the little-endian hosts xpf targets and, more
/// robustly, IP_RECVTOS's documented payload is a `u8`. Returns `None`
/// when no TOS cmsg is present (kernel ignored the sockopt, or a
/// truncated cmsg).
pub(super) fn parse_outer_ecn_from_cmsg(msg: &libc::msghdr) -> Option<u8> {
    // SAFETY: `msg` is a fully-initialized msghdr returned by recvmsg
    // (msg_control / msg_controllen describe a valid buffer). The control
    // buffer is the 8-byte-aligned `CmsgBuf` (#2334), so the `cmsghdr`
    // base CMSG_FIRSTHDR/CMSG_NXTHDR return — and therefore the multi-byte
    // `cmsg_len` / `cmsg_level` / `cmsg_type` header-field reads below —
    // are naturally aligned (cmsghdr has alignment 8 on LP64). The single
    // payload byte at CMSG_DATA is read only after the `cmsg_len` guard
    // confirms it lies within the cmsg.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;
            let is_v4_tos = level == libc::IPPROTO_IP && ctype == libc::IP_TOS;
            let is_v6_tclass = level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_TCLASS;
            if is_v4_tos || is_v6_tclass {
                let data = libc::CMSG_DATA(cmsg);
                // cmsg_len includes the header; the payload starts at
                // CMSG_DATA. Guard with `>=` against a malformed/truncated
                // cmsg_len shorter than the header offset (a raw
                // subtraction would underflow the unsigned length): require
                // cmsg_len to cover the header plus at least one payload
                // byte before reading the DS byte.
                let data_off = data as usize - cmsg as usize;
                if (*cmsg).cmsg_len as usize >= data_off + 1 {
                    let ds = *data;
                    return Some(ds & 0x03);
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// #2317: convert a `recvmsg`-populated `sockaddr_storage` to a Rust
/// `SocketAddr`. The dual-stack v6 socket reports v4 peers as v4-mapped
/// IPv6 (caller `canonicalize_endpoint`s the result, as the prior
/// `recv_from` path did). Returns `None` for an unrecognized family.
pub(super) fn sockaddr_storage_to_socketaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: family is AF_INET and len covers a sockaddr_in.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: family is AF_INET6 and len covers a sockaddr_in6.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            // #2995: preserve `sin6_scope_id` (and `sin6_flowinfo`). A
            // link-local WG peer endpoint (`fe80::/10`) carries the
            // receiving interface scope in the kernel-populated
            // `sockaddr_in6`; `SocketAddr::new` would drop it (scope_id =
            // 0), and the next `wg_send_to` toward that learned endpoint
            // would be rejected with EINVAL/ENODEV (a link-local
            // destination requires a non-zero scope). For a global v6
            // endpoint `sin6_scope_id` is already 0, so this is a no-op
            // there. `sin6_scope_id` / `sin6_flowinfo` are stored in host
            // byte order by the kernel, so no byte-swap is applied.
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
