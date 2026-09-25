use super::*;

pub(in crate::afxdp) fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

pub(super) fn monotonic_timestamp_to_datetime(
    last_nanos: u64,
    now_mono: u64,
    now_wall: chrono::DateTime<Utc>,
) -> Option<chrono::DateTime<Utc>> {
    if last_nanos == 0 {
        return None;
    }
    let age_ns = now_mono.saturating_sub(last_nanos).min(i64::MAX as u64) as i64;
    now_wall.checked_sub_signed(chrono::TimeDelta::nanoseconds(age_ns))
}

/// Send a raw Ethernet frame via AF_PACKET on the given interface.
/// Used for ARP/NDP solicitations that must bypass XSK (because the
/// XSK fill ring may not be bootstrapped on the egress interface).

/// Which kind of probe socket was opened. The two paths differ in how
/// the kernel treats the ICMP header we hand it, so the send-buffer
/// construction is keyed off this (see [`build_icmp4_echo`] /
/// [`build_icmp6_echo`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProbeSockKind {
    /// `SOCK_RAW` (primary; needs CAP_NET_RAW). The kernel does NOT touch
    /// the ICMP header — the application owns id + checksum.
    Raw,
    /// `SOCK_DGRAM` unprivileged "ping" socket (fallback; gated by
    /// `net.ipv4.ping_group_range`, no CAP_NET_RAW). The kernel REWRITES
    /// the ICMP Echo `id` to the socket's bound port and RECOMPUTES the
    /// checksum — the ping-socket contract.
    Dgram,
}

/// Select a probe socket for one address family: try `SOCK_RAW` first
/// (the privileged primary path), and on creation failure fall back to a
/// `SOCK_DGRAM` unprivileged ICMP "ping" socket. Returns the open fd and
/// the chosen kind, or `None` when BOTH fail.
///
/// The raw socket needs CAP_NET_RAW; under a rootless / unprivileged-
/// container / dropped-privilege runtime (the #1958 substrate) that
/// capability is absent and `socket(SOCK_RAW)` fails with EPERM/EACCES.
/// The DGRAM ping socket is creatable without CAP_NET_RAW when the
/// process GID is inside `net.ipv4.ping_group_range`, so it recovers
/// neighbor probing in those runtimes. Root deployments always take the
/// raw path, unchanged.
///
/// `mk(sock_type)` creates a socket of the given type for the family the
/// caller has already fixed (`AF_INET`/`AF_INET6`), returning the fd or a
/// negative value on failure. Injected so the fallback selection is
/// unit-testable without manipulating process capabilities.
///
/// `SOCK_CLOEXEC` is OR'd into the type arg so the probe fd is closed
/// atomically across any `exec` (no fd leak into exec'd children — same
/// hardening as the VRRP AF_PACKET socket in #2476 and the netlink
/// sockets already in this file).
pub(super) fn select_probe_socket(mk: impl Fn(c_int) -> c_int) -> Option<(c_int, ProbeSockKind)> {
    let raw = mk(libc::SOCK_RAW | libc::SOCK_CLOEXEC);
    if raw >= 0 {
        return Some((raw, ProbeSockKind::Raw));
    }
    let dgram = mk(libc::SOCK_DGRAM | libc::SOCK_CLOEXEC);
    if dgram >= 0 {
        return Some((dgram, ProbeSockKind::Dgram));
    }
    None
}

/// Build the 8-byte ICMPv4 Echo-Request message for a probe send.
///
/// The buffer is the ICMP message ONLY — never an IP header. (Sending a
/// raw-style buffer that began with an IP header through a DGRAM ping
/// socket was the original EINVAL: the kernel read the IP version nibble
/// `0x45` as the ICMP type and rejected it via `ping_supported()`.)
///
/// - `Raw`: the kernel does not compute the ICMP checksum for a raw
///   `IPPROTO_ICMP` socket, so embed the precomputed checksum `0xf7ff`
///   for {type=8, code=0, id=0, seq=0}.
/// - `Dgram`: the ping socket overwrites `id` with the bound port and
///   recomputes the checksum, so leave both zero. This makes the DGRAM
///   buffer byte-distinct from the raw buffer, reflecting the real
///   semantic difference.
fn build_icmp4_echo(kind: ProbeSockKind) -> [u8; 8] {
    match kind {
        // type=8, code=0, checksum=0xf7ff, id=0, seq=0
        ProbeSockKind::Raw => [8, 0, 0xf7, 0xff, 0, 0, 0, 0],
        // type=8, code=0, checksum=0 (kernel fills), id=0 (kernel fills)
        ProbeSockKind::Dgram => [8, 0, 0, 0, 0, 0, 0, 0],
    }
}

/// Build the 8-byte ICMPv6 Echo-Request message. ICMPv6 checksum is always
/// kernel-computed (raw via the `IPV6_CHECKSUM` offset sockopt; DGRAM ping
/// sockets intrinsically), so the body is identical for both kinds: type=128,
/// code=0, and a zero checksum the kernel overwrites.
fn build_icmp6_echo(_kind: ProbeSockKind) -> [u8; 8] {
    [128, 0, 0, 0, 0, 0, 0, 0]
}

/// Build the `sockaddr_in6` for an NDP-solicit probe send to `v6` egressing
/// `ifindex` (#2969).
///
/// `sin6_scope_id` MUST carry the outgoing interface's ifindex for a
/// LINK-LOCAL destination (`fe80::/10`): Linux cannot route a link-local
/// datagram without the interface scope, so a zero `sin6_scope_id` made the
/// kernel reject the `sendto` (EINVAL/ENETUNREACH) and the NDP solicit was
/// never emitted — the next-hop never resolved and IPv6 forwarding blackholed
/// to that link-local hop. `SO_BINDTODEVICE` alone is insufficient (and on the
/// DGRAM fallback it is a no-op without CAP_NET_RAW).
///
/// For a GLOBAL/ULA destination the kernel ignores `sin6_scope_id`, so setting
/// it unconditionally is harmless and keeps the construction uniform — the
/// caller does not have to special-case link-local detection. Kept as a pure
/// builder so the scope_id contract is unit-testable without a live socket.
pub(super) fn build_solicit_sockaddr_in6(v6: Ipv6Addr, ifindex: i32) -> libc::sockaddr_in6 {
    let mut sa6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
    sa6.sin6_family = libc::AF_INET6 as u16;
    sa6.sin6_addr.s6_addr = v6.octets();
    // ifindex is a non-negative kernel interface index; clamp a
    // pathological negative to 0 rather than wrap into a huge scope id.
    sa6.sin6_scope_id = ifindex.max(0) as u32;
    sa6
}

/// Trigger kernel ARP/NDP resolution by sending an ICMP echo via a
/// kernel socket bound to the egress interface. The kernel's own ARP
/// stack handles VLAN tagging correctly. No fork/exec overhead.
///
/// Primary path: `SOCK_RAW` (needs CAP_NET_RAW — held when xpfd runs as
/// root, the default). Fallback: an unprivileged `SOCK_DGRAM` ICMP ping
/// socket (no CAP_NET_RAW, gated by `net.ipv4.ping_group_range`) so
/// neighbor probing still works under the rootless/container substrate
/// (#1958, #2482). Either way the egress packet drives the kernel to
/// ARP/NDP-resolve the next-hop — the echo's reply is irrelevant.
///
/// `ifindex` is the egress interface index (available at every call site).
/// It is threaded into the IPv6 `sockaddr_in6.sin6_scope_id` so a LINK-LOCAL
/// (`fe80::/10`) next-hop solicit can actually be routed by the kernel
/// (#2969); a zero scope id silently dropped link-local NDP solicits and
/// blackholed IPv6 forwarding to those hops. The `sendto` return is checked
/// in both families and a failure is logged (it fires rarely — only on a
/// probe send error — so this does not violate the per-tick logging rules)
/// instead of being swallowed, which previously hid a never-sent solicit.
pub(super) fn trigger_kernel_arp_probe(iface_name: &str, ifindex: i32, target: IpAddr) {
    let name_c = std::ffi::CString::new(iface_name).unwrap_or_default();
    match target {
        IpAddr::V4(v4) => {
            let Some((fd, kind)) = select_probe_socket(|sock_type| unsafe {
                libc::socket(libc::AF_INET, sock_type, libc::IPPROTO_ICMP)
            }) else {
                return;
            };
            // Best-effort: SO_BINDTODEVICE itself needs CAP_NET_RAW, so on
            // the DGRAM fallback it is typically a no-op (EPERM, ignored).
            // The destination route still selects the correct egress
            // interface for a directly-connected next-hop, so resolution
            // proceeds regardless.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name_c.as_ptr() as *const libc::c_void,
                    name_c.to_bytes_with_nul().len() as libc::socklen_t,
                );
            }
            let icmp = build_icmp4_echo(kind);
            let mut sa: libc::sockaddr_in = unsafe { core::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            let sent = unsafe {
                libc::sendto(
                    fd,
                    icmp.as_ptr() as *const libc::c_void,
                    icmp.len(),
                    libc::MSG_DONTWAIT,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                // Fires only on a probe send error (rare) — do NOT swallow
                // it as the pre-#2969 code did; a silent failure hid a
                // never-sent solicit so the next-hop never resolved.
                eprintln!(
                    "xpf-userspace-dp: ARP probe sendto({iface_name}, {v4}) failed: {}",
                    io::Error::last_os_error()
                );
            }
            unsafe {
                libc::close(fd);
            }
        }
        IpAddr::V6(v6) => {
            let Some((fd, kind)) = select_probe_socket(|sock_type| unsafe {
                libc::socket(libc::AF_INET6, sock_type, libc::IPPROTO_ICMPV6)
            }) else {
                return;
            };
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name_c.as_ptr() as *const libc::c_void,
                    name_c.to_bytes_with_nul().len() as libc::socklen_t,
                );
            }
            // IPV6_CHECKSUM (auto-compute the ICMPv6 checksum at offset 2)
            // applies to RAW sockets only; a DGRAM ping6 socket computes
            // the checksum intrinsically and rejects this sockopt, so set
            // it only on the raw path.
            if kind == ProbeSockKind::Raw {
                let offset: c_int = 2;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_ICMPV6,
                        libc::IPV6_CHECKSUM,
                        &offset as *const c_int as *const libc::c_void,
                        core::mem::size_of::<c_int>() as libc::socklen_t,
                    );
                }
            }
            let icmp6 = build_icmp6_echo(kind);
            // #2969: carry the egress ifindex in sin6_scope_id so a
            // link-local (fe80::/10) solicit can actually be routed.
            let sa6 = build_solicit_sockaddr_in6(v6, ifindex);
            let sent = unsafe {
                libc::sendto(
                    fd,
                    icmp6.as_ptr() as *const libc::c_void,
                    icmp6.len(),
                    libc::MSG_DONTWAIT,
                    &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    core::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                // #2969: surface the NDP solicit send failure instead of
                // swallowing it. A zero sin6_scope_id used to fail here
                // (EINVAL/ENETUNREACH) for a link-local hop with no trace.
                eprintln!(
                    "xpf-userspace-dp: NDP probe sendto({iface_name}, {v6}%{ifindex}) failed: {}",
                    io::Error::last_os_error()
                );
            }
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// Long-lived neighbor-warmer worker loop (#1636 option C). Spawned
/// once at coordinator bring-up and fed `WarmItem`s via a bounded MPSC
/// queue from `Coordinator::queue_warm_pass`. For each item it:
///
///   1. GCs `last_probed` once per `WARM_GC_INTERVAL_NS` (runs on EVERY
///      loop iteration — idle timeout OR dequeue — so the prune is not
///      bypassed under continuous load).
///   2. Re-checks the item's owning RG is still forwarding-active on
///      this node immediately before firing (per-RG HA gate; an item
///      queued under an active RG but dequeued after demotion must NOT
///      fire).
///   3. Drops items tagged with a stale `warm_generation` (generation
///      collapse — only the latest snapshot's keys are warmed).
///   4. Skips keys probed within `WARM_PER_KEY_RATE_LIMIT_NS`.
///   5. Fires exactly ONE `trigger_kernel_arp_probe()` per (key, gen);
///      the kernel then runs its own retransmit schedule. No userspace
///      retry loop.
///
/// `last_probed.lock().expect(...)` panics on a poisoned mutex: silently
/// skipping forever would leave warming "alive but disabled" and
/// invisible. Panicking kills the worker, breaking the MPSC channel; the
/// next producer `try_send` hits `Disconnected`, increments
/// `warm_disconnected`, and emits the once-only operator warning.
pub(super) fn neighbor_warmer_loop(
    rx: Receiver<WarmItem>,
    last_probed: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
    warm_generation: Arc<AtomicU64>,
    rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    stop: Arc<AtomicBool>,
) {
    let mut last_gc_ns = monotonic_nanos();
    while !stop.load(Ordering::Relaxed) {
        // GC at the top of every iteration (idle OR dequeue path).
        let now = monotonic_nanos();
        if now.saturating_sub(last_gc_ns) >= WARM_GC_INTERVAL_NS {
            if let Ok(mut map) = last_probed.lock() {
                map.retain(|_k, &mut t| now.saturating_sub(t) < WARM_GC_MAX_AGE_NS);
            }
            last_gc_ns = now;
        }
        let item = match rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor warmer worker: channel disconnected; exiting"
                );
                return;
            }
        };
        // Re-check stop after dequeue: stop_inner sets `stop` and drops
        // the sender, but an item already in the channel would otherwise
        // be processed and fire one stray probe on a tearing-down
        // dataplane (Codex r1 Medium). Bail before any side effect.
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // Per-RG HA gate, re-checked immediately before firing.
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let rg_active = rg_runtime
            .load()
            .get(&item.rg_id)
            .map(|group| group.is_forwarding_active(now_secs))
            .unwrap_or(false);
        if !rg_active {
            continue;
        }
        // Generation collapse: drop items from a superseded snapshot.
        if item.generation != warm_generation.load(Ordering::Acquire) {
            continue;
        }
        let key = (item.ifindex, item.hop);
        let now = monotonic_nanos();
        let skip = {
            let mut map = last_probed
                .lock()
                .expect("last_probed mutex poisoned — neighbor warming forcibly disabled");
            match map.get(&key) {
                Some(&t) if now.saturating_sub(t) < WARM_PER_KEY_RATE_LIMIT_NS => true,
                _ => {
                    map.insert(key, now);
                    false
                }
            }
        };
        if !skip {
            trigger_kernel_arp_probe(&item.iface_name, item.ifindex, item.hop);
        }
    }
}

// RTM_NEWNEIGH = 28, NLM_F_REQUEST=1, NLM_F_CREATE=0x400, NLM_F_REPLACE=0x100.
pub(super) const RTM_NEWNEIGH: u16 = 28;
pub(super) const NLM_F_REQUEST: u16 = 1;
pub(super) const NLM_F_CREATE: u16 = 0x400;
pub(super) const NLM_F_REPLACE: u16 = 0x100;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
/// NUD states (`include/uapi/linux/neighbour.h`).
pub(super) const NUD_REACHABLE: u16 = 0x02;
pub(super) const NUD_STALE: u16 = 0x04;

/// NUD state installed for a DATA-PATH neighbor learn (an ARP reply /
/// NDP NA captured by XSK, see `poll_stages::stage_link_layer_classify`).
///
/// #4475 (opus-172 H-2, security hardening): this MUST be `NUD_STALE`,
/// NEVER `NUD_REACHABLE`. A data-path learn is driven by an UNSOLICITED
/// advertisement from the L2 segment — we did not necessarily probe for
/// it. Installing `NUD_REACHABLE` forced the kernel to trust the learned
/// `(ifindex, ip) -> mac` binding for the full reachable-time window with
/// NO revalidation, so a host emitting a gratuitous ARP reply / unsolicited
/// NA claiming a live next-hop (e.g. the WAN gateway) could silently
/// hijack transit + originated traffic to its own MAC (on-link neighbor-
/// cache poisoning / MITM). Installing `NUD_STALE` instead keeps the entry
/// USABLE (STALE entries forward immediately) but makes the kernel run its
/// normal neighbor-validation state machine — it revalidates (unicast
/// PROBE / upper-layer reachability confirmation) before treating the entry
/// as REACHABLE, and a fire-and-forget poison ages out on its own. This
/// also matches Linux `arp_accept=0` gratuitous-ARP handling (an existing
/// entry is refreshed to STALE, not blindly promoted). It preserves #3048
/// (a legitimate upstream VRRP-failover MAC change observed on the wire
/// still updates the binding — just as STALE, so the kernel confirms it).
///
/// Learning ONLY solicited replies (probe-driven) is the stronger fix but
/// needs a shared pending-solicitation table plumbed from the neighbor
/// warmer into the per-worker learn path; it is tracked as a follow-up and
/// is NOT required — STALE + the NDP Override honor already remove the
/// forced-REACHABLE hijack window.
pub(super) const DATA_PATH_NEIGH_STATE: u16 = NUD_STALE;

/// Serialize an `RTM_NEWNEIGH` netlink request installing
/// `(ifindex, ip) -> mac` with the given NUD `state`. Split out of
/// `add_kernel_neighbor` (#4475) so the wire encoding — in particular the
/// NUD state byte — is unit-testable without a privileged netlink socket.
///
/// `NLM_F_CREATE | NLM_F_REPLACE` semantics are unchanged: a data-path
/// learn that survives the `stage_link_layer_classify` gates (own-IP,
/// hop-limit, and the #4475 NDP Override honor) is a legitimate binding to
/// (create-or-)refresh. The anti-hijack decision — refusing to overwrite a
/// live entry that maps to a DIFFERENT LLA from an unsolicited NDP NA — is
/// enforced UPSTREAM at the learn site (it skips this call entirely), not
/// by dropping `NLM_F_REPLACE` here, because ARP replies and Override=1 NAs
/// must still update the binding (to STALE) for #3048 failover propagation.
pub(super) fn build_newneigh_request(
    ifindex: i32,
    ip: IpAddr,
    mac: [u8; 6],
    state: u16,
) -> Vec<u8> {
    let (family, ip_bytes): (u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };
    let ip_attr_len = 4 + ip_bytes.len(); // NLA header (4) + payload
    let ip_attr_padded = (ip_attr_len + 3) & !3;
    let mac_attr_len = 4 + 6;
    let mac_attr_padded = (mac_attr_len + 3) & !3;
    // ndmsg: family(1) + pad1(1) + pad2(2) + ifindex(4) + state(2) + flags(1) + type(1) = 12
    let ndmsg_len = 12;
    let total_len = 16 + ndmsg_len + ip_attr_padded + mac_attr_padded; // nlmsghdr(16) + ndmsg + attrs
    let mut buf = vec![0u8; total_len];
    // nlmsghdr
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
    // ndmsg
    buf[16] = family;
    buf[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    buf[24..26].copy_from_slice(&state.to_ne_bytes());
    // NDA_DST attribute
    let off = 16 + ndmsg_len;
    buf[off..off + 2].copy_from_slice(&(ip_attr_len as u16).to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
    buf[off + 4..off + 4 + ip_bytes.len()].copy_from_slice(&ip_bytes);
    // NDA_LLADDR attribute
    let off2 = off + ip_attr_padded;
    buf[off2..off2 + 2].copy_from_slice(&(mac_attr_len as u16).to_ne_bytes());
    buf[off2 + 2..off2 + 4].copy_from_slice(&NDA_LLADDR.to_ne_bytes());
    buf[off2 + 4..off2 + 10].copy_from_slice(&mac);
    buf
}

/// Add a neighbor entry to the kernel's neighbor table via raw netlink.
/// This ensures the kernel can forward IPv6 (and IPv4) traffic to hosts
/// whose ARP/NDP replies were captured by XSK instead of reaching the kernel.
///
/// The entry is installed `NUD_STALE`, not `NUD_REACHABLE` (#4475) — see
/// [`DATA_PATH_NEIGH_STATE`] for the anti-poisoning rationale.
pub(super) fn add_kernel_neighbor(ifindex: i32, ip: IpAddr, mac: [u8; 6]) {
    let buf = build_newneigh_request(ifindex, ip, mac, DATA_PATH_NEIGH_STATE);
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        libc::close(fd);
    }
}

#[cfg(test)]
mod newneigh_request_tests {
    use super::{
        build_newneigh_request, DATA_PATH_NEIGH_STATE, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
        NUD_REACHABLE, NUD_STALE, RTM_NEWNEIGH,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ndmsg NUD state is at byte offset 24..26 of the RTM_NEWNEIGH buffer
    // (nlmsghdr(16) + family(1) + pad(3) + ifindex(4) = 24).
    fn state_of(buf: &[u8]) -> u16 {
        u16::from_ne_bytes([buf[24], buf[25]])
    }
    fn nlmsg_flags_of(buf: &[u8]) -> u16 {
        u16::from_ne_bytes([buf[6], buf[7]])
    }

    /// #4475 FAIL-ON-REVERT (the core of the hardening). A data-path
    /// neighbor learn MUST install `NUD_STALE`, never `NUD_REACHABLE`, so
    /// the kernel revalidates a learned `(ifindex, ip) -> mac` binding
    /// instead of trusting an unsolicited ARP/NA for the full reachable-
    /// time window (on-link neighbor-cache poisoning / MITM). Reverting
    /// `DATA_PATH_NEIGH_STATE` to `NUD_REACHABLE` makes `state_of == 0x02`,
    /// failing both asserts RED.
    #[test]
    fn data_path_learn_installs_stale_not_reachable_4475() {
        assert_eq!(NUD_STALE, 0x04);
        assert_eq!(NUD_REACHABLE, 0x02);
        // The constant the data path actually passes to add_kernel_neighbor.
        assert_eq!(
            DATA_PATH_NEIGH_STATE, NUD_STALE,
            "data-path neighbor learns must install NUD_STALE (#4475), not \
             NUD_REACHABLE — the forced-reachable window is the poison"
        );
        for ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
        ] {
            let buf =
                build_newneigh_request(24, ip, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x18], DATA_PATH_NEIGH_STATE);
            assert_eq!(
                state_of(&buf),
                NUD_STALE,
                "the encoded ndmsg state for a data-path learn ({ip}) must be NUD_STALE"
            );
            assert_ne!(
                state_of(&buf),
                NUD_REACHABLE,
                "a data-path learn ({ip}) must NOT install NUD_REACHABLE"
            );
            // The message stays a create-or-replace RTM_NEWNEIGH — only the
            // NUD state changed (the anti-hijack no-overwrite decision is
            // enforced upstream at the learn site, not by dropping REPLACE).
            assert_eq!(u16::from_ne_bytes([buf[4], buf[5]]), RTM_NEWNEIGH);
            assert_eq!(
                nlmsg_flags_of(&buf),
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE
            );
        }
    }

    /// The builder faithfully encodes whatever NUD state it is handed, so
    /// the STALE guarantee above is a property of `DATA_PATH_NEIGH_STATE`,
    /// not of a hard-coded builder constant.
    #[test]
    fn build_newneigh_request_encodes_requested_state() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(
            state_of(&build_newneigh_request(3, ip, [1, 2, 3, 4, 5, 6], NUD_REACHABLE)),
            NUD_REACHABLE
        );
        assert_eq!(
            state_of(&build_newneigh_request(3, ip, [1, 2, 3, 4, 5, 6], NUD_STALE)),
            NUD_STALE
        );
    }
}

/// Monitor kernel neighbor table changes via netlink RTM_NEWNEIGH events.
/// When the kernel resolves ARP/NDP (from our send_raw_frame solicitations
/// or from slow-path reinject), it sends a netlink notification. This thread
/// receives it and updates the helper's dynamic_neighbors cache instantly,
/// so the next packet for that destination finds the neighbor and forwards
/// directly through XSK — no waiting for the Go-side snapshot refresh.
pub(super) fn update_dynamic_neighbor(
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ifindex: i32,
    ip: IpAddr,
    entry: NeighborEntry,
) -> bool {
    dynamic_neighbors.insert_if_changed((ifindex, ip), entry)
}

pub(super) fn remove_dynamic_neighbor(
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ifindex: i32,
    ip: IpAddr,
) -> bool {
    dynamic_neighbors.remove_if_present(&(ifindex, ip))
}

/// Map mutation performed by [`parse_neighbor_msg`] for one netlink
/// neighbor message. Split from the former plain `bool` (#1771 §2.6) so
/// the monitor loop can count re-dump UPSERTS (`Upserted`) for
/// `netlink_redump_upserts` without conflating them with the
/// FAILED/INCOMPLETE/DELNEIGH removal path (which also "changes" the map
/// but re-adds nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NeighborMsgEffect {
    /// No map mutation (unparseable body, no IP/MAC, or a redundant
    /// update/removal that left the map unchanged).
    None,
    /// A usable RTM_NEWNEIGH inserted or updated the entry.
    Upserted,
    /// An RTM_DELNEIGH, or an RTM_NEWNEIGH in FAILED/INCOMPLETE,
    /// removed a present entry.
    Removed,
}

pub(super) fn parse_neighbor_msg(
    nlmsg_type: u16,
    body: &[u8],
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> NeighborMsgEffect {
    fn removal(removed: bool) -> NeighborMsgEffect {
        if removed {
            NeighborMsgEffect::Removed
        } else {
            NeighborMsgEffect::None
        }
    }
    if body.len() < 12 {
        return NeighborMsgEffect::None;
    }
    let family = body[0];
    let ifindex = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    let state = u16::from_ne_bytes([body[8], body[9]]);
    let mut attr_off = 12usize;
    let mut ip: Option<IpAddr> = None;
    let mut mac: Option<[u8; 6]> = None;
    while attr_off + 4 <= body.len() {
        let attr_len = u16::from_ne_bytes([body[attr_off], body[attr_off + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([body[attr_off + 2], body[attr_off + 3]]);
        if attr_len < 4 || attr_off + attr_len > body.len() {
            break;
        }
        let payload = &body[attr_off + 4..attr_off + attr_len];
        match attr_type {
            1 => {
                if family == libc::AF_INET as u8 && payload.len() >= 4 {
                    ip = Some(IpAddr::V4(Ipv4Addr::new(
                        payload[0], payload[1], payload[2], payload[3],
                    )));
                } else if family == libc::AF_INET6 as u8 && payload.len() >= 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&payload[..16]);
                    ip = Some(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
            }
            2 => {
                if payload.len() >= 6 {
                    mac = Some([
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    ]);
                }
            }
            _ => {}
        }
        attr_off += (attr_len + 3) & !3;
    }
    let Some(ip) = ip else {
        return NeighborMsgEffect::None;
    };
    match nlmsg_type {
        28 => {
            // INCOMPLETE, FAILED, and NOARP are unusable resolved neighbors.
            // Remove a prior row too: keeping its old MAC would preserve a
            // stale forwarding path after the kernel changes the NUD state.
            const NUD_INCOMPLETE: u16 = 0x01;
            const NUD_FAILED: u16 = 0x20;
            const NUD_NOARP: u16 = 0x40;
            if (state & (NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP)) != 0 {
                return removal(remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip));
            }
            let Some(mac) = mac else {
                return NeighborMsgEffect::None;
            };
            if update_dynamic_neighbor(dynamic_neighbors, ifindex, ip, NeighborEntry { mac }) {
                NeighborMsgEffect::Upserted
            } else {
                NeighborMsgEffect::None
            }
        }
        29 => removal(remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip)),
        _ => NeighborMsgEffect::None,
    }
}

pub(super) fn request_neighbor_dump(fd: c_int, family: u8, seq: u32) -> io::Result<()> {
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ROOT: u16 = 0x100;
    const NLM_F_MATCH: u16 = 0x200;
    let mut buf = [0u8; 28];
    buf[0..4].copy_from_slice(&(28u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH).to_ne_bytes());
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
    buf[16] = family;
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    let rc = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Netlink control message types shared by the initial dump and the
/// steady-state monitor loop (re-dump completion detection, #1771 §2.6).
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;

/// Outcome of parsing one `recv()` batch during the initial dump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DumpBatchOutcome {
    /// Batch parsed; `changed` is true if any message mutated the map and
    /// `dump_done` is true if this batch carried the dump's `NLMSG_DONE`.
    Parsed { changed: bool, dump_done: bool },
    /// The dump request itself failed (`NLMSG_ERROR` carrying `next_seq`).
    Error,
}

/// Parse one netlink `recv()` batch during the startup neighbor dump.
///
/// The dump runs on a socket already subscribed to `RTMGRP_NEIGH` (the same
/// fd backs the steady-state monitor), so async multicast
/// `RTM_NEWNEIGH`/`RTM_DELNEIGH` notifications — which carry `nlmsg_seq == 0`
/// (#1771 §2.6) — can interleave with the dump reply. The previous code
/// skipped every message whose `nlmsg_seq != next_seq`, which silently
/// dropped those seq-0 events: they had already been consumed off the
/// socket and would never be re-delivered, leaving the dynamic neighbor map
/// stale until an unrelated later event or re-dump (#2918). Startup and HA
/// failover are exactly when neighbor churn is highest, so a dropped event
/// could leave a first-packet blackhole.
///
/// Fix: route a seq-0 RTM_NEWNEIGH/RTM_DELNEIGH through the same
/// `parse_neighbor_msg` path the steady-state monitor uses, absorbing it
/// into the cache instead of discarding it. The dump's own seq-matching is
/// preserved for `NLMSG_DONE`/`NLMSG_ERROR` (completion + failure
/// detection): a non-matching, non-multicast control message is still
/// skipped, and a control message that DOES match `next_seq` drives
/// completion/error exactly as before.
pub(super) fn process_dump_batch(
    buf: &[u8],
    n: usize,
    next_seq: u32,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> DumpBatchOutcome {
    let mut changed = false;
    let mut dump_done = false;
    let mut offset = 0usize;
    while offset + 16 <= n {
        let nlmsg_len = u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        let nlmsg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
        let nlmsg_seq = u32::from_ne_bytes([
            buf[offset + 8],
            buf[offset + 9],
            buf[offset + 10],
            buf[offset + 11],
        ]);
        if nlmsg_len < 16 || offset + nlmsg_len > n {
            break;
        }
        if nlmsg_seq != next_seq {
            // A message that is not part of this dump request. An async
            // multicast neighbor notification (seq 0, type 28/29) MUST be
            // absorbed — it was already pulled off the socket and will not
            // be redelivered (#2918). Any other off-sequence control
            // message is unrelated to this dump and is skipped (its own
            // dump, if any, tracks completion via its own next_seq).
            if nlmsg_seq == 0 && (nlmsg_type == 28 || nlmsg_type == 29) {
                changed |= parse_neighbor_msg(
                    nlmsg_type,
                    &buf[offset + 16..offset + nlmsg_len],
                    dynamic_neighbors,
                ) != NeighborMsgEffect::None;
            }
            offset += (nlmsg_len + 3) & !3;
            continue;
        }
        match nlmsg_type {
            NLMSG_DONE => {
                dump_done = true;
            }
            NLMSG_ERROR => {
                return DumpBatchOutcome::Error;
            }
            28 | 29 => {
                changed |= parse_neighbor_msg(
                    nlmsg_type,
                    &buf[offset + 16..offset + nlmsg_len],
                    dynamic_neighbors,
                ) != NeighborMsgEffect::None;
            }
            _ => {}
        }
        offset += (nlmsg_len + 3) & !3;
    }
    DumpBatchOutcome::Parsed { changed, dump_done }
}

pub(super) fn initial_neighbor_dump(
    fd: c_int,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> io::Result<u64> {
    let mut next_seq = 1u32;
    let mut changed = false;
    let mut buf = vec![0u8; 8192];
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        request_neighbor_dump(fd, family, next_seq)?;
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                let kind = err.kind();
                if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                    return Err(err);
                }
                continue;
            }
            match process_dump_batch(&buf, n as usize, next_seq, dynamic_neighbors) {
                DumpBatchOutcome::Error => {
                    return Err(io::Error::other("netlink neighbor dump failed"));
                }
                DumpBatchOutcome::Parsed {
                    changed: batch_changed,
                    dump_done,
                } => {
                    changed |= batch_changed;
                    if dump_done {
                        break;
                    }
                }
            }
        }
        next_seq += 1;
    }
    Ok(if changed { 1 } else { 0 })
}

/// Bounded backoff schedule (milliseconds) for retrying a FAILED initial
/// neighbor dump (#2919). The dump runs once at monitor startup and
/// publishes `neighbor_generation = 1` as the "baseline acquired"
/// sentinel the resolver epoch logic relies on. A dump that returns
/// `Err` (timeout / `WouldBlock` / `NLMSG_ERROR`) acquired NO baseline,
/// so publishing generation 1 anyway would falsely advertise a complete
/// neighbor population — quiet existing neighbors missed by the failed
/// dump would never be loaded until an unrelated later event, an
/// avoidable first-packet blackhole after helper startup or HA failover.
///
/// Instead we retry the full v4/v6 dump on this schedule until one full
/// pass completes, and publish generation 1 ONLY then. The `stop` flag
/// is honored between attempts so shutdown is not delayed. If every
/// attempt fails the generation stays 0 (an explicit "baseline
/// incomplete" state); the steady-state loop's per-batch `fetch_add` and
/// the ENOBUFS re-dump path then recover the population from 0 rather
/// than from a bogus 1.
const INITIAL_DUMP_RETRY_BACKOFF_MS: &[u64] = &[200, 500, 1000, 2000, 5000];

/// Decide whether an `initial_neighbor_dump` result may be published as
/// the `neighbor_generation = 1` baseline (#2919).
///
/// Only `Ok` — a fully completed v4+v6 dump — establishes the baseline.
/// An `Err` (timeout, `WouldBlock`, or netlink `NLMSG_ERROR`) means no
/// complete baseline was acquired and MUST NOT be published as
/// generation 1; the caller retries instead. Kept as a tiny pure
/// predicate so the publish/skip contract is unit-testable without a
/// live netlink socket (a regression that re-publishes the failure as
/// generation 1 is caught here).
pub(super) fn dump_establishes_baseline(result: &io::Result<u64>) -> bool {
    result.is_ok()
}

/// Requested receive-buffer size for the neighbor-monitor netlink socket
/// (#1658). Under an RTM_NEWNEIGH/DELNEIGH multicast burst (HA failover,
/// large neighbor churn) the default rcvbuf can overflow and the kernel
/// drops notifications + returns ENOBUFS; the steady-state loop swallows
/// `recv() <= 0` so the loss is silent and `dynamic_neighbors` can
/// permanently desync (the full dump is startup-only). 4 MiB holds many
/// thousands of small (~80-200 B wire, larger skb truesize) events —
/// enough headroom to absorb a full large-L2-domain neighbor flush while
/// the thread is stalled up to one 500 ms SO_RCVTIMEO tick.
const NEIGH_RCVBUF_BYTES: libc::c_int = 4 * 1024 * 1024; // 4 MiB

// Compile-time floor: a future edit must not silently shrink the monitor
// buffer below the burst-absorbing target.
const _: () = assert!(NEIGH_RCVBUF_BYTES >= (1 << 20));

/// Enlarge the netlink monitor receive buffer to `request` bytes.
///
/// Best-effort: tries `SO_RCVBUFFORCE` first (bypasses
/// `net.core.rmem_max`, requires CAP_NET_ADMIN — held because the helper
/// runs as root for AF_XDP/BPF), falling back to plain `SO_RCVBUF`
/// (clamped to `rmem_max`). FORCE makes the buffer guarantee
/// self-contained instead of depending on the Go-side `tuneSocketBuffers`
/// `rmem_max` bump (a cross-process side effect that is silently
/// swallowed on failure).
///
/// Returns the effective buffer size read back via `getsockopt`. The
/// kernel doubles the request for bookkeeping and may clamp the plain
/// `SO_RCVBUF` path to `rmem_max`, so the `setsockopt` return alone hides
/// a silent clamp — the readback is the ground truth and is logged. A
/// tuning failure is logged and tolerated (the monitor still works with
/// the default buffer); crashing the thread over a socket-buffer knob
/// would be a worse outcome.
fn set_neigh_monitor_rcvbuf(fd: libc::c_int, request: libc::c_int) -> libc::c_int {
    // Stack local so &-of-value is well-defined for the FFI pointer.
    let want: libc::c_int = request;
    let optlen = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let forced = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &want as *const libc::c_int as *const libc::c_void,
            optlen,
        )
    };
    let mut via = "SO_RCVBUFFORCE";
    if forced < 0 {
        let force_err = std::io::Error::last_os_error();
        let set = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &want as *const libc::c_int as *const libc::c_void,
                optlen,
            )
        };
        via = "SO_RCVBUF";
        if set < 0 {
            eprintln!(
                "neigh_monitor: SO_RCVBUFFORCE({want}) and SO_RCVBUF({want}) \
                 both failed (force: {force_err}, set: {}); using kernel \
                 default receive buffer",
                std::io::Error::last_os_error()
            );
            via = "default";
        }
    }
    // Read back the effective size: a plain SO_RCVBUF set can succeed
    // while silently clamping to rmem_max, so the setsockopt return is
    // not enough to confirm the preventive buffer is active.
    let mut eff: libc::c_int = 0;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut eff as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        eprintln!(
            "neigh_monitor: rcvbuf set via {via}: requested {want}, \
             effective {eff} bytes"
        );
    } else {
        eprintln!(
            "neigh_monitor: rcvbuf set via {via}: requested {want}, \
             getsockopt readback failed: {}",
            std::io::Error::last_os_error()
        );
    }
    eff
}

pub(super) fn neigh_monitor_thread(
    stop: Arc<AtomicBool>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    neighbor_generation: Arc<AtomicU64>,
    // #1771 §2.6: ENOBUFS/re-dump telemetry. Counted here on the monitor
    // thread but carried on the shared resolver-counter block so it
    // rides the existing status wire path (netlink_enobufs,
    // netlink_redumps, netlink_redump_upserts).
    counters: Arc<super::neighbor_resolver::ResolverCounters>,
) {
    // Create NETLINK_ROUTE socket and subscribe to neighbor events
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        eprintln!("neigh_monitor: failed to create netlink socket");
        return;
    }
    // Bind to RTMGRP_NEIGH group to receive neighbor notifications
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_groups = 1 << (libc::RTNLGRP_NEIGH - 1) as u32; // RTMGRP_NEIGH
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        eprintln!("neigh_monitor: bind failed");
        unsafe { libc::close(fd) };
        return;
    }
    // Enlarge the receive buffer before the dump + steady-state loop so a
    // burst of RTM_NEWNEIGH/DELNEIGH multicast notifications does not
    // overflow the default rcvbuf and silently drop adverts (#1658). Same
    // fd used by initial_neighbor_dump() and the recv() loop below.
    set_neigh_monitor_rcvbuf(fd, NEIGH_RCVBUF_BYTES);
    // Set 500ms receive timeout for periodic stop check.
    // Neighbor events arrive instantly via the multicast group —
    // recv() returns immediately when the kernel pushes an update.
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    // #2919: publish generation 1 ONLY once a full v4+v6 dump completes.
    // A failed dump (timeout / WouldBlock / NLMSG_ERROR) acquired no
    // baseline; publishing it as generation 1 would falsely advertise a
    // complete neighbor population and there was previously no retry,
    // stranding quiet neighbors until an unrelated later event. Retry the
    // full dump on a bounded backoff, honoring `stop` between attempts;
    // if every attempt fails the generation stays 0 ("baseline
    // incomplete") and the steady-state / ENOBUFS re-dump paths recover.
    let mut attempt = 0usize;
    loop {
        let result = initial_neighbor_dump(fd, &dynamic_neighbors);
        if dump_establishes_baseline(&result) {
            neighbor_generation.store(1, Ordering::Relaxed);
            if attempt == 0 {
                eprintln!("neigh_monitor: initial kernel neighbor dump complete");
            } else {
                eprintln!(
                    "neigh_monitor: initial kernel neighbor dump complete \
                     (after {attempt} retr{})",
                    if attempt == 1 { "y" } else { "ies" }
                );
            }
            break;
        }
        let err = result.expect_err("dump_establishes_baseline rejected an Ok result");
        if attempt >= INITIAL_DUMP_RETRY_BACKOFF_MS.len() {
            eprintln!(
                "neigh_monitor: initial dump failed after {attempt} retries \
                 ({err}); neighbor baseline incomplete (generation stays 0), \
                 relying on steady-state events / ENOBUFS re-dump to recover"
            );
            break;
        }
        let backoff_ms = INITIAL_DUMP_RETRY_BACKOFF_MS[attempt];
        eprintln!(
            "neigh_monitor: initial dump failed ({err}); retrying in \
             {backoff_ms}ms (attempt {})",
            attempt + 1
        );
        // Sleep in short slices so a stop request aborts the backoff
        // promptly instead of blocking shutdown for up to 5s.
        let mut slept = 0u64;
        while slept < backoff_ms {
            if stop.load(Ordering::Relaxed) {
                eprintln!("neigh_monitor: stop requested during initial-dump backoff");
                unsafe { libc::close(fd) };
                return;
            }
            let slice = (backoff_ms - slept).min(100);
            std::thread::sleep(std::time::Duration::from_millis(slice));
            slept += slice;
        }
        attempt += 1;
    }
    eprintln!("neigh_monitor: listening for kernel neighbor events");
    neigh_monitor_steady_state(
        fd,
        &stop,
        &dynamic_neighbors,
        &neighbor_generation,
        &counters,
    );
    unsafe { libc::close(fd) };
    eprintln!("neigh_monitor: stopped");
}

/// #5165: the steady-state neighbor-monitor loop, split out of
/// [`neigh_monitor_thread`] so it can be driven DETERMINISTICALLY over an
/// AF_UNIX `SOCK_DGRAM` socketpair in tests — no privileged AF_NETLINK socket
/// and no reliance on real kernel neighbor churn (the team-requested
/// "factor for deterministic unit-testing" seam). The caller supplies the
/// already-bound, already-dumped netlink `fd` and closes it after this
/// returns. The PRODUCTION caller sets a 500ms `SO_RCVTIMEO` on it
/// (`neigh_monitor_thread`), which is what bounds stop-latency in the field —
/// but this loop does not depend on that value, and the #5165 tests
/// deliberately supply a much longer one so the loop stays parked in `recv`
/// across a stop and the post-recv re-check is actually reached. Do not read
/// the 500ms as a precondition of this function.
///
/// Each `recv()` batch bumps the neighbor generation (`Release`, before any
/// mutation) and applies every RTM_{NEW,DEL}NEIGH message to
/// `dynamic_neighbors`. The #5165 addition is the post-recv `stop` re-check
/// below: a stop signalled while blocked in recv() retires this thread, so it
/// must NOT apply the just-received (old-generation) batch to a map that
/// `stop_inner` is about to clear / a fresh baseline is about to repopulate.
fn neigh_monitor_steady_state(
    fd: i32,
    stop: &AtomicBool,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    neighbor_generation: &AtomicU64,
    counters: &super::neighbor_resolver::ResolverCounters,
) {
    let mut buf = vec![0u8; 8192];
    // #1771 §2.5: throttle state for the ENOBUFS-triggered upsert re-dump.
    let mut last_redump_ns: u64 = 0;
    let mut redump_seq: u32 = 1000;
    // #1771 §2.6: nlmsg_seq values of the in-flight v4/v6 re-dump
    // requests (0 = none). Dump replies are unicast on this same fd and
    // carry the request seq, while multicast RTM_{NEW,DEL}NEIGH events
    // carry seq 0 — so a seq match identifies a re-dump reply and lets
    // the parse loop below count `netlink_redump_upserts` precisely.
    let mut redump_pending: [u32; 2] = [0, 0];
    while !stop.load(Ordering::Relaxed) {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            // #1771 §2.5: distinguish ENOBUFS (the kernel dropped neighbor
            // multicast notifications on rcvbuf overflow — the silent
            // desync this fixes) from the benign SO_RCVTIMEO timeout.
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOBUFS) => {
                    // #1771 §2.6: every ENOBUFS recv is a kernel-reported
                    // notification loss — count it even when the re-dump
                    // below is throttled away.
                    counters.netlink_enobufs.fetch_add(1, Ordering::Relaxed);
                    // Lost RTM_{NEW,DEL}NEIGH leave dynamic_neighbors
                    // desynced (a dropped good NEWNEIGH blackholes a dst
                    // until its next per-key event). Recover with a THROTTLED
                    // family re-dump whose GETNEIGH replies flow through the
                    // same parse path below: RTM_NEWNEIGH → insert, and a
                    // kernel-reported NUD_FAILED/INCOMPLETE → the existing
                    // #1769 immediate-revocation (correct — a dead neighbor
                    // SHOULD be removed). Crucially this is NOT a
                    // replacement/reconciling dump: it NEVER deletes an entry
                    // merely because it is ABSENT from the dump, so the
                    // RX-learned + manager-populated entries that also feed
                    // dynamic_neighbors survive (the Codex r2 "no absent-key
                    // eviction" requirement). The 5s throttle bounds RTNL
                    // contention if ENOBUFS recurs (AGY F2). The single-key
                    // on-demand GET path is NOT this dump path.
                    let now = monotonic_nanos();
                    if now.saturating_sub(last_redump_ns) > 5_000_000_000 {
                        last_redump_ns = now;
                        redump_seq = redump_seq.wrapping_add(1);
                        let seq_v4 = redump_seq;
                        let v4 = request_neighbor_dump(fd, libc::AF_INET as u8, seq_v4);
                        redump_seq = redump_seq.wrapping_add(1);
                        let seq_v6 = redump_seq;
                        let v6 = request_neighbor_dump(fd, libc::AF_INET6 as u8, seq_v6);
                        // #1771 §2.6: a re-dump counts as ISSUED when at
                        // least one family request was sent; the pending
                        // seqs let the parse loop attribute the unicast
                        // dump replies to this re-dump for the upsert
                        // counter. A failed family keeps seq 0 (no match).
                        redump_pending = [
                            if v4.is_ok() { seq_v4 } else { 0 },
                            if v6.is_ok() { seq_v6 } else { 0 },
                        ];
                        if v4.is_ok() || v6.is_ok() {
                            counters.netlink_redumps.fetch_add(1, Ordering::Relaxed);
                        }
                        match (&v4, &v6) {
                            (Ok(_), Ok(_)) => eprintln!(
                                "neigh_monitor: ENOBUFS — throttled re-dump (v4+v6) issued"
                            ),
                            _ => eprintln!(
                                "neigh_monitor: ENOBUFS — re-dump request failed (v4={v4:?} v6={v6:?})"
                            ),
                        }
                    }
                }
                // SO_RCVTIMEO periodic stop-check timeout — normal, not an
                // error. (EAGAIN == EWOULDBLOCK on Linux; the catch-all below
                // covers the alias without an unreachable-pattern warning.)
                Some(libc::EAGAIN) => {}
                // Any other recv error: skip this read and keep listening.
                _ => {}
            }
            continue;
        }
        if n == 0 {
            // EOF on a netlink socket shouldn't happen; treat as a skip.
            continue;
        }
        // #5165: re-check `stop` AFTER the blocking recv, BEFORE mutating the
        // shared neighbor map. The top-of-loop check only gates ENTRY to
        // recv(); a stop signalled while this thread was blocked in recv() (or
        // arriving with the batch) RETIRES it. Applying this now-stale batch
        // would let an old-generation consumer mutate a map that `stop_inner`
        // is about to clear / a fresh baseline is about to repopulate — the
        // exact no-mutation-after-stop violation #5165 fixes. Break so the
        // batch is dropped; `stop_inner`'s JOIN is the outer guarantee that
        // this thread is gone before the map is rebuilt.
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // #1769 epoch-guard ordering: bump the generation with `Release`
        // BEFORE mutating dynamic_neighbors. The socket is bound to
        // RTMGRP_NEIGH only, so every recv carries neighbor events; a
        // bump-first per batch guarantees the on-demand resolver's in-lock
        // `Acquire` read (`insert_confirmed_if_unchanged`) observes the
        // advance if ANY mutation in this batch could invalidate its
        // GET-derived MAC — including a DELNEIGH for an already-absent key
        // (which the old `if changed` post-bump missed entirely). The
        // resolver's worst case is a conservative reject, never a stale
        // insert. `store(1)` on dump completion stays the startup
        // sentinel; here we always advance.
        neighbor_generation.fetch_add(1, Ordering::Release);
        let mut offset = 0usize;
        while offset + 16 <= n as usize {
            let nlmsg_len = u32::from_ne_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            let nlmsg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
            if nlmsg_len < 16 || offset + nlmsg_len > n as usize {
                break;
            }
            // #1771 §2.6: nlmsg_seq (header bytes 8..12) attributes a
            // message to an in-flight re-dump (multicast events carry 0).
            let nlmsg_seq = u32::from_ne_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ]);
            let from_redump =
                nlmsg_seq != 0 && (nlmsg_seq == redump_pending[0] || nlmsg_seq == redump_pending[1]);
            if nlmsg_type == 28 || nlmsg_type == 29 {
                let effect = parse_neighbor_msg(
                    nlmsg_type,
                    &buf[offset + 16..offset + nlmsg_len],
                    &dynamic_neighbors,
                );
                // Count only genuine re-adds from a re-dump reply: an
                // RTM_NEWNEIGH whose insert CHANGED the map. Removals
                // (FAILED/INCOMPLETE) and no-op updates do not prove a
                // lost-NEWNEIGH was healed.
                if from_redump && effect == NeighborMsgEffect::Upserted {
                    counters
                        .netlink_redump_upserts
                        .fetch_add(1, Ordering::Relaxed);
                }
            } else if nlmsg_type == NLMSG_DONE && from_redump {
                // Re-dump for this family completed — retire its seq so a
                // stale slot can never match a future message.
                if nlmsg_seq == redump_pending[0] {
                    redump_pending[0] = 0;
                }
                if nlmsg_seq == redump_pending[1] {
                    redump_pending[1] = 0;
                }
            }
            offset += (nlmsg_len + 3) & !3; // align to 4
        }
    }
}

/// Enumerate the allowed CPUs described by `is_set` into the caller-provided
/// `buf`, then pick the `worker_id % count`-th entry. Pure helper — no
/// syscalls, no allocations — so behaviour can be regression-tested without
/// mutating the process affinity mask.
///
/// `is_set(cpu)` returns true if CPU index `cpu` is in the allowed mask.
/// `buf.len()` bounds the scan range (caller passes a `[u16; CPU_SETSIZE]`
/// in production; tests pass smaller arrays).
///
/// Returns `None` when the allowed set is empty.
#[cfg(target_os = "linux")]
fn nth_allowed_cpu(
    worker_id: u32,
    is_set: impl Fn(usize) -> bool,
    buf: &mut [u16],
) -> Option<usize> {
    let mut count: usize = 0;
    for cpu in 0..buf.len() {
        if is_set(cpu) {
            // CPU index is <= buf.len() <= u16::MAX in practice
            // (libc::CPU_SETSIZE = 1024). Saturating guard is cheap
            // insurance against a pathological caller.
            buf[count] = cpu.min(u16::MAX as usize) as u16;
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let idx = (worker_id as usize) % count;
    Some(buf[idx] as usize)
}

/// Pin the current thread to one CPU from the inherited affinity mask.
///
/// The previous implementation used `available_parallelism() % cpus`, which
/// picked an **absolute** CPU index — so under systemd `CPUAffinity=2 3 4 5`
/// the workers pinned to CPUs 0/1/2/3, **outside** the unit-level mask.
/// `sched_setaffinity` silently succeeded because `CPUAffinity=` is plain
/// task affinity (not a cgroup cpuset), so the violation was invisible
/// until it showed up in `/proc/<tid>/status`.
///
/// Fix: read the inherited mask with `sched_getaffinity`, enumerate the
/// allowed CPUs, and pick the `worker_id % allowed_count`-th entry. With
/// no `CPUAffinity=` the allowed set is `0..N-1` and behaviour is
/// unchanged; with `CPUAffinity=2 3 4 5` worker 0→CPU 2, worker 1→CPU 3,
/// worker 2→CPU 4, worker 3→CPU 5.
///
/// Best-effort: returns silently on `sched_getaffinity` failure or an
/// empty mask. Pinning is a tuning hint, not a correctness requirement.
pub(super) fn pin_current_thread(worker_id: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut inherited: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut inherited);
        if libc::sched_getaffinity(0, core::mem::size_of_val(&inherited), &mut inherited) != 0 {
            return;
        }
        // Fixed-size stack buffer sized to CPU_SETSIZE (1024 on Linux
        // glibc). u16 entries keep the footprint at 2 KB — well under
        // the 8 MB Rust default thread stack — and cover the full range
        // of CPU indices the kernel allows (nr_cpu_ids ≤ CONFIG_NR_CPUS,
        // currently 8192 max but CPU_SETSIZE bounds what this codepath
        // sees via cpu_set_t). Called once per worker at thread-start;
        // no hot-path cost.
        let mut allowed = [0u16; libc::CPU_SETSIZE as usize];
        let Some(target) =
            nth_allowed_cpu(worker_id, |cpu| libc::CPU_ISSET(cpu, &inherited), &mut allowed)
        else {
            return;
        };
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(target, &mut set);
        let _ = libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

pub fn neighbor_state_usable_str(state: &str) -> bool {
    neighbor_state_usable(state)
}

pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    parse_mac(s)
}

pub(super) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub(super) fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod dump_batch_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const RTM_NEWNEIGH: u16 = 28;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    const NUD_REACHABLE: u16 = 0x02;

    /// Serialize one RTM_NEWNEIGH netlink message (header + ndmsg + NDA_DST
    /// + NDA_LLADDR) into `out`, mirroring the kernel wire layout that
    /// `process_dump_batch`/`parse_neighbor_msg` decode. `seq` is the
    /// nlmsghdr sequence: the dump reply uses the request seq, a multicast
    /// notification uses 0.
    fn push_newneigh_v4(out: &mut Vec<u8>, seq: u32, ifindex: i32, ip: Ipv4Addr, mac: [u8; 6]) {
        let ip_bytes = ip.octets();
        let ip_attr_len = 4 + ip_bytes.len(); // NLA header + payload
        let ip_attr_padded = (ip_attr_len + 3) & !3;
        let mac_attr_len = 4 + 6;
        let mac_attr_padded = (mac_attr_len + 3) & !3;
        let ndmsg_len = 12;
        let total_len = 16 + ndmsg_len + ip_attr_padded + mac_attr_padded;
        let start = out.len();
        out.resize(start + total_len, 0);
        let buf = &mut out[start..];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes()); // flags
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
        // ndmsg
        buf[16] = libc::AF_INET as u8;
        buf[20..24].copy_from_slice(&ifindex.to_ne_bytes());
        buf[24..26].copy_from_slice(&NUD_REACHABLE.to_ne_bytes());
        // NDA_DST
        let off = 16 + ndmsg_len;
        buf[off..off + 2].copy_from_slice(&(ip_attr_len as u16).to_ne_bytes());
        buf[off + 2..off + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
        buf[off + 4..off + 4 + ip_bytes.len()].copy_from_slice(&ip_bytes);
        // NDA_LLADDR
        let off2 = off + ip_attr_padded;
        buf[off2..off2 + 2].copy_from_slice(&(mac_attr_len as u16).to_ne_bytes());
        buf[off2 + 2..off2 + 4].copy_from_slice(&NDA_LLADDR.to_ne_bytes());
        buf[off2 + 4..off2 + 10].copy_from_slice(&mac);
    }

    /// Serialize an NLMSG_DONE (type 3) control message carrying `seq`.
    fn push_done(out: &mut Vec<u8>, seq: u32) {
        let total_len = 16usize;
        let start = out.len();
        out.resize(start + total_len, 0);
        let buf = &mut out[start..];
        buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        buf[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    }

    /// #2918 fail-on-revert: a seq-0 (unsolicited multicast)
    /// RTM_NEWNEIGH that interleaves with the dump reply must be ABSORBED
    /// into the dynamic neighbor map, not consumed-and-dropped. The dump
    /// runs on a socket already joined to RTMGRP_NEIGH, so such an event
    /// can arrive in the same recv() batch as the dump entries; the old
    /// `if nlmsg_seq != next_seq { continue }` skip silently lost it.
    ///
    /// This test feeds `process_dump_batch` a single batch holding the
    /// dump's own entry (seq 1), an interleaved multicast entry (seq 0),
    /// and the dump's NLMSG_DONE (seq 1). Reverting the fix to the bare
    /// skip drops the seq-0 entry and the second `get` assertion FAILS.
    #[test]
    fn dump_batch_absorbs_interleaved_seq0_multicast_newneigh() {
        let dynamic = Arc::new(ShardedNeighborMap::new());
        let next_seq = 1u32;
        let ifindex = 7;
        let dump_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dump_mac = [0x02, 0, 0, 0, 0, 0x01];
        let mcast_ip = Ipv4Addr::new(10, 0, 0, 2);
        let mcast_mac = [0x02, 0, 0, 0, 0, 0x02];

        let mut buf = Vec::new();
        // Dump reply entry (carries the request seq).
        push_newneigh_v4(&mut buf, next_seq, ifindex, dump_ip, dump_mac);
        // Unsolicited multicast notification (seq 0) interleaved BEFORE
        // the dump completes — the bug case.
        push_newneigh_v4(&mut buf, 0, ifindex, mcast_ip, mcast_mac);
        // Dump completion for this family.
        push_done(&mut buf, next_seq);

        let n = buf.len();
        let outcome = process_dump_batch(&buf, n, next_seq, &dynamic);

        match outcome {
            DumpBatchOutcome::Parsed { changed, dump_done } => {
                assert!(changed, "batch mutated the map, so changed must be true");
                assert!(dump_done, "NLMSG_DONE for next_seq must end the dump");
            }
            DumpBatchOutcome::Error => panic!("unexpected NLMSG_ERROR outcome"),
        }

        // The dump's own entry is absorbed (baseline).
        assert_eq!(
            dynamic.get(&(ifindex, IpAddr::V4(dump_ip))).map(|e| e.mac),
            Some(dump_mac),
            "dump entry must be in the cache",
        );
        // FAIL-ON-REVERT: the interleaved seq-0 multicast entry must also be
        // absorbed. With the old `nlmsg_seq != next_seq` skip this is None.
        assert_eq!(
            dynamic.get(&(ifindex, IpAddr::V4(mcast_ip))).map(|e| e.mac),
            Some(mcast_mac),
            "seq-0 multicast RTM_NEWNEIGH interleaved during the dump must \
             be absorbed, not dropped (#2918)",
        );
    }

    /// Guard the completion path: NLMSG_DONE detection still keys off the
    /// dump's own seq. A seq-0 multicast event must NOT be mistaken for a
    /// dump-completion control message, and an unrelated off-seq control
    /// message must still be skipped without ending the dump early.
    #[test]
    fn dump_batch_completion_keys_off_request_seq() {
        let dynamic = Arc::new(ShardedNeighborMap::new());
        let next_seq = 2u32;

        let mut buf = Vec::new();
        // An NLMSG_DONE for an UNRELATED seq must not complete this dump.
        push_done(&mut buf, 99);
        // Dump entry + the matching completion.
        push_newneigh_v4(
            &mut buf,
            next_seq,
            3,
            Ipv4Addr::new(192, 0, 2, 9),
            [0x02, 0, 0, 0, 0, 0x09],
        );
        push_done(&mut buf, next_seq);

        let n = buf.len();
        let outcome = process_dump_batch(&buf, n, next_seq, &dynamic);
        assert_eq!(
            outcome,
            DumpBatchOutcome::Parsed {
                changed: true,
                dump_done: true,
            },
            "only the matching-seq NLMSG_DONE ends the dump",
        );
    }

    /// #2919 fail-on-revert: a FAILED initial neighbor dump must NOT be
    /// published as the `neighbor_generation = 1` baseline.
    ///
    /// `dump_establishes_baseline` is the predicate the monitor uses to
    /// gate the `store(1)` publish: it returns `true` ONLY for `Ok`
    /// (a fully completed v4+v6 dump). The pre-#2919 bug stored
    /// generation 1 on BOTH the Ok and Err arms, so a timeout /
    /// WouldBlock / NLMSG_ERROR dump looked like a successful empty
    /// baseline and was never retried.
    ///
    /// Reverting the predicate to "always publish" (e.g. `true` for both
    /// arms, mirroring the old `Err => store(1)`) makes the Err
    /// assertion below FAIL. This is the load-bearing invariant:
    /// generation 1 means a complete baseline was acquired.
    #[test]
    fn failed_initial_dump_does_not_establish_generation1_baseline() {
        // A completed dump (Ok) — empty or populated — establishes the
        // baseline and may publish generation 1.
        let ok_empty: io::Result<u64> = Ok(0);
        let ok_changed: io::Result<u64> = Ok(1);
        assert!(
            dump_establishes_baseline(&ok_empty),
            "a completed (empty) dump establishes the baseline",
        );
        assert!(
            dump_establishes_baseline(&ok_changed),
            "a completed (populated) dump establishes the baseline",
        );

        // Every failure mode that initial_neighbor_dump can return —
        // timeout, WouldBlock, and an NLMSG_ERROR-derived io::Error —
        // acquired NO baseline and MUST NOT be published as generation 1.
        for err in [
            io::Error::from(io::ErrorKind::TimedOut),
            io::Error::from(io::ErrorKind::WouldBlock),
            io::Error::other("netlink neighbor dump failed"),
        ] {
            let failed: io::Result<u64> = Err(err);
            assert!(
                !dump_establishes_baseline(&failed),
                "a failed dump must NOT publish generation 1 (it acquired no baseline)",
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod pin_tests {
    use super::nth_allowed_cpu;

    /// Build an `is_set` closure that returns true iff `cpu` is in `allowed`.
    fn mask_from<const N: usize>(allowed: [usize; N]) -> impl Fn(usize) -> bool {
        move |cpu| allowed.contains(&cpu)
    }

    #[test]
    fn nth_allowed_cpu_picks_nth_of_allowed_cpus() {
        let is_set = mask_from([2usize, 3, 4, 5]);
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(2));
        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(3));
        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(4));
        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(5));
        // worker_id 4 wraps around via `worker_id % count`
        assert_eq!(nth_allowed_cpu(4, &is_set, &mut buf), Some(2));
    }

    #[test]
    fn nth_allowed_cpu_returns_none_when_mask_is_empty() {
        let is_set = |_cpu: usize| false;
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, is_set, &mut buf), None);
        assert_eq!(nth_allowed_cpu(7, is_set, &mut buf), None);
    }

    /// #1658: setting SO_RCVBUF[FORCE] on a NETLINK_ROUTE socket must
    /// actually enlarge the effective receive buffer, and the helper must
    /// return the read-back size (the surrounding production recv() loop
    /// ignores its return; this knob must not). Uses a deliberately small
    /// request (256 KiB) so the test does not depend on running as root:
    /// the kernel sets buf = 2 * min(request, rmem_max). On a typical host
    /// rmem_max far exceeds 256 KiB, so the effective size is ~512 KiB; the
    /// assertion below uses a conservative floor (min(2*req, rmem_max),
    /// which is always <= the kernel value) so it stays flake-proof across
    /// privilege levels and any host rmem_max.
    #[test]
    fn neigh_monitor_rcvbuf_enlarges_effective_buffer() {
        const TEST_REQ: libc::c_int = 256 * 1024; // well below typical rmem_max
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        assert!(fd >= 0, "failed to create NETLINK_ROUTE socket for test");

        let effective = super::set_neigh_monitor_rcvbuf(fd, TEST_REQ);

        // Conservative floor: the kernel sets buf = 2 * min(request,
        // rmem_max) (the non-root SO_RCVBUF fallback clamps to rmem_max,
        // NOT 2*rmem_max). min(2*req, rmem_max) is always <= that value,
        // so asserting >= it never false-fails. Fall back to the weaker
        // "grew to at least the request" check if rmem_max is unreadable.
        let rmem_max = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());
        match rmem_max {
            Some(max) => {
                let doubled = 2i64 * TEST_REQ as i64;
                let expected_floor = doubled.min(max);
                assert!(
                    effective as i64 >= expected_floor,
                    "effective {effective} < expected floor {expected_floor} \
                     (request {TEST_REQ}, rmem_max {max})"
                );
                // Confirm the buffer actually grew past the ~208 KB default
                // (unless this host's rmem_max is pathologically small).
                assert!(
                    effective > 212992 || max <= TEST_REQ as i64,
                    "effective {effective} did not exceed the 208 KB default \
                     (rmem_max {max})"
                );
            }
            None => {
                assert!(
                    effective >= TEST_REQ,
                    "effective {effective} < requested {TEST_REQ}"
                );
            }
        }

        unsafe { libc::close(fd) };
    }

    #[test]
    fn nth_allowed_cpu_handles_sparse_masks() {
        let is_set = mask_from([0usize, 7, 15]);
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(0));
        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(7));
        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(15));
        // wrap-around: 3 % 3 == 0 -> first entry
        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(0));
    }

    /// Counter-factual regression guard for the systemd `CPUAffinity=2 3 4 5`
    /// scenario from #738. Reconstructs the OLD behaviour
    /// (`CPU_SET(worker_id % available_parallelism())`, which pins to an
    /// *absolute* CPU index regardless of the inherited mask) and asserts
    /// that the NEW behaviour picks the `worker_id`-th entry of the allowed
    /// set instead. Without this test a future refactor could silently
    /// revert to `CPU_SET(worker_id % n)` and no other test would catch
    /// it — the other `nth_allowed_cpu_*` tests would still pass because
    /// they exercise the pure helper, not the overall pinning contract.
    #[test]
    fn nth_allowed_cpu_regression_for_systemd_cpuaffinity_2_3_4_5() {
        let allowed_cpus = [2usize, 3, 4, 5];
        let is_set = mask_from(allowed_cpus);
        let mut buf = [0u16; 16];

        // Under the old code, `available_parallelism()` honours the
        // inherited mask and returns 4, so `worker_id % 4` maps to
        // absolute CPUs 0/1/2/3. The NEW code maps the same worker_ids
        // to allowed[0..3] = 2/3/4/5. The issue body verified this live
        // via /proc/<tid>/status:
        //
        //     xpf-userspace-w cpus_allowed=0   <-- old worker 0
        //     xpf-userspace-w cpus_allowed=1   <-- old worker 1
        //     xpf-userspace-w cpus_allowed=2   <-- old worker 2
        //     xpf-userspace-w cpus_allowed=3   <-- old worker 3
        //
        // Expected NEW behaviour: workers pin to cpus_allowed=2/3/4/5.
        for (worker_id, old_absolute_cpu, new_allowed_cpu) in [
            (0u32, 0usize, 2usize),
            (1, 1, 3),
            (2, 2, 4),
            (3, 3, 5),
        ] {
            // Reconstruct the old formula verbatim. Uses the allowed-set
            // *size* (what `available_parallelism()` returned under the
            // systemd mask), not the allowed-set members.
            let reconstructed_old = (worker_id as usize) % allowed_cpus.len();
            assert_eq!(
                reconstructed_old, old_absolute_cpu,
                "old formula reconstruction drifted",
            );

            let picked = nth_allowed_cpu(worker_id, &is_set, &mut buf)
                .expect("allowed mask is non-empty");
            assert_eq!(
                picked, new_allowed_cpu,
                "worker {worker_id} should pin to allowed CPU {new_allowed_cpu}, got {picked}",
            );
            assert!(
                allowed_cpus.contains(&picked),
                "picked CPU {picked} must be inside the systemd CPUAffinity={{2,3,4,5}} mask",
            );
        }

        // The core regression: for workers 0 and 1, the old absolute CPU
        // (0, 1) is strictly outside the systemd mask {2,3,4,5}, while
        // the new picks (2, 3) are strictly inside. This pair alone is
        // enough to refute any revert to `CPU_SET(worker_id % n)` — a
        // revert would pick 0/1 and fall outside the allowed set.
        let old_worker_0 = 0usize; // (0u32 as usize) % 4
        let old_worker_1 = 1usize; // (1u32 as usize) % 4
        assert!(!allowed_cpus.contains(&old_worker_0));
        assert!(!allowed_cpus.contains(&old_worker_1));
        let new_worker_0 =
            nth_allowed_cpu(0, &is_set, &mut buf).expect("allowed mask is non-empty");
        let new_worker_1 =
            nth_allowed_cpu(1, &is_set, &mut buf).expect("allowed mask is non-empty");
        assert!(allowed_cpus.contains(&new_worker_0));
        assert!(allowed_cpus.contains(&new_worker_1));
        assert_ne!(old_worker_0, new_worker_0);
        assert_ne!(old_worker_1, new_worker_1);
    }
}

#[cfg(test)]
mod probe_socket_tests {
    use super::{
        build_icmp4_echo, build_icmp6_echo, build_solicit_sockaddr_in6, select_probe_socket,
        ProbeSockKind,
    };
    use std::net::Ipv6Addr;
    use std::cell::RefCell;

    /// Base socket type with the `SOCK_CLOEXEC` (and any future flag) bits
    /// masked off — `SOCK_CLOEXEC` is OR'd into the type arg at creation.
    fn base_type(sock_type: libc::c_int) -> libc::c_int {
        sock_type & !libc::SOCK_CLOEXEC
    }

    /// The raw socket is the primary path: when raw creation succeeds the
    /// DGRAM fallback must NEVER be attempted. Also pins that
    /// `SOCK_CLOEXEC` is OR'd into the type arg (#2476 consistency: no fd
    /// leak into exec'd children).
    #[test]
    fn prefers_raw_and_never_tries_dgram_when_raw_succeeds() {
        let attempts = RefCell::new(Vec::new());
        let sel = select_probe_socket(|sock_type| {
            attempts.borrow_mut().push(sock_type);
            42 // pretend raw fd
        });
        assert_eq!(sel, Some((42, ProbeSockKind::Raw)));
        let attempts = attempts.borrow();
        assert_eq!(attempts.len(), 1, "DGRAM must not be attempted once raw succeeds");
        assert_eq!(base_type(attempts[0]), libc::SOCK_RAW);
        assert_ne!(
            attempts[0] & libc::SOCK_CLOEXEC,
            0,
            "raw probe socket must be created with SOCK_CLOEXEC",
        );
    }

    /// FAIL-ON-REVERT: this is the core of the #2482 fix. On raw-creation
    /// failure the selector MUST try `SOCK_DGRAM` and return the DGRAM fd.
    /// Pre-fix (master) `trigger_kernel_arp_probe` returned immediately on
    /// `fd < 0` with no fallback — there is no `select_probe_socket` and no
    /// DGRAM attempt, so this assertion (and the recorded
    /// `[SOCK_RAW, SOCK_DGRAM]` attempt order) cannot hold. Deleting the
    /// fallback arm regresses this test. Both attempts must carry
    /// `SOCK_CLOEXEC`.
    #[test]
    fn falls_back_to_dgram_when_raw_creation_fails() {
        let attempts = RefCell::new(Vec::new());
        let sel = select_probe_socket(|sock_type| {
            attempts.borrow_mut().push(sock_type);
            if base_type(sock_type) == libc::SOCK_RAW {
                -1 // EPERM/EACCES: no CAP_NET_RAW
            } else {
                7 // DGRAM ping socket fd
            }
        });
        assert_eq!(sel, Some((7, ProbeSockKind::Dgram)));
        let attempts = attempts.borrow();
        assert_eq!(attempts.len(), 2, "raw must be tried first, then DGRAM");
        assert_eq!(base_type(attempts[0]), libc::SOCK_RAW);
        assert_eq!(base_type(attempts[1]), libc::SOCK_DGRAM);
        for (i, t) in attempts.iter().enumerate() {
            assert_ne!(
                t & libc::SOCK_CLOEXEC,
                0,
                "probe socket attempt {i} must be created with SOCK_CLOEXEC",
            );
        }
    }

    /// Both creation attempts failing yields `None` (probe is skipped, as
    /// the pre-fix code did on raw failure).
    #[test]
    fn returns_none_when_both_socket_types_fail() {
        let attempts = RefCell::new(Vec::new());
        let sel = select_probe_socket(|sock_type| {
            attempts.borrow_mut().push(sock_type);
            -1
        });
        assert_eq!(sel, None);
        let attempts = attempts.borrow();
        assert_eq!(attempts.len(), 2);
        assert_eq!(base_type(attempts[0]), libc::SOCK_RAW);
        assert_eq!(base_type(attempts[1]), libc::SOCK_DGRAM);
    }

    /// The DGRAM send buffer is the ICMP message ONLY (8 bytes, no 20-byte
    /// IP header) with a valid Echo-Request type/code, and is byte-distinct
    /// from the raw buffer (raw carries the precomputed checksum; the DGRAM
    /// ping socket has the kernel recompute it, so checksum bytes are zero).
    /// Sending a raw-style buffer (leading IP header) through a DGRAM ping
    /// socket was the original EINVAL.
    #[test]
    fn dgram_v4_buffer_is_icmp_only_and_distinct_from_raw() {
        let raw = build_icmp4_echo(ProbeSockKind::Raw);
        let dgram = build_icmp4_echo(ProbeSockKind::Dgram);
        // ICMP-only: exactly 8 bytes, no IP header prepended.
        assert_eq!(dgram.len(), 8);
        // Echo Request type=8, code=0.
        assert_eq!(dgram[0], 8, "ICMP type must be Echo Request (8)");
        assert_eq!(dgram[1], 0, "ICMP code must be 0");
        // First byte is NOT an IPv4 version/IHL nibble (0x45) — proves no
        // IP header, the prior-EINVAL trap.
        assert_ne!(dgram[0], 0x45);
        // DGRAM leaves the checksum for the kernel; raw carries 0xf7ff.
        assert_eq!(&dgram[2..4], &[0, 0], "kernel recomputes csum for ping socket");
        assert_eq!(&raw[2..4], &[0xf7, 0xff], "raw must carry a valid csum");
        assert_ne!(raw, dgram, "DGRAM buffer must be distinct from raw");
    }

    /// ICMPv6 Echo Request is type=128, code=0; checksum is always kernel-
    /// computed so the body is the same for both kinds.
    #[test]
    fn v6_buffer_is_icmpv6_echo_request() {
        let raw = build_icmp6_echo(ProbeSockKind::Raw);
        let dgram = build_icmp6_echo(ProbeSockKind::Dgram);
        assert_eq!(dgram.len(), 8);
        assert_eq!(dgram[0], 128, "ICMPv6 type must be Echo Request (128)");
        assert_eq!(dgram[1], 0, "ICMPv6 code must be 0");
        assert_eq!(raw, dgram);
    }

    /// FAIL-ON-REVERT (#2969): the NDP-solicit `sockaddr_in6` MUST carry the
    /// egress ifindex in `sin6_scope_id` for a LINK-LOCAL target. Linux
    /// cannot route a link-local datagram with `sin6_scope_id == 0`, so the
    /// pre-fix code (which left scope_id at the `mem::zeroed()` default 0)
    /// silently dropped every link-local NDP solicit and blackholed IPv6
    /// forwarding to those next-hops. Reverting to `sin6_scope_id = 0`
    /// regresses this assertion.
    #[test]
    fn ndp_solicit_sockaddr_carries_ifindex_scope_for_link_local() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let ifindex = 7;
        let sa6 = build_solicit_sockaddr_in6(ll, ifindex);
        assert_eq!(sa6.sin6_family, libc::AF_INET6 as u16);
        assert_eq!(
            sa6.sin6_scope_id, ifindex as u32,
            "link-local NDP solicit must scope to the egress ifindex (#2969); \
             a zero scope_id makes the kernel drop the solicit",
        );
        assert_ne!(
            sa6.sin6_scope_id, 0,
            "sin6_scope_id reverted to 0 — link-local solicit would be dropped",
        );
        assert_eq!(sa6.sin6_addr.s6_addr, ll.octets());
    }

    /// The scope id is set uniformly (harmless for a global/ULA target the
    /// kernel ignores it for), so the builder does not have to special-case
    /// link-local detection — the contract is "scope_id == ifindex always".
    #[test]
    fn ndp_solicit_sockaddr_carries_ifindex_scope_for_global() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200);
        let ifindex = 12;
        let sa6 = build_solicit_sockaddr_in6(global, ifindex);
        assert_eq!(sa6.sin6_scope_id, ifindex as u32);
        assert_eq!(sa6.sin6_addr.s6_addr, global.octets());
    }

    /// A pathological negative ifindex clamps to 0 rather than wrapping into
    /// a huge scope id via an `as u32` sign-extension.
    #[test]
    fn ndp_solicit_sockaddr_clamps_negative_ifindex() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let sa6 = build_solicit_sockaddr_in6(ll, -1);
        assert_eq!(sa6.sin6_scope_id, 0, "negative ifindex must clamp to 0");
    }
}

#[cfg(test)]
mod warmer_tests {
    use super::*;
    use std::time::Duration;

    fn active_rg(rg_id: i32) -> Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>> {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            rg_id,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        )])))
    }

    fn warm_item(generation: u64, rg_id: i32) -> WarmItem {
        WarmItem {
            // Use an interface name that will not resolve so
            // trigger_kernel_arp_probe is a cheap no-op even without
            // CAP_NET_RAW; the observable effect we assert is the
            // last_probed_at insertion.
            ifindex: 999,
            hop: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            iface_name: "xpf-test-nodev".to_string(),
            generation,
            rg_id,
        }
    }

    fn spawn_loop(
        rx: Receiver<WarmItem>,
        last_probed: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
        warm_generation: Arc<AtomicU64>,
        rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            neighbor_warmer_loop(rx, last_probed, warm_generation, rg_runtime, stop)
        })
    }

    fn wait_for<F: Fn() -> bool>(pred: F) -> bool {
        for _ in 0..200 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn warmer_processes_message_and_records_probe() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(7));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        tx.try_send(warm_item(7, 0)).expect("send");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(
            wait_for(|| last_probed.lock().unwrap().contains_key(&key)),
            "warmer must record the probed key in last_probed_at",
        );
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_drops_stale_generation_items() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(10));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        // Item tagged with an OLD generation (current is 10).
        tx.try_send(warm_item(3, 0)).expect("send stale");
        // Then a current-gen item to act as a barrier we CAN observe.
        tx.try_send(warm_item(10, 0)).expect("send current");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(
            wait_for(|| last_probed.lock().unwrap().contains_key(&key)),
            "current-gen item must be processed",
        );
        // Exactly one insertion total (stale dropped, current recorded);
        // the per-key 5s rate-limit also coalesces, so len stays 1.
        assert_eq!(last_probed.lock().unwrap().len(), 1);
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_skips_inactive_rg_items() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(1));
        // RG runtime has RG 0 active, but the item targets RG 5 (absent).
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        tx.try_send(warm_item(1, 5)).expect("send inactive-rg");
        // Give the worker time to process and discard it.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            last_probed.lock().unwrap().is_empty(),
            "item for a non-forwarding-active RG must not be probed",
        );
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_exits_on_disconnect() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(0));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed, warm_generation, rg, stop);
        // Drop the sender WITHOUT setting stop: the recv_timeout must see
        // Disconnected and the loop must exit on its own.
        drop(tx);
        handle.join().expect("warmer must exit cleanly on channel disconnect");
    }

    #[test]
    fn warmer_per_key_rate_limit_coalesces() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(1));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        // Same key sent twice within the 5s window → one recorded probe.
        tx.try_send(warm_item(1, 0)).expect("send 1");
        tx.try_send(warm_item(1, 0)).expect("send 2");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(wait_for(|| last_probed.lock().unwrap().contains_key(&key)));
        // The recorded timestamp must not change on the second (rate-
        // limited) item — assert the map stays at one entry.
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(last_probed.lock().unwrap().len(), 1);
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }
}

#[cfg(test)]
mod monitor_lifecycle_tests_5165 {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    fn set_rcvtimeo(fd: i32, ms: i64) {
        let tv = libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    /// Push one RTM_NEWNEIGH datagram into the socketpair.
    ///
    /// #6621: this uses `write(2)`, NOT `send(2)`. On a CONNECTED
    /// `SOCK_DGRAM` socket the two are equivalent — POSIX defines
    /// `write` as `send` with `flags == 0`, and a socketpair is
    /// connected by construction — but `libc::send` compiles to the
    /// `sendto` syscall, and a seccomp network-egress filter can deny
    /// `sendto` (`EPERM`) while leaving `write` and `recvfrom`
    /// permitted on that same socket. Measured in the sandbox that
    /// reported #6621: `socketpair` ok, `send` -> `-1 EPERM`,
    /// `write` -> 48 bytes delivered, `recv` -> 48 bytes read. Under
    /// `send` this helper's assert therefore fired with an opaque
    /// `n == -1` before the loop under test ever saw a byte — a
    /// permanently-red test that said nothing about the dataplane.
    /// Do NOT switch this back to `send`.
    fn write_newneigh(fd: i32, ifindex: i32, ip: IpAddr, mac: [u8; 6]) {
        let buf = build_newneigh_request(ifindex, ip, mac, NUD_REACHABLE);
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        assert_eq!(
            n,
            buf.len() as isize,
            "socketpair write must deliver the whole RTM_NEWNEIGH datagram \
             (errno: {})",
            io::Error::last_os_error(),
        );
    }

    /// #5165 FAIL-ON-REVERT (post-recv re-check): the steady-state monitor loop
    /// applies a kernel neighbor event received BEFORE stop, but MUST NOT apply
    /// one received AFTER stop is signalled — a retired old-generation consumer
    /// may not mutate a map that teardown is about to clear / a fresh baseline
    /// is about to repopulate. Driven over an AF_UNIX SOCK_DGRAM socketpair so
    /// the loop runs deterministically with no real AF_NETLINK socket.
    ///
    /// Sequencing makes the post-recv re-check the gate under test: event 1 is
    /// applied and confirmed, then a 30ms settle guarantees the loop is BLOCKED
    /// in recv() (past its top-of-loop stop check); only THEN is stop set and
    /// event 2 injected to unblock recv(). Reverting the post-recv
    /// `if stop { break }` makes the loop apply event 2 -> `key2` appears -> RED.
    ///
    /// #6621: that sequencing is only a real gate if the loop actually RECEIVES
    /// event 2, so the run is now self-verifying — a long harness recv timeout
    /// keeps the loop parked in recv() across the stop, and a post-join drain
    /// asserts the datagram was consumed rather than left queued.
    #[test]
    fn steady_state_drops_batch_received_after_stop_5165() {
        let mut fds = [0i32; 2];
        let rc =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        let (write_fd, read_fd) = (fds[0], fds[1]);
        // #6621: a LONG harness receive timeout, deliberately not the
        // production 500ms. The sequence below signals stop while the loop is
        // BLOCKED in recv() so the POST-recv re-check is the gate under test.
        // If the timeout could expire in that window the loop would instead
        // exit on its TOP-of-loop check, never receive event 2, and the `key2`
        // assertion would hold VACUOUSLY — green while proving nothing. 10s is
        // far longer than the 30ms settle and costs nothing at runtime: the
        // loop returns the moment event 2 unblocks recv (or, on a revert,
        // immediately after applying it).
        set_rcvtimeo(read_fd, 10_000);

        let map = Arc::new(ShardedNeighborMap::new());
        let generation = Arc::new(AtomicU64::new(1));
        let counters = Arc::new(super::super::neighbor_resolver::ResolverCounters::default());
        let stop = Arc::new(AtomicBool::new(false));

        let handle = {
            let (m, g, c, s) = (map.clone(), generation.clone(), counters.clone(), stop.clone());
            std::thread::spawn(move || neigh_monitor_steady_state(read_fd, &s, &m, &g, &c))
        };

        let if1 = 101;
        let ip1 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let key1 = (if1, ip1);
        write_newneigh(write_fd, if1, ip1, [0x02, 0, 0, 0, 0, 1]);

        let mut applied = false;
        for _ in 0..400 {
            if map.get(&key1).is_some() {
                applied = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(applied, "steady-state loop must apply a pre-stop RTM_NEWNEIGH");

        // The loop has processed event 1, looped back, and is now blocked in
        // recv() on the empty socket. Signal stop while it is blocked so the
        // post-recv re-check (not the top-of-loop check) governs event 2.
        std::thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Relaxed);

        let if2 = 202;
        let ip2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        let key2 = (if2, ip2);
        write_newneigh(write_fd, if2, ip2, [0x02, 0, 0, 0, 0, 2]);

        // The loop's recv() returns event 2, the post-recv re-check observes
        // stop, and it breaks WITHOUT applying it. join() returns once broken.
        handle.join().expect("monitor steady-state join");

        // #6621: PROVE the loop consumed event 2 before asserting on it. A
        // recv() dequeues the datagram, so a loop that reached the post-recv
        // re-check leaves the socket EMPTY (EAGAIN). A loop that exited on the
        // top-of-loop check instead never read it, and the datagram is still
        // queued — in which case `key2` being absent says nothing about the
        // re-check and this run must NOT be reported as a pass.
        let mut drained = [0u8; 128];
        // EINTR is a legitimate recv() outcome and says nothing about whether
        // the queue is empty, so retry it rather than reporting it as a
        // failure. Bounded so a pathological signal storm cannot spin here.
        let (leftover, drain_errno) = {
            let mut last = (0isize, None);
            for _ in 0..16 {
                let n = unsafe {
                    libc::recv(
                        read_fd,
                        drained.as_mut_ptr() as *mut libc::c_void,
                        drained.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                let e = std::io::Error::last_os_error().raw_os_error();
                last = (n, e);
                if !(n < 0 && e == Some(libc::EINTR)) {
                    break;
                }
            }
            last
        };
        // `leftover < 0` alone would accept ANY error as "drained" — an EBADF
        // from a future refactor would read as success. Only EAGAIN means the
        // queue is genuinely empty. (EWOULDBLOCK is not matched separately:
        // Linux defines it as the same value as EAGAIN, so a second arm is an
        // unreachable pattern; this file is Linux-only.)
        assert!(
            leftover < 0,
            "the post-stop batch must have been RECEIVED by the loop, but \
             {leftover} bytes are still queued — the loop exited on its \
             top-of-loop check, so the post-recv re-check was never exercised",
        );
        assert!(
            drain_errno == Some(libc::EAGAIN),
            "drain recv failed with errno {drain_errno:?}, not EAGAIN. The queue \
             being empty is the ONLY acceptable reason this returns <0; any other \
             error means the fd is unusable and this assertion would otherwise \
             have passed for the wrong reason",
        );

        assert!(
            map.get(&key2).is_none(),
            "a batch received AFTER stop must NOT mutate the map (post-recv re-check)",
        );
        assert!(
            map.get(&key1).is_some(),
            "the pre-stop entry must remain",
        );

        // Both ends are ours and the loop is joined, so close both — the
        // read end used to leak for the lifetime of the test binary.
        unsafe {
            libc::close(write_fd);
            libc::close(read_fd);
        }
    }

    /// #5165: the steady-state loop honors stop and returns promptly so it can
    /// be joined (bounded by the 500ms SO_RCVTIMEO). With no events pending it
    /// exits within the timeout window once stop is set — the property that
    /// makes `stop_inner`'s JOIN latency bounded.
    #[test]
    fn steady_state_exits_on_stop_when_idle_5165() {
        let mut fds = [0i32; 2];
        let rc =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        let (write_fd, read_fd) = (fds[0], fds[1]);
        set_rcvtimeo(read_fd, 500);

        let map = Arc::new(ShardedNeighborMap::new());
        let generation = Arc::new(AtomicU64::new(1));
        let counters = Arc::new(super::super::neighbor_resolver::ResolverCounters::default());
        let stop = Arc::new(AtomicBool::new(false));

        let handle = {
            let (m, g, c, s) = (map.clone(), generation.clone(), counters.clone(), stop.clone());
            std::thread::spawn(move || neigh_monitor_steady_state(read_fd, &s, &m, &g, &c))
        };

        // Idle (no events); set stop and confirm the loop exits within a couple
        // of recv-timeout windows.
        std::thread::sleep(Duration::from_millis(20));
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("idle monitor must exit on stop");

        unsafe {
            libc::close(write_fd);
            libc::close(read_fd);
        }
    }
}
#[cfg(test)]
mod noarp_listener_10690_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn newneigh_body(ifindex: i32, ip: Ipv4Addr, mac: [u8; 6], state: u16) -> Vec<u8> {
        let mut body = vec![0u8; 12];
        body[0] = libc::AF_INET as u8;
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        body[8..10].copy_from_slice(&state.to_ne_bytes());

        body.extend_from_slice(&8u16.to_ne_bytes());
        body.extend_from_slice(&1u16.to_ne_bytes());
        body.extend_from_slice(&ip.octets());
        body.extend_from_slice(&10u16.to_ne_bytes());
        body.extend_from_slice(&2u16.to_ne_bytes());
        body.extend_from_slice(&mac);
        body.extend_from_slice(&[0u8; 2]);
        body
    }

    #[test]
    fn noarp_neighbor_event_never_becomes_a_resolved_neighbor_10690() {
        const NUD_REACHABLE: u16 = 0x02;
        const NUD_NOARP: u16 = 0x40;
        let ip = Ipv4Addr::new(10, 0, 61, 255);
        for state in [NUD_NOARP, NUD_NOARP | NUD_REACHABLE] {
            for had_prior_row in [false, true] {
                let neighbors = Arc::new(ShardedNeighborMap::new());
                let key = (7, IpAddr::V4(ip));
                if had_prior_row {
                    neighbors.insert_if_changed(
                        key,
                        NeighborEntry {
                            mac: [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
                        },
                    );
                }
                let effect = parse_neighbor_msg(
                    28,
                    &newneigh_body(7, ip, [0xff; 6], state),
                    &neighbors,
                );
                assert_eq!(
                    effect,
                    if had_prior_row {
                        NeighborMsgEffect::Removed
                    } else {
                        NeighborMsgEffect::None
                    },
                    "NOARP must remove, not install, the neighbor row"
                );
                assert!(
                    neighbors.get(&key).is_none(),
                    "NOARP row must not survive in dynamic resolution"
                );
            }
        }
    }
}
