//! #1769 immediate stuck-state fix: shared, per-key, rate-limited
//! on-demand neighbor resolver.
//!
//! ## The bug this closes
//!
//! The `MissingNeighbor` negative-cache gate
//! (`poll_descriptor/mod.rs`) fast-fails new SYNs to a dst whose
//! `(egress_ifindex, next_hop)` is negatively cached, BEFORE the ARP
//! probe and BEFORE the `pending_neigh` buffer. Once `dynamic_neighbors`
//! loses a directly-connected target (a transient FAILED/DELNEIGH, or a
//! dropped good RTM_NEWNEIGH — the monitor swallows `recv()<=0` and only
//! full-dumps at startup) and the 3 s negative entry arms, that dst is
//! never re-probed or re-buffered. The kernel's valid DELAY/STALE
//! lladdr is unusable because the hot path refuses an on-demand kernel
//! read (`forwarding/mod.rs::lookup_neighbor_entry`). Result: repeated
//! 3 s connect blackouts until the kernel independently re-validates and
//! emits a fresh RTM_NEWNEIGH.
//!
//! ## What this does (converged plan §9)
//!
//! On a negative-cache fast-fail the worker enqueues the dst into ONE
//! shared resolver (the `neg_neigh_cache` is per-binding across 6 WAN
//! workers, so a per-binding GET would be 6× rtnl — this routes every
//! worker's misses through a single thread). The resolver:
//!
//! 1. Rate-limits per `(ifindex, hop)` key — coalesces a SYN storm down
//!    to one in-flight GET/probe per key per window (no probe storm).
//! 2. Issues a single-key `RTM_GETNEIGH` (`NLM_F_REQUEST` + `NDA_DST`,
//!    NO dump flags) — a direct lookup, NOT the RTNL-mutex dump path.
//! 3. Caches the lladdr into `dynamic_neighbors` ONLY if the GET returns
//!    `REACHABLE`/`PERMANENT` AND the global neighbor epoch has not
//!    advanced since the request was issued (epoch guard — defeats the
//!    out-of-order race where a concurrent monitor FAILED/DELNEIGH
//!    removal would otherwise be clobbered by our late stale insert).
//! 4. On `STALE`/`DELAY`/`PROBE` with an lladdr (the LIVE #1769 wedge
//!    state) it does NOT cache the unconfirmed MAC — it fires
//!    `trigger_kernel_arp_probe` to force kernel revalidation and lets
//!    the resulting confirmed multicast RTM_NEWNEIGH populate the map.
//! 5. On an AUTHORITATIVE `FAILED`/`INCOMPLETE` it caches nothing and
//!    revokes any existing dynamic entry — immediate-revocation firewall
//!    posture (AGY F3); recovery comes from the probe + the next
//!    CONFIRMED event, never from forwarding-grace. On a NON-authoritative
//!    no-reply (GET timeout / error / no match) it probes ONLY and does
//!    NOT revoke — a transient GET loss must not evict a still-good entry
//!    the monitor may have just (re)populated.
//!
//! The hot path only pays a non-blocking `try_send` on the negative
//! fast-fail (not per-packet) plus a depth bump; all netlink I/O is off
//! the worker thread on a persistent, reused socket.

use super::*;

/// One on-demand resolve request. `epoch` is the global
/// `neighbor_generation` snapshot captured at enqueue; the resolver
/// re-reads it after the GET and only caches a confirmed lladdr if it is
/// unchanged (epoch guard).
#[derive(Clone, Debug)]
pub(crate) struct ResolveItem {
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) hop: IpAddr,
    pub(in crate::afxdp) iface_name: String,
    pub(in crate::afxdp) epoch: u64,
}

/// Bounded resolver queue depth. The resolver coalesces per-key so the
/// queue holds at most a handful of distinct unresolved next-hops in
/// practice; a wide cap absorbs a multi-worker storm burst without
/// dropping enqueues. On overflow the new item is dropped and
/// `enqueue_drops` is incremented (the dst still fast-fails — no
/// availability regression, just no on-demand nudge this round).
pub(in crate::afxdp) const RESOLVER_QUEUE_DEPTH: usize = 4096;

/// Per-key rate-limit window: skip re-resolving the same `(ifindex,
/// hop)` within this window. Bounds rtnl GET traffic and probe storms
/// for a dst under sustained SYN retransmit. 1 s is well under the 3 s
/// negative-cache TTL so a genuinely recovering host is re-probed within
/// one negative window, but a dead-host storm fires at most one GET/s.
pub(in crate::afxdp) const RESOLVER_PER_KEY_RATE_LIMIT_NS: u64 = 1_000_000_000;

// #1771 §2.4 invariant N1 prerequisite, pinned at compile time: at least
// one per-key backoff window must elapse INSIDE the worker-side negative
// cache TTL. If the rate-limit window ever grew past the TTL, no GET
// could fire while a key is negatively cached and the resolver could not
// un-wedge a fast-failing dst (the exact #1769 blackout this thread
// exists to prevent).
const _: () = assert!(NEG_NEIGH_TTL_NS > RESOLVER_PER_KEY_RATE_LIMIT_NS);

/// `last_resolved_at` GC cadence + max entry age (mirrors the warmer's
/// GC). Prunes keys not seen within `RESOLVER_GC_MAX_AGE_NS` every
/// `RESOLVER_GC_INTERVAL_NS` so the per-key map cannot grow unbounded
/// under a wide scan.
pub(in crate::afxdp) const RESOLVER_GC_INTERVAL_NS: u64 = 60_000_000_000;
pub(in crate::afxdp) const RESOLVER_GC_MAX_AGE_NS: u64 = 300_000_000_000;

/// Per-binding worker-side enqueue throttle: skip cloning the egress
/// iface name + `try_send`ing the same `(ifindex, hop)` into the shared
/// resolver more than once per this window on the negative fast-fail.
/// The resolver coalesces per-key at 1 s anyway; this just keeps a
/// dead-host SYN storm from `String::clone()`-ing per fast-failed packet
/// (the hot-path-allocation concern). 100 ms is far below the resolver's
/// 1 s per-key window and the 3 s negative-cache TTL, so a genuinely
/// recovering host is still nudged promptly.
pub(in crate::afxdp) const RESOLVER_ENQUEUE_THROTTLE_NS: u64 = 100_000_000;

/// Short receive timeout for the single-key GET reply (ms). The kernel
/// answers a unicast RTM_GETNEIGH essentially immediately; this only
/// bounds the wait if the reply is lost so the resolver thread stays
/// responsive to the stop flag and the next queued item.
const RESOLVER_RECV_TIMEOUT_MS: i64 = 200;

/// Shared resolver counters. All `AtomicU64` (monotonic counters) except
/// `queue_depth` which is a live `AtomicI64` gauge (enqueue +1, dequeue
/// -1). Surfaced to Prometheus via the coordinator status path.
#[derive(Default)]
pub(crate) struct ResolverCounters {
    /// Live count of items queued but not yet processed (gauge).
    pub(crate) queue_depth: AtomicI64,
    /// Items dropped because the bounded queue was full (transient).
    pub(crate) enqueue_drops: AtomicU64,
    /// Items dropped because the resolver worker died (fatal — on-demand
    /// resolution disabled until daemon restart).
    pub(crate) disconnected: AtomicU64,
    /// Single-key RTM_GETNEIGH requests actually issued (after the
    /// per-key rate-limit coalesces a storm).
    pub(crate) get_attempts: AtomicU64,
    /// GET replies that confirmed REACHABLE/PERMANENT and were cached
    /// into `dynamic_neighbors` (epoch guard passed).
    pub(crate) get_resolved: AtomicU64,
    /// GET replies in STALE/DELAY/PROBE that triggered a revalidation
    /// probe instead of caching the unconfirmed MAC.
    pub(crate) probe_on_stale: AtomicU64,
    /// GET attempts that returned no usable reply (timeout, FAILED,
    /// INCOMPLETE, parse error, or recv error).
    pub(crate) get_failures: AtomicU64,
    /// Confirmed inserts skipped because the global neighbor epoch
    /// advanced between enqueue and the GET reply (epoch guard rejected
    /// a potentially-raced stale insert).
    pub(crate) epoch_rejects: AtomicU64,
    /// #1771 §2.6: subset of `get_attempts` that were backoff RETRIES —
    /// a GET admitted for a key the resolver had already attempted
    /// within its per-key memory (`last_resolved`, GC'd after
    /// `RESOLVER_GC_MAX_AGE_NS`). A rising rate means the same next-hops
    /// keep failing to resolve and the resolver is cycling its
    /// once-per-`RESOLVER_PER_KEY_RATE_LIMIT_NS` backoff on them.
    pub(crate) get_backoff_attempts: AtomicU64,
    /// #1771 §2.5/§2.6: ENOBUFS receives on the neighbor-monitor netlink
    /// socket — the kernel dropped RTM_{NEW,DEL}NEIGH multicast
    /// notifications on rcvbuf overflow (the lost-NEWNEIGH desync class
    /// the throttled re-dump self-heals). Counted on the MONITOR thread;
    /// lives here so it rides the existing ResolverCounters →
    /// NeighborResolverCounters → status wire path.
    pub(crate) netlink_enobufs: AtomicU64,
    /// #1771 §2.5/§2.6: throttle-admitted upsert-only family re-dumps
    /// actually issued after an ENOBUFS (at least one of the v4/v6
    /// RTM_GETNEIGH dump requests was sent successfully).
    pub(crate) netlink_redumps: AtomicU64,
    /// #1771 §2.5/§2.6: dynamic-neighbor entries (re)added by an
    /// upsert-only re-dump reply — RTM_NEWNEIGH dump replies (matched by
    /// nlmsg_seq) whose insert CHANGED the map. Nonzero proves a re-dump
    /// repopulated keys the dropped multicast events had desynced.
    pub(crate) netlink_redump_upserts: AtomicU64,
}

/// Plain snapshot of [`ResolverCounters`] for the status path (all
/// `u64`, queue depth clamped to >= 0). Carried out to `server/helpers`
/// → `protocol/control` → the Go Prometheus collector.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NeighborResolverCounters {
    pub(crate) queue_depth: u64,
    pub(crate) enqueue_drops: u64,
    pub(crate) disconnected: u64,
    pub(crate) get_attempts: u64,
    pub(crate) get_resolved: u64,
    pub(crate) probe_on_stale: u64,
    pub(crate) get_failures: u64,
    pub(crate) epoch_rejects: u64,
    pub(crate) get_backoff_attempts: u64,
    pub(crate) netlink_enobufs: u64,
    pub(crate) netlink_redumps: u64,
    pub(crate) netlink_redump_upserts: u64,
}

/// Handle held by the coordinator and cloned (as the producer + counter
/// `Arc`s) into each worker. The worker only ever calls [`Self::enqueue`]
/// on the negative fast-fail; all netlink I/O runs on the resolver thread.
pub(crate) struct NeighborResolver {
    /// Producer into the resolver thread's bounded queue.
    tx: SyncSender<ResolveItem>,
    pub(crate) counters: Arc<ResolverCounters>,
    /// Global neighbor epoch, snapshotted into each enqueued item so the
    /// resolver thread can detect a concurrent monitor event (epoch
    /// guard).
    neighbor_generation: Arc<AtomicU64>,
    // #1772: latency telemetry carried on the worker-facing handle so
    // `retry_pending_neigh` can record dwell + the timeout-drop / max-
    // depth counters without growing its already-wide parameter list.
    /// pending_neigh dwell-time histogram (shared aggregate).
    pub(crate) pending_dwell_hist: Arc<super::neighbor_latency::NeighborLatencyHist>,
    /// pending_neigh packets dropped after PENDING_NEIGH_TIMEOUT.
    pub(crate) pending_timeout_drops: Arc<AtomicU64>,
    /// High-water mark of `pending_neigh.len()` at retry-sweep entry.
    pub(crate) pending_max_depth: Arc<AtomicU64>,
}

impl NeighborResolver {
    pub(crate) fn new(
        tx: SyncSender<ResolveItem>,
        counters: Arc<ResolverCounters>,
        neighbor_generation: Arc<AtomicU64>,
        pending_dwell_hist: Arc<super::neighbor_latency::NeighborLatencyHist>,
        pending_timeout_drops: Arc<AtomicU64>,
        pending_max_depth: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx,
            counters,
            neighbor_generation,
            pending_dwell_hist,
            pending_timeout_drops,
            pending_max_depth,
        }
    }

    /// #1772: record a pending-neigh dwell observation (rare; off the
    /// per-packet fast path).
    #[inline]
    pub(crate) fn record_pending_dwell(&self, dwell_ns: u64) {
        self.pending_dwell_hist.record(dwell_ns);
    }

    /// #1772: count a pending-neigh timeout-drop.
    #[inline]
    pub(crate) fn record_pending_timeout_drop(&self) {
        self.pending_timeout_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// #1772: update the pending-neigh queue-depth high-water mark with a
    /// monotonic max. Cheap relaxed CAS loop; only loops under a true new
    /// maximum, which is rare.
    #[inline]
    pub(crate) fn observe_pending_depth(&self, depth: u64) {
        let mut cur = self.pending_max_depth.load(Ordering::Relaxed);
        while depth > cur {
            match self.pending_max_depth.compare_exchange_weak(
                cur,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Non-blocking enqueue from the worker hot path for `(ifindex, hop)`
    /// on egress interface `iface_name`. Snapshots the neighbor epoch so
    /// the resolver can guard against a concurrent monitor removal.
    /// Increments the depth gauge on success; on a full queue increments
    /// `enqueue_drops` (the dst still fast-fails this round, so
    /// availability is not affected — it just misses one on-demand
    /// nudge); on a dead worker increments `disconnected`. Never blocks.
    pub(crate) fn enqueue(&self, ifindex: i32, hop: IpAddr, iface_name: String) {
        let item = ResolveItem {
            ifindex,
            hop,
            iface_name,
            epoch: self.neighbor_generation.load(Ordering::Acquire),
        };
        // Increment the depth gauge BEFORE the send so the consumer's
        // post-dequeue decrement can never observe a not-yet-incremented
        // gauge and drive it transiently negative (the gauge-drift
        // finding). On send failure, undo the increment.
        self.counters.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(item) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.counters.enqueue_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.counters.disconnected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Open a persistent NETLINK_ROUTE socket for single-key GETNEIGH
/// queries with a short receive timeout. Reused across every query (no
/// per-query open/close — AGY F4). Returns -1 on failure.
fn open_resolver_socket() -> c_int {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return -1;
    }
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    // No group subscription: this socket only issues unicast GET
    // requests and reads their direct replies. It does NOT join
    // RTMGRP_NEIGH (that is the monitor's job).
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return -1;
    }
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: (RESOLVER_RECV_TIMEOUT_MS * 1000) as libc::suseconds_t,
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
    fd
}

/// Send a single-key `RTM_GETNEIGH` for `(ifindex, target)`. This is a
/// direct unicast lookup (`NLM_F_REQUEST` only + `NDA_DST` + ifindex in
/// the ndmsg) — explicitly NOT the dump path
/// (`NLM_F_ROOT|NLM_F_MATCH`), so it does not take the RTNL dump mutex
/// and cannot starve the Go coordinator's netlink ops (AGY F2).
fn send_get_neigh(fd: c_int, ifindex: i32, target: IpAddr, seq: u32) -> io::Result<()> {
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 0x1;
    const NDA_DST: u16 = 1;
    let (family, ip_bytes): (u8, Vec<u8>) = match target {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };
    let ip_attr_len = 4 + ip_bytes.len();
    let ip_attr_padded = (ip_attr_len + 3) & !3;
    // ndmsg: family(1)+pad1(1)+pad2(2)+ifindex(4)+state(2)+flags(1)+type(1) = 12
    let ndmsg_len = 12usize;
    let total_len = 16 + ndmsg_len + ip_attr_padded;
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
    // ndmsg
    buf[16] = family;
    buf[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    // NDA_DST attribute
    let off = 16 + ndmsg_len;
    buf[off..off + 2].copy_from_slice(&(ip_attr_len as u16).to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
    buf[off + 4..off + 4 + ip_bytes.len()].copy_from_slice(&ip_bytes);
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

/// Outcome of parsing the GET reply for a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum GetOutcome {
    /// Kernel confirmed REACHABLE/PERMANENT with this lladdr — safe to
    /// cache under the epoch guard.
    Confirmed([u8; 6]),
    /// Kernel has a candidate lladdr but it is STALE/DELAY/PROBE — do
    /// NOT cache; fire a revalidation probe.
    Unconfirmed,
    /// The kernel AUTHORITATIVELY reports the neighbor unusable
    /// (NUD_FAILED / NUD_INCOMPLETE) — revoke any existing dynamic entry
    /// (immediate-revocation firewall posture) and probe.
    Failed,
    /// No authoritative answer: GET timed out, recv error, NLMSG_ERROR,
    /// NLMSG_DONE, or no matching reply. Do NOT revoke — a transient GET
    /// loss must not evict a still-good entry the monitor may have just
    /// (re)populated (Copilot). Probe only.
    NoReply,
}

/// Classify a single NUD state + optional lladdr into a [`GetOutcome`].
/// Pure helper — unit-tested in isolation. REACHABLE/PERMANENT with a
/// MAC is the only confirmed-cache outcome; FAILED/INCOMPLETE is the only
/// authoritative-revoke outcome; everything else is NoReply (probe, no
/// revoke).
pub(in crate::afxdp) fn classify_nud(state: u16, mac: Option<[u8; 6]>) -> GetOutcome {
    const NUD_INCOMPLETE: u16 = 0x01;
    const NUD_REACHABLE: u16 = 0x02;
    const NUD_STALE: u16 = 0x04;
    const NUD_DELAY: u16 = 0x08;
    const NUD_PROBE: u16 = 0x10;
    const NUD_FAILED: u16 = 0x20;
    const NUD_PERMANENT: u16 = 0x80;
    match mac {
        Some(mac) if (state & (NUD_REACHABLE | NUD_PERMANENT)) != 0 => GetOutcome::Confirmed(mac),
        Some(_) if (state & (NUD_STALE | NUD_DELAY | NUD_PROBE)) != 0 => GetOutcome::Unconfirmed,
        // Kernel authoritatively says the neighbor is dead → revoke.
        _ if (state & (NUD_FAILED | NUD_INCOMPLETE)) != 0 => GetOutcome::Failed,
        // A reply with no usable lladdr and not an explicit FAILED state
        // (e.g. REACHABLE-without-lladdr, which should not happen) — treat
        // as no authoritative answer rather than revoking a good entry.
        _ => GetOutcome::NoReply,
    }
}

/// Read and parse the kernel's reply to our single-key GETNEIGH. Walks
/// netlink messages matching `seq`, finds the RTM_NEWNEIGH (28) for our
/// key, and returns the classified outcome. NLMSG_ERROR / NLMSG_DONE /
/// no-match / recv error all map to `NoReply` (probe, do NOT revoke — a
/// transient GET loss must not evict a still-good entry); only an
/// explicit kernel FAILED/INCOMPLETE in the parsed body returns `Failed`.
fn read_get_reply(fd: c_int, want_ifindex: i32, want_ip: IpAddr, seq: u32) -> GetOutcome {
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    let mut buf = vec![0u8; 8192];
    // The kernel answers a unicast GET with a single message in
    // practice; loop a bounded number of recvs to skip any interleaved
    // unrelated frame and to tolerate one short read.
    for _ in 0..4 {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return GetOutcome::NoReply;
        }
        let mut offset = 0usize;
        while offset + 16 <= n as usize {
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
            if nlmsg_len < 16 || offset + nlmsg_len > n as usize {
                break;
            }
            if nlmsg_seq == seq {
                match nlmsg_type {
                    // ENOENT et al.: ambiguous, do not revoke a possibly
                    // good entry — probe only.
                    NLMSG_ERROR => return GetOutcome::NoReply,
                    NLMSG_DONE => return GetOutcome::NoReply,
                    28 => {
                        if let Some(outcome) = parse_get_reply_body(
                            &buf[offset + 16..offset + nlmsg_len],
                            want_ifindex,
                            want_ip,
                        ) {
                            return outcome;
                        }
                    }
                    _ => {}
                }
            }
            offset += (nlmsg_len + 3) & !3;
        }
    }
    // No matching reply within the bounded recv attempts → no authoritative
    // answer; probe, do not revoke.
    GetOutcome::NoReply
}

/// Parse one RTM_NEWNEIGH body, confirm it matches the requested
/// `(ifindex, ip)`, and classify its NUD state. Returns `None` if the
/// body does not match our key (so the caller keeps scanning).
pub(in crate::afxdp) fn parse_get_reply_body(
    body: &[u8],
    want_ifindex: i32,
    want_ip: IpAddr,
) -> Option<GetOutcome> {
    if body.len() < 12 {
        return None;
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
    // Only accept a reply for the exact key we asked about.
    if ifindex != want_ifindex || ip != Some(want_ip) {
        return None;
    }
    Some(classify_nud(state, mac))
}

/// What the resolver should do with a GET outcome, given the epoch
/// guard. Pure decision so the race + outcome→action mapping is
/// deterministically testable without a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ResolveAction {
    /// REACHABLE/PERMANENT + epoch unchanged → cache this MAC.
    Cache([u8; 6]),
    /// Confirmed lladdr but the epoch advanced since enqueue → a monitor
    /// event raced in; back off rather than clobber the authoritative
    /// removal (AGY F1).
    EpochReject,
    /// STALE/DELAY/PROBE lladdr → probe to force kernel revalidation; do
    /// not cache the unconfirmed MAC.
    ProbeOnStale,
    /// Kernel AUTHORITATIVELY reports FAILED/INCOMPLETE → revoke any stale
    /// entry + probe (immediate-revocation firewall posture).
    RevokeAndProbe,
    /// No authoritative answer (GET timeout / error / no match) → probe
    /// only. Must NOT revoke: a transient GET loss could otherwise evict a
    /// still-good entry the monitor just (re)populated (Copilot).
    ProbeOnly,
}

/// Map a GET outcome + the before/after neighbor epoch to a
/// [`ResolveAction`]. The epoch guard applies ONLY to the
/// confirmed-cache path: a concurrent monitor event (which bumps the
/// epoch) means a FAILED/DELNEIGH may have just removed the key, so a
/// late confirmed insert could resurrect a stale MAC — reject it. Probe
/// and revoke paths are epoch-independent (they never write a MAC).
pub(in crate::afxdp) fn decide_action(
    outcome: GetOutcome,
    epoch_before: u64,
    epoch_after: u64,
) -> ResolveAction {
    match outcome {
        GetOutcome::Confirmed(mac) => {
            if epoch_after == epoch_before {
                ResolveAction::Cache(mac)
            } else {
                ResolveAction::EpochReject
            }
        }
        GetOutcome::Unconfirmed => ResolveAction::ProbeOnStale,
        GetOutcome::Failed => ResolveAction::RevokeAndProbe,
        GetOutcome::NoReply => ResolveAction::ProbeOnly,
    }
}

/// Outcome of the per-key rate-limit decision. Split (#1771 §2.6) so
/// the resolver loop can count backoff RETRIES (`AdmitRetry`) for the
/// `resolver_get_backoff_attempts` counter without changing the
/// admit/coalesce behavior of the original boolean helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum RateLimitDecision {
    /// First attempt for this key within the resolver's per-key memory
    /// (no `last_resolved` entry) → admit one GET.
    AdmitFirst,
    /// The key was attempted before and the
    /// `RESOLVER_PER_KEY_RATE_LIMIT_NS` window has lapsed → admit one
    /// GET; this is a backoff retry for a still-recurring key.
    AdmitRetry,
    /// Within the window → coalesce (no GET, no probe storm).
    Coalesce,
}

/// Per-key rate-limit decision. Admitting (`AdmitFirst`/`AdmitRetry`)
/// records `now_ns` for the key; `Coalesce` leaves the map untouched.
/// Pure helper over the caller's `last_resolved` map.
pub(in crate::afxdp) fn rate_limit_decide(
    last_resolved: &mut FastMap<(i32, IpAddr), u64>,
    key: (i32, IpAddr),
    now_ns: u64,
) -> RateLimitDecision {
    match last_resolved.get(&key) {
        Some(&t) if now_ns.saturating_sub(t) < RESOLVER_PER_KEY_RATE_LIMIT_NS => {
            RateLimitDecision::Coalesce
        }
        Some(_) => {
            last_resolved.insert(key, now_ns);
            RateLimitDecision::AdmitRetry
        }
        None => {
            last_resolved.insert(key, now_ns);
            RateLimitDecision::AdmitFirst
        }
    }
}

/// The long-lived resolver worker loop. Spawned once at coordinator
/// bring-up. Holds one persistent netlink socket. For each dequeued
/// item it rate-limits per key, issues a single-key GET, and either
/// caches a confirmed lladdr (epoch-guarded), probes on an unconfirmed
/// lladdr, or revokes on an unusable reply.
pub(super) fn neighbor_resolver_loop(
    rx: Receiver<ResolveItem>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    neighbor_generation: Arc<AtomicU64>,
    counters: Arc<ResolverCounters>,
    // #1772: single-key RTM_GETNEIGH round-trip-time histogram (request
    // sent → reply read), recorded on this resolver thread.
    get_rtt_hist: Arc<super::neighbor_latency::NeighborLatencyHist>,
    stop: Arc<AtomicBool>,
) {
    let fd = open_resolver_socket();
    if fd < 0 {
        eprintln!("xpf-userspace-dp: neighbor resolver: netlink socket open failed; exiting");
        // Keep the gauge at its steady state for a dead resolver so it
        // does not stick non-zero if a worker enqueued before the socket
        // open failed (Copilot).
        counters.queue_depth.store(0, Ordering::Relaxed);
        return;
    }
    let mut last_resolved: FastMap<(i32, IpAddr), u64> = FastMap::default();
    let mut seq: u32 = 1;
    let mut last_gc_ns = monotonic_nanos();
    while !stop.load(Ordering::Relaxed) {
        // GC the per-key rate-limit map at the top of every iteration so
        // the prune is not bypassed under continuous load.
        let now = monotonic_nanos();
        if now.saturating_sub(last_gc_ns) >= RESOLVER_GC_INTERVAL_NS {
            last_resolved.retain(|_k, &mut t| now.saturating_sub(t) < RESOLVER_GC_MAX_AGE_NS);
            last_gc_ns = now;
        }
        let item = match rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("xpf-userspace-dp: neighbor resolver: channel disconnected; exiting");
                break;
            }
        };
        // Dequeued — drop the live depth gauge regardless of whether we
        // act on the item (rate-limit skip still consumed a queue slot).
        counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let key = (item.ifindex, item.hop);
        // Per-key rate-limit: coalesce a SYN storm to one GET/probe per
        // window per key (no probe storm).
        let now = monotonic_nanos();
        match rate_limit_decide(&mut last_resolved, key, now) {
            RateLimitDecision::Coalesce => continue,
            RateLimitDecision::AdmitFirst => {}
            RateLimitDecision::AdmitRetry => {
                // #1771 §2.6: a re-admitted key after the per-key window
                // — the backoff-retry depth signal. Invariant N1 (§2.4):
                // these retries keep firing even while the worker-side
                // negative cache is fast-failing duplicate packets for
                // the same key.
                counters.get_backoff_attempts.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Snapshot epoch BEFORE the GET so a concurrent monitor event
        // that lands during the GET is detected by the post-GET re-read.
        // Prefer the item's enqueue-time epoch (older of the two) so the
        // guard is strictly conservative.
        let epoch_before = item.epoch.min(neighbor_generation.load(Ordering::Acquire));
        counters.get_attempts.fetch_add(1, Ordering::Relaxed);
        seq = seq.wrapping_add(1).max(1);
        // #1772: measure the GETNEIGH round-trip (request sent → reply
        // read) with the monotonic clock. Recorded only when the send
        // succeeded (a send-failure RTT would just be the syscall error
        // latency, not a kernel round-trip). saturating_sub on a
        // monotonic clock cannot underflow.
        let get_start_ns = monotonic_nanos();
        let outcome = match send_get_neigh(fd, item.ifindex, item.hop, seq) {
            Ok(()) => {
                let reply = read_get_reply(fd, item.ifindex, item.hop, seq);
                let rtt_ns = monotonic_nanos().saturating_sub(get_start_ns);
                get_rtt_hist.record(rtt_ns);
                reply
            }
            // Send failure is a transient local error, not an authoritative
            // kernel verdict — probe, do not revoke. No RTT recorded.
            Err(_) => GetOutcome::NoReply,
        };
        // Re-check stop AFTER the (up to 200 ms) GET, before any mutation
        // of the shared neighbor map. This is a fast early-out: the
        // authoritative no-mutation-after-stop guarantee comes from
        // Coordinator::stop_inner JOINING this thread (it retains the
        // JoinHandle in NeighborManager.resolver_join), so once stop_inner
        // returns this thread is gone and cannot mutate dynamic_neighbors
        // after a reconcile spawns a fresh resolver. Bailing here just
        // avoids one last wasted mutation in the common stop case.
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // Re-read the epoch AFTER the GET for a cheap fast-path reject
        // (avoids taking the shard lock when a monitor event has already
        // clearly raced in). The AUTHORITATIVE guard is the in-lock epoch
        // re-check inside insert_confirmed_if_unchanged below — paired
        // with the monitor's bump-first ordering, that closes the race
        // even when a removal lands between this load and the insert (the
        // Codex/AGY F1 counterexample).
        let epoch_after = neighbor_generation.load(Ordering::Acquire);
        match decide_action(outcome, epoch_before, epoch_after) {
            ResolveAction::Cache(mac) => {
                // Race-safe insert: the shard lock serializes against the
                // monitor's bump-first mutation of this same key, and the
                // generation is re-read INSIDE the lock against the
                // pre-GET snapshot. A late stale MAC can no longer
                // resurrect a key the monitor removed.
                if dynamic_neighbors.insert_confirmed_if_unchanged(
                    (item.ifindex, item.hop),
                    NeighborEntry { mac },
                    &neighbor_generation,
                    epoch_before,
                ) {
                    counters.get_resolved.fetch_add(1, Ordering::Relaxed);
                } else {
                    counters.epoch_rejects.fetch_add(1, Ordering::Relaxed);
                }
            }
            ResolveAction::EpochReject => {
                // Fast-path reject: the epoch already advanced before we
                // even attempted the locked insert. Back off rather than
                // clobber the monitor's authoritative removal.
                counters.epoch_rejects.fetch_add(1, Ordering::Relaxed);
            }
            ResolveAction::ProbeOnStale => {
                // The LIVE #1769 wedge state: kernel has a DELAY/STALE
                // lladdr we must not forward to blindly. Force kernel
                // revalidation; the confirmed multicast RTM_NEWNEIGH then
                // populates the map via the monitor.
                if trigger_kernel_arp_probe(&item.iface_name, item.ifindex, item.hop) {
                    dynamic_neighbors.record_neighbor_probe(key, monotonic_nanos());
                }
                counters.probe_on_stale.fetch_add(1, Ordering::Relaxed);
            }
            ResolveAction::RevokeAndProbe => {
                // Kernel AUTHORITATIVELY reports FAILED/INCOMPLETE: cache
                // nothing and revoke any stale dynamic entry — immediate-
                // revocation firewall posture (AGY F3); recovery comes from
                // a probe + the next confirmed event. Also fire a probe so
                // a genuinely-down-then-up host gets nudged.
                dynamic_neighbors.remove(&(item.ifindex, item.hop));
                if trigger_kernel_arp_probe(&item.iface_name, item.ifindex, item.hop) {
                    dynamic_neighbors.record_neighbor_probe(key, monotonic_nanos());
                }
                counters.get_failures.fetch_add(1, Ordering::Relaxed);
            }
            ResolveAction::ProbeOnly => {
                // No authoritative answer (GET timeout / error / no match).
                // Do NOT revoke — a transient GET loss must not evict a
                // still-good entry the monitor may have just (re)populated
                // (Copilot). Just probe to nudge resolution.
                if trigger_kernel_arp_probe(&item.iface_name, item.ifindex, item.hop) {
                    dynamic_neighbors.record_neighbor_probe(key, monotonic_nanos());
                }
                counters.get_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    unsafe { libc::close(fd) };
    // Reset the depth gauge on exit: any items still in the channel are
    // dropped when `rx` is dropped and will never be dequeued/decremented,
    // so the gauge would otherwise stay stuck non-zero while the resolver
    // is dead (Copilot). Steady state for a stopped resolver is 0.
    counters.queue_depth.store(0, Ordering::Relaxed);
    eprintln!("xpf-userspace-dp: neighbor resolver: stopped");
}

#[cfg(test)]
#[path = "neighbor_resolver_tests.rs"]
mod tests;
