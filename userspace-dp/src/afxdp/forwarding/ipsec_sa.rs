//! Shared inbound XFRM-SA existence snapshot for Stage-11 ESP-in-UDP.
//!
//! The packet path only reads the atomically published map.  The monitor is
//! deliberately the sole writer: kernel changes are folded into a fresh map
//! and published in one ArcSwap operation, so a worker cannot observe a
//! partially applied SA update.

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of inbound ESP states retained by the control-plane cache.
pub(in crate::afxdp) const IPSEC_SA_SNAPSHOT_CAP: usize = 4096;

/// Compact key used by the data-plane lookup. Addresses are in network byte
/// order (IPv4 occupies the low four bytes of the u128); `family` prevents
/// IPv4/IPv6 numeric-tail collisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::afxdp) struct IpsecSaKey {
    pub(in crate::afxdp) family: u8,
    pub(in crate::afxdp) dst: u128,
    pub(in crate::afxdp) spi: u32,
    pub(in crate::afxdp) src: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpsecSaEpoch {
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum IpsecSaLookup {
    Hit,
    Miss,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum IpsecSaMissReason {
    NoSa,
    Truncated,
    MalformedIke,
    Keepalive,
    Stale,
}

/// Process-wide counters owned by the SA monitor and read by status/tests.
/// The hot path updates only the miss atomics; it never takes a lock.
#[derive(Default)]
pub(in crate::afxdp) struct IpsecSaCounters {
    pub(in crate::afxdp) sa_miss_dropped_packets: AtomicU64,
    pub(in crate::afxdp) sa_miss_no_sa: AtomicU64,
    pub(in crate::afxdp) sa_miss_truncated: AtomicU64,
    pub(in crate::afxdp) sa_miss_malformed_ike: AtomicU64,
    pub(in crate::afxdp) sa_miss_keepalive: AtomicU64,
    pub(in crate::afxdp) sa_snapshot_stale_deny: AtomicU64,
    pub(in crate::afxdp) sa_inserts: AtomicU64,
    pub(in crate::afxdp) sa_removes: AtomicU64,
    pub(in crate::afxdp) sa_expiry_removes: AtomicU64,
    pub(in crate::afxdp) sa_evictions: AtomicU64,
    pub(in crate::afxdp) netlink_enobufs: AtomicU64,
    pub(in crate::afxdp) netlink_redumps: AtomicU64,
    pub(in crate::afxdp) netlink_redump_upserts: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IpsecSaCounterSnapshot {
    pub(crate) sa_miss_dropped_packets: u64,
    pub(crate) sa_miss_no_sa: u64,
    pub(crate) sa_miss_truncated: u64,
    pub(crate) sa_miss_malformed_ike: u64,
    pub(crate) sa_miss_keepalive: u64,
    pub(crate) sa_snapshot_stale_deny: u64,
    pub(crate) sa_inserts: u64,
    pub(crate) sa_removes: u64,
    pub(crate) sa_expiry_removes: u64,
    pub(crate) sa_evictions: u64,
    pub(crate) netlink_enobufs: u64,
    pub(crate) netlink_redumps: u64,
    pub(crate) netlink_redump_upserts: u64,
}

impl IpsecSaCounters {
    #[inline]
    pub(in crate::afxdp) fn record_miss(&self, reason: IpsecSaMissReason) {
        self.sa_miss_dropped_packets.fetch_add(1, Ordering::Relaxed);
        match reason {
            IpsecSaMissReason::NoSa => {
                self.sa_miss_no_sa.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Truncated => {
                self.sa_miss_truncated.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::MalformedIke => {
                self.sa_miss_malformed_ike.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Keepalive => {
                self.sa_miss_keepalive.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Stale => {
                self.sa_snapshot_stale_deny.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    fn miss_total(&self) -> u64 {
        self.sa_miss_dropped_packets.load(Ordering::Relaxed)
    }
    pub(in crate::afxdp) fn snapshot(&self) -> IpsecSaCounterSnapshot {
        IpsecSaCounterSnapshot {
            sa_miss_dropped_packets: self.sa_miss_dropped_packets.load(Ordering::Relaxed),
            sa_miss_no_sa: self.sa_miss_no_sa.load(Ordering::Relaxed),
            sa_miss_truncated: self.sa_miss_truncated.load(Ordering::Relaxed),
            sa_miss_malformed_ike: self.sa_miss_malformed_ike.load(Ordering::Relaxed),
            sa_miss_keepalive: self.sa_miss_keepalive.load(Ordering::Relaxed),
            sa_snapshot_stale_deny: self.sa_snapshot_stale_deny.load(Ordering::Relaxed),
            sa_inserts: self.sa_inserts.load(Ordering::Relaxed),
            sa_removes: self.sa_removes.load(Ordering::Relaxed),
            sa_expiry_removes: self.sa_expiry_removes.load(Ordering::Relaxed),
            sa_evictions: self.sa_evictions.load(Ordering::Relaxed),
            netlink_enobufs: self.netlink_enobufs.load(Ordering::Relaxed),
            netlink_redumps: self.netlink_redumps.load(Ordering::Relaxed),
            netlink_redump_upserts: self.netlink_redump_upserts.load(Ordering::Relaxed),
        }
    }
}

/// Read-mostly SA store.  `entries` is replaced only by the monitor/control
/// side; workers load an Arc and perform one hash lookup without a lock.
pub(in crate::afxdp) struct IpsecSaStore {
    entries: arc_swap::ArcSwap<FastMap<IpsecSaKey, IpsecSaEpoch>>,
    generation: AtomicU64,
    stale: AtomicBool,
    ready: AtomicBool,
    pub(in crate::afxdp) counters: IpsecSaCounters,
}
impl std::fmt::Debug for IpsecSaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpsecSaStore")
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .field("stale", &self.stale.load(Ordering::Relaxed))
            .field("ready", &self.ready.load(Ordering::Relaxed))
            .field("entries", &self.entries.load().len())
            .finish()
    }
}

impl Default for IpsecSaStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IpsecSaStore {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            entries: arc_swap::ArcSwap::from_pointee(FastMap::default()),
            generation: AtomicU64::new(0),
            stale: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            counters: IpsecSaCounters::default(),
        }
    }

    #[inline]
    pub(in crate::afxdp) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[inline]
    pub(in crate::afxdp) fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Acquire)
    }

    pub(in crate::afxdp) fn mark_stale(&self) {
        self.stale.store(true, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    #[inline]
    pub(in crate::afxdp) fn lookup(&self, key: IpsecSaKey) -> IpsecSaLookup {
        if self.stale.load(Ordering::Acquire) || self.generation.load(Ordering::Acquire) == 0 {
            return IpsecSaLookup::Stale;
        }
        if self.entries.load().contains_key(&key) {
            IpsecSaLookup::Hit
        } else {
            IpsecSaLookup::Miss
        }
    }

    /// Publish a complete dump. The generation becomes non-zero only after
    /// the new map is visible, which makes the first successful dump the ready
    /// gate for data-plane lookups.
    pub(in crate::afxdp) fn publish_full_dump(&self, entries: FastMap<IpsecSaKey, IpsecSaEpoch>) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        self.entries.store(Arc::new(cap_entries(entries, generation, &self.counters)));
        self.stale.store(false, Ordering::Release);
        self.ready.store(true, Ordering::Release);
    }

    pub(in crate::afxdp) fn reset_for_monitor_start(&self) {
        self.entries.store(Arc::new(FastMap::default()));
        self.generation.store(0, Ordering::Release);
        self.stale.store(true, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    pub(in crate::afxdp) fn wait_ready(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while !self.ready.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    pub(in crate::afxdp) fn upsert(&self, key: IpsecSaKey) {
        let mut next = self.entries.load_full().as_ref().clone();
        let generation = self.generation.load(Ordering::Acquire).saturating_add(1).max(1);
        next.insert(key, IpsecSaEpoch { generation });
        self.generation.store(generation, Ordering::Release);
        self.entries.store(Arc::new(cap_entries(next, generation, &self.counters)));
        // NEWSA/UPDSA are incremental observations. They MUST NOT clear a
        // stale fence: only a successful complete dump proves that no event
        // was lost and may re-enable positive lookups.
        self.counters.sa_inserts.fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::afxdp) fn remove(&self, key: IpsecSaKey) -> bool {
        let mut next = self.entries.load_full().as_ref().clone();
        let removed = next.remove(&key).is_some();
        if removed {
            self.entries.store(Arc::new(next));
            self.counters.sa_removes.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    pub(in crate::afxdp) fn remove_dst_spi(&self, family: u8, dst: u128, spi: u32) {
        let mut next = self.entries.load_full().as_ref().clone();
        let before = next.len();
        next.retain(|key, _| !(key.family == family && key.dst == dst && key.spi == spi));
        let removed = before.saturating_sub(next.len());
        if removed != 0 {
            self.entries.store(Arc::new(next));
            self.counters
                .sa_removes
                .fetch_add(removed as u64, Ordering::Relaxed);
        }
    }
    #[cfg(test)]
    fn entries_len(&self) -> usize {
        self.entries.load().len()
    }
}

fn cap_entries(
    mut entries: FastMap<IpsecSaKey, IpsecSaEpoch>,
    generation: u64,
    counters: &IpsecSaCounters,
) -> FastMap<IpsecSaKey, IpsecSaEpoch> {
    if entries.len() <= IPSEC_SA_SNAPSHOT_CAP {
        return entries;
    }
    let remove_count = entries.len() - IPSEC_SA_SNAPSHOT_CAP;
    let mut oldest: Vec<(IpsecSaKey, u64)> = entries
        .iter()
        .map(|(key, epoch)| (*key, epoch.generation))
        .collect();
    oldest.sort_unstable_by_key(|(_, epoch)| *epoch);
    for (key, _) in oldest.into_iter().take(remove_count) {
        entries.remove(&key);
        counters.sa_evictions.fetch_add(1, Ordering::Relaxed);
    }
    let _ = generation;
    entries
}

#[inline]
pub(in crate::afxdp) fn ipsec_sa_key(dst: IpAddr, spi: u32, src: IpAddr) -> IpsecSaKey {
    let family = match (dst, src) {
        (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET as u8,
        (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6 as u8,
        // A mixed-family flow is not a valid SA key.  Retain an explicit
        // impossible family value so it can never collide with either
        // address family in the map.
        _ => 0,
    };
    IpsecSaKey {
        family,
        dst: ip_to_u128(dst),
        spi,
        src: ip_to_u128(src),
    }
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

/// Classify and extract a UDP-4500 ESP SPI.  The caller handles positive IKE
/// first; this helper is deliberately defensive so a marker can never be
/// interpreted as an ESP SPI.
#[inline]
pub(in crate::afxdp) fn esp_in_udp_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> Option<u32> {
    if dst_port != 4500 {
        return None;
    }
    let _udp = packet_frame.get(l4_offset..l4_offset.checked_add(8)?)?;
    let payload = packet_frame.get(l4_offset.checked_add(8)?..)?;
    if payload == [0xff] {
        return None;
    }
    let spi = u32::from_be_bytes(payload.get(0..4)?.try_into().ok()?);
    if spi == 0 {
        return None;
    }
    Some(spi)
}

#[inline]
pub(in crate::afxdp) fn esp_in_udp_miss_reason(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
) -> IpsecSaMissReason {
    if dst_port != 4500 {
        return IpsecSaMissReason::Truncated;
    }
    let Some(_udp) = l4_offset
        .checked_add(8)
        .and_then(|end| packet_frame.get(l4_offset..end))
    else {
        return IpsecSaMissReason::Truncated;
    };
    let Some(payload) = l4_offset
        .checked_add(8)
        .and_then(|offset| packet_frame.get(offset..))
    else {
        return IpsecSaMissReason::Truncated;
    };
    if payload == [0xff] {
        return IpsecSaMissReason::Keepalive;
    }
    if payload.len() < 4 {
        IpsecSaMissReason::Truncated
    } else {
        IpsecSaMissReason::NoSa
    }
}

/// Minimal monitor state used by the coordinator lifecycle.  Socket parsing
/// is intentionally isolated below so deterministic tests can drive the store
/// without requiring NETLINK_XFRM privileges.
pub(in crate::afxdp) struct IpsecSaMonitor {
    pub(in crate::afxdp) store: Arc<IpsecSaStore>,
    pub(in crate::afxdp) stop: Option<Arc<AtomicBool>>,
    pub(in crate::afxdp) join: Option<std::thread::JoinHandle<()>>,
}

impl IpsecSaMonitor {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            store: Arc::new(IpsecSaStore::new()),
            stop: None,
            join: None,
        }
    }

    pub(in crate::afxdp) fn stop_and_join(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
const NLMSG_OVERRUN: u16 = 4;

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const XFRM_MSG_NEWSA: u16 = 0x10;
const XFRM_MSG_DELSA: u16 = 0x11;
const XFRM_MSG_GETSA: u16 = 0x12;
const XFRM_MSG_EXPIRE: u16 = 0x18;
const XFRM_MSG_UPDSA: u16 = 0x1a;
const XFRM_MSG_FLUSHSA: u16 = 0x1c;
const XFRMA_SA_DIR: u16 = 33;
const XFRM_SA_DIR_IN: u8 = 1;
const XFRMGRP_EXPIRE: u32 = 2;
const XFRMGRP_SA: u32 = 4;
const XFRM_INFO_LEN: usize = 224;
const XFRM_MSG_ID_LEN: usize = 24;

/// Run the event-driven XFRM-SA monitor.  A failed socket, dump, or receive
/// operation immediately sets the stale fence; only a later complete dump
/// clears it.  The 500 ms receive timeout is the lifecycle join bound.
pub(in crate::afxdp) fn ipsec_sa_monitor_loop(store: Arc<IpsecSaStore>, stop: Arc<AtomicBool>) {
    let fd = match open_xfrm_socket() {
        Some(fd) => fd,
        None => {
            store.mark_stale();
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(500));
            }
            return;
        }
    };
    let mut seq = 1u32;
    let mut next_drift = std::time::Instant::now() + Duration::from_secs(30);
    let mut dump_ready = false;
    while !stop.load(Ordering::Acquire) {
        if !dump_ready || std::time::Instant::now() >= next_drift {
            store.counters.netlink_redumps.fetch_add(1, Ordering::Relaxed);
            let ok = full_dump(fd, &store, seq);
            seq = seq.wrapping_add(1).max(1);
            if ok {
                dump_ready = true;
                next_drift = std::time::Instant::now() + Duration::from_secs(30);
            } else {
                store.mark_stale();
                dump_ready = false;
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        let mut buf = [0u8; 64 * 1024];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if matches!(err, Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)) {
                continue;
            }
            if err == Some(libc::ENOBUFS) {
                store.counters.netlink_enobufs.fetch_add(1, Ordering::Relaxed);
            }
            store.mark_stale();
            dump_ready = false;
            continue;
        }
        if n == 0 {
            store.mark_stale();
            dump_ready = false;
            continue;
        }
        if apply_xfrm_messages(&store, &buf[..n as usize]) {
            store.mark_stale();
            dump_ready = false;
        }
    }
    unsafe {
        libc::close(fd);
    }
}

fn open_xfrm_socket() -> Option<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_XFRM,
        )
    };
    if fd < 0 {
        return None;
    }
    let groups = XFRMGRP_SA | XFRMGRP_EXPIRE;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = groups;
    let bound = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }
    Some(fd)
}

fn full_dump(fd: libc::c_int, store: &IpsecSaStore, seq: u32) -> bool {
    let mut request = [0u8; NLMSG_HDR_LEN + XFRM_MSG_ID_LEN];
    let request_len = request.len() as u32;
    put_u32(&mut request[0..4], request_len);
    put_u16(&mut request[4..6], XFRM_MSG_GETSA);
    put_u16(
        &mut request[6..8],
        NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH,
    );
    put_u32(&mut request[8..12], seq);
    put_u32(&mut request[12..16], 0);
    // The all-zero xfrm_usersa_id is the kernel's dump selector.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let sent = unsafe {
        libc::sendto(
            fd,
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent != request.len() as isize {
        return false;
    }
    let mut entries = FastMap::default();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            if n < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS)
            {
                store.counters.netlink_enobufs.fetch_add(1, Ordering::Relaxed);
            }
            return false;
        }
        let bytes = &buf[..n as usize];
        let mut offset = 0usize;
        while offset + NLMSG_HDR_LEN <= bytes.len() {
            let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            if len < NLMSG_HDR_LEN || offset + len > bytes.len() {
                return false;
            }
            let msg_type =
                u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
            let flags =
                u16::from_ne_bytes(bytes[offset + 6..offset + 8].try_into().unwrap());
            let msg_seq =
                u32::from_ne_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
            // A multicast event interleaving a dump, or the kernel's
            // NLM_F_DUMP_INTR marker, invalidates the candidate snapshot.
            // Abort and retry rather than publishing a pre-delete map.
            if msg_seq != seq || (flags & 0x0010) != 0 {
                return false;
            }
            let payload = &bytes[offset + NLMSG_HDR_LEN..offset + len];
            if msg_type == NLMSG_DONE {
                if offset + ((len + 3) & !3) != bytes.len() {
                    return false;
                }
                store.counters
                    .netlink_redump_upserts
                    .fetch_add(entries.len() as u64, Ordering::Relaxed);
                store.publish_full_dump(entries);
                return true;
            }
            if msg_type == NLMSG_ERROR || msg_type == NLMSG_OVERRUN {
                return false;
            }
            if msg_type == XFRM_MSG_NEWSA {
                if let Some(key) = parse_sa_payload(payload, true) {
                    entries.insert(key, IpsecSaEpoch { generation: seq as u64 });
                }
            }
            offset += (len + 3) & !3;
        }
        if offset != bytes.len() {
            return false;
        }
    }
}

/// Return true when a full dump is required after applying these event
/// messages (FLUSHSA or a malformed/uncertain event).
fn apply_xfrm_messages(store: &IpsecSaStore, bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= bytes.len() {
        let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDR_LEN || offset + len > bytes.len() {
            return true;
        }
        let msg_type = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
        let payload = &bytes[offset + NLMSG_HDR_LEN..offset + len];
        match msg_type {
            NLMSG_ERROR | NLMSG_OVERRUN | NLMSG_DONE => return true,
            XFRM_MSG_NEWSA | XFRM_MSG_UPDSA => {
                if let Some(key) = parse_sa_payload(payload, true) {
                    store.upsert(key);
                } else if let Some((family, dst, spi, _src)) = parse_info_identity(payload) {
                    // The record is well-formed but ineligible (wrong
                    // direction/protocol or expired): fail closed by
                    // removing any previous matching observation.
                    store.remove_dst_spi(family, ip_to_u128(dst), spi);
                } else {
                    return true;
                }
            }
            XFRM_MSG_DELSA => {
                if let Some((family, dst, spi)) = parse_id_identity(payload) {
                    store.remove_dst_spi(family, dst, spi);
                } else {
                    return true;
                }
            }
            XFRM_MSG_EXPIRE => {
                if payload.len() < XFRM_INFO_LEN + 1 {
                    return true;
                }
                if let Some((family, dst, spi, _src)) = parse_info_identity(payload) {
                    // Both soft and hard expiry revoke the cache proof
                    // immediately; a later complete dump may re-add a
                    // replacement SA after rekey.
                    store.remove_dst_spi(family, ip_to_u128(dst), spi);
                    store
                        .counters
                        .sa_expiry_removes
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    return true;
                }
            }
            XFRM_MSG_FLUSHSA => return true,
            _ => {}
        }
        offset += (len + 3) & !3;
    }
    offset != bytes.len()
}

fn parse_sa_payload(payload: &[u8], require_direction: bool) -> Option<IpsecSaKey> {
    let (family, dst, spi, src) = parse_info_identity(payload)?;
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return None;
    }
    if payload.get(56 + 20).copied()? != libc::IPPROTO_ESP as u8 {
        return None;
    }
    let hard_bytes = read_u64_ne(payload, 96 + 8)?;
    let hard_packets = read_u64_ne(payload, 96 + 24)?;
    let hard_add = read_u64_ne(payload, 96 + 40)?;
    let cur_bytes = read_u64_ne(payload, 160)?;
    let cur_packets = read_u64_ne(payload, 168)?;
    let add_time = read_u64_ne(payload, 176)?;
    if (hard_bytes != u64::MAX && cur_bytes >= hard_bytes)
        || (hard_packets != u64::MAX && cur_packets >= hard_packets)
        || (hard_add != 0
            && hard_add != u64::MAX
            && add_time
                .checked_add(hard_add)
                .is_none_or(|deadline| now_secs() >= deadline))
    {
        return None;
    }
    if require_direction
        && parse_sa_direction(&payload[XFRM_INFO_LEN..]) != Some(XFRM_SA_DIR_IN)
    {
        return None;
    }
    Some(ipsec_sa_key(dst, spi, src))
}

fn parse_info_identity(payload: &[u8]) -> Option<(u8, IpAddr, u32, IpAddr)> {
    if payload.len() < XFRM_INFO_LEN {
        return None;
    }
    let family = u16::from_ne_bytes(payload[212..214].try_into().ok()?) as u8;
    let spi = u32::from_be_bytes(payload[72..76].try_into().ok()?);
    let dst = parse_address(family, payload.get(56..72)?)?;
    let src = parse_address(family, payload.get(80..96)?)?;
    Some((family, dst, spi, src))
}

fn parse_id_identity(payload: &[u8]) -> Option<(u8, u128, u32)> {
    if payload.len() < XFRM_MSG_ID_LEN {
        return None;
    }
    let family = u16::from_ne_bytes(payload[20..22].try_into().ok()?) as u8;
    let spi = u32::from_be_bytes(payload[16..20].try_into().ok()?);
    let dst = parse_address(family, payload.get(0..16)?)?;
    Some((family, ip_to_u128(dst), spi))
}

fn parse_address(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if bytes.len() >= 4 => {
            let octets: [u8; 4] = bytes[0..4].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 if bytes.len() >= 16 => {
            let octets: [u8; 16] = bytes[0..16].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_sa_direction(attrs: &[u8]) -> Option<u8> {
    let mut offset = 0usize;
    while offset + 4 <= attrs.len() {
        let len = u16::from_ne_bytes(attrs[offset..offset + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attrs[offset + 2..offset + 4].try_into().ok()?) & 0x3fff;
        if len < 4 || offset + len > attrs.len() {
            return None;
        }
        if kind == XFRMA_SA_DIR {
            return attrs.get(offset + 4).copied();
        }
        offset += (len + 3) & !3;
    }
    None
}

fn read_u64_ne(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn put_u16(dst: &mut [u8], value: u16) {
    dst.copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(dst: &mut [u8], value: u32) {
    dst.copy_from_slice(&value.to_ne_bytes());
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

/// Apply a single already-validated event to the snapshot.  Kept as a small
/// seam for deterministic monitor tests and for callers that have parsed a
/// netlink message outside the receive loop.
pub(in crate::afxdp) fn apply_xfrm_event(
    store: &IpsecSaStore,
    added: Option<IpsecSaKey>,
    removed: Option<IpsecSaKey>,
    expired: bool,
) {
    if let Some(key) = removed {
        if store.remove(key) && expired {
            store.counters.sa_expiry_removes.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(key) = added {
        store.upsert(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> IpsecSaKey {
        ipsec_sa_key(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, n as u8)),
            n,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, n as u8)),
        )
    }

    #[test]
    fn empty_store_denies_until_first_full_dump() {
        let store = IpsecSaStore::new();
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Stale);
        let mut entries = FastMap::default();
        entries.insert(key(1), IpsecSaEpoch { generation: 1 });
        store.publish_full_dump(entries);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Hit);
        assert_eq!(store.lookup(key(2)), IpsecSaLookup::Miss);
    }

    #[test]
    fn stale_denies_existing_entry_immediately() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(key(1), IpsecSaEpoch { generation: 1 });
        store.publish_full_dump(entries);
        store.mark_stale();
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Stale);
    }

    #[test]
    fn cap_eviction_is_control_side_only() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        for n in 0..(IPSEC_SA_SNAPSHOT_CAP + 3) {
            entries.insert(key(n as u32), IpsecSaEpoch { generation: n as u64 + 1 });
        }
        store.publish_full_dump(entries);
        assert_eq!(store.entries_len(), IPSEC_SA_SNAPSHOT_CAP);
    }

    #[test]
    fn esp_parser_distinguishes_keepalive_and_marker() {
        let mut frame = vec![0u8; 8];
        frame.extend_from_slice(&[0xff]);
        assert_eq!(esp_in_udp_spi(&frame, 0, 4500), None);
        assert_eq!(esp_in_udp_miss_reason(&frame, 0, 4500), IpsecSaMissReason::Keepalive);
        frame.truncate(8);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(esp_in_udp_miss_reason(&frame, 0, 4500), IpsecSaMissReason::NoSa);
    }

    #[test]
    fn parses_usersa_info_offsets_and_inbound_direction() {
        let mut payload = vec![0u8; XFRM_INFO_LEN + 8];
        payload[56..60].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        payload[72..76].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        payload[76] = libc::IPPROTO_ESP as u8;
        payload[80..84].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        payload[212..214].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        for offset in [96 + 8, 96 + 24] {
            payload[offset..offset + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
        }
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        payload[226..228].copy_from_slice(&XFRMA_SA_DIR.to_ne_bytes());
        payload[228] = XFRM_SA_DIR_IN;
        // A zero hard-add lifetime is disabled by XFRM, not immediately
        // expired. The parser must retain this ordinary unlimited SA.
        payload[136..144].fill(0);
        assert!(parse_sa_payload(&payload, true).is_some());
        payload[136..144].copy_from_slice(&u64::MAX.to_ne_bytes());
        // A present direction attribute is required by the gate.
        payload[224..232].fill(0);
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        payload[226..228].copy_from_slice(&XFRMA_SA_DIR.to_ne_bytes());
        payload[228] = 2;
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[228] = XFRM_SA_DIR_IN;
        let parsed = parse_sa_payload(&payload, true).expect("eligible inbound SA");
        assert_eq!(
            parsed,
            ipsec_sa_key(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                0x1122_3344,
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            )
        );
    }

    #[test]
    fn usersa_id_delete_layout_is_not_treated_as_usersa_info() {
        let mut payload = vec![0u8; XFRM_MSG_ID_LEN];
        payload[0..4].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        payload[16..20].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        payload[20..22].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        payload[22] = libc::IPPROTO_ESP as u8;
        assert_eq!(
            parse_id_identity(&payload),
            Some((
                libc::AF_INET as u8,
                ip_to_u128(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                0x1122_3344,
            ))
        );
        assert!(parse_info_identity(&payload).is_none());
    }

    #[test]
    fn incremental_upsert_does_not_clear_stale() {
        let store = IpsecSaStore::new();
        store.mark_stale();
        store.upsert(key(7));
        assert_eq!(store.lookup(key(7)), IpsecSaLookup::Stale);
        let mut entries = FastMap::default();
        entries.insert(key(7), IpsecSaEpoch { generation: 1 });
        store.publish_full_dump(entries);
        assert_eq!(store.lookup(key(7)), IpsecSaLookup::Hit);
    }
}
