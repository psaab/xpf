//! Screen/IDS attack protection checks for the userspace dataplane.
//!
//! Implements pre-session packet validation that mirrors the eBPF screen stage
//! (`bpf/xdp/xdp_screen.c`). Checks run on every packet BEFORE session lookup.
//!
//! Supported checks:
//! - Land attack (src == dst)
//! - TCP SYN+FIN
//! - TCP no-flag (null scan)
//! - TCP FIN without ACK
//! - WinNuke (URG to port 139)
//! - Ping of death (oversized ICMP)
//! - Teardrop (overlapping fragments)
//! - ICMP fragment
//! - IP source route options
//! - Rate limiting (ICMP, UDP flood)
//! - SYN flood (per-zone rate)

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

// TCP flag bits (matching BPF layout: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20)
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

const SYN_COOKIE_EPOCH_BITS: u32 = 5;
const SYN_COOKIE_MSS_BITS: u32 = 3;
const SYN_COOKIE_MAC_BITS: u32 = 24;
const SYN_COOKIE_ISN_BITS: u32 = 32;
const SYN_COOKIE_LAYOUT_BITS: u32 =
    SYN_COOKIE_EPOCH_BITS + SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
const SYN_COOKIE_EPOCH_MASK: u32 = (1 << SYN_COOKIE_EPOCH_BITS) - 1;
const SYN_COOKIE_MSS_MASK: u32 = (1 << SYN_COOKIE_MSS_BITS) - 1;
const SYN_COOKIE_MAC_MASK: u32 = (1 << SYN_COOKIE_MAC_BITS) - 1;
const SYN_COOKIE_EPOCH_SHIFT: u32 = SYN_COOKIE_MSS_BITS + SYN_COOKIE_MAC_BITS;
const SYN_COOKIE_MSS_SHIFT: u32 = SYN_COOKIE_MAC_BITS;
const SYN_COOKIE_MAC_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sync");
const SYN_COOKIE_SECRET_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck0");
const SYN_COOKIE_SECRET_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-sck1");
const SYN_COOKIE_CACHE_LEFT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv0");
const SYN_COOKIE_CACHE_RIGHT_DOMAIN: u64 = u64::from_be_bytes(*b"xpf-scv1");
const SYN_COOKIE_VALIDATED_CACHE_CAPACITY: usize = 4096;
const SYN_COOKIE_VALIDATED_CACHE_WAYS: usize = 4;
const SYN_COOKIE_VALIDATED_CACHE_TTL_SECS: u64 = SynCookieCodec::EPOCH_SECS;
const _: [(); SYN_COOKIE_ISN_BITS as usize] = [(); SYN_COOKIE_LAYOUT_BITS as usize];

/// Three-bit MSS table encoded in userspace SYN cookies.
///
/// The index, not the raw MSS, is transmitted in the ISN. Values are sorted so
/// selection can choose the largest value not exceeding the peer-advertised MSS.
pub(crate) const SYN_COOKIE_MSS_VALUES: [u16; 8] = [536, 1200, 1300, 1360, 1400, 1440, 1460, 8960];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl SynCookieTuple {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_packet(pkt: &ScreenPacketInfo) -> Self {
        Self {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieValidation {
    pub full_epoch: u64,
    pub mss_index: u8,
    pub mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieChallenge {
    pub cookie_isn: u32,
    pub peer_mss: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SynCookieAckVerdict {
    NotApplicable,
    Validated,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SynCookieCodec {
    master_key: [u8; 16],
}

impl SynCookieCodec {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const EPOCH_SECS: u64 = 64;

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn new(master_key: [u8; 16]) -> Self {
        Self { master_key }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn full_epoch_from_monotonic_secs(monotonic_secs: u64) -> u64 {
        monotonic_secs / Self::EPOCH_SECS
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mss_index(peer_mss: u16) -> u8 {
        let mut selected = 0u8;
        let mut i = 1;
        while i < SYN_COOKIE_MSS_VALUES.len() {
            if peer_mss >= SYN_COOKIE_MSS_VALUES[i] {
                selected = i as u8;
            }
            i += 1;
        }
        selected
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn mint_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        peer_mss: u16,
    ) -> u32 {
        let mss_index = Self::mss_index(peer_mss);
        let mac = self.cookie_mac(tuple, zone_id, full_epoch, mss_index);
        ((full_epoch as u32 & SYN_COOKIE_EPOCH_MASK) << SYN_COOKIE_EPOCH_SHIFT)
            | ((mss_index as u32 & SYN_COOKIE_MSS_MASK) << SYN_COOKIE_MSS_SHIFT)
            | mac
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn validate_isn(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        current_full_epoch: u64,
        cookie_isn: u32,
    ) -> Option<SynCookieValidation> {
        let wire_epoch = (cookie_isn >> SYN_COOKIE_EPOCH_SHIFT) & SYN_COOKIE_EPOCH_MASK;
        let mss_index = ((cookie_isn >> SYN_COOKIE_MSS_SHIFT) & SYN_COOKIE_MSS_MASK) as u8;
        let wire_mac = cookie_isn & SYN_COOKIE_MAC_MASK;

        for candidate_epoch in [current_full_epoch, current_full_epoch.saturating_sub(1)] {
            if (candidate_epoch as u32 & SYN_COOKIE_EPOCH_MASK) != wire_epoch {
                continue;
            }
            if self.cookie_mac(tuple, zone_id, candidate_epoch, mss_index) == wire_mac {
                return Some(SynCookieValidation {
                    full_epoch: candidate_epoch,
                    mss_index,
                    mss: SYN_COOKIE_MSS_VALUES[mss_index as usize],
                });
            }
        }

        None
    }

    fn cookie_mac(
        &self,
        tuple: SynCookieTuple,
        zone_id: u16,
        full_epoch: u64,
        mss_index: u8,
    ) -> u32 {
        let secret = self.epoch_secret(zone_id, full_epoch);
        let mut sip = SipHash24::new(secret[0], secret[1]);
        sip.write_u64(SYN_COOKIE_MAC_DOMAIN);
        sip.write_u16(zone_id);
        sip.write_u64(full_epoch);
        sip.write_u8(mss_index);
        sip.write_ip(tuple.src_ip);
        sip.write_ip(tuple.dst_ip);
        sip.write_u16(tuple.src_port);
        sip.write_u16(tuple.dst_port);
        (sip.finish() as u32) & SYN_COOKIE_MAC_MASK
    }

    fn epoch_secret(&self, zone_id: u16, full_epoch: u64) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_SECRET_LEFT_DOMAIN);
        left.write_u16(zone_id);
        left.write_u64(full_epoch);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_SECRET_RIGHT_DOMAIN);
        right.write_u16(zone_id);
        right.write_u64(full_epoch);

        [left.finish(), right.finish()]
    }

    fn cache_hash_keys(&self) -> [u64; 2] {
        let k0 = u64::from_le_bytes(self.master_key[0..8].try_into().expect("fixed slice"));
        let k1 = u64::from_le_bytes(self.master_key[8..16].try_into().expect("fixed slice"));

        let mut left = SipHash24::new(k0, k1);
        left.write_u64(SYN_COOKIE_CACHE_LEFT_DOMAIN);

        let mut right = SipHash24::new(k0, k1);
        right.write_u64(SYN_COOKIE_CACHE_RIGHT_DOMAIN);

        [left.finish(), right.finish()]
    }
}

#[derive(Debug, Clone, Copy)]
struct SipHash24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: [u8; 8],
    tail_len: usize,
    len: u64,
}

impl SipHash24 {
    fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
            tail: [0; 8],
            tail_len: 0,
            len: 0,
        }
    }

    fn write_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.write_u8(4);
                self.write_bytes(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.write_u8(6);
                self.write_bytes(&v6.octets());
            }
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.write_bytes(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_be_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_be_bytes());
    }

    fn write_bytes(&mut self, mut bytes: &[u8]) {
        self.len += bytes.len() as u64;

        if self.tail_len > 0 {
            let fill = (8 - self.tail_len).min(bytes.len());
            self.tail[self.tail_len..self.tail_len + fill].copy_from_slice(&bytes[..fill]);
            self.tail_len += fill;
            bytes = &bytes[fill..];
            if self.tail_len == 8 {
                self.compress(u64::from_le_bytes(self.tail));
                self.tail = [0; 8];
                self.tail_len = 0;
            }
        }

        while bytes.len() >= 8 {
            let block = u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice"));
            self.compress(block);
            bytes = &bytes[8..];
        }

        if !bytes.is_empty() {
            self.tail[..bytes.len()].copy_from_slice(bytes);
            self.tail_len = bytes.len();
        }
    }

    fn finish(mut self) -> u64 {
        let mut last = self.len << 56;
        let mut i = 0;
        while i < self.tail_len {
            last |= (self.tail[i] as u64) << (8 * i);
            i += 1;
        }
        self.compress(last);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }

    fn compress(&mut self, block: u64) {
        self.v3 ^= block;
        self.round();
        self.round();
        self.v0 ^= block;
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

/// Parsed packet fields needed for screen checks.
/// Extracted from raw packet bytes for speed — no allocations.
#[derive(Debug, Clone)]
pub(crate) struct ScreenPacketInfo {
    pub addr_family: u8, // AF_INET=2, AF_INET6=10
    pub protocol: u8,    // IPPROTO_*
    pub tcp_flags: u8,   // TCP flags byte
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16, // host byte order
    pub dst_port: u16, // host byte order
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_mss: u16,
    pub pkt_len: u16, // total packet length from meta
    pub is_fragment: bool,
    /// #1137: 1 = first fragment of a fragmented datagram (IPv4: MF=1
    /// && offset==0; IPv6: MF=1 && offset==0). Mirrors the BPF
    /// `is_first_fragment` flag in pkt_meta. `is_fragment=1 &&
    /// is_first_fragment=0` indicates a subsequent fragment.
    pub is_first_fragment: bool,
    pub ip_ihl: u8,        // IPv4 IHL field (header length in 32-bit words)
    pub ip_frag_off: u16,  // raw frag_off field (network byte order already parsed)
    pub ip_total_len: u16, // IPv4 total length
}

/// Screen profile configuration for a zone. Mirrors the BPF `screen_config`.
#[derive(Clone, Debug, Default)]
pub(crate) struct ScreenProfile {
    pub land: bool,
    pub syn_fin: bool,
    pub no_flag: bool,
    pub fin_no_ack: bool,
    pub winnuke: bool,
    pub ping_death: bool,
    pub teardrop: bool,
    pub icmp_fragment: bool,
    /// #1137: TCP SYN on a first-fragment is the fragmentation-based
    /// attack pattern. Mirrors the BPF SCREEN_SYN_FRAG (#866) on the
    /// userspace dataplane path.
    pub syn_frag: bool,
    pub source_route: bool,
    pub icmp_flood_threshold: u32, // packets per second, 0 = disabled
    pub udp_flood_threshold: u32,  // packets per second, 0 = disabled
    pub syn_flood_threshold: u32,  // SYN packets per second per zone, 0 = disabled
    /// Enable SYN-cookie challenge/validation behavior for SYN flood threshold
    /// crossings. Defaults false so rate-based SYN flood behavior remains a
    /// plain drop until the control plane explicitly enables cookie mode.
    pub syn_cookie: bool,
    pub session_limit_src: u32, // max sessions per source IP, 0 = disabled
    pub session_limit_dst: u32, // max sessions per destination IP, 0 = disabled
    pub port_scan_threshold: u32, // unique dst ports per src IP within window, 0 = disabled
    pub ip_sweep_threshold: u32, // unique dst IPs per src IP within window, 0 = disabled
}

/// Result of a screen check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScreenVerdict {
    Pass,
    Drop(&'static str),
    SynCookieChallenge(SynCookieChallenge),
}

/// Simple rate counter: counts events within a 1-second window.
#[derive(Debug, Clone, Default)]
struct RateCounter {
    count: u32,
    window_start_secs: u64,
}

impl RateCounter {
    /// Increment and return true if the threshold is exceeded.
    fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
        if now_secs != self.window_start_secs {
            self.count = 0;
            self.window_start_secs = now_secs;
        }
        self.count += 1;
        self.count > threshold
    }

    /// Reset counter (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    fn reset(&mut self) {
        self.count = 0;
        self.window_start_secs = 0;
    }
}

/// Per-IP session counter for session limiting.
#[derive(Debug, Clone, Default)]
struct SessionLimitTracker {
    src_counts: FxHashMap<IpAddr, u32>,
    dst_counts: FxHashMap<IpAddr, u32>,
}

impl SessionLimitTracker {
    /// Increment session count for a source IP. Returns true if limit exceeded.
    fn check_src(&mut self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let count = self.src_counts.entry(ip).or_insert(0);
        *count >= limit
    }

    /// Increment session count for a destination IP. Returns true if limit exceeded.
    fn check_dst(&mut self, ip: IpAddr, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let count = self.dst_counts.entry(ip).or_insert(0);
        *count >= limit
    }

    /// Called when a new session is created (after the check passes).
    #[cfg_attr(not(test), allow(dead_code))]
    fn session_created(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        *self.src_counts.entry(src_ip).or_insert(0) += 1;
        *self.dst_counts.entry(dst_ip).or_insert(0) += 1;
    }

    /// Called when a session expires.
    #[cfg_attr(not(test), allow(dead_code))]
    fn session_expired(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if let Some(c) = self.src_counts.get_mut(&src_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.src_counts.remove(&src_ip);
            }
        }
        if let Some(c) = self.dst_counts.get_mut(&dst_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.dst_counts.remove(&dst_ip);
            }
        }
    }
}

/// Tracks unique destination ports per source IP within a time window.
#[derive(Debug, Clone)]
struct PortScanTracker {
    per_src: FxHashMap<IpAddr, (u64, FxHashSet<u16>)>, // (window_start_secs, unique_ports)
    window_secs: u64,
}

impl Default for PortScanTracker {
    fn default() -> Self {
        Self {
            per_src: FxHashMap::default(),
            window_secs: 10, // 10-second detection window
        }
    }
}

impl PortScanTracker {
    /// Check if src_ip has exceeded the port scan threshold. Returns true if exceeded.
    fn check(&mut self, src_ip: IpAddr, dst_port: u16, now_secs: u64, threshold: u32) -> bool {
        if threshold == 0 {
            return false;
        }
        let entry = self
            .per_src
            .entry(src_ip)
            .or_insert_with(|| (now_secs, FxHashSet::default()));
        // Reset window if expired
        if now_secs.saturating_sub(entry.0) >= self.window_secs {
            entry.0 = now_secs;
            entry.1.clear();
        }
        entry.1.insert(dst_port);
        entry.1.len() as u32 > threshold
    }

    /// Remove entries with empty sets (periodic cleanup).
    fn cleanup(&mut self, now_secs: u64) {
        self.per_src.retain(|_, (start, ports)| {
            now_secs.saturating_sub(*start) < self.window_secs && !ports.is_empty()
        });
    }
}

/// Tracks unique destination IPs per source IP within a time window.
#[derive(Debug, Clone)]
struct IpSweepTracker {
    per_src: FxHashMap<IpAddr, (u64, FxHashSet<IpAddr>)>, // (window_start_secs, unique_dst_ips)
    window_secs: u64,
}

impl Default for IpSweepTracker {
    fn default() -> Self {
        Self {
            per_src: FxHashMap::default(),
            window_secs: 10, // 10-second detection window
        }
    }
}

impl IpSweepTracker {
    /// Check if src_ip has exceeded the IP sweep threshold. Returns true if exceeded.
    fn check(&mut self, src_ip: IpAddr, dst_ip: IpAddr, now_secs: u64, threshold: u32) -> bool {
        if threshold == 0 {
            return false;
        }
        let entry = self
            .per_src
            .entry(src_ip)
            .or_insert_with(|| (now_secs, FxHashSet::default()));
        // Reset window if expired
        if now_secs.saturating_sub(entry.0) >= self.window_secs {
            entry.0 = now_secs;
            entry.1.clear();
        }
        entry.1.insert(dst_ip);
        entry.1.len() as u32 > threshold
    }

    /// Remove entries with empty sets (periodic cleanup).
    fn cleanup(&mut self, now_secs: u64) {
        self.per_src.retain(|_, (start, ips)| {
            now_secs.saturating_sub(*start) < self.window_secs && !ips.is_empty()
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SynCookieValidatedKey {
    zone_id: u16,
    tuple: SynCookieTuple,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedEntry {
    key: SynCookieValidatedKey,
    expires_secs: u64,
    age: u64,
}

#[derive(Clone, Copy, Debug)]
struct SynCookieValidatedSet {
    entries: [Option<SynCookieValidatedEntry>; SYN_COOKIE_VALIDATED_CACHE_WAYS],
}

impl Default for SynCookieValidatedSet {
    fn default() -> Self {
        Self {
            entries: [None; SYN_COOKIE_VALIDATED_CACHE_WAYS],
        }
    }
}

#[derive(Debug, Clone)]
struct SynCookieValidatedCache {
    sets: Box<[SynCookieValidatedSet]>,
    ttl_secs: u64,
    hash_keys: [u64; 2],
    len: usize,
    clock: u64,
}

impl Default for SynCookieValidatedCache {
    fn default() -> Self {
        Self::new(
            SYN_COOKIE_VALIDATED_CACHE_CAPACITY,
            SYN_COOKIE_VALIDATED_CACHE_TTL_SECS,
        )
    }
}

impl SynCookieValidatedCache {
    fn new(capacity: usize, ttl_secs: u64) -> Self {
        let set_count = capacity.div_ceil(SYN_COOKIE_VALIDATED_CACHE_WAYS);
        Self {
            sets: vec![SynCookieValidatedSet::default(); set_count].into_boxed_slice(),
            ttl_secs,
            hash_keys: [0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908],
            len: 0,
            clock: 0,
        }
    }

    fn insert(&mut self, zone_id: u16, tuple: SynCookieTuple, now_secs: u64) {
        if self.sets.is_empty() {
            return;
        }
        let key = SynCookieValidatedKey { zone_id, tuple };
        let set_index = self.set_index(&key);
        self.clock = self.clock.wrapping_add(1);
        let set = &mut self.sets[set_index];
        let new_entry = SynCookieValidatedEntry {
            key,
            expires_secs: now_secs.saturating_add(self.ttl_secs),
            age: self.clock,
        };

        let mut empty_or_expired = None;
        let mut oldest_index = 0;
        let mut oldest_age = u64::MAX;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            match set.entries[index] {
                Some(entry) if entry.key == key => {
                    set.entries[index] = Some(new_entry);
                    return;
                }
                Some(entry) if entry.expires_secs <= now_secs => {
                    empty_or_expired.get_or_insert(index);
                }
                Some(entry) => {
                    if entry.age < oldest_age {
                        oldest_age = entry.age;
                        oldest_index = index;
                    }
                }
                None => {
                    empty_or_expired.get_or_insert(index);
                }
            }
        }

        let replace_index = empty_or_expired.unwrap_or(oldest_index);
        if set.entries[replace_index].is_none() {
            self.len += 1;
        }
        set.entries[replace_index] = Some(new_entry);
    }

    fn take_valid(&mut self, zone_id: u16, tuple: SynCookieTuple, now_secs: u64) -> bool {
        if self.sets.is_empty() {
            return false;
        }
        let key = SynCookieValidatedKey { zone_id, tuple };
        let set_index = self.set_index(&key);
        let set = &mut self.sets[set_index];
        let mut valid = false;

        for index in 0..SYN_COOKIE_VALIDATED_CACHE_WAYS {
            let Some(entry) = set.entries[index] else {
                continue;
            };
            if entry.key == key {
                valid = entry.expires_secs > now_secs;
                set.entries[index] = None;
                self.len = self.len.saturating_sub(1);
                break;
            }
            if entry.expires_secs <= now_secs {
                set.entries[index] = None;
                self.len = self.len.saturating_sub(1);
            }
        }

        valid
    }

    fn set_hash_keys(&mut self, hash_keys: [u64; 2]) {
        if self.hash_keys != hash_keys {
            self.hash_keys = hash_keys;
            self.clear();
        }
    }

    fn clear(&mut self) {
        for set in self.sets.iter_mut() {
            *set = SynCookieValidatedSet::default();
        }
        self.len = 0;
        self.clock = 0;
    }

    fn set_index(&self, key: &SynCookieValidatedKey) -> usize {
        debug_assert!(!self.sets.is_empty());
        (self.key_hash(key) as usize) % self.sets.len()
    }

    fn key_hash(&self, key: &SynCookieValidatedKey) -> u64 {
        let mut sip = SipHash24::new(self.hash_keys[0], self.hash_keys[1]);
        sip.write_u16(key.zone_id);
        sip.write_ip(key.tuple.src_ip);
        sip.write_ip(key.tuple.dst_ip);
        sip.write_u16(key.tuple.src_port);
        sip.write_u16(key.tuple.dst_port);
        sip.finish()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.sets.len() * SYN_COOKIE_VALIDATED_CACHE_WAYS
    }

    #[cfg(test)]
    fn debug_set_index(&self, zone_id: u16, tuple: SynCookieTuple) -> Option<usize> {
        if self.sets.is_empty() {
            return None;
        }
        Some(self.set_index(&SynCookieValidatedKey { zone_id, tuple }))
    }
}

/// Per-zone screen state with mutable rate counters and advanced trackers.
pub(crate) struct ScreenState {
    profiles: FxHashMap<String, ScreenProfile>, // zone_name -> profile
    // Per-zone rate counters
    icmp_counters: FxHashMap<String, RateCounter>,
    udp_counters: FxHashMap<String, RateCounter>,
    syn_counters: FxHashMap<String, RateCounter>,
    syn_cookie_active_until_secs: FxHashMap<String, u64>,
    syn_cookie_codec: Option<SynCookieCodec>,
    syn_cookie_validated: SynCookieValidatedCache,
    // Advanced screen trackers (shared across all zones since they track per-IP)
    session_limits: SessionLimitTracker,
    port_scan: PortScanTracker,
    ip_sweep: IpSweepTracker,
    last_cleanup_secs: u64,
}

impl ScreenState {
    pub fn new() -> Self {
        Self {
            profiles: FxHashMap::default(),
            icmp_counters: FxHashMap::default(),
            udp_counters: FxHashMap::default(),
            syn_counters: FxHashMap::default(),
            syn_cookie_active_until_secs: FxHashMap::default(),
            syn_cookie_codec: None,
            syn_cookie_validated: SynCookieValidatedCache::default(),
            session_limits: SessionLimitTracker::default(),
            port_scan: PortScanTracker::default(),
            ip_sweep: IpSweepTracker::default(),
            last_cleanup_secs: 0,
        }
    }

    /// Replace all screen profiles (called on config update).
    pub fn update_profiles(&mut self, profiles: FxHashMap<String, ScreenProfile>) {
        // Clear rate counters for zones that no longer have profiles
        self.icmp_counters.retain(|k, _| profiles.contains_key(k));
        self.udp_counters.retain(|k, _| profiles.contains_key(k));
        self.syn_counters.retain(|k, _| profiles.contains_key(k));
        self.syn_cookie_active_until_secs
            .retain(|k, _| profiles.contains_key(k));
        for zone in profiles.keys() {
            self.icmp_counters.entry(zone.clone()).or_default();
            self.udp_counters.entry(zone.clone()).or_default();
            self.syn_counters.entry(zone.clone()).or_default();
            self.syn_cookie_active_until_secs
                .entry(zone.clone())
                .or_insert(0);
        }
        self.profiles = profiles;
    }

    /// Publish the cluster-wide SYN-cookie master key into this worker's screen
    /// state. Until HA-safe publication is wired, production snapshots leave this
    /// unset and SYN-cookie mode fails closed instead of minting local-only
    /// cookies.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update_syn_cookie_master_key(&mut self, master_key: Option<[u8; 16]>) {
        if let Some(master_key) = master_key {
            let codec = SynCookieCodec::new(master_key);
            self.syn_cookie_validated
                .set_hash_keys(codec.cache_hash_keys());
            self.syn_cookie_codec = Some(codec);
        } else {
            self.syn_cookie_codec = None;
            self.syn_cookie_validated.clear();
        }
    }

    /// Returns true if any zone has a screen profile configured.
    pub fn has_profiles(&self) -> bool {
        !self.profiles.is_empty()
    }

    /// Run all screen checks for a packet arriving on the given zone.
    /// Returns `ScreenVerdict::Pass` if the packet is clean, or
    /// `ScreenVerdict::Drop(reason)` if it should be dropped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn check_packet(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        self.check_packet_with_zone_id(zone, 0, pkt, now_secs)
    }

    /// Run all screen checks with the stable numeric zone id available to
    /// SYN-cookie MACs. `check_packet` remains for callers/tests that do not
    /// need cookie mode.
    pub fn check_packet_with_zone_id(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        let profile = match self.profiles.get(zone) {
            Some(p) => p.clone(), // clone to avoid borrow issues with &mut self
            None => return ScreenVerdict::Pass,
        };

        // --- Stateless checks ---

        // LAND attack: src_ip == dst_ip AND src_port == dst_port
        if profile.land && pkt.src_ip == pkt.dst_ip && pkt.src_port == pkt.dst_port {
            return ScreenVerdict::Drop("land-attack");
        }

        // TCP-specific stateless checks.
        //
        // Outer guard `!is_fragment || is_first_fragment` mirrors the
        // BPF #853 defense (#1137 / Copilot review): subsequent
        // fragments don't carry the L4 header, so `tcp_flags` is
        // unreliable for them. Without this guard a subsequent
        // fragment whose payload bytes happen to look like flag bits
        // could falsely trip syn_fin / no_flag / fin_no_ack / winnuke
        // / syn_frag. First-fragments DO carry the TCP header, so
        // they pass through the guard and the SYN-centric checks
        // (including syn_frag) fire correctly.
        if pkt.protocol == PROTO_TCP && (!pkt.is_fragment || pkt.is_first_fragment) {
            let tf = pkt.tcp_flags;

            // SYN+FIN
            if profile.syn_fin && (tf & TCP_SYN) != 0 && (tf & TCP_FIN) != 0 {
                return ScreenVerdict::Drop("tcp-syn-fin");
            }

            // No-flag (null scan)
            if profile.no_flag && tf == 0 {
                return ScreenVerdict::Drop("tcp-no-flag");
            }

            // FIN without ACK
            if profile.fin_no_ack && (tf & TCP_FIN) != 0 && (tf & TCP_ACK) == 0 {
                return ScreenVerdict::Drop("tcp-fin-no-ack");
            }

            // WinNuke: URG flag to port 139
            if profile.winnuke && (tf & TCP_URG) != 0 && pkt.dst_port == 139 {
                return ScreenVerdict::Drop("winnuke");
            }

            // #1137: SYN-fragment — TCP SYN on a first-fragment is the
            // fragmentation-based attack pattern. The outer guard
            // already excludes subsequent fragments; this check fires
            // on first-fragment + SYN, which is the actual attack.
            if profile.syn_frag && (tf & TCP_SYN) != 0 && pkt.is_first_fragment {
                return ScreenVerdict::Drop("syn-frag");
            }
        }

        // Ping of Death: oversized ICMP
        if profile.ping_death
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
            && pkt.pkt_len as u32 > 65535
        {
            return ScreenVerdict::Drop("ping-of-death");
        }

        // Teardrop: overlapping IP fragments (IPv4 only)
        // Non-first fragment with tiny payload (< 8 bytes)
        if profile.teardrop && pkt.addr_family == libc::AF_INET as u8 && pkt.is_fragment {
            let frag_offset = pkt.ip_frag_off & 0x1FFF;
            if frag_offset > 0 {
                let hdr_len = (pkt.ip_ihl as u16) * 4;
                if pkt.ip_total_len > hdr_len {
                    let payload = pkt.ip_total_len - hdr_len;
                    if payload < 8 {
                        return ScreenVerdict::Drop("teardrop");
                    }
                }
            }
        }

        // ICMP fragment: any fragmented ICMP packet
        if profile.icmp_fragment
            && pkt.is_fragment
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
        {
            return ScreenVerdict::Drop("icmp-fragment");
        }

        // IP source route option: IPv4 with IHL > 5 (options present)
        if profile.source_route && pkt.addr_family == libc::AF_INET as u8 && pkt.ip_ihl > 5 {
            return ScreenVerdict::Drop("ip-source-route");
        }

        // --- Rate-based flood checks ---

        // ICMP flood
        if profile.icmp_flood_threshold > 0
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
        {
            if let Some(counter) = self.icmp_counters.get_mut(zone) {
                if counter.increment(now_secs, profile.icmp_flood_threshold) {
                    return ScreenVerdict::Drop("icmp-flood");
                }
            }
        }

        // UDP flood
        if profile.udp_flood_threshold > 0 && pkt.protocol == PROTO_UDP {
            if let Some(counter) = self.udp_counters.get_mut(zone) {
                if counter.increment(now_secs, profile.udp_flood_threshold) {
                    return ScreenVerdict::Drop("udp-flood");
                }
            }
        }

        // SYN flood: count TCP SYN (without ACK) per zone
        if profile.syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            if (tf & TCP_SYN) != 0 && (tf & TCP_ACK) == 0 {
                let syn_cookie_validated = profile.syn_cookie
                    && self.syn_cookie_validated.take_valid(
                        zone_id,
                        SynCookieTuple::from_packet(pkt),
                        now_secs,
                    );
                if !syn_cookie_validated {
                    if let Some(counter) = self.syn_counters.get_mut(zone)
                        && counter.increment(now_secs, profile.syn_flood_threshold)
                    {
                        if profile.syn_cookie {
                            if let Some(active_until) =
                                self.syn_cookie_active_until_secs.get_mut(zone)
                            {
                                *active_until = now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
                            } else {
                                debug_assert!(
                                    false,
                                    "screen profile update prepopulates SYN-cookie active state"
                                );
                            }
                            let Some(codec) = self.syn_cookie_codec else {
                                return ScreenVerdict::Drop("syn-cookie-unavailable");
                            };
                            let full_epoch =
                                SynCookieCodec::full_epoch_from_monotonic_secs(now_secs);
                            let cookie_isn = codec.mint_isn(
                                SynCookieTuple::from_packet(pkt),
                                zone_id,
                                full_epoch,
                                pkt.tcp_mss,
                            );
                            return ScreenVerdict::SynCookieChallenge(SynCookieChallenge {
                                cookie_isn,
                                peer_mss: pkt.tcp_mss,
                            });
                        }
                        return ScreenVerdict::Drop("syn-flood");
                    }
                }
            }
        }

        // --- Advanced stateful checks ---
        // These run only on TCP SYN (new connection attempts) to avoid
        // false positives on established traffic.
        if pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            let is_syn = (tf & TCP_SYN) != 0 && (tf & TCP_ACK) == 0;

            // Port scan detection: count unique dst ports per src IP
            if is_syn && profile.port_scan_threshold > 0 {
                if self.port_scan.check(
                    pkt.src_ip,
                    pkt.dst_port,
                    now_secs,
                    profile.port_scan_threshold,
                ) {
                    return ScreenVerdict::Drop("port-scan");
                }
            }
        }

        // IP sweep detection: count unique dst IPs per src IP (all protocols)
        if profile.ip_sweep_threshold > 0 {
            if self
                .ip_sweep
                .check(pkt.src_ip, pkt.dst_ip, now_secs, profile.ip_sweep_threshold)
            {
                return ScreenVerdict::Drop("ip-sweep");
            }
        }

        // Per-IP session limits: check before session creation
        if profile.session_limit_src > 0 {
            if self
                .session_limits
                .check_src(pkt.src_ip, profile.session_limit_src)
            {
                return ScreenVerdict::Drop("session-limit-src");
            }
        }
        if profile.session_limit_dst > 0 {
            if self
                .session_limits
                .check_dst(pkt.dst_ip, profile.session_limit_dst)
            {
                return ScreenVerdict::Drop("session-limit-dst");
            }
        }

        // Periodic cleanup of tracker state (every 30 seconds)
        if now_secs.saturating_sub(self.last_cleanup_secs) >= 30 {
            self.port_scan.cleanup(now_secs);
            self.ip_sweep.cleanup(now_secs);
            self.last_cleanup_secs = now_secs;
        }

        ScreenVerdict::Pass
    }

    /// Validate a returning SYN-cookie ACK only after the caller has already
    /// established that no normal session matched. This preserves established
    /// ACK traffic and prevents random ACKs from installing sessions while a
    /// cookie flood is active.
    pub fn validate_syn_cookie_ack_on_session_miss(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> SynCookieAckVerdict {
        let Some(profile) = self.profiles.get(zone) else {
            return SynCookieAckVerdict::NotApplicable;
        };
        if !profile.syn_cookie || profile.syn_flood_threshold == 0 || pkt.protocol != PROTO_TCP {
            return SynCookieAckVerdict::NotApplicable;
        }
        let flags = pkt.tcp_flags;
        if (flags & TCP_ACK) == 0 || (flags & TCP_SYN) != 0 {
            return SynCookieAckVerdict::NotApplicable;
        }
        if self
            .syn_cookie_active_until_secs
            .get(zone)
            .copied()
            .is_none_or(|until| until <= now_secs)
        {
            return SynCookieAckVerdict::NotApplicable;
        }
        if (flags & (TCP_FIN | TCP_RST)) != 0 {
            return SynCookieAckVerdict::Invalid;
        }
        let Some(codec) = self.syn_cookie_codec else {
            return SynCookieAckVerdict::Invalid;
        };
        let cookie_isn = pkt.tcp_ack.wrapping_sub(1);
        let current_epoch = SynCookieCodec::full_epoch_from_monotonic_secs(now_secs);
        let tuple = SynCookieTuple::from_packet(pkt);
        if codec
            .validate_isn(tuple, zone_id, current_epoch, cookie_isn)
            .is_some()
        {
            self.syn_cookie_validated.insert(zone_id, tuple, now_secs);
            SynCookieAckVerdict::Validated
        } else {
            SynCookieAckVerdict::Invalid
        }
    }

    #[cfg(test)]
    fn syn_cookie_validated_len(&self) -> usize {
        self.syn_cookie_validated.len()
    }

    #[cfg(test)]
    fn syn_cookie_active_zone_count(&self) -> usize {
        self.syn_cookie_active_until_secs.len()
    }

    /// Notify the screen state that a new session was created. This increments
    /// per-IP session counters for session limiting.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_created(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        self.session_limits.session_created(src_ip, dst_ip);
    }

    /// Notify the screen state that a session has expired. This decrements
    /// per-IP session counters for session limiting.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_expired(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        self.session_limits.session_expired(src_ip, dst_ip);
    }

    /// Returns true if any zone has session limits, port scan, or IP sweep enabled.
    #[allow(dead_code)]
    pub fn has_advanced_features(&self) -> bool {
        self.profiles.values().any(|p| {
            p.session_limit_src > 0
                || p.session_limit_dst > 0
                || p.port_scan_threshold > 0
                || p.ip_sweep_threshold > 0
        })
    }
}

/// Extract screen-relevant fields from raw packet bytes and metadata.
/// This avoids full packet parsing — just reads the fields needed for checks.
pub(crate) fn extract_screen_info(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    pkt_len: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    l3_offset: usize,
) -> ScreenPacketInfo {
    let mut info = ScreenPacketInfo {
        addr_family,
        protocol,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
    };

    let mut tcp_offset: Option<usize> = None;

    if addr_family == libc::AF_INET as u8 && l3_offset + 20 <= frame.len() {
        // IPv4: extract IHL, total_len, frag_off from the fixed 20-byte
        // base header. frag_off is bytes 6-7, big-endian.
        let ip_hdr = &frame[l3_offset..];
        info.ip_ihl = ip_hdr[0] & 0x0F;
        info.ip_total_len = u16::from_be_bytes([ip_hdr[2], ip_hdr[3]]);
        info.ip_frag_off = u16::from_be_bytes([ip_hdr[6], ip_hdr[7]]);
        // Fragment if MF bit (0x2000) set OR fragment offset (0x1FFF) > 0.
        // First fragment: MF=1 AND offset==0 (#1137, mirrors BPF #866).
        info.is_fragment = (info.ip_frag_off & 0x3FFF) != 0;
        info.is_first_fragment =
            (info.ip_frag_off & 0x2000) != 0 && (info.ip_frag_off & 0x1FFF) == 0;
        tcp_offset = Some(l3_offset + (info.ip_ihl as usize) * 4);
    } else if addr_family == libc::AF_INET6 as u8 && l3_offset + 40 <= frame.len() {
        // IPv6: walk the extension header chain looking for
        // NEXTHDR_FRAGMENT (44). Fixed IPv6 base header is 40 bytes.
        // We bound the walk to MAX_EXT_HDRS=8 like the BPF parser.
        //
        // Parity note (#1137 / Codex round-1): if the chain is
        // truncated (out-of-bounds before we find a FRAGMENT
        // header), we silently `break` and leave is_first_fragment
        // at its default `false`. The BPF `parse_ipv6hdr` returns
        // -1 on the same condition, causing the packet to be
        // dropped earlier in the pipeline. On the userspace-dp
        // path the upstream metadata parser (try_parse_metadata)
        // should already have rejected malformed IPv6 packets
        // before they reach extract_screen_info, so the parity
        // gap is theoretical. If a SYN-bearing IPv6 frame with a
        // truncated FRAGMENT header somehow reaches the screen
        // layer, it would pass syn_frag — operators relying on
        // that defense should keep the BPF screen path enabled
        // upstream of userspace-dp.
        const NEXTHDR_HOP: u8 = 0;
        const NEXTHDR_ROUTING: u8 = 43;
        const NEXTHDR_FRAGMENT: u8 = 44;
        const NEXTHDR_DEST: u8 = 60;
        const NEXTHDR_AUTH: u8 = 51;
        let mut nexthdr = frame[l3_offset + 6];
        let mut offset = l3_offset + 40;
        for _ in 0..8 {
            match nexthdr {
                NEXTHDR_HOP | NEXTHDR_ROUTING | NEXTHDR_DEST => {
                    if offset + 2 > frame.len() {
                        break;
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 1) * 8;
                }
                NEXTHDR_AUTH => {
                    if offset + 2 > frame.len() {
                        break;
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 2) * 4;
                }
                NEXTHDR_FRAGMENT => {
                    if offset + 8 > frame.len() {
                        break;
                    }
                    // IPv6 frag_off layout (big-endian u16 at offset+2):
                    //   offset (13 bits, top) | reserved (2 bits) | M (1 bit, lowest)
                    // Mirrors BPF #866: MF=0x1, offset=0xFFF8.
                    let frag_off = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    info.ip_frag_off = frag_off;
                    info.is_fragment = (frag_off & 0x1) != 0 || (frag_off & 0xFFF8) != 0;
                    info.is_first_fragment = (frag_off & 0x1) != 0 && (frag_off & 0xFFF8) == 0;
                    if frame[offset] == PROTO_TCP {
                        tcp_offset = Some(offset + 8);
                    }
                    break;
                }
                PROTO_TCP => {
                    tcp_offset = Some(offset);
                    break;
                }
                _ => break,
            }
        }
    }

    if protocol == PROTO_TCP
        && (!info.is_fragment || info.is_first_fragment)
        && let Some(tcp_start) = tcp_offset
        && tcp_start + 20 <= frame.len()
    {
        let tcp = &frame[tcp_start..];
        info.tcp_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        info.tcp_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        if data_offset >= 20 && tcp.len() >= data_offset {
            let mut pos = 20;
            while pos < data_offset {
                let kind = tcp[pos];
                if kind == 0 {
                    break;
                }
                if kind == 1 {
                    pos += 1;
                    continue;
                }
                if pos + 2 > data_offset {
                    break;
                }
                let opt_len = tcp[pos + 1] as usize;
                if opt_len < 2 || pos + opt_len > data_offset {
                    break;
                }
                if kind == 2 && opt_len == 4 {
                    info.tcp_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
                    break;
                }
                pos += opt_len;
            }
        }
    }

    info
}

#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
