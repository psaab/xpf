//! #9950 (F-035): stateful IPv4/IPv6 fragment-overlap tracker.
//!
//! The stateless screens (`screen/stateless.rs`) inspect only the FIRST fragment's
//! L4 flags (`check_tcp_flag_screens` skips non-first) and explicitly state they
//! are NOT overlap detectors. Enforcement (zone policy `application any`, screens,
//! NAT) therefore runs on bytes a later overlapping fragment can rewrite before the
//! receiver reassembles — an IDS/enforcement-evasion primitive.
//!
//! This tracker closes the ordering gap by dropping overlapping fragments (RFC 5722 /
//! Juniper `tear-drop` semantics: "when the sum of the offset and size of one
//! fragmented packet differs from that of the next, the packets overlap").
//!
//! Key is the RECEIVER's reassembly key — `(family, src, dst, ident, proto)` for IPv4,
//! `(family, src, dst, ident)` for IPv6 (protocol pinned to 0, since the receiver
//! reassembles on src/dst/ident only, RFC 8200 §4.5, while the Fragment Header's Next
//! Header is vary-able) — WITHOUT `FragAuthority`. Including the ingress domain would
//! miss ECMP/LAG-split same-datagram fragments that still reassemble together at the
//! receiver. The cost is a documented squat residual: any ingress can plant ranges
//! under a victim key (strictly weaker than status-quo reassembly corruption, which
//! needs no state; alias fails CLOSED here — one datagram dropped — vs fail-OPEN for
//! `FragAssoc` permit-inherit).
//!
//! Design (mirrors `fragment_assoc` where the failure direction matches, diverges
//! where it does not):
//!   * SHARDED LRU, fixed cap (16 x 64 = 1024 datagrams), prune-expired-first on
//!     insert (#5447), cross-worker Arc-shared via `Nat64State` (threaded across
//!     reloads so a commit does not open a 2s evasion window).
//!   * TTL: 2s idle (refreshed on record) + 10s absolute (never refreshed by a
//!     record for the SAME datagram? No — a record IS a new fragment of the same
//!     datagram re-admitted through enforcement, so it MAY extend? See below).
//!     Actually: absolute is measured from FIRST sighting (`created_ns`), never
//!     refreshed by later fragments of the same datagram (unlike `FragAssoc` where
//!     a re-install is a fresh admission — here every fragment is already admitted,
//!     so refreshing would let a sustained fragment stream hold the entry open).
//!     Hmm — but a legitimate 44-fragment datagram arrives within ms, far under 10s,
//!     so absolute never fires benignly. Attack residue (sustained same-key stream)
//!     is reclaimed at 10s.
//!   * DROP-ONLY: entries never inherit permit/translation, so NO config-generation
//!     or owner-RG fence is needed (unlike `FragAssoc`). Overlap is a wire property,
//!     not a verdict.
//!   * RANGES: inline `[(u32,u32); 8]` (no per-packet alloc, #2211), coalesced on
//!     insert (in-order datagrams hold 1 range, so 44-fragment benign flows never
//!     overflow). Overflow (9th disjoint range) fails CLOSED (drop + counter) —
//!     evict-oldest would be a 9-fragment bypass.
//!   * RECORD-ON-EVERYTHING (first AND non-first): required for tail-then-first order
//!     (the tail must plant its range so the later head overlaps it). This breaks the
//!     `FragAssoc` first-only-install DoS bound by design; the bound here is the shard
//!     cap + TTL + coalescing, with flood-evict documented as a transient under-detect
//!     window (same class as #7054).
//!
//! Hook: ONE site post-screen + IPsec, pre-flow-cache, post-decap (inner), with a cheap
//! `is_any_fragment` gate so unfragmented packets pay only a frag-word check (v4) or a
//! base-next-header pre-gate + bounded walk for ext-header packets (v6, via the shared
//! `#6435` walker). Atomic fragments (v4 `0x3FFF==0`, v6 offset==0&M==0) skip the table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

/// Overlap drops (strict overlap `max(starts) < min(ends)`). Read as a delta in tests.
pub(crate) static FRAG_OVERLAP_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Range-cap overflow drops (9th disjoint range, fail-closed). Separate from overlap
/// so a benign-large-datagram regression is distinguishable from attack overlap.
pub(crate) static FRAG_OVERLAP_OVERFLOW_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Absolute-lifetime evictions (sustained same-key streams). Mirrors
/// `FRAG_MAX_LIFETIME_EVICTIONS` semantics: only idle-fresh entries pruned for age count.
pub(crate) static FRAG_OVERLAP_MAX_LIFETIME_EVICTIONS: AtomicU64 = AtomicU64::new(0);

pub(crate) const OVERLAP_SHARDS: usize = 16;
pub(crate) const OVERLAP_CAP_PER_SHARD: usize = 64;
pub(crate) const OVERLAP_TTL_NS: u64 = 2_000_000_000;
pub(crate) const OVERLAP_MAX_LIFETIME_NS: u64 = 10_000_000_000;
pub(crate) const OVERLAP_MAX_RANGES: usize = 8;

/// Receiver's reassembly key. `protocol` is the IPv4 Protocol byte; for IPv6 it is
/// always 0 (dropped from the key — see module docs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct OverlapKey {
    pub(crate) addr_family: u8,
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) ident: u32,
    pub(crate) protocol: u8,
}

#[derive(Clone, Copy)]
struct OverlapEntry {
    key: OverlapKey,
    ranges: [(u32, u32); OVERLAP_MAX_RANGES],
    len: u8,
    deadline_ns: u64,
    created_ns: u64,
}

/// Cross-worker overlap tracker. Cheap to `Clone` (Arc-backed shards).
#[derive(Clone)]
pub(crate) struct OverlapTracker {
    shards: Arc<Vec<Mutex<Vec<OverlapEntry>>>>,
}

impl std::fmt::Debug for OverlapTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OverlapTracker")
    }
}

impl Default for OverlapTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn ip_octets(ip: IpAddr, out: &mut [u8; 16]) -> usize {
    match ip {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            out.copy_from_slice(&v6.octets());
            16
        }
    }
}

/// FNV-1a over the coarse `(family, src, dst, ident)` digest (protocol deliberately
/// excluded so v4 same-datagram candidates with varying proto — hostile — still
/// co-locate; membership is by full-key equality). Same shape as `frag_shard_index`.
pub(crate) fn overlap_shard_index(key: &OverlapKey) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    mix(key.addr_family);
    let mut buf = [0u8; 16];
    let n = ip_octets(key.src, &mut buf);
    for &b in &buf[..n] {
        mix(b);
    }
    let n = ip_octets(key.dst, &mut buf);
    for &b in &buf[..n] {
        mix(b);
    }
    for b in key.ident.to_be_bytes() {
        mix(b);
    }
    (h as usize) & (OVERLAP_SHARDS - 1)
}

#[inline]
fn overlap_entry_live(e: &OverlapEntry, now_ns: u64) -> bool {
    let idle_live = e.deadline_ns > now_ns;
    let absolutely_live = now_ns.saturating_sub(e.created_ns) < OVERLAP_MAX_LIFETIME_NS;
    if idle_live && !absolutely_live {
        FRAG_OVERLAP_MAX_LIFETIME_EVICTIONS.fetch_add(1, Ordering::Relaxed);
    }
    idle_live && absolutely_live
}

impl OverlapTracker {
    pub(crate) fn new() -> Self {
        let mut shards = Vec::with_capacity(OVERLAP_SHARDS);
        for _ in 0..OVERLAP_SHARDS {
            shards.push(Mutex::new(Vec::with_capacity(OVERLAP_CAP_PER_SHARD)));
        }
        Self {
            shards: Arc::new(shards),
        }
    }

    /// Check `new_range` against prior ranges for `key`; on no overlap, record it
    /// (coalescing adjacency) and return `false`. On strict overlap OR range-cap
    /// overflow OR empty range, return `true` (drop) without recording.
    pub(crate) fn check_and_record(
        &self,
        key: OverlapKey,
        start: u32,
        end: u32,
        now_ns: u64,
    ) -> bool {
        // Empty (or inverted) ranges carry no data; fail closed (teardrop screens
        // already drop zero-payload non-firsts when armed — this covers screens-off).
        if start >= end {
            FRAG_OVERLAP_DROPPED.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let idx = overlap_shard_index(&key);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shard.retain(|e| overlap_entry_live(e, now_ns));
        if let Some(pos) = shard.iter().position(|e| e.key == key) {
            // Strict overlap: max(starts) < min(ends). Adjacency (end==start) is NOT overlap.
            for i in 0..(shard[pos].len as usize) {
                let (rs, re) = shard[pos].ranges[i];
                if start.max(rs) < end.min(re) {
                    FRAG_OVERLAP_DROPPED.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
            // No overlap: insert + coalesce adjacency.
            let mut e = shard.remove(pos);
            let mut tmp = [(0u32, 0u32); OVERLAP_MAX_RANGES + 1];
            tmp[..(e.len as usize)].copy_from_slice(&e.ranges[..(e.len as usize)]);
            tmp[e.len as usize] = (start, end);
            let n = e.len as usize + 1;
            // Insertion sort by start (n <= 9, tiny).
            for i in 1..n {
                let mut j = i;
                while j > 0 && tmp[j].0 < tmp[j - 1].0 {
                    tmp.swap(j, j - 1);
                    j -= 1;
                }
            }
            // Merge adjacent (end==start). No overlaps remain (checked above).
            let mut out = [(0u32, 0u32); OVERLAP_MAX_RANGES];
            let mut out_len = 0usize;
            let mut cur = tmp[0];
            for &nxt in tmp.iter().take(n).skip(1) {
                if nxt.0 <= cur.1 {
                    // Adjacent (==) or subsumed (should not happen post-overlap-check,
                    // but clamp defensively): extend.
                    if nxt.1 > cur.1 {
                        cur.1 = nxt.1;
                    }
                } else {
                    if out_len >= OVERLAP_MAX_RANGES {
                        // Overflow: fail closed, do NOT record (evict-oldest would be bypassable).
                        FRAG_OVERLAP_OVERFLOW_DROPPED.fetch_add(1, Ordering::Relaxed);
                        // Restore the entry (without the new range) to preserve LRU position.
                        shard.push(e);
                        return true;
                    }
                    out[out_len] = cur;
                    out_len += 1;
                    cur = nxt;
                }
            }
            if out_len >= OVERLAP_MAX_RANGES {
                FRAG_OVERLAP_OVERFLOW_DROPPED.fetch_add(1, Ordering::Relaxed);
                shard.push(e);
                return true;
            }
            out[out_len] = cur;
            out_len += 1;
            e.ranges = out;
            e.len = out_len as u8;
            e.deadline_ns = now_ns.saturating_add(OVERLAP_TTL_NS);
            // created_ns NEVER refreshed (absolute bound from first sighting).
            shard.push(e);
            return false;
        }
        // New datagram: prune-first already done; evict oldest live only if still at cap.
        if shard.len() >= OVERLAP_CAP_PER_SHARD {
            shard.remove(0);
        }
        let mut ranges = [(0u32, 0u32); OVERLAP_MAX_RANGES];
        ranges[0] = (start, end);
        shard.push(OverlapEntry {
            key,
            ranges,
            len: 1,
            deadline_ns: now_ns.saturating_add(OVERLAP_TTL_NS),
            created_ns: now_ns,
        });
        false
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }
}

/// Parse the overlap `(key, start, end)` from an L3-relative packet slice.
/// Returns `None` for unfragmented/atomic/truncated packets (no table ops).
/// Clamps declared lengths to wire bytes; reads addrs from the slice, never meta.
pub(crate) fn overlap_fragment_range(
    l3_packet: &[u8],
    addr_family: i32,
) -> Option<(OverlapKey, u32, u32)> {
    match addr_family {
        libc::AF_INET => {
            if l3_packet.len() < 20 {
                return None;
            }
            let ihl = ((l3_packet[0] & 0x0F) as usize) * 4;
            if ihl < 20 || l3_packet.len() < ihl {
                return None;
            }
            let total_len = u16::from_be_bytes([l3_packet[2], l3_packet[3]]) as usize;
            let frag_off = u16::from_be_bytes([l3_packet[6], l3_packet[7]]);
            // Atomic (MF=0, offset=0) or unfragmented: skip.
            if (frag_off & 0x3FFF) == 0 {
                return None;
            }
            let ident = u16::from_be_bytes([l3_packet[4], l3_packet[5]]) as u32;
            let proto = l3_packet[9];
            let src = Ipv4Addr::new(l3_packet[12], l3_packet[13], l3_packet[14], l3_packet[15]);
            let dst = Ipv4Addr::new(l3_packet[16], l3_packet[17], l3_packet[18], l3_packet[19]);
            let start = ((frag_off & 0x1FFF) as u32) << 3;
            let declared = total_len.saturating_sub(ihl);
            let wire = l3_packet.len().saturating_sub(ihl);
            let len = declared.min(wire) as u32;
            let end = start.saturating_add(len);
            Some((
                OverlapKey {
                    addr_family: libc::AF_INET as u8,
                    src: IpAddr::V4(src),
                    dst: IpAddr::V4(dst),
                    ident,
                    protocol: proto,
                },
                start,
                end,
            ))
        }
        libc::AF_INET6 => {
            if l3_packet.len() < 40 {
                return None;
            }
            let walk = crate::afxdp::frame::walk_ipv6_ext_chain(l3_packet, 0);
            let frag = walk.fragment?;
            let bytes = frag.bytes?;
            let frag_off = u16::from_be_bytes([bytes[2], bytes[3]]);
            // Atomic (offset==0, M==0): whole datagram, skip.
            if (frag_off & 0xFFF9) == 0 {
                return None;
            }
            let start = (frag_off & 0xFFF8) as u32;
            let ident = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let mut src_b = [0u8; 16];
            let mut dst_b = [0u8; 16];
            src_b.copy_from_slice(&l3_packet[8..24]);
            dst_b.copy_from_slice(&l3_packet[24..40]);
            let payload_len = u16::from_be_bytes([l3_packet[4], l3_packet[5]]) as usize;
            // frag_data_off: payload-region bytes consumed up to + including frag header.
            let frag_data_off = (frag.header_offset + 8).saturating_sub(40);
            let declared = payload_len.saturating_sub(frag_data_off);
            let wire = l3_packet.len().saturating_sub(frag.header_offset + 8);
            let len = declared.min(wire) as u32;
            let end = start.saturating_add(len);
            Some((
                OverlapKey {
                    addr_family: libc::AF_INET6 as u8,
                    src: IpAddr::V6(Ipv6Addr::from(src_b)),
                    dst: IpAddr::V6(Ipv6Addr::from(dst_b)),
                    ident,
                    protocol: 0,
                },
                start,
                end,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_key() -> OverlapKey {
        OverlapKey {
            addr_family: libc::AF_INET as u8,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ident: 0xBEEF,
            protocol: 6,
        }
    }

    #[test]
    fn adjacent_ranges_do_not_overlap_9950() {
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(v4_key(), 0, 16, 1_000));
        assert!(!t.check_and_record(v4_key(), 16, 24, 2_000));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn strict_overlap_drops_both_orders_9950() {
        for (a, b) in [((0u32, 16u32), (8u32, 24u32)), ((8, 24), (0, 16))] {
            let t = OverlapTracker::new();
            FRAG_OVERLAP_DROPPED.store(0, Ordering::Relaxed);
            assert!(!t.check_and_record(v4_key(), a.0, a.1, 1_000));
            assert!(t.check_and_record(v4_key(), b.0, b.1, 2_000));
            assert_eq!(FRAG_OVERLAP_DROPPED.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn identical_retransmit_drops_9950() {
        // A byte-identical retransmit is strict overlap (max==min fails only for
        // adjacency). Dropping the duplicate is harmless (single delivery); TCP
        // retransmits mint new idents, so this never fires benignly for TCP.
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(v4_key(), 0, 16, 1_000));
        assert!(t.check_and_record(v4_key(), 0, 16, 2_000));
    }

    #[test]
    fn empty_range_drops_fail_closed_9950() {
        let t = OverlapTracker::new();
        assert!(t.check_and_record(v4_key(), 8, 8, 1_000));
        assert!(t.check_and_record(v4_key(), 16, 8, 1_000));
    }

    #[test]
    fn large_in_order_datagram_coalesces_to_one_range_9950() {
        // 44-fragment 64KB datagram, in-order adjacent 1480B chunks: coalescing keeps
        // 1 range, never overflows. Without coalescing this would need 44 slots.
        let t = OverlapTracker::new();
        let mut off = 0u32;
        for _ in 0..44 {
            assert!(
                !t.check_and_record(v4_key(), off, off + 1480, 1_000),
                "off={off}"
            );
            off += 1480;
        }
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn sparse_disjoint_overflow_drops_fail_closed_9950() {
        // 8 disjoint 8B ranges with 16B gaps (no adjacency to coalesce): fills the 8
        // slots. The 9th disjoint range overflows -> drop + counter (evict-oldest
        // would be a 9-fragment bypass).
        let t = OverlapTracker::new();
        FRAG_OVERLAP_OVERFLOW_DROPPED.store(0, Ordering::Relaxed);
        for i in 0..8u32 {
            let s = i * 24;
            assert!(!t.check_and_record(v4_key(), s, s + 8, 1_000), "i={i}");
        }
        assert!(t.check_and_record(v4_key(), 8 * 24, 8 * 24 + 8, 1_000));
        assert_eq!(FRAG_OVERLAP_OVERFLOW_DROPPED.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn v4_parse_clamps_to_wire_and_skips_atomic_9950() {
        // Atomic (MF=0, offset=0): None.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes());
        ip[6..8].copy_from_slice(&0x0000u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 61, 100]);
        ip[16..20].copy_from_slice(&[172, 16, 80, 200]);
        let mut pkt = ip.clone();
        pkt.extend_from_slice(&[0u8; 8]);
        assert!(overlap_fragment_range(&pkt, libc::AF_INET).is_none());
        // First fragment (MF=1, offset=0) with lying declared len (100) but only 8
        // wire bytes: clamped to 8 (0..8).
        let mut first = ip;
        first[2..4].copy_from_slice(&120u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        let mut pkt = first;
        pkt.extend_from_slice(&[0u8; 8]);
        let (k, s, e) = overlap_fragment_range(&pkt, libc::AF_INET).expect("first");
        assert_eq!((s, e), (0, 8));
        assert_eq!(k.ident, 0xBEEF);
        assert_eq!(k.protocol, 6);
    }

    #[test]
    fn v6_parse_drops_proto_and_sizes_via_shared_walker_9950() {
        // Base(40) + frag header(8): next=TCP(6), offset 0 M=1, ident 0x01020304,
        // payload 16B. Protocol in key must be 0 (dropped), range 0..16.
        let mut pkt = vec![0u8; 40 + 8 + 16];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&24u16.to_be_bytes());
        pkt[6] = 44;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[40] = 6;
        pkt[42..44].copy_from_slice(&0x0001u16.to_be_bytes());
        pkt[44..48].copy_from_slice(&0x01020304u32.to_be_bytes());
        let (k, s, e) = overlap_fragment_range(&pkt, libc::AF_INET6).expect("v6 first");
        assert_eq!((s, e), (0, 16));
        assert_eq!(k.protocol, 0);
        assert_eq!(k.ident, 0x01020304);
        // Same datagram with different Next Header (UDP=17) must build the SAME key
        // (proto dropped) so the overlap is still detected.
        let mut pkt2 = pkt.clone();
        pkt2[40] = 17;
        pkt2[42..44].copy_from_slice(&0x0009u16.to_be_bytes());
        let (k2, s2, e2) = overlap_fragment_range(&pkt2, libc::AF_INET6).expect("v6 tail");
        assert_eq!(k2, k);
        assert_eq!((s2, e2), (8, 24));
        let t = OverlapTracker::new();
        assert!(!t.check_and_record(k, s, e, 1_000));
        assert!(t.check_and_record(k2, s2, e2, 2_000));
        // Atomic (offset 0 M 0): None.
        let mut atomic = pkt;
        atomic[42..44].copy_from_slice(&0x0000u16.to_be_bytes());
        assert!(overlap_fragment_range(&atomic, libc::AF_INET6).is_none());
    }
}
