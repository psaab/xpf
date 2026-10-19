//! #14645/#15102: bounded reassembly of outer-fragmented tunnel datagrams.
//!
//! A tunnel endpoint is the IP host for its outer datagram, so it must
//! reassemble that datagram before decap (RFC 1122 section 3.3.2). Before
//! #14645 the GRE head reached `try_native_gre_decap_from_frame`, which
//! correctly refused a truncated inner, while tails were steered elsewhere
//! and never reassembled anywhere. #15102 is the WireGuard sibling: the
//! first fragment was claimed and failed AEAD as a truncated record, and
//! non-first fragments went to the kernel.
//!
//! This is a deliberately small, per-worker pool. It accepts only fragments
//! the caller has already identified as tunnel traffic (GRE head protocol
//! GRE / tail wire protocol GRE, or WG head UDP to a steered listener /
//! tail whose first fragment was admitted), keyed by the outer reassembly
//! identity. The upper-layer protocol is carried in the key and in the
//! completed meta, so a GRE datagram and a WG datagram that share an outer
//! identity can never splice. Bounds: at most 64 incomplete datagrams, at
//! most 64 KiB reassembled per datagram, 32 fragments per datagram, and a
//! 10-second incomplete lifetime. Every refusal is fail-closed and counted
//! in [`GRE_OUTER_FRAG_DROPS`]; a completed datagram is returned exactly
//! once as a synthetic unfragmented frame for the ordinary decap path.

use super::types::UserspaceDpMeta;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const MAX_GRE_FRAG_DATAGRAMS: usize = 64;
pub(super) const MAX_GRE_FRAG_BYTES: usize = 64 * 1024;
pub(super) const MAX_GRE_FRAGS_PER_DATAGRAM: usize = 32;
pub(super) const GRE_FRAG_TIMEOUT_NS: u64 = 10_000_000_000;

/// #14645/#15102: outer-fragmented tunnel datagrams dropped by the bounded
/// reassembly pool (overlap, oversize, capacity, timeout, or malformed).
/// Surfaced as `xpf_userspace_gre_outer_frag_drops_total`.
pub(in crate::afxdp) static GRE_OUTER_FRAG_DROPS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(in crate::afxdp) fn gre_outer_frag_counter_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn counted_drop() {
    GRE_OUTER_FRAG_DROPS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FragKey {
    family: u8,
    src: [u8; 16],
    dst: [u8; 16],
    ident: u32,
    ingress_ifindex: u32,
    vlan: u16,
    vlan_present: u8,
    upper_protocol: u8,
}

struct FragEntry {
    first_seen_ns: u64,
    last_seen_ns: u64,
    l2: Vec<u8>,
    first_meta: Option<UserspaceDpMeta>,
    head_header: Option<Vec<u8>>,
    ranges: Vec<(usize, usize)>,
    buf: Vec<u8>,
    total: Option<usize>,
    frag_count: usize,
    upper_protocol: u8,
    v6_ext_len: usize,
}
impl FragEntry {
    fn new(now_ns: u64) -> Self {
        Self {
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            l2: Vec::new(),
            first_meta: None,
            head_header: None,
            ranges: Vec::new(),
            buf: Vec::new(),
            total: None,
            frag_count: 0,
            upper_protocol: 0,
            v6_ext_len: 0,
        }
    }
}

/// Per-worker bounded pool. One worker owns one pool; no locking is needed
/// beyond the worker's single-threaded poll loop.
#[derive(Default)]
pub(super) struct GreReassembler {
    entries: HashMap<FragKey, FragEntry>,
}

struct FragInfo {
    key: FragKey,
    offset: usize,
    more: bool,
    payload_start: usize,
    payload_end: usize,
    upper_protocol: u8,
}

fn parse_fragment(frame: &[u8], meta: UserspaceDpMeta) -> Option<FragInfo> {
    parse_fragment_with_protocol(frame, meta, None)
}

fn parse_fragment_with_protocol(
    frame: &[u8],
    meta: UserspaceDpMeta,
    expected_upper: Option<u8>,
) -> Option<FragInfo> {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let ip = frame.get(l3..l3.checked_add(20)?)?;
            let ihl = ((ip[0] & 0x0f) as usize).checked_mul(4)?;
            if ihl < 20 || frame.get(l3..l3.checked_add(ihl)?).is_none() {
                return None;
            }
            let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            if total_len < ihl || l3.checked_add(total_len)? > frame.len() {
                return None;
            }
            let field = u16::from_be_bytes([ip[6], ip[7]]);
            let offset = ((field & 0x1fff) as usize).checked_mul(8)?;
            let more = field & 0x2000 != 0;
            if offset == 0 && !more {
                return None;
            }
            let upper_protocol = ip[9];
            if expected_upper.is_some_and(|want| want != upper_protocol) {
                return None;
            }
            Some(FragInfo {
                key: FragKey {
                    family: meta.addr_family,
                    src: meta.flow_src_addr,
                    dst: meta.flow_dst_addr,
                    ident: u16::from_be_bytes([ip[4], ip[5]]) as u32,
                    ingress_ifindex: meta.ingress_ifindex,
                    vlan: meta.ingress_vlan_id,
                    vlan_present: meta.ingress_vlan_present,
                    upper_protocol,
                },
                offset,
                more,
                payload_start: l3.checked_add(ihl)?,
                payload_end: l3.checked_add(total_len)?,
                upper_protocol,
            })
        }
        libc::AF_INET6 => {
            // Walk the extension chain to the Fragment header (44). The
            // payload of a non-first fragment starts after that header; the
            // upper-layer identity is the Fragment header's Next Header.
            let mut next = *frame.get(l3.checked_add(6)?)?;
            let mut off = l3.checked_add(40)?;
            for _ in 0..8 {
                match next {
                    44 => {
                        let frag = frame.get(off..off.checked_add(8)?)?;
                        let word = u16::from_be_bytes([frag[2], frag[3]]);
                        // RFC 8200: offset field is bits 3..15, in 8-octet units; M is bit 0.
                        let frag_offset = ((word & 0xfff8) as usize >> 3).checked_mul(8)?;
                        let more = word & 1 != 0;
                        if frag_offset == 0 && !more {
                            return None;
                        }
                        let payload_len =
                            u16::from_be_bytes([*frame.get(l3 + 4)?, *frame.get(l3 + 5)?]) as usize;
                        let datagram_end = l3.checked_add(40)?.checked_add(payload_len)?;
                        if datagram_end > frame.len() {
                            return None;
                        }
                        if expected_upper.is_some_and(|want| want != frag[0]) {
                            return None;
                        }
                        // AH before Fragment keeps AH identity, mirroring
                        // fragment_protocol_from_frame; such datagrams are
                        // never GRE/WG and the expected check above already
                        // rejects them for tunnel callers.
                        let upper_protocol = frag[0];
                        return Some(FragInfo {
                            key: FragKey {
                                family: meta.addr_family,
                                src: meta.flow_src_addr,
                                dst: meta.flow_dst_addr,
                                ident: u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]),
                                ingress_ifindex: meta.ingress_ifindex,
                                vlan: meta.ingress_vlan_id,
                                vlan_present: meta.ingress_vlan_present,
                                upper_protocol,
                            },
                            offset: frag_offset,
                            more,
                            payload_start: off.checked_add(8)?,
                            payload_end: datagram_end,
                            upper_protocol,
                        });
                    }
                    0 | 43 | 60 | 135 | 139 | 140 => {
                        let hdr = frame.get(off..off.checked_add(2)?)?;
                        next = hdr[0];
                        off =
                            off.checked_add(((hdr[1] as usize).checked_add(1)?).checked_mul(8)?)?;
                    }
                    51 => {
                        let hdr = frame.get(off..off.checked_add(2)?)?;
                        next = hdr[0];
                        off =
                            off.checked_add(((hdr[1] as usize).checked_add(2)?).checked_mul(4)?)?;
                    }
                    _ => return None,
                }
            }
            None
        }
        _ => None,
    }
}

/// True when `frame`/`meta` describe one fragment of a larger datagram.
pub(super) fn frame_is_fragment(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    parse_fragment(frame, meta).is_some()
}

/// True when the fragment is the head (offset zero). Heads keep the GRE
/// protocol; tails carry the shim's 255 sentinel in production meta.
pub(super) fn frame_is_first_fragment(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    parse_fragment(frame, meta).is_some_and(|f| f.offset == 0)
}

/// #15102: like `frame_is_fragment`, but only for the given upper protocol.
pub(super) fn frame_is_fragment_for_protocol(
    frame: &[u8],
    meta: UserspaceDpMeta,
    upper_protocol: u8,
) -> bool {
    parse_fragment_with_protocol(frame, meta, Some(upper_protocol)).is_some()
}

/// #15102: the upper-layer protocol of a fragment, recovered from the wire
/// (IPv4 Protocol byte / IPv6 Fragment Next Header), or `None`.
pub(super) fn fragment_upper_protocol(frame: &[u8], meta: UserspaceDpMeta) -> Option<u8> {
    parse_fragment(frame, meta).map(|f| f.upper_protocol)
}

impl GreReassembler {
    /// #15102: does the pool already hold the head (offset 0) of the
    /// datagram this tail belongs to, under `upper_protocol`? Tails are
    /// admitted to the WG pool only on a buffered head, so a stray tail
    /// can never create state.
    pub(super) fn has_admitted_head(
        &self,
        frame: &[u8],
        meta: UserspaceDpMeta,
        upper_protocol: u8,
    ) -> bool {
        let Some(info) = parse_fragment_with_protocol(frame, meta, Some(upper_protocol)) else {
            return false;
        };
        if info.offset == 0 {
            return false;
        }
        self.entries
            .get(&info.key)
            .is_some_and(|e| e.first_meta.is_some())
    }

    /// Number of incomplete datagrams currently buffered (test/diagnostic).
    pub(super) fn buffered_len(&self) -> usize {
        self.entries.len()
    }
}

fn ranges_cover(ranges: &[(usize, usize)], total: usize) -> bool {
    let mut covered = 0usize;
    let mut sorted: Vec<(usize, usize)> = ranges.to_vec();
    sorted.sort_unstable();
    for (start, end) in sorted {
        if start > covered {
            return false;
        }
        covered = covered.max(end);
        if covered >= total {
            return true;
        }
    }
    covered >= total
}

fn build_complete(entry: &FragEntry, total: usize) -> Option<(Vec<u8>, UserspaceDpMeta)> {
    match entry.first_meta?.addr_family as i32 {
        libc::AF_INET => build_complete_v4(entry, total),
        libc::AF_INET6 => build_complete_v6(entry, total),
        _ => None,
    }
}

fn build_complete_v4(
    entry: &FragEntry,
    total_payload: usize,
) -> Option<(Vec<u8>, UserspaceDpMeta)> {
    let mut meta = entry.first_meta?;
    let head = entry.head_header.as_ref()?;
    let ihl = head.len();
    let total_len = ihl.checked_add(total_payload)?;
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut frame = Vec::with_capacity(entry.l2.len() + total_len);
    frame.extend_from_slice(&entry.l2);
    frame.extend_from_slice(head);
    frame.extend_from_slice(entry.buf.get(..total_payload)?);
    let l3 = entry.l2.len();
    frame[l3 + 2..l3 + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    // Clear MF and fragment offset, keep DF/reserved as authored.
    let field = u16::from_be_bytes([frame[l3 + 6], frame[l3 + 7]]) & 0xc000;
    frame[l3 + 6..l3 + 8].copy_from_slice(&field.to_be_bytes());
    frame[l3 + 10] = 0;
    frame[l3 + 11] = 0;
    let sum = super::frame::checksum16(&frame[l3..l3 + ihl]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&sum.to_be_bytes());
    meta.protocol = entry.upper_protocol;
    meta.pkt_len = frame.len() as u16;
    meta.l4_offset = (l3 + ihl) as u16;
    meta.payload_offset = match entry.upper_protocol {
        crate::ip_proto::PROTO_GRE => meta.l4_offset.checked_add(4)?,
        crate::ip_proto::PROTO_UDP => meta.l4_offset.checked_add(8)?,
        _ => meta.l4_offset,
    };
    if entry.upper_protocol == crate::ip_proto::PROTO_UDP {
        // Ports come from the head fragment's UDP header, preserved in buf.
        let udp = entry.buf.get(..8)?;
        meta.flow_src_port = u16::from_be_bytes([udp[0], udp[1]]);
        meta.flow_dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    } else {
        meta.flow_src_port = 0;
        meta.flow_dst_port = 0;
    }
    meta.tcp_flags = 0;
    Some((frame, meta))
}

fn build_complete_v6(
    entry: &FragEntry,
    total_payload: usize,
) -> Option<(Vec<u8>, UserspaceDpMeta)> {
    let mut meta = entry.first_meta?;
    let head = entry.head_header.as_ref()?;
    // head = fixed 40-byte header + any pre-Fragment extension headers,
    // with the Fragment header removed by construction (see offer()).
    let payload_len = head.len().checked_sub(40)?.checked_add(total_payload)?;
    if payload_len > u16::MAX as usize {
        return None;
    }
    let mut frame = Vec::with_capacity(entry.l2.len() + head.len() + total_payload);
    frame.extend_from_slice(&entry.l2);
    frame.extend_from_slice(head);
    frame.extend_from_slice(entry.buf.get(..total_payload)?);
    let l3 = entry.l2.len();
    frame[l3 + 4..l3 + 6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    meta.protocol = entry.upper_protocol;
    meta.pkt_len = frame.len() as u16;
    // Upper layer starts where the Fragment header's Next Header pointed:
    // after the retained pre-Fragment headers.
    meta.l4_offset = (l3 + head.len()) as u16;
    meta.payload_offset = match entry.upper_protocol {
        crate::ip_proto::PROTO_GRE => meta.l4_offset.checked_add(4)?,
        crate::ip_proto::PROTO_UDP => meta.l4_offset.checked_add(8)?,
        _ => meta.l4_offset,
    };
    if entry.upper_protocol == crate::ip_proto::PROTO_UDP {
        let udp = entry.buf.get(..8)?;
        meta.flow_src_port = u16::from_be_bytes([udp[0], udp[1]]);
        meta.flow_dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    } else {
        meta.flow_src_port = 0;
        meta.flow_dst_port = 0;
    }
    meta.tcp_flags = 0;
    Some((frame, meta))
}

impl GreReassembler {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn expire(&mut self, now_ns: u64) {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now_ns.saturating_sub(e.first_seen_ns) <= GRE_FRAG_TIMEOUT_NS);
        let expired = before - self.entries.len();
        for _ in 0..expired {
            counted_drop();
        }
    }

    /// Offer one fragment. Returns the completed unfragmented frame+meta
    /// exactly once when the final gap fills; otherwise `None` (buffered
    /// or counted-drop). The caller owns disposition of the returned frame.
    pub(super) fn offer(
        &mut self,
        frame: &[u8],
        meta: UserspaceDpMeta,
        now_ns: u64,
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        self.offer_inner(frame, meta, now_ns, None)
    }

    /// #15102: offer with an explicit upper-layer protocol the caller has
    /// already authenticated from the head (UDP for WireGuard). Fragments
    /// whose wire protocol disagrees are counted drops, never spliced.
    pub(super) fn offer_for_protocol(
        &mut self,
        frame: &[u8],
        meta: UserspaceDpMeta,
        now_ns: u64,
        upper_protocol: u8,
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        self.offer_inner(frame, meta, now_ns, Some(upper_protocol))
    }

    fn offer_inner(
        &mut self,
        frame: &[u8],
        meta: UserspaceDpMeta,
        now_ns: u64,
        expected_upper: Option<u8>,
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        self.expire(now_ns);
        let Some(info) = parse_fragment_with_protocol(frame, meta, expected_upper) else {
            counted_drop();
            return None;
        };
        let payload = frame.get(info.payload_start..info.payload_end)?;
        // Non-final fragments must carry a multiple of 8 payload bytes
        // (RFC 791 / RFC 8200); the final fragment establishes the total.
        if info.more && payload.len() % 8 != 0 {
            counted_drop();
            return None;
        }
        let end = match info.offset.checked_add(payload.len()) {
            Some(e) if e <= MAX_GRE_FRAG_BYTES => e,
            _ => {
                counted_drop();
                return None;
            }
        };
        if !self.entries.contains_key(&info.key) && self.entries.len() >= MAX_GRE_FRAG_DATAGRAMS {
            counted_drop();
            return None;
        }
        let key = info.key.clone();
        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| FragEntry::new(now_ns));
        entry.last_seen_ns = now_ns;
        entry.frag_count += 1;
        if entry.frag_count > MAX_GRE_FRAGS_PER_DATAGRAM {
            self.entries.remove(&key);
            counted_drop();
            return None;
        }
        if !info.more {
            match entry.total {
                Some(t) if t != end => {
                    self.entries.remove(&key);
                    counted_drop();
                    return None;
                }
                _ => entry.total = Some(end),
            }
        }
        if let Some(t) = entry.total {
            if end > t {
                self.entries.remove(&key);
                counted_drop();
                return None;
            }
        }
        // Overlap (including exact retransmission) is refused: reassembling
        // ambiguous bytes could promote attacker-spliced GRE/inner content.
        if entry
            .ranges
            .iter()
            .any(|&(s, e)| info.offset < e && s < end)
        {
            self.entries.remove(&key);
            counted_drop();
            return None;
        }
        if info.offset == 0 {
            let l3 = meta.l3_offset as usize;
            entry.upper_protocol = info.upper_protocol;
            entry.l2 = frame.get(..l3)?.to_vec();
            entry.first_meta = Some(meta);
            match meta.addr_family as i32 {
                libc::AF_INET => {
                    entry.head_header = Some(frame.get(l3..info.payload_start)?.to_vec());
                }
                libc::AF_INET6 => {
                    let frag_off = info.payload_start.checked_sub(8)?;
                    entry.v6_ext_len = frag_off.checked_sub(l3 + 40)?;
                    let mut head = frame.get(l3..frag_off)?.to_vec();
                    patch_v6_next_header_to_protocol(&mut head, info.upper_protocol);
                    entry.head_header = Some(head);
                }
                _ => return None,
            }
        } else if entry.upper_protocol == 0 {
            entry.upper_protocol = info.upper_protocol;
        }
        if entry.buf.len() < end {
            entry.buf.resize(end, 0);
        }
        entry.buf[info.offset..end].copy_from_slice(payload);
        entry.ranges.push((info.offset, end));
        let total = entry.total?;
        if !ranges_cover(&entry.ranges, total) {
            return None;
        }
        let entry = self.entries.remove(&key)?;
        build_complete(&entry, total)
    }
}

fn patch_v6_next_header_to_protocol(head: &mut [u8], protocol: u8) {
    // Walk retained headers; set the last header's next-header byte (the
    // one that named Fragment, 44) to the reassembled upper protocol.
    // Fixed header byte 6 is the first candidate; each retained
    // generic/AH header's byte 0 follows.
    if head.len() < 40 {
        return;
    }
    let mut next = head[6];
    let mut off = 40usize;
    let mut last_next_pos = 6usize;
    loop {
        match next {
            44 => {
                head[last_next_pos] = protocol;
                return;
            }
            0 | 43 | 60 | 135 | 139 | 140 => {
                let Some(hdr) = head.get(off..off + 2) else {
                    return;
                };
                last_next_pos = off;
                next = hdr[0];
                let Some(adv) = ((hdr[1] as usize) + 1).checked_mul(8) else {
                    return;
                };
                let Some(n) = off.checked_add(adv) else {
                    return;
                };
                off = n;
            }
            51 => {
                let Some(hdr) = head.get(off..off + 2) else {
                    return;
                };
                last_next_pos = off;
                next = hdr[0];
                let Some(adv) = ((hdr[1] as usize) + 2).checked_mul(4) else {
                    return;
                };
                let Some(n) = off.checked_add(adv) else {
                    return;
                };
                off = n;
            }
            _ => return,
        }
    }
}
