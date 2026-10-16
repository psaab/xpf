// Consolidated outer-header serializers for L2/L3/L4 wire layout.
//
// Issue #1440 — collapse the duplicated Ethernet / IPv4 / IPv6 / UDP
// header writing logic that previously lived inline in
// `gre.rs::encapsulate_native_gre_frame`, `icmp.rs::build_local_*`,
// and (since-deleted) `wg/outer.rs`. Single source of truth for the
// byte offsets / network-byte-order writes.
//
// Issue #2844 — `write_eth_header_slice` is also the writer for the
// NAT64 frame builders (`crate::nat64::build_nat64_v6_to_v4_frame` /
// `build_nat64_v4_to_v6_frame`), which previously carried a private
// hardcoded copy. NAT64 is the one consumer outside `crate::afxdp`, so
// `write_eth_header_slice` is `pub(crate)` (re-exported from
// `afxdp/mod.rs`) while the other writers stay `pub(in crate::afxdp)`.
//
// Hot-path discipline:
//   - All builders take `&mut [u8]` — zero allocations.
//   - All builders are `#[inline]` so the optimizer folds the
//     function-call hop at GRE-TX call sites.
//   - The IPv4 header checksum is computed via the shared
//     `frame::checksum::checksum16` (which now has a `< 32` length
//     short-circuit, so 20-byte headers stay on the scalar path).
//
// RFC compliance and outer-fragmentation posture:
//   - `write_ipv4_header` sets DF=1 (Flags+FragOffset = 0x4000) while
//     retaining ID=0. RFC 6864 §4 / §5.3.1 permits a constant ID for
//     atomic datagrams (DF=1, MF=0, FragOffset=0).
//   - `write_ipv4_tunnel_header` accepts an explicit DF choice and uses an
//     advancing Identification. GRE copies inner IPv4 DF by default or
//     clears it when configured; WireGuard always clears it. A clear-DF
//     outer can be fragmented by a downstream router when the underlay path
//     is smaller than the local link. Generated ICMP errors and other header
//     users retain the default DF-set behavior.
//   - `write_ipv6_header` writes the IPv6 fixed header with
//     caller-supplied traffic-class / flow-label / hop-limit.
//   - `write_udp_header` accepts a plain `u16` checksum (not
//     `Option<u16>`). Callers pass `0` to take the RFC 768 "no
//     checksum computed" default — legal for IPv4 outer only.

use super::checksum::checksum16;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};

/// Default 802.1Q customer-VLAN TPID.
pub(in crate::afxdp) const TPID_8021Q: u16 = 0x8100;
/// 802.1ad service-VLAN (Q-in-Q outer) TPID. Recognized on ingress and
/// preserved on reflected local-origin errors so an inbound 0x88a8 tag
/// is not silently rewritten to 0x8100.
pub(in crate::afxdp) const TPID_8021AD: u16 = 0x88a8;

// RFC 6864 requires unique IDs for non-atomic IPv4 datagrams. When a tunnel
// outer clears DF, its downstream fragments need distinct IDs for reassembly.
static IPV4_TUNNEL_ID: AtomicU16 = AtomicU16::new(1);

/// An egress 802.1Q/802.1ad tag carrying the full TCI (PCP, DEI, VID)
/// plus the TPID and a presence flag.
///
/// #2149: the old builder API took a bare `vlan_id: u16` and emitted a
/// tag only when `vlan_id > 0`, hard-coding TPID 0x8100 and zeroing
/// PCP/DEI. That cannot emit an 802.1p *priority-tagged* frame (a real
/// tag with VID 0 but PCP != 0, used for priority-only QoS without VLAN
/// membership), and it dropped the inbound PCP/DEI/TPID when reflecting
/// a local-origin ICMP error. `TxVlanTag` carries enough state to do
/// both: emit on tag *presence* (VID > 0 OR PCP > 0, or an explicitly
/// present tag) and preserve the full TCI + TPID.
///
/// `From<u16>` reproduces the legacy bare-VID semantics exactly
/// (present iff `vid > 0`, TPID 0x8100, PCP/DEI 0), so the egress
/// config-driven call sites that only have a VID are bit-identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(in crate::afxdp) struct TxVlanTag {
    /// Tag Protocol Identifier (0x8100 for 802.1Q, 0x88a8 for 802.1ad).
    pub tpid: u16,
    /// Tag Control Information: PCP (3 bits) | DEI (1 bit) | VID (12 bits).
    pub tci: u16,
    /// Whether a tag should be emitted at all.
    pub present: bool,
}

impl TxVlanTag {
    /// No tag — emit a bare 14-byte Ethernet header.
    pub(in crate::afxdp) const NONE: TxVlanTag = TxVlanTag {
        tpid: TPID_8021Q,
        tci: 0,
        present: false,
    };

    /// Build a present tag from its parts. `pcp` low 3 bits, `dei` low
    /// bit, `vid` low 12 bits are packed into the TCI. Used by the
    /// reflected-local-error path to preserve the inbound priority bits.
    #[inline]
    pub(in crate::afxdp) fn from_parts(tpid: u16, pcp: u8, dei: bool, vid: u16) -> TxVlanTag {
        let tci = (((pcp & 0x07) as u16) << 13)
            | ((dei as u16) << 12)
            | (vid & 0x0fff);
        TxVlanTag {
            tpid,
            tci,
            present: true,
        }
    }

    /// True iff this tag should be serialized (present AND carries at
    /// least one meaningful bit — VID > 0 or PCP/DEI set). A present tag
    /// with an all-zero TCI is a degenerate "tag with no information"
    /// and is treated as untagged, matching the legacy bare-VID
    /// behavior for `vid == 0`.
    #[inline]
    pub(in crate::afxdp) fn emits(&self) -> bool {
        self.present && self.tci != 0
    }

    /// Serialized L2 header length: 18 if a tag is emitted, else 14.
    #[inline]
    pub(in crate::afxdp) fn header_len(&self) -> usize {
        if self.emits() { 18 } else { 14 }
    }
}

impl From<u16> for TxVlanTag {
    /// Legacy bare-VID semantics: present iff `vid > 0`, TPID 0x8100,
    /// PCP/DEI 0. Bit-identical to the pre-#2149 `vlan_id > 0` builders.
    #[inline]
    fn from(vid: u16) -> TxVlanTag {
        let vid = vid & 0x0fff;
        TxVlanTag {
            tpid: TPID_8021Q,
            tci: vid,
            present: vid > 0,
        }
    }
}

/// Length of an outer L2 header with optional 802.1Q tag.
#[inline]
pub(in crate::afxdp) fn eth_header_len(vlan_id: u16) -> usize {
    TxVlanTag::from(vlan_id).header_len()
}

/// Write the Ethernet header (with optional 802.1Q tag) into a
/// caller-pushed `Vec<u8>`. Existing call sites (icmp.rs,
/// poll_stages.rs, tests, frame::build paths) use this Vec-push
/// shape.
#[inline]
pub(in crate::afxdp) fn write_eth_header(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) {
    write_eth_header_tagged(buf, dst, src, TxVlanTag::from(vlan_id), ether_type);
}

/// Tag-aware Vec-push Ethernet writer. Emits an 802.1Q/802.1ad tag
/// whenever `tag.emits()` — i.e. VID > 0 OR PCP/DEI set (priority-
/// tagged VLAN-0) — preserving the full TCI and the carried TPID.
#[inline]
pub(in crate::afxdp) fn write_eth_header_tagged(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    tag: TxVlanTag,
    ether_type: u16,
) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if tag.emits() {
        buf.extend_from_slice(&tag.tpid.to_be_bytes());
        buf.extend_from_slice(&tag.tci.to_be_bytes());
    }
    buf.extend_from_slice(&ether_type.to_be_bytes());
}

/// In-place Ethernet-header writer. Returns `None` if `buf` is
/// shorter than the required header length (14 without VLAN, 18
/// with). Existing call sites (gre.rs, icmp_embed.rs,
/// tx/tcp_segmentation.rs, frame/tcp_segmentation.rs) use this
/// slice shape.
// #2844: `pub(crate)` (not `pub(in crate::afxdp)`) so the top-level
// `crate::nat64` module can reach this single source-of-truth writer
// via the `pub(crate)` re-export in `afxdp/mod.rs`. NAT64 lives outside
// `crate::afxdp` and previously carried a private hardcoded copy.
#[inline]
pub(crate) fn write_eth_header_slice(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    write_eth_header_slice_tagged(buf, dst, src, TxVlanTag::from(vlan_id), ether_type)
}

/// Tag-aware in-place Ethernet writer. Emits the full TCI + carried
/// TPID whenever `tag.emits()`, so a priority-tagged VLAN-0 tag (VID 0,
/// PCP != 0) is serialized rather than collapsed to untagged (#2149).
#[inline]
pub(in crate::afxdp) fn write_eth_header_slice_tagged(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    tag: TxVlanTag,
    ether_type: u16,
) -> Option<()> {
    let eth_len = tag.header_len();
    if buf.len() < eth_len {
        return None;
    }
    let ether_type_bytes = ether_type.to_be_bytes();
    // SAFETY: buf.len() >= eth_len is guaranteed by the guard above.
    // eth_len is 14 (no tag) or 18 (tag), so all writes are in-bounds.
    debug_assert!(buf.len() >= eth_len);
    unsafe {
        let ptr = buf.as_mut_ptr();
        core::ptr::copy_nonoverlapping(dst.as_ptr(), ptr, 6);
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr.add(6), 6);
        if tag.emits() {
            core::ptr::copy_nonoverlapping(tag.tpid.to_be_bytes().as_ptr(), ptr.add(12), 2);
            core::ptr::copy_nonoverlapping(tag.tci.to_be_bytes().as_ptr(), ptr.add(14), 2);
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(16), 2);
        } else {
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(12), 2);
        }
    }
    Some(())
}

/// Write an outer IPv4 header into `buf[..20]`. Computes the
/// header checksum and writes it at bytes 10..12.
///
/// Writes an atomic (DF-set) IPv4 datagram with ID=0. In RFC 6864
/// terminology its Identification has no reassembly semantics.
/// Tunnel outers that permit downstream fragmentation use
/// `write_ipv4_tunnel_header` instead.
///
/// Returns `Some(20)` (bytes written) on success, `None` if
/// `buf.len() < 20`.
#[inline]
pub(in crate::afxdp) fn write_ipv4_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    tos: u8,
    ttl: u8,
    total_len: u16,
) -> Option<usize> {
    let ip = buf.get_mut(..20)?;
    ip[0] = 0x45; // version=4, IHL=5
    ip[1] = tos;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // ID = 0
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF=1, FragOffset=0
    ip[8] = if ttl == 0 { 64 } else { ttl };
    ip[9] = protocol;
    ip[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = checksum16(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    Some(20)
}

/// Write a tunnel outer IPv4 header with caller-selected DF and an
/// advancing Identification, preserving the RFC 6864 requirement for
/// fragmented datagrams when DF is clear.
#[inline]
pub(in crate::afxdp) fn write_ipv4_tunnel_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    tos: u8,
    ttl: u8,
    total_len: u16,
    df: bool,
) -> Option<usize> {
    let ip = buf.get_mut(..20)?;
    ip[0] = 0x45;
    ip[1] = tos;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&IPV4_TUNNEL_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    ip[6..8].copy_from_slice(&(if df { 0x4000u16 } else { 0 }).to_be_bytes()); // DF, FragOffset=0
    ip[8] = if ttl == 0 { 64 } else { ttl };
    ip[9] = protocol;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = checksum16(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    Some(20)
}

/// Write an outer IPv6 fixed header into `buf[..40]`.
///
/// `traffic_class`, `flow_label` (low 20 bits used), and
/// `hop_limit` are caller-supplied. `hop_limit == 0` defaults to
/// 64 (matches existing gre.rs idiom).
///
/// IPv6 has no header checksum.
///
/// Returns `Some(40)` on success, `None` if `buf.len() < 40`.
#[inline]
pub(in crate::afxdp) fn write_ipv6_header(
    buf: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    traffic_class: u8,
    flow_label: u32,
    hop_limit: u8,
    payload_len: u16,
) -> Option<usize> {
    let ip = buf.get_mut(..40)?;
    // Version 6 (high 4 bits) + TC high 4 bits.
    ip[0] = 0x60 | (traffic_class >> 4);
    // TC low 4 bits + Flow Label high 4 bits.
    ip[1] = (traffic_class << 4) | (((flow_label >> 16) as u8) & 0x0f);
    // Flow Label remaining 16 bits.
    ip[2] = (flow_label >> 8) as u8;
    ip[3] = flow_label as u8;
    ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip[6] = next_header;
    ip[7] = if hop_limit == 0 { 64 } else { hop_limit };
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    Some(40)
}

/// Write an outer UDP header into `buf[..8]`.
///
/// `checksum`:
///   - non-zero — written verbatim in network byte order.
///   - `0` — RFC 768 "no checksum computed". Legal for IPv4 UDP
///     only; not legal for IPv6 UDP per RFC 8200 §8.1. The caller
///     is responsible for matching the legality.
///
/// Returns `Some(8)` on success, `None` if `buf.len() < 8`.
#[inline]
pub(in crate::afxdp) fn write_udp_header(
    buf: &mut [u8],
    src_port: u16,
    dst_port: u16,
    udp_len: u16,
    checksum: u16,
) -> Option<usize> {
    let udp = buf.get_mut(..8)?;
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    Some(8)
}

#[cfg(test)]
#[path = "headers_tests.rs"]
mod tests;
