//! Shared generators for the #1824 property harness.
//!
//! Two strategy families per plan §5.2:
//!   - garbage: arbitrary bytes with a 25%-weighted plausible-prefix
//!     stamp (EtherType/version bytes) so the generator doesn't waste
//!     most cases failing the first length check, plus arbitrary
//!     (semi-trusted) `UserspaceDpMeta`.
//!   - valid: synthetic packets built from generated tuples with
//!     correct checksums and a consistent metadata block. The v6
//!     ext-header chain strategy (`arb_ext_chain`) is the primary
//!     generator for the v6 parse arms — forced routing(43)/AH(51)/
//!     fragment(44) coverage, chains longer than the 6-iteration walk
//!     bound, and a mangling layer for truncation/oversize cases.
//!
//! NAT-applying properties see ext-headered v6 packets too (#1838
//! fixed — the generators were widened when the fixed-40 defect was
//! closed). Valid-packet generators still never emit v6 UDP zero
//! checksums: that encoding is malformed on the wire (RFC 8200 §8.1),
//! so it stays outside the VALID domain and is covered by the
//! deterministic #1840 pins in `rewrite.rs` instead.

use super::*;

pub(super) const AF4: u8 = libc::AF_INET as u8;
pub(super) const AF6: u8 = libc::AF_INET6 as u8;

pub(super) const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
pub(super) const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// A fully-built valid frame plus the ground truth it was built from.
#[derive(Clone, Debug)]
pub(super) struct ValidPacket {
    pub(super) frame: Vec<u8>,
    /// Metadata block consistent with the frame (offsets, tuple,
    /// protocol, pkt_len).
    pub(super) meta: UserspaceDpMeta,
    pub(super) l3: usize,
    /// L4 offset relative to the L3 header (v4: IHL; v6: 40 + ext).
    pub(super) rel_l4: usize,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) src_ip: IpAddr,
    pub(super) dst_ip: IpAddr,
    /// For ICMP/ICMPv6 this is the echo identifier; dst_port is 0.
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    /// v4 UDP only: frame was built with the RFC 768 "no checksum"
    /// encoding (0x0000).
    pub(super) udp_zero_csum: bool,
    pub(super) l4_header_len: usize,
    pub(super) payload_len: usize,
}

impl ValidPacket {
    /// Absolute frame offset of the L4 header.
    pub(super) fn l4(&self) -> usize {
        self.l3 + self.rel_l4
    }

    /// The L3 packet slice (what `apply_nat_*` operates on).
    pub(super) fn l3_packet(&self) -> Vec<u8> {
        self.frame[self.l3..].to_vec()
    }

    pub(super) fn session_flow(&self) -> SessionFlow {
        SessionFlow {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            forward_key: SessionKey {
                addr_family: self.addr_family,
                protocol: self.protocol,
                src_ip: self.src_ip,
                dst_ip: self.dst_ip,
                src_port: self.src_port,
                dst_port: self.dst_port,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        }
    }
}

/// IPv6 extension headers the inspect walk understands. The payload
/// byte E is the on-wire hdr-ext-len field; encoded sizes follow the
/// per-type arithmetic in inspect.rs:50-79.
#[derive(Clone, Copy, Debug)]
pub(super) enum ExtHdr {
    /// type 0 — (E+1)*8 bytes
    HopByHop(u8),
    /// type 43 — (E+1)*8 bytes
    Routing(u8),
    /// type 60 — (E+1)*8 bytes
    DestOpts(u8),
    /// type 51 — (E+2)*4 bytes (AH's RFC 4302 arithmetic differs from
    /// the options headers)
    Ah(u8),
    /// type 44 — fixed 8 bytes
    Fragment,
}

impl ExtHdr {
    pub(super) fn type_byte(self) -> u8 {
        match self {
            ExtHdr::HopByHop(_) => 0,
            ExtHdr::Routing(_) => 43,
            ExtHdr::DestOpts(_) => 60,
            ExtHdr::Ah(_) => 51,
            ExtHdr::Fragment => 44,
        }
    }

    pub(super) fn encoded_len(self) -> usize {
        match self {
            ExtHdr::HopByHop(e) | ExtHdr::Routing(e) | ExtHdr::DestOpts(e) => {
                (usize::from(e) + 1) * 8
            }
            ExtHdr::Ah(e) => (usize::from(e) + 2) * 4,
            ExtHdr::Fragment => 8,
        }
    }
}

/// Everything needed to deterministically build one valid frame.
#[derive(Clone, Debug)]
pub(super) struct PacketSpec {
    pub(super) v6: bool,
    pub(super) src4: u32,
    pub(super) dst4: u32,
    pub(super) src6: [u8; 16],
    pub(super) dst6: [u8; 16],
    pub(super) protocol: u8,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) vlan_id: u16,
    /// Whether an 802.1Q tag is present on the wire. Decoupled from
    /// `vlan_id` so the generators can produce 802.1p priority-tagged
    /// VLAN-0 frames (`vlan_present = true, vlan_id = 0, pcp > 0`) — the
    /// #2145 shape that a `vlan_id != 0` test could not reach.
    pub(super) vlan_present: bool,
    /// 802.1p priority code point (0..=7), only meaningful when
    /// `vlan_present` is set.
    pub(super) pcp: u8,
    pub(super) ttl: u8,
    /// v4 only — header length in bytes (20..=60, multiple of 4).
    pub(super) ihl: usize,
    /// v6 only — extension-header chain between the fixed header and
    /// the L4 header.
    pub(super) ext: Vec<ExtHdr>,
    pub(super) payload_len: usize,
    pub(super) payload_seed: u64,
    pub(super) udp_zero_csum: bool,
    pub(super) tcp_flags: u8,
    /// TCP options length (multiple of 4, 0..=40), NOP-filled.
    pub(super) tcp_opt_len: usize,
    pub(super) seq: u32,
}

fn fill_payload(out: &mut Vec<u8>, len: usize, seed: u64) {
    let mut state = seed | 1;
    for _ in 0..len {
        // xorshift64 — cheap deterministic bytes that shrink with the
        // (len, seed) tuple instead of per-byte strategies.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xff) as u8);
    }
}

/// Build a valid frame + consistent metadata from a spec. Checksums
/// are computed with the `checksum16*` primitives only (the SIMD
/// differential tests in checksum.rs pin those against a scalar
/// reference), never with the incremental adjust helpers under test.
pub(super) fn build_valid_frame(spec: &PacketSpec) -> ValidPacket {
    let mut frame = Vec::new();
    let ether_type: u16 = if spec.v6 { 0x86dd } else { 0x0800 };
    // Emit the L2 header by tag PRESENCE, not by `vlan_id != 0`, so a
    // priority-tagged VLAN-0 frame still carries the 4-byte 802.1Q tag
    // and lands L3 at offset 18. `write_eth_header` (production egress
    // helper) keys on `vlan_id > 0`, so the priority-tagged-VID-0 case
    // is built explicitly here (#2145).
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    if spec.vlan_present {
        // TCI = PCP(3) | DEI(1=0) | VID(12).
        let tci = ((spec.pcp as u16 & 0x7) << 13) | (spec.vlan_id & 0x0fff);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());
    }
    frame.extend_from_slice(&ether_type.to_be_bytes());
    let l3 = frame.len();

    let l4_header_len = match spec.protocol {
        PROTO_TCP => 20 + spec.tcp_opt_len,
        PROTO_UDP => 8,
        _ => 8, // ICMP/ICMPv6 echo header
    };

    let (addr_family, protocol) = (if spec.v6 { AF6 } else { AF4 }, spec.protocol);
    let (src_ip, dst_ip): (IpAddr, IpAddr) = if spec.v6 {
        (
            IpAddr::V6(Ipv6Addr::from(spec.src6)),
            IpAddr::V6(Ipv6Addr::from(spec.dst6)),
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::from(spec.src4)),
            IpAddr::V4(Ipv4Addr::from(spec.dst4)),
        )
    };

    let rel_l4;
    if spec.v6 {
        let ext_len: usize = spec.ext.iter().map(|e| e.encoded_len()).sum();
        rel_l4 = 40 + ext_len;
        let l4_total = l4_header_len + spec.payload_len;
        let payload_len_field = (ext_len + l4_total) as u16;
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len_field.to_be_bytes());
        let first_type = spec
            .ext
            .first()
            .map(|e| e.type_byte())
            .unwrap_or(spec.protocol);
        frame.push(first_type);
        frame.push(spec.ttl);
        frame.extend_from_slice(&spec.src6);
        frame.extend_from_slice(&spec.dst6);
        // Extension chain: each header's byte 0 is the next header
        // type, byte 1 the on-wire length field, remainder zero pad.
        for (i, ext) in spec.ext.iter().enumerate() {
            let next = spec
                .ext
                .get(i + 1)
                .map(|e| e.type_byte())
                .unwrap_or(spec.protocol);
            let start = frame.len();
            frame.resize(start + ext.encoded_len(), 0);
            frame[start] = next;
            frame[start + 1] = match ext {
                ExtHdr::HopByHop(e) | ExtHdr::Routing(e) | ExtHdr::DestOpts(e) => *e,
                ExtHdr::Ah(e) => *e,
                ExtHdr::Fragment => 0,
            };
        }
    } else {
        rel_l4 = spec.ihl;
        let total_len = (spec.ihl + l4_header_len + spec.payload_len) as u16;
        frame.push(0x40 | (spec.ihl / 4) as u8);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        frame.push(spec.ttl);
        frame.push(spec.protocol);
        frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        frame.extend_from_slice(&spec.src4.to_be_bytes());
        frame.extend_from_slice(&spec.dst4.to_be_bytes());
        // IPv4 options as NOPs.
        frame.resize(l3 + spec.ihl, 0x01);
        let ip_csum = checksum16(&frame[l3..l3 + spec.ihl]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    }

    // L4 header + payload.
    let l4_start = frame.len();
    debug_assert_eq!(l4_start, l3 + rel_l4);
    let (src_port, dst_port) = match spec.protocol {
        PROTO_TCP => {
            frame.extend_from_slice(&spec.src_port.to_be_bytes());
            frame.extend_from_slice(&spec.dst_port.to_be_bytes());
            frame.extend_from_slice(&spec.seq.to_be_bytes());
            frame.extend_from_slice(&0u32.to_be_bytes()); // ack
            frame.push((((20 + spec.tcp_opt_len) / 4) as u8) << 4);
            frame.push(spec.tcp_flags);
            frame.extend_from_slice(&[0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
            frame.resize(l4_start + 20 + spec.tcp_opt_len, 0x01); // NOP opts
            (spec.src_port, spec.dst_port)
        }
        PROTO_UDP => {
            frame.extend_from_slice(&spec.src_port.to_be_bytes());
            frame.extend_from_slice(&spec.dst_port.to_be_bytes());
            frame.extend_from_slice(&((8 + spec.payload_len) as u16).to_be_bytes());
            frame.extend_from_slice(&[0x00, 0x00]);
            (spec.src_port, spec.dst_port)
        }
        _ => {
            // ICMP echo request (v4 type 8 / v6 type 128), identifier =
            // src_port, sequence 1. dst_port is 0 by parse convention.
            frame.push(if spec.v6 { 128 } else { 8 });
            frame.push(0);
            frame.extend_from_slice(&[0x00, 0x00]);
            frame.extend_from_slice(&spec.src_port.to_be_bytes());
            frame.extend_from_slice(&1u16.to_be_bytes());
            (spec.src_port, 0)
        }
    };
    fill_payload(&mut frame, spec.payload_len, spec.payload_seed);

    // L4 checksum over the final segment bytes.
    let seg_start = l4_start;
    let csum_off = match spec.protocol {
        PROTO_TCP => Some(seg_start + 16),
        PROTO_UDP => Some(seg_start + 6),
        _ => Some(seg_start + 2),
    };
    if let Some(csum_off) = csum_off {
        let sum = if spec.v6 {
            let (s6, d6) = (Ipv6Addr::from(spec.src6), Ipv6Addr::from(spec.dst6));
            checksum16_ipv6(s6, d6, spec.protocol, &frame[seg_start..])
        } else if spec.protocol == PROTO_ICMP {
            checksum16(&frame[seg_start..])
        } else {
            let (s4, d4) = (Ipv4Addr::from(spec.src4), Ipv4Addr::from(spec.dst4));
            checksum16_ipv4(s4, d4, spec.protocol, &frame[seg_start..])
        };
        let stored = if spec.protocol == PROTO_UDP {
            if !spec.v6 && spec.udp_zero_csum {
                // RFC 768: IPv4 UDP "no checksum" encoding. Never
                // emitted for v6 (#1840 — that input is malformed).
                0u16
            } else if sum == 0 {
                0xffff
            } else {
                sum
            }
        } else {
            sum
        };
        frame[csum_off..csum_off + 2].copy_from_slice(&stored.to_be_bytes());
    }

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: l3 as u16,
        l4_offset: (l3 + rel_l4) as u16,
        payload_offset: (l3 + rel_l4 + l4_header_len) as u16,
        pkt_len: frame.len() as u16,
        addr_family,
        protocol,
        tcp_flags: if spec.protocol == PROTO_TCP {
            spec.tcp_flags
        } else {
            0
        },
        ingress_vlan_id: spec.vlan_id,
        ingress_pcp: spec.pcp,
        ingress_vlan_present: u8::from(spec.vlan_present),
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        flow_src_addr: if spec.v6 {
            spec.src6
        } else {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&spec.src4.to_be_bytes());
            a
        },
        flow_dst_addr: if spec.v6 {
            spec.dst6
        } else {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&spec.dst4.to_be_bytes());
            a
        },
        ..UserspaceDpMeta::default()
    };

    ValidPacket {
        frame,
        meta,
        l3,
        rel_l4,
        addr_family,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        udp_zero_csum: !spec.v6 && spec.protocol == PROTO_UDP && spec.udp_zero_csum,
        l4_header_len,
        payload_len: spec.payload_len,
    }
}

// ---------------------------------------------------------------------------
// Garbage strategies
// ---------------------------------------------------------------------------

/// Arbitrary bytes 0..2048 with a 25%-weighted plausible-prefix stamp
/// (EtherType at 12..14 and an IP version/IHL byte at 14) so the
/// majority of cases reach past the first ethertype check.
pub(super) fn arb_garbage_frame() -> impl Strategy<Value = Vec<u8>> {
    (
        proptest::collection::vec(any::<u8>(), 0..2048),
        any::<u8>(),
        any::<u8>(),
    )
        .prop_map(|(mut frame, stamp_sel, kind_sel)| {
            if stamp_sel % 4 == 0 && frame.len() >= 15 {
                let et: u16 = match kind_sel % 4 {
                    0 => 0x0800,
                    1 => 0x86dd,
                    2 => 0x8100,
                    _ => 0x88a8,
                };
                frame[12..14].copy_from_slice(&et.to_be_bytes());
                match kind_sel % 3 {
                    0 => frame[14] = 0x45,
                    1 => frame[14] = 0x60,
                    _ => {}
                }
            }
            frame
        })
}

/// Weighted address family: mostly the two real families, sometimes
/// arbitrary garbage.
pub(super) fn arb_af() -> impl Strategy<Value = u8> {
    prop_oneof![
        4 => Just(AF4),
        4 => Just(AF6),
        1 => any::<u8>(),
    ]
}

pub(super) fn arb_proto() -> impl Strategy<Value = u8> {
    prop_oneof![
        3 => Just(PROTO_TCP),
        3 => Just(PROTO_UDP),
        2 => Just(PROTO_ICMP),
        2 => Just(PROTO_ICMPV6),
        1 => any::<u8>(),
    ]
}

/// Fully arbitrary (semi-trusted) metadata: the XDP shim produces it,
/// but the parse fns must defend against inconsistent values.
pub(super) fn arb_meta() -> impl Strategy<Value = UserspaceDpMeta> {
    (
        (any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()),
        arb_af(),
        arb_proto(),
        (any::<u16>(), any::<u16>()),
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u8>(),
    )
        .prop_map(
            |(
                (l3_offset, l4_offset, payload_offset, pkt_len),
                addr_family,
                protocol,
                (flow_src_port, flow_dst_port),
                flow_src_addr,
                flow_dst_addr,
                meta_flags,
            )| UserspaceDpMeta {
                magic: USERSPACE_META_MAGIC,
                version: USERSPACE_META_VERSION,
                length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                l3_offset,
                l4_offset,
                payload_offset,
                pkt_len,
                addr_family,
                protocol,
                flow_src_port,
                flow_dst_port,
                flow_src_addr,
                flow_dst_addr,
                meta_flags,
                ..UserspaceDpMeta::default()
            },
        )
}

// ---------------------------------------------------------------------------
// Valid-packet strategies
// ---------------------------------------------------------------------------

/// Egress VLAN ID for the TX/rewrite/segment differential strategies,
/// where VID 0 == untagged is the correct semantic (`write_eth_header`
/// keys on `vid > 0`). The ingress frame builders use [`arb_vlan_tag`]
/// instead so they can also generate priority-tagged VLAN-0 frames.
pub(super) fn arb_vlan() -> impl Strategy<Value = u16> {
    prop_oneof![
        2 => Just(0u16),
        1 => 1u16..4095,
    ]
}

/// A generated 802.1Q tag decision for an INGRESS frame: whether a tag
/// is present, the VID, and the PCP. Untagged frames carry
/// `present = false`; tagged frames carry `present = true` with an
/// arbitrary VID (which may be 0 — the 802.1p priority-tagged shape)
/// and PCP (#2145).
#[derive(Clone, Copy, Debug)]
pub(super) struct VlanTag {
    pub(super) present: bool,
    pub(super) vid: u16,
    pub(super) pcp: u8,
}

pub(super) fn arb_vlan_tag() -> impl Strategy<Value = VlanTag> {
    prop_oneof![
        // Untagged.
        2 => Just(VlanTag { present: false, vid: 0, pcp: 0 }),
        // Tagged with a non-zero VID (the common 802.1Q case).
        2 => (1u16..4095, 0u8..=7)
            .prop_map(|(vid, pcp)| VlanTag { present: true, vid, pcp }),
        // Priority-tagged VLAN 0 (PCP > 0, VID 0) — the #2145 shape the
        // old `present = (vid != 0)` derivation could never produce.
        1 => (1u8..=7).prop_map(|pcp| VlanTag { present: true, vid: 0, pcp }),
    ]
}

fn arb_ihl() -> impl Strategy<Value = usize> {
    (5usize..=15).prop_map(|w| w * 4)
}

pub(super) fn arb_ext_hdr() -> impl Strategy<Value = ExtHdr> {
    prop_oneof![
        (0u8..3).prop_map(ExtHdr::HopByHop),
        (0u8..3).prop_map(ExtHdr::Routing),
        (0u8..3).prop_map(ExtHdr::DestOpts),
        (0u8..3).prop_map(ExtHdr::Ah),
        Just(ExtHdr::Fragment),
    ]
}

pub(super) fn arb_ext_chain(max: usize) -> impl Strategy<Value = Vec<ExtHdr>> {
    proptest::collection::vec(arb_ext_hdr(), 0..=max)
}

/// Common tuple pieces shared by every valid-packet strategy.
type TupleParts = (
    (u32, u32, [u8; 16], [u8; 16]),
    (u16, u16),
    VlanTag, // 802.1Q tag decision (present / vid / pcp)
    u8,      // ttl 2..=255
    (usize, u64), // payload (len, seed)
);

fn arb_tuple_parts(max_payload: usize) -> impl Strategy<Value = TupleParts> {
    (
        (
            any::<u32>(),
            any::<u32>(),
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
        ),
        (any::<u16>(), any::<u16>()),
        arb_vlan_tag(),
        2u8..=255,
        (0usize..=max_payload, any::<u64>()),
    )
}

fn spec_from_parts(
    parts: TupleParts,
    v6: bool,
    protocol: u8,
    ihl: usize,
    ext: Vec<ExtHdr>,
    udp_zero_csum: bool,
    tcp_flags: u8,
    tcp_opt_len: usize,
    seq: u32,
) -> PacketSpec {
    let ((src4, dst4, src6, dst6), (src_port, dst_port), vlan, ttl, (payload_len, payload_seed)) =
        parts;
    PacketSpec {
        v6,
        src4,
        dst4,
        src6,
        dst6,
        protocol,
        src_port,
        dst_port,
        vlan_id: vlan.vid,
        vlan_present: vlan.present,
        pcp: vlan.pcp,
        ttl,
        ihl,
        ext,
        payload_len,
        payload_seed,
        udp_zero_csum,
        tcp_flags,
        tcp_opt_len,
        seq,
    }
}

/// Valid packets for the read-only S1 parse properties: both families,
/// all four protocols, v6 ext-header chains up to `max_ext` headers
/// (pass 6 for round-trip properties — the inspect walk's loop bound —
/// and more for no-panic/bounds properties).
pub(super) fn arb_parse_packet(max_ext: usize) -> impl Strategy<Value = ValidPacket> {
    (
        arb_tuple_parts(300),
        any::<bool>(),
        prop_oneof![
            3 => Just(PROTO_TCP),
            3 => Just(PROTO_UDP),
            2 => Just(0xffu8), // placeholder → mapped to family ICMP below
        ],
        arb_ihl(),
        arb_ext_chain(max_ext),
        any::<bool>(),
        any::<u32>(),
    )
        .prop_map(
            move |(parts, v6, proto_sel, ihl, ext, udp_zero, seq)| {
                let protocol = match proto_sel {
                    0xff => {
                        if v6 {
                            PROTO_ICMPV6
                        } else {
                            PROTO_ICMP
                        }
                    }
                    p => p,
                };
                let udp_zero_csum = udp_zero && !v6 && protocol == PROTO_UDP;
                let ext = if v6 { ext } else { Vec::new() };
                let spec = spec_from_parts(
                    parts,
                    v6,
                    protocol,
                    ihl,
                    ext,
                    udp_zero_csum,
                    0x10, // ACK
                    0,
                    seq,
                );
                build_valid_frame(&spec)
            },
        )
}

/// Valid packets for NAT-applying properties (P-N1..P-N4, P-T4 inputs):
/// TCP/UDP only, TTL ≥ 2, v6 with ext-header chains up to 4 headers
/// (re-admitted when #1838 was fixed — the chain stays within the
/// 6-iteration walk bound), v6 UDP checksum never zero (malformed per
/// RFC 8200 §8.1 — covered by the deterministic #1840 pins instead).
pub(super) fn arb_nat_packet() -> impl Strategy<Value = ValidPacket> {
    (
        arb_tuple_parts(256),
        any::<bool>(),
        prop_oneof![Just(PROTO_TCP), Just(PROTO_UDP)],
        arb_ihl(),
        arb_ext_chain(4),
        any::<bool>(),
        any::<u32>(),
    )
        .prop_map(|(parts, v6, protocol, ihl, ext, udp_zero, seq)| {
            let udp_zero_csum = udp_zero && !v6 && protocol == PROTO_UDP;
            let ext = if v6 { ext } else { Vec::new() };
            let spec = spec_from_parts(
                parts,
                v6,
                protocol,
                ihl,
                ext,
                udp_zero_csum,
                0x18, // PSH|ACK
                0,
                seq,
            );
            build_valid_frame(&spec)
        })
}

/// Family-matched NAT decision: any non-empty subset of
/// {src ip, dst ip, sport, dport}. Never NAT64/NPTv6 (the descriptor
/// path refuses those and the flow cache never builds them).
pub(super) fn arb_nat(v6: bool) -> impl Strategy<Value = NatDecision> {
    (
        1u8..16,
        any::<u32>(),
        any::<u32>(),
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u16>(),
        any::<u16>(),
    )
    .prop_map(move |(mask, s4, d4, s6, d6, sp, dp)| {
        NatDecision {
            rewrite_src: (mask & 1 != 0).then(|| {
                if v6 {
                    IpAddr::V6(Ipv6Addr::from(s6))
                } else {
                    IpAddr::V4(Ipv4Addr::from(s4))
                }
            }),
            rewrite_dst: (mask & 2 != 0).then(|| {
                if v6 {
                    IpAddr::V6(Ipv6Addr::from(d6))
                } else {
                    IpAddr::V4(Ipv4Addr::from(d4))
                }
            }),
            rewrite_src_port: (mask & 4 != 0).then_some(sp),
            rewrite_dst_port: (mask & 8 != 0).then_some(dp),
            source_nat_icmp: None,
            nat64: false,
            nptv6: false,
        }
    })
}

pub(super) fn arb_packet_with_nat() -> impl Strategy<Value = (ValidPacket, NatDecision)> {
    arb_nat_packet().prop_flat_map(|pkt| {
        let v6 = pkt.addr_family == AF6;
        (Just(pkt), arb_nat(v6))
    })
}

/// Mangled structured v6 frames: a well-formed ext-chain packet (up to
/// 8 headers — past the 6-iteration walk bound) with random byte
/// overwrites (hits oversized hdr-ext-len, type mutations to 59 /
/// unknown, version nibble damage) and optional truncation mid-chain.
pub(super) fn arb_mangled_ext_frame() -> impl Strategy<Value = Vec<u8>> {
    (
        arb_parse_packet(8),
        proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        any::<prop::sample::Index>(),
        any::<bool>(),
    )
        .prop_map(|(pkt, writes, trunc, do_trunc)| {
            let mut frame = pkt.frame;
            if frame.is_empty() {
                return frame;
            }
            for (idx, byte) in writes {
                let i = idx.index(frame.len());
                frame[i] = byte;
            }
            if do_trunc {
                frame.truncate(trunc.index(frame.len()) + 1);
            }
            frame
        })
}

/// Oversized TCP packets for the S4 segmentation properties: payload
/// strictly larger than the MTU (1×..4×), TCP options 0..=40 bytes,
/// v4 IHL 20..=60, v6 ext chains up to 3 headers (re-admitted when
/// #1838 was fixed — each segment copies the full IP header incl. the
/// ext chain and the payload-length field counts it). Returns
/// (packet, mtu).
pub(super) fn arb_seg_packet() -> impl Strategy<Value = (ValidPacket, usize)> {
    (
        (
            any::<u32>(),
            any::<u32>(),
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
        ),
        (any::<u16>(), any::<u16>()),
        arb_vlan_tag(),
        2u8..=255,
        any::<bool>(),
        arb_ihl(),
        arb_ext_chain(3),
        (0usize..=10).prop_map(|w| w * 4),
        1280usize..=9216,
        (1usize..=3, 1usize..4096, any::<u64>()),
        prop_oneof![
            3 => Just(0x10u8),        // ACK
            2 => Just(0x18u8),        // PSH|ACK
            1 => Just(0x10u8 | 0x40), // ECE|ACK — exotic but legal
            // #5191: CWR and URG are the flags software segmentation must not
            // clone verbatim. Before #5191 the generator sampled neither, so
            // the S4 flag expectation varied an axis it never actually
            // exercised — a fixture that could only ever agree with the code.
            1 => Just(0x10u8 | 0x80), // CWR|ACK
            1 => Just(0x10u8 | 0x20), // URG|ACK
        ],
        prop_oneof![
            4 => any::<u32>(),
            1 => Just(u32::MAX - 1000), // force seq wrap mid-split
        ],
    )
        .prop_map(
            |(
                ips,
                ports,
                vlan,
                ttl,
                v6,
                ihl,
                ext,
                tcp_opt_len,
                mtu,
                (mult, extra, payload_seed),
                tcp_flags,
                seq,
            )| {
                // payload length: mtu < L3 payload ≤ 4×mtu, normalized
                // so the splitter always engages.
                let payload_len = mtu * mult + (extra % mtu.max(1)) + 1;
                let (src4, dst4, src6, dst6) = ips;
                let (src_port, dst_port) = ports;
                let spec = PacketSpec {
                    v6,
                    src4,
                    dst4,
                    src6,
                    dst6,
                    protocol: PROTO_TCP,
                    src_port,
                    dst_port,
                    vlan_id: vlan.vid,
                    vlan_present: vlan.present,
                    pcp: vlan.pcp,
                    ttl,
                    ihl,
                    ext: if v6 { ext } else { Vec::new() },
                    payload_len,
                    payload_seed,
                    udp_zero_csum: false,
                    tcp_flags,
                    tcp_opt_len,
                    seq,
                };
                (build_valid_frame(&spec), mtu)
            },
        )
}
