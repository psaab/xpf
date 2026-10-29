//! #17250 — NAT-to-L4-checksum rule parity cells (hermetic, deterministic).
//!
//! The rule is tested at both independent encodings: the descriptor's
//! precomputed delta and the generic packet rewrite. Pure NPTv6 is
//! checksum-neutral, but NPTv6+DNAT must still fold the DNAT delta.
//! The NPTv6-side addresses model the checksum-neutral RFC 6296 rewrite
//! emitted by the production compiler (word-sum preserved).
//!
//! The deterministic cells cover no NAT, plain IPv4/IPv6 NAT, pure
//! single-sided NPTv6 in both directions, and the NPTv6+DNAT compose
//! in both directions. Their independent reference uses the same
//! shared address-word primitives but not either checksum-delta engine.

use super::*;
use super::oracle::oracle_packet_valid;
use super::strategies::{build_valid_frame, PacketSpec, ValidPacket, AF4, AF6};
use crate::afxdp::frame::nat_folds_l4_checksum;
use crate::afxdp::frame::checksum::{ipv4_words, ipv6_words_from_octets};
use crate::afxdp::types::SessionFlow;
use crate::nat::NatDecision;
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROTO_TCP_U8: u8 = 6;

const DESCRIPTOR_ADDR: usize = 256;

fn descriptor_area(frame: &[u8]) -> MmapArea {
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(DESCRIPTOR_ADDR, frame.len())
        .expect("frame fits area")
        .copy_from_slice(frame);
    area
}

fn descriptor_for_packet(pkt: &ValidPacket, nat: NatDecision) -> RewriteDescriptor {
    let flow = pkt.session_flow();
    RewriteDescriptor {
        dst_mac: strategies::DST_MAC,
        src_mac: strategies::SRC_MAC,
        ether_type: if pkt.addr_family == AF6 { 0x86dd } else { 0x0800 },
        ..RewriteDescriptor::from_decision(&flow, nat)
    }
}

fn v6_packet() -> ValidPacket {
    build_valid_frame(&PacketSpec {
        v6: true,
        src4: 0x0a00_3d66,
        dst4: 0xac10_50c8,
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8],
        protocol: PROTO_TCP_U8,
        src_port: 0x1111,
        dst_port: 0x2222,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: Vec::new(),
        payload_len: 8,
        payload_seed: 42,
        udp_zero_csum: false,
        tcp_flags: 0x18,
        tcp_opt_len: 0,
        seq: 100,
    })
}

fn v4_packet() -> ValidPacket {
    build_valid_frame(&PacketSpec {
        v6: false,
        src4: 0x0a00_010a, // 10.0.1.10
        dst4: 0xc000_020a, // 192.0.2.10
        src6: [0; 16],
        dst6: [0; 16],
        protocol: PROTO_TCP_U8,
        src_port: 0x1111,
        dst_port: 0x2222,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: Vec::new(),
        payload_len: 8,
        payload_seed: 42,
        udp_zero_csum: false,
        tcp_flags: 0x18,
        tcp_opt_len: 0,
        seq: 100,
    })
}

fn flow_of(pkt: &ValidPacket) -> SessionFlow {
    SessionFlow {
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        forward_key: SessionKey {
            addr_family: pkt.addr_family,
            protocol: pkt.protocol,
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

/// Test-local RFC 1624 reference: computes the L4 delta without
/// touching either production checksum-delta engine.
fn reference_l4_delta(flow: &SessionFlow, nat: &NatDecision) -> u16 {
    if nat.nptv6 && !(nat.rewrite_src.is_some() && nat.rewrite_dst.is_some()) {
        return 0;
    }
    let mut sum: u32 = 0;
    let addr = |old: IpAddr, new: IpAddr, sum: &mut u32| {
        match (old, new) {
            (IpAddr::V4(o), IpAddr::V4(n)) => {
                for (ow, nw) in ipv4_words(o).into_iter().zip(ipv4_words(n)) {
                    *sum += (!u32::from(ow)) & 0xffff;
                    *sum += u32::from(nw);
                }
            }
            (IpAddr::V6(o), IpAddr::V6(n)) => {
                for (ow, nw) in ipv6_words_from_octets(o.octets())
                    .into_iter()
                    .zip(ipv6_words_from_octets(n.octets()))
                {
                    *sum += (!u32::from(ow)) & 0xffff;
                    *sum += u32::from(nw);
                }
            }
            _ => {}
        }
    };
    if let Some(new_src) = nat.rewrite_src {
        addr(flow.src_ip, new_src, &mut sum);
    }
    if let Some(new_dst) = nat.rewrite_dst {
        addr(flow.dst_ip, new_dst, &mut sum);
    }
    if let Some(new_port) = nat.rewrite_src_port {
        sum += (!u32::from(flow.forward_key.src_port)) & 0xffff;
        sum += u32::from(new_port);
    }
    if let Some(new_port) = nat.rewrite_dst_port {
        sum += (!u32::from(flow.forward_key.dst_port)) & 0xffff;
        sum += u32::from(new_port);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn reference_ip_delta(flow: &SessionFlow, nat: &NatDecision) -> u16 {
    let mut sum: u32 = 0;
    for (old_ip, new_ip) in [
        (flow.src_ip, nat.rewrite_src),
        (flow.dst_ip, nat.rewrite_dst),
    ] {
        if let (IpAddr::V4(o), Some(IpAddr::V4(n))) = (old_ip, new_ip) {
            for (ow, nw) in ipv4_words(o).into_iter().zip(ipv4_words(n)) {
                sum += (!u32::from(ow)) & 0xffff;
                sum += u32::from(nw);
            }
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn v6(ip: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(ip)
}

/// Checksum-neutral NPTv6 replacements for the packet's source/dest
/// (0x2001 + 0x0066/0x00c8 == 0xfd00 + 0x2300 + 0x0066/0x00c8).
const NPTV6_SRC: [u8; 16] = [0xfd, 0x00, 0, 0, 0, 0, 0x23, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x66];
const NPTV6_DST: [u8; 16] = [0xfd, 0x00, 0, 0, 0, 0, 0x23, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xc8];
const DNAT_DST: [u8; 16] = [0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
const SNAT_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

struct Cell {
    name: &'static str,
    nat: NatDecision,
    /// Expected fold verdict under the rule described above.
    folds: bool,
    delta_zero: bool,
}

fn assert_cell_v6(cell: &Cell) {
    let pkt = v6_packet();
    let flow = flow_of(&pkt);
    let nat = cell.nat;
    let rd = RewriteDescriptor::from_decision(&flow, nat);
    assert_eq!(
        nat_folds_l4_checksum(&nat),
        cell.folds,
        "{}: shared fold predicate verdict",
        cell.name
    );
    let delta = rd.l4_csum_delta;
    assert_eq!(
        delta,
        reference_l4_delta(&flow, &nat),
        "{}: descriptor delta must equal the rule reference",
        cell.name
    );
    if cell.delta_zero {
        assert_eq!(delta, 0, "{}: delta must be zero", cell.name);
    } else if cell.folds {
        assert_ne!(delta, 0, "{}: folded delta must be nonzero", cell.name);
    }

    let mut generic = pkt.l3_packet();
    let in_csum = u16::from_be_bytes([generic[pkt.rel_l4 + 16], generic[pkt.rel_l4 + 17]]);
    assert!(
        crate::afxdp::frame::apply_nat_ipv6(
            &mut generic, pkt.rel_l4, pkt.protocol, nat, false
        )
        .is_some(),
        "{}: generic apply must succeed",
        cell.name
    );
    let verdict = oracle_packet_valid(&generic, AF6, pkt.protocol, pkt.rel_l4, false);
    assert!(
        verdict.is_ok(),
        "{}: generic output checksum must validate: {verdict:?}",
        cell.name
    );
    let out_csum = u16::from_be_bytes([generic[pkt.rel_l4 + 16], generic[pkt.rel_l4 + 17]]);
    if !cell.folds {
        assert_eq!(
            out_csum, in_csum,
            "{}: pure NPTv6 must leave L4 checksum untouched",
            cell.name
        );
    }
    if let Some(IpAddr::V6(new_src)) = nat.rewrite_src {
        assert_eq!(&generic[8..24], &new_src.octets(), "{}: src rewrite", cell.name);
    }
    if let Some(IpAddr::V6(new_dst)) = nat.rewrite_dst {
        assert_eq!(&generic[24..40], &new_dst.octets(), "{}: dst rewrite", cell.name);
    }

    // Apply the actual descriptor fast path, built through the same
    // `RewriteDescriptor::from_decision` constructor as the flow cache.
    let area = descriptor_area(&pkt.frame);
    let desc = XdpDesc {
        addr: DESCRIPTOR_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let rd = descriptor_for_packet(&pkt, nat);
    let fast = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor rewrite must succeed");
    let out = area
        .slice(fast.offset as usize, fast.len as usize)
        .expect("descriptor output slice");
    let fast_l3 = &out[14..];
    let verdict = oracle_packet_valid(fast_l3, AF6, pkt.protocol, pkt.rel_l4, false);
    assert!(
        verdict.is_ok(),
        "{}: descriptor output checksum must validate: {verdict:?}",
        cell.name
    );
    assert_eq!(
        &fast_l3[8..40],
        &generic[8..40],
        "{}: descriptor and generic addresses must match",
        cell.name
    );
    assert_eq!(
        &fast_l3[pkt.rel_l4..pkt.rel_l4 + 4],
        &generic[pkt.rel_l4..pkt.rel_l4 + 4],
        "{}: descriptor and generic ports must match",
        cell.name
    );
    assert_eq!(
        &fast_l3[pkt.rel_l4 + 16..pkt.rel_l4 + 18],
        &generic[pkt.rel_l4 + 16..pkt.rel_l4 + 18],
        "{}: descriptor and generic L4 checksums must match",
        cell.name
    );
}

#[test]
fn nat_l4_rule_parity_no_nat() {
    assert_cell_v6(&Cell {
        name: "no-nat",
        nat: NatDecision::default(),
        folds: true,
        delta_zero: true,
    });
}

#[test]
fn nat_l4_rule_parity_plain_snat_v6() {
    assert_cell_v6(&Cell {
        name: "plain-snat-v6",
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(v6(SNAT_SRC))),
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_plain_dnat_v6() {
    assert_cell_v6(&Cell {
        name: "plain-dnat-v6",
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V6(v6(DNAT_DST))),
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_plain_both_v6() {
    assert_cell_v6(&Cell {
        name: "plain-both-v6",
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(v6(SNAT_SRC))),
            rewrite_dst: Some(IpAddr::V6(v6(DNAT_DST))),
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_ports_only_v6() {
    assert_cell_v6(&Cell {
        name: "ports-only-v6",
        nat: NatDecision {
            rewrite_src_port: Some(0x9999),
            rewrite_dst_port: Some(0x8888),
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_pure_nptv6_src() {
    assert_cell_v6(&Cell {
        name: "pure-nptv6-src",
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(v6(NPTV6_SRC))),
            nptv6: true,
            ..NatDecision::default()
        },
        folds: false,
        delta_zero: true,
    });
}

#[test]
fn nat_l4_rule_parity_pure_nptv6_dst() {
    assert_cell_v6(&Cell {
        name: "pure-nptv6-dst",
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V6(v6(NPTV6_DST))),
            nptv6: true,
            ..NatDecision::default()
        },
        folds: false,
        delta_zero: true,
    });
}

#[test]
fn nat_l4_rule_parity_nptv6_compose_dnat() {
    assert_cell_v6(&Cell {
        name: "nptv6+dnat-compose",
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(v6(NPTV6_SRC))),
            rewrite_dst: Some(IpAddr::V6(v6(DNAT_DST))),
            nptv6: true,
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_nptv6_compose_reverse() {
    assert_cell_v6(&Cell {
        name: "nptv6+dnat-compose-reverse",
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(v6(SNAT_SRC))),
            rewrite_dst: Some(IpAddr::V6(v6(NPTV6_DST))),
            nptv6: true,
            ..NatDecision::default()
        },
        folds: true,
        delta_zero: false,
    });
}

#[test]
fn nat_l4_rule_parity_nptv6_flag_no_rewrite() {
    assert_cell_v6(&Cell {
        name: "nptv6-flag-no-rewrite",
        nat: NatDecision {
            nptv6: true,
            ..NatDecision::default()
        },
        folds: false,
        delta_zero: true,
    });
}

fn assert_v4(nat: NatDecision, expect_nonzero_delta: bool, name: &str) {
    let pkt = v4_packet();
    let flow = flow_of(&pkt);
    let rd = RewriteDescriptor::from_decision(&flow, nat);
    assert!(nat_folds_l4_checksum(&nat), "{name}: IPv4 always folds");
    let delta = rd.l4_csum_delta;
    assert_eq!(
        delta,
        reference_l4_delta(&flow, &nat),
        "{name}: descriptor delta must equal reference"
    );
    if expect_nonzero_delta {
        assert_ne!(delta, 0, "{name}: expected nonzero delta");
    }
    assert_eq!(
        rd.ip_csum_delta,
        reference_ip_delta(&flow, &nat),
        "{name}: IP header delta must equal reference"
    );

    let mut generic = pkt.l3_packet();
    let old_src = Ipv4Addr::new(generic[12], generic[13], generic[14], generic[15]);
    let old_dst = Ipv4Addr::new(generic[16], generic[17], generic[18], generic[19]);
    let old_ttl = generic[8];
    assert!(
        crate::afxdp::frame::apply_nat_ipv4(&mut generic, pkt.protocol, nat, false).is_some(),
        "{name}: generic v4 apply must succeed"
    );
    crate::afxdp::frame::adjust_ipv4_header_checksum(&mut generic, old_src, old_dst, old_ttl)
        .expect("IPv4 header checksum adjust succeeds");
    let verdict = oracle_packet_valid(&generic, AF4, pkt.protocol, pkt.rel_l4, false);
    assert!(
        verdict.is_ok(),
        "{name}: generic v4 output checksum must validate: {verdict:?}"
    );
}
#[test]
fn nat_l4_rule_parity_v4_snat() {
    assert_v4(
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 9))),
            ..NatDecision::default()
        },
        true,
        "v4-snat",
    );
}

#[test]
fn nat_l4_rule_parity_v4_dnat_port() {
    assert_v4(
        NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))),
            rewrite_dst_port: Some(0x1f90),
            ..NatDecision::default()
        },
        true,
        "v4-dnat+port",
    );
}

#[test]
fn nat_l4_rule_parity_v4_no_nat() {
    assert_v4(NatDecision::default(), false, "v4-no-nat");
}
