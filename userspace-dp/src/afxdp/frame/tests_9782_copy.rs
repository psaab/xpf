//! #9782 copy-path cells: the copy builder must enforce arrival ports
//! BEFORE applying NAT (repair-then-translate), mirroring the generic
//! in-place path. Pre-fix, post-NAT enforcement clobbered PAT/DNAT port
//! translations with the original ports.
#![allow(unused_imports)]

use super::super::tests_support::*;
use super::tests_support::*;
use super::*;
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn copy_decision(nat: crate::nat::NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

#[test]
fn copy_v4_snat_port_survives_expected_ports_9782() {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        59508,
        5201,
        0x02,
    );
    // Valid input checksum (builder leaves TCP csum zero).
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv4(
        &mut frame[14..],
        20,
        PROTO_TCP,
        true,
    )
    .expect("seed");
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let decision = copy_decision(crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 7))),
        rewrite_src_port: Some(30001),
        ..Default::default()
    });
    let mut out = vec![0u8; frame.len() + 4];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        &frame,
        meta,
        &decision,
        &ForwardingState::default(),
        false,
        Some((59508, 5201)),
    )
    .expect("copy build must succeed");
    let out = &out[..written];
    assert_eq!(u16::from_be_bytes([out[34], out[35]]), 30001);
    assert_eq!(u16::from_be_bytes([out[36], out[37]]), 5201);
    assert!(tcp_checksum_ok_ipv4(&out[14..]), "copy output csum valid");
}

#[test]
fn copy_v6_snat_port_survives_expected_ports_9782() {
    let mut frame = build_txn_tcp_syn_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2001:559:8585:80::200".parse().unwrap(),
        59508,
        5201,
    );
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv6(
        &mut frame[14..],
        40,
        PROTO_TCP,
    )
    .expect("seed");
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let decision = copy_decision(crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        rewrite_src_port: Some(40001),
        ..Default::default()
    });
    let mut out = vec![0u8; frame.len() + 4];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        &frame,
        meta,
        &decision,
        &ForwardingState::default(),
        false,
        Some((59508, 5201)),
    )
    .expect("copy build must succeed");
    let out = &out[..written];
    assert_eq!(u16::from_be_bytes([out[54], out[55]]), 40001);
    assert!(tcp_checksum_ok_ipv6(&out[14..]), "copy output csum valid");
}

/// #9900 F-095 at the copy-builder layer: an untagged v4 frame stamped 18
/// builds the SAME correct output as a stamp of 14 — the payload copy, TTL
/// decrement and checksum all start at the wire-derived 14. Pre-fix the
/// stamp shifted L3 by 4 and the output carried a misaligned payload with a
/// TTL decrement applied to an IP-ID byte.
#[test]
fn copy_v4_build_ignores_wrong_l3_stamp_9900() {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        59508,
        5201,
        0x02,
    );
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv4(
        &mut frame[14..],
        20,
        PROTO_TCP,
        true,
    )
    .expect("seed");
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    for stamp in [14u16, 18u16] {
        let meta: ForwardPacketMeta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: stamp,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        }
        .into();
        let decision = copy_decision(crate::nat::NatDecision::default());
        let mut out = vec![0u8; frame.len() + 4];
        let written = build_forwarded_frame_into_from_frame(
            &mut out,
            &frame,
            meta,
            &decision,
            &ForwardingState::default(),
            false,
            Some((59508, 5201)),
        )
        .expect("copy build must succeed");
        let out = &out[..written];
        assert_eq!(written, frame.len(), "stamp {stamp}: no VLAN, same length");
        assert_eq!(
            &out[30..34],
            &dst.octets(),
            "stamp {stamp}: dst IP must survive at the v4 offset"
        );
        assert_eq!(out[14 + 8], 63, "stamp {stamp}: TTL 64 decremented once");
        assert!(tcp_checksum_ok_ipv4(&out[14..]), "stamp {stamp}: csum valid");
    }
}

/// #9900 F-095 (GPT-5): a corrected L3 never pairs with a stale L4. The
/// tagged v6 frame is stamped l3=14 (wrong; true 18) with an OVERSTATED
/// l4=62 (true 58) — the raw difference against the corrected L3 (44)
/// would pass the `>= 40` plausibility gate and drive the SNAT port write
/// 4 bytes into the TCP header. Neutralizing the L4 stamp forces the wire
/// walk (40) and the translation lands. Pre-fix the src port at 54 kept
/// 59508 instead of 40001 (and the enforce arm scribbled the seq bytes).
#[test]
fn copy_v6_build_coheres_l4_with_fallback_l3_9900() {
    let mut frame = build_txn_tcp_syn_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2001:559:8585:80::200".parse().unwrap(),
        59508,
        5201,
    );
    frame.splice(12..12, [0x81, 0x00, 0x00, 0x0a]);
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv6(
        &mut frame[18..],
        40,
        PROTO_TCP,
    )
    .expect("seed");
    let meta: ForwardPacketMeta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 62,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
    .into();
    let decision = copy_decision(crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        rewrite_src_port: Some(40001),
        ..Default::default()
    });
    let mut out = vec![0u8; frame.len() + 4];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        &frame,
        meta,
        &decision,
        &ForwardingState::default(),
        false,
        Some((59508, 5201)),
    )
    .expect("copy build must succeed");
    let out = &out[..written];
    assert_eq!(u16::from_be_bytes([out[54], out[55]]), 40001);
    assert!(tcp_checksum_ok_ipv6(&out[14..]), "copy output csum valid");
}
