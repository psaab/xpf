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
