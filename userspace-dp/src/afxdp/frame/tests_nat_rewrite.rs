// SYN-cookie SYN-ACK/RST builders, apply-NAT checksum/GRE/ESP handling, reverse-SNAT L3 extraction, and in-place VLAN/ICMP/NAT64 frame rewrites.
//
// Split out of afxdp/frame/tests.rs (#4840) as a sibling `#[path]` test
// module loaded from afxdp/frame/mod.rs. Pure code motion: every #[test]
// fn is moved verbatim; shared test-support helpers live in
// afxdp/frame/tests_support.rs.
#![allow(unused_imports)]

use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot};
use super::tests_support::*;

#[test]
fn syn_cookie_syn_ack_builder_swaps_tuple_and_preserves_vlan() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let out =
        build_syn_cookie_syn_ack_frame(&frame, 0xaabb_ccdd, 1460).expect("syn-cookie syn-ack");

    assert_eq!(&out[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(&out[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(&out[12..18], &frame[12..18]);
    assert_eq!(&out[30..34], &server.octets());
    assert_eq!(&out[34..38], &client.octets());
    assert_eq!(u16::from_be_bytes([out[20], out[21]]), 44);
    assert_eq!(u16::from_be_bytes([out[38], out[39]]), 443);
    assert_eq!(u16::from_be_bytes([out[40], out[41]]), 49152);
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0xaabb_ccdd
    );
    assert_eq!(
        u32::from_be_bytes([out[46], out[47], out[48], out[49]]),
        0x0102_0305
    );
    assert_eq!(out[50] >> 4, 6);
    assert_eq!(out[51], TCP_FLAG_SYN | 0x10);
    assert_eq!(&out[58..62], &[2, 4, 0x05, 0xb4]);
    assert_eq!(checksum16(&out[18..38]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}


#[test]
fn syn_cookie_ipv4_syn_ack_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let frame = build_ipv4_tcp_frame(client, server, 49152, 443, 0x0102_0304, 0, TCP_FLAG_SYN);

    let out =
        build_syn_cookie_syn_ack_frame(&frame, 0xaabb_ccdd, 1460).expect("syn-cookie syn-ack");

    assert_eq!(out.len(), 60);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 44);
    assert_eq!(&out[54..58], &[2, 4, 0x05, 0xb4]);
    assert_eq!(&out[58..60], &[0, 0]);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn syn_cookie_ipv4_rst_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let frame = build_ipv4_tcp_frame(client, server, 49152, 443, 0x1111_2222, 0x3333_4444, 0x10);

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(out.len(), 60);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 40);
    assert_eq!(
        u32::from_be_bytes([out[38], out[39], out[40], out[41]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0x1111_2223
    );
    assert_eq!(out[47], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[48..50], &[0, 0]);
    assert_eq!(&out[54..60], &[0, 0, 0, 0, 0, 0]);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn syn_cookie_vlan_ipv4_rst_builder_pads_to_ethernet_minimum() {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x1111_2222u32.to_be_bytes());
    frame.extend_from_slice(&0x3333_4444u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(out.len(), 60);
    assert_eq!(&out[12..18], &frame[12..18]);
    assert_eq!(u16::from_be_bytes([out[20], out[21]]), 40);
    assert_eq!(
        u32::from_be_bytes([out[42], out[43], out[44], out[45]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[46], out[47], out[48], out[49]]),
        0x1111_2223
    );
    assert_eq!(out[51], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[52..54], &[0, 0]);
    assert_eq!(&out[58..60], &[0, 0]);
    assert_eq!(checksum16(&out[18..38]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}


#[test]
fn syn_cookie_ack_rst_builder_uses_received_ack_as_rst_seq() {
    let client = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10);
    let server = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 20);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&20u16.to_be_bytes());
    frame.push(PROTO_TCP);
    frame.push(64);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&0x1111_2222u32.to_be_bytes());
    frame.extend_from_slice(&0x3333_4444u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let out = build_syn_cookie_ack_rst_frame(&frame).expect("syn-cookie rst");

    assert_eq!(&out[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    assert_eq!(&out[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(&out[22..38], &server.octets());
    assert_eq!(&out[38..54], &client.octets());
    assert_eq!(u16::from_be_bytes([out[18], out[19]]), 20);
    assert_eq!(u16::from_be_bytes([out[54], out[55]]), 443);
    assert_eq!(u16::from_be_bytes([out[56], out[57]]), 49152);
    assert_eq!(
        u32::from_be_bytes([out[58], out[59], out[60], out[61]]),
        0x3333_4444
    );
    assert_eq!(
        u32::from_be_bytes([out[62], out[63], out[64], out[65]]),
        0x1111_2223
    );
    assert_eq!(out[67], TCP_FLAG_RST | 0x10);
    assert_eq!(&out[68..70], &[0, 0]);
    assert!(tcp_checksum_ok_ipv6(&out[14..]));
}


#[test]
fn apply_nat_ipv4_recomputes_tcp_checksum() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ];
    let ip_sum = checksum16(&packet[..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut packet, 20, PROTO_TCP, false).expect("initial tcp sum");
    assert!(tcp_checksum_ok_ipv4(&packet));

    apply_nat_ipv4(
        &mut packet,
        PROTO_TCP,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        },
        false,
    )
    .expect("apply nat");

    assert_eq!(&packet[12..16], &[172, 16, 80, 8]);
    assert!(tcp_checksum_ok_ipv4(&packet));
}


// #3111 FAIL-ON-REVERT: the generic NAT rewriter must NOT write an L4
// "port" for a port-less protocol. apply_nat_ipv4 is fed a NatDecision
// that (as a buggy pool allocator would) carries rewrite_src_port =
// Some(_) for a GRE packet. The TCP|UDP gate in apply_nat_port_rewrite
// must suppress the port write so the first two bytes of the GRE header
// (flags/version) survive; only the source IP is translated. Reverting
// that gate writes 0xBEEF over the GRE flags -> RED.
#[test]
fn apply_nat_ipv4_gre_preserves_l4_header() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, crate::ip_proto::PROTO_GRE, 0x00, 0x00,
        10, 0, 1, 100, 8, 8, 8, 8,
        // GRE header: flags/version, protocol-type, then key.
        0x30, 0x01, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ];
    let ip_sum = checksum16(&packet[..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;

    apply_nat_ipv4(
        &mut packet,
        crate::ip_proto::PROTO_GRE,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            rewrite_src_port: Some(0xBEEF),
            ..NatDecision::default()
        },
        false,
    )
    .expect("apply nat");

    // Source IP translated, destination untouched.
    assert_eq!(&packet[12..16], &[203, 0, 113, 1]);
    assert_eq!(&packet[16..20], &[8, 8, 8, 8]);
    // GRE flags/version (first 2 L4 bytes) PRESERVED.
    assert_eq!(
        &packet[20..22],
        &[0x30, 0x01],
        "GRE header must not be overwritten by a NAT port"
    );
}


// #3111 FAIL-ON-REVERT: same gate, ESP (proto 50). A port write at the L4
// offset would land on the ESP SPI high half. The whole SPI must survive;
// only the source IP is translated.
#[test]
fn apply_nat_ipv4_esp_preserves_spi() {
    let mut packet = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, crate::ip_proto::PROTO_ESP, 0x00, 0x00,
        10, 0, 1, 100, 8, 8, 8, 8,
        // ESP header: SPI (4B) + sequence (4B).
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x01,
    ];
    let ip_sum = checksum16(&packet[..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;

    apply_nat_ipv4(
        &mut packet,
        crate::ip_proto::PROTO_ESP,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            rewrite_src_port: Some(0xBEEF),
            ..NatDecision::default()
        },
        false,
    )
    .expect("apply nat");

    assert_eq!(&packet[12..16], &[203, 0, 113, 1]);
    assert_eq!(
        &packet[20..24],
        &[0xAA, 0xBB, 0xCC, 0xDD],
        "ESP SPI must not be overwritten by a NAT port"
    );
}


#[test]
fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v4() {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
        b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let packet = extract_l3_packet_with_nat(
        &frame,
        meta,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    )
    .expect("slow-path packet");
    assert_eq!(&packet[12..16], &[172, 16, 80, 200]);
    assert_eq!(&packet[16..20], &[10, 0, 61, 102]);
    assert!(tcp_checksum_ok_ipv4(&packet));
}


#[test]
fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v6() {
    let src_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        80,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0x14, 0x51, 0x95, 0x2c, 0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x10, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e',
        b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[18..], 40, PROTO_TCP).expect("tcp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let packet = extract_l3_packet_with_nat(
        &frame,
        meta,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::102".parse().unwrap())),
            ..NatDecision::default()
        },
    )
    .expect("slow-path packet");
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
        src_ip
    );
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
        "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap()
    );
    assert!(tcp_checksum_ok_ipv6(&packet));
}


#[test]
fn build_forwarded_frame_keeps_tcp_checksum_valid_after_snat() {
    let state = build_forwarding_state(&nat_snapshot());
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let out = build_forwarded_frame(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        }, nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        }, install_table_domain: 0, install_table_check: 0 },
        &state,
        None,
    )
    .expect("forwarded frame");

    assert_eq!(&out[30..34], &[172, 16, 80, 8]);
    assert_eq!(out[26], 63);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}


#[test]
fn rewrite_forwarded_frame_in_place_keeps_icmpv6_checksum_valid_after_snat() {
    let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]);
    let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
    frame[56] = (sum >> 8) as u8;
    frame[57] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
    )
    .expect("in-place v6 forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(out[25], 63);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert!(icmpv6_checksum_ok(&out[18..]));
}


#[test]
fn rewrite_forwarded_frame_in_place_pushes_vlan_by_shifting_tx_descriptor() {
    let frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
    );
    let rx_addr = 256usize;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: rx_addr as u64,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &l2_rewrite_test_decision(80),
        false,
        None,
    )
    .expect("vlan push");

    assert_eq!(rewrite_result.offset, (rx_addr - 4) as u64);
    assert_eq!(rewrite_result.len, frame.len() as u32 + 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(out[18], 0x45);
    assert_eq!(
        area.slice(rx_addr + 14, 1).expect("ip-at-original-address")[0],
        0x45
    );
}


#[test]
fn rewrite_forwarded_frame_in_place_pops_vlan_by_shifting_tx_descriptor() {
    let frame = build_icmp_echo_frame_v4_vlan(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
        80,
    );
    let rx_addr = 256usize;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: rx_addr as u64,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &l2_rewrite_test_decision(0),
        false,
        None,
    )
    .expect("vlan pop");

    assert_eq!(rewrite_result.offset, (rx_addr + 4) as u64);
    assert_eq!(rewrite_result.len, frame.len() as u32 - 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPopDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(out[14], 0x45);
    assert_eq!(
        area.slice(rx_addr + 18, 1).expect("ip-at-original-address")[0],
        0x45
    );
}


#[test]
fn rewrite_forwarded_frame_in_place_pushes_vlan_with_memmove_without_headroom() {
    let frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
    );
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &l2_rewrite_test_decision(80),
        false,
        None,
    )
    .expect("vlan push fallback");

    assert_eq!(rewrite_result.offset, 0);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(out[18], 0x45);
}


#[test]
fn rewrite_forwarded_frame_in_place_keeps_icmpv6_echo_identifier_and_sequence() {
    let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap();
    let echo_id = 0x3e0f;
    let echo_seq = 0x80e9;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x07, 0x9f, 0x9c, 0x00, 0x18, PROTO_ICMPV6, 2]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        128,
        0,
        0,
        0,
        (echo_id >> 8) as u8,
        echo_id as u8,
        (echo_seq >> 8) as u8,
        echo_seq as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
    frame[56] = (sum >> 8) as u8;
    frame[57] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        flow_src_port: echo_id,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:50::8".parse().unwrap())),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };

    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
    )
    .expect("in-place v6 echo forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");

    let packet = &out[18..];
    assert_eq!(packet[40], 128);
    assert_eq!(packet[41], 0);
    assert_eq!(u16::from_be_bytes([packet[44], packet[45]]), echo_id);
    assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), echo_seq);
    assert!(icmpv6_checksum_ok(packet));
}


// #4074 FAIL-ON-REVERT (RFC 5508 §3.1): pool SNAT translates the ICMP Query
// Identifier on the wire and repairs the ICMP checksum — forward (orig ->
// translated) on egress and reverse (translated -> orig) on the reply.
// Reverting `apply_nat_icmp_identifier_rewrite` leaves the identifier AND the
// checksum untouched, turning the translated-id and checksum assertions RED.
#[test]
fn rewrite_forwarded_frame_in_place_translates_icmpv4_echo_identifier() {
    let host = Ipv4Addr::new(10, 0, 1, 100);
    let target = Ipv4Addr::new(8, 8, 8, 8);
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let orig_id: u16 = 0x1234;
    let translated_id: u16 = 40001;
    // `flow_src_port` carries the packet's on-wire ICMP identifier (the parser
    // fills it); `restore_l4_tuple_from_meta` uses it, so it must match the
    // frame — orig id on the request, translated id on the reply.
    let meta_for = |flow_src_port: u16| UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_port,
        ..UserspaceDpMeta::default()
    };
    let meta = meta_for(orig_id);

    // Forward: host -> target, echo request. SNAT src to pool + translate id.
    let frame = build_icmp_frame_v4(host, target, 64, 8, orig_id);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let fwd_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(pool)),
        rewrite_src_port: Some(translated_id),
        ..NatDecision::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(fwd_nat),
        false,
        None,
    )
    .expect("fwd rewrite");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("fwd out");
    // eth 14 + ip 20 => icmp at 34; type@34, identifier@38..40.
    assert_eq!(out[34], 8, "still an echo request");
    assert_eq!(&out[26..30], &pool.octets(), "src translated to pool");
    assert_eq!(
        u16::from_be_bytes([out[38], out[39]]),
        translated_id,
        "identifier translated on the wire",
    );
    assert_eq!(
        checksum16(&out[34..]),
        0,
        "ICMPv4 checksum valid after id rewrite",
    );

    // Reverse: reply target -> pool carries the translated id; un-NAT restores
    // the original id and dst. Use the real NatDecision::reverse inversion.
    let reply = build_icmp_frame_v4(target, pool, 64, 0, translated_id);
    let mut rarea = MmapArea::new(4096).expect("mmap");
    rarea
        .slice_mut(0, reply.len())
        .unwrap()
        .copy_from_slice(&reply);
    let rev_nat = fwd_nat.reverse(IpAddr::V4(host), IpAddr::V4(target), orig_id, 0);
    let rres = rewrite_forwarded_frame_in_place(
        &rarea,
        XdpDesc {
            addr: 0,
            len: reply.len() as u32,
            options: 0,
        },
        meta_for(translated_id),
        &icmp_test_decision(rev_nat),
        false,
        None,
    )
    .expect("rev rewrite");
    let rout = rarea
        .slice(rres.offset as usize, rres.len as usize)
        .expect("rev out");
    assert_eq!(rout[34], 0, "still an echo reply");
    assert_eq!(&rout[30..34], &host.octets(), "dst un-NAT'd to the host");
    assert_eq!(
        u16::from_be_bytes([rout[38], rout[39]]),
        orig_id,
        "identifier restored to the original on the reply",
    );
    assert_eq!(
        checksum16(&rout[34..]),
        0,
        "ICMPv4 checksum valid after reverse id rewrite",
    );
}


#[test]
fn nat64_4381_forward_frame_translates_l4_source_port() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap(); // ::8.8.8.8
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let orig_sport = 5000u16;
    let translated = 40001u16;

    let frame = build_ipv6_tcp_syn_with_mss(client, synthetic, orig_sport, 443, 1460);
    let decision = icmp_test_decision(Nat64State::forward_decision(pool, server, translated));
    let out = build_nat64_forwarded_frame(&frame, nat64_forward_meta(), &decision, None, false, &ForwardingState::default())
        .expect("forward NAT64 frame");

    // Output is IPv4 (eth 14 + ip 20 => L4 at 34); src IP @26..30, TCP src
    // port @34..36, dst port @36..38.
    assert_eq!(&out[26..30], &pool.octets(), "src IP translated to pool");
    assert_eq!(&out[30..34], &server.octets(), "dst IP is the real server");
    assert_eq!(
        u16::from_be_bytes([out[34], out[35]]),
        translated,
        "#4381: L4 source port rewritten to the unique translated port"
    );
    assert_eq!(
        u16::from_be_bytes([out[36], out[37]]),
        443,
        "destination port unchanged"
    );
    // The TCP checksum after the incremental port+address delta equals a full
    // recompute (one's-complement exactness).
    let mut recomputed = out.clone();
    recompute_l4_checksum_ipv4(&mut recomputed[14..], 20, PROTO_TCP, false).expect("v4 sum");
    assert_eq!(
        &out[50..52],
        &recomputed[50..52],
        "TCP checksum valid after forward port translation"
    );
}


#[test]
fn nat64_2562_forward_nonfirst_fragment_frame_translates_l3_only() {
    // #2562: build_nat64_forwarded_frame must L3-translate a NON-first v6
    // fragment (no L4 header) using the association-carried decision, instead of
    // dropping it. Frame = eth(14) + v6(40) + Fragment Header(8) + payload.
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap(); // ::8.8.8.8
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let ident: u32 = 0x0001_2345;
    let payload: &[u8] = &[0x5Au8; 24];

    let mut frame = vec![0u8; 14 + 40 + 8 + payload.len()];
    // Ethernet: dst/src MAC arbitrary, ethertype IPv6.
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    // IPv6 header.
    frame[14] = 0x60;
    let v6_payload_len = (8 + payload.len()) as u16;
    frame[18..20].copy_from_slice(&v6_payload_len.to_be_bytes());
    frame[20] = 44; // next header = Fragment
    frame[21] = 64; // hop limit
    frame[22..38].copy_from_slice(&client.octets());
    frame[38..54].copy_from_slice(&synthetic.octets());
    // Fragment Header (offset 100 units => non-first, MF=0).
    frame[54] = PROTO_UDP; // next header
    let word: u16 = (100u16 << 3) | 0;
    frame[56..58].copy_from_slice(&word.to_be_bytes());
    frame[58..62].copy_from_slice(&ident.to_be_bytes());
    frame[62..].copy_from_slice(payload);

    let decision = icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
    let out = build_nat64_forwarded_frame(&frame, nat64_forward_meta(), &decision, None, false, &ForwardingState::default())
        .expect("#2562: non-first v6 fragment L3-translates, not dropped");

    // Output is eth(14) + IPv4(20) + payload; NO L4 rewrite.
    assert_eq!(out[14] >> 4, 4, "output is IPv4");
    assert_eq!(&out[26..30], &pool.octets(), "inherited SNAT source");
    assert_eq!(&out[30..34], &server.octets(), "inherited v4 destination");
    // v4 ident = low 16 of the v6 ident; offset preserved; MF=0; DF=0.
    assert_eq!(
        u16::from_be_bytes([out[18], out[19]]),
        (ident & 0xFFFF) as u16
    );
    let fw = u16::from_be_bytes([out[20], out[21]]);
    assert_eq!(fw & 0x1FFF, 100, "fragment offset preserved");
    assert_eq!(fw & 0x2000, 0, "MF=0 (last fragment)");
    assert_eq!(fw & 0x4000, 0, "DF cleared");
    // Payload copied verbatim.
    assert_eq!(&out[34..], payload, "payload verbatim, no L4 touch");
}


#[test]
fn nat64_4381_reverse_frame_restores_each_clients_original_port() {
    // Two clients behind ONE pool address, distinct translated ports; each
    // reply must restore its OWN original client port (no cross-talk).
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let cases: [(Ipv6Addr, u16, u16); 2] = [
        ("2001:db8::1".parse().unwrap(), 5000, 40001),
        ("2001:db8::2".parse().unwrap(), 5000, 40002),
    ];
    for (client, orig_sport, translated) in cases {
        // Reply: server:443 -> pool:translated (what the server replied to).
        let reply = build_ipv4_tcp_frame(
            server,
            pool,
            443,
            translated,
            1,
            1,
            crate::tcp_flags::TCP_ACK,
        );
        // Reverse decision = forward decision inverted (as poll_descriptor does).
        let fwd = Nat64State::forward_decision(pool, server, translated);
        let rev = fwd.reverse(IpAddr::V6(client), IpAddr::V6(synthetic), orig_sport, 443);
        let decision = icmp_test_decision(rev);
        let info = Nat64ReverseInfo {
            orig_src_v6: client,
            orig_dst_v6: synthetic,
        };
        let out = build_nat64_forwarded_frame(
            &reply,
            nat64_reverse_meta(),
            &decision,
            Some(&info),
            false,
            &ForwardingState::default(),
        )
        .expect("reverse NAT64 frame");

        // Output is IPv6 (eth 14 + ip 40 => L4 at 54); dst IP @38..54, TCP
        // src port @54..56, dst port @56..58.
        assert_eq!(
            &out[38..54],
            &client.octets(),
            "reply delivered to the correct original client"
        );
        assert_eq!(
            u16::from_be_bytes([out[54], out[55]]),
            443,
            "source (server) port unchanged"
        );
        assert_eq!(
            u16::from_be_bytes([out[56], out[57]]),
            orig_sport,
            "#4381: reply dst port restored to THIS client's original source port"
        );
        // Checksum valid after the reverse (dst-port + address) delta.
        let mut recomputed = out.clone();
        recompute_l4_checksum_ipv6(&mut recomputed[14..], 40, PROTO_TCP).expect("v6 sum");
        assert_eq!(
            &out[70..72],
            &recomputed[70..72],
            "TCP checksum valid after reverse port restoration"
        );
    }
}

// #5606: the NAT64 reverse (v4->v6) frame builder HARD-REQUIRES the request's
// `nat64_reverse` (original v6 src/dst) to translate a server's IPv4 reply back
// to IPv6. When the poll loop failed to thread it (the pre-#5606 hard-coded
// `nat64_reverse: None` on the live forward request), this AF_INET branch
// returned `None` and the reply was dropped. This pins BOTH halves of that
// contract: `Some(info)` yields a correct IPv6 reply addressed to the original
// client (NOT IPv4), and `None` fails closed (drops).
#[test]
fn nat64_5606_reverse_frame_requires_reverse_info_or_drops() {
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let translated = 40001u16;
    let orig_sport = 5000u16;

    // Reply: server:443 -> pool:translated (what the server replied to).
    let reply = build_ipv4_tcp_frame(
        server,
        pool,
        443,
        translated,
        1,
        1,
        crate::tcp_flags::TCP_ACK,
    );
    // Reverse decision = forward decision inverted (as poll_descriptor does).
    let fwd = Nat64State::forward_decision(pool, server, translated);
    let rev = fwd.reverse(IpAddr::V6(client), IpAddr::V6(synthetic), orig_sport, 443);
    let decision = icmp_test_decision(rev);
    let info = Nat64ReverseInfo {
        orig_src_v6: client,
        orig_dst_v6: synthetic,
    };

    // WITH reverse info: a correct IPv6 reply addressed to the original client.
    // Output is IPv6 (eth 14 + ip 40): ethertype @12..14, src IP @22..38,
    // dst IP @38..54.
    let out = build_nat64_forwarded_frame(&reply, nat64_reverse_meta(), &decision, Some(&info), false, &ForwardingState::default())
        .expect("#5606: reverse info present -> IPv6 reply built");
    assert_eq!(
        u16::from_be_bytes([out[12], out[13]]),
        0x86dd,
        "#5606: reverse reply must be IPv6 (ethertype 0x86dd), not IPv4"
    );
    assert_eq!(
        &out[22..38],
        &synthetic.octets(),
        "#5606: src = original v6 server (NAT64-prefix embedded), not the v4 pool"
    );
    assert_eq!(
        &out[38..54],
        &client.octets(),
        "#5606: dst = original v6 client, so the reply reaches the real host"
    );

    // WITHOUT reverse info: the builder cannot reconstruct the v6 tuple and
    // fails closed (None) — the pre-#5606 dropped-reply symptom.
    assert!(
        build_nat64_forwarded_frame(&reply, nat64_reverse_meta(), &decision, None, false, &ForwardingState::default()).is_none(),
        "#5606: missing reverse info must fail closed (None) — the dropped-reply symptom"
    );
}

#[test]
fn rewrite_forwarded_frame_in_place_translates_icmpv6_echo_identifier() {
    let host = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
    let target = "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap();
    let pool = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
    let orig_id: u16 = 0x3e0f;
    let translated_id: u16 = 40002;
    // `flow_src_port` mirrors the packet's on-wire ICMPv6 identifier so
    // `restore_l4_tuple_from_meta` is a no-op and MY incremental checksum
    // adjustment (not a full recompute) is what the test validates.
    let meta_for = |flow_src_port: u16| UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        flow_src_port,
        ..UserspaceDpMeta::default()
    };
    let meta = meta_for(orig_id);

    // Forward: host -> target, echo request (128). SNAT src + translate id.
    let frame = build_icmpv6_echo_frame(host, target, 64, 128, orig_id);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let fwd_nat = NatDecision {
        rewrite_src: Some(IpAddr::V6(pool)),
        rewrite_src_port: Some(translated_id),
        ..NatDecision::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(fwd_nat),
        false,
        None,
    )
    .expect("fwd v6 rewrite");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("fwd v6 out");
    // eth 14 + ipv6 40 => icmp at 54; type@54, identifier@58..60.
    assert_eq!(out[54], 128, "still an echo request");
    assert_eq!(&out[22..38], &pool.octets(), "src translated to pool");
    assert_eq!(
        u16::from_be_bytes([out[58], out[59]]),
        translated_id,
        "identifier translated on the wire",
    );
    assert!(
        icmpv6_checksum_ok(&out[14..]),
        "ICMPv6 checksum valid after id rewrite",
    );

    // Reverse: reply target -> pool with the translated id; un-NAT restores it.
    let reply = build_icmpv6_echo_frame(target, pool, 64, 129, translated_id);
    let mut rarea = MmapArea::new(4096).expect("mmap");
    rarea
        .slice_mut(0, reply.len())
        .unwrap()
        .copy_from_slice(&reply);
    let rev_nat = fwd_nat.reverse(IpAddr::V6(host), IpAddr::V6(target), orig_id, 0);
    let rres = rewrite_forwarded_frame_in_place(
        &rarea,
        XdpDesc {
            addr: 0,
            len: reply.len() as u32,
            options: 0,
        },
        meta_for(translated_id),
        &icmp_test_decision(rev_nat),
        false,
        None,
    )
    .expect("rev v6 rewrite");
    let rout = rarea
        .slice(rres.offset as usize, rres.len as usize)
        .expect("rev v6 out");
    assert_eq!(rout[54], 129, "still an echo reply");
    assert_eq!(&rout[38..54], &host.octets(), "dst un-NAT'd to the host");
    assert_eq!(
        u16::from_be_bytes([rout[58], rout[59]]),
        orig_id,
        "identifier restored to the original on the reply",
    );
    assert!(
        icmpv6_checksum_ok(&rout[14..]),
        "ICMPv6 checksum valid after reverse id rewrite",
    );
}


// #4074: end-to-end — a DNAT'd ICMP echo (address-only, `rewrite_dst` set,
// `rewrite_dst_port` None, which is what the gated DNAT lookup now produces for
// a port-less protocol) must PRESERVE the ICMP Query Identifier and leave the
// checksum valid. This is the wire-level counterpart to the decision-layer test
// `dnat_pooled_port_does_not_translate_icmp_identifier`: the gate keeps
// `rewrite_dst_port` None, so `apply_nat_icmp_identifier_rewrite` no-ops here.
#[test]
fn rewrite_forwarded_frame_in_place_dnat_preserves_icmpv4_identifier() {
    let client = Ipv4Addr::new(198, 51, 100, 1);
    let public = Ipv4Addr::new(203, 0, 113, 10);
    let internal = Ipv4Addr::new(10, 0, 0, 5);
    let orig_id: u16 = 0x1234;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_port: orig_id,
        ..UserspaceDpMeta::default()
    };
    let frame = build_icmp_frame_v4(client, public, 64, 8, orig_id);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    // Address-only DNAT decision (the gated lookup's output for ICMP).
    let dnat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(internal)),
        rewrite_dst_port: None,
        ..NatDecision::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(dnat),
        false,
        None,
    )
    .expect("dnat rewrite");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("dnat out");
    assert_eq!(&out[30..34], &internal.octets(), "dst translated by DNAT");
    assert_eq!(
        u16::from_be_bytes([out[38], out[39]]),
        orig_id,
        "ICMP identifier PRESERVED through address-only DNAT",
    );
    assert_eq!(
        checksum16(&out[34..]),
        0,
        "ICMPv4 checksum valid (identifier untouched)",
    );
}



// #5191 FAIL-ON-REVERT (RFC 792 / RFC 1624): the metadata ICMP-identifier
// restore in `restore_l4_tuple_from_meta` must repair the ICMPv4 checksum for
// the bytes it changes. IPv4 ICMP has no arm in `recompute_l4_checksum_ipv4`
// (only TCP and UDP), so before #5191 the restore rewrote [l4+4, l4+6) and the
// message left the box with the PRE-change checksum — every receiver
// (RFC 1122 §3.2.2 requires the check) discards it.
//
// The expected checksum here is computed INDEPENDENTLY, from the bytes the
// message must end up carrying, with the general `checksum16` routine — not
// read back from whatever the incremental adjuster produced. Reverting the
// `checksum16_adjust` write in `write_icmp_identifier` fails BOTH the
// independent-value assertion and the `checksum16(icmp) == 0` validity
// assertion.
#[test]
fn restore_icmpv4_identifier_repairs_the_icmp_checksum_5191() {
    let host = Ipv4Addr::new(10, 0, 1, 100);
    let target = Ipv4Addr::new(8, 8, 8, 8);
    let on_wire_id: u16 = 0x1111;
    let session_id: u16 = 0x2222;

    // The frame carries `on_wire_id`; the session metadata says the flow's
    // identifier is `session_id`, so the restore has a real repair to make.
    let frame = build_icmp_frame_v4(host, target, 64, 8, on_wire_id);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_port: session_id,
        ..UserspaceDpMeta::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(NatDecision::default()),
        false,
        None,
    )
    .expect("in-place icmpv4 forward");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("rewritten frame");

    // eth 14 + ip 20 => ICMP at 34; type@34, checksum@36..38, ident@38..40.
    assert_eq!(out[34], 8, "still an echo request");
    assert_eq!(
        u16::from_be_bytes([out[38], out[39]]),
        session_id,
        "identifier restored from the session metadata",
    );

    // Independent expectation: the ICMPv4 checksum of the message the frame
    // must now carry, computed from scratch over a locally-built copy with the
    // checksum field zeroed. Nothing here reads the emitted checksum.
    let expected_msg = [
        8u8,
        0,
        0,
        0,
        (session_id >> 8) as u8,
        session_id as u8,
        0x00,
        0x01,
    ];
    let expected_csum = checksum16(&expected_msg);
    assert_eq!(
        u16::from_be_bytes([out[36], out[37]]),
        expected_csum,
        "ICMPv4 checksum equals the independently computed value",
    );
    assert_eq!(
        checksum16(&out[34..]),
        0,
        "ICMPv4 checksum verifies over the emitted message",
    );
}


// #5191 FAIL-ON-REVERT (RFC 792 §Redirect): the metadata identifier restore is
// gated on the identifier-bearing ICMP QUERY types. For an error/control
// message the [l4+4, l4+6) bytes are a gateway address / next-hop MTU / pointer
// / reserved field, never an identifier — and the metadata pseudo-port for such
// a packet is 0 (`parse_flow_ports` declines every non-query type, so the
// GRE-decap inner-meta synthesis in `gre.rs` falls back to `unwrap_or_default`).
// Before #5191 the ungated restore therefore ZEROED the top half of a forwarded
// Redirect's Gateway Internet Address. Reverting the `icmp_identifier_bearing`
// gate in `write_icmp_identifier` turns the gateway assertion RED.
#[test]
fn restore_icmpv4_identifier_skips_a_non_query_type_5191() {
    let router = Ipv4Addr::new(10, 0, 1, 1);
    let host = Ipv4Addr::new(10, 0, 1, 100);
    // ICMP Redirect (type 5). The builder's "id" argument lands on [l4+4,
    // l4+6), which for a Redirect is the HIGH half of the Gateway Internet
    // Address — 192.0 of gateway 192.0.0.1.
    let gateway_high: u16 = 0xc000;

    let frame = build_icmp_frame_v4(router, host, 64, 5, gateway_high);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        // What the GRE-decap meta synthesis produces for a non-query ICMP.
        flow_src_port: 0,
        ..UserspaceDpMeta::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(NatDecision::default()),
        false,
        None,
    )
    .expect("in-place icmpv4 redirect forward");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("rewritten frame");

    assert_eq!(out[34], 5, "still a Redirect");
    assert_eq!(
        u16::from_be_bytes([out[38], out[39]]),
        gateway_high,
        "Redirect gateway address must not be overwritten with a pseudo-port",
    );
    assert_eq!(
        checksum16(&out[34..]),
        0,
        "an untouched Redirect keeps its original valid checksum",
    );
}


// #5191 FAIL-ON-REVERT, IPv6 half of the query-type gate. The v6 path DOES have
// an ICMPv6 arm in `recompute_l4_checksum_ipv6`, so before #5191 the corrupted
// message was re-checksummed and left the box VERIFYING — the receiver accepts
// a message whose Maximum Response Delay has been silently zeroed, which is a
// worse outcome than the v4 drop. Reverting the `icmp_identifier_bearing` gate
// turns the delay assertion RED.
#[test]
fn restore_icmpv6_identifier_skips_a_non_query_type_5191() {
    let router: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let group: Ipv6Addr = "ff02::1".parse().unwrap();
    // MLD Query (type 130). [l4+4, l4+6) is the Maximum Response Delay.
    let max_response_delay: u16 = 10_000;

    let frame = build_icmpv6_echo_frame(router, group, 64, 130, max_response_delay);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        flow_src_port: 0,
        ..UserspaceDpMeta::default()
    };
    let res = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &icmp_test_decision(NatDecision::default()),
        false,
        None,
    )
    .expect("in-place icmpv6 mld forward");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("rewritten frame");

    // eth 14 + ipv6 40 => ICMPv6 at 54; delay@58..60.
    assert_eq!(out[54], 130, "still an MLD Query");
    assert_eq!(
        u16::from_be_bytes([out[58], out[59]]),
        max_response_delay,
        "MLD Maximum Response Delay must not be overwritten with a pseudo-port",
    );
}

/// #8890 — a tunnel-marked NAT64 decision must NOT produce a frame.
///
/// The measurement this cell replaces, taken at `c2e0a9ecb` before the gate
/// existed, is the reason it is written this way:
///
/// ```text
/// P8890 tunnel_endpoint_id=7 -> Some(len=58)  control_len=58  IDENTICAL_TO_PLAINTEXT=true
/// P8890   ethertype=0x0800   ipproto@23=0x06
/// ```
///
/// With a tunnel endpoint on the decision the builder returned a frame
/// **byte-identical to the no-tunnel control** — plain IPv4, no encapsulation
/// and no drop. Three outcomes were possible and that was the worst of them:
/// encapsulating would have refuted the finding, `None` would have been
/// fail-closed like #1873, and what actually happened was the inner packet
/// leaving unencrypted on the underlay.
///
/// **THE CONTROL IS LOAD-BEARING AND IS THE FIRST ASSERTION FOR THAT REASON.**
/// Asserting only `is_none()` on the subject is satisfied by a builder that
/// returns `None` for any reason at all — a broken fixture, a bad MAC, a
/// changed meta — so the cell would stay green while measuring nothing. The
/// control is what proves the builder produces a real translated frame from
/// this fixture, and byte-identity to a *working* output is what showed the
/// tunnel field was simply ignored. The only variable between the two arms is
/// `resolution.tunnel_endpoint_id`.
#[test]
fn nat64_8890_tunnel_marked_decision_is_not_emitted_plaintext() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_ipv6_tcp_syn_with_mss(client, synthetic, 5000, 443, 1460);

    // CONTROL: identical in every respect except tunnel_endpoint_id == 0.
    let control_decision =
        icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
    assert_eq!(
        control_decision.resolution.tunnel_endpoint_id, 0,
        "control arm must be untunnelled — if the fixture ever starts carrying a \
         tunnel id, both arms would be the subject and the cell would compare \
         nothing"
    );
    let control = build_nat64_forwarded_frame(
        &frame,
        nat64_forward_meta(),
        &control_decision,
        None,
        false,
        &ForwardingState::default(),
    )
    .expect(
        "NON-VACUITY: the untunnelled control MUST translate. If this fixture \
         cannot produce a frame, the `is_none()` assertion below is satisfied by \
         the fixture being broken rather than by the #8890 gate, and the cell \
         measures nothing",
    );
    // The control is a real, plain IPv4 frame — this is what "emitted as
    // plaintext" meant when the subject returned these same bytes.
    assert_eq!(
        &control[12..14],
        &0x0800u16.to_be_bytes(),
        "control must be plain IPv4 (ethertype 0x0800) — no encapsulation"
    );
    assert_eq!(
        &control[26..30],
        &pool.octets(),
        "control must be genuinely NAT64-translated, not a passthrough copy"
    );

    // SUBJECT: the same decision with a tunnel endpoint attached.
    //
    // SWEEP THE ID SPACE rather than pinning one value. The first version of
    // this cell used only 7, and the reverse cell used 7 as well, so both arms
    // sat at one point with the controls at 0 — leaving the gate FREE BETWEEN
    // THEM. A reviewer weakened `!= 0` to `> 1` and all four cells survived,
    // which leaks plaintext for endpoint id 1.
    //
    // **1 is not a boundary nobody hits.** `tunnel_endpoint_id` is a u16 whose
    // only reserved value is 0 — ~54 sites use `== 0` / `!= 0` as the
    // has-a-tunnel predicate — so 1 is a perfectly ordinary id and is the
    // natural FIRST one to allocate. A single-tunnel deployment is plausibly
    // exactly the case that would have leaked.
    for id in [1u16, 2, 7, u16::MAX] {
    let mut tunnel_decision =
        icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
    tunnel_decision.resolution.tunnel_endpoint_id = id;

    let subject = build_nat64_forwarded_frame(
        &frame,
        nat64_forward_meta(),
        &tunnel_decision,
        None,
        false,
        &ForwardingState::default(),
    );

    assert!(
        subject.is_none(),
        "#8890/#2327: a NAT64 decision whose tunnel endpoint resolves to NO ROW \
         must FAIL CLOSED. §8896 made a RESOLVED endpoint encapsulate, so this \
         arm now measures the residue rather than the whole combination — note \
         the empty `ForwardingState` passed above, which is what makes the id \
         unresolvable. The original measurement still stands: before §8890 the \
         frame was byte-identical to the control above ({} bytes, ethertype \
         0x0800), traffic an operator routed through WireGuard leaving as \
         plaintext on the underlay. The positive half is now \
         `nat64_8896_tunnel_marked_decision_is_encapsulated_not_plaintext`. \
         FAILING ID = {}. Got {:?} bytes.",
        control.len(),
        id,
        subject.as_ref().map(|f| f.len()),
    );
    }
}

/// #8890 — the gate must hold in the REVERSE (v4->v6) direction too.
///
/// **A hostile review proposed this exact weakening and it survived every other
/// cell**: restricting the gate to `meta.addr_family == AF_INET6` — i.e. the
/// forward direction only — left the builder cell above and both dispatcher
/// cells GREEN, because all three drive an IPv6 ingress. Measured, not
/// hypothesised.
///
/// The reverse direction has the same defect and needs the same gate. The
/// builder's v4->v6 arm performs no encapsulation either — `grep
/// 'encap|wg_|gre|tunnel_endpoint'` returns 0 for the WHOLE function, both arms
/// — so a reply toward an IPv6 client reached through a tunnel would leave
/// unencapsulated exactly as the forward packet did. Placing the gate above the
/// family match is what makes one line cover both, and this cell is what stops
/// someone narrowing it to a single arm.
#[test]
fn nat64_8890_gate_holds_in_the_reverse_v4_to_v6_direction() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let orig_sport = 5000u16;
    let translated = 40001u16;

    let reply = build_ipv4_tcp_frame(
        server, pool, 443, translated, 1, 1, crate::tcp_flags::TCP_ACK,
    );
    let fwd = Nat64State::forward_decision(pool, server, translated);
    let rev = fwd.reverse(IpAddr::V6(client), IpAddr::V6(synthetic), orig_sport, 443);
    let info = Nat64ReverseInfo {
        orig_src_v6: client,
        orig_dst_v6: synthetic,
    };

    // CONTROL: untunnelled reverse reply builds a real IPv6 frame.
    let control_decision = icmp_test_decision(rev.clone());
    assert_eq!(
        control_decision.resolution.tunnel_endpoint_id, 0,
        "control arm must be untunnelled, or both arms are the subject"
    );
    let control = build_nat64_forwarded_frame(
        &reply,
        nat64_reverse_meta(),
        &control_decision,
        Some(&info),
        false,
        &ForwardingState::default(),
    )
    .expect(
        "NON-VACUITY: the untunnelled reverse control MUST build. The reverse arm          already fails closed without reverse info (#5606), so a broken fixture          here would satisfy the is_none() below for the wrong reason entirely",
    );
    assert_eq!(
        u16::from_be_bytes([control[12], control[13]]),
        0x86dd,
        "control must be a genuine IPv6 reply, so the subject's None is about the          tunnel and not about the reverse translation failing"
    );

    // SUBJECT: same reverse reply, tunnel-marked.
    let mut tunnel_decision = icmp_test_decision(rev);
    // Deliberately 1, not 7: 1 is the natural FIRST endpoint id to allocate and
    // the value a `> 1` off-by-one would let through. The forward cell sweeps
    // {1, 2, 7, u16::MAX}; this arm pins the dangerous end of that range so the
    // reverse direction cannot regress to a two-point fixture either.
    tunnel_decision.resolution.tunnel_endpoint_id = 1;
    let subject = build_nat64_forwarded_frame(
        &reply,
        nat64_reverse_meta(),
        &tunnel_decision,
        Some(&info),
        false,
        &ForwardingState::default(),
    );

    assert!(
        subject.is_none(),
        "#8890 must gate the REVERSE (v4->v6) direction as well as the forward          one. The reverse arm encapsulates nothing either, so a tunnel-marked          reply toward an IPv6 client would go out unencapsulated. A gate narrowed          to AF_INET6 survives every other #8890 cell — this is the one that          catches it. Got {:?} bytes.",
        subject.as_ref().map(|f| f.len()),
    );
}

// ===========================================================================
// #8896: NAT64 + native tunnel now COMPOSE. The cells below are the positive
// half; the two #8890 cells above are retained as the fail-closed control for
// the residue (#2327: no endpoint row / unknown mode).
// ===========================================================================

/// Build a ForwardingState carrying one native-GRE endpoint at `id`, plus the
/// physical egress the outer path resolves through.
fn gre_forwarding_8896(id: u16) -> ForwardingState {
    let mut fwd = ForwardingState::default();
    // The decision fixture resolves egress_ifindex=12 / tx_ifindex=11, and the
    // GRE builder refuses a decision whose egress_ifindex disagrees with the
    // endpoint's logical_ifindex. Populate both so the outer MTU resolves.
    for ifx in [11, 12] {
        fwd.egress.insert(
            ifx,
            EgressInterface {
                bind_ifindex: 0,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0, 0, 0, 0, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );
    }
    fwd.tunnel_endpoints.insert(
        id,
        TunnelEndpoint {
            id,
            logical_ifindex: 12,
            interface_label: "gr-0/0/0".into(),
            interface: "gr-0/0/0.0".into(),
            redundancy_group: 0,
            mode: "gre".into(),
            outer_family: libc::AF_INET,
            source: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            key: 0,
            ttl: 64,
            transport_table: String::new(),
            wg_listen_port: 0,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        },
    );
    fwd
}

/// #8896: the composed output is ENCAPSULATED, and specifically it is not the
/// plaintext frame #8890 measured.
///
/// **The control is the same load-bearing one #8890 used, and it is why this
/// cell can tell composition from a no-op.** An `is_some()` assertion on the
/// subject alone is satisfied by a builder that ignored the tunnel field
/// entirely — which is exactly the `c2e0a9ecb` defect, where the tunnel-marked
/// output was byte-identical to the untunnelled control. So the subject must
/// differ from the control AND carry the tunnel's own outer header.
#[test]
fn nat64_8896_tunnel_marked_decision_is_encapsulated_not_plaintext() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_ipv6_tcp_syn_with_mss(client, synthetic, 5000, 443, 1460);

    let control_decision = icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
    assert_eq!(control_decision.resolution.tunnel_endpoint_id, 0);
    let control = build_nat64_forwarded_frame(
        &frame,
        nat64_forward_meta(),
        &control_decision,
        None,
        false,
        &ForwardingState::default(),
    )
    .expect(
        "NON-VACUITY: the untunnelled control MUST translate, or every comparison \
         below is against an absent frame",
    );

    // Sweep the id space for the same reason #8890 does: a single pinned id
    // leaves the predicate free between the pinned value and 0.
    for id in [1u16, 2, 7, u16::MAX] {
        let fwd = gre_forwarding_8896(id);
        let mut tunnel_decision =
            icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
        tunnel_decision.resolution.tunnel_endpoint_id = id;

        let subject = build_nat64_forwarded_frame(
            &frame,
            nat64_forward_meta(),
            &tunnel_decision,
            None,
            false,
            &fwd,
        )
        .unwrap_or_else(|| {
            panic!(
                "#8896: a NAT64 decision routed through a RESOLVED native-GRE \
                 endpoint must now be encapsulated, not dropped. id={id}"
            )
        });

        assert_ne!(
            subject, control,
            "#8896: the tunnel-marked output is BYTE-IDENTICAL to the untunnelled \
             control — the tunnel field was ignored and the inner packet is \
             leaving as plaintext on the underlay. That is the exact \
             `c2e0a9ecb` measurement #8890 gated. id={id}"
        );
        // The outer header is the TUNNEL's: IPv4 outer, protocol 47 (GRE),
        // source and destination from the endpoint row rather than the NAT64
        // pool/server the inner packet carries.
        assert_eq!(
            &subject[12..14],
            &0x0800u16.to_be_bytes(),
            "#8896: outer ethertype must be IPv4 for an AF_INET GRE outer. id={id}"
        );
        assert_eq!(
            subject[23], 47,
            "#8896: outer IP protocol must be 47 (GRE). Got {}. id={id}",
            subject[23]
        );
        assert_eq!(
            &subject[26..30],
            &Ipv4Addr::new(172, 16, 80, 8).octets(),
            "#8896: outer source must be the tunnel endpoint's, not the NAT64 pool. id={id}"
        );
        assert_eq!(
            &subject[30..34],
            &Ipv4Addr::new(203, 0, 113, 9).octets(),
            "#8896: outer destination must be the tunnel endpoint's. id={id}"
        );
    }
}

/// #8896 / #2327: the fail-closed posture is UNCHANGED for the genuine
/// residue. An endpoint id resolving to no row, or to a row whose mode is
/// neither GRE nor WireGuard, is still dropped rather than emitted.
///
/// This is what `nat64_tunnel_encap_unsupported` counts now that a known mode
/// is no longer part of the unsupported set.
#[test]
fn nat64_8896_unknown_mode_and_missing_row_still_fail_closed() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_ipv6_tcp_syn_with_mss(client, synthetic, 5000, 443, 1460);

    for id in [1u16, 2, 7, u16::MAX] {
        let mut decision = icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
        decision.resolution.tunnel_endpoint_id = id;

        // (a) no endpoint row at all.
        assert!(
            build_nat64_forwarded_frame(
                &frame,
                nat64_forward_meta(),
                &decision,
                None,
                false,
                &ForwardingState::default(),
            )
            .is_none(),
            "#2327: a tunnel id resolving to NO endpoint row must fail closed. id={id}"
        );

        // (b) a row whose mode is neither GRE nor WireGuard. A fail-OPEN
        // default here would GRE-encapsulate an unrecognised or future mode.
        let mut fwd = gre_forwarding_8896(id);
        fwd.tunnel_endpoints.get_mut(&id).expect("row").mode = "ipsec-vti-future".into();
        assert!(
            build_nat64_forwarded_frame(
                &frame,
                nat64_forward_meta(),
                &decision,
                None,
                false,
                &fwd,
            )
            .is_none(),
            "#2327: an UNKNOWN tunnel mode must fail closed, not fall back to GRE. id={id}"
        );
    }
}

/// #8896: the composition claims the encapsulators read exactly two meta
/// fields — `addr_family` and `l3_offset`. This binds that claim.
///
/// Every OTHER field is poisoned with a value unlike the real one; the emitted
/// bytes must not change. If a third field is ever read, this reds and the
/// `nat64_translated_meta` doc comment stops being true silently.
#[test]
fn nat64_8896_encap_ignores_every_meta_field_but_family_and_l3() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let frame = build_ipv6_tcp_syn_with_mss(client, synthetic, 5000, 443, 1460);
    let fwd = gre_forwarding_8896(7);
    let mut decision = icmp_test_decision(Nat64State::forward_decision(pool, server, 40001));
    decision.resolution.tunnel_endpoint_id = 7;

    let clean =
        build_nat64_forwarded_frame(&frame, nat64_forward_meta(), &decision, None, false, &fwd)
            .expect("NON-VACUITY: the clean arm must encapsulate or there is nothing to compare");

    let mut poisoned = nat64_forward_meta();
    poisoned.ingress_ifindex = 0xDEAD;
    poisoned.ingress_vlan_id = 4094;
    poisoned.ingress_pcp = 7;
    poisoned.ingress_vlan_present = 1;
    poisoned.l4_offset = 0xFFFF;
    poisoned.payload_offset = 0xFFFF;
    poisoned.pkt_len = 0xFFFF;
    poisoned.tcp_flags = 0xFF;
    poisoned.meta_flags = 0xFF;
    poisoned.dscp = 0x3F;
    poisoned.flow_src_port = 0xFFFF;
    poisoned.flow_dst_port = 0xFFFF;

    let out = build_nat64_forwarded_frame(&frame, poisoned, &decision, None, false, &fwd)
        .expect("the poisoned arm must still encapsulate — only unread fields were changed");

    assert_eq!(
        out, clean,
        "#8896: poisoning a meta field OTHER than addr_family/l3_offset changed the \
         emitted frame, so the tunnel encapsulators read more of `meta` than \
         `nat64_translated_meta` rebuilds. That function's claim — and the #8890 \
         doc comment's list of three `addr_family` sites — is now incomplete"
    );
}

/// #8896: the composition must hold in the REVERSE (v4->v6) direction too.
///
/// This cell exists for the reason the #8890 reverse cell exists, restated for
/// the positive half: **a composition narrowed to the forward direction
/// survives every other #8896 cell.** All three above drive v6->v4 ingress, so
/// an `addr_family` rebuild that only handled `AF_INET6` — or a tunnel
/// post-pass reached only from the forward arm — would pass them all and drop
/// (or leak) every reply toward an IPv6 client.
#[test]
fn nat64_8896_encapsulates_the_reverse_v4_to_v6_direction() {
    let client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let synthetic: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let pool = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(8, 8, 8, 8);
    let orig_sport = 5000u16;
    let translated = 40001u16;

    let reply = build_ipv4_tcp_frame(
        server,
        pool,
        443,
        translated,
        1,
        1,
        crate::tcp_flags::TCP_ACK,
    );
    let fwd_state = Nat64State::forward_decision(pool, server, translated);
    let rev = fwd_state.reverse(IpAddr::V6(client), IpAddr::V6(synthetic), orig_sport, 443);
    let info = Nat64ReverseInfo {
        orig_src_v6: client,
        orig_dst_v6: synthetic,
    };

    // CONTROL: the untunnelled reverse reply is a real, plain IPv6 frame.
    let control = build_nat64_forwarded_frame(
        &reply,
        nat64_reverse_meta(),
        &icmp_test_decision(rev.clone()),
        Some(&info),
        false,
        &ForwardingState::default(),
    )
    .expect("NON-VACUITY: the untunnelled reverse control MUST build");
    assert_eq!(
        u16::from_be_bytes([control[12], control[13]]),
        0x86dd,
        "CONTROL: the reverse arm must produce a genuine IPv6 reply, or the \
         comparison below is against a broken fixture"
    );

    // SUBJECT: id 1 — the natural first id and the value a `> 1` off-by-one
    // lets through, matching the reverse #8890 cell's choice.
    let tunnel_id = 1u16;
    let gre = gre_forwarding_8896(tunnel_id);
    let mut tunnel_decision = icmp_test_decision(rev);
    tunnel_decision.resolution.tunnel_endpoint_id = tunnel_id;

    let subject = build_nat64_forwarded_frame(
        &reply,
        nat64_reverse_meta(),
        &tunnel_decision,
        Some(&info),
        false,
        &gre,
    )
    .expect(
        "#8896: the REVERSE (v4->v6) NAT64 direction through a resolved native-GRE \
         endpoint must encapsulate. If this is None while the forward cells pass, \
         the composition was wired into the forward arm only",
    );

    assert_ne!(
        subject, control,
        "#8896 reverse: the tunnel-marked reply is byte-identical to the \
         untunnelled control — the reply is leaving as plaintext on the underlay"
    );
    // The outer header is the tunnel's IPv4 outer even though the INNER packet
    // is now IPv6 — which is the whole point of rebuilding `addr_family`.
    assert_eq!(
        &subject[12..14],
        &0x0800u16.to_be_bytes(),
        "#8896 reverse: outer ethertype must be IPv4 (the GRE outer family), not \
         the inner IPv6 family"
    );
    assert_eq!(
        subject[23], 47,
        "#8896 reverse: outer IP protocol must be 47 (GRE). Got {}",
        subject[23]
    );
    assert_eq!(
        &subject[30..34],
        &Ipv4Addr::new(203, 0, 113, 9).octets(),
        "#8896 reverse: outer destination must be the tunnel endpoint's"
    );
}
