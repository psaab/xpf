// TCP port authority/repair, live-forward-request port selection, and build-forwarded-frame-into port handling.
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
fn enforce_expected_ports_repairs_ipv6_tcp_ports_and_checksum() {
    let src_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
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
        0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 5201
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[18..], 40, PROTO_TCP).expect("initial checksum");
    assert!(tcp_checksum_ok_ipv6(&frame[18..]));

    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET6 as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        false,
    )
    .expect("repair");
    assert!(repaired);
    assert_eq!(tcp_ports_ipv6(&frame[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&frame[18..]));
}


#[test]
fn enforce_expected_ports_repairs_ipv4_tcp_ports_and_checksum() {
    let src_ip = Ipv4Addr::new(172, 16, 80, 8);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 54688
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, true).expect("initial checksum");
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));

    let repaired = enforce_expected_ports(
        &mut frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        Some((54688, 5201)),
        false,
    )
    .expect("repair");
    assert!(repaired);
    assert_eq!(tcp_ports_ipv4(&frame[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));
}


#[test]
fn rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv6(&frame[14..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: 5201,
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
        Some((54688, 5201)),
        0,
    )
    .expect("rewrite in place");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_forwarded_frame_into_keeps_ipv6_tcp_ports_after_vlan_snat() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&[
        0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv6(&frame[14..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: 5201,
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
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((54688, 5201)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
        "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_forwarded_frame_into_ignores_ipv6_tcp_metadata_port_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 38276u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: real_dst_port,
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
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_live_forward_request_prefers_session_flow_ports_over_frame() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let frame_src_port = 38276u16;
    let frame_dst_port = 5201u16;
    let session_src_port = 1025u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&frame_src_port.to_be_bytes());
    frame.extend_from_slice(&frame_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: session_src_port,
        flow_dst_port: frame_dst_port,
        ..UserspaceDpMeta::default()
    };
    // Session flow ports differ from frame ports — session is authoritative
    // because it is immune to UMEM DMA races.
    let session_flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: session_src_port,
            dst_port: frame_dst_port,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
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
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some(&session_flow),
        None,
        false,
        0,
    )
    .expect("request");
    // Session flow ports (1025, 5201) take priority over frame ports (38276, 5201)
    assert_eq!(req.expected_ports, Some((session_src_port, frame_dst_port)));
}


#[test]
fn build_live_forward_request_uses_live_frame_ports_when_no_session_flow() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 38276u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: real_dst_port,
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
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
        },
    );
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    // No session flow — live frame ports should be used (over meta ports)
    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("request");
    assert_eq!(req.expected_ports, Some((real_src_port, real_dst_port)));
}


#[test]
fn build_live_forward_request_meters_non_l4_metadata_flow() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        pkt_len: 128,
        flow_src_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&src_ip.octets());
            bytes
        },
        flow_dst_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&dst_ip.octets());
            bytes
        },
        ..UserspaceDpMeta::default()
    };
    let filter_state = crate::filter::parse_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter-gre".into(),
                action: "accept".into(),
                protocols: vec!["gre".into()],
                policer: "gre-pol".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "gre-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 64,
            peak_or_excess_burst_bytes: 32,
            then_action: "discard".into(),
            ..Default::default()
        }],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 10,
            filter_input_v4: "policed".into(),
            ..Default::default()
        }],
        "policed",
        "",
    ).expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.cos.interfaces.insert(
        12,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: crate::afxdp::cos::COS_MIN_BURST_BYTES,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: Vec::new(),
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
            inet_precedence_classifier: String::new(),
            inet_precedence_queue_by_prec: [u8::MAX; 8],
        },
    );
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    );

    assert!(
        req.is_none(),
        "red-drop policer should reject non-L4 metadata flow"
    );
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}


#[test]
fn build_live_forward_request_marks_empty_cos_selection_resolved() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        pkt_len: 64,
        flow_src_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&src_ip.octets());
            bytes
        },
        flow_dst_addr: {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&dst_ip.octets());
            bytes
        },
        ..UserspaceDpMeta::default()
    };
    let filter_state = crate::filter::parse_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter-gre".into(),
                action: "accept".into(),
                protocols: vec!["gre".into()],
                policer: "gre-pol".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "gre-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 128,
            peak_or_excess_burst_bytes: 64,
            then_action: "discard".into(),
            ..Default::default()
        }],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 10,
            filter_input_v4: "policed".into(),
            ..Default::default()
        }],
        "policed",
        "",
    ).expect("filter state compiles");
    let forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("green policer should permit request");

    assert_eq!(req.cos_queue_id, None);
    assert_eq!(req.dscp_rewrite, None);
    assert!(req.cos_tx_selection_resolved);
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
}


#[test]
fn build_live_forward_request_emits_output_filter_log_event() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 20);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 64,
        dscp: 0,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 49152,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "egress-log".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/2.0".into(),
            ifindex: 12,
            filter_output_v4: "egress-log".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.ifindex_to_zone_id.insert(10, TEST_LAN_ZONE_ID);
    // #6722: the EGRESS zone comes from `ifindex_unambiguous_zone_id`, not from
    // the `egress` row. `populate_egress` sources `EgressInterface::zone_id`
    // from this same map, so a hand-built state that sets one without the other
    // models a state the builder cannot produce. Both are set here for that
    // reason, not because the resolver reads both.
    forwarding
        .ifindex_unambiguous_zone_id
        .insert(12, TEST_WAN_ZONE_ID);
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(198, 51, 100, 1)),
            primary_v6: None,
        },
    );
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    )
    .expect("output filter log should not block forwarding");

    assert!(req.cos_tx_selection_resolved);
    let filter_event = event_rx
        .try_recv()
        .expect("output filter-log event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(filter_event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(filter_event.filter_id, 0);
    assert_eq!(filter_event.term_id, 0);
    assert_eq!(filter_event.reason, FilterLogSource::Output.wire_reason());
    assert_eq!(filter_event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(filter_event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}


/// Build the #6722 secure-tunnel state through the REAL `build_forwarding_state`
/// and drive `build_live_forward_request_from_frame` for a flow that ingresses
/// the fixture's LAN interface and egresses `egress_ifindex`. Returns the built
/// state plus the zone ids the emitted filter-log record carries.
///
/// The state is NOT hand-built. Round 3 hand-populated a `ForwardingState` here
/// and in `poll_descriptor::filter`, which encoded a MAP LAYOUT rather than a
/// snapshot: both hand-built states inserted into `ifindex_to_zone_id` alone, so
/// they agreed with the resolver only by coincidence and went red on a builder
/// change that was correct. One fixture, driven through the real builder, in all
/// three test files that adjudicate these shapes.
///
/// FIXTURE SCAFFOLDING, do not read as the invariant: the `ForwardingResolution`
/// below carries `src_mac: Some(..)`, which the real
/// `session_glue::populate_egress_resolution` would leave `None` for a row-less
/// interface. It is the house style for every fixture in this file, the field is
/// not on the path under test, and what these tests assert is the logged
/// `egress_zone_id`.
fn live_forward_filter_log_zones_6722(egress_ifindex: i32) -> (ForwardingState, u16, u16) {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 20);
    let meta = UserspaceDpMeta {
        ingress_ifindex: LAN_IFINDEX_6722 as u32,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 64,
        dscp: 0,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 49152,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "egress-log".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "st0.0".into(),
            ifindex: egress_ifindex,
            filter_output_v4: "egress-log".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let mut forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
        &sibling_tunnel_units_snapshot_6722(),
    );
    // The output filter and the v4 TX selector are the only things this call
    // site needs beyond what the snapshot builder produces; the fixture carries
    // no `firewall` stanza of its own.
    forwarding.filter_state = filter_state;
    forwarding.tx_selection_enabled_v4 = true;
    assert!(
        !forwarding.egress.contains_key(&egress_ifindex),
        "precondition: the MAC-less egress interface must have NO egress row -- \
         without that hole the #6713 fallback never fires here"
    );
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex,
        tx_ifindex: egress_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let ingress = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: LAN_IFINDEX_6722,
    };
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let _req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        0,
        &ingress,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        None,
    )
    .expect("output filter log should not block forwarding");

    let filter_event = event_rx
        .try_recv()
        .expect("output filter-log event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(filter_event.kind, DataplaneEventKind::FilterLog);
    (
        forwarding,
        filter_event.ingress_zone_id,
        filter_event.egress_zone_id,
    )
}

/// #6713 binding for `forward_request.rs`'s OWN `egress_zone_id` call.
///
/// `build_live_forward_request` resolves the filter-log egress zone with a
/// SECOND, independent call to the shared resolver -- it does not go through
/// `filter_log_egress_zone_id`. Reverting just that line to the pre-#6713
/// `state.egress`-only read left the entire suite green, because the sibling
/// test above (`build_live_forward_request_emits_output_filter_log_event`) uses
/// a MAC-FUL egress interface where both reads agree.
///
/// Same topology as that test, with ONE difference: the egress interface is
/// MAC-less (an IPsec xfrmi on its OWN ifindex, `st0.1`), so `populate_egress`'s
/// `src_mac` gate leaves it with NO `state.egress` row and the zone can only
/// come from the fallback. The emitted event must still carry the tunnel's real
/// zone.
#[test]
fn build_live_forward_request_logs_a_macless_egress_zone_6713() {
    let (forwarding, ingress_zone_id, egress_zone_id) =
        live_forward_filter_log_zones_6722(ZONED_TUNNEL_IFINDEX_6722);

    assert_eq!(ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(
        egress_zone_id, TEST_SIBLING_VPN_ZONE_ID_6722,
        "the filter-log record for a flow egressing a MAC-less tunnel must carry \
         the tunnel's real zone, not the 0 'unknown' sentinel"
    );
    assert_eq!(
        forwarding
            .ifindex_unambiguous_zone_id
            .get(&ZONED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "the zone must have come from the unambiguous map -- `st0.1` is one row \
         on its own ifindex"
    );
}

/// #6722 at the live-forward log site. `forward_request.rs` calls the resolver
/// independently of `filter_log_egress_zone_id`, so the ambiguity gate has to be
/// proven at BOTH log sites: a log field naming `vpnb` for transit the firewall
/// denied under the default policy sends an operator hunting a `lan->vpnb` rule
/// that never ran.
#[test]
fn build_live_forward_request_logs_no_zone_for_an_ambiguous_ifindex_6722() {
    let (forwarding, ingress_zone_id, egress_zone_id) =
        live_forward_filter_log_zones_6722(SHARED_TUNNEL_IFINDEX_6722);

    assert_eq!(ingress_zone_id, TEST_LAN_ZONE_ID);
    // #7509 retarget of this cell's non-vacuity guard. It used to read "the map
    // this site must NOT read carries a nonzero zone for the shared ifindex",
    // which stopped holding once INGRESS refused the inherited zone too. The
    // guard it is replaced by is the one that still discriminates: an
    // UNCONTESTED ifindex in the SAME state resolves a real zone at this same
    // log site, so "logs 0" cannot pass on a state with no zones in it.
    assert_eq!(
        forwarding
            .ifindex_unambiguous_zone_id
            .get(&ZONED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        TEST_SIBLING_VPN_ZONE_ID_6722,
        "control: the sibling ifindex 43 IS unambiguous and resolves `vpnb` in \
         this same state -- otherwise 'logs 0' would be indistinguishable from an \
         empty state"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&SHARED_TUNNEL_IFINDEX_6722)
            .copied()
            .unwrap_or(0),
        0,
        "and after #7509 the INGRESS map refuses the shared ifindex as well, so \
         both halves agree that ifindex 42 names no zone"
    );
    assert_eq!(
        egress_zone_id, 0,
        "the logged to-zone must be the adjudicated 0, not the sibling unit's zone"
    );
}


#[test]
fn build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1025,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: 54688,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
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
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some(&flow),
        None,
        false,
        0,
    )
    .expect("request");
    assert_eq!(req.expected_ports, Some((54688, 5201)));
}


#[test]
fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
    let zone_redirect = resolve_zone_encoded_fabric_redirect_by_id(&forwarding, TEST_WAN_ZONE_ID)
        .expect("zone redirect");
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, 64).expect("slice").fill(0xaa);
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("fab0"),
        ifindex: 21,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 5201,
        flow_dst_port: 44278,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: fabric_redirect, nat: NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 44278,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };

    let req = build_live_forward_request(
        &area,
        &WorkerBindingLookup::default(),
        0,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        Some(TEST_WAN_ZONE_ID),
        true,
        0,
    )
    .expect("request");

    assert!(req.apply_nat_on_fabric);
    assert_eq!(
        req.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(req.decision.resolution.src_mac, zone_redirect.src_mac);
}


#[test]
fn build_live_forward_request_caches_target_binding_index() {
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, 64).expect("slice").fill(0xaa);
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 12345,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_if_queue.insert((11, 3), 5);
    lookup.first_by_if.insert(11, 4);

    let req = build_live_forward_request(
        &area,
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        0,
    )
    .expect("request");

    assert_eq!(req.target_ifindex, 11);
    assert_eq!(req.target_binding_index, Some(5));
}


#[test]
fn build_forwarded_frame_applies_nat_on_fabric_when_requested() {
    let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
    let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0xac, 0xf6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 5201,
        flow_dst_port: 44278,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: fabric_redirect, nat: NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };

    let no_nat = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &forwarding,
        false,
        Some((5201, 44278)),
    )
    .expect("frame without nat");
    assert_eq!(&no_nat[30..34], &[172, 16, 80, 8]);

    let nat = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &forwarding,
        true,
        Some((5201, 44278)),
    )
    .expect("frame with nat");
    assert_eq!(&nat[30..34], &[10, 0, 61, 102]);
    assert!(tcp_checksum_ok_ipv4(&nat[14..]));
}


#[test]
fn build_forwarded_frame_into_keeps_ipv6_ports_when_frame_and_metadata_disagree() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 0x0401u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 54688,
        flow_dst_port: real_dst_port,
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
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_forwarded_frame_into_prefers_expected_ipv6_ports_over_wrong_live_ports() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let real_src_port = 42566u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1042,
        flow_dst_port: real_dst_port,
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
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((1042, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (1042, real_dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_forwarded_frame_into_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 36394u16;
    let wrong_src_port = 1025u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
    ]);
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        flow_src_port: expected_src_port,
        flow_dst_port: dst_port,
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
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((expected_src_port, dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    assert_eq!(tcp_ports_ipv6(&out[18..]), (expected_src_port, dst_port));
    assert!(tcp_checksum_ok_ipv6(&out[18..]));
}


#[test]
fn build_forwarded_frame_into_ignores_wrong_ipv4_offsets() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let real_src_port = 47032u16;
    let real_dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x00, 0x00, 64, PROTO_TCP, 0, 0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&real_src_port.to_be_bytes());
    frame.extend_from_slice(&real_dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
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
        l3_offset: 54,
        l4_offset: 74,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1059,
        flow_dst_port: real_dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst_ip)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };
    let mut out = [0u8; 256];
    let frame_len = build_forwarded_frame_into(
        &mut out,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &ForwardingState::default(),
        Some((real_src_port, real_dst_port)),
    )
    .expect("build forwarded frame");
    let out = &out[..frame_len];
    let tcp = &out[18 + 20..];
    assert_eq!(
        (
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]])
        ),
        (real_src_port, real_dst_port)
    );
}

