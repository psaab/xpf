// TSO segmentation of forwarded TCP frames (SNAT/VLAN/GRE/TTL) and authoritative forward-port selection.
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
fn segment_forwarded_tcp_frames_splits_ipv6_snat_payload_by_mtu() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 54688u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x18, 0x00, 0x40, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
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
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
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

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    let mut expected_seq = 0x3196c832u32;
    let mut total_payload = 0usize;
    for (idx, seg) in segments.iter().enumerate() {
        assert!(seg.len() <= 18 + 1500);
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        let tcp = &seg[18 + 40..];
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = seg.len() - 18 - 40 - 20;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
        if idx + 1 != segments.len() {
            assert_eq!(tcp[13] & TCP_FLAG_PSH, 0);
        }
    }
    assert_eq!(total_payload, tcp_payload_len);
}


#[test]
fn segment_forwarded_tcp_frames_repairs_ipv6_tcp_ports_when_metadata_disagrees() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 38276u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
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
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
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
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}


#[test]
fn segment_forwarded_tcp_frames_prefers_expected_ipv6_ports_over_wrong_live_ports() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 42566u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
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
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
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
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((1042, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (1042, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}


#[test]
fn segment_forwarded_tcp_frames_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 36394u16;
    let wrong_src_port = 1025u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let plen = (20 + tcp_payload_len) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&wrong_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(8192).expect("mmap");
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
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
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
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((expected_src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    for seg in &segments {
        assert_eq!(tcp_ports_ipv6(&seg[18..]), (expected_src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&seg[18..]));
    }
}


#[test]
fn authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 55068u16;
    let wrong_src_port = 1041u16;
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
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            src_port: expected_src_port,
            dst_port,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };

    assert_eq!(
        authoritative_forward_ports(&frame, meta, Some(&flow)),
        Some((expected_src_port, dst_port))
    );
}


#[test]
fn authoritative_forward_ports_prefers_frame_tuple_over_metadata_when_flow_missing() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let frame_src_port = 1041u16;
    let meta_src_port = 55068u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&frame_src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut flow_src_addr = [0u8; 16];
    flow_src_addr[..4].copy_from_slice(&src_ip.octets());
    let mut flow_dst_addr = [0u8; 16];
    flow_dst_addr[..4].copy_from_slice(&dst_ip.octets());
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_addr,
        flow_dst_addr,
        flow_src_port: meta_src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };

    // Live frame ports preferred over metadata (flow > frame > meta)
    assert_eq!(
        authoritative_forward_ports(&frame, meta, None),
        Some((frame_src_port, dst_port))
    );
}


#[test]
fn authoritative_forward_ports_falls_back_to_live_frame_ports_when_metadata_missing() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 55068u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_UDP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x14, 0x00, 0x00]);
    frame.extend_from_slice(b"userspace-udp");
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_UDP).expect("udp sum");

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(
        authoritative_forward_ports(&frame, meta, None),
        Some((src_port, dst_port))
    );
}


#[test]
fn parse_session_flow_prefers_metadata_tuple_when_frame_ports_mismatch() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let expected_src_port = 55068u16;
    let wrong_src_port = 1041u16;
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
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.forward_key.src_port, expected_src_port);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}


#[test]
fn segment_forwarded_tcp_frames_keeps_ipv4_tcp_ports_after_vlan_snat() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 30_408usize;
    let tcp_header_len = 32usize;
    let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xd1,
        0x43,
        0x40,
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x80, 0x10, 0x00, 0x3f, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
        0x01, 0x01, 0x08, 0x0a, // TCP timestamp option
        0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(65_536).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1041,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect("segmented");
    assert!(segments.len() > 1);
    let mut total_payload = 0usize;
    let mut expected_seq = 0x5204c1a3u32;
    for seg in &segments {
        assert!(seg.len() <= 18 + 1500);
        let tcp = &seg[18 + 20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (src_port, dst_port)
        );
        assert!(tcp_checksum_ok_ipv4(&seg[18..]));
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = seg.len() - 18 - 20 - tcp_header_len;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
    }
    assert_eq!(total_payload, tcp_payload_len);
}


/// #5159 RED-on-revert: a valid IPv4 egress MTU BELOW the wrongly-applied 1280
/// IPv6-link-MTU floor must actually chunk a non-DF TCP datagram. Egress MTU
/// 900; a ~1100-byte L3 TCP datagram (in the (real_mtu, 1280] oversize band):
/// the builder MUST segment it into >=2 pieces each <= 900. Restoring the
/// builder's `.max(1280)` floor raises the MTU to 1280, so the 1100-byte
/// datagram is `<= mtu` and the builder returns None (no segmentation) — RED.
#[test]
fn segment_forwarded_tcp_frames_honors_sub_1280_ipv4_egress_mtu_5159() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let egress_mtu = 900usize;
    // 20 (IP) + 20 (TCP, no options) + 1060 payload = 1100-byte L3 datagram.
    let tcp_payload_len = 1060usize;
    let total_len = (20 + 20 + tcp_payload_len) as u16;
    assert!(
        (egress_mtu as u16) < total_len && total_len <= 1280,
        "datagram must sit in the (real_mtu, 1280] oversize band"
    );

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, // v4, ihl=5, dscp/ecn
        (total_len >> 8) as u8, total_len as u8, // total_len = 1100
        0xd1, 0x43, // identification
        0x00, 0x00, // flags/frag: NON-DF (0x0000), offset 0
        64, PROTO_TCP, 0x00, 0x00, // ttl, proto, checksum placeholder
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x50, 0x10, 0x00, 0x3f, // data offset (20, no opts) / flags / window
        0x00, 0x00, 0x00, 0x00, // checksum / urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(65_536).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: egress_mtu, // 900 — below the bogus 1280 floor, above the real IPv4 min (68)
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc { addr: 0, len: frame.len() as u32, options: 0 },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    )
    .expect(
        "a 1100-byte L3 datagram MUST segment at a 900-byte egress MTU; the \
         1280 floor is an IPv6-link-MTU value, not an IPv4 floor (#5159)",
    );
    assert!(
        segments.len() >= 2,
        "the datagram must split into >=2 segments, got {}",
        segments.len()
    );
    // Output frames are VLAN-tagged (tx_vlan_id=80): L2 is 18 bytes, so L3
    // starts at offset 18 and the IPv4 total_len is at seg[20..22].
    for seg in &segments {
        let ip_total_len = u16::from_be_bytes([seg[20], seg[21]]) as usize;
        assert!(
            ip_total_len <= egress_mtu,
            "each segment's IPv4 total_len must be <= the 900 egress MTU, got {ip_total_len}"
        );
        assert!(seg.len() <= 18 + egress_mtu);
    }
}


#[test]
fn segment_forwarded_tcp_frames_keeps_ipv4_snat_inside_native_gre() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 30_408usize;
    let tcp_header_len = 32usize;
    let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xd1,
        0x43,
        0x40,
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, 0x73, 0x7f, 0x63, 0x1c, 0x80, 0x10, 0x00, 0x3f, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x08, 0x0a, 0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(65_536).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 1041,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true, None),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            ..NatDecision::default()
        },
    };

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &state,
        Some((src_port, dst_port)),
    )
    .expect("segmented native gre");
    assert!(segments.len() > 1);
    let outer_eth_len = 18usize;
    let outer_ip_len = 40usize;
    let gre_len = 4usize;
    let transport_mtu = 1500usize;
    let inner_start = outer_eth_len + outer_ip_len + gre_len;
    let mut total_payload = 0usize;
    let mut expected_seq = 0x5204c1a3u32;
    for seg in &segments {
        assert!(seg.len() >= outer_eth_len);
        assert!(
            seg.len() - outer_eth_len <= transport_mtu,
            "native GRE segment exceeds transport MTU: {}",
            seg.len() - outer_eth_len
        );
        assert_eq!(&seg[16..18], &[0x86, 0xdd]);
        assert_eq!(seg[24], PROTO_GRE);
        let inner = &seg[inner_start..];
        assert_eq!(&inner[12..16], &snat_ip.octets());
        assert_eq!(&inner[16..20], &dst_ip.octets());
        assert!(tcp_checksum_ok_ipv4(inner));
        let tcp = &inner[20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (src_port, dst_port)
        );
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        assert_eq!(seq, expected_seq);
        let seg_payload = inner.len() - 20 - tcp_header_len;
        total_payload += seg_payload;
        expected_seq = expected_seq.wrapping_add(seg_payload as u32);
    }
    assert_eq!(total_payload, tcp_payload_len);
}

// #5148: the segmentation builder must REFUSE any IP fragment — first or
// non-first. A first IPv4 fragment (MF=1, offset 0) carries a real TCP header,
// so before #5148 it flowed through the builder, which cloned the
// fragment-bearing IP header (Identification / MF / offset) into every output
// while rewriting seq/checksum — emitting overlapping offset-0 pseudo-fragments
// that break reassembly at the receiver. The builder now carries its own
// `is_any_fragment` guard (defense in depth behind the admission gate) and
// returns None so the caller forwards the original frame unchanged. RED-on-
// revert: remove the builder guard and this oversized-but-fragmented frame
// segments (returns Some), tripping the assertion.
#[test]
fn segment_forwarded_tcp_frames_refuses_first_ipv4_fragment() {
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let tcp_header_len = 20usize;
    let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xd1,
        0x43,
        0x20, // flags: MF=1 (first fragment), fragment offset 0
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x50, 0x10, 0x00, 0x3f, // data offset (5)/ACK/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

    let mut area = MmapArea::new(16_384).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    );
    assert!(
        segments.is_none(),
        "a first IPv4 fragment (MF=1) carrying a TCP header must NOT be \
         segmented into overlapping offset-0 pseudo-fragments"
    );
}

// #5148 IPv6 sibling: an IPv6 packet carrying a Fragment extension header
// (next-header 44) — even the FIRST fragment (offset 0, M=1) — must never be
// TCP-segmented. Same overlapping-pseudo-fragment defect, IPv6 flavor. The
// builder's `is_any_fragment` guard returns None. RED-on-revert: remove the
// guard and this oversized fragmented frame segments (returns Some).
#[test]
fn segment_forwarded_tcp_frames_refuses_ipv6_fragment_header() {
    let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
    let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
    let src_port = 54688u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 4096usize;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    // payload_len = fragment header (8) + TCP header (20) + data.
    let plen = (8 + 20 + tcp_payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        44, // next-header: Fragment extension header
        64, // hop limit
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // Fragment extension header (8 bytes): next-header TCP, offset 0, M=1.
    frame.extend_from_slice(&[
        PROTO_TCP, 0x00, // next-header, reserved
        0x00, 0x01, // fragment offset 0, res, M=1
        0x00, 0x00, 0x00, 0x2a, // identification
    ]);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x31, 0x96, 0xc8, 0x32, // seq
        0x08, 0xf0, 0x5a, 0xc6, // ack
        0x50, 0x10, 0x00, 0x40, // data offset (5)/ACK/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    // L4 checksum is over the TCP header + data; the fragment ext header sits
    // between the base header and TCP, so the rel-L4 offset is 40 + 8 = 48.
    recompute_l4_checksum_ipv6(&mut frame[14..], 48, PROTO_TCP).expect("tcp sum");

    let mut area = MmapArea::new(16_384).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 62, // 14 + 40 base + 8 fragment header
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
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

    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((src_port, dst_port)),
    );
    assert!(
        segments.is_none(),
        "an IPv6 packet carrying a Fragment header must NOT be TCP-segmented"
    );
}

// --- #2077: TCP-segmentation TTL/hop-limit gate v4/v6 symmetry ---
//
// The TTL==1 drop in the segmentation builders must be gated on
// NOT-fabric-ingress, matching every other forwarding path
// (build/ipv4.rs, build/ipv6.rs, frame/mod.rs, rewrite/ipv4.rs,
// rewrite/ipv6.rs). A fabric-ingress segment (FABRIC_INGRESS_FLAG =
// 0x80 in meta_flags) was already decremented by the peer chassis at
// its real ingress; the fabric crossing is an internal cross-chassis
// redirect, not an IP hop, so neither the decrement NOR the drop
// applies. Before the fix the IPv4 builder dropped UNCONDITIONALLY on
// TTL <= 1 while IPv6 was correctly gated — a fabric-ingress oversized
// IPv4 TCP segment with TTL==1 was wrongly dropped.



// ---------------------------------------------------------------------------
// #5191 A1-b2-F6: per-segment header fidelity.
//
// Both segmentation builders clone the ORIGINAL IPv4 + TCP headers verbatim
// into every output. Before #5191 only seq and PSH were repaired, so the
// IPv4 Identification, the TCP CWR bit, and the URG bit + urgent pointer were
// replicated onto every segment. The admission gate rejects only SYN / FIN /
// RST, so an ACK carrying CWR or URG reaches this builder.
//
// The fixtures below build ONE over-MTU IPv4 ACK and vary exactly the field
// under test; each test names the one-line revert in
// `finalize_tcp_segment_headers` that turns it RED.
// ---------------------------------------------------------------------------

const SEG5191_SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SEG5191_DST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const SEG5191_SPORT: u16 = 47308;
const SEG5191_DPORT: u16 = 5201;
const SEG5191_SEQ: u32 = 0x5204_c1a3;
const SEG5191_ID: u16 = 0xd143;
const SEG5191_MTU: usize = 200;
const SEG5191_PAYLOAD: usize = 500;
/// mtu - ip(20) - tcp(20); the builder's `segment_payload_max`.
const SEG5191_CHUNK: usize = SEG5191_MTU - 40;

/// One over-MTU IPv4 TCP datagram. `frag_off` is the raw flags/fragment word
/// (0x0000 = DF clear, 0x4000 = DF set), `tcp_flags` the control-bits octet,
/// `urg_ptr` the urgent pointer.
fn seg5191_frame(frag_off: u16, tcp_flags: u8, urg_ptr: u16) -> Vec<u8> {
    let total_len = (20 + 20 + SEG5191_PAYLOAD) as u16;
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        (SEG5191_ID >> 8) as u8,
        SEG5191_ID as u8,
        (frag_off >> 8) as u8,
        frag_off as u8,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&SEG5191_SRC.octets());
    frame.extend_from_slice(&SEG5191_DST.octets());
    frame.extend_from_slice(&SEG5191_SPORT.to_be_bytes());
    frame.extend_from_slice(&SEG5191_DPORT.to_be_bytes());
    frame.extend_from_slice(&SEG5191_SEQ.to_be_bytes());
    frame.extend_from_slice(&[0x73, 0x7f, 0x63, 0x1c]); // ack
    frame.extend_from_slice(&[0x50, tcp_flags, 0x00, 0x3f]); // data offset / flags / window
    frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    frame.extend_from_slice(&urg_ptr.to_be_bytes());
    frame.extend((0..SEG5191_PAYLOAD).map(|i| (i & 0xff) as u8));
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    frame
}

/// Segment `frame` at a `SEG5191_MTU` egress. Output frames are untagged, so
/// L3 starts at 14 and the TCP header at 34.
fn seg5191_segments(frame: &[u8]) -> Vec<Vec<u8>> {
    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: SEG5191_SPORT,
        flow_dst_port: SEG5191_DPORT,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(SEG5191_DST)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: SEG5191_MTU,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    let segments = segment_forwarded_tcp_frames(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        &forwarding,
        Some((SEG5191_SPORT, SEG5191_DPORT)),
    )
    .expect("over-MTU IPv4 ACK must segment");
    assert!(
        segments.len() >= 3,
        "fixture must produce >=3 segments so index 0/1/2+ are distinguishable, got {}",
        segments.len()
    );
    segments
}


// #5191 FAIL-ON-REVERT (RFC 3168 §6.1.2): CWR is a one-shot "I already reduced
// cwnd" signal. The receiver stops echoing ECE on the first CWR it sees, so a
// CWR cloned onto later segments retracts an ECE the receiver may have
// re-raised for a NEW congestion event in the same burst — the sender never
// reduces cwnd for it. Keep CWR on segment 0 only, as a TSO NIC and Linux's
// `tcp_gso_segment` do. Reverting the `*tcp.get_mut(13)? &= !TCP_FLAG_CWR;`
// line in `finalize_tcp_segment_headers` turns the per-segment assertion RED.
//
// The TCP-checksum assertion is also an ORDERING guard: the flags octet is
// covered by the checksum, so it fails if the header fixups are ever moved
// after the per-segment `recompute_l4_checksum_ipv4`.
#[test]
fn segments_keep_cwr_on_the_first_segment_only_5191() {
    const ACK: u8 = 0x10;
    const CWR: u8 = 0x80;
    let segments = seg5191_segments(&seg5191_frame(0x0000, ACK | CWR, 0));

    for (idx, seg) in segments.iter().enumerate() {
        let flags = seg[34 + 13];
        assert_eq!(flags & ACK, ACK, "segment {idx} must keep ACK");
        if idx == 0 {
            assert_eq!(
                flags & CWR,
                CWR,
                "segment 0 carries the original CWR signal",
            );
        } else {
            assert_eq!(
                flags & CWR,
                0,
                "segment {idx} must NOT replicate CWR (flags {flags:#04x})",
            );
        }
        assert_eq!(
            checksum16_ipv4(SEG5191_SRC, SEG5191_DST, PROTO_TCP, &seg[34..]),
            0,
            "segment {idx} TCP checksum must cover the emitted flags octet",
        );
    }
}


// #5191 FAIL-ON-REVERT (RFC 6864 §4.1): a NON-atomic IPv4 datagram (DF clear)
// must carry a unique Identification per source/destination/protocol for as
// long as it could be fragmented downstream. Cloning one ID across N segments
// lets a fragmenting router downstream emit fragments of DIFFERENT segments
// that share the reassembly key, so the receiver splices a corrupt datagram.
// Reverting the `id.wrapping_add(segment_index)` write in
// `finalize_tcp_segment_headers` leaves every segment at the original ID and
// turns the distinctness assertion RED.
#[test]
fn segments_get_distinct_ipv4_ids_when_df_is_clear_5191() {
    let segments = seg5191_segments(&seg5191_frame(0x0000, 0x10, 0));

    let ids: Vec<u16> = segments
        .iter()
        .map(|seg| u16::from_be_bytes([seg[14 + 4], seg[14 + 5]]))
        .collect();
    for (idx, id) in ids.iter().enumerate() {
        assert_eq!(
            *id,
            SEG5191_ID.wrapping_add(idx as u16),
            "segment {idx} must carry a distinct IPv4 Identification; got {ids:?}",
        );
    }
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        ids.len(),
        "every segment's IPv4 Identification must be distinct; got {ids:?}",
    );
    // Positive control: the DF bit really was clear on the wire, so this
    // fixture exercises the non-atomic arm rather than passing vacuously.
    for (idx, seg) in segments.iter().enumerate() {
        assert_eq!(
            seg[14 + 6] & 0x40,
            0,
            "control: segment {idx} must be non-atomic (DF clear)",
        );
    }
}


// #5191 FAIL-ON-REVERT (RFC 6864 §4.1, the other direction): an ATOMIC datagram
// (DF set — the normal PMTUD case) has an IGNORED Identification field, so the
// segmenter must not churn it. Reverting the `(*packet.get(6)? & 0x40) == 0`
// guard to an unconditional rewrite turns this RED.
#[test]
fn segments_keep_the_ipv4_id_when_df_is_set_5191() {
    let segments = seg5191_segments(&seg5191_frame(0x4000, 0x10, 0));

    for (idx, seg) in segments.iter().enumerate() {
        assert_eq!(
            seg[14 + 6] & 0x40,
            0x40,
            "control: segment {idx} must stay atomic (DF set)",
        );
        assert_eq!(
            u16::from_be_bytes([seg[14 + 4], seg[14 + 5]]),
            SEG5191_ID,
            "an atomic datagram's Identification is ignored — leave it alone",
        );
    }
}


// #5191 FAIL-ON-REVERT (RFC 9293 §3.1): the urgent pointer is relative to the
// segment's OWN sequence number. Cloning it advances the urgent point by one
// chunk per segment and invents urgent data the sender never marked; a
// receiver with SO_OOBINLINE off then pulls a byte OUT of the data stream at
// the wrong offset, corrupting the application byte stream. The ABSOLUTE
// urgent point must be preserved instead, and a segment that starts past it
// must have URG cleared. Reverting the urgent-pointer arm in
// `finalize_tcp_segment_headers` turns the absolute-point assertion RED.
#[test]
fn segments_rebase_the_urgent_pointer_5191() {
    const ACK: u8 = 0x10;
    const URG: u8 = 0x20;
    // Deliberately inside the SECOND chunk so the fixture samples BOTH arms:
    // segments 0-1 keep URG with a rebased pointer, segment 2+ clear it.
    let urg_ptr: u16 = (SEG5191_CHUNK + 40) as u16;
    assert!(
        (urg_ptr as usize) > SEG5191_CHUNK && (urg_ptr as usize) < 2 * SEG5191_CHUNK,
        "fixture must place the urgent point inside segment 1",
    );
    let segments = seg5191_segments(&seg5191_frame(0x0000, ACK | URG, urg_ptr));

    let absolute = SEG5191_SEQ.wrapping_add(u32::from(urg_ptr));
    let mut kept = 0usize;
    let mut cleared = 0usize;
    for (idx, seg) in segments.iter().enumerate() {
        let flags = seg[34 + 13];
        let seq = u32::from_be_bytes([seg[34 + 4], seg[34 + 5], seg[34 + 6], seg[34 + 7]]);
        let ptr = u16::from_be_bytes([seg[34 + 18], seg[34 + 19]]);
        if (flags & URG) != 0 {
            kept += 1;
            assert_eq!(
                seq.wrapping_add(u32::from(ptr)),
                absolute,
                "segment {idx} must point at the SAME absolute urgent octet",
            );
        } else {
            cleared += 1;
            assert!(
                seq > absolute || seq.wrapping_sub(absolute) < u32::MAX / 2,
                "segment {idx} may only drop URG once it starts past the urgent point",
            );
            assert_eq!(ptr, 0, "segment {idx} cleared URG, so the pointer is 0");
        }
    }
    // Both arms must actually have been sampled — a fixture that only ever
    // reaches one of them would pass while the other is broken.
    assert_eq!(kept, 2, "segments 0 and 1 keep URG (got {kept})");
    assert!(cleared >= 1, "at least one later segment clears URG");
}
