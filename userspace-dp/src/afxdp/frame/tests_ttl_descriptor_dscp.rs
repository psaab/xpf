// fabric-ingress TTL gating, descriptor-driven apply paths, and DSCP/L4-checksum rewrites.
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

/// Fabric-ingress (meta_flags = FABRIC_INGRESS_FLAG = 0x80) oversized
/// TCP segment with TTL/hop-limit == 1 must NOT be dropped, for BOTH
/// address families. Non-tautological: pre-fix the IPv4 arm returns
/// None (unconditional `packet[8] <= 1` drop) and this test fails for
/// the v4 case.
#[test]
fn segment_forwarded_tcp_frames_keeps_fabric_ingress_low_ttl_both_families() {
    for (label, af, ttl_off) in [
        ("v4", libc::AF_INET, 8usize),
        ("v6", libc::AF_INET6, 7usize),
    ] {
        let (frame, mut meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 1);
        meta.meta_flags = 0x80; // FABRIC_INGRESS_FLAG — peer already decremented

        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false, // apply_nat_on_fabric
            Some((meta.flow_src_port, meta.flow_dst_port)),
        )
        .unwrap_or_else(|| {
            panic!(
                "[{}] fabric-ingress oversized segment with TTL/hop-limit==1 \
                 must segment, not drop (the peer already decremented)",
                label
            )
        });
        assert!(
            segments.len() > 1,
            "[{}] expected multiple segments for oversized payload",
            label
        );
        // The TTL/hop-limit must be preserved (NOT decremented) on the
        // fabric-ingress path. IP header starts at the L2 offset; the
        // built frames have no VLAN tag so eth_len == 14.
        for seg in &segments {
            let post = seg[14 + ttl_off];
            assert_eq!(
                post, 1,
                "[{}] fabric-ingress must preserve TTL/hop-limit (got {})",
                label, post
            );
        }
    }
}


/// Non-fabric (meta_flags == 0) oversized TCP segment with TTL/hop-
/// limit == 1 must STILL be dropped, for BOTH address families. Guards
/// against an over-broad fix that would also drop the legitimate
/// TTL-expiry behaviour on the normal forwarding path.
#[test]
fn segment_forwarded_tcp_frames_drops_non_fabric_low_ttl_both_families() {
    for (label, af) in [("v4", libc::AF_INET), ("v6", libc::AF_INET6)] {
        let (frame, meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 1);
        // meta_flags defaults to 0 (NOT fabric-ingress).
        assert_eq!(
            meta.meta_flags & 0x80,
            0,
            "[{}] expected non-fabric meta",
            label
        );

        let result = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((meta.flow_src_port, meta.flow_dst_port)),
        );
        assert!(
            result.is_none(),
            "[{}] non-fabric oversized segment with TTL/hop-limit==1 must be \
             dropped (TTL expiry)",
            label
        );
    }
}


/// Sanity twin: a non-fabric oversized segment with a healthy TTL (64)
/// segments normally AND decrements the TTL/hop-limit by one on every
/// segment — confirming the gate only blocks the expiry case and the
/// normal decrement path is intact for BOTH families.
#[test]
fn segment_forwarded_tcp_frames_decrements_non_fabric_healthy_ttl_both_families() {
    for (label, af, ttl_off) in [
        ("v4", libc::AF_INET, 8usize),
        ("v6", libc::AF_INET6, 7usize),
    ] {
        let (frame, meta, decision, forwarding) = build_oversized_tcp_frame_for_ttl_gate(af, 64);

        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((meta.flow_src_port, meta.flow_dst_port)),
        )
        .unwrap_or_else(|| panic!("[{}] healthy-TTL oversized segment must segment", label));
        assert!(segments.len() > 1, "[{}] expected multiple segments", label);
        for seg in &segments {
            let post = seg[14 + ttl_off];
            assert_eq!(
                post, 63,
                "[{}] non-fabric forwarding must decrement TTL/hop-limit 64->63 \
                 (got {})",
                label, post
            );
        }
    }
}


#[test]
fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_snat() {
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
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

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
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
                ..NatDecision::default()
            },
        },
        false,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    assert_eq!(&out[30..34], &[172, 16, 80, 8]);
    assert_eq!(out[26], 63);
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}


#[test]
fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_dnat() {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
        80,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
        b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[18..]));

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
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
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        },
        false,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(&out[30..34], &[10, 0, 61, 102]);
    assert_eq!(out[22], 63);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn rewrite_forwarded_frame_in_place_applies_nat_for_fabric_redirect_when_enabled() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

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
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        true,
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[172, 16, 80, 8]);
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


/// Sentinel for #963 round-1 #2: inverse of the
/// `_when_enabled` test above. Set
/// `disposition = FabricRedirect`, `apply_nat_on_fabric = false`,
/// SNAT rewrite_src to 198.51.100.99. After the rewrite, assert
/// the source IP in the frame is the ORIGINAL — confirms the
/// `apply_nat` gate at the dispatch correctly suppresses NAT
/// when fabric NAT is disabled.
#[test]
fn rewrite_forwarded_frame_in_place_skips_nat_for_fabric_redirect_when_disabled() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
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
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))),
                ..NatDecision::default()
            },
        },
        false, // apply_nat_on_fabric = false
        None,
    )
    .expect("rewrite in place");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    // Source IP MUST be the original 10.0.61.102, not the SNAT'd
    // 198.51.100.99. This validates that apply_nat=false is
    // correctly threaded through the dispatch into rewrite_apply_v4.
    assert_eq!(
        &out[26..30],
        &[10, 0, 61, 102],
        "apply_nat_on_fabric=false must suppress SNAT"
    );
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63); // TTL still decremented (skip_ttl=false)
}


/// Sentinel for #963 round-1 #2 (extended in round-2): table-
/// driven over IPv4 TTL (offset 8 from IP start) and IPv6
/// hop-limit (offset 7 from IP start). For each address family,
/// set `meta.meta_flags = 0x80 (FABRIC_INGRESS_FLAG)` so the
/// sending peer is treated as having already decremented TTL.
/// Capture the relevant byte before and after; assert pre == post
/// (no decrement). Validates the skip_ttl gate in BOTH
/// rewrite_apply_v4 and rewrite_apply_v6.
#[test]
fn rewrite_forwarded_frame_in_place_skips_ttl_when_fabric_ingress_flag_set() {
    // Table-driven: (addr_family, ether_type, ip_header,
    //                 ttl_rel_offset_from_ip_start)
    // ttl_rel_offset is HEADER-relative (not Ethernet-relative)
    // to avoid confusion (Codex round-3 non-blocking note).
    // IP total_len = 0x002c (44 bytes = 20 IP + 24 TCP/data) so
    // the IP header total_len matches the actual constructed
    // frame (Codex impl review round-1 caught a 0x0030 mismatch).
    let v4_header: Vec<u8> = vec![
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200,
    ];
    let v4_payload: Vec<u8> = vec![
        0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't',
    ];
    let v6_header: Vec<u8> = vec![
        0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_TCP, 64, // src 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        // dst 2001:db8::200
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
    ];
    let v6_payload: Vec<u8> = vec![
        0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for (label, addr_family, ether_type, ip_header, ip_payload, ttl_rel_offset, src_ip) in [
        (
            "v4",
            libc::AF_INET as u8,
            0x0800u16,
            v4_header,
            v4_payload,
            8usize,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        ),
        (
            "v6",
            libc::AF_INET6 as u8,
            0x86ddu16,
            v6_header,
            v6_payload,
            7usize,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
        ),
    ] {
        let mut frame = Vec::new();
        write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, ether_type);
        frame.extend_from_slice(&ip_header);
        frame.extend_from_slice(&ip_payload);
        if addr_family == libc::AF_INET as u8 {
            let ip_sum = checksum16(&frame[14..14 + ip_header.len()]);
            frame[24] = (ip_sum >> 8) as u8;
            frame[25] = ip_sum as u8;
            recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("v4 tcp sum");
        } else {
            recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("v6 tcp sum");
        }
        let pre_ttl = frame[14 + ttl_rel_offset];

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family,
            protocol: PROTO_TCP,
            meta_flags: 0x80, // FABRIC_INGRESS_FLAG — peer already decremented TTL
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
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(src_ip),
                    neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision::default(),
            },
            false,
            None,
        )
        .unwrap_or_else(|| panic!("[{}] rewrite_in_place returned None", label));

        let out = area
            .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
            .expect("rewritten frame");
        let post_ttl = out[14 + ttl_rel_offset];
        assert_eq!(
            pre_ttl, post_ttl,
            "[{}] FABRIC_INGRESS_FLAG must suppress TTL/hop-limit decrement \
             (pre={} post={})",
            label, pre_ttl, post_ttl
        );
    }
}

// --- apply_rewrite_descriptor tests ---


#[test]
fn apply_descriptor_ipv4_no_nat_ttl_and_checksum() {
    // IPv4 TCP, no NAT, just TTL decrement + ethernet rewrite.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, // IPv4, IHL=5, total_len=40
        0x00, 0x01, 0x00, 0x00, // ID, flags/frag
        64, PROTO_TCP, 0x00, 0x00, // TTL=64, proto=TCP, checksum placeholder
        10, 0, 1, 102, // src = 10.0.1.102
        172, 16, 80, 200, // dst = 172.16.80.200
        // TCP header (20 bytes)
        0x9c, 0x40, 0x01, 0xbb, // src_port=40000 dst_port=443
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x10, 0x20, 0x00, // data_off=5 flags=ACK win=8192
        0x00, 0x00, 0x00, 0x00, // checksum+urgent
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

    let rx_addr = 256u64;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr as usize, frame.len())
        .unwrap()
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
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: rx_addr,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // Ethernet header
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    // TTL decremented
    assert_eq!(out[22], 63);
    // IP checksum valid
    assert_eq!(checksum16(&out[14..34]), 0);
    // TCP checksum valid
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn apply_descriptor_ipv4_snat_with_vlan() {
    // IPv4 TCP with SNAT 10.0.61.102 -> 172.16.80.8, adding VLAN 80.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, // IPv4, total_len=48
        0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
        102, // src = 10.0.61.102
        172, 16, 80, 200, // dst = 172.16.80.200
        0x9c, 0x40, 0x14, 0x51, // src_port=40000 dst_port=5201
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let rd = test_descriptor(&flow, &decision, 80, 0x0800);

    let rx_addr = 256u64;
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(rx_addr as usize, frame.len())
        .unwrap()
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
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: rx_addr,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor snat rewrite");

    assert_eq!(rewrite_result.offset, rx_addr - 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPushDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // VLAN tag added
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
    // SNAT applied
    assert_eq!(&out[30..34], &[172, 16, 80, 8]); // new src IP
    assert_eq!(&out[34..38], &[172, 16, 80, 200]); // dst unchanged
    // TTL
    assert_eq!(out[26], 63);
    // IP checksum valid
    assert_eq!(checksum16(&out[18..38]), 0);
    // TCP checksum valid
    assert!(tcp_checksum_ok_ipv4(&out[18..]));
}


#[test]
fn apply_descriptor_fabric_redirect_skips_nat_when_flag_is_false() {
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't',
        b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    assert!(tcp_checksum_ok_ipv4(&frame[14..]));

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            egress_ifindex: 21,
            tx_ifindex: 21,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let mut rd = test_descriptor(&flow, &decision, 0, 0x0800);
    rd.apply_nat_on_fabric = false;

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
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor fabric rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[10, 0, 61, 102]);
    assert_eq!(&out[30..34], &[172, 16, 80, 200]);
    assert_eq!(out[22], 63);
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn apply_descriptor_ipv4_dnat_removes_vlan() {
    // IPv4 TCP with DNAT 172.16.80.8 -> 10.0.61.102, ingress VLAN 80 -> no VLAN.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 80, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
        200, // src
        172, 16, 80, 8, // dst (pre-DNAT)
        0x14, 0x51, 0x9c, 0x40, // src_port=5201 dst_port=40000
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[18..38]);
    frame[28] = (ip_sum >> 8) as u8;
    frame[29] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 40000,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 5,
            tx_ifindex: 5,
            neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 18,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor dnat rewrite");

    assert_eq!(rewrite_result.offset, 4);
    assert_eq!(
        rewrite_result.l2_rewrite,
        InPlaceL2Rewrite::VlanPopDescriptor
    );
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    // No VLAN
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    // DNAT applied
    assert_eq!(&out[30..34], &[10, 0, 61, 102]); // new dst IP
    // TTL
    assert_eq!(out[22], 63);
    // Checksums valid
    assert_eq!(checksum16(&out[14..34]), 0);
    assert!(tcp_checksum_ok_ipv4(&out[14..]));
}


#[test]
fn apply_descriptor_ipv6_no_nat_hop_limit() {
    // IPv6 TCP, no NAT, hop limit decrement only.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x86dd);
    let src = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xbf01, 0, 0, 0, 0x102);
    let dst = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0x80, 0, 0, 0, 0x200);
    frame.push(0x60);
    frame.push(0x00);
    frame.push(0x00);
    frame.push(0x00); // version+flow
    frame.extend_from_slice(&20u16.to_be_bytes()); // payload_len = 20 (TCP header only)
    frame.push(PROTO_TCP); // next header
    frame.push(64); // hop limit = 64
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    // TCP header (20 bytes)
    frame.extend_from_slice(&40000u16.to_be_bytes()); // src port
    frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
    frame.extend_from_slice(&1u32.to_be_bytes()); // seq
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0x00]); // data_off=5, ACK, win=8192
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum + urgent
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("tcp6 sum");

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src),
            dst_ip: IpAddr::V6(dst),
            src_port: 40000,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x86dd);

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .unwrap()
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54, // 14 + 40
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        None,
    )
    .expect("descriptor ipv6 rewrite");

    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("out");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
    // Hop limit decremented
    assert_eq!(out[21], 63);
    // TCP checksum still valid (no NAT changes to pseudo-header)
    let tcp_csum_ok = {
        let packet = &out[14..];
        let rel_l4 = 40usize;
        let csum_off = rel_l4 + 16;
        let stored = u16::from_be_bytes([packet[csum_off], packet[csum_off + 1]]);
        stored != 0 // basic sanity — full validation via recompute
    };
    assert!(tcp_csum_ok);
}


#[test]
fn apply_descriptor_returns_none_on_port_mismatch() {
    // If frame ports don't match expected_ports, descriptor path falls back to None.
    let mut frame = Vec::new();
    write_eth_header(&mut frame, [0xaa; 6], [0xbb; 6], 0, 0x0800);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 1, 102,
        172, 16, 80, 200, 0x9c, 0x40, 0x01, 0xbb, // src=40000 dst=443
        0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let flow = SessionFlow {
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            egress_ifindex: 12,
            tx_ifindex: 11,
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
            local_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
        },
        nat: NatDecision::default(),
    };
    let rd = test_descriptor(&flow, &decision, 0, 0x0800);

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
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    // Expected ports don't match frame (99/99 vs 40000/443).
    let result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &rd,
        Some((99, 99)),
    );
    assert!(result.is_none(), "should return None on port mismatch");
}


#[test]
fn apply_descriptor_nat64_falls_back() {
    let rd = RewriteDescriptor {
        dst_mac: [0; 6],
        src_mac: [0; 6],
        fabric_redirect: false,
        tx_vlan_id: 0,
        ether_type: 0x0800,
        rewrite_src_ip: None,
        rewrite_dst_ip: None,
        rewrite_src_port: None,
        rewrite_dst_port: None,
        ip_csum_delta: 0,
        l4_csum_delta: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        target_binding_index: None,
        input_filter_log: None,
        input_filter_counters: crate::filter::CachedFilterCounters::default(),
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: true,
        nptv6: false,
        apply_nat_on_fabric: false,
    };
    let area = MmapArea::new(4096).expect("mmap");
    let meta = UserspaceDpMeta::default();
    let result = apply_rewrite_descriptor(
        &area,
        XdpDesc {
            addr: 0,
            len: 64,
            options: 0,
        },
        meta,
        &rd,
        None,
    );
    assert!(result.is_none(), "NAT64 should fall back to generic");
}


#[test]
fn apply_dscp_rewrite_to_ipv4_frame_updates_tos_and_checksum() {
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut frame = build_icmp_echo_frame_v4(src, dst, 64);
    let l3 = frame_l3_offset(&frame).expect("l3");
    let old_tos = frame[l3 + 1];
    let old_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);

    apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

    assert_eq!(frame[l3 + 1] >> 2, 46);
    assert_eq!(frame[l3 + 1] & 0x03, old_tos & 0x03);
    let new_checksum = u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]);
    assert_ne!(new_checksum, old_checksum);
    assert_eq!(checksum16(&frame[l3..l3 + 20]), 0);
}


#[test]
fn apply_dscp_rewrite_to_ipv6_frame_updates_traffic_class() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd]);
    frame.extend_from_slice(&[
        0x60, 0x0b, 0x12, 0x34, // version + traffic class + flow label
        0x00, 0x08, // payload len
        58, 64, // next header + hop limit
    ]);
    frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    frame.extend_from_slice(&Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200).octets());
    frame.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);

    let l3 = frame_l3_offset(&frame).expect("l3");
    let old_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);

    apply_dscp_rewrite_to_frame(&mut frame, 46).expect("rewrite");

    let new_tc = ((frame[l3] & 0x0f) << 4) | (frame[l3 + 1] >> 4);
    assert_eq!(new_tc >> 2, 46);
    assert_eq!(new_tc & 0x03, old_tc & 0x03);
}


/// #1840: adjust_l4_checksum_port family pair — the RFC 768 stored-0
/// skip fires for IPv4 UDP only; the same stored-0 v6 UDP input gets
/// adjusted. Deterministic example (miri-COVERABLE twin of the
/// prop_tests pins -- coverable, not covered: `afxdp::frame::` is not in
/// userspace-dp/MIRI.registry, see #9499).
#[test]
fn adjust_l4_checksum_port_v4_skip_v6_no_skip() {
    // 8-byte UDP header at offset 0; checksum bytes at 6..8 = 0.
    let base = [0x12u8, 0x34, 0x56, 0x78, 0x00, 0x08, 0x00, 0x00];

    // v4: stored 0 => skip (bytes unchanged).
    let mut p = base;
    assert_eq!(
        adjust_l4_checksum_port(&mut p, 0, PROTO_UDP, ChecksumFamily::V4, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(p, base, "v4 UDP stored-0 must keep the RFC 768 skip");

    // v6: stored 0 => adjusted like any other value.
    let mut p = base;
    assert_eq!(
        adjust_l4_checksum_port(&mut p, 0, PROTO_UDP, ChecksumFamily::V6, 0x1234, 0x4321),
        Some(())
    );
    let updated = u16::from_be_bytes([p[6], p[7]]);
    assert_eq!(
        updated,
        checksum16_adjust(0, &[0x1234], &[0x4321]),
        "v6 UDP stored-0 must be incrementally adjusted (#1840)"
    );
    assert_ne!(updated, 0, "adjusted value is non-zero for this delta");

    // Non-zero stored checksum adjusts identically on both families.
    let mut p4 = base;
    p4[6..8].copy_from_slice(&0xBEEFu16.to_be_bytes());
    let mut p6 = p4;
    assert_eq!(
        adjust_l4_checksum_port(&mut p4, 0, PROTO_UDP, ChecksumFamily::V4, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(
        adjust_l4_checksum_port(&mut p6, 0, PROTO_UDP, ChecksumFamily::V6, 0x1234, 0x4321),
        Some(())
    );
    assert_eq!(
        p4, p6,
        "non-zero stored checksum: families behave identically"
    );
}

// ---------------------------------------------------------------------------
// #1852 — non-first-fragment NAT rewrite gating + MSS-clamp ext-aware fix.
// ---------------------------------------------------------------------------

