// Tests for nat64.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep nat64.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "nat64_tests.rs"]` from nat64.rs.

use super::*;

fn well_known_prefix() -> NAT64RuleSnapshot {
    NAT64RuleSnapshot {
        name: "nat64-wkp".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()],
        no_v6_frag_header: false,
    }
}

#[test]
fn parse_well_known_prefix() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    assert!(state.is_active());
    assert_eq!(state.prefixes.len(), 1);
    assert_eq!(
        state.prefixes[0].prefix_bytes,
        [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
}

#[test]
fn match_ipv6_dest_extracts_v4() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    // 64:ff9b::198.51.100.50 = 64:ff9b::c633:6432
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let (idx, v4) = state.match_ipv6_dest(dst).expect("should match");
    assert_eq!(idx, 0);
    assert_eq!(v4, Ipv4Addr::new(198, 51, 100, 50));
}

#[test]
fn match_ipv6_dest_no_match() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(state.match_ipv6_dest(dst).is_none());
}

#[test]
fn pool_allocation_round_robin() {
    let state = Nat64State::from_snapshots(&[well_known_prefix()]);
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3");
    assert_eq!(a1, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(a2, Ipv4Addr::new(198, 51, 100, 2));
    assert_eq!(a3, Ipv4Addr::new(198, 51, 100, 1)); // wraps
}

#[test]
fn empty_pool_returns_none() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "no-pool".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![],
        no_v6_frag_header: false,
    }]);
    assert!(state.allocate_v4_source(0).is_none());
}

#[test]
fn nat64_pool_with_cidr_mask_yields_nonempty_pool() {
    // #2123: a range-form source pool (`address A to B`) is expanded by the
    // Go compiler into per-IP /32 entries. Ipv4Addr::from_str rejects the
    // mask, so pre-fix the filter_map discarded every entry, leaving pool_v4
    // empty and allocate_v4_source returning None. The parse must strip the
    // /32 mask. This test FAILS on the unfixed code.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-range".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "100.64.0.1/32".to_string(),
            "100.64.0.2/32".to_string(),
        ],
        no_v6_frag_header: false,
    }]);
    assert!(state.is_active());
    assert_eq!(
        state.prefixes[0].pool_v4.len(),
        2,
        "range-expanded /32 pool addresses must parse, not be dropped"
    );
    // Round-robin allocation must now succeed (was None pre-fix).
    let a1 = state.allocate_v4_source(0).expect("alloc1");
    let a2 = state.allocate_v4_source(0).expect("alloc2");
    let a3 = state.allocate_v4_source(0).expect("alloc3 wraps");
    assert_eq!(a1, Ipv4Addr::new(100, 64, 0, 1));
    assert_eq!(a2, Ipv4Addr::new(100, 64, 0, 2));
    assert_eq!(a3, Ipv4Addr::new(100, 64, 0, 1));
}

#[test]
fn nat64_pool_mixed_bare_and_masked() {
    // Discrete bare-IP `address` lines and range-expanded /32 entries must
    // coexist: stripping the mask must not break the bare-IP parse.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-mixed".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "198.51.100.1".to_string(),
            "198.51.100.5/32".to_string(),
        ],
        no_v6_frag_header: false,
    }]);
    assert_eq!(state.prefixes[0].pool_v4.len(), 2);
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 1)));
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(198, 51, 100, 5)));
}

#[test]
fn nat64_pool_genuinely_invalid_still_dropped() {
    // A genuinely-malformed pool address must still be discarded (the skip
    // path is preserved), while a valid masked entry is kept.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-bad".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "not-an-ip".to_string(),
            "100.64.0.7/32".to_string(),
        ],
        no_v6_frag_header: false,
    }]);
    assert_eq!(state.prefixes[0].pool_v4.len(), 1);
    assert!(state.prefixes[0].pool_v4.contains(&Ipv4Addr::new(100, 64, 0, 7)));
}

#[test]
fn nat64_pool_non_host_mask_rejected() {
    // A non-host mask or garbage suffix on a pool address must be filtered,
    // not coerced to a host address. Only bare and /32 forms install. A valid
    // /32 alongside the bad entries proves the good one survives.
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "nat64-bad-mask".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![
            "100.64.0.1/24".to_string(),      // non-host prefix -> rejected
            "100.64.0.2/notanum".to_string(), // non-numeric mask -> rejected
            "100.64.0.3/".to_string(),        // empty mask -> rejected
            "100.64.0.4//32".to_string(),     // double slash -> rejected
            "100.64.0.9/32".to_string(),      // canonical host -> kept
        ],
        no_v6_frag_header: false,
    }]);
    assert_eq!(
        state.prefixes[0].pool_v4,
        vec![Ipv4Addr::new(100, 64, 0, 9)],
        "only the canonical /32 host entry must survive"
    );
}

#[test]
fn invalid_prefix_length_ignored() {
    let state = Nat64State::from_snapshots(&[NAT64RuleSnapshot {
        name: "bad".to_string(),
        prefix: "64:ff9b::/64".to_string(),
        pool_addresses: vec!["1.2.3.4".to_string()],
        no_v6_frag_header: false,
    }]);
    assert!(!state.is_active());
}

// --- Packet translation tests ---

fn make_ipv6_tcp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut pkt = vec![0u8; 40 + tcp_len];
    // IPv6 header
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    pkt[6] = PROTO_TCP;
    pkt[7] = 64; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    // TCP header (minimal)
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20 bytes)
    pkt[53] = 0x02; // SYN
    pkt[54..56].copy_from_slice(&1024u16.to_be_bytes()); // window
                                                         // Copy payload
    pkt[60..60 + payload.len()].copy_from_slice(payload);
    // Compute TCP checksum
    pkt[56..58].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src, dst, PROTO_TCP, &pkt[40..]);
    pkt[56..58].copy_from_slice(&sum.to_be_bytes());
    pkt
}

fn make_ipv4_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let mut pkt = vec![0u8; total_len];
    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5
    pkt[33] = 0x12; // SYN+ACK
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    pkt[40..40 + payload.len()].copy_from_slice(payload);
    // Compute checksums
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[36..38].copy_from_slice(&[0, 0]);
    let tcp_sum = checksum16_ipv4_pseudo(src, dst, PROTO_TCP, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    pkt
}

#[test]
fn translate_v6_to_v4_tcp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"hello");
    let ipv4_pkt = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Verify IPv4 header.
    assert_eq!(ipv4_pkt[0], 0x45);
    assert_eq!(ipv4_pkt[8], 63); // TTL = 64-1
    assert_eq!(ipv4_pkt[9], PROTO_TCP);
    assert_eq!(&ipv4_pkt[12..16], &snat_v4.octets());
    assert_eq!(&ipv4_pkt[16..20], &dst_v4.octets());

    // Verify size: IPv6 was 40+25=65, IPv4 should be 20+25=45.
    assert_eq!(ipv4_pkt.len(), 45);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv4_pkt[20], ipv4_pkt[21]]), 12345);
    assert_eq!(u16::from_be_bytes([ipv4_pkt[22], ipv4_pkt[23]]), 80);

    // Verify IPv4 header checksum.
    assert_eq!(checksum16(&ipv4_pkt[..20]), 0);

    // Verify TCP checksum.
    let tcp_payload = &ipv4_pkt[20..];
    let src = Ipv4Addr::new(ipv4_pkt[12], ipv4_pkt[13], ipv4_pkt[14], ipv4_pkt[15]);
    let dst = Ipv4Addr::new(ipv4_pkt[16], ipv4_pkt[17], ipv4_pkt[18], ipv4_pkt[19]);
    assert_eq!(checksum16_ipv4_pseudo(src, dst, PROTO_TCP, tcp_payload), 0);
}

#[test]
fn translate_v4_to_v6_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap(); // server→client reply
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"world");
    let ipv6_pkt = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Verify IPv6 header.
    assert_eq!(ipv6_pkt[0] >> 4, 6);
    assert_eq!(ipv6_pkt[6], PROTO_TCP);
    assert_eq!(ipv6_pkt[7], 63); // hop limit = 64-1
    assert_eq!(&ipv6_pkt[8..24], &src_v6.octets());
    assert_eq!(&ipv6_pkt[24..40], &dst_v6.octets());

    // Verify size: IPv4 was 20+25=45, IPv6 should be 40+25=65.
    assert_eq!(ipv6_pkt.len(), 65);

    // Verify TCP ports preserved.
    assert_eq!(u16::from_be_bytes([ipv6_pkt[40], ipv6_pkt[41]]), 80);
    assert_eq!(u16::from_be_bytes([ipv6_pkt[42], ipv6_pkt[43]]), 12345);

    // Verify TCP checksum.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0
    );
}

#[test]
fn translate_v6_to_v4_udp() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build IPv6 + UDP.
    let dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns_query.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = PROTO_UDP;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..48 + dns_query.len()].copy_from_slice(dns_query);
    // UDP checksum
    pkt[46..48].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_UDP, &pkt[40..]);
    pkt[46..48].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_UDP);
    assert_eq!(checksum16(&v4[..20]), 0);
}

#[test]
fn translate_v6_to_v4_icmp_echo() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);

    // Build ICMPv6 Echo Request.
    let icmp_len = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let mut pkt = vec![0u8; 40 + icmp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt[6] = PROTO_ICMPV6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_v6.octets());
    pkt[24..40].copy_from_slice(&dst_v6.octets());
    pkt[40] = ICMPV6_ECHO_REQUEST;
    pkt[41] = 0; // code
    pkt[44..46].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt[46..48].copy_from_slice(&0x0001u16.to_be_bytes()); // seq
                                                           // ICMPv6 checksum
    pkt[42..44].copy_from_slice(&[0, 0]);
    let sum = checksum16_ipv6_pseudo(src_v6, dst_v6, PROTO_ICMPV6, &pkt[40..]);
    pkt[42..44].copy_from_slice(&sum.to_be_bytes());

    let v4 = translate_v6_to_v4(&pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4[9], PROTO_ICMP);
    assert_eq!(v4[20], ICMP_ECHO_REQUEST); // type mapped
    assert_eq!(checksum16(&v4[..20]), 0);
    // ICMPv4 checksum: no pseudo-header.
    assert_eq!(checksum16(&v4[20..]), 0);
}

#[test]
fn translate_v4_to_v6_icmp_echo_reply() {
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // Build ICMPv4 Echo Reply.
    let icmp_len = 8;
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_ICMP;
    pkt[12..16].copy_from_slice(&src_v4.octets());
    pkt[16..20].copy_from_slice(&dst_v4.octets());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    pkt[20] = ICMP_ECHO_REPLY;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&[0, 0]);
    let icmp_sum = checksum16(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&pkt, src_v6, dst_v6).expect("translate");
    assert_eq!(v6[6], PROTO_ICMPV6);
    assert_eq!(v6[40], ICMPV6_ECHO_REPLY); // type mapped
                                           // ICMPv6 checksum verification.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(checksum16_ipv6_pseudo(s6, d6, PROTO_ICMPV6, &v6[40..]), 0);
}

#[test]
fn packet_size_delta() {
    // IPv6 packet: 40 header + 20 TCP header + 5 payload = 65 bytes
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"hello");
    assert_eq!(pkt.len(), 65); // 40 + 20 + 5

    let v4 = translate_v6_to_v4(
        &pkt,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        false,
    )
    .expect("translate");
    assert_eq!(v4.len(), 45); // 20 + 20 + 5
    assert_eq!(pkt.len() - v4.len(), 20); // IPv6→IPv4 shrinks by 20 bytes
}

#[test]
fn forward_decision_sets_nat64_flag() {
    let d = Nat64State::forward_decision(Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(8, 8, 8, 8));
    assert!(d.nat64);
    assert_eq!(
        d.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
    );
    assert_eq!(d.rewrite_dst, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn frame_building_v6_to_v4() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    // Build Ethernet + IPv6 frame.
    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"test");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]); // dst mac
    frame.extend_from_slice(&[0xbb; 6]); // src mac
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        false,
    )
    .expect("build");

    // Should be 14 (eth) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 44);
    // Check Ethernet type is IPv4.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x0800);
}

#[test]
fn frame_building_v4_to_v6() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);

    let pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"resp");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let result =
        build_nat64_v4_to_v6_frame(&frame, src_v6, dst_v6, [0x11; 6], [0x22; 6], 0).expect("build");

    // Should be 14 (eth) + 64 (40 ipv6 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 14 + 64);
    // Check Ethernet type is IPv6.
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x86dd);
}

#[test]
fn ttl_expired_returns_none() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let mut pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 1025, 80, b"x");
    pkt[7] = 1; // hop limit = 1
                // Need to recompute TCP checksum after modifying hop limit
                // (hop limit isn't in pseudo-header so checksum is still valid).
    assert!(
        translate_v6_to_v4(&pkt, Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), false).is_none()
    );
}

#[test]
fn frame_building_v6_to_v4_with_vlan() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"vlan");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        100, // VLAN 100
        false,
    )
    .expect("build");

    // 18 (eth+vlan) + 44 (20 ipv4 + 20 tcp + 4 payload)
    assert_eq!(result.len(), 18 + 44);
    // VLAN tag
    assert_eq!(u16::from_be_bytes([result[12], result[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([result[16], result[17]]), 0x0800);
}

// ---------------------------------------------------------------------------
// Regression tests for #1641: translate_v4_to_v6 must trim the L4 payload to
// the IPv4 Total Length field, not the end of the input slice. The caller
// passes the whole L3-onward frame, which can carry Ethernet padding when the
// reply is shorter than the 60/64-byte minimum frame size. Before the fix the
// padding was copied into the IPv6 packet, inflating payload_len and poisoning
// the L4 checksum so the receiver dropped the reply.
// ---------------------------------------------------------------------------

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_tcp() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    // A minimal TCP segment with no L4 payload: 20B IP + 20B TCP = 40B on the
    // wire (make_ipv4_tcp_packet sets SYN+ACK flags; the exact flag bits are
    // irrelevant to the padding bug). The NIC/driver pads the frame to the
    // 60-byte L2 minimum, so the L3-onward slice the caller hands us is 46
    // bytes (40B real + 6B zero padding).
    let mut packet = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"");
    assert_eq!(packet.len(), 40, "unpadded segment should be 40 bytes");
    let real_len = packet.len();
    packet.extend_from_slice(&[0u8; 6]); // simulate trailing Ethernet padding
    assert_eq!(packet.len(), 46);

    let ipv6_pkt = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");

    // payload_len must reflect the real L4 length (20B TCP), NOT the padded
    // slice length. Before the fix this was 26 (20 + 6 padding bytes).
    let payload_len = u16::from_be_bytes([ipv6_pkt[4], ipv6_pkt[5]]) as usize;
    assert_eq!(payload_len, 20, "payload_len must exclude Ethernet padding");
    // Total translated length = 40B IPv6 header + 20B TCP, with no padding.
    assert_eq!(ipv6_pkt.len(), 40 + (real_len - 20));
    assert_eq!(ipv6_pkt.len(), 60);

    // The L4 checksum must verify over the trimmed payload. A padding-poisoned
    // checksum (the pre-fix bug) leaves a non-zero residual here.
    let src6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[8..24]).unwrap());
    let dst6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6_pkt[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(src6, dst6, PROTO_TCP, &ipv6_pkt[40..]),
        0,
        "TCP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_trims_ethernet_padding_udp_dns() {
    // Short UDP/DNS reply (the canonical Ethernet-padded case). Build a 12B
    // DNS-ish payload: 20B IP + 8B UDP + 12B = 40B real, padded to 46B.
    let src_v4 = Ipv4Addr::new(8, 8, 8, 8);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let dns = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00";
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&src_v4.octets());
    packet[16..20].copy_from_slice(&dst_v4.octets());
    packet[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port
    packet[22..24].copy_from_slice(&12345u16.to_be_bytes()); // dst port
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..28 + dns.len()].copy_from_slice(dns);
    packet[26..28].copy_from_slice(&[0, 0]);
    let udp_sum = checksum16_ipv4_pseudo(src_v4, dst_v4, PROTO_UDP, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());

    assert_eq!(packet.len(), 40);
    packet.extend_from_slice(&[0u8; 6]); // Ethernet padding to 46B L3 slice

    let v6 = translate_v4_to_v6(&packet, src_v6, dst_v6).expect("translate");
    let payload_len = u16::from_be_bytes([v6[4], v6[5]]) as usize;
    assert_eq!(payload_len, udp_len, "payload_len must exclude padding");
    assert_eq!(v6.len(), 40 + udp_len);

    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&v6[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6_pseudo(s6, d6, PROTO_UDP, &v6[40..]),
        0,
        "UDP checksum must verify over the unpadded payload"
    );
}

#[test]
fn translate_v4_to_v6_total_len_larger_than_slice_returns_none() {
    // Malformed Total Length advertising more bytes than we received: must be
    // rejected safely (no panic, no out-of-bounds), not trusted.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    // Advertise a Total Length 100 bytes beyond the actual slice.
    let bogus = (packet.len() + 100) as u16;
    packet[2..4].copy_from_slice(&bogus.to_be_bytes());
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "oversized total_len must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #1662: NAT64 must copy the IP traffic class (DSCP + ECN) across translation
// in BOTH directions. Before the fix the IPv4 TOS byte / IPv6 traffic class was
// hard-zeroed, so DiffServ marking and end-to-end ECN were lost across the
// translator. RFC 7915 §4/§5 default is a verbatim full-byte copy (DSCP copied,
// ECN copied verbatim) — NAT64 is stateless translation, not RFC 6040 tunnel
// encapsulation.
//
// All cases use TOS/TC = 0xBA = (DSCP 46 EF << 2) | ECN 0b10 (ECT(0)). The
// non-zero ECN nibble means a DSCP-only implementation that dropped ECN would
// also fail these assertions.
// ---------------------------------------------------------------------------

/// DSCP 46 (EF) in bits 7:2, ECN 0b10 (ECT(0)) in bits 1:0 → 0xBA.
const TC_EF_ECT0: u8 = (46u8 << 2) | 0b10;

#[test]
fn translate_v6_to_v4_copies_traffic_class() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"qos");
    // Set the IPv6 traffic class to 0xBA across bytes 0-1 (preserving version
    // nibble and flow label). TC[7:4] in byte0 low nibble, TC[3:0] in byte1
    // high nibble. (TCP checksum does not cover the TC byte, so no recompute.)
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);
    // Sanity: reconstruct and confirm the input really carries 0xBA.
    let in_tc = ((ipv6_pkt[0] & 0x0f) << 4) | (ipv6_pkt[1] >> 4);
    assert_eq!(in_tc, TC_EF_ECT0);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // IPv4 TOS byte must equal the source traffic class exactly (DSCP+ECN).
    assert_eq!(v4[1], TC_EF_ECT0, "IPv4 TOS must copy the IPv6 traffic class");
    // IPv4 header checksum must still verify with the non-zero TOS byte.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v4_to_v6_copies_traffic_class() {
    let src_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(src_v4, dst_v4, 80, 12345, b"qos");
    // Set the IPv4 TOS byte to 0xBA and recompute the IPv4 header checksum
    // (the header checksum DOES cover the TOS byte).
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6 = translate_v4_to_v6(&ipv4_pkt, src_v6, dst_v6).expect("translate");

    // Reconstruct the IPv6 traffic class from bytes 0-1 and compare exactly.
    let out_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(
        out_tc, TC_EF_ECT0,
        "IPv6 traffic class must copy the IPv4 TOS byte"
    );
    // Version nibble must remain 6.
    assert_eq!(v6[0] >> 4, 6, "IPv6 version nibble must be preserved");
    // Flow label (low nibble of byte 1 + bytes 2-3) must stay 0.
    assert_eq!(v6[1] & 0x0f, 0, "flow-label high nibble must be 0");
    assert_eq!(v6[2], 0, "flow label must be 0");
    assert_eq!(v6[3], 0, "flow label must be 0");
}

#[test]
fn nat64_traffic_class_round_trips() {
    // v6 → v4 → v6: the traffic class survives a full round trip.
    let client_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let mut ipv6_pkt = make_ipv6_tcp_packet(client_v6, dst_v6, 12345, 80, b"rt");
    ipv6_pkt[0] = (ipv6_pkt[0] & 0xf0) | (TC_EF_ECT0 >> 4);
    ipv6_pkt[1] = (ipv6_pkt[1] & 0x0f) | ((TC_EF_ECT0 & 0x0f) << 4);

    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("v6->v4");
    assert_eq!(v4[1], TC_EF_ECT0);

    // Translate the IPv4 packet back to IPv6 (reply direction reuses the same
    // helper). The TOS byte carried by v4 must reappear in the IPv6 TC.
    let v6 = translate_v4_to_v6(&v4, dst_v6, client_v6).expect("v4->v6");
    let rt_tc = ((v6[0] & 0x0f) << 4) | (v6[1] >> 4);
    assert_eq!(rt_tc, TC_EF_ECT0, "traffic class must survive round trip");
    assert_eq!(v6[0] >> 4, 6);

    // v4 → v6 → v4: the traffic class also survives the opposite round trip.
    let server_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let client_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let server_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let client_v6_reverse: Ipv6Addr = "2001:db8::1".parse().unwrap();

    let mut ipv4_pkt = make_ipv4_tcp_packet(server_v4, client_v4, 80, 12345, b"rt2");
    ipv4_pkt[1] = TC_EF_ECT0;
    ipv4_pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(&ipv4_pkt[..20]);
    ipv4_pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let v6_reverse = translate_v4_to_v6(&ipv4_pkt, server_v6, client_v6_reverse).expect("v4->v6");
    let v6_reverse_tc = ((v6_reverse[0] & 0x0f) << 4) | (v6_reverse[1] >> 4);
    assert_eq!(v6_reverse_tc, TC_EF_ECT0);

    let v4_reverse = translate_v6_to_v4(&v6_reverse, server_v4, client_v4, false).expect("v6->v4");
    assert_eq!(
        v4_reverse[1], TC_EF_ECT0,
        "traffic class must survive v4->v6->v4 round trip"
    );
    assert_eq!(
        checksum16(&v4_reverse[..20]),
        0,
        "IPv4 header checksum must verify"
    );
}

#[test]
fn translate_v4_to_v6_total_len_below_ihl_returns_none() {
    // Total Length shorter than the IPv4 header is nonsensical: reject it.
    let src_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let dst_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut packet = make_ipv4_tcp_packet(
        Ipv4Addr::new(198, 51, 100, 50),
        Ipv4Addr::new(198, 51, 100, 1),
        80,
        12345,
        b"hi",
    );
    packet[2..4].copy_from_slice(&10u16.to_be_bytes()); // < 20B IHL
    assert!(
        translate_v4_to_v6(&packet, src_v6, dst_v6).is_none(),
        "total_len below the IPv4 header length must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #2008 H16: `security nat natv6v4 no-v6-frag-header` must be honored by the
// IPv6->IPv4 translator. Before the fix the option parsed, compiled into typed
// config, and rode the snapshot wire but had NO runtime consumer: the global
// flag never reached the dataplane snapshot and translate_v6_to_v4 always set
// the Don't-Fragment (DF) bit. These tests pin the runtime enforcement: the
// flags+frag-offset word (IPv4 header bytes 6-7) must be DF=1 (0x4000) by
// default and DF=0 (0x0000) when the option is set. The DF clearing is an
// option-gated LOCAL policy, not the size-driven RFC 7915 5.1 selection.
//
// They also pin the DF/Identification consistency the Copilot review on #2014
// flagged: a DF=1 atomic datagram keeps Identification=0 (legal per RFC 6864
// 4.1), while a DF=0 fragmentable datagram MUST carry a non-zero, non-repeating
// Identification drawn from the per-translator generator (RFC 7915 5.1 / RFC
// 6864 4.1) — pinning ID=0 while clearing DF was the original bug.
// ---------------------------------------------------------------------------

/// Helper: read the IPv4 flags + fragment-offset word from a translated L3
/// packet (bytes 6-7).
fn ipv4_frag_word(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[6], pkt[7]])
}

/// Helper: read the IPv4 Identification field (bytes 4-5) from a translated L3
/// packet.
fn ipv4_identification(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[4], pkt[5]])
}

#[test]
fn translate_v6_to_v4_default_sets_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"df");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");

    // Default (no-v6-frag-header NOT set): DF=1, no fragment offset.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x4000,
        "default translation must set the DF bit (atomic, non-fragmentable)"
    );
    // ID=0 is legal for an ATOMIC datagram (DF=1) per RFC 6864 4.1.
    assert_eq!(
        ipv4_identification(&v4),
        0,
        "atomic (DF=1) translation keeps Identification=0"
    );
    // Header checksum must still verify.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_clears_df_bit() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);

    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"nofrag");
    let v4 = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate");

    // With no-v6-frag-header set: DF cleared so the packet stays fragmentable.
    assert_eq!(
        ipv4_frag_word(&v4),
        0x0000,
        "no-v6-frag-header must clear the DF bit (fragmentable, per RFC 7915 5.1)"
    );
    // A fragmentable (DF=0) datagram is NON-ATOMIC. RFC 7915 5.1 sets the
    // Identification from a per-translator generator, and RFC 6864 4.1 forbids
    // a constant/repeated ID for non-atomic datagrams. A pinned ID=0 (the
    // pre-fix bug) would mis-reassemble distinct datagrams when a downstream
    // router fragments them, so the ID MUST be non-zero here.
    assert_ne!(
        ipv4_identification(&v4),
        0,
        "fragmentable (DF=0) translation MUST carry a non-zero Identification \
         (RFC 7915 5.1 / RFC 6864 4.1)"
    );
    // The change must not break the IPv4 header checksum.
    assert_eq!(checksum16(&v4[..20]), 0, "IPv4 header checksum must verify");

    // Everything else (TTL, protocol, addresses, payload) must be unchanged
    // relative to the default translation — only the DF bit (bytes 6-7), the
    // Identification (bytes 4-5), and the resulting header checksum (bytes
    // 10-11) differ.
    let v4_default = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, false).expect("translate");
    assert_eq!(v4.len(), v4_default.len());
    assert_eq!(v4[8], v4_default[8], "TTL unchanged");
    assert_eq!(v4[9], v4_default[9], "protocol unchanged");
    assert_eq!(&v4[12..20], &v4_default[12..20], "src/dst addresses unchanged");
    assert_eq!(&v4[20..], &v4_default[20..], "L4 payload unchanged");
    // The frag word is one header field that must differ.
    assert_ne!(
        ipv4_frag_word(&v4),
        ipv4_frag_word(&v4_default),
        "frag word must differ between the two modes"
    );
}

#[test]
fn translate_v6_to_v4_no_v6_frag_header_identification_is_unique() {
    // RFC 6864 4.1: a source emitting non-atomic (DF=0) datagrams MUST NOT
    // repeat the Identification for a given src/dst/proto tuple within one MDL.
    // The per-translator generator advances on every fragmentable translation,
    // so successive DF=0 translations must carry DISTINCT non-zero IDs.
    //
    // This test is DETERMINISTIC and robust to the process-global counter's
    // start value (it does not assume the generator begins at any particular
    // raw value): it exercises the pure mapping `map_frag_id` over a CONTROLLED
    // consecutive sequence that crosses the 0/1 boundary AND a full 16-bit wrap,
    // and asserts the cycle invariants directly. The old test passed only by
    // accident — other tests advanced the shared atomic before it ran, so it
    // FAILED in isolation (`cargo test <name> -- --exact`).
    //
    // Mutation check: the pre-fix mapping `if raw==0 {1} else {raw as u16}`
    // maps BOTH raw=0 and raw=1 to 1, so the raw=0->raw=1 step below produces a
    // consecutive duplicate and the no-repeat assertion fails.
    let mut prev: Option<u16> = None;
    // 0..=65536 covers the first two values (raw=0,1 — the boundary that the
    // pre-fix remap collided), the top of the cycle (raw=65534 -> 65535), and
    // the wrap (raw=65535 -> 1, raw=65536 -> 2). Iterating one full period plus
    // a step proves there is no consecutive duplicate ANYWHERE, including the
    // 65535 -> 1 jump.
    for raw in 0u32..=65536 {
        let id = map_frag_id(raw);
        assert_ne!(id, 0, "Identification must be non-zero (raw={raw})");
        assert!(
            (1..=65535).contains(&id),
            "Identification must lie in 1..=65535 (raw={raw}, id={id})"
        );
        if let Some(p) = prev {
            assert_ne!(
                p, id,
                "successive Identifications must differ (RFC 6864 4.1 no-repeat): \
                 raw={raw} produced {id} == previous {p}"
            );
        }
        prev = Some(id);
    }
    // Spot-check the boundary and wrap values the pre-fix mapping got wrong.
    assert_eq!(map_frag_id(0), 1);
    assert_eq!(map_frag_id(1), 2, "raw=1 must NOT collide with raw=0 (the bug)");
    assert_eq!(map_frag_id(65534), 65535, "top of the cycle");
    assert_eq!(map_frag_id(65535), 1, "wrap is a jump 65535 -> 1, not a repeat");
    assert_eq!(map_frag_id(65536), 2);

    // End-to-end smoke: two back-to-back fragmentable translations both carry
    // non-zero IDs and stay DF=0 with valid checksums. (The no-consecutive-dup
    // proof lives in the deterministic loop above; this only confirms the
    // generator is actually wired into the DF=0 translation path.)
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let snat_v4 = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(198, 51, 100, 50);
    let ipv6_pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"uniq");
    let a = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate a");
    let b = translate_v6_to_v4(&ipv6_pkt, snat_v4, dst_v4, true).expect("translate b");
    assert_ne!(ipv4_identification(&a), 0, "first fragmentable ID must be non-zero");
    assert_ne!(ipv4_identification(&b), 0, "second fragmentable ID must be non-zero");
    assert_ne!(
        ipv4_identification(&a),
        ipv4_identification(&b),
        "two back-to-back fragmentable translations must use distinct IDs"
    );
    assert_eq!(ipv4_frag_word(&a), 0x0000);
    assert_eq!(ipv4_frag_word(&b), 0x0000);
    assert_eq!(checksum16(&a[..20]), 0, "header checksum must verify (a)");
    assert_eq!(checksum16(&b[..20]), 0, "header checksum must verify (b)");
}

#[test]
fn build_nat64_v6_to_v4_frame_honors_no_v6_frag_header() {
    let src_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst_v6: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();

    let pkt = make_ipv6_tcp_packet(src_v6, dst_v6, 12345, 80, b"frame");
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa; 6]);
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);

    // no_v6_frag_header = true: the inner IPv4 header (after the 14B Ethernet
    // header) must carry DF=0.
    let result = build_nat64_v6_to_v4_frame(
        &frame,
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(198, 51, 100, 50),
        [0x11; 6],
        [0x22; 6],
        0,
        true,
    )
    .expect("build");
    let ipv4 = &result[14..];
    assert_eq!(
        ipv4_frag_word(ipv4),
        0x0000,
        "frame builder must thread no-v6-frag-header into the IPv4 framing"
    );
}

#[test]
fn nat64_state_threads_no_v6_frag_header_from_snapshot() {
    // The flag rides on the per-rule snapshot (the Go side stamps the global
    // natv6v4 option onto every rule). from_snapshots must surface it.
    let mut snap = well_known_prefix();
    assert!(
        !Nat64State::from_snapshots(&[snap.clone()]).no_v6_frag_header,
        "default snapshot must leave no_v6_frag_header unset"
    );
    snap.no_v6_frag_header = true;
    assert!(
        Nat64State::from_snapshots(&[snap]).no_v6_frag_header,
        "from_snapshots must surface the no_v6_frag_header flag"
    );
}
