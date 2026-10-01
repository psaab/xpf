use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn nat64_ipv6_frame(l3_len: usize, protocol: u8) -> Vec<u8> {
    let l4_header_len = match protocol {
        PROTO_UDP => 8,
        PROTO_TCP => 20,
        _ => panic!("unsupported test protocol"),
    };
    assert!(l3_len >= 40 + l4_header_len);
    let src: Ipv6Addr = "2001:4860::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    let l4_len = l3_len - 40;
    let mut frame = Vec::with_capacity(14 + l3_len);
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(l4_len as u16).to_be_bytes());
    frame.push(protocol);
    frame.push(64);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let l4_offset = frame.len();
    frame.extend_from_slice(&12345u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    if protocol == PROTO_UDP {
        frame.extend_from_slice(&(l4_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
    } else {
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(0x18);
        frame.extend_from_slice(&65535u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0, 0]);
    }
    frame.resize(14 + l3_len, 0x5a);
    let checksum = crate::afxdp::frame::checksum16_ipv6(src, dst, protocol, &frame[l4_offset..]);
    let checksum_offset = l4_offset + if protocol == PROTO_UDP { 6 } else { 16 };
    frame[checksum_offset..checksum_offset + 2]
        .copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
    frame
}

fn nat64_ipv6_nonfirst_fragment_frame(l3_len: usize, protocol: u8) -> Vec<u8> {
    let src: Ipv6Addr = "2001:4860::1".parse().unwrap();
    let dst: Ipv6Addr = "64:ff9b::c633:6432".parse().unwrap();
    assert!(l3_len >= 48);
    let fragment_payload_len = l3_len - 48;
    assert_eq!(fragment_payload_len % 8, 0);
    let mut frame = Vec::with_capacity(14 + l3_len);
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&((l3_len - 40) as u16).to_be_bytes());
    frame.push(44); // Fragment Header
    frame.push(64);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.push(protocol);
    frame.push(0);
    frame.extend_from_slice(&((17u16 << 3) | 1).to_be_bytes());
    frame.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    frame.resize(14 + l3_len, 0x5a);
    frame
}

fn assert_nat64_v6_packet_fragments_for_ipv4_egress_mtu(protocol: u8) {
    let _rate_limit = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let frame = nat64_ipv6_frame(1280, protocol);
    let mut forwarding = test_forwarding_with_egress_mtu(1200);
    forwarding.egress.insert(
        11,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0, 1],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: Some("2001:db8::fe".parse().unwrap()),
        },
    );

    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    decision.nat.nat64 = true;
    decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
    decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)));
    decision.nat.rewrite_src_port = Some(40000);
    let mut request = test_live_forward_request_for_frame(frame.len(), decision);
    request.meta.addr_family = libc::AF_INET6 as u8;
    request.meta.protocol = protocol;
    request.meta.l3_offset = 14;
    request.meta.l4_offset = 54;
    request.meta.pkt_len = frame.len() as u16;
    request.meta.flow_src_addr.copy_from_slice(&frame[22..38]);
    request.meta.flow_dst_addr.copy_from_slice(&frame[38..54]);

    let expected = crate::afxdp::frame::build_nat64_forwarded_frame(
        &frame,
        request.meta,
        &request.decision,
        None,
        false,
        &forwarding,
    )
    .expect("unfragmented NAT64 translation");
    assert_eq!(u16::from_be_bytes([expected[16], expected[17]]), 1260);

    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![request];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut counters,
        0,
        &worker_commands_by_id,
    );

    assert!(
        bindings[0].tx_pipeline.pending_tx_local.is_empty(),
        "fragmentable NAT64 packet must not send PTB"
    );
    let fragments = &bindings[1].tx_pipeline.pending_tx_local;
    assert_eq!(
        fragments.len(),
        2,
        "1260-byte translated IPv4 packet must be fragmented to fit the 1200-byte next-hop MTU"
    );
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);

    let mut reassembled_payload = Vec::new();
    let mut expected_offset = 0usize;
    let mut identification = None;
    for (index, request) in fragments.iter().enumerate() {
        let ip = &request.bytes[14..];
        let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let frag_word = u16::from_be_bytes([ip[6], ip[7]]);
        let offset = (frag_word & 0x1fff) as usize * 8;
        let payload_len = total_len - 20;
        assert_eq!(ip[0] >> 4, 4);
        assert!(total_len <= 1200);
        assert_eq!(frag_word & 0x4000, 0, "emitted fragments must have DF clear");
        assert_eq!(offset, expected_offset);
        assert_eq!(crate::afxdp::frame::checksum16(&ip[..20]), 0);
        let id = u16::from_be_bytes([ip[4], ip[5]]);
        assert_ne!(id, 0);
        assert_eq!(*identification.get_or_insert(id), id);
        assert_eq!(frag_word & 0x2000 != 0, index + 1 < fragments.len());
        if index + 1 < fragments.len() {
            assert_eq!(payload_len % 8, 0);
        }
        reassembled_payload.extend_from_slice(&ip[20..20 + payload_len]);
        expected_offset += payload_len;
    }
    let expected_total_len = u16::from_be_bytes([expected[16], expected[17]]) as usize;
    assert_eq!(
        reassembled_payload,
        expected[34..14 + expected_total_len],
        "fragment payloads must reassemble to the translated IPv4 payload"
    );
}

#[test]
fn nat64_udp_v6_packet_under_1280_fragments_for_ipv4_egress_mtu_11353() {
    assert_nat64_v6_packet_fragments_for_ipv4_egress_mtu(PROTO_UDP);
}

#[test]
fn nat64_tcp_v6_packet_under_1280_fragments_for_ipv4_egress_mtu_11353() {
    assert_nat64_v6_packet_fragments_for_ipv4_egress_mtu(PROTO_TCP);
}

#[test]
fn nat64_v6_nonfirst_fragment_fragments_for_ipv4_egress_mtu_11353() {
    let _rate_limit = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let frame = nat64_ipv6_nonfirst_fragment_frame(1280, PROTO_UDP);
    let mut forwarding = test_forwarding_with_egress_mtu(1200);
    forwarding.egress.insert(
        11,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0, 1],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: Some("2001:db8::fe".parse().unwrap()),
        },
    );
    let mut decision = test_forwarding_decision_to_bound_ifindex(22);
    decision.nat.nat64 = true;
    decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
    decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)));
    let mut request = test_live_forward_request_for_frame(frame.len(), decision);
    request.meta.addr_family = libc::AF_INET6 as u8;
    request.meta.protocol = PROTO_UDP;
    request.meta.l3_offset = 14;
    request.meta.l4_offset = 62;
    request.meta.pkt_len = frame.len() as u16;
    request.meta.flow_src_addr.copy_from_slice(&frame[22..38]);
    request.meta.flow_dst_addr.copy_from_slice(&frame[38..54]);

    let expected = crate::afxdp::frame::build_nat64_forwarded_frame(
        &frame,
        request.meta,
        &request.decision,
        None,
        false,
        &forwarding,
    )
    .expect("unfragmented non-first NAT64 translation");
    assert_eq!(u16::from_be_bytes([expected[16], expected[17]]), 1252);

    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    unsafe { bindings[0].umem.area().slice_mut_unchecked(0, frame.len()) }
        .expect("ingress frame")
        .copy_from_slice(&frame);
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut pending = vec![request];
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();

    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut counters,
        0,
        &worker_commands_by_id,
    );

    assert!(
        bindings[0].tx_pipeline.pending_tx_local.is_empty(),
        "a non-first NAT64 fragment must not generate an IPv6 PTB"
    );
    let fragments = &bindings[1].tx_pipeline.pending_tx_local;
    assert_eq!(
        fragments.len(),
        2,
        "translated non-first IPv4 fragment must be refragmented for the 1200-byte MTU"
    );
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);

    let mut translated_payload = Vec::new();
    let mut expected_offset_units = 17usize;
    for request in fragments {
        let ip = &request.bytes[14..];
        let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let frag_word = u16::from_be_bytes([ip[6], ip[7]]);
        let offset_units = (frag_word & 0x1fff) as usize;
        let payload_len = total_len - 20;
        assert_eq!(ip[0] >> 4, 4);
        assert!(total_len <= 1200);
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 0x5678);
        assert_eq!(offset_units, expected_offset_units);
        assert_eq!(frag_word & 0x2000, 0x2000, "original MF flag is preserved");
        assert_eq!(crate::afxdp::frame::checksum16(&ip[..20]), 0);
        translated_payload.extend_from_slice(&ip[20..20 + payload_len]);
        expected_offset_units += payload_len / 8;
    }
    let expected_total_len = u16::from_be_bytes([expected[16], expected[17]]) as usize;
    assert_eq!(
        translated_payload,
        expected[34..14 + expected_total_len],
        "refragmented payload must preserve the translated non-first payload"
    );
}
