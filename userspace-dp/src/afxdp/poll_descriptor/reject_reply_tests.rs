// Tests for afxdp/poll_descriptor/reject_reply.rs (#4668) — relocated
// verbatim out of the former inline `#[cfg(test)] mod tests { ... }` block
// to keep the production file (cold reject-reply enqueue paths) readable.
// Loaded as a sibling submodule via `#[path = "reject_reply_tests.rs"]`
// from reject_reply.rs. No test logic changed.

use super::*;

fn tx_pipeline(max_pending_tx: usize, free_frames: usize) -> WorkerTxPipeline {
    WorkerTxPipeline {
        free_tx_frames: (0..free_frames as u64).collect(),
        pending_tx_prepared: VecDeque::new(),
        pending_tx_local: VecDeque::new(),
        backup_retry_scratch: std::collections::VecDeque::new(),
        max_pending_tx,
        outstanding_tx: 0,
        pending_fill_frames: VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        in_flight_untracked_tx: FastSet::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    }
}

fn tcp_v4_syn() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
    let src_ip = std::net::Ipv4Addr::new(192, 0, 2, 10);
    let dst_ip = std::net::Ipv4Addr::new(198, 51, 100, 20);
    let src_port = 49152u16;
    let dst_port = 22u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6, 0x08, 0x00,
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0xfa, 0xf0, // data offset / SYN / window
        0x00, 0x00, 0x00, 0x00, // checksum + urgent
    ]);
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src_ip.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst_ip.octets());
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: std::net::IpAddr::V4(src_ip),
        dst_ip: std::net::IpAddr::V4(dst_ip),
        src_port,
        dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(src_ip),
        dst_ip: std::net::IpAddr::V4(dst_ip),
        forward_key: key,
    };
    (frame, meta, flow)
}
fn policy_reject_packet_v4(protocol: u8) -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
    let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
    let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let payload = match protocol {
        crate::ip_proto::PROTO_UDP => [0xc0, 0, 0, 53, 0, 8, 0, 0],
        crate::ip_proto::PROTO_ICMP => [8, 0, 0, 0, 0x12, 0x34, 0, 1],
        crate::ip_proto::PROTO_GRE => [0, 0, 0x08, 0, 0, 0, 0, 0],
        crate::ip_proto::PROTO_ESP => [0, 0, 0, 1, 0, 0, 0, 1],
        _ => panic!("unsupported test protocol {protocol}"),
    };
    let (src_port, dst_port) = match protocol {
        crate::ip_proto::PROTO_UDP => (0xc000, 53),
        crate::ip_proto::PROTO_ICMP => (0x1234, 0),
        _ => (0, 0),
    };
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, protocol, 0, 0,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&payload);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(client),
        dst_ip: std::net::IpAddr::V4(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol,
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            src_port,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    (frame, meta, flow)
}

fn policy_reject_packet_v6(protocol: u8) -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
    let client: std::net::Ipv6Addr = "2001:db8:61::102".parse().unwrap();
    let server: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let payload = match protocol {
        crate::ip_proto::PROTO_UDP => [0xc0, 0, 0, 53, 0, 8, 0, 0],
        crate::ip_proto::PROTO_ICMPV6 => [128, 0, 0, 0, 0x12, 0x34, 0, 1],
        crate::ip_proto::PROTO_GRE => [0, 0, 0x08, 0, 0, 0, 0, 0],
        crate::ip_proto::PROTO_ESP => [0, 0, 0, 1, 0, 0, 0, 1],
        _ => panic!("unsupported test protocol {protocol}"),
    };
    let (src_port, dst_port) = match protocol {
        crate::ip_proto::PROTO_UDP => (0xc000, 53),
        crate::ip_proto::PROTO_ICMPV6 => (0x1234, 0),
        _ => (0, 0),
    };
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, protocol, 64]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&payload);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V6(client),
        dst_ip: std::net::IpAddr::V6(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol,
            src_ip: std::net::IpAddr::V6(client),
            dst_ip: std::net::IpAddr::V6(server),
            src_port,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    (frame, meta, flow)
}

fn policy_reject_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0, 0x61, 1],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: Some("2001:db8:61::1".parse().unwrap()),
        },
    );
    forwarding
}

fn stamped_fabric_reject_forwarding() -> ForwardingState {
    let mut forwarding = policy_reject_forwarding();
    let mut ingress_egress = forwarding
        .egress
        .get(&5)
        .expect("policy reject egress fixture")
        .clone();
    ingress_egress.bind_ifindex = 21;
    forwarding.egress.insert(21, ingress_egress);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 22,
        peer_addr: "192.0.2.1".parse().unwrap(),
        peer_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x02],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding
}

#[test]
fn policy_reject_udp_uses_port_unreachable_11303_v4() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    let forwarding = policy_reject_forwarding();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    assert!(enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    ));
    assert_eq!(counters.policy_reject_sent, 1);
    let reply = pipeline
        .pending_tx_local
        .pop_front()
        .expect("UDP policy reject reply");
    assert_eq!(
        &reply.bytes[34..36],
        &[3, 3],
        "UDP policy reject must return ICMPv4 destination-unreachable/port-unreachable"
    );
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
}

#[test]
fn policy_reject_udp_uses_port_unreachable_11303_v6() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = policy_reject_packet_v6(crate::ip_proto::PROTO_UDP);
    let forwarding = policy_reject_forwarding();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    assert!(enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    ));
    assert_eq!(counters.policy_reject_sent, 1);
    let reply = pipeline
        .pending_tx_local
        .pop_front()
        .expect("UDP policy reject reply");
    assert_eq!(
        &reply.bytes[54..56],
        &[1, 4],
        "UDP policy reject must return ICMPv6 destination-unreachable/port-unreachable"
    );
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
}

#[test]
fn policy_reject_non_udp_protocols_drop_silently_11303() {
    for protocol in [
        crate::ip_proto::PROTO_ICMP,
        crate::ip_proto::PROTO_GRE,
        crate::ip_proto::PROTO_ESP,
    ] {
        let (frame, meta, flow) = policy_reject_packet_v4(protocol);
        let forwarding = policy_reject_forwarding();
        let mut pipeline = tx_pipeline(64, 64);
        let mut counters = BatchCounters::default();
        assert!(
            !enqueue_policy_reject_reply(
                &mut pipeline,
                &forwarding,
                5,
                &frame,
                meta,
                &flow,
                &mut counters,
            ),
            "IPv4 protocol {protocol} policy reject must be silent"
        );
        assert_eq!(counters.policy_reject_sent, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }
    for protocol in [
        crate::ip_proto::PROTO_ICMPV6,
        crate::ip_proto::PROTO_GRE,
        crate::ip_proto::PROTO_ESP,
    ] {
        let (frame, meta, flow) = policy_reject_packet_v6(protocol);
        let forwarding = policy_reject_forwarding();
        let mut pipeline = tx_pipeline(64, 64);
        let mut counters = BatchCounters::default();
        assert!(
            !enqueue_policy_reject_reply(
                &mut pipeline,
                &forwarding,
                5,
                &frame,
                meta,
                &flow,
                &mut counters,
            ),
            "IPv6 protocol {protocol} policy reject must be silent"
        );
        assert_eq!(counters.policy_reject_sent, 0);
        assert!(pipeline.pending_tx_local.is_empty());
    }
}

#[test]
fn reject_reply_budget_exhausted_fails_closed_no_send() {
    let (frame, meta, flow) = tcp_v4_syn();
    // Zero max-pending => budget unavailable => silent-drop fail-closed.
    let mut pipeline = tx_pipeline(0, 64);
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(!sent, "must fail-closed under budget exhaustion");
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(counters.policy_reject_reply_budget_drops, 1);
    assert!(pipeline.pending_tx_local.is_empty());
}

#[test]
fn reject_tcp_with_egress_enqueues_rst() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    // #2472/#2955: the Reject token bucket is a global GCRA word whose TAT
    // advances monotonically; reset-to-full alone is not enough because a
    // parallel test can advance/drain the TAT after the reset. Hold the
    // shared global-bucket test lock for the whole reset→drive→assert window
    // so no sibling can starve this success-path assertion.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut forwarding = ForwardingState::default();
    // build_reject_rst_frame is self-contained (it reflects the
    // inbound frame), so a TCP reject does not need an egress entry;
    // it should enqueue regardless.
    forwarding.egress.clear();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(sent, "TCP reject must enqueue a RST");
    assert_eq!(counters.policy_reject_sent, 1);
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("reject RST request");
    assert_eq!(req.egress_ifindex, 5);
    assert_eq!(req.cos_queue_id, None);
    assert_eq!(req.dscp_rewrite, None);
    assert!(!req.mirror_clone);
    assert_eq!(req.flow_key, Some(flow.forward_key));
    // Reflected RST: dst MAC is the inbound src MAC; RST flag set.
    assert_eq!(&req.bytes[0..6], &[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    let tcp_flags = req.bytes[14 + 20 + 13];
    assert_ne!(tcp_flags & 0x04, 0, "RST flag must be set");
}

/// #2238: a policy-generated UDP port-unreachable matching an OUTPUT filter
/// `then discard` is not enqueued, and the dedicated
/// `policy_reject_output_filter_drops` counter increments.
#[test]
fn reject_reply_dropped_by_egress_output_filter() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    // Policy UDP reject builds an ICMP port-unreachable, which the egress
    // output filter discards.
    let (frame, meta, flow) = policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    let filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "drop-icmp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: "drop-icmp".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        !sent,
        "reject reply dropped by egress output filter must not enqueue"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(counters.policy_reject_output_filter_drops, 1);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #2521: a firewall-filter `then reject` on a TCP flow synthesizes a TCP
/// RST (not a silent drop) and increments `filter_reject_sent` — NOT
/// `policy_reject_sent`. Fail-on-revert: if the call site reverts to a
/// silent recycle (no synthesis), `pending_tx_local` stays empty and
/// `filter_reject_sent` stays 0; if it routes through the policy counter,
/// the per-source counter assertion fails.
#[test]
fn filter_reject_tcp_enqueues_rst_filter_counter() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(sent, "filter TCP reject must enqueue a RST");
    assert_eq!(
        counters.filter_reject_sent, 1,
        "filter reject must bump filter_reject_sent"
    );
    assert_eq!(
        counters.policy_reject_sent, 0,
        "filter reject must NOT bump policy_reject_sent"
    );
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("filter reject RST request");
    assert_eq!(req.egress_ifindex, 5);
    // Reflected RST: dst MAC is the inbound src MAC; RST flag set.
    assert_eq!(&req.bytes[0..6], &[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    let tcp_flags = req.bytes[14 + 20 + 13];
    assert_ne!(tcp_flags & 0x04, 0, "RST flag must be set");
}

/// #2521: a firewall-filter `then reject` on a NON-TCP (ICMP) flow
/// still uses the configured/default admin-prohibited message, unlike
/// policy `reject` (#11303). It increments `filter_reject_sent`.
#[test]
fn filter_reject_non_tcp_enqueues_icmp_unreachable() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
    let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(client),
        dst_ip: std::net::IpAddr::V4(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            src_port: 0x1234,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    // build_reject_icmp_unreachable needs an egress with a v4 primary on
    // the reply's egress interface (the inbound ingress ifindex).
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(
        sent,
        "filter non-TCP reject must enqueue an ICMP unreachable"
    );
    assert_eq!(counters.filter_reject_sent, 1);
    assert_eq!(counters.policy_reject_sent, 0);
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("filter reject ICMP request");
    // ICMP unreachable: type 3 at the L4 offset of the reply.
    assert_eq!(
        req.bytes[14 + 20],
        3,
        "ICMP type must be Destination Unreachable"
    );
    assert_eq!(
        req.bytes[14 + 20 + 1],
        13,
        "filter reject retains default ICMPv4 admin-prohibited code"
    );
}

/// #3615 (L04) fail-on-revert: a FILTER `then reject` reply suppressed by
/// TX-frame budget exhaustion must bump `filter_reject_reply_budget_drops`,
/// NOT the policy sibling. Reverting the source-routed budget counter (back
/// to always `policy_reject_reply_budget_drops`) turns this RED.
#[test]
fn filter_reject_budget_exhausted_uses_filter_counter() {
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(0, 64); // zero budget => suppressed
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(
        !sent,
        "filter reject must fail-closed under budget exhaustion"
    );
    assert_eq!(
        counters.filter_reject_reply_budget_drops, 1,
        "filter-source budget drop must bump the filter counter"
    );
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "a filter-reject budget drop must NOT bump the policy counter"
    );
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3615 (L05) fail-on-revert: a FILTER `then reject` reply discarded by an
/// egress OUTPUT filter must bump `filter_reject_output_filter_drops`, NOT
/// the policy sibling. Mirrors `reject_reply_dropped_by_egress_output_-
/// filter` (policy source) but drives the FILTER entry point.
#[test]
fn filter_reject_output_filter_drop_uses_filter_counter() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
    let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(client),
        dst_ip: std::net::IpAddr::V4(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            src_port: 0x1234,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "drop-icmp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: "drop-icmp".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(
        !sent,
        "filter reject discarded by egress output filter must not enqueue"
    );
    assert_eq!(
        counters.filter_reject_output_filter_drops, 1,
        "filter-source output-filter drop must bump the filter counter"
    );
    assert_eq!(
        counters.policy_reject_output_filter_drops, 0,
        "a filter-reject output-filter drop must NOT bump the policy counter"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #2472 call-site fail-on-revert: once the global per-reason `Reject`
/// token bucket is empty, `enqueue_policy_reject_reply` MUST fail-closed
/// (no RST enqueued, `policy_reject_sent` stays 0) and the observable
/// `Reject` rate-limited counter MUST advance — even though the TX-frame
/// budget is plentiful. Without the #2472 limiter the reject reply would
/// enqueue regardless of how many were generated, so this test fails on a
/// revert of the call-site gate.
#[test]
fn reject_reply_rate_limited_when_bucket_empty() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    // #2955: serialise with the other global Reject-bucket tests so a
    // parallel reset-to-full cannot undo the far-future drain mid-test.
    let _g = global_bucket_test_lock();
    let (frame, meta, flow) = tcp_v4_syn();
    // The call site samples the REAL `monotonic_nanos()` (boot-relative,
    // small), which we cannot freeze. To keep the global Reject bucket
    // empty across that call, pin its refill epoch (`last_ns`) to a FAR
    // FUTURE value, then drain it: the call site's smaller `now_ns` yields
    // `saturating_sub == 0` → zero refill → the bucket stays empty and the
    // call site's `allow_generated_error(Reject)` is denied. (On a deny
    // with no refill, `try_take` does NOT advance `last_ns`, so the
    // far-future epoch — and thus the empty state — survives the call.)
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
    while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::Reject);
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(!sent, "reject reply must fail-closed when rate-limited");
    assert_eq!(
        counters.policy_reject_sent, 0,
        "no reject must be counted as sent under rate limit"
    );
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no RST may be enqueued under rate limit"
    );
    assert!(
        rate_limited_count(GeneratedErrorReason::Reject) > before,
        "the rate-limited drop must bump the observable Reject counter"
    );
    // #3656 H12: a REPLIABLE reply suppressed by the rate limiter is
    // counted as rate-limited (above), NOT as TX-frame queue pressure — the
    // budget gate passed, so no budget drop may be attributed to it.
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "a rate-limited (buildable) reject must not count a budget drop"
    );
    // #3661 fail-on-revert: a POLICY-source rate-limit drop must bump the
    // policy-source per-binding counter, NOT the filter sibling. Reverting
    // the source split (dropping the `match source` arms) leaves both at 0
    // and turns this RED.
    assert_eq!(
        counters.policy_reject_rate_limit_drops, 1,
        "a policy-reject rate-limit drop must bump the policy counter"
    );
    assert_eq!(
        counters.filter_reject_rate_limit_drops, 0,
        "a policy-reject rate-limit drop must NOT bump the filter counter"
    );
    // Restore a full bucket so sibling tests in this binary are unaffected.
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #3661 fail-on-revert: a FILTER `then reject` reply dropped because the
/// shared REJECT_BUCKET rate-limit bucket is empty must bump
/// `filter_reject_rate_limit_drops`, NOT the policy sibling. Mirrors
/// `reject_reply_rate_limited_when_bucket_empty` (policy source) but drives
/// the FILTER entry point. Reverting the source split (the rate-limit drop
/// stays source-neutral) leaves the filter counter at 0 → RED. The
/// source-neutral aggregate (`rate_limited_count`) still advances for both.
#[test]
fn filter_reject_rate_limited_uses_filter_counter() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    let (frame, meta, flow) = tcp_v4_syn();
    // Drain the shared Reject bucket at a far-future epoch (see the policy
    // sibling test for why): the call site's smaller monotonic `now`
    // yields zero refill, so the bucket stays empty across the call.
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
    while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::Reject);
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(!sent, "filter reject must fail-closed when rate-limited");
    assert_eq!(
        counters.filter_reject_sent, 0,
        "no filter reject must be counted as sent under rate limit"
    );
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no RST may be enqueued under rate limit"
    );
    assert!(
        rate_limited_count(GeneratedErrorReason::Reject) > before,
        "the source-neutral aggregate rate-limited counter must still advance"
    );
    assert_eq!(
        counters.filter_reject_rate_limit_drops, 1,
        "a filter-reject rate-limit drop must bump the filter counter"
    );
    assert_eq!(
        counters.policy_reject_rate_limit_drops, 0,
        "a filter-reject rate-limit drop must NOT bump the policy counter"
    );
    // Restore a full bucket so sibling tests in this binary are unaffected.
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

#[test]
fn reject_inbound_rst_is_not_answered() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    // Flip the inbound to a RST: must not be answered (no RST storm).
    frame[14 + 20 + 13] = 0x04;
    meta.tcp_flags = 0x04;
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(!sent, "inbound RST must not be answered");
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3656 H11 fail-on-revert: a frame that can NEVER produce a reply (an
/// inbound TCP RST) must NOT consume a token from the shared REJECT_BUCKET.
/// Drives the reject path with the bucket EMPTY and the TX budget plentiful:
/// on the fixed code the reply-build feasibility check runs first, returns
/// None, and short-circuits BEFORE `allow_generated_error`, so the empty
/// bucket is never touched and its rate-limited counter does not advance.
/// On a revert (token consumed before feasibility), the empty-bucket deny
/// bumps the rate-limited counter — turning this RED. This is the H11 DoS:
/// a flood of unreplyable frames draining the shared bucket would silently
/// downgrade legitimate rejects to drops.
#[test]
fn unreplyable_reject_does_not_drain_bucket_3656() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    // Pin the refill epoch to the far future then drain, so the call site's
    // smaller monotonic `now_ns` yields zero refill and the bucket stays
    // empty across the call (mirrors reject_reply_rate_limited_when_bucket_-
    // empty). A denied `try_take` does not advance the epoch, so the empty
    // state survives.
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
    while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::Reject);

    // Inbound TCP RST => build_reject_rst_frame returns None (unreplyable).
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    frame[14 + 20 + 13] = 0x04;
    meta.tcp_flags = 0x04;
    // TX budget plentiful — isolates the token-bucket behavior.
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(!sent, "inbound RST is unreplyable");
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        before,
        "an unreplyable frame must not consume a REJECT_BUCKET token (H11)"
    );
    // H12: and it must not be mis-attributed as TX-frame budget pressure.
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "an unreplyable frame must not count a budget drop"
    );
    assert!(pipeline.pending_tx_local.is_empty());
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #3656 H12 fail-on-revert: a frame that can never produce a reply must
/// NOT be counted as a TX-frame-budget drop. Drives the reject path with an
/// inbound TCP RST (unreplyable) and the TX budget EXHAUSTED (zero
/// max-pending). On the fixed code the reply-build feasibility check runs
/// FIRST, returns None, and short-circuits BEFORE the budget gate, so no
/// budget drop is counted for a reply that could never have existed. On a
/// revert (budget checked before feasibility), the exhausted budget bumps
/// `policy_reject_reply_budget_drops` here — hiding the true attack shape
/// as queue pressure — turning this RED.
#[test]
fn unreplyable_reject_does_not_count_budget_drop_3656() {
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    // Inbound TCP RST => unreplyable.
    frame[14 + 20 + 13] = 0x04;
    meta.tcp_flags = 0x04;
    // Zero max-pending => TX budget exhausted.
    let mut pipeline = tx_pipeline(0, 64);
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(!sent, "inbound RST is unreplyable");
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "an unreplyable frame must not be mis-attributed as budget pressure (H12)"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3656 fail-on-revert (non-first-fragment variant): a non-first IPv4
/// fragment has no transport header to quote, so `build_reject_icmp_-
/// unreachable` (`can_generate_icmp_error_reply`) returns None — the frame
/// is unreplyable. It must consume neither the shared REJECT_BUCKET token
/// nor a budget drop. Runs with the TX budget EXHAUSTED so a reverted
/// budget-before-feasibility order would count a budget drop (RED). The
/// FILTER entry point is exercised here to cover both counter families.
#[test]
fn unreplyable_non_first_fragment_reject_untouched_3656() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    // Empty the shared bucket (far-future epoch drain) so a reverted token-
    // before-feasibility order would deny + bump the rate-limited counter.
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
    while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::Reject);

    let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
    let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header with a non-zero fragment offset (0x0001) => non-first
    // fragment => can_generate_icmp_error_reply() == false => build None.
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x01, 64, PROTO_ICMP, 0, 0,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // fragment payload
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(client),
        dst_ip: std::net::IpAddr::V4(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            src_port: 0,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    // Zero max-pending => TX budget exhausted (drives the H12 leg too).
    let mut pipeline = tx_pipeline(0, 64);
    // An egress primary would be needed to BUILD an ICMP unreachable, but a
    // non-first fragment is rejected before the family build, so omit it.
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(!sent, "a non-first fragment is unreplyable");
    assert_eq!(counters.filter_reject_sent, 0);
    assert_eq!(
        counters.filter_reject_reply_budget_drops, 0,
        "a non-first fragment must not count a filter budget drop (H12)"
    );
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "a non-first fragment must not count a policy budget drop (H12)"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        before,
        "a non-first fragment must not drain the REJECT_BUCKET (H11)"
    );
    assert!(pipeline.pending_tx_local.is_empty());
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// An ICMP echo (non-TCP) frame for tests of non-TCP reject/deny handling.
fn icmp_v4_echo() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
    let client = std::net::Ipv4Addr::new(10, 0, 61, 102);
    let server = std::net::Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
    ]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(client),
        dst_ip: std::net::IpAddr::V4(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: std::net::IpAddr::V4(client),
            dst_ip: std::net::IpAddr::V4(server),
            src_port: 0x1234,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    (frame, meta, flow)
}

/// #11304 fail-on-revert: plain policy `deny` remains a silent drop even
/// when the ingress zone has Junos `tcp-rst`. The option applies at the
/// transit session-miss gate, not when a policy denies traffic.
#[test]
fn deny_reply_zone_tcp_rst_policy_deny_is_silent_11304() {
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(64, 64);
    let mut forwarding = ForwardingState::default();
    forwarding.zone_tcp_rst.insert(7, true);
    let mut counters = BatchCounters::default();
    let sent = enqueue_deny_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        false, // plain deny, not `then reject`
    );
    assert!(!sent, "zone `tcp-rst` must not answer a policy deny");
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #11304: a plain TCP `deny` stays silent when no ingress zone has
/// `tcp-rst` enabled; explicit `then reject` remains an active reply.
#[test]
fn deny_reply_no_zone_tcp_rst_is_silent_drop() {
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(64, 64);
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_deny_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        false,
    );
    assert!(
        !sent,
        "a plain policy deny must stay a silent drop"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// A denied non-TCP (ICMP) flow is a silent drop; explicit reject uses its
/// separate active ICMP reply path.
#[test]
fn deny_reply_plain_deny_non_tcp_is_silent_drop() {
    let (frame, meta, flow) = icmp_v4_echo();
    let mut pipeline = tx_pipeline(64, 64);
    let mut forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    let sent = enqueue_deny_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        false,
    );
    assert!(
        !sent,
        "non-TCP policy deny must stay silent"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3035: forwarding state where the VLAN unit reth0.80 (logical ifindex
/// 202, parent 11, VID 80) carries a TCP-discard output filter and the
/// physical parent 11 carries NONE. Proves the reject reply is classified
/// on the LOGICAL unit ifindex, not the physical ingress port.
fn vlan_drop_tcp_snapshot() -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 202,
            parent_ifindex: 11,
            vlan_id: 80,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "drop-tcp".into(),
            ..Default::default()
        }],
        filters: vec![crate::FirewallFilterSnapshot {
            name: "drop-tcp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-tcp".into(),
                action: "discard".into(),
                protocols: vec!["tcp".into()],
                ..Default::default()
            }],
        }],
        ..Default::default()
    }
}

/// #3035 fail-on-revert: a reject reply (TCP RST) for a SYN arriving on a
/// VLAN sub-interface must be classified (output filter / CoS) on the
/// LOGICAL unit ifindex, not the physical ingress port. The logical unit
/// reth0.80 (202) carries a TCP-discard output filter; the physical parent
/// 11 does not. Driving the real enqueue with the physical ingress ifindex
/// 11 must resolve the logical unit and drop the RST. If the classify
/// reverts to the physical `ingress_ifindex`, the parent has no filter and
/// the reply is wrongly admitted -> this test goes RED. A reflected TCP RST
/// needs no egress primary, so this isolates the classify ifindex.
#[test]
fn reject_reply_classifies_on_logical_vlan_ifindex_3035() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, mut meta, flow) = tcp_v4_syn();
    // Inbound SYN arrives on physical parent ifindex 11, tagged VID 80.
    meta.ingress_ifindex = 11;
    meta.ingress_vlan_id = 80;
    let forwarding = build_forwarding_state(&vlan_drop_tcp_snapshot());

    // Fixture sanity + divergence: logical-keyed classify drops (the
    // unit's drop-tcp filter), physical-parent-keyed classify admits.
    assert_eq!(
        resolve_ingress_logical_ifindex(&forwarding, 11, 80),
        Some(202),
        "parent 11 / VLAN 80 must resolve to logical ifindex 202"
    );
    let rst = build_reject_rst_frame(&frame).expect("reflected RST builds");
    let now_ns = monotonic_nanos();
    assert!(
        classify_generated_reply(&forwarding, 202, &rst, now_ns).drop,
        "logical-keyed classify must hit the VLAN unit's drop-tcp filter"
    );
    assert!(
        !classify_generated_reply(&forwarding, 11, &rst, now_ns).drop,
        "physical-parent-keyed classify has no filter and would wrongly admit"
    );

    // Drive the real enqueue with the PHYSICAL ingress ifindex 11.
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        11, // physical parent ingress ifindex
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        !sent,
        "reject reply on a VLAN unit must be dropped by the unit's output filter"
    );
    assert_eq!(counters.policy_reject_output_filter_drops, 1);
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #11786 fail-on-revert: a permitted reject is shaped on the logical VLAN
/// CoS queue, not looked up against its physical XSK parent.
#[test]
fn reject_reply_queues_on_logical_vlan_ifindex_11786() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, mut meta, flow) = tcp_v4_syn();
    meta.ingress_ifindex = 11;
    meta.ingress_vlan_id = 80;
    let mut snapshot = vlan_drop_tcp_snapshot();
    snapshot.interfaces[0].filter_output_v4.clear();
    let mut forwarding = build_forwarding_state(&snapshot);
    forwarding.tx_selection_enabled_v4 = true;
    forwarding
        .cos
        .interfaces
        .insert(202, crate::afxdp::tests_support::test_reply_cos_interface(4));

    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    assert!(enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        11,
        &frame,
        meta,
        &flow,
        &mut counters,
    ));

    let request = pipeline
        .pending_tx_local
        .front()
        .expect("generated reject queued");
    assert_eq!(request.egress_ifindex, 202, "CoS key is logical unit");
    assert_eq!(request.cos_queue_id, Some(4), "logical default queue is selected");
}

/// #3035 non-VLAN regression: on an untagged interface the logical unit IS
/// the ingress ifindex (no (parent, vlan) mapping), so `resolve_ingress_-
/// logical_ifindex` returns None and the classify falls back to the
/// physical ifindex unchanged — behavior is byte-identical to pre-#3035.
#[test]
fn reject_reply_non_vlan_classify_unchanged_3035() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn(); // ingress_ifindex 5, vlan 0
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            hardware_addr: "02:bf:72:00:00:05".into(),
            filter_output_v4: "drop-tcp".into(),
            ..Default::default()
        }],
        filters: vec![crate::FirewallFilterSnapshot {
            name: "drop-tcp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-tcp".into(),
                action: "discard".into(),
                protocols: vec!["tcp".into()],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    // An untagged unit maps to ITSELF (logical == physical == 5), so the
    // resolve is a no-op and the classify ifindex is unchanged.
    assert_eq!(
        resolve_ingress_logical_ifindex(&forwarding, 5, 0),
        Some(5),
        "an untagged port resolves logical == physical; the classify ifindex is unchanged"
    );
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5, // logical == physical for an untagged port
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        !sent,
        "untagged interface still applies its own output filter (unchanged)"
    );
    assert_eq!(counters.policy_reject_output_filter_drops, 1);
    assert_eq!(counters.policy_reject_sent, 0);
}

/// #3976 fail-on-revert (IPv4): a UDP policy reject arriving on a VLAN
/// sub-interface must build its ICMP port-unreachable from the INGRESS
/// SUB-INTERFACE's own primary address and VLAN tag, not the physical parent's.
/// The logical unit reth0.80 (ifindex 202, parent 11, VID 80) carries
/// 172.16.80.8/24; the physical parent 11 has NO egress entry of its own.
/// Driving the real enqueue with the physical ingress ifindex 11 must resolve
/// the logical unit and source the reply from 172.16.80.8 tagged VID 80. On
/// revert the physical-parent-keyed lookup misses and the reject silently
/// degrades to a discard — RED.
#[test]
fn reject_reply_non_tcp_sources_from_logical_vlan_ifindex_3976() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    // reth0.80: logical ifindex 202, parent 11, VID 80, 172.16.80.8/24.
    // The physical parent 11 is deliberately NOT a configured interface, so
    // a physical-parent-keyed egress lookup misses entirely.
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 202,
            parent_ifindex: 11,
            vlan_id: 80,
            hardware_addr: "02:bf:72:00:80:08".into(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "172.16.80.8/24".into(),
                scope: 0,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    // Fixture sanity: parent 11 / VID 80 resolves to the logical unit 202.
    assert_eq!(
        resolve_ingress_logical_ifindex(&forwarding, 11, 80),
        Some(202),
        "parent 11 / VLAN 80 must resolve to logical unit 202"
    );

    // Inbound UDP datagram (untagged frame; hardware tag in metadata) from a
    // VLAN-80 host to a unicast destination.
    let client = std::net::Ipv4Addr::new(172, 16, 80, 55);
    let server = std::net::Ipv4Addr::new(8, 8, 8, 8);
    let (mut frame, mut meta, mut flow) =
        policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    frame[26..30].copy_from_slice(&client.octets());
    frame[30..34].copy_from_slice(&server.octets());
    meta.ingress_ifindex = 11;
    meta.ingress_vlan_id = 80;
    flow.src_ip = std::net::IpAddr::V4(client);
    flow.dst_ip = std::net::IpAddr::V4(server);
    flow.forward_key.src_ip = std::net::IpAddr::V4(client);
    flow.forward_key.dst_ip = std::net::IpAddr::V4(server);

    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    // Drive the real enqueue with the PHYSICAL ingress ifindex 11.
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        11, // physical parent ingress ifindex
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        sent,
        "UDP policy reject on a VLAN sub-if must build + enqueue an ICMP \
         port-unreachable (a physical-parent-keyed build misses the sub-if \
         egress and silently drops)"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("reject ICMP port-unreachable request");
    // CoS uses the logical sub-if key; the request stays on the physical TX pipeline.
    assert_eq!(req.egress_ifindex, 202);
    // The reply carries the sub-if's VLAN tag (VID 80), from the egress
    // vlan_id fallback (the inbound frame was untagged).
    assert_eq!(
        &req.bytes[12..14],
        &[0x81, 0x00],
        "reply must carry an 802.1Q tag"
    );
    let vid = u16::from_be_bytes([req.bytes[14], req.bytes[15]]) & 0x0fff;
    assert_eq!(vid, 80, "reply VLAN id must be the sub-if VID 80");
    assert_eq!(
        &req.bytes[16..18],
        &0x0800u16.to_be_bytes(),
        "inner EtherType IPv4"
    );
    // ICMP source == the sub-if's own primary v4 (172.16.80.8), NOT parent.
    assert_eq!(
        &req.bytes[30..34],
        &[172, 16, 80, 8],
        "ICMP unreachable must be sourced from the ingress sub-if address"
    );
    // UDP policy reject: ICMP Destination Unreachable, port-unreachable (3/3).
    assert_eq!(req.bytes[38], 3, "ICMP type Destination Unreachable");
    assert_eq!(req.bytes[39], 3, "ICMP code port-unreachable");
}

/// #3976 fail-on-revert (IPv6): the same VLAN-sub-if reject fix on the
/// ICMPv6 path — the generated ICMPv6 admin-prohibited unreachable must be
/// sourced from the sub-if's primary v6 and carry the sub-if VLAN tag.
/// Uses the FILTER entry point to cover that source too. On revert the
/// physical-parent-keyed build misses the sub-if egress → None → drop.
#[test]
fn filter_reject_non_tcp_v6_sources_from_logical_vlan_ifindex_3976() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 202,
            parent_ifindex: 11,
            vlan_id: 80,
            hardware_addr: "02:bf:72:00:80:08".into(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet6".into(),
                address: "2001:559:8585:80::8/64".into(),
                scope: 0,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    let client: std::net::Ipv6Addr = "2001:559:8585:80::55".parse().unwrap();
    let server: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let src_ip: std::net::Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst (fw)
    frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]); // src (host)
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    // IPv6 header: version 6, payload len 8 (ICMPv6 echo), next-hdr 58.
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, PROTO_ICMPV6, 64]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMPv6 echo req
    let meta = UserspaceDpMeta {
        ingress_ifindex: 11,
        ingress_vlan_id: 80,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        pkt_len: frame.len() as u16,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V6(client),
        dst_ip: std::net::IpAddr::V6(server),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: std::net::IpAddr::V6(client),
            dst_ip: std::net::IpAddr::V6(server),
            src_port: 0x1234,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_filter_reject_reply(
        &mut pipeline,
        &forwarding,
        11, // physical parent ingress ifindex
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    );
    assert!(
        sent,
        "non-TCP v6 reject on a VLAN sub-if must build + enqueue an ICMPv6 unreachable"
    );
    assert_eq!(counters.filter_reject_sent, 1);
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("reject ICMPv6 request");
    assert_eq!(req.egress_ifindex, 202, "CoS key is the logical VLAN unit");
    assert_eq!(
        &req.bytes[12..14],
        &[0x81, 0x00],
        "reply must carry an 802.1Q tag"
    );
    let vid = u16::from_be_bytes([req.bytes[14], req.bytes[15]]) & 0x0fff;
    assert_eq!(vid, 80, "reply VLAN id must be the sub-if VID 80");
    assert_eq!(
        &req.bytes[16..18],
        &0x86ddu16.to_be_bytes(),
        "inner EtherType IPv6"
    );
    // ICMPv6 source (IPv6 header src at bytes 8..24 of the L3 packet;
    // L2 is 18 bytes tagged, so the source octets are at [26..42]).
    assert_eq!(
        &req.bytes[26..42],
        &src_ip.octets(),
        "ICMPv6 unreachable must be sourced from the ingress sub-if v6 address"
    );
    // ICMPv6 Destination Unreachable, admin-prohibited (type 1, code 1).
    assert_eq!(req.bytes[58], 1, "ICMPv6 type Destination Unreachable");
    assert_eq!(req.bytes[59], 1, "ICMPv6 code admin-prohibited");
}

/// #3071: the unified deny-reply still drives explicit policy `reject`
/// (is_reject=true) through the active reject path regardless of zone
/// tcp-rst — a TCP RST is enqueued even when the from-zone has no tcp-rst.
#[test]
fn deny_reply_explicit_reject_still_resets_tcp() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default(); // no zone tcp-rst at all
    let mut counters = BatchCounters::default();
    let sent = enqueue_deny_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        true, // explicit `then reject`
    );
    assert!(
        sent,
        "explicit reject must enqueue a RST regardless of zone tcp-rst"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    assert!(!pipeline.pending_tx_local.is_empty());
}

// #3615 M10: poll-loop-path ordering coverage for `deny_reply_and_emit` —
// the combining helper the transit deny sites + junos-host deny call. RT_FLOW
// action bytes mirror event_emit.rs (DENY = 0, REJECT = 2).
const RT_FLOW_ACTION_DENY: u8 = 0;
const RT_FLOW_ACTION_REJECT: u8 = 2;

fn unlimited_event_handle() -> (
    EventStreamWorkerHandle,
    std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
) {
    crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    )
}

/// #3615 M10 fail-on-revert: a policy `then reject` whose reply is
/// SUPPRESSED by TX-frame budget on the poll path must (a) NOT enqueue a
/// reply, (b) bump `policy_reject_reply_budget_drops`, and (c) emit a
/// policy-deny event whose action is the TRUTHFUL DENY, not REJECT.
/// Reverting `deny_reply_and_emit` to emit BEFORE the enqueue (or hardcode
/// `reject_reply_enqueued=true`) flips the wire action back to REJECT — RED
/// on the event-action assertion. Asserts action + counter + TX queue
/// length together (issue #3615 M10).
#[test]
fn deny_reply_and_emit_suppressed_reject_logs_deny() {
    let (frame, meta, flow) = tcp_v4_syn();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(0, 64); // zero budget => reply suppressed
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,   // from_zone
        9,   // to_zone
        0,   // owner_rg
        101, // policy_id
        PolicyAction::Reject,
        0, // app_id
        123,
    );
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no reply may be enqueued under budget exhaustion"
    );
    assert_eq!(counters.policy_reject_reply_budget_drops, 1);
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "a suppressed reject on the poll path must log DENY, not REJECT"
    );
}

/// #3615 M10 (rate-limit suppression variant): once the global `Reject`
/// token bucket is empty, `deny_reply_and_emit` enqueues no reply and the
/// emitted policy-deny action is the truthful DENY.
#[test]
fn deny_reply_and_emit_rate_limited_reject_logs_deny() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    let (frame, meta, flow) = tcp_v4_syn();
    // Pin the refill epoch to the far future then drain, so the call site's
    // smaller monotonic `now_ns` yields zero refill (mirrors
    // reject_reply_rate_limited_when_bucket_empty).
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::Reject, far_future);
    while allow_generated_error_at(GeneratedErrorReason::Reject, far_future, 1000, 1000) {}
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(64, 64); // budget plentiful; rate limits
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no reply may be enqueued when rate-limited"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "a rate-limited reject on the poll path must log DENY, not REJECT"
    );
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #3615 M10 GREEN companion: a policy `then reject` whose reply IS enqueued
/// logs the truthful REJECT and increments `policy_reject_sent`.
#[test]
fn deny_reply_and_emit_success_logs_reject() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );
    assert_eq!(counters.policy_reject_sent, 1, "the RST must be enqueued");
    assert_eq!(pipeline.pending_tx_local.len(), 1);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.action, RT_FLOW_ACTION_REJECT,
        "an enqueued reject must log the truthful REJECT"
    );
}
/// #12051: a TCP `then reject` on a stamped fabric arrival is a truthful
/// silent drop. The incoming source MAC is the synthetic zone stamp, not the
/// client's L2 address; reflecting it in a RST would only queue on the fabric.
#[test]
fn stamped_fabric_policy_reject_suppresses_tcp_rst_and_logs_deny_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0xfe, 0x00, 0x02]);
    meta.ingress_ifindex = 21;
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut forwarding = ForwardingState::default();
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 22,
        peer_addr: "192.0.2.1".parse().unwrap(),
        peer_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x02],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );

    assert!(
        pipeline.pending_tx_local.is_empty(),
        "a stamped fabric arrival must not queue its synthetic source MAC as RST destination"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
}

/// #12051 regression for preferred V2 fabric stamps. The stamp is produced
/// by the production ingress-identity redirect helper so this pins the wire
/// format rather than duplicating it in the test.
#[test]
fn v2_stamped_fabric_policy_reject_suppresses_tcp_rst_and_logs_deny_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    meta.ingress_ifindex = 21;
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut forwarding = stamped_fabric_reject_forwarding();
    let scope_id = crate::afxdp::forwarding::fabric_nat_scope_stamp_id(7, "reth0.7", "default");
    forwarding
        .ifindex_to_fabric_nat_scope_id
        .insert(21, scope_id);
    forwarding.fabric_nat_scope_id_to_identity.insert(
        scope_id,
        crate::afxdp::types::FabricNatScopeIdentity {
            zone_id: 7,
            ifindex: 21,
            redundancy_group: 1,
        },
    );
    let stamp = crate::afxdp::forwarding::resolve_fabric_redirect_for_ingress_identity(
        &forwarding,
        Some(7),
        Some(21),
    )
    .expect("V2 ingress-identity fabric redirect");
    let source_mac = stamp.src_mac.expect("V2 fabric source stamp");
    assert_eq!(&source_mac[..3], &FABRIC_NAT_SCOPE_MAC_PREFIX);
    frame[6..12].copy_from_slice(&source_mac);

    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );

    assert!(
        pipeline.pending_tx_local.is_empty(),
        "a V2-stamped fabric arrival must not queue its synthetic source MAC as RST destination"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
}

/// #12051 M1 control: a stamp-shaped source MAC on native ingress is not a
/// synthetic fabric arrival, so its ordinary TCP policy reject still RSTs.
#[test]
fn stamp_shaped_native_policy_reject_still_enqueues_tcp_rst_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    let stamp = [0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02];
    frame[6..12].copy_from_slice(&stamp);
    meta.ingress_ifindex = 5;
    let forwarding = ForwardingState::default();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    assert!(enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    ));
    assert_eq!(counters.policy_reject_sent, 1);
    let reply = pipeline
        .pending_tx_local
        .pop_front()
        .expect("native TCP reject RST");
    assert_eq!(&reply.bytes[..6], &stamp);
    assert_ne!(reply.bytes[14 + 20 + 13] & crate::tcp_flags::TCP_RST, 0);
}

/// #12051 M2 control: a known fabric ingress without a synthetic source stamp
/// retains its peer-routable TCP policy reject.
#[test]
fn unstamped_fabric_policy_reject_still_enqueues_tcp_rst_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, mut meta, flow) = tcp_v4_syn();
    let client_mac = frame[6..12].to_vec();
    meta.ingress_ifindex = 21;
    let forwarding = stamped_fabric_reject_forwarding();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    assert!(enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
    ));
    assert_eq!(counters.policy_reject_sent, 1);
    let reply = pipeline
        .pending_tx_local
        .pop_front()
        .expect("unstamped fabric TCP reject RST");
    assert_eq!(&reply.bytes[..6], client_mac.as_slice());
}

/// #12319 M3: both legs of a stamped-fabric UDP policy reject must fail closed.
/// ICMP would reflect the synthetic source stamp, so no reply is queued or
/// counted and the policy-deny event reports DENY rather than REJECT.
#[test]
fn stamped_fabric_udp_policy_reject_suppresses_icmp_and_logs_deny_12319() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02]);
    meta.ingress_ifindex = 21;
    let forwarding = stamped_fabric_reject_forwarding();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );

    assert!(pipeline.pending_tx_local.is_empty());
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(counters.policy_reject_reply_budget_drops, 0);
    assert_eq!(counters.policy_reject_rate_limit_drops, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
    assert!(rx.try_recv().is_err());
}

/// #12319: a V2 stamp produced by the ingress-identity redirect helper is
/// suppressed by the same shared gate as the V1 stamp above.
#[test]
fn v2_stamped_fabric_udp_policy_reject_suppresses_icmp_12319() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    meta.ingress_ifindex = 21;
    let mut forwarding = stamped_fabric_reject_forwarding();
    let scope_id = crate::afxdp::forwarding::fabric_nat_scope_stamp_id(7, "reth0.7", "default");
    forwarding
        .ifindex_to_fabric_nat_scope_id
        .insert(21, scope_id);
    forwarding.fabric_nat_scope_id_to_identity.insert(
        scope_id,
        crate::afxdp::types::FabricNatScopeIdentity {
            zone_id: 7,
            ifindex: 21,
            redundancy_group: 1,
        },
    );
    let stamp = crate::afxdp::forwarding::resolve_fabric_redirect_for_ingress_identity(
        &forwarding,
        Some(7),
        Some(21),
    )
    .expect("V2 ingress-identity fabric redirect");
    let source_mac = stamp.src_mac.expect("V2 fabric source stamp");
    frame[6..12].copy_from_slice(&source_mac);
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );

    assert!(pipeline.pending_tx_local.is_empty());
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
}

/// #12319 positive control: an unstamped fabric UDP reject keeps its
/// peer-routable ICMPv4 port-unreachable, counts the queued reply, and logs
/// REJECT rather than over-suppressing every fabric ingress.
#[test]
fn unstamped_fabric_udp_policy_reject_still_enqueues_icmp_12319() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, mut meta, flow) = policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    let client_mac = frame[6..12].to_vec();
    meta.ingress_ifindex = 21;
    let forwarding = stamped_fabric_reject_forwarding();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );

    assert_eq!(counters.policy_reject_sent, 1);
    let reply = pipeline
        .pending_tx_local
        .pop_front()
        .expect("unstamped-fabric UDP ICMP reply");
    assert_eq!(&reply.bytes[..6], client_mac.as_slice());
    assert_eq!(&reply.bytes[34..36], &[3, 3]);
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
}

/// #4499 E2 (reject half): a policy `then reject` deny path emits a single
/// RT_FLOW record whose KIND is `PolicyDeny` — NOT a `SessionCreate`
/// (session-init) record — and NO second frame follows. The reject branch in
/// the poll loop never reaches the session-install path, so a `then reject`
/// policy configured with `then log session-init` produces the policy-deny log
/// and the RST, but no session and hence no session-init log. This pins the
/// EVENT KIND (the existing `deny_reply_and_emit_success_logs_reject` pins only
/// the action byte). Fail-on-revert: if the deny path ever emitted a
/// `SessionCreate`-kind record (a session-init leak on a denied flow), the kind
/// assertion flips; if it emitted a trailing frame, the drain assertion flips.
#[test]
fn deny_reply_and_emit_reject_logs_policy_deny_kind_not_session_init_4499() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::event_stream::codec::DataplaneEventKind;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (frame, meta, flow) = tcp_v4_syn();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = ForwardingState::default();
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7,
        9,
        0,
        101,
        PolicyAction::Reject,
        0,
        123,
    );
    // The RST is enqueued (active reject).
    assert_eq!(counters.policy_reject_sent, 1, "the RST must be enqueued");
    assert_eq!(pipeline.pending_tx_local.len(), 1);
    // Exactly ONE record, and it is a POLICY_DENY — never a SESSION_CREATE.
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        DataplaneEventKind::PolicyDeny,
        "#4499 E2: a `then reject` deny logs POLICY_DENY, never a session-init (SessionCreate)"
    );
    assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
    assert!(
        rx.try_recv().is_err(),
        "#4499 E2: no second (session-init) frame may follow a denied flow"
    );
}

/// #4499 E2 (deny half): a policy `then deny` (plain deny, no ingress-zone
/// `tcp-rst`) is a SILENT drop — `deny_reply_and_emit` enqueues NO reply, yet
/// still emits a single RT_FLOW record whose kind is `PolicyDeny` and whose
/// action is the truthful DENY. As with the reject half, the deny branch never
/// installs a session, so even with `then log session-init` there is no
/// session-init (SessionCreate) record: exactly one POLICY_DENY frame and no
/// trailing frame. The existing `deny_reply_no_zone_tcp_rst_is_silent_drop`
/// exercises only `enqueue_deny_reply` (the no-reply decision) and never drives
/// the event emit; this pins the combined emit path for plain deny.
/// Fail-on-revert: a plain deny that started synthesizing an RST flips the
/// no-reply assertion; a plain deny that emitted a session-init flips the kind
/// / drain assertions.
#[test]
fn deny_reply_and_emit_plain_deny_silent_logs_deny_no_session_init_4499() {
    use crate::event_stream::codec::DataplaneEventKind;
    let (frame, meta, flow) = tcp_v4_syn();
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(64, 64); // ample budget; plain deny still silent
    let forwarding = ForwardingState::default(); // ingress zone 7 has no tcp-rst
    let mut counters = BatchCounters::default();
    deny_reply_and_emit(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
        &NatDecision::default(),
        7, // from_zone (not tcp-rst enabled)
        9, // to_zone
        0, // owner_rg
        101,
        PolicyAction::Deny,
        0,
        123,
    );
    // Silent drop: no RST/ICMP reply enqueued, no reject counter bumped.
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "#4499 E2: a plain `then deny` (no zone tcp-rst) must enqueue no reply"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    // Exactly ONE POLICY_DENY record with the truthful DENY action, and no
    // trailing session-init frame.
    let event = rx
        .try_recv()
        .expect("policy-deny event frame")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        DataplaneEventKind::PolicyDeny,
        "#4499 E2: a `then deny` logs POLICY_DENY, never a session-init (SessionCreate)"
    );
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "#4499 E2: a plain deny logs the truthful DENY action"
    );
    assert!(
        rx.try_recv().is_err(),
        "#4499 E2: a denied flow installs no session, so no session-init frame follows"
    );
}

/// #3618 call-site fail-on-revert (end-to-end): with per-(from-)zone Reject
/// buckets, a rejected-flow flood that drains ZONE A's bucket must NOT stop
/// ZONE B from emitting its reject through `enqueue_policy_reject_reply`.
/// The bucket is selected by resolving the ingress ifindex → zone via
/// `ifindex_to_zone_id`, so this exercises the full wiring (ingress ifindex
/// → from-zone → per-zone bucket). On the single-global-bucket revert,
/// draining zone A empties the one shared bucket and zone B fails closed →
/// RED.
#[test]
fn per_zone_reject_isolation_at_call_site_3618() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::ZoneLimiter;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
    };
    use crate::afxdp::types::FastMap;
    use std::sync::Arc;

    let _g = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);

    let zone_a = 4_321u16;
    let zone_b = 8_765u16;
    let ifidx_a = 5i32; // ingress interface in zone A (the flooded zone)
    let ifidx_b = 6i32; // ingress interface in zone B (a quiet zone)

    // Ingress-ifindex → from-zone map + fresh per-zone Reject buckets.
    let mut ifindex_to_zone_id: FastMap<i32, u16> = FastMap::default();
    ifindex_to_zone_id.insert(ifidx_a, zone_a);
    ifindex_to_zone_id.insert(ifidx_b, zone_b);
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    reject_buckets.insert(zone_a, Arc::new(ZoneLimiter::new()));
    reject_buckets.insert(zone_b, Arc::new(ZoneLimiter::new()));
    let forwarding = ForwardingState {
        ifindex_to_zone_id,
        reject_buckets,
        ..ForwardingState::default()
    };

    // Drain zone A's limiter AGGREGATE. The enqueue call samples the REAL
    // (small) monotonic clock, so pin the refill epoch to the far future and
    // drain it there: the smaller call-site `now` yields zero refill and the
    // limiter stays empty across the call (mirrors the #2472 tests). #9901
    // (F-074): drain the aggregate tier DIRECTLY — a gate drain would stop at
    // the source tier's smaller budget and leave the aggregate half-full.
    let far_future = u64::MAX / 2;
    forwarding
        .generated_error_bucket(GeneratedErrorReason::Reject, zone_a)
        .expect("per-zone reject limiter")
        .drain_aggregate_for_test(far_future, 1000, 1000);

    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();

    // Zone A (ingress ifindex 5): its own flood drained the bucket →
    // fail-closed.
    let sent_a = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        ifidx_a,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        !sent_a,
        "zone A reject must fail-closed under its own rejected-flow flood"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());

    // Zone B (ingress ifindex 6): untouched bucket → still emits its RST.
    let sent_b = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        ifidx_b,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        sent_b,
        "zone B reject must NOT be starved by zone A's flood (per-zone isolation)"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    assert_eq!(pipeline.pending_tx_local.len(), 1);

    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #5569 RED-on-revert (the whole fix): a flood of egress-FILTERED rejects —
/// rejects whose generated ICMP unreachable is DISCARDED by the reply's own
/// egress output filter — must NOT drain the per-zone reject token bucket, so
/// a later filter-PERMITTED reject (a TCP RST the SAME zone's output filter
/// accepts) still finds a token. The output filter accepts TCP (the RST is
/// permitted) and discards ICMP (the flood is filtered); both ingress on
/// ifindex 5 → zone A → the SAME per-zone bucket, so this is same-zone
/// cross-protocol starvation, not the #3618 cross-ZONE case.
///
/// FIXED ordering (classify BEFORE token): each policy-generated UDP
/// port-unreachable short-circuits at the output-filter drop and spends no
/// token, so the bucket stays full and the trailing PERMITTED RST is admitted.
/// Pre-fix ordering (token BEFORE classify): each filtered UDP policy reject
/// builds an ICMP port-unreachable and consumes a token before being discarded;
/// a flood larger than the burst drains the bucket (and out-consumes any
/// wall-clock refill), so the trailing PERMITTED RST is denied (rate-limited)
/// — RED there on the output-filter-drop count, the rate-limit-drop count,
/// AND the permitted-RST send.
#[test]
fn egress_filtered_reject_does_not_drain_zone_token_5569() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::ZoneLimiter;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
    };
    use crate::afxdp::types::FastMap;
    use std::sync::Arc;

    // This test's per-zone bucket is local, but hold the shared lock + reset
    // the fallback (mirrors per_zone_reject_isolation_at_call_site_3618) so a
    // sibling cannot perturb the fallback if any resolution falls through.
    let _g = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);

    let zone_a = 4_321u16;
    let ifidx = 5i32;
    let mut ifindex_to_zone_id: FastMap<i32, u16> = FastMap::default();
    ifindex_to_zone_id.insert(ifidx, zone_a);
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    reject_buckets.insert(zone_a, Arc::new(ZoneLimiter::new()));

    // Output filter on ifindex 5: accept TCP (RST permitted), discard ICMP
    // (the generated ICMP unreachable is filtered). First-match terms.
    let filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "fc".into(),
            family: "inet".into(),
            terms: vec![
                crate::FirewallTermSnapshot {
                    name: "allow-tcp".into(),
                    action: "accept".into(),
                    protocols: vec!["tcp".into()],
                    ..Default::default()
                },
                crate::FirewallTermSnapshot {
                    name: "drop-icmp".into(),
                    action: "discard".into(),
                    protocols: vec!["icmp".into()],
                    ..Default::default()
                },
            ],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: "fc".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ifindex_to_zone_id,
        reject_buckets,
        ..ForwardingState::default()
    };
    // Egress[5] has a v4 primary so the UDP-triggered ICMP port-unreachable
    // BUILDS (feasible) — the flood must reach the classify/token gate, not
    // short-circuit at the #3656 feasibility check.
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    // Flood N filtered UDP rejects. N > DEFAULT_BURST (1000) so the pre-fix
    // ordering fully drains the bucket.
    let (udp_frame, udp_meta, udp_flow) =
        policy_reject_packet_v4(crate::ip_proto::PROTO_UDP);
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    const FLOOD: u64 = 1_500;
    for _ in 0..FLOOD {
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            5,
            &udp_frame,
            udp_meta,
            &udp_flow,
            &mut counters,
        );
        assert!(!sent, "an egress-filtered UDP reject must not enqueue");
    }
    // Every filtered reject took the output-filter drop leg and spent NO
    // token: all counted as output-filter drops, none as rate-limit drops.
    assert_eq!(
        counters.policy_reject_output_filter_drops, FLOOD,
        "all filtered rejects must count as output-filter drops"
    );
    assert_eq!(
        counters.policy_reject_rate_limit_drops, 0,
        "a filtered reject must not drain the token → no rate-limit drops"
    );
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no filtered reject may enqueue a reply"
    );

    // The trailing filter-PERMITTED reject (a TCP RST the filter accepts) in
    // the SAME zone still finds a token on the fixed ordering.
    let (tcp_frame, tcp_meta, tcp_flow) = tcp_v4_syn();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &tcp_frame,
        tcp_meta,
        &tcp_flow,
        &mut counters,
    );
    assert!(
        sent,
        "a filter-PERMITTED reject must still get a token after a filtered flood (#5569)"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    assert_eq!(
        pipeline.pending_tx_local.len(),
        1,
        "the permitted RST must be enqueued"
    );
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #5569 invariant 2 (rate-limiting preserved): a reject that SURVIVES the
/// output-filter classification but whose per-zone token bucket is EXHAUSTED
/// is still dropped (rate-limited) and bumps the reject rate-limited counter
/// EXACTLY once — the reorder neither double-consumes the token nor drops the
/// rate limit for filter-admitted replies. No output filter is configured, so
/// the RST trivially survives classify; the zone bucket is drained empty, so
/// the token denies. The drop is attributed to the rate-limit counter, NOT the
/// output-filter counter.
#[test]
fn token_exhausted_reject_after_classify_survives_still_rate_limited_5569() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::ZoneLimiter;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, rate_limited_count, reset_bucket_for_test,
    };
    use crate::afxdp::types::FastMap;
    use std::sync::Arc;

    let _g = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);

    let zone_a = 4_321u16;
    let ifidx = 5i32;
    let mut ifindex_to_zone_id: FastMap<i32, u16> = FastMap::default();
    ifindex_to_zone_id.insert(ifidx, zone_a);
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    reject_buckets.insert(zone_a, Arc::new(ZoneLimiter::new()));
    let forwarding = ForwardingState {
        ifindex_to_zone_id,
        reject_buckets,
        ..ForwardingState::default()
    };

    // Drain zone A's limiter aggregate at a far-future epoch so the call
    // site's smaller monotonic `now` yields zero refill and the limiter stays
    // empty across the call (mirrors per_zone_reject_isolation_at_call_site_3618).
    // #9901 (F-074): aggregate tier directly — see the note above.
    let far_future = u64::MAX / 2;
    forwarding
        .generated_error_bucket(GeneratedErrorReason::Reject, zone_a)
        .expect("per-zone reject limiter")
        .drain_aggregate_for_test(far_future, 1000, 1000);
    let before = rate_limited_count(GeneratedErrorReason::Reject);

    let (frame, meta, flow) = tcp_v4_syn(); // RST survives classify (no filter)
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        !sent,
        "a token-exhausted reject must be dropped (rate-limiting preserved)"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert!(pipeline.pending_tx_local.is_empty());
    // The reply SURVIVED classify (no output filter), so it is a rate-limit
    // drop, NOT an output-filter drop.
    assert_eq!(
        counters.policy_reject_output_filter_drops, 0,
        "a filter-admitted reply must not count an output-filter drop"
    );
    assert_eq!(
        counters.policy_reject_rate_limit_drops, 1,
        "the token denial must bump the rate-limit drop exactly once (no double-consume)"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        before + 1,
        "the aggregate reject rate-limited counter must advance by exactly one"
    );
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}

/// #5569 invariant 3 (verdict threaded through): a reject that survives
/// classify AND whose token is allowed is enqueued carrying the SAME verdict
/// (cos_queue_id / dscp_rewrite) the output-filter classification produced —
/// the reorder threads the classify verdict through to the enqueue unchanged.
/// An output filter `then accept forwarding-class iperf-a` on the reply's
/// egress routes the generated RST to that class's queue (4).
#[test]
fn token_allowed_reject_enqueues_with_classify_verdict_5569() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            hardware_addr: "02:bf:72:00:00:05".into(),
            filter_output_v4: "fc-tcp".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![crate::FirewallFilterSnapshot {
            name: "fc-tcp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "fc-rst".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                forwarding_class: "iperf-a".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(crate::ClassOfServiceSnapshot {
            forwarding_classes: vec![
                crate::CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                crate::CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
            ],
            schedulers: vec![
                crate::CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                crate::CoSSchedulerSnapshot {
                    name: "a".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![crate::CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    crate::CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    crate::CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "a".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    let (frame, meta, flow) = tcp_v4_syn();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        &flow,
        &mut counters,
    );
    assert!(
        sent,
        "a classify-surviving, token-allowed reject must enqueue"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("reject RST request");
    assert_eq!(
        req.cos_queue_id,
        Some(4),
        "the enqueued RST must carry the classify verdict's cos_queue_id (iperf-a → q4)"
    );
    assert_eq!(
        req.dscp_rewrite, None,
        "no dscp rewrite configured → verdict.dscp_rewrite passed through as None"
    );
}

/// #12051 F2(a) / M9 fail-on-revert: the stamped-fabric TCP gate sits in the
/// shared `enqueue_reject_reply` choke, so a filter `then reject` on a stamped
/// fabric arrival is suppressed exactly like its policy sibling — no RST
/// queued, `filter_reject_sent` stays 0, and the filter log reports the
/// truthful DENY (per the #3615 `FilterAction::Reject` contract: a caller that
/// cannot synthesize the reject packet must not log that a reject was
/// generated). M9 (exempting `RejectReplySource::Filter` from the gate —
/// the shape the first 12051 commit's policy-wrapper guard had) enqueues the
/// RST and logs REJECT, turning every assertion below RED.
#[test]
fn stamped_fabric_filter_reject_suppresses_tcp_rst_and_logs_deny_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use super::filter::{PendingFilterLog, filter_terminal};
    use crate::afxdp::event_emit::FilterLogSource;
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let (mut frame, mut meta, flow) = tcp_v4_syn();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02]);
    meta.ingress_ifindex = 21;
    let (handle, rx) = unlimited_event_handle();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let forwarding = stamped_fabric_reject_forwarding();
    let mut counters = BatchCounters::default();
    let drop = filter_terminal(
        &mut pipeline,
        &forwarding,
        Some(&handle),
        21,
        &frame,
        meta,
        &flow,
        &mut counters,
        crate::filter::FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
        Some(PendingFilterLog {
            ingress_zone_id: 7,
            egress_zone_id: 0,
            filter_id: 23,
            term_id: 6,
            action: crate::filter::FilterAction::Reject(
                crate::filter::RejectMessage::ADMIN_PROHIBITED,
            ),
            source: FilterLogSource::Input,
            app_id: 0,
        }),
        123,
    );
    assert!(drop, "a filter reject terminal action drops the packet");
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "a stamped fabric filter arrival must not queue its synthetic source MAC as RST destination"
    );
    assert_eq!(counters.filter_reject_sent, 0);
    assert_eq!(counters.policy_reject_sent, 0);
    let event = rx
        .try_recv()
        .expect("filter-log event frame")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "a suppressed filter reject on the poll path must log DENY, not REJECT"
    );
}

/// #12051 F2(b) / M6+M6b fail-on-revert: the stamped-fabric gate runs BEFORE
/// the TX budget gate and the per-zone token gate, so a stamped-fabric TCP
/// reject flood consumes neither. Drives N stamped policy rejects against a
/// fresh per-zone Reject bucket: the aggregate TAT must not move (no token
/// spent), the observable `rate_limited_count(Reject)` must not advance
/// (no deny recorded), and neither budget-drop counter may bump. A trailing
/// unstamped reject in the SAME zone must still find a token — proving the
/// flood did not starve the bucket (the #3656 H11 shape). M6 (gate after the
/// token consume) moves the TAT / starves the trailing RST; M6b (gate after
/// the budget gate) spends budget on the flood instead.
#[test]
fn stamped_fabric_reject_flood_consumes_no_budget_or_token_12051() {
    use super::cookie_reply::SYN_COOKIE_REPLY_PENDING_RESERVE;
    use crate::afxdp::icmp_ratelimit::ZoneLimiter;
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, rate_limited_count, reset_bucket_for_test,
    };
    use crate::afxdp::types::FastMap;
    use std::sync::Arc;
    // The zone bucket is local, but hold the shared lock + reset the fallback
    // (mirrors per_zone_reject_isolation_at_call_site_3618) so a sibling
    // cannot perturb the fallback if any resolution falls through.
    let _g = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
    let zone_a = 4_321u16;
    let mut forwarding = stamped_fabric_reject_forwarding();
    forwarding.ifindex_to_zone_id.insert(21, zone_a);
    forwarding.ifindex_to_zone_id.insert(5, zone_a);
    let zone_bucket = Arc::new(ZoneLimiter::new());
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    reject_buckets.insert(zone_a, zone_bucket.clone());
    forwarding.reject_buckets = reject_buckets;
    let arrival_before = zone_bucket.aggregate_arrival_ns();
    let rate_limited_before = rate_limited_count(GeneratedErrorReason::Reject);
    let (mut stamped_frame, mut stamped_meta, stamped_flow) = tcp_v4_syn();
    stamped_frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02]);
    stamped_meta.ingress_ifindex = 21;
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
    );
    let mut counters = BatchCounters::default();
    // N exceeds the per-source burst and DEFAULT_BURST (1000). A reverted
    // gate-behind-token order would charge each iteration, causing rate-limit
    // drops and starving the trailing native control RST.
    const FLOOD: u64 = 1_500;
    for _ in 0..FLOOD {
        let sent = enqueue_policy_reject_reply(
            &mut pipeline,
            &forwarding,
            21,
            &stamped_frame,
            stamped_meta,
            &stamped_flow,
            &mut counters,
        );
        assert!(!sent, "every stamped-fabric TCP reject must suppress");
    }
    assert!(
        pipeline.pending_tx_local.is_empty(),
        "no stamped-fabric reject may enqueue a reply"
    );
    assert_eq!(counters.policy_reject_sent, 0);
    assert_eq!(
        counters.policy_reject_reply_budget_drops, 0,
        "a stamped-fabric reject must not spend TX budget (gate runs first)"
    );
    assert_eq!(
        counters.policy_reject_rate_limit_drops, 0,
        "a stamped-fabric reject must not spend a token (gate runs first)"
    );
    assert_eq!(
        zone_bucket.aggregate_arrival_ns(),
        arrival_before,
        "the stamped flood must not move the zone aggregate TAT (no token spent)"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        rate_limited_before,
        "the stamped flood must not record a rate-limited deny"
    );
    // The trailing NATIVE-ingress, unstamped reject in the same zone still
    // finds a token — proving the flood left the bucket full.
    let (native_frame, mut native_meta, native_flow) = tcp_v4_syn();
    native_meta.ingress_ifindex = 5;
    let sent = enqueue_policy_reject_reply(
        &mut pipeline,
        &forwarding,
        5,
        &native_frame,
        native_meta,
        &native_flow,
        &mut counters,
    );
    assert!(
        sent,
        "an unstamped reject must still get a token after a stamped flood"
    );
    assert_eq!(counters.policy_reject_sent, 1);
    assert_eq!(pipeline.pending_tx_local.len(), 1);

    // Isolate the TX-budget ordering control. With no TX budget, a stamped
    // reject must still stop at the shared gate: neither budget-drop counter
    // is truthful because the reply is known to be unreplyable on this ingress.
    // M6b (gate after the budget check) counts this as queue pressure.
    let budget_arrival_before = zone_bucket.aggregate_arrival_ns();
    let budget_rate_limited_before = rate_limited_count(GeneratedErrorReason::Reject);
    let mut no_budget_pipeline = tx_pipeline(0, 0);
    let mut budget_counters = BatchCounters::default();
    let sent = enqueue_policy_reject_reply(
        &mut no_budget_pipeline,
        &forwarding,
        21,
        &stamped_frame,
        stamped_meta,
        &stamped_flow,
        &mut budget_counters,
    );
    assert!(
        !sent,
        "a stamped reject must suppress with an empty TX budget"
    );
    assert!(no_budget_pipeline.pending_tx_local.is_empty());
    assert_eq!(
        budget_counters.policy_reject_reply_budget_drops, 0,
        "a stamped reject is not a TX-budget drop (the gate runs first)"
    );
    assert_eq!(
        budget_counters.policy_reject_rate_limit_drops, 0,
        "a stamped reject with no TX budget still must not consume a token"
    );
    assert_eq!(
        zone_bucket.aggregate_arrival_ns(),
        budget_arrival_before,
        "the zero-budget stamped reject must not move the token bucket"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        budget_rate_limited_before,
        "the zero-budget stamped reject must not record a rate-limited deny"
    );
    reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
}
