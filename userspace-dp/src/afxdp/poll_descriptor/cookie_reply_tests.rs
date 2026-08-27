use super::*;

fn dummy_tx_request() -> TxRequest {
    TxRequest {
        bytes: Vec::new(),
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 0,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    }
}

fn tx_pipeline(
    max_pending_tx: usize,
    free_frames: usize,
    pending_local: usize,
) -> WorkerTxPipeline {
    let mut pipeline = WorkerTxPipeline {
        free_tx_frames: (0..free_frames as u64).collect(),
        pending_tx_prepared: VecDeque::new(),
        pending_tx_local: VecDeque::new(),
        max_pending_tx,
        outstanding_tx: 0,
        pending_fill_frames: VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    };
    for _ in 0..pending_local {
        pipeline.pending_tx_local.push_back(dummy_tx_request());
    }
    pipeline
}

fn tcp_v4_syn_frame() -> (Vec<u8>, UserspaceDpMeta, SessionFlow) {
    let src_ip = std::net::Ipv4Addr::new(192, 0, 2, 10);
    let dst_ip = std::net::Ipv4Addr::new(198, 51, 100, 20);
    let src_port = 49152u16;
    let dst_port = 443u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6, 0x08, 0x00,
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00,
        0x00,
        0x00,
        0x01, // seq
        0x00,
        0x00,
        0x00,
        0x00, // ack
        0x60,
        TCP_FLAG_SYN,
        0xfa,
        0xf0, // data offset / flags / window
        0x00,
        0x00,
        0x00,
        0x00, // checksum + urgent
        0x02,
        0x04,
        0x05,
        0xb4, // MSS 1460
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
        payload_offset: 58,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
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
    };
    let flow = SessionFlow {
        src_ip: std::net::IpAddr::V4(src_ip),
        dst_ip: std::net::IpAddr::V4(dst_ip),
        forward_key: key,
    };
    (frame, meta, flow)
}

#[test]
fn syn_cookie_reply_budget_preserves_tx_batch_reserve() {
    let limit = SYN_COOKIE_REPLY_PENDING_RESERVE * 2;

    assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
        0,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        0,
    )));
    assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
        limit,
        SYN_COOKIE_REPLY_PENDING_RESERVE,
        0,
    )));
    assert!(syn_cookie_reply_budget_available(&tx_pipeline(
        limit,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        SYN_COOKIE_REPLY_PENDING_RESERVE - 1,
    )));
    assert!(!syn_cookie_reply_budget_available(&tx_pipeline(
        limit,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        SYN_COOKIE_REPLY_PENDING_RESERVE,
    )));
}

/// #2238: a generated SYN-cookie reply matching an egress OUTPUT filter
/// `then discard` (keyed on the reply's own TCP tuple) is NOT enqueued,
/// and the dedicated `syn_cookie_output_filter_drops` counter increments.
#[test]
fn syn_cookie_reply_dropped_by_egress_output_filter() {
    let (frame, meta, flow) = tcp_v4_syn_frame();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        0,
    );
    // Output filter on ifindex 5 discards TCP — the generated SYN-ACK is
    // TCP, so it is dropped.
    let filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "drop-tcp".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "drop-tcp".into(),
                action: "discard".into(),
                protocols: vec!["tcp".into()],
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: "drop-tcp".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    let mut counters = BatchCounters::default();
    let sent = enqueue_syn_cookie_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        Some(&flow),
        SynCookieReply::SynAck(SynCookieChallenge {
            cookie_isn: 0xaabb_ccdd,
            peer_mss: 1460,
        }),
        &mut counters,
    );
    assert!(
        !sent,
        "SYN-cookie reply dropped by egress output filter must not enqueue"
    );
    assert_eq!(counters.syn_cookie_syn_ack_sent, 0);
    assert_eq!(counters.syn_cookie_output_filter_drops, 1);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3035: build a forwarding state where the VLAN unit reth0.80 (logical
/// ifindex 202, parent 11, VID 80) carries a TCP-discard output filter and
/// the physical parent 11 carries NONE. Used to prove the SYN-cookie reply
/// is classified on the LOGICAL unit ifindex, not the physical bind port.
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

/// #3035 fail-on-revert: a SYN-cookie reply for a SYN arriving on a VLAN
/// sub-interface must be classified (output filter / CoS) on the LOGICAL
/// unit ifindex, not the physical bind port. The logical unit reth0.80
/// (202) carries a TCP-discard output filter; the physical parent 11 does
/// not. Driving the real enqueue with the physical bind ifindex 11 must
/// resolve the logical unit and drop the reply. If the classify reverts to
/// the physical `ifindex`, the parent has no filter and the reply is
/// wrongly admitted -> this test goes RED.
#[test]
fn syn_cookie_reply_classifies_on_logical_vlan_ifindex_3035() {
    let (frame, mut meta, flow) = tcp_v4_syn_frame();
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
    let now_ns = monotonic_nanos();
    assert!(
        classify_generated_reply(&forwarding, 202, &frame, now_ns).drop,
        "logical-keyed classify must hit the VLAN unit's drop-tcp filter"
    );
    assert!(
        !classify_generated_reply(&forwarding, 11, &frame, now_ns).drop,
        "physical-parent-keyed classify has no filter and would wrongly admit"
    );

    // Drive the real enqueue with the PHYSICAL bind ifindex 11.
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        0,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_syn_cookie_reply(
        &mut pipeline,
        &forwarding,
        11, // physical parent bind ifindex
        &frame,
        meta,
        Some(&flow),
        SynCookieReply::SynAck(SynCookieChallenge {
            cookie_isn: 0xaabb_ccdd,
            peer_mss: 1460,
        }),
        &mut counters,
    );
    assert!(
        !sent,
        "SYN-cookie reply on a VLAN unit must be dropped by the unit's output filter"
    );
    assert_eq!(counters.syn_cookie_output_filter_drops, 1);
    assert_eq!(counters.syn_cookie_syn_ack_sent, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
    assert!(pipeline.pending_tx_local.is_empty());
}

/// #3035 non-VLAN regression: on an untagged interface the logical unit IS
/// the bind ifindex (no (parent, vlan) mapping), so `resolve_ingress_-
/// logical_ifindex` returns None and the classify falls back to the
/// physical ifindex unchanged — behavior is byte-identical to pre-#3035.
#[test]
fn syn_cookie_reply_non_vlan_classify_unchanged_3035() {
    let (frame, meta, flow) = tcp_v4_syn_frame(); // ingress_ifindex 5, vlan 0
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
        0,
    );
    let mut counters = BatchCounters::default();
    let sent = enqueue_syn_cookie_reply(
        &mut pipeline,
        &forwarding,
        5, // logical == physical for an untagged port
        &frame,
        meta,
        Some(&flow),
        SynCookieReply::SynAck(SynCookieChallenge {
            cookie_isn: 0xaabb_ccdd,
            peer_mss: 1460,
        }),
        &mut counters,
    );
    assert!(
        !sent,
        "untagged interface still applies its own output filter (unchanged)"
    );
    assert_eq!(counters.syn_cookie_output_filter_drops, 1);
    assert_eq!(counters.syn_cookie_syn_ack_sent, 0);
}

#[test]
fn syn_cookie_reply_enqueues_host_generated_frame_without_transit_policy_metadata() {
    let (frame, meta, flow) = tcp_v4_syn_frame();
    let mut pipeline = tx_pipeline(
        SYN_COOKIE_REPLY_PENDING_RESERVE * 2,
        SYN_COOKIE_REPLY_PENDING_RESERVE + 1,
        0,
    );
    let mut counters = BatchCounters::default();
    let forwarding = ForwardingState::default();

    assert!(enqueue_syn_cookie_reply(
        &mut pipeline,
        &forwarding,
        5,
        &frame,
        meta,
        Some(&flow),
        SynCookieReply::SynAck(SynCookieChallenge {
            cookie_isn: 0xaabb_ccdd,
            peer_mss: 1460,
        }),
        &mut counters,
    ));

    let req = pipeline
        .pending_tx_local
        .pop_front()
        .expect("SYN-cookie reply request");
    assert_eq!(req.egress_ifindex, 5);
    assert_eq!(req.cos_queue_id, None);
    assert_eq!(req.dscp_rewrite, None);
    assert!(!req.mirror_clone);
    assert_eq!(req.flow_key, Some(flow.forward_key));
    assert_eq!(counters.syn_cookie_syn_ack_sent, 1);
    assert_eq!(counters.syn_cookie_reply_budget_drops, 0);
}
