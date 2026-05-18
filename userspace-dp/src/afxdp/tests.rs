use super::test_fixtures::*;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, PolicyRuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot,
    ThreeColorPolicerSnapshot,
};

#[test]
fn mlx5_keeps_umem_owner_bind_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("mlx5_core")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("mlx5_core"), AfXdpBindStrategy::UmemOwnerSocket),
        None
    );
}

#[test]
fn virtio_uses_auto_mode_umem_owner_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("virtio_net")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("virtio_net"), AfXdpBindStrategy::UmemOwnerSocket,),
        None
    );
    assert_eq!(
        binder_for_strategy(AfXdpBindStrategy::UmemOwnerSocket),
        AfXdpBinder::Umem
    );
    assert_eq!(bind_flag_candidates_for_driver(Some("virtio_net")), &[0]);
    assert_eq!(
        bind_flag_candidates_for_driver(Some("mlx5_core")),
        &[XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY]
    );
}

#[test]
fn shared_umem_socket_roles_use_kernel_legal_bind_flags() {
    let mut info = IfInfo::invalid();
    info.set_queue(0);

    assert_eq!(
        bind_flag_candidates_for_socket_role(&info, Some("mlx5_core"), XskSocketRole::SharedOwner),
        &[XSK_BIND_FLAGS_ZEROCOPY]
    );

    let secondary = bind_flag_candidates_for_socket_role(
        &info,
        Some("mlx5_core"),
        XskSocketRole::SharedSecondary,
    );
    assert_eq!(secondary, &[SocketConfig::XDP_BIND_SHARED_UMEM]);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_COPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_ZEROCOPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_NEED_WAKEUP, 0);
    assert_eq!(describe_bind_flags(secondary[0]), "shared-umem");
}

#[test]
fn shared_umem_group_key_is_same_device_mlx5_only() {
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("mlx5_core"),
            Some("/sys/devices/pci0000:00/0000:08:00.0")
        ),
        Some("mlx5:/sys/devices/pci0000:00/0000:08:00.0".to_string())
    );
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("virtio_net"),
            Some("/sys/devices/pci0000:00/0000:00:07.0")
        ),
        None
    );
    assert_eq!(
        shared_umem_group_key_for_device(Some("mlx5_core"), None),
        None
    );
}

#[test]
fn split_owner_fabric_redirect_skips_local_reverse_placeholder() {
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };

    assert!(!should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}

#[test]
fn fabric_redirect_reply_from_real_fabric_ingress_keeps_local_reverse() {
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };

    assert!(should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}

#[test]
fn cloned_worker_umem_shares_allocation_identity() {
    let shared = match WorkerUmem::new(64) {
        Ok(shared) => shared,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    let shared_clone = shared.clone();
    let private = match WorkerUmem::new(64) {
        Ok(private) => private,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    assert!(shared.shares_allocation_with(&shared_clone));
    assert!(!shared.shares_allocation_with(&private));
}

#[test]
fn worker_binding_lookup_prefers_same_queue_binding() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_if_queue.insert((5, 0), 0);
    lookup.by_if_queue.insert((5, 1), 1);
    lookup.first_by_if.insert(5, 0);
    lookup.all_by_if.insert(5, vec![0, 1]);

    assert_eq!(lookup.target_index(2, 7, 1, 5), Some(1));
    assert_eq!(lookup.target_index(2, 7, 3, 5), Some(0));
    assert_eq!(lookup.target_index(2, 5, 1, 5), Some(2));
}

#[test]
fn worker_binding_lookup_hashes_fabric_target_across_queues() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.all_by_if.insert(5, vec![10, 11, 12, 13]);

    let indices = [
        lookup.fabric_target_index(5, 0),
        lookup.fabric_target_index(5, 1),
        lookup.fabric_target_index(5, 2),
        lookup.fabric_target_index(5, 3),
    ];
    assert_eq!(indices, [Some(10), Some(11), Some(12), Some(13)]);
}

#[test]
fn worker_binding_lookup_resolves_slot_index() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(11, 3);
    assert_eq!(lookup.slot_index(11), Some(3));
    assert_eq!(lookup.slot_index(99), None);
}

#[test]
fn build_live_forward_request_from_frame_uses_precomputed_hints() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let desc = XdpDesc {
        addr: 0,
        len: 0,
        options: 0,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
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
        nat: NatDecision::default(),
    };
    let hints = PendingForwardHints {
        expected_ports: Some((12345, 5201)),
        target_binding_index: Some(9),
    };

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        desc,
        &[],
        meta,
        &decision,
        &ForwardingState::default(),
        None,
        None,
        false,
        0,
        Some(hints),
        None,
    )
    .expect("request");

    assert_eq!(req.expected_ports, hints.expected_ports);
    assert_eq!(req.target_binding_index, hints.target_binding_index);
    assert_eq!(req.target_ifindex, 11);
}

#[test]
fn icmp_reverse_key_keeps_identifier_position() {
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let reverse = flow.reverse_key_with_nat(NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    });
    assert_eq!(reverse.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(reverse.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(reverse.src_port, 0x1234);
    assert_eq!(reverse.dst_port, 0);
}

#[test]
fn synced_replica_entry_keeps_peer_synced_entries_promotable() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert!(replica.origin.is_peer_synced());
    assert!(replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}

#[test]
fn synced_replica_entry_marks_local_entries_worker_local() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert_eq!(replica.origin, SessionOrigin::WorkerLocalImport);
    assert!(replica.origin.is_peer_synced());
    assert!(!replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}

#[test]
fn reconcile_stop_preserves_shared_synced_sessions() {
    let mut coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );

    coordinator.stop_inner(false);

    let preserved = coordinator.snapshot_shared_session_entries();
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].key, entry.key);
    assert_eq!(preserved[0].decision, entry.decision);

    coordinator.stop();
    assert!(coordinator.snapshot_shared_session_entries().is_empty());
}

#[test]
fn replay_synced_sessions_requeues_preserved_entries_for_new_workers() {
    let coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let worker_command_queues = BTreeMap::from([
        (0u32, Arc::new(Mutex::new(VecDeque::new()))),
        (1u32, Arc::new(Mutex::new(VecDeque::new()))),
    ]);

    let replayed = coordinator.replay_synced_sessions(&[entry.clone()], &worker_command_queues, -1);
    assert_eq!(replayed, 1);

    for commands in worker_command_queues.values() {
        let pending = commands.lock().expect("worker command queue");
        assert_eq!(pending.len(), 1);
        match pending.front().expect("queued command") {
            WorkerCommand::UpsertSynced(replayed_entry) => {
                assert_eq!(replayed_entry.key, entry.key);
                assert!(replayed_entry.origin.is_peer_synced());
            }
            other => panic!("unexpected command queued during replay: {other:?}"),
        }
    }
}

#[test]
fn resolution_target_uses_rewritten_destination_for_reverse_dnat() {
    let flow = SessionFlow {
        src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
        dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
            dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(
                "2001:559:8585:ef00::100".parse().expect("next hop"),
            )),
            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))),
            ..NatDecision::default()
        },
    };
    assert_eq!(
        resolution_target_for_session(&flow, decision),
        IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))
    );
}

#[test]
fn session_resolution_falls_back_to_cached_neighbor_on_miss() {
    let mut state = build_forwarding_state(&nat_snapshot());
    state.neighbors.clear();
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        decision,
    );
    let expected_src = state
        .egress
        .get(&12)
        .map(|egress| egress.src_mac)
        .expect("egress src mac");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 11);
    assert_eq!(resolved.neighbor_mac, decision.resolution.neighbor_mac);
    assert_eq!(resolved.src_mac, Some(expected_src));
    assert_eq!(resolved.tx_vlan_id, 80);
}

#[test]
fn build_forwarded_frame_rewrites_l2_and_decrements_ttl() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

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
        &SessionDecision {
            resolution,
            nat: NatDecision::default(),
        },
        &state,
        None,
    )
    .expect("forwarded frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(out[22], 63);
}

#[test]
fn rewrite_forwarded_frame_in_place_reuses_rx_frame() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

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
            resolution,
            nat: NatDecision::default(),
        },
        false,
        None,
    )
    .expect("in-place forward");
    let out = area.slice(rewrite_result.offset as usize, rewrite_result.len as usize).expect("rewritten frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(out[22], 63);
}

#[test]
fn build_forwarded_frame_uses_fabric_header_without_nat() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 61, 100, 172, 16, 80,
        200, 8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

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
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        &state,
        None,
    )
    .expect("fabric frame");
    assert_eq!(&out[0..6], &[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[10, 0, 61, 100]);
    assert_eq!(out[22], 63);
}

// --- Static NAT integration tests ---

#[test]
fn static_nat_external_ip_recognized_as_local() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // The external IP 203.0.113.10 should be in local_v4 so traffic
    // destined to it is recognized by the firewall.
    assert!(
        state
            .local_v4
            .contains(&"203.0.113.10".parse::<Ipv4Addr>().unwrap()),
        "static NAT external IP must be in local_v4"
    );
}

#[test]
fn static_nat_dnat_routes_to_internal_ip() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate inbound: packet from 198.51.100.1 -> 203.0.113.10
    // The static NAT DNAT should match and the resolution should route
    // to the internal host 192.168.1.10 (on trust interface ifindex=5).
    let dnat = state
        .static_nat
        .match_dnat("203.0.113.10".parse().unwrap(), "untrust");
    assert!(dnat.is_some(), "DNAT must match external IP from untrust");
    let dnat = dnat.unwrap();
    assert_eq!(
        dnat.rewrite_dst,
        Some("192.168.1.10".parse::<IpAddr>().unwrap())
    );

    // After DNAT translation, resolution target is internal IP
    let internal_ip: IpAddr = "192.168.1.10".parse().unwrap();
    let resolution =
        lookup_forwarding_resolution_with_dynamic(&state, &Default::default(), internal_ip);
    // Should resolve to trust interface (ifindex 5) via connected route
    assert_eq!(resolution.egress_ifindex, 5);
}

#[test]
fn static_nat_snat_rewrites_outbound_source() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate outbound: packet from 192.168.1.10 -> 198.51.100.1
    // coming from trust zone. Static NAT SNAT should rewrite src
    // to external IP 203.0.113.10.
    // SNAT does not check from_zone -- internal IP match is sufficient.
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(
        snat.is_some(),
        "SNAT should match internal IP regardless of zone"
    );
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn static_nat_snat_matches_when_zone_is_empty() {
    // Create a snapshot where from_zone is empty (matches any zone)
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "web-server".to_string(),
        from_zone: String::new(), // matches any zone
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }];
    let state = build_forwarding_state(&snapshot);

    // Now SNAT should match from any zone
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    let snat = snat.unwrap();
    assert_eq!(
        snat.rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
    assert!(snat.rewrite_dst.is_none());
}

#[test]
fn static_nat_takes_priority_over_interface_snat() {
    // Create snapshot with both static NAT and interface SNAT
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "static-web".to_string(),
        from_zone: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
    }];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "interface-snat".to_string(),
        from_zone: "trust".to_string(),
        to_zone: "untrust".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    // For src=192.168.1.10, static NAT should match first
    let static_match = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(
        static_match.is_some(),
        "static NAT should match internal IP"
    );
    assert_eq!(
        static_match.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn static_nat_v6_dnat_and_snat() {
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "v6-server".to_string(),
        from_zone: String::new(),
        external_ip: "2001:db8::10".to_string(),
        internal_ip: "fd00::10".to_string(),
    }];
    // Add v6 addresses to interfaces
    snapshot.interfaces[0]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "fd00::1/64".to_string(),
            scope: 0,
        });
    snapshot.interfaces[1]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8::1/64".to_string(),
            scope: 0,
        });
    let state = build_forwarding_state(&snapshot);

    // External v6 IP should be in local_v6
    assert!(
        state
            .local_v6
            .contains(&"2001:db8::10".parse::<Ipv6Addr>().unwrap())
    );

    // DNAT match
    let dnat = state
        .static_nat
        .match_dnat("2001:db8::10".parse().unwrap(), "any-zone");
    assert!(dnat.is_some());
    assert_eq!(
        dnat.unwrap().rewrite_dst,
        Some("fd00::10".parse::<IpAddr>().unwrap())
    );

    // SNAT match
    let snat = state
        .static_nat
        .match_snat("fd00::10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("2001:db8::10".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn post_dnat_source_nat_matches_translated_destination() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "twice-snat".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        destination_addresses: vec!["10.0.61.102/32".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "172.16.80.8".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
    }];
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "allow-inbound".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    });

    let state = build_forwarding_state(&snapshot);
    assert!(
        state
            .local_v4
            .contains(&"172.16.80.8".parse::<Ipv4Addr>().unwrap())
    );

    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 54321,
            dst_port: 443,
        },
    };
    let dnat = state
        .dnat_table
        .lookup(PROTO_TCP, flow.dst_ip, 443, "wan")
        .expect("dnat");
    assert_eq!(
        dnat.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(dnat.rewrite_dst_port, Some(8443));

    let translated_flow = flow.with_destination(dnat.rewrite_dst.unwrap());
    let snat = match_source_nat_for_flow(&state, "wan", "lan", 24, &translated_flow)
        .expect("snat after dnat");
    assert_eq!(
        snat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );

    let merged = dnat.merge(snat);
    assert_eq!(
        merged.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );
    assert_eq!(
        merged.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(merged.rewrite_dst_port, Some(8443));
}

#[test]
fn is_icmp_error_identifies_v4_types() {
    // ICMPv4 error types
    assert!(is_icmp_error(PROTO_ICMP, 3)); // Destination Unreachable
    assert!(is_icmp_error(PROTO_ICMP, 11)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMP, 12)); // Parameter Problem
    // Non-error types
    assert!(!is_icmp_error(PROTO_ICMP, 0)); // Echo Reply
    assert!(!is_icmp_error(PROTO_ICMP, 8)); // Echo Request
}

#[test]
fn is_icmp_error_identifies_v6_types() {
    // ICMPv6 error types
    assert!(is_icmp_error(PROTO_ICMPV6, 1)); // Destination Unreachable
    assert!(is_icmp_error(PROTO_ICMPV6, 2)); // Packet Too Big
    assert!(is_icmp_error(PROTO_ICMPV6, 3)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMPV6, 4)); // Parameter Problem
    // Non-error types
    assert!(!is_icmp_error(PROTO_ICMPV6, 128)); // Echo Request
    assert!(!is_icmp_error(PROTO_ICMPV6, 129)); // Echo Reply
}

#[test]
fn is_icmp_error_rejects_non_icmp_protocols() {
    assert!(!is_icmp_error(PROTO_TCP, 3));
    assert!(!is_icmp_error(PROTO_UDP, 3));
}

#[test]
fn forwarding_state_includes_session_timeouts() {
    let snapshot = nat_snapshot();
    let state = build_forwarding_state(&snapshot);
    // Default timeouts when snapshot has 0 values
    assert_eq!(state.session_timeouts.tcp_established_ns, 300_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 60_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 60_000_000_000);
}

#[test]
fn forwarding_state_custom_session_timeouts() {
    let mut snapshot = nat_snapshot();
    snapshot.flow.tcp_session_timeout = 120;
    snapshot.flow.udp_session_timeout = 30;
    snapshot.flow.icmp_session_timeout = 5;
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.session_timeouts.tcp_established_ns, 120_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 30_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 5_000_000_000);
}

#[test]
fn forwarding_state_allow_embedded_icmp_wired() {
    let mut snapshot = nat_snapshot();
    assert!(!build_forwarding_state(&snapshot).allow_embedded_icmp);
    snapshot.flow.allow_embedded_icmp = true;
    assert!(build_forwarding_state(&snapshot).allow_embedded_icmp);
}

fn build_icmp_echo_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

fn build_icmp_echo_frame_v6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, hop_limit]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16_ipv6(src, dst, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}

#[test]
fn packet_ttl_would_expire_identifies_v4_and_v6() {
    let frame_v4 =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 1);
    let meta_v4 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v4, meta_v4), Some(true));

    let frame_v6 = build_icmp_echo_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
        2,
    );
    let meta_v6 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v6, meta_v6), Some(false));
}

#[test]
fn build_local_time_exceeded_request_returns_prebuilt_forward_for_ttl_expiry() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
    )
    .expect("ttl-expiring session/flow-cache hit should enqueue local TE");

    assert_eq!(request.target_ifindex, 5);
    assert_eq!(request.ingress_queue_id, ingress_ident.queue_id);
    assert_eq!(request.desc.addr, desc.addr);
    assert_eq!(request.flow_key.as_ref(), Some(&flow.forward_key));
    assert!(request.cos_tx_selection_resolved);
    assert!(matches!(request.frame, PendingForwardFrame::Prebuilt(_)));
}

#[test]
fn build_local_time_exceeded_request_meters_icmp_flow_key() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let filter_state = crate::filter::parse_filter_state_with_three_color(
        &[FirewallFilterSnapshot {
            name: "policed-icmp".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter-icmp".into(),
                action: "accept".into(),
                protocols: vec!["icmp".into()],
                policer: "icmp-pol".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[ThreeColorPolicerSnapshot {
            name: "icmp-pol".into(),
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
            ifindex: 5,
            filter_input_v4: "policed-icmp".into(),
            ..Default::default()
        }],
        "policed-icmp",
        "",
    );
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
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
    );

    assert!(
        request.is_none(),
        "red-drop policer should reject the generated ICMP response"
    );
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn build_local_time_exceeded_request_skips_fabric_ingress_packets() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        meta_flags: FABRIC_INGRESS_FLAG,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 8192,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("fab0"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_FABRIC_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
    );

    assert!(
        request.is_none(),
        "fabric-ingress packets should not enqueue local Time Exceeded"
    );
}

#[test]
fn build_local_time_exceeded_v4_quotes_original_packet() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let out =
        build_local_time_exceeded_v4(&frame, meta, 5, &forwarding).expect("build local IPv4 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(
        Ipv4Addr::new(out[26], out[27], out[28], out[29]),
        Ipv4Addr::new(10, 0, 61, 1)
    );
    assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
    assert_eq!(out[34], 11);
    assert_eq!(out[35], 0);
    let quoted_ip_start = 42;
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 12],
            out[quoted_ip_start + 13],
            out[quoted_ip_start + 14],
            out[quoted_ip_start + 15]
        ),
        client_ip
    );
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 16],
            out[quoted_ip_start + 17],
            out[quoted_ip_start + 18],
            out[quoted_ip_start + 19]
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 8], 1);
}

#[test]
fn build_local_time_exceeded_v6_quotes_original_packet() {
    let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
        },
    );
    let out =
        build_local_time_exceeded_v6(&frame, meta, 5, &forwarding).expect("build local IPv6 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[22..38]).unwrap()),
        "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[38..54]).unwrap()),
        client_ip
    );
    assert_eq!(out[54], 3);
    assert_eq!(out[55], 0);
    let quoted_ip_start = 62;
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 8..quoted_ip_start + 24]).unwrap()
        ),
        client_ip
    );
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 24..quoted_ip_start + 40]).unwrap()
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 7], 1);
}

// --- ICMP error NAT reversal tests ---

/// Build an IPv4 ICMP Time Exceeded frame with an embedded TCP packet.
/// outer: [Eth][IP: src=router_ip, dst=snat_ip][ICMP type=11 code=0]
///        [Embedded: IP src=snat_ip, dst=server_ip, proto=TCP][TCP src=snat_port, dst=server_port]
fn build_icmp_te_frame_v4(
    router_ip: Ipv4Addr,
    snat_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], // dst MAC
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56], // src MAC
        0,
        0x0800,
    );
    let ip_start = frame.len(); // 14

    // Build embedded IP+L4 first to know sizes
    let mut embedded = Vec::new();
    // Embedded IPv4 header (20 bytes, IHL=5)
    embedded.extend_from_slice(&[
        0x45,
        0x00,
        0x00,
        0x00, // version/IHL, DSCP, total length (fill later)
        0x00,
        0x01,
        0x00,
        0x00, // ID, flags, fragment offset
        64,
        embedded_proto,
        0x00,
        0x00, // TTL, protocol, checksum (fill later)
    ]);
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq/other
    } else if embedded_proto == PROTO_ICMP {
        embedded.extend_from_slice(&[8, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }
    // Fill embedded IP total length
    let emb_total = embedded.len() as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    // Compute embedded IP checksum
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // Outer ICMP header: type=11 (Time Exceeded), code=0, checksum, unused
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[11, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type, code, csum, unused
    icmp.extend_from_slice(&embedded);
    // Compute ICMP checksum
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IPv4 header
    let outer_total_len = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[
        0x45, 0x00, // version/IHL, DSCP
    ]);
    frame.extend_from_slice(&outer_total_len.to_be_bytes()); // total length
    frame.extend_from_slice(&[
        0x00, 0x02, 0x00, 0x00, // ID, flags
        64, PROTO_ICMP, 0x00, 0x00, // TTL, protocol, checksum
    ]);
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute outer IP checksum
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // Append ICMP payload
    frame.extend_from_slice(&icmp);

    frame
}

#[test]
fn icmp_te_nat_reversal_v4_rewrites_outer_dst_and_embedded_src() {
    // Scenario: client 10.0.61.102 -> server 1.1.1.1, SNAT'd to 172.16.80.8
    // Router 10.0.0.1 sends ICMP Time Exceeded back to 172.16.80.8
    // NAT reversal: outer dst 172.16.80.8 -> 10.0.61.102,
    //               embedded src 172.16.80.8 -> 10.0.61.102
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]); // src MAC
    assert_eq!(&result[12..14], &[0x08, 0x00]); // ethertype IPv4

    // Verify outer IP dst is now the original client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(
        outer_dst, client_ip,
        "outer IP dst should be original client"
    );

    // Verify outer IP src is still the router
    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, router_ip, "outer IP src should remain router");

    // Verify embedded IP src is now the original client
    // Embedded IP starts at: eth(14) + outer_ip(20) + icmp_hdr(8) = 42
    let emb_ip_start = 42;
    let emb_src = Ipv4Addr::new(
        result[emb_ip_start + 12],
        result[emb_ip_start + 13],
        result[emb_ip_start + 14],
        result[emb_ip_start + 15],
    );
    assert_eq!(emb_src, client_ip, "embedded src should be original client");

    // Verify embedded dst is still the server
    let emb_dst = Ipv4Addr::new(
        result[emb_ip_start + 16],
        result[emb_ip_start + 17],
        result[emb_ip_start + 18],
        result[emb_ip_start + 19],
    );
    assert_eq!(emb_dst, server_ip, "embedded dst should remain server");

    // Verify embedded TCP src port is now the original client port
    let emb_l4_start = emb_ip_start + 20; // IHL=5, so 20 bytes
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify outer IP checksum is valid
    let outer_ihl = ((result[14] & 0x0f) as usize) * 4;
    let ip_csum_check = checksum16(&result[14..14 + outer_ihl]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid (0)");

    // Verify outer ICMP checksum is valid
    let icmp_start = 14 + outer_ihl;
    let icmp_csum_check = checksum16(&result[icmp_start..]);
    assert_eq!(
        icmp_csum_check, 0,
        "outer ICMP checksum should be valid (0)"
    );

    // Verify embedded IP checksum is valid
    let emb_ihl = ((result[emb_ip_start] & 0x0f) as usize) * 4;
    let emb_ip_csum_check = checksum16(&result[emb_ip_start..emb_ip_start + emb_ihl]);
    assert_eq!(
        emb_ip_csum_check, 0,
        "embedded IP checksum should be valid (0)"
    );
}

#[test]
fn icmp_te_nat_reversal_v4_with_port_snat() {
    // Same as above but verifying UDP port reversal specifically
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 50000;
    let client_port: u16 = 5353;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 53, PROTO_UDP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify embedded UDP src port is now the original client port
    let emb_ip_start = 42; // eth(14) + outer_ip(20) + icmp_hdr(8)
    let emb_l4_start = emb_ip_start + 20;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded UDP src port should be original"
    );

    // Verify all checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid");
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0, "outer ICMP checksum should be valid");
}

#[test]
fn icmp_dest_unreach_nat_reversal_v4() {
    // ICMP Destination Unreachable (type 3, code 1) with embedded TCP
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // Build ICMP Destination Unreachable frame manually
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    let ip_start = frame.len();

    // Embedded IP+TCP
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    embedded.extend_from_slice(&snat_ip.octets());
    embedded.extend_from_slice(&server_ip.octets());
    let emb_total = (20 + 8) as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    embedded.extend_from_slice(&40000u16.to_be_bytes()); // src port (SNAT'd)
    embedded.extend_from_slice(&80u16.to_be_bytes()); // dst port
    embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // ICMP type=3 (Dest Unreach), code=1 (Host Unreachable)
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[3, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp.extend_from_slice(&embedded);
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IP
    let outer_total = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&outer_total.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&snat_ip.octets());
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&icmp);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: 12345,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify outer IP dst is client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(outer_dst, client_ip);

    // Verify ICMP type/code NOT modified
    assert_eq!(result[34], 3, "ICMP type must remain Dest Unreach");
    assert_eq!(result[35], 1, "ICMP code must remain Host Unreachable");

    // Verify checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0);
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0);
}

/// Build an IPv6 ICMPv6 Time Exceeded frame with an embedded TCP packet.
fn build_icmpv6_te_frame(
    router_ip: Ipv6Addr,
    snat_ip: Ipv6Addr,
    server_ip: Ipv6Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );

    // Build embedded IPv6+L4
    let mut embedded = Vec::new();
    // IPv6 header (40 bytes)
    embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version, traffic class, flow label
    let emb_payload_len = 8u16; // 8 bytes of L4
    embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
    embedded.push(embedded_proto); // next header
    embedded.push(64); // hop limit
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    } else if embedded_proto == PROTO_ICMPV6 {
        embedded.extend_from_slice(&[128, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }

    // ICMPv6 header: type=3 (Time Exceeded), code=0, checksum, unused
    let mut icmp6 = Vec::new();
    icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp6.extend_from_slice(&embedded);

    // Outer IPv6 header
    let payload_len = icmp6.len() as u16;
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_ICMPV6); // next header
    frame.push(64); // hop limit
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute ICMPv6 checksum (covers pseudo-header)
    icmp6[2..4].copy_from_slice(&[0, 0]);
    let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

    frame.extend_from_slice(&icmp6);
    frame
}

#[test]
fn icmpv6_te_nat_reversal_v6_rewrites_outer_dst_and_embedded_src() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmpv6_te_frame(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_ip),
        original_src_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame");

    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[12..14], &[0x86, 0xdd]); // ethertype IPv6

    // Verify outer IPv6 dst is now the original client (bytes 24..40 in IPv6)
    let outer_dst_bytes: [u8; 16] = result[38..54].try_into().unwrap();
    let outer_dst = Ipv6Addr::from(outer_dst_bytes);
    assert_eq!(
        outer_dst, client_ip,
        "outer IPv6 dst should be original client"
    );

    // Verify outer IPv6 src is still the router (bytes 8..24 in IPv6)
    let outer_src_bytes: [u8; 16] = result[22..38].try_into().unwrap();
    let outer_src = Ipv6Addr::from(outer_src_bytes);
    assert_eq!(outer_src, router_ip, "outer IPv6 src should remain router");

    // Verify embedded IPv6 src is now the original client
    // Embedded IPv6 starts at: eth(14) + outer_ipv6(40) + icmpv6_hdr(8) = 62
    let emb_ip_start = 62;
    let emb_src_bytes: [u8; 16] = result[emb_ip_start + 8..emb_ip_start + 24]
        .try_into()
        .unwrap();
    let emb_src = Ipv6Addr::from(emb_src_bytes);
    assert_eq!(
        emb_src, client_ip,
        "embedded IPv6 src should be original client"
    );

    // Verify embedded dst is still the server
    let emb_dst_bytes: [u8; 16] = result[emb_ip_start + 24..emb_ip_start + 40]
        .try_into()
        .unwrap();
    let emb_dst = Ipv6Addr::from(emb_dst_bytes);
    assert_eq!(emb_dst, server_ip, "embedded IPv6 dst should remain server");

    // Verify embedded TCP src port
    let emb_l4_start = emb_ip_start + 40;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify ICMPv6 checksum is valid
    let icmp6_start = 54; // eth(14) + ipv6(40)
    let src_v6 = Ipv6Addr::from(outer_src_bytes);
    let dst_v6 = Ipv6Addr::from(outer_dst_bytes);
    let icmp6_data = &result[icmp6_start..];
    // Zero checksum and recompute
    let mut icmp6_copy = icmp6_data.to_vec();
    icmp6_copy[2] = 0;
    icmp6_copy[3] = 0;
    let expected_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, &icmp6_copy);
    let actual_csum = u16::from_be_bytes([icmp6_data[2], icmp6_data[3]]);
    assert_eq!(
        actual_csum, expected_csum,
        "ICMPv6 checksum should be valid"
    );
}

#[test]
fn icmpv6_te_nptv6_reverse_lookup_restores_internal_client() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(internal_client)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(external_client)),
            rewrite_dst: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: false,
            nptv6: true,
        },
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6(internal_client),
            dst_ip: IpAddr::V6(server_ip),
            src_port: echo_id,
            dst_port: 0,
        },
        decision,
        metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(icmp_match.original_src_port, echo_id);
    assert!(icmp_match.nat.nptv6);
    assert_eq!(
        icmp_match.nat.rewrite_src,
        Some(IpAddr::V6(external_client))
    );
}

#[test]
fn icmpv6_te_prefers_reverse_session_resolution_for_client_return_path() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let forward_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: IpAddr::V6(internal_client),
        dst_ip: IpAddr::V6(server_ip),
        src_port: echo_id,
        dst_port: 0,
    };
    let forward_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(server_ip)),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(external_client)),
            rewrite_dst: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            nat64: false,
            nptv6: true,
        },
    };
    let forward_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };

    let reverse_key = reverse_session_key(&forward_key, forward_decision.nat);
    let reverse_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(internal_client)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
        tx_vlan_id: 0,
    };
    let reverse_decision = SessionDecision {
        resolution: reverse_resolution,
        nat: forward_decision.nat.reverse(
            forward_key.src_ip,
            forward_key.dst_ip,
            forward_key.src_port,
            forward_key.dst_port,
        ),
    };
    let reverse_metadata = SessionMetadata {
        ingress_zone: TEST_WAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
    };

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        forward_key.clone(),
        forward_decision,
        forward_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));
    assert!(sessions.install_with_protocol(
        reverse_key,
        reverse_decision,
        reverse_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(
        icmp_match.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn no_match_embedded_icmp_returns_none() {
    // An ICMP error with no matching session should return None
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, 40000, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    // Don't install any sessions
    let result = try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000);
    assert!(
        result.is_none(),
        "should return None when no session matches"
    );
}

#[test]
fn embedded_icmp_nat_match_uses_shared_nat_session_for_ipv4() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("shared NAT session should match embedded ICMP");

    assert_eq!(icmp_match.original_src, IpAddr::V4(client_ip));
    assert_eq!(icmp_match.original_src_port, client_port);
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn embedded_icmp_nat_match_ignores_non_error_echo() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    let forwarding = ForwardingState::default();
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let result = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    );
    assert!(
        result.is_none(),
        "non-error ICMP echo should not trigger embedded NAT reversal"
    );
}

#[test]
fn maybe_reinject_slow_path_ignores_forward_candidate_disposition() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        decision,
        &recent_exceptions,
    &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().expect("exceptions").is_empty());
}

#[test]
fn maybe_reinject_slow_path_records_extract_failure_for_invalid_desc() {
    let area = MmapArea::new(128).expect("mmap");
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    // Addr beyond the registered UMEM length forces an extract failure.
    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 512,
            len: 96,
            options: 0,
        },
        meta,
        decision,
        &recent_exceptions,
    &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_extract_failed");
    assert_eq!(last.packet_length, 96);
}

#[test]
fn maybe_reinject_slow_path_from_frame_records_unavailable() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    maybe_reinject_slow_path_from_frame(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &frame,
        meta,
        decision,
        &recent_exceptions,
        "forward_build_slow_path",
    &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_unavailable");
    assert_eq!(last.ifindex, 6);
}

#[test]
fn handle_forward_build_failure_records_build_and_slow_path_failures() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        6,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
    &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "slow_path_unavailable"]
    );
}

#[test]
fn handle_forward_build_failure_without_fallback_only_records_build_failure() {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        false,
    &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason.clone())
        .collect();
    assert_eq!(reasons, vec!["forward_build_failed"]);
}

#[test]
fn slow_path_accept_is_categorized_by_reason_and_disposition() {
    let live = BindingLiveState::new();

    live.record_slow_path_accept(ForwardingDisposition::MissingNeighbor, "slow_path", 128);
    live.record_slow_path_accept(
        ForwardingDisposition::NoRoute,
        "forward_build_slow_path",
        64,
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 2);
    assert_eq!(live.slow_path_bytes.load(Ordering::Relaxed), 192);
    assert_eq!(
        live.slow_path_missing_neighbor_packets
            .load(Ordering::Relaxed),
        1
    );
}

// #1187: regression tests for DispositionCounters hot/cold accounting modes.
// Hot callers must accumulate in BatchCounters and only write to
// BindingLiveState on flush(). Cold callers must write immediately.

#[test]
fn disposition_counters_hot_accumulates_in_batch_not_live() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };
    let mut counters = BatchCounters::default();

    // Before any calls: live counter must be 0, batch must be clean.
    assert_eq!(live.policy_denied_packets.load(Ordering::Relaxed), 0);
    assert!(!counters.touched);

    // Hot call — should land in batch, not in live.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Hot(&mut counters),
        ForwardingResolution {
            disposition: ForwardingDisposition::PolicyDenied,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(counters.policy_denied_packets, 1, "batch should hold the count");
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        0,
        "live must not be updated before flush"
    );
    assert!(counters.touched, "touched flag must be set after hot bump");

    // After flush: batch clears, live receives the accumulated count.
    counters.flush(&live);
    assert_eq!(counters.policy_denied_packets, 0, "batch must be zero after flush");
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        1,
        "live must receive count after flush"
    );
    assert!(!counters.touched, "touched flag must clear after flush");
}

#[test]
fn disposition_counters_cold_writes_live_immediately() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };

    // Before any calls: live counter must be 0.
    assert_eq!(live.route_miss_packets.load(Ordering::Relaxed), 0);

    // Cold call — should write to live immediately, no batch involved.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Cold(&live),
        ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(
        live.route_miss_packets.load(Ordering::Relaxed),
        1,
        "cold path must update live immediately"
    );
}

#[test]
fn disposition_counters_hot_screen_drops_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    // Simulate the screen-check fast path directly (3 drops).
    for _ in 0..3 {
        counters.touched = true;
        counters.screen_drops += 1;
    }

    assert_eq!(counters.screen_drops, 3);
    assert_eq!(live.screen_drops.load(Ordering::Relaxed), 0, "live must be 0 before flush");

    counters.flush(&live);
    assert_eq!(counters.screen_drops, 0, "batch must clear after flush");
    assert_eq!(live.screen_drops.load(Ordering::Relaxed), 3, "live must receive count after flush");
}

#[test]
fn syn_cookie_counters_hot_path_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    counters.touched = true;
    counters.syn_cookie_challenges = 2;
    counters.syn_cookie_secret_unavailable = 3;
    counters.syn_cookie_ack_valid = 5;
    counters.syn_cookie_ack_invalid = 7;
    counters.syn_cookie_bypass = 11;

    counters.flush(&live);

    assert_eq!(counters.syn_cookie_challenges, 0);
    assert_eq!(counters.syn_cookie_secret_unavailable, 0);
    assert_eq!(counters.syn_cookie_ack_valid, 0);
    assert_eq!(counters.syn_cookie_ack_invalid, 0);
    assert_eq!(counters.syn_cookie_bypass, 0);
    assert_eq!(live.syn_cookie_challenges.load(Ordering::Relaxed), 2);
    assert_eq!(
        live.syn_cookie_secret_unavailable.load(Ordering::Relaxed),
        3
    );
    assert_eq!(live.syn_cookie_ack_valid.load(Ordering::Relaxed), 5);
    assert_eq!(live.syn_cookie_ack_invalid.load(Ordering::Relaxed), 7);
    assert_eq!(live.syn_cookie_bypass.load(Ordering::Relaxed), 11);
}
