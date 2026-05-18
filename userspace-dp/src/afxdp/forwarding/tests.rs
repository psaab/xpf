use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::nat::SourceNatFailureReason;
use crate::test_zone_ids::*;
use crate::{FabricSnapshot, NeighborSnapshot, SourceNATRuleSnapshot, ZoneSnapshot};

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

#[test]
fn metadata_classification_accepts_matching_generations() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::Valid
    );
}

#[test]
fn metadata_classification_rejects_generation_mismatch() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 22,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::ConfigGenerationMismatch
    );
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 9,
    };
    assert_eq!(
        classify_metadata(valid_meta(), validation),
        PacketDisposition::FibGenerationMismatch
    );
}

#[test]
fn metadata_classification_rejects_unknown_address_family() {
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 7,
    };
    let mut meta = valid_meta();
    meta.addr_family = 0;
    assert_eq!(
        classify_metadata(meta, validation),
        PacketDisposition::UnsupportedPacket
    );
}
#[test]
fn ha_resolution_blocks_inactive_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn ha_resolution_allows_fresh_active_owner_rg() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        active_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let resolved = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
}

#[test]
fn cached_flow_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_fabric_ingress_when_local_owner_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_invalidates_fabric_redirect_on_non_fabric_ingress_when_local_owner_active()
{
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(!cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_flow_decision_keeps_fabric_redirect_on_non_fabric_ingress_when_local_owner_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

    assert!(cached_flow_decision_valid(
        &state,
        &ha_state,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        resolution
    ));
}

#[test]
fn cached_local_delivery_decision_invalidates_when_owner_rg_is_demoted() {
    let state = build_forwarding_state(&nat_snapshot());
    let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolution = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("interface nat local delivery");
    let now_secs = monotonic_nanos() / 1_000_000_000;

    assert!(cached_flow_decision_valid(
        &state,
        &active,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
    assert!(!cached_flow_decision_valid(
        &state,
        &demoted,
        &dynamic_neighbors,
        now_secs,
        1,
        false,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        resolution
    ));
}

#[test]
fn inactive_owner_rg_redirects_established_session_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
    assert_eq!(
        redirected.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01])
    );
}

#[test]
fn inactive_owner_missing_neighbor_redirects_to_fabric() {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot
        .neighbors
        .retain(|neighbor| neighbor.ip != "172.16.80.1");
    let state = build_forwarding_state(&snapshot);
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let blocked = enforce_ha_resolution(
        &state,
        &ha_state,
        lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
    );
    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
    );
}

#[test]
fn fabric_ingress_prefers_local_active_owner_resolution_over_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
    let redirected = resolve_fabric_redirect(&state).expect("fabric redirect");
    let preferred = prefer_local_forward_candidate_for_fabric_ingress(
        &state,
        &ha_state,
        &Default::default(),
        now_secs,
        true,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        redirected,
    );
    assert_eq!(
        preferred.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(preferred.egress_ifindex, 12);
    assert_eq!(owner_rg_for_resolution(&state, preferred), 1);
}

#[test]
fn build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface() {
    let mut snapshot = nat_snapshot();
    snapshot.fabrics = vec![FabricSnapshot {
        name: "fab0".to_string(),
        parent_interface: "ge-0/0/0".to_string(),
        parent_linux_name: "ge-0-0-0".to_string(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".to_string(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".to_string(),
        local_mac: "02:bf:72:ff:00:01".to_string(),
        peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
    }];
    let state = build_forwarding_state(&snapshot);
    let redirect = resolve_fabric_redirect(&state).expect("fabric redirect");
    assert_eq!(redirect.egress_ifindex, 21);
    assert_eq!(redirect.tx_ifindex, 21);
    assert_eq!(
        redirect.neighbor_mac,
        Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    );
    assert_eq!(redirect.src_mac, Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]));
}

#[test]
fn zone_encoded_fabric_redirect_preserves_ingress_zone() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let redirected =
        resolve_zone_encoded_fabric_redirect(&state, "lan").expect("zone-encoded redirect");
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn parse_zone_encoded_fabric_ingress_uses_zone_override() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_zone_encoded_fabric_ingress(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &state,
        ),
        Some(TEST_LAN_ZONE_ID)
    );
}

#[test]
fn zone_encoded_fabric_ingress_skips_dynamic_neighbor_learning() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = vec![0u8; 64];
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut last_learned = None;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        ..UserspaceDpMeta::default()
    };
    learn_dynamic_neighbor_from_packet(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        &mut last_learned,
        &state,
        &neighbors,
    );
    assert!(neighbors.is_empty());
}

#[test]
fn manager_neighbor_replace_preserves_packet_learned_entries() {
    let mut coordinator = Coordinator::new();
    coordinator.dynamic_neighbors_ref().insert(
        (
            5,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
            )),
        ),
        NeighborEntry {
            mac: [0x10, 0x66, 0x6a, 0x0b, 0xd0, 0x17],
        },
    );

    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let neighbors = coordinator.dynamic_neighbors_ref();
    assert_eq!(neighbors.len(), 2);
    assert!(neighbors.contains_key(&(
        5,
        IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
        ))
    )));
    assert!(neighbors.contains_key(&(13, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))));
}

#[test]
fn manager_neighbor_replace_overrides_snapshot_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
        neighbors: vec![NeighborSnapshot {
            ifindex: 13,
            family: "inet".to_string(),
            ip: target.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    });

    let before = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("snapshot neighbor");
    assert_eq!(before.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );

    let after = lookup_neighbor_entry(
        &coordinator.forwarding,
        Some(coordinator.dynamic_neighbors_ref()),
        13,
        target,
    )
    .expect("updated manager neighbor");
    assert_eq!(after.mac, [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32]);
}

#[test]
fn manager_neighbor_replace_removes_snapshot_seeded_neighbor_entry() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
        neighbors: vec![NeighborSnapshot {
            ifindex: 13,
            family: "inet".to_string(),
            ip: target.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    });

    coordinator.apply_manager_neighbors(true, &[]);

    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

#[test]
fn refresh_runtime_snapshot_clears_old_manager_neighbor_cache_entries() {
    let mut coordinator = Coordinator::new();
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    coordinator.apply_manager_neighbors(
        true,
        &[(
            13,
            target,
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        )],
    );
    assert!(
        coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );

    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());

    assert!(
        !coordinator
            .dynamic_neighbors_ref()
            .contains_key(&(13, target))
    );
    assert!(
        lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .is_none()
    );
}

#[test]
fn new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let (from_zone, _) = zone_pair_for_flow(&state, 24, routed.egress_ifindex);
    let redirected = finalize_new_flow_ha_resolution(
        &state,
        &ha_state,
        now_secs,
        routed,
        false,
        24,
        state.zone_name_to_id.get(&from_zone).copied().unwrap_or(0),
        0,
    );
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(
        redirected.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn new_flow_from_fabric_keeps_forward_candidate_when_owner_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
    let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let resolved =
        finalize_new_flow_ha_resolution(&state, &ha_state, now_secs, routed, true, 21, 1, 0);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, routed.egress_ifindex);
}

#[test]
fn fabric_originated_reverse_session_prefers_local_client_delivery_when_rg_active() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(resolved.tx_ifindex, 24);
}

#[test]
fn fabric_originated_reverse_session_uses_zone_encoded_fabric_redirect_when_client_rg_inactive() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        1,
        true,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
    );
}

#[test]
fn cluster_peer_return_fast_path_allows_sfmix_to_lan_reply() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (5, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMP,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [0u8];

    let (decision, metadata) = cluster_peer_return_fast_path(
        &state,
        &dynamic_neighbors,
        &packet_frame,
        meta,
        Some(TEST_SFMIX_ZONE_ID),
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
    )
    .expect("fabric return fast path");

    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(decision.resolution.egress_ifindex, 5);
    assert_eq!(metadata.ingress_zone, 5);
    assert_eq!(metadata.egress_zone, 1);
    assert!(metadata.fabric_ingress);
    assert!(metadata.is_reverse);
}

#[test]
fn cluster_peer_return_fast_path_skips_pure_tcp_syn() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        ..UserspaceDpMeta::default()
    };

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &[],
            meta,
            Some(TEST_SFMIX_ZONE_ID),
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        )
        .is_none()
    );
}

#[test]
fn cluster_peer_return_fast_path_skips_icmp_echo_request() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMP,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [8u8];

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &packet_frame,
            meta,
            Some(TEST_LAN_ZONE_ID),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        )
        .is_none()
    );
}

#[test]
fn cluster_peer_return_fast_path_skips_icmpv6_echo_request() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let meta = UserspaceDpMeta {
        ingress_ifindex: 4,
        protocol: PROTO_ICMPV6,
        l4_offset: 0,
        ..UserspaceDpMeta::default()
    };
    let packet_frame = [128u8];

    assert!(
        cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &packet_frame,
            meta,
            Some(TEST_LAN_ZONE_ID),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        )
        .is_none()
    );
}

#[test]
fn missing_neighbor_session_metadata_preserves_fabric_ingress() {
    let mut state = build_forwarding_state(&native_gre_pbr_snapshot(false));
    state.fabrics.push(FabricLink {
        parent_ifindex: 4,
        overlay_ifindex: 104,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    });
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 13,
            tx_ifindex: 13,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0x50, 0, 0, 0, 0x1,
            ))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };

    let metadata = build_missing_neighbor_session_metadata(
        &state,
        TEST_LAN_ZONE_ID,
        TEST_WAN_ZONE_ID,
        true,
        decision,
    );

    assert_eq!(metadata.ingress_zone, 1);
    assert_eq!(metadata.egress_zone, 2);
    assert!(metadata.fabric_ingress);
    assert!(!metadata.is_reverse);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn reverse_session_blocks_inactive_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
}

#[test]
fn reverse_session_prefers_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let resolved = reverse_resolution_for_session(
        &state,
        &ha_state,
        &dynamic_neighbors,
        "2001:559:8585:80::8".parse().expect("dst"),
        2,
        false,
        monotonic_nanos() / 1_000_000_000,
        false,
    );

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 12);
}

#[test]
fn session_hit_keeps_interface_snat_ipv4_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn inactive_interface_snat_session_hit_redirects_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
        1,
        inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
    )])));
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let looked_up =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);
    let blocked = enforce_ha_resolution(&state, &ha_state, looked_up);
    let redirected = redirect_via_fabric_if_needed(&state, blocked, 12);

    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
}

#[test]
fn session_hit_keeps_interface_snat_ipv6_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:80::200".parse().expect("src"),
        dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:80::200".parse().expect("src"),
            dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
            src_port: 5201,
            dst_port: 43600,
        },
    };
    let decision = SessionDecision {
        resolution: interface_nat_local_resolution(&state, flow.dst_ip)
            .expect("interface nat local delivery"),
        nat: NatDecision::default(),
    };

    let resolved =
        lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn embedded_icmp_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_no_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        embedded_proto: PROTO_UDP,
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
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
    assert_eq!(
        resolved.src_mac,
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
    );
}

#[test]
fn embedded_icmp_discard_route_uses_zone_encoded_fabric_redirect() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::new();
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::DiscardRoute,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        12,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
    assert_eq!(resolved.egress_ifindex, 21);
    assert_eq!(resolved.tx_ifindex, 21);
}

#[test]
fn embedded_icmp_from_fabric_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        original_src_port: 33434,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
    };

    let resolved = finalize_embedded_icmp_resolution(
        &state,
        &ha_state,
        monotonic_nanos() / 1_000_000_000,
        21,
        &icmp_match,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn fabric_ingress_does_not_redirect_back_to_fabric() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let blocked = ForwardingResolution {
        disposition: ForwardingDisposition::HAInactive,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: None,
        tx_vlan_id: 80,
    };
    assert_eq!(
        redirect_via_fabric_if_needed(&state, blocked, 21).disposition,
        ForwardingDisposition::HAInactive
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_selection_uses_interface_addresses_v6() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
        dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
            dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
    assert_eq!(
        match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn source_nat_pool_unavailable_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "wrong-family".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "v6-only".to_string(),
        pool_addresses: vec!["2001:db8::10".to_string()],
        port_low: 10_000,
        port_high: 10_010,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "wrong-family".to_string(),
            pool_name: "v6-only".to_string(),
            reason: SourceNatFailureReason::WrongAddressFamily,
        })
    );
}

#[test]
fn source_nat_allocator_exhausted_reports_rule_and_pool_identity() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "exhausted".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "tiny-pool".to_string(),
        pool_unusable: true,
        pool_unusable_reason: "allocator_exhausted".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);

    assert_eq!(
        match_source_nat_for_flow_result(&state, &from_zone, &to_zone, 12, &flow),
        SourceNatLookup::Unavailable(SourceNatFailure {
            rule_name: "exhausted".to_string(),
            pool_name: "tiny-pool".to_string(),
            reason: SourceNatFailureReason::AllocatorExhausted,
        })
    );
}

#[test]
fn interface_snat_addresses_are_not_treated_as_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = lookup_forwarding_resolution(&state, "172.16.80.8".parse().expect("v4"));
    assert_ne!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    let resolved_v6 =
        lookup_forwarding_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"));
    assert_ne!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
}

#[test]
fn interface_snat_addresses_are_local_delivered_on_session_miss() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
        .expect("v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 =
        interface_nat_local_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"))
            .expect("v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn icmp_session_miss_resolution_prefers_frame_destination_for_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 18;
    meta.l4_offset = 38;
    meta.flow_src_addr[..4].copy_from_slice(&[172, 16, 80, 201]);
    // Deliberately poison the metadata tuple to model a stamped-dst mismatch.
    meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);

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
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolution_target = parse_packet_destination(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("frame destination");
    assert_eq!(resolution_target, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

    let resolved =
        interface_nat_local_resolution_on_session_miss(&state, resolution_target, PROTO_ICMP)
            .expect("nat local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_interface_nat_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp v4 nat local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = interface_nat_local_resolution_on_session_miss(
        &state,
        "2001:559:8585:80::8".parse().expect("v6"),
        PROTO_UDP,
    )
    .expect("udp v6 nat local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_interface_nat_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = interface_nat_local_resolution_on_session_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        PROTO_TCP,
    )
    .expect("tcp nat local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("v4"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

#[test]
fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
    let mut snapshot = native_gre_snapshot(true);
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "lan-to-sfmix".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "sfmix".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_TCP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_UDP,
    ));
    assert!(should_block_tunnel_interface_nat_session_miss(
        &state,
        tunnel_snat_ip,
        PROTO_ICMP,
    ));
}

#[test]
fn ingress_interface_local_resolution_matches_vlan_local_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved =
        ingress_interface_local_resolution(&state, 11, 80, "172.16.80.8".parse().expect("dst"))
            .expect("ingress local delivery");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

#[test]
fn tcp_session_miss_local_delivers_ingress_vlan_address() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolved_v4 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert_eq!(
        resolved_v4.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v4.local_ifindex, 12);

    let resolved_v6 = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "2001:559:8585:80::8".parse().expect("dst"),
        PROTO_UDP,
    )
    .expect("udp ingress local delivery");
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(resolved_v6.local_ifindex, 12);
}

#[test]
fn tcp_ack_session_miss_does_not_cache_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(!should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn tcp_syn_session_miss_still_caches_ingress_local_delivery() {
    let state = build_forwarding_state(&nat_snapshot());
    let resolution = ingress_interface_local_resolution_on_session_miss(
        &state,
        11,
        80,
        "172.16.80.8".parse().expect("dst"),
        PROTO_TCP,
    )
    .expect("tcp ingress local delivery");
    assert!(should_cache_local_delivery_session_on_miss(
        &state,
        "172.16.80.8".parse().expect("dst"),
        resolution,
        PROTO_TCP,
        0x02,
    ));
}

#[test]
fn helper_local_session_on_miss_stays_out_of_shared_alias_maps() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        metadata,
        SessionOrigin::LocalMiss,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(sessions.lookup(&key, 1_000_000, 0x10).is_some());
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn helper_local_session_on_miss_clears_stale_shared_aliases() {
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let state = build_forwarding_state(&nat_snapshot());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "172.16.80.8".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 40278,
        dst_port: 5201,
    };
    let decision = SessionDecision {
        resolution: ingress_interface_local_resolution_on_session_miss(
            &state, 11, 80, key.src_ip, PROTO_TCP,
        )
        .expect("tcp ingress local delivery"),
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    };

    // Install with SyncImport origin so take_synced_local recognizes
    // this as a peer-synced session.
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(install_helper_local_session_on_miss(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &key,
        decision,
        entry.metadata.clone(),
        SessionOrigin::LocalMiss,
        2_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&key)
            .is_none()
    );
    assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("forward wire lock")
            .is_empty()
    );
}

#[test]
fn unsolicited_dns_reply_respects_flow_knob() {
    let mut state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "172.16.80.53".parse().expect("src"),
        dst_ip: "10.0.61.102".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: "172.16.80.53".parse().expect("src"),
            dst_ip: "10.0.61.102".parse().expect("dst"),
            src_port: 53,
            dst_port: 5353,
        },
    };
    state.allow_dns_reply = true;
    assert!(allow_unsolicited_dns_reply(&state, &flow));
    state.allow_dns_reply = false;
    assert!(!allow_unsolicited_dns_reply(&state, &flow));
}

#[test]
fn policy_selection_permits_matching_zone_pair() {
    let state = build_forwarding_state(&nat_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn policy_selection_denies_on_default_policy() {
    let state = build_forwarding_state(&policy_deny_snapshot());
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    assert_eq!(
        evaluate_policy(
            &state.policy,
            from_id,
            to_id,
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn policy_selection_deny_emits_rt_flow_event() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
        },
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
        },
    ];
    let state = build_forwarding_state(&snapshot);
    let flow = SessionFlow {
        src_ip: "10.0.61.102".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let (from_id, to_id) = zone_pair_ids_for_flow(&state, 24, 12);
    let action = evaluate_policy(
        &state.policy,
        from_id,
        to_id,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
    );
    assert_eq!(action, PolicyAction::Deny);

    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 24,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..Default::default()
    };

    super::super::emit_policy_deny_event(
        Some(&event_handle),
        &flow,
        meta,
        from_id,
        to_id,
        1,
        action,
        123,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, 0);
    assert_eq!(event.reason, 5);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}

#[test]
fn forwarding_resolution_reports_egress_and_neighbor() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn forwarding_resolution_supports_next_table_recursion() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table(true));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
    );

    let resolved_v6 = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved_v6.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved_v6.egress_ifindex, 12);
    assert_eq!(
        resolved_v6.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn forwarding_state_normalizes_ipv6_routes_emitted_in_inet_table() {
    let mut snapshot = forwarding_snapshot(true);
    snapshot.routes[1].table = "inet.0".to_string();
    snapshot.routes[1].family = "inet".to_string();
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
    );
}

#[test]
fn dynamic_neighbor_cache_enables_forward_candidate() {
    let state = build_forwarding_state(&forwarding_snapshot(false));
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        NeighborEntry {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        },
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

#[test]
fn parse_neighbor_entries_accepts_stale_ipv4_and_ipv6_rows() {
    let parsed = parse_neighbor_entries(
        "172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE\n2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE\n",
    );
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].0, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(
        parsed[1].0,
        IpAddr::V6("2001:559:8585:80::200".parse().expect("ipv6"))
    );
    assert_eq!(parsed[0].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    assert_eq!(parsed[1].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
}

#[test]
fn learned_ingress_neighbor_enables_reverse_lan_resolution() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 24);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

#[test]
fn learned_vlan_ingress_neighbor_maps_to_logical_ifindex() {
    let state = build_forwarding_state(&nat_snapshot());
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &state,
        &dynamic_neighbors,
        11,
        80,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
    );
    let resolved = lookup_forwarding_resolution_with_dynamic(
        &state,
        &dynamic_neighbors,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(
        resolved.neighbor_mac,
        Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
}

#[test]
fn forwarding_resolution_rejects_next_table_loop() {
    let state = build_forwarding_state(&forwarding_snapshot_with_next_table_loop());
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::NextTableUnsupported
    );
}

#[test]
fn tx_binding_resolution_prefers_bind_ifindex_for_vlan_units() {
    let state = build_forwarding_state(&nat_snapshot());
    assert_eq!(resolve_tx_binding_ifindex(&state, 12), 11);
}

#[test]
fn tx_binding_resolution_uses_fabric_parent_ifindex() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    assert_eq!(resolve_tx_binding_ifindex(&state, 21), 21);
}
