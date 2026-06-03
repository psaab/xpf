// Tests for afxdp/coordinator/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from coordinator/mod.rs.

use super::*;
use crate::INJECT_PACKET_TUPLE_PROTOCOL_VERSION;
use crate::test_zone_ids::*;
use crate::{
    ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot,
    CoSSchedulerMapSnapshot,
};

#[test]
fn stamp_injected_packet_tuple_builds_ipv4_icmp_flow_key() {
    let mut meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: 0,
        ..UserspaceDpMeta::default()
    };
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };
    let tuple = inject::validate_injected_packet_tuple(&req, dst).expect("validate tuple");
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 0,
        mtu: 1500,
        src_mac: [0; 6],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
        primary_v6: None,
    };

    inject::stamp_injected_packet_tuple(&mut meta, 98, tuple, &egress).expect("stamp tuple");

    let flow = parse_session_flow_from_meta(meta).expect("metadata flow");
    assert_eq!(meta.protocol, PROTO_ICMP);
    assert_eq!(meta.l3_offset, 14);
    assert_eq!(meta.l4_offset, 34);
    assert_eq!(meta.payload_offset, 42);
    assert_eq!(
        flow.forward_key.src_ip,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))
    );
    assert_eq!(
        flow.forward_key.dst_ip,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))
    );
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn stamp_injected_packet_tuple_builds_ipv6_icmp_flow_key() {
    let mut meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: 0,
        ..UserspaceDpMeta::default()
    };
    let src = "2001:db8:80::8".parse::<Ipv6Addr>().unwrap();
    let dst = "2001:db8:80::200".parse::<Ipv6Addr>().unwrap();
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        destination_ip: "2001:db8:80::200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "2001:db8:80::8".into(),
        source_port: Some(0x4321),
        destination_port: Some(0),
        ..Default::default()
    };
    let tuple =
        inject::validate_injected_packet_tuple(&req, IpAddr::V6(dst)).expect("validate tuple");
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 80,
        mtu: 1500,
        src_mac: [0; 6],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: None,
        primary_v6: Some(src),
    };

    inject::stamp_injected_packet_tuple(&mut meta, 118, tuple, &egress).expect("stamp tuple");

    let flow = parse_session_flow_from_meta(meta).expect("metadata flow");
    assert_eq!(meta.protocol, PROTO_ICMPV6);
    assert_eq!(meta.l3_offset, 18);
    assert_eq!(meta.l4_offset, 58);
    assert_eq!(meta.payload_offset, 66);
    assert_eq!(flow.forward_key.src_ip, IpAddr::V6(src));
    assert_eq!(flow.forward_key.dst_ip, IpAddr::V6(dst));
    assert_eq!(flow.forward_key.src_port, 0x4321);
    assert_eq!(flow.forward_key.dst_port, 0);
}

#[test]
fn validate_injected_packet_tuple_rejects_legacy_wire_request() {
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };

    let err =
        inject::validate_injected_packet_tuple(&req, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))
            .expect_err("legacy request must fail closed");
    assert!(err.contains("tuple metadata version"), "{err}");
}

#[test]
fn validate_injected_packet_tuple_rejects_protocol_mismatch() {
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };

    let err =
        inject::validate_injected_packet_tuple(&req, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))
            .expect_err("non-ICMP tuple must fail closed");
    assert!(err.contains("supports only protocol"), "{err}");
}

#[test]
fn build_injected_packet_uses_wire_tuple_source_ipv4() {
    let req = InjectPacketRequest {
        packet_length: 98,
        ..Default::default()
    };
    let src = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let egress = EgressInterface {
        bind_ifindex: 12,
        vlan_id: 0,
        mtu: 1500,
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
        primary_v6: None,
    };
    let resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 80,
        tx_ifindex: 80,
        tunnel_endpoint_id: 0,
        next_hop: Some(dst),
        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        src_mac: Some(egress.src_mac),
        tx_vlan_id: 0,
    };

    let frame = build_injected_packet(&req, src, dst, 0x3456, resolution, &egress)
        .expect("build injected packet");

    assert_eq!(&frame[26..30], &[172, 16, 80, 8]);
    assert_eq!(&frame[30..34], &[172, 16, 80, 200]);
    assert_eq!(&frame[38..40], &0x3456u16.to_be_bytes());
}

#[test]
fn build_cos_owner_worker_by_queue_prefers_lowest_worker_with_tx_binding() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let worker_binding_ifindexes = BTreeMap::from([
        (2, std::collections::BTreeSet::from([12])),
        (7, std::collections::BTreeSet::from([12, 13])),
    ]);

    let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
        &forwarding,
        &worker_binding_ifindexes,
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
}

#[test]
fn build_cos_owner_worker_by_queue_spreads_queues_across_eligible_workers() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 2,
                    forwarding_class: "af12".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let worker_binding_ifindexes = BTreeMap::from([
        (2, std::collections::BTreeSet::from([12])),
        (7, std::collections::BTreeSet::from([12])),
    ]);

    let owner_by_queue = build_cos_owner_worker_by_queue_from_binding_ifindexes(
        &forwarding,
        &worker_binding_ifindexes,
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
    assert_eq!(owner_by_queue.get(&(80, 1)), Some(&7));
    assert_eq!(owner_by_queue.get(&(80, 2)), Some(&2));
}

#[test]
fn build_cos_owner_worker_by_queue_prefers_ready_workers_when_available() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 4,
                    forwarding_class: "iperf-a".into(),
                    priority: 5,
                    transmit_rate_bytes: 1_000_000,
                    guarantee_enabled: true,
                    exact: true,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        &forwarding,
        &BTreeMap::from([(7, std::collections::BTreeSet::from([12]))]),
        &BTreeMap::from([
            (2, std::collections::BTreeSet::from([12])),
            (7, std::collections::BTreeSet::from([12])),
        ]),
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&7));
    assert_eq!(owner_by_queue.get(&(80, 4)), Some(&7));
}

#[test]
fn build_cos_owner_worker_by_queue_falls_back_when_no_ready_workers_exist() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: 64 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );

    let owner_by_queue = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        &forwarding,
        &BTreeMap::new(),
        &BTreeMap::from([(2, std::collections::BTreeSet::from([12]))]),
    );

    assert_eq!(owner_by_queue.get(&(80, 0)), Some(&2));
}

#[test]
fn build_worker_binding_ifindexes_from_identities_groups_by_worker() {
    let identities = BTreeMap::from([
        (
            10,
            BindingIdentity {
                slot: 10,
                queue_id: 0,
                worker_id: 2,
                interface: "ge-0-0-2".into(),
                ifindex: 12,
            },
        ),
        (
            11,
            BindingIdentity {
                slot: 11,
                queue_id: 1,
                worker_id: 2,
                interface: "ge-0-0-2".into(),
                ifindex: 12,
            },
        ),
        (
            20,
            BindingIdentity {
                slot: 20,
                queue_id: 0,
                worker_id: 7,
                interface: "ge-0-0-3".into(),
                ifindex: 13,
            },
        ),
    ]);

    let worker_binding_ifindexes = build_worker_binding_ifindexes_from_identities(&identities);

    assert_eq!(
        worker_binding_ifindexes.get(&2),
        Some(&std::collections::BTreeSet::from([12]))
    );
    assert_eq!(
        worker_binding_ifindexes.get(&7),
        Some(&std::collections::BTreeSet::from([13]))
    );
}

#[test]
fn refresh_runtime_snapshot_rebuilds_cos_owner_worker_map_from_identities() {
    let mut coordinator = Coordinator::new();
    coordinator.workers.identities.insert(
        1,
        BindingIdentity {
            slot: 1,
            queue_id: 0,
            worker_id: 2,
            interface: "ge-0-0-2".into(),
            ifindex: 12,
        },
    );
    coordinator.workers.identities.insert(
        2,
        BindingIdentity {
            slot: 2,
            queue_id: 0,
            worker_id: 7,
            interface: "ge-0-0-3".into(),
            ifindex: 13,
        },
    );

    let mut snapshot = ConfigSnapshot::default();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth0.80".into(),
        ifindex: 80,
        parent_ifindex: 12,
        hardware_addr: "02:00:00:00:00:80".into(),
        cos_shaping_rate_bytes_per_sec: 1_000_000,
        cos_scheduler_map: "wan-map".into(),
        ..Default::default()
    });
    snapshot.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
            flow_rebalance: None,
        });

    coordinator.refresh_runtime_snapshot(&snapshot);

    assert_eq!(
        coordinator.cos_owner_worker_by_queue.get(&(80, 0)),
        Some(&2)
    );
    let shared = coordinator.cos.owner_worker_by_queue.load();
    assert_eq!(shared.get(&(80, 0)), Some(&2));
}

#[test]
fn build_shared_cos_root_leases_uses_active_workers_per_interface() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let leases = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
    let lease = leases.get(&80).expect("shared root lease");

    // The root lease budget must scale with active_shards: total
    // grantable = lease_bytes * active_shards. That is the actual
    // invariant this test pins. Drive it by reading active_shards
    // from the fixture (so the assertion does not silently decouple
    // from the setup) and drain the budget with fixed-size requests
    // plus a tail remainder for whatever the budget does not cleanly
    // divide by — lease_bytes is a function of shaping rate and
    // COS_ROOT_LEASE_TARGET_US, both of which are tuning knobs, so
    // an exact-divisibility assertion would make this test brittle
    // against legitimate scheduler tuning.
    let active_shards = *active_shards_by_egress_ifindex
        .get(&80)
        .expect("active shards configured for egress ifindex 80") as u64;
    let lease_bytes = lease.lease_bytes();
    let expected_total = lease_bytes * active_shards;
    let per_request = 2500u64;

    let mut remaining = expected_total;
    let mut total = 0u64;
    while remaining > 0 {
        let req = remaining.min(per_request);
        let granted = lease.acquire(1, req);
        assert_eq!(
            granted, req,
            "root lease must grant the full request while budget remains",
        );
        total += granted;
        remaining -= granted;
    }
    assert_eq!(total, expected_total);
    // Budget fully drained — any further acquire must return 0.
    assert_eq!(lease.acquire(1, 1), 0);
}

#[test]
fn build_shared_cos_root_leases_reuses_existing_matching_lease_arc() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 100_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 1usize)]);

    let existing = build_shared_cos_root_leases(&forwarding, &active_shards_by_egress_ifindex);
    let reused = build_shared_cos_root_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        &existing,
    );

    assert!(Arc::ptr_eq(
        existing.get(&80).expect("existing lease"),
        reused.get(&80).expect("reused lease")
    ));
}

#[test]
fn build_shared_cos_queue_leases_reuses_existing_matching_lease_arc() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    let reused = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );

    assert!(Arc::ptr_eq(
        existing.get(&(80, 4)).expect("existing queue lease"),
        reused.get(&(80, 4)).expect("reused queue lease")
    ));
}

#[test]
fn build_shared_cos_queue_leases_rebuilds_when_equal_flow_mode_toggles() {
    let mut forwarding = ForwardingState::default();
    forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-b".into(),
                priority: 5,
                transmit_rate_bytes: 50_000_000,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .equal_flow_enforcement = true;
    let rebuilt = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &existing,
    );

    let old = existing.get(&(80, 4)).expect("existing queue lease");
    let new = rebuilt.get(&(80, 4)).expect("rebuilt queue lease");
    assert!(
        !Arc::ptr_eq(old, new),
        "equal-flow mode toggle must rebuild the lease Arc"
    );
    assert!(new.v8_equal_flow_active());
}

#[test]
fn refresh_cos_owner_worker_map_from_binding_statuses_keeps_shared_arcs_when_unchanged() {
    let mut coordinator = Coordinator::new();
    coordinator.forwarding.cos.interfaces.insert(
        80,
        CoSInterfaceConfig {
            shaping_rate_bytes: 100_000_000,
            burst_bytes: 256 * 1024,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                CoSQueueConfig {
                    queue_id: 0,
                    forwarding_class: "best-effort".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
                CoSQueueConfig {
                    queue_id: 1,
                    forwarding_class: "af11".into(),
                    priority: 5,
                    transmit_rate_bytes: 50_000_000,
                    guarantee_enabled: true,
                    exact: false,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        },
    );
    coordinator.forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let bindings = vec![BindingStatus {
        worker_id: 7,
        ifindex: 12,
        ready: true,
        ..Default::default()
    }];

    coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
    let owners_before = coordinator.cos.owner_worker_by_queue.load_full();
    let leases_before = coordinator.cos.root_leases.load_full();
    let lease_before = leases_before.get(&80).expect("shared root lease").clone();
    assert_eq!(lease_before.acquire(1, 2500), 2500);

    coordinator.refresh_cos_owner_worker_map_from_binding_statuses(&bindings);
    let owners_after = coordinator.cos.owner_worker_by_queue.load_full();
    let leases_after = coordinator.cos.root_leases.load_full();

    assert!(Arc::ptr_eq(&owners_before, &owners_after));
    assert!(Arc::ptr_eq(
        &lease_before,
        leases_after.get(&80).expect("shared root lease")
    ));
}

#[test]
fn unique_interface_owner_worker_id_returns_none_when_queues_split() {
    let owner = 7u32;
    let queues = vec![
        crate::protocol::CoSQueueStatus {
            queue_id: 0,
            owner_worker_id: Some(2),
            ..Default::default()
        },
        crate::protocol::CoSQueueStatus {
            queue_id: 1,
            owner_worker_id: Some(owner),
            ..Default::default()
        },
    ];

    assert_eq!(unique_interface_owner_worker_id(&queues), None);
}

#[test]
fn aggregate_cos_statuses_sums_drop_counters_across_worker_snapshots() {
    // #710 regression pin. This is the EXACT code path where the
    // live bug landed: `Coordinator::cos_statuses` re-aggregates
    // per-worker snapshots, and before this PR that re-aggregation
    // silently dropped every new drop-counter field. The unit test
    // gate must be at this layer, not just the worker layer.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 256 * 1024,
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            buffer_bytes: 64 * 1024,
            queued_bytes: 48 * 1024,
            admission_flow_share_drops: 3,
            admission_buffer_drops: 5,
            admission_ecn_marked: 37,
            root_token_starvation_parks: 7,
            queue_token_starvation_parks: 11,
            tx_ring_full_submit_stalls: 13,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let worker_b = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        shaping_rate_bytes: 1_250_000_000,
        burst_bytes: 256 * 1024,
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            buffer_bytes: 64 * 1024,
            queued_bytes: 16 * 1024,
            admission_flow_share_drops: 17,
            admission_buffer_drops: 19,
            admission_ecn_marked: 41,
            root_token_starvation_parks: 23,
            queue_token_starvation_parks: 29,
            tx_ring_full_submit_stalls: 31,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    assert_eq!(aggregated.len(), 1);
    let iface = &aggregated[0];
    assert_eq!(iface.ifindex, 80);
    assert_eq!(iface.queues.len(), 1);
    let q = &iface.queues[0];
    assert_eq!(q.queue_id, 4);
    assert_eq!(q.owner_worker_id, Some(3));
    assert_eq!(q.buffer_bytes, 128 * 1024);
    assert_eq!(q.queued_bytes, 64 * 1024);
    // Each counter is non-coprime-prime on both sides to catch
    // accidental re-attribution between counters.
    assert_eq!(q.admission_flow_share_drops, 3 + 17);
    assert_eq!(q.admission_buffer_drops, 5 + 19);
    assert_eq!(q.admission_ecn_marked, 37 + 41);
    assert_eq!(q.root_token_starvation_parks, 7 + 23);
    assert_eq!(q.queue_token_starvation_parks, 11 + 29);
    assert_eq!(q.tx_ring_full_submit_stalls, 13 + 31);
}

#[test]
fn aggregate_cos_statuses_sums_owner_profile_across_workers_coherently() {
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            drain_latency_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[0] = 5;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[1] = 3;
                v
            },
            drain_invocations: 5,
            drain_noop_invocations: 1,
            owner_pps: 100,
            peer_pps: 40,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let worker_b = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            drain_latency_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[7] = 11;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::umem::DRAIN_HIST_BUCKETS];
                v[2] = 13;
                v
            },
            drain_invocations: 11,
            drain_noop_invocations: 2,
            owner_pps: 200,
            peer_pps: 50,
            ..Default::default()
        }],
        ..Default::default()
    }];

    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    let q = &aggregated[0].queues[0];
    assert_eq!(q.drain_latency_hist[0], 5);
    assert_eq!(q.drain_latency_hist[7], 11);
    assert_eq!(q.redirect_acquire_hist[1], 3);
    assert_eq!(q.redirect_acquire_hist[2], 13);
    assert_eq!(q.drain_invocations, 16);
    assert_eq!(q.drain_noop_invocations, 3);
    assert_eq!(q.owner_pps, 300);
    assert_eq!(q.peer_pps, 90);
    assert_eq!(
        q.drain_latency_hist.iter().copied().sum::<u64>(),
        q.drain_invocations,
        "cross-worker aggregation must preserve hist == invocation invariant",
    );
}

#[test]
fn cos_no_owner_binding_drops_total_sums_across_every_live_state() {
    // #710: the per-binding `no_owner_binding_drops` atomic is the
    // mechanical accumulator; the operator-facing surface is
    // `Coordinator::cos_no_owner_binding_drops_total`, which must
    // sum across every `BindingLiveState`. Without this test, a
    // refactor that reads only `bindings.first()` or only one
    // worker's bindings could silently undercount.
    let a = std::sync::Arc::new(BindingLiveState::new());
    let b = std::sync::Arc::new(BindingLiveState::new());
    let c = std::sync::Arc::new(BindingLiveState::new());
    a.no_owner_binding_drops
        .store(3, std::sync::atomic::Ordering::Relaxed);
    b.no_owner_binding_drops
        .store(5, std::sync::atomic::Ordering::Relaxed);
    c.no_owner_binding_drops
        .store(7, std::sync::atomic::Ordering::Relaxed);

    let total: u64 = [a, b, c]
        .iter()
        .map(|live| {
            live.no_owner_binding_drops
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    assert_eq!(total, 15);
}

#[test]
fn ring_pressure_counters_round_trip_through_snapshot() {
    // #802: verify that the new ring-pressure atomics on
    // BindingLiveState are surfaced via `snapshot()`. Without this
    // pin, a refactor that drops the new fields from `snapshot()`
    // would silently zero the operator-facing counters.
    use std::sync::atomic::Ordering;
    let live = BindingLiveState::new();
    live.dbg_tx_ring_full.store(11, Ordering::Relaxed);
    live.dbg_sendto_enobufs.store(13, Ordering::Relaxed);
    // #804: two distinct counters — bound-pending FIFO overflow
    // (17) and CoS queue admission overflow (41). Non-coprime-prime
    // per field so an accidental swap across the two is caught.
    live.dbg_bound_pending_overflow.store(17, Ordering::Relaxed);
    live.dbg_cos_queue_overflow.store(41, Ordering::Relaxed);
    live.rx_fill_ring_empty_descs.store(19, Ordering::Relaxed);
    live.debug_outstanding_tx.store(23, Ordering::Relaxed);
    let snap = live.snapshot();
    assert_eq!(snap.dbg_tx_ring_full, 11);
    assert_eq!(snap.dbg_sendto_enobufs, 13);
    assert_eq!(snap.dbg_bound_pending_overflow, 17);
    assert_eq!(snap.dbg_cos_queue_overflow, 41);
    assert_eq!(snap.rx_fill_ring_empty_descs, 19);
    assert_eq!(snap.debug_outstanding_tx, 23);
}

// -------------------------------------------------------------
// #925 Phase 1: worker supervisor catch_unwind tests.
// -------------------------------------------------------------

/// Helper: extract the message from a caught panic payload using
/// the same renderer the supervisor uses.
fn caught_message<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> String {
    let r = std::panic::catch_unwind(f);
    let payload = r.unwrap_err();
    super::supervisor::panic_payload_message(&payload)
}

#[test]
fn panic_payload_message_renders_str_panic() {
    assert_eq!(caught_message(|| panic!("hello world")), "hello world");
}

#[test]
fn panic_payload_message_renders_string_panic() {
    let s = String::from("owned message");
    assert_eq!(caught_message(move || panic!("{}", s)), "owned message");
}

#[test]
fn panic_payload_message_falls_back_for_non_string() {
    // panic_any unwinds with a non-string payload (i32 here).
    let msg = caught_message(|| std::panic::panic_any(42_i32));
    assert_eq!(msg, "non-string panic payload");
}

/// Integration test against the same `spawn_supervised_worker`
/// production uses (the spawn-closure body is the only thing we
/// substitute — the supervisor wrapper is the real one).
#[test]
fn spawn_supervised_worker_catches_string_panic_and_marks_dead() {
    use std::sync::atomic::Ordering;
    let atomics = Arc::new(super::super::worker_runtime::WorkerRuntimeAtomics::new());
    let slot = Arc::new(Mutex::new(None::<String>));
    let join = super::supervisor::spawn_supervised_worker(7, atomics.clone(), slot.clone(), || {
        panic!("intentional test panic")
    })
    .expect("spawn_supervised_worker");
    // The supervisor must NOT propagate the panic to the joiner.
    join.join().expect("supervisor must catch worker panic");
    assert!(atomics.dead.load(Ordering::Relaxed));
    let msg = slot
        .lock()
        .expect("panic slot lock")
        .clone()
        .expect("panic message published");
    assert_eq!(msg, "intentional test panic");
}

/// #925-A: same as the worker test above but for the auxiliary-thread
/// helper. No `runtime_atomics` / `panic_slot` — aux threads only get
/// catch_unwind + journald log + clean exit.
#[test]
fn spawn_supervised_aux_catches_string_panic_and_returns_cleanly() {
    let join = super::supervisor::spawn_supervised_aux("test-aux", || {
        panic!("intentional aux test panic")
    })
    .expect("spawn_supervised_aux");
    // Joiner must observe a clean Ok(()) — supervisor swallowed the panic.
    join.join()
        .expect("supervisor must catch aux thread panic and return Ok(())");
}

#[test]
fn spawn_supervised_aux_runs_body_to_completion_when_no_panic() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let ran = Arc::new(AtomicBool::new(false));
    let ran_clone = ran.clone();
    let join = super::supervisor::spawn_supervised_aux("test-aux-noop", move || {
        ran_clone.store(true, Ordering::Relaxed);
    })
    .expect("spawn_supervised_aux");
    join.join().expect("aux thread join");
    assert!(
        ran.load(Ordering::Relaxed),
        "aux body must execute when no panic occurs"
    );
}

#[test]
fn spawn_supervised_aux_catches_non_string_panic_payload() {
    // Non-string payload exercises the panic_payload_message fallback
    // path, mirroring the worker_loop integration test above.
    let join =
        super::supervisor::spawn_supervised_aux("test-aux-i32", || std::panic::panic_any(99_i32))
            .expect("spawn_supervised_aux");
    join.join().expect("supervisor must catch non-string panic");
}

// -------------------------------------------------------------
// #943 Copilot round-2 finding #6: refresh_bindings hop test.
//
// The wire pipeline is:
//   BindingLiveState::v_min_throttles (AtomicU64)
//     -> snapshot()  (umem/mod.rs)
//     -> refresh_bindings (coordinator/mod.rs)  <-- THIS HOP
//     -> BindingStatus.v_min_throttles
//     -> BindingCountersSnapshot.v_min_throttles (wire JSON)
//
// Codex round-1 caught the BLOCKER where this exact hop was
// missing — refresh_bindings did not bridge the V_min fields, so
// the wire surface projected zeros despite the worker incrementing
// the atomic correctly. That fix lives at coordinator/mod.rs:1149.
//
// This test exercises the production refresh_bindings call against
// a real Coordinator + real BindingLiveState, so a future drop of
// either bridge line surfaces here rather than silently re-zeroing
// the wire field. Non-coprime-prime values per field catch a swap.
// -------------------------------------------------------------
#[test]
fn refresh_bindings_bridges_v_min_counters_into_binding_status() {
    use std::sync::atomic::Ordering;
    let mut coordinator = Coordinator::new();
    let live = std::sync::Arc::new(BindingLiveState::new());
    live.v_min_throttle_hard_cap_overrides
        .store(83, Ordering::Relaxed);
    live.v_min_throttles.store(89, Ordering::Relaxed);
    // Set an unrelated bridged field so the test also pins the
    // surrounding bridge layout (a refactor that re-orders the
    // assignments and drops one in the middle would surface here).
    live.flow_cache_collision_evictions
        .store(79, Ordering::Relaxed);
    live.syn_cookie_challenges.store(97, Ordering::Relaxed);
    live.syn_cookie_secret_unavailable
        .store(101, Ordering::Relaxed);
    live.syn_cookie_syn_ack_sent.store(103, Ordering::Relaxed);
    live.syn_cookie_ack_rst_sent.store(107, Ordering::Relaxed);
    live.syn_cookie_reply_budget_drops
        .store(109, Ordering::Relaxed);
    live.syn_cookie_ack_valid.store(113, Ordering::Relaxed);
    live.syn_cookie_ack_invalid.store(127, Ordering::Relaxed);
    live.syn_cookie_bypass.store(131, Ordering::Relaxed);
    coordinator.workers.live.insert(0, live);

    let mut bindings = vec![BindingStatus {
        slot: 0,
        worker_id: 1,
        ifindex: 12,
        // Pre-populate with junk values so the test also catches a
        // refresh_bindings that fails to overwrite the field (a
        // bridge that branches on `if x != 0` and skips, etc.).
        v_min_throttle_hard_cap_overrides: 0xdead_beef,
        v_min_throttles: 0xcafe_f00d,
        flow_cache_collision_evictions: 0xbad_c0de,
        syn_cookie_challenges: 1,
        syn_cookie_secret_unavailable: 1,
        syn_cookie_syn_ack_sent: 1,
        syn_cookie_ack_rst_sent: 1,
        syn_cookie_reply_budget_drops: 1,
        syn_cookie_ack_valid: 1,
        syn_cookie_ack_invalid: 1,
        syn_cookie_bypass: 1,
        ..Default::default()
    }];

    coordinator.refresh_bindings(&mut bindings);

    assert_eq!(
        bindings[0].v_min_throttle_hard_cap_overrides, 83,
        "refresh_bindings must bridge v_min_throttle_hard_cap_overrides \
         from BindingLiveState into BindingStatus"
    );
    assert_eq!(
        bindings[0].v_min_throttles, 89,
        "refresh_bindings must bridge v_min_throttles from \
         BindingLiveState into BindingStatus"
    );
    assert_eq!(
        bindings[0].flow_cache_collision_evictions, 79,
        "refresh_bindings must bridge flow_cache_collision_evictions \
         (companion bridge line — pinning the surrounding layout)"
    );
    assert_eq!(bindings[0].syn_cookie_challenges, 97);
    assert_eq!(bindings[0].syn_cookie_secret_unavailable, 101);
    assert_eq!(bindings[0].syn_cookie_syn_ack_sent, 103);
    assert_eq!(bindings[0].syn_cookie_ack_rst_sent, 107);
    assert_eq!(bindings[0].syn_cookie_reply_budget_drops, 109);
    assert_eq!(bindings[0].syn_cookie_ack_valid, 113);
    assert_eq!(bindings[0].syn_cookie_ack_invalid, 127);
    assert_eq!(bindings[0].syn_cookie_bypass, 131);
}

#[test]
fn refresh_bindings_zeroes_v_min_counters_when_worker_absent() {
    // Codex BLOCKER fix at coordinator/mod.rs:~1294: when the
    // BindingLiveState is missing for a slot, refresh_bindings
    // resets the V_min fields to 0 rather than leaving stale
    // counter values from a previous live snapshot. Without this,
    // a worker death + slot reassignment would project ghost
    // counters onto the new binding.
    let mut coordinator = Coordinator::new();
    // No insert into coordinator.workers.live for slot 7 — that's
    // the precondition for the reset path.

    let mut bindings = vec![BindingStatus {
        slot: 7,
        worker_id: 9,
        v_min_throttle_hard_cap_overrides: 999,
        v_min_throttles: 888,
        screen_drops: 777,
        syn_cookie_challenges: 666,
        syn_cookie_secret_unavailable: 555,
        syn_cookie_syn_ack_sent: 444,
        syn_cookie_ack_rst_sent: 333,
        syn_cookie_reply_budget_drops: 222,
        syn_cookie_ack_valid: 111,
        syn_cookie_ack_invalid: 99,
        syn_cookie_bypass: 88,
        ..Default::default()
    }];

    coordinator.refresh_bindings(&mut bindings);

    assert_eq!(bindings[0].v_min_throttle_hard_cap_overrides, 0);
    assert_eq!(bindings[0].v_min_throttles, 0);
    assert_eq!(bindings[0].screen_drops, 0);
    assert_eq!(bindings[0].syn_cookie_challenges, 0);
    assert_eq!(bindings[0].syn_cookie_secret_unavailable, 0);
    assert_eq!(bindings[0].syn_cookie_syn_ack_sent, 0);
    assert_eq!(bindings[0].syn_cookie_ack_rst_sent, 0);
    assert_eq!(bindings[0].syn_cookie_reply_budget_drops, 0);
    assert_eq!(bindings[0].syn_cookie_ack_valid, 0);
    assert_eq!(bindings[0].syn_cookie_ack_invalid, 0);
    assert_eq!(bindings[0].syn_cookie_bypass, 0);
}

/// #1328 — verify `reconcile(None, ...)` reaches the
/// `"no_snapshot"` early-exit cleanly, runs the teardown phase
/// (resetting `slow_path` to None), zeros `workers.live`, and
/// increments `reconcile_calls`.
///
/// `last_reconcile_stage` is a single field with no history, so
/// the test asserts the final write only. The per-stage write
/// ORDERING (start -> stopped -> no_snapshot) is verified by
/// reading the diff against the inventory documented in
/// `docs/pr/1328-coordinator-reconcile-split/plan.md`
/// §"Hidden invariants" #2.
#[test]
fn reconcile_with_none_snapshot_reaches_no_snapshot_early_exit() {
    let mut coordinator = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        bound: true,
        xsk_registered: true,
        ready: true,
        rx_packets: 42,
        ..BindingStatus::default()
    }];
    coordinator.reconcile(None, &mut bindings, 64);
    assert_eq!(coordinator.last_reconcile_stage, "no_snapshot");
    assert_eq!(coordinator.reconcile_calls, 1);
    assert!(
        coordinator.workers.live.is_empty(),
        "no live workers expected on None snapshot"
    );
    assert!(
        coordinator.slow_path.is_none(),
        "slow_path should be None after teardown of an unbound coordinator"
    );
    // Reset phase zeroed counter / ready / bound flags.
    assert!(!bindings[0].ready);
    assert!(!bindings[0].bound);
    assert!(!bindings[0].xsk_registered);
    assert_eq!(bindings[0].rx_packets, 0);
}

// ---------------------------------------------------------------------------
// #1636 option C: proactive neighbor warm tests.
// ---------------------------------------------------------------------------

fn warm_active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// Build a coordinator with an installed warm queue (returning the
/// receiver), one egress interface on RG `rg_id`, that RG marked
/// forwarding-active, and a single static route whose next-hop is
/// UNRESOLVED. The caller drains the receiver after queue_warm_pass.
fn warm_test_coordinator(rg_id: i32) -> (Coordinator, Receiver<WarmItem>) {
    let mut coord = Coordinator::new();
    let (tx, rx) = mpsc::sync_channel::<WarmItem>(WARM_QUEUE_DEPTH);
    coord.neighbors.warm_queue = Some(tx);

    let now_secs = monotonic_nanos() / 1_000_000_000;
    coord
        .ha
        .rg_runtime
        .store(Arc::new(BTreeMap::from([(rg_id, warm_active_ha_runtime(now_secs))])));

    let egress_ifindex = 80i32;
    coord.forwarding.ifindex_to_name.insert(egress_ifindex, "ge-0-0-2".to_string());
    coord.forwarding.egress.insert(
        egress_ifindex,
        EgressInterface {
            bind_ifindex: egress_ifindex,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 0,
            redundancy_group: rg_id,
            primary_v4: None,
            primary_v6: None,
        },
    );
    coord.forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4 {
            prefix: PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: Some(Ipv4Addr::new(172, 16, 80, 1)),
            discard: false,
            next_table: String::new(),
        }],
    );
    (coord, rx)
}

#[test]
fn queue_warm_pass_fires_for_unresolved_next_hop() {
    let (coord, rx) = warm_test_coordinator(0);
    coord.queue_warm_pass(false);
    let item = rx.try_recv().expect("one warm item for the unresolved next-hop");
    assert_eq!(item.ifindex, 80);
    assert_eq!(item.hop, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1)));
    assert_eq!(item.iface_name, "ge-0-0-2");
    assert_eq!(item.rg_id, 0);
    assert!(rx.try_recv().is_err(), "exactly one item expected");
}

#[test]
fn queue_warm_pass_skips_already_resolved_next_hop() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Resolve the next-hop in the forwarding neighbor map.
    coord.forwarding.neighbors.insert(
        (80, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
        NeighborEntry { mac: [0xaa; 6] },
    );
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "resolved next-hop must not be warmed");
}

#[test]
fn queue_warm_pass_skips_when_owning_rg_inactive() {
    // Route is on RG 1 but RG 1 is NOT forwarding-active.
    let (coord, rx) = warm_test_coordinator(1);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Replace runtime: RG 1 inactive.
    coord.ha.rg_runtime.store(Arc::new(BTreeMap::from([(
        1i32,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: now_secs,
            lease: HAForwardingLease::Inactive,
        },
    )])));
    coord.queue_warm_pass(false);
    assert!(
        rx.try_recv().is_err(),
        "standby RG next-hop must not be warmed",
    );
}

#[test]
fn queue_warm_pass_skips_tunnel_routes() {
    // Codex r1 High #1: a route with tunnel_endpoint_id != 0 is HA-owned
    // by the tunnel endpoint's RG, not the underlay egress RG, and is out
    // of warm scope. The warmer must skip it rather than gate it on the
    // wrong RG.
    let (mut coord, rx) = warm_test_coordinator(0);
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].tunnel_endpoint_id = 7;
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "tunnel route must not be warmed");
}

#[test]
fn queue_warm_pass_skips_invalid_addresses() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Replace the route's next-hop with a multicast address.
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].next_hop =
        Some(Ipv4Addr::new(224, 0, 0, 1));
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "multicast next-hop must be filtered");
}

#[test]
fn queue_warm_pass_dedups_within_one_call() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Two routes with the SAME (ifindex, next-hop) in different tables.
    coord.forwarding.routes_v4.insert(
        "vrf-a.inet.0".to_string(),
        vec![RouteEntryV4 {
            prefix: PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            ifindex: 80,
            tunnel_endpoint_id: 0,
            next_hop: Some(Ipv4Addr::new(172, 16, 80, 1)),
            discard: false,
            next_table: String::new(),
        }],
    );
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok(), "first item expected");
    assert!(rx.try_recv().is_err(), "duplicate (ifindex, hop) must coalesce");
}

#[test]
fn queue_warm_pass_respects_snapshot_rate_limit() {
    let (coord, rx) = warm_test_coordinator(0);
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok());
    // Second non-forced sweep within 1s must be skipped wholesale.
    coord.queue_warm_pass(false);
    assert!(
        rx.try_recv().is_err(),
        "second sweep within 1s rate-limit must not enqueue",
    );
    // Forced sweep (RG-promote path) bypasses the snapshot rate-limit.
    coord.queue_warm_pass(true);
    assert!(rx.try_recv().is_ok(), "forced sweep must bypass snapshot rate-limit");
}

#[test]
fn queue_warm_pass_warms_fabric_peer_over_parent_ifindex() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Drop the route so only the fabric is a candidate.
    coord.forwarding.routes_v4.clear();
    let parent = 80i32;
    coord.forwarding.ifindex_to_name.insert(parent, "ge-0-0-0".to_string());
    coord.forwarding.fabrics.push(FabricLink {
        parent_ifindex: parent,
        overlay_ifindex: 90,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)),
        peer_mac: [0; 6],
        local_mac: [0; 6],
    });
    coord.queue_warm_pass(false);
    let item = rx.try_recv().expect("fabric peer warm item");
    assert_eq!(item.ifindex, parent, "fabric warms over parent_ifindex (AGY r7 #3)");
    assert_eq!(item.hop, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)));
}

#[test]
fn queue_warm_pass_noop_without_worker_queue() {
    // No warm_queue installed (worker not yet spawned) → no panic, no-op.
    let mut coord = Coordinator::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    coord
        .ha
        .rg_runtime
        .store(Arc::new(BTreeMap::from([(0i32, warm_active_ha_runtime(now_secs))])));
    coord.forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4 {
            prefix: PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            ifindex: 80,
            tunnel_endpoint_id: 0,
            next_hop: Some(Ipv4Addr::new(172, 16, 80, 1)),
            discard: false,
            next_table: String::new(),
        }],
    );
    coord.queue_warm_pass(false); // must not panic
}

#[test]
fn on_rg_promote_active_clears_rate_limit_and_forces_warm() {
    let (coord, rx) = warm_test_coordinator(0);
    // Pre-load a recent probe for the key so the per-key 5s rate-limit
    // would normally suppress it.
    {
        let mut probed = coord.neighbors.last_probed_at.lock().unwrap();
        probed.insert((80, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))), monotonic_nanos());
    }
    // First non-forced sweep enqueues (queue_warm_pass does not consult
    // last_probed_at — that is the worker's job — so the item IS sent).
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_ok());
    // on_rg_promote_active clears last_probed_at AND forces a sweep that
    // bypasses the snapshot rate-limit.
    coord.on_rg_promote_active();
    assert!(
        coord.neighbors.last_probed_at.lock().unwrap().is_empty(),
        "RG-promote must clear the per-key rate-limit map",
    );
    assert!(rx.try_recv().is_ok(), "forced warm pass on RG-promote must enqueue");
}

// #1628: waterfill counter cross-worker aggregation.

#[test]
fn aggregate_cos_waterfill_epochs_sum_and_min_over_active_workers() {
    // Two workers, both with active exact-guarantee backlog. The
    // coordinator MIN-combines the PER-WORKER min_epochs_per_worker each
    // worker already computed over its own bindings (interface_row.rs).
    // Worker A healthy (epochs 1000), worker B frozen in Phase-2 lock-in
    // (epochs 3). The summed epochs climb, but the MIN reflects the
    // frozen worker (F2 regression guard).
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let active_exact_queue = || CoSQueueStatus {
        queue_id: 4,
        worker_instances: 1,
        exact: true,
        guarantee_enabled: true,
        queued_bytes: 32 * 1024,
        ..Default::default()
    };
    let worker_healthy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 1000,
        waterfill_phase1_budget_breaks: 4,
        // worker-side per-binding MIN (one active binding here = its own
        // epochs).
        waterfill_min_epochs_per_worker: 1000,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let worker_frozen = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 3, // locked in Phase 2 — barely advanced
        waterfill_phase1_budget_breaks: 900,
        waterfill_min_epochs_per_worker: 3,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated =
        aggregate_cos_statuses_across_workers(&[worker_healthy, worker_frozen], &owner_by_queue);
    assert_eq!(aggregated.len(), 1);
    let iface = &aggregated[0];
    assert_eq!(iface.waterfill_epochs, 1000 + 3, "epochs SUM across workers");
    assert_eq!(
        iface.waterfill_phase1_budget_breaks,
        4 + 900,
        "budget breaks SUM across workers"
    );
    assert_eq!(
        iface.waterfill_min_epochs_per_worker, 3,
        "MIN must reflect the frozen worker, not be drowned by the healthy SUM"
    );
}

#[test]
fn aggregate_cos_waterfill_min_excludes_idle_workers() {
    // The idle-worker conflation guard: an idle worker reports the
    // u64::MAX "no active-backlog binding" sentinel; the coordinator
    // skips it so it cannot pin the MIN. The MIN reflects only the
    // worker WITH a candidate.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let busy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 500,
        waterfill_min_epochs_per_worker: 500,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 64 * 1024,
            ..Default::default()
        }],
        ..Default::default()
    }];
    // Idle worker: reports MAX (no active-backlog binding) per the
    // worker-side sentinel.
    let idle = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 0,
        waterfill_min_epochs_per_worker: u64::MAX,
        queues: vec![CoSQueueStatus {
            queue_id: 5,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 0,
            queued_packets: 0,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32), ((80, 5u8), 4u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[busy, idle], &owner_by_queue);
    let iface = &aggregated[0];
    assert_eq!(
        iface.waterfill_min_epochs_per_worker, 500,
        "idle worker (MAX sentinel) must be EXCLUDED from the MIN"
    );
}

#[test]
fn aggregate_cos_waterfill_min_captures_zero_epoch_lockin() {
    // A backlogged binding that completed ZERO epochs is the STRONGEST
    // lock-in signal — the worker reports 0 (NOT the MAX sentinel), and
    // the coordinator MUST capture it as the MIN even alongside a healthy
    // worker. This is the sentinel-collision case the code review flagged.
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let active_exact_queue = || CoSQueueStatus {
        queue_id: 4,
        worker_instances: 1,
        exact: true,
        guarantee_enabled: true,
        queued_bytes: 16 * 1024,
        ..Default::default()
    };
    let healthy = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 900,
        waterfill_min_epochs_per_worker: 900,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let locked_zero = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 0, // never completed an epoch — hard lock-in
        waterfill_min_epochs_per_worker: 0,
        queues: vec![active_exact_queue()],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated =
        aggregate_cos_statuses_across_workers(&[healthy, locked_zero], &owner_by_queue);
    assert_eq!(
        aggregated[0].waterfill_min_epochs_per_worker, 0,
        "a backlogged 0-epoch worker (lock-in) MUST be captured, not treated as 'no candidate'"
    );
}

#[test]
fn aggregate_cos_waterfill_min_max_sentinel_when_no_candidate() {
    // No worker reports a candidate (all u64::MAX) → the AGGREGATED MIN
    // stays u64::MAX (NOT 0), so an idle interface is distinguishable
    // from a hard 0-epoch lock-in. Prometheus suppresses the MAX gauge
    // and the CLI renders it as "none"; only a genuine 0-epoch lock-in
    // emits 0 (code-review r2, both reviewers).
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        waterfill_epochs: 777,
        waterfill_min_epochs_per_worker: u64::MAX,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            exact: true,
            guarantee_enabled: true,
            queued_bytes: 0,
            queued_packets: 0,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::from([((80, 4u8), 3u32)]);
    let aggregated = aggregate_cos_statuses_across_workers(&[worker], &owner_by_queue);
    assert_eq!(
        aggregated[0].waterfill_min_epochs_per_worker,
        u64::MAX,
        "no candidate (all MAX) → aggregated MIN stays the MAX sentinel, NOT 0"
    );
    assert_eq!(aggregated[0].waterfill_epochs, 777);
}

// #1748 review-r3 (soundness): exercise the rebalance teardown wiring that
// previously aliased the controller's socket through a raw pointer during a
// &mut self call. With the socket split into a separate Coordinator map, this
// path is borrow-checked. The test constructs a controller + a real loopback
// ntuple socket in the two lockstep maps, then runs the plain teardown and
// asserts both maps are cleared with no panic / no aliasing UB. (An empty
// ledger drives no worker barrier commands, so no live workers are needed.)
#[test]
fn rebalance_plain_teardown_clears_both_maps_soundly() {
    let mut coordinator = Coordinator::new();
    // Open a real ethtool socket on the loopback device. If the sandbox denies
    // it, skip — the soundness property under test is the borrow structure,
    // which still compiles regardless.
    let Ok(sock) = crate::afxdp::rebalance::NtupleSocket::open("lo") else {
        eprintln!("rebalance_plain_teardown_clears_both_maps_soundly: skipped (no lo ethtool socket)");
        return;
    };
    let ifindex = 1;
    coordinator.rebalance_sockets.insert(ifindex, sock);
    coordinator.rebalance_controllers.insert(
        ifindex,
        crate::afxdp::rebalance::RebalanceController::new(
            crate::afxdp::rebalance::RebalanceConfig::default(),
        ),
    );
    assert_eq!(coordinator.rebalance_controllers.len(), 1);
    assert_eq!(coordinator.rebalance_sockets.len(), 1);

    // The formerly-unsafe path. Must not panic and must clear both maps in
    // lockstep.
    coordinator.teardown_all_rebalance_rules_plain();

    assert!(
        coordinator.rebalance_controllers.is_empty(),
        "controllers cleared on plain teardown"
    );
    assert!(
        coordinator.rebalance_sockets.is_empty(),
        "sockets cleared on plain teardown (no fd leak)"
    );
}

// #1748 live BUG #2: snapshot-apply reconcile transitions. A flow-rebalance
// config delivered on a live snapshot must CONSTRUCT the controller (None ->
// Some) and removing it must TEAR IT DOWN (Some -> None), via the shared
// reconcile_rebalance_from_snapshot entry point that BOTH the boot path
// (apply_snapshot) and the same-plan live-commit path (refresh_runtime_snapshot)
// now call. Before the fix, the same-plan live path never reconciled the knob.
#[test]
fn reconcile_rebalance_from_snapshot_constructs_and_tears_down() {
    let mut coordinator = Coordinator::new();

    // None initially.
    assert!(coordinator.rebalance_config.is_none(), "off by default");

    // Snapshot WITH flow-rebalance enabled => config constructed.
    let mut snap_on = crate::ConfigSnapshot::default();
    snap_on.class_of_service = Some(crate::ClassOfServiceSnapshot {
        flow_rebalance: Some(crate::protocol::CoSFlowRebalanceSnapshot {
            count_delta: 2,
            rebalance_interval_secs: 1,
            max_rules: 64,
            ..Default::default()
        }),
        ..Default::default()
    });
    coordinator.reconcile_rebalance_from_snapshot(&snap_on);
    assert!(
        coordinator.rebalance_config.is_some(),
        "enabling flow-rebalance via snapshot must set the config (None -> Some)"
    );

    // Re-applying the SAME config is a no-op (idempotent — must not churn).
    let prev = coordinator.rebalance_config;
    coordinator.reconcile_rebalance_from_snapshot(&snap_on);
    assert_eq!(
        coordinator.rebalance_config, prev,
        "re-applying identical config is a no-op"
    );

    // Snapshot WITHOUT flow-rebalance (deleted) => config torn down to None.
    let mut snap_off = crate::ConfigSnapshot::default();
    snap_off.class_of_service = Some(crate::ClassOfServiceSnapshot::default());
    coordinator.reconcile_rebalance_from_snapshot(&snap_off);
    assert!(
        coordinator.rebalance_config.is_none(),
        "deleting flow-rebalance via snapshot must tear the config down (Some -> None)"
    );
    assert!(
        coordinator.rebalance_controllers.is_empty(),
        "controllers cleared on disable"
    );
    assert!(
        coordinator.rebalance_sockets.is_empty(),
        "sockets cleared on disable (no fd leak)"
    );

    // A disabled snapshot (max_rules == 0 => is_enabled() false) stays off.
    let mut snap_invalid = crate::ConfigSnapshot::default();
    snap_invalid.class_of_service = Some(crate::ClassOfServiceSnapshot {
        flow_rebalance: Some(crate::protocol::CoSFlowRebalanceSnapshot {
            count_delta: 2,
            rebalance_interval_secs: 1,
            max_rules: 0, // zero budget => is_enabled() false
            ..Default::default()
        }),
        ..Default::default()
    });
    // max_rules == 0 in the wire snapshot maps to the controller default (64)
    // in rebalance_config_from_snapshot, so this actually ENABLES with the
    // default budget — assert it is Some (the only disable path is an ABSENT
    // flow_rebalance block, exercised by snap_off above).
    coordinator.reconcile_rebalance_from_snapshot(&snap_invalid);
    assert!(
        coordinator.rebalance_config.is_some(),
        "max_rules 0 maps to the default budget => enabled"
    );
}

// #1748 live BUG #1: tick_rebalance must only EVALUATE at the rebalance_interval
// cadence, not every ~24/s status-poll tick. Sampling the per-flow byte-rate
// every ~42ms saw a stale flow-worker snapshot (rate ~0) and stalled at the
// epsilon band. This test asserts the eval-cadence gate: back-to-back ticks
// within the interval do NOT re-arm the eval timestamp; only a tick >= interval
// later does. (No live workers, so no move is taken — we assert the gate's
// timing bookkeeping, which is the part that controls the sampling window.)
#[test]
fn tick_rebalance_evaluates_at_interval_cadence_not_every_tick() {
    let mut coordinator = Coordinator::new();
    coordinator.rebalance_config = Some(
        crate::afxdp::rebalance::RebalanceConfig {
            count_delta_k: 2,
            rebalance_interval_secs: 1,
            max_rules: 64,
        },
    );
    // No live workers => no per-iface sampling, but the eval-cadence gate runs
    // first and updates rebalance_last_eval_ns on an admitted evaluation.
    assert_eq!(coordinator.rebalance_last_eval_ns, 0, "not evaluated yet");

    // First tick: admitted (last_eval == 0), arms the timer.
    coordinator.tick_rebalance();
    let first_eval = coordinator.rebalance_last_eval_ns;
    assert!(first_eval > 0, "first tick evaluates and arms the timer");

    // Immediate second tick (well under the 1s interval): MUST be gated out —
    // the eval timestamp must not advance.
    coordinator.tick_rebalance();
    assert_eq!(
        coordinator.rebalance_last_eval_ns, first_eval,
        "a back-to-back tick within the interval must NOT re-evaluate (BUG #1 gate)"
    );

    // A tick after the interval has elapsed re-evaluates. Simulate elapsed time
    // by backdating the last-eval stamp by > 1s.
    coordinator.rebalance_last_eval_ns =
        first_eval.saturating_sub(2 * 1_000_000_000);
    let backdated = coordinator.rebalance_last_eval_ns;
    coordinator.tick_rebalance();
    assert!(
        coordinator.rebalance_last_eval_ns > backdated,
        "a tick >= interval after the last eval must re-evaluate"
    );

    // Default-OFF: with no config, tick is a pure no-op (timer never moves).
    coordinator.rebalance_config = None;
    let before = coordinator.rebalance_last_eval_ns;
    coordinator.tick_rebalance();
    assert_eq!(
        coordinator.rebalance_last_eval_ns, before,
        "default-OFF tick_rebalance is a no-op"
    );
}

// #1748 live BUG (r6): the controller's per-worker rate vector was keyed by
// binding SLOT (the `workers.live` map key) while the flow-worker-map rows
// carry the real `binding.worker_id`. With slot != worker_id (the norm),
// select_move's `f.worker_id == hottest.worker_id` never matched, so the
// hottest worker always had ZERO candidate flows -> NoEligibleFlow -> zero
// installs under load even though binding_active_flow_count showed flows.
//
// This test reproduces that id-space mismatch (slot deliberately != worker_id)
// with a real per-worker tx_bytes imbalance and a populated flow-worker map
// whose rows carry the real worker_ids, then drives tick_rebalance and asserts
// the controller does NOT record NoEligibleFlow for the steered ifindex — i.e.
// the slot->worker_id join now lets the flow list match the worker rate vector.
#[test]
fn tick_rebalance_joins_flows_to_workers_by_real_worker_id_not_slot() {
    use crate::protocol::{FlowTupleStatus, FlowWorkerStatus};
    let mut coordinator = Coordinator::new();
    coordinator.rebalance_config = Some(crate::afxdp::rebalance::RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 1,
        max_rules: 64,
    });
    // ifindex 5 maps to loopback so the lazy controller can open a real
    // ethtool socket; the move attempt is fine — we assert on the skip reason,
    // not on a committed install (no worker handles => barrier would fail, but
    // that is BarrierFailed, NOT NoEligibleFlow).
    let ifindex = 5;
    if crate::afxdp::rebalance::NtupleSocket::open("lo").is_err() {
        eprintln!("tick_rebalance_joins...: skipped (no lo ethtool socket)");
        return;
    }
    coordinator.forwarding.ifindex_to_name.insert(ifindex, "lo".to_string());

    // 6 workers on ifindex 5. CRITICAL: slot != worker_id (slot = 100+w,
    // worker_id = 10+w) — the exact id-space split that broke the join.
    // tx_bytes give the R1 [2,2,2,1,3,2] partition (worker 14 hottest).
    let tx_for = |w: u32| -> u64 {
        match w {
            14 => 4_200_000_000, // hottest (3 flows)
            13 => 1_400_000_000, // coolest (1 flow)
            _ => 2_800_000_000,  // 2 flows each
        }
    };
    let worker_ids = [10u32, 11, 12, 13, 14, 15];
    for (i, &w) in worker_ids.iter().enumerate() {
        let slot = 100 + i as u32;
        let live = std::sync::Arc::new(crate::afxdp::BindingLiveState::new());
        live.test_set_tx_bytes(tx_for(w));
        // Flow rows for this worker: rows carry the REAL worker_id (w), as the
        // live publish path does. Worker 14 gets 3 flows, 13 gets 1, else 2.
        let nflows = match w { 14 => 3, 13 => 1, _ => 2 };
        let mut rows = Vec::new();
        for f in 0..nflows {
            let sport = (1000 + (w as u16) * 10 + f as u16) as u16;
            rows.push(FlowWorkerStatus {
                slot,
                queue_id: i as u32,
                worker_id: w,
                interface: "lo".into(),
                ifindex,
                ingress_ifindex: ifindex,
                session_key: FlowTupleStatus {
                    addr_family: libc::AF_INET as u8,
                    protocol: 6,
                    src_ip: "10.0.61.102".to_string(),
                    dst_ip: "172.16.80.200".to_string(),
                    src_port: sport,
                    dst_port: 5210,
                },
                ..Default::default()
            });
        }
        live.test_publish_flow_worker_map(rows);
        coordinator.workers.live.insert(slot, live);
        coordinator.workers.identities.insert(
            slot,
            BindingIdentity {
                slot,
                queue_id: i as u32,
                worker_id: w,
                interface: "lo".into(),
                ifindex,
            },
        );
    }

    // Drive several evals so the rate window fills and the hysteresis dwell
    // clears, letting the controller actually reach select_move. Each eval
    // advances every worker's cumulative tx_bytes by one window's worth and
    // backdates the eval timer so the cadence gate admits the eval.
    for round in 0..5u64 {
        for (i, &w) in worker_ids.iter().enumerate() {
            let slot = 100 + i as u32;
            if let Some(live) = coordinator.workers.live.get(&slot) {
                // Cumulative grows by `tx_for(w)` bytes per ~1s window.
                live.test_set_tx_bytes(tx_for(w).saturating_mul(round + 1));
            }
        }
        // Backdate the prior eval so the >= rebalance_interval gate admits this
        // one (first round has last_eval == 0 and is admitted unconditionally).
        if coordinator.rebalance_last_eval_ns != 0 {
            coordinator.rebalance_last_eval_ns = coordinator
                .rebalance_last_eval_ns
                .saturating_sub(2 * 1_000_000_000);
        }
        coordinator.tick_rebalance();
    }

    // The decisive assertion: with the slot->worker_id join fixed, the hottest
    // worker's flows are visible to the controller, so it does NOT record
    // NoEligibleFlow. Pre-fix (per-worker vector keyed by slot, flows keyed by
    // worker_id) EVERY post-dwell eval recorded no_eligible_flow because the
    // hottest worker (by slot) had no flow with a matching worker_id.
    let status = coordinator.flow_rebalance_status();
    let row = status
        .iter()
        .find(|s| s.ifindex == ifindex)
        .expect("a controller exists for the steered ifindex");
    // Per-worker rates were built (non-degenerate CoV) — proves we got past
    // sampling regardless of the join.
    assert!(
        row.worker_byterate_cov > 0.0,
        "per-worker rates were built; skips={:?}", row.moves_skipped
    );
    // The join is correct iff the controller reached a real move decision
    // without a NoEligibleFlow skip. (With handles absent the move attempt
    // fails the ack barrier => BarrierFailed, NOT NoEligibleFlow — either an
    // install or a BarrierFailed proves select_move found a candidate.)
    let no_eligible = row.moves_skipped.get("no_eligible_flow").copied().unwrap_or(0);
    assert_eq!(
        no_eligible, 0,
        "slot->worker_id join must make the hottest worker's flows eligible \
         (no NoEligibleFlow); skips={:?}", row.moves_skipped
    );
    let reached_decision = row.installs_total > 0
        || row.moves_skipped.get("barrier_failed").copied().unwrap_or(0) > 0
        || row.moves_skipped.get("magnitude").copied().unwrap_or(0) > 0
        || row.moves_skipped.get("epsilon").copied().unwrap_or(0) > 0;
    assert!(
        reached_decision,
        "controller must reach select_move's move decision (install/barrier/\
         magnitude/epsilon), proving flows joined to the hottest worker; \
         skips={:?} installs={}", row.moves_skipped, row.installs_total
    );
}
