// Tests for afxdp/coordinator/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from coordinator/mod.rs.

use super::*;

impl Coordinator {
    /// #7209 test seam: assign `forwarding` AND publish it, which is what every
    /// production assignment does.
    ///
    /// Both production sites that set `self.forwarding`
    /// (`coordinator/snapshot_refresh.rs`, `Coordinator::stop_inner`) publish on
    /// the very next lines, so an UNPUBLISHED forwarding is a state the daemon
    /// never occupies. A fixture that assigned the field alone modelled that
    /// impossible state, and it stopped being harmless once the peer-synced
    /// import path started reading the PUBLISHED view: the import would resolve
    /// against a default forwarding while the test believed it had installed
    /// one. Fourteen cells said so the moment the read source moved.
    ///
    /// It lives in this FIXTURE file, not in `coordinator/mod.rs`, so it stays
    /// out of `forwarding_publish_population_is_pinned_7015`'s population. That
    /// canary pins the `.forwarding = ` assignment sites in PRODUCTION source to
    /// catch a third apply path that forgets its counter prune; adding a
    /// test-only exception to its list would raise `coordinator/mod.rs` from 1 to
    /// 2 and mask exactly the apply it exists to catch.
    pub(crate) fn set_forwarding_for_test(&mut self, forwarding: ForwardingState) {
        self.forwarding = forwarding;
        self.publish_runtime_view();
    }
}

use crate::INJECT_PACKET_TUPLE_PROTOCOL_VERSION;
use crate::test_zone_ids::*;
use crate::{
    ClassOfServiceSnapshot, CoSForwardingClassSnapshot, CoSSchedulerMapEntrySnapshot,
    CoSSchedulerMapSnapshot,
};

/// #6563: a `ForwardingState` that OWNS the given addresses, i.e. they are in
/// the global local-address membership sets `local_v4`/`local_v6`. The
/// emit-on-wire source gate admits exactly these.
fn forwarding_owning(addrs: &[IpAddr]) -> ForwardingState {
    let mut state = ForwardingState::default();
    for addr in addrs {
        match addr {
            IpAddr::V4(v4) => {
                state.local_v4.insert(*v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(*v6);
            }
        }
    }
    state
}

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
    let owned = forwarding_owning(&[IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))]);
    let tuple =
        inject::validate_injected_packet_tuple(&req, dst, &owned).expect("validate tuple");
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
    let owned = forwarding_owning(&[IpAddr::V6(src)]);
    let tuple = inject::validate_injected_packet_tuple(&req, IpAddr::V6(dst), &owned)
        .expect("validate tuple");
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

// ── #6563: emit-on-wire source validation ───────────────────────────
//
// `--emit-on-wire` puts a real frame on a real egress interface. The emit path
// runs FIB, HA and CoS/output-filter processing but NEVER security policy,
// screen, or any source check — `inject.rs` contained zero references to
// policy or screen — so `source_ip` was operator-arbitrary and emitted
// verbatim. That is a spoofing primitive: a local principal could put spoofed
// ICMP/ICMPv6 on the wire, bypassing the zone policy and screen that govern
// transit traffic. The usual "loopback gRPC, therefore administrator-only"
// bound does not hold here — #5278 establishes that any provisioned
// login-class shell user reaches this plane.
//
// The source must now be an address the firewall itself owns (the global
// `local_v4`/`local_v6` membership sets: interface host addresses plus
// static-NAT/DNAT externals).
//
// FAIL-ON-REVERT: delete the `is_firewall_local_address` gate from
// `validate_injected_packet_tuple` and the foreign-source cases below are
// accepted again.

#[test]
fn emit_on_wire_refuses_a_foreign_source_ip() {
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        // Not an address this firewall owns — a third party's.
        source_ip: "203.0.113.7".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };
    let owned = forwarding_owning(&[IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))]);

    let err = inject::validate_injected_packet_tuple(
        &req,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        &owned,
    )
    .expect_err("a foreign source_ip must not be emitted on the wire");
    assert!(err.contains("203.0.113.7"), "{err}");
    assert!(err.contains("not an address this firewall"), "{err}");
}

#[test]
fn emit_on_wire_refuses_a_foreign_source_ipv6() {
    let src = "2001:db8:dead::1".parse::<Ipv6Addr>().unwrap();
    let dst = "2001:db8:80::200".parse::<Ipv6Addr>().unwrap();
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        destination_ip: "2001:db8:80::200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "2001:db8:dead::1".into(),
        source_port: Some(0x4321),
        destination_port: Some(0),
        ..Default::default()
    };
    // The firewall owns a DIFFERENT v6 address, so the refusal is about this
    // source and not about an empty state.
    let owned = forwarding_owning(&[IpAddr::V6("2001:db8:80::8".parse().unwrap())]);

    let err = inject::validate_injected_packet_tuple(&req, IpAddr::V6(dst), &owned)
        .expect_err("a foreign IPv6 source must not be emitted on the wire");
    assert!(err.contains("2001:db8:dead::1"), "{err}");
    let _ = src;
}

#[test]
fn emit_on_wire_accepts_a_local_interface_source() {
    // The positive control. Without it the gate could refuse everything and
    // both refusal tests would still pass.
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
    let owned = forwarding_owning(&[IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))]);

    let tuple = inject::validate_injected_packet_tuple(
        &req,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        &owned,
    )
    .expect("a firewall-owned source must be accepted");
    assert_eq!(tuple.source_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
}

#[test]
fn emit_on_wire_accepts_a_static_nat_external_source() {
    // `local_v4` carries static-NAT/DNAT externals as well as interface host
    // addresses. Those are addresses the firewall answers for, so emitting
    // from one is not third-party spoofing and must not be refused.
    let nat_external = Ipv4Addr::new(198, 51, 100, 20);
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "198.51.100.20".into(),
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };
    let owned = forwarding_owning(&[IpAddr::V4(nat_external)]);

    inject::validate_injected_packet_tuple(
        &req,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        &owned,
    )
    .expect("a firewall-owned NAT external source must be accepted");
}

#[test]
fn emit_on_wire_source_gate_is_the_last_check() {
    // Ordering matters for the operator-facing message: a request that is BOTH
    // malformed AND foreign-sourced must report the STRUCTURAL fault, so the
    // structural tests above cannot pass for the source gate's reason and vice
    // versa. Parse -> validate shape -> authorize.
    let req = InjectPacketRequest {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP, // structural fault: not ICMP for v4
        destination_ip: "172.16.80.200".into(),
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "203.0.113.7".into(), // also foreign
        source_port: Some(0x1234),
        destination_port: Some(0),
        ..Default::default()
    };
    let err = inject::validate_injected_packet_tuple(
        &req,
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        &forwarding_owning(&[]),
    )
    .expect_err("must fail");
    assert!(
        err.contains("supports only protocol"),
        "structural fault must be reported before the source gate: {err}"
    );
}

#[test]
fn is_firewall_local_address_is_family_exact() {
    // A v4 address must not be admitted by a v6 membership entry or vice
    // versa — the sets are separate and the match arms must not be crossed.
    let state = forwarding_owning(&[
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6("2001:db8::1".parse().unwrap()),
    ]);
    assert!(inject::is_firewall_local_address(
        &state,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    ));
    assert!(inject::is_firewall_local_address(
        &state,
        IpAddr::V6("2001:db8::1".parse().unwrap())
    ));
    assert!(!inject::is_firewall_local_address(
        &state,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    ));
    assert!(!inject::is_firewall_local_address(
        &state,
        IpAddr::V6("2001:db8::2".parse().unwrap())
    ));
    // An empty state owns nothing.
    let empty = forwarding_owning(&[]);
    assert!(!inject::is_firewall_local_address(
        &empty,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    ));
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
        inject::validate_injected_packet_tuple(
            &req,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            &forwarding_owning(&[IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))]),
        )
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
        inject::validate_injected_packet_tuple(
            &req,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            &forwarding_owning(&[IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))]),
        )
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 64 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
        inet_precedence_classifiers: vec![],
    });

    coordinator.refresh_runtime_snapshot(&snapshot).expect("refresh_runtime_snapshot must succeed");

    assert_eq!(
        coordinator.cos_owner_worker_by_queue.get(&(80, 0)),
        Some(&2)
    );
    let shared = coordinator.cos.owner_worker_by_queue.load();
    assert_eq!(shared.get(&(80, 0)), Some(&2));
}

/// #5166 ordering regression: the in-place `refresh_runtime_snapshot` must
/// publish the derived CoS owner/live/lease/backlog/vtime maps BEFORE it
/// makes the new `ForwardingState` worker-visible (the `ha.runtime` store).
/// A live worker loads the `RuntimeView` first and the CoS maps second
/// within one tick, then rebuilds `cos_fast_interfaces` from both — so if
/// forwarding were published first, a worker could see the new queue config
/// with a stale/empty CoS owner map (transient class blackhole / old-rate /
/// N-worker over-admission).
///
/// The coordinator records `cos_owner_at_forwarding_publish` (a `cfg(test)`
/// seam) at the exact instant just before the forwarding store. With the fix
/// the CoS owner map is already populated with the new queue there; reverting
/// the reorder (moving `refresh_cos_owner_worker_map_from_identities` back
/// after the `ha.runtime` store) captures the stale empty map and this test
/// goes RED.
#[test]
fn refresh_runtime_snapshot_publishes_cos_owner_map_before_forwarding() {
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

    // Sanity: a fresh coordinator has published nothing yet.
    assert!(
        coordinator.cos_owner_at_forwarding_publish.is_none(),
        "no snapshot applied yet",
    );
    assert!(
        coordinator.cos.owner_worker_by_queue.load().is_empty(),
        "the CoS owner map starts empty (old generation)",
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
        inet_precedence_classifiers: vec![],
    });

    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh_runtime_snapshot must succeed");

    // The forwarding state gained a new CoS queue (80, 0). The invariant:
    // at the instant forwarding became worker-visible, the CoS owner map
    // already owned that queue — otherwise a worker sees new forwarding with
    // no owner for the new queue.
    let captured = coordinator
        .cos_owner_at_forwarding_publish
        .as_ref()
        .expect("refresh must record the CoS owner map at the forwarding-publish point");
    assert_eq!(
        captured.get(&(80, 0)),
        Some(&2),
        "CoS owner for the new queue (80,0) must be published BEFORE forwarding \
         becomes worker-visible (#5166 ordering)",
    );

    // Post-refresh sanity: the fixture really did create queue (80,0).
    assert_eq!(
        coordinator.cos.owner_worker_by_queue.load().get(&(80, 0)),
        Some(&2),
    );
}

/// #6592 pairing regression, PRODUCER half: every worker-visible publish must
/// carry the coordinator's INTENDED `(validation, forwarding)` pair.
///
/// The consumer half — a worker takes both halves from ONE `ArcSwap` load — is
/// guarded by `snapshot_refresh_runtime_view_pair_is_atomic_6592`
/// (worker/loop_body/mod.rs). That test proves no reader can tear the pair;
/// this one proves the pair was coherent when it was published. Both are
/// needed: an atomic reader faithfully delivers whatever the producer put in
/// the view, so a site that published a stale validation alongside a new
/// forwarding would produce exactly the #6291 defect with a perfectly atomic
/// worker.
///
/// The coordinator records `runtime_view_at_publish` (a `cfg(test)` seam
/// inside the single publish choke point `store_runtime_view`, successor to the
/// #6291 `validation_at_forwarding_publish`) at the exact instant just before
/// the view store: the intended pair, plus the still-visible previous view.
/// The previous view makes the seam prove its own position — hoisting the store
/// above the capture would let the equality assert pass vacuously, and goes RED
/// here instead. It retains an `Arc` rather than a raw pointer so the old
/// allocation stays alive and `ptr_eq` cannot be fooled by address reuse.
#[test]
fn refresh_runtime_snapshot_publishes_a_coherent_view_pair() {
    const NEW_GEN: u64 = 7;
    const NEW_FIB_GEN: u32 = 3;

    let mut coordinator = Coordinator::new();

    // Sanity: a fresh coordinator has published nothing yet, and the
    // worker-visible validation is still the default (old) generation.
    assert!(
        coordinator.runtime_view_at_publish.is_none(),
        "no snapshot applied yet",
    );
    let before = coordinator.published_validation();
    assert_eq!(
        before,
        ValidationState::default(),
        "the worker-visible validation starts at the default (old) generation",
    );

    let snapshot = ConfigSnapshot {
        generation: NEW_GEN,
        fib_generation: NEW_FIB_GEN,
        ..Default::default()
    };

    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh_runtime_snapshot must succeed");

    let (intended, previous_view) = coordinator
        .runtime_view_at_publish
        .clone()
        .expect("refresh must record the view it published");
    let published = coordinator.ha.runtime.load_full();

    // THE INVARIANT, part 1: the pair the coordinator intended IS the pair a
    // worker observes — same validation, same forwarding allocation. A publish
    // site that built its view from a stale `validation`, or that stored
    // forwarding through some path other than the choke point, breaks this.
    assert_eq!(
        published.validation(),
        ValidationState {
            snapshot_installed: true,
            config_generation: NEW_GEN,
            fib_generation: NEW_FIB_GEN,
        },
        "the published view must carry this refresh's generation",
    );
    assert_eq!(
        intended.validation(), published.validation(),
        "the published validation must be the one the choke point intended \
         (#6592 coherent publish)",
    );
    assert!(
        Arc::ptr_eq(intended.forwarding(), published.forwarding()),
        "the published forwarding must be the exact allocation the choke point \
         paired with that validation — a second store would decouple them",
    );

    // THE INVARIANT, part 2 (position proof): the capture is taken BEFORE the
    // view store. Without this, hoisting the store above the seam would satisfy
    // the equality asserts vacuously by capturing an already-published view.
    assert!(
        !Arc::ptr_eq(&previous_view, &published),
        "the view capture must be taken BEFORE the ha.runtime store, or the \
         asserts above prove nothing",
    );

    // Not vacuous: the fixture really did rotate the generation, so the
    // published value could have differed from the pre-refresh default.
    assert_ne!(
        published.validation(), before,
        "the fixture must actually rotate the generation, or the asserts above \
         are vacuous",
    );
    assert_eq!(
        previous_view.validation(), before,
        "the retained previous view is the pre-refresh one",
    );
}

/// #6592 / #1188: a validation-only publish (`bump_fib_generation`) must
/// advance the worker-visible stamps WITHOUT rotating the forwarding `Arc`.
///
/// This is the measured constraint that decided the design. The structurally
/// simplest atomic pairing — inlining `ValidationState` into `ForwardingState`
/// — would make this path clone the whole forwarding state (69 fields, ~20
/// heap-owning collections including the FIB) and rotate the worker-visible
/// `Arc`, dragging every worker through its expensive rotation branch
/// (screen-profile and opening-override clones, cold-path slot rescan,
/// input-filter session purges, CoS runtime reset) for a change that touched no
/// table. Go fires `Manager.BumpFIBGeneration` repeatedly during route
/// convergence precisely to avoid a full rebuild, so that is a real regression
/// and #1188 exists to prevent it.
///
/// Nesting the forwarding half as an `Arc` inside `RuntimeView` keeps the pair
/// atomic AND keeps this path allocation-light: one small view, same inner
/// `Arc`. If the pairing is ever reworked so a FIB bump rotates forwarding,
/// this goes RED.
#[test]
fn bump_fib_generation_publishes_new_stamps_without_rotating_forwarding() {
    let mut coordinator = Coordinator::new();

    let snapshot = ConfigSnapshot {
        generation: 4,
        fib_generation: 9,
        ..Default::default()
    };
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh_runtime_snapshot must succeed");

    let before = coordinator.ha.runtime.load_full();
    assert_eq!(before.validation().fib_generation, 9);

    assert!(
        coordinator.bump_fib_generation(10),
        "a monotone bump must be accepted"
    );

    let after = coordinator.ha.runtime.load_full();

    // The stamps advanced and are worker-visible...
    assert_eq!(
        after.validation().fib_generation, 10,
        "the bump must be published to workers"
    );
    assert_eq!(
        after.validation().config_generation, 4,
        "a FIB bump must not disturb the config generation"
    );
    // ...paired with the SAME forwarding allocation, so the worker's #1188
    // `Arc::ptr_eq` short-circuit still short-circuits and the rotation branch
    // is not taken.
    assert!(
        Arc::ptr_eq(before.forwarding(), after.forwarding()),
        "#1188: a validation-only publish must REUSE the published forwarding \
         Arc — rotating it forces every worker through the expensive \
         forwarding-rotation branch for a change that touched no table",
    );
    // The view Arc itself DID rotate, or the bump would not be visible at all.
    assert!(
        !Arc::ptr_eq(&before, &after),
        "the view must rotate, or the new stamps never reach a worker",
    );

    // A rejected (rollback) bump publishes nothing at all.
    let before_reject = coordinator.ha.runtime.load_full();
    assert!(
        !coordinator.bump_fib_generation(9),
        "a rollback bump must be refused (#3767)"
    );
    assert!(
        Arc::ptr_eq(&before_reject, &coordinator.ha.runtime.load_full()),
        "a refused bump must not publish a new view",
    );
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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

/// #1746 F3: a live `equal-flow-target-policy` edit (slowest -> mean)
/// must rebuild the lease Arc — `matches_config_v8` includes the
/// policy, so a stale lease cannot keep publishing with the old
/// target math. Same-policy rebuild input must still reuse.
#[test]
fn build_shared_cos_queue_leases_rebuilds_when_equal_flow_target_policy_changes() {
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
                equal_flow_enforcement: true,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
            inet_precedence_classifier: String::new(),
            inet_precedence_queue_by_prec: [u8::MAX; 8],
        },
    );
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );

    // Same config -> reuse (no policy change).
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

    // Policy edit -> rebuild.
    forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .equal_flow_target_policy = EqualFlowTargetPolicy::Mean;
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
        "equal-flow target-policy change must rebuild the lease Arc"
    );
    assert!(new.v8_equal_flow_active());
    assert_eq!(new.v8_equal_flow_target_policy_label(), "mean");
}

/// #1830 follow-up (Codex review on PR #1841): shared fixture for the
/// sparse-worker-id sizing pins below — one exact 50 MB/s queue on
/// ifindex 80 / queue 4, mirroring the fixtures of the reuse/rebuild
/// tests above.
fn exact_queue_forwarding_fixture() -> ForwardingState {
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
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
                codel_target_ns: 0,
            }],
            oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
            oversubscription_guarantee_fraction: 0.0,
            priority_low_min_share_bytes: 0,
            inet_precedence_classifier: String::new(),
            inet_precedence_queue_by_prec: [u8::MAX; 8],
        },
    );
    forwarding
}

/// #1830 follow-up (Codex review on PR #1841): `planned_worker_slots`
/// must derive the per-worker-id array length from the MAX planned
/// worker id, not the worker COUNT — ids are sparse when the bindings
/// carrying the low ids were unregistered.
#[test]
fn planned_worker_slots_uses_max_id_not_count() {
    let empty: BTreeMap<u32, ()> = BTreeMap::new();
    assert_eq!(reconcile::bringup::planned_worker_slots(&empty), 0);

    let dense = BTreeMap::from([(0u32, ()), (1, ()), (2, ())]);
    assert_eq!(reconcile::bringup::planned_worker_slots(&dense), 3);

    // Sparse: two workers survive, but the highest id is 40 — the
    // sizing value must be 41, NOT the count (2).
    let sparse = BTreeMap::from([(3u32, ()), (40, ())]);
    assert_eq!(reconcile::bringup::planned_worker_slots(&sparse), 41);
}

/// #1830 follow-up (Codex review on PR #1841): a lease built for a
/// sparse topology whose only high worker id is 40 must size its
/// per-worker arrays to 41 slots — acquire_v8(40) is in range and
/// granted, and matches_config_v8 keys on the true max id.
#[test]
fn build_shared_cos_queue_leases_sizes_for_sparse_high_worker_id() {
    let forwarding = exact_queue_forwarding_fixture();
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    // worker_slots = 41 as planned_worker_slots derives for a sparse
    // workers map whose highest id is 40 (count would be far lower).
    let leases = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        41,
        &BTreeMap::new(),
    );
    let lease = leases.get(&(80, 4)).expect("queue lease");

    let burst_bytes = (128 * 1024u64).max(64 * 1500);
    assert!(
        lease.matches_config_v8(50_000_000, burst_bytes, 2, 40, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "lease must be sized for max_worker_id 40 (41 per-worker slots)"
    );
    assert!(
        !lease.matches_config_v8(50_000_000, burst_bytes, 2, 1, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "a 41-slot lease must not match a 2-slot topology"
    );

    // Worker id 40 (above the pre-fix count-derived sizing) acquires
    // through the lease end to end: in range, nonzero grant, rotation
    // publishes its fair share.
    lease.rehydrate_worker_active_count(40, 1);
    let granted = lease.acquire_v8(40, 1_000_000, 4096);
    assert_eq!(
        granted, 4096,
        "worker id 40 must be in range of the lease arrays and granted"
    );
}

/// #1830 follow-up (Codex review on PR #1841): a worker-slot change
/// with an otherwise identical queue topology must REBUILD the lease
/// (no false reuse) — matches_config_v8 keys on max_worker_id, so a
/// topology whose max id changed never reuses the old sizing even
/// when the worker COUNT is unchanged.
#[test]
fn build_shared_cos_queue_leases_rebuilds_when_worker_slots_change() {
    let forwarding = exact_queue_forwarding_fixture();
    let active_shards_by_egress_ifindex = BTreeMap::from([(80, 2usize)]);

    let existing = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        2,
        &BTreeMap::new(),
    );
    let rebuilt = build_shared_cos_queue_leases_reusing_existing(
        &forwarding,
        &active_shards_by_egress_ifindex,
        41,
        &existing,
    );

    let old = existing.get(&(80, 4)).expect("existing queue lease");
    let new = rebuilt.get(&(80, 4)).expect("rebuilt queue lease");
    assert!(
        !Arc::ptr_eq(old, new),
        "worker-slot change must rebuild the lease Arc, not reuse the old sizing"
    );

    // And the V_min floors honor the same sizing source. The floor
    // builder additionally gates on COS_SHARED_EXACT_MIN_RATE_BYTES
    // (2.5 Gbps), so raise the queue rate above that gate first.
    let mut high_rate_forwarding = exact_queue_forwarding_fixture();
    high_rate_forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("iface")
        .queues[0]
        .transmit_rate_bytes = 500_000_000;
    let floors = build_shared_cos_queue_vtime_floors_reusing_existing(
        &high_rate_forwarding,
        41,
        &BTreeMap::new(),
    );
    assert_eq!(
        floors.get(&(80, 4)).expect("vtime floor").slots.len(),
        41,
        "V_min floor slots must cover the highest planned worker id"
    );
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
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
                    equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                    surplus_weight: 1,
                    buffer_bytes: 128 * 1024,
                    dscp_rewrite: None,
                codel_target_ns: 0,
                },
            ],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
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
    // #hb166 T-7: buffer_bytes is a per-queue CONFIG value identical across
    // workers — aggregate by MAX, not SUM. Pre-fix summed 64 KB + 64 KB =
    // 128 KB (an N× "stats-that-lie" inflation). RED-on-revert.
    assert_eq!(q.buffer_bytes, 64 * 1024);
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
                let mut v = vec![0; super::super::binding_state::DRAIN_HIST_BUCKETS];
                v[0] = 5;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::binding_state::DRAIN_HIST_BUCKETS];
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
                let mut v = vec![0; super::super::binding_state::DRAIN_HIST_BUCKETS];
                v[7] = 11;
                v
            },
            redirect_acquire_hist: {
                let mut v = vec![0; super::super::binding_state::DRAIN_HIST_BUCKETS];
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
    let _ = coordinator.reconcile(None, &mut bindings, 64);
    assert_eq!(coordinator.last_reconcile_stage, ReconcileStage::NoSnapshot);
    // #6244: legacy operator string preserved byte-for-byte.
    assert_eq!(coordinator.last_reconcile_stage.to_string(), "no_snapshot");
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

/// #2515 fail-on-revert: the `no_snapshot` teardown path must run
/// `refresh_bindings` so every now-workerless slot is routed through
/// `zero_unbound_slot` AND the CoS owner->worker map is rebuilt empty.
///
/// `reset_binding_counters` (the phase that always runs before the
/// `no_snapshot` early-return) ONLY zeroes the counter scalars plus
/// `bound`/`xsk_registered`/`socket_fd`. It deliberately does NOT touch
/// `xsk_bind_mode`, `socket_ifindex`/`queue_id`/`bind_flags`,
/// `zero_copy`, `flow_cache_capacity`, or `active_flow_count` — those
/// are cleared only by `zero_unbound_slot` inside `refresh_bindings`.
/// So this test pre-populates exactly those reset-survivor fields and a
/// stale CoS owner-map entry, runs `reconcile(None, ...)`, and asserts
/// they are cleared. Reverting the `self.refresh_bindings(bindings)`
/// call added in the `no_snapshot` arm leaves every one of these stale
/// → the asserts go RED.
#[test]
fn reconcile_none_snapshot_refreshes_bindings_clearing_reset_survivor_fields() {
    let mut coordinator = Coordinator::new();
    // A stale CoS owner->worker entry that the teardown's
    // `refresh_cos_owner_worker_map_from_binding_statuses` (reached only
    // via refresh_bindings) must rebuild empty. `stop_inner` clears the
    // atomic CoS maps directly, but `cos_owner_worker_by_queue` (the
    // plain field compared in `refresh_cos_runtime_maps`) is the
    // operator-facing owner snapshot — confirm it ends empty.
    coordinator.cos_owner_worker_by_queue.insert((10, 3), 7);

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
        // Fields the reset pass leaves UNTOUCHED — only
        // `zero_unbound_slot` (via refresh_bindings) clears them.
        xsk_bind_mode: "ZEROCOPY".into(),
        zero_copy: true,
        socket_ifindex: 10,
        socket_queue_id: 3,
        socket_bind_flags: 0xc0,
        flow_cache_capacity: 65536,
        active_flow_count: 4096,
        ..BindingStatus::default()
    }];

    let _ = coordinator.reconcile(None, &mut bindings, 64);

    assert_eq!(coordinator.last_reconcile_stage, ReconcileStage::NoSnapshot);
    // #6244: legacy operator string preserved byte-for-byte.
    assert_eq!(coordinator.last_reconcile_stage.to_string(), "no_snapshot");
    // The reset-survivor fields must now be cleared by the teardown
    // refresh. Each of these stays stale if refresh_bindings is skipped.
    assert_eq!(
        bindings[0].xsk_bind_mode, "",
        "#2515: no_snapshot teardown must clear stale xsk_bind_mode"
    );
    assert!(
        !bindings[0].zero_copy,
        "#2515: no_snapshot teardown must clear stale zero_copy"
    );
    assert_eq!(
        bindings[0].socket_ifindex, 0,
        "#2515: no_snapshot teardown must clear stale socket_ifindex"
    );
    assert_eq!(
        bindings[0].socket_queue_id, 0,
        "#2515: no_snapshot teardown must clear stale socket_queue_id"
    );
    assert_eq!(
        bindings[0].socket_bind_flags, 0,
        "#2515: no_snapshot teardown must clear stale socket_bind_flags"
    );
    assert_eq!(
        bindings[0].flow_cache_capacity, 0,
        "#2515: no_snapshot teardown must clear stale flow_cache_capacity"
    );
    assert_eq!(
        bindings[0].active_flow_count, 0,
        "#2515: no_snapshot teardown must clear stale active_flow_count"
    );
    // The CoS owner->worker map must be rebuilt empty (no live/ready
    // workers remain after teardown).
    assert!(
        coordinator.cos_owner_worker_by_queue.is_empty(),
        "#2515: no_snapshot teardown must rebuild the CoS owner->worker \
         map empty"
    );
}

// ---------------------------------------------------------------------------
// #2522: the mlx5 zero-copy teardown quiesce (500ms) is gated on BOTH
// `had_live_workers` AND `will_rebind` (a snapshot is being applied, so
// a rebind on the same queue set follows). A teardown with no following
// bind — the `no_snapshot` / shutdown path — never rebinds, so the
// quiesce was pure dead latency there.
//
// Under `cfg(test)` the quiesce records its requested duration on the
// PER-INSTANCE `Coordinator::last_quiesce_ms` field and skips the real
// `thread::sleep`. Each test reads its OWN coordinator's field — there
// is NO process-global state, so the three tests are independent and
// safe to run in parallel (the default `cargo test` mode).
// `reconcile_quiesce_count` is an internal/test counter mirroring the
// gate.
// ---------------------------------------------------------------------------

/// No live workers + no rebind: the quiesce never fires. (Sanity floor
/// for the gate — the first conjunct alone is enough to skip.)
#[test]
fn teardown_quiesce_skipped_when_no_live_workers() {
    let mut coordinator = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let _ = coordinator.reconcile(None, &mut bindings, 64);
    assert_eq!(
        coordinator.last_quiesce_ms, 0,
        "no live workers => no mlx5 quiesce"
    );
    assert_eq!(coordinator.reconcile_quiesce_count, 0);
}

/// THE #2522 fail-on-revert pin: live workers WERE torn down, but the
/// reconcile carries NO snapshot (`will_rebind == false`) — the
/// `no_snapshot` early-exit follows with no rebind. The quiesce MUST be
/// skipped.
///
/// Fail-on-revert: revert the fix (gate back to `if had_live_workers`,
/// dropping the `&& will_rebind` conjunct) and this teardown sleeps the
/// full 500ms again — `last_quiesce_ms` becomes 500 and
/// `reconcile_quiesce_count` becomes 1, failing both assertions. The
/// pre-fix code paid this stall on every live-worker config-clear /
/// shutdown reconcile.
#[test]
fn teardown_quiesce_skipped_on_no_snapshot_even_with_live_workers() {
    let mut coordinator = gre1881_coordinator_with_worker();
    assert!(
        !coordinator.workers.records().is_empty(),
        "precondition: a live worker handle is seeded (had_live_workers == true)"
    );
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let _ = coordinator.reconcile(None, &mut bindings, 64);
    assert_eq!(
        coordinator.last_reconcile_stage,
        ReconcileStage::NoSnapshot,
        "None snapshot reaches the no_snapshot early-exit"
    );
    assert_eq!(coordinator.last_reconcile_stage.to_string(), "no_snapshot");
    assert!(
        coordinator.workers.records().is_empty(),
        "the seeded worker WAS torn down (proves had_live_workers held)"
    );
    assert_eq!(
        coordinator.last_quiesce_ms, 0,
        "#2522: a teardown with no following rebind must NOT pay the 500ms mlx5 quiesce"
    );
    assert_eq!(
        coordinator.reconcile_quiesce_count, 0,
        "no quiesce event counted on the no-rebind teardown"
    );
}

/// The other side of the gate: live workers AND a snapshot to apply
/// (`will_rebind == true`) — the rebind on the same queue set follows,
/// so the mlx5 EBUSY quiesce is load-bearing and MUST still fire. This
/// is the barrier-preservation half: the fix narrows WHEN the quiesce
/// runs, it does not remove the barrier from the path that needs it.
///
/// Fail-on-revert: if a future change drops the quiesce entirely (or
/// gates it on `will_rebind` alone, losing the `had_live_workers`
/// conjunct in a way that skips this case), `last_quiesce_ms` stays 0
/// and this assertion fails.
#[test]
fn teardown_quiesce_fires_when_live_workers_and_snapshot_rebinds() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::wrap(gre1881_coordinator_with_worker()); // #6637
    assert!(
        !coordinator.workers.records().is_empty(),
        "precondition: had_live_workers == true"
    );
    // All-OK mandatory pins so the map-FD preflight + forwarding build
    // pass and the reconcile REACHES `tear_down` (and the quiesce). The
    // post-teardown bringup may not fully bind a real XSK in the unit
    // env, but the quiesce already ran inside `tear_down` before any of
    // that — which is exactly the EBUSY-guard placement under test.
    let mut snap = fail_open_snapshot(1);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);
    assert_eq!(
        coordinator.last_quiesce_ms, 500,
        "#2522: live workers + a rebinding snapshot MUST still pay the mlx5 EBUSY quiesce"
    );
    assert_eq!(
        coordinator.reconcile_quiesce_count, 1,
        "exactly one quiesce event counted for the rebinding teardown"
    );
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
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            egress_ifindex,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
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
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].next_hops[0].tunnel_endpoint_id = 7;
    coord.queue_warm_pass(false);
    assert!(rx.try_recv().is_err(), "tunnel route must not be warmed");
}

#[test]
fn queue_warm_pass_skips_invalid_addresses() {
    let (mut coord, rx) = warm_test_coordinator(0);
    // Replace the route's next-hop with a multicast address.
    coord.forwarding.routes_v4.get_mut("inet.0").unwrap()[0].next_hops[0].next_hop =
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
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            80,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
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
        up: true,
    });
    coord.queue_warm_pass(false);
    let item = rx.try_recv().expect("fabric peer warm item");
    assert_eq!(item.ifindex, parent, "fabric warms over parent_ifindex (AGY r7 #3)");
    assert_eq!(item.hop, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)));
}

// #5686: a fabric peer REPLACED under the same parent must not leave the OLD
// peer selectable as a `resolve_fabric_redirect` target while the replacement
// is still unresolved. A "resolved" fabric snapshot carries a parseable
// `peer_mac`; an empty `peer_mac` (no neighbor) is the UNRESOLVED window that
// `resolve_fabric_links_from_snapshots` skips.
fn fabric_snap_5686(parent: i32, peer: &str, peer_mac: &str) -> crate::FabricSnapshot {
    crate::FabricSnapshot {
        name: format!("fab-{parent}"),
        parent_ifindex: parent,
        overlay_ifindex: parent + 1000,
        peer_address: peer.to_string(),
        local_mac: "02:bf:72:00:00:01".to_string(),
        peer_mac: peer_mac.to_string(),
        up: true,
        ..Default::default()
    }
}

#[test]
fn refresh_fabric_links_replacement_peer_invalidates_stale_old_5686() {
    let mut coord = Coordinator::new();
    let parent = 80i32;
    let p_old: IpAddr = "10.99.0.2".parse().unwrap();
    let p_new: IpAddr = "10.99.0.9".parse().unwrap();

    // 1. Install P_old (resolved) under parent X → it is the redirect target.
    coord.refresh_fabric_links(&[fabric_snap_5686(parent, "10.99.0.2", "02:00:00:00:00:02")]);
    let res = resolve_fabric_redirect(&coord.forwarding).expect("P_old redirect after install");
    assert_eq!(res.next_hop, Some(p_old), "P_old is the redirect target after install");
    assert_eq!(res.egress_ifindex, parent);

    // 2. Replace with P_new under the SAME parent while P_new is UNRESOLVED
    //    (empty peer_mac → the resolver skips it, so nothing resolves this pass
    //    and the preserve path runs). #5686: the stale P_old must NO LONGER be
    //    a redirect target, and the unresolved P_new must not be returned.
    coord.refresh_fabric_links(&[fabric_snap_5686(parent, "10.99.0.9", "")]);
    assert!(
        resolve_fabric_redirect(&coord.forwarding).is_none(),
        "after a same-parent replacement the OLD peer is no longer a fabric \
         redirect target, and the unresolved replacement is not returned either",
    );
    // The worker-visible fast-path Arc must be pruned too — otherwise its
    // supplemental non-empty patch re-adds the stale peer on the hot path.
    assert!(
        coord.ha.fabrics.load().iter().all(|f| f.peer_addr != p_old),
        "shared worker Arc (ha.fabrics) must not retain the stale old peer",
    );

    // 3. Once P_new RESOLVES → redirect returns P_new.
    coord.refresh_fabric_links(&[fabric_snap_5686(parent, "10.99.0.9", "02:00:00:00:00:09")]);
    let res = resolve_fabric_redirect(&coord.forwarding).expect("P_new redirect after resolve");
    assert_eq!(res.next_hop, Some(p_new), "resolved replacement P_new is the redirect target");
    assert_eq!(res.egress_ifindex, parent);
}

#[test]
fn refresh_fabric_links_replacement_leaves_other_parent_untouched_5686() {
    let mut coord = Coordinator::new();
    let x = 80i32;
    let y = 90i32;
    let py: IpAddr = "10.99.1.2".parse().unwrap();

    // Install both X→Px_old and Y→Py, both resolved.
    coord.refresh_fabric_links(&[
        fabric_snap_5686(x, "10.99.0.2", "02:00:00:00:00:02"),
        fabric_snap_5686(y, "10.99.1.2", "02:00:00:00:01:02"),
    ]);
    assert_eq!(coord.forwarding.fabrics.len(), 2, "both fabrics resolved");

    // Replace X's peer (UNRESOLVED) while Y still names the SAME peer (also
    // unresolved this pass → replace=false, the preserve path). #5686 must drop
    // ONLY the superseded X link and keep the untouched Y link.
    coord.refresh_fabric_links(&[
        fabric_snap_5686(x, "10.99.0.9", ""),
        fabric_snap_5686(y, "10.99.1.2", ""),
    ]);
    let parents: Vec<i32> = coord.forwarding.fabrics.iter().map(|f| f.parent_ifindex).collect();
    assert_eq!(parents, vec![y], "only Y survives; the superseded X link is dropped");
    let res = resolve_fabric_redirect(&coord.forwarding).expect("Y still redirects");
    assert_eq!(
        res.next_hop,
        Some(py),
        "different-parent peer Y is unaffected by X's replacement",
    );
    assert_eq!(res.egress_ifindex, y);
}

#[test]
fn fabric_link_superseded_by_snapshots_only_on_same_parent_different_peer_5686() {
    let link = FabricLink {
        parent_ifindex: 80,
        overlay_ifindex: 1080,
        peer_addr: "10.99.0.2".parse().unwrap(),
        peer_mac: [2, 0, 0, 0, 0, 2],
        local_mac: [2, 0xbf, 0x72, 0, 0, 1],
        up: true,
    };
    // Same parent, DIFFERENT peer → superseded.
    assert!(fabric_link_superseded_by_snapshots(
        &link,
        &[fabric_snap_5686(80, "10.99.0.9", "")]
    ));
    // Same parent, SAME peer (steady-state refresh) → NOT superseded.
    assert!(!fabric_link_superseded_by_snapshots(
        &link,
        &[fabric_snap_5686(80, "10.99.0.2", "")]
    ));
    // DIFFERENT parent, different peer → NOT superseded (other fabric).
    assert!(!fabric_link_superseded_by_snapshots(
        &link,
        &[fabric_snap_5686(90, "10.99.0.9", "")]
    ));
    // Parent OMITTED entirely (removal, not replacement) → NOT superseded.
    assert!(!fabric_link_superseded_by_snapshots(&link, &[]));
    // Unparseable replacement address on the same parent → NOT superseded
    // (the malformed new link cannot resolve, so it is not yet a replacement).
    assert!(!fabric_link_superseded_by_snapshots(
        &link,
        &[fabric_snap_5686(80, "not-an-ip", "")]
    ));
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
        vec![RouteEntryV4::single(
            PrefixV4::from_net("0.0.0.0/0".parse().unwrap()),
            80,
            0,
            Some(Ipv4Addr::new(172, 16, 80, 1)),
            false,
            String::new(),
            5,
        )],
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

// #1829 Phase 1: cross-worker sojourn aggregation pin. The sojourn
// trio MAX-merges across workers (worst instance) — summing delays
// would be meaningless and a `..Default::default()` fall-through
// would silently zero the gate metric at exactly this layer (the
// same failure shape as the #710 drop-counter regression above).
#[test]
fn aggregate_cos_statuses_max_merges_sojourn_across_worker_snapshots() {
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    let worker_a = vec![CoSInterfaceStatus {
        ifindex: 80,
        interface_name: "reth0.80".into(),
        worker_instances: 1,
        queues: vec![CoSQueueStatus {
            queue_id: 4,
            worker_instances: 1,
            sojourn_ewma_ns: 2_000_000,
            sojourn_peak_ns: 9_000_000,
            sojourn_windowed_min_ns: 1_500_000,
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
            sojourn_ewma_ns: 4_000_000,
            sojourn_peak_ns: 6_000_000,
            sojourn_windowed_min_ns: 5_500_000,
            ..Default::default()
        }],
        ..Default::default()
    }];
    let owner_by_queue = BTreeMap::new();
    let aggregated = aggregate_cos_statuses_across_workers(&[worker_a, worker_b], &owner_by_queue);

    assert_eq!(aggregated.len(), 1);
    let q = &aggregated[0].queues[0];
    assert_eq!(q.sojourn_ewma_ns, 4_000_000, "EWMA must MAX-merge");
    assert_eq!(q.sojourn_peak_ns, 9_000_000, "peak must MAX-merge");
    assert_eq!(
        q.sojourn_windowed_min_ns, 5_500_000,
        "windowed min (the gate metric) must MAX-merge across workers",
    );
}

// ---------------------------------------------------------------------
// #1866 — WG control-thread teardown / lifecycle regression suite.
//
// These tests drive the REAL spawn path: refresh_runtime_snapshot
// spawns an actual control thread that binds the listen UDP port and
// then fails open_tun (no TUN device in the test environment) and
// exits — which is exactly the early-exit shape the tombstone
// machinery must handle. Each test takes its listen port from
// `crate::test_ports` (#9549): unique within the suite, so it can run in
// parallel, and ephemeral rather than a fixed number, so a second copy of
// the suite on the same host (a mutation matrix runs two) cannot collide.
// ---------------------------------------------------------------------

const WG1866_PRIVKEY_A: &str =
    "a01010101010101010101010101010101010101010101010101010101010101a";
const WG1866_PRIVKEY_B: &str =
    "c03030303030303030303030303030303030303030303030303030303030303c";
const WG1866_PUBKEY: &str =
    "b02020202020202020202020202020202020202020202020202020202020202b";

fn wg1866_snapshot(id: u16, ifindex: i32, name: &str, port: u16, privkey: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id,
            interface: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            mode: "wireguard".to_string(),
            wg_listen_port: port,
            wg_local_privkey_hex: privkey.to_string(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: WG1866_PUBKEY.to_string(),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
                wg_endpoint: "127.0.0.1:9".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Drive the finished sweep until the entry for `id` is a tombstone
/// (its real thread exited) or the timeout elapses.
fn wg1866_wait_tombstone(coordinator: &mut Coordinator, id: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        // None snapshot: sweep-only (the tombstone-only respawn needs a
        // coherent snapshot, so this can never spawn).
        coordinator.reconcile_wg_control_liveness(None);
        match coordinator.wg_control_threads.get(&id) {
            Some(entry) if entry.handle.is_none() => return true,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Plan §9 test 1 — removal prune: a snapshot refresh that drops the
/// WG endpoint stops + joins the thread, removes the entry, and
/// releases the listen port.
#[test]
fn wg1866_removal_refresh_prunes_thread_and_releases_port() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4242, "wgt1866a", port, WG1866_PRIVKEY_A)).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "WG control entry created on snapshot with WG endpoint"
    );
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default()).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "removal refresh must prune the entry (stop+join)"
    );
    let bind = std::net::UdpSocket::bind(("0.0.0.0", port));
    assert!(
        bind.is_ok(),
        "listen port must be released after removal: {:?}",
        bind.err()
    );
}

/// Plan §9 tests 2+3 — EADDRINUSE regression (rigged old behavior) +
/// tombstone backoff: a thread that dies on a pre-bound port leaves a
/// tombstone; the sweep does NOT retry within the backoff window and
/// DOES retry past it once the port is free.
#[test]
fn wg1866_eaddrinuse_tombstone_backoff_and_retry() {
    let mut coordinator = Coordinator::new();
    // Rig the failure: a dual-stack [::]:port blocker occupies the port
    // for BOTH of bind_wg_socket's attempts (v6 preferred, v4 fallback).
    let (blocker, blocker_v4, port) = crate::test_ports::hold_ephemeral_udp_port();
    let snap = wg1866_snapshot(1, 4242, "wgt1866b", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "spawn attempt recorded even though bind will fail"
    );
    // The thread exits on EADDRINUSE; the sweep must tombstone, not drop.
    assert!(
        wg1866_wait_tombstone(&mut coordinator, 1, 2_000),
        "EADDRINUSE thread must become a tombstone"
    );
    let stamp_after_fail = coordinator
        .wg_control_threads
        .get(&1)
        .expect("tombstone entry retained")
        .last_spawn_attempt_ns;
    // Within the backoff window: no respawn even with a coherent
    // snapshot and the port now free.
    drop(blocker_v4);
    drop(blocker);
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry kept");
    assert!(entry.handle.is_none(), "no respawn within the 3s backoff");
    assert_eq!(
        entry.last_spawn_attempt_ns, stamp_after_fail,
        "backoff stamp unchanged while gated"
    );
    // Force past the backoff (tests own the entry — no 3s sleep).
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("entry")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry kept");
    assert!(
        entry.handle.is_some(),
        "tombstone respawned past backoff with a coherent snapshot"
    );
    assert!(entry.last_spawn_attempt_ns > 0, "attempt re-stamped");
}

/// Plan §9 test 4 — the #1866 headline contract: remove then re-add
/// the SAME identity; the re-add must spawn a fresh thread (no dead
/// entry shadowing, no EADDRINUSE from a leaked holder).
#[test]
fn wg1866_remove_then_readd_same_identity_respawns() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let snap = wg1866_snapshot(1, 4242, "wgt1866c", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.wg_control_threads.contains_key(&1));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default()).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.wg_control_threads.is_empty());
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator
        .wg_control_threads
        .get(&1)
        .expect("re-add with the same identity must create a fresh entry");
    assert!(entry.handle.is_some(), "fresh thread spawned on re-add");
}

/// Plan §9 test 5 — stop-gate shape: stop() clears all entries and a
/// subsequent sweep (tombstone-only) cannot create any, even with a
/// coherent snapshot in hand.
#[test]
fn wg1866_sweep_cannot_spawn_after_stop() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let snap = wg1866_snapshot(1, 4242, "wgt1866d", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.wg_control_threads.contains_key(&1));
    coordinator.stop();
    assert!(coordinator.wg_control_threads.is_empty(), "stop clears entries");
    for _ in 0..3 {
        coordinator.reconcile_wg_control_liveness(Some(&snap));
    }
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "tombstone-only sweep must never create entries after stop"
    );
}

/// Plan §9 tests 6+6b — defer-workers prune (Change 2b / D4) + F7
/// regression: the prune stops the thread WITHOUT touching forwarding,
/// and the sweep must NOT resurrect it from the stale forwarding state.
#[test]
fn wg1866_defer_prune_releases_port_and_sweep_does_not_resurrect() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let snap = wg1866_snapshot(1, 4242, "wgt1866e", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.wg_control_threads.contains_key(&1));
    // Defer-branch apply removed the endpoint: narrow prune only.
    let removed = ConfigSnapshot::default();
    coordinator.prune_wg_control_threads_for_snapshot(&removed);
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "defer prune must stop+join+remove the entry"
    );
    assert!(
        coordinator.forwarding.tunnel_endpoints.contains_key(&1),
        "defer prune must NOT touch the (intentionally stale) forwarding state"
    );
    let bind = std::net::UdpSocket::bind(("0.0.0.0", port));
    assert!(bind.is_ok(), "port released by the defer prune: {:?}", bind.err());
    // F7 regression: repeated sweeps against the STORED (endpoint-free)
    // snapshot must not resurrect the thread from stale forwarding.
    for _ in 0..3 {
        coordinator.reconcile_wg_control_liveness(Some(&removed));
    }
    assert!(
        coordinator.wg_control_threads.is_empty(),
        "tombstone-only sweep must not resurrect a defer-pruned endpoint"
    );
}

/// Plan §9 test 6c — Codex r3 regression: a tombstone whose latest
/// STORED snapshot row carries a DIFFERENT crypto identity must not
/// respawn from the stale forwarding state during a defer window.
#[test]
fn wg1866_sweep_suppresses_stale_identity_respawn_under_defer() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let snap_a = wg1866_snapshot(1, 4242, "wgt1866f", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap_a).expect("refresh_runtime_snapshot must succeed");
    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
    // Defer window: stored snapshot re-keys id 1 to identity B while
    // forwarding still holds identity A. Force past the backoff.
    let snap_b = wg1866_snapshot(1, 4242, "wgt1866f", port, WG1866_PRIVKEY_B);
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap_b));
    let entry = coordinator.wg_control_threads.get(&1).expect("tombstone kept");
    assert!(
        entry.handle.is_none(),
        "sweep must not respawn identity A when the stored snapshot says identity B"
    );
    // The coherent apply with B then restarts cleanly (engine changed
    // => stale prune => fresh spawn).
    coordinator.refresh_runtime_snapshot(&snap_b).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after B apply");
    assert!(entry.handle.is_some(), "identity B spawns at the coherent apply");
}

/// Plan §9 test 6d — Codex r4 regression: same id, same crypto
/// identity, RENAMED interface in the stored snapshot — the sweep must
/// not respawn the OLD attachment from stale forwarding.
#[test]
fn wg1866_sweep_suppresses_stale_attachment_respawn_under_defer() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let snap_a = wg1866_snapshot(1, 4242, "wgt1866g", port, WG1866_PRIVKEY_A);
    coordinator.refresh_runtime_snapshot(&snap_a).expect("refresh_runtime_snapshot must succeed");
    assert!(wg1866_wait_tombstone(&mut coordinator, 1, 2_000), "open_tun failure tombstones");
    // Stored snapshot renames the interface (same id + identity).
    let snap_renamed = wg1866_snapshot(1, 4243, "wgt1866h", port, WG1866_PRIVKEY_A);
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap_renamed));
    let entry = coordinator.wg_control_threads.get(&1).expect("tombstone kept");
    assert!(
        entry.handle.is_none(),
        "sweep must not respawn the old TUN attachment when the stored snapshot renamed it"
    );
}

/// Plan §9 test 6e — D5 regression (pre-existing master gap): an
/// apply-time interface rename with an UNCHANGED crypto identity must
/// restart the thread on the new TUN attachment (the reused engine Arc
/// alone must not keep the old thread).
#[test]
fn wg1866_apply_time_rename_restarts_thread_on_new_attachment() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4242, "wgt1866i", port, WG1866_PRIVKEY_A)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert_eq!(entry.spawned_tunnel_name, "wgt1866i");
    // Rename (same id, same identity): engine Arc is REUSED, but the
    // attachment-aware stale prune must restart the thread.
    coordinator.refresh_runtime_snapshot(&wg1866_snapshot(1, 4243, "wgt1866j", port, WG1866_PRIVKEY_A)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after rename");
    assert_eq!(
        entry.spawned_tunnel_name, "wgt1866j",
        "rename must stop the old thread and spawn against the new TUN"
    );
    assert_eq!(entry.spawned_ifindex, 4243);
}

/// PR #1872 Codex code-r1 F2 regression: rows whose `linux_name` is
/// empty resolve their forwarding label from the logical name
/// (forwarding_build/interfaces.rs fallback) — the tombstone-respawn
/// coherence check must apply the SAME fallback or self-heal never
/// fires for such rows.
#[test]
fn wg1866_sweep_respawns_with_empty_linux_name_rows() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    let mut snap = wg1866_snapshot(1, 4244, "wgt1866k", port, WG1866_PRIVKEY_A);
    snap.interfaces[0].linux_name = String::new();
    snap.tunnel_endpoints[0].linux_name = String::new();
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(
        wg1866_wait_tombstone(&mut coordinator, 1, 2_000),
        "open_tun failure tombstones"
    );
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    coordinator.reconcile_wg_control_liveness(Some(&snap));
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert!(
        entry.handle.is_some(),
        "coherence check must accept the empty-linux_name fallback label and respawn"
    );
}

// ---------------------------------------------------------------------
// #2921 — stale captured outer_mtu after a same-engine refresh.
//
// The WG identity tuple (`wg_identity_unchanged`: listen port, local
// private key, peer set) ignores the underlay transport table, the
// resolved egress ifindex, and the egress MTU. So a refresh that only
// changes the underlay route/table/egress MTU reuses the engine Arc and
// — before #2921 — left the spawn-time `outer_mtu` captured by value in
// the TUN-origin egress guard, while the transit/forwarded path
// re-resolved per snapshot. The apply-time stale prune now restarts the
// thread when a fresh `resolve_wg_outer_mtu` diverges from the captured
// value, so both packet origins enforce the SAME current outer MTU.
// ---------------------------------------------------------------------

/// #2921 helper: a WG snapshot whose peer endpoint (`10.50.0.9:9`) is
/// reachable via a SEPARATE underlay egress interface (`ge2921wan`,
/// `10.50.0.1/24`). `resolve_wg_outer_mtu` route-looks-up the peer in
/// the default table, lands on that interface's connected route, and
/// returns its egress MTU (`egress_mtu`) instead of the
/// `WG_DEFAULT_OUTER_MTU` fallback. The WG identity tuple (port +
/// privkey + peers) is held constant, so a refresh that changes ONLY
/// `egress_mtu` reuses the engine Arc (the #2921 stale path).
fn wg2921_snapshot(
    id: u16,
    wg_ifindex: i32,
    wg_name: &str,
    port: u16,
    egress_mtu: i32,
) -> ConfigSnapshot {
    use crate::protocol::snapshot::{
        InterfaceAddressSnapshot, InterfaceSnapshot, TunnelEndpointSnapshot, TunnelWgPeerSnapshot,
    };
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: wg_name.to_string(),
                linux_name: wg_name.to_string(),
                ifindex: wg_ifindex,
                tunnel: true,
                ..Default::default()
            },
            // Underlay egress carrying the peer-endpoint subnet (a
            // connected route in inet.0). Its MTU is the underlay outer
            // MTU that resolve_wg_outer_mtu returns for this tunnel.
            InterfaceSnapshot {
                name: "ge2921wan".to_string(),
                linux_name: "ge2921wan".to_string(),
                ifindex: 5921,
                mtu: egress_mtu,
                hardware_addr: "02:00:00:29:21:01".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.50.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id,
            interface: wg_name.to_string(),
            linux_name: wg_name.to_string(),
            ifindex: wg_ifindex,
            mode: "wireguard".to_string(),
            wg_listen_port: port,
            wg_local_privkey_hex: WG1866_PRIVKEY_A.to_string(),
            wg_peers: vec![TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: WG1866_PUBKEY.to_string(),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
                wg_endpoint: "10.50.0.9:9".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// #2921 regression: a same-engine refresh that changes ONLY the
/// underlay egress MTU must RESTART the WG control thread so the
/// TUN-origin egress guard picks up the NEW outer MTU. Before the fix
/// the reused engine Arc kept the stale spawn-time capture.
#[test]
fn wg2921_outer_mtu_change_restarts_control_thread() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    // First apply: peer reachable via ge2921wan @ MTU 1400.
    coordinator.refresh_runtime_snapshot(&wg2921_snapshot(1, 4242, "wgt2921a", port, 1400)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert_eq!(
        entry.spawned_outer_mtu, 1400,
        "spawn must capture the resolved underlay egress MTU (not the 1500 default fallback)"
    );
    let engine_ptr_before = entry.engine_ptr;
    // Stamp the attempt to NOW so a tombstone (open_tun fails in the test
    // env) cannot self-respawn within the backoff window — isolating the
    // restart to the stale-prune path under test.
    let t0 = monotonic_nanos();
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("entry")
        .last_spawn_attempt_ns = t0;

    // Second apply: SAME WG identity (port/privkey/peer), underlay MTU
    // dropped to 1280. The engine Arc is reused (wg_identity_unchanged),
    // so only the #2921 outer-MTU prune can restart the thread.
    coordinator.refresh_runtime_snapshot(&wg2921_snapshot(1, 4242, "wgt2921a", port, 1280)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after MTU change");
    assert_eq!(
        entry.engine_ptr, engine_ptr_before,
        "engine Arc must be REUSED (identity unchanged) — exercising the same-engine path"
    );
    assert_eq!(
        entry.spawned_outer_mtu, 1280,
        "outer-MTU change must restart the thread and re-resolve the underlay MTU"
    );
    assert_ne!(
        entry.last_spawn_attempt_ns, t0,
        "restart must re-stamp the spawn attempt"
    );
}

/// #2921 companion: an unchanged underlay (same egress MTU) must NOT
/// restart the thread — the common case stays byte-identical (no thread
/// churn on the hot reconcile path).
#[test]
fn wg2921_unchanged_outer_mtu_keeps_control_thread() {
    let mut coordinator = Coordinator::new();
    let port = crate::test_ports::reserve_ephemeral_udp_port();
    coordinator.refresh_runtime_snapshot(&wg2921_snapshot(1, 4242, "wgt2921b", port, 1400)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    assert_eq!(entry.spawned_outer_mtu, 1400, "resolved underlay MTU captured");
    let engine_ptr_before = entry.engine_ptr;
    // Recent attempt stamp: suppresses any tombstone self-respawn so the
    // assertion isolates the prune decision.
    let t0 = monotonic_nanos();
    coordinator
        .wg_control_threads
        .get_mut(&1)
        .expect("entry")
        .last_spawn_attempt_ns = t0;

    // Identical underlay MTU — resolve_wg_outer_mtu is unchanged.
    coordinator.refresh_runtime_snapshot(&wg2921_snapshot(1, 4242, "wgt2921b", port, 1400)).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator.wg_control_threads.get(&1).expect("entry after no-op refresh");
    assert_eq!(
        entry.engine_ptr, engine_ptr_before,
        "engine Arc reused on the unchanged refresh"
    );
    assert_eq!(entry.spawned_outer_mtu, 1400, "captured MTU unchanged");
    assert_eq!(
        entry.last_spawn_attempt_ns, t0,
        "no restart: the spawn attempt stamp must survive an unchanged-MTU refresh"
    );
}

/// #5291 fail-on-revert (resolver half): `resolve_wg_per_peer_outer_mtus`
/// must resolve the underlay egress MTU PER PEER — keyed by public key —
/// not one first-peer scalar for the whole interface. Two peers whose
/// endpoints route over SEPARATE underlays (peer A via ge5291a @1500,
/// peer B via ge5291b @1400) must yield DISTINCT per-peer MTUs; a revert
/// to the first-peer scalar collapses both to peer A's 1500. This is the
/// data half of the #5291 fix — the TUN-origin egress guard consumes this
/// map (see `wg_tun_origin_egress_uses_per_peer_outer_mtu_5291`).
#[test]
fn wg5291_per_peer_outer_mtu_resolves_distinct_underlays() {
    use crate::protocol::snapshot::{
        InterfaceAddressSnapshot, InterfaceSnapshot, TunnelEndpointSnapshot, TunnelWgPeerSnapshot,
    };
    // A second peer pubkey distinct from WG1866_PUBKEY (arbitrary 32-byte
    // key — the compiler hex-decodes it without curve validation).
    const WG5291_PUBKEY_B: &str =
        "d04040404040404040404040404040404040404040404040404040404040404d";

    let mut coordinator = Coordinator::new();
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "wgt5291".to_string(),
                linux_name: "wgt5291".to_string(),
                ifindex: 4291,
                tunnel: true,
                ..Default::default()
            },
            // Peer A underlay @1500 (connected route in inet.0).
            InterfaceSnapshot {
                name: "ge5291a".to_string(),
                linux_name: "ge5291a".to_string(),
                ifindex: 5291,
                mtu: 1500,
                hardware_addr: "02:00:00:52:91:0a".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.50.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            // Peer B underlay @1400 (a DIFFERENT egress interface).
            InterfaceSnapshot {
                name: "ge5291b".to_string(),
                linux_name: "ge5291b".to_string(),
                ifindex: 5292,
                mtu: 1400,
                hardware_addr: "02:00:00:52:91:0b".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.60.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id: 1,
            interface: "wgt5291".to_string(),
            linux_name: "wgt5291".to_string(),
            ifindex: 4291,
            mode: "wireguard".to_string(),
            wg_listen_port: 51892,
            wg_local_privkey_hex: WG1866_PRIVKEY_A.to_string(),
            wg_peers: vec![
                TunnelWgPeerSnapshot {
                    wg_peer_pubkey_hex: WG1866_PUBKEY.to_string(),
                    wg_allowed_ips: vec!["10.71.0.0/24".to_string()],
                    wg_endpoint: "10.50.0.9:9".to_string(),
                    ..Default::default()
                },
                TunnelWgPeerSnapshot {
                    wg_peer_pubkey_hex: WG5291_PUBKEY_B.to_string(),
                    wg_allowed_ips: vec!["10.72.0.0/24".to_string()],
                    wg_endpoint: "10.60.0.9:9".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh_runtime_snapshot must succeed");

    // The per-peer map captured at spawn (the output of
    // `resolve_wg_per_peer_outer_mtus`, handed by value into the control
    // thread) is retained on the entry — assert on it directly, mirroring
    // the wg2921 `spawned_outer_mtu` pattern.
    let entry = coordinator.wg_control_threads.get(&1).expect("entry");
    let per_peer = &entry.spawned_per_peer_outer_mtu;
    assert_eq!(
        per_peer.len(),
        2,
        "both endpoint-bearing peers must resolve a per-peer underlay MTU"
    );
    let mut values: Vec<usize> = per_peer.values().copied().collect();
    values.sort_unstable();
    assert_eq!(
        values,
        vec![1400, 1500],
        "each peer must resolve its OWN underlay MTU; a first-peer-scalar \
         revert collapses both to 1500"
    );

    // Precise key association: peer B (over the 1400 underlay) must map to
    // 1400 — proving the lookup is not borrowing peer A's scalar.
    let mut pk_b = [0u8; 32];
    for (i, byte) in pk_b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&WG5291_PUBKEY_B[i * 2..i * 2 + 2], 16).unwrap();
    }
    assert_eq!(
        per_peer.get(&pk_b).copied(),
        Some(1400),
        "peer B must resolve its own 1400 underlay, not peer A's 1500"
    );
    // The interface-level scalar remains peer A's 1500 — the fallback for
    // a peer absent from the per-peer map (learned/roamed endpoint).
    assert_eq!(
        entry.spawned_outer_mtu, 1500,
        "the scalar fallback stays the first endpoint-bearing peer's MTU"
    );
}

// ---------------------------------------------------------------------
// #1881 — GRE local-origin thread lifecycle regression suite.
//
// Same shape as the wg1866 suite above: these drive the REAL spawn
// path; the spawned thread fails open_tun (no TUN privilege in the
// test environment) and exits — exactly the early-exit shape the
// tombstone machinery must handle. On master (pre-#1881) the
// entry-creation pins fail outright: refresh_runtime_snapshot never
// touched tunnel_sources (threads were spawned at bring-up only).
// ---------------------------------------------------------------------

fn gre1881_snapshot(id: u16, ifindex: i32, name: &str, dst: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id,
            interface: name.to_string(),
            linux_name: name.to_string(),
            ifindex,
            mode: "gre".to_string(),
            outer_family: "inet".to_string(),
            source: "192.0.2.1".to_string(),
            destination: dst.to_string(),
            ttl: 64,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// #1881 plan SMR-1: the spawn pass is gated on live worker handles —
/// a thread spawned with zero workers would freeze EMPTY
/// live/identities/worker_commands captures for its lifetime. Tests
/// that want spawns install one fake handle.
fn gre1881_fake_worker_handle() -> WorkerHandle {
    WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(Mutex::new(VecDeque::new())),
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    }
}

fn gre1881_coordinator_with_worker() -> Coordinator {
    let mut coordinator = Coordinator::new();
    // #6242: register the whole runtime record (handle + empty observability
    // slots) as one op.
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle()), None);
    coordinator
}

/// Drive the finished sweep until the entry for `id` is a tombstone.
fn gre1881_wait_tombstone(coordinator: &mut Coordinator, id: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        coordinator.reconcile_local_tunnel_liveness(None);
        match coordinator.tunnel_sources.get(&id) {
            Some(entry) if entry.handle.is_none() => return true,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// THE bug pin (#1881 F3): a same-plan refresh that adds a GRE tunnel
/// must create the local-origin entry AND publish its delivery sender.
/// Fails on master, where refresh never reconciled tunnel_sources.
#[test]
fn gre1881_refresh_creates_entry_and_publishes_delivery() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36281, "gre1881a", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("GRE local-origin entry created on armed refresh");
    assert_eq!(entry.spawned_ifindex, 36281);
    assert_eq!(entry.spawned_tunnel_name, "gre1881a");
    assert!(entry.handle.is_some(), "live handle right after spawn");
    assert!(
        coordinator
            .local_tunnel_deliveries
            .load()
            .contains_key(&36281),
        "delivery sender published for the spawned ifindex"
    );
}

/// #1881 F4: a refresh that REMOVES the tunnel stops + joins the
/// thread, removes the entry, and unpublishes the delivery sender.
#[test]
fn gre1881_removal_refresh_prunes_entry_and_unpublishes() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36282, "gre1881b", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default()).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "removed endpoint prunes the entry"
    );
    assert!(
        coordinator.local_tunnel_deliveries.load().is_empty(),
        "removed endpoint unpublishes the delivery sender"
    );
}

/// #1881 plan SMR-1: the deferred same-plan window reaches the armed
/// refresh with ZERO worker handles — the spawn pass must do nothing.
#[test]
fn gre1881_no_workers_spawn_gate() {
    let mut coordinator = Coordinator::new();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36283, "gre1881c", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "no spawn without live worker handles (frozen empty captures)"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 core property: endpoint CONTENT changes (destination edit,
/// same id + same attachment) must NOT restart the thread — the live
/// loop tracks them through the shared forwarding ArcSwap. No respawn
/// means the spawn-attempt stamp is untouched.
#[test]
fn gre1881_destination_edit_preserves_entry_without_respawn() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36284, "gre1881d", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    let stamp = coordinator
        .tunnel_sources
        .get(&1)
        .expect("entry")
        .last_spawn_attempt_ns;
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36284, "gre1881d", "203.0.113.9")).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("destination edit keeps the entry");
    assert_eq!(
        entry.last_spawn_attempt_ns, stamp,
        "destination-only edit must not respawn (no TUN churn)"
    );
}

/// #1881: attachment drift (same id, new logical ifindex) is the ONLY
/// restart condition — the TUN fd is bound to the old netdev.
#[test]
fn gre1881_attachment_change_restarts_thread() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36285, "gre1881e", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    let stamp = coordinator
        .tunnel_sources
        .get(&1)
        .expect("entry")
        .last_spawn_attempt_ns;
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36286, "gre1881e", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    let entry = coordinator
        .tunnel_sources
        .get(&1)
        .expect("reattached endpoint respawned");
    assert_eq!(entry.spawned_ifindex, 36286, "entry re-spawned on the new ifindex");
    assert!(
        entry.last_spawn_attempt_ns > stamp,
        "attachment change respawns (fresh attempt stamp)"
    );
    let deliveries = coordinator.local_tunnel_deliveries.load();
    assert!(deliveries.contains_key(&36286));
    assert!(
        !deliveries.contains_key(&36285),
        "old attachment's sender unpublished"
    );
}

/// #1881 / Codex plan r1 MAJOR 1 companion: a same-id mode flip
/// gre→wireguard (reachable because ids are name-derived) prunes the
/// GRE entry; the WG pass owns the id from then on.
#[test]
fn gre1881_mode_flip_to_wireguard_prunes_gre_entry() {
    let mut coordinator = gre1881_coordinator_with_worker();
    coordinator.refresh_runtime_snapshot(&gre1881_snapshot(1, 36287, "gre1881f", "198.51.100.7")).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator
        .refresh_runtime_snapshot(&wg1866_snapshot(1, 36287, "gre1881f", crate::test_ports::reserve_ephemeral_udp_port(), WG1866_PRIVKEY_A)).expect("refresh_runtime_snapshot must succeed");
    assert!(
        !coordinator.tunnel_sources.contains_key(&1),
        "mode flip prunes the GRE local-origin entry"
    );
    assert!(
        coordinator.wg_control_threads.contains_key(&1),
        "the WG pass owns the id after the flip"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 (mirrors the #1866 disarmed rule): a disarmed same-plan
/// refresh stops all GRE local-origin threads and empties the
/// delivery map (plan SMR2-2).
#[test]
fn gre1881_disarmed_refresh_stops_threads() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36288, "gre1881g", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.refresh_runtime_snapshot_disarmed(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "disarmed refresh must not hold TUN reader fds"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 (mirrors #1866 Change 2b): the defer-workers narrow prune
/// removes entries absent from (or no longer gre/ip6gre in) the new
/// snapshot and keeps the rest.
#[test]
fn gre1881_defer_prune_removes_only_stale_entries() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36289, "gre1881h", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    // Same snapshot: nothing pruned.
    coordinator.prune_local_tunnel_sources_for_snapshot(&snap);
    assert!(coordinator.tunnel_sources.contains_key(&1));
    // Same id, MOVED attachment (Codex code r1): the defer branch
    // never rotates forwarding, so the prune itself must catch
    // attachment drift against the entry's spawned attachment.
    let moved = gre1881_snapshot(1, 46289, "gre1881h", "198.51.100.7");
    coordinator.prune_local_tunnel_sources_for_snapshot(&moved);
    assert!(
        coordinator.tunnel_sources.is_empty(),
        "same-id attachment drift must prune on the defer path"
    );
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());

    // Re-arm an entry and verify full removal still prunes.
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.prune_local_tunnel_sources_for_snapshot(&ConfigSnapshot::default());
    assert!(coordinator.tunnel_sources.is_empty());
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
}

/// #1881 F6: a thread that exits (open_tun failure here) is
/// tombstoned by the periodic liveness sweep — which must ALSO
/// unpublish its delivery sender (Codex plan r1 R3) — and respawns
/// past the backoff only when the stored snapshot is coherent with
/// the forwarding attachment.
#[test]
fn gre1881_exit_tombstones_sweep_unpublishes_and_respawn_is_coherence_gated() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36290, "gre1881i", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(
        gre1881_wait_tombstone(&mut coordinator, 1, 2_000),
        "open_tun failure tombstones the entry"
    );
    assert!(
        coordinator.local_tunnel_deliveries.load().is_empty(),
        "sweep republishes the delivery map without the dead sender"
    );
    // Incoherent snapshot (attachment mismatch): no respawn even past
    // the backoff.
    coordinator
        .tunnel_sources
        .get_mut(&1)
        .expect("tombstone")
        .last_spawn_attempt_ns = 0;
    let mismatched = gre1881_snapshot(1, 99999, "gre1881i", "198.51.100.7");
    coordinator.reconcile_local_tunnel_liveness(Some(&mismatched));
    assert_eq!(
        coordinator
            .tunnel_sources
            .get(&1)
            .expect("tombstone retained")
            .last_spawn_attempt_ns,
        0,
        "incoherent snapshot must not respawn"
    );
    // Coherent snapshot past the backoff: one respawn attempt.
    coordinator.reconcile_local_tunnel_liveness(Some(&snap));
    assert!(
        coordinator
            .tunnel_sources
            .get(&1)
            .expect("entry retained")
            .last_spawn_attempt_ns
            > 0,
        "tombstone respawned past backoff with a coherent snapshot"
    );
}

/// #1881: after stop_inner the entry map and delivery map are empty,
/// and a subsequent liveness sweep cannot create entries (tombstone-
/// only rule), even with a coherent snapshot.
#[test]
fn gre1881_stop_inner_clears_and_sweep_creates_nothing() {
    let mut coordinator = gre1881_coordinator_with_worker();
    let snap = gre1881_snapshot(1, 36291, "gre1881j", "198.51.100.7");
    coordinator.refresh_runtime_snapshot(&snap).expect("refresh_runtime_snapshot must succeed");
    assert!(coordinator.tunnel_sources.contains_key(&1));
    coordinator.stop_inner(false);
    assert!(coordinator.tunnel_sources.is_empty(), "stop clears entries");
    assert!(coordinator.local_tunnel_deliveries.load().is_empty());
    for _ in 0..3 {
        coordinator.reconcile_local_tunnel_liveness(Some(&snap));
        assert!(
            coordinator.tunnel_sources.is_empty(),
            "liveness sweep never creates entries"
        );
    }
}

// ---------------------------------------------------------------------------
// #2440 — reconcile must NOT publish a newer forwarding generation (or tear
// down the prior workers) when a mandatory BPF map FD fails to open. The
// mandatory map open (xsk/heartbeat/sessions) is the real correctness
// boundary, so it runs in a PREFLIGHT before teardown/publish.
// ---------------------------------------------------------------------------

/// Build a minimal snapshot whose three mandatory map pins are populated
/// with sentinel paths (see `bpf_map::pin`): xsk + heartbeat resolve to
/// dummy fds, while `sessions` is forced to fail its open. This isolates
/// the failure to the third mandatory open without any real bpffs pins.
/// `generation` is the new generation the reconcile would publish if it
/// ran to completion.
fn fail_open_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        generation,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{TEST_MAP_PIN_OK}xsk"),
            heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
            sessions: format!("{TEST_MAP_PIN_FAIL}sessions"),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// fail-on-revert regression: with `map_pins.sessions` unopenable, the
/// reconcile must abort in the preflight — leaving the previously
/// published generation intact and NOT advancing `snapshot_installed`
/// / `config_generation`. The xsk + heartbeat opens are forced to
/// "succeed" (dummy fds) so the failure is isolated to the session map,
/// exercising the third mandatory open specifically.
///
/// Fail-on-revert proof: if the fix is reverted so publish happens
/// before the open (the pre-#2440 order), the reconcile stamps the new
/// generation into `validation` + the published `RuntimeView` BEFORE the session
/// open fails, and every assertion below that the prior generation
/// survives will fail.
#[test]
fn reconcile_mandatory_map_open_failure_keeps_prior_generation_published() {
    let mut coordinator = Coordinator::new();

    // Seed a prior, successfully-published forwarding generation. This
    // stands in for "stale-but-correct state backed by running workers".
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 3,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        bound: true,
        ready: true,
        ..BindingStatus::default()
    }];

    // `fail_open_snapshot` wires xsk + heartbeat to "succeed" (dummy
    // fds) and `sessions` to fail its open, so the failure is isolated
    // to the third mandatory open. The optional maps (conntrack/dnat)
    // are empty so they are never opened.
    let _ = coordinator.reconcile(Some(&fail_open_snapshot(8)), &mut bindings, 64);

    // The reconcile aborted at the session-map open.
    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::OpenMapFailed { map: "session", .. }
        ),
        "expected abort at session-map open, got {:?}",
        coordinator.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .starts_with("open_session_map_failed:")
    );

    // FAIL-ON-REVERT CORE: the prior generation is still the published
    // one. A pre-#2440 publish-before-open would have advanced these to
    // generation 8 before the session open failed.
    assert_eq!(
        coordinator.validation.config_generation, 7,
        "config_generation must NOT advance on a mandatory-FD failure"
    );
    assert_eq!(
        coordinator.validation.fib_generation, 3,
        "fib_generation must NOT advance on a mandatory-FD failure"
    );
    assert!(
        coordinator.validation.snapshot_installed,
        "snapshot_installed must stay at its prior value"
    );
    let shared = coordinator.published_validation();
    assert_eq!(
        shared.config_generation, 7,
        "the published RuntimeView (the worker-visible pair) must still hold the prior generation"
    );
    assert_eq!(
        shared, prior,
        "the published validation must equal the prior published state"
    );

    // The registered binding records the open failure for the operator.
    assert!(
        bindings[0].last_error.starts_with("open session map:"),
        "expected per-binding last_error to record the session-map open failure, got {:?}",
        bindings[0].last_error
    );

    // No workers were brought up (the abort precedes bring-up).
    assert!(
        coordinator.workers.live.is_empty(),
        "no workers should be live after an aborted reconcile"
    );
}

/// A missing (empty) mandatory pin string must abort in the preflight
/// the same way an unopenable FD does — before any publish.
#[test]
fn reconcile_missing_session_pin_keeps_prior_generation_published() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 11,
        fib_generation: 5,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory xsk + heartbeat present, sessions deliberately empty.
    let mut snap = fail_open_snapshot(12);
    snap.map_pins.sessions = String::new();

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.last_reconcile_stage,
        ReconcileStage::MissingPin(MandatoryPin::Session),
        "expected abort at the missing-session-pin guard"
    );
    assert_eq!(
        coordinator.last_reconcile_stage.to_string(),
        "missing_session_pin"
    );
    assert_eq!(coordinator.validation.config_generation, 11);
    assert_eq!(coordinator.published_validation().config_generation, 11);
    assert_eq!(
        bindings[0].last_error, "missing session map pin path",
        "expected per-binding last_error for the missing session pin"
    );
}

/// Positive control: when all mandatory pins open, the reconcile
/// proceeds past the preflight and DOES advance the published
/// generation (proving the preflight is not over-gating legitimate
/// applies). Bring-up itself is exercised by the broader reconcile
/// fixtures; here we only assert the publish happened.
#[test]
fn reconcile_all_mandatory_maps_open_advances_published_generation() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new(); // #6637
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 1,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // All three mandatory pins resolve to dummy fds (sentinel-OK), so
    // the preflight passes and the reconcile proceeds to publish.
    let mut snap = fail_open_snapshot(2);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 2,
        "a fully-openable snapshot must advance the published generation"
    );
    assert_eq!(coordinator.published_validation().config_generation, 2);
}

/// #3789: a snapshot that PASSES the policy preflight and opens every
/// mandatory map, but FAILS the pre-teardown forwarding build (here an
/// unparseable interface address), must return
/// `Err(ReconcileError::Integrity(_))` — NOT the old `()` that silently
/// swallowed the reject — while leaving the prior published generation
/// intact (build fails BEFORE teardown, #2484). This is the coordinator-
/// level half of the fix: the control-plane handler relies on this Err to
/// fail closed on the full-apply / same-plan-needs-reconcile legs.
///
/// Fail-on-revert: before #3789 `reconcile` returned `()` and
/// `build_reconcile_forwarding` discarded the error to `()`; the
/// `matches!(..., Err(ReconcileError::Integrity(_)))` assertion cannot be
/// expressed against a `()` return, so reverting the signature re-breaks
/// the handler's ability to observe the reject.
#[test]
fn reconcile_build_failure_returns_integrity_err_and_keeps_prior_generation_3789() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 7,
        fib_generation: 3,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // All three mandatory pins open (sentinel-OK) so the preflight passes
    // and control reaches the fallible `build_reconcile_forwarding`.
    let mut snap = fail_open_snapshot(8);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    // An unparseable interface address (/33 is invalid for IPv4) makes the
    // forwarding build fail with a non-policy integrity error.
    snap.interfaces = vec![crate::protocol::snapshot::InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        ifindex: 10,
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.0.0/33".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }];

    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(result, Err(ReconcileError::Integrity(_))),
        "a non-policy forwarding-build failure must surface as Err(Integrity), got {result:?}"
    );
    assert_eq!(
        coordinator.validation.config_generation, 7,
        "the rejected build must not advance the published generation"
    );
    assert_eq!(
        coordinator.published_validation().config_generation,
        7,
        "the rejected build must not advance the worker-visible generation"
    );
}

/// #3789: the mandatory-map preflight failure surfaces as
/// `Err(ReconcileError::MapSetup(..))` (not `()`), carrying the
/// `last_reconcile_stage` descriptor, so the handler can fail closed on
/// an unopenable-pin reject too (the #2440 sibling of the build reject).
#[test]
fn reconcile_missing_pin_returns_map_setup_err_3789() {
    let mut coordinator = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let mut snap = fail_open_snapshot(3);
    // Sessions pin empty -> preflight_map_fds aborts at missing_session_pin.
    snap.map_pins.sessions = String::new();

    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    match result {
        Err(ReconcileError::MapSetup(stage)) => {
            assert!(
                matches!(stage, ReconcileStage::MissingPin(MandatoryPin::Session)),
                "unexpected stage: {stage}"
            );
            assert_eq!(stage.to_string(), "missing_session_pin");
        }
        other => panic!("expected Err(MapSetup(missing_session_pin)), got {other:?}"),
    }
}

/// #4952: a worker-thread spawn failure on the POST-TEARDOWN destructive
/// path (`bring_up_workers` -> `spawn_supervised_worker`) must FAIL CLOSED —
/// `reconcile` returns `Err(ReconcileError::WorkerSpawn(_))` and
/// `last_reconcile_stage` RETAINS the `spawn_worker_failed:..` descriptor
/// (it is NOT overwritten with `spawned:workers=..`).
///
/// Before #4952 `bring_up_workers` returned `()`, only LOGGED the spawn
/// failure + recorded an exception, then unconditionally overwrote the
/// stage with `spawned:..` and returned success. So a post-teardown
/// `pthread_create` EAGAIN/ENOMEM left a queue set with NO XSK-bound worker
/// yet `reconcile` returned `Ok(())` — the control handler then acked
/// ok=true AND persisted the broken snapshot as the boot baseline (a silent
/// forwarding outage with no retry). #3789 fail-closes only the PRE-teardown
/// integrity/map legs, not this post-teardown spawn failure.
///
/// The per-instance `force_worker_spawn_fail` seam forces the spawn to
/// return the EAGAIN/ENOMEM error a resource-exhausted `pthread_create`
/// returns (unprovokable in-process), so the propagation is unit-verifiable.
///
/// Fail-on-revert: revert the propagation (`bring_up_workers` back to `()` +
/// the unconditional `spawned:..` stage overwrite) and BOTH the
/// `Err(WorkerSpawn)` match and the `spawn_worker_failed` stage assertion
/// flip (`reconcile` returns `Ok`, stage becomes `spawned:workers=..`).
#[test]
fn reconcile_post_teardown_worker_spawn_failure_fails_closed_4952() {
    let mut coordinator = Coordinator::new();
    // One registered binding => exactly one planned worker to spawn.
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];
    // Force the (only) planned worker's spawn to fail on the post-teardown
    // path — the fallible step the fix propagates.
    coordinator.force_worker_spawn_fail = 1;

    // All mandatory pins open so the reconcile clears the pre-teardown
    // integrity legs, tears down, applies the snapshot, and REACHES the
    // worker spawn (the destructive path #4952 guards).
    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerSpawn(ReconcileStage::SpawnWorkerFailed { .. }))
        ),
        "a post-teardown worker-spawn failure must surface as \
         Err(WorkerSpawn(SpawnWorkerFailed)), got {result:?}"
    );
    // #6244: the spawn-failure identity must be PRESERVED as the typed
    // SpawnWorkerFailed variant (not overwritten with the Spawned success
    // variant). The legacy operator string is preserved byte-for-byte.
    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::SpawnWorkerFailed { .. }
        ),
        "the spawn-failure stage must be PRESERVED (not the Spawned variant), got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        !matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::Spawned { .. }
        ),
        "the reconcile must NOT report a successful spawn after a spawn failure, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .starts_with("spawn_worker_failed:")
    );
    // The seam consumed its single forced failure (no over-fire).
    assert_eq!(
        coordinator.force_worker_spawn_fail, 0,
        "exactly one forced spawn failure should have been consumed"
    );
}

/// #5143: a worker that SPAWNS successfully on the POST-TEARDOWN path but whose
/// IN-THREAD XSK/UMEM bind does NOT bring up its full planned binding set (a
/// partial/empty bind) must FAIL CLOSED — `reconcile` returns
/// `Err(ReconcileError::WorkerBindIncomplete(_))`, the newly-started workers
/// are STOPPED + JOINED (no leaked live-but-unbound worker heartbeating past a
/// fail-closed reconcile), and `last_reconcile_stage` carries the
/// `worker_bind_incomplete:..` descriptor (NOT `spawned:workers=..`).
///
/// This is DISTINCT from #4952: #4952 propagates a worker-thread SPAWN failure
/// (`pthread_create` EAGAIN/ENOMEM) — the thread never runs. #5143 is the
/// POST-SPAWN, in-thread bind failure — the spawn SUCCEEDED and the worker
/// heartbeats, but it bound an incomplete queue set. #4952's spawn-error
/// propagation does not catch it; the per-worker startup readiness barrier
/// (HEARTBEAT != READINESS) does.
///
/// The per-instance `force_worker_bind_incomplete` seam spawns a joinable STUB
/// worker that reports a bound set MISSING one planned slot (a real
/// `worker_loop` cannot bind a real XSK in-process), then heartbeats until the
/// barrier stops it — so the fail-close + stop/join is unit-verifiable.
///
/// Fail-on-revert: remove the readiness barrier (the worker binds partially but
/// `bring_up_workers` returns Ok and the reconcile commits) and BOTH the
/// `Err(WorkerBindIncomplete)` match and the stop/join assertions flip
/// (`reconcile` returns Ok, the stub worker leaks in `workers.records`, and the
/// stage becomes `spawned:workers=..`).
#[test]
fn post_spawn_inthread_bind_failure_fails_closed_5143() {
    let mut coordinator = Coordinator::new();
    // One registered binding => exactly one planned worker to bring up.
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];
    // Force the (only) planned worker to SPAWN but report an INCOMPLETE bound
    // set — the post-spawn in-thread bind failure the fix guards.
    coordinator.force_worker_bind_incomplete = 1;

    // All mandatory pins open so the reconcile clears the pre-teardown
    // integrity legs, tears down, applies the snapshot, and REACHES the worker
    // bring-up + readiness barrier.
    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    // (a) fail closed with the typed post-spawn-bind error.
    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerBindIncomplete(
                ReconcileStage::WorkerBindIncomplete(_)
            ))
        ),
        "a post-spawn in-thread bind failure must surface as \
         Err(WorkerBindIncomplete(WorkerBindIncomplete)), got {result:?}"
    );
    // #6244: the stage identifies the barrier verdict (the typed
    // WorkerBindIncomplete variant), not a spawn success; legacy string kept.
    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::WorkerBindIncomplete(_)
        ),
        "the bind-incomplete stage must be recorded, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        !matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::Spawned { .. }
        ),
        "the reconcile must NOT report a successful spawn after a partial bind, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .starts_with("worker_bind_incomplete:")
    );
    // (c) the newly-started worker was STOPPED + JOINED and its coordinator
    // state cleared — no leaked live-but-unbound worker.
    assert!(
        coordinator.workers.records().is_empty(),
        "the partially-bound worker must be stopped/joined (no leaked handle)"
    );
    assert!(
        coordinator.workers.live.is_empty(),
        "the partially-bound worker's live state must be cleared on fail-close"
    );
    // The seam consumed its single forced incomplete report (no over-fire).
    assert_eq!(
        coordinator.force_worker_bind_incomplete, 0,
        "exactly one forced bind-incomplete report should have been consumed"
    );
}

/// #6242: three registered bindings on distinct worker_ids so `bring_up_workers`
/// plans exactly three workers, iterated in worker-id order.
fn six242_three_worker_bindings() -> Vec<BindingStatus> {
    (0..3u32)
        .map(|i| BindingStatus {
            slot: i + 1,
            worker_id: i,
            queue_id: i,
            interface: "ge-0-0-0".into(),
            ifindex: 10,
            registered: true,
            ..BindingStatus::default()
        })
        .collect()
}

/// #6242 — THE DIFFERENTIAL ROLLBACK (the crux). A PARTIAL-success worker spawn
/// on the POST-TEARDOWN path (workers `0..K-1` launched, worker `K` fails to
/// spawn) must fail the reconcile closed WITHOUT tearing down the launched
/// workers — their consolidated `WorkerRuntimeRecord`s SURVIVE (they are
/// reclaimed by the next reconcile's teardown), and the failed worker never
/// registered a record at all.
///
/// The pre-existing #4952 test uses ONE worker, so partial-success cleanup was
/// UNCHARACTERIZED — `force_worker_spawn_fail` alone always fails the FIRST
/// worker. The #6242 `force_worker_spawn_fail_skip` seam lets the first K
/// workers launch (as benign healthy stubs, `force_worker_healthy_stub`, so no
/// real `worker_loop` runs in-process) before the (K+1)th spawn is forced to
/// fail.
///
/// This pins the invariant the consolidation must preserve: because
/// registration is now ONE `WorkerManager::register` POST-spawn-success, a
/// failed worker has nothing to unwind and the launched records are NEVER
/// touched on the spawn-fail arm. Fail-on-revert: make the spawn-fail arm also
/// call `WorkerManager::stop_and_clear` (or move registration back pre-spawn)
/// and the launched-records-survive assertions below flip RED.
///
/// #7209 note: the recipe above USED to say `coord.workers.records.clear()`,
/// which no longer compiles — `records` is private and `clear_records` is too.
/// A fail-on-revert recipe whose instructions do not build is a guard nobody
/// can run, so it is respelled rather than left as archaeology.
#[test]
fn reconcile_partial_spawn_failure_preserves_launched_records_6242() {
    let mut coordinator = Coordinator::new();
    let mut bindings = six242_three_worker_bindings();
    // Fail the spawn of the THIRD worker (skip the first two), routing the first
    // two through a benign healthy stub so no real dataplane body runs.
    coordinator.force_worker_spawn_fail = 1;
    coordinator.force_worker_spawn_fail_skip = 2;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    // (a) fail closed with the typed post-teardown spawn error.
    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerSpawn(ReconcileStage::SpawnWorkerFailed { worker_id: 2, .. }))
        ),
        "a partial-success spawn failure must surface as \
         Err(WorkerSpawn(SpawnWorkerFailed{{worker_id:2}})), got {result:?}"
    );

    // (b) THE DIFFERENTIAL: workers 0 and 1 LAUNCHED — their records SURVIVE
    // (no stop_inner ran); worker 2 (the failed spawn) has NO record.
    assert_eq!(
        coordinator.workers.records().len(),
        2,
        "launched workers 0 and 1 keep their records (differential rollback)"
    );
    assert!(
        coordinator.workers.records().contains_key(&0)
            && coordinator.workers.records().contains_key(&1),
        "workers 0 and 1 launched before the failure and must still be registered"
    );
    assert!(
        !coordinator.workers.records().contains_key(&2),
        "the failed worker never registered a record (post-spawn insert)"
    );

    // (c) each surviving record carries ALL FOUR owners together — a live
    // (joinable) handle AND its panic / exception-ring / last-resolution slots.
    for wid in [0u32, 1] {
        let records = coordinator.workers.records();
        let rec = records.get(&wid).expect("launched worker record");
        // #7209: the join handle moved from `rec.handle.join` into
        // `WorkerManager::joins` so the record could be published behind an
        // `Arc`. The property asserted is unchanged — a LAUNCHED worker is
        // still joinable, which is the #4952 differential against a spawn
        // failure — only its owner moved, so the assertion moved with it.
        assert!(
            coordinator.workers.has_join_handle(wid),
            "launched worker {wid} keeps a joinable handle (still live)"
        );
        // The three observability Arcs are the SAME allocations registered with
        // the handle in ONE op — the consolidation's point. They are readable
        // (real slots, not phantoms).
        assert!(rec.panic.lock().is_ok());
        assert!(rec.exception_ring.lock().is_ok());
        assert!(rec.last_resolution.lock().is_ok());
    }

    // (d) the seams consumed exactly their budget (no over-fire).
    assert_eq!(coordinator.force_worker_spawn_fail, 0);
    assert_eq!(coordinator.force_worker_spawn_fail_skip, 0);

    // Clean up the two live healthy-stub threads (this is the NEXT reconcile's
    // teardown that reclaims them). stop_inner clears ALL records in one step.
    coordinator.stop_inner(false);
    assert!(
        coordinator.workers.records().is_empty(),
        "teardown clears every launched record"
    );
}

/// #6242 — the OTHER side of the differential (symmetric pin). A post-spawn
/// BIND-INCOMPLETE failure (HEARTBEAT != READINESS) fails the reconcile closed
/// via `stop_inner`, which tears down and clears ALL worker records — contrast
/// the spawn-fail partial case above, where launched records survive. Uses
/// THREE workers (worker 0 reports an incomplete bound set; 1 and 2 are healthy
/// stubs) to prove the clear is fleet-wide, not just the one failing worker.
#[test]
fn reconcile_bind_incomplete_clears_all_records_6242() {
    let mut coordinator = Coordinator::new();
    let mut bindings = six242_three_worker_bindings();
    // Worker 0 reports an INCOMPLETE bound set; workers 1 and 2 spawn as healthy
    // stubs (full bound set) so the barrier's verdict is driven solely by 0.
    coordinator.force_worker_bind_incomplete = 1;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerBindIncomplete(
                ReconcileStage::WorkerBindIncomplete(_)
            ))
        ),
        "a post-spawn bind-incomplete must surface as \
         Err(WorkerBindIncomplete(_)), got {result:?}"
    );
    // stop_inner cleared the WHOLE fleet — every record, not just worker 0.
    assert!(
        coordinator.workers.records().is_empty(),
        "bind-incomplete fail-close clears ALL worker records (records.clear via stop_inner)"
    );
    assert!(
        coordinator.workers.live.is_empty(),
        "the workers' live state is cleared on the fail-closed teardown"
    );
}

/// #8388 fixture: three registered AND ARMED bindings on distinct worker ids,
/// so `bring_up_workers` plans exactly three workers and the resulting
/// `BindingStatus` rows are the exact shape the Go auto-rebind wedge predicate
/// reads (`hasBusyBindingsWedgeLocked` counts a binding only when
/// `Registered && Armed`). `six242_three_worker_bindings` leaves `armed` at its
/// `false` default, which is fine for the record-level #6242 pins but would put
/// these cells' rows OUTSIDE the predicate they are about.
fn wedge8388_three_worker_bindings() -> Vec<BindingStatus> {
    (0..3u32)
        .map(|i| BindingStatus {
            slot: i + 1,
            worker_id: i,
            queue_id: i,
            interface: "ge-0-0-0".into(),
            ifindex: 10,
            registered: true,
            armed: true,
            ..BindingStatus::default()
        })
        .collect()
}

/// #8388 — THE PREMISE MEASUREMENT. A per-slot bind failure leaves NO bound
/// sibling, so there is no "one wedged binding among healthy ones" state for a
/// targeted per-slot rebind to spare.
///
/// #8388 proposed a `rebind_slot` control verb (and, per its own follow-up
/// analysis, the per-slot worker lifecycle + per-slot zero-copy quiesce that
/// would have to exist first) on this premise: *"with `Sum min(rx, 16)`
/// bindings the realistic failure is PARTIAL — fifteen bind, one returns
/// EBUSY"*, so the global `rebind` destroys fifteen healthy sockets to recover
/// one.
///
/// The reconcile is a TRANSACTION, and that is what this measures. The #5143
/// startup readiness barrier requires `bound == planned` for EVERY spawned
/// worker; on ANY shortfall `bring_up_workers` calls `stop_inner(false)`, which
/// stops and joins EVERY worker — the ones that bound their full planned set
/// included — and `reconcile`'s closing `refresh_bindings` then routes every
/// now-workerless slot through `zero_unbound_slot`. So the status the Go
/// manager polls after a bind failure reports ZERO bound slots, not fifteen.
/// The disproportion #8388 describes is not reachable from a bind failure: by
/// the time recovery can observe the fault, the healthy siblings are already
/// gone, and a global rebind is exactly proportionate to a globally-down
/// dataplane.
///
/// This cell measures the OPERATOR- and GO-VISIBLE surface (`BindingStatus`),
/// which is what the premise is about. The sibling
/// `reconcile_bind_incomplete_clears_all_records_6242` pins the coordinator
/// INTERNALS (`workers.records` / `workers.live`) for the same reconcile; the
/// two are not interchangeable — `refresh_bindings` is what turns the internal
/// teardown into the reported state, and only the reported state reaches
/// `hasBusyBindingsWedgeLocked`.
///
/// FIXTURE SHAPE IS LOAD-BEARING: three workers, of which TWO bind their full
/// planned set. A single-worker fixture (the shape
/// `post_spawn_inthread_bind_failure_fails_closed_5143` uses) satisfies
/// "nothing is bound" vacuously — there is no sibling to spare — and would stay
/// green against a per-worker-scoped fail-close.
///
/// WHAT THE INSTRUMENT REPORTS IF THE PROPERTY IS FALSE: the sibling positive
/// control `spawn_failure_does_leave_bound_siblings_8388` runs the SAME
/// instrument over the OTHER post-teardown failure class (#4952 spawn failure,
/// which deliberately does NOT `stop_inner`) and reads back a MIXED 2-of-3
/// bound set. The instrument can see "partial"; this reconcile does not produce
/// one.
///
/// Fail-on-revert / mutation: scope the fail-close to the failing worker — drop
/// the `coord.stop_inner(false)` from the `BindIncomplete` arm of
/// `bring_up_workers`, mirroring the #4952 spawn-fail arm — and workers 1 and 2
/// keep their published `live` state, so `refresh_bindings` takes
/// `copy_live_snapshot` for their slots and this cell reds on `bound_slots`
/// being `[2, 3]` instead of empty.
#[test]
fn bind_incomplete_leaves_no_bound_sibling_8388() {
    let mut coordinator = Coordinator::new();
    let mut bindings = wedge8388_three_worker_bindings();
    // Worker 0 reports an INCOMPLETE bound set; workers 1 and 2 spawn healthy
    // and publish bound live state for their full planned sets.
    coordinator.force_worker_bind_incomplete = 1;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerBindIncomplete(
                ReconcileStage::WorkerBindIncomplete(_)
            ))
        ),
        "a post-spawn bind-incomplete must fail the reconcile closed, got {result:?}"
    );

    // THE MEASUREMENT. Not one bound sibling survives the fail-close.
    let bound_slots: Vec<u32> = bindings
        .iter()
        .filter(|binding| binding.bound)
        .map(|binding| binding.slot)
        .collect();
    assert!(
        bound_slots.is_empty(),
        "#8388's premise requires healthy siblings to survive a per-slot bind \
         failure; the reconcile transaction stops every worker, so the reported \
         bound set must be EMPTY, got {bound_slots:?}"
    );
    assert!(
        bindings.iter().all(|binding| !binding.ready),
        "no slot can report ready after a fail-closed reconcile"
    );

    // The rows STAY registered+armed, which is what makes every one of them a
    // `wedged` binding for the Go predicate — the reported shape is "all
    // wedged", never "one wedged among bound siblings".
    assert!(
        bindings
            .iter()
            .all(|binding| binding.registered && binding.armed),
        "registered/armed are not touched by the fail-close, so every slot is \
         counted as wedged by hasBusyBindingsWedgeLocked"
    );
    assert_eq!(
        bindings
            .iter()
            .filter(|binding| binding.registered && binding.armed && !binding.bound)
            .count(),
        bindings.len(),
        "the wedge is FLEET-WIDE: every registered+armed slot is unbound"
    );
}

/// #8388 — THE POSITIVE CONTROL for the cell above. The same instrument, run
/// over the OTHER post-teardown failure class, DOES read back a partial set.
///
/// A #4952 worker SPAWN failure (`pthread_create` EAGAIN/ENOMEM) at worker K
/// deliberately returns WITHOUT `stop_inner`: workers `0..K-1` are already
/// launched and keep running (#6242's differential rollback). So this is the
/// one reachable state in which some slots report bound and others do not —
/// and this cell proves the `bindings`-array instrument can see it. Without
/// this control, `bind_incomplete_leaves_no_bound_sibling_8388` could be green
/// merely because the instrument never reports `bound` for a stub worker.
///
/// It also settles the residual #8388 asks about. The partial state exists, but
/// what is missing at the unbound slots is a WORKER THREAD, not a socket: a
/// `rebind_slot` verb cannot `pthread_create`, so the targeted rebind #8388
/// wants would not repair this either. The global rebind — which re-runs the
/// whole plan, spawning the missing worker — is the proportionate response.
///
/// Fail-on-revert / mutation: make the spawn-fail arm ALSO call
/// `coord.stop_inner(false)` and the surviving `[1, 2]` bound set collapses to
/// empty, reding the assertion below (and, symmetrically, telling you the
/// sibling cell above would then be green for the wrong reason).
#[test]
fn spawn_failure_does_leave_bound_siblings_8388() {
    let mut coordinator = Coordinator::new();
    let mut bindings = wedge8388_three_worker_bindings();
    // Workers 0 and 1 launch as healthy stubs (full bound set published);
    // worker 2's spawn is forced to fail.
    coordinator.force_worker_spawn_fail = 1;
    coordinator.force_worker_spawn_fail_skip = 2;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerSpawn(
                ReconcileStage::SpawnWorkerFailed { worker_id: 2, .. }
            ))
        ),
        "a partial-success spawn failure must surface as \
         Err(WorkerSpawn(SpawnWorkerFailed{{worker_id:2}})), got {result:?}"
    );

    // THE CONTROL: a MIXED set — slots 1 and 2 (workers 0 and 1) bound, slot 3
    // (the worker that never spawned) not.
    let bound_slots: Vec<u32> = bindings
        .iter()
        .filter(|binding| binding.bound)
        .map(|binding| binding.slot)
        .collect();
    assert_eq!(
        bound_slots,
        vec![1, 2],
        "the launched workers' slots must still report bound — otherwise the \
         sibling #8388 cell's empty bound set proves nothing about the \
         fail-close and only that the instrument never reports bound"
    );
    let wedged_slots: Vec<u32> = bindings
        .iter()
        .filter(|binding| binding.registered && binding.armed && !binding.bound)
        .map(|binding| binding.slot)
        .collect();
    assert_eq!(
        wedged_slots,
        vec![3],
        "exactly the unspawned worker's slot is wedged — a MISSING THREAD, not \
         a missing socket, so a per-slot socket rebind could not repair it"
    );

    // Reclaim the two live healthy-stub threads (the next reconcile's teardown).
    coordinator.stop_inner(false);
}

/// #8558 — THE WIRING CELL. The bind-failure cause must survive the fail-closed
/// teardown **and every subsequent status refresh**, because that ordering is
/// the defect.
///
/// `bring_up_workers`' `BindIncomplete` arm calls `stop_inner(false)`, which
/// empties `workers.live`; `refresh_bindings` then routes every now-workerless
/// slot through `zero_unbound_slot`, whose last act is
/// `binding.last_error.clear()`. So the `"Device or resource busy"` the bind
/// actually returned was erased before any status left the helper, and
/// `hasBusyBindingsWedgeLocked`'s `busyErr` term — a substring match on exactly
/// that field — could never be true. Its only other route in, `repaired`, needs
/// a forwarding-LIVE (`Ready`) binding, of which a fail-closed reconcile leaves
/// none. Recovery for the fault it exists for was unreachable while looking
/// alive.
///
/// THE SECOND REFRESH IS THE POINT, and it is what a hand-built fixture cannot
/// see. `refresh_status` runs `refresh_bindings` on EVERY control response, so
/// a fix that restored the cause once — into the `bindings` array at the end of
/// `reconcile`, say — is erased by the next ~1 Hz status poll, well inside the
/// 5s dwell the Go predicate requires before it acts. The existing Go cells
/// (`partial_wedge_recovery_7497_test.go`) construct a `BindingStatus` with the
/// error already in it, so they stay green against either version; only driving
/// the real teardown-then-refresh-then-refresh order separates them.
///
/// Fixture is three workers, one binding short — the same shape as the #8388
/// cells, so the healthy siblings are present and the assertion below that they
/// carry NO cause is not vacuous.
///
/// Fail-on-revert / mutations:
/// - Delete the `record_bind_failure_causes(coord, &stage)` call from the
///   `BindIncomplete` arm (master's behaviour): the first `last_error`
///   assertion reds with an empty string.
/// - Move that call ABOVE `coord.stop_inner(false)`: `stop_inner` clears the
///   map it just wrote and the same assertion reds. Ordering IS the fix.
/// - Delete the restore in `Coordinator::refresh_bindings`: the cause never
///   reaches `BindingStatus` at all and the same assertion reds.
#[test]
fn bind_failure_cause_survives_the_failclosed_teardown_8558() {
    let mut coordinator = Coordinator::new();
    let mut bindings = wedge8388_three_worker_bindings();
    coordinator.force_worker_bind_incomplete = 1;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerBindIncomplete(
                ReconcileStage::WorkerBindIncomplete(_)
            ))
        ),
        "the fixture must reach the fail-closed bind-incomplete arm, got {result:?}"
    );

    // The failing slot is worker 0's only planned slot (slot 1): the seam drops
    // the SMALLEST planned slot and reports it as the explicit failure.
    let failed = &bindings[0];
    assert_eq!(failed.slot, 1, "fixture drift: worker 0 owns slot 1");
    assert!(
        failed
            .last_error
            .to_lowercase()
            .contains("resource busy"),
        "the reconcile that stopped every worker must still publish WHY slot {} \
         could not bind — this is the exact substring \
         hasBusyBindingsWedgeLocked's busyErr term matches, and master left it \
         empty. got {:?}",
        failed.slot,
        failed.last_error
    );

    // The siblings bound; they have no cause, and must not inherit one.
    for binding in &bindings[1..] {
        assert!(
            binding.last_error.is_empty(),
            "slot {} did not fail its bind and must carry no cause, got {:?}",
            binding.slot,
            binding.last_error
        );
    }

    // THE ORDERING HALF. Two more refreshes — the ~1 Hz status polls that follow
    // the failed reconcile. The cause must still be there on both; the Go
    // predicate does not act until it has seen the wedge for 5s, so a cause that
    // survives only the reconcile's own refresh is a cause that never fires
    // recovery.
    for poll in 1..=2 {
        coordinator.refresh_bindings(&mut bindings);
        assert!(
            bindings[0]
                .last_error
                .to_lowercase()
                .contains("resource busy"),
            "status poll {poll} erased the bind-failure cause; the Go wedge \
             predicate needs it to persist past the 5s dwell. got {:?}",
            bindings[0].last_error
        );
        assert!(
            bindings[1..]
                .iter()
                .all(|binding| binding.last_error.is_empty()),
            "status poll {poll} spread the cause onto a slot that did not fail"
        );
    }
}

/// #8558 — THE MIDDLE STATE: a fault that self-clears must leave nothing behind.
///
/// Runs both reconciles on ONE coordinator, which is what makes it the
/// transient case rather than two independent snapshots: the first fails closed
/// and records the cause, the second (the retry a rebind or a commit drives)
/// succeeds. Afterwards every slot is bound and carries no error, so the Go
/// wedge predicate reads `wedged == 0`, returns false, and resets
/// `consecutiveFailedAutoRebinds` — recovery is armed again for the NEXT fault
/// rather than spending a budget on a fault that is gone.
///
/// This is the state a wrong fix breaks silently. A cause made permanent (or
/// cleared only on a path this sequence does not take) leaves a healthy box
/// advertising `"Device or resource busy"` on bound slots, and a rebind storm
/// is what that buys once anything re-reads it.
///
/// Fail-on-revert / mutation: delete `self.last_bind_failures.clear()` from
/// `stop_inner` and the recorded-state assertion reds (the map still holds
/// slot 1's cause after the successful reconcile). The `last_error` assertions
/// alone would NOT catch that — a bound slot has a `live` entry, so
/// `refresh_bindings` takes `copy_live_snapshot` and never consults the map —
/// which is exactly why the mechanism is asserted alongside the observable.
#[test]
fn a_recovered_reconcile_leaves_no_stale_bind_failure_cause_8558() {
    let mut coordinator = Coordinator::new();
    let mut bindings = wedge8388_three_worker_bindings();
    coordinator.force_worker_bind_incomplete = 1;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let first = coordinator.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        matches!(first, Err(ReconcileError::WorkerBindIncomplete(_))),
        "phase 1 must fail closed, got {first:?}"
    );
    assert!(
        !coordinator.last_bind_failures.is_empty(),
        "phase 1 must have recorded a cause, or phase 2 proves nothing"
    );

    // Phase 2: the fault is gone. The seam's bind-incomplete budget was spent by
    // phase 1, so every worker now comes up as a healthy stub and binds its full
    // planned set.
    let second = coordinator.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        second.is_ok(),
        "phase 2 must succeed — the fault self-cleared, got {second:?}"
    );

    assert!(
        coordinator.last_bind_failures.is_empty(),
        "the recovered reconcile must drop the recorded cause; a retained one \
         re-publishes 'resource busy' the moment anything unbinds those slots"
    );
    for binding in &bindings {
        assert!(
            binding.bound,
            "slot {} must be bound after the recovered reconcile",
            binding.slot
        );
        assert!(
            binding.last_error.is_empty(),
            "slot {} still reports {:?} after a successful reconcile",
            binding.slot,
            binding.last_error
        );
    }

    // And the refresh that follows (the next status poll) must not resurrect it.
    coordinator.refresh_bindings(&mut bindings);
    assert!(
        bindings.iter().all(|binding| binding.last_error.is_empty()),
        "a status poll after recovery re-published a stale cause"
    );

    coordinator.stop_inner(false);
}

/// #8558 — the OTHER direction: a slot that is unbound for a LEGITIMATE reason
/// must not inherit the previous fault's cause.
///
/// After a fail-closed reconcile has recorded causes, a disarm (`should_run
/// _afxdp` false -> `Coordinator::stop`) or a config-cleared teardown unbinds
/// every slot on purpose. Those slots take the same `zero_unbound_slot` branch
/// the restore hangs off, so a cause that outlives its worker set would be
/// re-published onto them — an operator reading "Device or resource busy" on a
/// box that was simply disarmed, and a false `busyErr` waiting for whatever
/// re-arms it.
///
/// Fail-on-revert / mutation: delete `self.last_bind_failures.clear()` from
/// `stop_inner` and this reds — slot 1 comes back carrying the retired
/// generation's bind error.
#[test]
fn a_legitimate_teardown_does_not_inherit_the_bind_failure_cause_8558() {
    let mut coordinator = Coordinator::new();
    let mut bindings = wedge8388_three_worker_bindings();
    coordinator.force_worker_bind_incomplete = 1;
    coordinator.force_worker_healthy_stub = true;

    let snap = mandatory_ok_snapshot(5);
    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        bindings[0]
            .last_error
            .to_lowercase()
            .contains("resource busy"),
        "precondition: the fail-closed reconcile recorded a cause"
    );

    // The disarm path: `reconcile_status_bindings` calls `afxdp.stop()` when
    // forwarding is not armed, then refreshes the bindings.
    coordinator.stop();
    coordinator.refresh_bindings(&mut bindings);

    for binding in &bindings {
        assert!(
            binding.last_error.is_empty(),
            "slot {} inherited the retired generation's bind error {:?} after a \
             deliberate teardown",
            binding.slot,
            binding.last_error
        );
    }
    assert!(
        coordinator.last_bind_failures.is_empty(),
        "the recorded causes must not outlive the worker set they describe"
    );
}

/// #6242 — teardown atomicity / no double-clear. `stop_inner` drops each worker
/// record's FOUR owners (handle + panic + exception ring + last-resolution)
/// EXACTLY ONCE via the teardown's record publish (#7209: `clear_records`,
/// formerly `records.clear()`). The pre-#6242 layout ran three separate
/// `Coordinator.*.clear()` calls PLUS two dead content-clear loops that iterated
/// the already-emptied maps (the #5289 double-clear drift artifact); both are
/// deleted. This asserts the single-drop by holding external clones of the
/// record's observability `Arc`s and checking their strong counts collapse from
/// 2 (record + our clone) to 1 (our clone) after teardown.
#[test]
fn stop_inner_drops_worker_record_owners_exactly_once_6242() {
    let mut coordinator = Coordinator::new();
    // Seed one worker record; retain external clones of its observability Arcs.
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let panic = rec.panic.clone();
    let exception_ring = rec.exception_ring.clone();
    let last_resolution = rec.last_resolution.clone();
    coordinator.workers.register(0, rec, None);

    // Two owners each: the registered record + our external clone.
    assert_eq!(Arc::strong_count(&panic), 2, "record + external clone own the panic slot");
    assert_eq!(Arc::strong_count(&exception_ring), 2);
    assert_eq!(Arc::strong_count(&last_resolution), 2);

    coordinator.stop_inner(false);

    // the teardown's record publish dropped the record — and its four owners
    // — exactly once (#7209: `clear_records`, formerly `records.clear()`).
    assert!(
        coordinator.workers.records().is_empty(),
        "stop_inner clears the records map"
    );
    assert_eq!(
        Arc::strong_count(&panic),
        1,
        "the record's panic Arc is dropped exactly once (no lingering owner)"
    );
    assert_eq!(
        Arc::strong_count(&exception_ring),
        1,
        "the record's exception-ring Arc is dropped exactly once"
    );
    assert_eq!(
        Arc::strong_count(&last_resolution),
        1,
        "the record's last-resolution Arc is dropped exactly once"
    );
}

/// #6245: a post-spawn in-thread bind failure must now be reported EXPLICITLY.
/// The `WorkerStartupReport` carries a typed per-slot `BindingSetupFailure`
/// (worker + slot + phase + owned error) instead of signalling the failure
/// ONLY by OMITTING the failed slot from a success-shaped `bound_slots` list.
/// The readiness barrier surfaces that explicit cause into the fail-closed
/// reconcile stage, so the `worker_bind_incomplete:..` descriptor now names the
/// slot, phase, and reason — not just the `bound=N:planned=M` set-difference
/// counts.
///
/// This is the #6245 contract change over #5143: #5143 established
/// HEARTBEAT != READINESS (a partial bind fails the reconcile closed by
/// set-difference); #6245 makes the CAUSE of that shortfall explicit in the
/// report and the surfaced stage.
///
/// The `force_worker_bind_incomplete` stub reports a bound set short by one
/// slot AND a matching explicit `BindingSetupFailure` for the dropped (smallest
/// planned) slot — modelling what the real `worker_loop_setup` Err arm now
/// records — so the report->barrier->stage explicit-failure path is verified
/// end-to-end without CAP_NET_ADMIN.
///
/// Fail-on-revert: revert the explicit-failure contract (drop the report's
/// `binding_failures` field, or the barrier's `render_binding_setup_failures`
/// append, returning to the pre-#6245 `bound=N:planned=M` omission-only stage)
/// and the `failures=[private:slot=1:..]` assertion below FAILS — the stage no
/// longer carries the typed cause. The pre-#6245 counts-only prefix is
/// deliberately NOT asserted-absent (it is retained), so this pins the ADDED
/// explicit cause, not its formatting.
#[test]
fn worker_bind_incomplete_report_carries_explicit_failure_6245() {
    let mut coordinator = Coordinator::new();
    // One registered binding at slot 1 => exactly one planned worker (id 0),
    // one planned slot (1). The stub drops the smallest planned slot (1).
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];
    coordinator.force_worker_bind_incomplete = 1;

    let snap = mandatory_ok_snapshot(5);
    let result = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    // Still fails closed with the typed post-spawn-bind error (the #5143 gate).
    // #6244 composed: the error now carries the typed `ReconcileStage`
    // (`WorkerBindIncomplete` variant), not a free-form `String`.
    assert!(
        matches!(
            result,
            Err(ReconcileError::WorkerBindIncomplete(
                ReconcileStage::WorkerBindIncomplete(_)
            ))
        ),
        "a post-spawn in-thread bind failure must surface as \
         Err(WorkerBindIncomplete(WorkerBindIncomplete)), got {result:?}"
    );
    // Render the typed stage to its legacy operator string for the
    // substring assertions below (the #6245 explicit-cause contract lives in
    // the rendered form).
    let stage = coordinator.last_reconcile_stage.to_string();
    assert!(
        stage.starts_with("worker_bind_incomplete:"),
        "the bind-incomplete stage must be recorded, got {stage:?}"
    );
    // #6245 core assertion: the EXPLICIT typed failure (phase + slot) reached
    // the barrier via WorkerStartupReport.binding_failures and is surfaced in
    // the stage — NOT inferred solely from the shorter bound_slots list.
    assert!(
        stage.contains("failures=[private:slot=1:"),
        "the stage must carry the EXPLICIT per-slot binding-setup failure \
         (phase + slot), not just the bound/planned counts, got {stage:?}"
    );
    // The owned error reason string propagated end-to-end (report -> barrier).
    assert!(
        stage.contains("forced private bind failure (test seam #6245)"),
        "the explicit failure's owned reason must propagate into the stage, \
         got {stage:?}"
    );
    // The seam consumed its single forced incomplete report (no over-fire).
    assert_eq!(
        coordinator.force_worker_bind_incomplete, 0,
        "exactly one forced bind-incomplete report should have been consumed"
    );
}

/// #6240: the on-demand neighbor resolver is ATTEMPTED before the worker launch
/// (so `WorkerSharedDataplane::from_coord` captures a live handle for every
/// worker), and that attempt is BEST-EFFORT. `ensure_resolver` returns the
/// installed handle as an `Option` and is guarded by `resolver.is_none()` so a
/// re-reconcile REUSES the existing thread rather than re-spawning. This pins
/// the ORDERING/ATTEMPT contract — attempt-before-launch, resolver as an
/// `Option` — NOT "resolver must exist": the resolver is NEVER threaded into
/// `spawn_workers` as a required input (a compile-time property of its
/// signature), so a resolver spawn failure would leave `neighbors.resolver`
/// `None` and workers would still launch with `resolver: None`.
///
/// Fail-on-revert: drop the `is_none()` reuse guard in `ensure_resolver` (so it
/// re-spawns a fresh resolver every reconcile) and the `Arc::ptr_eq` reuse
/// assertion below FAILS — the second attempt returns a different handle. Making
/// `ensure_resolver` mandatory (returning the handle threaded into
/// `spawn_workers`) would not compile against the best-effort `Option` return
/// this test asserts.
#[test]
fn ensure_resolver_attempts_before_launch_best_effort_6240() {
    let mut coordinator = Coordinator::new();
    // A fresh coordinator has no resolver installed — the attempt has not run.
    assert!(
        coordinator.neighbors.resolver.is_none(),
        "a fresh coordinator has no resolver before bring-up attempts one"
    );

    // ATTEMPT (pre-launch): `ensure_resolver` spawns + installs the shared
    // resolver and RETURNS the installed handle as `Some` — the best-effort
    // `Option` (it would be `None` on a spawn failure). The shell runs exactly
    // this BEFORE `spawn_workers`, so each worker's `from_coord` clone captures a
    // live handle.
    let installed = reconcile::bringup::ensure_resolver(&mut coordinator);
    assert!(
        installed.is_some(),
        "ensure_resolver returns the installed handle (Some) on a successful attempt"
    );
    assert!(
        coordinator.neighbors.resolver.is_some(),
        "the resolver is installed on coord so a worker's from_coord captures it before launch"
    );

    // BEST-EFFORT / idempotent: the `is_none()` guard makes a re-reconcile REUSE
    // the already-installed resolver thread (never re-spawn). The second attempt
    // returns the SAME `Arc` — proving the guarded attempt, not an unconditional
    // spawn.
    let again = reconcile::bringup::ensure_resolver(&mut coordinator);
    assert!(again.is_some());
    assert!(
        Arc::ptr_eq(installed.as_ref().unwrap(), again.as_ref().unwrap()),
        "a re-reconcile reuses the already-installed resolver (guarded attempt), never re-spawns"
    );

    // Clean up the spawned resolver thread (stop + join) — the resolver retains
    // a join handle exactly so `stop_inner` can reclaim it.
    coordinator.stop_inner(false);
    assert!(
        coordinator.neighbors.resolver.is_none(),
        "stop_inner joins + clears the resolver"
    );
}

/// #5171: the side-effect-free `validate_snapshot_buildable` gate (used by
/// the deferred-activation apply path, which never reaches `reconcile`) and
/// the worker-spawning `reconcile` MUST reject the IDENTICAL non-buildable
/// snapshots — same `ReconcileError` variant, same stage descriptor — so the
/// defer path can never drift from the path that actually builds forwarding.
/// This locks the no-drift guarantee that lets the defer branch reuse the
/// integrity legs without duplicating their logic.
///
/// Two failure classes are checked: a MISSING mandatory map pin
/// (`ReconcileError::MapSetup`) and a forwarding-build integrity fault —
/// unparseable interface address (`ReconcileError::Integrity`). A fully
/// buildable snapshot passes both; a `None` snapshot (teardown) is trivially
/// buildable.
///
/// Fail-on-revert: `validate_snapshot_buildable` calls the SAME
/// `preflight_policy_state` / `validate_map_pins` (open the same pins) /
/// `build_forwarding_state_..` primitives `reconcile` runs; a drift in
/// either path (e.g. skipping the map-pin or forwarding leg) makes one of
/// the paired assertions below diverge.
#[test]
fn validate_snapshot_buildable_matches_reconcile_5171() {
    // --- Class 1: a MISSING mandatory map pin -----------------------------
    let mut missing_pin = fail_open_snapshot(8);
    missing_pin.map_pins.sessions = String::new(); // -> missing_session_pin

    let mut recon_coord = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let recon = recon_coord.reconcile(Some(&missing_pin), &mut bindings, 64);
    assert!(
        matches!(
            &recon,
            Err(ReconcileError::MapSetup(ReconcileStage::MissingPin(MandatoryPin::Session)))
        ),
        "reconcile must reject the missing-session-pin snapshot at missing_session_pin, got {recon:?}"
    );

    // validate rejects the SAME snapshot with the SAME MapSetup stage, on a
    // FRESH coordinator with NO bindings — proving it needs neither.
    let validate_coord = Coordinator::new();
    let validated = validate_coord.validate_snapshot_buildable(Some(&missing_pin));
    assert!(
        matches!(
            &validated,
            Err(ReconcileError::MapSetup(ReconcileStage::MissingPin(MandatoryPin::Session)))
        ),
        "validate_snapshot_buildable must reject the same snapshot with the same MapSetup stage, got {validated:?}"
    );
    // Side-effect-free: no workers spawned, no per-binding error stamped.
    assert!(
        validate_coord.workers.live.is_empty(),
        "validate_snapshot_buildable must not bring up workers"
    );

    // --- Class 2: a forwarding-build integrity fault ----------------------
    let mut bad_build = fail_open_snapshot(9);
    bad_build.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions"); // all pins open
    bad_build.interfaces = vec![crate::protocol::snapshot::InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        ifindex: 10,
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.0.0/33".to_string(), // unparseable -> Integrity
            ..Default::default()
        }],
        ..Default::default()
    }];

    let mut recon_coord2 = Coordinator::new();
    let mut bindings2: Vec<BindingStatus> = Vec::new();
    let recon2 = recon_coord2.reconcile(Some(&bad_build), &mut bindings2, 64);
    assert!(
        matches!(recon2, Err(ReconcileError::Integrity(_))),
        "reconcile must reject the unparseable-address snapshot as Integrity, got {recon2:?}"
    );
    let validate_coord2 = Coordinator::new();
    assert!(
        matches!(
            validate_coord2.validate_snapshot_buildable(Some(&bad_build)),
            Err(ReconcileError::Integrity(_))
        ),
        "validate_snapshot_buildable must reject the same snapshot as Integrity"
    );

    // --- Buildable + None both pass validate ------------------------------
    let mut ok_snap = fail_open_snapshot(10);
    ok_snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    let ok_coord = Coordinator::new();
    assert!(
        ok_coord.validate_snapshot_buildable(Some(&ok_snap)).is_ok(),
        "a fully-buildable snapshot must pass validate_snapshot_buildable"
    );
    assert!(
        ok_coord.validate_snapshot_buildable(None).is_ok(),
        "a None snapshot (teardown) is trivially buildable"
    );
}

/// #5171 rev-5605 fold: `validate_snapshot_buildable` must NOT mutate the
/// live published `coord.forwarding.zone_counter_store`. Leg 3's forwarding
/// build carries the zone-counter store forward from `previous`, and that
/// store's `Clone` SHARES the inner `Arc<Mutex>` — so a build that passed
/// `Some(&coord.forwarding)` would `.reconcile(retain)` the LIVE store IN
/// PLACE, dropping cumulative per-zone totals for any zone absent from the
/// candidate snapshot (a mutation of the live `show security zones` / REST /
/// Prometheus surface that fires even when validation ultimately rejects and
/// that the fail-closed restore cannot undo). The fix passes `previous =
/// None`, so the discarded validation build gets a FRESH store and touches
/// nothing live.
///
/// Fail-on-revert: reverting `validate_forwarding_buildable` to `previous =
/// Some(&coord.forwarding)` prunes zone B (absent from the candidate) from
/// the live store → the `after.contains(B)` assertion FAILS.

#[test]
fn validate_snapshot_buildable_does_not_prune_live_zone_counters_5171() {
    use crate::afxdp::zone_counters::{
        flush_recorded_zone_counters, record_zone_traffic, ZoneCounterSlotMap,
    };
    const ZONE_A: u16 = 100;
    const ZONE_B: u16 = 200;

    let coord = Coordinator::new();
    // Seed the LIVE forwarding zone-counter store with cumulative totals for
    // zones A and B, as steady-state forwarded traffic would.
    // #5163: build the seed map FROM the live store so its cached per-zone
    // atomics are the coordinator's — the lock-free fold then lands directly in
    // `coord.forwarding.zone_counter_store`.
    let seed_map =
        ZoneCounterSlotMap::build(&[ZONE_A, ZONE_B], &coord.forwarding.zone_counter_store);
    record_zone_traffic(&seed_map, ZONE_A, ZONE_B, 1000);
    record_zone_traffic(&seed_map, ZONE_B, ZONE_A, 500);
    flush_recorded_zone_counters(&coord.forwarding.zone_counter_store, &seed_map);
    let before: std::collections::HashSet<u16> = coord
        .forwarding
        .zone_counter_store
        .snapshot()
        .into_iter()
        .map(|r| r.zone_id)
        .collect();
    assert!(
        before.contains(&ZONE_A) && before.contains(&ZONE_B),
        "precondition: live store must carry both zones, got {before:?}"
    );

    // A buildable candidate that configures ONLY zone A (drops B). Mandatory
    // pins open so validation reaches Leg 3's forwarding build and its
    // zone-counter reconcile.
    let candidate = ConfigSnapshot {
        generation: 2,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{TEST_MAP_PIN_OK}xsk"),
            heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
            sessions: format!("{TEST_MAP_PIN_OK}sessions"),
            ..Default::default()
        },
        zones: vec![crate::protocol::snapshot::ZoneSnapshot {
            name: "A".to_string(),
            id: ZONE_A,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(
        coord.validate_snapshot_buildable(Some(&candidate)).is_ok(),
        "the single-zone candidate must be buildable"
    );

    // The live store must be UNTOUCHED — zone B's totals survive even though
    // the candidate does not configure zone B.
    let after: std::collections::HashSet<u16> = coord
        .forwarding
        .zone_counter_store
        .snapshot()
        .into_iter()
        .map(|r| r.zone_id)
        .collect();
    assert!(
        after.contains(&ZONE_A) && after.contains(&ZONE_B),
        "validate_snapshot_buildable must NOT prune the live zone-counter store; got {after:?} (zone B dropped = the rev-5605 leak)"
    );
}

// ── #6832 fold r5: the prune's commit point is the APPLY, not the build ──
//
// The r2 restructuring moved the per-zone counter binding out of the fallible
// builder so a snapshot rejected by an INTEGRITY belt could not touch the live
// store. That is necessary and it holds — but it is not the whole rejection
// surface. A build can succeed and the apply still be rejected AFTERWARDS, by a
// worker-thread spawn failure (#4952) or an incomplete queue bind (#5143).
// Measured on the branch before this fold, with live zones {100,200} carrying
// folded traffic, candidate {100,300}, and `force_worker_spawn_fail = 1`:
//
//   visible rows  [100, 200] -> [100]
//   tracked ids   [100, 200] -> [100, 300]
//
// Zone 200's cumulative totals were destroyed by a configuration that never
// brought up a single worker. The `WorkerSpawn` arm is the one that makes this
// operator-visible rather than merely internal: unlike `WorkerBindIncomplete`
// (which calls `stop_inner` and defaults `coord.forwarding`), it returns with
// the candidate state still PUBLISHED, so `show security zones` keeps reporting
// from the store it just pruned.
//
// The destructive prune therefore moved to `forwarding_build::
// commit_zone_counter_prune`, called by each apply path at ITS commit point.
// The three tests below are one per direction, and they are not
// interchangeable: the first binds that the prune is NOT at build time, the
// second and third bind that each production call site still performs it.

/// Seed `coord.forwarding` with zones 100 and 200 and fold traffic into both,
/// then hand back the snapshot that produced it. The store is `Arc`-shared, so
/// what this seeds is what an apply would mutate in place.
fn zone_counter_live_coordinator(coord: &mut Coordinator) {
    use crate::afxdp::zone_counters::{flush_recorded_zone_counters, record_zone_traffic};
    let mut baseline = mandatory_ok_snapshot(5);
    baseline.zones = zone_counter_zones(&[100, 200]);
    coord.set_forwarding_for_test(crate::afxdp::forwarding_build::build_forwarding_state_with_policy_counters_and_previous(
            &baseline,
            &coord.policy_counters,
            &coord.nat_counters,
            None,
        )
        .expect("the baseline zone snapshot must build"));
    record_zone_traffic(&coord.forwarding.zone_counter_slot_map, 100, 200, 64);
    record_zone_traffic(&coord.forwarding.zone_counter_slot_map, 200, 100, 64);
    flush_recorded_zone_counters(
        &coord.forwarding.zone_counter_store,
        &coord.forwarding.zone_counter_slot_map,
    );
    assert_eq!(
        zone_counter_rows(coord),
        vec![100, 200],
        "fixture: both zones must be counting before the apply under test"
    );
}

fn zone_counter_zones(ids: &[u16]) -> Vec<crate::protocol::snapshot::ZoneSnapshot> {
    ids.iter()
        .map(|&id| crate::protocol::snapshot::ZoneSnapshot {
            name: format!("zone{id}"),
            id,
            ..Default::default()
        })
        .collect()
}

/// Operator-visible rows, sorted — what `show security zones` reports.
fn zone_counter_rows(coord: &Coordinator) -> Vec<u16> {
    let mut rows: Vec<u16> = coord
        .zone_traffic_counters()
        .iter()
        .map(|r| r.zone_id)
        .collect();
    rows.sort_unstable();
    rows
}

fn zone_counter_binding() -> Vec<BindingStatus> {
    vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }]
}

#[test]
fn rejected_apply_does_not_prune_live_zone_counters_6832() {
    // The NEGATIVE direction. A build that succeeded but whose workers failed
    // to spawn is a rejected apply: zone 200's totals must survive it, ready
    // for the retry or the operator's revert.
    //
    // Reds if `commit_zone_counter_prune` is hoisted back into
    // `attach_zone_counters` (or inlined into the builder as the pre-r5 shape
    // had it) — that is the whole point of the split, and no assertion in
    // `forwarding_build/tests.rs` can see it, because those drive the builder
    // directly and never reach a worker.
    let mut coordinator = Coordinator::new();
    zone_counter_live_coordinator(&mut coordinator);
    let live_store = coordinator.forwarding.zone_counter_store.clone();

    let mut bindings = zone_counter_binding();
    let mut candidate = mandatory_ok_snapshot(6);
    candidate.zones = zone_counter_zones(&[100, 300]);
    coordinator.force_worker_spawn_fail = 1;
    let result = coordinator.reconcile(Some(&candidate), &mut bindings, 64);

    assert!(
        matches!(result, Err(ReconcileError::WorkerSpawn(_))),
        "fixture: this apply must be rejected by the worker SPAWN arm — the arm \
         that leaves the candidate state published — got {result:?}"
    );
    let mut surviving: Vec<u16> = live_store.snapshot().iter().map(|r| r.zone_id).collect();
    surviving.sort_unstable();
    assert_eq!(
        surviving,
        vec![100, 200],
        "a REJECTED apply pruned zone 200's cumulative totals out of the live, \
         Arc-shared store. The config never brought up a worker, and the \
         WorkerSpawn arm leaves it published — so `show security zones` reports \
         from this store with the removed zone's history already destroyed"
    );
    assert_eq!(
        zone_counter_rows(&coordinator),
        vec![100],
        "fixture: zone 200 is correctly no longer PUBLISHED (the candidate does \
         not configure it) — this test is about its totals surviving in the \
         store, not about republishing an unconfigured zone"
    );
}

/// #7010 fixtures. The policy and NAT HIT-counter twin of the #6832 zone
/// fixtures above, and the same three directions.
///
/// Both stores are seeded through the PRODUCTION entry points — the policy half
/// via `parse_policy_state_with_counters` (which get-or-creates a block per
/// rule) and the NAT half via `NatCounterStore::rule_counter` — so the seeding
/// path is the one the builder itself takes.
const RULE_COUNTER_LIVE_NAT_ID: u32 = 7;
const RULE_COUNTER_DOOMED_NAT_ID: u32 = 4243;
const RULE_COUNTER_LIVE_POLICY_ID: &str = "zone100->zone200/live-rule";
const RULE_COUNTER_DOOMED_POLICY_ID: &str = "zone100->zone200/doomed-rule";

fn rule_counter_policy_snapshots() -> Vec<crate::PolicyRuleSnapshot> {
    ["live-rule", "doomed-rule"]
        .iter()
        .map(|name| crate::PolicyRuleSnapshot {
            name: (*name).into(),
            from_zone: "zone100".into(),
            to_zone: "zone200".into(),
            action: "permit".into(),
            ..Default::default()
        })
        .collect()
}

/// Seed BOTH stores with a live id and a doomed id, and give the live policy
/// rule a non-zero hit count.
///
/// The live id is what separates a correctly deferred prune from a prune that
/// simply never runs: an over-correction that stops pruning entirely passes
/// "the doomed id survived a rejection" and fails
/// `committed_reconcile_prunes_rule_counters_for_removed_rules_7010`.
fn rule_counter_live_coordinator(coord: &mut Coordinator) {
    let mut zone_map = rustc_hash::FxHashMap::default();
    zone_map.insert("zone100".to_string(), 100u16);
    zone_map.insert("zone200".to_string(), 200u16);
    crate::policy::parse_policy_state_with_counters(
        "deny",
        &rule_counter_policy_snapshots(),
        &zone_map,
        &[],
        &coord.policy_counters,
    )
    .expect("the live seed policy must parse");
    // A real total on the LIVE NAT row. This is what separates "the block
    // SURVIVED the prune" from "the build re-created it": a committed reconcile
    // runs the additive get-or-create BEFORE the prune, so a present id alone
    // is satisfied by a freshly minted zero block.
    coord
        .nat_counters
        .rule_counter(RULE_COUNTER_LIVE_NAT_ID)
        .expect("the live NAT counter must be creatable")
        .add(64);
    let _ = coord.nat_counters.rule_counter(RULE_COUNTER_DOOMED_NAT_ID);

    for want in [RULE_COUNTER_LIVE_POLICY_ID, RULE_COUNTER_DOOMED_POLICY_ID] {
        assert!(
            coord.policy_counters.tracked_rule_ids().iter().any(|id| id == want),
            "fixture: policy id {want} must be seeded, or every assertion below is \
             vacuous. Got {:?}",
            coord.policy_counters.tracked_rule_ids()
        );
    }
    let mut nat_ids = coord.nat_counters.tracked_ids();
    nat_ids.sort_unstable();
    assert_eq!(
        nat_ids,
        vec![RULE_COUNTER_LIVE_NAT_ID, RULE_COUNTER_DOOMED_NAT_ID],
        "fixture: both NAT ids must be seeded"
    );
}

/// The candidate: it keeps the live policy rule and the live NAT rule, and
/// DROPS the doomed pair. A committed apply must prune exactly the doomed two.
fn rule_counter_candidate(generation: u64) -> crate::ConfigSnapshot {
    let mut snap = mandatory_ok_snapshot(generation);
    snap.zones = zone_counter_zones(&[100, 200]);
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "live-rule".into(),
        from_zone: "zone100".into(),
        to_zone: "zone200".into(),
        action: "permit".into(),
        ..Default::default()
    }];
    snap.static_nat_rules = vec![crate::StaticNATRuleSnapshot {
        name: "live-static".into(),
        counter_id: RULE_COUNTER_LIVE_NAT_ID,
        external_ip: "198.51.100.7".into(),
        internal_ip: "10.9.9.7".into(),
        ..Default::default()
    }];
    snap
}

fn rule_counter_state(coord: &Coordinator) -> (Vec<String>, Vec<u32>) {
    let mut policy = coord.policy_counters.tracked_rule_ids();
    policy.sort();
    let mut nat = coord.nat_counters.tracked_ids();
    nat.sort_unstable();
    (policy, nat)
}

/// #7010 NEGATIVE, `WorkerSpawn` arm — the arm that leaves the candidate state
/// PUBLISHED, so `nat_rule_counters()` keeps serving from a store the rejected
/// apply already pruned.
///
/// RED before the fix: the prune ran inside `apply_snapshot`, above
/// `bring_up_workers`, so the doomed ids were already gone. Measured on
/// origin/master, both arms.
#[test]
fn rejected_spawn_apply_does_not_prune_live_rule_counters_7010() {
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    // `StoppedCoordinator`, not a trailing `coordinator.stop()`: a cell that
    // PANICS skips the trailing call and leaks its neigh-monitor thread into the
    // process-wide #6637 gates, which then red alongside it. Measured — the
    // first #7010 mutation matrix showed this cell's G1 red carrying two
    // collateral #6637 failures that had nothing to do with the mutation, and a
    // mutation cell that reds three tests when it should red one cannot
    // localise.
    let mut coordinator = StoppedCoordinator::new();
    rule_counter_live_coordinator(&mut coordinator);

    let mut bindings = zone_counter_binding();
    coordinator.force_worker_spawn_fail = 1;
    let result = coordinator.reconcile(Some(&rule_counter_candidate(6)), &mut bindings, 64);
    assert!(
        matches!(result, Err(ReconcileError::WorkerSpawn(_))),
        "fixture: this apply must be rejected by the worker SPAWN arm — got {result:?}"
    );

    let (policy, nat) = rule_counter_state(&coordinator);
    assert!(
        policy.iter().any(|id| id == RULE_COUNTER_DOOMED_POLICY_ID),
        "a REJECTED apply destroyed the hit counter of a policy rule the refused \
         candidate removed. The config never brought up a worker and the \
         WorkerSpawn arm leaves it published, so `show security policies \
         hit-count` serves from a store whose history is already gone — and \
         unlike the zone store, `stop_inner` never resets this one, so it stays \
         gone (#7010). Got {policy:?}"
    );
    assert!(
        nat.contains(&RULE_COUNTER_DOOMED_NAT_ID),
        "same, NAT half: `nat_rule_counters()` serves from this store (#7010). \
         Got {nat:?}"
    );
    assert!(
        policy.iter().any(|id| id == RULE_COUNTER_LIVE_POLICY_ID)
            && nat.contains(&RULE_COUNTER_LIVE_NAT_ID),
        "control: the LIVE ids must also still be present — an assertion that \
         only the doomed ids survive would pass against a store nothing pruned \
         and nothing seeded"
    );
}

/// #7010 NEGATIVE, `WorkerBindIncomplete` arm.
///
/// The zone case only leaked on the spawn arm, because `stop_inner(false)`
/// defaults `coord.forwarding` and takes the zone store's publisher with it.
/// These two stores are Coordinator fields that `stop_inner` never touches, so
/// BOTH arms leak here — which is why this arm gets its own cell rather than
/// being folded into the one above.
#[test]
fn rejected_bind_apply_does_not_prune_live_rule_counters_7010() {
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new();
    rule_counter_live_coordinator(&mut coordinator);

    let mut bindings = zone_counter_binding();
    // No healthy-worker stub: a real XSK bind is impossible in-process, so the
    // reconcile is rejected at the bind-incomplete arm.
    let result = coordinator.reconcile(Some(&rule_counter_candidate(6)), &mut bindings, 64);
    assert!(
        result.is_err(),
        "fixture: this apply must be REJECTED — got {result:?}"
    );

    let (policy, nat) = rule_counter_state(&coordinator);
    assert!(
        policy.iter().any(|id| id == RULE_COUNTER_DOOMED_POLICY_ID)
            && nat.contains(&RULE_COUNTER_DOOMED_NAT_ID),
        "a reconcile rejected at the BIND arm destroyed the removed rules' hit \
         counters. `stop_inner` defaults only `self.forwarding`; policy_counters \
         and nat_counters are untouched, so this arm leaks exactly as the spawn \
         arm does (#7010). policy={policy:?} nat={nat:?}"
    );
}

/// #7010 POSITIVE — the anti-over-fix direction. Deferring the prune must not
/// DELETE it: a COMMITTED apply must still drop the removed rules.
#[test]
fn committed_reconcile_prunes_rule_counters_for_removed_rules_7010() {
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new();
    rule_counter_live_coordinator(&mut coordinator);

    let mut bindings = zone_counter_binding();
    coordinator.force_worker_healthy_stub = true;
    let result = coordinator.reconcile(Some(&rule_counter_candidate(6)), &mut bindings, 64);
    assert!(
        result.is_ok(),
        "fixture: this apply must COMMIT (workers up) — got {result:?}"
    );

    let (policy, nat) = rule_counter_state(&coordinator);
    assert!(
        !policy.iter().any(|id| id == RULE_COUNTER_DOOMED_POLICY_ID),
        "a COMMITTED reconcile must still prune the removed policy rule's \
         counter; deferring the prune past worker bring-up must not delete it. \
         Got {policy:?}"
    );
    assert!(
        !nat.contains(&RULE_COUNTER_DOOMED_NAT_ID),
        "same, NAT half. Got {nat:?}"
    );
    assert!(
        policy.iter().any(|id| id == RULE_COUNTER_LIVE_POLICY_ID),
        "the surviving rule must keep its block across the commit, not be swept \
         with the doomed one — a prune that empties the store passes the two \
         assertions above for the wrong reason. Got {policy:?}"
    );
    assert!(
        nat.contains(&RULE_COUNTER_LIVE_NAT_ID),
        "NAT half of the same control. Got {nat:?}"
    );
    let live_row = coordinator
        .nat_counters
        .snapshots()
        .into_iter()
        .find(|r| r.counter_id == RULE_COUNTER_LIVE_NAT_ID)
        .expect("the live NAT row must still exist after a committed prune");
    assert!(
        live_row.packets > 0,
        "the surviving NAT row must keep its CARRIED-FORWARD totals. A zero here \
         means the block was re-created by the build's get-or-create rather than \
         retained — which the id-presence assertion above cannot tell apart"
    );
}

/// #7010, the REFRESH call site. The reconcile cells above cannot see this one
/// and vice versa — one production line, one assertion.
///
/// This path's prune MOVED in #7010, from above the `self.forwarding` swap to
/// beside the zone prune below it. The move is behaviour-neutral (nothing
/// between the two positions can return, so the prune already ran only on a
/// committed refresh), but "behaviour-neutral" was an unbound claim until this
/// cell existed: deleting the call outright leaves every other test green.
#[test]
fn committed_refresh_prunes_rule_counters_for_removed_rules_7010() {
    let mut coordinator = StoppedCoordinator::new();
    rule_counter_live_coordinator(&mut coordinator);

    coordinator
        .refresh_runtime_snapshot(&rule_counter_candidate(6))
        .expect("fixture: the candidate must refresh cleanly");

    let (policy, nat) = rule_counter_state(&coordinator);
    assert!(
        !policy.iter().any(|id| id == RULE_COUNTER_DOOMED_POLICY_ID)
            && !nat.contains(&RULE_COUNTER_DOOMED_NAT_ID),
        "a COMMITTED same-plan refresh must drop the removed rules' hit counters. \
         policy={policy:?} nat={nat:?}"
    );
    assert!(
        policy.iter().any(|id| id == RULE_COUNTER_LIVE_POLICY_ID)
            && nat.contains(&RULE_COUNTER_LIVE_NAT_ID),
        "...and must keep the surviving rules — a prune that empties the store \
         passes the assertion above for the wrong reason. policy={policy:?} nat={nat:?}"
    );
}

#[test]
fn committed_reconcile_prunes_zone_counters_for_removed_zones_6832() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    // POSITIVE direction, reconcile call site. Anti-over-fix: deferring the
    // prune must not DELETE it. Same zone move, but the workers come up, so the
    // apply commits and zone 200 is dropped.
    //
    // `force_worker_healthy_stub` (#6242) is what makes this reachable in a
    // unit test — a real XSK bind is impossible in-process, and without the
    // stub every reconcile here fails at `WorkerBindIncomplete` and this
    // direction would be untestable. Reds if the `bringup_result.is_ok()`
    // call in `coordinator/reconcile/mod.rs` is deleted.
    // #7810: StoppedCoordinator, not a trailing `coordinator.stop()`. A panic
    // anywhere below skips a trailing call and leaks this test's
    // neigh-monitor into the process-wide #6637 gates, which then red
    // alongside it and read as a real monitor leak.
    let mut coordinator = StoppedCoordinator::new();
    zone_counter_live_coordinator(&mut coordinator);
    let live_store = coordinator.forwarding.zone_counter_store.clone();

    let mut bindings = zone_counter_binding();
    let mut candidate = mandatory_ok_snapshot(6);
    candidate.zones = zone_counter_zones(&[100, 300]);
    coordinator.force_worker_healthy_stub = true;
    let result = coordinator.reconcile(Some(&candidate), &mut bindings, 64);
    assert!(
        result.is_ok(),
        "fixture: this apply must COMMIT (workers up) — got {result:?}"
    );

    let mut surviving: Vec<u16> = live_store.snapshot().iter().map(|r| r.zone_id).collect();
    surviving.sort_unstable();
    assert_eq!(
        surviving,
        vec![100],
        "a COMMITTED reconcile must still drop the removed zone's totals; \
         deferring the prune past worker bring-up must not delete it"
    );
    let survivor = live_store
        .snapshot()
        .into_iter()
        .find(|r| r.zone_id == 100)
        .expect("zone 100 is configured by both generations");
    assert!(
        survivor.ingress_packets > 0,
        "the surviving zone must keep its CARRIED-FORWARD totals across the \
         commit, not restart from zero"
    );
}

#[test]
fn committed_refresh_prunes_zone_counters_for_removed_zones_6832() {
    // POSITIVE direction, refresh call site. The same-plan refresh keeps its
    // live workers, so nothing fallible follows the `self.forwarding` swap and
    // the swap IS the commit. Reds if the `commit_zone_counter_prune` call in
    // `coordinator/snapshot_refresh.rs` is deleted — the reconcile test above
    // cannot see that deletion, and vice versa.
    let mut coordinator = Coordinator::new();
    zone_counter_live_coordinator(&mut coordinator);
    let live_store = coordinator.forwarding.zone_counter_store.clone();

    let mut candidate = mandatory_ok_snapshot(6);
    candidate.zones = zone_counter_zones(&[100, 300]);
    coordinator
        .refresh_runtime_snapshot(&candidate)
        .expect("fixture: the candidate must refresh cleanly");

    let mut surviving: Vec<u16> = live_store.snapshot().iter().map(|r| r.zone_id).collect();
    surviving.sort_unstable();
    assert_eq!(
        surviving,
        vec![100],
        "a COMMITTED same-plan refresh must drop the removed zone's totals"
    );
}

#[test]
fn zone_traffic_counters_drops_a_zone_that_lost_its_slot_6843() {
    // #6843 (Codex gate): drive the PRODUCTION publication accessor,
    // `Coordinator::zone_traffic_counters`, not the extracted
    // `publishable_zone_rows` primitive. The primitive tests in
    // zone_counters.rs prove the filter; they do NOT prove the coordinator
    // calls it, so reverting this accessor to its old inline
    // "configured-only" body left them all green. This test binds the wiring.
    use crate::afxdp::zone_counters::{
        flush_recorded_zone_counters, record_zone_traffic, ZoneCounterSlotMap,
        ZONE_COUNTER_ASSIGNABLE_SLOTS,
    };
    const Z: u16 = 50675; // config::StableZoneID("trust")

    let mut coord = Coordinator::new();

    // Apply 1: Z alone, holding a slot, moving traffic.
    let map1 = ZoneCounterSlotMap::build(&[Z], &coord.forwarding.zone_counter_store);
    record_zone_traffic(&map1, Z, 0, 1500);
    flush_recorded_zone_counters(&coord.forwarding.zone_counter_store, &map1);
    coord.forwarding.zone_counter_slot_map = std::sync::Arc::new(map1);
    coord.forwarding.zone_id_to_name.insert(Z, "trust".to_string());

    let published = coord.zone_traffic_counters();
    assert!(
        published.iter().any(|r| r.zone_id == Z),
        "apply 1: the coordinator must publish a slotted zone with traffic: {published:?}"
    );

    // Apply 2: enough lower ids to exhaust capacity. Z stays CONFIGURED and
    // keeps its retained totals, but loses its slot.
    let mut ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
    ids.push(Z);
    for id in &ids {
        coord
            .forwarding
            .zone_id_to_name
            .insert(*id, format!("z{id}"));
    }
    let map2 = ZoneCounterSlotMap::build(&ids, &coord.forwarding.zone_counter_store);
    assert_eq!(map2.slot_of(Z), 0, "Z must lose its slot in apply 2");
    coord.forwarding.zone_counter_slot_map = std::sync::Arc::new(map2);

    // The store still retains Z's totals -- assert it, so this test cannot
    // pass because the data vanished for an unrelated reason.
    assert!(
        coord
            .forwarding
            .zone_counter_store
            .snapshot()
            .iter()
            .any(|r| r.zone_id == Z),
        "precondition: the store must still retain Z's totals"
    );

    // Move traffic on a zone that KEPT its slot in apply 2, so the assertions
    // below constrain both directions.
    const SURVIVOR: u16 = 1;
    let survivor_map = ZoneCounterSlotMap::build(&ids, &coord.forwarding.zone_counter_store);
    record_zone_traffic(&survivor_map, SURVIVOR, 0, 64);
    flush_recorded_zone_counters(&coord.forwarding.zone_counter_store, &survivor_map);

    let published = coord.zone_traffic_counters();
    assert!(
        !published.iter().any(|r| r.zone_id == Z),
        "the coordinator kept publishing a zone that lost its slot: its total can \
         never advance again, so Prometheus would emit a FROZEN counter: {published:?}"
    );
    // #6843 gate F1: without this, a coordinator-level blanket
    // `if overflow_active { return Vec::new() }` satisfies the assertion above
    // and escapes the WHOLE suite -- the primitive sibling test that exists to
    // stop exactly that over-reach drives `publishable_zone_rows` directly, so
    // it cannot see an over-reach introduced HERE. Runtime consequence of the
    // escape: at >=64 configured zones the entire per-zone Prometheus family
    // vanishes for every zone and the unpopulated gauge jumps to the full zone
    // count.
    assert!(
        published.iter().any(|r| r.zone_id == SURVIVOR),
        "a zone that KEPT its slot stopped publishing once overflow became \
         active: the filter must drop only the zones that lost their slot, not \
         everything: {published:?}"
    );

    // #6843 gate R3: bind the coordinator's CONFIGURED predicate too. Dropping
    // it (`|_| true`) passed the entire cargo suite — the mirror of F1, left
    // open for this predicate after being closed for the slot one. The gate
    // could not construct a REACHABLE runtime divergence (apply-time
    // `reconcile` prunes unconfigured zones, and the reserved-id path is
    // filtered identically in policy.rs), so this predicate is defence in
    // depth rather than a live guard — but it is documented as load-bearing at
    // the call site, so it gets a test rather than an unbound claim.
    coord.forwarding.zone_id_to_name.remove(&SURVIVOR);
    let published = coord.zone_traffic_counters();
    assert!(
        !published.iter().any(|r| r.zone_id == SURVIVOR),
        "a zone dropped from the configured set kept publishing: the configured \
         predicate must hold independently of the slot predicate: {published:?}"
    );
}

#[test]
fn zone_flood_counters_drops_a_zone_that_lost_its_slot_3651() {
    // #3651 gate B1: drive the PRODUCTION publication accessor,
    // `Coordinator::zone_flood_counters`, not the extracted
    // `publishable_flood_rows` primitive. The primitive tests in
    // flood_counters.rs prove the filter; they do NOT prove the coordinator
    // calls it, so THREE distinct over-reaches introduced HERE compile and
    // leave the entire Rust suite green:
    //
    //   1. `|zone_id| configured.contains_key(&zone_id)` -> `|_| true`
    //      (publishes unconfigured zones). Made likelier by the accessor's own
    //      doc calling that filter "defence in depth", which invites a trim.
    //   2. a blanket `if overflow_active { return Vec::new(); }` -- verbatim
    //      the #6843 gate F1 over-reach, one plane over. Runtime consequence:
    //      at >=64 configured zones the ENTIRE per-zone flood surface vanishes
    //      and `show security screen ids-option statistics` reports
    //      "not available" for every zone.
    //   3. passing `FloodCounterSlotMap::default()` instead of the live map
    //      (publishes nothing).
    //
    // This is the exact asymmetry #6843 closed on the traffic half: the Go
    // call site was bound by TestSyncBPFCountersReplacesFloodOffsetsAcrossPolls3651,
    // the Rust one was not. Mirrors
    // `zone_traffic_counters_drops_a_zone_that_lost_its_slot_6843` above.
    use crate::afxdp::flood_counters::{
        flush_recorded_flood_counters, record_zone_flood_drop, FloodCounterSlotMap,
        FLOOD_COUNTER_ASSIGNABLE_SLOTS,
    };
    const Z: u16 = 50675; // config::StableZoneID("trust")

    let mut coord = Coordinator::new();

    // Apply 1: Z alone, holding a slot, tripping a flood check.
    let map1 = FloodCounterSlotMap::build(&[Z], &coord.forwarding.flood_counter_store);
    record_zone_flood_drop(&map1, Z, "syn-flood");
    flush_recorded_flood_counters(&coord.forwarding.flood_counter_store, &map1);
    coord.forwarding.flood_counter_slot_map = std::sync::Arc::new(map1);
    coord.forwarding.zone_id_to_name.insert(Z, "trust".to_string());

    let published = coord.zone_flood_counters();
    assert!(
        published.iter().any(|r| r.zone_id == Z),
        "apply 1: the coordinator must publish a slotted zone with flood events \
         (a default/empty slot map publishes nothing): {published:?}"
    );

    // Apply 2: enough lower ids to exhaust capacity. Z stays CONFIGURED and
    // keeps its retained counts, but loses its slot.
    let mut ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
    ids.push(Z);
    for id in &ids {
        coord
            .forwarding
            .zone_id_to_name
            .insert(*id, format!("z{id}"));
    }
    let map2 = FloodCounterSlotMap::build(&ids, &coord.forwarding.flood_counter_store);
    assert_eq!(map2.slot_of(Z), 0, "Z must lose its slot in apply 2");
    assert!(map2.overflow_active, "apply 2 must set overflow_active");
    coord.forwarding.flood_counter_slot_map = std::sync::Arc::new(map2);

    // The store still retains Z's counts -- assert it, so this test cannot pass
    // because the data vanished for an unrelated reason.
    assert!(
        coord
            .forwarding
            .flood_counter_store
            .snapshot()
            .iter()
            .any(|r| r.zone_id == Z),
        "precondition: the store must still retain Z's flood counts"
    );

    // Trip a flood check on a zone that KEPT its slot in apply 2, so the
    // assertions below constrain both directions.
    const SURVIVOR: u16 = 1;
    let survivor_map = FloodCounterSlotMap::build(&ids, &coord.forwarding.flood_counter_store);
    record_zone_flood_drop(&survivor_map, SURVIVOR, "udp-flood");
    flush_recorded_flood_counters(&coord.forwarding.flood_counter_store, &survivor_map);

    let published = coord.zone_flood_counters();
    assert!(
        !published.iter().any(|r| r.zone_id == Z),
        "the coordinator kept publishing a zone that lost its slot: its count can \
         never advance again, so the screen-statistics surface would report a \
         FROZEN flood total that under-reports every subsequent attack: {published:?}"
    );
    // Gate (a), the over-reach half: without this, a coordinator-level blanket
    // `if overflow_active { return Vec::new() }` -- or a default slot map --
    // satisfies the assertion above and escapes the WHOLE suite. The primitive
    // sibling test that exists to stop exactly that over-reach drives
    // `publishable_flood_rows` directly, so it cannot see an over-reach
    // introduced HERE.
    assert!(
        published.iter().any(|r| r.zone_id == SURVIVOR),
        "a zone that KEPT its slot stopped publishing once overflow became \
         active: the filter must drop only the zones that lost their slot, not \
         everything: {published:?}"
    );

    // Gate (b): bind the coordinator's CONFIGURED predicate too. Dropping it
    // (`|_| true`) is the mirror of the over-reach above -- the accessor's doc
    // calls it defence in depth (apply-time `reconcile` prunes unconfigured
    // zones), so it is documented as load-bearing at the call site and gets a
    // test rather than an unbound claim.
    coord.forwarding.zone_id_to_name.remove(&SURVIVOR);
    let published = coord.zone_flood_counters();
    assert!(
        !published.iter().any(|r| r.zone_id == SURVIVOR),
        "a zone dropped from the configured set kept publishing: the configured \
         predicate must hold independently of the slot predicate: {published:?}"
    );
}

/// #3402: a FRESH-BOOT snapshot ships its zones AND a concrete-zone policy in
/// the SAME atomic ConfigSnapshot, with the coordinator's live forwarding zone
/// table still EMPTY (populate_zones(snapshot) runs only later inside
/// build_forwarding_state). The reconcile policy preflight MUST resolve the
/// rule's zones against the INCOMING snapshot's own zones, so a
/// `from trust to untrust permit` rule passes and the reconcile advances the
/// published generation.
///
/// Fail-on-revert: the #3402-introduced `UnresolvableZoneReference` reject is
/// correct, but the preflight previously validated against
/// `self.forwarding.zone_name_to_id` (empty on a fresh boot). Point the
/// reconcile preflight back at that live table and this concrete-zone rule
/// becomes UnresolvableZoneReference → `last_reconcile_stage` =
/// "snapshot_integrity_error: ..." and the published generation never advances
/// → both asserts below go RED. This is the boot-bricking regression the
/// preflight-zone-source fix prevents.
#[test]
fn reconcile_fresh_boot_concrete_zone_policy_passes_preflight_3402() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new(); // #6637
    // Fresh coordinator: the live forwarding zone table is EMPTY (the bug
    // condition — the snapshot carries the zones, the live table does not yet).
    assert!(
        coordinator.forwarding.zone_name_to_id.is_empty(),
        "precondition: a fresh coordinator has no live zones"
    );
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 1,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();
    // All three mandatory pins resolve so the reconcile proceeds to publish.
    let mut snap = fail_open_snapshot(2);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    // Zones {trust:1, untrust:2} ship in the SAME snapshot as the policy.
    snap.zones = vec![
        crate::ZoneSnapshot {
            name: "trust".into(),
            id: 1,
            ..Default::default()
        },
        crate::ZoneSnapshot {
            name: "untrust".into(),
            id: 2,
            ..Default::default()
        },
    ];
    snap.default_policy = "deny".into();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        rule_id: "p1".into(),
        name: "allow".into(),
        from_zone: "trust".into(),
        to_zone: "untrust".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        action: "permit".into(),
        ..Default::default()
    }];

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        !matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::SnapshotIntegrityError
                | ReconcileStage::SnapshotIntegrityErrorDetail(_)
        ),
        "fresh-boot concrete-zone policy must pass the integrity preflight, got stage {:?}",
        coordinator.last_reconcile_stage
    );
    assert_eq!(
        coordinator.validation.config_generation, 2,
        "preflight passed → reconcile advances the published generation to the snapshot's"
    );
}

/// #3402 fail-closed preserved: a policy referencing a zone that is ABSENT from
/// the snapshot's OWN zones is genuinely unresolvable and MUST still be rejected
/// (the real bug #3402 fixes). default-policy permit-all makes the dropped-rule
/// fall-through the dangerous fail-OPEN case. The reconcile aborts in the
/// preflight, keeping the prior published generation.
#[test]
fn reconcile_policy_references_undefined_zone_still_fails_closed_3402() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 5,
        fib_generation: 2,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();
    let mut snap = fail_open_snapshot(6);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    // The snapshot defines ONLY `trust`; the rule's to-zone `ghostzone` is
    // absent from snapshot.zones → unresolvable against the snapshot's own
    // zones → fail closed (not a stale/empty-live-table false reject).
    snap.zones = vec![crate::ZoneSnapshot {
        name: "trust".into(),
        id: 1,
        ..Default::default()
    }];
    snap.default_policy = "permit".into();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        rule_id: "p-bad".into(),
        name: "deny-ghost".into(),
        from_zone: "trust".into(),
        to_zone: "ghostzone".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        action: "deny".into(),
        ..Default::default()
    }];

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::SnapshotIntegrityErrorDetail(_)
        ),
        "a policy naming a zone absent from snapshot.zones must fail closed, got stage {:?}",
        coordinator.last_reconcile_stage
    );
    // #6244: the typed detail still renders the unresolvable zone name in the
    // legacy operator string byte-for-byte.
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .contains("ghostzone"),
        "the integrity error must name the unresolvable zone, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert_eq!(
        coordinator.validation.config_generation, 5,
        "a rejected snapshot keeps the prior published generation"
    );
}

/// #2484 (completes the #2440/#2444 fail-open trilogy): a snapshot
/// INTEGRITY fault must abort the reconcile BEFORE `tear_down`, keeping
/// the prior generation published AND the prior workers/state live — not
/// merely record an observable stage post-teardown.
///
/// Seam: an NPTv6 rule with an unparseable internal prefix trips
/// `Nptv6State::try_from_snapshots` (Nptv6UnparseableRule). That path is
/// NOT checked by the top-of-reconcile policy preflight (which only parses
/// the policy/address-book state), so before #2484 it reached the
/// `apply_snapshot` integrity Err arm — which ran AFTER `tear_down`
/// (`stop_inner`) had already reset `coord.validation`,
/// the published `RuntimeView`, `snapshot_installed`, and stopped the workers.
/// #2484 hoists the full forwarding build into the pre-teardown preflight
/// (`build_reconcile_forwarding`), so the fault is now detected with the
/// prior state still live. Map pins are sentinel-OK so the map-FD preflight
/// passes and the integrity check is what fires.
///
/// Fail-on-revert: this is the KEY difference from the pre-#2484 test
/// (which asserted only the stage + non-installation, because the check was
/// post-teardown). With the fix reverted — integrity build back inside
/// `apply_snapshot`, after `tear_down` — `stop_inner` resets
/// `coord.validation` (config_generation -> 0, snapshot_installed -> false)
/// and the published `RuntimeView` to default, so EVERY preservation assertion
/// below fails. The stage assertion alone is NOT revert-sensitive (both the
/// old post-teardown leg and the new pre-teardown leg set it); the
/// preservation assertions are.
#[test]
fn reconcile_snapshot_integrity_error_preserves_prior_generation_and_state() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 20,
        fib_generation: 7,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    // Seed a sentinel live worker. `tear_down` -> `stop_inner` ->
    // `workers.stop_and_clear` would empty `workers.live`; if the integrity
    // fault is (correctly) detected before teardown, this entry survives.
    // This is the direct "prior workers are NOT torn down" proof.
    coordinator
        .workers
        .live
        .insert(0, std::sync::Arc::new(BindingLiveState::new()));

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Sentinel-OK mandatory pins (preflight passes) + an NPTv6 rule with an
    // unparseable internal prefix (integrity Err in build_forwarding_state).
    // #3888: NAT64 is now fail-scoped (skip-and-continue, never an integrity
    // Err), so NPTv6 — which intentionally stays fail-CLOSED for its #2241
    // order-dependent overlap guard — is the seam that still trips this
    // pre-teardown-preflight regression check.
    let mut snap = fail_open_snapshot(21);
    snap.map_pins.sessions = format!("{TEST_MAP_PIN_OK}sessions");
    snap.nptv6_rules = vec![crate::protocol::Nptv6RuleSnapshot {
        name: "bad-nptv6".to_string(),
        internal_prefix: "not-a-prefix".to_string(),
        external_prefix: "2001:db8:9::/48".to_string(),
        ..Default::default()
    }];

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.last_reconcile_stage,
        ReconcileStage::SnapshotIntegrityError,
        "integrity-error leg must record an observable stage, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert_eq!(
        coordinator.last_reconcile_stage.to_string(),
        "snapshot_integrity_error"
    );

    // FAIL-ON-REVERT CORE: the prior generation is still the published one,
    // proving the integrity fault aborted BEFORE `tear_down`. A pre-#2484
    // post-teardown reject would have run `stop_inner`, defaulting these.
    assert_eq!(
        coordinator.validation.config_generation, 20,
        "integrity reject must PRESERVE the prior generation (not tear down)"
    );
    assert_eq!(
        coordinator.validation.fib_generation, 7,
        "integrity reject must PRESERVE the prior fib generation"
    );
    assert!(
        coordinator.validation.snapshot_installed,
        "integrity reject must keep snapshot_installed (stop_inner would clear it)"
    );
    let shared = coordinator.published_validation();
    assert_eq!(
        shared, prior,
        "the published RuntimeView (worker-visible pair) must still hold the prior published state"
    );
    // The rejected generation is never published anywhere.
    assert_ne!(coordinator.validation.config_generation, 21);
    assert_ne!(shared.config_generation, 21);

    // FAIL-ON-REVERT (worker preservation): the seeded prior worker is
    // still present — `tear_down`/`stop_inner`/`stop_and_clear` was never
    // reached. A pre-#2484 post-teardown reject would have emptied
    // `workers.live` before the integrity fault was detected.
    assert_eq!(
        coordinator.workers.live.len(),
        1,
        "integrity reject must PRESERVE the prior workers (not tear them down)"
    );
    assert!(
        coordinator.workers.live.contains_key(&0),
        "the seeded prior worker (slot 0) must survive an integrity-faulted reconcile"
    );
}

// ---------------------------------------------------------------------------
// #2444 — an OPTIONAL map (conntrack v4/v6, dnat tables) whose pin is
// PRESENT but fails to open must fail closed exactly like a mandatory map:
// abort the reconcile in the preflight BEFORE teardown/publish, keeping the
// prior generation + workers live. An EMPTY pin (feature genuinely absent)
// must still reconcile normally — the anti-over-gate control.
// ---------------------------------------------------------------------------

/// Build a snapshot whose three mandatory pins are sentinel-OK (so the
/// mandatory preflight passes) and `generation` is the new generation the
/// reconcile would publish if it ran to completion. Optional pins are left
/// empty by the caller unless explicitly set.
fn mandatory_ok_snapshot(generation: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        generation,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{TEST_MAP_PIN_OK}xsk"),
            heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
            sessions: format!("{TEST_MAP_PIN_OK}sessions"),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// fail-on-revert: a PRESENT conntrack_v4 pin that fails to open must
/// abort the reconcile in the preflight, leaving the prior published
/// generation intact and recording an observable
/// `open_conntrack_v4_map_failed:` stage.
///
/// Fail-on-revert proof: restoring the pre-#2444
/// `open_bpf_map(...).ok()` swallows the open error -> the optional map
/// silently becomes `None`, the reconcile proceeds, and `config_generation`
/// wrongly advances to the new generation. Every assertion below that the
/// prior generation survives then fails.
#[test]
fn reconcile_present_conntrack_pin_open_failure_keeps_prior_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 30,
        fib_generation: 9,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory pins OK; conntrack_v4 pin PRESENT but forced to fail open.
    let mut snap = mandatory_ok_snapshot(31);
    snap.map_pins.conntrack_v4 = format!("{TEST_MAP_PIN_FAIL}conntrack_v4");

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::OpenMapFailed {
                map: "conntrack_v4",
                ..
            }
        ),
        "expected abort at the conntrack_v4 open, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .starts_with("open_conntrack_v4_map_failed:")
    );

    // FAIL-ON-REVERT CORE: the prior generation is still published.
    assert_eq!(
        coordinator.validation.config_generation, 30,
        "config_generation must NOT advance on a present-but-unopenable optional map"
    );
    assert_eq!(coordinator.validation.fib_generation, 9);
    assert_eq!(
        coordinator.published_validation().config_generation,
        30,
        "the published validation must still hold the prior generation"
    );
    assert!(
        bindings[0]
            .last_error
            .starts_with("open conntrack_v4 map:"),
        "expected per-binding last_error for the conntrack_v4 open failure, got {:?}",
        bindings[0].last_error
    );
    assert!(
        coordinator.workers.live.is_empty(),
        "no workers should be live after an aborted reconcile"
    );
}

/// fail-on-revert: same fail-closed behavior for a PRESENT dnat_table pin
/// that fails to open (embedded-ICMP NAT reversal feature configured but
/// unopenable -> must block, not run degraded).
#[test]
fn reconcile_present_dnat_pin_open_failure_keeps_prior_generation() {
    let mut coordinator = Coordinator::new();
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 40,
        fib_generation: 12,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];

    // Mandatory + conntrack pins OK; dnat_table pin PRESENT but fails open.
    let mut snap = mandatory_ok_snapshot(41);
    snap.map_pins.dnat_table = format!("{TEST_MAP_PIN_FAIL}dnat_table");

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert!(
        matches!(
            coordinator.last_reconcile_stage,
            ReconcileStage::OpenMapFailed {
                map: "dnat_table",
                ..
            }
        ),
        "expected abort at the dnat_table open, got {:?}",
        coordinator.last_reconcile_stage
    );
    assert!(
        coordinator
            .last_reconcile_stage
            .to_string()
            .starts_with("open_dnat_table_map_failed:")
    );
    assert_eq!(
        coordinator.validation.config_generation, 40,
        "config_generation must NOT advance on a present-but-unopenable dnat map"
    );
    assert_eq!(
        coordinator.published_validation().config_generation,
        40
    );
    assert!(
        bindings[0].last_error.starts_with("open dnat_table map:"),
        "expected per-binding last_error for the dnat_table open failure, got {:?}",
        bindings[0].last_error
    );
}

/// ANTI-OVER-GATE control: when the optional conntrack/dnat pins are EMPTY
/// (feature genuinely absent — the common deploy), the reconcile must NOT
/// be gated: the preflight returns `None` silently for each empty pin and
/// the reconcile proceeds to publish the new generation. This guards
/// against the fix being too aggressive (treating "feature absent" as a
/// failure).
#[test]
fn reconcile_empty_optional_pins_advance_published_generation() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new(); // #6637
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 50,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Mandatory pins OK; ALL optional pins left empty (the default).
    let snap = mandatory_ok_snapshot(51);
    assert!(snap.map_pins.conntrack_v4.is_empty());
    assert!(snap.map_pins.conntrack_v6.is_empty());
    assert!(snap.map_pins.dnat_table.is_empty());
    assert!(snap.map_pins.dnat_table_v6.is_empty());

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 51,
        "empty optional pins must NOT gate the reconcile (anti-over-gate)"
    );
    assert_eq!(
        coordinator.published_validation().config_generation,
        51
    );
}

/// Positive control: PRESENT optional pins that OPEN OK must reconcile
/// normally and advance the published generation (the fix accepts a
/// healthy configured map).
#[test]
fn reconcile_present_optional_pins_open_ok_advance_generation() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut coordinator = StoppedCoordinator::new(); // #6637
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 60,
        fib_generation: 0,
    };
    coordinator.validation = prior;
    coordinator.seed_published_validation(prior);

    let mut bindings: Vec<BindingStatus> = Vec::new();

    // Mandatory + all optional pins sentinel-OK (present + openable).
    let mut snap = mandatory_ok_snapshot(61);
    snap.map_pins.conntrack_v4 = format!("{TEST_MAP_PIN_OK}conntrack_v4");
    snap.map_pins.conntrack_v6 = format!("{TEST_MAP_PIN_OK}conntrack_v6");
    snap.map_pins.dnat_table = format!("{TEST_MAP_PIN_OK}dnat_table");
    snap.map_pins.dnat_table_v6 = format!("{TEST_MAP_PIN_OK}dnat_table_v6");

    let _ = coordinator.reconcile(Some(&snap), &mut bindings, 64);

    assert_eq!(
        coordinator.validation.config_generation, 61,
        "present + openable optional maps must reconcile normally"
    );
    assert_eq!(
        coordinator.published_validation().config_generation,
        61
    );
}

// ---------------------------------------------------------------------------
// #6243 — the activated (`preflight_map_fds`) and deferred (`validate_map_pins`)
// map-pin preflights are now ONE shared opener (`open_snapshot_maps`). These
// tests lock ALL SEVEN pins' stage + per-binding strings (including the
// previously-UNCOVERED uppercase-XSK label, heartbeat strings, conntrack_v6,
// and dnat_table_v6), prove BOTH callers react IDENTICALLY, and lock the two
// divergence fixes (two-pass multi-fault precedence + shared FD retention).
// ---------------------------------------------------------------------------

/// A `MapPins` whose three mandatory pins are sentinel-OK and every optional
/// pin is empty (absent). Individual pins are overridden per case.
fn all_map_pins_ok_6243() -> crate::protocol::snapshot::MapPins {
    crate::protocol::snapshot::MapPins {
        xsk: format!("{TEST_MAP_PIN_OK}xsk"),
        heartbeat: format!("{TEST_MAP_PIN_OK}heartbeat"),
        sessions: format!("{TEST_MAP_PIN_OK}sessions"),
        ..Default::default()
    }
}

/// Drive the ACTIVATED path (`reconcile` -> `preflight_map_fds`) for a faulted
/// `MapPins` and return the rendered `last_reconcile_stage` string + the
/// per-registered-binding `last_error` string it stamped.
fn drive_map_pin_reconcile_6243(pins: crate::protocol::snapshot::MapPins) -> (String, String) {
    let mut coord = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];
    let snap = ConfigSnapshot {
        generation: 99,
        map_pins: pins,
        ..Default::default()
    };
    let _ = coord.reconcile(Some(&snap), &mut bindings, 64);
    (
        coord.last_reconcile_stage.to_string(),
        bindings[0].last_error.clone(),
    )
}

/// The typed `ReconcileStage` the ACTIVATED path records for a faulted
/// `MapPins` (asserts the reconcile fails closed with `MapSetup`).
fn activated_map_pin_stage_6243(pins: crate::protocol::snapshot::MapPins) -> ReconcileStage {
    let mut coord = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let snap = ConfigSnapshot {
        generation: 99,
        map_pins: pins,
        ..Default::default()
    };
    let result = coord.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        matches!(result, Err(ReconcileError::MapSetup(_))),
        "expected a MapSetup reject from reconcile, got {result:?}"
    );
    coord.last_reconcile_stage.clone()
}

/// The typed `ReconcileStage` the DEFERRED path (`validate_snapshot_buildable`
/// -> `validate_map_pins`) reports for a faulted `MapPins`.
fn deferred_map_pin_stage_6243(pins: crate::protocol::snapshot::MapPins) -> ReconcileStage {
    let coord = Coordinator::new();
    let snap = ConfigSnapshot {
        generation: 99,
        map_pins: pins,
        ..Default::default()
    };
    match coord.validate_snapshot_buildable(Some(&snap)) {
        Err(ReconcileError::MapSetup(stage)) => stage,
        other => {
            panic!("expected Err(MapSetup(_)) from validate_snapshot_buildable, got {other:?}")
        }
    }
}

/// #6243 fail-on-revert (byte-parity): lock every one of the seven pins' typed
/// stage string AND per-binding `last_error` string on the activated path. The
/// pre-#6243 suite covered only `session` / `conntrack_v4` / `dnat_table`; this
/// adds the UNCOVERED cases — the uppercase-`XSK` per-binding label (vs the
/// lowercase `xsk` stage token), the `heartbeat` strings, `conntrack_v6`, and
/// `dnat_table_v6`. Rewriting the per-binding `XSK` label to the lowercase stage
/// token (or dropping any pin's requiredness/label) turns the matching
/// assertion RED.
#[test]
fn reconcile_all_seven_pin_faults_lock_stage_and_binding_strings_6243() {
    // #6361 OPEN-failure byte-parity helper. The old `starts_with` accepted ANY
    // suffix after the prefix, so a corrupted stage/label suffix — or a
    // stage-vs-binding `err` divergence — could slip past. This asserts the
    // stage-token prefix AND the per-binding-label prefix EXACTLY (strip_prefix
    // fails otherwise), that a NONEMPTY `{err}` suffix exists, and that BOTH
    // paths render the IDENTICAL err text (they share one `MapPinFault::Open {
    // err }`, so a suffix corruption on either side reds this). It stays robust
    // to a nondeterministic OS error string — it never hardcodes the err text.
    let assert_open_parity = |stage: &str, be: &str, stage_prefix: &str, be_prefix: &str| {
        let stage_err = stage.strip_prefix(stage_prefix).unwrap_or_else(|| {
            panic!("stage {stage:?} must start with the exact prefix {stage_prefix:?}")
        });
        let be_err = be.strip_prefix(be_prefix).unwrap_or_else(|| {
            panic!("binding {be:?} must start with the exact prefix {be_prefix:?}")
        });
        assert!(
            !stage_err.is_empty(),
            "stage {stage:?} must carry a nonempty err suffix after {stage_prefix:?}"
        );
        assert_eq!(
            stage_err, be_err,
            "stage and binding must render the identical open err \
             (stage={stage:?}, binding={be:?})"
        );
    };

    // Mandatory xsk — the byte-parity trap: stage token lowercase `xsk`,
    // per-binding label UPPERCASE `XSK`.
    let mut p = all_map_pins_ok_6243();
    p.xsk = String::new();
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_eq!(stage, "missing_xsk_pin");
    assert_eq!(be, "missing XSK map pin path");

    let mut p = all_map_pins_ok_6243();
    p.xsk = format!("{TEST_MAP_PIN_FAIL}xsk");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(&stage, &be, "open_xsk_map_failed:", "open XSK map: ");

    // Mandatory heartbeat.
    let mut p = all_map_pins_ok_6243();
    p.heartbeat = String::new();
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_eq!(stage, "missing_heartbeat_pin");
    assert_eq!(be, "missing heartbeat map pin path");

    let mut p = all_map_pins_ok_6243();
    p.heartbeat = format!("{TEST_MAP_PIN_FAIL}heartbeat");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(&stage, &be, "open_heartbeat_map_failed:", "open heartbeat map: ");

    // Mandatory session.
    let mut p = all_map_pins_ok_6243();
    p.sessions = String::new();
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_eq!(stage, "missing_session_pin");
    assert_eq!(be, "missing session map pin path");

    let mut p = all_map_pins_ok_6243();
    p.sessions = format!("{TEST_MAP_PIN_FAIL}sessions");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(&stage, &be, "open_session_map_failed:", "open session map: ");

    // Optional pins: PRESENT-but-unopenable is fatal (#2444). There is no
    // "missing" variant — an empty optional pin is silent absence. The stage
    // token and per-binding label are the SAME lowercase name for optionals
    // (only xsk's two forms diverge).
    let mut p = all_map_pins_ok_6243();
    p.conntrack_v4 = format!("{TEST_MAP_PIN_FAIL}conntrack_v4");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(
        &stage,
        &be,
        "open_conntrack_v4_map_failed:",
        "open conntrack_v4 map: ",
    );

    let mut p = all_map_pins_ok_6243();
    p.conntrack_v6 = format!("{TEST_MAP_PIN_FAIL}conntrack_v6");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(
        &stage,
        &be,
        "open_conntrack_v6_map_failed:",
        "open conntrack_v6 map: ",
    );

    let mut p = all_map_pins_ok_6243();
    p.dnat_table = format!("{TEST_MAP_PIN_FAIL}dnat_table");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(
        &stage,
        &be,
        "open_dnat_table_map_failed:",
        "open dnat_table map: ",
    );

    let mut p = all_map_pins_ok_6243();
    p.dnat_table_v6 = format!("{TEST_MAP_PIN_FAIL}dnat_table_v6");
    let (stage, be) = drive_map_pin_reconcile_6243(p);
    assert_open_parity(
        &stage,
        &be,
        "open_dnat_table_v6_map_failed:",
        "open dnat_table_v6 map: ",
    );
}

/// #6243 fail-on-revert (SSOT parity): for EACH of the seven pins' single-fault
/// snapshots, the activated (`reconcile`) and deferred
/// (`validate_snapshot_buildable`) paths must report the IDENTICAL typed
/// `ReconcileStage`. Both now route through the one `open_snapshot_maps`;
/// reverting either caller to its own hand-rolled pin list (or flipping a pin's
/// requiredness) diverges one of these pairs.
#[test]
fn map_pin_faults_react_identically_activated_and_deferred_6243() {
    let mut cases: Vec<crate::protocol::snapshot::MapPins> = Vec::new();
    // Mandatory empties.
    {
        let mut p = all_map_pins_ok_6243();
        p.xsk = String::new();
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.heartbeat = String::new();
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.sessions = String::new();
        cases.push(p);
    }
    // Mandatory open failures.
    {
        let mut p = all_map_pins_ok_6243();
        p.xsk = format!("{TEST_MAP_PIN_FAIL}xsk");
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.heartbeat = format!("{TEST_MAP_PIN_FAIL}heartbeat");
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.sessions = format!("{TEST_MAP_PIN_FAIL}sessions");
        cases.push(p);
    }
    // Present-optional open failures.
    {
        let mut p = all_map_pins_ok_6243();
        p.conntrack_v4 = format!("{TEST_MAP_PIN_FAIL}conntrack_v4");
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.conntrack_v6 = format!("{TEST_MAP_PIN_FAIL}conntrack_v6");
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.dnat_table = format!("{TEST_MAP_PIN_FAIL}dnat_table");
        cases.push(p);
    }
    {
        let mut p = all_map_pins_ok_6243();
        p.dnat_table_v6 = format!("{TEST_MAP_PIN_FAIL}dnat_table_v6");
        cases.push(p);
    }

    for pins in cases {
        let activated = activated_map_pin_stage_6243(pins.clone());
        let deferred = deferred_map_pin_stage_6243(pins);
        assert_eq!(
            activated, deferred,
            "activated and deferred map-pin paths must report the identical stage; \
             activated={activated}, deferred={deferred}"
        );
    }

    // #6361: a MULTI-FAULT case so THIS named identity test — not only the
    // separate `multi_fault_map_pins_use_two_pass_precedence_from_both_paths`
    // sibling — reds on a one-pass revert of the deferred path. The single-fault
    // cases above are tautological on such a revert: with only one fault both
    // one-pass and two-pass surface the same stage. Here xsk is
    // present-but-unopenable AND heartbeat is EMPTY: the canonical two-pass
    // order (check ALL emptiness first, then open) reports the LATER empty
    // heartbeat from BOTH paths, while a one-pass deferred walk would surface
    // the EARLIER xsk open failure — breaking the identity assertion.
    let mut multi = all_map_pins_ok_6243();
    multi.xsk = format!("{TEST_MAP_PIN_FAIL}xsk");
    multi.heartbeat = String::new();
    let activated = activated_map_pin_stage_6243(multi.clone());
    let deferred = deferred_map_pin_stage_6243(multi);
    assert_eq!(
        activated, deferred,
        "multi-fault (xsk unopenable + heartbeat empty) must report the identical \
         stage from both paths; a one-pass deferred revert diverges here \
         (activated={activated}, deferred={deferred})"
    );
    assert_eq!(
        activated,
        ReconcileStage::MissingPin(MandatoryPin::Heartbeat),
        "two-pass precedence must report the later empty heartbeat, not the xsk open failure"
    );
}

/// #6243 fail-on-revert (DIVERGENCE 1 — two-pass multi-fault precedence): when
/// an EARLIER mandatory pin is present-but-unopenable AND a LATER mandatory pin
/// is EMPTY, the canonical two-pass order (check ALL emptiness first, then open)
/// makes BOTH paths report the LATER pin's emptiness — not the earlier pin's
/// open failure a one-pass walk would surface. Before #6243 the deferred path
/// was one-pass and reported a DIFFERENT stage than the activated two-pass path
/// on exactly these inputs (both still fail-closed). Reverting the shared opener
/// to a one-pass walk flips the deferred assertions to `OpenMapFailed`.
#[test]
fn multi_fault_map_pins_use_two_pass_precedence_from_both_paths_6243() {
    // Case 1: xsk present-but-unopenable, heartbeat EMPTY.
    let mut p = all_map_pins_ok_6243();
    p.xsk = format!("{TEST_MAP_PIN_FAIL}xsk");
    p.heartbeat = String::new();
    let activated = activated_map_pin_stage_6243(p.clone());
    let deferred = deferred_map_pin_stage_6243(p);
    assert_eq!(
        activated,
        ReconcileStage::MissingPin(MandatoryPin::Heartbeat),
        "activated two-pass must report the empty heartbeat, not the xsk open failure"
    );
    assert_eq!(
        deferred,
        ReconcileStage::MissingPin(MandatoryPin::Heartbeat),
        "deferred must MATCH the activated two-pass (was OpenMapFailed(xsk) pre-#6243)"
    );

    // Case 2: xsk OK, heartbeat present-but-unopenable, sessions EMPTY.
    let mut p = all_map_pins_ok_6243();
    p.heartbeat = format!("{TEST_MAP_PIN_FAIL}heartbeat");
    p.sessions = String::new();
    let activated = activated_map_pin_stage_6243(p.clone());
    let deferred = deferred_map_pin_stage_6243(p);
    assert_eq!(
        activated,
        ReconcileStage::MissingPin(MandatoryPin::Session),
        "activated two-pass must report the empty sessions, not the heartbeat open failure"
    );
    assert_eq!(
        deferred,
        ReconcileStage::MissingPin(MandatoryPin::Session),
        "deferred must MATCH the activated two-pass (was OpenMapFailed(heartbeat) pre-#6243)"
    );
}

/// #6243 (DIVERGENCE 2 — shared FD retention): the shared `open_snapshot_maps`
/// holds every opened FD in one `OpenedSnapshotMaps` bundle until the WHOLE
/// seven-pin contract succeeds. The activated path KEEPS the bundle; the
/// deferred path DROPS it (RAII). Because both callers route through that single
/// opener, the point at which FD-table pressure would fail an open is identical
/// for both — the deferred path can no longer PASS (dropping each FD per pin)
/// where the activated path (holding all seven simultaneously) FAILS.
///
/// Real FD-pressure cannot be injected through the `TEST_MAP_PIN_OK` seam (it
/// returns fd=-1 without consuming a descriptor), so retention parity is
/// enforced STRUCTURALLY by the shared opener; the observable anchor here is
/// that BOTH paths accept a snapshot whose all seven pins are present + openable
/// — proving each walks and opens the FULL bundle before returning Ok.
#[test]
fn both_paths_open_full_seven_pin_bundle_before_ok_6243() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let mut pins = all_map_pins_ok_6243();
    pins.conntrack_v4 = format!("{TEST_MAP_PIN_OK}conntrack_v4");
    pins.conntrack_v6 = format!("{TEST_MAP_PIN_OK}conntrack_v6");
    pins.dnat_table = format!("{TEST_MAP_PIN_OK}dnat_table");
    pins.dnat_table_v6 = format!("{TEST_MAP_PIN_OK}dnat_table_v6");

    // Activated: reconcile advances the published generation (opened + retained
    // all seven FDs and proceeded past the preflight).
    let mut coord = StoppedCoordinator::new(); // #6637
    let prior = ValidationState {
        snapshot_installed: true,
        config_generation: 70,
        fib_generation: 0,
    };
    coord.validation = prior;
    coord.seed_published_validation(prior);
    let mut bindings: Vec<BindingStatus> = Vec::new();
    let snap = ConfigSnapshot {
        generation: 71,
        map_pins: pins.clone(),
        ..Default::default()
    };
    let _ = coord.reconcile(Some(&snap), &mut bindings, 64);
    assert_eq!(
        coord.validation.config_generation, 71,
        "all seven present+openable pins must let the activated reconcile advance"
    );

    // Deferred: validate_snapshot_buildable returns Ok (opened all seven, then
    // dropped the bundle) with no worker side effects.
    let validate_coord = Coordinator::new();
    let snap2 = ConfigSnapshot {
        generation: 71,
        map_pins: pins,
        ..Default::default()
    };
    assert!(
        validate_coord
            .validate_snapshot_buildable(Some(&snap2))
            .is_ok(),
        "all seven present+openable pins must pass the deferred validation gate"
    );
    assert!(
        validate_coord.workers.live.is_empty(),
        "the deferred validation must not bring up workers"
    );

    // #6361: bind "opens the FULL bundle" from the FAULT side too, HERE — the
    // Ok-acceptance above only proves all-seven-present+openable passes; it
    // stays green if an optional open were dropped from the shared
    // `open_snapshot_maps`. Each optional pin set to a present-but-unopenable
    // FAIL pin must be REJECTED by BOTH paths with the matching
    // `OpenMapFailed(token)` — dropping any one optional open would let its FAIL
    // pin slip through Ok and red this loop. The sibling
    // `reconcile_all_seven_pin_faults` test independently catches the same
    // dropped open on the activated path; this adds the DEFERRED path and ties
    // the guarantee to this test's own all-seven claim.
    //
    // Retention (all seven FDs held simultaneously until the whole contract
    // succeeds) cannot be exercised directly: the fd=-1 `TEST_MAP_PIN_OK` seam
    // consumes no descriptor, so real FD-table pressure is uninjectable. That
    // guarantee is therefore STRUCTURAL — the RAII `OwnedFd`s in the private
    // `OpenedSnapshotMaps` bundle (`reconcile/snapshot.rs`) are held together by
    // ownership — and this fault probe is the strongest observable proxy.
    let assert_optional_open_fault = |faulted: crate::protocol::snapshot::MapPins, token: &str| {
        let activated = activated_map_pin_stage_6243(faulted.clone());
        let deferred = deferred_map_pin_stage_6243(faulted);
        match &activated {
            ReconcileStage::OpenMapFailed { map, err } => {
                assert_eq!(*map, token, "activated must fault the {token} optional open");
                assert!(!err.is_empty(), "activated {token} fault must carry a nonempty err");
            }
            other => panic!("expected OpenMapFailed({token}) from activated, got {other:?}"),
        }
        assert_eq!(
            activated, deferred,
            "both paths must reject the present-but-unopenable {token} optional identically \
             (activated={activated}, deferred={deferred})"
        );
    };

    let mut p = all_map_pins_ok_6243();
    p.conntrack_v4 = format!("{TEST_MAP_PIN_FAIL}conntrack_v4");
    assert_optional_open_fault(p, "conntrack_v4");

    let mut p = all_map_pins_ok_6243();
    p.conntrack_v6 = format!("{TEST_MAP_PIN_FAIL}conntrack_v6");
    assert_optional_open_fault(p, "conntrack_v6");

    let mut p = all_map_pins_ok_6243();
    p.dnat_table = format!("{TEST_MAP_PIN_FAIL}dnat_table");
    assert_optional_open_fault(p, "dnat_table");

    let mut p = all_map_pins_ok_6243();
    p.dnat_table_v6 = format!("{TEST_MAP_PIN_FAIL}dnat_table_v6");
    assert_optional_open_fault(p, "dnat_table_v6");
}

/// #3766 fail-closed same-plan refresh (H2 + H3 + M1): a runtime-snapshot
/// refresh whose POLICY preflight passes but whose full
/// `build_forwarding_state` FAILS a non-policy integrity check (here an
/// unparseable interface address) MUST be an atomic no-op — it returns
/// `Err`, leaves the prior validation generation untouched (H2), and does
/// not rotate/delete the neighbor-manager keys (H3). The still-live prior
/// state is never left split-brain (validation ahead of forwarding) and no
/// live neighbor key is blackholed.
///
/// Fail-on-revert: the pre-#3766 code bumped `self.validation` and rotated
/// the neighbor-manager keys BEFORE the fallible build, then swallowed the
/// error with a bare `return`. Restore that order and: (a) the refresh
/// returns `()` so the caller cannot observe the reject (M1), (b)
/// `validation.config_generation` advances to the rejected snapshot's
/// generation while forwarding stays at the prior one (split-brain, H2),
/// and (c) the manager keys rotate to the rejected snapshot's neighbor set
/// while the old key is deleted (H3) — every assertion below goes RED.
#[test]
fn refresh_runtime_snapshot_build_failure_is_atomic_noop_3766() {
    let mut coordinator = Coordinator::new();

    let good_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    let good_snapshot = |generation: u64| ConfigSnapshot {
        generation,
        fib_generation: generation as u32,
        neighbors: vec![crate::NeighborSnapshot {
            ifindex: 13,
            family: "inet".to_string(),
            ip: good_ip.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };

    // Install a valid baseline (generation 7) carrying one usable manager
    // neighbor. This is the "stale-but-correct prior good state".
    coordinator
        .refresh_runtime_snapshot(&good_snapshot(7))
        .expect("valid snapshot must apply");
    assert_eq!(coordinator.validation.config_generation, 7);
    assert_eq!(coordinator.validation.fib_generation, 7);
    assert!(
        coordinator
            .neighbors
            .manager_keys
            .lock()
            .expect("manager_keys")
            .contains(&(13, good_ip)),
        "baseline manager neighbor key must be installed"
    );

    // A snapshot that PASSES the policy preflight (no policies) but FAILS
    // build_forwarding_state on an unparseable interface address, and
    // carries a DIFFERENT neighbor set so a pre-build key rotation would be
    // observable.
    let bad_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201));
    let bad_snapshot = ConfigSnapshot {
        generation: 9,
        fib_generation: 9,
        neighbors: vec![crate::NeighborSnapshot {
            ifindex: 14,
            family: "inet".to_string(),
            ip: bad_ip.to_string(),
            mac: "00:11:22:33:44:66".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: "ge-0/0/9".to_string(),
            ifindex: 99,
            hardware_addr: "02:00:00:00:00:99".to_string(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.0.0.0/33".to_string(), // not a parseable CIDR
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    // M1: the build failure is surfaced as an Err (not swallowed).
    let err = coordinator
        .refresh_runtime_snapshot(&bad_snapshot)
        .expect_err("a build_forwarding_state failure must be returned as Err");
    assert!(
        matches!(
            err,
            crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable { .. }
        ),
        "expected InterfaceAddressUnparseable, got {err:?}"
    );

    // H2: the rejected snapshot must NOT advance the validation generation
    // (which would publish config_generation=9 against the still-G7
    // forwarding table via a later bump_fib_generation / store).
    assert_eq!(
        coordinator.validation.config_generation, 7,
        "rejected snapshot must not bump validation.config_generation (split-brain)"
    );
    assert_eq!(
        coordinator.validation.fib_generation, 7,
        "rejected snapshot must not bump validation.fib_generation"
    );
    assert_eq!(
        coordinator.published_validation().config_generation,
        7,
        "worker-visible published generation must stay at the prior good value"
    );

    // H3: the neighbor-manager keys must NOT be rotated/deleted by the
    // rejected snapshot — the prior good key survives, the rejected key is
    // absent.
    {
        let keys = coordinator
            .neighbors
            .manager_keys
            .lock()
            .expect("manager_keys");
        assert!(
            keys.contains(&(13, good_ip)),
            "prior good neighbor key must survive a rejected snapshot (no blackhole)"
        );
        assert!(
            !keys.contains(&(14, bad_ip)),
            "rejected snapshot's neighbor key must not be installed"
        );
    }

    // Positive control (not over-gating): a valid refresh still applies and
    // advances the generation after a rejected one.
    coordinator
        .refresh_runtime_snapshot(&good_snapshot(11))
        .expect("valid snapshot must still apply after a rejected one");
    assert_eq!(coordinator.validation.config_generation, 11);
    assert_eq!(
        coordinator.published_validation().config_generation,
        11
    );
}

/// #5190 (A1-b8-F6) fail-on-revert + structural CENSUS: every field
/// `copy_live_snapshot` writes onto a BOUND slot must be cleared again by
/// `zero_unbound_slot` when that slot loses its worker. The two halves had
/// drifted: the copy half wrote `shared_umem_mode`/`shared_umem_group`/
/// `shared_umem_socket_role`/`shared_umem_disabled_reason` (four Strings)
/// and the `martian_dropped`/`ipv6_ext_header_dropped` drop counters, and
/// the reset half cleared none of them — so an unbound slot kept
/// advertising a dead socket's shared-UMEM role and a frozen drop count
/// next to `rx_packets == 0`.
///
/// Rather than re-enumerate 150+ fields by hand (an enumeration is a
/// FLOOR, not a census, and the next field added to the copy half would
/// slip through it), this drives the real
/// `Coordinator::refresh_bindings` unbound branch over a status whose
/// EVERY serialized field has been poisoned with a sentinel, then asserts
/// the result is field-for-field equal to `BindingStatus::default()`
/// except for the registry-owned identity fields. A future field added to
/// `copy_live_snapshot` but not to `zero_unbound_slot` fails this test
/// with the offending key NAMED, without anyone having to remember to
/// extend the test.
#[test]
fn zero_unbound_slot_clears_every_copied_field_5190() {
    use serde_json::Value;

    /// Replace every scalar in the tree with a sentinel that is NOT the
    /// serde default, so a field the reset half forgets stays visibly
    /// poisoned. `Null` stays null (a `None` Option carries no sentinel
    /// to poison); empty arrays gain one element so a `.clear()` that
    /// never runs is observable.
    fn poison(v: &mut Value) {
        match v {
            Value::Null => {}
            Value::Bool(b) => *b = true,
            Value::Number(n) => *n = serde_json::Number::from(4242u64),
            Value::String(s) => *s = "STALE-5190".to_string(),
            Value::Array(a) => {
                if a.is_empty() {
                    a.push(Value::Number(serde_json::Number::from(4242u64)));
                } else {
                    for e in a.iter_mut() {
                        poison(e);
                    }
                }
            }
            Value::Object(o) => {
                for (_k, e) in o.iter_mut() {
                    poison(e);
                }
            }
        }
    }

    // Registry-owned identity: `refresh_bindings` must NOT clear these —
    // they name the slot, not the (now absent) worker.
    const IDENTITY_KEYS: &[&str] = &[
        "slot",
        "queue_id",
        "worker_id",
        "interface",
        "ifindex",
        "registered",
        "armed",
    ];

    let default_json = serde_json::to_value(BindingStatus::default())
        .expect("BindingStatus must serialize");
    let mut poisoned_json = default_json.clone();
    poison(&mut poisoned_json);
    let poisoned: BindingStatus =
        serde_json::from_value(poisoned_json).expect("poisoned BindingStatus must deserialize");
    // Sanity: the poison actually took, otherwise this test is vacuous.
    assert_eq!(
        poisoned.shared_umem_mode, "STALE-5190",
        "poison harness failed to populate shared_umem_mode — test would be vacuous"
    );
    assert_ne!(
        poisoned.martian_dropped, 0,
        "poison harness failed to populate martian_dropped — test would be vacuous"
    );

    let mut bindings = vec![poisoned];
    // No live worker registered for this slot -> refresh_bindings takes
    // the `zero_unbound_slot` branch (the production path).
    let mut coordinator = Coordinator::new();
    coordinator.refresh_bindings(&mut bindings);

    let cleared = serde_json::to_value(&bindings[0]).expect("BindingStatus must serialize");
    let (cleared_obj, default_obj) = match (&cleared, &default_json) {
        (Value::Object(c), Value::Object(d)) => (c, d),
        _ => panic!("BindingStatus must serialize as a JSON object"),
    };
    let mut stale: Vec<String> = Vec::new();
    for (key, got) in cleared_obj.iter() {
        if IDENTITY_KEYS.contains(&key.as_str()) {
            continue;
        }
        let want = default_obj.get(key).unwrap_or(&Value::Null);
        if got != want {
            stale.push(format!("{key}: got {got}, want {want}"));
        }
    }
    assert!(
        stale.is_empty(),
        "#5190: zero_unbound_slot left these fields stale on an unbound \
         slot (copy_live_snapshot writes them, the reset half must clear \
         them): {stale:?}"
    );
}

// --- #6637: the neighbor-monitor thread leak -------------------------------

/// `StoppedCoordinator` is a `Coordinator` that tears itself down on drop.
///
/// THE LEAK. A successful reconcile ends in `bring_up_workers` ->
/// `start_post_readiness_neighbor_services`, which spawns the `neigh-monitor`
/// thread and stores its stop flag + join handle on the coordinator. There is no
/// `impl Drop for Coordinator`, so a test that builds one, reconciles, and lets
/// it fall out of scope stops nothing. Measured across the suite before this
/// change: 8 spawned, 1 stopped, **7 leaked**.
///
/// WHY ONLY THIS THREAD. Its two siblings self-terminate: `neigh-warmer` and
/// `neigh-resolver` both exit on `RecvTimeoutError::Disconnected`, and dropping
/// the coordinator drops the channel producers they are watching.
/// `neigh_monitor_thread` has no channel — only an `Arc<AtomicBool>` whose other
/// clone it holds itself — so it can never learn its owner is gone. It keeps a
/// netlink socket subscribed to `RTMGRP_NEIGH`, wakes twice a second on its
/// 500ms `SO_RCVTIMEO`, and parses every ARP/NDP event on the host into a map
/// nobody reads, for the life of the test binary.
///
/// PRODUCTION IS NOT AFFECTED and needs no change: every reconcile tears down
/// first (`reconcile/teardown.rs` -> `stop_inner`), the respawn is gated on
/// `monitor_stop.is_none()`, and the daemon's exit path and `shutdown` verb both
/// join it. The machinery is complete and correct — the tests simply never
/// pulled it.
///
/// RAII rather than a `stop()` at the end of each test, deliberately. 28 test
/// functions in this file call `reconcile`; most fail preflight before bringup
/// today, so any one of them that later starts passing preflight would join the
/// leak set silently. A guard makes the correct construction the default one.
struct StoppedCoordinator(Coordinator);

impl StoppedCoordinator {
    fn new() -> Self {
        Self(Coordinator::new())
    }

    /// Wrap a coordinator a fixture helper already built.
    fn wrap(inner: Coordinator) -> Self {
        Self(inner)
    }
}

impl std::ops::Deref for StoppedCoordinator {
    type Target = Coordinator;
    fn deref(&self) -> &Coordinator {
        &self.0
    }
}

impl std::ops::DerefMut for StoppedCoordinator {
    fn deref_mut(&mut self) -> &mut Coordinator {
        &mut self.0
    }
}

impl Drop for StoppedCoordinator {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// neigh_monitor_thread_count reads this process's own thread names and counts
/// the live `neigh-monitor` threads.
///
/// `/proc/self/task/*/comm` is the same surface the wedged-process dump in the
/// issue was read from, so the gate below measures exactly what was reported
/// rather than a proxy for it.
fn neigh_monitor_thread_count() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| {
            std::fs::read_to_string(e.path().join("comm"))
                .map(|c| c.trim() == "neigh-monitor")
                .unwrap_or(false)
        })
        .count()
}

/// await_neigh_monitor_count waits (bounded) for the live `neigh-monitor` count
/// to reach `want`, returning the last value it saw.
///
/// An instant sample after `reconcile` returns is RACY and fails
/// intermittently: `std::thread::Builder::name` is applied by the CHILD at
/// startup, so the thread can exist while `/proc/self/task/<tid>/comm` still
/// holds the parent's name. The first version of this gate sampled immediately
/// and reported `during=0` while the monitor was demonstrably running.
///
/// The teardown direction does not need this — `stop()` JOINS — but it polls
/// through the same helper so both directions read one implementation.
fn await_neigh_monitor_count(want: usize) -> usize {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let got = neigh_monitor_thread_count();
        if got == want || std::time::Instant::now() >= deadline {
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// #6637 fail-on-revert gate: a coordinator bringup must not leave a
/// `neigh-monitor` thread behind.
///
/// It asserts BOTH directions, and the second is what stops the fix degenerating
/// into "do not start the monitor at all":
///
///   - after a successful reconcile the count must RISE by exactly one, and
///   - after teardown it must return to where it started.
///
/// Removing `stop_and_join_monitor()` from `stop_inner` reds the second.
/// Preventing the spawn reds the first.
#[test]
fn coordinator_bringup_does_not_leak_a_neigh_monitor_thread_6637() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let before = neigh_monitor_thread_count();
    // #7413 anti-rot precondition. The guard above makes this hold; an
    // ELEVENTH spawner added without taking it breaks it, and this fails
    // naming the missing lock instead of failing later as an off-by-one delta
    // that reads like a real monitor leak.
    assert_eq!(
        before, 0,
        "a neigh-monitor thread is already running when this gate started \
         (before={before}). Either a sibling test spawned one without taking \
         neigh_monitor_test_serial(), or a previous test leaked one; both make \
         the deltas below measure the wrong thing (#7413)"
    );

    let mut coordinator = Coordinator::new();
    zone_counter_live_coordinator(&mut coordinator);
    let mut bindings = zone_counter_binding();
    let mut candidate = mandatory_ok_snapshot(6);
    candidate.zones = zone_counter_zones(&[100, 300]);
    coordinator.force_worker_healthy_stub = true;
    let _ = coordinator.reconcile(Some(&candidate), &mut bindings, 64);

    let during = await_neigh_monitor_count(before + 1);
    if during != before + 1 {
        // Not a silent skip: if bringup stopped spawning the monitor, the
        // teardown assertion below would pass vacuously and this gate would
        // certify a fix that simply disabled the feature.
        coordinator.stop();
        panic!(
            "expected a reconcile to spawn exactly one neigh-monitor thread \
             (before={before} during={during}); the teardown half of this gate \
             is meaningless unless the spawn actually happened"
        );
    }

    coordinator.stop();

    let after = await_neigh_monitor_count(before);
    assert_eq!(
        after, before,
        "a neigh-monitor thread survived teardown (before={before} during={during} \
         after={after}); it holds a netlink socket subscribed to RTMGRP_NEIGH and \
         keeps parsing every host neighbor event into a map nobody reads, for the \
         life of the process"
    );
}

/// #6637: the RAII guard must actually stop the monitor on drop, which is what
/// the converted tests rely on.
///
/// Deleting the `Drop` impl reds this.
#[test]
fn stopped_coordinator_guard_joins_the_neigh_monitor_on_drop_6637() {
    // #7413: this test spawns a `neigh-monitor` thread, and the #6637 leak
    // gates read the PROCESS-WIDE count of those. Held for the whole body so a
    // parallel sibling cannot move that count inside their window.
    let _neigh_serial = crate::afxdp::neigh_monitor_test_serial();
    let before = neigh_monitor_thread_count();
    // #7413 anti-rot precondition. The guard above makes this hold; an
    // ELEVENTH spawner added without taking it breaks it, and this fails
    // naming the missing lock instead of failing later as an off-by-one delta
    // that reads like a real monitor leak.
    assert_eq!(
        before, 0,
        "a neigh-monitor thread is already running when this gate started \
         (before={before}). Either a sibling test spawned one without taking \
         neigh_monitor_test_serial(), or a previous test leaked one; both make \
         the deltas below measure the wrong thing (#7413)"
    );
    {
        let mut coordinator = StoppedCoordinator::new();
        zone_counter_live_coordinator(&mut coordinator);
        let mut bindings = zone_counter_binding();
        let mut candidate = mandatory_ok_snapshot(6);
        candidate.zones = zone_counter_zones(&[100, 300]);
        coordinator.force_worker_healthy_stub = true;
        let _ = coordinator.reconcile(Some(&candidate), &mut bindings, 64);
        assert_eq!(
            await_neigh_monitor_count(before + 1),
            before + 1,
            "the guard must not suppress the spawn — it must clean up AFTER one"
        );
    }
    assert_eq!(
        await_neigh_monitor_count(before),
        before,
        "StoppedCoordinator dropped without joining the neigh-monitor thread"
    );
}

/// #6593: EVERY pre-publish sibling must already be worker-visible when the
/// runtime view goes out — not just the CoS owner map.
///
/// `refresh_runtime_snapshot` relies on a documented order. The runtime view is
/// the single worker-visible gate and a worker reads it first, so any structure
/// published AFTER it opens a window where a worker holds new forwarding paired
/// with a stale sibling.
///
/// Seven structures are in that set: the six CoS maps published by
/// `refresh_cos_runtime_maps` (owner-by-queue, owner-live, root leases, exact
/// backlogs, queue leases, queue vtime floors) and `ha.fabrics`. Before this
/// test exactly ONE of them had an ordering assertion —
/// `refresh_runtime_snapshot_publishes_cos_owner_map_before_forwarding` — and
/// that assertion had a hoist bypass. The other six had none.
///
/// The invariant is asserted uniformly and without knowing what changed: for
/// each sibling, the `Arc` that was worker-visible at the capture instant must
/// be the SAME allocation as the one visible after the refresh. Same means it
/// was already published when the view went out. Different means it was
/// published afterwards — the defect. A sibling this refresh did not republish
/// compares equal, which is correct: there is nothing to order.
///
/// Hoist resistance comes from `previous_view` (the #6592 technique): the
/// capture retains the still-visible view from the same instant and asserts it
/// is NOT the post-publish view, so the capture proves its own position.
/// Without it, moving the view store ABOVE the capture would make every
/// `ptr_eq` above pass vacuously by reading already-published values — which is
/// precisely the bypass the one pre-existing guard had.
#[test]
fn refresh_runtime_snapshot_publishes_every_sibling_before_the_view() {
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

    assert!(
        coordinator.prepublish_siblings.is_none(),
        "no snapshot applied yet",
    );

    // A snapshot that actually MOVES the CoS structures: a new shaped
    // interface with a scheduler map creates queue (80, 0). A snapshot that
    // changed nothing would make every ptr_eq trivially true and the test
    // vacuous.
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
        inet_precedence_classifiers: vec![],
    });

    coordinator
        .refresh_runtime_snapshot(&snapshot)
        .expect("refresh_runtime_snapshot must succeed");

    let captured = coordinator
        .prepublish_siblings
        .clone()
        .expect("refresh must record the siblings at the view-publish point");

    // Guard against a vacuous run: this snapshot must actually have moved the
    // CoS owner map, or every assertion below would hold trivially.
    assert_eq!(
        captured.cos_owner_worker_by_queue.get(&(80, 0)),
        Some(&2u32),
        "setup: the CoS owner map must already own the new queue at publish time — \
         if this snapshot did not move the CoS structures the ordering assertions \
         below would pass vacuously",
    );

    // THE INVARIANT, part 1: every sibling visible at publish time is the same
    // allocation a worker sees now.
    for (name, same) in [
        (
            "cos.owner_worker_by_queue",
            Arc::ptr_eq(
                &captured.cos_owner_worker_by_queue,
                &coordinator.cos.owner_worker_by_queue.load_full(),
            ),
        ),
        (
            "cos.owner_live_by_queue",
            Arc::ptr_eq(
                &captured.cos_owner_live_by_queue,
                &coordinator.cos.owner_live_by_queue.load_full(),
            ),
        ),
        (
            "cos.root_leases",
            Arc::ptr_eq(
                &captured.cos_root_leases,
                &coordinator.cos.root_leases.load_full(),
            ),
        ),
        (
            "cos.exact_backlogs",
            Arc::ptr_eq(
                &captured.cos_exact_backlogs,
                &coordinator.cos.exact_backlogs.load_full(),
            ),
        ),
        (
            "cos.queue_leases",
            Arc::ptr_eq(
                &captured.cos_queue_leases,
                &coordinator.cos.queue_leases.load_full(),
            ),
        ),
        (
            "cos.queue_vtime_floors",
            Arc::ptr_eq(
                &captured.cos_queue_vtime_floors,
                &coordinator.cos.queue_vtime_floors.load_full(),
            ),
        ),
        (
            "ha.fabrics",
            Arc::ptr_eq(&captured.ha_fabrics, &coordinator.ha.fabrics.load_full()),
        ),
    ] {
        assert!(
            same,
            "#6593: {name} was published AFTER the runtime view. The view is the single \
             worker-visible gate and a worker reads it first, so a worker can observe this \
             refresh's forwarding paired with the PREVIOUS {name}. Publish it before \
             `publish_runtime_view`.",
        );
    }

    // THE INVARIANT, part 2 (hoist resistance): the capture sat BEFORE the
    // view store, so the view it retained is not the one now published.
    let published_view = coordinator.ha.runtime.load_full();
    assert!(
        !Arc::ptr_eq(&captured.previous_view, &published_view),
        "#6593: the sibling capture ran at or after the view store, so every ptr_eq above \
         passed vacuously by reading already-published values. Capture before the store — \
         this is the same bypass the single pre-existing CoS-owner guard had.",
    );
}

/// #6873 STEP 2 — the ORDERING INVARIANT that makes the host-inbound
/// cold-boot window unreachable.
///
/// `host_inbound_admits` takes its `None => true` arm for every zone id when
/// `zone_host_inbound` is empty, so an empty table admits every host-bound
/// packet — demonstrated, not assumed, by
/// `cold_forwarding_state_admits_every_host_inbound_service_6873`
/// (forwarding/host_inbound_tests.rs).
///
/// #6873 asked whether that state is observable before the first snapshot is
/// installed, and proposed gating the admit site on `snapshot_installed`. It is
/// NOT observable, so such a gate would be dead code. The reason is lifecycle
/// ordering, not a flag:
///
///   - `bring_up_workers` is the only worker spawn path (README:133 forbids a
///     bare `std::thread::spawn` for a worker), and it runs AFTER
///     `apply_snapshot` has published a snapshot-derived forwarding state;
///   - `reconcile(None, ..)` takes its early exit AFTER `tear_down`, so "no
///     snapshot" means "no workers" rather than "workers on an empty table";
///   - inside `stop_inner`, `workers.stop_and_clear(..)` JOINS every worker
///     thread before `self.forwarding = ForwardingState::default()` (#6592).
///
/// So a worker exists only while a snapshot-derived state is published. What
/// this cell adds, measured rather than assumed:
///
///   - the "no worker survives" half is ALREADY pinned, by
///     `teardown_quiesce_skipped_on_no_snapshot_even_with_live_workers` — a
///     cell whose stated subject is #2522 quiesce timing, but which seeds a
///     live worker and asserts `workers.records().is_empty()`. Removing the
///     teardown reds it too.
///   - the "the dangerous state is actually REACHED" half was pinned by
///     nothing. Deleting `self.forwarding = ForwardingState::default()` from
///     `stop_inner` reds THIS cell alone; the quiesce cell stays green because
///     it never looks at the forwarding state.
///
/// That second half is what makes the first one mean something: without it,
/// "no reader survives" guards a state nobody showed was dangerous, and the
/// pairing with `cold_forwarding_state_admits_every_host_inbound_service_6873`
/// (the payload proof) has no anchor at this end.
///
/// The cell that LOOKS like it covers this does not:
/// `reconcile_with_none_snapshot_reaches_no_snapshot_early_exit` (#1328)
/// asserts `workers.live.is_empty()` from a `Coordinator::new()` that never had
/// a worker, so removing the teardown leaves it GREEN. A fixture that cannot
/// produce the state it asserts absent is mutation-insensitive by construction.
///
/// Fail-on-revert: stop clearing the worker records and the surviving-worker
/// assertion goes RED (with the quiesce cell, and NOT the #1328 cell); stop
/// defaulting the forwarding state and the emptied-table assertion goes RED
/// alone.
#[test]
fn no_snapshot_reconcile_leaves_no_reader_for_the_empty_table_6873() {
    const ZONE: u16 = 7;

    let mut coordinator = Coordinator::new();

    // A LIVE worker record: the reader that must not survive.
    coordinator
        .workers
        .register(0, WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle()), None);

    // A POPULATED host-inbound table: the state that must be emptied. Both
    // halves matter — with an empty table the "it was emptied" assertion is
    // vacuous, and with no worker the "no reader survives" assertion is.
    let mut zone = ZoneHostInbound::default();
    zone.tcp_ports.insert(22);
    coordinator.forwarding.zone_host_inbound.insert(ZONE, zone);

    assert!(
        !coordinator.workers.records().is_empty(),
        "fixture broken: there must be a live worker record BEFORE the reconcile, \
         or this cell cannot tell a teardown from a no-op"
    );
    assert!(
        !coordinator.forwarding.zone_host_inbound.is_empty(),
        "fixture broken: the host-inbound table must be POPULATED before the \
         reconcile, or 'it was emptied' proves nothing"
    );

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
        ..BindingStatus::default()
    }];
    let _ = coordinator.reconcile(None, &mut bindings, 64);

    // The dangerous state IS reached — a no-snapshot reconcile really does
    // leave the admit path's table empty.
    assert!(
        coordinator.forwarding.zone_host_inbound.is_empty(),
        "a no-snapshot reconcile must reset the forwarding state, leaving the \
         host-inbound table empty — if this ever stops being true the cell below \
         is guarding nothing"
    );
    // ...and NOTHING survives that could observe it. This is the invariant that
    // makes a `snapshot_installed` gate at the admit site unnecessary.
    assert!(
        coordinator.workers.records().is_empty(),
        "a worker record survived a no-snapshot reconcile — it would be reading a \
         forwarding state whose empty zone_host_inbound admits EVERY host-bound \
         packet (#6873). The teardown-before-early-exit ordering is what prevents \
         that, and it has just been broken"
    );
    assert!(
        coordinator.workers.live.is_empty(),
        "no live worker may outlive the forwarding state it was reading"
    );
}

/// #6979: the retirement sweep must be WIRED, one-shot, and must not touch a
/// live worker's reservations.
///
/// `PortAllocator::retire_worker` (#7092) is already covered by
/// `nat::tests_pool` — that it clears one bit, spares a second holder, and frees
/// only when the mask empties. None of that binds this change, which is the
/// CALL SITE: #7092 landed the primitive deliberately unwired, and a test of the
/// primitive passes identically whether or not anything ever calls it. So this
/// drives the coordinator entry point instead.
#[test]
fn retire_dead_worker_holders_reclaims_only_dead_workers_6979() {
    use crate::nat::NatHolder;
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let atomics = rec.handle.runtime_atomics.clone();
    coordinator.workers.register(3, rec, None);

    // A live interface-mode allocation held by worker 3.
    let egress: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let alloc = coordinator
        .forwarding
        .iface_nat_allocators
        .allocator_for(egress)
        .expect("allocator");
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.5".parse().unwrap(),
        dst_ip: "198.51.100.9".parse().unwrap(),
        src_port: 4000,
        dst_port: 80,
        routing_scope: 0,
    };
    let translated = crate::nat::TranslatedTuple {
        ip: egress,
        port: 20000,
    };
    assert!(
        alloc.reserve_flow(flow, translated, 0, false, 1_000, NatHolder::Worker(3)),
        "fixture must actually take the reservation, or the sweep below has \
         nothing to reclaim and would pass vacuously"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 20000),
        "fixture precondition: the port is occupied before any retirement"
    );

    // NEGATIVE CONTROL: worker 3 is ALIVE. The sweep must leave it alone — a
    // sweep that retired every worker would satisfy the positive case below
    // while freeing tuples out from under workers that are still forwarding,
    // which is the over-release the holder mask exists to prevent.
    assert_eq!(
        coordinator.retire_dead_worker_holders(),
        0,
        "a LIVE worker's reservations must not be reclaimed"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 20000),
        "...and its port must still be occupied"
    );
    assert!(
        !atomics.holders_retired.load(Ordering::Relaxed),
        "a live worker must not be latched as retired"
    );

    // The worker panics: supervisor sets `dead` and the thread exits.
    atomics.dead.store(true, Ordering::Relaxed);

    assert_eq!(
        coordinator.retire_dead_worker_holders(),
        1,
        "a dead worker's last-holder reservation must be reclaimed — without \
         this wiring the bit survives for the life of the allocator and the \
         pool port is never returned (#7092's leak, unwired until #6979)"
    );
    assert!(
        !alloc.debug_is_port_occupied(0, 20000),
        "the reclaimed port must be free for a new flow"
    );
    assert!(
        atomics.holders_retired.load(Ordering::Relaxed),
        "the one-shot latch must be set after the sweep"
    );

    // ONE-SHOT, and the fixture has to be built so that this can actually FAIL.
    //
    // Asserting "the second call returns 0" against the state left above is
    // VACUOUS: the first sweep already freed the only record, so a second sweep
    // finds nothing to free whether or not the latch works. Measured — mutating
    // the latch away left that assertion green.
    //
    // So take a NEW reservation for the same dead worker first. With the latch,
    // the second sweep skips the worker entirely and the new reservation
    // survives. Without it, the sweep runs again and frees it. That is the
    // hazard #7092's doc named as the reason it would not choose this call
    // site: without "already retired" state every 1 Hz tick re-walks
    // `live_by_flow` under each allocator's mutex forever.
    let flow2 = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.6".parse().unwrap(),
        dst_ip: "198.51.100.9".parse().unwrap(),
        src_port: 4001,
        dst_port: 80,
        routing_scope: 0,
    };
    assert!(
        alloc.reserve_flow(flow2, translated, 0, false, 3_000, NatHolder::Worker(3)),
        "fixture: a second reservation must take, or the one-shot check below is          vacuous again"
    );
    assert_eq!(
        coordinator.retire_dead_worker_holders(),
        0,
        "the sweep must be one-shot per dead worker, not once per status tick"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 20000),
        "the one-shot latch must stop the second sweep from touching a          reservation taken after the retirement"
    );
}

/// #6979: the retirement must be REACHED from the production status path, not
/// merely reachable.
///
/// The sibling test above drives `retire_dead_worker_holders` directly, which
/// binds what the sweep DOES and nothing about whether anything calls it —
/// measured: deleting the call from `server/helpers/status.rs` left that test
/// green. #7092 landed this primitive deliberately unwired, so "the function is
/// correct" is exactly the state this change is supposed to move past, and a
/// test that cannot tell the two apart is the wrong instrument.
///
/// So this enters through `refresh_status`, the real 1 Hz status entry point
/// that the call lives in.
#[test]
fn refresh_status_reclaims_dead_worker_holders_6979() {
    use crate::nat::NatHolder;
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let atomics = rec.handle.runtime_atomics.clone();
    coordinator.workers.register(5, rec, None);

    let egress: std::net::IpAddr = "192.0.2.8".parse().unwrap();
    let alloc = coordinator
        .forwarding
        .iface_nat_allocators
        .allocator_for(egress)
        .expect("allocator");
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.9".parse().unwrap(),
        dst_ip: "198.51.100.4".parse().unwrap(),
        src_port: 5000,
        dst_port: 443,
        routing_scope: 0,
    };
    let translated = crate::nat::TranslatedTuple {
        ip: egress,
        port: 30000,
    };
    assert!(
        alloc.reserve_flow(flow, translated, 0, false, 1_000, NatHolder::Worker(5)),
        "fixture must take the reservation"
    );
    atomics.dead.store(true, Ordering::Relaxed);

    let mut state = crate::server::state::ServerState {
        status: Default::default(),
        snapshot: None,
        afxdp: coordinator,
        state_writer: std::sync::Arc::new(crate::state_writer::StateWriter::new()),
    };
    crate::server::helpers::status::refresh_status(&mut state);

    assert!(
        !alloc.debug_is_port_occupied(0, 30000),
        "a status refresh must reclaim a dead worker's stranded NAT reservation \
         — if this passes only when retire_dead_worker_holders is called by hand, \
         the primitive is still unwired and #7092's leak is still open"
    );
    assert!(
        atomics.holders_retired.load(Ordering::Relaxed),
        "the status path must latch the worker as retired"
    );
}

/// #7092 REPLAN route: a generation teardown must reclaim holder bits across
/// ALL THREE allocator families, for a worker that is perfectly healthy.
///
/// `dead` is written only by the panic supervisor, so a replan — which stops and
/// joins a healthy generation — never sets it. #8069's sweep is keyed on `dead`
/// and therefore cannot see this case at all; that gap is exactly what kept
/// #7092 open after the panic route closed.
///
/// The fixture covers interface-mode, pool-mode and NAT64 deliberately. #8069's
/// test exercised interface-mode only, and its disclosed consequence was that
/// dropping either of the other two sweeps red nothing. Binding one family and
/// claiming three is the shape that lets a sweep silently stop covering a
/// family, so all three hold a live reservation here and each is asserted
/// separately.
#[test]
fn stop_inner_retires_holders_for_all_allocator_families_7092() {
    use crate::nat::{NatHolder, PortAllocator, SourceNatFlowKey, TranslatedTuple};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let atomics = rec.handle.runtime_atomics.clone();
    coordinator.workers.register(2, rec, None);
    assert!(
        !atomics.dead.load(Ordering::Relaxed),
        "the worker must be HEALTHY: a replan retires a live generation, and a \
         dead-keyed sweep cannot see that"
    );

    let flow = |src_port: u16| SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.11".parse().unwrap(),
        dst_ip: "198.51.100.11".parse().unwrap(),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    };

    // (1) interface-mode
    let egress: IpAddr = "192.0.2.20".parse().unwrap();
    let iface_alloc = coordinator
        .forwarding
        .iface_nat_allocators
        .allocator_for(egress)
        .expect("iface allocator");
    assert!(iface_alloc.reserve_flow(
        flow(6001),
        TranslatedTuple { ip: egress, port: 40001 },
        0,
        false,
        1_000,
        NatHolder::Worker(2),
    ));

    // (2) pool-mode rule. The allocator is Clone-shared, so the clone kept here
    // observes the same state as the one inside `source_nat_rules`.
    let mut rule = crate::nat::SourceNatRule::default();
    rule.pool_allocator = PortAllocator::new(1, 40000, 40100);
    let pool_alloc = rule.pool_allocator.clone();
    let pool_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    assert!(pool_alloc.reserve_flow(
        flow(6002),
        TranslatedTuple { ip: pool_addr, port: 40002 },
        0,
        false,
        1_000,
        NatHolder::Worker(2),
    ));
    coordinator.forwarding.source_nat_rules.push(rule);

    // (3) NAT64 prefix
    let nat64_alloc = PortAllocator::new(1, 40000, 40100);
    let nat64_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    assert!(nat64_alloc.reserve_flow(
        flow(6003),
        TranslatedTuple { ip: nat64_addr, port: 40003 },
        0,
        false,
        1_000,
        NatHolder::Worker(2),
    ));
    coordinator
        .forwarding
        .nat64
        .prefixes
        .push(crate::nat64::Nat64Prefix::for_test(
            [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![Ipv4Addr::new(198, 51, 100, 77)],
            nat64_alloc.clone(),
        ));

    // Preconditions: without these the assertions after teardown could pass
    // against reservations that were never taken.
    assert!(iface_alloc.debug_is_port_occupied(0, 40001), "iface fixture");
    assert!(pool_alloc.debug_is_port_occupied(0, 40002), "pool fixture");
    assert!(nat64_alloc.debug_is_port_occupied(0, 40003), "nat64 fixture");

    coordinator.stop_inner(false);

    assert!(
        !iface_alloc.debug_is_port_occupied(0, 40001),
        "interface-mode reservation survived the generation teardown"
    );
    assert!(
        !pool_alloc.debug_is_port_occupied(0, 40002),
        "pool-mode reservation survived the generation teardown — this is the \
         family #8069's fixture did not cover"
    );
    assert!(
        !nat64_alloc.debug_is_port_occupied(0, 40003),
        "NAT64 reservation survived the generation teardown — the other family \
         #8069's fixture did not cover"
    );
}

// #7160 (#2387) — the two routing-domain accessors the session-sync handler
// calls. Both answer questions a peer-synced session cannot answer for itself:
// which domain to import it under, and which domains a bare-5-tuple delete has
// to sweep.
mod routing_domain_7160 {
    use super::*;

    const DOMAIN_A: u32 = 100_001;
    const DOMAIN_B: u32 = 100_002;

    fn coordinator_with_domains() -> Coordinator {
        let mut c = Coordinator::new();
        // Two member interfaces in tenant-a, one in tenant-b, one in the
        // default instance. The duplicate is deliberate: `routing_domains`
        // must DEDUPE, or the delete sweep repeats work per interface rather
        // than per instance.
        c.forwarding.has_routing_domains = true;
        c.forwarding.ifindex_to_routing_domain.insert(10, DOMAIN_A);
        c.forwarding.ifindex_to_routing_domain.insert(11, DOMAIN_A);
        c.forwarding.ifindex_to_routing_domain.insert(12, DOMAIN_B);
        // A trunk unit: the logical ifindex is what the map is keyed on, so the
        // (parent, vlan) -> logical mapping has to be consulted.
        c.forwarding.ingress_logical_ifindex.insert((20, 50), 12);
        c
    }

    #[test]
    fn synced_routing_domain_resolves_through_the_logical_unit() {
        let c = coordinator_with_domains();
        assert_eq!(c.synced_routing_domain(10, 0), Some(DOMAIN_A));
        assert_eq!(
            c.synced_routing_domain(20, 50),
            Some(DOMAIN_B),
            "a trunk unit must resolve its LOGICAL ifindex's domain, not its \
             parent's — the parent maps only to its first unit"
        );
    }

    /// The THIRD state. A session whose ingress identity the peer could not
    /// name arrives with ifindex 0, and on a node that runs routing instances
    /// that is UNKNOWN, not "the default instance".
    ///
    /// This cell asserted the opposite until the sync path was re-examined:
    /// it claimed such a session "must import at domain 0 — the pre-#7160
    /// identity". That reading is wrong because 0 is not a neutral placeholder
    /// on a VRF node, it is the DEFAULT ROUTING INSTANCE — so importing there
    /// files a tenant's session in another tenant's identity space, where the
    /// domain-agnostic fallback probe can reach it.
    ///
    /// FAIL-ON-REVERT: collapse `None` back into `Some(0)` and this goes red.
    #[test]
    fn an_unnamed_peer_ingress_is_unknown_not_the_default_domain() {
        let c = coordinator_with_domains();
        for (ifindex, why) in [
            (0i32, "the sender had no cluster-stable ingress name to fold"),
            (-1, "a negative ifindex is not an interface"),
        ] {
            assert_eq!(
                c.synced_routing_domain(ifindex, 0),
                None,
                "ifindex {ifindex} ({why}) must resolve UNKNOWN on a node with \
                 routing instances, so the caller refuses rather than filing \
                 the session under the default instance"
            );
        }
        // An ifindex this node knows nothing about is a different case: the
        // request DID name an interface, this node resolved it, and it is in
        // no routing instance. That is genuinely the default domain.
        assert_eq!(
            c.synced_routing_domain(999, 0),
            Some(0),
            "a NAMED ingress that resolves to no routing instance is the \
             default domain, not unknown — refusing it would drop every \
             default-instance session on a VRF node"
        );
    }

    /// The same input on a node with NO routing instances is not unknown at
    /// all: 0 is the only domain there, so nothing is ever refused and a
    /// single-instance cluster keeps importing exactly as it did pre-#7160.
    #[test]
    fn an_unnamed_peer_ingress_is_the_default_domain_with_no_membership() {
        let c = Coordinator::new();
        assert_eq!(c.synced_routing_domain(0, 0), Some(0));
        assert_eq!(c.synced_routing_domain(-1, 0), Some(0));
        assert_eq!(c.synced_routing_domain(24, 0), Some(0));
    }

    /// The delete sweep's domain set: one entry per INSTANCE, not per member
    /// interface, and never 0 (the bare key already covers the default
    /// instance).
    #[test]
    fn routing_domains_is_the_deduped_nonzero_set() {
        let c = coordinator_with_domains();
        assert_eq!(c.routing_domains(), vec![DOMAIN_A, DOMAIN_B]);
    }

    /// The gate: with no routing-instance interface membership both accessors
    /// are inert, so the delete retry loop does not exist and the import path
    /// resolves 0 without a map probe.
    #[test]
    fn no_membership_makes_both_accessors_inert() {
        let c = Coordinator::new();
        assert!(!c.forwarding.has_routing_domains);
        assert!(
            c.routing_domains().is_empty(),
            "the per-domain delete retry must be a no-op in a deployment with \
             no routing-instance interface membership"
        );
        assert_eq!(c.synced_routing_domain(10, 0), Some(0));
    }
}

// ---------------------------------------------------------------------------
// #6979 F4 — a DROPPED `DeleteSynced` stranded the worker's NAT reservation.
//
// The finding says the coordinator removes the key from shared authority BEFORE
// queueing `DeleteSynced`, so "a worker that passes its command stage and then
// stops in between never releases". That route is real and it is BOUNDED: the
// worker is gone, so `retire_dead_worker_holders` (#8069, panic) or
// `retire_all_worker_holders` (#7092, generation teardown) clears its bit.
//
// MEASURED at the parent of this change, the UNBOUNDED route is a different
// one: `push_bounded` DROPS the command when the queue is at
// `MAX_PENDING_WORKER_COMMANDS`, and its return was ignored. The worker stays
// ALIVE — so neither sweep selects it, both being keyed on a worker that is
// dead or being torn down — and shared authority is already gone, so no replay
// re-delivers. Probe output at the parent: queue-drop delta 1, port still
// occupied, `dead` false, dead-worker sweep freed 0.
//
// So the issue's own closing note ("bounded by the holder-set") is right about
// the mechanism it names and wrong about the finding as a whole.
// ---------------------------------------------------------------------------

fn f4_pool_rules() -> Vec<crate::nat::SourceNatRule> {
    crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 20000,
        port_high: 20000,
        ..crate::SourceNATRuleSnapshot::default()
    }])
}

fn f4_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.0.5".parse().unwrap(),
        dst_ip: "198.51.100.9".parse().unwrap(),
        src_port: 4000,
        dst_port: 80,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn f4_filler_key(i: usize) -> crate::session::SessionKey {
    let mut key = f4_key();
    key.src_port = 30000 + (i as u16 % 20000);
    key.dst_port = 81;
    key
}

/// Seat a synced session in shared authority with worker `worker_id` holding
/// its pool reservation, exactly as an import followed by that worker's
/// `UpsertSynced` would leave it.
fn f4_seed(coordinator: &mut Coordinator, worker_id: u32) -> crate::nat::TranslatedTuple {
    use crate::nat::NatHolder;
    coordinator.forwarding.source_nat_rules = f4_pool_rules();
    // #7209: PUBLISH. The synced delete path resolves its allocators through the
    // published view now, and an unpublished fixture leaves it releasing against
    // a DEFAULT forwarding with no rules — so the port stays held and the cell
    // reds for a reason that has nothing to do with what it tests.
    //
    // Equivalent in production, and that is checked rather than assumed:
    // `publish_runtime_view` clones `ForwardingState`, `PortAllocator` derives
    // `Clone` over an `Arc<PortAllocatorShared>`, so the published rules carry
    // the SAME allocator state. A deep-cloning allocator would have made this a
    // real port leak instead of a fixture gap.
    coordinator.publish_runtime_view();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    coordinator.workers.register(worker_id, rec, None);

    let key = f4_key();
    let translated = crate::nat::TranslatedTuple {
        ip: "203.0.113.1".parse().unwrap(),
        port: 20000,
    };
    let flow = crate::nat::SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        routing_scope: 0,
    };
    let alloc = &coordinator.forwarding.source_nat_rules[0].pool_allocator;
    assert!(
        alloc.reserve_flow(flow, translated, 0, false, 1_000, NatHolder::Worker(worker_id)),
        "fixture must take the reservation, or every assertion below is vacuous"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 20000),
        "fixture precondition: the port is occupied before the delete"
    );

    f4_seed_shared_only(coordinator, &key, translated);
    translated
}

/// Seed shared authority alone (no allocator reservation, no worker record).
fn f4_seed_shared_only(
    coordinator: &Coordinator,
    key: &crate::session::SessionKey,
    translated: crate::nat::TranslatedTuple,
) {
    // The session must be in SHARED AUTHORITY. Without it the delete finds
    // no `removed_entry`, so there is no NAT decision to release and the cell
    // would red for the wrong reason — measured while writing this: the first
    // fixture seeded only the allocator and the binding cell failed with the
    // fix applied.
    let entry = crate::afxdp::worker::SyncedSessionEntry {
        key: key.clone(),
        decision: crate::afxdp::SessionDecision {
            resolution: crate::afxdp::ForwardingResolution {
                disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: crate::nat::NatDecision {
                rewrite_src: Some(translated.ip),
                rewrite_src_port: Some(translated.port),
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: crate::afxdp::SessionOrigin::SyncImport,
        protocol: key.protocol,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    crate::afxdp::shared_ops::lock_shared_recover(&coordinator.sessions.synced)
        .insert(key.clone(), entry);
    assert!(
        crate::afxdp::shared_ops::lock_shared_recover(&coordinator.sessions.synced)
            .contains_key(&key),
        "fixture: the session must be in shared authority, or the delete has no \
         NAT decision to act on"
    );
}

fn f4_fill_queue(coordinator: &Coordinator, worker_id: u32) {
    use crate::afxdp::worker_queue::{self, MAX_PENDING_WORKER_COMMANDS};
    let records = coordinator.workers.records();
    let rec = records.get(&worker_id).expect("record");
    let mut pending = worker_queue::lock_recover(&rec.handle.commands);
    for i in 0..MAX_PENDING_WORKER_COMMANDS {
        pending.push_back(crate::afxdp::WorkerCommand::DeleteSynced(f4_filler_key(i)));
    }
    assert_eq!(
        pending.len(),
        MAX_PENDING_WORKER_COMMANDS,
        "fixture: the queue must be exactly at capacity so the next push is dropped"
    );
}

/// THE BINDING. A `DeleteSynced` the queue drops must not leave the reservation
/// behind: nothing else will ever free it.
///
/// RED AT THE PARENT: the port stays occupied for the life of the allocator.
#[test]
fn a_dropped_deletesynced_releases_the_workers_reservation_6979_f4() {
    use crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_DROPS;
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    f4_seed(&mut coordinator, 3);
    f4_fill_queue(&coordinator, 3);

    let drops_before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);
    coordinator.delete_synced_session(f4_key());
    assert!(
        WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed) > drops_before,
        "fixture: the DeleteSynced must actually have been DROPPED — if the queue \
         accepted it, this cell is testing the ordinary path and proves nothing"
    );

    assert!(
        !coordinator.forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, 20000),
        "the dropped DeleteSynced stranded 203.0.113.1:20000. Shared authority was \
         already removed, so no replay re-delivers the command; the worker is ALIVE, \
         so neither the dead-worker sweep (#8069) nor the generation-teardown sweep \
         (#7092) can see its holder bit. The port is held for the life of the \
         allocator (#6979 F4)"
    );
    assert_eq!(
        coordinator.session_delete_dropped_released_total(),
        1,
        "the repair must be counted — a silent repair of a silent drop leaves an \
         operator with no signal that a worker queue is saturating"
    );
}

/// THE OVER-RELEASE CONTROL. When the command IS queued, the coordinator must
/// NOT release: the worker will run the teardown itself, and releasing here too
/// would free a `(pool addr, port)` while that worker is still forwarding
/// through it — the direction of error `drop_holder_locked` forbids.
///
/// Fires on: releasing unconditionally instead of only on a dropped push.
#[test]
fn a_queued_deletesynced_leaves_the_release_to_the_worker_6979_f4() {
    let mut coordinator = Coordinator::new();
    f4_seed(&mut coordinator, 3);
    // Queue NOT filled: the push succeeds.

    coordinator.delete_synced_session(f4_key());

    assert!(
        coordinator.forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, 20000),
        "the coordinator released a reservation the worker is still going to release \
         itself. The command was queued, so the worker WILL run this teardown; \
         freeing the port here hands it to a new flow while the old one is still \
         being torn down (#6979 F4)"
    );
    assert_eq!(
        coordinator.session_delete_dropped_released_total(),
        0,
        "and nothing was dropped, so the repair counter must stay at zero"
    );
}



/// #8157: the bringup replay derives its set from the LIVE shared synced map,
/// and applies the tunnel-remap filter THERE.
///
/// Before this, `teardown::tear_down` cloned `snapshot_shared_session_entries()`
/// before `stop_inner(false)` and bringup replayed that clone. An entry landing
/// in the shared map between the clone and the replay was therefore absent from
/// the replay, never published to the new session map (`session_map_fd` is
/// `None` for the whole reconcile) and never replayed — while
/// `upsert_synced_session` still answered Go `Applied`. A split truth with no
/// signal.
///
/// WHAT THIS CELL CAN AND CANNOT BIND. It cannot drive the interleaving. Today
/// the snapshot-wide `ServerState` mutex excludes `sync_session` for the whole
/// reconcile, and bypassing the server does not help either, because
/// `reconcile` takes `&mut self` so safe Rust forbids a concurrent `&self`
/// upsert. #7209 is what makes the window reachable. So this binds the two
/// properties the fix rests on rather than the race:
///
///   A. an entry in the shared map is replayed — and with the
///      `preserved_synced_sessions` parameter DELETED, the live map is the only
///      set the replay can read, so the compiler carries half of this;
///   B. an entry whose tunnel the new snapshot purged is STILL filtered out.
///
/// B is the one that earns the cell. The filter used to run in `apply_snapshot`
/// against the captured `Vec`; moving the read without moving the filter would
/// resurrect purged sessions — including "half-dead pairs", since the predicate
/// also drops a purged forward entry's derived reverse companion. Delete the
/// `filter_replayed_synced_sessions` call at the new site and this reds.
#[test]
fn bringup_replay_reads_the_live_map_and_still_filters_purged_tunnels_8157() {
    use std::collections::BTreeMap;

    const PURGED_TUNNEL: u16 = 7;

    let mut coordinator = Coordinator::new();

    // Survivor: tunnel_endpoint_id 0, so no purge id can match it.
    let survivor_key = f4_key();
    f4_seed_shared_only(
        &coordinator,
        &survivor_key,
        crate::nat::TranslatedTuple {
            ip: "203.0.113.1".parse().unwrap(),
            port: 40000,
        },
    );

    // Purged: a DISTINCT key (or it replaces the survivor and the two legs
    // collapse into one) carrying the tunnel the new snapshot remapped.
    let mut purged_key = f4_key();
    purged_key.src_port = survivor_key.src_port.wrapping_add(1);
    f4_seed_shared_only(
        &coordinator,
        &purged_key,
        crate::nat::TranslatedTuple {
            ip: "203.0.113.1".parse().unwrap(),
            port: 40001,
        },
    );
    {
        let mut shared = crate::afxdp::lock_shared_recover(&coordinator.sessions.synced);
        let entry = shared
            .get_mut(&purged_key)
            .expect("the purged fixture entry is in shared authority");
        entry.decision.resolution.tunnel_endpoint_id = PURGED_TUNNEL;
    }

    assert_eq!(
        coordinator.snapshot_shared_session_entries().len(),
        2,
        "fixture broken: both entries must be in the LIVE shared map, or leg A \
         proves nothing about reading it and leg B has nothing to filter"
    );

    // One worker, so the replay builds exactly one command queue to observe.
    let workers: BTreeMap<u32, Vec<crate::afxdp::BindingPlan>> =
        BTreeMap::from([(0u32, Vec::new())]);

    // fd -1 makes the kernel publish fail — that is the #1789 counter's
    // business; `replicate_session_upsert` still enqueues, which is what this
    // cell reads.
    let queues = super::reconcile::bringup::replay_preserved_sessions(
        &mut coordinator,
        &workers,
        &[PURGED_TUNNEL],
        -1,
    );

    let queued = queues
        .get(&0)
        .expect("one worker queue")
        .lock()
        .expect("queue lock")
        .len();

    assert_eq!(
        queued, 1,
        "the bringup replay enqueued {queued} commands, want exactly 1. TWO means \
         the tunnel-remap filter did not run at the replay site, so a session \
         whose tunnel the new snapshot purged is resurrected (and a forward \
         entry drags its derived reverse companion with it — a half-dead pair). \
         ZERO means the replay read nothing from the live shared map, which is \
         the window #8157 closes and #7209 makes reachable."
    );
}

/// #8428 — the PRODUCER half of the shared_exact / V_min-floor divergence,
/// asserted against the real allocator rather than a mirror of its condition.
///
/// `queue_uses_shared_exact_service` routes on RATE alone (since #1598), while
/// this allocator admits on `exact && rate >= COS_SHARED_EXACT_MIN_RATE_BYTES`
/// — a STRICT SUBSET. The allocator's own comment states that divergence is
/// deliberate ("V_min-floor is exact-only ... both gates keep their own
/// predicate"), so the consumer is what must tolerate it, and
/// `cos_queue_v_min_continue` now does.
///
/// This cell exists so the divergence cannot be closed from the PRODUCER side
/// without someone noticing. If a later change starts allocating floors for
/// every routed queue, the consumer cells in `no_floor_8428.rs` would keep
/// passing — they only prove the absence is survivable — and the design would
/// have changed silently. The issue proposed pinning
/// `shared_exact() == vtime_floor.is_some()`, which is exactly that closure
/// expressed as an invariant; it is false by design here, so this pins the
/// containment instead.
#[test]
fn a_non_exact_high_rate_queue_gets_no_vtime_floor_8428() {
    let high_rate = 500_000_000u64; // well above COS_SHARED_EXACT_MIN_RATE_BYTES

    // CONTROL FIRST: exact + high rate DOES get a floor, so a missing floor
    // below is attributable to `exact = false` and not to the fixture.
    let mut exact_fixture = exact_queue_forwarding_fixture();
    {
        let q = &mut exact_fixture
            .cos
            .interfaces
            .get_mut(&80)
            .expect("iface")
            .queues[0];
        q.transmit_rate_bytes = high_rate;
        assert!(q.exact, "control premise: the fixture queue must be exact");
    }
    let control_floors =
        build_shared_cos_queue_vtime_floors_reusing_existing(&exact_fixture, 4, &BTreeMap::new());
    assert!(
        control_floors.contains_key(&(80, 4)),
        "control: an EXACT queue at a high rate must still receive a V_min floor \
         — if it does not, this cell cannot attribute the absence below"
    );

    // THE DIVERGENCE: same rate, not exact.
    let mut non_exact = exact_queue_forwarding_fixture();
    {
        let q = &mut non_exact
            .cos
            .interfaces
            .get_mut(&80)
            .expect("iface")
            .queues[0];
        q.transmit_rate_bytes = high_rate;
        q.exact = false;
    }
    let floors =
        build_shared_cos_queue_vtime_floors_reusing_existing(&non_exact, 4, &BTreeMap::new());
    assert!(
        !floors.contains_key(&(80, 4)),
        "a NON-exact queue must NOT receive a V_min floor even at a rate the \
         routing gate admits — the allocator is deliberately stricter than \
         `queue_uses_shared_exact_service`. Allocating one here would close the \
         divergence from the producer side, which is the fix shape #8428 \
         explicitly did not take (#8428)"
    );
}

// ===========================================================================
// #9367 — a PANICKED worker's V_min slot must be vacated by the dead-worker
// sweep.
//
// `PaddedVtimeSlot` has no TTL, generation or liveness input:
// `participating_v_min_snapshot` counts every non-sentinel peer slot and takes
// the MIN. Both production `vacate()` sites are executed by the OWNING worker
// (`cos/queue_ops/accounting.rs` when its last flow bucket on the queue
// drained, `worker/cos/mod.rs` on binding reset / HA demotion), and a worker
// that exits by panic executes neither. The supervisor catches the unwind,
// sets `dead`, and lets the thread go; nothing respawns it, and the floor Arc
// survives because `cos_leases.rs` reuses a floor while
// `f.slots.len() == num_workers` and a panic does not change `num_workers`.
//
// The frozen slot pins the cross-worker V_min, `cos_queue_v_min_continue`
// never passes, and the suspension window — restored to full only on a PASSING
// check — decays 1000 -> 64 and sticks. Steady state is 8 throttled + 64
// suspended: the fairness brake is off for 64/72 = 88.9% of drain
// opportunities on that exact class, additive to the RX capacity the panic
// already cost.
//
// The sweep that should own this ALREADY EXISTS. `retire_worker_holders_where`
// walks every `.dead` worker under a one-shot `holders_retired` CAS and
// reclaimed NAT holder bits only — #7092 fixed that class for NAT and did not
// enroll V_min.
//
// NOTHING EXISTING IS CLOSE. `v_min_tests/hard_cap.rs` and
// `v_min_tests/prepared_drain.rs` call `vacate()` themselves (the happy path);
// `v_min_tests/rejoiner.rs` covers the #4254 door, which was fixed.
// ===========================================================================

/// A floors map with one shared_exact queue and `num_workers` slots, matching
/// what `build_shared_cos_queue_vtime_floors_reusing_existing` produces.
fn v_min_floor_map_9367(
    num_workers: usize,
) -> std::collections::BTreeMap<
    (i32, u8),
    Arc<SharedCoSQueueVtimeFloor>,
> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        (7, 3u8),
        Arc::new(SharedCoSQueueVtimeFloor::new(num_workers)),
    );
    map
}

/// THE BINDER. A dead worker's participating slot must be vacated; a LIVE
/// worker's and a surviving PEER's must not.
///
/// FAIL-ON-REVERT: remove the `vacate_worker_v_min_slots` call from
/// `retire_worker_holders_where` and the dead worker's slot still reads
/// `Some(..)`, which is the state that pins the frontier.
///
/// Three controls, because a sweep that vacated everything would satisfy the
/// positive case while destroying the fairness coordination it exists to
/// protect:
///   - worker 3 is ALIVE for the first sweep — its slot must survive;
///   - worker 4 is a surviving PEER throughout — its slot must survive BOTH
///     sweeps;
///   - the dead worker's slot must be participating before the sweep, or the
///     assertion after it would pass on a slot that was never poisoned.
#[test]
fn retire_dead_worker_holders_vacates_the_dead_workers_v_min_slot_9367() {
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let dead_rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let dead_atomics = dead_rec.handle.runtime_atomics.clone();
    coordinator.workers.register(3, dead_rec, None);
    let peer_rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    coordinator.workers.register(4, peer_rec, None);

    let floors = v_min_floor_map_9367(6);
    let floor = floors.get(&(7, 3u8)).expect("fixture floor").clone();
    coordinator
        .cos
        .queue_vtime_floors
        .store(Arc::new(floors.clone()));

    // Both workers are participating with a committed vtime. Worker 3's is the
    // LOWER one, so it is the cross-worker V_min the survivors obey — the exact
    // value that gets frozen when it dies.
    floor.slots[3].publish(1_000);
    floor.slots[4].publish(9_000);
    assert_eq!(
        floor.slots[3].read(),
        Some(1_000),
        "fixture: the worker that is about to die must be PARTICIPATING, or the \
         assertion after the sweep would pass on a slot that was never poisoned",
    );
    assert_eq!(
        floor.participating_v_min_snapshot(4),
        (1, Some(1_000)),
        "fixture: worker 3's slot must be the frontier worker 4 obeys, or this \
         cell is not exercising the pin at all",
    );

    // NEGATIVE CONTROL: worker 3 is still ALIVE. The sweep must not touch it —
    // vacating a live worker's slot would remove it from the V_min reduction
    // while it is still serving, which is the opposite fairness defect.
    coordinator.retire_dead_worker_holders();
    assert_eq!(
        floor.slots[3].read(),
        Some(1_000),
        "a LIVE worker's V_min slot must not be vacated",
    );

    // The worker panics: the supervisor sets `dead` and the thread exits.
    dead_atomics.dead.store(true, Ordering::Relaxed);
    coordinator.retire_dead_worker_holders();

    assert_eq!(
        floor.slots[3].read(),
        None,
        "a dead worker's V_min slot must be vacated. Left participating, its \
         frozen queue_vtime pins the cross-worker V_min, cos_queue_v_min_continue \
         never passes, and every survivor on this shared_exact queue decays into \
         the minimum suspension window — the brake off for 64/72 of drain \
         opportunities (#9367)",
    );
    assert_eq!(
        floor.slots[4].read(),
        Some(9_000),
        "the SURVIVING peer's slot must be untouched — a sweep that vacated \
         every slot would satisfy the assertion above while deleting the \
         cross-worker coordination entirely",
    );
    assert_eq!(
        floor.participating_v_min_snapshot(4),
        (0, None),
        "with the dead peer gone, worker 4 must see no participating peer and \
         run unthrottled rather than obeying a frozen frontier",
    );
}

/// WIRING BIND. The vacate must be REACHED from the production status path.
///
/// The cell above drives `retire_dead_worker_holders` by hand, which binds
/// what the sweep DOES and says nothing about whether anything calls it — the
/// #6979 note on the sibling NAT pair records that deleting the call from
/// `server/helpers/status.rs` left the direct cell green. So this enters
/// through `refresh_status`, the real 1 Hz entry point.
///
/// THE FIXTURE IS BUILT BY THE PRODUCTION ALLOCATOR, not stored by hand.
/// `refresh_status`'s FIRST statement is `refresh_bindings`, which runs
/// `refresh_cos_runtime_maps` and rebuilds `cos.queue_vtime_floors` from the
/// plan. A hand-stored floor for a queue the plan does not contain is therefore
/// discarded before the sweep ever runs — measured: an earlier draft of this
/// cell stored `(7, 3)` into an otherwise-empty coordinator and the map was
/// EMPTY by the time `retire_dead_worker_holders` walked it, so the retained
/// Arc still read `Some(4242)`. Building the floor from
/// `exact_queue_forwarding_fixture` puts the queue in the plan, which is also
/// the only shape in which the reuse filter is exercised.
///
/// AND THAT IS WHY THE Arc CONTROL BELOW IS LOAD-BEARING. A REBUILT floor is
/// all-sentinel, so `read() == None` is bit-identical to the vacate having
/// worked. `Arc::ptr_eq` is the only thing that distinguishes "the sweep
/// released a poisoned slot" from "the plan handed us a fresh floor" — without
/// it this cell would pass just as happily on a tree where the vacate does not
/// exist but the reuse filter happens to miss.
#[test]
fn refresh_status_vacates_a_dead_workers_v_min_slot_9367() {
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let dead_rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let dead_atomics = dead_rec.handle.runtime_atomics.clone();
    coordinator.workers.register(2, dead_rec, None);
    coordinator
        .workers
        .register(3, WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle()), None);
    // An EXACT queue at or above COS_SHARED_EXACT_MIN_RATE_BYTES is the only
    // shape the V_min-floor allocator admits (#8428 pins that containment), and
    // six slots so worker id 2 is indexable and the reuse filter has a stable
    // `num_workers` to compare against. `exact_queue_forwarding_fixture`
    // defaults to 50 MB/s, which is BELOW the 2.5 Gb/s floor — measured: the
    // fixture assertion below caught that as "the plan produced no floor"
    // rather than passing on an empty map, which is what it is there for.
    coordinator.forwarding = exact_queue_forwarding_fixture();
    coordinator
        .forwarding
        .cos
        .interfaces
        .get_mut(&80)
        .expect("fixture iface")
        .queues[0]
        .transmit_rate_bytes = 500_000_000;
    coordinator.workers.last_planned_worker_slots = 6;

    let mut state = crate::server::state::ServerState {
        status: Default::default(),
        snapshot: None,
        afxdp: coordinator,
        state_writer: std::sync::Arc::new(crate::state_writer::StateWriter::new()),
    };

    // TICK 1 — the production path builds the floor.
    crate::server::helpers::status::refresh_status(&mut state);
    let floor = state
        .afxdp
        .cos
        .queue_vtime_floors
        .load()
        .get(&(80, 4))
        .cloned()
        .expect(
            "fixture: the exact-queue plan must produce a V_min floor. Without \
             one this cell measures nothing, and the assertion below would pass \
             on an empty map",
        );
    assert_eq!(
        floor.slots.len(),
        6,
        "fixture: six slots, so worker id 2 is indexable and the rebuild's \
         `slots.len() == num_workers` reuse filter holds across tick 2",
    );

    // Worker 2 commits a vtime and then panics; worker 3 survives and keeps
    // advancing. Worker 2's is the LOWER value, so it is the cross-worker V_min
    // worker 3 obeys — the exact value that freezes.
    floor.slots[2].publish(4_242);
    floor.slots[3].publish(9_000);
    assert_eq!(
        floor.participating_v_min_snapshot(3),
        (1, Some(4_242)),
        "fixture: worker 2's slot must be the frontier worker 3 obeys, or this \
         cell is not exercising the pin at all",
    );
    dead_atomics.dead.store(true, Ordering::Relaxed);

    // TICK 2 — the real 1 Hz status path.
    crate::server::helpers::status::refresh_status(&mut state);

    let after = state
        .afxdp
        .cos
        .queue_vtime_floors
        .load()
        .get(&(80, 4))
        .cloned()
        .expect("the floor must still exist after the second refresh");
    assert!(
        std::sync::Arc::ptr_eq(&floor, &after),
        "the rebuild must REUSE the same floor Arc (`slots.len() == num_workers`). \
         If it built a fresh one, every slot reads None for a reason that has \
         nothing to do with the sweep, and the verdict below would be vacuous",
    );
    assert_eq!(
        after.slots[2].read(),
        None,
        "a status refresh must vacate a dead worker's V_min slot — if this \
         passes only when retire_dead_worker_holders is called by hand, the \
         vacate is unwired and the frontier stays pinned (#9367)",
    );
    assert_eq!(
        after.slots[3].read(),
        Some(9_000),
        "the SURVIVING peer's slot must be untouched — a sweep that cleared \
         every slot would satisfy the assertion above while deleting the \
         cross-worker coordination entirely",
    );
    assert!(
        dead_atomics.holders_retired.load(Ordering::Relaxed),
        "the status path must latch the worker as retired",
    );
}

/// The sweep is ONE-SHOT, and the vacate must not resurrect a slot.
///
/// `holders_retired` is a CAS, so the second observation of `dead` skips the
/// whole body. This pins that the vacate rides that latch rather than running
/// on every 1 Hz tick — a per-tick walk of every floor would be a new cost on
/// the status path, and (worse) it would keep re-vacating a slot index that a
/// LATER generation could legitimately hand to a live worker.
#[test]
fn dead_worker_v_min_vacate_is_one_shot_9367() {
    use std::sync::atomic::Ordering;

    let mut coordinator = Coordinator::new();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let atomics = rec.handle.runtime_atomics.clone();
    coordinator.workers.register(1, rec, None);

    let floors = v_min_floor_map_9367(6);
    let floor = floors.get(&(7, 3u8)).expect("fixture floor").clone();
    coordinator.cos.queue_vtime_floors.store(Arc::new(floors));
    floor.slots[1].publish(77);
    atomics.dead.store(true, Ordering::Relaxed);

    coordinator.retire_dead_worker_holders();
    assert_eq!(floor.slots[1].read(), None, "first sweep vacates");

    // A later generation legitimately re-uses slot index 1 for a LIVE worker.
    // The second sweep must not touch it: the latch means the body never runs
    // again for this record.
    floor.slots[1].publish(555);
    coordinator.retire_dead_worker_holders();
    assert_eq!(
        floor.slots[1].read(),
        Some(555),
        "the one-shot `holders_retired` CAS must gate the V_min vacate too — a \
         sweep that re-ran every tick would keep clearing a slot index a later \
         generation handed to a live worker (#9367)",
    );
}

/// The vacate is gated on `dead`, NOT on the sweep's own predicate.
///
/// `retire_all_worker_holders` passes `|_| true`: it retires every registered
/// worker id, LIVE ones included, because the #7092 teardown reclaim has to
/// name them before `stop_and_clear` drops the records. At that moment those
/// workers are still RUNNING, so an ungated vacate would make the coordinator a
/// SECOND writer to a slot whose documented contract is single-writer — racing
/// a live `publish()` — and it would buy nothing, because the same teardown
/// discards `cos.queue_vtime_floors` outright a few statements later.
///
/// This is the cell the first draft of #9367 would have failed: the vacate call
/// sat unconditionally in the shared body, and the prose on it claimed the
/// single-writer contract held "because the sweep runs only for a dead worker",
/// which is true of `retire_dead_worker_holders` and false of its sibling.
#[test]
fn retire_all_worker_holders_does_not_vacate_a_live_workers_v_min_slot_9367() {
    let mut coordinator = Coordinator::new();
    let rec = WorkerRuntimeRecord::for_test(gre1881_fake_worker_handle());
    let atomics = rec.handle.runtime_atomics.clone();
    coordinator.workers.register(5, rec, None);

    let floors = v_min_floor_map_9367(6);
    let floor = floors.get(&(7, 3u8)).expect("fixture floor").clone();
    coordinator.cos.queue_vtime_floors.store(Arc::new(floors));
    floor.slots[5].publish(31_337);

    // The all-ids sweep DOES do its NAT work for this live worker — that is the
    // #7092 contract and this cell must not weaken it.
    coordinator.retire_all_worker_holders();
    assert!(
        atomics
            .holders_retired
            .load(std::sync::atomic::Ordering::Relaxed),
        "the all-ids sweep must still retire this worker's NAT holder bits — \
         this cell constrains the V_min vacate only",
    );
    assert_eq!(
        floor.slots[5].read(),
        Some(31_337),
        "a LIVE worker's V_min slot must survive the all-ids teardown sweep. \
         The worker is still running there (stop_and_clear has not been called), \
         so vacating makes the coordinator a second writer to a single-writer \
         slot, and the teardown discards the floors map moments later anyway \
         (#9367)",
    );
}

// ---------------------------------------------------------------------
// #9521: the steered-port decision made at spawn reaches the thread.
//
// Every earlier WG control-thread test in this file ends at `open_tun`,
// which fails without CAP_NET_ADMIN — so none of them could see what a
// spawned thread does with a packet. These register TUN stand-ins
// (wg_control::register_tun_standin_9521) and drive the whole path:
// snapshot -> forwarding state -> spawn decision -> thread -> TUN write.
// ---------------------------------------------------------------------

fn wg9521_snapshot(
    names: [&str; 2],
    ifindexes: [i32; 2],
    ports: [u16; 2],
    steered: u16,
    peer_pub_hex: &str,
) -> ConfigSnapshot {
    let mut snap = wg1866_snapshot(1, ifindexes[0], names[0], ports[0], WG1866_PRIVKEY_A);
    let second = wg1866_snapshot(2, ifindexes[1], names[1], ports[1], WG1866_PRIVKEY_B);
    snap.interfaces.extend(second.interfaces);
    snap.tunnel_endpoints.extend(second.tunnel_endpoints);
    for endpoint in &mut snap.tunnel_endpoints {
        // Responder-only (no endpoint): no bring-up handshake traffic to race
        // the records this test sends.
        endpoint.wg_peers = vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
            wg_peer_pubkey_hex: peer_pub_hex.to_string(),
            wg_allowed_ips: vec!["10.95.21.0/24".to_string(), "fd95:21::/64".to_string()],
            ..Default::default()
        }];
    }
    snap.wg_steered_listen_port = steered;
    snap
}

fn wg9521_decision(
    coordinator: &Coordinator,
    id: u16,
) -> Option<crate::afxdp::types::WgKernelTransport> {
    coordinator
        .wg_control_threads
        .get(&id)
        .map(|entry| entry.spawned_kernel_transport)
}

/// #9521 end to end. Two WireGuard endpoints on distinct listen ports; the
/// snapshot steers the first. A real authenticated transport record — IPv4 and
/// IPv6, both outer and inner — is sent to each endpoint's real control-thread
/// socket. The steered endpoint's thread must write the plaintext to its TUN
/// (positive control); the unsteered endpoint's thread must count the record as
/// an unsteered-port drop and write nothing.
#[test]
fn wg_unsteered_endpoint_refuses_kernel_transport_end_to_end_9521() {
    use crate::afxdp::coordinator::wg_control::{
        inner_v4_9521, inner_v6_9521, register_tun_standin_9521, tun_standin_recv_9521,
    };
    use crate::afxdp::types::WgKernelTransport;
    use std::sync::atomic::Ordering;

    let (peer_priv, peer_pub) = crate::afxdp::wg::tests::keypair();
    let peer_hex: String = peer_pub.iter().map(|b| format!("{b:02x}")).collect();
    // #9549: listen ports come from test_ports; the test only needs two distinct ports.
    let (steered_port, unsteered_port) = (crate::test_ports::reserve_ephemeral_udp_port(), crate::test_ports::reserve_ephemeral_udp_port());
    let snap = wg9521_snapshot(
        ["wgt9521s", "wgt9521u"],
        [4531, 4532],
        [steered_port, unsteered_port],
        steered_port,
        &peer_hex,
    );
    let steered_tun = register_tun_standin_9521("wgt9521s");
    let unsteered_tun = register_tun_standin_9521("wgt9521u");

    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap)
        .expect("refresh_runtime_snapshot must succeed");
    assert_eq!(wg9521_decision(&coordinator, 1), Some(WgKernelTransport::Deliver));
    assert_eq!(wg9521_decision(&coordinator, 2), Some(WgKernelTransport::DropUnsteered));

    let allowed: Vec<ipnet::IpNet> =
        vec!["10.95.21.0/24".parse().unwrap(), "fd95:21::/64".parse().unwrap()];
    for (id, port, tun, steered) in [
        (1u16, steered_port, &steered_tun, true),
        (2u16, unsteered_port, &unsteered_tun, false),
    ] {
        let engine = coordinator
            .forwarding
            .wg_engines
            .get(&id)
            .cloned()
            .expect("the snapshot built a WireGuard engine for this endpoint");
        let init = crate::afxdp::wg::tests::established_initiator_for(
            &engine,
            peer_priv,
            peer_pub,
            allowed.clone(),
        );
        let resp_pub = engine.local_public_key();
        for outer_v6 in [false, true] {
            let family = if outer_v6 { "IPv6" } else { "IPv4" };
            let inner = if outer_v6 { inner_v6_9521() } else { inner_v4_9521() };
            // Settle and drain, so a datagram from the previous family cannot be
            // read as this family's outcome.
            thread::sleep(Duration::from_millis(200));
            while tun_standin_recv_9521(tun).is_some() {}
            let drops_before = engine.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed);
            let dst: std::net::SocketAddr = if outer_v6 {
                format!("[::1]:{port}")
            } else {
                format!("127.0.0.1:{port}")
            }
            .parse()
            .unwrap();
            let sender =
                std::net::UdpSocket::bind(if outer_v6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let (mut delivered, mut dropped) = (None, false);
            // Resend until the thread (which binds asynchronously) accounts for one.
            while std::time::Instant::now() < deadline {
                let mut wire = vec![0u8; 2048];
                let enc = init.try_encap(&resp_pub, &inner, &mut wire).expect("initiator encap");
                let _ = sender.send_to(&wire[..enc.len], dst);
                thread::sleep(Duration::from_millis(40));
                if let Some(bytes) = tun_standin_recv_9521(tun) {
                    delivered = Some(bytes);
                    break;
                }
                if engine.counters().rx_unsteered_transport_drops.load(Ordering::Relaxed) > drops_before {
                    dropped = true;
                    break;
                }
            }
            if steered {
                assert_eq!(
                    delivered.as_deref(),
                    Some(&inner[..]),
                    "{family}: the steered endpoint's spawned thread must deliver kernel-path \
                     transport plaintext (positive control)"
                );
                assert!(!dropped, "{family}: the steered endpoint counted an unsteered drop");
            } else {
                assert!(
                    dropped,
                    "{family}: the unsteered endpoint never counted an unsteered-port drop — \
                     either the record never arrived or the thread spawned with the wrong decision"
                );
                thread::sleep(Duration::from_millis(100));
                assert!(
                    delivered.is_none() && tun_standin_recv_9521(tun).is_none(),
                    "{family}: the UNSTEERED endpoint's spawned thread wrote plaintext to its \
                     wgN TUN, where the kernel forwards it with no zone policy (#9521)"
                );
            }
        }
    }
    // The operator-visible surface. The status row built for each endpoint must
    // carry the drops its engine counted — the unsteered endpoint dropped at
    // least one record per family above, the steered endpoint none.
    thread::sleep(Duration::from_millis(300));
    let rows = coordinator.wg_tunnel_statuses();
    let row = |id: u16| {
        rows.iter()
            .find(|r| r.tunnel_endpoint_id as u64 == u64::from(id))
            .expect("a status row per WireGuard endpoint")
    };
    assert!(
        row(2).rx_unsteered_transport_drops >= 2,
        "the unsteered endpoint's status row reports {} unsteered-port drops; its engine \
         dropped at least one record per family, so the status mapping is not carrying \
         the counter to the operator",
        row(2).rx_unsteered_transport_drops
    );
    assert_eq!(row(1).rx_unsteered_transport_drops, 0, "the steered endpoint reports unsteered drops");
    coordinator.stop();
}

/// #9521: re-steering. Changing ONLY the steered port between two snapshots
/// must restart both threads with the flipped decision. The endpoints and their
/// engines are unchanged across the two snapshots, so no other stale reason can
/// restart them — this is the `kernel_transport_changed` prune arm or nothing.
#[test]
fn wg_resteering_restarts_control_threads_with_the_new_decision_9521() {
    use crate::afxdp::types::WgKernelTransport::{Deliver, DropUnsteered};
    let (_, peer_pub) = crate::afxdp::wg::tests::keypair();
    let peer_hex: String = peer_pub.iter().map(|b| format!("{b:02x}")).collect();
    // #9549: listen ports come from test_ports; the test only needs two distinct ports.
    let (names, ifindexes, ports) = (["wgt9521r1", "wgt9521r2"], [4541, 4542], [crate::test_ports::reserve_ephemeral_udp_port(), crate::test_ports::reserve_ephemeral_udp_port()]);

    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&wg9521_snapshot(names, ifindexes, ports, ports[0], &peer_hex))
        .expect("first refresh");
    assert_eq!(wg9521_decision(&coordinator, 1), Some(Deliver));
    assert_eq!(wg9521_decision(&coordinator, 2), Some(DropUnsteered));
    let engine_before = coordinator.forwarding.wg_engines.get(&1).map(|e| Arc::as_ptr(e) as usize);

    coordinator
        .refresh_runtime_snapshot(&wg9521_snapshot(names, ifindexes, ports, ports[1], &peer_hex))
        .expect("second refresh");
    assert_eq!(
        coordinator.forwarding.wg_engines.get(&1).map(|e| Arc::as_ptr(e) as usize),
        engine_before,
        "fixture premise: the engine must be REUSED, or engine_changed restarts the thread \
         and this cell cannot see the kernel_transport_changed arm"
    );
    assert_eq!(
        wg9521_decision(&coordinator, 1),
        Some(DropUnsteered),
        "the formerly steered endpoint kept delivering kernel-path plaintext after the \
         snapshot moved steering away from it"
    );
    assert_eq!(wg9521_decision(&coordinator, 2), Some(Deliver));
    coordinator.stop();
}

/// #9594 end to end, through the real spawn path: `spawn_one_wg_control_thread`
/// hands the thread the runtime view, `wg_control_loop` builds the PRODUCTION
/// posture view (`ShimMapsKernelPathView`), and that view — here reading the
/// per-tunnel map seam instead of bpffs — decides. The steered endpoint's ingress
/// (loopback) is placed in the shim's adjudicated set, so its record is a
/// degraded-window arrival: transit must be refused and counted, and the same
/// record addressed to the firewall must still be delivered.
///
/// This is the cell that dies if `wg_control_loop` ever runs the loop without the
/// shim-map view: every loop-level cell drives the loop directly with a fake.
#[test]
fn wg_steered_endpoint_refuses_degraded_transit_end_to_end_9594() {
    use crate::afxdp::coordinator::wg_control::kernel_path::{
        TEST_SHIM_MAPS_9594, TestShimMaps9594, inner_destination,
    };
    use crate::afxdp::coordinator::wg_control::{
        inner_v4_9521, register_tun_standin_9521, tun_standin_recv_9521,
    };
    use crate::afxdp::types::WgKernelTransport;
    use std::sync::atomic::Ordering;

    let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert!(lo > 0, "setup: the loopback interface has no ifindex");
    let (peer_priv, peer_pub) = crate::afxdp::wg::tests::keypair();
    let peer_hex: String = peer_pub.iter().map(|b| format!("{b:02x}")).collect();
    // #9549: listen ports come from test_ports, never fixed numbers. This cell first
    // bound 51971/51972 — the #9521 resteering cell's pair before #9606 moved it.
    let (steered_port, other_port) = (
        crate::test_ports::reserve_ephemeral_udp_port(),
        crate::test_ports::reserve_ephemeral_udp_port(),
    );
    let snap = wg9521_snapshot(
        ["wgt9594s", "wgt9594o"],
        [4541, 4542],
        [steered_port, other_port],
        steered_port,
        &peer_hex,
    );
    let tun = register_tun_standin_9521("wgt9594s");
    let _other_tun = register_tun_standin_9521("wgt9594o");
    let inner = inner_v4_9521();
    let inner_dst = inner_destination(&inner).expect("parseable inner");
    let set_maps = |local: bool| {
        let mut seam = TEST_SHIM_MAPS_9594.lock().unwrap_or_else(|e| e.into_inner());
        seam.retain(|(name, _)| name != "wgt9594s");
        let mut maps = TestShimMaps9594::default();
        maps.ingress.insert(lo);
        if local {
            maps.local.insert(inner_dst);
        }
        seam.push(("wgt9594s".to_string(), maps));
    };
    set_maps(false);

    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap)
        .expect("refresh_runtime_snapshot must succeed");
    assert_eq!(wg9521_decision(&coordinator, 1), Some(WgKernelTransport::Deliver));

    let allowed: Vec<ipnet::IpNet> =
        vec!["10.95.21.0/24".parse().unwrap(), "fd95:21::/64".parse().unwrap()];
    let engine = coordinator
        .forwarding
        .wg_engines
        .get(&1)
        .cloned()
        .expect("the snapshot built a WireGuard engine for the steered endpoint");
    let init =
        crate::afxdp::wg::tests::established_initiator_for(&engine, peer_priv, peer_pub, allowed);
    let resp_pub = engine.local_public_key();
    let dst: std::net::SocketAddr = format!("127.0.0.1:{steered_port}").parse().unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let send_until = |want_delivery: bool| -> (Option<Vec<u8>>, bool) {
        thread::sleep(Duration::from_millis(200));
        while tun_standin_recv_9521(&tun).is_some() {}
        let before = engine.counters().rx_degraded_transit_drops.load(Ordering::Relaxed);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let mut wire = vec![0u8; 2048];
            let enc = init.try_encap(&resp_pub, &inner, &mut wire).expect("initiator encap");
            let _ = sender.send_to(&wire[..enc.len], dst);
            thread::sleep(Duration::from_millis(40));
            if let Some(bytes) = tun_standin_recv_9521(&tun) {
                return (Some(bytes), false);
            }
            if !want_delivery
                && engine.counters().rx_degraded_transit_drops.load(Ordering::Relaxed) > before
            {
                thread::sleep(Duration::from_millis(100));
                return (tun_standin_recv_9521(&tun), true);
            }
        }
        (None, false)
    };

    let (delivered, dropped) = send_until(false);
    assert!(
        dropped,
        "the steered endpoint's spawned thread never counted a degraded-transit drop for a record \
         on an adjudicated ingress — either the record never arrived, or the thread is running \
         without the shim-map posture view"
    );
    assert!(
        delivered.is_none(),
        "the steered endpoint's spawned thread wrote degraded-window TRANSIT plaintext to its \
         wgN TUN (#9594)"
    );

    set_maps(true);
    let (delivered, _) = send_until(true);
    assert_eq!(
        delivered.as_deref(),
        Some(&inner[..]),
        "positive control through the same spawned thread: a record addressed to the firewall \
         must still be delivered on an adjudicated ingress"
    );

    TEST_SHIM_MAPS_9594
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(name, _)| name != "wgt9594s");
    drop(coordinator);
}

/// #9594: the PRODUCTION posture view places an ingress the way the fix depends
/// on — in the shim's ingress set is covered (degraded arrival); a CONFIGURED
/// interface outside it is uncovered, #8274's residual, and must stay delivered;
/// an ifindex that is neither cannot be placed. The middle case is the one a
/// regression would hide in: if the view stopped consulting the runtime
/// forwarding state, every uncovered ingress would read as unplaceable and its
/// transit would be silently dropped — no loop cell sees that, because they all
/// drive the loop with a fixed view.
#[test]
fn shim_maps_view_places_configured_uncovered_ingress_9594() {
    use crate::afxdp::coordinator::wg_control::kernel_path::{
        ShimMapsKernelPathView, TEST_SHIM_MAPS_9594, TestShimMaps9594, WgKernelPathIngress,
        WgKernelPathView,
    };
    let (_peer_priv, peer_pub) = crate::afxdp::wg::tests::keypair();
    let peer_hex: String = peer_pub.iter().map(|b| format!("{b:02x}")).collect();
    // #9549: the snapshot spawns real control threads that bind these ports.
    let (port_k, port_l) = (
        crate::test_ports::reserve_ephemeral_udp_port(),
        crate::test_ports::reserve_ephemeral_udp_port(),
    );
    let snap = wg9521_snapshot(
        ["wgt9594k", "wgt9594l"],
        [4551, 4552],
        [port_k, port_l],
        port_k,
        &peer_hex,
    );
    let mut coordinator = Coordinator::new();
    coordinator
        .refresh_runtime_snapshot(&snap)
        .expect("refresh_runtime_snapshot must succeed");
    assert!(
        coordinator.forwarding.ifindex_to_name.contains_key(&4551),
        "setup: ifindex 4551 must be a configured interface in the runtime forwarding state"
    );
    {
        let mut seam = TEST_SHIM_MAPS_9594.lock().unwrap_or_else(|e| e.into_inner());
        seam.retain(|(name, _)| name != "wgt9594-view");
        let mut maps = TestShimMaps9594::default();
        maps.ingress.insert(4552);
        seam.push(("wgt9594-view".to_string(), maps));
    }
    let view = ShimMapsKernelPathView::new("wgt9594-view".to_string(), coordinator.ha.runtime_reader());
    assert_eq!(view.ingress(Some(4552)), WgKernelPathIngress::Covered, "in the shim's ingress set");
    assert_eq!(
        view.ingress(Some(4551)),
        WgKernelPathIngress::Uncovered,
        "a configured interface the shim does not adjudicate is #8274's residual and must be \
         delivered — reading it as unplaceable would drop its transit silently"
    );
    assert_eq!(
        view.ingress(Some(999_999)),
        WgKernelPathIngress::Unknown,
        "an ifindex neither adjudicated nor configured cannot be placed"
    );
    assert_eq!(view.ingress(None), WgKernelPathIngress::Unknown, "no pktinfo cmsg");
    TEST_SHIM_MAPS_9594
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|(name, _)| name != "wgt9594-view");
}
