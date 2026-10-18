//! #14654: transit directed broadcasts + ICMP directed-broadcast scope.
//!
//! Leg 1: a transit packet to a connected subnet-directed broadcast must be
//! dropped as martian (domain-scoped), not proceed to policy/session/NAT.
//! Leg 2: ICMP-error suppression for a directed broadcast must be scoped to
//! the trigger's routing table — a `.255` host in a /23 in one VRF must not
//! be suppressed merely because another VRF owns the /24 broadcast.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use std::net::{IpAddr, Ipv4Addr};

const RED_BCAST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 255);
const BLUE_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 255); // same addr, host in blue /16

fn add_vrf_interfaces(snapshot: &mut ConfigSnapshot) -> (u32, u32) {
    let (red_domain, _) = crate::session::install_table_identity("red");
    let (blue_domain, _) = crate::session::install_table_identity("blue");
    snapshot.interfaces.extend([
        crate::InterfaceSnapshot {
            name: "red-in".to_string(),
            zone: "lan".to_string(),
            routing_instance: "red".to_string(),
            routing_domain: red_domain,
            linux_name: "red-in".to_string(),
            ifindex: 127,
            hardware_addr: "02:bf:72:01:00:02".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.0.0.1/24".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "red-out".to_string(),
            zone: "wan".to_string(),
            routing_instance: "red".to_string(),
            routing_domain: red_domain,
            linux_name: "red-out".to_string(),
            ifindex: 128,
            hardware_addr: "02:bf:72:00:81:09".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.82.2/24".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "blue-in".to_string(),
            zone: "lan".to_string(),
            routing_instance: "blue".to_string(),
            routing_domain: blue_domain,
            linux_name: "blue-in".to_string(),
            ifindex: 125,
            hardware_addr: "02:bf:72:01:00:01".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.0.0.2/16".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        crate::InterfaceSnapshot {
            name: "blue-out".to_string(),
            zone: "wan".to_string(),
            routing_instance: "blue".to_string(),
            routing_domain: blue_domain,
            linux_name: "blue-out".to_string(),
            ifindex: 126,
            hardware_addr: "02:bf:72:00:81:08".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.81.2/24".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
    ]);
    snapshot.routes.push(crate::RouteSnapshot {
        reject: false,
        table: "blue.inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.81.1@blue-out".to_string()],
        ..Default::default()
    });
    snapshot.routes.push(crate::RouteSnapshot {
        reject: false,
        table: "red.inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.82.1@red-out".to_string()],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "blue-out".to_string(),
        ifindex: 126,
        family: "inet".to_string(),
        ip: "172.16.81.1".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: true,
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "red-out".to_string(),
        ifindex: 128,
        family: "inet".to_string(),
        ip: "172.16.82.1".to_string(),
        mac: "00:aa:bb:cc:dd:ef".to_string(),
        state: "reachable".to_string(),
        router: true,
        ..Default::default()
    });
    (red_domain, blue_domain)
}

#[test]
fn directed_broadcast_transit_predicate_is_domain_scoped_14654() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules.clear();
    let (red_domain, blue_domain) = add_vrf_interfaces(&mut snapshot);
    let forwarding = build_forwarding_state(&v5(snapshot));

    // Index sanity: 10.0.0.255 is red's /24 broadcast, a host in blue's /16.
    assert!(
        forwarding
            .connected_v4_directed_broadcasts
            .contains(&(red_domain, RED_BCAST))
    );
    assert!(
        !forwarding
            .connected_v4_directed_broadcasts
            .contains(&(blue_domain, BLUE_HOST))
    );

    // RED on master: transit_dst_is_martian has no domain arg and returns
    // false for 10.0.0.255 in every domain.
    assert!(
        crate::afxdp::frame::transit_dst_is_martian(&forwarding, IpAddr::V4(RED_BCAST), red_domain),
        "red-domain transit to its connected directed broadcast must be martian"
    );
    assert!(
        !crate::afxdp::frame::transit_dst_is_martian(
            &forwarding,
            IpAddr::V4(BLUE_HOST),
            blue_domain
        ),
        "blue-domain transit to a /16 host whose address equals red's broadcast must not be martian"
    );
    // Existing classes still fire regardless of domain.
    assert!(crate::afxdp::frame::transit_dst_is_martian(
        &forwarding,
        IpAddr::V4(Ipv4Addr::BROADCAST),
        blue_domain
    ));
    assert!(!crate::afxdp::frame::transit_dst_is_martian(
        &forwarding,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
        red_domain
    ));

    // Wrapper: disposition + domain plumbing.
    let meta = crate::afxdp::types::ForwardPacketMeta::from(txn_meta_v4(125, TCP_FLAG_SYN, 64));
    assert!(
        !crate::afxdp::poll_descriptor::transit_destination_class_drop(
            &forwarding,
            ForwardingDisposition::ForwardCandidate,
            IpAddr::V4(BLUE_HOST),
            None,
            0,
            meta,
            None,
        ),
        "blue ingress (domain resolved from ifindex 125) must not drop the /16 host"
    );
    assert!(
        crate::afxdp::poll_descriptor::transit_destination_class_drop(
            &forwarding,
            ForwardingDisposition::ForwardCandidate,
            IpAddr::V4(RED_BCAST),
            None,
            red_domain,
            meta,
            None,
        ),
        "red-domain flow to red's directed broadcast must drop"
    );
    // LocalDelivery exempt.
    assert!(
        !crate::afxdp::poll_descriptor::transit_destination_class_drop(
            &forwarding,
            ForwardingDisposition::LocalDelivery,
            IpAddr::V4(RED_BCAST),
            None,
            red_domain,
            meta,
            None,
        ),
        "LocalDelivery must remain exempt"
    );
    // Translated destination also checked in the caller's domain.
    assert!(
        crate::afxdp::poll_descriptor::transit_destination_class_drop(
            &forwarding,
            ForwardingDisposition::ForwardCandidate,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            Some(IpAddr::V4(RED_BCAST)),
            red_domain,
            meta,
            None,
        ),
        "DNAT to red's directed broadcast must drop in red domain"
    );
    assert!(
        !crate::afxdp::poll_descriptor::transit_destination_class_drop(
            &forwarding,
            ForwardingDisposition::ForwardCandidate,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            Some(IpAddr::V4(BLUE_HOST)),
            blue_domain,
            meta,
            None,
        ),
        "DNAT to blue /16 host must not drop in blue domain"
    );
}

#[test]
fn directed_broadcast_destination_drops_in_descriptor_path_14654() {
    // End-to-end: LAN ingress (reth1.0, 10.0.61.1/24) to its own directed
    // broadcast 10.0.61.255 must be martian-dropped with no session/TX.
    // RED on master: packet proceeds (TX / session / neighbor pending).
    let forwarding = {
        let mut snapshot = nat_snapshot();
        snapshot.source_nat_rules.clear();
        build_forwarding_state(&snapshot)
    };
    let destination = Ipv4Addr::new(10, 0, 61, 255);
    let source = Ipv4Addr::new(10, 0, 61, 100);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame =
        build_txn_tcp_syn_frame_v4(source, destination, 54321, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    meta.flow_src_port = 54321;
    meta.flow_dst_port = 443;
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        &frame,
        meta,
        true,
    );
    assert_eq!(debug.rx, 1);
    assert_eq!(
        batch.martian_dropped, 1,
        "connected directed broadcast transit must be martian-dropped"
    );
    assert_eq!(debug.tx, 0, "directed broadcast must not be transmitted");
    assert_eq!(
        batch.session_creates, 0,
        "no session may be created for a directed broadcast"
    );
    assert_eq!(sessions.len(), 0);
    assert_eq!(
        binding.pending_neigh.len(),
        0,
        "must not enter neighbor retry"
    );
}

#[test]
fn icmp_directed_broadcast_suppression_is_table_scoped_14654() {
    // Leg 2: 10.0.0.255 is red's 10.0.0.0/24 broadcast but a host in blue's
    // 10.0.0.0/16 (broadcast 10.0.255.255). Table-scoped checks must differ.
    let mut state = ForwardingState::default();
    for (cidr, table) in [
        ("10.0.0.0/24", "red.inet.0"),
        ("10.0.0.0/16", "blue.inet.0"),
    ] {
        let net: ipnet::Ipv4Net = cidr.parse().expect("cidr");
        state.connected_v4.push(ConnectedRouteV4 {
            prefix: crate::prefix::PrefixV4::from_net(net),
            host: net.addr(),
            ifindex: 24,
            tunnel_endpoint_id: 0,
            table: table.to_string(),
        });
    }
    let addr = Ipv4Addr::new(10, 0, 0, 255);
    assert!(
        crate::afxdp::frame::v4_addr_is_directed_broadcast_in_table(
            &state,
            addr,
            Some("red.inet.0")
        ),
        "10.0.0.255 is red's /24 directed broadcast"
    );
    assert!(
        !crate::afxdp::frame::v4_addr_is_directed_broadcast_in_table(
            &state,
            addr,
            Some("blue.inet.0")
        ),
        "10.0.0.255 is a host in blue's /16, not its broadcast"
    );
    assert!(
        crate::afxdp::frame::v4_addr_is_directed_broadcast_in_table(
            &state,
            Ipv4Addr::new(10, 0, 255, 255),
            Some("blue.inet.0")
        ),
        "10.0.255.255 is blue's /16 directed broadcast"
    );
    let mut packet = vec![0u8; 20];
    packet[16..20].copy_from_slice(&addr.octets());
    assert!(crate::afxdp::frame::dest_is_directed_broadcast_in_table(
        &state,
        &packet,
        Some("red.inet.0")
    ));
    assert!(!crate::afxdp::frame::dest_is_directed_broadcast_in_table(
        &state,
        &packet,
        Some("blue.inet.0")
    ));
    let mut spacket = vec![0u8; 20];
    spacket[12..16].copy_from_slice(&addr.octets());
    assert!(crate::afxdp::frame::src_is_directed_broadcast_in_table(
        &state,
        &spacket,
        Some("red.inet.0")
    ));
    assert!(!crate::afxdp::frame::src_is_directed_broadcast_in_table(
        &state,
        &spacket,
        Some("blue.inet.0")
    ));
    // End-to-end: ingress ifindex 24 mapped to blue vs red domain.
    for (domain_name, expect_allowed) in [("blue", true), ("red", false)] {
        let mut fwd = ForwardingState::default();
        fwd.egress.insert(
            24,
            EgressInterface {
                bind_ifindex: 0,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: Some("2001:559:8585:80::8".parse().expect("v6")),
            },
        );
        for (cidr, table) in [
            ("10.0.0.0/24", "red.inet.0"),
            ("10.0.0.0/16", "blue.inet.0"),
        ] {
            let net: ipnet::Ipv4Net = cidr.parse().expect("cidr");
            fwd.connected_v4.push(ConnectedRouteV4 {
                prefix: crate::prefix::PrefixV4::from_net(net),
                host: net.addr(),
                ifindex: 24,
                tunnel_endpoint_id: 0,
                table: table.to_string(),
            });
        }
        let (domain, check) = crate::session::install_table_identity(domain_name);
        fwd.has_routing_domains = true;
        fwd.ifindex_to_routing_domain.insert(24, domain);
        fwd.install_tables.insert(
            domain,
            crate::afxdp::types::InstallTables {
                v4: Some(format!("{domain_name}.inet.0")),
                v6: None,
                h2: check,
            },
        );
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let l3 = frame.len();
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&28u16.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 1, 17, 0x00, 0x00]);
        frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        frame.extend_from_slice(&addr.octets());
        let csum = checksum16(&frame[l3..l3 + 20]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        let meta = UserspaceDpMeta {
            ingress_ifindex: 24,
            l3_offset: l3 as u16,
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            can_generate_icmp_error_reply(&frame, meta, &fwd),
            expect_allowed,
            "{domain_name}-ingress trigger to 10.0.0.255 allowed={expect_allowed}"
        );
        assert_eq!(
            ptb_reply_suppressed(&frame, meta, l3, &fwd),
            !expect_allowed,
            "{domain_name}-ingress PTB suppression must mirror reject gate"
        );
    }
}
