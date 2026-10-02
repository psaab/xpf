use super::*;

const LOOPBACK_IFINDEX_11437: i32 = 25;
const NON_LOOPBACK_IFINDEX_11437: i32 = 26;
const FOREIGN_IFINDEX_11437: i32 = 27;

fn connected_v4_11437(ifindex: i32, table: &str, host: Ipv4Addr) -> ConnectedRouteV4 {
    ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net(
            ipnet::Ipv4Net::new(host, 32).expect("connected /32"),
        ),
        host,
        ifindex,
        tunnel_endpoint_id: 0,
        table: table.to_string(),
    }
}

fn connected_v6_11437(ifindex: i32, table: &str, host: Ipv6Addr) -> ConnectedRouteV6 {
    ConnectedRouteV6 {
        prefix: crate::prefix::PrefixV6::from_net(
            ipnet::Ipv6Net::new(host, 128).expect("connected /128"),
        ),
        host,
        ifindex,
        tunnel_endpoint_id: 0,
        table: table.to_string(),
    }
}

#[test]
fn frag_needed_uses_loopback_primary_in_same_routing_instance_11437() {
    let (frame, meta) = inbound_v4_udp(1500, true);
    let mut forwarding = forwarding_with_egress(1400);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v4 = None;
    forwarding
        .ifindex_to_routing_instance
        .insert(PTB_IFINDEX, "blue".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(FOREIGN_IFINDEX_11437, "red".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(NON_LOOPBACK_IFINDEX_11437, "blue".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(LOOPBACK_IFINDEX_11437, "blue".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(NON_LOOPBACK_IFINDEX_11437, "reth0.0".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(LOOPBACK_IFINDEX_11437, "lo0.0".to_string());
    // A foreign-RI address is first, followed by a same-RI any-interface
    // primary. Loopback must win over both without crossing routing instances.
    forwarding.connected_v4.push(connected_v4_11437(
        FOREIGN_IFINDEX_11437,
        "red.inet.0",
        Ipv4Addr::new(198, 51, 100, 7),
    ));
    forwarding.connected_v4.push(connected_v4_11437(
        NON_LOOPBACK_IFINDEX_11437,
        "blue.inet.0",
        Ipv4Addr::new(192, 0, 2, 7),
    ));
    forwarding.connected_v4.push(connected_v4_11437(
        LOOPBACK_IFINDEX_11437,
        "blue.inet.0",
        Ipv4Addr::new(192, 0, 2, 8),
    ));

    let out = build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &forwarding, 1400)
        .expect("same-RI loopback primary should make Frag-Needed buildable");
    assert_eq!(
        &out[6..12],
        &EGRESS_SRC_MAC,
        "L2 remains the ingress egress"
    );
    assert_eq!(
        &out[26..30],
        &Ipv4Addr::new(192, 0, 2, 8).octets(),
        "outer source must use the same-RI loopback primary"
    );
}

#[test]
fn packet_too_big_uses_any_interface_primary_in_same_routing_instance_11437() {
    let (frame, meta) = inbound_v6_udp(1300);
    let mut forwarding = forwarding_with_egress(1280);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v6 = None;
    forwarding
        .ifindex_to_routing_instance
        .insert(PTB_IFINDEX, "blue".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(NON_LOOPBACK_IFINDEX_11437, "blue".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(NON_LOOPBACK_IFINDEX_11437, "reth0.0".to_string());
    let source: Ipv6Addr = "2001:db8:42::8".parse().expect("v6 source");
    forwarding.connected_v6.push(connected_v6_11437(
        NON_LOOPBACK_IFINDEX_11437,
        "blue.inet6.0",
        source,
    ));

    let out = build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &forwarding, 1280)
        .expect("same-RI interface primary should make Packet-Too-Big buildable");
    assert_eq!(
        &out[22..38],
        &source.octets(),
        "outer source must use a same-RI IPv6 primary"
    );
}

#[test]
fn frag_needed_does_not_fall_back_to_another_routing_instance_11437() {
    let (frame, meta) = inbound_v4_udp(1500, true);
    let mut forwarding = forwarding_with_egress(1400);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v4 = None;
    forwarding
        .ifindex_to_routing_instance
        .insert(PTB_IFINDEX, "blue".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(FOREIGN_IFINDEX_11437, "red".to_string());
    forwarding.connected_v4.push(connected_v4_11437(
        FOREIGN_IFINDEX_11437,
        "red.inet.0",
        Ipv4Addr::new(198, 51, 100, 7),
    ));

    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &forwarding, 1400).is_none(),
        "a foreign-RI address must not become the PTB source"
    );
}

#[test]
fn packet_too_big_does_not_fall_back_to_another_routing_instance_11437() {
    let (frame, meta) = inbound_v6_udp(1300);
    let mut forwarding = forwarding_with_egress(1280);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v6 = None;
    forwarding
        .ifindex_to_routing_instance
        .insert(PTB_IFINDEX, "blue".to_string());
    forwarding
        .ifindex_to_routing_instance
        .insert(FOREIGN_IFINDEX_11437, "red".to_string());
    forwarding.connected_v6.push(connected_v6_11437(
        FOREIGN_IFINDEX_11437,
        "red.inet6.0",
        "2001:db8:99::8".parse().expect("foreign v6 source"),
    ));

    assert!(
        build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &forwarding, 1280).is_none(),
        "a foreign-RI IPv6 address must not become the PTB source"
    );
}

#[test]
fn frag_needed_rejects_cross_interface_link_local_fallback_11437() {
    let (frame, meta) = inbound_v4_udp(1500, true);
    let mut forwarding = forwarding_with_egress(1400);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v4 = None;
    for ifindex in [
        PTB_IFINDEX,
        LOOPBACK_IFINDEX_11437,
        NON_LOOPBACK_IFINDEX_11437,
    ] {
        forwarding
            .ifindex_to_routing_instance
            .insert(ifindex, "blue".to_string());
    }
    forwarding
        .ifindex_to_config_name
        .insert(LOOPBACK_IFINDEX_11437, "lo0.0".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(NON_LOOPBACK_IFINDEX_11437, "reth0.0".to_string());
    forwarding.connected_v4.extend([
        connected_v4_11437(
            LOOPBACK_IFINDEX_11437,
            "blue.inet.0",
            Ipv4Addr::new(169, 254, 1, 1),
        ),
        connected_v4_11437(
            NON_LOOPBACK_IFINDEX_11437,
            "blue.inet.0",
            Ipv4Addr::new(169, 254, 1, 2),
        ),
    ]);

    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &forwarding, 1400).is_none(),
        "link-local IPv4 primaries on other interfaces cannot source this PTB"
    );
}

#[test]
fn packet_too_big_rejects_cross_interface_link_local_fallback_11437() {
    let (frame, meta) = inbound_v6_udp(1300);
    let mut forwarding = forwarding_with_egress(1280);
    forwarding.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v6 = None;
    for ifindex in [
        PTB_IFINDEX,
        LOOPBACK_IFINDEX_11437,
        NON_LOOPBACK_IFINDEX_11437,
    ] {
        forwarding
            .ifindex_to_routing_instance
            .insert(ifindex, "blue".to_string());
    }
    forwarding
        .ifindex_to_config_name
        .insert(LOOPBACK_IFINDEX_11437, "lo0.0".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(NON_LOOPBACK_IFINDEX_11437, "reth0.0".to_string());
    forwarding.connected_v6.extend([
        connected_v6_11437(
            LOOPBACK_IFINDEX_11437,
            "blue.inet6.0",
            "fe80::1".parse().expect("loopback link-local"),
        ),
        connected_v6_11437(
            NON_LOOPBACK_IFINDEX_11437,
            "blue.inet6.0",
            "fe80::2".parse().expect("interface link-local"),
        ),
    ]);

    assert!(
        build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &forwarding, 1280).is_none(),
        "link-local IPv6 primaries on other interfaces cannot source this PTB"
    );
}
