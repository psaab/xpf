use super::*;
use crate::protocol::snapshot::InterfaceAddressSnapshot;
use crate::{ConfigSnapshot, RouteSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn iface_11650(
    name: &str,
    linux_name: &str,
    ifindex: i32,
    routing_instance: &str,
    addresses: &[(&str, i32)],
) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.into(),
        linux_name: linux_name.into(),
        ifindex,
        routing_instance: routing_instance.into(),
        hardware_addr: format!("02:00:00:00:11:{:02x}", ifindex & 0xff),
        addresses: addresses
            .iter()
            .map(|(address, scope)| InterfaceAddressSnapshot {
                family: if address.contains(':') { "inet6" } else { "inet" }.into(),
                address: (*address).into(),
                scope: *scope,
            })
            .collect(),
        ..Default::default()
    }
}

fn route_v6_11650(table: &str, destination: &str, next_hops: &[&str]) -> RouteSnapshot {
    RouteSnapshot {
        table: table.into(),
        family: "inet6".into(),
        destination: destination.into(),
        next_hops: next_hops.iter().map(|next_hop| (*next_hop).into()).collect(),
        ..Default::default()
    }
}

#[test]
fn daemon_unique_bare_link_local_ignores_kernel_link_scope_11650() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("2001:db8:1::1/64", 0)],
            ),
            // A managed IPv4-only/mgmt link can still carry the kernel's
            // autoconf fe80 row; it is not a configured IPv6 egress candidate.
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[("fe80::2/64", 253)],
            ),
        ],
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0-0-1".into(),
            ifindex: 101,
            family: "inet6".into(),
            ip: "fe80::254".into(),
            mac: "02:00:00:00:11:fe".into(),
            state: "reachable".into(),
            ..Default::default()
        }],
        routes: vec![route_v6_11650(
            "inet6.0",
            "2001:db8:beef::/48",
            &["fe80::254"],
        )],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("inet6.0 table")
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("bare link-local route");
    assert_eq!(
        route.next_hops[0].ifindex, 101,
        "one Universe candidate plus a kernel LINK row must resolve to the configured egress"
    );
    let resolution = lookup_forwarding_resolution_v6(&state,
    None,
    "2001:db8:beef::5".parse().unwrap(),
    "inet6.0",
    0,
    true,
    None,).resolution;
    assert_eq!(resolution.disposition, ForwardingDisposition::ForwardCandidate);
    assert_eq!(resolution.egress_ifindex, 101);
}

#[test]
fn configured_link_local_universe_scope_remains_a_candidate_11650() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("fe80::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[("fe80::2/64", 253)],
            ),
        ],
        routes: vec![route_v6_11650(
            "inet6.0",
            "2001:db8:beef::/48",
            &["fe80::254"],
        )],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("inet6.0 table")
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("bare link-local route");
    assert_eq!(
        route.next_hops[0].ifindex, 101,
        "an explicitly configured fe80 address (Universe scope) remains eligible"
    );
}

// A scope-only filter keeps every UNIVERSE row eligible; the snapshot does not
// encode whether a global address came from configuration, DHCP, RA, or PD.
// Thus an extra kernel-learned GUA remains a candidate and genuine ambiguity
// stays fail-closed until that source capability is modeled explicitly.

#[test]
fn genuinely_ambiguous_universe_link_local_stays_no_route_11650() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("2001:db8:1::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[("2001:db8:2::1/64", 0), ("fe80::2/64", 253)],
            ),
            iface_11650(
                "ge-0/0/3.0",
                "ge-0-0-3",
                103,
                "",
                &[("fe80::3/64", 253)],
            ),
        ],
        routes: vec![
            route_v6_11650("inet6.0", "2001:db8:beef::/48", &["fe80::254"]),
            route_v6_11650(
                "inet6.0",
                "2001:db8:cafe::/48",
                &["fe80::254@ge-0-0-2"],
            ),
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let table = state.routes_v6.get("inet6.0").expect("inet6.0 table");
    let ambiguous = table
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("ambiguous route");
    assert_eq!(ambiguous.next_hops[0].ifindex, 0);
    let unresolved = lookup_forwarding_resolution_v6(&state,
    None,
    "2001:db8:beef::5".parse().unwrap(),
    "inet6.0",
    0,
    true,
    None,).resolution;
    assert_eq!(unresolved.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(unresolved.egress_ifindex, 0);

    // An explicit interface remains authoritative even when bare inference is
    // ambiguous; the scope filter applies only to candidate discovery.
    let explicit = table
        .iter()
        .find(|route| route.prefix.contains("2001:db8:cafe::5".parse().unwrap()))
        .expect("explicit route");
    assert_eq!(explicit.next_hops[0].ifindex, 102);
}

#[test]
fn ip_monitoring_overlay_bare_link_local_uses_scope_candidates_11650() {
    // Matches the RouteSnapshot emitted from an ip-monitoring overlay: unlike
    // config statics, the overlay is applied after the #11317 recursive-static
    // gate (pinned in pkg/dataplane/userspace/fbf_snapshot_test.go).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("2001:db8:1::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[("fe80::2/64", 253)],
            ),
            iface_11650(
                "ge-0/0/3.0",
                "ge-0-0-3",
                103,
                "",
                &[("fe80::3/64", 253)],
            ),
        ],
        routes: vec![route_v6_11650(
            "inet6.0",
            "2001:db8:beef::/48",
            &["fe80::254"],
        )],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("inet6.0 table")
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("overlay route");
    assert_eq!(route.next_hops[0].ifindex, 101);
}

#[test]
fn mixed_link_local_ecmp_keeps_resolvable_member_11650() {
    let direct_gateway: Ipv6Addr = "2001:db8:1::254".parse().unwrap();
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("2001:db8:1::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[("2001:db8:2::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/3.0",
                "ge-0-0-3",
                103,
                "",
                &[("fe80::3/64", 253)],
            ),
        ],
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0-0-1".into(),
            ifindex: 101,
            family: "inet6".into(),
            ip: direct_gateway.to_string(),
            mac: "02:00:00:00:11:fe".into(),
            state: "reachable".into(),
            ..Default::default()
        }],
        routes: vec![route_v6_11650(
            "inet6.0",
            "2001:db8:beef::/48",
            &["2001:db8:1::254", "fe80::254"],
        )],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let route = state
        .routes_v6
        .get("inet6.0")
        .expect("inet6.0 table")
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("mixed ECMP route");
    assert_eq!(route.next_hops.len(), 2);
    let direct = route
        .next_hops
        .iter()
        .find(|next_hop| next_hop.next_hop == Some(direct_gateway))
        .expect("direct member");
    assert_eq!(direct.ifindex, 101);
    let recursive = route
        .next_hops
        .iter()
        .find(|next_hop| next_hop.next_hop == Some("fe80::254".parse().unwrap()))
        .expect("bare link-local member");
    assert_eq!(recursive.ifindex, 0, "genuinely ambiguous member remains unresolved");

    let resolution = lookup_forwarding_resolution_v6(&state,
    None,
    "2001:db8:beef::5".parse().unwrap(),
    "inet6.0",
    0,
    true,
    None,).resolution;
    assert_eq!(resolution.disposition, ForwardingDisposition::ForwardCandidate);
    assert_eq!(resolution.egress_ifindex, 101);
    assert_eq!(resolution.next_hop, Some(IpAddr::V6(direct_gateway)));
}

#[test]
fn bare_link_local_inference_is_table_scoped_in_vrfs_11650() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "blue",
                &[("2001:db8:1::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "blue",
                &[("fe80::2/64", 253)],
            ),
            iface_11650(
                "ge-0/0/3.0",
                "ge-0-0-3",
                201,
                "red",
                &[("2001:db8:2::1/64", 0)],
            ),
            iface_11650(
                "ge-0/0/4.0",
                "ge-0-0-4",
                202,
                "red",
                &[("fe80::4/64", 253)],
            ),
        ],
        routes: vec![
            route_v6_11650("blue.inet6.0", "2001:db8:beef::/48", &["fe80::254"]),
            route_v6_11650("red.inet6.0", "2001:db8:beef::/48", &["fe80::254"]),
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    for (table, want_ifindex) in [("blue.inet6.0", 101), ("red.inet6.0", 201)] {
        let route = state
            .routes_v6
            .get(table)
            .expect("VRF route table")
            .iter()
            .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
            .expect("bare link-local route");
        assert_eq!(
            route.next_hops[0].ifindex, want_ifindex,
            "link-local inference must stay within {table}"
        );
    }
}

#[test]
fn global_lpm_and_ipv4_inference_unchanged_by_v6_scope_11650() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            iface_11650(
                "ge-0/0/1.0",
                "ge-0-0-1",
                101,
                "",
                &[("192.0.2.1/24", 0), ("2001:db8::1/32", 0)],
            ),
            iface_11650(
                "ge-0/0/2.0",
                "ge-0-0-2",
                102,
                "",
                &[
                    ("192.0.3.1/24", 0),
                    ("2001:db8:2::1/64", 0),
                    ("fe80::2/64", 253),
                ],
            ),
        ],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "198.51.100.0/24".into(),
                next_hops: vec!["192.0.3.254".into()],
                ..Default::default()
            },
            route_v6_11650(
                "inet6.0",
                "2001:db8:beef::/48",
                &["2001:db8:2::254"],
            ),
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let v4 = state.routes_v4.get("inet.0").expect("inet.0 table");
    let v4_route = v4
        .iter()
        .find(|route| route.prefix.contains(Ipv4Addr::new(198, 51, 100, 5)))
        .expect("IPv4 route");
    assert_eq!(v4_route.next_hops[0].ifindex, 102);

    let v6 = state.routes_v6.get("inet6.0").expect("inet6.0 table");
    let v6_route = v6
        .iter()
        .find(|route| route.prefix.contains("2001:db8:beef::5".parse().unwrap()))
        .expect("global IPv6 route");
    assert_eq!(v6_route.next_hops[0].ifindex, 102);
}
