use super::*;
use std::net::Ipv4Addr;

#[test]
fn ordinary_route_without_next_hops_or_connected_interface_fails_closed_12063() {
    for (table, family, destination) in [
        ("inet.0", "inet", "10.77.0.0/24"),
        ("inet6.0", "inet6", "2001:db8:77::/64"),
    ] {
        let snapshot = ConfigSnapshot {
            routes: vec![crate::RouteSnapshot {
                table: table.into(),
                family: family.into(),
                destination: destination.into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = try_build_forwarding_state_with_policy_counters(
            &snapshot,
            &crate::policy::PolicyCounterStore::default(),
        );
        match result {
            Err(crate::policy::SnapshotIntegrityError::RouteEmptyNextHops {
                table: got_table,
                destination: got_destination,
            }) => {
                assert_eq!(got_table, table);
                assert_eq!(got_destination, destination);
            }
            other => panic!(
                "ordinary route {destination} without next-hops or a connected interface must fail closed, got {other:?}"
            ),
        }
    }
}

#[test]
fn connected_marker_with_live_interface_remains_usable_12063() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "ge-0/0/77".into(),
            linux_name: "ge-0-0-77".into(),
            ifindex: 77,
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.77.0.1/24".into(),
                scope: 0,
            }],
            ..Default::default()
        }],
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "10.77.0.0/24".into(),
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "0.0.0.0/0".into(),
                next_hops: vec!["10.77.0.2".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    let resolution = crate::afxdp::forwarding::lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(10, 77, 0, 9),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolution.egress_ifindex, 77,
        "the connected marker backed by a live interface must still win over the default route"
    );
}
