use super::*;
use crate::protocol::snapshot::InterfaceAddressSnapshot;
use crate::{ConfigSnapshot, InterfaceSnapshot, ZoneSnapshot};
use std::net::{Ipv4Addr, Ipv6Addr};

fn addr(family: &str, address: &str, primary: bool) -> InterfaceAddressSnapshot {
    InterfaceAddressSnapshot {
        family: family.into(),
        address: address.into(),
        scope: 0,
        primary,
    }
}

fn iface_15155(addresses: Vec<InterfaceAddressSnapshot>) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: "reth0.0".into(),
        linux_name: "reth0".into(),
        ifindex: 42,
        zone: "wan".into(),
        hardware_addr: "02:00:00:00:00:2a".into(),
        addresses,
        ..Default::default()
    }
}

/// #15155 (B15-02): the operator's designated primary must beat the
/// lexicographic snapshot order the Go builder emits. String sort puts
/// "10.0.0.10/24" before "10.0.0.9/24" and "2001:db8::10/64" before
/// "2001:db8::9/64"; without the marker every primary_v4/v6 consumer
/// (interface SNAT at forwarding/nat.rs, local delivery, RST) used the
/// .10 / ::10 address the operator did not choose.
///
/// FAIL-ON-REVERT: drop the prefer-primary arm in pick_interface_v4/v6
/// and both discriminating picks return .10 / ::10 again.
#[test]
fn pick_prefers_designated_primary_over_sort_order_15155() {
    let iface = iface_15155(vec![
        addr("inet", "10.0.0.10/24", false),
        addr("inet", "10.0.0.9/24", true),
        addr("inet6", "2001:db8::10/64", false),
        addr("inet6", "2001:db8::9/64", true),
    ]);
    assert_eq!(
        pick_interface_v4(&iface),
        Some(Ipv4Addr::new(10, 0, 0, 9)),
        "configured v4 primary must win over lexicographic order"
    );
    assert_eq!(
        pick_interface_v6(&iface),
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
        "configured v6 primary must win over lexicographic order"
    );
}

/// The full build: egress[ifindex].primary_v4/v6 carry the designated
/// addresses into every downstream consumer.
#[test]
fn egress_primary_carries_designated_address_15155() {
    let snapshot = crate::afxdp::test_fixtures::v5(ConfigSnapshot {
        interfaces: vec![iface_15155(vec![
            addr("inet", "10.0.0.10/24", false),
            addr("inet", "10.0.0.9/24", true),
            addr("inet6", "2001:db8::10/64", false),
            addr("inet6", "2001:db8::9/64", true),
        ])],
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 1,
            ..Default::default()
        }],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let egress = state.egress.get(&42).expect("egress row for ifindex 42");
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(
        egress.primary_v6,
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9))
    );
}

/// Control: no marker anywhere — the pick is exactly the old
/// first-non-link-local-in-snapshot-order rule (link-local only as the
/// last-resort fallback).
#[test]
fn pick_without_marker_keeps_order_rule_15155() {
    let iface = iface_15155(vec![
        addr("inet", "169.254.1.1/16", false),
        addr("inet", "192.0.2.20/24", false),
        addr("inet6", "fe80::1/64", false),
        addr("inet6", "2001:db8::20/64", false),
    ]);
    assert_eq!(
        pick_interface_v4(&iface),
        Some(Ipv4Addr::new(192, 0, 2, 20))
    );
    assert_eq!(
        pick_interface_v6(&iface),
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20))
    );

    let link_local_only = iface_15155(vec![
        addr("inet", "169.254.1.1/16", false),
        addr("inet6", "fe80::1/64", false),
    ]);
    assert_eq!(
        pick_interface_v4(&link_local_only),
        Some(Ipv4Addr::new(169, 254, 1, 1)),
        "pure link-local control keeps the fallback"
    );
    assert_eq!(
        pick_interface_v6(&link_local_only),
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        "pure link-local control keeps the fallback"
    );
}
