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

// #16513 helpers: shared-ifindex rows as the Go builder emits them for
// a zoned untagged unit 0. The base row carries the kernel addresses
// (unmarked, order pick .10/::10); the unit row carries the configured
// marker (designated .9/::9). Both share ifindex 42 and zone "trust".
fn shared_row_16513(
    name: &str,
    zone: &str,
    egress_zone: &str,
    tunnel: bool,
    addresses: Vec<InterfaceAddressSnapshot>,
) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.into(),
        linux_name: "ge-0-0-1".into(),
        ifindex: 42,
        zone: zone.into(),
        egress_zone: egress_zone.into(),
        tunnel,
        hardware_addr: "02:00:00:00:00:2a".into(),
        addresses,
        ..Default::default()
    }
}

fn kernel_addrs_16513() -> Vec<InterfaceAddressSnapshot> {
    vec![
        addr("inet", "10.0.0.10/24", false),
        addr("inet", "10.0.0.9/24", false),
        addr("inet6", "2001:db8::10/64", false),
        addr("inet6", "2001:db8::9/64", false),
    ]
}

fn marked_addrs_16513() -> Vec<InterfaceAddressSnapshot> {
    vec![
        addr("inet", "10.0.0.10/24", false),
        addr("inet", "10.0.0.9/24", true),
        addr("inet6", "2001:db8::10/64", false),
        addr("inet6", "2001:db8::9/64", true),
    ]
}

fn snapshot_16513(interfaces: Vec<InterfaceSnapshot>) -> ConfigSnapshot {
    crate::afxdp::test_fixtures::v5(ConfigSnapshot {
        interfaces,
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 1,
            ..Default::default()
        }],
        ..Default::default()
    })
}

/// #16513: base row (unmarked) + unit row (marked) on one consistently
/// zoned ifindex must build Ok and the egress primary must be the
/// DESIGNATED address, in either row order.
///
/// FAIL-ON-REVERT: restore the #13181 per-row-pick comparison and the
/// base-first order returns InterfaceSharedIfindexAttributeConflict
/// {primary_v4: 10.0.0.10 vs 10.0.0.9}; restore first-row-wins merging
/// and the base-first order silently yields .10/::10.
#[test]
fn shared_ifindex_designated_primary_wins_over_base_row_16513() {
    for base_first in [true, false] {
        let base = shared_row_16513("ge-0/0/1", "trust", "trust", false, kernel_addrs_16513());
        let unit = shared_row_16513("ge-0/0/1.0", "trust", "trust", false, marked_addrs_16513());
        let interfaces = if base_first {
            vec![base, unit]
        } else {
            vec![unit, base]
        };
        let snapshot = snapshot_16513(interfaces);
        let state = try_build_forwarding_state_with_policy_counters(
            &snapshot,
            &PolicyCounterStore::default(),
        )
        .unwrap_or_else(|e| {
            panic!("base_first={base_first}: designated primary must build, got {e:?}")
        });
        let egress = state.egress.get(&42).expect("egress row for ifindex 42");
        assert_eq!(
            egress.primary_v4,
            Some(Ipv4Addr::new(10, 0, 0, 9)),
            "base_first={base_first}: designated v4 primary must win the merge"
        );
        assert_eq!(
            egress.primary_v6,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
            "base_first={base_first}: designated v6 primary must win the merge"
        );
    }
}

/// #16513 control: no marker on either row — the merge keeps the
/// order-based pick (.10/::10) exactly as before.
#[test]
fn shared_ifindex_unmarked_control_keeps_order_pick_16513() {
    let snapshot = snapshot_16513(vec![
        shared_row_16513("ge-0/0/1", "trust", "trust", false, kernel_addrs_16513()),
        shared_row_16513("ge-0/0/1.0", "trust", "trust", false, kernel_addrs_16513()),
    ]);
    let state = build_forwarding_state(&snapshot);
    let egress = state.egress.get(&42).expect("egress row for ifindex 42");
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 0, 0, 10)));
    assert_eq!(
        egress.primary_v6,
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10))
    );
}

/// #16513: on a shape that is NOT consistently zoned (base row unzoned,
/// unit zoned — the RETH-member / fan-up shape), the designation must
/// still win instead of being silently dropped by first-row-wins.
#[test]
fn shared_ifindex_designated_primary_wins_when_not_consistently_zoned_16513() {
    let snapshot = snapshot_16513(vec![
        shared_row_16513("ge-0/0/1", "", "trust", false, kernel_addrs_16513()),
        shared_row_16513("ge-0/0/1.0", "trust", "trust", false, marked_addrs_16513()),
    ]);
    let state = build_forwarding_state(&snapshot);
    let egress = state.egress.get(&42).expect("egress row for ifindex 42");
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 0, 0, 9)));
    assert_eq!(
        egress.primary_v6,
        Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9))
    );
}

/// #16513: two DIFFERENT designated primaries on one consistently
/// zoned non-tunnel ifindex are a genuine config conflict and must
/// still fail closed — the designated-wins merge must not degenerate
/// into last-designation-wins.
#[test]
fn shared_ifindex_conflicting_designations_still_fail_closed_16513() {
    let other_marked = vec![
        addr("inet", "10.0.0.10/24", true),
        addr("inet", "10.0.0.9/24", false),
        addr("inet6", "2001:db8::10/64", false),
        addr("inet6", "2001:db8::9/64", false),
    ];
    let snapshot = snapshot_16513(vec![
        shared_row_16513("ge-0/0/1.0", "trust", "trust", false, marked_addrs_16513()),
        shared_row_16513("ge-0/0/1.1", "trust", "trust", false, other_marked),
    ]);
    let result =
        try_build_forwarding_state_with_policy_counters(&snapshot, &PolicyCounterStore::default());
    assert!(
        matches!(
            result,
            Err(
                crate::policy::SnapshotIntegrityError::InterfaceSharedIfindexAttributeConflict {
                    attribute: "primary_v4",
                    ..
                }
            )
        ),
        "conflicting designations must reject the snapshot, got {result:?}"
    );
}

/// #16513 acceptance: tunnel units sharing one netdev with genuinely
/// different designated primaries are still accepted (the #13181
/// tunnel exemption is preserved).
#[test]
fn shared_ifindex_tunnel_designations_still_accepted_16513() {
    let other_marked = vec![
        addr("inet", "10.0.0.10/24", true),
        addr("inet", "10.0.0.9/24", false),
    ];
    let snapshot = snapshot_16513(vec![
        shared_row_16513("gr-0/0/0.0", "trust", "trust", true, marked_addrs_16513()),
        shared_row_16513("gr-0/0/0.1", "trust", "trust", true, other_marked),
    ]);
    let result =
        try_build_forwarding_state_with_policy_counters(&snapshot, &PolicyCounterStore::default());
    assert!(
        result.is_ok(),
        "tunnel units with different primaries must stay accepted, got {result:?}"
    );
}

/// #18174: the live loss-cluster RETH shape. Go emits the base row
/// (`reth1`, kernel-observed, carrying only the per-node
/// `169.254.<rg>.<node+1>/32` RETH address — scope link) BEFORE the unit
/// row (`reth1.0`, carrying the LAN address) on the SAME ifindex. The
/// base row's per-row pick is its link-local FALLBACK; first-row-wins let
/// it shadow the unit row's real address, so every locally generated ICMP
/// error toward the LAN (traceroute hop 1, reject, PTB) left with source
/// 169.254.2.1. The v6 twin is the same shape with a kernel fe80 RETH
/// address on the base row (observed as mtr hop 1 `fe80::bf:72ff:fe16:202`
/// in the #18168 diag). Both row orders must yield the routable address.
///
/// FAIL-ON-REVERT: restore `existing.primary_v4.or(Some(p))` (and the v6
/// twin) in the shared-ifindex merge and the base-first order yields
/// 169.254.2.1 / fe80::bf72:16:2 again.
#[test]
fn shared_ifindex_reth_base_link_local_does_not_shadow_unit_address_18174() {
    let base_addrs = || {
        vec![
            InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "169.254.2.1/32".into(),
                scope: 253,
                primary: false,
            },
            InterfaceAddressSnapshot {
                family: "inet6".into(),
                address: "fe80::bf72:16:2/128".into(),
                scope: 253,
                primary: false,
            },
        ]
    };
    let unit_addrs = || {
        vec![
            addr("inet", "10.0.61.1/24", false),
            InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "169.254.2.1/32".into(),
                scope: 253,
                primary: false,
            },
            addr("inet6", "2001:559:8585:ef00::1/64", false),
        ]
    };
    for base_first in [true, false] {
        let base = shared_row_16513("reth1", "trust", "trust", false, base_addrs());
        let unit = shared_row_16513("reth1.0", "trust", "trust", false, unit_addrs());
        let interfaces = if base_first {
            vec![base, unit]
        } else {
            vec![unit, base]
        };
        let state = build_forwarding_state(&snapshot_16513(interfaces));
        let egress = state.egress.get(&42).expect("egress row for ifindex 42");
        assert_eq!(
            egress.primary_v4,
            Some(Ipv4Addr::new(10, 0, 61, 1)),
            "base_first={base_first}: a link-local base-row pick must not shadow the unit's LAN v4"
        );
        assert_eq!(
            egress.primary_v6,
            Some(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0xef00, 0, 0, 0, 1)),
            "base_first={base_first}: a link-local base-row pick must not shadow the unit's global v6"
        );
    }

    // Control: when EVERY row offers only link-local, the merged primary
    // stays the first row's fallback (the per-row last-resort rule).
    let state = build_forwarding_state(&snapshot_16513(vec![
        shared_row_16513("reth1", "trust", "trust", false, base_addrs()),
        shared_row_16513(
            "reth1.0",
            "trust",
            "trust",
            false,
            vec![
                addr("inet", "169.254.9.9/32", false),
                addr("inet6", "fe80::9/64", false),
            ],
        ),
    ]));
    let egress = state.egress.get(&42).expect("egress row for ifindex 42");
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(169, 254, 2, 1)));
    assert_eq!(
        egress.primary_v6,
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xbf72, 0x16, 2))
    );
}
