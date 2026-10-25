//! #16799 — rib-group RETURN rows (kernel priority in (1000, 2000)) run
//! AFTER the source VRF table's own lookup, not before it.
//!
//! The kernel RPDB for a packet ingressing tenant A is:
//!   0 local, 1000 l3mdev lookup A, 1001..1999 return rules
//!   (`to <peer-prefix> iif vrf-A lookup B`), 2000 VRF miss terminator,
//!   32766 main.
//! So A's own route (default, /25 more-specific, connected, discard)
//! always beats a return row into B; the return fires only when A's
//! table misses. The 30000-band leaks are different rules entirely
//! (after main's table rule) and keep stage-1 precedence in inet.0.
//!
//! These cells drive the production `build_forwarding_state` +
//! `lookup_forwarding_resolution_inner` with the exact snapshot shape
//! the Go mirror emits for a return row: a `RouteSnapshot` in
//! `tenant-a.inet.0` with `next_table = tenant-b.inet.0` and
//! `rule_priority` in (1000, 2000) (1225 = /24 v4, per
//! `config.RibGroupReturnRulePriority`; 1449 = /64 v6).

use super::super::forwarding_build::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot, ZoneSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const A_WAN_IFINDEX: i32 = 20;
const B_IFINDEX: i32 = 21;
/// Kernel return priority for a /24 peer prefix (1001 + 8*28).
const RETURN_PRIO_V4: u32 = 1225;
/// Kernel return priority for a /64 peer prefix (1001 + 64*7).
const RETURN_PRIO_V6: u32 = 1449;

fn iface(name: &str, ifindex: i32, instance: &str, addr: &str) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.to_string(),
        routing_instance: instance.to_string(),
        zone: "wan".to_string(),
        linux_name: name.replace('/', "-"),
        ifindex,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: if addr.contains(':') { "inet6" } else { "inet" }.to_string(),
            address: addr.to_string(),
            scope: 0,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn neighbor(iface_name: &str, ifindex: i32, family: &str, ip: &str) -> NeighborSnapshot {
    NeighborSnapshot {
        interface: iface_name.to_string(),
        ifindex,
        family: family.to_string(),
        ip: ip.to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
        ..Default::default()
    }
}

fn route(
    table: &str,
    family: &str,
    destination: &str,
    next_hops: Vec<String>,
    next_table: &str,
    rule_priority: u32,
) -> RouteSnapshot {
    RouteSnapshot {
        reject: false,
        cluster_terminal: false,
        table: table.to_string(),
        family: family.to_string(),
        destination: destination.to_string(),
        next_hop_weights: vec![],
        next_hops,
        discard: false,
        next_table: next_table.to_string(),
        preference: 0,
        rule_priority,
        mtu: 0,
        next_table_route: false,
    }
}

/// The va38 fixture: tenant A holds a deferred return row
/// `10.20.0.0/24 -> tenant-b.inet.0 @1225`; B routes that prefix out
/// ifindex 21. `a_routes` adds A's own routes (out ifindex 20).
fn snapshot_v4(a_routes: Vec<RouteSnapshot>) -> crate::ConfigSnapshot {
    let mut routes = vec![
        route(
            "tenant-a.inet.0",
            "inet",
            "10.20.0.0/24",
            vec![],
            "tenant-b.inet.0",
            RETURN_PRIO_V4,
        ),
        route(
            "tenant-b.inet.0",
            "inet",
            "10.20.0.0/24",
            vec!["172.16.21.1@ge-0/0/21.50".to_string()],
            "",
            0,
        ),
    ];
    routes.extend(a_routes);
    super::super::test_fixtures::v5(crate::ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            iface("ge-0/0/20.50", A_WAN_IFINDEX, "tenant-a", "172.16.20.8/24"),
            iface("ge-0/0/21.50", B_IFINDEX, "tenant-b", "172.16.21.8/24"),
        ],
        forwarding_tables: vec![
            "tenant-a.inet.0".to_string(),
            "tenant-a.inet6.0".to_string(),
            "tenant-b.inet.0".to_string(),
            "tenant-b.inet6.0".to_string(),
        ],
        routes,
        neighbors: vec![
            neighbor("ge-0-0-20.50", A_WAN_IFINDEX, "inet", "172.16.20.1"),
            neighbor("ge-0-0-21.50", B_IFINDEX, "inet", "172.16.21.1"),
            neighbor("ge-0-0-20.50", A_WAN_IFINDEX, "inet", "192.0.2.254"),
        ],
        ..Default::default()
    })
}

fn a_route(destination: &str, next_hop: &str) -> RouteSnapshot {
    route(
        "tenant-a.inet.0",
        "inet",
        destination,
        vec![next_hop.to_string()],
        "",
        0,
    )
}

fn lookup_a_v4(state: &ForwardingState, ip: Ipv4Addr) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, IpAddr::V4(ip), Some("tenant-a.inet.0"))
        .resolution
}

#[test]
fn return_row_control_source_miss_still_leaks_16799() {
    // Control (kernel: `dev b0 table 200`): A has no covering route, so
    // the return row fires and B's egress (21) wins.
    let state = build_forwarding_state(&snapshot_v4(vec![]));
    let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "control: return row must fire on a source miss"
    );
}

#[test]
fn return_row_loses_to_source_default_16799() {
    // A has its own default via its WAN (kernel: `via 192.0.2.254 dev aw
    // table 100`). Pre-fix this resolved to 21.
    let state = build_forwarding_state(&snapshot_v4(vec![a_route(
        "0.0.0.0/0",
        "192.0.2.254@ge-0/0/20.50",
    )]));
    let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, A_WAN_IFINDEX,
        "A's own default must beat the return row into B"
    );
}

#[test]
fn return_row_loses_to_more_specific_source_route_16799() {
    // A has a MORE-SPECIFIC /25 covering the probe (kernel: `via
    // 192.0.2.253 dev aw`). Pre-fix even this lost to the /24 return row.
    let mut snap = snapshot_v4(vec![a_route("10.20.0.0/25", "192.0.2.253@ge-0/0/20.50")]);
    snap.neighbors.push(neighbor(
        "ge-0-0-20.50",
        A_WAN_IFINDEX,
        "inet",
        "192.0.2.253",
    ));
    let state = build_forwarding_state(&snap);
    let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, A_WAN_IFINDEX,
        "A's own /25 must beat the return row into B"
    );
}

#[test]
fn return_row_loses_to_source_discard_16799() {
    // A discard route is the source table's own terminal answer; the
    // kernel returns it at l3mdev time and never reaches the return row.
    let mut discard = a_route("10.20.0.0/24", "");
    discard.discard = true;
    let state = build_forwarding_state(&snapshot_v4(vec![discard]));
    let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
    assert_eq!(resolved.disposition, ForwardingDisposition::DiscardRoute);
}

#[test]
fn return_row_priority_band_edges_16799() {
    // 1000 (l3mdev itself) and 2000 (miss terminator) are NOT return
    // priorities: rows there keep stage-1 precedence. 1500 (legacy flat
    // return) IS deferred.
    for (prio, want_ifindex, label) in [
        (1000u32, B_IFINDEX, "1000 is not a return priority"),
        (1500, A_WAN_IFINDEX, "legacy 1500 must defer"),
        (1999, A_WAN_IFINDEX, "1999 must defer"),
        (2000, B_IFINDEX, "2000 is not a return priority"),
        (30001, B_IFINDEX, "30000-band leak keeps stage-1 precedence"),
    ] {
        let mut snap = snapshot_v4(vec![a_route("0.0.0.0/0", "192.0.2.254@ge-0/0/20.50")]);
        for r in &mut snap.routes {
            if !r.next_table.is_empty() {
                r.rule_priority = prio;
            }
        }
        let state = build_forwarding_state(&snap);
        let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
        assert_eq!(
            resolved.egress_ifindex, want_ifindex,
            "{label} (prio {prio})"
        );
    }
}

#[test]
fn immediate_leak_still_beats_main_default_16799() {
    // Negative control for the deferral itself: a 30000-band leak in
    // inet.0 must still beat inet.0's own default (#9955 semantics,
    // unchanged by deferring only the (1000, 2000) band).
    let mut snap = snapshot_v4(vec![]);
    snap.routes.push(route(
        "inet.0",
        "inet",
        "10.20.0.0/24",
        vec![],
        "tenant-b.inet.0",
        30001,
    ));
    snap.routes.push(route(
        "inet.0",
        "inet",
        "0.0.0.0/0",
        vec!["192.0.2.254@ge-0/0/20.50".to_string()],
        "",
        0,
    ));
    let state = build_forwarding_state(&snap);
    let resolved = lookup_forwarding_resolution_inner(
        &state,
        None,
        IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5)),
        None,
    )
    .resolution;
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "30000-band leak in inet.0 must keep stage-1 precedence over main's default"
    );
}

#[test]
fn return_row_v6_twin_16799() {
    // v6 twin: A default via its WAN wins; without it the return fires.
    let probe: Ipv6Addr = "2001:db8:20::5".parse().unwrap();
    let build = |with_default: bool| {
        let mut routes = vec![
            route(
                "tenant-a.inet6.0",
                "inet6",
                "2001:db8:20::/64",
                vec![],
                "tenant-b.inet6.0",
                RETURN_PRIO_V6,
            ),
            route(
                "tenant-b.inet6.0",
                "inet6",
                "2001:db8:20::/64",
                vec!["2001:db8:21::1@ge-0/0/21.50".to_string()],
                "",
                0,
            ),
        ];
        if with_default {
            routes.push(route(
                "tenant-a.inet6.0",
                "inet6",
                "::/0",
                vec!["2001:db8:20f::1@ge-0/0/20.50".to_string()],
                "",
                0,
            ));
        }
        super::super::test_fixtures::v5(crate::ConfigSnapshot {
            zones: vec![ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                ..Default::default()
            }],
            interfaces: vec![
                iface(
                    "ge-0/0/20.50",
                    A_WAN_IFINDEX,
                    "tenant-a",
                    "2001:db8:20f::8/64",
                ),
                iface("ge-0/0/21.50", B_IFINDEX, "tenant-b", "2001:db8:21::8/64"),
            ],
            forwarding_tables: vec![
                "tenant-a.inet.0".to_string(),
                "tenant-a.inet6.0".to_string(),
                "tenant-b.inet.0".to_string(),
                "tenant-b.inet6.0".to_string(),
            ],
            routes,
            neighbors: vec![
                neighbor("ge-0-0-20.50", A_WAN_IFINDEX, "inet6", "2001:db8:20f::1"),
                neighbor("ge-0-0-21.50", B_IFINDEX, "inet6", "2001:db8:21::1"),
            ],
            ..Default::default()
        })
    };
    let state = build_forwarding_state(&build(true));
    let resolved = lookup_forwarding_resolution_inner(
        &state,
        None,
        IpAddr::V6(probe),
        Some("tenant-a.inet6.0"),
    )
    .resolution;
    assert_eq!(
        resolved.egress_ifindex, A_WAN_IFINDEX,
        "v6: A's own default must beat the return row"
    );
    let state = build_forwarding_state(&build(false));
    let resolved = lookup_forwarding_resolution_inner(
        &state,
        None,
        IpAddr::V6(probe),
        Some("tenant-a.inet6.0"),
    )
    .resolution;
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "v6 control: return row must fire on a source miss"
    );
}

#[test]
fn return_row_target_miss_stays_no_route_16799() {
    // Deferred target miss must not fabricate a result: A misses, the
    // return's target (B) also has no route for the probe -> NoRoute.
    let mut snap = snapshot_v4(vec![]);
    snap.routes.retain(|r| r.table != "tenant-b.inet.0");
    let state = build_forwarding_state(&snap);
    let resolved = lookup_a_v4(&state, Ipv4Addr::new(10, 20, 0, 5));
    assert_eq!(resolved.disposition, ForwardingDisposition::NoRoute);
}

#[test]
fn return_row_incarnation_not_stamped_when_source_owns_16799() {
    // When A's own default carries the destination, the deferred return
    // owns nothing: no incarnation stamp. On a source miss it stamps.
    let state = build_forwarding_state(&snapshot_v4(vec![a_route(
        "0.0.0.0/0",
        "192.0.2.254@ge-0/0/20.50",
    )]));
    assert_eq!(
        leak_incarnation_for_resolution(
            &state,
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5)),
            Some("tenant-a.inet.0")
        ),
        None,
        "source-owned destination must not stamp the deferred return"
    );
    let state = build_forwarding_state(&snapshot_v4(vec![]));
    assert!(
        leak_incarnation_for_resolution(
            &state,
            IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5)),
            Some("tenant-a.inet.0")
        )
        .is_some(),
        "source miss must stamp the deferred return that carries it"
    );
}
