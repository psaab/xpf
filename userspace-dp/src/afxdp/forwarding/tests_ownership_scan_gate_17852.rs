//! #17852 — the #16799 return-order fix ran its linear source-ownership
//! scan (`source_table_owns_v[46]`) unconditionally: once before the
//! LPM of every leak-evaluating lookup, and once in
//! `leak_incarnation_for_resolution` before even checking whether the
//! table has leak rules. Tables with no deferred (`post_table`)
//! rib-group return covering the destination need none of that work.
//!
//! These cells prove the gating with a thread-local scan counter
//! (`source_ownership_scans_for_test`): ordinary successful lookups,
//! NoRoute lookups, stage-1-only leak tables, and incarnation checks
//! in tables without deferred returns perform ZERO ownership walks,
//! while tables whose deferred return actually covers a source miss
//! still scan and still defer (controls re-asserting #16799 order).
//!
//! Fixtures drive the production `build_forwarding_state` + resolvers
//! with the same snapshot shape as #16799 (`tests_return_order_16799`).

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
/// A 30000-band leak (post-main in the kernel): stage-1 precedence,
/// never deferred.
const STAGE1_PRIO: u32 = 30001;

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

/// The #16799 va38 fixture, parametrised on the leak row: `None` omits
/// it entirely (no leak rules for A), `Some(prio)` keeps the
/// `10.20.0.0/24 -> tenant-b.inet.0` row at the given kernel priority.
/// B always routes the prefix out ifindex 21; `a_routes` adds A's own
/// routes out ifindex 20.
fn snapshot_v4(a_routes: Vec<RouteSnapshot>, leak_prio: Option<u32>) -> crate::ConfigSnapshot {
    let mut routes = vec![route(
        "tenant-b.inet.0",
        "inet",
        "10.20.0.0/24",
        vec!["172.16.21.1@ge-0/0/21.50".to_string()],
        "",
        0,
    )];
    if let Some(prio) = leak_prio {
        routes.push(route(
            "tenant-a.inet.0",
            "inet",
            "10.20.0.0/24",
            vec![],
            "tenant-b.inet.0",
            prio,
        ));
    }
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

fn snapshot_v6(with_default: bool, leak_prio: Option<u32>) -> crate::ConfigSnapshot {
    let mut routes = vec![route(
        "tenant-b.inet6.0",
        "inet6",
        "2001:db8:20::/64",
        vec!["2001:db8:21::1@ge-0/0/21.50".to_string()],
        "",
        0,
    )];
    if let Some(prio) = leak_prio {
        routes.push(route(
            "tenant-a.inet6.0",
            "inet6",
            "2001:db8:20::/64",
            vec![],
            "tenant-b.inet6.0",
            prio,
        ));
    }
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
}

fn lookup_a_v4(state: &ForwardingState, ip: Ipv4Addr) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, IpAddr::V4(ip), Some("tenant-a.inet.0"))
        .resolution
}

fn lookup_a_v6(state: &ForwardingState, ip: Ipv6Addr) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, IpAddr::V6(ip), Some("tenant-a.inet6.0"))
        .resolution
}

/// A table with no leak rules at all: a successful lookup and a NoRoute
/// lookup both do zero ownership walks.
#[test]
fn no_leak_rules_v4_lookup_skips_ownership_scan_17852() {
    let hit = Ipv4Addr::new(10, 20, 0, 5);
    let miss = Ipv4Addr::new(10, 30, 0, 5);

    let state = build_forwarding_state(&snapshot_v4(
        vec![a_route("0.0.0.0/0", "192.0.2.254@ge-0/0/20.50")],
        None,
    ));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, hit);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "successful lookup without leak rules must not run the ownership scan"
    );

    let state = build_forwarding_state(&snapshot_v4(vec![], None));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, miss);
    assert_eq!(resolved.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "NoRoute lookup without leak rules must not run the ownership scan"
    );
}

/// A leak set that contains only a stage-1 (30000-band) row: neither
/// its stage-1 leak walk nor the miss tail runs an ownership scan.
#[test]
fn stage1_only_leaks_v4_lookup_skips_ownership_scan_17852() {
    let leaked = Ipv4Addr::new(10, 20, 0, 5);
    let missed = Ipv4Addr::new(10, 30, 0, 5);

    let state = build_forwarding_state(&snapshot_v4(vec![], Some(STAGE1_PRIO)));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, leaked);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "stage-1 leak still resolves via B"
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "stage-1 leak resolution must not run the ownership scan"
    );

    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, missed);
    assert_eq!(resolved.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "miss past a stage-1-only leak set must not run the ownership scan"
    );
}

/// Control: when a deferred return actually covers the destination, the
/// ownership scan still runs (exactly on the miss tail) and #16799
/// ordering is unchanged — source miss defers to B, source-owned stays
/// with A (and needs no scan at all: the LPM already answered).
#[test]
fn deferred_return_v4_control_still_scans_and_defers_17852() {
    let probe = Ipv4Addr::new(10, 20, 0, 5);

    let state = build_forwarding_state(&snapshot_v4(vec![], Some(RETURN_PRIO_V4)));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, probe);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "control: deferred return must still fire on a source miss"
    );
    assert!(
        source_ownership_scans_for_test() >= 1,
        "control: a covering deferred return must still consult ownership"
    );

    let state = build_forwarding_state(&snapshot_v4(
        vec![a_route("0.0.0.0/0", "192.0.2.254@ge-0/0/20.50")],
        Some(RETURN_PRIO_V4),
    ));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v4(&state, probe);
    assert_eq!(resolved.egress_ifindex, A_WAN_IFINDEX);
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "source-owned hit answers at the LPM; the tail never scans"
    );
}

/// Incarnation stamping in tables without deferred returns: no rules at
/// all, and a stage-1-only rule set, both stamp (or miss) without any
/// ownership walk.
#[test]
fn incarnation_without_deferred_rules_skips_ownership_scan_17852() {
    let probe = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5));

    let state = build_forwarding_state(&snapshot_v4(vec![], None));
    reset_source_ownership_scans_for_test();
    assert_eq!(
        leak_incarnation_for_resolution(&state, probe, Some("tenant-a.inet.0")),
        None,
        "no leak rules: nothing to stamp"
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "incarnation check without leak rules must not run the ownership scan"
    );

    let state = build_forwarding_state(&snapshot_v4(vec![], Some(STAGE1_PRIO)));
    reset_source_ownership_scans_for_test();
    assert!(
        leak_incarnation_for_resolution(&state, probe, Some("tenant-a.inet.0")).is_some(),
        "stage-1 leak carrying the destination must still stamp its incarnation"
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "stage-1-only incarnation stamping must not run the ownership scan"
    );
}

/// Control: a covering deferred return keeps #16799 stamping semantics
/// and does consult ownership on both sides of it.
#[test]
fn incarnation_deferred_control_17852() {
    let probe = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 5));

    let state = build_forwarding_state(&snapshot_v4(vec![], Some(RETURN_PRIO_V4)));
    reset_source_ownership_scans_for_test();
    assert!(
        leak_incarnation_for_resolution(&state, probe, Some("tenant-a.inet.0")).is_some(),
        "control: source miss must still stamp the deferred return"
    );
    assert!(
        source_ownership_scans_for_test() >= 1,
        "control: deferred-return stamping must still consult ownership"
    );

    let state = build_forwarding_state(&snapshot_v4(
        vec![a_route("0.0.0.0/0", "192.0.2.254@ge-0/0/20.50")],
        Some(RETURN_PRIO_V4),
    ));
    reset_source_ownership_scans_for_test();
    assert_eq!(
        leak_incarnation_for_resolution(&state, probe, Some("tenant-a.inet.0")),
        None,
        "control: source-owned destination must not stamp the deferred return"
    );
    assert!(
        source_ownership_scans_for_test() >= 1,
        "control: the deferred stamp decision must still consult ownership"
    );
}

/// v6 twins: no deferred returns -> zero scans on hit and miss; a
/// covering deferred return -> scan + deferral unchanged.
#[test]
fn v6_twins_gate_and_control_17852() {
    let hit: Ipv6Addr = "2001:db8:20::5".parse().unwrap();
    let missed: Ipv6Addr = "2001:db8:30::5".parse().unwrap();

    let state = build_forwarding_state(&snapshot_v6(true, None));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v6(&state, hit);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "v6: successful lookup without leak rules must not scan"
    );

    let state = build_forwarding_state(&snapshot_v6(false, None));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v6(&state, missed);
    assert_eq!(resolved.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "v6: NoRoute lookup without leak rules must not scan"
    );

    let state = build_forwarding_state(&snapshot_v6(false, Some(RETURN_PRIO_V6)));
    reset_source_ownership_scans_for_test();
    let resolved = lookup_a_v6(&state, hit);
    assert_eq!(
        resolved.egress_ifindex, B_IFINDEX,
        "v6 control: deferred return must still fire on a source miss"
    );
    assert!(
        source_ownership_scans_for_test() >= 1,
        "v6 control: covering deferred return must still consult ownership"
    );

    let state = build_forwarding_state(&snapshot_v6(false, Some(STAGE1_PRIO)));
    reset_source_ownership_scans_for_test();
    assert!(
        leak_incarnation_for_resolution(&state, IpAddr::V6(hit), Some("tenant-a.inet6.0"))
            .is_some(),
        "v6: stage-1-only incarnation stamping still works"
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "v6: stage-1-only incarnation stamping must not scan"
    );

    let state = build_forwarding_state(&snapshot_v6(false, None));
    reset_source_ownership_scans_for_test();
    assert_eq!(
        leak_incarnation_for_resolution(&state, IpAddr::V6(missed), Some("tenant-a.inet6.0")),
        None,
        "v6: no leak rules: nothing to stamp"
    );
    assert_eq!(
        source_ownership_scans_for_test(),
        0,
        "v6: incarnation check without leak rules must not scan"
    );
}
