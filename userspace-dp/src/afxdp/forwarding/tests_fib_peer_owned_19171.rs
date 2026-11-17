//! #19171 (the FIB-level fix): one cell per census reader whose behaviour
//! changes now that a peer-owned connected prefix stays in the transit FIB.
//! The census (docs/log/19171.md) traced every reader of `connected_v4/v6`;
//! these pin the readers that answer differently, end to end from a snapshot
//! carrying the `connected_rg_peer_owned` mark, so `populate_interfaces` (the
//! code that changed) is on every path.

use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::tests_split_rg_gateway_18517::{address, find_route_v4, route, split_node_snapshot};
use super::*;
use crate::InterfaceSnapshot;

/// Census row 2: equal-length transit rows in one table now break the tie to
/// the LOWEST ifindex (the #17053 canonical rule), not snapshot order. Two
/// non-peer-owned units carry 10.0.61.0/24; the one listed second has the
/// lower ifindex and must win.
#[test]
fn equal_length_transit_rows_answer_the_lowest_ifindex_19171() {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth5.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-5".to_string(),
        ifindex: 7,
        hardware_addr: "02:bf:72:05:00:07".to_string(),
        addresses: vec![address("inet", "10.0.61.9/24")],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let order: Vec<i32> = snapshot
        .interfaces
        .iter()
        .filter(|iface| iface.name == "reth1.0" || iface.name == "reth5.0")
        .map(|iface| iface.ifindex)
        .collect();
    assert_eq!(order, vec![24, 7], "FIXTURE: the higher ifindex is listed first");
    let answer = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))).resolution;
    assert_eq!(answer.egress_ifindex, 7, "the equal-length tie answers the lowest ifindex, got {answer:?}");
}

/// The split-node fixture of census rows 4 and 9/10: `reth6.0` (ifindex 8,
/// RG4, ACTIVE, not peer-owned) carries the broad 172.16.0.0/16; `reth0.80`
/// (12, RG1, peer-owned) the narrow 172.16.80.0/24 inside it.
fn broad_active_narrow_peer_owned() -> crate::ConfigSnapshot {
    let mut snapshot = split_node_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth6.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-6".to_string(),
        ifindex: 8,
        redundancy_group: 4,
        hardware_addr: "02:bf:72:06:00:08".to_string(),
        addresses: vec![address("inet", "172.16.0.6/16")],
        ..Default::default()
    });
    snapshot
}

/// Census row 4: gateway binding is now true longest-prefix match across both
/// row sets. A bare gateway inside the narrow peer-owned /24 binds that unit
/// (12), where before the covering broad transit /16 (8) won and the #18517
/// fallback never ran.
#[test]
fn bare_gateway_binds_the_longest_covering_row_even_when_peer_owned_19171() {
    let mut snapshot = broad_active_narrow_peer_owned();
    snapshot.routes.push(route("inet", "inet.0", "10.40.0.0/24", &["172.16.80.1"], 5));
    let state = build_forwarding_state(&snapshot);
    let bound = find_route_v4(&state, "inet.0", "10.40.0.0/24");
    assert_eq!(
        bound.next_hops.iter().map(|nh| nh.ifindex).collect::<Vec<_>>(),
        vec![12],
        "the gateway binds the longest covering row, the peer-owned /24"
    );
}

/// Census rows 9/10: connected-owner attribution. A destination inside the
/// narrow peer-owned /24 is owned by its RG (1), not by the broad active /16's
/// RG (4), which before beat the longer peer-owned ledger prefix.
#[test]
fn connected_owner_is_the_longest_covering_row_even_when_peer_owned_19171() {
    let state = build_forwarding_state(&broad_active_narrow_peer_owned());
    let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, target, Some("inet.0")),
        1,
        "the narrow peer-owned /24's RG owns the destination"
    );
    assert_eq!(
        crate::afxdp::session_glue::connected_ifindex_for_target_in_table(&state, target, Some("inet.0")),
        12,
        "and its interface is the connected egress"
    );
}

/// Census row 18: the subnet directed broadcast of a peer-owned prefix is now
/// recognised, so ICMP errors to it are suppressed as for any other subnet.
#[test]
fn peer_owned_subnet_broadcast_is_a_directed_broadcast_19171() {
    let state = build_forwarding_state(&split_node_snapshot());
    // An IPv4 header to the subnet broadcast (the classifier reads bytes
    // 16..20, the destination).
    let mut header = [0u8; 20];
    header[16..20].copy_from_slice(&Ipv4Addr::new(172, 16, 80, 255).octets());
    assert!(
        crate::afxdp::frame::dest_is_directed_broadcast(&state, &header, Some("inet.0")),
        "172.16.80.255 is the peer-owned /24's directed broadcast"
    );
}

/// Census row 15: a configured next-table route no longer outranks a
/// peer-owned connected prefix at least as long. 8.8.8.0/24 leaks to
/// `blue.inet.0`; a peer-owned default-instance unit (`reth8.0`, RG1) also
/// carries 8.8.8.0/24. The connected row wins and HA judges its egress; before,
/// the withheld prefix let the next-table route win.
#[test]
fn peer_owned_connected_prefix_outranks_an_equal_length_next_table_route_19171() {
    let mut snapshot = forwarding_snapshot_with_next_table(true);
    // A CONFIGURED next-table route (the census row's reader,
    // `junos_next_table_winner_v4`), not a kernel-model leak rule: those run
    // before longest-prefix match and no connected row pre-empts them.
    for route in &mut snapshot.routes {
        if route.table == "inet.0" && route.destination == "8.8.8.0/24" {
            route.next_table_route = true;
        }
    }
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth8.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-8".to_string(),
        ifindex: 33,
        redundancy_group: 1,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:08:00:21".to_string(),
        addresses: vec![address("inet", "8.8.8.1/24")],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let answer = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).resolution;
    assert!(
        matches!(
            answer.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        ) && answer.egress_ifindex == 33,
        "the peer-owned connected /24 outranks the next-table route, got {answer:?}"
    );
}

/// Census row 13: the subnet-router anycast of a peer-owned IPv6 prefix is
/// owned by its table and attributed to the peer-owned unit (12); HA then
/// gates that local delivery on the inactive RG.
#[test]
fn peer_owned_subnet_router_anycast_is_attributed_and_ha_gated_19171() {
    let state = build_forwarding_state(&split_node_snapshot());
    let anycast = IpAddr::V6("2001:559:8585:80::".parse().expect("anycast"));
    let answer = lookup_forwarding_resolution(&state, anycast).resolution;
    assert_eq!(
        (answer.disposition, answer.local_ifindex),
        (ForwardingDisposition::LocalDelivery, 12),
        "the peer-owned prefix's subnet-router anycast is attributed to its unit, got {answer:?}"
    );
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = BTreeMap::from([(1, HAGroupRuntime {
        active: false,
        watchdog_timestamp: now_secs,
        lease: HAForwardingLease::Inactive,
    })]);
    let gated = enforce_ha_resolution_snapshot(&state, &ha, now_secs, answer);
    assert_ne!(
        gated.disposition,
        ForwardingDisposition::LocalDelivery,
        "HA gates the peer-owned unit's local delivery"
    );
}

/// #19171 cost: transit lookups with K peer-owned connected rows in the FIB.
/// Before the fix those rows were withheld, so K = 0 is the master-equivalent
/// cost for every K. The connected rows are scanned linearly
/// (`select_v4_route`), so this is the price of keeping them in transit:
/// - `off-link`: a routed destination, which scans every connected row;
/// - `in-prefix`: a destination inside the LAST peer-owned prefix.
///
/// Ignored, release only:
/// `cargo test --release --bin xpf-userspace-dp -- --ignored --exact
///  afxdp::forwarding::tests_fib_peer_owned_19171::connected_lpm_cost_bench_19171 --nocapture`
#[test]
#[ignore = "MEASUREMENT: #19171 transit LPM cost per peer-owned connected row; gates nothing"]
fn connected_lpm_cost_bench_19171() {
    const N: u32 = 200_000;
    for k in [0u16, 16, 128, 1024] {
        let mut snapshot = split_node_snapshot();
        for i in 0..k {
            snapshot.interfaces.push(InterfaceSnapshot {
                name: format!("reth{}.0", 100 + i),
                zone: "lan".to_string(),
                linux_name: format!("ge-1-{}-{}", i / 256, i % 256),
                ifindex: 1000 + i32::from(i),
                redundancy_group: 5,
                connected_rg_peer_owned: true,
                hardware_addr: format!("02:bf:73:{:02x}:{:02x}:01", i / 256, i % 256),
                addresses: vec![address("inet", &format!("10.{}.{}.1/24", 100 + i / 256, i % 256))],
                ..Default::default()
            });
        }
        let state = build_forwarding_state(&snapshot);
        let in_prefix = if k == 0 {
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))
        } else {
            let last = k - 1;
            IpAddr::V4(Ipv4Addr::new(10, (100 + last / 256) as u8, (last % 256) as u8, 77))
        };
        for (label, dst) in [
            ("off-link", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            ("in-prefix", in_prefix),
        ] {
            let mut rounds = Vec::new();
            for _ in 0..7 {
                let started = std::time::Instant::now();
                for _ in 0..N {
                    std::hint::black_box(lookup_forwarding_resolution(&state, std::hint::black_box(dst)));
                }
                rounds.push(started.elapsed().as_nanos() as f64 / f64::from(N));
            }
            rounds.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
            eprintln!(
                "COST19171A k={k} {label:>9}: median {:.1} ns/op (min {:.1}, max {:.1}) over 7 x {N}",
                rounds[3], rounds[0], rounds[6]
            );
        }
    }
}

/// Census row 14: a leak into a table whose only claim on the destination is
/// a peer-owned connected prefix. `inet.0` leaks 8.8.8.0/24 to `blue.inet.0`;
/// blue's own route for it is removed, and a peer-owned blue unit (`reth9.0`,
/// RG1) carries 8.8.8.1/24. The leak target's claim now counts, so the lookup
/// recurses into blue and answers Connected on that unit (then HA judges it).
/// Before, the withheld prefix gave blue no claim.
#[test]
fn leak_target_claimed_only_by_a_peer_owned_prefix_resolves_its_unit_19171() {
    let mut snapshot = forwarding_snapshot_with_next_table(true);
    snapshot
        .routes
        .retain(|r| !(r.table == "blue.inet.0" && r.destination == "8.8.8.0/24"));
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth9.0".to_string(),
        zone: "wan".to_string(),
        routing_instance: "blue".to_string(),
        linux_name: "ge-0-0-9".to_string(),
        ifindex: 34,
        redundancy_group: 1,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:09:00:22".to_string(),
        addresses: vec![address("inet", "8.8.8.1/24")],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let answer = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).resolution;
    assert!(
        matches!(
            answer.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        ) && answer.egress_ifindex == 34,
        "the leak target's peer-owned connected prefix answers, got {answer:?}"
    );
}
