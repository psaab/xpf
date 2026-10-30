//! #18517 review fold: the split-node bare-gateway binding
//! (`peer_owned_connected_target_v4/v6` in `forwarding_build/fib.rs`) and the
//! #15917 gateway-owner terminal attribution it left behind.
//!
//! All cells drive the production builder (`build_forwarding_state`) from a
//! snapshot, so each shape below is reachable from the helper's input, not
//! hand-built state. The base topology is `nat_snapshot_with_fabric`:
//! `reth0.80` (ifindex 12, RG1, 172.16.80.8/24, 2001:559:8585:80::8/64) is the
//! WAN unit, `reth1.0` (ifindex 24, RG2, 10.0.61.1/24,
//! 2001:559:8585:ef00::1/64) the LAN unit, and `fab0` the fabric link.

use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;
use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot, ZoneSnapshot};

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

fn ha_map(groups: &[(i32, bool)]) -> Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>> {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    Arc::new(ArcSwap::from_pointee(
        groups
            .iter()
            .map(|&(rg, active)| {
                (
                    rg,
                    if active {
                        active_ha_runtime(now_secs)
                    } else {
                        inactive_ha_runtime(now_secs)
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    ))
}

fn address(family: &str, address: &str) -> InterfaceAddressSnapshot {
    InterfaceAddressSnapshot {
        family: family.to_string(),
        address: address.to_string(),
        scope: 0,
        ..Default::default()
    }
}

fn route(family: &str, table: &str, destination: &str, next_hops: &[&str], preference: i32) -> RouteSnapshot {
    RouteSnapshot {
        table: table.to_string(),
        family: family.to_string(),
        destination: destination.to_string(),
        next_hops: next_hops.iter().map(|nh| nh.to_string()).collect(),
        preference,
        ..Default::default()
    }
}

fn cluster_terminal(family: &str, table: &str, destination: &str) -> RouteSnapshot {
    RouteSnapshot {
        discard: true,
        cluster_terminal: true,
        preference: 200,
        ..route(family, table, destination, &[], 200)
    }
}

fn neighbor(interface: &str, ifindex: i32, family: &str, ip: &str) -> NeighborSnapshot {
    NeighborSnapshot {
        interface: interface.to_string(),
        ifindex,
        family: family.to_string(),
        ip: ip.to_string(),
        mac: "00:11:22:33:44:66".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
        ..Default::default()
    }
}

/// The split-node base: WAN unit peer-owned, gateways emitted bare (the Go
/// shape for `next-hop <gw>`), so nothing lends the WAN gateway an egress
/// except the peer-owned binding.
fn split_node_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    for route in &mut snapshot.routes {
        for nh in &mut route.next_hops {
            if nh.starts_with("172.16.80.1") {
                *nh = "172.16.80.1".to_string();
            } else if nh.starts_with("2001:559:8585:80::1") {
                *nh = "2001:559:8585:80::1".to_string();
            }
        }
    }
    for iface in &mut snapshot.interfaces {
        if iface.name == "reth0.80" {
            iface.connected_rg_peer_owned = true;
        }
    }
    snapshot
}

fn find_route_v4<'a>(state: &'a ForwardingState, table: &str, dst: &str) -> &'a RouteEntryV4 {
    let net: PrefixV4 = PrefixV4::from_net(dst.parse().expect("v4 prefix"));
    state
        .routes_v4
        .get(table)
        .and_then(|routes| routes.iter().find(|r| r.prefix == net))
        .unwrap_or_else(|| panic!("FIXTURE: {table} has no {dst} row"))
}

fn find_route_v6<'a>(state: &'a ForwardingState, table: &str, dst: &str) -> &'a RouteEntryV6 {
    let net: PrefixV6 = PrefixV6::from_net(dst.parse().expect("v6 prefix"));
    state
        .routes_v6
        .get(table)
        .and_then(|routes| routes.iter().find(|r| r.prefix == net))
        .unwrap_or_else(|| panic!("FIXTURE: {table} has no {dst} row"))
}

/// #18517 review LOW (both seats): the binding must only ever bind a
/// PEER-OWNED connected row, scoped by that row's OWN table. The by-ifindex
/// ledger the binding used to consult cannot promise either: it merges every
/// row sharing an ifindex under the ONE routing instance that first claimed
/// it (`ifindex_to_routing_instance`). Fixture: ifindex 40 carries a
/// routing-domain member row in `tenant-y` (10.88.0.1/24) and a zero-domain
/// row in the default instance (10.77.0.1/24); neither is peer-owned. The
/// member claims the ifindex, so the ledger shows 10.77.0.0/24 to
/// `tenant-y.inet.0` (the FIXTURE assertion proves that divergence is
/// present). A `tenant-y` static via 10.77.0.254 must NOT bind ifindex 40:
/// that prefix belongs to the default instance (#4446 cross-VRF wrong
/// egress). Also pins the partition the binding relies on: a row is in
/// `connected_v*_peer_owned` exactly when it is withheld from transit.
/// FAIL-ON-REVERT: bind through `connected_lpm_ifindex_v4/v6` (the ledger)
/// again and the tenant static's member binds ifindex 40 in both families.
#[test]
fn bare_gateway_never_binds_a_non_peer_owned_ledger_row_18517() {
    let mut snapshot = split_node_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/5.0".to_string(),
        zone: "lan".to_string(),
        routing_instance: "tenant-y".to_string(),
        routing_domain: 7,
        linux_name: "ge-0-0-5".to_string(),
        ifindex: 40,
        hardware_addr: "02:bf:72:05:00:01".to_string(),
        addresses: vec![address("inet", "10.88.0.1/24"), address("inet6", "2001:db8:88::1/64")],
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/5".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-5".to_string(),
        ifindex: 40,
        hardware_addr: "02:bf:72:05:00:01".to_string(),
        addresses: vec![address("inet", "10.77.0.1/24"), address("inet6", "2001:db8:77::1/64")],
        ..Default::default()
    });
    snapshot
        .routes
        .push(route("inet", "tenant-y.inet.0", "10.99.0.0/16", &["10.77.0.254"], 5));
    snapshot.routes.push(route(
        "inet6",
        "tenant-y.inet6.0",
        "2001:db8:99::/48",
        &["2001:db8:77::254"],
        5,
    ));
    let state = build_forwarding_state(&snapshot);

    // FIXTURE: the ledger really does cover the default-instance gateway
    // from tenant-y's table, so the cell sits on the divergence it guards.
    let gw4 = Ipv4Addr::new(10, 77, 0, 254);
    let gw6: Ipv6Addr = "2001:db8:77::254".parse().unwrap();
    assert_eq!(connected_lpm_ifindex_v4(&state, gw4, "tenant-y.inet.0"), 40, "FIXTURE: v4 ledger divergence");
    assert_eq!(connected_lpm_ifindex_v6(&state, gw6, "tenant-y.inet6.0"), 40, "FIXTURE: v6 ledger divergence");

    let v4 = find_route_v4(&state, "tenant-y.inet.0", "10.99.0.0/16");
    assert!(
        v4.next_hops.iter().all(|nh| nh.ifindex != 40),
        "a tenant-y static must not bind the default instance's non-peer-owned prefix: {:?}",
        v4.next_hops
    );
    let v6 = find_route_v6(&state, "tenant-y.inet6.0", "2001:db8:99::/48");
    assert!(
        v6.next_hops.iter().all(|nh| nh.ifindex != 40),
        "a tenant-y v6 static must not bind the default instance's non-peer-owned prefix: {:?}",
        v6.next_hops
    );

    // The partition: peer-owned rows are exactly reth0.80's, each with its
    // own table, and none of them is also a transit row.
    let peer4: Vec<(i32, &str)> = state
        .connected_v4_peer_owned
        .iter()
        .map(|row| (row.ifindex, row.table.as_str()))
        .collect();
    let peer6: Vec<(i32, &str)> = state
        .connected_v6_peer_owned
        .iter()
        .map(|row| (row.ifindex, row.table.as_str()))
        .collect();
    assert_eq!(peer4, vec![(12, "inet.0")]);
    assert_eq!(peer6, vec![(12, "inet6.0")]);
    assert!(state.connected_v4.iter().all(|row| row.ifindex != 12));
    assert!(state.connected_v6.iter().all(|row| row.ifindex != 12));
}

/// #18517 review MINOR (dataplane seat): the #15917 gateway-owner arm of
/// `select_source_ifindex_v4/v6` lost its pin when the bare-gateway shape
/// started binding at FIB build. It is still reachable: an EXPLICIT-interface
/// member (`gw@iface`, Go's `qualified-next-hop <gw> interface <iface>`)
/// whose interface fails table resolution (`explicit_ifindex_in_route_table`:
/// here `reth2.0` is in the `tenant-x` VRF while the route is in `inet.0`)
/// stays at ifindex 0, the cluster terminal is selected, and the terminal's
/// would-be egress comes only from the gateway's connected owner in the
/// lookup's table. The gateway is covered in BOTH tables by /24s, and the
/// tenant ifindex (9) is below the WAN's (12), so an attribution that lost
/// its table scope tie-breaks to the tenant.
/// FAIL-ON-REVERT: `let owner = 0;` in either family's gateway-owner arm
/// leaves `source_ifindex` 0 for that family (plain DiscardRoute, no
/// redirect); dropping `instance_owns_table_*` from the ledger kernel
/// attributes it to 9.
#[test]
fn terminal_gateway_owner_reached_by_out_of_table_explicit_member_18517() {
    let mut snapshot = split_node_snapshot();
    for route in &mut snapshot.routes {
        route.preference = 5;
        for nh in &mut route.next_hops {
            if nh == "172.16.80.1" {
                *nh = "172.16.80.1@reth2.0".to_string();
            } else if nh == "2001:559:8585:80::1" {
                *nh = "2001:559:8585:80::1@reth2.0".to_string();
            }
        }
    }
    snapshot.zones.push(ZoneSnapshot {
        name: "dmz2".to_string(),
        id: 9,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["any-service".to_string()],
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".to_string(),
        zone: "dmz2".to_string(),
        routing_instance: "tenant-x".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        ifindex: 9,
        redundancy_group: 3,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:02:00:01".to_string(),
        addresses: vec![address("inet", "172.16.80.1/24"), address("inet6", "2001:559:8585:80::1/64")],
        ..Default::default()
    });
    snapshot.routes.push(cluster_terminal("inet", "inet.0", "0.0.0.0/0"));
    snapshot.routes.push(cluster_terminal("inet6", "inet6.0", "::/0"));
    let state = build_forwarding_state(&snapshot);

    // FIXTURE: the explicit member really failed table resolution, so the
    // lookup can only reach the terminal (and the gateway-owner arm).
    let v4 = find_route_v4(&state, "inet.0", "0.0.0.0/0");
    let v4_static = state.routes_v4["inet.0"]
        .iter()
        .find(|r| r.prefix == v4.prefix && !r.discard)
        .expect("FIXTURE: v4 static default");
    assert!(
        v4_static.next_hops.iter().all(|nh| nh.ifindex == 0),
        "FIXTURE: the out-of-table explicit member must stay unbound: {:?}",
        v4_static.next_hops
    );
    let v6 = find_route_v6(&state, "inet6.0", "::/0");
    let v6_static = state.routes_v6["inet6.0"]
        .iter()
        .find(|r| r.prefix == v6.prefix && !r.discard)
        .expect("FIXTURE: v6 static default");
    assert!(
        v6_static.next_hops.iter().all(|nh| nh.ifindex == 0),
        "FIXTURE: the out-of-table explicit v6 member must stay unbound: {:?}",
        v6_static.next_hops
    );

    let ha = ha_map(&[(1, false), (3, false)]);
    for dst in [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    ] {
        let raw = lookup_forwarding_resolution(&state, dst).resolution;
        assert_eq!(
            raw.disposition,
            ForwardingDisposition::ClusterTerminalHAInactive,
            "{dst}: the unbound explicit member must leave the cluster terminal selected: {raw:?}"
        );
        assert_eq!(
            raw.source_ifindex, 12,
            "{dst}: the terminal's would-be egress must be the gateway's owner in inet.0 (12), not the tenant's (9) or none (0)"
        );
        let blocked = enforce_ha_resolution(&state, &ha, raw);
        assert_eq!(
            redirect_via_fabric_if_needed(&state, blocked, 24, None).disposition,
            ForwardingDisposition::FabricRedirect,
            "{dst}: the attributed peer-owned egress must fabric-redirect"
        );
    }
}

/// #18517 review LOW (both seats): an ECMP static with one member via the
/// peer-owned WAN gateway and one via a local LAN gateway. Lookup liveness
/// for a gateway member is an installed neighbor, so the split depends on
/// neighbor state, not on config alone:
/// * no neighbor for the WAN gateway: the peer-owned member is never live,
///   and every flow takes the local member;
/// * both neighbors present: flows hash across both members; the peer-owned
///   member's flows demote to HAInactive and cross the fabric, the local
///   member's forward out the LAN.
/// FAIL-ON-REVERT: drop either family's binding and the peer-owned member is
/// stranded at ifindex 0, so the both-neighbors sweep never reaches the
/// fabric for that family.
#[test]
fn ecmp_static_with_one_peer_owned_member_18517() {
    let build = |wan_neighbor: bool| {
        let mut snapshot = split_node_snapshot();
        if !wan_neighbor {
            snapshot.neighbors.retain(|n| n.ifindex != 12);
        }
        snapshot.neighbors.push(neighbor("ge-0-0-1", 24, "inet", "10.0.61.254"));
        snapshot
            .neighbors
            .push(neighbor("ge-0-0-1", 24, "inet6", "2001:559:8585:ef00::254"));
        snapshot.routes.push(route(
            "inet",
            "inet.0",
            "10.40.0.0/16",
            &["172.16.80.1", "10.0.61.254"],
            5,
        ));
        snapshot.routes.push(route(
            "inet6",
            "inet6.0",
            "2001:db8:40::/48",
            &["2001:559:8585:80::1", "2001:559:8585:ef00::254"],
            5,
        ));
        build_forwarding_state(&snapshot)
    };
    let ha = ha_map(&[(1, false), (2, true)]);
    let dsts = |v6: bool| -> Vec<IpAddr> {
        (1..=255u16)
            .map(|i| {
                if v6 {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x40, 0, 0, 0, i >> 4, i))
                } else {
                    IpAddr::V4(Ipv4Addr::new(10, 40, (i >> 4) as u8, i as u8))
                }
            })
            .collect()
    };
    for v6 in [false, true] {
        // No WAN neighbor: the peer-owned member is a non-live fallback only.
        let state = build(false);
        for dst in dsts(v6) {
            let raw = lookup_forwarding_resolution(&state, dst).resolution;
            let out = redirect_via_fabric_if_needed(&state, enforce_ha_resolution(&state, &ha, raw), 24, None);
            assert_eq!(
                (out.disposition, out.egress_ifindex),
                (ForwardingDisposition::ForwardCandidate, 24),
                "{dst}: with no WAN neighbor every flow must take the local member: {raw:?}"
            );
        }
        // Both neighbors: per-member disposition, both members carry flows.
        let state = build(true);
        let (mut fabric, mut local) = (0, 0);
        for dst in dsts(v6) {
            let raw = lookup_forwarding_resolution(&state, dst).resolution;
            let blocked = enforce_ha_resolution(&state, &ha, raw);
            let out = redirect_via_fabric_if_needed(&state, blocked, 24, None);
            match raw.egress_ifindex {
                12 => {
                    assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive, "{dst}");
                    assert_eq!(out.disposition, ForwardingDisposition::FabricRedirect, "{dst}");
                    fabric += 1;
                }
                24 => {
                    assert_eq!(out.disposition, ForwardingDisposition::ForwardCandidate, "{dst}");
                    local += 1;
                }
                other => panic!("{dst}: ECMP member must be 12 or 24, got {other}: {raw:?}"),
            }
        }
        assert!(
            fabric > 0 && local > 0,
            "v6={v6}: both members must carry flows when both neighbors are live (fabric {fabric}, local {local})"
        );
    }
}

/// #18517 review LOW (both seats): a static in a tenant VRF binds ITS OWN
/// peer-owned RETH, and only that. `reth2.0` (ifindex 9, RG3, `tenant-x`)
/// carries 172.16.90.1/24 and 2001:db8:90::1/64. The tenant default via
/// 172.16.90.254 binds 9, HA-demotes while RG3 is peer-owned and crosses the
/// fabric, and forwards locally once RG3 is local. The scoping control: a
/// tenant static whose gateway (172.16.80.1) only the DEFAULT table's
/// peer-owned `reth0.80` covers must stay unbound in the tenant table.
/// FAIL-ON-REVERT: drop either family's binding and that family's tenant
/// default is stranded at ifindex 0; drop the `entry.table == table` filter
/// in `peer_owned_connected_target_v4/v6` and the control binds ifindex 12.
#[test]
fn tenant_vrf_static_binds_its_own_peer_owned_reth_18517() {
    let mut snapshot = split_node_snapshot();
    snapshot.zones.push(ZoneSnapshot {
        name: "dmz2".to_string(),
        id: 9,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["any-service".to_string()],
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".to_string(),
        zone: "dmz2".to_string(),
        routing_instance: "tenant-x".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        ifindex: 9,
        redundancy_group: 3,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:02:00:01".to_string(),
        addresses: vec![address("inet", "172.16.90.1/24"), address("inet6", "2001:db8:90::1/64")],
        ..Default::default()
    });
    snapshot
        .routes
        .push(route("inet", "tenant-x.inet.0", "0.0.0.0/0", &["172.16.90.254"], 5));
    snapshot
        .routes
        .push(route("inet6", "tenant-x.inet6.0", "::/0", &["2001:db8:90::254"], 5));
    snapshot
        .routes
        .push(route("inet", "tenant-x.inet.0", "10.60.0.0/16", &["172.16.80.1"], 5));
    snapshot.routes.push(route(
        "inet6",
        "tenant-x.inet6.0",
        "2001:db8:60::/48",
        &["2001:559:8585:80::1"],
        5,
    ));
    let state = build_forwarding_state(&snapshot);
    let dyn_neighbors = Arc::new(ShardedNeighborMap::new());
    let split = ha_map(&[(1, false), (3, false)]);
    let owner = ha_map(&[(1, false), (3, true)]);
    for (dst, table) in [
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "tenant-x.inet.0"),
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            "tenant-x.inet6.0",
        ),
    ] {
        let raw = lookup_forwarding_resolution_in_table_with_dynamic(&state, &dyn_neighbors, dst, Some(table))
            .resolution;
        assert_eq!(raw.egress_ifindex, 9, "{dst} in {table}: the tenant static must bind its own RETH: {raw:?}");
        let blocked = enforce_ha_resolution(&state, &split, raw);
        assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive, "{dst} in {table}");
        assert_eq!(
            redirect_via_fabric_if_needed(&state, blocked, 24, None).disposition,
            ForwardingDisposition::FabricRedirect,
            "{dst} in {table}: the peer-owned tenant RETH must fabric-redirect"
        );
        let local = enforce_ha_resolution(&state, &owner, raw);
        assert!(
            matches!(
                local.disposition,
                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
            ),
            "{dst} in {table}: a locally-owned RG3 must forward out the tenant RETH, got {:?}",
            local.disposition
        );
    }
    // Scoping control: the default table's peer-owned prefix is invisible to
    // a tenant static.
    let v4 = find_route_v4(&state, "tenant-x.inet.0", "10.60.0.0/16");
    assert!(
        v4.next_hops.iter().all(|nh| nh.ifindex != 12),
        "a tenant static must not bind the default table's peer-owned RETH: {:?}",
        v4.next_hops
    );
    let v6 = find_route_v6(&state, "tenant-x.inet6.0", "2001:db8:60::/48");
    assert!(
        v6.next_hops.iter().all(|nh| nh.ifindex != 12),
        "a tenant v6 static must not bind the default table's peer-owned RETH: {:?}",
        v6.next_hops
    );
}

/// #18517 review MINOR (HA seat): on the split node the configured static
/// via the peer-owned WAN gateway replaces a same-prefix learned route via a
/// LOCAL interface (Go suppresses the twin; its cell is
/// `TestSplitNodeStaticReplacesLocalLearnedTwin18517`). The helper therefore
/// holds only the static, and the flow's fate rides on the fabric:
/// * fabric configured and up: FabricRedirect to the owner;
/// * fabric configured but its link down: still FabricRedirect, into the
///   down link (#4082 fail-open fallback), so the flow is lost there;
/// * no resolvable fabric: the HAInactive demotion stands and the split node
///   drops the flow, where master forwarded it out the local learned route.
/// FAIL-ON-REVERT: drop the #4082 fail-open `or_else` in
/// `resolve_fabric_redirect_from_list` and the down-link case returns
/// HAInactive.
#[test]
fn split_node_static_fate_follows_the_fabric_18517() {
    let build = |fabric: &str| {
        let mut snapshot = split_node_snapshot();
        snapshot.neighbors.push(neighbor("ge-0-0-1", 24, "inet", "10.0.61.254"));
        snapshot
            .routes
            .push(route("inet", "inet.0", "10.50.0.0/16", &["172.16.80.1"], 5));
        snapshot.routes.push(route(
            "inet6",
            "inet6.0",
            "2001:db8:50::/48",
            &["2001:559:8585:80::1"],
            5,
        ));
        match fabric {
            "up" => {}
            "down" => snapshot.fabrics[0].up = false,
            "absent" => snapshot.fabrics.clear(),
            other => unreachable!("{other}"),
        }
        build_forwarding_state(&snapshot)
    };
    let ha = ha_map(&[(1, false), (2, true)]);
    for (fabric, want) in [
        ("up", ForwardingDisposition::FabricRedirect),
        ("down", ForwardingDisposition::FabricRedirect),
        ("absent", ForwardingDisposition::HAInactive),
    ] {
        let state = build(fabric);
        for dst in [
            IpAddr::V4(Ipv4Addr::new(10, 50, 0, 5)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x50, 0, 0, 0, 0, 5)),
        ] {
            let raw = lookup_forwarding_resolution(&state, dst).resolution;
            assert_eq!(raw.egress_ifindex, 12, "fabric {fabric}, {dst}: {raw:?}");
            let out = redirect_via_fabric_if_needed(&state, enforce_ha_resolution(&state, &ha, raw), 24, None);
            assert_eq!(out.disposition, want, "fabric {fabric}, {dst}: {out:?}");
        }
    }
}
