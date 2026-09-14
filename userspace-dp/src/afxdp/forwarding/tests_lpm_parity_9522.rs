//! #9522 Phase 0: selected lookup-semantic coverage for the route FIB.
//!
//! Parity corpus pinning what today's linear-scan lookup DECIDES, so a future
//! LPM cutover (or any table-growth fix) proves equivalence against cells rather
//! than prose. Test-only: this file + the two-line `mod.rs` wiring are the entire
//! change; no production file is touched.
//!
//! Construction is snapshot-build EXCLUSIVELY (`build_forwarding_state`), so every
//! cell exercises the production sort path — never a copied comparator. Gateway
//! next-hops resolve through the #4446 table-scoped connected inference; the
//! complementary gates live at `forwarding_build/tests.rs:3315+` (#6568 ingest),
//! `:3525+` (gateway inference) and `tests.rs:2746` (IPv6 canonical table), cited
//! here rather than duplicated.
//!
//! Fixture hygiene (reviewer-mandated): positive DISTINCT egress ifindices, tunnel IDs
//! zero, EMPTY static and dynamic neighbor maps, probe ranges avoid local addresses
//! (else `LocalDelivery`). Winner is read as `(disposition, egress_ifindex)` —
//! `MissingNeighbor` still attributes the winning route's egress, so no neighbor
//! seeding is needed and none is performed.

use super::super::forwarding_build::*;
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// lan `ge-0/0/0` (ifindex 11, 10.99.0.1/24 + 2001:db8:99::1/64) and wan `ge-0/0/1`
/// (ifindex 12, 192.0.2.10/24 + 2001:db8:98::1/64). Connected: 10.99.0.0/24 (11),
/// 192.0.2.0/24 (12), and the v6 /64s. Gateways resolving per #4446: 10.99.0.2 → 11,
/// 192.0.2.1 → 12, 2001:db8:99::2 → 11, 2001:db8:98::2 → 12. None of the gateway
/// addresses is a local address, so probes never hit `LocalDelivery` for that reason.
fn base_snapshot() -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/0".into(),
                ifindex: 11,
                hardware_addr: "02:00:00:00:00:0b".into(),
                addresses: vec![
                    crate::InterfaceAddressSnapshot {
                        family: "inet".into(),
                        address: "10.99.0.1/24".into(),
                        ..Default::default()
                    },
                    crate::InterfaceAddressSnapshot {
                        family: "inet6".into(),
                        address: "2001:db8:99::1/64".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/1".into(),
                ifindex: 12,
                hardware_addr: "02:00:00:00:00:0c".into(),
                addresses: vec![
                    crate::InterfaceAddressSnapshot {
                        family: "inet".into(),
                        address: "192.0.2.10/24".into(),
                        ..Default::default()
                    },
                    crate::InterfaceAddressSnapshot {
                        family: "inet6".into(),
                        address: "2001:db8:98::1/64".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

fn v4_route(destination: &str, next_hops: Vec<&str>, preference: i32) -> crate::RouteSnapshot {
    crate::RouteSnapshot {
        table: "inet.0".into(),
        family: "inet".into(),
        destination: destination.into(),
        next_hops: next_hops.into_iter().map(str::to_string).collect(),
        preference,
        ..Default::default()
    }
}

fn v6_route(destination: &str, next_hops: Vec<&str>, preference: i32) -> crate::RouteSnapshot {
    crate::RouteSnapshot {
        table: "inet6.0".into(),
        family: "inet6".into(),
        destination: destination.into(),
        next_hops: next_hops.into_iter().map(str::to_string).collect(),
        preference,
        ..Default::default()
    }
}

fn state_with(routes: Vec<crate::RouteSnapshot>) -> ForwardingState {
    let mut snapshot = base_snapshot();
    snapshot.routes = routes;
    build_forwarding_state(&snapshot)
}

fn empty_neighbors() -> Arc<ShardedNeighborMap> {
    Arc::new(ShardedNeighborMap::new())
}

fn resolve_v4(state: &ForwardingState, dst: Ipv4Addr) -> ForwardingResolution {
    lookup_forwarding_resolution_in_table_with_dynamic(
        state,
        &empty_neighbors(),
        IpAddr::V4(dst),
        Some("inet.0"),
    )
}

fn resolve_v6(state: &ForwardingState, dst: Ipv6Addr) -> ForwardingResolution {
    lookup_forwarding_resolution_in_table_with_dynamic(
        state,
        &empty_neighbors(),
        IpAddr::V6(dst),
        Some("inet6.0"),
    )
}

/// Explicit-hash ECMP entry point (`inner_ecmp`, documented exception to the plain
/// wrapper: the plain wrapper threads `ecmp_flow_hash = None`, i.e. destination
/// hashing only). The hash is used VERBATIM as the spread value.
fn resolve_ecmp_v4(state: &ForwardingState, dst: Ipv4Addr, hash: u64) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        None,
        IpAddr::V4(dst),
        Some("inet.0"),
        Some(hash),
    )
}

// ---------------------------------------------------------------------------
// v4 longest-match / preference / stability
// ---------------------------------------------------------------------------

/// NOVEL: no longest-prefix test exists in tree. A /24 with a far worse
/// preference still beats a /8.
///
/// FAIL-ON-REVERT: route the tie-break preference-first and 10.1.2.3 resolves
/// via 192.0.2.1 (egress 12) instead of 10.99.0.2 (egress 11).
#[test]
fn longest_match_beats_better_preference_9522() {
    let state = state_with(vec![
        v4_route("10.0.0.0/8", vec!["192.0.2.1"], 5),
        v4_route("10.1.0.0/16", vec!["10.99.0.2"], 200),
    ]);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(
        r.egress_ifindex, 11,
        "longest match (/16 via 10.99.0.2) must win over the better-preference /8"
    );
}

/// Deliberate RE-HOMING of #2390 (`tests.rs:4679`) into the unified parity
/// contract — stated as re-homing, not novel coverage.
#[test]
fn same_prefix_lowest_preference_wins_9522() {
    let state = state_with(vec![
        v4_route("172.16.0.0/12", vec!["192.0.2.1"], 10),
        v4_route("172.16.0.0/12", vec!["10.99.0.2"], 5),
        v4_route("172.16.0.0/12", vec!["192.0.2.1"], 7),
    ]);
    let r = resolve_v4(&state, Ipv4Addr::new(172, 16, 5, 5));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 11, "lowest preference (5) must win");
}

/// NOVEL: equal (prefix, preference) keeps insertion order (stable sort +
/// first match). Listed first: 192.0.2.1 (egress 12).
#[test]
fn equal_preference_keeps_insertion_order_9522() {
    let state = state_with(vec![
        v4_route("198.51.100.0/24", vec!["192.0.2.1"], 5),
        v4_route("198.51.100.0/24", vec!["10.99.0.2"], 5),
    ]);
    let r = resolve_v4(&state, Ipv4Addr::new(198, 51, 100, 7));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(
        r.egress_ifindex, 12,
        "stable sort must keep the first-inserted equal route winning"
    );
}

/// The HONEST direction of the stability property: reversing the tie changes
/// the winner. A corpus claiming order-independence WITH ties would be false
/// (stable sort + first match). Revert stability (e.g. unstable sort) and this
/// pair goes nondeterministic rather than cleanly swapped.
#[test]
fn reversed_tie_changes_winner_9522() {
    let state = state_with(vec![
        v4_route("198.51.100.0/24", vec!["10.99.0.2"], 5),
        v4_route("198.51.100.0/24", vec!["192.0.2.1"], 5),
    ]);
    let r = resolve_v4(&state, Ipv4Addr::new(198, 51, 100, 7));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(
        r.egress_ifindex, 11,
        "reversed insertion order must reverse the tied winner"
    );
}

/// Order-independence holds ONLY for distinct (prefix, preference) keys — the
/// same set built in two snapshot orders resolves identically over a sweep
/// (this is the property a chunked transfer's sort-then-install relies on).
/// The 10/8 + 10.1/16 overlap is load-bearing: without prefix-length sorting,
/// forward insertion order finds the /8 first (egress 12) for 10.1.x.x probes.
#[test]
fn distinct_key_reassembly_order_independent_9522() {
    let forward = state_with(vec![
        v4_route("10.0.0.0/8", vec!["192.0.2.1"], 5),
        v4_route("10.1.0.0/16", vec!["10.99.0.2"], 5),
        v4_route("172.16.0.0/12", vec!["10.99.0.2"], 5),
    ]);
    let reversed = state_with(vec![
        v4_route("172.16.0.0/12", vec!["10.99.0.2"], 5),
        v4_route("10.1.0.0/16", vec!["10.99.0.2"], 5),
        v4_route("10.0.0.0/8", vec!["192.0.2.1"], 5),
    ]);
    // Expected winners pin the sort itself, not just cross-order equivalence:
    // the overlapping /16 must beat the /8 in BOTH orders.
    for (dst, expected_egress) in [
        (Ipv4Addr::new(10, 1, 2, 3), 11),
        (Ipv4Addr::new(10, 2, 2, 2), 12),
        (Ipv4Addr::new(172, 16, 5, 5), 11),
    ] {
        for (which, state) in [("forward", &forward), ("reversed", &reversed)] {
            let r = resolve_v4(state, dst);
            assert_eq!(
                r.disposition,
                ForwardingDisposition::MissingNeighbor,
                "{which} build must attribute (dst {dst})"
            );
            assert_eq!(
                r.egress_ifindex, expected_egress,
                "{which} build must route (dst {dst}) via the longest match"
            );
        }
    }
    // Cross-order equivalence sweep, including a miss in both builds.
    for octet in [1u8, 2, 3] {
        let probes = [
            Ipv4Addr::new(10, octet, 1, 1),
            Ipv4Addr::new(172, 16, octet, 5),
            Ipv4Addr::new(198, 51, 100, octet),
            Ipv4Addr::new(203, 0, 113, octet),
        ];
        for dst in probes {
            let a = resolve_v4(&forward, dst);
            let b = resolve_v4(&reversed, dst);
            assert_eq!(
                (a.disposition as u8, a.egress_ifindex),
                (b.disposition as u8, b.egress_ifindex),
                "distinct-key sets must resolve identically regardless of build order (dst {dst})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// v4 discard / next-table / NoRoute
// ---------------------------------------------------------------------------

/// A selected discard route never falls back to a less-specific ancestor.
#[test]
fn discard_never_falls_back_to_ancestor_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![
        v4_route("10.0.0.0/8", vec!["192.0.2.1"], 5),
        crate::RouteSnapshot {
            discard: true,
            ..v4_route("10.1.0.0/16", vec![], 5)
        },
    ];
    let state = build_forwarding_state(&snap);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(r.disposition, ForwardingDisposition::DiscardRoute);
    assert_eq!(r.egress_ifindex, 0);
}

/// LPM-novel angle only: a LONGER direct route beats a next-table route in the
/// same table. (Recursion/self-loop/cycle terminals already covered at
/// `tests.rs:2717,3071,3090,3123` — cited, not duplicated.)
#[test]
fn next_table_loses_longest_match_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![
        crate::RouteSnapshot {
            next_table: "other.inet.0".into(),
            ..v4_route("10.2.0.0/16", vec!["192.0.2.1"], 5)
        },
        v4_route("10.2.3.0/24", vec!["192.0.2.1"], 5),
    ];
    let state = build_forwarding_state(&snap);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 2, 3, 4));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(
        r.egress_ifindex, 12,
        "the longer direct /24 must win over the next-table /16"
    );
}

/// Unresolvable recursion terminates as `NextTableUnsupported` — and, per the
/// review constraint, this cell claims terminal disposition ONLY (a self-loop
/// and depth exhaustion produce the same asserted pair, so no
/// early-cycle-detection claim is made).
#[test]
fn next_table_unresolvable_chain_is_unsupported_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![crate::RouteSnapshot {
        next_table: "inet.0".into(),
        ..v4_route("10.5.0.0/16", vec![], 5)
    }];
    let state = build_forwarding_state(&snap);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 5, 1, 1));
    assert_eq!(
        r.disposition,
        ForwardingDisposition::NextTableUnsupported,
        "a next-table chain that cannot resolve must terminate, not recurse forever"
    );
}

/// A next-table reference to a MISSING target table terminates as `(NoRoute,
/// 0)` (the recursion arm finds no table) rather than recursing forever.
#[test]
fn next_table_missing_target_is_noroute_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![crate::RouteSnapshot {
        next_table: "missing.inet.0".into(),
        ..v4_route("10.6.0.0/16", vec![], 5)
    }];
    let state = build_forwarding_state(&snap);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 6, 1, 1));
    assert_eq!(r.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(r.egress_ifindex, 0);
}

/// No STATIC routes (connected /24s+/64s from the fixture interfaces are still
/// present) ⇒ `(NoRoute, 0)` for an unconnected probe.
#[test]
fn noroute_no_static_routes_9522() {
    let state = state_with(vec![]);
    let r = resolve_v4(&state, Ipv4Addr::new(203, 0, 113, 9));
    assert_eq!(r.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(r.egress_ifindex, 0);
}

/// A miss inside a POPULATED table is also `(NoRoute, 0)` — no-static-routes
/// coverage alone does not pin the populated-table miss path.
#[test]
fn noroute_outside_prefix_populated_table_9522() {
    let state = state_with(vec![v4_route("10.0.0.0/8", vec!["192.0.2.1"], 5)]);
    let r = resolve_v4(&state, Ipv4Addr::new(203, 0, 113, 9));
    assert_eq!(r.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(r.egress_ifindex, 0);
}

// ---------------------------------------------------------------------------
// v4 connected composition (three prefix-length relations) + table scoping
// ---------------------------------------------------------------------------

/// Connected /24 beats a SHORTER static /16.
#[test]
fn connected_longer_than_route_wins_9522() {
    let state = state_with(vec![v4_route("192.0.0.0/16", vec!["10.99.0.2"], 5)]);
    let r = resolve_v4(&state, Ipv4Addr::new(192, 0, 2, 50));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 12, "longer connected /24 must win");
}

/// Connected /24 beats an EQUAL static /24 regardless of static preference.
#[test]
fn connected_equal_to_route_wins_9522() {
    let state = state_with(vec![v4_route("192.0.2.0/24", vec!["10.99.0.2"], 1)]);
    let r = resolve_v4(&state, Ipv4Addr::new(192, 0, 2, 50));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(
        r.egress_ifindex, 12,
        "equal-length connected must win over the static, preference notwithstanding"
    );
}

/// Connected /24 LOSES to a longer static /25.
#[test]
fn connected_shorter_than_route_loses_9522() {
    let state = state_with(vec![v4_route("10.99.0.128/25", vec!["192.0.2.1"], 5)]);
    let r = resolve_v4(&state, Ipv4Addr::new(10, 99, 0, 130));
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 12, "longer static /25 must win");
}

/// A connected prefix owned by another routing instance never matches
/// (table-scoped connected, #2388). Separate snapshot: red (101) + blue (202)
/// share 10.99.1.0/24.
#[test]
fn connected_is_table_scoped_9522() {
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "ge-0/0/3".into(),
                ifindex: 101,
                routing_instance: "red".into(),
                hardware_addr: "02:00:00:00:00:65".into(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "10.99.1.1/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/4".into(),
                ifindex: 202,
                routing_instance: "blue".into(),
                hardware_addr: "02:00:00:00:00:ca".into(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "10.99.1.2/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let neighbors = empty_neighbors();
    let red = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 99, 1, 50)),
        Some("red.inet.0"),
    );
    let blue = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(Ipv4Addr::new(10, 99, 1, 50)),
        Some("blue.inet.0"),
    );
    assert_eq!(red.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(blue.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(red.egress_ifindex, 101, "red lookup must use red's interface");
    assert_eq!(blue.egress_ifindex, 202, "blue lookup must use blue's interface");
}

// ---------------------------------------------------------------------------
// v4 ECMP (explicit-hash entry point, exact members)
// ---------------------------------------------------------------------------

/// Exact member selection at supplied hashes (documented exception: the
/// `inner_ecmp` entry — the plain wrapper threads `None`, i.e. destination
/// hashing only). Two gateways ⇒ egresses 11, 12; hash selects `members[h % 2]`
/// identically under the live and all-dead arms (shared liveness state), so the
/// assertions hold under both.
#[test]
fn ecmp_exact_member_at_explicit_hash_9522() {
    let state = state_with(vec![v4_route(
        "203.0.113.0/24",
        vec!["10.99.0.2", "192.0.2.1"],
        5,
    )]);
    let dst = Ipv4Addr::new(203, 0, 113, 7);
    let r0 = resolve_ecmp_v4(&state, dst, 0);
    let r1 = resolve_ecmp_v4(&state, dst, 1);
    assert_eq!(r0.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r1.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r0.egress_ifindex, 11);
    assert_eq!(r1.egress_ifindex, 12);
}

/// Reordered authored slice swaps the winners — selection is authored-order
/// modulo liveness, not prefix- or ifindex-ordered.
#[test]
fn ecmp_reordered_slice_swaps_winners_9522() {
    let state = state_with(vec![v4_route(
        "203.0.113.0/24",
        vec!["192.0.2.1", "10.99.0.2"],
        5,
    )]);
    let dst = Ipv4Addr::new(203, 0, 113, 7);
    let r0 = resolve_ecmp_v4(&state, dst, 0);
    let r1 = resolve_ecmp_v4(&state, dst, 1);
    assert_eq!(r0.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r1.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r0.egress_ifindex, 12);
    assert_eq!(r1.egress_ifindex, 11);
}

/// Sweep containment + per-destination repeatability via the PLAIN wrapper
/// (destination hashing): every winner ∈ the authored slice; same dst twice ⇒
/// same winner. NO exact dst→member map is pinned (bitmask internals may evolve
/// without changing selection — GLM F6).
#[test]
fn ecmp_sweep_contained_and_repeatable_9522() {
    let state = state_with(vec![v4_route(
        "203.0.113.0/24",
        vec!["10.99.0.2", "192.0.2.1"],
        5,
    )]);
    for last in 1u8..=16 {
        let dst = Ipv4Addr::new(203, 0, 113, last);
        let a = resolve_v4(&state, dst);
        let b = resolve_v4(&state, dst);
        assert_eq!(
            a.disposition,
            ForwardingDisposition::MissingNeighbor,
            "sweep winners attribute via MissingNeighbor (dst {dst})"
        );
        assert!(
            a.egress_ifindex == 11 || a.egress_ifindex == 12,
            "every ECMP winner must come from the authored slice (dst {dst})"
        );
        assert_eq!(
            (a.disposition as u8, a.egress_ifindex),
            (b.disposition as u8, b.egress_ifindex),
            "same destination must reselect identically (dst {dst})"
        );
    }
}

// ---------------------------------------------------------------------------
// v6 twins (the v6 preference tie-break has NO tree coverage — NOVEL)
// ---------------------------------------------------------------------------

#[test]
fn v6_longest_match_beats_better_preference_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![
        v6_route("2001:db8::/32", vec!["2001:db8:98::2"], 5),
        v6_route("2001:db8:100::/48", vec!["2001:db8:99::2"], 200),
    ];
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:100::5".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 11, "longest v6 match must win over preference");
}

#[test]
fn v6_same_prefix_lowest_preference_wins_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![
        v6_route("2001:db8:200::/48", vec!["2001:db8:98::2"], 10),
        v6_route("2001:db8:200::/48", vec!["2001:db8:99::2"], 5),
    ];
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:200::7".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 11, "lowest v6 preference must win");
}

#[test]
fn v6_connected_longer_than_route_wins_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![v6_route("2001:db8::/32", vec!["2001:db8:99::2"], 5)];
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:98::50".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 12, "longer connected v6 /64 must win");
}

#[test]
fn v6_connected_equal_to_route_wins_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![v6_route("2001:db8:98::/64", vec!["2001:db8:99::2"], 1)];
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:98::50".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 12, "equal-length connected v6 must win");
}

#[test]
fn v6_connected_shorter_than_route_loses_9522() {
    let mut snap = base_snapshot();
    snap.routes = vec![v6_route("2001:db8:99::/80", vec!["2001:db8:98::2"], 5)];
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:99::130".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(r.egress_ifindex, 12, "longer static v6 /80 must win");
}

#[test]
fn v6_noroute_no_static_routes_9522() {
    let snap = base_snapshot();
    let state = build_forwarding_state(&snap);
    let r = resolve_v6(&state, "2001:db8:100::9".parse().unwrap());
    assert_eq!(r.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(r.egress_ifindex, 0);
}

// #6568 ingest fail-closed + IPv6 canonical-table normalization are cited,
// not duplicated: `forwarding_build/tests.rs:3315-3367` (fail-closed +
// anti-over-reject) and `forwarding/tests.rs:2746` (v6 routes emitted in
// `inet` normalize into `inet6.0`). A trie cutover must keep both green;
// no new cell here duplicates them.
