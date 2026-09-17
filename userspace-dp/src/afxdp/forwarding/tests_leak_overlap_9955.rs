//! #9955 — the kernel two-stage leak-resolution contract.
//!
//! `next-table` / rib-group leaks are kernel policy-routing rules, not
//! ordinary routes in one shared userspace LPM list:
//!
//!   * stage 1 scans matching leak rules by ascending `rule_priority`;
//!   * a target-table miss falls through to the next rule;
//!   * stage 2 performs ordinary per-table longest-prefix matching.
//!
//! The Go snapshot producer carries the kernel priority through
//! `RouteSnapshot.rule_priority`. The Rust builder partitions next-table rows
//! into a priority-ordered leak index and leaves only ordinary routes in each
//! table's LPM list. The target lookup runs stage 2 without restarting stage 1
//! from the selected table.
//!
//! These tests are fail-on-revert guards for all three measured divergences:
//! overlapping leak order, leak-versus-ordinary precedence, and fall-through
//! when a selected target table is empty. The generated cross-language corpus
//! adds IPv4/IPv6 coverage for the same oracle.

use super::super::forwarding_build::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot, ZoneSnapshot,
};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

/// One leak the operator authored: a prefix, the kernel rule priority it was
/// installed at, and the table it redirects into.
#[derive(Clone, Copy, Debug)]
struct Leak {
    prefix_len: u8,
    /// Kernel ip-rule priority. xpf installs next-table leaks in the 100-199
    /// band and rib-group per-prefix imports in 30000-30999
    /// (`pkg/routing/rules.go`), so a next-table leak ALWAYS precedes a
    /// rib-group import in the kernel regardless of prefix length.
    rule_priority: u32,
    /// Distinguishes which leak won: each target table routes the probe out a
    /// different ifindex.
    target: &'static str,
    egress_ifindex: i32,
    /// Third octet of this leak's own /24, so the interface address and the
    /// target table's next-hop agree. They must: the next-hop has to be
    /// on-subnet for the recursion to resolve to a forward candidate, and a
    /// fixture whose recursion silently fails would make every shape "agree" by
    /// resolving to nothing.
    subnet: u8,
}

const PROBE: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 5);

fn prefix_containing_probe(len: u8) -> String {
    // Every prefix below contains PROBE, which is what makes the shapes
    // OVERLAPPING — the whole point. Masking the probe rather than hand-writing
    // the prefixes keeps that true as the lengths vary.
    let bits = u32::from(PROBE);
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    };
    format!("{}/{}", Ipv4Addr::from(bits & mask), len)
}

fn snapshot_for(leaks: &[Leak]) -> crate::ConfigSnapshot {
    let mut routes = Vec::new();
    for leak in leaks {
        // The leak itself, in the main table.
        routes.push(RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: prefix_containing_probe(leak.prefix_len),
            next_hops: vec![],
            discard: false,
            next_table: format!("{}.inet.0", leak.target),
            preference: 0,
            rule_priority: leak.rule_priority,
        });
        // A route in the target table so the recursion resolves to something
        // distinguishable.
        routes.push(RouteSnapshot {
            table: format!("{}.inet.0", leak.target),
            family: "inet".to_string(),
            destination: "10.0.0.0/8".to_string(),
            next_hops: vec![format!(
                "172.16.{}.1@ge-0/0/{}.50",
                leak.subnet, leak.egress_ifindex
            )],
            discard: false,
            next_table: String::new(),
            preference: 0,
            rule_priority: 0,
        });
    }

    let interfaces = leaks
        .iter()
        .map(|leak| InterfaceSnapshot {
            name: format!("ge-0/0/{}.50", leak.egress_ifindex),
            zone: "wan".to_string(),
            linux_name: format!("ge-0-0-{}.50", leak.egress_ifindex),
            ifindex: leak.egress_ifindex,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: format!("172.16.{}.8/24", leak.subnet),
                scope: 0,
            }],
            ..Default::default()
        })
        .collect();

    // Each leak's next-hop needs a resolved neighbor, or the lookup stops at
    // NeighborMiss and every shape "agrees" by resolving to nothing — which is
    // exactly what the single-leak control caught on the first run.
    let neighbors = leaks
        .iter()
        .map(|leak| NeighborSnapshot {
            interface: format!("ge-0-0-{}.50", leak.egress_ifindex),
            ifindex: leak.egress_ifindex,
            family: "inet".to_string(),
            ip: format!("172.16.{}.1", leak.subnet),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
            ..Default::default()
        })
        .collect();

    super::super::test_fixtures::v5(crate::ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces,
        routes,
        neighbors,
        ..Default::default()
    })
}

/// What the KERNEL would pick: the lowest-numbered rule priority whose prefix
/// contains the probe. Every generated prefix contains the probe by
/// construction, so this reduces to "the lowest priority", which is exactly why
/// prefix length is irrelevant on that side.
fn kernel_choice(leaks: &[Leak]) -> &'static str {
    leaks
        .iter()
        .min_by_key(|l| l.rule_priority)
        .expect("at least one leak")
        .target
}

/// What the HELPER picks, by actually running the production build + lookup
/// rather than re-implementing its rule here — a re-implementation would agree
/// with itself and prove nothing.
fn helper_choice(leaks: &[Leak]) -> Option<&'static str> {
    let state = build_forwarding_state(&snapshot_for(leaks));
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(PROBE));
    if resolved.disposition != ForwardingDisposition::ForwardCandidate {
        // Not a divergence — a fixture that never resolved. Reported distinctly
        // so "the helper chose differently" is never confused with "the helper
        // chose nothing".
        eprintln!(
            "  fixture did not resolve: disposition={:?} for {} leak(s)",
            resolved.disposition,
            leaks.len()
        );
        return None;
    }
    leaks
        .iter()
        .find(|l| l.egress_ifindex == resolved.egress_ifindex)
        .map(|l| l.target)
}

/// THE DIFFERENTIAL. Generated over both orderings of (prefix length, priority)
/// so the two axes are separated: a shape where the more specific prefix is ALSO
/// the higher-priority rule cannot distinguish the algorithms, and a shape where
/// they disagree is the only one that can.
#[test]
fn leak_overlap_resolution_matches_the_kernel_9955() {
    // next-table band vs rib-group import band, per pkg/routing/rules.go.
    const NEXT_TABLE_PRIO: u32 = 150;
    const RIB_GROUP_PRIO: u32 = 30_500;

    let mut divergences = Vec::new();
    let mut agreements = 0usize;
    let mut checked = 0usize;

    for &(short_len, long_len) in &[(8u8, 24u8), (8, 16), (16, 24), (12, 28), (8, 32)] {
        // Two arrangements. The first is the realistic one — a broad next-table
        // leak and a more specific rib-group import — and it is where the two
        // algorithms disagree: the kernel takes the next-table rule because its
        // priority is lower, the helper takes the rib-group entry because its
        // prefix is longer.
        for &(short_prio, long_prio, label) in &[
            (
                NEXT_TABLE_PRIO,
                RIB_GROUP_PRIO,
                "broad next-table + specific rib-group",
            ),
            (
                RIB_GROUP_PRIO,
                NEXT_TABLE_PRIO,
                "broad rib-group + specific next-table",
            ),
        ] {
            let leaks = [
                Leak {
                    prefix_len: short_len,
                    rule_priority: short_prio,
                    target: "red",
                    egress_ifindex: 12,
                    subnet: 50,
                },
                Leak {
                    prefix_len: long_len,
                    rule_priority: long_prio,
                    target: "blue",
                    egress_ifindex: 13,
                    subnet: 51,
                },
            ];
            checked += 1;
            let want = kernel_choice(&leaks);
            match helper_choice(&leaks) {
                Some(got) if got == want => agreements += 1,
                got => divergences.push(format!(
                    "  /{short_len} (prio {short_prio}) vs /{long_len} (prio {long_prio}) \
                     [{label}]: kernel -> {want}, helper -> {got:?}"
                )),
            }
        }
    }

    assert_eq!(
        divergences.len(),
        0,
        "#9955: {checked} shapes, {agreements} agreements; divergences:\n{}",
        divergences.join("\n")
    );
}

/// A leak rule is evaluated before ordinary routes in the source table.
/// Consequently a matching /8 leak wins over a more-specific /24 ordinary
/// route when the target table contains a route for the destination.
#[test]
fn leak_versus_ordinary_route_in_the_same_table_9955() {
    let leak = Leak {
        prefix_len: 8,
        rule_priority: 150,
        target: "red",
        egress_ifindex: 12,
        subnet: 50,
    };
    let mut snapshot = snapshot_for(&[leak]);
    // An ordinary, more-specific route in the SAME table as the leak, out a
    // third interface so the winner is unambiguous.
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.1.2.0/24".to_string(),
        next_hops: vec!["172.16.52.1@ge-0/0/14.50".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/14.50".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-14.50".to_string(),
        ifindex: 14,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.52.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-14.50".to_string(),
        ifindex: 14,
        family: "inet".to_string(),
        ip: "172.16.52.1".to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
        ..Default::default()
    });

    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(PROBE));
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise: the fixture must resolve, or this measures nothing"
    );
    assert_eq!(
        resolved.egress_ifindex, 12,
        "the leak rule must run before main-table LPM, even with a shorter prefix"
    );
}

/// THIRD shape family: a leak whose TARGET TABLE MISSES.
///
/// The kernel treats the matching rule as a miss and continues to the next
/// rule, eventually reaching the ordinary main-table lookup. The helper must
/// preserve that fall-through rather than returning the target miss as the
/// final answer. The test below keeps the main fallback broader than the leak
/// so it proves the rule miss path rather than accidentally bypassing it.
#[test]
fn a_leak_into_a_table_that_misses_falls_through_9955() {
    // The leak is the MORE SPECIFIC entry (/24) and the main-table fallback is
    // broader (/8). That ordering is load-bearing: with the fallback more
    // specific, the helper's prefix-length sort would return the fallback
    // WITHOUT EVER ENTERING the leak arm, and the cell would report a forward
    // candidate that says nothing about fall-through. (It did, on the first run —
    // the assertion caught a cell that could not detect its own defect.)
    let leak = Leak {
        prefix_len: 24,
        rule_priority: 150,
        target: "red",
        egress_ifindex: 12,
        subnet: 50,
    };
    let mut snapshot = snapshot_for(&[leak]);
    // Remove the target table's route so the leak lands on an EMPTY table.
    snapshot.routes.retain(|r| r.table != "red.inet.0");
    // Main can route it perfectly well, via a BROADER prefix.
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.0.0.0/8".to_string(),
        next_hops: vec!["172.16.52.1@ge-0/0/14.50".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/14.50".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-14.50".to_string(),
        ifindex: 14,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.52.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-14.50".to_string(),
        ifindex: 14,
        family: "inet".to_string(),
        ip: "172.16.52.1".to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: true,
        link_local: false,
        ..Default::default()
    });

    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(PROBE));

    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "a target-table miss must fall through to the main table"
    );
    assert_eq!(resolved.egress_ifindex, 14);
}

/// A CONTROL that must pass both before and after any fix: with a SINGLE leak
/// there is nothing to order, so both sides must agree trivially.
///
/// Without it, a "fix" that broke leak resolution outright would make the
/// differential above pass by making every shape resolve to nothing — the
/// failure mode where a deny and a broken probe read identically.
#[test]
fn a_single_leak_resolves_the_same_either_way_9955() {
    for &len in &[8u8, 16, 24, 32] {
        let leaks = [Leak {
            prefix_len: len,
            rule_priority: 150,
            target: "red",
            egress_ifindex: 12,
            subnet: 50,
        }];
        assert_eq!(
            helper_choice(&leaks),
            Some(kernel_choice(&leaks)),
            "#9955: a single /{len} leak must resolve identically on both sides — with one rule \
             there is no ordering question. If this fails, leak resolution is broken outright \
             and the differential above is not measuring what it claims."
        );
    }
}

/// Pins the corrected priority direction: a broad, higher-priority leak beats
/// a more-specific lower-priority leak because stage 1 is ordered by the
/// kernel rule priority, not the FIB prefix length.
#[test]
fn the_priority_order_beats_prefix_length_9955() {
    let leaks = [
        Leak {
            prefix_len: 8,
            rule_priority: 150, // next-table: the kernel's winner
            target: "red",
            egress_ifindex: 12,
            subnet: 50,
        },
        Leak {
            prefix_len: 24,
            rule_priority: 30_500, // rib-group: longer prefix, worse priority
            target: "blue",
            egress_ifindex: 13,
            subnet: 51,
        },
    ];
    assert_eq!(
        kernel_choice(&leaks),
        "red",
        "premise: the kernel takes the lower-numbered rule priority"
    );
    assert_eq!(
        helper_choice(&leaks),
        Some("red"),
        "rule priority, not prefix length, must choose the target table"
    );
}
#[derive(Debug, Deserialize)]
struct LeakCorpusRow9955 {
    name: String,
    routes: Vec<RouteSnapshot>,
    destination: String,
    want_ifindex: i32,
}

fn snapshot_from_go_leak_corpus_9955(row: &LeakCorpusRow9955) -> crate::ConfigSnapshot {
    let interface = |ifindex: i32, v4: &str, v6: &str| InterfaceSnapshot {
        name: format!("ge-0/0/{ifindex}.50"),
        linux_name: format!("ge-0-0-{ifindex}.50"),
        ifindex,
        zone: "wan".to_string(),
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![
            InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: v4.to_string(),
                ..Default::default()
            },
            InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: v6.to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    super::super::test_fixtures::v5(crate::ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![
            interface(12, "172.16.50.8/24", "2001:db8:50::8/64"),
            interface(13, "172.16.51.8/24", "2001:db8:51::8/64"),
            interface(14, "172.16.52.8/24", "2001:db8:52::8/64"),
        ],
        routes: row.routes.clone(),
        ..Default::default()
    })
}

/// Cross-language agreement: consume the exact JSON emitted by the Go
/// `buildRouteSnapshots` producer and compare Rust's production builder +
/// resolver with Go's independent kernel-stage oracle. This catches both a
/// producer field/sort drift and a Rust model drift across IPv4 and IPv6.
#[test]
fn go_leak_corpus_agrees_with_rust_kernel_model_9955() {
    const CORPUS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pkg/dataplane/userspace/testdata/leak_resolution_9955.json"
    ));
    let rows: Vec<LeakCorpusRow9955> =
        serde_json::from_str(CORPUS).expect("the committed Go leak corpus is valid JSON");
    assert!(
        rows.len() >= 30,
        "corpus must retain the full IPv4/IPv6 overlap and fall-through matrix"
    );
    assert!(
        rows.iter().any(|row| row.destination.contains(':')),
        "corpus must include IPv6 cases"
    );
    assert!(
        rows.iter().any(|row| !row.destination.contains(':')),
        "corpus must include IPv4 cases"
    );

    for row in rows {
        let destination: IpAddr = row
            .destination
            .parse()
            .unwrap_or_else(|err| panic!("{} has invalid destination: {err}", row.name));
        let state = build_forwarding_state(&snapshot_from_go_leak_corpus_9955(&row));
        let resolved = lookup_forwarding_resolution(&state, destination);
        assert_eq!(
            resolved.egress_ifindex, row.want_ifindex,
            "{}: Rust egress {} disagrees with Go kernel-stage oracle {}",
            row.name, resolved.egress_ifindex, row.want_ifindex
        );
        if row.want_ifindex == 0 {
            assert_eq!(
                resolved.disposition,
                ForwardingDisposition::NoRoute,
                "{}: an oracle miss must remain NoRoute",
                row.name
            );
        } else {
            assert!(
                matches!(
                    resolved.disposition,
                    ForwardingDisposition::ForwardCandidate
                        | ForwardingDisposition::MissingNeighbor
                ),
                "{}: expected a forwarding resolution, got {:?}",
                row.name,
                resolved.disposition
            );
        }
    }
}
/// A leak target can own the destination as a local address. The target-table
/// lookup must retain the local-delivery decision instead of falling through
/// to its connected route.
#[test]
fn v4_leak_target_preserves_local_delivery_9955() {
    let snapshot = super::super::test_fixtures::v5(crate::ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/12.50".to_string(),
            routing_instance: "red".to_string(),
            ifindex: 12,
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.1.2.1/32".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "10.1.2.0/24".to_string(),
            next_table: "red.inet.0".to_string(),
            rule_priority: 100,
            ..Default::default()
        }],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 1)));
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}

/// A NAT-only leak target has no connected or ordinary FIB route. The
/// table-presence precheck must still admit the target so local delivery runs.
#[test]
fn v4_nat_only_leak_target_preserves_local_delivery_9955() {
    let target = Ipv4Addr::new(203, 0, 113, 9);
    let snapshot = super::super::test_fixtures::v5(crate::ConfigSnapshot {
        static_nat_rules: vec![crate::StaticNATRuleSnapshot {
            name: "nat-only-leak-target".to_string(),
            from_routing_instance: "red".to_string(),
            external_ip: target.to_string(),
            internal_ip: "192.0.2.9".to_string(),
            ..Default::default()
        }],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "203.0.113.0/24".to_string(),
            next_table: "red.inet.0".to_string(),
            rule_priority: 100,
            ..Default::default()
        }],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    assert!(state.local_v4.contains(&target));
    assert!(state
        .local_tables_v4
        .get(&target)
        .is_some_and(|tables| tables.contains("red.inet.0")));
    assert!(
        state
            .routes_v4
            .get("red.inet.0")
            .is_none_or(|routes| routes.iter().all(|entry| entry.next_table != ""))
    );
    assert!(
        state
            .connected_v4
            .iter()
            .all(|entry| entry.table != "red.inet.0")
    );

    let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(target));
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 0);
}

#[test]
fn v6_leak_target_preserves_local_delivery_9955() {
    let snapshot = super::super::test_fixtures::v5(crate::ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/12.50".to_string(),
            routing_instance: "red".to_string(),
            ifindex: 12,
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: "2001:db8:1::1/128".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        routes: vec![RouteSnapshot {
            table: "inet6.0".to_string(),
            family: "inet6".to_string(),
            destination: "2001:db8:1::/64".to_string(),
            next_table: "red.inet6.0".to_string(),
            rule_priority: 100,
            ..Default::default()
        }],
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let resolved = lookup_forwarding_resolution(
        &state,
        IpAddr::V6("2001:db8:1::1".parse().expect("v6 local address")),
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 12);
}
