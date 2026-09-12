//! #9955 — the leak-resolution differential.
//!
//! An operator can author overlapping `next-table` / rib-group leaks and the
//! compiler accepts them without comment. When the leaked prefixes overlap, the
//! kernel and this helper choose by DIFFERENT algorithms, by construction and
//! not by accident:
//!
//!   * **kernel** — leaks are installed as ip RULES (`pkg/routing/rules.go`
//!     assigns `rule.Priority = prio + added`, monotonically increasing). FIB
//!     rules are evaluated in priority order and the FIRST match wins. Prefix
//!     length is not a tiebreak and plays no part.
//!   * **helper** — `sort_routes` orders each table by DESCENDING PREFIX LENGTH,
//!     then ascending preference, and the lookup is
//!     `routes.iter().find(|e| e.prefix.contains(ip))`. Its own comment states
//!     the intent: the most specific one, "NOT the insertion-order first".
//!
//! The ordering key never crosses the boundary. `pkg/dataplane/userspace/routes.go`
//! reads `rule.Priority` only to classify the PBR window (31000-31999) and drops
//! it; `RouteSnapshot` carries no priority at all. So the helper cannot reproduce
//! the kernel's order even in principle.
//!
//! This is a DIFFERENTIAL over a GENERATED set of overlap shapes rather than one
//! hand-built case, because a single case can agree by luck: with only one
//! (outer, inner) pair you cannot tell "the algorithms agree" from "these two
//! prefixes happen to rank the same way under both".

use super::super::forwarding_build::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot, ZoneSnapshot,
};
use std::net::Ipv4Addr;

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

    // CHARACTERIZATION of a KNOWN defect, not an aspiration. Every shape where
    // the broader prefix carries the better rule priority diverges; every shape
    // where the more specific prefix ALSO has the better priority agrees, because
    // there the two algorithms happen to rank the same entry first.
    //
    // That 50/50 split is the reason the issue asked for a GENERATED set. A
    // single hand-built case drawn from the agreeing half would have shown no
    // defect at all, and a single case drawn from the diverging half would not
    // have revealed that half the space agrees by luck.
    //
    // When the model is fixed this number must go DOWN to zero. If it changes in
    // either direction unexpectedly, the resolution model moved and the change
    // needs to say why.
    assert_eq!(
        divergences.len(),
        5,
        "#9955: expected the 5 known diverging shapes of {checked} ({agreements} agree); got \
         {}.\n{}\n\nThe kernel evaluates leaks as ip RULES in PRIORITY order, first match \
         wins, and prefix length is not a tiebreak. The helper sorts each table by DESCENDING \
         PREFIX LENGTH then preference and takes the first containing entry. The ordering key \
         never crosses the boundary: pkg/dataplane/userspace/routes.go reads rule.Priority only \
         to classify the PBR window and drops it, so RouteSnapshot carries no priority and the \
         helper cannot reproduce the kernel's order even in principle.",
        divergences.len(),
        divergences.join("\n")
    );
}

/// A SECOND shape family, measured before deciding anything about it: a leak
/// overlapping an ordinary route in the SAME table.
///
/// In the kernel these are not peers. Leaks are ip RULES at priority 100-199 /
/// 30000-30999, and the main table is reached by the `from all lookup main` rule
/// at 32766 — so a matching leak rule fires BEFORE the table is consulted at
/// all, whatever the prefix lengths are. In the helper both live in one list
/// sorted by prefix length, so a /24 route beats a /8 leak.
///
/// This is reported rather than asserted. It is a wider behaviour change than
/// the overlapping-leak question this issue was filed for, and the honest order
/// is to measure it, say so, and get a scope decision — not to quietly widen the
/// fix to something no differential demonstrated.
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
    // 12 = the leak's target; 14 = the ordinary /24 route.
    assert_eq!(
        resolved.egress_ifindex, 14,
        "#9955 (second shape family, CHARACTERIZED): the helper prefers the ordinary /24 route \
         (ifindex 14) over the /8 LEAK (ifindex 12); expected to become 12 when fixed. \
         over the /8 LEAK (ifindex 12). In the kernel a leak is an ip RULE at priority 150 and \
         the main table is only reached via the `from all lookup main` rule at 32766, so the \
         leak fires first regardless of prefix length and the packet is redirected into the \
         target VRF. This is a WIDER divergence than the overlapping-leak question #9955 was \
         filed for; it is asserted here so the scope decision is made on a measurement rather \
         than on a hunch."
    );
}

/// THIRD shape family, and the one that settles what the fix has to be: a leak
/// whose TARGET TABLE MISSES.
///
/// Kernel FIB rules FALL THROUGH on a table miss. A rule that matches sends the
/// lookup to its table; if that table has no route, evaluation CONTINUES with
/// the next rule, and eventually reaches `from all lookup main` at 32766. So a
/// leak pointing at a table that cannot route the packet costs nothing — main
/// still routes it.
///
/// The helper cannot do this. `lookup_forwarding_resolution_v4_inner` ends the
/// leak arm with `return lookup_forwarding_resolution_v4_inner(...)` — the
/// recursive result is returned UNCONDITIONALLY, so a target-table miss becomes
/// the final answer (NoRoute) rather than a fall-through. The packet is
/// blackholed where the kernel forwards it.
///
/// This is why "carry the ordering key through" is necessary but NOT sufficient.
/// The kernel mechanism is TWO-STAGE — priority-ordered rules with fall-through,
/// then per-table longest-prefix-match — and the helper models it as ONE sorted
/// list per table with unconditional recursion. No choice of comparator over a
/// single list reproduces a two-stage mechanism with fall-through, so adding a
/// priority field and re-sorting cannot close this on its own.
#[test]
fn a_leak_into_a_table_that_misses_does_not_fall_through_9955() {
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

    // CHARACTERIZED. The kernel would fall through the missing table to main and
    // forward out ifindex 14. Expected to become ForwardCandidate/14 when the
    // model is fixed.
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate,
        "#9955 (third shape family, CHARACTERIZED): the helper resolved a leak into an EMPTY \
         target table to a forward candidate, which would mean fall-through is now modelled. \
         Today it returns the recursive result unconditionally, so the packet is blackholed \
         where the kernel falls through to main and forwards it out ifindex 14. If this \
         assertion flips, the two-stage model landed and this cell should assert \
         ForwardCandidate with egress_ifindex 14."
    );
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

/// Pins the DIRECTION of the current divergence, so the differential's failure
/// cannot be read as "something is different" without saying what.
///
/// This is deliberately an observation, not an aspiration: it documents that the
/// helper is choosing by prefix length today. It is expected to need updating by
/// the fix, and that is the point — a cell that survives the fix unchanged was
/// not pinning the behaviour the fix changes.
#[test]
fn the_divergence_is_prefix_length_beating_rule_priority_9955() {
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
        Some("blue"),
        "#9955: this pins the DIRECTION of the divergence — the helper takes the LONGER PREFIX \
         (blue) where the kernel takes the LOWER-PRIORITY RULE (red), so a packet to 10.1.2.5 \
         is leaked into a DIFFERENT VRF by the two sides. It is expected to flip to \
         Some(\"red\") when the model is fixed; a cell that survives the fix unchanged was not \
         pinning the behaviour the fix changes."
    );
}
