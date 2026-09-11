// #7717 part 2 — the DRAIN, and the quarantine it makes safe.
//
// The companion pin (`tests_iface_pool_overlap_7717.rs`) demonstrates the
// collision with a HEALTHY pool and, as its own header records, does NOT invert
// when this lands: it constructs its rule sets directly and never passes through
// the snapshot builder that quarantines. So the acceptance control lives here
// and is driven by the QUARANTINE the builder emits — `pool_unusable` with the
// `iface_snat_egress_overlap` reason — which is the state a runtime-learned
// overlapping address actually produces.

use super::allocator::{NatHolder, TranslatedTuple};
use super::*;
use super::source::SourceNatFlowKey;
use crate::SourceNATRuleSnapshot;
use std::net::IpAddr;

const E: &str = "172.16.80.8";
const SRV: &str = "172.16.80.200";
const TCP: u8 = 6;

fn pool_snapshot(quarantined: bool) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "P".to_string(),
        pool_addresses: vec![E.to_string()],
        pool_unusable: quarantined,
        pool_unusable_reason: if quarantined {
            "iface_snat_egress_overlap".to_string()
        } else {
            String::new()
        },
        ..SourceNATRuleSnapshot::default()
    }
}

fn iface_snapshot() -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "iface-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }
}

fn admit(reg: &InterfaceNatAllocators, rules: &[SourceNatRule], src: &str, src_port: u16) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        reg,
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        SRV.parse().expect("dst"),
        Some(TCP),
        src_port,
        80,
        Some(E.parse().expect("egress")),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

/// The quarantined pool's allocator SURVIVES into the next generation.
///
/// This is the stranding the merged config gate names as the reason the
/// quarantine could not ship alone: "marking a pool unusable with nothing
/// draining would strand live sessions". Before the drain, `allocator_key`
/// refused a failed pool and the carry-over dropped it, so the flows still
/// holding identities from that allocator lost the state that releases them.
#[test]
fn quarantined_pool_retains_its_allocator_so_live_flows_drain_7717() {
    // Generation 1: healthy pool, one live flow.
    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    assert!(matches!(
        admit(&reg, &gen1, "10.0.0.1", 5555),
        SourceNatLookup::Matched(_)
    ));
    let live_before = gen1[0].pool_allocator.live_flow_count();
    assert_eq!(live_before, 1, "setup: the pool must hold one live flow");

    // Generation 2: the SAME pool, now quarantined by the builder.
    let gen2 = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    assert_eq!(
        gen2[0].pool_allocator.live_flow_count(),
        live_before,
        "#7717: a quarantined pool must RETAIN its allocator — its live flows still hold \
         identities and need the state that releases them. Dropping it is the stranding the \
         merged config gate names as why the quarantine could not ship without this drain"
    );

    // And it must survive REPEATED quarantined snapshots. A carry-over key that
    // dropped on the second rebuild would strand exactly the flows the first
    // one preserved, and every rebuild while the overlap persists is one of
    // these.
    let gen3 = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen2),
        &NatCounterStore::default(),
        0,
    );
    assert_eq!(
        gen3[0].pool_allocator.live_flow_count(),
        live_before,
        "#7717: retention must survive repeated quarantined snapshots, not just the first"
    );
}

/// A quarantined pool mints NOTHING new, which is what makes the drain finite.
#[test]
fn quarantined_pool_refuses_new_mints_7717() {
    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    assert!(matches!(
        admit(&reg, &gen1, "10.0.0.1", 5555),
        SourceNatLookup::Matched(_)
    ));

    let gen2 = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    match admit(&reg, &gen2, "10.0.0.9", 6666) {
        SourceNatLookup::Unavailable(_) => {}
        other => panic!(
            "#7717: a quarantined pool must refuse NEW mints, or the drain never finishes \
             because the pool keeps adding to what has to drain. Got {other:?}"
        ),
    }
}

/// THE ACCEPTANCE CONTROL, and it is a PAIR.
///
/// While the quarantined pool still holds a live allocation on E, an
/// interface-mode mint on E fails CLOSED — that is the collision the pin
/// demonstrates, refused. And when the drain COMPLETES the same mint succeeds:
/// without that second half this would be indistinguishable from a permanent
/// quarantine, which is a working drain's exact failure mode and reads
/// identically on every operator surface.
#[test]
fn interface_mint_fails_closed_while_draining_then_recovers_7717() {
    // Live pool flow on E, then quarantine.
    // gen1 is POOL-ONLY so the pool is what admits and holds the live flow.
    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    let pool_port = match admit(&reg, &gen1, "10.0.0.1", 5555) {
        SourceNatLookup::Matched(d) => d.rewrite_src_port.expect("pool mode PATs, so a port"),
        other => panic!("setup: the healthy pool must admit: {other:?}"),
    };
    assert_eq!(gen1[0].pool_allocator.live_flow_count(), 1, "setup");

    // The draining generation lists the INTERFACE rule first, so it is the rule
    // that matches this flow. Order matters here and the ordering is the point:
    // with the quarantined pool first it matches and refuses on its own
    // account, which exercises the pool arm rather than the interface arm the
    // collision actually lives on.
    let draining = parse_source_nat_rules_with_previous(
        &[iface_snapshot(), pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    let pool_idx = draining
        .iter()
        .position(|r| r.pool_mode)
        .expect("the quarantined pool rule must be present — it is what the gate scans for");
    assert_eq!(
        draining[pool_idx].pool_allocator.live_flow_count(),
        1,
        "setup: still draining"
    );

    match admit(&reg, &draining, "10.0.0.2", 5555) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::InterfaceOverlapDraining,
            "#7717: the refusal must name the DRAIN, not exhaustion — the remedy and the \
             expected duration differ, and an operator seeing this should look at the overlap"
        ),
        other => panic!(
            "#7717: an interface-mode mint on an address a quarantined pool is still draining \
             must fail CLOSED. Got {other:?} — that is the collision the pin demonstrates"
        ),
    }

    // DRAIN COMPLETES — through the REAL release path, not a test backdoor, so
    // this proves the production mechanism finishes the drain and not merely
    // that a counter can be zeroed. The quarantine must then lift on its own:
    // it is scoped to LIVE occupancy, not to the quarantine flag.
    let flow = SourceNatFlowKey {
        protocol: TCP,
        src_ip: "10.0.0.1".parse().expect("src"),
        dst_ip: SRV.parse().expect("dst"),
        src_port: 5555,
        dst_port: 80,
        routing_scope: 0,
    };
    let translated = TranslatedTuple {
        ip: E.parse::<IpAddr>().expect("egress"),
        port: pool_port,
    };
    assert!(
        draining[pool_idx]
            .pool_allocator
            .release_flow(flow, translated, 2_000, NatHolder::Untracked),
        "the live pool flow must release through the RETAINED allocator — if the carry-over \
         dropped it, this is exactly the stranding: the flow is live and nothing can free it"
    );
    assert_eq!(draining[pool_idx].pool_allocator.live_flow_count(), 0, "setup: drained");

    match admit(&reg, &draining, "10.0.0.2", 5555) {
        SourceNatLookup::Matched(_) => {}
        other => panic!(
            "#7717: once the drain completes the interface mint must SUCCEED. A refusal that \
             never lifts is a permanent quarantine wearing the shape of a working drain, and \
             it looks identical on every operator surface. Got {other:?}"
        ),
    }
}

/// The drain is scoped to the OVERLAP quarantine, and only to it.
///
/// Added because a mutation cell found the scope unbound: widening
/// `is_draining_pool` to `pool_failure.is_some()` red nothing, so the narrowing
/// this change argues for was a claim with no test behind it.
///
/// It matters because retention is not free. A pool failed for its own reasons —
/// over budget, empty, invalid range — has nothing to drain: no interface-mode
/// mint is being refused on its behalf, so holding its allocator only keeps
/// aggregate-budget capacity (#6812) occupied by state nothing will release. The
/// overlap case is different precisely because something IS being refused on its
/// behalf, and that refusal must end.
#[test]
fn only_the_overlap_quarantine_retains_its_allocator_7717() {
    let mut over_budget = pool_snapshot(true);
    over_budget.pool_unusable_reason = "aggregate_over_budget".to_string();

    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    assert!(matches!(
        admit(&reg, &gen1, "10.0.0.1", 5555),
        SourceNatLookup::Matched(_)
    ));
    assert_eq!(gen1[0].pool_allocator.live_flow_count(), 1, "setup");

    let gen2 = parse_source_nat_rules_with_previous(
        &[over_budget],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    assert_eq!(
        gen2[0].pool_allocator.live_flow_count(),
        0,
        "#7717: a pool failed for a reason OTHER than the interface-SNAT overlap must NOT \
         retain its allocator — that is the pre-existing behaviour, and widening retention to \
         every failure holds #6812 aggregate-budget capacity for state nothing is waiting on"
    );

    // CONTROL, same generation shape: the OVERLAP reason DOES retain. Without
    // it this test passes against a build that retains nothing at all.
    let gen2_overlap = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    assert_eq!(
        gen2_overlap[0].pool_allocator.live_flow_count(),
        1,
        "control: the overlap quarantine must still retain, or the assertion above is \
         satisfied by retention being broken outright"
    );
}

/// #7799: NAT64 is a THIRD occupancy domain. It mints from `Nat64Prefix`'s own
/// `PortAllocator`, which can see neither the interface registry nor a
/// source-NAT pool's occupancy bitmap — so a NAT64 mint on an address a
/// quarantined pool is still DRAINING can hand out an identity that pool still
/// owns, and the reverse index cannot disambiguate the reply.
///
/// The CONTROL half carries as much weight as the refusal: with the same rules
/// before they are quarantined, the same mint must SUCCEED. Without it a
/// permanently-broken NAT64 mint would pass this cell, and a permanent
/// quarantine is a working drain's exact failure mode.
#[test]
fn nat64_mint_fails_closed_while_a_pool_drains_the_same_address_7799() {
    // A live pool-mode flow on E, exactly as the interface-arm cell sets up.
    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    match admit(&reg, &gen1, "10.0.0.1", 5555) {
        SourceNatLookup::Matched(_) => {}
        other => panic!("setup: the healthy pool must admit: {other:?}"),
    }
    assert_eq!(gen1[0].pool_allocator.live_flow_count(), 1, "setup");

    // A NAT64 rule-set whose pool is the SAME address the pool SNAT holds.
    let nat64 = crate::nat64::Nat64State::from_snapshots(&[crate::NAT64RuleSnapshot {
        name: "n64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![E.to_string()],
        ..Default::default()
    }]);
    let client: std::net::Ipv6Addr = "2001:db8::1".parse().expect("client v6");
    let dst_v4: std::net::Ipv4Addr = SRV.parse().expect("server v4");

    // CONTROL: nothing is draining, so the NAT64 mint succeeds. This is what
    // makes the refusal below attributable to the DRAIN rather than to the
    // rule set, the pool, or the allocator being unusable in the first place.
    nat64
        .allocate_source_for_worker(0, TCP, client, dst_v4, 6000, 443, 0, 0, &gen1, 0)
        .expect("control: with no draining pool a NAT64 mint on E must succeed");

    // Quarantine the pool. Its allocator is RETAINED, so it is still holding
    // the live flow from gen1 — the draining state, not the drained one.
    let draining = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    let pool_idx = draining
        .iter()
        .position(|r| r.pool_mode)
        .expect("the quarantined pool rule must be present — it is what the gate scans for");
    assert_eq!(
        draining[pool_idx].pool_allocator.live_flow_count(),
        1,
        "setup: still draining, not drained"
    );

    match nat64.allocate_source_for_worker(0, TCP, client, dst_v4, 6001, 443, 0, 0, &draining, 0) {
        Err(SourceNatFailureReason::Nat64OverlapDraining) => {}
        other => panic!(
            "#7799: a NAT64 mint on an address a quarantined pool is still draining must fail \
             CLOSED, and must name the DRAIN so the counter does not blame interface SNAT. \
             Got {other:?}"
        ),
    }
}

/// #7799, second mint path. `Nat64State` has TWO ways to mint on `pool_v4`:
/// round-robin `allocate_nat64_pool_port` and the mode-2 deterministic NAPT64
/// `allocate_nat64_pool_port_deterministic_v6`. #7799 named only the first.
/// Both allocate from the same pool and carry the same collision, so the gate
/// is placed before the deterministic branch — and this cell is what makes that
/// placement a tested property rather than a claim about a set from one member.
#[test]
fn nat64_deterministic_mint_also_fails_closed_while_draining_7799() {
    let gen1 = parse_source_nat_rules(&[pool_snapshot(false)]);
    let reg = InterfaceNatAllocators::default();
    match admit(&reg, &gen1, "10.0.0.1", 5555) {
        SourceNatLookup::Matched(_) => {}
        other => panic!("setup: the healthy pool must admit: {other:?}"),
    }

    // A DETERMINISTIC (mode 2) NAT64 prefix whose pool is the drained address.
    let nat64 = crate::nat64::Nat64State::from_snapshots(&[crate::NAT64RuleSnapshot {
        name: "n64-det".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![E.to_string()],
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_prefix_len: 32,
        deterministic_host_base_v6: "2001:db8::".to_string(),
        ..Default::default()
    }]);
    assert!(
        nat64.prefixes[0].deterministic_v6.is_some(),
        "setup: this cell is only meaningful if the DETERMINISTIC branch is the one taken"
    );

    let client: std::net::Ipv6Addr = "2001:db8:0:5::".parse().expect("client v6");
    let dst_v4: std::net::Ipv4Addr = SRV.parse().expect("server v4");

    // CONTROL: the deterministic path mints fine while nothing is draining.
    nat64
        .allocate_source_for_worker(0, TCP, client, dst_v4, 6000, 443, 0, 0, &gen1, 0)
        .expect("control: a deterministic NAPT64 mint must succeed with no draining pool");

    let draining = parse_source_nat_rules_with_previous(
        &[pool_snapshot(true)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    match nat64.allocate_source_for_worker(0, TCP, client, dst_v4, 6001, 443, 0, 0, &draining, 0) {
        Err(SourceNatFailureReason::Nat64OverlapDraining) => {}
        other => panic!(
            "#7799: the DETERMINISTIC NAPT64 mint path allocates from the same pool and must \
             fail closed on a draining address too. Got {other:?}"
        ),
    }
}
