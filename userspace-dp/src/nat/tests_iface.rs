// #6751 PR 2/3: interface-mode source-NAT translated-identity admission.
//
// The defect these pin: interface SNAT preserved the source port
// unconditionally, so two internal hosts that picked one source port to one
// server produced BYTE-IDENTICAL reverse wire keys and both forward sessions
// validated against a reply. Every reply reached whichever session installed
// first — H2's return traffic delivered to H1.
//
// The remedy: reserve the translated reverse identity at admission, PRESERVE
// the port when that identity is free, PAT the LATER collider when it is not.
#![allow(unused_imports)]

use super::allocator::NatHolder;
use super::source::{SourceNatFailureReason, SourceNatFlowKey};
use super::*;
use crate::ip_proto::{PROTO_GRE, PROTO_ICMP};
use crate::{SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

const EGRESS: &str = "172.16.80.8";
const SERVER: &str = "172.16.80.200";
const SERVER_B: &str = "172.16.80.201";
const PROTO_TCP_U8: u8 = 6;
const PROTO_UDP_U8: u8 = 17;

fn iface_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "iface-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }])
}

/// One admission through the real entry point. Every argument the #6751 mint
/// reads is a parameter, so a test can vary exactly one axis at a time.
#[allow(clippy::too_many_arguments)]
fn admit(
    reg: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    src: &str,
    src_port: u16,
    dst: &str,
    dst_port: u16,
    protocol: u8,
    non_first_fragment: bool,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        reg,
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        dst.parse().expect("dst"),
        Some(protocol),
        src_port,
        dst_port,
        Some(EGRESS.parse().expect("egress")),
        None,
        1_000,
        non_first_fragment,
        protocol == PROTO_ICMP,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn admit_tcp(
    reg: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    src: &str,
    src_port: u16,
    dst: &str,
) -> SourceNatLookup {
    admit(reg, rules, src, src_port, dst, 80, PROTO_TCP_U8, false)
}

fn decision(lookup: SourceNatLookup) -> NatDecision {
    match lookup {
        SourceNatLookup::Matched(d) => d,
        other => panic!("expected a matched SNAT decision, got {other:?}"),
    }
}

fn failure_reason(lookup: SourceNatLookup) -> SourceNatFailureReason {
    match lookup {
        SourceNatLookup::Unavailable(f) => f.reason,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

fn key(src: &str, src_port: u16, dst: &str, dst_port: u16) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP_U8,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port,
        dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// THE DEFECT. Two internal hosts, one source port, one server: the first
/// preserves and the second is PAT'd, so their reverse identities differ.
///
/// The assertion that matters is the LAST one — before #6751 both decisions
/// carried `rewrite_src_port: None` and the two reverse wire keys were equal,
/// which is precisely why `find_forward_nat_match` could not tell the sessions
/// apart and sent both hosts' replies to the first.
#[test]
fn interface_snat_second_host_on_one_port_is_patted_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    let second = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));

    assert_eq!(first.rewrite_src, Some(EGRESS.parse::<IpAddr>().unwrap()));
    assert_eq!(second.rewrite_src, Some(EGRESS.parse::<IpAddr>().unwrap()));
    // The FIRST flow is untouched on the wire — preserve-first.
    assert_eq!(
        first.rewrite_src_port, None,
        "the first flow must keep its own source port"
    );
    // The SECOND is moved.
    let patted = second
        .rewrite_src_port
        .expect("the colliding second flow must be PAT'd");
    assert_ne!(
        patted, 5555,
        "a PAT'd port equal to the preserved one would still be ambiguous"
    );
    assert!(
        (1024..=65535).contains(&patted),
        "PAT candidates are drawn from the ephemeral range, got {patted}"
    );

    // The property the two assertions above exist to produce: the reverse
    // identities are now DISTINGUISHABLE.
    assert_ne!(
        first.rewrite_src_port.unwrap_or(5555),
        second.rewrite_src_port.unwrap_or(5555),
        "the two flows must not share one translated reverse identity"
    );
}

/// OVER-REACH CONTROL. Every non-colliding shape must stay wire-stable.
///
/// A delete-the-feature mutation cannot see this test; a mutation that PATs
/// MORE aggressively than shipped (always PAT, never preserve; or key
/// occupancy on the port alone rather than the full reverse identity) reds
/// here and nowhere else. Preserve-first is the intentional xpf semantic —
/// losing it silently is the regression that matters.
#[test]
fn interface_snat_non_colliding_flows_stay_wire_stable_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    // Same host, same port, DIFFERENT servers — two distinct reverse
    // identities, so both preserve. (Occupancy keyed on the port alone would
    // PAT the second.)
    let a = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    let b = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER_B));
    assert_eq!(a.rewrite_src_port, None, "first server: preserve");
    assert_eq!(
        b.rewrite_src_port, None,
        "same port to a DIFFERENT server is not a collision"
    );

    // TCP and UDP on the same numeric port to the same server — the protocol
    // is part of the reverse identity.
    let udp = decision(admit(
        &reg,
        &rules,
        "10.0.61.103",
        5555,
        SERVER,
        80,
        PROTO_UDP_U8,
        false,
    ));
    assert_eq!(
        udp.rewrite_src_port, None,
        "UDP/5555 does not collide with TCP/5555"
    );

    // A well-known source port below 1024 is PRESERVED when free. PAT
    // candidates are drawn from the ephemeral range, but preservation is not
    // restricted to it.
    let low = decision(admit_tcp(&reg, &rules, "10.0.61.104", 123, SERVER));
    assert_eq!(
        low.rewrite_src_port, None,
        "a sub-1024 source port must still be preserved when free"
    );

    // A different source port to the same server.
    let other = decision(admit_tcp(&reg, &rules, "10.0.61.105", 5556, SERVER));
    assert_eq!(other.rewrite_src_port, None, "5556 is its own identity");

    // And the same destination reached on a different destination PORT is a
    // different identity too.
    let other_dport = decision(admit(
        &reg,
        &rules,
        "10.0.61.106",
        5555,
        SERVER,
        443,
        PROTO_TCP_U8,
        false,
    ));
    assert_eq!(
        other_dport.rewrite_src_port, None,
        "same source port to a different destination port is not a collision"
    );
}

/// A second packet of the SAME flow returns the first decision and mints
/// nothing new — otherwise a racing session install would double-mint and only
/// one record would ever be released.
#[test]
fn interface_snat_reentry_is_idempotent_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    let again = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    assert_eq!(first, again);

    let alloc = reg
        .allocator_if_present(EGRESS.parse().unwrap())
        .expect("allocator");
    assert_eq!(
        alloc.live_flow_count(),
        1,
        "re-entry must not mint a second record for one flow"
    );

    // Re-entry on a PAT'd flow returns the SAME PAT'd port, not a fresh one.
    let second = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    let second_again = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    assert_eq!(second, second_again);
    assert!(second.rewrite_src_port.is_some());
    assert_eq!(alloc.live_flow_count(), 2);
}

/// RELEASE SYMMETRY. The mint is freed by the EXISTING teardown path — no new
/// delete site — for a preserved token and a PAT'd one alike.
///
/// Without the interface arm in `release_source_nat_allocation_with_mode` the
/// identity is held for the node's lifetime and the third flow below would be
/// PAT'd forever.
#[test]
fn interface_snat_release_frees_the_identity_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    let second = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    assert_eq!(first.rewrite_src_port, None);
    assert!(second.rewrite_src_port.is_some());

    let alloc = reg
        .allocator_if_present(EGRESS.parse().unwrap())
        .expect("allocator");
    assert_eq!(alloc.live_flow_count(), 2);

    // Retire the PRESERVED flow through the production teardown entry point.
    release_source_nat_allocation(
        &reg,
        &rules,
        &key("10.0.61.101", 5555, SERVER, 80),
        first,
        false,
        2_000,
    );
    assert_eq!(alloc.live_flow_count(), 1, "the preserved token was freed");

    // A NEW flow may now take the freed identity — preserved, not PAT'd.
    let third = decision(admit_tcp(&reg, &rules, "10.0.61.103", 5555, SERVER));
    assert_eq!(
        third.rewrite_src_port, None,
        "the released identity must be reusable"
    );

    // And retiring the PAT'd flow frees its (moved) identity too: the release
    // path reconstructs `translated.port` from `rewrite_src_port`, so a
    // reconstruction that ignored it would leave this record behind.
    release_source_nat_allocation(
        &reg,
        &rules,
        &key("10.0.61.102", 5555, SERVER, 80),
        second,
        false,
        3_000,
    );
    assert_eq!(
        alloc.live_flow_count(),
        1,
        "only the third flow's record should remain"
    );
}

/// ROLLBACK. An admitted-then-refused install must not strand the identity.
#[test]
fn interface_snat_rollback_frees_the_identity_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    rollback_source_nat_allocation(
        &reg,
        &rules,
        &key("10.0.61.101", 5555, SERVER, 80),
        first,
        false,
        2_000,
    );
    // A different host may now PRESERVE the same port.
    let next = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    assert_eq!(next.rewrite_src_port, None);
}

/// PROBE PURITY. Both probe classes mint NOTHING.
///
/// A non-first fragment has no L4 header (its "ports" are payload) and the
/// address-only wrapper has no tuple at all. A mint on either would claim an
/// identity no real flow owns and no teardown would ever free — one per
/// fragment. The proof is not "the decision looks the same": it is that a REAL
/// flow with the same tuple afterwards still PRESERVES.
#[test]
fn interface_snat_probe_classes_mint_nothing_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    // Non-first fragment.
    let frag = decision(admit(
        &reg,
        &rules,
        "10.0.61.101",
        5555,
        SERVER,
        80,
        PROTO_TCP_U8,
        true,
    ));
    assert_eq!(frag.rewrite_src, Some(EGRESS.parse::<IpAddr>().unwrap()));
    assert_eq!(frag.rewrite_src_port, None);

    // Tuple-unknown (the address-only `match_source_nat` wrapper).
    let unknown = match_source_nat(
        &reg,
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.101".parse().unwrap(),
        SERVER.parse().unwrap(),
        Some(EGRESS.parse().unwrap()),
        None,
    )
    .expect("interface rule matches");
    assert_eq!(unknown.rewrite_src_port, None);

    assert!(
        reg.allocator_if_present(EGRESS.parse().unwrap())
            .is_none_or(|a| a.live_flow_count() == 0),
        "a probe must mint no record"
    );

    // A DIFFERENT host now admits the same tuple. If either probe had minted,
    // this would be PAT'd.
    let real = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    assert_eq!(
        real.rewrite_src_port, None,
        "a probe must not consume the identity a real flow needs"
    );
}

/// A PORT-LESS protocol has ONE identity per `(egress, remote)` and no port to
/// move, so the second colliding flow fails CLOSED — the pool-mode
/// address-only contract, unchanged. Admitting it would recreate the exact
/// indistinguishable reverse tuple.
#[test]
fn interface_snat_port_less_second_flow_fails_closed_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit(
        &reg,
        &rules,
        "10.0.61.101",
        0,
        SERVER,
        0,
        PROTO_GRE,
        false,
    ));
    assert_eq!(first.rewrite_src, Some(EGRESS.parse::<IpAddr>().unwrap()));
    assert_eq!(first.rewrite_src_port, None);

    let second = admit(&reg, &rules, "10.0.61.102", 0, SERVER, 0, PROTO_GRE, false);
    assert_eq!(
        failure_reason(second),
        SourceNatFailureReason::InterfaceIdentityExhausted,
    );

    // A port-less flow to a DIFFERENT remote is its own identity and succeeds
    // — the fail-closed above is a collision, not a blanket refusal.
    let other = decision(admit(
        &reg,
        &rules,
        "10.0.61.103",
        0,
        SERVER_B,
        0,
        PROTO_GRE,
        false,
    ));
    assert_eq!(other.rewrite_src_port, None);
}

/// #5688 regression: an interface rule with no same-family egress address
/// still fails CLOSED, and does so BEFORE any registry state is created.
#[test]
fn interface_snat_no_egress_address_still_fails_closed_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &reg,
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.101".parse().unwrap(),
        SERVER.parse().unwrap(),
        Some(PROTO_TCP_U8),
        5555,
        80,
        None, // no v4 egress address
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        failure_reason(lookup),
        SourceNatFailureReason::InterfaceNoEgressAddress,
    );
    assert_eq!(reg.retained_len(), 0, "a fail-closed must create no state");
}

/// The §5.8 PAT-collision counter moves for the colliding admission and NOT
/// for the non-colliding ones — otherwise it would be an alias for "an
/// interface-mode flow was admitted" and could not answer how often the
/// #6751 shape occurs.
#[test]
fn interface_snat_pat_collision_counter_discriminates_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let before = INTERFACE_SNAT_PAT_COLLISIONS.load(Ordering::Relaxed);
    admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER);
    // A non-colliding sibling: same port, different server.
    admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER_B);
    assert_eq!(
        INTERFACE_SNAT_PAT_COLLISIONS.load(Ordering::Relaxed),
        before,
        "non-colliding admissions must not bump the collision counter"
    );

    admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER);
    assert_eq!(
        INTERFACE_SNAT_PAT_COLLISIONS.load(Ordering::Relaxed),
        before + 1,
        "the colliding admission must bump it exactly once"
    );
}

/// HA: the standby holds the identities the active minted BEFORE it ever mints
/// locally. Without the interface arm of the synced-reserve scan, the standby's
/// registry stays empty and its first post-failover admission preserves a port
/// an imported live session is already using.
#[test]
fn interface_snat_synced_import_reserves_the_identity_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    // The active preserved 5555 for H1. Import that decision.
    let imported = NatDecision {
        rewrite_src: Some(EGRESS.parse().unwrap()),
        ..NatDecision::default()
    };
    assert!(
        reserve_synced_source_nat_allocation_untracked(
            &reg,
            &rules,
            &key("10.0.61.101", 5555, SERVER, 80),
            imported,
            false,
            None,
            1_000,
        ),
        "an interface-mode import must be publishable"
    );

    // The standby's registry now holds the identity, so its own admission of a
    // DIFFERENT host on the same port PATs rather than duplicating it.
    let local = decision(admit_tcp(&reg, &rules, "10.0.61.102", 5555, SERVER));
    assert!(
        local.rewrite_src_port.is_some(),
        "a local mint must not preserve a port an imported session owns"
    );
}

/// The tri-state's discriminating half: an import whose identity a LOCAL flow
/// already owns is REFUSED, rather than published as a duplicate.
#[test]
fn interface_snat_synced_import_conflict_is_refused_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    // A local flow owns (egress, 5555, SERVER:80).
    let local = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    assert_eq!(local.rewrite_src_port, None);

    // A DIFFERENT peer flow claims the same translated identity.
    let imported = NatDecision {
        rewrite_src: Some(EGRESS.parse().unwrap()),
        ..NatDecision::default()
    };
    assert!(
        !reserve_synced_source_nat_allocation_untracked(
            &reg,
            &rules,
            &key("10.0.61.199", 5555, SERVER, 80),
            imported,
            false,
            None,
            1_000,
        ),
        "an import colliding with a live local identity must be refused"
    );

    // #7581 control: a synced session with NO source NAT is still publishable,
    // so the refusal above is the conflict and not a blanket rejection.
    assert!(reserve_synced_source_nat_allocation_untracked(
        &reg,
        &rules,
        &key("10.0.61.200", 6000, SERVER, 80),
        NatDecision::default(),
        false,
        None,
        1_000,
    ));
}

/// An import conflict is an HA-FIDELITY loss, not a data-path drop, so it must
/// land on its OWN counter. Folded into the admission counter, an operator
/// could not tell "a peer's session lost a race with a local flow" from "this
/// node is dropping its own new flows" — different severities, different
/// remedies.
#[test]
fn interface_snat_sync_conflict_uses_its_own_counter_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    // A local flow owns the identity.
    decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));

    let before_sync = INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.load(Ordering::Relaxed);
    let before_admission = INTERFACE_SNAT_IDENTITY_EXHAUSTION.load(Ordering::Relaxed);

    let imported = NatDecision {
        rewrite_src: Some(EGRESS.parse().unwrap()),
        ..NatDecision::default()
    };
    assert!(!reserve_synced_source_nat_allocation_untracked(
        &reg,
        &rules,
        &key("10.0.61.199", 5555, SERVER, 80),
        imported,
        false,
        None,
        1_000,
    ));

    assert_eq!(
        INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.load(Ordering::Relaxed),
        before_sync + 1,
        "an import conflict must bump the sync-conflict counter"
    );
    assert_eq!(
        INTERFACE_SNAT_IDENTITY_EXHAUSTION.load(Ordering::Relaxed),
        before_admission,
        "an import conflict must NOT be counted as a local admission drop"
    );
}

/// Reclamation drops an allocator only when its address is absent from the
/// live egress set AND it holds no records. "Absent" alone would strand the
/// releases of sessions still forwarding on a just-removed address.
#[test]
fn interface_snat_registry_reclaims_only_absent_and_empty_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();

    let first = decision(admit_tcp(&reg, &rules, "10.0.61.101", 5555, SERVER));
    assert_eq!(reg.retained_len(), 1);

    // Address gone from the egress set, but a live record remains: RETAINED.
    reg.reclaim_absent(&rustc_hash::FxHashSet::default());
    assert_eq!(
        reg.retained_len(),
        1,
        "an allocator with live records must survive its address leaving"
    );

    release_source_nat_allocation(
        &reg,
        &rules,
        &key("10.0.61.101", 5555, SERVER, 80),
        first,
        false,
        2_000,
    );
    // Now absent AND empty.
    reg.reclaim_absent(&rustc_hash::FxHashSet::default());
    assert_eq!(reg.retained_len(), 0);

    // Present in the egress set but empty: still RETAINED (a busy address must
    // not be dropped in the gap between two flows).
    admit_tcp(&reg, &rules, "10.0.61.101", 7000, SERVER);
    let live: rustc_hash::FxHashSet<IpAddr> =
        std::iter::once(EGRESS.parse::<IpAddr>().unwrap()).collect();
    reg.reclaim_absent(&live);
    assert_eq!(reg.retained_len(), 1);
}

/// An IPv6 interface-mode flow takes the same admission path — the registry is
/// keyed by address, not family, so the v6 egress address gets its own
/// identity space.
#[test]
fn interface_snat_v6_collision_is_patted_6751() {
    let reg = InterfaceNatAllocators::default();
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "iface-snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress6: IpAddr = "2001:559:8585:80::8".parse().unwrap();
    let server6: IpAddr = "2001:559:8585:80::200".parse().unwrap();

    let mut mint = |src: &str| -> NatDecision {
        let mut counter = None;
        decision(match_source_nat_result_for_tuple(
            &reg,
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().unwrap(),
            server6,
            Some(PROTO_TCP_U8),
            5555,
            80,
            None,
            Some("2001:559:8585:80::8".parse().unwrap()),
            1_000,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        ))
    };

    let a = mint("2001:559:8585:ef00::101");
    let b = mint("2001:559:8585:ef00::102");
    assert_eq!(a.rewrite_src, Some(egress6));
    assert_eq!(a.rewrite_src_port, None);
    assert!(
        b.rewrite_src_port.is_some(),
        "the v6 collider must be PAT'd too"
    );
}

/// The MINT path and the RELEASE path must resolve the SAME allocator for one
/// egress address, and a repeat resolve must return the STORED one.
///
/// This is the agreement the two halves of the fix depend on: admission mints
/// through `allocator_for` and teardown frees through `allocator_if_present`,
/// so a registry that handed out a fresh allocator per call would look
/// perfectly healthy — every mint would succeed, every release would find
/// nothing, and every identity would leak. Binding the AGREEMENT rather than
/// either side is what catches that.
#[test]
fn interface_snat_registry_resolves_one_allocator_per_address_6751() {
    let reg = InterfaceNatAllocators::default();
    let egress: IpAddr = EGRESS.parse().unwrap();

    let first = reg.allocator_for(egress).expect("create");
    let again = reg.allocator_for(egress).expect("stored winner");
    assert!(
        std::sync::Arc::ptr_eq(&first, &again),
        "a repeat resolve must return the stored allocator, not a fresh one"
    );

    let for_release = reg
        .allocator_if_present(egress)
        .expect("the release path must find what the mint path created");
    assert!(
        std::sync::Arc::ptr_eq(&first, &for_release),
        "mint and release must agree on which allocator owns this address"
    );

    // A DIFFERENT egress address is its own identity space.
    let other: IpAddr = "172.16.50.8".parse().unwrap();
    let other_alloc = reg.allocator_for(other).expect("second address");
    assert!(!std::sync::Arc::ptr_eq(&first, &other_alloc));
    assert_eq!(reg.retained_len(), 2);

    // And the release path never CREATES: an address with no allocator stays
    // absent, so a teardown storm cannot fill the registry with empty ones.
    assert!(
        reg.allocator_if_present("172.16.80.99".parse().unwrap())
            .is_none()
    );
    assert_eq!(reg.retained_len(), 2);
}

// #9388 — the interface-mode identity leaks on exactly the same key miss.
//
// `release_source_nat_allocation_with_mode` builds ONE `flow` and uses it for
// both the pool sweep and the interface-registry free 90 lines below, so a
// key that misses `live_by_flow` in the pool domain misses the interface
// registry identically. Interface-mode SNAT composed with a port-moving DNAT
// therefore held its translated identity for the node's lifetime, and the
// registry's capacity check (`allocate_interface_identity`, allocator.rs) is
// what eventually refuses new admissions.
//
// The admission runs through the real `match_source_nat_result_for_tuple`
// entry point on the POST-DNAT tuple (10.10.10.7:8443) — what `policy_dst_port`
// carries since #9034 — and the teardown through the INSTALLED session key
// (198.51.100.7:443).
//
// POSITIVE CONTROL, same run, same helpers: the address-only DNAT (no port
// move) frees. It is green on both sides of #9388 and is what separates "the
// release is broken" from "this fixture never minted anything".
#[test]
fn interface_snat_9388_release_frees_a_post_dnat_port_identity() {
    let rules = iface_rules();
    let post_dnat_dst = "10.10.10.7";
    let orig_dst = "198.51.100.7";

    // CONTROL: DNAT rewrites the ADDRESS only, so the wire port and the policy
    // port agree and the pre-#9388 key was already correct.
    {
        let reg = InterfaceNatAllocators::default();
        let mut nat = decision(admit(
            &reg,
            &rules,
            "10.0.61.101",
            5555,
            post_dnat_dst,
            443,
            PROTO_TCP_U8,
            false,
        ));
        nat.rewrite_dst = Some(post_dnat_dst.parse().unwrap());
        nat.rewrite_dst_port = None;
        let alloc = reg
            .allocator_if_present(EGRESS.parse().unwrap())
            .expect("the admission must have created the egress allocator");
        assert_eq!(alloc.live_flow_count(), 1);

        release_source_nat_allocation(
            &reg,
            &rules,
            &key("10.0.61.101", 5555, orig_dst, 443),
            nat,
            false,
            2_000,
        );
        assert_eq!(
            alloc.live_flow_count(),
            0,
            "CONTROL: an address-only DNAT must still free the identity"
        );
    }

    // UNDER TEST: the DNAT moves the port (443 -> 8443).
    let reg = InterfaceNatAllocators::default();
    let mut nat = decision(admit(
        &reg,
        &rules,
        "10.0.61.101",
        5555,
        post_dnat_dst,
        8443,
        PROTO_TCP_U8,
        false,
    ));
    nat.rewrite_dst = Some(post_dnat_dst.parse().unwrap());
    nat.rewrite_dst_port = Some(8443);
    let alloc = reg
        .allocator_if_present(EGRESS.parse().unwrap())
        .expect("the admission must have created the egress allocator");
    assert_eq!(
        alloc.live_flow_count(),
        1,
        "fixture premise: the admission recorded exactly one interface identity"
    );

    release_source_nat_allocation(
        &reg,
        &rules,
        // The INSTALLED session key: the ORIGINAL, pre-DNAT destination.
        &key("10.0.61.101", 5555, orig_dst, 443),
        nat,
        false,
        2_000,
    );
    assert_eq!(
        alloc.live_flow_count(),
        0,
        "#9388: the interface-mode identity free shares the pool sweep's `flow` \
         key, so it misses on the same pre-translation dst_port and holds the \
         translated identity for the node's lifetime"
    );
}

// #13944 (H10-02): an interface-mode preserve whose translated identity
// equals the firewall's own fixed-port control-plane tuple must be PAT'd
// off that port (or refused). An inside flow H:500->P:500 (and
// H:4500->P:4500) through interface SNAT must NOT mint (E:500, P:500) /
// (E:4500, P:4500), because that reverse identity is exactly the host-local
// IKE/NAT-T session key, which reverse-NAT install would replace. RED on
// base: UDP/500 and UDP/4500 are preserved.
#[test]
fn interface_snat_never_mints_own_fixed_control_ports_13944() {
    use crate::ip_proto::PROTO_UDP;
    for fixed in crate::nat::iface_registry::IFACE_RESERVED_UDP_PORTS {
        let reg = InterfaceNatAllocators::default();
        let rules = iface_rules();
        let d = decision(admit(
            &reg,
            &rules,
            "10.0.61.101",
            fixed,
            SERVER,
            fixed,
            PROTO_UDP,
            false,
        ));
        assert_eq!(d.rewrite_src, Some(EGRESS.parse::<IpAddr>().unwrap()));
        let port = d.rewrite_src_port.unwrap_or(fixed);
        let forward_key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: "10.0.61.101".parse().expect("inside"),
            dst_ip: SERVER.parse().expect("peer"),
            src_port: fixed,
            dst_port: fixed,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let local_delivery_key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: SERVER.parse().expect("peer"),
            dst_ip: EGRESS.parse().expect("egress"),
            src_port: fixed,
            dst_port: fixed,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        assert_ne!(
            crate::session::reverse_session_key(&forward_key, d),
            local_delivery_key,
            "the SNAT reverse companion must not alias the firewall's cached \
             LocalDelivery key for UDP/{fixed}"
        );
        let allocator = reg
            .allocator_for(EGRESS.parse().expect("egress"))
            .expect("interface allocator");
        let mut previous_snapshot = None;
        assert_eq!(
            allocator.reserve_interface_identity(
                SourceNatFlowKey {
                    protocol: PROTO_UDP,
                    src_ip: "10.0.61.101".parse().expect("inside"),
                    dst_ip: SERVER.parse().expect("peer"),
                    src_port: fixed,
                    dst_port: fixed,
                    routing_scope: 0,
                },
                EGRESS.parse().expect("egress"),
                fixed,
                1_000,
                NatHolder::Untracked,
                false,
                &mut previous_snapshot,
            ),
            super::allocator::InterfaceDomainReserve::IdentityConflict,
            "peer-synced interface SNAT must refuse the same local tuple"
        );
        assert_ne!(
            port, fixed,
            "interface SNAT minted the firewall's own fixed control-plane \
             identity (port {fixed}); it must be PAT'd off or refused"
        );
        assert!(
            (1024..=65535).contains(&port),
            "PAT'd control-plane flow must land in the ephemeral range, got {port}"
        );
    }
    // POSITIVE CONTROL: a non-reserved UDP source port still preserves.
    let reg = InterfaceNatAllocators::default();
    let rules = iface_rules();
    let ctrl = decision(admit(
        &reg,
        &rules,
        "10.0.61.101",
        54321,
        SERVER,
        54321,
        PROTO_UDP,
        false,
    ));
    assert_eq!(
        ctrl.rewrite_src_port, None,
        "non-reserved UDP/54321 must stay preserved (preserve-first unchanged)"
    );
}
