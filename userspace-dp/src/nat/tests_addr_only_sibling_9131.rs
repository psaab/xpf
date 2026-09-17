// #9131: the ADDRESS-ONLY PERSISTENT source-NAT allocator's behaviour when the
// translated reverse identity it wants is already owned.
//
// `reserve_address_only_persistent` returned `AllocatorExhausted` on that
// collision without ever looking at another pool address, while its sibling
// `reserve_address_only_roundrobin` does `continue` on the identical condition
// ("This address's reverse identity is owned by a DIFFERENT flow for this
// remote — try the next sibling instead of dropping").
//
// For a PORT-LESS protocol — GRE(47), ESP(50), ICMP — the identity degenerates
// to `(proto, translated_ip, 0, dst_ip, 0)`, so two tunnels from different
// subscribers to the SAME popular remote (a VPN concentrator, a cloud SASE
// endpoint) collide the moment they land on one pool address, and the second
// was denied while other pool addresses sat idle.
//
// WHAT IS NOT THE DEFECT, and why half this file is over-reach guards: the
// refusal is correct fail-CLOSED behaviour for the two PINNED cases. A blanket
// fallback — the shape the originating report asked for — would break BOTH
// `address-persistent` (the address is `sticky_pool_index(src_ip)`, a pure
// function of the source) and `persistent-nat` address pinning (an existing
// lease's address must not move for the permit scope's lifetime). Only the
// fresh-lease, `address-persistent`-off case may probe on.

use super::allocator::{NS_PER_SEC, PoolAddressFamily, PortAllocator, sticky_pool_index};
use super::source::{PersistentNatPermit, SourceNatFailureReason, SourceNatFlowKey};
use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_GRE;
use std::net::{IpAddr, Ipv4Addr};

const A1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const A2: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const REMOTE_R: &str = "8.8.8.8";
const REMOTE_S: &str = "9.9.9.9";
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

/// A PORT-LESS GRE flow: `src_port`/`dst_port` are 0, so the reverse identity
/// is `(47, translated_ip, 0, dst_ip, 0)` — the degenerate key the issue is
/// about.
fn gre_flow(src: &str, dst: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_GRE,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port: 0,
        dst_port: 0,
        routing_scope: 0,
    }
}

fn reserve(
    alloc: &PortAllocator,
    pool: &[Ipv4Addr],
    flow: SourceNatFlowKey,
    address_persistent: bool,
) -> Result<TranslatedTuple, SourceNatFailureReason> {
    alloc.reserve_address_only_persistent(
        flow,
        PoolAddressFamily::V4(pool),
        0,
        address_persistent,
        PersistentNatPermit::AnyRemoteHost,
        TIMEOUT_NS,
        NS_PER_SEC,
        NatHolder::Untracked,
    )
}

/// THE FIX. Three port-less flows over a TWO-address pool, `address-persistent`
/// OFF, `persistent-nat` ON:
///
///   F1 (S1 -> R)  round-robin index 0 -> A1, owns (GRE, A1, 0, R, 0)
///   F2 (S2 -> S)  index 1 -> A2, owns (GRE, A2, 0, S, 0)   [advances the counter]
///   F3 (S3 -> R)  index 2 % 2 == 0 -> A1, which F1 owns FOR THIS REMOTE
///
/// F3 must land on the free sibling A2 — `(GRE, A2, 0, R, 0)` is a different
/// identity from the one F2 holds, so the address is genuinely available.
///
/// The F1/F2 placement assertions are the FIXTURE claim, not decoration: they
/// are what establishes that F3's preferred index is 0 (= A1, owned) rather
/// than an untaken address, which is the only arrangement in which the fallback
/// is exercised at all.
///
/// RED at master: F3 returns `AllocatorExhausted`.
#[test]
fn address_only_persistent_fresh_lease_probes_free_sibling_9131() {
    let pool = [A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    let t1 = reserve(&alloc, &pool, gre_flow("10.0.1.100", REMOTE_R), false)
        .expect("F1 must mint on the first pool address");
    assert_eq!(
        t1.ip,
        IpAddr::V4(A1),
        "fixture: F1 takes round-robin index 0"
    );
    assert_eq!(t1.port, 0, "a port-less flow carries no translated port");

    let t2 = reserve(&alloc, &pool, gre_flow("10.0.1.101", REMOTE_S), false)
        .expect("F2 goes to a DIFFERENT remote, so it cannot collide");
    assert_eq!(
        t2.ip,
        IpAddr::V4(A2),
        "fixture: F2 advances the round-robin counter onto A2"
    );

    let t3 = reserve(&alloc, &pool, gre_flow("10.0.1.102", REMOTE_R), false).expect(
        "F3's preferred address A1 is owned by F1 for this remote, but A2 is \
         free for it — a fresh, non-sticky lease must probe on instead of \
         reporting exhaustion (#9131)",
    );
    assert_eq!(
        t3.ip,
        IpAddr::V4(A2),
        "F3 must land on the FREE sibling A2, not exhaust on the owned A1"
    );
    assert_ne!(t3.ip, t1.ip, "F3 must not be handed F1's reverse identity");

    // Three distinct reverse identities, one owner each — the fallback must not
    // weaken the #5269 uniqueness guarantee it routes around.
    let owners = alloc.debug_address_only_owners();
    assert_eq!(
        owners.len(),
        3,
        "F1, F2 and F3 each own a distinct identity"
    );
    let mut keys: Vec<(IpAddr, IpAddr)> = owners
        .iter()
        .map(|(k, _)| (k.translated_ip, k.dst_ip))
        .collect();
    keys.sort_by_key(|(a, b)| (a.to_string(), b.to_string()));
    keys.dedup();
    assert_eq!(keys.len(), 3, "no two owners may share a reverse identity");
}

/// The LEASE must record the address the flow actually got, not the one it
/// first tried. Otherwise every later flow keyed to the same persistent source
/// would be pinned to an address it was never placed on, and `persistent-nat`
/// would hand out a translation that contradicts the live token.
///
/// RED on a fix that probes for the token but leaves the lease on the
/// originally-chosen address.
#[test]
fn the_sibling_fallback_pins_the_lease_to_the_address_it_used_9131() {
    let pool = [A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    reserve(&alloc, &pool, gre_flow("10.0.1.100", REMOTE_R), false).expect("F1");
    reserve(&alloc, &pool, gre_flow("10.0.1.101", REMOTE_S), false).expect("F2");
    let t3 = reserve(&alloc, &pool, gre_flow("10.0.1.102", REMOTE_R), false).expect("F3");
    assert_eq!(t3.ip, IpAddr::V4(A2), "fixture: F3 used the sibling");

    let live = alloc.debug_live();
    let f3_key =
        gre_flow("10.0.1.102", REMOTE_R).persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let lease = live
        .persistent_by_source
        .get(&f3_key)
        .copied()
        .expect("F3 must have created a lease");
    assert_eq!(
        lease.translated.ip,
        IpAddr::V4(A2),
        "the lease must pin the address the flow was PLACED on"
    );
    assert_eq!(
        lease.addr_index, 1,
        "the lease's addr_index must be the sibling's, not the first probe's"
    );
    assert!(
        lease.address_only,
        "an address-only lease holds no pool port"
    );
}

/// OVER-REACH GUARD 1 — `address-persistent`. The address is
/// `sticky_pool_index(src_ip, pool_len)`, a pure function of the source, so
/// probing on would break the contract the operator configured. The sibling
/// `reserve_address_only_roundrobin` likewise sets `address_attempts = 1` here.
///
/// The two sources are SEARCHED for at runtime rather than hardcoded: what
/// matters is that they share a sticky slot, and the hash is not something a
/// literal should silently depend on.
///
/// GREEN at master; RED under the blanket fallback the originating report
/// asked for.
#[test]
fn an_address_persistent_collision_still_exhausts_9131() {
    let pool = [A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    // Two DIFFERENT sources that hash to the SAME sticky slot.
    let mut pair: Option<(String, String)> = None;
    'outer: for a in 1u8..64 {
        for b in (a + 1)..64 {
            let ia = IpAddr::V4(Ipv4Addr::new(10, 0, 1, a));
            let ib = IpAddr::V4(Ipv4Addr::new(10, 0, 1, b));
            if sticky_pool_index(ia, pool.len()) == sticky_pool_index(ib, pool.len()) {
                pair = Some((format!("10.0.1.{a}"), format!("10.0.1.{b}")));
                break 'outer;
            }
        }
    }
    let (src_a, src_b) = pair.expect("fixture: two sources must share a sticky slot");

    let t1 = reserve(&alloc, &pool, gre_flow(&src_a, REMOTE_R), true)
        .expect("the first sticky source must mint");
    let denied = reserve(&alloc, &pool, gre_flow(&src_b, REMOTE_R), true);
    assert_eq!(
        denied.err(),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "an address-persistent pool must NOT rotate off its sticky address — \
         probing on would break the contract the operator configured (#9131 \
         narrowing)"
    );

    // The sibling really was free: that is what makes this a guard rather than
    // a restatement of "the pool was full".
    let sibling = if t1.ip == IpAddr::V4(A1) { A2 } else { A1 };
    let owners = alloc.debug_address_only_owners();
    assert_eq!(owners.len(), 1, "the denied flow minted no token");
    assert!(
        !owners
            .iter()
            .any(|(k, _)| k.translated_ip == IpAddr::V4(sibling)),
        "fixture: {sibling} must be unowned, or this cell proves nothing"
    );
    {
        let live = alloc.debug_live();
        assert_eq!(live.persistent_by_source.len(), 1, "no second lease");
    }
}

/// OVER-REACH GUARD 2 — an EXISTING lease. Its address is pinned by
/// `persistent-nat` for the permit scope's lifetime and must not move.
///
/// #10018 changes the old cross-scope premise: routing scope is now part of
/// `PersistentSourceKey`, so a second VRF must no longer reuse this lease.
/// Keep this guard in ONE scope instead. Two same-scope GRE flows to different
/// remotes still share the `permit-any-remote-host` lease, and that existing
/// lease must stay pinned to its original address rather than probing a sibling.
///
/// GREEN at master; RED if the persistent lease is accidentally re-keyed by
/// remote endpoint or if reuse is allowed to move the translated address.
#[test]
fn a_same_scope_reused_lease_stays_pinned_9131() {
    let pool = [A1, A2];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    let base = gre_flow("10.0.1.100", REMOTE_R);
    let t1 = reserve(&alloc, &pool, base, false).expect("the first flow must mint");
    assert_eq!(t1.ip, IpAddr::V4(A1), "fixture: round-robin index 0");

    let same_scope_other_remote = gre_flow("10.0.1.100", REMOTE_S);
    assert_eq!(
        same_scope_other_remote.routing_scope, base.routing_scope,
        "fixture: both flows stay in one routing scope"
    );
    assert_eq!(
        same_scope_other_remote.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        base.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        "permit-any-remote-host must share the existing lease within one scope"
    );

    let reused = reserve(&alloc, &pool, same_scope_other_remote, false)
        .expect("a same-scope any-remote flow must reuse its persistent lease");
    assert_eq!(
        reused, t1,
        "reusing a pinned lease must keep the original translated tuple"
    );
    let owners = alloc.debug_address_only_owners();
    assert_eq!(owners.len(), 2, "the two remote reverse identities are both live");
    assert!(
        owners
            .iter()
            .all(|(k, _)| k.translated_ip == IpAddr::V4(A1)),
        "reuse must not move the existing lease onto sibling A2"
    );
    {
        let live = alloc.debug_live();
        let lease = live
            .persistent_by_source
            .values()
            .next()
            .expect("one same-scope lease");
        assert_eq!(
            lease.translated.ip,
            IpAddr::V4(A1),
            "the pinned address must be untouched by reuse"
        );
        assert_eq!(
            lease.active_flows, 2,
            "both same-scope flows must credit the one reused lease"
        );
    }
}

/// A ONE-address pool has no sibling to probe, so the collision is REAL
/// exhaustion and must stay a refusal. This is the shape
/// `notrans_persistent_collision_guard_denies_conflicting_owner_6041` already
/// pins through the match path; it is restated here on the direct entry point
/// so the fallback loop's terminating condition is bound next to the loop.
#[test]
fn a_single_address_pool_collision_is_real_exhaustion_9131() {
    let pool = [A1];
    let alloc = PortAllocator::new(pool.len(), 1024, 65535);

    reserve(&alloc, &pool, gre_flow("10.0.1.100", REMOTE_R), false).expect("F1 mints on A1");
    let denied = reserve(&alloc, &pool, gre_flow("10.0.1.101", REMOTE_R), false);
    assert_eq!(
        denied.err(),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "with no sibling address the collision is genuine exhaustion"
    );
    assert_eq!(alloc.debug_address_only_owners().len(), 1);
}

/// END-TO-END through the real match path, so the fallback is bound to the
/// WIRING and not only to the allocator entry point. Same pool shape, driven by
/// `match_source_nat_result_for_tuple` with a `persistent-nat` +
/// `port no-translation` rule.
///
/// RED at master: the second flow returns
/// `Unavailable(AllocatorExhausted)` and `expect_matched` panics.
#[test]
fn address_only_persistent_sibling_fallback_end_to_end_9131() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "notrans-persist".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "np-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string(), "203.0.113.2/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        persistent_nat: true,
        persistent_nat_permit: "any-remote-host".to_string(),
        persistent_nat_inactivity_timeout: 300,
        address_persistent: false,
        ..SourceNATRuleSnapshot::default()
    }]);

    let lookup = |src: &str, dst: &str| -> SourceNatLookup {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().expect("src"),
            dst.parse().expect("dst"),
            Some(PROTO_GRE),
            0,
            0,
            None,
            None,
            NS_PER_SEC,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        )
    };
    let expect_matched = |l: SourceNatLookup, who: &str| -> NatDecision {
        match l {
            SourceNatLookup::Matched(d) => d,
            other => panic!("{who} must be translated, got {other:?}"),
        }
    };

    let d1 = expect_matched(lookup("10.0.1.100", REMOTE_R), "F1");
    let d2 = expect_matched(
        lookup("10.0.1.101", REMOTE_R),
        "F2 (a second port-less tunnel to the SAME remote)",
    );
    assert_ne!(
        d1.rewrite_src, d2.rewrite_src,
        "the two subscribers must be placed on DIFFERENT pool addresses — one \
         tunnel to a popular remote must not deny another while a pool address \
         sits idle (#9131)"
    );
    assert_eq!(
        d1.rewrite_src_port, None,
        "port-less GRE keeps its wire port"
    );
    assert_eq!(
        d2.rewrite_src_port, None,
        "port-less GRE keeps its wire port"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        2,
        "both flows own a distinct reverse identity"
    );
    // Binds this cell to the PERSISTENT path specifically. Without it the cell
    // is blind to the wiring: disabling the `rule.persistent_nat` branch sends
    // these flows to `reserve_address_only_roundrobin`, which ALSO probes
    // siblings, so every assertion above still passes. Only the roundrobin path
    // creates no lease.
    {
        let live = rules[0].pool_allocator.debug_live();
        assert_eq!(
            live.persistent_by_source.len(),
            2,
            "each subscriber must hold an address-only PERSISTENT lease — this \
             is the persistent branch, not the #6226 round-robin one"
        );
        assert!(
            live.persistent_by_source.values().all(|l| l.address_only),
            "an address-only lease holds no pool port"
        );
    }
    // Address-only tokens are off the port bitmap.
    assert_eq!(source_nat_pool_statuses(&rules)[0].used_ports, 0);
    assert_eq!(source_nat_pool_statuses(&rules)[0].live_flows, 2);
}
