// #6979 F6 — two source-NAT pools over one address are two occupancy domains.
//
// # What was measured before any of this was designed
//
// F6 as filed says a MATCH-ONLY rule edit "strands a reservation in an
// allocator that can no longer match the flow, while the rule that now owns it
// is free to reissue the tuple". Three probes against master, with
// single-address pools and a ONE-port range so a duplicate is unambiguous:
//
// | probe | construction | master |
// |---|---|---|
// | P1 | pools `a` and `b` both `[203.0.113.1]`, then a match-only edit moves the flow from r1 to r2 | flow 2 gets the IDENTICAL `203.0.113.1:20000` flow 1 still holds |
// | P2 | the same two pools, NO edit at all | the same duplicate |
// | P3 | ONE pool, the same match-only edit | `AllocatorExhausted` — no defect |
//
// P3 is the correction that decided the fix. The key's ignorance of match
// criteria and zone scope is harmless on its own: a match-only edit changes
// none of `(pool name, addresses, range)`, the allocator is reused by `Arc`,
// and its live reservation keeps refusing the tuple. Adding match criteria to
// the key — F6's own suggestion — would have broken exactly that and fixed
// nothing.
//
// P2 is the defect: the edit is not load-bearing. What produces the duplicate
// is that two DISTINCT allocator keys can cover one pool address, so that
// address carries two independent occupancy bitmaps and neither can see the
// other's reservations.
//
// # What this file binds
//
// The mint-time peer check: a pool-mode allocation that lands on a
// `(pool address, port)` a PEER pool already owns is rolled back and failed
// instead of published. Every cell names the input that makes it fire, and the
// controls are what stop the check from becoming "refuse the second pool" —
// overlapping pools are a shape this dataplane deliberately supports (#6211's
// pass-1 narrowing and #6876's release sweep both exist for it), so nothing may
// stop translating that is not an actual duplicate.

use super::allocator::{NatHolder, TranslatedTuple};
use super::destination::PROTO_TCP;
use super::source::{SourceNatFlowKey, SourceNatRule};
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::{IpAddr, Ipv4Addr};

const SHARED: &str = "203.0.113.1";
const OTHER: &str = "203.0.113.9";
const REMOTE: &str = "8.8.8.8";

/// One pool-mode rule. A ONE-port range makes "did the second flow get the
/// identity the first one holds" a yes/no question rather than a probability.
fn rule(name: &str, pool: &str, source: &str, addr: &str) -> SourceNATRuleSnapshot {
    rule_ports(name, pool, source, addr, 20000, 20000)
}

fn rule_ports(
    name: &str,
    pool: &str,
    source: &str,
    addr: &str,
    port_low: u16,
    port_high: u16,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{addr}/32")],
        port_low,
        port_high,
        ..SourceNATRuleSnapshot::default()
    }
}

/// The v6 twin of [`rule`]. The IPv6 PAT mint is a SEPARATE arm of
/// `match_source_nat_result_for_tuple` with its own `allocate_translation`
/// call, so a check wired only into the v4 arm passes every v4 cell in this
/// file. Measured: removing the v6 call alone escapes all seven of them.
fn rule_v6(name: &str, pool: &str, source: &str, addr: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{addr}/128")],
        port_low: 20000,
        port_high: 20000,
        ..SourceNATRuleSnapshot::default()
    }
}

fn mint(rules: &[SourceNatRule], src: &str, src_port: u16) -> SourceNatLookup {
    mint_to(rules, src, src_port, REMOTE)
}

fn mint_to(rules: &[SourceNatRule], src: &str, src_port: u16, dst: &str) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        dst.parse().expect("dst"),
        Some(PROTO_TCP),
        src_port,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

/// The translated `(address, port)` a decision carries, or `None` when the
/// lookup did not mint one.
fn identity(lookup: &SourceNatLookup) -> Option<(IpAddr, Option<u16>)> {
    match lookup {
        SourceNatLookup::Matched(d) => d.rewrite_src.map(|ip| (ip, d.rewrite_src_port)),
        _ => None,
    }
}

fn failure_reason(lookup: &SourceNatLookup) -> Option<SourceNatFailureReason> {
    match lookup {
        SourceNatLookup::Unavailable(f) => Some(f.reason),
        _ => None,
    }
}

fn flow(src: &str, src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: REMOTE.parse().expect("dst"),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn shared_tuple(port: u16) -> TranslatedTuple {
    TranslatedTuple {
        ip: SHARED.parse().expect("shared"),
        port,
    }
}

// ---------------------------------------------------------------------------
// THE BINDING — probe P2, verbatim.
// ---------------------------------------------------------------------------

/// RED AT MASTER. Two pools over one address each mint `203.0.113.1:20000` for
/// a different live flow: one wire identity, two sessions, replies the reverse
/// index cannot attribute.
///
/// Fires on: deleting `quarantine_overlapping_pool_keys`. The second flow then
/// reaches pool `b`'s own empty occupancy bitmap and is handed the identity
/// pool `a` is holding.
#[test]
fn overlapping_pools_do_not_both_mint_one_identity_6979() {
    let rules = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24", SHARED),
        rule("r2", "b", "10.1.0.0/24", SHARED),
    ]);

    let first = mint(&rules, "10.0.0.7", 1111);
    let first_identity = identity(&first).expect("the FIRST pool must still translate");
    assert_eq!(
        first_identity,
        (SHARED.parse::<IpAddr>().unwrap(), Some(20000)),
        "fixture: flow 1 must take the single identity of the shared address"
    );

    let second = mint(&rules, "10.1.0.7", 2222);
    assert_ne!(
        identity(&second),
        Some(first_identity),
        "pool {:?} handed out {:?} — the identity pool {:?} is holding for a live \
         flow. Two pools over one address are two independent occupancy bitmaps, \
         each blind to the other, so both mint the same (address, port) and the \
         replies to two sessions arrive on one reverse tuple (#6979 F6)",
        "b",
        first_identity,
        "a",
    );
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the colliding mint must fail CLOSED with its own reason, not translate and \
         not fall through to a different failure that would hide it"
    );
}

/// F6's own construction — the match-only edit — with the correction that it is
/// not what causes the duplicate. Two things are asserted together because the
/// pair is the whole point: the edit must NOT cost the live reservation
/// (carryover is what a wider key would have broken), and it must not produce a
/// second minting domain either.
///
/// Fires on: deleting the quarantine (second flow gets the duplicate), OR
/// adding match criteria to `SourceNatPoolAllocatorKey` (the first assertion
/// drops to 0 — the allocator is not found and the live flow is freed).
#[test]
fn a_match_only_edit_keeps_the_reservation_and_mints_no_second_identity_6979() {
    let counters = NatCounterStore::default();
    let gen1 = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24", SHARED),
        rule("r2", "b", "10.0.0.0/24", SHARED),
    ]);
    let first = mint(&gen1, "10.0.0.7", 1111);
    let first_identity = identity(&first).expect("flow 1 must translate");

    // MATCH-ONLY edit: r1's `source-address` no longer covers 10.0.0.0/24.
    // Pool name, addresses and port range are untouched, so the allocator key
    // is untouched.
    let gen2 = parse_source_nat_rules_with_previous(
        &[
            rule("r1", "a", "10.9.0.0/24", SHARED),
            rule("r2", "b", "10.0.0.0/24", SHARED),
        ],
        Some(&gen1),
        &counters,
        0,
    );
    assert_eq!(
        gen2[0].pool_allocator.live_flow_count(),
        1,
        "the match-only edit lost pool a's live reservation. Retention must stay \
         WIDER than minting: the key is (pool name, addresses, port range) and none \
         of the three changed, so the allocator must be carried over by Arc and keep \
         holding {first_identity:?} (#6979 F6, #7717)"
    );

    let second = mint(&gen2, "10.0.0.8", 2222);
    assert_ne!(
        identity(&second),
        Some(first_identity),
        "after the edit the flow matches r2, whose pool is a SECOND occupancy domain \
         over the same address, and it was handed the identity r1's pool still holds"
    );
}


// ---------------------------------------------------------------------------
// The check must refuse the DUPLICATE, and nothing else.
// ---------------------------------------------------------------------------

/// The overlapping pool is NOT failed closed as a pool: it keeps translating,
/// it just cannot publish an identity its peer owns.
///
/// Fires on: any fix that disables the second pool (a `pool_failure`
/// quarantine, an apply-time refusal). #6211's pass-1 narrowing exists because
/// two rules with overlapping pools in separate allocators is a state the
/// standby must RESOLVE, and #6876's release sweep frees from every allocator
/// for the same reason — a fix that stops the pool translating inverts both.
#[test]
fn an_overlapping_pool_still_mints_an_identity_its_peer_does_not_own_6979() {
    let rules = parse_source_nat_rules(&[
        rule_ports("r1", "a", "10.0.0.0/24", SHARED, 20000, 20001),
        rule_ports("r2", "b", "10.1.0.0/24", SHARED, 20000, 20001),
    ]);
    assert_eq!(
        (rules[0].pool_failure, rules[1].pool_failure),
        (None, None),
        "overlapping pools must both stay USABLE — the duplicate is what is refused, \
         not the pool"
    );
    let first = identity(&mint(&rules, "10.0.0.7", 1111)).expect("pool a must translate");

    // The peer's first attempt lands on the identity pool `a` is holding and is
    // refused. Its allocator cursor has moved on, so the NEXT flow finds the
    // free port and translates.
    assert_eq!(
        failure_reason(&mint(&rules, "10.1.0.7", 2222)),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "fixture: the peer's first mint must be the colliding one"
    );
    let third = identity(&mint(&rules, "10.1.0.8", 3333))
        .expect("the peer must still be able to mint a port its peer does not own");
    assert_ne!(
        third, first,
        "the peer's next mint must be a DIFFERENT identity"
    );
}

/// CONTROL. Two rules naming ONE pool are one allocator and one occupancy
/// domain — the thing the key exists to produce. They must not be peers of each
/// other.
///
/// Fires on: comparing allocator KEYS (or pool names) instead of allocator
/// INSTANCES when deciding who is a peer — or, worse, treating every rule
/// sharing an address as a peer. Either makes a rule check its own bitmap,
/// which it has just set, so EVERY mint on the shared pool is refused. That is
/// invisible in every other cell here (each uses one rule per pool) and would
/// fail closed on the ordinary multi-rule single-pool config.
#[test]
fn two_rules_naming_one_pool_are_not_peers_6979() {
    let rules = parse_source_nat_rules(&[
        rule_ports("r1", "a", "10.0.0.0/24", SHARED, 20000, 20001),
        rule_ports("r2", "a", "10.1.0.0/24", SHARED, 20000, 20001),
    ]);
    assert!(
        rules[0].overlap_owners.is_none() && rules[1].overlap_owners.is_none(),
        "two rules naming one pool share an allocator and are ONE occupancy domain"
    );
    let first = identity(&mint(&rules, "10.0.0.7", 1111)).expect("rule 1 must translate");
    let second = identity(&mint(&rules, "10.1.0.7", 2222)).expect("rule 2 must translate");
    assert_ne!(
        first, second,
        "sharing one allocator is what makes the two rules hand out DIFFERENT ports \
         off the same address"
    );
}

/// CONTROL. Pools on different addresses are independent by construction and
/// must be wired with no peers at all — the empty-`Vec` fast path every valid
/// config takes.
///
/// Fires on: a peer relation keyed on "another pool-mode rule exists" rather
/// than on an actual shared address.
#[test]
fn disjoint_pools_are_not_peers_6979() {
    let rules = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24", SHARED),
        rule("r2", "b", "10.1.0.0/24", OTHER),
    ]);
    assert!(
        rules[0].overlap_owners.is_none() && rules[1].overlap_owners.is_none(),
        "non-overlapping pools must carry NO shared-address index — this is every \
         config a strict commit accepts, and the mint path there must pay only an \
         Option::is_none"
    );
    assert!(identity(&mint(&rules, "10.0.0.7", 1111)).is_some());
    assert!(identity(&mint(&rules, "10.1.0.7", 2222)).is_some());
}

/// The refused mint must not LEAK the port it briefly held. The rollback is
/// what makes the refusal free rather than a slow exhaustion of the pool.
///
/// Fires on: returning the failure without rolling back. The peer's allocator
/// then keeps `live_flow_count() == 1` for a flow that was never published, and
/// nothing will ever release it — the teardown sweep only fires for a session
/// that exists.
#[test]
fn a_refused_mint_leaves_no_reservation_behind_6979() {
    let rules = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24", SHARED),
        rule("r2", "b", "10.1.0.0/24", SHARED),
    ]);
    assert!(identity(&mint(&rules, "10.0.0.7", 1111)).is_some());
    assert_eq!(
        failure_reason(&mint(&rules, "10.1.0.7", 2222)),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "fixture: the peer's mint must be refused"
    );
    assert_eq!(
        rules[1].pool_allocator.live_flow_count(),
        0,
        "the refused mint left a reservation in the peer's allocator. Nothing releases \
         it: the flow was never published, so no session teardown will ever name it, \
         and the port is held for the life of the allocator (#6979 F6)"
    );
}

/// The refusal is per-IDENTITY, not per-address: once the peer's flow releases,
/// the same identity becomes mintable again.
///
/// Fires on: refusing on "the peer's pool covers this address" or "the peer has
/// any live flow" rather than on the peer holding THIS `(address, port)`. Both
/// look identical while the peer holds the tuple; only this cell separates them.
#[test]
fn the_identity_is_mintable_again_once_the_peer_releases_it_6979() {
    let rules = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24", SHARED),
        rule("r2", "b", "10.1.0.0/24", SHARED),
    ]);
    let held = identity(&mint(&rules, "10.0.0.7", 1111)).expect("pool a must translate");
    assert_eq!(
        failure_reason(&mint(&rules, "10.1.0.7", 2222)),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "fixture: the peer must be refused while pool a holds the identity"
    );

    // The ordinary teardown: pool a's session goes away.
    assert!(
        rules[0].pool_allocator.release_flow(
            flow("10.0.0.7", 1111),
            shared_tuple(20000),
            0,
            NatHolder::Untracked,
        ),
        "fixture: pool a's flow must actually release"
    );

    assert_eq!(
        identity(&mint(&rules, "10.1.0.7", 2222)),
        Some(held),
        "once the peer has released the identity it must be mintable again. A refusal \
         keyed on the ADDRESS rather than the identity never lifts, which is a \
         permanent outage wearing the shape of a collision guard"
    );
}

/// The IPv6 PAT arm is a SEPARATE `allocate_translation` call site, so it needs
/// its own cell: every other cell in this file is v4 and a check wired only
/// into the v4 arm passes all of them.
///
/// Fires on: removing the peer check from the v6 arm. Measured — that mutation
/// escaped the whole v4 suite before this cell existed.
#[test]
fn overlapping_v6_pools_do_not_both_mint_one_identity_6979() {
    const SHARED_V6: &str = "2001:db8::1";
    const REMOTE_V6: &str = "2001:4860:4860::8888";
    let rules = parse_source_nat_rules(&[
        rule_v6("r1", "a", "2001:db8:1::/48", SHARED_V6),
        rule_v6("r2", "b", "2001:db8:2::/48", SHARED_V6),
    ]);
    let first = identity(&mint_to(&rules, "2001:db8:1::7", 1111, REMOTE_V6))
        .expect("the first v6 pool must translate");
    assert_eq!(
        first,
        (SHARED_V6.parse::<IpAddr>().unwrap(), Some(20000)),
        "fixture: flow 1 must take the single identity of the shared v6 address"
    );

    let second = mint_to(&rules, "2001:db8:2::7", 2222, REMOTE_V6);
    assert_ne!(
        identity(&second),
        Some(first),
        "the v6 peer pool published the identity the first pool is holding for a live \
         flow — the same duplicate as the v4 arm, on the call site the v4 cells cannot \
         reach (#6979 F6)"
    );
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the colliding v6 mint must fail closed with the same reason as the v4 arm"
    );
}

/// The DETERMINISTIC-CGNAT (mode 1) arm is a third `allocate_*` call site with
/// its own `SourceNatLookup::Matched` return, so it needs its own cell for the
/// same reason the v6 arm does — measured, removing the check from this arm
/// alone escapes every other cell in this file.
///
/// Two pools over one address with DIFFERENT `host address` bases map different
/// subscribers onto the SAME external block: the deterministic parameters are
/// not part of the allocator key, so the two pools cannot see that they have
/// computed the same identity.
///
/// LIMITATION PINNED BY `a_deterministic_collision_refuses_the_subscriber_6979`
/// below: the refusal costs the colliding subscriber its whole block, not just
/// the one port, because `allocate_deterministic_v4` restarts its scan at the
/// block's first port on every call. Fail-closed on an invalid config, but say
/// so rather than let the word "refused" imply the sibling port is tried.
#[test]
fn overlapping_deterministic_pools_do_not_both_mint_one_identity_6979() {
    fn det_rule(name: &str, pool: &str, source: &str, host_base: &str) -> SourceNATRuleSnapshot {
        SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![source.to_string()],
            pool_name: pool.to_string(),
            pool_addresses: vec![format!("{SHARED}/32")],
            port_low: 20000,
            port_high: 20255,
            deterministic_mode: 1,
            deterministic_block_size: 1,
            deterministic_blocks_per_ip: 256,
            deterministic_host_base: u32::from(
                host_base.parse::<std::net::Ipv4Addr>().expect("host base"),
            ),
            deterministic_host_count: 256,
            ..SourceNATRuleSnapshot::default()
        }
    }

    let rules = parse_source_nat_rules(&[
        det_rule("r1", "a", "10.0.0.0/24", "10.0.0.0"),
        det_rule("r2", "b", "10.1.0.0/24", "10.1.0.0"),
    ]);
    assert!(
        rules[0].deterministic_v4.is_some() && rules[1].deterministic_v4.is_some(),
        "fixture: both rules must build a deterministic (mode 1) pool"
    );

    // Subscriber offset 7 in each pool's own host range, so both resolve to
    // block 7 of the SAME shared external address.
    let first = identity(&mint(&rules, "10.0.0.7", 1111)).expect("pool a must translate");
    let second = mint(&rules, "10.1.0.7", 2222);
    assert_ne!(
        identity(&second),
        Some(first),
        "the deterministic peer published the identity pool a is holding for a live \
         flow. Two deterministic pools over one address compute blocks from their own \
         `host address` base, which is not part of the allocator key, so neither can \
         see that it produced the same (address, port) (#6979 F6)"
    );
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the colliding deterministic mint must fail closed with the same reason as the \
         round-robin arms"
    );
}

/// LIMITATION PIN, not a guarantee — read the name before the assertions.
///
/// `allocate_deterministic_v4` restarts its scan at the subscriber's block
/// start on every call, and the peer-conflict rollback frees the bit without
/// recycling it, so a subscriber whose block START port is owned by a peer pool
/// is refused on EVERY later flow even when the rest of its block is free. The
/// retry that would step past it is not expressible with the current allocator
/// API: `allocate_deterministic_v4` is idempotent per flow key, so a second
/// call for the same flow returns the same tuple, and holding the rejected port
/// claimed across retries has no public entry point.
///
/// Pinned rather than fixed because the direction is the project's stated one —
/// at master this subscriber receives a DUPLICATE identity instead, which is
/// mis-delivery — and because the config is one the Go #5144 strict gate
/// rejects at commit. Raised by Codex round 1 on PR #8111, finding 5.
#[test]
fn a_deterministic_collision_refuses_the_subscriber_6979() {
    fn det_rule(name: &str, pool: &str, source: &str, host_base: &str) -> SourceNATRuleSnapshot {
        SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![source.to_string()],
            pool_name: pool.to_string(),
            pool_addresses: vec![format!("{SHARED}/32")],
            port_low: 20000,
            port_high: 20255,
            deterministic_mode: 1,
            // Block size 4, so the subscriber has three FREE sibling ports the
            // scan never reaches. A block size of 1 would make this cell
            // indistinguishable from "the block really was full".
            deterministic_block_size: 4,
            deterministic_blocks_per_ip: 64,
            deterministic_host_base: u32::from(
                host_base.parse::<std::net::Ipv4Addr>().expect("host base"),
            ),
            deterministic_host_count: 64,
            ..SourceNATRuleSnapshot::default()
        }
    }

    let rules = parse_source_nat_rules(&[
        det_rule("r1", "a", "10.0.0.0/24", "10.0.0.0"),
        det_rule("r2", "b", "10.1.0.0/24", "10.1.0.0"),
    ]);
    // Pool a's subscriber takes the block-start port of block 1.
    let held = identity(&mint(&rules, "10.0.0.1", 1111)).expect("pool a must translate");

    // Pool b's subscriber maps to the SAME block. Its block-start port is taken,
    // and the three siblings are free — but it is refused anyway, on this flow
    // and on every later one.
    for attempt in 0..3 {
        let blocked = mint(&rules, "10.1.0.1", 2000 + attempt);
        assert_eq!(
            identity(&blocked),
            None,
            "attempt {attempt}: the deterministic collider must never publish {held:?}"
        );
        assert_eq!(
            failure_reason(&blocked),
            Some(SourceNatFailureReason::PoolPeerAddressOverlap),
            "attempt {attempt}: and it is refused for the peer-overlap reason, not \
             exhaustion — the block is NOT full, three sibling ports are free. This \
             is the pinned limitation, not the desired behaviour (#6979 F6)"
        );
    }
}


/// MIXED FAMILY. A peer pool whose shared address is v6 while it ALSO carries a
/// v4 address must be probed at `v4_len + position`, not at `position`.
///
/// Fires on: `index: v4_len + pos` -> `index: pos` in `wire_overlap_peers`.
/// Every other cell here is v4-only or v6-ONLY, and a v6-only peer has
/// `v4_len == 0`, which makes that mutation a no-op — measured: Codex round 2
/// on PR #8111 supplied it as a mutation the eight-cell matrix misses, and it
/// did.
#[test]
fn a_mixed_family_peers_v6_index_is_offset_past_its_v4_addresses_6979() {
    const SHARED_V6: &str = "2001:db8::1";
    const REMOTE_V6: &str = "2001:4860:4860::8888";

    fn mixed_rule(
        name: &str,
        pool: &str,
        source: &str,
        addrs: &[&str],
    ) -> SourceNATRuleSnapshot {
        SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![source.to_string()],
            pool_name: pool.to_string(),
            pool_addresses: addrs.iter().map(|a| a.to_string()).collect(),
            port_low: 20000,
            port_high: 20000,
            ..SourceNATRuleSnapshot::default()
        }
    }

    // Pool b carries a v4 address FIRST, so the shared v6 address sits at
    // occupancy slot 1, not slot 0. Pool a is v6-only, so its own index is 0 —
    // the two disagree, which is the whole point.
    let rules = parse_source_nat_rules(&[
        mixed_rule(
            "r2",
            "b",
            "2001:db8:2::/48",
            &[&format!("{OTHER}/32"), &format!("{SHARED_V6}/128")],
        ),
        mixed_rule("r1", "a", "2001:db8:1::/48", &[&format!("{SHARED_V6}/128")]),
    ]);
    assert_eq!(
        rules[0].pool_addresses_v4.len(),
        1,
        "fixture: the peer must carry a v4 address, or v4_len is 0 and the offset \
         cannot be wrong"
    );
    assert_eq!(rules[0].pool_addresses_v6.len(), 1);

    // The mixed peer takes the shared v6 identity first.
    let held = identity(&mint_to(&rules, "2001:db8:2::7", 2222, REMOTE_V6))
        .expect("the mixed-family peer must translate");
    assert_eq!(held.0, SHARED_V6.parse::<IpAddr>().unwrap());

    let attempt = mint_to(&rules, "2001:db8:1::7", 1111, REMOTE_V6);
    assert_ne!(
        identity(&attempt),
        Some(held),
        "the v6-only pool published {held:?}, which the mixed-family peer holds at \
         occupancy slot v4_len + 0. Probing slot 0 reads the peer's unrelated V4 \
         bitmap, finds it free, and publishes the duplicate (#6979 F6)"
    );
    assert_eq!(
        failure_reason(&attempt),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
    );
}

/// #10700: duplicate and overlapping source-pool members expand only once.
///
/// Duplicate positions each had a distinct occupancy bitmap, allowing two
/// same-remote flows to mint the identical `(address, port_low)` reverse tuple.
/// Expansion now keeps the first occurrence of each address, so the allocator
/// has one slot and allocates distinct ports for the two flows. Rust's reported
/// address count is checked here too because Go's pool alarm uses it as the
/// capacity denominator.
///
/// Fires on revert: restoring append-only expansion produces two pool positions
/// and both flows receive `(203.0.113.1, 20000)`.
#[test]
fn duplicate_pool_members_mint_distinct_ports_10700() {
    fn dup_rule() -> SourceNATRuleSnapshot {
        SourceNATRuleSnapshot {
            name: "r1".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "a".to_string(),
            pool_addresses: vec![format!("{SHARED}/32"), format!("{SHARED}/32")],
            port_low: 20000,
            port_high: 20001,
            ..SourceNATRuleSnapshot::default()
        }
    }

    let rules = parse_source_nat_rules(&[dup_rule()]);
    assert_eq!(
        rules[0].pool_addresses_v4,
        vec![SHARED.parse::<Ipv4Addr>().unwrap()]
    );
    assert!(
        rules[0].pool_failure.is_none(),
        "a duplicated member must not fail the pool"
    );
    assert_eq!(
        source_nat_pool_statuses(&rules)[0].address_count,
        1,
        "the Go AppliedNATView/alarm capacity denominator must use the same deduped count"
    );

    // Same remote (REMOTE:443/TCP), distinct inside ports — the #10700 probe.
    let t1 = identity(&mint(&rules, "10.0.0.7", 1111)).expect("the first flow must mint");
    let t2 = identity(&mint(&rules, "10.0.0.8", 2222)).expect("the second flow must mint");
    assert_eq!(t1.0, t2.0, "both flows translate from the pool's one address");
    assert_eq!(t1.1, Some(20000), "first occurrence keeps pool order and gets port_low");
    assert_eq!(
        t2.1,
        Some(20001),
        "the second flow must get a distinct reverse tuple"
    );

    // Nested and repeated prefixes dedupe across members while preserving
    // network enumeration and first-occurrence order.
    let mut overlapping_snapshot = dup_rule();
    overlapping_snapshot.pool_addresses = vec![
        "203.0.113.0/31".to_string(),
        "203.0.113.1/32".to_string(),
        "203.0.113.0/31".to_string(),
    ];
    let overlapping = parse_source_nat_rules(&[overlapping_snapshot]);
    assert_eq!(
        overlapping[0].pool_addresses_v4,
        vec![Ipv4Addr::new(203, 0, 113, 0), Ipv4Addr::new(203, 0, 113, 1)],
        "contained and repeated CIDR members must retain first-seen address order (#10700)"
    );
}

fn rule_in_instance_9389(
    name: &str,
    pool: &str,
    source: &str,
    addr: &str,
    instance: &str,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{addr}/32")],
        port_low: 20000,
        port_high: 20009,
        from_routing_instance: instance.to_string(),
        ..SourceNATRuleSnapshot::default()
    }
}

/// Mint with an ingress routing instance in scope.
///
/// `mint` uses `NatScopeCtx::default()`, whose `ingress_routing_instance` is
/// empty — so a rule carrying `from_routing_instance` never MATCHES through it
/// and the rule is skipped before any allocator or peer logic runs. My first
/// version of the cells below used it and both failed at the FIRST mint with
/// "vrf-a must translate": the fixture could not reach the code it was about.
/// Worth recording, because the same mistake written the other way round — an
/// assertion that something does NOT happen — would have PASSED, for the reason
/// that the rule never ran at all.
fn mint_in_instance_9389(
    rules: &[SourceNatRule],
    src: &str,
    src_port: u16,
    instance: &str,
) -> SourceNatLookup {
    let scope = NatScopeCtx {
        ingress_routing_instance: instance,
        ..NatScopeCtx::default()
    };
    let mut counter = None;
    match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &scope,
        "lan",
        "wan",
        src.parse().expect("src"),
        REMOTE.parse().expect("dst"),
        Some(PROTO_TCP),
        src_port,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

/// #9389: the invariant `two_rules_naming_one_pool_are_not_peers_6979` asserts,
/// held for rules in DIFFERENT ROUTING INSTANCES.
///
/// That cell was green throughout the regression, because its fixture leaves
/// `from_routing_instance` empty — so both rules built the same allocator key
/// and the split it was guarding against never happened in it. **A fixture that
/// cannot express the distinguishing field cannot observe a defect keyed on it.**
///
/// #9062 added `from_routing_instance` to `SourceNatPoolAllocatorKey`, giving two
/// rule-sets over ONE pool two pointer-distinct `PortAllocator`s. Since
/// `same_allocator` is `Arc::ptr_eq`, the #6979 overlap index then read them as
/// hostile peers and refused every mint whose candidate the other already held:
/// measured five consecutive `PoolPeerAddressOverlap` refusals on a pool with
/// free capacity.
///
/// The guard was right and the split was wrong. One pool is one set of wire
/// identities; a `(addr, port)` can back exactly one flow whatever routing
/// instance it came from.
///
/// Fail-on-revert: restore `from_routing_instance` to the allocator key and both
/// assertions fire — `overlap_owners` becomes `Some` and the second instance's
/// mint is refused.
#[test]
fn two_instances_naming_one_pool_are_not_peers_9389() {
    let rules = parse_source_nat_rules(&[
        rule_in_instance_9389("r1", "wan-pool", "10.0.0.0/24", SHARED, "vrf-a"),
        rule_in_instance_9389("r2", "wan-pool", "10.1.0.0/24", SHARED, "vrf-b"),
    ]);
    assert!(
        rules[0].overlap_owners.is_none() && rules[1].overlap_owners.is_none(),
        "two rule-sets naming ONE pool from different routing instances were wired \
         as overlap PEERS. They share one pool, so they must share one allocator \
         and one occupancy domain — as peers, each refuses the identities the \
         other holds and mints are dropped while the pool has free capacity"
    );

    let first = identity(&mint_in_instance_9389(&rules, "10.0.0.7", 1111, "vrf-a"))
        .expect("vrf-a must translate");
    let second = identity(&mint_in_instance_9389(&rules, "10.1.0.7", 2222, "vrf-b")).expect(
        "vrf-b must translate — this is the refusal #9389 measured, five in a row \
         on a ten-port pool",
    );
    assert_ne!(
        first, second,
        "sharing one allocator is what makes the two instances hand out DIFFERENT \
         ports off the same address; identical identities would be the collision \
         the overlap guard exists to prevent"
    );
}

/// NARROWNESS. Removing the routing instance from the allocator key must not
/// merge pools that are genuinely different.
///
/// This is what makes the removal safe rather than merely convenient: the key
/// still carries `pool_addresses_v4`/`_v6`, so two pools that happen to share a
/// NAME across instances are still discriminated by the addresses they hand out.
/// The routing instance added no discrimination the addresses did not already
/// provide — which is why it could be removed without reopening anything.
#[test]
fn same_pool_name_different_addresses_stays_independent_9389() {
    let rules = parse_source_nat_rules(&[
        rule_in_instance_9389("r1", "wan-pool", "10.0.0.0/24", "203.0.113.1", "vrf-a"),
        rule_in_instance_9389("r2", "wan-pool", "10.1.0.0/24", "203.0.113.9", "vrf-b"),
    ]);
    let first = identity(&mint_in_instance_9389(&rules, "10.0.0.7", 1111, "vrf-a"))
        .expect("vrf-a must translate");
    let second = identity(&mint_in_instance_9389(&rules, "10.1.0.7", 2222, "vrf-b"))
        .expect("vrf-b must translate");
    assert_ne!(
        first.0, second.0,
        "same pool NAME over different ADDRESSES must stay two independent pools; \
         the addresses in the allocator key are what keeps them apart"
    );
}
