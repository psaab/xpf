// #8115 R1 — the ADDRESS-ONLY route to the pool-vs-pool duplicate identity.
//
// #6979 F6 (PR #8111) closed one route: a LOCAL, port-translating (PAT) mint
// may not publish a `(pool address, port)` a PEER pool's occupancy bitmap
// already holds. That check asks the bitmap, and the bitmap is only ONE of the
// two ownership tokens this allocator issues.
//
// A `port no-translation` flow, or a port-less protocol, takes the ADDRESS-ONLY
// path: it claims NO occupancy bit and instead owns an entry in
// `address_only_owners`, keyed by the full reverse identity
// `(protocol, translated ip, translated port, dst ip, dst port)`. The two
// spaces never met, so BOTH directions were open:
//
//   - a peer pool preserving `X:P` toward `R` did not stop a PAT mint of `X:P`
//     toward `R`;
//   - two address-only flows in DIFFERENT pools over one address collided
//     whenever protocol and remote matched.
//
// # Population
//
// Same as F6's, and verified rather than assumed: the Go #5144 gate
// (`validateNATPoolExternalTupleOverlapStrict`) rejects overlapping pools at
// commit on address overlap alone, so an overlapping config arrives only from
// the tolerant load / peer-sync path (`lenientCompileOpts`, wired at
// `configstore.Store` load and SyncApply). That path is real, and its own
// compiler doc records the part that makes this worth fixing: unlike
// `lenientNPTv6` / `lenientNAT64Prefix`, "the dataplane does NOT reject the
// overlapping snapshot — the overlap installs with a LATENT collision".
//
// # The two sub-questions are not equally precise
//
// The bitmap question is REMOTE-AGNOSTIC and the address-only question is
// REMOTE-SPECIFIC. The controls below are what hold that line: a peer
// address-only identity toward a DIFFERENT remote is not a wire collision and
// must still translate. Overlapping pools are a shape this dataplane
// deliberately supports, so nothing may stop translating that is not an actual
// duplicate.

use super::allocator::NatHolder;
use super::destination::PROTO_TCP;
use super::source::SourceNatRule;
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::IpAddr;

const SHARED: &str = "203.0.113.1";
const REMOTE: &str = "8.8.8.8";
const OTHER_REMOTE: &str = "9.9.9.9";

/// A PAT pool-mode rule. The ONE-port range makes "did the second flow get the
/// identity the first one holds" a yes/no question rather than a probability.
fn pat_rule(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 20000,
        port_high: 20000,
        ..SourceNATRuleSnapshot::default()
    }
}

/// The address-only twin: `port no-translation` preserves the source port, so a
/// flow whose source port is 20000 puts the SAME wire identity on the link that
/// the PAT rule above mints.
fn notrans_rule(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        pool_no_translation: true,
        ..pat_rule(name, pool, source)
    }
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

fn shared_ip() -> IpAddr {
    SHARED.parse().expect("shared")
}

/// DIRECTION A: a peer's preserved `X:P` must block a PAT mint of `X:P`.
///
/// Fires on: deleting the `peer_holds_address_only_identity` term from
/// `peer_owns_wire_identity`. The bitmap term alone answers `false` here —
/// pool `a` holds no occupancy bit at all — so the PAT mint publishes the
/// identity pool `a` is already preserving on the wire.
#[test]
fn an_address_only_peer_identity_blocks_a_pat_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        pat_rule("r2", "b", "10.1.0.0/24"),
    ]);

    // Pool `a` preserves source port 20000 -> wire identity 203.0.113.1:20000.
    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: the address-only rule must translate the ADDRESS and preserve \
         the port (rewrite_src_port None). If this minted a port, the rule is \
         not on the address-only path and the cell is measuring the PAT arm"
    );

    // Pool `b`'s PAT mint lands on the same address:port toward the same remote.
    let second = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "pool `b` published 203.0.113.1:20000 while pool `a` preserves that exact \
         wire identity toward the same remote. An address-only flow owns no \
         occupancy bit, so #6979 F6's bitmap query cannot see it and reports the \
         identity free (#8115 R1)"
    );
    assert_eq!(
        identity(&second),
        None,
        "and it must not translate at all — a refusal that still handed back a \
         decision would be the duplicate wearing a failure's shape"
    );
}

/// CONTROL for direction A, and the reason the address-only term is keyed on the
/// remote rather than on `(address, port)`.
///
/// The same two pools, the same preserved identity, a DIFFERENT remote. The
/// reverse conntrack index keys on the full tuple, so `X:P -> R` and
/// `X:P -> R'` are distinguishable and both must translate.
///
/// Fires on: widening the address-only term to ignore `dst_ip`/`dst_port` —
/// which is the obvious "make it match the bitmap's shape" simplification.
#[test]
fn an_address_only_peer_toward_another_remote_does_not_block_a_pat_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        pat_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: pool `a` preserves 203.0.113.1:20000 toward 8.8.8.8"
    );

    let second = mint_to(&rules, "10.1.0.7", 33333, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), Some(20000))),
        "a PAT mint toward a DIFFERENT remote is not a duplicate and must still \
         translate. Overlapping pools are a supported shape; a check that \
         refuses here stops translating traffic that never collided"
    );
}

/// DIRECTION B: two address-only pools over one address must not both mint one
/// identity.
///
/// Neither flow claims an occupancy bit, so this route is invisible to the
/// bitmap query in BOTH directions — it is the pure address-only collision.
///
/// Fires on: deleting the `peer_holds_address_only_identity` term. Each pool's
/// own `address_only_owners` map is empty of the other's tokens, so both mint.
#[test]
fn two_address_only_pools_do_not_both_mint_one_identity_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: pool `a` takes the identity first"
    );

    let second = mint_to(&rules, "10.1.0.7", 20000, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "two address-only flows in different pools, same protocol, same preserved \
         port, same remote — one wire identity, two sessions, and replies the \
         reverse (1:N) index cannot attribute (#8115 R1)"
    );
}

/// CONTROL for direction B.
///
/// Same two address-only pools, different remotes. Both identities are distinct
/// on the wire and both must translate.
#[test]
fn two_address_only_pools_toward_different_remotes_both_mint_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(identity(&first), Some((shared_ip(), None)), "fixture");

    let second = mint_to(&rules, "10.1.0.7", 20000, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), None)),
        "a different remote is a different wire identity and must still translate"
    );
}

/// The common case: NO overlapping pools, so no index is built and the new term
/// is never consulted.
///
/// This is the cell that fails if the check is ever wired to something other
/// than `overlap_owners` — an unconditional query would refuse here too, since
/// the two pools' addresses differ and nothing shares an identity.
#[test]
fn non_overlapping_address_only_pools_are_untouched_8115() {
    let mut r2 = notrans_rule("r2", "b", "10.1.0.0/24");
    r2.pool_addresses = vec!["203.0.113.9/32".to_string()];
    let rules = parse_source_nat_rules(&[notrans_rule("r1", "a", "10.0.0.0/24"), r2]);

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    let second = mint_to(&rules, "10.1.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "pool `a` translates to its own address"
    );
    assert_eq!(
        identity(&second),
        Some(("203.0.113.9".parse::<IpAddr>().expect("other"), None)),
        "pool `b` translates to ITS own address — disjoint pools share no \
         identity and the peer query must not be reached at all"
    );
}

// ---------------------------------------------------------------------------
// Per-ARM coverage.
//
// The address-only mint has THREE arms — v4 round-robin/persistent, v6
// round-robin/persistent, and deterministic-v4 — each with its own reserve call
// and its own copy of the peer check. #6979 F6's own test file records the
// lesson: "removing the v6 call alone escapes all seven of them."
//
// Measured here rather than assumed. With only the v4 cells above, disabling
// the v6 arm's check and disabling the deterministic arm's check BOTH escaped
// the full 5143-test suite. These two cells are what closes that.

const SHARED_V6: &str = "2001:db8:ff::1";
const REMOTE_V6: &str = "2001:4860:4860::8888";

fn notrans_rule_v6(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED_V6}/128")],
        port_low: 20000,
        port_high: 20000,
        pool_no_translation: true,
        ..SourceNATRuleSnapshot::default()
    }
}

/// ARM: the IPv6 address-only mint.
///
/// A separate arm of `match_source_nat_result_for_tuple` with its own reserve
/// call, so a check wired only into the v4 arm passes every cell above.
///
/// Fires on: removing the peer check from the v6 arm alone.
#[test]
fn two_address_only_v6_pools_do_not_both_mint_one_identity_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule_v6("r1", "a", "2001:db8:1::/64"),
        notrans_rule_v6("r2", "b", "2001:db8:2::/64"),
    ]);

    let first = mint_to(&rules, "2001:db8:1::7", 20000, REMOTE_V6);
    assert_eq!(
        identity(&first),
        Some((SHARED_V6.parse::<IpAddr>().expect("v6"), None)),
        "fixture: the v6 address-only rule must translate the ADDRESS and \
         preserve the port"
    );

    let second = mint_to(&rules, "2001:db8:2::7", 20000, REMOTE_V6);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the v6 address-only arm owes the same peer check as the v4 one — \
         without it two v6 pools over one address both preserve the identical \
         wire identity (#8115 R1)"
    );
}

/// ARM: the deterministic-v4 (CGNAT mode 1) address-only mint.
///
/// `port no-translation` on a deterministic pool takes a THIRD reserve call
/// (`reserve_address_only` on the deterministically chosen external address),
/// which the two arms above do not touch.
///
/// Fires on: removing the peer check from the deterministic arm alone.
#[test]
fn two_deterministic_address_only_pools_do_not_both_mint_one_identity_8115() {
    // 100.64.0.0 as a u32 — the deterministic subscriber host base.
    const HOST_BASE: u32 = (100 << 24) | (64 << 16);
    let det = |name: &str, pool: &str, source: &str| SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 1024,
        port_high: 65535,
        pool_no_translation: true,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: HOST_BASE,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    };
    // Both subscribers must fall inside `blocks_per_ip` (126) of the host base,
    // or the deterministic map has no block for them and the mint fails
    // `AllocatorExhausted` — a refusal that looks like a pass for the wrong
    // reason. Measured: `100.64.1.5` is subscriber index 261 and did exactly
    // that.
    let rules = parse_source_nat_rules(&[
        det("r1", "a", "100.64.0.5/32"),
        det("r2", "b", "100.64.0.6/32"),
    ]);
    assert!(
        rules[0].deterministic_v4.is_some() && rules[1].deterministic_v4.is_some(),
        "precondition: both mode-1 snapshots must build deterministic rules, or \
         this cell silently measures the round-robin arm it is not about"
    );

    let first = mint_to(&rules, "100.64.0.5", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: a deterministic pool with `port no-translation` translates the \
         ADDRESS and preserves the port"
    );

    let second = mint_to(&rules, "100.64.0.6", 20000, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the deterministic address-only arm owes the same peer check — two \
         deterministic pools over one external address otherwise both preserve \
         the identical wire identity (#8115 R1)"
    );
}

// ===========================================================================
// #8115 R2 — the HA synced reserve never reached the peer check.
//
// `reserve_synced_on_first_pool_owner` calls `reserve_flow_maybe_persistent` /
// `reserve_address_only` on ONE allocator. Those check and set only that
// allocator's own state, so an imported flow narrowed to pool B succeeded while
// a LOCAL flow already owned the same tuple in pool A — and the coordinator
// then published the import, letting the reverse-map insert displace A's owner.
// Sequential; no concurrency needed.
//
// # Why refusing is not a new policy
//
// The issue calls this "a decision, not a patch", because the synced path
// exists to reproduce what the ACTIVE node decided (#6211 pass 1) and so must
// not simply refuse. Two facts settle it without inventing a disposition:
//
//   1. This function ALREADY refuses this exact conflict when it happens inside
//      ONE allocator — a taken bit or an owned token returns `Refused`. Wiring
//      the peer query in makes the two-allocator case behave like the
//      one-allocator case; it does not introduce a new answer.
//   2. `Refused` is OBSERVABLE by construction: `may_publish()` is false, the
//      caller turns it into `SyncedImportOutcome::RejectedReserve`, and
//      `xpf_userspace_synced_import_reserve_refused_total` counts it — a metric
//      whose help text already says those flows will not survive a failover
//      (#8101). "Surface the conflict rather than silently reserve" is exactly
//      what `Refused` already means here.
//
// The alternative — import anyway — is the LATENT loss the #6979 F1 comment
// measured three steps of: the import is accepted into the wrong allocator, the
// squatter retires, and the first allocator re-issues an identity the imported
// flow is still live on.

fn synced_key(src: &str, src_port: u16, dst: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// Import the active node's decision, with the zone pair present so the #6979
/// F1 pass-1 narrowing applies (that is the path R2 is about).
fn import(rules: &[SourceNatRule], key: &crate::session::SessionKey, port: Option<u16>) -> bool {
    reserve_synced_source_nat_allocation_untracked(
        &InterfaceNatAllocators::default(),
        rules,
        key,
        NatDecision {
            rewrite_src: Some(shared_ip()),
            rewrite_src_port: port,
            ..NatDecision::default()
        },
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains::default(),
    )
}

fn pat_rule_two_ports(name: &str, pool: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        port_high: 20001,
        ..pat_rule(name, pool, source)
    }
}

/// R2, PORT-BEARING arm: an import must not take a tuple a LOCAL flow already
/// owns in a peer pool.
///
/// Fires on: deleting the `peer_owns_wire_identity` call from the port-bearing
/// arm of `reserve_synced_on_first_pool_owner`. Pool `b`'s own bitmap is empty,
/// so the reserve succeeds and the import is published.
#[test]
fn a_synced_import_is_refused_when_a_peer_pool_owns_the_identity_8115() {
    let rules = parse_source_nat_rules(&[
        pat_rule_two_ports("r1", "a", "10.0.0.0/24"),
        pat_rule_two_ports("r2", "b", "10.1.0.0/24"),
    ]);

    // A LOCAL flow takes 203.0.113.1:20000 in pool `a`.
    let local = mint_to(&rules, "10.0.0.7", 1111, REMOTE);
    assert_eq!(
        identity(&local),
        Some((shared_ip(), Some(20000))),
        "fixture: the local flow must own the identity the import will claim"
    );

    // The active node's decision names that same identity, and the importing
    // flow's source only matches rule r2 — so pass 1 narrows to pool `b`, whose
    // bitmap knows nothing about pool `a`.
    let accepted = import(&rules, &synced_key("10.1.0.7", 40000, REMOTE), Some(20000));
    assert!(
        !accepted,
        "the import must be REFUSED: a local flow in peer pool `a` already owns \
         203.0.113.1:20000. Accepting books the reservation in an allocator the \
         active never used, and once the local flow retires pool `a` re-issues \
         an identity the imported session is still live on (#8115 R2)"
    );
}

/// CONTROL for the port-bearing arm.
///
/// The same two pools, an import for an identity NO peer owns. It must still be
/// reserved — #6211's contract is that a standby reproduces what the active
/// decided, and a check that refuses here would drop synced sessions that never
/// collided.
#[test]
fn a_synced_import_of_an_unowned_identity_is_still_reserved_8115() {
    let rules = parse_source_nat_rules(&[
        pat_rule_two_ports("r1", "a", "10.0.0.0/24"),
        pat_rule_two_ports("r2", "b", "10.1.0.0/24"),
    ]);

    let local = mint_to(&rules, "10.0.0.7", 1111, REMOTE);
    assert_eq!(identity(&local), Some((shared_ip(), Some(20000))), "fixture");

    let accepted = import(&rules, &synced_key("10.1.0.7", 40000, REMOTE), Some(20001));
    assert!(
        accepted,
        "port 20001 is owned by no peer, so the import must be reserved. A \
         refusal here would be the check over-reaching into every synced \
         session over an overlapping pool"
    );
}

/// R2, ADDRESS-ONLY arm: the same property on the other synced reserve call.
///
/// A separate arm with its own `reserve_address_only`, so a fix wired only into
/// the port-bearing arm passes both cells above.
///
/// Fires on: deleting the `peer_owns_wire_identity` call from the address-only
/// arm alone.
#[test]
fn a_synced_address_only_import_is_refused_when_a_peer_pool_owns_it_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    // A LOCAL address-only flow preserves 203.0.113.1:20000 toward 8.8.8.8.
    let local = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&local),
        Some((shared_ip(), None)),
        "fixture: the local flow must own the ADDRESS-ONLY identity (no port \
         minted), or this cell is measuring the port-bearing arm"
    );

    // `rewrite_src_port: None` is what routes the import to the address-only arm.
    let accepted = import(&rules, &synced_key("10.1.0.7", 20000, REMOTE), None);
    assert!(
        !accepted,
        "the address-only import must be REFUSED: pool `a` already owns the \
         reverse identity (TCP, 203.0.113.1, 20000, 8.8.8.8, 443). \
         `reserve_address_only` consults only pool `b`'s own \
         `address_only_owners`, which is empty of it (#8115 R2)"
    );
}

/// CONTROL for the address-only arm, and the reason its key keeps the remote.
///
/// The same preserved port toward a DIFFERENT remote is a different wire
/// identity. It must still be reserved.
#[test]
fn a_synced_address_only_import_toward_another_remote_is_reserved_8115() {
    let rules = parse_source_nat_rules(&[
        notrans_rule("r1", "a", "10.0.0.0/24"),
        notrans_rule("r2", "b", "10.1.0.0/24"),
    ]);

    let local = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(identity(&local), Some((shared_ip(), None)), "fixture");

    let accepted = import(
        &rules,
        &synced_key("10.1.0.7", 20000, OTHER_REMOTE),
        None,
    );
    assert!(
        accepted,
        "a different remote is a different reverse identity — the import must \
         still be reserved"
    );
}

/// R2, the DETERMINISTIC route through the port-bearing arm.
///
/// Not a fourth call site — deterministic pools take the SAME
/// `reserve_flow_maybe_persistent` — but they take a different ROLLBACK: #6528
/// frees a deterministic block port with `free_no_recycle`, so a refusal that
/// mishandles it either strands the port or feeds it back to the recycle ring
/// the deterministic mapping must never draw from. The two cells above cannot
/// see that; both pools there are ordinary PAT.
///
/// The collision is natural rather than contrived: two deterministic pools over
/// one external address, each mapping its OWN subscriber #5 to block 5, so both
/// derive port 3584.
#[test]
fn a_synced_deterministic_import_is_refused_and_leaves_no_reservation_8115() {
    let det = |name: &str, pool: &str, source: &str, host_base: u32| SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: pool.to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 1024,
        port_high: 65535,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 256,
        ..SourceNATRuleSnapshot::default()
    };
    const BASE_A: u32 = (100 << 24) | (64 << 16);
    const BASE_B: u32 = BASE_A + 256;
    let rules = parse_source_nat_rules(&[
        det("r1", "a", "100.64.0.0/24", BASE_A),
        det("r2", "b", "100.64.1.0/24", BASE_B),
    ]);
    assert!(
        rules[0].deterministic_v4.is_some() && rules[1].deterministic_v4.is_some(),
        "precondition: both rules must be deterministic, or this cell silently \
         measures the round-robin path it is not about"
    );

    // Pool `a`'s subscriber #5 -> block 5 -> port 1024 + 5*512 = 3584.
    let local = mint_to(&rules, "100.64.0.5", 1111, REMOTE);
    assert_eq!(
        identity(&local),
        Some((shared_ip(), Some(3584))),
        "fixture: the deterministic mapping must put the local flow on 3584 — if \
         this moves, the import below is no longer naming a contended identity"
    );

    // Pool `b`'s subscriber #5 derives the SAME 3584 on the SAME address.
    let accepted = import(&rules, &synced_key("100.64.1.5", 40000, REMOTE), Some(3584));
    assert!(
        !accepted,
        "a deterministic import must be refused when a peer deterministic pool \
         already owns the identity (#8115 R2)"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 3584),
        "and the refusal must leave pool `b` CLEAN. A rollback that skips the \
         deterministic release strands 3584 in an allocator no session will ever \
         free — the import was never published, so no teardown names it"
    );
}

// ---------------------------------------------------------------------------
// #15145 — a refused synced RE-decision must not evict the flow's incumbent.
//
// #13691 ordered refusals INSIDE the allocator. The caller-side peer/static
// refusal in `reserve_synced_on_first_pool_owner` ran AFTER the reserve: the
// reserve evicted the same flow's incumbent (different tuple), installed the
// replacement, and only then did rollback remove the replacement — leaving
// the still-live flow with no reservation at all. The fix asks ownership
// before reserving and restores the incumbent if the post-reserve recheck
// fires anyway.
//
// RED on master: the import below is refused (correct) but the incumbent
// reservation in pool `b` is gone — `debug_is_port_occupied` for the
// incumbent port and the live record both vanish.
#[test]
fn a_refused_synced_redecision_keeps_the_incumbent_reservation_15145() {
    let rules = parse_source_nat_rules(&[
        pat_rule_two_ports("r1", "a", "10.0.0.0/24"),
        pat_rule_two_ports("r2", "b", "10.1.0.0/24"),
    ]);
    // The importing flow's incumbent in ITS OWN pool `b`: tuple 20001.
    let key = synced_key("10.1.0.7", 40000, REMOTE);
    assert!(
        import(&rules, &key, Some(20001)),
        "fixture: the incumbent import must reserve 203.0.113.1:20001 in pool b"
    );
    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20001),
        "fixture: pool b must hold the incumbent port"
    );
    // A LOCAL flow takes 203.0.113.1:20000 in peer pool `a`.
    let local = mint_to(&rules, "10.0.0.7", 1111, REMOTE);
    assert_eq!(
        identity(&local),
        Some((shared_ip(), Some(20000))),
        "fixture: the local flow must own the identity the re-decision will claim"
    );
    // The peer re-decides the SAME flow onto 20000 — peer `a` owns it.
    assert!(
        !import(&rules, &key, Some(20000)),
        "the re-decision must still be REFUSED: peer pool a owns 203.0.113.1:20000"
    );
    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20001),
        "#15145: the refused re-decision must leave the incumbent reservation \
         (203.0.113.1:20001 in pool b) intact — on master the reserve evicted \
         it before the peer refusal rolled the replacement back"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the refused replacement must not linger in pool b either"
    );
    assert_eq!(
        rules[1].pool_allocator.live_flow_count(),
        1,
        "exactly the incumbent record survives in pool b"
    );
}

/// #15145 CONTROL: an admissible synced re-decision still replaces the
/// incumbent — the pre-check must not freeze the first decision forever.
#[test]
fn an_admissible_synced_redecision_still_replaces_the_incumbent_15145() {
    let rules = parse_source_nat_rules(&[
        pat_rule_two_ports("r1", "a", "10.0.0.0/24"),
        pat_rule_two_ports("r2", "b", "10.1.0.0/24"),
    ]);
    let key = synced_key("10.1.0.7", 40000, REMOTE);
    assert!(import(&rules, &key, Some(20001)), "fixture: incumbent import");
    // Nobody owns 20000 anywhere: the re-decision is admissible.
    assert!(
        import(&rules, &key, Some(20000)),
        "an unowned re-decision must still be reserved (#15145 control)"
    );
    assert!(
        !rules[1].pool_allocator.debug_is_port_occupied(0, 20001),
        "the replaced incumbent port is freed"
    );
    assert!(
        rules[1].pool_allocator.debug_is_port_occupied(0, 20000),
        "the replacement port is held"
    );
    assert_eq!(rules[1].pool_allocator.live_flow_count(), 1);
}
