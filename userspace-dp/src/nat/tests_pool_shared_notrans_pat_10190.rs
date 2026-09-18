// #10190 — address-only and PAT rules SHARING ONE allocator must not mint the
// same public tuple.
//
// `SourceNatPoolAllocatorKey` is pool name + addresses + port range and omits
// `no_translation`, so a `port no-translation` rule and a PAT rule over one
// pool share one `PortAllocator` (pinned by
// `notrans_and_pat_rules_share_one_allocator_6528`). That allocator issues TWO
// ownership tokens that never met:
//
//   - an address-only mint records only `address_only_owners` (no bitmap bit);
//   - a PAT mint claims only the occupancy bitmap.
//
// The cross-allocator guard (`peer_owns_wire_identity`) asks both questions
// but intentionally skips owners from the SAME allocator, so two rules over
// one shared allocator admit an address-only flow preserving port P and a PAT
// flow allocated at the same public address and P toward the same remote.
// That duplicate reverse tuple is fail-open: replies the reverse (1:N) index
// cannot attribute.
//
// This is distinct from #5269/#5341 (address-only versus address-only within
// one domain) and #8115 (the same two-domains split ACROSS allocators). The
// fix makes the two domains mutually exclusive at admission INSIDE one
// allocator, in BOTH directions, keyed EXACT (remote-specific) on both sides:
//   - a PAT mint of `(X, P)` toward `R` cannot publish that identity while an
//     address-only token `(proto, X, P, R)` is live; it skips the candidate and
//     retries another PAT port when one exists;
//   - an address-only mint of `(X, P)` toward `R` is denied while a PAT flow
//     holds `(X, P)` toward `R`.
// Exact on both sides, not conservative: the #6528 headline cell mints an
// address-only `(X, P)` toward `R'` while a PAT flow holds `(X, P)` toward
// `R`, and that must keep translating — the reverse index keys on the full
// tuple, so the two are distinguishable. The controls below pin that line:
// widen either probe to ignore the remote and a control reds.

use super::allocator::{NatHolder, PoolAddressFamily, PortAllocator};
use super::destination::PROTO_TCP;
use super::source::{PersistentNatPermit, SourceNatFlowKey, SourceNatRule};
use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::IpAddr;

const SHARED: &str = "203.0.113.1";
const REMOTE: &str = "8.8.8.8";
const OTHER_REMOTE: &str = "9.9.9.9";

/// A PAT pool-mode rule over the SHARED pool. The two-port range lets the
/// remote-specific controls use the other port while the collision cells pin
/// the first port deterministically.
fn pat_rule(name: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![source.to_string()],
        pool_name: "shared-pool".to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: 20000,
        port_high: 20001,
        ..SourceNATRuleSnapshot::default()
    }
}

/// The address-only twin: `port no-translation` preserves the source port, so
/// a flow whose source port is 20000 puts the SAME wire identity on the link
/// that the PAT rule above mints. Same pool name / addresses / range, so the
/// same `allocator_key` — one shared `PortAllocator`.
fn notrans_rule(name: &str, source: &str) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        pool_no_translation: true,
        ..pat_rule(name, source)
    }
}

fn shared_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        notrans_rule("r-notrans", "10.0.0.0/24"),
        pat_rule("r-pat", "10.1.0.0/24"),
    ])
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

// FIXTURE GUARD, not a property: the two rules really do share one allocator,
// so the collision cells below test the same-allocator split they claim to.
// If `allocator_key()` ever starts discriminating on `no_translation` this
// cell fails first and says why, instead of the collision cells silently
// going vacuous (mirrors the #6528 guard).
#[test]
fn shared_notrans_pat_rules_share_one_allocator_10190() {
    let rules = shared_rules();
    assert_eq!(
        rules[0].pool_allocator.debug_shared_identity(),
        rules[1].pool_allocator.debug_shared_identity(),
        "#10190 fixture: `port no-translation` and PAT rules over the same pool \
         name / addresses / port range must share ONE allocator — that sharing \
         is what leaves the two occupancy domains unchecked against each other"
    );
}

/// DIRECTION A: an address-only flow preserving `X:P` toward `R` must make
/// a PAT mint of `(X, P)` toward `R` skip that port in the same allocator.
///
/// Fires on: a PAT admission path that claims only the bitmap. The address-
/// only flow owns no occupancy bit, so the bitmap answers free and the PAT
/// mint publishes the identity the address-only flow is already preserving on
/// the wire — one reverse tuple, two sessions. A correct allocator retries
/// the next PAT port when one remains available.
#[test]
fn address_only_first_skips_pat_to_same_remote_10190() {
    let rules = shared_rules();

    // The address-only rule preserves source port 20000 -> wire identity
    // 203.0.113.1:20000 toward 8.8.8.8.
    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: the address-only rule must translate the ADDRESS and preserve \
         the port (rewrite_src_port None). If this minted a port, the rule is \
         not on the address-only path and the cell is measuring the PAT arm"
    );

    // The PAT rule must skip the colliding 20000 candidate and retry 20001.
    let second = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), Some(20001))),
        "the shared allocator must skip 203.0.113.1:20000, which the \
         address-only flow preserves toward the same remote, and retry the \
         next free PAT port (#10190)"
    );
}

/// The retry loop must terminate when every PAT candidate collides with an
/// address-only reverse token. Releasing each rejected claim back to the
/// allocator while probing would recycle the same port forever.
#[test]
fn address_only_claims_all_pat_candidates_terminate_10190() {
    let rules = shared_rules();

    for (src, src_port) in [("10.0.0.7", 20000), ("10.0.0.8", 20001)] {
        let lookup = mint_to(&rules, src, src_port, REMOTE);
        assert_eq!(
            identity(&lookup),
            Some((shared_ip(), None)),
            "fixture: address-only flow {src}:{src_port} must preserve its \
             source port before the PAT all-candidates probe"
        );
    }

    let pat = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        failure_reason(&pat),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "PAT must terminate with exhaustion after both pool ports collide \
         with address-only reverse tokens; it must not reclaim and retry one \
         rejected port forever (#10190)"
    );
    assert_eq!(identity(&pat), None);
}

/// Persistent PAT lease reuse must run the same exact reverse-identity guard
/// as fresh PAT minting. An idle lease keeps its bitmap bit but no live PAT
/// owner remains; an address-only flow can therefore claim the exact token,
/// and the next persistent PAT flow must bypass the lease and take another
/// port rather than reusing the duplicate.
#[test]
fn persistent_pat_lease_reuse_skips_address_only_identity_10190() {
    let addrs = [SHARED.parse().expect("v4 pool address")];
    let alloc = PortAllocator::new(1, 20000, 20001);
    let pat_flow = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.2.0.7".parse().expect("src"),
        dst_ip: REMOTE.parse().expect("dst"),
        src_port: 33333,
        dst_port: 443,
        routing_scope: 0,
    };
    let translated = alloc
        .allocate_translation(
            pat_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            300 * 1_000_000_000,
            1_000,
            NatHolder::Untracked,
        )
        .expect("first persistent PAT flow");
    assert_eq!(translated.port, 20000);
    assert!(
        alloc.release_flow(pat_flow, translated, 2_000, NatHolder::Untracked),
        "release must leave an idle PAT lease holding port 20000"
    );

    let address_only_flow = SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.0.0.7".parse().expect("address-only src"),
        dst_ip: REMOTE.parse().expect("dst"),
        src_port: 20000,
        dst_port: 443,
        routing_scope: 0,
    };
    let preserved = alloc
        .reserve_address_only(address_only_flow, shared_ip(), NatHolder::Untracked)
        .expect("address-only flow may claim the idle lease's exact token");
    assert_eq!(preserved.port, 20000);

    let rebound = alloc
        .allocate_translation(
            pat_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            300 * 1_000_000_000,
            3_000,
            NatHolder::Untracked,
        )
        .expect("PAT flow must fall back to a fresh non-conflicting port");
    assert_eq!(
        rebound.port, 20001,
        "persistent lease reuse must not republish 20000 while the \
         address-only reverse token owns that exact remote identity (#10190)"
    );
}

/// DIRECTION B: a PAT flow holding `(X, P)` toward `R` must block an
/// address-only mint of `X:P` toward `R` from the same allocator.
///
/// Fires on: an address-only admission path that consults only its own token
/// map. The PAT flow owns no token, so the map answers free and the
/// address-only mint preserves the identity the PAT flow already holds — the
/// same duplicate from the other arrival order.
#[test]
fn pat_first_blocks_address_only_to_same_remote_10190() {
    let rules = shared_rules();

    // The PAT rule mints the pool's first candidate toward 8.8.8.8.
    let first = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), Some(20000))),
        "fixture: the PAT rule must mint 203.0.113.1:20000 for the first flow. \
         If this did not mint, the pool is not serving PAT and the cell is \
         measuring nothing"
    );

    // The address-only rule would preserve the same address:port toward the
    // same remote. It must be denied as exhaustion (the address-only capacity
    // limit), not admitted as a duplicate.
    let second = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        failure_reason(&second),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "the shared allocator preserved 203.0.113.1:20000 for an address-only \
         flow while a PAT flow holds that exact wire identity toward the same \
         remote. The address-only arm consults only its own token map, and a \
         PAT flow owns no token (#10190)"
    );
    assert_eq!(
        identity(&second),
        None,
        "and it must not translate at all — a refusal that still handed back a \
         decision would be the duplicate wearing a failure's shape"
    );
}

/// CONTROL for direction B, and the reason the address-only probe is keyed on
/// the remote rather than on `(address, port)`.
///
/// The same shared pool, the same held identity, a DIFFERENT remote. The
/// reverse conntrack index keys on the full tuple, so `X:P -> R` and
/// `X:P -> R'` are distinguishable and both must translate. This is also the
/// shape the #6528 headline cell relies on; a conservative (remote-blind)
/// address-only probe breaks that cell and this one together.
///
/// Fires on: widening the address-only-side probe to deny on any bitmap-held
/// `(address, port)` regardless of remote.
#[test]
fn address_only_toward_another_remote_coexists_with_pat_10190() {
    let rules = shared_rules();

    let first = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), Some(20000))),
        "fixture: the PAT flow holds 203.0.113.1:20000 toward 8.8.8.8"
    );

    let second = mint_to(&rules, "10.0.0.7", 20000, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), None)),
        "an address-only flow toward a DIFFERENT remote is not a duplicate and \
         must still translate. A check that refuses here stops translating \
         traffic that never collided — and breaks the #6528 headline shape"
    );
}

/// CONTROL for direction A: a PAT mint toward a DIFFERENT remote is not a
/// duplicate of a preserved identity and must still translate.
///
/// Fires on: widening the PAT-side probe to deny on any live token over
/// `(address, port)` regardless of remote.
#[test]
fn pat_toward_another_remote_coexists_with_address_only_10190() {
    let rules = shared_rules();

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "fixture: the address-only flow preserves 203.0.113.1:20000 toward 8.8.8.8"
    );

    let second = mint_to(&rules, "10.1.0.7", 33333, OTHER_REMOTE);
    assert_eq!(
        identity(&second),
        Some((shared_ip(), Some(20000))),
        "a PAT mint toward a DIFFERENT remote is not a duplicate and must still \
         translate. A check that refuses here stops translating traffic that \
         never collided"
    );
}

/// Single-rule case unaffected: one PAT rule over its own pool still hands
/// consecutive flows distinct ports. The new probes consult the OTHER domain;
/// a pool serving PAT alone has no tokens, so nothing new can refuse.
#[test]
fn single_pat_rule_still_mints_distinct_ports_10190() {
    let mut solo = pat_rule("r-solo", "10.2.0.0/24");
    solo.pool_name = "solo-pool".to_string();
    solo.pool_addresses = vec!["203.0.113.7/32".to_string()];
    solo.port_low = 20000;
    solo.port_high = 20001;
    let rules = parse_source_nat_rules(&[solo]);

    let first = mint_to(&rules, "10.2.0.7", 11111, REMOTE);
    let second = mint_to(&rules, "10.2.0.8", 22222, REMOTE);
    let solo_ip: IpAddr = "203.0.113.7".parse().expect("solo");
    assert_eq!(
        identity(&first),
        Some((solo_ip, Some(20000))),
        "fixture: first PAT flow mints the first port"
    );
    assert_eq!(
        identity(&second),
        Some((solo_ip, Some(20001))),
        "a lone PAT rule must still serve consecutive flows distinct ports — \
         the #10190 probes consult the address-only domain, which is empty here"
    );
}

/// Distinct-allocator case unaffected: an address-only pool and a PAT pool
/// over DIFFERENT addresses are different allocators with no shared index, so
/// the same numeric port on each is not a collision and both must translate.
#[test]
fn distinct_allocator_pools_are_untouched_10190() {
    let mut pat = pat_rule("r-pat", "10.1.0.0/24");
    pat.pool_name = "pat-pool".to_string();
    pat.pool_addresses = vec!["203.0.113.9/32".to_string()];
    let rules = parse_source_nat_rules(&[notrans_rule("r-notrans", "10.0.0.0/24"), pat]);

    assert_ne!(
        rules[0].pool_allocator.debug_shared_identity(),
        rules[1].pool_allocator.debug_shared_identity(),
        "fixture: different pool addresses must be different allocators, or \
         this control is testing the shared case it claims to exclude"
    );

    let first = mint_to(&rules, "10.0.0.7", 20000, REMOTE);
    assert_eq!(
        identity(&first),
        Some((shared_ip(), None)),
        "the address-only pool translates to its own address"
    );
    let second = mint_to(&rules, "10.1.0.7", 33333, REMOTE);
    let pat_ip: IpAddr = "203.0.113.9".parse().expect("pat");
    assert_eq!(
        identity(&second),
        Some((pat_ip, Some(20000))),
        "the PAT pool translates to its own address — the same numeric port on \
         a different address is not a collision"
    );
}
