// #8115 R3 — a NAT64 prefix is its own occupancy domain, and was never a MEMBER
// of the peer index.
//
// `Nat64Prefix::port_allocator` is keyed by `(prefix_bytes, pool_v4)`; a
// source-NAT pool's allocator is keyed by pool NAME. Two independent bitmaps
// over one address mint the same `X:P` for two live flows, and the reverse
// (1:N) conntrack index cannot attribute the replies — the same defect #6979 F6
// closed between two source pools, one feature over.
//
// # This is a REGISTRY gap, not a missing caller, and the guard shape follows
//
// R2's fix was a missing CALL: the query existed and the code did not reach it.
// R3's is a missing MEMBER: the query works fine, the domain was simply absent
// from the population it searches. A cell that builds a `PoolAddressOwners` by
// hand and asks it about a NAT64 allocator would prove the query works and
// would stay green with the registration deleted.
//
// So every cell here goes through `build_forwarding_state` — the real path that
// populates the index. `wire_nat64_overlap_peers` runs there, after both
// `source_nat_rules` and `nat64` exist, because the first pass runs inside
// `parse_source_nat_rules_with_previous` where `state.nat64` does not exist yet.
// Deleting that call reds these.

use super::forwarding_build::build_forwarding_state;
use super::ForwardingState;
use super::test_fixtures::nat_snapshot;
use crate::nat::{InterfaceNatAllocators, NatHolder, SourceNatFailureReason, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, NAT64RuleSnapshot, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The one address a source-NAT pool and a NAT64 prefix both carry.
const SHARED_V4: &str = "172.16.80.50";
/// A one-port range makes "did the second feature hand out the identity the
/// first one holds" a yes/no question rather than a probability.
///
/// 1024 rather than an arbitrary port because the NAT64 prefix carries its OWN
/// port range and no snapshot knob narrows it here — its first mint is the
/// bottom of that range. Pinning the source pool to the same value is what makes
/// the two features contend; with the source pool at 20000 they minted 20000 and
/// 1024 and never collided, so the first version of these cells was measuring
/// nothing.
const PORT: u16 = 1024;

fn snapshot_with(source_pool_addr: &str, nat64_pool_addr: &str) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "spool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "sp".to_string(),
        pool_addresses: vec![format!("{source_pool_addr}/32")],
        port_low: PORT,
        port_high: PORT,
        ..Default::default()
    }];
    snapshot.nat64_rules = vec![NAT64RuleSnapshot {
        name: "n64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![nat64_pool_addr.to_string()],
        ..Default::default()
    }];
    snapshot
}

/// The IPv4 source-NAT mint, through the production entry point.
fn snat_mint(state: &ForwardingState, src: &str) -> SourceNatLookup {
    let mut counter = None;
    crate::nat::match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        Some(6),
        33333,
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

/// The NAT64 mint, through the production entry point. `draining_rules` is
/// empty on purpose: the #7799 draining gate is a DIFFERENT refusal
/// (`Nat64OverlapDraining`), and letting it fire here would let these cells pass
/// without the peer check existing at all.
fn nat64_mint(
    state: &ForwardingState,
    src_v6: &str,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    state.nat64.allocate_source_for_worker(
        0,
        6,
        src_v6.parse::<Ipv6Addr>().expect("v6 src"),
        "8.8.8.8".parse::<Ipv4Addr>().expect("v4 dst"),
        40000,
        443,
        0,
        0,
        &[],
        0,
    )
}

fn snat_identity(lookup: &SourceNatLookup) -> Option<(IpAddr, Option<u16>)> {
    match lookup {
        SourceNatLookup::Matched(d) => d.rewrite_src.map(|ip| (ip, d.rewrite_src_port)),
        _ => None,
    }
}

fn snat_reason(lookup: &SourceNatLookup) -> Option<SourceNatFailureReason> {
    match lookup {
        SourceNatLookup::Unavailable(f) => Some(f.reason),
        _ => None,
    }
}

/// THE REGISTRY CELL. A NAT64 prefix that shares an address with a source-NAT
/// pool must come out of the forwarding build holding the index.
///
/// This is the property a hand-built index cannot express: the query was never
/// broken, the member was never added. Both sides are asserted because the fix
/// has to register BOTH — the combined index replaces the source-only one, and
/// a version that handed it to NAT64 alone would leave the source-NAT mint
/// blind in the other direction.
///
/// Fires on: deleting the `wire_nat64_overlap_peers` call from
/// `forwarding_build`.
#[test]
fn a_nat64_prefix_sharing_a_source_pool_address_is_registered_8115() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));
    assert_eq!(
        state.nat64.prefixes.len(),
        1,
        "fixture: the NAT64 rule must have built a prefix"
    );
    assert!(
        state.nat64.prefixes[0].overlap_owners.is_some(),
        "the NAT64 prefix shares {SHARED_V4} with a source-NAT pool and must be \
         REGISTERED in the peer index. #6979 F6 built the index from source-NAT \
         rules only, so this was always None and the NAT64 allocator was invisible \
         to every peer query (#8115 R3)"
    );
    assert!(
        state.source_nat_rules[0].overlap_owners.is_some(),
        "and the source-NAT rule must hold the COMBINED index — on master it \
         holds None here, because with only one source pool the source-only pass \
         finds fewer than two domains and returns before building anything. That \
         is the other direction of the same gap"
    );
}

/// CONTROL for the registry cell: disjoint addresses register nothing, so the
/// common case keeps the `Option::is_none` fast path.
///
/// Without this, a fix that unconditionally handed every prefix an index would
/// pass the cell above.
#[test]
fn disjoint_nat64_and_source_pools_are_not_registered_8115() {
    let state = build_forwarding_state(&snapshot_with("172.16.80.51", SHARED_V4));
    assert!(
        state.nat64.prefixes[0].overlap_owners.is_none(),
        "no address is shared, so no index may be built or handed out"
    );
    assert!(
        state.source_nat_rules[0].overlap_owners.is_none(),
        "same for the source-NAT side"
    );
}

/// DIRECTION A: a source-NAT flow owns the identity; the NAT64 mint must refuse.
#[test]
fn a_nat64_mint_is_refused_when_a_source_pool_owns_the_identity_8115() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));

    let local = snat_mint(&state, "10.0.61.7");
    assert_eq!(
        snat_identity(&local),
        Some((SHARED_V4.parse::<IpAddr>().unwrap(), Some(PORT))),
        "fixture: the source-NAT flow must own {SHARED_V4}:{PORT}"
    );

    assert_eq!(
        nat64_mint(&state, "2001:db8::7"),
        Err(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the NAT64 mint must refuse an identity a source-NAT pool already holds \
         for a live flow. Each owns a separate bitmap over {SHARED_V4}, so \
         without the index NAT64 hands out the identical (address, port) and the \
         reverse index cannot attribute the replies (#8115 R3)"
    );
}

/// DIRECTION B: a NAT64 flow owns the identity; the source-NAT mint must refuse.
///
/// The mirror of direction A, and NOT covered by it: the fix has to both add
/// NAT64 to the index AND give the source-NAT rules the combined view. A version
/// that only queried from the NAT64 side passes the cell above and fails here.
#[test]
fn a_source_nat_mint_is_refused_when_a_nat64_prefix_owns_the_identity_8115() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));

    let minted = nat64_mint(&state, "2001:db8::7").expect("the NAT64 mint must succeed first");
    assert_eq!(
        minted,
        (SHARED_V4.parse::<Ipv4Addr>().unwrap(), PORT),
        "fixture: the NAT64 flow must own {SHARED_V4}:{PORT} — the one-port range \
         is what makes this deterministic"
    );

    let refused = snat_mint(&state, "10.0.61.7");
    assert_eq!(
        snat_reason(&refused),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the source-NAT mint must refuse an identity the NAT64 prefix already \
         holds. This is the direction that needs the source rules to carry the \
         COMBINED index, not the source-only one"
    );
    assert_eq!(
        snat_identity(&refused),
        None,
        "and it must not translate at all"
    );
}

/// The DETERMINISTIC NAPT64 (#4559, mode 2) route.
///
/// Not a second check site — the fix puts ONE check after both arms, because
/// the arms differ in how they CHOOSE the tuple, not in what makes it a
/// duplicate. It is a separate route because of the ROLLBACK: #6528 frees a
/// deterministic block port with `free_no_recycle` rather than onto the recycle
/// ring the deterministic mapping must never draw from, and the round-robin
/// cells cannot see that.
///
/// So this cell asserts the refusal AND that the refusal left no reservation
/// behind. A rollback that is skipped or takes the wrong arm strands the port in
/// an allocator no session will ever free — the mint was refused, so nothing
/// downstream names it.
#[test]
fn a_deterministic_nat64_mint_is_refused_and_leaves_no_reservation_8115() {
    let mut snapshot = snapshot_with(SHARED_V4, SHARED_V4);
    snapshot.nat64_rules[0].deterministic_block_size = 512;
    snapshot.nat64_rules[0].deterministic_blocks_per_ip = 126;
    snapshot.nat64_rules[0].deterministic_host_prefix_len = 64;
    snapshot.nat64_rules[0].deterministic_host_base_v6 = "2001:db8::".to_string();
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.nat64.prefixes[0].deterministic_v6.is_some(),
        "precondition: the prefix must actually be deterministic, or this cell \
         silently measures the round-robin arm it is not about"
    );

    // The source-NAT pool takes 172.16.80.50:1024 first.
    let local = snat_mint(&state, "10.0.61.7");
    assert_eq!(
        snat_identity(&local),
        Some((SHARED_V4.parse::<IpAddr>().unwrap(), Some(PORT))),
        "fixture: the source-NAT flow must own the identity"
    );

    // Subscriber index 0 maps to block 0, whose first port is the bottom of the
    // range — the same 1024 the source pool holds.
    assert_eq!(
        nat64_mint(&state, "2001:db8::"),
        Err(SourceNatFailureReason::PoolPeerAddressOverlap),
        "a deterministic NAPT64 mint must refuse an identity a source-NAT pool \
         already owns"
    );
    assert!(
        !state.nat64.prefixes[0]
            .port_allocator
            .debug_is_port_occupied(0, PORT),
        "and the refusal must leave the NAT64 allocator CLEAN — a rollback that \
         is skipped strands {PORT} in an allocator no session will ever free"
    );
}

// ---------------------------------------------------------------------------
// #9021 — the SYNCED NAT64 import was the one arm of four that never asked
// ---------------------------------------------------------------------------
//
// Both SNAT synced arms call `peer_owns_wire_identity`; the local NAT64 mint
// calls `nat64_refuse_if_peer_owns` (the cells above). The HA-synced NAT64
// import returned `reserve_nat64_pool_port` DIRECTLY on both of its routes.
//
// The refusal was not one level down: `reserve_nat64_pool_port` ends at
// `allocator.reserve_flow`, and `PortAllocator` carries no `PoolAddressOwners`
// logic at all — so nothing on that path could have asked.
//
// Consequence: a peer-synced import reserves against the NAT64 prefix's OWN
// bitmap only. With a local source-NAT flow already holding (X, P) in the
// overlapping pool, the import SUCCEEDS, the coordinator publishes, and the
// reverse (1:N) index carries two live flows on one translated identity — the
// exact split #8115 R2/R3 closed for the other three arms.
//
// The two consumers are why the bool has to be right HERE: the coordinator
// (`afxdp/ha/session_import.rs`) uses it as its ONLY refusal point, and the
// worker twin (`upsert_synced.rs`) discards it entirely, so nothing downstream
// re-checks.

/// A peer-synced NAT64 forward flow, keyed on the ORIGINAL IPv6 5-tuple — which
/// is what `reserve_synced_nat64_allocation` narrows on (`match_ipv6_dest`
/// against `key.dst_ip`), so this key exercises the NARROWED route.
fn synced_nat64_key_9021(client: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(client.parse().expect("v6 client")),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().expect("v6 dst")),
        src_port: 5000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// A v4-keyed synced flow, which cannot narrow and therefore takes the FALLBACK
/// SCAN route. Both routes needed the refusal; wiring only the narrowed one
/// would be the partial-fix shape on the path whose entire purpose is to keep
/// working when the narrowed pick cannot.
fn synced_nat64_v4keyed_9021(client: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(client.parse().expect("v4 client")),
        dst_ip: IpAddr::V4("8.8.8.8".parse().expect("v4 dst")),
        src_port: 5000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn import_synced_9021(state: &ForwardingState, key: &crate::session::SessionKey) -> bool {
    let decision = crate::nat64::Nat64State::forward_decision(
        SHARED_V4.parse::<Ipv4Addr>().expect("shared v4"),
        "8.8.8.8".parse::<Ipv4Addr>().expect("v4 dst"),
        PORT,
    );
    crate::nat64::reserve_synced_nat64_allocation(&state.nat64, key, decision, false, 0)
}

/// THE DEFECT, narrowed route: a source-NAT flow owns the identity and the
/// peer-synced NAT64 import must refuse it.
#[test]
fn a_synced_nat64_import_is_refused_when_a_source_pool_owns_the_identity_9021() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));

    let local = snat_mint(&state, "10.0.61.7");
    assert_eq!(
        snat_identity(&local),
        Some((SHARED_V4.parse::<IpAddr>().unwrap(), Some(PORT))),
        "fixture: the source-NAT flow must own {SHARED_V4}:{PORT}, or this cell \
         measures nothing"
    );

    assert!(
        !import_synced_9021(&state, &synced_nat64_key_9021("2001:db8::7")),
        "the peer-synced NAT64 import must REFUSE an identity a source-NAT pool \
         already holds for a LIVE local flow. Each feature owns a separate bitmap \
         over {SHARED_V4}, so without the peer query the import reserves against \
         the NAT64 bitmap only, returns true, and the coordinator publishes — two \
         live flows on one translated identity, which the reverse (1:N) index \
         cannot attribute (#9021)"
    );
}

/// THE DEFECT, fallback-scan route. A v4-keyed synced key cannot narrow, so it
/// reaches the pool scan — a separate `return` that needed the same refusal.
#[test]
fn the_synced_nat64_fallback_scan_is_also_refused_9021() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));

    let local = snat_mint(&state, "10.0.61.8");
    assert_eq!(
        snat_identity(&local),
        Some((SHARED_V4.parse::<IpAddr>().unwrap(), Some(PORT))),
        "fixture: the source-NAT flow must own the identity"
    );

    assert!(
        !import_synced_9021(&state, &synced_nat64_v4keyed_9021("10.0.61.9")),
        "the FALLBACK SCAN route must refuse too. It is the route a v4-keyed or \
         prefix-less key takes (config drift between nodes, an old peer), so \
         wiring the refusal into the narrowed arm alone leaves the defect live on \
         exactly the path that exists for when narrowing fails (#9021)"
    );
}

/// CONTROL — and it is load-bearing, because a "fix" that refused every synced
/// import would satisfy both cells above while breaking HA session sync
/// entirely: the standby would reserve nothing and a post-failover local flow
/// could reuse a live translated identity, which is the #4512 defect this whole
/// path exists to prevent.
#[test]
fn a_synced_nat64_import_still_succeeds_when_nothing_owns_the_identity_9021() {
    let state = build_forwarding_state(&snapshot_with(SHARED_V4, SHARED_V4));

    // No local mint: nothing holds (SHARED_V4, PORT).
    assert!(
        import_synced_9021(&state, &synced_nat64_key_9021("2001:db8::7")),
        "an unowned identity must still be RESERVED — refusing it would leave the \
         standby with no record of the peer's translation (#4512)"
    );
}

/// CONTROL — disjoint pools must not consult a peer index at all, keeping the
/// `Option::is_none` fast path and proving the refusals above are attributable
/// to the OVERLAP rather than to the import path being broken generally.
#[test]
fn a_synced_nat64_import_over_disjoint_pools_is_unaffected_9021() {
    let state = build_forwarding_state(&snapshot_with("172.16.80.51", SHARED_V4));
    assert!(
        state.nat64.prefixes[0].overlap_owners.is_none(),
        "fixture: disjoint pools register no index"
    );
    let _ = snat_mint(&state, "10.0.61.7");
    assert!(
        import_synced_9021(&state, &synced_nat64_key_9021("2001:db8::7")),
        "with no shared address there is no contention and the import must \
         proceed exactly as before"
    );
}
