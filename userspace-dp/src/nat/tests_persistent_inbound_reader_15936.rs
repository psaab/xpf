// #15936: persistent-NAT non-zone inbound reader hashes (wan, wan) instead
// of the admitted (src,dst) zone pair.
//
// Outbound mint (match_rules.rs) and HA synced import (synced.rs) both fold
// the original flow's resolved pair — e.g. trust->wan becomes
// (trust, wan) for an interface- or global-scoped rule whose authored zones
// are empty. The pre-routing inbound reader in poll_descriptor/mod.rs has
// no knowledge of the internal zone: it substitutes the ARRIVAL zone
// (wan) for both sides, hashing (wan, wan). That bucket never holds the
// grant, so an idle persistent lease (no live reverse session) is missed
// on ordinary inbound reopening for every non-zone-scoped rule whose
// internal and external zones differ.
//
// Fix: the inbound lookup must not require the caller to re-derive the
// mint pair. A lease records grants under the bucket(s) its admitting
// rule(s) minted; the reader's zone-pair hash is only a hint. When the
// exact bucket is absent, the lookup falls back to the rule's authored
// scope identity — the rule fields (authored zones/interfaces/RIs) with
// the ARRIVAL zone as packet_to — which is deterministic from the rule
// alone and matches the mint for zone-authored rules while admitting
// the non-zone grants minted under any internal zone. Sibling isolation
// is preserved: a different rule's authored fields fold differently, so
// one rule's grant never authorizes another rule's binding (the fallback
// requires the candidate lease to hold a grant whose bucket folds to
// THIS rule under SOME internal packet_from, realised by scanning only
// buckets the lease actually holds and re-deriving this rule's key with
// the stored packet_from candidates — see implementation; the observable
// contract pinned here is: own grant admits, sibling grant does not,
// disallowed remote still denies).
use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_TCP;
use std::net::IpAddr;

const POOL_PORT: u16 = 20_000;
const POOL_PORT_HIGH: u16 = 20_001;

fn iface_scoped_rule() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "iface-persistent".to_string(),
        from_zone: String::new(),
        to_zone: String::new(),
        from_interface: "ge-0/0/0.0".to_string(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        pool_name: "shared".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: POOL_PORT,
        port_high: POOL_PORT_HIGH,
        persistent_nat: true,
        persistent_nat_permit: "target-host-port".to_string(),
        persistent_nat_inactivity_timeout: 300,
        ..SourceNATRuleSnapshot::default()
    }])
}

fn global_rule() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "global-persistent".to_string(),
        from_zone: String::new(),
        to_zone: String::new(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        pool_name: "shared".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: POOL_PORT,
        port_high: POOL_PORT_HIGH,
        persistent_nat: true,
        persistent_nat_permit: "target-host-port".to_string(),
        persistent_nat_inactivity_timeout: 300,
        ..SourceNATRuleSnapshot::default()
    }])
}

fn zone_scoped_rule() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "zone-persistent".to_string(),
        from_zone: "trust".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        pool_name: "shared".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: POOL_PORT,
        port_high: POOL_PORT_HIGH,
        persistent_nat: true,
        persistent_nat_permit: "target-host-port".to_string(),
        persistent_nat_inactivity_timeout: 300,
        ..SourceNATRuleSnapshot::default()
    }])
}

/// Sibling isolation fixture: two interface-scoped rules sharing one pool
/// (mirrors tests_persistent_nonzone_15133). A = any-remote-host via
/// ge-0/0/0.0, B = target-host-port via ge-0/0/1.0.
fn sibling_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "iface-any".to_string(),
            from_zone: String::new(),
            to_zone: String::new(),
            from_interface: "ge-0/0/0.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "iface-strict".to_string(),
            from_zone: String::new(),
            to_zone: String::new(),
            from_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

fn outbound(
    rules: &[SourceNatRule],
    ingress_ifname: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> TranslatedTuple {
    let mut counter = None;
    let scope = NatScopeCtx {
        ingress_ifname,
        ..NatScopeCtx::default()
    };
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &scope,
        "trust",
        "wan",
        "10.0.0.5".parse().expect("src"),
        dst_ip,
        Some(PROTO_TCP),
        40_000,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(decision) => TranslatedTuple {
            ip: decision.rewrite_src.expect("pool rewrite"),
            port: decision.rewrite_src_port.expect("pool port rewrite"),
        },
        other => panic!("outbound must translate, got {other:?}"),
    }
}

fn outbound_pair(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> TranslatedTuple {
    let mut counter = None;
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &NatScopeCtx::default(),
        from_zone,
        to_zone,
        "10.0.0.5".parse().expect("src"),
        dst_ip,
        Some(PROTO_TCP),
        40_000,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(decision) => TranslatedTuple {
            ip: decision.rewrite_src.expect("pool rewrite"),
            port: decision.rewrite_src_port.expect("pool port rewrite"),
        },
        other => panic!("outbound {from_zone}->{to_zone} must translate, got {other:?}"),
    }
}

/// Production inbound spelling at poll_descriptor/mod.rs (#15936): for a
/// non-zone rule the packet_from is substituted with the ARRIVAL zone, so
/// the pair hashed is (wan, wan) — NOT the admitted (trust, wan).
fn inbound_as_production(
    rule: &SourceNatRule,
    translated: TranslatedTuple,
    remote_ip: IpAddr,
    remote_port: u16,
    now_ns: u64,
) -> PersistentInbound {
    let packet_from_zone: &str = if rule.from_zone.is_empty() {
        "wan"
    } else {
        &rule.from_zone
    };
    rule.pool_allocator.persistent_inbound_lookup_for_rule(
        PROTO_TCP,
        translated.ip,
        translated.port,
        remote_ip,
        remote_port,
        now_ns,
        rule,
        "wan",
        packet_from_zone,
        "wan",
        &NatScopeCtx::default(),
    )
}

/// THE CELL (interface-scoped): outbound trust->wan mints the grant;
/// production inbound (wan,wan) must still find it.
/// RED pre-fix: Miss (bucket (wan,wan) empty).
#[test]
fn inbound_reader_finds_iface_scoped_grant_15936() {
    let rules = iface_scoped_rule();
    let dst: IpAddr = "198.51.100.20".parse().expect("dst");
    let now = 1_000;
    let translated = outbound(&rules, "ge-0/0/0.0", dst, 443, now);
    assert!(
        matches!(
            inbound_as_production(&rules[0], translated, dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "production (wan,wan) inbound must find the (trust,wan) grant for an interface-scoped rule (#15936)"
    );
    // Disallowed remote control: same production spelling, wrong remote.
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary");
    assert_eq!(
        inbound_as_production(&rules[0], translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "a remote the grant never permitted must still deny, not widen (#15936)"
    );
}

/// THE CELL (global): fully unscoped rule, same mechanism.
#[test]
fn inbound_reader_finds_global_grant_15936() {
    let rules = global_rule();
    let dst: IpAddr = "198.51.100.20".parse().expect("dst");
    let now = 1_000;
    let translated = outbound(&rules, "", dst, 443, now);
    assert!(
        matches!(
            inbound_as_production(&rules[0], translated, dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "production (wan,wan) inbound must find the (trust,wan) grant for a global rule (#15936)"
    );
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary");
    assert_eq!(
        inbound_as_production(&rules[0], translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "global rule: disallowed remote must still deny (#15936)"
    );
}

/// Zone-scoped control: authored zones make production's pair already
/// correct (trust,wan); must keep passing.
#[test]
fn inbound_reader_zone_scoped_still_admits_15936() {
    let rules = zone_scoped_rule();
    let dst: IpAddr = "198.51.100.20".parse().expect("dst");
    let now = 1_000;
    let translated = outbound(&rules, "", dst, 443, now);
    assert!(
        matches!(
            inbound_as_production(&rules[0], translated, dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "zone-scoped control must keep admitting (#15936)"
    );
}

/// Sibling isolation under the production spelling: the permissive
/// sibling's any-remote grant must NOT widen the strict sibling, even
/// though the reader now recovers non-zone grants without knowing the
/// internal zone. RED for a naive UNSCOPED fallback.
#[test]
fn inbound_reader_does_not_merge_sibling_grants_15936() {
    let rules = sibling_rules();
    assert!(
        rules[0]
            .pool_allocator
            .same_allocator(&rules[1].pool_allocator),
        "fixture: rules naming one pool must share one allocator"
    );
    let permissive_dst: IpAddr = "198.51.100.30".parse().expect("permissive dst");
    let strict_dst: IpAddr = "198.51.100.20".parse().expect("strict dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary");
    let now = 1_000;
    let permissive_translated = outbound(&rules, "ge-0/0/0.0", permissive_dst, 443, now);
    let strict_translated = outbound(&rules, "ge-0/0/1.0", strict_dst, 443, now);
    assert_eq!(
        strict_translated, permissive_translated,
        "shared lease must keep one translated tuple (#9389)"
    );
    // Permissive rule keeps its own any-remote grant (production spelling).
    assert!(
        matches!(
            inbound_as_production(&rules[0], permissive_translated, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "permissive sibling keeps its any-remote grant (#15936 control)"
    );
    // Strict rule's own grant admits (production spelling).
    assert!(
        matches!(
            inbound_as_production(&rules[1], strict_translated, strict_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "strict sibling's own target-host-port grant must admit (#15936 control)"
    );
    // The permissive grant must not widen the strict binding.
    assert_eq!(
        inbound_as_production(&rules[1], strict_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "any-remote-host minted via an interface-scoped sibling must not authorize inbound on the strict rule (#15936)"
    );
    assert_eq!(
        inbound_as_production(&rules[1], strict_translated, permissive_dst, 443, now),
        PersistentInbound::Denied,
        "permissive flow destination must not become a strict-rule grant (#15936)"
    );
}

/// Exact-bucket shadowing (review fold): one GLOBAL rule, one shared
/// lease, two mints — A trust->wan grants remote A, B wan->wan grants
/// remote B. The reader spells (wan,wan), so B's bucket is the EXACT
/// bucket; it exists but does not grant A. Pre-fold the reader stopped
/// at that exact bucket and Denied A without trying the provenance
/// re-fold. Admission must be ANY granting bucket: A (via the
/// (trust,wan) provenance bucket) and B (via the exact bucket) both
/// admit; a third remote neither granted still denies.
#[test]
fn inbound_reader_exact_bucket_does_not_shadow_provenance_grant_15936() {
    let rules = global_rule();
    let remote_a: IpAddr = "198.51.100.20".parse().expect("remote A");
    let remote_b: IpAddr = "198.51.100.30".parse().expect("remote B");
    let remote_c: IpAddr = "203.0.113.99".parse().expect("remote C");
    let now = 1_000;
    // A: mint under (trust,wan); B: mint under (wan,wan) — same source,
    // same global rule, so both grants land on ONE lease (#9389).
    let translated_a = outbound_pair(&rules, "trust", "wan", remote_a, 443, now);
    let translated_b = outbound_pair(&rules, "wan", "wan", remote_b, 443, now);
    assert_eq!(
        translated_a, translated_b,
        "fixture: both mints must share one lease/translated tuple"
    );
    // B via the exact (wan,wan) bucket.
    assert!(
        matches!(
            inbound_as_production(&rules[0], translated_b, remote_b, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "exact (wan,wan) bucket must admit its own remote (#15936 control)"
    );
    // A via the provenance re-fold — the cell that was shadowed pre-fold.
    assert!(
        matches!(
            inbound_as_production(&rules[0], translated_a, remote_a, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "exact bucket that does not grant A must fall through to the (trust,wan) provenance grant, not Deny (#15936)"
    );
    // Neither bucket grants C.
    assert_eq!(
        inbound_as_production(&rules[0], translated_a, remote_c, 9_999, now),
        PersistentInbound::Denied,
        "a remote neither mint granted must still deny (#15936)"
    );
}
