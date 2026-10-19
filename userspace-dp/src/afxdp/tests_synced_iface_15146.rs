// #15146 — HA synced reserves skipped the #14367 interface-domain
// cross-check.
//
// Local mints (#14367) refuse when another occupancy domain already owns
// the wire identity:
//   * NAT64 -> interface: `nat64_refuse_if_interface_owns`
//   * pool  -> interface: `reject_peer_owned_*` (+ `iface_overlap_owners`)
//   * interface -> pool/NAT64: `peer_owns_for_interface`
//
// The three HA synced-reserve arms skipped that cross-check:
//   1. `reserve_synced_nat64_port_unless_peer_owns` asked only the static
//      and pool/NAT64-peer questions, never the interface registry.
//   2. `reserve_synced_on_first_pool_owner` (PASS 1) asked only
//      `peer_owns_wire_identity` / statics, never the interface registry.
//   3. `reserve_synced_interface_identity` never asked whether a
//      pool/NAT64 peer already owns the candidate identity.
//
// So a standby could import a translation onto an identity a LOCAL
// interface-SNAT flow already holds (or vice-versa): two live flows share
// one wire identity and the reverse (1:N) index misdelivers replies to
// whichever installed first.
//
// Every fixture here goes through `build_forwarding_state`, so the
// combined pool+NAT64+interface overlap index is built exactly as
// production builds it (`sync_interface_overlap_peers` from the real
// egress addresses). The fixture egress in `nat_snapshot` is
// E=172.16.80.8 (reth0.80 primary v4).

use super::ForwardingState;
use super::forwarding_build::build_forwarding_state;
use super::test_fixtures::nat_snapshot;
use crate::nat::{NatHolder, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, NAT64RuleSnapshot, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const E: &str = "172.16.80.8";
const SRV: &str = "93.184.216.34";
const TCP: u8 = 6;

/// Interface-SNAT rule plus a NAT64 prefix whose pool is exactly E.
fn snap_iface_nat64() -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "iface-snat".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["0.0.0.0/0".into()],
        interface_mode: true,
        ..Default::default()
    }];
    snap.nat64_rules = vec![NAT64RuleSnapshot {
        name: "n64".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec![E.to_string()],
        ..Default::default()
    }];
    snap
}

/// Interface-SNAT rule (first, 10.0.0.0/24) plus a one-port pool rule
/// (10.1.0.0/24) whose only address is E.
fn snap_iface_pool() -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.source_nat_rules = vec![
        SourceNATRuleSnapshot {
            name: "iface-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["10.0.0.0/24".into()],
            interface_mode: true,
            ..Default::default()
        },
        SourceNATRuleSnapshot {
            name: "pool-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["10.1.0.0/24".into()],
            pool_name: "P".into(),
            pool_addresses: vec![format!("{E}/32")],
            port_low: 40000,
            port_high: 40000,
            ..Default::default()
        },
    ];
    snap
}

/// Local interface-SNAT admission through the production mint. With
/// `src_port == 1024` toward SRV this preserves (E,1024) — the identity
/// the first NAT64 mint on E would also pick (bottom of its range).
fn iface_admit(state: &ForwardingState, src: &str, src_port: u16, dst: &str) -> SourceNatLookup {
    let mut c = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().unwrap(),
        dst.parse().unwrap(),
        Some(TCP),
        src_port,
        443,
        Some(E.parse::<Ipv4Addr>().unwrap()),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut c,
    )
}

fn iface_identity(lookup: &SourceNatLookup) -> Option<(IpAddr, Option<u16>)> {
    match lookup {
        SourceNatLookup::Matched(d) => d.rewrite_src.map(|ip| (ip, d.rewrite_src_port)),
        _ => None,
    }
}

/// Local pool-SNAT admission. The pool carries one port (40000), so a
/// successful mint owns (E,40000).
fn pool_admit(state: &ForwardingState, src: &str, src_port: u16) -> SourceNatLookup {
    let mut c = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().unwrap(),
        SRV.parse().unwrap(),
        Some(TCP),
        src_port,
        443,
        Some(E.parse::<Ipv4Addr>().unwrap()),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut c,
    )
}

/// A peer-synced NAT64 forward flow naming (E, port), narrowed route
/// (v6 key -> `match_ipv6_dest`).
fn synced_nat64_key(client: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V6(client.parse().expect("v6 client")),
        dst_ip: IpAddr::V6("64:ff9b::5db8:d822".parse().expect("v6 dst")),
        src_port: 5000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// The same import on the fallback-scan route (v4-keyed, cannot narrow).
fn synced_nat64_v4keyed(client: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(client.parse().expect("v4 client")),
        dst_ip: IpAddr::V4(SRV.parse().expect("v4 dst")),
        src_port: 5000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn import_synced_nat64(
    state: &ForwardingState,
    key: &crate::session::SessionKey,
    port: u16,
) -> bool {
    let decision = crate::nat64::Nat64State::forward_decision(
        E.parse::<Ipv4Addr>().expect("egress"),
        SRV.parse::<Ipv4Addr>().expect("srv"),
        port,
    );
    crate::nat64::reserve_synced_nat64_allocation(&state.nat64, key, decision, false, 0)
}

fn snat_key(src: &str, src_port: u16, dst: &str) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: src.parse().expect("src"),
        dst_ip: dst.parse().expect("dst"),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// Import `nat` as a peer-synced SNAT session through the production
/// synced-reserve entry, with the active's zone pair resolved (PASS 1).
fn import_synced_snat(
    state: &ForwardingState,
    key: &crate::session::SessionKey,
    nat: crate::nat::NatDecision,
) -> bool {
    crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        key,
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains::default(),
    )
}

// ---------------------------------------------------------------------------
// Leg 1 — synced NAT64 import vs a local interface-SNAT flow
// ---------------------------------------------------------------------------

/// THE DEFECT, narrowed route: an interface-SNAT flow already owns
/// (E,1024); the synced NAT64 import naming that identity must refuse.
#[test]
fn a_synced_nat64_import_is_refused_when_an_interface_flow_owns_the_identity_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());
    assert!(
        state.nat64.prefixes[0].iface_allocs.is_some(),
        "fixture: the NAT64 prefix pool is the egress address, so the build \
         must have synced the interface registry onto the prefix"
    );

    let local = iface_admit(&state, "10.0.0.2", 1024, SRV);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), None)),
        "fixture: the interface flow must PRESERVE (E,1024) toward SRV"
    );

    assert!(
        !import_synced_nat64(&state, &synced_nat64_key("2001:db8::7"), 1024),
        "the synced NAT64 import must REFUSE (E,1024): a local interface-SNAT \
         flow already owns that wire identity. Pre-fix the synced arm asked \
         only the static/peer-pool questions, reserved against the NAT64 \
         bitmap alone, and returned true — two live flows on one identity \
         (#15146)"
    );
    assert!(
        !state.nat64.prefixes[0]
            .port_allocator
            .debug_is_port_occupied(0, 1024),
        "and the refusal must leave the NAT64 allocator CLEAN — a skipped \
         rollback strands the port in an allocator no published session will \
         ever free"
    );
}

/// THE DEFECT, fallback-scan route: a v4-keyed synced key cannot narrow,
/// so it reaches the pool scan — the second return that needed the check.
#[test]
fn the_synced_nat64_fallback_scan_is_refused_when_an_interface_flow_owns_it_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());

    let local = iface_admit(&state, "10.0.0.2", 1024, SRV);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), None)),
        "fixture: the interface flow must own (E,1024)"
    );

    assert!(
        !import_synced_nat64(&state, &synced_nat64_v4keyed("10.0.61.9"), 1024),
        "the FALLBACK SCAN route must refuse too — it is the route a v4-keyed \
         or prefix-less key takes, so wiring the refusal into the narrowed \
         arm alone leaves the defect live exactly where narrowing fails \
         (#15146)"
    );
}

/// CONTROL: nothing owns the identity, so the synced NAT64 import must
/// still reserve — refusing here would break HA session sync outright.
#[test]
fn a_synced_nat64_import_still_succeeds_when_no_interface_flow_owns_it_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());
    assert!(
        import_synced_nat64(&state, &synced_nat64_key("2001:db8::7"), 1024),
        "an unowned identity must still be RESERVED (#4512) — a fix that \
         refused every synced import would pass the defect cells above while \
         breaking session sync"
    );
    assert!(
        state.nat64.prefixes[0]
            .port_allocator
            .debug_is_port_occupied(0, 1024),
        "and the reservation must actually land in the NAT64 allocator"
    );
}

/// CONTROL: an interface flow toward a DIFFERENT remote holds an
/// address-only (remote-specific) token, so (E,1024) toward SRV is a
/// distinct wire identity and the import must still reserve.
#[test]
fn a_synced_nat64_import_toward_another_remote_still_succeeds_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());

    let local = iface_admit(&state, "10.0.0.2", 1024, "9.9.9.9");
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), None)),
        "fixture: the interface flow must own (E,1024) toward 9.9.9.9"
    );

    assert!(
        import_synced_nat64(&state, &synced_nat64_key("2001:db8::7"), 1024),
        "the interface agent's address-only token is remote-specific: \
         (E,1024)->9.9.9.9 does not own (E,1024)->{SRV}, so the import must \
         still reserve"
    );
}

/// CONTROL: an interface flow on a DIFFERENT port does not own the
/// imported identity.
#[test]
fn a_synced_nat64_import_on_another_port_still_succeeds_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());

    let local = iface_admit(&state, "10.0.0.2", 1025, SRV);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), None)),
        "fixture: the interface flow must own (E,1025)"
    );

    assert!(
        import_synced_nat64(&state, &synced_nat64_key("2001:db8::7"), 1024),
        "(E,1024) is unowned, so the import must reserve"
    );
}

// ---------------------------------------------------------------------------
// Leg 2 — synced pool import (PASS 1) vs a local interface-SNAT flow
// ---------------------------------------------------------------------------

/// THE DEFECT, port-bearing arm: PASS 1 narrows the import to the pool
/// rule (its source matches), the pool's own bitmap is empty — but an
/// interface flow already owns (E,40000).
#[test]
fn a_synced_pool_import_is_refused_when_an_interface_flow_owns_the_identity_15146() {
    let state = build_forwarding_state(&snap_iface_pool());

    let local = iface_admit(&state, "10.0.0.2", 40000, SRV);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), None)),
        "fixture: the interface flow must PRESERVE (E,40000) toward SRV"
    );

    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: Some(40000),
        ..Default::default()
    };
    assert!(
        !import_synced_snat(&state, &snat_key("10.1.0.7", 40000, SRV), nat),
        "the synced pool import must REFUSE (E,40000): PASS 1 asked only the \
         peer-pool question, and the pool's own bitmap is empty, so pre-fix \
         the reservation landed on an identity a local interface-SNAT flow \
         already owns (#15146)"
    );
    assert!(
        !state.source_nat_rules[1]
            .pool_allocator
            .debug_is_port_occupied(0, 40000),
        "and the refusal must leave the pool allocator CLEAN"
    );
}

/// CONTROL: no interface flow owns the identity, so the pool import must
/// still reserve in the pool allocator.
#[test]
fn a_synced_pool_import_still_succeeds_when_no_interface_flow_owns_it_15146() {
    let state = build_forwarding_state(&snap_iface_pool());

    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: Some(40000),
        ..Default::default()
    };
    assert!(
        import_synced_snat(&state, &snat_key("10.1.0.7", 40000, SRV), nat),
        "an unowned identity must still be reserved in the pool"
    );
    assert!(
        state.source_nat_rules[1]
            .pool_allocator
            .debug_is_port_occupied(0, 40000),
        "and the reservation must land in the pool allocator"
    );
}

// ---------------------------------------------------------------------------
// Leg 3 — synced interface import vs a local pool / NAT64 flow
// ---------------------------------------------------------------------------

/// THE DEFECT, interface-vs-pool: PASS 1 proves the interface rule is the
/// active's first match and books in `iface_allocs` without asking whether
/// the pool — whose only address is E — already owns (E,40000) toward the
/// same remote.
#[test]
fn a_synced_interface_import_is_refused_when_a_pool_flow_owns_the_identity_15146() {
    let state = build_forwarding_state(&snap_iface_pool());

    let local = pool_admit(&state, "10.1.0.7", 33333);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), Some(40000))),
        "fixture: the pool flow must own (E,40000)"
    );

    // The synced flow's source matches the interface rule (10.0.0.0/24),
    // so PASS 1's interface-first detection routes it to the interface
    // domain. Its decision preserves port 40000 (rewrite_src_port None).
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: None,
        ..Default::default()
    };
    assert!(
        !import_synced_snat(&state, &snat_key("10.0.0.9", 40000, SRV), nat),
        "the synced interface import must REFUSE (E,40000) toward {SRV}: the \
         pool flow already owns that wire identity and the interface arm \
         never asked the peer question (#15146)"
    );
}

/// THE DEFECT, interface-vs-NAT64: a local NAT64 mint owns (E,1024); a
/// synced interface import naming (E,1024) toward the same remote must
/// refuse.
#[test]
fn a_synced_interface_import_is_refused_when_a_nat64_flow_owns_the_identity_15146() {
    let state = build_forwarding_state(&snap_iface_nat64());

    let minted = state
        .nat64
        .allocate_source_for_worker(
            0,
            TCP,
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            SRV.parse::<Ipv4Addr>().unwrap(),
            40000,
            443,
            1_000,
            0,
            &state.source_nat_rules,
            0,
            Some(&state.iface_nat_allocators),
        )
        .expect("fixture: the NAT64 mint must succeed first");
    assert_eq!(
        minted,
        (E.parse::<Ipv4Addr>().unwrap(), 1024),
        "fixture: the NAT64 flow must own (E,1024) toward SRV"
    );

    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: None,
        ..Default::default()
    };
    assert!(
        !import_synced_snat(&state, &snat_key("10.0.0.9", 1024, SRV), nat),
        "the synced interface import must REFUSE (E,1024) toward {SRV}: a \
         local NAT64 flow already owns that wire identity (#15146)"
    );
}

/// CONTROL (shipped #14367 semantics): the pool's PAT occupancy bit is
/// REMOTE-AGNOSTIC — a pool mint publishes (E,40000) for any remote, so a
/// synced interface import naming (E,40000) toward a different remote is
/// still refused. The local interface mint asks the same question the
/// same way (`peer_owns_for_interface` PAT term); refusing here is the
/// fail-closed twin, not over-reach. The remote-SPECIFIC control is the
/// address-only direction (the NAT64 cell above), which does distinguish
/// remotes.
#[test]
fn a_synced_interface_import_on_a_pool_pat_identity_is_refused_for_any_remote_15146() {
    let state = build_forwarding_state(&snap_iface_pool());

    let local = pool_admit(&state, "10.1.0.7", 33333);
    assert_eq!(
        iface_identity(&local),
        Some((E.parse::<IpAddr>().unwrap(), Some(40000))),
        "fixture: the pool flow must own (E,40000) toward SRV"
    );

    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: None,
        ..Default::default()
    };
    assert!(
        !import_synced_snat(&state, &snat_key("10.0.0.9", 40000, "9.9.9.9"), nat),
        "a PAT occupancy bit owns (E,40000) for every remote, so the \
         interface import must refuse even toward a different remote — the \
         same answer the local #14367 interface-mint peer check gives"
    );
}

/// CONTROL: nothing owns the identity, so the interface import must book
/// in the interface registry.
#[test]
fn a_synced_interface_import_still_succeeds_when_nothing_owns_it_15146() {
    let state = build_forwarding_state(&snap_iface_pool());

    let nat = crate::nat::NatDecision {
        rewrite_src: Some(E.parse::<IpAddr>().unwrap()),
        rewrite_src_port: None,
        ..Default::default()
    };
    assert!(
        import_synced_snat(&state, &snat_key("10.0.0.9", 40000, SRV), nat),
        "an unowned identity must still book in the interface domain"
    );
    let alloc = state
        .iface_nat_allocators
        .allocator_if_present(E.parse::<IpAddr>().unwrap())
        .expect("the import must have created the interface allocator for E");
    assert_eq!(
        alloc.live_flow_count(),
        1,
        "the interface reservation must be live"
    );
}
