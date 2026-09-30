// #11298: reverse-NAT admission is keyed by the forward egress interface's
// routing domain. The forward key records ingress identity and is not a reply
// compatibility test: asymmetric routes may legitimately cross instances,
// while domain 0 is strict rather than a wildcard.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::*;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DOMAIN_A: u32 = 100_001;
const DOMAIN_B: u32 = 100_002;
const IFINDEX_EGRESS_B: i32 = 12;
const IFINDEX_EGRESS_DEFAULT: i32 = 13;
const IFINDEX_EGRESS_A: i32 = 14;

fn forward_key_v4(domain: u32) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12345,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: domain,
    }
}

fn forward_key_v6(domain: u32) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        dst_ip: IpAddr::V6("2001:db8::8".parse().unwrap()),
        src_port: 12345,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: domain,
    }
}

fn reply_key(forward: &SessionKey, nat: NatDecision, domain: u32) -> SessionKey {
    let mut reply = super::key::reverse_wire_key(forward, nat);
    reply.routing_domain = domain;
    reply
}

fn egress_routing_domain(egress_ifindex: i32) -> u32 {
    match egress_ifindex {
        IFINDEX_EGRESS_A => DOMAIN_A,
        IFINDEX_EGRESS_B => DOMAIN_B,
        _ => 0,
    }
}

fn decision(egress_ifindex: i32, nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex,
            tx_ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn install(table: &mut SessionTable, key: &SessionKey, decision: SessionDecision) {
    assert!(
        table.install_with_protocol(
            key.clone(),
            decision,
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ),
        "install must succeed for {key:?}"
    );
}

#[test]
fn mixed_zero_reply_domains_are_not_wildcards_11298() {
    let nat = NatDecision::default();

    // A default-keyed/default-egress forward must not admit a reply arriving
    // from B. The ordinary default-domain reply remains valid.
    let mut table = SessionTable::new();
    let forward_zero = forward_key_v4(0);
    install(&mut table, &forward_zero, decision(IFINDEX_EGRESS_DEFAULT, nat));
    let reply_b = reply_key(&forward_zero, nat, DOMAIN_B);
    assert!(
        table
            .find_forward_nat_match(&reply_b, egress_routing_domain)
            .is_none(),
        "a B-domain reply must not borrow a default-domain forward session"
    );
    let reply_zero = reply_key(&forward_zero, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_some(),
        "the default-domain control reply must still match"
    );

    // The opposite mixed-zero direction is equally strict: a B-keyed/B-egress
    // forward must not admit a reply arriving in domain 0.
    let mut table = SessionTable::new();
    let forward_b = forward_key_v4(DOMAIN_B);
    install(&mut table, &forward_b, decision(IFINDEX_EGRESS_B, nat));
    let reply_zero = reply_key(&forward_b, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_none(),
        "a default-domain reply must not borrow a B-domain forward session"
    );
    let reply_b = reply_key(&forward_b, nat, DOMAIN_B);
    assert!(
        table
            .find_forward_nat_match(&reply_b, egress_routing_domain)
            .is_some(),
        "the matching B-domain reply must still resolve"
    );

    // An asymmetric A-ingress/default-egress flow accepts its actual egress
    // domain, not a reply that happens to match its ingress key.
    let mut table = SessionTable::new();
    let forward_a = forward_key_v4(DOMAIN_A);
    install(&mut table, &forward_a, decision(IFINDEX_EGRESS_DEFAULT, nat));
    let reply_a = reply_key(&forward_a, nat, DOMAIN_A);
    assert!(
        table
            .find_forward_nat_match(&reply_a, egress_routing_domain)
            .is_none(),
        "the reply domain must match the forward egress domain, not its ingress key"
    );
    let reply_zero = reply_key(&forward_a, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_some(),
        "an asymmetric default-egress reply must still resolve"
    );
}

#[test]
fn asymmetric_egress_domains_demultiplex_both_directions_11298() {
    let mut table = SessionTable::new();
    let forward_a = forward_key_v4(DOMAIN_A);
    let forward_b = forward_key_v4(DOMAIN_B);
    let nat = NatDecision::default();
    install(&mut table, &forward_a, decision(IFINDEX_EGRESS_B, nat));
    install(&mut table, &forward_b, decision(IFINDEX_EGRESS_A, nat));

    // The reply arriving in B belongs to the flow ingressed in A.
    let reply_b = reply_key(&forward_a, nat, DOMAIN_B);
    let hit_a = table
        .find_forward_nat_match(&reply_b, egress_routing_domain)
        .expect("A-ingress/B-egress reply must match its forward session");
    assert_eq!(hit_a.key, forward_a);

    // The reverse asymmetry must work too. The first bucket candidate (A)
    // has the wrong egress domain, so lookup must continue to B's companion.
    let reply_a = reply_key(&forward_b, nat, DOMAIN_A);
    let hit_b = table
        .find_forward_nat_match(&reply_a, egress_routing_domain)
        .expect("B-ingress/A-egress reply must match its forward session");
    assert_eq!(hit_b.key, forward_b);
}

fn assert_nat_reply_uses_egress_domain(forward: SessionKey, nat: NatDecision) {
    let mut table = SessionTable::new();
    install(&mut table, &forward, decision(IFINDEX_EGRESS_B, nat));

    let reply_b = reply_key(&forward, nat, DOMAIN_B);
    let hit = table
        .find_forward_nat_match(&reply_b, egress_routing_domain)
        .expect("a NAT reply in the forward egress domain must match");
    assert_eq!(hit.key, forward);

    let reply_a = reply_key(&forward, nat, DOMAIN_A);
    assert!(
        table
            .find_forward_nat_match(&reply_a, egress_routing_domain)
            .is_none(),
        "the ingress key domain must not admit a reply from the wrong egress domain"
    );

    // A default-keyed/default-egress NAT session must refuse a reply from B,
    // while its ordinary default-domain reply remains valid.
    let mut table = SessionTable::new();
    let mut forward_zero = forward.clone();
    forward_zero.routing_domain = 0;
    install(&mut table, &forward_zero, decision(IFINDEX_EGRESS_DEFAULT, nat));
    let reply_b = reply_key(&forward_zero, nat, DOMAIN_B);
    assert!(
        table
            .find_forward_nat_match(&reply_b, egress_routing_domain)
            .is_none(),
        "a B-domain NAT reply must not borrow a default-domain session"
    );
    let reply_zero = reply_key(&forward_zero, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_some(),
        "the matching default-domain NAT reply must still resolve"
    );

    // The opposite mixed-zero direction must also refuse borrowing.
    let mut table = SessionTable::new();
    let mut forward_b = forward.clone();
    forward_b.routing_domain = DOMAIN_B;
    install(&mut table, &forward_b, decision(IFINDEX_EGRESS_B, nat));
    let reply_zero = reply_key(&forward_b, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_none(),
        "a default-domain NAT reply must not borrow a B-domain session"
    );

    // An A-keyed flow that actually egresses in the default instance must
    // accept its domain-0 reply, not a reply in its ingress-key domain.
    let mut table = SessionTable::new();
    let forward_default_egress = forward;
    install(&mut table, &forward_default_egress, decision(IFINDEX_EGRESS_DEFAULT, nat));
    let reply_a = reply_key(&forward_default_egress, nat, DOMAIN_A);
    assert!(
        table
            .find_forward_nat_match(&reply_a, egress_routing_domain)
            .is_none(),
        "an A-domain NAT reply must not borrow a default-domain egress session"
    );
    let reply_zero = reply_key(&forward_default_egress, nat, 0);
    assert!(
        table
            .find_forward_nat_match(&reply_zero, egress_routing_domain)
            .is_some(),
        "the matching default-domain NAT reply must still resolve"
    );

}

#[test]
fn nat_ipv6_and_nat64_replies_use_the_same_egress_domain_predicate_11298() {
    let v4_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    assert_nat_reply_uses_egress_domain(forward_key_v4(DOMAIN_A), v4_nat);

    let v6_nat = NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:db8::ff".parse().unwrap())),
        rewrite_src_port: Some(40001),
        ..NatDecision::default()
    };
    assert_nat_reply_uses_egress_domain(forward_key_v6(DOMAIN_A), v6_nat);

    // IPv6 forward translated to the IPv4 wire family. The reverse key is
    // cross-family, but route admission must use the same forward egress map.
    let nat64 = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11))),
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        rewrite_src_port: Some(40002),
        rewrite_dst_port: Some(8443),
        nat64: true,
        ..NatDecision::default()
    };
    assert_nat_reply_uses_egress_domain(forward_key_v6(DOMAIN_A), nat64);
}
