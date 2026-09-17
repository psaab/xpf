// #9895: the reverse lookup's pass-2 fallback must refuse a reply from
// ANOTHER non-zero routing domain.
//
// `find_forward_nat_match` walks the domain-agnostic reverse bucket in two
// passes: pass 1 returns a candidate whose forward session carries the reply's
// OWN domain; pass 2 remembers the first validating candidate from any other
// domain as a fallback. The fallback exists for the non-contained VRF shape
// (reply legitimately arrives in a different domain because transit lookup is
// not VRF-isolated). But when BOTH sides are non-zero and different, the reply
// belongs to another tenant whose address space merely overlaps — admitting it
// injects tenant B's reply into tenant A's flow (the reverse-direction
// counterpart of the #7160 forward collision).
//
// The zone gate (#7169/#9383, `shared_ops.rs:revalidate_reverse_ingress`)
// narrows the blast radius to zone-matching replies, but zone-matching is a
// supported multi-VRF CGNAT posture, not an anomaly — the lookup is the
// decisive layer and must fail closed here.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.
//
// FAIL-ON-REVERT contract:
// - `cross_domain_reply_is_refused_9895` REDS on the pre-fix code (the
//   fallback returns `Some`) and greens after the refusal.
// - The three control cells green BOTH before and after: they pin the
//   legitimate fallback (same-domain demux + both mixed zero/non-zero
//   directions) so the fix cannot be "refuse everything".

use super::*;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};

// In-band tenant domains (100_000..999_999, the `#7160` stable-ID band), so
// the fixture reads as two real routing instances rather than synthetic ids.
// Distinct from the wire sentinels 0/1/2 on purpose.
const DOMAIN_A: u32 = 100_001;
const DOMAIN_B: u32 = 100_002;
const DOMAIN_C: u32 = 100_003;

/// Overlapping forward tuple: both tenants use the IDENTICAL 5-tuple, which
/// is the supported multi-VRF posture that makes the reverse bucket shared.
/// Only the routing domain differs.
fn forward_key(domain: u32) -> SessionKey {
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

/// The reverse tuple of `forward_key` — what a reply on the wire parses to —
/// carrying the ARRIVAL domain the reply resolved.
fn reply_key(domain: u32) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 443,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: domain,
    }
}

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
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

fn install(table: &mut SessionTable, key: &SessionKey) {
    assert!(
        table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            1_000_000_000,
            PROTO_TCP,
            0x10
        ),
        "install must succeed for {key:?}"
    );
}

/// The decisive cell: a zone-matching, tuple-matching reply from ANOTHER
/// non-zero domain must NOT land in this flow.
///
/// Single-entry shape (tenant A installed, tenant B replies): pre-fix the
/// pass-2 fallback returns A's session — RED. Post-fix it refuses — GREEN.
/// Third-domain shape (A and B installed, C replies): neither candidate
/// shares C's domain, so the answer is still refusal, not "first in bucket".
#[test]
fn cross_domain_reply_is_refused_9895() {
    // Single-entry: only tenant A holds this tuple.
    let mut table = SessionTable::new();
    let forward_a = forward_key(DOMAIN_A);
    install(&mut table, &forward_a);
    let reply_b = reply_key(DOMAIN_B);
    assert!(
        table.find_forward_nat_match(&reply_b).is_none(),
        "#9895: tenant-B reply admitted into tenant-A flow via the pass-2 \
         fallback (both domains non-zero and different); must refuse"
    );

    // Third-domain: A and B both hold the tuple, C matches neither.
    let mut table = SessionTable::new();
    install(&mut table, &forward_key(DOMAIN_A));
    install(&mut table, &forward_key(DOMAIN_B));
    let reply_c = reply_key(DOMAIN_C);
    assert!(
        table.find_forward_nat_match(&reply_c).is_none(),
        "#9895: domain-C reply admitted into a foreign-domain flow; \
         no same-domain candidate exists so the fallback must refuse"
    );
}

/// Control 1 — same-domain demux is preserved: with both tenants installed,
/// each tenant's reply resolves to ITS OWN forward session via pass 1.
/// Greens before and after; a fix that broke pass-1 preference would red it.
#[test]
fn same_domain_reply_is_admitted_9895() {
    let mut table = SessionTable::new();
    let forward_a = forward_key(DOMAIN_A);
    let forward_b = forward_key(DOMAIN_B);
    install(&mut table, &forward_a);
    install(&mut table, &forward_b);

    let hit_a = table
        .find_forward_nat_match(&reply_key(DOMAIN_A))
        .expect("same-domain reply A must resolve");
    assert_eq!(
        hit_a.key, forward_a,
        "domain-A reply must demux to the domain-A forward session"
    );
    let hit_b = table
        .find_forward_nat_match(&reply_key(DOMAIN_B))
        .expect("same-domain reply B must resolve");
    assert_eq!(
        hit_b.key, forward_b,
        "domain-B reply must demux to the domain-B forward session"
    );
}

/// Control 2 — non-contained reply direction: a forward in a tenant domain
/// whose reply arrives in the default instance (domain 0) still resolves.
/// This is the legitimate pass-2 fallback (one side zero) and must survive.
#[test]
fn zero_domain_reply_falls_back_9895() {
    let mut table = SessionTable::new();
    let forward_a = forward_key(DOMAIN_A);
    install(&mut table, &forward_a);
    let hit = table
        .find_forward_nat_match(&reply_key(0))
        .expect("domain-0 reply to a tenant forward must still resolve");
    assert_eq!(hit.key, forward_a);
}

/// Control 3 — non-contained forward direction: a default-instance forward
/// whose reply arrives in a tenant domain still resolves. Mirror of control 2.
#[test]
fn zero_domain_forward_falls_back_9895() {
    let mut table = SessionTable::new();
    let forward_zero = forward_key(0);
    install(&mut table, &forward_zero);
    let hit = table
        .find_forward_nat_match(&reply_key(DOMAIN_B))
        .expect("tenant-domain reply to a domain-0 forward must still resolve");
    assert_eq!(hit.key, forward_zero);
}
