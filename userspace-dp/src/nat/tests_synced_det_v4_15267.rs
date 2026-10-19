// #15267 (B10-03): synced deterministic-v4 (CGNAT mode 1) imports were
// booked without a block-membership check.
//
// The v6 twin (`reserve_synced_nat64_port_unless_peer_owns`) already
// requires `deterministic_v6_tuple_matches` before reserving, but the
// v4 arms in `synced.rs` passed only `rule.deterministic_v4.is_some()`
// as a tag to the allocator. `deterministic_v4_tuple_matches` /
// `deterministic_tuple_matches` had no production caller, so a synced
// import whose translated `(pool address, port)` lies outside the
// subscriber's deterministic block — the config-sync window or a peer
// bug where the nodes disagree on the deterministic map — was booked
// on the standby. Once configs converge the active's port is in-block
// under the shared map, so this only bites while the maps disagree;
// booking it anyway publishes a session whose translation this node
// would never have minted and whose reverse mapping disagrees with
// the deterministic function.
//
// Fix: require `deterministic_v4_tuple_matches` in both synced v4 arms
// (address check only in the address-only arm, where the wire carries
// no translated port) and return `Refused` otherwise.
//
// Fixture arithmetic (mirrors `synced_deterministic_reservation_recycled_5178_14625`):
//   subscriber 100.64.0.5 -> sub_idx 5, blocks_per_ip 126 -> ip_idx 0,
//   block_idx 5 -> pool[0] = 203.0.113.1, block [1024 + 5*512, +511]
//   = [3584, 4095]. Port 4096 is block 6 (subscriber 100.64.0.6);
//   203.0.113.2 is pool[1], which subscriber 5 never maps to.

use super::*;
use crate::SourceNATRuleSnapshot;
use std::net::{IpAddr, Ipv4Addr};

const POOL0: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const POOL1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
const IN_BLOCK_PORT: u16 = 3584;
const OUT_OF_BLOCK_PORT: u16 = 4096;

fn det_rules() -> Vec<SourceNatRule> {
    let host_base = u32::from(Ipv4Addr::new(100, 64, 0, 0));
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "cgn-pool".to_string(),
        from_zone: "subs".to_string(),
        to_zone: "inet".to_string(),
        source_addresses: vec!["100.64.0.0/22".to_string()],
        pool_name: "cgn-pool".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string(), "203.0.113.2/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        deterministic_mode: 1,
        deterministic_block_size: 512,
        deterministic_blocks_per_ip: 126,
        deterministic_host_base: host_base,
        deterministic_host_count: 1024,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert!(
        rules[0].deterministic_v4.is_some(),
        "fixture: mode-1 snapshot must build a deterministic rule, or this \
         cell silently measures the round-robin arm it is not about"
    );
    rules
}

fn synced_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "100.64.0.5".parse().expect("src"),
        dst_ip: "8.8.8.8".parse().expect("dst"),
        src_port: 40000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn import(
    rules: &[SourceNatRule],
    nat: NatDecision,
    synced_zones: SyncedNatZones<'_>,
) -> bool {
    reserve_synced_source_nat_allocation_untracked(
        &InterfaceNatAllocators::default(),
        rules,
        &synced_key(),
        nat,
        false,
        synced_zones,
        0,
        SyncedSourceNatDomains::default(),
    )
}

/// FAIL-ON-REVERT (port-bearing arm, PASS 1): a synced deterministic-v4
/// import whose translated port lies OUTSIDE the subscriber's block
/// must be refused. Pre-fix it returns `true` and occupies the port.
#[test]
fn synced_det_v4_out_of_block_port_refused_15267() {
    let rules = det_rules();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(POOL0)),
        rewrite_src_port: Some(OUT_OF_BLOCK_PORT),
        ..NatDecision::default()
    };
    assert!(
        !import(&rules, nat, Some(("subs", "inet"))),
        "#15267: a synced deterministic-v4 import with a translated port \
         outside the subscriber's block must be refused"
    );
    assert!(
        !rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, OUT_OF_BLOCK_PORT),
        "#15267: a refused import must not occupy the out-of-block port"
    );
}

/// FAIL-ON-REVERT (port-bearing arm, PASS 2): the translated ADDRESS
/// is checked too — an in-block port on the wrong pool address is not
/// this subscriber's deterministic tuple.
#[test]
fn synced_det_v4_wrong_pool_address_refused_15267() {
    let rules = det_rules();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(POOL1)),
        rewrite_src_port: Some(IN_BLOCK_PORT),
        ..NatDecision::default()
    };
    assert!(
        !import(&rules, nat, None),
        "#15267: a synced deterministic-v4 import on a pool address the \
         subscriber does not map to must be refused"
    );
    assert!(
        !rules[0]
            .pool_allocator
            .debug_is_port_occupied(1, IN_BLOCK_PORT),
        "#15267: a refused import must not occupy the wrong-address port"
    );
}

/// FAIL-ON-REVERT (address-only arm, PASS 1): an address-only synced
/// decision (`rewrite_src_port == None`, port preserved on the wire)
/// carries no port to check, but its ADDRESS must still be the
/// subscriber's deterministic pool address.
#[test]
fn synced_det_v4_address_only_wrong_address_refused_15267() {
    let rules = det_rules();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(POOL1)),
        rewrite_src_port: None,
        ..NatDecision::default()
    };
    assert!(
        !import(&rules, nat, Some(("subs", "inet"))),
        "#15267: an address-only synced deterministic-v4 import on a pool \
         address the subscriber does not map to must be refused"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        0,
        "#15267: a refused address-only import must mint no reverse-identity token"
    );
}

/// CONTROL (port-bearing arm): the subscriber's own deterministic
/// tuple — pool[0] plus a port inside [3584, 4095] — still reserves.
/// This passed before the fix too; it pins that the domain check does
/// not refuse legitimate synced deterministic imports.
#[test]
fn synced_det_v4_in_block_port_reserved_control_15267() {
    let rules = det_rules();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(POOL0)),
        rewrite_src_port: Some(IN_BLOCK_PORT),
        ..NatDecision::default()
    };
    assert!(
        import(&rules, nat, Some(("subs", "inet"))),
        "control: an in-block synced deterministic-v4 import must reserve"
    );
    assert!(
        rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, IN_BLOCK_PORT),
        "control: a reserved import must occupy its pool port"
    );
}

/// CONTROL (address-only arm): an address-only synced decision naming
/// the subscriber's deterministic pool address still reserves its
/// reverse-identity token.
#[test]
fn synced_det_v4_in_block_address_only_reserved_control_15267() {
    let rules = det_rules();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(POOL0)),
        rewrite_src_port: None,
        ..NatDecision::default()
    };
    assert!(
        import(&rules, nat, None),
        "control: an address-only synced deterministic-v4 import on the \
         subscriber's pool address must reserve"
    );
    assert_eq!(
        rules[0].pool_allocator.debug_address_only_owners().len(),
        1,
        "control: a reserved address-only import must mint its token"
    );
}
