// #15676: HA standby synced persistent-NAT permission recording hashed the
// rule's authored `(from_zone, to_zone)` instead of the flow's resolved zone
// pair (`synced_zones`), mismatching the active node's grant bucket for
// non-zone-scoped rule-sets.
//
// A rule-set scoped by interface (`from interface ge-…`) or globally has
// empty authored zones. The ACTIVE node mints its persistent grant under
// `persistent_rule_scope(packet_from, packet_to)` — empty authored zones
// replaced by the packet's resolved zones (e.g. trust->wan). The pre-fix
// standby passed the rule's own authored zones as the packet pair, folding
// ("","") into a different bucket, so after failover the promoted node's
// inbound lookup (keyed by the admitting rule with the real packet pair)
// missed the synced grant and denied inbound that the active had permitted.
//
// These cells run the REAL synced-reserve path
// (`reserve_synced_source_nat_allocation`, the same call
// `handle_upsert_synced` makes) with the resolved pair threaded, then probe
// the promoted node's inbound lookup. RED pre-fix, GREEN post-fix.

use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_TCP;
use std::net::IpAddr;

const POOL_PORT: u16 = 20_000;
const POOL_PORT_HIGH: u16 = 20_001;
const SRC_IP: &str = "10.0.0.5";
const SRC_PORT: u16 = 40_000;

fn session_key(src_port: u16, dst_ip: &str, dst_port: u16) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: SRC_IP.parse().expect("src"),
        dst_ip: dst_ip.parse().expect("dst"),
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// One interface-scoped persistent rule: empty authored zones, scoped only
/// by `from_interface`. Pool mode, `target-host-port` so the grant is a
/// specific remote binding whose loss is observable as Denied/Miss.
fn iface_scoped_persistent_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "iface-persist".to_string(),
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

/// Global (fully unscoped) persistent rule: no zone, interface or RI scope.
fn global_persistent_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "global-persist".to_string(),
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

fn outbound_iface(
    rules: &[SourceNatRule],
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> NatDecision {
    let mut counter = None;
    let scope = NatScopeCtx {
        ingress_ifname: "ge-0/0/0.0",
        ..NatScopeCtx::default()
    };
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &scope,
        "trust",
        "wan",
        SRC_IP.parse().expect("src"),
        dst_ip,
        Some(PROTO_TCP),
        SRC_PORT,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(d) => d,
        other => panic!("active outbound must translate, got {other:?}"),
    }
}

fn outbound_global(
    rules: &[SourceNatRule],
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> NatDecision {
    let mut counter = None;
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &NatScopeCtx::default(),
        "trust",
        "wan",
        SRC_IP.parse().expect("src"),
        dst_ip,
        Some(PROTO_TCP),
        SRC_PORT,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(d) => d,
        other => panic!("active outbound must translate, got {other:?}"),
    }
}

fn import_synced(
    standby: &[SourceNatRule],
    dst_ip: &str,
    dst_port: u16,
    active: &NatDecision,
    synced_zones: SyncedNatZones<'_>,
    now_ns: u64,
) {
    reserve_synced_source_nat_allocation(
        &InterfaceNatAllocators::default(),
        standby,
        &session_key(SRC_PORT, dst_ip, dst_port),
        NatDecision {
            rewrite_src: active.rewrite_src,
            rewrite_src_port: active.rewrite_src_port,
            ..NatDecision::default()
        },
        false,
        synced_zones,
        now_ns,
        SyncedSourceNatDomains::default(),
    );
}

/// Promoted-node inbound probe, spelled exactly as production admission
/// (`poll_descriptor`): packet pair is (resolved internal zone, arrival
/// zone) = ("trust", "wan") for the original trust->wan flow.
fn inbound(
    rule: &SourceNatRule,
    active: &NatDecision,
    remote_ip: IpAddr,
    remote_port: u16,
    now_ns: u64,
) -> PersistentInbound {
    rule.pool_allocator.persistent_inbound_lookup_for_rule(
        PROTO_TCP,
        active.rewrite_src.expect("pool rewrite"),
        active.rewrite_src_port.expect("pool port"),
        remote_ip,
        remote_port,
        now_ns,
        rule,
        "wan",
        "trust",
        "wan",
        &NatScopeCtx::default(),
    )
}

/// THE CELL (port-bearing, interface-scoped): the active mints under
/// (trust,wan); the standby imports with the resolved pair. Post-failover
/// inbound from the granted remote must be Permitted.
///
/// RED pre-fix: the standby folded ("","") so the lookup's (trust,wan)
/// bucket held no grant — Miss/Denied, not Permitted.
#[test]
fn synced_iface_scoped_persistent_grant_survives_failover_15676() {
    let active_rules = iface_scoped_persistent_rules();
    assert!(
        active_rules[0].from_zone.is_empty() && active_rules[0].to_zone.is_empty(),
        "fixture: non-zone rule-set"
    );
    let remote: IpAddr = "198.51.100.20".parse().expect("remote");
    let now = 1_000u64;
    let active = outbound_iface(&active_rules, remote, 443, now);
    // Control: the active itself admits its own grant inbound.
    assert!(
        matches!(
            inbound(&active_rules[0], &active, remote, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "fixture: active must admit its own target-host-port grant"
    );

    let standby = iface_scoped_persistent_rules();
    import_synced(
        &standby,
        "198.51.100.20",
        443,
        &active,
        Some(("trust", "wan")),
        now,
    );
    assert_eq!(
        source_nat_pool_statuses(&standby)[0].persistent_leases,
        1,
        "fixture: standby must rebuild the lease"
    );
    assert!(
        matches!(
            inbound(&standby[0], &active, remote, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "synced grant must land in the active's (trust,wan) bucket so the promoted node admits the granted remote (#15676)"
    );
    // Fail-closed guard: an ungranted remote is still not admitted via this
    // lease's bucket (Denied once the bucket exists, never Permitted).
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary");
    assert!(
        !matches!(
            inbound(&standby[0], &active, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "an arbitrary remote must never be admitted by the synced grant (#15676 fail-closed)"
    );
}

/// Same mechanism, address-only arm (`rewrite_src_port == None`): the
/// standby's `record_synced_persistent_permission` on the address-only path
/// must use the same resolved pair.
#[test]
fn synced_address_only_persistent_grant_survives_failover_15676() {
    // Port-bearing flow on the active, imported as address-only on the
    // standby: same session key, wire decision carries no translated port.
    let active_rules = iface_scoped_persistent_rules();
    let remote: IpAddr = "198.51.100.20".parse().expect("remote");
    let now = 1_000u64;
    let active = outbound_iface(&active_rules, remote, 443, now);

    let standby = iface_scoped_persistent_rules();
    reserve_synced_source_nat_allocation(
        &InterfaceNatAllocators::default(),
        &standby,
        &session_key(SRC_PORT, "198.51.100.20", 443),
        NatDecision {
            rewrite_src: active.rewrite_src,
            rewrite_src_port: None,
            ..NatDecision::default()
        },
        false,
        Some(("trust", "wan")),
        now,
        SyncedSourceNatDomains::default(),
    );
    // Address-only: the translated port is the preserved source port.
    let mut probe = active;
    probe.rewrite_src_port = Some(SRC_PORT);
    assert!(
        matches!(
            inbound(&standby[0], &probe, remote, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "address-only synced grant must land in the active's (trust,wan) bucket (#15676)"
    );
}

/// Global rule-set variant: no authored scope at all.
#[test]
fn synced_global_persistent_grant_survives_failover_15676() {
    let active_rules = global_persistent_rules();
    let remote: IpAddr = "198.51.100.20".parse().expect("remote");
    let now = 1_000u64;
    let active = outbound_global(&active_rules, remote, 443, now);

    let standby = global_persistent_rules();
    import_synced(
        &standby,
        "198.51.100.20",
        443,
        &active,
        Some(("trust", "wan")),
        now,
    );
    assert!(
        matches!(
            inbound(&standby[0], &active, remote, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "global rule-set synced grant must land in the active's (trust,wan) bucket (#15676)"
    );
}

/// Zone-scoped control: authored zones already equal the resolved pair, so
/// this passed pre-fix and must keep passing (no regression on the common
/// case #15133 fixed).
#[test]
fn synced_zone_scoped_persistent_grant_still_survives_15676() {
    let snap = || SourceNATRuleSnapshot {
        name: "zone-persist".to_string(),
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
    };
    let active_rules = parse_source_nat_rules(&[snap()]);
    let remote: IpAddr = "198.51.100.20".parse().expect("remote");
    let now = 1_000u64;
    let mut counter = None;
    let active = match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &active_rules,
        &NatScopeCtx::default(),
        "trust",
        "wan",
        SRC_IP.parse().expect("src"),
        remote,
        Some(PROTO_TCP),
        SRC_PORT,
        443,
        None,
        None,
        now,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(d) => d,
        other => panic!("active outbound must translate, got {other:?}"),
    };
    let standby = parse_source_nat_rules(&[snap()]);
    import_synced(
        &standby,
        "198.51.100.20",
        443,
        &active,
        Some(("trust", "wan")),
        now,
    );
    assert!(
        matches!(
            inbound(&standby[0], &active, remote, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "zone-scoped synced grant must keep surviving failover (#15676 control)"
    );
}

/// PASS-2 fallback guard: with `synced_zones == None` (old peer / drift) the
/// reservation is still taken and the lease rebuilt — the fix must not
/// remove reservations the pre-#6211 fallback provided. (The grant bucket
/// keeps the authored fallback; this cell pins availability, not bucket
/// identity, for the unresolvable case.)
#[test]
fn synced_without_resolved_zones_still_reserves_15676() {
    let active_rules = iface_scoped_persistent_rules();
    let remote: IpAddr = "198.51.100.20".parse().expect("remote");
    let now = 1_000u64;
    let active = outbound_iface(&active_rules, remote, 443, now);

    let standby = iface_scoped_persistent_rules();
    import_synced(&standby, "198.51.100.20", 443, &active, None, now);
    let status = &source_nat_pool_statuses(&standby)[0];
    assert_eq!(
        status.persistent_leases, 1,
        "PASS 2 fallback must still rebuild the lease (#15676)"
    );
    assert_eq!(
        status.live_flows, 1,
        "PASS 2 fallback must still hold the reservation (#15676)"
    );
}
