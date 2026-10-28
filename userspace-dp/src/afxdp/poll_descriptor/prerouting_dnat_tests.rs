// #17197: parity between the production pre-routing DNAT verdict and
// the Stage-11 IPsec claim. The matrix iterates
// {unambiguous, ambiguous} x {no rule, unscoped dnat, scoped dnat,
// scoped dnat-to-self, poisoned dnat, static-nat, persistent lease}
// and asserts the Stage-11 claim (via the real
// `stage_ipsec_passthrough_check_with_scope`) equals "production
// verdict is None or a translate-to-self".
//
// RED on the pre-fix tree: the poisoned, static-nat and ambiguous
// scoped-dnat-to-self rows fail because the deleted mirror
// (`ipsec_destination_matches_transit_dnat`) consulted only the
// dynamic tier through the collapsing lookup and modelled the scope
// instead of calling `prerouting_ingress_scope{,_ambiguous}`.
use super::super::poll_stages::{
    IpsecPassthroughOutcome, stage_ipsec_passthrough_check_with_scope,
};
use super::*;
use crate::afxdp::tests_support::*;
use std::net::Ipv4Addr;

const VIP: &str = "172.16.80.8";
const TRANSIT: &str = "10.0.61.102";
const SELF_ADDR: &str = "172.16.80.8";

fn ike_frame_17197() -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = PROTO_UDP;
    frame.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
    frame.extend_from_slice(&0u64.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x20, 0x22, 0x08]);
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame
}

fn ike_meta_17197(frame: &[u8]) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 21,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    }
}

fn ike_flow_17197() -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let dst_ip: IpAddr = VIP.parse().unwrap();
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip,
            dst_ip,
            src_port: 40000,
            dst_port: 500,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Row {
    NoRule,
    UnscopedDnat,
    ScopedDnat,
    ScopedDnatToSelf,
    PoisonedDnat,
    StaticNat,
    PersistentLease,
}

fn snapshot_17197(row: Row) -> crate::ConfigSnapshot {
    let mut snap = super::super::test_fixtures::nat_snapshot_with_fabric();
    snap.zones.push(crate::ZoneSnapshot {
        name: "fabric".to_string(),
        id: crate::test_zone_ids::TEST_FABRIC_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["ike".to_string()],
        ..Default::default()
    });
    for iface in &mut snap.interfaces {
        if iface.ifindex == 21 {
            iface.zone = "fabric".to_string();
        }
        if iface.name == "reth0.80" {
            iface.redundancy_group = 1;
        }
    }
    match row {
        Row::NoRule => {}
        Row::UnscopedDnat | Row::ScopedDnat | Row::ScopedDnatToSelf | Row::PoisonedDnat => {
            let (from_zone, pool, poisoned) = match row {
                Row::UnscopedDnat => ("", TRANSIT, false),
                Row::ScopedDnat => ("fabric", TRANSIT, false),
                Row::ScopedDnatToSelf => ("fabric", SELF_ADDR, false),
                Row::PoisonedDnat => ("", TRANSIT, true),
                _ => unreachable!(),
            };
            snap.destination_nat_rules = vec![crate::DestinationNATRuleSnapshot {
                name: "parity-17197".to_string(),
                from_zone: from_zone.to_string(),
                destination_address: VIP.to_string(),
                destination_port: 500,
                protocol: "udp".to_string(),
                pool_address: pool.to_string(),
                pool_port: 500,
                lenient_match_dropped: poisoned,
                ..Default::default()
            }];
        }
        Row::StaticNat => {
            snap.static_nat_rules = vec![crate::StaticNATRuleSnapshot {
                name: "static-17197".to_string(),
                external_ip: VIP.to_string(),
                internal_ip: TRANSIT.to_string(),
                ..Default::default()
            }];
        }
        Row::PersistentLease => {
            snap.source_nat_rules.clear();
            snap.source_nat_rules.push(crate::SourceNATRuleSnapshot {
                name: "persistent-17197".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "fabric".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                pool_name: "persistent-pool-17197".to_string(),
                pool_addresses: vec![VIP.to_string()],
                port_low: 500,
                port_high: 500,
                persistent_nat: true,
                persistent_nat_permit_any_remote_host: true,
                persistent_nat_permit: "any-remote-host".to_string(),
                persistent_nat_inactivity_timeout: 3600,
                ..Default::default()
            });
        }
    }
    snap
}

/// Mint the LAN host's persistent lease outbound (TRANSIT:12345 ->
/// 8.8.8.8:53 translated to VIP:500), then release the outbound flow
/// so the lease is idle and admits the inbound IKE packet to VIP:500.
fn mint_persistent_lease_17197(forwarding: &ForwardingState) {
    let rule = forwarding
        .source_nat_rules
        .iter()
        .find(|rule| rule.persistent_nat && rule.pool_mode)
        .expect("fixture: persistent pool rule");
    let internal_host = TRANSIT;
    let mut counter = None;
    let minted = match crate::nat::match_source_nat_result_for_tuple(
        &crate::nat::InterfaceNatAllocators::default(),
        std::slice::from_ref(rule),
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "fabric",
        internal_host.parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(PROTO_UDP),
        12345,
        53,
        None,
        None,
        TEST_NOW_NS_17197,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(decision) => decision,
        other => panic!("fixture: outbound persistent mint must match, got {other:?}"),
    };
    assert_eq!(
        minted.rewrite_src,
        Some(VIP.parse().unwrap()),
        "fixture: persistent mint must translate the source to the VIP"
    );
    assert_eq!(
        minted.rewrite_src_port,
        Some(500),
        "fixture: persistent mint must allocate pool port 500"
    );
    let outbound_key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: internal_host.parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 12345,
        dst_port: 53,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    crate::nat::release_source_nat_allocation_for_worker(
        &crate::nat::InterfaceNatAllocators::default(),
        std::slice::from_ref(rule),
        &outbound_key,
        minted,
        false,
        TEST_NOW_NS_17197 + 1,
        0,
    );
}
const TEST_NOW_NS_17197: u64 = 128 * 1_000_000_000;

fn production_claim_17197(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ambiguous: bool,
) -> bool {
    let scope = if ambiguous {
        prerouting_ingress_scope_ambiguous(forwarding, 21, 0)
    } else {
        prerouting_ingress_scope(forwarding, 21, 0, None, None)
    };
    let verdict = prerouting_dnat_verdict(
        forwarding,
        &meta,
        flow,
        &scope,
        None,
        false,
        TEST_NOW_NS_17197,
    );
    match &verdict {
        PreroutingDnatVerdict::None => true,
        PreroutingDnatVerdict::Static(..)
        | PreroutingDnatVerdict::Persistent(..)
        | PreroutingDnatVerdict::Dynamic(..) => verdict.translates_to_self(forwarding),
        PreroutingDnatVerdict::Poisoned(_) | PreroutingDnatVerdict::Denied => false,
    }
}

fn stage11_claim_17197(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    frame: &[u8],
    meta: UserspaceDpMeta,
    ambiguous: bool,
) -> bool {
    let ha_state = BTreeMap::from([
        (
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 128,
                lease: HAForwardingLease::ActiveUntil(128 + 60),
            },
        ),
        (
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 128,
                lease: HAForwardingLease::ActiveUntil(128 + 60),
            },
        ),
    ]);
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 21,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let pptp_control = Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let ctx = WorkerContext {
        pptp_control: &pptp_control,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state: &ha_state,
        forwarding_active_rgs: &*EMPTY_FWD_ACTIVE_RGS_16217,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let live = BindingLiveState::new();
    let outcome = stage_ipsec_passthrough_check_with_scope(
        Some(flow),
        frame,
        meta,
        None,
        ambiguous.then_some(crate::test_zone_ids::TEST_LAN_ZONE_ID),
        None,
        None,
        &live,
        &ctx,
        TEST_NOW_NS_17197,
        128,
    );
    !matches!(outcome, IpsecPassthroughOutcome::NotClaimed)
}
#[test]
fn prerouting_dnat_stage11_parity_17197() {
    let frame = ike_frame_17197();
    let flow = ike_flow_17197();
    let rows = [
        Row::NoRule,
        Row::UnscopedDnat,
        Row::ScopedDnat,
        Row::ScopedDnatToSelf,
        Row::PoisonedDnat,
        Row::StaticNat,
        Row::PersistentLease,
    ];
    for row in rows {
        for ambiguous in [false, true] {
            let forwarding = build_forwarding_state(&snapshot_17197(row));
            if row == Row::PersistentLease {
                mint_persistent_lease_17197(&forwarding);
            }
            let meta = ike_meta_17197(&frame);
            let production = production_claim_17197(&forwarding, &flow, meta, ambiguous);
            // Fixture sanity per row: the production verdict must be
            // the one the row names, so a vacuous fixture cannot make
            // both sides agree on the wrong answer.
            match (row, ambiguous) {
                (Row::NoRule, _) => assert!(
                    production,
                    "fixture: no-rule row must leave the destination local"
                ),
                (Row::UnscopedDnat, _) | (Row::ScopedDnat, false) => assert!(
                    !production,
                    "fixture: {row:?} unambiguous must select transit DNAT"
                ),
                (Row::ScopedDnat, true) => assert!(
                    !production,
                    "fixture: scoped DNAT under ambiguous provenance must fail closed"
                ),
                (Row::ScopedDnatToSelf, false) => {
                    assert!(production, "fixture: scoped DNAT-to-self must stay local")
                }
                (Row::ScopedDnatToSelf, true) => assert!(
                    !production,
                    "fixture: ambiguous scoped DNAT-to-self must fail closed (production Poisoned)"
                ),
                (Row::PoisonedDnat, _) => {
                    assert!(!production, "fixture: poisoned DNAT must fail closed")
                }
                (Row::StaticNat, _) => assert!(
                    !production,
                    "fixture: static NAT must select the transit translation"
                ),
                (Row::PersistentLease, false) => assert!(
                    !production,
                    "fixture: persistent lease must select the transit translation"
                ),
                (Row::PersistentLease, true) => assert!(
                    production,
                    "fixture: persistent reader is skipped under ambiguous provenance"
                ),
            }
            let stage11 = stage11_claim_17197(&forwarding, &flow, &frame, meta, ambiguous);
            assert_eq!(
                stage11, production,
                "#17197 parity: row {row:?} ambiguous={ambiguous}: Stage-11 claim \
                 must equal \"production verdict is None or translate-to-self\""
            );
        }
    }
}
