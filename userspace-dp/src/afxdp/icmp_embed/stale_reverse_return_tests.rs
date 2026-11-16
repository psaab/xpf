//! Repro: an ICMP error (PTB, unreachable) quoting a client's FORWARD packet
//! is returned to the client with the reverse session's STORED resolution
//! (`embedded_icmp_return_resolution`, `icmp_embed/return_resolution.rs`). A
//! reply on that same reverse goes through the packet path's consolidated
//! re-resolution (`reresolve_stored_session`) on every packet. When the stored
//! value is stale, the two disagree, and the ICMP error goes somewhere the
//! flow's replies do not.
//!
//! Two shapes, each asserting the CORRECT property (the ICMP error follows the
//! reply path). Each FAILS while the defect exists:
//! - **(a) HA:** the shared reverse is the import-time FabricRedirect,
//!   synthesized while the client-side RG was inactive here. After that RG
//!   activates, a reply forwards locally, but the ICMP error goes over the
//!   fabric to the demoted peer, blackholing path-MTU discovery.
//! - **(b) non-HA:** a local reverse resolved under one FIB; the route to the
//!   client moves. A reply follows the new route; the ICMP error follows the
//!   old one.

use super::return_resolution::embedded_icmp_return_resolution;
use super::*;
use crate::afxdp::forwarding::{
    lookup_forwarding_resolution_with_dynamic_for_flow, resolve_fabric_redirect,
};
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::session_glue::{FabricArrival, reresolve_stored_session};
use crate::afxdp::test_fixtures::nat_snapshot_with_fabric;
use crate::prefix::PrefixV4;

const NOW_SECS: u64 = 1_000_000;
const NOW_NS: u64 = NOW_SECS * 1_000_000_000;

fn active() -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: NOW_SECS,
        lease: HAGroupRuntime::active_lease_until(NOW_SECS, NOW_SECS),
    }
}

fn reverse_metadata(
    ingress_zone: u32,
    egress_zone: u32,
    ingress_ifindex: u32,
    owner_rg_id: i32,
) -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone,
        egress_zone,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

fn decision(resolution: ForwardingResolution) -> SessionDecision {
    SessionDecision {
        resolution,
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn packet_arrival(ingress_ifindex: i32) -> FabricArrival<'static> {
    FabricArrival::Packet {
        fabric_ingress: false,
        fabric_link_ingress: false,
        ingress_ifindex,
        ha_startup_grace_until_secs: 0,
        fabric_adopted: false,
        adopted_recovery: None,
    }
}

struct Maps {
    sessions: SessionTable,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_indexes: crate::afxdp::types::SharedSessionOwnerRgIndexes,
}

impl Maps {
    fn new() -> Self {
        Self {
            sessions: SessionTable::new(),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            owner_indexes: crate::afxdp::types::SharedSessionOwnerRgIndexes::default(),
        }
    }

    fn ctx<'a>(
        &'a mut self,
        forwarding: &'a ForwardingState,
        neighbors: &'a Arc<ShardedNeighborMap>,
    ) -> NatMatchCtx<'a> {
        NatMatchCtx {
            sessions: &mut self.sessions,
            forwarding,
            dynamic_neighbors: neighbors,
            shared_sessions: &self.shared_sessions,
            shared_nat_sessions: &self.shared_nat_sessions,
            shared_owner_rg_indexes: Some(&self.owner_indexes),
            shared_forward_wire_sessions: &self.shared_forward_wire_sessions,
            ingress_zone_override: None,
        }
    }
}

/// (a) The loss-cluster topology (`nat_snapshot_with_fabric`): `reth0.80`
/// (RG1) is the WAN, `reth1.0` (RG2) the LAN, `fab0` the fabric. The flow is a
/// LAN client's TCP flow to a WAN server, imported from the peer while this node
/// owned only RG1. Its reverse (server -> client) was synthesized then as a
/// FabricRedirect, because the client-side RG2 was the peer's. Now RG2 is active
/// here too.
#[test]
fn an_icmp_error_follows_the_reply_path_after_activation_not_a_stale_fabric_redirect() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let forward = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: client,
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 35_790,
        dst_port: 5211,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let redirect = resolve_fabric_redirect(&state).expect("FIXTURE: the fabric redirect resolves");
    let stored = decision(redirect);
    let metadata = reverse_metadata(state.egress_zone_id(12), state.egress_zone_id(24), 12, 2);

    let mut maps = Maps::new();
    crate::afxdp::shared_ops::publish_shared_session(
        &maps.shared_sessions,
        &maps.shared_nat_sessions,
        &maps.shared_forward_wire_sessions,
        &maps.owner_indexes,
        &SyncedSessionEntry {
            sibling_last_seen_ns: 0,
            last_served_ns: 0,
            key: reverse.clone(),
            decision: stored,
            metadata: metadata.clone(),
            leak_incarnation: 0,
            origin: SessionOrigin::SyncImport,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0x10,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            rev_packets: 0,
            fwd_packets: 0,
            pptp_call_ids: 0,
            persistent_lease_hold: None,
            source_nat_static: None,
        },
    );

    // The reply's forwarding after activation (both RGs active here): the
    // packet path's consolidated re-resolution of the stored reverse.
    let ha = BTreeMap::from([(1, active()), (2, active())]);
    let looked_up =
        lookup_forwarding_resolution_with_dynamic_for_flow(&state, &neighbors, client, &reverse)
            .resolution;
    let reply = reresolve_stored_session(
        &state,
        &ha,
        &neighbors,
        NOW_SECS,
        &stored,
        &metadata,
        &reverse,
        client,
        looked_up,
        packet_arrival(12),
    );
    assert_ne!(
        reply.disposition,
        ForwardingDisposition::FabricRedirect,
        "FIXTURE: once the client-side RG is active here, the reply must forward locally ({reply:?})"
    );

    // An ICMP error quoting the client's forward packet, returned to the client.
    let icmp = embedded_icmp_return_resolution(
        &mut maps.ctx(&state, &neighbors),
        &forward,
        stored,
        client,
        NOW_NS,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "an ICMP error to the client must take the reply's path; the return path used the reverse's \
         STORED import-time FabricRedirect and sends it over the fabric to the demoted peer \
         (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (b) No HA: a local reverse resolved while the route to the client went out
/// egress 99; the route moves to egress 11.
#[test]
fn an_icmp_error_follows_the_reply_path_after_a_fib_change() {
    let client = Ipv4Addr::new(10, 99, 1, 50);
    let fib = |egress: i32| {
        let row = |src_mac: [u8; 6]| EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu: 1500,
            src_mac,
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        };
        let mut state = ForwardingState::default();
        state.egress.insert(11, row([0x02, 0xaa, 0, 0, 0, 11]));
        state.egress.insert(99, row([0x02, 0xaa, 0, 0, 0, 99]));
        state.routes_v4.insert(
            "inet.0".to_string(),
            vec![RouteEntryV4::single(
                PrefixV4::from_net("10.99.1.0/24".parse().expect("prefix")),
                egress,
                0,
                Some(client),
                false,
                String::new(),
                0,
            )],
        );
        state
    };
    let neighbors = Arc::new(ShardedNeighborMap::new());
    for ifindex in [11, 99] {
        neighbors.insert(
            (ifindex, IpAddr::V4(client)),
            crate::afxdp::types::NeighborEntry {
                mac: [0x02, 0, 0, 0, 0, ifindex as u8],
            },
        );
    }
    let forward = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(client),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        src_port: 40_000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let before = fib(99);
    let stored_resolution = lookup_forwarding_resolution_with_dynamic_for_flow(
        &before,
        &neighbors,
        IpAddr::V4(client),
        &reverse,
    )
    .resolution;
    assert_eq!(
        (
            stored_resolution.disposition,
            stored_resolution.egress_ifindex
        ),
        (ForwardingDisposition::ForwardCandidate, 99),
        "FIXTURE: the reverse resolves out egress 99 before the change ({stored_resolution:?})"
    );
    let stored = decision(stored_resolution);
    let metadata = reverse_metadata(0, 0, 0, 0);
    let mut maps = Maps::new();
    assert!(
        maps.sessions.install_with_protocol(
            reverse.clone(),
            stored,
            metadata.clone(),
            NOW_NS,
            crate::ip_proto::PROTO_TCP,
            0x10
        ),
        "FIXTURE: the local reverse must install"
    );

    let after = fib(11);
    let looked_up = lookup_forwarding_resolution_with_dynamic_for_flow(
        &after,
        &neighbors,
        IpAddr::V4(client),
        &reverse,
    )
    .resolution;
    let reply = reresolve_stored_session(
        &after,
        &BTreeMap::new(),
        &neighbors,
        NOW_SECS,
        &stored,
        &metadata,
        &reverse,
        IpAddr::V4(client),
        looked_up,
        packet_arrival(0),
    );
    assert_eq!(
        reply.egress_ifindex, 11,
        "FIXTURE: after the route moves, the reply re-resolves out egress 11 ({reply:?})"
    );

    let icmp = embedded_icmp_return_resolution(
        &mut maps.ctx(&after, &neighbors),
        &forward,
        stored,
        IpAddr::V4(client),
        NOW_NS,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "an ICMP error to the client must take the reply's path after a FIB change; the return path \
         used the reverse's STORED resolution (icmp={icmp:?}, reply={reply:?})"
    );
}
