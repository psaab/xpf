//! #19164: an ICMP error (PTB, unreachable) quoting a client's FORWARD packet
//! is returned to the client by the route a REPLY on the matched reverse
//! session would take. Before #19164 it used the reverse's STORED resolution
//! verbatim (`embedded_icmp_return_resolution`), while a reply on the same
//! reverse is looked up again on every packet (`resolve.rs` into
//! `reresolve_stored_session`).
//!
//! Each cell drives the poll arm's real sequence: the return resolution, then
//! `finalize_embedded_icmp_return_parts` (the HA snapshot, the fabric redirect
//! and, for a stored FabricRedirect, the reply's retain verdict). It compares
//! the result with the reply pipeline's.
//! - **(a) HA activation:** the shared reverse is the import-time
//!   FabricRedirect; the client-side RG is now active here.
//! - **(b) a FIB change:** a local reverse; the route moves and the forwarding
//!   generation advances.
//! - **(c) the split node, v4 and v6** (#19164 review, seat r23 P1-1): the peer
//!   owns the client-side RG, and its LAN prefix is withheld from the FIB
//!   (#15742), so the FIB answers the client with the WAN default route. The
//!   reply keeps its fabric redirect, and so must the error.
//! - **No fallback the reply would refuse** (r23 P2-1): (d) a stale stamp
//!   whose new route has no neighbor yet, (e) a #11315 MAC mismatch, (f) a
//!   #1873 re-owned tunnel, (h) a vanished installing table.
//! - **(g) the lookup variant, v4 and v6** (r23 P3-1): synced for a
//!   peer-synced reverse, cached for a local one.
//!
//! (a) and (b) were RED at b725d9542e, before the fix; (c)-(f) at e5ecb4e764.

use super::return_resolution::embedded_icmp_return_resolution;
use super::*;
use crate::afxdp::forwarding::{
    lookup_forwarding_resolution_with_dynamic_for_flow, resolve_fabric_redirect,
};
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::session_glue::{FabricArrival, reresolve_stored_session};
use crate::afxdp::test_fixtures::nat_snapshot_with_fabric;
use crate::prefix::{PrefixV4, PrefixV6};
use std::net::Ipv6Addr;

const NOW_SECS: u64 = 1_000_000;
const NOW_NS: u64 = NOW_SECS * 1_000_000_000;
const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);

fn active() -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: NOW_SECS,
        lease: HAGroupRuntime::active_lease_until(NOW_SECS, NOW_SECS),
    }
}

fn inactive() -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp: NOW_SECS,
        lease: HAForwardingLease::Inactive,
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

/// The reply path's lookup for a stored reverse (`resolve.rs`'s hit arm): the
/// cache-free variant when its forwarding generation is stale, else the
/// synced-session variant for a peer-synced reverse, else the cached one.
fn reply_lookup(
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    reverse: &SessionKey,
    stored: SessionDecision,
    stale: bool,
    peer_synced: bool,
) -> ForwardingResolution {
    let flow = SessionFlow {
        src_ip: reverse.src_ip,
        dst_ip: reverse.dst_ip,
        forward_key: reverse.clone(),
    };
    if stale {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_session_without_cache(
            forwarding, neighbors, &flow, stored,
        )
        .resolution
    } else if peer_synced {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_synced_session(
            forwarding, neighbors, &flow, stored,
        )
        .resolution
    } else {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_session(
            forwarding, neighbors, &flow, stored,
        )
        .resolution
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

    fn publish_shared_reverse(
        &self,
        key: &SessionKey,
        stored: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.shared_sessions,
            &self.shared_nat_sessions,
            &self.shared_forward_wire_sessions,
            &self.owner_indexes,
            &SyncedSessionEntry {
                sibling_last_seen_ns: 0,
                last_served_ns: 0,
                key: key.clone(),
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
    }
}

/// The loss-cluster topology (`nat_snapshot_with_fabric`): `reth0.80` (RG1,
/// ifindex 12) is the WAN, `reth1.0` (RG2, ifindex 24) the LAN, `fab0` the
/// fabric; v4 and v6 default routes leave by the WAN gateway. A LAN client's
/// TCP flow to a WAN server; its shared reverse (server -> client) is the
/// import-time FabricRedirect, synthesized while RG2 was the peer's. The
/// client's neighbor is known on the LAN egress.
///
/// `split`: the production FIB of the node whose peer owns RG2. The peer-owned
/// LAN connected prefix is withheld from the transit FIB (#15742,
/// `connected_rg_peer_owned`), so the FIB answers the client with the WAN
/// default route.
struct HaShape {
    state: ForwardingState,
    neighbors: Arc<ShardedNeighborMap>,
    client: IpAddr,
    forward: SessionKey,
    reverse: SessionKey,
    stored: SessionDecision,
    metadata: SessionMetadata,
    maps: Maps,
}

fn flow(client: IpAddr, server: IpAddr, src_port: u16) -> (SessionKey, SessionKey) {
    let forward = SessionKey {
        addr_family: match client {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        },
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: client,
        dst_ip: server,
        src_port,
        dst_port: 5211,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    (forward, reverse)
}

fn learn(neighbors: &ShardedNeighborMap, ifindex: i32, ip: IpAddr, mac: [u8; 6]) {
    neighbors.insert((ifindex, ip), crate::afxdp::types::NeighborEntry { mac });
}

fn ha_shape(src_port: u16, client: IpAddr, server: IpAddr, split: bool) -> HaShape {
    let (forward, reverse) = flow(client, server, src_port);
    let mut snapshot = nat_snapshot_with_fabric();
    if split {
        for iface in &mut snapshot.interfaces {
            if iface.name == "reth1.0" {
                iface.connected_rg_peer_owned = true;
            }
        }
    }
    let state = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn(&neighbors, 24, client, [0x02, 0, 0, 0, 0, 24]);
    let stored =
        decision(resolve_fabric_redirect(&state).expect("FIXTURE: the fabric redirect resolves"));
    let metadata = reverse_metadata(state.egress_zone_id(12), state.egress_zone_id(24), 12, 2);
    let maps = Maps::new();
    maps.publish_shared_reverse(&reverse, stored, &metadata);
    HaShape {
        state,
        neighbors,
        client,
        forward,
        reverse,
        stored,
        metadata,
        maps,
    }
}

/// The ICMP error as the poll arm resolves it: the return resolution, then
/// `finalize_embedded_icmp_return_parts`, for an arrival on `ingress_ifindex`
/// in `ingress_zone`.
#[expect(clippy::too_many_arguments, reason = "#19164 test driver")]
fn icmp_return(
    maps: &mut Maps,
    state: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    forward: &SessionKey,
    forward_decision: SessionDecision,
    ingress_ifindex: i32,
    ingress_zone: u32,
) -> ForwardingResolution {
    let raw = embedded_icmp_return_resolution(
        &mut maps.ctx(state, neighbors),
        forward,
        forward_decision,
        forward.src_ip,
        NOW_NS,
    );
    super::builders::finalize_embedded_icmp_return_parts(
        state,
        ha,
        NOW_SECS,
        ingress_ifindex,
        raw.resolution,
        ingress_zone,
        raw.stored_redirect.as_ref(),
    )
}

/// The reply on `reverse`, for an arrival on `ingress_ifindex`.
#[expect(clippy::too_many_arguments, reason = "#19164 test driver")]
fn reply(
    state: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    neighbors: &Arc<ShardedNeighborMap>,
    reverse: &SessionKey,
    stored: SessionDecision,
    metadata: &SessionMetadata,
    stale: bool,
    peer_synced: bool,
    ingress_ifindex: i32,
) -> ForwardingResolution {
    let looked_up = reply_lookup(state, neighbors, reverse, stored, stale, peer_synced);
    reresolve_stored_session(
        state,
        ha,
        neighbors,
        NOW_SECS,
        &stored,
        metadata,
        reverse,
        crate::afxdp::session_glue::resolution_target_for_session(
            &SessionFlow {
                src_ip: reverse.src_ip,
                dst_ip: reverse.dst_ip,
                forward_key: reverse.clone(),
            },
            stored,
        ),
        looked_up,
        packet_arrival(ingress_ifindex),
    )
}

fn icmp_as_finalized(
    shape: &mut HaShape,
    ha: &BTreeMap<i32, HAGroupRuntime>,
) -> ForwardingResolution {
    let zone = shape.state.egress_zone_id(12);
    icmp_return(
        &mut shape.maps,
        &shape.state,
        &shape.neighbors,
        ha,
        &shape.forward,
        shape.stored,
        12,
        zone,
    )
}

fn reply_of(shape: &HaShape, ha: &BTreeMap<i32, HAGroupRuntime>) -> ForwardingResolution {
    reply(
        &shape.state,
        ha,
        &shape.neighbors,
        &shape.reverse,
        shape.stored,
        &shape.metadata,
        false,
        true,
        12,
    )
}

/// (a) After RG2 activates here, the reply forwards locally, and so must the
/// ICMP error. Before the fix it took the stale FabricRedirect over the fabric.
#[test]
fn an_icmp_error_follows_the_reply_path_after_activation_not_a_stale_fabric_redirect() {
    let mut shape = ha_shape(
        35_790,
        IpAddr::V4(CLIENT_V4),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        false,
    );
    let ha = BTreeMap::from([(1, active()), (2, active())]);
    let reply = reply_of(&shape, &ha);
    assert_eq!(
        (reply.disposition, reply.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, 24),
        "FIXTURE: once the client-side RG is active here, the reply forwards out the LAN ({reply:?})"
    );
    let icmp = icmp_as_finalized(&mut shape, &ha);
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "an ICMP error to the client must take the reply's path, not the reverse's stored import-time \
         FabricRedirect over the fabric to the demoted peer (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (c) The split node: RG1 (WAN) active here, RG2 (LAN) on the peer, with the
/// production split FIB. The fresh lookup answers the LAN client with the WAN
/// default route, an active local ForwardCandidate. The reply keeps its stored
/// FabricRedirect over it (the retain verdict), and so must the ICMP error;
/// e5ecb4e764 sent it out the WAN to the client's private address.
fn split_node_keeps_the_fabric_redirect(client: IpAddr, server: IpAddr, src_port: u16) {
    let mut shape = ha_shape(src_port, client, server, true);
    let ha = BTreeMap::from([(1, active()), (2, inactive())]);
    let fresh = reply_lookup(
        &shape.state,
        &shape.neighbors,
        &shape.reverse,
        shape.stored,
        false,
        true,
    );
    assert_eq!(
        (fresh.disposition, fresh.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, 12),
        "FIXTURE: on the split node the FIB answers the peer-owned LAN client {client} with the WAN \
         default route (#15742) ({fresh:?})"
    );
    let reply = reply_of(&shape, &ha);
    assert_eq!(
        reply.disposition,
        ForwardingDisposition::FabricRedirect,
        "FIXTURE: the reply keeps its fabric redirect over the WAN answer ({reply:?})"
    );
    let icmp = icmp_as_finalized(&mut shape, &ha);
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex, icmp.neighbor_mac),
        (reply.disposition, reply.egress_ifindex, reply.neighbor_mac),
        "an ICMP error to the peer-owned client {client} must follow the reply over the fabric, not \
         out the WAN (icmp={icmp:?}, reply={reply:?})"
    );
    assert_eq!(shape.client, client);
}

#[test]
fn an_icmp_error_keeps_the_fabric_redirect_on_the_split_node_v4() {
    split_node_keeps_the_fabric_redirect(
        IpAddr::V4(CLIENT_V4),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        35_791,
    );
}

#[test]
fn an_icmp_error_keeps_the_fabric_redirect_on_the_split_node_v6() {
    split_node_keeps_the_fabric_redirect(
        IpAddr::V6("2001:559:8585:ef00::102".parse().expect("v6 client")),
        IpAddr::V6("2001:559:8585:80::200".parse().expect("v6 server")),
        35_793,
    );
}

/// A local FIB: egress rows 11 and 99, and, when `route_egress` is set, a
/// route for `prefix` out that egress with `client` as the next hop.
fn local_fib(client: IpAddr, prefix: &str, route_egress: Option<i32>) -> ForwardingState {
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
    let Some(egress) = route_egress else {
        return state;
    };
    match client {
        IpAddr::V4(client) => {
            state.routes_v4.insert(
                "inet.0".to_string(),
                vec![RouteEntryV4::single(
                    PrefixV4::from_net(prefix.parse().expect("v4 prefix")),
                    egress,
                    0,
                    Some(client),
                    false,
                    String::new(),
                    0,
                )],
            );
        }
        IpAddr::V6(client) => {
            state.routes_v6.insert(
                "inet6.0".to_string(),
                vec![RouteEntryV6::single(
                    PrefixV6::from_net(prefix.parse().expect("v6 prefix")),
                    egress,
                    0,
                    Some(client),
                    false,
                    String::new(),
                    0,
                )],
            );
        }
    }
    state
}

/// A local reverse for `client`, resolved under `before` and installed in the
/// worker's table.
fn install_local_reverse(
    maps: &mut Maps,
    before: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    reverse: &SessionKey,
    client: IpAddr,
    egress: i32,
) -> SessionDecision {
    let resolved =
        lookup_forwarding_resolution_with_dynamic_for_flow(before, neighbors, client, reverse)
            .resolution;
    assert_eq!(
        (resolved.disposition, resolved.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, egress),
        "FIXTURE: the reverse resolves out egress {egress} when it is installed ({resolved:?})"
    );
    let stored = decision(resolved);
    assert!(
        maps.sessions.install_with_protocol(
            reverse.clone(),
            stored,
            reverse_metadata(0, 0, 0, 0),
            NOW_NS,
            crate::ip_proto::PROTO_TCP,
            0x10
        ),
        "FIXTURE: the local reverse must install"
    );
    stored
}

fn stamp_is_stale(maps: &Maps, reverse: &SessionKey) -> bool {
    let stamp = crate::afxdp::shared_ops::probe_session_across_scopes_with_wire_indexes(
        &maps.sessions,
        &maps.shared_sessions,
        &maps.shared_forward_wire_sessions,
        Some(&maps.owner_indexes),
        reverse,
        NOW_NS,
    )
    .expect("FIXTURE: the reverse is found")
    .lookup
    .forwarding_generation;
    maps.sessions.forwarding_resolution_is_stale(stamp)
}

const SERVER_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

/// (b) No HA: a local reverse resolved while the route to the client went out
/// egress 99. The route moves to egress 11, and the worker's forwarding
/// generation advances with it, as a FIB change does in production. The reply
/// re-resolves cache-free and leaves by egress 11, and so must the ICMP error.
#[test]
fn an_icmp_error_follows_the_reply_path_after_a_fib_change() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 99, 1, 50));
    let (forward, reverse) = flow(client, IpAddr::V4(SERVER_V4), 40_000);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn(&neighbors, 11, client, [0x02, 0, 0, 0, 0, 11]);
    learn(&neighbors, 99, client, [0x02, 0, 0, 0, 0, 99]);
    let mut maps = Maps::new();
    maps.sessions.set_forwarding_revalidation_gen(1, 1);
    let before = local_fib(client, "10.99.1.0/24", Some(99));
    let stored = install_local_reverse(&mut maps, &before, &neighbors, &reverse, client, 99);
    let after = local_fib(client, "10.99.1.0/24", Some(11));
    maps.sessions.set_forwarding_revalidation_gen(1, 2);
    assert!(
        stamp_is_stale(&maps, &reverse),
        "FIXTURE: the stored resolution must be stale after the generation advanced"
    );
    let unclustered = BTreeMap::new();
    let reply = reply(
        &after,
        &unclustered,
        &neighbors,
        &reverse,
        stored,
        &reverse_metadata(0, 0, 0, 0),
        true,
        false,
        0,
    );
    assert_eq!(
        reply.egress_ifindex, 11,
        "FIXTURE: after the route moves, the reply re-resolves out egress 11 ({reply:?})"
    );
    let icmp = icmp_return(
        &mut maps,
        &after,
        &neighbors,
        &unclustered,
        &forward,
        stored,
        0,
        0,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "an ICMP error to the client must take the reply's path after a FIB change; the return path \
         used the reverse's STORED resolution (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (d) A stale stamp, and the new route has no neighbor yet. The reply refuses
/// the stored value there (cache-free lookup: MissingNeighbor on egress 11),
/// and so must the error. e5ecb4e764 fell back to the stored route and sent the
/// error out egress 99, which the FIB had replaced.
#[test]
fn an_icmp_error_never_takes_a_replaced_route_when_the_new_route_has_no_neighbor() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 99, 1, 51));
    let (forward, reverse) = flow(client, IpAddr::V4(SERVER_V4), 40_001);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn(&neighbors, 99, client, [0x02, 0, 0, 0, 0, 99]);
    let mut maps = Maps::new();
    maps.sessions.set_forwarding_revalidation_gen(1, 1);
    let before = local_fib(client, "10.99.1.0/24", Some(99));
    let stored = install_local_reverse(&mut maps, &before, &neighbors, &reverse, client, 99);
    let after = local_fib(client, "10.99.1.0/24", Some(11));
    maps.sessions.set_forwarding_revalidation_gen(1, 2);
    let unclustered = BTreeMap::new();
    let reply = reply(
        &after,
        &unclustered,
        &neighbors,
        &reverse,
        stored,
        &reverse_metadata(0, 0, 0, 0),
        true,
        false,
        0,
    );
    assert_eq!(
        (reply.disposition, reply.egress_ifindex),
        (ForwardingDisposition::MissingNeighbor, 11),
        "FIXTURE: no neighbor is known on the new egress yet ({reply:?})"
    );
    let icmp = icmp_return(
        &mut maps,
        &after,
        &neighbors,
        &unclustered,
        &forward,
        stored,
        0,
        0,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "the error must get the reply's answer, never the stale stored route out egress 99 \
         (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (e) A current stamp, but the stored MAC is no longer the live neighbor
/// (#11315: a gateway failover replaced it), and the route is gone. The reply's
/// cached variant rejects the stored value (`cached_session_resolution`) and
/// answers NoRoute; the error must not be sent to the stale MAC.
#[test]
fn an_icmp_error_never_takes_a_stored_mac_the_live_neighbor_contradicts() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 99, 2, 60));
    let (forward, reverse) = flow(client, IpAddr::V4(SERVER_V4), 40_002);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let stale_mac = [0x02, 0, 0, 0, 0xa0, 99];
    learn(&neighbors, 99, client, stale_mac);
    let mut maps = Maps::new();
    let before = local_fib(client, "10.99.2.0/24", Some(99));
    let stored = install_local_reverse(&mut maps, &before, &neighbors, &reverse, client, 99);
    assert_eq!(
        stored.resolution.neighbor_mac,
        Some(stale_mac),
        "FIXTURE: the stored MAC"
    );
    learn(&neighbors, 99, client, [0x02, 0, 0, 0, 0xb0, 99]);
    let after = local_fib(client, "10.99.2.0/24", None);
    assert!(
        !stamp_is_stale(&maps, &reverse),
        "FIXTURE: the stamp stays current"
    );
    let unclustered = BTreeMap::new();
    let reply = reply(
        &after,
        &unclustered,
        &neighbors,
        &reverse,
        stored,
        &reverse_metadata(0, 0, 0, 0),
        false,
        false,
        0,
    );
    assert_eq!(
        reply.disposition,
        ForwardingDisposition::NoRoute,
        "FIXTURE: the reply rejects the contradicted stored MAC and has no route ({reply:?})"
    );
    let icmp = icmp_return(
        &mut maps,
        &after,
        &neighbors,
        &unclustered,
        &forward,
        stored,
        0,
        0,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex, icmp.neighbor_mac),
        (reply.disposition, reply.egress_ifindex, reply.neighbor_mac),
        "the error must get the reply's answer, never the stale stored MAC (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (f) #1873: the stored resolution names tunnel endpoint 7 on ifindex 50, and
/// the id has since been re-owned by ifindex 51. The reply's lookup returns a
/// gated NoRoute so the session never adopts the new owner's encap; the error
/// must not fall back to the stored tunnel resolution.
#[test]
fn an_icmp_error_never_takes_a_re_owned_tunnel() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 99, 3, 70));
    let (forward, reverse) = flow(client, IpAddr::V4(SERVER_V4), 40_003);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut state = ForwardingState::default();
    state.tunnel_endpoints.insert(
        7,
        TunnelEndpoint {
            id: 7,
            logical_ifindex: 51,
            mtu: 0,
            interface_label: "gr1".into(),
            interface: "gr-0/0/0.1".into(),
            redundancy_group: 0,
            mode: "gre".into(),
            kind: crate::afxdp::tunnel_mode_kind("gre"),
            outer_family: libc::AF_INET,
            source: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            key: 0,
            ttl: 64,
            clear_dont_fragment_bit: false,
            transport_table: String::new(),
            wg_listen_port: 0,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        },
    );
    let stored = decision(ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 50,
        tx_ifindex: 50,
        tunnel_endpoint_id: 7,
        next_hop: None,
        neighbor_mac: Some([0x02, 0, 0, 0, 0, 50]),
        src_mac: Some([0x02, 0xaa, 0, 0, 0, 50]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    });
    let mut maps = Maps::new();
    assert!(
        maps.sessions.install_with_protocol(
            reverse.clone(),
            stored,
            reverse_metadata(0, 0, 0, 0),
            NOW_NS,
            crate::ip_proto::PROTO_TCP,
            0x10
        ),
        "FIXTURE: the local reverse must install"
    );
    let unclustered = BTreeMap::new();
    let reply = reply(
        &state,
        &unclustered,
        &neighbors,
        &reverse,
        stored,
        &reverse_metadata(0, 0, 0, 0),
        false,
        false,
        0,
    );
    let fresh = reply_lookup(&state, &neighbors, &reverse, stored, false, false);
    assert_eq!(
        (
            fresh.disposition,
            fresh.tunnel_endpoint_id,
            fresh.egress_ifindex
        ),
        (ForwardingDisposition::NoRoute, 7, 50),
        "FIXTURE: the reply's lookup gates the re-owned tunnel to NoRoute (#1873) ({fresh:?})"
    );
    assert_eq!(
        reply.disposition,
        ForwardingDisposition::NoRoute,
        "FIXTURE: the reply drops it ({reply:?})"
    );
    let icmp = icmp_return(
        &mut maps,
        &state,
        &neighbors,
        &unclustered,
        &forward,
        stored,
        0,
        0,
    );
    assert_eq!(
        icmp.disposition, reply.disposition,
        "the error must get the gated NoRoute, never the stored tunnel resolution (icmp={icmp:?})"
    );
}

/// (h) The reverse's installing table is gone (a deleted routing instance).
/// The reply's lookup answers TableUnavailable and does not use the stored
/// egress; neither may the error.
#[test]
fn an_icmp_error_never_takes_the_stored_egress_of_a_vanished_table() {
    let client = IpAddr::V4(Ipv4Addr::new(10, 99, 4, 80));
    let (forward, reverse) = flow(client, IpAddr::V4(SERVER_V4), 40_004);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn(&neighbors, 99, client, [0x02, 0, 0, 0, 0, 99]);
    let state = local_fib(client, "10.99.4.0/24", Some(99));
    let resolved =
        lookup_forwarding_resolution_with_dynamic_for_flow(&state, &neighbors, client, &reverse)
            .resolution;
    let stored = SessionDecision {
        install_table_domain: 0x5eed_0001,
        install_table_check: 1,
        ..decision(resolved)
    };
    let mut maps = Maps::new();
    assert!(
        maps.sessions.install_with_protocol(
            reverse.clone(),
            stored,
            reverse_metadata(0, 0, 0, 0),
            NOW_NS,
            crate::ip_proto::PROTO_TCP,
            0x10
        ),
        "FIXTURE: the local reverse must install"
    );
    let unclustered = BTreeMap::new();
    let reply = reply(
        &state,
        &unclustered,
        &neighbors,
        &reverse,
        stored,
        &reverse_metadata(0, 0, 0, 0),
        false,
        false,
        0,
    );
    assert_eq!(
        reply.disposition,
        ForwardingDisposition::TableUnavailable,
        "FIXTURE: the reply's lookup refuses the vanished installing table ({reply:?})"
    );
    let icmp = icmp_return(
        &mut maps,
        &state,
        &neighbors,
        &unclustered,
        &forward,
        stored,
        0,
        0,
    );
    assert_eq!(
        icmp.disposition, reply.disposition,
        "the error must not use the stored egress of a vanished table (icmp={icmp:?})"
    );
}

/// (g) The lookup variant. Both reverses were resolved out egress 99 and the
/// route has since moved to egress 11, with NO generation change, so both
/// stamps are current and the stored values still revalidate (#11315).
/// - A LOCAL reverse takes the cached variant: its fast path serves the stored
///   egress 99.
/// - A PEER-SYNCED reverse takes the synced variant, which skips the fast path:
///   the FIB answers egress 11.
///
/// The error must take each reply's variant.
fn the_return_uses_the_replys_lookup_variant(client: IpAddr, server: IpAddr, prefix: &str) {
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn(&neighbors, 11, client, [0x02, 0, 0, 0, 0, 11]);
    learn(&neighbors, 99, client, [0x02, 0, 0, 0, 0, 99]);
    let before = local_fib(client, prefix, Some(99));
    let after = local_fib(client, prefix, Some(11));
    let mut maps = Maps::new();
    let (forward_local, reverse_local) = flow(client, server, 41_000);
    let stored_local =
        install_local_reverse(&mut maps, &before, &neighbors, &reverse_local, client, 99);
    let (forward_synced, reverse_synced) = flow(client, server, 41_001);
    let stored_synced = decision(
        lookup_forwarding_resolution_with_dynamic_for_flow(
            &before,
            &neighbors,
            client,
            &reverse_synced,
        )
        .resolution,
    );
    let metadata = reverse_metadata(0, 0, 0, 0);
    maps.publish_shared_reverse(&reverse_synced, stored_synced, &metadata);
    let unclustered = BTreeMap::new();
    for (label, forward, reverse, stored, peer_synced, want) in [
        (
            "local",
            &forward_local,
            &reverse_local,
            stored_local,
            false,
            99,
        ),
        (
            "peer-synced",
            &forward_synced,
            &reverse_synced,
            stored_synced,
            true,
            11,
        ),
    ] {
        assert!(
            !stamp_is_stale(&maps, reverse),
            "FIXTURE: the {label} stamp stays current"
        );
        let reply = reply(
            &after,
            &unclustered,
            &neighbors,
            reverse,
            stored,
            &metadata,
            false,
            peer_synced,
            0,
        );
        assert_eq!(
            (reply.disposition, reply.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, want),
            "FIXTURE: the {label} reply's lookup variant answers egress {want} ({reply:?})"
        );
        let icmp = icmp_return(
            &mut maps,
            &after,
            &neighbors,
            &unclustered,
            forward,
            stored,
            0,
            0,
        );
        assert_eq!(
            (icmp.disposition, icmp.egress_ifindex, icmp.neighbor_mac),
            (reply.disposition, reply.egress_ifindex, reply.neighbor_mac),
            "the error to {client} on a {label} reverse must use the reply's lookup variant \
             (icmp={icmp:?}, reply={reply:?})"
        );
    }
}

#[test]
fn the_return_uses_the_replys_lookup_variant_v4() {
    the_return_uses_the_replys_lookup_variant(
        IpAddr::V4(Ipv4Addr::new(10, 99, 5, 90)),
        IpAddr::V4(SERVER_V4),
        "10.99.5.0/24",
    );
}

#[test]
fn the_return_uses_the_replys_lookup_variant_v6() {
    the_return_uses_the_replys_lookup_variant(
        IpAddr::V6("2001:db8:99::90".parse::<Ipv6Addr>().expect("v6 client")),
        IpAddr::V6("2001:db8:7::7".parse::<Ipv6Addr>().expect("v6 server")),
        "2001:db8:99::/64",
    );
}

/// #19164 cost: what the fresh lookup adds per ICMP error. Ignored; run it in
/// release: `cargo test --release --bins icmp_return_reresolve_cost_bench
/// -- --ignored --nocapture`.
/// - **OLD:** the reverse probe alone (the stored resolution was returned
///   verbatim, so the probe was the whole cost).
/// - **NEW:** `embedded_icmp_return_resolution` on the HA fixture (the probe
///   plus the reply's lookup variant).
#[test]
#[ignore = "#19164 cost bench: cargo test --release --bins icmp_return_reresolve_cost_bench -- --ignored --nocapture"]
fn icmp_return_reresolve_cost_bench() {
    const N: u32 = 200_000;
    let mut shape = ha_shape(
        35_792,
        IpAddr::V4(CLIENT_V4),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        false,
    );
    for round in 0..3 {
        let started = std::time::Instant::now();
        for _ in 0..N {
            let ctx = shape.maps.ctx(&shape.state, &shape.neighbors);
            std::hint::black_box(
                crate::afxdp::shared_ops::probe_session_across_scopes_with_wire_indexes(
                    ctx.sessions,
                    ctx.shared_sessions,
                    ctx.shared_forward_wire_sessions,
                    ctx.shared_owner_rg_indexes,
                    &shape.reverse,
                    NOW_NS,
                ),
            );
        }
        let old_ns = started.elapsed().as_nanos() as f64 / f64::from(N);
        let started = std::time::Instant::now();
        for _ in 0..N {
            std::hint::black_box(embedded_icmp_return_resolution(
                &mut shape.maps.ctx(&shape.state, &shape.neighbors),
                &shape.forward,
                shape.stored,
                IpAddr::V4(CLIENT_V4),
                NOW_NS,
            ));
        }
        let new_ns = started.elapsed().as_nanos() as f64 / f64::from(N);
        eprintln!(
            "ICMPRETURN19164 round={round} old_probe_only_ns={old_ns:.0} new_fresh_lookup_ns={new_ns:.0} added_ns={:.0}",
            new_ns - old_ns
        );
    }
}
