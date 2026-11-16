//! #19164: an ICMP error (PTB, unreachable) quoting a client's FORWARD packet
//! is returned to the client by the matched reverse session's route. Before
//! #19164 that route was the reverse's STORED resolution, verbatim
//! (`embedded_icmp_return_resolution`), while a reply on the same reverse is
//! looked up again on every packet (`resolve.rs` into `reresolve_stored_session`).
//! When the stored value was stale, the error left by a different path than the
//! flow's replies.
//!
//! Each cell drives the poll arm's real sequence: the return resolution, then
//! `finalize_embedded_icmp_resolution_parts` (the HA snapshot and the fabric
//! redirect). It asserts the CORRECT property: the result matches the reply's.
//! - **(a) HA:** the shared reverse is the import-time FabricRedirect,
//!   synthesized while the client-side RG was the peer's; now that RG is
//!   active here.
//! - **(b) non-HA:** a local reverse resolved under one FIB; the route to the
//!   client moves, and the forwarding generation advances with it.
//! - **(c) the negative control for (a):** the peer still owns the client-side
//!   RG, so the error must follow the reply over the fabric. No
//!   over-correction.
//!
//! (a) and (b) were RED at b725d9542e, before the fix.

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
/// fabric. A LAN client's TCP flow to a WAN server; its shared reverse (server
/// -> client) is the import-time FabricRedirect, synthesized while RG2 was the
/// peer's. The client's neighbor is known on the LAN egress.
struct HaShape {
    state: ForwardingState,
    neighbors: Arc<ShardedNeighborMap>,
    forward: SessionKey,
    reverse: SessionKey,
    stored: SessionDecision,
    metadata: SessionMetadata,
    maps: Maps,
}

fn ha_shape(src_port: u16) -> HaShape {
    let client = IpAddr::V4(CLIENT_V4);
    let forward = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: client,
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5211,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert(
        (24, client),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0, 24],
        },
    );
    let stored =
        decision(resolve_fabric_redirect(&state).expect("FIXTURE: the fabric redirect resolves"));
    let metadata = reverse_metadata(state.egress_zone_id(12), state.egress_zone_id(24), 12, 2);
    let maps = Maps::new();
    maps.publish_shared_reverse(&reverse, stored, &metadata);
    HaShape {
        state,
        neighbors,
        forward,
        reverse,
        stored,
        metadata,
        maps,
    }
}

/// The ICMP error as the poll arm resolves it: the return resolution, then its
/// finalization for an arrival on the WAN (ifindex 12, the WAN zone).
fn icmp_as_finalized(
    shape: &mut HaShape,
    ha: &BTreeMap<i32, HAGroupRuntime>,
) -> ForwardingResolution {
    let raw = embedded_icmp_return_resolution(
        &mut shape.maps.ctx(&shape.state, &shape.neighbors),
        &shape.forward,
        shape.stored,
        IpAddr::V4(CLIENT_V4),
        NOW_NS,
    );
    finalize_embedded_icmp_resolution_parts(
        &shape.state,
        ha,
        NOW_SECS,
        12,
        raw,
        shape.state.egress_zone_id(12),
    )
}

/// The reply on the same reverse, for the same arrival.
fn reply_of(shape: &HaShape, ha: &BTreeMap<i32, HAGroupRuntime>) -> ForwardingResolution {
    let looked_up = reply_lookup(
        &shape.state,
        &shape.neighbors,
        &shape.reverse,
        shape.stored,
        false,
        true,
    );
    reresolve_stored_session(
        &shape.state,
        ha,
        &shape.neighbors,
        NOW_SECS,
        &shape.stored,
        &shape.metadata,
        &shape.reverse,
        IpAddr::V4(CLIENT_V4),
        looked_up,
        packet_arrival(12),
    )
}

/// (a) After RG2 activates here, the reply forwards locally, and so must the
/// ICMP error. Before the fix it took the stale FabricRedirect over the fabric.
#[test]
fn an_icmp_error_follows_the_reply_path_after_activation_not_a_stale_fabric_redirect() {
    let mut shape = ha_shape(35_790);
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

/// (c) The negative control: the PEER still owns RG2 here (RG1 active, RG2
/// not). The reply keeps the fabric redirect, and so must the ICMP error.
#[test]
fn an_icmp_error_keeps_the_fabric_redirect_while_the_peer_owns_the_client_rg() {
    let mut shape = ha_shape(35_791);
    let ha = BTreeMap::from([(1, active()), (2, inactive())]);
    let reply = reply_of(&shape, &ha);
    assert_eq!(
        reply.disposition,
        ForwardingDisposition::FabricRedirect,
        "FIXTURE: while the peer owns the client-side RG, the reply keeps the fabric redirect ({reply:?})"
    );
    let icmp = icmp_as_finalized(&mut shape, &ha);
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "while the peer owns the client-side RG the ICMP error must follow the reply over the fabric \
         (icmp={icmp:?}, reply={reply:?})"
    );
}

/// (b) No HA: a local reverse resolved while the route to the client went out
/// egress 99. The route moves to egress 11, and the worker's forwarding
/// generation advances with it, as a FIB change does in production. The reply
/// re-resolves cache-free and leaves by egress 11, and so must the ICMP error.
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
    let mut maps = Maps::new();
    maps.sessions.set_forwarding_revalidation_gen(1, 1);
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
    // The FIB changes, and the worker's forwarding generation advances.
    let after = fib(11);
    maps.sessions.set_forwarding_revalidation_gen(1, 2);
    let stamp = crate::afxdp::shared_ops::probe_session_across_scopes_with_wire_indexes(
        &maps.sessions,
        &maps.shared_sessions,
        &maps.shared_forward_wire_sessions,
        Some(&maps.owner_indexes),
        &reverse,
        NOW_NS,
    )
    .expect("FIXTURE: the reverse is found")
    .lookup
    .forwarding_generation;
    assert!(
        maps.sessions.forwarding_resolution_is_stale(stamp),
        "FIXTURE: the stored resolution must be stale after the generation advanced"
    );
    let looked_up = reply_lookup(&after, &neighbors, &reverse, stored, true, false);
    let unclustered = BTreeMap::new();
    let reply = reresolve_stored_session(
        &after,
        &unclustered,
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
    let raw = embedded_icmp_return_resolution(
        &mut maps.ctx(&after, &neighbors),
        &forward,
        stored,
        IpAddr::V4(client),
        NOW_NS,
    );
    let icmp = finalize_embedded_icmp_resolution_parts(&after, &unclustered, NOW_SECS, 0, raw, 0);
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex),
        (reply.disposition, reply.egress_ifindex),
        "an ICMP error to the client must take the reply's path after a FIB change; the return path \
         used the reverse's STORED resolution (icmp={icmp:?}, reply={reply:?})"
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
    let mut shape = ha_shape(35_792);
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

/// (d) The fallback: the route moves to egress 11, but no neighbor is known
/// there yet, so the fresh lookup cannot forward (MissingNeighbor). The
/// return keeps the STORED route (egress 99) and its MAC, the pre-#19164
/// behaviour, rather than dropping the ICMP error.
#[test]
fn an_icmp_error_keeps_the_stored_route_when_the_fresh_lookup_cannot_forward() {
    let client = Ipv4Addr::new(10, 99, 1, 51);
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
    neighbors.insert(
        (99, IpAddr::V4(client)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0, 99],
        },
    );
    let forward = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(client),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        src_port: 40_001,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let before = fib(99);
    let mut maps = Maps::new();
    maps.sessions.set_forwarding_revalidation_gen(1, 1);
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
    let after = fib(11);
    maps.sessions.set_forwarding_revalidation_gen(1, 2);
    let fresh = reply_lookup(&after, &neighbors, &reverse, stored, true, false);
    assert_eq!(
        fresh.disposition,
        ForwardingDisposition::MissingNeighbor,
        "FIXTURE: no neighbor is known on the new egress yet ({fresh:?})"
    );
    let icmp = embedded_icmp_return_resolution(
        &mut maps.ctx(&after, &neighbors),
        &forward,
        stored,
        IpAddr::V4(client),
        NOW_NS,
    );
    assert_eq!(
        (icmp.disposition, icmp.egress_ifindex, icmp.neighbor_mac),
        (
            stored_resolution.disposition,
            stored_resolution.egress_ifindex,
            stored_resolution.neighbor_mac
        ),
        "when the fresh lookup cannot forward, the ICMP error keeps the stored route and MAC (icmp={icmp:?})"
    );
}
