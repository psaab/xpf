//! WG TUN-origin session publish (#10038 Part A).
//!
//! Inner packets the kernel routes onto a `wgN` TUN are read by the WG control
//! thread, encapped, and sent on its UDP socket — and (before this fix)
//! NOTHING installed the worker session for the inner flow, so the peer's
//! solicited reply arrived at the worker with no session and died at
//! host-inbound. GRE local-origin does not have this hole:
//! `build_local_origin_tunnel_tx_request` + `maybe_enqueue_local_tunnel_session`
//! (`tunnel.rs`) publish the forward + synthesized reverse before encap. This
//! module is the WG equivalent, with four deliberate deviations from the GRE
//! template (all adjudicated — see `docs/log/10038.md`):
//!
//! - shared-only publish: no `worker_commands` UpsertLocal prewarm. WG threads
//!   spawn ungated (unlike GRE's), so the queue set is empty at spawn; the
//!   first reply installs via reactive `materialize_shared_session_hit`.
//! - publish AFTER encap, gated on `EncapOutcome::Sent`: a session for a packet
//!   that never left (MTU drop, NoSession handshake request, encap/send
//!   failure) would admit replies with no causally-prior outbound packet.
//! - honest per-peer outer: WG has no single endpoint destination (cryptokey
//!   routing selects the peer per inner dst), so the forward's outer hop is
//!   resolved per SELECTED peer endpoint (FIB + neighbor) and stamped honestly
//!   (`ForwardCandidate` / `MissingNeighbor` / `NoRoute`), mapped onto the
//!   tunnel logical like `resolve_tunnel_forwarding_resolution`.
//! - parse-then-dedup-then-build: the cheap parse + dedup check runs before
//!   encap; the expensive outer resolve + reverse synthesis runs only on a
//!   dedup miss AND encap success. Strictly cheaper than GRE (which builds
//!   before deduping).
//!
//! Encap behavior is NEVER gated by this module: every builder failure, an
//! unattached endpoint row, and every non-`Sent` outcome skips the publish and
//! still encapsulates.

use super::super::*;
use crate::afxdp::tunnel::{
    local_origin_packet_meta, prune_local_tunnel_sessions, wrap_raw_ip_packet_for_tunnel,
};
use std::net::SocketAddr;

/// A TUN-read inner packet parsed far enough to dedup: eth-wrapped frame +
/// adjusted meta + session flow with the routing domain stamped.
pub(in crate::afxdp) struct WgTunOriginParsed {
    pub(in crate::afxdp) frame: Vec<u8>,
    pub(in crate::afxdp) meta: UserspaceDpMeta,
    pub(in crate::afxdp) flow: SessionFlow,
}

/// Parse one TUN-read bare inner IP packet into the dedup key. `None` (not a
/// parseable v4/v6 flow, or the tunnel row is gone) means skip-publish — the
/// caller still encapsulates.
///
/// Mirrors the GRE builder's wrap+parse prologue
/// (`build_local_origin_tunnel_tx_request`): eth-wrap, +14 offset fixup (the
/// meta from `local_origin_packet_meta` is TUN-relative; the parser wants
/// frame-relative), parse, then the #9032 routing-domain stamp from the
/// tunnel's egress interface (a TUN reader never reaches "THE single site" in
/// `poll_descriptor/mod.rs`, so without this the session publishes under
/// domain 0 — a different identity on a box with routing instances).
pub(in crate::afxdp) fn parse_wg_tun_origin_flow(
    packet: &[u8],
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
) -> Option<WgTunOriginParsed> {
    let mut meta = local_origin_packet_meta(packet)?;
    let frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
    meta.l3_offset = 14;
    meta.l4_offset = meta.l4_offset.saturating_add(14);
    meta.payload_offset = meta.payload_offset.saturating_add(14);
    let mut flow = parse_session_flow_from_bytes(&frame, meta)?;
    // Parent-review (GPT-3 + SPARK-A1): TUN-read provenance. The kernel
    // routes ANYTHING onto a wgN TUN — including, pre-#10527, peer-originated
    // transit an Uncovered-ingress TUN write looped back (`dispatch_inbound`
    // then wrote AllowedIPs-gated but possibly non-local-src plaintext; pre-#10302
    // the kernel routed that out this or another TUN, and now the armed forward
    // fence drops it as unallowlisted wgN transit — #10527 refuses uncovered
    // transit at the source, and this gate stays as defense-in-depth). Only a
    // firewall-LOCAL inner source is self-originated; anything else is
    // encap-only (None), never published as TUN-origin. `owns_configured_ip`
    // covers tunnel + physical + SNAT-WAN + NAT-external addrs (local_v*
    // alone would miss SNAT-sourced packets).
    if !forwarding.owns_configured_ip(flow.forward_key.src_ip) {
        return None;
    }
    let endpoint = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id)?;
    flow.forward_key.routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        forwarding,
        endpoint.logical_ifindex,
        0,
        None,
    );
    Some(WgTunOriginParsed { frame, meta, flow })
}

/// #10038 publish-only attachment gate: whether the loaded forwarding state
/// still describes the tunnel this thread is attached to. The WG twin of
/// `tunnel.rs::endpoint_attachment_valid` (which admits only GRE modes) — same
/// shape (endpoint row present, mode match, logical ifindex + name match),
/// recomputed ONLY when the forwarding Arc rotates.
///
/// Unlike GRE (which PARKS while unattached), the WG caller only skips the
/// PUBLISH: encap is never gated, preserving current behavior across the
/// store-to-join window.
pub(in crate::afxdp) fn wg_endpoint_attachment_valid(
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    spawned_tunnel_name: &str,
) -> bool {
    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return false;
    };
    if endpoint.mode != "wireguard" {
        return false;
    }
    endpoint.logical_ifindex == spawned_logical_ifindex
        && forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
            .is_some_and(|name| name == spawned_tunnel_name)
}

/// #10038 dedup check: is a publish DUE for this flow? Runs the shared GRE
/// prune sweep first (same constants/thresholds — one SSOT, no drift), then
/// the GRE refresh windows (5s TCP / 1s everything else): a flow published
/// within its window is still fresh in the shared maps and needs no republish.
///
/// The caller inserts into `local_sessions` only via
/// `publish_wg_tun_origin_entries` (on `Sent`), so a failed encap never marks
/// the flow published and the next packet retries.
pub(in crate::afxdp) fn wg_tun_origin_publish_due(
    local_sessions: &mut FastMap<SessionKey, u64>,
    local_sessions_last_prune_ns: &mut u64,
    key: &SessionKey,
    protocol: u8,
    now_ns: u64,
) -> bool {
    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
    // GRE parity (`maybe_enqueue_local_tunnel_session`): TCP's window is the
    // established-cadence refresh, everything else the 1s liveness tick.
    let refresh_after_ns = if protocol == PROTO_TCP {
        5_000_000_000
    } else {
        1_000_000_000
    };
    !matches!(
        local_sessions.get(key),
        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
    )
}

/// The TUN-origin pair: the forward plus its synthesized reverse (always
/// `Some` — synthesis only declines `is_reverse` input, which the forward
/// never is — but `Option` keeps the GRE plan shape).
#[derive(Debug)]
pub(in crate::afxdp) struct WgTunOriginEntries {
    pub(in crate::afxdp) forward: SyncedSessionEntry,
    pub(in crate::afxdp) reverse: Option<SyncedSessionEntry>,
}

/// Whether a FIB-resolved outer hop is usable as a tunnel transport hop: not
/// local delivery, and not back into a tunnel interface (the
/// `resolve_tunnel_outer` recursion guard, as a builder failure instead of a
/// NoRoute map — see the call site).
fn wg_tun_origin_outer_usable(forwarding: &ForwardingState, outer: &ForwardingResolution) -> bool {
    outer.disposition != ForwardingDisposition::LocalDelivery
        && !forwarding.tunnel_interfaces.contains(&outer.egress_ifindex)
}

/// Build the TUN-origin forward + reverse for one successfully-encapped inner
/// packet. `peer_endpoint` is the SELECTED effective endpoint cryptokey
/// routing already chose for this packet (not the row destination: a WG row
/// has no single outer destination).
///
/// The outer hop is resolved per-peer (FIB + neighbor on the peer IP, in the
/// row's transport table) and stamped HONESTLY — `ForwardCandidate`,
/// `MissingNeighbor`, or `NoRoute` — mapped onto the tunnel logical exactly
/// like `resolve_tunnel_forwarding_resolution` (tunnel-logical egress, outer
/// tx/next-hop/MACs, tunnel id). The cached session-resolution fallback then
/// holds on the materialized copy. HA is enforced on the stamped resolution,
/// and a standby STILL publishes (`HAInactive` forward + `HAInactive` reverse
/// — encap is ungated there too, so a standby's reply HIT follows the
/// `HAInactive` path, matching GRE's post-publish flap behavior of persisting
/// to expiry/purge).
///
/// Every `Err` is skip-publish-still-encap: unknown row, outer recursion (the
/// peer endpoint FIB-resolves to local delivery or a tunnel interface —
/// nonsense for a tunnel outer), or an unparsable flow. Encap never consults
/// this function's result.
pub(in crate::afxdp) fn build_wg_tun_origin_entries(
    parsed: &WgTunOriginParsed,
    peer_endpoint: SocketAddr,
    tunnel_endpoint_id: u16,
    forwarding: &ForwardingState,
    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
) -> Result<WgTunOriginEntries, &'static str> {
    let endpoint = forwarding
        .tunnel_endpoints
        .get(&tunnel_endpoint_id)
        .ok_or("wg_tun_origin_unknown_endpoint")?;
    let logical_ifindex = endpoint.logical_ifindex;
    // Per-peer outer: the row destination is NOT consulted (see doc above).
    // Depth/flags mirror `resolve_tunnel_outer` (per-tunnel-endpoint, no
    // 5-tuple ECMP hash — per-destination spread across outer ECMP).
    let outer = match peer_endpoint.ip() {
        IpAddr::V4(ip) => crate::afxdp::forwarding::lookup_forwarding_resolution_v4(
            forwarding,
            Some(dynamic_neighbors),
            ip,
            &endpoint.transport_table,
            1,
            false,
            None,
        ),
        IpAddr::V6(ip) => crate::afxdp::forwarding::lookup_forwarding_resolution_v6(
            forwarding,
            Some(dynamic_neighbors),
            ip,
            &endpoint.transport_table,
            1,
            false,
            None,
        ),
    };
    // Recursion guard, mirroring `resolve_tunnel_outer`: an outer that resolves
    // to local delivery or back into a tunnel is not a usable transport hop.
    // Defensive: plain FIB usually refuses both first (`allow_tunnels=false`
    // yields NoRoute for tunnel egresses, and the local short-circuit is
    // table-scoped), in which case the honest arm below stamps NoRoute. But if
    // FIB behavior ever changes, failing closed beats stamping nonsense — and
    // unlike that helper (which maps to NoRoute), this is a builder failure.
    if !wg_tun_origin_outer_usable(forwarding, &outer) {
        return Err("wg_tun_origin_outer_recursion");
    }
    // Map onto the tunnel logical, mirroring
    // `resolve_tunnel_forwarding_resolution` — disposition included (honest).
    let resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_runtime,
        now_secs,
        ForwardingResolution {
            disposition: outer.disposition,
            local_ifindex: outer.local_ifindex,
            egress_ifindex: logical_ifindex,
            tx_ifindex: outer.tx_ifindex,
            tunnel_endpoint_id,
            next_hop: outer.next_hop,
            neighbor_mac: outer.neighbor_mac,
            src_mac: outer.src_mac,
            tx_vlan_id: outer.tx_vlan_id,
        },
    );
    // #9752 fields are inert here (0,0): Part C declines TUN-origin before
    // any re-resolve could run in an install table (same as the synthesized
    // precedent in `shared_ops.rs`).
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    // The tunnel's zone, both directions — same as GRE (`egress_zone_id` on
    // the tunnel logical: "what zone is this tunnel in").
    let zone_id = forwarding.egress_zone_id(logical_ifindex);
    let forward = SyncedSessionEntry {
        key: parsed.flow.forward_key.clone(),
        decision,
        metadata: SessionMetadata {
            ingress_zone: zone_id,
            egress_zone: zone_id,
            ingress_zone_check: crate::session::zone_vintage_check_for_id(
                &forwarding.zone_id_to_name,
                zone_id,
            ),
            egress_zone_check: crate::session::zone_vintage_check_for_id(
                &forwarding.zone_id_to_name,
                zone_id,
            ),
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            // Self-originated: no admitting policy/application (Junos runs no
            // security policy on firewall-self-originated traffic, #6224), so
            // zeroed policy fields + the global per-protocol idle timeout
            // (`None`), exactly like the GRE local-origin builder.
            // `TunOrigin` (item 5) is POSITIVE provenance — stamped only
            // here and in the GRE builder — never a peer wire import.
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        leak_incarnation: 0,
        origin: SessionOrigin::TunOrigin,
        protocol: parsed.meta.protocol,
        tcp_flags: if parsed.meta.protocol == PROTO_TCP {
            extract_tcp_flags_and_window(&parsed.frame)
                .map(|(flags, _)| flags)
                .unwrap_or_default()
        } else {
            0
        },
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    // Table-scoped synthesis (item 6): the reply target resolves in the
    // tunnel's instance table, so a VRF reverse finds its connected/local
    // view instead of NoRoute-ing against inet.0.
    let table = crate::afxdp::tunnel::tun_origin_reverse_route_table(forwarding, logical_ifindex);
    let mut reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry_in_table(
        forwarding,
        ha_runtime,
        dynamic_neighbors,
        &forward,
        now_secs,
        Some(table.as_str()),
    );
    if let Some(rev) = reverse.as_mut() {
        rev.origin = SessionOrigin::TunOrigin;
    }
    Ok(WgTunOriginEntries { forward, reverse })
}

/// Parent-review item 2: publisher-owned idle sweep. A TUN-published pair
/// whose flow sees no TUN traffic for this long is deleted from the shared
/// maps — the publisher that created the authorization revokes it, so
/// unanswered/idle flows never accumulate (shared maps have no TTL of their
/// own). A worker holding a materialized copy is unaffected (local shadows
/// shared, so established flows continue); a late reply on a stateless
/// worker MISSES and faces the normal gates. Well under the 30s refresh
/// prune horizon with 5s sweep cadence, so the stamp is always present when
/// the sweep reads it.
const WG_TUN_ORIGIN_DELETE_IDLE_NS: u64 = 20_000_000_000;
/// Parent-review item 4: tombstone horizon. Last-publish memory per flow —
/// a response-shaped resume within this window republishes (the flow was
/// recently outbound), past it the flow is forgotten and a response-shaped
/// packet creates nothing. Covers TCP keepalives (75s) and BGP holds.
const WG_TUN_ORIGIN_TOMBSTONE_IDLE_NS: u64 = 300_000_000_000;
/// Sweep cadence throttle (mirrors the 5s prune interval, separate clock).
const WG_TUN_ORIGIN_SWEEP_INTERVAL_NS: u64 = 5_000_000_000;
/// Tombstone memory bound (scan/sweep cost); past it the oldest go first.
const WG_TUN_ORIGIN_TOMBSTONE_CAP: usize = 16384;
const WG_TUN_ORIGIN_TOMBSTONE_RETAIN: usize = 8192;

/// Parent-review item 4: does this TUN packet INITIATE (vs respond)?
///
/// The kernel reads TUN packets for BOTH directions: genuine outbound
/// requests AND responses to admitted inbound (peer→firewall request
/// admitted worker-locally, kernel answers firewall→peer). Stamping a
/// response as a TUN-origin FORWARD would synthesize its request tuple
/// as an exempt LocalDelivery reverse — admitting future peer requests
/// as "solicited replies" past tightening. So creation requires an
/// initiating shape: TCP SYN-without-ACK, ICMP echo/timestamp request
/// (v4 8/13, v6 128/133). UDP and everything else carry no direction
/// signal and always create (documented residual: a UDP response to
/// inbound creates a pair — narrow: needs a fw UDP service + WG +
/// entry loss or tightening-after-publish).
pub(in crate::afxdp) fn wg_tun_origin_packet_initiates(parsed: &WgTunOriginParsed) -> bool {
    match parsed.meta.protocol {
        PROTO_TCP => crate::afxdp::frame::extract_tcp_flags_and_window(&parsed.frame)
            .map(|(flags, _)| {
                (flags & crate::tcp_flags::TCP_SYN) != 0 && (flags & crate::tcp_flags::TCP_ACK) == 0
            })
            .unwrap_or(false),
        PROTO_ICMP => {
            let ty = parsed.frame.get(parsed.meta.l4_offset as usize).copied();
            match parsed.meta.addr_family as i32 {
                libc::AF_INET => matches!(ty, Some(8) | Some(13)),
                _ => matches!(ty, Some(128) | Some(133)),
            }
        }
        _ => true,
    }
}

/// Publish the TUN-origin pair to the shared maps (forward + reverse when
/// synthesized) and mark the flow published in the thread-local dedup map +
/// tombstones. Shared-only by design (no `worker_commands` UpsertLocal).
///
/// Parent-review item 4 (inbound-orientation preservation): a
/// response-shaped packet (`initiates == false`) must not CREATE — it
/// publishes only as refresh (forward already shared) or resume
/// (tombstone = published within 300s). A skip marks nothing, so the
/// flow stays forgotten and every response re-decides the same way.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn publish_wg_tun_origin_entries(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    local_sessions: &mut FastMap<SessionKey, u64>,
    tombstones: &mut FastMap<SessionKey, u64>,
    entries: &WgTunOriginEntries,
    initiates: bool,
    now_ns: u64,
) {
    if !initiates
        && crate::afxdp::shared_ops::lookup_shared_session(shared_sessions, &entries.forward.key)
            .is_none()
        && !tombstones.contains_key(&entries.forward.key)
    {
        return;
    }
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &entries.forward,
    );
    if let Some(reverse) = &entries.reverse {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            reverse,
        );
    }
    local_sessions.insert(entries.forward.key.clone(), now_ns);
    tombstones.insert(entries.forward.key.clone(), now_ns);
}

/// Parent-review item 2: publisher-owned idle sweep (throttled; call every
/// outer iteration). Deletes shared pairs idle past `DELETE_IDLE` and
/// forgets tombstones past `TOMBSTONE_IDLE`. Removal is idempotent, so a
/// re-delete between the idle read and the next sweep is a no-op.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn sweep_wg_tun_origin_idle(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    tombstones: &mut FastMap<SessionKey, u64>,
    last_sweep_ns: &mut u64,
    now_ns: u64,
) {
    if now_ns.saturating_sub(*last_sweep_ns) < WG_TUN_ORIGIN_SWEEP_INTERVAL_NS {
        return;
    }
    *last_sweep_ns = now_ns;
    for (key, last) in tombstones.iter() {
        if now_ns.saturating_sub(*last) > WG_TUN_ORIGIN_DELETE_IDLE_NS {
            let rev_key =
                crate::session::reverse_session_key(key, crate::nat::NatDecision::default());
            crate::afxdp::shared_ops::remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                key,
            );
            crate::afxdp::shared_ops::remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                &rev_key,
            );
        }
    }
    tombstones.retain(|_, last| now_ns.saturating_sub(*last) <= WG_TUN_ORIGIN_TOMBSTONE_IDLE_NS);
    if tombstones.len() > WG_TUN_ORIGIN_TOMBSTONE_CAP {
        let mut ordered: Vec<(u64, SessionKey)> =
            tombstones.iter().map(|(k, t)| (*t, k.clone())).collect();
        ordered.sort_by_key(|(t, _)| core::cmp::Reverse(*t));
        for (_, k) in ordered.into_iter().skip(WG_TUN_ORIGIN_TOMBSTONE_RETAIN) {
            tombstones.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::test_fixtures::wg_outer_mtu_snapshot;
    use crate::afxdp::tests_support::txn_ha_state;
    use crate::test_zone_ids::TEST_SFMIX_ZONE_ID;
    use std::net::Ipv6Addr;

    const FW: [u8; 4] = [10, 123, 0, 1];
    const PEER: [u8; 4] = [10, 123, 0, 5];

    /// A bare inner IPv4 UDP packet (TUN-shaped: no L2).
    fn inner_udp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&8u16.to_be_bytes());
        p
    }

    /// A bare inner IPv6 UDP packet (TUN-shaped: no L2).
    fn inner_udp_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40 + 8];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        p[6] = PROTO_UDP;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[44..46].copy_from_slice(&8u16.to_be_bytes());
        p
    }

    /// #10038 builder unit: a TUN-shaped inner packet builds the forward +
    /// reverse the worker needs, carrying the TUN-origin marker the HIT
    /// exemption and the #9604 decline both key on.
    #[test]
    fn wg_tun_origin_entries_carry_the_marker_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let endpoint = forwarding.tunnel_endpoints.get(&1).expect("wg row");
        assert_eq!(endpoint.mode, "wireguard");
        assert_eq!(endpoint.logical_ifindex, 400);
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let ha = txn_ha_state();
        let peer_ep: SocketAddr = "203.0.113.7:51820".parse().unwrap();

        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("inner UDP must parse");
        assert_eq!(parsed.meta.protocol, PROTO_UDP);
        let entries =
            build_wg_tun_origin_entries(&parsed, peer_ep, 1, &forwarding, &ha, &neighbors, 123)
                .expect("build must succeed");

        // The marker: synced-family origin, forward half, no ingress identity,
        // tunnel endpoint set, no admitting policy counter.
        let fwd = &entries.forward;
        assert_eq!(fwd.origin, SessionOrigin::TunOrigin);
        assert!(!fwd.metadata.is_reverse);
        assert_eq!(fwd.metadata.ingress_ifindex, 0);
        assert_eq!(fwd.decision.resolution.tunnel_endpoint_id, 1);
        assert_eq!(fwd.metadata.policy_counter_idx, 0);
        // Self-originated shape: tunnel zone both ways, tunnel's owner RG,
        // zeroed policy fields, global idle timeout.
        assert_eq!(
            (fwd.metadata.ingress_zone, fwd.metadata.egress_zone),
            (TEST_SFMIX_ZONE_ID, TEST_SFMIX_ZONE_ID)
        );
        assert_eq!(fwd.metadata.owner_rg_id, 1);
        assert_eq!(fwd.metadata.policy_id, 0);
        assert_eq!(fwd.metadata.inactivity_timeout_ns, None);
        assert_eq!(fwd.protocol, PROTO_UDP);
        assert_eq!(fwd.key.src_ip, IpAddr::V4(FW.into()));
        assert_eq!(fwd.key.dst_ip, IpAddr::V4(PEER.into()));
        assert_eq!((fwd.key.src_port, fwd.key.dst_port), (5001, 5002));

        // Honest outer: the stamped hop is the FIB result for the SELECTED
        // peer endpoint, mapped onto the tunnel logical — byte-equal on the
        // outer fields, tunnel-owned on the logical ones.
        let expected = crate::afxdp::forwarding::lookup_forwarding_resolution_v4(
            &forwarding,
            Some(&neighbors),
            Ipv4Addr::new(203, 0, 113, 7),
            "inet.0",
            1,
            false,
            None,
        );
        let got = fwd.decision.resolution;
        assert_eq!(got.disposition, expected.disposition);
        assert_eq!(got.local_ifindex, expected.local_ifindex);
        assert_eq!(got.tx_ifindex, expected.tx_ifindex);
        assert_eq!(got.next_hop, expected.next_hop);
        assert_eq!(got.neighbor_mac, expected.neighbor_mac);
        assert_eq!(got.src_mac, expected.src_mac);
        assert_eq!(got.tx_vlan_id, expected.tx_vlan_id);
        assert_eq!(got.egress_ifindex, 400);

        // The reverse: host-bound solicited companion for the firewall's own
        // WG address, keyed as the forward's inverse.
        let rev = entries.reverse.as_ref().expect("reverse must synthesize");
        assert!(rev.metadata.is_reverse);
        assert_eq!(
            rev.decision.resolution.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(
            rev.key,
            crate::session::reverse_session_key(&fwd.key, fwd.decision.nat)
        );
        assert_eq!(rev.origin, SessionOrigin::TunOrigin);
        assert_eq!(rev.metadata.policy_counter_idx, 0);
    }

    /// #10038: the builder parses inner IPv6 as well (the outer stays the
    /// selected v4 peer endpoint — WG transports either family).
    #[test]
    fn wg_tun_origin_builder_parses_inner_v6_10038() {
        // fd00::1 must be a CONFIGURED addr (else the provenance gate drops
        // it — see the nonlocal test below): extend the stock snapshot.
        let mut snap = wg_outer_mtu_snapshot();
        snap.interfaces
            .iter_mut()
            .find(|i| i.ifindex == 400)
            .expect("wg0.0 row")
            .addresses
            .push(crate::InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: "fd00::1/64".to_string(),
                scope: 0,
            });
        let forwarding = build_forwarding_state(&snap);
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let ha = txn_ha_state();
        let peer_ep: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let request = inner_udp_v6(
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            5001,
            5002,
        );
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("inner v6 must parse");
        assert_eq!(parsed.flow.forward_key.addr_family, libc::AF_INET6 as u8);
        let entries =
            build_wg_tun_origin_entries(&parsed, peer_ep, 1, &forwarding, &ha, &neighbors, 123)
                .expect("v6 build must succeed");
        assert_eq!(entries.forward.origin, SessionOrigin::TunOrigin);
        assert!(entries.reverse.is_some(), "v6 reverse must synthesize");
    }

    /// Parent-review (GPT-3 + SPARK-A1): TUN-read provenance. A parseable
    /// inner whose source is NOT firewall-local (the Uncovered-ingress
    /// producer's output shape: AllowedIPs-gated peer src, kernel-looped
    /// onto a TUN under misconfig) parses to None — encap-only, never
    /// published. v4 + v6; the local-src controls are the marker/v6 cells.
    #[test]
    fn wg_tun_origin_nonlocal_src_skips_publish_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        // Peer-net src (AllowedIPs, but not ours): the looped-transit shape.
        let looped = inner_udp_v4(PEER, [10, 123, 0, 9], 5001, 5002);
        assert!(
            parse_wg_tun_origin_flow(&looped, &forwarding, 1).is_none(),
            "a non-local inner src must not parse for publish"
        );
        // Unconfigured v6 src: same gate, other family.
        let looped_v6 = inner_udp_v6(
            "fd00::9".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            5001,
            5002,
        );
        assert!(
            parse_wg_tun_origin_flow(&looped_v6, &forwarding, 1).is_none(),
            "a non-local inner v6 src must not parse for publish"
        );
    }

    /// #10038: the #9032 routing-domain stamp. On the stock snapshot the
    /// domain is 0 either way (which would make a `== 0` assert vacuous), so
    /// this pins the stamp on a domain-bearing row: parse leaves 0, the stamp
    /// writes 7, and deleting the stamp line reds.
    #[test]
    fn wg_tun_origin_builder_stamps_routing_domain_10038() {
        let mut snap = wg_outer_mtu_snapshot();
        let wg = snap
            .interfaces
            .iter_mut()
            .find(|i| i.ifindex == 400)
            .expect("wg0.0 row");
        wg.routing_instance = "cust".to_string();
        wg.routing_domain = 7;
        let forwarding = build_forwarding_state(&snap);
        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("parse must succeed");
        assert_eq!(
            parsed.flow.forward_key.routing_domain, 7,
            "the TUN reader must stamp the tunnel egress interface's domain"
        );
    }

    /// #10038: builder failure arms — every one is skip-publish-still-encap
    /// at the call site (pinned by the loop cells), so this pins the errors
    /// themselves (unparseable packets, unknown rows) plus the honest-NoRoute
    /// stamp. The outer-usability guard has its own table below.
    #[test]
    fn wg_tun_origin_builder_failure_arms_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let ha = txn_ha_state();
        // Not IP at all.
        assert!(parse_wg_tun_origin_flow(&[0x00], &forwarding, 1).is_none());
        assert!(parse_wg_tun_origin_flow(&[], &forwarding, 1).is_none());
        // Unknown tunnel row.
        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        assert!(parse_wg_tun_origin_flow(&request, &forwarding, 999).is_none());
        // Honest NoRoute: a "peer endpoint" inside the firewall's own WG
        // subnet has no usable outer (plain FIB refuses tunnel egresses with
        // `allow_tunnels=false`), and that stamps HONESTLY — NoRoute on the
        // tunnel logical — rather than failing the build.
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("parse must succeed");
        let inside_own_tunnel: SocketAddr = "10.123.0.5:51820".parse().unwrap();
        let noroute = build_wg_tun_origin_entries(
            &parsed,
            inside_own_tunnel,
            1,
            &forwarding,
            &ha,
            &neighbors,
            123,
        )
        .expect("NoRoute stamps honestly, it does not fail the build");
        assert_eq!(
            noroute.forward.decision.resolution.disposition,
            ForwardingDisposition::NoRoute
        );
        assert_eq!(noroute.forward.decision.resolution.egress_ifindex, 400);
        assert_eq!(noroute.forward.decision.resolution.tunnel_endpoint_id, 1);
    }

    /// #10038: the outer-usability guard table. Defensive in practice (plain
    /// FIB refuses both shapes first — see the NoRoute pin above), but if FIB
    /// behavior ever changes, local delivery and tunnel-egress outers must
    /// fail the build rather than stamp nonsense.
    #[test]
    fn wg_tun_origin_outer_guard_table_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let base = ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
        assert!(wg_tun_origin_outer_usable(&forwarding, &base));
        let mut missing = base;
        missing.disposition = ForwardingDisposition::MissingNeighbor;
        assert!(wg_tun_origin_outer_usable(&forwarding, &missing));
        let mut noroute = base;
        noroute.disposition = ForwardingDisposition::NoRoute;
        assert!(wg_tun_origin_outer_usable(&forwarding, &noroute));
        let mut local = base;
        local.disposition = ForwardingDisposition::LocalDelivery;
        assert!(!wg_tun_origin_outer_usable(&forwarding, &local));
        let mut back_into_tunnel = base;
        back_into_tunnel.egress_ifindex = 400;
        assert!(!wg_tun_origin_outer_usable(&forwarding, &back_into_tunnel));
    }

    /// #10038: the publish-only attachment gate — the WG twin of GRE's
    /// `endpoint_attachment_valid` (which admits only GRE modes).
    #[test]
    fn wg_endpoint_attachment_valid_table_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        assert!(wg_endpoint_attachment_valid(&forwarding, 1, 400, "wg0"));
        assert!(!wg_endpoint_attachment_valid(&forwarding, 999, 400, "wg0"));
        assert!(!wg_endpoint_attachment_valid(&forwarding, 1, 401, "wg0"));
        assert!(!wg_endpoint_attachment_valid(&forwarding, 1, 400, "wg1"));
        // A GRE-mode row with the same attachment is NOT a WG attachment.
        let mut gre = forwarding.clone();
        gre.tunnel_endpoints.get_mut(&1).expect("wg row").mode = "gre".to_string();
        assert!(!wg_endpoint_attachment_valid(&gre, 1, 400, "wg0"));
    }

    /// #10038: dedup windows (GRE parity: 5s TCP / 1s else) + the shared GRE
    /// prune sweep (a 5000-stale map past the interval prunes through this
    /// call — deleting the sweep call reds the length assert).
    #[test]
    fn wg_tun_origin_dedup_windows_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("parse must succeed");
        let key = parsed.flow.forward_key.clone();
        let mut map = FastMap::<SessionKey, u64>::default();
        let mut last_prune_ns = 0u64;
        assert!(wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_UDP,
            1_000_000_000
        ));
        map.insert(key.clone(), 1_000_000_000);
        assert!(!wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_UDP,
            1_500_000_000
        ));
        assert!(wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_UDP,
            2_000_000_001
        ));
        map.insert(key.clone(), 10_000_000_000);
        assert!(!wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_TCP,
            14_000_000_000
        ));
        assert!(wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_TCP,
            16_000_000_000
        ));
        // Shared sweep: 5000 stale entries, 40s later (past the 5s interval,
        // older than the 30s staleness horizon) — the sweep runs inline.
        map.clear();
        for port in 0..5000u16 {
            let mut filler = key.clone();
            filler.src_port = port;
            map.insert(filler, 0);
        }
        last_prune_ns = 0;
        let _ = wg_tun_origin_publish_due(
            &mut map,
            &mut last_prune_ns,
            &key,
            PROTO_UDP,
            40_000_000_000,
        );
        assert!(
            map.is_empty(),
            "the shared GRE sweep must prune 5000 stale entries, else this call is not wired to it"
        );
    }

    /// A bare inner IPv4 TCP packet (TUN-shaped: no L2) with explicit flags.
    fn inner_tcp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p
    }

    /// A bare inner IPv4 ICMP packet (TUN-shaped: no L2) with explicit type.
    fn inner_icmp_v4(icmp_type: u8, src: [u8; 4], dst: [u8; 4], ident: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20] = icmp_type;
        p[24..26].copy_from_slice(&ident.to_be_bytes());
        p
    }

    /// Parent-review item 4: the initiates table. TCP SYN-only and ICMP
    /// echo/timestamp requests initiate; SYN-ACK/ACK/RST/FIN, echo replies,
    /// and errors do not; UDP always does (no direction signal).
    #[test]
    fn wg_tun_origin_packet_initiates_table_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let initiates = |packet: &[u8]| {
            parse_wg_tun_origin_flow(packet, &forwarding, 1)
                .map(|parsed| wg_tun_origin_packet_initiates(&parsed))
        };
        use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        // TCP: only SYN-without-ACK opens.
        assert_eq!(
            initiates(&inner_tcp_v4(FW, PEER, 5001, 80, TCP_SYN)),
            Some(true)
        );
        assert_eq!(
            initiates(&inner_tcp_v4(FW, PEER, 5001, 80, TCP_SYN | TCP_ACK)),
            Some(false)
        );
        assert_eq!(
            initiates(&inner_tcp_v4(FW, PEER, 5001, 80, TCP_ACK)),
            Some(false)
        );
        assert_eq!(
            initiates(&inner_tcp_v4(FW, PEER, 5001, 80, TCP_RST | TCP_ACK)),
            Some(false)
        );
        assert_eq!(
            initiates(&inner_tcp_v4(FW, PEER, 5001, 80, TCP_FIN | TCP_ACK)),
            Some(false)
        );
        // ICMPv4: echo/timestamp requests only.
        assert_eq!(initiates(&inner_icmp_v4(8, FW, PEER, 1)), Some(true));
        assert_eq!(initiates(&inner_icmp_v4(13, FW, PEER, 1)), Some(true));
        assert_eq!(initiates(&inner_icmp_v4(0, FW, PEER, 1)), Some(false));
        // ICMP errors never even parse (#3067 query-only keying) — skipped at
        // parse, before this gate is reachable.
        assert_eq!(initiates(&inner_icmp_v4(3, FW, PEER, 1)), None);
        // UDP: directionless, always initiates.
        assert_eq!(initiates(&inner_udp_v4(FW, PEER, 5001, 5002)), Some(true));
    }

    type SharedMaps10038 = (
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        SharedSessionOwnerRgIndexes,
    );

    fn fresh_shared_10038() -> SharedMaps10038 {
        (
            Arc::new(Mutex::new(FastMap::default())),
            Arc::new(Mutex::new(FastMap::default())),
            Arc::new(Mutex::new(FastMap::default())),
            SharedSessionOwnerRgIndexes::default(),
        )
    }

    /// Parent-review item 4: the create gate decision table, through the
    /// production publish. Response-shaped + absent-everywhere skips (marks
    /// nothing); refresh (shared hit) and resume (tombstone) publish;
    /// initiating always publishes.
    #[test]
    fn wg_tun_origin_create_gate_table_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let ha = txn_ha_state();
        let peer_ep: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("parse must succeed");
        let entries =
            build_wg_tun_origin_entries(&parsed, peer_ep, 1, &forwarding, &ha, &neighbors, 123)
                .expect("build must succeed");
        let fwd_key = entries.forward.key.clone();
        let (shared, nat, wire, indexes) = fresh_shared_10038();
        let mut dedup = FastMap::<SessionKey, u64>::default();
        let mut tombstones = FastMap::<SessionKey, u64>::default();
        let publish = |shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
                       nat: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
                       wire: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
                       indexes: &SharedSessionOwnerRgIndexes,
                       dedup: &mut FastMap<SessionKey, u64>,
                       tombstones: &mut FastMap<SessionKey, u64>,
                       initiates: bool| {
            publish_wg_tun_origin_entries(
                shared,
                nat,
                wire,
                indexes,
                dedup,
                tombstones,
                &entries,
                initiates,
                1_000_000_000,
            )
        };
        // Response-shaped + absent everywhere: skip, marks nothing.
        publish(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            false,
        );
        assert!(shared.lock().expect("shared").is_empty());
        assert!(dedup.is_empty() && tombstones.is_empty());
        // Initiating + absent: create (marks both).
        publish(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            true,
        );
        assert!(shared.lock().expect("shared").contains_key(&fwd_key));
        assert!(dedup.contains_key(&fwd_key) && tombstones.contains_key(&fwd_key));
        // Response-shaped + shared hit: refresh (republish over present pair).
        publish(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            false,
        );
        assert!(shared.lock().expect("shared").contains_key(&fwd_key));
        // Resume: pair swept away but tombstone remembered → republish.
        shared.lock().expect("shared").clear();
        publish(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            false,
        );
        assert!(shared.lock().expect("shared").contains_key(&fwd_key));
        // Forgotten: pair swept + tombstone gone → skip again, marks nothing.
        shared.lock().expect("shared").clear();
        tombstones.clear();
        dedup.clear();
        publish(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            false,
        );
        assert!(shared.lock().expect("shared").is_empty());
        assert!(dedup.is_empty() && tombstones.is_empty());
    }

    /// Parent-review item 2: publisher-owned idle sweep. A published pair
    /// idle past 20s is deleted from shared (both halves); the tombstone
    /// survives to 300s (resume grace); past that it is forgotten. Fake
    /// time throughout; the sweep throttle is defeated by driving it once
    /// per case with a fresh clock.
    #[test]
    fn wg_tun_origin_idle_sweep_bounds_lifetime_10038() {
        let forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let ha = txn_ha_state();
        let peer_ep: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let request = inner_udp_v4(FW, PEER, 5001, 5002);
        let parsed =
            parse_wg_tun_origin_flow(&request, &forwarding, 1).expect("parse must succeed");
        let entries =
            build_wg_tun_origin_entries(&parsed, peer_ep, 1, &forwarding, &ha, &neighbors, 123)
                .expect("build must succeed");
        let fwd_key = entries.forward.key.clone();
        let rev_key = crate::session::reverse_session_key(&fwd_key, entries.forward.decision.nat);
        let (shared, nat, wire, indexes) = fresh_shared_10038();
        let mut dedup = FastMap::<SessionKey, u64>::default();
        let mut tombstones = FastMap::<SessionKey, u64>::default();
        let mut last_sweep = 0u64;
        const T0: u64 = 100_000_000_000;
        publish_wg_tun_origin_entries(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut dedup,
            &mut tombstones,
            &entries,
            true,
            T0,
        );
        assert!(shared.lock().expect("shared").contains_key(&fwd_key));
        // Fresh (5s): sweep keeps everything.
        sweep_wg_tun_origin_idle(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut tombstones,
            &mut last_sweep,
            T0 + 5_000_000_000,
        );
        assert!(shared.lock().expect("shared").contains_key(&fwd_key));
        assert!(tombstones.contains_key(&fwd_key));
        // Idle 21s: pair deleted (both halves), tombstone kept (resume grace).
        last_sweep = 0;
        sweep_wg_tun_origin_idle(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut tombstones,
            &mut last_sweep,
            T0 + 21_000_000_000,
        );
        assert!(!shared.lock().expect("shared").contains_key(&fwd_key));
        assert!(!shared.lock().expect("shared").contains_key(&rev_key));
        assert!(tombstones.contains_key(&fwd_key));
        // Idle 301s: tombstone forgotten.
        last_sweep = 0;
        sweep_wg_tun_origin_idle(
            &shared,
            &nat,
            &wire,
            &indexes,
            &mut tombstones,
            &mut last_sweep,
            T0 + 301_000_000_000,
        );
        assert!(!tombstones.contains_key(&fwd_key));
    }
}
