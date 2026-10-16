//! #5650: host-local delivery session caching on session-miss (the
//! LocalDelivery / interface-address inbound path). Pure code-motion split out
//! of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// #3769: count of `LocalDelivery` resolutions returned with `local_ifindex ==
/// 0` — i.e. a NAT/DNAT-only local target (no interface owns the address, so
/// the table-scoped connected scan cannot attribute an ifindex). This is
/// legitimate for a NAT/DNAT external IP owned in the resolving table (the NAT
/// subsystem owns it, there is no interface), but downstream zone / security-
/// policy / HA-RG-owner selection then operate on ifindex 0, so the count is
/// exposed as a diagnostic. A steadily climbing value on a router with per-VRF
/// NAT is expected; a climbing value that correlates with mis-attributed
/// sessions is the signal to inspect. `LocalDelivery` for a genuine interface
/// address always carries the real ifindex and does NOT bump this.
pub(in crate::afxdp) static LOCAL_DELIVERY_IFINDEX0: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(in crate::afxdp) fn should_cache_local_delivery_session_on_miss(
    state: &ForwardingState,
    resolution_target: IpAddr,
    resolution: ForwardingResolution,
    protocol: u8,
    tcp_flags: u8,
) -> bool {
    if resolution.disposition != ForwardingDisposition::LocalDelivery {
        return false;
    }
    // Non-TCP (ICMP / UDP) LocalDelivery always caches — the handshake gate
    // below is TCP-only and MUST NOT change non-TCP behavior.
    if !matches!(protocol, PROTO_TCP) {
        return true;
    }
    let _ = state;
    let _ = resolution_target;
    // #4539/#13941 (gate-consistency hardening): cache a host-inbound TCP
    // session ONLY off a non-closing handshake packet — an initial SYN, or a
    // SYN|ACK for the inbound leg of a firewall-originated flow. A SYN that
    // also carries FIN or RST is not a valid session opener and must not seed
    // an immediately-closing session.
    //
    // This declines every other TCP first packet: ACK/data, bare RST/FIN, and
    // anomalous packets that carry neither ACK nor SYN (pure PSH, null, URG,
    // or ECE/CWR-only). The packet is NOT dropped: a declined packet still
    // reaches the host via the LocalDelivery reinject chokepoint. This gate
    // only declines to CACHE, so policy remains in the session-hit path.
    //
    // Peer RST/FIN packets still reach the local stack so kernel sockets can
    // tear down firewall-originated flows; declining to cache never skips
    // policy because a later real SYN is re-evaluated by the `to-zone
    // junos-host` mandatory-teardown gate on every LocalDelivery session hit.
    crate::tcp_flags::has_syn(tcp_flags) && !crate::tcp_flags::is_closing(tcp_flags)
}

pub(in crate::afxdp) fn install_helper_local_session_on_miss(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
    // #9517: threaded, not a constant. The publish wrapper this reaches fixes
    // `SessionOrigin::ForwardFlow`, so the kernel-local predicate is inert here
    // TODAY -- but a constant would silently become the wrong answer if that
    // origin ever changed, and every other publish site carries the real flag.
    has_routing_domains: bool,
) -> bool {
    if let Some(previous) = sessions.take_synced_local(key) {
        remove_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            key,
        );
        delete_session_map_entry_for_removed_session(
            session_map,
            key,
            previous.decision,
            &previous.metadata,
        );
    }
    if !sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        origin,
        now_ns,
        protocol,
        tcp_flags,
    ) {
        return false;
    }
    let local_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        leak_incarnation: 0,
        origin,
        protocol,
        tcp_flags,
        // Local forwarding-learn entry: no peer install generation (#2170).
        generation: 0,
        // #5212: a local-origin shared-map publish. The stable id is carried on
        // the wire straight off the live entry by the incremental Open delta
        // (`install_with_protocol_with_origin`) / the owner-RG cold-sync export
        // (`emit_open_delta_with_origin`), not via this shared replica — so 0
        // here (a cross-worker materialize of this entry re-allocs a local id).
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: sessions.handshake_state_wire_for(key),
        pptp_call_ids: sessions.pptp_call_ids_wire_for(key),
        source_nat_static: None,
    };
    // #1789: count a failed helper-local session publish (same
    // shim-missing-key consequence as every other publish site).
    if publish_session_map_entry_for_session(
        session_map,
        key,
        decision,
        &local_entry.metadata,
        has_routing_domains,
    )
    .is_err()
    {
        crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

pub(in crate::afxdp) fn ingress_interface_local_resolution(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    let logical_ifindex = resolve_ingress_logical_ifindex(state, ingress_ifindex, ingress_vlan_id)
        .or_else(|| {
            state.egress.iter().find_map(|(ifindex, iface)| {
                ((iface.bind_ifindex == ingress_ifindex || *ifindex == ingress_ifindex)
                    && iface.vlan_id == ingress_vlan_id)
                    .then_some(*ifindex)
            })
        })
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(ingress_ifindex);
    let iface = state.egress.get(&logical_ifindex)?;
    let matches_local = match dst {
        IpAddr::V4(ip) => iface.primary_v4 == Some(ip),
        IpAddr::V6(ip) => iface.primary_v6 == Some(ip),
    };
    if !matches_local {
        return None;
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: logical_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: logical_ifindex,
        tunnel_endpoint_id: state
            .tunnel_endpoint_by_ifindex
            .get(&logical_ifindex)
            .copied()
            .unwrap_or_default(),
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    })
}

pub(in crate::afxdp) fn ingress_interface_local_resolution_on_session_miss(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    ingress_interface_local_resolution(state, ingress_ifindex, ingress_vlan_id, dst)
}
