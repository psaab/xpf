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
    // #4539 (gate-consistency hardening; subsumes #2151 + #4487): cache a
    // host-inbound TCP session ONLY off the handshake — a first packet that
    // carries SYN (an initial SYN, or a SYN|ACK for the inbound leg of a
    // firewall-originated flow). Decline every other non-SYN TCP first packet.
    //
    // A SINGLE POSITIVE `has_syn` predicate replaces the two prior NARROW
    // decline-gates that this subsumes:
    //   - #2151 declined a bare/established ACK (`has_ack && !has_syn`) — the
    //     prior inline `(tcp_flags & ACK) != 0 && (tcp_flags & SYN) == 0`.
    //   - #4487 (residual of P6 / #4400) declined a bare RST / FIN closing
    //     segment (`is_closing && !has_syn`) — a session-table DoS surface (a
    //     RST/FIN flood to a firewall IP churns the per-worker table) plus a
    //     policy-evaluation skip (a stray teardown seeding an immediately
    //     `closing` host-local session).
    // Both are `!has_syn` cases, so a single `has_syn` gate subsumes them. It
    // ADDITIONALLY closes the residual the two decline-gates left open: a
    // non-handshake anomalous / crafted first packet that is neither ACK-set
    // nor closing — pure PSH (0x08), a null segment (0x00), pure URG (0x20),
    // or an ECE/CWR-only segment — which previously fell through to the
    // default `true` and seeded a 300s host-local LocalDelivery session
    // (`is_initial_syn` false at install → `established = true`). Aligning on
    // `has_syn` matches the gate to its stated "only off the handshake" intent.
    //
    // The packet is NOT dropped: a declined non-SYN first packet still reaches
    // the host via the LocalDelivery reinject chokepoint (the #4400
    // drop-exemption for host-inbound — the ACTION differs BY DISPOSITION, as
    // #4400 deliberately chose: the TRANSIT dispositions DROP a bare teardown,
    // host-inbound LocalDelivery must NOT). A peer RST/FIN tearing down a
    // firewall-ORIGINATED TCP flow (BGP-active, syslog-TCP/TLS, feed/RPM
    // fetches, DNS-over-TCP), or a connection-refused RST for the firewall's
    // own outbound SYN, therefore still reaches the local stack so the kernel
    // socket tears down promptly — this gate only declines to CACHE. A later
    // real SYN hitting a firewall IP is re-evaluated by the `to-zone
    // junos-host` mandatory-teardown gate that runs on EVERY LocalDelivery
    // session hit (poll_descriptor), so declining to cache never skips policy.
    crate::tcp_flags::has_syn(tcp_flags)
}

pub(in crate::afxdp) fn install_helper_local_session_on_miss(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
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
            session_map_fd,
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
    };
    // #1789: count a failed helper-local session publish (same
    // shim-missing-key consequence as every other publish site).
    if publish_session_map_entry_for_session(
        session_map_fd,
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
