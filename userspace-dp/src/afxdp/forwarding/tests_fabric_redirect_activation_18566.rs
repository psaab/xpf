//! #18566: a cached FabricRedirect must not outlive the activation of the RG
//! that owns its destination.
//!
//! Base topology is `nat_snapshot_with_fabric` (the loss cluster shape):
//! `reth0.80` (RG1, 172.16.80.8/24) is the WAN unit, `reth1.0` (RG2,
//! 10.0.61.1/24) the LAN unit, `fab0` the fabric. The live shape is the reverse
//! ACK of a `lan -> wan` iperf flow, `172.16.80.200:5211 -> 10.0.61.102`, on the
//! node that owned only the WAN RG when the entry was seeded. Its stamp owner
//! is the session's owner (RG1), so RG2's epoch bump at activation never
//! reaches it. Before this arm the hit-stage revalidation kept serving the
//! redirect (direct ingress, so neither `OwnerActiveRedirect` nor the
//! FabricRedirect block superseded it).

use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;

fn active(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp: now_secs,
        lease: HAForwardingLease::Inactive,
    }
}

const LAN_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));

fn reverse_ack_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: LAN_CLIENT,
        src_port: 5211,
        dst_port: 35790,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// The production hit-path validator, fed the same connected-owner answer
/// the entry memo would give.
fn judge(
    state: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    stamp_owner_rg: i32,
    packet_fabric_ingress: bool,
    target: IpAddr,
    resolution: ForwardingResolution,
) -> Option<CachedDecisionInvalid> {
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let key = reverse_ack_key();
    cached_flow_decision_invalid_reason_for_cached_flow(
        state,
        ha_state,
        &neighbors,
        now_secs,
        stamp_owner_rg,
        packet_fabric_ingress,
        false,
        Some(&key),
        target,
        None,
        resolution,
        || crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(state, target, None),
    )
}

/// The defect cell. RED on revert of the FabricRedirect branch in
/// `cached_flow_decision_invalid_reason_inner` (the validator returns None
/// and the stale redirect is served).
#[test]
fn cached_redirect_superseded_once_destination_rg_is_local_18566() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let redirect = resolve_fabric_redirect(&state).expect("premise: fabric redirect resolves");
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, LAN_CLIENT, None),
        2,
        "premise: the LAN client's connected owner is RG2 (reth1.0)"
    );
    // RG2 has just been activated here; the entry still names RG1.
    let ha_both = BTreeMap::from([(1, active(now_secs)), (2, active(now_secs))]);
    assert_eq!(
        judge(&state, &ha_both, now_secs, 1, false, LAN_CLIENT, redirect),
        Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
        "a direct-ingress redirect whose destination RG is now local must re-resolve"
    );
    // Any stamp owner the re-homed entry can keep fires: an unknown (0) one,
    // and a locally active one (the RG-epoch fence also covers RG2's own
    // stamp). A known owner that is NOT active here (7: no such group) does
    // not: `forward_candidate_owner_departed` would evict the re-homed
    // ForwardCandidate on its next hit (seat W, #16222 option B).
    for (stamp_owner, fires) in [(0, true), (2, true), (7, false)] {
        assert_eq!(
            judge(&state, &ha_both, now_secs, stamp_owner, false, LAN_CLIENT, redirect)
                == Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
            fires,
            "stamp owner {stamp_owner}"
        );
    }
}

/// While the peer still owns the destination RG the redirect is the right
/// answer and must be served. RED if the arm stops reading activeness (e.g.
/// fires on any known destination owner).
#[test]
fn cached_redirect_kept_while_destination_rg_is_peer_owned_18566() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let redirect = resolve_fabric_redirect(&state).expect("premise: fabric redirect resolves");
    let split = BTreeMap::from([(1, active(now_secs)), (2, inactive(now_secs))]);
    assert_eq!(judge(&state, &split, now_secs, 1, false, LAN_CLIENT, redirect), None);
    // An RG2 with an expired lease is not forwarding-active either.
    let expired = BTreeMap::from([
        (1, active(now_secs)),
        (
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 0,
                lease: HAForwardingLease::ActiveUntil(now_secs.saturating_sub(1)),
            },
        ),
    ]);
    assert_eq!(judge(&state, &expired, now_secs, 1, false, LAN_CLIENT, redirect), None);
}

/// Scope guards. A routed destination (no connected owner) and a standalone
/// node never fire, and a fabric arrival stays with the arms that already own
/// it. RED if the `dest_rg > 0` or `fabric_ingress` guard is removed (the
/// standalone assertion documents the shape; with an empty HA map the
/// destination RG can never be active, so it is not a separate guard cell).
#[test]
fn arm_scope_guards_18566() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let redirect = resolve_fabric_redirect(&state).expect("premise: fabric redirect resolves");
    // RG0 active too, so a dropped `dest_rg > 0` guard would match the
    // unknown owner (rg 0) below.
    let ha_both = BTreeMap::from([(0, active(now_secs)), (1, active(now_secs)), (2, active(now_secs))]);
    let routed = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, routed, None),
        0,
        "premise: a routed destination has no connected owner"
    );
    assert_ne!(
        judge(&state, &ha_both, now_secs, 1, false, routed, redirect),
        Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
        "unknown destination owner"
    );
    assert_eq!(
        fabric_redirect_destination_now_local(&BTreeMap::new(), now_secs, false, redirect, || 2),
        false,
        "standalone node"
    );
    assert_eq!(
        fabric_redirect_destination_now_local(&ha_both, now_secs, true, redirect, || 2),
        false,
        "fabric arrival"
    );
    assert_ne!(
        judge(&state, &ha_both, now_secs, 1, true, LAN_CLIENT, redirect),
        Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
        "fabric arrival through the validator"
    );
    // A destination that is one of this node's own (non-NAT) addresses: the
    // session path answers LocalDelivery, which the arm never accepts (a
    // self-targeting reverse to such an address is redirected again by the
    // slow path). RED if the agreement check accepts LocalDelivery.
    let own = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    assert!(
        interface_nat_local_resolution(&state, own, None).is_none(),
        "premise: 10.0.61.1 is not an interface-NAT address"
    );
    let neighbors = Arc::new(ShardedNeighborMap::new());
    assert_eq!(
        lookup_forwarding_resolution_with_dynamic(&state, &neighbors, own).resolution.disposition,
        ForwardingDisposition::LocalDelivery,
        "premise: the FIB answers the node's own LAN address as LocalDelivery"
    );
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, own, None),
        2,
        "premise: its connected owner is the now-local RG2"
    );
    assert_ne!(
        judge(&state, &ha_both, now_secs, 1, false, own, redirect),
        Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
        "own address"
    );
    // Only a FabricRedirect qualifies; a local candidate is judged by the
    // ForwardCandidate arms.
    let mut candidate = redirect;
    candidate.disposition = ForwardingDisposition::ForwardCandidate;
    assert_eq!(
        fabric_redirect_destination_now_local(&ha_both, now_secs, false, candidate, || 2),
        false,
        "ForwardCandidate"
    );
}

/// Seat V (M1): while the FIB still carries the LAN connected row as
/// peer-owned (built before RG2 was activated here), the slow path keeps the
/// redirect. The cache arm must then keep it too, or each hit evicts an entry
/// the slow path re-seeds identically. Agreement is pinned on three shapes:
/// withheld row -> neither re-homes; local row -> both re-home; withheld row
/// with RG1 inactive (seat V, delta) -> the FIB answers via the WAN, HA
/// enforcement turns that into HAInactive, and the slow path still keeps the
/// redirect, so the arm must not accept an HAInactive answer. The third
/// shape judges with stamp owner RG2 (active), so the stamp-owner guard
/// cannot mask a candidate-disposition defect.
#[test]
fn arm_agrees_with_slow_path_rehome_18566() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_both = BTreeMap::from([(1, active(now_secs)), (2, active(now_secs))]);
    let ha_rg1_down = BTreeMap::from([(1, inactive(now_secs)), (2, active(now_secs))]);
    for (withheld, ha, stamp_owner) in [(true, &ha_both, 1), (false, &ha_both, 1), (true, &ha_rg1_down, 2)] {
        let mut snapshot = nat_snapshot_with_fabric();
        if withheld {
            for iface in &mut snapshot.interfaces {
                if iface.name == "reth1.0" {
                    iface.connected_rg_peer_owned = true;
                }
            }
        }
        let state = build_forwarding_state(&snapshot);
        let redirect = resolve_fabric_redirect(&state).expect("premise: fabric redirect resolves");
        let neighbors = Arc::new(ShardedNeighborMap::new());
        let key = reverse_ack_key();
        let looked_up =
            lookup_forwarding_resolution_with_dynamic_for_flow(&state, &neighbors, LAN_CLIENT, &key).resolution;
        let stored = crate::session::SessionDecision {
            resolution: redirect,
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        let metadata = crate::session::SessionMetadata {
            ingress_zone: state.egress_zone_id(12),
            egress_zone: state.egress_zone_id(24),
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 12,
            ingress_vlan_id: 80,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
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
        };
        let slow = crate::afxdp::session_glue::reresolve_stored_session(
            &state,
            ha,
            &neighbors,
            now_secs,
            &stored,
            &metadata,
            &key,
            LAN_CLIENT,
            looked_up,
            crate::afxdp::session_glue::FabricArrival::Packet {
                fabric_ingress: false,
                fabric_link_ingress: false,
                ingress_ifindex: 12,
                ha_startup_grace_until_secs: 0,
                fabric_adopted: false,
                adopted_recovery: None,
            },
        );
        let slow_keeps_redirect = slow.disposition == ForwardingDisposition::FabricRedirect;
        let arm_evicts = judge(&state, ha, now_secs, stamp_owner, false, LAN_CLIENT, redirect)
            == Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal);
        assert_eq!(
            arm_evicts, !slow_keeps_redirect,
            "withheld={withheld} rg1_active={}: the cache arm (evict={arm_evicts}) must agree with the slow path (keeps redirect={slow_keeps_redirect}, {slow:?})",
            ha.get(&1).is_some_and(|g| g.active)
        );
        if withheld {
            assert!(slow_keeps_redirect, "premise: with the row withheld the slow path keeps the redirect");
        }
        if std::ptr::eq(ha, &ha_rg1_down) {
            let looked_up = enforce_ha_resolution_snapshot(&state, ha, now_secs, looked_up);
            assert_eq!(
                looked_up.disposition,
                ForwardingDisposition::HAInactive,
                "premise: with RG1 down the fresh answer is HAInactive ({looked_up:?})"
            );
        }
    }
}

/// Seat W (#16222 option B, connected destination). On the node that holds
/// only the WAN RG, a direct-ingress `lan -> wan` flow owned by the LAN RG
/// (the peer's) keeps its redirect to the owner. The #16222 cells judge a
/// routed destination (8.8.8.8), where this arm cannot fire; the live target
/// 172.16.80.200 is CONNECTED on the now-local RG1. Without the stamp-owner
/// guard the arm fires there, the slow path re-homes onto reth0.80, and
/// `forward_candidate_owner_departed` evicts that candidate on the next hit
/// (stamp owner RG2 inactive): the flow takes the slow path on every packet.
/// RED on removal of the stamp-owner guard in `fabric_redirect_rehome_agrees`.
#[test]
fn option_b_redirect_to_connected_destination_is_kept_18566() {
    let mut snapshot = nat_snapshot_with_fabric();
    let server = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: server.to_string(),
        mac: "00:11:22:33:44:55".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
        ..Default::default()
    });
    let state = build_forwarding_state(&snapshot);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let redirect = resolve_fabric_redirect(&state).expect("premise: fabric redirect resolves");
    let split = BTreeMap::from([(1, active(now_secs)), (2, inactive(now_secs))]);
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, server, None),
        1,
        "premise: the server is connected on the local WAN RG"
    );
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: LAN_CLIENT,
        dst_ip: server,
        src_port: 52490,
        dst_port: 5211,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    // Premise: the fresh answer IS a ForwardCandidate via the connected
    // interface, so only the stamp-owner guard keeps the arm quiet, and that
    // candidate is one the owner-departed arm evicts under stamp owner RG2.
    let looked_up =
        lookup_forwarding_resolution_with_dynamic_for_flow(&state, &neighbors, server, &key).resolution;
    let candidate = enforce_ha_resolution_snapshot(&state, &split, now_secs, looked_up);
    assert_eq!(candidate.disposition, ForwardingDisposition::ForwardCandidate, "premise: {candidate:?}");
    assert_eq!(
        candidate.egress_ifindex,
        crate::afxdp::session_glue::connected_ifindex_for_target_in_table(&state, server, None),
        "premise: the candidate egresses via the server's connected interface"
    );
    assert!(
        forward_candidate_owner_departed(&split, now_secs, 2, candidate),
        "premise: a re-homed candidate stamped RG2 would be evicted on its next hit"
    );
    let neighbors_for_judge = Arc::new(ShardedNeighborMap::new());
    let verdict = cached_flow_decision_invalid_reason_for_cached_flow(
        &state,
        &split,
        &neighbors_for_judge,
        now_secs,
        2,
        false,
        false,
        Some(&key),
        server,
        None,
        redirect,
        || crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(&state, server, None),
    );
    assert_ne!(
        verdict,
        Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
        "an option-B redirect owned by the peer's RG must be served, not re-homed into a churn loop"
    );
}
