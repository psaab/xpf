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
    // The stamp owner does not matter: the RG-epoch fence covers the
    // RG2-stamped entry, this arm covers every other stamp.
    for stamp_owner in [0, 2, 7] {
        assert_eq!(
            judge(&state, &ha_both, now_secs, stamp_owner, false, LAN_CLIENT, redirect),
            Some(CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
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
/// it. RED if the `dest_rg > 0`, `ha_state.is_empty()` or `fabric_ingress`
/// guard is removed.
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
