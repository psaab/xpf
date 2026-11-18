//! #19171 fold 1 (codex-e P2-2): a legitimate route MORE SPECIFIC than a
//! peer-owned connected prefix must survive the destination-owner
//! compensations. Since #19171 the connected-owner attribution finds the
//! peer-owned prefix, and these compensations used to treat a local answer for
//! a destination inside it as the withheld FIB's default-route mistake:
//! - #16217's reverse-hit conversion;
//! - the #15958b/#18659/#18672 rehome/retain of a stored redirect;
//! - the flow-cache validator's departed-owner arm.
//!
//! Shape (both families):
//! - `reth6.0` (ifindex 8, RG4, ACTIVE) carries the broad 172.16.0.0/16 and
//!   2001:559:8585::/48;
//! - `reth0.80` (12, RG1, peer-owned) carries the narrow 172.16.80.0/24 and
//!   2001:559:8585:80::/64;
//! - an explicit 172.16.80.200/32 (2001:559:8585:80::200/128) goes via
//!   172.16.90.1 (2001:559:8585:90::1) on `reth6.0`, whose neighbour is known.
//!
//! The FIB selects that /32 and HA accepts RG4. The flow is inbound from
//! 172.16.80.200 to a LAN server, so its reply's destination is the /32 host.

use super::test_fixtures::nat_snapshot_with_fabric;
use super::tests_split_rg_failback_18531::rg;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot};

const BROAD_UNIT: i32 = 8;
const FABRIC_PARENT: i32 = 21;
const LAN_UNIT: i32 = 24;

fn host(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6("2001:559:8585:80::200".parse().expect("v6 host"))
    } else {
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))
    }
}

fn server(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6("2001:559:8585:ef00::50".parse().expect("v6 server"))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50))
    }
}

fn gateway(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6("2001:559:8585:90::1".parse().expect("v6 gw"))
    } else {
        IpAddr::V4(Ipv4Addr::new(172, 16, 90, 1))
    }
}

/// `with_route` false is the control: no /32, so the FIB answers the host on
/// the peer-owned connected /24 itself.
fn forwarding(with_route: bool) -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    for iface in &mut snapshot.interfaces {
        if iface.name == "reth0.80" {
            iface.connected_rg_peer_owned = true;
        }
    }
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth6.0".into(),
        zone: "wan".into(),
        linux_name: "ge-0-0-6".into(),
        ifindex: BROAD_UNIT,
        redundancy_group: 4,
        hardware_addr: "02:bf:72:06:00:08".into(),
        addresses: vec![
            InterfaceAddressSnapshot { family: "inet".into(), address: "172.16.0.6/16".into(), ..Default::default() },
            InterfaceAddressSnapshot { family: "inet6".into(), address: "2001:559:8585::6/48".into(), ..Default::default() },
        ],
        ..Default::default()
    });
    for v6 in [false, true] {
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-6".into(),
            ifindex: BROAD_UNIT,
            family: if v6 { "inet6" } else { "inet" }.into(),
            ip: gateway(v6).to_string(),
            mac: "02:00:19:17:16:01".into(),
            state: "reachable".into(),
            router: true,
            link_local: false,
            ..Default::default()
        });
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-1".into(),
            ifindex: LAN_UNIT,
            family: if v6 { "inet6" } else { "inet" }.into(),
            ip: server(v6).to_string(),
            mac: "02:00:19:17:16:02".into(),
            state: "reachable".into(),
            router: false,
            link_local: false,
            ..Default::default()
        });
        if with_route {
            snapshot.routes.push(RouteSnapshot {
                table: if v6 { "inet6.0" } else { "inet.0" }.into(),
                family: if v6 { "inet6" } else { "inet" }.into(),
                destination: if v6 { "2001:559:8585:80::200/128" } else { "172.16.80.200/32" }.into(),
                next_hops: vec![gateway(v6).to_string()],
                preference: 5,
                ..Default::default()
            });
        }
    }
    build_forwarding_state(&snapshot)
}

fn ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (1, rg(false, now_secs)),
        (2, rg(true, now_secs)),
        (4, rg(true, now_secs)),
    ])
}

fn keys(v6: bool) -> (crate::session::SessionKey, crate::session::SessionKey) {
    let forward = crate::session::SessionKey {
        addr_family: if v6 { libc::AF_INET6 } else { libc::AF_INET } as u8,
        protocol: PROTO_TCP,
        src_ip: host(v6),
        dst_ip: server(v6),
        src_port: 40000,
        dst_port: 8080,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse = crate::session::reverse_session_key(&forward, NatDecision::default());
    (forward, reverse)
}

fn metadata(is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: if is_reverse { TEST_LAN_ZONE_ID } else { TEST_WAN_ZONE_ID },
        egress_zone: if is_reverse { TEST_WAN_ZONE_ID } else { TEST_LAN_ZONE_ID },
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
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
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

/// Install the pair. The reverse stores `reverse_stored`.
/// `reverse_owner_rg`: the reverse's owner RG (an HA-managed row is what a
/// refresh visits).
fn install_pair(
    state: &ForwardingState,
    v6: bool,
    reverse_stored: ForwardingResolution,
    reverse_owner_rg: i32,
) -> SessionTable {
    let (forward, reverse) = keys(v6);
    let to_server = lookup_forwarding_resolution(state, server(v6)).resolution;
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        forward,
        decision(to_server),
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse,
        decision(reverse_stored),
        SessionMetadata {
            owner_rg_id: reverse_owner_rg,
            ..metadata(true)
        },
        SessionOrigin::ReverseFlow,
        122_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    sessions
}

/// The reply, server -> host, on the LAN binding: `(target, disposition)` of
/// what it queued.
fn reply(state: &ForwardingState, sessions: &mut SessionTable, v6: bool) -> Vec<(i32, ForwardingDisposition)> {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let lan_mac = [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01];
    let (frame, mut meta) = match (server(v6), host(v6)) {
        (IpAddr::V4(s), IpAddr::V4(h)) => {
            let frame = build_txn_tcp_syn_frame_v4(s, h, 8080, 40000, crate::tcp_flags::TCP_ACK, lan_mac);
            let mut meta = txn_meta_v4(LAN_UNIT as u32, crate::tcp_flags::TCP_ACK, frame.len() as u16);
            meta.flow_src_addr[..4].copy_from_slice(&s.octets());
            meta.flow_dst_addr[..4].copy_from_slice(&h.octets());
            (frame, meta)
        }
        (IpAddr::V6(s), IpAddr::V6(h)) => {
            let frame = build_txn_tcp_frame_v6(s, h, 8080, 40000, crate::tcp_flags::TCP_ACK, lan_mac);
            let mut meta = txn_meta_v6(LAN_UNIT as u32, frame.len());
            meta.tcp_flags = crate::tcp_flags::TCP_ACK;
            meta.flow_src_addr = s.octets();
            meta.flow_dst_addr = h.octets();
            (frame, meta)
        }
        _ => unreachable!("one family"),
    };
    meta.flow_src_port = 8080;
    meta.flow_dst_port = 40000;
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_UNIT, 0);
    binding.interface = Arc::<str>::from("ge-0-0-1");
    let (_batch, dbg) = txn_run_descriptor(&mut binding, sessions, state, &ha(now_secs), &frame, meta);
    assert_eq!(dbg.session_hit, 1, "the reply hits the reverse");
    binding
        .scratch
        .scratch_forwards
        .iter()
        .map(|forward| (forward.target_ifindex, forward.decision.resolution.disposition))
        .collect()
}

/// RED before fold 1. A reverse hit to the /32 host leaves by the /32's active
/// interface (8). #16217's conversion turned it into a fabric redirect
/// because the covering /24's owner (RG1) is the peer's. Control: without the
/// /32, the same reply goes to the /24's owner over the fabric.
#[test]
fn reverse_hit_keeps_a_more_specific_route_under_a_peer_owned_prefix_19171() {
    for v6 in [false, true] {
        let state = forwarding(true);
        let to_host = lookup_forwarding_resolution(&state, host(v6)).resolution;
        assert_eq!(
            (to_host.disposition, to_host.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, BROAD_UNIT),
            "FIXTURE v6={v6}: the FIB selects the /32 via reth6.0 ({to_host:?})"
        );
        let mut sessions = install_pair(&state, v6, to_host, 0);
        let queued = reply(&state, &mut sessions, v6);
        assert!(
            queued.iter().all(|(target, disposition)| *target != FABRIC_PARENT
                && *disposition != ForwardingDisposition::FabricRedirect),
            "v6={v6}: the /32 stands, never redirected over the fabric: {queued:?}"
        );
        assert_eq!(queued.len(), 1, "v6={v6}: the reply is forwarded: {queued:?}");

        let control = forwarding(false);
        let to_host = lookup_forwarding_resolution(&control, host(v6)).resolution;
        let mut sessions = install_pair(&control, v6, to_host, 0);
        let queued = reply(&control, &mut sessions, v6);
        assert_eq!(
            queued,
            vec![(FABRIC_PARENT, ForwardingDisposition::FabricRedirect)],
            "control v6={v6}: with no /32 the reply goes to the /24's owner"
        );
    }
}

/// RED before fold 1. A stored-redirect reverse: the refresh's retain verdict
/// kept the FabricRedirect because the covering /24's owner is inactive. The
/// /32 via the active reth6.0 must replace it.
#[test]
fn stored_redirect_refresh_takes_a_more_specific_route_19171() {
    for v6 in [false, true] {
        let state = forwarding(true);
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let redirect = crate::afxdp::forwarding::resolve_zone_encoded_fabric_redirect_by_id(&state, TEST_LAN_ZONE_ID)
            .expect("FIXTURE: a fabric redirect resolves");
        // An HA-managed reverse, owned by the /24's RG (RG1) when its redirect
        // was stored.
        let sessions = install_pair(&state, v6, redirect, 1);
        let items = crate::afxdp::session_glue::commands::collect_refresh_owner_rgs_items(
            &sessions,
            &state,
            &ha(now_secs),
            &Arc::new(ShardedNeighborMap::default()),
            now_secs,
        );
        let reverse: Vec<_> = items.iter().filter(|(_, _, metadata, _, _)| metadata.is_reverse).collect();
        assert!(!reverse.is_empty(), "v6={v6}: the refresh visits the reverse");
        for (_, refreshed, _, _, _) in reverse {
            assert_eq!(
                (refreshed.resolution.disposition, refreshed.resolution.egress_ifindex),
                (ForwardingDisposition::ForwardCandidate, BROAD_UNIT),
                "v6={v6}: the /32 replaces the stored redirect, got {:?}",
                refreshed.resolution
            );
        }
    }
}

/// RED before fold 1. The flow-cache validator must agree with the slow path:
/// a cached ForwardCandidate to the /32 host on reth6.0 stays valid, while the
/// same cached answer for a host the /32 does not serve (172.16.80.201, a
/// stale default-route line) is still evicted.
#[test]
fn cache_validator_keeps_a_more_specific_route_and_still_evicts_a_stale_line_19171() {
    let state = forwarding(true);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let neighbors = Arc::new(ShardedNeighborMap::default());
    let cached = lookup_forwarding_resolution(&state, host(false)).resolution;
    let judge = |target: IpAddr| {
        crate::afxdp::forwarding::cached_flow_decision_invalid_reason_for_flow(
            &state, &ha(now_secs), &neighbors, now_secs, 4, false, false, None, target, None, cached,
        )
    };
    assert_eq!(judge(host(false)), None, "the /32's cached answer stays valid");
    assert_eq!(
        judge(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 201))),
        Some(crate::afxdp::forwarding::CachedDecisionInvalid::ForwardCandidateEgressDeparted),
        "a cached line the /32 does not serve is still evicted"
    );
}

/// RED before fold 1. The cache arm agrees with the slow path's rehome: a
/// cached FabricRedirect for the /32 host is evicted (the rehome keeps the
/// /32's local candidate), where the covering /24's inactive owner used to keep
/// it cached, still crossing the fabric.
#[test]
fn cache_arm_evicts_a_cached_redirect_the_rehome_replaces_with_a_more_specific_route_19171() {
    let state = forwarding(true);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let neighbors = Arc::new(ShardedNeighborMap::default());
    let cached = crate::afxdp::forwarding::resolve_zone_encoded_fabric_redirect_by_id(&state, TEST_LAN_ZONE_ID)
        .expect("FIXTURE: a fabric redirect resolves");
    // Stamp owners 0 (unknown) and 4 (active). A stamp owner that is the
    // peer's RG keeps its redirect under #16222's option-B posture, which this
    // fold does not change.
    for stamp_owner in [0, 4] {
        let reason = crate::afxdp::forwarding::cached_flow_decision_invalid_reason_for_flow(
            &state, &ha(now_secs), &neighbors, now_secs, stamp_owner, false, false, None, host(false), None, cached,
        );
        assert_eq!(
            reason,
            Some(crate::afxdp::forwarding::CachedDecisionInvalid::FabricRedirectDestinationNowLocal),
            "stamp owner {stamp_owner}: the cached redirect is evicted, as the rehome would replace it"
        );
    }
}

/// RED before fold 1. Reverse synthesis for a forward whose decision is a
/// FabricRedirect: the reply target is the /32 host, so the reverse takes the
/// /32 via reth6.0. The synthesis's destination-owner arm redirected it over
/// the fabric because the covering /24's owner is the peer's.
#[test]
fn reverse_synthesis_keeps_a_more_specific_route_19171() {
    for v6 in [false, true] {
        let state = forwarding(true);
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let redirect = crate::afxdp::forwarding::resolve_zone_encoded_fabric_redirect_by_id(&state, TEST_LAN_ZONE_ID)
            .expect("FIXTURE: a fabric redirect resolves");
        let (forward_key, _) = keys(v6);
        let forward = SyncedSessionEntry {
            sibling_last_seen_ns: 0,
            last_served_ns: 0,
            key: forward_key,
            decision: decision(redirect),
            metadata: SessionMetadata { owner_rg_id: 2, ..metadata(false) },
            leak_incarnation: 0,
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            rev_packets: 1,
            fwd_packets: 1,
            pptp_call_ids: 0,
            persistent_lease_hold: None,
            source_nat_static: None,
        };
        let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &state,
            &ha(now_secs),
            &Arc::new(ShardedNeighborMap::default()),
            &forward,
            now_secs,
        )
        .expect("the synthesis produces the reverse");
        assert_eq!(
            (reverse.decision.resolution.disposition, reverse.decision.resolution.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, BROAD_UNIT),
            "v6={v6}: the synthesized reverse takes the /32, got {:?}",
            reverse.decision.resolution
        );
    }
}

/// RED before fold 1 (MF7's cell). The live reverse repair's #16217 arm for a
/// FabricRedirect forward (`reverse_resolution_for_session_in_table_gated` with
/// the proof, no fabric ingress) converted the reply to a fabric redirect
/// whenever the target's connected owner is inactive. The /32 host keeps the
/// /32. Control: without the /32, the arm still converts, as #16217 needs.
#[test]
fn reverse_repair_fabric_redirect_arm_keeps_a_more_specific_route_19171() {
    for v6 in [false, true] {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let neighbors = Arc::new(ShardedNeighborMap::default());
        let repaired = |state: &ForwardingState| {
            crate::afxdp::shared_ops::reverse_resolution_for_session_in_table_gated(
                state,
                &ha(now_secs),
                &neighbors,
                host(v6),
                TEST_LAN_ZONE_ID,
                false,
                now_secs,
                false,
                None,
                true,
            )
        };
        let with_route = repaired(&forwarding(true));
        assert_eq!(
            (with_route.disposition, with_route.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, BROAD_UNIT),
            "v6={v6}: the repaired reverse takes the /32, got {with_route:?}"
        );
        let control = repaired(&forwarding(false));
        assert_eq!(
            control.disposition,
            ForwardingDisposition::FabricRedirect,
            "control v6={v6}: with no /32 the arm converts to the owner, got {control:?}"
        );
    }
}
