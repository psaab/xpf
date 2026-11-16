//! #19171: on a split node, a reply toward a client whose redundancy group has
//! moved to the peer must never be resolved, stored or sent out the WAN
//! default route.
//!
//! **The shape** (the loss topology, `nat_snapshot_with_fabric`): `reth0.80`
//! (RG1, ifindex 12) is the WAN with the default routes; `reth1.0` (RG2,
//! ifindex 24, 10.0.61.0/24) is the LAN. RG1 stays active here, and RG2 moves
//! to the peer. The withholding publish marks `reth1.0` peer-owned (#15742),
//! so the transit FIB no longer has 10.0.61.0/24, and a LAN client resolves to
//! the WAN default route: a ForwardCandidate on egress 12, whose RG1 is active.
//!
//! The local reverse (server -> client) was resolved out `reth1.0` while RG2
//! was active here.
//! - **(A1) the demote after the withholding publish** (the persistent form):
//!   the worker's `DemoteOwnerRGS` runs after the new forwarding state reached
//!   it. Its cache-free lookup answers the WAN, and master STORES that, so
//!   every later reply leaves by the WAN. The control arm runs the same demote
//!   with the prefix still present.
//! - **(A2) a reply before the demote** (the transient form): a stale-stamped
//!   reply on the still-local reverse. On a WAN arrival the hit arm's #16217
//!   conversion already turns the WAN answer into the fabric redirect (the
//!   control); on a fabric-link arrival it is skipped (anti-loop).
//! - **(B) a stored FabricRedirect, arriving over the fabric link:**
//!   `rehome_skipped` hands it the WAN answer.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::nat_snapshot_with_fabric;

const NOW_SECS: u64 = 1_000;
const NOW_NS: u64 = NOW_SECS * 1_000_000_000;
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
const WAN: i32 = 12;
const LAN: i32 = 24;

fn rg(active: bool) -> HAGroupRuntime {
    if active {
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: NOW_SECS,
            lease: HAGroupRuntime::active_lease_until(NOW_SECS, NOW_SECS),
        }
    } else {
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: NOW_SECS,
            lease: HAForwardingLease::Inactive,
        }
    }
}

/// RG1 (WAN) active here; RG2 (LAN) the peer's.
fn split_ha() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(1, rg(true)), (2, rg(false))])
}

/// The forwarding state, with `reth1.0`'s prefix withheld when `withheld`.
fn forwarding(withheld: bool) -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    if withheld {
        for iface in &mut snapshot.interfaces {
            if iface.name == "reth1.0" {
                iface.connected_rg_peer_owned = true;
            }
        }
    }
    build_forwarding_state(&snapshot)
}

fn neighbors() -> Arc<ShardedNeighborMap> {
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert(
        (LAN, IpAddr::V4(CLIENT)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0x61, 0x66],
        },
    );
    neighbors
}

fn reverse_key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(CLIENT),
        src_port: 443,
        dst_port: src_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn reverse_metadata(state: &ForwardingState) -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: state.egress_zone_id(WAN),
        egress_zone: state.egress_zone_id(LAN),
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: WAN as u32,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 2,
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

fn flow(key: &SessionKey) -> SessionFlow {
    SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    }
}

/// A local reverse, resolved out `reth1.0` while RG2 was active here.
fn install_local_reverse(sessions: &mut SessionTable, key: &SessionKey) -> SessionDecision {
    let before = forwarding(false);
    let resolution = lookup_forwarding_resolution_with_dynamic_for_flow(
        &before,
        &neighbors(),
        IpAddr::V4(CLIENT),
        key,
    )
    .resolution;
    assert_eq!(
        (resolution.disposition, resolution.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, LAN),
        "FIXTURE: while RG2 was active here the reverse resolved out the LAN ({resolution:?})"
    );
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    assert!(
        sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            reverse_metadata(&before),
            SessionOrigin::ReverseFlow,
            NOW_NS,
            PROTO_TCP,
            0x10,
        ),
        "FIXTURE: the local reverse installs"
    );
    let _ = sessions.drain_deltas(8);
    decision
}

/// The worker's `DemoteOwnerRGS{[2]}` against `state`; returns the stored
/// resolution afterwards.
fn demote(
    sessions: &mut SessionTable,
    key: &SessionKey,
    state: &ForwardingState,
) -> ForwardingResolution {
    let mut cancelled_keys = Vec::new();
    let mut cancelled_keys_seen = rustc_hash::FxHashSet::default();
    let _ = super::commands::handle_demote_owner_rgs(
        sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        state,
        &split_ha(),
        &neighbors(),
        vec![2],
        NOW_NS,
        NOW_SECS,
        &mut cancelled_keys,
        &mut cancelled_keys_seen,
    );
    sessions
        .entry_with_origin(key)
        .expect("the demote retains the reverse")
        .0
        .resolution
}

/// The reply on `key` with `stored`, as the session-hit arm resolves it
/// (`resolve.rs` 700-830): the cache-free variant when stale, the synced variant
/// for a peer-synced row, else the cached one; then the one pipeline; then the
/// #16217 departed-destination conversion for a reverse hit.
fn reply(
    state: &ForwardingState,
    key: &SessionKey,
    stored: SessionDecision,
    stale: bool,
    peer_synced: bool,
    ingress_ifindex: i32,
    fabric_link: bool,
) -> ForwardingResolution {
    let neighbors = neighbors();
    let flow = flow(key);
    let looked_up = if stale {
        lookup_forwarding_resolution_for_session_without_cache(state, &neighbors, &flow, stored)
    } else if peer_synced {
        lookup_forwarding_resolution_for_synced_session(state, &neighbors, &flow, stored)
    } else {
        lookup_forwarding_resolution_for_session(state, &neighbors, &flow, stored)
    }
    .resolution;
    let metadata = reverse_metadata(state);
    let target = resolution_target_for_session(&flow, stored);
    let mut decision = stored;
    decision.resolution = reresolve_stored_session(
        state,
        &split_ha(),
        &neighbors,
        NOW_SECS,
        &stored,
        &metadata,
        key,
        target,
        looked_up,
        FabricArrival::Packet {
            fabric_ingress: fabric_link,
            fabric_link_ingress: fabric_link,
            ingress_ifindex,
            ha_startup_grace_until_secs: 0,
            fabric_adopted: false,
            adopted_recovery: None,
        },
    );
    if let Some(redirect) = reverse_hit_departed_destination_redirect(
        state,
        &split_ha(),
        NOW_SECS,
        fabric_link,
        metadata.is_reverse,
        target,
        install_table_name_for_session(state, decision, target),
        metadata.egress_zone,
        decision.resolution.disposition,
    ) {
        decision.resolution = redirect;
    }
    decision.resolution
}

fn is_local_wan(resolution: &ForwardingResolution) -> bool {
    matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && resolution.egress_ifindex == WAN
}

/// (A1) The demote that runs after the withholding publish must store what it
/// stores when the prefix is still present (the control arm), never the WAN
/// egress. The next reply must not leave by the WAN either.
#[test]
fn a_demote_after_the_withholding_publish_never_stores_the_wan_egress_19171() {
    let control_key = reverse_key(40_100);
    let mut control_sessions = SessionTable::new();
    install_local_reverse(&mut control_sessions, &control_key);
    let control = demote(&mut control_sessions, &control_key, &forwarding(false));
    assert!(
        !is_local_wan(&control) && control.disposition == ForwardingDisposition::FabricRedirect,
        "FIXTURE (control): with the prefix still present, the demote stores a fabric redirect \
         ({control:?})"
    );

    let key = reverse_key(40_101);
    let mut sessions = SessionTable::new();
    install_local_reverse(&mut sessions, &key);
    let after = forwarding(true);
    let fresh = lookup_forwarding_resolution_with_dynamic_for_flow(
        &after,
        &neighbors(),
        IpAddr::V4(CLIENT),
        &key,
    )
    .resolution;
    assert!(
        is_local_wan(&fresh),
        "FIXTURE: with the prefix withheld, the FIB answers the LAN client with the WAN ({fresh:?})"
    );
    let stored = demote(&mut sessions, &key, &after);
    assert_eq!(
        (stored.disposition, stored.egress_ifindex),
        (control.disposition, control.egress_ifindex),
        "a demote that runs after the withholding publish must store what it stores with the \
         prefix present, never the WAN egress (stored={stored:?})"
    );

    let (decision, _, origin) = sessions
        .entry_with_origin(&key)
        .expect("the reverse survives");
    let next = reply(
        &after,
        &key,
        decision,
        false,
        origin.is_peer_synced(),
        WAN,
        false,
    );
    assert!(
        !is_local_wan(&next),
        "the next reply after the demote must not leave by the WAN to the client's private \
         address (reply={next:?})"
    );
}

/// (A2, the WAN arrival: a control) A reply that reaches the still-local
/// reverse after the withholding publish and before the demote. Its stamp is
/// stale, so it re-resolves cache-free and gets the WAN answer, and the hit
/// arm's #16217 conversion turns that into the fabric redirect. Green on
/// master; it pins the conversion this issue's correction relies on.
#[test]
fn a_stale_wan_reply_before_the_demote_is_converted_19171() {
    let key = reverse_key(40_102);
    let mut sessions = SessionTable::new();
    let stored = install_local_reverse(&mut sessions, &key);
    let reply = reply(&forwarding(true), &key, stored, true, false, WAN, false);
    assert!(
        !is_local_wan(&reply),
        "a stale WAN-arrival reply to a client whose RG is the peer's is converted (#16217) \
         (reply={reply:?})"
    );
}

/// (A2, the fabric-link arrival) The same reply arriving over the fabric
/// link: #16217 skips it (anti-loop), and the WAN answer stands. Its
/// production reachability is topology-dependent (#19171: it needs a reply
/// handed over the fabric to the non-owner), so it is left open, as is (B).
#[test]
#[ignore = "#19171 row A2-fabric: open, topology-dependent; red on master"]
fn a_stale_fabric_link_reply_before_the_demote_never_leaves_by_the_wan_19171() {
    let key = reverse_key(40_106);
    let mut sessions = SessionTable::new();
    let stored = install_local_reverse(&mut sessions, &key);
    let reply = reply(&forwarding(true), &key, stored, true, false, 21, true);
    assert!(
        !is_local_wan(&reply),
        "a stale fabric-link reply to a client whose RG is the peer's must not leave by the WAN \
         (reply={reply:?})"
    );
}

/// (B) A stored FabricRedirect, arriving over the fabric link: the reply skips
/// the retain verdict (`rehome_skipped`) and takes the fresh answer. It must
/// not be the WAN.
#[test]
#[ignore = "#19171 row B: open, topology-dependent; red on master"]
fn a_fabric_link_reply_on_a_stored_redirect_never_leaves_by_the_wan_19171() {
    let after = forwarding(true);
    let key = reverse_key(40_103);
    let stored = SessionDecision {
        resolution: crate::afxdp::forwarding::resolve_fabric_redirect(&after)
            .expect("FIXTURE: the fabric redirect resolves"),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    for stale in [true, false] {
        let reply = reply(&after, &key, stored, stale, true, 21, true);
        assert!(
            !is_local_wan(&reply),
            "a fabric-link reply on a stored redirect (stale={stale}) to a client whose RG is the \
             peer's must not leave by the WAN (reply={reply:?})"
        );
    }
}

/// The open question (#19171 correction): a demote that ran after the
/// withholding publish stored the WAN egress. Does the next reply, which the
/// hit arm converts to the fabric redirect (#16217), write that back and heal
/// the stored row? Driven through the real hit arm
/// (`resolve_flow_session_decision`, the Owner verdict as for a WAN arrival
/// on the reverse):
/// - step 1, a reply with the stamp the demote left;
/// - step 2, a reply after the next forwarding-generation change, which is
///   when the #11373 deferred revalidation persists.
///
/// Each step prints what was served and what is stored. The assertion is the
/// property the fix must provide: after the demote, the stored row is never a
/// local WAN egress. It holds trivially once the demote never stores one.
#[test]
fn a_wan_stored_row_and_the_replies_that_follow_19171() {
    let key = reverse_key(40_104);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    install_local_reverse(&mut sessions, &key);
    let after = forwarding(true);
    sessions.set_forwarding_revalidation_gen(1, 2);
    let demoted = demote(&mut sessions, &key, &after);
    eprintln!(
        "HEAL19171 step=demote stored=({:?}, egress {})",
        demoted.disposition, demoted.egress_ifindex
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let neighbors = neighbors();
    let hit = |sessions: &mut SessionTable, step: &str| {
        let resolved = resolve_flow_session_decision(
            sessions,
            SteeringMap::unshared_for_test(-1),
            SharedSessionRefs {
                sessions: &shared_sessions,
                nat_sessions: &shared_nat_sessions,
                forward_wire_sessions: &shared_forward_wire_sessions,
                owner_rg_indexes: &shared_owner_rg_indexes,
                peer_worker_commands: &peer_worker_commands,
                worker_commands_by_id: empty_worker_commands_by_id(),
                conntrack: ConntrackFds { v4: -1, v6: -1 },
                tick: Tick::from_ns(NOW_NS),
            },
            &after,
            &split_ha(),
            &neighbors,
            &flow(&key),
            PROTO_TCP,
            0x10,
            WAN,
            0,
            false,
            false,
            0,
            0,
            crate::afxdp::session_glue::SessionHitVerdict::Owner,
        )
        .expect("FIXTURE: the reply hits the reverse");
        let served = resolved.decision.resolution;
        let stored = sessions
            .entry_with_origin(&key)
            .expect("the reverse survives")
            .0
            .resolution;
        eprintln!(
            "HEAL19171 step={step} served=({:?}, egress {}) stored=({:?}, egress {})",
            served.disposition, served.egress_ifindex, stored.disposition, stored.egress_ifindex
        );
        (served, stored)
    };
    let (served1, stored1) = hit(&mut sessions, "reply-1");
    sessions.set_forwarding_revalidation_gen(1, 3);
    let (served2, stored2) = hit(&mut sessions, "reply-2-after-a-generation-change");
    assert!(
        !is_local_wan(&served1) && !is_local_wan(&served2),
        "FIXTURE: the hit arm serves no WAN reply either way (#16217) ({served1:?}, {served2:?})"
    );
    assert!(
        !is_local_wan(&demoted) && !is_local_wan(&stored1) && !is_local_wan(&stored2),
        "after a split-RG demote the stored row must never be a local WAN egress: demote={:?}, \
         after reply 1={:?}, after reply 2={:?}",
        demoted.egress_ifindex,
        stored1.egress_ifindex,
        stored2.egress_ifindex
    );
}

/// (A1, the refresh writer) `RefreshOwnerRGS` wide-scans every HA-managed
/// session, whatever RG list it carries (`worker_queue.rs`, #9720 net-effect
/// note). A refresh for RG1 that reaches the still-local reverse after the
/// withholding publish runs the same cache-free lookup as the demote and
/// stores its result. It must never store the WAN egress for a client whose
/// RG is the peer's.
#[test]
fn a_refresh_after_the_withholding_publish_never_stores_the_wan_egress_19171() {
    let key = reverse_key(40_105);
    let mut sessions = SessionTable::new();
    install_local_reverse(&mut sessions, &key);
    let after = forwarding(true);
    let _ = super::commands::handle_refresh_owner_rgs(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &after,
        &split_ha(),
        &neighbors(),
        vec![1],
        NOW_NS,
        NOW_SECS,
    );
    let stored = sessions
        .entry_with_origin(&key)
        .expect("the refresh retains the reverse")
        .0
        .resolution;
    assert!(
        !is_local_wan(&stored),
        "a refresh after the withholding publish must never store the WAN egress for a client \
         whose RG is the peer's (stored={stored:?})"
    );
}
