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
    let state = forwarding(true);
    let reply = reply(&state, &key, stored, true, false, WAN, false);
    // #16217's exact answer, byte-for-byte: the derivation must leave its
    // domain (a non-fabric-link reverse hit on a non-redirect stored value)
    // untouched.
    let converted = crate::afxdp::forwarding::resolve_zone_encoded_fabric_redirect_by_id(
        &state,
        reverse_metadata(&state).egress_zone,
    )
    .expect("FIXTURE: the zone-encoded redirect resolves");
    assert_eq!(
        reply, converted,
        "a stale WAN-arrival reply to a client whose RG is the peer's is #16217's conversion, \
         exactly (reply={reply:?})"
    );
}

/// (A2, the fabric-link arrival) The same reply arriving over the fabric
/// link: #16217 skips it (anti-loop), and on master the WAN answer stands. Its
/// production reachability is topology-dependent (it needs a reply handed over
/// the fabric to the non-owner). v2 derives the client's connected candidate,
/// which HA refuses on a fabric-link arrival.
#[test]
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

/// The forwarding state after the client's prefix MOVED: 10.0.61.0/24 now
/// sits on `reth3.0` (RG3, ifindex 26), and `reth1.0` (24, RG2) was renumbered
/// to another LAN. With `rg3_peer_owned`, RG3 is the peer's and its prefix is
/// withheld from the transit FIB (#15742).
fn moved_forwarding(rg3_peer_owned: bool) -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    for iface in &mut snapshot.interfaces {
        if iface.name == "reth1.0" {
            for address in &mut iface.addresses {
                if address.family == "inet" {
                    address.address = "10.0.63.1/24".to_string();
                }
            }
        }
    }
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth3.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-3".to_string(),
        ifindex: 26,
        redundancy_group: 3,
        connected_rg_peer_owned: rg3_peer_owned,
        hardware_addr: "02:bf:72:03:00:01".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.61.1/24".to_string(),
            scope: 0,
            ..Default::default()
        }],
        ..Default::default()
    });
    build_forwarding_state(&snapshot)
}

/// RG1 and RG2 active here; RG3 active only when `rg3_active`.
fn moved_ha(rg3_active: bool) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(1, rg(true)), (2, rg(true)), (3, rg(rg3_active))])
}

const NEW_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x26, 0x66];

/// (P2-1, Codex on #19164) The client's prefix moved from `reth1.0` (24, RG2,
/// still active here) to `reth3.0` (26, RG3), with a new neighbor MAC there.
/// The reverse still stores ForwardCandidate(24, the old MAC).
/// - **RG3 the peer's (its prefix withheld):** a refresh must store neither the
///   WAN answer (master) nor the stale 24 and its old MAC (#19171 v1's guard,
///   which restored the stored value and let active RG2 permit it). The
///   derivation names 26/RG3, and HA turns it into the redirect to the owner.
/// - **The control, RG3 active here:** the FIB answers 26 with the new MAC, and
///   the refresh adopts it.
#[test]
fn a_refresh_after_a_prefix_move_never_stores_the_old_egress_or_the_wan_19171() {
    for (rg3_peer_owned, label) in [
        (true, "RG3 the peer's"),
        (false, "RG3 active here (control)"),
    ] {
        let key = reverse_key(if rg3_peer_owned { 40_108 } else { 40_109 });
        let mut sessions = SessionTable::new();
        let installed = install_local_reverse(&mut sessions, &key);
        let after = moved_forwarding(rg3_peer_owned);
        let moved_neighbors = Arc::new(ShardedNeighborMap::new());
        moved_neighbors.insert(
            (26, IpAddr::V4(CLIENT)),
            crate::afxdp::types::NeighborEntry { mac: NEW_MAC },
        );
        let _ = super::commands::handle_refresh_owner_rgs(
            &mut sessions,
            SteeringMap::unshared_for_test(-1),
            &after,
            &moved_ha(!rg3_peer_owned),
            &moved_neighbors,
            vec![2],
            NOW_NS,
            NOW_SECS,
        );
        let stored = sessions
            .entry_with_origin(&key)
            .expect("the refresh retains the reverse")
            .0
            .resolution;
        if rg3_peer_owned {
            assert!(
                !is_local_wan(&stored)
                    && stored.egress_ifindex != LAN
                    && stored.neighbor_mac != installed.resolution.neighbor_mac
                    && stored.disposition == ForwardingDisposition::FabricRedirect,
                "{label}: after the prefix move the refresh must store the redirect to the owner, \
                 never the WAN or the stale egress 24 and its old MAC (stored={stored:?})"
            );
        } else {
            let fib = lookup_forwarding_resolution_for_session_without_cache(
                &after,
                &moved_neighbors,
                &flow(&key),
                installed,
            )
            .resolution;
            assert_eq!(
                (fib.disposition, fib.egress_ifindex, fib.neighbor_mac),
                (ForwardingDisposition::ForwardCandidate, 26, Some(NEW_MAC)),
                "FIXTURE ({label}): the FIB answers the moved prefix with its new MAC ({fib:?})"
            );
            assert_eq!(
                stored, fib,
                "{label}: the refresh adopts the FIB's own answer, byte-for-byte (stored={stored:?})"
            );
        }
    }
}

/// (P2-1, the fabric-link arrival) The same prefix move with RG3 the peer's: a
/// stale reply arriving over the fabric link must leave neither by the WAN nor
/// by the stale egress 24 with its old MAC.
#[test]
fn a_fabric_link_reply_after_a_prefix_move_never_takes_the_old_egress_or_the_wan_19171() {
    let key = reverse_key(40_110);
    let mut sessions = SessionTable::new();
    let installed = install_local_reverse(&mut sessions, &key);
    let after = moved_forwarding(true);
    let moved_neighbors = Arc::new(ShardedNeighborMap::new());
    moved_neighbors.insert(
        (26, IpAddr::V4(CLIENT)),
        crate::afxdp::types::NeighborEntry { mac: NEW_MAC },
    );
    let flow = flow(&key);
    let looked_up = lookup_forwarding_resolution_for_session_without_cache(
        &after,
        &moved_neighbors,
        &flow,
        installed,
    )
    .resolution;
    let reply = reresolve_stored_session(
        &after,
        &moved_ha(false),
        &moved_neighbors,
        NOW_SECS,
        &installed,
        &reverse_metadata(&after),
        &key,
        resolution_target_for_session(&flow, installed),
        looked_up,
        FabricArrival::Packet {
            fabric_ingress: true,
            fabric_link_ingress: true,
            ingress_ifindex: 21,
            ha_startup_grace_until_secs: 0,
            fabric_adopted: false,
            adopted_recovery: None,
        },
    );
    assert!(
        !is_local_wan(&reply)
            && !(matches!(
                reply.disposition,
                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
            ) && reply.egress_ifindex == LAN),
        "a fabric-link reply after the prefix move must take neither the WAN nor the stale egress \
         24 (reply={reply:?})"
    );
}

/// The forward direction, which no conversion protects today: a WAN client's
/// forward session to a server on the LAN (10.0.61.50), stored out `reth1.0`
/// while RG2 was active here. RG2 moves to the peer and its prefix is
/// withheld, so the FIB answers the server with the WAN default route. A
/// forward packet arriving on the WAN must not hairpin back out the WAN; it
/// belongs to the owner across the fabric.
#[test]
fn a_forward_hit_to_a_peer_owned_lan_server_never_leaves_by_the_wan_19171() {
    let server = Ipv4Addr::new(10, 0, 61, 50);
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(server),
        src_port: 50_000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let before = forwarding(false);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert(
        (LAN, IpAddr::V4(server)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0x61, 0x50],
        },
    );
    let resolution = lookup_forwarding_resolution_with_dynamic_for_flow(
        &before,
        &neighbors,
        IpAddr::V4(server),
        &key,
    )
    .resolution;
    assert_eq!(
        (resolution.disposition, resolution.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, LAN),
        "FIXTURE: while RG2 was active here the forward resolved out the LAN ({resolution:?})"
    );
    let stored = SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = SessionMetadata {
        is_reverse: false,
        ingress_zone: before.egress_zone_id(WAN),
        egress_zone: before.egress_zone_id(LAN),
        ..reverse_metadata(&before)
    };
    let after = forwarding(true);
    let flow = flow(&key);
    let looked_up =
        lookup_forwarding_resolution_for_session_without_cache(&after, &neighbors, &flow, stored)
            .resolution;
    assert!(
        is_local_wan(&looked_up),
        "FIXTURE: with the prefix withheld the FIB answers the server with the WAN ({looked_up:?})"
    );
    let forward = reresolve_stored_session(
        &after,
        &split_ha(),
        &neighbors,
        NOW_SECS,
        &stored,
        &metadata,
        &key,
        resolution_target_for_session(&flow, stored),
        looked_up,
        FabricArrival::Packet {
            fabric_ingress: false,
            fabric_link_ingress: false,
            ingress_ifindex: WAN,
            ha_startup_grace_until_secs: 0,
            fabric_adopted: false,
            adopted_recovery: None,
        },
    );
    assert!(
        !is_local_wan(&forward),
        "a forward packet to a server on a peer-owned LAN must not hairpin out the WAN \
         (forward={forward:?})"
    );
}

/// The retain verdict stays where it applies today, byte-for-byte: a demote of
/// a STORED FabricRedirect after the withholding publish is decided by the
/// rehome/retain verdict, not by the derivation. The cell computes the
/// pipeline's answer and the retain verdict's own result for the same inputs.
#[test]
fn a_command_on_a_stored_redirect_keeps_the_retain_verdict_19171() {
    let after = forwarding(true);
    let key = reverse_key(40_111);
    let stored = SessionDecision {
        resolution: crate::afxdp::forwarding::resolve_fabric_redirect(&after)
            .expect("FIXTURE: the fabric redirect resolves"),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = reverse_metadata(&after);
    let flow = flow(&key);
    let target = resolution_target_for_session(&flow, stored);
    let looked_up =
        lookup_forwarding_resolution_for_session_without_cache(&after, &neighbors(), &flow, stored)
            .resolution;
    let pipeline = reresolve_stored_session(
        &after,
        &split_ha(),
        &neighbors(),
        NOW_SECS,
        &stored,
        &metadata,
        &key,
        target,
        looked_up,
        FabricArrival::Command {
            fabric_ingress: false,
        },
    );
    let retained = rehome_or_retain_fabric_redirect(
        &after,
        stored.resolution,
        redirect_session_via_fabric_if_needed(
            &after,
            enforce_ha_resolution_snapshot(&after, &split_ha(), NOW_SECS, looked_up),
            false,
            metadata.ingress_zone,
        ),
        metadata.egress_zone,
        DestinationOwner::from_dest_rg(
            connected_owner_rg_for_target_in_table(&after, target, None),
            &split_ha(),
            NOW_SECS,
        ),
        Some(target),
        None,
    );
    assert_eq!(
        pipeline, retained,
        "a command on a stored redirect is the retain verdict's answer, byte-for-byte \
         (pipeline={pipeline:?})"
    );
}

/// The owner check: a destination whose connected prefix has NO redundancy
/// group has no known owner, so a more-specific route the operator added since
/// install is adopted, not overridden by the connected interface (#16524).
#[test]
fn a_refresh_adopts_a_more_specific_route_for_an_rg_less_connected_destination_19171() {
    let host = Ipv4Addr::new(10, 99, 7, 70);
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "ge-0/0/5.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-5".to_string(),
        ifindex: 30,
        redundancy_group: 0,
        hardware_addr: "02:bf:72:05:00:01".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.99.7.1/24".to_string(),
            scope: 0,
            ..Default::default()
        }],
        ..Default::default()
    });
    let before = build_forwarding_state(&snapshot);
    let mut with_route = snapshot.clone();
    with_route.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.99.7.70/32".to_string(),
        next_hops: vec!["172.16.80.1@reth0.80".to_string()],
        ..Default::default()
    });
    let after = build_forwarding_state(&with_route);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert(
        (30, IpAddr::V4(host)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0x30, 0x70],
        },
    );
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(host),
        src_port: 443,
        dst_port: 40_112,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let installed = lookup_forwarding_resolution_with_dynamic_for_flow(
        &before,
        &neighbors,
        IpAddr::V4(host),
        &key,
    )
    .resolution;
    assert_eq!(
        (installed.disposition, installed.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, 30),
        "FIXTURE: before the route, the host resolves on its RG-less connected interface ({installed:?})"
    );
    let fib = lookup_forwarding_resolution_with_dynamic_for_flow(
        &after,
        &neighbors,
        IpAddr::V4(host),
        &key,
    )
    .resolution;
    assert!(
        is_local_wan(&fib),
        "FIXTURE: the more-specific route sends the host by the WAN gateway ({fib:?})"
    );
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        SessionDecision {
            resolution: installed,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            owner_rg_id: 1,
            ..reverse_metadata(&before)
        },
        SessionOrigin::ReverseFlow,
        NOW_NS,
        PROTO_TCP,
        0x10,
    ));
    let _ = super::commands::handle_refresh_owner_rgs(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &after,
        &split_ha(),
        &neighbors,
        vec![1],
        NOW_NS,
        NOW_SECS,
    );
    let stored = sessions
        .entry_with_origin(&key)
        .expect("retained")
        .0
        .resolution;
    assert_eq!(
        (stored.disposition, stored.egress_ifindex),
        (fib.disposition, fib.egress_ifindex),
        "an RG-less connected destination has no known owner: the refresh adopts the operator's \
         more-specific route (stored={stored:?})"
    );
}

/// The owner ACTIVE here behind a lagging FIB: the snapshot still withholds
/// `reth1.0`'s prefix although RG2 is active again. A forward packet to the LAN
/// server is delivered on the connected interface, never out the WAN. With no
/// neighbor known there, the derived candidate is MissingNeighbor on that
/// interface (a ForwardCandidate with no MAC could not be transmitted).
#[test]
fn a_forward_hit_behind_a_lagging_fib_is_delivered_on_the_connected_interface_19171() {
    let server = Ipv4Addr::new(10, 0, 61, 51);
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(server),
        src_port: 50_001,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let before = forwarding(false);
    let lagging = forwarding(true);
    let both_active = BTreeMap::from([(1, rg(true)), (2, rg(true))]);
    let mac = [0x02, 0, 0, 0, 0x61, 0x51];
    for neighbor_known in [true, false] {
        let at_install = Arc::new(ShardedNeighborMap::new());
        at_install.insert(
            (LAN, IpAddr::V4(server)),
            crate::afxdp::types::NeighborEntry { mac },
        );
        let stored = SessionDecision {
            resolution: lookup_forwarding_resolution_with_dynamic_for_flow(
                &before,
                &at_install,
                IpAddr::V4(server),
                &key,
            )
            .resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        let live = Arc::new(ShardedNeighborMap::new());
        if neighbor_known {
            live.insert(
                (LAN, IpAddr::V4(server)),
                crate::afxdp::types::NeighborEntry { mac },
            );
        }
        let flow = flow(&key);
        let looked_up =
            lookup_forwarding_resolution_for_session_without_cache(&lagging, &live, &flow, stored)
                .resolution;
        let forward = reresolve_stored_session(
            &lagging,
            &both_active,
            &live,
            NOW_SECS,
            &stored,
            &SessionMetadata {
                is_reverse: false,
                ..reverse_metadata(&lagging)
            },
            &key,
            resolution_target_for_session(&flow, stored),
            looked_up,
            FabricArrival::Packet {
                fabric_ingress: false,
                fabric_link_ingress: false,
                ingress_ifindex: WAN,
                ha_startup_grace_until_secs: 0,
                fabric_adopted: false,
                adopted_recovery: None,
            },
        );
        let want = if neighbor_known {
            (ForwardingDisposition::ForwardCandidate, LAN, Some(mac))
        } else {
            (ForwardingDisposition::MissingNeighbor, LAN, None)
        };
        assert_eq!(
            (
                forward.disposition,
                forward.egress_ifindex,
                forward.neighbor_mac
            ),
            want,
            "behind a lagging FIB with the owner active (neighbor known: {neighbor_known}), a forward \
             packet goes to the connected interface, never the WAN (forward={forward:?})"
        );
    }
}

/// #19171 cost: `reresolve_stored_session` on the UNCONTRADICTED path, master
/// vs the derivation. Ignored; run it in release:
/// `cargo test --release --bins reresolve_uncontradicted_cost_bench -- --ignored --nocapture`.
/// - **reverse:** a reverse packet, outside the derivation's domain;
/// - **forward:** a forward packet, inside the domain, whose answer is the
///   stored egress (the derivation's single comparison).
#[test]
#[ignore = "#19171 cost bench: cargo test --release --bins reresolve_uncontradicted_cost_bench -- --ignored --nocapture"]
fn reresolve_uncontradicted_cost_bench_19171() {
    const N: u32 = 500_000;
    let state = forwarding(false);
    let neighbors = neighbors();
    let key = reverse_key(40_199);
    let stored = SessionDecision {
        resolution: lookup_forwarding_resolution_with_dynamic_for_flow(
            &state,
            &neighbors,
            IpAddr::V4(CLIENT),
            &key,
        )
        .resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let flow = flow(&key);
    let target = resolution_target_for_session(&flow, stored);
    let looked_up =
        lookup_forwarding_resolution_for_session(&state, &neighbors, &flow, stored).resolution;
    let ha = BTreeMap::from([(1, rg(true)), (2, rg(true))]);
    let arrival = FabricArrival::Packet {
        fabric_ingress: false,
        fabric_link_ingress: false,
        ingress_ifindex: WAN,
        ha_startup_grace_until_secs: 0,
        fabric_adopted: false,
        adopted_recovery: None,
    };
    for round in 0..4 {
        for (label, is_reverse) in [("reverse", true), ("forward", false)] {
            let metadata = SessionMetadata {
                is_reverse,
                ..reverse_metadata(&state)
            };
            let started = std::time::Instant::now();
            for _ in 0..N {
                std::hint::black_box(reresolve_stored_session(
                    &state, &ha, &neighbors, NOW_SECS, &stored, &metadata, &key, target, looked_up,
                    arrival,
                ));
            }
            let ns = started.elapsed().as_nanos() as f64 / f64::from(N);
            eprintln!("RERESOLVE19171 round={round} path={label} ns_per_call={ns:.1}");
        }
    }
}

// ---------------------------------------------------------------------------
// The caller matrix (r24's addendum): every writer that re-resolves a stored
// session, under every ownership state.
//
// The property is exact, not "not the WAN":
// - **on the split node** (the peer owns RG2 and its prefix is withheld), every
//   caller gives EXACTLY what it gives when the FIB still holds the prefix;
// - **the hit arm's reverse** keeps #16217's exact redirect;
// - **a locally owned or routed destination** adopts the FIB's answer;
// - **a fabric-link arrival** for a peer-owned client is refused (HAInactive on
//   the connected interface).
// ---------------------------------------------------------------------------

const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 50);
const NET_HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

fn both_active() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(1, rg(true)), (2, rg(true))])
}

/// The forwarding state and HA view of each ownership state.
#[derive(Clone, Copy, Debug)]
enum State {
    /// The peer owns RG2 and the FIB withholds its prefix (the split node).
    PeerWithheld,
    /// The peer owns RG2 but the FIB still holds its prefix (the honest FIB).
    PeerPresent,
    /// RG2 is active here; nothing is withheld.
    LocalOwned,
}

fn state_of(state: State) -> (ForwardingState, BTreeMap<i32, HAGroupRuntime>) {
    match state {
        State::PeerWithheld => (forwarding(true), split_ha()),
        State::PeerPresent => (forwarding(false), split_ha()),
        State::LocalOwned => (forwarding(false), both_active()),
    }
}

/// Live neighbors for the LAN destinations, on the LAN interface.
fn matrix_neighbors() -> Arc<ShardedNeighborMap> {
    let neighbors = neighbors();
    neighbors.insert(
        (LAN, IpAddr::V4(LAN_HOST)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0x61, 0x50],
        },
    );
    neighbors
}

/// A session key toward `dst` (reverse: from the server; forward: from a WAN
/// host), and its stored local resolution under the honest FIB.
fn matrix_session(
    dst: Ipv4Addr,
    is_reverse: bool,
    port: u16,
) -> (SessionKey, SessionDecision, SessionMetadata) {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(dst),
        src_port: if is_reverse { 443 } else { port },
        dst_port: if is_reverse { port } else { 443 },
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let honest = forwarding(false);
    let resolution = lookup_forwarding_resolution_with_dynamic_for_flow(
        &honest,
        &matrix_neighbors(),
        IpAddr::V4(dst),
        &key,
    )
    .resolution;
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = SessionMetadata {
        is_reverse,
        ..reverse_metadata(&honest)
    };
    (key, decision, metadata)
}

fn packet(ingress_ifindex: i32, fabric_link: bool) -> FabricArrival<'static> {
    FabricArrival::Packet {
        fabric_ingress: fabric_link,
        fabric_link_ingress: fabric_link,
        ingress_ifindex,
        ha_startup_grace_until_secs: 0,
        fabric_adopted: false,
        adopted_recovery: None,
    }
}

/// The hit arm: the stale (cache-free) lookup, the pipeline, then #16217 for a
/// reverse hit.
fn hit(
    state: State,
    session: &(SessionKey, SessionDecision, SessionMetadata),
    fabric_link: bool,
) -> ForwardingResolution {
    let (forwarding, ha) = state_of(state);
    let neighbors = matrix_neighbors();
    let (key, stored, metadata) = session;
    let flow = flow(key);
    let target = resolution_target_for_session(&flow, *stored);
    let looked_up = lookup_forwarding_resolution_for_session_without_cache(
        &forwarding,
        &neighbors,
        &flow,
        *stored,
    )
    .resolution;
    let arrival = if fabric_link {
        packet(21, true)
    } else {
        packet(WAN, false)
    };
    let mut decision = *stored;
    decision.resolution = reresolve_stored_session(
        &forwarding,
        &ha,
        &neighbors,
        NOW_SECS,
        stored,
        metadata,
        key,
        target,
        looked_up,
        arrival,
    );
    if let Some(redirect) = reverse_hit_departed_destination_redirect(
        &forwarding,
        &ha,
        NOW_SECS,
        fabric_link,
        metadata.is_reverse,
        target,
        install_table_name_for_session(&forwarding, decision, target),
        metadata.egress_zone,
        decision.resolution.disposition,
    ) {
        decision.resolution = redirect;
    }
    decision.resolution
}

/// The HA commands: install the session, run the command, read what it stored.
fn command(
    state: State,
    session: &(SessionKey, SessionDecision, SessionMetadata),
    demote: bool,
) -> ForwardingResolution {
    let (forwarding, ha) = state_of(state);
    let (key, stored, metadata) = session;
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        *stored,
        SessionMetadata {
            owner_rg_id: 2,
            ..metadata.clone()
        },
        SessionOrigin::ReverseFlow,
        NOW_NS,
        PROTO_TCP,
        0x10,
    ));
    if demote {
        let mut cancelled_keys = Vec::new();
        let mut cancelled_keys_seen = rustc_hash::FxHashSet::default();
        let _ = super::commands::handle_demote_owner_rgs(
            &mut sessions,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &forwarding,
            &ha,
            &matrix_neighbors(),
            vec![2],
            NOW_NS,
            NOW_SECS,
            &mut cancelled_keys,
            &mut cancelled_keys_seen,
        );
    } else {
        let _ = super::commands::handle_refresh_owner_rgs(
            &mut sessions,
            SteeringMap::unshared_for_test(-1),
            &forwarding,
            &ha,
            &matrix_neighbors(),
            vec![1],
            NOW_NS,
            NOW_SECS,
        );
    }
    sessions
        .entry_with_origin(key)
        .expect("the command retains the row")
        .0
        .resolution
}

/// The forward-companion revalidation (`policy_revalidation.rs`).
fn forward_companion(
    state: State,
    session: &(SessionKey, SessionDecision, SessionMetadata),
    fabric_link: bool,
) -> ForwardingResolution {
    let (forwarding, ha) = state_of(state);
    let (key, stored, metadata) = session;
    crate::afxdp::poll_descriptor::resolve_current_forward_companion(
        &forwarding,
        &ha,
        &matrix_neighbors(),
        key,
        *stored,
        metadata,
        fabric_link,
        fabric_link,
        NOW_SECS,
        if fabric_link { 21 } else { WAN },
        0,
    )
}

/// A forward synced import: what `handle_upsert_synced` stores, and the owner
/// RG it records.
fn forward_import(
    state: State,
    session: &(SessionKey, SessionDecision, SessionMetadata),
) -> (ForwardingResolution, i32) {
    let (forwarding, ha) = state_of(state);
    let (key, stored, metadata) = session;
    let mut sessions = SessionTable::new();
    super::commands::handle_upsert_synced(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &forwarding,
        &ha,
        &matrix_neighbors(),
        SyncedSessionEntry {
            sibling_last_seen_ns: 0,
            last_served_ns: 0,
            key: key.clone(),
            decision: *stored,
            metadata: metadata.clone(),
            leak_incarnation: 0,
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
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
        NOW_NS,
        NOW_SECS,
        0,
    );
    let (decision, metadata, _) = sessions
        .entry_with_origin(key)
        .expect("the import installs");
    (decision.resolution, metadata.owner_rg_id)
}

/// The split node converges to the honest-FIB answer, caller by caller; the
/// hit arm's reverse keeps #16217's exact redirect.
#[test]
fn every_caller_on_the_split_node_gives_its_honest_fib_answer_19171() {
    let reverse = matrix_session(CLIENT, true, 40_300);
    let forward = matrix_session(LAN_HOST, false, 40_301);
    let (split, _) = state_of(State::PeerWithheld);
    let converted = crate::afxdp::forwarding::resolve_zone_encoded_fabric_redirect_by_id(
        &split,
        reverse.2.egress_zone,
    )
    .expect("FIXTURE: the zone-encoded redirect resolves");
    assert_eq!(
        hit(State::PeerWithheld, &reverse, false),
        converted,
        "hit/reverse: #16217's exact redirect"
    );
    for (caller, split_answer, honest_answer) in [
        (
            "hit/forward",
            hit(State::PeerWithheld, &forward, false),
            hit(State::PeerPresent, &forward, false),
        ),
        (
            "demote/reverse",
            command(State::PeerWithheld, &reverse, true),
            command(State::PeerPresent, &reverse, true),
        ),
        (
            "refresh/reverse",
            command(State::PeerWithheld, &reverse, false),
            command(State::PeerPresent, &reverse, false),
        ),
        (
            "refresh/forward",
            command(State::PeerWithheld, &forward, false),
            command(State::PeerPresent, &forward, false),
        ),
        (
            "forward-companion",
            forward_companion(State::PeerWithheld, &forward, false),
            forward_companion(State::PeerPresent, &forward, false),
        ),
        (
            "forward-import",
            forward_import(State::PeerWithheld, &forward).0,
            forward_import(State::PeerPresent, &forward).0,
        ),
    ] {
        assert!(
            !is_local_wan(&honest_answer),
            "FIXTURE ({caller}): the honest FIB never answers the WAN ({honest_answer:?})"
        );
        assert_eq!(
            split_answer, honest_answer,
            "{caller}: on the split node the caller must give its honest-FIB answer, exactly"
        );
    }
    assert_eq!(
        forward_import(State::PeerWithheld, &forward).1,
        2,
        "forward-import: the owner RG stays RG2, never relabelled to the WAN's RG"
    );
}

/// A locally owned destination and a routed one (no connected owner) adopt the
/// FIB's own answer, caller by caller.
#[test]
fn every_caller_adopts_the_fib_for_a_local_or_routed_destination_19171() {
    let (local_fib, _) = state_of(State::LocalOwned);
    for (label, dst, state) in [
        ("local-owned", LAN_HOST, State::LocalOwned),
        ("routed", NET_HOST, State::PeerWithheld),
    ] {
        let (fib_state, _) = state_of(state);
        let forward = matrix_session(dst, false, 40_310);
        let fib = lookup_forwarding_resolution_for_session_without_cache(
            &fib_state,
            &matrix_neighbors(),
            &flow(&forward.0),
            forward.1,
        )
        .resolution;
        assert_eq!(
            fib.disposition,
            ForwardingDisposition::ForwardCandidate,
            "FIXTURE ({label}): the FIB forwards it ({fib:?})"
        );
        for (caller, answer) in [
            ("hit/forward", hit(state, &forward, false)),
            ("refresh/forward", command(state, &forward, false)),
            (
                "forward-companion",
                forward_companion(state, &forward, false),
            ),
            ("forward-import", forward_import(state, &forward).0),
        ] {
            assert_eq!(
                (
                    answer.disposition,
                    answer.egress_ifindex,
                    answer.neighbor_mac
                ),
                (fib.disposition, fib.egress_ifindex, fib.neighbor_mac),
                "{label} {caller}: adopts the FIB's answer"
            );
        }
    }
    let _ = local_fib;
}

/// A fabric-link arrival for a peer-owned client is refused (HAInactive on the
/// connected interface), never forwarded out the WAN, never redirected back.
#[test]
fn every_packet_caller_refuses_a_fabric_link_arrival_for_a_peer_owned_client_19171() {
    let reverse = matrix_session(CLIENT, true, 40_320);
    let forward = matrix_session(LAN_HOST, false, 40_321);
    for (caller, answer) in [
        ("hit/reverse", hit(State::PeerWithheld, &reverse, true)),
        ("hit/forward", hit(State::PeerWithheld, &forward, true)),
        (
            "forward-companion",
            forward_companion(State::PeerWithheld, &forward, true),
        ),
    ] {
        assert_eq!(
            (answer.disposition, answer.egress_ifindex),
            (ForwardingDisposition::HAInactive, LAN),
            "{caller}: a fabric-link arrival for a peer-owned client is refused on its connected \
             interface ({answer:?})"
        );
    }
}

/// r24's anti-loop case: each node's view says the OTHER owns RG2. A reply
/// handed over the fabric is refused on both sides, so it cannot ping-pong.
#[test]
fn a_split_view_cannot_ping_pong_a_reply_over_the_fabric_19171() {
    let reverse = matrix_session(CLIENT, true, 40_330);
    for node in ["node0", "node1"] {
        let answer = hit(State::PeerWithheld, &reverse, true);
        assert_ne!(
            answer.disposition,
            ForwardingDisposition::FabricRedirect,
            "{node}: a fabric-link reply for a client this view gives to the peer is never \
             redirected back ({answer:?})"
        );
        assert!(
            !is_local_wan(&answer),
            "{node}: nor sent out the WAN ({answer:?})"
        );
    }
}

/// r24 P3-1: a fabric-link reply in the takeover window that the hit arm
/// persisted with a CURRENT stamp, relabelling the row to the WAN's RG. On
/// master the RG demote never visits it again (it is filed under RG1 now). With
/// the derivation the hit arm never produces that WAN answer, and a refresh of
/// an already-polluted row heals it to the honest-FIB answer.
#[test]
fn a_persisted_and_relabelled_wan_row_is_healed_by_the_next_refresh_19171() {
    let reverse = matrix_session(CLIENT, true, 40_340);
    let (split, _) = state_of(State::PeerWithheld);
    let polluted = lookup_forwarding_resolution_for_session_without_cache(
        &split,
        &matrix_neighbors(),
        &flow(&reverse.0),
        reverse.1,
    )
    .resolution;
    assert!(
        is_local_wan(&polluted),
        "FIXTURE: the polluted row is the WAN answer ({polluted:?})"
    );
    let polluted_session = (
        reverse.0.clone(),
        SessionDecision {
            resolution: polluted,
            ..reverse.1
        },
        SessionMetadata {
            owner_rg_id: 1,
            ..reverse.2.clone()
        },
    );
    let healed = command(State::PeerWithheld, &polluted_session, false);
    assert_eq!(
        healed,
        command(State::PeerPresent, &reverse, false),
        "a refresh heals an already-polluted WAN row to the honest-FIB answer"
    );
}

/// The trigger is a WITHHELD prefix, not merely a known owner: on an honest FIB
/// the FIB is authoritative. An operator's more-specific route to a host inside
/// the RETH-connected LAN (RG2 active here, nothing withheld) is adopted by a
/// refresh, never overridden by the connected interface.
#[test]
fn a_refresh_adopts_an_operators_more_specific_route_on_an_honest_fib_19171() {
    let host = Ipv4Addr::new(10, 0, 61, 99);
    let snapshot = nat_snapshot_with_fabric();
    let before = build_forwarding_state(&snapshot);
    let mut with_route = snapshot.clone();
    with_route.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "10.0.61.99/32".to_string(),
        next_hops: vec!["172.16.80.1@reth0.80".to_string()],
        ..Default::default()
    });
    let after = build_forwarding_state(&with_route);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    neighbors.insert(
        (LAN, IpAddr::V4(host)),
        crate::afxdp::types::NeighborEntry {
            mac: [0x02, 0, 0, 0, 0x61, 0x99],
        },
    );
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(SERVER),
        dst_ip: IpAddr::V4(host),
        src_port: 443,
        dst_port: 40_113,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let installed = lookup_forwarding_resolution_with_dynamic_for_flow(
        &before,
        &neighbors,
        IpAddr::V4(host),
        &key,
    )
    .resolution;
    assert_eq!(
        (installed.disposition, installed.egress_ifindex),
        (ForwardingDisposition::ForwardCandidate, LAN),
        "FIXTURE: before the route, the host resolves on the LAN ({installed:?})"
    );
    let fib = lookup_forwarding_resolution_with_dynamic_for_flow(
        &after,
        &neighbors,
        IpAddr::V4(host),
        &key,
    )
    .resolution;
    assert!(
        is_local_wan(&fib),
        "FIXTURE: the operator's /32 sends the host by the WAN gateway ({fib:?})"
    );
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        SessionDecision {
            resolution: installed,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        reverse_metadata(&before),
        SessionOrigin::ReverseFlow,
        NOW_NS,
        PROTO_TCP,
        0x10,
    ));
    let _ = super::commands::handle_refresh_owner_rgs(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &after,
        &both_active(),
        &neighbors,
        vec![2],
        NOW_NS,
        NOW_SECS,
    );
    let stored = sessions
        .entry_with_origin(&key)
        .expect("retained")
        .0
        .resolution;
    assert_eq!(
        stored, fib,
        "on an honest FIB the refresh adopts the operator's more-specific route, byte-for-byte \
         (stored={stored:?})"
    );
}

/// The exemption: an answer already on the withheld row's interface keeps its
/// own next hop and MAC. The WAN host 172.16.80.77 lies in `reth0.80`'s subnet,
/// withheld because RG1 is the peer's; the FIB answers it by the default
/// route's gateway, which #18517 binds to that same withheld row. A forward
/// import (stored as resolved on the standby) must keep the FIB's own answer
/// (the gateway's next hop and MAC), not a derived direct line to the host.
#[test]
fn an_answer_on_the_withheld_rows_own_interface_is_adopted_19171() {
    let host = Ipv4Addr::new(172, 16, 80, 77);
    let mut snapshot = nat_snapshot_with_fabric();
    for iface in &mut snapshot.interfaces {
        if iface.name == "reth0.80" {
            iface.connected_rg_peer_owned = true;
        }
    }
    let state = build_forwarding_state(&snapshot);
    let wan_peer = BTreeMap::from([(1, rg(false)), (2, rg(true))]);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(host),
        src_port: 40_114,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let stored = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let flow = flow(&key);
    let fib =
        lookup_forwarding_resolution_for_session_without_cache(&state, &neighbors, &flow, stored)
            .resolution;
    assert_eq!(
        (fib.disposition, fib.egress_ifindex, fib.next_hop),
        (
            ForwardingDisposition::ForwardCandidate,
            WAN,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1)))
        ),
        "FIXTURE: the FIB answers the withheld-subnet host by the gateway bound to that row ({fib:?})"
    );
    let mut sessions = SessionTable::new();
    super::commands::handle_upsert_synced(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &state,
        &wan_peer,
        &neighbors,
        SyncedSessionEntry {
            sibling_last_seen_ns: 0,
            last_served_ns: 0,
            key: key.clone(),
            decision: stored,
            metadata: SessionMetadata {
                is_reverse: false,
                ingress_zone: state.egress_zone_id(LAN),
                egress_zone: state.egress_zone_id(WAN),
                ..reverse_metadata(&state)
            },
            leak_incarnation: 0,
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
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
        NOW_NS,
        NOW_SECS,
        0,
    );
    let imported = sessions
        .entry_with_origin(&key)
        .expect("the import installs")
        .0
        .resolution;
    assert_eq!(
        imported, fib,
        "an answer on the withheld row's own interface is adopted, gateway and MAC included \
         (imported={imported:?})"
    );
}
