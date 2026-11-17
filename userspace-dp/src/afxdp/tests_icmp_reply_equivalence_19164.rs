//! #19164 v3: the equivalence matrix. An embedded ICMP error that quotes a
//! FORWARD packet of a session returns by the route a REPLY on that session
//! gets. The error's return route is `session_glue::reverse_reply_resolution`,
//! the same function the reply's session-hit arm calls.
//!
//! Each row builds its shape twice, from scratch. It drives a reply through
//! the production poll pipeline on one copy and the error on the other, then
//! compares where each left: the binding it was transmitted on and the
//! destination MAC.
//!
//! Each row also pins the reply's own outcome (its premise). A defect inside
//! the shared resolution moves both arms together, so the comparison alone
//! cannot see it. The premise is also what makes a row able to fail: on the
//! pre-#19164 code the error took the stored resolution, and every row marked
//! RED-ON-BASE below has a reply that does not.
//!
//! Topology (the #18531 harness, the captured loss-cluster fw1 snapshot):
//! - binding WAN (`reth0.80`, ifindex 14 on parent 6, RG1);
//! - binding FABRIC (`fab0`);
//! - binding LAN (`reth1.0`, ifindex 5, RG2).
//!
//! The flow is LAN client C -> WAN server S, interface-SNAT to P. A reply is
//! S -> P arriving on the WAN. The error is an ICMP Time Exceeded from a WAN
//! router to P, quoting the translated forward packet P -> S.

use super::tests_split_rg_failback_18531::*;
use super::tests_support::*;
use super::*;

/// The client's neighbor in the captured snapshot (v4 and v6 alike).
const CLIENT_MAC: [u8; 6] = [0x10, 0x66, 0x6a, 0x0b, 0xd0, 0x17];
/// The client's MAC after a NIC swap (the MAC row).
const NEW_CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x19, 0x16, 0x04, 0x01];
/// A WAN gateway the route-move rows send the client's /32 or /128 through.
const MOVED_GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x19, 0x16, 0x04, 0x02];
/// The WAN unit's MAC: what an upstream router addresses frames to.
const WAN_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01];

fn router(family: Family) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1)),
        Family::V6 => IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 1)),
    }
}

fn moved_gateway(family: Family) -> IpAddr {
    match family {
        Family::V4 => IpAddr::V4(Ipv4Addr::new(172, 16, 80, 77)),
        Family::V6 => IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x77)),
    }
}

fn host_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

fn route(family: Family, destination: String, next_hop: Option<IpAddr>, discard: bool) -> crate::protocol::RouteSnapshot {
    let (table, fam) = match family {
        Family::V4 => ("inet.0", "inet"),
        Family::V6 => ("inet6.0", "inet6"),
    };
    serde_json::from_value(serde_json::json!({
        "table": table, "family": fam, "destination": destination,
        "next_hops": next_hop.map(|n| vec![n.to_string()]).unwrap_or_default(),
        "next_hop_weights": [], "discard": discard, "reject": false,
        "cluster_terminal": false, "next_table": "", "rule_priority": 0,
        "preference": 5,
    }))
    .expect("route snapshot")
}

/// The split node: WAN RG1 active here, LAN RG2 the peer's. The peer-owned LAN
/// connected prefix is withheld from the transit FIB (#15742): the interface is
/// marked and the connected route is absent, as the Go side builds it.
fn split_forwarding() -> ForwardingState {
    let mut snapshot = fw1_owner_snapshot();
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.connected_rg_peer_owned = true;
        }
    }
    snapshot
        .routes
        .retain(|r| r.destination != "10.0.61.0/24" && r.destination != "2001:559:8585:ef00::/64");
    build_forwarding_state(&snapshot)
}

fn split_node_ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ])
}

/// fw1 owning both RGs, with `extra` routes added to its snapshot.
fn owner_forwarding_with(extra: Vec<crate::protocol::RouteSnapshot>) -> ForwardingState {
    let mut snapshot = fw1_owner_snapshot();
    snapshot.routes.extend(extra);
    build_forwarding_state(&snapshot)
}

fn client(family: Family) -> IpAddr {
    addrs(family).0
}

fn canonical_reverse_key(family: Family, forwarding: &ForwardingState) -> crate::session::SessionKey {
    let forward = exported_forward(forwarding, family);
    crate::session::reverse_session_key(&forward.key, forward.decision.nat)
}

/// Import ONLY the reverse half of the canonical pair (Codex P2-2): the
/// error's quote then matches through the reply key, on the reverse.
fn import_reverse_only(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
) {
    let forward = exported_forward(forwarding, family);
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::default()),
        &forward,
        now_secs,
    )
    .expect("production reverse synthesis must produce the companion");
    apply_commands(sessions, forwarding, ha, vec![WorkerCommand::UpsertSynced(reverse)]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arrival {
    Wan,
    /// Redirected to this node over the fabric with the WAN zone stamp.
    Fabric,
}

/// The error: ICMP Time Exceeded from a WAN router to the wire source P,
/// quoting the forward packet P:`quote_src_port` -> S:DPORT.
fn icmp_error_frame(
    forwarding: &ForwardingState,
    family: Family,
    quote_src_port: u16,
    arrival: Arrival,
) -> (Vec<u8>, UserspaceDpMeta) {
    let (_, wan, snat) = addrs(family);
    let dst_mac = match arrival {
        Arrival::Wan => WAN_MAC,
        Arrival::Fabric => LOCAL_FABRIC_MAC,
    };
    let ingress = match arrival {
        Arrival::Wan => WAN_UNIT_IFINDEX as u32,
        Arrival::Fabric => FABRIC_IFINDEX as u32,
    };
    let (mut frame, mut meta) = match (router(family), snat, wan) {
        (IpAddr::V4(r), IpAddr::V4(p), IpAddr::V4(s)) => {
            let frame =
                build_icmp_te_frame_v4_with_mac(r, p, s, quote_src_port, DPORT, PROTO_TCP, dst_mac);
            let mut meta = txn_meta_v4(ingress, 0, frame.len() as u16);
            meta.protocol = PROTO_ICMP;
            meta.payload_offset = 42;
            (frame, meta)
        }
        (IpAddr::V6(r), IpAddr::V6(p), IpAddr::V6(s)) => {
            let frame =
                build_icmpv6_te_frame_with_mac(r, p, s, quote_src_port, DPORT, PROTO_TCP, dst_mac);
            let mut meta = txn_meta_v6(ingress, frame.len());
            meta.protocol = PROTO_ICMPV6;
            meta.tcp_flags = 0;
            meta.payload_offset = 62;
            (frame, meta)
        }
        _ => unreachable!("one family"),
    };
    match arrival {
        Arrival::Wan => meta.ingress_vlan_id = 80,
        Arrival::Fabric => {
            let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
            frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
        }
    }
    set_flow(&mut meta, router(family), snat, 0, 0);
    (frame, meta)
}

/// The reply S:DPORT -> P:`dst_port`, arriving as `arrival` says.
fn reply_frame(
    forwarding: &ForwardingState,
    family: Family,
    dst_port: u16,
    arrival: Arrival,
) -> (Vec<u8>, UserspaceDpMeta) {
    match arrival {
        Arrival::Wan => wan_reply_frame_to(family, dst_port),
        Arrival::Fabric => {
            let (_, wan, snat) = addrs(family);
            let mut frame = match (wan, snat) {
                (IpAddr::V4(w), IpAddr::V4(s)) => {
                    build_txn_tcp_syn_frame_v4(w, s, DPORT, dst_port, TCP_ACK, LOCAL_FABRIC_MAC)
                }
                (IpAddr::V6(w), IpAddr::V6(s)) => {
                    build_txn_tcp_frame_v6(w, s, DPORT, dst_port, TCP_ACK, LOCAL_FABRIC_MAC)
                }
                _ => unreachable!("one family"),
            };
            let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
            frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
            let mut meta = match family {
                Family::V4 => txn_meta_v4(FABRIC_IFINDEX as u32, TCP_ACK, frame.len() as u16),
                Family::V6 => {
                    let mut meta = txn_meta_v6(FABRIC_IFINDEX as u32, frame.len());
                    meta.tcp_flags = TCP_ACK;
                    meta
                }
            };
            set_flow(&mut meta, wan, snat, DPORT, dst_port);
            (frame, meta)
        }
    }
}

/// Where one packet left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    /// Packets transmitted on [WAN, FABRIC, LAN].
    tx: [u64; 3],
    /// The destination MAC of the transmitted frame, when the harness captured
    /// it (it captures the bindings other than the ingress one).
    dst_mac: Option<[u8; 6]>,
}

fn send(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    arrival: Arrival,
    (frame, mut meta): (Vec<u8>, UserspaceDpMeta),
    neighbor_generation: u64,
) -> Seen {
    meta.config_generation = 7;
    let mut bindings = bindings();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let ingress = match arrival {
        Arrival::Wan => WAN,
        Arrival::Fabric => FABRIC,
    };
    let (_batch, dbg, egress) = txn_run_multi_binding_at_generations(
        &mut bindings,
        ingress,
        sessions,
        forwarding,
        ha,
        &frame,
        meta,
        &shared,
        7,
        neighbor_generation,
    );
    assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor must reach the poll body");
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    Seen {
        tx: [tx(&bindings[WAN]), tx(&bindings[FABRIC]), tx(&bindings[LAN])],
        dst_mac: egress.and_then(|f| f.get(0..6).map(|m| m.try_into().expect("6 bytes"))),
    }
}

/// One matrix row: the state each arm starts from, and what to send.
struct Row<'a> {
    name: &'static str,
    family: Family,
    /// Builds the session table the packet meets. It may itself drive packets
    /// (a priming reply), identically for both arms.
    setup: &'a dyn Fn() -> SessionTable,
    forwarding: &'a ForwardingState,
    ha: &'a BTreeMap<i32, HAGroupRuntime>,
    arrival: Arrival,
    /// The quoted / replied-to port on P.
    port: u16,
    neighbor_generation: u64,
    /// The reply's own outcome: the row's premise.
    reply_tx: [u64; 3],
    reply_mac: Option<[u8; 6]>,
}

fn run_row(row: &Row<'_>) {
    let ctx = format!("{} ({:?})", row.name, row.family);
    let mut reply_sessions = (row.setup)();
    let reply = send(
        &mut reply_sessions,
        row.forwarding,
        row.ha,
        row.arrival,
        reply_frame(row.forwarding, row.family, row.port, row.arrival),
        row.neighbor_generation,
    );
    assert_eq!(reply.tx, row.reply_tx, "PREMISE {ctx}: where the reply leaves ({reply:?})");
    if row.reply_mac.is_some() {
        assert_eq!(reply.dst_mac, row.reply_mac, "PREMISE {ctx}: the reply's next-hop MAC");
    }
    let mut error_sessions = (row.setup)();
    let error = send(
        &mut error_sessions,
        row.forwarding,
        row.ha,
        row.arrival,
        icmp_error_frame(row.forwarding, row.family, row.port, row.arrival),
        row.neighbor_generation,
    );
    assert_eq!(
        error, reply,
        "{ctx}: an ICMP error quoting the forward packet must leave where the reply does (#19164)"
    );
}

fn imported_pair(forwarding: &ForwardingState, ha: &BTreeMap<i32, HAGroupRuntime>, family: Family) -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    import_on_with_service(&mut sessions, forwarding, ha, family, true);
    assert_eq!(sessions.len(), 2, "fixture: imported pair ({family:?})");
    sessions
}

fn stored_reverse(sessions: &SessionTable, key: &crate::session::SessionKey) -> (ForwardingDisposition, i32, crate::session::SessionOrigin) {
    let (decision, _, origin) = sessions.entry_with_origin(key).expect("fixture: the reverse is held");
    (decision.resolution.disposition, decision.resolution.egress_ifindex, origin)
}

/// RED-ON-BASE. A pair imported while the peer owned the LAN stores a reverse
/// that does not deliver to the LAN. Once RG2 is active here, the reply
/// rehomes to the LAN and the error must too. The base returned the stored
/// value. Two import FIBs:
/// - the LAN row present with RG2 inactive (the shape #19164 was filed on):
///   the import stores a FabricRedirect, and the base sent the error to the
///   demoted peer;
/// - the production split FIB, the LAN prefix withheld (#15742): the import
///   resolves the client by the WAN default, and the base sent the error by
///   that stored WAN answer.
#[test]
fn icmp_error_follows_the_reply_after_lan_activation_19164() {
    let split = split_forwarding();
    let owner = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    for (family, withheld) in [
        (Family::V4, false),
        (Family::V6, false),
        (Family::V4, true),
        (Family::V6, true),
    ] {
        let import_fib = if withheld { &split } else { &owner };
        let setup = || {
            let sessions = imported_pair(import_fib, &split_node_ha(now_secs), family);
            let (disposition, egress, _) =
                stored_reverse(&sessions, &canonical_reverse_key(family, import_fib));
            if withheld {
                assert!(
                    !(disposition == ForwardingDisposition::ForwardCandidate && egress == LAN_IFINDEX),
                    "fixture: the split import does not deliver to the LAN ({family:?}: {disposition:?} on {egress})"
                );
            } else {
                assert_eq!(
                    disposition,
                    ForwardingDisposition::FabricRedirect,
                    "fixture: imported while the peer owned the LAN ({family:?})"
                );
            }
            sessions
        };
        run_row(&Row {
            name: if withheld { "LAN activation, withheld import" } else { "LAN activation" },
            family,
            setup: &setup,
            forwarding: &owner,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [0, 0, 1],
            reply_mac: Some(CLIENT_MAC),
        });
    }
}

/// Guard (r23 P1). The split node keeps the stored FabricRedirect: the FIB
/// answers the client by the WAN default, and the reply's retain verdict keeps
/// the fabric. So must the error.
#[test]
fn icmp_error_keeps_the_replys_fabric_redirect_on_the_split_node_19164() {
    let split = split_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha = split_node_ha(now_secs);
    for family in [Family::V4, Family::V6] {
        let fib = crate::afxdp::forwarding::lookup_forwarding_resolution_with_dynamic(
            &split,
            &Arc::new(ShardedNeighborMap::new()),
            client(family),
        )
        .resolution;
        assert_ne!(
            fib.egress_ifindex, LAN_IFINDEX,
            "fixture: the split FIB withholds the LAN prefix ({family:?}: {fib:?})"
        );
        let setup = || imported_pair(&split, &ha, family);
        run_row(&Row {
            name: "split node",
            family,
            setup: &setup,
            forwarding: &split,
            ha: &ha,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [0, 1, 0],
            reply_mac: None,
        });
    }
}

/// Guard (Codex P1). The node holds only the forward-wire alias of a flow whose
/// canonical row (and its NAT) is on the peer; its reverse un-NATs to the SNAT
/// address itself. Once the SNAT address is local, the reply is handed to the
/// peer, not the host (#18531), and so is the error. Refresh-first and
/// reply-first.
#[test]
fn icmp_error_on_an_alias_is_handed_to_the_peer_like_the_reply_19164() {
    let window = rg_taking_node_forwarding();
    let owner = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let activated = split_node_ha(now_secs);
    for (family, refresh_first) in [
        (Family::V4, true),
        (Family::V4, false),
        (Family::V6, true),
        (Family::V6, false),
    ] {
        let canonical = exported_forward(&window, family);
        let setup = || {
            let mut sessions = SessionTable::new();
            sessions.set_forwarding_revalidation_gen(7, 9);
            import_alias_only_of(&mut sessions, &window, &window_ha(now_secs), &canonical);
            if refresh_first {
                crate::afxdp::session_glue::handle_refresh_owner_rgs_for_test(
                    &mut sessions,
                    crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
                    &owner,
                    &activated,
                    &Arc::new(ShardedNeighborMap::default()),
                    vec![1],
                    now_ns + 2,
                    now_secs,
                );
            }
            sessions
        };
        run_row(&Row {
            name: if refresh_first { "alias, refresh first" } else { "alias, reply first" },
            family,
            setup: &setup,
            forwarding: &owner,
            ha: &activated,
            arrival: Arrival::Wan,
            port: alias_of(&canonical).key.src_port,
            neighbor_generation: 2,
            reply_tx: [0, 1, 0],
            reply_mac: None,
        });
    }
}

/// D1 anti-loop. A reply that reaches the alias-only owner OVER THE FABRIC is
/// dropped, never bounced back (#18531). An error redirected the same way must
/// not be bounced either.
#[test]
fn icmp_error_over_the_fabric_is_not_bounced_like_the_reply_19164() {
    let window = rg_taking_node_forwarding();
    let owner = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let activated = split_node_ha(now_secs);
    for family in [Family::V4, Family::V6] {
        let canonical = exported_forward(&window, family);
        let setup = || {
            let mut sessions = SessionTable::new();
            sessions.set_forwarding_revalidation_gen(7, 9);
            import_alias_only_of(&mut sessions, &window, &window_ha(now_secs), &canonical);
            sessions
        };
        run_row(&Row {
            name: "alias, fabric arrival",
            family,
            setup: &setup,
            forwarding: &owner,
            ha: &activated,
            arrival: Arrival::Fabric,
            port: alias_of(&canonical).key.src_port,
            neighbor_generation: 2,
            reply_tx: [0, 0, 0],
            reply_mac: None,
        });
    }
}

/// RED-ON-BASE (Codex P2-2). Only the reverse half is held, so the error's
/// quote matches through the reply key, on the reverse. After LAN activation
/// the reply rehomes to the LAN; the base returned the stored FabricRedirect
/// for this arm.
#[test]
fn icmp_error_matched_through_the_reverse_half_follows_the_reply_19164() {
    let split = split_forwarding();
    let owner = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    for family in [Family::V4, Family::V6] {
        let setup = || {
            let mut sessions = SessionTable::new();
            sessions.set_forwarding_revalidation_gen(7, 9);
            import_reverse_only(&mut sessions, &split, &split_node_ha(now_secs), family);
            assert_eq!(sessions.len(), 1, "fixture: only the reverse half ({family:?})");
            sessions
        };
        run_row(&Row {
            name: "reverse half only",
            family,
            setup: &setup,
            forwarding: &owner,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [0, 0, 1],
            reply_mac: Some(CLIENT_MAC),
        });
    }
}

/// RED-ON-BASE. The client's route moves: a /32 (/128) now sends it through a
/// WAN gateway. The reply follows the FIB; the base sent the error out the
/// stored LAN egress to the stored MAC.
#[test]
fn icmp_error_follows_the_reply_after_a_route_move_19164() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    let before = fw1_owner_forwarding();
    for family in [Family::V4, Family::V6] {
        let mut moved = owner_forwarding_with(vec![route(
            family,
            host_prefix(client(family)),
            Some(moved_gateway(family)),
            false,
        )]);
        moved.neighbors.insert(
            (WAN_UNIT_IFINDEX, moved_gateway(family)),
            crate::afxdp::types::NeighborEntry { mac: MOVED_GATEWAY_MAC },
        );
        let setup = || imported_pair(&before, &all_active, family);
        run_row(&Row {
            name: "route move",
            family,
            setup: &setup,
            forwarding: &moved,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [1, 0, 0],
            reply_mac: None,
        });
    }
}

/// RED-ON-BASE. The client's MAC changes (same subnet, same egress). The reply
/// uses the live neighbor; the base sent the error to the stored MAC.
#[test]
fn icmp_error_follows_the_reply_after_a_neighbor_mac_change_19164() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    let before = fw1_owner_forwarding();
    for family in [Family::V4, Family::V6] {
        let mut after = fw1_owner_forwarding();
        after.neighbors.insert(
            (LAN_IFINDEX, client(family)),
            crate::afxdp::types::NeighborEntry { mac: NEW_CLIENT_MAC },
        );
        let setup = || imported_pair(&before, &all_active, family);
        run_row(&Row {
            name: "neighbor MAC change",
            family,
            setup: &setup,
            forwarding: &after,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [0, 0, 1],
            reply_mac: Some(NEW_CLIENT_MAC),
        });
    }
}

/// RED-ON-BASE, and D2 ("HA once"). The operator discards the client's /32
/// (/128). The reply drops: DiscardRoute is not a fabric-rescue disposition
/// for a session reply. The error must drop too. The pre-#19164 finalization
/// redirects a non-fabric DiscardRoute to the peer, so finalizing the reply's
/// verdict a second time would send it over the fabric.
#[test]
fn icmp_error_drops_where_the_reply_drops_on_a_discard_route_19164() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    let before = fw1_owner_forwarding();
    for family in [Family::V4, Family::V6] {
        let discarded =
            owner_forwarding_with(vec![route(family, host_prefix(client(family)), None, true)]);
        let setup = || imported_pair(&before, &all_active, family);
        run_row(&Row {
            name: "discard route",
            family,
            setup: &setup,
            forwarding: &discarded,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: 2,
            reply_tx: [0, 0, 0],
            reply_mac: None,
        });
    }
}

/// The lookup variant of a LOCAL reverse. A priming reply makes the imported
/// reverse local and stamps it in the pass at neighbor generation 1; then the
/// client's route moves.
/// - Stamp stale (the packet's pass is at generation 2): the reply takes the
///   cache-free lookup and follows the move. RED-ON-BASE.
/// - Stamp current (generation 1): the reply's cached fast path serves the
///   stored LAN delivery, and so must the error.
#[test]
fn icmp_error_takes_the_replys_lookup_variant_for_a_local_reverse_19164() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let all_active = owner_ha(now_secs);
    let before = fw1_owner_forwarding();
    for (family, stale) in [
        (Family::V4, true),
        (Family::V4, false),
        (Family::V6, true),
        (Family::V6, false),
    ] {
        let mut moved = owner_forwarding_with(vec![route(
            family,
            host_prefix(client(family)),
            Some(moved_gateway(family)),
            false,
        )]);
        moved.neighbors.insert(
            (WAN_UNIT_IFINDEX, moved_gateway(family)),
            crate::afxdp::types::NeighborEntry { mac: MOVED_GATEWAY_MAC },
        );
        let setup = || {
            let mut sessions = imported_pair(&before, &all_active, family);
            let primed = send(
                &mut sessions,
                &before,
                &all_active,
                Arrival::Wan,
                reply_frame(&before, family, SPORT, Arrival::Wan),
                1,
            );
            assert_eq!(primed.tx, [0, 0, 1], "fixture: the priming reply leaves by the LAN ({family:?})");
            let (_, egress, origin) = stored_reverse(&sessions, &canonical_reverse_key(family, &before));
            assert!(
                !origin.is_peer_synced() && egress == LAN_IFINDEX,
                "fixture: the priming reply made the reverse local on the LAN ({family:?}: {origin:?} {egress})"
            );
            sessions
        };
        run_row(&Row {
            name: if stale { "local reverse, stale stamp" } else { "local reverse, current stamp" },
            family,
            setup: &setup,
            forwarding: &moved,
            ha: &all_active,
            arrival: Arrival::Wan,
            port: SPORT,
            neighbor_generation: if stale { 2 } else { 1 },
            reply_tx: if stale { [1, 0, 0] } else { [0, 0, 1] },
            reply_mac: None,
        });
    }
}
