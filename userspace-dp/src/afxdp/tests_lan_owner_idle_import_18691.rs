// #18691: the LAN-owner node of an RG split must not revoke an IDLE
// peer-owned SNAT flow at its first packet.
//
// Live shape (tcp, `/var/tmp/fz/r-18691-cell.py`; #18683 phase 2): one idle
// LAN->WAN TCP flow with interface SNAT, all RGs moved to node1, then RG1
// (WAN) alone back to node0. node1 keeps RG2 (LAN) and holds the flow only
// as rows sync-imported from node0 after the RG1 move; no packet has touched
// them. The import re-resolves the forward row against node1's split FIB,
// where the RG1 connected prefix (reth0.80) is withheld, so the WAN target
// falls to the default via the WAN gateway VLAN (reth0.50):
// `missing_neighbor` or `forward_candidate egress-if=10 next-hop
// 172.16.50.1` in the live deltas. The peer's own line cannot stand in: it
// names the PEER's ifindexes. The server's first reply comes back over the
// fabric from the WAN owner; its reverse hit ran the #16215 first-hit
// source-NAT revalidation against the forward companion's stored line, and
// the reth0.80 interface translation does not match reth0.50's address, so
// StaleSourceNat revoked the pair (`snat_revoked_sessions_total` equal to
// the FAIL count, 2 of 3 reps on master 19e5a71d55 WITH #18660) and dropped
// the reply. The sender lost one ACK; in #18683 that sender was already
// backed off to a 64 s RTO and lost 120 s.
//
// The cells drive the real poll pipeline (the #18531 harness) on the
// captured fw1 split snapshot with the split FIB's default via reth0.50,
// RG0/RG2 active and RG1 inactive (`split_ha`).
use super::tests_split_rg_failback_18531::*;
use super::tests_support::*;
use super::*;

/// reth0.50 in the captured snapshot: the WAN gateway VLAN.
const WAN_GATEWAY_UNIT_IFINDEX: i32 = 13;
/// An egress/tx pair this node does not have: the peer's numbering, which
/// is what the HA wire carries (`handle_upsert_synced`: "synced sessions
/// arrive with the remote node's interface indices").
const PEER_EGRESS_IFINDEX: i32 = 211;
const PEER_TX_IFINDEX: i32 = 203;

/// How the imported forward row names its egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Numbering {
    /// The peer's ifindexes (live): the #326 standby fallback cannot
    /// revalidate them, so the import keeps the split-FIB line.
    Peer,
    /// This node's ifindexes (fixture shortcut): the fallback validates
    /// and the import keeps the connected reth0.80 line.
    Local,
}

/// Import the pair on `forwarding` under `ha`, as the HA import does.
fn import_pair(
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
    served: bool,
    numbering: Numbering,
    rewrite_src: Option<IpAddr>,
    dst: Option<IpAddr>,
) -> SessionTable {
    let mut forward = exported_forward(forwarding, family);
    if numbering == Numbering::Peer {
        forward.decision.resolution.egress_ifindex = PEER_EGRESS_IFINDEX;
        forward.decision.resolution.tx_ifindex = PEER_TX_IFINDEX;
    }
    if let Some(src) = rewrite_src {
        forward.decision.nat.rewrite_src = Some(src);
    }
    if let Some(dst) = dst {
        forward.key.dst_ip = dst;
        forward.decision.resolution.next_hop = Some(dst);
    }
    if !served {
        forward.fwd_packets = 0;
        forward.rev_packets = 0;
    }
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::default()),
        &forward,
        now_secs,
    )
    .expect("production reverse synthesis must produce the companion");
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    apply_commands(
        &mut sessions,
        forwarding,
        ha,
        vec![
            WorkerCommand::UpsertSynced(forward),
            WorkerCommand::UpsertSynced(reverse),
        ],
    );
    assert_eq!(sessions.len(), 2, "fixture: imported pair ({family:?})");
    sessions
}

/// The LAN owner's import of the live flow.
fn lan_owner_import(family: Family, served: bool) -> (SessionTable, ForwardingState, u64) {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let sessions = import_pair(
        &forwarding,
        &split_ha(now_secs),
        family,
        served,
        Numbering::Peer,
        None,
        None,
    );
    (sessions, forwarding, now_secs)
}

/// The fabric-borne reply: the WAN owner redirects the server's reply to the
/// LAN owner still translated (WAN host -> SNAT address), stamped with the
/// WAN zone.
fn fabric_reply_frame(
    forwarding: &ForwardingState,
    family: Family,
    wan: Option<IpAddr>,
) -> (Vec<u8>, UserspaceDpMeta) {
    let (_, default_wan, snat) = addrs(family);
    let wan = wan.unwrap_or(default_wan);
    let mut frame = match (wan, snat) {
        (IpAddr::V4(w), IpAddr::V4(s)) => {
            build_txn_tcp_syn_frame_v4(w, s, DPORT, SPORT, TCP_ACK, LOCAL_FABRIC_MAC)
        }
        (IpAddr::V6(w), IpAddr::V6(s)) => {
            build_txn_tcp_frame_v6(w, s, DPORT, SPORT, TCP_ACK, LOCAL_FABRIC_MAC)
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
    set_flow(&mut meta, wan, snat, DPORT, SPORT);
    (frame, meta)
}

fn fabric_reply(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
    wan: Option<IpAddr>,
) -> Outcome {
    let (frame, meta) = fabric_reply_frame(forwarding, family, wan);
    drive(sessions, forwarding, ha, FABRIC, &frame, meta, 1)
}

fn stored_forward_line(sessions: &SessionTable, key: &crate::session::SessionKey) -> ForwardingResolution {
    sessions
        .entry_with_origin(key)
        .expect("fixture: imported forward row")
        .0
        .resolution
}

/// Premise (the live 08:29:07 / 10:49:02 deltas): with the peer's numbering
/// the import stores a local line on the WAN gateway VLAN, not the reth0.80
/// egress the translation was minted for and not a fabric redirect. This is
/// the line the reverse hit judged. IPv4 and IPv6.
#[test]
fn lan_owner_idle_import_stores_wan_gateway_line_18691() {
    for family in [Family::V4, Family::V6] {
        let (sessions, forwarding, _) = lan_owner_import(family, false);
        let key = exported_forward(&forwarding, family).key;
        let (_, _, origin) = sessions.entry_with_origin(&key).expect("forward row");
        assert_eq!(origin, SessionOrigin::SyncImport, "{family:?}");
        let line = stored_forward_line(&sessions, &key);
        assert!(
            matches!(
                line.disposition,
                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
            ) && line.egress_ifindex == WAN_GATEWAY_UNIT_IFINDEX,
            "premise: the split FIB answers via the WAN gateway VLAN ({family:?}): {line:?}"
        );
    }
}

/// THE defect cell. The first fabric-borne reply of the idle flow must keep
/// the pair and be delivered to the LAN host. RED on origin/master
/// 7eba89fedd: StaleSourceNat, full-pair teardown, one Close.
#[test]
fn lan_owner_idle_import_first_fabric_reply_keeps_flow_18691() {
    for family in [Family::V4, Family::V6] {
        for served in [false, true] {
            let (mut sessions, forwarding, now_secs) = lan_owner_import(family, served);
            let out = fabric_reply(&mut sessions, &forwarding, &split_ha(now_secs), family, None);
            assert_eq!(
                out.session_hit, 1,
                "the reply must hit the reverse row ({family:?}, served={served})"
            );
            assert_eq!(
                (out.snat_revoked, out.closes, sessions.len()),
                (0, 0, 2),
                "judging the WAN-gateway line revoked a valid translation \
                 ({family:?}, served={served})"
            );
            assert_eq!(
                out.tx,
                [0, 0, 1],
                "the reply is delivered to the LAN host ({family:?}, served={served})"
            );
        }
    }
}

/// The first LAN packet of the idle flow (direct arrival on the LAN owner)
/// must keep the pair and cross the fabric to the WAN owner. GREEN on master
/// as well (the live cell's client data was delivered); pinned so the fix
/// cannot regress it.
#[test]
fn lan_owner_idle_import_first_lan_packet_keeps_flow_18691() {
    for served in [false, true] {
        let (mut sessions, forwarding, now_secs) = lan_owner_import(Family::V4, served);
        let out = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 1);
        assert_eq!(out.session_hit, 1, "the packet must hit the row (served={served})");
        assert_eq!(
            (out.snat_revoked, out.closes, sessions.len()),
            (0, 0, 2),
            "the LAN packet keeps the flow (served={served})"
        );
        assert_eq!(
            out.tx,
            [0, 1, 0],
            "the packet is handed to the WAN owner over the fabric (served={served})"
        );
    }
}

/// Positive control, the owner: an imported flow whose interface translation
/// no longer matches the egress address (the interface was readdressed on
/// the node that forwards it) still revokes, on the first reply and on the
/// first LAN packet. The decline needs the egress RG to be inactive here.
#[test]
fn owner_readdressed_translation_still_revokes_18691() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let readdressed = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99)));
    let mut sessions = import_pair(
        &forwarding,
        &owner_ha(now_secs),
        Family::V4,
        true,
        Numbering::Peer,
        readdressed,
        None,
    );
    let out = lan_ack(&mut sessions, &forwarding, &owner_ha(now_secs), 1);
    assert_eq!(out.session_hit, 1, "the LAN packet must hit the row");
    assert_eq!(
        (out.snat_revoked, sessions.len()),
        (1, 0),
        "the owner revokes a translation no live rule produces"
    );

    let mut sessions = import_pair(
        &forwarding,
        &owner_ha(now_secs),
        Family::V4,
        // No carried traffic: the #16217 established reverse guard must
        // not be what decides this cell.
        false,
        Numbering::Peer,
        readdressed,
        None,
    );
    let (frame, meta) = {
        let wan_mac = [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01];
        let frame = build_txn_tcp_syn_frame_v4(
            WAN_HOST,
            Ipv4Addr::new(172, 16, 80, 99),
            DPORT,
            SPORT,
            TCP_ACK,
            wan_mac,
        );
        let mut meta = txn_meta_v4(WAN_UNIT_IFINDEX as u32, TCP_ACK, frame.len() as u16);
        meta.ingress_vlan_id = 80;
        set_flow(
            &mut meta,
            IpAddr::V4(WAN_HOST),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99)),
            DPORT,
            SPORT,
        );
        (frame, meta)
    };
    let out = drive(&mut sessions, &forwarding, &owner_ha(now_secs), WAN, &frame, meta, 1);
    assert_eq!(out.session_hit, 1, "the WAN reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, sessions.len()),
        (1, 0),
        "the owner revokes on the reply as well"
    );
}

/// Positive control, the LAN owner on the destination's CONNECTED egress:
/// a line that names reth0.80 is judged here even though RG1 is the peer's
/// (the reverse sibling of the #18531 twin), so an invalid translation still
/// revokes on the reply. Twin of the defect cell: same node, same HA view,
/// only the stored line differs.
#[test]
fn lan_owner_connected_line_invalid_translation_still_revokes_18691() {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut sessions = import_pair(
        &forwarding,
        &split_ha(now_secs),
        Family::V4,
        false, // #16217 guard out of the way, as above
        Numbering::Local,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99))),
        None,
    );
    let key = exported_forward(&forwarding, Family::V4).key;
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "premise: with this node's numbering the import keeps reth0.80"
    );
    let (frame, meta) = {
        let mut frame = build_txn_tcp_syn_frame_v4(
            WAN_HOST,
            Ipv4Addr::new(172, 16, 80, 99),
            DPORT,
            SPORT,
            TCP_ACK,
            LOCAL_FABRIC_MAC,
        );
        let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
        let mut meta = txn_meta_v4(FABRIC_IFINDEX as u32, TCP_ACK, frame.len() as u16);
        set_flow(
            &mut meta,
            IpAddr::V4(WAN_HOST),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99)),
            DPORT,
            SPORT,
        );
        (frame, meta)
    };
    let out = drive(&mut sessions, &forwarding, &split_ha(now_secs), FABRIC, &frame, meta, 1);
    assert_eq!(out.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, sessions.len()),
        (1, 0),
        "a connected-egress line is still judged on a non-owner"
    );
}

/// Positive control, a gateway-routed destination: no connected prefix
/// serves it (`DestinationOwner::Unknown`), so the default via reth0.50 IS
/// the owner's egress and the line is judged; an invalid translation still
/// revokes on the reply.
#[test]
fn lan_owner_gateway_routed_destination_still_judged_18691() {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let internet = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let mut sessions = import_pair(
        &forwarding,
        &split_ha(now_secs),
        Family::V4,
        false, // #16217 guard out of the way, as above
        Numbering::Peer,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99))),
        Some(internet),
    );
    let mut key = exported_forward(&forwarding, Family::V4).key;
    key.dst_ip = internet;
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_GATEWAY_UNIT_IFINDEX,
        "premise: the internet destination routes via the WAN gateway VLAN"
    );
    let (frame, meta) = {
        let IpAddr::V4(internet4) = internet else { unreachable!() };
        let mut frame = build_txn_tcp_syn_frame_v4(
            internet4,
            Ipv4Addr::new(172, 16, 80, 99),
            DPORT,
            SPORT,
            TCP_ACK,
            LOCAL_FABRIC_MAC,
        );
        let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
        let mut meta = txn_meta_v4(FABRIC_IFINDEX as u32, TCP_ACK, frame.len() as u16);
        set_flow(
            &mut meta,
            internet,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 99)),
            DPORT,
            SPORT,
        );
        (frame, meta)
    };
    let out = drive(&mut sessions, &forwarding, &split_ha(now_secs), FABRIC, &frame, meta, 1);
    assert_eq!(out.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, sessions.len()),
        (1, 0),
        "an Unknown-owner destination keeps the judgment"
    );
}

/// Review (seat Y): the decline switches off when RG1 activates here, and the
/// stored split-FIB line is healed by `RefreshOwnerRGS` re-resolving it
/// against the activated FIB, which carries reth0.80 again (#16270
/// republishes connected prefixes before `SetRGActive`). The first WAN reply
/// after the refresh is judged on reth0.80 and kept. IPv4 and IPv6.
#[test]
fn activation_refresh_heals_the_line_and_keeps_the_flow_18691() {
    for family in [Family::V4, Family::V6] {
        let (mut sessions, split_forwarding, now_secs) = lan_owner_import(family, false);
        let key = exported_forward(&split_forwarding, family).key;
        assert_eq!(
            stored_forward_line(&sessions, &key).egress_ifindex,
            WAN_GATEWAY_UNIT_IFINDEX,
            "premise: imported under the split FIB ({family:?})"
        );
        let owner_forwarding = fw1_owner_forwarding();
        apply_commands(
            &mut sessions,
            &owner_forwarding,
            &owner_ha(now_secs),
            vec![WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] }],
        );
        let line = stored_forward_line(&sessions, &key);
        assert_eq!(
            line.egress_ifindex, WAN_UNIT_IFINDEX,
            "the refresh re-resolves onto reth0.80 ({family:?}): {line:?}"
        );
        let (frame, meta) = wan_reply_frame_for(family);
        let out = drive(
            &mut sessions,
            &owner_forwarding,
            &owner_ha(now_secs),
            WAN,
            &frame,
            meta,
            1,
        );
        assert_eq!(out.session_hit, 1, "the reply must hit the reverse row ({family:?})");
        assert_eq!(
            (out.snat_revoked, out.closes, sessions.len()),
            (0, 0, 2),
            "the healed line is judged valid ({family:?})"
        );
        assert_eq!(out.tx, [0, 0, 1], "the reply reaches the LAN host ({family:?})");
    }
}

/// Review (seat Y) window, pre-existing on master: the coordinator stores
/// the activated HA state before it queues `RefreshOwnerRGS`, so a worker
/// pass can load the new state, find its queue still empty, and judge a
/// reply against the stale split-FIB line. RG1 is now forwarding-active
/// here, so this decline no longer applies and the line names reth0.50:
/// StaleSourceNat. The window is one RX batch, or longer while a refused
/// refresh waits as transition debt (#9720). Ignored until that issue is
/// fixed; it asserts the behaviour the fix must produce. Un-ignored on
/// 36acce9efb it fails with `(snat_revoked, closes, len) = (1, 1, 0)`.
#[test]
#[ignore = "#18705: a reply between the HA store and RefreshOwnerRGS judges the stale line"]
fn activation_before_refresh_keeps_the_flow_18691() {
    let (mut sessions, _, now_secs) = lan_owner_import(Family::V4, false);
    let owner_forwarding = fw1_owner_forwarding();
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(
        &mut sessions,
        &owner_forwarding,
        &owner_ha(now_secs),
        WAN,
        &frame,
        meta,
        1,
    );
    assert_eq!(out.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "a line the refresh has not reached yet is no ground to revoke"
    );
}
