// #18531: split-RG failback must not revoke an established SNAT flow on the
// node that keeps the LAN RG.
//
// Live shape (loss/tcp `make test-failover`, P8 iperf LAN 10.0.61.102 ->
// 172.16.80.200:5211, interface SNAT to 172.16.80.8): fw0 crashes, fw1 takes
// every RG and PROMOTES the fw0-originated SyncImport rows it serves
// (`SharedPromote`, locally authored). That slow-path hit judges the row's
// source NAT, but data then rides the flow cache, which never re-judges it,
// while every kernel neighbor batch advances the helper-local neighbor
// generation (#16109) the judgment is stamped with, so it reads Stale at the
// next slow-path hit. About a minute after fw0 rejoins, RG1 (WAN) moves back
// to fw0 while RG2 (LAN) stays on fw1.
//
// `update_ha_state` publishes the inactive RG1 BEFORE the workers drain
// `DemoteOwnerRGS`, and the RG epoch bump invalidates the flow cache, so the
// next LAN packet on the serving worker takes the slow path against a row
// that is still `SharedPromote`. The hit re-resolves to `FabricRedirect`
// (egress = the fabric parent) and persists it (#12265 Owner-persist), then
// the source-NAT revalidation judged that stored fabric egress: no egress row
// -> invalid -> StaleSourceNat revocation -> full-pair teardown + a Close the
// daemon syncs to the new WAN owner, which deletes its live copy. The #16215
// FabricRedirect decline that exists for exactly this shape was keyed on the
// row's ORIGIN (peer-synced only), so a locally-authored row fell through.
//
// The cells drive the real poll pipeline on the captured loss-cluster fw1
// snapshot, with the WAN connected routes restored so fw1 is the owner of
// both RGs before the failback (the FIB still holds them in the live window:
// FRR reloads ~300 ms after the demotion).
use super::tests_support::*;
use super::*;

const TCP_ACK: u8 = crate::tcp_flags::TCP_ACK;
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const WAN_HOST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const SNAT_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
const SPORT: u16 = 36552;
const DPORT: u16 = 5211;
/// Captured fw1 snapshot ifindexes: reth1.0 (LAN) = 5, reth0 (WAN parent)
/// = 6, reth0.80 = 14, fabric parent ge-7-0-0 = 4.
const LAN_IFINDEX: i32 = 5;
const WAN_PARENT_IFINDEX: i32 = 6;
const WAN_UNIT_IFINDEX: i32 = 14;
const FABRIC_IFINDEX: i32 = 4;
/// Binding positions in `bindings()`.
const WAN: usize = 0;
const FABRIC: usize = 1;
const LAN: usize = 2;

fn rg(active: bool, now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active,
        watchdog_timestamp: now_secs,
        lease: if active {
            HAGroupRuntime::active_lease_until(now_secs, now_secs)
        } else {
            HAForwardingLease::Inactive
        },
    }
}

/// fw1 owning both RGs (post crash takeover).
fn owner_ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(true, now_secs)),
    ])
}

/// fw1 after the RG1 failback: WAN peer-owned, LAN still local.
fn split_ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(false, now_secs)),
        (2, rg(true, now_secs)),
    ])
}

/// The captured fw1 split snapshot with fw1 restored as the WAN owner: the
/// reth0 units are no longer peer-owned and the WAN connected/default routes
/// replace the cluster-terminal default (what fw1's FIB held while it owned
/// RG1, and still holds in the window before FRR reloads).
fn fw1_owner_forwarding() -> ForwardingState {
    let raw = include_str!("testdata_15742h/snap-split-fw1.json");
    let mut v: serde_json::Value = serde_json::from_str(raw).expect("json");
    let snap = v.get_mut("snapshot").expect("snapshot");
    for iface in snap["interfaces"].as_array_mut().expect("interfaces") {
        if iface["connected_rg_peer_owned"].as_bool() == Some(true) {
            iface["connected_rg_peer_owned"] = serde_json::Value::Bool(false);
        }
    }
    let routes = snap["routes"].as_array_mut().expect("routes");
    routes.retain(|r| !(r["table"] == "inet.0" && r["destination"] == "0.0.0.0/0"));
    for (dst, next_hop) in [
        ("0.0.0.0/0", Some("172.16.50.1")),
        ("172.16.50.0/24", None),
        ("172.16.80.0/24", None),
    ] {
        routes.push(serde_json::json!({
            "table": "inet.0", "family": "inet", "destination": dst,
            "next_hops": next_hop.map(|n| vec![n]).unwrap_or_default(),
            "next_hop_weights": [], "discard": false, "reject": false,
            "cluster_terminal": false, "next_table": "", "rule_priority": 0,
            "preference": if next_hop.is_some() { 5 } else { 0 },
        }));
    }
    let snapshot: crate::ConfigSnapshot =
        serde_json::from_value(snap.clone()).expect("decode fw1 owner snapshot");
    build_forwarding_state(&snapshot)
}

fn forward_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(LAN_HOST),
        dst_ip: IpAddr::V4(WAN_HOST),
        src_port: SPORT,
        dst_port: DPORT,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// The forward row as fw1 (owner of both RGs) exports it: owner RG1 out
/// reth0.80 with interface SNAT to `rewrite_src`, Established.
fn imported_pair_entry(
    forwarding: &ForwardingState,
    key: crate::session::SessionKey,
    rewrite_src: IpAddr,
) -> SyncedSessionEntry {
    let next_hop = key.dst_ip;
    SyncedSessionEntry {
        key,
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: WAN_UNIT_IFINDEX,
                tx_ifindex: WAN_PARENT_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(next_hop),
                neighbor_mac: Some([0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x01]),
                tx_vlan_id: 80,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(rewrite_src),
                ..NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: forwarding.zone_name_to_id["lan"],
            egress_zone: forwarding.zone_name_to_id["wan"],
            ingress_zone_check: 0,
            egress_zone_check: 0,
            // #7095: the import carries THIS node's resolved ingress identity.
            ingress_ifindex: LAN_IFINDEX as u32,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
            // The HA wire carries the admitting NAT scope as a cluster-stable
            // fold that the importer resolves to its own ifindex (reth1.0).
            nat_scope_ifindex: Some(LAN_IFINDEX),
        },
        persistent_lease_hold: None,
        // Interface SNAT mints dynamic provenance; it rides the HA wire.
        source_nat_static: Some(false),
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK,
        generation: 0,
        session_id: (1u64 << 48) | 12,
        tcp_close_class: 0,
        tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(),
        rev_packets: 100,
        fwd_packets: 100,
        pptp_call_ids: 0,
    }
}

/// The fw0-originated established flow as fw1 imported it (SyncImport pair:
/// forward owner RG1 out reth0.80 with interface SNAT, reverse synthesized by
/// production reverse synthesis exactly as the HA import does).
fn imported_pair(forwarding: &ForwardingState, now_ns: u64, rewrite_src: Ipv4Addr) -> SessionTable {
    let now_secs = now_ns / 1_000_000_000;
    let entry = imported_pair_entry(forwarding, forward_key(), IpAddr::V4(rewrite_src));
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        forwarding,
        &owner_ha(now_secs),
        &Arc::new(ShardedNeighborMap::default()),
        &entry,
        now_secs,
    )
    .expect("production reverse synthesis must produce the companion");
    let mut sessions = SessionTable::new();
    for e in [&entry, &reverse] {
        assert!(
            sessions.upsert_synced_with_origin(
                crate::session::SessionInstall {
                    key: e.key.clone(),
                    decision: e.decision,
                    metadata: e.metadata.clone(),
                    source_nat_static: e.source_nat_static,
                    origin: SessionOrigin::SyncImport,
                    now_ns,
                    protocol: PROTO_TCP,
                    tcp_flags: TCP_ACK,
                    session_id: e.session_id,
                    tcp_close_class: 0,
                    tcp_handshake_state: e.tcp_handshake_state,
                    persistent_lease_hold: None,
                    fwd_packets: e.fwd_packets,
                    rev_packets: e.rev_packets,
                },
                false,
            ),
            "fixture: the HA import must install {:?}",
            e.key
        );
    }
    // Same generation the descriptor meta carries (txn_meta_v4: 7 / 9).
    sessions.set_forwarding_revalidation_gen(7, 9);
    sessions
}

/// Fresh bindings per packet: a fresh flow cache stands in for the RG-epoch
/// invalidation that sends the first post-transition packet down the slow
/// path in production.
fn bindings() -> Vec<BindingWorker> {
    let mut wan = BindingWorker::new_for_mirror_test(0, 0, WAN_PARENT_IFINDEX, 0);
    wan.interface = Arc::<str>::from("ge-7-0-2");
    let mut fabric = BindingWorker::new_for_mirror_test(1, 0, FABRIC_IFINDEX, 0);
    fabric.interface = Arc::<str>::from("ge-7-0-0");
    let mut lan = BindingWorker::new_for_mirror_test(2, 0, LAN_IFINDEX, 0);
    lan.interface = Arc::<str>::from("ge-7-0-1");
    vec![wan, fabric, lan]
}

struct Outcome {
    session_hit: u64,
    snat_revoked: u64,
    tx: [u64; 3],
    closes: usize,
    /// Each Close delta's key and NAT decision: what the daemon turns into
    /// the peer's delete of that key and its reverse companion.
    closed: Vec<(crate::session::SessionKey, NatDecision)>,
}

/// Push one descriptor through the production poll pipeline on binding
/// `ingress` in a pass whose helper-local neighbor generation is
/// `neighbor_generation`. Fresh bindings per packet: a fresh flow cache
/// stands in for the RG-epoch invalidation that sends the first
/// post-transition packet down the slow path in production.
fn drive(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    ingress: usize,
    frame: &[u8],
    meta: UserspaceDpMeta,
    neighbor_generation: u64,
) -> Outcome {
    drive_at(
        sessions,
        forwarding,
        ha,
        ingress,
        frame,
        meta,
        7,
        neighbor_generation,
    )
}

/// As `drive`, in a pass at config generation `config_generation` (a commit
/// advances it).
#[expect(clippy::too_many_arguments, reason = "test harness")]
fn drive_at(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    ingress: usize,
    frame: &[u8],
    mut meta: UserspaceDpMeta,
    config_generation: u64,
    neighbor_generation: u64,
) -> Outcome {
    meta.config_generation = config_generation;
    let mut bindings = bindings();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let (_batch, dbg, _egress) = txn_run_multi_binding_at_generations(
        &mut bindings,
        ingress,
        sessions,
        forwarding,
        ha,
        frame,
        meta,
        &shared,
        config_generation,
        neighbor_generation,
    );
    assert_eq!(
        dbg.rx, 1,
        "anti-vacuity: the descriptor must reach the poll body"
    );
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    let closed: Vec<_> = sessions
        .drain_deltas(64)
        .iter()
        .filter(|d| d.kind == crate::session::SessionDeltaKind::Close)
        .map(|d| (d.key.clone(), d.decision.nat))
        .collect();
    Outcome {
        session_hit: dbg.session_hit,
        snat_revoked: dbg.snat_revoked_sessions,
        tx: [
            tx(&bindings[WAN]),
            tx(&bindings[FABRIC]),
            tx(&bindings[LAN]),
        ],
        closes: closed.len(),
        closed,
    }
}

/// One mid-stream LAN -> WAN ACK on the LAN binding.
fn lan_ack(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    neighbor_generation: u64,
) -> Outcome {
    lan_ack_at(sessions, forwarding, ha, 7, neighbor_generation)
}

/// As `lan_ack`, in a pass at config generation `config_generation`.
fn lan_ack_at(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    config_generation: u64,
    neighbor_generation: u64,
) -> Outcome {
    let frame = build_txn_tcp_syn_frame_v4(
        LAN_HOST,
        WAN_HOST,
        SPORT,
        DPORT,
        TCP_ACK,
        [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
    );
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&LAN_HOST.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&WAN_HOST.octets());
    meta.flow_src_port = SPORT;
    meta.flow_dst_port = DPORT;
    drive_at(
        sessions,
        forwarding,
        ha,
        LAN,
        &frame,
        meta,
        config_generation,
        neighbor_generation,
    )
}

fn assert_forward_row_owned_by_rg1(sessions: &SessionTable, when: &str) {
    let (_, metadata, _) = sessions
        .entry_with_origin(&forward_key())
        .unwrap_or_else(|| panic!("forward row present {when}"));
    assert_eq!(
        metadata.owner_rg_id, 1,
        "{when}: the forward row must keep its egress RG (got owner_rg {})",
        metadata.owner_rg_id
    );
    assert!(
        sessions
            .owner_rg_session_keys(&[1])
            .contains(&forward_key()),
        "{when}: the forward row must stay in the RG1 owner index"
    );
}

/// `DemoteOwnerRGS([1])` through the production funnel.
fn demote_rg1(sessions: &mut SessionTable, forwarding: &ForwardingState, now_ns: u64) {
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled = Vec::new();
    let mut cancelled_seen = rustc_hash::FxHashSet::default();
    crate::afxdp::session_glue::handle_demote_owner_rgs_for_test(
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        &split_ha(now_secs),
        &Arc::new(ShardedNeighborMap::default()),
        vec![1],
        now_ns + 1,
        now_secs,
        &mut cancelled,
        &mut cancelled_seen,
    );
}

/// Apply worker commands (peer delete, HA import) through the production
/// dispatcher.
fn apply_commands(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    commands: Vec<WorkerCommand>,
) {
    let queue = Arc::new(Mutex::new(VecDeque::from(commands)));
    crate::afxdp::session_glue::apply_worker_commands(
        &queue,
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::default()),
        0,
        &mut VecDeque::new(),
    );
}

/// fw1 at the RG1 failback instant: the crash-takeover promotion has run, and
/// the inactive RG1 is visible to the packet path before `DemoteOwnerRGS`.
fn promoted_on_owner(forwarding: &ForwardingState, now_ns: u64) -> SessionTable {
    let now_secs = now_ns / 1_000_000_000;
    let mut sessions = imported_pair(forwarding, now_ns, SNAT_IP);
    // Crash takeover: the first LAN packet on the new owner promotes the
    // imported forward row (Owner verdict -> SharedPromote) and forwards it
    // out the WAN. The reverse half is served by another worker in
    // production, so nothing re-stamps this row's source-NAT judgment.
    let takeover = lan_ack(&mut sessions, forwarding, &owner_ha(now_secs), 0);
    assert_eq!(
        takeover.session_hit, 1,
        "takeover packet must hit the import"
    );
    assert_eq!(takeover.tx[WAN], 1, "the owner must forward out the WAN");
    let (_, _, origin) = sessions
        .entry_with_origin(&forward_key())
        .expect("forward row present after takeover");
    assert_eq!(
        origin,
        SessionOrigin::SharedPromote,
        "fixture: the takeover hit must promote the import (the live fw1 shape)"
    );
    assert_eq!(
        sessions.source_nat_revalidated_config_generation(&forward_key()),
        Some(7),
        "fixture: the takeover slow-path hit judged the promoted row's SNAT"
    );
    sessions
}

/// RED on origin/master: the first LAN packet after the RG1 failback is
/// StaleSourceNat-revoked on the node that still owns the LAN RG — the pair
/// is deleted and a Close is emitted (which the daemon syncs to the new WAN
/// owner). The packet must instead ride the fabric to the WAN owner with the
/// session intact.
#[test]
fn split_rg_failback_keeps_promoted_snat_flow_18531() {
    let forwarding = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut sessions = promoted_on_owner(&forwarding, now_ns);
    assert_eq!(sessions.len(), 2, "fixture: forward + reverse rows");

    // Production: the promoted row then rides the flow cache for ~76 s while
    // kernel neighbor batches advance the helper-local neighbor generation
    // (#16109), so its SNAT judgment reads Stale at the next slow-path hit —
    // the first packet after the RG epoch bump. Generation 1 models that.
    let failback = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 1);
    assert_eq!(
        failback.session_hit, 1,
        "the failback packet must hit the session"
    );
    assert_eq!(
        failback.snat_revoked, 0,
        "a FabricRedirect re-resolution carries no local egress to judge the \
         SNAT against; the WAN owner judges it — it must not be revoked here"
    );
    assert_eq!(
        failback.closes, 0,
        "no Close may be emitted: the daemon would sync it to the new WAN owner \
         and delete the owner's live copy"
    );
    assert_eq!(sessions.len(), 2, "both halves must survive the failback");
    assert_eq!(
        failback.tx,
        [0, 1, 0],
        "the LAN packet must be fabric-redirected to the WAN owner (tx wan/fabric/lan)"
    );

    // Witness that the failback hit reached the decline: it persisted the
    // redirect on the still-locally-authored row and left the SNAT judgment
    // unstamped. Without the neighbor-generation bump the hit would neither
    // persist nor judge, and every assertion above would hold on master.
    let (stored, _, origin) = sessions
        .entry_with_origin(&forward_key())
        .expect("forward row present after the failback hit");
    assert_eq!(
        (stored.resolution.disposition, origin),
        (
            ForwardingDisposition::FabricRedirect,
            SessionOrigin::SharedPromote
        ),
        "the failback hit must persist the redirect on the promoted row"
    );
    assert!(
        matches!(
            sessions.source_nat_revalidation_target(&forward_key()),
            crate::session::SourceNatRevalidationTarget::Stale { .. }
        ),
        "the failback hit must have judged and declined, not stamped"
    );
    // The persisted redirect keeps the flow's egress RG (the fabric parent
    // names none), so the row stays in the RG1 index the HA commands walk.
    assert_forward_row_owned_by_rg1(&sessions, "after the failback hit");

    // The demotion command lands afterwards and retags the row.
    demote_rg1(&mut sessions, &forwarding, now_ns);
    let (_, _, origin) = sessions
        .entry_with_origin(&forward_key())
        .expect("forward row present after the demote");
    assert!(
        origin.is_peer_synced(),
        "DemoteOwnerRGS must retag the redirected row (got {origin:?}); a \
         row left locally authored refuses the WAN owner's delete"
    );
    let after = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 2);
    assert_eq!((after.snat_revoked, after.closes), (0, 0));
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        after.tx,
        [0, 1, 0],
        "post-demote packet must still redirect"
    );
}

/// Control: the SAME promoted shape whose translation no longer matches any
/// live rule (172.16.80.99 is not reth0.80's address) is still revoked while
/// it resolves to a REAL local egress. The decline must not turn source-NAT
/// revalidation off for locally-authored rows.
#[test]
fn split_rg_failback_control_stale_snat_on_real_egress_still_revokes_18531() {
    let forwarding = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut sessions = imported_pair(&forwarding, now_ns, Ipv4Addr::new(172, 16, 80, 99));
    let takeover = lan_ack(&mut sessions, &forwarding, &owner_ha(now_secs), 0);
    assert_eq!(takeover.session_hit, 1);
    assert_eq!(
        takeover.snat_revoked, 1,
        "a translation no live rule produces must still revoke on a real egress"
    );
    assert_eq!(sessions.len(), 0, "the revoked pair is torn down");
}

/// Twin of the decline (dataplane seat, #18532): the decline keys on the
/// JUDGED resolution, not the packet's. Here the packet re-resolves to
/// FabricRedirect (RG1 is the peer's) but the row's stored resolution is a
/// real egress, freshly stamped, so nothing persists the redirect and the
/// stored line is what is judged. Its translation (172.16.80.99) is not one
/// any rule produces, so it must revoke. A decline keyed on the packet's
/// FabricRedirect would keep it.
#[test]
fn split_rg_failback_twin_stored_real_egress_invalid_translation_revokes_18531() {
    let forwarding = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut sessions = imported_pair(&forwarding, now_ns, Ipv4Addr::new(172, 16, 80, 99));
    // Stamp the forwarding generation fresh (the HA-transition rewrite does,
    // and clears the SNAT judgment) so the hit does not persist.
    let (decision, metadata, _) = sessions
        .entry_with_origin(&forward_key())
        .expect("fixture: imported forward row");
    assert!(sessions.refresh_for_ha_transition(&forward_key(), decision, metadata, now_ns));
    let out = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 0);
    assert_eq!(out.session_hit, 1, "the packet must hit the row");
    assert_eq!(
        out.snat_revoked, 1,
        "a stored real egress with an invalid translation must revoke even \
         when the packet itself redirects"
    );
    assert_eq!(sessions.len(), 0, "the revoked pair is torn down");
}

// ---------------------------------------------------------------------------
// Review of #18532 (HA/security seat): the WAN owner's revocation must still
// reach the LAN node's redirected row, and the row must be judged on its real
// egress the moment RG1 returns.
// ---------------------------------------------------------------------------

/// The flow's reverse key under its interface SNAT.
fn reverse_key() -> crate::session::SessionKey {
    crate::session::reverse_session_key(
        &forward_key(),
        NatDecision {
            rewrite_src: Some(IpAddr::V4(SNAT_IP)),
            ..NatDecision::default()
        },
    )
}

/// fw1's interface-SNAT rules withdrawn by a commit.
fn withdrawn_owner_forwarding() -> ForwardingState {
    let mut forwarding = fw1_owner_forwarding();
    forwarding.source_nat_rules.clear();
    forwarding
}

/// RED at aaed88773b: the failback hit persisted the redirect with owner RG
/// 0 (the fabric parent has no egress row), dropping the row out of the RG1
/// index. `DemoteOwnerRGS` never retagged it, so it stayed `SharedPromote`,
/// and the WAN owner's revocation Close, which reaches this node as a peer
/// `DeleteSynced`, was refused by the locally-owned guard (#9048/#9714).
/// No node could tear the LAN row down. Both orderings: the delete before
/// and after the demote command lands.
#[test]
fn split_rg_failback_wan_owner_delete_removes_lan_row_18531() {
    let forwarding = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    for demote_first in [false, true] {
        let mut sessions = promoted_on_owner(&forwarding, now_ns);
        let failback = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 1);
        assert_eq!(
            (failback.snat_revoked, failback.tx),
            (0, [0, 1, 0]),
            "fixture: the failback packet redirects (demote_first={demote_first})"
        );
        if demote_first {
            demote_rg1(&mut sessions, &forwarding, now_ns);
        }
        apply_commands(
            &mut sessions,
            &forwarding,
            &split_ha(now_secs),
            vec![
                WorkerCommand::DeleteSynced(forward_key()),
                WorkerCommand::DeleteSynced(reverse_key()),
            ],
        );
        assert_eq!(
            sessions.len(),
            0,
            "the WAN owner's peer delete must remove both halves on the LAN \
             node (demote_first={demote_first})"
        );
    }
}

/// RED at aaed88773b: with the SNAT rule withdrawn and RG1 back on this node
/// at the SAME generation, the stored FabricRedirect declined the judgment
/// while the live resolution sent the withdrawn translation out the WAN.
/// The live, locally-forwarding resolution must be judged whatever the
/// origin, and the RG1 refresh must reach the row. Three orderings: RG1
/// flaps back before `DemoteOwnerRGS` lands (the row is still locally
/// authored), after it, and after `RefreshOwnerRGS([1])` too.
#[test]
fn split_rg_failback_rg_return_revokes_withdrawn_translation_18531() {
    let forwarding = fw1_owner_forwarding();
    let withdrawn = withdrawn_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    for (demoted, refresh_first) in [(false, false), (true, false), (true, true)] {
        let mut sessions = promoted_on_owner(&forwarding, now_ns);
        let failback = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 1);
        assert_eq!(
            failback.tx,
            [0, 1, 0],
            "fixture: the failback packet redirects"
        );
        if demoted {
            demote_rg1(&mut sessions, &forwarding, now_ns);
        }
        if refresh_first {
            crate::afxdp::session_glue::handle_refresh_owner_rgs_for_test(
                &mut sessions,
                crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
                &withdrawn,
                &owner_ha(now_secs),
                &Arc::new(ShardedNeighborMap::default()),
                vec![1],
                now_ns + 2,
                now_secs,
            );
        }
        // Same neighbor generation as the failback hit: nothing re-stores
        // the row on its own.
        let back = lan_ack(&mut sessions, &withdrawn, &owner_ha(now_secs), 1);
        assert_eq!(
            back.tx[WAN], 0,
            "a withdrawn translation must not leave on the WAN \
             (demoted={demoted} refresh_first={refresh_first})"
        );
        assert_eq!(
            back.snat_revoked, 1,
            "the live egress must be judged and the withdrawn translation \
             revoked (demoted={demoted} refresh_first={refresh_first})"
        );
        assert_eq!(sessions.len(), 0, "the revoked pair is torn down");
    }
}

/// The WAN owner's half of the safety argument: the node that owns RG1
/// judges a translated flow redirected to it over the fabric. With the rule
/// intact it forwards out the WAN; with the rule withdrawn it revokes and
/// emits the Close the daemon syncs to the LAN node (whose removal the cell
/// above pins). The daemon-side routing of that Close is the existing
/// owner-RG gate in `shouldSyncUserspaceDelta`, not exercised here.
#[test]
fn wan_owner_revokes_redirected_flow_with_withdrawn_translation_18531() {
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let wan_owner_ha = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    for withdrawn_rule in [false, true] {
        let forwarding = fw1_owner_forwarding();
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        import_on(&mut sessions, &forwarding, &wan_owner_ha, Family::V4);
        assert_eq!(sessions.len(), 2, "fixture: the owner imported the pair");
        let judge = if withdrawn_rule {
            withdrawn_owner_forwarding()
        } else {
            fw1_owner_forwarding()
        };
        let (frame, meta) = fabric_forward_frame(&judge, Family::V4);
        let out = drive(
            &mut sessions,
            &judge,
            &wan_owner_ha,
            FABRIC,
            &frame,
            meta,
            1,
        );
        assert_eq!(
            out.session_hit, 1,
            "the redirected packet must hit the owner's copy"
        );
        if withdrawn_rule {
            assert_eq!(
                (out.snat_revoked, out.closes, out.tx[WAN]),
                (1, 1, 0),
                "the egress owner must revoke a withdrawn translation and emit its Close"
            );
            assert_eq!(sessions.len(), 0);
        } else {
            assert_eq!(
                (out.snat_revoked, out.closes, out.tx[WAN]),
                (0, 0, 1),
                "the egress owner forwards a valid redirected flow out the WAN"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The RG-taking node (fw0 in the live run) in the dual-inactive window: fw1
// has demoted RG1 and fabric-redirects the translated flow, fw0 has not
// activated RG1 yet.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

const LAN_HOST6: Ipv6Addr = Ipv6Addr::new(
    0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
);
const WAN_HOST6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200);
const SNAT_IP6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x8);
/// fw1's fabric link in the captured snapshot.
const LOCAL_FABRIC_MAC: [u8; 6] = [0x10, 0x66, 0x6a, 0x3f, 0x67, 0x60];

fn addrs(family: Family) -> (IpAddr, IpAddr, IpAddr) {
    match family {
        Family::V4 => (
            IpAddr::V4(LAN_HOST),
            IpAddr::V4(WAN_HOST),
            IpAddr::V4(SNAT_IP),
        ),
        Family::V6 => (
            IpAddr::V6(LAN_HOST6),
            IpAddr::V6(WAN_HOST6),
            IpAddr::V6(SNAT_IP6),
        ),
    }
}

/// A node that owns neither RG: the captured split snapshot (reth0 units
/// peer-owned, WAN connected prefixes withheld) carrying the split FIB the
/// integration build installs (#18519): the configured default via the
/// peer-owned WAN gateway on reth0.50 is kept, so the WAN destination
/// resolves to a REAL egress, 13, in RG1. Master's FIB cannot bind a gateway
/// inside a withheld prefix, so the fixture leaves reth0.50's prefix
/// connected to reach the same resolution.
fn rg_taking_node_forwarding() -> ForwardingState {
    let raw = include_str!("testdata_15742h/snap-split-fw1.json");
    let mut v: serde_json::Value = serde_json::from_str(raw).expect("json");
    let snap = v.get_mut("snapshot").expect("snapshot");
    for iface in snap["interfaces"].as_array_mut().expect("interfaces") {
        if iface["ifindex"].as_i64() == Some(13) {
            iface["connected_rg_peer_owned"] = serde_json::Value::Bool(false);
        }
    }
    let routes = snap["routes"].as_array_mut().expect("routes");
    for (table, family, dst, next_hop) in [
        ("inet.0", "inet", "172.16.50.0/24", None),
        ("inet.0", "inet", "0.0.0.0/0", Some("172.16.50.1")),
        ("inet6.0", "inet6", "2001:559:8585:50::/64", None),
        ("inet6.0", "inet6", "::/0", Some("2001:559:8585:50::1")),
    ] {
        routes.push(serde_json::json!({
            "table": table, "family": family, "destination": dst,
            "next_hops": next_hop.map(|n| vec![n]).unwrap_or_default(),
            "next_hop_weights": [], "discard": false, "reject": false,
            "cluster_terminal": false, "next_table": "", "rule_priority": 0,
            "preference": if next_hop.is_some() { 5 } else { 0 },
        }));
    }
    let snapshot: crate::ConfigSnapshot =
        serde_json::from_value(snap.clone()).expect("decode rg-taking snapshot");
    build_forwarding_state(&snapshot)
}

/// The window: the peer has demoted RG1, this node has not activated it,
/// and RG2 (LAN) is the peer's.
fn window_ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([
        (0, rg(false, now_secs)),
        (1, rg(false, now_secs)),
        (2, rg(false, now_secs)),
    ])
}

/// The forward row as fw1 (owner of both RGs) exports it.
fn exported_forward(forwarding: &ForwardingState, family: Family) -> SyncedSessionEntry {
    let (lan, wan, snat) = addrs(family);
    let neighbor_mac = match family {
        Family::V4 => [0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4],
        Family::V6 => [0xf6, 0xf0, 0x06, 0x10, 0x77, 0xd5],
    };
    let mut key = forward_key();
    if family == Family::V6 {
        key.addr_family = libc::AF_INET6 as u8;
    }
    key.src_ip = lan;
    key.dst_ip = wan;
    let mut entry = imported_pair_entry(forwarding, key, snat);
    entry.decision.resolution.next_hop = Some(wan);
    entry.decision.resolution.neighbor_mac = Some(neighbor_mac);
    entry
}

/// Import the exported pair through the production worker dispatcher,
/// with the reverse synthesized the way the HA import does.
fn import_on(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
) {
    import_on_with_service(sessions, forwarding, ha, family, true);
}

/// As `import_on`; `served = false` imports the pair with no admitted
/// packets on the wire, so the #16217 established-with-traffic reverse
/// guard cannot be what holds it.
fn import_on_with_service(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
    served: bool,
) {
    let mut forward = exported_forward(forwarding, family);
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
    apply_commands(
        sessions,
        forwarding,
        ha,
        vec![
            WorkerCommand::UpsertSynced(forward),
            WorkerCommand::UpsertSynced(reverse),
        ],
    );
}

/// fw1's translated forward packet, redirected over the fabric with the
/// LAN zone stamp.
fn fabric_forward_frame(
    forwarding: &ForwardingState,
    family: Family,
) -> (Vec<u8>, UserspaceDpMeta) {
    let (_, wan, snat) = addrs(family);
    let mut frame = match (snat, wan) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            build_txn_tcp_syn_frame_v4(s, d, SPORT, DPORT, TCP_ACK, LOCAL_FABRIC_MAC)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            build_txn_tcp_frame_v6(s, d, SPORT, DPORT, TCP_ACK, LOCAL_FABRIC_MAC)
        }
        _ => unreachable!("one family"),
    };
    let [_, _, hi, lo] = forwarding.zone_name_to_id["lan"].to_be_bytes();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let mut meta = match family {
        Family::V4 => txn_meta_v4(FABRIC_IFINDEX as u32, TCP_ACK, frame.len() as u16),
        Family::V6 => {
            let mut meta = txn_meta_v6(FABRIC_IFINDEX as u32, frame.len());
            meta.tcp_flags = TCP_ACK;
            meta
        }
    };
    set_flow(&mut meta, snat, wan, SPORT, DPORT);
    (frame, meta)
}

fn set_flow(meta: &mut UserspaceDpMeta, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            meta.flow_src_addr[..4].copy_from_slice(&s.octets());
            meta.flow_dst_addr[..4].copy_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            meta.flow_src_addr.copy_from_slice(&s.octets());
            meta.flow_dst_addr.copy_from_slice(&d.octets());
        }
        _ => unreachable!("one family"),
    }
    meta.flow_src_port = sport;
    meta.flow_dst_port = dport;
}

/// RED on master/aaed88773b (and the live failback on integ4): the first
/// redirected packet in the window re-resolves to HAInactive on egress 13
/// (reth0.50, the default via the WAN gateway; reth0.80's prefix is
/// withheld on a node that does not own RG1), persists it, and the SNAT
/// validator judged reth0.50's address against the reth0.80 translation:
/// StaleSourceNat, full-pair teardown, one Close. An ownership transient
/// must hold the session and drop the packet. IPv4 and IPv6.
#[test]
fn rg_taking_node_window_keeps_imported_snat_flow_18531() {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    for family in [Family::V4, Family::V6] {
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        import_on(&mut sessions, &forwarding, &window_ha(now_secs), family);
        assert_eq!(sessions.len(), 2, "fixture: imported pair ({family:?})");
        let (frame, meta) = fabric_forward_frame(&forwarding, family);
        let out = drive(
            &mut sessions,
            &forwarding,
            &window_ha(now_secs),
            FABRIC,
            &frame,
            meta,
            1,
        );
        assert_eq!(
            out.session_hit, 1,
            "the redirected packet must hit ({family:?})"
        );
        let (fwd_decision, _, _) = sessions
            .entry_with_origin(&exported_forward(&forwarding, family).key)
            .unwrap_or_else(|| panic!("the forward row must survive the window ({family:?})"));
        assert_eq!(
            fwd_decision.resolution.disposition,
            ForwardingDisposition::HAInactive,
            "fixture: the hit persisted the HA-inactive resolution ({family:?})"
        );
        assert_eq!(
            (out.snat_revoked, out.closes),
            (0, 0),
            "an RG this node does not own yet is no ground to revoke ({family:?})"
        );
        assert_eq!(sessions.len(), 2, "both halves held ({family:?})");
        assert_eq!(
            out.tx,
            [0, 0, 0],
            "the packet is dropped, not forwarded ({family:?})"
        );
    }
}

/// The reverse direction in the same window: a WAN reply arriving on the
/// RG-taking node judges the forward companion, whose stored resolution
/// the redirected forward packet left HA-inactive. It must hold too.
#[test]
fn rg_taking_node_window_reverse_reply_keeps_flow_18531() {
    // `served = false`: no admitted packets on the wire, so the #16217
    // established-with-traffic reverse guard cannot be what holds the
    // flow (with traffic it independently declines this arm).
    for served in [true, false] {
        reverse_reply_case(served);
    }
}

fn reverse_reply_case(served: bool) {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    import_on_with_service(
        &mut sessions,
        &forwarding,
        &window_ha(now_secs),
        Family::V4,
        served,
    );
    let (frame, meta) = fabric_forward_frame(&forwarding, Family::V4);
    let forward = drive(
        &mut sessions,
        &forwarding,
        &window_ha(now_secs),
        FABRIC,
        &frame,
        meta,
        1,
    );
    assert_eq!(
        (forward.snat_revoked, forward.closes, sessions.len()),
        (0, 0, 2),
        "the forward step must hold the flow (see the forward cell; served={served})"
    );
    let frame = build_txn_tcp_syn_frame_v4(
        WAN_HOST,
        SNAT_IP,
        DPORT,
        SPORT,
        TCP_ACK,
        [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01],
    );
    let mut meta = txn_meta_v4(WAN_UNIT_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    meta.ingress_vlan_id = 80;
    set_flow(
        &mut meta,
        IpAddr::V4(WAN_HOST),
        IpAddr::V4(SNAT_IP),
        DPORT,
        SPORT,
    );
    let reply = drive(
        &mut sessions,
        &forwarding,
        &window_ha(now_secs),
        WAN,
        &frame,
        meta,
        2,
    );
    assert_eq!(reply.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (reply.snat_revoked, reply.closes),
        (0, 0),
        "the reverse arm judges the HA-inactive forward companion: hold \
         (served={served})"
    );
    assert_eq!(sessions.len(), 2, "both halves held (served={served})");
}

// ---------------------------------------------------------------------------
// #18535 item 1: a forward-wire alias (the Go-synthesized row keyed by the
// translated tuple) of a live flow must survive the RG-taking node's window.
// ---------------------------------------------------------------------------

/// The alias row the daemon synthesizes for a fabric-redirect delta
/// (`userspaceForwardWireAliasV4/V6`): the same value, keyed by the
/// translated forward tuple.
fn alias_of(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut alias = entry.clone();
    alias.key.src_ip = entry.decision.nat.rewrite_src.expect("an SNAT row");
    alias
}

/// The RG-taking node holding ONLY the alias of the flow (plus its reverse)
/// — the integ3 trace's shape for 36552 on fw0, and the diag6 shape for the
/// five streams fw0 lost. The reverse is the one the import synthesizes from
/// the alias itself (the canonical row was refused, so it is the only forward
/// row the importer saw): its un-NAT names the SNAT address, not the client.
fn import_alias_only(sessions: &mut SessionTable, forwarding: &ForwardingState, family: Family) {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    import_alias_only_under(sessions, forwarding, &window_ha(now_secs), family);
}

/// As `import_alias_only`, under the HA state `ha` (the import's reverse
/// synthesis resolves against it).
fn import_alias_only_under(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    family: Family,
) {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let alias = alias_of(&exported_forward(forwarding, family));
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::default()),
        &alias,
        now_secs,
    )
    .expect("production reverse synthesis must produce the companion");
    assert_eq!(
        reverse.decision.nat.rewrite_dst,
        Some(alias.key.src_ip),
        "fixture: an alias-synthesized reverse un-NATs to the SNAT address ({family:?})"
    );
    apply_commands(
        sessions,
        forwarding,
        ha,
        vec![
            WorkerCommand::UpsertSynced(reverse),
            WorkerCommand::UpsertSynced(alias),
        ],
    );
}

/// RED at 42a2c81a12: the redirected translated packet hits the alias row
/// directly, `should_keep_synced_hit_transient` holds it transient (RG1 not
/// active yet), and `purge_translated_synced_hit` removed it with no Close.
/// The first packet after RG1 activated then missed, so the flow died. The
/// alias must survive the window and serve the flow once RG1 is active.
/// IPv4 and IPv6.
#[test]
fn rg_taking_node_window_keeps_alias_only_flow_18531() {
    let window_fwd = rg_taking_node_forwarding();
    let owner_fwd = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    // review (dataplane seat): with fw1's captured neighbor table the v4
    // import stores the #326 standby fallback (ForwardCandidate on 14),
    // which validates, so v4 exercised only the purge. With no neighbor
    // (`cold`) the import stores MissingNeighbor on 13 in both families,
    // the disposition the live trace showed, and the stand-in is what keeps
    // v4 too.
    let mut cold_fwd = rg_taking_node_forwarding();
    cold_fwd.neighbors.clear();
    for (family, cold) in [
        (Family::V4, false),
        (Family::V6, false),
        (Family::V4, true),
        (Family::V6, true),
    ] {
        let window_fwd = if cold { &cold_fwd } else { &window_fwd };
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        import_alias_only(&mut sessions, window_fwd, family);
        let alias_key = alias_of(&exported_forward(window_fwd, family)).key;
        assert_eq!(sessions.len(), 2, "fixture: alias + reverse ({family:?} cold={cold})");
        if cold {
            let (stored, _, _) = sessions
                .entry_with_origin(&alias_key)
                .expect("fixture: alias imported");
            assert_eq!(
                (stored.resolution.disposition, stored.resolution.egress_ifindex),
                (ForwardingDisposition::MissingNeighbor, 13),
                "fixture: a cold import stores MissingNeighbor on reth0.50 ({family:?})"
            );
        }
        let (frame, meta) = fabric_forward_frame(window_fwd, family);
        let window = drive(
            &mut sessions,
            window_fwd,
            &window_ha(now_secs),
            FABRIC,
            &frame,
            meta,
            1,
        );
        assert_eq!(
            window.session_hit, 1,
            "the redirected packet hits the alias ({family:?} cold={cold})"
        );
        assert_eq!(window.tx, [0, 0, 0], "dropped in the window ({family:?} cold={cold})");
        assert!(
            sessions.entry_with_origin(&alias_key).is_some(),
            "an ownership transient must not remove the alias of a live flow ({family:?} cold={cold})"
        );
        assert_eq!(
            (window.closes, sessions.len()),
            (0, 2),
            "nothing torn down ({family:?} cold={cold})"
        );
        let (frame, meta) = fabric_forward_frame(&owner_fwd, family);
        let after = drive(
            &mut sessions,
            &owner_fwd,
            &activated,
            FABRIC,
            &frame,
            meta,
            2,
        );
        assert_eq!(
            (after.session_hit, after.tx[WAN]),
            (1, 1),
            "once RG1 is active the alias serves the flow out the WAN ({family:?} cold={cold})"
        );
    }
}

/// Control: the #6599 purge of a translated hit that arrives DIRECTLY on a
/// non-owner (a spoofed or martian translated source on the LAN, not a
/// redirect over the fabric) is unchanged: the alias row goes.
#[test]
fn non_owner_direct_translated_arrival_still_purges_alias_18531() {
    let forwarding = rg_taking_node_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    import_alias_only(&mut sessions, &forwarding, Family::V4);
    let alias_key = alias_of(&exported_forward(&forwarding, Family::V4)).key;
    let frame = build_txn_tcp_syn_frame_v4(
        SNAT_IP,
        WAN_HOST,
        SPORT,
        DPORT,
        TCP_ACK,
        [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
    );
    let mut meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    set_flow(
        &mut meta,
        IpAddr::V4(SNAT_IP),
        IpAddr::V4(WAN_HOST),
        SPORT,
        DPORT,
    );
    let out = drive(
        &mut sessions,
        &forwarding,
        &window_ha(now_secs),
        LAN,
        &frame,
        meta,
        1,
    );
    assert_eq!(
        out.session_hit, 1,
        "the direct packet must hit the alias row"
    );
    assert!(
        sessions.entry_with_origin(&alias_key).is_none(),
        "a direct translated arrival on a non-owner still purges the alias (#6599)"
    );
}

/// A WAN -> LAN reply of the flow on the WAN unit (reth0.80), addressed to
/// the SNAT address.
fn wan_reply_frame() -> (Vec<u8>, UserspaceDpMeta) {
    wan_reply_frame_for(Family::V4)
}

fn wan_reply_frame_for(family: Family) -> (Vec<u8>, UserspaceDpMeta) {
    let (_, wan, snat) = addrs(family);
    let wan_mac = [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01];
    let (frame, mut meta) = match (wan, snat) {
        (IpAddr::V4(w), IpAddr::V4(s)) => {
            let frame = build_txn_tcp_syn_frame_v4(w, s, DPORT, SPORT, TCP_ACK, wan_mac);
            let meta = txn_meta_v4(WAN_UNIT_IFINDEX as u32, TCP_ACK, frame.len() as u16);
            (frame, meta)
        }
        (IpAddr::V6(w), IpAddr::V6(s)) => {
            let frame = build_txn_tcp_frame_v6(w, s, DPORT, SPORT, TCP_ACK, wan_mac);
            let mut meta = txn_meta_v6(WAN_UNIT_IFINDEX as u32, frame.len());
            meta.tcp_flags = TCP_ACK;
            (frame, meta)
        }
        _ => unreachable!("one family"),
    };
    meta.ingress_vlan_id = 80;
    set_flow(&mut meta, wan, snat, DPORT, SPORT);
    (frame, meta)
}

/// Third failback teardown (diag6, tcp): the five streams fw0 lost at the
/// RG1 failback were exactly the five it held only as the alias. The
/// reverse synthesized from the alias un-NATs to the SNAT address, which is
/// local once RG1 is active. RED at e760f5eef5: the activation refresh
/// re-resolved that reverse to LocalDelivery (the trace's `old_disp=
/// FabricRedirect new_disp=LocalDelivery`), and the next WAN reply ran the
/// host-inbound gate, was denied, and tore the pair down (`TERMINAL-DELETE
/// ... disp=LocalDelivery`). The same happens on the session hit when the
/// reply arrives before the refresh lands. The reply must be handed to the
/// peer that holds the canonical row, with nothing torn down. v4 and v6,
/// refresh first and reply first.
#[test]
fn alias_only_owner_reply_is_handed_to_peer_not_host_18531() {
    let window_fwd = rg_taking_node_forwarding();
    let owner_fwd = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    for family in [Family::V4, Family::V6] {
        for refresh_first in [true, false] {
            let mut sessions = SessionTable::new();
            sessions.set_forwarding_revalidation_gen(7, 9);
            import_alias_only(&mut sessions, &window_fwd, family);
            let alias = alias_of(&exported_forward(&window_fwd, family));
            let reverse_key =
                crate::session::reverse_session_key(&alias.key, alias.decision.nat);
            assert!(
                sessions.entry_with_origin(&reverse_key).is_some(),
                "fixture: the alias's reverse is held ({family:?})"
            );
            if refresh_first {
                crate::afxdp::session_glue::handle_refresh_owner_rgs_for_test(
                    &mut sessions,
                    crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
                    &owner_fwd,
                    &activated,
                    &Arc::new(ShardedNeighborMap::default()),
                    vec![1],
                    now_ns + 2,
                    now_secs,
                );
                let (stored, _, _) = sessions
                    .entry_with_origin(&reverse_key)
                    .expect("reverse present after the refresh");
                assert_eq!(
                    stored.resolution.disposition,
                    ForwardingDisposition::FabricRedirect,
                    "the activation refresh must hand the alias's reverse to the peer, \
                     not the host ({family:?})"
                );
            }
            let (frame, meta) = wan_reply_frame_for(family);
            let reply = drive(&mut sessions, &owner_fwd, &activated, WAN, &frame, meta, 2);
            assert_eq!(
                (reply.session_hit, reply.closes, sessions.len()),
                (1, 0, 2),
                "the reply must not tear the flow down ({family:?} refresh_first={refresh_first})"
            );
            assert_eq!(
                reply.tx,
                [0, 1, 0],
                "the reply is handed to the peer over the fabric ({family:?} refresh_first={refresh_first})"
            );
        }
    }
}

/// The synthesis twin: an alias imported AFTER this node activated the
/// egress RG resolves its reverse at import time against a FIB where the
/// SNAT address is already local. RED at e760f5eef5: the import stored
/// LocalDelivery, which the session map publishes for the host. The stored
/// reverse must hand the reply to the peer. v4 and v6.
#[test]
fn alias_reverse_imported_after_activation_is_not_host_bound_18531() {
    let owner_fwd = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    for family in [Family::V4, Family::V6] {
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        import_alias_only_under(&mut sessions, &owner_fwd, &activated, family);
        let alias = alias_of(&exported_forward(&owner_fwd, family));
        let reverse_key = crate::session::reverse_session_key(&alias.key, alias.decision.nat);
        let (stored, _, _) = sessions
            .entry_with_origin(&reverse_key)
            .expect("fixture: the alias's reverse is held");
        assert_eq!(
            stored.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "an alias's reverse imported on the egress owner is handed to the peer ({family:?})"
        );
    }
}

/// The no-bounce branch: a reply that reaches the alias-only owner OVER THE
/// FABRIC is never redirected back to the peer, and is not host-bound
/// either: it is dropped and the pair is held.
#[test]
fn fabric_reply_on_alias_reverse_is_dropped_not_bounced_18531() {
    let window_fwd = rg_taking_node_forwarding();
    let owner_fwd = fw1_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(7, 9);
    import_alias_only(&mut sessions, &window_fwd, Family::V4);
    let mut frame = build_txn_tcp_syn_frame_v4(
        WAN_HOST,
        SNAT_IP,
        DPORT,
        SPORT,
        TCP_ACK,
        LOCAL_FABRIC_MAC,
    );
    let [_, _, hi, lo] = owner_fwd.zone_name_to_id["wan"].to_be_bytes();
    frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    let mut meta = txn_meta_v4(FABRIC_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    set_flow(
        &mut meta,
        IpAddr::V4(WAN_HOST),
        IpAddr::V4(SNAT_IP),
        DPORT,
        SPORT,
    );
    let reply = drive(&mut sessions, &owner_fwd, &activated, FABRIC, &frame, meta, 2);
    assert_eq!(
        (reply.tx, reply.closes, sessions.len()),
        ([0, 0, 0], 0, 2),
        "a fabric-borne reply on an alias's reverse is dropped, never bounced or torn down"
    );
}

/// Control (twin): a reverse whose un-NAT names a GENUINELY local address
/// other than its wire destination (the reply to a flow whose original
/// source is this node's own LAN address) is still host-bound, and the
/// host-inbound gate still denies it and tears the pair down. Only the
/// un-NAT that rewrites nothing is handed to the peer.
#[test]
fn genuine_local_un_nat_reply_is_still_host_gated_18531() {
    let owner_fwd = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(true, now_secs)),
    ]);
    let lan_egress = owner_fwd
        .egress
        .get(&LAN_IFINDEX)
        .expect("fixture: the LAN unit has an egress row");
    for family in [Family::V4, Family::V6] {
        let local = match family {
            Family::V4 => lan_egress.primary_v4.map(IpAddr::V4),
            Family::V6 => lan_egress.primary_v6.map(IpAddr::V6),
        }
        .expect("fixture: the LAN unit has an address");
        let mut canonical = exported_forward(&owner_fwd, family);
        canonical.key.src_ip = local;
        let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &owner_fwd,
            &activated,
            &Arc::new(ShardedNeighborMap::default()),
            &canonical,
            now_secs,
        )
        .expect("production reverse synthesis must produce the companion");
        assert_eq!(
            reverse.decision.nat.rewrite_dst,
            Some(local),
            "fixture: the reverse un-NATs to the local LAN address ({family:?})"
        );
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        apply_commands(
            &mut sessions,
            &owner_fwd,
            &activated,
            vec![
                WorkerCommand::UpsertSynced(canonical),
                WorkerCommand::UpsertSynced(reverse),
            ],
        );
        assert_eq!(sessions.len(), 2, "fixture: pair imported ({family:?})");
        let (frame, meta) = wan_reply_frame_for(family);
        let reply = drive(&mut sessions, &owner_fwd, &activated, WAN, &frame, meta, 2);
        assert_eq!(
            (reply.session_hit, reply.tx, reply.closes, sessions.len()),
            (1, [0, 0, 0], 1, 0),
            "a genuinely host-bound reply is still gated and torn down ({family:?})"
        );
    }
}

/// A coordinator on `forwarding` with no worker registered: a synced import
/// then books no source-NAT allocator (the fixture's interface allocator
/// would refuse the reservation), which is all these cells need.
fn bare_coordinator(forwarding: &ForwardingState) -> crate::afxdp::Coordinator {
    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding.clone());
    coordinator
}

/// Register one worker and return its command queue.
fn register_worker(
    coordinator: &mut crate::afxdp::Coordinator,
) -> Arc<Mutex<VecDeque<WorkerCommand>>> {
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        3,
        crate::afxdp::WorkerRuntimeRecord::for_test(crate::afxdp::WorkerHandle {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            heartbeat: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            commands: worker_commands.clone(),
            session_export_ack: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(
                crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new(),
            ),
        }),
        None,
    );
    worker_commands
}

/// Review N1 (HA seat), production shape. The RG-taking node that holds only
/// the alias (reverse synthesized from the alias, so it cannot know the
/// original source) revokes the flow once RG1 is active and the SNAT rule is
/// withdrawn. Its Close names the translated tuple, and that is all it can
/// name. RED at e760f5eef5: the LAN node's coordinator matched the peer
/// delete on the exact key, so its canonical pair (original tuple) survived
/// and kept applying the withdrawn translation. The peer delete of the
/// translated key must remove the canonical pair and fan the deletes out to
/// the workers. v4 and v6.
#[test]
fn alias_only_owner_revocation_removes_lan_row_18531() {
    let window_fwd = rg_taking_node_forwarding();
    let judge = withdrawn_owner_forwarding();
    let lan_fwd = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let activated = BTreeMap::from([
        (0, rg(true, now_secs)),
        (1, rg(true, now_secs)),
        (2, rg(false, now_secs)),
    ]);
    for family in [Family::V4, Family::V6] {
        let mut owner = SessionTable::new();
        owner.set_forwarding_revalidation_gen(7, 9);
        import_alias_only(&mut owner, &window_fwd, family);
        let (frame, meta) = fabric_forward_frame(&judge, family);
        let revoke = drive(&mut owner, &judge, &activated, FABRIC, &frame, meta, 2);
        assert_eq!(
            (revoke.snat_revoked, owner.len()),
            (1, 0),
            "fixture: the alias-only owner revokes the withdrawn translation ({family:?})"
        );
        let canonical = exported_forward(&lan_fwd, family);
        let canonical_reverse =
            crate::session::reverse_session_key(&canonical.key, canonical.decision.nat);
        assert_eq!(
            revoke.closed.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>(),
            vec![alias_of(&canonical).key],
            "fixture: an alias-only owner can name only the translated tuple ({family:?})"
        );
        // The LAN node's shared authority.
        let mut coordinator = bare_coordinator(&lan_fwd);
        assert_eq!(
            coordinator.upsert_synced_session(canonical.clone()),
            crate::afxdp::SyncedImportOutcome::Applied,
            "fixture: the LAN node holds the canonical pair ({family:?})"
        );
        let worker_commands = register_worker(&mut coordinator);
        assert!(
            coordinator.synced_session_contains(&canonical.key)
                && coordinator.synced_session_contains(&canonical_reverse),
            "fixture: canonical forward and reverse imported ({family:?})"
        );
        // The daemon's peer delete for each Close: the key, peer-marked.
        for (key, _) in &revoke.closed {
            let _ = coordinator.session_domain().delete_synced(
                key.clone(),
                crate::afxdp::SyncedDeleteMode::PEER,
                false,
            );
        }
        assert_eq!(
            (
                coordinator.synced_session_contains(&canonical.key),
                coordinator.synced_session_contains(&canonical_reverse),
            ),
            (false, false),
            "the alias-only owner's revocation must remove the LAN node's canonical pair ({family:?})"
        );
        let fanned_out = worker_commands
            .lock()
            .unwrap()
            .iter()
            .any(|command| matches!(command, WorkerCommand::DeleteSynced(key) if *key == canonical.key));
        assert!(
            fanned_out,
            "the canonical delete reaches the workers ({family:?})"
        );
    }
}

/// Guard of the N1 resolution: a peer delete of a key this node HOLDS is
/// never widened to the canonical row (Go's #6368 stale-epoch rollback
/// deletes a key whose install landed). Here the node holds both the alias
/// and the canonical row; deleting the alias leaves the canonical row.
#[test]
fn held_key_peer_delete_is_not_widened_to_canonical_18531() {
    let lan_fwd = fw1_owner_forwarding();
    let canonical = exported_forward(&lan_fwd, Family::V4);
    let alias = alias_of(&canonical);
    let coordinator = bare_coordinator(&lan_fwd);
    assert_eq!(
        coordinator.upsert_synced_session(canonical.clone()),
        crate::afxdp::SyncedImportOutcome::Applied,
        "fixture: canonical imported"
    );
    // Hold the alias key as a row of its own (published directly: the
    // import would refuse a second row for the same translation).
    crate::afxdp::shared_ops::publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &alias,
    );
    assert!(
        coordinator.synced_session_contains(&alias.key),
        "fixture: alias held"
    );
    let _ = coordinator.session_domain().delete_synced(
        alias.key.clone(),
        crate::afxdp::SyncedDeleteMode::PEER,
        false,
    );
    assert!(
        !coordinator.synced_session_contains(&alias.key)
            && coordinator.synced_session_contains(&canonical.key),
        "a peer delete of a held key removes that key only, never the canonical row"
    );
}

/// Review N2 (HA seat), a bounded window pinned rather than closed. When RG1
/// returns to the LAN node with the SNAT rule withdrawn by a commit (config
/// epoch 8), a WAN reply that arrives before any forward packet judges the
/// forward row's STORED FabricRedirect, which declines: the reply is un-NATed
/// and delivered. Reverse hits never substitute the reply's own resolution
/// (it is the LAN egress). `RefreshOwnerRGS([1])` rewrites the stored line
/// to the real egress but, like every HA identity rewrite, clears the row's
/// source-NAT judgment, and the #16217 guard declines reverse revocation of
/// an unjudged row with no forward VLAN provenance: the reply after the
/// refresh is still delivered. The window closes at the first forward
/// slow-path hit, which judges the real egress and revokes the pair.
#[test]
fn rg_return_reply_first_window_closes_at_forward_hit_18531() {
    let forwarding = fw1_owner_forwarding();
    let withdrawn = withdrawn_owner_forwarding();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    for demoted in [false, true] {
        let mut sessions = promoted_on_owner(&forwarding, now_ns);
        let failback = lan_ack(&mut sessions, &forwarding, &split_ha(now_secs), 1);
        assert_eq!(
            (failback.snat_revoked, failback.tx),
            (0, [0, 1, 0]),
            "fixture: the failback packet redirects (demoted={demoted})"
        );
        if demoted {
            demote_rg1(&mut sessions, &forwarding, now_ns);
        }
        let reply = |sessions: &mut SessionTable| {
            let (frame, meta) = wan_reply_frame();
            drive_at(
                sessions,
                &withdrawn,
                &owner_ha(now_secs),
                WAN,
                &frame,
                meta,
                8,
                1,
            )
        };
        let first = reply(&mut sessions);
        assert_eq!(
            (first.snat_revoked, first.tx),
            (0, [0, 0, 1]),
            "the window: a reply before any forward packet is delivered (demoted={demoted})"
        );
        crate::afxdp::session_glue::handle_refresh_owner_rgs_for_test(
            &mut sessions,
            crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
            &withdrawn,
            &owner_ha(now_secs),
            &Arc::new(ShardedNeighborMap::default()),
            vec![1],
            now_ns + 2,
            now_secs,
        );
        let (stored, _, _) = sessions
            .entry_with_origin(&forward_key())
            .expect("forward row present after the refresh");
        assert_eq!(
            (stored.resolution.disposition, stored.resolution.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, WAN_UNIT_IFINDEX),
            "fixture: the refresh rewrites the stored line to the WAN unit (demoted={demoted})"
        );
        // #18531 (third teardown, the LAN node): fw1's own reverse un-NATs to
        // the client, so an RG change never re-resolves it onto a local
        // address.
        let (reverse_stored, _, _) = sessions
            .entry_with_origin(&reverse_key())
            .expect("reverse row present after the refresh");
        assert_ne!(
            reverse_stored.resolution.disposition,
            ForwardingDisposition::LocalDelivery,
            "the LAN node's own reverse row is never host-bound (demoted={demoted})"
        );
        let second = reply(&mut sessions);
        assert_eq!(
            (second.snat_revoked, second.tx),
            (0, [0, 0, 1]),
            "the refresh does not close the reverse window: the row is unjudged \
             (demoted={demoted})"
        );
        let forward = lan_ack_at(&mut sessions, &withdrawn, &owner_ha(now_secs), 8, 1);
        assert_eq!(
            (forward.snat_revoked, forward.tx[WAN]),
            (1, 0),
            "the first forward slow-path hit judges the real egress and revokes \
             (demoted={demoted})"
        );
        let last = reply(&mut sessions);
        assert_eq!(
            (last.session_hit, last.tx[LAN]),
            (0, 0),
            "after the revocation the reply has no session (demoted={demoted})"
        );
    }
}
