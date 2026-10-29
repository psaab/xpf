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

/// The fw0-originated established flow as fw1 imported it (SyncImport pair:
/// forward owner RG1 out reth0.80 with interface SNAT, reverse synthesized by
/// production reverse synthesis exactly as the HA import does).
fn imported_pair(forwarding: &ForwardingState, now_ns: u64, rewrite_src: Ipv4Addr) -> SessionTable {
    let now_secs = now_ns / 1_000_000_000;
    let entry = SyncedSessionEntry {
        key: forward_key(),
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: WAN_UNIT_IFINDEX,
                tx_ifindex: WAN_PARENT_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(WAN_HOST)),
                neighbor_mac: Some([0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x01]),
                tx_vlan_id: 80,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(rewrite_src)),
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
            nat_scope_ifindex: None,
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
    };
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
}

/// One mid-stream LAN -> WAN ACK on the LAN binding, processed in a pass
/// whose helper-local neighbor generation is `neighbor_generation`.
fn lan_ack(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
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
    let mut bindings = bindings();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let (_batch, dbg, _egress) = txn_run_multi_binding_at_neighbor_generation(
        &mut bindings,
        LAN,
        sessions,
        forwarding,
        ha,
        &frame,
        meta,
        &shared,
        neighbor_generation,
    );
    assert_eq!(
        dbg.rx, 1,
        "anti-vacuity: the descriptor must reach the poll body"
    );
    let tx = |b: &BindingWorker| b.live.tx_packets.load(std::sync::atomic::Ordering::Relaxed);
    Outcome {
        session_hit: dbg.session_hit,
        snat_revoked: dbg.snat_revoked_sessions,
        tx: [
            tx(&bindings[WAN]),
            tx(&bindings[FABRIC]),
            tx(&bindings[LAN]),
        ],
        closes: sessions
            .drain_deltas(64)
            .iter()
            .filter(|d| d.kind == crate::session::SessionDeltaKind::Close)
            .count(),
    }
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

    // The demotion command lands afterwards; the row keeps redirecting.
    let mut cancelled = Vec::new();
    let mut cancelled_seen = rustc_hash::FxHashSet::default();
    crate::afxdp::session_glue::handle_demote_owner_rgs_for_test(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &split_ha(now_secs),
        &Arc::new(ShardedNeighborMap::default()),
        vec![1],
        now_ns + 1,
        now_secs,
        &mut cancelled,
        &mut cancelled_seen,
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
    let first = if takeover.snat_revoked == 1 {
        takeover
    } else {
        // Promotion may consume the first hit; the next owner hit judges.
        lan_ack(&mut sessions, &forwarding, &owner_ha(now_secs), 1)
    };
    assert_eq!(
        first.snat_revoked, 1,
        "a translation no live rule produces must still revoke on a real egress"
    );
    assert_eq!(sessions.len(), 0, "the revoked pair is torn down");
}
