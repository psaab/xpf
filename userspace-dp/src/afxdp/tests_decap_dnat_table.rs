// decapsulated missing-neighbor handling and replay filtering.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};

/// #1902: VLAN-tagged underlay (the live reth0.80 shape, #1885
/// parity) — the buffered outer frame's L3 sits at 18 while the inner
/// meta says 14, so the pre-fix retry rewrote the dot1q tail.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_tagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(80);
}

/// #1902: untagged underlay — `outer_frame[14..]` IS the outer L3
/// header (valid version nibble), so the pre-fix retry TXed the
/// still-encapsulated OUTER GRE packet toward the INNER next-hop.
/// Byte-indistinguishable from a valid frame at retry time, which is
/// why the fix gates ADMISSION rather than detecting at retry.
#[test]
fn txn_decapped_missing_neighbor_not_buffered_untagged() {
    assert_decapped_missing_neighbor_never_buffered_or_retried(0);
}

/// #1902 regression pin for the UNCHANGED path: a NON-decapped packet
/// (desc and meta describe the same UMEM frame) with a cold neighbor
/// must still buffer in pending_neigh, and after resolution the retry
/// must TX the correctly rewritten ORIGINAL packet (resolved dst MAC,
/// egress src MAC, TTL-1, IP/L4 bytes otherwise identical).
#[test]
fn txn_non_decap_missing_neighbor_buffers_and_retries_correctly() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 24, 0)];
    bindings[0].interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // LAN hairpin: 10.0.61.102 -> 10.0.61.50, directly connected on
    // reth1.0 (egress == ingress binding), neighbor cold.
    let dst = Ipv4Addr::new(10, 0, 61, 50);
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let frame = build_txn_tcp_syn_frame_v4(
        src,
        dst,
        12345,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&src.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_eq!(dbg.missing_neigh, 1, "cold neighbor -> MissingNeighbor arm");
    assert_eq!(
        bindings[0].pending_neigh.len(),
        1,
        "a non-decapped cold-neighbor packet must still buffer"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_decap_drops
            .load(Ordering::Relaxed),
        0,
        "the decap gate must not touch UMEM-paired packets"
    );

    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    forwarding
        .neighbors
        .insert((24, IpAddr::V4(dst)), NeighborEntry { mac });
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    let recent_exceptions = std::sync::Arc::new(std::sync::Mutex::new(
        crate::afxdp::ExceptionEventRing::new(),
    ));
    let mut debug_counters = crate::afxdp::DebugPollCounters::default();
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: same single-threaded umem-area contract as above.
        unsafe { &*area },
        &mut shared_recycles,
        None,
        &mut BatchCounters::default(),
        &recent_exceptions,
        &mut debug_counters,
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "entry consumed by retry"
    );
    let req = bindings[0]
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("resolved retry must produce a prepared TX");
    let rewritten = bindings[0]
        .umem
        .area()
        .slice(req.offset as usize, req.len as usize)
        .expect("rewritten frame")
        .to_vec();
    assert_eq!(
        &rewritten[0..6],
        &mac,
        "dst MAC must be the resolved neighbor"
    );
    assert_eq!(
        &rewritten[6..12],
        &[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        "src MAC must be the reth1.0 egress interface MAC"
    );
    assert_eq!(
        rewritten.len(),
        frame.len(),
        "no length change on a plain forward"
    );
    assert_eq!(rewritten[22], 63, "TTL decremented exactly once (64 -> 63)");
    assert_eq!(
        &rewritten[26..34],
        &frame[26..34],
        "IP src+dst must be byte-identical to the original packet"
    );
    assert_eq!(
        &rewritten[34..],
        &frame[34..],
        "L4 segment must be byte-identical to the original packet"
    );
}

/// #1873 replay-filter companion pin (AGY code r4 HIGH): filtering the
/// preserved synced-session replay list by purged tunnel ids must
/// mirror delete_synced_session's companion semantics — the derived
/// reverse companion (tunnel_endpoint_id == 0) of a dropped forward
/// entry is dropped too, never resurrected as a half-dead pair; a
/// reverse-marked entry drops standalone; unrelated entries survive.
#[test]
fn replay_filter_drops_purged_forward_and_derived_reverse_companion() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse_key = crate::session::reverse_session_key(&forward_key, nat);
    let tunnel_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id: 824,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let plain_resolution = ForwardingResolution {
        tunnel_endpoint_id: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
        ..tunnel_resolution
    };
    let make =
        |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| SyncedSessionEntry {
            key: key.clone(),
        decision: SessionDecision {
            resolution,
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
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
        },
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            rev_packets: 0u64,
            fwd_packets: 0,
            pptp_call_ids: 0,
            persistent_lease_hold: None,
            source_nat_static: None,
        };
    let unrelated_key = SessionKey {
        src_port: 23456,
        ..forward_key.clone()
    };

    // Case 1: tunnel-marked forward + unmarked derived reverse
    // companion + unrelated unmarked entry.
    let mut entries = vec![
        make(&forward_key, tunnel_resolution, false),
        make(&reverse_key, plain_resolution, true),
        make(&unrelated_key, plain_resolution, false),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824], &ForwardingState::default());
    assert_eq!(entries.len(), 1, "forward + derived reverse both dropped");
    assert_eq!(entries[0].key, unrelated_key);

    // Case 2: reverse-marked tunnel entry drops standalone; its
    // unmarked forward keeps forwarding (matches live purge
    // semantics: delete_synced_session on a reverse key derives no
    // companion).
    let mut entries = vec![
        make(&forward_key, plain_resolution, false),
        make(&reverse_key, tunnel_resolution, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824], &ForwardingState::default());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, forward_key);

    // Case 3: no purged ids — untouched.
    let mut entries = vec![make(&forward_key, tunnel_resolution, false)];
    filter_replayed_synced_sessions(&mut entries, &[7], &ForwardingState::default());
    assert_eq!(entries.len(), 1);
}

/// #4975 membership-index pin: the drop set is a HashSet, but the retain
/// must stay behavior-identical to the prior `Vec::contains` scan — it
/// tests membership only, never reorders or over-drops. This exercises a
/// many-drop-keys set interleaved with survivors so a broken membership
/// index (wrong key type, a collision-prone hashable projection that
/// collapses distinct keys, or a survivor accidentally swept) is caught:
///   * survivors are returned in ORIGINAL order (retain is in-place);
///   * a survivor that shares src_ip/dst_ip/proto/family with a dropped
///     forward key and differs ONLY in src_port MUST survive — a
///     projection keyed on anything less than the whole SessionKey would
///     wrongly drop it;
///   * a derived reverse companion entry (present in the fixture with
///     tunnel-id 0, so NOT purged on its own) is swept because its parent
///     forward's purge inserts the derived reverse key, and a
///     reverse-marked purged entry drops standalone (asymmetry preserved).
/// INVARIANT PIN (not a diff-revert failure — Vec<->HashSet is
/// behavior-identical, so reverting THIS commit leaves the test green): a
/// lossy membership projection that collapses distinct keys, or a retain
/// that reorders, fails the ordered-survivor assertion. Validated against
/// the real optimization by manual fail-injection into the retain
/// predicate (see _Log.md), which goes RED here.
#[test]
fn replay_filter_preserves_order_and_survivors_across_many_drops() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let base = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 10000,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let key_at = |src_port: u16| SessionKey {
        src_port,
        ..base.clone()
    };
    let tunnel_resolution = |id: u16| ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id: id,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let make =
        |key: &SessionKey, resolution: ForwardingResolution, is_reverse: bool| SyncedSessionEntry {
            key: key.clone(),
        decision: SessionDecision {
            resolution,
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
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
        },
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            rev_packets: 0u64,
            fwd_packets: 0,
            pptp_call_ids: 0,
            persistent_lease_hold: None,
            source_nat_static: None,
        };

    // Purge ids 100..=131 (a large drop set). Build many purged forward
    // entries interleaved with survivors. One survivor (`survivor_shares_ip`)
    // shares every field of a purged forward except src_port — a lossy index
    // would wrongly sweep it. A derived reverse companion entry (below) that
    // is NOT itself purged must still drop, swept by its forward's purge.
    let purge_ids: Vec<u16> = (100u16..=131).collect();
    // The derived reverse companion of the FIRST purged forward
    // (src_port 40000). It carries tunnel-id 0, so it is never purged on its
    // own — it must drop ONLY because the forward's purge inserts this
    // reverse key into the drop set (the companion-derivation semantic the
    // sibling test pins at unit scale; here it must hold amid many drops).
    let derived_companion = crate::session::reverse_session_key(&key_at(40000), nat);
    let survivor_shares_ip = key_at(20000); // distinct src_port, not purged
    let survivor_other = SessionKey {
        src_port: 30000,
        dst_port: 443,
        ..base.clone()
    };

    let mut entries: Vec<SyncedSessionEntry> = Vec::new();
    let mut expected_survivors: Vec<SessionKey> = Vec::new();

    // A leading survivor to pin that position 0 is retained.
    entries.push(make(&survivor_other, tunnel_resolution(0), false));
    expected_survivors.push(survivor_other.clone());

    for (i, &id) in purge_ids.iter().enumerate() {
        // Each purged forward uses a unique src_port so its derived
        // reverse companion is unique too.
        let fk = key_at(40000 + i as u16);
        entries.push(make(&fk, tunnel_resolution(id), false));
        // Interleave the derived reverse companion of the first purged
        // forward early. tunnel-id 0 → not purged on its own; it must drop
        // solely via the forward's inserted reverse key. NOT a survivor.
        if i == 1 {
            entries.push(make(&derived_companion, tunnel_resolution(0), true));
        }
        // Interleave the shared-IP survivor exactly once, mid-stream.
        if i == purge_ids.len() / 2 {
            entries.push(make(&survivor_shares_ip, tunnel_resolution(0), false));
            expected_survivors.push(survivor_shares_ip.clone());
        }
    }

    // A reverse-marked purged entry (drops standalone; no companion added).
    let reverse_only = SessionKey {
        src_port: 55000,
        ..base.clone()
    };
    entries.push(make(&reverse_only, tunnel_resolution(131), true));

    // A trailing survivor to pin the last position is retained.
    let survivor_tail = SessionKey {
        src_port: 60000,
        ..base.clone()
    };
    entries.push(make(&survivor_tail, tunnel_resolution(0), false));
    expected_survivors.push(survivor_tail.clone());

    filter_replayed_synced_sessions(&mut entries, &purge_ids, &ForwardingState::default());

    let got: Vec<SessionKey> = entries.iter().map(|e| e.key.clone()).collect();
    assert_eq!(
        got, expected_survivors,
        "survivors must be exactly the non-purged entries, in original order"
    );
    // The shared-IP survivor differs from purged forwards only in src_port
    // — an index keyed on less than the whole SessionKey would drop it.
    assert!(
        got.contains(&survivor_shares_ip),
        "survivor sharing src_ip/dst_ip/proto with purged keys must not be swept"
    );
    // The derived reverse companion (tunnel-id 0, never purged on its own)
    // must be swept by its forward's purge — the companion-derivation
    // semantic, exercised amid many drops.
    assert!(
        !got.contains(&derived_companion),
        "derived reverse companion of a purged forward must be dropped"
    );
}

/// #10612 T5: the coordinator replay filter drops stale-zone forwards
/// (plus their derived reverse companions by key) while tunnel-purge
/// semantics stay byte-identical and live-zone entries survive — with
/// the fence ENABLED (validated set), which the pre-existing cells do
/// not cover (they pass an unvalidated default).
///
/// RED-on-revert: removing the zone clause from
/// `filter_replayed_synced_sessions` leaves the stale pair in the replay vec.
///
/// #17229 deleted this doc comment and the `#[test]` attribute along with
/// the dead dnat_table cells above it, so the cell stopped running.
#[test]
fn replay_filter_drops_stale_zone_pair_and_keeps_tunnel_semantics_10612() {
    use crate::afxdp::coordinator::filter_replayed_synced_sessions;

    let nat = NatDecision::default();
    let mut seq = 0u16;
    let mut fresh_key = || {
        seq += 1;
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 30000 + seq,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
        }
    };
    let resolution = |tunnel_endpoint_id| ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 41,
        tx_ifindex: 3,
        tunnel_endpoint_id,
        next_hop: None,
        neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
        src_mac: Some([2, 0, 0, 0, 0, 1]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let make = |key: &SessionKey,
                tunnel_endpoint_id: u16,
                ingress_zone: u32,
                egress_zone: u32,
                is_reverse: bool| SyncedSessionEntry {
        key: key.clone(),
                decision: SessionDecision {
                    resolution: resolution(tunnel_endpoint_id),
                    nat,
                    install_table_domain: 0,
                    install_table_check: 0,
                },
                metadata: SessionMetadata {
                    ingress_zone,
                    egress_zone,
                    ingress_zone_check: 0,
                    egress_zone_check: 0,
                    ingress_ifindex: 0,
                    ingress_vlan_id: 0,
                    forward_ingress_vlan_id: None,
                    owner_rg_id: 1,
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
                },
                leak_incarnation: 0,
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                generation: 0,
                session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0u64,
        fwd_packets: 0,
        pptp_call_ids: 0,
            persistent_lease_hold: None,
        source_nat_static: None,
    };

    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_set_validated = true;

    // Stale forward + derived reverse companion drop; live pair survives.
    let stale_forward = fresh_key();
    let stale_reverse = crate::session::reverse_session_key(&stale_forward, nat);
    let live_forward = fresh_key();
    let live_reverse = crate::session::reverse_session_key(&live_forward, nat);
    let mut entries = vec![
        make(&stale_forward, 0, 9, 10, false),
        make(&stale_reverse, 0, 9, 10, true),
        make(&live_forward, 0, 1, 2, false),
        make(&live_reverse, 0, 1, 2, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[], &forwarding);
    let got: Vec<SessionKey> = entries.iter().map(|e| e.key.clone()).collect();
    assert_eq!(
        got,
        vec![live_forward.clone(), live_reverse.clone()],
        "stale-zone pair drops, live-zone pair survives, order preserved"
    );

    // Tunnel-purge semantics unchanged with the fence enabled: a
    // tunnel-marked live-zone entry still drops by tunnel id.
    let mut entries = vec![
        make(&live_forward, 824, 1, 2, false),
        make(&live_reverse, 0, 1, 2, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[824], &forwarding);
    assert!(
        entries.is_empty(),
        "tunnel purge must still drop the forward and its derived companion"
    );

    // Fail-open: an unvalidated set admits the stale pair.
    let mut entries = vec![
        make(&stale_forward, 0, 9, 10, false),
        make(&stale_reverse, 0, 9, 10, true),
    ];
    filter_replayed_synced_sessions(&mut entries, &[], &ForwardingState::default());
    assert_eq!(
        entries.len(),
        2,
        "unvalidated forwarding must admit (fail-open)"
    );

    // Reverse-alone (10619/m3): a lone stale reverse (no forward in the vec
    // for companion-key derivation) drops by its own zone membership now
    // that the predicate judges reverses (no is_reverse exemption).
    let mut entries = vec![make(&stale_reverse, 0, 9, 10, true)];
    filter_replayed_synced_sessions(&mut entries, &[], &forwarding);
    assert!(
        entries.is_empty(),
        "a lone stale reverse must drop by zone membership, not linger"
    );
}
