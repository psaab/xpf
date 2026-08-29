// NAT64 translation/exhaustion accounting and tunnel-gate delivery.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
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
use super::tests_support::*;

// I14: a NAT64 flow refused at cap is dropped like any other refused
// flow — one translated packet must NOT leak out, nothing installs,
// nothing caches (the NAT64 v4-source pick is a stateless round-robin
// with no reservation, so there is nothing to roll back — plan §4 I14).
#[test]
fn txn_nat64_refusal_at_cap_drops_translated_packet() {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(0);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.tx, 0,
        "a refused NAT64 flow must not forward its translated trigger packet"
    );
    assert_eq!(sessions.len(), 0);
    assert_eq!(sessions.admission_refused(), 1);
    assert_eq!(txn_flow_cache_entries(&binding), 0);
    assert_eq!(batch.session_creates, 0);

    // Below cap the same flow is admitted — sanity that the fixture
    // actually exercises the NAT64 install path (forward + reverse).
    sessions.set_max_sessions_for_test(16);
    let meta2 = UserspaceDpMeta { ..meta };
    let (batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    assert_eq!(
        sessions.len(),
        2,
        "NAT64 forward + reverse install below cap"
    );
    assert_eq!(batch2.session_creates, 2);
    assert_eq!(dbg2.tx, 1);
}


// #2161: a successful NAT64 forward translation (v6 client SYN -> v4) must
// bump the per-binding nat64_translations counter, and the matching v4
// reply (v4 server -> v6 client, reverse session hit) must bump it again.
// The counter previously stayed 0 even though the translated packets flowed
// on the wire (observability gap caught in the #2132 NAT smoke). A refused
// flow (table at cap, packet dropped) must NOT bump it.
#[test]
fn txn_nat64_translation_bumps_counter_both_directions() {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }];
    // The reverse v4->v6 reply forwards back to the v6 client on reth1.0;
    // seed its neighbor so the reverse resolution is a usable ForwardCandidate
    // (otherwise the reply would stall on MissingNeighbor and never reach the
    // forward-candidate counting site — a fixture gap, not a code gap).
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet6".to_string(),
        ip: "2001:559:8585:ef00::102".to_string(),
        mac: "02:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Refused-at-cap case first: the translated trigger is dropped, so the
    // counter must stay 0 (counting happens only on the admitted forward).
    sessions.set_max_sessions_for_test(0);
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let fwd_frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let fwd_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: fwd_frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let (refused_batch, refused_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &fwd_frame,
        fwd_meta,
    );
    assert_eq!(refused_dbg.tx, 0, "refused NAT64 flow must not forward");
    assert_eq!(
        refused_batch.nat64_translations, 0,
        "a dropped NAT64 trigger must not increment the translations counter"
    );

    // Below cap: the forward v6->v4 translation is admitted and counted once.
    sessions.set_max_sessions_for_test(16);
    let (fwd_batch, fwd_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &fwd_frame,
        UserspaceDpMeta { ..fwd_meta },
    );
    assert_eq!(
        fwd_dbg.tx, 1,
        "admitted NAT64 forward must translate + forward"
    );
    assert_eq!(sessions.len(), 2, "NAT64 forward + reverse install");
    assert_eq!(
        fwd_batch.nat64_translations, 1,
        "the admitted v6->v4 translation must bump the counter exactly once"
    );

    // Reverse: the v4 server reply hits the reverse session and translates
    // v4->v6, bumping the counter again.
    //
    // #4381: the forward flow's source port is now TRANSLATED to a UNIQUE pool
    // port (RFC 6146 BIB) instead of being preserved, so the server replies to
    // the TRANSLATED port and the reverse session keys on it. Discover the
    // translated port from the installed reverse (v4) session rather than
    // assuming the original 12345 is preserved.
    let pool_v4: Ipv4Addr = "172.16.80.50".parse().expect("pool v4");
    let dst_v4: Ipv4Addr = "8.8.8.8".parse().expect("dst v4");
    let mut translated_port = 0u16;
    sessions.iter_with_origin(|key, _decision, _metadata, _origin| {
        if key.addr_family == libc::AF_INET as u8 {
            translated_port = key.dst_port;
        }
    });
    assert_ne!(
        translated_port, 0,
        "the reverse NAT64 (v4) session must key on a translated port"
    );
    assert_ne!(
        translated_port, 12345,
        "#4381: the source port must be translated, not preserved"
    );
    // SYN-ACK = SYN (0x02) | ACK (0x10). TCP_FLAG_ACK is not exported at the
    // afxdp module level, so spell the ACK bit inline.
    const ACK: u8 = 0x10;
    let reply_frame =
        build_txn_tcp_syn_frame_v4(dst_v4, pool_v4, 443, translated_port, TCP_FLAG_SYN | ACK);
    let reply_meta = txn_meta_v4(24, TCP_FLAG_SYN | ACK, reply_frame.len() as u16);
    let (rev_batch, _rev_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_frame,
        reply_meta,
    );
    assert_eq!(
        rev_batch.nat64_translations, 1,
        "the v4->v6 reverse translation must bump the counter exactly once"
    );
}


// #2218: a translated forward flow through the worker poll path must bump the
// matched SNAT rule's per-rule hit counter exactly once on the committed
// install, and NOT bump it for a refused-at-cap flow (the trigger is dropped,
// no session is created). FAIL-ON-REVERT: with the cold-path increment line
// removed, the admitted-flow assertion (count == 1) fails.
#[test]
fn txn_source_nat_translation_bumps_rule_counter_once() {
    let mut snapshot = nat_snapshot();
    // Stamp a per-rule counter id on the interface-mode SNAT rule that the
    // 10.0.61.x -> 8.8.8.8 lan->wan flow matches.
    snapshot.source_nat_rules[0].counter_id = 5;

    let policy_counters = crate::policy::PolicyCounterStore::default();
    let nat_counters = crate::nat::NatCounterStore::default();
    let forwarding =
        build_forwarding_state_with_counters(&snapshot, &policy_counters, &nat_counters);
    let counter = nat_counters
        .rule_counter(5)
        .expect("store must hold the parsed rule's counter");

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // Phase 1 — refused at cap 0: the trigger is dropped, nothing installs, so
    // the counter MUST stay 0.
    sessions.set_max_sessions_for_test(0);
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_b0, d0) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d0.tx, 0, "refused SNAT flow must not forward");
    assert_eq!(
        nat_counters.snapshots()[0].packets,
        0,
        "a refused (rolled-back) SNAT translation must not be counted"
    );

    // Phase 2 — admitted below cap: the forward translation commits and the
    // counter bumps exactly once (per committed flow, with the trigger len).
    sessions.set_max_sessions_for_test(16);
    let (_b1, d1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d1.tx, 1, "admitted SNAT flow must forward its trigger");
    let snaps = nat_counters.snapshots();
    assert_eq!(snaps.len(), 1, "exactly one NAT rule counter");
    assert_eq!(snaps[0].counter_id, 5);
    assert_eq!(
        snaps[0].packets, 1,
        "the committed SNAT translation must bump the counter exactly once"
    );
    assert_eq!(
        snaps[0].bytes,
        frame.len() as u64,
        "the per-flow byte count is the trigger descriptor length (full frame, matching the policy counter's desc.len semantic)"
    );
    // The shared Arc reflects the same count.
    assert_eq!(
        counter.snapshot(5).packets,
        1,
        "the rule's shared Arc carries the committed count"
    );

    // Phase 3 — a NON-translated flow (different SNAT rule with no counter):
    // build a fresh forwarding with the rule's counter_id back to 0 and verify
    // the store stays empty after a flow.
    let mut snapshot2 = nat_snapshot();
    snapshot2.source_nat_rules[0].counter_id = 0;
    let nat_counters2 = crate::nat::NatCounterStore::default();
    let forwarding2 = build_forwarding_state_with_counters(
        &snapshot2,
        &crate::policy::PolicyCounterStore::default(),
        &nat_counters2,
    );
    let mut binding2 = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding2.interface = Arc::<str>::from("reth1.0");
    let mut sessions2 = SessionTable::new();
    sessions2.set_max_sessions_for_test(16);
    let (_b2, d2) = txn_run_descriptor(
        &mut binding2,
        &mut sessions2,
        &forwarding2,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(d2.tx, 1, "the uncounted SNAT flow still forwards");
    assert!(
        nat_counters2.snapshots().is_empty(),
        "a counter_id-0 SNAT rule allocates no counter, so the store stays empty"
    );
}


// #2161: BatchCounters.nat64_translations must flush into BindingLiveState
// and survive into the snapshot the coordinator reads to build the wire
// BindingStatus.nat64_translations the Go control plane sums. This guards
// the deepest plumbing layer end to end (counter -> live atomic ->
// snapshot) so a dropped flush line or a missed snapshot field is caught.
#[test]
fn nat64_translations_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    // rx_telemetry sets `touched` for every RX packet before the
    // forward-candidate counting site; mirror that so flush runs.
    batch.touched = true;
    batch.nat64_translations = 3;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_translations, 0,
        "flush must zero the batched count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_translations, 3,
        "the live atomic + snapshot must carry the flushed NAT64 count"
    );
}


// #2291: the fail-closed NAT64 drop counter (prefix matched, no source pool)
// must flush BatchCounters -> BindingLiveState -> snapshot the same way as
// nat64_translations, so an operator can see the drops and a dropped flush
// line is caught at build/test time.
#[test]
fn nat64_no_source_pool_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_no_source_pool = 5;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_no_source_pool, 0,
        "flush must zero the batched no-source-pool drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_no_source_pool, 5,
        "the live atomic + snapshot must carry the flushed no-source-pool count"
    );
}


// #4520: the transient NAT64 pool-exhaustion drop counter must flush
// BatchCounters -> BindingLiveState -> snapshot the same way as its
// config/empty sibling nat64_no_source_pool, so an operator can see the
// transient drops and a dropped flush/snapshot line is caught at build/test
// time.
#[test]
fn nat64_pool_exhausted_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_pool_exhausted = 7;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_pool_exhausted, 0,
        "flush must zero the batched pool-exhausted drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_pool_exhausted, 7,
        "the live atomic + snapshot must carry the flushed pool-exhausted count"
    );
    assert_eq!(
        snap.nat64_no_source_pool, 0,
        "the config/empty sibling must NOT be touched by a pool-exhaustion drop"
    );
}


// #4520: the NAT64 source-allocation failure reason must be attributed to the
// RIGHT counter — transient port exhaustion (add capacity) split from a
// config/empty pool (fix config), mirroring source-NAT. FAIL-ON-REVERT:
// collapsing both arms back onto nat64_no_source_pool (the pre-#4520
// `Err(_) => nat64_no_source_pool += 1`) makes the AllocatorExhausted
// assertion below fail RED.
#[test]
fn record_nat64_source_failure_splits_exhaustion_from_config() {
    use crate::nat::SourceNatFailureReason;

    // Transient exhaustion -> nat64_pool_exhausted, NOT nat64_no_source_pool.
    let mut batch = BatchCounters::default();
    batch.record_nat64_source_failure(SourceNatFailureReason::AllocatorExhausted);
    assert_eq!(
        batch.nat64_pool_exhausted, 1,
        "AllocatorExhausted must bump nat64_pool_exhausted (transient)"
    );
    assert_eq!(
        batch.nat64_no_source_pool, 0,
        "AllocatorExhausted must NOT bump nat64_no_source_pool (config/empty)"
    );
    assert!(batch.touched, "recording a drop must mark the batch touched");

    // Every non-exhaustion reason -> nat64_no_source_pool (config/empty).
    for reason in [
        SourceNatFailureReason::MissingPool,
        SourceNatFailureReason::EmptyPool,
        SourceNatFailureReason::InvalidPool,
        SourceNatFailureReason::WrongAddressFamily,
    ] {
        let mut b = BatchCounters::default();
        b.record_nat64_source_failure(reason);
        assert_eq!(
            b.nat64_no_source_pool, 1,
            "{reason:?} must bump nat64_no_source_pool (config/empty)"
        );
        assert_eq!(
            b.nat64_pool_exhausted, 0,
            "{reason:?} must NOT bump nat64_pool_exhausted (transient)"
        );
    }
}


// #2562: the fail-closed NAT64 fragment-drop counter must flush
// BatchCounters -> BindingLiveState -> snapshot the same way as the sibling
// nat64 drop counters, so an operator can see fragmented-NAT64 drops and a
// dropped flush/snapshot line is caught at build/test time.
#[test]
fn nat64_frag_dropped_flushes_to_live_and_snapshot() {
    let live = BindingLiveState::new();
    let mut batch = BatchCounters::default();
    batch.touched = true;
    batch.nat64_frag_dropped = 4;
    batch.flush(&live);
    assert_eq!(
        batch.nat64_frag_dropped, 0,
        "flush must zero the batched fragment-drop count"
    );
    let snap = live.snapshot();
    assert_eq!(
        snap.nat64_frag_dropped, 4,
        "the live atomic + snapshot must carry the flushed fragment-drop count"
    );
    // The fragment drop is a distinct bucket from the pool counters.
    assert_eq!(snap.nat64_no_source_pool, 0);
    assert_eq!(snap.nat64_pool_exhausted, 0);
}


// #2562: `record_nat64_frag_dropped` bumps the fragment-drop counter and marks
// the batch touched (so the value survives to the next flush).
#[test]
fn record_nat64_frag_dropped_bumps_counter() {
    let mut batch = BatchCounters::default();
    assert!(!batch.touched);
    batch.record_nat64_frag_dropped();
    batch.record_nat64_frag_dropped();
    assert_eq!(
        batch.nat64_frag_dropped, 2,
        "each record must bump the fragment-drop counter"
    );
    assert!(batch.touched, "recording a drop must mark the batch touched");
    // Sibling nat64 drop counters are untouched.
    assert_eq!(batch.nat64_no_source_pool, 0);
    assert_eq!(batch.nat64_pool_exhausted, 0);
}

// === #1873 R-C: blanket tunnel gate at the slow-path chokepoint ===


/// #1873 R-C: a tunnel-marked inner packet must NEVER be enqueued to
/// the kernel slow-path TUN — through ANY door (build-failure
/// fallback, NoRoute, MissingNeighbor non-forward dispositions). It is
/// dropped with the dedicated counter + exception, and the generic
/// slow_path_drops counter stays untouched (proving the gate fires
/// BEFORE the enqueue/unavailable handling, not as a side effect of
/// slow_path being absent).
#[test]
fn tunnel_marked_frame_never_reaches_slow_path() {
    for (i, disposition) in [
        ForwardingDisposition::ForwardCandidate, // build-failure door
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::MissingNeighbor,
    ]
    .into_iter()
    .enumerate()
    {
        let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        maybe_reinject_slow_path_from_frame(
            &binding,
            &live,
            None,
            &local_tunnel_deliveries,
            &frame,
            meta,
            tunnel_marked_decision(disposition),
            &recent_exceptions,
            "forward_build_slow_path",
            &ForwardingState::default(),
        );
        assert_eq!(
            live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
            1,
            "case {i}: tunnel gate did not fire"
        );
        assert_eq!(
            live.slow_path_drops.load(Ordering::Relaxed),
            0,
            "case {i}: generic slow-path drop counted — gate fired too late"
        );
        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        let exceptions = recent_exceptions.lock().expect("exceptions");
        assert_eq!(
            exceptions.back().expect("exception").reason,
            "tunnel_encap_unresolved",
            "case {i}"
        );
    }
}


/// #1873 R-C: the build-failure entry point (`handle_forward_build_failure`
/// with fallback_to_slow_path = true) funnels through the same gate.
#[test]
fn tunnel_marked_build_failure_drops_instead_of_slow_path() {
    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let mut dbg = DebugPollCounters::default();
    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        6,
        frame.len() as u32,
        &frame,
        meta,
        tunnel_marked_decision(ForwardingDisposition::ForwardCandidate),
        true,
        &ForwardingState::default(),
    );
    assert_eq!(
        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
}


/// #1873 R-C: the local_tunnel_deliveries branch (GRE local-origin
/// INBOUND delivery, keyed by local_ifindex) must stay OPEN — the gate
/// sits after it.
#[test]
fn tunnel_gate_keeps_local_tunnel_delivery_open() {
    let (binding, live, recent_exceptions, meta, frame) = tunnel_gate_test_fixture();
    let (tx, rx) = mpsc::sync_channel(4);
    // #2412: the delivery map now carries the eventfd wake alongside the
    // sender; the worker slow path signals it via LocalTunnelDelivery.
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(9, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));
    let mut decision = tunnel_marked_decision(ForwardingDisposition::LocalDelivery);
    decision.resolution.local_ifindex = 9;
    maybe_reinject_slow_path_from_frame(
        &binding,
        &live,
        None,
        &local_tunnel_deliveries,
        &frame,
        meta,
        decision,
        &recent_exceptions,
        "forward_build_slow_path",
        &ForwardingState::default(),
    );
    assert_eq!(
        live.tunnel_encap_unresolved_drops.load(Ordering::Relaxed),
        0
    );
    let delivered = rx.try_recv().expect("local tunnel delivery still open");
    assert!(!delivered.is_empty());
}


/// #1873 R-E: a tunnel-marked decision whose OUTER next-hop is
/// unresolved must NOT be buffered in pending_neigh — the retry path's
/// in-place rewrite cannot encapsulate, so a buffered tunnel inner
/// packet would later TX PLAINTEXT. The frame is dropped instead.
///
/// In this fixture the tunnel endpoint carries no redundancy_group and
/// the egress RG is unowned, so the HA gate resolves the tunnel-marked
/// decision to a residual `HAInactive` (rg=0) — the §2.3 corner. Before
/// #1913 the trailing reinject chokepoint ran UNFILTERED, so this
/// HAInactive frame fell into `maybe_reinject_slow_path_from_frame` and
/// was dropped+counted at the R-C tunnel gate
/// (`tunnel_encap_unresolved_drops`). After #1913 the chokepoint gates
/// on `is_slow_path_eligible`, so the HAInactive frame is dropped
/// EARLIER, at the disposition gate (counted as an `ha_inactive`
/// exception and recycled) and never reaches `_from_frame`. Either way
/// the frame is DROPPED, NOT buffered, and NOT reinjected to the kernel
/// FIB — which is the R-E invariant under test.
#[test]
fn txn_tunnel_marked_missing_neighbor_not_buffered() {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        ..Default::default()
    });
    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 824,
        interface: "gr-0/0/0.0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        zone: "wan".to_string(),
        mode: "gre".to_string(),
        outer_family: "inet".to_string(),
        source: "172.16.80.8".to_string(),
        destination: "203.0.113.9".to_string(),
        transport_table: "inet.0".to_string(),
        ttl: 64,
        ..Default::default()
    }];
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "8.8.8.8/32".to_string(),
        next_hops: vec!["@gr-0/0/0.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    // No neighbors: the tunnel's OUTER destination (203.0.113.9 via the
    // 172.16.80.1 default gateway) is unresolved -> MissingNeighbor
    // with tunnel_endpoint_id preserved.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    // First packet: residual HAInactive (rg=0) tunnel-marked frame.
    // R-E invariant: never buffered for in-place retry.
    assert!(
        binding.pending_neigh.is_empty(),
        "tunnel-marked frame must never be admitted to pending_neigh (#1873 R-E)"
    );
    // #1913: the HAInactive frame is dropped at the disposition gate
    // (not eligible for slow-path reinjection) and never reaches
    // `_from_frame`, so it is NOT handed to the kernel FIB. It is
    // counted as an `ha_inactive` exception by record_forwarding_
    // disposition and recycled.
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "HAInactive tunnel frame must NOT be reinjected to the kernel slow path (#1913)"
    );
    assert_eq!(
        binding
            .live
            .tunnel_encap_unresolved_drops
            .load(Ordering::Relaxed),
        0,
        "HAInactive frame is gated before the R-C tunnel gate post-#1913"
    );
    let _ = dbg;

    // Second packet: the HAInactive arm never seeds a session, so this
    // run re-executes the session-miss path (the `sessions` table is
    // still empty). It re-resolves to the same residual HAInactive
    // tunnel decision and must again be dropped — never buffered for
    // in-place retry and never reinjected.
    assert_eq!(
        sessions.len(),
        0,
        "HAInactive frame must NOT seed a session (second run stays on the miss path)"
    );
    let meta2 = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta2,
    );
    let _ = dbg2;
    assert!(
        binding.pending_neigh.is_empty(),
        "tunnel-marked frame must skip pending_neigh admission on the re-run too (#1873 R-E)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "second packet must also NOT be reinjected to the kernel slow path (#1913)"
    );
}


/// #1913 (Codex r1): a packet DENIED by zone policy whose forwarding
/// resolution is `MissingNeighbor` (connected destination, no neighbor
/// learned yet) must NOT be reinjected to the kernel slow path. The
/// MissingNeighbor arm has its own policy evaluation that historically
/// only gated SNAT — a DENY fell through to session install + pending-
/// neighbor buffer + the trailing reinject chokepoint with the
/// disposition still `MissingNeighbor` (slow-path-eligible), so a denied
/// unresolved-neighbor cold-path packet leaked to the kernel FIB. The
/// fix converts the deny to `PolicyDenied` and drops+recycles it inside
/// the arm. Asserts: zero reinjects, no session created, not buffered.
#[test]
fn txn_policy_denied_missing_neighbor_is_dropped_not_reinjected() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        // #3457: policy_deny_snapshot() carries a dmz->wan permit policy;
        // the dmz zone must stay in the table or the #3402 fail-closed
        // gate raises UnresolvableZoneReference and build_forwarding_state
        // panics. The flow under test is lan->wan, so dmz is inert here.
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    // No neighbor for 172.16.80.200: the connected WAN route resolves
    // but ARP is unresolved -> MissingNeighbor (the cold path under test).
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // src 10.0.61.102 (lan, ingress ifindex 24) -> dst 172.16.80.200
    // (connected wan). lan->wan is default-deny.
    let frame = build_policy_deny_tcp_syn_frame();
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let sessions_before = sessions.len();
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "denied MissingNeighbor flow must be counted as a policy deny (#1913)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "denied MissingNeighbor flow must NOT be reinjected to the kernel slow path (#1913)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "denied flow must NOT be buffered for in-place neighbor retry (#1913)"
    );
    assert_eq!(
        sessions.len(),
        sessions_before,
        "denied flow must NOT seed a MissingNeighbor session (#1913)"
    );
}


/// #1913 (Codex r3): the deny gate must run BEFORE the negative-cache
/// fast-fail / resolver enqueue at the top of the MissingNeighbor arm.
/// With the dst's neg-cache key pre-seeded, a denied flow must STILL be
/// converted to PolicyDenied and counted — not silently recycled by the
/// neg_neigh_gate fast-fail path (which would skip the deny event/count
/// and could enqueue a resolver probe for a flow policy says to drop).
#[test]
fn txn_policy_denied_missing_neighbor_skips_neg_cache_fast_fail() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        // #3457: keep the dmz zone so policy_deny_snapshot()'s dmz->wan
        // permit policy resolves under the #3402 fail-closed gate. The
        // flow under test is lan->wan; dmz is inert.
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    // Pre-seed the negative cache for the connected WAN dst's neg-cache
    // key (egress reth0.80 ifindex 12, next_hop = the connected dst). If
    // the deny gate ran AFTER neg_neigh_gate, this packet would fast-fail
    // and recycle as a dead-host miss with NO policy deny counted.
    let now_ns = 123_000_000_000u64;
    binding
        .neg_neigh_cache
        .insert((12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))), now_ns);
    let mut sessions = SessionTable::new();

    let frame = build_policy_deny_tcp_syn_frame();
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "denied flow must be counted as a policy deny even with the neg-cache key seeded (#1913 Codex r3)"
    );
    assert_eq!(
        dbg.neg_neigh_fast_fail, 0,
        "deny gate must run BEFORE the neg-cache fast-fail — a denied flow must not take the dead-host recycle path (#1913 Codex r3)"
    );
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "denied flow must NOT be reinjected (#1913)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "denied flow must NOT be buffered (#1913)"
    );
}


// =====================================================================
// #5174: NAT64 MissingNeighbor cold-path fail-closed. NAT64 classification +
// source allocation are gated inside the ForwardCandidate session-miss branch,
// so a NAT64 flow whose extracted-IPv4 next-hop is UNRESOLVED reaches the
// MissingNeighbor arm with a non-NAT64 `decision.nat` — the arm previously
// evaluated policy on the SYNTHETIC IPv6 dst and seeded/buffered an untranslated
// forward (an HA-synced broken session that replays the IPv6 frame to the IPv4
// gateway). The bounded fix: re-classify NAT64 in the arm (policy on the
// extracted V4 dst), and for a permitted NAT64 flow fire the neighbor probe then
// DROP (no seed, no untranslated buffer) — the flow recovers via ForwardCandidate
// once the neighbor resolves. Full buffer-and-translate parity is a follow-up.
// =====================================================================

/// #6836: the meta carries the FLOW ADDRESSES of the frame it describes.
///
/// Both NAT64 meta fixtures used to leave `flow_src_addr`/`flow_dst_addr` at
/// their all-zero default. `l3_session_flow_from_meta` returns `None` for an
/// unspecified address, so the ENTIRE flowless input-filter block in
/// `forward_request.rs` was unreachable under every test built on these
/// fixtures — including the pre-existing miss-branch filter, which has been
/// carrying coverage it did not have.
///
/// A test asserting a value that happens to equal its path's failure default is
/// at least EXECUTING the path. Here the path was not executed at all, so no
/// assertion strength saved it, and nothing in the output distinguished that
/// from a genuine pass.
///
/// The addresses are PARAMETERS rather than baked-in constants deliberately: a
/// meta that silently disagrees with its frame is the same class of defect one
/// step over, and every caller already has the real `src`/`dst` in scope.
fn nat64_v6_syn_meta(frame_len: usize, src: Ipv6Addr, dst: Ipv6Addr) -> UserspaceDpMeta {
    UserspaceDpMeta {
        flow_src_addr: src.octets(),
        flow_dst_addr: dst.octets(),
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #5174 FAIL-ON-REVERT: a PERMITTED NAT64 flow whose extracted-IPv4 next-hop is
/// UNRESOLVED must be handled fail-closed — (a) policy is evaluated on the
/// extracted IPv4 dst (8.8.8.8), NOT the synthetic IPv6 dst (64:ff9b::808:808),
/// and (b) NO MissingNeighborSeed is installed and NO untranslated frame is
/// buffered (the arm probes then drops). The permit rule's destination is the
/// IPv4 host `8.8.8.8/32` under a default-deny, so the flow is permitted ONLY if
/// policy matched the extracted IPv4 dst (proves (a)). Reverting the fix:
///   - drop the policy-tuple fix → policy denies on the synthetic IPv6 →
///     `nat64_missing_neigh_drop == 0` → RED;
///   - drop the fail-closed divert → the permitted flow seeds + buffers the
///     untranslated frame → `sessions.len() >= 1` / `pending_neigh` non-empty /
///     counter 0 → RED.
#[test]
fn nat64_missing_neighbor_fail_closed_drop_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"));
    // The extracted IPv4 dst 8.8.8.8 routes via the default gw 172.16.80.1;
    // clear neighbors so that gateway is unresolved -> MissingNeighbor.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = nat64_v6_syn_meta(frame.len(), src, dst);
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 1,
        "a permitted NAT64 flow with an unresolved extracted-IPv4 next-hop must \
         fail-closed drop (policy matched the V4 dst AND the arm recycled after the probe)"
    );
    assert_eq!(
        sessions.len(),
        0,
        "NAT64 MissingNeighbor must NOT seed a (non-NAT64) MissingNeighborSeed session"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "NAT64 MissingNeighbor must NOT buffer the untranslated IPv6 frame for in-place replay"
    );
}

/// #5174 control: a PERMITTED NON-NAT64 flow (plain IPv4) whose next-hop is
/// unresolved is UNCHANGED — it still seeds/buffers the normal MissingNeighbor
/// cold path (the #5174 divert fires ONLY for a NAT64 flow). Counter stays 0.
#[test]
fn non_nat64_missing_neighbor_still_buffers_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("9.9.9.9/32", "permit-v4"));
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(9, 9, 9, 9),
        12345,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 0,
        "the NAT64 fail-closed divert must NOT fire for a non-NAT64 flow"
    );
    assert!(
        sessions.len() >= 1 || !binding.pending_neigh.is_empty(),
        "a permitted non-NAT64 MissingNeighbor flow must still seed/buffer (unregressed cold path)"
    );
}

/// #5174 FAIL-ON-REVERT (Harm A — policy tuple): a NAT64 flow to the extracted
/// IPv4 dst 8.8.8.8 under a permit rule for a DIFFERENT v4 host (9.9.9.9) must be
/// DENIED — policy is evaluated on the correct extracted V4 dst (8.8.8.8 ∉
/// 9.9.9.9/32 → default-deny), so it exits via the normal PolicyDenied path, NOT
/// the NAT64 fail-closed divert. Reverting the policy-tuple fix evaluates policy
/// on the SYNTHETIC IPv6 dst (64:ff9b::808:808): a v4-destination rule matches a
/// v6 destination as match-any (the cross-family legacy convention), so the flow
/// is WRONGLY PERMITTED → it hits the divert (`nat64_missing_neigh_drop == 1`,
/// `policy_deny == 0`) → RED. This is the policy-divergence security bug the arm
/// classification fixes.
#[test]
fn nat64_missing_neighbor_denied_no_fail_closed_drop_5174() {
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("9.9.9.9/32", "permit-other-v4"));
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = nat64_v6_syn_meta(frame.len(), src, dst);
    let (_batch, dbg) =
        txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        dbg.nat64_missing_neigh_drop, 0,
        "a DENIED NAT64 flow must exit at the policy deny, NOT the fail-closed divert"
    );
    assert!(dbg.policy_deny >= 1, "the NAT64 flow to a non-permitted v4 dst must be policy-denied");
    assert_eq!(sessions.len(), 0);
    assert!(binding.pending_neigh.is_empty());
}

// =====================================================================
// #5146: NAT64 first-fragment association is published ONLY post-commit
// =====================================================================
//
// The first-fragment association (the #2562 cross-family fragment cache) must
// become visible ONLY after the anchor first fragment COMMITS to the outcome it
// authorizes — i.e. past `can_admit` AND a successful forward session install.
// Before #5146 the install fired at NAT64 source-allocation time (pre-commit);
// a subsequent rollback (hop-limit ICMP-TE, admission refusal, install-partial)
// released only the pool port and left the association LIVE for ~2s. A non-first
// fragment of that rolled-back datagram then inherited a rolled-back verdict AND
// a now-reusable translation — cross-flow NAT64 fragment ambiguity under port
// reuse. These two tests pin both directions of the invariant through the real
// `poll_binding_process_descriptor` path.

/// eth(14) + IPv6(40, next-header 44 Fragment) + Fragment(8) + TCP(20).
/// `frag_off` is the IPv6 Fragment-Header offset/flags word: `0x0001` => offset
/// 0, MF=1 (FIRST fragment — installs); `0x0008` => offset 1 (8-octet units),
/// MF=0 (NON-first fragment — flowless, consults only). `ident` is the 32-bit
/// Fragment Identification shared by every fragment of one datagram. src is a
/// lan v6 host; dst is the NAT64 synthetic prefix `64:ff9b::808:808` (extracts
/// 8.8.8.8). For a first fragment the trailing 20 bytes are a real TCP header
/// (sport/dport); for a non-first fragment they are opaque payload (#2344 — never
/// read as L4 ports).
fn nat64_v6_frag_frame(
    frag_off: u16,
    ident: u32,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x01, 0x00, 0x01, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd,
    ];
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60; // version 6
    let payload_len = (8 + 20) as u16; // fragment header + TCP
    ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip[6] = 44; // next header = Fragment
    ip[7] = 64; // hop limit (> 1: no ICMP-TE)
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    f.extend_from_slice(&ip);
    // Fragment extension header (8 bytes).
    let mut frag = [0u8; 8];
    frag[0] = PROTO_TCP; // next header after the fragment header
    frag[2..4].copy_from_slice(&frag_off.to_be_bytes());
    frag[4..8].copy_from_slice(&ident.to_be_bytes());
    f.extend_from_slice(&frag);
    // TCP header (20 bytes). A transit router does not verify the ingress L4
    // checksum, so it is left 0 (matches the #5689 udp_frag fixture).
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[3 + 9] = 0x50; // data offset (byte 12)
    tcp[13] = TCP_FLAG_SYN;
    tcp[14..16].copy_from_slice(&0xfaf0u16.to_be_bytes());
    f.extend_from_slice(&tcp);
    f
}

/// Metadata for a v6 NAT64 fragment: the L4 header sits after the 8-byte
/// Fragment extension header, so `l4_offset = 14 + 40 + 8 = 62`.
/// #6836: as `nat64_v6_syn_meta` — the meta carries the frame's flow addresses.
fn nat64_v6_frag_meta(frame_len: usize, src: Ipv6Addr, dst: Ipv6Addr) -> UserspaceDpMeta {
    UserspaceDpMeta {
        flow_src_addr: src.octets(),
        flow_dst_addr: dst.octets(),
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 62,
        payload_offset: 82,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn nat64_frag_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    // #6835: this fixture used to DELETE the v6 default route
    // (`snapshot.routes.retain(|r| r.family != "inet6")`), justified as "the
    // synthetic NAT64 prefix is never v6-routable in production". That
    // justification was wrong in the direction that mattered: a real firewall
    // has a default route, and `::/0` matches a Pref64 destination like any
    // other. Deleting it removed the ONLY condition under which the #4617
    // fail-closed claim could be tested — with the route present, a missed
    // NAT64 non-first fragment FORWARDED untranslated, and every test here
    // passed anyway because the route was gone. The subtraction was the bug.
    //
    // The route stays. The fail-closed drop is now enforced by production code
    // (the Pref64-destination gate on the flowless arm in
    // `poll_descriptor/mod.rs`), which is what `nat64_frag_assoc_miss_must_drop_with_default_route_6927`
    // pins. The NAT64 FORWARD resolves the extracted IPv4 dst (8.8.8.8) via
    // inet.0, so a committed first fragment still translates and forwards.
    debug_assert!(
        snapshot
            .routes
            .iter()
            .any(|r| r.family == "inet6" && r.destination == "::/0"),
        "#6835: the NAT64 fragment fixture must keep the v6 default route — deleting it is what \
         hid the untranslated-forward leak"
    );
    snapshot
}

// #5146 SUCCESS path (the #2562/#6095 feature must survive the fix): a COMMITTED
// NAT64 first fragment DOES publish its association, and a non-first fragment of
// the same datagram inherits the translation and forwards. If this went RED the
// fix would have broken legitimate NAT64 fragment forwarding.
#[test]
fn nat64_committed_first_fragment_publishes_frag_assoc_and_nonfirst_inherits_5146() {
    let forwarding = build_forwarding_state(&nat64_frag_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");

    // FIRST fragment (offset 0, MF=1). Runs the full ported cold path: NAT64
    // source allocation, admission, forward+reverse install, THEN (post-commit)
    // the first-fragment association install.
    let first = nat64_v6_frag_frame(0x0001, 0x1234_5678, src, dst, 12345, 443);
    let (b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(dbg1.tx, 1, "the committed NAT64 first fragment must translate + forward");
    assert_eq!(b1.nat64_translations, 1, "the first fragment is NAT64-translated");
    assert_eq!(sessions.len(), 2, "NAT64 forward + reverse install below cap");
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "#5146: a COMMITTED NAT64 first fragment MUST publish exactly one association \
         (the #2562 feature — RED if the post-commit install is removed)"
    );

    // NON-first fragment (offset 1, SAME ident) is flowless: it consults the
    // association and inherits the first fragment's NAT64 translation.
    let non_first = nat64_v6_frag_frame(0x0008, 0x1234_5678, src, dst, 0, 0);
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        nat64_v6_frag_meta(non_first.len(), src, dst),
    );
    assert_eq!(
        dbg2.tx, 1,
        "#5146: the non-first fragment must INHERIT the committed association and forward"
    );
    assert_eq!(
        b2.nat64_translations, 1,
        "#5146: the inherited non-first fragment must be NAT64-translated (the #2562 feature)"
    );
}

// #5146 FAIL-ON-REVERT: a NAT64 first fragment whose flow is ROLLED BACK (the
// session table is at cap, so `can_admit` refuses) must leave NO live fragment
// association, and a subsequent non-first fragment of the same datagram must
// MISS (drop fail-closed) rather than inherit the released translation.
//
// RED on revert: with the pre-commit install (association published at NAT64
// source-allocation time, before `can_admit`), the rolled-back first fragment
// still publishes -> `frag_assoc.len() == 1` -> the `== 0` assertion goes RED,
// and the non-first fragment inherits + forwards -> the `dbg2.tx == 0`
// assertion goes RED. Target-count 1 (this single test).
#[test]
fn nat64_rolled_back_first_fragment_publishes_no_frag_assoc_5146() {
    let forwarding = build_forwarding_state(&nat64_frag_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    // Cap 0: the forward session `can_admit` preflight refuses, so the NAT64
    // forward flow is ROLLED BACK (pool port released) after source allocation.
    sessions.set_max_sessions_for_test(0);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst (extracts 8.8.8.8)");

    // FIRST fragment (offset 0, MF=1) — admission-refused, rolled back.
    let first = nat64_v6_frag_frame(0x0001, 0x0bad_f00d, src, dst, 12345, 443);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(dbg1.tx, 0, "a refused NAT64 first fragment must not forward");
    assert_eq!(sessions.admission_refused(), 1, "the flow must hit the can_admit rollback arm");
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        0,
        "#5146: a ROLLED-BACK NAT64 first fragment must publish NO association \
         (RED on revert: the pre-commit install leaves 1 live association behind \
          the released pool port)"
    );

    // NON-first fragment (offset 1, SAME ident). With no live association it
    // MISSES and drops fail-closed (#4617) — it must NOT inherit the released
    // translation. Cap is irrelevant to a flowless fragment (it installs no
    // session), so raise it to isolate the miss from any admission effect.
    sessions.set_max_sessions_for_test(16);
    let non_first = nat64_v6_frag_frame(0x0008, 0x0bad_f00d, src, dst, 0, 0);
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        nat64_v6_frag_meta(non_first.len(), src, dst),
    );
    assert_eq!(
        b2.nat64_translations, 0,
        "#5146: a non-first fragment of a rolled-back first fragment must NOT inherit the \
         released NAT64 translation (RED on revert: the pre-commit association makes it \
         inherit + translate -> 1)"
    );
    assert_eq!(
        dbg2.tx, 0,
        "#5146: with no association to inherit, the missed non-first fragment drops \
         fail-closed. The fixture DOES carry a v6 default route now — deleting it is what hid \
         the #6835 leak — so this is a real fail-closed drop, NOT the absence of a route. \
         This cell does NOT identify WHICH gate dropped it: the flowless arm carries two \
         independent fail-closed gates that both cover this packet (the #6122 same-family \
         NAT-miss gate and the #6835 Pref64-destination gate), so tx==0 survives removing \
         either one. Each gate is bound by its own cell — #6122 by \
         tests_fragment::nat_nonfirst_fragment_assoc_miss_fails_closed_6122, #6835 by \
         nat64_frag_assoc_miss_must_drop_with_default_route_6927 — and mutating either gate \
         reds exactly that cell, not this one"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        0,
        "#5146: the consult miss must not resurrect an association"
    );
}

// #5798 FAIL-ON-REVERT (end-to-end, through the REAL poll_descriptor path): a
// non-first fragment arriving from a DIFFERENT security domain must NOT inherit
// the first fragment's permit + egress + NAT64 translation.
//
// This is the production-wiring counterpart to the key-level guards in
// nat64_tests.rs. Those prove `Nat64FragKey` DISCRIMINATES by authority; this
// proves the authority is actually THREADED at the real install and consult
// sites — a fix that widened the key but passed a constant authority from
// poll_descriptor would pass the key-level tests and still be bypassable.
//
// Domains are the fixture's two REAL interfaces, so the cross-domain fragment is
// a fully-configured ingress rather than an unknown one that might be dropped
// for an unrelated reason:
//   - domain A: reth1.0, ifindex 24, zone `lan`  (installs)
//   - domain B: reth0.80, ifindex 12, vlan 80, zone `wan` (attempts to inherit)
//
// What is pinned, precisely. The guard is DIFFERENTIAL: the two runs below use
// the IDENTICAL frame bytes, the same worker and the same cache state, and
// differ ONLY in `meta.ingress_ifindex` / `ingress_vlan_id` — yet one forwards
// and the other does not. Plus the association is asserted still LIVE after the
// cross-domain attempt, so the fragment failed to MATCH a present entry rather
// than the entry having expired or been evicted.
//
// What is NOT pinned, stated so a later reader does not over-read this test: the
// exact gate that finally discards the missed fragment. Measured firsthand, it
// is NOT the #4617 `nat64_frag_dropped` translate-path counter. That reasoning
// described the PRE-#6835 fixture, which deleted the inet6 routes so an
// unassociated NAT64 v6 fragment died for want of a route. `nat64_frag_snapshot`
// now deliberately RETAINS `::/0` — the deletion was hiding a real leak — so the
// missed fragment is stopped by the Pref64-destination gate instead. The same convention is used by the sibling
// `nat64_rolled_back_first_fragment_publishes_no_frag_assoc_5146` miss test,
// which also asserts tx/translations rather than a drop-reason counter.
//
// RED on revert: pass a constant authority (or drop `authority` from the key)
// and the domain-B fragment inherits -> the `dbg2.tx == 0` assertion goes RED.
#[test]
fn nat64_cross_domain_nonfirst_fragment_does_not_inherit_5798() {
    let forwarding = build_forwarding_state(&nat64_frag_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");

    // Domain A installs the association off a committed first fragment.
    let first = nat64_v6_frag_frame(0x0001, 0x5798_0042, src, dst, 12345, 443);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(dbg1.tx, 1, "the domain-A first fragment must translate + forward");
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "the committed first fragment publishes exactly one association"
    );

    // Domain B: SAME (src, dst, ident) — the whole pre-#5798 key — but a
    // different, fully-configured ingress interface/VLAN/zone.
    let non_first = nat64_v6_frag_frame(0x0008, 0x5798_0042, src, dst, 0, 0);
    let mut meta_b = nat64_v6_frag_meta(non_first.len(), src, dst);
    meta_b.ingress_ifindex = 12;
    meta_b.ingress_vlan_id = 80;
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        meta_b,
    );
    assert_eq!(
        dbg2.tx, 0,
        "#5798: a non-first fragment from ANOTHER security domain must NOT inherit \
         domain A's permit/egress/NAT64 translation"
    );
    assert_eq!(
        b2.nat64_translations, 0,
        "#5798: the cross-domain fragment must not be NAT64-translated under domain A's decision"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "domain A's association must still be live — the cross-domain fragment simply \
         failed to match it (proves the drop was a miss, not a vanished entry)"
    );

    // Positive control: the SAME domain still inherits and forwards, so the
    // authority scoping is not blackholing legitimate fragmented NAT64 traffic.
    let (b3, dbg3) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        nat64_v6_frag_meta(non_first.len(), src, dst),
    );
    assert_eq!(
        dbg3.tx, 1,
        "#5798 control: a SAME-domain non-first fragment must still inherit and forward"
    );
    assert_eq!(
        b3.nat64_translations, 1,
        "#5798 control: the same-domain fragment is still NAT64-translated"
    );
}

// #5798 Element 2 FAIL-ON-REVERT: an association HIT must NOT bypass the
// per-packet INTERFACE INPUT FILTER.
//
// The authority key (Element 1) closes cross-domain permit inheritance, but it
// does NOT close this: the input filter ran ONLY in the miss `else` branch —
// the hit arm returned the cached decision directly — so even a correctly-scoped
// SAME-DOMAIN hit skipped a `from is-fragment then discard` term entirely. The
// fix ADDS a filter evaluation to the hit arm; the consult itself was not
// reordered. Required-fix #4 says a hit may
// inherit the first fragment's STATEFUL zone-policy permit + NAT translation +
// egress route, but must still be subject to per-packet filter semantics.
//
// Why the cache is seeded directly instead of installed by a first fragment: an
// `is-fragment` term matches EVERY fragment of a datagram, first ones included,
// so a filter that can catch the non-first fragment would also discard the first
// and leave nothing installed to inherit. Seeding lets the filter exist ONLY for
// the run under test. The key is built through the SAME production authority
// resolver the consult uses (`frag_ingress_authority`), so the entry is a
// genuine same-domain hit — not a synthetic one that would miss for the wrong
// reason. The control below proves exactly that: with the discard term removed,
// the identical seeded entry DOES produce a forwarded, translated fragment.
//
// RED on revert: delete the input-filter block from the `{ hit }` arm in
// poll_descriptor and the discarded case forwards (tx == 1).
#[test]
fn nat64_association_hit_still_runs_interface_input_filter_5798() {
    // `discard_fragments` wires an inet6 input filter on reth1.0 whose first
    // term is `from is-fragment then discard`.
    let run = |discard_fragments: bool| -> (u64, u64) {
        let mut snapshot = nat64_frag_snapshot();
        if discard_fragments {
            if let Some(iface) = snapshot.interfaces.iter_mut().find(|i| i.name == "reth1.0") {
                iface.filter_input_v6 = "frag-discard6".to_string();
            }
            snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
                name: "frag-discard6".to_string(),
                family: "inet6".to_string(),
                terms: vec![
                    crate::protocol::FirewallTermSnapshot {
                        name: "drop-fragments".to_string(),
                        is_fragment: true,
                        action: "discard".to_string(),
                        ..Default::default()
                    },
                    crate::protocol::FirewallTermSnapshot {
                        name: "default".to_string(),
                        action: "accept".to_string(),
                        ..Default::default()
                    },
                ],
            });
        }
        let forwarding = build_forwarding_state(&snapshot);
        let ha_state = txn_ha_state();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        sessions.set_max_sessions_for_test(16);

        let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
        let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
        let ident: u32 = 0x5798_0002;
        let first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
        let non_first = nat64_v6_frag_frame(0x0008, ident, src, dst, 0, 0);
        let mut meta = nat64_v6_frag_meta(non_first.len(), src, dst);
        // The shared NAT64 fragment fixture leaves `flow_{src,dst}_addr` at their
        // all-zero default. `l3_session_flow_from_meta` returns None for an
        // unspecified address, and BOTH the hit-arm filter added here and the
        // pre-existing miss-branch flowless filter are gated on it — so without
        // these the filter block is skipped entirely and this test would pass
        // vacuously. Production always has them stamped by the shim.
        meta.flow_src_addr = src.octets();
        meta.flow_dst_addr = dst.octets();

        // The seeded decision is a REAL one: it is produced by running a genuine
        // first fragment through the full cold path on an unfiltered twin state,
        // then read back out of that state's cache. Hand-rolling a decision here
        // could accidentally build one that is not actually forwardable, which
        // would make the filtered case pass for the wrong reason.
        let decision = {
            let seed_fwd = build_forwarding_state(&nat64_frag_snapshot());
            let seed_ha = txn_ha_state();
            let mut seed_binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
            seed_binding.interface = Arc::<str>::from("reth1.0");
            let mut seed_sessions = SessionTable::new();
            seed_sessions.set_max_sessions_for_test(16);
            let (_sb, seed_dbg) = txn_run_descriptor(
                &mut seed_binding,
                &mut seed_sessions,
                &seed_fwd,
                &seed_ha,
                &first,
                nat64_v6_frag_meta(first.len(), src, dst),
            );
            assert_eq!(seed_dbg.tx, 1, "the seed first fragment must translate + forward");
            let seed_authority = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
                &seed_fwd,
                nat64_v6_frag_meta(first.len(), src, dst),
                None,
            );
            let seed_key = crate::nat64::nat64_first_fragment_key(
                &first[14..],
                libc::AF_INET6,
                seed_authority,
            )
            .expect("seed key");
            seed_fwd
                .nat64
                .frag_assoc
                .lookup(&seed_key, 0, seed_fwd.nat64.build_generation, |_| true)
                .expect("the seed first fragment must have published an association")
                .0
        };

        let authority = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
            &forwarding,
            meta,
            None,
        );
        let key =
            crate::nat64::nat64_first_fragment_key(&first[14..], libc::AF_INET6, authority)
                .expect("seeded first-fragment key");
        // Install on the SAME clock the poll path reads (CLOCK_MONOTONIC), or the
        // entry is already past its 2s TTL by the time the consult runs and the
        // control below would fail for a timing reason rather than a filter one.
        forwarding.nat64.frag_assoc.install(
            key,
            decision,
            None,
            crate::afxdp::neighbor::monotonic_nanos(),
            forwarding.nat64.build_generation,
            0,
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "the seeded association must be live before the consult"
        );

        let (batch, dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            meta,
        );
        (batch.nat64_translations, dbg.tx)
    };

    // Control: with NO discard term the seeded association is inherited and the
    // fragment forwards + translates. This proves the seed is a REAL hit, so the
    // discarded case below cannot be passing for an unrelated reason.
    let (xlate_open, tx_open) = run(false);
    assert_eq!(
        tx_open, 1,
        "#5798 control: without an input-filter discard term the association hit must forward"
    );
    assert_eq!(
        xlate_open, 1,
        "#5798 control: the inherited fragment must be NAT64-translated"
    );

    // The guard: the same hit, with `from is-fragment then discard` on the
    // ingress interface, must be DROPPED rather than inheriting its way past the
    // per-packet filter.
    let (xlate_filtered, tx_filtered) = run(true);
    assert_eq!(
        tx_filtered, 0,
        "#5798: an association HIT must still be subject to the per-packet interface \
         input filter — `from is-fragment then discard` must drop it"
    );
    assert_eq!(
        xlate_filtered, 0,
        "#5798: the filtered fragment must not be NAT64-translated"
    );
}

/// #5798: a second interface in the SAME zone as `reth1.0`, so an end-to-end
/// test can vary the ingress INTERFACE without also varying the ingress ZONE.
/// Zone and interface are otherwise coupled in a forwarding state (a logical
/// ifindex maps to exactly one zone), which is precisely why keying on zone
/// alone would alias two interfaces that can carry DIFFERENT input filters.
fn nat64_frag_snapshot_with_second_lan_iface() -> ConfigSnapshot {
    let mut snapshot = nat64_frag_snapshot();
    snapshot.interfaces.push(crate::protocol::InterfaceSnapshot {
        name: "reth1.1".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1.1".to_string(),
        ifindex: 25,
        redundancy_group: 2,
        hardware_addr: "02:bf:72:01:00:02".to_string(),
        addresses: vec![crate::protocol::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:559:8585:ef01::1/64".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot
}

// #5798 FAIL-ON-REVERT: EVERY authority dimension must be threaded end to end,
// ONE AT A TIME.
//
// `nat64_cross_domain_nonfirst_fragment_does_not_inherit_5798` above changes the
// ingress ifindex AND the VLAN AND (consequently) the zone in a single step, so
// it would still pass if production keyed on the ifindex alone and ignored VLAN,
// zone and routing instance. This test perturbs exactly ONE dimension per case
// against a fixed baseline and PROVES the single-dimension claim by comparing
// the two `frag_ingress_authority` results field by field — a later fixture edit
// that silently perturbs two dimensions fails the `differing == 1` assertion
// rather than quietly weakening the guard.
//
//   - ifindex only: `reth1.1` (ifindex 25) is in the SAME `lan` zone as
//     `reth1.0` (ifindex 24), so the zone byte is IDENTICAL and only the
//     interface differs. This is the case zone-keying alone would alias.
//   - VLAN only: same physical ifindex 24, VLAN 80. `(24, 80)` resolves to no
//     logical unit, so `frag_ingress_authority` falls back to the PHYSICAL
//     ifindex — the exact fallback the `ingress_vlan_id` field exists to cover
//     (without it two VLAN siblings on one port collapse onto one authority).
//   - routing-instance only: same interface, same VLAN, `routing_table` 1.
//
// `ingress_zone` alone cannot be varied through the production path here: a
// forwarding state maps a logical ifindex to exactly one zone, so the only way
// to move the zone without moving the interface is a fabric/tunnel zone stamp,
// which this fixture has no ingress for.
//
// Be exact about what covers that dimension instead, because an earlier
// revision of this paragraph was not. It said the zone is "pinned in isolation
// by `frag_assoc_every_authority_dimension_is_load_bearing` (nat64_tests.rs),
// which drives the key builder directly" — and that overstated what the cited
// test can see. It hands `FragAuthority` STRUCT LITERALS to the key builders,
// so what it binds is the KEY'S EQUALITY being zone-sensitive; it never calls
// `frag_ingress_authority`, so it cannot tell whether production POPULATES the
// field at all. Measured: replacing the override argument at BOTH production
// sites with `None` compiled with zero errors and left the entire suite green.
//
// The PRODUCTION WIRING — `frag_authority_zone_override` at the install site
// and `ingress_zone_override` at the consult site (poll_descriptor/mod.rs) — is
// bound by `frag_assoc_authority_binds_the_fabric_zone_stamp_5798`
// (tests_fabric_zone_stamp.rs), which drives a real stamped fabric ingress
// through `poll_binding_process_descriptor`. Both kinds of coverage are needed,
// and neither substitutes for the other.
//
// RED on revert: drop any one of the three fields from `FragAuthority` (or stop
// threading it in `frag_ingress_authority`) and that case's fragment inherits →
// its `tx == 0` assertion goes RED.
#[test]
fn nat64_frag_authority_dimensions_are_threaded_end_to_end_5798() {
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let ident: u32 = 0x5798_0100;
    let first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
    let non_first = nat64_v6_frag_frame(0x0008, ident, src, dst, 0, 0);

    let base_meta = nat64_v6_frag_meta(non_first.len(), src, dst);
    let ifindex_only = UserspaceDpMeta {
        ingress_ifindex: 25,
        ..base_meta
    };
    let vlan_only = UserspaceDpMeta {
        ingress_vlan_id: 80,
        ..base_meta
    };
    // #6835 r2 (F-A): `routing_table` is INERT in production today. The only two
    // assignments are literal zero — the XDP writer (userspace-xdp/src/lib.rs)
    // and the Default impl (afxdp/types/mod.rs) — so no real packet ever carries
    // a non-zero value into `frag_ingress_authority`. This input is FABRICATED,
    // and the case is labelled for what it actually demonstrates: that the field
    // participates in the key's equality, not that a routing instance reaches
    // the key.
    //
    // Real VRF discrimination is nonetheless covered, by a different field.
    // Routing-instance membership is per-INTERFACE
    // (config.RoutingInstanceConfig.Interfaces), so two fragments in different
    // instances necessarily arrive on different interfaces and already differ in
    // `ingress_ifindex` — the first case below. The field is kept because the
    // key is then ready if the shim ever stamps it; if it is ever made live,
    // relabel this case and drive it from a real ingress instead.
    let vrf_only = UserspaceDpMeta {
        routing_table: 1,
        ..base_meta
    };

    for (dimension, perturbed) in [
        ("logical ingress interface (same zone)", ifindex_only),
        ("ingress VLAN (physical-ifindex fallback)", vlan_only),
        ("routing_table field participates in the key (FABRICATED input — inert in production)", vrf_only),
    ] {
        let forwarding = build_forwarding_state(&nat64_frag_snapshot_with_second_lan_iface());
        let ha_state = txn_ha_state();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        sessions.set_max_sessions_for_test(16);

        // Prove the SINGLE-dimension claim through the production resolver, not
        // by inspecting the meta literals: resolve both authorities and count
        // the fields that differ.
        let base_authority = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
            &forwarding,
            base_meta,
            None,
        );
        let other_authority = crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
            &forwarding,
            perturbed,
            None,
        );
        let differing = [
            base_authority.ingress_ifindex != other_authority.ingress_ifindex,
            base_authority.ingress_vlan_id != other_authority.ingress_vlan_id,
            base_authority.ingress_zone != other_authority.ingress_zone,
            base_authority.routing_table != other_authority.routing_table,
        ]
        .into_iter()
        .filter(|d| *d)
        .count();
        assert_eq!(
            differing, 1,
            "{dimension}: the production authority resolver must differ in EXACTLY one \
             dimension for this case to be a single-dimension guard (base {base_authority:?}, \
             perturbed {other_authority:?})"
        );

        // Domain A installs off a real committed first fragment.
        let (_b1, dbg1) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &first,
            nat64_v6_frag_meta(first.len(), src, dst),
        );
        assert_eq!(
            dbg1.tx, 1,
            "{dimension}: the baseline first fragment must translate + forward"
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "{dimension}: exactly one association is published"
        );

        // Same frame bytes, one dimension of ingress authority changed.
        let (b2, dbg2) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            perturbed,
        );
        assert_eq!(
            dbg2.tx, 0,
            "#5798: {dimension} must be load-bearing end to end — a non-first fragment \
             differing ONLY in it inherited the permit + egress + NAT64 translation"
        );
        assert_eq!(
            b2.nat64_translations, 0,
            "#5798: {dimension} — the refused fragment must not be NAT64-translated"
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "{dimension}: the baseline association must still be live (the fragment MISSED; \
             the entry did not expire or get evicted)"
        );

        // Positive control per case: the UNPERTURBED fragment still inherits, so
        // the negative assertion above cannot be satisfied by a cache/consult
        // that simply never returns a hit.
        let (b3, dbg3) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            base_meta,
        );
        assert_eq!(
            dbg3.tx, 1,
            "{dimension} control: the baseline-authority fragment must still inherit + forward"
        );
        assert_eq!(
            b3.nat64_translations, 1,
            "{dimension} control: the baseline fragment is still NAT64-translated"
        );
    }
}

// #5798 FAIL-ON-REVERT: the ORDERING property, over a real THREE-fragment
// datagram.
//
// Two fragments can show an association being created and consumed. They cannot
// show that state DECIDED by one domain is still refused to another domain after
// the association has already been used — which is the property this change
// exists to establish. So this submits three DISTINCT production descriptors
// with three distinct fragment offsets, in order:
//
//   1. first-A   (offset 0, MF=1)  — domain A, installs the association
//   2. middle-A  (offset 1, MF=1)  — domain A, HITS and forwards (positive)
//   3. last-B    (offset 2, MF=0)  — domain B, must be REFUSED
//
// Step 2 matters: it proves the refusal in step 3 is not just "the cache was
// never usable", and it exercises the refusal AFTER a hit has already refreshed
// the entry's TTL and touched its LRU position.
//
// RED on revert: pass a constant authority (or drop `authority` from the key)
// and step 3's `tx == 0` goes RED while steps 1-2 stay green.
#[test]
fn nat64_third_fragment_from_another_domain_refused_after_a_same_domain_hit_5798() {
    let forwarding = build_forwarding_state(&nat64_frag_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let ident: u32 = 0x5798_0003;

    // Three DISTINCT fragments of one datagram. The IPv6 Fragment Header
    // offset/flags word is `offset << 3 | MF`, so 0x0001 = offset 0 + MF,
    // 0x0009 = offset 1 + MF, 0x0010 = offset 2, MF clear (the last fragment).
    let frag1_first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
    let frag2_middle = nat64_v6_frag_frame(0x0009, ident, src, dst, 0, 0);
    let frag3_last = nat64_v6_frag_frame(0x0010, ident, src, dst, 0, 0);
    assert_ne!(
        frag2_middle, frag3_last,
        "the middle and last fragments must be DISTINCT descriptors, not the same bytes twice"
    );

    // (1) first-A installs.
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frag1_first,
        nat64_v6_frag_meta(frag1_first.len(), src, dst),
    );
    assert_eq!(dbg1.tx, 1, "the domain-A first fragment must translate + forward");
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "the committed first fragment publishes exactly one association"
    );

    // (2) middle-A HITS — the state is now not merely created but USED.
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frag2_middle,
        nat64_v6_frag_meta(frag2_middle.len(), src, dst),
    );
    assert_eq!(
        dbg2.tx, 1,
        "the SECOND domain-A fragment must inherit the association and forward"
    );
    assert_eq!(
        b2.nat64_translations, 1,
        "the inherited middle fragment is NAT64-translated"
    );

    // (3) last-B — same datagram identity, different security domain. Must be
    //     refused even though the association is live AND has just been hit.
    let mut meta_b = nat64_v6_frag_meta(frag3_last.len(), src, dst);
    meta_b.ingress_ifindex = 12;
    meta_b.ingress_vlan_id = 80;
    let (b3, dbg3) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frag3_last,
        meta_b,
    );
    assert_eq!(
        dbg3.tx, 0,
        "#5798: a THIRD fragment from another security domain must be refused even after \
         the association has already served a same-domain hit"
    );
    assert_eq!(
        b3.nat64_translations, 0,
        "#5798: the cross-domain last fragment must not be NAT64-translated"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "the association must still be live — the third fragment MISSED it"
    );

    // (4) And domain A can STILL use it afterwards: the refusal did not poison
    //     or evict the entry.
    let (b4, dbg4) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frag3_last,
        nat64_v6_frag_meta(frag3_last.len(), src, dst),
    );
    assert_eq!(
        dbg4.tx, 1,
        "control: the same LAST fragment, from domain A, must inherit and forward"
    );
    assert_eq!(
        b4.nat64_translations, 1,
        "control: the domain-A last fragment is still NAT64-translated"
    );
}

// #5798 counter-ownership FAIL-ON-REVERT: an accepted fragment must be counted
// EXACTLY ONCE on the association-hit arm — not zero times, not twice.
//
// #6835 INVERTED THE REASON, and the assertion below is unchanged only because
// the two errors it excludes swapped places. `routing_eval_follows` selects the
// #2620 policy: `true` means "an Accept verdict here proceeds to
// `ingress_route_table_override`, which counts the same terms", and defers the
// Accept-exit count to that evaluator (`OnlyTerminalNonAccept`) whenever the
// filter is route-lookup-affecting.
//
// Originally the hit arm called no routing evaluator at all, so `false`
// (`Always`) was the only way an accepted fragment got counted, and `true` would
// have deferred the count to something that never ran — an UNDER-count. #6835
// made the hit arm call `ingress_route_table_override` (it has to: that is where
// a matching PBR drop term is evaluated), so a routing evaluator now really does
// follow, and it counts every matched term unconditionally. `true` is therefore
// correct today and `false` would DOUBLE-count. Same assertion, opposite
// mutation.
//
// The filter here is route-lookup-affecting (a `routing-instance` term is
// present) but that term is scoped to UDP while the fragments are TCP, so it
// never matches and never steers a route — the filter's PBR-affecting FLAG is
// what selects the counter policy, which is exactly the input under test. (That
// same UDP scoping is why this test could not see the #6835 blocker: a PBR term
// the fragments never match never reaches the arm. See
// `nat64_frag_assoc_hit_applies_matching_pbr_discard_6927` for one that does.)
//
// RED on revert (MEASURED, not reasoned): set `routing_eval_follows = false` on
// the association-hit call in `poll_descriptor/mod.rs` and this reads 3 instead
// of 2. Three and not four because only the SECOND fragment double-counts — the
// first takes the flow-backed miss arm, whose `routing_eval_follows` is
// untouched at `true`, so it still counts exactly once.
#[test]
fn nat64_frag_assoc_hit_counts_route_lookup_affecting_input_filter_5798() {
    use std::sync::atomic::Ordering;

    let mut snapshot = nat64_frag_snapshot();
    let iface = snapshot
        .interfaces
        .iter_mut()
        .find(|i| i.name == "reth1.0")
        .expect("reth1.0 in the fixture");
    iface.filter_input_v6 = "pbr-count6".to_string();
    snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
        name: "pbr-count6".to_string(),
        family: "inet6".to_string(),
        terms: vec![
            // Makes the filter route-lookup-affecting. Scoped to UDP, so it
            // never matches these TCP fragments and never steers a route.
            crate::protocol::FirewallTermSnapshot {
                name: "steer-udp".to_string(),
                protocols: vec!["udp".to_string()],
                routing_instance: "scrub".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
            crate::protocol::FirewallTermSnapshot {
                name: "count-all".to_string(),
                action: "accept".to_string(),
                count: "c-frag6".to_string(),
                ..Default::default()
            },
        ],
    });

    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        crate::filter::interface_filter_affects_route_lookup(&forwarding.filter_state, 24, true),
        "precondition: the fixture filter must be route-lookup-affecting, or the buggy \
         counter policy is never selected and this test cannot fail"
    );
    let counter = forwarding
        .filter_state
        .iface_filter_v6_fast
        .get(&24)
        .expect("input filter compiled for ifindex 24")
        .terms
        .get(1)
        .expect("the count term")
        .counter
        .clone();
    assert_eq!(counter.packets.load(Ordering::Relaxed), 0);

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let ident: u32 = 0x5798_0004;

    // Fragment 1 (first): flow-backed cold path. Its Accept exit legitimately
    // defers to the routing evaluator, which DOES run there and counts.
    let first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
    let (_b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(dbg1.tx, 1, "the first fragment must translate + forward");
    assert_eq!(
        counter.packets.load(Ordering::Relaxed),
        1,
        "the first fragment counts once (the routing evaluator owns its Accept-exit count)"
    );

    // Fragment 2 (non-first): association HIT. #6835 added a routing evaluator
    // to this arm (`ingress_route_table_override`, poll_descriptor/mod.rs), so
    // the hit path passes `routing_eval_follows = true` and the ROUTING walk
    // owns the Accept-exit count — the same ownership the miss arm has. The
    // count still lands once per fragment; what changed is which evaluator
    // records it.
    let non_first = nat64_v6_frag_frame(0x0008, ident, src, dst, 0, 0);
    let mut meta = nat64_v6_frag_meta(non_first.len(), src, dst);
    // The shared NAT64 fragment fixture leaves `flow_{src,dst}_addr` zeroed;
    // `l3_session_flow_from_meta` returns None for an unspecified address and
    // the hit-arm filter block is gated on it, so without these the block is
    // skipped and the test would pass vacuously. Production always has them
    // stamped by the shim.
    meta.flow_src_addr = src.octets();
    meta.flow_dst_addr = dst.octets();
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        meta,
    );
    assert_eq!(
        dbg2.tx, 1,
        "the non-first fragment must inherit the association and forward"
    );
    assert_eq!(
        b2.nat64_translations, 1,
        "the inherited fragment is NAT64-translated"
    );
    assert_eq!(
        counter.packets.load(Ordering::Relaxed),
        2,
        "#5798/#6835: the hit fragment must be counted exactly ONCE. Shipped value is \
         `routing_eval_follows = true`, which defers the Accept-exit count to the routing \
         evaluator that now runs on this arm. MEASURED on revert to `false`: this reaches 3, \
         not 2 — `Always` counts here AND the routing walk counts again, double-counting the \
         second fragment only (the first takes the miss arm, where `true` was already right)"
    );
}

// ---------------------------------------------------------------------------
// #6835: what a fragment-association HIT may and may not inherit.
//
// The association exists so the rest of a datagram reuses the FIRST fragment's
// stateful decision — zone-policy permit, NAT translation, egress route. #5798
// established that per-packet INTERFACE INPUT FILTER semantics are not part of
// that inheritance. These pin the two enforcement gates that were still being
// inherited, plus the fail-closed claim that turned out to be enforced by a
// test fixture rather than by production.
// ---------------------------------------------------------------------------

/// An HA runtime whose RGs exist but are NOT forwarding-active — the state the
/// OLD owner is in immediately after an RG transition. Deliberately built from
/// the same shape as `txn_ha_state` so the only difference between the control
/// and the subject below is `active`.
fn txn_ha_state_inactive() -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha = BTreeMap::new();
    for rg in [1, 2] {
        ha.insert(
            rg,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 123,
                lease: HAGroupRuntime::active_lease_until(123, 123),
            },
        );
    }
    ha
}

/// #6835 B1 FAIL-ON-REVERT: a matching PBR term with a drop action must DROP the
/// fragment on an association hit, and must record its counter.
///
/// `evaluate_non_pbr_input_filter` — the only filter evaluator the hit arm ran
/// before #6835 — returns `FilterResult::default()` the moment a matching term
/// carries a non-empty `routing-instance`, BEFORE recording its counter and
/// BEFORE applying its action. `FilterResult::default().action` is `Accept`. So
/// a configured `then { routing-instance scrub; discard; count X; }` was
/// silently ACCEPTED and `X` stayed at zero: the drop guard could not fire and
/// nothing counted to show it.
///
/// The term ORDER is what makes this reachable rather than hypothetical, and it
/// is also what the PR's existing counter test lacked — its PBR term was scoped
/// to UDP while the fragments were TCP, so it never reached the arm at all:
///   * `allow-443` matches the FIRST fragment on `destination-port 443` and
///     terminates, so the first fragment forwards and installs the association;
///   * `scrub-frags` matches the NON-FIRST fragment on `is-fragment` — the
///     port term above fails closed for it (`l4_present = false`, ports 0/0) —
///     and carries the PBR drop.
///
/// RED on revert: remove the `ingress_route_table_override` block from the
/// association-hit arm in `poll_descriptor/mod.rs` and BOTH the `dbg2.tx == 0`
/// and the `counter == 1` assertions fail.
#[test]
fn nat64_frag_assoc_hit_applies_matching_pbr_discard_6927() {
    use std::sync::atomic::Ordering;

    let mut snapshot = nat64_frag_snapshot();
    let iface = snapshot
        .interfaces
        .iter_mut()
        .find(|i| i.name == "reth1.0")
        .expect("reth1.0 in the fixture");
    iface.filter_input_v6 = "pbr-drop6".to_string();
    snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
        name: "pbr-drop6".to_string(),
        family: "inet6".to_string(),
        terms: vec![
            crate::protocol::FirewallTermSnapshot {
                name: "allow-443".to_string(),
                destination_ports: vec!["443".to_string()],
                action: "accept".to_string(),
                ..Default::default()
            },
            crate::protocol::FirewallTermSnapshot {
                name: "scrub-frags".to_string(),
                is_fragment: true,
                routing_instance: "scrub".to_string(),
                action: "discard".to_string(),
                count: "c-pbr-frag6".to_string(),
                ..Default::default()
            },
        ],
    });

    let forwarding = build_forwarding_state(&snapshot);
    let counter = forwarding
        .filter_state
        .iface_filter_v6_fast
        .get(&24)
        .expect("input filter compiled for ifindex 24")
        .terms
        .get(1)
        .expect("the PBR drop term")
        .counter
        .clone();
    assert_eq!(counter.packets.load(Ordering::Relaxed), 0);

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let ident: u32 = 0x6927_0001;

    // POSITIVE CONTROL: the first fragment is permitted by `allow-443`,
    // translates, forwards, and installs the association. Without this the
    // `tx == 0` below could just mean nothing was ever cached.
    let first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
    let (b1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(
        dbg1.tx, 1,
        "#6835: the first fragment must be permitted by the port term and forward, or no \
         association is installed and the hit path below is never exercised"
    );
    assert_eq!(b1.nat64_translations, 1);

    let non_first = nat64_v6_frag_frame(0x0008, ident, src, dst, 0, 0);
    let mut meta = nat64_v6_frag_meta(non_first.len(), src, dst);
    meta.flow_src_addr = src.octets();
    meta.flow_dst_addr = dst.octets();
    let (b2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        meta,
    );
    assert_eq!(
        dbg2.tx, 0,
        "#6835: a matching PBR `routing-instance + discard` term must DROP the fragment on an \
         association hit. It forwarded — the non-PBR evaluator returns Accept for a matching \
         routing-instance term, so the configured drop guard never fires"
    );
    assert_eq!(
        b2.nat64_translations, 0,
        "#6835: a dropped fragment must not be counted as a NAT64 translation"
    );
    assert_eq!(
        counter.packets.load(Ordering::Relaxed),
        1,
        "#6835: the PBR term's `then count` must record the fragment it dropped — without it an \
         operator cannot even see that the guard fired"
    );
}

/// #6835 B2 FAIL-ON-REVERT: an association hit must re-check owner-RG activity.
///
/// The association is process-local and survives an RG transition untouched, and
/// every hit re-stamps its deadline, so the OLD owner kept serving hits from a
/// group it no longer owns — indefinitely. `enforce_ha_resolution_snapshot` is
/// the guard that demotes an inactive owner to `HAInactive`, and before #6835 it
/// ran only on the miss path's freshly-resolved decision, never on the cached
/// one.
///
/// The pair is the point: the same association SHAPE, installed under the ACTIVE
/// runtime in both legs and then replayed against an ACTIVE and an INACTIVE one,
/// must give different outcomes. The active leg is what excludes "the fragment
/// stopped forwarding for some other reason".
///
/// The two legs use DIFFERENT fragment identifiers, so they mint two distinct
/// entries rather than sharing one (#6835 r2). That is deliberate isolation, not
/// an oversight: a shared entry would let the active leg's consult re-stamp the
/// deadline before the inactive leg ran. It does not weaken the test, because
/// the closure installs from a first fragment under `&active` in BOTH legs and
/// asserts `dbg1.tx == 1`, so the inactive leg is provably consulting a LIVE
/// association rather than missing. Measured: removing
/// `enforce_ha_resolution_snapshot` from the hit arm makes the inactive leg
/// forward (`left: 1, right: 0`), so the drop is that guard and nothing else.
///
/// RED on revert: drop the `enforce_ha_resolution_snapshot` call from the hit arm
/// and the inactive leg forwards (`tx == 1`) exactly like the active one.
#[test]
fn nat64_frag_assoc_hit_reenforces_owner_rg_6927() {
    let snapshot = nat64_frag_snapshot();
    let forwarding = build_forwarding_state(&snapshot);
    let active = txn_ha_state();
    let inactive = txn_ha_state_inactive();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");

    // One helper run: install an association from a first fragment under the
    // ACTIVE runtime, then replay a non-first fragment under `ha` and report
    // whether it forwarded.
    let mut run = |ha: &BTreeMap<i32, HAGroupRuntime>, ident: u32| -> u64 {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        sessions.set_max_sessions_for_test(16);

        let first = nat64_v6_frag_frame(0x0001, ident, src, dst, 12345, 443);
        let (_b1, dbg1) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &active,
            &first,
            nat64_v6_frag_meta(first.len(), src, dst),
        );
        assert_eq!(
            dbg1.tx, 1,
            "#6835: the first fragment must forward under the ACTIVE runtime and install the \
             association — the transition is modelled as happening AFTER it"
        );

        let non_first = nat64_v6_frag_frame(0x0008, ident, src, dst, 0, 0);
        let mut meta = nat64_v6_frag_meta(non_first.len(), src, dst);
        meta.flow_src_addr = src.octets();
        meta.flow_dst_addr = dst.octets();
        let (_b2, dbg2) =
            txn_run_descriptor(&mut binding, &mut sessions, &forwarding, ha, &non_first, meta);
        dbg2.tx
    };

    assert_eq!(
        run(&active, 0x6927_0002),
        1,
        "control: while this node still owns the RG, the non-first fragment inherits the \
         association and forwards"
    );
    assert_eq!(
        run(&inactive, 0x6927_0003),
        0,
        "#6835: after an RG transition the old owner must NOT keep serving association hits. The \
         cached decision was returned without re-checking owner-RG activity, and because every \
         hit re-stamps the entry's deadline the stale ownership was indefinitely renewable"
    );
}

/// #6835 B3 FAIL-ON-REVERT: an association MISS must drop even with a v6 default
/// route present.
///
/// The #4617 fail-closed claim — "an unassociated NAT64 non-first fragment
/// drops" — was not enforced by any production code. The consult returns `None`
/// on a miss, which only means "no association"; the packet then resolved like
/// any other IPv6 destination and, with `::/0` in the FIB, FORWARDED — still
/// addressed to the synthetic Pref64 destination and still carrying the client's
/// real IPv6 source. Every test passed because the fixture DELETED the default
/// route.
///
/// The route deletion is gone (see `nat64_frag_snapshot`), so this test now
/// asserts the claim against the condition that falsified it. The first
/// assertion is the load-bearing precondition: without `::/0` present this test
/// proves nothing at all.
///
/// RED on revert: remove the Pref64-destination gate from the flowless arm in
/// `poll_descriptor/mod.rs` and this forwards (`tx == 1`).
#[test]
fn nat64_frag_assoc_miss_must_drop_with_default_route_6927() {
    let mut snapshot = nat64_frag_snapshot();
    assert!(
        snapshot
            .routes
            .iter()
            .any(|r| r.family == "inet6" && r.destination == "::/0"),
        "#6835: the fixture MUST carry a v6 default route — deleting it is what hid this leak, \
         and without it the drop below happens for the wrong reason (no route) and proves nothing"
    );
    // ISOLATE THE GATE UNDER TEST. `nat_snapshot` carries an interface-SNAT rule
    // covering `::/0` lan->wan, and the #6122 same-family gate claims any
    // fragment it would translate — including this one, for a reason that has
    // nothing to do with NAT64. Leaving it in would make this test pass with the
    // Pref64 gate deleted, which is the failure mode the whole exercise is
    // about. With no same-family NAT configured #6122 fast-outs, so the only
    // thing that can stop this fragment is the gate being tested.
    snapshot.source_nat_rules.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");

    // No first fragment: nothing installs an association, so this is a MISS.
    let non_first = nat64_v6_frag_frame(0x0008, 0x6927_0004, src, dst, 0, 0);
    let mut meta = nat64_v6_frag_meta(non_first.len(), src, dst);
    meta.flow_src_addr = src.octets();
    meta.flow_dst_addr = dst.octets();
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        meta,
    );
    assert_eq!(
        dbg.tx, 0,
        "#6835: a NAT64 fragment-association MISS must DROP. It forwarded — untranslated, to a \
         synthetic Pref64 destination no downstream router can deliver, with the client's real \
         IPv6 source still on the wire"
    );
    assert_eq!(
        batch.nat64_translations, 0,
        "#6835: a miss must not translate — there is no cached mapping to translate with"
    );
    assert_eq!(
        batch.nat64_frag_dropped, 1,
        "#6835: the fail-closed drop must be observable on the #2562 NAT64 fragment-drop counter"
    );
    assert_eq!(
        batch.nat_frag_untranslated_dropped, 0,
        "#6835: ATTRIBUTION — the drop must come from the Pref64 gate, not from the #6122 \
         same-family gate. If this moves instead, the assertion above is being satisfied by a \
         different gate and the Pref64 one could be deleted with this test still green"
    );

    // OVER-REACH GUARD, GREEN under the revert: an ordinary IPv6 destination
    // OUTSIDE every configured Pref64 still FORWARDS on the same arm, over the
    // same `::/0` route, in the same NAT-free snapshot. This is what excludes a
    // gate that has quietly become a blanket flowless-fragment drop.
    // OFF-link on purpose: an address inside the connected `2001:559:8585:80::/64`
    // resolves through its own (absent) neighbor entry and stalls on
    // MissingNeighbor, which would make this leg drop for a reason unrelated to
    // the gate. This one takes the `::/0` next hop, whose neighbor the fixture
    // declares reachable — the same path the Pref64 destination above took.
    let plain_dst: Ipv6Addr = "2606:4700:4700::1111".parse().expect("plain v6 dst");
    let plain = nat64_v6_frag_frame(0x0008, 0x6927_0005, src, plain_dst, 0, 0);
    // #6836: the meta is constructed with the frame's OWN dst. Passing the
    // NAT64 `dst` here and repairing it on the next two lines worked, and it is
    // exactly the fixture/frame disagreement the parameterisation exists to
    // prevent: the repair lines look redundant, and deleting them would
    // reintroduce a meta that describes a packet the frame does not carry.
    let plain_meta = nat64_v6_frag_meta(plain.len(), src, plain_dst);
    let (plain_batch, plain_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &plain,
        plain_meta,
    );
    assert_eq!(
        plain_dbg.tx, 1,
        "#6835: a non-first fragment to an ORDINARY IPv6 destination must still forward over \
         `::/0` — the Pref64 gate is scoped to the translation prefix, not to flowless IPv6 \
         fragments in general"
    );
    assert_eq!(
        plain_batch.nat64_frag_dropped, 0,
        "#6835: and it must not be accounted as a NAT64 fail-closed drop"
    );
}

/// #6836: the flowless egress filter-log path, exercised for the first time —
/// and what it actually shows is a FAMILY asymmetry, not a missing log.
///
/// `forward_request.rs`'s flowless branch (#5467) rebuilds an L3-only flow
/// solely to attribute a filter-log event for a packet with no
/// `tx_selection_flow`. It had never run under a NAT64 fixture, because two
/// independent conditions gate it and no NAT64 fixture satisfied either: the
/// meta fixtures left the flow addresses zeroed, and none ever set an output
/// filter.
///
/// # The asymmetry, measured
///
/// `resolve_cos_tx_selection_at` picks the output-filter family from the
/// egress `flow_key` when there is one, and falls back to the INGRESS
/// `meta.addr_family` when there is not (`cos_classify.rs`, "Fall back to the
/// ingress meta family only on the flowless / default-queue path"). Under NAT64
/// the packet CHANGES family, so:
///
///     first fragment  (has a flow_key)  -> evaluated against the egress V4 filter
///     non-first frag  (flowless)        -> evaluated against the egress V6 filter
///
/// Both leave the box as IPv4 on the same interface. An operator who applies a
/// v4 output filter to that v4 egress sees the first fragment and not the rest.
///
/// # This test asserts the behaviour, not a gap
///
/// An earlier version of this cell attached only a v4 filter, observed
/// `filter_log.sent == 0` for the flowless packet, and concluded the branch did
/// not run. That was wrong, and wrong in the way this whole issue is about:
/// zero is also what you get when no filter of the looked-up family exists, so
/// the assertion could not tell "the branch is broken" from "nothing matched".
/// Deleting the entire #5467 branch left it green.
///
/// Both arms are now asserted, which is what makes either mean anything: with
/// the v6 filter the flowless packet IS logged, and with only the v4 filter it
/// is not.
#[test]
fn nat64_flowless_fragment_uses_the_ingress_family_output_filter_6836() {
    // Each arm attaches filters to the SAME v4 egress interface and states the
    // expected event count for BOTH packets: the flow-bearing first fragment
    // (which has an egress flow_key, so it selects the v4 egress family) and
    // the flowless non-first fragment (which has none, so it falls back to the
    // INGRESS meta family, v6).
    //
    // Arm 3 is the one that binds the property in this test's name, and arms 1
    // and 2 cannot do it on their own. Arm 2's zero is ALSO explained by "no v6
    // filter is configured on the box at all": with no v6 filter the per-family
    // short-circuit in resolve_cos_tx_selection_at returns before any lookup, so
    // that zero holds whichever family the flowless path selects. Measured:
    // inverting the fallback to use the egress family instead of the ingress
    // meta left BOTH of the original arms green.
    //
    // Arm 3 removes that escape. Both families have a filter, so neither
    // aggregate short-circuits, and only the V6 one logs. The expected pair is
    // then first=0 / flowless=1, which is producible ONLY if the two packets
    // select DIFFERENT families -- exactly the asymmetry under test.
    for tc in [
        (
            "both families log: the flowless arm finds the v6 filter",
            true,
            true,
            1u64,
            1u64,
        ),
        (
            "v4 filter only: the flowless arm looks up v6 and finds nothing",
            false,
            true,
            1u64,
            0u64,
        ),
        (
            "ONLY the v6 filter logs: the selected FAMILY is the sole difference",
            true,
            false,
            0u64,
            1u64,
        ),
    ] {
        let (name, attach_v6, v4_logs, want_first, want_flowless) = tc;
        t_run_6836(name, attach_v6, v4_logs, want_first, want_flowless);
    }
}

fn t_run_6836(
    name: &str,
    attach_v6: bool,
    v4_logs: bool,
    want_first_events: u64,
    want_flowless_events: u64,
) {
    let mut snapshot = nat64_frag_snapshot();

    let egress = snapshot
        .interfaces
        .iter_mut()
        .find(|i| i.name == "reth0.80")
        .expect("#6836 premise: the NAT64 fixture must have the reth0.80 v4 egress");
    egress.filter_output_v4 = "nat64-egress-v4".to_string();
    if attach_v6 {
        egress.filter_output_v6 = "nat64-egress-v6".to_string();
    }

    // A filter that is PRESENT but does not log is the whole point of arm 3:
    // presence keeps the per-family aggregate enabled (so no short-circuit),
    // while `log: false` means an event can only have come from the other
    // family.
    let term = |n: &str, logs: bool| crate::protocol::FirewallFilterSnapshot {
        name: n.to_string(),
        family: if n.ends_with("v6") { "inet6" } else { "inet" }.to_string(),
        terms: vec![crate::protocol::FirewallTermSnapshot {
            name: "log-all".to_string(),
            action: "accept".to_string(),
            log: logs,
            ..Default::default()
        }],
    };
    snapshot.filters = vec![term("nat64-egress-v4", v4_logs)];
    if attach_v6 {
        snapshot.filters.push(term("nat64-egress-v6", true));
    }

    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808"
        .parse()
        .expect("nat64 dst (extracts 8.8.8.8)");

    // BOTH packets go through the CAPTURING runner, and that is load-bearing.
    // `txn_run_descriptor` passes a fixed `123_000_000_000` for `now_ns` while
    // the capturing variant passes real `monotonic_nanos()`. Mixing them hands
    // the two packets clocks billions of nanoseconds apart, so the association
    // the first installs is not valid for the second and the non-first fragment
    // silently does not forward -- `tx=0` with NO drop counted, which reads as
    // "this test is wrong" rather than "the helpers disagree about time".
    let first = nat64_v6_frag_frame(0x0001, 0x1234_5678, src, dst, 12345, 443);
    let (b1, dbg1, first_handle, _rx1) = txn_run_descriptor_capturing_events(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(
        dbg1.tx, 1,
        "{name}: the first fragment must translate and forward"
    );
    assert_eq!(
        b1.nat64_translations, 1,
        "{name}: the first fragment must be NAT64-TRANSLATED. Without this, \
         `tx == 1` proves only that something forwarded -- a regression that kept \
         the cached resolution but lost decision.nat would forward it as native \
         IPv6, never reach the v4 egress filter, and still satisfy every other \
         assertion here"
    );
    // The flow-bearing fragment HAS an egress flow_key, so it selects the v4
    // egress family and is evaluated against the v4 filter. In arms 1 and 2
    // that filter logs, so this is 1 and serves as the liveness control -- if
    // it were 0 the fixture would log nothing anywhere and the flowless
    // assertion below would prove nothing.
    //
    // In arm 3 the v4 filter deliberately does NOT log, so this is 0 -- and
    // that zero is half the discriminator rather than a missing control: paired
    // with a flowless count of 1, it says the two packets resolved to DIFFERENT
    // families. Liveness for arm 3 comes from the flowless assertion being 1.
    assert_eq!(
        first_handle.dataplane_event_stats().filter_log.sent,
        want_first_events,
        "{name}: the flow-bearing first fragment is evaluated against the EGRESS \
         (v4) family because it has a flow_key. Expected {want_first_events} event(s)."
    );

    let non_first = nat64_v6_frag_frame(0x0008, 0x1234_5678, src, dst, 0, 0);
    let (b2, dbg2, second_handle, _rx2) = txn_run_descriptor_capturing_events(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        nat64_v6_frag_meta(non_first.len(), src, dst),
    );
    assert_eq!(
        dbg2.tx, 1,
        "{name}: the inheriting non-first fragment must forward"
    );
    assert_eq!(
        b2.nat64_translations, 1,
        "{name}: the non-first fragment must ALSO be NAT64-translated -- it is the \
         packet under test and it must leave as IPv4 for the family question to mean \
         anything"
    );

    assert_eq!(
        second_handle.dataplane_event_stats().filter_log.sent,
        want_flowless_events,
        "{name}: the flowless arm selects the output-filter family from the INGRESS \
         meta (v6 here), not from the v4 egress the packet actually leaves by. So a \
         v6 filter on that interface logs it and a v4 filter does not, even though \
         the packet on the wire is IPv4."
    );
}

/// #6857 WIRING: the install SITE must derive the owner RG, not stamp a
/// constant.
///
/// The cells in nat64_tests.rs call `Nat64FragAssoc::install` directly with an
/// explicit owner RG, so they pin the fence and say nothing about where the
/// stamp comes from. The mutation matrix proved it: replacing the
/// `owner_rg_for_resolution(...)` call at both install sites with a literal `0`
/// left the ENTIRE suite green — the fence was correct and permanently unarmed,
/// because owner RG 0 is deliberately never fenced.
///
/// This drives a real NAT64 first fragment through `txn_run_descriptor` with an
/// RG-bound egress, then asks the published association which RG it carries.
#[test]
fn nat64_frag_assoc_install_site_derives_the_owner_rg_6857() {
    let mut forwarding = build_forwarding_state(&nat64_frag_snapshot());
    // Bind every egress to RG 3. The fixture binds none, so without this the
    // derivation returns 0 legitimately and the cell could not tell a derived
    // zero from a hardcoded one.
    for iface in forwarding.egress.values_mut() {
        iface.redundancy_group = 3;
    }
    // RG 3 must be forwarding-active for the first fragment to be admitted at
    // all — the install is what publishes the association this cell reads.
    // txn_ha_state() only carries RGs 1 and 2, and the PREMISE assertion below
    // is what turned that omission into a named failure rather than an empty
    // read.
    let mut ha_state = txn_ha_state();
    ha_state.insert(
        3,
        crate::afxdp::types::HAGroupRuntime {
            active: true,
            watchdog_timestamp: 123,
            lease: crate::afxdp::types::HAGroupRuntime::active_lease_until(123, 123),
        },
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let first = nat64_v6_frag_frame(0x0001, 0x1234_5678, src, dst, 12345, 443);
    let (_b, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        nat64_v6_frag_meta(first.len(), src, dst),
    );
    assert_eq!(
        dbg.tx, 1,
        "#6857 PREMISE: the first fragment must translate and forward, or no \
         association is published and the assertion below reads nothing"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "#6857 PREMISE: exactly one association must have been published"
    );

    // Ask the association which RG it carries, by recording what the fence
    // predicate is asked about. A hardcoded 0 never reaches the predicate at
    // all, because owner_rg 0 is deliberately not fenced.
    let non_first = nat64_v6_frag_frame(0x0008, 0x1234_5678, src, dst, 0, 0);
    let key = crate::nat64::nat64_nonfirst_fragment_key(
        &non_first[14..],
        libc::AF_INET6,
        crate::afxdp::poll_descriptor::frag_assoc::frag_ingress_authority(
            &forwarding,
            nat64_v6_frag_meta(non_first.len(), src, dst),
            None,
        ),
    );
    let Some(key) = key else {
        panic!("#6857: could not build the non-first fragment key");
    };
    let asked = std::cell::Cell::new(Vec::<i32>::new());
    let hit =
        forwarding
            .nat64
            .frag_assoc
            .lookup(&key, 1_000, forwarding.nat64.build_generation, |rg| {
                let mut v = asked.take();
                v.push(rg);
                asked.set(v);
                true
            });
    assert!(
        hit.is_some(),
        "#6857 PREMISE: the association must be findable"
    );
    assert_eq!(
        asked.take(),
        vec![3],
        "#6857: the install site must DERIVE the owner RG from the resolution. \
         An empty list means the entry carries 0, so the fence can never fire \
         and the whole change is inert — which is exactly what the matrix saw \
         when the derivation was replaced by a literal"
    );
}
