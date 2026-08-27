// GRE-to-self delivery, junos-host / host-inbound local delivery, and native GRE decap.
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

/// #1885 session-HIT pin: the live keepalive/echo-reply stream rides
/// an EXISTING session (the first packet installs it), so the
/// session-hit leg must ALSO deliver the decapped inner packet
/// exactly once. Runs the same tagged GRE-to-self frame twice through
/// one (binding, sessions) pair and asserts both deliveries.
#[test]
fn gre_to_self_session_hit_delivery_is_inner_packet_exactly_once() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    for pass in ["session-miss", "session-hit"] {
        let meta = gre_to_self_outer_meta(80, frame.len());
        txn_run_descriptor_with_deliveries(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
            &local_tunnel_deliveries,
        );
        let delivered = rx.try_recv().unwrap_or_else(|_| {
            panic!("{pass} pass must deliver the inner packet to the gr- channel")
        });
        assert_eq!(
            delivered, inner,
            "{pass} pass delivery must be the decapped INNER packet byte-identical"
        );
        assert!(
            rx.try_recv().is_err(),
            "{pass} pass must deliver exactly once"
        );
    }
}


/// #1885: VLAN-tagged underlay (the live reth0.80 topology). Pre-fix
/// the LocalDelivery arm sliced the ORIGINAL tagged outer frame at the
/// post-decap inner meta's l3_offset (14) — the payload started with
/// the dot1q TCI tail (`00 50 86 dd ...` in the issue strace) and
/// every TUN write failed EINVAL.
#[test]
fn gre_to_self_vlan_tagged_local_delivery_is_inner_packet_exactly_once() {
    assert_gre_to_self_delivers_inner_exactly_once(80);
}


/// #1885 blast radius: on an UNTAGGED underlay the mis-paired slice
/// started at the outer L3 header — a valid version nibble, so the TUN
/// write SUCCEEDED but delivered the still-encapsulated OUTER packet.
/// Byte-equality (not just the nibble check) pins this case.
#[test]
fn gre_to_self_untagged_local_delivery_is_inner_packet_exactly_once() {
    assert_gre_to_self_delivers_inner_exactly_once(0);
}


/// #1885 blast radius: NON-decapped local delivery was enqueued TWICE
/// (the in-arm desc-based call duplicated the leg's trailing
/// decap-aware chokepoint — both pass the same disposition filter).
/// A host-bound packet whose `local_ifindex` is not a registered
/// tunnel channel funnels to the kernel slow-path TUN; with no
/// reinjector wired the per-attempt `slow_path_drops` counter is the
/// enqueue-attempt observable: pre-#1885 this read 2, fixed it must
/// read exactly 1.
#[test]
fn unencapsulated_local_delivery_reinjects_slow_path_exactly_once() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    let (_batch, dbg) = txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert!(
        rx.try_recv().is_err(),
        "a non-tunnel-ingress local packet must NOT hit the gr- channel"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "exactly ONE slow-path enqueue attempt per LocalDelivery packet \
         (#1885 duplicate-enqueue pin — the in-arm call would make it 2)"
    );
}


/// #3019 LITERAL fail-on-revert (session-MISS): a `from-zone lan to-zone
/// junos-host then deny` policy DROPS a host-bound packet on the LocalDelivery
/// session-miss path, AFTER host-inbound admission. The packet is denied
/// (dbg.policy_deny == 1), never reaches the slow-path reinject
/// (slow_path_drops == 0), and no host-local session is cached. Remove the
/// `junos_host_policy_drops` call in the session-miss LocalDelivery arm and
/// this test goes RED (the packet would reinject to the slow path instead),
/// while `poll_descriptor_no_junos_host_policy_local_delivery_unchanged_session_miss`
/// stays GREEN.
#[test]
fn poll_descriptor_junos_host_deny_drops_local_delivery_session_miss() {
    let forwarding = build_forwarding_state(&junos_host_local_delivery_snapshot(Some("deny")));
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    let (_batch, dbg) = txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        dbg.policy_deny, 1,
        "to-zone junos-host deny must drop the host-bound packet"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "a junos-host-denied host-bound packet must NOT reach the slow-path \
         reinject (#3019 — the deny short-circuits before should_cache)"
    );
    assert_eq!(
        sessions.len(),
        0,
        "no host-local session may be cached for a junos-host-denied flow"
    );
    assert!(
        rx.try_recv().is_err(),
        "a denied packet must not reach any delivery channel"
    );
}


/// #3019 lifeline fail-safe (session-MISS GREEN pair): with NO junos-host
/// policy configured, a host-bound packet keeps pre-#3019 behavior — admitted
/// (dbg.policy_deny == 0) and reinjected to the slow path (slow_path_drops ==
/// 1). This stays GREEN when the LocalDelivery policy-eval call is removed,
/// proving the deny test above is the literal fail-on-revert sentinel and that
/// the change cannot newly deny management/host traffic.
#[test]
fn poll_descriptor_no_junos_host_policy_local_delivery_unchanged_session_miss() {
    let forwarding = build_forwarding_state(&junos_host_local_delivery_snapshot(None));
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    let (_batch, dbg) = txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        dbg.policy_deny, 0,
        "no junos-host policy: host-bound packet must not be policy-denied"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "no junos-host policy: host-bound packet keeps pre-#3019 slow-path reinject"
    );
    assert!(rx.try_recv().is_err());
}


/// #3706 LITERAL fail-on-revert (session-MISS): a `from-zone lan to-zone
/// junos-host then permit log session-init session-close` policy admits a
/// host-bound flow, and the installed local-delivery session MUST carry BOTH
/// log flags, the admitting `policy_id`, and a non-zero hit-counter handle.
/// Before #3706 the junos-host permit gate discarded its
/// [`PolicyEvaluationResult`], so the session installed with
/// `log_session_init`/`log_session_close = false`, `policy_id = 0`, and
/// `policy_counter_idx = 0` — the host-bound management session was unlogged and
/// unattributable. Revert the `JunosHostLocalPolicy::Permit` stamp (drop the
/// permit result on the local-delivery path) and this test goes RED, while
/// `poll_descriptor_junos_host_permit_no_log_local_delivery_no_overlog` stays
/// GREEN (a bare permit must not over-log).
#[test]
fn poll_descriptor_junos_host_permit_log_stamps_local_delivery_session_miss() {
    let snapshot = junos_host_local_delivery_permit_snapshot(true, true, 4242);
    let (log_init, log_close, policy_id, counter_idx) =
        run_junos_host_permit_local_delivery(&snapshot);

    assert!(
        log_init,
        "#3706: to-zone junos-host `then permit log session-init` must stamp \
         log_session_init on the installed host-local session (was false)"
    );
    assert!(
        log_close,
        "#3706: `then permit log session-close` must stamp log_session_close \
         on the installed host-local session (was false)"
    );
    assert_eq!(
        policy_id, 4242,
        "#3706: the admitting junos-host policy id must be stamped so the \
         SESSION_CREATE/CLOSE RT_FLOW record attributes the flow (was the 0 \
         sentinel)"
    );
    assert_ne!(
        counter_idx, 0,
        "#3706: the admitting junos-host rule's 1-based hit-counter handle must \
         be stamped (was the 0 no-counter sentinel)"
    );
}


/// #3706 GREEN pair (session-MISS): a `to-zone junos-host then permit` policy
/// with NO `then log` clause installs the host-local session but MUST NOT set
/// either log flag — proving the #3706 stamp propagates the policy's ACTUAL log
/// selection and does not blanket-log every permitted host-bound flow. The
/// admitting policy id is still stamped for attribution parity with transit.
#[test]
fn poll_descriptor_junos_host_permit_no_log_local_delivery_no_overlog() {
    let snapshot = junos_host_local_delivery_permit_snapshot(false, false, 77);
    let (log_init, log_close, policy_id, _counter_idx) =
        run_junos_host_permit_local_delivery(&snapshot);

    assert!(
        !log_init,
        "a permit WITHOUT `then log` must not set log_session_init (no over-log)"
    );
    assert!(
        !log_close,
        "a permit WITHOUT `then log` must not set log_session_close (no over-log)"
    );
    assert_eq!(
        policy_id, 77,
        "the admitting junos-host policy id is stamped even without `then log`"
    );
}


/// #3706 fail-on-revert (established session-HIT double-count): a
/// `to-zone junos-host then permit` host-local session must count each packet
/// against the admitting rule's hit counter EXACTLY ONCE — parity with transit.
/// The #3706 MISS-install stamps a bound `policy_counter`, and the LocalDelivery
/// session-HIT path ALSO re-evaluates the junos-host policy on every hit (the
/// mandatory teardown re-check), whose `try_match_rule` counts the packet.
/// Counting at the generic session-hit `record_policy_hit_counter` site TOO
/// would double-count every established host-local permit packet (2N for N
/// hits). This drives 1 SYN (miss) + 3 established ACKs (hits) and asserts the
/// rule's packet counter == 4. Remove the `!= LocalDelivery` guard on the
/// session-hit counter and this goes RED (reads 7).
#[test]
fn poll_descriptor_junos_host_permit_established_hit_counts_once() {
    // No `then log`; policy id 55. Counting is orthogonal to the log flags.
    let snapshot = junos_host_local_delivery_permit_snapshot(false, false, 55);
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    // `stable_policy_rule_id` for a rule with no explicit rule_id is
    // "<from>-><to>/<name>". The fixture rule is lan -> junos-host / host-permit-log.
    let rule_id = "lan->junos-host/host-permit-log";
    let hit_packets = |f: &ForwardingState| -> u64 {
        f.policy
            .counter_snapshots()
            .into_iter()
            .find(|c| c.rule_id == rule_id)
            .map(|c| c.packets)
            .unwrap_or_else(|| panic!("missing policy counter for {rule_id}"))
    };

    // Packet 1: SYN => session MISS => install. The miss-site junos-host
    // re-eval counts this first packet once (cold path).
    let syn = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let syn_meta = txn_meta_v4(24, TCP_FLAG_SYN, (syn.len() - 14) as u16);
    let (_b, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        syn_meta,
    );
    assert_eq!(dbg.local, 1, "SYN must take the LocalDelivery arm");
    assert_eq!(
        sessions.len(),
        1,
        "the permitted SYN must install one host-local session"
    );
    assert_eq!(
        hit_packets(&forwarding),
        1,
        "the miss SYN counts once against the admitting rule (cold path)"
    );

    // Packets 2..=4: pure ACKs (0x10) on the SAME 5-tuple => session HIT. Each
    // must count exactly once (via the mandatory junos-host teardown re-eval).
    let ack = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        0x10_u8,
    );
    let ack_meta = txn_meta_v4(24, 0x10_u8, (ack.len() - 14) as u16);
    for i in 0..3 {
        let (_b, dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &ack,
            ack_meta,
        );
        assert_eq!(
            dbg.session_hit, 1,
            "established ACK #{i} must hit the installed host-local session"
        );
    }

    assert_eq!(
        hit_packets(&forwarding),
        4,
        "#3706: 1 miss + 3 established hits must count EXACTLY 4 packets against \
         the admitting junos-host rule; double-counting the session-hit path \
         reads 7 (the pre-fix regression)"
    );
}


/// #3326 LITERAL fail-on-revert (session-MISS): a host-bound packet denied by
/// the zone host-inbound admission gate must increment the
/// `host_inbound_denied_packets` batch counter (which `syncBPFCountersLocked`
/// mirrors into `GlobalCtrHostInboundDeny` for REST/Prometheus/`show`). Remove
/// the `telemetry.counters.host_inbound_denied_packets += 1` bump in the
/// session-MISS host-inbound `None` arm and this test goes RED (the deny would
/// drop uncounted — the original bug). The admit-all companion below stays
/// GREEN, proving the bump fires ONLY on a real host-inbound deny.
#[test]
fn poll_descriptor_host_inbound_deny_counts_local_delivery_session_miss() {
    // gre_to_self_snapshot is default-permit with 10.255.0.1 firewall-local =>
    // LocalDelivery; add a present-but-empty host-inbound set on every zone so
    // the TCP/179 host-bound packet is denied (Junos deny-all posture).
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let zone_ids: Vec<u16> = forwarding.zone_id_to_name.keys().copied().collect();
    assert!(!zone_ids.is_empty(), "fixture must define at least one zone");
    for id in zone_ids {
        forwarding
            .zone_host_inbound
            .insert(id, crate::afxdp::types::ZoneHostInbound::default());
    }
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "a host-inbound-denied host-bound packet must bump the host-inbound \
         deny counter (#3326 — was silently dropped uncounted)"
    );
    assert_eq!(
        sessions.len(),
        0,
        "no host-local session may be cached for a host-inbound-denied flow"
    );
}


/// #3610 fail-on-revert (session-MISS, poll loop): a host-bound packet denied by
/// the zone host-inbound admission gate must emit a tuple-rich RT_FLOW deny event
/// — the #3615 policy-deny event kind carried with the DISTINCT host-inbound
/// reason (6), not just the aggregate `host_inbound_denied_packets` counter — so
/// an operator can see WHICH control-plane flow was dropped. Remove the
/// `emit_host_inbound_deny` call in the session-MISS host-inbound `None` arm and
/// this goes RED (empty event channel). Also pins the #3610/M07 debug-counter
/// split: the deny bumps `dbg.host_inbound_deny`, NOT `dbg.policy_deny`.
#[test]
fn poll_descriptor_host_inbound_deny_emits_tuple_event_session_miss() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let zone_ids: Vec<u16> = forwarding.zone_id_to_name.keys().copied().collect();
    assert!(!zone_ids.is_empty(), "fixture must define at least one zone");
    for id in zone_ids {
        forwarding
            .zone_host_inbound
            .insert(id, crate::afxdp::types::ZoneHostInbound::default());
    }
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (batch, dbg, event_handle, event_rx) = txn_run_descriptor_capturing_events(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "the #3326 aggregate host-inbound deny counter must still fire"
    );
    // #3610/M07: the deny is accounted on its own debug counter, not policy_deny.
    assert_eq!(
        dbg.host_inbound_deny, 1,
        "#3610/M07: host-inbound deny must bump dbg.host_inbound_deny"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "#3610/M07: host-inbound deny must NOT be conflated with dbg.policy_deny"
    );

    let event = event_rx
        .try_recv()
        .expect("#3610: host-inbound deny must emit a tuple-rich event")
        .decode_dataplane_event()
        .expect("host-inbound deny payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    // Distinct host-inbound reason (6), NOT the transit policy-deny reason (5).
    assert_eq!(event.reason, 6, "host-inbound deny reason byte");
    assert_eq!(event.action, 0, "host-inbound is a silent drop → DENY");
    assert_eq!(event.protocol, PROTO_TCP);
    assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
    assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)));
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 179);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.policy_id, 0, "host-inbound admission is not a policy");
    assert!(
        event.timestamp_ns > 0,
        "poll-path host-inbound deny event must carry a real wall-clock timestamp"
    );
    // Rides the policy-deny per-kind stats, not a new event channel.
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}


/// #3326 GREEN companion: with an admit-all host-inbound zone (the fixture zones
/// carry `system-services all` since #3705 — every known zone is enforcing, so
/// admit-all is now explicit rather than the removed configured=false default),
/// the same host-bound packet is admitted and the host-inbound deny counter
/// stays 0. Proves the #3326 bump cannot newly over-count admitted host/
/// management traffic.
#[test]
fn poll_descriptor_host_inbound_admit_does_not_count_deny_session_miss() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "admit-all host-inbound must NOT bump the host-inbound deny counter"
    );
}


/// #3019 LITERAL fail-on-revert (session-HIT): a tightened `to-zone junos-host
/// then deny` tears down an ALREADY ESTABLISHED host-bound session on the next
/// hit (mirroring the #3070 host-inbound re-check) and emits the policy-deny
/// RT_FLOW. Remove the `junos_host_policy_drops` call in the session-HIT
/// LocalDelivery arm and this test goes RED (the session would survive and no
/// PolicyDeny event would be emitted).
#[test]
fn poll_descriptor_junos_host_deny_drops_local_delivery_session_hit() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "host-deny".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }];
    snapshot.interfaces[0].addresses = vec![InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    set_ipv4_dst(&mut frame, Ipv4Addr::new(10, 0, 61, 1));
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let flow_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
    };
    let local_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 24,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let local_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key.clone(),
        local_decision,
        local_metadata.clone(),
        SessionOrigin::LocalMiss,
        123_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    let shared_entry = SyncedSessionEntry {
        key: flow_key.clone(),
        decision: local_decision,
        metadata: local_metadata,
        origin: SessionOrigin::LocalMiss,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &shared_entry,
    );
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event from junos-host deny on cached local session hit")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    assert_eq!(sessions.len(), 0, "junos-host deny must tear down the cached session");
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, flow_key);
    assert!(telemetry.dbg.policy_deny >= 1);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}


/// #1885 decap-level consistency pin: on VLAN-TAGGED ingress the decap
/// must produce a synthetic frame and an inner meta that describe EACH
/// OTHER — `synthetic[meta.l3_offset..]` IS the inner packet. (The
/// poll-descriptor defect was pairing this inner meta with the
/// original outer frame instead of the synthetic one.)
#[test]
fn native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("tagged GRE-to-self outer frame must decap");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "synthetic frame and inner meta must be self-consistent"
    );
    assert_eq!(decap.meta.ingress_ifindex, 77);
    assert_eq!(decap.meta.addr_family, libc::AF_INET as u8);
}


/// #2782 fail-on-revert: a Checksum-Present GRE frame (C bit set, valid
/// checksum) MUST decap to the inner packet — exactly the inner bytes at
/// the correct offset. Before #2782 the decap path returned `None` the
/// instant the C bit was seen (an uncounted blackhole of any checksummed
/// peer, e.g. a vSRX with GRE checksum enabled). Reverting the
/// skip+validate makes this row drop and the assert fires.
#[test]
fn native_gre_decap_checksum_present_yields_inner_packet() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_checksum_present_outer_frame_v4(
        80,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM,
        0,
        0,
        &inner,
        false,
    );
    let meta = gre_to_self_outer_meta(80, frame.len());
    let before = crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed);
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("checksum-present GRE frame must decap (RFC 2784 §2.1 / RFC 2890)");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "decapped inner must be byte-identical and at the correct offset"
    );
    assert_eq!(decap.meta.addr_family, libc::AF_INET as u8);
    assert_eq!(
        crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed),
        before,
        "a VALID checksum must not bump the invalid-drop counter"
    );
}


/// #2782: composed optional fields — C + Key + Sequence all present. The
/// Checksum+Reserved1 (4B) precedes Key (4B) precedes Sequence (4B) per
/// RFC 2890; the decap must skip ALL three to land on the inner payload.
/// (`key` is 0 so it matches the keyless test endpoint while still
/// exercising the key-field offset advance.)
#[test]
fn native_gre_decap_checksum_key_sequence_present_yields_inner_packet() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_checksum_present_outer_frame_v4(
        80,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM
            | crate::afxdp::gre::GRE_FLAG_KEY
            | crate::afxdp::gre::GRE_FLAG_SEQUENCE,
        0,
        0x0000_002a,
        &inner,
        false,
    );
    let meta = gre_to_self_outer_meta(80, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("C+Key+Seq GRE frame must decap with all optional fields skipped");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "decapped inner must be byte-identical with C+Key+Seq present"
    );
}


/// #2782: a Checksum-Present frame whose checksum does NOT verify is a
/// COUNTED drop (not a silent blackhole, not a misforward). The
/// `gre_decap_checksum_invalid_drops_total` counter must advance by one
/// and the decap must return `None`.
#[test]
fn native_gre_decap_checksum_invalid_drops_and_counts() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_checksum_present_outer_frame_v4(
        80,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM,
        0,
        0,
        &inner,
        true, // corrupt a payload byte after sealing the checksum
    );
    let meta = gre_to_self_outer_meta(80, frame.len());
    let before = crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed);
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a corrupt-checksum GRE frame must be dropped, not misforwarded"
    );
    assert_eq!(
        crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed),
        before + 1,
        "an invalid GRE checksum must bump the specific drop counter"
    );
}


/// #2782 fail-closed: a Checksum-Present frame truncated past the 4-byte
/// Checksum+Reserved1 field must NOT over-read — it returns `None`. Here
/// the outer IP Total Length lies (claims a full frame) but the captured
/// frame is cut right after the flags/proto word, so the checksum-region
/// bound or the post-field bounds-check rejects it.
#[test]
fn native_gre_decap_checksum_present_truncated_header_fails_closed() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let mut frame = build_gre_checksum_present_outer_frame_v4(
        80,
        crate::afxdp::gre::GRE_FLAG_CHECKSUM,
        0,
        0,
        &inner,
        false,
    );
    // Cut the frame so only the 4-byte GRE flags/proto word survives —
    // the Checksum+Reserved1 field is gone. The outer IP Total Length
    // still claims the original (longer) length.
    let l3 = gre_to_self_outer_meta(80, frame.len()).l3_offset as usize;
    frame.truncate(l3 + 20 + 4);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a truncated checksum-present GRE header must fail closed (no over-read)"
    );
}


/// #2327 fail-on-revert: a GRE (proto-47) frame whose outer tuple/key
/// match ONLY a non-GRE (here: WireGuard) tunnel row must NOT be
/// decapsulated as GRE. Pre-#2327 `match_tunnel_endpoint` scanned
/// `tunnel_endpoints.values()` ignoring `mode`, so any row whose outer
/// tuple lined up was decapped as GRE. We mutate the built state so the
/// ONLY endpoint that carries the matching outer tuple is mode
/// "wireguard" — the GRE decap must return `None` (no match / drop),
/// never decap the WireGuard endpoint's traffic as GRE. If the
/// kind-segregation in `match_tunnel_endpoint` / the build-side
/// `gre_decap_index` is reverted, this row reappears and the assert
/// fires.
#[test]
fn gre_decap_does_not_match_wireguard_row_with_same_outer_tuple() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    // Flip the single (GRE) endpoint to WireGuard while keeping the
    // exact outer tuple/key the inbound frame matches, and drop it from
    // the kind-segregated decap index (as the WG build path would).
    let id = 824u16;
    if let Some(ep) = forwarding.tunnel_endpoints.get_mut(&id) {
        ep.mode = "wireguard".to_string();
    }
    forwarding.gre_decap_index.clear();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a GRE frame matching only a WireGuard row must NOT decap as GRE"
    );
}


/// #2327 fail-on-revert (defense-in-depth pin): even if the build-side
/// index were wrong and surfaced a non-GRE endpoint id for the inbound
/// tuple, the per-candidate `tunnel_mode_kind` re-check in
/// `match_tunnel_endpoint` must reject it. Here the decap index DOES
/// point at the endpoint, but the endpoint's mode is non-GRE — the
/// match must still be `None`.
#[test]
fn gre_decap_rejects_non_gre_candidate_even_if_indexed() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let id = 824u16;
    if let Some(ep) = forwarding.tunnel_endpoints.get_mut(&id) {
        ep.mode = "wireguard".to_string();
    }
    // Index intentionally left pointing at the now-WireGuard endpoint to
    // exercise the per-candidate kind re-check.
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "the per-candidate kind re-check must reject a non-GRE endpoint \
         even when the decap index lists it"
    );
}


/// #2327 fail-on-revert: a genuine GRE frame matching a GRE-mode row
/// still decaps (the kind-segregation must not break the happy path).
/// Complements the existing
/// `native_gre_decap_tagged_ingress_yields_self_consistent_frame_meta`.
#[test]
fn gre_decap_still_matches_genuine_gre_row() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);
    let meta = gre_to_self_outer_meta(80, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("a genuine GRE frame matching a GRE row must still decap");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "decapped inner packet must be byte-identical"
    );
}

// ====================================================================
// #2376: GRE decap inner-L4 minimum-header bounds (UDP/ICMP/ICMPv6).
//
// The inner-protocol parser length-validated inner TCP but advanced the
// UDP/ICMP/ICMPv6 payload offset by 8 with NO minimum-header bounds
// check. The inner is trimmed to its IP-declared total length before the
// parse, so an inner whose declared length ends before its L4 header
// (e.g. IPv4 total_len = ihl + 2, proto = UDP) survived and stamped a
// synthetic `protocol`/`l4_offset`/`payload_offset` from bytes that are
// not a real L4 header — `payload_offset` even pointed past the packet
// end. The fix fails CLOSED (no decap) when the inner cannot contain the
// claimed 8-byte L4 minimum header. These tests pin that contract and
// the anti-over-reject happy path. They drive
// `try_native_gre_decap_from_frame` directly so the assertion is on the
// decap chokepoint, not a downstream consumer.
// ====================================================================


/// A GRE packet whose IPv4 inner declares UDP but its IP-declared length
/// ends before the 8-byte UDP header (total_len = ihl + 2). Pre-#2376
/// this stamped `protocol = UDP`, `l4_offset = ihl`, and
/// `payload_offset = ihl + 8` (past the packet end) from non-L4 bytes.
/// The guard must now drop (decap returns `None`). FAILS if the
/// `packet.len() >= ihl + 8` guard is removed.
#[test]
fn gre_decap_drops_truncated_udp_inner_v4() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_v4(PROTO_UDP, 2); // only 2 of 8 UDP bytes declared
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a GRE inner declaring UDP but shorter than the 8-byte UDP \
         header must fail closed (no decap), not stamp synthetic ports \
         from out-of-bounds bytes"
    );
}


/// Same as above for an IPv4 ICMP inner shorter than its 8-byte header.
#[test]
fn gre_decap_drops_truncated_icmp_inner_v4() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_v4(PROTO_ICMP, 3); // only 3 of 8 ICMP bytes declared
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "a GRE inner declaring ICMP but shorter than the 8-byte ICMP \
         header must fail closed (no decap)"
    );
}


/// IPv6 inner declaring UDP but with payload_len < 8 (the UDP header does
/// not fit). FAILS if the IPv6 `packet.len() >= l4 + 8` guard is removed.
#[test]
fn gre_decap_drops_truncated_udp_inner_v6() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_v6(PROTO_UDP, 4); // 4 of 8 UDP bytes
    let frame = build_gre_to_self_outer_frame_with_inner(0x86dd, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "an IPv6 GRE inner declaring UDP shorter than the 8-byte UDP \
         header must fail closed (no decap)"
    );
}


/// IPv6 inner declaring ICMPv6 but with payload_len < 8.
#[test]
fn gre_decap_drops_truncated_icmpv6_inner_v6() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_v6(PROTO_ICMPV6, 7); // 7 of 8 ICMPv6 bytes
    let frame = build_gre_to_self_outer_frame_with_inner(0x86dd, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "an IPv6 GRE inner declaring ICMPv6 shorter than the 8-byte \
         header must fail closed (no decap)"
    );
}


/// #2376 anti-over-reject: a WELL-FORMED GRE-tunneled UDP inner (full
/// 8-byte UDP header + payload) still decaps and stamps the correct
/// ports / L4 offset. Guards the happy path against an over-strict
/// length check. The synthetic inner meta's `l4_offset` is `14 + ihl`
/// (eth + IP header) and the stamped ports come from the real UDP header.
#[test]
fn gre_decap_well_formed_udp_inner_v4_still_decaps_with_ports() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let mut inner = build_gre_inner_v4(PROTO_UDP, 8 + 4); // full UDP header + 4B payload
    // src port 0x1234, dst port 0x5678, length 16, checksum 0 (unchecked).
    inner[20..28].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x00, 0x10, 0x00, 0x00]);
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("a well-formed GRE-tunneled UDP inner must still decap");
    assert_eq!(decap.meta.protocol, PROTO_UDP);
    assert_eq!(decap.meta.l4_offset, 14 + 20, "inner L4 at eth+IP header");
    assert_eq!(decap.meta.flow_src_port, 0x1234, "stamped UDP src port");
    assert_eq!(decap.meta.flow_dst_port, 0x5678, "stamped UDP dst port");
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &inner[..],
        "synthetic frame and inner meta must stay self-consistent"
    );
}


/// #2376 anti-over-reject: a well-formed GRE-tunneled ICMP echo inner
/// still decaps (mirrors `build_gre_inner_icmp_packet_v4`, full 8-byte
/// ICMP header). Complements the existing self-consistency tests.
#[test]
fn gre_decap_well_formed_icmp_inner_v4_still_decaps() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("a well-formed GRE-tunneled ICMP inner must still decap");
    assert_eq!(decap.meta.protocol, PROTO_ICMP);
    assert_eq!(decap.meta.l4_offset, 14 + 20);
}


/// #2486 fail-on-revert: native GRE decap MUST stamp
/// `GRE_DECAP_INGRESS_FLAG` on the inner packet's meta so the
/// forward-frame builder selects the `tcp-mss gre-in` clamp. Reverting
/// the `meta_flags: GRE_DECAP_INGRESS_FLAG` set in
/// `try_native_gre_decap_from_frame` (gre.rs) makes this assertion fail
/// — and with it the inbound GRE-decapped SYN goes back to being
/// forwarded unclamped (the original silent full-MSS blackhole).
#[test]
fn gre_decap_marks_inner_meta_with_gre_in_flag() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("well-formed GRE inner must decap");
    assert_ne!(
        decap.meta.meta_flags & GRE_DECAP_INGRESS_FLAG,
        0,
        "decap must mark the inner meta as GRE-decapped (gre-in clamp marker)"
    );
}


/// #2376 composition / no-regression: the pre-existing TCP guard must
/// still drop a GRE inner declaring TCP but shorter than the 20-byte TCP
/// header — the UDP/ICMP fix must not weaken the TCP path.
#[test]
fn gre_decap_drops_truncated_tcp_inner_v4_no_regression() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_v4(PROTO_TCP, 10); // 10 of 20 TCP bytes
    let frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    let meta = gre_to_self_outer_meta(0, frame.len());
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "the existing TCP minimum-header guard must still drop a short \
         TCP inner (the #2376 UDP/ICMP fix must not regress TCP)"
    );
}


/// #2327 fail-on-revert: the egress encap dispatcher must FAIL CLOSED on
/// an unknown tunnel mode — a row whose mode is neither GRE nor
/// WireGuard must NOT be silently GRE-encapsulated (the pre-#2327
/// `_ => GRE` fail-open default). `tunnel_mode_kind` classifies it as
/// `Unknown`; the dispatcher drops (`None`). Asserted at the kind layer
/// (the dispatch's `match` arms) so the test pins the fail-closed
/// contract without standing up a full forwarded-frame fixture.
#[test]
fn unknown_tunnel_mode_classifies_as_unknown_not_gre() {
    use crate::afxdp::{tunnel_mode_kind, TunnelKind};
    assert_eq!(tunnel_mode_kind("gre"), TunnelKind::Gre);
    assert_eq!(tunnel_mode_kind("ip6gre"), TunnelKind::Gre);
    assert_eq!(tunnel_mode_kind("wireguard"), TunnelKind::WireGuard);
    // Any unrecognized / future / malformed mode must NOT map to GRE.
    for bad in ["", "ipip", "vxlan", "GRE", "wireguard ", "gre6", "geneve"] {
        assert_eq!(
            tunnel_mode_kind(bad),
            TunnelKind::Unknown,
            "mode {bad:?} must classify Unknown (fail closed), never GRE"
        );
    }
}


/// #5140 LITERAL fail-on-revert (security): the post-GRE-decap host-inbound
/// admission gate MUST read the ICMP/ICMPv6 type from the decapped inner
/// `packet_frame`, NOT the outer `raw_frame`. After `stage_native_gre_decap`
/// the inner meta's `l4_offset` is inner-relative (14 + inner IHL = 34 for a
/// 20-byte inner IPv4 header). For an UNTAGGED GRE underlay that offset lands
/// EXACTLY on the outer GRE flags byte (eth 14 + outer IP 20 = 34 = the GRE
/// header). The GRE flags low bits (Recur / reserved) are attacker-controllable
/// and ignored by the decap (only C/R/K/S/version are checked), so an attacker
/// can seed `raw_frame[34]` with an ICMP-error type value (11 = time-exceeded).
///
/// The trigger here is a GRE-tunnelled inner ICMP ECHO (type 8) to the firewall-
/// local gr- address on a PING-LESS zone (empty host-inbound set → Junos deny-all
/// posture for ping). The correct disposition is DENY: an echo is not an
/// error/PMTUD control message, so the #3171 global-accept exemption does not
/// apply and the empty zone set drops it.
///
/// - FIXED (`packet_frame[34]` = inner type 8 = echo): NOT globally accepted →
///   empty zone set → DENIED → `host_inbound_denied_packets == 1`.
/// - BUGGY (`raw_frame[34]` = outer GRE flags 0x0B = 11 = time-exceeded): the
///   #3171 `is_icmp_host_inbound_global_accept` exemption ADMITS it before the
///   zone lookup → `host_inbound_denied_packets == 0` — an ordinary echo bypasses
///   host-inbound admission (the security misclassification #5140 fixes).
///
/// Swap `packet_frame` back to `raw_frame` at the session-MISS host-inbound
/// ICMP-type read (`poll_descriptor/mod.rs`, the `host_inbound_gated_lo0_action`
/// icmp_type argument) and this test goes RED. Drives the REAL decap+classify
/// path via `poll_binding_process_descriptor` (not a synthetic leaf call).
#[test]
fn gre_decap_inner_icmp_echo_denied_by_host_inbound_reads_inner_type() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    // Ping-less posture: a present-but-EMPTY host-inbound set on every zone so
    // an inner ICMP echo to the firewall-local gr- address is denied (Junos
    // deny-all), while ICMP ERROR types stay globally admitted (#3171). This is
    // what makes the outer-vs-inner read observable: outer flags 0x0B decodes to
    // error type 11 (admit-exempt); inner type 8 is echo (deny).
    let zone_ids: Vec<u16> = forwarding.zone_id_to_name.keys().copied().collect();
    assert!(!zone_ids.is_empty(), "fixture must define at least one zone");
    for id in zone_ids {
        forwarding
            .zone_host_inbound
            .insert(id, crate::afxdp::types::ZoneHostInbound::default());
    }
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    // Inner: ICMP echo request (type 8) 10.255.0.2 -> 10.255.0.1 (gr-local).
    let inner = build_gre_inner_icmp_packet_v4();
    assert_eq!(inner[20], 8, "inner must be an ICMP echo request (type 8)");
    // Untagged GRE-to-self outer frame; then plant an ICMP-error type value in
    // the outer GRE flags byte (frame[34], the byte the buggy read indexes).
    // 0x0B sets only Recur/reserved low bits (no C/R/K/S) so decap is unaffected.
    let mut frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    assert_eq!(
        frame[34], 0x00,
        "untagged frame[34] is the GRE flags byte (eth14 + outerIP20)"
    );
    frame[34] = 0x0B; // ICMPv4 time-exceeded (11) — an error type in the #3171 set
    let meta = gre_to_self_outer_meta(0, frame.len());

    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.local, 1,
        "the decapped inner echo to the gr-local address must take the \
         LocalDelivery arm"
    );
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "#5140: the host-inbound gate must read the INNER ICMP type (8 = echo) \
         from packet_frame and DENY on the ping-less zone; the buggy raw_frame \
         read sees the outer GRE flags byte (0x0B = 11 = time-exceeded) and \
         admits the echo as an exempt error (host-inbound bypass)"
    );
    assert_eq!(
        dbg.host_inbound_deny, 1,
        "#3610/M07: the deny is accounted on dbg.host_inbound_deny"
    );
    assert_eq!(
        sessions.len(),
        0,
        "a host-inbound-denied inner echo must not cache a host-local session"
    );
}


// ── #5615: direct GRE-decap fail-on-revert coverage for the other 6 #5140
// post-decap inner-read sites. #5140/PR #5613 swapped 7 `raw_frame`→
// `packet_frame` inner reads but shipped a direct fail-on-revert test for only
// ONE (session-MISS host-inbound ICMP type, above). Each test below drives a
// REAL GRE-tunnelled frame through `poll_binding_process_descriptor` and
// constructs the fixture so the INNER field the site reads differs from the
// OUTER byte at the same inner-relative `meta` offset — so a revert of that
// site to `raw_frame` (reading the outer) flips the observable. See the issue
// #5615 body for the 7-site map. ─────────────────────────────────────────────


/// #5615 fail-on-revert (session-HIT host-inbound ICMP type,
/// `poll_descriptor/mod.rs` ~1622). Sibling of the covered session-MISS test
/// `gre_decap_inner_icmp_echo_denied_by_host_inbound_reads_inner_type`.
///
/// Two passes on ONE (binding, sessions) pair. Pass 1 admits the inner echo
/// (fixture zones carry `system-services all`) and CACHES the host-local
/// session. Pass 2 runs after the host-inbound set is tightened to ping-less
/// (present-but-empty), so the #3070/#3485 session-HIT re-check runs the
/// host-inbound gate again — reading the INNER ICMP type from `packet_frame`.
///
/// - FIXED (`packet_frame[34]` = inner type 8 = echo): NOT globally accepted →
///   empty zone set → DENY on the hit → `host_inbound_denied_packets == 1`,
///   the cached session is torn down.
/// - REVERTED (`raw_frame[34]` = outer GRE flags `0x0B` = 11 = time-exceeded):
///   the #3171 `is_icmp_host_inbound_global_accept` exemption ADMITS the echo →
///   `host_inbound_denied_packets == 0` and the session survives.
///
/// Swap `packet_frame` → `raw_frame` at the session-HIT
/// `host_inbound_gated_lo0_action` icmp_type argument and this goes RED.
#[test]
fn gre_decap_session_hit_host_inbound_reads_inner_icmp_type_5615() {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    // Inner: ICMP echo request (type 8) 10.255.0.2 -> 10.255.0.1 (gr-local).
    let inner = build_gre_inner_icmp_packet_v4();
    assert_eq!(inner[20], 8, "inner must be an ICMP echo request (type 8)");
    // Untagged GRE-to-self outer frame; plant an ICMP-error type value in the
    // outer GRE flags byte (frame[34], the byte the buggy read indexes). 0x0B
    // sets only Recur/reserved low bits (no C/R/K/S) so decap is unaffected.
    let mut frame = build_gre_to_self_outer_frame_with_inner(0x0800, &inner);
    assert_eq!(
        frame[34], 0x00,
        "untagged frame[34] is the GRE flags byte (eth14 + outerIP20)"
    );
    frame[34] = 0x0B; // ICMPv4 time-exceeded (11) — an error type in the #3171 set
    let meta = gre_to_self_outer_meta(0, frame.len());

    // Pass 1 — admit-all host-inbound: the inner echo is admitted on the
    // session-MISS local-delivery arm and caches a host-local session.
    let (batch1, dbg1) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg1.local, 1, "pass 1 inner echo must take LocalDelivery");
    assert_eq!(
        batch1.host_inbound_denied_packets, 0,
        "pass 1 admit-all host-inbound must not deny"
    );
    assert_eq!(
        sessions.len(),
        1,
        "pass 1 must cache the host-local session (arms the session-HIT re-check)"
    );

    // Tighten to a ping-less (present-but-EMPTY) host-inbound set on every zone.
    let zone_ids: Vec<u16> = forwarding.zone_id_to_name.keys().copied().collect();
    assert!(!zone_ids.is_empty(), "fixture must define at least one zone");
    for id in zone_ids {
        forwarding
            .zone_host_inbound
            .insert(id, crate::afxdp::types::ZoneHostInbound::default());
    }

    // Pass 2 — session-HIT: the host-inbound re-check reads the INNER ICMP type.
    let (batch2, dbg2) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg2.local, 1,
        "pass 2 must take the session-HIT local-delivery arm"
    );
    assert_eq!(
        batch2.host_inbound_denied_packets, 1,
        "#5615: the session-HIT host-inbound re-check must read the INNER ICMP \
         type (8 = echo) from packet_frame and DENY on the ping-less zone; the \
         buggy raw_frame read sees the outer GRE flags byte (0x0B = 11 = \
         time-exceeded) and admits the echo as an exempt error"
    );
    assert_eq!(
        dbg2.host_inbound_deny, 1,
        "the session-HIT host-inbound deny bumps dbg.host_inbound_deny"
    );
    assert_eq!(
        sessions.len(),
        0,
        "the session-HIT host-inbound deny must tear down the cached session"
    );
}


/// #5615 helper: an untagged GRE-to-self OUTER frame (outer TTL 64) wrapping an
/// inner IPv4 ICMP echo request 10.255.0.2 -> `dst` with the given inner TTL.
/// The outer TTL (frame[22]) is fixed at 64 by the builder while the inner TTL
/// (synthetic[22] after decap) is `inner_ttl` — so a TTL read reverted to the
/// outer `raw_frame` tests the wrong (non-expiring 64) byte.
fn gre_frame_inner_icmp_echo_v4(dst: Ipv4Addr, inner_ttl: u8) -> Vec<u8> {
    let mut inner = build_gre_inner_icmp_packet_v4();
    inner[8] = inner_ttl;
    inner[16..20].copy_from_slice(&dst.octets());
    inner[10] = 0;
    inner[11] = 0;
    let sum = checksum16(&inner[0..20]);
    inner[10] = (sum >> 8) as u8;
    inner[11] = sum as u8;
    build_gre_to_self_outer_frame_with_inner(0x0800, &inner)
}

/// #5615 helper: an untagged GRE-to-self OUTER frame (outer TTL 64) wrapping an
/// inner IPv4 UDP datagram 10.255.0.2 -> `dst` with the given inner TTL. UDP is
/// flow-cache eligible, so a seed pass (inner TTL 64) followed by a TTL=1 pass
/// exercises the flow-cache-HIT TTL path.
fn gre_frame_inner_udp_v4(dst: Ipv4Addr, inner_ttl: u8, sport: u16, dport: u16) -> Vec<u8> {
    let d = dst.octets();
    let total: u16 = 28; // 20 IPv4 + 8 UDP
    let mut inner = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        inner_ttl,
        PROTO_UDP,
        0x00,
        0x00,
        10,
        255,
        0,
        2,
        d[0],
        d[1],
        d[2],
        d[3],
    ];
    let sum = checksum16(&inner[0..20]);
    inner[10] = (sum >> 8) as u8;
    inner[11] = sum as u8;
    inner.extend_from_slice(&sport.to_be_bytes());
    inner.extend_from_slice(&dport.to_be_bytes());
    inner.extend_from_slice(&8u16.to_be_bytes()); // UDP length
    inner.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum 0 (optional, IPv4)
    build_gre_to_self_outer_frame_with_inner(0x0800, &inner)
}

/// #5615 helper: count the prebuilt ICMP Time Exceeded replies queued in the
/// binding's `scratch_forwards`. The TTL-expiry path pushes a
/// `PendingForwardFrame::Prebuilt` and consumes the trigger; a non-expiring
/// forward never touches `scratch_forwards`, so this is 1 when the inner TTL
/// read fired and 0 when it did not.
fn prebuilt_te_count(binding: &BindingWorker) -> usize {
    binding
        .scratch
        .scratch_forwards
        .iter()
        .filter(|r| matches!(r.frame, PendingForwardFrame::Prebuilt(_)))
        .count()
}

/// #5615 GRE-to-self outer meta for a WAN-ingress binding (ifindex 12,
/// reth0.80). Same shape as `gre_to_self_outer_meta` but with the ingress
/// ifindex the TTL tests bind on so the locally-generated Time Exceeded resolves
/// a real egress object (`forwarding.egress[12]`) and builds deterministically.
fn gre_to_self_outer_meta_wan(frame_len: usize) -> UserspaceDpMeta {
    let mut meta = gre_to_self_outer_meta(0, frame_len);
    meta.ingress_ifindex = 12;
    meta
}


/// #5615 fail-on-revert (session-MISS TTL, `poll_descriptor/mod.rs` ~3240).
/// A GRE-tunnelled inner ICMP echo to a TRANSIT destination (8.8.8.8) whose
/// INNER TTL is 1 must generate an ICMP Time Exceeded on the session-MISS
/// forward path — the TTL byte read from the decapped inner `packet_frame`
/// (synthetic[22] = 1), NOT the outer `raw_frame` (frame[22] = outer TTL 64).
///
/// - FIXED (`packet_frame`): `packet_ttl_would_expire` sees inner TTL 1 →
///   `build_local_time_exceeded_request` builds a prebuilt TE and CONSUMES the
///   trigger before session install → one prebuilt TE queued, no session cached.
/// - REVERTED (`raw_frame`): the read sees outer TTL 64 → not expiring → the
///   echo is forwarded and a transit session is installed → zero prebuilt TEs.
///
/// The generated-error token bucket is pinned FULL under the global test lock so
/// the buildable reply is deterministic (the bucket is a shared static).
#[test]
fn gre_decap_session_miss_ttl_expiry_reads_inner_ttl_5615() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
    };
    let _guard = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);

    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Inner ICMP echo to transit 8.8.8.8, inner TTL = 1 (would expire).
    let frame = gre_frame_inner_icmp_echo_v4(Ipv4Addr::new(8, 8, 8, 8), 1);
    assert_eq!(frame[22], 64, "outer IPv4 TTL byte must be 64 (differs from inner 1)");
    let meta = gre_to_self_outer_meta_wan(frame.len());

    let (_batch, _dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        prebuilt_te_count(&binding),
        1,
        "#5615: the session-MISS TTL check must read the INNER TTL (1) from \
         packet_frame and generate one ICMP Time Exceeded; the buggy raw_frame \
         read sees the outer TTL (64), forwards the echo, and queues no TE"
    );
    assert_eq!(
        sessions.len(),
        0,
        "a TTL-expired session-MISS echo is consumed as a Time Exceeded before \
         session install; the raw_frame revert would forward it and cache a session"
    );
}


/// #5615 fail-on-revert (session-HIT TTL, `poll_descriptor/mod.rs` ~1803).
/// Two passes on one (binding, sessions) pair. Pass 1 (inner TTL 64) forwards
/// the inner ICMP echo to a TRANSIT destination and installs a transit session.
/// Pass 2 (inner TTL 1) is a session-HIT (ICMP is never flow-cache eligible, so
/// it takes the session slow path): the session-HIT TTL check must read the
/// INNER TTL from `packet_frame`.
///
/// - FIXED (`packet_frame`): pass 2 sees inner TTL 1 → one prebuilt TE queued,
///   the trigger consumed.
/// - REVERTED (`raw_frame`): pass 2 sees outer TTL 64 → forwarded, no TE.
#[test]
fn gre_decap_session_hit_ttl_expiry_reads_inner_ttl_5615() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
    };
    let _guard = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);

    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Pass 1: inner TTL 64 — forwards + installs the transit session.
    let frame_seed = gre_frame_inner_icmp_echo_v4(Ipv4Addr::new(8, 8, 8, 8), 64);
    let meta_seed = gre_to_self_outer_meta_wan(frame_seed.len());
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame_seed,
        meta_seed,
    );
    assert!(
        sessions.len() >= 1,
        "pass 1 (inner TTL 64) must install a transit session (arms the session-HIT read)"
    );

    // Pass 2: same 5-tuple, inner TTL 1 — session-HIT TTL check.
    let frame_hit = gre_frame_inner_icmp_echo_v4(Ipv4Addr::new(8, 8, 8, 8), 1);
    assert_eq!(frame_hit[22], 64, "outer IPv4 TTL byte must be 64 (differs from inner 1)");
    let meta_hit = gre_to_self_outer_meta_wan(frame_hit.len());
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame_hit,
        meta_hit,
    );

    assert_eq!(
        prebuilt_te_count(&binding),
        1,
        "#5615: the session-HIT TTL check must read the INNER TTL (1) from \
         packet_frame and generate one ICMP Time Exceeded; the buggy raw_frame \
         read sees the outer TTL (64) and forwards the echo with no TE"
    );
}


/// #5615 fail-on-revert (flow-cache-HIT TTL, `poll_descriptor/flow_cache_hit.rs`
/// ~158 `packet_ttl_would_expire` + ~167 `build_local_time_exceeded_request`).
/// A GRE-tunnelled inner UDP flow (flow-cache eligible) seeds the flow cache on
/// pass 1 (inner TTL 64); pass 2 (inner TTL 1) HITS the flow cache, where the
/// TTL-expiry check + the generated Time Exceeded must read the decapped inner
/// `packet_frame` TTL (1), not the outer `raw_frame` TTL (64).
///
/// - FIXED (`packet_frame`): pass 2 sees inner TTL 1 → one prebuilt TE queued.
/// - REVERTED at the `packet_ttl_would_expire` arg (`raw_frame`): sees outer TTL
///   64 → not expiring → forwarded, no TE.
/// - REVERTED at the `build_local_time_exceeded_request` arg (`raw_frame`): the
///   would-expire branch is entered (inner TTL 1) but the builder's own internal
///   TTL check sees the outer 64 → returns None → the packet is dropped with no
///   TE queued.
///
/// Either revert drops the prebuilt-TE count to 0, so this single test binds to
/// both flow-cache-hit inner reads.
#[test]
fn gre_decap_flow_cache_hit_ttl_expiry_reads_inner_ttl_5615() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
    };
    let _guard = global_bucket_test_lock();
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);

    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Pass 1: inner UDP TTL 64 to transit 8.8.8.8 — seeds the flow cache.
    let frame_seed = gre_frame_inner_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 64, 12345, 53);
    let meta_seed = gre_to_self_outer_meta_wan(frame_seed.len());
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame_seed,
        meta_seed,
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "pass 1 (inner UDP TTL 64) must seed one flow-cache entry (arms the \
         flow-cache-HIT TTL read on pass 2)"
    );

    // Pass 2: same 5-tuple, inner UDP TTL 1 — flow-cache HIT TTL check.
    let frame_hit = gre_frame_inner_udp_v4(Ipv4Addr::new(8, 8, 8, 8), 1, 12345, 53);
    assert_eq!(frame_hit[22], 64, "outer IPv4 TTL byte must be 64 (differs from inner 1)");
    let meta_hit = gre_to_self_outer_meta_wan(frame_hit.len());
    txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame_hit,
        meta_hit,
    );

    assert_eq!(
        prebuilt_te_count(&binding),
        1,
        "#5615: the flow-cache-HIT TTL check + Time Exceeded build must read the \
         INNER TTL (1) from packet_frame and generate one prebuilt TE; either \
         raw_frame revert (would-expire arg or builder arg) drops this to 0"
    );
}

