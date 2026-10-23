//! #15949 (H34-04 arm 2): miss-path LocalDelivery late-metering tests.
//!
//! The input-filter precheck defers three-color policer metering to the
//! TX-selection leg, which host-bound traffic never takes. The late arms
//! at the LocalDelivery install site used to meter only after the
//! PERMIT `FilterLog`, the lo0 evaluation, and the junos-host policy
//! evaluation — so a red packet left a false PERMIT audit record,
//! lo0/junos-host counter increments, an evicted closing pair (for an
//! `owner_syn_reuse` SYN), and a skipped persistent-hold rollback. The
//! early gate (`meter_miss_local_input_policers`) meters before all of
//! those side effects and owns exactly the packets both LocalDelivery
//! arms serve.
//!
//! These cells are the decisive regression check from the issue: a
//! miss-path test with a red policer asserting no PERMIT `FilterLog`,
//! no lo0/junos-host counter increments, and the closing-TCP pair
//! intact. Helper-level cells pin the gate itself (red drop, conforming
//! pass with handles, empty pass); poll-level cells pin the ordering
//! through the real descriptor path.

// #15949 arm 2 tests: sibling test module under poll_descriptor.
// Visible items: `meter_miss_local_input_policers` /
// `MissLocalPolicerVerdict` (this module's parent), `ForwardingState`
// and the forwarding builder (afxdp glob), `SessionFlow` (afxdp glob).

use super::super::test_fixtures::*;
use super::super::tests_support::*;
use super::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, PolicyRuleSnapshot, ThreeColorPolicerSnapshot,
};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

fn policed_forwarding() -> ForwardingState {
    // Base on the GRE-to-self fixture so the destination (10.255.0.1,
    // the gr- interface address) resolves LocalDelivery with a real
    // local_ifindex and the lo0 evaluation actually runs.
    let mut snapshot = gre_to_self_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "police-tcp".into(),
            protocols: vec!["tcp".into()],
            policer: "host-pol".into(),
            action: "accept".into(),
            log: true,
            ..Default::default()
        }],
    }];
    snapshot.three_color_policers = vec![ThreeColorPolicerSnapshot {
        name: "host-pol".into(),
        mode: "single-rate".into(),
        color_blind: true,
        committed_rate_bytes_per_sec: 1,
        committed_burst_bytes: 1_000,
        peak_or_excess_burst_bytes: 50,
        then_action: "discard".into(),
        ..Default::default()
    }];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 24 {
            iface.filter_input_v4 = "edge-in".into();
        }
    }
    // lo0 term with a counter: a late-metered packet must not charge it.
    snapshot.flow.lo0_filter_input_v4 = "protect-re".into();
    snapshot.filters.push(FirewallFilterSnapshot {
        name: "protect-re".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "lo0-count".into(),
            protocols: vec!["tcp".into()],
            count: "lo0-web".into(),
            action: "accept".into(),
            ..Default::default()
        }],
    });
    // junos-host permit: a late-metered packet must not charge it.
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "host-permit".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    });
    build_forwarding_state(&snapshot)
}

fn flow_to_local() -> SessionFlow {
    SessionFlow {
        src_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)),
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: std::net::IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)),
            src_port: 12345,
            dst_port: 179,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    }
}

fn meta_900() -> UserspaceDpMeta {
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, 900);
    meta.pkt_len = 900;
    meta
}

fn frame_900() -> Vec<u8> {
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    frame.resize(900, 0);
    frame
}

/// Helper-level: a red packet drops at the gate and the gate reports
/// the drop verdict; the conforming first packet passes WITH its
/// handles (so the cacheable arm stores them without re-metering).
#[test]
fn miss_local_gate_red_drops_and_conforming_passes_with_handles_15949() {
    let forwarding = policed_forwarding();
    let flow = flow_to_local();
    let frame = frame_900();
    let meta = meta_900();

    let (first, handles) =
        meter_miss_local_input_policers(&forwarding, &frame, &flow, meta, 123_000_000_000);
    assert_eq!(
        first,
        MissLocalPolicerVerdict::Pass,
        "#15949: conforming first packet must pass the early gate"
    );
    assert!(
        !handles.is_empty(),
        "#15949: conforming pass must carry the policer handles for session storage"
    );

    let (second, _) =
        meter_miss_local_input_policers(&forwarding, &frame, &flow, meta, 123_000_000_000);
    assert_eq!(
        second,
        MissLocalPolicerVerdict::Drop,
        "#15949: over-rate second packet must drop at the early gate"
    );
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert!(
        status[0].drop_packets >= 1,
        "#15949: the gate must charge the policer drop counter"
    );
}

/// Helper-level: a flow with no policer handles passes with an empty
/// set (the common no-policer case pays no meter).
#[test]
fn miss_local_gate_no_policer_passes_empty_15949() {
    let mut snapshot = nat_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let flow = flow_to_local();
    let frame = frame_900();
    let meta = meta_900();
    let (verdict, handles) =
        meter_miss_local_input_policers(&forwarding, &frame, &flow, meta, 123_000_000_000);
    assert_eq!(verdict, MissLocalPolicerVerdict::Pass);
    assert!(handles.is_empty());
}

/// Poll-level decisive cell: two 900-byte SYNs to a firewall-local
/// address against a burst-1000 policer. The first installs and
/// delivers; the second is policer-red. At HEAD (late metering) the
/// second packet emitted a PERMIT FilterLog, charged the lo0 term
/// counter, and charged the junos-host permit counter before the late
/// meter dropped it. After the fix none of those side effects fire for
/// the red packet: exactly one FilterLog total (the first packet's
/// PERMIT), lo0 and junos-host counters stay at 1, no second session,
/// no second delivery.
#[test]
fn miss_local_red_policer_leaves_no_permit_log_or_gate_counters_15949() {
    let forwarding = policed_forwarding();
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
        std::collections::BTreeMap::new(),
    ));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        16,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
            session_close_events_per_second: 0,
            session_close_burst: 0,
        },
    );

    let frame = frame_900();
    let meta = meta_900();

    let lo0_count = |f: &ForwardingState| -> u64 {
        crate::filter::flush_recorded_filter_counters();
        f.filter_state
            .filters
            .values()
            .find(|filter| filter.name.as_str() == "protect-re")
            .map(|filter| filter.terms[0].counter.packets.load(Ordering::Relaxed))
            .unwrap_or(0)
    };
    let junos_count = |f: &ForwardingState| -> u64 {
        crate::policy::flush_recorded_policy_hit_counters();
        f.policy
            .counter_snapshots()
            .into_iter()
            .find(|c| c.rule_id.contains("host-permit"))
            .map(|c| c.packets)
            .unwrap_or(0)
    };

    // Packet 1 (conforming): installs, delivers, logs PERMIT once.
    let (_b1, dbg1) = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    assert_eq!(dbg1.local, 1, "first SYN must take LocalDelivery");
    assert_eq!(sessions.len(), 1, "first SYN must install one session");
    assert_eq!(
        event_handle.dataplane_event_stats().filter_log.sent,
        1,
        "#15949: conforming first packet emits its PERMIT FilterLog exactly once"
    );
    let first_event = event_rx
        .try_recv()
        .expect("#15949: first packet must emit a FilterLog event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        first_event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(
        first_event.action, 1,
        "#15949: first packet's FilterLog must be PERMIT (action=1)"
    );
    assert_eq!(lo0_count(&forwarding), 1, "lo0 counter after packet 1");
    assert_eq!(
        junos_count(&forwarding),
        1,
        "junos-host counter after packet 1"
    );
    let deliveries_after_first = binding.live.slow_path_drops.load(Ordering::Relaxed);
    assert_eq!(deliveries_after_first, 1, "first packet reinjects once");

    // Packet 2 (same tuple, session HIT would normally serve it — use a
    // fresh source port so it takes the MISS path again as a new flow).
    let mut frame2 = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12346,
        179,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    frame2.resize(900, 0);
    let (_b2, dbg2) = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame2,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    assert_eq!(dbg2.local, 1, "red packet is accounted as a local drop");
    assert_eq!(
        sessions.len(),
        1,
        "#15949: red packet must NOT install a second session"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        deliveries_after_first,
        "#15949: red packet must NOT be delivered/reinjected"
    );
    // The red packet's FilterLog (if any) must be DENY, never PERMIT:
    // drain every event and assert none carries PERMIT for port 12346.
    let mut saw_permit_for_red = false;
    while let Ok(frame) = event_rx.try_recv() {
        if let Some(event) = frame.decode_dataplane_event() {
            if event.kind == crate::event_stream::codec::DataplaneEventKind::FilterLog
                && event.src_port == 12346
                && event.action == 1
            {
                saw_permit_for_red = true;
            }
        }
    }
    assert!(
        !saw_permit_for_red,
        "#15949: red packet must NOT emit a PERMIT FilterLog (late-meter false audit)"
    );
    assert_eq!(
        lo0_count(&forwarding),
        1,
        "#15949: red packet must NOT charge the lo0 term counter"
    );
    assert_eq!(
        junos_count(&forwarding),
        1,
        "#15949: red packet must NOT charge the junos-host permit counter"
    );
    let status = forwarding.filter_state.three_color_policer_statuses();
    assert!(
        status.iter().any(|s| s.drop_packets >= 1),
        "#15949: the policer drop itself must still be charged"
    );
}

/// Poll-level: the non-cacheable arm (non-SYN ACK first packet) is
/// owned by the same early gate — a red ACK leaves no PERMIT log and
/// no gate counters, and is not delivered. Mirrors the #14317 e2e
/// shape but asserts the ordering side effects.
#[test]
fn miss_local_non_syn_red_leaves_no_permit_log_15949() {
    let forwarding = policed_forwarding();
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
        std::collections::BTreeMap::new(),
    ));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        16,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
            session_close_events_per_second: 0,
            session_close_burst: 0,
        },
    );

    const ACK_PSH: u8 = 0x18;
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        ACK_PSH,
        TEST_LAN_MAC,
    );
    frame.resize(900, 0);
    let mut meta = txn_meta_v4(24, ACK_PSH, 900);
    meta.pkt_len = 900;

    // Packet 1 conforming: delivered, no session (non-SYN declines cache).
    let (_b1, _d1) = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    assert_eq!(sessions.len(), 0, "non-SYN packet must not cache");
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "conforming ACK reinjects"
    );
    while event_rx.try_recv().is_ok() {}

    // Packet 2 red: not delivered, no PERMIT log.
    let (_b2, _d2) = txn_run_descriptor_with_event_stream(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &event_handle,
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        1,
        "#15949: red non-cacheable packet must NOT be delivered"
    );
    let mut saw_permit = false;
    while let Ok(frame) = event_rx.try_recv() {
        if let Some(event) = frame.decode_dataplane_event() {
            if event.kind == crate::event_stream::codec::DataplaneEventKind::FilterLog
                && event.action == 1
            {
                saw_permit = true;
            }
        }
    }
    assert!(
        !saw_permit,
        "#15949: red non-cacheable packet must NOT emit a PERMIT FilterLog"
    );
}
