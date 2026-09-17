use super::*;
use crate::event_stream::codec::DataplaneEventKind;
use crate::event_stream::{DataplaneEventRateLimitConfig, EventStreamWorkerHandle};
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr};

/// A real CLOCK_MONOTONIC reading, mirroring what the worker poll loop
/// hands the emitters as `now_ns`. The emitters convert this to a
/// wall-clock Unix ns at emit time (#2470), so a realistic monotonic
/// instant is required for the conversion to produce a present-day
/// timestamp (a tiny synthetic value like `123` converts to ~0 because it
/// reads as an "ancient" monotonic instant).
fn mono_now_ns() -> u64 {
    crate::afxdp::neighbor::monotonic_nanos()
}

fn test_flow() -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip,
            dst_ip,
            src_port: 49152,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    }
}

/// #3058: a flow whose received destination is a PUBLIC address+port that
/// DNATs to an inside host (203.0.113.10:2222 -> 10.0.0.10:22). The
/// `forward_key` carries the original (pre-translation) tuple, exactly as
/// the live deny sites see it.
fn dnat_test_flow() -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip,
            dst_ip,
            src_port: 51000,
            dst_port: 2222,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    }
}

fn test_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 42,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    }
}

fn unlimited_handle() -> (
    EventStreamWorkerHandle,
    std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
) {
    crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    )
}

#[test]
fn policy_deny_event_emit_builds_rt_flow_payload() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        0,
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
    assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_POLICY);
    assert_eq!(event.ingress_zone_id, 7);
    assert_eq!(event.egress_zone_id, 9);
    assert_eq!(event.ingress_ifindex, 42);
    assert_eq!(event.policy_id, 101);
    assert_eq!(event.rule_id, 101);
    assert_eq!(event.owner_rg_id, 3);
    assert_eq!(event.src_port, 49152);
    assert_eq!(event.dst_port, 443);
    // #2470 fail-on-revert: the emitter stamps the dataplane DECISION
    // instant (wall-clock Unix ns) on the wire instead of 0. Reverting
    // `timestamp_ns` back to 0 makes the Go side fall back to RECEIVE
    // time; this assertion fails in that case.
    assert!(
        event.timestamp_ns > 0,
        "policy-deny event must carry a real wall-clock timestamp, got 0"
    );
    assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
}

#[test]
fn policy_deny_event_emit_carries_default_policy_sentinel() {
    // #3057: a deny produced by the implicit default-policy passes the
    // reserved sentinel ID through emit_policy_deny_event. The wire
    // policy_id (and the mirrored rule_id) must carry it unchanged so the
    // Go side renders "default-policy" instead of the first rule's name.
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        PolicyAction::Deny,
        0,
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(event.policy_id, crate::policy::DEFAULT_POLICY_SENTINEL_ID);
    assert_eq!(event.rule_id, crate::policy::DEFAULT_POLICY_SENTINEL_ID);
    assert_ne!(
        event.policy_id, 0,
        "the default-policy sentinel must not alias the first policy ID 0"
    );
}

#[test]
fn policy_deny_event_emit_reject_maps_to_reject_action() {
    // #2089: the policy-deny path now synthesizes a TCP RST / ICMP
    // unreachable for `reject`, so the RT_FLOW action must report
    // reject (was deny while reject was a silent drop).
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Reject,
        0,
        // #3615: the reply WAS enqueued, so REJECT is the truthful action.
        true,
        123,
    );

    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
    assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_POLICY);
    assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
}

/// #3615 fail-on-revert: a policy `then reject` whose synthesized reply was
/// SUPPRESSED (fail-closed silent drop — reject_reply_enqueued=false) must
/// report the truthful RT_FLOW_ACTION_DENY, not REJECT. Reverting
/// `policy_action_to_rt_flow` to map Reject→REJECT unconditionally makes the
/// event claim an active reject that was never sent — RED here.
#[test]
fn policy_deny_event_emit_suppressed_reject_reports_deny() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Reject,
        0,
        // Reply fail-closed to a silent drop.
        false,
        123,
    );

    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "a suppressed reject must log DENY (silent drop), not REJECT"
    );
}

/// #3610 fail-on-revert: the host-inbound deny emitter builds a tuple-rich
/// RT_FLOW deny event that rides the `PolicyDeny` wire kind (so it reuses the
/// #3615 policy-deny event machinery) but carries the DISTINCT host-inbound
/// reason and an unconditional DENY action (host-inbound is always a silent
/// drop, never a reject). Reverting the reason back to the policy reason — or
/// the action away from DENY — makes these assertions fail; the event would
/// then be indistinguishable from a transit security-policy deny (the #3610
/// conflation the fix removes).
#[test]
fn host_inbound_deny_event_carries_host_inbound_reason() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_host_inbound_deny_event(Some(&handle), &flow, test_meta(), 7, 0, mono_now_ns());

    let event = rx
        .try_recv()
        .expect("host-inbound deny frame")
        .decode_dataplane_event()
        .expect("host-inbound deny payload");
    assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
    assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_HOST_INBOUND);
    assert_ne!(
        event.reason, RT_FLOW_CLOSE_REASON_POLICY,
        "a host-inbound deny must NOT alias the transit policy-deny reason"
    );
    // No admitting/denying security policy on a host-inbound deny.
    assert_eq!(event.policy_id, 0);
    // Egress "zone" is the firewall host itself (#3110 sentinel 0).
    assert_eq!(event.egress_zone_id, 0);
    assert_eq!(event.ingress_zone_id, 7);
    // Full tuple so an operator sees WHICH control-plane flow was denied.
    assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
    assert_eq!(event.src_port, 49152);
    assert_eq!(event.dst_port, 443);
    assert_eq!(event.ingress_ifindex, 42);
    assert!(
        event.timestamp_ns > 0,
        "host-inbound deny event must carry a real wall-clock timestamp, got 0"
    );
    // Rides the policy-deny per-kind stats/rate-limiter — not a new channel.
    assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
}

#[test]
fn screen_drop_event_emit_uses_screen_reason_flag() {
    let (handle, rx) = unlimited_handle();
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 12345,
        dst_port: 80,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 60,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 60,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };

    emit_screen_drop_event(
        Some(&handle),
        &pkt,
        test_meta(),
        11,
        "land-attack",
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("screen event frame")
        .decode_dataplane_event()
        .expect("screen event payload");
    assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
    assert_eq!(event.screen_id, SCREEN_LAND_ATTACK);
    assert_eq!(event.ingress_zone_id, 11);
    assert_eq!(event.egress_zone_id, 0);
    assert_eq!(event.src_ip, pkt.src_ip);
    assert_eq!(event.dst_ip, pkt.dst_ip);
    // #2470 fail-on-revert: a real decision timestamp on the wire.
    assert!(
        event.timestamp_ns > 0,
        "screen-drop event must carry a real wall-clock timestamp, got 0"
    );
    assert_eq!(handle.dataplane_event_stats().screen_drop.sent, 1);
}

#[test]
fn screen_alarm_event_is_permit_not_deny() {
    // #2234 fail-on-revert: the scan-table-pressure ALARM must carry the
    // PERMIT action so downstream stats / syslog / dashboards do NOT count
    // it as a drop/deny (the packet still forwards). Reverting the alarm
    // emitter back to emit_screen_drop_event (action=DENY) breaks this.
    let (handle, rx) = unlimited_handle();
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
        src_port: 40000,
        dst_port: 443,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 1460,
        pkt_len: 60,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 60,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };

    emit_screen_alarm_event(
        Some(&handle),
        &pkt,
        test_meta(),
        2,
        "scan-table-pressure",
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("screen alarm frame")
        .decode_dataplane_event()
        .expect("screen alarm payload");
    assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
    assert_eq!(
        event.action, RT_FLOW_ACTION_PERMIT,
        "a pressure ALARM must not report a drop/deny action"
    );
    assert_eq!(event.screen_id, SCREEN_SCAN_TABLE_PRESSURE);
    assert_eq!(event.src_ip, pkt.src_ip);
    assert_eq!(event.dst_ip, pkt.dst_ip);
    // #2470 fail-on-revert: a real decision timestamp on the wire.
    assert!(
        event.timestamp_ns > 0,
        "screen-alarm event must carry a real wall-clock timestamp, got 0"
    );
}

#[test]
fn screen_reason_id_maps_icmp_fragment() {
    let (handle, rx) = unlimited_handle();
    let pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 60,
        is_fragment: true,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0x2000,
        ip_total_len: 60,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };

    emit_screen_drop_event(
        Some(&handle),
        &pkt,
        test_meta(),
        11,
        "icmp-fragment",
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("screen event frame")
        .decode_dataplane_event()
        .expect("screen event payload");
    assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
    assert_eq!(event.screen_id, SCREEN_ICMP_FRAGMENT);
}

#[test]
fn screen_reason_id_maps_ip_malformed() {
    // #2146: the fail-closed reason for an unparseable L3 header
    // must map to a dedicated screen_id bit so operators can tell a
    // malformed-frame drop apart from the syn-frag screen.
    assert_eq!(screen_reason_id("ip-malformed"), SCREEN_IP_MALFORMED);
    assert_ne!(SCREEN_IP_MALFORMED, SCREEN_SYN_FRAG);
}

#[test]
fn screen_reason_id_maps_scan_table_pressure() {
    // #2234: the bounded stalest-eviction operator ALARM must map to a
    // dedicated screen_id bit, distinct from the port-scan / ip-sweep
    // DROP reasons (it is a saturation signal, not a packet drop), so an
    // operator can tell "detector is saturated" apart from a real scan
    // detection.
    assert_eq!(
        screen_reason_id("scan-table-pressure"),
        SCREEN_SCAN_TABLE_PRESSURE
    );
    assert_ne!(SCREEN_SCAN_TABLE_PRESSURE, SCREEN_PORT_SCAN);
    assert_ne!(SCREEN_SCAN_TABLE_PRESSURE, SCREEN_IP_SWEEP);
}

#[test]
fn screen_parse_error_info_carries_flow_tuple() {
    // The fail-closed event built from meta+flow must log the
    // offending 5-tuple even though the packet bytes past L3 are
    // untrustworthy.
    let info = screen_parse_error_info(&test_meta(), &test_flow());
    assert_eq!(info.addr_family, libc::AF_INET as u8);
    assert_eq!(info.protocol, PROTO_TCP);
    assert_eq!(info.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(info.dst_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
    assert_eq!(info.src_port, 49152);
    assert_eq!(info.dst_port, 443);
}

#[test]
fn filter_log_event_emit_builds_rt_flow_payload() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        5,
        FilterAction::Accept,
        FilterLogSource::Input,
        0,
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("filter event frame")
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(event.action, RT_FLOW_ACTION_PERMIT);
    assert_eq!(event.filter_id, 23);
    assert_eq!(event.term_id, 5);
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.ingress_zone_id, 7);
    assert_eq!(event.egress_zone_id, 0);
    // #2470 fail-on-revert: a real decision timestamp on the wire.
    assert!(
        event.timestamp_ns > 0,
        "filter-log event must carry a real wall-clock timestamp, got 0"
    );
    assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
}

/// #2521: filter `then reject` now synthesizes an active reply (the
/// dataplane enqueues a TCP RST / ICMP unreachable), so the RT_FLOW filter
/// log reports REJECT — matching policy reject and Junos. (Pre-#2521 this
/// asserted DENY because no reply was generated.) `discard` still maps to
/// DENY (`filter_log_event_emit_discard_as_deny`).
#[test]
fn filter_log_event_emit_reject_reports_reject() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        6,
        FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
        FilterLogSource::Lo0,
        0,
        // #3615: the reply WAS enqueued, so REJECT is the truthful action.
        true,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("filter event frame")
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(event.action, RT_FLOW_ACTION_REJECT);
    assert_eq!(event.filter_id, 23);
    assert_eq!(event.term_id, 6);
    assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
    assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
}

/// #3615 fail-on-revert: a firewall-filter `then reject` whose reply was
/// SUPPRESSED (fail-closed — reject_reply_enqueued=false) must report the
/// truthful RT_FLOW_ACTION_DENY, honoring the FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED) contract
/// ("must not log that an ICMP/RST reject was generated" when the reply
/// cannot be synthesized). Reverting `filter_action_to_rt_flow` to map
/// Reject→REJECT unconditionally turns this RED.
#[test]
fn filter_log_event_emit_suppressed_reject_reports_deny() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        6,
        FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
        FilterLogSource::Lo0,
        0,
        // Reply fail-closed to a silent drop.
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("filter event frame")
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(
        event.action, RT_FLOW_ACTION_DENY,
        "a suppressed filter reject must log DENY (silent drop), not REJECT"
    );
}

/// #2521: `then discard` stays a silent drop → RT_FLOW DENY (the
/// distinction from reject above).
#[test]
fn filter_log_event_emit_discard_as_deny() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        6,
        FilterAction::Discard,
        FilterLogSource::Lo0,
        0,
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("filter event frame")
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(event.action, RT_FLOW_ACTION_DENY);
    assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
}

/// #2520 fail-on-revert: a CONFIGURED application (TCP/443 → app_id 7 in
/// the catalog) must surface in BOTH the policy-deny and filter-log RT_FLOW
/// records. The emitter call sites resolve the AppID with the SAME
/// `app_catalog.lookup` the forwarding hot path uses (here via
/// `resolve_flow_app_id`). Reverting the emitters back to a hardcoded
/// `application_id: 0` makes both assertions fail (the wire slot reads 0,
/// which the Go RT_FLOW logger renders as application="UNKNOWN").
#[test]
fn cold_path_events_carry_resolved_app_id() {
    // TCP/443 single-dst-port app → app_id 7 (matches test_flow()).
    let catalog = AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: 7,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let flow = test_flow();
    let app_id = resolve_flow_app_id(&catalog, &flow);
    assert_eq!(app_id, 7, "configured TCP/443 app must resolve to id 7");

    let (handle, rx) = unlimited_handle();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        app_id,
        false,
        mono_now_ns(),
    );
    let deny = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(
        deny.application_id, 7,
        "policy-deny RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );

    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        5,
        FilterAction::Accept,
        FilterLogSource::Input,
        app_id,
        false,
        mono_now_ns(),
    );
    let filt = rx
        .try_recv()
        .expect("filter event frame")
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(
        filt.application_id, 7,
        "filter-log RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );
}

/// #2520: a tuple with no catalog match resolves to 0 (UNKNOWN), the
/// unchanged behavior — we must NOT fabricate an AppID.
#[test]
fn cold_path_events_unresolvable_tuple_stays_zero() {
    let catalog = AppCatalog::default();
    assert_eq!(resolve_flow_app_id(&catalog, &test_flow()), 0);
}

/// #3058 fail-on-revert: a DNAT'd policy-deny RT_FLOW record must log the
/// PUBLIC dst in the 5-tuple AND the real internal dst in the nat_* fields
/// (the same convention `emit_session_close_rt_flow` uses for a permit),
/// and resolve the AppID from the POST-NAT port (22 -> junos-ssh), not the
/// pre-NAT port (2222 -> UNKNOWN). Reverting the emitter back to hardcoded
/// `nat_*: None/0` + pre-NAT AppID makes this test RED.
#[test]
fn policy_deny_event_dnat_logs_post_translation_dst_and_app() {
    let inside = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    // TCP/22 → app_id 17 (stand-in for junos-ssh).
    let catalog = AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: 17,
        protocol: PROTO_TCP,
        dst_port_low: 22,
        dst_port_high: 22,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let flow = dnat_test_flow();
    let nat = NatDecision {
        rewrite_dst: Some(inside),
        rewrite_dst_port: Some(22),
        ..NatDecision::default()
    };
    // `policy_dst_port` at the deny call site is the translated dst port.
    let app_id = resolve_policy_deny_app_id(&catalog, &flow, 22);
    assert_eq!(
        app_id, 17,
        "post-NAT dst port 22 must resolve junos-ssh(17)"
    );
    // The pre-NAT resolution (the #3058 bug) resolves UNKNOWN(0).
    assert_eq!(
        resolve_flow_app_id(&catalog, &flow),
        0,
        "pre-NAT dst port 2222 resolves UNKNOWN — the misleading old behavior"
    );

    let (handle, rx) = unlimited_handle();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &nat,
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        app_id,
        false,
        mono_now_ns(),
    );
    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    // 5-tuple = ORIGINAL public dst.
    assert_eq!(event.dst_ip, flow.dst_ip);
    assert_eq!(event.dst_port, 2222);
    // nat_* = TRANSLATED internal dst.
    assert_eq!(event.nat_dst_ip, Some(inside));
    assert_eq!(event.nat_dst_port, 22);
    // No source translation on a denied flow.
    assert_eq!(event.nat_src_ip, None);
    assert_eq!(event.nat_src_port, 0);
    // AppID from the post-NAT tuple.
    assert_eq!(event.application_id, 17);
}

/// #3058: a deny whose NatDecision carries a SOURCE rewrite (NPTv6 / SNAT)
/// must populate the nat_src_* fields, mirroring the permit/session-close
/// record. The emitter serializes every field from the decision.
#[test]
fn policy_deny_event_source_translation_logs_nat_src() {
    let xlated_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
    let flow = test_flow(); // src 192.0.2.10:49152 -> dst 198.51.100.20:443
    let nat = NatDecision {
        rewrite_src: Some(xlated_src),
        rewrite_src_port: Some(40000),
        nptv6: true,
        ..NatDecision::default()
    };
    let (handle, rx) = unlimited_handle();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &nat,
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        0,
        false,
        mono_now_ns(),
    );
    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    // 5-tuple = ORIGINAL src.
    assert_eq!(event.src_ip, flow.src_ip);
    assert_eq!(event.src_port, 49152);
    // nat_* = TRANSLATED src.
    assert_eq!(event.nat_src_ip, Some(xlated_src));
    assert_eq!(event.nat_src_port, 40000);
    assert_eq!(event.nat_dst_ip, None);
    assert_eq!(event.nat_dst_port, 0);
}

/// #3058 regression guard (the GREEN-stays half of the fail-on-revert
/// exercise): a deny with NO translation (default NatDecision) keeps the
/// original 5-tuple and EMPTY nat fields — byte-identical to the pre-#3058
/// record. Only NAT'd denies change.
#[test]
fn policy_deny_event_non_nat_has_empty_nat_fields() {
    let flow = test_flow();
    let (handle, rx) = unlimited_handle();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        0,
        false,
        mono_now_ns(),
    );
    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(event.src_ip, flow.src_ip);
    assert_eq!(event.dst_ip, flow.dst_ip);
    assert_eq!(event.src_port, 49152);
    assert_eq!(event.dst_port, 443);
    assert_eq!(event.nat_src_ip, None);
    assert_eq!(event.nat_dst_ip, None);
    assert_eq!(event.nat_src_port, 0);
    assert_eq!(event.nat_dst_port, 0);
}

/// #2470: two events emitted in monotonic-instant order carry
/// non-decreasing wall-clock timestamps on the wire. This is the timeline
/// correctness property the fix delivers: under queued / backlogged
/// Go-side delivery the logged ordering reflects the DECISION instants,
/// not the (possibly reordered or bunched) consumption instants.
#[test]
fn emitted_timestamps_are_non_decreasing() {
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();

    let t0 = mono_now_ns();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        7,
        9,
        3,
        101,
        PolicyAction::Deny,
        0,
        false,
        t0,
    );
    // A strictly later monotonic instant for the second event.
    let t1 = mono_now_ns().max(t0 + 1);
    emit_filter_log_event(
        Some(&handle),
        &flow,
        test_meta(),
        7,
        0,
        23,
        5,
        FilterAction::Accept,
        FilterLogSource::Input,
        0,
        false,
        t1,
    );

    let first = rx
        .try_recv()
        .expect("first event frame")
        .decode_dataplane_event()
        .expect("first event payload");
    let second = rx
        .try_recv()
        .expect("second event frame")
        .decode_dataplane_event()
        .expect("second event payload");
    assert!(first.timestamp_ns > 0, "first event must be stamped");
    assert!(second.timestamp_ns > 0, "second event must be stamped");
    assert!(
        second.timestamp_ns >= first.timestamp_ns,
        "events emitted in monotonic order must have non-decreasing \
             wall-clock timestamps: first={} second={}",
        first.timestamp_ns,
        second.timestamp_ns
    );
}

/// #9989: the RT_FLOW PolicyDeny record for an unzoned-ingress deny AGREES
/// with the policy evaluation result — both record paths carry the
/// unattributed id, never the default-policy sentinel.
///
/// Threads `result.policy_id` through `emit_policy_deny_event` exactly as the
/// transit deny sites do (`poll_descriptor/mod.rs` passes
/// `policy_result.policy_id`), then decodes the frame and pins both paths to
/// the same value. The Go side renders that value `unattributed`
/// (`logging.EventReader.resolvePolicyName` honors
/// `dataplane.ReservedPolicyName`, pinned by the #3057 sentinel test and the
/// #4626/#6851 zero-id tests); the sentinel would render `default-policy`.
///
/// Fail-on-revert: restoring the sentinel in the #6682 arm turns BOTH the
/// result and the wire record back into `default-policy` (RED here and in
/// `unzoned_ingress_deny_is_unattributed_not_default_policy_9989`).
#[test]
fn unzoned_deny_rt_flow_agrees_with_policy_result_9989() {
    use crate::policy::{evaluate_policy_result_l3_aware, parse_policy_state};
    use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};

    let mut zones: rustc_hash::FxHashMap<String, u16> = Default::default();
    zones.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    zones.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    let state = parse_policy_state(
        "permit",
        &[crate::PolicyRuleSnapshot {
            rule_id: "both-any-permit".to_string(),
            name: "baseline-allow".to_string(),
            from_zone: "any".to_string(),
            to_zone: "any".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &zones,
    );
    let result = evaluate_policy_result_l3_aware(
        &state,
        0,
        TEST_WAN_ZONE_ID,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 5)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        PROTO_TCP,
        40000,
        443,
        None,
        64,
        true,
    );
    assert_eq!(
        result.action,
        crate::policy::PolicyAction::Deny,
        "setup: an unzoned ingress must be denied (#6682)",
    );

    // The transit deny sites pass `policy_result.policy_id` straight into
    // the emitter; mirror that call shape (unzoned from-zone 0).
    let (handle, rx) = unlimited_handle();
    let flow = test_flow();
    emit_policy_deny_event(
        Some(&handle),
        &flow,
        &NatDecision::default(),
        test_meta(),
        0,
        TEST_WAN_ZONE_ID,
        0,
        result.policy_id,
        result.action,
        0,
        false,
        mono_now_ns(),
    );

    let event = rx
        .try_recv()
        .expect("policy event frame")
        .decode_dataplane_event()
        .expect("policy event payload");
    assert_eq!(
        event.policy_id, result.policy_id,
        "the RT_FLOW PolicyDeny record must agree with the policy evaluation \
         result (#9989)",
    );
    assert_eq!(
        event.rule_id, result.policy_id,
        "the mirrored rule_id rides the same attribution (#9989)",
    );
    assert_eq!(
        result.policy_id,
        crate::policy::UNATTRIBUTED_POLICY_ID,
        "both record paths must carry the unattributed id (#9989)",
    );
    assert_ne!(
        event.policy_id,
        crate::policy::DEFAULT_POLICY_SENTINEL_ID,
        "the RT_FLOW record for an unzoned deny must not alias \
         default-policy (#9989)",
    );
}
