use super::*;
use crate::event_stream::EventStreamWorkerHandle;
use crate::event_stream::codec::{DataplaneEventKind, DataplaneEventPayload};
use crate::filter::FilterAction;
use crate::nat::NatDecision;
use crate::policy::{AppCatalog, PolicyAction};
use crate::screen::ScreenPacketInfo;

const RT_FLOW_ACTION_DENY: u8 = 0;
const RT_FLOW_ACTION_PERMIT: u8 = 1;
pub(in crate::afxdp) const RT_FLOW_ACTION_REJECT: u8 = 2;
const RT_FLOW_CLOSE_REASON_POLICY: u8 = 5;
// #3610: a host-inbound-traffic admission deny (the ingress zone's
// `host-inbound-traffic` gate rejecting a host-bound / control-plane packet) is
// NOT a transit security-policy deny. It rides the SAME `PolicyDeny` event kind
// / wire path (so it inherits the per-kind rate limiter, queue budget, and Go
// RT_FLOW rendering — no parallel emit path), but carries this distinct reason
// byte so the Go structured RT_FLOW_SESSION_DENY record and operators can tell a
// control-plane host-inbound drop apart from a transit policy deny. Must equal
// the Go `closeReasonHostInbound` (pkg/logging/ringbuf.go).
const RT_FLOW_CLOSE_REASON_HOST_INBOUND: u8 = 6;
const NS_PER_SEC: u64 = 1_000_000_000;

const SCREEN_SYN_FLOOD: u32 = 1 << 0;
const SCREEN_ICMP_FLOOD: u32 = 1 << 1;
const SCREEN_UDP_FLOOD: u32 = 1 << 2;
const SCREEN_PORT_SCAN: u32 = 1 << 3;
const SCREEN_IP_SWEEP: u32 = 1 << 4;
const SCREEN_LAND_ATTACK: u32 = 1 << 5;
const SCREEN_PING_OF_DEATH: u32 = 1 << 6;
const SCREEN_TEARDROP: u32 = 1 << 7;
const SCREEN_TCP_SYN_FIN: u32 = 1 << 8;
const SCREEN_TCP_NO_FLAG: u32 = 1 << 9;
const SCREEN_TCP_FIN_NO_ACK: u32 = 1 << 10;
const SCREEN_WINNUKE: u32 = 1 << 11;
const SCREEN_IP_SOURCE_ROUTE: u32 = 1 << 12;
const SCREEN_SYN_FRAG: u32 = 1 << 13;
const SCREEN_SYN_COOKIE: u32 = 1 << 14;
const SCREEN_SESSION_LIMIT_SRC: u32 = 1 << 15;
const SCREEN_SESSION_LIMIT_DST: u32 = 1 << 16;
const SCREEN_ICMP_FRAGMENT: u32 = 1 << 17;
/// #2146: a frame whose L3 header could not be parsed far enough to
/// evaluate the fragment/TCP screens (e.g. a truncated IPv6
/// extension-header chain) is dropped FAIL-CLOSED under this reason.
const SCREEN_IP_MALFORMED: u32 = 1 << 18;
/// #2234: NOT a packet drop — a rare (logarithmic) operator ALARM that the
/// per-zone scan/sweep source table is saturated and the detector is
/// displacing stale sources (bounded stalest-eviction) to keep tracking a
/// fresh real scanner under a high-cardinality spoofed flood. Rides the
/// screen event path so it surfaces alongside other screen activity; the
/// triggering 5-tuple is the new source that forced an eviction.
const SCREEN_SCAN_TABLE_PRESSURE: u32 = 1 << 19;
/// #3315: the per-zone SYN rate crossed `alarm-threshold` (below
/// `attack-threshold`). A log-only NOTICE-severity alarm, NOT a drop — like
/// scan-table-pressure it rides the screen event frame with action=PERMIT, so
/// the packet still forwards. Rate-limited to ≤1/sec/zone in the screen runtime.
const SCREEN_SYN_FLOOD_ALARM: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FilterLogSource {
    Pbr,
    Input,
    Output,
    CachedOutput,
    Lo0,
}

impl FilterLogSource {
    #[inline]
    pub(super) fn wire_reason(self) -> u8 {
        match self {
            Self::Pbr => 1,
            Self::Input => 2,
            Self::Output => 3,
            Self::CachedOutput => 4,
            Self::Lo0 => 5,
        }
    }
}

#[inline]
pub(super) fn event_now_ns_from_secs(now_secs: u64) -> u64 {
    now_secs.saturating_mul(NS_PER_SEC)
}

/// #2520: resolve the AppID for a cold-path RT_FLOW record (policy-deny /
/// filter-log / session-close) from the flow 5-tuple, reusing the SAME
/// direction-aware `app_catalog` the forwarding hot path runs when it stamps
/// the conntrack entry. #3321: a cold-path record carries the received
/// (forward) 5-tuple, so this uses `lookup_forward` — the service port is the
/// DESTINATION and a forward flow whose source port coincides with a service
/// port is NOT mislabeled. (The session-create / -close stamps that DO know
/// their binding direction call `lookup_directional` with `metadata.is_reverse`
/// so a legitimately reverse-keyed session still resolves on the src slot.)
/// Returns 0 (UNKNOWN) when nothing matches, which the Go RT_FLOW logger
/// renders as `application="UNKNOWN"` — the unchanged behavior for an
/// unresolvable tuple.
#[inline]
pub(super) fn resolve_flow_app_id(app_catalog: &AppCatalog, flow: &SessionFlow) -> u16 {
    // #3321: a cold-path record carries the received (forward) 5-tuple, so the
    // service port is the destination — resolve forward-directionally so a
    // forward flow whose source port coincides with a service port is not
    // mislabeled.
    app_catalog.lookup_forward(
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
    )
}

/// #3058: resolve the AppID for a policy-DENY RT_FLOW record from the
/// POST-translation destination port the policy was actually evaluated
/// against. #2345 moved DNAT/static-NAT/inbound-NPTv6 policy evaluation to
/// the translated destination tuple, so the deny log's application must be
/// resolved from that same translated port (e.g. a public `:2222` DNAT'd to
/// inside `:22` resolves `junos-ssh`, not UNKNOWN(2222)). `policy_dst_port`
/// is `policy_dst_port` at the deny call sites (the value fed to
/// `evaluate_policy_result_with_len`). For a non-NAT deny it equals
/// `flow.forward_key.dst_port`, so the result is byte-identical to
/// `resolve_flow_app_id`. The catalog probe is the SAME `app_catalog.lookup`
/// the forwarding hot path runs, so no resolution logic is duplicated.
#[inline]
pub(super) fn resolve_policy_deny_app_id(
    app_catalog: &AppCatalog,
    flow: &SessionFlow,
    policy_dst_port: u16,
) -> u16 {
    // #3321: forward-directional — the policy was evaluated against the
    // (post-translation) destination port, which is the service slot.
    app_catalog.lookup_forward(
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        policy_dst_port,
    )
}

#[inline]
pub(super) fn emit_policy_deny_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    nat: &NatDecision,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    owner_rg_id: i32,
    policy_id: u32,
    action: PolicyAction,
    app_id: u16,
    // #3615: the ACTUAL outcome of the reject-reply enqueue. When `action` is
    // `Reject` but no reply was enqueued (fail-closed silent drop), the wire
    // action is downgraded to DENY so the event never claims an active reject
    // that was not sent. Ignored for `Deny`/`Permit`; a policy `deny` remains
    // DENY and does not enter the tcp-rst session-miss reset path.
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: policy_action_to_rt_flow(action, reject_reply_enqueued),
        // #3058: the 5-tuple carries the ORIGINAL (received) addresses/ports;
        // the nat_* fields below carry the TRANSLATED values — the SAME
        // convention `emit_session_close_rt_flow` follows for a permitted
        // session (event_stream/mod.rs: `delta.key.*` for the tuple,
        // `nat.rewrite_*` for the nat-* slots). A denied DNAT/static-NAT/
        // inbound-NPTv6 flow therefore logs the public/received dst in
        // dst_ip/dst_port AND the real internal dst in nat_dst_ip/nat_dst_port,
        // matching how a permit record represents the same translation.
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        // #3058: populate the NAT slots from the decision the policy was
        // evaluated against (#2345 post-translation tuple) instead of the old
        // hardcoded None/0. A non-NAT deny passes a default `NatDecision`
        // (all-None), so the wire is byte-identical to the pre-#3058 record.
        nat_src_ip: nat.rewrite_src,
        nat_dst_ip: nat.rewrite_dst,
        nat_src_port: nat.rewrite_src_port.unwrap_or(0),
        nat_dst_port: nat.rewrite_dst_port.unwrap_or(0),
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id,
        rule_id: policy_id,
        term_id: 0,
        // #10978: the numeric ID is positional; its map is trustworthy only
        // for the config generation that evaluated the deny.
        config_generation: meta.config_generation,
        reason: RT_FLOW_CLOSE_REASON_POLICY,
        owner_rg_id: owner_rg_id_to_wire(owner_rg_id),
        // #2520: carry the resolved AppID (the caller runs the same
        // app_catalog.lookup the hot path uses) so policy-deny RT_FLOW
        // records show the resolved application instead of UNKNOWN.
        application_id: app_id,
        filter_id: 0,
        screen_id: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns)
        // here at emit time so a backlogged Go-side delivery cannot skew the
        // logged event time to consumption time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

/// #3610: emit a tuple-rich RT_FLOW deny event for a host-inbound-traffic
/// admission deny — a host-bound (LocalDelivery) packet rejected by the ingress
/// zone's `host-inbound-traffic` gate. Before #3610 these drops were accounted
/// only as aggregate counters (`host_inbound_denied_packets`) with no dataplane
/// event, so operators could see THAT host-inbound denies happened but not who
/// hit which control-plane service.
///
/// Reuses the #3615 policy-deny event machinery: the SAME
/// `DataplaneEventKind::PolicyDeny` wire kind, per-kind rate limiter, queue
/// budget, and Go RT_FLOW renderer / decoder — no parallel emit path is added.
/// Only the reason byte (`RT_FLOW_CLOSE_REASON_HOST_INBOUND`) distinguishes it
/// from a transit security-policy deny.
///
/// A host-inbound admission deny is ALWAYS a silent drop: there is no admitting/
/// denying security policy and no reject reply is ever synthesized, so the action
/// is unconditionally DENY, `policy_id`/`rule_id` are 0 (not a security policy),
/// the egress "zone" is the firewall host itself (#3110 sentinel 0, matching the
/// junos-host deny), `owner_rg_id` is 0 (host-local, not policy-forwarded), and
/// the record carries no NAT translation. The 5-tuple, ingress zone, ingress
/// ifindex, protocol, and resolved application come from the denied flow so an
/// operator can see WHICH control-plane flow was dropped (issue #3610 / Codex
/// H06 + L04). Cold path only (LocalDelivery deny).
#[inline]
pub(super) fn emit_host_inbound_deny_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    app_id: u16,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        // Host-inbound admission is a silent drop — never a reject.
        action: RT_FLOW_ACTION_DENY,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        // LocalDelivery applies no NAT to a host-bound packet.
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        // The egress "zone" is the firewall host itself; carry the #3110
        // sentinel 0, same as the junos-host deny (see emit_junos_host_deny).
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        // Host-inbound admission is not a security policy — no policy/rule id.
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        config_generation: meta.config_generation,
        reason: RT_FLOW_CLOSE_REASON_HOST_INBOUND,
        // Host-local sessions are not policy-forwarded; owner_rg_id 0.
        owner_rg_id: 0,
        application_id: app_id,
        filter_id: 0,
        screen_id: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
pub(super) fn emit_screen_drop_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    pkt: &ScreenPacketInfo,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    reason: &'static str,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::ScreenDrop,
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        action: RT_FLOW_ACTION_DENY,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        reason: 0,
        owner_rg_id: 0,
        application_id: 0,
        filter_id: 0,
        screen_id: screen_reason_id(reason),
        config_generation: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

/// Emit a screen ALARM event — a `ScreenDrop`-kind event that did NOT drop
/// the packet (#2234 scan-table-pressure). It shares the screen event frame
/// so it surfaces alongside other screen activity, but the RT_FLOW action is
/// PERMIT (the flow forwards). The Go consumers classify the screen event by
/// BOTH kind AND action (#2298): a screen event with action=PERMIT is counted
/// as a screen ALARM (not a screen drop) and logged at NOTICE severity (not
/// ERROR), so downstream stats / syslog / dashboards do NOT treat it as a
/// deny/drop. See `pkg/dataplane/userspace/eventstream.go`
/// (`recordDataplaneEvent`) and `pkg/logging/ringbuf.go` (`eventSeverity`).
/// The `reason` maps to a dedicated `screen_id` bit; the 5-tuple is the source
/// that forced an eviction.
#[inline]
pub(super) fn emit_screen_alarm_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    pkt: &ScreenPacketInfo,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    reason: &'static str,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::ScreenDrop,
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        // PERMIT — this is a saturation alarm, not a drop. The packet still
        // forwards; reporting DENY here would inflate drop/deny counters.
        action: RT_FLOW_ACTION_PERMIT,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        reason: 0,
        owner_rg_id: 0,
        application_id: 0,
        filter_id: 0,
        screen_id: screen_reason_id(reason),
        config_generation: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time, same as the screen-drop path. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

/// Build a minimal `ScreenPacketInfo` describing an L3 header that the
/// screen extractor could NOT parse (#2146 fail-closed path). The
/// packet bytes are untrustworthy past L3, so only the fields the
/// upstream metadata/flow parser already resolved are populated —
/// enough for `emit_screen_drop_event` to log the offending 5-tuple.
/// Fragment/TCP fields stay at their conservative defaults; the verdict
/// is already DROP so they are never consulted for a screen decision.
#[inline]
pub(super) fn screen_parse_error_info(
    meta: &UserspaceDpMeta,
    flow: &SessionFlow,
) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: meta.addr_family,
        protocol: meta.protocol,
        tcp_flags: meta.tcp_flags,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: meta.pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

/// #3064: flowless variant of `screen_parse_error_info`. The non-first
/// fragment path has no `SessionFlow` (it is deliberately left flowless
/// by #2344 so the fragment payload is never parsed as L4 ports), so
/// there are no L4 PORTS to log. Everything the upstream metadata parser
/// already resolved IS logged: `addr_family`, `protocol` and `pkt_len`
/// come from the authoritative `UserspaceDpMeta`, and the L3 addresses
/// come from the caller's `flowless_l3_addrs` read of the IP header (a
/// non-first fragment / ICMP control message carries a full IP header;
/// that helper already returns the family-correct UNSPECIFIED placeholder
/// when the header is too short to read, so a wholly unreadable frame
/// degrades exactly as it did before).
///
/// #5190 (A1-b1-F5): `protocol`, `pkt_len` and both L3 addresses used to
/// be hard-coded 0 / UNSPECIFIED here while the authoritative values sat
/// unused at the single call site, so EVERY flowless malformed-packet
/// screen drop reported `protocol=0` and `0.0.0.0`/`::` to
/// syslog/NetFlow. Taking `&UserspaceDpMeta` plus the derived addresses
/// rather than a bare `addr_family` makes the omission unrepresentable.
/// `addr_family`/`protocol`/`src_ip`/`dst_ip` reach the wire through
/// `emit_screen_drop_event`; `pkt_len` is not part of that event payload
/// but is populated so the struct is not silently untruthful to any
/// future reader. Ports and the fragment/TCP fields stay at their
/// conservative defaults; the verdict is already DROP, so they are never
/// consulted for a screen decision (the per-reason drop counter is keyed
/// by the reason STRING, not by anything in this struct).
#[inline]
pub(super) fn screen_parse_error_info_flowless(
    meta: &UserspaceDpMeta,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
) -> ScreenPacketInfo {
    ScreenPacketInfo {
        addr_family: meta.addr_family,
        protocol: meta.protocol,
        tcp_flags: 0,
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: meta.pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    }
}

#[inline]
pub(super) fn emit_filter_log_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    filter_id: u32,
    term_id: u32,
    action: FilterAction,
    source: FilterLogSource,
    app_id: u16,
    // #3615: the ACTUAL outcome of the reject-reply enqueue for a filter
    // `then reject`. When `action` is `Reject` but the reply was suppressed
    // (fail-closed silent drop) the wire action is downgraded to DENY so the
    // filter-log never claims an active reject that was not sent. Ignored for
    // `Accept`/`Discard`; callers on a non-reject or reply-free path (accept
    // `then log`, cached-log replay, flowless fragment) pass `false`.
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::FilterLog,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: filter_action_to_rt_flow(action, reject_reply_enqueued),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id,
        reason: source.wire_reason(),
        owner_rg_id: 0,
        // #2520: carry the resolved AppID so filter-log RT_FLOW records show
        // the resolved application instead of UNKNOWN. Same lookup as the hot
        // path (see resolve_flow_app_id).
        application_id: app_id,
        filter_id,
        screen_id: 0,
        config_generation: 0,
        // #2470: stamp the dataplane DECISION instant (wall-clock Unix ns) at
        // emit time. `now_ns` is CLOCK_MONOTONIC.
        timestamp_ns: crate::event_stream::mono_ns_to_wall_clock_unix_ns(now_ns),
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
fn policy_action_to_rt_flow(action: PolicyAction, reject_reply_enqueued: bool) -> u8 {
    match action {
        PolicyAction::Permit => RT_FLOW_ACTION_PERMIT,
        PolicyAction::Deny => RT_FLOW_ACTION_DENY,
        // #2089: the policy-deny path synthesizes a TCP RST / ICMP
        // unreachable for `reject` (poll_descriptor reject_reply), so a
        // reject whose reply was ACTUALLY enqueued reports RT_FLOW_ACTION_-
        // REJECT, matching the wire behavior and Junos.
        //
        // #3615: the reply can fail-close AFTER the action is decided (TX
        // budget exhausted, reject token bucket empty, unparseable built
        // frame, or an egress output-filter drop of the reflected reply). In
        // that case the packet is a SILENT drop, so the truthful RT_FLOW
        // action is DENY, not REJECT — the event must not claim an active
        // reject was sent when it was suppressed. The caller passes the real
        // enqueue outcome (see enqueue_deny_reply / enqueue_filter_reject_-
        // reply), so a suppressed reject is logged as DENY.
        PolicyAction::Reject if reject_reply_enqueued => RT_FLOW_ACTION_REJECT,
        PolicyAction::Reject => RT_FLOW_ACTION_DENY,
    }
}

#[inline]
fn filter_action_to_rt_flow(action: FilterAction, reject_reply_enqueued: bool) -> u8 {
    match action {
        FilterAction::Accept => RT_FLOW_ACTION_PERMIT,
        FilterAction::Discard => RT_FLOW_ACTION_DENY,
        // #2521: filter `then reject` synthesizes an active reply (TCP RST /
        // ICMP unreachable) via the same path as policy reject
        // (poll_descriptor enqueue_filter_reject_reply). #3615: report REJECT
        // only when the reply was actually enqueued; if it fail-closed to a
        // silent drop (budget/rate/parse/output-filter), report the truthful
        // DENY — honoring the FilterAction::Reject(RejectMessage::ADMIN_PROHIBITED) contract ("callers that
        // cannot synthesize the reject packet ... must not log that an
        // ICMP/RST reject was generated"). `discard` is always a silent drop
        // → deny.
        FilterAction::Reject(_) if reject_reply_enqueued => RT_FLOW_ACTION_REJECT,
        FilterAction::Reject(_) => RT_FLOW_ACTION_DENY,
    }
}

#[inline]
fn ingress_ifindex_to_wire(ifindex: u32) -> i32 {
    ifindex.min(i32::MAX as u32) as i32
}

#[inline]
fn owner_rg_id_to_wire(owner_rg_id: i32) -> i16 {
    owner_rg_id.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

#[inline]
fn screen_reason_id(reason: &'static str) -> u32 {
    match reason {
        "syn-flood" => SCREEN_SYN_FLOOD,
        "icmp-flood" => SCREEN_ICMP_FLOOD,
        "udp-flood" => SCREEN_UDP_FLOOD,
        "port-scan" => SCREEN_PORT_SCAN,
        "ip-sweep" => SCREEN_IP_SWEEP,
        "land-attack" => SCREEN_LAND_ATTACK,
        "ping-of-death" => SCREEN_PING_OF_DEATH,
        "teardrop" => SCREEN_TEARDROP,
        "tcp-syn-fin" => SCREEN_TCP_SYN_FIN,
        "tcp-no-flag" => SCREEN_TCP_NO_FLAG,
        "tcp-fin-no-ack" => SCREEN_TCP_FIN_NO_ACK,
        "winnuke" => SCREEN_WINNUKE,
        "ip-source-route" => SCREEN_IP_SOURCE_ROUTE,
        "syn-frag" => SCREEN_SYN_FRAG,
        "syn-cookie" | "syn-cookie-unavailable" => SCREEN_SYN_COOKIE,
        "session-limit-src" => SCREEN_SESSION_LIMIT_SRC,
        "session-limit-dst" => SCREEN_SESSION_LIMIT_DST,
        "icmp-fragment" => SCREEN_ICMP_FRAGMENT,
        "ip-malformed" => SCREEN_IP_MALFORMED,
        "scan-table-pressure" => SCREEN_SCAN_TABLE_PRESSURE,
        "syn-flood-alarm" => SCREEN_SYN_FLOOD_ALARM,
        _ => 0,
    }
}

#[cfg(test)]
#[path = "event_emit_tests.rs"]
mod tests;
