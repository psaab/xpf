// #6386 leaf extraction: the Junos host-inbound / to-zone junos-host
// policy helpers (#3019/#3292/#3610/#3706), lifted verbatim out of
// poll_descriptor/mod.rs: policy_packet_icmp, junos_host_policy_eval,
// enum JunosHostLocalPolicy, emit_junos_host_deny, emit_host_inbound_deny,
// junos_host_local_policy. policy_packet_icmp keeps its #[inline]; the
// two per-packet-capable evaluators junos_host_policy_eval and
// junos_host_local_policy GAIN #[inline] (the only non-motion change,
// #6386 hot-path preservation contract — restores same-CGU inlining
// eligibility across the new module boundary); the two cold event
// emitters stay un-hinted. Bodies byte-identical to their prior location.

use super::*;
use super::reject_reply::enqueue_deny_reply;

/// #3020: extract the ICMP/ICMPv6 `(type, code)` for policy matching. Returns
/// `None` for non-ICMP protocols, and for ICMP/ICMPv6 frames whose type/code
/// bytes are not safely readable (a truncated frame or a non-first fragment),
/// so an icmp-type-constrained application term (junos-ping = echo-request only)
/// fails closed rather than matching against a fabricated type/code of 0.
///
/// Reuses the canonical, fragment/truncation-safe extractor
/// `term_match_extra_from_frame` (the same one the firewall-filter icmp-type
/// terms consume), so the policy and filter planes agree on which type/code a
/// frame carries. Cold-path only (policy is evaluated on session miss).
#[inline]
pub(super) fn policy_packet_icmp(packet_frame: &[u8], meta: UserspaceDpMeta) -> Option<(u8, u8)> {
    if !matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return None;
    }
    let extra = crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta);
    if extra.l4_present {
        Some((extra.icmp_type, extra.icmp_code))
    } else {
        None
    }
}

/// #3019: enforce a configured `to-zone junos-host` security policy on the
/// host-bound (LocalDelivery) path. MUST be called AFTER `host_inbound_admits`
/// (Junos order: host-inbound-traffic admission first, then security policy),
/// so a `then permit` can never re-admit what host-inbound already rejected.
/// The gate itself is [`junos_host_local_policy`], which returns a
/// [`JunosHostLocalPolicy`] verdict (drop / permit-with-metadata / no-match);
/// [`junos_host_policy_eval`] is the reply-FREE evaluation core it and the
/// flowless arm share.
///
/// #3019/#3292: evaluate the configured `to-zone junos-host` security policy for
/// a host-bound (LocalDelivery) packet and, on a matching deny/reject, emit the
/// policy-deny RT_FLOW. This is the reply-FREE core shared by both the
/// flow-backed [`junos_host_local_policy`] gate (which adds the synthesized
/// reject/tcp-rst reply on a deny/reject and surfaces a permit's metadata) and
/// the flowless LocalDelivery arm (#3292, which can emit no reply — a fragment
/// has no L4 header to build a RST from).
///
/// `l4_present = false` routes through the l3-aware junos-host evaluation so a
/// port-bearing application term fails closed for a flowless packet; the
/// flow-backed wrapper passes `true` (byte-identical to pre-#3292).
///
/// #3706: returns the FULL [`PolicyEvaluationResult`] of a matching junos-host
/// rule — permit as well as deny/reject — so the local-delivery session-install
/// path can stamp a matching PERMIT's `then log` selection, admitting
/// `policy_id`, and hit-counter handle onto the installed host-bound session
/// (parity with the transit permit path). `None` means no junos-host policy is
/// configured or none matched; the caller then keeps the default no-policy
/// local-session metadata. Callers that only gate (drop on deny/reject) inspect
/// `result.action` themselves.
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) fn junos_host_policy_eval(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    // #9529: the destination the policy is asked about — post-translation for a
    // host-bound packet that only reached the firewall through a DNAT. See
    // [`host_bound_policy_dst`].
    policy_dst: (IpAddr, u16),
    from_zone_id: u16,
    packet_len: u64,
    l4_present: bool,
    packet_icmp: Option<(u8, u8)>,
) -> Option<crate::policy::PolicyEvaluationResult> {
    crate::policy::evaluate_junos_host_policy_l3_aware(
        &forwarding.policy,
        from_zone_id,
        flow.src_ip,
        policy_dst.0,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        policy_dst.1,
        packet_icmp,
        packet_len,
        l4_present,
    )
}

/// #3706: verdict of the flow-backed `to-zone junos-host` security-policy gate
/// on the local-delivery (host-inbound) path, returned by
/// [`junos_host_local_policy`]. The pre-#3706 gate collapsed to a bare `bool`
/// (dropped?) and discarded a matching permit's metadata, so a
/// `to-zone junos-host then permit log` session installed with no log flags and
/// `policy_id` 0 — unlogged and unattributable.
pub(super) enum JunosHostLocalPolicy {
    /// A matching junos-host `deny`/`reject` dropped the host-bound packet (the
    /// reject/tcp-rst reply was enqueued and the policy-deny RT_FLOW emitted).
    /// The caller recycles the frame and skips session install.
    Dropped,
    /// A matching junos-host policy PERMITTED the host-bound flow. Carries the
    /// full evaluation result so the session-install path stamps the policy's
    /// `then log session-init/session-close` selection, admitting `policy_id`,
    /// and per-rule hit-counter handle onto the installed local session +
    /// published conntrack row (#3706), matching the transit permit path.
    Permit(crate::policy::PolicyEvaluationResult),
    /// No junos-host policy matched (none configured, or none matched). The
    /// caller continues local delivery with the default no-policy metadata
    /// (byte-identical to pre-#3706 host-local behavior).
    NoMatch,
}

/// #3019/#3292/#3615: emit the junos-host (`to-zone junos-host`) policy-deny
/// RT_FLOW. `reject_reply_enqueued` is the ACTUAL outcome of the reject-reply
/// enqueue — the flowless LocalDelivery arm can synthesize NO reply (a fragment
/// has no L4 header), so it passes `false` and a `reject` there logs the
/// truthful DENY; the flow-backed wrapper passes the real
/// `enqueue_deny_reply` result. Kept emit-only (evaluation is
/// `junos_host_policy_eval`) so the enqueue can run BEFORE the emit on the
/// flow-backed path.
pub(super) fn emit_junos_host_deny(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    from_zone_id: u16,
    policy_id: u32,
    action: PolicyAction,
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    emit_policy_deny_event(
        event_stream,
        flow,
        // LocalDelivery applies no NAT — the deny record carries no nat_*
        // translation (byte-identical to a non-NAT transit deny).
        &crate::nat::NatDecision::default(),
        meta,
        from_zone_id,
        // The egress "zone" is the firewall host itself. The reserved
        // JUNOS_HOST_ZONE_ID (u16::MAX-1) does not fit the u8 wire zone-id slot
        // (#919/#922), so the deny RT_FLOW carries 0 ("unknown / host", the
        // #3110 sentinel) rather than a value that would truncate into a real
        // zone id on the wire.
        0,
        // Host-local sessions are not policy-forwarded; owner_rg_id 0.
        0,
        policy_id,
        action,
        resolve_policy_deny_app_id(&forwarding.app_catalog, flow, flow.forward_key.dst_port),
        reject_reply_enqueued,
        now_ns,
    );
}

/// #3610: emit the tuple-rich host-inbound-traffic deny event for a host-bound
/// packet rejected by the ingress zone's `host-inbound-traffic` admission gate.
/// Resolves the application from the flow's destination (service) port with the
/// same `resolve_policy_deny_app_id` the transit / junos-host deny path uses,
/// then delegates to [`emit_host_inbound_deny_event`] (which reuses the #3615
/// policy-deny event machinery with a distinct host-inbound reason). Shared by
/// all three host-inbound deny arms: session-hit, session-miss, and the #3292
/// flowless LocalDelivery arm — so every host-inbound drop emits an identical,
/// tuple-rich record.
pub(super) fn emit_host_inbound_deny(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    from_zone_id: u16,
    now_ns: u64,
) {
    emit_host_inbound_deny_event(
        event_stream,
        flow,
        meta,
        from_zone_id,
        resolve_policy_deny_app_id(&forwarding.app_catalog, flow, flow.forward_key.dst_port),
        now_ns,
    );
}

/// #9529: the destination the HOST-BOUND gates judge — the host-inbound service
/// gate's port and `to-zone junos-host` policy's address and port.
///
/// Post-translation, because a packet DNATed to a firewall-local address is
/// host-bound only BY VIRTUE of that translation: the kernel listener sees the
/// translated tuple, and transit policy already judges it (#2345). Judging the
/// wire tuple let a fine deny written on the firewall address or the translated
/// port match nothing, and the kernel's `iifname`-scoped DROP rules cannot catch
/// it either, because the reinject arrives on the slow-path TUN.
///
/// Two things deliberately stay on the WIRE tuple: the `lo0` filter (Junos
/// filters are pre-NAT; its caller keeps passing the frame and `flow`), and the
/// reject reply and deny record `junos_host_local_policy` emits, because the
/// client is addressing the pre-translation tuple.
///
/// Same-family only. A NAT64 target is a different address family from the
/// packet, and host-bound NAT64 is not what this governs, so the address falls
/// back to the wire value; the port still follows the translation. With no
/// translation both fall back to the wire, so direct-to-local traffic is
/// judged exactly as before.
#[inline]
pub(super) fn host_bound_policy_dst(
    flow: &SessionFlow,
    wire_dst_port: u16,
    translated_dst: Option<IpAddr>,
    translated_dst_port: Option<u16>,
) -> (IpAddr, u16) {
    let ip = match translated_dst {
        Some(ip) if ip.is_ipv4() == flow.dst_ip.is_ipv4() => ip,
        _ => flow.dst_ip,
    };
    (ip, translated_dst_port.unwrap_or(wire_dst_port))
}

/// #9529: [`host_bound_policy_dst`] for an established hit, from the translation
/// the session recorded at admission.
///
/// Both directions, unlike #9382's forward-only re-derivation: that rule exists
/// because a reverse companion carries SWAPPED zones, which says nothing about a
/// gate asking what the local listener receives. A host-bound reverse companion
/// the AF_XDP path could hit does not arise in practice (the firewall's own
/// replies leave through the kernel), so a direction branch here would be code no
/// cell can reach.
#[inline]
pub(super) fn session_host_bound_policy_dst(
    flow: &SessionFlow,
    wire_dst_port: u16,
    decision: crate::session::SessionDecision,
) -> (IpAddr, u16) {
    host_bound_policy_dst(
        flow,
        wire_dst_port,
        decision.nat.rewrite_dst,
        decision.nat.rewrite_dst_port,
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) fn junos_host_local_policy(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    tx_pipeline: &mut crate::afxdp::worker::WorkerTxPipeline,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    counters: &mut BatchCounters,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    // #9529: evaluated post-translation. The reject reply and the deny record
    // below still use `flow` — the client is talking to the pre-translation
    // address, and the reply must come back from it.
    policy_dst: (IpAddr, u16),
    from_zone_id: u16,
    packet_len: u64,
    now_ns: u64,
) -> JunosHostLocalPolicy {
    let policy_icmp = policy_packet_icmp(packet_frame, meta);
    match junos_host_policy_eval(
        forwarding,
        flow,
        policy_dst,
        from_zone_id,
        packet_len,
        // Flow-backed host-bound traffic always carries a real L4 header.
        true,
        policy_icmp,
    ) {
        // #3706: a matching PERMIT carries its `then log` selection, admitting
        // policy_id, and hit-counter handle back to the caller so the installed
        // host-bound session is logged + attributed like a transit permit.
        Some(result) if matches!(result.action, PolicyAction::Permit) => {
            JunosHostLocalPolicy::Permit(result)
        }
        Some(result) => {
            let action = result.action;
            // #3615: enqueue the reject/tcp-rst reply FIRST, then emit the
            // junos-host deny with the ACTUAL reply outcome so a suppressed
            // reject logs the truthful DENY.
            let reject_reply_enqueued = enqueue_deny_reply(
                tx_pipeline,
                forwarding,
                ingress_ifindex,
                packet_frame,
                meta,
                flow,
                counters,
                matches!(action, PolicyAction::Reject),
                from_zone_id,
            );
            emit_junos_host_deny(
                forwarding,
                event_stream,
                flow,
                meta,
                from_zone_id,
                result.policy_id,
                action,
                reject_reply_enqueued,
                now_ns,
            );
            JunosHostLocalPolicy::Dropped
        }
        None => JunosHostLocalPolicy::NoMatch,
    }
}

#[cfg(test)]
#[path = "host_bound_policy_dst_9529_tests.rs"]
mod host_bound_policy_dst_9529_tests;
