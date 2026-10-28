// #6386 leaf extraction: the new-flow session-admission predicates
// (#2134 per-IP session-limit, #4400/#10270 non-SYN TCP session-MISS drop),
// originally lifted verbatim out of poll_descriptor/mod.rs. Each moved bare fn
// becomes pub(super); both keep their existing #[inline] attributes. The
// extraction keeps the poll call site small; behavior-specific changes remain
// in this leaf and are covered by its tests.

/// Resources needed by the cold pressure-shed teardown protocol. Keeping the
/// side effects here gives packet admission and the deferred-GC retry one
/// ordering for shared rows, BPF state, NAT holds, and peer replication.
pub(in crate::afxdp) struct ShedTeardownCtx<'a> {
    pub(in crate::afxdp) forwarding: &'a ForwardingState,
    pub(in crate::afxdp) session_map: SteeringMap<'a>,
    pub(in crate::afxdp) conntrack_v4_fd: c_int,
    pub(in crate::afxdp) conntrack_v6_fd: c_int,
    pub(in crate::afxdp) dnat_fds: &'a crate::afxdp::checksum::DnatTableFds,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub(in crate::afxdp) worker_commands_by_id: &'a crate::afxdp::types::WorkerCommandQueues,
    pub(in crate::afxdp) shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_nat_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_forward_wire_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub(in crate::afxdp) now_ns: u64,
}

/// Complete the external teardown for pressure victims already removed from
/// the local table. A failed all-key lease preserves the intents for retry and
/// returns `false`, so every admission caller refuses the incoming flow. This
/// applies #14661's refusal policy to ForwardCandidate; that copy was wrong to
/// continue installing after the shed lease failed.
///
/// Shared reply evidence is rechecked only after the tuple lease is acquired:
/// the lease drains publishers and prevents a stale pre-lease snapshot from
/// deleting a flow that acquired reply evidence while this path waited.
#[cold]
#[inline(never)]
pub(in crate::afxdp) fn teardown_pressure_shed_victims(
    sessions: &mut SessionTable,
    sheds: crate::session::PressureShedSessions,
    ctx: ShedTeardownCtx<'_>,
    invalidate: &mut dyn FnMut(&SessionKey),
) -> bool {
    if sheds.is_empty() {
        return true;
    }
    let shed_keys: Vec<_> = sheds.iter().map(|shed| shed.key.clone()).collect();
    let Ok(_lease) = crate::afxdp::bpf_map::global_tuple_gate().acquire_lease(shed_keys) else {
        sessions.defer_pressure_shed(sheds);
        return false;
    };
    for shed in sheds {
        if !shed.is_reverse
            && (sessions.session_replied(&shed.key)
                || crate::afxdp::shared_ops::shared_session_replied(
                    ctx.shared_sessions,
                    &shed.key,
                    shed.decision.nat,
                ))
        {
            sessions.cancel_pending_close(&shed.key, shed.session_id);
            continue;
        }
        let shared_removal = crate::afxdp::shared_ops::remove_shared_session_if(
            ctx.shared_sessions,
            ctx.shared_nat_sessions,
            ctx.shared_forward_wire_sessions,
            ctx.shared_owner_rg_indexes,
            &shed.key,
            |current| {
                crate::afxdp::poll_descriptor::is_pressure_shed_shared_unreplied(current, &shed)
            },
        );
        if matches!(
            shared_removal,
            crate::afxdp::shared_ops::SharedRemoval::Declined
        ) {
            // Keep the established guard before releasing NAT state. The old
            // MissingNeighbor copy omitted it, but analysis found that difference
            // behaviorally equivalent because shedding removes both local rows.
            if sessions.probe_with_origin(&shed.key).is_none() {
                crate::nat::release_source_nat_allocation_for_worker_with_hold(
                    &ctx.forwarding.iface_nat_allocators,
                    &ctx.forwarding.source_nat_rules,
                    &shed.key,
                    shed.decision.nat,
                    shed.is_reverse,
                    ctx.now_ns,
                    ctx.worker_id,
                    shed.persistent_lease_hold,
                );
                crate::nat64::release_nat64_allocation_for_worker(
                    &ctx.forwarding.nat64,
                    &shed.key,
                    shed.decision.nat,
                    shed.is_reverse,
                    ctx.now_ns,
                    ctx.worker_id,
                );
            }
            continue;
        }
        crate::afxdp::bpf_map::release_coordinator_session_rows(ctx.session_map, &shed.key);
        let _ = crate::afxdp::bpf_map::delete_bpf_conntrack_entry_under_gate(
            ctx.conntrack_v4_fd,
            ctx.conntrack_v6_fd,
            &shed.key,
        );
        if !shed.is_reverse {
            crate::afxdp::checksum::delete_dnat_table_entry(
                ctx.dnat_fds,
                &shed.key,
                shed.decision.nat,
            );
        }
        crate::afxdp::bpf_map::delete_live_session_entry(
            ctx.session_map,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
        );
        // SessionKey omits ingress ifindex; invalidate every binding's slot
        // through the caller closure, not only the binding that saw this packet.
        invalidate(&shed.key);
        crate::nat::release_source_nat_allocation_for_worker_with_hold(
            &ctx.forwarding.iface_nat_allocators,
            &ctx.forwarding.source_nat_rules,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            ctx.now_ns,
            ctx.worker_id,
            shed.persistent_lease_hold,
        );
        crate::nat64::release_nat64_allocation_for_worker(
            &ctx.forwarding.nat64,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            ctx.now_ns,
            ctx.worker_id,
        );
        super::session_glue::replicate_session_delete_repairing(
            ctx.peer_worker_commands,
            ctx.worker_commands_by_id,
            ctx.forwarding,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            ctx.now_ns,
        );
    }
    true
}

use super::*;

/// #2134/#10985/#11057: per-zone session-limit enforcement at the NEW-FLOW decision.
///
/// Junos `limit-session source-ip-based <n>` / `destination-ip-based <n>`
/// caps concurrent sessions from one source / to one destination IP. When
/// `source-ip-based` is unset or zero, a default per-source quota applies;
/// a positive configured value overrides it. Destination limits remain
/// opt-in. The decision MUST fire exactly once per new flow, before that
/// flow's own session exists — NOT in the per-packet screen stage, which runs
/// on every data packet and would re-check an established flow's own counted
/// session and self-drop it at the limit boundary (#2134 r2 BLOCKER).
///
/// This is a read-only query on the per-worker `SessionTable` count keyed by
/// `(ingress_zone_id, IP)` (maintained at the install/remove sinks + HA
/// promote/demote), so sessions admitted in another zone cannot consume this
/// zone's allowance. The source default is independently enforced in each
/// ingress zone and worker. It preserves the #2128 leak-fix by construction:
/// an IP that never installs a session never gets a map entry. Returns the
/// screen-drop reason if the new flow must be rejected, or `None` to proceed.
#[inline]
pub(super) fn new_flow_session_limit_drop(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    from_zone: &str,
    from_zone_id: u32,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<&'static str> {
    // Profiles carry explicit overrides; absent profiles and zero source
    // thresholds use the safe default.
    let profile = forwarding.screen_profiles.get(from_zone);
    let src_limit = profile
        .map(|p| p.session_limit_src)
        .filter(|limit| *limit > 0)
        .unwrap_or(crate::session::DEFAULT_MAX_SESSIONS_PER_SOURCE);
    if sessions.session_limit_src_count(from_zone_id, src_ip) >= src_limit {
        return Some("session-limit-src");
    }
    if profile.is_some_and(|p| {
        p.session_limit_dst > 0
            && sessions.session_limit_dst_count(from_zone_id, dst_ip) >= p.session_limit_dst
    }) {
        return Some("session-limit-dst");
    }
    None
}

/// #4400/#10270/#10703/#16479: TCP session-MISS admission for transit new flows.
///
/// By default, TCP misses require SYN so stale ACK/data cannot create new
/// sessions (#10270), and bare RST/FIN misses are always dropped to prevent
/// closing-entry churn (#4400). `no-syn-check` opts into mid-stream pickup
/// for non-closing packets. Explicit `strict-syn-check` also drops SYN
/// segments carrying payload (Junos: "When you enable `strict-syn-check`
/// the SYN packets carrying data are dropped") and keeps the SYN-first
/// requirement. (#16479: strict no longer "overrides" no-syn-check at
/// commit — the compiler rejects the combination — but the dataplane keeps
/// the precedence so a leniently-loaded legacy config stays fail-closed.)
///
/// Established and HA-synced flows are session HITS and never reach this
/// predicate. LocalDelivery uses its separate cache-only SYN gate so peer
/// control traffic for firewall-originated connections still reaches the
/// local stack.
/// #16479 (a): payload-aware MISS gate. A SYN carrying TCP payload is
/// dropped only when `strict_syn_check` is set; without strict the
/// SYN+payload miss keeps its prior admission (TFO-style, and the #16042
/// ISN seed already accounts for SYN payload in the expected ack end).
/// All other arms are identical to the flags-only predicate.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow_with_payload(
    protocol: u8,
    tcp_flags: u8,
    tcp_flags_unknown: bool,
    no_syn_check: bool,
    strict_syn_check: bool,
    payload_len: u32,
) -> bool {
    strict_syn_check_drops_new_flow_tunnel_with_payload(
        protocol,
        tcp_flags,
        tcp_flags_unknown,
        no_syn_check,
        strict_syn_check,
        false,
        false,
        payload_len,
    )
}


/// #16479: payload-aware tunnel variant — the production MISS gate.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow_tunnel_with_payload(
    protocol: u8,
    tcp_flags: u8,
    tcp_flags_unknown: bool,
    no_syn_check: bool,
    strict_syn_check: bool,
    no_syn_check_in_tunnel: bool,
    is_tunnel: bool,
    payload_len: u32,
) -> bool {
    if !matches!(protocol, crate::ip_proto::PROTO_TCP) {
        return false;
    }
    // #16007: flags UNKNOWN (tiny first fragment, flags byte outside the
    // declared datagram) fails closed in EVERY mode — including
    // `no_syn_check` and the tunnel opt-out. The stamped 0 is not a
    // proven non-closing, non-SYN packet; it is no information at all,
    // and admitting it would let an 8-byte first fragment seed a session
    // on flags nobody has seen, with the reassembled SYN arriving only
    // in the offset-1 second fragment.
    if tcp_flags_unknown {
        return true;
    }
    if crate::tcp_flags::is_closing(tcp_flags) {
        return true;
    }
    if crate::tcp_flags::has_syn(tcp_flags) {
        // #16479 (a): Junos strict SYN checking drops SYN packets
        // carrying data. Only under strict — the default and
        // no-syn-check paths keep admitting SYN+payload misses.
        return strict_syn_check && payload_len > 0;
    }
    let effective_no_syn = no_syn_check || (is_tunnel && no_syn_check_in_tunnel);
    !effective_no_syn || strict_syn_check
}

/// #16479 (b): strict-SYN pre-handshake data drop on a session HIT.
///
/// With `strict_syn_check`, a data-bearing TCP segment must not be
/// forwarded while the session's three-way handshake is incomplete
/// (Junos: strict SYN checking "enhances security by dropping data
/// packets before the three-way handshake is done"). Only SYN-ACK and
/// the handshake-completing ACK pass; both carry no payload by
/// construction of this predicate, so they are never dropped here.
/// Segments on closing entries keep their teardown handling (a FIN
/// with payload drains the send buffer; RST handling is seq-gated
/// elsewhere), and SYN-bearing segments (retransmits) are handshake
/// control, not data injection.
///
/// `established`/`handshake_pending`/`syn_ack_first`/`closing` are the
/// matched entry's handshake state BEFORE this packet's lookup would
/// promote/complete it (the caller reads them via the read-only
/// `strict_pre_handshake_state` probe), so a completing ACK+data —
/// the segment that finishes the handshake while carrying the first
/// data — is dropped exactly as Junos drops it: data before the
/// handshake is done. A mid-stream pickup starts `established`, so it
/// is never gated here.
#[inline]
pub(super) fn strict_syn_check_drops_pre_handshake_data(
    strict_syn_check: bool,
    tcp_flags: u8,
    payload_len: u32,
    established: bool,
    handshake_pending: bool,
    syn_ack_first: bool,
    closing: bool,
) -> bool {
    if !strict_syn_check || payload_len == 0 {
        return false;
    }
    if closing || crate::tcp_flags::is_closing(tcp_flags) {
        return false;
    }
    if crate::tcp_flags::has_syn(tcp_flags) {
        return false;
    }
    // SYN-first session, handshake incomplete: either the SYN-ACK has
    // not been seen yet (!established, not a SYN-ACK-first pickup) or
    // it has and the completing ACK is still outstanding
    // (handshake_pending, which SYN-ACK-first also seeds).
    !established || handshake_pending || syn_ack_first
}

/// Shared inputs for the pure transit-admission verdict. Callers supply
/// the finalized resolution/zone pair and keep destination classification
/// separate from the effective post-translation policy tuple.
pub(super) struct AdmissionInput<'a> {
    pub(super) flow: &'a SessionFlow,
    pub(super) meta: ForwardPacketMeta,
    pub(super) resolution: ForwardingResolution,
    /// Wire destination used for martian classification.
    pub(super) class_dst: IpAddr,
    /// Any pre-policy translation also checked for martian classification.
    pub(super) translated_dst: Option<IpAddr>,
    /// Effective post-translation destination used by security policy.
    pub(super) policy_dst: IpAddr,
    pub(super) protocol: u8,
    pub(super) policy_dst_port: u16,
    pub(super) policy_icmp: Option<(u8, u8)>,
    pub(super) from_zone_id: u32,
    pub(super) to_zone_id: u32,
    pub(super) fabric_arrival_zone: Option<u32>,
    pub(super) now_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransitClassDrop {
    Destination,
    Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TransitClassVerdict {
    pub(super) transit_disposition: bool,
    pub(super) drop: Option<TransitClassDrop>,
}

/// Pure martian-class part of the miss admission chain. The ordinary path
/// maps each drop to its existing counter; cookies only need the verdict.
pub(super) fn transit_class_verdict(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    meta: ForwardPacketMeta,
    resolution: ForwardingResolution,
    class_dst: IpAddr,
    translated_dst: Option<IpAddr>,
    fabric_arrival_zone: Option<u32>,
) -> TransitClassVerdict {
    let transit_disposition = matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::FabricRedirect
    );
    if !transit_disposition {
        return TransitClassVerdict {
            transit_disposition,
            drop: None,
        };
    }
    if super::transit_destination_class_drop(
        forwarding,
        resolution.disposition,
        class_dst,
        translated_dst,
        flow.forward_key.routing_domain,
        meta,
        fabric_arrival_zone,
    ) {
        return TransitClassVerdict {
            transit_disposition,
            drop: Some(TransitClassDrop::Destination),
        };
    }
    if super::transit_source_class_drop(
        forwarding,
        resolution.disposition,
        flow.src_ip,
        flow.forward_key.routing_domain,
        meta,
        fabric_arrival_zone,
    ) {
        return TransitClassVerdict {
            transit_disposition,
            drop: Some(TransitClassDrop::Source),
        };
    }
    TransitClassVerdict {
        transit_disposition,
        drop: None,
    }
}

/// A complete, side-effect-free transit-admission result. The miss path
/// applies its class counters and policy hit count separately; SYN-cookie
/// paths consume only `permits()`. A normal miss delegates `FabricRedirect`
/// policy to the peer that owns the packet, while a cookie reply is consumed
/// locally and must be authorized against the finalized pair.
pub(super) struct AdmissionVerdict {
    pub(super) class: TransitClassVerdict,
    pub(super) policy_result: Option<crate::policy::PolicyEvaluationResult>,
}

impl AdmissionVerdict {
    pub(super) fn permits(&self) -> bool {
        self.class.transit_disposition
            && self.class.drop.is_none()
            && self.policy_result.map_or(true, |result| {
                result.action == crate::policy::PolicyAction::Permit
            })
    }
}

/// Pure miss-path verdict. `class_verdict` lets the miss path reuse the class
/// check it ran at its original ordering point, then apply the counted policy
/// effect when its later policy stage is reached. `FabricRedirect` remains
/// peer-adjudicated because the packet itself is punted to that peer.
pub(super) fn transit_admission_verdict(
    forwarding: &ForwardingState,
    input: &AdmissionInput<'_>,
    class_verdict: Option<TransitClassVerdict>,
) -> AdmissionVerdict {
    transit_admission_verdict_with_cookie_redirect_policy(
        forwarding,
        input,
        class_verdict,
        false,
    )
}

/// A cookie reply is emitted and its ACK is consumed locally even when the
/// finalized disposition is `FabricRedirect`. Unlike a normal punt, it must
/// therefore receive a local policy verdict for the finalized zone pair.
pub(super) fn cookie_reply_admission_verdict(
    forwarding: &ForwardingState,
    input: &AdmissionInput<'_>,
) -> AdmissionVerdict {
    transit_admission_verdict_with_cookie_redirect_policy(forwarding, input, None, true)
}

fn transit_admission_verdict_with_cookie_redirect_policy(
    forwarding: &ForwardingState,
    input: &AdmissionInput<'_>,
    class_verdict: Option<TransitClassVerdict>,
    authorize_fabric_redirect: bool,
) -> AdmissionVerdict {
    let class = class_verdict.unwrap_or_else(|| {
        transit_class_verdict(
            forwarding,
            input.flow,
            input.meta,
            input.resolution,
            input.class_dst,
            input.translated_dst,
            input.fabric_arrival_zone,
        )
    });
    let local_policy_disposition = matches!(
        input.resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) || (authorize_fabric_redirect
        && input.resolution.disposition == ForwardingDisposition::FabricRedirect);
    let policy_result = if local_policy_disposition
        && class.transit_disposition
        && class.drop.is_none()
    {
        Some(crate::policy::evaluate_policy_result_without_counting_at(
            &forwarding.policy,
            input.from_zone_id,
            input.to_zone_id,
            input.flow.src_ip,
            input.policy_dst,
            input.protocol,
            input.flow.forward_key.src_port,
            input.policy_dst_port,
            input.policy_icmp,
            input.now_ns,
        ))
    } else {
        None
    };
    AdmissionVerdict {
        class,
        policy_result,
    }
}

#[cfg(test)]
#[path = "session_admission_tests.rs"]
mod tests;
