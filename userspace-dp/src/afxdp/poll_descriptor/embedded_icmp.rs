// #5690: generic embedded-ICMP NAT reversal, wired into the FLOWLESS poll
// arm — the path an inbound non-query ICMP error actually takes.
//
// An ICMP error (Time-Exceeded, Destination-Unreachable, Packet-Too-Big,
// Parameter-Problem, Redirect, ...) carries the offending datagram quoted in
// its payload. When that quoted datagram belongs to a NAT'd flow, the quoted
// inner header still holds the POST-NAT (public/SNAT) tuple, and the error's
// outer destination is the firewall's own NAT address. To deliver the error to
// the real internal host, the inner quoted packet must be reverse-translated
// back to the pre-NAT tuple and the frame forwarded toward the client.
//
// Why this lives on the flowless path: #3290 makes every non-query ICMP type
// FLOWLESS — `parse_session_flow_from_bytes` discards the metadata pseudo-port
// so the shim's ungated `[l4+4..l4+6)` control word can never seed a fake
// identifier-keyed session (session-table pollution / spurious collisions).
// That routing is correct and MUST be preserved. But it also meant this
// reversal — historically wired only into the FLOW-BACKED session-miss arm —
// could never run in production: a real ICMP error never has a flow, so it
// never entered that arm. The helper below is invoked from the flowless arm,
// where these errors land, so the capability is live and not merely
// helper-tested. The suppression's legitimate effect (no fake session) is
// untouched: the reversed error is queued as a prebuilt forward with
// `flow_key: None`, so it never becomes a session / flow-cache authority.

use super::*;

/// Outcome of [`try_reverse_embedded_icmp_error`].
pub(super) enum EmbeddedIcmpReversal {
    /// A NAT'd flow matched and the reverse-translated error frame was queued
    /// as a prebuilt forward toward the original client. The original
    /// descriptor is now owned by that `PendingForwardRequest`; the caller MUST
    /// NOT recycle it and MUST stop processing this descriptor.
    Queued,
    /// A NAT'd flow matched and a reversed frame was built, but the egress
    /// CoS / output classification dropped it. The caller MUST recycle the
    /// descriptor and stop processing it (fail-closed: never generate an ICMP
    /// error in response to an ICMP error).
    Dropped,
    /// No NAT match / no source rewrite / unbuildable reversed frame. The
    /// caller falls through to normal flowless enforcement, unchanged.
    NotHandled,
}

/// Attempt the generic embedded-ICMP NAT reversal for a non-query ICMP error
/// on the flowless poll path. Returns [`EmbeddedIcmpReversal`] telling the
/// caller how the descriptor was consumed. Only invoked when
/// `allow_embedded_icmp` is set AND the packet is classified as an ICMP error
/// (both checked by the caller).
#[allow(clippy::too_many_arguments)]
pub(super) fn try_reverse_embedded_icmp_error(
    desc: XdpDesc,
    // #8271: the frame this function PARSES. On a native-GRE-decapped packet
    // this is the owned inner frame, NOT the raw UMEM frame `desc` points at.
    // `meta` describes the inner packet after `stage_native_gre_decap` rebinds
    // it, so every read here must be at inner offsets against the inner bytes.
    // Pairing `meta` with the un-decapped outer frame is the #1885/#1902 class:
    // two other arms of `poll_binding_process_descriptor` were fixed for it and
    // these were not. `desc` is still the OUTER descriptor and stays that way —
    // it is used only to queue/recycle the original UMEM frame, which is
    // correct.
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_index: usize,
    sessions: &mut SessionTable,
    worker_ctx: &WorkerContext,
    scratch_forwards: &mut Vec<PendingForwardRequest>,
    now_ns: u64,
    now_secs: u64,
) -> EmbeddedIcmpReversal {
    #[cfg(feature = "debug-log")]
    let icmpv6_trace = meta.protocol == PROTO_ICMPV6
        && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
    let icmp_match = match try_embedded_icmp_nat_match_from_frame(
        packet_frame,
        meta,
        sessions,
        worker_ctx.forwarding,
        worker_ctx.dynamic_neighbors,
        worker_ctx.shared_sessions,
        worker_ctx.shared_nat_sessions,
        worker_ctx.shared_forward_wire_sessions,
        now_ns,
    ) {
        EmbeddedMatchOutcome::Match(m) => m,
        // #9901 (F-077): a session MATCHED but its per-session error budget
        // is exhausted. Drop the descriptor — falling through to flowless
        // forwarding would keep delivering the "suppressed" error under an
        // ICMP-permitting policy (an outbound-SNAT error would even forward
        EmbeddedMatchOutcome::BudgetDenied => return EmbeddedIcmpReversal::Dropped,
        EmbeddedMatchOutcome::NoMatch => {
            #[cfg(feature = "debug-log")]
            if icmpv6_trace {
                debug_log!(
                    "ICMPV6_EMBED: no_match ingress_if={} proto={}",
                    meta.ingress_ifindex,
                    meta.protocol,
                );
            }
            return EmbeddedIcmpReversal::NotHandled;
        }
    };
    #[cfg(feature = "debug-log")]
    if icmpv6_trace {
        debug_log!(
            "ICMPV6_EMBED: match orig_src={} orig_port={} nat={:?} resolution={:?} egress_if={} tx_if={} neigh={:?}",
            icmp_match.original_src,
            icmp_match.original_src_port,
            icmp_match.nat,
            icmp_match.resolution.disposition,
            icmp_match.resolution.egress_ifindex,
            icmp_match.resolution.tx_ifindex,
            icmp_match.resolution.neighbor_mac,
        );
    }
    // Reverse whenever the forward flow recorded ANY translation. Decline only
    // a genuinely untranslated flow, whose inner quote already matches what the
    // client sent.
    //
    // #9030: this gate used to read `rewrite_src.is_none()` — SNAT-only — and
    // the comment it carried ("a flow with no source translation leaves the
    // inner quoted source unchanged, so no reversal is required") is true of
    // the SOURCE and says nothing about the destination. For a pure-DNAT flow
    // the decision is `rewrite_dst: Some(_), rewrite_src: None`, so the gate
    // fired and returned NotHandled — which made every builder, struct field
    // and regression test #3112 landed for exactly that case unreachable from
    // production. `build_nat_reversed_icmp_error_v4/v6` have one production
    // caller each, below this line.
    //
    // The builders were already complete for the widened set, which is why this
    // is a pure reachability change and touches no builder: the destination
    // ADDRESS restore is guarded by `had_dst_nat` (rewrite_dst), the
    // destination PORT restore by `rewrite_dst_port || rewrite_dst`, and the
    // source restores by `rewrite_src_port || rewrite_src`. Each arm tests its
    // own field, so admitting DNAT-only, port-only or static-NAT flows cannot
    // half-restore a quote — an arm whose field is None simply does not fire.
    if icmp_match.nat.rewrite_src.is_none()
        && icmp_match.nat.rewrite_dst.is_none()
        && icmp_match.nat.rewrite_src_port.is_none()
        && icmp_match.nat.rewrite_dst_port.is_none()
    {
        #[cfg(feature = "debug-log")]
        if icmpv6_trace {
            debug_log!("ICMPV6_EMBED: no_rewrite nat={:?}", icmp_match.nat);
        }
        return EmbeddedIcmpReversal::NotHandled;
    }
    let icmp_resolution = finalize_embedded_icmp_resolution(
        worker_ctx.forwarding,
        worker_ctx.ha_state,
        now_secs,
        meta.ingress_ifindex as i32,
        &icmp_match,
    );
    let rewritten = match meta.addr_family as i32 {
        // #6474: an OUTBOUND error through source NAT takes the re-NAT
        // builders (external outer source + associable quote), never the
        // #5690 reversal (which would leak the internal source and leave
        // the quote in pre-NAT form).
        libc::AF_INET if icmp_match.outbound_snat => {
            build_snat_outbound_icmp_error_v4(packet_frame, meta, &icmp_match)
        }
        libc::AF_INET6 if icmp_match.outbound_snat => {
            build_snat_outbound_icmp_error_v6(packet_frame, meta, &icmp_match)
        }
        libc::AF_INET => build_nat_reversed_icmp_error_v4(packet_frame, meta, &icmp_match),
        libc::AF_INET6 => build_nat_reversed_icmp_error_v6(packet_frame, meta, &icmp_match),
        _ => None,
    };
    let Some(rewritten_frame) = rewritten else {
        #[cfg(feature = "debug-log")]
        if icmpv6_trace {
            debug_log!(
                "ICMPV6_EMBED: build_none resolution={:?} egress_if={} tx_if={} neigh={:?}",
                icmp_resolution.disposition,
                icmp_resolution.egress_ifindex,
                icmp_resolution.tx_ifindex,
                icmp_resolution.neighbor_mac,
            );
        }
        return EmbeddedIcmpReversal::NotHandled;
    };
    queue_prebuilt_embedded_icmp_error(
        desc,
        meta,
        binding_index,
        worker_ctx,
        scratch_forwards,
        now_ns,
        icmp_resolution,
        rewritten_frame,
        #[cfg(feature = "debug-log")]
        icmpv6_trace,
    )
}

/// Shared tail of the embedded-ICMP error paths (#5690 same-family
/// reversal, #6472 NAT64 cross-family translation): run egress CoS /
/// output classification on the already-finalized resolution and queue the
/// prebuilt frame as a forward that never seeds a session. Extracted so
/// both arms carry ONE copy of the CoS/target-binding/queue mechanics —
/// behavior for the #5690 path is byte-identical to the pre-extraction
/// inline tail.
#[allow(clippy::too_many_arguments)]
pub(super) fn queue_prebuilt_embedded_icmp_error(
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    binding_index: usize,
    worker_ctx: &WorkerContext,
    scratch_forwards: &mut Vec<PendingForwardRequest>,
    now_ns: u64,
    icmp_resolution: ForwardingResolution,
    rewritten_frame: Vec<u8>,
    #[cfg(feature = "debug-log")] icmpv6_trace: bool,
) -> EmbeddedIcmpReversal {
    let icmp_decision = SessionDecision {
        resolution: icmp_resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let target_ifindex = if icmp_decision.resolution.tx_ifindex > 0 {
        icmp_decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(worker_ctx.forwarding, icmp_decision.resolution.egress_ifindex)
    };
    let cos = resolve_cos_tx_selection_at(
        worker_ctx.forwarding,
        icmp_decision.resolution.egress_ifindex,
        meta,
        // #5690: the reversed error is a synthesized L3 reply. Classify CoS by
        // the outer DSCP / 802.1p only (`flow_key = None`): the quoted
        // transport flow is NOT the outer flow, and a non-query ICMP error
        // carries no trustworthy 5-tuple (its metadata `[l4+4..l4+6)` bytes are
        // a control word, not ports), so a port-bearing output/CoS term must
        // fail closed rather than key on a fabricated tuple.
        None,
        // #2362 fold B: generated ICMP error reply — meta-only extra
        // (tcp_flags authoritative; no per-packet frame re-read for this
        // synthesized frame).
        crate::afxdp::frame::term_match_extra_from_meta(meta.into()),
        now_ns,
    );
    if cos.drop {
        #[cfg(feature = "debug-log")]
        if icmpv6_trace {
            debug_log!(
                "ICMPV6_EMBED: cos_drop egress_if={}",
                icmp_decision.resolution.egress_ifindex,
            );
        }
        return EmbeddedIcmpReversal::Dropped;
    }
    let target_binding_index = worker_ctx.binding_lookup.target_index(
        binding_index,
        worker_ctx.ident.ifindex,
        worker_ctx.ident.queue_id,
        target_ifindex,
    );
    #[cfg(feature = "debug-log")]
    if icmpv6_trace {
        debug_log!(
            "ICMPV6_EMBED: queued resolution={:?} egress_if={} tx_if={} target_if={}",
            icmp_decision.resolution.disposition,
            icmp_decision.resolution.egress_ifindex,
            icmp_decision.resolution.tx_ifindex,
            target_ifindex,
        );
    }
    scratch_forwards.push(PendingForwardRequest {
        target_ifindex,
        target_binding_index,
        ingress_queue_id: worker_ctx.ident.queue_id,
        desc,
        frame: PendingForwardFrame::Prebuilt(rewritten_frame),
        meta: meta.into(),
        decision: icmp_decision,
        apply_nat_on_fabric: false,
        expected_ports: None,
        // #5690: keep `flow_key` None so the non-query ICMP error never becomes
        // a session / flow-cache authority — the same invariant #3290 protects
        // by routing it flowless in the first place.
        flow_key: None,
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
    });
    EmbeddedIcmpReversal::Queued
}
