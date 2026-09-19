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
pub(in crate::afxdp) enum EmbeddedIcmpReversal {
    /// A live session matched and the related error frame was queued as a
    /// prebuilt forward toward the quoted packet's original source. NAT'd
    /// matches are reverse-translated; untranslated matches preserve the wire
    /// tuple. The original descriptor is now owned by that
    /// `PendingForwardRequest`; the caller MUST then pop + recycle on deny and
    /// MUST stop processing this descriptor. `related_untranslated` is true
    /// only for the untranslated admission; NAT and NAT64 callers keep it
    /// false.
    Queued { related_untranslated: bool },
    /// A NAT'd flow matched and a reversed frame was built, but the egress
    /// CoS / output classification dropped it. The caller MUST recycle the
    /// descriptor and stop processing it (fail-closed: never generate an ICMP
    /// error in response to an ICMP error).
    Dropped,
    /// No matching session / unbuildable reversed frame. The caller falls
    /// through to normal flowless enforcement, unchanged.
    NotHandled,
}


/// Attempt the generic embedded-ICMP NAT reversal for a non-query ICMP error
/// on the flowless poll path. Returns [`EmbeddedIcmpReversal`] telling the
/// caller how the descriptor was consumed. Only invoked when
/// `allow_embedded_icmp` is set AND the packet is classified as an ICMP error
/// (both checked by the caller).
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn try_reverse_embedded_icmp_error(
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
    ingress_zone_override: Option<u16>,
) -> EmbeddedIcmpReversal {
    #[cfg(feature = "debug-log")]
    let icmpv6_trace = meta.protocol == PROTO_ICMPV6
        && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
    let mut icmp_match = match try_embedded_icmp_nat_match_from_frame(
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
    // A matched quote with no NAT rewrite is an untranslated live session.
    // Keep it on this related-error path: the existing session is the
    // admission authority, while ordinary flowless reverse-zone policy would
    // incorrectly classify the error as a new packet and drop PMTUD.
    //
    // #9030 widened the old SNAT-only gate to test every rewrite field so
    // pure-DNAT, port-only, and composed NAT sessions reach their builders.
    // The same all-fields predicate now identifies the no-rewrite RELATED
    // case. Each builder independently guards its address/port writes, so the
    // untranslated output remains wire-identical apart from checksum refresh.
    let untranslated_related = icmp_match.nat.rewrite_src.is_none()
        && icmp_match.nat.rewrite_dst.is_none()
        && icmp_match.nat.rewrite_src_port.is_none()
        && icmp_match.nat.rewrite_dst_port.is_none();
    let icmp_resolution = finalize_embedded_icmp_resolution_parts(
        worker_ctx.forwarding,
        worker_ctx.ha_state,
        now_secs,
        meta.ingress_ifindex as i32,
        icmp_match.resolution,
        actual_embedded_icmp_ingress_zone(
            worker_ctx.forwarding,
            meta,
            ingress_zone_override,
        ),
    );
    // Builders consume the match's resolution for L2 construction. Replace it
    // with the finalized (possibly zone-stamped FabricRedirect) decision before
    // building the prebuilt frame.
    icmp_match.resolution = icmp_resolution;
    if matches!(packet_ttl_would_expire(packet_frame, meta), Some(true)) {
        return EmbeddedIcmpReversal::Dropped;
    }
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
    let queued = queue_prebuilt_embedded_icmp_error(
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
    );
    match queued {
        EmbeddedIcmpReversal::Queued { .. } => EmbeddedIcmpReversal::Queued {
            related_untranslated: untranslated_related,
        },
        other => other,
    }
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
        overlap_admissions: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
    });
    EmbeddedIcmpReversal::Queued {
        related_untranslated: false,
    }
}

/// Authorize the queued disposition and, for locally forwardable frames, apply
/// the flowless transit zone-policy gate. The input/PBR filters are intentionally
/// evaluated by the caller before either ICMP arm (#7359/#9528); this helper is
/// the missing final authorization that the queued prebuilt otherwise skips
/// (#9948).
/// The policy direction is the packet's actual arrival zone to the queued
/// resolution's egress zone, not the quoted session's original direction.
/// That keeps a forged error arriving from an untrusted zone subject to the
/// same `wan -> lan` policy as any other flowless transit packet while still
/// allowing an explicitly permitted PMTUD error through (#7169).
pub(super) fn enforce_queued_embedded_icmp_policy(
    queued_frame: &[u8],
    ingress_meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    resolution: ForwardingResolution,
    worker_ctx: &WorkerContext,
    now_ns: u64,
    now_secs: u64,
    related_untranslated: bool,
) -> bool {
    // A queued prebuilt never reaches the later flowless disposition arms:
    // both callers continue after this adjudicator and TX dispatch sends a
    // `Prebuilt` unconditionally. FabricRedirect is the one peer-owned
    // exception: #3291 adjudicates it on the owning peer, and TX #1946
    // explicitly transmits its prebuilt frame across the fabric.
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        return true;
    }
    // An untranslated error quoting a live session is admitted by the
    // allow-embedded-icmp RELATED contract. Keep HA/route dispositions
    // authoritative, but do not re-run the reverse flowless zone pair: that
    // pair describes the error's arrival direction, not the permitted flow
    // it quotes. NAT-translated errors retain the policy gate below.
    if related_untranslated && resolution.disposition == ForwardingDisposition::ForwardCandidate {
        return true;
    }
    // Every terminal/non-sendable disposition must fail closed here rather
    // than be treated as peer-owned by default.
    let Some((policy_flow, mut policy_meta)) = queued_embedded_icmp_identity(queued_frame)
    else {
        // A prebuilt frame that cannot expose an L3 policy identity is not
        // safe to deliver. Builders normally make this unreachable; keeping
        // the gate fail-closed protects the queue if a new builder regresses.
        return false;
    };
    policy_meta.ingress_ifindex = ingress_meta.ingress_ifindex;
    policy_meta.ingress_vlan_id = ingress_meta.ingress_vlan_id;
    let ingress_logical = super::resolve_ingress_logical_ifindex(
        worker_ctx.forwarding,
        ingress_meta.ingress_ifindex as i32,
        ingress_meta.ingress_vlan_id,
    )
    .unwrap_or(ingress_meta.ingress_ifindex as i32);
    let gated_zone_override = super::gate_fabric_zone_override_on_owner_rg(
        worker_ctx.forwarding,
        worker_ctx.ha_state,
        now_secs,
        ingress_zone_override,
        resolution,
    );
    let (from_zone_id, to_zone_id) = super::zone_pair_ids_for_flow_with_override(
        worker_ctx.forwarding,
        ingress_logical,
        gated_zone_override,
        resolution.egress_ifindex,
    );
    let policy_result = if resolution.disposition == ForwardingDisposition::ForwardCandidate {
        crate::policy::evaluate_policy_result_l3_aware(
            &worker_ctx.forwarding.policy,
            from_zone_id,
            to_zone_id,
            policy_flow.src_ip,
            policy_flow.dst_ip,
            policy_flow.forward_key.protocol,
            0,
            0,
            super::policy_packet_icmp(queued_frame, policy_meta),
            queued_frame.len() as u64,
            false,
        )
    } else {
        // HAInactive, PolicyDenied, and all unresolved route dispositions are
        // not transmit-authorized even when their eventual zone pair would
        // permit the packet. Preserve the deny event's normal default-policy
        // identity while making the queue ownership decision fail closed.
        crate::policy::PolicyEvaluationResult {
            action: PolicyAction::Deny,
            policy_id: crate::policy::DEFAULT_POLICY_SENTINEL_ID,
            ..Default::default()
        }
    };
    if resolution.disposition == ForwardingDisposition::ForwardCandidate
        && matches!(policy_result.action, PolicyAction::Permit)
    {
        return true;
    }
    let owner_rg_id = super::owner_rg_for_resolution(worker_ctx.forwarding, resolution);
    super::emit_policy_deny_event(
        worker_ctx.event_stream,
        &policy_flow,
        &NatDecision::default(),
        policy_meta,
        from_zone_id,
        to_zone_id,
        owner_rg_id,
        policy_result.policy_id,
        policy_result.action,
        0,
        false,
        now_ns,
    );
    false
}

/// Resolve the zone identity that a peer-owned embedded error must carry.
/// Fabric ingress already supplies an authenticated override; otherwise derive
/// the actual packet arrival zone from the logical ingress unit, not the quoted
/// session metadata.
pub(super) fn actual_embedded_icmp_ingress_zone(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> u16 {
    ingress_zone_override.unwrap_or_else(|| {
        let logical_ifindex = super::resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        forwarding
            .ifindex_to_zone_id
            .get(&logical_ifindex)
            .copied()
            .unwrap_or(meta.ingress_zone)
    })
}

/// Recover the outer L3 identity from the actual prebuilt wire frame. The
/// queued frame can be cross-family (NAT64), so the original ingress metadata
/// is not authoritative for policy addresses or ICMP type/code.
fn queued_embedded_icmp_identity(frame: &[u8]) -> Option<(SessionFlow, UserspaceDpMeta)> {
    let l3 = crate::afxdp::frame::frame_l3_offset(frame)?;
    let version = frame.get(l3).map(|byte| byte >> 4)?;
    let (addr_family, protocol, src_ip, dst_ip) = match version {
        4 => {
            let src = <[u8; 4]>::try_from(frame.get(l3 + 12..l3 + 16)?).ok()?;
            let dst = <[u8; 4]>::try_from(frame.get(l3 + 16..l3 + 20)?).ok()?;
            (
                libc::AF_INET as u8,
                *frame.get(l3 + 9)?,
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dst)),
            )
        }
        6 => {
            let src = <[u8; 16]>::try_from(frame.get(l3 + 8..l3 + 24)?).ok()?;
            let dst = <[u8; 16]>::try_from(frame.get(l3 + 24..l3 + 40)?).ok()?;
            (
                libc::AF_INET6 as u8,
                PROTO_ICMPV6,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
            )
        }
        _ => return None,
    };
    let l4 = crate::afxdp::frame::frame_l4_offset(frame, addr_family)?;
    let policy_meta = UserspaceDpMeta {
        l3_offset: l3 as u16,
        l4_offset: l4 as u16,
        pkt_len: frame.len().min(u16::MAX as usize) as u16,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    Some((flow, policy_meta))
}
