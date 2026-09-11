// Dispatch module (#1443). Pure code-motion split of the original
// 1474-LOC `dispatch.rs` into cohesive submodules:
//
// - `cos`             — Phase 1 (CoS TX-selection resolve) +
//                       the COS fast-path helpers
//                       (cos_queue_fast_path_for_request,
//                        cos_owner_live_for_request,
//                        request_runs_under_shared_exact_policy,
//                        enqueue_local_request_to_target_or_owner).
// - `shared_recycle`  — Phase 10 + cross-tick recycle routing
//                       (apply_shared_recycles*,
//                        resolve_tx_binding_ifindex,
//                        and the slot-resolution helpers).
// - `slow_path`       — handle_forward_build_failure,
//                       maybe_reinject_slow_path*, slow_path_admit
//                       (the single admit/refuse decision, #6664),
//                       extract_l3_packet* family. All marked
//                       #[cold] #[inline(never)] per AGY round-2
//                       finding D.
//
// The orchestrator (`enqueue_pending_forwards`) and Phase 8
// (try_inplace_rewrite_or_build) intentionally stay in `mod.rs` for
// this PR — Phase 8 body extraction is deferred to a follow-up so
// reviewers can compare the in-tree control flow against current
// master without a body-shape diff. See plan.md §"Out of scope".
//
// External callers reach the re-exported symbols via the
// `use self::tx::dispatch::*;` glob at `afxdp/mod.rs:140`. The
// re-export block below preserves every `pub(in crate::afxdp)`
// symbol verbatim.

use super::*;

use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;

mod cos;
mod shared_recycle;
mod slow_path;

use cos::{
    cos_owner_live_for_request, enqueue_local_request_to_target_or_owner,
    request_runs_under_shared_exact_policy,
};
pub(in crate::afxdp) use shared_recycle::{
    apply_shared_recycles, apply_shared_recycles_to_bindings, resolve_tx_binding_ifindex,
};
// Test-only access to internal shared_recycle helpers from the dispatch
// tests (the `tests/` submodule under this `mod.rs`, reached via `use
// super::*`).
#[cfg(test)]
use shared_recycle::{
    record_shared_recycle_unknown_slot_drops, shared_recycle_target_index,
    shared_recycle_target_index_for_split,
};
pub(in crate::afxdp) use slow_path::{
    extract_l3_packet_with_nat, handle_forward_build_failure, maybe_reinject_slow_path,
    maybe_reinject_slow_path_from_frame, slow_path_admit,
};
// pub(in crate::afxdp::tx) was previously pub(super) on the
// extract_l3_packet[_from_frame] family; the re-export keeps the
// pre-split sibling-tx/ visibility verbatim.
pub(in crate::afxdp::tx) use slow_path::{extract_l3_packet, extract_l3_packet_from_frame};

// #2208: test-only fault injection for the oversized-frame control flow.
// A built copy-path frame larger than `tx_frame_capacity()` (4096) cannot
// be produced from a single in-UMEM ingress frame in a unit test (the
// frame itself is capped at one UMEM frame), so this thread-local lets the
// dispatch tests force the oversized branch to prove it recycles the
// ingress descriptor (the pre-fix bare `continue;` leaked it). It is
// `#[cfg(test)]` only and DCEs out of release builds — the hot path keeps
// the bare `cp_len > tx_frame_capacity()` comparison with zero added cost.
#[cfg(test)]
thread_local! {
    static FORCE_OVERSIZED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[inline(always)]
fn copy_frame_is_oversized(cp_len: usize) -> bool {
    #[cfg(test)]
    if FORCE_OVERSIZED.with(|c| c.get()) {
        return true;
    }
    cp_len > tx_frame_capacity()
}

// #4041: test-only fault injection for the direct-TX tuple-mismatch
// diagnostic. The mismatch is a builder-bug paranoia check that a CORRECT
// builder can never trip — `enforce_expected_ports()` in
// `build_forwarded_frame_into_from_frame` makes the built L4 ports equal the
// expected tuple, so `forward_tuple_mismatch_reason` always returns `None`
// on a real frame. To exercise the single-recycle invariant on the diagnostic
// branch (where the frame's `tx_offset` must be returned to `free_tx_frames`
// EXACTLY once), this thread-local forces the branch. Like `FORCE_OVERSIZED`
// above it is `#[cfg(test)]` only and DCEs out of release builds.
#[cfg(test)]
thread_local! {
    static FORCE_TUPLE_MISMATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// #4041: wrapper around `forward_tuple_mismatch_reason` that lets the dispatch
// tests force the direct-TX mismatch branch. The hot path is a single tail call
// (the `#[cfg(test)]` block DCEs out), so release builds keep the bare check.
#[inline(always)]
fn direct_tx_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    #[cfg(test)]
    if FORCE_TUPLE_MISMATCH.with(|c| c.get()) {
        return Some("forward_tuple_mismatch:forced-test".to_string());
    }
    forward_tuple_mismatch_reason(source_ports, expected_ports, built_ports)
}

#[inline]
fn recycle_ingress_frame(ingress_binding: &mut BindingWorker, source_offset: u64, now_ns: u64) {
    ingress_binding
        .tx_pipeline
        .pending_fill_frames
        .push_back(source_offset);
    if ingress_binding.tx_pipeline.pending_fill_frames.len() >= FILL_BATCH_SIZE {
        let _ = drain_pending_fill(ingress_binding, now_ns);
    }
}

/// Derive the egress-MTU Path-MTU-Discovery reply for a forwarded frame the
/// TCP-segmentation path did not handle (non-TCP, TCP seg-miss, or
/// non-segmentable TCP). Pure code-motion split out of
/// `enqueue_pending_forwards` (#4408 increment 1) — behaviour is identical to
/// the inline block it replaces.
///
/// #2301 + #2330: #2301 handled ONLY plain forwards (size-preserving), where
/// the egress MTU compared against the SOURCE frame is exact. #2330 closes the
/// gap for the size-CHANGING paths (NAT64, native GRE, WireGuard): there the
/// on-wire frame grows (encap) or its header shrinks/grows (NAT64), so a
/// source-frame-vs-egress comparison is wrong. Instead we derive the
/// INNER-source MTU (the largest inner IP packet whose TRANSFORMED frame fits
/// the egress/transport MTU) from the #2300/#2331 SSOT helpers
/// (`native_gre_inner_mtu` / `wg::mss::wg_inner_mtu` / the NAT64 v6<->v4 header
/// delta) and compare the SAME inner `source_frame` against THAT.
///
/// In all three transformed cases `source_frame` IS the pre-encap /
/// pre-translation inner packet and `meta.addr_family` is the inner family, so
/// the existing `build_frag_needed_v4` / `build_packet_too_big_v6` builders
/// already target the correct inner source — they just carry the inner MTU
/// instead of the egress MTU. The generated PTB then routes through
/// `classify_generated_reply` (#2328) at the finalizer, exactly like the plain
/// path. When `mtu` is 0 (no MTU resolvable / unknown tunnel kind)
/// `forwarded_egress_mtu_decision` returns `Forward` (fail-open) and the
/// transformed frame falls through to its normal build (and, for GRE/WG
/// oversize, the #2331 encap drop guard). This CLOSES the signal #2331
/// deferred here: an oversized GRE/WG inner now yields a PTB instead of a
/// silent `GRE_ENCAP_DF_OVERSIZE_DROPS` / `encap_mtu_drops`.
///
/// Returns `(ptb_reply, mtu_signalled)`:
/// - `ptb_reply` — the built ICMP Frag-Needed (v4) / Packet-Too-Big (v6) to
///   emit back out the ingress interface, or `None` when no PTB is needed, the
///   reply is RFC/rate-limit suppressed, or the builder returned `None`.
/// - `mtu_signalled` — `true` when the oversized original MUST be dropped (a
///   PTB decision fired, whether or not a reply could be built). A `None`
///   `ptb_reply` with `mtu_signalled == true` is the fail-closed silent drop.
#[inline]
fn compute_forwarded_egress_ptb(
    source_frame: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    is_nat64: bool,
    uses_native_tunnel: bool,
    ingress_ident: &BindingIdentity,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> (Option<Vec<u8>>, bool) {
    let mut ptb_reply: Option<Vec<u8>> = None;
    let mut mtu_signalled = false;
    let egress_mtu = forwarded_egress_mtu(decision, forwarding);
    // #2845: derive the inner destination so the WG PTB picks
    // the SAME peer (and thus the SAME underlay MTU) the encap
    // path will. `source_frame` IS the pre-encap inner packet
    // and `meta.addr_family` its family. Only the WG arm
    // of `post_transform_inner_mtu` consumes this; cheap enough
    // to always derive.
    let inner_dst = frame_l3_offset(source_frame)
        .or_else(|| match meta.l3_offset {
            14 | 18 => Some(meta.l3_offset as usize),
            _ => None,
        })
        .and_then(|l3| source_frame.get(l3..))
        .and_then(|pkt| {
            crate::afxdp::gre::inner_dst_ip(pkt, meta.addr_family)
        });
    let mtu = if is_nat64 || uses_native_tunnel {
        post_transform_inner_mtu(
            decision,
            forwarding,
            is_nat64,
            meta.addr_family,
            egress_mtu,
            inner_dst,
        )
    } else {
        egress_mtu
    };
    let ptb_meta: UserspaceDpMeta = meta.into();
    let l3 = frame_l3_offset(source_frame).or_else(|| {
        match meta.l3_offset {
            14 | 18 => Some(meta.l3_offset as usize),
            _ => None,
        }
    });
    if let Some(l3) = l3 {
        let egress_decision =
            forwarded_egress_mtu_decision(source_frame, l3, meta.addr_family, mtu);
        // #9328: an oversized DF-CLEAR IPv4 datagram is still forwarded at full
        // length, but it is no longer booked as a plain successful forward. It
        // used to be indistinguishable from a frame that FITS: same `Forward`
        // value, then `enqueue_ok`, `enqueue_copy`, `pending_copy_tx_packets`
        // and `tx_bytes_total`, and no exception.
        //
        // The TCP arm of an oversized forward has recorded
        // `tcp_segmentation_miss` since #1282; this is the non-TCP counterpart,
        // for UDP, ICMP, ESP, GRE and every forwarded IPv4 fragment.
        //
        // Recorded, NOT dropped (#9395). What happens next on each path is
        // stated once, on `EgressMtuDecision::ForwardOversizeNoDf`. The
        // exception is a sampled record, delivered or not.
        if matches!(egress_decision, EgressMtuDecision::ForwardOversizeNoDf) {
            record_exception(
                recent_exceptions,
                ingress_ident,
                "egress_mtu_exceeded_forwarded_no_df",
                source_frame.len() as u32,
                Some(meta.into()),
                None,
                forwarding,
            );
        }
        if let EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } = egress_decision {
            // RFC 792 / RFC 4443 suppression: never reply to
            // a non-first fragment or an inbound ICMP error.
            // #2472/#5856: AND a per-reason, PER-INGRESS-ZONE
            // token-bucket rate limit — an oversized-DF / IPv6
            // flood would otherwise emit one PTB per trigger
            // packet, unbounded (CPU/TX amplification +
            // reflection). On bucket-empty the PTB is suppressed
            // (the `PacketTooBig` rate-limited counter is bumped
            // inside the gate); the oversized original is still
            // dropped below (`mtu_signalled`), so this never
            // falls through to forward the MTU-violating frame.
            // #5856: the bucket is PER INGRESS (from) ZONE,
            // resolved from the PHYSICAL ingress bind ifindex
            // `ingress_ident.ifindex` via `ifindex_to_zone_id`. This
            // site does NOT resolve the logical unit like the #3618
            // reject path does, so VLAN sub-interfaces on one physical
            // port SHARE that port's PTB bucket (the physical parent
            // inherits its first sub-interface's zone); an untagged
            // port has physical == logical, so its zone is exact. Even
            // so an oversized-DF flood ingressing ONE physical port can
            // no longer drain a single global bucket and suppress
            // legitimate PMTUD for every OTHER port/zone — strictly
            // better than the pre-#5856 global bucket, just coarser than
            // the reject path's per-logical-unit granularity. An
            // unzoned / unknown ingress (id 0) falls back to the
            // shared `PACKET_TOO_BIG_FALLBACK_BUCKET`.
            if !ptb_reply_suppressed(source_frame, ptb_meta, l3, forwarding) {
                // #5567: build the PTB FIRST — the build IS the feasibility
                // proof (each builder returns None on a missing egress object
                // for the ingress ifindex, a missing primary address of the
                // inbound family, or an unparseable trigger) — then consume the
                // per-reason token ONLY when a reply was actually produced.
                // Previously the token was spent before the build, so a flood
                // of reply-eligible-but-UNBUILDABLE oversized-DF / IPv6 triggers
                // on one interface drained the shared PacketTooBig bucket and
                // starved buildable PMTUD on ANOTHER interface (a cross-interface
                // false-deny DoS). Mirrors the reject path's #3656 H11
                // build-before-consume ordering; the suppression gate above
                // still runs first, so no token is spent on a suppressed PTB.
                // #6102: resolve the LOGICAL ingress unit for the reply BUILD.
                // `build_frag_needed_v4`/`build_packet_too_big_v6` each do
                // `forwarding.egress.get(&ingress_ifindex)` — egress is keyed by
                // the logical unit ifindex, while `ingress_ident.ifindex` is the
                // PHYSICAL bind port (#6046, a VLAN sub-if's physical parent).
                // Passing the physical index silently dropped the PTB on a
                // tagged sub-if with no untagged parent unit (egress miss →
                // `?`-drop → PMTUD blackhole). Mirrors the reject (#3976) /
                // cookie (#3035) precedent; the PHYSICAL index stays for the XSK
                // transmit and the #5856 per-zone bucket below. Untagged: logical
                // == physical (no-op).
                let logical_ingress = resolve_ingress_logical_ifindex(
                    forwarding,
                    ingress_ident.ifindex,
                    ptb_meta.ingress_vlan_id,
                )
                .unwrap_or(ingress_ident.ifindex);
                let built = match meta.addr_family as i32 {
                    libc::AF_INET => build_frag_needed_v4(
                        source_frame,
                        ptb_meta,
                        logical_ingress,
                        forwarding,
                        next_hop_mtu,
                    ),
                    libc::AF_INET6 => build_packet_too_big_v6(
                        source_frame,
                        ptb_meta,
                        logical_ingress,
                        forwarding,
                        next_hop_mtu as u32,
                    ),
                    _ => None,
                };
                // A buildable reply the token DENIES is rate-limited (dropped,
                // token consumed + `PacketTooBig` counter bumped inside the
                // gate). An UNBUILDABLE reply short-circuits the `&&`, so the
                // token is NOT consumed. Either way the oversized original is
                // still dropped below (`mtu_signalled`), so the trigger
                // disposition is unchanged. #5856: the token is taken from the
                // ingress zone's per-zone PTB bucket, resolved from the PHYSICAL
                // ingress bind ifindex `ingress_ident.ifindex` via
                // `ifindex_to_zone_id` — NOT the logical unit (unlike the #3618
                // reject path), so VLAN sub-interfaces on one physical port share
                // that port's bucket (unzoned / unknown → the shared
                // `PACKET_TOO_BIG_FALLBACK_BUCKET`).
                let from_zone_id = forwarding
                    .ifindex_to_zone_id
                    .get(&ingress_ident.ifindex)
                    .copied()
                    .unwrap_or(0);
                if built.is_some()
                    && allow_generated_error_zoned(
                        forwarding,
                        GeneratedErrorReason::PacketTooBig,
                        from_zone_id,
                    )
                {
                    ptb_reply = built;
                }
            }
            // Drop the oversized original regardless of
            // whether the PTB could be built (a suppressed
            // or unbuildable PTB must not fall through to
            // forward the MTU-violating frame). `ptb_reply`
            // being None here is the fail-closed silent drop.
            mtu_signalled = true;
            record_exception(
                recent_exceptions,
                ingress_ident,
                "egress_mtu_exceeded",
                source_frame.len() as u32,
                Some(meta.into()),
                None,
                forwarding,
            );
        }
    }
    (ptb_reply, mtu_signalled)
}
/// The immutable per-request inputs the copy fallback reads.
///
/// Bundled by REFERENCE, and the reason is the module discipline rather than
/// taste. The helper below needs eleven inputs; `docs/engineering-style.md`
/// draws a line at eight parameters, and shipping a signature over it silently
/// is worse than either fixing it or declaring it. This fixes it: the struct is
/// stack-only and holds only borrows, so the no-allocation hot-path invariant is
/// untouched, and the three `&mut` receivers stay separate parameters because
/// folding them in would borrow-conflict at the call sites.
struct CopyFallbackInputs<'a> {
    source_frame: &'a [u8],
    request: &'a PendingForwardRequest,
    expected_ports: Option<(u16, u16)>,
    is_nat64: bool,
    forwarding: &'a ForwardingState,
    ingress_ident: &'a BindingIdentity,
    recent_exceptions: &'a Arc<Mutex<ExceptionEventRing>>,
}

/// Build the forwarded frame into a `Vec` and enqueue it, returning
/// `(build_failed, fallback_to_slow_path)` for the caller's finalizer flags.
///
/// #6922: this was written TWICE, verbatim -- 102 lines agreeing on 100, the
/// only differences being an enclosing `None => match` versus a bare `match`
/// and one local's name. Two independently-fixed behaviours lived in both: the
/// NAT64 build-`None` drop attribution (#5625 ext-header eligibility, #2562
/// fragment guards) and the #2208 oversized / enqueue-fail recycle handling.
///
/// SINGLE-SOURCED rather than bound by an agreement test, because a divergence
/// between the two copies is ALWAYS a bug: they are the same fallback, for the
/// same frame, with the same semantics, and the two call sites differ only in
/// which upstream condition sent them here. A NAT64 drop attributed differently
/// depending on whether the in-place rewrite returned `None` or direct TX was
/// unavailable would classify one packet by an unrelated TX-path condition, and
/// an operator reading the counters could not tell which had happened.
///
/// The rationale for the attribution ORDER now lives with the code instead of
/// being an English cross-reference between two copies -- and the copy that
/// held it was the DEAD one (see
/// `nat64_never_reaches_the_in_place_rewrite_path_6922`). It mirrors the
/// translator's own guard order: `write_v6_to_v4_into` applies the #5625
/// eligibility gate BEFORE the #2562 fragment guards, so an AH / active-Routing
/// / Mobility / HIP / Shim6 packet is attributed to `nat64_exthdr_ineligible`
/// and only a genuine non-ext-header fragment drop falls through to
/// `nat64_frag_dropped`. Bound by
/// `nat64_build_none_attributes_exthdr_before_fragment_6922`, on a fixture BOTH
/// predicates match -- the order is unobservable on any frame only one matches.
///
/// `#[inline(always)]`: this is the hottest TX path in the dataplane and the two
/// call sites are the only ones. Outlining it would add a call per copy-fallback
/// packet for no benefit; #4404 is the precedent for not splitting this cascade.
#[inline(always)]
fn enqueue_copy_fallback_frame(
    inputs: &CopyFallbackInputs<'_>,
    target_binding: &mut BindingWorker,
    flow_key: &mut Option<SessionKey>,
    dbg: &mut DebugPollCounters,
    counters: &mut BatchCounters,
) -> (bool, bool) {
    let CopyFallbackInputs {
        source_frame,
        request,
        expected_ports,
        is_nat64,
        forwarding,
        ingress_ident,
        recent_exceptions,
    } = *inputs;
    let mut build_failed = false;
    let mut fallback_to_slow_path = false;
    match if is_nat64 {
        build_nat64_forwarded_frame(
            source_frame,
            request.meta,
            &request.decision,
            request.nat64_reverse.as_ref(),
            forwarding.nat64.no_v6_frag_header,
            forwarding,
        )
    } else {
        build_forwarded_frame_from_frame(
            source_frame,
            request.meta,
            &request.decision,
            forwarding,
            request.apply_nat_on_fabric,
            expected_ports,
        )
    } {
        Some(frame) => {
            if cfg!(feature = "debug-log") {
                if let Some(reason) = forward_tuple_mismatch_reason(
                    live_frame_ports_from_meta_bytes(
                        source_frame,
                        request.meta,
                    ),
                    expected_ports,
                    live_frame_ports_bytes(
                        &frame,
                        request.meta.addr_family,
                        request.meta.protocol,
                    ),
                ) {
                    record_exception_owned(
                recent_exceptions,
                ingress_ident,
                &reason,
                frame.len() as u32,
                Some(request.meta.into()),
                None,
            );
                    // Don't continue — the frame was built successfully,
                    // forward it anyway. Mismatch is diagnostic only.
                }
            }
            let copy_len = frame.len();
            if copy_frame_is_oversized(copy_len) {
                record_exception(
                    recent_exceptions,
                    ingress_ident,
                    "oversized_forward_frame",
                    copy_len as u32,
                    Some(request.meta.into()),
                    None,
                    forwarding,
                );
                // #2208: oversized fallback-copy frame —
                // undeliverable. Fall through to the
                // finalizer (recycle the ingress
                // descriptor); the bare `continue;` here
                // leaked it. Drop-and-recycle, no slow-path
                // reinject (the frame is already oversized).
                build_failed = true;
            } else {
                let req = TxRequest {
                    bytes: frame,
                    expected_ports,
                    expected_addr_family: request.meta.addr_family,
                    expected_protocol: request.meta.protocol,
                    flow_key: flow_key.take(),
                    egress_ifindex: request.decision.resolution.egress_ifindex,
                    cos_queue_id: request.cos_queue_id,
                    dscp_rewrite: request.dscp_rewrite,
                    mirror_clone: false,
                    enqueue_ns: 0,
                };
                if enqueue_local_request_to_target_or_owner(target_binding, req)
                    .is_err()
                {
                    // #2208: cross-binding CoS-owner queue
                    // full (TX congestion). Set the
                    // build-failure flags and FALL THROUGH
                    // to the finalizer instead of the old
                    // bare `continue;`, which skipped both
                    // handle_forward_build_failure (the
                    // slow-path reinject the flags request)
                    // AND recycle_ingress_frame (leaking the
                    // ingress descriptor under congestion).
                    build_failed = true;
                    fallback_to_slow_path = true;
                } else {
                    dbg.enqueue_ok += 1;
                    dbg.enqueue_copy += 1;
                    target_binding.tx_counters.pending_copy_tx_packets += 1;
                    dbg.tx_bytes_total += copy_len as u64;
                    if (copy_len as u32) > dbg.tx_max_frame {
                        dbg.tx_max_frame = copy_len as u32;
                    }
                }
            }
        }
        None => {
            build_failed = true;
            fallback_to_slow_path = true;
            // Attribute a NAT64 build-`None` to a distinct
            // fail-closed drop counter — #5625 ext-header
            // ineligibility first, else #2562 fragment drop.
            //
            // This comment used to end "(same SSOT predicates +
            // translator-order rationale as the direct/in-place
            // copy path above)". There is no longer an "above":
            // #6922 collapsed the two copies into this one owner,
            // and the rationale it pointed at now lives in this
            // function's doc comment, with the code it explains.
            // Left as a cross-reference it would name a copy that
            // does not exist — the stale-pointer half of the
            // defect this change closes.
            if is_nat64 {
                // #8890 FIRST, mirroring the builder's own guard order: the
                // tunnel check is the first statement in
                // `build_nat64_forwarded_frame`, so a tunnel-marked decision
                // returns `None` for THAT reason whatever else the frame also
                // is. Attributing it to an ext-header or fragment reason would
                // send an operator chasing a translation problem when the real
                // signal is "this NAT64 + tunnel route is not forwarded at all".
                if request.decision.resolution.tunnel_endpoint_id != 0
                    && !nat64_tunnel_is_encapsulable(
                        forwarding,
                        request.decision.resolution.tunnel_endpoint_id,
                    )
                {
                    // §8896 NARROWED THIS. `tunnel_endpoint_id != 0` used to be
                    // the whole condition, because §8890 refused the entire
                    // combination. A known mode is now encapsulated, so
                    // attributing every tunnel-marked NAT64 `None` here would
                    // report "unsupported" for a route that IS supported and
                    // failed for an ordinary reason -- sending an operator to
                    // look for a missing capability instead of at the
                    // ext-header / fragment signal the next arms carry.
                    //
                    // What remains is the genuine §2327 residue: an endpoint id
                    // resolving to NO row, or to a row whose mode is neither
                    // GRE nor WireGuard.
                    counters.record_nat64_tunnel_encap_unsupported();
                } else if crate::nat64::frame_is_nat64_exthdr_ineligible(
                    source_frame,
                    request.meta.addr_family as i32,
                ) {
                    counters.record_nat64_exthdr_ineligible();
                } else if crate::nat64::frame_is_nat64_fragment_drop(
                    source_frame,
                    request.meta.addr_family as i32,
                ) {
                    counters.record_nat64_frag_dropped();
                }
            }
        }
    }
    (build_failed, fallback_to_slow_path)
}


pub(in crate::afxdp) fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    post_recycles: &mut Vec<(u32, u64)>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    dbg: &mut DebugPollCounters,
    counters: &mut BatchCounters,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
    if pending_forwards.is_empty() {
        return;
    }
    let ingress_area = ingress_binding.umem.area() as *const MmapArea;
    post_recycles.clear();
    // Walk the scratch vector in place. Moving large PendingForwardRequest
    // values through the iterator path was still forcing per-request memcpy
    // traffic before any forwarding work started.
    for request in pending_forwards.iter_mut() {
        let source_offset = request.desc.addr;
        let ingress_slot = ingress_binding.slot;
        // #hb166 T-7: the deferred CoS-TX-selection resolution that used to
        // live here was DEAD. Every PendingForwardRequest is constructed
        // with `cos_tx_selection_resolved = true` (forward_request.rs,
        // icmp.rs, poll_descriptor/mod.rs), so CoS TX selection is always
        // resolved upstream and never deferred to this dispatch loop. The
        // removed block also carried two latent bugs that only mattered if
        // it ever went live: an UNCONDITIONAL `recycle_ingress_frame` that
        // mis-/double-recycled Prebuilt/Owned frames (whose `source_offset`
        // is not a live ingress frame), and a fully UNCOUNTED drop (no
        // tx_errors / CoS drop / fabric_redirect_unsendable_drops). Deleting
        // the dead path drops both. The `cos_tx_selection_resolved` field is
        // retained as the load-bearing invariant marker (asserted by the
        // constructor tests).
        let target_binding_index = request.target_binding_index.or_else(|| {
            binding_lookup.target_index(
                ingress_index,
                ingress_binding.ifindex,
                request.ingress_queue_id,
                request.target_ifindex,
            )
        });

        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
        // The frame is already fully rewritten — just enqueue for TX.
        if let PendingForwardFrame::Prebuilt(prebuilt) = &mut request.frame {
            // #1946: a Prebuilt frame (e.g. an embedded-ICMP NAT-reversed
            // error) can carry a FabricRedirect resolution
            // (`finalize_embedded_icmp_resolution`). When that frame is
            // unsendable to the peer — no fabric XSK binding, or the
            // local enqueue fails — drop it fail-closed AND count it on
            // `fabric_redirect_unsendable_drops`, the same observability
            // invariant as the desc-frame no-binding / build-failure
            // paths. (Non-FabricRedirect Prebuilt drops keep their prior
            // silent recycle+continue.)
            let prebuilt_is_fabric_redirect = request.decision.resolution.disposition
                == ForwardingDisposition::FabricRedirect;
            let Some(target_binding) = resolve_pending_forward_target_binding(
                left,
                ingress_index,
                ingress_binding,
                request.ingress_queue_id,
                right,
                binding_lookup,
                target_binding_index,
                request.target_ifindex,
            ) else {
                if prebuilt_is_fabric_redirect {
                    ingress_live
                        .fabric_redirect_unsendable_drops
                        .fetch_add(1, Ordering::Relaxed);
                    record_exception(
                        recent_exceptions,
                        ingress_ident,
                        "fabric_redirect_no_binding",
                        request.desc.len,
                        Some(request.meta.into()),
                        None,
                        forwarding,
                    );
                }
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            };
            let frame_len = prebuilt.len();
            let req = TxRequest {
                bytes: core::mem::take(prebuilt),
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: request.flow_key.clone(),
                egress_ifindex: request.decision.resolution.egress_ifindex,
                cos_queue_id: request.cos_queue_id,
                dscp_rewrite: request.dscp_rewrite,
                mirror_clone: false,
                enqueue_ns: 0,
            };
            if enqueue_local_request_to_target_or_owner(target_binding, req).is_err() {
                if prebuilt_is_fabric_redirect {
                    ingress_live
                        .fabric_redirect_unsendable_drops
                        .fetch_add(1, Ordering::Relaxed);
                    record_exception(
                        recent_exceptions,
                        ingress_ident,
                        "fabric_redirect_build_failed",
                        request.desc.len,
                        Some(request.meta.into()),
                        None,
                        forwarding,
                    );
                }
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            target_binding.tx_counters.pending_copy_tx_packets += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        }

        // Read source frame directly from ingress UMEM — no heap copy needed.
        // The frame is safe to read: RX ring released but frame not yet returned
        // to fill ring (that happens after this function completes).
        let source_frame = match &request.frame {
            PendingForwardFrame::Owned(frame) => frame.as_slice(),
            PendingForwardFrame::Live => {
                if let Some(frame) = (unsafe { &*ingress_area })
                    .slice(request.desc.addr as usize, request.desc.len as usize)
                {
                    frame
                } else {
                    recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                    continue;
                }
            }
            PendingForwardFrame::Prebuilt(_) => unreachable!(),
        };
        if let Some(result) = enqueue_sampled_mirror_clone(
            left,
            ingress_index,
            ingress_binding,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            request.meta.ingress_ifindex as i32,
            request.meta.ingress_vlan_id,
            request.ingress_queue_id,
            source_frame,
            request.meta,
            request.flow_key.as_ref(),
        ) {
            record_mirror_clone_result(&ingress_binding.live, result, source_frame.len());
        }
        let expected_ports = request.expected_ports;
        let ingress_umem_ptr = ingress_binding.umem.allocation_ptr();
        let Some(target_binding) = resolve_pending_forward_target_binding(
            left,
            ingress_index,
            ingress_binding,
            request.ingress_queue_id,
            right,
            binding_lookup,
            target_binding_index,
            request.target_ifindex,
        ) else {
            // No XSK binding for the target interface.  Normally fabric
            // parents have bindings; this is a safety-net fallback in case
            // the binding is not yet ready or bind() failed.
            if request.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                // #1946: a FabricRedirect with no XSK binding on the
                // fabric parent is a rare safety net (bind not ready /
                // bind() failed). The frame is a cross-chassis L2 redirect
                // destined for the peer's pipeline, NOT a kernel-FIB-
                // routable packet — reinjecting it to the local kernel
                // slow path is a wrong-path / conntrack-poison hazard (the
                // pre-#1946 PendingForwardFrame::Owned branch did exactly
                // that, while the Live branch was silently dropped by the
                // filtered maybe_reinject_slow_path wrapper). Drop BOTH
                // frame kinds identically, fail-closed, and count (cf. the
                // #1873 R-C tunnel_encap_unresolved_drops gate). We touch
                // neither frame, so the Owned (GRE-decapped copy) vs Live
                // (raw in-UMEM) representation difference is irrelevant.
                ingress_live
                    .fabric_redirect_unsendable_drops
                    .fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    ingress_ident,
                    "fabric_redirect_no_binding",
                    request.desc.len,
                    Some(request.meta.into()),
                    None,
                    forwarding,
                );
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
                continue;
            }
            dbg.no_egress_binding += 1;
            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {
                debug_log!(
                    "DBG NO_EGRESS_BINDING: target_ifindex={} ingress_if={} ingress_q={}",
                    request.target_ifindex,
                    ingress_ident.ifindex,
                    request.ingress_queue_id,
                );
            }
            record_exception(
                recent_exceptions,
                ingress_ident,
                "missing_egress_binding",
                request.desc.len,
                None,
                None,
                forwarding,
            );
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            continue;
        };
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        // #2301: a locally-generated ICMP Frag-Needed / Packet-Too-Big to
        // send back out the ingress interface when the forwarded frame
        // exceeds the egress MTU and the TCP-segmentation path did not
        // handle it. Built inside the `target_binding` borrow (it needs
        // only `source_frame`/`meta`/`ingress_ident`/`forwarding`) and
        // enqueued onto `ingress_binding` in the finalizer once that
        // borrow ends. `mtu_signalled` suppresses the oversized build.
        let mut ptb_reply: Option<Vec<u8>> = None;
        let mut mtu_signalled = false;
        let mut flow_key = request.flow_key.take();
        {
            let tcp_segmentation_needed = forwarded_tcp_may_need_segmentation(
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
            );
            if tcp_segmentation_needed {
                if let Some((segments, bytes, max_frame)) =
                    segment_forwarded_tcp_frames_into_prepared(
                        target_binding,
                        source_frame,
                        request.meta,
                        &request.decision,
                        forwarding,
                        request.apply_nat_on_fabric,
                        expected_ports,
                        flow_key.clone(),
                        request.cos_queue_id,
                        request.dscp_rewrite,
                        now_ns,
                        post_recycles,
                        worker_id,
                        worker_commands_by_id,
                    )
                {
                    dbg.enqueue_ok += segments as u64;
                    dbg.enqueue_direct += segments as u64;
                    target_binding.tx_counters.pending_direct_tx_packets += segments as u64;
                    dbg.tx_bytes_total += bytes;
                    if max_frame > dbg.tx_max_frame {
                        dbg.tx_max_frame = max_frame;
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                    }
                } else if let Some(segmented) = segment_forwarded_tcp_frames_from_frame(
                    source_frame,
                    request.meta,
                    &request.decision,
                    forwarding,
                    request.apply_nat_on_fabric,
                    expected_ports,
                ) {
                    for frame in segmented {
                        if cfg!(feature = "debug-log") {
                            if let Some(reason) = forward_tuple_mismatch_reason(
                                live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                expected_ports,
                                live_frame_ports_bytes(
                                    &frame,
                                    request.meta.addr_family,
                                    request.meta.protocol,
                                ),
                            ) {
                                record_exception_owned(
                                    recent_exceptions,
                                    ingress_ident,
                                    &reason,
                                    frame.len() as u32,
                                    Some(request.meta.into()),
                                    None,
                                );
                                build_failed = true;
                                break;
                            }
                        }
                        let seg_frame_len = frame.len();
                        target_binding
                            .tx_pipeline
                            .pending_tx_local
                            .push_back(TxRequest {
                                bytes: frame,
                                expected_ports,
                                expected_addr_family: request.meta.addr_family,
                                expected_protocol: request.meta.protocol,
                                flow_key: flow_key.clone(),
                                egress_ifindex: request.decision.resolution.egress_ifindex,
                                cos_queue_id: request.cos_queue_id,
                                dscp_rewrite: request.dscp_rewrite,
                                mirror_clone: false,
                                enqueue_ns: 0,
                            });
                        bound_pending_tx_local(target_binding);
                        dbg.enqueue_ok += 1;
                        dbg.enqueue_copy += 1;
                        target_binding.tx_counters.pending_copy_tx_packets += 1;
                        dbg.tx_bytes_total += seg_frame_len as u64;
                        if (seg_frame_len as u32) > dbg.tx_max_frame {
                            dbg.tx_max_frame = seg_frame_len as u32;
                        }
                    }
                    copied_source_frame = true;
                    if target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                    }
                }
            }
            // Track when segmentation was needed but both builders returned None.
            if count_forwarded_tcp_segmentation_miss_if_needed(
                dbg,
                copied_source_frame,
                tcp_segmentation_needed,
            ) {
                thread_local! {
                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                SEG_MISS_LOG.with(|cap| {
                    record_forwarded_tcp_segmentation_miss(
                        cap,
                        recent_exceptions,
                        ingress_ident,
                        source_frame,
                        request,
                        forwarding,
                    );
                });
            }
            if !copied_source_frame {
                // NAT64: header size changes prevent in-place rewrite.
                // Always use copy path with NAT64-specific frame builder.
                let is_nat64 = request.decision.nat.nat64;
                let uses_native_tunnel = request.decision.resolution.tunnel_endpoint_id != 0;

                // #2301 + #2330 + #2845: PMTUD for forwarded frames the TCP
                // segmentation path did not handle. Extracted to
                // `compute_forwarded_egress_ptb` (#4408 increment 1); see its
                // doc comment for the full rationale. Pure code-motion: same
                // inner-MTU derivation, `forwarded_egress_mtu_decision`, PTB
                // build, and `egress_mtu_exceeded` exception recording.
                (ptb_reply, mtu_signalled) = compute_forwarded_egress_ptb(
                    source_frame,
                    request.meta,
                    &request.decision,
                    forwarding,
                    is_nat64,
                    uses_native_tunnel,
                    ingress_ident,
                    recent_exceptions,
                );
                // Skip the oversized-frame build/forward entirely when an
                // egress-MTU PTB was signalled; the finalizer enqueues
                // `ptb_reply` (if any) and recycles the ingress descriptor.
                if !mtu_signalled {
                // #1598 secondary fix: gate on `shared_exact` policy
                // (not on `shared_queue_lease.is_some()`), see the
                // doc comment on `request_runs_under_shared_exact_policy`
                // in dispatch/cos.rs. Non-exact uncapped queues now
                // qualify for the local in-place rewrite path.
                let owner_matches_target = request_runs_under_shared_exact_policy(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                ) || cos_owner_live_for_request(
                    &target_binding.cos.cos_fast_interfaces,
                    request.decision.resolution.egress_ifindex,
                    request.cos_queue_id,
                )
                .is_none_or(|live| Arc::ptr_eq(live, &target_binding.live));

                /*
                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
                 * and submit it to the target binding's TX ring without copying.
                 * This is valid whenever ingress and egress bindings share the same
                 * UMEM allocation. That includes same-binding hairpin and the narrow
                 * shared-UMEM groups.
                 */
                let can_rewrite_in_place = target_binding.umem.allocation_ptr() == ingress_umem_ptr
                    && !is_nat64
                    && !uses_native_tunnel
                    && owner_matches_target
                    && matches!(request.frame, PendingForwardFrame::Live);
                if can_rewrite_in_place {
                    match rewrite_forwarded_frame_in_place(
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        &request.decision,
                        request.apply_nat_on_fabric,
                        expected_ports,
                    ) {
                        Some(rewrite_result) => {
                            target_binding.tx_pipeline.pending_tx_prepared.push_back(
                                PreparedTxRequest {
                                    offset: rewrite_result.offset,
                                    len: rewrite_result.len,
                                    recycle: PreparedTxRecycle::fill_on_slot(
                                        ingress_slot,
                                        rewrite_result.offset,
                                        source_offset,
                                    ),
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: flow_key.take(),
                                    egress_ifindex: request.decision.resolution.egress_ifindex,
                                    cos_queue_id: request.cos_queue_id,
                                    dscp_rewrite: request.dscp_rewrite,
                                    mirror_clone: false,
                                    enqueue_ns: 0,
                                },
                            );
                            bound_pending_tx_prepared(target_binding, Some(post_recycles));
                            target_binding.tx_counters.pending_in_place_tx_packets += 1;
                            target_binding
                                .tx_counters
                                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
                            dbg.enqueue_ok += 1;
                            dbg.enqueue_inplace += 1;
                            dbg.tx_bytes_total += rewrite_result.len as u64;
                            if rewrite_result.len > dbg.tx_max_frame {
                                dbg.tx_max_frame = rewrite_result.len;
                            }
                            retained_source_frame = true;
                        }
                        None => {
                            let (bf, fs) = enqueue_copy_fallback_frame(
                                &CopyFallbackInputs {
                                    source_frame,
                                    request,
                                    expected_ports,
                                    is_nat64,
                                    forwarding,
                                    ingress_ident,
                                    recent_exceptions,
                                },
                                target_binding,
                                &mut flow_key,
                                dbg,
                                counters,
                            );
                            build_failed |= bf;
                            fallback_to_slow_path |= fs;
                        }
                    }
                } else {
                    enum DirectTxFallbackReason {
                        NoFreeTxFrame,
                        BuildReturnedNone,
                        DisallowedByRewriteMode,
                    }
                    // Direct TX build: write the forwarded frame directly into
                    // the target binding's UMEM TX frame, eliminating the
                    // intermediate Vec allocation and one memcpy.
                    // NAT64 cannot use direct TX (header size changes), so
                    // it falls through to the copy path below.
                    let mut direct_tx_offset =
                        target_binding.tx_pipeline.free_tx_frames.pop_front();
                    if direct_tx_offset.is_none()
                        && (target_binding.tx_pipeline.outstanding_tx > 0
                            || !target_binding.tx_pipeline.pending_tx_prepared.is_empty()
                            || !target_binding.tx_pipeline.pending_tx_local.is_empty())
                    {
                        let _ = drain_pending_tx_local_owner(
                            target_binding,
                            now_ns,
                            post_recycles,
                            forwarding,
                            worker_id,
                            worker_commands_by_id,
                        );
                        direct_tx_offset = target_binding.tx_pipeline.free_tx_frames.pop_front();
                    }
                    let mut direct_tx_fallback_reason = None;
                    let direct_built = if is_nat64 || uses_native_tunnel {
                        // NAT64 can't use direct TX — return the frame if we popped one.
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if !owner_matches_target {
                        if let Some(off) = direct_tx_offset {
                            target_binding.tx_pipeline.free_tx_frames.push_front(off);
                        }
                        // A prepared/direct frame on a non-owner binding would be
                        // cloned back into a local Vec during CoS owner redirection.
                        // Skip that waste and fall back to the single-copy local path.
                        direct_tx_fallback_reason =
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
                        false
                    } else if let Some(tx_offset) = direct_tx_offset {
                        let target_area = target_binding.umem.area();
                        // Prefetch target frame to warm cache before copy.
                        #[cfg(target_arch = "x86_64")]
                        if let Some(pf) = target_area.slice(tx_offset as usize, 64) {
                            unsafe {
                                core::arch::x86_64::_mm_prefetch(
                                    pf.as_ptr() as *const i8,
                                    core::arch::x86_64::_MM_HINT_T0,
                                );
                            }
                        }
                        let written = unsafe {
                            target_area.slice_mut_unchecked(tx_offset as usize, tx_frame_capacity())
                        }
                        .and_then(|out| {
                            build_forwarded_frame_into_from_frame(
                                out,
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                request.apply_nat_on_fabric,
                                expected_ports,
                            )
                        });
                        if let Some(written) = written {
                            // Debug-only: validate built frame ports match expected.
                            // enforce_expected_ports() in build_forwarded_frame_into_from_frame
                            // already ensures correctness; this catches builder bugs.
                            if cfg!(feature = "debug-log") {
                                let built_ports = unsafe {
                                    target_area.slice_mut_unchecked(tx_offset as usize, written)
                                }
                                .and_then(|f| {
                                    live_frame_ports_bytes(
                                        f,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    )
                                });
                                if let Some(reason) = direct_tx_tuple_mismatch_reason(
                                    live_frame_ports_from_meta_bytes(source_frame, request.meta),
                                    expected_ports,
                                    built_ports,
                                ) {
                                    // #4041: DO NOT recycle `tx_offset` here.
                                    // Setting `build_failed` routes this frame
                                    // through the single `if build_failed`
                                    // recycle below, which pushes the offset
                                    // back onto `free_tx_frames` exactly once.
                                    // Pushing it in this diagnostic branch too
                                    // double-recycled the offset — it would be
                                    // handed out twice on a later TX and alias
                                    // an in-flight frame (on-wire corruption /
                                    // double-free on the debug-log build). The
                                    // `record_exception` below still surfaces
                                    // the mismatch to operators.
                                    record_exception_owned(
                                    recent_exceptions,
                                    ingress_ident,
                                    &reason,
                                    written as u32,
                                    Some(request.meta.into()),
                                    None,
                                );
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding
                                    .tx_pipeline
                                    .free_tx_frames
                                    .push_front(tx_offset);
                                true
                            } else if written > tx_frame_capacity() {
                                target_binding
                                    .tx_pipeline
                                    .free_tx_frames
                                    .push_front(tx_offset);
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    "oversized_forward_frame",
                                    written as u32,
                                    Some(request.meta.into()),
                                    None,
                                    forwarding,
                                );
                                true
                            } else {
                                target_binding.tx_pipeline.pending_tx_prepared.push_back(
                                    PreparedTxRequest {
                                        offset: tx_offset,
                                        len: written as u32,
                                        recycle: PreparedTxRecycle::FreeTxFrame,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: flow_key.take(),
                                        egress_ifindex: request.decision.resolution.egress_ifindex,
                                        cos_queue_id: request.cos_queue_id,
                                        dscp_rewrite: request.dscp_rewrite,
                                        mirror_clone: false,
                                        enqueue_ns: 0,
                                    },
                                );
                                bound_pending_tx_prepared(target_binding, Some(post_recycles));
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_direct += 1;
                                target_binding.tx_counters.pending_direct_tx_packets += 1;
                                dbg.tx_bytes_total += written as u64;
                                if (written as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = written as u32;
                                }
                                true
                            }
                        } else {
                            target_binding
                                .tx_pipeline
                                .free_tx_frames
                                .push_front(tx_offset);
                            direct_tx_fallback_reason =
                                Some(DirectTxFallbackReason::BuildReturnedNone);
                            false
                        }
                    } else {
                        direct_tx_fallback_reason = Some(DirectTxFallbackReason::NoFreeTxFrame);
                        false
                    };
                    // Fallback: Vec copy path when direct build unavailable.
                    if !direct_built {
                        match direct_tx_fallback_reason {
                            Some(DirectTxFallbackReason::NoFreeTxFrame) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_no_frame_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::BuildReturnedNone) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_build_fallback_packets += 1;
                            }
                            Some(DirectTxFallbackReason::DisallowedByRewriteMode) => {
                                target_binding
                                    .tx_counters
                                    .pending_direct_tx_disallowed_fallback_packets += 1;
                            }
                            None => {}
                        }
                        let (bf, fs) = enqueue_copy_fallback_frame(
                            &CopyFallbackInputs {
                                source_frame,
                                request,
                                expected_ports,
                                is_nat64,
                                forwarding,
                                ingress_ident,
                                recent_exceptions,
                            },
                            target_binding,
                            &mut flow_key,
                            dbg,
                            counters,
                        );
                        build_failed |= bf;
                        fallback_to_slow_path |= fs;
                    }
                }
                } // close `if !mtu_signalled` (#2301 egress-MTU PTB)
            }
            if target_binding.tx_pipeline.pending_tx_prepared.len() >= TX_BATCH_SIZE
                || target_binding.tx_pipeline.pending_tx_local.len() >= TX_BATCH_SIZE
            {
                let _ = drain_pending_tx_local_owner(
                    target_binding,
                    now_ns,
                    post_recycles,
                    forwarding,
                    worker_id,
                    worker_commands_by_id,
                );
            }
        }
        if !post_recycles.is_empty() {
            apply_shared_recycles(
                left,
                ingress_index,
                ingress_binding,
                right,
                binding_lookup,
                post_recycles,
            );
        }
        // #2301: enqueue the egress-MTU PTB back out the ingress interface
        // now that the `target_binding` borrow has ended. The reply is L2-
        // reflected (dst = inbound src), so it leaves via `ingress_binding`.
        // The oversized original is dropped: `mtu_signalled` left
        // `retained_source_frame` false, so the recycle below returns its
        // descriptor to the fill ring. A None `ptb_reply` (suppressed or
        // unbuildable) is the fail-closed silent drop.
        if let Some(ptb_bytes) = ptb_reply.take() {
            // #2328: classify the GENERATED egress-MTU PTB / Frag-Needed reply
            // by its OWN egress 5-tuple + egress interface, exactly like the
            // ICMP/ICMPv6 Time Exceeded (#2238), policy-`reject`, and
            // SYN-cookie generators. The PTB is L2-reflected back out the
            // ingress interface. Pre-#2328 the PTB enqueued an UNCLASSIFIED
            // TxRequest (`cos_queue_id: None, dscp_rewrite: None`), so an output
            // firewall filter terminal `discard`/`reject` keyed on the generated
            // ICMP tuple never fired and CoS forwarding-class / DSCP rewrite were
            // skipped. A parse failure of our own built bytes fails CLOSED (drop
            // + dedicated parse-error counter, §6.2) rather than leaking past the
            // filter.
            //
            // #6102: `classify_generated_reply` is keyed by the LOGICAL unit
            // ifindex, but `ingress_ident.ifindex` is the PHYSICAL bind port
            // (#6046, a VLAN sub-if's physical parent). Resolve the logical unit
            // so a tagged sub-if's OWN output filter / CoS is enforced (pre-fix
            // the parent's — or first sub-if's — filter was applied). The
            // enqueue below stays on the PHYSICAL `ingress_ident.ifindex` (the
            // XSK transmit device). Untagged: logical == physical (no-op).
            let logical_ingress = resolve_ingress_logical_ifindex(
                forwarding,
                ingress_ident.ifindex,
                request.meta.ingress_vlan_id,
            )
            .unwrap_or(ingress_ident.ifindex);
            let verdict =
                classify_generated_reply(forwarding, logical_ingress, &ptb_bytes, now_ns);
            if verdict.drop {
                counters.touched = true;
                if verdict.parse_error {
                    counters.generated_reply_classify_parse_errors += 1;
                } else {
                    counters.ptb_output_filter_drops += 1;
                }
                // Fail-closed: the oversized original is already dropped
                // (`mtu_signalled`); dropping the PTB here leaves no frame to
                // leak past the egress output filter.
            } else {
                let ptb_len = ptb_bytes.len();
                ingress_binding
                    .tx_pipeline
                    .pending_tx_local
                    .push_back(TxRequest {
                        bytes: ptb_bytes,
                        expected_ports: None,
                        expected_addr_family: request.meta.addr_family,
                        expected_protocol: request.meta.protocol,
                        flow_key: None,
                        egress_ifindex: ingress_ident.ifindex,
                        cos_queue_id: verdict.cos_queue_id,
                        dscp_rewrite: verdict.dscp_rewrite,
                        mirror_clone: false,
                        enqueue_ns: 0,
                    });
                bound_pending_tx_local(ingress_binding);
                dbg.enqueue_ok += 1;
                dbg.enqueue_copy += 1;
                ingress_binding.tx_counters.pending_copy_tx_packets += 1;
                dbg.tx_bytes_total += ptb_len as u64;
                if (ptb_len as u32) > dbg.tx_max_frame {
                    dbg.tx_max_frame = ptb_len as u32;
                }
            }
        }
        if build_failed {
            handle_forward_build_failure(
                ingress_ident,
                ingress_live,
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                dbg,
                request.target_ifindex,
                request.desc.len,
                source_frame,
                request.meta,
                request.decision,
                fallback_to_slow_path,
                forwarding,
            );
            if !retained_source_frame {
                recycle_ingress_frame(ingress_binding, source_offset, now_ns);
            }
            continue;
        }
        if !retained_source_frame {
            recycle_ingress_frame(ingress_binding, source_offset, now_ns);
        }
    }
    while !ingress_binding.tx_pipeline.pending_fill_frames.is_empty() {
        let pending_before = ingress_binding.tx_pipeline.pending_fill_frames.len();
        let _ = drain_pending_fill(ingress_binding, now_ns);
        if ingress_binding.tx_pipeline.pending_fill_frames.len() >= pending_before {
            break;
        }
    }
    update_binding_debug_state(ingress_binding);
    pending_forwards.clear();
}

fn resolve_pending_forward_target_binding<'a>(
    left: &'a mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    target_binding_index: Option<usize>,
    target_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    if let Some(target_index) = target_binding_index {
        return binding_by_index_mut(left, ingress_index, ingress_binding, right, target_index);
    }
    find_target_binding_mut(
        left,
        ingress_index,
        ingress_binding,
        ingress_queue_id,
        right,
        binding_lookup,
        target_ifindex,
    )
}

#[inline(always)]
fn count_forwarded_tcp_segmentation_miss_if_needed(
    dbg: &mut DebugPollCounters,
    copied_source_frame: bool,
    tcp_segmentation_needed: bool,
) -> bool {
    if copied_source_frame || !tcp_segmentation_needed {
        return false;
    }
    dbg.seg_needed_but_none += 1;
    true
}

/// Surface a genuine TCP segmentation miss to operators, rate-capped per
/// worker thread.
///
/// #1282: when segmentation is needed but both frame builders return
/// `None`, the dispatcher falls back to forwarding the original oversized
/// frame whole; for a DF-clear IPv4 frame, what then happens is stated on
/// `EgressMtuDecision::ForwardOversizeNoDf`.
/// The `dbg.seg_needed_but_none` counter that records this is
/// `pub(in crate::afxdp)` and is never exported to Go/CLI, so it is not an
/// operator-visible signal. We record a first-class `tcp_segmentation_miss`
/// exception so the event shows up under `Recent exceptions` in `show
/// chassis cluster data-plane statistics` even in release builds.
///
/// The recording is rate-capped via the caller-owned `cap` cell (20 per
/// worker thread) so a pathological per-packet seg-miss cannot spin the
/// `recent_exceptions` mutex on the hot path. The `DBG SEG_MISS` packet-
/// shape print is `debug-log`-only, matching the sibling debug prints in
/// this file; it DCEs out of release builds.
#[inline(always)]
fn record_forwarded_tcp_segmentation_miss(
    cap: &std::cell::Cell<u32>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    ingress_ident: &BindingIdentity,
    source_frame: &[u8],
    request: &PendingForwardRequest,
    forwarding: &ForwardingState,
) {
    let n = cap.get();
    if n >= 20 {
        return;
    }
    cap.set(n + 1);
    record_exception(
        recent_exceptions,
        ingress_ident,
        "tcp_segmentation_miss",
        source_frame.len() as u32,
        Some(request.meta.into()),
        None,
        forwarding,
    );
    if cfg!(feature = "debug-log") {
        let egress_mtu = forwarding
            .egress
            .get(&request.decision.resolution.egress_ifindex)
            .or_else(|| {
                forwarding
                    .egress
                    .get(&request.decision.resolution.tx_ifindex)
            })
            .map(|e| e.mtu);
        eprintln!(
            "DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} \
             target_if={} src_frame_bytes={}",
            n,
            source_frame.len(),
            request.meta.protocol,
            request.decision.resolution.egress_ifindex,
            request.decision.resolution.tx_ifindex,
            egress_mtu,
            request.target_ifindex,
            source_frame.len(),
        );
    }
}

/// Resolve the egress interface MTU for a forwarding decision, preferring
/// the egress ifindex and falling back to the tx ifindex (the same lookup
/// `forwarded_tcp_may_need_segmentation` performs). Returns `0` when no
/// egress entry is known, which the MTU decision treats as "no MTU known →
/// forward unchanged".
#[inline(always)]
/// §8896: can this tunnel endpoint actually be encapsulated by the NAT64
/// builder? True only for a row that EXISTS and whose mode is one the frame
/// builders handle. Mirrors the §2327 dispatch in
/// `build_nat64_forwarded_frame` so the counter and the builder cannot
/// disagree about what "unsupported" means.
fn nat64_tunnel_is_encapsulable(forwarding: &ForwardingState, tunnel_endpoint_id: u16) -> bool {
    forwarding
        .tunnel_endpoints
        .get(&tunnel_endpoint_id)
        .is_some_and(|e| {
            matches!(
                crate::afxdp::forwarding_build::tunnel_mode_kind(&e.mode),
                crate::afxdp::forwarding_build::TunnelKind::Gre
                    | crate::afxdp::forwarding_build::TunnelKind::WireGuard
            )
        })
}

fn forwarded_egress_mtu(decision: &SessionDecision, forwarding: &ForwardingState) -> usize {
    forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or(0)
}

#[inline(always)]
fn forwarded_tcp_may_need_segmentation(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> bool {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
        return false;
    }
    // #5159: use the ACTUAL egress MTU, in lockstep with both segmentation
    // builders. The prior `.max(1280)` floored a valid IPv4 MTU of 68-1279 to
    // the IPv6-minimum LINK MTU (1280 is NOT an IPv4 floor; IPv4 min is 68), so
    // this gate never admitted a non-DF TCP datagram whose L3 length fell in
    // (real_mtu, 1280] and it was submitted OVERSIZE to AF_XDP TX. Treat 0 (no
    // egress entry / unknown MTU) as "don't segment" — forward unchanged,
    // matching the builders' now-live `mtu == 0` guard.
    let mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default();
    if mtu == 0 {
        return false;
    }
    // Prefer the actual Ethernet header in the frame. Metadata can lag
    // behind VLAN normalization; a VLAN frame with 18 bytes of L2 and a
    // 1500-byte L3 payload is 1518 bytes total, and treating stale
    // `l3_offset=14` as authoritative falsely flags it as needing TCP
    // segmentation. The segmentation builders already re-derive L3 from
    // the frame, so keep this predicate aligned with them.
    let l3 = frame_l3_offset(frame).or_else(|| match meta.l3_offset {
        14 | 18 => Some(meta.l3_offset as usize),
        _ => None,
    });
    let Some(l3) = l3 else {
        return false;
    };
    if l3 >= frame.len() {
        return false;
    }
    // #1852 + #5148: NEVER TCP-segment ANY IP fragment — first or
    // non-first. A non-first fragment (#1852) has no TCP header at the
    // post-IP offset (its "L4" bytes are payload). A FIRST fragment (IPv4
    // MF=1 offset=0, or an IPv6 packet carrying a Fragment header) DOES
    // carry a real TCP header, so the pre-#5148 non-first-only gate
    // admitted it into the segmentation builders. Segmentation then cloned
    // the fragment-bearing IP header (Identification / MF / offset) into
    // every output while rewriting seq/checksum — emitting overlapping
    // offset-0 pseudo-fragments that break reassembly at the receiver.
    // `meta.protocol == PROTO_TCP` holds for both classes (the shim reads
    // the protocol from the IP header / v6 fragment next-header). A
    // fragmented datagram must never be transformed into independent TCP
    // segments — segmentation is only for WHOLE (unfragmented) over-MTU TCP
    // datagrams. Route any fragment to the normal forwarding path unchanged
    // (same disposition as the sibling #1852 non-first handling).
    if is_any_fragment(&frame[l3..], meta.addr_family) {
        return false;
    }
    // #5141: admit on the IP-DECLARED datagram length, not the raw backing
    // length. `frame.len() - l3` counts trailing Ethernet slack / appended
    // bytes that the segmentation builders now clamp away via
    // `declared_l3_end`. Admitting on the backing length would flag a
    // within-MTU datagram that merely carries slack as "needs segmentation",
    // and the builder would then clamp and refuse — a wasted admission plus a
    // spurious `tcp_segmentation_miss`. Keep this gate in lockstep with the
    // builders: segment only when the declared datagram itself exceeds the
    // egress MTU. A truncated/unknown-family L3 header fails closed (no seg).
    let Some(l3_end) = declared_l3_end(frame, l3, meta.addr_family) else {
        return false;
    };
    l3_end.saturating_sub(l3) > mtu
}

#[cfg(test)]
mod tests;
