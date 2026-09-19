// Slow-path / exception / build-failure routing for the dispatch
// loop (#1443).
//
// Pure code motion from `dispatch/mod.rs`. Hot-path callers reach
// these helpers only on exception branches (build failure, missing
// egress binding, fabric-redirect fallback), so we tag the
// reinjection family `#[cold] #[inline(never)]` per AGY round-2
// finding D — `#[cold]` alone does not stop LLVM from inlining a
// single-caller helper and bloating the hot i-cache footprint;
// `#[inline(never)]` guarantees the cold body stays out-of-line.
//
// The dispatch `mod.rs` re-exports
// - `handle_forward_build_failure`,
// - `maybe_reinject_slow_path`,
// - `maybe_reinject_slow_path_from_frame`,
// - `extract_l3_packet_with_nat`
// at `pub(in crate::afxdp)`; `extract_l3_packet` and
// `extract_l3_packet_from_frame` keep their pre-split `pub(super)`
// (visible to all of `tx/`) via `pub(in crate::afxdp::tx)`.

use super::*;

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn handle_forward_build_failure(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    dbg: &mut DebugPollCounters,
    _target_ifindex: i32,
    packet_length: u32,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    fallback_to_slow_path: bool,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    dbg.build_fail += 1;
    #[cfg(feature = "debug-log")]
    if dbg.build_fail <= 3 {
        debug_log!(
            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
            _target_ifindex,
            packet_length,
            fallback_to_slow_path,
        );
    }
    record_exception(
        recent_exceptions,
        binding,
        "forward_build_failed",
        packet_length,
        Some(meta),
        None,
        forwarding,
    );
    // #1946: a FabricRedirect frame is a cross-chassis L2 redirect for the
    // peer's pipeline, never a kernel-FIB-routable packet. If the
    // forward-frame build/enqueue failed (binding present but build/TX
    // failed), reinjecting it to the local kernel slow path via the raw
    // `maybe_reinject_slow_path_from_frame` primitive is the same
    // wrong-path / conntrack-poison hazard the no-binding fallback in
    // `tx/dispatch/mod.rs` now avoids. Drop fail-closed and count on the
    // SHARED `fabric_redirect_unsendable_drops` counter (distinct
    // exception reason for path observability). This also keeps the
    // documented invariant true: after #1946 the only intentional
    // unfiltered caller of the raw primitive ON A RESOLVED DISPOSITION is
    // the ForwardCandidate build-failure reinject below (ForwardCandidate
    // IS a route the kernel may legitimately serve). #6664 corrects the
    // scope of that sentence: `poll_stages.rs` also calls the raw
    // primitive unfiltered, but with a SYNTHETIC `LocalDelivery` decision
    // for host-terminated IPsec passthrough, so it never carries a
    // resolved disposition past the predicate.
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
        live.fabric_redirect_unsendable_drops
            .fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "fabric_redirect_build_failed",
            packet_length,
            Some(meta),
            None,
            forwarding,
        );
        return;
    }
    if fallback_to_slow_path {
        maybe_reinject_slow_path_from_frame(
            binding,
            live,
            slow_path,
            local_tunnel_deliveries,
            frame,
            meta,
            decision,
            // #9637 operator narrowing: the build-failure fallback carries a
            // FORWARD disposition (possibly firewall-local via a non-owning
            // table) that never passed a host gate — delegated outlet, so the
            // kernel judges it by destination exactly as pre-#9637.
            false,
            recent_exceptions,
            "forward_build_slow_path",
            forwarding,
        );
    }
}

/// #1913/#6664: the ONE place that asks whether a disposition may be handed to
/// the kernel slow path, and the one place a refusal is accounted.
///
/// Returns true to admit. On a refusal it records the per-disposition
/// fail-closed drop, which is why this is a function rather than two calls to
/// `is_slow_path_eligible`: the predicate and the accounting must never
/// disagree about a frame. Both refusal points -- this module's filtered
/// wrapper and the trailing chokepoint in `poll_descriptor` -- route through
/// here, so there is a single site to bind and a single site to get wrong.
///
/// Before #6664 the accounting lived at each caller. That is a divergence that
/// could only ever be a bug, never a policy difference, and it showed up as one
/// immediately: a mutation deleting the `poll_descriptor` copy passed the whole
/// suite, because no test drives that function. Collapsing the two sites into
/// one is what makes the behaviour testable at all.
pub(in crate::afxdp) fn slow_path_admit(
    live: &BindingLiveState,
    disposition: ForwardingDisposition,
) -> bool {
    if disposition.is_slow_path_eligible() {
        return true;
    }
    // #6664: NextTableUnsupported left the allow-list, so its refusal is
    // counted here. Without this the signal would vanish with the accept-path
    // counter it used to bump (`slow_path_next_table_packets`), which is
    // exported to Prometheus and would have frozen at zero -- to an operator,
    // indistinguishable from "no such packets ever arrived".
    if disposition == ForwardingDisposition::NextTableUnsupported {
        live.record_next_table_unsupported_drop();
    }
    // #9752: same accounting shape as #6664 above — the refusal must be
    // counted where it happens or the signal vanishes.
    if disposition == ForwardingDisposition::TableUnavailable {
        live.record_table_unavailable_drop();
    }
    false
}

/// #9637/#10391 operator narrowing: which slow-path outlet a reinject takes.
///
/// `Trusted` is the gated LocalDelivery outlet (`xpf-usp0`). `Adjudicated`
/// is policy-permitted xfrm/reinject traffic on queue zero of the shared
/// `xpf-usp1` TUN; the TC classifier converts that queue identity to the
/// fence mark. `Delegated` is queue one of `xpf-usp1` and remains unmarked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum SlowPathOutlet {
    Trusted,
    Adjudicated,
    Delegated,
}

/// The ONLY trusted path is a `LocalDelivery` disposition through the
/// FILTERED chokepoint (`poll_descriptor`, downstream of the session-hit /
/// session-miss / flowless host-inbound gates — every deny `continue`s before
/// reinject). All other reinject classes are delegated or explicitly
/// adjudicated at their policy-gated outlet.
pub(in crate::afxdp) fn reinject_host_authorized(
    disposition: ForwardingDisposition,
) -> bool {
    matches!(disposition, ForwardingDisposition::LocalDelivery)
}

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    // #9637: test-only wrapper (no production callers) — threaded through
    // so tests pin the outlet under test explicitly.
    host_authorized: bool,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    // #1913: single source of truth for the slow-path allow-list. A
    // disposition the predicate rejects (PolicyDenied / HAInactive /
    // DiscardRoute / ForwardCandidate / FabricRedirect) must be dropped,
    // never reinjected to the kernel FIB.
    if !slow_path_admit(live, decision.resolution.disposition) {
        return;
    }
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_extract_failed",
            desc.len as u32,
            Some(meta),
            None,
            forwarding,
        );
        return;
    };
    maybe_reinject_slow_path_from_frame(
        binding,
        live,
        slow_path,
        local_tunnel_deliveries,
        frame,
        meta,
        decision,
        host_authorized,
        recent_exceptions,
        "slow_path",
        forwarding,
    );
}

/// RAW / unchecked slow-path reinjection primitive.
///
/// This helper does NOT filter on `decision.resolution.disposition`: it
/// will hand ANY parseable L3 frame to the kernel slow path (or local
/// tunnel-delivery channel). Callers are responsible for applying
/// [`ForwardingDisposition::is_slow_path_eligible`] BEFORE calling this,
/// unless they have a documented reason to bypass the allow-list.
///
/// The filtered entry point is the `maybe_reinject_slow_path` wrapper
/// above (and the gated trailing chokepoint in
/// `poll_descriptor::poll_binding_process_descriptor`, #1913), which both
/// apply the predicate.
///
/// The TWO INTENTIONAL unfiltered callers (disposition deliberately
/// outside the allow-list):
///   - `handle_forward_build_failure` (above): reinjects a
///     `ForwardCandidate` frame when the forward descriptor build fails
///     (ForwardCandidate IS a route the kernel FIB may legitimately
///     serve). That helper now drops `FabricRedirect` fail-closed BEFORE
///     reaching this primitive (#1946), so it never raw-reinjects a
///     fabric frame. This is the only unfiltered caller that carries a
///     RESOLVED disposition.
///   - the host-terminated IPsec passthrough in `poll_stages.rs`
///     (#6664): calls this primitive with a SYNTHETIC `LocalDelivery`
///     decision, so it never carries a resolved disposition past the
///     predicate. ESP/AH, ESP-in-UDP and NAT-T keepalives are
///     unconditionally exempt; IKE faces its own host-inbound admit
///     checks (#4323/#6471) before reaching this call.
/// These callers rely on the unfiltered behavior; do NOT add a
/// disposition filter inside this primitive (it would break them — #1913
/// Path B, rejected).
///
/// #7480: this enumeration is PINNED by
/// `tests/slow_path_admit_single_site_6664.rs`
/// (`raw_reinject_primitive_caller_set_is_pinned_7480`), so a new call
/// site reds rather than silently invalidating this list. It went stale
/// once already: #1946 wrote "ONE", #6664 found the second caller and
/// corrected the SIBLING comment at the build-failure call site while
/// leaving this block — the one a caller actually reads before bypassing
/// the predicate — saying "ONE".
///
/// #1946: the former second unfiltered caller — the `tx/dispatch/mod.rs`
/// FabricRedirect-Owned no-binding fallback — was removed; a
/// FabricRedirect with no fabric XSK binding (or whose build/enqueue
/// failed) is now dropped fail-closed and counted
/// (`fabric_redirect_unsendable_drops`) rather than reinjected to the
/// local kernel FIB (a cross-chassis L2 redirect is never kernel-FIB
/// routable).
#[cold]
#[inline(never)]
pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    // #9637 compatibility wrapper: callers that already have the historical
    // boolean contract map true to the trusted outlet and false to delegated.
    host_authorized: bool,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    reason: &'static str,
    forwarding: &ForwardingState,
) -> bool {
    maybe_reinject_slow_path_from_frame_with_outlet(
        binding,
        live,
        slow_path,
        local_tunnel_deliveries,
        frame,
        meta,
        decision,
        if host_authorized {
            SlowPathOutlet::Trusted
        } else {
            SlowPathOutlet::Delegated
        },
        recent_exceptions,
        reason,
        forwarding,
    )
}

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame_with_outlet(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    outlet: SlowPathOutlet,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    reason: &'static str,
    forwarding: &ForwardingState,
) -> bool {
    let meta = meta.into();
    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_prepare_failed",
            frame.len() as u32,
            Some(meta),
            None,
            forwarding,
        );
        return false;
    };
    let packet_len = packet.len() as u64;
    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.local_ifindex > 0
    {
        local_tunnel_deliveries
            .load()
            .get(&decision.resolution.local_ifindex)
            .cloned()
    } else {
        None
    };
    if let Some(delivery) = tunnel_delivery {
        let accepted = match delivery.try_send(packet) {
            Ok(()) => {
                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
                true
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_queue_full",
                    frame.len() as u32,
                    Some(meta),
                    None,
                    forwarding,
                );
                false
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_unavailable",
                    frame.len() as u32,
                    Some(meta),
                    None,
                    forwarding,
                );
                false
            }
        };
        return accepted;
    }
    // #1873 R-C (blanket gate, plan v4): a tunnel-marked inner packet
    // is NEVER enqueued to the kernel slow-path TUN. Reinjection hands
    // the UNENCAPSULATED inner packet to the kernel FIB; whenever the
    // kernel's view diverges from the userspace FIB (tunnel removed,
    // admin-down with the route withdrawn, VRF-table divergence) the
    // kernel default-routes it — a plaintext leak (AGY plan r1/r3,
    // verified). The gate is unconditional: the supposed WG cold-path
    // benefit of reinjection is illusory (wg_control's TUN-read encap
    // hits the same EncapError::NoSession and drops, and the worker
    // already armed the handshake before the build returned None —
    // frame/wg.rs), and GRE outer-neighbor cold start is recovered by
    // the #1769 prober + retransmission. The local_tunnel_deliveries
    // branch above stays open: that is GRE local-origin INBOUND
    // delivery keyed by local_ifindex, never the generic TUN.
    if decision.resolution.tunnel_endpoint_id != 0 {
        live.tunnel_encap_unresolved_drops
            .fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "tunnel_encap_unresolved",
            frame.len() as u32,
            Some(meta),
            None,
            forwarding,
        );
        return false;
    }
    let selected_path = slow_path.cloned();
    let Some(slow_path) = selected_path else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_unavailable",
            frame.len() as u32,
            Some(meta),
            None,
            forwarding,
        );
        return false;
    };
    // #9637/#10391 operator narrowing: the outlet is structural. Trusted
    // uses xpf-usp0; adjudicated and delegated share xpf-usp1 but queue zero
    // alone receives the exact fence mark from the TC classifier.
    let enqueue_outcome = match outlet {
        SlowPathOutlet::Trusted => slow_path.enqueue(packet),
        SlowPathOutlet::Adjudicated => slow_path.enqueue_adjudicated(packet),
        SlowPathOutlet::Delegated => slow_path.enqueue_delegated(packet),
    };
    let accepted = match enqueue_outcome {
        Ok(EnqueueOutcome::Accepted) => {
            live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
            true
        }
        Ok(EnqueueOutcome::RateLimited) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
            // #6101: `reason` + a `'static` suffix — recorded alloc-free
            // (no per-event `format!`) so a reinject-failure flood cannot
            // allocate a `String` per event. The operator-visible reason is
            // reconstructed as `"{reason}_rate_limited"` on the status thread.
            record_exception_suffixed(
                recent_exceptions,
                binding,
                reason,
                "_rate_limited",
                frame.len() as u32,
                Some(meta),
                None,
            );
            false
        }
        Ok(EnqueueOutcome::QueueFull) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception_suffixed(
                recent_exceptions,
                binding,
                reason,
                "_queue_full",
                frame.len() as u32,
                Some(meta),
                None,
            );
            false
        }
        // #2471: the slow path is degraded (MTU programming failed); the live
        // TUN is at 1500 and this frame is jumbo. Refused at enqueue with a
        // counted exception rather than being silently dropped by the kernel.
        Ok(EnqueueOutcome::MtuExceeded) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception_suffixed(
                recent_exceptions,
                binding,
                reason,
                "_slow_path_mtu_exceeded",
                frame.len() as u32,
                Some(meta),
                None,
            );
            false
        }
        Err(err) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.set_error(err);
            record_exception_suffixed(
                recent_exceptions,
                binding,
                reason,
                "_enqueue_failed",
                frame.len() as u32,
                Some(meta),
                None,
            );
            false
        }
    };
    accepted
}

#[allow(dead_code)]
pub(in crate::afxdp::tx) fn extract_l3_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    extract_l3_packet_from_frame(frame, meta)
}

pub(in crate::afxdp::tx) fn extract_l3_packet_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

pub(in crate::afxdp) fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    // #1852: non-first-fragment predicate, computed once and threaded.
    let non_first_fragment = is_non_first_fragment(&packet, meta.addr_family);
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat, non_first_fragment)?,
        libc::AF_INET6 => {
            // Ext-aware L4 offset via the shared helper (#1838).
            let rel_l4 =
                v6_rel_l4_offset(&packet, meta.l3_offset, meta.l4_offset, meta.addr_family)?;
            apply_nat_ipv6(&mut packet, rel_l4, meta.protocol, nat, non_first_fragment)?
        }
        _ => return None,
    }
    Some(packet)
}
