// Hot-path inner loop extracted from afxdp.rs (#1054). The body is
// byte-for-byte identical to its previous location; this PR only
// changes the enclosing module so afxdp.rs drops below the
// modularity-discipline LOC threshold. `use super::*;` brings every
// type, constant, and helper from afxdp.rs into scope, including
// the sibling submodules (parser, rst, sharded_neighbor, etc.)
// that the extracted fn references.
//
// #1327 Step 1 (Phase 1.5 follow-up to #946): converted from flat
// poll_descriptor.rs to a directory module. The flow-cache fast path
// extraction (`flow_cache_hit::stage_flow_cache_hit`) and the
// per-descriptor RX telemetry helper (`rx_telemetry::record_rx_descriptor_telemetry`)
// live as sibling modules. The post-flow-cache slow path (stages 12+)
// stays inline — see docs/pr/1327-poll-descriptor-stages/plan.md for
// the architectural verdict that further extraction is blocked by
// mutable-locals coupling.
//
// #6433: the flow-cache SEED (write) path joined the read half —
// `flow_cache_seed::stage_flow_cache_seed` carries the #1861 §5.4
// refused-install gate, the #3048/#3918/#5147 pre-resolve shard-epoch
// stamp, and the #3073/#3322 policy-counter stamps, colocated with
// `flow_cache_hit` so the cache's eviction invariants review as one
// contract. Pure code-motion (`#[inline]`, disjoint `&mut
// binding.flow.flow_cache` field borrow — the #1327 split-borrow
// discipline); the order-coupled slow-path arms stay inline.
//
// #4404 increment 1: the cold-path `debug-log` throttle predicates
// (`debug_log_throttle::{session_miss,policy_deny}_debug_log_allowed`,
// their #4120 caps, and the `debug_log_throttle_tests` pinned-contract
// tests) moved out to the `debug_log_throttle` sibling — a pure,
// dependency-free code-motion. Further decomposition of the
// `poll_binding_process_descriptor` god-function (the session-hit /
// session-miss / flowless arms it fuses) is tracked on #4404 and needs
// /triple-review because it touches the single-recycle and CoS
// guarantee-guard invariants.

mod cookie_reply;
mod debug_log_throttle;
mod embedded_icmp;
mod filter;
mod flow_cache_hit;
mod flow_cache_seed;
mod flowless_verdict;
pub(in crate::afxdp) mod frag_assoc;
mod host_inbound_policy;
mod nat64_icmp_error;
mod nat_exception;
mod prerouting_scope;
pub(in crate::afxdp) mod reject_reply;
mod resolver_enqueue;
mod rx_telemetry;
mod session_admission;

use debug_log_throttle::{policy_deny_debug_log_allowed, session_miss_debug_log_allowed};
use embedded_icmp::{EmbeddedIcmpReversal, try_reverse_embedded_icmp_error};
use flow_cache_hit::{FlowCacheOutcome, stage_flow_cache_hit};
use flow_cache_seed::stage_flow_cache_seed;
use frag_assoc::{
    flowless_fragment_requires_nat_translation, frag_ingress_authority,
    nat64_consult_forward_fragment_assoc,
    nat64_install_forward_fragment_assoc, nat_consult_forward_fragment_assoc,
    nat_install_forward_fragment_assoc,
};
use flowless_verdict::{
    FlowlessLocalVerdict, flowless_base_resolution, flowless_local_delivery_verdict,
    ipv6_ext_header_over_limit_drop,
};
use host_inbound_policy::{
    JunosHostLocalPolicy, emit_host_inbound_deny, junos_host_local_policy, policy_packet_icmp,
};
use nat64_icmp_error::try_translate_nat64_icmp_error;
use rx_telemetry::record_rx_descriptor_telemetry;
use session_admission::{new_flow_session_limit_drop, strict_syn_check_drops_new_flow};

use super::poll_stages::{
    FabricIngressOutcome, IpsecPassthroughOutcome, ScreenCheckOutcome, StageOutcome,
    SynCookieAckOutcome, stage_classify_fabric_ingress, stage_ipsec_passthrough_check,
    stage_link_layer_classify, stage_native_gre_decap, stage_parse_flow_and_learn,
    stage_screen_check, stage_screen_syn_cookie_ack_on_session_miss,
};
use super::*;
use crate::policy::evaluate_policy_result_with_icmp;

use cookie_reply::{SynCookieReply, enqueue_syn_cookie_reply};
use nat_exception::{record_source_nat_failure, source_nat_decision_for_flow};
use prerouting_scope::{PreroutingIngressScope, prerouting_ingress_scope};
use reject_reply::{deny_reply_and_emit, enqueue_filter_reject_reply};
use resolver_enqueue::try_enqueue_resolver;

use filter::{
    emit_input_filter_log_match,
    evaluate_dscp_sensitive_input_filter_on_session_hit, evaluate_non_pbr_input_filter,
    evaluate_non_pbr_input_filter_counters_cached, evaluate_non_pbr_input_filter_log_only,
    filter_terminal, host_inbound_gated_lo0_action,
};

// Per-batch packet processing lifted from `poll_binding` (#678).
//
// Runs `binding.xsk.rx.receive(available)` + the descriptor while-let +
// `received.release(); drop(received);` as its own compilation unit so
// it surfaces under its own symbol in `perf top`.
//
// #946 Phase 1 (commit ea8fa4e6) extracted seven per-packet
// sub-stages out of the while-let body into named helpers in
// `afxdp/poll_stages.rs`. The helpers are all `#[inline]` so the
// extracted bodies stay in the caller's CGU and the call/return
// overhead is amortized to zero — the refactor is pure
// code-motion at the IR level (modulo what rustc's inliner picks
// up; the explicit hint matches other hot-path extractions in
// this repo).
//
// `area` raw-pointer contract (#1826, applies to every
// `unsafe { &*area }` reborrow in this function): the caller
// (worker/lifecycle.rs `process_binding_rx`) casts `area` from a
// `&MmapArea` borrowed out of `binding.umem`'s `Rc<WorkerUmemInner>`
// allocation. The pointee outlives this call — nothing on the poll
// path drops or replaces `binding.umem`, and the only
// `&mut WorkerUmemInner` escape hatch (`WorkerUmem::umem_mut` via
// `Rc::get_mut`) runs solely at bind time, never while a worker is
// polling — so each shared reborrow is valid and cannot alias a
// mutable reference. The raw pointer only decouples the immutable
// UMEM-area borrow from the `&mut BindingWorker` borrow.
#[allow(clippy::too_many_arguments)]
pub(super) fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    // #6211 F2: no longer inert. The packet-path rollbacks and the synced-hit
    // purge below release allocator reservations that a peer-synced session
    // holds on EVERY worker, so each must drop only THIS worker's holder bit.
    //
    // #6522: it is also the holder RECORDED when this worker's packet path
    // ALLOCATES a pool source-NAT / NAT64 translation. The resulting session is
    // replicated to every sibling worker, each of which reserves against the
    // same allocator record, so an allocation that does not name its own owner
    // ends up with a holder mask covering every worker EXCEPT the one
    // forwarding.
    worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) {
    let mut received = binding.xsk.rx.receive(available);
    binding.scratch.scratch_recycle.clear();
    binding.scratch.scratch_forwards.clear();
    binding.scratch.scratch_rst_teardowns.clear();
    while let Some(desc) = received.read() {
        record_rx_descriptor_telemetry(desc, area, telemetry, worker_ctx);
        let mut recycle_now = true;
        // SAFETY: per the `area` contract in this function's header
        // comment — pointee outlives the call, never aliased mutably.
        if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
            telemetry.counters.metadata_packets += 1;
            let disposition = classify_metadata(meta, validation);
            if disposition == PacketDisposition::Valid {
                telemetry.counters.validated_packets += 1;
                telemetry.counters.validated_bytes += desc.len as u64;
                // SAFETY: per the `area` contract in this function's
                // header comment.
                let Some(raw_frame) =
                    unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                else {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                };
                // #946 Phase 1 stage 5: ARP / NDP link-layer
                // classification. ARP frames recycle without
                // transiting; NDP NA learns and falls through.
                if let StageOutcome::RecycleAndContinue = stage_link_layer_classify(
                    raw_frame,
                    meta,
                    now_ns,
                    &mut binding.neigh_program_limiter,
                    worker_ctx,
                ) {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                }
                // #946 Phase 1 stage 6: native GRE decap. Caller
                // binds the active slice locally; helper does NOT
                // return the slice (would be self-referential).
                // `owned_packet_frame` MUST be `mut` — deferred
                // stage-12+ code at lines below calls `.take()`.
                let (mut meta, mut owned_packet_frame) =
                    stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
                let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                // #946 Phase 1 stage 7+8: parse session flow and
                // learn the source-side dynamic neighbor.
                // `learn_from_live_frame` MUST be
                // `owned_packet_frame.is_none()` — preserves the
                // GRE guard at the original line 113 (neighbor
                // learning uses the live UMEM Ethernet frame so
                // the source MAC is the outer host's, not the
                // GRE tunnel egress).
                let flow = stage_parse_flow_and_learn(
                    // SAFETY: per the `area` contract in this
                    // function's header comment.
                    unsafe { &*area },
                    desc,
                    packet_frame,
                    meta,
                    owned_packet_frame.is_none(),
                    &mut binding.last_learned_neighbor,
                    worker_ctx,
                );
                // #4743: fail-closed drop for an OVER-LIMIT IPv6 extension-header
                // chain. `stage_parse_flow_and_learn` returns `None` (flowless)
                // when the #2292 helper walkers give up past
                // MAX_IPV6_EXT_HEADERS; the flowless path would otherwise forward
                // the packet uninspectable (`l4_present = false`) — an ext-header
                // IDS-evasion. Gate on `flow.is_none()` (helper could not derive
                // an L4 tuple) and drop+count ONLY the genuine over-limit chain;
                // a non-first fragment / ICMPv6 / truncated packet is not
                // over-limit and keeps its existing flowless handling.
                if flow.is_none()
                    && ipv6_ext_header_over_limit_drop(
                        packet_frame,
                        meta.addr_family,
                        &mut *telemetry.counters,
                    )
                {
                    binding.scratch.scratch_recycle.push(desc.addr);
                    continue;
                }
                // #946 Phase 1 stage 9: fabric-ingress
                // classification. Mutates meta.meta_flags. MUST
                // run before screen/IPsec/flow-cache because they
                // read meta.meta_flags downstream.
                let FabricIngressOutcome {
                    ingress_zone_override,
                    packet_fabric_ingress,
                } = stage_classify_fabric_ingress(packet_frame, &mut meta, now_secs, worker_ctx);
                // #946 Phase 1 stage 10: screen / IDS slow-path.
                // Caller still owns the recycle push (matches
                // original code's pattern).
                match stage_screen_check(
                    flow.as_ref(),
                    packet_frame,
                    meta,
                    ingress_zone_override,
                    now_ns,
                    now_secs,
                    screen,
                    telemetry.counters,
                    worker_ctx,
                ) {
                    StageOutcome::RecycleAndContinue => {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    StageOutcome::Continue(ScreenCheckOutcome::Pass) => {}
                    StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge)) => {
                        enqueue_syn_cookie_reply(
                            &mut binding.tx_pipeline,
                            worker_ctx.forwarding,
                            binding.ifindex,
                            packet_frame,
                            meta,
                            flow.as_ref(),
                            SynCookieReply::SynAck(challenge),
                            telemetry.counters,
                        );
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                }
                // #946 Phase 1 stage 11: IPsec passthrough. ESP
                // (proto 50), AH and the IPsec data plane reinject via
                // the slow-path TUN; recycle the UMEM frame. #4323: a NEW
                // inbound IKE initiation the ingress zone's host-inbound
                // set does not permit is denied here (silent drop) before
                // it can reach the local IKE daemon. #6471: a
                // Responder-SPI-nonzero IKE packet matching NO seeded live
                // exchange faces the same gate — a forged Responder SPI no
                // longer rides the established exemption on a closed zone.
                match stage_ipsec_passthrough_check(
                    flow.as_ref(),
                    packet_frame,
                    meta,
                    ingress_zone_override,
                    &binding.live,
                    worker_ctx,
                    now_ns,
                    now_secs,
                ) {
                    IpsecPassthroughOutcome::NotClaimed => {}
                    IpsecPassthroughOutcome::Passthrough => {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    IpsecPassthroughOutcome::Denied { from_zone_id } => {
                        // #4323/#6471: IKE denied by the ingress zone's
                        // host-inbound set (a NEW initiation, or a
                        // Responder-SPI-nonzero packet with no live-exchange
                        // seed). Emit the tuple-rich deny event and account
                        // the drop (GlobalCtrHostInboundDeny), then recycle
                        // the frame — a silent drop, never a reject.
                        if let Some(flow) = flow.as_ref() {
                            emit_host_inbound_deny(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                flow,
                                meta,
                                from_zone_id,
                                now_ns,
                            );
                        }
                        telemetry.counters.host_inbound_denied_packets += 1;
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                }
                // ── Flow cache fast path (#1327 Step 1) ────────────────
                // Extracted to poll_descriptor/flow_cache_hit.rs. The
                // helper owns ALL recycle/forward pushes on Consumed;
                // caller MUST `continue` without touching desc.addr.
                // The original L477 `packet_frame` binding's NLL
                // lifetime ends at the previous line (last use was
                // inside stage_ipsec_passthrough_check); it is rebound
                // below the helper call for the slow-path code.
                if FlowCacheEntry::packet_eligible(meta)
                    && let Some(flow) = flow.as_ref()
                {
                    match stage_flow_cache_hit(
                        &mut binding.flow,
                        &mut binding.tx_pipeline,
                        &mut binding.tx_counters,
                        &mut binding.scratch,
                        &mut binding.mirror_sample_counter,
                        &binding.live,
                        binding.slot,
                        binding_index,
                        desc,
                        area,
                        raw_frame,
                        &mut owned_packet_frame,
                        meta,
                        flow,
                        packet_fabric_ingress,
                        validation,
                        sessions,
                        now_ns,
                        now_secs,
                        worker_ctx,
                        telemetry,
                    ) {
                        FlowCacheOutcome::Consumed => continue,
                        FlowCacheOutcome::FallThrough => {}
                    }
                }
                // Re-bind packet_frame for slow-path code below
                // (original L477 binding's NLL lifetime ended before
                // the helper call above).
                let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                // ── End flow cache fast path ─────────────────────────
                let mut debug = flow
                    .as_ref()
                    .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
                let mut session_ingress_zone: Option<u16> = None;
                // #5606: the matched session's NAT64 reverse info (original v6
                // src/dst), carried out of the session-hit resolve scope so the
                // live forward request built below can thread it onto
                // `PendingForwardRequest.nat64_reverse`. The reverse (v4->v6)
                // reply of a NAT64 flow hits the pre-installed reverse companion
                // session whose metadata carries this; without threading it, the
                // TX dispatcher's `build_nat64_forwarded_frame` AF_INET branch
                // hard-requires `request.nat64_reverse` and returns None (the
                // reply is dropped / an ICMP error cannot be translated). `None`
                // for every non-NAT64 flow, so the common path stays untouched.
                let mut session_nat64_reverse: Option<Nat64ReverseInfo> = None;
                let mut flow_cache_owner_rg_id = 0i32;
                // #3073: the admitting policy rule's 1-based hit-counter handle
                // for this flow (0 = none). Set from the resolved session
                // metadata (hit) or the install metadata (miss) below, then
                // stamped onto the flow-cache entry so its hit path re-counts
                // every cached packet against the same policy.
                let mut flow_cache_policy_counter_idx: u32 = 0;
                // #3322: the reorder-stable BOUND hit-counter handle for this
                // flow, carried alongside the positional idx and stamped onto
                // the flow-cache entry so its hit path counts against the same
                // rule the session was admitted under even after a live policy
                // reorder renumbers the rule table.
                let mut flow_cache_policy_counter: Option<
                    std::sync::Arc<crate::policy::PolicyRuleCounter>,
                > = None;
                let mut apply_nat_on_fabric = false;
                // #1861 §5.4: true when a session install was attempted
                // for this packet's decision and refused (max_sessions).
                // Gates the flow-cache population below — caching a
                // sessionless decision would suppress the per-packet
                // reply repair (and, on the new-flow path, persist a
                // rolled-back SNAT tuple) until cache invalidation.
                let mut flow_cache_install_failed = false;
                // #2218: the matched pre-routing DNAT/static-DNAT rule's
                // per-rule hit counter, hoisted to the outer (post-resolution)
                // scope so BOTH the inner miss-block install sites (LocalMiss,
                // ForwardCandidate) and the later MissingNeighbor seed path
                // can increment it once on a committed translated flow. Set
                // inside the session-miss block below; stays None on a
                // session hit (the established fast path applies no new
                // translation, so it is never counted again).
                let mut pre_routing_dnat_counter: Option<
                    std::sync::Arc<crate::nat::NatRuleCounter>,
                > = None;
                // #3918/#5147: snapshot EVERY shard's neighbor-MAC-change
                // epoch BEFORE the neighbor MAC that backs this packet's
                // forwarding decision is resolved. `resolve_flow_session_
                // decision` (session-hit resolve) and the session-miss
                // `finalize_new_flow_ha_resolution` below both consult
                // `dynamic_neighbors`; the flow-cache entry built further down
                // stamps the resolved shard's PRE-RESOLVE snapshot value
                // (extracted just before `from_forward_decision`). The resolved
                // shard is not known until after the resolve, so the whole
                // vector is snapshotted first. Reading pre-resolve — not a
                // fresh post-resolve shard read at stamp time — closes a TOCTOU
                // that re-opened the #3048 stale-MAC blackhole: a kernel
                // ARP/NDP update (a VRRP gateway failover changing the gateway
                // MAC) landing between the resolve and the stamp would, on a
                // post-resolve read, stamp the NEW shard epoch onto the cached
                // OLD dst_mac — a fresh-looking stale entry that survives every
                // fast-path hit until it ages out (blackhole). Snapshotting
                // first guarantees the stamped shard epoch <= the shard epoch
                // observed at resolve time, so a subsequent MAC-change bump
                // makes the entry stale on its next hit -> evicted -> re-
                // resolved to the new MAC. Mirrors the #2170/#3912
                // record-before-use discipline. Relaxed loads suffice: this
                // snapshot and the stamp run on this one worker thread (program
                // order sequences the snapshot before the resolve), and the
                // neighbor shard Mutex — not these counters — synchronizes the
                // MAC bytes; the epochs are monotonic invalidation signals that
                // only need eventual cross-thread visibility. NUM_SHARDS relaxed
                // loads, on this cold cache-miss/resolve path only.
                let neighbor_epoch_snapshot = worker_ctx.dynamic_neighbors.snapshot_shard_epochs();
                let mut decision = if let Some(flow) = flow.as_ref() {
                    if let Some(resolved) = resolve_flow_session_decision(
                        sessions,
                        binding.bpf_maps.session_map_fd,
                        worker_ctx.shared_sessions,
                        worker_ctx.shared_nat_sessions,
                        worker_ctx.shared_forward_wire_sessions,
                        &worker_ctx.shared_owner_rg_indexes,
                        worker_ctx.peer_worker_commands,
                        worker_ctx.forwarding,
                        worker_ctx.ha_state,
                        worker_ctx.dynamic_neighbors,
                        flow,
                        now_ns,
                        now_secs,
                        meta.protocol,
                        meta.tcp_flags,
                        meta.ingress_ifindex as i32,
                        packet_fabric_ingress,
                        ha_startup_grace_until_secs,
                        worker_id,
                    ) {
                        telemetry.counters.session_hits += 1;
                        telemetry.dbg.session_hit += 1;
                        // #3073: re-count this established-session packet against
                        // the admitting policy's hit counter. The cold path
                        // counts the first packet in `try_match_rule`; this
                        // covers every subsequent packet that hits the session
                        // (and reply traffic on the reverse companion), so
                        // `show security policies hit-count` reflects the real
                        // load the rule carries — not just the first frame.
                        // `resolve_flow_session_decision` never runs policy
                        // evaluation, so a packet reaching here was never counted
                        // by the cold path: exactly-once holds. The per-worker
                        // coalescer keeps this off the shared counter cacheline.
                        // #3322: prefer the session's reorder-stable bound
                        // handle over the positional idx so a live policy
                        // reorder cannot re-attribute this established flow's
                        // packets to a different rule.
                        //
                        // #3706: EXCEPT on the LocalDelivery (host-bound) path.
                        // A host-local session re-evaluates the `to-zone
                        // junos-host` policy on EVERY hit (the mandatory teardown
                        // re-check below), and that re-eval's `try_match_rule`
                        // already counts this packet against the admitting rule's
                        // hit counter — exactly as it did pre-#3706, when a
                        // host-local session carried no bound counter and this
                        // line was a no-op (`resolve_session_hit_counter(None, 0)`
                        // -> None). Now that a junos-host permit stamps a bound
                        // counter (#3706), counting HERE too would double-count
                        // every established host-local permit packet. Transit has
                        // no per-hit policy re-eval, so it counts solely here.
                        // Gate on disposition so the count fires exactly once on
                        // both paths (parity with transit) while the #3706 permit
                        // attribution — policy_id / log flags / the bound counter
                        // handle used for close-time re-resolution + HA sync —
                        // stays stamped on the session.
                        //
                        // #5445: the bound hit-counter Arc is NO LONGER carried
                        // on the per-packet established-hit `SessionLookup`
                        // (cloning it there bumped the shared `Arc` refcount —
                        // a `LOCK XADD` — on every established-session lookup,
                        // the #919 hot-path atomic). Re-source it once here:
                        // prefer the value the resolve threaded (the session-
                        // MISS / forward-wire paths still carry it, an owner
                        // handoff), else BORROW-and-clone it from THIS worker's
                        // own session-table entry (the established-hit path,
                        // whose lookup return is now counter-stripped). Both
                        // sources are contention-free (owned local metadata /
                        // per-worker table). `None` (idx-0 / peer-synced
                        // transient not in the local table) falls back to the
                        // positional `policy_counter_idx`, exactly as
                        // `resolve_session_hit_counter(None, idx)` did before.
                        // The single clone here replaces the two prior per-
                        // packet Arc clones (the lookup return + the flow-cache
                        // stamp), and hands ownership straight to the flow-cache
                        // entry below.
                        let bound_policy_counter = match resolved
                            .metadata
                            .policy_counter
                            .clone()
                        {
                            some @ Some(_) => some,
                            None => sessions
                                .bound_policy_counter_for(&flow.forward_key)
                                .cloned(),
                        };
                        if resolved.decision.resolution.disposition
                            != ForwardingDisposition::LocalDelivery
                        {
                            if let Some(counter) =
                                worker_ctx.forwarding.policy.resolve_session_hit_counter(
                                    bound_policy_counter.as_ref(),
                                    resolved.metadata.policy_counter_idx,
                                )
                            {
                                crate::policy::record_policy_hit_counter(counter, desc.len as u64);
                            }
                        }
                        flow_cache_install_failed = resolved.install_failed;
                        if resolved.created {
                            telemetry.counters.session_creates += 1;
                            telemetry.dbg.session_create += 1;
                            // Mirror new session to BPF conntrack map for
                            // `show security flow session` zone/interface display.
                            // #2008 M5: resolve the application id from the
                            // 5-tuple so the conntrack entry carries app_id.
                            // #3321: resolve directionally — the service port
                            // is the dst on a forward-keyed session, the src on
                            // a reverse-keyed one, so a forward flow with a
                            // service-valued SOURCE port is not mislabeled.
                            // #3416: resolve the forward service port from the
                            // post-translation (DNAT-rewritten) destination so a
                            // port-forwarded session's conntrack row carries the
                            // admitting application, not the pre-NAT public port.
                            let app_id = worker_ctx.forwarding.app_catalog.lookup_admitted(
                                flow.forward_key.protocol,
                                flow.forward_key.src_port,
                                flow.forward_key.dst_port,
                                resolved.metadata.is_reverse,
                                resolved.decision.nat.rewrite_dst_port,
                            );
                            // #5213: mirror the STABLE session id from the just-
                            // installed table entry so `show security flow
                            // session` reports the SAME id RT_FLOW emits.
                            let session_id = sessions.session_id_for(&flow.forward_key);
                            publish_bpf_conntrack_entry(
                                conntrack_v4_fd,
                                conntrack_v6_fd,
                                &flow.forward_key,
                                resolved.decision,
                                &resolved.metadata,
                                &worker_ctx.forwarding.zone_name_to_id,
                                worker_ctx.forwarding.alg_disable_flags,
                                app_id,
                                session_id,
                            );
                        }
                        // Log first N session hits from WAN (return path)
                        if cfg!(feature = "debug-log")
                            && meta.ingress_ifindex == 6
                            && telemetry.dbg.wan_return_hits < 5
                        {
                            telemetry.dbg.wan_return_hits += 1;
                            debug_log!(
                                "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                telemetry.dbg.wan_return_hits,
                                flow.src_ip,
                                flow.forward_key.src_port,
                                flow.dst_ip,
                                flow.forward_key.dst_port,
                                meta.protocol,
                                meta.tcp_flags,
                                resolved.decision.nat.rewrite_src,
                                resolved.decision.nat.rewrite_dst,
                                resolved.metadata.is_reverse,
                            );
                        }
                        if let Some(debug) = debug.as_mut() {
                            debug.from_zone = Some(resolved.metadata.ingress_zone);
                            debug.to_zone = Some(resolved.metadata.egress_zone);
                        }
                        session_ingress_zone = Some(resolved.metadata.ingress_zone);
                        // #5606: carry the matched session's NAT64 reverse info
                        // (original v6 src/dst) so the live forward request built
                        // below translates a v4->v6 reply back to IPv6. Set for
                        // the reverse companion of a NAT64 flow; `None` otherwise.
                        session_nat64_reverse = resolved.metadata.nat64_reverse;
                        flow_cache_owner_rg_id = resolved.metadata.owner_rg_id;
                        // #3073: carry the admitting rule's hit-counter handle so
                        // the flow-cache entry populated below re-counts cached
                        // packets against the same policy.
                        flow_cache_policy_counter_idx = resolved.metadata.policy_counter_idx;
                        // #3322: carry the bound handle from the established
                        // session onto the flow-cache entry too.
                        // #5445: hand the already-sourced bound counter to the
                        // flow-cache entry (was `resolved.metadata.policy_counter
                        // .clone()`, a SECOND per-packet Arc clone on top of the
                        // now-removed lookup-return clone). `bound_policy_counter`
                        // above already resolved the same handle exactly once.
                        flow_cache_policy_counter = bound_policy_counter;
                        apply_nat_on_fabric = true;
                        if let Some(input_filter_eval) =
                            evaluate_dscp_sensitive_input_filter_on_session_hit(
                                worker_ctx.forwarding,
                                packet_frame,
                                Some(flow),
                                meta,
                                Some(resolved.metadata.ingress_zone),
                            )
                        {
                            // #2521/#3615: a filter `then reject` synthesizes a
                            // TCP RST / ICMP unreachable back toward the source
                            // (same machinery as policy reject); `discard` stays
                            // a silent drop. Enqueue the reply FIRST so the
                            // `then log` filter-log below reports the TRUTHFUL
                            // action — a reject whose reply fail-closes
                            // (budget/rate/parse/output-filter) logs DENY, not
                            // REJECT.
                            let reject_reply_enqueued = if let crate::filter::FilterAction::Reject(
                                reject_msg,
                            ) = input_filter_eval.action
                            {
                                enqueue_filter_reject_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                    reject_msg,
                                )
                            } else {
                                false
                            };
                            if let Some(cached_log) = input_filter_eval.cached_log {
                                emit_input_filter_log_match(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    flow,
                                    meta,
                                    cached_log,
                                    reject_reply_enqueued,
                                    now_ns,
                                );
                            }
                            if input_filter_eval.action != crate::filter::FilterAction::Accept {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        // #3070 + #3485: on the session-HIT local-delivery path,
                        // the host-inbound-traffic zone gate runs BEFORE the lo0
                        // host-bound filter. Re-checked on every hit (so a
                        // tightened host-inbound set tears down an already
                        // established host-bound session WITHOUT an explicit
                        // purge); the ingress zone is the session metadata's
                        // recorded ingress_zone. A host-inbound DENY is a silent
                        // drop with NO lo0 side-effects (no reject reply, no lo0
                        // counter/log) — before #3485 the lo0 filter ran first, so
                        // a denied service still triggered its reject/RST/teardown/
                        // counter/log (codex-review-118 M1). Only an ADMITTED
                        // packet pays the lo0 evaluation.
                        if resolved.decision.resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                        {
                            // #3609: the per-interface host-inbound override is
                            // keyed by the LOGICAL unit ifindex; resolve the
                            // physical bind port + VLAN to it so a host-bound
                            // packet on a VLAN sub-interface gets its own
                            // override (mirrors the input-filter HIT re-eval).
                            let ingress_logical = resolve_ingress_logical_ifindex(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                            )
                            .unwrap_or(meta.ingress_ifindex as i32);
                            match host_inbound_gated_lo0_action(
                                worker_ctx.forwarding,
                                ingress_logical,
                                resolved.metadata.ingress_zone,
                                resolved.key.dst_port,
                                matches!(flow.dst_ip, IpAddr::V6(_)),
                                // #3171: first L4 byte = ICMP/ICMPv6 type, so an
                                // error/PMTUD control message stays admitted on a
                                // ping-less zone (mirrors the kernel chain). 0
                                // for non-ICMP (ignored by host_inbound_admits).
                                // #5140: read the INNER type via `packet_frame`
                                // (= decapped frame post native-GRE, else
                                // `raw_frame`); `meta.l4_offset` is inner-relative
                                // after `stage_native_gre_decap`, so indexing the
                                // outer `raw_frame` would read the wrong byte and
                                // could admit an ordinary echo as an exempt error.
                                packet_frame
                                    .get(meta.l4_offset as usize)
                                    .copied()
                                    .unwrap_or(0),
                                crate::afxdp::frame::term_match_extra_from_frame(
                                    packet_frame,
                                    meta,
                                ),
                                flow,
                                meta,
                                Some(resolved.metadata.ingress_zone),
                                now_ns,
                            ) {
                                None => {
                                    // Host-inbound denied: silent drop, tear down
                                    // the established host-bound session.
                                    delete_terminal_filtered_session(
                                        sessions,
                                        binding.bpf_maps.session_map_fd,
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        worker_ctx.shared_sessions,
                                        worker_ctx.shared_nat_sessions,
                                        worker_ctx.shared_forward_wire_sessions,
                                        &worker_ctx.shared_owner_rg_indexes,
                                        worker_ctx.peer_worker_commands,
                                        worker_ctx.forwarding,
                                        &resolved.key,
                                        resolved.decision,
                                        &resolved.metadata,
                                        resolved.origin,
                                        now_ns,
                                        worker_id,
                                    );
                                    telemetry.dbg.local += 1;
                                    // #3610/M07: account the host-inbound deny on
                                    // its OWN debug counter, NOT `policy_deny` —
                                    // conflating host-inbound drops with security-
                                    // policy denies sent dataplane investigations
                                    // down the wrong path.
                                    telemetry.dbg.host_inbound_deny += 1;
                                    // #3326: account the host-inbound deny so
                                    // `GlobalCtrHostInboundDeny` (REST/Prometheus/
                                    // `show security flow statistics`) reflects the
                                    // drop. `touched` must be set so the batch is
                                    // flushed into BindingLiveState.
                                    telemetry.counters.touched = true;
                                    telemetry.counters.host_inbound_denied_packets += 1;
                                    // #3610: emit the tuple-rich host-inbound deny
                                    // event so an operator can see WHICH host-bound
                                    // flow was dropped (src/dst/proto/port + zone +
                                    // ingress ifindex), not just an aggregate
                                    // counter. Reuses the #3615 policy-deny event
                                    // machinery with a distinct host-inbound reason.
                                    emit_host_inbound_deny(
                                        worker_ctx.forwarding,
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        resolved.metadata.ingress_zone,
                                        now_ns,
                                    );
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                                // #2521/#3615: a lo0 `then reject` synthesizes a
                                // TCP RST / ICMP unreachable; `filter_terminal`
                                // enqueues the reply FIRST then emits the lo0
                                // filter-log with the TRUTHFUL action (a
                                // suppressed reject logs DENY, not REJECT), and
                                // returns true iff the packet must be dropped
                                // (discard/reject). An accepted flow with a lo0
                                // `then log` term still emits and falls through.
                                Some((lo0_action, lo0_log)) => {
                                    if filter_terminal(
                                        &mut binding.tx_pipeline,
                                        worker_ctx.forwarding,
                                        worker_ctx.event_stream,
                                        binding.ifindex,
                                        packet_frame,
                                        meta,
                                        flow,
                                        telemetry.counters,
                                        lo0_action,
                                        lo0_log,
                                        now_ns,
                                    ) {
                                        delete_terminal_filtered_session(
                                            sessions,
                                            binding.bpf_maps.session_map_fd,
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            worker_ctx.peer_worker_commands,
                                            worker_ctx.forwarding,
                                            &resolved.key,
                                            resolved.decision,
                                            &resolved.metadata,
                                            resolved.origin,
                                            now_ns,
                                            worker_id,
                                        );
                                        telemetry.dbg.local += 1;
                                        telemetry.dbg.policy_deny += 1;
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                }
                            }
                        }
                        // #3019: `to-zone junos-host` security policy on the
                        // session-HIT local-delivery path, mirroring the #3070
                        // host-inbound re-check above: re-evaluated on every hit
                        // so a tightened junos-host deny tears down an already
                        // established host-bound session WITHOUT an explicit
                        // purge. Runs AFTER host-inbound admission (Junos order).
                        // A matching deny/reject drops + emits the policy-deny
                        // RT_FLOW; permit / no-match continue. No-op unless a
                        // junos-host policy is configured. #3706: the session is
                        // already installed (with the miss-time permit metadata),
                        // so only the DROP verdict matters here — a permit /
                        // no-match leaves the established session untouched.
                        if resolved.decision.resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                            && matches!(
                                junos_host_local_policy(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    &mut binding.tx_pipeline,
                                    binding.ifindex,
                                    packet_frame,
                                    telemetry.counters,
                                    flow,
                                    meta,
                                    resolved.metadata.ingress_zone,
                                    desc.len as u64,
                                    now_ns,
                                ),
                                JunosHostLocalPolicy::Dropped
                            )
                        {
                            delete_terminal_filtered_session(
                                sessions,
                                binding.bpf_maps.session_map_fd,
                                conntrack_v4_fd,
                                conntrack_v6_fd,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                &worker_ctx.shared_owner_rg_indexes,
                                worker_ctx.peer_worker_commands,
                                worker_ctx.forwarding,
                                &resolved.key,
                                resolved.decision,
                                &resolved.metadata,
                                resolved.origin,
                                now_ns,
                                worker_id,
                            );
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // TTL/hop-limit check on session-hit path: generate
                        // ICMP Time Exceeded for packets that would expire
                        // after decrement. The session-miss path handles this
                        // in build_local_time_exceeded_request(); the session-
                        // hit path previously silently dropped these packets
                        // (the rewrite functions return None for TTL<=1).
                        if matches!(
                            resolved.decision.resolution.disposition,
                            ForwardingDisposition::ForwardCandidate
                        ) {
                            // #5140: read the INNER packet via `packet_frame`
                            // (decapped frame post native-GRE, else `raw_frame`).
                            // The TTL/hop-limit test + the embedded original in
                            // the generated Time Exceeded are keyed on the
                            // inner-relative `meta` offsets; `desc` is carried
                            // only to recycle the outer UMEM slot (the reply is a
                            // freshly built prebuilt frame).
                            let local_icmp_te = build_local_time_exceeded_request(
                                packet_frame,
                                desc,
                                meta,
                                &worker_ctx.ident,
                                flow,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                                worker_ctx.ha_state,
                                now_secs,
                                telemetry.counters,
                            );
                            if let Some(request) = local_icmp_te {
                                binding.scratch.scratch_forwards.push(request);
                                // Don't recycle: the TE response references
                                // the original frame via desc.addr on the request.
                                // The continue skips recycle_now handling.
                                continue;
                            }
                        }
                        resolved.decision
                    } else {
                        telemetry.counters.session_misses += 1;
                        telemetry.dbg.session_miss += 1;
                        match stage_screen_syn_cookie_ack_on_session_miss(
                            Some(flow),
                            packet_frame,
                            meta,
                            ingress_zone_override,
                            now_ns,
                            now_secs,
                            screen,
                            telemetry.counters,
                            worker_ctx,
                        ) {
                            StageOutcome::RecycleAndContinue => {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            StageOutcome::Continue(SynCookieAckOutcome::Pass) => {}
                            StageOutcome::Continue(SynCookieAckOutcome::Validated) => {
                                enqueue_syn_cookie_reply(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    Some(flow),
                                    SynCookieReply::AckRst,
                                    telemetry.counters,
                                );
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        let resolution_target =
                            parse_packet_destination_from_frame(packet_frame, meta)
                                .unwrap_or(flow.dst_ip);
                        // #6478: the cluster-peer return fast path was REMOVED.
                        // It fast-pathed session-less fabric-ingress TCP
                        // SYN-ACK / ACK / ICMP echo-reply forms into a NAT-less
                        // `SessionOrigin::ReverseFlow` seed gated only on the
                        // forgeable zone-encoded stamp — after #6458's stamp
                        // validation a forged frame can still pass V1 on any
                        // node whose claimed zone's RG is remote, so the seed
                        // stayed forgeable. Session-less fabric-ingress
                        // packets now take the normal miss path below: policy
                        // under the #6458-validated zone, NAT applied, a
                        // FORWARD session when permitted (the Junos
                        // no-syn-check asymmetric pickup, #3152). The sync-race
                        // sub-window the fast path covered (a peer-punted
                        // return packet arriving before its synced session)
                        // reverts to a bounded drop, which the #6478 verifier
                        // explicitly prefers over unauthenticated seeding; a
                        // genuine established flow's return is still served by
                        // the synced session in `resolve_flow_session_decision`
                        // before this point.

                        // --- DNAT pre-routing ---
                        // #6473: Junos evaluates static NAT BEFORE
                        // destination NAT (Junos NAT overview, first-packet
                        // order: static NAT → destination NAT → route →
                        // policy → reverse static → source NAT; "static NAT
                        // rules take precedence over destination NAT
                        // rules"). The pre-#6473 code checked the DNAT pool
                        // table first and only fell back to static-DNAT on
                        // a miss, so an external address covered by BOTH a
                        // static rule and a DNAT pool rule took the pool
                        // translation and the static mapping was silently
                        // shadowed (policy is written for the static
                        // tuple). The outbound direction already evaluates
                        // static SNAT first (source_nat_decision_for_flow
                        // in nat_exception.rs); this aligns the inbound
                        // direction with Junos and with the outbound order.
                        // Behavior change: on an overlapping static+pool
                        // config the static mapping now wins, and the
                        // static rule's hit counter advances instead of the
                        // pool rule's. The translated destination affects
                        // FIB lookup.
                        //
                        // #5802: derive the pre-routing DNAT/static-NAT/NPTv6
                        // scope identity from the LOGICAL VLAN unit that received
                        // the frame, NOT the physical bind `meta.ingress_ifindex`.
                        // `prerouting_ingress_scope` resolves the logical unit
                        // ifindex (the same identity the later zone-policy /
                        // filter / CoS path uses, #3021) and reads the zone /
                        // config-name / routing-instance the scoped `from zone` /
                        // `from interface` / `from routing-instance` matches
                        // against. Scoping on the physical parent let a packet on
                        // one VLAN unit match another unit's scoped NAT rule (or
                        // miss its own) on a trunk whose units sit in distinct
                        // zones / interfaces / routing-instances — a NAT
                        // scope-escape. Non-VLAN ports resolve logical == physical
                        // so their behavior is byte-identical. `logical_ifindex`
                        // is threaded into the zone-pair policy below so both
                        // sites share ONE logical-unit ingress identity.
                        let PreroutingIngressScope {
                            logical_ifindex: ingress_logical,
                            zone_name: ingress_zone_name,
                            ifname: ingress_ifname_dnat,
                            routing_instance: ingress_ri_dnat,
                        } = prerouting_ingress_scope(
                            worker_ctx.forwarding,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                            ingress_zone_override,
                        );
                        // #3437: the DNAT `match application` term may pin a
                        // source-port (H10) and an ICMP type/code (H11). Supply
                        // the flow's source port and the packet's ICMP
                        // (type, code) so an application-scoped DNAT only fires
                        // for the source-port / ICMP message it intends; a
                        // non-ICMP packet yields None and never satisfies an
                        // ICMP-type-constrained entry (fail closed).
                        let dnat_packet_icmp = policy_packet_icmp(packet_frame, meta);
                        // #6473 (Junos order): static DNAT first.
                        let static_dnat_decision = worker_ctx
                            .forwarding
                            .static_nat
                            .match_dnat_with_counter_scoped(
                                resolution_target,
                                flow.forward_key.dst_port,
                                // #3435: gate the inbound static DNAT on the
                                // packet SOURCE against `match source-address`.
                                Some(flow.forward_key.src_ip),
                                ingress_zone_name,
                                ingress_ifname_dnat,
                                ingress_ri_dnat,
                            );
                        let dnat_decision = if static_dnat_decision.is_none()
                            && !worker_ctx.forwarding.dnat_table.is_empty()
                        {
                            worker_ctx.forwarding.dnat_table.lookup_with_counter_scoped(
                                meta.protocol,
                                flow.forward_key.src_ip,
                                resolution_target,
                                flow.forward_key.src_port,
                                flow.forward_key.dst_port,
                                ingress_zone_name,
                                ingress_ifname_dnat,
                                ingress_ri_dnat,
                                dnat_packet_icmp,
                            )
                        } else {
                            None
                        };
                        // #2218: DNAT/static-DNAT now yields
                        // (NatDecision, Option<Arc<NatRuleCounter>>). Split
                        // the counter off — the decision flows unchanged into
                        // `decision`/`effective_resolution_target` below; the
                        // counter is recorded into the outer-scoped
                        // `pre_routing_dnat_counter` and incremented only at a
                        // committed session install (here or the later
                        // MissingNeighbor seed path).
                        let pre_routing_dnat = match static_dnat_decision.or(dnat_decision) {
                            Some((decision, counter)) => {
                                pre_routing_dnat_counter = counter;
                                Some(decision)
                            }
                            None => None,
                        };

                        // --- NPTv6 inbound pre-routing ---
                        // If dst matches an external NPTv6 prefix, translate the
                        // destination to the internal prefix. This is stateless
                        // prefix translation (RFC 6296) -- no L4 checksum update.
                        let nptv6_inbound = if pre_routing_dnat.is_none() {
                            if let IpAddr::V6(mut dst_v6) = resolution_target {
                                // #5176: gate NPTv6 inbound on the packet's
                                // INGRESS zone so a rule-set scoped `from zone X`
                                // never translates traffic arriving from another
                                // zone (security-domain crossing).
                                if worker_ctx
                                    .forwarding
                                    .nptv6
                                    .translate_inbound(&mut dst_v6, ingress_zone_name)
                                {
                                    Some(dst_v6)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // --- NAT64 pre-routing ---
                        // If dst is IPv6 matching a NAT64 prefix, extract IPv4
                        // dest and allocate an IPv4 SNAT address. Route lookup
                        // must use the IPv4 destination.
                        //
                        // #2291: tri-state lookup. The pre-fix code collapsed
                        // "prefix matched but no source pool" into "no match"
                        // (a bare Option whose None meant both), so a matched-
                        // but-unallocatable destination fell through to IPv6
                        // route lookup on the SYNTHETIC NAT64 address — a
                        // fail-OPEN that could leak it upstream on a default
                        // IPv6 route. Now MatchUnavailable fails CLOSED (drop +
                        // counter); only NoPrefixMatch continues IPv6 routing.
                        let nat64_match = if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                            if let IpAddr::V6(dst_v6) = resolution_target {
                                // #5623: gate on SOURCE eligibility BEFORE any
                                // NAT64 allocation/translation. RFC 6146 §3.5
                                // mandates dropping an incoming IPv6 packet whose
                                // source itself lies within a configured Pref64 —
                                // a looping/synthesized "already-translated"
                                // source (the §5 hairpin construction), including
                                // the lower/upper Pref64 boundary and any embedded
                                // non-global v4. `classify_ipv6_packet` folds that
                                // check ahead of the unchanged destination match,
                                // so an eligible global-unicast source translates
                                // exactly as before. An IPv6 destination always
                                // pairs with an IPv6 source at L3; the V4 arm is
                                // unreachable for a real packet and degrades to the
                                // dest-only classify rather than asserting.
                                let nat64_result = match flow.forward_key.src_ip {
                                    IpAddr::V6(src_v6) => worker_ctx
                                        .forwarding
                                        .nat64
                                        .classify_ipv6_packet(src_v6, dst_v6),
                                    IpAddr::V4(_) => {
                                        worker_ctx.forwarding.nat64.classify_ipv6_dest(dst_v6)
                                    }
                                };
                                match nat64_result {
                                    crate::nat64::Nat64Match::NoPrefixMatch => None,
                                    // #4381: the source `(snat_v4, port)` is no
                                    // longer allocated here — it is allocated
                                    // per-flow at the Permit branch below so a
                                    // denied flow never consumes a pool port.
                                    crate::nat64::Nat64Match::MatchReady {
                                        prefix_idx,
                                        dst_v4,
                                        dst_v6,
                                    } => Some((prefix_idx, dst_v4, dst_v6)),
                                    crate::nat64::Nat64Match::IneligibleSource => {
                                        // #5623: RFC 6146 §3.5 source/hairpin drop.
                                        // The source is inside a configured Pref64
                                        // (looping/synthesized). Fail closed with a
                                        // distinct counter BEFORE route lookup,
                                        // policy, or `allocate_source` — no session,
                                        // BIB, or allocation state is minted.
                                        telemetry.counters.record_nat64_ineligible_source();
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    crate::nat64::Nat64Match::IneligibleDestination => {
                                        // #6475: RFC 6052 §3.1 non-global
                                        // embedded-destination drop. The extracted
                                        // v4 destination is 0.0.0.0/8, 127.0.0.0/8,
                                        // 169.254.0.0/16, 224.0.0.0/4, or
                                        // 240.0.0.0/4 — e.g. `64:ff9b::127.0.0.1`,
                                        // which would otherwise resolve
                                        // LocalDelivery to the localhost-only
                                        // control plane (gRPC 50051 / REST 8080)
                                        // once lo0 lands in `state.local_v4`.
                                        // Fail closed with a distinct counter
                                        // BEFORE route lookup, policy, or
                                        // `allocate_source` — no session, BIB, or
                                        // allocation state is minted.
                                        telemetry.counters.record_nat64_ineligible_dest();
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    crate::nat64::Nat64Match::MatchUnavailable => {
                                        // Fail closed: a NAT64 prefix matched
                                        // but the source pool is empty/exhausted.
                                        // Drop rather than route the synthetic
                                        // IPv6 destination as ordinary IPv6.
                                        telemetry.counters.nat64_no_source_pool += 1;
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        let effective_resolution_target =
                            if let Some((_, dst_v4, _)) = &nat64_match {
                                IpAddr::V4(*dst_v4)
                            } else if let Some(internal_dst) = nptv6_inbound {
                                IpAddr::V6(internal_dst)
                            } else {
                                match &pre_routing_dnat {
                                    Some(d) => d.rewrite_dst.unwrap_or(resolution_target),
                                    None => resolution_target,
                                }
                            };
                        // #2345: Junos evaluates the inbound security policy
                        // against the POST-translation destination tuple. For
                        // the SAME-FAMILY destination translations that happen
                        // BEFORE the route/zone lookup — DNAT, static-DNAT, and
                        // inbound NPTv6 — the policy must match on the translated
                        // (real/internal) destination address + port, in the
                        // zone derived from that translated destination, NOT the
                        // original public/virtual destination. The egress zone
                        // (`to_zone_id`) is already derived from
                        // `effective_resolution_target`, so the zone is correct;
                        // these bindings carry the translated address + port into
                        // the policy-match call so the address/port match also
                        // runs on the post-translation tuple. Only port-based
                        // DNAT carries a destination-port rewrite; static-DNAT
                        // and NPTv6 preserve the L4 port, so the original port
                        // flows through for those.
                        //
                        // #2358: NAT64 inbound now also matches the
                        // POST-translation destination — the real internal IPv4
                        // host the synthetic NAT64 address was extracted to —
                        // consistent with Junos/SRX (destination translation
                        // precedes the policy lookup). NAT64 is a CROSS-FAMILY
                        // translation: the flow source stays IPv6 while the
                        // translated destination is IPv4, so the policy match runs
                        // on a mixed (V6 src, V4 dst) tuple. `policy.rs`
                        // `try_match_rule` grew a dedicated (V6 src, V4 dst) arm
                        // (#2358) that matches the source against the rule's IPv6
                        // source set and the destination against the rule's IPv4
                        // destination set, so an operator writes a NAT64 policy
                        // against the real IPv4 server + its destination zone (the
                        // `to_zone_id` is already derived from the v4
                        // `effective_resolution_target`). MIGRATION: policies
                        // previously authored against the synthetic IPv6 NAT64
                        // prefix no longer match — rewrite them against the real
                        // IPv4 host. `effective_resolution_target` is already the
                        // extracted IPv4 destination for a NAT64 match, so it
                        // carries the correct post-translation tuple for all
                        // inbound destination translations (DNAT/static-DNAT/
                        // NPTv6/NAT64). See `docs/next-features/twice-nat.md`.
                        let policy_dst_ip = effective_resolution_target;
                        let policy_dst_port = pre_routing_dnat
                            .as_ref()
                            .and_then(|d| d.rewrite_dst_port)
                            .unwrap_or(flow.forward_key.dst_port);
                        // #2620: session-MISS path — an Accept verdict here
                        // proceeds to ingress_route_table_override (the routing
                        // evaluator), so pass routing_eval_follows = true. The
                        // precheck then counts only on the terminal
                        // discard/reject exit (the routing evaluator owns the
                        // Accept/defer exit count).
                        let input_filter_eval = evaluate_non_pbr_input_filter(
                            worker_ctx.forwarding,
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
                            Some(flow),
                            meta,
                            ingress_zone_override,
                            true,
                        );
                        // #2617: emit the matched input-filter `then log` event
                        // on THIS (session-miss / first) packet, regardless of
                        // the term's terminal action. Previously the emit fired
                        // only inside the `action != Accept` branch below and at
                        // the ForwardCandidate session-install success site
                        // (~L1850); the install emit was removed in this fix in
                        // favour of this single early site. The old layout left
                        // two accept-path gaps:
                        //
                        //   - LocalDelivery (host-bound) accepted flows never
                        //     reached the install emit, so an accepted `then log`
                        //     never fired on the miss packet.
                        //   - A ForwardCandidate flow whose session install was
                        //     refused (max-sessions admission) dropped via
                        //     `continue` BEFORE the install emit, losing the
                        //     audit record entirely for a cache-declined /
                        //     short-lived permitted flow.
                        //
                        // Emitting once here — before the action branch — gives
                        // exactly-once miss-packet semantics across every accept
                        // exit (forward, local-delivery, install-refused) and is
                        // bit-identical to the non-accept path's prior immediate
                        // emit. The log_match comes from the SAME counted
                        // evaluation at ~L838, so emitting it does not re-count
                        // the filter hit. The flow-cache descriptor populated
                        // later (~L2615) stores the log via
                        // evaluate_non_pbr_input_filter_log_only (the
                        // non-counting variant) for cache-hit replay on
                        // SUBSEQUENT packets; the miss packet does not take the
                        // cache-hit path, so the same packet is never
                        // double-logged.
                        // #2521/#3615: filter `then reject` synthesizes an active
                        // reply (TCP RST / ICMP unreachable) like policy reject;
                        // `discard` remains a silent drop. Enqueue the reply
                        // FIRST so the `then log` filter-log below reports the
                        // TRUTHFUL action — a reject whose reply fail-closes logs
                        // DENY, not REJECT.
                        let reject_reply_enqueued = if let crate::filter::FilterAction::Reject(
                            reject_msg,
                        ) = input_filter_eval.action
                        {
                            enqueue_filter_reject_reply(
                                &mut binding.tx_pipeline,
                                worker_ctx.forwarding,
                                binding.ifindex,
                                packet_frame,
                                meta,
                                flow,
                                telemetry.counters,
                                reject_msg,
                            )
                        } else {
                            false
                        };
                        if let Some(cached_log) = input_filter_eval.cached_log {
                            emit_input_filter_log_match(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                flow,
                                meta,
                                cached_log,
                                reject_reply_enqueued,
                                now_ns,
                            );
                        }
                        if input_filter_eval.action != crate::filter::FilterAction::Accept {
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // #4392: a PBR `then { routing-instance X; reject |
                        // discard; }` term is a DENY, not a forward. Pass the
                        // reject sink so a flow-backed `reject` synthesizes the
                        // RST/ICMP reply (byte-identical to a non-PBR
                        // `then reject`); on `RouteOverride::Drop` recycle the
                        // frame and skip the route-lookup/forward entirely.
                        let route_table_override = match ingress_route_table_override(
                            worker_ctx.forwarding,
                            packet_frame,
                            meta,
                            flow,
                            ingress_zone_override,
                            worker_ctx.event_stream,
                            now_ns,
                            Some(PbrRejectSink {
                                tx_pipeline: &mut binding.tx_pipeline,
                                ingress_ifindex: binding.ifindex,
                                counters: &mut *telemetry.counters,
                            }),
                        ) {
                            RouteOverride::Drop => {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            RouteOverride::Table(table) => Some(table),
                            RouteOverride::None => None,
                        };

                        let resolution = if should_block_tunnel_interface_nat_session_miss(
                            worker_ctx.forwarding,
                            effective_resolution_target,
                            meta.protocol,
                        ) {
                            no_route_resolution(Some(effective_resolution_target))
                        } else {
                            ingress_interface_local_resolution_on_session_miss(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                                effective_resolution_target,
                                meta.protocol,
                            )
                            .or_else(|| {
                                interface_nat_local_resolution_on_session_miss(
                                    worker_ctx.forwarding,
                                    effective_resolution_target,
                                    meta.protocol,
                                )
                            })
                            .unwrap_or_else(|| {
                                enforce_ha_resolution_snapshot(
                                    worker_ctx.forwarding,
                                    worker_ctx.ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_in_table_with_dynamic(
                                        worker_ctx.forwarding,
                                        worker_ctx.dynamic_neighbors,
                                        effective_resolution_target,
                                        route_table_override.as_deref(),
                                    ),
                                )
                            })
                        };
                        let fabric_ingress = packet_fabric_ingress;
                        let resolution = prefer_local_forward_candidate_for_fabric_ingress(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            worker_ctx.dynamic_neighbors,
                            now_secs,
                            fabric_ingress,
                            effective_resolution_target,
                            resolution,
                        );
                        let nptv6_nat = nptv6_inbound.map(|internal_dst| NatDecision {
                            rewrite_src: None,
                            rewrite_dst: Some(IpAddr::V6(internal_dst)),
                            nat64: false,
                            nptv6: true,
                            ..NatDecision::default()
                        });
                        let mut decision = SessionDecision {
                            resolution,
                            nat: nptv6_nat.or(pre_routing_dnat).unwrap_or_default(),
                        };
                        // #919/#922: zero-allocation zone-pair resolution
                        // direct from u16 IDs — no String materialisation
                        // on the per-flow miss path.
                        //
                        // #3021: resolve the LOGICAL ingress ifindex for the
                        // zone-pair policy. `ifindex_to_zone_id` is keyed by the
                        // logical unit ifindex (forwarding_build/interfaces.rs:76);
                        // a VLAN subinterface's physical bind ifindex maps only to
                        // its parent's FIRST-subinterface zone, so the raw physical
                        // index would evaluate the wrong zone-pair policy on a
                        // parent carrying multiple VLAN units in distinct zones.
                        // Mirrors filter.rs / cos_classify.rs; non-VLAN ports
                        // resolve physical == logical (unchanged). #5802: reuse the
                        // `ingress_logical` resolved once by `prerouting_ingress_scope`
                        // at the pre-routing DNAT site above — the pre-routing NAT
                        // scope and the zone-pair policy now share ONE logical-unit
                        // ingress identity.
                        // #6458 V2: a zone-encoded fabric stamp drives
                        // NEW-flow policy only when the resolution's owner
                        // RG is forwarding-active LOCALLY (the peer punts a
                        // new flow to us only because we own its egress
                        // RG). Otherwise the stamp is ignored and the
                        // fabric interface's own zone governs. Shadow the
                        // override so every zone-pair consumer below (this
                        // site, the NAT scope borrows, and the
                        // MissingNeighbor arm) sees the gated value.
                        // #5798: capture the RAW zone-encoded fabric ingress stamp
                        // BEFORE the RG gate shadows it. A fragment-association
                        // AUTHORITY must be a pure INGRESS property: the gated value
                        // below is a function of the RESOLUTION, which the non-first
                        // fragment's CONSULT cannot know — resolving is exactly what
                        // an association hit short-circuits. Keying install and
                        // consult on the raw stamp keeps the two symmetric BY
                        // CONSTRUCTION; stamping the gated value at install while the
                        // consult can only see the raw one would desynchronize them
                        // and turn legitimate same-domain fragments into misses.
                        let frag_authority_zone_override = ingress_zone_override;
                        let ingress_zone_override = gate_fabric_zone_override_on_owner_rg(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            ingress_zone_override,
                            resolution,
                        );
                        let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                            worker_ctx.forwarding,
                            ingress_logical,
                            ingress_zone_override,
                            resolution.egress_ifindex,
                        );
                        // Borrow zone names as &str for string-typed downstream
                        // callers (static_nat, match_source_nat_for_flow, debug
                        // log). No clone — the borrow lives only inside this
                        // miss-path block while `worker_ctx.forwarding` is held.
                        let from_zone: &str = worker_ctx
                            .forwarding
                            .zone_id_to_name
                            .get(&from_zone_id)
                            .map(|s| s.as_str())
                            .unwrap_or("");
                        let to_zone: &str = worker_ctx
                            .forwarding
                            .zone_id_to_name
                            .get(&to_zone_id)
                            .map(|s| s.as_str())
                            .unwrap_or("");
                        // #2210 + #2209: port-scan / IP-sweep screen
                        // detection at the new-flow / session-MISS
                        // decision. Running it HERE (not on the per-packet
                        // pre-session stage) is what fixes the #2210
                        // false positives: an established flow's packets
                        // are session HITS and never reach this point, so
                        // mid-stream ACKs/data no longer inflate the sweep
                        // counter. port-scan keeps its TCP-initial-SYN
                        // gate; IP-sweep counts the new flow on any
                        // protocol. State is per-`(from_zone_id, src_ip)`
                        // and bounded (see `screen/scan.rs`). The reason
                        // is `port-scan` / `ip-sweep`; emit + recycle in
                        // the shared block below.
                        // #2227 MINOR-5: parse the screen 5-tuple ONCE on
                        // this cold new-flow path. It feeds both the
                        // scan/sweep check below and the drop-event tuple
                        // if a drop fires. If the L3 header is unparseable
                        // (#2146 Err), fall back to a meta+flow info so the
                        // scan/sweep tuple and any drop event still carry
                        // the offending 5-tuple.
                        let l3_off = if meta.ingress_vlan_present != 0 {
                            18
                        } else {
                            14
                        };
                        let screen_pkt = extract_screen_info(
                            packet_frame,
                            meta.addr_family,
                            meta.protocol,
                            meta.tcp_flags,
                            meta.pkt_len,
                            flow.src_ip,
                            flow.dst_ip,
                            flow.forward_key.src_port,
                            flow.forward_key.dst_port,
                            l3_off,
                        )
                        .unwrap_or_else(|_| screen_parse_error_info(&meta, flow));
                        let new_flow_screen_reason = (if packet_fabric_ingress {
                            // #4155: a fabric-redirected packet was already
                            // scan/sweep-screened on the peer ingress node
                            // before it crossed the fabric link. In the
                            // session-sync race window it can arrive here as a
                            // session MISS; re-running the per-(zone,src)
                            // scan/sweep counter on the RG owner would
                            // double-count the same new flow. The ingress node
                            // owns scan/sweep for this packet — skip it here.
                            // (Session-limit enforcement below still runs: it
                            // guards the owner's own SessionTable, which the
                            // ingress node did not populate.)
                            None
                        } else {
                            screen.scan_sweep_drop_on_new_flow(
                                from_zone,
                                from_zone_id,
                                &screen_pkt,
                                // #4114: scan/sweep windows are microseconds.
                                now_ns / 1_000,
                            )
                        })
                        // #2134: per-IP session-limit enforcement at the
                            // new-flow decision. This dominates BOTH counted
                            // install sites below (LocalMiss host-inbound and
                            // ForwardFlow transit), fires exactly once per new
                            // flow before its session exists, and reads the
                            // SessionTable count read-only (so an over-limit /
                            // rejected IP never gets a phantom map entry —
                            // #2128). Keys on the pre-NAT original src/dst
                            // (`flow.src_ip`/`flow.dst_ip`), matching Junos
                            // per-source-IP semantics and the screen stage's
                            // own tuple. Evaluated only if scan/sweep did not
                            // already decide a drop.
                            .or_else(|| {
                                new_flow_session_limit_drop(
                                    worker_ctx.forwarding,
                                    sessions,
                                    from_zone,
                                    flow.src_ip,
                                    flow.dst_ip,
                                )
                            });
                        // #2234: surface a rare (logarithmic) operator alarm
                        // when the scan/sweep source table is saturated and
                        // the detector is displacing stale sources to stay
                        // able to track a fresh real scanner. This is NOT a
                        // drop — the packet still forwards — so it uses the
                        // ALARM emitter (RT_FLOW action PERMIT), which rides
                        // the screen event frame with a dedicated
                        // `scan-table-pressure` reason WITHOUT inflating the
                        // drop/deny counters. It fires at most a handful of
                        // times under a sustained flood (never per-flow), and
                        // is checked here on the cold session-miss path only
                        // (the same path that performs the eviction), so the
                        // hot established-flow path pays nothing.
                        if screen.take_scan_table_pressure_event() {
                            emit_screen_alarm_event(
                                worker_ctx.event_stream,
                                &screen_pkt,
                                meta,
                                from_zone_id,
                                "scan-table-pressure",
                                event_now_ns_from_secs(now_secs),
                            );
                        }
                        if let Some(reason) = new_flow_screen_reason {
                            // The screen verdict is already decided; reuse
                            // the single parse above for the drop/alarm
                            // event's 5-tuple.
                            if screen.alarm_without_drop(from_zone) {
                                // Junos `alarm-without-drop`: the scan/sweep
                                // (or session-limit) check already ran and
                                // updated its tracker; suppress only the drop
                                // and raise a log-only alarm, then fall
                                // through and install the new flow normally.
                                emit_screen_alarm_event(
                                    worker_ctx.event_stream,
                                    &screen_pkt,
                                    meta,
                                    from_zone_id,
                                    reason,
                                    event_now_ns_from_secs(now_secs),
                                );
                                screen.record_alarm_without_drop();
                            } else {
                                emit_screen_drop_event(
                                    worker_ctx.event_stream,
                                    &screen_pkt,
                                    meta,
                                    from_zone_id,
                                    reason,
                                    event_now_ns_from_secs(now_secs),
                                );
                                telemetry.counters.record_screen_drop(
                                    reason,
                                    from_zone_id,
                                    &worker_ctx.forwarding.flood_counter_slot_map,
                                );
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        decision.resolution = finalize_new_flow_ha_resolution(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            decision.resolution,
                            packet_fabric_ingress,
                            meta.ingress_ifindex as i32,
                            from_zone_id,
                            ha_startup_grace_until_secs,
                        );
                        // #4400: strict-syn-check drop. A bare TCP RST/FIN (a
                        // connection-closing control bit with no SYN) that
                        // MISSES the session table can never legitimately open
                        // a connection — a real flow starts with a SYN, and a
                        // RST/FIN for a flow this node does not track is a late
                        // segment for an already-GC'd session or an attack.
                        // Dropping it here, before the ForwardCandidate /
                        // MissingNeighbor install sites below, keeps a RST/FIN
                        // flood from churning the per-worker session table with
                        // immediately-`closing` seed entries (P6, confirmed 4x).
                        // A SYN-ACK / bare ACK / data first packet is NOT
                        // dropped, preserving the Junos no-syn-check default and
                        // #3152 asymmetric-routing mid-stream pickup. Only the
                        // two TRANSIT dispositions that seed a new local session
                        // from this packet's flags are gated: LocalDelivery
                        // (host-inbound to the RE) is deliberately exempt so a
                        // peer RST tearing down a firewall-originated TCP session
                        // (BGP, IKE, management) still reaches the local stack,
                        // and NoRoute / FabricRedirect / HAInactive never seed a
                        // local session from this packet. Legitimate teardowns
                        // for a SYNCED peer-owned session are session HITs served
                        // by `resolve_flow_session_decision` before the fast path;
                        // a session-MISS fabric-ingress bare RST/FIN is dropped
                        // RIGHT HERE by this strict-syn-check (#6478 removed the
                        // cluster-peer return fast path — session-less
                        // fabric-ingress packets take this normal miss path), so
                        // the local and fabric-ingress paths handle a bare
                        // RST/FIN identically.
                        // Counted in the aggregate `screen_drops` flow-statistics
                        // tally (no per-reason ordinal — that array mirrors the
                        // Junos SCREEN checks, and strict-syn-check is a flow
                        // tcp-session control, not a screen check; joins the
                        // syn-cookie / icmp-fragment aggregate-only class). No
                        // per-packet event is emitted: a RST/FIN flood must not
                        // become a log storm.
                        if matches!(
                            decision.resolution.disposition,
                            ForwardingDisposition::ForwardCandidate
                                | ForwardingDisposition::MissingNeighbor
                        ) && strict_syn_check_drops_new_flow(meta.protocol, meta.tcp_flags)
                        {
                            telemetry.counters.record_screen_drop(
                                "strict-syn-check",
                                from_zone_id,
                                &worker_ctx.forwarding.flood_counter_slot_map,
                            );
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // Debug: log session miss with flow details (throttled)
                        if cfg!(feature = "debug-log") {
                            if session_miss_debug_log_allowed(telemetry.dbg.session_miss) {
                                eprintln!(
                                    "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
                                    telemetry.dbg.session_miss,
                                    flow.src_ip,
                                    flow.forward_key.src_port,
                                    flow.dst_ip,
                                    flow.forward_key.dst_port,
                                    meta.protocol,
                                    meta.tcp_flags,
                                    meta.ingress_ifindex,
                                    resolution.disposition,
                                    resolution.egress_ifindex,
                                    resolution.neighbor_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    from_zone,
                                    to_zone,
                                );
                                // If from WAN (if6), dump what session key was tried
                                if meta.ingress_ifindex == 6 {
                                    eprintln!(
                                        "DBG SESS_MISS_KEY: af={} proto={} key={}:{}->{}:{} bpf_entries={} local_sessions={}",
                                        flow.forward_key.addr_family,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_ip,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_ip,
                                        flow.forward_key.dst_port,
                                        count_bpf_session_entries(binding.bpf_maps.session_map_fd),
                                        sessions.len(),
                                    );
                                    // Dump all local sessions to compare
                                    if telemetry.dbg.session_miss <= 3 {
                                        let mut sess_dump = String::new();
                                        let mut count = 0;
                                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                                            if count < 30 {
                                                use std::fmt::Write;
                                                let _ = write!(sess_dump,
                                                    "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={} origin={}",
                                                    key.addr_family, key.protocol,
                                                    key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                    metadata.is_reverse, origin.is_peer_synced(), origin.as_str(),
                                                );
                                                count += 1;
                                            }
                                        });
                                        if !sess_dump.is_empty() {
                                            eprintln!("DBG SESS_MISS_DUMP:{sess_dump}");
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(debug) = debug.as_mut() {
                            debug.from_zone = Some(from_zone_id);
                            debug.to_zone = Some(to_zone_id);
                        }
                        // #5690: a non-query ICMP error is FLOWLESS (#3290
                        // discards its metadata pseudo-port so it never seeds a
                        // session), so it never reaches this flow-backed
                        // session-miss arm — a flow-backed ICMP packet here is
                        // always an identifier-bearing query (echo), never an
                        // error. The old `is_embedded_icmp_error` skip of the
                        // local-delivery caching below was therefore a structural
                        // no-op; the generic embedded-ICMP NAT reversal it guarded
                        // now runs on the flowless path
                        // (`embedded_icmp::try_reverse_embedded_icmp_error`).
                        // #3070 + #3485: on the session-MISS local-delivery path,
                        // the host-inbound-traffic zone gate runs BEFORE the lo0
                        // host-bound filter. A host-bound packet (destined to a
                        // firewall-local interface IP) whose system-service /
                        // protocol is not in the INGRESS zone's host-inbound set
                        // is denied (silent drop, Junos posture) and never cached.
                        // #3405: a CONFIGURED zone with no host-inbound stanza
                        // default-DENIES host-bound traffic (it ships an EMPTY
                        // token set, not admit-all). Admit-all now applies only
                        // to a zone absent from the snapshot entirely (legacy /
                        // truly-unconfigured). Lifeline interfaces (fxp0/em0/
                        // fab*) never reach this local-delivery classifier
                        // (#3682). SSOT: docs/host-inbound-service-matrix.md.
                        // A host-inbound DENY drops with NO lo0 side-effects (no
                        // reject reply, no lo0 counter/log) — before #3485 the lo0
                        // filter ran first, so a denied service still triggered its
                        // reject/RST/counter/log (codex-review-118 M1). Only an
                        // ADMITTED packet pays the lo0 evaluation. Gated on
                        // LocalDelivery so transit traffic never pays for it.
                        if resolution.disposition == ForwardingDisposition::LocalDelivery {
                            match host_inbound_gated_lo0_action(
                                worker_ctx.forwarding,
                                // #3609: the host-inbound override is keyed by
                                // the LOGICAL unit ifindex (already resolved
                                // above for the zone-pair lookup); pass it, not
                                // the raw physical `meta.ingress_ifindex`.
                                ingress_logical,
                                from_zone_id,
                                flow.forward_key.dst_port,
                                matches!(flow.dst_ip, IpAddr::V6(_)),
                                // #3171: first L4 byte = ICMP/ICMPv6 type, so
                                // error/PMTUD control messages are admitted on a
                                // ping-less zone (mirrors the kernel chain). 0
                                // for non-ICMP (ignored by host_inbound_admits).
                                // #5140: read the INNER type via `packet_frame`
                                // (decapped frame post native-GRE, else
                                // `raw_frame`) — `meta.l4_offset` is inner-relative
                                // after `stage_native_gre_decap`, so the outer
                                // `raw_frame` would read the wrong byte and could
                                // host-admit an ordinary echo as an exempt error.
                                packet_frame
                                    .get(meta.l4_offset as usize)
                                    .copied()
                                    .unwrap_or(0),
                                crate::afxdp::frame::term_match_extra_from_frame(
                                    packet_frame,
                                    meta,
                                ),
                                flow,
                                meta,
                                ingress_zone_override,
                                now_ns,
                            ) {
                                None => {
                                    // Host-inbound denied: silent drop, never
                                    // cached.
                                    telemetry.dbg.local += 1;
                                    // #3610/M07: own debug counter, not policy_deny.
                                    telemetry.dbg.host_inbound_deny += 1;
                                    telemetry.counters.touched = true;
                                    // #3326: account the host-inbound deny so
                                    // `GlobalCtrHostInboundDeny` reflects the drop
                                    // (REST/Prometheus/`show security flow
                                    // statistics`).
                                    telemetry.counters.host_inbound_denied_packets += 1;
                                    // #3610: emit the tuple-rich host-inbound deny
                                    // event so an operator can see WHICH host-bound
                                    // flow was dropped, not just an aggregate
                                    // counter (reuses the policy-deny event
                                    // machinery with a distinct host-inbound reason).
                                    emit_host_inbound_deny(
                                        worker_ctx.forwarding,
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        from_zone_id,
                                        now_ns,
                                    );
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                                // #2521/#3615: `filter_terminal` enqueues the lo0
                                // reject reply FIRST, then emits the lo0
                                // filter-log with the TRUTHFUL action (a
                                // suppressed reject logs DENY, not REJECT), and
                                // returns true iff the packet must be dropped
                                // (discard/reject). An accepted lo0 `then log`
                                // flow still emits and falls through.
                                Some((lo0_action, lo0_log)) => {
                                    if filter_terminal(
                                        &mut binding.tx_pipeline,
                                        worker_ctx.forwarding,
                                        worker_ctx.event_stream,
                                        binding.ifindex,
                                        packet_frame,
                                        meta,
                                        flow,
                                        telemetry.counters,
                                        lo0_action,
                                        lo0_log,
                                        now_ns,
                                    ) {
                                        telemetry.dbg.local += 1;
                                        telemetry.dbg.policy_deny += 1;
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                }
                            }
                        }
                        // #3019/#3706: `to-zone junos-host` security policy on
                        // the session-MISS local-delivery path, AFTER
                        // host-inbound admission (Junos order). A matching
                        // junos-host deny/reject drops the host-bound packet
                        // (and emits the policy-deny RT_FLOW + reject/tcp-rst
                        // reply); a matching PERMIT is carried forward so its
                        // `then log` selection + admitting policy id + counter
                        // handle can be stamped onto the installed session
                        // (#3706); a no-match continues to local delivery with
                        // the default no-policy metadata. No-op unless a
                        // junos-host policy is configured.
                        let junos_host_outcome = if resolution.disposition
                            == ForwardingDisposition::LocalDelivery
                        {
                            junos_host_local_policy(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                &mut binding.tx_pipeline,
                                binding.ifindex,
                                packet_frame,
                                telemetry.counters,
                                flow,
                                meta,
                                from_zone_id,
                                desc.len as u64,
                                now_ns,
                            )
                        } else {
                            JunosHostLocalPolicy::NoMatch
                        };
                        if matches!(junos_host_outcome, JunosHostLocalPolicy::Dropped) {
                            telemetry.dbg.local += 1;
                            telemetry.dbg.policy_deny += 1;
                            telemetry.counters.touched = true;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        if resolution.disposition == ForwardingDisposition::LocalDelivery
                            && should_cache_local_delivery_session_on_miss(
                                worker_ctx.forwarding,
                                effective_resolution_target,
                                resolution,
                                meta.protocol,
                                meta.tcp_flags,
                            )
                        {
                            // #3706: a matching `to-zone junos-host then permit
                            // [log ...]` policy admitted this host-bound flow, so
                            // stamp its log selection, admitting policy id, and
                            // per-rule hit-counter handle onto the installed
                            // session — parity with the transit permit path. The
                            // #2508/#3056/#3073 comments below ("host-local
                            // sessions are not policy-forwarded, so they carry no
                            // log / policy id / counter") predate junos-host
                            // permit-policy matching and are true ONLY for a
                            // no-match host-local session; an explicit permit DOES
                            // have an admitting policy + logging selection.
                            let (
                                host_log_session_init,
                                host_log_session_close,
                                host_policy_id,
                                host_policy_counter_idx,
                            ) = match &junos_host_outcome {
                                JunosHostLocalPolicy::Permit(result) => (
                                    result.log_session_init,
                                    result.log_session_close,
                                    result.policy_id,
                                    result.policy_counter_idx,
                                ),
                                // No junos-host policy matched: default no-policy
                                // host-local metadata (byte-identical to
                                // pre-#3706). Dropped never reaches here.
                                _ => (false, false, 0, 0),
                            };
                            // #3706/#3322: bind the admitting rule's shared hit
                            // counter here, where `host_policy_counter_idx` still
                            // indexes the rule that admitted this flow, so a later
                            // live policy reorder cannot re-point the count.
                            // `hit_counter_by_idx(0)` is None (the no-match case).
                            let host_policy_counter = worker_ctx
                                .forwarding
                                .policy
                                .hit_counter_by_idx(host_policy_counter_idx)
                                .cloned();
                            let local_metadata = SessionMetadata {
                                ingress_zone: from_zone_id,
                                egress_zone: to_zone_id,
                                // #4983: stamp the session's TRUE ingress identity from the frame that
                                // created it — the binding it was actually received on plus its 802.1Q
                                // tag. Recorded ONCE here and never re-derived from the zone, which is
                                // the approximation `show/clear security flow session interface <name>`
                                // is being freed from.
                                ingress_ifindex: meta.ingress_ifindex,
                                ingress_vlan_id: meta.ingress_vlan_id,
                                owner_rg_id: 0,
                                fabric_ingress: false,
                                is_reverse: false,
                                // Keep firewall-local sessions in the helper only for HA
                                // state. Publish only the exact observed key back into the
                                // BPF session map so subsequent established packets bypass
                                // userspace and return directly to the kernel.
                                nat64_reverse: None,
                                // #2508/#3706: a matching `to-zone junos-host then
                                // permit log` policy's per-policy RT_FLOW SYSLOG
                                // selection (a no-match host-local session carries
                                // none, so both stay false).
                                log_session_init: host_log_session_init,
                                log_session_close: host_log_session_close,
                                // #3056/#3706: the admitting junos-host policy's ID
                                // so the live-session BPF-compat publish and the
                                // SESSION_CREATE/CLOSE RT_FLOW records reference the
                                // policy that admitted the host-bound flow (0 only
                                // for a no-match host-local session).
                                policy_id: host_policy_id,
                                // #3227: host-local sessions are not policy-app-matched.
                                inactivity_timeout_ns: None,
                                // #3073/#3706: the admitting junos-host rule's
                                // hit-counter handle (0 / None for a no-match
                                // host-local session).
                                policy_counter_idx: host_policy_counter_idx,
                                policy_counter: host_policy_counter,
                            };
                            if install_helper_local_session_on_miss(
                                sessions,
                                binding.bpf_maps.session_map_fd,
                                worker_ctx.shared_sessions,
                                worker_ctx.shared_nat_sessions,
                                worker_ctx.shared_forward_wire_sessions,
                                &worker_ctx.shared_owner_rg_indexes,
                                &flow.forward_key,
                                decision,
                                local_metadata.clone(),
                                SessionOrigin::LocalMiss,
                                now_ns,
                                meta.protocol,
                                meta.tcp_flags,
                            ) {
                                telemetry.counters.session_creates += 1;
                                telemetry.dbg.session_create += 1;
                                // #2218: a DNAT/static-DNAT to a firewall-
                                // local service commits its translation
                                // here. No SNAT is applied on the local-
                                // delivery path, so only the pre-routing
                                // DNAT counter is bumped, once.
                                if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                    c.add(desc.len as u64);
                                }
                                // #2008 M5: stamp the resolved application id.
                                // #3321: directional resolution (service = dst
                                // forward / src reverse).
                                // #3416: this is the DNAT-to-firewall-local
                                // delivery path — resolve the forward service
                                // port from the post-translation (rewritten)
                                // destination so the local-service conntrack row
                                // shows the admitting application (e.g. the
                                // private :22), not the public port.
                                let app_id = worker_ctx.forwarding.app_catalog.lookup_admitted(
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                    local_metadata.is_reverse,
                                    decision.nat.rewrite_dst_port,
                                );
                                // #5213: stamp the stable id from the installed
                                // host-local entry so the mirror row matches
                                // RT_FLOW.
                                let session_id =
                                    sessions.session_id_for(&flow.forward_key);
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    decision,
                                    &local_metadata,
                                    &worker_ctx.forwarding.zone_name_to_id,
                                    worker_ctx.forwarding.alg_disable_flags,
                                    app_id,
                                    session_id,
                                );
                            }
                        }
                        // #5690: the generic embedded-ICMP NAT reversal is
                        // NOT wired here. A non-query ICMP error is FLOWLESS
                        // (#3290 discards its pseudo-port so it never seeds a
                        // session), so it never enters this flow-backed arm;
                        // the reversal runs on the flowless path via
                        // `embedded_icmp::try_reverse_embedded_icmp_error`.
                        if decision.resolution.disposition
                            == ForwardingDisposition::ForwardCandidate
                        {
                            let owner_rg_id =
                                owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                            flow_cache_owner_rg_id = owner_rg_id;
                            // #850: allow-dns-reply admits sessionless DNS replies
                            // through policy (not around it). Always evaluate policy;
                            // the session-install step below is skipped only when
                            // the knob matches AND no NAT is required (to avoid
                            // orphan NAT state without a session anchor).
                            //
                            // #1620: cold-path latency histogram pre-eval gate.
                            // Per plan v4 §4.4: open a scoped &mut binding.cold_path
                            // borrow that ENDS before evaluate_policy_*, so no
                            // mutable cold_path borrow overlaps the policy call.
                            let (cp_sample_tag, cp_t_in) = {
                                let cp = &mut binding.cold_path;
                                cp.sample_phase = cp.sample_phase.wrapping_add(1);
                                let tag = (cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0;
                                let t = if tag {
                                    crate::afxdp::cold_path_hist::sample_tsc_start()
                                } else {
                                    0
                                };
                                (tag, t)
                            };
                            // #2345: match on the POST-translation destination
                            // tuple (translated dst addr + port) in the
                            // translated-dst zone. `policy_dst_ip` /
                            // `policy_dst_port` collapse to the original dst when
                            // no inbound destination translation applies.
                            // #3020: extract the ICMP/ICMPv6 type/code so an
                            // icmp-type-constrained application term (junos-ping
                            // = echo-request only) is enforced. `None` for
                            // non-ICMP flows and for ICMP frames whose L4 header
                            // is not safely readable (truncated / non-first
                            // fragment), so such terms fail closed.
                            let policy_icmp = policy_packet_icmp(packet_frame, meta);
                            let policy_result = evaluate_policy_result_with_icmp(
                                &worker_ctx.forwarding.policy,
                                from_zone_id,
                                to_zone_id,
                                flow.src_ip,
                                policy_dst_ip,
                                flow.forward_key.protocol,
                                flow.forward_key.src_port,
                                policy_dst_port,
                                policy_icmp,
                                desc.len as u64,
                            );
                            // #1620: cold-path latency histogram post-eval record.
                            // q32-skip + wrapper_underflow_count per plan v4 §4.4.
                            if cp_sample_tag {
                                let t_out = crate::afxdp::cold_path_hist::sample_tsc_end();
                                let q32 = binding.cold_path.ns_per_tsc_q32;
                                if q32 != 0 {
                                    let delta_tsc = t_out.saturating_sub(cp_t_in);
                                    let raw_ns = ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
                                    let baseline = binding.cold_path.wrapper_ns_baseline;
                                    let delta_ns = if raw_ns < baseline {
                                        binding.cold_path.wrapper_underflow_count = binding
                                            .cold_path
                                            .wrapper_underflow_count
                                            .saturating_add(1);
                                        0
                                    } else {
                                        raw_ns - baseline
                                    };
                                    // #1635: direct slot map lookup;
                                    // skip the sample on a miss
                                    // (capacity exhausted or zone-id
                                    // ≥ 65).
                                    if let Some(slot) = crate::afxdp::cold_path_hist::lookup_slot(
                                        &worker_ctx.forwarding.cold_path_slot_map,
                                        from_zone_id,
                                        to_zone_id,
                                    ) {
                                        binding.cold_path.record_sample(
                                            slot,
                                            from_zone_id,
                                            to_zone_id,
                                            delta_ns,
                                        );
                                    }
                                }
                            }
                            if let PolicyAction::Permit = policy_result.action {
                                // NAT64: cross-family translation takes
                                // priority over same-family SNAT.
                                let mut source_nat_release_key = None;
                                // #2218: the matched SNAT/static-SNAT rule's
                                // per-rule hit counter, captured from the
                                // decision helper; incremented once at the
                                // committed forward install below.
                                let mut source_nat_counter: Option<
                                    std::sync::Arc<crate::nat::NatRuleCounter>,
                                > = None;
                                // #1852: gate pool-mode SNAT allocation
                                // for a non-first fragment (no L4 ports —
                                // allocating leaks a pool port + corrupts
                                // payload). Computed from the ingress
                                // frame at the L3 offset.
                                let snat_non_first_fragment = {
                                    let l3 = meta.l3_offset as usize;
                                    l3 <= packet_frame.len()
                                        && is_non_first_fragment(
                                            &packet_frame[l3..],
                                            meta.addr_family,
                                        )
                                };
                                let nat64_info = if let Some((prefix_idx, dst_v4, orig_dst_v6)) =
                                    nat64_match
                                {
                                    // #4381: allocate a UNIQUE translated
                                    // (pool v4 source, L4 port/identifier) for
                                    // this admitted forward flow, reusing the
                                    // pool-mode SNAT PortAllocator (RFC 6146
                                    // BIB). Two v6 clients behind one pool
                                    // address that share a source port/echo id
                                    // now get distinct translated values, so
                                    // their reverse (v4->v6) tuples never
                                    // collide.
                                    let orig_src_v6 = match flow.src_ip {
                                        IpAddr::V6(v6) => v6,
                                        _ => std::net::Ipv6Addr::UNSPECIFIED,
                                    };
                                    match worker_ctx.forwarding.nat64.allocate_source_for_worker(
                                        prefix_idx,
                                        meta.protocol,
                                        orig_src_v6,
                                        dst_v4,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                        now_ns,
                                        // #6522: THIS worker holds the NAT64
                                        // allocation it just made. Its
                                        // sibling replicas each reserve the
                                        // same record, so the owner's own bit
                                        // is what stops the last replica's
                                        // age-reap from freeing a live
                                        // `(pool_v4, port)`.
                                        worker_id,
                                    ) {
                                        Ok((snat_v4, translated_port)) => {
                                            decision.nat = Nat64State::forward_decision(
                                                snat_v4,
                                                dst_v4,
                                                translated_port,
                                            );
                                            // #2562/#5146: the first-fragment
                                            // association is NO LONGER installed
                                            // here. Source allocation is not the
                                            // commit point — the flow can still be
                                            // rolled back (hop-limit ICMP-TE,
                                            // admission refusal, install-partial),
                                            // and the rollback releases only the
                                            // pool port, leaving a pre-published
                                            // association live to hand a non-first
                                            // fragment a rolled-back verdict + a
                                            // now-reusable translation (#5146). The
                                            // install moved to the POST-COMMIT site
                                            // (inside `if forward_installed`),
                                            // alongside the ordinary-NAT install,
                                            // so it is published ONLY on the
                                            // outcome the anchor authorized.
                                            Some(Nat64ReverseInfo {
                                                orig_src_v6,
                                                orig_dst_v6,
                                            })
                                        }
                                        Err(reason) => {
                                            // Fail closed: no translated source
                                            // could be allocated. Drop rather
                                            // than emit a colliding translation.
                                            // Nothing was allocated or installed
                                            // yet on this flow, so a bare recycle
                                            // is a clean bail. #4520: attribute
                                            // transient port exhaustion
                                            // (nat64_pool_exhausted) distinctly
                                            // from a config/empty pool
                                            // (nat64_no_source_pool) — the reason
                                            // is carried on the Err.
                                            telemetry
                                                .counters
                                                .record_nat64_source_failure(reason);
                                            binding.scratch.scratch_recycle.push(desc.addr);
                                            continue;
                                        }
                                    }
                                } else {
                                    // Check NPTv6 outbound, then static NAT SNAT, then interface SNAT.
                                    // Use merge() to combine with any pre-routing DNAT
                                    // decision rather than overwriting it.
                                    let nat_match_flow =
                                        flow.with_destination(effective_resolution_target);
                                    // #3121: NPTv6 outbound source-prefix translation is
                                    // orthogonal to a pre-routing destination rewrite
                                    // (DNAT / static DNAT). The two NAT stages COMPOSE --
                                    // DNAT rewrites the destination, NPTv6 the source --
                                    // so NPTv6 is attempted regardless of whether a
                                    // destination rewrite is already present and is
                                    // merged into the decision (not gated on
                                    // rewrite_dst.is_none(), which leaked the internal
                                    // IPv6 source whenever DNAT also matched). The merge
                                    // preserves rewrite_dst (DNAT) + rewrite_src (NPTv6);
                                    // the NPTv6 source rewrite is checksum-neutral by
                                    // RFC 6296 (see afxdp::checksum / frame::apply_nat_ipv6),
                                    // so only the DNAT destination delta is folded into the
                                    // L4 checksum. #5176: gate on the EGRESS zone
                                    // (`to_zone`) so a rule-set scoped `from zone X`
                                    // never rewrites the source of traffic leaving
                                    // via another zone (security-domain crossing).
                                    let nptv6_snat =
                                        if let IpAddr::V6(mut src_v6) = nat_match_flow.src_ip {
                                            if worker_ctx
                                                .forwarding
                                                .nptv6
                                                .translate_outbound(&mut src_v6, to_zone)
                                            {
                                                Some(NatDecision {
                                                    rewrite_src: Some(IpAddr::V6(src_v6)),
                                                    rewrite_dst: None,
                                                    nat64: false,
                                                    nptv6: true,
                                                    ..NatDecision::default()
                                                })
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        };
                                    if let Some(nptv6_decision) = nptv6_snat {
                                        // NPTv6 matched: compose with any pre-routing
                                        // DNAT decision. NPTv6 is the source translation
                                        // and takes precedence over static/interface
                                        // SNAT for the source (same precedence the old
                                        // rewrite_dst.is_none() branch applied). NPTv6
                                        // carries no per-rule NAT counter.
                                        decision.nat = decision.nat.merge(nptv6_decision);
                                        source_nat_release_key =
                                            Some(nat_match_flow.forward_key.clone());
                                    } else {
                                        // No NPTv6 match: fall back to static / interface
                                        // SNAT, merging with any pre-routing DNAT decision.
                                        // #2218: capture the matched rule's counter via
                                        // the out-param.
                                        let mut snat_match_counter = None;
                                        match source_nat_decision_for_flow(
                                            worker_ctx.forwarding,
                                            meta.ingress_ifindex as i32,
                                            &from_zone,
                                            &to_zone,
                                            decision.resolution.egress_ifindex,
                                            &nat_match_flow,
                                            now_ns,
                                            snat_non_first_fragment,
                                            // #6522: THIS worker holds the
                                            // pool allocation this decision
                                            // mints — see `nat::NatHolder`.
                                            worker_id,
                                            &mut snat_match_counter,
                                        ) {
                                            Ok(snat_decision) => {
                                                decision.nat = decision.nat.merge(snat_decision);
                                                source_nat_release_key =
                                                    Some(nat_match_flow.forward_key.clone());
                                                source_nat_counter = snat_match_counter;
                                            }
                                            Err(failure) => {
                                                record_source_nat_failure(
                                                    telemetry,
                                                    worker_ctx,
                                                    meta,
                                                    flow,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    desc.len,
                                                    &failure,
                                                );
                                                binding.scratch.scratch_recycle.push(desc.addr);
                                                continue;
                                            }
                                        }
                                    }
                                    None
                                };
                                // #5140: read the INNER packet via `packet_frame`
                                // (decapped frame post native-GRE, else
                                // `raw_frame`). The TTL/hop-limit test + the
                                // embedded original in the generated Time Exceeded
                                // are keyed on the inner-relative `meta` offsets;
                                // `desc` is carried only to recycle the outer UMEM
                                // slot (the reply is a freshly built prebuilt
                                // frame).
                                let local_icmp_te = build_local_time_exceeded_request(
                                    packet_frame,
                                    desc,
                                    meta,
                                    &worker_ctx.ident,
                                    flow,
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    worker_ctx.ha_state,
                                    now_secs,
                                    telemetry.counters,
                                );
                                if let Some(request) = local_icmp_te {
                                    if let Some(release_key) = source_nat_release_key.as_ref() {
                                        rollback_source_nat_allocation_for_worker(
                                            &worker_ctx.forwarding.iface_nat_allocators,
                                            &worker_ctx.forwarding.source_nat_rules,
                                            release_key,
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                    }
                                    // #4381: a NAT64 forward flow whose hop-limit
                                    // expired allocated a translated pool port at
                                    // the branch above; roll it back so the
                                    // ICMP-TE bounce does not leak it (self-gated
                                    // on `nat.nat64`).
                                    crate::nat64::rollback_nat64_allocation_for_worker(
                                        &worker_ctx.forwarding.nat64,
                                        &flow.forward_key,
                                        decision.nat,
                                        false,
                                        now_ns,
                                        worker_id,
                                    );
                                    binding.scratch.scratch_forwards.push(request);
                                    recycle_now = false;
                                } else {
                                    let mut created = 0u64;
                                    // #850: DNS-reply fast-path skips session install
                                    // when no NAT is required.  If NAT is required, fall
                                    // through to normal session install so NAT state is
                                    // anchored for GC.
                                    let dns_fastpath_admit =
                                        allow_unsolicited_dns_reply(worker_ctx.forwarding, flow)
                                            && decision.nat.rewrite_src.is_none()
                                            && decision.nat.rewrite_dst.is_none()
                                            && !decision.nat.nat64
                                            && !decision.nat.nptv6;
                                    let track_in_userspace = decision.resolution.disposition
                                        != ForwardingDisposition::LocalDelivery
                                        && !dns_fastpath_admit;
                                    let install_local_reverse =
                                        should_install_local_reverse_session(
                                            decision,
                                            fabric_ingress,
                                        );
                                    // #1861 §5.2: transaction boundary for the
                                    // forward+reverse install pair. The table is
                                    // per-worker single-threaded, so a passing
                                    // preflight makes both installs below
                                    // infallible within this descriptor
                                    // iteration. On refusal: roll back the SNAT
                                    // allocation (same call shape as the old
                                    // failure arm), count, and DROP the trigger
                                    // packet (Junos parity: session-creation
                                    // failure ⇒ packet dropped) — skipping the
                                    // reverse install, the forwarding block,
                                    // and the flow-cache population.
                                    // `needed == 0` is the tracking-not-required
                                    // case (DNS fast-path, LocalDelivery): no
                                    // install is attempted and nothing changes.
                                    let needed_sessions = usize::from(track_in_userspace)
                                        + usize::from(track_in_userspace && install_local_reverse);
                                    if needed_sessions > 0 && !sessions.can_admit(needed_sessions) {
                                        sessions.note_admission_refused();
                                        rollback_source_nat_allocation_for_worker(
                                            &worker_ctx.forwarding.iface_nat_allocators,
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                        // #4381: also roll back any NAT64 pool
                                        // port (self-gated on `nat.nat64`).
                                        crate::nat64::rollback_nat64_allocation_for_worker(
                                            &worker_ctx.forwarding.nat64,
                                            &flow.forward_key,
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    // #3322: bind the admitting rule's shared
                                    // hit counter ONCE here, where
                                    // `policy_result.policy_counter_idx` still
                                    // indexes the rule that just admitted this
                                    // flow. Carried on both session entries and
                                    // the flow-cache entry so a later live
                                    // policy reorder cannot re-point the count.
                                    let bound_policy_counter = worker_ctx
                                        .forwarding
                                        .policy
                                        .hit_counter_by_idx(policy_result.policy_counter_idx)
                                        .cloned();
                                    let forward_metadata = SessionMetadata {
                                        ingress_zone: from_zone_id,
                                        egress_zone: to_zone_id,
                                        // #4983: stamp the session's TRUE ingress identity from the frame that
                                        // created it — the binding it was actually received on plus its 802.1Q
                                        // tag. Recorded ONCE here and never re-derived from the zone, which is
                                        // the approximation `show/clear security flow session interface <name>`
                                        // is being freed from.
                                        ingress_ifindex: meta.ingress_ifindex,
                                        ingress_vlan_id: meta.ingress_vlan_id,
                                        owner_rg_id,
                                        fabric_ingress,
                                        is_reverse: false,
                                        nat64_reverse: nat64_info,
                                        // #2508: stamp the admitting policy's
                                        // per-policy RT_FLOW SYSLOG log selection.
                                        log_session_init: policy_result.log_session_init,
                                        log_session_close: policy_result.log_session_close,
                                        // #3056: stamp the admitting policy's ID so
                                        // the live-session BPF-compat publish and the
                                        // SESSION_CREATE RT_FLOW record reference the
                                        // policy that admitted the flow (was the `0`
                                        // sentinel → first-configured-policy misattribution).
                                        policy_id: policy_result.policy_id,
                                        // #3227: stamp the matched application term's
                                        // per-application inactivity (idle) timeout
                                        // (seconds -> ns; None = use the global
                                        // per-protocol timeout) so the conntrack GC
                                        // ages this flow out on the app's value,
                                        // closing the legacy-eBPF appTimeout parity
                                        // regression.
                                        inactivity_timeout_ns:
                                            crate::session::app_inactivity_timeout_ns(
                                                policy_result.inactivity_timeout,
                                            ),
                                        // #3073: stamp the admitting rule's hit-counter
                                        // handle so the established fast path re-counts
                                        // every forward packet of this flow.
                                        policy_counter_idx: policy_result.policy_counter_idx,
                                        // #3322: the reorder-stable bound handle.
                                        policy_counter: bound_policy_counter.clone(),
                                    };
                                    // #3073: carry the admitting rule's handle so
                                    // the flow-cache entry populated for this new
                                    // flow re-counts its cached packets. #3322:
                                    // also carry the bound handle.
                                    flow_cache_policy_counter_idx =
                                        policy_result.policy_counter_idx;
                                    flow_cache_policy_counter = bound_policy_counter.clone();
                                    let forward_installed = track_in_userspace
                                        && sessions.install_with_protocol_with_origin(
                                            flow.forward_key.clone(),
                                            decision,
                                            forward_metadata.clone(),
                                            SessionOrigin::ForwardFlow,
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        );
                                    if track_in_userspace && !forward_installed {
                                        // #1861 §5.2 residual: impossible by
                                        // construction after a passing
                                        // can_admit (cap is the only install
                                        // failure mode; nothing mutates the
                                        // table mid-iteration). Debug: loud.
                                        // Release (#1855 contract): count,
                                        // roll back, drop — never half-commit.
                                        debug_assert!(
                                            false,
                                            "forward install failed after can_admit preflight"
                                        );
                                        sessions.note_install_partial();
                                        rollback_source_nat_allocation_for_worker(
                                            &worker_ctx.forwarding.iface_nat_allocators,
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                        // #4381: also roll back any NAT64 pool
                                        // port (self-gated on `nat.nat64`).
                                        crate::nat64::rollback_nat64_allocation_for_worker(
                                            &worker_ctx.forwarding.nat64,
                                            &flow.forward_key,
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                        binding.scratch.scratch_recycle.push(desc.addr);
                                        continue;
                                    }
                                    if forward_installed {
                                        created += 1;
                                        // #2218: count the per-rule NAT
                                        // translation hit ONCE per committed
                                        // translated forward flow. This is
                                        // the cold-path success point — past
                                        // every rollback door (ICMP-TE
                                        // bounce, max_sessions refusal,
                                        // install-partial), so a rolled-back
                                        // SNAT allocation is never counted.
                                        // DNAT/static-DNAT and SNAT/static-
                                        // SNAT counters are independent Arcs;
                                        // a DNAT+SNAT flow bumps both.
                                        let nat_hit_len = desc.len as u64;
                                        if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        if let Some(c) = source_nat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        // #5689: install the ordinary same-family
                                        // NAT / NPTv6 fragment association for a
                                        // FIRST fragment of this now-committed
                                        // flow, so its non-first fragments inherit
                                        // this translation on the flowless arm
                                        // (address-only L3 rewrite) instead of
                                        // being forwarded UNTRANSLATED. No-op
                                        // unless this packet is a first fragment
                                        // (offset 0, MF=1) carrying a same-family
                                        // rewrite; the cross-family NAT64 path
                                        // installs its own association (with
                                        // reverse info) earlier on the cold path.
                                        if let Some(l3_packet) =
                                            packet_frame.get(meta.l3_offset as usize..)
                                        {
                                            // #5146: publish the NAT64 (cross-
                                            // family) first-fragment association
                                            // ONLY now — the flow has COMMITTED
                                            // (past `can_admit` and a successful
                                            // forward session install). Publishing
                                            // it at source-allocation time left the
                                            // association live behind every
                                            // rollback arm (hop-limit ICMP-TE,
                                            // admission refusal, install-partial),
                                            // and the rollback releases only the
                                            // pool port — so a non-first fragment
                                            // of a rolled-back first fragment
                                            // inherited a rolled-back verdict AND a
                                            // now-reusable translation (#5146). Both
                                            // helpers self-gate (NAT64 vs ordinary
                                            // same-family), so exactly one fires for
                                            // a given committed first fragment.
                                            // #5798: stamp the association with the
                                            // ingress domain that ADMITTED this first
                                            // fragment, so only a non-first fragment
                                            // from the SAME domain can inherit it.
                                            let frag_authority = frag_ingress_authority(
                                                worker_ctx.forwarding,
                                                meta,
                                                frag_authority_zone_override,
                                            );
                                            nat64_install_forward_fragment_assoc(
                                                worker_ctx.forwarding,
                                                l3_packet,
                                                meta.addr_family as i32,
                                                frag_authority,
                                                &decision,
                                                now_ns,
                                            );
                                            nat_install_forward_fragment_assoc(
                                                worker_ctx.forwarding,
                                                l3_packet,
                                                meta.addr_family as i32,
                                                frag_authority,
                                                &decision,
                                                now_ns,
                                            );
                                        }
                                        let forward_entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision,
                                            metadata: forward_metadata,
                                            origin: SessionOrigin::ForwardFlow,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                            // Local forward-flow learn (#2170): no peer gen.
                                            generation: 0,
                                            // #5212: local-origin shared publish; the id
                                            // rides the wire off the live entry via the
                                            // Open delta, not this replica (0 here).
                                            session_id: 0,
                                        };
                                        // #1789: count failed publishes so
                                        // map-at-capacity / stale-fd
                                        // failures are visible in release
                                        // builds (was `let _ =`).
                                        if publish_live_session_entry(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            decision.nat,
                                            false,
                                        )
                                        .is_err()
                                        {
                                            binding
                                                .live
                                                .session_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        // #4800: the single place a locally
                                        // learned transit forward flow is
                                        // installed — count it per binding so
                                        // the per-worker distribution of the
                                        // allocate/publish/replicate work is
                                        // observable, not inferred.
                                        binding
                                            .live
                                            .new_flow_installs
                                            .fetch_add(1, Ordering::Relaxed);
                                        // #6965: mirror the TRANSIT forward
                                        // session into the kernel-visible
                                        // conntrack map. Until this call
                                        // existed, `publish_bpf_conntrack_entry`
                                        // was reached only from the host-inbound
                                        // LocalMiss install, the
                                        // MissingNeighborSeed install and the
                                        // reverse-companion repair — so the
                                        // DOMINANT population, ordinary transit
                                        // flows, had NO row in the map that
                                        // `show security flow session`
                                        // enumerates. Not a row with a zeroed
                                        // identity: no row at all, which is why
                                        // #6656 saw 33 sessions on a node
                                        // carrying 4.6M rx packets.
                                        //
                                        // FORWARD ONLY. The reverse companion
                                        // installed below deliberately gets no
                                        // row: every `show`/`clear` call site
                                        // skips `IsReverse != 0` before
                                        // filtering, so a reverse row costs a
                                        // syscall per connection and can never
                                        // surface a flow. The forward row
                                        // already carries BOTH directions'
                                        // counters (#2501).
                                        //
                                        // Cost: one `bpf_map_update_elem` on
                                        // the new-flow path, which already
                                        // performs several (the steering
                                        // publish above is 1-4, `dnat_table`
                                        // below is 1). Measured at ~1.1-1.4us,
                                        // indistinguishable per-call from the
                                        // steering writes it joins — see
                                        // docs/log/6965.md.
                                        //
                                        // #2008 M5 / #3321 / #3416: directional
                                        // app resolution off the POST-DNAT
                                        // destination, identical to the
                                        // neighbor-seed site.
                                        let ct_app_id = worker_ctx
                                            .forwarding
                                            .app_catalog
                                            .lookup_admitted(
                                                flow.forward_key.protocol,
                                                flow.forward_key.src_port,
                                                flow.forward_key.dst_port,
                                                forward_entry.metadata.is_reverse,
                                                decision.nat.rewrite_dst_port,
                                            );
                                        // #5213: the stable id of the session
                                        // just installed, so the mirrored row
                                        // reports the SAME id RT_FLOW emits.
                                        let ct_session_id =
                                            sessions.session_id_for(&flow.forward_key);
                                        publish_bpf_conntrack_entry(
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            &flow.forward_key,
                                            decision,
                                            &forward_entry.metadata,
                                            &worker_ctx.forwarding.zone_name_to_id,
                                            worker_ctx.forwarding.alg_disable_flags,
                                            ct_app_id,
                                            ct_session_id,
                                        );
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &forward_entry,
                                        );
                                        // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                        // Without this, mtr/traceroute intermediate hops are invisible.
                                        // #2244: a failed map publish silently loses the reverse
                                        // record — count it so map pressure is operator-visible.
                                        if !publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            decision.nat,
                                        ) {
                                            binding
                                                .live
                                                .dnat_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        replicate_session_upsert(
                                            worker_ctx.peer_worker_commands,
                                            &forward_entry,
                                        );
                                        // #2617: the input-filter `then log`
                                        // emit moved to the single early site at
                                        // the accept fall-through (~L876), so it
                                        // now fires once per miss packet across
                                        // every accept exit (forward,
                                        // local-delivery, install-refused). The
                                        // former per-install emit here would
                                        // double-log a successfully installed
                                        // ForwardCandidate flow once the early
                                        // site is in place.
                                    } else {
                                        // #1861: only reachable when
                                        // track_in_userspace == false (a true
                                        // install failure now drops above) —
                                        // no session anchors the NAT state, so
                                        // release any allocation. No-op for the
                                        // DNS fast-path (its guard requires no
                                        // NAT).
                                        rollback_source_nat_allocation_for_worker(
                                            &worker_ctx.forwarding.iface_nat_allocators,
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                        // #4381: also release any NAT64 pool port
                                        // when no session anchors it (self-gated
                                        // on `nat.nat64`).
                                        crate::nat64::rollback_nat64_allocation_for_worker(
                                            &worker_ctx.forwarding.nat64,
                                            &flow.forward_key,
                                            decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                    }
                                    let reverse_resolution = reverse_resolution_for_session(
                                        worker_ctx.forwarding,
                                        worker_ctx.ha_state,
                                        worker_ctx.dynamic_neighbors,
                                        flow.src_ip,
                                        from_zone_id,
                                        fabric_ingress,
                                        now_secs,
                                        false,
                                    );
                                    // Install the reverse entry even if the initial reply-side
                                    // resolution is not immediately usable. On live traffic the
                                    // first server reply can arrive before the reverse neighbor
                                    // state has converged on every worker, and dropping the reverse
                                    // entry creation turns that race into a hard policy miss. The
                                    // hit path re-resolves on demand and can fall back to the
                                    // cached decision when neighbor convergence is still in flight.
                                    let reverse_decision = SessionDecision {
                                        resolution: reverse_resolution,
                                        nat: decision.nat.reverse(
                                            flow.src_ip,
                                            flow.dst_ip,
                                            flow.forward_key.src_port,
                                            flow.forward_key.dst_port,
                                        ),
                                    };
                                    // For NAT64: the reverse key is IPv4 (different AF
                                    // from the forward IPv6 key). The reply arrives as
                                    // IPv4: src=dst_v4, dst=snat_v4.
                                    let (reverse_key, reverse_protocol) = if nat64_info.is_some() {
                                        let nat = decision.nat;
                                        let dst_v4 = match nat.rewrite_dst {
                                            Some(IpAddr::V4(v4)) => v4,
                                            _ => Ipv4Addr::UNSPECIFIED,
                                        };
                                        let snat_v4 = match nat.rewrite_src {
                                            Some(IpAddr::V4(v4)) => v4,
                                            _ => Ipv4Addr::UNSPECIFIED,
                                        };
                                        // Map protocol: ICMPv6→ICMP for the reverse key.
                                        let rev_proto = match meta.protocol {
                                            PROTO_ICMPV6 => PROTO_ICMP,
                                            p => p,
                                        };
                                        // #4381: the reply's L4 field the server
                                        // replies TO is the UNIQUE translated
                                        // source port / echo identifier (carried
                                        // in `rewrite_src_port`), NOT the
                                        // original v6 client value. The reverse
                                        // key must therefore key on the
                                        // translated value or the reply misses
                                        // the session. For TCP/UDP the reply's
                                        // destination port is the translated
                                        // port; for ICMP echo the reply's
                                        // identifier (mapped to `src_port` by
                                        // `parse_flow_ports`) is the translated
                                        // id.
                                        let translated_l4 = nat
                                            .rewrite_src_port
                                            .unwrap_or(flow.forward_key.src_port);
                                        let (src_port, dst_port) =
                                            if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
                                                (translated_l4, flow.forward_key.dst_port)
                                            } else {
                                                (flow.forward_key.dst_port, translated_l4)
                                            };
                                        (
                                            SessionKey {
                                                addr_family: libc::AF_INET as u8,
                                                protocol: rev_proto,
                                                src_ip: IpAddr::V4(dst_v4),
                                                dst_ip: IpAddr::V4(snat_v4),
                                                src_port,
                                                dst_port,
                                            },
                                            rev_proto,
                                        )
                                    } else {
                                        (flow.reverse_key_with_nat(decision.nat), meta.protocol)
                                    };
                                    let _ = reverse_protocol; // used below for install
                                    let reverse_metadata = SessionMetadata {
                                        ingress_zone: to_zone_id,
                                        egress_zone: from_zone_id,
                                        // #4983: the reverse companion has NO ingress identity of its own —
                                        // the reply's ingress has not been OBSERVED yet, and routing may be
                                        // asymmetric, so there is nothing truthful to stamp. Note the forward
                                        // flow's egress IS available here (`decision.resolution.egress_ifindex`,
                                        // resolved above); it is simply the wrong datum, being a prediction of
                                        // where the reply will arrive rather than an observation of where it
                                        // did. Stamping either it or the forward frame's own ingress would put
                                        // a confident value on an unobserved binding. Left 0 = "no identity
                                        // carried"; the Go filter falls back to the zone approximation.
                                        ingress_ifindex: 0,
                                        ingress_vlan_id: 0,
                                        owner_rg_id,
                                        fabric_ingress,
                                        is_reverse: true,
                                        nat64_reverse: nat64_info,
                                        // #2508: mirror the admitting policy's log
                                        // selection onto the reverse entry so the
                                        // close delta carries a consistent gate
                                        // regardless of which entry expires it.
                                        log_session_init: policy_result.log_session_init,
                                        log_session_close: policy_result.log_session_close,
                                        // #3056: mirror the admitting policy ID onto
                                        // the reverse companion so a row keyed on the
                                        // reverse tuple attributes the same policy.
                                        policy_id: policy_result.policy_id,
                                        // #3227: mirror the matched application term's
                                        // per-application inactivity (idle) timeout onto
                                        // the reverse entry so whichever entry the GC
                                        // expires uses the app's idle window.
                                        inactivity_timeout_ns:
                                            crate::session::app_inactivity_timeout_ns(
                                                policy_result.inactivity_timeout,
                                            ),
                                        // #3073: mirror the admitting rule's hit-counter
                                        // handle onto the reverse companion so reply
                                        // traffic of the flow counts against the same
                                        // policy as the forward direction. #3322:
                                        // mirror the reorder-stable bound handle too.
                                        policy_counter_idx: policy_result.policy_counter_idx,
                                        policy_counter: bound_policy_counter.clone(),
                                    };
                                    // #1861 §5.2: the reverse install is gated on
                                    // forward_installed (was track_in_userspace —
                                    // a forward failure used to fall through and
                                    // still attempt the reverse, the latent
                                    // half-open-reverse hazard). At this point
                                    // track_in_userspace ⇒ forward_installed
                                    // (the residual arm above drops otherwise),
                                    // so this gate is explicit, not a behavior
                                    // fork.
                                    let reverse_installed = forward_installed
                                        && install_local_reverse
                                        && sessions.install_with_protocol_with_origin(
                                            reverse_key.clone(),
                                            reverse_decision,
                                            reverse_metadata.clone(),
                                            SessionOrigin::ReverseFlow,
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        );
                                    if forward_installed
                                        && install_local_reverse
                                        && !reverse_installed
                                    {
                                        // #1861 §5.2 residual (reverse half):
                                        // impossible after a passing can_admit
                                        // for needed_sessions == 2. Release
                                        // (#1855 contract): keep the committed
                                        // forward (the reply repair services
                                        // inbound), count, and suppress the
                                        // flow-cache entry so the partially-
                                        // installed flow is re-evaluated per
                                        // packet instead of being persisted.
                                        debug_assert!(
                                            false,
                                            "reverse install failed after can_admit preflight"
                                        );
                                        sessions.note_install_partial();
                                        flow_cache_install_failed = true;
                                    }
                                    if reverse_installed {
                                        // #1789: count failed reverse-key
                                        // publishes (was `let _ =`; the
                                        // debug-only verify below re-reads
                                        // the map and cannot see the Err).
                                        if publish_live_session_key(
                                            binding.bpf_maps.session_map_fd,
                                            &reverse_key,
                                        )
                                        .is_err()
                                        {
                                            binding
                                                .live
                                                .session_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        // Verify session keys and log creations (debug-only: BPF syscalls)
                                        if cfg!(feature = "debug-log") {
                                            if verify_session_key_in_bpf(
                                                binding.bpf_maps.session_map_fd,
                                                &reverse_key,
                                            ) {
                                                SESSION_PUBLISH_VERIFY_OK
                                                    .fetch_add(1, Ordering::Relaxed);
                                            } else {
                                                SESSION_PUBLISH_VERIFY_FAIL
                                                    .fetch_add(1, Ordering::Relaxed);
                                                debug_log!(
                                                    "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
                                                             af={} proto={} {}:{} -> {}:{} (map_fd={})",
                                                    reverse_key.addr_family,
                                                    reverse_key.protocol,
                                                    reverse_key.src_ip,
                                                    reverse_key.src_port,
                                                    reverse_key.dst_ip,
                                                    reverse_key.dst_port,
                                                    binding.bpf_maps.session_map_fd,
                                                );
                                            }
                                            if !verify_session_key_in_bpf(
                                                binding.bpf_maps.session_map_fd,
                                                &flow.forward_key,
                                            ) {
                                                debug_log!(
                                                    "SESS_VERIFY_FAIL: forward key NOT found! \
                                                             af={} proto={} {}:{} -> {}:{}",
                                                    flow.forward_key.addr_family,
                                                    flow.forward_key.protocol,
                                                    flow.forward_key.src_ip,
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_ip,
                                                    flow.forward_key.dst_port,
                                                );
                                            }
                                            let logged = SESSION_CREATIONS_LOGGED
                                                .fetch_add(1, Ordering::Relaxed);
                                            if logged < 10 {
                                                debug_log!(
                                                    "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
                                                             | REV af={} proto={} {}:{} -> {}:{} \
                                                             | NAT src={:?} dst={:?} \
                                                             | map_fd={} bpf_entries={}",
                                                    logged,
                                                    flow.forward_key.addr_family,
                                                    flow.forward_key.protocol,
                                                    flow.forward_key.src_ip,
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_ip,
                                                    flow.forward_key.dst_port,
                                                    reverse_key.addr_family,
                                                    reverse_key.protocol,
                                                    reverse_key.src_ip,
                                                    reverse_key.src_port,
                                                    reverse_key.dst_ip,
                                                    reverse_key.dst_port,
                                                    decision.nat.rewrite_src,
                                                    decision.nat.rewrite_dst,
                                                    binding.bpf_maps.session_map_fd,
                                                    count_bpf_session_entries(
                                                        binding.bpf_maps.session_map_fd
                                                    ),
                                                );
                                                dump_bpf_session_entries(
                                                    binding.bpf_maps.session_map_fd,
                                                    20,
                                                );
                                            }
                                        }
                                        created += 1;
                                        let reverse_entry = SyncedSessionEntry {
                                            key: reverse_key,
                                            decision: reverse_decision,
                                            metadata: reverse_metadata,
                                            origin: SessionOrigin::ReverseFlow,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                            // Local reverse-flow learn (#2170): no peer gen.
                                            generation: 0,
                                            // #5212: a reverse companion never emits
                                            // RT_FLOW (is_reverse skip) and gets its own
                                            // fresh id at install — no carried id.
                                            session_id: 0,
                                        };
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &reverse_entry,
                                        );
                                        replicate_session_upsert(
                                            worker_ctx.peer_worker_commands,
                                            &reverse_entry,
                                        );
                                    }
                                    if created > 0 {
                                        telemetry.counters.session_creates += created;
                                        telemetry.dbg.session_create += created;
                                    }
                                }
                            } else {
                                // #2089/#3071/#3615: enqueue the deny/reject
                                // reply FIRST, then emit the policy-deny RT_FLOW
                                // with the TRUTHFUL action. `reject` synthesizes
                                // a TCP RST / ICMP unreachable back toward the
                                // source; plain `deny` is a silent drop UNLESS
                                // the flow is TCP and the ingress (from) zone has
                                // Junos `tcp-rst`. When a `reject` reply
                                // fail-closes (budget/rate/parse/output-filter)
                                // the event is downgraded REJECT→DENY so the log
                                // never claims an active reject that was not sent
                                // (#3615). `decision.nat` carries the inbound dst
                                // translation (#2345/#3058); the AppID is
                                // resolved from the POST-translation dst port
                                // (#2520/#3058) so a DNAT'd deny logs the inside
                                // app, not UNKNOWN(pre-NAT port).
                                deny_reply_and_emit(
                                    &mut binding.tx_pipeline,
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    binding.ifindex,
                                    packet_frame,
                                    meta,
                                    flow,
                                    telemetry.counters,
                                    &decision.nat,
                                    from_zone_id,
                                    to_zone_id,
                                    owner_rg_id,
                                    policy_result.policy_id,
                                    policy_result.action,
                                    resolve_policy_deny_app_id(
                                        &worker_ctx.forwarding.app_catalog,
                                        flow,
                                        policy_dst_port,
                                    ),
                                    now_ns,
                                );
                                telemetry.dbg.policy_deny += 1;
                                if cfg!(feature = "debug-log")
                                    && policy_deny_debug_log_allowed(telemetry.dbg.policy_deny)
                                {
                                    debug_log!(
                                        "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                        telemetry.dbg.policy_deny,
                                        flow.src_ip,
                                        flow.forward_key.src_port,
                                        flow.dst_ip,
                                        flow.forward_key.dst_port,
                                        meta.protocol,
                                        from_zone,
                                        to_zone,
                                        meta.ingress_ifindex,
                                        resolution.egress_ifindex,
                                    );
                                }
                                // #3615: the deny/reject reply was enqueued by
                                // `deny_reply_and_emit` above (before the event
                                // emit) so the RT_FLOW action reflects the actual
                                // reply outcome.
                                decision.resolution.disposition =
                                    ForwardingDisposition::PolicyDenied;
                            }
                        } else if decision.resolution.disposition
                            == ForwardingDisposition::HAInactive
                            && !packet_fabric_ingress
                        {
                            let owner_rg_id =
                                owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                            if owner_rg_id > 0 {
                                flow_cache_owner_rg_id = owner_rg_id;
                            }
                            // New flow to inactive RG: fabric-redirect to the peer
                            // that owns the egress RG.  Use from_zone_arc directly
                            // (always in scope) rather than going through the debug
                            // struct which may not have been populated.
                            // #919/#922: ID-keyed redirect — no name lookup.
                            if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
                                worker_ctx.forwarding,
                                from_zone_id,
                            )
                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                            {
                                decision.resolution = redirect;
                            }
                        }
                        decision
                    }
                } else if let Some(hit) = packet_frame
                    .get(meta.l3_offset as usize..)
                    .and_then(|l3| {
                        // #2562: NAT64 forward non-first fragment fast path. A
                        // cached association (installed by the FIRST fragment on
                        // the cold path above) lets this non-first fragment
                        // inherit the first fragment's permitted verdict, egress
                        // resolution, AND NAT64 translation, so the whole
                        // datagram traverses NAT64 and reassembles at the
                        // receiver instead of the non-first fragments dropping
                        // fail-closed (#4617). A MISS falls through to the normal
                        // flowless L3 enforcement below (which drops an
                        // unassociated NAT64 fragment fail-closed). The consult is
                        // gated on a non-first fragment carrying a NAT64-decision
                        // cache hit, so no other flowless traffic is touched.
                        // #5798: consult under THIS fragment's OWN ingress
                        // authority. A fragment from a different security domain
                        // that merely reproduces (src, dst, ident) now builds a
                        // DIFFERENT key, misses, and falls through to the full
                        // enforcement arm below under its real identity — instead
                        // of inheriting the first domain's permit + egress + NAT.
                        // Here `ingress_zone_override` is still the RAW stamp (the
                        // RG-gated shadow is bound later, in the miss arm), which
                        // is the same value the install captured.
                        let frag_authority = frag_ingress_authority(
                            worker_ctx.forwarding,
                            meta,
                            ingress_zone_override,
                        );
                        nat64_consult_forward_fragment_assoc(
                            worker_ctx.forwarding,
                            l3,
                            meta.addr_family as i32,
                            frag_authority,
                            now_ns,
                            worker_ctx.ha_state,
                            now_secs,
                        )
                        // #5689: fall back to the ORDINARY same-family NAT /
                        // NPTv6 fragment association so a non-first fragment of
                        // a SNAT/DNAT/static-NAT/NPTv6 flow inherits its
                        // translation (address-only L3 rewrite) instead of being
                        // forwarded UNTRANSLATED (the #5689 leak). NAT64
                        // (cross-family) is tried first; a given datagram
                        // installs exactly one association, so at most one
                        // consult returns a hit.
                        .or_else(|| {
                            nat_consult_forward_fragment_assoc(
                                worker_ctx.forwarding,
                                l3,
                                meta.addr_family as i32,
                                frag_authority,
                                now_ns,
                                worker_ctx.ha_state,
                                now_secs,
                            )
                        })
                    })
                {
                    // #5798 (required-fix #4): an association HIT may inherit the
                    // first fragment's STATEFUL zone-policy permit + NAT
                    // translation + egress route — but it must NOT inherit
                    // per-packet INTERFACE INPUT FILTER semantics. The input
                    // filter is evaluated per packet, and a non-first fragment
                    // carries its own L3 identity, so a `from is-fragment then
                    // discard` (or address / protocol) term must still catch it.
                    //
                    // Before this gate the filter ran ONLY in the miss `else`
                    // branch below, so even a correctly-authority-scoped
                    // SAME-domain hit skipped it entirely — the authority key
                    // alone does NOT close this half of the defect.
                    //
                    // Evaluated with the SAME inputs, in the same shape, as the
                    // miss branch's copy below (frame-derived `extra` carrying
                    // is_fragment + l4_present=false, the RAW pre-RG-gate
                    // `ingress_zone_override` that site also uses) so hit and
                    // miss cannot diverge on what the filter sees. Screen /
                    // IPsec are NOT repeated here: `stage_screen_check` already
                    // runs earlier in this loop for every packet, hit or miss.
                    let hit_l3_ctx = crate::afxdp::frame::l3_session_flow_from_meta(meta);
                    if let Some(l3_flow) = hit_l3_ctx.as_ref() {
                        let input_eval = evaluate_non_pbr_input_filter(
                            worker_ctx.forwarding,
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
                            Some(l3_flow),
                            meta,
                            ingress_zone_override,
                            // #2620 counter ownership. #6835: `true`, because a
                            // routing evaluator DOES follow on this arm now —
                            // `ingress_route_table_override` runs below. Before
                            // #6835 nothing followed, so `false` (`Always`) was
                            // correct and `true` would have deferred this
                            // fragment's `then count` terms to an evaluator that
                            // never ran. Now the reverse is true: `false` would
                            // count every matched term TWICE (once here under
                            // `Always`, once in the routing walk, which counts
                            // every matched term unconditionally). This is the
                            // same value, for the same reason, as the miss arm
                            // below.
                            true,
                        );
                        if let Some(cached_log) = input_eval.cached_log {
                            emit_input_filter_log_match(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                l3_flow,
                                meta,
                                cached_log,
                                // A flowless deny is always a SILENT drop (no L4
                                // to synthesize a reject from), so a `then reject`
                                // term logs the truthful DENY — same contract as
                                // the miss branch (#3615).
                                false,
                                now_ns,
                            );
                        }
                        if input_eval.action != crate::filter::FilterAction::Accept {
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // #6835: and the PBR half of the same filter. A matching
                        // term with a non-empty `routing-instance` makes
                        // `evaluate_non_pbr_input_filter` return
                        // `FilterResult::default()` — BEFORE recording its
                        // counter and BEFORE applying its action — and that
                        // default action is `Accept`. So a configured
                        // `from { is-fragment; } then { routing-instance scrub;
                        // discard; count X; }` was silently ACCEPTED on an
                        // association hit, and `X` stayed at zero: a reachable
                        // configured drop guard that could not fire, and no
                        // counter to notice it by. The PBR verdict lives in the
                        // routing-instance evaluator, which only
                        // `ingress_route_table_override` runs.
                        //
                        // Same call shape as the miss arm below, including the
                        // sink-less flowless contract: a non-first fragment has
                        // no L4 header to reflect, so `reject` degrades to the
                        // same silent drop as `discard`.
                        match ingress_route_table_override(
                            worker_ctx.forwarding,
                            packet_frame,
                            meta,
                            l3_flow,
                            ingress_zone_override,
                            worker_ctx.event_stream,
                            now_ns,
                            None,
                        ) {
                            RouteOverride::Drop => {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            // A non-drop PBR steer is DELIBERATELY not applied
                            // here. An association hit exists to inherit the
                            // first fragment's forwarding decision — egress,
                            // neighbor and NAT translation — for the rest of the
                            // datagram; re-steering only the non-first fragments
                            // into an override table would split one datagram
                            // across two egresses and defeat reassembly. What
                            // does NOT get inherited is per-packet ENFORCEMENT,
                            // which is why the drop above applies and why the
                            // term's counter/log were recorded by the call.
                            RouteOverride::Table(_) | RouteOverride::None => {}
                        }
                    }
                    // #6835: an association hit inherits the STATEFUL decision,
                    // never the per-packet authorization behind it. Owner-RG
                    // activity is per-packet: after an RG transition the old
                    // owner still hits a same-generation association, and
                    // because every hit re-stamps the entry's deadline the stale
                    // ownership was indefinitely renewable. The guard that
                    // demotes an inactive owner to `HAInactive` sat only on the
                    // miss path's resolution, so it could never fire here. Run
                    // it on the cached resolution too; the shared HAInactive
                    // safety net below then fabric-redirects to the peer that
                    // now owns the egress RG, exactly as it does for a demoted
                    // session.
                    let mut hit = hit;
                    hit.resolution = enforce_ha_resolution_snapshot(
                        worker_ctx.forwarding,
                        worker_ctx.ha_state,
                        now_secs,
                        hit.resolution,
                    );
                    hit
                } else {
                    // #6472: NAT64 (cross-family) ICMP error translation
                    // (RFC 7915 §4.2/§5.2), wired HERE on the flowless arm —
                    // the path an ICMP error actually takes (#3290 below).
                    // Tried BEFORE the same-family #5690 reversal and NOT
                    // gated on `allow_embedded_icmp`: translating errors for
                    // the translator's OWN admitted sessions is core NAT64
                    // behavior, and the same-family arm's NAT64 matches
                    // decline anyway (its single-family builders reject a
                    // cross-family `original_src`), so nothing it serves is
                    // stolen. A non-NAT64 deployment exits on the
                    // empty-prefix gate before any parse; a match queues the
                    // translated error as a prebuilt forward and consumes
                    // the descriptor; a miss falls through to the #5690
                    // reversal and normal flowless enforcement, unchanged.
                    let is_nat64_icmp_error = !worker_ctx.forwarding.nat64.prefixes.is_empty()
                        && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
                        && packet_frame
                            .get(meta.l4_offset as usize)
                            .copied()
                            .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
                            .unwrap_or(false);
                    if is_nat64_icmp_error {
                        match try_translate_nat64_icmp_error(
                            desc,
                            raw_frame,
                            meta,
                            binding_index,
                            sessions,
                            worker_ctx,
                            &mut binding.scratch.scratch_forwards,
                            now_ns,
                            now_secs,
                        ) {
                            EmbeddedIcmpReversal::Queued => {
                                telemetry.counters.touched = true;
                                continue;
                            }
                            EmbeddedIcmpReversal::Dropped => {
                                telemetry.counters.touched = true;
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            EmbeddedIcmpReversal::NotHandled => {}
                        }
                    }
                    // #5690: an inbound non-query ICMP error referencing a NAT'd
                    // flow is FLOWLESS (#3290 discards its metadata pseudo-port so
                    // it never seeds a session). Attempt the generic embedded-ICMP
                    // NAT reversal HERE, on the path these errors actually take:
                    // reverse-translate the inner quoted packet back to the
                    // pre-NAT tuple and forward the error to the real internal
                    // host. A match rebuilds + queues the reversed error and
                    // consumes the descriptor; a miss / no-rewrite / unbuildable
                    // frame falls through to the normal flowless L3 enforcement
                    // below. The reversal was previously wired only into the
                    // flow-backed session-miss arm and could never run in
                    // production (an ICMP error never has a flow), so the
                    // capability was helper-tested but dead; wiring it here makes
                    // it live. #5140-safe classification: read the INNER ICMP type
                    // from `packet_frame` (decapped post native-GRE, else
                    // `raw_frame`) at the inner-relative `meta.l4_offset`.
                    let is_embedded_icmp_error = worker_ctx.forwarding.allow_embedded_icmp
                        && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
                        && packet_frame
                            .get(meta.l4_offset as usize)
                            .copied()
                            .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
                            .unwrap_or(false);
                    if is_embedded_icmp_error {
                        match try_reverse_embedded_icmp_error(
                            // SAFETY: per the `area` contract in this function's
                            // header comment.
                            unsafe { &*area },
                            desc,
                            raw_frame,
                            meta,
                            binding_index,
                            sessions,
                            worker_ctx,
                            &mut binding.scratch.scratch_forwards,
                            now_ns,
                            now_secs,
                        ) {
                            EmbeddedIcmpReversal::Queued => {
                                // Reversed error queued as a prebuilt forward; the
                                // descriptor is owned by that request (no recycle).
                                telemetry.counters.touched = true;
                                continue;
                            }
                            EmbeddedIcmpReversal::Dropped => {
                                // Matched but egress CoS / output-filter dropped
                                // the reversed error — fail-closed silent drop
                                // (never answer an ICMP error with an ICMP error).
                                telemetry.counters.touched = true;
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            // No NAT match / no source rewrite / unbuildable frame:
                            // fall through to the normal flowless enforcement below.
                            EmbeddedIcmpReversal::NotHandled => {}
                        }
                    }
                    // #3291: flowless transit enforcement. A non-first fragment
                    // / no-L4 transit packet (#2344 makes it flowless so payload
                    // bytes are never read as L4 ports) STILL carries L3 identity
                    // — src/dst/protocol/zones/ingress interface — so it must be
                    // subject to the interface input filter, firewall-filter PBR
                    // (`then routing-instance`), and zone security policy exactly
                    // like the flow-backed session-miss arm above. Without this a
                    // `deny-all` zone pair fails OPEN for fragments (it resolves a
                    // route and forwards). The synthetic L3 flow below carries
                    // ports = 0 and drives `l4_present = false`, so port-bearing
                    // application / filter terms FAIL CLOSED; it is used ONLY for
                    // enforcement + logging and is NEVER inserted into a session
                    // index (#3290 invariant). Permitted address/protocol/`any`
                    // policy still forwards the fragment — legitimate flowless
                    // forwarding is preserved. (L4-specific-PERMITTED fragmented
                    // flows are the deferred fragment-association-cache stage of
                    // the #3291 plan; until then their non-first fragments fall to
                    // the default policy, the documented fail-closed limitation.)
                    let l3_ctx = crate::afxdp::frame::l3_session_flow_from_meta(meta);

                    // (1) Interface input filter (pre-routing), mirroring the
                    //     session-miss site above. The frame-derived `extra`
                    //     carries `is_fragment` + `l4_present = false`, so a
                    //     `from is-fragment then discard` term matches while
                    //     tcp-flags / icmp-type / flex predicates fail closed. No
                    //     filter configured => Accept (no behavior change).
                    if let Some(l3_flow) = l3_ctx.as_ref() {
                        let input_eval = evaluate_non_pbr_input_filter(
                            worker_ctx.forwarding,
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
                            Some(l3_flow),
                            meta,
                            ingress_zone_override,
                            true,
                        );
                        if let Some(cached_log) = input_eval.cached_log {
                            emit_input_filter_log_match(
                                worker_ctx.forwarding,
                                worker_ctx.event_stream,
                                l3_flow,
                                meta,
                                cached_log,
                                // #3615: a flowless (non-first fragment / no-L4)
                                // deny is ALWAYS a silent drop — no reply can be
                                // synthesized — so a `then reject` term logs the
                                // truthful DENY (reject_reply_enqueued = false).
                                false,
                                now_ns,
                            );
                        }
                        if input_eval.action != crate::filter::FilterAction::Accept {
                            // A flowless deny is SILENT: a non-first fragment has
                            // no L4 header to synthesize a TCP RST / reject from,
                            // so both `discard` and `reject` drop quietly.
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                    }

                    // (2) PBR `then routing-instance` override + base resolution.
                    //     When a PBR term matches a flowless predicate
                    //     (is-fragment / address / protocol) the route lookup is
                    //     steered to the override table; otherwise fall back to
                    //     the existing default-table resolve.
                    //
                    //     #3292 / #3600 review Note 2: try INGRESS-interface and
                    //     interface-NAT LOCAL-delivery resolution BEFORE applying
                    //     the PBR override, mirroring the flow-backed session-miss
                    //     arm. A host-bound flowless packet (dst = a firewall
                    //     interface IP) that also matches a PBR `routing-instance`
                    //     term must reach LocalDelivery, NOT be steered into an
                    //     override table that has no local route (→ NoRoute →
                    //     drop). The override governs only the transit fallback.
                    // #4392: on the flowless path a PBR `then { routing-instance
                    // X; reject | discard; }` term is still a DENY. Pass no
                    // reject sink — a flowless deny is a silent drop (a non-first
                    // fragment / L3-only packet has no L4 header to reflect),
                    // identical to the flowless non-PBR input-filter deny above.
                    // On `RouteOverride::Drop` recycle the frame and skip the
                    // override/route-lookup/forward.
                    let route_table_override = match l3_ctx
                        .as_ref()
                        .map(|l3_flow| {
                            ingress_route_table_override(
                                worker_ctx.forwarding,
                                packet_frame,
                                meta,
                                l3_flow,
                                ingress_zone_override,
                                worker_ctx.event_stream,
                                now_ns,
                                None,
                            )
                        })
                        .unwrap_or(RouteOverride::None)
                    {
                        RouteOverride::Drop => {
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        RouteOverride::Table(table) => Some(table),
                        RouteOverride::None => None,
                    };
                    let base_resolution = match l3_ctx.as_ref() {
                        Some(l3_flow) => flowless_base_resolution(
                            worker_ctx.forwarding,
                            worker_ctx.dynamic_neighbors,
                            worker_ctx.ha_state,
                            now_secs,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                            meta.protocol,
                            l3_flow.dst_ip,
                            route_table_override.as_deref(),
                        ),
                        None => enforce_ha_resolution_snapshot(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            resolve_forwarding(
                                // SAFETY: per the `area` contract in this
                                // function's header comment.
                                unsafe { &*area },
                                desc,
                                meta,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                            ),
                        ),
                    };
                    // For non-flow packets (no L4 ports), also attempt fabric
                    // redirect when the egress RG is inactive.
                    let final_resolution = if base_resolution.disposition
                        == ForwardingDisposition::HAInactive
                        && !packet_fabric_ingress
                    {
                        resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(base_resolution)
                    } else {
                        base_resolution
                    };

                    // #6458 V2: honor the zone-encoded fabric stamp for this
                    // flowless enforcement only when the resolution's owner RG
                    // is forwarding-active locally (mirrors the flow-backed
                    // session-miss gate above); otherwise the stamp is ignored
                    // and the fabric interface's own zone governs the transit
                    // policy (3) and host-inbound local-delivery (4) checks.
                    let ingress_zone_override = gate_fabric_zone_override_on_owner_rg(
                        worker_ctx.forwarding,
                        worker_ctx.ha_state,
                        now_secs,
                        ingress_zone_override,
                        final_resolution,
                    );

                    // (3) Zone security policy — only for TRANSIT
                    //     (ForwardCandidate). Local delivery (host-inbound) is
                    //     #3292; NoRoute is NOT adjudicated here and does NOT
                    //     drop — it is slow-path eligible
                    //     (ForwardingDisposition::is_slow_path_eligible) and is
                    //     REINJECTED to the kernel FIB, which forwards it with
                    //     no zone policy, session, NAT or screen. This comment
                    //     claimed "NoRoute drops anyway" until #7409; that was
                    //     false, and being false in the SAFE direction is why
                    //     the gap went unexamined for so long. #7409 narrows the
                    //     exposure by importing kernel-learned routes into the
                    //     helper FIB so NoRoute becomes rare rather than routine,
                    //     but does NOT close it: the FIB is refreshed only on
                    //     commit and ip-monitoring actuation, so a route learned
                    //     between pushes still lands here. Do not "fix" this by
                    //     dropping NoRoute — that black-holes every learned
                    //     destination for the width of that window;
                    //     MissingNeighbor keeps its
                    //     own cold-path arm, which now enforces this SAME zone
                    //     policy on its flowless (flow == None) branch (#4024 —
                    //     before which a flowless MissingNeighbor fragment was
                    //     FIB-reinjected past a deny-all); FabricRedirect is HA
                    //     peer-owned and enforced on the peer. A non-Permit
                    //     verdict is a SILENT
                    //     drop (no L4 header to reject), with a PolicyDeny event
                    //     for observability — same record the flow-backed deny
                    //     emits, with ports = 0.
                    if final_resolution.disposition == ForwardingDisposition::ForwardCandidate
                        && let Some(l3_flow) = l3_ctx.as_ref()
                    {
                        let ingress_logical = resolve_ingress_logical_ifindex(
                            worker_ctx.forwarding,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                        )
                        .unwrap_or(meta.ingress_ifindex as i32);
                        let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                            worker_ctx.forwarding,
                            ingress_logical,
                            ingress_zone_override,
                            final_resolution.egress_ifindex,
                        );
                        // #3020: an icmp-type-constrained application term fails
                        // closed for a non-first fragment (no readable L4 → None).
                        let policy_icmp = policy_packet_icmp(packet_frame, meta);
                        let policy_result = crate::policy::evaluate_policy_result_l3_aware(
                            &worker_ctx.forwarding.policy,
                            from_zone_id,
                            to_zone_id,
                            l3_flow.src_ip,
                            l3_flow.dst_ip,
                            meta.protocol,
                            0,
                            0,
                            policy_icmp,
                            desc.len as u64,
                            // #3291: L4 header ABSENT — port-bearing app terms
                            // fail closed; address/protocol/`any` still match.
                            false,
                        );
                        if !matches!(policy_result.action, PolicyAction::Permit) {
                            let owner_rg_id =
                                owner_rg_for_resolution(worker_ctx.forwarding, final_resolution);
                            emit_policy_deny_event(
                                worker_ctx.event_stream,
                                l3_flow,
                                &NatDecision::default(),
                                meta,
                                from_zone_id,
                                to_zone_id,
                                owner_rg_id,
                                policy_result.policy_id,
                                policy_result.action,
                                // No L4 port for a flowless packet → no AppID.
                                0,
                                // #3615: a flowless (non-first fragment / no-L4)
                                // deny is ALWAYS a silent drop — there is no L4
                                // header to synthesize a RST/ICMP reject from —
                                // so no reply is ever enqueued and a `reject`
                                // must log the truthful DENY.
                                false,
                                now_ns,
                            );
                            telemetry.dbg.policy_deny += 1;
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        // #6122: fail-closed NAT'd non-first-fragment MISS. The
                        // fragment passed policy and would be FORWARDED, but it
                        // reached this flowless arm on a fragment-association
                        // MISS (reorder / eviction / TTL straddle / config-
                        // generation bump / a first fragment that never
                        // forwarded). If its flow WOULD be same-family NAT-
                        // translated (SNAT / static-NAT / DNAT / NPTv6 — matched
                        // on the fragment's L3 identity), forwarding it with the
                        // default (no-NAT) decision below would leak the internal
                        // source (SNAT / NPTv6) or the pre-NAT destination
                        // (DNAT). Drop it fail-closed: the sender retransmits, a
                        // rare reordered fragment ahead of its first is
                        // recoverable, but the leak is not. Scoped to a GENUINE
                        // non-first fragment (a first fragment / full-L4 packet
                        // is NAT-translated on the flow-backed arm and installs
                        // the association, so it never reaches here); a plain
                        // (no-NAT) fragment matches no rule and forwards normally,
                        // preserving ordinary fragmented forwarding.
                        if crate::afxdp::frame::frame_is_non_first_fragment(packet_frame, meta)
                            && flowless_fragment_requires_nat_translation(
                                worker_ctx.forwarding,
                                l3_flow,
                                meta,
                                ingress_zone_override,
                                from_zone_id,
                                to_zone_id,
                                final_resolution.egress_ifindex,
                                now_ns,
                            )
                        {
                            // Dedicated fail-closed observability (sets `touched`
                            // + bumps `nat_frag_untranslated_dropped`); NOT a
                            // policy deny, so `dbg.policy_deny` is left untouched.
                            telemetry.counters.record_nat_frag_untranslated_dropped();
                            binding.scratch.scratch_recycle.push(desc.addr);
                            continue;
                        }
                    }

                    // #6835: the CROSS-FAMILY sibling of the #6122 gate above,
                    // and the one #6122's comment assumed already existed ("its
                    // own consult already drops fail-closed on a miss"). It does
                    // not. `nat64_consult_forward_fragment_assoc` returns `None`
                    // on a miss, which only means "no association" — the packet
                    // then falls through to this arm and is resolved like any
                    // other IPv6 destination. With a default route present that
                    // FORWARDS it, still addressed to the synthetic Pref64
                    // destination and still carrying the client's real IPv6
                    // source. The fail-closed claim held only inside the test
                    // fixture, which deleted `::/0` to keep it holding.
                    //
                    // A Pref64 is a translation namespace, not a forwardable
                    // destination: nothing downstream can deliver
                    // `64:ff9b::8.8.8.8` as native IPv6. So when such a packet
                    // reaches this arm untranslated, refuse it rather than emit
                    // it. Observable through the existing #2562 fail-closed
                    // fragment counter.
                    //
                    // The destination comes from the FRAME, not from `l3_ctx`.
                    // `l3_ctx` is built from `meta.flow_{src,dst}_addr`, which
                    // the shim stamps but a flowless packet need not carry — it
                    // is `None` for exactly the meta-less fragments this gate
                    // exists to stop, so gating on it would have left the leak
                    // open on the majority of them. Placed after the transit
                    // policy block (not inside it) for the same reason, and
                    // scoped to ForwardCandidate: NoRoute/MissingNeighbor/
                    // HAInactive/LocalDelivery have their own arms and none of
                    // them emits the packet natively.
                    if final_resolution.disposition == ForwardingDisposition::ForwardCandidate
                        && let Some(IpAddr::V6(dst_v6)) =
                            crate::afxdp::frame::parse_packet_destination_from_frame(
                                packet_frame,
                                meta,
                            )
                        && worker_ctx
                            .forwarding
                            .nat64
                            .match_ipv6_dest(dst_v6)
                            .is_some()
                    {
                        telemetry.counters.record_nat64_frag_dropped();
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }

                    // (4) #3292: flowless LocalDelivery (host-bound) enforcement.
                    //     A host-bound flowless packet (a non-first fragment / no-
                    //     L4 packet addressed to a firewall interface IP) MUST pass
                    //     the same gates the flow-backed LocalDelivery arm applies:
                    //     host-inbound admission, the lo0 host-bound filter, and
                    //     `to-zone junos-host` policy. Before #3292 this arm
                    //     reinjected to the host ungated (fail-open). The synthetic
                    //     L3 flow is evaluated with l4_present = false (ports = 0),
                    //     so port-bearing terms fail closed while protocol/address/
                    //     `any` still admit — fail-closed without over-gating. A
                    //     flowless deny is SILENT (no L4 header to reject).
                    if final_resolution.disposition == ForwardingDisposition::LocalDelivery
                        && let Some(l3_flow) = l3_ctx.as_ref()
                    {
                        let ingress_logical = resolve_ingress_logical_ifindex(
                            worker_ctx.forwarding,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                        )
                        .unwrap_or(meta.ingress_ifindex as i32);
                        let from_zone_id = zone_pair_ids_for_flow_with_override(
                            worker_ctx.forwarding,
                            ingress_logical,
                            ingress_zone_override,
                            final_resolution.egress_ifindex,
                        )
                        .0;
                        match flowless_local_delivery_verdict(
                            worker_ctx.forwarding,
                            worker_ctx.event_stream,
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
                            l3_flow,
                            meta,
                            // #3609: the host-inbound override map is keyed by
                            // the LOGICAL unit ifindex; pass the resolved value,
                            // not the raw physical bind port.
                            ingress_logical,
                            from_zone_id,
                            ingress_zone_override,
                            desc.len as u64,
                            now_ns,
                        ) {
                            FlowlessLocalVerdict::Deliver => {}
                            FlowlessLocalVerdict::HostInboundDeny => {
                                telemetry.dbg.local += 1;
                                // #3610/M07: own debug counter, not policy_deny.
                                // The tuple-rich host-inbound deny event is emitted
                                // inside `flowless_local_delivery_verdict` (co-
                                // located with the decision, like the junos-host /
                                // lo0 emits there).
                                telemetry.dbg.host_inbound_deny += 1;
                                telemetry.counters.touched = true;
                                // #3326: account the host-inbound deny so
                                // `GlobalCtrHostInboundDeny` reflects the drop.
                                telemetry.counters.host_inbound_denied_packets += 1;
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            FlowlessLocalVerdict::Filtered => {
                                telemetry.dbg.local += 1;
                                telemetry.dbg.policy_deny += 1;
                                telemetry.counters.touched = true;
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                    }
                    SessionDecision {
                        resolution: final_resolution,
                        nat: NatDecision::default(),
                    }
                };
                // Safety net: convert any remaining HAInactive to fabric
                // redirect. Session-hit and new-flow paths each attempt
                // fabric redirect internally, but demoted sessions that
                // arrive via DNAT/interface-NAT XDP shim paths can slip
                // through with HAInactive when the inner conversion found
                // no fabric link at the time. Anti-loop: never redirect
                // packets that arrived on the fabric interface itself.
                // Only redirect when the egress maps to a known RG.
                // HAInactive with unknown ownership (rg=0) means unresolved
                // — those should NOT be fabric-redirected.
                let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                if decision.resolution.disposition == ForwardingDisposition::HAInactive
                    && egress_rg > 0
                    && !packet_fabric_ingress
                {
                    if flow_cache_owner_rg_id <= 0 {
                        flow_cache_owner_rg_id = egress_rg;
                    }
                    // #919: prefer the cached u16 zone ID; fall back to
                    // looking up the ifindex's zone name and translating
                    // to an ID. resolve_zone_encoded_fabric_redirect_by_id
                    // skips the name round-trip.
                    // #921: direct ifindex → u16 (was a two-hop
                    // name round-trip).
                    let zone_id = session_ingress_zone.or_else(|| {
                        worker_ctx
                            .forwarding
                            .ifindex_to_zone_id
                            .get(&(meta.ingress_ifindex as i32))
                            .copied()
                    });
                    if let Some(redirect) = zone_id
                        .and_then(|id| {
                            resolve_zone_encoded_fabric_redirect_by_id(worker_ctx.forwarding, id)
                        })
                        .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                    {
                        decision.resolution = redirect;
                    }
                }
                if matches!(
                    decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
                ) {
                    telemetry.dbg.forward += 1;
                    // #2501: account this slow-path forwarded packet against
                    // its session. The flow-cache fast path accounts every
                    // packet of an established flow; this chokepoint covers
                    // the packets that reach the full forward-build — the
                    // first packet(s) of a flow before the cache warms, and
                    // any non-cacheable flow (NAT64/NPTv6). `account_packet`
                    // derives the direction from the resolved entry and folds
                    // it onto the canonical forward entry; a packet whose
                    // session does not yet exist (the very first SYN, accounted
                    // on its install pass via the cache or this site once the
                    // session lands) is a no-op miss.
                    if let Some(flow) = flow.as_ref() {
                        // #2749: observe TCP control bits + DSCP alongside the
                        // volume (see flow_cache_hit.rs).
                        sessions.account_packet(
                            &flow.forward_key,
                            meta.pkt_len as u64,
                            meta.tcp_flags,
                            meta.dscp,
                        );
                    }
                    // Direction-specific tracking
                    let ingress_if = meta.ingress_ifindex as i32;
                    let egress_if = decision.resolution.egress_ifindex;
                    if ingress_if == 5 {
                        telemetry.dbg.rx_from_trust += 1;
                        telemetry.dbg.fwd_trust_to_wan += 1;
                    } else if ingress_if == 6 {
                        telemetry.dbg.rx_from_wan += 1;
                        telemetry.dbg.fwd_wan_to_trust += 1;
                    }
                    // NAT decision tracking
                    if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some() {
                        telemetry.dbg.nat_applied_snat += 1;
                        telemetry.dbg.nat_applied_dnat += 1;
                    } else if decision.nat.rewrite_src.is_some() {
                        telemetry.dbg.nat_applied_snat += 1;
                    } else if decision.nat.rewrite_dst.is_some() {
                        telemetry.dbg.nat_applied_dnat += 1;
                    } else {
                        telemetry.dbg.nat_applied_none += 1;
                    }
                    // Log NAT details for first few forward-candidate packets
                    if cfg!(feature = "debug-log") {
                        if telemetry.dbg.forward <= 10 {
                            let flow_str = flow
                                .as_ref()
                                .map(|f| {
                                    format!(
                                        "{}:{} -> {}:{}",
                                        f.src_ip,
                                        f.forward_key.src_port,
                                        f.dst_ip,
                                        f.forward_key.dst_port
                                    )
                                })
                                .unwrap_or_else(|| "no-flow".into());
                            let nat_str = format!(
                                "snat={:?} dnat={:?}",
                                decision.nat.rewrite_src, decision.nat.rewrite_dst,
                            );
                            eprintln!(
                                "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
                                telemetry.dbg.forward,
                                ingress_if,
                                egress_if,
                                flow_str,
                                nat_str,
                                meta.protocol,
                            );
                        }
                    }
                    // TCP flag tracking on forwarded frames
                    if cfg!(feature = "debug-log") {
                        if meta.protocol == 6 {
                            // Compare meta.tcp_flags from BPF shim with raw frame TCP flags.
                            // #1145: reuse line-50 raw_frame bind instead of re-slicing.
                            let raw_tcp_info = extract_tcp_flags_and_window(raw_frame);
                            let raw_flags = raw_tcp_info.map(|(f, _)| f);
                            let raw_window = raw_tcp_info.map(|(_, w)| w);
                            // Log first 20 forwarded TCP packets: compare meta vs raw
                            if telemetry.dbg.forward <= 20 {
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                eprintln!(
                                    "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
                                    telemetry.dbg.forward,
                                    meta.tcp_flags,
                                    raw_flags
                                        .map(|f| format!("0x{:02x}", f))
                                        .unwrap_or_else(|| "NONE".into()),
                                    raw_window
                                        .map(|w| format!("{}", w))
                                        .unwrap_or_else(|| "NONE".into()),
                                    desc.len,
                                    meta.l4_offset,
                                    flow_str,
                                );
                                // Hex dump bytes around TCP flags position in raw frame.
                                // #1145: reuse line-50 raw_frame bind (no Option wrapper).
                                let l4 = meta.l4_offset as usize;
                                if raw_frame.len() > l4 + 20 {
                                    let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    eprintln!(
                                        "FWD_TCP_HDR[{}]: offset={} {}",
                                        telemetry.dbg.forward, l4, tcp_hdr
                                    );
                                }
                            }
                            if crate::tcp_flags::has_rst(meta.tcp_flags) {
                                // RST
                                telemetry.dbg.fwd_tcp_rst += 1;
                                if telemetry.dbg.fwd_tcp_rst <= 5 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
                                        telemetry.dbg.fwd_tcp_rst,
                                        meta.tcp_flags,
                                        raw_flags
                                            .map(|f| format!("0x{:02x}", f))
                                            .unwrap_or_else(|| "NONE".into()),
                                        raw_window
                                            .map(|w| format!("{}", w))
                                            .unwrap_or_else(|| "NONE".into()),
                                        desc.len,
                                        telemetry.dbg.forward,
                                        flow_str,
                                    );
                                    // Hex dump TCP header when RST detected.
                                    // #1145: reuse line-50 raw_frame bind.
                                    let l4 = meta.l4_offset as usize;
                                    if raw_frame.len() > l4 + 20 {
                                        let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                            .iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        eprintln!(
                                            "FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}",
                                            telemetry.dbg.fwd_tcp_rst,
                                            l4,
                                            frame_l3_offset(raw_frame).unwrap_or(0),
                                            tcp_hdr
                                        );
                                    }
                                }
                            }
                            if crate::tcp_flags::has_fin(meta.tcp_flags) {
                                // FIN
                                telemetry.dbg.fwd_tcp_fin += 1;
                                if telemetry.dbg.fwd_tcp_fin <= 5 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
                                        telemetry.dbg.fwd_tcp_fin,
                                        meta.ingress_ifindex,
                                        flow_str,
                                        meta.tcp_flags,
                                    );
                                }
                            }
                            // Detect zero-window in TCP frames by inspecting raw packet
                            if let Some(win) = raw_window {
                                if win == 0 {
                                    telemetry.dbg.fwd_tcp_zero_window += 1;
                                    if telemetry.dbg.fwd_tcp_zero_window <= 10 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
                                            telemetry.dbg.fwd_tcp_zero_window,
                                            meta.ingress_ifindex,
                                            flow_str,
                                            meta.tcp_flags,
                                            raw_flags
                                                .map(|f| format!("0x{:02x}", f))
                                                .unwrap_or_else(|| "NONE".into()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    if should_teardown_tcp_rst(meta, flow.as_ref())
                        && let Some(flow) = flow.as_ref()
                    {
                        binding
                            .scratch
                            .scratch_rst_teardowns
                            .push((flow.forward_key.clone(), decision.nat));
                    }
                    telemetry.counters.forward_candidate_packets += 1;
                    // #3651: per-zone traffic volume for this slow-path (first-
                    // packet / non-cacheable) forwarded packet, mirroring the
                    // flow-cache-hit fast path.
                    crate::afxdp::zone_counters::record_zone_traffic(
                        &worker_ctx.forwarding.zone_counter_slot_map,
                        meta.ingress_zone,
                        worker_ctx
                            .forwarding
                            .egress_zone_id(decision.resolution.egress_ifindex),
                        meta.pkt_len as u64,
                    );
                    if decision.nat.rewrite_src.is_some() {
                        telemetry.counters.snat_packets += 1;
                    }
                    if decision.nat.rewrite_dst.is_some() {
                        telemetry.counters.dnat_packets += 1;
                    }
                    // #2161: count every NAT64-translated forwarded packet
                    // here, the single forward-candidate site reached by
                    // both directions of a NAT64 flow (v6->v4 forward and
                    // v4->v6 reverse — both carry `decision.nat.nat64`).
                    // NAT64 flows are non-cacheable (FlowCacheEntry::
                    // should_cache excludes nat64), so the flow-cache-hit
                    // fast path never serves them and this is the only site
                    // that needs to count. Forward NAT64 also sets
                    // rewrite_src/rewrite_dst, so it is additionally counted
                    // as SNAT+DNAT above — the NAT64 counter is a distinct,
                    // additive translation tally, not a replacement.
                    if decision.nat.nat64 {
                        telemetry.counters.nat64_translations += 1;
                    }
                    if let Some(mut request) = build_live_forward_request_from_frame(
                        worker_ctx.binding_lookup,
                        binding_index,
                        &worker_ctx.ident,
                        desc,
                        packet_frame,
                        meta,
                        &decision,
                        worker_ctx.forwarding,
                        flow.as_ref(),
                        session_ingress_zone,
                        apply_nat_on_fabric,
                        now_ns,
                        worker_ctx.event_stream,
                        None,
                        None,
                        // #3608: give the transit forward path the ingress TX
                        // pipeline so an output-filter `then reject` emits the
                        // active reply instead of a silent drop.
                        Some(ForwardRejectReply {
                            tx_pipeline: &mut binding.tx_pipeline,
                            counters: telemetry.counters,
                        }),
                        // #5606: thread the matched session's NAT64 reverse info
                        // (original v6 src/dst) — captured from `resolved.metadata`
                        // in the session-hit resolve above — onto the request. The
                        // reverse (v4->v6) reply of a NAT64 flow hits the
                        // pre-installed reverse companion whose metadata carries
                        // this; the TX dispatcher's `build_nat64_forwarded_frame`
                        // AF_INET branch requires it to translate the reply back to
                        // IPv6 (with `None` it returns `None` and drops the reply).
                        // `None` for every non-NAT64 flow.
                        session_nat64_reverse,
                    ) {
                        // #2362: capture the per-packet L4 match inputs from the
                        // frame BEFORE `owned_packet_frame.take()` below moves the
                        // backing buffer out — the flow-cache log-only evaluation
                        // further down would otherwise borrow `packet_frame`
                        // after the take. TermMatchExtra is a small Copy value
                        // holding no borrow.
                        // #3077: to_static() drops the borrowed frame slice so this
                        // value holds no borrow (as the comment above requires) and
                        // survives the frame take below. The flex byte-offset term
                        // is not re-evaluated on this log-only path (under-matches,
                        // harmless — it only affects flow-cache log metadata).
                        let filter_match_extra =
                            crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta)
                                .to_static();
                        request.frame = owned_packet_frame
                            .take()
                            .map(PendingForwardFrame::Owned)
                            .unwrap_or(PendingForwardFrame::Live);
                        telemetry.dbg.tx += 1; // track forward requests queued
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.tx <= 5 {
                                let dst_mac_str = decision
                                    .resolution
                                    .neighbor_mac
                                    .map(|m| {
                                        format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )
                                    })
                                    .unwrap_or_else(|| "NONE".into());
                                let src_mac_str = decision
                                    .resolution
                                    .src_mac
                                    .map(|m| {
                                        format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )
                                    })
                                    .unwrap_or_else(|| "NONE".into());
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                eprintln!(
                                    "DBG FWD_REQ: target_if={} egress_if={} tx_if={} len={} proto={} vlan={} dst_mac={} src_mac={} flow={}",
                                    request.target_ifindex,
                                    decision.resolution.egress_ifindex,
                                    decision.resolution.tx_ifindex,
                                    desc.len,
                                    meta.protocol,
                                    decision.resolution.tx_vlan_id,
                                    dst_mac_str,
                                    src_mac_str,
                                    flow_str,
                                );
                            }
                        }
                        let request_target_binding_index = request.target_binding_index;
                        binding.scratch.scratch_forwards.push(request);
                        recycle_now = false;
                        // ── Flow cache population ────────────────────
                        // #6433: the seed/write half of the flow-cache contract
                        // (the #1861 §5.4 refused-install gate, the
                        // #3048/#3918/#5147 pre-resolve shard-epoch stamp, the
                        // #3073/#3322 policy-counter stamps) is extracted to the
                        // `flow_cache_seed` sibling — colocated with the read half
                        // (`flow_cache_hit`) so the eviction invariants review as
                        // one contract. Pure code-motion; `#[inline]` keeps the
                        // body in this CGU.
                        stage_flow_cache_seed(
                            &mut binding.flow.flow_cache,
                            &flow,
                            meta,
                            validation,
                            decision,
                            request_target_binding_index,
                            flow_cache_owner_rg_id,
                            session_ingress_zone,
                            flow_cache_install_failed,
                            flow_cache_policy_counter_idx,
                            &flow_cache_policy_counter,
                            filter_match_extra,
                            ingress_zone_override,
                            apply_nat_on_fabric,
                            &neighbor_epoch_snapshot,
                            worker_ctx,
                        );
                        // ── End flow cache population ────────────────
                    } else {
                        telemetry.dbg.build_fail += 1;
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.build_fail <= 3 {
                                eprintln!(
                                    "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
                                    decision.resolution.egress_ifindex,
                                    decision.resolution.tx_ifindex,
                                    decision.resolution.neighbor_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    decision.resolution.src_mac.map(|m| format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        m[0], m[1], m[2], m[3], m[4], m[5]
                                    )),
                                    desc.len,
                                    meta.protocol,
                                );
                            }
                        }
                    }
                } else {
                    // Debug: count non-forward dispositions
                    match decision.resolution.disposition {
                        ForwardingDisposition::LocalDelivery => {
                            telemetry.dbg.local += 1;
                            // Host-bound traffic (NDP, ICMP echo, BGP,
                            // GRE-to-self inner packets, etc.) is
                            // delivered by the SINGLE decap-aware
                            // reinject chokepoint at the end of this
                            // leg (`maybe_reinject_slow_path_from_frame`
                            // over `packet_frame`). #1885: this arm used
                            // to ALSO call the desc-based
                            // `maybe_reinject_slow_path` here, pairing
                            // the ORIGINAL UMEM frame (the VLAN-tagged
                            // GRE OUTER frame on a tagged underlay) with
                            // the post-decap INNER meta
                            // (`stage_native_gre_decap` rebinds `meta`
                            // but `desc` still points at the un-decapped
                            // frame) — the slice landed 4 bytes early on
                            // tagged ingress (TUN write EINVAL: payload
                            // started with the dot1q TCI tail instead of
                            // the IP version nibble) and delivered the
                            // still-encapsulated OUTER packet on
                            // untagged ingress. It was ALSO a duplicate
                            // enqueue for non-decapped local packets
                            // (both calls pass the same disposition
                            // filter). The first delivered packet
                            // creates a BPF session map entry so
                            // subsequent packets bypass userspace
                            // entirely.
                            recycle_now = true;
                        }
                        ForwardingDisposition::NoRoute => {
                            telemetry.dbg.no_route += 1;
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.no_route <= 3 {
                                    if let Some(flow) = flow.as_ref() {
                                        eprintln!(
                                            "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.protocol,
                                            meta.ingress_ifindex,
                                        );
                                    }
                                }
                            }
                        }
                        ForwardingDisposition::MissingNeighbor => {
                            // #6432: the arm's recycle-exactly-once invariant is
                            // encoded in the proven poll_stages::StageOutcome
                            // ownership enum instead of five hand-maintained
                            // `scratch_recycle.push + continue` pairs. Every
                            // terminal path of the arm produces the outcome and
                            // the SINGLE push + continue lives at the consumer
                            // below, so a future exit added to the arm cannot
                            // forget (or duplicate) the recycle. `Continue(())`
                            // falls through to the shared epilogue with
                            // `recycle_now` still owned by the caller (the
                            // pending_neigh buffer branch sets it false when it
                            // takes the frame).
                            let missing_neighbor_outcome: StageOutcome<()> = 'missing_neighbor: {
                                telemetry.dbg.missing_neigh += 1;
                                // #919/#922: zero-allocation ID-native zone
                                // resolution. Computed at the TOP of the arm so
                                // the #1913 policy gate below can run BEFORE the
                                // negative-cache fast-fail / resolver enqueue.
                                //
                                // #3021: resolve the LOGICAL ingress ifindex first
                                // (see the ForwardCandidate arm above) so a VLAN
                                // subinterface evaluates its OWN ingress zone, not
                                // the parent's first-subinterface zone.
                                let ingress_logical = resolve_ingress_logical_ifindex(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
                                    meta.ingress_vlan_id,
                                )
                                .unwrap_or(meta.ingress_ifindex as i32);
                                // #6458 V2: same owner-RG binding as the
                                // ForwardCandidate session-miss gate above —
                                // a zone-encoded fabric stamp is honored here
                                // only when the decision's owner RG is
                                // forwarding-active locally.
                                let ingress_zone_override = gate_fabric_zone_override_on_owner_rg(
                                    worker_ctx.forwarding,
                                    worker_ctx.ha_state,
                                    now_secs,
                                    ingress_zone_override,
                                    decision.resolution,
                                );
                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                    worker_ctx.forwarding,
                                    ingress_logical,
                                    ingress_zone_override,
                                    decision.resolution.egress_ifindex,
                                );
                                // Borrow zone names as &str (no clone) for the
                                // string-typed downstream NAT helpers.
                                let from_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&from_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
                                let to_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&to_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
                                // #5174: the MissingNeighbor arm never ran NAT64
                                // classification — that lives in the ForwardCandidate
                                // session-miss branch (`nat64.allocate_source` ->
                                // `decision.nat = Nat64State::forward_decision`), gated
                                // on disposition==ForwardCandidate + Permit. So a NAT64
                                // flow whose extracted-IPv4 next-hop is UNRESOLVED
                                // reaches here with `decision.nat` still default
                                // (rewrite_dst == None, nat64 == false): without this
                                // its policy would evaluate on the SYNTHETIC IPv6 dst
                                // and its seed/replay would forward the UNTRANSLATED
                                // IPv6 frame to the IPv4 gateway. Re-classify the
                                // destination (a cheap, pure dest-only lookup;
                                // source-eligibility / RFC 6146 §3.5 hairpin was already
                                // enforced by the pre-routing classify in the
                                // session-miss block — which is exactly why the route
                                // resolved to the IPv4 next-hop). `Some(dst_v4)` marks a
                                // NAT64 MissingNeighbor flow: policy is matched on the
                                // extracted IPv4 dst below (the #2358 cross-family
                                // tuple), and a PERMITTED such flow is handled
                                // fail-closed (probe + drop, NO seed/buffer) so it
                                // recovers via the ForwardCandidate path once the
                                // neighbor resolves. Full buffer-and-translate parity
                                // (zero cold-start loss) is deferred to a follow-up —
                                // the cross-family v6->v4 replay the cold-path lacks is
                                // why this is fail-closed, not buffered.
                                let nat64_dst_v4 = flow.as_ref().and_then(|f| {
                                    if decision.nat.rewrite_dst.is_some() {
                                        return None;
                                    }
                                    match f.dst_ip {
                                        IpAddr::V6(dst_v6) => {
                                            match worker_ctx.forwarding.nat64.classify_ipv6_dest(dst_v6) {
                                                crate::nat64::Nat64Match::MatchReady {
                                                    dst_v4,
                                                    ..
                                                } => Some(dst_v4),
                                                _ => None,
                                            }
                                        }
                                        IpAddr::V4(_) => None,
                                    }
                                });
                                // #1913 (Codex r2/r3): evaluate policy for the
                                // MissingNeighbor cold path BEFORE any forwarding
                                // OR neighbor-resolution side-effect. The
                                // MissingNeighbor arm has its OWN policy
                                // evaluation (the main deny→PolicyDenied
                                // conversion lives only in the ForwardCandidate
                                // branch). A DENY must exit here so a denied flow
                                // never enqueues the shared resolver / fires a
                                // kernel ARP/NDP probe (network traffic for a
                                // flow policy says to drop, repeated per packet
                                // since denied frames are not buffered), never
                                // runs the negative-cache fast-fail, never seeds
                                // a session, never buffers in pending_neigh, and
                                // never reaches the slow-path reinject gate.
                                // `MissingNeighbor` is slow-path-eligible, so
                                // without this conversion a denied unresolved-
                                // neighbor cold-path packet was forwarded by the
                                // kernel FIB (a zone-policy bypass). The cold-path
                                // histogram samples this eval (session-install
                                // slow path).
                                if let Some(flow) = flow.as_ref() {
                                    let (cp_sample_tag, cp_t_in) = {
                                        let cp = &mut binding.cold_path;
                                        cp.sample_phase = cp.sample_phase.wrapping_add(1);
                                        let tag =
                                            (cp.sample_phase & worker_ctx.cold_path_sample_mask) == 0;
                                        let t = if tag {
                                            crate::afxdp::cold_path_hist::sample_tsc_start()
                                        } else {
                                            0
                                        };
                                        (tag, t)
                                    };
                                    // #2345: MissingNeighbor cold path must match
                                    // the SAME post-translation destination tuple as
                                    // the ForwardCandidate path above so a denied
                                    // (or permitted) verdict is identical whether or
                                    // not the next-hop neighbor is already resolved.
                                    // The session-miss block's `effective_resolution_target`
                                    // is out of scope here, so reconstruct the
                                    // post-translation dst tuple from the merged
                                    // `decision.nat`:
                                    //   - DNAT / static-DNAT / inbound NPTv6 each
                                    //     populate `decision.nat.rewrite_dst` (set at
                                    //     the decision build as `nptv6_nat.or(
                                    //     pre_routing_dnat)`), so the translated
                                    //     internal dst is used; only port-based DNAT
                                    //     also sets `rewrite_dst_port`.
                                    //   - NAT64 (#5174): `nat64_dst_v4` (computed at
                                    //     the top of this arm via `classify_ipv6_dest`)
                                    //     carries the extracted IPv4 destination when
                                    //     the flow is a NAT64 MissingNeighbor flow, so
                                    //     policy matches the SAME post-translation
                                    //     (V6 src, V4 dst) tuple the ForwardCandidate
                                    //     path matches (#2358) instead of the synthetic
                                    //     IPv6 dst. `decision.nat.rewrite_dst` is still
                                    //     None in this arm (the NAT64 forward decision
                                    //     is built only in the ForwardCandidate branch),
                                    //     which is why the extracted dst is recovered
                                    //     from a fresh classify rather than the merged
                                    //     `decision.nat`.
                                    // Both halves fall back to the original dst/port
                                    // when no inbound destination translation applies.
                                    let policy_dst_ip = match nat64_dst_v4 {
                                        Some(dst_v4) => IpAddr::V4(dst_v4),
                                        None => decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                    };
                                    let policy_dst_port = decision
                                        .nat
                                        .rewrite_dst_port
                                        .unwrap_or(flow.forward_key.dst_port);
                                    // #3020: same ICMP type/code extraction as the
                                    // ForwardCandidate path so a denied/permitted
                                    // verdict for an icmp-type-constrained term
                                    // (junos-ping) is identical whether or not the
                                    // next-hop neighbor is already resolved.
                                    let policy_icmp = policy_packet_icmp(packet_frame, meta);
                                    let policy_result = evaluate_policy_result_with_icmp(
                                        &worker_ctx.forwarding.policy,
                                        from_zone_id,
                                        to_zone_id,
                                        flow.src_ip,
                                        policy_dst_ip,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        policy_dst_port,
                                        policy_icmp,
                                        desc.len as u64,
                                    );
                                    if cp_sample_tag {
                                        let t_out = crate::afxdp::cold_path_hist::sample_tsc_end();
                                        let q32 = binding.cold_path.ns_per_tsc_q32;
                                        if q32 != 0 {
                                            let delta_tsc = t_out.saturating_sub(cp_t_in);
                                            let raw_ns =
                                                ((delta_tsc as u128 * q32 as u128) >> 32) as u64;
                                            let baseline = binding.cold_path.wrapper_ns_baseline;
                                            let delta_ns = if raw_ns < baseline {
                                                binding.cold_path.wrapper_underflow_count = binding
                                                    .cold_path
                                                    .wrapper_underflow_count
                                                    .saturating_add(1);
                                                0
                                            } else {
                                                raw_ns - baseline
                                            };
                                            if let Some(slot) =
                                                crate::afxdp::cold_path_hist::lookup_slot(
                                                    &worker_ctx.forwarding.cold_path_slot_map,
                                                    from_zone_id,
                                                    to_zone_id,
                                                )
                                            {
                                                binding.cold_path.record_sample(
                                                    slot,
                                                    from_zone_id,
                                                    to_zone_id,
                                                    delta_ns,
                                                );
                                            }
                                        }
                                    }
                                    if !matches!(policy_result.action, PolicyAction::Permit) {
                                        let owner_rg_id = owner_rg_for_resolution(
                                            worker_ctx.forwarding,
                                            decision.resolution,
                                        );
                                        // #2089/#3071/#3615: enqueue the deny/reject
                                        // reply FIRST, then emit the policy-deny
                                        // RT_FLOW with the TRUTHFUL action (a `reject`
                                        // whose reply fail-closes is logged as DENY,
                                        // not REJECT). `decision.nat` carries the
                                        // inbound dst translation (#2345/#3058); the
                                        // AppID is resolved from the POST-translation
                                        // dst port (#2520/#3058).
                                        deny_reply_and_emit(
                                            &mut binding.tx_pipeline,
                                            worker_ctx.forwarding,
                                            worker_ctx.event_stream,
                                            binding.ifindex,
                                            packet_frame,
                                            meta,
                                            flow,
                                            telemetry.counters,
                                            &decision.nat,
                                            from_zone_id,
                                            to_zone_id,
                                            owner_rg_id,
                                            policy_result.policy_id,
                                            policy_result.action,
                                            resolve_policy_deny_app_id(
                                                &worker_ctx.forwarding.app_catalog,
                                                flow,
                                                policy_dst_port,
                                            ),
                                            now_ns,
                                        );
                                        telemetry.dbg.policy_deny += 1;
                                        decision.resolution.disposition =
                                            ForwardingDisposition::PolicyDenied;
                                        record_forwarding_disposition(
                                            &worker_ctx.ident,
                                            DispositionCounters::Hot(telemetry.counters),
                                            decision.resolution,
                                            desc.len as u32,
                                            Some(meta),
                                            debug.as_ref(),
                                            worker_ctx.recent_exceptions,
                                            worker_ctx.last_resolution,
                                            worker_ctx.forwarding,
                                        );
                                        break 'missing_neighbor StageOutcome::RecycleAndContinue;
                                    }
                                } else {
                                    // #4024: a FLOWLESS packet (non-first fragment /
                                    // no-L4) that resolves to MissingNeighbor still
                                    // carries FULL L3 identity — src/dst/protocol/
                                    // ingress+egress zones — so it MUST pass the zone
                                    // security policy BEFORE any neighbor-resolution
                                    // side-effect (neg-cache probe, #1769 resolver
                                    // enqueue, kernel ARP/NDP probe, pending_neigh
                                    // buffer) OR the trailing slow-path reinject.
                                    //
                                    // Before #4024 the flowless case fell through
                                    // here to the reinject path (documented as
                                    // "preserving the pre-#1913 behavior — a flowless
                                    // MissingNeighbor packet was always slow-path-
                                    // eligible"). That FAILED OPEN: under a `deny-all`
                                    // zone pair, a flowless fragment whose next-hop
                                    // neighbor was unresolved was FIB-reinjected and
                                    // the kernel forwarded it — a zone-policy bypass.
                                    // #3291 enforces zone policy on the flowless
                                    // ForwardCandidate arm but deferred MissingNeighbor
                                    // to "its own cold-path arm" (this one), whose
                                    // #1913 gate is `if let Some(flow)` and so never
                                    // fired for a flowless (flow == None) packet.
                                    //
                                    // `l3_session_flow_from_meta` rebuilds the L3
                                    // tuple the shim stamped even for a fragment; the
                                    // synthetic flow is evaluated with ports = 0 /
                                    // l4_present = false, so port-bearing application
                                    // terms fail closed while address/protocol/`any`
                                    // still match — parity with the #3291 flowless
                                    // ForwardCandidate gate and the #1913 flow-backed
                                    // gate above, with no over-gating of a permitted
                                    // flowless flow. `from_zone_id`/`to_zone_id` were
                                    // resolved at the top of this arm (MissingNeighbor
                                    // has a valid egress_ifindex). A deny is a SILENT
                                    // drop — a fragment has no L4 header to synthesize
                                    // a reject from — with a PolicyDeny event for
                                    // observability, then PolicyDenied so the trailing
                                    // #1913 reinject chokepoint drops it fail-closed.
                                    if let Some(l3_flow) =
                                        crate::afxdp::frame::l3_session_flow_from_meta(meta)
                                    {
                                        let policy_icmp = policy_packet_icmp(packet_frame, meta);
                                        let policy_result =
                                            crate::policy::evaluate_policy_result_l3_aware(
                                                &worker_ctx.forwarding.policy,
                                                from_zone_id,
                                                to_zone_id,
                                                l3_flow.src_ip,
                                                l3_flow.dst_ip,
                                                meta.protocol,
                                                0,
                                                0,
                                                policy_icmp,
                                                desc.len as u64,
                                                // L4 header ABSENT — port-bearing app
                                                // terms fail closed.
                                                false,
                                            );
                                        if !matches!(policy_result.action, PolicyAction::Permit) {
                                            let owner_rg_id = owner_rg_for_resolution(
                                                worker_ctx.forwarding,
                                                decision.resolution,
                                            );
                                            emit_policy_deny_event(
                                                worker_ctx.event_stream,
                                                &l3_flow,
                                                &decision.nat,
                                                meta,
                                                from_zone_id,
                                                to_zone_id,
                                                owner_rg_id,
                                                policy_result.policy_id,
                                                policy_result.action,
                                                // No L4 port for a flowless packet →
                                                // no AppID.
                                                0,
                                                // #3615: a flowless deny is ALWAYS a
                                                // silent drop — no reply can be
                                                // synthesized — so a `reject` term
                                                // logs the truthful DENY.
                                                false,
                                                now_ns,
                                            );
                                            telemetry.dbg.policy_deny += 1;
                                            decision.resolution.disposition =
                                                ForwardingDisposition::PolicyDenied;
                                            record_forwarding_disposition(
                                                &worker_ctx.ident,
                                                DispositionCounters::Hot(telemetry.counters),
                                                decision.resolution,
                                                desc.len as u32,
                                                Some(meta),
                                                debug.as_ref(),
                                                worker_ctx.recent_exceptions,
                                                worker_ctx.last_resolution,
                                                worker_ctx.forwarding,
                                            );
                                            break 'missing_neighbor StageOutcome::RecycleAndContinue;
                                        }
                                    }
                                    // Flowless permit (or no derivable L3 tuple):
                                    // fall through to the negative-cache / probe /
                                    // reinject path. A permitted flowless fragment is
                                    // legitimately forwarded once the neighbor
                                    // resolves — `MissingNeighbor` stays slow-path-
                                    // eligible for it.
                                }
                                // #1651 B3: dead-host fast-fail gate. Runs at
                                // the very top of the MissingNeighbor arm,
                                // BEFORE the kernel probe, session seed, and
                                // pending_neigh buffer, so a dead host never
                                // consumes a queue slot, fires a probe, or
                                // creates a MissingNeighborSeed session.
                                //
                                // Resolved-neighbor-wins (RTM_NEWNEIGH
                                // invalidation): check static then dynamic
                                // neighbors FIRST (same order as
                                // retry_pending_neigh / lookup_neighbor_entry).
                                // If the dst is now resolved, drop any stale
                                // negative entry and fall through to normal
                                // forwarding. Otherwise, if it is still
                                // negatively cached + un-expired, recycle the
                                // frame immediately.
                                // #1912: key the OUTER-hop neighbor
                                // resolution side-effects (ARP/NDP probe,
                                // #1769 resolver enqueue, neg-cache,
                                // resolved-wins, already-probing dedup) by the
                                // OUTER transport's L3 egress ifindex, not the
                                // tunnel logical ifindex. For a non-tunnel
                                // resolution this equals
                                // decision.resolution.egress_ifindex so the
                                // path is byte-identical; for a tunnel-marked
                                // decision (next_hop = outer hop) it is the
                                // outer transport egress where the outer
                                // neighbor is actually keyed (a VLAN outer
                                // transport keys on the L3 subif, not the VLAN
                                // parent / tx_ifindex). Computed once per cold
                                // packet on this arm.
                                let neigh_if = outer_neighbor_ifindex(
                                    worker_ctx.forwarding,
                                    Some(worker_ctx.dynamic_neighbors),
                                    &decision.resolution,
                                );
                                if let Some(next_hop) = decision.resolution.next_hop {
                                    let neg_key = (neigh_if, next_hop);
                                    // neg_neigh_gate runs the resolved-wins
                                    // probe (static neighbors THEN dynamic,
                                    // same order as retry_pending_neigh /
                                    // lookup_neighbor_entry) and the TTL check.
                                    // Returns true ⇒ fast-fail this packet.
                                    let fast_fail = neg_neigh_gate(
                                        &mut binding.neg_neigh_cache,
                                        &neg_key,
                                        now_ns,
                                        || {
                                            worker_ctx.forwarding.neighbors.contains_key(&neg_key)
                                                || worker_ctx.dynamic_neighbors.get(&neg_key).is_some()
                                        },
                                    );
                                    if fast_fail {
                                        telemetry.dbg.neg_neigh_fast_fail += 1;
                                        // #1782: promote the debug counter to a
                                        // real per-binding atomic so the
                                        // cold-start capture can read it from
                                        // Prometheus. Single Relaxed fetch_add
                                        // on the existing discard path — no new
                                        // hot-path work, no behavior change.
                                        binding
                                            .live
                                            .neg_neigh_fast_fail
                                            .fetch_add(1, Ordering::Relaxed);
                                        // #1769: the negative gate suppresses
                                        // the probe + buffer below, so a dst
                                        // that lost its dynamic entry (transient
                                        // FAILED/DELNEIGH or a dropped good
                                        // RTM_NEWNEIGH) would blackhole for the
                                        // full 3s TTL with nothing nudging it
                                        // back. Route it through the shared
                                        // resolver: a single-key RTM_GETNEIGH
                                        // off the hot path caches a confirmed
                                        // REACHABLE/PERMANENT lladdr (epoch-
                                        // guarded) or probes to force kernel
                                        // revalidation on a DELAY/STALE one.
                                        // Per-key rate-limited in the resolver
                                        // thread, so a SYN storm fires at most
                                        // one GET/probe per key per window. The
                                        // hot path only pays a non-blocking
                                        // try_send here (not per-packet — this
                                        // arm fires only on the negative fast-
                                        // fail).
                                        // Per-key rate-limited (the resolver
                                        // coalesces per-key anyway) so a
                                        // dead-host SYN storm does NOT clone +
                                        // try_send per fast-failed packet. See
                                        // try_enqueue_resolver.
                                        if let Some(resolver) = worker_ctx.neighbor_resolver {
                                            try_enqueue_resolver(
                                                resolver,
                                                &mut binding.resolver_enqueue_throttle,
                                                &worker_ctx.forwarding.ifindex_to_name,
                                                neg_key,
                                                now_ns,
                                            );
                                        }
                                        // Fresh RX descriptor → recycle via
                                        // scratch_recycle + continue, matching
                                        // the source-NAT-failure discard
                                        // pattern. The continue skips the
                                        // recycle_now epilogue and the
                                        // session-seed/buffer below.
                                        break 'missing_neighbor StageOutcome::RecycleAndContinue;
                                    }
                                }
                                // Send ARP/NDP solicitation via RAW socket (not XSK)
                                // so the reply goes through the kernel's normal RX
                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
                                // Also reinject original packet to slow-path for kernel
                                // to forward once the neighbor is resolved.
                                // Trigger ARP/NDP resolution via kernel netlink.
                                // Adding an INCOMPLETE neighbor entry makes the
                                // kernel send its own ARP/NDP solicitation through
                                // the normal stack, which correctly handles VLAN
                                // tagging and TX offload. The netlink monitor then
                                // picks up the resolved entry instantly.
                                if let Some(next_hop) = decision.resolution.next_hop {
                                    // #1912: tunnel-marked decisions are NEVER
                                    // buffered in pending_neigh (R-E), and the
                                    // per-hop neg-cache arms only on a
                                    // pending_neigh timeout (neighbor_dispatch.rs
                                    // neg_neigh_record), so for an unresolved
                                    // OUTER hop the top-of-arm neg fast-fail can
                                    // never arm and suppress this block. The
                                    // outer-hop probe + resolver are therefore
                                    // gated by the per-(neigh_if, next_hop)
                                    // resolver_enqueue_throttle window below.
                                    //
                                    // outer_if_distinct: true only when this is a
                                    // tunnel decision whose outer transport
                                    // RESOLVED to a real L3 egress distinct from
                                    // the tunnel logical ifindex. If
                                    // outer_neighbor_ifindex fell back to
                                    // egress_ifindex (endpoint vanished / outer
                                    // egress <= 0 — unreachable within the
                                    // single-threaded worker loop, but explicit),
                                    // neigh_if == egress_ifindex == tunnel logical;
                                    // probing / RTM_GETNEIGH on the GRE logical
                                    // iface is the useless pre-#1912 behavior, so
                                    // skip it (Copilot #1912 r1 Low).
                                    let tunnel_marked = decision.resolution.tunnel_endpoint_id != 0;
                                    let outer_if_distinct = tunnel_marked
                                        && neigh_if > 0
                                        && neigh_if != decision.resolution.egress_ifindex;
                                    let throttle_key = (neigh_if, next_hop);
                                    // For a tunnel decision, gate BOTH the kernel
                                    // ARP probe AND the resolver enqueue behind
                                    // ONE throttle window so a SYN flood to a
                                    // flushed outer hop fires at most one
                                    // probe + enqueue per outer key per window
                                    // (else trigger_kernel_arp_probe — a raw
                                    // socket open/setsockopt/sendto/close — would
                                    // run per packet; AGY #1912 r1 High).
                                    let tunnel_throttled = outer_if_distinct
                                        && matches!(
                                            binding
                                                .resolver_enqueue_throttle
                                                .get(&throttle_key),
                                            Some(&t) if now_ns.saturating_sub(t)
                                                < RESOLVER_ENQUEUE_THROTTLE_NS
                                        );
                                    // Only spawn ping if we don't already have a
                                    // pending probe for this (ifindex, hop).
                                    // #1771 §2.2: pending_neigh is keyed by
                                    // (egress_ifindex, next_hop), so the
                                    // "already probing this hop" dedup is a
                                    // direct contains_key (was an O(n) iter scan).
                                    // #1912: dedup + iface lookup on the OUTER
                                    // L3 egress (neigh_if), not the tunnel
                                    // logical ifindex. For a non-tunnel flow
                                    // neigh_if == egress_ifindex so the dedup is
                                    // byte-identical; for a tunnel flow
                                    // pending_neigh never holds the key (R-E), so
                                    // the per-window throttle is the probe-storm
                                    // bound instead.
                                    let already_probing =
                                        binding.pending_neigh.contains_key(&(neigh_if, next_hop));
                                    // Suppress the probe for a tunnel decision
                                    // with NO distinct outer egress: neigh_if
                                    // would be the tunnel logical ifindex and the
                                    // probe would bind to the GRE iface (no ARP —
                                    // the useless pre-#1912 behavior). For a
                                    // non-tunnel flow tunnel_marked is false so
                                    // this never suppresses (byte-identical).
                                    let tunnel_without_outer = tunnel_marked && !outer_if_distinct;
                                    if !already_probing && !tunnel_throttled && !tunnel_without_outer {
                                        let iface_name = worker_ctx
                                            .forwarding
                                            .ifindex_to_name
                                            .get(&neigh_if)
                                            .cloned();
                                        if let Some(name) = iface_name {
                                            // Fast path: ICMP socket triggers kernel ARP
                                            // in microseconds (no fork/exec).
                                            trigger_kernel_arp_probe(&name, neigh_if, next_hop);
                                        }
                                    }
                                    // #1912: for a tunnel-marked MissingNeighbor
                                    // with a DISTINCT resolved outer egress (e.g.
                                    // GRE outer hop), ALSO drive the #1769
                                    // resolver on the OUTER L3 egress, not only on
                                    // the neg-cache fast-fail. A freshly-flushed
                                    // outer hop has no negative entry, so without
                                    // this only the one-shot kernel ARP probe
                                    // fires; the resolver hardens the STALE/DELAY
                                    // outer-entry case via RTM_GETNEIGH. The frame
                                    // is STILL NOT buffered (R-E), so no
                                    // plaintext-leak window opens. try_enqueue_-
                                    // resolver re-reads the SAME throttle entry
                                    // and bumps it once, so the probe above and
                                    // this enqueue share one window per key.
                                    if outer_if_distinct && !tunnel_throttled {
                                        if let Some(resolver) = worker_ctx.neighbor_resolver {
                                            try_enqueue_resolver(
                                                resolver,
                                                &mut binding.resolver_enqueue_throttle,
                                                &worker_ctx.forwarding.ifindex_to_name,
                                                throttle_key,
                                                now_ns,
                                            );
                                        } else {
                                            // No resolver (probe-only build): bump
                                            // the throttle directly so the probe
                                            // above is still rate-limited to one
                                            // per window. Bounded like the neg
                                            // cache.
                                            let throttle = &mut binding.resolver_enqueue_throttle;
                                            if throttle.len() >= MAX_NEG_NEIGH_CACHE
                                                && !throttle.contains_key(&throttle_key)
                                            {
                                                throttle.clear();
                                            }
                                            throttle.insert(throttle_key, now_ns);
                                        }
                                    }
                                }
                                // #5174: NAT64 MissingNeighbor fail-closed. The kernel
                                // ARP/NDP probe above already fired for the extracted
                                // IPv4 next-hop (so the neighbor will resolve), but the
                                // cold-path seed + pending_neigh replay is SAME-FAMILY
                                // only — the replay `rewrite_forwarded_frame_in_place`
                                // does MAC/VLAN/NAT, NOT the v6->v4 cross-family NAT64
                                // rebuild. Seeding a plain-forward decision + buffering
                                // the IPv6 frame here would therefore TX the UNTRANSLATED
                                // IPv6 frame to the IPv4 gateway AND persist a broken,
                                // HA-synced `MissingNeighborSeed` session that poisons
                                // every subsequent packet (session-hit → non-NAT64
                                // decision). Drop this cold-start packet instead; the
                                // flow forwards correctly via the ForwardCandidate path
                                // (which builds the real NAT64 translation) on a later
                                // packet once the neighbor is resolved. Only a PERMITTED
                                // flow reaches here — a NAT64 deny already exited above
                                // with the normal PolicyDenied disposition, so this
                                // never probe-loops a denied flow. Buffer-and-translate
                                // parity (zero cold-start loss) is a deferred follow-up.
                                if nat64_dst_v4.is_some() {
                                    telemetry.dbg.nat64_missing_neigh_drop += 1;
                                    break 'missing_neighbor StageOutcome::RecycleAndContinue;
                                }
                                // Create the session NOW so the SYN-ACK (reverse
                                // direction) finds the forward NAT match and creates
                                // a reverse session. Without this, the SYN-ACK hits
                                // session miss → policy deny (no rule for WAN→LAN).
                                let mut pending_decision = decision;
                                let mut source_nat_release_key = None;
                                // #2218: matched SNAT/static-SNAT rule counter
                                // for the seeded translated flow; incremented at
                                // the committed seed install below.
                                let mut source_nat_counter: Option<
                                    std::sync::Arc<crate::nat::NatRuleCounter>,
                                > = None;
                                // #1861 §5.3: true when the seed install was
                                // ATTEMPTED and refused (max_sessions). Gates
                                // the pending-neighbor buffering below: a
                                // refused seed's SNAT allocation was rolled
                                // back, so replaying the buffered frame after
                                // neighbor resolution would forward it on an
                                // unreserved NAT tuple with no session. Flow-
                                // less packets (no install attempted) keep
                                // buffering as before.
                                let mut seed_install_refused = false;
                                if let Some(flow) = flow.as_ref() {
                                    // #1913 (Codex r2): policy was already
                                    // evaluated (and any DENY dropped+recycled)
                                    // above, BEFORE the kernel ARP probe. Only a
                                    // permitted flow reaches here, so the SNAT
                                    // allocation runs unconditionally for the
                                    // permitted MissingNeighbor flow. The
                                    // cold-path histogram sample is taken at the
                                    // early eval site above.
                                    {
                                        let nat_match_flow = flow.with_destination(
                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                        );
                                        // #1852: gate pool-mode SNAT allocation
                                        // for a non-first fragment (no L4 ports).
                                        let snat_non_first_fragment = {
                                            let l3 = meta.l3_offset as usize;
                                            l3 <= packet_frame.len()
                                                && is_non_first_fragment(
                                                    &packet_frame[l3..],
                                                    meta.addr_family,
                                                )
                                        };
                                        // #3121: mirror the main NAT-decision site
                                        // (Permit path above) on the missing-neighbor
                                        // seed path so the seed session carries the
                                        // SAME composed NAT decision regardless of
                                        // ARP-resolution timing. NPTv6 outbound source
                                        // translation composes with any pre-routing DNAT
                                        // (rewrite_dst): NPTv6 rewrites the source, DNAT
                                        // the destination; both are merged. The NPTv6
                                        // source rewrite is checksum-neutral (RFC 6296).
                                        // #5176: gate on the EGRESS zone (`to_zone`) so
                                        // a rule-set scoped `from zone X` never rewrites
                                        // the source of traffic leaving via another zone.
                                        let nptv6_snat =
                                            if let IpAddr::V6(mut src_v6) = nat_match_flow.src_ip {
                                                if worker_ctx
                                                    .forwarding
                                                    .nptv6
                                                    .translate_outbound(&mut src_v6, to_zone)
                                                {
                                                    Some(NatDecision {
                                                        rewrite_src: Some(IpAddr::V6(src_v6)),
                                                        rewrite_dst: None,
                                                        nat64: false,
                                                        nptv6: true,
                                                        ..NatDecision::default()
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };
                                        if let Some(nptv6_decision) = nptv6_snat {
                                            // NPTv6 is the source translation and takes
                                            // precedence over static/interface SNAT; merge
                                            // into any pre-routing DNAT. No per-rule counter.
                                            pending_decision.nat =
                                                pending_decision.nat.merge(nptv6_decision);
                                            source_nat_release_key =
                                                Some(nat_match_flow.forward_key.clone());
                                        } else {
                                            let mut snat_match_counter = None;
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                meta.ingress_ifindex as i32,
                                                &from_zone,
                                                &to_zone,
                                                pending_decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                                now_ns,
                                                snat_non_first_fragment,
                                                // #6522: THIS worker holds the
                                                // pool allocation this decision
                                                // mints — see `nat::NatHolder`.
                                                worker_id,
                                                &mut snat_match_counter,
                                            ) {
                                                Ok(snat_decision) => {
                                                    pending_decision.nat =
                                                        pending_decision.nat.merge(snat_decision);
                                                    source_nat_release_key =
                                                        Some(nat_match_flow.forward_key.clone());
                                                    source_nat_counter = snat_match_counter;
                                                }
                                                Err(failure) => {
                                                    record_source_nat_failure(
                                                        telemetry,
                                                        worker_ctx,
                                                        meta,
                                                        flow,
                                                        from_zone_id,
                                                        to_zone_id,
                                                        desc.len,
                                                        &failure,
                                                    );
                                                    break 'missing_neighbor StageOutcome::RecycleAndContinue;
                                                }
                                            }
                                        }
                                    }
                                    let sess_meta = build_missing_neighbor_session_metadata(
                                        worker_ctx.forwarding,
                                        from_zone_id,
                                        to_zone_id,
                                        // #4983: stamp the seed's TRUE ingress identity from the
                                        // frame that created it, exactly as the two other
                                        // FRAME-DRIVEN install sites above do. ("Frame-driven",
                                        // not "policy-admitted": the transit install is
                                        // policy-admitted, but the LocalDelivery install also runs
                                        // for a `JunosHostLocalPolicy::NoMatch` host-bound flow
                                        // that the zone's host-inbound set admits with no
                                        // junos-host policy matching at all -- #6928 review.)
                                        // This seed is published to the BPF
                                        // conntrack map below and is never re-installed once the
                                        // neighbor resolves, so it is the session's only chance to
                                        // record where the flow actually arrived.
                                        meta.ingress_ifindex,
                                        meta.ingress_vlan_id,
                                        packet_fabric_ingress,
                                        pending_decision,
                                    );
                                    let pending_installed = sessions.install_with_protocol_with_origin(
                                        flow.forward_key.clone(),
                                        pending_decision,
                                        sess_meta.clone(),
                                        SessionOrigin::MissingNeighborSeed,
                                        now_ns,
                                        meta.protocol,
                                        meta.tcp_flags,
                                    );
                                    if pending_installed {
                                        // #2218: the seed install is the
                                        // committed translation for this
                                        // missing-neighbor flow (a refused seed
                                        // takes the else-arm below and rolls the
                                        // SNAT allocation back, so it is never
                                        // counted). Count the DNAT and SNAT
                                        // per-rule hits once each.
                                        let nat_hit_len = desc.len as u64;
                                        if let Some(c) = pre_routing_dnat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        if let Some(c) = source_nat_counter.as_ref() {
                                            c.add(nat_hit_len);
                                        }
                                        let entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision: pending_decision,
                                            metadata: sess_meta,
                                            origin: SessionOrigin::MissingNeighborSeed,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                            // Local missing-neighbor seed (#2170): no peer gen.
                                            generation: 0,
                                            // #5212: local-origin seed; no carried id (0).
                                            session_id: 0,
                                        };
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &entry,
                                        );
                                        // #1789: count a failed publish
                                        // (shim misses the key -> NO_SESSION
                                        // degraded path for the seeded flow).
                                        if publish_session_map_entry_for_session(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                        )
                                        .is_err()
                                        {
                                            binding
                                                .live
                                                .session_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        // #2008 M5: stamp the resolved app id.
                                        // #3321: directional resolution (service =
                                        // dst forward / src reverse).
                                        // #3416: forward service port from the
                                        // post-translation (DNAT-rewritten)
                                        // destination so a port-forwarded
                                        // neighbor-seed row carries the admitting
                                        // application, not the public port.
                                        let app_id = worker_ctx.forwarding.app_catalog.lookup_admitted(
                                            flow.forward_key.protocol,
                                            flow.forward_key.src_port,
                                            flow.forward_key.dst_port,
                                            entry.metadata.is_reverse,
                                            pending_decision.nat.rewrite_dst_port,
                                        );
                                        // #5213: stable id from the just-installed
                                        // neighbor-seed entry so the mirror row
                                        // matches RT_FLOW.
                                        let session_id =
                                            sessions.session_id_for(&flow.forward_key);
                                        publish_bpf_conntrack_entry(
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                            &worker_ctx.forwarding.zone_name_to_id,
                                            worker_ctx.forwarding.alg_disable_flags,
                                            app_id,
                                            session_id,
                                        );
                                        // #2244: count failed reverse-NAT publishes so
                                        // map-pressure loss is operator-visible.
                                        if !publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            pending_decision.nat,
                                        ) {
                                            binding
                                                .live
                                                .dnat_publish_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        telemetry.counters.session_creates += 1;
                                    } else {
                                        // #1861 §5.3: at-cap seed refusal. The
                                        // single-entry install IS the
                                        // transaction here (no pair); the
                                        // refusal is counted by the table's
                                        // create_drops (exported since #1861 —
                                        // admission_refused stays preflight-
                                        // only). Roll back the SNAT allocation
                                        // and drop the frame instead of
                                        // buffering it for replay.
                                        seed_install_refused = true;
                                        rollback_source_nat_allocation_for_worker(
                                            &worker_ctx.forwarding.iface_nat_allocators,
                                            &worker_ctx.forwarding.source_nat_rules,
                                            source_nat_release_key
                                                .as_ref()
                                                .unwrap_or(&flow.forward_key),
                                            pending_decision.nat,
                                            false,
                                            now_ns,
                                            worker_id,
                                        );
                                    }
                                }
                                // Buffer the packet. The ICMP probe resolves ARP
                                // in ~1ms. The retry loop below re-forwards the
                                // buffered packet once the neighbor resolves via the
                                // netlink monitor. The session was already created
                                // above so the SYN-ACK reverse path works too.
                                // Total latency: ~2ms (ARP + netlink + retry).
                                //
                                // NOTE: we do NOT reinject to slow-path here because
                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
                                // in zero-copy mode (mlx5). The ICMP probe + netlink
                                // monitor + buffer-retry path bypasses this issue.
                                // #1771 §2.2: buffer one representative packet
                                // per (egress_ifindex, next_hop). Keep the
                                // OLDEST (it drives the probe/dwell clock):
                                // a duplicate for an already-buffered hop is
                                // dropped+recycled (recycle_now stays true),
                                // pinning ≤1 UMEM frame per unresolved hop.
                                // A packet with no next_hop cannot be keyed or
                                // resolved (the retry sweep needs next_hop to
                                // look up a MAC), so it is not buffered —
                                // recycled instead of held until timeout.
                                // #1861 §5.3: a refused seed is recycled, not
                                // buffered (see seed_install_refused above) —
                                // the kernel ARP probe already fired, and the
                                // next packet retries the install once the
                                // table has room, converging with the #1771
                                // duplicate-drop semantics.
                                // #1873 R-E: tunnel-marked decisions are
                                // NEVER admitted to pending_neigh. The retry
                                // path TXes buffered frames via in-place
                                // MAC/VLAN rewrite with no encapsulation, so
                                // a buffered tunnel inner packet would go out
                                // PLAINTEXT on the physical wire when the
                                // outer neighbor resolves (AGY plan r2,
                                // verified). The kernel ARP/ICMP probe above
                                // already fired, and the post-match
                                // maybe_reinject_slow_path_from_frame call
                                // routes this frame into the R-C tunnel gate
                                // (counted drop) — the #1769 resolver keeps
                                // driving the outer next-hop, and the flow
                                // recovers via retransmission once resolved.
                                // #1902 (sibling of #1885): a GRE-DECAPPED
                                // packet is NEVER admitted to pending_neigh.
                                // `desc` still references the un-decapped
                                // OUTER UMEM frame while `meta`/the decision
                                // describe the synthetic INNER frame in
                                // `owned_packet_frame`; the retry path's
                                // rewrite_forwarded_frame_in_place(pkt.desc,
                                // pkt.meta, ..) would MAC/NAT/TTL-rewrite the
                                // still-encapsulated outer packet at inner
                                // offsets and TX it toward the inner next-hop
                                // — a corrupt transmit, not a drop. The
                                // kernel ARP/ICMP probe above already fired,
                                // the trailing decap-aware
                                // maybe_reinject_slow_path_from_frame
                                // chokepoint (#1901) still hands the
                                // correctly-paired INNER packet to the kernel
                                // slow path, and the #1769 resolver +
                                // retransmission recover the flow once the
                                // neighbor resolves. Counted per binding so
                                // the live gate is observable
                                // (xpf_userspace_pending_neigh_decap_drops_total).
                                if !seed_install_refused
                                    && pending_decision.resolution.tunnel_endpoint_id == 0
                                    && pending_decision.resolution.next_hop.is_some()
                                    && owned_packet_frame.is_some()
                                {
                                    binding
                                        .live
                                        .pending_neigh_decap_drops
                                        .fetch_add(1, Ordering::Relaxed);
                                } else if !seed_install_refused
                                    && pending_decision.resolution.tunnel_endpoint_id == 0
                                    && let Some(hop) = pending_decision.resolution.next_hop
                                {
                                    let pending_key = (pending_decision.resolution.egress_ifindex, hop);
                                    // #1782: split the buffer-admission test so
                                    // the capture can tell WHY a sibling was not
                                    // buffered. The DuplicateDrop branch is the
                                    // H5 sibling drop (key already pending — the
                                    // first packet drove the kernel probe); the
                                    // CapacityDrop branch is a distinct
                                    // condition, counted SEPARATELY (#2375) in
                                    // pending_neigh_capacity_drops. #1771
                                    // §2.4: the decision is the pure
                                    // `pending_neigh_admission` helper so
                                    // invariant N1's "at most one buffered
                                    // packet per key" half is unit-tested;
                                    // behavior is unchanged — an insert happens
                                    // iff the key is absent AND there is room,
                                    // otherwise `recycle_now` stays true and
                                    // the frame is recycled.
                                    let admission = pending_neigh_admission(
                                        binding.pending_neigh.contains_key(&pending_key),
                                        binding.pending_neigh.len(),
                                    );
                                    // #2375: record the drop counters via the
                                    // extracted helper so both the duplicate and
                                    // the capacity case are a unit-tested
                                    // side-effect (the test fails if either
                                    // increment is removed). Buffer is a no-op
                                    // here — the buffering insert stays inline
                                    // below.
                                    record_pending_neigh_admission_drop(&binding.live, admission);
                                    match admission {
                                        PendingNeighAdmission::DuplicateDrop => {}
                                        PendingNeighAdmission::Buffer => {
                                            // #2357: when this buffered packet is
                                            // later flushed by retry_pending_neigh,
                                            // its stored flow_key drives
                                            // resolve_cos_tx_selection_at (egress
                                            // queue / DSCP / output-filter). A
                                            // non-first IP fragment carries no L4
                                            // header, so refuse to synthesize a
                                            // ported tuple from metadata for it —
                                            // store `None` so the flush selects the
                                            // interface default queue with no
                                            // port-filter eval. `flow` is already
                                            // `None` for a fragment (#2344); the
                                            // gate only suppresses the meta
                                            // fallback, leaving legitimate flowless
                                            // TCP/UDP packets (real L4 header) their
                                            // meta-derived ports. `raw_frame` is the
                                            // UMEM slice for `desc`; this branch is
                                            // only reached when
                                            // `owned_packet_frame.is_none()`, so it
                                            // describes the packet `meta` refers to.
                                            // #2357/#3290: stored flow_key drives
                                            // CoS/output-filter selection AND the TX
                                            // request when retry_pending_neigh later
                                            // flushes this packet. The helper gates
                                            // the metadata fallback (non-first
                                            // fragment, and non-identifier-bearing
                                            // ICMP) so a fabricated pseudo-port is
                                            // never buffered — the SAME gate the
                                            // immediate forward path and the
                                            // conntrack path apply. `raw_frame` is
                                            // the UMEM slice for `desc` (this branch
                                            // is only reached when
                                            // `owned_packet_frame.is_none()`).
                                            let pending_flow_key = pending_neigh_flow_key(
                                                flow.as_ref(),
                                                raw_frame,
                                                meta,
                                            );
                                            binding.pending_neigh.insert(
                                                pending_key,
                                                PendingNeighPacket {
                                                    addr: desc.addr,
                                                    desc,
                                                    meta,
                                                    decision: pending_decision,
                                                    flow_key: pending_flow_key,
                                                    queued_ns: now_ns,
                                                    probe_attempts: 0,
                                                },
                                            );
                                            recycle_now = false;
                                        }
                                        PendingNeighAdmission::CapacityDrop => {
                                            // #2375: a NEW distinct hop refused
                                            // because pending_neigh is at
                                            // MAX_PENDING_NEIGH (distinct-hop
                                            // neighbor exhaustion — the
                                            // scan/upstream-outage failure mode).
                                            // The counter increment is the helper
                                            // call above; the frame is recycled
                                            // exactly like the duplicate branch
                                            // (recycle_now stays true).
                                        }
                                    }
                                }
                                if cfg!(feature = "debug-log") {
                                    if telemetry.dbg.missing_neigh <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
                                                "SOLICIT+SLOW",
                                                flow.src_ip,
                                                flow.forward_key.src_port,
                                                flow.dst_ip,
                                                flow.forward_key.dst_port,
                                                meta.protocol,
                                                pending_decision.resolution.egress_ifindex,
                                                pending_decision.resolution.next_hop,
                                            );
                                        }
                                    }
                                }
                                StageOutcome::Continue(())
                            };
                            if let StageOutcome::RecycleAndContinue = missing_neighbor_outcome {
                                // Fresh RX descriptor: the arm's recycle outcome is
                                // consumed by the SINGLE scratch_recycle push +
                                // continue here; the continue skips the recycle_now
                                // epilogue below.
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                        }
                        ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
                        ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
                        _ => telemetry.dbg.disposition_other += 1,
                    }
                    record_forwarding_disposition(
                        &worker_ctx.ident,
                        DispositionCounters::Hot(telemetry.counters),
                        decision.resolution,
                        desc.len as u32,
                        Some(meta),
                        debug.as_ref(),
                        worker_ctx.recent_exceptions,
                        worker_ctx.last_resolution,
                        worker_ctx.forwarding,
                    );
                    // #1913: gate the trailing reinjection with the
                    // shared allow-list. Without this, PolicyDenied /
                    // HAInactive / DiscardRoute frames were handed to
                    // the kernel FIB unfiltered (a zone-policy DENY
                    // silently bypassed on the cold path). When the
                    // predicate rejects the disposition the frame is
                    // already counted by record_forwarding_disposition
                    // above and recycled by the recycle_now epilogue
                    // below — no leak, no double-count.
                    if slow_path_admit(&binding.live, decision.resolution.disposition) {
                        maybe_reinject_slow_path_from_frame(
                            &worker_ctx.ident,
                            &binding.live,
                            worker_ctx.slow_path,
                            worker_ctx.local_tunnel_deliveries,
                            packet_frame,
                            meta,
                            decision,
                            worker_ctx.recent_exceptions,
                            "slow_path",
                            worker_ctx.forwarding,
                        );
                    }
                }
            } else {
                record_disposition(
                    &worker_ctx.ident,
                    &binding.live,
                    DispositionCounters::Hot(telemetry.counters),
                    disposition,
                    desc.len as u32,
                    Some(meta),
                    worker_ctx.recent_exceptions,
                    worker_ctx.forwarding,
                );
            }
        } else {
            telemetry.dbg.metadata_err += 1;
            binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
            record_exception(
                worker_ctx.recent_exceptions,
                &worker_ctx.ident,
                "metadata_parse",
                desc.len as u32,
                None,
                None,
                worker_ctx.forwarding,
            );
        }
        if recycle_now {
            binding.scratch.scratch_recycle.push(desc.addr);
        }
    }
    received.release();
    drop(received);
}
