// Session-delta processing extracted from afxdp.rs (Issue 67.1).
// `flush_session_deltas` is the workhorse: it drains the per-binding
// SessionDelta queues, applies them to the SessionTable, and emits
// the corresponding session-life events to the event-stream channel.
// `purge_queued_flows_for_closed_deltas` post-processes per-binding
// pending-forward queues to drop frames whose flow is now closed,
// and `session_delta_event` is a tiny string-mapping helper.
//
// Pure relocation. `use super::*;` brings every type, helper, and
// sibling-submodule item from afxdp.rs into scope.

use super::*;
// #6949: the single-source HA attribution shared with the binary open-frame
// producer. Named explicitly rather than left to the glob so the coupling
// between the two session-delta legs is visible at the top of this file.
use crate::session::{SessionSyncAttribution, nat64_snat_v4_string};

/// #5290: fairly drain up to `max` session deltas across `bindings` using a
/// rotating cursor and a per-binding quantum, instead of handing the whole
/// budget to each binding in slot order with an early break.
///
/// The old whole-budget-first-binding drain let a single low-slot worker with
/// many pending deltas consume the entire caller-wide budget during the
/// event-stream RPC fallback, starving higher-slot workers so HA state quality
/// depended on worker-slot assignment. This spreads a `budget / num_bindings`
/// quantum across every live binding per pass, and returns the cursor to resume
/// from next call so no binding is perpetually starved across successive drains
/// (a budget < num_bindings still makes progress and the remainder is served
/// first next time).
///
/// Returns `(drained, next_cursor, overflow)`:
/// - `drained`: the deltas popped (at most `max`), in fair round-robin order.
/// - `next_cursor`: the binding index to resume from on the next call.
/// - `overflow`: true when the budget was exhausted AND at least one binding
///   still holds undrained deltas. The steady-state RPC-fallback caller
///   (`Coordinator::drain_session_deltas`) uses this to arm loss-of-sync on the
///   residual bindings so a full owner-RG resync recovers them (never a silent
///   drop). The bulk owner-RG export caller ignores it — that path IS the
///   resync, and its completeness is governed by the caller-supplied `max`.
pub(in crate::afxdp) fn drain_session_deltas_fair(
    bindings: &[&BindingLiveState],
    max: usize,
    start_cursor: usize,
) -> (Vec<SessionDeltaInfo>, usize, bool) {
    let n = bindings.len();
    if n == 0 {
        return (Vec::new(), start_cursor, false);
    }
    let mut budget = max.max(1);
    // Per-turn quantum: spread the budget across all live bindings so no single
    // binding drains more than its fair share before the others get a turn. At
    // least 1 so a budget < n still makes progress (the cursor covers the
    // remaining bindings on the next call).
    let quantum = (budget / n).max(1);
    let mut out = Vec::new();
    let mut cursor = start_cursor % n;
    loop {
        let mut progressed = false;
        for _ in 0..n {
            if budget == 0 {
                break;
            }
            let take = quantum.min(budget);
            let drained = bindings[cursor].drain_session_deltas(take);
            cursor = (cursor + 1) % n;
            let got = drained.len();
            if got > 0 {
                progressed = true;
                // got <= take <= budget, so this never underflows.
                budget = budget.saturating_sub(got);
                out.extend(drained);
            }
        }
        // Stop once the budget is spent or a full pass drained nothing (every
        // binding is now empty).
        if budget == 0 || !progressed {
            break;
        }
    }
    // Overflow only matters when the budget capped us: if we stopped because a
    // full pass drained nothing, every binding is empty and no delta was left
    // behind. The scan re-locks each buffer (cold control path only).
    let overflow =
        budget == 0 && bindings.iter().any(|b| b.has_pending_session_deltas());
    (out, cursor, overflow)
}

pub(super) fn purge_queued_flows_for_closed_deltas(
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    deltas: &[SessionDelta],
) {
    for delta in deltas {
        if delta.kind != SessionDeltaKind::Close {
            continue;
        }
        let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
        for binding in bindings.iter_mut() {
            cancel_queued_flow_on_binding(
                binding,
                &delta.key,
                &reverse_key,
                Some(shared_recycles),
            );
        }
        apply_shared_recycles_to_bindings(bindings, binding_lookup, shared_recycles);
    }
}

/// Convert one internal `SessionDelta` into the JSON `SessionDeltaInfo` the
/// control-plane RPC legs carry: the `drain_session_deltas` polling fallback
/// used while the binary event stream is down, and the owner-RG resync export.
///
/// Split out of `flush_session_deltas` so the field-by-field wire mapping is
/// reachable on its own — that function needs live BPF map fds, per-binding
/// shared state and an event-stream handle, so nothing could test what this
/// leg actually puts on the wire (#6312).
pub(in crate::afxdp) fn session_delta_info(
    ident: &BindingIdentity,
    delta: &SessionDelta,
    zone_id_to_name: &FastMap<u16, String>,
) -> SessionDeltaInfo {
    // #919/#922: emit both the resolved zone NAMES (legacy field,
    // empty when the ID is unknown) and the u16 IDs. New daemons
    // prefer the IDs; older daemons read the names. The previous
    // code wrote `metadata.ingress_zone.to_string()` here, which
    // produced "1"/"2" string literals that broke `zoneIDs[name]`
    // on the Go side.
    let ingress_name = zone_id_to_name
        .get(&delta.metadata.ingress_zone)
        .cloned()
        .unwrap_or_default();
    let egress_name = zone_id_to_name
        .get(&delta.metadata.egress_zone)
        .cloned()
        .unwrap_or_default();
    // #6949: the HA-carried policy attribution comes from the SAME helper the
    // binary open frame uses (`event_stream::codec::encode_session_open`), so
    // the two legs cannot describe one session differently. The destructure is
    // EXHAUSTIVE on purpose — no `..` — so a field added to
    // `SessionSyncAttribution` fails to compile here until this leg carries it
    // too. Before #6949 this leg carried none of these five.
    let SessionSyncAttribution {
        policy_id,
        policy_counter_idx,
        inactivity_timeout_secs,
        nat64,
        nat64_snat_v4,
    } = SessionSyncAttribution::from_session(&delta.decision, &delta.metadata);
    SessionDeltaInfo {
        timestamp: Utc::now(),
        slot: ident.slot,
        queue_id: ident.queue_id,
        worker_id: ident.worker_id,
        interface: ident.interface.to_string(),
        ifindex: ident.ifindex,
        event: session_delta_event(delta.kind).to_string(),
        addr_family: delta.key.addr_family,
        protocol: delta.key.protocol,
        src_ip: delta.key.src_ip.to_string(),
        dst_ip: delta.key.dst_ip.to_string(),
        src_port: delta.key.src_port,
        dst_port: delta.key.dst_port,
        ingress_zone: ingress_name,
        egress_zone: egress_name,
        ingress_zone_id: delta.metadata.ingress_zone,
        egress_zone_id: delta.metadata.egress_zone,
        owner_rg_id: delta.metadata.owner_rg_id,
        disposition: match delta.decision.resolution.disposition {
            ForwardingDisposition::ForwardCandidate => "forward_candidate",
            ForwardingDisposition::LocalDelivery => "local_delivery",
            ForwardingDisposition::NoRoute => "no_route",
            ForwardingDisposition::MissingNeighbor => "missing_neighbor",
            ForwardingDisposition::PolicyDenied => "policy_denied",
            ForwardingDisposition::FabricRedirect => "fabric_redirect",
            ForwardingDisposition::HAInactive => "ha_inactive",
            ForwardingDisposition::DiscardRoute => "discard_route",
            ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
        }
        .to_string(),
        origin: delta.origin.as_str().to_string(),
        egress_ifindex: delta.decision.resolution.egress_ifindex,
        tx_ifindex: delta.decision.resolution.tx_ifindex,
        tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
        tx_vlan_id: delta.decision.resolution.tx_vlan_id,
        next_hop: delta
            .decision
            .resolution
            .next_hop
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        neighbor_mac: delta
            .decision
            .resolution
            .neighbor_mac
            .map(format_mac)
            .unwrap_or_default(),
        src_mac: delta
            .decision
            .resolution
            .src_mac
            .map(format_mac)
            .unwrap_or_default(),
        nat_src_ip: delta
            .decision
            .nat
            .rewrite_src
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        nat_dst_ip: delta
            .decision
            .nat
            .rewrite_dst
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        nat_src_port: delta.decision.nat.rewrite_src_port.unwrap_or(0),
        nat_dst_port: delta.decision.nat.rewrite_dst_port.unwrap_or(0),
        fabric_redirect: delta.fabric_redirect_sync
            || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
        fabric_ingress: delta.metadata.fabric_ingress,
        // #2785: carry the per-policy log selection on the JSON fallback
        // delta so the synced session logs identically after failover.
        log_session_init: delta.metadata.log_session_init,
        log_session_close: delta.metadata.log_session_close,
        // #6312: carry the ORIGINATING node's stable RT_FLOW session id on the
        // JSON leg too. `SessionDelta.session_id` is the same value the binary
        // open frame's trailing u64 carries (#5212); before this the JSON leg
        // dropped it and a session recovered through a full resync lost its
        // cross-node correlation. 0 (a synthesized delta with no backing entry)
        // keeps the legacy "peer allocates a fresh local id" behaviour.
        rt_flow_session_id: delta.session_id,
        // #7239 (#7160/#2387): carry the key's ROUTING DOMAIN on the JSON leg
        // too, at parity with the binary open frame's trailing u32. The value
        // comes off the KEY, so it is the domain stamped at install from the
        // interface the flow actually arrived on — which is the whole reason it
        // is carried rather than re-derived on the peer from an ingress fold
        // that can name a recycled sibling.
        routing_domain: crate::session::routing_domain_to_wire(delta.key.routing_domain),
        // #6949: carry the admitting policy's firewall metadata on the JSON leg
        // too. The binary open frame has carried policy_id/policy_counter_idx
        // since #3301 and the app timeout since #3227; this leg carried none,
        // so a session recovered through the drain fallback or a FullResync
        // export imported policy 0 (rendered `unattributed`, and excluded from
        // the commit-time deletion-clear and the #4234 policy-rematch because
        // id 0 is skipped there), no per-rule hit counter, and the global idle
        // timeout instead of its per-application one.
        policy_id,
        policy_counter_idx,
        app_timeout: inactivity_timeout_secs,
        // #6949/#4565: without the pool source a NAT64 session promoted from
        // this leg cannot rebuild its reverse v4->v6 BIB at all — the standby
        // cannot derive it from the synced forward v6 key.
        nat64,
        nat64_snat_v4: nat64_snat_v4_string(nat64_snat_v4),
        // #7188: carry the session key's tunnel discriminator on the JSON leg.
        // Read from `delta.key`, the SAME key the binary open frame encodes, so
        // the two legs cannot describe one session's identity differently. A
        // non-GRE session encodes `None`, which is an EXPLICIT statement and not
        // the reserved absent tag 0 — that distinction is what lets the receiver
        // withhold a protocol-47 session from a peer that cannot express it
        // instead of importing it aliased onto another tunnel's key.
        tunnel_discriminator: delta.key.discriminator.to_wire(),
        // #9412: the close class, on the JSON leg exactly as on the binary frame.
        tcp_close_class: delta.tcp_close_class,
    }
}

// #2669: `live` is `Option` because a drain cycle can coincide with an
// empty `bindings` slice (XSK sockets admin-down / unconfigured during a
// reload or transaction while the session table is still aging entries
// out). The drained deltas MUST still reach every binding-independent
// consumer — the shared session/conntrack tables, the peer-worker command
// queues, the HA delete replication, the recent-deltas RPC buffer, and the
// event stream — so they are flushed unconditionally below. Only the
// per-binding RPC fallback push (`live.push_session_delta`) is gated on a
// binding existing: with no binding there is no interface-local RPC queue
// to push into. Previously the entire flush was skipped when `bindings`
// was empty, but the deltas were still drained off the ring — silently
// discarding session-close/expire events and desynchronizing peers,
// sibling workers, and CLI/gRPC visibility.
// Returns `true` if a correctness-critical HA session open/close delta could
// not be queued losslessly to the event-stream consumer (channel wedged or peer
// disconnected) — #2874. The caller latches loss-of-sync so the worker loop
// re-exports the full owner-RG snapshot (the #2442 recovery path) and the peer
// re-derives a complete session view instead of silently missing the delta.
//
// #5468 (aggregate bound): `worker_lossless_wedged` is an in/out per-drain-cycle
// latch shared by EVERY `flush_session_deltas` call the worker loop makes in one
// iteration (the steady-state incremental drain, the #2442 loss-of-sync resync,
// AND the #2653 command export). Each individual call already bounds its lossless
// backpressure to a single `WORKER_LOSSLESS_QUEUE_BUDGET` wait, but the resync /
// export paths call this ONCE PER 256-delta batch across the entire owned-session
// set — so for K owned sessions an unread peer would cost ~(K/256) budgets of
// worker-loop stall, re-crossing `HEARTBEAT_STALE_AFTER` for large K and
// re-triggering the SAME spurious failover via the resync path. To bound the
// AGGREGATE, the first wedged call sets `*worker_lossless_wedged`; every
// subsequent call this cycle inherits it and SKIPS the lossless wait entirely
// (it never attempts a push, so no further budget is spent), while still draining
// each delta to its other consumers — the per-binding live RPC buffer, the shared
// conntrack/session tables, peer-worker delete replication, and the best-effort
// RT_FLOW frames. Losslessness is preserved: every wedged call still returns
// `true` so the caller keeps the loss-of-sync latch set and the resync retries
// next cycle (deliver-or-resync, never a silent drop). Net effect: the worker
// loop's total lossless WAIT per drain cycle is ~1 budget regardless of K.
pub(super) fn flush_session_deltas(
    ident: &BindingIdentity,
    live: Option<&BindingLiveState>,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    // #2979: the reverse-NAT dnat_table / dnat_table_v6 fds so a closing SNAT
    // session's published reverse-NAT entry is deleted here, mirroring the
    // session_map / conntrack cleanup below. Without it the HASH (non-LRU)
    // dnat_table leaks one entry per closed SNAT session until it fills.
    dnat_fds: &super::checksum::DnatTableFds,
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    // #8114 item 4: the same queues keyed by worker id, so a `DeleteSynced` a
    // full sibling queue REFUSES can be attributed and that sibling's NAT
    // holder bit released on its behalf.
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    forwarding: &ForwardingState,
    // #5468: per-drain-cycle aggregate lossless-wedge latch (see doc above).
    worker_lossless_wedged: &mut bool,
) -> bool {
    let zone_name_to_id = &forwarding.zone_name_to_id;
    let zone_id_to_name = &forwarding.zone_id_to_name;
    // #2874: set the moment a session open/close delta cannot be queued
    // losslessly to the event-stream consumer. Once set we stop attempting
    // further lossless pushes this batch — the full owner-RG resync the caller
    // schedules supersedes the remaining incremental deltas, and this bounds the
    // worst-case producer backpressure to a single lossless wait per drain
    // cycle even when the consumer is genuinely wedged. #5468: that single wait
    // is itself bounded to `WORKER_LOSSLESS_QUEUE_BUDGET` (well below
    // `HEARTBEAT_STALE_AFTER`), so the worst case is one short worker stall per
    // drain cycle rather than a full 5 s heartbeat-threatening block.
    //
    // #5468 (aggregate): seed the flag from the per-drain-cycle wedge latch so a
    // resync/export that calls this once per 256-delta batch does NOT pay a fresh
    // budget wait on every batch. If a prior batch this cycle already wedged, we
    // start out-of-sync and never attempt another lossless push — the aggregate
    // worker-loop wait stays ~1 budget regardless of the owned-session count K.
    let mut event_stream_out_of_sync = *worker_lossless_wedged;
    for delta in deltas {
        let info = session_delta_info(ident, delta, zone_id_to_name);
        // #2669: per-binding RPC fallback push is the ONLY binding-dependent
        // step. Skipped when no binding exists; every consumer below is
        // binding-independent and runs regardless.
        if let Some(live) = live {
            // #8593: route on the DELTA, not on a flag the call site chose. A
            // bulk owner-RG export delta whose push is refused must not arm the
            // loss-of-sync latch — that latch triggers the export that produced
            // it. Deciding here means a new drain call site cannot get it wrong,
            // because it does not choose.
            if delta.bulk_resync {
                live.push_session_delta_bulk_export(info.clone());
            } else {
                live.push_session_delta(info.clone());
            }
        }
        // Push to event stream (new path) alongside existing RPC fallback.
        if let Some(es) = event_stream {
            // #2874: route the correctness-critical HA session open/close delta
            // through the LOSSLESS producer instead of the lossy `push_delta`.
            // `push_delta`'s `try_send` silently drops on a full channel AFTER
            // burning a sequence number, leaving a hole the Go consumer then
            // cumulatively ACKs past — permanently trimming the helper replay
            // window over a missing open/close (silent standby session loss,
            // the #2874 defect). `push_delta_lossless` applies the producer's
            // bounded backpressure and PROPAGATES a genuine failure (peer
            // disconnect / queue timeout) as an error instead of swallowing it.
            // On failure we latch out-of-sync; the caller then re-exports the
            // full owner-RG snapshot (the #2442 recovery path) so the peer
            // re-derives a complete session view. The RT_FLOW telemetry frames
            // below stay best-effort (`try_send`) — a dropped flow-export record
            // is not a correctness loss and must not force a resync.
            //
            // #5468: this runs on the PACKET WORKER LOOP, so the lossless send is
            // BOUNDED to `WORKER_LOSSLESS_QUEUE_BUDGET` (well below
            // `HEARTBEAT_STALE_AFTER`) instead of the 5 s `LOSSLESS_QUEUE_TIMEOUT`.
            // A connected-but-unread peer (full lossless queue) that blocked the
            // worker for the full 5 s would stop the loop stamping its heartbeat,
            // the peer would mark this node stale, and a spurious failover would
            // fire. On the bounded timeout we latch out-of-sync exactly as on any
            // other lossless failure — deliver-or-resync, never a silent drop, so
            // the #2874 losslessness contract holds.
            if !event_stream_out_of_sync {
                if let Err(err) =
                    es.push_delta_lossless_within(delta, zone_name_to_id, WORKER_LOSSLESS_QUEUE_BUDGET)
                {
                    event_stream_out_of_sync = true;
                    eprintln!(
                        "xpf-event-stream: HA session-sync delta could not be queued losslessly ({err}); latching out-of-sync to force a full owner-RG resync"
                    );
                }
            }
            // #2460: a Close delta also emits a SEPARATE RT_FLOW
            // SESSION_CLOSE frame (type 14) on the raw dataplane-event
            // channel. `push_delta` above already sent the type-2 HA
            // session-sync close delta unchanged; this is ADDITIVE and
            // feeds the Go NetFlow/IPFIX session-close exporters, which only
            // fire on a `Type == "SESSION_CLOSE"` EventRecord (never
            // produced in userspace mode before this). The two frames are a
            // 1:1 pair per close — no double-counting on the HA channel.
            if delta.kind == SessionDeltaKind::Close {
                // #2520: resolve the AppID for the closing 5-tuple with the
                // SAME app_catalog the forwarding hot path runs, so the
                // SESSION_CLOSE RT_FLOW record carries the application instead
                // of UNKNOWN. 0 (no match) keeps the prior UNKNOWN rendering.
                // #3321: resolve directionally off the delta's own direction
                // flag (service = dst forward / src reverse) so a forward flow
                // with a service-valued source port is not mislabeled.
                // #3416: resolve the FORWARD service port from the
                // post-translation destination (the DNAT-rewritten port the
                // policy admitted the session under), mirroring the deny side,
                // so a port-forwarded service is not mislabeled UNKNOWN/public.
                let app_id = forwarding.app_catalog.lookup_admitted(
                    delta.key.protocol,
                    delta.key.src_port,
                    delta.key.dst_port,
                    delta.metadata.is_reverse,
                    delta.decision.nat.rewrite_dst_port,
                );
                // #3395: re-resolve the admitting policy's CURRENT positional id
                // from the session's bound rule handle against the live rule
                // table. A live mid-list policy insert/delete renumbers every
                // later rule, so the frozen `delta.metadata.policy_id` would name
                // the wrong policy on the close log; the close path already holds
                // `forwarding.policy`, so this needs no new plumbing. A deleted
                // admitting rule resolves to the unattributed default-policy
                // sentinel (never a reassigned index); an unbound (non-policy /
                // peer-synced) session keeps its frozen id.
                let reresolved_policy_id = forwarding.policy.reresolve_session_policy_id(
                    delta.metadata.policy_counter.as_ref(),
                    delta.metadata.policy_id,
                );
                // #2615: thread the closing binding's ingress ifindex so the
                // SESSION_CLOSE RT_FLOW record shows the admitting interface
                // (`packet-incoming-interface`) instead of "N/A". `ident` is
                // the binding draining this delta; its ifindex is the ingress
                // interface. A kernel ifindex is always positive, so the
                // i32 -> u32 cast is loss-free.
                es.emit_session_close_rt_flow(
                    delta,
                    app_id,
                    ident.ifindex as u32,
                    reresolved_policy_id,
                );
            }
            // #2508: a session admitted by a policy configured with
            // `then log session-init` emits an RT_FLOW SESSION_CREATE frame
            // (type 15) on the same raw dataplane-event channel. Unlike the
            // close frame this is producer-gated: there is no flowexport
            // consumer of session opens, so we only ever send it when the
            // admitting policy requested session-init logging. The
            // SESSION_CLOSE syslog record is gated on the Go side (via the
            // frame's gate byte) because flowexport still needs every close.
            if delta.kind == SessionDeltaKind::Open && delta.metadata.log_session_init {
                // #2615: resolve the AppID for the new 5-tuple with the SAME
                // app_catalog the forwarding hot path runs (mirroring the #2520
                // close-side fix), so the SESSION_CREATE RT_FLOW record carries
                // the application instead of UNKNOWN. 0 (no match) keeps the
                // prior UNKNOWN rendering. The ingress ifindex comes from the
                // admitting binding (`ident`); a kernel ifindex is always
                // positive so the i32 -> u32 cast is loss-free.
                // #3321: directional resolution off the delta's direction flag
                // (service = dst forward / src reverse).
                // #3416: forward service port from the post-translation
                // (DNAT-rewritten) destination — the port the policy admitted
                // the session under — so a port-forwarded create record carries
                // the admitting application instead of UNKNOWN/the public port.
                let app_id = forwarding.app_catalog.lookup_admitted(
                    delta.key.protocol,
                    delta.key.src_port,
                    delta.key.dst_port,
                    delta.metadata.is_reverse,
                    delta.decision.nat.rewrite_dst_port,
                );
                es.emit_session_create_rt_flow(delta, app_id, ident.ifindex as u32);
            }
        }
        if let Ok(mut recent) = recent_session_deltas.lock() {
            push_recent_session_delta(&mut recent, info);
        }
        if delta.kind == SessionDeltaKind::Close {
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE: proto={} {}:{} -> {}:{} nat_src={:?} nat_dst={:?} bpf_entries_before={}",
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.src_port,
                    delta.key.dst_ip,
                    delta.key.dst_port,
                    delta.decision.nat.rewrite_src,
                    delta.decision.nat.rewrite_dst,
                    count_bpf_session_entries(session_map_fd),
                );
            }
            delete_live_session_entry(
                session_map_fd,
                &delta.key,
                delta.decision.nat,
                delta.metadata.is_reverse,
            );
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &delta.key);
            // #2979: delete the dynamic reverse-NAT dnat_table entry this
            // SNAT'd session published at install. Keyed on the SAME forward
            // key + nat decision used by publish_dnat_table_entry (the Close
            // delta carries the forward key — it is gated on !is_reverse at
            // construction in session/expire.rs and session/mod.rs). A
            // non-SNAT session is a no-op (no rewrite_src -> no key). Only the
            // forward key publishes a dnat_table entry, so it is NOT repeated
            // for the reverse key below.
            super::checksum::delete_dnat_table_entry(dnat_fds, &delta.key, delta.decision.nat);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &reverse_key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &reverse_key,
            );
            // #8114 item 4: repair the sibling NAT holder bit a refused
            // `DeleteSynced` would otherwise strand. The forward key carries
            // the reservation; the reverse call self-gates on `is_reverse` and
            // is a no-op for it, exactly as `handle_delete_synced` is.
            replicate_session_delete_repairing(
                peer_worker_commands,
                worker_commands_by_id,
                forwarding,
                &delta.key,
                delta.decision.nat,
                delta.metadata.is_reverse,
                crate::afxdp::wg::counters::monotonic_now_ns(),
            );
            // #1069: reuse the reverse_key already computed above instead of
            // recomputing it. reverse_session_key is pure on its inputs and
            // delta + nat are not modified between the two replicate calls.
            replicate_session_delete_repairing(
                peer_worker_commands,
                worker_commands_by_id,
                forwarding,
                &reverse_key,
                delta.decision.nat,
                true,
                crate::afxdp::wg::counters::monotonic_now_ns(),
            );
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE_DONE: bpf_entries_after={}",
                    count_bpf_session_entries(session_map_fd),
                );
            }
        }
    }
    // #5468: propagate this batch's wedge into the per-drain-cycle latch so the
    // NEXT `flush_session_deltas` call this cycle (the next resync/export batch)
    // inherits it and skips the lossless wait — bounding the aggregate worker-loop
    // wait to ~1 budget regardless of the owned-session count.
    if event_stream_out_of_sync {
        *worker_lossless_wedged = true;
    }
    event_stream_out_of_sync
}

fn session_delta_event(kind: SessionDeltaKind) -> &'static str {
    match kind {
        SessionDeltaKind::Open => "open",
        SessionDeltaKind::Close => "close",
        // #9412: the JSON leg names it; the Go walker syncs it like an open.
        SessionDeltaKind::Update => "update",
    }
}
