//! RT_FLOW session create/close projection.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. These two
//! `EventStreamWorkerHandle` emitters project a session-sync `SessionDelta` into
//! the RT_FLOW SESSION_CLOSE (type 14) / SESSION_CREATE (type 15) wire frames the
//! Go NetFlow/IPFIX and per-policy syslog exporters consume. Both route through
//! the shared per-kind rate-limiter + queue-budget path (`try_emit_dataplane_frame`
//! in producer.rs), anchoring monotonic session instants to wall-clock via
//! clock.rs at emit time (#2465/#2853).

use super::*;

impl EventStreamWorkerHandle {
    /// #2460: emit a SESSION_CLOSE RT_FLOW frame (type 14) for a Close delta
    /// on the raw dataplane-event channel.
    ///
    /// This is ADDITIVE to — and must be called ALONGSIDE, never instead of
    /// — `push_delta`, which carries the unchanged type-2 HA session-sync
    /// close delta. The RT_FLOW frame drives the Go NetFlow/IPFIX
    /// session-close exporters (`pkg/daemon/daemon_flowexport.go`), which
    /// only run on a `Type == "SESSION_CLOSE"` `logging.EventRecord` — a
    /// record userspace mode never produced before this. The caller
    /// (`flush_session_deltas`) gates on `delta.kind == Close`, but the
    /// guard is repeated here so a future caller cannot misuse it on an Open
    /// delta. Best-effort (`try_send`): a dropped close frame loses only one
    /// flow-export record, never the HA close delta (a separate frame).
    /// `app_id` is the application resolved for the closing session's 5-tuple
    /// by the caller (`flush_session_deltas`) via the same `app_catalog.lookup`
    /// the forwarding hot path runs — #2520. 0 means UNKNOWN (no catalog
    /// match), the unchanged behavior.
    /// `ingress_ifindex` is the closing binding's interface index (#2615); the
    /// Go side resolves it to the RT_FLOW `packet-incoming-interface`. 0 keeps
    /// the prior "N/A" rendering.
    ///
    /// #3395: `policy_id` is the RE-RESOLVED admitting policy id, computed by the
    /// caller (`flush_session_deltas`) from the session's bound rule handle
    /// against the CURRENT rule table — NOT `delta.metadata.policy_id` (which is
    /// frozen at install and goes stale after a live policy reorder). The caller
    /// owns re-resolution because only it holds the `ForwardingState`/`PolicyState`
    /// the lookup needs.
    pub(crate) fn emit_session_close_rt_flow(
        &self,
        delta: &SessionDelta,
        app_id: u16,
        ingress_ifindex: u32,
        policy_id: u32,
    ) {
        if delta.kind != SessionDeltaKind::Close {
            return;
        }
        let nat = &delta.decision.nat;
        // #2465: convert the monotonic creation / last-seen instants on the
        // close delta to absolute wall-clock values for the wire. The session
        // table uses CLOCK_MONOTONIC, but the flow record needs an absolute
        // StartTime (and the EndTime is a wall-clock instant on the Go side),
        // so we anchor monotonic deltas against a single (mono, wall) reading
        // taken here at emit time. A 0 created_ns stays 0 on the wire and
        // triggers the Go-side packet-count fallback.
        let (now_mono_ns, now_unix_ns) = read_mono_and_wall_clocks();
        // #2853: carry BOTH the integer Unix second (offset 108) and the
        // sub-second nanosecond remainder (offset 44, the close-unused policy_id
        // slot) so the Go exporters render a millisecond-accurate flow
        // StartTime. The pre-#2853 code stamped only the truncated second, so
        // every flow opened in the same second shared one start instant.
        let (created_unix_secs, created_subsec_nanos) =
            monotonic_ns_to_unix_secs_subnanos(delta.created_ns, now_mono_ns, now_unix_ns);
        let close_unix_ns = monotonic_ns_to_unix_ns(delta.last_seen_ns, now_mono_ns, now_unix_ns);
        // #2512: route through the per-kind rate limiter + queue budget +
        // sent/dropped counters instead of a bare `try_send`. The same mono
        // clock reading anchors the limiter so a dropped close is counted
        // under DataplaneEventKind::SessionClose. The frame is encoded only
        // after the budget passes (seq supplied by the budget path), so a
        // rate-limited / budget-exhausted close never burns a sequence
        // number. A dropped close loses only one flow-export record — the
        // separate type-2 HA close delta (`push_delta`) is untouched.
        self.try_emit_dataplane_frame(
            DataplaneEventKind::SessionClose,
            delta.metadata.ingress_zone,
            now_mono_ns,
            |seq| {
                EventFrame::encode_session_close_rt_flow(
                    seq,
                    delta.key.addr_family,
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.dst_ip,
                    delta.key.src_port,
                    delta.key.dst_port,
                    nat.rewrite_src,
                    nat.rewrite_dst,
                    nat.rewrite_src_port.unwrap_or(0),
                    nat.rewrite_dst_port.unwrap_or(0),
                    delta.metadata.ingress_zone,
                    delta.metadata.egress_zone,
                    // #3056: the admitting policy ID, so the SESSION_CLOSE
                    // RT_FLOW record (and the NetFlow/IPFIX close exporters) name
                    // the policy that admitted the flow instead of policy 0.
                    // Rides the trailing [136:140] slot because #2853 took
                    // [44:48] on a close. #3395: this is the caller's RE-RESOLVED
                    // id (current positional id of the bound admitting rule),
                    // not the frozen `delta.metadata.policy_id`, so a live policy
                    // reorder before the close no longer mis-attributes the
                    // record.
                    policy_id,
                    delta.metadata.owner_rg_id as i16,
                    // #2508: per-policy RT_FLOW SYSLOG gate byte. The frame is
                    // sent unconditionally (the Go NetFlow/IPFIX exporter
                    // accounts every close), but this bit tells the Go
                    // logEvent path whether to ALSO emit the per-policy
                    // RT_FLOW_SESSION_CLOSE syslog record.
                    delta.metadata.log_session_close,
                    created_unix_secs,
                    // #2853: sub-second nanosecond remainder of the creation
                    // instant, rides the [44:48] slot (unused on a close).
                    created_subsec_nanos,
                    close_unix_ns,
                    // #2520: carry the resolved AppID in the [132:134] wire
                    // slot so SESSION_CLOSE RT_FLOW records (and the
                    // NetFlow/IPFIX exporters) show the application.
                    app_id,
                    // #2615: carry the closing binding's ingress ifindex in
                    // the [128:132] wire slot so the record shows the
                    // admitting interface instead of "N/A".
                    ingress_ifindex,
                    // #2501: real per-session volume harvested off the
                    // expiring entry's counters, into the reserved
                    // [56:64]/[64:72] (forward) and [112:120]/[120:128]
                    // (reverse) slots.
                    delta.counters.fwd_packets,
                    delta.counters.fwd_bytes,
                    delta.counters.rev_packets,
                    delta.counters.rev_bytes,
                    // #2749: observed forward ToS + cumulative TCP control
                    // bits harvested off the closing entry, and the session's
                    // resolved egress (output) interface. These drive the
                    // re-introduced NetFlow v9 / IPFIX close-record fields
                    // (srcTos/ipClassOfService, tcpControlBits, egressInterface
                    // / OutputSNMP). A kernel ifindex is positive; a 0/unset or
                    // negative (no concrete egress, e.g. local delivery)
                    // resolution maps to 0 — the collector's "unknown
                    // interface" sentinel.
                    delta.observed_tos,
                    delta.observed_tcp_flags,
                    u32::try_from(delta.decision.resolution.egress_ifindex).unwrap_or(0),
                    // #4915: the stable session id harvested off the expiring
                    // entry (0 for a synthesized close with no live entry). Rides
                    // the additive [152:160] slot so the SESSION_CLOSE record
                    // carries the same id as this session's SESSION_CREATE.
                    delta.session_id,
                )
            },
        );
    }

    /// #2508: emit an RT_FLOW SESSION_CREATE frame (type 15) for a session
    /// admitted by a policy configured with `then log session-init`. There is
    /// NO flowexport consumer of session opens, so unlike the close frame this
    /// is gated entirely at the producer: the caller invokes it only when
    /// `delta.metadata.log_session_init` is set. The frame rides the same raw
    /// dataplane-event channel and is formatted as RT_FLOW_SESSION_CREATE by
    /// the Go logEvent path. Best-effort (`try_send`).
    /// #2615: `app_id` is the application resolved for the new session's
    /// 5-tuple (caller runs the same `app_catalog.lookup` the close path uses,
    /// mirroring #2520) and `ingress_ifindex` is the admitting binding's
    /// interface index. 0 in either keeps the prior UNKNOWN / N/A rendering.
    pub(crate) fn emit_session_create_rt_flow(
        &self,
        delta: &SessionDelta,
        app_id: u16,
        ingress_ifindex: u32,
    ) {
        if delta.kind != SessionDeltaKind::Open {
            return;
        }
        let nat = &delta.decision.nat;
        // #2512: same per-kind budget path as the close frame (see
        // emit_session_close_rt_flow). SESSION_CREATE is producer-gated by
        // the caller (only emitted for `log session-init` policies), but it
        // still rides the shared dataplane-event channel so it MUST honor the
        // same limiter / budget / counters under
        // DataplaneEventKind::SessionCreate rather than a bare `try_send`.
        let (now_mono_ns, _) = read_mono_and_wall_clocks();
        self.try_emit_dataplane_frame(
            DataplaneEventKind::SessionCreate,
            delta.metadata.ingress_zone,
            now_mono_ns,
            |seq| {
                EventFrame::encode_session_create_rt_flow(
                    seq,
                    delta.key.addr_family,
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.dst_ip,
                    delta.key.src_port,
                    delta.key.dst_port,
                    nat.rewrite_src,
                    nat.rewrite_dst,
                    nat.rewrite_src_port.unwrap_or(0),
                    nat.rewrite_dst_port.unwrap_or(0),
                    delta.metadata.ingress_zone,
                    delta.metadata.egress_zone,
                    // #3056: the admitting policy ID stamped on the session at
                    // install, so the SESSION_CREATE RT_FLOW record names the
                    // policy that admitted the flow instead of policy 0.
                    delta.metadata.policy_id,
                    // #2615: ingress ifindex ([128:132]) + resolved AppID
                    // ([132:134]) so the SESSION_CREATE RT_FLOW record shows
                    // the admitting interface and application instead of
                    // N/A / UNKNOWN.
                    ingress_ifindex,
                    app_id,
                    // #4915: the stable session id assigned at install, carried
                    // in the additive [152:160] slot so this SESSION_CREATE
                    // record shares an id with its eventual SESSION_CLOSE.
                    delta.session_id,
                )
            },
        );
    }
}
