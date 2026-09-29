// RT_FLOW SESSION_CREATE/SESSION_CLOSE emit + monotonic->wall-clock
// conversion tests. Split from event_stream/tests.rs (#4664).

use super::*;

#[test]
fn test_emit_session_close_rt_flow_pairs_with_ha_delta() {
    // #2460 no-double-emit contract: a single close emits exactly ONE type-2
    // HA session-sync close delta (push_delta, unchanged) AND exactly ONE
    // type-14 RT_FLOW SESSION_CLOSE frame (emit_session_close_rt_flow). The
    // two are a 1:1 pair — the RT_FLOW frame is additive, it does not
    // duplicate or replace the HA delta.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    // Mirror flush_session_deltas: the HA delta then the RT_FLOW frame.
    handle.push_delta(&delta, &zone_map);
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);

    let frames: Vec<EventFrame> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(
        frames.len(),
        2,
        "expected exactly one HA delta + one RT_FLOW frame"
    );

    let ha = frames
        .iter()
        .filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE)
        .count();
    let rt = frames
        .iter()
        .filter(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .count();
    assert_eq!(ha, 1, "exactly one type-2 HA close delta");
    assert_eq!(rt, 1, "exactly one type-14 RT_FLOW close frame");

    // The RT_FLOW frame carries the SESSION_CLOSE event-type byte and tuple.
    let rt_frame = frames
        .iter()
        .find(|f| f.data[4] == codec::MSG_SESSION_CLOSE_RT_FLOW)
        .unwrap();
    let p = &rt_frame.data[FRAME_HEADER_SIZE..rt_frame.len as usize];
    assert_eq!(p[52], 2, "RT_FLOW event type must be SESSION_CLOSE (2)");
    assert_eq!(&p[8..12], &[10, 0, 1, 102]);
    assert_eq!(&p[24..28], &[172, 16, 80, 200]);
}

#[test]
fn test_monotonic_ns_to_unix_conversions() {
    // #2465: pure-function contract for the monotonic→wall-clock conversion
    // used by emit_session_close_rt_flow. Anchored against a (mono, wall)
    // reference, a creation instant 30s in the monotonic past maps to a
    // wall-clock time 30s before the wall reference.
    let now_mono = 1_000_000_000_000u64; // 1000s monotonic
    let now_unix = 1_700_000_000_000_000_000u64; // 1.7e9 s in ns
    let created_mono = now_mono - 30 * NS_PER_SEC; // 30s ago
    let created_ns_abs = monotonic_ns_to_unix_ns(created_mono, now_mono, now_unix);
    assert_eq!(created_ns_abs, now_unix - 30 * NS_PER_SEC);
    assert_eq!(
        monotonic_ns_to_unix_secs(created_mono, now_mono, now_unix),
        1_700_000_000 - 30
    );

    // 0 / unknown inputs map to 0 (→ the Go-side packet-count fallback).
    assert_eq!(monotonic_ns_to_unix_ns(0, now_mono, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_secs(0, now_mono, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_ns(created_mono, 0, now_unix), 0);
    assert_eq!(monotonic_ns_to_unix_ns(created_mono, now_mono, 0), 0);

    // A monotonic value slightly AHEAD of the reference (cross-CPU read skew)
    // clamps to the present, never the future.
    let ahead = now_mono + 5 * NS_PER_SEC;
    assert_eq!(monotonic_ns_to_unix_ns(ahead, now_mono, now_unix), now_unix);
}

#[test]
fn test_monotonic_ns_to_unix_secs_subnanos() {
    // #2853: the secs+subnanos split must reconstruct the exact wall-clock
    // nanosecond instant, preserving the sub-second remainder the seconds-only
    // helper truncated. A creation instant 30.123456789s before a sub-second
    // wall reference splits into the right second and the right nanos.
    let now_mono = 1_000_000_000_000u64; // 1000s monotonic
    let now_unix = 1_700_000_000_123_456_789u64; // 1.7e9 s + 123456789 ns
    let created_mono = now_mono - 30 * NS_PER_SEC; // 30s ago (whole seconds)
    let (secs, subnanos) = monotonic_ns_to_unix_secs_subnanos(created_mono, now_mono, now_unix);
    assert_eq!(secs, 1_700_000_000 - 30);
    assert_eq!(subnanos, 123_456_789);
    // The seconds-only helper still returns just the truncated second.
    assert_eq!(
        monotonic_ns_to_unix_secs(created_mono, now_mono, now_unix),
        1_700_000_000 - 30
    );
    // Reconstruction is lossless.
    assert_eq!(
        secs as u64 * NS_PER_SEC + subnanos as u64,
        now_unix - 30 * NS_PER_SEC
    );
    // 0 / unknown maps to (0, 0).
    assert_eq!(
        monotonic_ns_to_unix_secs_subnanos(0, now_mono, now_unix),
        (0, 0)
    );
    // subnanos is always a valid sub-second remainder.
    assert!(subnanos < NS_PER_SEC as u32);
}

#[test]
fn test_emit_session_close_rt_flow_carries_real_created_stamp() {
    // #2465 fail-on-revert: a close delta with a real (non-zero) created_ns
    // must produce a non-zero `created` (offset 108) and `timestamp_ns`
    // (offset 0) on the RT_FLOW frame. If the producer drops the created_ns →
    // wire conversion (or the encoder reverts to writing 0), these stay 0 and
    // the flow exporter falls back to the packet-count heuristic StartTime —
    // exactly the #2465 bug. A monotonic created_ns ~60s in the past must land
    // ~60s before the close timestamp on the wire.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    // Anchor the delta's monotonic timestamps to the live CLOCK_MONOTONIC so
    // the conversion against the emit-time reading yields a plausible age.
    let (now_mono, _now_wall) = read_mono_and_wall_clocks();
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    delta.created_ns = now_mono.saturating_sub(60 * NS_PER_SEC);
    delta.last_seen_ns = now_mono;

    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];

    let created_secs = u32::from_le_bytes(p[108..112].try_into().unwrap());
    let ts_ns = u64::from_le_bytes(p[0..8].try_into().unwrap());
    assert!(
        created_secs > 0,
        "created stamp must be populated (not the #2465 zero)"
    );
    assert!(ts_ns > 0, "record timestamp must be populated");
    // created is ~60s before the close timestamp (allow a few seconds of GC /
    // scheduling slack on top of the 60s age).
    let ts_secs = ts_ns / NS_PER_SEC;
    let delta_secs = ts_secs.saturating_sub(created_secs as u64);
    assert!(
        (58..=65).contains(&delta_secs),
        "expected ~60s session age on the wire, got {delta_secs}s (created={created_secs}, close_secs={ts_secs})"
    );
}

#[test]
fn test_emit_session_close_rt_flow_carries_app_id() {
    // #2520 fail-on-revert: the AppID the caller resolves (the same
    // app_catalog.lookup the forwarding hot path runs) must ride the
    // [132:134] wire slot of the SESSION_CLOSE frame so the Go RT_FLOW logger
    // renders application=<name> instead of UNKNOWN. Reverting
    // emit_session_close_rt_flow / encode_session_close_rt_flow to drop the
    // app_id (leaving the slot 0) makes this assertion fail.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    handle.emit_session_close_rt_flow(&delta, 7, 42, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u16::from_le_bytes([p[132], p[133]]),
        7,
        "SESSION_CLOSE RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );
    // #2615 fail-on-revert: the ingress ifindex the caller threads
    // (ident.ifindex) must ride the [128:132] slot so the close record renders
    // packet-incoming-interface=<name> instead of N/A. Reverting the emit /
    // encode path to leave the slot 0 makes this assertion fail.
    assert_eq!(
        u32::from_le_bytes(p[128..132].try_into().unwrap()),
        42,
        "SESSION_CLOSE RT_FLOW must carry the ingress ifindex, not N/A(0)"
    );
}

#[test]
fn test_emit_session_close_rt_flow_carries_admitting_policy_id() {
    // #3056 fail-on-revert: a session admitted by a policy must carry that
    // policy's ID on the SESSION_CLOSE RT_FLOW frame so the
    // RT_FLOW_SESSION_CLOSE syslog record (and the NetFlow/IPFIX close
    // exporters) name the admitting policy instead of policy 0. The admit path
    // stamps SessionMetadata.policy_id, which the Close delta carries;
    // emit_session_close_rt_flow threads it into the trailing [136:140] wire
    // slot — NOT [44:48], which #2853 took for the created-subsec-nanos on a
    // close. The Go decoder reads [136:140] back as PolicyID only on a close.
    // Reverting the stamp (metadata.policy_id) or the encode ([136:140]) back to
    // 0 makes this assertion fail (the record would log policy 0 / the first
    // configured policy).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Close);
    // The session was admitted by policy ID 42.
    delta.metadata.policy_id = 42;
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u32::from_le_bytes(p[136..140].try_into().unwrap()),
        42,
        "SESSION_CLOSE RT_FLOW must carry the admitting policy ID in [136:140], \
         not the policy-0 sentinel"
    );
    // The event type byte must be SESSION_CLOSE (2); the policy ID rides
    // [136:140] precisely because [44:48] is the #2853 created-subsec-nanos here.
    assert_eq!(p[52], 2, "RT_FLOW event type must be SESSION_CLOSE (2)");
}

#[test]
fn test_emit_session_close_rt_flow_zero_created_stays_zero() {
    // #2465: a close delta with an UNKNOWN (0) created_ns must keep the wire
    // created/timestamp fields 0 so the Go exporter falls back to the
    // packet-count estimate (the explicit-delete / HA-purge close paths).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close); // created_ns == 0
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    let frame = rx.try_recv().expect("RT_FLOW close frame");
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(u32::from_le_bytes(p[108..112].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(p[0..8].try_into().unwrap()), 0);
}

#[test]
fn test_emit_session_close_rt_flow_ignores_open_delta() {
    // #2460: the RT_FLOW close emit is gated on Close — calling it for an
    // Open delta is a no-op (guards against a future caller misusing it and
    // injecting a bogus SESSION_CLOSE for an opening session).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    assert!(
        rx.try_recv().is_err(),
        "Open delta must emit no RT_FLOW close frame"
    );
}

#[test]
fn test_emit_session_close_rt_flow_accounts_under_session_close_kind() {
    // #2512 fail-on-revert: a SESSION_CLOSE RT_FLOW frame must travel the same
    // per-kind budget path as deny/screen/filter — NOT a bare unaccounted
    // `try_send`. With an UNLIMITED limiter but a tiny queue capacity, a
    // close burst beyond the per-kind queue budget must increment the
    // SessionClose `dropped`/`queue_full` counters (and the generic
    // frames_dropped), and the accepted prefix must be counted under
    // SessionClose `sent`. If a reviewer reverts the emit path back to
    // `self.try_send(frame)`, no SessionClose counter ever moves and the
    // dropped close is silent — this test fails.
    //
    // capacity 4 → max_total_queued = 4/2 = 2; per-kind budget = ceil(2/5) = 1.
    let (handle, _rx) = test_worker_handle(
        4,
        DataplaneEventRateLimitConfig {
            events_per_second: 0, // unlimited: isolate the queue-budget gate
            burst: 0,
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    // Emit 4 closes; the per-kind budget admits 1, the rest are queue-full.
    // (`_rx` is never drained, so the budget is never released.)
    for _ in 0..4 {
        handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(
        stats.session_close.sent, 1,
        "one close fits the per-kind budget"
    );
    assert_eq!(
        stats.session_close.queue_full, 3,
        "three closes shed by the per-kind queue budget"
    );
    assert_eq!(
        stats.session_close.dropped, 3,
        "queue-full drops roll into the SessionClose dropped total"
    );
    // The bare-try_send revert leaves every other kind at zero AND moves no
    // SessionClose counter; assert the close kind owns the accounting.
    assert_eq!(stats.policy_deny.sent, 0);
    assert_eq!(stats.policy_deny.dropped, 0);
}

#[test]
fn test_emit_session_close_rt_flow_rate_limited_is_counted() {
    // #2512 fail-on-revert: a SESSION_CLOSE burst beyond the per-(kind,zone)
    // rate-limiter token budget must be counted as a SessionClose
    // `rate_limited` drop. Session-table closes can be bursty at GC time;
    // this proves the limiter is actually applied to type-14 (a bare
    // try_send would never rate-limit and this counter would stay 0).
    let (handle, rx) = test_worker_handle(
        64, // large channel/budget so the limiter, not the queue, is the gate
        DataplaneEventRateLimitConfig {
            events_per_second: 1_000,
            burst: 2, // only 2 closes allowed in the instantaneous burst
        },
    );
    let delta = test_close_delta(crate::session::SessionDeltaKind::Close);

    for _ in 0..5 {
        handle.emit_session_close_rt_flow(&delta, 0, 0, delta.metadata.policy_id);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.session_close.sent, 2, "burst of 2 closes admitted");
    assert_eq!(
        stats.session_close.rate_limited, 3,
        "the 3 closes past the burst are rate-limited, not silently sent"
    );
    assert_eq!(stats.session_close.dropped, 3);
    // Exactly the admitted prefix reached the channel.
    let frames: Vec<EventFrame> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(frames.len(), 2);
}

#[test]
fn test_emit_session_create_rt_flow_accounts_under_session_create_kind() {
    // #2512: the SESSION_CREATE (type 15) sibling of the close path also
    // rides the per-kind budget under DataplaneEventKind::SessionCreate.
    let (handle, _rx) = test_worker_handle(
        4, // per-kind budget = 1
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;

    for _ in 0..3 {
        handle.emit_session_create_rt_flow(&delta, 0, 0);
    }

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.session_create.sent, 1);
    assert_eq!(stats.session_create.queue_full, 2);
    assert_eq!(stats.session_create.dropped, 2);
    // Must not steal the close kind's budget/counters.
    assert_eq!(stats.session_close.sent, 0);
    assert_eq!(stats.session_close.dropped, 0);
}

#[test]
fn test_emit_session_create_rt_flow_carries_app_id_and_ifindex() {
    // #2615 fail-on-revert: the SESSION_CREATE emit path must thread the
    // resolved AppID ([132:134]) and the admitting binding's ingress ifindex
    // ([128:132]) into the wire frame, mirroring the #2520 close-side AppID
    // fix. Reverting emit_session_create_rt_flow / encode_session_create_rt_flow
    // to leave either slot 0 makes the create record log application="UNKNOWN"
    // / packet-incoming-interface="N/A" — and these assertions fail.
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;
    handle.emit_session_create_rt_flow(&delta, 9, 77);
    let frame = rx.try_recv().expect("RT_FLOW create frame");
    assert_eq!(frame.data[4], MSG_SESSION_CREATE_RT_FLOW);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u16::from_le_bytes([p[132], p[133]]),
        9,
        "SESSION_CREATE RT_FLOW must carry the resolved AppID, not UNKNOWN(0)"
    );
    assert_eq!(
        u32::from_le_bytes(p[128..132].try_into().unwrap()),
        77,
        "SESSION_CREATE RT_FLOW must carry the ingress ifindex, not N/A(0)"
    );
}

#[test]
fn test_emit_session_create_rt_flow_carries_admitting_policy_id() {
    // #3056 fail-on-revert: a session admitted by a policy must carry that
    // policy's ID on the SESSION_CREATE RT_FLOW frame so the
    // RT_FLOW_SESSION_CREATE syslog record names the admitting policy instead
    // of policy 0. The admit path stamps SessionMetadata.policy_id, which the
    // Open delta carries; emit_session_create_rt_flow threads it into the
    // [44:48] policy_id wire slot — the same slot the Go decoder reads as
    // PolicyID for non-close frames and resolves a policy name from. Reverting
    // the stamp (metadata.policy_id) or the encode ([44:48]) back to 0 makes
    // this assertion fail (the record would log policy 0 / the first configured
    // policy).
    let (handle, rx) = test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut delta = test_close_delta(crate::session::SessionDeltaKind::Open);
    delta.metadata.log_session_init = true;
    // The session was admitted by policy ID 42.
    delta.metadata.policy_id = 42;
    handle.emit_session_create_rt_flow(&delta, 0, 0);
    let frame = rx.try_recv().expect("RT_FLOW create frame");
    assert_eq!(frame.data[4], MSG_SESSION_CREATE_RT_FLOW);
    let p = &frame.data[FRAME_HEADER_SIZE..frame.len as usize];
    assert_eq!(
        u32::from_le_bytes(p[44..48].try_into().unwrap()),
        42,
        "SESSION_CREATE RT_FLOW must carry the admitting policy ID in [44:48], \
         not the policy-0 sentinel"
    );
    // The Go decoder reads [44:48] as PolicyID for non-close frames; the event
    // type byte must therefore be SESSION_CREATE (1), not SESSION_CLOSE (2)
    // (whose [44:48] is repurposed by #2853).
    assert_eq!(p[52], 1, "RT_FLOW event type must be SESSION_CREATE (1)");
}
