//! #13679 (D12-04): a companion that has never been replied to must not keep
//! its paired half alive past that half's own expiry.
//!
//! A bare-SYN install seeds BOTH halves `established=false,
//! handshake_pending=false`. The pre-fix `companion_keeps_alive` consulted
//! only `handshake_pending`, so the still-fresh un-established reverse half
//! rescued the forward half at its (shorter, per-zone #3527) opening deadline
//! and — because the re-stamp copies the companion's `last_seen_ns` and the
//! reverse half ages on the longer window — dragged the pair past the
//! screened zone's syn-flood timeout. A guard on `!companion.established`
//! (with TCP additionally requiring `!companion.handshake_pending`) closes it.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::test_zone_ids::*;
use crate::tcp_flags::{TCP_ACK, TCP_SYN};

const SEC: u64 = 1_000_000_000;

fn pair_with_distinct_opening_windows() -> (SessionTable, SessionKey, SessionKey) {
    // Ingress (forward) zone gets a 5s #3527 syn-flood override; the reverse
    // companion's ingress zone (WAN) keeps the global 20s opening window.
    let mut table = SessionTable::new();
    let mut overrides = FxHashMap::default();
    overrides.insert(TEST_LAN_ZONE_ID, 5 * SEC);
    table.set_opening_overrides(overrides);
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    let fwd = table.entry_by_key(&forward).expect("forward half");
    let rev = table.entry_by_key(&reverse).expect("reverse half");
    assert!(
        !fwd.established && !fwd.handshake_pending,
        "fixture: bare SYN seeds the forward half un-established, not pending"
    );
    assert!(
        !rev.established && !rev.handshake_pending,
        "fixture: bare SYN seeds the reverse half un-established, not pending"
    );
    assert_eq!(fwd.expires_after_ns, 5 * SEC, "fixture: forward on screened 5s window");
    assert_eq!(
        rev.expires_after_ns, table.timeouts.tcp_opening_ns,
        "fixture: reverse on the global opening window"
    );
    (table, forward, reverse)
}

/// The forward half crosses its 5s screened window at 6s while the reverse
/// half is still fresh inside its 20s window. The un-replied companion must
/// not rescue it.
#[test]
fn opening_forward_reaps_despite_fresh_unreplied_reverse_13679() {
    let (mut table, forward, reverse) = pair_with_distinct_opening_windows();
    let now = 1_000_000_000u64 + 6 * SEC;
    table.last_gc_ns = now - 2 * SEC;
    let _ = table.expire_stale_entries(now);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "#13679: an un-established, never-replied reverse companion must not keep \
         the forward half alive past its per-zone syn-flood window"
    );
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        0,
        "#13679: the companion probe must not fire for an un-replied companion"
    );
    assert!(
        table.entry_by_key(&reverse).is_some(),
        "control: the reverse half itself is still inside its own window"
    );
}

/// Symmetric direction: the reverse half crosses its own (global 20s) window
/// while the forward half was refreshed by a bare-SYN retransmit at 15s. The
/// forward half is still un-established, so it must not rescue its companion.
#[test]
fn opening_reverse_reaps_despite_fresh_unreplied_forward_13679() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    // Client retransmits the bare SYN at 15s: forward half re-stamps, still
    // OPENING (no SYN-ACK ever arrives).
    assert!(table.lookup(&forward, now + 15 * SEC, TCP_SYN).is_some());
    assert!(
        !table.entry_by_key(&forward).expect("forward").established,
        "fixture: a SYN retransmit must not establish the forward half"
    );
    // Reverse half is now 21s idle (> 20s opening window); forward is 6s idle.
    let gc_now = now + 21 * SEC;
    table.last_gc_ns = gc_now - 2 * SEC;
    let _ = table.expire_stale_entries(gc_now);
    assert!(
        table.entry_by_key(&reverse).is_none(),
        "#13679: an un-established forward companion refreshed only by SYN \
         retransmits must not keep the reverse half alive forever"
    );
}

/// A completed handshake must retain #4380 single-session semantics: the
/// established reverse half keeps the quiet forward half alive.
#[test]
fn established_companion_still_keeps_quiet_half_alive_13679() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    assert!(
        table.entry_by_key(&reverse).expect("reverse").established,
        "fixture: ACK install establishes both halves"
    );
    table.touch(&reverse, now + 250 * SEC);
    let gc_now = now + 310 * SEC;
    table.last_gc_ns = gc_now - 2 * SEC;
    let expired = table.expire_stale_entries(gc_now);
    assert!(expired.is_empty(), "established flow must not reap its quiet half");
    assert_eq!(table.len(), 2, "both established halves survive");
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        1,
        "the established companion must still retain the quiet half"
    );
}

/// Non-TCP parity: an app-gated UDP pair whose halves start un-established
/// must not retain a half after a synthetic keepalive refresh of its peer.
/// This regression covers eviction only; the test does not exercise UDP reply
/// promotion.
#[test]
fn unreplied_udp_companion_does_not_keep_half_alive_13679() {
    // Forward window: install both halves, give only the forward half a short
    // window by expiring past the UDP timeout while the reverse half is fresh.
    let mut table = SessionTable::new();
    let mut forward = key_v4();
    forward.protocol = PROTO_UDP;
    let now = 1_000_000_000u64;
    // #10889: a custom app timeout gates a non-TCP session until a genuine
    // reply is observed, so both halves start `established=false`. The
    // default-`metadata()` UDP install is established at install, which would
    // not exercise the un-replied shape at all.
    let mut fwd_meta = metadata();
    fwd_meta.inactivity_timeout_ns = Some(30 * SEC);
    let mut rev_meta = fwd_meta.clone();
    rev_meta.is_reverse = true;
    assert!(table.install_with_protocol(forward.clone(), decision(), fwd_meta, now, PROTO_UDP, 0));
    let reverse = reverse_session_key(&forward, NatDecision::default());
    assert!(table.install_with_protocol(reverse.clone(), decision(), rev_meta, now, PROTO_UDP, 0));
    assert!(
        !table.entry_by_key(&forward).expect("forward").established
            && !table.entry_by_key(&reverse).expect("reverse").established,
        "fixture: un-replied UDP pair with an app timeout starts un-established"
    );
    let _ = table.drain_deltas(8);
    let udp_window = table.entry_by_key(&forward).expect("forward").expires_after_ns;
    // Simulate a non-promoting keepalive refresh on the reverse half; the
    // forward half remains frozen and neither half has observed a UDP reply.
    table.touch(&reverse, now + udp_window - SEC);
    let gc_now = now + udp_window + SEC;
    assert!(
        gc_now - (now + udp_window - SEC) < udp_window,
        "fixture: reverse half must still be inside its idle window"
    );
    table.last_gc_ns = gc_now - 2 * SEC;
    let _ = table.expire_stale_entries(gc_now);
    // Pre-fix the un-replied reverse half rescues the forward half; post-fix
    // the forward half may survive ONLY if a genuine reply promoted it — it
    // never saw one, so it must be gone unless touch() itself promoted it.
    // (touch is a bare keepalive, not a lookup, so no promotion occurs.)
    assert!(
        table.entry_by_key(&forward).is_none(),
        "#13679: an un-replied UDP companion must not keep its paired half alive"
    );
}
