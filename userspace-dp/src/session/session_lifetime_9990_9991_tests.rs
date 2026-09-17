// Fail-on-revert coverage for #9990 and #9991.
use super::*;
use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use crate::tcp_flags::{TCP_ACK, TCP_SYN};

/// #9990: an ownership/delete pre-decision probe must inspect the installed
/// state without completing a TCP handshake or moving its idle clock.
#[test]
fn predecision_probe_preserves_handshake_state_9990() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let install_ns = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, install_ns, TCP_SYN);

    // A real reverse SYN-ACK promotes both halves but leaves the forward half
    // waiting for the completing client segment.
    assert!(table
        .lookup(&reverse, install_ns + 1_000_000, TCP_SYN | TCP_ACK)
        .is_some());
    let before = {
        let entry = table.entry_by_key(&forward).expect("forward session");
        (entry.last_seen_ns, entry.handshake_pending, entry.expires_after_ns)
    };
    assert!(before.1, "premise: SYN-ACK leaves forward handshake pending");
    assert_eq!(before.2, table.timeouts.tcp_opening_ns);

    let (lookup, origin) = table
        .probe_with_origin(&forward)
        .expect("pre-decision probe must find the live session");
    assert!(!origin.is_peer_synced());
    assert_eq!(lookup.decision, decision());
    assert_eq!(lookup.metadata, metadata());

    let after = {
        let entry = table.entry_by_key(&forward).expect("forward session remains");
        (entry.last_seen_ns, entry.handshake_pending, entry.expires_after_ns)
    };
    assert_eq!(after, before, "#9990: probe must not mutate lifetime state");
}

/// #9991: a packet lookup one second beyond the strict idle deadline is a
/// miss, even while the wheel has not yet physically removed the entry.
#[test]
fn lookup_rejects_idle_crossed_session_9991() {
    let mut table = SessionTable::new();
    let mut key = key_v4();
    key.protocol = PROTO_UDP;
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0,
    ));
    let _ = table.drain_deltas(8);
    let timeout_ns = table.entry_by_key(&key).expect("installed session").expires_after_ns;
    let past_deadline = install_ns + timeout_ns + 1_000_000_000;

    // Flow-cache hits call this keepalive without reaching `lookup`; it must
    // obey the same strict deadline rather than resurrecting this entry.
    assert!(!table.touch_if_stale(&key, past_deadline));
    assert!(table.lookup(&key, past_deadline, 0).is_none());
    assert_eq!(
        table.entry_by_key(&key).expect("wheel-lazy entry remains").last_seen_ns,
        install_ns,
        "#9991: an idle-crossed hit must not re-stamp last_seen_ns",
    );
    assert!(
        table.probe_with_origin_at(&key, past_deadline).is_none(),
        "#9990/#9991: quote-style expiry-aware probe must also miss",
    );
    assert_eq!(table.len(), 1, "wheel GC still owns physical removal");
}
