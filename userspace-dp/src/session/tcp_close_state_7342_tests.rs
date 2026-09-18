// #7342: the CLOSING vs TIME_WAIT close-state split, and the three
// `security flow tcp-session` windows it lets the operator configure.
//
// Before this, `session_timeout_ns` split a TCP close only into RST and
// not-RST, so `closing-timeout` and `time-wait-timeout` had ONE window between
// them and #6539 could only record that neither was enforced. The discriminator
// is a FIN per DIRECTION: one direction is Junos CLOSING, both is TIME_WAIT.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::tests::{install_forward_reverse_pair, key_v4, tcp_key_v6};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST};

/// Distinct from every default and from each other, so a window that ends up
/// holding the wrong one is named by the value rather than merely unequal.
const INITIAL_SECS: u64 = 45;
const CLOSING_SECS: u64 = 7;
const TIME_WAIT_SECS: u64 = 150;

fn configured() -> SessionTimeouts {
    SessionTimeouts::default().with_tcp_session_windows(TcpSessionWindowSecs {
        initial: INITIAL_SECS,
        closing: CLOSING_SECS,
        time_wait: TIME_WAIT_SECS,
    })
}

/// Each leaf lands in its OWN window and moves no other.
///
/// The three are same-typed and adjacent, so the failure this guards is a
/// transposition — which no compiler catches and which a fixture using one
/// shared value could not see. The three constants above are deliberately
/// different from one another AND from all four defaults.
#[test]
fn each_tcp_session_window_lands_in_its_own_field_7342() {
    let t = configured();
    assert_eq!(t.tcp_opening_ns, INITIAL_SECS * 1_000_000_000);
    assert_eq!(t.tcp_closing_ns, CLOSING_SECS * 1_000_000_000);
    assert_eq!(t.tcp_time_wait_ns, TIME_WAIT_SECS * 1_000_000_000);
    // ...and the windows these three do NOT govern are untouched.
    let base = SessionTimeouts::default();
    assert_eq!(t.tcp_established_ns, base.tcp_established_ns);
    assert_eq!(t.udp_ns, base.udp_ns);
    assert_eq!(t.icmp_ns, base.icmp_ns);
}

/// An UNSET leaf (`0`) leaves its window at the dataplane default, per leaf.
///
/// Driven one leaf at a time: a single all-zero call would also pass against an
/// implementation that ignored the struct entirely, and a single all-set call
/// would not show that `0` is the unset sentinel rather than a literal zero
/// window (which would reap every session instantly).
#[test]
fn an_unset_tcp_session_window_keeps_the_dataplane_default_7342() {
    let base = SessionTimeouts::default();
    type Window = fn(&SessionTimeouts) -> u64;
    for (name, secs, got, want) in [
        (
            "initial",
            TcpSessionWindowSecs {
                closing: CLOSING_SECS,
                time_wait: TIME_WAIT_SECS,
                ..Default::default()
            },
            (|t: &SessionTimeouts| t.tcp_opening_ns) as Window,
            base.tcp_opening_ns,
        ),
        (
            "closing",
            TcpSessionWindowSecs {
                initial: INITIAL_SECS,
                time_wait: TIME_WAIT_SECS,
                ..Default::default()
            },
            (|t: &SessionTimeouts| t.tcp_closing_ns) as Window,
            base.tcp_closing_ns,
        ),
        (
            "time_wait",
            TcpSessionWindowSecs {
                initial: INITIAL_SECS,
                closing: CLOSING_SECS,
                ..Default::default()
            },
            (|t: &SessionTimeouts| t.tcp_time_wait_ns) as Window,
            base.tcp_time_wait_ns,
        ),
    ] {
        let t = SessionTimeouts::default().with_tcp_session_windows(secs);
        assert_eq!(
            got(&t),
            want,
            "an unset {name} window must stay at the dataplane default, not become 0"
        );
    }
}

/// With NEITHER close leaf set, CLOSING and TIME_WAIT are the SAME window — the
/// one every post-FIN close reaped on before the state existed.
///
/// This is the compatibility claim the whole change rests on: splitting a state
/// must not move any session an operator did not ask to move.
#[test]
fn unset_close_windows_are_byte_identical_to_pre_split_7342() {
    let t = SessionTimeouts::default();
    assert_eq!(t.tcp_closing_ns, TCP_CLOSING_TIMEOUT_NS);
    assert_eq!(t.tcp_time_wait_ns, TCP_CLOSING_TIMEOUT_NS);
    assert_eq!(
        tcp_close_window_ns(TcpCloseClass::Closing, &t),
        tcp_close_window_ns(TcpCloseClass::TimeWait, &t),
        "with neither leaf set the two classes must be indistinguishable"
    );
}

/// A FIN in ONE direction is CLOSING; a FIN in BOTH is TIME_WAIT — on both
/// halves of the flow.
///
/// The two-step drive is the point. After the first FIN both halves are already
/// `closing` (#4109 F17 pulls the companion onto the close window), so a fixture
/// that stopped there would show CLOSING and prove nothing about the split: the
/// pre-#7342 code produces exactly that. Only the SECOND FIN, from the other
/// direction, separates the implementations.
fn fin_in_both_directions_reaches_time_wait(forward: SessionKey) {
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);

    // First FIN: forward direction only.
    assert!(table.lookup(&forward, now + 1_000_000, TCP_FIN).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after first fin");
        assert!(e.closing, "{label}: one FIN closes both halves (#4109 F17)");
        assert_eq!(
            e.expires_after_ns,
            CLOSING_SECS * 1_000_000_000,
            "{label}: one FIN is Junos CLOSING, so it reaps on closing-timeout"
        );
    }

    // Second FIN: the other direction. The close handshake is complete.
    assert!(table.lookup(&reverse, now + 2_000_000, TCP_FIN).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after second fin");
        assert_eq!(
            e.expires_after_ns,
            TIME_WAIT_SECS * 1_000_000_000,
            "{label}: a FIN in BOTH directions is Junos TIME_WAIT, so it reaps on \
             time-wait-timeout — this is the assertion the pre-#7342 single \
             post-FIN window cannot satisfy"
        );
    }
}

#[test]
fn fin_in_both_directions_reaches_time_wait_v4() {
    fin_in_both_directions_reaches_time_wait(key_v4());
}

#[test]
fn fin_in_both_directions_reaches_time_wait_v6() {
    fin_in_both_directions_reaches_time_wait(tcp_key_v6());
}

/// The SAME direction FINning twice — a retransmitted FIN — is still CLOSING.
///
/// Without this, an implementation that counted FINs rather than tracking their
/// DIRECTION would pass the cell above: two FINs, TIME_WAIT. TCP retransmits
/// FINs routinely, so that implementation would put half-closed flows on the
/// TIME_WAIT window whenever a FIN-ACK was lost.
#[test]
fn a_retransmitted_fin_from_one_direction_stays_closing_7342() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);

    assert!(table.lookup(&forward, now + 1_000_000, TCP_FIN).is_some());
    assert!(table.lookup(&forward, now + 2_000_000, TCP_FIN).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after retransmitted fin");
        assert_eq!(
            e.expires_after_ns,
            CLOSING_SECS * 1_000_000_000,
            "{label}: two FINs from ONE direction is still a half-close"
        );
    }
}

/// A RST takes the abort window whatever the FIN history is, and stays there.
///
/// `reset` short-circuits the class, and it is sticky (#3046): a graceful FIN
/// arriving after a RST must not promote the entry onto a longer window. The
/// FIN-in-both-directions path is the new way that could have happened.
#[test]
fn a_reset_beats_time_wait_and_stays_beaten_7342() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);

    // A full FIN close first, so both directions have FINed...
    assert!(table.lookup(&forward, now + 1_000_000, TCP_FIN).is_some());
    assert!(table.lookup(&reverse, now + 2_000_000, TCP_FIN).is_some());
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").expires_after_ns,
        TIME_WAIT_SECS * 1_000_000_000,
        "precondition: the flow really is in TIME_WAIT before the RST"
    );

    // ...then a RST. It must win, on both halves.
    assert!(table.lookup(&forward, now + 3_000_000, TCP_RST).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after rst");
        assert!(e.reset, "{label}: the reset flag is set");
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "{label}: a RST aborts onto the short window even from TIME_WAIT"
        );
    }

    // And a later FIN cannot promote it back (#3046 stickiness, via the new
    // class rather than around it).
    assert!(table.lookup(&forward, now + 4_000_000, TCP_FIN).is_some());
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").expires_after_ns,
        TCP_RST_TIMEOUT_NS,
        "a FIN after a RST must not lengthen the window"
    );
}

/// `initial-timeout` governs the half-open window, and the per-zone #3527
/// `syn-flood timeout` override still beats it.
///
/// The precedence is the load-bearing half: a per-zone override that a global
/// leaf could silently outrank would make the screen control unreliable exactly
/// where it matters. Both values are asserted, so a change that dropped either
/// input is named.
#[test]
fn initial_timeout_governs_the_half_open_window_and_yields_to_the_zone_7342() {
    let forward = key_v4();
    let zone_override_secs = 3u64;

    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let now = 1_000_000_000u64;
    // A bare SYN installs a half-open (OPENING) session.
    assert!(table.install_with_protocol(
        forward.clone(),
        super::tests::decision(),
        super::tests::metadata(),
        now,
        PROTO_TCP,
        crate::tcp_flags::TCP_SYN,
    ));
    assert_eq!(
        table.entry_by_key(&forward).expect("syn").expires_after_ns,
        INITIAL_SECS * 1_000_000_000,
        "a half-open session reaps on initial-timeout, not the established window"
    );

    // With the ingress zone carrying a syn-flood timeout, that wins.
    let mut zoned = SessionTable::new();
    zoned.set_timeouts(configured());
    let mut overrides = FxHashMap::default();
    overrides.insert(super::tests::metadata().ingress_zone, zone_override_secs * 1_000_000_000);
    zoned.set_opening_overrides(overrides);
    assert!(zoned.install_with_protocol(
        forward.clone(),
        super::tests::decision(),
        super::tests::metadata(),
        now,
        PROTO_TCP,
        crate::tcp_flags::TCP_SYN,
    ));
    assert_eq!(
        zoned.entry_by_key(&forward).expect("syn").expires_after_ns,
        zone_override_secs * 1_000_000_000,
        "#3527: a per-zone syn-flood timeout still overrides the global \
         initial-timeout for that zone's half-opens"
    );
}

/// A session INSTALLED by a closing packet is CLOSING, never TIME_WAIT.
///
/// One packet carries one direction's FIN, so TIME_WAIT — a statement about
/// both — is not something an install can reach. It is also what such a session
/// reaped on before the split.
#[test]
fn a_session_installed_by_a_fin_is_closing_not_time_wait_7342() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    assert!(table.install_with_protocol(
        forward.clone(),
        super::tests::decision(),
        super::tests::metadata(),
        1_000_000_000,
        PROTO_TCP,
        TCP_FIN,
    ));
    assert_eq!(
        table.entry_by_key(&forward).expect("fin install").expires_after_ns,
        CLOSING_SECS * 1_000_000_000,
    );
}

/// #10287: exercise the full reuse transition, not just the eviction gate.
///
/// The old incarnation closes, a bare SYN reuses the tuple immediately, and
/// the new pair completes a real three-way handshake. The new pair must start
/// on OPENING (20 s), promote to ESTABLISHED (300 s), survive an opening-window
/// idle gap, and accept a server-first packet after that gap.
fn reused_tuple_completes_handshake_after_close(close_flags: u8) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let old_reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    let old_session_id = table.session_id_for(&forward);
    assert!(table.lookup(&forward, now + 1_000_000, close_flags).is_some());
    let _ = table.drain_deltas(8);

    let reuse = now + 10_000_000;
    let (evicted_forward, evicted_reverse) = table
        .evict_closing_tcp_pair_for_syn(&forward, crate::tcp_flags::TCP_SYN)
        .expect("a bare SYN inside the close window must evict the old pair");
    assert_eq!(evicted_forward, forward);
    assert_eq!(evicted_reverse, old_reverse);
    assert!(table.entry_by_key(&forward).is_none());
    assert!(table.entry_by_key(&old_reverse).is_none());

    let reverse = install_forward_reverse_pair(
        &mut table,
        &forward,
        reuse,
        crate::tcp_flags::TCP_SYN,
    );
    let new_session_id = table.session_id_for(&forward);
    assert_ne!(
        new_session_id, old_session_id,
        "tuple reuse must allocate a fresh session incarnation id"
    );
    assert_eq!(
        table.entry_by_key(&forward).expect("new opening forward").expires_after_ns,
        DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "tuple reuse must arm the fresh 20 s OPENING window"
    );
    assert_eq!(
        table.entry_by_key(&reverse).expect("new opening reverse").expires_after_ns,
        DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "the fresh companion must also start on OPENING"
    );

    assert!(table
        .lookup(&reverse, reuse + 1_000_000, crate::tcp_flags::TCP_SYN | TCP_ACK)
        .is_some());
    assert!(table
        .lookup(&forward, reuse + 2_000_000, TCP_ACK)
        .is_some());
    // Refresh the responder half once after handshake completion so BOTH
    // halves visibly carry the 300 s established window before the idle-gap
    // / server-first assertion.
    assert!(table
        .lookup(&reverse, reuse + 3_000_000, TCP_ACK)
        .is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("established reused entry");
        assert!(
            entry.established,
            "{label}: a completed handshake must promote the new incarnation"
        );
        assert_eq!(
            entry.expires_after_ns,
            DEFAULT_TCP_SESSION_TIMEOUT_NS,
            "{label}: the new incarnation must use the full 300 s idle window"
        );
    }

    let idle = reuse + TCP_CLOSING_TIMEOUT_NS + 5_000_000_000;
    table.last_gc_ns = idle - 2_000_000_000;
    let _ = table.expire_stale_entries(idle);
    assert!(
        table.lookup(&reverse, idle + 1_000_000, TCP_ACK).is_some(),
        "server-first traffic after an opening-window idle gap must hit the \
         newly established tuple, not a reaped close-window entry"
    );
}

#[test]
fn fin_tuple_reuse_gets_fresh_opening_and_established_windows_10287() {
    reused_tuple_completes_handshake_after_close(TCP_FIN);
}

#[test]
fn rst_tuple_reuse_gets_fresh_opening_and_established_windows_10287() {
    reused_tuple_completes_handshake_after_close(TCP_RST);
}
