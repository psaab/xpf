// #10885: closing-entry refresh is gated on close progress and direction.
//
// Before this, EVERY hit on a closing entry reset `last_seen_ns` and reapplied
// the close window (the slow-path `lookup`), the flow-cache keepalive
// (`touch_if_stale`) touched without close-state checks, and the GC companion
// probe (`companion_keeps_alive`) retained closed state without considering
// reset or FIN direction. Repeated matching traffic therefore kept RST/FIN
// state alive indefinitely.

// The gate: an RST-aborted entry never slides; a FIN half-close slides only
// from the non-FINed direction (`!fin_own`); companion retention allows a fresh
// non-FINed half to keep its FINed peer alive, but not vice versa. In-window
// close traffic still forwards — only the timer stops sliding.

// Loaded as a sibling submodule via `#[path]` from session/mod.rs.
//

use super::tests::{install_forward_reverse_pair, key_v4};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST};

/// Distinct close windows so a half-close landing on the wrong one is named by
/// the value (same idiom as the #7342 fixtures).
const CLOSING_SECS: u64 = 7;
const TIME_WAIT_SECS: u64 = 150;

fn configured() -> SessionTimeouts {
    SessionTimeouts::default().with_tcp_session_windows(TcpSessionWindowSecs {
        initial: 45,
        closing: CLOSING_SECS,
        time_wait: TIME_WAIT_SECS,
    })
}

/// A flow first admitted by FIN has one FINed direction, not two: the reverse
/// companion receives the same install flags but must classify that FIN as its
/// peer's. This is necessary for the non-FINed side to keep a half-close alive.
#[test]
fn fresh_fin_install_seeds_the_observed_direction_10885() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_FIN);

    let fwd = table.entry_by_key(&forward).expect("forward seed");
    assert!(fwd.fin_own);
    assert!(!fwd.fin_peer);
    let rev = table.entry_by_key(&reverse).expect("reverse seed");
    assert!(!rev.fin_own, "the companion did not observe a FIN itself");
    assert!(rev.fin_peer, "the companion knows its peer observed a FIN");

    // A packet from the actual non-FINed side still refreshes the seeded
    // half-close rather than being mistaken for a retransmission on both sides.
    let hit_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&reverse, hit_ns, TCP_ACK).is_some());
    assert_eq!(
        table
            .entry_by_key(&reverse)
            .expect("reverse hit")
            .last_seen_ns,
        hit_ns
    );
}

/// Acceptance core: RST-aborted state reaps in ~2-4s even under hits at 1.5s
/// intervals (three orders of magnitude inside the old infinite hold).
///
/// RED pre-fix: each in-window hit re-stamps `last_seen_ns`, so the
/// post-hit assertion fails and neither half ever reaps.
#[test]
fn rst_hits_at_half_window_intervals_do_not_keep_state_alive_10885() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);

    // The RST aborts both halves onto the 2s window, stamped at the RST.
    let rst_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, rst_ns, TCP_RST).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after rst");
        assert!(e.closing && e.reset, "{label}: a rst marks closing+reset");
        assert_eq!(e.last_seen_ns, rst_ns, "{label}: stamped at the rst");
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "{label}: a rst aborts onto the 2s window"
        );
    }

    // In-window traffic still forwards (the fix gates the timer, not the hit)...
    let hit_ns = rst_ns + 1_500_000_000;
    table.last_gc_ns = hit_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(hit_ns);
    assert!(expired.is_empty(), "1.5s into a 2s window nothing reaps");
    assert!(table.lookup(&forward, hit_ns, TCP_ACK).is_some());
    assert!(table.lookup(&reverse, hit_ns, TCP_ACK).is_some());
    // ...but must NOT slide the abort window.
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_eq!(
            table
                .entry_by_key(key)
                .expect("live in-window")
                .last_seen_ns,
            rst_ns,
            "{label}: an in-window hit on a reset entry must not re-stamp last_seen"
        );
    }

    // At rst+3s — inside the ~2-4s acceptance bound — both halves reap despite
    // the continuous traffic above.
    let reap_ns = rst_ns + 3_000_000_000;
    assert!(
        table.lookup(&forward, reap_ns, TCP_ACK).is_none(),
        "traffic past the fixed RST deadline is no longer admitted"
    );
    table.last_gc_ns = reap_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(reap_ns);
    assert_eq!(
        expired.len(),
        2,
        "both reset halves must reap at rst+3s despite hits every 1.5s"
    );
    assert!(table.entry_by_key(&forward).is_none());
    assert!(table.entry_by_key(&reverse).is_none());
}

/// A FIN half-close slides only from the non-FINed direction: the peer may
/// still be sending, while the FINed side is done and its retransmits/ACKs
/// must not extend the window.
///
/// RED pre-fix: the FINed-side hit re-stamps `last_seen_ns`.
#[test]
fn half_close_slides_only_from_the_non_fined_direction_10885() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);

    // Forward FINs: forward is the FINed side, reverse is not.
    let fin_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, fin_ns, TCP_FIN).is_some());
    assert!(
        table.entry_by_key(&forward).expect("fwd").fin_own,
        "precondition: the FINing direction records fin_own"
    );
    assert!(
        !table.entry_by_key(&reverse).expect("rev").fin_own,
        "precondition: the other direction has not FINed"
    );

    // FINed-side traffic still forwards in-window but does not slide...
    let fin_retrans_ns = fin_ns + 500_000_000;
    assert!(table.lookup(&forward, fin_retrans_ns, TCP_FIN).is_some());
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").last_seen_ns,
        fin_ns,
        "a retransmitted FIN from the same direction must not slide"
    );
    let fwd_hit_ns = fin_ns + 1_000_000_000;
    assert!(table.lookup(&forward, fwd_hit_ns, TCP_ACK).is_some());
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").last_seen_ns,
        fin_ns,
        "hits from the FINed direction must not slide the close window"
    );

    // ...while the non-FINed direction keeps sliding (legitimate half-close).
    // This ACK models pre-FIN data reordered behind the close from the peer.
    let rev_hit_ns = fin_ns + 2_000_000_000;
    assert!(table.lookup(&reverse, rev_hit_ns, TCP_ACK).is_some());
    assert_eq!(
        table.entry_by_key(&reverse).expect("rev").last_seen_ns,
        rev_hit_ns,
        "hits from the non-FINed direction must keep sliding the half-close window"
    );
}

/// Once both directions have FINed (TIME_WAIT) neither side slides.
///
/// RED pre-fix: both hits re-stamp.
#[test]
fn time_wait_hits_do_not_slide_either_half_10885() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);

    assert!(
        table
            .lookup(&forward, t0 + 1_000_000_000, TCP_FIN)
            .is_some()
    );
    // The second FIN is close progress: it stamps BOTH halves (matched entry
    // plus the #4109 companion propagation) onto the TIME_WAIT window.
    let fin2_ns = t0 + 2_000_000_000;
    assert!(table.lookup(&reverse, fin2_ns, TCP_FIN).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("entry after second fin");
        assert_eq!(
            e.expires_after_ns,
            TIME_WAIT_SECS * 1_000_000_000,
            "{label}: precondition: both FINed is TIME_WAIT"
        );
        assert_eq!(
            e.last_seen_ns, fin2_ns,
            "{label}: precondition: the completing FIN stamps"
        );
    }

    let hit_ns = t0 + 3_000_000_000;
    assert!(table.lookup(&forward, hit_ns, TCP_ACK).is_some());
    assert!(table.lookup(&reverse, hit_ns, TCP_ACK).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_eq!(
            table
                .entry_by_key(key)
                .expect("live in-window")
                .last_seen_ns,
            fin2_ns,
            "{label}: TIME_WAIT hits must not slide either half"
        );
    }
}

/// Control: reordered pre-FIN data (plain ACKs on an open entry) still
/// refreshes, and close progress (a FIN / the completing second FIN) still
/// stamps. Guards against an over-broad gate that stops all closing refresh.
///
/// GREEN pre- and post-fix by design.
#[test]
fn pre_fin_data_and_close_progress_still_refresh_10885() {
    let forward = key_v4();
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);

    // Open-entry data slides the idle window.
    let data_ns = t0 + 5_000_000_000;
    assert!(table.lookup(&forward, data_ns, TCP_ACK).is_some());
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").last_seen_ns,
        data_ns,
        "pre-FIN data must keep refreshing an open entry"
    );

    // The first FIN is close progress: it stamps and demotes to CLOSING.
    let fin1_ns = t0 + 6_000_000_000;
    assert!(table.lookup(&forward, fin1_ns, TCP_FIN).is_some());
    let e = table.entry_by_key(&forward).expect("fwd after fin");
    assert_eq!(e.last_seen_ns, fin1_ns, "the closing FIN must stamp");
    assert_eq!(
        e.expires_after_ns,
        CLOSING_SECS * 1_000_000_000,
        "one FIN is CLOSING"
    );

    // The completing second FIN is close progress too: it stamps TIME_WAIT.
    let fin2_ns = t0 + 7_000_000_000;
    assert!(table.lookup(&reverse, fin2_ns, TCP_FIN).is_some());
    let e = table.entry_by_key(&reverse).expect("rev after second fin");
    assert_eq!(e.last_seen_ns, fin2_ns, "the completing FIN must stamp");
    assert_eq!(
        e.expires_after_ns,
        TIME_WAIT_SECS * 1_000_000_000,
        "a FIN in both directions is TIME_WAIT"
    );
}

/// The flow-cache keepalive reports a closing entry live (it still serves
/// in-window traffic) but must not re-stamp it — except from the non-FINed
/// direction of a half-close, mirroring the slow path.
///
/// RED pre-fix: the reset and FINed-side touches re-stamp.
#[test]
fn flow_cache_keepalive_respects_close_state_10885() {
    // A reset entry: live, but frozen. The 2s window's staleness threshold is
    // 0.5s, so a touch at +1s is stale-eligible and would re-stamp pre-fix.
    let forward = key_v4();
    let mut table = SessionTable::new();
    let t0 = 10_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);
    let rst_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, rst_ns, TCP_RST).is_some());
    let ka_ns = rst_ns + 1_000_000_000;
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert!(
            table.touch_if_stale(key, ka_ns),
            "{label}: a reset entry inside its window is still live"
        );
        assert_eq!(
            table.entry_by_key(key).expect("live").last_seen_ns,
            rst_ns,
            "{label}: the keepalive must not slide a reset entry"
        );
    }

    // A FIN half-close: the FINed side is frozen, the non-FINed side slides.
    // The default 30s close window's threshold is 7.5s; +8s is stale-eligible.
    let mut table = SessionTable::new();
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);
    let fin_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, fin_ns, TCP_FIN).is_some());
    let ka_ns = fin_ns + 8_000_000_000;
    assert!(table.touch_if_stale(&forward, ka_ns));
    assert_eq!(
        table.entry_by_key(&forward).expect("fwd").last_seen_ns,
        fin_ns,
        "the keepalive must not slide the FINed side of a half-close"
    );
    assert!(table.touch_if_stale(&reverse, ka_ns));
    assert_eq!(
        table.entry_by_key(&reverse).expect("rev").last_seen_ns,
        ka_ns,
        "the keepalive must keep sliding the non-FINed side of a half-close"
    );
}

/// Companion retention follows close direction: a live non-FINed half may
/// keep its FINed peer alive, but traffic on the FINed side cannot keep the
/// non-FINed peer alive. RST has no half-close companion retention.
#[test]
fn companion_retention_respects_close_state_and_direction_10885() {
    let forward = key_v4();
    let t0 = 10_000_000_000u64;

    // Legitimate half-close: traffic from the non-FINed reverse direction
    // slides its own window and keeps the FINed forward half alive.
    let mut table = SessionTable::new();
    table.set_timeouts(configured());
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);
    let fin_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, fin_ns, TCP_FIN).is_some());
    let active_ns = t0 + 10_000_000_000; // FINed half is past its 7s window.
    for hit_ns in [t0 + 4_000_000_000, t0 + 7_000_000_000, active_ns] {
        assert!(
            table.lookup(&reverse, hit_ns, TCP_ACK).is_some(),
            "non-FINed direction stays active throughout the close window"
        );
    }
    table.last_gc_ns = active_ns - SESSION_GC_INTERVAL_NS;
    let _ = table.expire_stale_entries(active_ns);
    assert_eq!(
        table
            .entry_by_key(&forward)
            .expect("retained FINed half")
            .last_seen_ns,
        active_ns,
        "fresh non-FINed companion may keep the FINed half alive"
    );

    // Reverse direction is now quiet. A cache keepalive on the FINed forward
    // side must neither stamp it nor make it a fresh companion for reverse.
    let fin_side_ns = active_ns + 2_000_000_000;
    assert!(table.touch_if_stale(&forward, fin_side_ns));
    assert_eq!(
        table.entry_by_key(&forward).expect("live").last_seen_ns,
        active_ns,
        "a FINed-side keepalive must not re-stamp the retained half"
    );

    // Once the actual non-FINed activity expires, both halves age out despite
    // the FIN-side cache hit; the companion probe cannot make freshness.
    let idle_ns = active_ns + CLOSING_SECS * 1_000_000_000 + SESSION_GC_INTERVAL_NS_FOR_TEST + 1;
    table.last_gc_ns = idle_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(idle_ns);
    assert_eq!(expired.len(), 2, "both quiet half-close entries reap");
    assert!(table.entry_by_key(&forward).is_none());
    assert!(table.entry_by_key(&reverse).is_none());

    // Reset is never extended by companion retention, even if just one half
    // had recent activity at the time of the RST.
    let mut table = SessionTable::new();
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_ACK);
    let rst_ns = t0 + 1_000_000_000;
    assert!(table.lookup(&forward, rst_ns, TCP_RST).is_some());
    let reset_idle_ns = rst_ns + TCP_RST_TIMEOUT_NS + SESSION_GC_INTERVAL_NS_FOR_TEST + 1;
    table.last_gc_ns = reset_idle_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(reset_idle_ns);
    assert_eq!(expired.len(), 2, "reset halves reap on the abort window");
    assert!(table.entry_by_key(&forward).is_none());
    assert!(table.entry_by_key(&reverse).is_none());
}
