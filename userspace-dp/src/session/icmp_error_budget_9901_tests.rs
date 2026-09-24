// #9901 (F-077): per-session embedded-ICMP-error budget tests (burst 64 /
// rate 64/s in one u64 TAT). Loaded as a sibling submodule via
// `#[path = "icmp_error_budget_9901_tests.rs"]` from session/mod.rs.
// The match-level RED cell (`short_tcp_quote_in_atomic_outer_refused_9901`)
// and the PTB-pair / same-router cells in `tests_embedded_poll_filter.rs`
// pin the end-to-end wiring; these cells pin the budget math, the refill,
// the cross-session independence, and the shared/peer side table.

use super::tests::{decision, key_v4, metadata};
use super::*;
use std::sync::atomic::Ordering as TestOrdering;

fn install(table: &mut SessionTable, key: &SessionKey, now_ns: u64) {
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now_ns,
        PROTO_TCP,
        0x10
    ));
}

fn suppressed_delta(f: impl FnOnce()) -> u64 {
    let before =
        EMBEDDED_ERROR_PER_SESSION_SUPPRESSED_TOTAL.load(TestOrdering::Relaxed);
    f();
    EMBEDDED_ERROR_PER_SESSION_SUPPRESSED_TOTAL.load(TestOrdering::Relaxed) - before
}

/// mtr drives ~30 same-session probes/second; traceroute multi-quoter
/// same-id sessions behave the same. All 30 within one second MUST pass —
/// this is why the budget is 64/64 and NOT a 1s min-interval (which would
/// deliver exactly 1 of the 30).
#[test]
fn mtr_burst_all_delivered_9901() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let t0 = 1_000_000_000u64;
    install(&mut table, &key, t0);
    for i in 0..30u64 {
        assert!(
            table.note_icmp_error_delivered(&key, t0 + i * 1_000_000),
            "mtr probe {i} of 30 within one second must be delivered"
        );
    }
}

/// A forgery flood at a frozen instant is capped at the 64-token burst;
/// the 936 excess are suppressed AND counted. Severing the take (always
/// true) reds both assertions.
#[test]
fn flood_capped_at_burst_and_counted_9901() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let t0 = 2_000_000_000u64;
    install(&mut table, &key, t0);
    let mut delivered = 0u32;
    let suppressed = suppressed_delta(|| {
        for _ in 0..1000 {
            if table.note_icmp_error_delivered(&key, t0) {
                delivered += 1;
            }
        }
    });
    assert_eq!(delivered, 64, "a frozen-instant flood delivers exactly the burst");
    assert_eq!(suppressed, 936, "the excess must be suppressed AND counted");
}

/// The budget refills at 64/s: after draining the burst, one second later
/// a full second's worth (64) is available again.
#[test]
fn budget_refills_over_time_9901() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let t0 = 3_000_000_000u64;
    install(&mut table, &key, t0);
    for _ in 0..64 {
        assert!(table.note_icmp_error_delivered(&key, t0));
    }
    assert!(
        !table.note_icmp_error_delivered(&key, t0),
        "burst exhausted at the frozen instant"
    );
    for i in 0..64 {
        assert!(
            table.note_icmp_error_delivered(&key, t0 + 1_000_000_000),
            "refilled token {i} one second later must be delivered"
        );
    }
    assert!(
        !table.note_icmp_error_delivered(&key, t0 + 1_000_000_000),
        "refill is capped at one second's worth"
    );
}

/// #10667: each policy-refused match gives its pre-policy token back, so a
/// burst of denied errors cannot consume the next permitted error's budget.
/// Exercise both local sessions and shared/peer side-table budgets.
#[test]
fn policy_refused_icmp_burst_does_not_starve_permitted_10667() {
    let key = key_v4();
    let t0 = 3_500_000_000u64;

    for shared in [false, true] {
        let mut table = SessionTable::new();
        if !shared {
            install(&mut table, &key, t0);
        }

        for refused in 0..ICMP_ERROR_BURST {
            assert!(
                table.note_icmp_error_delivered(&key, t0),
                "refused error {refused} must have a token before policy"
            );
            table.refund_icmp_error_not_delivered(&key, t0);
        }

        assert!(
            table.note_icmp_error_delivered(&key, t0),
            "the next policy-permitted error must survive 64 prior refusals (shared={shared})"
        );
        for delivered in 1..ICMP_ERROR_BURST {
            assert!(
                table.note_icmp_error_delivered(&key, t0),
                "permitted error budget token {delivered} must remain available (shared={shared})"
            );
        }
        assert!(
            !table.note_icmp_error_delivered(&key, t0),
            "64 permitted errors exhaust the ordinary burst (shared={shared})"
        );
    }
}

/// Same-router shape: one quoter, MANY sessions — draining session A's
/// budget must not touch session B's. Per-session independence is the
/// whole point; a global error budget would fail this.
#[test]
fn sessions_budgeted_independently_9901() {
    let mut table = SessionTable::new();
    let mut key_b = key_v4();
    key_b.src_port = key_b.src_port.wrapping_add(1);
    let t0 = 4_000_000_000u64;
    install(&mut table, &key_v4(), t0);
    install(&mut table, &key_b, t0);
    for _ in 0..64 {
        assert!(table.note_icmp_error_delivered(&key_v4(), t0));
    }
    assert!(!table.note_icmp_error_delivered(&key_v4(), t0));
    for i in 0..64 {
        assert!(
            table.note_icmp_error_delivered(&key_b, t0),
            "session B token {i} must survive session A's exhaustion"
        );
    }
}

/// A match with NO local entry (shared/peer session) budgets through the
/// bounded side table: same 64-burst behavior, same suppression counting.
#[test]
fn shared_key_budgets_via_side_table_9901() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let t0 = 5_000_000_000u64;
    // NOTE: no install — the key resolves only via the side table.
    let mut delivered = 0u32;
    let suppressed = suppressed_delta(|| {
        for _ in 0..100 {
            if table.note_icmp_error_delivered(&key, t0) {
                delivered += 1;
            }
        }
    });
    assert_eq!(delivered, 64, "side-table budget is the same 64 burst");
    assert_eq!(suppressed, 36, "side-table excess is counted");
    assert_eq!(table.icmp_error_side_tats.len(), 1);
}

/// At the 1024 cap with every resident budget holding live debt, an unknown
/// key is REFUSED (suppressed + counted), never admitted on a fresh budget.
/// Evict-and-admit here would let a 1025-key round-robin exceed 64/s per
/// session indefinitely — each evicted key re-entering with full credit.
#[test]
fn side_table_denies_unknown_keys_at_cap_9901() {
    let mut table = SessionTable::new();
    let t0 = 6_000_000_000u64;
    for i in 0..1024u32 {
        let mut k = key_v4();
        k.src_port = 1000 + i as u16;
        assert!(table.note_icmp_error_delivered(&k, t0));
    }
    assert_eq!(table.icmp_error_side_tats.len(), 1024);
    let mut extra = key_v4();
    extra.src_port = 3000;
    let suppressed = suppressed_delta(|| {
        assert!(
            !table.note_icmp_error_delivered(&extra, t0),
            "an unknown key at a debt-full cap must be refused, not admitted fresh"
        );
    });
    assert_eq!(suppressed, 1, "the cap refusal must be counted");
    assert_eq!(
        table.icmp_error_side_tats.len(),
        1024,
        "the side table never exceeds its cap"
    );
    assert!(
        !table.icmp_error_side_tats.contains_key(&extra),
        "a refused key leaves no budget behind"
    );
}

/// The cap is not a permanent clamp: fully-recovered budgets (TAT at or
/// behind `now`) are pruned on the at-cap insert path, so a new key is
/// admitted once the residents' debt has drained.
#[test]
fn side_table_prunes_recovered_budgets_at_cap_9901() {
    let mut table = SessionTable::new();
    let t0 = 7_000_000_000u64;
    for i in 0..1024u32 {
        let mut k = key_v4();
        k.src_port = 1000 + i as u16;
        assert!(table.note_icmp_error_delivered(&k, t0));
    }
    // One take each: every TAT is t0 + one 64/s interval. Past that instant
    // every budget is fully recovered and prunable.
    let t1 = t0 + 1_000_000_000;
    let mut fresh = key_v4();
    fresh.src_port = 3000;
    assert!(
        table.note_icmp_error_delivered(&fresh, t1),
        "a new key must be admitted once resident budgets have recovered"
    );
    assert!(
        table.icmp_error_side_tats.len() <= 1024,
        "prune-then-insert never exceeds the cap"
    );
}
