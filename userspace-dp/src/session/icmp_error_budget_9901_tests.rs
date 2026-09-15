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

/// Past the 1024 cap the side table evicts the STALEST (min-TAT) budget —
/// bounded memory, and the evicted key simply starts over.
#[test]
fn side_table_evicts_stalest_at_cap_9901() {
    let mut table = SessionTable::new();
    let t0 = 6_000_000_000u64;
    let mut first = key_v4();
    first.src_port = 1000;
    assert!(table.note_icmp_error_delivered(&first, t0));
    for i in 1..=1024u32 {
        let mut k = key_v4();
        k.src_port = 1000 + i as u16;
        assert!(table.note_icmp_error_delivered(&k, t0 + i as u64));
    }
    assert_eq!(
        table.icmp_error_side_tats.len(),
        1024,
        "the side table never exceeds its cap"
    );
    assert!(
        !table.icmp_error_side_tats.contains_key(&first),
        "the stalest (min-TAT) budget is evicted first"
    );
}
