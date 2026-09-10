//! #9412 ACCEPTANCE: install a session OPEN, close it on the primary, fail over
//! with no traffic, and the standby's copy must reap on the CLOSE window.
//!
//! Written BEFORE the fix, and shaped to COMPILE at base, so "red at base" is a
//! behavioural failure, not a missing symbol. The standby record carries
//! `tcp_close_class` through JSON, and serde ignores a key the struct lacks.
//!
//! The chain has two Rust ends and a Go middle. These cells are the two ends:
//!   * PRIMARY: a session this node owns closes, so a sync delta must be
//!     produced. At base `lookup` sets `closing` and pushes nothing, so the
//!     peer's copy stays frozen at its install-time state (the issue's
//!     Correction 1: the sweep re-sends only sessions CREATED since its last
//!     tick).
//!   * STANDBY: handed a record that says the session is closing, and now
//!     forwarding that session's RG with no traffic, the node must reap the copy
//!     on the close window. At base the class has nowhere to land, so the copy
//!     ages on the ESTABLISHED window.
//! The Go hops between the ends, and a golden frame shared by both languages,
//! are separate cells.
//!
//! The windows are deliberately distinct (CLOSING 7s, TIME_WAIT 150s, RST 2s,
//! established at the default). A copy that lands in the wrong window is then
//! named by WHEN it reaps, not merely by reaping.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::server::helpers::build_synced_session_entry;
use crate::tcp_flags::{TCP_ACK, TCP_FIN};
use crate::test_zone_ids::*;
use crate::SessionSyncRequest;

const SEC: u64 = 1_000_000_000;
const CLOSING_SECS: u64 = 7;
const TIME_WAIT_SECS: u64 = 150;
const OWNER_RG: i32 = 1;

fn windows() -> SessionTimeouts {
    SessionTimeouts::default().with_tcp_session_windows(TcpSessionWindowSecs {
        initial: 45,
        closing: CLOSING_SECS,
        time_wait: TIME_WAIT_SECS,
    })
}

// ---------------------------------------------------------------- primary end

#[test]
fn a_close_on_the_primary_produces_a_sync_delta_9412() {
    let mut table = SessionTable::new();
    table.set_timeouts(windows());
    let forward = key_v4();
    let now = SEC;
    let _reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);

    // POSITIVE CONTROL for the drain. The fixture drained its own installs, so an
    // ACK refresh must produce nothing. Otherwise "a delta appeared" below could
    // be a late install Open rather than anything the close caused.
    assert!(table.lookup(&forward, now + 1_000, TCP_ACK).is_some());
    let refresh = table.drain_deltas(64);
    assert!(refresh.is_empty(), "FIXTURE: an ACK refresh emitted {} delta(s)", refresh.len());

    assert!(table.lookup(&forward, now + 2_000, TCP_FIN).is_some());
    let deltas = table.drain_deltas(64);
    assert!(
        deltas.iter().any(|d| d.key == forward),
        "#9412 ACCEPTANCE: the primary saw this session CLOSE (FIN) and produced no \
         sync delta for it (got {:?}). The standby's copy stays frozen at its \
         install-time state, so after a failover with no traffic it reaps on the \
         ESTABLISHED window instead of the close window.",
        deltas.iter().map(|d| (d.kind, d.key.clone())).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------- standby end

/// A TCP peer-sync record whose sender says the session is in close `class`
/// (0 = not carried, 1 = CLOSING, 2 = TIME_WAIT, 3 = RST). The key is injected
/// through JSON, the form the Go sender writes.
fn record(class: u8) -> SessionSyncRequest {
    let base = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 54321,
        dst_port: 5201,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: OWNER_RG,
        ..SessionSyncRequest::default()
    };
    let mut v = serde_json::to_value(&base).expect("FIXTURE: serialize");
    v["tcp_close_class"] = serde_json::json!(class);
    serde_json::from_value(v).expect("FIXTURE: deserialize")
}

fn import(table: &mut SessionTable, req: &SessionSyncRequest, now: u64) -> SessionKey {
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(req, &zones, 0).expect("FIXTURE: record must import");
    let key = entry.key.clone();
    // The PRODUCTION mapping, not a literal of this test's own, so a close class
    // dropped between the synced entry and the install reds these cells.
    assert!(
        table.upsert_synced_with_origin(entry.into_session_install(now), false),
        "FIXTURE: upsert must install"
    );
    key
}

/// One GC pass as a node that FORWARDS every RG, which is this node after the
/// failover. The interval gate is reset so each call is a real pass.
fn gc_as_forwarder(table: &mut SessionTable, now: u64) -> Vec<ExpiredSession> {
    let fwd = |_rg: i32| true;
    let epoch = |_rg: i32| 0u32;
    let ctx = ExpireHaContext {
        node_active: true,
        forwards_rg: &fwd,
        epoch_of: &epoch,
        ceiling_mult: 4,
        ceiling_abs_ns: u64::MAX,
    };
    table.last_gc_ns = 0;
    table.expire_stale_entries_ha(now, Some(&ctx))
}

fn reaped(expired: &[ExpiredSession], key: &SessionKey) -> bool {
    expired.iter().any(|e| &e.key == key)
}

/// Imports `class`, fails over, and returns (table, key, failover instant).
/// Timings are measured from the failover instant rather than the import, so a
/// #2120 self-heal refresh at promotion cannot shift the edges.
fn imported_and_failed_over(class: u8) -> (SessionTable, SessionKey, u64) {
    let mut table = SessionTable::new();
    table.set_timeouts(windows());
    let now = 10 * SEC;
    let key = import(&mut table, &record(class), now);
    let failover = now + SEC / 10;
    assert!(
        !reaped(&gc_as_forwarder(&mut table, failover), &key),
        "FIXTURE: class {class} reaped at the failover instant itself"
    );
    (table, key, failover)
}

#[test]
fn the_fixture_windows_are_distinct_9412() {
    let t = windows();
    assert_eq!(t.tcp_closing_ns, CLOSING_SECS * SEC);
    assert_eq!(t.tcp_time_wait_ns, TIME_WAIT_SECS * SEC);
    assert!(TCP_RST_TIMEOUT_NS < CLOSING_SECS * SEC);
    assert!(
        t.tcp_established_ns > (TIME_WAIT_SECS + 1) * SEC,
        "FIXTURE: the established window must outlast every close window, or the \
         control cell below cannot tell them apart"
    );
}

#[test]
fn an_imported_closing_session_reaps_on_the_closing_window_9412() {
    let (mut table, key, failover) = imported_and_failed_over(1);
    assert!(
        !reaped(&gc_as_forwarder(&mut table, failover + (CLOSING_SECS - 1) * SEC), &key),
        "reaped BEFORE the {CLOSING_SECS}s closing window elapsed"
    );
    assert!(
        reaped(&gc_as_forwarder(&mut table, failover + (CLOSING_SECS + 1) * SEC), &key),
        "#9412 ACCEPTANCE: the primary said this session was CLOSING, this node now \
         forwards its RG, no traffic arrived, and the copy was NOT reaped on the \
         {CLOSING_SECS}s closing window. It is ageing on the established window."
    );
}

#[test]
fn an_imported_time_wait_session_reaps_on_the_time_wait_window_9412() {
    let (mut table, key, failover) = imported_and_failed_over(2);
    assert!(
        !reaped(&gc_as_forwarder(&mut table, failover + (CLOSING_SECS + 1) * SEC), &key),
        "a TIME_WAIT copy reaped on the CLOSING window: the class was collapsed"
    );
    assert!(
        reaped(&gc_as_forwarder(&mut table, failover + (TIME_WAIT_SECS + 1) * SEC), &key),
        "#9412 ACCEPTANCE: a TIME_WAIT copy was NOT reaped on the {TIME_WAIT_SECS}s \
         time-wait window after failover with no traffic"
    );
}

/// #9412: an import must READ BACK as the class the peer stated, not only reap on its
/// window.
///
/// The install derives the reap window from the wire class. But the class a later
/// resync re-export or promote republish announces is re-derived from the entry's
/// close bits, through `close_class_wire_for`. That function's own consumers are
/// bound by the re-export and promote cells.
///
/// A TIME_WAIT imported with CLOSING bits would still reap on the 150 s window here.
/// Once this node owns the session, though, it would re-announce CLOSING, and a
/// returning peer would import that on the 7 s window. The mutation matrix found this
/// gap: `fin_peer: false` survived every reap cell. Class 0 is the control.
#[test]
fn an_import_reads_back_as_the_peer_stated_class_9412() {
    for class in [0u8, 1, 2, 3] {
        let mut table = SessionTable::new();
        table.set_timeouts(windows());
        let key = import(&mut table, &record(class), 10 * SEC);
        let read_back = table.close_class_wire_for(&key);
        assert_eq!(
            read_back, class,
            "#9412: an import stating close class {class} reads back as {read_back}, so a \
             re-export or promote of it would announce the wrong class"
        );
    }
}

#[test]
fn an_imported_reset_session_reaps_on_the_rst_window_9412() {
    let (mut table, key, failover) = imported_and_failed_over(3);
    assert!(
        reaped(&gc_as_forwarder(&mut table, failover + TCP_RST_TIMEOUT_NS + SEC), &key),
        "#9412 ACCEPTANCE: a RST copy was NOT reaped on the RST window after failover \
         with no traffic"
    );
}

/// CONTROL: a record without close state (an older peer, or a session that is
/// not closing) must keep today's behaviour exactly, the established window.
/// It passes at base and must keep passing. A fix that closed every imported
/// session would pass the three cells above and fail this one.
#[test]
fn a_record_without_close_state_still_ages_on_the_established_window_9412() {
    let (mut table, key, failover) = imported_and_failed_over(0);
    assert!(
        !reaped(&gc_as_forwarder(&mut table, failover + (TIME_WAIT_SECS + 1) * SEC), &key),
        "a record carrying NO close state was reaped on a close window"
    );
}

// ------------------------------------------------------------------ volume

/// Volume, argued against #8593 and pinned here: one Update per class
/// TRANSITION, always keyed on the forward entry, and nothing for a repeated
/// packet in the same class. A full close therefore costs at most three extra
/// deltas. The peer-synced side emitting nothing is pinned by the existing
/// synced-FIN cell in `tests.rs`.
#[test]
fn a_close_emits_one_update_per_class_transition_9412() {
    use crate::tcp_flags::TCP_RST;
    let mut table = SessionTable::new();
    table.set_timeouts(windows());
    let forward = key_v4();
    let now = SEC;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    let mut step = |t: &mut SessionTable, key: &SessionKey, at: u64, flags: u8| {
        assert!(t.lookup(key, at, flags).is_some());
        t.drain_deltas(64)
            .into_iter()
            .map(|d| (d.kind, d.tcp_close_class, d.key == forward))
            .collect::<Vec<_>>()
    };
    let upd = SessionDeltaKind::Update;
    assert_eq!(step(&mut table, &forward, now + 1_000, TCP_FIN), vec![(upd, 1, true)], "first FIN: CLOSING");
    assert_eq!(step(&mut table, &forward, now + 2_000, TCP_FIN), vec![], "a retransmitted FIN in the same class");
    assert_eq!(
        step(&mut table, &reverse, now + 3_000, TCP_FIN | TCP_ACK),
        vec![(upd, 2, true)],
        "the other direction's FIN: TIME_WAIT, keyed on the FORWARD entry"
    );
    assert_eq!(step(&mut table, &forward, now + 4_000, TCP_RST), vec![(upd, 3, true)], "a RST: RESET");
    assert_eq!(step(&mut table, &forward, now + 5_000, TCP_RST), vec![], "a second RST");
}

// ------------------------------------------------------------ resync re-export

/// #9412: the bulk re-export must stamp the LIVE entry's close class. That
/// re-export is the #2442 loss-of-sync resync, which re-announces every session
/// as an Open.
///
/// This is the only recovery for a close-state Update that the bounded delta
/// ring dropped. A re-export that stated `0` would re-announce a closing
/// session as open, and the peer would keep the defect even after a resync.
#[test]
fn a_resync_reexport_carries_the_live_close_class_9412() {
    let mut table = SessionTable::new();
    table.set_timeouts(windows());
    let forward = key_v4();
    let now = SEC;
    let _reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    assert!(table.lookup(&forward, now + 1_000, TCP_FIN).is_some());
    // Discard the Update itself: this cell presumes the incremental stream lost it.
    let _ = table.drain_deltas(64);
    table.emit_open_delta_with_origin(forward.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, false);
    let reexport: Vec<_> = table.drain_deltas(64).into_iter().map(|d| (d.kind, d.tcp_close_class)).collect();
    assert_eq!(
        reexport,
        vec![(SessionDeltaKind::Open, 1)],
        "#9412: a resync re-export of a CLOSING session must carry close class 1, or a \
         dropped close-state Update is never restored"
    );
}
