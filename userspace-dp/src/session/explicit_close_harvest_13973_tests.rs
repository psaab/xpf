use crate::tcp_flags::TCP_RST;
use super::tests::{decision, key_v4, metadata};
use super::*;

#[test]
// FAIL-ON-REVERT: explicit pressure removal must snapshot the forward-owned
// counters before `remove_entry`; the removed entry's reverse traffic is folded
// into the same counters.
fn pressure_shed_close_harvests_counters_and_timestamps_13973() {
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(2);
    let key = key_v4();
    let reverse = super::tests::install_forward_reverse_pair(&mut table, &key, now, 0x02);
    table.account_packet(&key, 111, 0x10, 0);
    table.account_packet(&reverse, 222, 0x10, 0);

    let (admitted, shed) = table.can_admit_new_syn(1, PROTO_TCP, 0x02);
    assert!(admitted);
    assert_eq!(shed.len(), 2);
    assert!(table.entry_by_key(&key).is_none());
    assert!(table.entry_by_key(&reverse).is_none());

    let close = table
        .drain_deltas(8)
        .into_iter()
        .find(|delta| delta.kind == SessionDeltaKind::Close)
        .expect("pressure-shed close");
    assert_eq!(close.counters.fwd_packets, 1);
    assert_eq!(close.counters.fwd_bytes, 111);
    assert_eq!(close.counters.rev_packets, 1);
    assert_eq!(close.counters.rev_bytes, 222);
    assert_eq!(close.created_ns, now);
    assert_eq!(close.last_seen_ns, now);
}

#[test]
// The lower-level explicit-close path has the same contract as the production
// revalidation and purge callers, which snapshot before deleting the entry.
fn explicit_close_emitter_accepts_removed_entry_snapshot_13973() {
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, 0x02));
    let _ = table.drain_deltas(8);
    table.account_packet(&key, 111, 0, 0);
    table.account_packet(&key, 222, 0, 0);
    assert!(table.lookup(&key, now + 1, TCP_RST).is_some());
    let snapshot = table.close_snapshot_for(&key).expect("live close snapshot");
    let removed = table.remove_entry(&key, RemovalKind::Terminal).expect("removed entry");

    table.emit_close_delta_with_snapshot(
        key,
        removed.decision,
        removed.metadata.clone(),
        removed.origin,
        false,
        removed.session_id,
        snapshot,
    );
    let close = table
        .drain_deltas(8)
        .into_iter()
        .find(|delta| delta.kind == SessionDeltaKind::Close)
        .expect("explicit close");
    assert_eq!(close.counters.fwd_packets, 2);
    assert_eq!(close.counters.fwd_bytes, 333);
    assert_eq!(close.created_ns, now);
    assert_eq!(close.last_seen_ns, now + 1);
    assert_eq!(close.tcp_close_class, TcpCloseClass::Reset.to_wire());
}
