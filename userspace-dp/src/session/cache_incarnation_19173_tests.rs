//! #19173: the fused cache-hit probe binds a hit to ONE incarnation of the
//! backing record.
//!
//! The flow-cache seed stamps `install_epoch` of the record the probe will
//! resolve (`backing_install_epoch_for_cache_hit`); the probe refuses any
//! other incarnation (`ProbeHitVerdict::Replaced`) before it writes
//! anything. These cells pin the token's two obligations at table level:
//! every same-key replacement moves it, and nothing a hit or an ordinary
//! slow-path packet does to the row in place moves it.
use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH};
use std::net::{IpAddr, Ipv4Addr};

const SEC: u64 = 1_000_000_000;

fn epoch(table: &SessionTable, key: &SessionKey) -> u64 {
    table
        .entry_by_key_quiet(key)
        .expect("row present")
        .install_epoch
}

fn probe(table: &mut SessionTable, key: &SessionKey, expected: u64, now: u64) -> ProbeHitVerdict {
    let mut wire_canonical = None;
    table.probe_hit_deferring_state_update_with_ack_rollback_verdict_lazy(
        key,
        expected,
        now,
        1514,
        TCP_ACK | TCP_PSH,
        1448,
        0,
        || None,
        true,
        &mut wire_canonical,
    )
}

fn import(table: &mut SessionTable, key: &SessionKey, now: u64) {
    assert!(table.upsert_synced(key.clone(), decision(), metadata(), now, PROTO_TCP, TCP_ACK, false));
}

/// A re-import of `key` that changes a forwarding input (the egress), so it
/// is a new incarnation (the #19173 fold keeps the epoch only for an
/// identical one, `reimport_carry_19173_tests.rs`).
fn import_changed(table: &mut SessionTable, key: &SessionKey, now: u64) {
    let mut d = decision();
    d.resolution.egress_ifindex += 1;
    d.resolution.tx_ifindex += 1;
    assert!(table.upsert_synced(key.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
}

/// A replaced record is refused before ANY write: no accounting, no
/// keepalive, no packet stamp, no served-here bit, no rollback undo. The
/// replacing incarnation is served; `PROBE_ANY_INCARNATION` skips the check.
#[test]
fn replaced_record_is_refused_before_any_write_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 10 * SEC;
    import(&mut table, &key, now);
    let seeded = epoch(&table, &key);
    import_changed(&mut table, &key, now + SEC);
    let live = epoch(&table, &key);
    assert_ne!(live, seeded, "premise: a changed re-import is a new incarnation");
    let before = table.entry_by_key_quiet(&key).expect("row").clone();
    let t = now + 600 * SEC;
    assert_eq!(probe(&mut table, &key, seeded, t), ProbeHitVerdict::Replaced);
    let after = table.entry_by_key_quiet(&key).expect("row");
    assert_eq!(after.counters.fwd_packets, before.counters.fwd_packets, "not accounted");
    assert_eq!(after.last_seen_ns, before.last_seen_ns, "no keepalive");
    assert_eq!(after.last_packet_seen_ns, before.last_packet_seen_ns, "no packet stamp");
    assert_eq!(after.served_here, before.served_here, "not marked served");
    assert_eq!(table.pending_probe_undo_len_for_test(), 0, "no rollback undo recorded");
    assert_eq!(probe(&mut table, &key, live, t), ProbeHitVerdict::Live);
    assert_eq!(probe(&mut table, &key, PROBE_ANY_INCARNATION, t + SEC), ProbeHitVerdict::Live);
}

/// The token moves on every same-key replacement that is a NEW incarnation:
/// a same-id re-import that changes a forwarding input, a new-id re-import,
/// a local re-install over a synced row, and a delete followed by a
/// re-install. (A same-id IDENTICAL re-import keeps it since the #19173
/// fold: `reimport_carry_19173_tests.rs`.) Epoch 0
/// (`PROBE_ANY_INCARNATION`) is never minted.
#[test]
fn every_new_incarnation_moves_the_install_epoch_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 10 * SEC;
    import(&mut table, &key, now);
    let mut seen = vec![epoch(&table, &key)];
    assert_ne!(seen[0], PROBE_ANY_INCARNATION);
    // Same wire id, a changed forwarding input.
    let mut req = table.synced_entry_for(&key).expect("row").into_session_install(now + SEC);
    req.session_id = table.session_id_for(&key);
    req.decision.resolution.egress_ifindex += 1;
    assert!(table.upsert_synced_with_origin(req, false));
    seen.push(epoch(&table, &key));
    // A different wire id.
    let mut req = table.synced_entry_for(&key).expect("row").into_session_install(now + 2 * SEC);
    req.session_id = table.session_id_for(&key) + 1;
    assert!(table.upsert_synced_with_origin(req, false));
    seen.push(epoch(&table, &key));
    // A local install over the synced row.
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now + 3 * SEC, PROTO_TCP, TCP_ACK));
    seen.push(epoch(&table, &key));
    // Delete, then re-install.
    table.delete(&key);
    assert!(table.entry_by_key_quiet(&key).is_none());
    import(&mut table, &key, now + 4 * SEC);
    seen.push(epoch(&table, &key));
    for pair in seen.windows(2) {
        assert!(pair[1] > pair[0], "every replacement mints a new, larger epoch: {seen:?}");
    }
}

/// The token does NOT move on in-place updates a steady flow makes: cache
/// hits (accounting, keepalive refresh, served-here) and slow-path session
/// hits. Otherwise every hit would re-seed (the MY3 shape).
#[test]
fn in_place_updates_keep_the_install_epoch_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 10 * SEC;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, TCP_ACK));
    let seeded = epoch(&table, &key);
    for n in 1..=5u64 {
        // 600 s apart: past the keepalive throttle, so the refresh arm runs.
        let t = now + n * 600 * SEC;
        assert_eq!(probe(&mut table, &key, seeded, t), ProbeHitVerdict::Live, "hit {n}");
        table.rollback_dropped_probe_hit(&key, 1514, TCP_ACK | TCP_PSH);
        assert_eq!(probe(&mut table, &key, seeded, t + 1), ProbeHitVerdict::Live, "hit {n}b");
        table.emit_probe_hit_state_update(&key);
        assert!(table.lookup_with_origin(&key, t + 2, TCP_ACK).is_some(), "slow-path hit {n}");
        assert_eq!(epoch(&table, &key), seeded, "in-place update {n} moved the epoch");
    }
}

/// The seed-time accessor resolves exactly what the probe resolves: the
/// direct row, the reverse row, the forward-wire tuple's canonical row
/// (#18656), and nothing for an unknown tuple. The probe then accepts each
/// returned epoch and refuses it once the canonical row is replaced.
#[test]
fn seed_accessor_resolves_like_the_probe_19173() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(40000),
        ..crate::nat::NatDecision::default()
    };
    let mut d = decision();
    d.nat = nat;
    let now = 10 * SEC;
    assert!(table.upsert_synced(forward.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    let reverse = reverse_session_key(&forward, nat);
    let mut rmeta = metadata();
    rmeta.is_reverse = true;
    assert!(table.upsert_synced(reverse.clone(), d, rmeta, now, PROTO_TCP, TCP_ACK, false));
    let wire = forward_wire_key(&forward, nat);
    assert!(table.entry_by_key_quiet(&wire).is_none(), "premise: wire is only an index");
    let t = now + SEC;
    for (name, key, owner) in [("forward", &forward, &forward), ("reverse", &reverse, &reverse), ("wire", &wire, &forward)] {
        let bound = table
            .backing_install_epoch_for_cache_hit(key, t)
            .unwrap_or_else(|| panic!("{name}: resolves a row"));
        assert_eq!(bound, epoch(&table, owner), "{name}: the probe's row");
        assert_eq!(probe(&mut table, key, bound, t), ProbeHitVerdict::Live, "{name}");
    }
    let mut unknown = forward.clone();
    unknown.src_port ^= 1;
    assert_eq!(table.backing_install_epoch_for_cache_hit(&unknown, t), None);
    // An identical re-import of the canonical forward row keeps its
    // incarnation (#19173 fold), so the wire tuple's hit is still served.
    let wire_bound = table.backing_install_epoch_for_cache_hit(&wire, t).expect("wire");
    assert!(table.upsert_synced(forward.clone(), d, metadata(), t, PROTO_TCP, TCP_ACK, false));
    assert_eq!(probe(&mut table, &wire, wire_bound, t + SEC), ProbeHitVerdict::Live);
    // A changed one (another egress, same NAT so the same wire tuple) is a
    // new incarnation: the wire tuple's hit is refused.
    let mut changed = d;
    changed.resolution.egress_ifindex += 1;
    assert!(table.upsert_synced(forward.clone(), changed, metadata(), t, PROTO_TCP, TCP_ACK, false));
    assert_eq!(probe(&mut table, &wire, wire_bound, t + 2 * SEC), ProbeHitVerdict::Replaced);
}

/// codex-c (inspected, now pinned): a reverse row whose NAT moves its
/// translated tuple is reached through the reverse-translated alias index.
/// The seed-time accessor and the probe resolve the SAME row through that
/// alias: the accessor binds the reverse row's epoch, the probe serves it,
/// an identical re-import of the reverse row keeps serving it, and a changed
/// one is refused.
#[test]
fn reverse_translated_alias_resolves_like_the_probe_19173() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(40000),
        ..crate::nat::NatDecision::default()
    };
    let mut d = decision();
    d.nat = nat;
    let now = 10 * SEC;
    assert!(table.upsert_synced(forward.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    let reverse = reverse_session_key(&forward, nat);
    let mut rmeta = metadata();
    rmeta.is_reverse = true;
    assert!(table.upsert_synced(reverse.clone(), d, rmeta.clone(), now, PROTO_TCP, TCP_ACK, false));
    let alias = translated_session_key(&reverse, nat);
    assert_ne!(alias, reverse, "premise: the reverse row's NAT moves its translated tuple");
    assert_ne!(alias, forward);
    assert!(table.key_to_handle.get(&alias).is_none(), "premise: the alias is no row's key");
    let (handle, via_alias) = table.resolve_lookup_handle(&alias).expect("alias resolves");
    assert!(via_alias, "premise: resolved through the reverse-translated alias index");
    assert_eq!(Some(&handle), table.key_to_handle.get(&reverse), "premise: to the reverse row");
    let t = now + SEC;
    let bound = table.backing_install_epoch_for_cache_hit(&alias, t).expect("alias binds");
    assert_eq!(bound, epoch(&table, &reverse), "the accessor binds the reverse row");
    assert_eq!(probe(&mut table, &alias, bound, t), ProbeHitVerdict::Live);
    assert_eq!(probe(&mut table, &alias, bound.wrapping_add(1), t), ProbeHitVerdict::Replaced);
    // Identical re-import of the reverse row: still the same incarnation.
    assert!(table.upsert_synced(reverse.clone(), d, rmeta.clone(), t, PROTO_TCP, TCP_ACK, false));
    assert_eq!(probe(&mut table, &alias, bound, t + SEC), ProbeHitVerdict::Live);
    // Changed (another egress, same NAT so the same alias): refused.
    let mut changed = d;
    changed.resolution.egress_ifindex += 1;
    assert!(table.upsert_synced(reverse.clone(), changed, rmeta, t, PROTO_TCP, TCP_ACK, false));
    assert_eq!(probe(&mut table, &alias, bound, t + 2 * SEC), ProbeHitVerdict::Replaced);
    assert_eq!(
        table.backing_install_epoch_for_cache_hit(&alias, t + 2 * SEC),
        Some(epoch(&table, &reverse)),
        "a re-seed binds the replacing reverse row through the alias"
    );
}

/// codex-c (inspected, now pinned): an AMBIGUOUS wire tuple (two live forward
/// rows translate to it, #14382) resolves no row for the seed and no row for
/// the probe, so the seed binds `PROBE_NO_BACKING_ROW` and its hit is a
/// no-record refusal, never first-wins. When the ambiguity collapses (one row
/// goes away) the wire tuple resolves the survivor: the sentinel-bound entry
/// is refused as `Replaced` (it was computed without that row), and a re-seed
/// binds the survivor.
#[test]
fn ambiguous_wire_tuple_binds_no_row_and_the_probe_agrees_19173() {
    let mut table = SessionTable::new();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(40000),
        ..crate::nat::NatDecision::default()
    };
    let mut d = decision();
    d.nat = nat;
    let now = 10 * SEC;
    let first = key_v4();
    let mut second = key_v4();
    second.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let wire = forward_wire_key(&first, nat);
    assert_eq!(forward_wire_key(&second, nat), wire, "premise: one wire tuple");
    assert!(table.upsert_synced(first.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    assert!(table.upsert_synced(second.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    let t = now + SEC;
    assert_eq!(
        table.find_forward_wire_match_expiry(&wire, t),
        SessionExpiryProbe::Absent,
        "premise: two live candidates make the wire tuple ambiguous"
    );
    assert_eq!(table.backing_install_epoch_for_cache_hit(&wire, t), None, "the seed binds no row");
    let mut canonical = None;
    let verdict = table.probe_hit_deferring_state_update_with_ack_rollback_verdict_lazy(
        &wire,
        PROBE_NO_BACKING_ROW,
        t,
        1514,
        TCP_ACK | TCP_PSH,
        1448,
        0,
        || None,
        true,
        &mut canonical,
    );
    assert_eq!(verdict, ProbeHitVerdict::NoRecord, "the probe agrees: no row, no first-wins");
    assert_eq!(canonical, None);
    // The ambiguity collapses: the wire tuple now names the survivor.
    table.delete(&second);
    let survivor = table.backing_install_epoch_for_cache_hit(&wire, t).expect("unique now");
    assert_eq!(survivor, epoch(&table, &first));
    assert_eq!(
        probe(&mut table, &wire, PROBE_NO_BACKING_ROW, t + SEC),
        ProbeHitVerdict::Replaced,
        "the entry seeded while the tuple was ambiguous must not be served the survivor"
    );
    assert_eq!(probe(&mut table, &wire, survivor, t + SEC), ProbeHitVerdict::Live);
}

/// A seed that resolved no row binds `PROBE_NO_BACKING_ROW`, which no
/// installed row matches: a row that appears later is refused, not served
/// the decision computed without it.
#[test]
fn no_backing_row_sentinel_matches_no_row_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    assert_eq!(table.backing_install_epoch_for_cache_hit(&key, SEC), None);
    import(&mut table, &key, SEC);
    assert_eq!(probe(&mut table, &key, PROBE_NO_BACKING_ROW, 2 * SEC), ProbeHitVerdict::Replaced);
}

/// MEASUREMENT: which cache lines of `SessionEntry` the incarnation compare
/// reads (`install_epoch`) against the fields the fused probe already reads
/// on every steady-state hit. Prints only.
#[test]
#[ignore = "MEASUREMENT: #19173 SessionEntry install_epoch line; prints only"]
fn session_entry_install_epoch_line_19173() {
    let mut fields: Vec<(usize, usize, &str)> = Vec::new();
    macro_rules! field {
        ($name:ident, $ty:ty) => {
            fields.push((
                std::mem::offset_of!(SessionEntry, $name),
                std::mem::size_of::<$ty>(),
                stringify!($name),
            ))
        };
    }
    field!(install_epoch, u64);
    field!(last_seen_ns, u64);
    field!(last_packet_seen_ns, u64);
    field!(expires_after_ns, u64);
    field!(closing, bool);
    field!(established, bool);
    field!(handshake_pending, bool);
    field!(served_here, bool);
    field!(observed_tos, u8);
    field!(observed_tcp_flags, u8);
    field!(counters, SessionCounters);
    field!(metadata, SessionMetadata);
    field!(decision, SessionDecision);
    fields.sort();
    eprintln!(
        "#19173 SessionRecord size {} (entry {} at record offset {}), align {}",
        std::mem::size_of::<SessionRecord>(),
        std::mem::size_of::<SessionEntry>(),
        std::mem::offset_of!(SessionRecord, entry),
        std::mem::align_of::<SessionEntry>()
    );
    for (offset, size, name) in fields {
        eprintln!(
            "  {offset:>4}..{:>4} line {}..{} {name}",
            offset + size,
            offset / 64,
            (offset + size - 1) / 64
        );
    }
}
