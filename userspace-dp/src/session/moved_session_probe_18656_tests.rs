//! #18656: a moved session is never flow-cached on the new RG owner.
//!
//! Live shape (loss, RG1 moved to node1 under load, RG2 stays on node0):
//! node0 still owns the session and its SNAT, so after the move it
//! fabric-redirects the forward data ALREADY source-translated. On node1
//! the packet tuple is the session's forward-wire alias
//! (`forward_wire_key(canonical, nat)`), which the worker table indexes
//! only in `forward_wire_index`. The slow path resolves it there
//! (`probe_local_wire_at`) and seeds a cache entry under that tuple; the
//! fused cache-hit probe (`probe_hit_inner`) resolved only the direct key
//! and the reverse-translated alias, refused every hit (`NoRecord`), and
//! the entry was evicted and re-seeded per packet — ~18 k/s
//! `post_hit_session_dead` evictions, ~95% of node1's packets on the slow
//! path, 1.6 vs 5.1 Gbit/s.
//!
//! These cells pin, at SessionTable level: the wire key resolves to the
//! canonical record (and is accounted, refreshed and undone under the
//! canonical key), while every refusal the probe exists for still
//! refuses — an idle-crossed canonical record, an ambiguous wire tuple,
//! and a deleted session.
use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH};
use std::net::{IpAddr, Ipv4Addr};

const SEC: u64 = 1_000_000_000;
const MSS: u32 = 1448;

fn snat(port: u16) -> crate::nat::NatDecision {
    crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(port),
        ..crate::nat::NatDecision::default()
    }
}

/// The synced pair the new RG owner holds for a moved session: canonical
/// forward row + its reverse row, both peer-synced (`SyncImport`),
/// Established. Returns `(table, canonical, wire, reverse, now)`.
fn moved_pair() -> (SessionTable, SessionKey, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let nat = snat(40000);
    let mut d = decision();
    d.nat = nat;
    let now = 10 * SEC;
    assert!(table.upsert_synced(forward.clone(), d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    let reverse = reverse_session_key(&forward, nat);
    let mut rmeta = metadata();
    rmeta.is_reverse = true;
    assert!(table.upsert_synced(reverse.clone(), d, rmeta, now, PROTO_TCP, TCP_ACK, false));
    let wire = forward_wire_key(&forward, nat);
    assert_ne!(wire, forward, "premise: SNAT moves the forward wire tuple");
    assert!(
        table.entry_by_key_quiet(&wire).is_none(),
        "premise: no row is keyed by the wire tuple itself"
    );
    assert!(
        table.has_session_hit_at(&wire, now + SEC),
        "premise: the slow path's scope order resolves the wire tuple"
    );
    (table, forward, wire, reverse, now)
}

fn probe(
    table: &mut SessionTable,
    key: &SessionKey,
    now_ns: u64,
    rollback_possible: bool,
) -> (ProbeHitVerdict, Option<SessionKey>) {
    let mut wire_canonical = None;
    let verdict = table.probe_hit_deferring_state_update_with_ack_rollback_verdict(
        key,
        now_ns,
        1514,
        TCP_ACK | TCP_PSH,
        MSS,
        0,
        None,
        rollback_possible,
        &mut wire_canonical,
    );
    (verdict, wire_canonical)
}

/// The defect cell: a hit on the forward-wire tuple serves the canonical
/// record. Pre-fix the verdict was `NoRecord`.
#[test]
fn wire_key_hit_serves_canonical_record_18656() {
    let (mut table, forward, wire, _reverse, now) = moved_pair();
    let before = table.entry_by_key_quiet(&forward).expect("canonical").counters;
    let t = now + 600 * SEC; // past the keepalive throttle of an established row
    let (verdict, canonical) = probe(&mut table, &wire, t, false);
    assert_eq!(verdict, ProbeHitVerdict::Live, "wire-keyed hit must be served");
    assert_eq!(canonical.as_ref(), Some(&forward), "probe names the canonical key");
    let entry = table.entry_by_key_quiet(&forward).expect("canonical");
    assert_eq!(
        entry.counters.fwd_packets,
        before.fwd_packets + 1,
        "the hit is accounted on the canonical forward row"
    );
    assert!(entry.served_here, "the canonical row records local service");
    assert_eq!(entry.last_seen_ns, t, "the keepalive refreshes the canonical row");
    // A direct-key hit names no wire canonical (steady state unchanged).
    let (verdict, canonical) = probe(&mut table, &forward, t + SEC, false);
    assert_eq!(verdict, ProbeHitVerdict::Live);
    assert_eq!(canonical, None);
}

/// Guard: the wire scope never resurrects an idle-crossed record. The
/// candidate selection is expiry-aware, exactly as the slow path's.
#[test]
fn wire_key_hit_refuses_idle_crossed_canonical_18656() {
    let (mut table, forward, wire, _reverse, now) = moved_pair();
    let expiry = table.entry_by_key_quiet(&forward).expect("canonical").expires_after_ns;
    let t = now + expiry + SEC;
    assert!(!table.has_session_hit_at(&wire, t), "premise: slow path refuses too");
    let (verdict, _) = probe(&mut table, &wire, t, false);
    assert_eq!(verdict, ProbeHitVerdict::NoRecord);
    assert!(!table.session_is_live_at(&wire, t));
    assert_eq!(table.live_ingress_zone_matches_at(&wire, t, metadata().ingress_zone), None);
}

/// Guard: two live forward rows sharing one wire tuple fail closed
/// (#14382), never first-wins.
#[test]
fn wire_key_hit_refuses_ambiguous_wire_tuple_18656() {
    let (mut table, _forward, wire, _reverse, now) = moved_pair();
    let mut other = key_v4();
    other.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut d = decision();
    d.nat = snat(40000);
    assert_eq!(forward_wire_key(&other, d.nat), wire, "premise: same wire tuple");
    assert!(table.upsert_synced(other, d, metadata(), now, PROTO_TCP, TCP_ACK, false));
    // Premise, independent of the candidate walk under test: two validated,
    // live, non-reverse forward rows really do share this wire tuple.
    let live_candidates = table
        .forward_wire_index
        .get(&wire)
        .map(|bucket| {
            bucket
                .iter()
                .filter_map(|&h| table.entries.get(h as usize))
                .filter(|r| {
                    !r.entry.metadata.is_reverse
                        && forward_wire_key(&r.key, r.entry.decision.nat) == wire
                        && (now + SEC).saturating_sub(r.entry.last_seen_ns) <= r.entry.expires_after_ns
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(live_candidates, 2, "premise: two live candidates share the wire tuple");
    let (verdict, canonical) = probe(&mut table, &wire, now + SEC, false);
    assert_eq!(verdict, ProbeHitVerdict::NoRecord);
    assert_eq!(canonical, None);
}

/// Guard: a deleted session refuses through the wire tuple too.
#[test]
fn wire_key_hit_refuses_deleted_session_18656() {
    let (mut table, forward, wire, reverse, now) = moved_pair();
    table.delete(&forward);
    table.delete(&reverse);
    let (verdict, _) = probe(&mut table, &wire, now + SEC, false);
    assert_eq!(verdict, ProbeHitVerdict::NoRecord);
    assert!(!table.session_is_live_at(&wire, now + SEC));
}

/// The deferring probe records its undo under the CANONICAL key; a dropped
/// wire-keyed packet rolled back under the canonical key the probe named
/// restores the pre-probe counters, and an admitted one consumes the undo.
#[test]
fn wire_key_hit_undo_keys_on_canonical_18656() {
    let (mut table, forward, wire, _reverse, now) = moved_pair();
    let before = table.entry_by_key_quiet(&forward).expect("canonical").counters;
    let (verdict, canonical) = probe(&mut table, &wire, now + SEC, true);
    assert_eq!(verdict, ProbeHitVerdict::Live);
    let canonical = canonical.expect("wire hit names its canonical key");
    table.rollback_dropped_probe_hit(&canonical, 1514, TCP_ACK);
    assert_eq!(
        table.entry_by_key_quiet(&forward).expect("canonical").counters,
        before,
        "a dropped wire-keyed hit leaves no accounting behind"
    );
    assert!(table.pending_probe_undo.is_empty(), "rollback consumed the undo");
    let (verdict, canonical) = probe(&mut table, &wire, now + 2 * SEC, true);
    assert_eq!(verdict, ProbeHitVerdict::Live);
    table.emit_probe_hit_state_update(&canonical.expect("canonical"));
    assert!(table.pending_probe_undo.is_empty(), "admission consumed the undo");
}

/// The #10670 zone fence and the TTL-arm liveness probe judge the same
/// record the probe serves: a stamped fabric arrival on the wire tuple is
/// matched against the canonical row's ingress zone (pre-fix: `None`, i.e.
/// the fence was skipped).
#[test]
fn wire_key_zone_fence_and_liveness_resolve_canonical_18656() {
    let (table, _forward, wire, _reverse, now) = moved_pair();
    let zone = metadata().ingress_zone;
    assert_eq!(table.live_ingress_zone_matches_at(&wire, now + SEC, zone), Some(true));
    assert_eq!(table.live_ingress_zone_matches_at(&wire, now + SEC, zone + 1), Some(false));
    assert!(table.session_is_live_at(&wire, now + SEC));
}

/// #18656 (review): the likely live shape. A fabric-arrival promotion marks
/// the moved session's row `fabric_ingress = true`, which makes a SNAT-only
/// forward row a fabric wire placeholder for the slow path
/// (`is_fabric_wire_placeholder`: it takes its decision from the shared
/// forward-wire entry). The probe still serves the local canonical row
/// through the wire tuple, which is the liveness and accounting record.
#[test]
fn wire_key_hit_serves_fabric_ingress_placeholder_row_18656() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let nat = snat(40000);
    let mut d = decision();
    d.nat = nat;
    let mut meta = metadata();
    meta.fabric_ingress = true;
    let now = 10 * SEC;
    assert!(table.upsert_synced(forward.clone(), d, meta, now, PROTO_TCP, TCP_ACK, false));
    let reverse = reverse_session_key(&forward, nat);
    let mut rmeta = metadata();
    rmeta.is_reverse = true;
    assert!(table.upsert_synced(reverse, d, rmeta, now, PROTO_TCP, TCP_ACK, false));
    let wire = forward_wire_key(&forward, nat);
    assert!(
        table.entry_by_key_quiet(&forward).expect("canonical").metadata.fabric_ingress,
        "premise: the canonical row carries the promoted fabric-ingress mark"
    );
    let (verdict, canonical) = probe(&mut table, &wire, now + SEC, false);
    assert_eq!(verdict, ProbeHitVerdict::Live);
    assert_eq!(canonical.as_ref(), Some(&forward));
    assert_eq!(table.entry_by_key_quiet(&forward).expect("canonical").counters.fwd_packets, 1);
}
