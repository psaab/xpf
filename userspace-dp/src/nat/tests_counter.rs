// NAT counter-store and counter-clear tests for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, PoolAddressFamily,
    TranslatedTuple, sticky_pool_index,
};
use super::source::{PersistentNatPermit, SOURCE_NAT_PROTO_ANY, SourceNatFlowKey};
use super::destination::{PROTO_ANY, PROTO_TCP, PROTO_UDP};
use super::*;
use crate::ip_proto::{PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6};
use crate::{
    DestinationNATRuleSnapshot, NatAppTermWire, NatPortRangeWire, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// FAIL-ON-REVERT: this test fails if NatRuleCounter::add stops counting or
// snapshots() drops a stored id. It exercises the store contract directly
// (get-or-insert, add packets+bytes, snapshot, the counter_id==0 skip, and
// reconcile/clear) independent of the worker path.
#[test]
fn nat_counter_store_counts_and_skips_id_zero() {
    let store = NatCounterStore::default();

    // counter_id 0 is the "no per-rule counter" sentinel — never allocated.
    assert!(
        store.rule_counter(0).is_none(),
        "counter_id 0 must not allocate a counter"
    );

    // get-or-insert returns the SAME Arc for the same id.
    let c1 = store.rule_counter(1).expect("id 1 counter");
    let c1_again = store.rule_counter(1).expect("id 1 counter again");
    assert!(
        std::sync::Arc::ptr_eq(&c1, &c1_again),
        "rule_counter must share one Arc per id"
    );

    // N adds of 100 bytes each -> packets=N, bytes=100*N.
    const N: u64 = 7;
    for _ in 0..N {
        c1.add(100);
    }
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "exactly one stored counter");
    assert_eq!(snaps[0].counter_id, 1);
    assert_eq!(snaps[0].packets, N, "one packet counted per add");
    assert_eq!(snaps[0].bytes, 100 * N, "bytes accumulate per add");

    // A second id is independent.
    let c2 = store.rule_counter(2).expect("id 2 counter");
    c2.add(40);
    let mut snaps = store.snapshots();
    snaps.sort_by_key(|s| s.counter_id);
    assert_eq!(snaps.len(), 2);
    assert_eq!(
        (snaps[1].counter_id, snaps[1].packets, snaps[1].bytes),
        (2, 1, 40)
    );

    // reconcile_ids drops counters whose id is no longer active.
    store.reconcile_ids(&[1]);
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "id 2 dropped by reconcile");
    assert_eq!(snaps[0].counter_id, 1);
    assert_eq!(snaps[0].packets, N, "surviving counter keeps its count");

    // clear zeroes the survivors but keeps them registered.
    store.clear();
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "clear keeps the registration");
    assert_eq!((snaps[0].packets, snaps[0].bytes), (0, 0), "clear zeroes");
}

// === #2255: counter_id stability across config reorder/removal ===

// FAIL-ON-REVERT for #2255 at the store layer. The cumulative numeric-keyed
// store stays correctly attributed ONLY because the compiler now derives a
// STABLE, identity-bound counter_id (a wide u32 hash) for each rule. This test
// proves the store's two safety properties that the stable id relies on:
//
//   1. A retained id keeps its cumulative count across reconcile (a rule that
//      survives a config reorder reads its OWN prior count).
//   2. A removed id is dropped, so a later rule that gets a DIFFERENT stable id
//      can never read the removed rule's leftover count.
//
// With the pre-#2255 sequential id assignment, a reorder reused a small id (1)
// for a different rule, and reconcile_ids([1]) would RETAIN the old slot 1 — so
// the new rule inherited the old rule's count. The wide, identity-derived ids
// here are the values the compiler produces (no two distinct rules share one),
// so reconcile retains the right rule and drops the rest.
#[test]
fn nat_counter_store_stable_ids_survive_reorder_and_removal() {
    let store = NatCounterStore::default();

    // Two rules with stable, identity-derived u32 ids (as the compiler emits).
    const ID_A: u32 = 0x9E37_79B1; // "rule-a"-shaped wide id
    const ID_B: u32 = 0x1234_5678; // "rule-b"-shaped wide id

    let a = store.rule_counter(ID_A).expect("id A");
    let b = store.rule_counter(ID_B).expect("id B");
    for _ in 0..5 {
        a.add(10);
    }
    for _ in 0..3 {
        b.add(10);
    }

    // Reorder: the snapshot now lists the SAME ids (identity-bound), just in a
    // different order. reconcile retains both; each rule reads its OWN count.
    store.reconcile_ids(&[ID_B, ID_A]);
    let snaps = store.snapshots();
    let a_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_A)
        .map(|s| s.packets);
    let b_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_B)
        .map(|s| s.packets);
    assert_eq!(a_pkts, Some(5), "rule A keeps its count across reorder");
    assert_eq!(b_pkts, Some(3), "rule B keeps its count across reorder");

    // Removal: rule A is removed. Its id is dropped from the store entirely.
    store.reconcile_ids(&[ID_B]);
    let snaps = store.snapshots();
    assert_eq!(snaps.len(), 1, "removed rule A's counter is dropped");
    assert_eq!(snaps[0].counter_id, ID_B);
    assert_eq!(snaps[0].packets, 3, "surviving rule B is untouched");

    // Re-add a NEW rule C with a different stable id. It starts at zero — it can
    // never inherit removed rule A's count, because A's id is gone and C's id
    // (a function of C's identity) differs from A's.
    const ID_C: u32 = 0xCAFE_BABE;
    let c = store.rule_counter(ID_C).expect("id C");
    c.add(10);
    store.reconcile_ids(&[ID_B, ID_C]);
    let snaps = store.snapshots();
    let c_pkts = snaps
        .iter()
        .find(|s| s.counter_id == ID_C)
        .map(|s| s.packets);
    assert_eq!(
        c_pkts,
        Some(1),
        "re-added rule C starts from its own count, not A's"
    );
    assert!(
        snaps.iter().all(|s| s.counter_id != ID_A),
        "removed rule A's id never reappears"
    );
}

// FAIL-ON-REVERT: a parsed SourceNatRule / DnatEntry / StaticNatEntry must
// SHARE the store's Arc for its counter_id, and carry None for counter_id 0.
// If the build wiring drops the store, the Arcs would not be ptr-eq (or the
// rule would carry None), and this fails.
#[test]
fn parsed_nat_rules_share_store_counters() {
    let store = NatCounterStore::default();

    // SNAT rule with a counter and one without.
    let snat = parse_source_nat_rules_with_previous(
        &[
            SourceNATRuleSnapshot {
                name: "snat-counted".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                counter_id: 11,
                ..SourceNATRuleSnapshot::default()
            },
            SourceNATRuleSnapshot {
                name: "snat-uncounted".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                counter_id: 0,
                ..SourceNATRuleSnapshot::default()
            },
        ],
        None,
        &store,
        0,
    );
    let snat_counter = snat[0]
        .hit_counter
        .clone()
        .expect("counted snat has counter");
    assert!(
        std::sync::Arc::ptr_eq(&snat_counter, &store.rule_counter(11).expect("store id 11")),
        "SNAT rule shares the store Arc for counter_id 11"
    );
    assert!(
        snat[1].hit_counter.is_none(),
        "counter_id 0 SNAT rule carries no counter"
    );

    // Static NAT entry with a counter.
    let static_tbl = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "static-counted".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
            counter_id: 22,
        }],
        &store,
    );
    let (_d, static_counter) = static_tbl
        .match_dnat_with_counter("203.0.113.10".parse().unwrap(), 0, "untrust")
        .expect("static dnat match");
    assert!(
        std::sync::Arc::ptr_eq(
            &static_counter.expect("static has counter"),
            &store.rule_counter(22).expect("store id 22")
        ),
        "static NAT entry shares the store Arc for counter_id 22"
    );

    // DNAT entry with a counter.
    let dnat_tbl = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat-counted".to_string(),
            counter_id: 33,
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            source_addresses: vec![],
            destination_address: "203.0.113.20".to_string(),
            destination_prefix: String::new(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.20".to_string(),
            pool_port: 8443,
            match_source_ports: vec![],
            match_destination_ports: vec![],
            match_icmp_type: None,
            match_icmp_code: None,
            off: false,
            lenient_match_dropped: false,
        }],
        &store,
    );
    let (_d, dnat_counter) = dnat_tbl
        .lookup_with_counter(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
            0,
            443,
            "untrust",
            None,
        )
        .expect("dnat match");
    assert!(
        std::sync::Arc::ptr_eq(
            &dnat_counter.expect("dnat has counter"),
            &store.rule_counter(33).expect("store id 33")
        ),
        "DNAT entry shares the store Arc for counter_id 33"
    );
}

// ---------------------------------------------------------------------------
// #2396: DNAT must not silently drop non-TCP/UDP protocols or IP-only rules.
// ---------------------------------------------------------------------------

// #3830: `clear` of the per-rule NAT hit counters (`NatCounterStore::clear` ->
// `NatRuleCounter::reset`) must not WIPE a per-flow increment recorded in the
// same instant as the clear. `reset` observes the pre-clear total, then
// `fetch_sub`s exactly that amount instead of `store(0)`, so a concurrent
// post-clear cold-path `add` survives — both are atomic RMWs on the same
// location and serialize in the modification order (no lost update). Mirrors
// the #3782 `PolicyRuleCounter` fix; narrower here (per-flow cold-path
// increment, no coalescer/generation to fence).
//
// Drives the reset/increment interleaving deterministically through the real
// subtraction seam (`subtract_observed`): a live two-thread race would be
// non-deterministic. RED-on-revert: restoring `packets.store(0)` /
// `bytes.store(0)` in `subtract_observed` (or collapsing `reset` back to
// `store(0)`) wipes the concurrent post-clear increment (1 -> 0) and fails
// the packet/byte assertions.
#[test]
fn nat_counter_clear_preserves_concurrent_post_clear_hit_3830() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    let counter = Arc::new(NatRuleCounter::default());

    // Pre-clear traffic already folded into the shared atomics: 100 translated
    // flows, 64 bytes on each trigger packet (the per-flow semantic).
    for _ in 0..100 {
        counter.add(64);
    }

    // === reset() stage 1: OBSERVE the pre-clear totals — exactly what reset()
    // reads before its subtraction. ===
    let observed_packets = counter.packets.load(Ordering::Relaxed);
    let observed_bytes = counter.bytes.load(Ordering::Relaxed);
    assert_eq!(observed_packets, 100, "observed pre-clear packet total");
    assert_eq!(observed_bytes, 100 * 64, "observed pre-clear byte total");

    // === Concurrent cold-path worker: a LEGITIMATE post-clear translated flow
    // is counted in the window between reset's observation and its
    // subtraction. ===
    counter.add(64);

    // === reset() stage 2: subtract the observed pre-clear amount. fetch_sub
    // removes only the pre-clear 100 pkts / 6400 B; a store(0) here would wipe
    // the counter INCLUDING the concurrent post-clear 1 pkt / 64 B. ===
    counter.subtract_observed(observed_packets, observed_bytes);

    let snap = counter.snapshot(7);
    assert_eq!(
        snap.packets, 1,
        "post-clear NAT hit wiped by clear — a store(0) clobbered the \
         concurrent post-clear increment (#3830)"
    );
    assert_eq!(
        snap.bytes, 64,
        "post-clear NAT bytes wiped by clear (#3830)"
    );
    assert_eq!(snap.counter_id, 7, "snapshot echoes the counter id");
}

// #3830: with NO concurrent increment, a `clear` still zeroes both fields
// exactly (the fetch_sub path is not a regression of the normal clear).
// Exercises the full operator path: `NatCounterStore::clear` -> reset.
#[test]
fn nat_counter_clear_zeroes_when_uncontended_3830() {
    let store = NatCounterStore::default();
    let counter = store.rule_counter(42).expect("non-zero id yields a counter");
    counter.add(64);
    counter.add(1500);
    let before = counter.snapshot(42);
    assert_eq!(before.packets, 2, "two flows counted");
    assert_eq!(before.bytes, 64 + 1500, "byte total accumulated");

    store.clear();

    let after = counter.snapshot(42);
    assert_eq!(after.packets, 0, "clear zeroes packets when uncontended");
    assert_eq!(after.bytes, 0, "clear zeroes bytes when uncontended");
}


// #6568 (member 6): `rule_counter` must SURVIVE a poisoned counter mutex, not
// panic on it.
//
// The pre-fix `.expect("nat counter store poisoned")` ran on the NAT
// translation path, so one unrelated panic — whatever poisoned the mutex —
// became a panic on EVERY subsequent packet that consulted a rule counter.
// That is panic amplification: a single worker fault turns into a forwarding
// outage. A rule counter is DIAGNOSTIC state; losing an increment is a
// reporting gap and never a forwarding decision, so the correct posture is to
// recover the guard and carry on.
//
// The poisoning thread panicked, it did not corrupt the BTreeMap, so
// `PoisonError::into_inner` yields a structurally intact map and the counters
// keep working through the incident — which this asserts, rather than merely
// asserting "did not panic".
//
// The sibling `NatCounterStore::snapshots` in the SAME struct already degrades
// gracefully on a poisoned lock (`let Ok(counters) = ... else { return
// Vec::new() }`), so `rule_counter` was the odd one out — and it is the one on
// the packet path.
//
// FAIL-ON-REVERT: restore `.lock().expect(...)` and this test panics instead
// of returning a counter.
#[test]
fn nat_rule_counter_recovers_from_a_poisoned_store_mutex() {
    let store = NatCounterStore::default();

    // Seed a counter BEFORE poisoning, so the recovery path is proven to see
    // the pre-existing map contents rather than a fresh empty one.
    let seeded = store.rule_counter(7).expect("counter 7");
    for _ in 0..3 {
        seeded.add(100);
    }

    // Poison the mutex the way the established #1790 test does: take the lock
    // on another thread and panic while holding it.
    let poisoner = {
        let store_ref = &store;
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let _guard = store_ref.counters.lock().unwrap();
                    panic!("deliberate poison");
                })
                .join()
        })
    };
    assert!(poisoner.is_err(), "the poisoning thread must have panicked");
    assert!(
        store.counters.lock().is_err(),
        "premise: the mutex must actually be poisoned, else this test proves nothing"
    );

    // The whole point: this call must not panic.
    let recovered = store.rule_counter(7).expect("counter 7 after poisoning");
    // ...and it must be the SAME counter, carrying the pre-poison total —
    // returning a fresh zeroed counter would silently reset the operator's
    // numbers, which is a quieter version of the same defect.
    let got = recovered.snapshot(7);
    assert_eq!(got.packets, 3, "pre-poison packet count lost");
    assert_eq!(got.bytes, 300, "pre-poison byte count lost");

    // The store still works for a NEW id after the incident.
    let fresh = store.rule_counter(9).expect("counter 9 after poisoning");
    fresh.add(100);
    let fresh_got = fresh.snapshot(9);
    assert_eq!((fresh_got.packets, fresh_got.bytes), (1, 100));

    // The id==0 sentinel is unaffected.
    assert!(store.rule_counter(0).is_none());
}
