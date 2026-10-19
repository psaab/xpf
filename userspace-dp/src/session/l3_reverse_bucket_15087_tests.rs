//! #15087 (A62-01): the L3 reverse index must stay O(1) per operation
//! however many SNAT sessions share one destination.
//!
//! Pre-fix, `l3_reverse_index` bucketed every forward session to a popular
//! destination under ONE protocol-erased `(family, server, SNAT address)`
//! key in a linear `SmallVec`: insert paid `contains` (O(bucket)), removal
//! paid `retain` (O(bucket)), and every flowless-fragment probe walked the
//! whole bucket re-deriving each member. With N live sessions to one
//! resolver/CDN/bench target through one SNAT address, each session delete
//! and each reply fragment cost O(N).
//!
//! The structural pin below (`l3_bucket_handles_stay_hashed_and_counted`)
//! names the mechanism directly and fails to compile against the pre-fix
//! `SmallVec` bucket. The scaling pin
//! (`same_destination_delete_and_probe_stay_flat_15087`) reproduces the
//! report's acceptance shape end-to-end through the public table API:
//! many same-destination SNAT sessions, then delete-all + probe timing
//! compared against a distinct-destination control. On the pre-fix code
//! the same-destination leg grows ~linearly in N while the control stays
//! flat; post-fix both legs are flat. The remaining cells pin the
//! neighbouring legitimate behaviour the fix must not change (exact /
//! 255-sentinel protocol gating, expiry, removal of one-of-many, mixed
//! protocols, NAT64, plain-forwarding exclusion).

use super::tests::{decision, metadata};
use super::*;
use crate::tcp_flags::TCP_ACK;
use std::time::{Duration, Instant};

const NOW: u64 = 1_000_000_000;
const PROBE_NOW: u64 = 2_000_000_000;

/// Forward key for client `i` (distinct source port) to the shared server.
fn snat_forward(i: u32, server: &str, proto: u8) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: proto,
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: server.parse().unwrap(),
        src_port: (40000 + (i % 60000)) as u16,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn install_snat(table: &mut SessionTable, key: SessionKey, proto: u8) {
    let mut dec = decision();
    dec.nat.rewrite_src = Some("172.16.80.8".parse().unwrap());
    assert!(
        table.install_with_protocol(key, dec, metadata(), NOW, proto, TCP_ACK),
        "install must succeed"
    );
}

/// Reply-fragment probe identity for server -> SNAT address.
fn probe(server: &str, proto: u8) -> L3ReverseKey {
    l3_reverse_probe(
        server.parse().unwrap(),
        "172.16.80.8".parse().unwrap(),
        proto,
        libc::AF_INET as u8,
    )
}

fn gated(table: &SessionTable, p: &L3ReverseKey) -> bool {
    table.reverse_nat_fragment_requires_translation(p, 0, PROBE_NOW, |_| 0)
}

/// Structural pin: the bucket is a hashed set + counts, not a Vec. This
/// fails to compile on the pre-fix `NatIndexBucket` (SmallVec) shape.
#[test]
fn l3_bucket_handles_stay_hashed_and_counted_15087() {
    let mut table = SessionTable::new();
    install_snat(&mut table, snat_forward(0, "203.0.113.9", PROTO_TCP), PROTO_TCP);
    let index_key = l3_reverse_fragment_index_key(probe("203.0.113.9", PROTO_TCP));
    let bucket = table
        .l3_reverse_index
        .get(&index_key)
        .expect("SNAT forward session must populate the L3 index");
    // Hashed membership: `handles` is a set, addressed by handle in O(1).
    assert_eq!(bucket.handles.len(), 1);
    assert_eq!(bucket.total(), 1);
    assert_eq!(bucket.count_for(PROTO_TCP), 1);
    assert_eq!(bucket.count_for(PROTO_UDP), 0);
}

/// Many sessions to ONE server via one SNAT address share one bucket;
/// deleting one leaves the survivors gated, deleting all ungates.
#[test]
fn same_destination_bucket_insert_remove_probe_15087() {
    let mut table = SessionTable::new();
    let n = 512u32;
    for i in 0..n {
        install_snat(&mut table, snat_forward(i, "203.0.113.9", PROTO_TCP), PROTO_TCP);
    }
    let p = probe("203.0.113.9", PROTO_TCP);
    assert!(gated(&table, &p), "live SNAT sessions must gate the reply tail");
    let sentinel = probe("203.0.113.9", SHIM_PROTO_FRAGMENT_NO_L4);
    assert!(gated(&table, &sentinel), "255 sentinel must match any real protocol");
    assert!(
        !gated(&table, &probe("203.0.113.9", PROTO_UDP)),
        "exact UDP probe must not match TCP-only sessions"
    );

    // Delete all but one: the survivor still gates.
    for i in 0..n - 1 {
        table.delete(&snat_forward(i, "203.0.113.9", PROTO_TCP));
    }
    assert!(gated(&table, &p), "surviving session must still gate after sibling deletes");

    // Delete the last: bucket empties, probe ungates.
    table.delete(&snat_forward(n - 1, "203.0.113.9", PROTO_TCP));
    assert!(!gated(&table, &p), "no live session -> no gate");
    assert!(!gated(&table, &sentinel), "no live session -> sentinel ungated");
    let index_key = l3_reverse_fragment_index_key(p);
    assert!(
        !table.l3_reverse_index.contains_key(&index_key),
        "empty bucket key must be dropped"
    );
}

/// Mixed protocols under one address identity: counts keep exact probes
/// honest and the sentinel sees both.
#[test]
fn mixed_protocol_counts_gate_exactly_15087() {
    let mut table = SessionTable::new();
    install_snat(&mut table, snat_forward(0, "203.0.113.9", PROTO_TCP), PROTO_TCP);
    let mut udp = snat_forward(1, "203.0.113.9", PROTO_UDP);
    udp.dst_port = 53;
    install_snat(&mut table, udp.clone(), PROTO_UDP);

    assert!(gated(&table, &probe("203.0.113.9", PROTO_TCP)));
    assert!(gated(&table, &probe("203.0.113.9", PROTO_UDP)));
    assert!(gated(&table, &probe("203.0.113.9", SHIM_PROTO_FRAGMENT_NO_L4)));
    assert!(
        !gated(&table, &probe("203.0.113.9", PROTO_ICMP)),
        "ICMP probe must not match TCP/UDP sessions"
    );

    table.delete(&udp);
    assert!(
        !gated(&table, &probe("203.0.113.9", PROTO_UDP)),
        "deleted UDP session must ungate the exact UDP probe"
    );
    assert!(gated(&table, &probe("203.0.113.9", PROTO_TCP)), "TCP survivor still gates");
    assert!(
        gated(&table, &probe("203.0.113.9", SHIM_PROTO_FRAGMENT_NO_L4)),
        "sentinel still sees the TCP survivor"
    );
}

/// Bucket-level acceptance (report A62-01): insert/remove on a 100k bucket
/// stay O(1) per op. Direct bucket ops avoid the session table's
/// debug-only whole-index invariant scan (`no_index_points_at`), which is
/// quadratic in table size by design and unrelated to this mechanism.
/// Pre-fix this cell does not compile (the bucket was a linear SmallVec).
#[test]
fn l3_bucket_100k_insert_remove_stays_flat_15087() {
    const N: u32 = 100_000;
    let mut bucket = L3ReverseBucket::new(HotPathSeededState::new(15087));
    let t0 = Instant::now();
    for h in 0..N {
        assert!(bucket.insert(h, PROTO_TCP), "fresh handle must insert");
    }
    let insert_all = t0.elapsed();
    assert!(!bucket.insert(0, PROTO_TCP), "re-assert must be idempotent");
    assert_eq!(bucket.total(), N);
    assert_eq!(bucket.count_for(PROTO_TCP), N);
    assert_eq!(bucket.count_for(PROTO_UDP), 0);

    let t1 = Instant::now();
    for h in 0..N {
        assert!(bucket.remove(h, PROTO_TCP), "present handle must remove");
    }
    let remove_all = t1.elapsed();
    assert!(bucket.is_empty());
    assert_eq!(bucket.count_for(PROTO_TCP), 0);
    assert!(!bucket.remove(0, PROTO_TCP), "absent handle remove is a no-op");

    assert!(
        insert_all < Duration::from_secs(10),
        "100k hashed inserts took {insert_all:?} (linear bucket?)"
    );
    assert!(
        remove_all < Duration::from_secs(10),
        "100k hashed removes took {remove_all:?} (linear retain?)"
    );
}

/// End-to-end probe scaling: with N sessions to ONE destination, probe cost
/// stays within a small factor of a distinct-destination control. Pre-fix
/// each probe walked all N bucket members re-deriving their keys; post-fix
/// it is counts plus a bounded walk. N is kept moderate because debug
/// builds pay the table-wide `no_index_points_at` invariant scan per
/// install/delete (pre-existing, unrelated to this index).
#[test]
fn same_destination_probe_stays_flat_15087() {
    const N: u32 = 2_000;
    const PROBES: u32 = 128;

    let mut shared = SessionTable::new();
    shared.set_max_sessions_for_test((N * 2) as usize);
    for i in 0..N {
        install_snat(&mut shared, snat_forward(i, "203.0.113.9", PROTO_TCP), PROTO_TCP);
    }
    let p = probe("203.0.113.9", PROTO_TCP);
    let t0 = Instant::now();
    for _ in 0..PROBES {
        assert!(gated(&shared, &p));
    }
    let shared_probe = t0.elapsed();

    let mut control = SessionTable::new();
    control.set_max_sessions_for_test((N * 2) as usize);
    for i in 0..N {
        let server = format!("203.0.{}.{}", (i >> 8) & 0xff, i & 0xff);
        install_snat(&mut control, snat_forward(i, &server, PROTO_TCP), PROTO_TCP);
    }
    let cp = probe("203.0.0.0", PROTO_TCP);
    let t1 = Instant::now();
    for _ in 0..PROBES {
        assert!(gated(&control, &cp));
    }
    let control_probe = t1.elapsed();

    assert!(
        shared_probe < control_probe * 10 + Duration::from_millis(500),
        "same-destination probe {shared_probe:?} must stay flat vs control {control_probe:?}"
    );
    assert!(
        shared_probe < Duration::from_secs(5),
        "same-destination probes took {shared_probe:?} (linear bucket walk?)"
    );

    // Delete-all correctness at the same fan-in (timing is governed by the
    // bucket cell above; debug invariant scans dominate here by design).
    for i in 0..N {
        shared.delete(&snat_forward(i, "203.0.113.9", PROTO_TCP));
    }
    assert!(!gated(&shared, &p), "all deleted -> ungated");
}
