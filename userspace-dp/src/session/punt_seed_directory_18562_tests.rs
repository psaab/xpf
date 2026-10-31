// #18562: the node-wide punt-seed directory is a SNAPSHOT of live worker-local
// #7770 seeds, so its whole contract is lifecycle: a row exists only while the
// table that minted it still holds that seed incarnation, unmodified. Each
// cell drives the table's real install / removal paths — the directory is
// never written directly except by the cap cell, which pins the directory's own
// bound.

use super::tests::{decision, key_v4, metadata};
use super::*;
use std::sync::Arc;

const T0: u64 = 5_000_000_000;

fn udp_key() -> SessionKey {
    SessionKey {
        protocol: PROTO_UDP,
        ..key_v4()
    }
}

fn table_on(dir: &Arc<PuntSeedDirectory>) -> SessionTable {
    let mut table = SessionTable::new();
    table.set_punt_seed_directory(Arc::clone(dir));
    table
}

fn install(table: &mut SessionTable, key: &SessionKey, origin: SessionOrigin, now_ns: u64) {
    assert!(
        table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            origin,
            now_ns,
            key.protocol,
            0,
        ),
        "premise: {origin:?} installs"
    );
}

/// Only a forward `FabricPuntSeed` is published, and the row names the seed's
/// own incarnation and adjudicated zone pair. Every other local origin —
/// including the other transient seed — publishes nothing: the directory is not
/// a second shared-session map.
#[test]
fn only_a_forward_fabric_punt_seed_is_published_18562() {
    for origin in [
        SessionOrigin::ForwardFlow,
        SessionOrigin::LocalMiss,
        SessionOrigin::MissingNeighborSeed,
        SessionOrigin::SyncImport,
    ] {
        let dir = Arc::new(PuntSeedDirectory::new());
        let mut table = table_on(&dir);
        install(&mut table, &udp_key(), origin, T0);
        assert_eq!(dir.len(), 0, "{origin:?} must not reach the punt-seed directory");
    }
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let key = udp_key();
    install(&mut table, &key, SessionOrigin::FabricPuntSeed, T0);
    let row = dir.probe(&key, T0).expect("a forward punt seed is published");
    assert_eq!(row.session_id, table.session_id_for(&key), "the row names this incarnation");
    assert_eq!(row.metadata.ingress_zone, metadata().ingress_zone);
    assert_eq!(row.metadata.egress_zone, metadata().egress_zone);
    assert!(!row.metadata.is_reverse);

    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let mut reverse = metadata();
    reverse.is_reverse = true;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        reverse,
        SessionOrigin::FabricPuntSeed,
        T0,
        PROTO_UDP,
        0,
    ));
    assert_eq!(dir.len(), 0, "a reverse-shaped row is never published (seeds are forward-only)");
}

/// Every way the seed can stop existing — or stop being the snapshot — retires
/// its row: explicit delete, idle expiry, replacement by another install, an
/// in-place HA refresh, the table moving to another directory, and the table
/// being dropped. A retire path missing here would leave a row that admits
/// errors for a flow this node no longer holds. One cell per path, so a
/// mutant of one retire site cannot hide behind another's earlier failure.
fn assert_removal_path_retires(name: &str, path: impl FnOnce(&mut Option<SessionTable>, &SessionKey)) {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = Some(table_on(&dir));
    let key = udp_key();
    install(table.as_mut().unwrap(), &key, SessionOrigin::FabricPuntSeed, T0);
    assert!(dir.probe(&key, T0).is_some(), "{name}: premise: row published");
    path(&mut table, &key);
    assert!(dir.probe(&key, T0 + 1).is_none(), "{name}: the seed's row must be retired");
    assert_eq!(dir.len(), 0, "{name}: no row left behind");
}

#[test]
fn seed_delete_retires_its_row_18562() {
    assert_removal_path_retires("delete", |t, k| t.as_mut().unwrap().delete(k));
}

#[test]
fn seed_idle_expiry_retires_its_row_18562() {
    assert_removal_path_retires("idle expiry", |t, k| {
        let expired = t.as_mut().unwrap().expire_stale_entries(T0 + 3_600_000_000_000);
        assert!(expired.iter().any(|e| e.key == *k), "premise: the seed expired");
    });
}

#[test]
fn seed_replacement_install_retires_its_row_18562() {
    assert_removal_path_retires("replacement install", |t, k| {
        install(t.as_mut().unwrap(), k, SessionOrigin::ForwardFlow, T0 + 1)
    });
}

#[test]
fn seed_in_place_ha_refresh_retires_its_row_18562() {
    assert_removal_path_retires("in-place HA refresh", |t, k| {
        assert!(t.as_mut().unwrap().refresh_for_ha_transition(k, decision(), metadata(), T0 + 1));
    });
}

#[test]
fn table_moved_to_another_directory_retires_its_rows_18562() {
    assert_removal_path_retires("moved to another directory", |t, _| {
        t.as_mut().unwrap().set_punt_seed_directory(Arc::new(PuntSeedDirectory::new()))
    });
}

#[test]
fn dropped_table_retires_its_rows_18562() {
    assert_removal_path_retires("table dropped", |t, _| drop(t.take()));
}

/// A retire removes only the incarnation it names: another worker's seed for
/// the same tuple (its own table) survives this worker's delete, and dies with
/// its own table.
#[test]
fn retire_is_fenced_by_table_and_incarnation_18562() {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut worker_a = table_on(&dir);
    let mut worker_b = table_on(&dir);
    let key = udp_key();
    install(&mut worker_a, &key, SessionOrigin::FabricPuntSeed, T0);
    install(&mut worker_b, &key, SessionOrigin::FabricPuntSeed, T0 + 1);
    let b_id = worker_b.session_id_for(&key);
    worker_a.delete(&key);
    assert_eq!(
        dir.probe(&key, T0 + 2).map(|r| r.session_id),
        Some(b_id),
        "worker A's delete must not retire worker B's row"
    );
    drop(worker_a);
    assert!(dir.probe(&key, T0 + 2).is_some(), "dropping A must not retire B's row");
    drop(worker_b);
    assert!(dir.probe(&key, T0 + 2).is_none());
}

/// The row stops matching at the seed's idle deadline AS INSTALLED, capped at
/// the bridge TTL; it is never extended, so a seed kept alive by traffic outlives its row (fail
/// closed) rather than the reverse.
#[test]
fn row_stops_matching_at_the_install_deadline_18562() {
    let dir = Arc::new(PuntSeedDirectory::new());
    let mut table = table_on(&dir);
    let key = udp_key();
    install(&mut table, &key, SessionOrigin::FabricPuntSeed, T0);
    let deadline = dir.probe(&key, T0).expect("published").expires_at_ns;
    assert!(deadline > T0, "premise: a positive idle window");
    assert!(
        deadline <= T0 + PUNT_SEED_ROW_TTL_NS,
        "a row bridges at most the TTL, however long the seed's idle window"
    );
    assert!(dir.probe(&key, deadline - 1).is_some());
    assert!(dir.probe(&key, deadline).is_none(), "the row must not outlive the installed deadline");
}

fn row_at(expires_at_ns: u64, session_id: u64) -> PuntSeedRow {
    PuntSeedRow {
        decision: decision(),
        metadata: metadata(),
        session_id,
        table_token: 1,
        expires_at_ns,
    }
}

/// `n` distinct keys that all hash to `dir`'s shard 0, so a cell can drive one
/// shard to its cap deterministically.
fn keys_in_one_shard(dir: &PuntSeedDirectory, n: usize) -> Vec<SessionKey> {
    let target = dir.shard_of_for_test(&udp_key());
    let mut out = Vec::with_capacity(n);
    let mut i: u32 = 0;
    while out.len() < n {
        let key = SessionKey {
            src_port: (i & 0xffff) as u16,
            dst_port: (i >> 16) as u16,
            ..udp_key()
        };
        if dir.shard_of_for_test(&key) == target {
            out.push(key);
        }
        i += 1;
    }
    out
}

/// Review seat L/K (#18562): at the cap a publish must cost O(1) amortized —
/// the pre-review design scanned the whole map under a node mutex on EVERY
/// publish at the cap (139-284 us each). Pinned by work (queue entries and rows
/// touched), not time: a full shard of LIVE rows refuses without touching
/// anything, and nothing live is evicted. RED on the old full-map `retain`
/// (CAP touches per refused publish).
#[test]
fn full_shard_of_live_rows_refuses_in_constant_work_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let keys = keys_in_one_shard(&dir, cap + 1000);
    for (n, key) in keys[..cap].iter().enumerate() {
        assert!(dir.publish(key, row_at(T0 + 1_000_000_000, n as u64), T0));
    }
    let work_before = dir.work_for_test();
    let refused_before = PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    for (n, key) in keys[cap..].iter().enumerate() {
        assert!(!dir.publish(key, row_at(T0 + 1_000_000_000, (cap + n) as u64), T0), "a full shard refuses");
    }
    assert_eq!(dir.work_for_test() - work_before, 0, "a refusal at the cap must touch nothing");
    assert!(
        PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed) - refused_before >= 1000,
        "each refusal is counted"
    );
    assert!(keys[..cap].iter().all(|k| dir.probe(k, T0).is_some()), "no live row was evicted");
}

/// Steady state at the cap: rows keep expiring while new flows keep arriving.
/// Each publish pops only what has expired, so total work stays within a
/// constant factor of the publish count. RED on any per-publish scan.
#[test]
fn steady_state_at_cap_costs_constant_amortized_work_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let n = 4 * cap;
    let keys = keys_in_one_shard(&dir, cap + n);
    for (i, key) in keys[..cap].iter().enumerate() {
        assert!(dir.publish(key, row_at(T0 + 1 + i as u64, i as u64), T0));
    }
    let work_before = dir.work_for_test();
    for (j, key) in keys[cap..].iter().enumerate() {
        let now = T0 + 1 + j as u64;
        assert!(
            dir.publish(key, row_at(now + cap as u64, (cap + j) as u64), now),
            "a row expired, so the publish fits"
        );
    }
    let work = dir.work_for_test() - work_before;
    assert!(work <= 3 * n as u64, "{work} units of work for {n} publishes at the cap");
    assert!(dir.len() <= cap);
}

/// Retired rows leave their queue slots behind (O(1) retire); a stale slot at
/// the front is popped by the next publish, so one-flow-at-a-time churn keeps
/// the queue short and total work linear in publishes.
#[test]
fn retire_churn_keeps_the_queue_short_in_amortized_constant_work_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let rounds = 8;
    let keys = keys_in_one_shard(&dir, cap * rounds);
    let shard = dir.shard_of_for_test(&keys[0]);
    let work_before = dir.work_for_test();
    let mut publishes = 0u64;
    for (i, key) in keys.iter().enumerate() {
        assert!(dir.publish(key, row_at(T0 + 3_600_000_000_000, i as u64), T0), "churned rows never fill the shard");
        publishes += 1;
        dir.retire(key, 1, i as u64);
        assert!(dir.queue_len_for_test(shard) <= 2, "stale front slots are popped by the next publish");
    }
    let work = dir.work_for_test() - work_before;
    assert!(work <= 4 * publishes, "{work} units of work for {publishes} publish+retire pairs");
    assert_eq!(dir.len(), 0);
}

/// Seat L's adversarial shape (r2): a live front, 1023 lazily retired slots
/// behind it, and 1023 more live rows, ALL expiring at the same instant. The
/// pre-fold design popped every slot in ONE publish (2047 pops, 252-279 us
/// under the shard lock that `retire`/`probe` wait on). A single call is now
/// capped at `MAINTAIN_BUDGET` pops; the rest drain over the following calls.
/// RED on an unbounded `maintain`.
#[test]
fn one_publish_does_bounded_work_however_much_expires_at_once_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let budget = PuntSeedDirectory::maintain_budget_for_test() as u64;
    let keys = keys_in_one_shard(&dir, 2 * cap + 1);
    let shard = dir.shard_of_for_test(&keys[0]);
    // Live front.
    assert!(dir.publish(&keys[0], row_at(T0 + 1, 0), T0));
    // 1023 lazily retired slots behind it (the live front keeps them queued).
    for (n, key) in keys[1..cap].iter().enumerate() {
        let id = (n + 1) as u64;
        assert!(dir.publish(key, row_at(T0 + 1, id), T0));
        dir.retire(key, 1, id);
    }
    // 1023 more live rows, same deadline.
    for (n, key) in keys[cap..2 * cap - 1].iter().enumerate() {
        assert!(dir.publish(key, row_at(T0 + 1, (cap + n) as u64), T0));
    }
    assert_eq!(dir.queue_len_for_test(shard), 2 * cap - 1, "premise: the adversarial queue");
    let before = dir.work_for_test();
    let _ = dir.publish(&keys[2 * cap], row_at(T0 + 10, 9_999_999), T0 + 2);
    let single = dir.work_for_test() - before;
    assert!(single <= budget, "one publish did {single} units of work (budget {budget})");
    // The rest drains over the following calls, and nothing expired matches.
    for (n, key) in keys[..cap].iter().enumerate() {
        let _ = dir.publish(key, row_at(T0 + 10, 20_000_000 + n as u64), T0 + 2);
    }
    assert!(keys[cap..2 * cap - 1].iter().all(|k| dir.probe(k, T0 + 2).is_none()), "expired rows never match");
}

/// A live front with churn behind it cannot be drained from the front, so the
/// queue is HARD-capped: past `QUEUE_CAP` a publish is refused (fail closed,
/// counted) instead of the queue growing or being compacted in one pass. RED
/// without the queue-cap refusal.
#[test]
fn stuck_front_queue_is_capped_and_refuses_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let qcap = PuntSeedDirectory::queue_cap_for_test();
    let keys = keys_in_one_shard(&dir, qcap + 500);
    let shard = dir.shard_of_for_test(&keys[0]);
    assert!(dir.publish(&keys[0], row_at(T0 + 3_600_000_000_000, 0), T0));
    let refused_before = PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let mut refused = 0;
    for (n, key) in keys[1..].iter().enumerate() {
        let id = (n + 1) as u64;
        if dir.publish(key, row_at(T0 + 3_600_000_000_000, id), T0) {
            dir.retire(key, 1, id);
        } else {
            refused += 1;
        }
        assert!(dir.queue_len_for_test(shard) <= qcap, "the queue never exceeds its cap");
    }
    assert!(refused > 0, "past the queue cap publishes are refused");
    assert!(
        PUNT_SEED_DIRECTORY_FULL_TOTAL.load(std::sync::atomic::Ordering::Relaxed) - refused_before >= refused,
        "and counted"
    );
    let _ = cap;
}

/// Measurement harness for the review (not a gate): ns per publish below the
/// cap, at a full shard of live rows, and in steady state at the cap. Run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "timing harness for #18562 review; run explicitly"]
fn punt_seed_directory_publish_cost_bench_18562() {
    let reps = 20_000usize;
    let cap = PuntSeedDirectory::row_cap_for_test();
    let time = |f: &mut dyn FnMut()| {
        let t = std::time::Instant::now();
        f();
        t.elapsed().as_nanos() as f64 / reps as f64
    };
    let dir = PuntSeedDirectory::new();
    let below = keys_in_one_shard(&dir, reps);
    let mut i = 0u64;
    let below_ns = time(&mut || {
        for key in &below {
            i += 1;
            let _ = dir.publish(key, row_at(T0 + i, i), T0);
            dir.retire(key, 1, i);
        }
    });
    let full = PuntSeedDirectory::new();
    let keys = keys_in_one_shard(&full, cap + reps);
    for (n, key) in keys[..cap].iter().enumerate() {
        full.publish(key, row_at(u64::MAX, n as u64), T0);
    }
    let refused_ns = time(&mut || {
        for (n, key) in keys[cap..].iter().enumerate() {
            let _ = full.publish(key, row_at(u64::MAX, n as u64), T0);
        }
    });
    let steady = PuntSeedDirectory::new();
    let keys = keys_in_one_shard(&steady, cap + reps);
    for (n, key) in keys[..cap].iter().enumerate() {
        steady.publish(key, row_at(T0 + 1 + n as u64, n as u64), T0);
    }
    let steady_ns = time(&mut || {
        for (j, key) in keys[cap..].iter().enumerate() {
            let now = T0 + 1 + j as u64;
            let _ = steady.publish(key, row_at(now + cap as u64, (cap + j) as u64), now);
        }
    });
    // Review LOW: growing a shard rehashes it under its lock. Worst single
    // publish while one shard fills from empty to its cap (<= 1024 rows).
    let grow = PuntSeedDirectory::new();
    let keys = keys_in_one_shard(&grow, cap);
    let mut grow_max_ns = 0u128;
    for (n, key) in keys.iter().enumerate() {
        let t = std::time::Instant::now();
        let _ = grow.publish(key, row_at(u64::MAX, n as u64), T0);
        grow_max_ns = grow_max_ns.max(t.elapsed().as_nanos());
    }
    // Review seat L (r2): the adversarial single publish — a live front, 1023
    // lazily retired slots, 1023 more live rows, all expiring together.
    let adv = PuntSeedDirectory::new();
    let keys = keys_in_one_shard(&adv, 2 * cap + 1);
    adv.publish(&keys[0], row_at(T0 + 1, 0), T0);
    for (n, key) in keys[1..cap].iter().enumerate() {
        adv.publish(key, row_at(T0 + 1, (n + 1) as u64), T0);
        adv.retire(key, 1, (n + 1) as u64);
    }
    for (n, key) in keys[cap..2 * cap - 1].iter().enumerate() {
        adv.publish(key, row_at(T0 + 1, (cap + n) as u64), T0);
    }
    let mut adv_max_ns = 0u128;
    for (n, key) in keys[..cap].iter().enumerate() {
        let t = std::time::Instant::now();
        let _ = adv.publish(key, row_at(T0 + 10, 50_000_000 + n as u64), T0 + 2);
        adv_max_ns = adv_max_ns.max(t.elapsed().as_nanos());
    }
    // Review seat L (r3): worst single publish under 100k-step churn at the
    // live-row cap (retire one, publish one).
    let churn = PuntSeedDirectory::new();
    let steps = 100_000usize;
    let keys = keys_in_one_shard(&churn, cap + steps);
    for (n, key) in keys[..cap].iter().enumerate() {
        churn.publish(key, row_at(u64::MAX, n as u64), T0);
    }
    let mut churn_ns: Vec<u128> = Vec::with_capacity(steps);
    for step in 0..steps {
        churn.retire(&keys[step], 1, step as u64);
        let t = std::time::Instant::now();
        let _ = churn.publish(&keys[cap + step], row_at(u64::MAX, (cap + step) as u64), T0);
        churn_ns.push(t.elapsed().as_nanos());
    }
    // A single max over 100k samples catches host preemption as easily as
    // real lock work, so report the tail shape too.
    let tail = |v: &mut Vec<u128>| -> String {
        v.sort_unstable();
        let at = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
        format!(
            "p50={} p99.9={} max={} over30us={}",
            at(0.5),
            at(0.999),
            v[v.len() - 1],
            v.iter().filter(|&&n| n > 30_000).count()
        )
    };
    let churn_tail = tail(&mut churn_ns);
    // The two candidate fixes, measured on the raw table the shard uses:
    // (A, chosen) reserve 1024, keep <= half its capacity live; (B) reserve
    // 2048, keep 1024 live. (bug) reserve 1024, keep 1016 live.
    // Per variant: rehash events (an insert after which `capacity()` jumped
    // back up = tombstones purged), the worst insert that DID rehash, the
    // worst that did not (noise floor), and whether the table grew.
    let raw = |reserve: usize, live: usize| -> String {
        let mut m: std::collections::HashMap<SessionKey, PuntSeedRow, crate::hot_hash_seed::HotPathSeededState> =
            std::collections::HashMap::with_hasher(crate::hot_hash_seed::HotPathSeededState::new(7));
        m.reserve(reserve);
        let start_cap = m.capacity();
        let key = |i: usize| SessionKey { src_port: (i & 0xffff) as u16, dst_port: (i >> 16) as u16, ..udp_key() };
        for i in 0..live {
            m.insert(key(i), row_at(u64::MAX, i as u64));
        }
        let (mut events, mut worst_rehash, mut worst_plain, mut max_cap) = (0u32, 0u128, 0u128, start_cap);
        let mut all: Vec<u128> = Vec::with_capacity(steps);
        for step in 0..steps {
            m.remove(&key(step));
            let before = m.capacity();
            let t = std::time::Instant::now();
            m.insert(key(live + step), row_at(u64::MAX, step as u64));
            let ns = t.elapsed().as_nanos();
            all.push(ns);
            let after = m.capacity();
            max_cap = max_cap.max(after);
            // A tombstone reuse raises `capacity()` by exactly 1; a rehash
            // restores many slots at once.
            if after > before + 1 {
                events += 1;
                worst_rehash = worst_rehash.max(ns);
            } else {
                worst_plain = worst_plain.max(ns);
            }
        }
        format!("cap {start_cap}->max {max_cap} rehash-events={events} worst-rehash-insert={worst_rehash}ns worst-plain-insert={worst_plain}ns insert {}", tail(&mut all))
    };
    let a = raw(1024, 896);
    let b = raw(2048, cap);
    let x = raw(1024, 1016);
    eprintln!(
        "R18562BENCH publish ns: below-cap(publish+retire)={below_ns:.0} at-cap-refused={refused_ns:.0} steady-at-cap={steady_ns:.0} worst-growth-publish={grow_max_ns} worst-adversarial-publish={adv_max_ns} churn-at-cap-publish[{churn_tail}]"
    );
    eprintln!("R18562BENCH raw churn 100k A reserve1024/live896: {a}");
    eprintln!("R18562BENCH raw churn 100k B (chosen) reserve2048/live{cap}: {b}");
    eprintln!("R18562BENCH raw churn 100k bug reserve1024/live1016: {x}");
}

/// Every in-place writer of a forward entry's decision or metadata retires a
/// seed's row before it rewrites it (review seat K: `revalidate_forwarding_
/// resolution_with_egress_zone` rewrote resolution, owner RG and egress zone in
/// place without retiring). One cell per writer.
#[test]
fn seed_resolution_revalidation_retires_its_row_18562() {
    assert_removal_path_retires("revalidate resolution + egress zone", |t, k| {
        assert!(t.as_mut().unwrap().revalidate_forwarding_resolution_with_egress_zone(
            k,
            decision().resolution,
            Some(7),
            Some(metadata().egress_zone + 1),
        ));
    });
}

#[test]
fn seed_forward_egress_rebind_retires_its_row_18562() {
    assert_removal_path_retires("rebind forward egress zone", |t, k| {
        assert!(t.as_mut().unwrap().rebind_forward_egress_zone(k, metadata().egress_zone + 1));
    });
}

#[test]
fn seed_zone_pair_rebind_retires_its_row_18562() {
    assert_removal_path_retires("rebind zones pair", |t, k| {
        let m = metadata();
        let _ = t.as_mut().unwrap().rebind_zones_pair(k, m.ingress_zone + 1, 0, m.egress_zone, 0);
    });
}

#[test]
fn seed_policy_pair_rebind_retires_its_row_18562() {
    assert_removal_path_retires("rebind policy pair", |t, k| {
        let m = metadata();
        let _ = t.as_mut().unwrap().rebind_policy_pair(
            k,
            9,
            1,
            Arc::new(crate::policy::PolicyRuleCounter::default()),
            m.ingress_zone,
            0,
            m.egress_zone,
            0,
        );
    });
}

/// Publish never waits on the directory (review seat L: a worker blocked on the
/// directory mutex stalls its whole RX loop). With the row's shard held by
/// another thread for 300 ms, the publish returns `false` at once and is
/// counted as contended. RED with a blocking `lock()` (the publish then waits
/// out the holder and succeeds) — bounded, never a hang.
#[test]
fn publish_skips_a_held_shard_instead_of_waiting_18562() {
    let dir = Arc::new(PuntSeedDirectory::new());
    let key = udp_key();
    let shard = dir.shard_of_for_test(&key);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let dir = Arc::clone(&dir);
        std::thread::spawn(move || {
            dir.with_shard_held_for_test(shard, || {
                held_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
            });
        })
    };
    held_rx.recv().unwrap();
    let contended_before =
        PUNT_SEED_DIRECTORY_CONTENDED_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let started = std::time::Instant::now();
    let published = dir.publish(&key, row_at(T0 + 1_000_000_000, 1), T0);
    let waited = started.elapsed();
    holder.join().unwrap();
    assert!(!published, "a held shard is skipped, not waited on");
    assert!(waited < std::time::Duration::from_millis(100), "publish waited {waited:?}");
    assert!(
        PUNT_SEED_DIRECTORY_CONTENDED_TOTAL.load(std::sync::atomic::Ordering::Relaxed) > contended_before,
        "the skip is counted"
    );
    assert!(dir.probe(&key, T0).is_none());
}

/// Review seat L (LOW): growing a shard rehashed it under its lock (a 97 us
/// worst single publish while one shard filled). The first publish into an
/// empty shard reserves its whole cap, and filling to the cap never resizes
/// it. RED without the first-publish reservation (capacity starts small and
/// grows).
#[test]
fn shard_reserves_its_cap_once_and_never_resizes_while_populated_18562() {
    let dir = PuntSeedDirectory::new();
    let shard_cap = PuntSeedDirectory::shard_cap_for_test();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let keys = keys_in_one_shard(&dir, cap);
    let shard = dir.shard_of_for_test(&keys[0]);
    assert_eq!(dir.rows_capacity_for_test(shard), 0, "an unused shard holds nothing");
    assert!(dir.publish(&keys[0], row_at(T0 + 10, 0), T0));
    let reserved = dir.rows_capacity_for_test(shard);
    assert!(reserved >= shard_cap, "the first publish reserves the shard cap ({reserved} < {shard_cap})");
    assert!(cap <= reserved / 2, "live rows are capped at half the reserved capacity ({cap} > {reserved}/2)");
    for (n, key) in keys.iter().enumerate().skip(1) {
        assert!(dir.publish(key, row_at(T0 + 10, n as u64), T0));
        assert_eq!(dir.rows_capacity_for_test(shard), reserved, "no resize while filling (row {n})");
    }
    // Everything expires: a publish into this full shard reclaims (at most a
    // budget of) expired rows and fits, and no expired row matches.
    let late = keys_in_one_shard(&dir, cap + 1)[cap].clone();
    // (No capacity check here: removals can leave hashbrown tombstones, which
    // shift `capacity()` without any reallocation — review seat K's point.)
    assert!(dir.publish(&late, row_at(T0 + 20, 99_999), T0 + 11), "expired rows make room");
    assert!(keys.iter().all(|k| dir.probe(k, T0 + 11).is_none()), "expired rows never match");
}

/// Review seat L (r3): churn at the live-row cap (one retire plus one publish
/// per step) leaves hashbrown tombstones. With more than half the table's
/// capacity live, the tombstone purge RESIZED the table under the shard lock
/// (1792 -> 3584, 339-383 us once per shard) instead of rehashing in place.
/// With live rows capped at half the reserved capacity the table never grows
/// across 100k churn publishes, and every single call stays within the pop
/// budget. RED with the old full `SHARD_CAP` live-row cap (capacity jumps).
#[test]
fn churn_at_the_cap_never_resizes_the_shard_18562() {
    let dir = PuntSeedDirectory::new();
    let cap = PuntSeedDirectory::row_cap_for_test();
    let budget = PuntSeedDirectory::maintain_budget_for_test() as u64;
    let steps = 100_000usize;
    let keys = keys_in_one_shard(&dir, cap + steps);
    let shard = dir.shard_of_for_test(&keys[0]);
    for (n, key) in keys[..cap].iter().enumerate() {
        assert!(dir.publish(key, row_at(T0 + 3_600_000_000_000, n as u64), T0), "premise: fill to the cap");
    }
    let reserved = dir.rows_capacity_for_test(shard);
    let mut worst_call = 0u64;
    for step in 0..steps {
        dir.retire(&keys[step], 1, step as u64);
        let before = dir.work_for_test();
        let id = (cap + step) as u64;
        assert!(dir.publish(&keys[cap + step], row_at(T0 + 3_600_000_000_000, id), T0), "churn at the cap fits (step {step})");
        worst_call = worst_call.max(dir.work_for_test() - before);
        // `capacity()` dips as tombstones accumulate and is restored by the
        // in-place rehash; a RESIZE would push it past the reservation.
        assert!(
            dir.rows_capacity_for_test(shard) <= reserved,
            "the shard table grew at step {step}: {} > {reserved}",
            dir.rows_capacity_for_test(shard)
        );
    }
    assert!(worst_call <= budget, "a single churn publish did {worst_call} units of work");
    assert_eq!(dir.len(), cap);
}
