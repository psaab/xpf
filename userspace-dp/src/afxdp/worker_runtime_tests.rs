// Tests for afxdp/worker_runtime.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep worker_runtime.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "worker_runtime_tests.rs"]` from worker_runtime.rs.

use super::*;

#[test]
fn snapshot_roundtrip() {
    let atomics = WorkerRuntimeAtomics::new();
    let c = WorkerRuntimeCounters {
        wall_ns: 10_000_000_000,
        active_ns: 9_700_000_000,
        idle_spin_ns: 250_000_000,
        idle_block_ns: 50_000_000,
        thread_cpu_ns: 9_950_000_000,
        work_loops: 1_234_567,
        idle_loops: 1_234,
        cos_queue_lease_acquire_v8_calls: 55,
        cos_queue_lease_acquire_v8_granted_bytes: 123_456,
    };
    atomics.publish(&c, 0);
    let s = atomics.snapshot();
    assert_eq!(s.wall_ns, c.wall_ns);
    assert_eq!(s.active_ns, c.active_ns);
    assert_eq!(s.idle_spin_ns, c.idle_spin_ns);
    assert_eq!(s.idle_block_ns, c.idle_block_ns);
    assert_eq!(s.thread_cpu_ns, c.thread_cpu_ns);
    assert_eq!(s.work_loops, c.work_loops);
    assert_eq!(s.idle_loops, c.idle_loops);
    assert_eq!(
        s.cos_queue_lease_acquire_v8_calls,
        c.cos_queue_lease_acquire_v8_calls
    );
    assert_eq!(
        s.cos_queue_lease_acquire_v8_granted_bytes,
        c.cos_queue_lease_acquire_v8_granted_bytes
    );
}

#[test]
fn counters_default_zero() {
    let c: WorkerRuntimeCounters = Default::default();
    assert_eq!(c.wall_ns, 0);
    assert_eq!(c.active_ns, 0);
    assert_eq!(c.idle_spin_ns, 0);
    assert_eq!(c.idle_block_ns, 0);
    assert_eq!(c.thread_cpu_ns, 0);
    assert_eq!(c.work_loops, 0);
    assert_eq!(c.idle_loops, 0);
    assert_eq!(c.cos_queue_lease_acquire_v8_calls, 0);
    assert_eq!(c.cos_queue_lease_acquire_v8_granted_bytes, 0);
}

#[test]
fn window_rotates_after_interval() {
    let atomics = WorkerRuntimeAtomics::new();
    let t0: u64 = 1_000_000_000;
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: 1_000_000_000,
            active_ns: 500_000_000,
            thread_cpu_ns: 450_000_000,
            ..Default::default()
        },
        t0,
    );
    let w0 = atomics.snapshot_window();
    assert_eq!(
        w0.window_ns, 0,
        "first publish only seeds the window base; no completed window yet"
    );

    // Publish 30s later — still inside the first window, so no rotation.
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: 31_000_000_000,
            active_ns: 16_000_000_000,
            thread_cpu_ns: 15_000_000_000,
            ..Default::default()
        },
        t0 + 30 * 1_000_000_000,
    );
    let w_mid = atomics.snapshot_window();
    assert_eq!(w_mid.window_ns, 0);

    // Publish ≥60s after the seed: window rotates with the delta.
    let t_rot = t0 + WR_WINDOW_INTERVAL_NS + 1_000_000_000;
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: 62_000_000_000,
            active_ns: 32_000_000_000,
            thread_cpu_ns: 30_000_000_000,
            ..Default::default()
        },
        t_rot,
    );
    let w = atomics.snapshot_window();
    assert_eq!(w.wall_ns, 62_000_000_000 - 1_000_000_000);
    assert_eq!(w.active_ns, 32_000_000_000 - 500_000_000);
    assert_eq!(w.thread_cpu_ns, 30_000_000_000 - 450_000_000);
    assert_eq!(w.window_ns, t_rot - t0);
}

#[test]
fn snapshot_window_returns_consistent_tuple_after_sequential_publish() {
    // Sequential sanity check: after a completed rotation, the
    // snapshot's invariants hold. This does NOT exercise the
    // concurrent-publication race that the seqlock guards against —
    // see `snapshot_window_never_observes_torn_tuple_under_concurrent_writer`
    // for that.
    let atomics = WorkerRuntimeAtomics::new();
    let t0: u64 = 1_000_000_000;
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: 1_000_000_000,
            active_ns: 500_000_000,
            thread_cpu_ns: 450_000_000,
            ..Default::default()
        },
        t0,
    );
    let t_rot = t0 + WR_WINDOW_INTERVAL_NS + 1_000_000_000;
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: 62_000_000_000,
            active_ns: 32_000_000_000,
            thread_cpu_ns: 30_000_000_000,
            ..Default::default()
        },
        t_rot,
    );
    let w = atomics.snapshot_window();
    if w.window_ns > 0 {
        assert!(
            w.thread_cpu_ns <= w.window_ns,
            "thread_cpu_ns ({}) must be <= window_ns ({}) in a consistent snapshot",
            w.thread_cpu_ns,
            w.window_ns,
        );
        assert!(
            w.active_ns <= w.window_ns,
            "active_ns ({}) must be <= window_ns ({}) in a consistent snapshot",
            w.active_ns,
            w.window_ns,
        );
    } else {
        assert_eq!(w.wall_ns, 0);
        assert_eq!(w.active_ns, 0);
        assert_eq!(w.thread_cpu_ns, 0);
    }
}

#[test]
fn snapshot_window_never_observes_torn_tuple_under_concurrent_writer() {
    // Stress test for the seqlock publication. Writer thread loops
    // publishing rotations as fast as it can (each `now_ns` is far
    // enough past the previous `base_at` to trigger the rotation
    // branch). Reader thread snapshots 100k times and asserts the
    // tuple is internally consistent: `thread_cpu_ns <= window_ns` and
    // `active_ns <= window_ns`.
    //
    // Invariant sensitivity: `now = tick² × WR_WINDOW_INTERVAL_NS` gives
    // monotonically growing window widths: window_ns(N) = (2N-1)×unit.
    // thread_cpu_ns = active_ns = wall_ns = now, so each rotation's
    // delta equals its window_ns exactly. A torn snapshot that pairs
    // thread_cpu_delta from rotation N+1 with window_ns from rotation N
    // gives (2(N+1)-1)×unit vs (2N-1)×unit, tripping the assertion.
    // With the old linear `tick×interval` schema all deltas were a
    // constant 250 ms against a 60 s window — a tear was undetectable.
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let atomics = Arc::new(WorkerRuntimeAtomics::new());
    let stop = Arc::new(AtomicBool::new(false));

    // Seed at tick=1: now = 1²×unit = unit. Sets window_base_at_ns=unit
    // so tick=2 (now=4×unit, delta=3×unit ≥ unit) immediately rotates.
    let unit = WR_WINDOW_INTERVAL_NS;
    atomics.publish(
        &WorkerRuntimeCounters {
            wall_ns: unit,
            active_ns: unit,
            thread_cpu_ns: unit,
            ..Default::default()
        },
        unit,
    );

    let writer_atomics = atomics.clone();
    let writer_stop = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut tick: u64 = 2;
        // now = tick²×unit grows quadratically; every tick triggers a
        // rotation and produces a different window_ns = (2×tick-1)×unit.
        // thread_cpu_ns = wall_ns = active_ns = now so the delta for
        // each rotation exactly equals that rotation's window_ns.
        // A torn pairing (cpu from rotation N+1, window_ns from N) gives
        // cpu_delta = (2N+1)×unit > window_ns = (2N-1)×unit, tripping
        // the reader's invariant check. u64 saturates around tick≈17 000
        // (now≈u64::MAX); on the first saturated publish window_base_at_ns
        // is also set to u64::MAX, so subsequent now-base_at deltas are 0
        // (below WR_WINDOW_INTERVAL_NS) and no further rotations occur.
        // The reader then sees the last valid snapshot indefinitely, which
        // satisfies the invariant and is harmless for the stress test.
        while !writer_stop.load(Ordering::Relaxed) {
            let now = tick.saturating_mul(tick).saturating_mul(unit);
            writer_atomics.publish(
                &WorkerRuntimeCounters {
                    wall_ns: now,
                    active_ns: now,
                    thread_cpu_ns: now,
                    ..Default::default()
                },
                now,
            );
            tick = tick.saturating_add(1);
        }
    });

    // Wait for the writer to publish at least one rotation before counting.
    // Without this guard, OS thread-spawn latency (1-5ms under load) can
    // cause the reader's 100k Relaxed-read loop (<1ms) to finish before
    // the writer publishes its first rotation, making the
    // nonzero_snapshots > 1_000 assertion below false-fail with 0
    // nonzero observations. The seed publish() at t=unit doesn't enter
    // the rotation branch, so window_ns stays 0 until the spawned
    // writer's first publish.
    //
    // Bound the spin so a future writer regression that panics before the
    // first publish() fails the test cleanly via writer.join().unwrap()
    // instead of hanging on the CI runner timeout. 10M iterations is ~1s
    // on a typical x86_64 CPU; the writer normally publishes within a
    // few ms.
    let mut waited: u64 = 0;
    while atomics.snapshot_window().window_ns == 0 {
        waited = waited.saturating_add(1);
        assert!(
            waited < 10_000_000,
            "writer never published first rotation in {} iterations",
            waited,
        );
        assert!(
            !writer.is_finished(),
            "writer thread exited before publishing first rotation",
        );
        std::hint::spin_loop();
    }

    let mut nonzero_snapshots: u64 = 0;
    for _ in 0..100_000 {
        let w = atomics.snapshot_window();
        if w.window_ns > 0 {
            nonzero_snapshots = nonzero_snapshots.saturating_add(1);
            assert!(
                w.thread_cpu_ns <= w.window_ns,
                "torn tuple: thread_cpu_ns={} > window_ns={}",
                w.thread_cpu_ns,
                w.window_ns,
            );
            assert!(
                w.active_ns <= w.window_ns,
                "torn tuple: active_ns={} > window_ns={}",
                w.active_ns,
                w.window_ns,
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();

    // Guard against a broken reader returning all zeros (window_ns=0
    // skips the asserts above): require a non-trivial number of real
    // observations across 100k iterations.
    assert!(
        nonzero_snapshots > 1_000,
        "expected >1000 non-default snapshots in 100k iterations, got {}",
        nonzero_snapshots,
    );
}

#[test]
fn cpu_sample_is_monotonic_or_zero() {
    let a = sample_thread_cpu_ns();
    // busy wait briefly
    let until = std::time::Instant::now() + std::time::Duration::from_millis(5);
    let mut _acc = 0u64;
    while std::time::Instant::now() < until {
        _acc = _acc.wrapping_add(1);
    }
    let b = sample_thread_cpu_ns();
    // Zero is the syscall-failure sentinel; only assert monotonicity
    // when both samples succeeded.
    if a != 0 && b != 0 {
        assert!(b >= a, "thread cpu time must be monotonic: a={a} b={b}");
    }
}
