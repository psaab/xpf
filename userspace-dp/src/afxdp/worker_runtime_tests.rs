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
    atomics.publish(&c);
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
