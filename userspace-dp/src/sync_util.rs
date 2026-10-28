//! Crate-level poison-tolerant lock acquisition (#17201, R4-Q51-03).
//!
//! Engineering-style (`docs/engineering-style.md`): a `Mutex`/`RwLock` in
//! production Rust is acquired poison-tolerantly, never with `.unwrap()` /
//! `.expect(..)`, never with `if let Ok(..)` (silently skips the operation)
//! and never with `.lock().map(..).unwrap_or_default()` (substitutes EMPTY
//! state — the #2402 failover bug). One contained panic (the #925 worker
//! supervisor contains it) must not become a panic, a skipped mutation, or
//! an empty table on EVERY later acquisition.
//!
//! Subsystem-specific helpers stay authoritative for their own state and
//! are NOT folded into this module: `worker_queue::lock_recover` (#1807,
//! worker-command queues), `shared_ops::lock_shared_recover` (#2402,
//! shared-session / owner-RG maps), `lock_ha_recover` (HA leaf `Mutex<()>`),
//! and `lock_server_state_recover` (#9900, `ServerState` quarantine). Each
//! stamps its own journald line and counter, so borrowing one for unrelated
//! state would make both the operator message and the counter lie. Those
//! helpers delegate their poison arm to [`lock_tolerant`] / friends where
//! their extra behaviour (counter, log, quarantine, `clear_poison`) allows.
//!
//! This module is the generic default for every other lock: the inline
//! `unwrap_or_else(PoisonError::into_inner)` idiom, named once so reviewers
//! can require it. The uncontended fast path is the same single CAS as
//! `lock()`; the poisoned arm is cold. Recovered state is the committed
//! prefix of everything already written — well-formed for the small state
//! flips these locks guard (check the critical section for panic sites
//! before converting a cross-field-invariant lock, per the style rule).
//!
//! An optional counter hook is available via [`lock_tolerant_counted`] /
//! [`read_tolerant_counted`] / [`write_tolerant_counted`]: pass
//! `Some(&AtomicU64)` to bump a per-subsystem recovery counter on the
//! poisoned arm only (no journald line per acquisition). Pass `None` (the
//! plain helpers) when the subsystem has no counter to stamp.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

/// Lock a `Mutex`, recovering the committed state on poison instead of
/// panicking, skipping, or substituting empty state.
#[inline]
pub(crate) fn lock_tolerant<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    lock_tolerant_counted(m, None)
}

/// [`lock_tolerant`] with an optional poison-recovery counter, bumped only
/// on the poisoned arm.
#[inline]
pub(crate) fn lock_tolerant_counted<'a, T>(
    m: &'a Mutex<T>,
    counter: Option<&AtomicU64>,
) -> MutexGuard<'a, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            if let Some(counter) = counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            poisoned.into_inner()
        }
    }
}

/// Read-lock an `RwLock`, recovering on poison (see [`lock_tolerant`]).
#[inline]
pub(crate) fn read_tolerant<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    read_tolerant_counted(l, None)
}

/// [`read_tolerant`] with an optional poison-recovery counter.
#[inline]
pub(crate) fn read_tolerant_counted<'a, T>(
    l: &'a RwLock<T>,
    counter: Option<&AtomicU64>,
) -> RwLockReadGuard<'a, T> {
    match l.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            if let Some(counter) = counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            poisoned.into_inner()
        }
    }
}

/// Write-lock an `RwLock`, recovering on poison (see [`lock_tolerant`]).
#[inline]
pub(crate) fn write_tolerant<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    write_tolerant_counted(l, None)
}

/// [`write_tolerant`] with an optional poison-recovery counter.
#[inline]
pub(crate) fn write_tolerant_counted<'a, T>(
    l: &'a RwLock<T>,
    counter: Option<&AtomicU64>,
) -> RwLockWriteGuard<'a, T> {
    match l.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            if let Some(counter) = counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            poisoned.into_inner()
        }
    }
}

/// `Condvar::wait_timeout`, recovering the guard on poison instead of
/// panicking. The timeout result is returned unchanged.
#[inline]
pub(crate) fn wait_timeout_tolerant<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    dur: Duration,
) -> (MutexGuard<'a, T>, std::sync::WaitTimeoutResult) {
    match condvar.wait_timeout(guard, dur) {
        Ok(pair) => pair,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// `Condvar::wait_timeout` with an optional poison-recovery counter.
#[inline]
pub(crate) fn wait_timeout_tolerant_counted<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    dur: Duration,
    counter: Option<&AtomicU64>,
) -> (MutexGuard<'a, T>, std::sync::WaitTimeoutResult) {
    match condvar.wait_timeout(guard, dur) {
        Ok(pair) => pair,
        Err(poisoned) => {
            if let Some(counter) = counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod sync_util_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;

    fn poison_mutex(m: &Arc<Mutex<u32>>) {
        let probe = Arc::clone(m);
        let caught = catch_unwind(AssertUnwindSafe(move || {
            let _guard = probe.lock().unwrap();
            panic!("sync_util probe panic");
        }));
        assert!(caught.is_err());
        assert!(m.is_poisoned());
    }

    #[test]
    fn lock_tolerant_recovers_committed_value_17201() {
        let m = Arc::new(Mutex::new(42u32));
        poison_mutex(&m);
        // FAIL-ON-REVERT: `.lock().expect(..)` / `.unwrap()` panics here.
        let mut guard = lock_tolerant(&m);
        assert_eq!(*guard, 42, "committed prefix must survive poison");
        *guard = 43;
        drop(guard);
        assert_eq!(*lock_tolerant(&m), 43);
    }

    #[test]
    fn lock_tolerant_counted_bumps_only_on_poison_17201() {
        let counter = AtomicU64::new(0);
        let m = Arc::new(Mutex::new(1u32));
        drop(lock_tolerant_counted(&m, Some(&counter)));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "fast path must not count"
        );
        poison_mutex(&m);
        drop(lock_tolerant_counted(&m, Some(&counter)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn read_write_tolerant_recover_committed_value_17201() {
        let l = Arc::new(RwLock::new(vec![1u32]));
        {
            let l = Arc::clone(&l);
            let caught = catch_unwind(AssertUnwindSafe(move || {
                let _guard = l.write().unwrap();
                panic!("sync_util rw probe panic");
            }));
            assert!(caught.is_err());
        }
        assert_eq!(*read_tolerant(&l), vec![1]);
        write_tolerant(&l).push(2);
        assert_eq!(*read_tolerant(&l), vec![1, 2]);
    }

    #[test]
    fn wait_timeout_tolerant_recovers_poisoned_guard_17201() {
        let m = Arc::new(Mutex::new(7u32));
        poison_mutex(&m);
        let condvar = Condvar::new();
        let guard = lock_tolerant(&m);
        let (guard, timeout) = wait_timeout_tolerant(&condvar, guard, Duration::from_millis(1));
        assert!(timeout.timed_out());
        assert_eq!(*guard, 7);
    }
}
