// Per-connection fault containment + poison-recovering state lock (#9900 F-094).
//
// Two guards, one cold-path module (request path only, never the worker loop):
// - `lock_server_recover`: lock the `ServerState` mutex, recovering and
//   clearing poison instead of wedging every later request on `.expect`.
// - `serve_one_catch_unwind`: serve one accepted connection under
//   `catch_unwind` so a handler panic drops that connection instead of
//   killing the accept loop's thread.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// #9900 F-094: `ServerState` mutex poison recoveries across the request path.
///
/// A panic while a handler holds the state lock poisons it; the next request
/// would wedge on `.expect("server state poisoned")`, and every request after
/// that too. The guarded state still holds the committed prefix of every
/// completed mutation, so recovery keeps using it. Read by tests; like the
/// sibling violation counters it is journald-visible via the capped log line
/// below rather than status-wired (a poison recovery is a bug report, not an
/// operator gauge — there is no healthy nonzero rate to dashboard).
pub(crate) static SERVER_STATE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// #9900 F-094: handler panics contained at the per-connection boundary.
///
/// Each count is one accepted connection whose handler unwound and was
/// dropped while the listener kept serving. Any nonzero value is a bug
/// report against the handler, same as the poison counter above.
pub(crate) static SERVER_HANDLER_PANICS: AtomicU64 = AtomicU64::new(0);

/// Lock the `ServerState` mutex, RECOVERING and clearing poison instead of
/// wedging on it.
///
/// Policy (#9900 F-094, mirrors `afxdp::shared_ops::lock_shared_recover`
/// #2402 and `worker_queue::lock_recover` #1807): a panic that poisoned the
/// mutex already happened and was contained (per-connection, by
/// `serve_one_catch_unwind`). The guarded state still holds the committed
/// prefix of every completed mutation, so the correct recovery is to keep
/// using that data — NOT to fail the request (`.expect`, which wedges every
/// later request on every later connection) or to substitute a fresh state
/// (which would drop the running dataplane's status, snapshot and
/// coordinator). `clear_poison` restores the fast unpoisoned path for
/// subsequent locks so the Poisoned arm stays cold.
///
/// Generic over `T` like `lock_shared_recover`, so the healing property is
/// unit-testable on a `Mutex<u32>` without constructing a `ServerState`.
#[inline]
pub(crate) fn lock_server_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            // First-N cap, mirroring the #9900 F-092 violation logs: a
            // deterministically panicking handler must not flood journald.
            if SERVER_STATE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed) < 10 {
                eprintln!(
                    "xpf-userspace-dp: server state mutex poisoned by a prior handler panic; \
                     recovering guarded state and clearing poison"
                );
            }
            poisoned.into_inner()
        }
    }
}

/// Render a `catch_unwind` payload as an operator-readable string.
///
/// A twin of `afxdp::coordinator::supervisor::panic_payload_message` (#925),
/// which is `pub(super)` there: not widened across modules, and this codebase
/// already duplicates both this shape and the `lock_recover` shape rather
/// than coupling the dataplane supervisor to the control-socket server.
fn server_panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("non-string panic payload")
    }
}

/// Serve one accepted connection with per-connection panic containment.
///
/// Owns nothing: `f` closes over the accepted stream, the state-file path and
/// the cloned `Arc`s. `Ok(())` is silent (success was always silent);
/// `Ok(Err)` logs the pre-existing per-socket failure line verbatim, keyed by
/// `sock_name` (`"session"` / `"control"`); a panic is counted, logged
/// (first-N capped, same policy as the poison log above), and swallowed — the
/// connection drops and the accept loop continues.
///
/// `AssertUnwindSafe` is sound here: the handler takes no `&mut` (all mutation
/// goes through `Arc<Mutex<ServerState>>` and friends), owned values captured
/// by `f` drop during the unwind, and a poisoned state lock is recovered
/// lazily by `lock_server_recover` on the next request.
pub(crate) fn serve_one_catch_unwind(sock_name: &str, f: impl FnOnce() -> Result<(), String>) {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("xpf-userspace-dp: {sock_name} request failed: {err}");
        }
        Err(payload) => {
            let msg = server_panic_payload_message(&payload);
            if SERVER_HANDLER_PANICS.fetch_add(1, Ordering::Relaxed) < 10 {
                eprintln!(
                    "xpf-userspace-dp: {sock_name} handler panicked: {msg}; connection dropped, \
                     listener continues"
                );
            }
        }
    }
}

#[cfg(test)]
mod guards_tests_9900 {
    use super::*;

    /// A poisoned `ServerState`-shaped lock heals: the guarded value survives,
    /// the poison flag clears, and the recovery is counted. Pre-#9900 the
    /// request path locked with `.expect("server state poisoned")`, so this
    /// poison wedged every later request instead.
    #[test]
    fn lock_server_recover_heals_poison_and_counts_9900() {
        let m = Mutex::new(7u32);
        let before = SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed);
        let caught = catch_unwind(AssertUnwindSafe(|| {
            let _guard = m.lock().unwrap();
            panic!("9900 probe panic");
        }));
        assert!(caught.is_err(), "probe must unwind to poison the lock");
        assert!(m.is_poisoned(), "probe must leave the lock poisoned");
        {
            let guard = lock_server_recover(&m);
            assert_eq!(*guard, 7, "recovery keeps the committed value");
        }
        assert!(
            !m.is_poisoned(),
            "recovery clears poison so the next lock takes the fast path"
        );
        assert_eq!(
            SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed),
            before + 1,
            "exactly one recovery counted"
        );
    }

    /// Control: an unpoisoned lock takes the fast path with no count.
    #[test]
    fn lock_server_recover_fast_path_is_silent_9900() {
        let m = Mutex::new(1u32);
        let before = SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed);
        assert_eq!(*lock_server_recover(&m), 1);
        assert_eq!(
            SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed),
            before,
            "healthy locks must not count"
        );
    }

    /// Ok, Err and panicking handlers are all contained: none propagate past
    /// the wrapper, and the panic is counted. Reaching the final assertion IS
    /// the loop-continues property.
    #[test]
    fn serve_one_catch_unwind_contains_all_outcomes_9900() {
        let before = SERVER_HANDLER_PANICS.load(Ordering::Relaxed);
        serve_one_catch_unwind("session", || Ok(()));
        serve_one_catch_unwind("control", || Err("decode boom".to_string()));
        serve_one_catch_unwind("session", || -> Result<(), String> {
            panic!("9900 probe panic")
        });
        assert_eq!(
            SERVER_HANDLER_PANICS.load(Ordering::Relaxed),
            before + 1,
            "exactly the panicking arm counts"
        );
    }
}
