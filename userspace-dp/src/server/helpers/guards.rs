// Per-connection fault containment + quarantining state lock (#9900 F-094).
//
// Two guards, one cold-path module (request path only, never the worker loop):
// - `lock_server_state_recover`: lock the `ServerState` mutex; on poison,
//   clear it, count it, and QUARANTINE (a poisoned lock proves a handler
//   panicked mid-mutation, and cleared poison repairs nothing).
// - `serve_one_catch_unwind`: serve one accepted connection under
//   `catch_unwind`; on panic, quarantine and initiate shutdown so the
//   supervisor restarts into clean state.
//
// GPT-4 design note — clearing poison is NOT recovery. A panic can unwind
// through multi-step mutations (a moved-out bindings vec dropped by unwind,
// a half-applied snapshot, torn coordinator internals) that no `into_inner`
// can un-tear, and the restore legs in `snapshot.rs`/refresh only run on
// RETURNED errors, never on unwind. So a poisoned lock (or a caught handler
// panic) means the guarded state is SUSPECT: the daemon refuses further
// requests (`quarantined_after_panic`), skips persisting the suspect state,
// shuts down, and exits nonzero so Go's `superviseHelper` restarts it — the
// same crash-restart it already performs for any unexpected helper exit.
// Availability cost: one supervisor restart per handler panic (which has no
// known trigger — the hot-path census was negative). The alternative,
// resuming ordinary requests on torn state, risks silent inconsistency
// (e.g. an emptied bindings vec reporting `enabled` over zero bindings).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::server::ServerState;

/// #9900 F-094: `ServerState` mutex poison recoveries across the request path.
///
/// Every count also sets `quarantined_after_panic` (see below) — the counter
/// exists so the quarantine has a countable cause in status/Prometheus, not
/// as a gauge of anything healthy.
pub(crate) static SERVER_STATE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// #9900 F-094: handler panics contained at the per-connection boundary.
///
/// Each count quarantined the daemon and initiated shutdown; any nonzero
/// value is a bug report against the handler.
pub(crate) static SERVER_HANDLER_PANICS: AtomicU64 = AtomicU64::new(0);

/// Lock the `ServerState` mutex, quarantining on poison instead of wedging
/// or resuming blindly.
///
/// Policy (#9900 F-094 as hardened by GPT-4): a panic that poisoned the mutex
/// already happened and was contained per-connection. The guarded state may
/// be torn mid-mutation, so the ONLY sound recovery is to mark it quarantined
/// (`quarantined_after_panic`, never cleared in-process) and let the request
/// paths refuse + shut down. `clear_poison` restores lockability so the
/// quarantine flag itself remains readable and the shutdown path can still
/// tear down workers.
#[inline]
pub(crate) fn lock_server_state_recover(m: &Mutex<ServerState>) -> MutexGuard<'_, ServerState> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            // First-N cap: a deterministically panicking handler must not
            // flood journald on its way down.
            if SERVER_STATE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed) < 10 {
                eprintln!(
                    "xpf-userspace-dp: server state mutex poisoned by a prior handler panic; \
                     quarantining state and shutting down for a clean restart"
                );
            }
            let mut guard = poisoned.into_inner();
            guard.quarantined_after_panic = true;
            guard
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
/// (first-N capped), quarantines the state, and stops the daemon (`running`
/// cleared FIRST, so shutdown proceeds even if the quarantine lock below
/// blocks behind another thread's in-flight request).
///
/// `AssertUnwindSafe` is sound here: the handler takes no `&mut` (all mutation
/// goes through `Arc<Mutex<ServerState>>` and friends) and owned values
/// captured by `f` drop during the unwind. What it does NOT mean is that the
/// guarded state is intact — hence the quarantine rather than a resume.
pub(crate) fn serve_one_catch_unwind(
    sock_name: &str,
    state: &Arc<Mutex<ServerState>>,
    running: &Arc<AtomicBool>,
    f: impl FnOnce() -> Result<(), String>,
) {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("xpf-userspace-dp: {sock_name} request failed: {err}");
        }
        Err(payload) => {
            let msg = server_panic_payload_message(&payload);
            running.store(false, Ordering::SeqCst);
            if SERVER_HANDLER_PANICS.fetch_add(1, Ordering::Relaxed) < 10 {
                eprintln!(
                    "xpf-userspace-dp: {sock_name} handler panicked: {msg}; quarantining state \
                     and shutting down for a clean restart"
                );
            }
            lock_server_state_recover(state).quarantined_after_panic = true;
        }
    }
}

#[cfg(test)]
mod guards_tests_9900 {
    use super::*;

    fn test_state() -> Arc<Mutex<ServerState>> {
        Arc::new(Mutex::new(ServerState {
            status: crate::protocol::ProcessStatus::default(),
            snapshot: None,
            afxdp: crate::afxdp::Coordinator::new(),
            state_writer: Arc::new(crate::state_writer::StateWriter::new()),
            quarantined_after_panic: false,
        }))
    }

    /// A poisoned state lock recovers the guard AND quarantines: the value
    /// survives (for a readable shutdown), the poison flag clears, the
    /// recovery is counted, and no later request may serve from the state.
    /// Pre-#9900 the request path locked with `.expect`, so this poison
    /// wedged every later request instead.
    #[test]
    fn lock_server_state_recover_heals_and_quarantines_9900() {
        let state = test_state();
        let before = SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed);
        let caught = catch_unwind(AssertUnwindSafe(|| {
            let _guard = state.lock().unwrap();
            panic!("9900 probe panic");
        }));
        assert!(caught.is_err(), "probe must unwind to poison the lock");
        assert!(state.is_poisoned(), "probe must leave the lock poisoned");
        {
            let guard = lock_server_state_recover(&state);
            assert!(
                guard.quarantined_after_panic,
                "recovery must quarantine suspect state"
            );
        }
        assert!(
            !state.is_poisoned(),
            "recovery clears poison so the flag stays readable"
        );
        assert_eq!(
            SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed),
            before + 1,
            "exactly one recovery counted"
        );
    }

    /// Control: an unpoisoned lock takes the fast path with no count and no
    /// quarantine.
    #[test]
    fn lock_server_state_recover_fast_path_is_silent_9900() {
        let state = test_state();
        let before = SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed);
        assert!(!lock_server_state_recover(&state).quarantined_after_panic);
        assert_eq!(
            SERVER_STATE_POISON_RECOVERIES.load(Ordering::Relaxed),
            before,
            "healthy locks must not count"
        );
    }

    /// Ok and Err handlers are contained with no quarantine and no shutdown.
    #[test]
    fn serve_one_catch_unwind_contains_ok_and_err_9900() {
        let state = test_state();
        let running = Arc::new(AtomicBool::new(true));
        let before = SERVER_HANDLER_PANICS.load(Ordering::Relaxed);
        serve_one_catch_unwind("session", &state, &running, || Ok(()));
        serve_one_catch_unwind("control", &state, &running, || {
            Err("decode boom".to_string())
        });
        assert!(running.load(Ordering::SeqCst), "no shutdown without panic");
        assert!(
            !state.lock().unwrap().quarantined_after_panic,
            "no quarantine without panic"
        );
        assert_eq!(
            SERVER_HANDLER_PANICS.load(Ordering::Relaxed),
            before,
            "only panics count"
        );
    }

    /// A panicking handler is contained, counted, quarantines the state, and
    /// stops the daemon for a supervisor restart. Reaching the end IS the
    /// loop-continues property (the loop then observes `running == false`
    /// and tears down rather than serving another request).
    #[test]
    fn serve_one_catch_unwind_panic_quarantines_and_stops_9900() {
        let state = test_state();
        let running = Arc::new(AtomicBool::new(true));
        let before = SERVER_HANDLER_PANICS.load(Ordering::Relaxed);
        serve_one_catch_unwind("session", &state, &running, || -> Result<(), String> {
            panic!("9900 probe panic")
        });
        assert!(
            !running.load(Ordering::SeqCst),
            "a handler panic must stop the daemon"
        );
        assert!(
            state.lock().unwrap().quarantined_after_panic,
            "a handler panic must quarantine the state it may have torn"
        );
        assert_eq!(
            SERVER_HANDLER_PANICS.load(Ordering::Relaxed),
            before + 1,
            "exactly the panicking arm counts"
        );
    }
}
