//! #17123 (R4-Q15-01): the single Unix-socket accept loop.
//!
//! Before this module, the control, session, reinject-submit and
//! reinject-complete sockets each carried a hand-written ~40-line accept
//! loop around `accept_step`. The reinject pair was written as fresh
//! copies in 79558c02f7 with `Err(_) => break`, re-creating the defect
//! 0286b1e339 (#9172) had removed nine days earlier; the #15112 fix
//! (61cfe3a483) pasted `accept_step` plus a bare `catch_unwind` into both,
//! so the copies still disagreed on panic handling: `serve_one_catch_unwind`
//! renders the panic payload, counts `SERVER_HANDLER_PANICS` and caps the
//! log at the first 10, while the reinject copies did none of the three.
//!
//! `run_accept_loop` is now the only loop body. Every socket is described
//! by an [`AcceptLoopSpec`] (name, poll interval, whether unclassified
//! errors are retried, and the peer-label used for the #9003 check), a
//! `running` flag, a [`PanicPolicy`], and a `serve` closure that serves
//! one accepted `UnixStream`. The loop owes three things on every socket:
//! an accept error never kills the loop (#9172), the peer is uid-checked
//! before dispatch (#9003), and a handler panic is contained (#9900
//! F-094). Each is implemented once, here.
//!
//! The policies really do differ, but each difference is one parameter:
//! - The control loop's `Fail` is process-fatal (`return Err(msg)`).
//!   The session and reinject loops must never exit: their `Fail` arm
//!   (unreachable while `retry_unclassified = true`) logs and sleeps
//!   `AcceptBackoff::MAX` so a future `accept_step` change cannot turn
//!   them into a hot loop or a process exit.
//! - Control and session quarantine `ServerState` on a panic
//!   ([`PanicPolicy::QuarantineAndStop`]); reinject has no `ServerState`,
//!   so "drop one connection, keep the loop" (61cfe3a483) is correct for
//!   it ([`PanicPolicy::DropConnection`]).
//! Both panic arms share one payload renderer and the first-10 cap;
//! each counts on its own counter (`SERVER_HANDLER_PANICS` for the
//! quarantine arm, `REINJECT_HANDLER_PANICS` for the drop arm) because
//! the former means "quarantined and shutting down" and the latter
//! means neither.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::server::helpers::{
    reinject_panic_should_log, serve_connection_panic_counted, serve_one_catch_unwind,
    REINJECT_HANDLER_PANICS,
};
use crate::server::ServerState;

/// Tuning for one accept loop. `name` is the socket label used in
/// `accept_step` log lines (e.g. `"control socket"`); `peer_label` is
/// the label passed to `reject_unprivileged_peer` (#9003). The two
/// differ on the reinject sockets (`"reinject submit socket"` for
/// accept logs, `"reinject submit"` for the peer check), so both are
/// carried explicitly.
pub(crate) struct AcceptLoopSpec {
    pub name: &'static str,
    pub poll: Duration,
    pub retry_unclassified: bool,
    pub peer_label: &'static str,
}

/// What to do when a served connection panics.
pub(crate) enum PanicPolicy<'a> {
    /// Control/session: quarantine `ServerState` and stop the daemon for
    /// a supervisor restart (`serve_one_catch_unwind`, #9900 F-094) — the
    /// socket label (`"session"` / `"control"`) keys the per-socket
    /// failure/panic lines inside that helper.
    QuarantineAndStop {
        sock_name: &'static str,
        state: &'a Arc<Mutex<ServerState>>,
    },
    /// Reinject: drop the connection and keep accepting. The loops there
    /// have no `ServerState` to quarantine; 61cfe3a483 established
    /// "a handler panic drops one connection, not the loop" (#15112).
    DropConnection,
}

/// Run one accept loop until `running` is cleared (or, for the control
/// loop, until an unclassified accept error returns `Err`).
///
/// `serve` receives each accepted, peer-checked stream. For
/// `QuarantineAndStop` it must return the handler's `Result` so the
/// existing `"{sock} request failed: {err}"` line is preserved; for
/// `DropConnection` the reinject serve functions return `()`, so callers
/// wrap them in `|| Ok(())` — a serve error there was never logged
/// before either (the reinject handlers close on error internally).
pub(crate) fn run_accept_loop(
    listener: &UnixListener,
    spec: AcceptLoopSpec,
    running: &Arc<AtomicBool>,
    on_panic: PanicPolicy<'_>,
    mut serve: impl FnMut(UnixStream) -> Result<(), String>,
) -> Result<(), String> {
    let mut backoff = super::lifecycle::AcceptBackoff::new();
    while running.load(Ordering::SeqCst) {
        let decision = accept_step(
            listener.accept(),
            spec.poll,
            spec.name,
            &mut backoff,
            Instant::now(),
            spec.retry_unclassified,
        );
        if let Some(line) = decision.log {
            eprintln!("xpf-userspace-dp: {line}");
        }
        match decision.step {
            AcceptStep::Serve((stream, _)) => {
                // #9003: prove the peer before dispatching.
                if let Err(err) =
                    super::lifecycle::reject_unprivileged_peer(spec.peer_label, &stream)
                {
                    eprintln!("xpf-userspace-dp: {err}");
                    continue;
                }
                match &on_panic {
                    PanicPolicy::QuarantineAndStop { sock_name, state } => {
                        serve_one_catch_unwind(sock_name, state, running, || serve(stream));
                    }
                    PanicPolicy::DropConnection => {
                        // Shared with the quarantine arm: payload is
                        // rendered and the log is capped at the first
                        // 10 (#17123). The helper returns Ok on the
                        // non-panic path (serve Ok) and Err(payload) on
                        // a panic; a serve Err cannot occur because the
                        // reinject serve fns return `()` and callers wrap
                        // them in `Ok(())` — they handle errors by
                        // closing the connection, as before #17123.
                        if let Err(payload) = serve_connection_panic_counted(|| serve(stream)) {
                            if reinject_panic_should_log(
                                REINJECT_HANDLER_PANICS.load(Ordering::Relaxed),
                            ) {
                                eprintln!(
                                    "xpf-userspace-dp: {} handler panicked: {payload}; connection dropped, accept loop continues (#15112)",
                                    spec.peer_label
                                );
                            }
                        }
                    }
                }
            }
            AcceptStep::Sleep(delay) => thread::sleep(delay),
            AcceptStep::Fail(msg) => {
                if spec.retry_unclassified {
                    // Session/reinject: never exit. Unreachable today
                    // (retry_unclassified = true makes accept_step retry
                    // every error); kept so a future change to
                    // accept_step cannot turn this into a hot loop or a
                    // process exit from this thread.
                    eprintln!("xpf-userspace-dp: {msg}");
                    thread::sleep(super::lifecycle::AcceptBackoff::MAX);
                } else {
                    // Control: process-fatal, as before #17123.
                    return Err(msg);
                }
            }
        }
    }
    Ok(())
}

pub(crate) use super::lifecycle::{accept_step, AcceptBackoff, AcceptDecision, AcceptStep};

#[cfg(test)]
mod accept_loop_tests_17123 {
    use super::super::helpers::{
        reinject_panic_should_log, serve_connection_panic_counted, REINJECT_HANDLER_PANICS,
    };
    use std::sync::atomic::Ordering;

    /// #17123: a panicking reinject-style handler (DropConnection arm)
    /// increments the counter, its payload is rendered, and at most 10
    /// log lines are produced over 20 panics. This exercises the exact
    /// helper + cap logic the DropConnection arm uses, so the reinject
    /// loops cannot drift back to the bare `catch_unwind` of 61cfe3a483
    /// that lost the payload, the counter and the cap.
    #[test]
    fn drop_connection_panics_are_counted_rendered_and_capped_17123() {
        let before = REINJECT_HANDLER_PANICS.load(Ordering::Relaxed);
        let mut logged = 0usize;
        let mut last_payload = String::new();
        for _ in 0..20 {
            // Mirror the loop arm exactly: the cap decision is the
            // production helper applied to the post-increment counter,
            // not a re-implemented `<= 10` comparison.
            match serve_connection_panic_counted(|| -> Result<(), String> {
                panic!("17123 probe panic")
            }) {
                Ok(()) => panic!("panicking handler must not return Ok"),
                Err(payload) => {
                    last_payload = payload;
                    if reinject_panic_should_log(REINJECT_HANDLER_PANICS.load(Ordering::Relaxed)) {
                        logged += 1;
                    }
                }
            }
        }
        assert_eq!(
            REINJECT_HANDLER_PANICS.load(Ordering::Relaxed),
            before + 20,
            "every panicking reinject connection must be counted"
        );
        assert!(
            last_payload.contains("17123 probe panic"),
            "the panic payload must be rendered, got: {last_payload}"
        );
        assert_eq!(logged, 10, "at most the first 10 panics produce a log line");
    }

    /// Non-panicking handlers pass through and do not count. A handler
    /// `Err` is a serve error, not a panic, and must not be mistaken
    /// for one (DropConnection callers wrap `()`-returning serve fns in
    /// `Ok(())`, so this arm is defensive).
    #[test]
    fn drop_connection_ok_is_not_counted_17123() {
        let before = REINJECT_HANDLER_PANICS.load(Ordering::Relaxed);
        assert_eq!(serve_connection_panic_counted(|| Ok(())), Ok(()));
        assert_eq!(
            REINJECT_HANDLER_PANICS.load(Ordering::Relaxed),
            before,
            "only panics count"
        );
    }

    /// #17123 B2: the cap DECISION is the exact helper the production
    /// DropConnection arm calls. Removing the cap (helper returns
    /// true unconditionally) reds the second assertion; shifting it
    /// reds the first/last.
    #[test]
    fn reinject_panic_cap_admits_first_ten_only_17123() {
        use super::reinject_panic_should_log;
        assert!(reinject_panic_should_log(1), "first panic logs");
        assert!(reinject_panic_should_log(10), "tenth panic logs");
        assert!(!reinject_panic_should_log(11), "eleventh panic is silent");
        assert!(
            !reinject_panic_should_log(u64::MAX),
            "far past cap stays silent"
        );
    }

    /// #17123 fold (Rev18170Opus-2 F1): the production DropConnection
    /// arm must actually CALL `reinject_panic_should_log` — the cells
    /// above only prove the helper and the mirrored loop agree, so
    /// bypassing the callsite (e.g. an inline `<= 10`) would stay
    /// green. Textual bind, following the #9172 wiring-cell shape:
    /// scan accept_loop.rs before its `#[cfg(test)]` module. Patterns
    /// are built at runtime so this test's own text does not match.
    #[test]
    fn production_drop_connection_arm_calls_reinject_panic_should_log_17123() {
        let file = include_str!("accept_loop.rs");
        let prod = match file.find("#[cfg(test)]") {
            Some(i) => &file[..i],
            None => file,
        };
        let call = ["reinject_panic_should_log", "("].concat();
        assert_eq!(
            prod.matches(call.as_str()).count(),
            1,
            "production accept_loop.rs must call reinject_panic_should_log( exactly once (the DropConnection cap decision)"
        );
    }
}
