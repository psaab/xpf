use super::*;

fn os(errno: i32) -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(errno))
}

fn control(b: &mut AcceptBackoff, r: std::io::Result<()>, at: Instant) -> AcceptDecision<()> {
    accept_step(r, Duration::from_millis(50), "control socket", b, at, false)
}

fn session(b: &mut AcceptBackoff, r: std::io::Result<()>, at: Instant) -> AcceptDecision<()> {
    accept_step(r, Duration::from_millis(10), "session socket", b, at, true)
}

const RESOURCE: [i32; 4] = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
const UNCLASSIFIED: [i32; 7] = [
    libc::EBADF,
    libc::EINVAL,
    libc::ENOTSOCK,
    libc::EACCES,
    libc::EPERM,
    libc::ECONNABORTED,
    libc::EPROTO,
];

#[test]
fn resource_exhaustion_does_not_end_either_accept_loop_9172() {
    // The failure mode: each of these used to reach the control loop's
    // `return Err(..)`, and `main` exits the helper on that Err.
    let t0 = Instant::now();
    for errno in RESOURCE {
        let mut b = AcceptBackoff::new();
        assert!(
            matches!(control(&mut b, os(errno), t0).step, AcceptStep::Sleep(_)),
            "control loop must retry errno {errno}"
        );
        let mut b = AcceptBackoff::new();
        assert!(
            matches!(session(&mut b, os(errno), t0).step, AcceptStep::Sleep(_)),
            "session loop must retry errno {errno}"
        );
    }
}

#[test]
fn the_control_loop_still_fails_on_an_unclassified_error_9172() {
    let t0 = Instant::now();
    for errno in UNCLASSIFIED {
        let mut b = AcceptBackoff::new();
        match control(&mut b, os(errno), t0).step {
            AcceptStep::Fail(msg) => {
                assert!(msg.starts_with("accept on control socket: "), "{msg:?}")
            }
            other => panic!("control loop, errno {errno}: must fail, got {other:?}"),
        }
    }
}

#[test]
fn the_session_loop_never_takes_forwarding_down_9172() {
    // errno does not say where an error came from: an LSM denial can arrive
    // as EINVAL. The session loop has no path to end the process, and
    // exiting would take forwarding down with the HA session socket, so it
    // retries every error -- and says, once, that it is doing so.
    let t0 = Instant::now();
    for errno in UNCLASSIFIED {
        let mut b = AcceptBackoff::new();
        let d = session(&mut b, os(errno), t0);
        assert!(
            matches!(d.step, AcceptStep::Sleep(_)),
            "session loop, errno {errno}: must retry, got {:?}",
            d.step
        );
        let line = d.log.expect("an episode onset writes one line");
        assert!(line.contains("does not exit the helper"), "{line:?}");
    }
}

#[test]
fn nothing_pending_keeps_the_loops_poll_interval_9172() {
    let mut b = AcceptBackoff::new();
    let d = session(
        &mut b,
        Err(std::io::ErrorKind::WouldBlock.into()),
        Instant::now(),
    );
    match d.step {
        // #18541: an idle wait (readiness-woken), not a failure-backoff sleep.
        AcceptStep::Idle(s) => assert_eq!(s, Duration::from_millis(10)),
        other => panic!("WouldBlock must wait idle for a connection, got {other:?}"),
    }
    assert!(d.log.is_none(), "an idle poll writes nothing");
    assert_eq!(b.failures, 0, "an idle poll is not a failure episode");
}

#[test]
fn failures_back_off_to_a_ceiling_and_reset_on_success_9172() {
    let mut b = AcceptBackoff::new();
    let mut at = Instant::now();
    let mut delays = Vec::new();
    for _ in 0..7 {
        match control(&mut b, os(libc::EMFILE), at).step {
            AcceptStep::Sleep(d) => {
                delays.push(d.as_millis());
                at += d;
            }
            other => panic!("EMFILE must be retried, got {other:?}"),
        }
    }
    // Doubling from 50 ms with a 1 s ceiling: a persistent condition costs
    // at most one accept attempt per second, not a spinning core.
    assert_eq!(delays, vec![50, 100, 200, 400, 800, 1000, 1000]);
    let served = control(&mut b, Ok(()), at);
    assert!(matches!(served.step, AcceptStep::Serve(())));
    let line = served
        .log
        .expect("a recovery after failures writes a recovery line");
    assert!(line.contains("recovered after 7 failure(s)"), "{line:?}");
    match control(&mut b, os(libc::EMFILE), at).step {
        AcceptStep::Sleep(d) => {
            assert_eq!(d, AcceptBackoff::INITIAL, "success must reset the episode")
        }
        other => panic!("EMFILE must be retried, got {other:?}"),
    }
}

#[test]
fn a_persistent_resource_failure_never_exits_and_logs_once_9172() {
    // The decision, pinned: no time bound exits the helper, because a bound
    // on "no successful accept" cannot tell a descriptor leak from
    // fluctuating pressure on an idle listener (EMFILE, then EAGAIN once a
    // descriptor frees, with no accept between). Recovering a helper wedged
    // by a real leak is issue 9651. An hour of one-a-second failures stays
    // one episode with one journal line.
    let t0 = Instant::now();
    let mut b = AcceptBackoff::new();
    let mut lines = 0;
    for i in 0..3600u64 {
        let d = control(&mut b, os(libc::EMFILE), t0 + Duration::from_secs(i));
        assert!(
            matches!(d.step, AcceptStep::Sleep(_)),
            "failure {i}: a resource error must never fail the loop"
        );
        lines += d.log.is_some() as usize;
    }
    assert_eq!(
        lines, 1,
        "a persistent failure must not write a line per retry"
    );
}

#[test]
fn a_quiet_gap_between_failures_starts_a_new_episode_9172() {
    let t0 = Instant::now();
    let mut b = AcceptBackoff::new();
    assert!(matches!(
        control(&mut b, os(libc::EMFILE), t0).step,
        AcceptStep::Sleep(_)
    ));
    let d = control(&mut b, os(libc::EMFILE), t0 + Duration::from_secs(600));
    match d.step {
        AcceptStep::Sleep(s) => assert_eq!(s, AcceptBackoff::INITIAL),
        other => panic!("a failure after a quiet gap must start a new episode, got {other:?}"),
    }
    let line = d.log.expect("the new episode writes its onset line");
    assert!(
        line.contains("previous episode of 1 failure(s) ended"),
        "{line:?}"
    );
}

#[test]
fn both_accept_loops_are_wired_through_accept_step_9172() {
    // #17123: both loops are now served by the single accept loop in
    // accept_loop.rs. A TEXTUAL scan, stated as one: it binds that
    // lifecycle.rs carries no `accept()`/`accept_step(` of its own, that
    // accept_loop.rs holds the only production `accept_step(` call, and
    // that run() wires the session (retry) and control (fail) specs.
    // Patterns are built at runtime so this test's own text does not match.
    let file = include_str!("lifecycle.rs");
    let run_sig = ["fn ", "run", "("].concat();
    let start = file.find(run_sig.as_str()).expect("run() not found");
    let end = start + file[start..].find("\n}\n").expect("end of run() not found");
    let src = &file[start..end];
    let bare = [".", "accept", "()"].concat();
    let call = ["accept_step", "("].concat();
    assert_eq!(
        src.matches(bare.as_str()).count(),
        0,
        "run() must not accept() directly after #17123 — the loop lives in accept_loop.rs"
    );
    assert_eq!(
        src.matches(call.as_str()).count(),
        0,
        "run() must not call accept_step directly after #17123"
    );
    // The shared loop itself: exactly one production accept_step call,
    // and it is fed the listener's accept() result.
    let loop_file = include_str!("accept_loop.rs");
    // Strip the test module: its text mentions the patterns under test.
    let prod = match loop_file.find("#[cfg(test)]") {
        Some(i) => &loop_file[..i],
        None => loop_file,
    };
    assert_eq!(
        prod.matches(call.as_str()).count(),
        1,
        "accept_loop.rs must hold the only production accept_step call"
    );
    assert!(
        prod.contains(bare.as_str()),
        "the shared loop must feed accept() into accept_step"
    );
    // run() wires both sockets through run_accept_loop with the right
    // retry policy: session retries unclassified errors, control fails.
    let loop_call = ["run_accept_loop", "("].concat();
    assert_eq!(
        src.matches(loop_call.as_str()).count(),
        2,
        "run() must wire exactly the session and control loops through run_accept_loop"
    );
    assert!(
        src.contains("\"session socket\"") && src.contains("retry_unclassified: true"),
        "session loop must retry unclassified errors"
    );
    assert!(
        src.contains("\"control socket\"") && src.contains("retry_unclassified: false"),
        "control loop must fail on unclassified errors"
    );
}
