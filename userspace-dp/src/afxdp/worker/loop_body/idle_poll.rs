// #6431: classification of the Interrupt-mode idle-regulation `poll(2)`
// return in the AF_XDP worker loop.
//
// Interrupt poll-mode has exactly ONE backoff: the blocking `poll()` itself,
// with an `INTERRUPT_POLL_TIMEOUT_MS` (1 ms) timeout. Discarding its return
// conflates outcomes that need different handling:
//
//   rc == 0                    timeout — the wait waited          -> resume
//   rc  > 0, POLLIN set        a queue is readable                -> resume
//   rc == -1, EINTR            a signal cut the wait short        -> retry
//   rc == -1, any other errno  the call fails and keeps failing   -> BACK OFF
//   rc  > 0, only error bits   POLLNVAL / POLLERR / POLLHUP       -> BACK OFF
//
// The last two rows are the bug. Both return IMMEDIATELY and keep doing so, so
// the 1 ms floor disappears and the idle path becomes a hot spin on a pinned
// worker core. Measured on this kernel with the production 1 ms timeout: a
// healthy idle poll yields ~950 loops/s; the same loop over a closed fd yields
// ~2.96M loops/s — a ~3120x amplification, held for as long as the condition
// lasts. `Degraded` therefore tells the caller to substitute its own sleep,
// which restores exactly the duty cycle the healthy path has.
//
// `EINTR` deliberately does NOT back off. A signal-interrupted wait is normal
// here — the helper installs a `ctrlc` handler (`server/lifecycle.rs`), and
// `poll(2)` is one of the calls `SA_RESTART` never restarts (signal(7)) — and
// the caller re-enters the blocking poll on its next pass, so the retry costs
// one work scan, not a spin. Treating it as an error would add a sleep to
// ordinary signal delivery; treating it as readiness would busy-loop.

/// What one idle-regulation `poll(2)` return means to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdlePoll {
    /// The wait actually waited — a timeout, or a descriptor became readable.
    /// The caller's idle regulation held; nothing more to do.
    Waited,
    /// `EINTR`. Retry: the caller re-enters the blocking poll next pass.
    Interrupted,
    /// The call returned immediately and will keep returning immediately.
    /// The caller MUST substitute its own backoff or it will spin.
    Degraded,
}

/// Revents bits that report a fault rather than readiness. `poll(2)` sets
/// these in `revents` regardless of `events`, and each is sticky for as long
/// as its cause lasts, so a wake carrying only these bits repeats at syscall
/// rate.
const FAULT_REVENTS: libc::c_short = libc::POLLNVAL | libc::POLLERR | libc::POLLHUP;

/// Classify one `libc::poll` return.
///
/// `rc` is the value the call returned, `errno` the thread's `errno` captured
/// immediately after it (read only when `rc < 0`), and `fds` the descriptor
/// slice the call filled in.
///
/// `#[inline]` because the caller is the worker loop; this is on the idle path
/// (the caller is about to make, or has just made, a syscall), so it is not
/// subject to the per-tick no-call-boundary constraint documented in `mod.rs`,
/// but there is no reason to leave a call behind either.
#[inline]
pub(super) fn classify(rc: libc::c_int, errno: libc::c_int, fds: &[libc::pollfd]) -> IdlePoll {
    if rc < 0 {
        return if errno == libc::EINTR {
            IdlePoll::Interrupted
        } else {
            IdlePoll::Degraded
        };
    }
    if rc == 0 {
        return IdlePoll::Waited;
    }
    // rc > 0: at least one descriptor reported something. It is a genuine wake
    // only if something is actually readable. A revents set carrying nothing
    // but fault bits — or, defensively, nothing at all — is an immediate,
    // repeating return, so it takes the fail-safe `Degraded` arm.
    if fds.iter().any(|pfd| pfd.revents & libc::POLLIN != 0) {
        IdlePoll::Waited
    } else {
        IdlePoll::Degraded
    }
}

/// Render the fault bits a degraded wake reported, for the caller's one-shot
/// log. Returns an empty string when no descriptor carried a fault bit (the
/// `rc < 0` arm, where the errno is the diagnosis).
pub(super) fn fault_summary(fds: &[libc::pollfd]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (idx, pfd) in fds.iter().enumerate() {
        if pfd.revents & FAULT_REVENTS == 0 {
            continue;
        }
        let mut bits: Vec<&str> = Vec::new();
        if pfd.revents & libc::POLLNVAL != 0 {
            bits.push("POLLNVAL");
        }
        if pfd.revents & libc::POLLERR != 0 {
            bits.push("POLLERR");
        }
        if pfd.revents & libc::POLLHUP != 0 {
            bits.push("POLLHUP");
        }
        parts.push(format!("[{}] fd={} {}", idx, pfd.fd, bits.join("|")));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pfd(revents: libc::c_short) -> libc::pollfd {
        libc::pollfd {
            fd: 7,
            events: libc::POLLIN,
            revents,
        }
    }

    #[test]
    fn timeout_is_a_wait_that_waited() {
        assert_eq!(
            classify(0, 0, &[pfd(0)]),
            IdlePoll::Waited,
            "rc==0 is the ordinary 1ms timeout — the idle regulation held, so \
             the caller must NOT add a second sleep on top of it"
        );
    }

    #[test]
    fn readable_descriptor_is_a_wait_that_waited() {
        assert_eq!(
            classify(1, 0, &[pfd(libc::POLLIN)]),
            IdlePoll::Waited,
            "a POLLIN wake is real work arriving — backing off here would add \
             latency to the ACK-sensitive path the interrupt spin exists for"
        );
    }

    #[test]
    fn eintr_is_retried_not_treated_as_error_or_readiness() {
        assert_eq!(
            classify(-1, libc::EINTR, &[pfd(0)]),
            IdlePoll::Interrupted,
            "a signal-interrupted poll must be retried: as Degraded it would \
             sleep on ordinary signal delivery, as Waited it is indistinguishable \
             from a timeout and would be fine here but wrong for any caller that \
             counts completed waits"
        );
        assert_ne!(
            classify(-1, libc::EINTR, &[pfd(0)]),
            IdlePoll::Degraded,
            "EINTR must not take the backoff arm"
        );
    }

    #[test]
    fn hard_errno_is_degraded() {
        for errno in [libc::EINVAL, libc::EFAULT, libc::ENOMEM] {
            assert_eq!(
                classify(-1, errno, &[pfd(0)]),
                IdlePoll::Degraded,
                "errno {errno} makes poll return immediately and keep doing so; \
                 without a substituted backoff the idle path spins at syscall rate"
            );
        }
    }

    #[test]
    fn pollnval_only_is_degraded_not_a_wake() {
        assert_eq!(
            classify(1, 0, &[pfd(libc::POLLNVAL)]),
            IdlePoll::Degraded,
            "a closed fd sets POLLNVAL and returns rc>0 IMMEDIATELY, forever — \
             measured ~2.96M loops/s vs ~950/s healthy. Counting rc>0 as a wake \
             is exactly the unchecked-return bug"
        );
        assert_eq!(classify(1, 0, &[pfd(libc::POLLERR)]), IdlePoll::Degraded);
        assert_eq!(classify(1, 0, &[pfd(libc::POLLHUP)]), IdlePoll::Degraded);
    }

    #[test]
    fn readable_wins_over_a_sibling_fault() {
        assert_eq!(
            classify(2, 0, &[pfd(libc::POLLNVAL), pfd(libc::POLLIN)]),
            IdlePoll::Waited,
            "one bad binding must not make the worker sleep past another \
             binding's pending RX"
        );
    }

    #[test]
    fn fault_on_the_same_fd_as_readable_still_waits() {
        assert_eq!(
            classify(1, 0, &[pfd(libc::POLLIN | libc::POLLHUP)]),
            IdlePoll::Waited,
            "POLLHUP alongside POLLIN means drain the readable data first"
        );
    }

    #[test]
    fn positive_return_with_no_revents_fails_safe() {
        assert_eq!(
            classify(1, 0, &[pfd(0)]),
            IdlePoll::Degraded,
            "rc>0 with nothing set should not happen; if it does it is an \
             immediate return, so the fail-safe arm is the backoff"
        );
    }

    #[test]
    fn errno_is_ignored_on_a_non_negative_return() {
        assert_eq!(
            classify(0, libc::EINTR, &[pfd(0)]),
            IdlePoll::Waited,
            "errno is only meaningful when the call failed; a stale EINTR left \
             in errno by an earlier call must not reclassify a real timeout"
        );
    }

    #[test]
    fn fault_summary_names_the_bits_and_is_empty_when_clean() {
        let s = fault_summary(&[pfd(libc::POLLIN), pfd(libc::POLLNVAL)]);
        assert!(s.contains("POLLNVAL"), "summary must name the bit: {s}");
        assert!(s.contains("[1]"), "summary must name the index: {s}");
        assert!(
            !s.contains("POLLERR"),
            "summary must not report bits that were not set: {s}"
        );
        assert!(
            fault_summary(&[pfd(libc::POLLIN), pfd(0)]).is_empty(),
            "no fault bits must render as empty, so the errno arm's log is not \
             padded with a meaningless revents dump"
        );
    }
}
