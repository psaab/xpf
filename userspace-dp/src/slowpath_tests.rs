use super::*;

/// #2378 fail-on-revert: when conf/all/rp_filter is strict (1) or loose (2),
/// the per-device rp_filter=0 we write on the slow-path TUN is overridden by
/// the kernel's max(all, dev) rule, so reinjected IPv4 packets are dropped.
/// `rp_filter_all_warning` MUST return a warning in that case. If the check
/// is removed (helper always returns None), these assertions fail.
#[test]
fn rp_filter_all_warning_fires_on_strict_and_loose() {
    let strict = rp_filter_all_warning("xpf-usp0", Some(1));
    assert!(strict.is_some(), "all=1 (strict) must warn");
    assert!(strict.unwrap().contains("rp_filter"));

    let loose = rp_filter_all_warning("xpf-usp0", Some(2));
    assert!(loose.is_some(), "all=2 (loose) must warn");
    let msg = loose.unwrap();
    assert!(msg.contains("xpf-usp0"), "warning names the device");
    assert!(msg.contains("=2"), "warning reports the offending value");
}

/// When conf/all/rp_filter is 0 (or unknown/unparsable) the per-device 0 is
/// effective, so the helper must stay quiet — no spurious operator warning.
#[test]
fn rp_filter_all_warning_quiet_when_zero_or_unknown() {
    assert!(
        rp_filter_all_warning("xpf-usp0", Some(0)).is_none(),
        "all=0 must not warn"
    );
    assert!(
        rp_filter_all_warning("xpf-usp0", None).is_none(),
        "unknown all value must not warn"
    );
}

/// The file-reading seam parses the sysctl value and tolerates trailing
/// whitespace; a missing or garbage file yields None (do-not-warn).
#[test]
fn read_all_rp_filter_parses_and_tolerates_missing() {
    let dir = std::env::temp_dir().join(format!("xpf-rpf-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ok = dir.join("all_rp_filter");
    std::fs::write(&ok, "1\n").unwrap();
    assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), Some(1));

    std::fs::write(&ok, "  2  ").unwrap();
    assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), Some(2));

    let missing = dir.join("does-not-exist");
    assert_eq!(read_all_rp_filter(missing.to_str().unwrap()), None);

    std::fs::write(&ok, "garbage").unwrap();
    assert_eq!(read_all_rp_filter(ok.to_str().unwrap()), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #2471 fail-on-revert: when the MTU-programming ioctl FAILS, the slow
/// path must NOT report a bare `active = true`. It must report `degraded`,
/// fall the live MTU back to the kernel default (1500), and record the
/// error. If the failure handling reverts to the buggy unconditional
/// `active.store(true)` with no degraded bit, these assertions fail.
#[test]
fn apply_mtu_status_degrades_on_failure() {
    let status = SharedStatus::new();
    let live = status.apply_mtu_status("xpf-usp0", 9000, |_name, _mtu| {
        Err("SIOCSIFMTU xpf-usp0 mtu=9000: Operation not permitted".to_string())
    });
    // The worker would still flip active=true after this; what proves the
    // bug is fixed is the degraded bit + the live-MTU fallback.
    assert_eq!(live, DEFAULT_TUN_MTU, "failed program falls back to 1500");
    let snap = status.snapshot();
    assert!(
        snap.degraded,
        "MTU program failure must mark the path degraded"
    );
    assert_eq!(
        snap.live_mtu, DEFAULT_TUN_MTU,
        "live MTU reports the 1500 fallback"
    );
    assert!(
        !snap.last_error.is_empty(),
        "the ioctl error must be recorded for the operator"
    );
}

/// On a successful program the path is NOT degraded and the live MTU is the
/// desired (jumbo) MTU, so jumbo reinjection is permitted.
#[test]
fn apply_mtu_status_clean_on_success() {
    let status = SharedStatus::new();
    let live = status.apply_mtu_status("xpf-usp0", 9000, |name, mtu| {
        assert_eq!(name, "xpf-usp0");
        assert_eq!(mtu, 9000);
        Ok(())
    });
    assert_eq!(live, 9000);
    let snap = status.snapshot();
    assert!(!snap.degraded, "a successful program is not degraded");
    assert_eq!(snap.live_mtu, 9000, "live MTU is the desired jumbo MTU");
}

/// #2471 fail-on-revert: a frame larger than the live TUN MTU must be
/// REFUSED at enqueue (counted), not silently passed to the kernel where it
/// would be dropped on TUN egress. With the bug (no live-MTU gate) the
/// jumbo frame would be Accepted; this asserts MtuExceeded + the counters.
#[test]
fn enqueue_refuses_frame_above_live_mtu() {
    let reinjector = SlowPathReinjector::new_without_worker(9000);
    // Simulate a degraded TUN: the worker programmed (or failed to) and the
    // live MTU is the 1500 default. Force that state directly.
    reinjector
        .status
        .live_mtu
        .store(DEFAULT_TUN_MTU as i64, Ordering::Relaxed);
    reinjector.status.degraded.store(true, Ordering::Relaxed);

    // A <=1500 frame is admitted (not MTU-refused).
    let small = reinjector.enqueue(vec![0u8; 1400]).expect("enqueue small");
    assert!(
        matches!(small, EnqueueOutcome::Accepted),
        "a 1400-byte frame is within the live MTU and must be accepted"
    );

    // A jumbo frame above the live MTU is refused with the MTU outcome.
    let jumbo = reinjector.enqueue(vec![0u8; 8000]).expect("enqueue jumbo");
    assert!(
        matches!(jumbo, EnqueueOutcome::MtuExceeded),
        "an 8000-byte frame above the 1500 live MTU must be refused, not silently dropped"
    );
    let snap = reinjector.status();
    assert_eq!(snap.mtu_dropped_packets, 1, "the MTU drop is counted");
    assert!(
        snap.dropped_packets >= 1,
        "MTU drop also rolls into dropped_packets"
    );
    assert!(
        snap.dropped_bytes >= 8000,
        "dropped bytes accumulate the refused frame"
    );
}

/// #5801 fail-on-revert: a day-2 reconcile that raises the MTU must advance the
/// live MTU and clear degraded on a SUCCESSFUL program (the day-2 sibling of
/// `apply_mtu_status_clean_on_success`).
#[test]
fn reprogram_mtu_status_advances_on_success() {
    let status = SharedStatus::new(); // live_mtu starts at the 1500 default
    let live = status.reprogram_mtu_status("xpf-usp0", 9000, |name, mtu| {
        assert_eq!(name, "xpf-usp0");
        assert_eq!(mtu, 9000);
        Ok(())
    });
    assert_eq!(live, 9000, "a successful reconcile installs the desired MTU");
    let snap = status.snapshot();
    assert!(!snap.degraded, "a successful reconcile is not degraded");
    assert_eq!(snap.live_mtu, 9000, "live MTU converges to the new ceiling");
}

/// #5801 fail-on-revert: a FAILED day-2 reconcile must KEEP the current live
/// MTU — unlike the creation-time `apply_mtu_status`, which falls a failure
/// back to the 1500 kernel default because the TUN was just created at 1500. On
/// a reconcile the running TUN already carries its last-programmed MTU, so
/// resetting `live_mtu` to 1500 would wrongly refuse frames the device can
/// still carry. If `reprogram_mtu_status` reverts to the creation-path 1500
/// fallback (or to `apply_mtu_status`), the retained-MTU assertion fails.
#[test]
fn reprogram_mtu_status_keeps_live_on_failure() {
    let status = SharedStatus::new();
    // Simulate a TUN already reconciled up to a 9000 jumbo ceiling.
    status.live_mtu.store(9000, Ordering::Relaxed);
    status.degraded.store(false, Ordering::Relaxed);

    // A later reconcile whose SIOCSIFMTU fails must leave the live MTU at 9000
    // (the running TUN is unchanged), mark degraded, and record the error.
    let live = status.reprogram_mtu_status("xpf-usp0", 4000, |_name, _mtu| {
        Err("SIOCSIFMTU xpf-usp0 mtu=4000: Operation not permitted".to_string())
    });
    assert_eq!(
        live, 9000,
        "a failed reconcile retains the current live MTU, not the 1500 default"
    );
    let snap = status.snapshot();
    assert_eq!(snap.live_mtu, 9000, "live MTU is unchanged on a failed program");
    assert!(snap.degraded, "a failed reconcile marks the path degraded");
    assert!(
        !snap.last_error.is_empty(),
        "the ioctl error is recorded for the operator"
    );
}

/// #5801 fail-on-revert (METHOD): a day-2 reconcile on the PRESERVED reinjector
/// must reprogram its live MTU field AND converge enqueue admission, so a frame
/// between the old (1500) and new (9000) ceiling is no longer MTU-refused. An
/// injected SUCCEEDING programmer stands in for the real `SIOCSIFMTU` (unit
/// tests run without CAP_NET_ADMIN). With the bug (reconcile is a no-op) `mtu()`
/// and `live_mtu` stay at 1500 and the 8000-byte frame stays `MtuExceeded`, so
/// the post-reconcile assertions fail.
#[test]
fn reconcile_mtu_reprograms_live_tun_and_admission() {
    let reinjector =
        SlowPathReinjector::new_without_worker(1500);
    // Force the deterministic 1500 startup state (the worker may not have run,
    // and without CAP_NET_ADMIN its TUN open fails — irrelevant to the MTU
    // admission gate, which is driven entirely by status.live_mtu).
    reinjector
        .status
        .live_mtu
        .store(DEFAULT_TUN_MTU as i64, Ordering::Relaxed);
    reinjector.status.degraded.store(false, Ordering::Relaxed);
    assert_eq!(reinjector.mtu(), 1500, "reinjector starts at the 1500 ceiling");

    // Pre: an 8000-byte frame (between the old 1500 and new 9000 ceiling) is
    // MTU-refused. This return path precedes the tx channel, so it is
    // independent of whether the worker's TUN actually opened.
    let before = reinjector.enqueue(vec![0u8; 8000]).expect("enqueue pre-reconcile");
    assert!(
        matches!(before, EnqueueOutcome::MtuExceeded),
        "an 8000-byte frame must be MTU-refused while the live TUN is 1500"
    );

    // Day-2 reconcile 1500 -> 9000 with a SUCCEEDING injected programmer.
    let live = reinjector.reconcile_mtu(9000, |_name, _mtu| Ok(()));
    assert_eq!(live, 9000, "a successful reconcile installs the desired MTU");
    assert_eq!(
        reinjector.mtu(),
        9000,
        "reconcile updates the reinjector's live mtu() field"
    );
    let snap = reinjector.status();
    assert_eq!(snap.live_mtu, 9000, "live_mtu converges to the new ceiling");
    assert!(!snap.degraded, "a successful reconcile is not degraded");

    // Post: the same 8000-byte frame is NO LONGER MTU-refused. Depending on
    // whether the worker's TUN opened, enqueue now returns Accepted (worker
    // alive) or a worker-not-running Err (the worker could not open the TUN in
    // this environment) — either way it is NOT the MtuExceeded outcome the
    // pre-reconcile 1500 state produced. If the reconcile were a no-op the live
    // MTU would still be 1500 and this WOULD be MtuExceeded.
    let after = reinjector.enqueue(vec![0u8; 8000]);
    assert!(
        !matches!(after, Ok(EnqueueOutcome::MtuExceeded)),
        "after reconcile to 9000 the 8000-byte frame must not be MTU-refused"
    );
}

/// #7820: a worker that cannot open its TUN must make `new` return `Err` with
/// the CAUSE, not `Ok` wrapping a reinjector whose worker has already exited.
///
/// Before the startup handshake, `new` returned `Ok` the instant the thread was
/// spawned. The worker then failed `open_tun`, recorded the reason, cleared
/// `active` and returned — so the caller held a reinjector backed by a dropped
/// receiver, every enqueue reported the downstream symptom "slow-path worker is
/// not running", and the real reason was unreachable in `last_error`. The one
/// production caller (`reconcile/snapshot.rs`) has an `Err` arm that publishes
/// the cause into `last_slow_path_status`; this is what makes it reachable.
///
/// The device name is deliberately longer than IFNAMSIZ (15) so `open_tun`
/// fails on EVERY machine. Relying on the suite being unprivileged would make
/// this pass for an environmental reason and silently stop testing anything on
/// a box with CAP_NET_ADMIN — the class of vacuous green that produced #7820 in
/// the first place.
#[test]
fn new_reports_the_workers_tun_failure_rather_than_a_dead_ok() {
    let too_long = "xpf-usp-name-well-past-ifnamsiz";
    assert!(too_long.len() > 15, "the name must exceed IFNAMSIZ to fail everywhere");

    // `expect_err` would need `Debug` on the reinjector; match instead.
    let err = match SlowPathReinjector::new(too_long, 1500) {
        Ok(_) => panic!(
            "a reinjector whose TUN cannot open must not construct successfully \
             — `new` returned Ok wrapping a worker that has already exited"
        ),
        Err(err) => err,
    };

    assert!(
        !err.is_empty(),
        "the constructor must carry the worker's recorded cause, not an empty string"
    );
    assert!(
        !err.contains("slow-path worker is not running"),
        "the constructor must report the CAUSE, not the downstream enqueue symptom: {err}"
    );
}

#[test]
fn rate_limiter_refills_after_window() {
    // Token-bucket: drain the 1-token budget, then advance the injected
    // clock by a full second so exactly one token re-accrues.
    let mut limiter = RateLimiter::new(1, 128);
    let t0 = Instant::now();
    assert!(limiter.allow_at(t0, 64));
    assert!(!limiter.allow_at(t0, 64));
    assert!(limiter.allow_at(t0 + Duration::from_secs(1), 64));
}

/// #2912 fail-on-revert: the fixed-window limiter admits up to **2x** the
/// configured rate across a window boundary — a sender pacing its first full
/// budget to the last instant of window N and its second full budget to the
/// first instant of window N+1 gets two budgets in an arbitrarily short
/// real interval, because the boundary reset zeroes the counters regardless
/// of how recently the budget was spent.
///
/// This drives the limiter with an INJECTED clock (`allow_at`) so the
/// boundary is exact and deterministic. We spend the whole budget at t0
/// (the end of window N for the fixed window: its window started at t0), then
/// jump the clock to t0 + 1.001s — just past the fixed window's 1s reset
/// threshold but only ~1s of real time — and try to drain a second budget.
///
/// We model the exact straddle attack the issue describes: the fixed window
/// starts at t0. The sender spends its FULL budget at the very END of window
/// N (t0 + 0.999s) and its FULL budget at the very START of window N+1
/// (t0 + 1.001s) — TWO budgets across a 2ms real interval. The total
/// admitted in that 2ms must be at most one budget plus the ~0.02 tokens
/// that refill in 2ms — i.e. one budget — NOT two. The fixed-window bug
/// admits 2*rate here (window N late budget + window N+1 reset budget); the
/// token bucket admits only ~rate because just 2ms of tokens accrued between
/// the two bursts.
///
/// FAIL-ON-REVERT: with the fixed-window `allow_at` reinstated, the count
/// across the 2ms straddle is 2*rate and the `<= rate + slack` assertion goes
/// RED. The token bucket keeps it at rate.
#[test]
fn rate_limiter_no_double_budget_across_boundary() {
    let rate: u64 = 10;
    let mut limiter = RateLimiter::new(rate, 1_000_000);
    let t0 = Instant::now();

    // Warm to steady state: at the END of window N the bucket is full and
    // the fixed window has not yet crossed 1s. Spend the full budget here.
    let late_n = t0 + Duration::from_millis(999);
    let mut burst_end_of_n = 0u64;
    while limiter.allow_at(late_n, 100) {
        burst_end_of_n += 1;
        if burst_end_of_n > rate * 4 {
            break;
        }
    }
    assert_eq!(
        burst_end_of_n, rate,
        "end-of-window-N burst is one full budget"
    );

    // 2ms later we cross into window N+1. The fixed window RESETS and hands
    // out a SECOND full budget; the token bucket has only accrued
    // 2ms * 10/s = 0.02 tokens, so it admits nothing.
    let start_n1 = t0 + Duration::from_millis(1_001);
    let mut burst_start_of_n1 = 0u64;
    while limiter.allow_at(start_n1, 100) {
        burst_start_of_n1 += 1;
        if burst_start_of_n1 > rate * 4 {
            break;
        }
    }
    // Total across the 2ms straddle must not be a second full budget.
    // Allow a 1-packet slack for the sub-token accrual rounding.
    assert!(
        burst_start_of_n1 <= 1,
        "the 2ms boundary straddle must not refill a second budget — only \
             ~0.02 tokens accrue in 2ms; got {burst_start_of_n1} (fixed-window 2x, #2912)"
    );
}

/// #2912 fail-on-revert (the sharp discriminator): with only a SUB-second of
/// real spacing after the budget is drained, the token bucket REFUSES — it
/// has accrued only a fraction of a token. The fixed window admits a full
/// budget the instant its window crosses 1s, with no regard for how recently
/// the budget was spent, which is exactly the 2x-burst defect (two budgets in
/// ~2ms by straddling the boundary).
///
/// We drain the budget at t0, then advance only 100ms (0.1s). At 10 tokens/s
/// that is 1.0 token of refill — right at the edge — so we use 99ms to stay
/// strictly below one token and assert the packet is refused. The token
/// bucket admits 0 here; any window/period scheme that grants a full budget
/// on a boundary fails this assertion.
#[test]
fn rate_limiter_refuses_subsecond_refill_after_drain() {
    let rate: u64 = 10;
    let mut limiter = RateLimiter::new(rate, 1_000_000);
    let t0 = Instant::now();
    for _ in 0..rate {
        assert!(limiter.allow_at(t0, 100));
    }
    // 99ms * 10/s = 0.99 tokens — strictly below 1.
    let t1 = t0 + Duration::from_millis(99);
    assert!(
        !limiter.allow_at(t1, 100),
        "0.99 tokens refilled in 99ms — below one token, must refuse (#2912)"
    );
    // One more millisecond (total 100ms → 1.0 token) admits exactly one.
    let t2 = t0 + Duration::from_millis(100);
    assert!(
        limiter.allow_at(t2, 100),
        "at 100ms exactly one token has refilled — admit one"
    );
    assert!(
        !limiter.allow_at(t2, 100),
        "and only one — the second is refused with no further time"
    );
}

/// The bucket caps at one second of tokens: arbitrarily long idle time does
/// NOT let a sender bank an unbounded burst. After idling for 100s a sender
/// may still only emit the per-second budget at once.
#[test]
fn rate_limiter_bucket_caps_at_one_second() {
    let rate: u64 = 5;
    let mut limiter = RateLimiter::new(rate, 1_000_000);
    let t0 = Instant::now();
    // Drain the initial full bucket.
    for _ in 0..rate {
        assert!(limiter.allow_at(t0, 100));
    }
    assert!(!limiter.allow_at(t0, 100));
    // Idle 100s, then try to drain: only `rate` (not 500) admitted.
    let t1 = t0 + Duration::from_secs(100);
    let mut burst = 0u64;
    while limiter.allow_at(t1, 100) {
        burst += 1;
        if burst > rate * 100 {
            break;
        }
    }
    assert_eq!(
        burst, rate,
        "the bucket caps at one second of tokens — idle cannot bank a larger burst"
    );
}

/// A zero rate admits nothing (defensive: the configured defaults are
/// non-zero, but a 0 rate must never accrue tokens and silently pass).
#[test]
fn rate_limiter_zero_rate_admits_nothing() {
    let mut limiter = RateLimiter::new(0, 0);
    let t0 = Instant::now();
    assert!(!limiter.allow_at(t0, 1), "zero packet rate admits nothing");
    // Even after a long idle the zero-rate bucket stays empty.
    let t1 = t0 + Duration::from_secs(100);
    assert!(!limiter.allow_at(t1, 1), "zero rate never accrues tokens");
}

/// The byte bucket is independent of the packet bucket: a tiny packet rate
/// with a generous byte budget is bounded by packets, and a generous packet
/// rate with a tiny byte budget is bounded by bytes. A refused frame must
/// charge NEITHER bucket (so a too-big frame does not silently drain the
/// packet budget).
#[test]
fn rate_limiter_byte_bucket_is_independent() {
    // 1000 packets/s but only 150 bytes/s: a single 100-byte frame fits,
    // the next does not (200 > 150) until bytes refill.
    let mut limiter = RateLimiter::new(1000, 150);
    let t0 = Instant::now();
    assert!(
        limiter.allow_at(t0, 100),
        "first 100-byte frame fits in 150 byte budget"
    );
    assert!(
        !limiter.allow_at(t0, 100),
        "second 100-byte frame exceeds the 150-byte budget"
    );
    // The refused frame must not have consumed a packet token (still ~999
    // packet tokens) — proven by a tiny frame fitting the leftover bytes.
    assert!(
        limiter.allow_at(t0, 50),
        "a 50-byte frame fits the remaining ~50 byte budget; the refused \
             100-byte frame charged neither bucket"
    );
}

#[test]
fn status_snapshot_reflects_counters() {
    let status = SharedStatus::new();
    status.active.store(true, Ordering::Relaxed);
    status.queued_packets.store(2, Ordering::Relaxed);
    status.injected_packets.store(3, Ordering::Relaxed);
    status.set_mode("io_uring");
    status.set_device_name("xpf-usp0");
    status.set_last_error("none".to_string());
    let snap = status.snapshot();
    assert!(snap.active);
    assert_eq!(snap.queued_packets, 2);
    assert_eq!(snap.injected_packets, 3);
    assert_eq!(snap.mode, "io_uring");
    assert_eq!(snap.device_name, "xpf-usp0");
    assert_eq!(snap.last_error, "none");
}

/// A normal full write succeeds in a single `write()` call (no regression).
#[test]
fn sync_full_write_succeeds_single_call() {
    let len = 100usize;
    let mut calls = 0usize;
    let res = write_packet_atomic(len, |buf_len| {
        calls += 1;
        assert_eq!(buf_len, len, "writer must always be handed the full packet");
        buf_len as isize
    });
    assert!(res.is_ok());
    assert_eq!(calls, 1, "a full write must not loop");
}

/// #2407 fail-on-revert: a short count (0 < n < len) on the packet fd MUST
/// drop the packet (Err) — it must NOT issue a follow-up write of the
/// remaining bytes. The writer is invoked exactly once and always with the
/// FULL length; there is never a `write(bytes[n..])` of length `len - n`.
///
/// If the stream-style remainder loop were restored, the writer would be
/// called a SECOND time with `len - n` to finish the packet — corrupting the
/// TUN. This asserts call count == 1 and that the one call used the full
/// length, so a remainder resubmit fails the test.
#[test]
fn sync_short_write_drops_no_remainder() {
    let len = 100usize;
    let mut observed_lens = Vec::new();
    let res = write_packet_atomic(len, |buf_len| {
        observed_lens.push(buf_len);
        40 // partial: 40 of 100
    });
    let err = res.unwrap_err();
    assert!(
        err.contains("short write on packet fd"),
        "partial packet write must be a drop, got: {err}"
    );
    assert_eq!(
        observed_lens,
        vec![len],
        "a partial write must NOT trigger a remainder write — exactly one \
             full-length write, never a write of bytes[n..]"
    );
}

/// EINTR retries the WHOLE packet (offset 0), never a partial offset.
#[test]
fn sync_eintr_retries_whole_packet() {
    let len = 100usize;
    let mut observed_lens = Vec::new();
    let mut first = true;
    let res = write_packet_atomic(len, |buf_len| {
        observed_lens.push(buf_len);
        if first {
            first = false;
            // Simulate write() returning -1 with errno = EINTR.
            set_errno(libc::EINTR);
            -1
        } else {
            buf_len as isize
        }
    });
    assert!(res.is_ok(), "EINTR must retry, not fail");
    assert_eq!(
        observed_lens,
        vec![len, len],
        "EINTR retry must re-issue the WHOLE packet, never bytes[n..]"
    );
}

/// A zero count is treated as a short write and dropped (no infinite loop).
#[test]
fn sync_zero_write_drops() {
    let res = write_packet_atomic(100, |_| 0);
    assert!(res.unwrap_err().contains("short write on packet fd"));
}

/// A hard error (non-EINTR negative) drops the packet.
#[test]
fn sync_hard_error_drops() {
    let res = write_packet_atomic(100, |_| {
        set_errno(libc::EIO);
        -1
    });
    assert!(res.unwrap_err().contains("slow-path write"));
}

// --- #2438 NON-BLOCKING packet-write helper -----------------------
//
// These cover the WG/GRE local-delivery TUN write paths
// (`write_packet_nonblocking`), whose fds are O_NONBLOCK. The ONE
// behavioural difference from the blocking helper is the
// WouldBlock/EAGAIN arm: it must RETRY the WHOLE packet (backpressure
// on a non-blocking fd is not a fault), never resume `buf[n..]`, and
// never drop the packet outright the way the blocking #2407 helper
// does.

/// A normal full write succeeds in a single `write()` (no regression).
#[test]
fn nb_full_write_succeeds_single_call() {
    let len = 100usize;
    let mut calls = 0usize;
    let res = write_packet_atomic_nonblocking(len, |buf_len| {
        calls += 1;
        assert_eq!(buf_len, len, "writer must always be handed the full packet");
        buf_len as isize
    }, || {});
    assert!(res.is_ok());
    assert_eq!(calls, 1, "a full write must not loop");
}

/// #2438 fail-on-revert (corruption): a SHORT count (0 < n < len) on
/// the non-blocking packet fd MUST drop the packet (Err) and issue
/// EXACTLY ONE write of the FULL length — never a follow-up
/// `write(buf[n..])` of `len - n`. The std `Write::write_all` this
/// replaced loops on `Ok(n)` and re-writes the remainder, injecting it
/// as a second malformed packet (the #2407 corruption class). If that
/// loop is restored, the writer is called a second time with `len - n`
/// and this fails the call-count + observed-length assertion.
#[test]
fn nb_short_write_drops_no_remainder() {
    let len = 100usize;
    let mut observed_lens = Vec::new();
    let res = write_packet_atomic_nonblocking(len, |buf_len| {
        observed_lens.push(buf_len);
        40 // partial: 40 of 100
    }, || {});
    let err = res.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EMSGSIZE),
        "a partial packet write must be a (non-fatal) drop, got: {err}"
    );
    assert_eq!(
        observed_lens,
        vec![len],
        "a partial write must NOT trigger a remainder write — exactly one \
             full-length write, never a write of buf[n..]"
    );
}

/// #2438 fail-on-revert (packet loss): WouldBlock/EAGAIN on the
/// NON-BLOCKING fd is legitimate backpressure — the helper must RETRY
/// the WHOLE packet (offset 0), NOT drop it. The blocking #2407 helper
/// drops on EAGAIN (its fd can never legitimately block); doing that
/// here would lose packets under load, which is the #2438 bug. This
/// asserts the retried write is re-issued at full length and ultimately
/// succeeds. If the EAGAIN arm were changed to drop (the blocking
/// behaviour), the second full-length write never happens and the
/// observed-length vec is `[len]` not `[len, len]`.
#[test]
fn nb_wouldblock_retries_whole_packet() {
    let len = 100usize;
    let mut observed_lens = Vec::new();
    let mut first = true;
    let res = write_packet_atomic_nonblocking(len, |buf_len| {
        observed_lens.push(buf_len);
        if first {
            first = false;
            set_errno(libc::EAGAIN);
            -1
        } else {
            buf_len as isize
        }
    }, || {});
    assert!(res.is_ok(), "WouldBlock must retry, not drop");
    assert_eq!(
        observed_lens,
        vec![len, len],
        "WouldBlock retry must re-issue the WHOLE packet, never buf[n..], \
             and must not drop it"
    );
}

/// EINTR retries the WHOLE packet (offset 0), like the blocking helper.
#[test]
fn nb_eintr_retries_whole_packet() {
    let len = 100usize;
    let mut observed_lens = Vec::new();
    let mut first = true;
    let res = write_packet_atomic_nonblocking(len, |buf_len| {
        observed_lens.push(buf_len);
        if first {
            first = false;
            set_errno(libc::EINTR);
            -1
        } else {
            buf_len as isize
        }
    }, || {});
    assert!(res.is_ok(), "EINTR must retry, not fail");
    assert_eq!(
        observed_lens,
        vec![len, len],
        "EINTR retry re-issues the whole packet"
    );
}

/// A WouldBlock that never clears is bounded: the helper gives up
/// after `NONBLOCK_WOULDBLOCK_RETRY_BUDGET` retries and drops the
/// packet with a non-fatal `ENOBUFS` (so the caller's fatal-errno
/// classifier drops + counts rather than killing the thread). Without
/// the bound this would spin forever. The writer is called
/// budget-plus-one times, always at full length, never a remainder.
#[test]
fn nb_wouldblock_budget_is_bounded_and_drops() {
    let len = 100usize;
    let mut calls = 0u32;
    let mut all_full_len = true;
    let res = write_packet_atomic_nonblocking(len, |buf_len| {
        calls += 1;
        if buf_len != len {
            all_full_len = false;
        }
        set_errno(libc::EAGAIN);
        -1
    }, || {});
    let err = res.unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOBUFS),
        "exhausted WouldBlock budget drops with non-fatal ENOBUFS, got: {err}"
    );
    assert_eq!(
        calls,
        NONBLOCK_WOULDBLOCK_RETRY_BUDGET + 1,
        "the busy-spin must be bounded by the retry budget"
    );
    assert!(all_full_len, "every retry must use the WHOLE packet length");
}

/// A hard error (e.g. EBADF) drops with the underlying errno preserved
/// so the WG/GRE fatal-errno classifier can act on it.
#[test]
fn nb_hard_error_preserves_errno() {
    let res = write_packet_atomic_nonblocking(100, |_| {
        set_errno(libc::EBADF);
        -1
    }, || {});
    assert_eq!(
        res.unwrap_err().raw_os_error(),
        Some(libc::EBADF),
        "hard errno must propagate for fatal-errno classification"
    );
}

/// Set the thread-local errno so the seam can simulate `libc::write`'s
/// errno reporting. `io::Error::last_os_error()` reads this.
fn set_errno(e: libc::c_int) {
    unsafe {
        *libc::__errno_location() = e;
    }
}

/// #2408: `set_if_mtu` rejects a non-positive MTU before touching any
/// device (defensive — the caller sources a clamped value, but a 0/neg
/// MTU must never be programmed). FAILS if the `mtu <= 0` guard is dropped
/// (the call would then open a socket and attempt the ioctl).
#[test]
fn set_if_mtu_rejects_nonpositive() {
    assert!(
        set_if_mtu("xpf-usp0", 0)
            .unwrap_err()
            .contains("invalid MTU")
    );
    assert!(
        set_if_mtu("xpf-usp0", -1)
            .unwrap_err()
            .contains("invalid MTU")
    );
}

/// #2479: the `ioctl_then_close` seam must capture the ioctl's errno
/// BEFORE `close()` runs, so a failing close() cannot clobber the reported
/// error. This is the deterministic fail-on-revert guard for both
/// `set_if_up` (SIOCSIFFLAGS) and `set_if_mtu` (SIOCSIFMTU), which both
/// route their capture-then-close through this seam.
///
/// We make close() FAIL deterministically by handing the seam an invalid
/// fd (`-1`): `close(-1)` returns -1 and sets errno to `EBADF`. The ioctl
/// closure instead leaves a sentinel errno (`ENODEV`). The seam must
/// return the SENTINEL — proving the capture happened before close.
///
/// FAIL-ON-REVERT: if the capture is moved to AFTER `close()` (the #2479
/// bug), `err` carries `EBADF` (close's errno), not `ENODEV`, and this
/// assertion goes RED. The valid-fd path is exercised by the live
/// `set_if_mtu_reports_ioctl_failure` test below.
#[test]
fn ioctl_then_close_captures_errno_before_close() {
    let (rc, err, close_rc) = ioctl_then_close(-1, |_fd| {
        // Simulate a failing ioctl that leaves ENODEV in errno.
        set_errno(libc::ENODEV);
        -1
    });
    assert_eq!(rc, -1, "the simulated ioctl returns failure");
    assert_eq!(close_rc, -1, "close(-1) must fail (EBADF)");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENODEV),
        "seam must report the IOCTL errno (ENODEV), not close()'s EBADF: {err}"
    );
    assert_ne!(
        err.raw_os_error(),
        Some(libc::EBADF),
        "the close()-clobbered errno must NOT leak through: {err}"
    );
}

/// #2479 (live path): a genuine `SIOCSIFMTU` failure surfaces a non-zero
/// ioctl errno, never close()'s success. Targets a nonexistent interface
/// (no NIC/privilege needed — opening an `AF_INET`/`SOCK_DGRAM` socket and
/// issuing a failing ioctl works in the sandbox). The errno varies with
/// privileges (`ENODEV`/`ENXIO` unprivileged, `EPERM` when CAP_NET_ADMIN
/// is checked first), so we assert only the load-bearing property: the
/// message carries a non-zero os-error, not "success (os error 0)".
#[test]
fn set_if_mtu_reports_ioctl_failure() {
    let err =
        set_if_mtu("xpf-nodev-zzz9", 9000).expect_err("ioctl on a nonexistent interface must fail");
    assert!(
        err.contains("SIOCSIFMTU"),
        "error should name the failing ioctl: {err}"
    );
    assert!(
        err.contains("os error") && !err.contains("os error 0"),
        "error must report a non-zero ioctl os-error, not success: {err}"
    );
}

/// #2408: the MTU is written into the `ifru.mtu` arm of the ifreq union
/// that `SIOCSIFMTU` reads. FAILS if the value is not stored (e.g. the
/// assignment is removed) — the union would carry 0, not 9000.
#[test]
fn ifreq_carries_mtu_value() {
    let mut ifr = IfReq::new("xpf-usp0", 0).unwrap();
    ifr.ifru.mtu = 9000;
    // SAFETY: we just wrote the `mtu` arm, so reading it back is defined.
    assert_eq!(unsafe { ifr.ifru.mtu }, 9000);
    assert_eq!(ifr.name_string(), "xpf-usp0");
}

use crate::io_uring_write::WriteResult;
use std::cell::Cell;

/// #2477 fail-on-revert: a PARTIAL io_uring write (`WriteResult::Transferred`)
/// already placed bytes on the packet-oriented TUN. Classification MUST NOT
/// invoke the synchronous write — doing so re-sends the whole frame on top of
/// the truncated one (truncated + duplicate delivery).
///
/// The sync-fallback thunk records whether it ran. With the old behaviour
/// (sync on ANY error), the thunk would fire for this partial and the assertions
/// below fail.
#[test]
fn partial_iouring_write_does_not_sync_fallback() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::Transferred(
            vec![0u8; 1400],
            "slow-path io_uring short write on packet fd: wrote 40 of 1400 bytes".to_string(),
        ),
        |_b| {
            sync_ran.set(true);
            Ok(())
        },
    );
    assert!(
        !sync_ran.get(),
        "a partial io_uring write must NOT sync-retry — re-sending the whole \
             packet on top of the bytes already on the TUN double-transmits (#2477)"
    );
    assert!(
        outcome.result.is_err(),
        "the partial packet must be DROPPED (Err), not silently succeeded"
    );
    assert!(
        !outcome.ring_terminal,
        "a reaped partial is a packet anomaly, not a ring death — keep io_uring"
    );
}

/// #5800: an ambiguous reap where the SQE may still be in flight is now a
/// `Deferred` (the owned buffer is parked in the ring's registry, not handed
/// back) — never sync-retry (the buffer is no longer ours and a re-send could
/// double-transmit).
#[test]
fn ambiguous_reap_error_does_not_sync_fallback() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::Deferred {
            id: 7,
            message: "slow-path io_uring wait interrupted repeatedly (4096 EINTR)".to_string(),
            fatal_ring: false,
        },
        |_b| {
            sync_ran.set(true);
            Ok(())
        },
    );
    assert!(
        !sync_ran.get(),
        "an in-flight-ambiguous (deferred) error must not sync-retry"
    );
    assert!(outcome.result.is_err());
}

/// Complement: a ZERO-byte io_uring failure (`WriteResult::NothingWritten`) put
/// nothing on the TUN, so the synchronous fallback MUST run from the handed-back
/// buffer — the packet is still deliverable and dropping it would be a regression.
#[test]
fn zero_byte_iouring_failure_does_sync_fallback() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::NothingWritten(
            vec![0u8; 64],
            "slow-path io_uring write failed: Input/output error".to_string(),
        ),
        |b| {
            sync_ran.set(true);
            assert_eq!(b.len(), 64, "the handed-back buffer feeds the sync retry");
            Ok(())
        },
    );
    assert!(
        sync_ran.get(),
        "a zero-byte io_uring failure transferred nothing — sync-retry MUST run"
    );
    assert!(
        outcome.result.is_ok(),
        "the sync fallback succeeded, so the result is Ok"
    );
}

/// The happy path: a successful io_uring write never touches the sync path.
#[test]
fn successful_iouring_write_skips_sync_fallback() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(WriteResult::Done(vec![0u8; 4]), |_b| {
        sync_ran.set(true);
        Ok(())
    });
    assert!(
        !sync_ran.get(),
        "a successful io_uring write must not sync-retry"
    );
    assert!(outcome.result.is_ok());
}

// ── #5172: io_uring WriteMode must DEMOTE to SyncFallback after a TERMINAL
// runtime ring failure, so subsequent slow-path packets stop retrying the
// broken ring (which degrades BGP/OSPF/mgmt/local traffic). Mirrors the
// state_writer #2958 runtime-demotion, adding a terminal-vs-transient split. ──

/// #5172 + #5800: `classify_io_uring_write` separates packet-transfer certainty
/// from ring health. A FATAL ring — `WriteResult::Deferred { fatal_ring: true }`,
/// the owned buffer parked in the registry pending teardown — must (a) flag
/// `ring_terminal` so the loop demotes, and (b) DROP the packet WITHOUT invoking
/// the sync fallback (the deferred write may be in flight and the buffer is
/// retained by the ring — re-sending would double-transmit, NO-RETRY).
#[test]
fn classify_terminal_ring_failure_flags_demote_and_does_not_resend() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::Deferred {
            id: 3,
            message: "slow-path io_uring permanent submit/wait error: EBADF".to_string(),
            fatal_ring: true,
        },
        |_b| {
            sync_ran.set(true);
            Ok(())
        },
    );
    assert!(
        outcome.ring_terminal,
        "a fatal io_uring ring failure must be classified TERMINAL so the worker \
         demotes to sync (#5172)"
    );
    assert!(
        !sync_ran.get(),
        "the deferred (in-flight) packet must NOT be sync-resent (no double-transmit)"
    );
    assert!(
        outcome.result.is_err(),
        "the deferred packet is dropped (no-retry), so the result is Err"
    );
    assert!(
        outcome.demotion_cause.is_some(),
        "a terminal failure records a demotion cause for status.last_error"
    );
}

/// #5172 (complement / #2477 preserved): a TRANSIENT io_uring failure —
/// `NothingWritten` — put nothing on the TUN, so the per-call sync fallback
/// rescues THIS packet and the ring is NOT demoted (do not abandon io_uring on a
/// momentary blip). `ring_terminal` must be false.
#[test]
fn classify_transient_ring_failure_keeps_iouring_and_rescues_packet() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::NothingWritten(
            vec![0u8; 128],
            "slow-path io_uring write failed: Input/output error".to_string(),
        ),
        |_b| {
            sync_ran.set(true);
            Ok(())
        },
    );
    assert!(
        !outcome.ring_terminal,
        "a nothing-written io_uring failure is TRANSIENT — keep io_uring, do not demote"
    );
    assert!(
        sync_ran.get(),
        "a transient (nothing-written) failure must sync-rescue the packet (#2477)"
    );
    assert!(outcome.result.is_ok(), "the sync fallback delivered the packet");
    assert!(outcome.demotion_cause.is_none());
}

/// #5800 fail-on-revert: a NON-fatal retry-ceiling deferral drops the packet but
/// KEEPS io_uring — the ring is otherwise healthy and the parked buffer is
/// reclaimed on a later write's reap. `ring_terminal` must be false, the sync
/// fallback must NOT run, and no demotion cause is recorded. Neutralising the
/// `ring_terminal: fatal_ring` line in `classify_io_uring_write` (e.g. hardcoding
/// `true`) would demote on every EINTR storm, turning this RED.
#[test]
fn classify_nonfatal_deferral_keeps_iouring_and_drops_packet() {
    let sync_ran = Cell::new(false);
    let outcome = classify_io_uring_write(
        WriteResult::Deferred {
            id: 9,
            message: "slow-path io_uring wait interrupted repeatedly (4096 EINTR)".to_string(),
            fatal_ring: false,
        },
        |_b| {
            sync_ran.set(true);
            Ok(())
        },
    );
    assert!(
        !outcome.ring_terminal,
        "a bare EINTR-ceiling storm is not a fatal ring — keep io_uring (#5800)"
    );
    assert!(!sync_ran.get(), "a deferred packet is not sync-resent");
    assert!(outcome.result.is_err(), "the deferred packet is dropped");
    assert!(
        outcome.demotion_cause.is_none(),
        "no demotion on a non-fatal deferral"
    );
}

/// #5172: a successful io_uring write is healthy — no demotion, no cause.
#[test]
fn classify_successful_write_is_healthy() {
    let outcome = classify_io_uring_write(WriteResult::Done(vec![0u8; 4]), |_b| Ok(()));
    assert!(!outcome.ring_terminal);
    assert!(outcome.result.is_ok());
    assert!(outcome.demotion_cause.is_none());
}

/// #5172 fail-on-revert: `apply_slowpath_outcome` is the runtime-demotion
/// chokepoint. On a TERMINAL ring failure it MUST demote `WriteMode` to
/// `SyncFallback` so every subsequent packet takes the sync branch (never the
/// broken ring), flip the reported `mode` to "sync", and record the demotion
/// cause. Reverting the `*mode = SyncFallback` assignment in `retire_ring_to_sync`
/// leaves `mode` as `IoUring`, turning the `matches!(mode, SyncFallback)`
/// assertion RED.
#[test]
fn terminal_ring_failure_demotes_write_mode_to_sync() {
    // Production always starts in io_uring when a ring is available; construct
    // that state. If the kernel cannot provide a ring (older CI), the demotion
    // path is unreachable — skip rather than give a false pass (mirrors the
    // state_writer #2958 demotion test).
    let ring = match crate::io_uring_write::RingWriter::new(256) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("io_uring unavailable on this kernel; skipping demotion test");
            return;
        }
    };
    let mut mode = WriteMode::IoUring(ring);
    let status = SharedStatus::new();
    status.set_mode("io_uring");

    // A terminal outcome as `classify_io_uring_write` would produce for a wedged
    // ring: the packet is dropped (Err), the ring is terminal, a cause is set.
    let cause = "slow-path io_uring ring failure, demoting to sync: ring wedged".to_string();
    let outcome = SlowPathWriteOutcome {
        result: Err("slow-path io_uring submit/wait: ring wedged".to_string()),
        ring_terminal: true,
        demotion_cause: Some(cause.clone()),
    };
    apply_slowpath_outcome(outcome, &mut mode, 1400, &status);

    // (a) mode demoted — the core #5172 fix (fail-on-revert anchor).
    assert!(
        matches!(mode, WriteMode::SyncFallback),
        "a terminal io_uring ring failure MUST demote WriteMode to SyncFallback \
         so later packets stop retrying the broken ring (#5172)"
    );
    // (b) reported status flipped to sync, and the drop counters advanced with
    // the demotion cause recorded as last_error.
    let snap = status.snapshot();
    assert_eq!(snap.mode, "sync", "status.mode must report sync after demotion");
    assert_eq!(snap.write_errors, 1, "the dropped ambiguous packet counts a write error");
    assert_eq!(snap.dropped_packets, 1);
    assert_eq!(snap.dropped_bytes, 1400);
    assert_eq!(
        snap.last_error, cause,
        "last_error must record WHY io_uring was retired"
    );

    // (c) the demotion is durable: a following packet takes the SyncFallback
    // branch structurally (the enum can no longer reach the ring). A transient
    // (or successful) outcome on the now-sync mode must NOT resurrect io_uring.
    let ok = SlowPathWriteOutcome {
        result: Ok(()),
        ring_terminal: false,
        demotion_cause: None,
    };
    apply_slowpath_outcome(ok, &mut mode, 100, &status);
    assert!(
        matches!(mode, WriteMode::SyncFallback),
        "mode must stay sync for the worker's lifetime (no flapping / re-promote)"
    );
    assert_eq!(status.snapshot().injected_packets, 1, "the sync write injected");
}

/// #5172 guard: a TRANSIENT outcome must NOT demote — reverting the
/// `ring_terminal` gate to demote on every failure would abandon io_uring on a
/// momentary blip, which this catches (mode must stay IoUring).
#[test]
fn transient_outcome_does_not_demote_write_mode() {
    let ring = match crate::io_uring_write::RingWriter::new(256) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("io_uring unavailable on this kernel; skipping no-demote test");
            return;
        }
    };
    let mut mode = WriteMode::IoUring(ring);
    let status = SharedStatus::new();
    status.set_mode("io_uring");

    // A transient failure that the sync fallback rescued: Ok result, not terminal.
    let outcome = SlowPathWriteOutcome {
        result: Ok(()),
        ring_terminal: false,
        demotion_cause: None,
    };
    apply_slowpath_outcome(outcome, &mut mode, 512, &status);

    assert!(
        matches!(mode, WriteMode::IoUring(_)),
        "a transient (non-terminal) failure must NOT demote — io_uring stays live"
    );
    assert_eq!(
        status.snapshot().mode,
        "io_uring",
        "status.mode must remain io_uring when no terminal failure occurred"
    );
    assert_eq!(status.snapshot().injected_packets, 1);
}

/// #7174 M05: every WouldBlock retry must WAIT for the device, not re-ask
/// immediately.
///
/// The arm used to be a bare `continue`, so a full TUN queue produced up to
/// NONBLOCK_WOULDBLOCK_RETRY_BUDGET back-to-back EAGAIN syscalls before the
/// packet was dropped — a tight spin that burns a core under sustained
/// backpressure, once per dropped packet.
///
/// WHY THIS ASSERTS THE WAIT COUNT RATHER THAN TIMING. The wait is injected as
/// a closure precisely so it is observable: a poll() buried inside the function
/// could not be asked whether it happened, and a timing assertion would be a
/// flake on a loaded box. Counting the injected waits binds the WIRING — remove
/// the `wait_writable()` call and this reds, while every pre-existing
/// WouldBlock test stays green because they only ever asserted the retry count.
#[test]
fn nb_wouldblock_waits_between_retries_7174() {
    let len = 100usize;
    let mut writes = 0usize;
    let mut waits = 0usize;
    // Two EAGAINs, then success.
    let res = write_packet_atomic_nonblocking(
        len,
        |buf_len| {
            writes += 1;
            if writes <= 2 {
                unsafe { *libc::__errno_location() = libc::EAGAIN };
                return -1;
            }
            buf_len as isize
        },
        || waits += 1,
    );
    assert!(res.is_ok(), "the write must succeed once the device drains");
    assert_eq!(writes, 3, "two EAGAINs then one successful write");
    assert_eq!(
        waits, 2,
        "each WouldBlock must be followed by a wait — one per retry. Zero waits \
         means the arm is spinning on the device again (#7174 M05)"
    );
}

/// Control: a write that succeeds first time must NOT wait. Without this, a
/// change that waited unconditionally would satisfy the cell above while adding
/// a poll to every single packet on the fast path.
#[test]
fn nb_successful_write_does_not_wait_7174() {
    let mut waits = 0usize;
    let res = write_packet_atomic_nonblocking(100, |buf_len| buf_len as isize, || waits += 1);
    assert!(res.is_ok());
    assert_eq!(
        waits, 0,
        "a write that never blocked must not poll — waiting unconditionally would \
         put a syscall on every packet"
    );
}

/// And the budget still bounds a genuinely wedged device: persistent EAGAIN
/// must terminate rather than wait forever, with one wait per retry.
#[test]
fn nb_wedged_device_still_terminates_with_bounded_waits_7174() {
    let mut waits = 0usize;
    let res = write_packet_atomic_nonblocking(
        100,
        |_| {
            unsafe { *libc::__errno_location() = libc::EAGAIN };
            -1
        },
        || waits += 1,
    );
    assert!(res.is_err(), "a permanently wedged device must give up, not hang");
    assert!(
        waits as u32 <= NONBLOCK_WOULDBLOCK_RETRY_BUDGET + 1,
        "waits must be bounded by the retry budget — the budget is what stops the \
         wait becoming an unbounded block, which would trade a CPU-burn for a \
         head-of-line stall. got {waits}"
    );
}

// #9637 F3 (GPT-1 form): staggered-start handshake matrix over the
// single-atom outlet outcomes. The load-bearing row is the second block's
// first: a live first outlet plus an initializing second must WAIT — never
// fail construction. The old two-load handshake failed exactly this shape
// (the live worker's io_uring-fallback note skewed the read); with one
// atomic per outlet that skew is unrepresentable — there is no input row
// for "live with a diagnostic", by construction. Genuine failure fast-fails
// without waiting for the sibling; both-pending timeout stays optimistic
// (pre-existing behaviour, not this lane's to change).
#[test]
fn handshake_step_staggered_start_waits_genuine_failure_fails() {
    use HandshakePoll::{Fail, Ready, Wait};
    use OutletInit::{Failed, Live, Starting};
    // Both live: ready.
    assert_eq!(handshake_step(Live, Live, false), Ready);
    // STAGGERED (F3): live + initializing waits, either side; both
    // initializing waits.
    assert_eq!(handshake_step(Live, Starting, false), Wait);
    assert_eq!(handshake_step(Starting, Live, false), Wait);
    assert_eq!(handshake_step(Starting, Starting, false), Wait);
    // GENUINE FAILURE: fast-fails, either outlet, without waiting for the
    // sibling — even against a live sibling.
    assert_eq!(handshake_step(Failed, Starting, false), Fail);
    assert_eq!(handshake_step(Failed, Live, false), Fail);
    assert_eq!(handshake_step(Starting, Failed, false), Fail);
    assert_eq!(handshake_step(Live, Failed, false), Fail);
    // TIMEOUT with anything pending: optimistic ready (pre-existing).
    assert_eq!(handshake_step(Starting, Starting, true), Ready);
    assert_eq!(handshake_step(Live, Starting, true), Ready);
}
