// #9169 — the process-global `producer_seq_lock` is the FOURTH #4800
// new-flow contention site, and it had no counter.
//
// Every session delta — Open as well as Close — allocates its wire sequence
// number and encodes its frame inside this mutex. #3878 F-152 requires the
// allocation and the channel enqueue to be atomic together, so the encode is
// INSIDE the critical section, and the mutex lives on `shared`, which makes it
// process-global across every producer thread.
//
// `docs/userspace-newflow-ceiling.md` named three cross-worker sites and not
// this one. That is the expensive shape of gap: a run bound HERE would report a
// new-flows/sec plateau with all three named sites cold, which reads as "the
// firewall is not lock-bound" and sends the next reader elsewhere. (A
// COUNTERFACTUAL, not a result — that harness has never been run, as its own
// status line says; the static bound and the missing counter are what is
// established.) A site with no counter cannot be named, and a model missing a
// site does not report a hole — it reports innocence.
//
// #9169 is an INSTRUMENT, not a remedy. The bound is static and proven; no
// benchmark is offered and none is claimed. So the cells below are about the
// instrument: does it count what it says it counts, does it distinguish
// contended from uncontended, is it actually WIRED into the producer paths
// rather than merely present, and does the number REACH `ProcessStatus`.

use super::*;
use std::sync::atomic::Ordering;

/// THE DENOMINATOR. A session delta must be counted.
///
/// FAIL-ON-REVERT: put `producer_seq_lock.lock()` back at `send_sequenced` and
/// the counter never moves, which the analyzer reads as `ratio: None` —
/// "never taken" — for a mutex every delta passes through.
#[test]
fn every_session_delta_counts_a_producer_seq_acquisition_9169() {
    let (sender, _rx) = EventStreamSender::test_sender(true, 16);
    let handle = sender.worker_handle();
    let zones = rustc_hash::FxHashMap::default();

    let before = sender.stats();
    assert_eq!(
        before.producer_seq_lock_acquisitions, 0,
        "setup: a fresh sender has taken nothing, so a non-zero reading below \
         cannot be a carried-over value",
    );

    // An OPEN delta, deliberately: the issue's point is that this site is on
    // the new-flow path and not only the teardown path.
    handle.push_delta(
        &test_close_delta(crate::session::SessionDeltaKind::Open),
        &zones,
    );
    let after_open = sender.stats();
    assert_eq!(
        after_open.producer_seq_lock_acquisitions, 1,
        "a session OPEN must count an acquisition — Open as well as Close is \
         the whole reason this is a NEW-FLOW site (#9169)",
    );
    assert_eq!(
        after_open.producer_seq_lock_contended, 0,
        "an uncontended acquisition must not be counted as contended, or the \
         ratio the analyzer computes is 1.0 on an idle box",
    );

    handle.push_delta(
        &test_close_delta(crate::session::SessionDeltaKind::Close),
        &zones,
    );
    assert_eq!(
        sender.stats().producer_seq_lock_acquisitions,
        2,
        "a Close counts too — both legs of a connection cross this mutex",
    );
}

/// THE NUMERATOR, and the cell that says the two counters are not the same
/// number under a different name.
///
/// A second thread holds `producer_seq_lock` while a producer pushes a delta.
/// The producer's `try_lock` fails, so the acquisition must be counted BOTH as
/// an acquisition and as contended — the pair is read as `contended /
/// acquisitions`, so a contended increment that skipped the denominator would
/// under-report the site and one that skipped the numerator would report it
/// permanently quiet.
///
/// The uncontended cell above is this one's control: same code path, same
/// counters, and the only difference is whether the mutex was held.
#[test]
fn a_blocked_producer_seq_acquisition_is_counted_contended_9169() {
    use std::sync::mpsc as std_mpsc;

    let (sender, _rx) = EventStreamSender::test_sender(true, 16);
    let handle = sender.worker_handle();
    let shared = Arc::clone(&sender.shared);

    let (holding_tx, holding_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let guard = shared
            .producer_seq_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        holding_tx.send(()).expect("announce the lock is held");
        // Hold until the main thread has committed to blocking on it.
        let _ = release_rx.recv();
        drop(guard);
    });
    holding_rx.recv().expect("holder acquired the lock");

    let (pushed_tx, pushed_rx) = std_mpsc::channel();
    let pusher = std::thread::spawn(move || {
        let zones = rustc_hash::FxHashMap::default();
        handle.push_delta(
            &test_close_delta(crate::session::SessionDeltaKind::Open),
            &zones,
        );
        pushed_tx.send(()).expect("announce the push completed");
    });

    // The push must NOT complete while the lock is held — that is what makes
    // this a contended acquisition rather than a lucky uncontended one.
    assert!(
        pushed_rx
            .recv_timeout(std::time::Duration::from_millis(150))
            .is_err(),
        "the producer must block while producer_seq_lock is held; if it \
         completed, this cell measured an UNCONTENDED acquisition and its \
         verdict below would be about nothing",
    );
    release_tx.send(()).expect("release the holder");
    holder.join().expect("holder thread");
    pushed_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the producer must proceed once the lock is free");
    pusher.join().expect("pusher thread");

    let stats = sender.stats();
    assert_eq!(
        stats.producer_seq_lock_acquisitions, 1,
        "a contended acquisition must still count in the DENOMINATOR — \
         contended/acquisitions is the reported ratio, and a numerator without \
         its denominator is not interpretable (#9169)",
    );
    assert_eq!(
        stats.producer_seq_lock_contended, 1,
        "an acquisition that found the mutex held must be counted contended",
    );
}

/// The LOSSLESS producer path is counted too.
///
/// `push_delta_lossless_within` is what the worker loop calls for every
/// session delta (`session_delta.rs`), so a counter wired only into
/// `send_sequenced` would miss the path that actually carries the new-flow
/// load, and would do so silently — the site would look merely quiet.
#[test]
fn the_lossless_delta_path_counts_its_acquisitions_9169() {
    let (sender, _rx) = EventStreamSender::test_sender(true, 16);
    let handle = sender.worker_handle();
    let zones = rustc_hash::FxHashMap::default();
    handle
        .push_delta_lossless(
            &test_close_delta(crate::session::SessionDeltaKind::Open),
            &zones,
        )
        .expect("connected sender with a live receiver must accept the delta");
    assert_eq!(
        sender.stats().producer_seq_lock_acquisitions,
        1,
        "the lossless path — the one the worker loop uses for every session \
         delta — must be counted, or site 4's denominator misses the load it \
         exists to measure (#9169)",
    );
}

/// THE PUBLISH WIRING. The counted pair must REACH `ProcessStatus` through the
/// real 1 Hz `refresh_status` path.
///
/// The three cells above prove the COUNTERS move. They say nothing about
/// whether anything publishes them, and that is the mutant this campaign has
/// twice watched survive: severing a daemon-side assignment leaves the callee's
/// own cells green because they only ever prove the callee handles what it is
/// GIVEN. So this enters at `refresh_status`, not at `stats()`.
///
/// DISTINCT VALUES, not two ones. The pair is published by two adjacent
/// assignments; equal values would make a swapped or duplicated assignment
/// indistinguishable from a correct one, and 0 is the value a DELETED
/// assignment leaves behind — which is why `contended` is seeded non-zero here
/// even though a real idle box reports 0.
#[test]
fn refresh_status_publishes_the_producer_seq_lock_pair_9169() {
    let (sender, _rx) = EventStreamSender::test_sender(true, 16);
    sender
        .shared
        .producer_seq_lock_acquisitions
        .store(9_169, Ordering::Relaxed);
    sender
        .shared
        .producer_seq_lock_contended
        .store(41, Ordering::Relaxed);

    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.event_stream = Some(sender);
    let mut state = crate::server::state::ServerState {
        status: Default::default(),
        snapshot: None,
        afxdp: coordinator,
        state_writer: Arc::new(crate::state_writer::StateWriter::new()),
        quarantined_after_panic: false,
    };
    assert_eq!(
        state.status.event_stream_producer_seq_lock_acquisitions_total, 0,
        "PROBE-pre: a default ProcessStatus reports nothing, so a non-zero \
         reading below cannot be a pre-existing value",
    );

    crate::server::helpers::status::refresh_status(&mut state);

    assert_eq!(
        state.status.event_stream_producer_seq_lock_acquisitions_total, 9_169,
        "refresh_status must publish the site-4 DENOMINATOR onto ProcessStatus \
         — delete that assignment and every event_stream cell above still \
         passes while the operator surface reports a mutex nobody takes \
         (#9169)",
    );
    assert_eq!(
        state.status.event_stream_producer_seq_lock_contended_total, 41,
        "refresh_status must publish the CONTENDED half too, and not the \
         denominator twice — the analyzer divides one by the other, so a \
         duplicated assignment reports a permanently 100%-contended or \
         permanently quiet site",
    );
}

/// WIRING CENSUS. Every PRODUCER acquisition must go through the counting
/// helper, and the sites that deliberately do not must be exactly the declared
/// set.
///
/// The cells above prove `lock_producer_seq` counts. They say nothing about
/// whether a future producer path takes the raw mutex instead, and that
/// failure is silent in the direction that matters: an uncounted producer
/// makes the site look quieter than it is, which is the same reading as
/// "not the bottleneck".
///
/// So this counts raw `.producer_seq_lock` acquisitions in PRODUCTION source
/// and pins them to the two declared exceptions:
///   - `event_stream/connection.rs`, the I/O thread's #5267 replay-gap
///     FullResync allocation. Not a producer, once per reconnect; counting it
///     would dilute the ratio with the observer.
/// Everything else must be `self.shared.lock_producer_seq()`.
#[test]
fn every_producer_acquisition_goes_through_the_counting_helper_9169() {
    const EVENT_STREAM_MOD: &str = include_str!("../mod.rs");
    const CONNECTION: &str = include_str!("../connection.rs");

    // Strip `//` comment tails and collapse whitespace, so the census counts
    // ACQUISITIONS and not prose — `mod.rs` explains this lock at length, and
    // a text guard that counts its own explanation is measuring the comment.
    // Collapsing whitespace also makes it immune to rustfmt breaking
    // `x.producer_seq_lock\n    .lock()` across lines, which is exactly how
    // the code was written before this change.
    fn acquisitions(src: &str) -> usize {
        let code: String = src
            .lines()
            .map(|line| match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            })
            .collect::<Vec<_>>()
            .join(" ");
        let flat: String = code.split_whitespace().collect::<Vec<_>>().join("");
        flat.matches("producer_seq_lock.lock()").count()
            + flat.matches("producer_seq_lock.try_lock()").count()
    }

    // FIXTURE CONTROL, both directions: the stripper must remove a comment
    // mention and must NOT remove a real acquisition, including one rustfmt
    // has split across lines.
    assert_eq!(acquisitions("// self.producer_seq_lock.lock()"), 0);
    assert_eq!(acquisitions("let g = self.producer_seq_lock.lock();"), 1);
    assert_eq!(
        acquisitions("let g = self\n    .shared\n    .producer_seq_lock\n    .lock();"),
        1,
    );

    // This test file itself takes the raw mutex (the holder thread in the
    // contention cell above), which is why the census reads PRODUCTION source
    // by `include_str!` rather than scanning the tree.
    assert_eq!(
        acquisitions(EVENT_STREAM_MOD),
        2,
        "event_stream/mod.rs must acquire `producer_seq_lock` ONLY inside \
         `lock_producer_seq` — its `try_lock()` fast path and its blocking \
         arm, two acquisitions in one function. A producer that takes the raw \
         mutex is UNCOUNTED, and an uncounted producer makes site 4 look \
         quiet, which reads the same as 'not the bottleneck' (#9169)",
    );
    assert_eq!(
        EVENT_STREAM_MOD
            .matches("self.shared.lock_producer_seq()")
            .count(),
        2,
        "both producer paths — `send_sequenced` and the body of \
         `send_lossless_encoded`'s retry loop — must go through the counting \
         helper",
    );
    assert_eq!(
        acquisitions(CONNECTION),
        1,
        "connection.rs holds exactly ONE declared-uncounted acquisition: the \
         #5267 replay-gap FullResync seq allocation on the I/O thread. It is \
         excluded on purpose — not a producer, once per reconnect, and \
         counting it would dilute the ratio with the observer. A SECOND one \
         here is a new uncounted site and needs a decision, not a default \
         (#9169)",
    );
}
