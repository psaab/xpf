// Tests for afxdp/worker_queue.rs (#1807) — poison recovery on the
// per-worker Mutex<VecDeque<WorkerCommand>> command queues. Loaded as a
// sibling submodule via `#[path = "worker_queue_tests.rs"]` from
// worker_queue.rs.

use super::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn export_command(sequence: u64) -> WorkerCommand {
    WorkerCommand::ExportOwnerRGSessions {
        sequence,
        owner_rgs: vec![1],
    }
}

fn export_sequence(command: &WorkerCommand) -> u64 {
    match command {
        WorkerCommand::ExportOwnerRGSessions { sequence, .. } => *sequence,
        other => panic!("unexpected command {other:?}"),
    }
}

/// Poison `m` deterministically: a thread panics while holding the lock
/// and join() observes the panic, so the mutex is poisoned on return.
/// Same shape as the #1790 ha_tests regression.
fn poison(m: &Arc<Mutex<VecDeque<WorkerCommand>>>) {
    let to_poison = m.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(m.is_poisoned(), "mutex must be poisoned");
}

#[test]
fn lock_recover_returns_committed_queue_and_clears_poison() {
    let m = Arc::new(Mutex::new(VecDeque::from([
        export_command(1),
        export_command(2),
    ])));
    poison(&m);
    let before = WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed);

    {
        let guard = lock_recover(&m);
        assert_eq!(
            guard.iter().map(export_sequence).collect::<Vec<_>>(),
            vec![1, 2],
            "recovered guard must expose the committed queue contents"
        );
    }
    // The counter is a process-global shared by every test in the
    // binary, so assert a relative bump rather than an absolute value.
    assert!(
        WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed) > before,
        "recovery must bump the poison-recovery counter"
    );

    // clear_poison verified: a subsequent PLAIN lock() succeeds — the
    // fast unpoisoned path is restored after one recovery.
    assert!(!m.is_poisoned(), "poison must be cleared after recovery");
    let plain = m.lock();
    assert!(plain.is_ok(), "plain lock() must be Ok after recovery");
    assert_eq!(plain.unwrap().len(), 2);
}

#[test]
fn try_lock_recover_preserves_wouldblock_skip_semantics() {
    let m = Mutex::new(VecDeque::from([export_command(7)]));
    let held = m.lock().expect("hold the lock");
    assert!(
        try_lock_recover(&m).is_none(),
        "WouldBlock must still read as None (skip), not a recovery"
    );
    drop(held);
    let guard = try_lock_recover(&m).expect("uncontended try_lock succeeds");
    assert_eq!(guard.len(), 1);
}

#[test]
fn try_lock_recover_recovers_and_clears_poison() {
    let m = Arc::new(Mutex::new(VecDeque::from([export_command(9)])));
    poison(&m);
    let before = WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed);

    {
        let guard = try_lock_recover(&m).expect("poisoned mutex must be recovered, not skipped");
        let sequences = guard.iter().map(export_sequence).collect::<Vec<_>>();
        assert_eq!(sequences, vec![9]);
    }
    assert!(WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed) > before);
    assert!(!m.is_poisoned(), "poison must be cleared after recovery");
    assert!(m.lock().is_ok(), "plain lock() must be Ok after recovery");
}

// Open question 6 from the plan: clear_poison under concurrent recovery.
// Two threads contend on a freshly poisoned mutex and drain it through
// lock_recover. The guards serialize, clear_poison is idempotent, and
// every queued command is processed exactly once (no double-processing,
// no loss).
#[test]
fn concurrent_recovery_processes_each_command_exactly_once() {
    const COMMANDS: u64 = 1000;
    let m = Arc::new(Mutex::new(
        (0..COMMANDS).map(export_command).collect::<VecDeque<_>>(),
    ));
    poison(&m);

    // Start barrier so both threads genuinely contend on the poisoned
    // mutex (Codex review on PR #1822: without it one thread can drain
    // everything before the other starts, proving only the final
    // no-loss/no-dup property, not contention-time behavior).
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let drain = |queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
                 barrier: Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            let mut seen = Vec::new();
            loop {
                let mut guard = lock_recover(&queue);
                match guard.pop_front() {
                    Some(command) => seen.push(export_sequence(&command)),
                    None => break,
                }
                // Drop the guard each iteration (end of scope) so the
                // peer thread can interleave.
            }
            seen
        })
    };
    let a = drain(m.clone(), barrier.clone());
    let b = drain(m.clone(), barrier);
    let seen_a = a.join().expect("drain thread a");
    let seen_b = b.join().expect("drain thread b");

    // #3457: do NOT assert that BOTH threads pop at least one command. The
    // start Barrier guarantees both threads enter `lock_recover` on the
    // poisoned mutex simultaneously (the genuine recovery-time contention PR
    // #1822's review asked for), but it CANNOT guarantee balanced draining:
    // once the first recoverer clears the poison, whichever thread holds the
    // lock may drain the entire queue within a single scheduling quantum,
    // leaving its peer to observe an already-empty queue. Under CPU contention
    // (full test-suite load) that is the COMMON outcome — the prior
    // `!seen_a.is_empty() && !seen_b.is_empty()` assertion failed ~18/20 under
    // load — so an empty peer slice is a scheduler artifact, not a correctness
    // violation. The deterministic poison-recovery contract is exactly-once
    // processing with the poison cleared and the queue drained, asserted below.
    let mut all = seen_a;
    all.extend(seen_b);
    all.sort_unstable();
    assert_eq!(
        all,
        (0..COMMANDS).collect::<Vec<_>>(),
        "every command processed exactly once across both recovering threads"
    );
    assert!(!m.is_poisoned());
    assert!(m.lock().expect("plain lock after race").is_empty());
}

// ---------------------------------------------------------------------------
// #6929: the per-worker command queue capacity bound.
// ---------------------------------------------------------------------------

// A survives-assertion on a capacity is structurally a FLOOR: pushing N items
// and checking they arrive passes identically with no bound at all. Every cell
// below therefore pushes PAST the cap and asserts what happens to the excess.

#[test]
fn worker_queue_6929_refuses_past_the_cap_and_counts_the_drop() {
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    let before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);

    // Fill EXACTLY to the cap: every one of these must be accepted, which is
    // what stops the fix being "refuse everything".
    for i in 0..MAX_PENDING_WORKER_COMMANDS {
        assert!(
            push_bounded(&mut q, export_command(i as u64)),
            "push {i} was refused BELOW the cap of {MAX_PENDING_WORKER_COMMANDS} — the bound \
             is rejecting commands a healthy worker would have drained"
        );
    }
    assert_eq!(q.len(), MAX_PENDING_WORKER_COMMANDS);

    // One past: refused, and COUNTED.
    assert!(
        !push_bounded(&mut q, export_command(9_999)),
        "a push at the cap was ACCEPTED — the queue is unbounded, so a worker that \
         stopped draining grows it until memory is exhausted (#6929)"
    );
    assert_eq!(
        q.len(),
        MAX_PENDING_WORKER_COMMANDS,
        "the refused command was still enqueued"
    );
    let after = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);
    assert!(
        after > before,
        "the drop was not COUNTED ({before} -> {after}). An unbounded queue that starts \
         silently discarding is worse than one that grows: the operator sees neither the \
         memory nor the loss (#6929)"
    );
}

// The retained prefix must stay the OLDEST commands, not the newest.
//
// This is the assertion that distinguishes refuse-newest from evict-oldest, and
// the two are not interchangeable: the queue carries ordered state transitions
// (an UpsertSynced then a DeleteSynced for one key), so evicting from the front
// would apply a delete whose matching upsert was discarded — inverting the
// worker's view of that key rather than merely making it stale.
#[test]
fn worker_queue_6929_refuses_the_newest_not_the_oldest() {
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    for i in 0..MAX_PENDING_WORKER_COMMANDS {
        assert!(push_bounded(&mut q, export_command(i as u64)));
    }
    push_bounded(&mut q, export_command(u64::MAX));

    match q.front() {
        Some(WorkerCommand::ExportOwnerRGSessions { sequence, .. }) => assert_eq!(
            *sequence, 0,
            "the OLDEST command was evicted to make room. Dropping from the front applies a \
             delete whose matching upsert was discarded (#6929)"
        ),
        other => panic!("unexpected front of queue: {other:?}"),
    }
    match q.back() {
        Some(WorkerCommand::ExportOwnerRGSessions { sequence, .. }) => assert_ne!(
            *sequence,
            u64::MAX,
            "the refused command was enqueued at the back anyway"
        ),
        other => panic!("unexpected back of queue: {other:?}"),
    }
}

// The counter must NOT move on an accepted push. Without this, "increment on
// drop" is satisfied by incrementing unconditionally, which would report a
// steady stream of losses on a perfectly healthy dataplane and train the
// operator to ignore the number.
#[test]
fn worker_queue_6929_accepted_pushes_do_not_count_as_drops() {
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    let before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);
    for i in 0..16 {
        assert!(push_bounded(&mut q, export_command(i)));
    }
    assert_eq!(
        WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed),
        before,
        "an accepted push incremented the drop counter"
    );
}

// The drop counter is DISTINCT from the poison-recovery counter. They describe
// opposite outcomes — a poison recovery keeps the committed prefix and loses
// NOTHING, a capacity drop discards a command — and folding them into one
// number would tell an operator that something happened to the queue while
// hiding whether anything was lost.
#[test]
fn worker_queue_6929_drops_are_not_folded_into_poison_recoveries() {
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    for i in 0..MAX_PENDING_WORKER_COMMANDS {
        push_bounded(&mut q, export_command(i as u64));
    }
    let poison_before = WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed);
    let drops_before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);

    push_bounded(&mut q, export_command(1));

    assert!(
        WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed) > drops_before,
        "the capacity drop did not move the drop counter"
    );
    assert_eq!(
        WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed),
        poison_before,
        "a capacity drop moved the POISON-RECOVERY counter — the two describe opposite \
         outcomes (nothing lost vs. a command discarded) and have opposite remediations"
    );
}

// ---------------------------------------------------------------------------
// #6929 wiring guard.
//
// The four cells above exercise `push_bounded` DIRECTLY, so every one of them
// stays green if a producer is reverted to a bare `pending.push_back(..)` —
// they assert a property of the helper, not of the wiring. The bound is only
// worth anything if EVERY producer goes through it, and that is a property of
// the whole afxdp tree rather than of any single call, so it is bound here as
// a source-level agreement instead of 16 separate behavioural fixtures.
//
// Scope: production sources under `src/afxdp`. Test fixtures are excluded on
// purpose — `session_glue/tests.rs` and `newflow_contention_tests.rs` seed a
// queue by hand to drive the CONSUMER, and routing those through the cap would
// change what they exercise. `worker_queue.rs` is excluded because it contains
// the one legitimate `push_back`, inside `push_bounded` itself.

/// Blank out `//` line comments, `/* */` blocks and string-literal bodies.
///
/// Comments are stripped so this guard cannot be satisfied by prose that
/// merely quotes the pattern it forbids — the doc comment on `push_bounded`
/// names `push_back` in exactly that way. String bodies are stripped so a
/// literal containing `//` (a URL, say) cannot silently blind the line scan
/// that follows it. Bytes are replaced by spaces rather than removed so line
/// numbers in a failure message still point at the real source line.
pub(crate) fn blank_comments_and_strings(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = vec![b' '; b.len()];
    let mut i = 0;
    while i < b.len() {
        let keep_nl = |out: &mut Vec<u8>, k: usize| {
            if b[k] == b'\n' {
                out[k] = b'\n';
            }
        };
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                keep_nl(&mut out, i);
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if b[i] == b'r' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            // Raw string: r"..", r#".."#, r##".."##
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                j += 1;
                loop {
                    if j >= b.len() {
                        break;
                    }
                    if b[j] == b'"' && b[j + 1..].iter().take(hashes).all(|c| *c == b'#') {
                        j += 1 + hashes;
                        break;
                    }
                    keep_nl(&mut out, j);
                    j += 1;
                }
                i = j;
            } else {
                out[i] = b[i];
                i += 1;
            }
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                keep_nl(&mut out, i.min(b.len() - 1));
                i += 1;
            }
            i = (i + 1).min(b.len());
        } else {
            out[i] = b[i];
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking preserves utf8 boundaries of ascii syntax")
}

/// The balanced-paren argument text of a call whose `(` is at `open`.
///
/// Walks parens rather than reading to the end of the line, so a push spread
/// over several lines — `ha/state.rs` and `ha/session_import.rs` both have
/// them — is matched exactly like a single-line one.
fn call_argument(src: &str, open: usize) -> &str {
    let b = src.as_bytes();
    let mut depth = 1usize;
    let mut j = open + 1;
    while j < b.len() && depth > 0 {
        match b[j] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    &src[open + 1..j.saturating_sub(1).max(open + 1)]
}

/// Every bare `push_back(..)` in `src` whose argument mentions `WorkerCommand`,
/// as (1-based line, argument text).
fn bare_worker_command_pushes(src: &str) -> Vec<(usize, String)> {
    let cleaned = blank_comments_and_strings(src);
    let mut hits = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = cleaned[from..].find("push_back(") {
        let at = from + rel;
        let open = at + "push_back".len();
        let arg = call_argument(&cleaned, open);
        if arg.contains("WorkerCommand") {
            let line = cleaned[..at].matches('\n').count() + 1;
            hits.push((line, arg.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
        from = open + 1;
    }
    hits
}

pub(crate) fn is_fixture(rel: &str) -> bool {
    rel == "tests.rs"
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_tests.rs")
        || rel.contains("/tests/")
}

pub(crate) fn afxdp_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir under src/afxdp") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            afxdp_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn worker_queue_6929_every_production_producer_routes_through_push_bounded() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp");
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);

    let mut fixtures = 0usize;
    let mut production = 0usize;
    let mut bounded_calls = 0usize;
    let mut bare: Vec<String> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src/afxdp")
            .to_string_lossy()
            .replace('\\', "/");
        if is_fixture(&rel) {
            fixtures += 1;
            continue;
        }
        if rel == "worker_queue.rs" {
            continue;
        }
        production += 1;
        let src = std::fs::read_to_string(path).expect("read source");
        let cleaned = blank_comments_and_strings(&src);
        bounded_calls += cleaned.matches("push_bounded(").count();
        for (line, arg) in bare_worker_command_pushes(&src) {
            bare.push(format!("{rel}:{line}: push_back({arg})"));
        }
    }

    // The absence assertion is only meaningful if the scan actually read the
    // tree, and it would pass vacuously if the fixture exclusion had gone
    // over-broad and swallowed every file. Both populations are asserted so a
    // scan that reached nothing fails instead of reporting a clean tree.
    assert!(
        production >= 200,
        "wiring scan reached only {production} production files under {} — \
         the walk or the fixture exclusion is broken, and an empty scan \
         reports a clean tree",
        root.display()
    );
    assert!(
        fixtures >= 2,
        "fixture exclusion matched {fixtures} files; the hand-seeded consumer \
         fixtures (session_glue/tests.rs, newflow_contention_tests.rs) must be \
         in the excluded set, not in the scanned one"
    );
    assert!(
        bounded_calls >= 12,
        "only {bounded_calls} push_bounded call sites in production afxdp \
         sources; #6929 converted 16 across 8 files, so the scan is not \
         reading the producers it is supposed to be guarding"
    );

    assert!(
        bare.is_empty(),
        "#6929: worker commands must be enqueued through \
         worker_queue::push_bounded, which refuses at \
         MAX_PENDING_WORKER_COMMANDS and counts the drop. A bare push_back \
         reopens the unbounded-growth path for a worker whose consumer has \
         died. Offending sites:\n{}",
        bare.join("\n")
    );
}

#[test]
fn worker_queue_6929_the_wiring_scan_can_actually_see_a_bare_push_back() {
    // The test above asserts an ABSENCE, which a detector that finds nothing
    // satisfies perfectly. This one proves the detector produces the finding
    // it claims is absent, and that neither the comment stripper nor the paren
    // walker is what makes the tree look clean.
    let sample = r#"
        // pending.push_back(WorkerCommand::UpsertLocal(commented_out));
        /* pending.push_back(WorkerCommand::UpsertSynced(block_commented)); */
        let msg = "pending.push_back(WorkerCommand::InAStringLiteral)";
        worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertLocal(ok));
        pending.push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![1],
        });
        other.push_back(unrelated_item);
    "#;

    let hits = bare_worker_command_pushes(sample);
    assert_eq!(
        hits.len(),
        1,
        "detector must find exactly the one real bare push — a comment, a \
         block comment, a string literal, a push_bounded call and an \
         unrelated push_back must all be ignored; got {hits:?}"
    );
    assert!(
        hits[0].1.contains("DemoteOwnerRGS"),
        "detector found the wrong push: {:?}",
        hits[0]
    );
    // The real push spans three lines: a line-oriented scan would miss it.
    assert!(
        hits[0].1.contains("owner_rgs"),
        "argument capture must span lines, so a multi-line push (ha/state.rs, \
         ha/session_import.rs) is not invisible to the guard: {:?}",
        hits[0]
    );
}
