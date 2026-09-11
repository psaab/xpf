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
/// is_fixture_with answers for one repo-relative path against a scanned set of
/// `#[cfg(test)]` module FILES.
///
/// Keyed on the resolved FILE PATH rather than on the module name, and that is
/// load-bearing: **85 of this tree's 179 `#[path = "..."]` declarations give the
/// module a name that differs from the file stem** — `#[path = "tcp_tests.rs"]
/// mod tests;` is the dominant form. A name-keyed set records `…::tests` while
/// the file is `…/tcp_tests.rs`, so all 85 would be classified as production.
/// The first version of this change did exactly that, and the agreement control
/// below is what caught it.
pub(crate) fn is_fixture_with(
    rel: &str,
    cfg_test_files: &std::collections::HashSet<String>,
) -> bool {
    cfg_test_files.contains(rel)
}

pub(crate) fn is_fixture(root: &std::path::Path, rel: &str) -> bool {
    use std::sync::OnceLock;
    static CFG_TEST: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    // Scanned ONCE, keyed relative to `src`, because the declaration graph is a
    // property of the crate rather than of any caller's subtree.
    let set = CFG_TEST.get_or_init(|| {
        cfg_test_modules(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
    });
    // Callers walk DIFFERENT roots — `src/afxdp` for the worker-queue and
    // forwarding-build canaries, `src/filter` for the filter one — and hand this
    // function a path relative to their own root. The first version ignored that
    // and compared `src`-relative keys against `src/afxdp`-relative paths, so
    // NOTHING matched: the fixture set silently emptied and three canaries began
    // scanning test files as production. They caught it, which is the system
    // working, but the lesson is that a shared predicate taking a relative path
    // must be told what it is relative TO.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root_rel = root
        .strip_prefix(&src)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let key = if root_rel.is_empty() {
        rel.to_string()
    } else {
        format!("{root_rel}/{rel}")
    };
    is_fixture_with(&key, set)
}

pub(crate) fn cfg_test_modules(root: &std::path::Path) -> std::collections::HashSet<String> {
    fn normalise(cand: &std::path::Path, root: &std::path::Path) -> String {
        // Textual `..` folding rather than canonicalize: the files exist, but an
        // absolute canonical path no longer strips against `root`.
        let mut parts: Vec<String> = Vec::new();
        for seg in cand.to_string_lossy().replace('\\', "/").split('/') {
            match seg {
                "." | "" => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s.to_string()),
            }
        }
        let joined = parts.join("/");
        let root_s = root.to_string_lossy().replace('\\', "/");
        let root_s = root_s.trim_start_matches('/').to_string();
        joined
            .strip_prefix(&format!("{root_s}/"))
            .unwrap_or(&joined)
            .to_string()
    }

    // Pass 1 collects every module declaration in the tree, remembering for each
    // OWNING FILE which files it brings in and whether the bringing-in carried
    // #[cfg(test)]. Pass 2 takes the transitive closure, because `#[cfg(test)]`
    // is INHERITED: a plain `mod control_frames;` inside a file that is itself
    // only compiled under test is equally test-only. Without the closure, 36
    // files under directories like `event_stream/tests/` were still classified
    // as production — the third defect this control caught.
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut files = Vec::new();
    afxdp_rs_files(root, &mut files);
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Where this file's `mod` declarations resolve from: for `a/b/mod.rs`
        // that is `a/b`; for `a/b.rs` it is also `a/b`.
        let owner = if path.file_name().is_some_and(|f| f == "mod.rs") {
            match path.parent() {
                Some(p) => p.to_path_buf(),
                None => continue,
            }
        } else {
            path.with_extension("")
        };

        let mut cfg_test = false;
        let mut path_attr: Option<String> = None;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("#[cfg(test)]") {
                cfg_test = true;
                continue;
            }
            if let Some(rest) = t.strip_prefix("#[path = \"") {
                if let Some(end) = rest.find('"') {
                    path_attr = Some(rest[..end].to_string());
                }
                continue;
            }
            // Visibility is stripped generically rather than by listing forms.
            // The first version matched only `mod ` and `pub mod `, and missed
            // `pub(crate) mod tests;` — which is how two files that the filename
            // patterns DID catch came back unresolved. A hand-listed set of
            // spellings is the same shape as the filename predicate this change
            // exists to remove.
            let decl = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub(super) "))
                .or_else(|| t.strip_prefix("pub(in crate) "))
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            if let Some(rest) = decl.strip_prefix("mod ") {
                if cfg_test {
                    let name = rest.split(&[';', ' ', '{'][..]).next().unwrap_or("");
                    // Two different resolution rules, and conflating them was
                    // the second defect the agreement control caught (104 files):
                    //
                    //   `#[path = P] mod x;`  resolves P relative to the
                    //       DIRECTORY CONTAINING this file — `src/nat64.rs`
                    //       with `#[path = "nat64_tests.rs"]` means
                    //       `src/nat64_tests.rs`, not `src/nat64/…`.
                    //   `mod x;`              resolves to `<owner>/x.rs` or
                    //       `<owner>/x/mod.rs`, where owner is the directory
                    //       named after this file.
                    let candidates: Vec<std::path::PathBuf> = match &path_attr {
                        Some(p) => match path.parent() {
                            Some(dir) => vec![dir.join(p)],
                            None => vec![],
                        },
                        None => vec![
                            owner.join(format!("{name}.rs")),
                            owner.join(name).join("mod.rs"),
                        ],
                    };
                    for cand in candidates {
                        out.insert(normalise(&cand, root));
                    }
                } else {
                    // Not test-gated HERE, but may inherit if this owning file
                    // turns out to be test-only. Recorded for pass 2.
                    let name = rest.split(&[';', ' ', '{'][..]).next().unwrap_or("");
                    let candidates: Vec<std::path::PathBuf> = match &path_attr {
                        Some(p) => match path.parent() {
                            Some(dir) => vec![dir.join(p)],
                            None => vec![],
                        },
                        None => vec![
                            owner.join(format!("{name}.rs")),
                            owner.join(name).join("mod.rs"),
                        ],
                    };
                    let from = normalise(&path, root);
                    for cand in candidates {
                        edges.push((from.clone(), normalise(&cand, root)));
                    }
                }
                cfg_test = false;
                path_attr = None;
                continue;
            }
            if !t.is_empty() && !t.starts_with("//") && !t.starts_with("#[") {
                cfg_test = false;
                path_attr = None;
            }
        }
    }

    // Pass 2: fixpoint. Bounded by the edge count, so it terminates even on a
    // cyclic declaration graph — which cannot exist in valid Rust, but a
    // scanner that hangs on malformed input is worse than one that stops early.
    for _ in 0..edges.len().max(1) {
        let mut grew = false;
        for (from, to) in &edges {
            if out.contains(from) && !out.contains(to) {
                out.insert(to.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    out
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
        if is_fixture(&root, &rel) {
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

// ---------------------------------------------------------------------------
// #7201: the bounded prefix drain.
// ---------------------------------------------------------------------------
//
// The defect: `apply_worker_commands` took the WHOLE deque in one
// `core::mem::take` and dispatched every command in one uninterrupted loop,
// never touching its AF_XDP rings until the batch was done. Measured at the
// #6929 cap of 4096 commands that is 3.85 ms of unserviced rings — a LOWER
// bound (the measurement ran at a steering-map fd of `-1`, so the map syscalls
// failed at the fd check without paying the kernel-side insert) — against a
// 4096-slot RX ring that fills in ~1.97 ms at 25 Gbps with 1500 B frames. The
// burst arrives at RG activation, when the node has just become
// forwarding-authoritative.
//
// A survives-assertion is a FLOOR here just as it was for #6929: draining N
// commands and checking they all arrive passes identically with NO budget. Every
// cell below therefore queues PAST the budget and asserts what is left behind.

#[test]
fn worker_queue_7201_drain_takes_the_budget_and_reports_the_remainder() {
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    let mut scratch: VecDeque<WorkerCommand> = VecDeque::new();
    let over = WORKER_COMMAND_DRAIN_BUDGET + 44;
    for i in 0..over {
        assert!(push_bounded(&mut q, export_command(i as u64)));
    }

    let backlogged = drain_bounded_into(&mut q, &mut scratch);
    assert_eq!(
        scratch.len(),
        WORKER_COMMAND_DRAIN_BUDGET,
        "the drain took {} commands instead of the {WORKER_COMMAND_DRAIN_BUDGET}-command \
         budget — an unbounded drain holds the AF_XDP rings for the whole batch",
        scratch.len()
    );
    assert_eq!(
        q.len(),
        44,
        "the remainder must stay in the SHARED queue for the next pass"
    );
    assert!(
        backlogged,
        "a drain that left 44 commands behind reported no backlog — the worker \
         loop reads this to decide whether it may go idle, so a false here parks \
         the rest of an RG-activation burst behind a 1 ms poll(2) each"
    );

    // FIFO, and a contiguous PREFIX: not merely 256 of the 300.
    let taken: Vec<u64> = scratch.iter().map(export_sequence).collect();
    assert_eq!(
        taken,
        (0..WORKER_COMMAND_DRAIN_BUDGET as u64).collect::<Vec<_>>(),
        "the budget must take the FRONT slice in order; reordering or skipping \
         breaks the UpsertSynced-then-DeleteSynced transitions the queue carries"
    );
    let left: Vec<u64> = q.iter().map(export_sequence).collect();
    assert_eq!(
        left,
        (WORKER_COMMAND_DRAIN_BUDGET as u64..over as u64).collect::<Vec<_>>(),
        "the remainder must be the untouched suffix, still in order"
    );

    // Second pass finishes it and clears the backlog signal.
    scratch.clear();
    let backlogged = drain_bounded_into(&mut q, &mut scratch);
    assert_eq!(scratch.len(), 44);
    assert!(
        !backlogged,
        "an emptied queue still reported a backlog — the worker would never go \
         idle, spinning a pinned core forever"
    );
}

#[test]
fn worker_queue_7201_drain_leaves_the_shared_queue_its_allocation() {
    // The allocation half of the finding. `core::mem::take(&mut *pending)`
    // handed the worker the producers' buffer and left the SHARED deque at
    // capacity zero, so the producers — which hold the lock — reallocated it
    // from nothing on every single pass.
    let mut q: VecDeque<WorkerCommand> = VecDeque::new();
    let mut scratch: VecDeque<WorkerCommand> = VecDeque::new();
    for i in 0..WORKER_COMMAND_DRAIN_BUDGET {
        push_bounded(&mut q, export_command(i as u64));
    }
    let grown = q.capacity();
    assert!(grown >= WORKER_COMMAND_DRAIN_BUDGET);

    drain_bounded_into(&mut q, &mut scratch);
    assert!(
        q.is_empty(),
        "precondition: this cell drains the queue completely, so the capacity \
         it then checks is a RETAINED allocation and not merely an unread tail"
    );
    assert!(
        q.capacity() >= grown,
        "the drain shrank the shared queue from {grown} to {} — `mem::take` \
         zeroes it, which is exactly the regrow this replaces",
        q.capacity()
    );
}

#[test]
fn worker_queue_7201_did_work_consumes_the_backlog_signal() {
    // `commands_backlogged` is only worth returning if the worker loop acts on
    // it, and the consumer is a local `did_work` inside a 1500-line function —
    // no unit fixture can reach it, so the wiring is bound as a source-level
    // agreement (the #6929 pattern).
    //
    // WHY THIS MATTERS MORE THAN IT LOOKS. `did_work` is set ONLY by
    // `poll_binding`, i.e. by packet work. Command work does not set it. So a
    // budget WITHOUT this wiring is a REGRESSION, not a partial fix: on a node
    // with no traffic yet — the standby that has just been promoted, which is
    // precisely when the RG-activation burst arrives — `idle_iters` runs past
    // `IDLE_SPIN_ITERS` and every remaining slice waits behind a 1 ms `poll(2)`
    // in Interrupt mode, turning a bounded 3.85 ms stall into ~16 ms of drain.
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/worker/loop_body/mod.rs");
    let src = std::fs::read_to_string(&path).expect("read worker loop_body");
    // Comments blanked so this cannot be satisfied by the prose above the line
    // it is looking for — that comment names `did_work` and `commands_backlogged`
    // in exactly the shape being matched.
    let code = blank_comments_and_strings(&src);
    assert!(
        code.contains("commands_backlogged"),
        "precondition: the guard read a tree with no `commands_backlogged` in \
         it at all, so its agreement check below would pass vacuously"
    );

    let seeds: Vec<&str> = code
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("let mut did_work"))
        .collect();
    assert_eq!(
        seeds.len(),
        1,
        "expected exactly one `did_work` seed to reason about; found {seeds:?}"
    );
    assert_eq!(
        seeds[0], "let mut did_work = commands_backlogged;",
        "the worker loop no longer seeds `did_work` from the command backlog. A \
         `let mut did_work = false;` here reverts #7201 to a pure regression: the \
         budget still splits the batch, but the loop classifies the split passes \
         as IDLE and parks each remaining slice behind a 1 ms poll(2)."
    );

    // The destructure must actually bind the field — a `..` rest pattern would
    // compile, leave `commands_backlogged` unbound, and take the seed line with
    // it, so pinning the seed alone is not enough.
    assert!(
        code.contains("commands_backlogged,\n        } = command_results;")
            || code.contains("commands_backlogged,\n    } = command_results;"),
        "`commands_backlogged` must be destructured out of WorkerCommandResults \
         at the call site, not dropped by a `..` rest pattern"
    );
}

/// #8325: the `#[cfg(test)]`-derived predicate must AGREE with the filename
/// patterns it replaces, on every file in the tree.
///
/// This is the control that makes the change safe to land. A derived predicate
/// that quietly classified a PRODUCTION file as a fixture would weaken every
/// canary built on it — silently, and in the direction where a canary stops
/// looking at code rather than starting to look at the wrong code. Nothing else
/// in the suite would notice: each canary is a content match against an expected
/// set, so a shrunken population simply finds fewer things and still passes.
///
/// So the two are run side by side over the whole tree and every disagreement is
/// reported with its path. The old patterns are reproduced here verbatim rather
/// than referenced, because the point is to compare against what the tree used
/// to believe, and a shared helper would make both sides move together.
#[test]
fn cfg_test_derived_fixture_predicate_agrees_with_the_filename_patterns_8325() {
    fn legacy(rel: &str) -> bool {
        rel == "tests.rs"
            || rel.ends_with("/tests.rs")
            || rel.ends_with("_tests.rs")
            || rel.contains("/tests/")
            || rel.starts_with("tests_")
            || rel.contains("/tests_")
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let cfg_test = cfg_test_modules(&src);
    let mut files = Vec::new();
    afxdp_rs_files(&src, &mut files);

    // Positive control on the scan itself. An empty declaration set would make
    // the derived predicate answer `false` for everything, which reads as "no
    // fixtures exist" and would fail below as a wall of disagreements rather
    // than as the scanner defect it actually is.
    assert!(
        cfg_test.len() > 20,
        "the #[cfg(test)] scan found only {} module declarations, which cannot be \
         right for this tree — the scan is broken and every verdict below would \
         be about the scanner rather than about the predicate",
        cfg_test.len()
    );
    assert!(
        files.len() > 100,
        "the file walk found only {} .rs files under src/",
        files.len()
    );

    let mut only_legacy = Vec::new();
    let mut only_derived = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let l = legacy(&rel);
        let d = is_fixture_with(&rel, &cfg_test);
        if l && !d {
            only_legacy.push(rel);
        } else if d && !l {
            only_derived.push(rel);
        }
    }

    // BOTH directions are reported before failing. The first version asserted
    // them in sequence, so the second assert never ran while the first was red —
    // and the two disagreements have completely different diagnoses. A test that
    // can only ever show you one half of a comparison is not a comparison.
    // ONLY_LEGACY is the safety property and it must be EMPTY. A file the
    // filename patterns skipped but the derived rule does not resolve would be
    // reclassified as PRODUCTION — the direction that adds files to a canary's
    // population, which is loud rather than silent, but still a change nobody
    // asked for.
    //
    // ONLY_DERIVED is the IMPROVEMENT, not a failure: files the patterns missed.
    // It is asserted against a floor so a broken scan cannot silently shrink it
    // back to the old behaviour, and reported by name so growth is visible.
    const KNOWN_MISSED_BY_FILENAME: usize = 18;
    assert!(
        only_derived.len() >= KNOWN_MISSED_BY_FILENAME,
        "#8325: the derived predicate now finds only {} test files that the \
         filename patterns miss, against {} when this landed. The scan has \
         regressed — files are being classified as PRODUCTION again. Do not \
         lower this number to make the test pass; find what the scan stopped \
         resolving.",
        only_derived.len(),
        KNOWN_MISSED_BY_FILENAME
    );

    let mut report = String::new();
    if !only_legacy.is_empty() {
        report.push_str(&format!(
            "\n{} file(s) match a filename pattern but do not resolve from a \
             #[cfg(test)] declaration. Either the declaration is missing the attribute \
             — in which case the file IS production and the old predicate was wrong to \
             skip it — or the scan failed to resolve it, most likely a #[path] or \
             visibility form it does not handle:\n  {}\n",
            only_legacy.len(),
            only_legacy.join("\n  ")
        ));
    }
    assert!(report.is_empty(), "#8325: predicates disagree.{report}");
}
