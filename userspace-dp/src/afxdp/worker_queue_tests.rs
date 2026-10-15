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

/// Blank out `//` line comments, nested `/* */` blocks, string-literal bodies
/// and char literals.
///
/// Comments are stripped so this guard cannot be satisfied by prose that
/// merely quotes the pattern it forbids — the doc comment on `push_bounded`
/// names `push_back` in exactly that way. String bodies are stripped so a
/// literal containing `//` (a URL, say) cannot silently blind the line scan
/// that follows it. Char and byte-char literals are stripped whole, because
/// the quote in `'"'` or `b'"'` would otherwise open a phantom string that
/// swaps code and string state until the next quote. Bytes are replaced by
/// spaces rather than removed so line numbers in a failure message still point
/// at the real source line.
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
            let mut depth = 1;
            while i < b.len() && depth > 0 {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    keep_nl(&mut out, i);
                    i += 1;
                }
            }
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
        } else if b[i] == b'\'' {
            // rustc's lexer rule: an escape, or exactly one character, then the
            // closing quote. Anything else (`'a`, `'static`, `'outer:`) is a
            // lifetime or label and stays code.
            let end = if b.get(i + 1) == Some(&b'\\') {
                b.get(i + 3..)
                    .and_then(|rest| rest.iter().position(|&c| c == b'\'' || c == b'\n'))
                    .map(|at| i + 3 + at)
                    .filter(|&at| b[at] == b'\'')
            } else {
                src[i + 1..]
                    .chars()
                    .next()
                    .map(|c| i + 1 + c.len_utf8())
                    .filter(|&at| b.get(at) == Some(&b'\''))
            };
            match end {
                Some(at) => i = at + 1,
                None => {
                    out[i] = b[i];
                    i += 1;
                }
            }
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

/// Blank inline `#[cfg(test)] mod` bodies before the producer census.
///
/// Production files can also contain test-only modules. The source walk excludes
/// test-only files, but scanning those inline modules would report fixture
/// queue setup as a production producer.
fn blank_cfg_test_modules(src: &str) -> String {
    let mut out = src.as_bytes().to_vec();
    let mut search = 0;
    while let Some(relative) = src[search..].find("#[cfg(test)]") {
        let attr_start = search + relative;
        let mut cursor = attr_start + "#[cfg(test)]".len();

        loop {
            while cursor < src.len() && src.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if src[cursor..].starts_with("#[") {
                let Some(close) = src[cursor..].find(']') else {
                    break;
                };
                cursor += close + 1;
                continue;
            }
            if src[cursor..].starts_with("pub") {
                cursor += "pub".len();
                while cursor < src.len() && src.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if src.as_bytes().get(cursor) == Some(&b'(') {
                    let mut depth = 1;
                    cursor += 1;
                    while cursor < src.len() && depth > 0 {
                        match src.as_bytes()[cursor] {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            _ => {}
                        }
                        cursor += 1;
                    }
                }
                while cursor < src.len() && src.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
            }
            let mod_end = cursor + "mod".len();
            if !src[cursor..].starts_with("mod")
                || src
                    .as_bytes()
                    .get(mod_end)
                    .map_or(true, |b| !b.is_ascii_whitespace())
            {
                break;
            }
            cursor = mod_end;
            while cursor < src.len() && src.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            while cursor < src.len()
                && (src.as_bytes()[cursor].is_ascii_alphanumeric()
                    || src.as_bytes()[cursor] == b'_')
            {
                cursor += 1;
            }
            while cursor < src.len() && src.as_bytes()[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if src.as_bytes().get(cursor) != Some(&b'{') {
                break;
            }

            let mut depth = 1;
            let mut end = cursor + 1;
            while end < src.len() && depth > 0 {
                match src.as_bytes()[end] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            if depth == 0 {
                for byte in &mut out[attr_start..end] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
                search = end;
                break;
            }
            search = attr_start + "#[cfg(test)]".len();
            break;
        }
        if search <= attr_start {
            search = attr_start + "#[cfg(test)]".len();
        }
    }
    String::from_utf8(out).expect("blanking preserves UTF-8 boundaries")
}

/// Every bare `push_back(..)` in `src` whose argument mentions `WorkerCommand`,
/// as (1-based line, argument text).
fn bare_worker_command_pushes(src: &str) -> Vec<(usize, String)> {
    let cleaned = blank_cfg_test_modules(&blank_comments_and_strings(src));
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

    // Pass 1 collects every module declaration and literal include! in the
    // tree: test-gated ones as seeds, the rest as edges from the declaring or
    // including file. Pass 2 takes the transitive closure, because #[cfg(test)]
    // is INHERITED: a plain mod or include! inside a file that is itself only
    // compiled under test is equally test-only. Without the closure, 36 files
    // under directories like event_stream/tests/ were still classified as
    // production — the third defect this control caught.
    let mut seeds: Vec<String> = Vec::new();
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut included: std::collections::HashSet<String> = std::collections::HashSet::new();
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
        let code = blank_comments_and_strings(&text);
        for (line, code_line) in text.lines().zip(code.lines()) {
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
            // include! source belongs to the file containing the macro,
            // unlike a module resolved from the owning module directory.
            // Record a seed under #[cfg(test)], else an edge, so test-only
            // parents classify included files too.
            // Match only a complete macro name at the start of a code line.
            // The blanked copy preserves byte offsets, so the path still comes
            // from the original string literal, never comment/string contents.
            let item = code_line.trim_start();
            let item = item.strip_prefix("::").unwrap_or(item);
            if let Some(rest) = item.strip_prefix("include!(") {
                let offset = code_line.len() - rest.len();
                let rest = line[offset..].trim_start();
                if let Some(rest) = rest.strip_prefix('"') {
                    if let Some(end) = rest.find('"') {
                        if let Some(dir) = path.parent() {
                            let target = normalise(&dir.join(&rest[..end]), root);
                            included.insert(target.clone());
                            if cfg_test {
                                seeds.push(target);
                            } else {
                                edges.push((normalise(&path, root), target));
                            }
                        }
                    }
                }
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
                        seeds.push(normalise(&cand, root));
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

    // Pass 2: fixpoint from the seeds. Bounded by the seed and edge counts, so
    // it terminates even on a cyclic declaration graph — which cannot exist in
    // valid Rust, but a scanner that hangs on malformed input is worse than one
    // that stops early.
    //
    // include! exists to reuse text, so one file can be included by a
    // test-only file and also declared or included by production. An include
    // target is admitted only once every ungated edge into it starts from a
    // test-only file; otherwise a test helper including shared production
    // source would hide that source from every canary. Admission only becomes
    // true as the set grows, so the iteration still reaches the least
    // fixpoint: an includer found test-only on a later pass admits the target
    // on the pass after.
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    for _ in 0..=seeds.len() + edges.len() {
        let reached: Vec<String> = seeds
            .iter()
            .chain(
                edges
                    .iter()
                    .filter(|(from, _)| out.contains(from))
                    .map(|(_, to)| to),
            )
            .filter(|to| !out.contains(*to))
            .filter(|to| {
                !included.contains(*to)
                    || edges
                        .iter()
                        .all(|(from, edge_to)| edge_to != *to || out.contains(from))
            })
            .cloned()
            .collect();
        if reached.is_empty() {
            break;
        }
        out.extend(reached);
    }
    out
}

#[test]
fn cfg_test_include_edges_ignore_non_code_text_12270() {
    let temp = std::env::temp_dir().join(format!(
        "xpf-include-edge-12270-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let non_code = [
        (
            "trailing_line_comment",
            r#"const VALUE: usize = 0; // include!("../prod.rs")"#,
        ),
        (
            "raw_string",
            r##"const DOC: &str = r#"include!("../prod.rs")"#;"##,
        ),
        ("block_comment", r#"/* include!("../prod.rs") */"#),
        (
            "multiline_block_comment",
            "/* comment\n * include!(\"../prod.rs\");\n */",
        ),
        (
            "nested_block_comment",
            "/* outer /* inner */ include!(\"../prod.rs\") */",
        ),
        // Line-start include! inside multi-line comments and raw strings: the
        // line-start rule alone accepts these, so only blanking rejects them.
        (
            "line_start_in_block_comment",
            "/*\ninclude!(\"../prod.rs\");\n*/",
        ),
        (
            "line_start_in_raw_string",
            "const DOC: &str = r#\"\ninclude!(\"../prod.rs\");\n\"#;",
        ),
        // An unblanked quote char opens a phantom string that ends at the raw
        // string's opening quote, exposing the raw string's body as code.
        (
            "char_quote_before_raw_string",
            "const Q: char = '\"';\nconst DOC: &str = r#\"\ninclude!(\"../prod.rs\");\n\"#;",
        ),
        (
            "byte_char_quote_before_raw_string",
            "const Q: u8 = b'\"';\nconst DOC: &str = r#\"\ninclude!(\"../prod.rs\");\n\"#;",
        ),
        ("macro_name", r#"my_include!("../prod.rs");"#),
        (
            "cfg_test_raw_string",
            "#[cfg(test)]\nconst DOC: &str = r#\"see include!(\"../prod.rs\")\"#;",
        ),
        ("doc_comment", r#"/// include!("../prod.rs")"#),
        (
            "escaped_normal_string",
            r#"const DOC: &str = "escaped quote: \" include!(\"../prod.rs\")";"#,
        ),
        ("include_str", r#"include_str!("../prod.rs");"#),
    ];

    for (name, fixture) in non_code {
        let root = temp.join(name);
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::create_dir_all(root.join("prod")).unwrap();
        std::fs::write(
            root.join("test_parent.rs"),
            "#[cfg(test)]\n#[path = \"tests/fixture.rs\"]\nmod tests;\n",
        )
        .unwrap();
        std::fs::write(root.join("tests/fixture.rs"), fixture).unwrap();
        std::fs::write(root.join("prod.rs"), "mod child;\n").unwrap();
        std::fs::write(root.join("prod/child.rs"), "").unwrap();

        let fixtures = cfg_test_modules(&root);
        assert!(
            fixtures.contains("tests/fixture.rs"),
            "{name}: synthetic test parent was not recognized"
        );
        assert!(
            !fixtures.contains("prod.rs"),
            "{name}: non-code include text created an edge to prod.rs"
        );
        assert!(
            !fixtures.contains("prod/child.rs"),
            "{name}: a false include edge propagated through prod.rs modules"
        );
    }

    let root = temp.join("positive_include_chain");
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(
        root.join("test_parent.rs"),
        "#[cfg(test)]\n#[path = \"tests/fixture.rs\"]\nmod tests;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("tests/fixture.rs"),
        "::include!(\"../nested/first.rs\");\n",
    )
    .unwrap();
    std::fs::write(root.join("nested/first.rs"), "include!(\"../second.rs\");\n").unwrap();
    std::fs::write(root.join("second.rs"), "").unwrap();
    let fixtures = cfg_test_modules(&root);
    assert!(fixtures.contains("nested/first.rs"), "literal include edge was missed");
    assert!(
        fixtures.contains("second.rs"),
        "nested include! edge or its .. path was not followed"
    );

    // A quote char literal must not hide the include! after it, and a lifetime
    // must not be read as a char literal that swallows it.
    let root = temp.join("char_literal_before_include");
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("test_parent.rs"),
        "#[cfg(test)]\n#[path = \"tests/fixture.rs\"]\nmod tests;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("tests/fixture.rs"),
        "const Q: char = '\"';\nfn f<'a>(s: &'a str) -> &'a str { s }\ninclude!(\"../helper.rs\");\n",
    )
    .unwrap();
    std::fs::write(root.join("helper.rs"), "").unwrap();
    assert!(
        cfg_test_modules(&root).contains("helper.rs"),
        "a char literal or lifetime hid the include! that follows it"
    );

    let root = temp.join("cfg_include_resets_before_mod");
    std::fs::create_dir_all(root.join("parent")).unwrap();
    std::fs::write(
        root.join("parent.rs"),
        "#[cfg(test)]\ninclude!(\"included.rs\");\nmod after;\n",
    )
    .unwrap();
    std::fs::write(root.join("included.rs"), "").unwrap();
    std::fs::write(root.join("parent/after.rs"), "").unwrap();
    let fixtures = cfg_test_modules(&root);
    assert!(fixtures.contains("included.rs"), "cfg(test) include edge was missed");
    assert!(
        !fixtures.contains("parent/after.rs"),
        "include! parsing leaked cfg(test) to the following mod"
    );

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(
        cfg_test_modules(&src).contains("afxdp/icmp_ptb_primary_fallback_11437_tests.rs"),
        "the real icmp_ptb_tests.rs:10 include! edge must remain classified"
    );
    let _ = std::fs::remove_dir_all(&temp);
}

/// The shared blanker strips char literals whole and leaves lifetimes and
/// labels as code. Unblanked, the quote in `'"'` opened a phantom string that
/// read the following code as string and the next string as code, in every
/// guard that calls the blanker rather than only in the include! scan.
#[test]
fn blank_comments_and_strings_strips_char_literals_not_lifetimes_12270() {
    let src = concat!(
        "let q = '\"'; let e = '\\''; let u = '\\u{22}'; let m = 'é';\n",
        "fn f<'a>(x: &'a str) -> &'static str { 'outer: loop { break 'outer; } x }\n",
        "let s = \"text\"; let b = b'\"'; code();\n",
    );
    let blanked = blank_comments_and_strings(src);
    assert_eq!(
        blanked.len(),
        src.len(),
        "blanking must preserve byte offsets"
    );
    let lines: Vec<&str> = blanked.lines().collect();
    assert_eq!(lines.len(), 3, "blanking must preserve line breaks");
    assert!(
        lines[0].starts_with("let q =")
            && lines[0].contains("let m =")
            && !lines[0].contains(['\'', '"']),
        "char literals were not stripped whole: {:?}",
        lines[0]
    );
    assert_eq!(
        lines[1],
        src.lines().nth(1).unwrap(),
        "lifetimes and labels must stay code"
    );
    assert!(
        lines[2].contains("code();")
            && !lines[2].contains("text")
            && !lines[2].contains(['\'', '"']),
        "a char literal swapped code and string state: {:?}",
        lines[2]
    );
}

/// include! copies text, so a file a test includes can also be compiled into
/// production. That file must stay production: classifying it as a fixture
/// drops it, and every module it declares, from the #6929, #7015, #7053 and
/// #8121 scans while #8325 stays green.
#[test]
fn cfg_test_include_targets_shared_with_production_stay_production_12270() {
    let temp = std::env::temp_dir().join(format!("xpf-include-share-12270-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    let scan = |name: &str, files: &[(&str, &str)]| {
        let root = temp.join(name);
        for (rel, text) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        cfg_test_modules(&root)
    };

    let fixtures = scan(
        "declared_by_production",
        &[
            (
                "lib/mod.rs",
                "mod prod;\n#[cfg(test)]\n#[path = \"t.rs\"]\nmod t;\n",
            ),
            ("lib/t.rs", "include!(\"prod.rs\");\n"),
            ("lib/prod.rs", "mod child;\n"),
            ("lib/prod/child.rs", ""),
        ],
    );
    assert!(
        fixtures.contains("lib/t.rs"),
        "the test-gated includer was not recognized"
    );
    assert!(
        !fixtures.contains("lib/prod.rs") && !fixtures.contains("lib/prod/child.rs"),
        "a test include! hid a production-declared module and its child"
    );

    let fixtures = scan(
        "included_by_production",
        &[
            (
                "test_parent.rs",
                "#[cfg(test)]\n#[path = \"tests/fixture.rs\"]\nmod tests;\n",
            ),
            ("tests/fixture.rs", "include!(\"../shared.rs\");\n"),
            ("prod_user.rs", "include!(\"shared.rs\");\n"),
            ("shared.rs", "mod child;\n"),
            ("shared/child.rs", ""),
        ],
    );
    assert!(
        fixtures.contains("tests/fixture.rs"),
        "the test fixture was not recognized"
    );
    assert!(
        !fixtures.contains("shared.rs") && !fixtures.contains("shared/child.rs"),
        "a file that production also includes was hidden as a fixture"
    );

    let fixtures = scan(
        "gated_and_ungated_include",
        &[
            ("a.rs", "#[cfg(test)]\ninclude!(\"shared.rs\");\n"),
            ("b.rs", "include!(\"shared.rs\");\n"),
            ("shared.rs", ""),
        ],
    );
    assert!(
        !fixtures.contains("shared.rs"),
        "a test-gated include! outweighed an ungated include! of the same file"
    );

    // Control: a helper shared only by test files is still a fixture when its
    // includers are classified on different passes.
    let fixtures = scan(
        "shared_by_test_only_files",
        &[
            (
                "test_parent.rs",
                "#[cfg(test)]\n#[path = \"tests/a.rs\"]\nmod a;\n",
            ),
            (
                "tests/a.rs",
                "#[path = \"b.rs\"]\nmod b;\ninclude!(\"common.rs\");\n",
            ),
            ("tests/b.rs", "include!(\"common.rs\");\n"),
            ("tests/common.rs", ""),
        ],
    );
    assert!(
        fixtures.contains("tests/b.rs") && fixtures.contains("tests/common.rs"),
        "a helper included only by test-only files was left as production"
    );

    // Pinned limit, disclosed in docs/log/12270.md: this scanner resolves a
    // crate root's `mod prod;` to main/prod.rs, so that declaration does not
    // block the include, and prod.rs is still classified as a fixture.
    let fixtures = scan(
        "crate_root_declaration",
        &[
            (
                "main.rs",
                "mod prod;\n#[cfg(test)]\n#[path = \"t.rs\"]\nmod t;\n",
            ),
            ("t.rs", "include!(\"prod.rs\");\n"),
            ("prod.rs", ""),
        ],
    );
    assert!(
        fixtures.contains("prod.rs"),
        "crate-root mod resolution changed: invert this pin and drop the crate-root \
         limit from the #12270 Risk text"
    );
    let _ = std::fs::remove_dir_all(&temp);
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
        let cleaned = blank_cfg_test_modules(&blank_comments_and_strings(&src));
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
        #[cfg(test)]
        mod fixture {
            pending.push_back(WorkerCommand::DeleteSynced(test_fixture));
        }
        pending.push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![1],
        });
        other.push_back(unrelated_item);
    "#;

    let hits = bare_worker_command_pushes(sample);
    assert_eq!(
        hits.len(),
        1,
        "detector must ignore inline cfg(test) queue setup and strip comments, \
         string literals, bounded calls, and unrelated push_back calls; got {hits:?}"
    );
    assert!(
        hits[0].1.contains("DemoteOwnerRGS"),
        "detector found the wrong production push: {:?}",
        hits[0]
    );
    // The real production push spans three lines: a line-oriented scan would miss it.
    assert!(
        hits[0].1.contains("owner_rgs"),
        "argument capture must span lines, so a multi-line push is not invisible: {:?}",
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
        seeds[0], "let mut did_work = commands_backlogged || !session_import_repairs.is_empty();",
        "the worker loop no longer seeds `did_work` from the command backlog. A \
         `let mut did_work = false;` here reverts #7201 to a pure regression: the \
         budget still splits the batch, but the loop classifies the split passes \
         as IDLE and parks each remaining slice behind a 1 ms poll(2)."
    );

    // The destructure must actually bind the field — a `..` rest pattern would
    // compile, leave `commands_backlogged` unbound, and take the seed line with
    // it, so pinning the seed alone is not enough.
    // #9720: `transition_debt_pending` joined the destructure after
    // `commands_backlogged` — pin the pair verbatim (a `..` rest pattern
    // would compile and silently drop either field; the 9720 guard below
    // pins the carry the new field feeds).
    assert!(
        code.contains(
            "commands_backlogged,\n            transition_debt_pending: transition_debt_pending_now,\n            session_import_repair_pending: session_import_repair_pending_now,\n        } = command_results;"
        ),
        "`commands_backlogged` and both repair-pending carries must be \
         destructured out of WorkerCommandResults at the call site"
    );
}

#[test]
fn worker_queue_9720_gate_truth_table() {
    for has in [false, true] {
        for transition_changed in [false, true] {
            for transition_pending in [false, true] {
                for import_changed in [false, true] {
                    for import_pending in [false, true] {
                        assert_eq!(
                            should_apply_worker_commands(
                                has,
                                transition_changed,
                                transition_pending,
                                import_changed,
                                import_pending,
                            ),
                            has
                                || transition_changed
                                || transition_pending
                                || import_changed
                                || import_pending,
                            "gate truth table diverged with queue={has}, transition_changed={transition_changed}, transition_pending={transition_pending}, import_changed={import_changed}, import_pending={import_pending}"
                        );
                    }
                }
            }
        }
    }
    assert!(should_apply_worker_commands(false, false, false, true, false));
    assert!(should_apply_worker_commands(false, false, false, false, true));
    assert!(!should_apply_worker_commands(false, false, false, false, false));
}

#[test]
fn worker_queue_9720_loop_gate_wiring() {
    // The gate helper is only worth having if the worker loop calls it with
    // a FRESH epoch load, consumes last-observed AFTER apply returns, and
    // carries the pending flag — and that consumer is locals inside a
    // 3000-line function no unit fixture can reach, so the wiring is bound
    // as a source-level agreement (the #7201 pattern above). Without it, a
    // helper-tested-but-unwired loop strands debt exactly like v2 while
    // every behavioral cell stays green (cells drive `apply_worker_commands`
    // directly and never pass through the loop gate).
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/worker/loop_body/mod.rs");
    let src = std::fs::read_to_string(&path).expect("read worker loop_body");
    let code = blank_comments_and_strings(&src);
    for token in [
        "should_apply_worker_commands",
        "transition_debt_epoch(worker_id)",
        "last_transition_debt_epoch",
        "transition_debt_pending",
        "session_import_repair_epoch(worker_id)",
        "last_session_import_repair_epoch",
        "session_import_repair_pending",
    ] {
        assert!(
            code.contains(token),
            "precondition: the guard read a tree with no `{token}` in it at all, \
             so its agreement checks below would pass vacuously"
        );
    }
    // Fresh load sampled into a local every pass (not hoisted, not reused).
    assert!(
        code.contains("let transition_debt_epoch =")
            && code.contains("transition_debt_epoch(worker_id)"),
        "the loop must sample a fresh transition-debt epoch every pass"
    );
    // The gate call itself.
    assert!(
        code.contains("should_apply_worker_commands("),
        "the loop must gate `apply_worker_commands` on `should_apply_worker_commands`"
    );
    // Post-apply consume: last-observed is assigned the sampled epoch only
    // on passes that applied (a record landing mid-apply refires next pass).
    assert!(
        code.contains("last_transition_debt_epoch = transition_debt_epoch;"),
        "last-observed must be consumed from the sampled epoch after apply"
    );
    // Pending carry across passes.
    assert!(
        code.contains("transition_debt_pending = transition_debt_pending_now;"),
        "the loop must carry `transition_debt_pending` across passes"
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

// #13076 (D4-15): worker_queue.rs must stay below the 2000-LOC
// [REFACTOR] ceiling (docs/refactoring-audit.md). The PPTP broadcast
// subsystem and its inline test modules pushed it to 2058 LOC despite
// this sibling test file already existing. This guard fails on the
// pre-split tree and passes once the PPTP production code lives in
// pptp_broadcast.rs and the inline test modules live here.
#[test]
fn worker_queue_13076_below_refactor_ceiling_and_pptp_extracted() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp");
    let wq = std::fs::read_to_string(root.join("worker_queue.rs")).expect("worker_queue.rs");
    let wq_loc = wq.lines().count();
    assert!(
        wq_loc < 2000,
        "worker_queue.rs is {wq_loc} LOC, at/above the 2000-LOC [REFACTOR] ceiling; \
         move the PPTP broadcast subsystem to pptp_broadcast.rs and inline tests here"
    );
    assert!(
        !wq.contains("mod pptp_broadcast_tests_7699"),
        "inline pptp_broadcast_tests_7699 must live in worker_queue_tests.rs, not worker_queue.rs"
    );
    assert!(
        !wq.contains("mod session_import_repair_debt_tests_11360"),
        "inline session_import_repair_debt_tests_11360 must live in worker_queue_tests.rs"
    );
    assert!(
        !wq.contains("fn broadcast_pptp_install"),
        "PPTP broadcast production code must live in pptp_broadcast.rs, not worker_queue.rs"
    );
    let pptp = std::fs::read_to_string(root.join("pptp_broadcast.rs"))
        .expect("pptp_broadcast.rs must exist as the extracted PPTP broadcast module");
    assert!(
        pptp.contains("fn broadcast_pptp_install")
            && pptp.contains("fn drain_pptp_control_inbox_for_worker"),
        "pptp_broadcast.rs must own the PPTP broadcast/drain entry points"
    );
    assert!(
        wq.contains("pub(in crate::afxdp) use pptp_broadcast::{"),
        "worker_queue.rs must re-export the PPTP entry points from pptp_broadcast"
    );
}

// ---------------------------------------------------------------------------
// #13076 (D4-15): PPTP broadcast tests (#7699), moved verbatim from the
// inline `pptp_broadcast_tests_7699` module in worker_queue.rs. They now
// exercise the extracted pptp_broadcast module; `use super::*` resolves
// through worker_queue's re-exports, and MAX_PENDING_WORKER_COMMANDS /
// WORKER_COMMAND_DRAIN_BUDGET / drain_bounded_into / lock_recover keep
// resolving from worker_queue itself.
// ---------------------------------------------------------------------------
use super::pptp_broadcast::retry_pending_pptp_call_installs_for_test as retry_pending_pptp_call_installs;

use super::*;
use crate::session::pptp::PptpCall;

fn queues(n: usize) -> Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> {
    (0..n).map(|_| Arc::new(Mutex::new(VecDeque::new()))).collect()
}

fn a_ctl() -> crate::session::pptp::ControlChannelId {
    crate::session::pptp::ControlChannelId::new(
        "198.51.100.7".parse().unwrap(),
        49152,
        "203.0.113.9".parse().unwrap(),
        1723,
    )
}

fn a_call() -> PptpCall {
    PptpCall::new(
        "198.51.100.7".parse().unwrap(),
        0x1111,
        "203.0.113.9".parse().unwrap(),
        0x2222,
    )
}

/// EVERY worker must get the install, not just one.
///
/// This is the property the whole broadcast exists for: RSS lands a call's
/// data packets on a worker chosen by the flow hash, which is generally not
/// the one that saw its control channel. A send-to-one would leave the call
/// unresolvable on N-1 workers, and a fixture with a single queue would not
/// notice — so this asserts over several.
#[test]
fn an_install_reaches_every_worker_7699() {
    let qs = queues(4);
    assert_eq!(broadcast_pptp_install(&qs, a_call(), a_ctl(), 0).0, 4);
    for (i, q) in qs.iter().enumerate() {
        let pending = q.lock().expect("queue");
        assert_eq!(pending.len(), 1, "worker {i} did not receive the install");
        assert!(matches!(pending[0], WorkerCommand::InstallPptpCall { .. }));
    }
}

/// A teardown must reach every worker too.
///
/// Asserted separately rather than assumed symmetric with the install: a
/// worker that keeps a stale association re-pairs a REUSED 16-bit call id
/// onto a dead handle, which is a mis-attribution rather than a leak.
#[test]
fn a_teardown_reaches_every_worker_7699() {
    let qs = queues(3);
    assert_eq!(broadcast_pptp_forget(&qs, 0xdead_beef), 3);
    for q in &qs {
        let pending = q.lock().expect("queue");
        assert!(matches!(pending[0], WorkerCommand::ForgetPptpCall(0xdead_beef)));
    }
}

/// A FULL queue is reported, not swallowed.
///
/// `push_bounded` drops when the queue is at capacity, so a broadcast can
/// be partial. That is survivable — the missed worker resolves those
/// packets as unassociated and forwards them — but it must be VISIBLE, or a
/// caller cannot tell a complete broadcast from one that reached half the
/// dataplane. The count is the signal.
#[test]
fn a_full_queue_makes_the_broadcast_report_short_7699() {
    let qs = queues(2);
    {
        let mut full = qs[1].lock().expect("queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let (accepted, unsent) = broadcast_pptp_install(&qs, a_call(), a_ctl(), 0);
    assert_eq!(
        accepted,
        1,
        "a broadcast that reached only one of two workers must report 1; \
         reporting 2 would let a caller treat a half-delivered association \
         as installed"
    );
    assert_eq!(unsent, vec![Arc::as_ptr(&qs[1]) as usize]);
}

/// A refused recipient must learn through its own peer-excluding drain.
///
/// Worker Q's queue refused X's broadcast. Q's peer list contains only X,
/// so the retry must apply to Q's own session table rather than consume the
/// shared gate and skip Q's identity.
#[test]
fn a_refused_worker_applies_its_install_retry_to_its_own_table_12133() {
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox,
        fixtures_7699::outgoing_call_reply,
    };

    let pac: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let pns: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let queues = queues(2);
    {
        let mut full = queues[0].lock().expect("Q queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }

    let inbox = PptpControlInbox::default();
    let mut x_sessions = crate::session::SessionTable::new();
    let mut q_sessions = crate::session::SessionTable::new();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 10,
        payload: outgoing_call_reply(0x1111, 0x2222, 1),
    }));
    // X's peer list contains Q, but excludes X itself.
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut x_sessions,
            Some(&queues[1]),
            std::slice::from_ref(&queues[0]),
            1_000_000_000,
        ),
        1
    );
    let handle = PptpCall::new(pac, 0x1111, pns, 0x2222).handle();
    assert_eq!(x_sessions.pptp().resolve(pac, 0x1111), Some(handle));
    assert!(
        !queues[0]
            .lock()
            .expect("Q queue")
            .iter()
            .any(|command| matches!(command, WorkerCommand::InstallPptpCall { .. })),
        "the full Q queue must have refused X's first broadcast"
    );

    drain_queue_bounded(&queues[0]);
    // Q's peer list contains X, but excludes Q. Q is first through the
    // retry gate, so its own table must receive the refused record.
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut q_sessions,
            Some(&queues[0]),
            std::slice::from_ref(&queues[1]),
            2_000_000_000,
        ),
        0,
        "a retry must not count as a second local learn"
    );
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x1111),
        Some(handle),
        "Q skipped its own refused queue after consuming the shared retry gate"
    );
    assert_eq!(q_sessions.pptp().resolve(pns, 0x2222), Some(handle));
}

/// A real CDN frees the colliding alias, after a peer-present broadcast
/// left the replacement retry pending for Q.
#[test]
fn own_retry_retains_allocator_collision_until_cdn_frees_alias_12133() {
    use crate::session::pptp::{ControlChannelId, PptpCall};
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox,
        fixtures_7699::{call_disconnect_notify, outgoing_call_reply},
    };

    let (pac, pns): (std::net::IpAddr, std::net::IpAddr) = (
        "198.51.100.7".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    let control = ControlChannelId::new(pac, 1723, pns, 49152);
    let old_call = PptpCall::new(pac, 0x1111, pns, 0x2222);
    let replacement = PptpCall::new(pac, 0x1111, pns, 0x3333);
    let queues = queues(2);
    let mut q_sessions = crate::session::SessionTable::new();
    let mut x_sessions = crate::session::SessionTable::new();
    q_sessions
        .pptp_mut()
        .install(old_call, control, 10)
        .expect("old Q association");
    {
        let mut full = queues[0].lock().expect("Q queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let inbox = PptpControlInbox::default();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 30,
        payload: outgoing_call_reply(0x1111, 0x3333, 1),
    }));

    // X learns the reply and its real broadcast is refused by Q's full
    // queue. Q retains the older association, so a direct retry collides.
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut x_sessions,
            Some(&queues[1]),
            std::slice::from_ref(&queues[0]),
            1_000_000_000,
        ),
        1
    );
    assert_eq!(
        x_sessions.pptp().resolve(pac, 0x1111),
        Some(replacement.handle())
    );
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x1111),
        Some(old_call.handle())
    );
    queues[0].lock().expect("Q queue").clear();
    drain_pptp_control_inbox_for_worker(
        &inbox,
        &mut q_sessions,
        Some(&queues[0]),
        std::slice::from_ref(&queues[1]),
        2_000_000_000,
    );
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x1111),
        Some(old_call.handle())
    );

    // The real disconnect timestamp predates the replacement reply. It
    // frees only the old association and does not cancel the newer retry.
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 20,
        payload: call_disconnect_notify(0x1111),
    }));
    drain_pptp_control_inbox_for_worker(
        &inbox,
        &mut q_sessions,
        Some(&queues[0]),
        std::slice::from_ref(&queues[1]),
        3_000_000_000,
    );
    assert_eq!(q_sessions.pptp().resolve(pac, 0x1111), None);
    drain_pptp_control_inbox_for_worker(
        &inbox,
        &mut q_sessions,
        Some(&queues[0]),
        std::slice::from_ref(&queues[1]),
        4_000_000_000,
    );
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x1111),
        Some(replacement.handle()),
        "the collision retry must survive until the real CDN frees the alias"
    );

    let forwarding = crate::afxdp::ForwardingState::default();
    let dynamic_neighbors = Arc::new(crate::afxdp::ShardedNeighborMap::new());
    let mut scratch = VecDeque::new();
    let result = crate::afxdp::session_glue::apply_worker_commands(
        &queues[1],
        &mut x_sessions,
        crate::afxdp::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &std::collections::BTreeMap::new(),
        &dynamic_neighbors,
        0,
        &mut scratch,
    );
    assert!(!result.commands_backlogged);
    assert_eq!(
        x_sessions.pptp().resolve(pac, 0x1111),
        Some(replacement.handle()),
        "the older CDN must not remove a later association on the peer"
    );
    assert!(
        inbox.take_call_install_retries(5_000_000_000).is_empty(),
        "a successful own-table install acknowledges Q"
    );
}

fn drain_queue_bounded(queue: &Arc<Mutex<VecDeque<WorkerCommand>>>) {
    let mut scratch = VecDeque::new();
    for _ in 0..MAX_PENDING_WORKER_COMMANDS.div_ceil(WORKER_COMMAND_DRAIN_BUDGET) {
        let backlogged = {
            let mut pending = lock_recover(queue);
            drain_bounded_into(&mut pending, &mut scratch)
        };
        scratch.clear();
        if !backlogged {
            break;
        }
    }
    assert!(queue.lock().expect("drained queue").is_empty());
}

/// A CDN cancels an outstanding install retry before the queue is cleared.
#[test]
fn a_cdn_cancels_a_pending_pptp_install_retry_12133() {
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox,
        fixtures_7699::{call_disconnect_notify, outgoing_call_reply},
    };

    let pac: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let pns: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let queues = queues(2);
    {
        let mut full = queues[1].lock().expect("queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let inbox = PptpControlInbox::default();
    let mut local = crate::session::SessionTable::new();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 10,
        payload: outgoing_call_reply(0x1111, 0x2222, 1),
    }));
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 1_000_000_000),
        1
    );

    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 20,
        payload: call_disconnect_notify(0x1111),
    }));
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 2_000_000_000),
        0
    );
    assert_eq!(local.pptp().resolve(pac, 0x1111), None);

    queues[1].lock().expect("queue").clear();
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 3_000_000_000),
        0
    );
    let pending = queues[1].lock().expect("queue");
    assert!(
        pending.iter().any(|command| matches!(
            command,
            WorkerCommand::ForgetPptpCallByControl(disconnect)
                if disconnect.call_id == 0x1111
        )),
        "the refused CDN must still retry"
    );
    assert!(
        !pending
            .iter()
            .any(|command| matches!(command, WorkerCommand::InstallPptpCall { .. })),
        "a CDN must cancel a pending install, or the install retries after \
         the teardown and resurrects the call"
    );
}

/// A CDN for A must not cancel B's retry on the same control channel.
///
/// The next interval is the #12133 path under test: after Q's bounded
/// queue drain, Q's self-excluding drainer must still learn B directly.
#[test]
fn a_cdn_cancels_only_its_call_and_the_next_call_still_retries_12133() {
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox,
        fixtures_7699::{call_disconnect_notify, outgoing_call_reply},
    };

    let pac: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let pns: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let queues = queues(2);
    {
        let mut full = queues[0].lock().expect("Q queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let inbox = PptpControlInbox::default();
    let mut x_sessions = crate::session::SessionTable::new();
    let mut q_sessions = crate::session::SessionTable::new();
    for (captured_ns, call_id, peer_call_id) in [(10, 0x1111, 0x2222), (11, 0x3333, 0x4444)] {
        assert!(inbox.push(PendingControlSegment {
            src: pac,
            dst: pns,
            src_port: 1723,
            dst_port: 49152,
            captured_ns,
            payload: outgoing_call_reply(call_id, peer_call_id, 1),
        }));
    }
    // X's peer list contains Q only; both installs are refused there.
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut x_sessions,
            Some(&queues[1]),
            std::slice::from_ref(&queues[0]),
            1_000_000_000,
        ),
        2
    );
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 20,
        payload: call_disconnect_notify(0x1111),
    }));
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut x_sessions,
            Some(&queues[1]),
            std::slice::from_ref(&queues[0]),
            2_000_000_000,
        ),
        0
    );
    assert_eq!(x_sessions.pptp().resolve(pac, 0x1111), None);
    assert_eq!(
        x_sessions.pptp().resolve(pac, 0x3333),
        Some(PptpCall::new(pac, 0x3333, pns, 0x4444).handle())
    );

    drain_queue_bounded(&queues[0]);
    assert_eq!(
        drain_pptp_control_inbox_for_worker(
            &inbox,
            &mut q_sessions,
            Some(&queues[0]),
            std::slice::from_ref(&queues[1]),
            3_000_000_000,
        ),
        0,
        "retrying B is not a second local learn"
    );
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x1111),
        None,
        "the CDN-named call A must not be retried"
    );
    let b_handle = PptpCall::new(pac, 0x3333, pns, 0x4444).handle();
    assert_eq!(
        q_sessions.pptp().resolve(pac, 0x3333),
        Some(b_handle),
        "the CDN for A canceled B's retry, restoring #12133 for B"
    );
    assert_eq!(q_sessions.pptp().resolve(pns, 0x4444), Some(b_handle));
}

/// Closing the control channel cancels retries learned on that channel.
#[test]
fn closing_a_control_channel_cancels_a_pending_pptp_install_retry_12133() {
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox, fixtures_7699::outgoing_call_reply,
    };

    let pac: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let pns: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let queues = queues(2);
    {
        let mut full = queues[1].lock().expect("queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let inbox = PptpControlInbox::default();
    let mut local = crate::session::SessionTable::new();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 10,
        payload: outgoing_call_reply(0x1111, 0x2222, 1),
    }));
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 1_000_000_000),
        1
    );

    let control_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: libc::IPPROTO_TCP as u8,
        src_ip: pac,
        dst_ip: pns,
        src_port: 1723,
        dst_port: 49152,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let (forgotten, _) = crate::afxdp::poll_descriptor::forget_pptp_control_channel(
        &mut local,
        &inbox,
        None,
        &queues,
        &control_key,
        20,
    );
    assert_eq!(forgotten, 1);
    assert_eq!(local.pptp().resolve(pac, 0x1111), None);

    queues[1].lock().expect("queue").clear();
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 2_000_000_000),
        0
    );
    let pending = queues[1].lock().expect("queue");
    assert!(
        pending.iter().any(|command| matches!(
            command,
            WorkerCommand::ForgetPptpControlChannel { closed_ns: 20, .. }
        )),
        "the channel close must still reach the late worker"
    );
    assert!(
        !pending
            .iter()
            .any(|command| matches!(command, WorkerCommand::InstallPptpCall { .. })),
        "a channel close must cancel pending installs, or one retries after \
         the teardown and resurrects a call"
    );
}

/// A complete later broadcast supersedes an older refused install retry.
#[test]
fn a_complete_rebroadcast_clears_the_older_install_retry_12133() {
    use crate::session::pptp_control::{
        PendingControlSegment, PptpControlInbox, fixtures_7699::outgoing_call_reply,
    };

    let pac: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    let pns: std::net::IpAddr = "203.0.113.9".parse().unwrap();
    let queues = queues(2);
    {
        let mut full = queues[1].lock().expect("refused queue");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            full.push_back(WorkerCommand::VacateAllSharedExactSlots);
        }
    }
    let inbox = PptpControlInbox::default();
    let mut local = crate::session::SessionTable::new();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 10,
        payload: outgoing_call_reply(0x1111, 0x2222, 1),
    }));
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 1_000_000_000),
        1
    );

    // Keep the old retry alive and advance only its gate while Q remains
    // full. A new reply can then be parsed before another retry snapshot.
    retry_pending_pptp_call_installs(&inbox, &mut local, None, &queues, 2_000_000_000);
    queues[1].lock().expect("refused queue").clear();
    assert!(inbox.push(PendingControlSegment {
        src: pac,
        dst: pns,
        src_port: 1723,
        dst_port: 49152,
        captured_ns: 20,
        payload: outgoing_call_reply(0x1111, 0x2222, 1),
    }));
    assert_eq!(
        drain_pptp_control_inbox(&inbox, &mut local, &queues, 2_500_000_000),
        1
    );

    retry_pending_pptp_call_installs(&inbox, &mut local, None, &queues, 3_000_000_000);
    let pending = queues[1].lock().expect("previously refused queue");
    let learned_ns: Vec<_> = pending
        .iter()
        .filter_map(|command| match command {
            WorkerCommand::InstallPptpCall { learned_ns, .. } => Some(*learned_ns),
            _ => None,
        })
        .collect();
    assert_eq!(
        learned_ns,
        vec![20],
        "the old refusal survived a complete re-broadcast and retried too"
    );
}


// ---------------------------------------------------------------------------
// #13076 (D4-15): session-import repair-debt tests (#11360), moved
// verbatim from the inline `session_import_repair_debt_tests_11360`
// module in worker_queue.rs.
// ---------------------------------------------------------------------------

use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn key(index: usize) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: index as u16,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

#[test]
fn repair_debt_is_bounded_and_keeps_the_latest_position_11360() {
    let mut debt = SessionImportRepairDebt::default();
    for index in 0..MAX_PENDING_SESSION_IMPORT_REPAIRS {
        debt.record(key(index), index as u64 + 1)
            .expect("entry below per-worker repair cap");
    }
    assert_eq!(debt.entries.len(), MAX_PENDING_SESSION_IMPORT_REPAIRS);

    let first = key(0);
    let original_token = debt.entries.get(&first).expect("first repair").1;
    assert!(
        debt.record(first.clone(), 5000).is_ok(),
        "a latest intent must replace the existing slot even when the map is full"
    );
    let (position, latest_token) = debt.entries.get(&first).expect("updated repair");
    assert_eq!(*position, 5000);
    assert_ne!(*latest_token, original_token);
    assert_eq!(debt.entries.len(), MAX_PENDING_SESSION_IMPORT_REPAIRS);

    assert!(
        debt.take_ready(usize::MAX, 4999)
            .iter()
            .all(|repair| repair.key != first),
        "repair escaped before its FIFO position"
    );
    assert!(
        debt.take_ready(usize::MAX, 5000)
            .iter()
            .any(|repair| repair.key == first),
        "latest repair did not become ready at its FIFO position"
    );
    assert!(
        debt.record(key(MAX_PENDING_SESSION_IMPORT_REPAIRS), 5000)
            .is_err(),
        "a distinct repair beyond the bound must escalate as overflow"
    );
    assert_eq!(debt.entries.len(), MAX_PENDING_SESSION_IMPORT_REPAIRS);
}
#[test]
fn repair_target_survives_recording_after_its_queue_prefix_drains_11360() {
    const WORKER_ID: u32 = crate::nat::MAX_NAT_HOLDER_WORKERS - 1;
    clear_session_import_repairs(WORKER_ID);
    let key = key(5000);
    let queue = Mutex::new(VecDeque::new());
    let pending = lock_recover(&queue);
    let target = session_import_repair_position(WORKER_ID, 4).expect("valid worker");
    note_worker_commands_drained(WORKER_ID, 4);
    assert!(record_session_import_repair(WORKER_ID, &key, target));
    drop(pending);

    let (ready, ready_remains, pending) =
        take_ready_session_import_repairs(WORKER_ID, SESSION_IMPORT_REPAIR_DRAIN_BUDGET);
    assert_eq!(ready.len(), 1, "the drained prefix must make repair due");
    assert_eq!(ready[0].key, key);
    assert!(!ready_remains);
    assert!(pending);
    complete_session_import_repair(WORKER_ID, &ready[0]);
    assert!(!has_session_import_repair_debt(WORKER_ID));
}
