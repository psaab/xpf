//! #16187: per-directory `unsafe` ratchet over production source.
//!
//! Measured at filing (origin/master `1f3e4e130e`): ~390 word-`unsafe`
//! hits across 64 non-test files under `userspace-dp/src/`, and zero
//! `deny(unsafe_code)` / `forbid` anywhere in the tree — a new `unsafe`
//! anywhere compiled silently. This file is the narrowed survivor of
//! rust-dp R10 (synthesis W1.13): per-directory ratchet cells in the
//! existing #7689 both-directions counting style, plus publication of
//! the measured baseline (below and in `userspace-dp/README.md`).
//! Deliberately NOT done, both unanimously rejected in review:
//! a crate-root `deny(unsafe_code)` (an `#[allow]` on a parent `mod`
//! propagates to whole subtrees — either useless at `afxdp` scope or a
//! 64-entry list nobody reviews; the finder's "~15 modules" was
//! fiction) and splitting `xsk_ffi.rs` (a cohesive xdpilone mirror —
//! ABI → Umem → Socket → rings — whose split destroys upstream
//! diffability for size alone).
//!
//! COUNTING CONTRACT — read this before touching a ceiling.
//! A hit is a whole-word `unsafe` in code, counted per directory
//! (the file's immediate parent under `src/`; crate-root files are
//! `"."`). Production source only:
//!   * comments and string/char bodies are blanked first (the shared
//!     `blank_comments_and_strings`), so prose that merely mentions
//!     `unsafe` — `policy.rs`'s "would be unsafe", a `// SAFETY:`
//!     comment — never counts, and adding a safety comment can never
//!     red this ratchet;
//!   * inline `#[cfg(test)] mod { .. }` bodies are blanked too (the
//!     shared `blank_cfg_test_modules`), so test-only unsafe inside a
//!     production file is not production surface;
//!   * files reachable only under `#[cfg(test)]` are excluded via
//!     `cfg_test_modules` (the #12270 declaration graph — keyed on
//!     resolved file paths, transitively closed over `mod`/`include!`,
//!     so `#[path]`-renamed test files are still fixtures). Reachable
//!     from BOTH production and a test declaration counts as
//!     production: the graph admits a target only when every
//!     ungated edge into it starts from a test-only file, for `mod`
//!     targets as for `include!` targets (`declared`, #16187 review
//!     fold — dual `#[path] mod` previously classified such a file
//!     test-only and its unsafe would never have been counted);
//!   * `test_alloc.rs` is named explicitly: it is the #4971 test-only
//!     counting allocator (`#[cfg(test)] mod test_alloc;` at the crate
//!     root), and the declaration graph resolves crate-root modules
//!     against `main/` (its pinned limit, see #12270), so the graph
//!     alone would misclassify this one file as production. Its
//!     allocator internals are test harness, not packet-path surface.
//! Test files are otherwise NOT policed by this ratchet: test-only
//! unsafe (FFI fixture construction, `xsk_ffi_tests.rs`) is reviewed
//! as test code. The seeded-unsafe acceptance check therefore seeds
//! production files; a seeded test-file unsafe staying green is by
//! design, stated here so nobody mistakes it for a hole someone
//! forgot.
//!
//! Residue formerly named here: the previously uncompiled orphan
//! `afxdp/tx/dispatch/tests/nat64_attribution_6922.rs` was restored
//! as a compiled `#[cfg(test)]` fixture by #16465 (`mod
//! nat64_attribution_6922;` in `tx/dispatch/tests/mod.rs`), so the
//! #12270 declaration graph now classifies it as test-only and its
//! 6 hits leave the production population; the
//! `afxdp/tx/dispatch/tests` ceiling is tightened to 0 in the same
//! change, as the improvement arm requires.
//!
//! Both directions, same shape as #7689: a directory that GAINS
//! unsafe reds (lower the ceiling only when unsafe is genuinely
//! removed), and a directory that LOSES unsafe also reds until its
//! ceiling is tightened — an untightened ceiling is room a future
//! unsafe can grow into silently, which is exactly how a ratchet
//! decays into permission. A new directory with any production
//! unsafe has no ceiling and reds by name. Zero ceilings are kept
//! in the table (not omitted) so the directory stays named as
//! covered-at-zero: a first unsafe there is the regression this
//! cell exists to catch (`forwarding_build/`, `session/`,
//! `filter/` … today).
//!
//! FAIL-ON-REVERT / seeded check: add `unsafe {}` to any production
//! file in a covered directory (or a first one in a zero-ceiling
//! directory) and the per-directory cell reds naming the directory,
//! both numbers, and the instruction. Remove a real `unsafe` and the
//! improvement arm reds until the ceiling follows it down.
//!
//! Production/perf impact: none. This file is `#[cfg(test)]`-only;
//! no production code, attribute, or hot-path behaviour changes.

use crate::test_support::source_scan::{
    afxdp_rs_files, blank_cfg_test_modules, blank_comments_and_strings, cfg_test_modules,
};

/// Per-directory production `unsafe` ceilings. ONLY EVER DECREASES.
///
/// Baseline measured on this change at `ba55ef764a` by the scan below
/// (367 hits in 55 production files, 25 directories). The published
/// 64-file list in `userspace-dp/README.md` is the filing measurement
/// (raw word hits in non-test-named files: 390 in 64, including
/// prose mentions this scan deliberately does not count) — the two
/// numbers describe the same surface with the two stated counting
/// rules, and the reconciling files are listed beside the table in
/// the README. Do not "fix" one number to match the other by
/// widening a ceiling; re-measure with the stated rule instead.
const UNSAFE_CEILING_PER_DIR: &[(&str, usize)] = &[
    (".", 97),
    ("afxdp", 80),
    ("afxdp/binding_state", 2),
    ("afxdp/bpf_map", 64),
    ("afxdp/coordinator", 0),
    ("afxdp/coordinator/reconcile", 0),
    ("afxdp/coordinator/wg_control", 30),
    ("afxdp/cos", 2),
    ("afxdp/cos/queue_ops", 0),
    ("afxdp/cos/queue_service", 4),
    ("afxdp/forwarding", 12),
    ("afxdp/forwarding_build", 0),
    ("afxdp/forwarding_build/cos", 0),
    ("afxdp/frame", 10),
    ("afxdp/frame/build", 1),
    ("afxdp/frame/rewrite", 1),
    ("afxdp/ha", 0),
    ("afxdp/icmp_embed", 0),
    ("afxdp/mirror", 1),
    ("afxdp/poll_descriptor", 15),
    ("afxdp/session_glue", 0),
    ("afxdp/session_glue/commands", 0),
    ("afxdp/shared_ops", 0),
    ("afxdp/tx", 8),
    ("afxdp/tx/dispatch", 5),
    ("afxdp/tx/dispatch/tests", 0),
    ("afxdp/tx/drain", 2),
    ("afxdp/tx/transmit", 2),
    ("afxdp/types", 1),
    ("afxdp/types/shared_cos_lease", 0),
    ("afxdp/umem", 9),
    ("afxdp/wg", 3),
    ("afxdp/worker", 5),
    ("afxdp/worker/cos", 0),
    ("afxdp/worker/loop_body", 2),
    ("bin", 0),
    ("event_stream", 2),
    ("event_stream/codec", 0),
    ("fairness_eval", 0),
    ("filter", 0),
    ("filter/engine", 0),
    ("filter/engine/cache_sensitive", 0),
    ("fragment_assoc", 0),
    ("fragment_overlap", 0),
    ("nat", 0),
    ("nat/source", 0),
    ("protocol", 0),
    ("screen", 0),
    ("server", 3),
    ("server/handlers", 0),
    ("server/helpers", 0),
    ("session", 0),
];

/// Files excluded from the production population by name, each with
/// its reason. Kept as data (not a silent `continue`) so the fixture
/// cell below can assert every entry still names a real file and the
/// exclusion cannot quietly become a hiding place: a production file
/// added here without the cell noticing is exactly the fail-open
/// direction this guard must not have.
const NAMED_PRODUCTION_EXCLUSIONS: &[(&str, &str)] = &[(
    "test_alloc.rs",
    "#4971 test-only counting allocator; #[cfg(test)] at the crate root, \
     which the #12270 declaration graph cannot resolve (pinned limit)",
)];

fn dir_of(rel: &str) -> String {
    match rel.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => ".".to_string(),
    }
}

/// Whole-word test: the bytes around `at..at+len` must not be
/// identifier bytes. `unsafe` inside a longer identifier
/// (`unsafe_foo`, `myunsafe`) is not the keyword and must not count;
/// `unsafe_foo` after blanking still contains the substring, so a
/// naive `matches("unsafe")` census would count identifiers as
/// unsafe surface.
pub(crate) fn is_word_at(bytes: &[u8], at: usize, word: &str) -> bool {
    let w = word.as_bytes();
    if at + w.len() > bytes.len() || &bytes[at..at + w.len()] != w {
        return false;
    }
    let before_ok = at == 0 || !(bytes[at - 1] == b'_' || bytes[at - 1].is_ascii_alphanumeric());
    let after = at + w.len();
    let after_ok =
        after >= bytes.len() || !(bytes[after] == b'_' || bytes[after].is_ascii_alphanumeric());
    before_ok && after_ok
}

/// Count whole-word `unsafe` in production code in `raw`: comments,
/// strings and char literals blanked, inline `#[cfg(test)]` module
/// bodies blanked. Split out so both directions can be pinned
/// against fixtures instead of against the tree — a cell that only
/// asserts "the false positive is gone" would also pass if the scan
/// were deleted.
pub(crate) fn unsafe_count_in_source(raw: &str) -> usize {
    let cleaned = blank_cfg_test_modules(&blank_comments_and_strings(raw));
    let bytes = cleaned.as_bytes();
    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(hit) = cleaned[from..].find("unsafe") {
        let at = from + hit;
        if is_word_at(bytes, at, "unsafe") {
            count += 1;
        }
        from = at + "unsafe".len();
    }
    count
}

/// Scan the production population once: (per-directory counts,
/// production file count, walked file count). Shared by the ratchet
/// and the population guard so both read the same census.
fn production_unsafe_census() -> (std::collections::BTreeMap<String, usize>, usize, usize) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let fixtures = cfg_test_modules(&root);
    let excluded: std::collections::HashSet<&str> = NAMED_PRODUCTION_EXCLUSIONS
        .iter()
        .map(|(f, _)| *f)
        .collect();
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);
    files.sort();
    let walked = files.len();
    let mut per_dir: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut production_files = 0usize;
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if fixtures.contains(&rel) || excluded.contains(rel.as_str()) {
            continue;
        }
        production_files += 1;
        let raw = std::fs::read_to_string(path).expect("read source");
        let count = unsafe_count_in_source(&raw);
        if count > 0 {
            *per_dir.entry(dir_of(&rel)).or_default() += count;
        }
    }
    (per_dir, production_files, walked)
}

/// #16187 both-directions fixture for the unsafe scan.
///
/// Every row pins one side or the other, deliberately in one cell:
/// a scan that always returns 0 satisfies every "must not count"
/// row, and a scan that counts substrings satisfies every "must
/// count" row — only the whole table pins the real function.
#[test]
fn unsafe_scan_counts_code_not_prose_16187() {
    // (source, expected count, why)
    let cases: &[(&str, usize, &str)] = &[
        // --- MUST COUNT: real production unsafe, every syntactic form ---
        ("unsafe { x(); }", 1, "unsafe block"),
        ("unsafe fn f() {}", 1, "unsafe fn"),
        ("unsafe impl Send for X {}", 1, "unsafe impl"),
        ("unsafe extern \"C\" { fn g(); }", 1, "unsafe extern block"),
        ("unsafe trait T {}", 1, "unsafe trait"),
        (
            "let a = unsafe { f() }; let b = unsafe { g() };",
            2,
            "two blocks on one line both count",
        ),
        // --- MUST NOT COUNT: prose, strings, identifiers ---
        (
            "// this would be unsafe\nlet x = 1;",
            0,
            "line-comment prose",
        ),
        (
            "/// `unsafe` on the precondition\nfn f() {}",
            0,
            "doc-comment prose",
        ),
        ("/* unsafe */ fn f() {}", 0, "block-comment prose"),
        (
            "// SAFETY: the unsafe below is sound\nunsafe { f(); }",
            1,
            "a SAFETY comment does not count, the block after it does",
        ),
        (
            "let s = \"unsafe\"; let t = \"an unsafe block\";",
            0,
            "string bodies do not count",
        ),
        (
            "fn unsafe_foo() {} let myunsafe = 1;",
            0,
            "identifiers containing the substring do not count",
        ),
        ("let unsafe_ = 1;", 0, "identifier with unsafe prefix"),
        // --- MUST NOT COUNT: test-only code inside a production file ---
        (
            "#[cfg(test)]\nmod tests { fn t() { unsafe { f(); } } }\nfn prod() {}",
            0,
            "inline cfg(test) module body is test code, not production surface",
        ),
        (
            "fn prod() { unsafe { f(); } }\n#[cfg(test)]\nmod tests { fn t() { unsafe { g(); } } }",
            1,
            "production unsafe before an inline test module still counts",
        ),
    ];
    for (src, want, why) in cases {
        let got = unsafe_count_in_source(src);
        assert_eq!(
            got, *want,
            "unsafe_count_in_source({src:?}) = {got}, want {want} — {why}"
        );
    }
    // NON-VACUITY: the scan must be capable of returning both answers,
    // or the table above could be satisfied by a function that always
    // returns 0 (or always returns the substring count).
    assert_eq!(
        unsafe_count_in_source("unsafe { f(); }"),
        1,
        "the scan never returns a nonzero count — it cannot be measuring anything"
    );
    assert_eq!(
        unsafe_count_in_source("// unsafe\n\"unsafe\""),
        0,
        "the scan never returns zero — it cannot be excluding anything"
    );
    assert_eq!(
        unsafe_count_in_source("let unsafe_foo = 1;"),
        0,
        "the scan counts identifiers — it is measuring substrings, not the keyword"
    );
}

/// Population guard: the census must actually be measuring the
/// production tree, and the exclusion list must not rot.
///
/// Without this, the ratchet below passes vacuously in three
/// distinct ways: a walk that reads nothing reports every directory
/// as 0 (all `<=` ceiling — but the improvement arm would red, so
/// this also pins that the walk is the reason), a fixture graph
/// that suddenly classified production as test would shrink the
/// population silently, and a named exclusion pointing at a deleted
/// or renamed file would hide nothing while claiming to exclude
/// something. Each is asserted against a floor/presence check, not
/// against the ratchet's own output.
#[test]
fn unsafe_ratchet_population_is_real_16187() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let fixtures = cfg_test_modules(&root);
    let (per_dir, production_files, walked) = production_unsafe_census();
    let total: usize = per_dir.values().sum();

    assert!(
        walked >= 700,
        "walk read only {walked} .rs files under src — the walk is broken and \
         every count in the ratchet would be measured against a tree it never opened"
    );
    assert!(
        production_files >= 300,
        "only {production_files} production files classified (walked {walked}, \
         fixtures {}) — the fixture graph is classifying production source as \
         test-only, so the ratchet is blind to the surface it names",
        fixtures.len()
    );
    assert!(
        total >= 300,
        "found only {total} production unsafe hits (expected ~367 at the \
         published baseline) — the scan stopped matching the keyword, so a \
         green ratchet here would mean nothing"
    );
    // Every named exclusion must still name a real file, and must
    // still be a file the fixture graph does NOT already classify —
    // if the graph learns to resolve it, the name must come out of
    // the list or the list is claiming credit for the graph's work
    // and hiding the day the two disagree.
    for (file, _reason) in NAMED_PRODUCTION_EXCLUSIONS {
        assert!(
            root.join(file).exists(),
            "NAMED_PRODUCTION_EXCLUSIONS names {file}, which no longer exists — \
             remove the stale entry; a stale exclusion silently widens what \
             the ratchet tolerates"
        );
        assert!(
            !fixtures.contains(*file),
            "NAMED_PRODUCTION_EXCLUSIONS names {file}, which cfg_test_modules \
             now classifies as a fixture — remove the redundant entry so the \
             exclusion list only carries what the graph cannot"
        );
    }
    // The covered-directory table must name every directory the
    // census found unsafe in, at least as a zero check happens in
    // the ratchet itself; here we pin the converse for the fixture:
    // a ceiling row for a directory that no longer exists on disk is
    // stale permission (it would silently cover a recreated
    // directory at the old number).
    for (dir, _) in UNSAFE_CEILING_PER_DIR {
        if *dir == "." {
            continue;
        }
        assert!(
            root.join(dir).is_dir(),
            "UNSAFE_CEILING_PER_DIR names {dir}, which is not a directory \
             under src — remove the stale row; a stale ceiling silently \
             covers a future directory of that name at the old number"
        );
    }
}

/// The ratchet: no directory may gain production `unsafe`, and any
/// directory that loses some must have its ceiling tightened in the
/// same change.
///
/// FAIL-ON-REVERT: seed `unsafe {}` into any production file and
/// the regression arm reds naming its directory; remove a real
/// `unsafe` without touching the table and the improvement arm reds.
#[test]
fn production_unsafe_only_ever_decreases_per_directory_16187() {
    let (per_dir, _production_files, _walked) = production_unsafe_census();

    let ceilings: std::collections::BTreeMap<&str, usize> =
        UNSAFE_CEILING_PER_DIR.iter().copied().collect();

    let mut regressions: Vec<String> = Vec::new();
    let mut improvements: Vec<String> = Vec::new();
    let mut uncovered: Vec<String> = Vec::new();

    for (dir, actual) in &per_dir {
        match ceilings.get(dir.as_str()) {
            Some(ceiling) if actual > ceiling => regressions.push(format!(
                "{dir}: {actual} production unsafe hits, ceiling {ceiling} (+{})",
                actual - ceiling
            )),
            Some(ceiling) if actual < ceiling => {
                improvements.push(format!("{dir}: {actual}, ceiling {ceiling}"))
            }
            Some(_) => {}
            None => uncovered.push(format!(
                "{dir}: {actual} production unsafe hits, no ceiling"
            )),
        }
    }
    // A ceiling row whose directory now measures ZERO and is absent
    // from the census is an improvement too (the census only records
    // directories with hits) — otherwise emptying a directory of
    // unsafe would leave its old ceiling standing as permission for
    // the next unsafe to return under.
    for (dir, ceiling) in &ceilings {
        if *ceiling > 0 && !per_dir.contains_key(*dir) {
            improvements.push(format!("{dir}: 0, ceiling {ceiling}"));
        }
    }

    assert!(
        uncovered.is_empty(),
        "{} director(ies) contain production unsafe with NO ceiling row:\n  {}\n\n\
         A new directory gained unsafe surface with no published baseline. \
         Add the directory to UNSAFE_CEILING_PER_DIR at the measured count \
         ONLY if the new unsafe is deliberate and reviewed — the ceiling is \
         the audit surface, so adding a row is the act of accepting it. \
         Prefer removing the unsafe.",
        uncovered.len(),
        uncovered.join("\n  ")
    );
    assert!(
        regressions.is_empty(),
        "{} director(ies) GAINED production unsafe:\n  {}\n\n\
         New unsafe in a packet-path binary must be a deliberate, visible \
         act (#16187). If this unsafe is genuinely required, raise the \
         named ceiling in UNSAFE_CEILING_PER_DIR in this same change and \
         say why in the commit — that diff is the review surface. If it \
         is not required, remove it. Do not delete this assertion.",
        regressions.len(),
        regressions.join("\n  ")
    );
    // Improvements are not a failure, but the ceiling must be
    // tightened or the ratchet silently stops ratcheting.
    assert!(
        improvements.is_empty(),
        "{} director(ies) now have FEWER production unsafe hits than their \
         ceiling. That is the fix working — tighten the ceiling in \
         UNSAFE_CEILING_PER_DIR to the new numbers so the ground gained \
         is held:\n  {}",
        improvements.len(),
        improvements.join("\n  ")
    );
}
