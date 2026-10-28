//! #17201 source-scan: no production lock acquisition may use a banned
//! poison shape. Compiled only under `cfg(test)` (declared in `main.rs`).
//!
//! Banned in production (engineering-style, #2402):
//! - `if let Ok(..) = <expr>.lock()/.read()/.write()` and the
//!   `let Ok(..) = .. else` form (silently skips the operation / empty state)
//! - `.lock()/.read()/.write() ... .map(..).unwrap_or_default()`,
//!   `.map(..).unwrap_or(0)` and `.map(..).unwrap_or(<non-literal-default>)`
//!   (substitutes EMPTY state)
//! - `.lock()/.read()/.write() ... .expect(..)` / `.unwrap()`, including
//!   the variable-mediated form `let g = <expr>.lock(); g.expect(..)` /
//!   `g.unwrap()` (panics on every later acquire), and
//!   `Condvar::wait_timeout(..).expect(..)`
//!
//! Production text is obtained with the shared #17152 blankers
//! (`test_support::source_scan`): comments/strings are blanked and
//! `#[cfg(test)] mod` bodies are blanked, and fixture files (files that
//! are `#[cfg(test)]` module targets, via `is_fixture`) are skipped — so
//! test code and historical prose may keep the banned spellings.
//! Documented exclusions, each counted exactly:
//! - the 3 deliberately fail-fast `server/lifecycle.rs` startup/teardown
//!   `.expect` sites (#9900, module comments document why);
//! - the 2 deliberately fail-closed neighbor-warmer sites in
//!   `afxdp/neighbor.rs` (one `.expect`, one GC `if let Ok`): the module
//!   doc states panicking/skipping there is the designed operator-visible
//!   failure, not a silent skip;
//! - the 3 `afxdp/ipsec_inner_queue.rs` sites owned by R4-Q10-01;
//! - `test_ports.rs`, a test utility compiled into the test binary only
//!   in effect (declared `#[cfg(test)]` in `main.rs`).
//! Any other banned shape — in any production file, including a file
//! added after this test — fails this test.

use std::path::{Path, PathBuf};

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn squash(src: &str) -> String {
    src.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Count banned hits in squashed production text. `expect` hits are
/// returned separately so the caller can apply the counted allow-list.

/// Additionally blank `#[cfg(test)]`-annotated ITEMS (fns, not just `mod`
/// bodies, which `blank_cfg_test_modules` handles). The shared blanker
/// only blanks inline test modules; production files also carry
/// `#[cfg(test)] fn` helpers whose lock spellings are test-only.
fn blank_cfg_test_items(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut removed = vec![false; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if trimmed.starts_with("#[cfg(test)]")
            || trimmed.starts_with("#[cfg(any(test")
            || trimmed.starts_with("#[cfg(all(test")
        {
            let mut j = i;
            let mut depth: i32 = 0;
            let mut started = false;
            while j < lines.len() {
                removed[j] = true;
                depth += lines[j].matches('{').count() as i32;
                depth -= lines[j].matches('}').count() as i32;
                if lines[j].contains('{') {
                    started = true;
                }
                if started && depth <= 0 {
                    break;
                }
                if !started && j > i && lines[j].trim_end().ends_with(';') {
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if removed[idx] {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn banned_hits(flat: &str) -> (Vec<String>, Vec<String>) {
    let mut hard: Vec<String> = Vec::new();
    let mut expect: Vec<String> = Vec::new();
    let ctx = |at: usize, len: usize| -> String {
        let s = at.saturating_sub(50);
        let e = (at + len + 50).min(flat.len());
        flat[s..e].to_string()
    };
    // if-let-Ok / let-Ok-else with a lock call within 120 chars.
    for pat in ["if let Ok("] {
        let mut start = 0;
        while let Some(pos) = flat[start..].find(pat) {
            let at = start + pos;
            let window = &flat[at..(at + 200).min(flat.len())];
            let lock_at = [".lock()", ".read()", ".write()"]
                .iter()
                .filter_map(|n| window.find(n))
                .min();
            if let Some(lock_at) = lock_at {
                if lock_at <= 120 {
                    hard.push(format!("{pat} lock: ...{}...", ctx(at, pat.len())));
                }
            }
            start = at + pat.len();
        }
    }
    // `let Ok(..) = ..lock() else` (excluding the `if let Ok(` already counted).
    {
        let total = flat.matches("let Ok(").count();
        let if_let = flat.matches("if let Ok(").count();
        if total > if_let {
            // Each remaining let-Ok is checked for a lock within 120 chars.
            let mut start = 0;
            while let Some(pos) = flat[start..].find("let Ok(") {
                let at = start + pos;
                if at >= 3 && &flat[at - 3..at] == "if " {
                    start = at + 7;
                    continue;
                }
                let window = &flat[at..(at + 200).min(flat.len())];
                let lock_at = [".lock()", ".read()", ".write()"]
                    .iter()
                    .filter_map(|n| window.find(n))
                    .min();
                if let Some(lock_at) = lock_at {
                    if lock_at <= 120 {
                        hard.push(format!("let Ok( lock else: ...{}...", ctx(at, 7)));
                    }
                }
                start = at + 7;
            }
        }
    }
    // .lock().map(..).unwrap_or_default() / .unwrap_or(0)
    for kind in [".lock()", ".read()", ".write()"] {
        let mut start = 0;
        while let Some(pos) = flat[start..].find(kind) {
            let at = start + pos;
            let window = &flat[at..(at + 300).min(flat.len())];
            // Skip the recovering idiom at THIS lock: `.lock().unwrap_or_else(..into_inner())`.
            let after_lock = &window[kind.len()..];
            if after_lock.trim_start().starts_with(".unwrap_or_else(") {
                start = at + kind.len();
                continue;
            }
            if let Some(map_at) = window.find(".map(") {
                let after = &window[map_at..];
                // The chain must close before the statement's `;`: an
                // unwrap in a LATER statement (e.g. `lock_tolerant(..); x.unwrap_or_default()`)
                // is not a lock-map-default chain.
                // `.unwrap_or_else(|e| e.into_inner())` is the RECOVERING
                // idiom itself, not a `.map(..)` chain: require `.map(`
                // to precede any recovering/other unwrap form.
                let stmt_end = after.find(';').unwrap_or(after.len());
                let chain = &after[..stmt_end];
                if chain.contains(".unwrap_or_else(") {
                    start = at + kind.len();
                    continue;
                }
                let unwrap_at = chain.find(".unwrap_or_default()").or_else(|| {
                    // `.unwrap_or(<arg>)` with a NON-literal-default argument
                    // (e.g. `unwrap_or(fallback)`, `unwrap_or(Vec::new())`)
                    // substitutes caller-chosen empty state just like
                    // `unwrap_or_default()`; only the recovering
                    // `unwrap_or_else(..into_inner())` (handled above) and
                    // a literal `0`... which is also banned — see below —
                    // are distinguished. In fact EVERY `.unwrap_or(` in a
                    // lock-map chain is banned here: `unwrap_or(0)` is the
                    // historical spelling, the rest are the same shape
                    // with a named default.
                    chain.find(".unwrap_or(")
                });
                if let Some(unwrap_at) = unwrap_at {
                    if map_at + unwrap_at <= 200 {
                        hard.push(format!(
                            "{kind}.map(..).unwrap_or_default(): ...{}...",
                            ctx(at, kind.len())
                        ));
                    }
                }
            }
            start = at + kind.len();
        }
    }
    // .lock()/.read()/.write() immediately followed by .expect( / .unwrap()
    // (squashing removes the newline between a trailing `.lock()` and its
    // `.expect(` on the next line, leaving `.lock().expect(` / `.lock() .expect(`).
    for kind in [".lock()", ".read()", ".write()"] {
        for tail in [".expect(", ".unwrap()"] {
            let needle = format!("{kind}{tail}");
            let mut start = 0;
            while let Some(pos) = flat[start..].find(&needle) {
                let at = start + pos;
                expect.push(format!("{needle}: ...{}...", ctx(at, needle.len())));
                start = at + needle.len();
            }
            let needle_sp = format!("{kind} {tail}");
            let mut start = 0;
            while let Some(pos) = flat[start..].find(&needle_sp) {
                let at = start + pos;
                expect.push(format!("{needle_sp}: ...{}...", ctx(at, needle_sp.len())));
                start = at + needle_sp.len();
            }
        }
    }
    // wait_timeout(..).expect(
    let mut start = 0;
    while let Some(pos) = flat[start..].find("wait_timeout(") {
        let at = start + pos;
        let window = &flat[at..(at + 200).min(flat.len())];
        if window.contains(".expect(") {
            expect.push(format!("wait_timeout(..).expect(: ...{}...", ctx(at, 13)));
        }
        start = at + "wait_timeout(".len();
    }
    // Variable-mediated expect/unwrap: `let g = <expr>.lock(); g.expect(..)`
    // / `g.unwrap()` / `g.unwrap_or(..)`. The direct-chain scan above only
    // sees `.lock().expect(`; binding the lock RESULT to a name first and
    // consuming it in a later statement evaded it. Track simple bindings
    // `let <name> = <expr>.lock()/.read()/.write()` (also the tuple form
    // `let (<name>, ..) = ..wait_timeout(..)`) and flag any later
    // `<name>.expect(` / `<name>.unwrap()` / `<name>.unwrap_or(` /
    // `<name>.unwrap_or_default()` in the same squashed text. The
    // recovering idiom binds a GUARD (`let g = lock_tolerant(..)` — no
    // `.lock()` on the RHS), so it is not tracked.
    {
        let lock_kinds = [".lock()", ".read()", ".write()", "wait_timeout("];
        let mut start = 0;
        while let Some(pos) = flat[start..].find("let ") {
            let at = start + pos;
            let stmt_end = flat[at..]
                .find(';')
                .map(|e| at + e)
                .unwrap_or(flat.len());
            let stmt = &flat[at..stmt_end];
            start = at + 4;
            if !lock_kinds.iter().any(|k| stmt.contains(k)) {
                continue;
            }
            // Binding name: text between `let ` (skipping `mut `) and `=`.
            let Some(eq) = stmt.find('=') else { continue };
            let mut name = stmt[4..eq].trim();
            if let Some(rest) = name.strip_prefix("mut ") {
                name = rest.trim();
            }
            // Tuple destructuring: take the first bound identifier.
            if name.starts_with('(') {
                name = name
                    .trim_start_matches('(')
                    .split([',', ')'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches("mut ")
                    .trim();
            }
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            for tail in [".expect(", ".unwrap()", ".unwrap_or(", ".unwrap_or_default()"] {
                let needle = format!("{name}{tail}");
                let mut s2 = stmt_end;
                while let Some(p2) = flat[s2..].find(&needle) {
                    let at2 = s2 + p2;
                    expect.push(format!(
                        "variable-mediated {needle}: ...{}...",
                        ctx(at2, needle.len())
                    ));
                    s2 = at2 + needle.len();
                }
            }
        }
    }
    // Direct `.lock()/.read()/.write() ... .unwrap_or(<non-literal>)`:
    // `x.lock().unwrap_or(fallback)` (no `.map(..)`) substitutes the
    // fallback on poison exactly like the map form. Flag any
    // `.unwrap_or(` / `.unwrap_or_default()` within the same statement
    // after a lock call (the recovering `.unwrap_or_else(` is excluded
    // by construction — different needle).
    for kind in [".lock()", ".read()", ".write()"] {
        let mut start = 0;
        while let Some(pos) = flat[start..].find(kind) {
            let at = start + pos;
            let stmt_end = flat[at..]
                .find(';')
                .map(|e| at + e)
                .unwrap_or((at + 300).min(flat.len()));
            let chain = &flat[at..stmt_end];
            if chain.contains(".unwrap_or_else(") {
                start = at + kind.len();
                continue;
            }
            // Only the RESULT of the lock call carries poison: flag
            // `.unwrap_or(` / `.unwrap_or_default()` when it is applied
            // directly to the lock result or through a `.map(..)` on it
            // (the map-chain scan above already reports the map form;
            // this catches the no-map direct form). An `unwrap_or` on a
            // value EXTRACTED from the guard (`.lock().unwrap_or_else(..)
            // .field`, `guard.get(..).unwrap_or(..)`, a `.clone()` of
            // recovered state, ...) is ordinary Option handling, not a
            // poison shape — requiring `.map(` or an immediate
            // `.unwrap_or` right after the lock call keeps those clean.
            let after_lock = &chain[kind.len()..];
            let direct = after_lock.trim_start().starts_with(".unwrap_or(")
                || after_lock.trim_start().starts_with(".unwrap_or_default()");
            if direct {
                hard.push(format!(
                    "{kind}...unwrap_or(non-default): ...{}...",
                    ctx(at, kind.len())
                ));
            }
            start = at + kind.len();
        }
    }
    (hard, expect)
}

#[test]
fn scan_detects_variable_mediated_and_nonliteral_unwrap_or_17201() {
    // Reviewer mutants that evaded the pre-fold scan: each snippet MUST
    // produce a banned hit. Squash first, exactly as the production scan
    // does.
    let mutants: &[(&str, &str)] = &[
        (
            "variable-mediated expect",
            "fn f(m: &Mutex<u32>) { let g = m.lock(); g.expect(\"poison\"); }",
        ),
        (
            "variable-mediated unwrap",
            "fn f(m: &Mutex<u32>) { let g = m.lock(); let _v = g.unwrap(); }",
        ),
        (
            "variable-mediated read expect",
            "fn f(l: &RwLock<u32>) { let g = l.read(); g.expect(\"poison\"); }",
        ),
        (
            "unwrap_or with non-literal default (map form)",
            "fn f(m: &Mutex<Vec<u32>>) -> Vec<u32> { m.lock().map(|g| g.clone()).unwrap_or(fallback) }",
        ),
        (
            "unwrap_or with non-literal default (direct form)",
            "fn f(m: &Mutex<u32>) -> u32 { m.lock().unwrap_or(fallback) }",
        ),
        (
            "unwrap_or_default via variable",
            "fn f(m: &Mutex<Vec<u32>>) -> Vec<u32> { let g = m.lock(); g.unwrap_or_default() }",
        ),
    ];
    for (name, src) in mutants {
        let (hard, expect) = banned_hits(&squash(src));
        assert!(
            !hard.is_empty() || !expect.is_empty(),
            "scan must flag the {name} mutant: {src:?} (hard={hard:?} expect={expect:?})"
        );
    }
    // The recovering idioms and clean code must NOT be flagged.
    let clean: &[&str] = &[
        "fn f(m: &Mutex<u32>) { let g = crate::sync_util::lock_tolerant(m); drop(g); }",
        "fn f(m: &Mutex<u32>) { let g = m.lock().unwrap_or_else(|e| e.into_inner()); drop(g); }",
        "fn f(m: &Mutex<u32>) { let g = lock_tolerant_counted(m, Some(&C)); drop(g); }",
    ];
    for src in clean {
        let (hard, expect) = banned_hits(&squash(src));
        assert!(
            hard.is_empty() && expect.is_empty(),
            "scan must not flag clean code: {src:?} (hard={hard:?} expect={expect:?})"
        );
    }
}

#[test]
fn no_banned_lock_poison_shapes_in_production_17201() {
    use crate::test_support::source_scan::{
        blank_cfg_test_modules, blank_comments_and_strings, is_fixture,
    };
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);
    files.sort();
    assert!(!files.is_empty());

    // Counted exclusions: file suffix -> (hard allowance, expect allowance).
    let allowances: &[(&str, usize, usize)] = &[
        ("server/lifecycle.rs", 0, 3),
        ("afxdp/neighbor.rs", 1, 1),
        ("afxdp/ipsec_inner_queue.rs", 3, 0),
    ];

    let mut failures: Vec<String> = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "sync_util_scan_tests.rs" || rel == "sync_util.rs" || rel == "test_ports.rs" {
            continue;
        }
        if is_fixture(&src_root, &rel) {
            continue;
        }
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let prod = blank_cfg_test_items(&blank_cfg_test_modules(&blank_comments_and_strings(&raw)));
        let flat = squash(&prod);
        let (hard, expect) = banned_hits(&flat);
        let (allow_hard, allow_expect) = allowances
            .iter()
            .find(|(suffix, _, _)| rel.ends_with(suffix))
            .map(|(_, h, e)| (*h, *e))
            .unwrap_or((0, 0));
        if hard.len() > allow_hard {
            failures.push(format!(
                "{rel}: {} banned non-expect lock shapes (allowed {allow_hard}):\n  {}",
                hard.len(),
                hard.join("\n  ")
            ));
        }
        if expect.len() > allow_expect {
            failures.push(format!(
                "{rel}: {} banned expect/unwrap lock shapes (allowed {allow_expect}):\n  {}",
                expect.len(),
                expect.join("\n  ")
            ));
        }
        let _ = count_occurrences;
    }
    assert!(
        failures.is_empty(),
        "banned lock-poison shapes in production (#17201):\n{}",
        failures.join("\n")
    );
}
