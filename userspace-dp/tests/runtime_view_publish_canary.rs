//! #6592 publish/read canary — defence in depth over the atomic
//! `(validation, forwarding)` pairing.
//!
//! # The type system is the boundary; this file is the backstop
//!
//! An earlier version of this canary WAS the write-capability boundary, and a
//! review probe showed that was fail-open. `HaState::runtime_reader` returned
//! the writable `Arc<ArcSwap<RuntimeView>>` and `RuntimeView` was `Clone` with
//! reachable fields, so production code could do:
//!
//! ```ignore
//! let alias = self.ha.runtime_reader();
//! let mut torn = alias.load_full().as_ref().clone();
//! torn.validation.fib_generation = torn.validation.fib_generation.wrapping_add(1);
//! alias.store(Arc::new(torn));
//! ```
//!
//! That compiled, published the exact `(new validation, old forwarding)` tear,
//! and every rule below passed: the store was not the choke point's literal
//! spelling, and the view came from a CLONE, not a construction — so the
//! "a publish needs a constructed view" argument was simply false. Enumerating
//! bypasses had by then failed twice on this canary (the first was a
//! rustfmt-wrapped method chain).
//!
//! The capability is now enforced by types, and each of those three lines is
//! independently a COMPILE error:
//!
//! - `runtime_reader()` returns [`RuntimeViewReader`], whose `ArcSwap` is a
//!   private field and whose only method is `load()`. No consumer can obtain a
//!   writer, so `alias.store(..)` and `alias.load_full()` do not exist.
//! - `RuntimeView` is not `Clone`, so `.as_ref().clone()` does not compile —
//!   `RuntimeView::new` is now the ONLY way to obtain a view value anywhere.
//! - `RuntimeView`'s fields are private, so `torn.validation.x = ..` does not
//!   compile.
//! - The coordinator's own handle is [`RuntimeViewChannel`], which likewise
//!   hides the `ArcSwap`: `publish` is the only mutation, so `swap`, `rcu`,
//!   `compare_and_swap` and `Deref` are unreachable rather than merely
//!   unmentioned by a regex.
//!
//! What remains for this file is the residue types cannot express: a NEW site
//! inside `coordinator/` calling `self.ha.runtime.publish(RuntimeView::new(
//! stale_validation, fwd))`, and a second view load inside one worker tick.
//! Because `RuntimeView` is no longer `Clone`, "a publish needs a CONSTRUCTED
//! view" is now a true statement rather than an enumeration, which is what
//! makes rule 2 meaningful.
//!
//! # What it pins
//!
//! 1. **One publish, and the writer stays inside its type.** Exactly one
//!    `.runtime.publish(` in the tree, at the choke point; and no file outside
//!    the type's own module may name `ArcSwap<RuntimeView>` — that spelling
//!    reappearing means the raw writer has escaped again, which is precisely
//!    how the probe got in.
//! 2. **No view constructed outside the choke point.** Sites outside the type's
//!    own module must be the choke point, or carry the marker
//!    `runtime-view-canary: test-local` — which is honoured ONLY in a file's
//!    test half, so it cannot silence production code.
//! 3. **One load per reader.** Each production reader takes BOTH halves from a
//!    single `load()`. Residual, stated rather than papered over: the count
//!    keys on the `shared_runtime.load(` spelling, so a future reader that
//!    binds its handle to another name evades the COUNT (it fails closed for
//!    any file that does use the spelling). The type system covers the worse
//!    half of that: every `load()` yields one coherent view, so a single call
//!    can never tear a pair — only two calls in one tick can.
//!
//! # Which half a line is in
//!
//! Rules 2 and 3 need to tell production code from test code, and an earlier
//! version did it by TRUNCATING each file at its first top-level
//! `#[cfg(test)]`. A hostile review showed that is fail-open, not conservative:
//! `#[cfg(test)]` on an item hides only THAT item, and in
//! `src/afxdp/coordinator/mod.rs` the first one sits on a test-only `use` at
//! line 35 — so 1200+ lines of production code, including the publish choke
//! point itself and the exact site where the residue above would be written,
//! were silently excluded from the scan. [`split_halves`] therefore tracks
//! regions: it skips the attributed item (or, for `mod`/`impl`/`macro!` forms,
//! its brace-delimited body) and KEEPS SCANNING. Brace tracking runs over
//! comment- and literal-masked text so a `"{"` in a string cannot desync it.
//!
//! Adding a legitimate site is meant to be possible — update the table below
//! and say why in the PR. Silently growing one is not.

use std::fs;
use std::path::{Path, PathBuf};

/// Marker that exempts a `RuntimeView` construction line (rule 2). Test-local
/// views built for a test-local channel never reach a worker.
///
/// Honoured ONLY in a file's TEST half (after the first top-level
/// `#[cfg(test)]`). A reviewer pointed out that an unconstrained marker
/// silences production code just as happily — so a production line carrying it
/// still counts.
const TEST_LOCAL_MARKER: &str = "runtime-view-canary: test-local";

/// Rule 1: the only file allowed to publish into the runtime channel.
const PUBLISH_CHOKE_POINT: &str = "src/afxdp/coordinator/mod.rs";

/// Rule 2: the module that DEFINES `RuntimeView` may construct it freely (its
/// own constructor and `Default` impl live there).
const RUNTIME_VIEW_DEFINITION: &str = "src/afxdp/types/runtime_view.rs";

/// Rule 2: production construction sites outside the definition module, as
/// `(file, expected_count, why)`.
const ALLOWED_CONSTRUCTION: &[(&str, usize, &str)] = &[
    (
        "src/afxdp/coordinator/mod.rs",
        1,
        "Coordinator::store_runtime_view — THE choke point; builds the view from \
         self.validation at the store",
    ),
];

/// Rule 3: production reader load sites, as `(file, expected_count, why)`.
/// Counted over the file's production code — everything outside a top-level
/// `#[cfg(test)]` item, which is NOT the same as everything above the first one
/// (see [`split_halves`]).
const ALLOWED_READER_LOADS: &[(&str, usize, &str)] = &[
    (
        "src/afxdp/worker/loop_body/mod.rs",
        1,
        "refresh_runtime_view — the per-tick worker refresh; BOTH halves come \
         from this one load",
    ),
    (
        "src/afxdp/worker/loop_body/setup.rs",
        1,
        "worker_loop_setup — the startup seed; same single-load rule so a fresh \
         worker cannot start on a torn pair",
    ),
    (
        "src/afxdp/tunnel.rs",
        1,
        "local_tunnel_source_loop — seeds the GRE local-origin thread's \
         forwarding half (it does not match generation stamps)",
    ),
    (
        "src/afxdp/session_glue/install_table_purge.rs",
        1,
        "fenced purge predicate — forwarding half ONLY (registry + fallback \
         sets for one stamp check), never paired with validation, so it \
         cannot tear a pair (#9752)",
    ),
    (
        "src/afxdp/types/runtime_view.rs",
        1,
        "load_forwarding_if_changed — the #1188 short-circuit for \
         forwarding-only readers",
    ),
];

#[derive(Debug)]
struct Violation {
    rule: &'static str,
    detail: String,
}

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("cannot read {} — {err}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Stand-in for a line that belongs to the OTHER half.
///
/// Deliberately not the empty string. [`code_blob_no_whitespace`] deletes all
/// whitespace and concatenates what is left, so eliding a region with blanks
/// could splice the tail of one surviving line onto the head of another across
/// the gap and manufacture a match present in neither. A NUL is not whitespace,
/// so it breaks that adjacency, and it is not a comment, so [`code_lines`]
/// keeps it.
const ELIDED: &str = "\u{0}";

/// `content` with every byte inside a comment, string literal or char literal
/// replaced by a space, and every other byte kept verbatim.
///
/// Byte- and line-aligned with `content`: multi-byte characters are masked to
/// as many spaces as they occupy and newlines are always restored, so an offset
/// into the mask is the same offset into the original. Only region detection
/// reads the mask — the halves are always built from the ORIGINAL lines.
///
/// Masking is what makes brace tracking trustworthy. `"{"` in a string literal
/// or a `//` comment would otherwise desync the depth counter for the rest of
/// the file, and desync is not a benign failure here: it decides which half a
/// line lands in.
fn mask_non_code(content: &str) -> String {
    let b = content.as_bytes();
    let n = b.len();
    let mut out = vec![b' '; n];
    let mut i = 0usize;
    // A leading `#!` line is a SHEBANG: rustc strips it before tokenization, so
    // its bytes are not code and its delimiters must not be counted. Only at
    // offset 0, and only when not `#![`, which is an inner attribute and IS
    // code. Missing this let a legal `#!/usr/bin/env rust-script }` desync the
    // depth counter for the whole file.
    if n >= 2 && b[0] == b'#' && b[1] == b'!' && !(n >= 3 && b[2] == b'[') {
        while i < n && b[i] != b'\n' {
            i += 1;
        }
    }
    while i < n {
        match b[i] {
            b'/' if i + 1 < n && b[i + 1] == b'/' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                // Rust block comments nest.
                let mut depth = 1usize;
                i += 2;
                while i < n && depth > 0 {
                    if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'r' | b'b' | b'c' if raw_string_open(b, i).is_some() => {
                let (quote, hashes) = raw_string_open(b, i).expect("just checked");
                i = quote + 1;
                while i < n {
                    if b[i] == b'"' {
                        let mut k = i + 1;
                        let mut seen = 0usize;
                        while k < n && seen < hashes && b[k] == b'#' {
                            seen += 1;
                            k += 1;
                        }
                        if seen == hashes {
                            i = k;
                            break;
                        }
                    }
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < n {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            b'\'' => match char_literal_end(b, i) {
                Some(end) => i = end + 1,
                // A lifetime tick, not a literal — ordinary code.
                None => {
                    out[i] = b[i];
                    i += 1;
                }
            },
            _ => {
                out[i] = b[i];
                i += 1;
            }
        }
    }
    for (idx, byte) in b.iter().enumerate() {
        if *byte == b'\n' {
            out[idx] = b'\n';
        }
    }
    String::from_utf8(out).expect("masking only ever substitutes ASCII spaces")
}

/// If a raw string literal opens at `at`, its opening quote offset and hash
/// count.
///
/// Covers every raw form in the language: `r"..."` / `r#"..."#` / `r##"..."##`,
/// the byte-string `br` forms, and the C-string `cr` forms. The `cr` prefix was
/// MISSING and a hostile review used exactly that: `cr#""{"#` desynchronised
/// brace tracking, `production_half` then returned the following production
/// function as elided NULs, and its `shared_runtime.load()` became invisible to
/// rule 3. The prefix set is now enumerated from the grammar rather than from
/// the shapes that happened to appear in this tree — see `LITERAL_SHAPES` in
/// the self-tests for the full matrix and for what is deliberately not covered.
fn raw_string_open(b: &[u8], at: usize) -> Option<(usize, usize)> {
    // Must be the start of a token, or this is the `r` in `for`.
    if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
        return None;
    }
    let mut k = at;
    // `b` (byte string) or `c` (C string) may prefix the `r`.
    if b[k] == b'b' || b[k] == b'c' {
        k += 1;
    }
    if k >= b.len() || b[k] != b'r' {
        return None;
    }
    k += 1;
    let mut hashes = 0usize;
    while k < b.len() && b[k] == b'#' {
        hashes += 1;
        k += 1;
    }
    if k < b.len() && b[k] == b'"' {
        Some((k, hashes))
    } else {
        None
    }
}

/// If a char literal starts at `at`, the offset of its closing tick. `None`
/// means the tick opens a lifetime (`&'a T`), which is ordinary code.
///
/// The case that matters is `'{'` / `'}'` / `'"'` and the escape form
/// `'\u{1F600}'` — each carries a brace or a quote that would otherwise be
/// counted.
fn char_literal_end(b: &[u8], at: usize) -> Option<usize> {
    let n = b.len();
    if at + 1 >= n {
        return None;
    }
    if b[at + 1] == b'\\' {
        // `'\''`, `'\\'`, `'\n'`, `'\u{1F600}'` — the byte after the backslash
        // is always part of the escape, so the search starts past it.
        let limit = (at + 16).min(n);
        let mut k = at + 3;
        while k < limit {
            if b[k] == b'\n' {
                return None;
            }
            if b[k] == b'\'' {
                return Some(k);
            }
            k += 1;
        }
        return None;
    }
    let width = match b[at + 1] {
        x if x < 0x80 => 1,
        x if x < 0xE0 => 2,
        x if x < 0xF0 => 3,
        _ => 4,
    };
    let close = at + 1 + width;
    if close < n && b[close] == b'\'' {
        Some(close)
    } else {
        None
    }
}

/// Byte offset at which each line of `content` starts.
fn line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (idx, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

fn line_of(starts: &[usize], offset: usize) -> usize {
    match starts.binary_search(&offset) {
        Ok(idx) => idx,
        Err(idx) => idx - 1,
    }
}

/// End offset (inclusive) of the item that the attribute beginning at `at`
/// applies to, over MASKED text.
///
/// This is the whole point of region tracking. `#[cfg(test)]` on an item hides
/// only THAT item — a `use`, a `const`, an `impl`, a `mod` — and the code after
/// it is production. Only the brace-delimited forms introduce a region.
///
/// Terminates at whichever comes first:
///   * a `;` outside any bracket (`mod tests;`, `use a::b;`, `static X: T = v;`)
///   * the `}` that closes the item's own body, plus a trailing `;` if present
///     (`mod tests { .. }`, `impl T { .. }`, `use a::{b, c};`)
fn attributed_item_end(masked: &[u8], at: usize) -> usize {
    let n = masked.len();
    let mut i = at;
    // Consume the whole attribute run — `#[cfg(test)]` is routinely followed by
    // `#[path = "..._tests.rs"]` before the item it attributes.
    loop {
        while i < n && masked[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n || masked[i] != b'#' {
            break;
        }
        let mut j = i + 1;
        if j < n && masked[j] == b'!' {
            j += 1;
        }
        if j >= n || masked[j] != b'[' {
            break;
        }
        let mut depth = 0i64;
        while j < n {
            match masked[j] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        i = j + 1;
    }
    // `i` now sits on the item itself.
    let mut brace = 0i64;
    let mut aux = 0i64;
    let mut saw_brace = false;
    while i < n {
        match masked[i] {
            b'{' => {
                // Only a brace at `aux == 0` can be the ITEM's own body. A brace
                // inside `()`/`[]` belongs to a macro argument, an array, or a
                // struct literal in a call — counting it as the body is how a
                // hostile review got `#[cfg(test)] swallow!({} #[cfg(test)]
                // garbage);` to "end" at its inner `{}`, leaving the trailing
                // attribute-shaped tokens to be read as top level and eliding
                // the production function after them.
                if aux == 0 {
                    saw_brace = true;
                }
                brace += 1;
            }
            b'}' => {
                brace -= 1;
                if saw_brace && brace == 0 && aux == 0 {
                    let mut k = i + 1;
                    while k < n && masked[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    return if k < n && masked[k] == b';' { k } else { i };
                }
            }
            b'(' | b'[' => aux += 1,
            b')' | b']' => aux -= 1,
            b';' if brace == 0 && aux == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    n.saturating_sub(1)
}

/// Inclusive line ranges covered by a top-level `#[cfg(test)]` item.
///
/// Region tracking, not truncation. The previous implementation cut the file at
/// its FIRST top-level `#[cfg(test)]` and treated everything below as test
/// code. A hostile review showed that is fail-open: in
/// `src/afxdp/coordinator/mod.rs` the first such attribute sits on a test-only
/// `use` at line 35, so 1200+ lines of production code — INCLUDING the publish
/// choke point itself — were being discarded from the scan. An explicit
/// construct-and-publish added below that line was invisible to rule 2 and any
/// production load was invisible to rule 3. A canary blind to the file it most
/// needs to watch is worse than no canary.
fn test_regions(content: &str) -> Vec<(usize, usize)> {
    const CFG_TEST: &str = "#[cfg(test)]";
    let masked = mask_non_code(content);
    let mb = masked.as_bytes();
    let starts = line_starts(content);
    let mut regions = Vec::new();
    let mut brace = 0i64;
    let mut aux = 0i64;
    let mut i = 0usize;
    while i < mb.len() {
        let top_level_cfg_test = brace == 0
            && aux == 0
            && mb[i] == b'#'
            && masked[i..].starts_with(CFG_TEST)
            && mb[starts[line_of(&starts, i)]..i]
                .iter()
                .all(u8::is_ascii_whitespace);
        if top_level_cfg_test {
            let end = attributed_item_end(mb, i);
            regions.push((line_of(&starts, i), line_of(&starts, end)));
            // The item is brace-balanced, so depth is still 0 after it.
            i = end + 1;
            continue;
        }
        match mb[i] {
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'(' | b'[' => aux += 1,
            b')' | b']' => aux -= 1,
            _ => {}
        }
        i += 1;
    }
    regions
}

/// Split a file into its production and test text, line by line.
///
/// The two halves are line-aligned with the original: every line appears
/// verbatim in exactly one half and as [`ELIDED`] in the other.
fn split_halves(content: &str) -> (String, String) {
    let regions = test_regions(content);
    let mut production = String::with_capacity(content.len());
    let mut test = String::with_capacity(content.len() / 4);
    for (idx, line) in content.lines().enumerate() {
        let in_test = regions
            .iter()
            .any(|(first, last)| idx >= *first && idx <= *last);
        let (mine, theirs) = if in_test {
            (&mut test, &mut production)
        } else {
            (&mut production, &mut test)
        };
        mine.push_str(line);
        mine.push('\n');
        theirs.push_str(ELIDED);
        theirs.push('\n');
    }
    (production, test)
}

/// The file's production code: everything outside a top-level `#[cfg(test)]`
/// item, with the test regions elided line for line.
fn production_half(content: &str) -> String {
    split_halves(content).0
}

/// Lines of CODE — comment-only lines dropped.
///
/// Load-bearing, not cosmetic: this file's own subject matter is documented in
/// the very comments it scans. The `#6592` docs quote `ha.runtime.store(`,
/// `RuntimeView::default()` and `shared_runtime.load()` in prose, and counting
/// those made the canary fire on its own documentation — a false positive that
/// would have been "fixed" by weakening the counts. A trailing comment on a
/// line that also holds code is kept, so the `TEST_LOCAL_MARKER` still works and
/// a construction cannot hide behind one.
fn code_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
}

/// Comment-stripped code with ALL whitespace removed.
///
/// Also load-bearing. rustfmt wraps a long method chain, so a real bypass reads
///
/// ```text
/// self.ha
///     .runtime
///     .store(Arc::new(RuntimeView::new(stale, fwd)));
/// ```
///
/// and the substring `.runtime.store(` never appears on any single line. A
/// line-based count silently missed exactly that shape when this canary was
/// fire-probed — the "canary that cannot fire" failure mode. Collapsing
/// whitespace makes the chain match regardless of how it is wrapped.
fn code_blob_no_whitespace(content: &str) -> String {
    code_lines(content)
        .flat_map(|line| line.chars())
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

/// Does this line CONSTRUCT a `RuntimeView` (as opposed to naming the type in a
/// signature)? `-> RuntimeView {` is a return type, not a construction.
fn constructs_runtime_view(line: &str) -> bool {
    if line.contains("RuntimeView::new(") || line.contains("RuntimeView::default()") {
        return true;
    }
    line.contains("RuntimeView {") && !line.contains("-> RuntimeView {")
}

/// Rule 1b: does this line name the raw `ArcSwap<RuntimeView>`?
///
/// Outside the type's own module that spelling means the write capability has
/// escaped its wrapper — exactly what let a review probe alias the writer and
/// publish a torn pair. Whitespace is already stripped by the caller so a
/// wrapped generic (`ArcSwap<\n    RuntimeView>`) still matches.
fn names_raw_runtime_arcswap(code_no_whitespace: &str) -> usize {
    code_no_whitespace.matches("ArcSwap<RuntimeView>").count()
}

/// Rule 1 + rule 2, over one file's full content.
fn scan_publish(rel: &str, content: &str, violations: &mut Vec<Violation>) {
    let stores = code_blob_no_whitespace(content)
        .matches(".runtime.publish(")
        .count();
    if rel == PUBLISH_CHOKE_POINT {
        if stores != 1 {
            violations.push(Violation {
                rule: "1 (one publish)",
                detail: format!(
                    "{rel}: found {stores} `.runtime.publish(` — expected exactly 1 \
                     (Coordinator::store_runtime_view). Every publish must go \
                     through the choke point so the view is built from \
                     self.validation AT the store; a second store site can pair a \
                     stale validation with new forwarding and neither #6592 \
                     RED-on-revert test would see it."
                ),
            });
        }
    } else if stores != 0 {
        violations.push(Violation {
            rule: "1 (one publish)",
            detail: format!(
                "{rel}: {stores} `.runtime.publish(` outside the choke point \
                 ({PUBLISH_CHOKE_POINT}). Publish via \
                 Coordinator::publish_runtime_view or \
                 republish_runtime_validation instead."
            ),
        });
    }

    // Rule 1b: the raw writable `ArcSwap<RuntimeView>` must not be nameable
    // outside the type's own module. Its escape is how the probe got in.
    if rel != RUNTIME_VIEW_DEFINITION {
        let raw = names_raw_runtime_arcswap(&code_blob_no_whitespace(content));
        if raw != 0 {
            violations.push(Violation {
                rule: "1b (writer stays inside its type)",
                detail: format!(
                    "{rel}: names `ArcSwap<RuntimeView>` {raw} time(s). The raw \
                     writable ArcSwap must not leave `{RUNTIME_VIEW_DEFINITION}` \
                     — anything holding it can `store`/`swap`/`rcu` a torn pair \
                     past the choke point, which is exactly the bypass this \
                     canary previously missed. Take a `RuntimeViewReader` (read \
                     only) or use the coordinator's `RuntimeViewChannel`."
                ),
            });
        }
    }

    if rel == RUNTIME_VIEW_DEFINITION {
        return;
    }
    // The `test-local` marker is honoured ONLY in a file's TEST half. Left
    // unconstrained it silences PRODUCTION code — a reviewer flagged that the
    // marker's mere presence on any line suppressed the rule. Which half a line
    // lands in comes from region tracking, not from truncating at the first
    // `#[cfg(test)]`: under truncation every line below a test-only `use` was
    // "test half", so the marker silenced production code after all.
    let (production, test_half) = split_halves(content);
    let constructions = code_lines(&production)
        .filter(|line| constructs_runtime_view(line))
        .count()
        + code_lines(&test_half)
            .filter(|line| {
                constructs_runtime_view(line) && !line.contains(TEST_LOCAL_MARKER)
            })
            .count();
    let expected = ALLOWED_CONSTRUCTION
        .iter()
        .find(|(file, _, _)| *file == rel)
        .map(|(_, count, _)| *count)
        .unwrap_or(0);
    if constructions != expected {
        let why = ALLOWED_CONSTRUCTION
            .iter()
            .find(|(file, _, _)| *file == rel)
            .map(|(_, _, why)| *why)
            .unwrap_or("no construction allowed here");
        violations.push(Violation {
            rule: "2 (no view built outside the choke point)",
            detail: format!(
                "{rel}: {constructions} RuntimeView construction(s), expected \
                 {expected} ({why}). `RuntimeView` is not Clone, so construction \
                 is the ONLY way to obtain a view value — which makes this the \
                 rule that catches a publish however it reaches the channel. If \
                 the site is a test-local view for a test-local channel, put \
                 `{TEST_LOCAL_MARKER}` on the construction line IN THE FILE'S \
                 TEST HALF; otherwise publish through the choke point."
            ),
        });
    }
}

/// Rule 3, over one file's PRODUCTION half.
fn scan_reader_loads(rel: &str, production: &str, violations: &mut Vec<Violation>) {
    let loads = code_blob_no_whitespace(production)
        .matches("shared_runtime.load(")
        .count();
    let expected = ALLOWED_READER_LOADS
        .iter()
        .find(|(file, _, _)| *file == rel)
        .map(|(_, count, _)| *count)
        .unwrap_or(0);
    if loads != expected {
        let why = ALLOWED_READER_LOADS
            .iter()
            .find(|(file, _, _)| *file == rel)
            .map(|(_, _, why)| *why)
            .unwrap_or("this file is not a runtime-view reader");
        violations.push(Violation {
            rule: "3 (one load per reader)",
            detail: format!(
                "{rel}: {loads} production runtime-view load(s), expected \
                 {expected} ({why}). Two loads in the same tick can observe two \
                 different views and pair halves across generations — the exact \
                 defect #6592 closed. Take both halves from ONE load."
            ),
        });
    }
}

#[test]
fn runtime_view_publish_and_read_sites_are_pinned() {
    let src = crate_src();
    let mut violations = Vec::new();
    for path in rust_sources(&src) {
        let rel = format!(
            "src/{}",
            path.strip_prefix(&src)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/")
        );
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read {} — {err}", path.display()));
        scan_publish(&rel, &content, &mut violations);
        scan_reader_loads(&rel, &production_half(&content), &mut violations);
    }

    // Every entry in the tables must correspond to a real file, or the table has
    // rotted into a rule that can never fire (a canary that cannot fire is worse
    // than no canary).
    for (file, _, _) in ALLOWED_CONSTRUCTION.iter().chain(ALLOWED_READER_LOADS) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        assert!(
            path.exists(),
            "{file} is listed in a runtime-view canary table but does not exist — \
             the entry is dead and its rule can never fire; fix the path or drop \
             the entry"
        );
    }

    assert!(
        violations.is_empty(),
        "#6592 runtime-view canary: {} violation(s)\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  [rule {}] {}", v.rule, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[cfg(test)]
mod self_tests {
    use super::*;

    /// Every token shape in Rust's literal/comment grammar that can legally
    /// contain an unbalanced `{`, as `(name, token, why it matters)`.
    ///
    /// The masking pass exists so brace tracking cannot be desynchronised by a
    /// brace that is not code. This table is the grammar-derived enumeration of
    /// what that means, replacing the previous approach of extending the pass
    /// one shape at a time as reviews found them — which failed twice: first on
    /// a rustfmt-wrapped chain, then on `cr#""{"#`, the raw C string.
    ///
    /// Each entry is exercised by `every_literal_shape_that_can_hide_a_brace`
    /// below, and each has been verified by MUTATION: with that shape's
    /// handling removed from `mask_non_code`, its row — and only its row —
    /// turns RED. See the matrix in the PR description.
    const LITERAL_SHAPES: &[(&str, &str, &str)] = &[
        ("line comment", "// {", "`//` runs to end of line"),
        ("block comment", "/* { */", "`/* */` spans lines"),
        (
            "nested block comment",
            "/* /* */ { */",
            "Rust block comments NEST, unlike C. The brace sits after the INNER \
             close on purpose: with the brace before it, a non-nesting masker \
             still covers the brace by accident and the row cannot fail.",
        ),
        ("char literal", "let _ = '{';", "a brace as a char value"),
        (
            "char escape with braces",
            r"let _ = '\u{7b}';",
            "the unicode escape form itself contains braces",
        ),
        ("byte char literal", "let _ = b'{';", "`b'..'` byte form"),
        ("string", "let _ = \"{\";", "the ordinary form"),
        (
            "string with escaped quote",
            "let _ = \"\\\"{\";",
            "an escaped quote must not end the literal early",
        ),
        ("byte string", "let _ = b\"{\";", "`b\"..\"`"),
        ("C string", "let _ = c\"{\";", "`c\"..\"`, Rust 1.77+"),
        ("raw string", "let _ = r\"{\";", "no escapes, no hashes"),
        ("raw string, 1 hash", "let _ = r#\"{\"#;", "`r#\"..\"#`"),
        (
            "raw string, 2 hashes",
            "let _ = r##\"{\"##;",
            "the hash count must be matched exactly",
        ),
        (
            "raw byte string",
            "let _ = br#\"\"{\"#;",
            "`br#\"..\"#` whose content STARTS with a quote. Without that the \
             plain-string arm masks the brace by accident and the `b` prefix is \
             never exercised; with it, a masker that misses the prefix closes \
             the literal at the inner quote and leaves the brace bare.",
        ),
        (
            "raw C string",
            "let _ = cr#\"\"{\"#;",
            "`cr#\"..\"#` whose content starts with a quote — the shape a \
             hostile review used to blind rule 3, and discriminating for the \
             same reason as the byte form above",
        ),
    ];

    /// Build a fixture where `token` sits inside a `#[cfg(test)]` item and a
    /// production function follows it.
    fn shape_fixture(token: &str) -> String {
        // The item body spans lines so a LINE comment token cannot swallow the
        // closing brace and make the fixture itself invalid Rust.
        format!(
            "fn before() {{}}\n\
             #[cfg(test)]\n\
             fn t() {{\n\
             \x20   {token}\n\
             }}\n\
             fn prod() {{ let v = shared_runtime.load(); }}\n"
        )
    }

    #[test]
    fn every_literal_shape_that_can_hide_a_brace() {
        for (name, token, why) in LITERAL_SHAPES {
            let fixture = shape_fixture(token);
            let (production, test) = split_halves(&fixture);
            assert!(
                production.contains("shared_runtime.load("),
                "[{name}] production code after the test item was ELIDED — the \
                 `{{` inside `{token}` desynchronised brace tracking ({why}). \
                 A load down there would be invisible to rule 3."
            );
            assert!(
                test.contains("fn t()"),
                "[{name}] the #[cfg(test)] item must land in the TEST half"
            );
            assert!(
                !production.contains("fn t()"),
                "[{name}] the #[cfg(test)] item must NOT land in the production half"
            );
            // And the canary agrees end to end.
            let mut v = Vec::new();
            scan_reader_loads("src/afxdp/ha/somewhere.rs", &production, &mut v);
            assert_eq!(
                v.len(),
                1,
                "[{name}] rule 3 must see the production load in an unlisted file"
            );
        }
    }

    #[test]
    fn hostile_fixture_raw_c_string_desync() {
        // Verbatim from the review that found it. Compiles under rustc 1.96 in
        // both production and test modes.
        let fixture = "#[cfg(test)]\n\
                       const S: &CStr = cr#\"\"{\"#;\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let production = production_half(fixture);
        assert!(
            production.contains("shared_runtime.load("),
            "the raw C string must not desync brace tracking; production half was:\n{production}"
        );
    }

    #[test]
    fn hostile_fixture_shebang_is_not_code() {
        // Verbatim from the review that found it. rustc strips a shebang before
        // tokenization, so its `}` is not a delimiter -- but the tracker was
        // counting it, desyncing depth for the whole file. `#![...]` is an INNER
        // ATTRIBUTE and must still be treated as code; the sibling row below
        // pins that direction.
        // The attribute must sit on a FIELD: a field has neither a semicolon nor
        // its own body, so once the stray `}` makes it look top-level,
        // attributed_item_end runs to EOF and elides `prod`. A plain field does
        // not reproduce -- the row would pass with the mask removed.
        let fixture = "#!/usr/bin/env rust-script }\n\
                       struct S {\n\
                           #[cfg(test)]\n\
                           test_only: u8,\n\
                       }\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let production = production_half(fixture);
        assert!(
            production.contains("shared_runtime.load("),
            "a shebang must not desync brace tracking; production half was:\n{production}"
        );
    }

    #[test]
    fn inner_attribute_is_not_mistaken_for_a_shebang() {
        // The over-reach direction: `#![...]` at offset 0 is code, not a
        // shebang. Masking it would swallow a real line.
        let fixture = "#![allow(dead_code)]\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let production = production_half(fixture);
        assert!(
            production.contains("shared_runtime.load("),
            "an inner attribute must not be masked as a shebang; production half was:\n{production}"
        );
    }

    #[test]
    fn hostile_fixture_macro_arg_brace_is_not_the_item_body() {
        // Verbatim from the review that found it. The item must end at the `;`,
        // not at the `{}` inside the macro's parentheses — otherwise the
        // trailing attribute-shaped tokens read as top level and elide `prod`.
        // Spans lines deliberately. With the whole invocation on ONE line a
        // mis-detected end lands on that same line, elides nothing extra, and
        // the row passes even with the `aux == 0` guard removed — the fixture
        // would not bind the fix.
        let fixture = "#[cfg(test)]\n\
                       swallow!({}\n\
                       \x20   #[cfg(test)]\n\
                       \x20   garbage);\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let production = production_half(fixture);
        assert!(
            production.contains("shared_runtime.load("),
            "a brace inside `()` is a macro argument, not the item body; \
             production half was:\n{production}"
        );
    }

    #[test]
    fn a_lifetime_tick_is_not_a_char_literal() {
        // `'a` must stay ordinary code. Treating it as a literal would mask
        // forward to the next tick and swallow the parens in between, which
        // desyncs `aux` and therefore the top-level test.
        let fixture = "fn before() {}\n\
                       #[cfg(test)]\n\
                       fn t<'a>(x: &'a u8) -> &'a u8 { x }\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let production = production_half(fixture);
        assert!(
            production.contains("shared_runtime.load("),
            "lifetimes must not be masked as char literals; production half was:\n{production}"
        );
    }

    #[test]
    fn cfg_test_inside_a_literal_does_not_open_a_region() {
        // The attribute text itself can appear in a string or a doc comment.
        // Masking is what stops that from eliding real code.
        for hider in [
            "const S: &str = \"#[cfg(test)]\";",
            "const S: &str = r#\"#[cfg(test)]\"#;",
            "/// #[cfg(test)]",
            "// #[cfg(test)]",
        ] {
            let fixture = format!("{hider}\nfn prod() {{ let v = shared_runtime.load(); }}\n");
            let production = production_half(&fixture);
            assert!(
                production.contains("shared_runtime.load("),
                "`{hider}` must not open a test region; production half was:\n{production}"
            );
        }
    }

    /// Shapes this pass deliberately does NOT handle, recorded as executable
    /// facts so the limits are known rather than assumed.
    ///
    /// None of them can hide a `{` from the masker — they are limits of the
    /// ATTRIBUTE matching, not of the literal grammar — and each fails CLOSED
    /// in the safe direction: the region is not recognised, so its lines stay
    /// in the PRODUCTION half and get scanned MORE, never less.
    #[test]
    fn documented_limits_fail_closed_not_open() {
        for (form, why) in [
            (
                "#[cfg(all(test, feature = \"x\"))]\nfn t() { let v = shared_runtime.load(); }\n",
                "only the literal `#[cfg(test)]` spelling opens a region",
            ),
            (
                "#[cfg_attr(unix, cfg(test))]\nfn t() { let v = shared_runtime.load(); }\n",
                "cfg_attr is not expanded",
            ),
            (
                "macro_rules! m { () => { #[cfg(test)] fn t() {} }; }\nfn prod() { let v = shared_runtime.load(); }\n",
                "macros are not expanded, so attributes they GENERATE are invisible",
            ),
        ] {
            let production = production_half(form);
            assert!(
                production.contains("shared_runtime.load("),
                "unhandled form `{why}` must leave the code in the PRODUCTION \
                 half (scanned more, never less); production half was:\n{production}"
            );
        }
    }

    #[test]
    fn detects_a_second_publish_in_the_choke_point_file() {
        let mut v = Vec::new();
        scan_publish(
            PUBLISH_CHOKE_POINT,
            "self.ha.runtime.publish(a);\nself.ha.runtime.publish(b);\n\
             let x = RuntimeView::new(1, 2);\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "two stores in the choke-point file must fire");
        assert!(v[0].rule.starts_with('1'), "got {:?}", v[0]);
    }

    #[test]
    fn detects_a_publish_outside_the_choke_point() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "self.ha.runtime.publish(view);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('1')),
            "a publish outside the choke point must fire: {v:?}"
        );
    }

    #[test]
    fn detects_a_view_constructed_outside_the_choke_point() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "let view = RuntimeView::new(older_validation, fwd);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "an unmarked construction must fire: {v:?}"
        );
    }

    #[test]
    fn test_local_marker_suppresses_a_construction() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "fn production() {}\n#[cfg(test)]\nmod t {\n\
             let view = RuntimeView::new(a, b); // runtime-view-canary: test-local\n}\n",
            &mut v,
        );
        assert!(
            v.is_empty(),
            "a marked construction in the TEST half must be tolerated: {v:?}"
        );
    }

    #[test]
    fn choke_point_with_exactly_one_store_and_one_construction_is_clean() {
        let mut v = Vec::new();
        scan_publish(
            PUBLISH_CHOKE_POINT,
            "let view = Arc::new(RuntimeView::new(self.validation, forwarding));\n\
             self.ha.runtime.publish(view);\n",
            &mut v,
        );
        assert!(v.is_empty(), "the real shape must be clean: {v:?}");
    }

    #[test]
    fn detects_a_second_reader_load() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            "let view = shared_runtime.load();\nlet again = shared_runtime.load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a second load must fire");
        assert!(v[0].rule.starts_with('3'), "got {:?}", v[0]);
    }

    #[test]
    fn detects_a_reader_load_in_an_unlisted_file() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/ha/somewhere.rs",
            "let view = shared_runtime.load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a load in an unlisted file must fire");
    }

    #[test]
    fn test_module_loads_are_not_counted() {
        // A `#[cfg(test)] mod` IS a test region, so loads inside it do not
        // inflate the count.
        let content = "let view = shared_runtime.load();\n#[cfg(test)]\nmod t {\n\
                       let a = shared_runtime.load();\n let b = shared_runtime.load();\n}\n";
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            &production_half(content),
            &mut v,
        );
        assert!(v.is_empty(), "test-module loads must not count: {v:?}");
    }

    /// THE hole a hostile review found, and the reason `production_half` does
    /// region tracking instead of truncating.
    ///
    /// `#[cfg(test)]` on a `use` hides ONLY that import. Under truncation the
    /// entire rest of the file counted as test code — and in
    /// `src/afxdp/coordinator/mod.rs` that attribute sits on line 35, so the
    /// publish choke point and every other production item in the file were
    /// unscanned. Each assertion here failed before region tracking.
    #[test]
    fn production_items_after_a_cfg_test_import_are_still_scanned() {
        let content = "use a::b;\n\
                       #[cfg(test)]\n\
                       use c::{d, e};\n\
                       fn prod(&mut self) {\n\
                       \x20   let view = RuntimeView::new(stale, fwd);\n\
                       \x20   let again = shared_runtime.load();\n\
                       }\n";

        let mut v = Vec::new();
        scan_publish("src/afxdp/coordinator/somewhere.rs", content, &mut v);
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a construction below a test-only import is PRODUCTION and must \
             fire: {v:?}"
        );

        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/coordinator/somewhere.rs",
            &production_half(content),
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('3')),
            "a load below a test-only import is PRODUCTION and must fire: {v:?}"
        );

        // The test-only import itself is the only thing hidden.
        let (production, test_half) = split_halves(content);
        assert!(production.contains("RuntimeView::new(stale, fwd)"));
        assert!(!production.contains("use c::{d, e};"));
        assert!(test_half.contains("use c::{d, e};"));
        assert!(!test_half.contains("RuntimeView::new"));
    }

    /// The same hole, exercised through the marker — the bypass it actually
    /// enabled. `runtime-view-canary: test-local` is honoured only in a file's
    /// test half; truncation made the whole file below line 35 "test half", so
    /// the marker silenced production code exactly where it mattered most.
    #[test]
    fn the_marker_cannot_hide_behind_a_cfg_test_import() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/mod.rs",
            // The leading production line is load-bearing: it puts the
            // attribute where `coordinator/mod.rs` has it — mid-file — so a
            // truncating implementation really does truncate here.
            "use super::*;\n\
             #[cfg(test)]\n\
             use cos_leases::{build_a, build_b};\n\
             fn store_runtime_view(&mut self) {\n\
             \x20   let view = RuntimeView::new(self.validation, fwd);\n\
             \x20   self.ha.runtime.publish(view);\n\
             }\n\
             fn sneak(&mut self) {\n\
             \x20   let torn = RuntimeView::new(stale, fwd); // runtime-view-canary: test-local\n\
             \x20   let channel = &self.ha.runtime;\n\
             \x20   channel.publish(torn);\n\
             }\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a marked construction in PRODUCTION code must still count — the \
             marker is only for a real test region: {v:?}"
        );
    }

    /// `#[cfg(test)] #[path = "x_tests.rs"] mod tests;` ends at its semicolon.
    /// Some 60 files in this tree declare their tests that way, several of them
    /// mid-file; truncation discarded everything after such a declaration.
    #[test]
    fn a_path_attributed_test_module_ends_at_its_semicolon() {
        let content = "use super::*;\n\
                       #[cfg(test)]\n\
                       #[path = \"mod_tests.rs\"]\n\
                       mod tests;\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let (production, test_half) = split_halves(content);
        assert!(test_half.contains("mod tests;"));
        assert!(
            production.contains("shared_runtime.load()"),
            "production after an external test module must survive: {production:?}"
        );
        let mut v = Vec::new();
        scan_reader_loads("src/afxdp/somewhere.rs", &production, &mut v);
        assert_eq!(v.len(), 1, "that load must be counted: {v:?}");
    }

    /// Region tracking must not over-correct: a real `#[cfg(test)] mod` body —
    /// and a `#[cfg(test)] impl` block, which `coordinator/mod.rs` also has —
    /// stay test regions, marker and all.
    #[test]
    fn cfg_test_blocks_remain_test_regions() {
        let content = "fn prod() {}\n\
                       #[cfg(test)]\n\
                       impl Coordinator {\n\
                       \x20   fn seam(&self) { let v = shared_runtime.load(); }\n\
                       }\n\
                       fn between() {}\n\
                       #[cfg(test)]\n\
                       mod t {\n\
                       \x20   fn mint() -> Arc<RuntimeView> {\n\
                       \x20       Arc::new(RuntimeView::new(  // runtime-view-canary: test-local\n\
                       \x20           v, f,\n\
                       \x20       ))\n\
                       \x20   }\n\
                       }\n";
        let (production, _) = split_halves(content);
        assert!(production.contains("fn between()"), "{production:?}");
        assert!(!production.contains("shared_runtime.load()"));

        let mut v = Vec::new();
        scan_publish("src/afxdp/worker/loop_body/mod.rs", content, &mut v);
        assert!(
            v.is_empty(),
            "a marked construction inside a real test region stays exempt: {v:?}"
        );
        let mut v = Vec::new();
        scan_reader_loads("src/afxdp/somewhere.rs", &production, &mut v);
        assert!(v.is_empty(), "a test-region load must not count: {v:?}");
    }

    /// Brace tracking runs over MASKED text, so a brace or a `#[cfg(test)]`
    /// inside a string literal or a comment cannot desync which half a line
    /// lands in. Desync is not benign here — it decides what gets scanned.
    #[test]
    fn braces_and_attributes_in_literals_do_not_desync_regions() {
        let content = "const UNBALANCED: &str = \"{\";\n\
                       const QUOTED: &str = \"#[cfg(test)]\";\n\
                       // prose: #[cfg(test)] hides only its own item\n\
                       const BRACE_CHAR: char = '{';\n\
                       #[cfg(test)]\n\
                       mod t { fn x() { let v = RuntimeView::new(a, b); } } \
                       // runtime-view-canary: test-local\n\
                       fn prod() { let v = shared_runtime.load(); }\n";
        let (production, test_half) = split_halves(content);
        assert!(
            test_half.contains("RuntimeView::new(a, b)"),
            "the real test module must be the region: {test_half:?}"
        );
        assert!(
            production.contains("shared_runtime.load()"),
            "production after it must survive: {production:?}"
        );
        assert!(production.contains("const QUOTED"), "{production:?}");

        let mut v = Vec::new();
        scan_publish("src/afxdp/somewhere.rs", content, &mut v);
        assert!(
            v.is_empty(),
            "an unmarked construction inside a real test region is exempt and \
             quoted attributes are not regions: {v:?}"
        );
    }

    #[test]
    fn production_half_keeps_whole_file_when_no_test_module() {
        let content = "let view = shared_runtime.load();\n";
        assert_eq!(production_half(content), content);
    }

    #[test]
    fn prose_mentioning_the_scanned_tokens_does_not_fire() {
        // The #6592 docs quote every token this canary counts. Before comment
        // skipping, that made the canary fire on its own documentation.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "// a site writing self.ha.runtime.store(Arc::new(RuntimeView::new(v, f)))\n\
             /// would reintroduce the torn pair; see RuntimeView::default()\n\
             //! and shared_runtime.load() in the module header\n",
            &mut v,
        );
        assert!(v.is_empty(), "comment-only lines must not count: {v:?}");
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/ha/somewhere.rs",
            "// a SECOND shared_runtime.load() would tear the pair\n",
            &mut v,
        );
        assert!(v.is_empty(), "comment-only loads must not count: {v:?}");
    }

    #[test]
    fn code_with_a_trailing_comment_still_counts() {
        // Skipping is comment-ONLY lines. A construction cannot hide behind a
        // trailing comment (only the explicit marker exempts it).
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "let view = RuntimeView::new(a, b); // perfectly innocent\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a trailing comment must not exempt a construction: {v:?}"
        );
    }

    #[test]
    fn detects_a_publish_wrapped_across_lines_by_rustfmt() {
        // The shape a fire-probe actually produced. A line-based count misses
        // it entirely, which is why the counts run over whitespace-stripped
        // code.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/snapshot_refresh.rs",
            "        self.ha\n            .runtime\n            .publish(view);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('1')),
            "a rustfmt-wrapped store chain must still fire rule 1: {v:?}"
        );
    }

    #[test]
    fn detects_a_reader_load_wrapped_across_lines() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            "let a = shared_runtime.load();\nlet b = shared_runtime\n    .load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a wrapped second load must still fire rule 3");
        assert!(v[0].rule.starts_with('3'), "got {:?}", v[0]);
    }

    #[test]
    fn the_marker_does_not_silence_production_code() {
        // The marker used to suppress rule 2 wherever it appeared, including in
        // production. It is now honoured only in a file's TEST half.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/snapshot_refresh.rs",
            "let view = RuntimeView::new(stale, fwd); // runtime-view-canary: test-local\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a marker on a PRODUCTION line must not exempt it: {v:?}"
        );
    }

    #[test]
    fn detects_the_raw_writable_arcswap_escaping_its_type() {
        // Rule 1b. Holding `ArcSwap<RuntimeView>` outside its module is the
        // capability escape a review probe used to publish a torn pair.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/ha_state.rs",
            "    pub(super) runtime: Arc<ArcSwap<RuntimeView>>,\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with("1b")),
            "a raw ArcSwap<RuntimeView> outside the type's module must fire: {v:?}"
        );
    }

    #[test]
    fn a_wrapped_generic_still_counts_as_the_raw_arcswap() {
        assert_eq!(
            names_raw_runtime_arcswap(&code_blob_no_whitespace(
                "fn f(x: Arc<ArcSwap<\n    RuntimeView,\n>>) {}"
            )),
            0,
            "a trailing comma is a different spelling; documented limit"
        );
        assert_eq!(
            names_raw_runtime_arcswap(&code_blob_no_whitespace(
                "fn f(x: Arc<ArcSwap<\n    RuntimeView>>) {}"
            )),
            1,
            "a plain wrapped generic must still match"
        );
    }

    #[test]
    fn a_return_type_is_not_a_construction() {
        assert!(
            !constructs_runtime_view("    fn mint(&mut self, gen: u64) -> RuntimeView {"),
            "`-> RuntimeView {{` names the type in a signature; it builds nothing"
        );
        assert!(
            constructs_runtime_view("        let view = RuntimeView { validation, forwarding };"),
            "a struct literal IS a construction"
        );
        assert!(constructs_runtime_view("        RuntimeView::new(v, f)"));
        assert!(constructs_runtime_view("        RuntimeView::default()"));
    }
}
