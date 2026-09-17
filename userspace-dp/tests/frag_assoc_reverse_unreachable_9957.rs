//! #9957: pin the production fragment-association reverse-info boundary.
//!
//! The AF_INET non-first NAT64 builder requires `Nat64ReverseInfo`, but the
//! production fragment-association installs currently pass `None` and both
//! lookup sites discard the cache's optional reverse value. The end-to-end
//! regression in `tests_nat64_tunnel.rs` proves today's packet disposition;
//! this source guard makes the producer/consumer wiring itself load-bearing.
//!
//! FAIL-ON-REVERT: adding a production `.frag_assoc.install(...)` or
//! `.frag_assoc.lookup(...)` caller anywhere in the tree, moving either
//! audited callsite out of `afxdp/poll_descriptor/frag_assoc.rs`, changing
//! either install's third positional argument away from `None`, or binding
//! either production lookup's reverse result instead of `_reverse` reds this
//! test. Test-only low-level fixtures are excluded by filename.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_test_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("test"))
}

/// Remove comment-only lines while preserving line numbers.
///
/// This deliberately matches the established source-guard convention in this
/// crate: a call in prose cannot satisfy the guard, while a call on a code line
/// remains visible even when it has a trailing comment.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn production_sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    rust_sources(&repo_src(), &mut files);
    files.sort();
    assert!(
        files.len() > 100,
        "scanned only {} Rust sources under {}; this guard is not reading the crate it claims to audit",
        files.len(),
        repo_src().display()
    );
    files
        .into_iter()
        .filter(|path| !is_test_file(path))
        .map(|path| {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            (path, code_only(&source))
        })
        .collect()
}

#[derive(Debug)]
struct Site {
    file: PathBuf,
    line: usize,
    offset: usize,
    third_arg: Option<String>,
}

fn rel(path: &Path) -> String {
    path.strip_prefix(repo_src())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1
}

fn skip_ws(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        offset += 1;
    }
    offset
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn identifier_at(source: &str, offset: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    if !bytes.get(offset).is_some_and(|byte| is_ident_start(*byte)) {
        return None;
    }
    let mut end = offset + 1;
    while bytes.get(end).is_some_and(|byte| is_ident_continue(*byte)) {
        end += 1;
    }
    Some((&source[offset..end], end))
}

/// Find a method call after either a direct `.frag_assoc` receiver or a local
/// alias. Whitespace/newlines between every receiver component are accepted.
fn method_after_receiver(source: &str, receiver_end: usize, method: &str) -> Option<usize> {
    let dot = skip_ws(source, receiver_end);
    if source.as_bytes().get(dot) != Some(&b'.') {
        return None;
    }
    let method_start = skip_ws(source, dot + 1);
    let method_end = method_start + method.len();
    if source.get(method_start..method_end) != Some(method)
        || source
            .as_bytes()
            .get(method_end)
            .is_some_and(|byte| is_ident_continue(*byte))
    {
        return None;
    }
    let open = skip_ws(source, method_end);
    (source.as_bytes().get(open) == Some(&b'(')).then_some(open)
}

/// Find local names assigned a value containing the fragment-association field.
/// The right-hand side is read through its semicolon so multiline aliases are
/// covered instead of relying on the current formatting.
fn frag_assoc_aliases(source: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    let mut search_from = 0usize;
    while let Some(relative) = source[search_from..].find("let") {
        let let_start = search_from + relative;
        let before_is_ident = let_start > 0
            && source
                .as_bytes()
                .get(let_start - 1)
                .is_some_and(|byte| is_ident_continue(*byte));
        let after_let = let_start + 3;
        let after_is_ident = source
            .as_bytes()
            .get(after_let)
            .is_some_and(|byte| is_ident_continue(*byte));
        if before_is_ident || after_is_ident {
            search_from = after_let;
            continue;
        }
        let mut cursor = skip_ws(source, after_let);
        if source.get(cursor..cursor + 4) == Some("mut ") {
            cursor = skip_ws(source, cursor + 4);
        }
        let Some((name, name_end)) = identifier_at(source, cursor) else {
            search_from = after_let;
            continue;
        };
        let Some(eq_relative) = source[name_end..].find('=') else {
            search_from = name_end;
            continue;
        };
        let equal = name_end + eq_relative;
        let Some(semi_relative) = source[equal + 1..].find(';') else {
            search_from = equal + 1;
            continue;
        };
        let semi = equal + 1 + semi_relative;
        let rhs = &source[equal + 1..semi];
        if rhs.contains("frag_assoc") {
            aliases.push(name.to_string());
        }
        search_from = semi + 1;
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

fn balanced_call_end(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in source[open..].char_indices() {
        let absolute = open + idx;
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    return Some(absolute);
                }
            }
            _ => {}
        }
    }
    None
}

fn third_argument(source: &str, open: usize, close: usize) -> Option<String> {
    let mut depth = 0usize;
    let mut arg_start = open + 1;
    let mut commas = 0usize;
    for (idx, ch) in source[open + 1..close].char_indices() {
        let absolute = open + 1 + idx;
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                if commas == 2 {
                    return Some(source[arg_start..absolute].trim().to_string());
                }
                commas += 1;
                arg_start = absolute + 1;
            }
            _ => {}
        }
    }
    (commas == 2).then(|| source[arg_start..close].trim().to_string())
}

fn method_sites_in_source(path: &Path, source: &str, method: &str) -> Vec<Site> {
    let mut starts = Vec::new();
    let mut search_from = 0usize;
    while let Some(relative) = source[search_from..].find(".frag_assoc") {
        let start = search_from + relative;
        let receiver_end = start + ".frag_assoc".len();
        if let Some(open) = method_after_receiver(source, receiver_end, method) {
            starts.push((start, open));
        }
        search_from = receiver_end;
    }
    for alias in frag_assoc_aliases(source) {
        let mut search_from = 0usize;
        while let Some(relative) = source[search_from..].find(&alias) {
            let start = search_from + relative;
            let before_is_ident = start > 0
                && source
                    .as_bytes()
                    .get(start - 1)
                    .is_some_and(|byte| is_ident_continue(*byte));
            let alias_end = start + alias.len();
            let after_is_ident = source
                .as_bytes()
                .get(alias_end)
                .is_some_and(|byte| is_ident_continue(*byte));
            if !before_is_ident
                && !after_is_ident
                && let Some(open) = method_after_receiver(source, alias_end, method)
            {
                starts.push((start, open));
            }
            search_from = alias_end;
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
        .into_iter()
        .map(|(offset, open)| {
            let close = balanced_call_end(source, open).unwrap_or_else(|| {
                panic!("unbalanced {method} call at {}:{}", rel(path), line_at(source, offset))
            });
            Site {
                file: path.to_path_buf(),
                line: line_at(source, offset),
                offset,
                third_arg: third_argument(source, open, close),
            }
        })
        .collect()
}

fn production_method_sites(method: &str) -> Vec<Site> {
    let mut sites = production_sources()
        .into_iter()
        .filter(|(_, source)| source.contains("frag_assoc"))
        .flat_map(|(path, source)| method_sites_in_source(&path, &source, method))
        .collect::<Vec<_>>();
    sites.sort_by(|left, right| (&left.file, left.offset).cmp(&(&right.file, right.offset)));
    sites
}

fn listed(sites: &[Site]) -> Vec<String> {
    sites
        .iter()
        .map(|site| format!("{}:{}", rel(&site.file), site.line))
        .collect()
}

/// Reload a production file's comment-stripped text for per-site checks.
///
/// `production_method_sites` drops the source strings, but `Site.offset` is
/// relative to `code_only` output, so re-reading the same file reproduces the
/// exact text the offset was computed against.
fn code_source_for(path: &Path) -> String {
    let raw =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    code_only(&raw)
}

fn lookup_discards_reverse(source: &str, offset: usize) -> bool {
    let statement_start = source[..offset].rfind(';').map_or(0, |idx| idx + 1);
    let compact = source[statement_start..offset]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    compact.contains("let(decision,_reverse)=")
}

#[test]
fn production_fragment_association_installs_keep_reverse_none_9957() {
    let sites = production_method_sites("install");
    let listing = listed(&sites);
    assert_eq!(
        sites.len(),
        2,
        "#9957 production FragAssoc::install caller set changed: {listing:?}; update the census and expiry rationale"
    );
    assert!(
        sites
            .iter()
            .all(|site| rel(&site.file) == "afxdp/poll_descriptor/frag_assoc.rs"),
        "#9957 production association installs moved outside the two audited poll-descriptor sites: {listing:?}"
    );
    assert!(
        sites.iter().all(|site| site.third_arg.as_deref() == Some("None")),
        "#9957 every production FragAssoc::install third positional argument must remain None: {listing:?}"
    );
}

#[test]
fn production_fragment_association_lookups_discard_reverse_9957() {
    let sites = production_method_sites("lookup");
    let listing = listed(&sites);
    assert_eq!(
        sites.len(),
        2,
        "#9957 production fragment-association lookup caller set changed: {listing:?}; update the census and expiry rationale"
    );
    assert!(
        sites
            .iter()
            .all(|site| rel(&site.file) == "afxdp/poll_descriptor/frag_assoc.rs"),
        "#9957 production association lookups moved outside the two audited poll-descriptor sites: {listing:?}"
    );
    assert!(
        sites.iter().all(|site| {
            let source = code_source_for(&site.file);
            lookup_discards_reverse(&source, site.offset)
        }),
        "#9957 every production lookup must bind its own result as `_reverse`: {listing:?}"
    );
}

#[test]
fn parser_handles_multiline_fragment_association_receiver_9957() {
    let source = code_only(
        "let result = forwarding.nat64\n    .frag_assoc\n    .install(\n        key,\n        decision,\n        None,\n        now,\n        generation,\n        owner,\n    );",
    );
    let sites = method_sites_in_source(Path::new("synthetic.rs"), &source, "install");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].third_arg.as_deref(), Some("None"));
}

#[test]
fn parser_handles_multiline_fragment_association_alias_9957() {
    let source = code_only(
        "let cache = forwarding.nat64\n    .frag_assoc;\ncache\n    .install(\n        key,\n        decision,\n        None,\n        now,\n        generation,\n        owner,\n    );",
    );
    let sites = method_sites_in_source(Path::new("synthetic.rs"), &source, "install");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].third_arg.as_deref(), Some("None"));
}

#[test]
fn lookup_binding_is_tied_to_the_same_call_9957() {
    let good = code_only(
        "let (decision, _reverse) = forwarding.nat64\n    .frag_assoc\n    .lookup(\n        &key,\n        now,\n        generation,\n        |_| true,\n    );",
    );
    let good_sites = method_sites_in_source(Path::new("synthetic.rs"), &good, "lookup");
    assert_eq!(good_sites.len(), 1);
    assert!(lookup_discards_reverse(&good, good_sites[0].offset));

    let bad = code_only(
        "let (decision, reverse) = forwarding.nat64\n    .frag_assoc\n    .lookup(\n        &key,\n        now,\n        generation,\n        |_| true,\n    );",
    );
    let bad_sites = method_sites_in_source(Path::new("synthetic.rs"), &bad, "lookup");
    assert_eq!(bad_sites.len(), 1);
    assert!(!lookup_discards_reverse(&bad, bad_sites[0].offset));
}
