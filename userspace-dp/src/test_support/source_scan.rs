//! #17152: shared source-scan helpers for `#[cfg(test)]` source gates.
//!
//! Moved here from `afxdp/worker_queue_tests.rs` (#12270) so every
//! source-scanning gate imports one blanker instead of reaching through
//! `crate::afxdp::worker_queue::tests` — an unrelated test module whose
//! widened visibility existed only to share these helpers. A second
//! implementation of comment-blanking is the shape where a
//! source-scanning gate quietly stops seeing what it is meant to see
//! (see `server::helpers::status` #17152: its whole-line-only `code_only`
//! stayed green when a trailing or block comment quoted the accessor).
//!
//! This module is `#[cfg(test)]`-only (declared so in `main.rs`); no
//! production code, attribute, or hot-path behaviour changes.

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

/// Blank inline `#[cfg(test)] mod` bodies before the producer census.
///
/// Production files can also contain test-only modules. The source walk excludes
/// test-only files, but scanning those inline modules would report fixture
/// queue setup as a production producer.
pub(crate) fn blank_cfg_test_modules(src: &str) -> String {
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
    // Every target reached by ANY declaration or include, gated or not.
    // A `mod` target is not an `include!` target, so without this set a
    // file declared both from production and under `#[cfg(test)]` (dual
    // `#[path] mod`, say) would be seeded by the test declaration and
    // admitted with no ungated edge ever blocking it - production
    // source classified test-only. Pass 2 admits a target only when
    // every ungated edge into it starts from a test-only file.
    let mut declared: std::collections::HashSet<String> = std::collections::HashSet::new();
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
                            declared.insert(target.clone());
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
                        let key = normalise(&cand, root);
                        declared.insert(key.clone());
                        seeds.push(key);
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
                        let key = normalise(&cand, root);
                        declared.insert(key.clone());
                        edges.push((from.clone(), key));
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
    // A target exists to be reused - by `include!`, and equally by `mod`:
    // one file can be reached both from production and from a test-gated
    // declaration (dual `#[path] mod` to the same file is ordinary,
    // compiler-accepted Rust). Such a target is admitted only once every
    // ungated edge into it starts from a test-only file; otherwise a test
    // declaration would hide production source from every canary that
    // consumes this set (#6929/#7015/#7053/#8121, and #16187's unsafe
    // census, where the hidden file's unsafe would never be counted).
    // The guard keys on `declared` - every target any declaration or
    // include reaches - not only on `include!` targets: `mod` targets
    // were previously admitted unconditionally, which is exactly the
    // dual-reachability hole. Admission only becomes true as the set
    // grows, so the iteration still reaches the least fixpoint: an
    // includer/declarer found test-only on a later pass admits the
    // target on the pass after.
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
                !declared.contains(*to)
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

/// #16187: a file reached by BOTH a production `mod` and a
/// `#[cfg(test)]` `mod` (dual `#[path]` to the same file - ordinary,
/// compiler-accepted Rust) is production, not a fixture. Before this
/// pin, pass 2's mixed-ownership guard keyed only on `include!`
/// targets, so the test declaration seeded the file and it was
/// admitted test-only with no ungated edge ever blocking it: every
/// consumer of this set (#6929/#7015/#7053/#8121 canaries, #16187's
/// unsafe census) would silently skip live production source.
///
/// Both directions in one cell, deliberately: a fix that simply
/// stops seeding `mod` targets would satisfy the production row and
/// break the test-only control, so the control is asserted here too.
#[test]
fn cfg_test_dual_mod_targets_shared_with_production_stay_production_16187() {
    let temp = std::env::temp_dir().join(format!(
        "xpf-dual-mod-16187-{}",
        std::process::id()
    ));
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

    // The review fixture, verbatim in shape: one file, two
    // `#[path]` declarations, one gated and one not.
    let fixtures = scan(
        "dual_path_mod",
        &[
            (
                "main.rs",
                "#[path = \"shared.rs\"]\nmod production;\n#[cfg(test)]\n#[path = \"shared.rs\"]\nmod test_copy;\n",
            ),
            ("shared.rs", "pub fn ordinary() { unsafe {} }\nmod child;\n"),
            ("shared/child.rs", ""),
        ],
    );
    assert!(
        !fixtures.contains("shared.rs"),
        "a file declared from production AND under cfg(test) was classified \
         test-only - its production unsafe would never be counted"
    );
    assert!(
        !fixtures.contains("shared/child.rs"),
        "the shared file's own module child was hidden with it"
    );

    // Same file via plain `mod` from two parents: `x.rs` and
    // `x/mod.rs` share owner directory `x/`, so both `mod shared;`
    // declarations resolve to the one `x/shared.rs`. One parent is
    // production, the other carries the gated declaration.
    let fixtures = scan(
        "dual_plain_mod",
        &[
            ("x.rs", "mod shared;\n"),
            ("x/mod.rs", "#[cfg(test)]\nmod shared;\n"),
            ("x/shared.rs", ""),
        ],
    );
    assert!(
        !fixtures.contains("x/shared.rs"),
        "a plain-mod file declared from production AND test-only parents \
         was classified test-only"
    );

    // Control: dual declaration where BOTH parents are test-only
    // still classifies the target as a fixture - the fix must not
    // simply stop admitting shared targets.
    let fixtures = scan(
        "dual_test_only_mod",
        &[
            (
                "test_parent.rs",
                "#[cfg(test)]\n#[path = \"tests/a.rs\"]\nmod a;\n#[cfg(test)]\n#[path = \"tests/b.rs\"]\nmod b;\n",
            ),
            ("tests/a.rs", "#[path = \"../shared.rs\"]\nmod a_shared;\n"),
            ("tests/b.rs", "#[path = \"../shared.rs\"]\nmod b_shared;\n"),
            ("shared.rs", ""),
        ],
    );
    assert!(
        fixtures.contains("shared.rs"),
        "a file declared only from test-only files was left as production"
    );
    let _ = std::fs::remove_dir_all(&temp);
}
