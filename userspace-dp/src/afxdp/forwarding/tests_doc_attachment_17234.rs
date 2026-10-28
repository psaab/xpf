//! #17234 — #7480 inserted `noroute_policy_denial` between the
//! #919/#922 zone-pair resolver's rustdoc + `#[inline]` and the
//! resolver itself, so the doc and the inline hint re-attached to
//! `noroute_policy_denial` and the per-packet resolver lost both.
//!
//! Rust attaches a contiguous run of outer doc comments and
//! attributes to the NEXT item, regardless of which item the text
//! describes. These cells pin the attachment by source inspection
//! (rustdoc text and `#[inline]` placement are not observable at
//! runtime): the resolver carries its own doc and hint, the
//! NoRoute adjudicator's doc opens with #7480, and no
//! doc -> attribute -> doc run exists anywhere under
//! `userspace-dp/src`, because such a run is exactly how a doc
//! block and its item get separated by an insertion.

fn is_doc(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("///") && !t.starts_with("////")
}

fn is_attr(line: &str) -> bool {
    line.trim_start().starts_with("#[")
}

fn preamble_above<'a>(lines: &[&'a str], signature: &str) -> Vec<&'a str> {
    let idx = lines
        .iter()
        .position(|l| l.contains(signature))
        .unwrap_or_else(|| panic!("signature not found: {signature}"));
    let mut out = Vec::new();
    let mut i = idx;
    while i > 0 && (is_doc(lines[i - 1]) || is_attr(lines[i - 1])) {
        i -= 1;
        out.push(lines[i]);
    }
    out.reverse();
    out
}

fn forwarding_mod_rs() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/afxdp/forwarding/mod.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn zone_pair_resolver_carries_its_own_doc_and_inline_17234() {
    let src = forwarding_mod_rs();
    let lines: Vec<&str> = src.lines().collect();
    let pre = preamble_above(
        &lines,
        "pub(super) fn zone_pair_ids_for_flow_with_override(",
    );
    assert!(
        pre.iter().any(|l| l.contains("#919/#922")),
        "resolver lost its #919/#922 rustdoc; preamble: {pre:?}"
    );
    assert!(
        pre.iter().any(|l| l.trim() == "#[inline]"),
        "resolver lost its #[inline] hint; preamble: {pre:?}"
    );
    assert!(
        !pre.iter().any(|l| l.contains("#7480")),
        "resolver preamble still carries the #7480 NoRoute doc: {pre:?}"
    );
}

#[test]
fn noroute_policy_denial_doc_opens_with_7480_17234() {
    let src = forwarding_mod_rs();
    let lines: Vec<&str> = src.lines().collect();
    let pre = preamble_above(&lines, "fn noroute_policy_denial(");
    let first_doc = pre
        .iter()
        .find(|l| is_doc(l))
        .expect("noroute_policy_denial has no rustdoc");
    assert!(
        first_doc.contains("#7480"),
        "noroute_policy_denial rustdoc must open with #7480, got: {first_doc}"
    );
    assert!(
        !pre.iter().any(|l| l.contains("#919/#922")),
        "noroute_policy_denial still carries the resolver's #919/#922 doc: {pre:?}"
    );
    assert!(
        !pre.iter().any(|l| l.trim() == "#[inline]"),
        "noroute_policy_denial still carries the resolver's #[inline]: {pre:?}"
    );
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_split_doc_attribute_doc_under_userspace_dp_src_17234() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&root, &mut files);
    assert!(files.len() > 100, "scan saw only {} files", files.len());
    let mut violations = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let lines: Vec<&str> = src.lines().collect();
        for i in 0..lines.len() {
            if !is_doc(lines[i]) {
                continue;
            }
            // Only start at the head of a doc/attribute run.
            if i > 0 && (is_doc(lines[i - 1]) || is_attr(lines[i - 1])) {
                continue;
            }
            let mut seen_attr = false;
            for (j, line) in lines.iter().enumerate().skip(i + 1) {
                if is_attr(line) {
                    seen_attr = true;
                } else if is_doc(line) {
                    if seen_attr {
                        violations.push(format!(
                            "{}:{}: doc resumes after attribute: {}",
                            path.display(),
                            j + 1,
                            line.trim()
                        ));
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "split doc/attribute/doc runs (doc separated from its item):\n{}",
        violations.join("\n")
    );
}
