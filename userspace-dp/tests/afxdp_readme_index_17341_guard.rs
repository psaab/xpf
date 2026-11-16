//! #17341: the `## Submodules` index in `userspace-dp/src/afxdp/README.md` is
//! the module's map, and it drifted: extractions created nine subdirectories
//! (`poll_descriptor/`, `forwarding_build/`, `wg/`, `ha/`, `bpf_map/`, ...)
//! that never got an entry, while their parent's index kept presenting itself
//! as complete. This guard keeps the index and the tree in step, both ways:
//!   - every subdirectory of `afxdp/` (except `testdata*` fixtures) has a
//!     top-level `- \`<dir>/\`` entry;
//!   - every top-level entry names a file or directory that exists.
//! It reads the tree at run time, so a new directory or a stale entry fails
//! here without any change to this file.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// The names of the top-level `- \`name\`` bullets of the `## Submodules`
/// section (nested bullets and notes are indented, so they are not entries).
fn index_entries(readme: &str) -> Vec<String> {
    let mut in_section = false;
    let mut out = Vec::new();
    for line in readme.lines() {
        if line.starts_with("## ") {
            in_section = line.trim_end() == "## Submodules";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(rest) = line.strip_prefix("- `") {
            if let Some(end) = rest.find('`') {
                out.push(rest[..end].to_string());
            }
        }
    }
    out
}

#[test]
fn afxdp_readme_submodules_index_matches_the_tree_17341() {
    let afxdp = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp");
    let readme = fs::read_to_string(afxdp.join("README.md"))
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", afxdp.join("README.md").display()));
    let entries = index_entries(&readme);
    assert!(
        !entries.is_empty(),
        "no top-level `## Submodules` entries found in afxdp/README.md; the guard cannot vouch for the index"
    );
    let indexed: BTreeSet<&str> = entries.iter().map(String::as_str).collect();
    let mut problems = Vec::new();

    for entry in fs::read_dir(&afxdp).unwrap_or_else(|e| panic!("cannot list {}: {e}", afxdp.display())) {
        let entry = entry.expect("directory entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("testdata") {
            continue;
        }
        let key = format!("{name}/");
        if !indexed.contains(key.as_str()) {
            problems.push(format!(
                "afxdp/{key} has no top-level `- \\`{key}\\`` entry in the README's `## Submodules` index"
            ));
        }
    }
    for entry in &entries {
        if !afxdp.join(entry.trim_end_matches('/')).exists() {
            problems.push(format!(
                "the `## Submodules` index lists `{entry}`, which does not exist under afxdp/"
            ));
        }
    }

    problems.sort();
    assert!(
        problems.is_empty(),
        "afxdp/README.md `## Submodules` index drift (#17341):\n  {}",
        problems.join("\n  ")
    );
}
