//! #6883: fixture `pkt_len` must equal the FULL frame length.
//!
//! The XDP shim stamps `pkt_len = data_end - data` (`userspace-xdp/src/lib.rs`,
//! `packet_len`), i.e. the whole frame INCLUDING the 14-byte Ethernet header.
//! A large family of fixtures instead built metadata with `frame.len() - 14`,
//! feeding the dataplane a value 14 bytes short of what production supplies.
//!
//! The premise that "nothing gates on `pkt_len`" is stale since #8581:
//! `pkt_len` is billed in every filter, policy, policer, session and zone
//! byte counter (`logical_ingress.rs` #8581 contract; `tx/cos_classify.rs`
//! `packet_bytes = meta.pkt_len`, `flow_cache.rs` `observed_bytes:
//! u64::from(meta.pkt_len)`), so a fixture 14 bytes short drives those
//! paths 14 bytes off their production boundary. That is exactly why it
//! needs a guard rather than a one-time correction: the convention is copied
//! verbatim between sibling fixtures, so a lane cloning an adjacent test
//! inherits it silently.
//!
//! A header-subtracted length is NOT banned outright: it is the CORRECT
//! expression for an IPv4 total-length or IPv6 payload-length wire invariant,
//! which genuinely excludes the Ethernet header. Four such assertions live in
//! `tests_mss_inject_inspect.rs` and must keep working. The guard therefore
//! matches only header-subtracted lengths that flow into `pkt_len` — either
//! as a `pkt_len` field/assignment directly, or as an argument to a helper
//! (`txn_meta_v4(.., pkt_len)`) whose parameter IS the `pkt_len` field
//! (#16444: the old three literal sinks missed `(frame_len - 14)`,
//! `frame.len() as u16 - 14`, `(inner.len() - 14)` and every `txn_meta_v4`
//! call site that subtracted at the call).

/// Scans the fixture tree for `pkt_len` built from a header-subtracted frame
/// length. Comments are stripped BEFORE matching so this file's own prose —
/// which necessarily spells the banned pattern — cannot satisfy the scan.
#[test]
fn fixture_pkt_len_is_the_full_frame_length_6883() {
    use std::path::Path;

    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// True when `text` (comment-stripped code up to a `pkt_len` value or a
    /// `txn_meta_v4(` argument) contains a header subtraction: `- 14`,
    /// `- l3` (the VLAN-aware L3 offset variable), or `saturating_sub(14)`.
    /// A bare length with no subtraction is the shim contract and is legal.
    fn has_header_subtraction(text: &str) -> bool {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        compact.contains("-14")
            || compact.contains("-l3")
            || compact.contains("saturating_sub(14)")
    }

    /// Extract the balanced `(...)` argument list starting at `open` (index
    /// of `(`), returning the inner text. `None` if unbalanced on this text.
    fn balanced_args(text: &str, open: usize) -> Option<&str> {
        let bytes = text.as_bytes();
        let mut depth = 0usize;
        for i in open..bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[open + 1..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Split a balanced argument list on top-level commas.
    fn split_args(args: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        for (i, b) in args.bytes().enumerate() {
            match b {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(&args[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        out.push(&args[start..]);
        out
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 50,
        "#6883 guard scanned {} files — the walk is broken, not the tree",
        files.len()
    );

    let mut hits = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "pkt_len_fixture_drift_6883_tests.rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(f) else { continue };
        let code = strip_comments(&src);
        // Line numbers are preserved by strip_comments (one line in, one out).
        let line_of = |pos: usize| code[..pos].bytes().filter(|&b| b == b'\n').count() + 1;

        // Sink 1: `pkt_len:` / `pkt_len =` / `.pkt_len =` whose value (up to
        // the terminating `,` or `;` on the same statement) subtracts the
        // header. Catches `(frame.len() - 14)`, `(frame_len - 14)`,
        // `frame.len() as u16 - 14`, `(inner.len() - 14)`, `- l3`, etc.
        for (idx, _) in code.match_indices("pkt_len") {
            let rest = &code[idx + "pkt_len".len()..];
            let Some(sep) = rest.find(|c: char| c == ':' || c == '=') else { continue };
            // Only a field/assignment separator directly after the name
            // (allowing whitespace) — not `pkt_len as u64`, comparisons, etc.
            if !rest[..sep].trim().is_empty() {
                continue;
            }
            let value = &rest[sep + 1..];
            let end = value.find(|c: char| c == ',' || c == ';').unwrap_or(value.len());
            if has_header_subtraction(&value[..end]) {
                hits.push(format!("{}:{}", f.display(), line_of(idx)));
            }
        }

        // Sink 2: `txn_meta_v4(.., <len> - 14)` — the helper's third parameter
        // is stored verbatim into `pkt_len` (tests_support.rs), so subtracting
        // at the call site is the same drift one indirection away. Legal
        // callers pass the full `frame.len() as u16` or a deliberate constant.
        for (idx, _) in code.match_indices("txn_meta_v4(") {
            // Skip the helper definition itself (`fn txn_meta_v4(`).
            if code[..idx].trim_end().ends_with("fn") {
                continue;
            }
            let open = idx + "txn_meta_v4".len();
            let Some(args) = balanced_args(&code, open) else { continue };
            let parts = split_args(args);
            if parts.len() >= 3 && has_header_subtraction(parts[2]) {
                hits.push(format!("{}:{}", f.display(), line_of(idx)));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "#6883/#16444: {} fixture site(s) build pkt_len from a header-subtracted \
         frame length. The shim stamps the FULL frame length (packet_len = \
         data_end - data); use `frame.len() as u16`. Sites:\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}
