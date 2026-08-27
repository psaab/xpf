//! #6883: fixture `pkt_len` must equal the FULL frame length.
//!
//! The XDP shim stamps `pkt_len = data_end - data` (`userspace-xdp/src/lib.rs`,
//! `packet_len`), i.e. the whole frame INCLUDING the 14-byte Ethernet header.
//! A large family of fixtures instead built metadata with `frame.len() - 14`,
//! feeding the dataplane a value 14 bytes short of what production supplies.
//!
//! Nothing gates on `pkt_len` today, so the drift was invisible — every test
//! passed before the sweep and every test passed after it. That is exactly why
//! it needs a guard rather than a one-time correction: the convention is copied
//! verbatim between sibling fixtures, so a lane cloning an adjacent test
//! inherits it silently, and the first code to gate on `pkt_len` (an MTU
//! comparison, a segmentation threshold, a length-derived hash) would be
//! exercised 14 bytes off its real boundary. A fixture sitting exactly on a
//! threshold in the test would sit off it in production.
//!
//! `frame.len() - 14` is NOT banned outright: it is the CORRECT expression for
//! an IPv4 total-length or IPv6 payload-length wire invariant, which genuinely
//! excludes the Ethernet header. Four such assertions live in
//! `tests_mss_inject_inspect.rs` and must keep working. The guard therefore
//! matches only the `pkt_len` sinks.

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

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() > 50,
        "#6883 guard scanned {} files — the walk is broken, not the tree",
        files.len()
    );

    // Only the pkt_len SINKS. `frame.len() - 14` on its own is legitimate for
    // IPv4 total-length / IPv6 payload-length invariants.
    let sinks = [
        "pkt_len: (frame.len() - 14)",
        "pkt_len = (frame.len() - 14)",
        "pkt_len: (fwd_frame.len() - 14)",
    ];

    let mut hits = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "pkt_len_fixture_drift_6883_tests.rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(f) else { continue };
        let code = strip_comments(&src);
        for (i, line) in code.lines().enumerate() {
            if sinks.iter().any(|s| line.contains(s)) {
                hits.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "#6883: {} fixture site(s) build pkt_len from a header-subtracted frame \
         length. The shim stamps the FULL frame length (packet_len = data_end - \
         data); use `frame.len() as u16`. Sites:\n  {}",
        hits.len(),
        hits.join("\n  ")
    );
}
