//! #6664: `is_slow_path_eligible` must be reachable from production code
//! through exactly ONE door — `slow_path_admit` — and both kernel-reinject
//! refusal points must walk through it.
//!
//! WHY A SOURCE GUARD RATHER THAN A BEHAVIOURAL TEST. The second refusal point
//! is the trailing chokepoint in `poll_binding_process_descriptor`, and no test
//! in this crate drives that function. That is not an oversight this issue
//! could fix: it takes a live binding, a UMEM, a descriptor ring and a worker
//! context. So the accounting there is unobservable to the suite, and before
//! #6664 that was demonstrated rather than assumed — a mutation deleting the
//! `poll_descriptor` copy of the fail-closed accounting passed the entire
//! cargo suite.
//!
//! #6664's answer was to collapse the predicate and the accounting into one
//! function so there is a single site to get wrong. This test is what makes
//! that answer load-bearing instead of a convention: reverting either refusal
//! point to a bare `is_slow_path_eligible()` call reds here, at the wiring,
//! which is the property a behavioural test cannot reach.
//!
//! FAIL-ON-REVERT, in both directions:
//!   * a second production call to `is_slow_path_eligible` (e.g. restoring the
//!     `poll_descriptor` chokepoint to call the predicate directly, which
//!     would refuse the frame but never count the drop) -> RED;
//!   * a refusal point that stops calling `slow_path_admit` -> RED;
//!   * the one permitted call moving out of `slow_path_admit`'s body -> RED.
//!
//! SCOPE, stated so a reader does not over-read it. Comment lines are stripped
//! before matching, so no prose here or anywhere else can satisfy this test.
//! Whole files whose NAME contains "test" are excluded; a `#[cfg(test)]` module
//! inlined into a production-named file is NOT excluded and would trip the
//! guard. That is over-strict in the safe direction — it can only deny a new
//! call site, never admit one — and no such module exists today.

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

/// True for a file that holds tests rather than production code.
fn is_test_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("test"))
}

/// The file's lines with comment-only lines blanked, so a match can never come
/// from prose. Trailing `// ...` on a code line is left alone: a call written
/// there is still a call.
fn code_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("//") { String::new() } else { l.to_string() }
        })
        .collect()
}

struct Site {
    file: PathBuf,
    line: usize,
}

fn production_call_sites(needle: &str) -> Vec<Site> {
    let mut files = Vec::new();
    rust_sources(&repo_src(), &mut files);
    files.sort();
    assert!(
        files.len() > 100,
        "scanned only {} Rust sources under {}; this guard is not reading the \
         crate it claims to audit",
        files.len(),
        repo_src().display()
    );
    let mut sites = Vec::new();
    for path in files {
        if is_test_file(&path) {
            continue;
        }
        for (i, line) in code_lines(&path).iter().enumerate() {
            // `fn <needle>(` is the definition, not a call.
            if line.contains(needle) && !line.contains(&format!("fn {}", needle.trim_end_matches('('))) {
                sites.push(Site { file: path.clone(), line: i + 1 });
            }
        }
    }
    sites
}

fn rel(p: &Path) -> String {
    p.strip_prefix(repo_src())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn is_slow_path_eligible_has_exactly_one_production_caller_6664() {
    let sites = production_call_sites("is_slow_path_eligible(");
    let listed: Vec<String> = sites.iter().map(|s| format!("{}:{}", rel(&s.file), s.line)).collect();

    assert_eq!(
        sites.len(),
        1,
        "`is_slow_path_eligible` must be consulted from exactly ONE production \
         site — inside `slow_path_admit`, which also records the fail-closed \
         drop. Found {}: {:?}.\n\
         A second caller is how the predicate and the accounting come apart: \
         the frame is still refused, so no forwarding test changes, but the \
         refusal is never counted and the operator sees a metric frozen at zero \
         — indistinguishable from \"no such packets ever arrived\".",
        sites.len(),
        listed
    );

    let site = &sites[0];
    assert_eq!(
        rel(&site.file),
        "afxdp/tx/dispatch/slow_path.rs",
        "the single caller moved to {}; #6664's invariant is that it lives in \
         `slow_path_admit`",
        rel(&site.file)
    );

    // ...and inside slow_path_admit's body, not merely in the same file.
    let lines = code_lines(&site.file);
    let start = lines
        .iter()
        .position(|l| l.contains("fn slow_path_admit("))
        .expect("slow_path_admit is gone from slow_path.rs");
    let end = lines[start..]
        .iter()
        .position(|l| l == "}")
        .map(|off| start + off)
        .expect("slow_path_admit has no closing brace at column 0");
    assert!(
        site.line > start && site.line <= end + 1,
        "the only `is_slow_path_eligible` call is at line {} but \
         `slow_path_admit`'s body spans {}..={}; the predicate is being \
         consulted outside the one function that also accounts for a refusal",
        site.line,
        start + 1,
        end + 1
    );
}

#[test]
fn both_reinject_refusal_points_call_slow_path_admit_6664() {
    let sites = production_call_sites("slow_path_admit(");
    let mut files: Vec<String> = sites.iter().map(|s| rel(&s.file)).collect();
    files.sort();
    files.dedup();

    assert_eq!(
        files,
        vec![
            "afxdp/poll_descriptor/mod.rs".to_string(),
            "afxdp/tx/dispatch/slow_path.rs".to_string(),
        ],
        "both kernel-reinject refusal points must route through \
         `slow_path_admit`: the filtered `maybe_reinject_slow_path` wrapper in \
         tx/dispatch/slow_path.rs and the trailing chokepoint in \
         poll_binding_process_descriptor. Found {files:?}.\n\
         The chokepoint is not covered by any behavioural test in this crate \
         (it needs a live binding, UMEM and descriptor ring), so this is the \
         only place a regression there is visible."
    );
}

/// #7480: the raw reinject primitive's caller set, pinned.
///
/// `maybe_reinject_slow_path_from_frame` hands ANY parseable L3 frame to the
/// kernel. Its own doc block is what a caller reads before deciding it may
/// bypass `is_slow_path_eligible`, so that enumeration is a security-relevant
/// claim — and it was WRONG. #1946 wrote "the ONE INTENTIONAL unfiltered
/// caller"; #6664 discovered a second (the host-terminated IPsec passthrough in
/// `poll_stages.rs`, which calls the primitive with a SYNTHETIC `LocalDelivery`
/// decision) and corrected the SIBLING comment at the `handle_forward_build_failure`
/// call site while leaving the primitive's own doc saying "ONE". Two spellings
/// of the same fact in one file, disagreeing, with the stale one on the item a
/// caller actually reads.
///
/// A comment cannot be kept true by review, so this pins the set instead. The
/// four production sites are two filtered and two unfiltered:
///
///   * `tx/dispatch/slow_path.rs` x2 — the filtered `maybe_reinject_slow_path`
///     wrapper (routes through `slow_path_admit`), and the UNFILTERED
///     `handle_forward_build_failure` ForwardCandidate fallback;
///   * `poll_descriptor/mod.rs` x1 — the #1913 trailing chokepoint, filtered;
///   * `poll_stages.rs` x1 — the UNFILTERED IPsec passthrough.
///
/// FAIL-ON-REVERT: any new production call site reds here. That is the point —
/// a new caller is a new way to hand an unadjudicated frame to the kernel FIB,
/// and it must be classified as filtered or unfiltered, added to this list, and
/// reflected in the primitive's doc block in the same change.
#[test]
fn raw_reinject_primitive_caller_set_is_pinned_7480() {
    let sites = production_call_sites("maybe_reinject_slow_path_from_frame(");
    let mut files: Vec<String> = sites.iter().map(|s| rel(&s.file)).collect();
    files.sort();

    let expected = vec![
        "afxdp/poll_descriptor/mod.rs".to_string(),
        "afxdp/poll_stages.rs".to_string(),
        "afxdp/tx/dispatch/slow_path.rs".to_string(),
        "afxdp/tx/dispatch/slow_path.rs".to_string(),
    ];

    let listed: Vec<String> = sites
        .iter()
        .map(|s| format!("{}:{}", rel(&s.file), s.line))
        .collect();

    assert_eq!(
        files, expected,
        "the raw reinject primitive's production caller set changed. Found {listed:?}.\n\
         Every caller of this primitive can hand an unadjudicated frame to the \
         kernel FIB, where there is no nftables `hook forward` chain, ip_forward \
         is force-enabled while armed, and rp_filter is 0 on the TUN — so nothing \
         downstream re-checks it. A new site must be classified filtered vs \
         unfiltered, listed here, AND reflected in the primitive's doc block, \
         which is what a future caller reads before bypassing the predicate."
    );
}

/// #7480: the NoRoute arm must actually ADJUDICATE before the trailing
/// chokepoint, and must express its refusal as a `PolicyDenied` downgrade.
///
/// WHY A SOURCE GUARD. Same reason as the two above: the call site is inside
/// `poll_binding_process_descriptor`, which no test in this crate can drive (it
/// needs a live binding, a UMEM and a descriptor ring). The policy SEMANTICS are
/// unit-tested against `noroute_policy_denial` directly; what no behavioural test
/// in this crate can see is whether the arm still calls it. Every existing cargo
/// test passed both before and after the behaviour change, which is the
/// demonstration rather than the assumption.
///
/// FAIL-ON-REVERT: delete the adjudication from the NoRoute arm, or stop
/// downgrading to `PolicyDenied` (so the frame stays slow-path eligible and is
/// handed to the kernel FIB), and this reds.
#[test]
fn noroute_arm_adjudicates_before_reinjecting_7480() {
    let path = repo_src().join("afxdp/poll_descriptor/mod.rs");
    let lines = code_lines(&path);

    let start = lines
        .iter()
        .position(|l| l.contains("ForwardingDisposition::NoRoute =>"))
        .expect("the NoRoute arm is gone from poll_descriptor");
    // The arm ends where the next disposition arm begins.
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.contains("ForwardingDisposition::MissingNeighbor =>"))
        .map(|off| start + 1 + off)
        .expect("the MissingNeighbor arm no longer follows NoRoute; re-anchor this guard");

    let arm = lines[start..end].join("\n");

    assert!(
        arm.contains("noroute_policy_denial"),
        "the NoRoute arm no longer adjudicates the zone pair. Without it a NoRoute \
         frame is slow-path eligible and the trailing #1913 chokepoint hands it to \
         the kernel FIB, which forwards it with no zone policy, session, NAT or \
         screen — the #6664 bypass, on the leg an attacker steers by choosing the \
         destination."
    );
    assert!(
        arm.contains("ForwardingDisposition::PolicyDenied"),
        "the NoRoute arm evaluates policy but no longer downgrades a denied frame \
         to PolicyDenied. The downgrade IS the enforcement: it is what makes the \
         existing chokepoint refuse the frame and account the fail-closed drop. \
         Evaluating without downgrading is a policy check whose result is discarded."
    );
    // #9054: the adjudication's soundness has a PRECONDITION, and the arm must
    // go through the entry point that checks it. `noroute_policy_denial` alone
    // answers "does policy deny this?"; it cannot answer "does NoRoute mean
    // anything right now?", and above the #8355 learned-route cap it does not —
    // the daemon declined the entire kernel import, so every dynamically learned
    // destination resolves NoRoute for a reason that has nothing to do with the
    // destination. Calling the ungated function here restores the total
    // blackhole this guard's sibling cells cannot see.
    assert!(
        arm.contains("noroute_policy_denial_gated"),
        "the NoRoute arm calls the UNGATED adjudication. It must call \
         noroute_policy_denial_gated, which delegates to the kernel while \
         ConfigSnapshot.learned_route_import_capped says the daemon withheld the \
         learned-route table (#9054). Adjudicating a FIB the daemon deliberately \
         left incomplete black-holes every learned destination on a default-deny \
         box, and #8355's operator log line says the opposite."
    );
}
