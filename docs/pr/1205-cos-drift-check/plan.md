---
status: REVISED v3 — round-2 verdict: Codex PLAN-NEEDS-MINOR (broad numeric pattern), Gemini PLAN-READY. v3 drops NUMERIC_STALE_PATTERNS; ready to ship.
issue: #1205
phase: single PR — new test only; no production code
---

## Round-1 verdict resolution

Both reviewers PLAN-NEEDS-MINOR. Convergent findings:

- **Blocklist is too narrow.** Codex: add `1024-bucket bookkeeping`,
  `all 1024 SFQ buckets`, `bounded by 1024 worst case`,
  `1024 active buckets`. Both reviewers: add `tx.rs:` line refs.
  v2 expands the blocklist with these phrase patterns AND a
  separate predicate for `tx.rs:N` (digit-suffix, per Codex).
- **SCAN_DIRS too narrow.** Both flag missing `worker/cos.rs`,
  `tx/cos_classify.rs`, `coordinator/cos_state.rs`. Gemini suggests
  collapsing to just `src/afxdp/` + `src/session/` since `scan_dir`
  is recursive. v2 adopts this — broader scope, simpler code.
- **Order with #1210**: both confirm "ship #1205 with patterns
  populated, gate merge on #1210 first". Codex: "stacking #1205 on
  top of #1210 for validation is fine". v2 records this explicitly.
- **Substring greediness.** Codex: for numeric stale patterns,
  require char after `1024` to not be `[0-9_]`. Gemini: the existing
  4 patterns are long enough to be safe via `.contains()`. v2 adopts
  Codex's more cautious approach for the two numeric patterns
  (`= 1024`).
- **Same-line allow marker is sufficient** (both confirm). No
  block markers.
- **Don't silently ignore missing scan dirs** (Codex). v2 panics
  loudly if a configured scan root is missing.



## 1. Issue framing

Per #1205 and Codex CoS findings retrospective: this session burned
three plan-review cycles on stale code-comment anchors (PR #1203,
#936 v1, Phase 2 byte-rate). #1210 scrubs the existing drift; this PR
adds a test that prevents future drift.

## 2. Scope

A single Rust integration test (`tests/cos_doc_drift.rs` or similar
under `userspace-dp/tests/`) that fails when known-stale policy
references reappear in active CoS source files.

## 3. Concrete design

### Test location

`userspace-dp/tests/cos_doc_drift.rs` — at the cargo workspace integration
test level, runs as part of `cargo test --release`.

### Test shape

```rust
//! CoS doc/code drift guard (#1205).
//!
//! Fails if any of the listed stale references reappear in the active
//! CoS scheduler source tree. See `docs/pr/1205-cos-drift-check/plan.md`
//! for context. Add new entries when a fairness/MQFQ change makes a
//! prior assertion stale; never silence by suppressing the check.
//!
//! Whitelist: lines marked `// drift-check: historical` are tolerated.

use std::fs;
use std::path::{Path, PathBuf};

// Substring patterns must NOT appear on a non-historical line in
// any file under SCAN_DIRS. Each entry is (pattern, rationale).
//
// v2 expanded blocklist per Codex+Gemini reviews:
const STALE_PATTERNS: &[(&str, &str)] = &[
    ("COS_FLOW_FAIR_BUCKETS = 1024",
     "value is 4096 since #785 Phase 3"),
    ("flow_fair = queue.exact && !shared_exact",
     "policy is `flow_fair = queue.exact` since #785 Phase 3"),
    ("shared_exact queues are NOT on the flow-fair path",
     "shared_exact runs flow_fair via #917 V_min sync since #785 Phase 3"),
    ("single-FIFO-per-worker drain",
     "shared_exact uses MQFQ, not FIFO, since #785 Phase 3"),
    ("1024-bucket bookkeeping",
     "value is 4096 since #785 Phase 3"),
    ("all 1024 SFQ buckets",
     "value is 4096 since #785 Phase 3"),
    ("bounded by 1024 worst case",
     "value is 4096 since #785 Phase 3"),
    ("1024 active buckets",
     "value is 4096 since #785 Phase 3"),
];

// v3: Codex round-2 caught that `= 1024` is too broad with the wider
// SCAN_DIRS — flags legitimate live constants in mod.rs:201,
// neighbor.rs:490, flow_cache.rs (unrelated buffer sizes etc).
// The 8 prose patterns above cover the actual stale CoS-bucket
// references unambiguously; the numeric pattern adds risk without
// closing a real gap. Removed in v3.

// `tx.rs:` followed by an ASCII digit — old line-number breadcrumbs
// are stale across the tx.rs decomposition (#956+). Module/function
// anchors like `tx.rs::transmit_batch` are fine.
const TX_LINE_REF_PATTERN: &str = "tx.rs:";

const SCAN_DIRS: &[&str] = &[
    "src/afxdp",   // recursive — covers cos/, types/, worker/cos.rs, tx/cos_classify.rs, coordinator/cos_state.rs, etc.
    "src/session",
];

const ALLOW_MARKER: &str = "drift-check: historical";

#[test]
fn cos_doc_drift_guard() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();

    for dir in SCAN_DIRS {
        let p = Path::new(manifest_dir).join(dir);
        scan_dir(&p, &mut violations);
    }

    if !violations.is_empty() {
        let report: Vec<String> = violations.iter()
            .map(|v| format!("  {}:{}: {} (rationale: {})",
                v.path.display(), v.line, v.pattern, v.rationale))
            .collect();
        panic!(
            "CoS doc/code drift detected (#1205):\n{}\n\n\
             If this is intentional historical retrospective text, \
             add `// drift-check: historical` on the same line.",
            report.join("\n")
        );
    }
}

struct Violation {
    path: PathBuf,
    line: usize,
    pattern: &'static str,
    rationale: &'static str,
}

fn scan_dir(dir: &Path, violations: &mut Vec<Violation>) {
    // v2: panic loudly if a configured scan root is missing.
    // Silent return on read_dir error converted refactor-induced
    // path moves into false passes (Codex finding).
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("scan_dir({}): {} — fix SCAN_DIRS or your tree is broken", dir.display(), e));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, violations);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in content.lines().enumerate() {
            if line.contains(ALLOW_MARKER) {
                continue;
            }
            for (pattern, rationale) in STALE_PATTERNS {
                if line.contains(pattern) {
                    violations.push(Violation { path: path.clone(), line: lineno + 1, pattern, rationale });
                }
            }
            // v3: NUMERIC_STALE_PATTERNS dropped — `= 1024` was too broad
            // with the wider SCAN_DIRS. Prose patterns above are sufficient.
            // tx.rs:N (digit-suffix) — line-number breadcrumb pattern.
            // Round-2 PR review (Codex+Gemini): use match_indices to
            // catch ALL occurrences on a line, not just the first.
            // A line like `// tx.rs::transmit_batch and tx.rs:262`
            // would have line.find() see only the first `tx.rs::`
            // (next char `:`, not digit), accept it, and silently
            // miss the digit-suffix breadcrumb later.
            for (idx, _) in line.match_indices(TX_LINE_REF_PATTERN) {
                let next = line.as_bytes().get(idx + TX_LINE_REF_PATTERN.len()).copied();
                if next.map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    violations.push(Violation {
                        path: path.clone(), line: lineno + 1,
                        pattern: TX_LINE_REF_PATTERN,
                        rationale: "stale tx.rs:NNN line breadcrumb across the tx.rs decomposition (#956+); use module/function anchor instead",
                    });
                }
            }
            // Self-tests: detects_tx_rs_line_ref_after_module_anchor_on_same_line
            // pins the find-vs-match_indices fix.
            // previous_line_allow_marker_does_not_suppress pins same-line
            // allow-marker scoping.
        }
    }
}
```

## 4. Public API preservation

None. Test only.

## 5. Hidden invariants

- The test must pass on master ONCE #1210 has scrubbed existing
  drift. Order constraint: this PR depends on #1210 merging first,
  OR this PR's blocklist starts empty and gets populated as a
  follow-up.

  Recommendation: ship #1205 with the patterns from §3 already
  included, and gate merge on #1210 having merged. The
  acceptance-criterion line in #1210's PR will literally be "does
  the #1205 test pass with this scrub applied".

- The test runs in `cargo test --release` — no separate make target.

- Skip directories should be added if they appear (e.g., a future
  `userspace-dp/src/scheduler/` extraction). Listed explicitly so
  reviewers see what's in scope.

## 6. Risk

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **NONE** | Test only |
| False positives | LOW-MED | If a future legitimate use of one of the strings appears, allow-marker handles it |
| Maintenance burden | LOW | Add a new entry only when a fairness/MQFQ landing makes a prior text stale |
| Order with #1210 | MED | Need to merge #1210 first OR ship `STALE_PATTERNS` empty initially |

## 7. Test plan

- `cargo test --release cos_doc_drift_guard` passes after #1210 merges.
- Hand-test: temporarily add one of the stale strings to a file in
  `src/afxdp/cos/`; test fails with the expected diagnostic.
- Hand-test: same string + `// drift-check: historical` marker; test
  passes.
- `cargo build --release` clean (test compiles).
- 5×flake on the test (deterministic file scan; should be 5/5).

## 8. Out of scope

- Doc files (`docs/`). The test only scans Rust source; doc drift is
  caught by the periodic refresh in #1208's audit.
- Go-side analogue. If `pkg/dataplane/userspace/` ever develops
  scheduler-relevant comments, add a sibling test then.
- Custom DSL or cargo-config integration. Plain test, plain assertion.

## 9. Open questions for adversarial review

1. **Allow-marker placement.** Current spec: `// drift-check:
   historical` on the same line. Is multi-line block-marker support
   needed for retrospectives that span 5+ lines (e.g., the
   `admission.rs:395-461` rationale)?
2. **Initial blocklist completeness.** Are the 4 patterns the right
   set? Should we also include `\`tx.rs:` or `tx\.rs:` as a literal
   pattern to catch old line references?
3. **Order with #1210.** Recommended approach (merge #1210 first or
   ship blocklist empty initially) — pick one.
4. **Scope breadth.** Is `src/session/` worth scanning for drift
   patterns? Currently has `installed_at_ns` / `installed_on_binding_slot`
   doc text from #789 work; not directly fairness, but adjacent.

## 10. Verdict request

PLAN-READY → execute.
PLAN-NEEDS-MINOR → tighten patterns / allow-marker semantics.
