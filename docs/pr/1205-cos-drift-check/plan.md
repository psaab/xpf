---
status: DRAFT v1 — pending adversarial plan review
issue: #1205
phase: single PR — new test only; no production code
---

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

const STALE_PATTERNS: &[(&str, &str)] = &[
    ("COS_FLOW_FAIR_BUCKETS = 1024",
     "value is 4096 since #785 Phase 3"),
    ("flow_fair = queue.exact && !shared_exact",
     "policy is `flow_fair = queue.exact` since #785 Phase 3"),
    ("shared_exact queues are NOT on the flow-fair path",
     "shared_exact runs flow_fair via #917 V_min sync since #785 Phase 3"),
    ("single-FIFO-per-worker drain",
     "shared_exact uses MQFQ, not FIFO, since #785 Phase 3"),
];

const SCAN_DIRS: &[&str] = &[
    "src/afxdp/cos",
    "src/afxdp/types",
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
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
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
                    violations.push(Violation {
                        path: path.clone(),
                        line: lineno + 1,
                        pattern,
                        rationale,
                    });
                }
            }
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
