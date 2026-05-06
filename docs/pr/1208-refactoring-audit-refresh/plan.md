---
status: REVISED v3 — Codex+Gemini r2 PLAN-NEEDS-MINOR (stale §5 invariant text). v3 ready to ship.
issue: #1208
phase: single PR — tooling + doc; no production code
---

## Round-1 verdict resolution

Convergent findings (both reviewers):

- **Awk pattern is fundamentally broken.** Codex: doesn't strip 2-line
  `#[cfg(test)]\nmod tests {` style (e.g., `protocol.rs:1863`, which
  becomes a false ≥2K candidate). Gemini: `EOF` is not an awk
  keyword — evaluates to uninitialized `0` (false), so the range
  pattern matches from start to end-of-file silently, erasing any
  production code that comes AFTER an inline test block.
  **v2 abandons the awk approach entirely. Test files are excluded
  by filename pattern; non-test files use total LOC.**
- **Skip patterns incomplete.** Both flag missing `*.pb.go`,
  `*_grpc.pb.go`, `*_bpfel.go`, `*_bpfeb.go`, and missing relocated-
  test exclusions like `(^|/)(tests\.rs|.*_tests\.rs)$` (the #1034
  colocation pattern produces these files at thousands of LOC each
  — frame/tests.rs at 4443, session_glue/tests.rs at 3570 —
  catastrophic false-positives). **v2 expands the skip regex.**
- **Sort determinism**: needs `LC_ALL=C sort -k1,1nr -k2,2` for
  cross-platform reproducibility (Codex + Gemini both flag).
- **Watch-list vs candidate categorization**: Gemini suggests
  separate sections / labels. **v2 adds `[REFACTOR]` and `[WATCH]`
  prefixes.**



## 1. Issue framing

Per #1208 and Codex CoS findings retrospective: `docs/refactoring-audit.md`
predates many landed splits. Many files it lists no longer exist or
have been refactored; some large files it doesn't list deserve watching.

## 2. Scope

Replace static doc with:

1. `docs/refactoring-audit.md` — narrative explaining the modularity
   rule from `docs/engineering-style.md` (>2K LOC = refactor candidate)
   and how to regenerate the audit.
2. `scripts/refactoring-audit.sh` — bash script producing a deterministic
   `(prod_loc, file)` table excluding generated code (bpf2go output,
   `vendor/`, `target/`, `_KILLED`/`_WITHDRAWN` plan files, large
   evidence artifacts under `docs/pr/*/findings*.md`).
3. `docs/refactoring-audit-current.txt` — committed regeneration that
   the script produces. Sorted by LOC desc, regenerated periodically.

## 3. Concrete deliverables

### `scripts/refactoring-audit.sh` (v2)

```bash
#!/usr/bin/env bash
# Modularity audit: list files >=1500 LOC, sorted desc with category
# tags ([REFACTOR] for >=2000, [WATCH] for 1500-1999).
#
# Test files and generated code are excluded by name pattern. We
# deliberately do NOT try to strip inline `#[cfg(test)] mod tests`
# blocks — that approach is fragile (awk range patterns silently
# erase production code that follows the test block). The #1034
# colocated-tests refactor moved most inline test blocks to
# `tests.rs` siblings anyway; remaining inline test blocks are rare
# and accepting the modest over-count is simpler than a brittle
# stripper.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# Skip:
#  - target/, vendor/ (build artifacts)
#  - generated bpf2go output (*_bpfel.go, *_bpfeb.go, also
#    *_x86_bpfel.go via the parent pattern)
#  - generated protobuf (*.pb.go, *_grpc.pb.go)
#  - generated zz_generated_*
#  - relocated/colocated tests (#1034): tests.rs, *_tests.rs, *_test.go
#  - test_support.rs (test-only helpers)
#  - plan retrospectives marked KILLED / WITHDRAWN
#  - findings docs (large evidence artifacts under docs/pr/*/)
#  - lockfiles
SKIP_RE='(^|/)(target|vendor)/'
SKIP_RE+='|/zz_generated'
SKIP_RE+='|_bpfel\.go$|_bpfeb\.go$'
SKIP_RE+='|\.pb\.go$|_grpc\.pb\.go$'
SKIP_RE+='|(^|/)tests\.rs$|_tests\.rs$|_test\.go$'
SKIP_RE+='|(^|/)test_support\.rs$'
SKIP_RE+='|/_KILLED|/_WITHDRAWN'
SKIP_RE+='|docs/pr/[^/]+/findings'
SKIP_RE+='|\.lock$'

categorize() {
    local loc=$1
    if [ "$loc" -ge 2000 ]; then echo "[REFACTOR]"; else echo "[WATCH]   "; fi
}

audit_rust() {
    find userspace-dp/src dpdk_worker -name '*.rs' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}

audit_go() {
    find pkg cmd dpdk_worker -name '*.go' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}

# LC_ALL=C + multi-key sort: descending LOC (col 2), ascending path (col 3)
(audit_rust; audit_go) | LC_ALL=C sort -k2,2nr -k3,3
```

### `docs/refactoring-audit.md` (rewritten body)

Short narrative:
- Rule: files >2000 LOC (Rust prod + Go) are refactor candidates per
  `docs/engineering-style.md`.
- Files 1500-2000 LOC are watch-list.
- Run `scripts/refactoring-audit.sh` to regenerate
  `docs/refactoring-audit-current.txt`.
- Re-run before any plan that touches a large file so the plan can
  cite current sizes.

### `docs/refactoring-audit-current.txt`

Generated output committed at PR open time. Format:
```
 NNNN  path/to/file.rs
 NNNN  path/to/another.go
```

## 4. Public API preservation

None. Tooling + doc only.

## 5. Hidden invariants

- Script must be deterministic (same output across runs at same git
  HEAD). Use `find ... | sort` discipline + `LC_ALL=C` for
  cross-platform locale-independent ordering.
- Skip-regex must not accidentally exclude legitimate large files.
- LOC metric is **total file LOC** for non-test, non-generated files.
  v2 abandoned the inline test-block stripping approach: it required
  fragile awk pattern matching, and the `EOF`-not-keyword bug caused
  silent erasure of any production code following an inline test
  block. The #1034 colocated-tests refactor moved most inline test
  blocks to sibling `tests.rs` files anyway; remaining inline cases
  are rare and the modest over-count is acceptable at 1500-2000 LOC
  thresholds.

## 6. Risk

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **NONE** | Tooling only |
| Stale audit at merge time | LOW | Regenerate at PR creation |
| Wrong skip pattern | LOW | Reviewers can flag specific exclusions |

## 7. Test plan

- `bash scripts/refactoring-audit.sh` runs without error.
- Output is non-empty (we have known >2K LOC files).
- Output is sorted desc by first column.
- Manual sanity check: top 5 entries match the user's auto-memory
  scan from 2026-05-01 (which found "every userspace-dp Rust
  production file under threshold after the 18-PR refactor stream").
- Re-running produces identical output (deterministic).

## 8. Out of scope

- CI integration (post a comment on PRs that cross 2000 LOC) — file
  as a follow-up if desired.
- Auto-regeneration on commit hook — too invasive; keep manual.
- Per-language LOC tools (cloc, scc) — overkill.

## 9. Open questions for adversarial review

1. Should the audit also flag files in the 1500-2000 LOC "watch-list"
   range, or only refactor candidates? **Resolved: yes; tagged
   `[WATCH]` separately from `[REFACTOR]`.**
2. Should `pkg/api/handlers.go` etc. (Go side) use raw LOC or some
   adjusted metric? **Resolved: total LOC for non-test files.**
3. ~~Is the `awk '/^#\[cfg(test)\] mod tests/,EOF'` pattern reliable~~
   **Resolved: awk approach abandoned in v2 entirely (Gemini r1
   caught the EOF-not-keyword bug). v2 excludes test files by name
   pattern instead.**

## 10. Verdict request

PLAN-READY → execute.
PLAN-NEEDS-MINOR → tweak.
