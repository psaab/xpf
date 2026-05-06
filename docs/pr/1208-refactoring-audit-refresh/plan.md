---
status: DRAFT v1 — pending adversarial plan review
issue: #1208
phase: single PR — tooling + doc; no production code
---

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

### `scripts/refactoring-audit.sh`

```bash
#!/usr/bin/env bash
# Modularity audit: list files >1500 prod LOC, sorted desc.
# "Prod LOC" = total LOC minus inline `#[cfg(test)] mod tests` blocks
# for Rust, minus `_test.go` files for Go.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# Skip generated code, vendor, target, plan retrospectives, large
# evidence artifacts.
SKIP_RE='(target/|vendor/|/zz_generated|_test\.go$|/_KILLED|/_WITHDRAWN|/findings|userspace-dp/target/|\.lock$)'

audit_rust() {
    find userspace-dp/src dpdk_worker -name '*.rs' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            total=$(wc -l < "$f")
            test_block=$(awk '/^#\[cfg\(test\)\] *mod tests/,EOF' "$f" | wc -l)
            prod=$((total - test_block))
            if [ "$prod" -ge 1500 ]; then
                printf "%5d  %s\n" "$prod" "$f"
            fi
        done
}

audit_go() {
    find pkg cmd dpdk_worker -name '*.go' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            prod=$(wc -l < "$f")
            if [ "$prod" -ge 1500 ]; then
                printf "%5d  %s\n" "$prod" "$f"
            fi
        done
}

(audit_rust; audit_go) | sort -rn
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
  HEAD). Use `find ... | sort` discipline.
- Skip-regex must not accidentally exclude legitimate large files.
- LOC method should match what `docs/engineering-style.md` already
  defines as "production LOC" (existing memory note specifies "total
  lines minus inline `#[cfg(test)] mod tests` block").

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
   range, or only refactor candidates?
2. Should `pkg/api/handlers.go` etc. (Go side) use raw LOC or some
   adjusted metric?
3. Is the `awk '/^#\[cfg(test)\] mod tests/,EOF'` pattern reliable for
   the Rust test-block stripping? Files using `#[path = "tests.rs"]
   mod tests;` (the colocated-tests pattern from #1034 series) have
   no inline test block, so the awk returns 0 lines and prod LOC =
   total LOC — which is correct.

## 10. Verdict request

PLAN-READY → execute.
PLAN-NEEDS-MINOR → tweak.
