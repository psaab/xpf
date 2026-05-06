#!/usr/bin/env bash
# Modularity audit (#1208): list files >=1500 LOC, sorted desc with
# category tags ([REFACTOR] for >=2000, [WATCH] for 1500-1999).
#
# Test files and generated code are excluded by name pattern. We
# deliberately do NOT try to strip inline `#[cfg(test)] mod tests`
# blocks — that approach is fragile (awk range patterns silently
# erase production code that follows the test block, per Gemini
# round-1 finding). The #1034 colocated-tests refactor moved most
# inline test blocks to `tests.rs` siblings anyway; remaining inline
# test blocks are rare and accepting the modest over-count is
# simpler than a brittle stripper.
#
# Run from repo root or anywhere — uses `git rev-parse` to anchor.
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

# LC_ALL=C + multi-key sort: descending LOC (col 2), ascending path (col 3).
# Both reviewers flagged that bare `sort -rn` yields locale-dependent
# tie-breakers — explicit multi-key + LC_ALL=C is reproducible.
(audit_rust; audit_go) | LC_ALL=C sort -k2,2nr -k3,3
