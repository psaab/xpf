#!/usr/bin/env bash
#
# G1 — Clean grep for the DPDK retirement.
#
# Runs `grep -rIn -i 'dpdk'` against the worktree (excluding .git,
# .claude, and historical docs/issues) and post-filters into a
# violations log. PASS if violations log is empty.
#
# Allowed-residue policy (matches #1530 acceptance criteria):
#   - CHANGELOG / retirement-note text (top-level CHANGELOG* files
#     and docs/retirement* notes)
#   - This issue's own runbook / artifact text
#     (docs/pr/1530-dpdk-final-validation/**)
#   - Historical docs/issues/*.md entries (already excluded by
#     --exclude-dir)
#   - Rejection-path test names containing dpdk in the file path
#     (e.g. *_reject_dpdk_test.go)
#
# Anything else — *.go, *.c, *.h, Makefile*, README.md, CLAUDE.md,
# AGENTS.md, or any other docs/*.md outside the retirement-note set
# — counts as a violation.
#
# Usage:
#   ./g1-grep-dpdk.sh          # run from any directory; resolves repo root
#
# Writes:
#   artifacts/grep-dpdk-raw.log         (all matches)
#   artifacts/grep-dpdk-violations.log  (post-filtered residue)
#
# Exit 0 if violations log is empty, 1 if violations remain, 2 on
# infra error (e.g. dpdk_worker/ still exists).

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

RAW="$ART_DIR/grep-dpdk-raw.log"
VIOL="$ART_DIR/grep-dpdk-violations.log"

# Hard check: forbidden directories must be gone.
INFRA_FAIL=0
for dir in dpdk_worker pkg/dataplane/dpdk; do
    if [[ -e "$dir" ]]; then
        echo "g1: INFRA-FAIL — $dir still present" >&2
        INFRA_FAIL=1
    fi
done
if [[ $INFRA_FAIL -ne 0 ]]; then
    echo "g1: at least one removed dataplane directory still exists. Phase 3 incomplete." >&2
    exit 2
fi

# Raw scan.
grep -rIn -i 'dpdk' . \
    --exclude-dir=.git \
    --exclude-dir=.claude \
    --exclude-dir=docs/issues \
    > "$RAW" || true

# Post-filter into violations.
#
# Allowed lines, dropped here:
#   1. CHANGELOG and top-level retirement-note files
#   2. docs/retirement* / docs/dpdk-retirement* / docs/pr/1530-dpdk-* paths
#   3. Rejection-path test files (file path contains reject_dpdk /
#      reject-dpdk)
#
# Everything else surfaces as a violation.
awk -F: '
{
    path = $1
    # Allowed: top-level CHANGELOG / RETIREMENT files.
    if (path ~ /^\.\/(CHANGELOG|RETIREMENT)/) next
    # Allowed: this issue runbook tree.
    if (path ~ /^\.\/docs\/pr\/1530-dpdk-final-validation\//) next
    # Allowed: explicit retirement notes.
    if (path ~ /^\.\/docs\/retirement/) next
    if (path ~ /^\.\/docs\/dpdk-retirement/) next
    # Allowed: rejection-path test names.
    if (path ~ /reject[_-]dpdk/) next
    # Allowed: AGENTS.md / CLAUDE.md historical retirement note blocks
    # are NOT auto-allowed — they should have been cleaned up in
    # Phase 4 (#1529). If the doc-sweep PR left intentional retirement
    # markers, they will surface here for explicit acceptance.
    print
}
' "$RAW" > "$VIOL"

VIOL_COUNT=$(wc -l < "$VIOL" | tr -d ' ')

echo "g1: raw matches:        $(wc -l < "$RAW" | tr -d ' ')"
echo "g1: post-filter residue: $VIOL_COUNT"

if [[ "$VIOL_COUNT" -eq 0 ]]; then
    echo "g1: PASS — no production DPDK references remain."
    exit 0
fi

echo "g1: FAIL — production DPDK references remain. See $VIOL" >&2
head -20 "$VIOL" >&2
exit 1
