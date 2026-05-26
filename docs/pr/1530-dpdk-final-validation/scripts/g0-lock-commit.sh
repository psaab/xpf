#!/usr/bin/env bash
#
# G0 — Lock the worktree to the merge SHA of the #1528 (DPDK Phase 3
# mechanical removal) PR.
#
# Usage:
#   ./g0-lock-commit.sh                   # auto-resolve via gh
#   ./g0-lock-commit.sh <explicit-sha>    # override
#
# Writes:
#   artifacts/commit.txt        — resolved SHA + HEAD verification
#   artifacts/commit-show.txt   — git log -1 --stat output
#
# Exit 0 only if HEAD matches the resolved SHA. Any other state aborts.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

if [[ $# -ge 1 ]]; then
    SHA="$1"
    echo "g0: using explicit SHA $SHA"
else
    echo "g0: resolving Phase 3 merge SHA from gh..."
    SHA=$(gh pr list --state merged --search "1528 in:title" \
        --json mergeCommit,number,title \
        --jq '.[] | select(.title | test("1528")) | .mergeCommit.oid' \
        | head -n1)
    if [[ -z "$SHA" ]]; then
        echo "g0: ERROR — could not resolve #1528 merge SHA. Pass one explicitly." >&2
        exit 1
    fi
    echo "g0: resolved #1528 merge SHA: $SHA"
fi

git fetch origin master --quiet
git checkout "$SHA"

HEAD_SHA=$(git rev-parse HEAD)
if [[ "$HEAD_SHA" != "$SHA"* && "$SHA" != "$HEAD_SHA"* ]]; then
    echo "g0: ERROR — HEAD ($HEAD_SHA) does not match target ($SHA)" >&2
    exit 2
fi

{
    echo "target_sha=$SHA"
    echo "head_sha=$HEAD_SHA"
    echo "checkout_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee "$ART_DIR/commit.txt"

git log -1 --stat | tee "$ART_DIR/commit-show.txt"

echo "g0: PASS — locked to $HEAD_SHA"
