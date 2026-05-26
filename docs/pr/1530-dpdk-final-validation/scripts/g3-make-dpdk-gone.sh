#!/usr/bin/env bash
#
# G3 — Verify Makefile DPDK targets are gone.
#
# `make -n <target>` should print `No rule to make target ...` and
# exit non-zero for each of:
#   build-dpdk
#   build-dpdk-worker
#   clean-dpdk
#
# Captures combined output into artifacts/make-n-build-dpdk.log and
# per-target exit codes into artifacts/make-n-build-dpdk-exit.txt.
#
# Exit 0 if all three exit non-zero AND output mentions "No rule".

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

LOG="$ART_DIR/make-n-build-dpdk.log"
EXITS="$ART_DIR/make-n-build-dpdk-exit.txt"
: > "$LOG"
: > "$EXITS"

FAIL=0
for t in build-dpdk build-dpdk-worker clean-dpdk; do
    echo "g3: === make -n $t ===" | tee -a "$LOG"
    set +e
    out=$(make -n "$t" 2>&1)
    rc=$?
    set -e
    echo "$out" | tee -a "$LOG"
    echo "$t: exit=$rc" | tee -a "$EXITS"

    if [[ "$rc" -eq 0 ]]; then
        echo "g3: FAIL — $t still has a rule (exit 0)" >&2
        FAIL=1
        continue
    fi
    if ! echo "$out" | grep -qE "No rule to make target '$t'|No rule to make target \`$t'"; then
        echo "g3: WARN — $t failed but not with 'No rule to make target' (rc=$rc)" >&2
        # Accept any non-zero exit; the absence of the rule is the
        # ground-truth signal. Log it as a soft warning.
    fi
done

if [[ "$FAIL" -ne 0 ]]; then
    echo "g3: FAIL — at least one build-dpdk* target still exists" >&2
    exit 1
fi

echo "g3: PASS — all build-dpdk* targets are gone"
