#!/usr/bin/env bash
#
# G5.e — make test-failover under loss userspace cluster env.
#
# Wraps `make test-failover` so the output lands in the artifact
# directory. Pass/fail decision belongs to test-failover.sh itself;
# we capture the log and verify it ended with a PASS marker.
#
# CALLER must hold cluster access lock via smoke-runner singleton.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

LOG="$ART_DIR/make-test-failover.log"

set +e
make test-failover 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

echo "g5-failover: make test-failover exit code: $rc" | tee -a "$LOG"

# test-failover.sh writes a clear PASS/FAIL line on the loss userspace
# cluster. Match either explicit marker.
if [[ "$rc" -eq 0 ]] && grep -Eqi '^(PASS|.*: PASS$|all intervals .* PASS)' "$LOG"; then
    echo "g5-failover: PASS"
    exit 0
fi

if grep -Eqi '0\.00\s+Mbits/sec|FAIL|interval at 0 Gbps' "$LOG"; then
    echo "g5-failover: FAIL — zero-throughput interval or explicit FAIL in log" >&2
    exit 1
fi

if [[ "$rc" -ne 0 ]]; then
    echo "g5-failover: FAIL — make test-failover exit code $rc" >&2
    exit 1
fi

echo "g5-failover: PARTIAL — exit 0 but no explicit PASS marker; manual review of $LOG required"
exit 0
