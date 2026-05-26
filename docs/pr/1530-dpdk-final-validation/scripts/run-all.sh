#!/usr/bin/env bash
#
# Phase B master driver — run G0..G5.e in sequence, regenerating
# summary.md after each gate.
#
# Pre-conditions:
#   1. #1528 PR has merged and the issue is CLOSED.
#   2. Smoke-runner singleton ab1c7bcf4d14b36b6 has granted cluster
#      access (caller is responsible for the SendMessage handshake;
#      this script does NOT auto-coordinate).
#
# Usage:
#   ./run-all.sh                            # auto-resolve Phase 3 SHA
#   ./run-all.sh <explicit-sha>             # override
#   STOP_ON_FAIL=0 ./run-all.sh             # continue past failed gates
#
# Each gate writes its own logs under artifacts/. After every gate
# (whether PASS or FAIL) the script regenerates summary.md so a
# partial-progress snapshot is always available.
#
# Exit 0 only if every gate PASSes; non-zero if any gate fails and
# STOP_ON_FAIL is non-zero (default).

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../../../.." && pwd)
ART_DIR=$(cd "$SCRIPT_DIR/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

STOP_ON_FAIL=${STOP_ON_FAIL:-1}
EXPLICIT_SHA=${1:-}

run_gate() {
    local label="$1"; shift
    echo
    echo "==================== $label ===================="
    set +e
    "$@"
    local rc=$?
    set -e
    "$SCRIPT_DIR/build-summary.sh" >/dev/null
    if [[ "$rc" -ne 0 ]]; then
        echo "$label: EXIT $rc"
        if [[ "$STOP_ON_FAIL" -ne 0 ]]; then
            echo "run-all: STOP_ON_FAIL=1 — aborting after $label"
            exit "$rc"
        fi
    fi
    return 0
}

# G0 — lock commit
if [[ -n "$EXPLICIT_SHA" ]]; then
    run_gate G0 "$SCRIPT_DIR/g0-lock-commit.sh" "$EXPLICIT_SHA"
else
    run_gate G0 "$SCRIPT_DIR/g0-lock-commit.sh"
fi

# G1 — clean grep
run_gate G1 "$SCRIPT_DIR/g1-grep-dpdk.sh"

# G2 — build + test
run_gate G2 "$SCRIPT_DIR/g2-build-test.sh"

# G3 — make targets gone
run_gate G3 "$SCRIPT_DIR/g3-make-dpdk-gone.sh"

# G5 pre-flight — cluster deploy + readiness (must run before G4
# CLI rejection because the daemon must be running on the cluster
# from the source-removal commit).
run_gate G5-deploy "$SCRIPT_DIR/g5-cluster-deploy.sh"

# G4 — CLI rejection (post-deploy, so the running daemon matches the
# source-removal SHA).
run_gate G4 "$SCRIPT_DIR/g4-cli-reject-dpdk.sh"

# G5.c prep — capture CoS DSCP map from running cluster.
run_gate G5-cos-map "$SCRIPT_DIR/g5-capture-cos-map.sh"

# G5.a + G5.b — CoS-off smoke
run_gate G5-cos-off "$SCRIPT_DIR/g5-smoke-cos-off.sh"

# G5.c — CoS-on class sweep
run_gate G5-cos-on  "$SCRIPT_DIR/g5-smoke-cos-on.sh"

# G5.d — screen baseline
run_gate G5-screen  "$SCRIPT_DIR/g5-screen-baseline.sh"

# G5.e — make test-failover
run_gate G5-failover "$SCRIPT_DIR/g5-failover.sh"

# Final summary refresh.
"$SCRIPT_DIR/build-summary.sh"

echo
echo "run-all: complete. Summary at docs/pr/1530-dpdk-final-validation/summary.md"
