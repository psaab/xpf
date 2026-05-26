#!/usr/bin/env bash
#
# G2 — Clean build + test gate.
#
# Runs each of:
#   make build
#   make build-ctl
#   make build-userspace-dp
#   make test
#
# Each writes to its own log under artifacts/. PASS only if all four
# exit 0 and `make test` shows no FAIL / panic / build error lines.
#
# Also records SHA-256 hashes of the three produced binaries into
# artifacts/binary-hashes.txt.
#
# Usage: ./g2-build-test.sh

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

run_step() {
    local label="$1"; shift
    local logfile="$ART_DIR/$label.log"
    echo "g2: == $label =="
    if "$@" 2>&1 | tee "$logfile"; then
        echo "g2:   $label: exit 0"
    else
        local rc=${PIPESTATUS[0]}
        echo "g2: FAIL — $label exited $rc. See $logfile" >&2
        return "$rc"
    fi
}

FAIL=0
run_step make-build              make build              || FAIL=1
run_step make-build-ctl          make build-ctl          || FAIL=1
run_step make-build-userspace-dp make build-userspace-dp || FAIL=1
run_step make-test               make test               || FAIL=1

# make test sometimes returns 0 even when a sub-package fails on
# certain CI configurations. Do a belt-and-braces scan.
if grep -E '^(--- FAIL|FAIL\s|panic:|^\s*FAIL\s+[a-z])' "$ART_DIR/make-test.log" >/dev/null 2>&1; then
    echo "g2: FAIL — make test log contains failure markers" >&2
    FAIL=1
fi

# Binary hashes.
HASH_FILE="$ART_DIR/binary-hashes.txt"
: > "$HASH_FILE"
for bin in xpfd cli userspace-dp/target/release/xpf-userspace-dp; do
    if [[ -f "$bin" ]]; then
        sha256sum "$bin" | tee -a "$HASH_FILE"
    else
        echo "g2: FAIL — expected binary missing: $bin" >&2
        echo "MISSING $bin" >> "$HASH_FILE"
        FAIL=1
    fi
done

if [[ "$FAIL" -ne 0 ]]; then
    echo "g2: FAIL — one or more build/test steps failed" >&2
    exit 1
fi

echo "g2: PASS — all four steps clean, hashes in $HASH_FILE"
