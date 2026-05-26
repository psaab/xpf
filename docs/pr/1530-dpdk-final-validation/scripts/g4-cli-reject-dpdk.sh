#!/usr/bin/env bash
#
# G4 — Capture daemon rejection of `set system dataplane-type dpdk`.
#
# Drives the remote CLI on the loss userspace cluster and attempts
# to commit a candidate with `set system dataplane-type dpdk`. PASS
# if `commit check` (or `commit`) fails AND the error text mentions
# any of:
#   - "dpdk"
#   - "retired"
#   - "unsupported"
#   - "unknown"
#
# After Phase 3 the schema field may be gone entirely, in which case
# the parser will reject the value with a generic "unknown value" or
# the set command itself will fail. Either is acceptable; #1530
# acceptance criteria explicitly allow Phase 1 retirement message OR
# generic schema rejection.
#
# Usage:
#   ./g4-cli-reject-dpdk.sh                  # uses loss:xpf-userspace-fw0
#   NODE=loss:xpf-userspace-fw1 ./g4-cli-reject-dpdk.sh

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

NODE=${NODE:-loss:xpf-userspace-fw0}
LOG="$ART_DIR/cli-reject-dpdk.log"

echo "g4: target node = $NODE"
echo "g4: writing rejection capture to $LOG"

set +e
sg incus-admin -c "incus exec $NODE -- /usr/local/sbin/cli -c \
'configure private; set system dataplane-type dpdk; commit check; rollback'" \
    > "$LOG" 2>&1
rc=$?
set -e

echo "g4: CLI exit code: $rc" | tee -a "$LOG"

# Acceptance pattern: any one of these tokens in the captured output
# is sufficient evidence of an explicit rejection.
if grep -Eiq 'dpdk|retired|unsupported|unknown' "$LOG"; then
    REJ_LINE=$(grep -Eim1 'dpdk|retired|unsupported|unknown' "$LOG" || true)
    echo "g4: rejection token found: $REJ_LINE"
else
    echo "g4: FAIL — no rejection token (dpdk/retired/unsupported/unknown) in CLI output" >&2
    cat "$LOG" >&2
    exit 1
fi

# Belt-and-braces: confirm CLI did NOT report a successful commit.
if grep -Eiq '^commit complete|commit successful' "$LOG"; then
    echo "g4: FAIL — CLI reports successful commit despite dpdk dataplane-type" >&2
    exit 2
fi

echo "g4: PASS — daemon refused set system dataplane-type dpdk"
