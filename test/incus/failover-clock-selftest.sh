#!/usr/bin/env bash
# Hermetic tests for the crash-failover clock resync (#11872).
# No incus, cluster, network, or real system clock changes.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/failover-clock-lib.sh
source "${SCRIPT_DIR}/failover-clock-lib.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
export CLOCK_CALLS="${TMP_DIR}/incus-calls"
export CLOCK_DATE_CALLS="${TMP_DIR}/date-calls"
: > "$CLOCK_CALLS"
: > "$CLOCK_DATE_CALLS"

# Fixed, host-side UTC clock reading. Logging survives command substitution.
date() {
	printf '%s\n' called >> "$CLOCK_DATE_CALLS"
	printf '%s\n' '2026-10-02 12:34:56'
}

CLOCK_FAIL_NODE=""
incus() {
	local args="$*" node
	[[ "$1" == exec ]] || return 90
	shift
	node="$1"
	printf '%s\n' "$args" >> "$CLOCK_CALLS"
	[[ "$node" != "$CLOCK_FAIL_NODE" ]]
}

if failover_resync_node_clocks fw0 fw1 >"${TMP_DIR}/ok.out" 2>&1; then
	if [[ "$(cat "$CLOCK_CALLS")" == $'exec fw0 -- date -u -s 2026-10-02 12:34:56\nexec fw1 -- date -u -s 2026-10-02 12:34:56' &&
	      "$(wc -l < "$CLOCK_DATE_CALLS")" -eq 1 ]]; then
		ok "both nodes receive the same single host UTC reading"
	else
		bad "both nodes receive the same single host UTC reading"
	fi
else
	bad "both nodes receive the same single host UTC reading"
fi

: > "$CLOCK_CALLS"
CLOCK_FAIL_NODE=fw0
if failover_resync_node_clocks fw0 fw1 >"${TMP_DIR}/failed.out" 2>&1; then
	bad "one clock-set failure is returned after attempting both nodes"
else
	if [[ "$(wc -l < "$CLOCK_CALLS")" -eq 2 &&
	      "$(cat "$CLOCK_CALLS" | cut -d' ' -f2 | tr '\n' ' ')" == 'fw0 fw1 ' &&
	      "$(cat "${TMP_DIR}/failed.out")" == *"FAILED to set fw0"* &&
	      "$(cat "${TMP_DIR}/failed.out")" == *"fw1 set to 2026-10-02 12:34:56 UTC"* ]]; then
		ok "failure names the node and does not skip the peer"
	else
		bad "failure names the node and does not skip the peer"
	fi
fi

if failover_resync_node_clocks >/dev/null 2>&1; then
	bad "empty node list is refused"
else
	ok "empty node list is refused"
fi

echo "----------------------------------------"
echo "failover clock selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
