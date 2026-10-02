#!/usr/bin/env bash
# Hermetic tests for test-window scoping of failover journal diagnostics (#11873).
# No incus, cluster, systemd journal, or network.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/failover-journal-lib.sh
source "${SCRIPT_DIR}/failover-journal-lib.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
export FAKE_JOURNAL="${TMP_DIR}/journal.tsv"
: > "$FAKE_JOURNAL"

# This incus fixture models journald's exclusive cursor boundary over a tiny
# retained journal. Entries before the captured cursor represent the rolling
# deploy; the later entry is from the failover test window.
incus() {
	local node seq text last_seq=0 after_cursor=""
	[[ "$1" == exec ]] || return 90
	shift
	node="$1"
	shift
	[[ "$1" == -- ]] || return 91
	shift
	[[ "$1" == journalctl ]] || return 92
	shift
	for arg in "$@"; do
		case "$arg" in
		--show-cursor) ;;
		--after-cursor=cursor-*) after_cursor="${arg#--after-cursor=cursor-}" ;;
		esac
	done
	if [[ -z "$after_cursor" && " $* " == *" --show-cursor "* ]]; then
		[[ "${FAIL_CURSOR_CAPTURE:-0}" == 0 ]] || return 93
		while IFS=$'\t' read -r seq text; do last_seq="$seq"; done < "$FAKE_JOURNAL"
		printf '%s\n' "-- cursor: cursor-${last_seq}"
		return 0
	fi
	[[ -n "$after_cursor" ]] || return 94
	while IFS=$'\t' read -r seq text; do
		if (( seq > after_cursor )); then
			printf '%s\n' "$text"
		fi
	done < "$FAKE_JOURNAL"
}

printf '1\tdeploy-time no-RETH sync-hold timeout\n2\tdeploy-time degraded promotion\n' > "$FAKE_JOURNAL"
cursor=$(failover_capture_journal_cursor fw0) || cursor=""
if [[ "$cursor" == cursor-2 ]]; then
	ok "test-start cursor is captured from the active journal"
else
	bad "test-start cursor is captured from the active journal"
fi

printf '3\ttest-window manual failback readiness gate\n' >> "$FAKE_JOURNAL"
window=$(failover_journal_after_cursor fw0 "$cursor" 2>"${TMP_DIR}/journal.err") || window=""
if [[ "$window" == *"test-window manual failback readiness gate"* &&
      "$window" != *"deploy-time"* ]]; then
	ok "failure diagnostic includes test-window records, not deploy transients"
else
	bad "failure diagnostic includes test-window records, not deploy transients"
fi

if failover_journal_after_cursor fw0 "" >"${TMP_DIR}/empty.out" 2>"${TMP_DIR}/empty.err"; then
	bad "empty cursor refuses to return an unscoped journal"
else
	if [[ ! -s "${TMP_DIR}/empty.out" &&
	      "$(cat "${TMP_DIR}/empty.err")" == *"refusing an unscoped read"* ]]; then
		ok "empty cursor refuses to return an unscoped journal"
	else
		bad "empty cursor refuses to return an unscoped journal"
	fi
fi

if FAIL_CURSOR_CAPTURE=1 failover_capture_journal_cursor fw0 >/dev/null 2>&1; then
	bad "failed cursor capture is reported"
else
	ok "failed cursor capture is reported"
fi

echo "----------------------------------------"
echo "failover journal selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
