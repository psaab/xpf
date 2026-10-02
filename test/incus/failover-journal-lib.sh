#!/usr/bin/env bash
#
# Test-window journal access for failover diagnostics (#11873).

# failover_capture_journal_cursor <node>
#   Return the node's current journal cursor, suitable as an exclusive
#   --after-cursor boundary. Failure is explicit; callers must not fall back to
#   an unscoped journal read, which can attribute deploy-time transients to the
#   test.
failover_capture_journal_cursor() {
	local node="$1" output cursor
	output=$(incus exec "$node" -- journalctl --show-cursor -n 0 --no-pager 2>/dev/null) || return 1
	cursor=$(printf '%s\n' "$output" | sed -n 's/^-- cursor: //p' | tail -1)
	[[ -n "$cursor" ]] || return 1
	printf '%s\n' "$cursor"
}

# failover_journal_after_cursor <node> <cursor>
#   Read xpfd journal entries strictly after a previously captured cursor.
#   Refuse an empty boundary rather than silently returning the full journal.
failover_journal_after_cursor() {
	local node="$1" cursor="$2"
	[[ -n "$cursor" ]] || {
		echo "failover journal cursor is empty; refusing an unscoped read" >&2
		return 1
	}
	incus exec "$node" -- journalctl --after-cursor="$cursor" -u xpfd -n 5000 --no-pager
}
