#!/usr/bin/env bash
# #18778: run a full go-test command line ("$GO" test ...) with its stdout
# passed through scripts/go-timeout-watch.awk. Used by the test-race-dp
# legs, whose recipe lines must keep the literal `test -race` text the
# #16715 / #6743 race-gate censuses parse. Exits with the command's status,
# or 3 (VOID, with a banner on stderr) when go test hit its -timeout.
set -u
here=$(cd "$(dirname "$0")" && pwd)
"$@" | awk -f "$here/go-timeout-watch.awk"
rc=("${PIPESTATUS[@]}")
if [ "${rc[1]}" -eq 3 ]; then
	exit 3
fi
exit "${rc[0]}"
