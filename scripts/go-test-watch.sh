#!/usr/bin/env bash
# #18778: run a full go-test command line ("$GO" test ...) with its stdout
# passed through scripts/go-timeout-watch.awk. Used by the test-race-dp
# legs, whose recipe lines must keep the literal `test -race` text the
# #16715 / #6743 race-gate censuses parse. Exits with the command's status,
# or 3 (VOID, with a banner on stderr) when go test hit its -timeout, unless
# the leg also changed production state on the host: then 1 (#19090).
set -u
here=$(cd "$(dirname "$0")" && pwd)
# #19090 R13-a: a leg that timed out AND changed production state on the host
# is a FAIL (1), not VOID (3). The state change is real whatever the timeout,
# and a rerun comes back clean because the files are already gone.
# testguard-run.sh records a state change in $XPF_TESTGUARD_STATE_VERDICT; a
# caller's own file is used as is (it reads the verdict too), otherwise this
# wrapper makes one for the leg.
if [ -z "${XPF_TESTGUARD_STATE_VERDICT:-}" ]; then
	own_state_verdict=$(mktemp "${TMPDIR:-/tmp}/go-test-watch-state.XXXXXX") || {
		echo "go-test-watch.sh: cannot create the state verdict file; refusing to run a leg whose state change could be voided" >&2
		exit 2
	}
	export XPF_TESTGUARD_STATE_VERDICT=$own_state_verdict
	trap 'rm -f "$own_state_verdict"' EXIT
fi
exit_void_unless_state_changed() {
	if grep -qx 'state-changed' "$XPF_TESTGUARD_STATE_VERDICT" 2>/dev/null; then
		echo "go-test-watch.sh: FAIL: the leg timed out AND changed production state on the host; that is a FAIL (1), not VOID (3) (#19090)" >&2
		exit 1
	fi
	exit 3
}
# -json in GOFLAGS changes go's stdout format, so pin the text output this
# watcher consumes. `go test` accepts this flag after packages and args.
"$here/testguard-run.sh" "$@" -json=false | awk -f "$here/go-timeout-watch.awk"
rc=("${PIPESTATUS[@]}")
if [ "${rc[1]}" -eq 3 ]; then
	exit_void_unless_state_changed
fi
exit "${rc[0]}"
