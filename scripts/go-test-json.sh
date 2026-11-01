#!/usr/bin/env bash
# go-test-json.sh — run a `go test` leg, optionally teeing a machine-readable
# `go test -json` stream to a side file while leaving stdout byte-identical.
#
# #8231. The mutation driver gates through `make test-go` / `make test-rust`
# because those targets carry legs a bare `go test` does not — `go vet`, the
# targeted `-race` runs with `-count=2`, and on the Rust side `--release` and
# `--test-threads=1`. So its KILLED verdicts are COUNT-based: they say
# *something* failed, not that the cell's target failed. If another test in the
# package was already red, a cell that changed nothing scores KILLED with rc and
# count in agreement and nothing looking wrong. That is a false claim of
# coverage, and only a NAME can refute it.
#
# The wrong repair is to convert the driver to `go test -json`, which would buy
# attribution and pay for it in gate coverage. This is the right one: the GATE
# TARGET emits the machine-readable stream alongside its normal output, so
# attribution costs nothing.
#
# usage: go-test-json.sh <jsonfile-or-empty> <go> [go test args...]
#
# With an EMPTY first argument this execs `<go> test <args>` unchanged — no
# `-json`, no `jq`, no pipeline. That is deliberate: `make test-go` is the shared
# gate and its default path must not acquire a jq dependency or a new failure
# mode. The selftest asserts the default path's stdout and exit code are
# identical to a direct `go test`.
#
# With a jsonfile it runs `<go> test -json <args>`, APPENDS the raw event stream
# to that file, and reconstructs the human-readable stream on stdout from the
# `.Output` fields. That reconstruction is exact: `go test -json` carries every
# byte the text formatter would have written, in order, in `.Output`.
set -u

json=${1-}
shift || true
if [ "$#" -eq 0 ]; then
	echo "go-test-json.sh: usage: go-test-json.sh <jsonfile-or-empty> <go> [args...]" >&2
	exit 2
fi
go_bin=$1
shift

# #18778: go test's timeout panic aborts a package mid-run, so every later
# test in it never runs. That is neither a pass nor an attributable failure:
# VOID the leg loudly with a distinct status (3) instead of letting it read
# as an ordinary FAIL. The detector passes every line through unchanged.
timeout_watch() {
	awk '{ print; fflush() } /^panic: test timed out after /{ t = 1 } END { exit t ? 3 : 0 }'
}
void_banner() {
	echo "go-test-json.sh: VOID: go test hit its -timeout (\"panic: test timed out\")." >&2
	echo "  Every test after that point in the timed-out package NEVER RAN; this leg is" >&2
	echo "  neither a pass nor an attributable failure. Rerun with a longer -timeout" >&2
	echo "  (make GOTEST_TIMEOUT=...) or on a quieter host." >&2
}

if [ -z "$json" ]; then
	"$go_bin" test "$@" | timeout_watch
	rc=("${PIPESTATUS[@]}")
	if [ "${rc[1]}" -eq 3 ]; then
		void_banner
		exit 3
	fi
	exit "${rc[0]}"
fi

if ! command -v jq >/dev/null 2>&1; then
	# Fail loudly rather than silently dropping to the plain path. A caller that
	# asked for a machine-readable stream and got a human one would attribute
	# over an empty file and read "no failing tests" — the exact
	# indistinguishable-from-healthy value this file exists to prevent.
	echo "go-test-json.sh: GOTESTJSON was set but jq is not installed; refusing to" >&2
	echo "  run, because a caller that asked for attribution must not silently get" >&2
	echo "  a stream it cannot attribute over." >&2
	exit 2
fi

# stderr is deliberately NOT piped. `go test -json` reports build and setup
# failures on stderr as plain text, not as JSON events, so folding it into the
# pipe would both corrupt the event stream and hide the message.
"$go_bin" test -json "$@" | tee -a "$json" | jq -j 'select(.Output != null) | .Output' | timeout_watch
rc=("${PIPESTATUS[@]}")

# rc[0] is the verdict. tee and jq are reported separately because a failure in
# either means the SIDE FILE is untrustworthy, which a caller attributing over
# it has to know — and `${PIPESTATUS[0]}` alone would report the test result and
# say nothing about whether the stream survived.
if [ "${rc[1]}" -ne 0 ]; then
	echo "go-test-json.sh: tee failed (rc=${rc[1]}); $json is incomplete" >&2
	exit 2
fi
if [ "${rc[2]}" -ne 0 ]; then
	echo "go-test-json.sh: jq failed (rc=${rc[2]}); the reconstructed output above is truncated" >&2
	exit 2
fi
if [ "${rc[3]}" -eq 3 ]; then
	void_banner
	exit 3
fi
exit "${rc[0]}"
