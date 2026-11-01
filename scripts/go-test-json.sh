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
# With an EMPTY first argument this runs `<go> test <args>` with no `-json`
# and no `jq`; its stdout passes through the #18778 timeout watcher (awk),
# which changes no line. That is deliberate: `make test-go` is the shared gate
# and its default path must not acquire a jq dependency. The selftest asserts
# the default path's stdout and exit code match a direct `go test`, except
# that a go-test timeout exits 3 (VOID).
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

# #18778: both paths run the shared timeout predicate
# (scripts/go-timeout-watch.awk). The default path pipes the human stream
# through it (it changes no line); the side-file path runs it afterwards over
# this leg's events tagged by package, because -json interleaves packages.
# go test's timeout aborts a package mid-run, so every later test in it never
# runs; the watcher prints a VOID banner naming the package(s) and the script
# exits 3, so a cut-off package reads as neither a pass nor an ordinary FAIL.
here=$(cd "$(dirname "$0")" && pwd)
timeout_watch() { awk -f "$here/go-timeout-watch.awk"; }

if [ -z "$json" ]; then
	"$go_bin" test "$@" | timeout_watch
	rc=("${PIPESTATUS[@]}")
	if [ "${rc[1]}" -eq 3 ]; then
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

# #18778 (seat AC): this leg's events start at the side file's current size.
# The file is APPENDED to, so an earlier leg's timeout must not void this one.
off=$(stat -c %s "$json" 2>/dev/null || echo 0)

# stderr is deliberately NOT piped. `go test -json` reports build and setup
# failures on stderr as plain text, not as JSON events, so folding it into the
# pipe would both corrupt the event stream and hide the message.
"$go_bin" test -json "$@" | tee -a "$json" | jq -j 'select(.Output != null) | .Output'
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
# The timeout check runs over THIS leg's events, tagged by package. -json
# interleaves packages line by line, so the watcher's "next line" pairing is
# only sound within one package's Output; the reconstructed human stream above
# cannot be used for it. Every Output chunk is split on newline so each line
# keeps its package tag. An empty chunk stays ONE empty line: jq's
# `"" | split("\n")` is [], and losing the blank line after a hung Example's
# panic breaks shape B's sequence (measured).
tail -c +"$((off + 1))" "$json" |
	jq -r 'select(.Output != null) | (.Package // "") as $p | (.Output | rtrimstr("\n")) as $o | (if $o == "" then [""] else ($o | split("\n")) end)[] | $p + "\t" + .' |
	awk -v TAGGED=1 -f "$here/go-timeout-watch.awk"
wrc=("${PIPESTATUS[@]}")
if [ "${wrc[1]}" -ne 0 ]; then
	echo "go-test-json.sh: jq failed reading $json for the timeout check (rc=${wrc[1]}); cannot tell whether a package timed out" >&2
	exit 2
fi
if [ "${wrc[2]}" -eq 3 ]; then
	exit 3
fi
exit "${rc[0]}"
