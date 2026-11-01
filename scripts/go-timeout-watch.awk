# #18778: the ONE go-test timeout predicate, shared by scripts/go-test-json.sh,
# scripts/go-test-watch.sh and mutate-lib.sh's mutation_timed_out.
#
# go test's -timeout aborts a package mid-run, so every later test in it never
# runs. Three output shapes mean that, and each needs TWO signals so that a test
# which merely PRINTS the text is never mistaken for one:
#
#   A  the alarm fired with tests running: column-0 "panic: test timed out
#      after" and, as that package's next line, go's indented "running tests:".
#   B  the alarm fired with NO test running (a hung Example; testing tracks only
#      t.Run tests in its running list): the same column-0 panic line, then a
#      blank line and the goroutine dump. The second signal is the alarm's own
#      frame as the FIRST frame of the first goroutine after the panic, in
#      exactly go's sequence: panic line, [running list], blank line,
#      "goroutine N [running]:", "testing.(*M).startAlarm.func1()". A test
#      that prints the frame text anywhere else does not pair.
#   C  the binary hung outside m.Run (a TestMain), so the alarm was never
#      armed: cmd/go kills it at -timeout + 1m and prints "*** Test killed with
#      quit: ran too long (1m1s)." (or "*** Test killed: ran too long" when the
#      signal could not be delivered), immediately followed by that package's
#      "FAIL<TAB><pkg>" line.
#
# Input modes:
#   default        a text stream. Every line passes through to stdout
#                  unchanged. cmd/go keeps each package's text output
#                  contiguous, so one stream state reset at every package
#                  terminal line is sound, and the package is named from its
#                  "FAIL<TAB><pkg>" line.
#   -v DETECTONLY=1  the same, printing nothing (mutate-lib reads a saved log).
#   -v TAGGED=1    "<pkg><TAB><output line>" lines built from a `go test -json`
#                  stream. Prints nothing. -json interleaves packages line by
#                  line (measured: 582 package switches in a two-package run),
#                  so "the next line" is only meaningful WITHIN a package and
#                  the state is kept per package.
#
# Exit 3 with a banner on stderr naming every timed-out package; 0 otherwise.
function hit(k, s) { if (!pending[k]) shape[k] = s; pending[k] = 1 }
function record(k, name) {
	if (!(name in named)) { named[name] = 1; order[++n] = name; why[name] = shape[k] }
	pending[k] = 0
}
{
	if (TAGGED) {
		i = index($0, "\t")
		k = substr($0, 1, i - 1)
		line = substr($0, i + 1)
	} else {
		k = ""
		line = $0
		if (!DETECTONLY) { print; fflush() }
	}
	if (armedA[k]) { armedA[k] = 0; if (line ~ /^[ \t]+running tests:/) hit(k, "A") }
	if (armedC[k]) { armedC[k] = 0; if (line ~ /^FAIL\t/) hit(k, "C") }
	# Shape B's sequence: st 1 after the panic line (the running list's
	# indented lines keep it there), 2 after the blank line, 3 after the
	# goroutine header; the alarm frame on the next line is the hit.
	if (st[k] == 3) {
		if (line ~ /^testing\.\(\*M\)\.startAlarm\.func1\(\)/) hit(k, "B")
		st[k] = 0
	} else if (st[k] == 2) {
		st[k] = (line ~ /^goroutine [0-9]+ \[running\]:$/) ? 3 : 0
	} else if (st[k] == 1) {
		if (line == "") st[k] = 2
		else if (line !~ /^\t/) st[k] = 0
	}
	if (line ~ /^panic: test timed out after /) {
		armedA[k] = 1
		st[k] = 1
	}
	if (line ~ /^\*\*\* Test killed( with [A-Za-z]+)?: ran too long /) armedC[k] = 1
	# A package's terminal line: "FAIL<TAB><pkg>..." or "ok  <TAB><pkg>...".
	# Name a pending timeout from it, then reset the stream state so one
	# package's panic line can never pair with the next package's output.
	if (line ~ /^(FAIL|ok)[ \t]+[^ \t]/) {
		split(line, f, /[ \t]+/)
		if (pending[k]) record(k, TAGGED ? k : f[2])
		st[k] = 0
		armedA[k] = 0
	}
}
END {
	for (k in pending) {
		if (pending[k]) record(k, (TAGGED && k != "") ? k : "(package not named in the output)")
	}
	if (n == 0) exit 0
	list = order[1]
	for (j = 2; j <= n; j++) list = list ", " order[j]
	print "go-test VOID: go test hit its -timeout in " list "." > "/dev/stderr"
	for (j = 1; j <= n; j++) {
		s = why[order[j]]
		d = (s == "A") ? "alarm fired with tests running" : (s == "B") ? "alarm fired with no test running (e.g. a hung Example)" : "binary killed by go test at -timeout + 1m (e.g. a hung TestMain)"
		print "  " order[j] ": " d > "/dev/stderr"
	}
	print "  Every test after that point in those packages NEVER RAN, so each is" > "/dev/stderr"
	print "  neither a pass nor an attributable failure. Failures reported for OTHER" > "/dev/stderr"
	print "  packages in this leg are still real. Rerun with a longer -timeout" > "/dev/stderr"
	print "  (make GOTEST_TIMEOUT=...) or on a quieter host." > "/dev/stderr"
	exit 3
}
