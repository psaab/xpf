# #18778: shared go-test timeout watcher for scripts/go-test-json.sh and
# scripts/go-test-watch.sh. It passes EVERY line through unchanged and
# detects go test's own timeout panic: a column-0 "panic: test timed out
# after" line IMMEDIATELY followed by go's indented "running tests:" line.
# Both are required, so a test that merely prints "timed out" (indented
# t.Log output, or its own unindented text) is not mistaken for one. The
# timed-out package is taken from go's next "FAIL<TAB><pkg>" line.
{ print; fflush() }
armed == 1 { if ($0 ~ /^[ \t]+running tests:/) t = 1; armed = 0 }
/^panic: test timed out after / { armed = 1 }
t == 1 && pkg == "" && /^FAIL\t/ { split($0, f, "\t"); pkg = f[2] }
END {
	if (t) {
		if (pkg == "") pkg = "(package not named in the output)"
		print "go-test VOID: go test hit its -timeout in " pkg "." > "/dev/stderr"
		print "  Every test after that point in " pkg " NEVER RAN, so that package is" > "/dev/stderr"
		print "  neither a pass nor an attributable failure. Failures reported for OTHER" > "/dev/stderr"
		print "  packages in this leg are still real. Rerun with a longer -timeout" > "/dev/stderr"
		print "  (make GOTEST_TIMEOUT=...) or on a quieter host." > "/dev/stderr"
		exit 3
	}
}
