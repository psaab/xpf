package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// #6743 r2-N3: the scoped `-race` gate must actually cover the tests whose
// property it exists to check.
//
// WHAT WAS WRONG, measured at 710a87569. The Makefile's `test-race-dp`
// target ran
//
//	go test -race ./pkg/daemon/ -run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit' -count=2
//
// which matched 19 of pkg/daemon's 1118 tests — and NONE of the tests this
// PR added that actually run a loop goroutine against a concurrently
// emptied cell: the seven in daemon_ha_userspace_stream_live_test.go
// matched nothing, nor did the seven capability tests, nor the escape
// tests. A PR whose headline gate is `-race` shipped that gate excluding
// its own concurrency tests.
//
// WHY A WIDER REGEX ALONE IS NOT THE FIX. A `-run` filter is a NAME
// predicate over a PROPERTY-defined set ("tests that exercise concurrent
// access to the #2114 cell"). Widening it fixes today's omission and
// leaves the mechanism that produced it: the next test added to one of
// these files is outside the gate the moment its name does not happen to
// match, and nothing says so. That is the same NAME-for-PROPERTY
// substitution this campaign has now hit seven times.
//
// So the regex is widened AND this canary makes the coverage itself an
// assertion: every Test function in the declared concurrency-binder files
// must match the regex the Makefile actually passes to -run. Add a test to
// one of those files with a name outside the pattern and this goes RED
// with the name and the fix.
//
// STATED RESIDUAL. The FILE list below is hand-maintained, so a
// concurrency binder written into a brand-new file is invisible here until
// the file is added. That is a strictly smaller and more visible surface
// than a name regex over 1118 tests, but it is not zero, and it is stated
// rather than implied: this canary binds "the regex has not fallen behind
// these files", not "these files are all the concurrency binders there
// are".

// raceGateConcurrencyFiles are the pkg/daemon test files whose tests drive
// the #2114 dataplane cell concurrently — a loop goroutine, a sampler
// overlap, a publish/disown against a live reader, or a management server
// resolving through the live indirection while the cell changes.
var raceGateConcurrencyFiles = []string{
	"daemon_dp_race_test.go",
	"daemon_ha_userspace_stream_live_test.go",
	"daemon_dp_capability_2114_test.go",
	"daemon_dp_escape_test.go",
	"daemon_dp_escape_rest_test.go",
	"daemon_dp_escape_canary_test.go",
	"full_resync_per_call_6743_test.go",
	"reconcile_one_snapshot_6743_test.go",
}

// raceGateRunPattern extracts the regex the Makefile passes to `-run` in
// the test-race-dp recipe. It reads the REAL Makefile so the canary cannot
// drift from the gate it is describing.
func raceGateRunPattern(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	inRecipe := false
	for _, line := range lines {
		if strings.HasPrefix(line, "test-race-dp:") {
			inRecipe = true
			continue
		}
		if !inRecipe {
			continue
		}
		// The recipe ends at the first non-indented, non-blank line.
		if line != "" && !strings.HasPrefix(line, "\t") {
			break
		}
		if !strings.Contains(line, "-run") {
			continue
		}
		// The A58-04 go test -list guard lines carry -list, not the
		// race run; the race line is the one invoking test -race (the
		// guard lines only name test-race-dp in prose).
		if !strings.Contains(line, "test -race") {
			continue
		}
		m := regexp.MustCompile(`-run\s+'([^']*)'`).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("test-race-dp recipe line has -run but no single-quoted pattern: %q", line)
		}
		return m[1]
	}
	t.Fatal("no `-run '<pattern>'` found in the test-race-dp recipe: the gate's scope " +
		"can no longer be read, so this canary cannot certify it. If the filter was " +
		"REMOVED (the whole package now races), delete this canary and say so.")
	return ""
}

// TestRaceGateCoversTheConcurrencyBinders is the fail-on-narrowing guard.
//
// RED-on-revert: restore the Makefile's old
// `-run 'DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit'` and
// every event-stream, capability and escape test is reported here.
func TestRaceGateCoversTheConcurrencyBinders(t *testing.T) {
	t.Parallel()

	pattern := raceGateRunPattern(t)
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("test-race-dp -run pattern %q does not compile: %v", pattern, err)
	}

	fset := token.NewFileSet()
	var uncovered []string
	total := 0
	for _, name := range raceGateConcurrencyFiles {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v — if the file was renamed or removed, update "+
				"raceGateConcurrencyFiles rather than deleting this assertion", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			total++
			if !re.MatchString(fn.Name.Name) {
				uncovered = append(uncovered, name+":"+fn.Name.Name)
			}
		}
	}

	// CONTROL: refuse a zero denominator. An empty file list, a parse that
	// silently found no tests, or a rename would otherwise make this test
	// vacuously green — the failure shape that looks exactly like success.
	if total == 0 {
		t.Fatal("found ZERO Test functions across raceGateConcurrencyFiles: this canary " +
			"is certifying nothing")
	}

	if len(uncovered) > 0 {
		t.Fatalf("%d of %d concurrency-binder tests are OUTSIDE the -race gate's -run "+
			"pattern %q:\n  %s\n\nThe gate runs `go test -race ./pkg/daemon/ -run <pattern>`, "+
			"so these never execute under the race detector. Either widen the pattern in "+
			"the Makefile's test-race-dp recipe or move the test out of these files.",
			len(uncovered), total, pattern, strings.Join(uncovered, "\n  "))
	}
}

// TestRaceGateCoverageCanaryDetectsANarrowedPattern is the self-test: it
// drives the same matching logic against a deliberately narrow pattern, so
// a canary that silently stopped matching cannot make the guard above
// vacuously green.
//
// It is a separate body from the guard because the guard's own green is
// the thing being questioned.
func TestRaceGateCoverageCanaryDetectsANarrowedPattern(t *testing.T) {
	t.Parallel()

	// The pre-r2 pattern, verbatim. It must leave real tests uncovered.
	re := regexp.MustCompile(`DataplaneCell|NATPoolAlarm|ForwardingStatus|BootstrapExit`)

	fset := token.NewFileSet()
	uncovered := 0
	total := 0
	for _, name := range raceGateConcurrencyFiles {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			total++
			if !re.MatchString(fn.Name.Name) {
				uncovered++
			}
		}
	}
	if total == 0 {
		t.Fatal("self-test found ZERO Test functions: the matcher is not running")
	}
	if uncovered == 0 {
		t.Fatalf("the pre-r2 pattern covers ALL %d concurrency-binder tests, which "+
			"contradicts the measurement this canary was built from. Either the matching "+
			"logic has stopped working, or the tests were renamed to match it — in which "+
			"case this self-test needs a new narrow pattern to stay meaningful", total)
	}
}
