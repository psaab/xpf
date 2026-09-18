package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// #9045: `test-race-dp` races three packages. pkg/daemon and pkg/cluster each
// carry a canary that fails when their leg's `-run` pattern narrows.
// pkg/dataplane's race recipe now names all concurrency probes:
//
//	TestPersistentNATTable_AllConcurrentSaveNoRace   NO MATCH
//	TestStatusPathReadRacesCompileWrite_6740         NO MATCH
//	TestDetachXDPIsSerializedWithFenceLease7547      matched after #10302
//
// THE FIRST TWO are the argument for this file. Their bodies are pure race
// **zero** `t.Error`/`t.Fatal` of any kind. It is a pure race probe -- the only
// way it can fail is the race detector firing -- so outside the race leg it is
// not a weak test, it is a test that CANNOT fail. It spent its life green
// while asserting nothing, and no counter anywhere was wrong.
//
// THE PREDICATE IS THE BODY, NOT THE FILE, and that distinction is load-
// bearing. The originating report swept test FILES containing `go func` and
// counted 33 tests, 14 of them inside the pattern. But `persistent_nat_test.go`
// holds fifteen ordinary table tests beside one concurrency probe, so a
// file-level predicate demands the race leg run tests that exercise no
// concurrency at all -- it over-reports by 24. Asking whether a test's OWN
// body launches a goroutine gives 9, and those 9 are the population that has
// anything to say under `-race`.
//
// Being structural rather than a hand-kept list is the point: a probe whose
// whole value is `-race` looks exactly like a passing test when excluded, so a
// NEW one must be caught by construction rather than by somebody remembering.

// dataplaneRaceRunPattern reads the REAL Makefile so this canary cannot drift
// from the gate it describes.
//
// It selects the recipe line by the PACKAGE PATH it races, not by position.
// pkg/daemon's canary reads "the FIRST -run line", which forced a comment in
// the Makefile warning that this leg "must stay BELOW the pkg/daemon one" -- a
// positional coupling a harmless reordering silently breaks. Keying on
// `./pkg/dataplane/` has no such hazard.
func dataplaneRaceRunPattern(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	inRecipe := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "test-race-dp:") {
			inRecipe = true
			continue
		}
		if !inRecipe {
			continue
		}
		if line != "" && !strings.HasPrefix(line, "\t") {
			break // the recipe ends at the first non-indented, non-blank line
		}
		if !strings.Contains(line, "./pkg/dataplane/") || !strings.Contains(line, "-run") {
			continue
		}
		m := regexp.MustCompile(`-run\s+'([^']*)'`).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("the ./pkg/dataplane/ race line has -run but no single-quoted "+
				"pattern: %q", line)
		}
		return m[1]
	}
	t.Fatal("no `-run '<pattern>'` line racing ./pkg/dataplane/ found in the " +
		"test-race-dp recipe. If the filter was REMOVED (the whole package now " +
		"races), delete this canary and say so in the commit. If the leg itself " +
		"was deleted, pkg/dataplane is no longer race-gated and that is the finding.")
	return ""
}

// launchesGoroutine reports whether fn's own body contains a `go` statement.
// A goroutine started by a helper the test calls is not counted: the helper's
// concurrency belongs to whichever test drives it, and attributing it here
// would re-introduce the file-level over-report described above.
func launchesGoroutine(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if _, ok := n.(*ast.GoStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func TestRaceGateCoversDataplaneConcurrencyProbes9045(t *testing.T) {
	t.Parallel()

	pattern := dataplaneRaceRunPattern(t)
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("the ./pkg/dataplane/ race -run pattern %q does not compile: %v",
			pattern, err)
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var uncovered []string
	probes, testsSeen := 0, 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			testsSeen++
			if !launchesGoroutine(fn) {
				continue
			}
			probes++
			if !re.MatchString(fn.Name.Name) {
				uncovered = append(uncovered, name+":"+fn.Name.Name)
			}
		}
	}

	// TWO POSITIVE CONTROLS, because this cell has two ways to pass while
	// having measured nothing.
	//
	// (1) The walk found no tests at all -- a parse or directory failure
	//     reported as full coverage.
	if testsSeen == 0 {
		t.Fatal("the AST walk found zero Test functions in pkg/dataplane, so the " +
			"coverage result is a measurement of the walk, not of the gate")
	}
	// (2) The walk found tests but classified none as a probe -- a broken
	//     goroutine predicate, which is the exact shape that reports a clean
	//     zero for a population it cannot see.
	if probes == 0 {
		t.Fatalf("the goroutine predicate classified 0 of %d tests as concurrency "+
			"probes. pkg/dataplane is known to contain several, so this is a "+
			"predicate defect reported as a clean result.", testsSeen)
	}

	if len(uncovered) > 0 {
		t.Errorf("the ./pkg/dataplane/ race leg's -run pattern %q excludes %d of %d "+
			"goroutine-launching tests (%d tests scanned):\n  %s\n\n"+
			"A probe excluded from this leg still PASSES, so nothing reports the "+
			"loss -- and TestPersistentNATTable_AllConcurrentSaveNoRace has zero "+
			"assertions of any kind, so outside `-race` it cannot fail at all.\n"+
			"Widen the pattern in the Makefile's ./pkg/dataplane/ line.",
			pattern, len(uncovered), probes, testsSeen, strings.Join(uncovered, "\n  "))
	}
	t.Logf("#9045: %d goroutine-launching probes, all inside the race leg (%d tests scanned)",
		probes, testsSeen)
}
