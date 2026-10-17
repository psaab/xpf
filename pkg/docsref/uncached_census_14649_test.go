package docsref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uncachedCensusPackages14649 are the tree-reading census packages whose
// verdicts depend on inputs the go test cache does not hash: the working
// tree, the git index, and `git grep` output. See the #6626/#14649 comment
// above the -count=1 leg in the Makefile's test-go target.
var uncachedCensusPackages14649 = []string{
	"./pkg/refactoraudit/",
	"./pkg/docsref/",
	"./pkg/memlockcensus/",
}

// uncachedCensusMissing14649 returns the census packages that no recipe line
// of the Makefile's test-go target runs with -count=1.
//
// The property is per-package and per-line, not a file-wide string search:
// a package named only in a comment, or named on a cached invocation while
// -count=1 sits on a different line, is exactly the cached-pass bug wearing
// the shape of a fix (#6626's audit_canary lesson, applied to #14649).
func uncachedCensusMissing14649(mk string) []string {
	lines := strings.Split(mk, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "test-go:") {
			start = i
			break
		}
	}
	if start < 0 {
		return append([]string{}, uncachedCensusPackages14649...)
	}
	satisfied := map[string]bool{}
	for _, line := range lines[start+1:] {
		if line == "" {
			break // end of the test-go recipe block
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // recipe comment lines prove nothing
		}
		if !strings.Contains(line, "-count=1") {
			continue
		}
		for _, pkg := range uncachedCensusPackages14649 {
			if strings.Contains(line, pkg) {
				satisfied[pkg] = true
			}
		}
	}
	var missing []string
	for _, pkg := range uncachedCensusPackages14649 {
		if !satisfied[pkg] {
			missing = append(missing, pkg)
		}
	}
	return missing
}

// TestMakefileRunsTreeCensusesUncached14649 binds the #14649 fix to the
// wiring that makes it live.
//
// Both this package and pkg/memlockcensus decide their verdicts from
// `git grep` over the tracked tree and read only the files it lists.
// Neither the cited/registered files (unless compiled into this package),
// the index, nor the grep output is a go test cache input, so under the
// plain ./... leg a new dangling citation or a new unregistered
// RemoveMemlock guard changes nothing the cache hashes: in a linked
// worktree `make test-go` returned "ok (cached)" for a tree carrying a
// new violation, even after `git add`, while -count=1 failed. Nothing
// inside Go can detect that from within a cached run — the test simply
// never executes — so the fix lives in the Makefile and this test guards
// the Makefile.
//
// FAIL-ON-REVERT: drop ./pkg/docsref/ or ./pkg/memlockcensus/ from the
// -count=1 leg of the test-go target, or drop -count=1 from that leg.
func TestMakefileRunsTreeCensusesUncached14649(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if missing := uncachedCensusMissing14649(string(b)); len(missing) > 0 {
		t.Fatalf("#14649: the Makefile test-go target does not run %s with -count=1.\n\n"+
			"These packages read the tracked tree via git grep, which is not a go test "+
			"cache input, so on the cached ./... leg a new violation in a linked "+
			"worktree returns \"ok (cached)\" and the gate passes without running. "+
			"Add the package(s) to the -count=1 leg in test-go (see the #6626/#14649 "+
			"comment there).", strings.Join(missing, ", "))
	}
}

// TestUncachedCensusGuardRejectsStaleShapes14649 pins the guard itself:
// the shapes that look like the fix but leave a census cached must be
// reported missing, or the guard above would green on a reverted Makefile.
func TestUncachedCensusGuardRejectsStaleShapes14649(t *testing.T) {
	cases := []struct {
		name string
		mk   string
		want []string
	}{
		{
			name: "all three uncached on one leg",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/\n\n",
			want: nil,
		},
		{
			name: "refactoraudit only is the pre-14649 shape",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/"},
		},
		{
			name: "named without -count=1 is cached",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/\n\n",
			want: []string{"./pkg/refactoraudit/", "./pkg/docsref/", "./pkg/memlockcensus/"},
		},
		{
			name: "named only in a comment proves nothing",
			mk: "test-go:\n" +
				"\t# -count=1 ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/"},
		},
		{
			name: "count1 on another line does not uncache this one",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" ./pkg/docsref/ ./pkg/memlockcensus/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/"},
		},
		{
			name: "no test-go target at all",
			mk:   "test:\n\t@true\n",
			want: []string{"./pkg/refactoraudit/", "./pkg/docsref/", "./pkg/memlockcensus/"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uncachedCensusMissing14649(tc.mk)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("uncachedCensusMissing14649 = %v, want %v", got, tc.want)
			}
		})
	}
}
