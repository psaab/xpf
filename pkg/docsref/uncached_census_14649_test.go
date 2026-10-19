package docsref

import (
	"os"
	"path/filepath"
	"sort"
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
	// #15255 (A91-04): pkg/dataplane's eBPF-retirement canaries exec
	// `git ls-files` / `git archive HEAD` (legacy_bpf_manifest_canary,
	// userspace_xdp_manifest_launder). Index/HEAD are not cache inputs,
	// so a re-added legacy BPF source returned "ok (cached)".
	"./pkg/dataplane/",
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
			name: "all four uncached on one leg",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/ ./pkg/dataplane/\n\n",
			want: nil,
		},
		{
			name: "refactoraudit only is the pre-14649 shape",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/", "./pkg/dataplane/"},
		},
		{
			name: "named without -count=1 is cached",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/ ./pkg/dataplane/\n\n",
			want: []string{"./pkg/refactoraudit/", "./pkg/docsref/", "./pkg/memlockcensus/", "./pkg/dataplane/"},
		},
		{
			name: "named only in a comment proves nothing",
			mk: "test-go:\n" +
				"\t# -count=1 ./pkg/refactoraudit/ ./pkg/docsref/ ./pkg/memlockcensus/ ./pkg/dataplane/\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/", "./pkg/dataplane/"},
		},
		{
			name: "count1 on another line does not uncache this one",
			mk: "test-go:\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" -count=1 ./pkg/refactoraudit/\n" +
				"\tbash ./scripts/go-test-json.sh \"\" \"$(GO)\" ./pkg/docsref/ ./pkg/memlockcensus/ ./pkg/dataplane/\n\n",
			want: []string{"./pkg/docsref/", "./pkg/memlockcensus/", "./pkg/dataplane/"},
		},
		{
			name: "no test-go target at all",
			mk:   "test:\n\t@true\n",
			want: []string{"./pkg/refactoraudit/", "./pkg/docsref/", "./pkg/memlockcensus/", "./pkg/dataplane/"},
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

// gitExecPackages15255 returns the sorted repo-relative package dirs
// whose *_test.go files exec git — every package whose verdict can
// change with the index/HEAD without any hashed input changing
// (#15255 A91-04). The census is derived, not listed: a hand-kept
// list is exactly what let pkg/dataplane escape the #14649 leg.
func gitExecPackages15255(root string) ([]string, error) {
	found := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "target", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(raw), `exec.Command("git"`) {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		found["./"+filepath.ToSlash(rel)+"/"] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// TestMakefileRunsTreeCensusesUncached15255 is the #15255 closure of
// the #14649 guard: the uncached leg must cover EVERY package whose
// tests exec git, derived by scanning the tree — not the three
// packages somebody remembered in 14649. pkg/dataplane's canaries
// (`git ls-files bpf/**`, `git archive HEAD`) were the escape: a
// re-added legacy BPF source changed only the index, the cached
// ./... leg returned "ok (cached)", and the retirement gate passed
// without running.
//
// FAIL-ON-REVERT: drop ./pkg/dataplane/ from the -count=1 leg, or
// add a git-execing *_test.go to any package outside the leg.
func TestMakefileRunsTreeCensusesUncached15255(t *testing.T) {
	root := repoRoot(t)
	want, err := gitExecPackages15255(root)
	if err != nil {
		t.Fatalf("scan tree for git-execing tests: %v", err)
	}
	if len(want) < 4 {
		t.Fatalf("only %v git-exec packages found — the scan is broken, so "+
			"the 'all covered' result below would be vacuous", want)
	}
	// The derived set and the pinned list must agree: a new git-exec
	// package forces an explicit addition here AND to the Makefile.
	pinned := append([]string{}, uncachedCensusPackages14649...)
	sort.Strings(pinned)
	if strings.Join(want, ",") != strings.Join(pinned, ",") {
		t.Fatalf("#15255: git-execing test packages %v do not match the pinned "+
			"uncached census list %v — add the new package to both "+
			"uncachedCensusPackages14649 and the Makefile -count=1 leg, or stop "+
			"execing git from its tests", want, pinned)
	}
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if missing := uncachedCensusMissing14649(string(b)); len(missing) > 0 {
		t.Fatalf("#15255: the Makefile test-go target does not run %s with -count=1, "+
			"so its git-driven canaries can pass from cache without running",
			strings.Join(missing, ", "))
	}
}
