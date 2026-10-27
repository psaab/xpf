package docsref

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestIsHistoricalArchive17115 pins the shared historical-archive set
// (#17115, R4-Q47-03), including the docs/log/ arm the CI selector already
// assumed docsref had. Both consumers load scripts/historical-paths.txt.
//
// FAIL-ON-REVERT: drop the docs/log/* pattern from the data file (the old
// hand-kept Go predicate) and the docs/log/1.md cell fails.
func TestIsHistoricalArchive17115(t *testing.T) {
	cases := []struct {
		file string
		want bool
	}{
		{"_Log.md", true},
		{"docs/log/1.md", true},
		{"docs/log/14649.md", true},
		{"docs/issues/1-history.md", true},
		{"docs/issues/1-history-archive.md", true},
		{"docs/research/1/plan" + ".md", false},
		{"docs/log.md", false},
		{"docs/issues/1-plan" + ".md", false},
		{"pkg/docsref/docsref_test.go", false},
	}
	for _, tc := range cases {
		if got := isHistoricalArchive(tc.file); got != tc.want {
			t.Errorf("isHistoricalArchive(%q) = %v, want %v (#17115)", tc.file, got, tc.want)
		}
	}
}

// TestHistoricalPatternsSharedWithSelector17115 binds the two consumers to
// the one data file (#17115): scripts/historical-paths.txt must be the only
// place either side names a historical-archive path literal, and the
// selector must load it (no second hand-kept copy in Python).
//
// FAIL-ON-REVERT: restore the hard-coded docs/log/ arm in the selector or
// inline the set in Go and this test fails.
func TestHistoricalPatternsSharedWithSelector17115(t *testing.T) {
	root := repoRoot(t)
	pats := loadHistoricalPatterns17115(t, root)
	// The docs/log arm is load-bearing: acceptance requires it present.
	foundLog := false
	for _, p := range pats {
		if p == "docs/log/*" {
			foundLog = true
		}
	}
	if !foundLog {
		t.Fatalf("#17115: %s lacks docs/log/* (patterns=%v)", historicalPathsFile, pats)
	}

	selector, err := os.ReadFile(filepath.Join(root, "scripts/ci_affected_go_tests.sh"))
	if err != nil {
		t.Fatalf("read selector: %v", err)
	}
	sel := string(selector)
	if !strings.Contains(sel, "historical-paths.txt") {
		t.Errorf("#17115: selector does not load scripts/historical-paths.txt")
	}
	// No duplicated literal outside the loader in the two consumer sources.
	literal := regexp.MustCompile("\"docs" + `/log/`)
	for _, src := range []struct{ name, path string }{
		{"selector", "scripts/ci_affected_go_tests.sh"},
		{"docsref_test.go", "pkg/docsref/docsref_test.go"},
	} {
		b, err := os.ReadFile(filepath.Join(root, src.path))
		if err != nil {
			t.Fatalf("read %s: %v", src.path, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if literal.MatchString(line) {
				t.Errorf("#17115: %s:%d re-introduces a docs/log literal instead of loading %s: %s",
					src.name, i+1, historicalPathsFile, strings.TrimSpace(line))
			}
		}
	}

	// The loaded Go set, sorted, is exactly the data file (loader parity).
	got := append([]string{}, historicalPatterns17115...)
	sort.Strings(got)
	want := append([]string{}, pats...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("#17115: package patterns %v != file patterns %v", got, want)
	}
}
