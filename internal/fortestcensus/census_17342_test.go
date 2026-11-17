package fortestcensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const allowFile = "scripts/go-fortest-seams.allow"

// The real module: every exported *ForTest* func and method has a row with a
// reason, and every row names one that exists.
func TestExportedForTestSeamsHaveARow17342(t *testing.T) {
	root := filepath.Join("..", "..")
	rows, malformed, err := readAllow(filepath.Join(root, filepath.FromSlash(allowFile)))
	if err != nil {
		t.Fatal(err)
	}
	seams, err := scanSeams(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d exported *ForTest* seams, %d rows", len(seams), len(rows))
	// Anti-vacuity: the tree has ~150 of them; a walk that found a handful
	// missed the tree, and the rows it could not match would read as the
	// list's fault rather than the walk's.
	if len(seams) < 100 {
		t.Errorf("only %d exported seams found under %s; the walk did not see the tree", len(seams), root)
	}
	for _, p := range append(malformed, check(seams, rows, allowFile)...) {
		t.Error(p)
	}
}

// fixture writes the given files under a temporary root.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const mgr = "package a\n\ntype Mgr struct{}\n\ntype Other struct{}\n\n"

func TestForTestSeamRuleCells17342(t *testing.T) {
	cells := []struct {
		name  string
		files map[string]string
		rows  map[string]string
		want  []string // each a substring of exactly one problem; no others
	}{
		{name: "an exported func with a row passes",
			files: map[string]string{"pkg/a/a.go": "package a\n\nfunc FooForTest() {}\n"},
			rows:  map[string]string{"pkg/a.FooForTest": "r"}},
		{name: "a new exported func without a row fails, named",
			files: map[string]string{"pkg/a/a.go": "package a\n\nfunc FooForTest() {}\n"},
			want:  []string{"exported seam pkg/a.FooForTest has no row"}},
		{name: "a new exported method without a row fails, named with its receiver",
			files: map[string]string{"pkg/a/a.go": mgr + "func (m *Mgr) ResetForTesting() {}\n"},
			want:  []string{"exported seam pkg/a.(Mgr).ResetForTesting has no row"}},
		{name: "an exported method on an unexported type still needs a row",
			files: map[string]string{"pkg/a/a.go": "package a\n\ntype srv struct{}\n\nfunc (s srv) DrainForTest() {}\n"},
			want:  []string{"exported seam pkg/a.(srv).DrainForTest has no row"}},
		{name: "a generic receiver is keyed by its type name",
			files: map[string]string{"pkg/a/a.go": "package a\n\ntype Cache[K comparable, V any] struct{}\n\nfunc (c *Cache[K, V]) DropForTest() {}\n"},
			rows:  map[string]string{"pkg/a.(Cache).DropForTest": "r"}},
		{name: "a stale row fails",
			files: map[string]string{"pkg/a/a.go": "package a\n\nfunc FooForTest() {}\n"},
			rows:  map[string]string{"pkg/a.FooForTest": "r", "pkg/a.GoneForTest": "r"},
			want:  []string{"stale row pkg/a.GoneForTest"}},
		{name: "a row for another receiver does not cover the seam, and is stale",
			files: map[string]string{"pkg/a/a.go": mgr + "func (m *Mgr) ResetForTest() {}\n"},
			rows:  map[string]string{"pkg/a.(Other).ResetForTest": "r"},
			want:  []string{"exported seam pkg/a.(Mgr).ResetForTest has no row", "stale row pkg/a.(Other).ResetForTest"}},
		{name: "same-named seams in two packages each need a row",
			files: map[string]string{"pkg/a/a.go": "package a\n\nfunc FooForTest() {}\n", "pkg/b/b.go": "package b\n\nfunc FooForTest() {}\n"},
			rows:  map[string]string{"pkg/a.FooForTest": "r"},
			want:  []string{"exported seam pkg/b.FooForTest has no row"}},
		{name: "unexported seams are the deadcode gate's, not this rule's",
			files: map[string]string{"pkg/a/a.go": mgr + "func setClockForTest() {}\n\nfunc (m *Mgr) resetForTest() {}\n"}},
		{name: "a seam declared in a _test.go file is not product code",
			files: map[string]string{"pkg/a/a.go": "package a\n", "pkg/a/a_test.go": "package a\n\nfunc HelperForTest() {}\n"}},
		{name: "a comment or string naming a seam is not a seam",
			files: map[string]string{"pkg/a/a.go": "package a\n\n// FooForTest is gone.\nvar s = \"func BarForTest() {}\"\n"}},
		{name: "a row for a seam that is now unexported is stale",
			files: map[string]string{"pkg/a/a.go": "package a\n\nfunc fooForTest() {}\n"},
			rows:  map[string]string{"pkg/a.FooForTest": "r"},
			want:  []string{"stale row pkg/a.FooForTest"}},
		{name: "vendor and testdata are not scanned",
			files: map[string]string{"vendor/x/x.go": "package x\n\nfunc FooForTest() {}\n", "pkg/a/testdata/t.go": "package t\n\nfunc FooForTest() {}\n"}},
		{name: "an interface's exported method without a row fails, keyed by the interface",
			files: map[string]string{"pkg/a/a.go": "package a\n\ntype applier interface {\n\tApply() error\n\tApplyFailedForTesting() bool\n}\n"},
			want:  []string{"exported seam pkg/a.(applier).ApplyFailedForTesting has no row"}},
		{name: "an interface's method with a row passes; unexported and embedded members are not seams",
			files: map[string]string{"pkg/a/a.go": "package a\n\nimport \"io\"\n\ntype applier interface {\n\tio.Reader\n\tresetForTest()\n\tApplyFailedForTesting() bool\n}\n"},
			rows:  map[string]string{"pkg/a.(applier).ApplyFailedForTesting": "r"}},
		{name: "a nested package is keyed by its full directory",
			files: map[string]string{"pkg/a/b/c.go": "package b\n\nfunc FooForTest() {}\n"},
			want:  []string{"exported seam pkg/a/b.FooForTest has no row"}},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			seams, err := scanSeams(fixture(t, c.files))
			if err != nil {
				t.Fatal(err)
			}
			rows := c.rows
			if rows == nil {
				rows = map[string]string{}
			}
			got := check(seams, rows, "allow")
			if len(got) != len(c.want) {
				t.Fatalf("got %d problem(s), want %d:\n  %s", len(got), len(c.want), strings.Join(got, "\n  "))
			}
			for _, w := range c.want {
				n := 0
				for _, p := range got {
					if strings.Contains(p, w) {
						n++
					}
				}
				if n != 1 {
					t.Errorf("want exactly one problem containing %q; got:\n  %s", w, strings.Join(got, "\n  "))
				}
			}
		})
	}
}

func TestForTestSeamRuleAllowFile17342(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow")
	body := "# comment\n\npkg/a.FooForTest\tkept for pkg/b tests\n" +
		"pkg/a.BarForTest\n" + // no reason
		"pkg/a.BazForTest\t \n" + // blank reason
		"pkg/a.FooForTest\tagain\n" // duplicate
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, problems, err := readAllow(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows["pkg/a.FooForTest"] != "kept for pkg/b tests" {
		t.Errorf("rows = %v, want only pkg/a.FooForTest with its first reason", rows)
	}
	want := []string{":4: want <seam id>", ":5: want <seam id>", ":6: duplicate row for pkg/a.FooForTest"}
	if len(problems) != len(want) {
		t.Fatalf("got %d problem(s), want %d:\n  %s", len(problems), len(want), strings.Join(problems, "\n  "))
	}
	for i, w := range want {
		if !strings.Contains(problems[i], w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, problems[i], w)
		}
	}
}
