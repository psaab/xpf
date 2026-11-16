package fortestcensus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real module: every *ForTest* hook is called, or baselined with its
// defining file and a reason.
func TestForTestHooksAreLiveInThisModule17342(t *testing.T) {
	root := filepath.Join("..", "..")
	allow, malformed, err := readAllow(filepath.Join(root, "scripts", "go-fortest-liveness.allow"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := runCensus(root, allow)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d *ForTest* hooks, %d with no caller, %d baseline row(s)", len(res.hooks), len(res.dead), len(allow))
	// Anti-vacuity: the tree has ~160 hooks; a walk that found a handful
	// missed the tree, and would vouch for everything it did not see.
	if len(res.hooks) < 100 {
		t.Errorf("only %d hooks found under %s; the walk did not see the tree", len(res.hooks), root)
	}
	for _, p := range append(malformed, res.problems...) {
		t.Error(p)
	}
}

// fixture writes a module example.com/fx with the given files.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module example.com/fx\n\ngo 1.24\n"
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

const liveHook = "package a\n\n// FooForTest is called by a_test.go.\nfunc FooForTest() int { return 1 }\n"
const liveCaller = "package a\n\nimport \"testing\"\n\nfunc TestFoo(t *testing.T) { _ = FooForTest() }\n"
const deadHook = "package a\n\n// BarForTest replaces the clock.\nfunc BarForTest() {}\n"

// expectProblems runs the census and checks the problem list: each want is a
// substring of exactly one problem, and there are no others.
func expectProblems(t *testing.T, root string, allow []allowRow, want ...string) {
	t.Helper()
	res, err := runCensus(root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.problems) != len(want) {
		t.Fatalf("got %d problem(s), want %d:\n  %s", len(res.problems), len(want), strings.Join(res.problems, "\n  "))
	}
	for _, w := range want {
		n := 0
		for _, p := range res.problems {
			if strings.Contains(p, w) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("want exactly one problem containing %q; got:\n  %s", w, strings.Join(res.problems, "\n  "))
		}
	}
}

func TestForTestCensusCells17342(t *testing.T) {
	cells := []struct {
		name  string
		files map[string]string
		allow []allowRow
		want  []string
	}{
		{name: "live: a hook called from its package's test", files: map[string]string{"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller}},
		{name: "live: a hook called package-qualified from another package", files: map[string]string{
			"pkg/a/a.go":      liveHook,
			"pkg/b/b_test.go": "package b\n\nimport (\n\t\"testing\"\n\n\t\"example.com/fx/pkg/a\"\n)\n\nfunc TestB(t *testing.T) { _ = a.FooForTest() }\n",
		}},
		{name: "line comment only is not a caller", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller, "pkg/a/b.go": deadHook,
			"pkg/a/c.go": "package a\n\n// Tests call BarForTest to freeze time.\nvar _ = 0\n",
		}, want: []string{"pkg/a.BarForTest has no caller"}},
		{name: "block comment only is not a caller", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller, "pkg/a/b.go": deadHook,
			"pkg/a/c.go": "package a\n\n/* BarForTest replaces the clock. */\nvar _ = 0\n",
		}, want: []string{"pkg/a.BarForTest has no caller"}},
		{name: "a string literal is not a caller", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller, "pkg/a/b.go": deadHook,
			"pkg/a/c.go": "package a\n\nvar diag = \"call BarForTest first\"\n",
		}, want: []string{"pkg/a.BarForTest has no caller"}},
		{name: "an uncalled method hook", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller,
			"pkg/a/m.go": "package a\n\ntype T struct{ v int }\n\nfunc (x *T) SetVForTesting(v int) { x.v = v }\n",
		}, want: []string{"pkg/a.(T).SetVForTesting has no caller"}},
		{name: "same-named hooks in two packages are counted separately", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller,
			"pkg/one/one.go":      "package one\n\ntype Monitor struct{}\n\nfunc (m *Monitor) SetTickForTest() {}\n",
			"pkg/two/two.go":      "package two\n\ntype Monitor struct{}\n\nfunc (m *Monitor) SetTickForTest() {}\n",
			"pkg/one/one_test.go": "package one_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/fx/pkg/one\"\n)\n\nfunc TestOne(t *testing.T) { m := &one.Monitor{}; m.SetTickForTest() }\n",
		}, want: []string{"pkg/two.(Monitor).SetTickForTest has no caller"}},
		{name: "a reference no scope can attribute fails, it does not pick one", files: map[string]string{
			"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller,
			"pkg/one/one.go": "package one\n\ntype Monitor struct{}\n\nfunc (m *Monitor) SetTickForTest() {}\n",
			"pkg/two/two.go": "package two\n\ntype Monitor struct{}\n\nfunc (m *Monitor) SetTickForTest() {}\n",
			"pkg/c/c_test.go": "package c\n\nimport (\n\t\"testing\"\n\n\t\"example.com/fx/pkg/one\"\n\t\"example.com/fx/pkg/two\"\n)\n\n" +
				"type ticker interface{ SetTickForTest() }\n\nfunc TestC(t *testing.T) {\n\tfor _, m := range []ticker{&one.Monitor{}, &two.Monitor{}} {\n\t\tm.SetTickForTest()\n\t}\n}\n",
		}, want: []string{"is ambiguous between pkg/one.(Monitor).SetTickForTest, pkg/two.(Monitor).SetTickForTest", "pkg/one.(Monitor).SetTickForTest has no caller", "pkg/two.(Monitor).SetTickForTest has no caller"}},
		{name: "a baselined dead hook passes", files: map[string]string{"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller, "pkg/a/b.go": deadHook},
			allow: []allowRow{{id: "pkg/a.BarForTest", file: "pkg/a/b.go", reason: "kept for a pending test"}}},
		{name: "a baseline row whose hook moved fails", files: map[string]string{"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller, "pkg/a/b.go": deadHook},
			allow: []allowRow{{id: "pkg/a.BarForTest", file: "pkg/a/old.go", reason: "kept for a pending test"}},
			want:  []string{"names pkg/a/old.go, but the hook is defined in pkg/a/b.go"}},
		{name: "a baseline row whose hook gained a caller fails", files: map[string]string{"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller},
			allow: []allowRow{{id: "pkg/a.FooForTest", file: "pkg/a/a.go", reason: "x"}},
			want:  []string{"is stale: the hook now has a caller"}},
		{name: "a baseline row whose hook is gone fails", files: map[string]string{"pkg/a/a.go": liveHook, "pkg/a/a_test.go": liveCaller},
			allow: []allowRow{{id: "pkg/a.GoneForTest", file: "pkg/a/gone.go", reason: "x"}},
			want:  []string{"is stale: the hook is gone"}},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			expectProblems(t, fixture(t, c.files), c.allow, c.want...)
		})
	}
}

func TestForTestCensusRefusesAnEmptyTreeAndMalformedRows17342(t *testing.T) {
	root := fixture(t, map[string]string{"pkg/a/a.go": "package a\n\nfunc F() {}\n"})
	if _, err := runCensus(root, nil); err == nil || !strings.Contains(err.Error(), "nothing to vouch for") {
		t.Errorf("a tree with no hooks: err=%v, want a refusal (it vouches for nothing)", err)
	}
	p := filepath.Join(t.TempDir(), "allow")
	if err := os.WriteFile(p, []byte("# comment\nJustAName\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, problems, err := readAllow(p)
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "want <hook id>") {
		t.Errorf("a malformed baseline row: problems=%v err=%v, want one refusal", problems, err)
	}
}
