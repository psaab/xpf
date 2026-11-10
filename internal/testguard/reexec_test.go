package testguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestStripUserNamespaceFlags19066(t *testing.T) {
	for _, tc := range []struct {
		in, want []string
	}{
		{[]string{"-rn"}, []string{"-n"}},
		{[]string{"-Urn"}, []string{"-n"}},
		{[]string{"-Urnm", "--propagation", "private", "--"}, []string{"-nm", "--propagation", "private", "--"}},
		{[]string{"-rm"}, []string{"-m"}},
		{[]string{"-f", "-rn"}, []string{"-f", "-n"}},
		{[]string{"-r", "-n"}, []string{"-n"}},
		{[]string{"--user", "--map-root-user", "--net"}, []string{"--net"}},
		{[]string{"--map-users=0:1000:1", "-n"}, []string{"-n"}},
		{[]string{"-n"}, []string{"-n"}},
		// R18 N2: a cluster carrying an attached argument is left alone.
		{[]string{"-w/srv/run", "-rn"}, []string{"-w/srv/run", "-n"}},
		{[]string{"-n/run/netns/x"}, []string{"-n/run/netns/x"}},
	} {
		if got := stripUserNamespaceFlags(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("stripUserNamespaceFlags(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnshareFlagsFollowsEUID19066(t *testing.T) {
	got := UnshareFlags("-rn")
	want := []string{"-rn"}
	if os.Geteuid() == 0 {
		want = []string{"-n"}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnshareFlags(-rn) at euid %d = %q, want %q", os.Geteuid(), got, want)
	}
}

// recTB records what NetnsUnavailable asked of the test.
type recTB struct {
	testing.TB
	fatal, skip string
}

func (r *recTB) Helper()                           {}
func (r *recTB) Fatalf(format string, args ...any) { r.fatal = fmt.Sprintf(format, args...) }
func (r *recTB) Skipf(format string, args ...any)  { r.skip = fmt.Sprintf(format, args...) }

func TestNetnsUnavailableFailsUnderRequire19066(t *testing.T) {
	t.Setenv(RequireNetnsEnv, "1")
	r := &recTB{}
	NetnsUnavailable(r, "child never started: %s", "x")
	if r.fatal == "" || r.skip != "" {
		t.Fatalf("under %s: fatal=%q skip=%q, want a FAIL", RequireNetnsEnv, r.fatal, r.skip)
	}
	if !strings.Contains(r.fatal, "child never started: x") {
		t.Errorf("failure lost the reason: %q", r.fatal)
	}
	t.Setenv(RequireNetnsEnv, "")
	r = &recTB{}
	NetnsUnavailable(r, "child never started")
	if r.skip == "" || r.fatal != "" {
		t.Fatalf("without %s: fatal=%q skip=%q, want a SKIP", RequireNetnsEnv, r.fatal, r.skip)
	}
}

// ---------------------------------------------------------------------------
// #19066 census: a re-exec netns cell in a guarded package must neither nest
// a user namespace nor skip silently.
// ---------------------------------------------------------------------------

// guardedTestMain19066 marks a guarded package: a TestMain whose first action
// is testguard.ExitIfUnsafe. A plain substring search for the call matched
// THIS file's own source (the census names the call) and wrongly marked
// internal/testguard, whose canaries run unshare on purpose, as guarded.
var guardedTestMain19066 = regexp.MustCompile(`func TestMain\(m \*testing\.M\)\s*\{\s*testguard\.ExitIfUnsafe\(\)`)

var userNSFlag19066 = regexp.MustCompile(`^(-[A-Za-z]*[rU][A-Za-z]*|--user|--map-root-user|--map-current-user)$`)

// netnsReexecViolations19066 reports, for one parsed _test.go file, every
// function that runs `unshare` and re-executes a test binary (it references
// os.Args[0] or calls os.Executable) and either
//   - carries a literal user-namespace flag outside testguard.UnshareFlags
//     (the nested-userns child the package guard refuses);
//   - calls t.Skip/Skipf/SkipNow instead of testguard.NetnsUnavailable (a
//     skip that never fails under XPF_REQUIRE_NETNS), unless the skip sits in
//     an `if` on runtime.GOOS, which is a platform guard, not a netns one;
//   - has no child-success witness: a testguard.RequireChildPass call, or a
//     string literal naming the child's own success ("--- PASS: " or a
//     "...PASSED..." sentinel). Exit status alone reads a skipped child, or a
//     -test.run that matched nothing, as a PASS (#19066 R2 F1);
//   - builds the re-exec with exec.Command/CommandContext instead of
//     testguard.ReexecCommand, so the child has no deadline of its own
//     (#19066 R18 N1).
//
// Reach (#19066 R2 NIT): the census reads one function's literals. Flags held
// in a package-level var, or a re-exec split across a helper that receives the
// binary path, escape it. The backstop for those shapes is forcing mode:
// testguard-run.sh exports XPF_REQUIRE_NETNS, so a nested user namespace the
// guard refuses makes the cell itself FAIL rather than skip.
func netnsReexecViolations19066(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		runsUnshare, reexecs := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "exec" &&
						(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
						for _, a := range e.Args {
							if id, ok := a.(*ast.Ident); ok && id.Name == "unshare" {
								runsUnshare = true
							}
							if lit, ok := a.(*ast.BasicLit); ok && lit.Value == `"unshare"` {
								runsUnshare = true
							}
						}
					}
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testguard" && sel.Sel.Name == "ReexecCommand" {
						for _, a := range e.Args {
							if isUnshareArg19066(a) {
								runsUnshare = true
							}
						}
					}
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && sel.Sel.Name == "Executable" {
						reexecs = true
					}
				}
			case *ast.IndexExpr:
				if sel, ok := e.X.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && sel.Sel.Name == "Args" {
						reexecs = true
					}
				}
			}
			return true
		})
		if !runsUnshare || !reexecs {
			continue
		}
		// A skip inside `if <cond on runtime.GOOS> { ... }` is a platform
		// guard, exempt from the netns-skip rule (#19066 R2 NIT 3, R18 N3).
		platformGuarded := map[token.Pos]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || !mentionsGOOS19066(ifs.Cond) {
				return true
			}
			ast.Inspect(ifs.Body, func(m ast.Node) bool {
				if c, ok := m.(*ast.CallExpr); ok {
					platformGuarded[c.Pos()] = true
				}
				return true
			})
			return true
		})
		// Idents assigned from an expression that holds os.Args[0]: the
		// `args := append(..., os.Args[0], ...)` then exec.Command(unshare,
		// args...) shape.
		argVars := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range as.Rhs {
				if i < len(as.Lhs) && holdsOSArgs0_19066(rhs, nil) {
					if id, ok := as.Lhs[i].(*ast.Ident); ok {
						argVars[id.Name] = true
					}
				}
			}
			return true
		})
		witness := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BasicLit:
				if e.Kind == token.STRING && (strings.Contains(e.Value, "--- PASS: ") || strings.Contains(e.Value, "PASSED")) {
					witness = true
				}
			case *ast.CallExpr:
				sel, ok := e.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if pkg.Name == "testguard" && sel.Sel.Name == "RequireChildPass" {
					witness = true
				}
				if pkg.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") &&
					len(e.Args) > 0 && isUnshareArg19066(e.Args[0]) || pkg.Name == "exec" && sel.Sel.Name == "CommandContext" &&
					len(e.Args) > 1 && isUnshareArg19066(e.Args[1]) {
					reexecCall := false
					for _, a := range e.Args {
						if holdsOSArgs0_19066(a, argVars) {
							reexecCall = true
						}
					}
					if reexecCall {
						out = append(out, fmt.Sprintf("%s: %s re-executes a test binary with exec.%s; use testguard.ReexecCommand so the child has a deadline of its own (#19066)",
							fset.Position(e.Pos()), fn.Name.Name, sel.Sel.Name))
					}
				}
			}
			return true
		})
		if !witness {
			out = append(out, fmt.Sprintf("%s: %s judges its re-executed child without a child-success witness; call testguard.RequireChildPass (or require the child's \"--- PASS: <name>\" line or a PASSED sentinel), because exit status alone reads a skipped child as a PASS (#19066)",
				fset.Position(fn.Pos()), fn.Name.Name))
		}
		// Literals that are arguments of testguard.UnshareFlags are fine.
		allowed := map[*ast.BasicLit]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "UnshareFlags" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testguard" {
					for _, a := range call.Args {
						if lit, ok := a.(*ast.BasicLit); ok {
							allowed[lit] = true
						}
					}
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BasicLit:
				if e.Kind == token.STRING && !allowed[e] {
					if s := strings.Trim(e.Value, "`\""); userNSFlag19066.MatchString(s) {
						out = append(out, fmt.Sprintf("%s: %s passes the user-namespace flag %s to a re-exec of a guarded test binary; use testguard.UnshareFlags(...) so a uid-0 caller does not nest a user namespace the package guard refuses (#19066)",
							fset.Position(e.Pos()), fn.Name.Name, e.Value))
					}
				}
			case *ast.CallExpr:
				sel, ok := e.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Skip" && sel.Sel.Name != "Skipf" && sel.Sel.Name != "SkipNow") {
					return true
				}
				if platformGuarded[e.Pos()] {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok {
					out = append(out, fmt.Sprintf("%s: %s calls %s.%s in a netns re-exec cell; use testguard.NetnsUnavailable so the cell FAILS under %s instead of skipping silently (#19066)",
						fset.Position(e.Pos()), fn.Name.Name, id.Name, sel.Sel.Name, RequireNetnsEnv))
				}
			}
			return true
		})
	}
	return out
}

// isUnshareArg19066 reports whether a call argument names unshare: the
// conventional `unshare` variable from exec.LookPath, or the literal.
func isUnshareArg19066(a ast.Expr) bool {
	if id, ok := a.(*ast.Ident); ok && id.Name == "unshare" {
		return true
	}
	lit, ok := a.(*ast.BasicLit)
	return ok && lit.Value == `"unshare"`
}

// holdsOSArgs0_19066 reports whether e contains os.Args[0] (or an ident in
// vars, which was assigned from one).
func holdsOSArgs0_19066(e ast.Expr, vars map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IndexExpr:
			if sel, ok := x.X.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" && sel.Sel.Name == "Args" {
					found = true
				}
			}
		case *ast.Ident:
			if vars[x.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// mentionsGOOS19066 reports whether an if condition reads runtime.GOOS.
func mentionsGOOS19066(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "GOOS" {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "runtime" {
				found = true
			}
		}
		return !found
	})
	return found
}

func TestNetnsReexecCensusCatchesBothShapes19066(t *testing.T) {
	src := `package p
import ("os"; "os/exec"; "runtime"; "testing"; "github.com/psaab/xpf/internal/testguard")
func TestBad(t *testing.T) {
	unshare, _ := exec.LookPath("unshare")
	out, err := exec.Command(unshare, "-rn", os.Args[0]).CombinedOutput()
	if err != nil { t.Skipf("netns unavailable: %s", out) }
}
func TestBadSlice(t *testing.T) {
	args := []string{"-Urnm", os.Args[0]}
	_ = exec.Command("unshare", args...)
}
func TestGood(t *testing.T) {
	if runtime.GOOS != "linux" { t.Skip("requires Linux") }
	unshare, _ := exec.LookPath("unshare")
	cmd := testguard.ReexecCommand(t, unshare, append(testguard.UnshareFlags("-rn"), os.Args[0], "-test.run=^TestGood$", "-test.v")...)
	out, err := cmd.CombinedOutput()
	testguard.RequireChildPass(t, "TestGood", out, err)
}
func TestGoodSentinel(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-1") { testguard.NetnsUnavailable(t, "no") }
}
func TestNoWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	if _, err := cmd.CombinedOutput(); err != nil { t.Fatal(err) }
}
func TestPlainCommand(t *testing.T) {
	args := append(testguard.UnshareFlags("-rn"), os.Args[0], "-test.v")
	out, err := exec.Command("unshare", args...).CombinedOutput()
	testguard.RequireChildPass(t, "TestPlainCommand", out, err)
}
func TestScriptChildIsOutOfScope(t *testing.T) {
	_ = exec.Command("unshare", "-rn", "bash", "-c", "ip link")
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture_test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := netnsReexecViolations19066(fset, f)
	want := []string{
		"TestBad re-executes a test binary with exec.Command",
		"TestBad judges its re-executed child without a child-success witness",
		"TestBad passes the user-namespace flag",
		"TestBad calls t.Skipf",
		"TestBadSlice re-executes a test binary with exec.Command",
		"TestBadSlice judges its re-executed child without a child-success witness",
		"TestBadSlice passes the user-namespace flag",
		"TestNoWitness judges its re-executed child without a child-success witness",
		"TestPlainCommand re-executes a test binary with exec.Command",
	}
	if len(got) != len(want) {
		t.Fatalf("census found %d violations, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for _, w := range want {
		n := 0
		for _, g := range got {
			if strings.Contains(g, w) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("want exactly one violation mentioning %q, got %d in:\n%s", w, n, strings.Join(got, "\n"))
		}
	}
}

// TestNetnsReexecCensus19066 is the census over the tree: every guarded
// package (a TestMain calling testguard.ExitIfUnsafe) must satisfy it.
func TestNetnsReexecCensus19066(t *testing.T) {
	root := filepath.Join("..", "..")
	guarded := map[string]bool{}
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || strings.HasPrefix(name, "xdp-tools")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		files = append(files, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if guardedTestMain19066.Match(b) {
			guarded[filepath.Dir(p)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(guarded) < 5 {
		t.Fatalf("census found only %d guarded packages (%v); the walk or the guard marker rotted", len(guarded), guarded)
	}
	var violations []string
	scanned := 0
	for _, p := range files {
		if !guarded[filepath.Dir(p)] {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		scanned++
		violations = append(violations, netnsReexecViolations19066(fset, f)...)
	}
	if scanned == 0 {
		t.Fatal("census scanned no guarded test files")
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
}
