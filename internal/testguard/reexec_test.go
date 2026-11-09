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
//     (the nested-userns child the package guard refuses), or
//   - calls t.Skip/Skipf/SkipNow instead of testguard.NetnsUnavailable (a
//     skip that never fails under XPF_REQUIRE_NETNS).
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

func TestNetnsReexecCensusCatchesBothShapes19066(t *testing.T) {
	src := `package p
import ("os"; "os/exec"; "testing"; "github.com/psaab/xpf/internal/testguard")
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
	unshare, _ := exec.LookPath("unshare")
	cmd := exec.Command(unshare, append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	if _, err := cmd.CombinedOutput(); err != nil { testguard.NetnsUnavailable(t, "netns unavailable") }
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
	want := []string{"TestBad passes", "TestBad calls t.Skipf", "TestBadSlice passes"}
	if len(got) != len(want) {
		t.Fatalf("census found %d violations, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("violation %d = %q, want it to mention %q", i, got[i], w)
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
