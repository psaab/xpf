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
		// Codex F4: -c (--map-current-user) implies --user.
		{[]string{"-cn"}, []string{"-n"}},
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

// #19090: every util-linux unshare option that creates a user namespace,
// including the --map-* options that imply --user and the --opt=value forms.
var userNSFlag19066 = regexp.MustCompile(`^(-[A-Za-z]*[rU][A-Za-z]*|-[A-Za-z]*c[A-Za-z]*|--user(=.*)?|--map-root-user|--map-current-user|--map-auto|--map-(user|group|users|groups)(=.*)?)$`)

// isUserNSFlag19066: a short cluster with c counts only beside an unshare
// namespace letter ("-cn"), so a shell's "-c" is not mistaken for one.
func isUserNSFlag19066(s string) bool {
	if !userNSFlag19066.MatchString(s) {
		return false
	}
	if strings.HasPrefix(s, "--") || strings.ContainsAny(s, "rU") {
		return true
	}
	return strings.ContainsAny(s[1:], "mnuipCT")
}

// netnsReexecViolations19066 reports, for one parsed _test.go file, every
// function that runs `unshare` and re-executes a test binary (it references
// os.Args[0] or calls os.Executable) and either
//   - carries a literal user-namespace flag outside testguard.UnshareFlags
//     (the nested-userns child the package guard refuses);
//   - calls t.Skip/Skipf/SkipNow instead of testguard.NetnsUnavailable (a
//     skip that never fails under XPF_REQUIRE_NETNS), unless the skip sits in
//     an `if` on runtime.GOOS, which is a platform guard, not a netns one;
//   - has no child-success witness: a testguard.RequireChildPass call, or an
//     `if !strings.Contains(out, "<success>") { t.Fatal... }` over the
//     child's captured output, where "<success>" is "--- PASS: " or a
//     "...PASSED..." sentinel, the negated Contains is reached only through
//     `||`, and the body fails this test through its own *testing.T
//     (#19090). Exit status alone reads a skipped child, or a -test.run that
//     matched nothing, as a PASS (#19066 R2 F1);
//   - builds the re-exec with exec.Command/CommandContext instead of
//     testguard.ReexecCommand, so the child has no deadline of its own
//     (#19066 R18 N1).
//
// Reach: the census reads one function at a time (plus package-level values,
// packageLevelUserNSFlags19066). A re-exec split across a helper that receives
// the binary path escapes it, and nothing else backstops that shape when its
// parent uses a raw t.Skip (#19066 Codex). Keep a re-exec, its flags and its
// verdict in one function.
func netnsReexecViolations19066(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		runsUnshare, reexecs := false, false
		// Idents holding the unshare path: `x, err := exec.LookPath("unshare")`
		// under any name (#19066 Codex F3), besides the conventional `unshare`.
		unshareVars := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
				return true
			}
			if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "LookPath" && len(call.Args) == 1 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == `"unshare"` {
						if id, ok := as.Lhs[0].(*ast.Ident); ok {
							unshareVars[id.Name] = true
						}
					}
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.CallExpr:
				if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "exec" &&
						(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
						for _, a := range e.Args {
							if isUnshareArg19066(a, unshareVars) {
								runsUnshare = true
							}
						}
					}
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testguard" && sel.Sel.Name == "ReexecCommand" {
						for _, a := range e.Args {
							if isUnshareArg19066(a, unshareVars) {
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
		// A witness is a check over the child's output that can FAIL the test
		// (#19066 Codex F3/D1): a RequireChildPass call, or an `if` whose
		// condition holds strings/bytes.Contains with a "--- PASS: " or
		// "...PASSED..." needle and whose body fails the test (t.Fatal*,
		// t.Error*, t.FailNow, testguard.NetnsUnavailable). A Contains whose
		// result is logged or discarded checks nothing and does not count.
		//
		// #19090 (Codex R1 on #19066): the shape is narrow on purpose. The
		// Contains must be NEGATED and reached only through `||` (so
		// `err != nil && !Contains(...)`, which a zero-exit no-run child
		// satisfies, is not a witness); its subject must be the child's
		// captured output (CombinedOutput/Output, or string() of it), not a
		// constant; and the body must fail THIS test through its own
		// *testing.T (t.Fatal*, t.Error*, t.FailNow, or
		// testguard.NetnsUnavailable(t, ...)), not any method named Error.
		tName := testingTParam19090(fn)
		outVars := childOutputVars19090(fn)
		witness := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ifs, ok := n.(*ast.IfStmt); ok && guardsChildSuccess19090(ifs.Cond, outVars) && failsThisTest19090(ifs.Body, tName) {
				witness = true
			}
			switch e := n.(type) {
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
					len(e.Args) > 0 && isUnshareArg19066(e.Args[0], unshareVars) || pkg.Name == "exec" && sel.Sel.Name == "CommandContext" &&
					len(e.Args) > 1 && isUnshareArg19066(e.Args[1], unshareVars) {
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
		for _, v := range unshareOptionViolations19066(fn, unshareVars) {
			out = append(out, fmt.Sprintf("%s: %s passes the user-namespace option %s to unshare; use testguard.UnshareFlags(...) (#19066)",
				fset.Position(v.Pos()), fn.Name.Name, v.Value))
		}
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
					if s := strings.Trim(e.Value, "`\""); isUserNSFlag19066(s) {
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
// conventional `unshare` variable, any ident in vars (assigned from
// exec.LookPath("unshare")), or the literal.
func isUnshareArg19066(a ast.Expr, vars map[string]bool) bool {
	if id, ok := a.(*ast.Ident); ok && (id.Name == "unshare" || vars[id.Name]) {
		return true
	}
	lit, ok := a.(*ast.BasicLit)
	return ok && lit.Value == `"unshare"`
}

// testingTParam19090 returns the name of fn's *testing.T parameter, or "".
func testingTParam19090(fn *ast.FuncDecl) string {
	for _, f := range fn.Type.Params.List {
		star, ok := f.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "T" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testing" && len(f.Names) == 1 {
			return f.Names[0].Name
		}
	}
	return ""
}

// childOutputVars19090 returns the idents that hold a child's captured
// output: assigned from x.CombinedOutput() or x.Output(), or from string(v)
// of one of those.
func childOutputVars19090(fn *ast.FuncDecl) map[string]bool {
	vars := map[string]bool{}
	for pass := 0; pass < 3; pass++ {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			fromOutput := false
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "CombinedOutput" || sel.Sel.Name == "Output") && len(call.Args) == 0 {
				fromOutput = true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "string" && len(call.Args) == 1 && refersTo19090(call.Args[0], vars) {
				fromOutput = true
			}
			if fromOutput {
				if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					vars[id.Name] = true
				}
			}
			return true
		})
	}
	return vars
}

// refersTo19090 reports whether e mentions an ident in vars.
func refersTo19090(e ast.Expr, vars map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && vars[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

// guardsChildSuccess19090 reports whether cond is `!Contains(out, success)`,
// or a `||` chain one of whose operands is: the only shapes in which a child
// output WITHOUT the success marker always makes the condition true.
func guardsChildSuccess19090(cond ast.Expr, outVars map[string]bool) bool {
	switch x := cond.(type) {
	case *ast.ParenExpr:
		return guardsChildSuccess19090(x.X, outVars)
	case *ast.BinaryExpr:
		return x.Op == token.LOR && (guardsChildSuccess19090(x.X, outVars) || guardsChildSuccess19090(x.Y, outVars))
	case *ast.UnaryExpr:
		if x.Op != token.NOT {
			return false
		}
		inner := x.X
		for {
			p, ok := inner.(*ast.ParenExpr)
			if !ok {
				break
			}
			inner = p.X
		}
		call, ok := inner.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Contains" {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && (pkg.Name == "strings" || pkg.Name == "bytes") &&
			holdsSuccessLiteral19066(call.Args[1]) && refersTo19090(call.Args[0], outVars)
	}
	return false
}

// failsThisTest19090 reports whether a block fails the test whose *testing.T
// is tName: tName.Fatal/Fatalf/FailNow/Error/Errorf, or
// testguard.NetnsUnavailable(tName, ...).
func failsThisTest19090(b *ast.BlockStmt, tName string) bool {
	if tName == "" {
		return false
	}
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return !found
		}
		switch sel.Sel.Name {
		case "Fatal", "Fatalf", "FailNow", "Error", "Errorf":
			if recv.Name == tName {
				found = true
			}
		case "NetnsUnavailable":
			if recv.Name == "testguard" && len(call.Args) > 0 {
				if a, ok := call.Args[0].(*ast.Ident); ok && a.Name == tName {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// unshareOptionViolations19066 finds user-namespace options by POSITION: in
// each unshare call it walks the arguments after the unshare path, through
// append(...) and local slice variables, up to the program (the first
// non-option argument), and reports any option literal that requests a user
// namespace, including a standalone "-c" (#19066 Codex D2). Arguments of
// testguard.UnshareFlags are allowed; a shell's "-c" after the program is not
// an unshare option.
func unshareOptionViolations19066(fn *ast.FuncDecl, unshareVars map[string]bool) []*ast.BasicLit {
	local := map[string]ast.Expr{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				local[id.Name] = as.Rhs[0]
			}
		}
		return true
	})
	var out []*ast.BasicLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !((pkg.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext")) ||
			(pkg.Name == "testguard" && sel.Sel.Name == "ReexecCommand")) {
			return true
		}
		at := -1
		for i, a := range call.Args {
			if isUnshareArg19066(a, unshareVars) {
				at = i
				break
			}
		}
		if at < 0 {
			return true
		}
		program := false
		operand := false
		var walk func(e ast.Expr, depth int)
		walk = func(e ast.Expr, depth int) {
			if program || depth > 4 {
				return
			}
			// #19090 (Codex R2 on #19066): an option that takes a separate
			// operand ("--propagation", "private") consumes the next word
			// whatever it is; it is not the program, so the walk goes on.
			if operand {
				if _, ok := e.(*ast.CallExpr); !ok || !isAppend19090(e) {
					operand = false
					return
				}
			}
			switch x := e.(type) {
			case *ast.BasicLit:
				v := strings.Trim(x.Value, "`\"")
				if x.Kind != token.STRING || !strings.HasPrefix(v, "-") {
					program = true
					return
				}
				if unshareOptionTakesOperand19090(v) {
					operand = true
				}
				// Spellings that are a user-namespace flag anywhere are
				// already reported by the literal scan; position adds the
				// standalone "-c", which only its place makes an unshare
				// option.
				if v == "-c" {
					out = append(out, x)
				}
			case *ast.CallExpr:
				if s2, ok := x.Fun.(*ast.SelectorExpr); ok && s2.Sel.Name == "UnshareFlags" {
					return // allowed: rewritten for uid 0
				}
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "append" {
					for _, a := range x.Args {
						walk(a, depth+1)
					}
					return
				}
				program = true
			case *ast.CompositeLit:
				for _, a := range x.Elts {
					walk(a, depth+1)
				}
			case *ast.Ident:
				if rhs, ok := local[x.Name]; ok {
					walk(rhs, depth+1)
					return
				}
				program = true
			default:
				program = true
			}
		}
		for _, a := range call.Args[at+1:] {
			walk(a, 0)
		}
		return true
	})
	return out
}

// holdsSuccessLiteral19066 reports whether e contains a string literal naming
// a child's success: "--- PASS: " or a "...PASSED..." sentinel.
func holdsSuccessLiteral19066(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
			(strings.Contains(lit.Value, "--- PASS: ") || strings.Contains(lit.Value, "PASSED")) {
			found = true
		}
		return !found
	})
	return found
}

// unshareOptionTakesOperand19090 reports whether an unshare(1) option takes
// its value as the NEXT argument (util-linux unshare; the "--opt=value" form
// carries its own value and does not).
func unshareOptionTakesOperand19090(v string) bool {
	switch v {
	case "--propagation", "--setgroups", "-S", "--setuid", "-G", "--setgid",
		"-R", "--root", "-w", "--wd", "--monotonic", "--boottime",
		"--map-user", "--map-group", "--map-users", "--map-groups":
		return true
	}
	return false
}

// isAppend19090 reports whether e is a call to the append builtin.
func isAppend19090(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "append"
}

// packageLevelUserNSFlags19066 reports package-level var/const values in a
// guarded package's test file that hold a literal user-namespace flag: the
// census reads function bodies, so flags parked at package level would escape
// it (#19066 Codex F3).
func packageLevelUserNSFlags19066(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
			continue
		}
		ast.Inspect(gd, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && isUserNSFlag19066(strings.Trim(lit.Value, "`\"")) {
				out = append(out, fmt.Sprintf("%s: a package-level value holds the user-namespace flag %s; build re-exec flags inside the function with testguard.UnshareFlags(...) so the census can see them (#19066)",
					fset.Position(lit.Pos()), lit.Value))
			}
			// A slice made only of options is an option list; a standalone
			// "-c" in it is --map-current-user (#19066 Codex D2). A shell's
			// []string{"-c", "true"} has a non-option and is left alone.
			if cl, ok := n.(*ast.CompositeLit); ok && len(cl.Elts) > 0 {
				// An option's separate operand ("--propagation", "private")
				// is part of an option list too (#19090, Codex R2 on #19066).
				allOpts := true
				operand := false
				for _, el := range cl.Elts {
					lit, ok := el.(*ast.BasicLit)
					if operand {
						operand = false
						if ok && lit.Kind == token.STRING {
							continue
						}
					}
					if !ok || lit.Kind != token.STRING || !strings.HasPrefix(strings.Trim(lit.Value, "`\""), "-") {
						allOpts = false
						continue
					}
					operand = unshareOptionTakesOperand19090(strings.Trim(lit.Value, "`\""))
				}
				if allOpts {
					for _, el := range cl.Elts {
						if lit := el.(*ast.BasicLit); strings.Trim(lit.Value, "`\"") == "-c" {
							out = append(out, fmt.Sprintf("%s: a package-level option list holds \"-c\" (--map-current-user, a user namespace); build re-exec flags with testguard.UnshareFlags(...) (#19066)",
								fset.Position(lit.Pos())))
						}
					}
				}
			}
			return true
		})
	}
	return out
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
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Executable" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
					found = true
				}
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
}
func TestLogOnlyWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	if _, err := cmd.CombinedOutput(); err != nil { t.Fatal(err) }
	t.Log("child PASSED")
}
func TestRenamedUnshare(t *testing.T) {
	u, _ := exec.LookPath("unshare")
	out, err := exec.Command(u, "-cn", os.Args[0], "-test.v").CombinedOutput()
	testguard.RequireChildPass(t, "TestRenamedUnshare", out, err)
}
func TestWrapperSplitIsAKnownEscape(t *testing.T) {
	out, err := childCommand19066(os.Args[0]).CombinedOutput()
	if err != nil { t.Skipf("netns unavailable: %s", out) }
}
func childCommand19066(binary string) *exec.Cmd { return exec.Command("unshare", "-rn", binary) }
func TestDiscardedContains(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	out, _ := cmd.CombinedOutput()
	_ = strings.Contains(string(out), "child PASSED")
}
func TestLoggedContains(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "NETNS-CHILD-PASSED") { t.Log("passed") }
}
func TestStandaloneC(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", "-c", "-n", os.Args[0], "-test.v")
	out, err := cmd.CombinedOutput()
	testguard.RequireChildPass(t, "TestStandaloneC", out, err)
}
func TestShellCAfterProgramIsNotAFlag(t *testing.T) {
	_ = exec.Command("unshare", "-n", "bash", "-c", "ip link")
	_ = exec.Command("unshare", "--propagation", "private", "-n", "bash", "-c", "ip link")
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0], "-test.v")...)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-X") { t.Fatalf("child failed: %v", err) }
}
func TestConjunctionWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "child PASSED") { t.Fatal("missing child success") }
}
func TestForeignErrorWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	out, err := cmd.CombinedOutput()
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(out), "child PASSED") { logger.Error("missing") }
}
func TestConstantWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0])...)
	if _, err := cmd.CombinedOutput(); err != nil { t.Fatal(err) }
	if !strings.Contains("child PASSED", "PASSED") { t.Fatal("constant") }
}
func TestDerivedOutputWitness(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", append(testguard.UnshareFlags("-rn"), os.Args[0], "-test.v")...)
	output, err := cmd.CombinedOutput()
	text := string(output)
	if err != nil { t.Fatalf("child failed: %v", err) }
	if !strings.Contains(text, "--- PASS: TestDerivedOutputWitness") { t.Fatalf("no pass line") }
}
func TestMapUserImpliesUserNS(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", "--map-user", "0", "-n", os.Args[0], "-test.v")
	out, err := cmd.CombinedOutput()
	testguard.RequireChildPass(t, "TestMapUserImpliesUserNS", out, err)
}
func TestOperandBeforeC(t *testing.T) {
	cmd := testguard.ReexecCommand(t, "unshare", "--propagation", "private", "-c", "-n", os.Args[0], "-test.v")
	out, err := cmd.CombinedOutput()
	testguard.RequireChildPass(t, "TestOperandBeforeC", out, err)
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
		// Codex F3/F4: a log line is not a witness; a renamed unshare path
		// and a -c cluster are still seen.
		"TestLogOnlyWitness judges its re-executed child without a child-success witness",
		"TestRenamedUnshare re-executes a test binary with exec.Command",
		"TestRenamedUnshare passes the user-namespace flag \"-cn\"",
		// Codex D1: a Contains that fails nothing is not a witness.
		"TestDiscardedContains judges its re-executed child without a child-success witness",
		"TestLoggedContains judges its re-executed child without a child-success witness",
		// Codex D2: a standalone "-c" in option position; the shell's "-c"
		// after the program (TestShellCAfterProgramIsNotAFlag) is not one.
		"TestStandaloneC passes the user-namespace option \"-c\"",
		// #19090 (Codex R1 on #19066): a Contains reached through &&, a
		// failure that is not this test's, and a constant subject are not
		// witnesses. TestDerivedOutputWitness (string() of the output, then
		// t.Fatalf) is, and must produce no violation.
		"TestConjunctionWitness judges its re-executed child without a child-success witness",
		"TestForeignErrorWitness judges its re-executed child without a child-success witness",
		"TestConstantWitness judges its re-executed child without a child-success witness",
		// #19090 (Codex R2 on #19066): an option operand ("private") is not
		// the program, so the "-c" after it is still an unshare option. The
		// same shape before "bash -c" (TestShellCAfterProgramIsNotAFlag) is
		// not one.
		"TestOperandBeforeC passes the user-namespace option \"-c\"",
		// #19090: --map-user implies --user.
		"TestMapUserImpliesUserNS passes the user-namespace flag \"--map-user\"",
		// TestWrapperSplitIsAKnownEscape: the helper has unshare but no
		// os.Args, the parent the reverse, so neither is in scope. This is
		// the documented limit (docs/testing.md); the row pins it so a
		// census that starts catching it updates the docs too.
	}
	// Errorf, not Fatalf: the per-row checks below must still report WHICH
	// row moved when the count does (#19090).
	if len(got) != len(want) {
		t.Errorf("census found %d violations, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	pkgSrc := `package p
var flags19066 = []string{"-rn"}
var optsC19066 = []string{"-c", "-n"}
var shellArgs19066 = []string{"-c", "true"}
var optsProp19090 = []string{"--propagation", "private", "-c", "-n"}
var shellProp19090 = []string{"--propagation", "private", "bash", "-c", "true"}`
	pf, err := parser.ParseFile(fset, "pkgflags_test.go", pkgSrc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pv := packageLevelUserNSFlags19066(fset, pf); len(pv) != 3 || !strings.Contains(pv[0], `"-rn"`) || !strings.Contains(pv[1], `"-c"`) ||
		!strings.Contains(pv[2], `"-c"`) || !strings.Contains(pv[2], "pkgflags_test.go:5:") {
		t.Errorf("package-level flag census = %q, want the \"-rn\" value, the option-list \"-c\", and the \"-c\" after an option's operand on line 5 (#19090); a shell's \"-c\" (lines 4 and 6) is not one", pv)
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
		violations = append(violations, packageLevelUserNSFlags19066(fset, f)...)
	}
	if scanned == 0 {
		t.Fatal("census scanned no guarded test files")
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
}
