package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// #5103: the daemon must hand programRethMAC a REAL beforeCycle hook, and must
// reach it through the wrapper that owns the hook and the abort rollback.
//
// The ordering tests in reth_worker_join_order_5103_test.go drive programRethMAC
// directly and the abort tests in reth_prepare_abort_recovery_5103_test.go drive
// programRethMACWithWorkerJoin directly, so they bind what happens INSIDE those.
// They do not bind the daemon's call TO them — and passing `nil` as the hook, or
// calling programRethMAC around the wrapper, compiles and keeps every one of
// those tests green while restoring the original defect.
//
// SCOPE, stated rather than implied — and this canary is deliberately SMALLER
// than it was in #5103 r4.
//
// It asserts three call-shape claims about PACKAGE DAEMON — every non-test file,
// derived from the directory, not one named file (#6871 round 15; see
// packageGoFiles for the escape that forced the widening):
//
//  1. exactly one programRethMAC call site, taking 3 args, the third not the
//     literal `nil` (the hook is really passed);
//  2. exactly one programRethMACWithWorkerJoin call site — which lives inside
//     programRethMemberMAC, so the apply loop cannot reach the wrapper any other
//     way without tripping this count; and
//  3. exactly one programRethMemberMAC call site, whose result is assigned with
//     `=` (not `:=`) back into BOTH accumulators — networkdErr and
//     needLinkCycleRecovery — and which is not nested inside a constant-false
//     `if`.
//
// It does NOT try to prove the fold itself is effective. It used to: r4 matched
// the inline `if prepareErr != nil { networkdErr = errors.Join(...) }` statement
// and its exact guarding condition. That was the wrong tool. A hostile reviewer
// escaped it three ways that all kept `go vet ./pkg/daemon` clean — wrapping the
// accepted `if` in `if false { ... }`, preceding the assignment with a
// duplicate-condition early return, and shadowing the target with `:=` — and each
// new escape shape only bought another AST clause. The fold now lives in
// programRethMemberMAC and is bound BEHAVIOURALLY by reth_commit_fold_5103_test.go,
// which fails on all three because it observes the returned error rather than the
// syntax that produces it.
//
// What remains unbound, stated plainly. Claim 3's reachability check rejects a
// CONSTANT-false enclosing `if`; it cannot reject a runtime-false one, an earlier
// `continue`/`return` under a runtime-false condition, or a `goto` over the call.
// Nothing structural can — those need the apply loop itself to be executable in a
// test, which needs a live cluster manager, a wired dataplane, a networkd writer
// and real netlink RETH members. What the checks above do buy is that the ONLY
// route from this file to the wrapper is the single assignment they pin, so a
// silent drop has to be a deliberate control-flow edit rather than a plausible
// refactor.
func TestDaemonPassesRethBeforeCycleHook_5103(t *testing.T) {
	files := packageGoFiles(t)

	fset := token.NewFileSet()
	calls := 0
	wrapperCalls := 0
	memberCalls := 0
	for _, file := range files {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		countRethCallSites(t, fset, file, f, &calls, &wrapperCalls, &memberCalls)
	}
	const where = "package daemon"
	// Guard the guard: a rename or a move would otherwise make this pass by
	// finding nothing to check.
	if calls != 1 {
		t.Fatalf("expected exactly 1 programRethMAC call site in %s, found %d — this canary "+
			"is keyed to that call site and is not checking anything otherwise", where, calls)
	}
	// The apply loop must go through the wrapper, not around it: calling
	// programRethMAC directly from the loop would keep the hook and lose the
	// rollback of an aborted cycle (#5103 F4), with every behavioural test in
	// reth_prepare_abort_recovery_5103_test.go still green because they drive
	// the wrapper. Exactly one call also means the wrapper has exactly one
	// consumer — programRethMemberMAC — so the loop cannot bypass the fold by
	// calling the wrapper itself.
	if wrapperCalls != 1 {
		t.Fatalf("expected exactly 1 programRethMACWithWorkerJoin call site in %s, found %d",
			where, wrapperCalls)
	}
	if memberCalls != 1 {
		t.Fatalf("expected exactly 1 programRethMemberMAC call site in %s, found %d — the "+
			"per-member fold of the commit error and the rebind gate (#5103, bound "+
			"behaviourally by reth_commit_fold_5103_test.go) is reached from nowhere else",
			where, memberCalls)
	}
}

// packageGoFiles lists this package's non-test Go files, DERIVED from the
// directory rather than named (#6871 round 15).
//
// The three counts above are "exactly one call site". Round 14 asked that
// question of one file, so it answered a narrower one — "exactly one in
// daemon_apply_dataplane.go" — and a second caller written in any sibling file
// of the same package was invisible. Measured: a
// reassertRethMemberMACOnRGTransition calling programRethMACWithWorkerJoin,
// appended to daemon_reth.go, kept the whole suite green; the identical function
// appended to the parsed file failed with "found 2".
//
// That is not a hazard the count merely fails to notice. The wrapper's success
// path returns without NotifyLinkCycle — step 2.6b2 owns the release — so a
// caller outside applyDataplaneAndHACore acquires a lease that nothing releases,
// and since round 8 the heartbeat re-arms it forever: the reconcile stays
// suppressed for the life of the process.
//
// PACKAGE SCOPE IS COMPLETE HERE, and that is an argument rather than a
// convenience. All three functions are unexported, so the set of possible
// callers is exactly this package — no wider walk can find one that this misses.
// Compare linkCycleAcquisitionSites, whose subject (PrepareLinkCycle) IS
// exported and therefore needs the module-wide walk it does.
func packageGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		t.Fatal("no non-test Go files found in the package directory; this canary would " +
			"count zero call sites and fail for the wrong reason")
	}
	sort.Strings(files)
	return files
}

// countRethCallSites accumulates the three call-site counts for one file, and
// checks the two claims that are about a call's SHAPE rather than its number.
func countRethCallSites(t *testing.T, fset *token.FileSet, file string, f *ast.File,
	calls, wrapperCalls, memberCalls *int) {
	t.Helper()
	// stack tracks the enclosing nodes so the member call site can be tested for
	// reachability, not merely for existence.
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		defer func() { stack = append(stack, n) }()

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "programRethMACWithWorkerJoin":
				*wrapperCalls++
			case "programRethMemberMAC":
				*memberCalls++
				checkRethMemberCallSite(t, fset, file, call, stack)
			}
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "programRethMAC" {
			return true
		}
		*calls++
		if len(call.Args) != 3 {
			t.Errorf("%s:%d: programRethMAC called with %d args, want 3 — the third is the "+
				"beforeCycle worker-join hook (#5103)",
				file, fset.Position(call.Pos()).Line, len(call.Args))
			return true
		}
		if arg, ok := call.Args[2].(*ast.Ident); ok && arg.Name == "nil" {
			t.Errorf("%s:%d: the daemon passes a nil beforeCycle hook, so the AF_XDP workers "+
				"are never joined before a RETH MAC link cycle — the #5103 defect, restored "+
				"with every producer-side test still green",
				file, fset.Position(call.Pos()).Line)
		}
		return true
	})
}

// checkRethMemberCallSite asserts claim 3: the fold's result is assigned back
// into both accumulators, with `=` rather than `:=`, and is not sitting inside a
// constant-false `if`.
func checkRethMemberCallSite(t *testing.T, fset *token.FileSet, file string,
	call *ast.CallExpr, stack []ast.Node) {
	t.Helper()
	pos := fset.Position(call.Pos()).Line

	var assign *ast.AssignStmt
	for i := len(stack) - 1; i >= 0; i-- {
		if a, ok := stack[i].(*ast.AssignStmt); ok {
			assign = a
			break
		}
	}
	if assign == nil {
		t.Errorf("%s:%d: programRethMemberMAC's result is DISCARDED. It returns the updated "+
			"commit error and rebind gate; throwing them away is the #5103 fail-closed "+
			"regression with the fold itself still intact and its tests still green", file, pos)
		return
	}
	if assign.Tok != token.ASSIGN {
		t.Errorf("%s:%d: programRethMemberMAC's result is bound with %q, not `=`. A short "+
			"declaration creates NEW locals that shadow networkdErr and "+
			"needLinkCycleRecovery, so the commit error and the rebind gate the apply tail "+
			"reads are never updated", file, pos, assign.Tok.String())
		return
	}
	// #7007 added the third accumulator. The property this pins is unchanged —
	// the loop must assign EVERY accumulator straight back into the variables
	// the apply tail reads, so none of them can be silently dropped or shadowed
	// — and rethRollbackKeptLease is exactly such an accumulator: lose it and
	// the apply where every member ABORTS strands its link-cycle lease to the
	// deferred abandon, which is the failure mode #7007 rejects a refcount for.
	want := []string{"networkdErr", "needLinkCycleRecovery", "rethRollbackKeptLease"}
	if len(assign.Lhs) != len(want) {
		t.Errorf("%s:%d: programRethMemberMAC's result is assigned to %d targets, want %d "+
			"(%v)", file, pos, len(assign.Lhs), len(want), want)
		return
	}
	for i, w := range want {
		id, ok := assign.Lhs[i].(*ast.Ident)
		if !ok || id.Name != w {
			t.Errorf("%s:%d: programRethMemberMAC result %d is assigned to something other "+
				"than %s — the accumulator the apply tail actually reads", file, pos, i, w)
		}
	}

	for _, n := range stack {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !isConstFalse(ifs.Cond) {
			continue
		}
		t.Errorf("%s:%d: the programRethMemberMAC call is nested inside a constant-false "+
			"`if` at line %d, so it never runs: RETH virtual MACs are never programmed and "+
			"no aborted cycle can ever fail the commit, while the assignment shape this "+
			"canary matches is still present", file, pos, fset.Position(ifs.Pos()).Line)
	}
}

// isConstFalse reports whether e is statically false: the literal `false`, or a
// conjunction with a statically-false operand. That is the escape shape a
// presence-only canary is defeated by (`if false && cond { ... }`), and it is
// invisible to `go vet`, which does not treat the body as unreachable.
func isConstFalse(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "false"
	case *ast.ParenExpr:
		return isConstFalse(v.X)
	case *ast.BinaryExpr:
		return v.Op == token.LAND && (isConstFalse(v.X) || isConstFalse(v.Y))
	}
	return false
}
