package dataplane

import (
	"errors"
	"go/ast"
	"testing"

	"github.com/cilium/ebpf/link"
)

// returnsNilPair reports whether stmt's body contains a `return nil, <expr>`.
func returnsNilPair(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if ok && len(ret.Results) == 2 && identName(ret.Results[0]) == "nil" {
			found = true
		}
		return !found
	})
	return found
}

// callName names a call whether it is a bare function (`CompileConfig(...)`, an
// *ast.Ident) or a method (`m.abortAfterHostMutation(...)`, an
// *ast.SelectorExpr). selectorName alone silently returns "" for the first
// shape, which would make the anchor below match nothing and the guard pass
// while measuring an empty statement range.
func callName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// TestAbortAfterHostMutationRepublishesCoverage is the #7289 R1 fail-on-revert
// cell for the reachable half of the hole: a LATER apply that aborts left the
// #7191 coverage cell holding the PREVIOUS apply's verdict, so the daemon's
// gate read Complete — an affirmative statement of coverage — for a box that
// had just failed to attach anything.
//
// The fixture is two applies on one Manager, which is the only shape in which
// the stale report exists at all. A single-apply fixture would leave the cell
// unpublished and exercise the OTHER state (unknown), where the bug is that the
// daemon's switch has no case rather than that the report is wrong — and
// deleting the fix would still look green here.
func TestAbortAfterHostMutationRepublishesCoverage7289(t *testing.T) {
	const ifidx = 5
	swapArmProbes(t,
		func(int) bool { return false },
		func(link.Link) (uint32, bool) { return 9, true },
	)

	m := New()
	m.loaded.Store(true)
	// Apply #1: the shim is attached at ifidx and the proof runs at the tail of
	// a SUCCESSFUL CompileUserspaceShim.
	m.xdpLinks[ifidx] = nil
	m.ProveArmCoverage(newProofResult([]int{ifidx}))

	uncovered, total, ran, seen := m.ArmCoverageSummary()
	if !seen || !ran || uncovered != 0 || total != 1 {
		t.Fatalf("fixture precondition: apply #1 must publish a COMPLETE verdict; "+
			"got uncovered=%d total=%d ran=%v seen=%v", uncovered, total, ran, seen)
	}

	// Apply #2: removeUserspaceShimXDPLinkPins has run and the re-attach failed,
	// so nothing is attached at ifidx any more. This is the state that makes the
	// interface an unadjudicated forwarding surface.
	delete(m.xdpLinks, ifidx)
	boom := errors.New("attach userspace shim XDP: generic attach refused")

	got := m.abortAfterHostMutation(newProofResult([]int{ifidx}), boom)

	if !errors.Is(got, boom) {
		t.Fatalf("the abort path must return its caller's error unchanged; got %v", got)
	}
	uncovered, total, ran, seen = m.ArmCoverageSummary()
	if !seen || !ran {
		t.Fatalf("an abort must leave a REAL verdict published, not an absent one "+
			"(the daemon gate has no case for unknown and disarms nothing); "+
			"got ran=%v seen=%v", ran, seen)
	}
	if uncovered != 1 || total != 1 {
		t.Fatalf("the published verdict still describes the PREVIOUS apply: uncovered=%d "+
			"total=%d. The daemon gate reads this as armCoverageComplete and leaves "+
			"an interface carrying no XDP shim read as covered — the blackholed-zone-member "+
			"state #7191 exists to prevent", uncovered, total)
	}
}

// The control, and the one that decides whether the fix is AIMED right rather
// than merely powerful: a re-attach can fail while the PREVIOUS shim is still
// attached and still adjudicating that interface's transit. Publishing a
// synthetic "everything uncovered" report on abort — the obvious
// implementation — would disarm that box and brick forwarding that was never
// unadjudicated. Running the real proof reports it COVERED, because it is.
func TestAbortAfterHostMutationDoesNotDisarmAStillAttachedSurface7289(t *testing.T) {
	const ifidx = 5
	swapArmProbes(t,
		func(int) bool { return false },
		func(link.Link) (uint32, bool) { return 9, true },
	)

	m := New()
	m.loaded.Store(true)
	// The shim from the previous apply is STILL attached; only the new attach
	// failed (e.g. a second interface, or a mode change the driver refused).
	m.xdpLinks[ifidx] = nil

	boom := errors.New("attach userspace shim XDP: generic attach refused")
	if got := m.abortAfterHostMutation(newProofResult([]int{ifidx}), boom); !errors.Is(got, boom) {
		t.Fatalf("error must pass through; got %v", got)
	}

	uncovered, total, ran, seen := m.ArmCoverageSummary()
	if !seen || !ran || total != 1 {
		t.Fatalf("expected a real verdict for the one required surface; got uncovered=%d "+
			"total=%d ran=%v seen=%v", uncovered, total, ran, seen)
	}
	if uncovered != 0 {
		t.Fatalf("a surface whose shim is still attached must be reported COVERED: an abort "+
			"is not evidence that forwarding is unadjudicated, and disarming here is a "+
			"brick, not a fence (#1960). got uncovered=%d", uncovered)
	}
}

// TestEveryPostCompileAbortPublishesCoverage7289 binds the WIRING, not the
// helper. The behavioural cells above prove abortAfterHostMutation does the
// right thing; they say nothing about whether CompileUserspaceShim calls it,
// and CompileUserspaceShim itself needs netlink and root so no unit test drives
// it end to end.
//
// The property: every `return nil, <err>` in CompileUserspaceShim that sits
// AFTER the CompileConfig success check is an abort with a live CompileResult
// in hand and a host that Phase 2 has already mutated, so each one owes a
// published verdict. A future step added to that window then cannot be wired
// without inheriting the contract — the same reason runPostMutationSteps exists
// as a named region rather than two inline blocks.
func TestEveryPostCompileAbortPublishesCoverage7289(t *testing.T) {
	fset, file := parseDataplaneFile(t, "loader.go")
	fn := findFuncDecl(t, file, "CompileUserspaceShim")

	// Anchor: the CompileConfig call. Everything after it has a `result`.
	compileIdx := -1
	for i, stmt := range fn.Body.List {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && callName(call.Fun) == "CompileConfig" {
				found = true
			}
			return !found
		})
		if found {
			compileIdx = i
			break
		}
	}
	if compileIdx < 0 {
		t.Fatal("CompileUserspaceShim no longer calls CompileConfig — this guard is " +
			"anchored on a call that does not exist, which is not evidence of anything")
	}

	// The statement immediately after the assignment is CompileConfig's own
	// error check, and its `return nil, err` is the ONE post-CompileConfig abort
	// that must NOT be routed through the helper: CompileConfig returns a nil
	// result on every phase error (compiler.go), so there is no pendingXDP to
	// prove coverage against. Assert that shape rather than skipping an index on
	// faith — if it ever stops being the nil-result guard, this fails loudly
	// instead of silently exempting a real abort.
	if compileIdx+1 >= len(fn.Body.List) {
		t.Fatal("nothing follows the CompileConfig assignment; the shape this guard " +
			"exempts no longer exists")
	}
	nilResultGuard, ok := fn.Body.List[compileIdx+1].(*ast.IfStmt)
	if !ok || !returnsNilPair(nilResultGuard) {
		t.Fatal("the statement after the CompileConfig assignment is no longer its " +
			"`if err != nil { return nil, err }` check. That check is the only abort " +
			"this guard exempts, on the grounds that CompileConfig returns a NIL result " +
			"there; re-derive the exemption before changing this shape")
	}

	// Non-vacuity FIRST: an anchor that matches no aborts would make the check
	// below pass for free, which is exactly how this guard would rot.
	aborts := 0
	guarded := 0
	for i, stmt := range fn.Body.List {
		if i <= compileIdx+1 {
			continue
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 2 || identName(ret.Results[0]) != "nil" {
				return true
			}
			aborts++
			if call, ok := ret.Results[1].(*ast.CallExpr); ok &&
				callName(call.Fun) == "abortAfterHostMutation" {
				guarded++
				return true
			}
			t.Errorf("CompileUserspaceShim aborts at line %d with a bare error, AFTER "+
				"CompileConfig's Phase 2 has already mutated the host. The #7191 coverage "+
				"cell then still describes a different apply — absent on the first apply "+
				"(the daemon gate has no case for unknown) or stale-and-affirmative on "+
				"every later one — so nothing disarms and transit stays open over an "+
				"interface that may carry no XDP shim. Route it through "+
				"m.abortAfterHostMutation(result, err).",
				fset.Position(ret.Pos()).Line)
			return true
		})
	}

	if aborts == 0 {
		t.Fatal("no post-CompileConfig `return nil, err` found in CompileUserspaceShim — " +
			"this guard measured nothing; the abort shape it is written against has changed")
	}
	if guarded == 0 {
		t.Fatalf("found %d post-CompileConfig aborts and none goes through "+
			"abortAfterHostMutation", aborts)
	}
}
