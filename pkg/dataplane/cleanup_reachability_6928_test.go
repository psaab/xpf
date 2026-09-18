package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #6928: bind the CALL-GRAPH claim the stale-pin remediation makes.
//
// The remediation, and the two `types.go` notes beside it, told the operator
// what does and does not release a bpffs pin. That is a claim about which
// production entry points reach `dataplane.Cleanup()` — and it has now been
// wrong in both directions:
//
//   - before r5 it said "a reload" releases the pin. Nothing does that.
//   - r5 replaced it with "restarting xpfd does NOT release it" plus
//     "Cleanup() is reachable only from the `xpfd cleanup` subcommand". Also
//     false: `Manager.Teardown` calls `Cleanup()`, and
//     `daemon_run_shutdown.go` calls `Teardown` on every NON-hitless shutdown
//     ("HA shutdown: tearing down BPF state"). On that path the pins are gone
//     and a plain restart is sufficient.
//
// Both wrong versions carried a PASSING test, because the assertions were
// substring checks on the message. A phrase-presence assertion is satisfied
// identically by a correct and an incorrect instruction — it defends the text,
// not the behaviour, which is exactly how the replacement inherited the same
// blind spot as the thing it replaced.
//
// The claim is about the call graph, so the check is about the call graph. This
// test derives `Cleanup()`'s production callers from the source and fails when
// that set changes, forcing whoever changes it to re-read the operator-facing
// text that describes it. It is not a proxy for the message's correctness: it
// is the same kind of fact the message asserts.
//
// #6743 ADDED A LEVEL OF INDIRECTION and it matters to what this walk can
// prove. `Manager.Teardown` no longer calls `Cleanup()`; it calls
// `teardownCleanupFn()`, a package-level var whose production value is
// `Cleanup` (a test seam, so a unit test can drive the real Teardown without
// os.RemoveAll-ing the machine's /sys/fs/bpf/xpf). Two consequences:
//
//   - A CALL-ONLY walk goes blind to that edge and reports it as "Teardown no
//     longer reaches Cleanup" — a false alarm pointing at the operator text in
//     the direction of a claim that is NOT true. The walk therefore records
//     function-VALUE references too, and tags each entry `(call)` or
//     `(value)`, so an indirection is visible as an indirection rather than as
//     a deletion.
//   - The value handoff alone no longer proves Teardown reaches Cleanup:
//     deleting `err := teardownCleanupFn()` leaves the var, its initializer,
//     and this entire caller set unchanged. That half is bound behaviourally
//     by TestTeardownInvokesTheCleanupSeam_6928 at the bottom of this file.
//     Both halves were measured, not argued: severing the invocation reds the
//     behavioural test and leaves this walk GREEN; rewriting the initializer
//     reds this walk and leaves the behavioural test green (it substitutes the
//     seam itself). Neither guard subsumes the other.
//
// SCOPE, measured rather than asserted (#6928). This pins WHO can name
// `Cleanup()`. It does NOT pin mode PLACEMENT — that a call sits in the
// non-hitless arm specifically, or that anything reaches it at all. That half
// is bound behaviourally, in
// `pkg/daemon/shutdown_dataplane_mode_6928_test.go`, which drives the real
// `runShutdownSequence` with a substituted `RuntimeDataPlane` and asserts both
// arms: non-hitless calls `Teardown` and not `Close`, hitless the reverse.
//
// A previous revision paired this with a SUBSTRING check that
// `daemon_run_shutdown.go` still contained the two call expressions, and
// described it as making the mode claim un-regressable. It did not, and this
// round measured both escapes rather than reasoning about them: inverting the
// condition to `if !hitless`, and replacing the call with
// `// d.dp.Teardown()`, each left that check GREEN (the second still builds).
// Both are RED against the behavioural test, so the substring companion was
// removed rather than re-labelled — it proved a strict subset of what its
// replacement proves.
//
// Deliberately NOT asserted here: the message's wording. Recording that the
// prose must contain some phrase is what produced two wrong-but-green rounds.
// stalepin_remediation_5363_test.go keeps only the NEGATIVE — that the
// disproven categorical claims are absent, which is a check on VOCABULARY and
// is labelled as such there; it cannot tell a true remediation from a false
// one that avoids those words.

// cleanupRefKind distinguishes the two ways production source can reach
// dataplane.Cleanup(). Both are real edges and the walk must see both:
// #6743 turned the Teardown edge from a CALL into a function VALUE
// (`var teardownCleanupFn = Cleanup`, invoked indirectly by Teardown), and a
// call-only walk reported that as "Teardown no longer reaches Cleanup" — a
// false alarm in the direction that would have invited someone to "correct"
// the operator text to a claim that is not true.
type cleanupRefKind string

const (
	cleanupRefCall  cleanupRefKind = "call"  // Cleanup(...)
	cleanupRefValue cleanupRefKind = "value" // Cleanup used as a func value
)

// cleanupCaller is one production reference to dataplane.Cleanup(),
// identified by the package-relative file, the enclosing declaration, and
// whether it is a call or a function-value handoff.
type cleanupCaller struct {
	file string // repo-relative, slash-separated
	fn   string
	kind cleanupRefKind
}

func (c cleanupCaller) String() string {
	return c.file + ":" + c.fn + " (" + string(c.kind) + ")"
}

// namesCleanup reports whether e names THIS package's Cleanup under the
// import binding the enclosing file established.
func namesCleanup(e ast.Expr, bareIsOurs bool, qualifier string) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return bareIsOurs && x.Name == "Cleanup"
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		return ok && qualifier != "" && pkg.Name == qualifier && x.Sel.Name == "Cleanup"
	}
	return false
}

// appendCleanupRefs records every reference to dataplane.Cleanup inside root,
// attributed to enclosing, tagging each as a call or a function value.
func appendCleanupRefs(found *[]cleanupCaller, root ast.Node, rel, enclosing string, bareIsOurs bool, qualifier string) {
	callees := map[ast.Expr]bool{}
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callees[call.Fun] = true
		}
		return true
	})
	record := func(e ast.Expr) {
		kind := cleanupRefValue
		if callees[e] {
			kind = cleanupRefCall
		}
		*found = append(*found, cleanupCaller{rel, enclosing, kind})
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if namesCleanup(e, bareIsOurs, qualifier) {
				record(e)
			}
			// Never descend into a selector. e.Sel is an Ident literally
			// named "Cleanup", so descending double-counts a qualified
			// reference — and inside package dataplane it would also count
			// an unrelated METHOD call `x.Cleanup()` as this package's
			// function.
			return false
		case *ast.Ident:
			if bareIsOurs && e.Name == "Cleanup" {
				record(e)
			}
			return false
		}
		return true
	})
}

// dataplaneImportPath is the package whose Cleanup() this test tracks.
const dataplaneImportPath = "github.com/psaab/xpf/pkg/dataplane"

// dataplaneLocalName reports how `dataplaneImportPath` is bound in f:
// the empty string if f does not import it, "." for a dot-import (where
// `Cleanup()` is written bare), otherwise the qualifier — the alias when the
// import has one, else the package name.
//
// Resolving the IMPORT rather than assuming the spelling `dataplane.Cleanup`
// is what makes an aliased call site visible. The previous revision matched
// the literal qualifier `dataplane`, so `import dp "…/pkg/dataplane"` followed
// by `dp.Cleanup()` was a real production caller this walk silently missed —
// reproduced by adding exactly that file and watching the test stay green.
func dataplaneLocalName(f *ast.File) string {
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != dataplaneImportPath {
			continue
		}
		if spec.Name != nil {
			if spec.Name.Name == "_" {
				return "" // blank import: no callable binding
			}
			return spec.Name.Name // "." for a dot-import, else the alias
		}
		return "dataplane" // package name, no alias
	}
	return ""
}

// findCleanupCallers walks the repo for non-test calls to
// dataplane.Cleanup(), resolving the callee through each file's IMPORT
// bindings rather than through its spelling.
//
// Three forms count: the bare `Cleanup()` inside package dataplane itself;
// the bare form in a file that dot-imports the package; and `<q>.Cleanup()`
// where <q> is whatever local name that file bound the package to.
//
// Not resolved, because that needs full type information: a local identifier
// that SHADOWS the package name, and any indirect call (`f := dataplane.Cleanup;
// f()`). Both would need `go/types`; neither is reachable by accident, and the
// walk errs toward reporting rather than hiding.
func findCleanupCallers(t *testing.T, root string) []cleanupCaller {
	t.Helper()
	var found []cleanupCaller
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Dot-directories and underscore-directories are not production
			// source: the Go tool ignores them when loading packages, so nothing
			// below them is importable or built.
			// #10154: `.claude/worktrees/*` holds nested checkouts of this
			// repo, and the walk counted each copy's `cmd/xpfd/main.go` as a
			// production Cleanup() caller — a red test with zero production
			// change. Skipping them keeps the walk to this checkout's source.
			if strings.HasPrefix(info.Name(), ".") || strings.HasPrefix(info.Name(), "_") {
				return filepath.SkipDir
			}
			switch info.Name() {
			// Vendored / generated / build-output trees carry no production
			// call sites and would make this walk slow and noisy.
			case ".git", "vendor", "target", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file this package cannot parse is not silently skipped: it
			// could be the one holding a call site.
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		local := dataplaneLocalName(f)
		// A bare `Cleanup()` names THIS package's function only inside the
		// dataplane package itself, or in a file that dot-imported it. Counting
		// it anywhere else is how an unrelated `Cleanup()` in another package —
		// a perfectly ordinary name — was falsely reported as a caller, which
		// this round reproduced by adding one and watching the caller-set
		// comparison fail on a package that never touches the dataplane.
		bareIsOurs := local == "." ||
			(f.Name.Name == "dataplane" && strings.HasPrefix(rel, "pkg/dataplane/"))
		qualifier := ""
		if local != "" && local != "." {
			qualifier = local
		}
		if !bareIsOurs && qualifier == "" {
			return nil // this file cannot name dataplane.Cleanup at all
		}

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				appendCleanupRefs(&found, d.Body, rel, d.Name.Name, bareIsOurs, qualifier)
			case *ast.GenDecl:
				// #6743 put the Teardown edge in a package-level var
				// initializer (`var teardownCleanupFn = Cleanup`), which has
				// no enclosing FuncDecl at all. A walk that only descends
				// into function bodies cannot see that edge, and reported its
				// disappearance as a call-graph change.
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					enclosing := strings.ToLower(d.Tok.String()) + " " + vs.Names[0].Name
					for _, v := range vs.Values {
						appendCleanupRefs(&found, v, rel, enclosing, bareIsOurs, qualifier)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].String() < found[j].String() })
	return found
}

// TestCleanupProductionCallersMatchRemediation_6928 pins the production caller
// set of dataplane.Cleanup(). Adding or removing one changes whether a restart
// can clear a stale pin, which is precisely what the remediation and the
// types.go notes describe — so it must not change silently.
func TestCleanupProductionCallersMatchRemediation_6928(t *testing.T) {
	t.Parallel()

	// The package lives at <root>/pkg/dataplane.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	got := findCleanupCallers(t, root)

	// --- DIAGNOSTIC, not a vacuity guard. Stating that precisely, because the
	// first version of this comment claimed the latter and was wrong (#6928
	// review): a walk that silently matched nothing (wrong root, changed AST
	// shape, over-eager SkipDir) does NOT pass vacuously. The comparison below
	// is against a NONEMPTY `want`, so an empty result already fails it, and
	// the >= 2 check fails too. What this arm buys is the right DIAGNOSIS —
	// "the walk is broken" instead of a zero-vs-two diff that reads as though
	// the production call sites had been deleted.
	if len(got) == 0 {
		t.Fatalf("found ZERO production callers of Cleanup() under %s; the walk is "+
			"broken, not the code — Cleanup() is called at least from "+
			"cmd/xpfd/main.go", root)
	}

	want := []string{
		// the `xpfd cleanup` subcommand
		"cmd/xpfd/main.go:main (call)",
		// the non-hitless shutdown path. #6743 moved this edge behind the
		// `teardownCleanupFn` test seam, so what the source now holds is a
		// function VALUE that Manager.Teardown invokes indirectly. That the
		// invocation still happens is not a syntactic fact and is bound
		// behaviourally by TestTeardownInvokesTheCleanupSeam_6928 below.
		"pkg/dataplane/loader.go:var teardownCleanupFn (value)",
	}
	gotStr := make([]string, 0, len(got))
	for _, c := range got {
		gotStr = append(gotStr, c.String())
	}
	sort.Strings(want)

	if strings.Join(gotStr, "\n") != strings.Join(want, "\n") {
		t.Fatalf("production callers of Cleanup() changed.\n got:\n  %s\nwant:\n  %s\n\n"+
			"This set decides whether a restart can clear a stale bpffs pin, which is "+
			"what userspaceShimStalePinRemediation and the types.go:sessions notes "+
			"tell an operator mid-upgrade. Re-read BOTH before updating this list "+
			"(#6928).",
			strings.Join(gotStr, "\n  "), strings.Join(want, "\n  "))
	}

	// --- THE PROPERTY THE MESSAGE DEPENDS ON: more than one production caller
	// means "does a restart release the pin?" has no categorical answer. If
	// this ever collapses to the single CLI caller again, the mode-dependent
	// wording becomes wrong in the other direction and must be revisited.
	if len(got) < 2 {
		t.Fatalf("Cleanup() now has a single production caller (%v), so restart "+
			"behaviour IS categorical again — the mode-dependent remediation text "+
			"is now the inaccurate one and must be rewritten (#6928)", gotStr)
	}
}

// The other half of the claim — that the second caller sits on the ORDINARY
// non-hitless shutdown path rather than a decommission-only helper — used to
// live here as a substring check over `pkg/daemon/daemon_run_shutdown.go`. It
// is now bound behaviourally by
// `TestShutdownModeChoosesCloseOrTeardown6928` in `pkg/daemon`, which observes
// which lifecycle method each arm actually calls. See the SCOPE note above for
// the two mutations that survived the substring form and are RED against the
// replacement.
//
// The reason the check could not simply be made behavioural HERE is worth
// recording: exercising it in `pkg/dataplane` means calling `Cleanup()` for
// real, which does `os.RemoveAll("/sys/fs/bpf/xpf")` and would destroy the
// pinned dataplane state of whatever machine runs the suite. Substituting the
// `RuntimeDataPlane` interface at the daemon's call site avoids that entirely:
// the fake records the call and touches no bpffs.

// TestTeardownInvokesTheCleanupSeam_6928 binds the half of the reachability
// claim the AST walk above structurally CANNOT bind after #6743.
//
// Before #6743 `Manager.Teardown` called `Cleanup()` directly, so "Teardown
// reaches Cleanup" was a syntactic fact and the walk was the whole proof.
// #6743 replaced the call with `teardownCleanupFn()`, a package-level var
// whose production value is `Cleanup`. The walk can still see the VALUE
// handoff — that is what the "(value)" entry in the want set is — but a
// function value sitting in a var proves nothing about whether anything
// invokes it. Deleting `err := teardownCleanupFn()` from Teardown leaves the
// var, its initializer, and therefore the entire caller set unchanged.
//
// So the two halves are split deliberately:
//   - the walk pins WHICH production sites can name Cleanup at all (and would
//     fire if a third appeared, or if the Teardown handoff were deleted);
//   - this test pins that Teardown actually INVOKES the seam, which is the
//     fact "a non-hitless shutdown unpins everything, so a restart is enough"
//     rests on;
//   - TestShutdownModeChoosesCloseOrTeardown6928 (pkg/daemon) pins that the
//     non-hitless arm is the one that calls Teardown.
//
// Fail-on-revert, observed: dropping the `teardownCleanupFn()` call from
// Teardown leaves `go test -run 6928 ./pkg/dataplane/` RED here and GREEN in
// the walk above — which is exactly why this test exists and the walk alone
// is no longer sufficient.
//
// The real Cleanup is never invoked: it does os.RemoveAll("/sys/fs/bpf/xpf")
// and would destroy the pinned dataplane state of whatever machine runs the
// suite. The seam is restored unconditionally on return.
func TestTeardownInvokesTheCleanupSeam_6928(t *testing.T) {
	// NOT t.Parallel(): this mutates a package-level var that the production
	// Teardown reads, and a sibling test doing the same would interleave.
	defer func(fn func() error) { teardownCleanupFn = fn }(teardownCleanupFn)

	called := 0
	teardownCleanupFn = func() error { called++; return nil }

	m := New()
	if err := m.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if called != 1 {
		t.Fatalf("Manager.Teardown invoked the pinned-state sweep %d times, want 1.\n\n"+
			"userspaceShimStalePinRemediation and the types.go:sessions notes tell an "+
			"operator that a NON-hitless shutdown unpins the maps, so a plain restart "+
			"clears a stale pin. That sentence is true only while Teardown actually "+
			"runs the sweep. The caller-set walk in this file cannot see this: it "+
			"reports the `var teardownCleanupFn = Cleanup` handoff, which survives "+
			"unchanged when the invocation is deleted (#6928/#6743).", called)
	}

	// Polarity control: Close is the HITLESS path and must NOT run the sweep,
	// because the pins are deliberately left for the next daemon. Without this
	// arm the test above stays green if BOTH lifecycle methods swept, which
	// would make the mode-dependent wording wrong in the other direction.
	called = 0
	m2 := New()
	if err := m2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if called != 0 {
		t.Fatalf("Manager.Close invoked the pinned-state sweep %d times, want 0 — a "+
			"hitless shutdown must PRESERVE the pins, and if it does not then "+
			"\"a hitless restart hits the identical refusal\" is false (#6928)", called)
	}
}
