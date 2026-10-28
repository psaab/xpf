package diagcmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #7294 item 1: the REGISTRATION guard for session-scan admission.
//
// THE DEFECT THIS EXISTS FOR. Admission is hand-duplicated —
// `sessionWalkLimiter.Acquire()` / `AcquireCtx(...)` is copied at each
// control surface. #6216 is the precedent for what that invites:
// `natPoolStatsHandler` drove the identical full v4+v6 conntrack walk and
// bypassed the shared bound entirely until a human noticed. Before this
// file nothing in the tree failed when a new scan surface appeared: the
// discipline lived in fifteen per-surface behavioural tests, each covering
// a surface someone remembered to add to a list.
//
// WHAT THIS ASKS, AND WHY NOT SOMETHING SIMPLER. The obvious detector —
// "does this function call a method whose name looks like a scan?" — is
// the one the issue records as having produced false hits. Three shapes
// defeat it, and all three are handled here by construction rather than
// by an exemption list:
//
//  1. `pkg/api/api.go:33` declares `SessionCount() (v4, v6 int)` as a
//     FIELD of the `apiRuntimeDataPlane` interface. Matching identifiers
//     rather than call position flags a type declaration as a scan. This
//     detector only considers *ast.CallExpr.
//  2. `pkg/grpcapi/runtime.go`'s `backendSessionCount` genuinely calls
//     SessionCount, but it is a five-line accessor whose only callers
//     (`showBuffers`, `showBuffersDetail`) already acquire. Flagging it
//     reports the wrong node in the chain. Coverage here is transitive:
//     a scanning function is covered when every caller that reaches it is
//     covered, so a helper inherits its callers' admission.
//  3. `buildTracerouteArgv` (three copies) touches no session primitive at
//     all — it delegates to `diagcmd.TracerouteArgv`. Any detector keyed
//     on the `diagcmd` package qualifier, or on a `Count` substring near
//     `buildPingArgv`'s `Count:` field, would flag it. Keying on the
//     primitive SET plus call position cannot. (Recorded honestly: unlike
//     the other two, I could not reproduce the original mechanism for this
//     one, so it is a control here rather than evidence about the old
//     detector.)
//
// WHICH BUDGET, NOT MERELY WHETHER. #8151 was a surface that DID acquire
// — `show security nat persistent-nat` held `MaxConcurrentSessionWalks`
// slots for an O(bindings) map copy that walks nothing, so a peer polling
// it could starve genuine session scans. A guard asking only "does it
// acquire?" would have rated that compliant. So the acquire must be on the
// session-walk limiter specifically; `SnapshotReadLimiter.Acquire()`,
// `diagLimiter.Acquire()` and `ribStreamLimiter.Acquire()` do not count.
//
// SCOPE, AND WHAT IS DELIBERATELY OUTSIDE IT. This guards `pkg/api` and
// `pkg/grpcapi` — the surfaces `MaxConcurrentSessionWalks`'s own doc
// comment says it bounds, and the only two packages where a new *endpoint*
// can appear. Two other groups walk and are outside on purpose:
//
//   - `pkg/cli` — 18 scan call sites, zero acquires, running IN-PROCESS in
//     the daemon (`daemon_run.go:701` builds the shell with the live
//     dataplane). It is bounded by construction rather than unbounded:
//     exactly one non-test `cli.New(...)` call site, inside
//     `if isInteractive()`, and a REPL runs one command at a time — so the
//     console contributes at most ONE concurrent walk. The decision is
//     already recorded at `pkg/cli/cli_show_nat.go:544-546`. The remote
//     `cli` binary reaches the daemon over gRPC and is bounded there.
//   - The daemon-internal background walkers — `cluster`
//     bulk/conn sweeps, `warmNeighborCache`, the policy
//     invalidation walks, `ReconcileClusterBulk`. These are not
//     request-driven, so a REQUEST admission budget is the wrong
//     instrument for them.
//
// Bringing either group in scope would mean ~20 exemption entries, and a
// guard that forces a workaround list is mis-specified — the list drifts
// and the guard stops meaning anything. They are named here instead so a
// later reader knows they were considered rather than missed.

// scanPrimitives are the session-table walk entry points. Every one of
// them iterates the v4 and/or v6 conntrack table.
//
// SessionCount is in the set deliberately. This issue's body cautions that
// the set is heterogeneous because "SessionCount can read a cached
// counter"; that is not true in this tree. Both non-test implementations
// walk — `pkg/dataplane/maps_session.go:371` runs two full kernel map
// iterations, and `pkg/daemon/daemon_dp_live.go:397` forwards to it. Only
// test fakes return a stored field. `pkg/diagcmd/limiter.go` says the same
// thing: "SessionCount is count-only ... but its KERNEL iteration +
// per-bucket lock cost is the same O(table) contention." Treating it as
// sometimes-cheap is the LOOSE failure direction — it would exempt a real
// full-table walk, which is what `GetStatus` and the REST status handler
// acquire for.
var scanPrimitives = map[string]bool{
	"IterateSessions":        true,
	"IterateSessionsV6":      true,
	"IterateSessionsFrom":    true,
	"IterateSessionsV6From":  true,
	"BatchIterateSessions":   true,
	"BatchIterateSessionsV6": true,
	"SessionCount":           true,
}

// scanCarriers are functions in OTHER packages that reach a scan
// primitive. Without them a surface could walk the whole table through a
// helper package and never mention a primitive in its own file.
//
// This is an allowlist, and an allowlist entry is a claim, so
// TestScanCarriersReallyWalk below binds each one against its source
// rather than trusting the name.
var scanCarriers = map[string]bool{
	"RenderSourceRuleDetail": true,
	"RenderDestRuleDetail":   true,
	"RenderPersistentDetail": true,
}

// sessionWalkAcquirers are the receiver spellings that count as taking the
// SESSION-WALK budget. The package-level alias in both scoped packages is
// `sessionWalkLimiter`; the qualified form is `diagcmd.SessionWalkLimiter`.
func isSessionWalkAcquire(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name != "Acquire" && sel.Sel.Name != "AcquireCtx" {
		return false
	}
	switch recv := sel.X.(type) {
	case *ast.Ident:
		return recv.Name == "sessionWalkLimiter"
	case *ast.SelectorExpr:
		return recv.Sel.Name == "SessionWalkLimiter"
	}
	return false
}

// scanPrimitiveCalled returns the primitive name when the call is a call
// OF one, and "" otherwise. Call position is the whole point: an interface
// method declaration is an *ast.Field, never an *ast.CallExpr.
func scanPrimitiveCalled(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if scanPrimitives[sel.Sel.Name] || scanCarriers[sel.Sel.Name] {
		return sel.Sel.Name
	}
	return ""
}

type funcFacts struct {
	name          string
	pos           string
	directAcquire bool
	// returnsRelease marks a DEDICATED admission helper: it acquires and
	// hands the release closure back to its caller, so calling it really
	// does admit the caller. A handler that acquires for itself returns a
	// response, not a func, and calling one admits nobody.
	returnsRelease bool
	scans          []string
	callees        map[string]bool
}

// repoRoot resolves the tree root from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd)) // pkg/diagcmd -> repo root
}

func parsePackageFacts(t *testing.T, dir string) map[string][]*funcFacts {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	byName := map[string][]*funcFacts{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ff := &funcFacts{
				name:    fn.Name.Name,
				pos:     fmt.Sprintf("%s:%d", filepath.Base(path), fset.Position(fn.Pos()).Line),
				callees: map[string]bool{},
			}
			if fn.Type.Results != nil {
				for _, r := range fn.Type.Results.List {
					if _, isFunc := r.Type.(*ast.FuncType); isFunc {
						ff.returnsRelease = true
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSessionWalkAcquire(call) {
					ff.directAcquire = true
				}
				if p := scanPrimitiveCalled(call); p != "" {
					ff.scans = append(ff.scans, p)
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					ff.callees[fun.Name] = true
				case *ast.SelectorExpr:
					ff.callees[fun.Sel.Name] = true
				}
				return true
			})
			byName[ff.name] = append(byName[ff.name], ff)
		}
	}
	return byName
}

// violations returns the scanning functions in dir that no admission
// reaches, plus the total number of scanning functions found (the
// population, so a detector that matched nothing cannot pass vacuously).
func violations(t *testing.T, dir string) (viol []string, scanFuncs int) {
	t.Helper()
	byName := parsePackageFacts(t, dir)

	// callers[g] = set of function names that call g.
	callers := map[string]map[string]bool{}
	for name, fns := range byName {
		for _, f := range fns {
			for callee := range f.callees {
				if _, ok := byName[callee]; !ok {
					continue
				}
				if callers[callee] == nil {
					callers[callee] = map[string]bool{}
				}
				callers[callee][name] = true
			}
		}
	}

	// acquiring: a function is admitted when it takes the session-walk
	// budget ITSELF, or when it calls a DEDICATED admission helper — one
	// that acquires and returns the release closure, so the caller really
	// is holding the slot (grpcapi's acquireNATShowWalk).
	//
	// This deliberately does NOT propagate transitively callee -> caller.
	// The first version of this file did, and it was too loose in a way no
	// amount of re-reading showed: a ShowText dispatcher that calls many
	// handlers, ONE of which acquires, was marked admitted, and through it
	// every scanning handler it dispatches to was marked covered. Deleting
	// the real acquire from showSessionsTop and from GetSessions then left
	// the guard GREEN. Both mutations red under the rule below.
	helper := map[string]bool{}
	acquiring := map[string]bool{}
	for name, fns := range byName {
		for _, f := range fns {
			if f.directAcquire {
				acquiring[name] = true
				if f.returnsRelease {
					helper[name] = true
				}
			}
		}
	}
	for name, fns := range byName {
		if acquiring[name] {
			continue
		}
		for _, f := range fns {
			for callee := range f.callees {
				if helper[callee] {
					acquiring[name] = true
					break
				}
			}
			if acquiring[name] {
				break
			}
		}
	}

	// covered: acquiring, or has callers and every one of them is covered.
	covered := map[string]bool{}
	for name := range acquiring {
		covered[name] = true
	}
	for changed := true; changed; {
		changed = false
		for name := range byName {
			if covered[name] {
				continue
			}
			cs := callers[name]
			if len(cs) == 0 {
				continue
			}
			all := true
			for c := range cs {
				if !covered[c] {
					all = false
					break
				}
			}
			if all {
				covered[name] = true
				changed = true
			}
		}
	}

	for name, fns := range byName {
		for _, f := range fns {
			if len(f.scans) == 0 {
				continue
			}
			scanFuncs++
			if covered[name] {
				continue
			}
			sort.Strings(f.scans)
			viol = append(viol, fmt.Sprintf(
				"%s (%s) calls %s with no session-walk admission on any path that reaches it",
				name, f.pos, strings.Join(f.scans, ", ")))
		}
	}
	sort.Strings(viol)
	return viol, scanFuncs
}

// scopedPackages is the guard's remit: the two packages where a new
// control-plane ENDPOINT can appear, and the ones MaxConcurrentSessionWalks
// documents itself as bounding. See the file header for what is outside it
// and why.
var scopedPackages = []string{"pkg/api", "pkg/grpcapi"}

func TestEverySessionScanSurfaceIsAdmitted7294(t *testing.T) {
	root := repoRoot(t)
	totalScanFuncs := 0
	for _, pkg := range scopedPackages {
		viol, n := violations(t, filepath.Join(root, pkg))
		totalScanFuncs += n
		for _, v := range viol {
			t.Errorf("%s: %s\n\tEvery function reaching a session-scan primitive must be "+
				"admitted by sessionWalkLimiter.Acquire/AcquireCtx, directly or through "+
				"every caller that reaches it. See pkg/diagcmd/limiter.go and #7294.", pkg, v)
		}
	}
	// Positive control on the DETECTOR, not the subject: a detector that
	// matched nothing would report zero violations and pass. The scan
	// population must be non-empty and of the right order.
	t.Logf("detector population: %d scanning functions across %v", totalScanFuncs, scopedPackages)
	// Measured 22 at 192f40502. The floor is well below that on purpose:
	// it exists to catch a detector that has stopped matching, not to pin
	// a surface count that legitimately moves.
	if totalScanFuncs < 15 {
		t.Fatalf("detector found only %d scanning functions across %v; it has stopped "+
			"matching and this test is now vacuous", totalScanFuncs, scopedPackages)
	}
}

// TestScanDetectorSparesTheKnownFalseHits7294 pins the three sites the
// issue records a first-pass detector flagging. They are controls on the
// CORRECT input: a detector can catch every real violation and still be
// unusable if it reds on unrelated edits, and a guard that forces a
// workaround list is mis-specified.
func TestScanDetectorSparesTheKnownFalseHits7294(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct {
		pkg, fn, why string
	}{
		{"pkg/grpcapi", "backendSessionCount",
			"a five-line accessor; its only callers showBuffers/showBuffersDetail acquire"},
		{"pkg/api", "buildTracerouteArgv",
			"delegates to diagcmd.TracerouteArgv and touches no session primitive"},
		{"pkg/grpcapi", "buildTracerouteArgv", "same"},
	} {
		viol, _ := violations(t, filepath.Join(root, tc.pkg))
		for _, v := range viol {
			if strings.HasPrefix(v, tc.fn+" ") {
				t.Errorf("%s.%s reported as a violation, but %s", tc.pkg, tc.fn, tc.why)
			}
		}
	}

	// The interface-declaration case cannot appear as a violation because
	// it is not a call — assert the reason directly rather than its
	// absence, so this stays meaningful if api.go moves.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "pkg/api/api.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse api.go: %v", err)
	}
	sawInterfaceField := false
	ast.Inspect(f, func(n ast.Node) bool {
		it, ok := n.(*ast.InterfaceType)
		if !ok || it.Methods == nil {
			return true
		}
		for _, m := range it.Methods.List {
			for _, nm := range m.Names {
				if scanPrimitives[nm.Name] {
					sawInterfaceField = true
				}
			}
		}
		return true
	})
	if !sawInterfaceField {
		t.Skip("pkg/api/api.go no longer declares a scan primitive in an interface; " +
			"the api.go:33 false-hit control has nothing to bind")
	}
}

// TestScanCarriersReallyWalk7294 binds the scanCarriers allowlist. An
// allowlist entry is a claim: if one of these stops walking, the guard is
// demanding admission for work that no longer needs it, and if the name
// drifts the entry silently covers nothing.
func TestScanCarriersReallyWalk7294(t *testing.T) {
	root := repoRoot(t)
	byName := parsePackageFacts(t, filepath.Join(root, "pkg/natshow"))
	// walkSessionValues is where pkg/natshow actually touches the table.
	walker := ""
	for name, fns := range byName {
		for _, f := range fns {
			for _, s := range f.scans {
				if scanPrimitives[s] {
					walker = name
				}
			}
		}
	}
	if walker == "" {
		t.Fatal("no function in pkg/natshow calls a scan primitive; the scanCarriers " +
			"allowlist now names functions that do not walk")
	}
	for carrier := range scanCarriers {
		fns, ok := byName[carrier]
		if !ok {
			t.Errorf("scanCarriers names %q but pkg/natshow has no such function", carrier)
			continue
		}
		reaches := false
		for _, f := range fns {
			if f.callees[walker] {
				reaches = true
			}
			for _, s := range f.scans {
				if scanPrimitives[s] {
					reaches = true
				}
			}
		}
		if !reaches {
			t.Errorf("scanCarriers names %q but it does not reach %s; the entry covers nothing",
				carrier, walker)
		}
	}
}
