package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #8526: the two structural facts the stop bound rests on, asserted rather
// than described.
//
// The bound in control_shutdown_8526.go fixes every m.mu-holding control
// caller at once for exactly one reason: they all reach the socket through
// requestDetailedLocked, which is the only place a control connection's
// deadline is set. Both halves of that are source-level properties nothing
// else checks, and both are one careless edit from being false — a new caller
// that dials and sets its own deadline is invisible to every behavioural cell
// in this file, because those drive requestDetailedLocked directly.
//
// This also retires a comment. The census of "which methods hold m.mu across a
// control round trip" has been written by hand twice now and was wrong the
// second time (16 listed, 21 present — the #8121 idle-lease pair and three
// manager_status.go/manager_sessions.go methods were missing). A hand count
// goes stale the next time someone adds a method; this one is recomputed on
// every run.

// controlCallFacts is what the analyzer extracts per function.
type controlCallFacts struct {
	name         string
	file         string
	acquiresMu   bool // takes m.mu with no preceding release
	callsReq     bool // calls requestLocked / requestDetailedLocked / requestApplySnapshotLocked
	setsDeadline bool
}

func analyzeControlCalls8526(t *testing.T, dir string) []controlCallFacts {
	t.Helper()
	fset := token.NewFileSet()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []controlCallFacts
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			cf := controlCallFacts{name: fn.Name.Name, file: filepath.Base(path)}
			// Ordered m.mu actions, so "unlock then relock for slow I/O" is
			// not misread as an acquire — the same distinction #7930 makes.
			type act struct {
				pos    token.Pos
				unlock bool
			}
			var acts []act
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
					switch sel.Sel.Name {
					case "Lock":
						acts = append(acts, act{call.Pos(), false})
					case "Unlock":
						acts = append(acts, act{call.Pos(), true})
					}
					return true
				}
				switch sel.Sel.Name {
				// #9520: requestApplySnapshotLocked is the one apply_snapshot send site, so
				// its callers issue a round trip exactly as direct requestLocked callers do.
				case "requestLocked", "requestDetailedLocked", "requestApplySnapshotLocked":
					cf.callsReq = true
				case "SetDeadline":
					cf.setsDeadline = true
				}
				return true
			})
			sort.Slice(acts, func(i, j int) bool { return acts[i].pos < acts[j].pos })
			for _, a := range acts {
				if a.unlock {
					break
				}
				cf.acquiresMu = true
				break
			}
			out = append(out, cf)
		}
	}
	return out
}

// TestEveryControlCallerHoldsTheManagerMutex8526 recomputes the census and
// asserts the property the stop bound depends on: a control round trip is
// never issued off m.mu, so bounding the round trip bounds the lock hold.
//
// MUTATION: give any acquirer's request call a caller that neither takes m.mu
// nor carries the Locked suffix and this reds, naming it.
func TestEveryControlCallerHoldsTheManagerMutex8526(t *testing.T) {
	facts := analyzeControlCalls8526(t, ".")
	if len(facts) == 0 {
		t.Fatal("analyzer found no functions — the parse produced nothing and this " +
			"check is passing vacuously")
	}

	var acquirers, lockedHelpers, unclassified []string
	for _, f := range facts {
		if !f.callsReq || f.name == "requestLocked" {
			continue
		}
		switch {
		case f.acquiresMu:
			acquirers = append(acquirers, f.name+" ("+f.file+")")
		case strings.HasSuffix(f.name, "Locked"):
			lockedHelpers = append(lockedHelpers, f.name+" ("+f.file+")")
		default:
			unclassified = append(unclassified, f.name+" ("+f.file+")")
		}
	}
	sort.Strings(acquirers)
	sort.Strings(unclassified)

	// The classifier must discriminate. If either class came back empty the
	// partition below would be meaningless and "0 unclassified" would prove
	// nothing.
	if len(acquirers) == 0 || len(lockedHelpers) == 0 {
		t.Fatalf("classifier degenerate: %d acquirers, %d Locked helpers — it is no "+
			"longer separating the two classes it partitions on",
			len(acquirers), len(lockedHelpers))
	}
	// Plurality, not a pinned number: the point of #8526 is that this is a
	// CLASS. A single-site fix would leave the rest of it intact.
	if len(acquirers) < 10 {
		t.Fatalf("only %d methods hold m.mu across a control round trip; the class this "+
			"bound covers has collapsed, and the analyzer is more likely wrong than "+
			"the tree: %v", len(acquirers), acquirers)
	}

	if len(unclassified) > 0 {
		t.Errorf("%d control round-trip caller(s) neither acquire m.mu nor carry the "+
			"Locked suffix:\n  %s\n"+
			"The #8526 stop bound assumes every control round trip happens under m.mu, "+
			"so bounding the round trip bounds the lock hold. A caller outside that "+
			"assumption is either a lock-graph bug or a hold this bound does not cover.",
			len(unclassified), strings.Join(unclassified, "\n  "))
	}

	t.Logf("%d methods hold m.mu across a control round trip:\n  %s",
		len(acquirers), strings.Join(acquirers, "\n  "))
}

// TestControlDeadlineHasExactlyOneSite8526 asserts the choke point. If a new
// path dials the control socket and sets its own deadline, the #8526 bound
// does not apply to it — and no behavioural cell in this package can see that,
// because they all drive requestDetailedLocked.
//
// The set is EXACT, not a lower bound: a new bypass appears as an extra
// element rather than being absorbed. Each member is here for a stated reason;
// adding a fourth is a decision someone has to make deliberately.
//
// MUTATION: put `_ = conn.SetDeadline(...)` back in requestDetailedLocked
// (the pre-#8526 shape) and this reds with requestDetailedLocked as an
// unexpected member.
func TestControlDeadlineHasExactlyOneSite8526(t *testing.T) {
	// armControlIO             — the #8526 bound itself: the ONE place a
	//                            control-socket deadline is CHOSEN for a new
	//                            round trip, so a stop can cap it.
	// cutInFlight...Locked     — the other half of the same mechanism: it
	//                            SHORTENS the deadline of a round trip already
	//                            in flight. It never lengthens one, so it
	//                            cannot be a bypass.
	// requestSessionSyncLocked — the dedicated SESSION socket, not this one.
	//                            Flat sessionSyncRoundtripDeadline (3s), already
	//                            inside the stop budget by construction.
	// ProbeStatus              — a standalone one-shot probe that stands up no
	//                            Manager and holds no lock; its deadline is the
	//                            caller's own timeout argument.
	want := map[string]bool{
		"armControlIO":               true,
		"cutInFlightControlIOLocked": true,
		"requestSessionSyncLocked":   true,
		"ProbeStatus":                true,
	}

	facts := analyzeControlCalls8526(t, ".")
	got := map[string]string{}
	for _, f := range facts {
		if f.setsDeadline {
			got[f.name] = f.file
		}
	}
	if len(got) == 0 {
		t.Fatal("no SetDeadline call found anywhere in the package — the analyzer can " +
			"no longer see the thing it exists to bound, so this is passing vacuously")
	}

	var extra, missing []string
	for name, file := range got {
		if !want[name] {
			extra = append(extra, name+" ("+file+")")
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)

	if len(extra) > 0 {
		t.Errorf("socket deadline set outside the known deadline sites:\n  %s\n"+
			"A control round trip whose deadline is set anywhere but armControlIO is "+
			"NOT covered by the #8526 stop bound: it can hold m.mu for its full scaled "+
			"deadline (67s reachable) past TimeoutStopSec=20. Route it through "+
			"armControlIO, or add it here with the reason it is already bounded.",
			strings.Join(extra, "\n  "))
	}
	if len(missing) > 0 {
		t.Errorf("expected deadline site(s) gone: %s — if one was renamed or removed, "+
			"this allowlist is now describing a tree that does not exist",
			strings.Join(missing, ", "))
	}
}
