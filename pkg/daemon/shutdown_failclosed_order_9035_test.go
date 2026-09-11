package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sync"
	"testing"
	"time"
)

// #9035: the two FAIL-CLOSED shutdown actions must run before any teardown
// that can block.
//
// `TimeoutStopSec=20`, and systemd SIGKILLs there wherever we are. Exactly two
// actions must have completed by then, because only they are fail-closed:
// rg_active cleared (this node stops forwarding) and the Kea units stopped
// (it stops answering DHCP, #6787). Everything else is best-effort cleanup
// whose loss costs telemetry, not correctness.
//
// The flow-export drain reached 22s on its own — serial, 2s per collector,
// uncapped cardinality, untimed join — and it ran FIRST. Bounding that drain
// is necessary and is done, but it is not sufficient and never could be: it
// fixes the one subsystem that was measured and leaves the next slow one to
// re-break the invariant. ORDER is what makes it structural.
//
// This is bound as a SOURCE-ORDER assertion because driving the real shutdown
// needs a live daemon with a dataplane, a store and systemd units. That is the
// half a behavioural test cannot reach, and it is the half that regressed:
// nothing stopped a teardown being added above the fail-closed block, which is
// how it ended up ~90 lines below the telemetry joins.
func TestFailClosedShutdownActionsPrecedeBlockingTeardowns9035(t *testing.T) {
	const file = "daemon_run_shutdown.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	// Offsets of the calls that matter, inside the shutdown function only.
	type site struct {
		name string
		pos  token.Pos
	}
	var failClosed, blocking []site
	// Every teardown below is a JOIN or an external-process stop — each can
	// block, and each used to precede the fail-closed block.
	blockingNames := map[string]bool{
		"stopFlowExporter":  true,
		"stopIPFIXExporter": true,
		"teardownSNMP":      true,
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				switch fun.Sel.Name {
				case "SetRGActive":
					failClosed = append(failClosed, site{"SetRGActive(false)", call.Pos()})
				case "markDataplaneNotArmed":
					// #9686: the fail-closed stop closes kernel transit.
					failClosed = append(failClosed, site{"markDataplaneNotArmed()", call.Pos()})
				case "Shutdown":
					// d.dhcpServer.Shutdown() — the #6787 Kea stop.
					if id, ok := fun.X.(*ast.SelectorExpr); ok && id.Sel.Name == "dhcpServer" {
						failClosed = append(failClosed, site{"dhcpServer.Shutdown()", call.Pos()})
					}
				default:
					if blockingNames[fun.Sel.Name] {
						blocking = append(blocking, site{fun.Sel.Name + "()", call.Pos()})
					}
				}
			}
			return true
		})
	}

	// FIXTURE CHECKS FIRST. If either set is empty the ordering assertion below
	// is vacuously true, which would read as a clean board for a file this
	// cell never actually examined.
	if len(failClosed) != 3 {
		t.Fatalf("#9035: expected exactly 3 fail-closed call sites in %s "+
			"(markDataplaneNotArmed() since #9686, SetRGActive(false) and "+
			"dhcpServer.Shutdown()), found %d: %v. "+
			"Fix this guard's model of the shutdown before trusting its verdict.",
			file, len(failClosed), failClosed)
	}
	if len(blocking) == 0 {
		t.Fatalf("#9035: found NO blocking teardown call sites in %s. Either "+
			"they were renamed or this guard is looking in the wrong place; "+
			"either way it is asserting nothing.", file)
	}

	var lastFailClosed site
	for _, s := range failClosed {
		if s.pos > lastFailClosed.pos {
			lastFailClosed = s
		}
	}
	for _, b := range blocking {
		if b.pos < lastFailClosed.pos {
			t.Errorf("#9035: %s runs at %s, BEFORE the fail-closed action %s at %s.\n"+
				"Every fail-closed action must complete before any teardown that can "+
				"block, because systemd SIGKILLs at TimeoutStopSec wherever we are. "+
				"A telemetry drain that outlives the budget then leaves this node "+
				"forwarding and answering DHCP while the peer promotes onto the same "+
				"segment — duplicate OFFERs from two lease databases, the outcome "+
				"#6787 exists to prevent.",
				b.name, fset.Position(b.pos), lastFailClosed.name,
				fset.Position(lastFailClosed.pos))
		}
	}
}

// #9035: and the drain is bounded, so a wedged collector cannot spend the stop
// budget even though the ordering above means spending it is now survivable.
//
// Both halves are asserted because they fail differently: without the ordering
// a bounded drain still delays ownership release by its bound times however
// many exporters exist, and without the bound a single wedged generation still
// burns the remainder of the budget after the fail-closed actions.
func TestTelemetryJoinIsBounded9035(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	// A goroutine that never finishes — the wedged-collector shape, without
	// needing a collector: the join is what is under test, not the write.
	release := make(chan struct{})
	go func() {
		defer wg.Done()
		<-release
	}()
	defer close(release)

	start := time.Now()
	completed := joinWithBudget(&wg, "test")
	elapsed := time.Since(start)

	if completed {
		t.Fatal("#9035: joinWithBudget reported a COMPLETED join on a goroutine " +
			"that never finished; the bound is not being applied at all")
	}
	if elapsed > telemetryDrainBudget*2 {
		t.Errorf("#9035: the join took %s against a %s budget — it is not bounded",
			elapsed, telemetryDrainBudget)
	}
	// The budget must be a real wait, not an instant give-up: a bound of ~0
	// would pass the check above while dropping every healthy final flush.
	if elapsed < telemetryDrainBudget/2 {
		t.Errorf("#9035: the join gave up after %s, far short of the %s budget. "+
			"A drain that abandons immediately loses the final flush for HEALTHY "+
			"collectors too, which the bound exists to preserve.",
			elapsed, telemetryDrainBudget)
	}
}

// The control: a join that CAN complete must complete, and promptly. Without
// it, a joinWithBudget that always gave up would satisfy the bound cell above
// while never draining anything.
func TestTelemetryJoinCompletesWhenItCan9035(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done() }()

	start := time.Now()
	if !joinWithBudget(&wg, "test") {
		t.Fatal("#9035: joinWithBudget abandoned a join that had already finished")
	}
	if elapsed := time.Since(start); elapsed > telemetryDrainBudget/2 {
		t.Errorf("#9035: a completable join took %s; it must return as soon as the "+
			"WaitGroup is done, not sit out the budget", elapsed)
	}
	// nil is the never-started-exporter case and must be a no-op success.
	if !joinWithBudget(nil, "test") {
		t.Error("#9035: joinWithBudget(nil) must succeed — a never-started " +
			"exporter joins cleanly, as the pre-#9035 nil check did")
	}
}

// BIND THE WIRING, NOT THE FUNCTION (#9035).
//
// TestTelemetryJoinIsBounded9035 above exercises joinWithBudget directly, and
// on its own that is NOT coverage: restoring `d.flowWg.Wait()` at the call site
// left it GREEN, because the cell still reached the helper by another route.
// Scored as a mutation, that arm SURVIVED — a bounded helper nothing calls is
// the same as no bound.
//
// So the CALL SITES are bound here: both exporter teardowns must join through
// the budget, and neither may carry a bare Wait() on its generation
// WaitGroup. Driving the real teardown needs live exporters and sockets, so
// this is the half a behavioural test cannot reach — and it is the half the
// mutation showed was unguarded.
func TestExporterTeardownsJoinThroughTheBudget9035(t *testing.T) {
	const file = "daemon_flowexport.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	want := map[string]bool{"teardownV9Locked": true, "teardownIPFIXLocked": true}
	seen := map[string]bool{}
	budgeted := map[string]int{}
	bareWait := map[string][]string{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || !want[fn.Name.Name] {
			continue
		}
		seen[fn.Name.Name] = true
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "joinWithBudget" {
					budgeted[fn.Name.Name]++
				}
			case *ast.SelectorExpr:
				// d.flowWg.Wait() / d.ipfixWg.Wait() — the unbounded shape.
				if fun.Sel.Name != "Wait" {
					return true
				}
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					switch sel.Sel.Name {
					case "flowWg", "ipfixWg":
						bareWait[fn.Name.Name] = append(bareWait[fn.Name.Name], sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
	// Fixture first: a renamed teardown would make every assertion below
	// vacuous, which reads as a clean board for functions never examined.
	for name := range want {
		if !seen[name] {
			t.Fatalf("#9035: %s not found in %s — this guard's model of the "+
				"teardown is stale; fix it before trusting its verdict", name, file)
		}
	}
	for name := range want {
		if budgeted[name] == 0 {
			t.Errorf("#9035: %s does not join through joinWithBudget. An untimed "+
				"join on a serial, uncapped, 2s-per-collector drain is how eleven "+
				"blocked collectors reach 22s against a 20s TimeoutStopSec.", name)
		}
		if len(bareWait[name]) > 0 {
			t.Errorf("#9035: %s carries a bare Wait() on %v. The bound must be on "+
				"the join that actually runs at shutdown, not merely available "+
				"nearby — a bounded helper nothing calls is the same as no bound.",
				name, bareWait[name])
		}
	}
}
