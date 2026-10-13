package grpcapi

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Codex PR #6743 r7-F3, RE-KEYED in r4-F1: the buffer renders must take
// exactly ONE load of the #2114 cell.
//
// Before r7 they took three — dataplane.Published(s.dp) (a predicate that
// no longer exists; it was `Unwrap(p) != nil` and was deleted in r2-B6),
// then s.dpProbe(), then s.dp.GetMapStats() — each an independent load. A
// setDataplane(nil) landing between them re-created the exact confusion
// that check existed to prevent: the publication check passed against a
// live backend, the later loads resolved nil, and the render printed "No
// BPF maps available" — a statement about a LOADED backend's maps — for a
// daemon that no longer had a backend at all.
//
// WHY THIS GUARD WAS RE-KEYED. The r7 version counted Unwrap CALLS and
// asserted the count was 1. That is a proxy: the property is how many
// times the render loads the cell, and not every load is an Unwrap. The
// old oneShotIndirection embedded *dataplane.Manager and declared only
// Unwrap, so `s.dp.SessionCount()` — which under the real liveDataPlane
// calls resolve(), an independent load — was served by the embedded
// Manager and never touched the counter. The guard therefore stayed green
// across a residual second load that lived in the very arm its own fixture
// drove (mapStatsBackend has no Status(), so the map-stats arm is the one
// exercised). Measured at 6163445e9: reverting BOTH userspace-arm
// conversions left ./pkg/grpcapi/... ./pkg/cli/... ./pkg/api/...
// ./pkg/dataplane/... AND ./pkg/daemon/... at rc=0 — a complete survivor.
//
// The fixture below is keyed on the property instead. Its reach is TOTAL
// over grpcRuntime's method set, and that is a property of how it is built
// rather than of how many methods it happens to declare:
//
//   - the three methods declared below (Unwrap, SessionCount, GetMapStats)
//     each perform their OWN counted cell load, exactly as liveDataPlane
//     does — Unwrap reads d.dataplane(); resolve() reads it again;
//   - EVERY OTHER method PANICS, because the embedded grpcRuntime is a nil
//     interface. Method promotion dispatches every undeclared method
//     through that one field, so none of them can quietly answer.
//
// There is therefore no method on this value that reaches the backend
// without the counter seeing it. That is the r4 correction: r4 embedded a
// concrete *dataplane.Manager, which SERVED all the rest — closing 2 of 25
// while the header claimed all of them. Measured at 44603f888: inserting
// `if !s.dp.IsLoaded() { buf.WriteString("stale\n") }` into showBuffers'
// map-stats arm — a real second cell load — left loads=1, all four
// subtests PASS, pkg/grpcapi rc=0.
//
// The undeclared-method count is NOT written down here, deliberately. Two
// rounds carried a hand-typed "22" against a 25-method interface with 2
// methods shadowed, which is 23 — a quantifier re-typed over a population
// nobody had counted, in a header whose whole subject is quantifiers.
// TestShowBuffersCountingIndirectionServesNothingSilently now derives both
// the population and the partition from the interface TYPE by reflection,
// so the claim is checked at every run instead of restated in prose.
//
// A render that takes a second load through a DECLARED method both bumps
// the counter AND observably tears, because the cell is empty from load 2
// onward. That is deterministic, not a race: a cell that holds a backend
// at load 1 and nothing afterwards is the observable consequence of a
// concurrent setDataplane(nil) with the timing removed.

const (
	// The published backend's session counts. Non-zero on BOTH families so
	// the render's `if v4 > 0 || v6 > 0` gate opens: a second load resolves
	// nil, yields (0,0), and the "Active sessions" line vanishes. A zero
	// count here would suppress the line either way and make the output
	// assertion vacuous — which is what the r7 fixture did.
	singleLoadV4 = 7
	singleLoadV6 = 3
)

// singleLoadActiveSessions is the operator-visible consequence of taking
// exactly one load. Under two loads this line is silently absent.
const singleLoadActiveSessions = "Active sessions: 7 IPv4, 3 IPv6, 10 total"

// countingIndirection is a live indirection modelled on pkg/daemon's
// liveDataPlane: a backend-reaching method performs its OWN cell load, and
// the cell is empty from the second load onward.
//
// The embedded grpcRuntime is a nil INTERFACE, never a concrete value. It
// is what makes this value assignable to Server.dp — the promoted method
// set is grpcRuntime's, so *countingIndirection satisfies the field — and
// it is simultaneously what makes the counter's reach total: the three
// methods below shadow their promoted counterparts, and every OTHER
// promoted method dispatches through a nil interface and panics at the
// production call site that took it.
//
// Do NOT restore the r4 `*dataplane.Manager` embed, and do not populate
// this field at a construction site either — r6 measured that spelling as
// the live escape. A non-nil embed satisfies the same field while SERVING
// every undeclared method, so a render that reached the backend through
// any of them took a cell load this fixture could not see, and the counter
// stayed at 1. A loud panic naming the production line is the intended
// answer; a silent zero is the bug. load() refuses a populated embed and
// TestShowBuffersCountingIndirectionServesNothingSilently proves that
// refusal fires.
type countingIndirection struct {
	grpcRuntime
	backend any
	loads   atomic.Int32
}

// load is the single counted cell read. Every forwarder goes through it,
// which is what makes the count a count of LOADS rather than of Unwraps.
//
// #6743 r6-B1: it is ALSO where the nil-embed invariant is enforced, and
// enforcing it here rather than in a test is the whole point. r5 asserted
// the invariant inside TestShowBuffersCountingIndirectionServesNothingSilently
// — on a value that test constructed itself, with the embed omitted from
// the composite literal, so the clause was a tautology over the zero value
// of an interface field. The value that matters is the one the GRID stores
// in Server.dp, and nothing looked at that one. Measured at 74ece3ff5:
// changing the grid literal to `&countingIndirection{grpcRuntime:
// dataplane.New(), backend: arm.backend()}` and re-inserting the r4
// witness (`if !s.dp.IsLoaded()`) into both map-stats arms left all four
// grid subtests PASSING, the ServesNothingSilently guard PASSING, and
// `go test ./pkg/grpcapi/ -count=1` at rc=0 on the full package.
//
// load() is the choke point every counted method already goes through, so
// a check here holds for EVERY instance a render actually touches — the
// grid's, the empty-cell control's, and any built later — without
// enumerating the construction sites. A construction site can be added or
// respelled; it cannot avoid this function and still be a fixture whose
// loads are counted.
func (o *countingIndirection) load() any {
	if o.grpcRuntime != nil {
		panic("countingIndirection: the embedded grpcRuntime is NON-NIL, so the methods " +
			"this fixture does not declare are SERVED rather than promoted through a nil " +
			"interface. A render reaching the backend through one of them takes a cell load " +
			"the counter cannot see, and the grid stays green at loads=1 — that is exactly " +
			"how the r4 *dataplane.Manager embed closed 2 of 25 methods while claiming all " +
			"of them. Build this fixture with the embed left nil.")
	}
	if o.loads.Add(1) == 1 {
		return o.backend
	}
	return nil
}

func (o *countingIndirection) Unwrap() any { return o.load() }

// SessionCount mirrors liveDataPlane.SessionCount, which resolves the cell
// itself. This is the method the r7 guard could not see.
func (o *countingIndirection) SessionCount() (int, int) {
	c, ok := o.load().(interface{ SessionCount() (int, int) })
	if !ok {
		return 0, 0
	}
	return c.SessionCount()
}

// GetMapStats mirrors liveDataPlane.GetMapStats for the same reason.
func (o *countingIndirection) GetMapStats() []dataplane.MapStats {
	m, ok := o.load().(interface{ GetMapStats() []dataplane.MapStats })
	if !ok {
		return nil
	}
	return m.GetMapStats()
}

// The Unwrap contract is NOT compile-checked anywhere else: the render
// reaches it through dataplane.Unwrap's runtime type assertion, so a
// rename would surface as a silent "not loaded" render rather than as a
// build error.
//
// #6743 r6-B4: the sibling `_ grpcRuntime = (*countingIndirection)(nil)`
// assertion that stood here was deleted. It could not fail on its own —
// the grid stores the fixture in Server.dp, which is typed grpcRuntime, so
// the compiler already made exactly that check at a site the tests
// actually exercise.
var _ dataplane.LiveUnwrapper = (*countingIndirection)(nil)

// mapStatsBackend drives the MAP-STATS arm: no userspace Status() probe,
// and a non-empty map list so "No BPF maps available" can only mean the
// render lost the backend.
type mapStatsBackend struct {
	*dataplane.Manager
}

func (*mapStatsBackend) IsLoaded() bool { return true }

func (*mapStatsBackend) SessionCount() (int, int) {
	return singleLoadV4, singleLoadV6
}

func (*mapStatsBackend) SessionCountContext(context.Context) (int, int, error) {
	return singleLoadV4, singleLoadV6, nil
}

func (*mapStatsBackend) GetMapStats() []dataplane.MapStats {
	return []dataplane.MapStats{{
		Name:       "sessions_v4",
		Type:       "Hash",
		MaxEntries: 1024,
		UsedCount:  4,
	}}
}

// userspaceArmBackend drives the USERSPACE arm — the arm this PR's own
// diff converted. Without a row here the conversion is unbound: a reviewer
// measured both userspace-arm reverts as complete survivors precisely
// because the shipped fixture never entered this arm.
type userspaceArmBackend struct {
	*dataplane.Manager
}

func (*userspaceArmBackend) IsLoaded() bool { return true }

func (*userspaceArmBackend) SessionCount() (int, int) {
	return singleLoadV4, singleLoadV6
}

func (*userspaceArmBackend) SessionCountContext(context.Context) (int, int, error) {
	return singleLoadV4, singleLoadV6, nil
}
func (*userspaceArmBackend) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{
		SessionTableEntries: 9,
		MaxSessions:         10,
		NeighborEntries:     6,
		PerBinding: []dpuserspace.BindingCountersSnapshot{{
			UmemTotalFrames:    1000,
			UmemInflightFrames: 800,
			TxRingCapacity:     100,
			OutstandingTX:      90,
			ActiveFlowCount:    4,
			FlowCacheCapacity:  10,
		}},
	}, nil
}

// singleLoadArms are the two capability shapes the renders branch on. Both
// must take one load; the arm names below appear in every failure message
// so a red says WHICH branch tore.
var singleLoadArms = []struct {
	name    string
	backend func() any
	// wantMarker is a string unique to this arm's body, so a green cannot
	// come from the render having silently taken the other branch.
	wantMarker string
}{
	{
		name:       "mapStatsArm",
		backend:    func() any { return &mapStatsBackend{Manager: dataplane.New()} },
		wantMarker: "sessions_v4",
	},
	{
		name:       "userspaceArm",
		backend:    func() any { return &userspaceArmBackend{Manager: dataplane.New()} },
		wantMarker: "Userspace Buffer Utilization:",
	},
}

var singleLoadRenders = []struct {
	name   string
	render func(*Server, *config.Config, *strings.Builder) error
}{
	{"showBuffers", (*Server).showBuffers},
	{"showBuffersDetail", (*Server).showBuffersDetail},
}

// TestShowBuffersTakesOneCellLoad is the fail-on-revert guard, over the
// full render x arm grid.
//
// FAIL-ON-REVERT, per arm:
//
//   - map-stats arm: resolve the backend once, then perform the session
//     count against that backend. A second indirection load resolves the
//     emptied cell and drops the "Active sessions" line, flipping the
//     load-count and marker assertions red.
//   - userspace arm: the same substitution inside the
//     `if provider, ok := backend.(userspaceStatusProvider)` branch, which
//     is the line this PR's diff created. Same two REDs.
//
// A three-load revert (a publication check that resolves the cell itself,
// then dpProbe(), then GetMapStats()) reds on the arm marker as well: the
// map arm falls to "No BPF maps available", which the explicit check below
// names.
func TestShowBuffersTakesOneCellLoad(t *testing.T) {
	for _, render := range singleLoadRenders {
		for _, arm := range singleLoadArms {
			t.Run(render.name+"/"+arm.name, func(t *testing.T) {
				dp := &countingIndirection{backend: arm.backend()}
				s := &Server{
					dp:    dp,
					store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
				}

				var buf strings.Builder
				if err := render.render(s, &config.Config{}, &buf); err != nil {
					t.Fatalf("%s/%s: %v", render.name, arm.name, err)
				}
				out := buf.String()

				if strings.Contains(out, "No BPF maps available") {
					t.Fatalf("%s/%s reported \"No BPF maps available\" after taking more "+
						"than one cell load (loads=%d): the render must take ONE load and "+
						"describe that instant.\n%s",
						render.name, arm.name, dp.loads.Load(), out)
				}
				if !strings.Contains(out, arm.wantMarker) {
					t.Fatalf("%s/%s did not render the published backend's %s body "+
						"(loads=%d); missing %q\n%s",
						render.name, arm.name, arm.name, dp.loads.Load(), arm.wantMarker, out)
				}

				// The operator-visible consequence. A second load resolves
				// the emptied cell, SessionCount yields (0,0), and the
				// render's `if v4 > 0 || v6 > 0` gate silently drops this
				// line: one render describing two instants, reported as
				// though the firewall simply had no sessions.
				if !strings.Contains(out, singleLoadActiveSessions) {
					t.Fatalf("%s/%s dropped the session-count line (loads=%d): want %q. "+
						"The tail must use the already-resolved backend for its cancellable "+
						"count rather than resolving s.dp again and reporting (0,0).\n%s",
						render.name, arm.name, dp.loads.Load(), singleLoadActiveSessions, out)
				}

				// The property itself.
				if got := dp.loads.Load(); got != 1 {
					t.Fatalf("%s/%s loaded the cell %d times, want exactly 1",
						render.name, arm.name, got)
				}
			})
		}
	}
}

// TestShowBuffersCountingIndirectionErasesCapabilities is fixture fidelity.
//
// countingIndirection must NOT itself satisfy userspaceStatusProvider, or
// the userspace-arm row above would pass without any unwrap at all and the
// grid would be vacuous in the arm this PR changed.
func TestShowBuffersCountingIndirectionErasesCapabilities(t *testing.T) {
	dp := &countingIndirection{backend: &userspaceArmBackend{Manager: dataplane.New()}}
	if _, ok := any(dp).(userspaceStatusProvider); ok {
		t.Fatal("fixture drift: countingIndirection implements userspaceStatusProvider " +
			"directly, so the userspace-arm rows no longer exercise a resolution")
	}
	if dp.loads.Load() != 0 {
		t.Fatalf("fixture drift: constructing countingIndirection loaded the cell %d times, want 0",
			dp.loads.Load())
	}
}

// partitionRuntimeMethods calls EVERY method of interface type iface on dp
// with zero-value arguments and reports which answered and which panicked.
//
// #6743 r6-B1: this is what turns "the counter's reach is total" from a
// sentence into a measurement. The population comes from the interface
// TYPE — reflect reads the method set out of the source — so the claim
// cannot drift from a number typed into a comment, and it covers every
// method rather than the one a reviewer happened to name.
//
// Zero-value arguments are safe on the correct fixture: dispatch through a
// nil embedded interface panics BEFORE any callee runs, so no argument is
// ever examined. It is deliberately NOT used on a fixture with a populated
// embed for anything but IsLoaded() — there the calls would reach a real
// backend.
func partitionRuntimeMethods(t *testing.T, dp any, iface reflect.Type) (served, panicked []string) {
	t.Helper()

	v := reflect.ValueOf(dp)
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		m := v.MethodByName(name)
		if !m.IsValid() {
			t.Fatalf("fixture drift: %T has no method %s, so it no longer satisfies the "+
				"runtime interface this guard quantifies over", dp, name)
		}
		args := make([]reflect.Value, m.Type().NumIn())
		for j := range args {
			args[j] = reflect.New(m.Type().In(j)).Elem()
		}
		func() {
			defer func() {
				if recover() != nil {
					panicked = append(panicked, name)
				}
			}()
			m.Call(args)
			served = append(served, name)
		}()
	}
	sort.Strings(served)
	sort.Strings(panicked)
	return served, panicked
}

// countingIndirectionShadows are the grpcRuntime methods countingIndirection
// DECLARES, and so answers itself with a counted load. Every other method
// of the interface must be unanswerable.
var countingIndirectionShadows = []string{"GetMapStats", "SessionCount"}

// TestShowBuffersCountingIndirectionServesNothingSilently is what makes
// the grid's claim a UNIVERSAL over grpcRuntime's whole method set rather
// than a statement about the 3 this fixture declares.
//
// r4 embedded a concrete *dataplane.Manager. That satisfies Server.dp
// identically, and it ALSO answers every method the fixture does not
// declare — so a render reaching the backend through any of them took a
// cell load the counter could not see, and the grid stayed green at
// loads=1. The r4 fixture closed 2 of 25 while its header said EVERY.
//
// #6743 r6-B1 — what changed, and why the r5 shape was worth nothing:
//
//   - r5's structural clause read `dp.grpcRuntime != nil` on a fixture
//     THIS TEST built with the embed omitted from the literal. That is the
//     zero value of an interface field: nil, unconditionally. The clause
//     was a tautology over the only value it inspected, and the value that
//     mattered — the one the grid stores in Server.dp — was never looked
//     at. Measured at 74ece3ff5, populating the grid's literal restored
//     the r4 second-load defect verbatim with every guard green and
//     pkg/grpcapi at rc=0.
//   - The invariant now lives in load(), the choke point every counted
//     method goes through, so it holds for every instance a render
//     touches, at every construction site, present or future.
//   - r5's behavioural clause sampled ONE method (IsLoaded). This one
//     partitions the ENTIRE interface method set, read from the type by
//     reflection, and asserts the partition is exactly {declared} /
//     {everything else}. A method added to grpcRuntime joins the
//     population automatically; a third shadow method added here without
//     updating countingIndirectionShadows reds by name.
//
// The POSITIVE CONTROL below is the part that makes the whole thing more
// than a green: it builds the defective fixture on purpose and proves both
// halves of the mechanism — that a populated embed really does SERVE an
// undeclared method silently, and that load() really does refuse it.
func TestShowBuffersCountingIndirectionServesNothingSilently(t *testing.T) {
	iface := reflect.TypeOf((*grpcRuntime)(nil)).Elem()

	served, panicked := partitionRuntimeMethods(t,
		&countingIndirection{backend: &mapStatsBackend{Manager: dataplane.New()}}, iface)

	if !reflect.DeepEqual(served, countingIndirectionShadows) {
		t.Fatalf("methods answered by countingIndirection = %v, want exactly %v.\n"+
			"Anything else answering means an undeclared method is SERVED rather than "+
			"promoted through a nil interface, so a render could reach the backend through "+
			"it and take a cell load the counter cannot see — the r4 defect. Anything "+
			"MISSING means a declared forwarder started panicking.\npanicked: %v",
			served, countingIndirectionShadows, panicked)
	}
	if want := iface.NumMethod() - len(countingIndirectionShadows); len(panicked) != want {
		t.Fatalf("%d of grpcRuntime's %d methods panicked, want %d: the counter's reach is "+
			"total only if every method this fixture does not declare is unanswerable\n%v",
			len(panicked), iface.NumMethod(), want, panicked)
	}

	// POSITIVE CONTROL. A populated embed is the r4/r6 defect; both halves
	// of what this guard asserts about it must be observable, or the
	// assertions above are green for reasons nobody has checked.
	defective := &countingIndirection{
		grpcRuntime: dataplane.New(),
		backend:     &mapStatsBackend{Manager: dataplane.New()},
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("control: IsLoaded() on a POPULATED embed panicked (%v); the "+
					"defect this guard exists to catch is that the embed answers "+
					"SILENTLY, so if it cannot answer, the guard is passing for the "+
					"wrong reason", r)
			}
		}()
		_ = defective.IsLoaded()
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("control: load() accepted a fixture with a POPULATED embed. The " +
					"invariant is not enforced at the choke point, so a grid that builds " +
					"its fixture that way counts one load while the render takes two — " +
					"which is the escape measured at 74ece3ff5")
			}
		}()
		_ = defective.Unwrap()
	}()
	// A refusal that counts first is not a refusal: moving the guard below
	// loads.Add(1) would leave the panic in place — so the clause above
	// still passes — while polluting the very number the grid asserts on.
	if got := defective.loads.Load(); got != 0 {
		t.Fatalf("control: the refused load still bumped the counter to %d, want 0: the "+
			"embed check must run BEFORE loads.Add(1)", got)
	}
}

// TestShowBuffersEmptyCellSaysNotLoaded is the negative control: with NO
// backend at all the render must still say "Dataplane not loaded", so the
// grid above cannot pass merely because the "No BPF maps available" string
// was deleted.
func TestShowBuffersEmptyCellSaysNotLoaded(t *testing.T) {
	dp := &countingIndirection{backend: nil}
	s := &Server{
		dp:    dp,
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	var buf strings.Builder
	if err := s.showBuffers(&config.Config{}, &buf); err != nil {
		t.Fatalf("showBuffers: %v", err)
	}
	if !strings.Contains(buf.String(), "Dataplane not loaded") {
		t.Fatalf("empty cell must render \"Dataplane not loaded\", got:\n%s", buf.String())
	}
}
