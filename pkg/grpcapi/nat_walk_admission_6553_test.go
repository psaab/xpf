// #6553: the gRPC NAT surfaces drove full v4+v6 conntrack walks with NO
// sessionWalkLimiter admission and NO cancellation. The REST twin acquired
// that gate in #6216.
//
// Six surfaces, on two different listeners:
//
//	GetNATPoolStats                      loopback   countSNATSessions
//	GetNATDestination                    loopback   countDNATSessions (no REST twin at all)
//	ShowText{persistent-nat}             FABRIC     natshow.RenderPersistent
//	ShowText{persistent-nat-detail}      FABRIC     natshow.RenderPersistentDetail
//	ShowText{nat-source-rule-detail}     FABRIC     natshow.RenderSourceRuleDetail
//	ShowText{nat-dest-rule-detail}       FABRIC     natshow.RenderDestRuleDetail
//
// The shared-budget point is what makes an un-gated surface other surfaces'
// problem: REST and gRPC alias ONE diagcmd.SessionWalkLimiter, so a gRPC walk
// that neither draws a slot nor stops on client disconnect degrades the REST
// twin that does both.
//
// FAIL-ON-REVERT: remove an AcquireCtx/Acquire from any of the six and its
// case below stops returning ResourceExhausted. Remove the ctx sampling from
// countNATSessions and the cancellation test stops observing a short walk.
package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// natWalkDP is a grpcRuntime fake reporting a loaded dataplane with a session
// table of a configurable size, so a walk can be observed as well as admitted.
type natWalkDP struct {
	*dataplane.Manager
	rows    int
	visited *int
}

func (natWalkDP) IsLoaded() bool { return true }

func (d natWalkDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.rows; i++ {
		if d.visited != nil {
			*d.visited++
		}
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT}) {
			return nil
		}
	}
	return nil
}

func (d natWalkDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.rows; i++ {
		if d.visited != nil {
			*d.visited++
		}
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT}) {
			return nil
		}
	}
	return nil
}

// Sessions routes the store through THIS fake. Without it SessionStoreOf sees
// the embedded Manager's SessionStoreProvider and hands back a nil-backed
// store, so the walk silently iterates nothing — a fixture that would make the
// cancellation assertion vacuously green.
func (d natWalkDP) Sessions() dataplane.SessionStore {
	return natWalkStore{rows: d.rows, visited: d.visited}
}

// natWalkStore is the SessionStore half of the fake. The embedded interface
// supplies the methods this probe never calls; only the two walks are real.
type natWalkStore struct {
	dataplane.SessionStore
	rows    int
	visited *int
}

func (d natWalkStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < d.rows; i++ {
		if d.visited != nil {
			*d.visited++
		}
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT}) {
			return nil
		}
	}
	return nil
}

func (d natWalkStore) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i := 0; i < d.rows; i++ {
		if d.visited != nil {
			*d.visited++
		}
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT}) {
			return nil
		}
	}
	return nil
}

// newNATWalkStore seeds an ACTIVE config with both a source pool and a
// destination rule-set: GetNATPoolStats and GetNATDestination both return
// early on a nil / empty config, so an unseeded store would make every
// admission assertion below vacuous.
func newNATWalkStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(`set security zones security-zone trust
set security zones security-zone untrust
set security nat source pool p1 address 203.0.113.10/32
set security nat source rule-set rs from zone trust
set security nat source rule-set rs to zone untrust
set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8
set security nat source rule-set rs rule r1 then source-nat pool p1
set security nat destination pool dp1 address 10.0.0.5
set security nat destination rule-set drs from zone untrust
set security nat destination rule-set drs rule dr1 match destination-address 203.0.113.10/32
set security nat destination rule-set drs rule dr1 then destination-nat pool dp1`); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return store
}

func newNATWalkServer(t *testing.T, dp natWalkDP) *Server {
	t.Helper()
	if dp.Manager == nil {
		dp.Manager = dataplane.New()
	}
	return &Server{dp: dp, store: newNATWalkStore(t)}
}

// saturateSessionWalkLimiter installs a single-slot limiter and holds its only
// slot. Returns the release so both halves of the contract can be exercised.
func saturateSessionWalkLimiter(t *testing.T) func() {
	t.Helper()
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only session-walk slot: %v", err)
	}
	return release
}

// TestGRPCNATWalkSurfacesAcquireTheSharedLimiter6553 covers the five surfaces
// that genuinely walk the conntrack table.
//
// #8151 removed `persistent-nat` from this list — not because the assertion
// got inconvenient, but because it was asserting the wrong thing. That topic
// copies an in-process map and never touches a conntrack bucket, so charging
// it to the session budget let a fabric peer starve real scans. It now takes
// diagcmd.SnapshotReadLimiter and is covered by
// TestPersistentNATUsesTheSnapshotBudget8151 below, which asserts BOTH
// directions of the independence.
// Each is driven twice: refused while the shared budget is saturated, admitted
// once a slot frees. The second half is not decoration — it is what catches a
// gate that acquires and never releases.
func TestGRPCNATWalkSurfacesAcquireTheSharedLimiter6553(t *testing.T) {
	surfaces := []struct {
		name string
		call func(*Server) error
	}{
		{"GetNATPoolStats", func(s *Server) error {
			_, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
			return err
		}},
		{"GetNATDestination", func(s *Server) error {
			_, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
			return err
		}},
		{"ShowText/persistent-nat-detail", func(s *Server) error {
			_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "persistent-nat-detail"})
			return err
		}},
		{"ShowText/nat-source-rule-detail", func(s *Server) error {
			_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "nat-source-rule-detail"})
			return err
		}},
		{"ShowText/nat-dest-rule-detail", func(s *Server) error {
			_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "nat-dest-rule-detail"})
			return err
		}},
	}

	for _, sf := range surfaces {
		t.Run(sf.name, func(t *testing.T) {
			release := saturateSessionWalkLimiter(t)
			s := newNATWalkServer(t, natWalkDP{rows: 4})

			if err := sf.call(s); !isResourceExhausted(err) {
				release()
				t.Fatalf("%s with a saturated session-walk limiter: err = %v, want "+
					"codes.ResourceExhausted — it drove an unadmitted full-table walk",
					sf.name, err)
			}
			release()
			if err := sf.call(s); isResourceExhausted(err) {
				t.Fatalf("%s still ResourceExhausted after the slot was released: %v "+
					"(the gate is leaking slots — release must run on every path)", sf.name, err)
			}
		})
	}
}

// TestNATPoolStatsWithoutDataplaneIsNotGated6553 is the negative control, and
// it is what keeps the gate in the right place. Acquiring at the top of the
// HANDLER rather than inside the dataplane-loaded branch would satisfy the
// test above while refusing a pure config read that walks nothing. A server
// whose dataplane is not loaded must answer normally even with the budget
// fully saturated.
func TestNATPoolStatsWithoutDataplaneIsNotGated6553(t *testing.T) {
	release := saturateSessionWalkLimiter(t)
	defer release()

	// dataplane.New() alone reports IsLoaded()==false (no natWalkDP override).
	s := &Server{dp: dataplane.New(), store: newNATWalkStore(t)}

	if _, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{}); isResourceExhausted(err) {
		t.Fatalf("GetNATPoolStats with no dataplane loaded was refused by the walk "+
			"limiter: %v — it walks nothing, so the gate is being taken at the "+
			"handler rather than at the walk", err)
	}
	if _, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{}); isResourceExhausted(err) {
		t.Fatalf("GetNATDestination with no dataplane loaded was refused: %v", err)
	}
}

// TestNATWalkStopsOnCancelledLease6553 binds the CANCELLATION half separately
// from the admission half, because they fail independently: a handler can
// acquire a slot correctly and still run the walk to completion after the
// client is gone, holding that slot against the surfaces queueing for it.
//
// The probe cancels the context before the walk and requires the callback to
// stop within one row per family. Counting VISITS rather than asserting the
// returned total is deliberate — the total is also 0 when the walk never ran,
// so a visit count discriminates "stopped early" from "did not start".
func TestNATWalkStopsOnCancelledLease6553(t *testing.T) {
	const rows = 500
	visited := 0
	s := newNATWalkServer(t, natWalkDP{rows: rows, visited: &visited})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	counts := s.countSNATSessions(ctx, nil)

	// One offered row per family before the guard trips: the callback samples
	// ctx on entry, so the iterator hands over row 0 of v4 and row 0 of v6.
	if visited > 2 {
		t.Errorf("cancelled walk visited %d of %d rows (v4+v6) — countNATSessions "+
			"is not sampling ctx.Err() inside the callbacks, so a disconnected "+
			"client's walk runs to completion holding a shared limiter slot", visited, 2*rows)
	}
	if visited == 0 {
		t.Fatal("the walk never started, so this proves nothing about cancellation — " +
			"check the fake dataplane still reports IsLoaded()")
	}
	if counts.total != 0 {
		t.Errorf("cancelled walk tallied %d sessions, want 0 (every row was refused)", counts.total)
	}

	// Control: the SAME fixture with a live context must walk everything, so
	// the assertion above is about cancellation and not about a broken fake.
	visited = 0
	counts = s.countSNATSessions(context.Background(), nil)
	if visited != 2*rows {
		t.Errorf("live walk visited %d rows, want %d — the fixture is not iterating", visited, 2*rows)
	}
	if counts.total != int64(2*rows) {
		t.Errorf("live walk tallied %d, want %d", counts.total, 2*rows)
	}
}

// TestSessionWalkLimiterIsTheSharedInstance6553 restates the premise the whole
// issue rests on: the budget is process-wide. If the gRPC alias ever stopped
// pointing at diagcmd.SessionWalkLimiter, every acquisition above would still
// pass while the two surfaces silently stopped aggregating.
func TestSessionWalkLimiterIsTheSharedInstance6553(t *testing.T) {
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Fatal("gRPC sessionWalkLimiter is not the shared diagcmd.SessionWalkLimiter " +
			"instance; REST+gRPC walk budgets are no longer aggregated")
	}
}

// TestNATPoolTotalPortsIsSingleSourced6553 pins the formula centralisation.
// The (portHigh-portLow+1)*addrCount expression had been written out five
// times and had already diverged — only REST carried the portHigh >= portLow
// guard. This asserts no non-test file re-inlines it.
func TestNATPoolTotalPortsIsSingleSourced6553(t *testing.T) {
	t.Parallel()

	// The literal shape every divergent copy shared.
	const inlined = "(portHigh - portLow + 1)"
	roots := []string{"../grpcapi", "../api", "../cli", "../natshow"}
	for _, root := range roots {
		ents, err := readGoFiles(root)
		if err != nil {
			t.Fatalf("scan %s: %v", root, err)
		}
		if len(ents) == 0 {
			t.Fatalf("scanned no non-test .go files under %s — a green here is vacuous", root)
		}
		for name, src := range ents {
			if strings.Contains(src, inlined) {
				t.Errorf("%s/%s re-inlines the NAT pool port formula %q — use "+
					"config.NATPoolTotalPorts so the portHigh >= portLow guard "+
					"cannot diverge across surfaces again (#6553)", root, name, inlined)
			}
		}
	}
}

// #8151: `persistent-nat` must draw from the snapshot budget, and the two
// budgets must be INDEPENDENT.
//
// These cells saturate the REAL limiters rather than substituting fresh
// single-slot ones, and that is the whole design of the test. A mutation
// aliasing `SnapshotReadLimiter = SessionWalkLimiter` ESCAPED the first
// version, because each helper swapped in its own new instance — the
// substitution destroyed the aliasing before the assertion could observe it.
// The test was structurally incapable of failing for the reason it existed.
//
// Draining the real limiters means the counts must match the real caps, so
// both are read from diagcmd rather than hardcoded; if a cap changes, the
// drain follows it instead of silently under-filling and admitting on a free
// slot.
func drainLimiter(t *testing.T, l *diagcmd.Limiter, n int) func() {
	t.Helper()
	releases := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		release, err := l.Acquire()
		if err != nil {
			t.Fatalf("could not drain slot %d of %d: %v", i+1, n, err)
		}
		releases = append(releases, release)
	}
	if l.InFlight() != n {
		t.Fatalf("drained %d slots but InFlight()=%d — the limiter is not saturated "+
			"and the assertion below would pass on a free slot", n, l.InFlight())
	}
	return func() {
		for _, r := range releases {
			r()
		}
	}
}

func TestPersistentNATUsesTheSnapshotBudget8151(t *testing.T) {
	persistentNAT := func(s *Server) error {
		_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "persistent-nat"})
		return err
	}
	// A genuine session-walk surface, standing for "the scans that were being
	// starved". GetNATPoolStats takes the session budget.
	sessionWalk := func(s *Server) error {
		_, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
		return err
	}

	t.Run("persistent-nat is bounded by the snapshot budget", func(t *testing.T) {
		s := newNATWalkServer(t, natWalkDP{})
		undo := drainLimiter(t, diagcmd.SnapshotReadLimiter, diagcmd.MaxConcurrentSnapshotReads)
		if err := persistentNAT(s); err == nil {
			undo()
			t.Fatal("persistent-nat was admitted with the snapshot budget saturated — " +
				"the bound was dropped rather than moved (#8151 keeps it: ShowText is " +
				"fabric-reachable and the O(bindings) copy is still worth bounding)")
		}
		undo()
		if err := persistentNAT(s); err != nil {
			t.Fatalf("persistent-nat still refused after the slots freed: %v — the gate "+
				"acquires and never releases", err)
		}
	})

	t.Run("a saturated snapshot budget does not refuse a session walk", func(t *testing.T) {
		s := newNATWalkServer(t, natWalkDP{rows: 4})
		defer drainLimiter(t, diagcmd.SnapshotReadLimiter, diagcmd.MaxConcurrentSnapshotReads)()
		if err := sessionWalk(s); err != nil {
			t.Fatalf("a session walk was refused while only the SNAPSHOT budget was "+
				"saturated: %v — the two budgets are the same instance", err)
		}
	})

	t.Run("a saturated session budget does not refuse persistent-nat", func(t *testing.T) {
		s := newNATWalkServer(t, natWalkDP{})
		defer drainLimiter(t, diagcmd.SessionWalkLimiter, diagcmd.MaxConcurrentSessionWalks)()
		if err := persistentNAT(s); err != nil {
			t.Fatalf("persistent-nat was refused while only the SESSION budget was "+
				"saturated: %v — this is the starvation #8151 fixes, in the direction "+
				"a fabric peer polling the session surfaces would cause", err)
		}
	})
}
