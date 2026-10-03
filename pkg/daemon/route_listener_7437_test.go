package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/coalesce"
	"github.com/psaab/xpf/pkg/routing"
)

// #7437: the listener's decision predicate.
//
// The netlink subscription loop itself is not unit-testable here — the sibling
// neighbour listener's tests cover its predicates and leave the subscription
// to the cluster smoke, and this follows that split deliberately. What IS
// testable is the two properties a bug would actually live in:
//
//   1. which route events warrant a refresh, and
//   2. that the imported-table set is the IMPORTER's, not a second copy.
//
// The rate property — the one the acceptance criteria call out — is asserted
// in pkg/coalesce against an injected clock, which is where it belongs: it is
// a property of the coalescing loop, not of this predicate.

func TestRouteEventWarrantsRefreshOnlyForImportedTables7437(t *testing.T) {
	imported := routing.LearnedRouteTableIDs([]int{100, 200})

	for _, tc := range []struct {
		name    string
		tableID int
		want    bool
	}{
		{"main table", 254, true},
		{"an imported routing-instance table", 100, true},
		{"another imported instance table", 200, true},
		// The control that keeps the predicate meaningful: a table the
		// importer does NOT read must not drive a publish. Without it, a
		// predicate returning true unconditionally satisfies every case above
		// — and burns a full snapshot replace on every unrelated route event,
		// which is the control-socket brownout this design exists to avoid.
		{"an unimported table", 300, false},
		{"the management VRF table, excluded by the importer", 42, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeEventWarrantsRefresh(tc.tableID, imported); got != tc.want {
				t.Errorf("routeEventWarrantsRefresh(%d) = %v, want %v", tc.tableID, got, tc.want)
			}
		})
	}
}

// TestImportedTableSetComesFromTheImporter7437 binds the predicate's input to
// routing.LearnedRouteTableIDs rather than to a list maintained here.
//
// A second copy of "which tables do we import" can disagree with the importer:
// marking for a table it ignores burns publishes, and skipping one it reads
// leaves exactly the staleness window this issue is about. The agreement is
// asserted, not the literal — pinning a table list here would encode which
// side we trust.
func TestImportedTableSetComesFromTheImporter7437(t *testing.T) {
	instance := []int{100, 200}
	want := routing.LearnedRouteTableIDs(instance)

	// Every table the importer reads must warrant a refresh...
	for _, id := range want {
		if !routeEventWarrantsRefresh(id, want) {
			t.Errorf("the importer reads table %d but the listener ignores it; routes "+
				"learned there never reach the helper FIB", id)
		}
	}
	// ...and the set must be non-trivial, or the loop above proves nothing.
	if len(want) < 2 {
		t.Fatalf("LearnedRouteTableIDs(%v) returned %v; the fixture must produce more "+
			"than the main table or the agreement above is vacuous", instance, want)
	}
}

func TestKeepaliveLivenessMarkBeforeRouteListenerStartup11423(t *testing.T) {
	d := &Daemon{}
	d.markRouteListenerImmediately()

	var actuations int
	loop := coalesce.New(func(context.Context) bool {
		actuations++
		return true
	})
	loop.SetTimings(0, 0)
	d.setRouteListenerLoop(loop)
	loop.Tick(context.Background())

	if actuations != 1 {
		t.Fatalf("startup loop actuations = %d, want one for the pending liveness change", actuations)
	}
	if d.routeListenerPending.Load() {
		t.Fatal("route listener startup did not consume the pending liveness mark")
	}
}
