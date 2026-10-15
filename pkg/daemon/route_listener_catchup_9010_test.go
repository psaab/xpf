package daemon

import (
	"context"
	"testing"
)

// #9010: a gap between route subscriptions is invisible to the update stream.
//
// The subscription is opened with ListExisting:false, so a NEW subscription
// replays nothing. Every route that changed while there was no subscription is
// therefore lost to `updates` permanently, and the outer loop's resubscribe
// closes the socket gap without closing the DATA gap.
//
// WHY #8915 DOES NOT COVER THIS. That fix marks from the ErrorCallback, which
// exists only for a fault during a LIVE subscription. A subscribe that FAILS
// never installs a callback at all -- the 2-second retry path marks nothing --
// and a subscription that simply ends returns before any error is raised.
//
// AND THE MARK IS READ TO MAKE A DECISION, which is what makes a missing one a
// defect rather than a cosmetic omission: the coalescer actuates only when
// dirty. #8915 measured 0 actuations across 50 sweeps with no mark, 1 after a
// single mark. There is no periodic floor to fall back on -- that alternative
// was considered and deliberately declined on #8915.
//
// This drives the function PRODUCTION calls (`routeListenerCatchUp`), not a
// re-implementation, for the same reason the #8915 cell drives
// `routeListenerErrorCallback`.
func TestSubscriptionReestablishmentForcesAFibRefresh9010(t *testing.T) {
	d := &Daemon{}
	var actuations int
	loop, advance := newTestLoop8915(&actuations)
	ctx := context.Background()

	// NON-VACUITY: nothing has marked, so a sweep must not actuate. Without
	// this the assertion below would pass against a loop that actuates freely.
	advance()
	loop.Tick(ctx)
	if actuations != 0 {
		t.Fatalf("NON-VACUITY: %d actuation(s) before any catch-up mark", actuations)
	}

	d.routeListenerCatchUp(loop)

	advance()
	loop.Tick(ctx)
	if actuations != 1 {
		t.Errorf("re-establishing a route subscription produced %d actuations, want 1. "+
			"A new subscription uses ListExisting:false and replays nothing, so without a "+
			"catch-up mark every route that changed during the gap is invisible and the "+
			"helper FIB stays stale until the next event that happens to arrive", actuations)
	}
}

// A nil loop must not panic: the catch-up runs on a path that can be reached
// before the loop is wired, and a refresh helper that crashes the daemon is
// worse than the staleness it exists to fix.
func TestCatchUpToleratesNilLoop9010(t *testing.T) {
	d := &Daemon{}
	d.routeListenerCatchUp(nil)
}
