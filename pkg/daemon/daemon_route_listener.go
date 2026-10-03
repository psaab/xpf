package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/coalesce"
	"github.com/psaab/xpf/pkg/routing"
)

// #7437: drive a helper-FIB refresh from kernel route events.
//
// THE GAP THIS CLOSES. #7409's ImportLearnedRoutes makes the helper FIB agree
// with the kernel FIB, but the snapshot was only republished on an operator
// commit or an ip-monitoring actuation. A route the kernel learned in between
// stayed absent from the helper FIB, so traffic for it resolved NoRoute and
// took the unadjudicated reinject #7409 exists to stop — forwarded by the
// kernel with no zone policy, session, NAT or screen. The window is bounded by
// "time to the next commit", which on a quiet box with a flapping BGP peer is
// unbounded in practice.
//
// IT MUST NOT PUSH PER EVENT, and that constraint shapes everything here.
// Every publish is a full snapshot replace over a control socket whose
// deadline scales with payload size, and CLAUDE.md's rule is explicit that a
// new caller above 1/s starves session installs during bulk sync. Under BGP
// churn a per-event push is a control-plane brownout, and the failure mode is
// not a visible error. So events only ever MARK; the bounded actuation is
// pkg/coalesce's, whose rate bound is asserted there against an injected clock.
//
// STALE-ABSENT IS THE EXPOSURE. A route the kernel withdrew but the helper
// still holds is self-healing — the helper forwards, gets MissingNeighbor, and
// reinjects, and that arm enforces zone policy (#4024). Both cases mark
// identically here rather than being distinguished, precisely so handling the
// benign one cannot complicate the one that matters.
//
// NOT ADDRESSED HERE: the per-publish snapshot SIZE. This changes how often
// a full snapshot replace happens, not how big one is, and a box holding a
// full BGP table would push hundreds of thousands of entries every time.
// That ceiling needs a measurement nobody has taken and is tracked as #8355;
// the listener's correctness does not depend on its value.

// routeRefreshDebounce / routeRefreshThrottle mirror pkg/ipmon's values, which
// are the in-tree precedent for coalescing an expensive republish rather than
// an independent choice.
const (
	routeRefreshDebounce = coalesce.DefaultDebounce
	routeRefreshThrottle = coalesce.DefaultThrottle
)

// routeEventWarrantsRefresh reports whether a kernel route event should mark
// the helper FIB dirty.
//
// The imported-table set is NOT re-derived here: it comes from
// routing.LearnedRouteTableIDs, the same function buildRouteSnapshots feeds to
// the importer. A second copy of "which tables do we import" is a rule that
// can disagree with the importer, and a listener that marks for a table the
// importer ignores burns publishes for nothing while one that skips a table
// the importer reads leaves exactly the window this issue is about.
func routeEventWarrantsRefresh(tableID int, importedTableIDs []int) bool {
	for _, id := range importedTableIDs {
		if id == tableID {
			return true
		}
	}
	return false
}

// markRouteListenerImmediately preserves keepalive liveness changes even if a
// transition races listener startup.
func (d *Daemon) markRouteListenerImmediately() {
	if loop := d.routeListenerLoop.Load(); loop != nil {
		loop.MarkImmediately()
		return
	}
	d.routeListenerPending.Store(true)
	if loop := d.routeListenerLoop.Load(); loop != nil && d.routeListenerPending.Swap(false) {
		loop.MarkImmediately()
	}
}

func (d *Daemon) setRouteListenerLoop(loop *coalesce.Loop) {
	d.routeListenerLoop.Store(loop)
	if d.routeListenerPending.Swap(false) {
		loop.MarkImmediately()
	}
}

// routeListener subscribes to kernel route events and marks the coalescer.
//
// Subscription lifetime and resubscribe-on-error follow
// daemon_neighbor_listener.go, which is the working sibling for this shape.
func (d *Daemon) routeListener(ctx context.Context, loop *coalesce.Loop) {
	loop.SetTimings(routeRefreshDebounce, routeRefreshThrottle)
	d.setRouteListenerLoop(loop)
	loop.Start()
	defer loop.Stop()

	for {
		if ctx.Err() != nil {
			return
		}
		if err := d.runOneRouteSubscription(ctx, loop); err != nil {
			slog.Warn("route listener: subscription ended; resubscribing", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// runOneRouteSubscription owns ONE RouteSubscribe lifetime.
func (d *Daemon) runOneRouteSubscription(ctx context.Context, loop *coalesce.Loop) error {
	updates := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.RouteSubscribeWithOptions(updates, done, netlink.RouteSubscribeOptions{
		ListExisting:  false,
		ErrorCallback: d.routeListenerErrorCallback(loop),
	}); err != nil {
		return err
	}
	// #9010: THE SUBSCRIPTION IS LIVE AGAIN, WHICH IS ITSELF A REFRESH EDGE.
	//
	// This options set passes ListExisting:false, so a new subscription
	// replays nothing: every route that changed while there was no
	// subscription is invisible to `updates` forever. The outer loop's
	// resubscribe therefore closes the socket gap and not the DATA gap.
	//
	// #8915 marks from the ErrorCallback, which covers a fault DURING a live
	// subscription. It cannot cover this: a subscribe that FAILS never
	// installs a callback, so the 2-second retry path marks nothing at all,
	// and a subscription that simply ends returns before any error is raised.
	//
	// The mark is what the coalescer reads to decide whether to actuate --
	// "an unmarked loop sweeps forever and actuates never" (#8915, measured:
	// 0 actuations across 50 sweeps). So without this the helper FIB stays
	// stale until the next route event that happens to arrive.
	//
	// Marking on the FIRST subscription too is deliberate: a refresh is
	// idempotent and the coalescer debounces, so the cost is one actuation at
	// startup, and special-casing "not the first" would make the recovery
	// depend on counting rather than on the invariant.
	d.routeListenerCatchUp(loop)

	for {
		select {
		case <-ctx.Done():
			return nil
		case upd, ok := <-updates:
			if !ok {
				return nil
			}
			if !routeEventWarrantsRefresh(upd.Route.Table, d.importedRouteTableIDs()) {
				continue
			}
			// MARK only. The publish is the coalescer's decision, never this
			// goroutine's — see the per-event note above.
			d.routeListenerMarks.Add(1)
			loop.Mark()
		}
	}
}

// routeListenerCatchUp marks the coalescer for a post-gap refresh.
//
// Named rather than inlined for the same reason as routeListenerErrorCallback:
// a cell must drive the function PRODUCTION calls, not a re-implementation of
// it (#8915). The counter is what a caller can observe.
func (d *Daemon) routeListenerCatchUp(loop *coalesce.Loop) {
	if loop == nil {
		return
	}
	d.routeListenerCatchUps.Add(1)
	loop.Mark()
}

// routeListenerErrorCallback is the subscription's ErrorCallback, named rather
// than inlined so a cell can drive the function PRODUCTION installs (#8915).
//
// A hand-rolled `func(err error)` in a test would pass whatever production
// does, which is the failure this extraction exists to prevent: the guard has
// to bind the wiring, not a re-implementation of it.
func (d *Daemon) routeListenerErrorCallback(loop *coalesce.Loop) func(error) {
	return func(err error) {
		// #8915: AN OVERFLOW DROPS THE ONLY REFRESH EDGE THERE IS.
		//
		// `updates` is bounded at 256. When the kernel outruns this
		// goroutine it drops route messages and reports ENOBUFS here --
		// and `loop.Mark()` has exactly ONE call site, the `case upd :=
		// <-updates` arm below. So the dropped messages ARE the refresh
		// edges: nothing else in the daemon can produce one.
		//
		// The coalescer's 100ms ticker is a SWEEP, not a periodic
		// actuate -- `Tick` fires only `if !l.dirtySince.IsZero()`, so an
		// unmarked loop sweeps forever and actuates never. Measured in
		// #8915: 0 actuations across 50 sweeps with no mark, 1 after a
		// single mark. There is no periodic recovery to fall back on.
		//
		// Logging at Debug therefore left the helper FIB stale until the
		// next route event that happened NOT to be dropped -- which on a
		// churning box is exactly when it is least likely to arrive
		// promptly, because the same churn is what overflowed the queue.
		//
		// MARK ON ERROR. The mark is unconditional rather than
		// ENOBUFS-only: this callback's contract is "something went wrong
		// with the subscription", every such condition means the update
		// stream may have gaps, and a refresh is idempotent -- the
		// coalescer decides whether to actuate. Discriminating on the
		// errno would make recovery depend on matching a string the
		// netlink library does not promise.
		d.routeListenerErrors.Add(1)
		slog.Warn("route listener: netlink error, forcing FIB refresh",
			"err", err, "errors_total", d.routeListenerErrors.Load())
		loop.Mark()
	}
}

// importedRouteTableIDs returns the tables the learned-route importer reads,
// derived from the active config through the importer's own helper.
func (d *Daemon) importedRouteTableIDs() []int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return routing.LearnedRouteTableIDs(nil)
	}
	instance := make([]int, 0, len(cfg.RoutingInstances))
	for _, inst := range cfg.RoutingInstances {
		if inst != nil {
			instance = append(instance, inst.TableID)
		}
	}
	return routing.LearnedRouteTableIDs(instance)
}

// actuateLearnedRouteRefresh republishes a routes-only snapshot so the helper
// FIB picks up learned kernel routes and committed tunnel keepalive transitions.
//
// It deliberately does NOT touch FRR and does NOT change the ip-monitoring
// overlay: the overlay is passed through as the ipmon engine currently holds
// it. The publish refreshes learned routes and tunnel endpoint link state;
// duplicate publishes remain idempotent.
//
// Returns whether it CONVERGED, in pkg/coalesce's contract: false keeps the
// state dirty and the loop retries on the next throttle-paced sweep rather
// than losing the event.
func (d *Daemon) actuateLearnedRouteRefresh(ctx context.Context) bool {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return false
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		// Nothing committed yet: nothing to republish, and the first commit
		// will publish anyway. Converged.
		return true
	}
	pub, ok := d.dataplane().(routeOverlayPublisher)
	if !ok {
		// Helperless build: FRR is the only routing consumer. Converged.
		return true
	}
	var schedulerState map[string]bool
	if sched := d.scheduler.Load(); sched != nil {
		schedulerState = sched.ActiveState()
	}
	// Bounded by the coalescer's throttle (one per 3 s at worst), so this is
	// a state-transition log rather than a per-event one — CLAUDE.md's rule is
	// about the latter. It is also the only operator-visible signal that the
	// listener is doing anything: nothing else exposes the helper's
	// learned-route set.
	slog.Debug("route listener: republishing routes-only snapshot after kernel route change")
	published, err := pub.PublishRouteOverlaySnapshot(cfg, d.ipmonActiveOverlay(), schedulerState)
	if err != nil {
		slog.Warn("route listener: routes-only republish failed — staying dirty for retry",
			"err", err)
		return false
	}
	if !published && !d.pendingFIBBump {
		// Duplicate-skip: the helper routes did not move and no earlier
		// generation bump is still owed.
		return true
	}
	if _, err := pub.BumpFIBGeneration(); err != nil {
		d.pendingFIBBump = true
		slog.Warn("route listener: FIB generation bump unconfirmed — staying dirty for retry",
			"err", err)
		return false
	}
	d.pendingFIBBump = false
	if !published {
		slog.Info("route listener: retried FIB generation bump after earlier failure")
	}
	return true
}

// RouteListenerMarks and RouteListenerRepublishes surface the #7437 pair for
// the xpf_route_listener_* metrics. Reported together because either alone is
// unreadable: republishes without marks cannot distinguish "no route churn"
// from "the listener is dead", and marks without republishes cannot show the
// coalescing that keeps the control socket safe.
func (d *Daemon) RouteListenerMarks() uint64 { return d.routeListenerMarks.Load() }

// RouteListenerErrors counts netlink subscription errors, each of which now
// forces a FIB refresh (#8915).
//
// Surfaced because a recovery nobody can see is its own problem: before #8915
// the overflow was a Debug line, so the ONLY externally visible symptom of a
// dropped refresh edge was a stale helper FIB with no counter pointing at it.
// A non-zero value here means the update stream had a gap and the daemon
// re-synced past it -- not that routing is broken, but that the 256-deep
// queue is being outrun and the marks below are partly recovery rather than
// route churn.
func (d *Daemon) RouteListenerErrors() uint64 { return d.routeListenerErrors.Load() }

func (d *Daemon) RouteListenerRepublishes() uint64 {
	if l := d.routeListenerLoop.Load(); l != nil {
		return l.Actuations()
	}
	return 0
}
