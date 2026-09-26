// Package ipmon implements the `services ip-monitoring` engine
// (#1827 PR-1b, plan §4.3): probe-driven preferred-route injection
// with Junos semantics.
//
// State machine: a policy is FAIL while ANY test of its matched RPM
// probe is FAILED; it recovers when all tests pass (after the optional
// hold-down, an extension beyond Junos that damps recovery flaps —
// hold-down applies to recovery ONLY; a failure is acted on at the next
// debounce tick).
//
// The single decision point is the engine's effective-route overlay
// (ActiveOverlay): the set of currently-injected preferred routes after
// winner resolution — per (routing-instance, prefix) the lowest
// preferred-metric wins, tie-break lexicographic policy name. Both
// consumers (the FRR managed-section render and the userspace snapshot
// builder) read the same overlay, so kernel and dataplane agree by
// construction.
//
// Actuation is coalesced: a dirty bit with a bounded debounce (default
// 1 s) plus a minimum inter-actuation throttle (default 3 s), at most
// one actuation in flight (the single run-loop goroutine), and the
// actuator snapshots the overlay at run time (last-writer-wins) — a
// flap storm across N policies collapses to one actuation per throttle
// window. With hold-down 0 a sustained per-cycle flapper produces one
// actuation per throttle window indefinitely — bounded and observable
// via the per-policy transition counters.
//
// The dirty bit is cleared only AFTER the actuator reports a
// consistent, converged result. A failed consumer (a hard FRR reload
// error, a snapshot-publish error, or an unconfirmed FIB-generation
// bump) keeps the state dirty and the loop retries autonomously at the
// throttle cadence until it converges (#3757). Because a hard FRR
// reload failure aborts the userspace snapshot publish, the kernel FIB
// and the userspace FIB never diverge into a split-brain — both stay on
// the last consistent state until the retry succeeds.
//
// The overlay is runtime state, never config: it does not sync to the
// HA peer and re-derives from fresh probe results within seconds of a
// takeover.
package ipmon

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"

	"github.com/psaab/xpf/pkg/coalesce"
)

const (
	// DefaultDebounce is the bounded delay between the first pending
	// state change and the actuation that publishes it.
	DefaultDebounce = time.Second
	// DefaultThrottle is the minimum spacing between consecutive
	// actuations (frr-reload cooling window).
	DefaultThrottle = 3 * time.Second
	// DefaultActuateTimeout bounds a single actuation so a wedged
	// consumer (an apply semaphore never released by a stuck operator
	// commit) cannot hold the run loop off its next retry indefinitely
	// while the daemon is still up (#4423 L). It aborts only the
	// ctx-checked wait (the apply-semaphore acquire, #3758) — a live FRR
	// reload past that point is never interrupted mid-apply — and a
	// timed-out actuation returns false so the engine keeps the state
	// dirty and retries on the next throttle-paced sweep. Chosen well
	// above a legitimate FRR reload + snapshot publish.
	DefaultActuateTimeout = 30 * time.Second
)

// UnresolvedRoute describes a FAILED policy's interface-typed preferred
// route that was skipped from the overlay because its next-hop could not
// be resolved (no DHCP lease/gateway, or no resolver wired) — #1844,
// #3761 M9. It carries enough context for an operator to tell WHICH DHCP
// unit / routing-instance is missing, not just the destination prefix.
type UnresolvedRoute struct {
	RoutingInstance  string
	Destination      string
	NextHopInterface string
	Metric           int
	Reason           string // e.g. "no DHCP gateway", "no next-hop resolver"
}

// SuppressedRoute describes a FAILED policy's resolvable candidate that
// lost winner resolution to another policy for the same
// (routing-instance, prefix) — #3761 M10. It is distinct from an
// unresolved route: the candidate WAS usable, but a lower-metric (or
// lexicographically-earlier) policy won the prefix. Surfacing it keeps a
// deterministic loser from reading as an unresolved/buggy route.
type SuppressedRoute struct {
	RoutingInstance string
	Destination     string
	NextHop         string
	Metric          int
	WinnerPolicy    string
}

// PolicyStatus is the per-policy view for show/metrics.
type PolicyStatus struct {
	Name   string
	Probe  string
	Failed bool
	// Known is true once at least one RPM result for the policy's probe
	// has been observed (#3761 H7). While false the policy's health is
	// UNKNOWN — status/metrics must NOT report it as PASS, because "no
	// probe has run" is not "the uplink is healthy".
	Known             bool
	Since             time.Time // last state-change time (zero = never evaluated)
	FailingTests      []string
	HoldDownSecs      int
	PendingRecoveryAt time.Time // non-zero while a recovery hold-down is running
	// Routes is the DESIRED winner-resolved overlay for this policy — the
	// routes the engine WANTS injected right now given current FAIL
	// state. It is not necessarily what is live in the FIB; see
	// AppliedRoutes.
	Routes []config.RouteOverlayEntry
	// AppliedRoutes is the subset of the last CONVERGED actuation's
	// overlay owned by this policy — what is actually live in both the
	// kernel and userspace FIBs (#3761 H8). It diverges from Routes while
	// an actuation is pending or the actuator is failing to converge
	// (#3757). Feeds the honest xpf_ipmon_routes_applied gauge.
	AppliedRoutes []config.RouteOverlayEntry
	// UnresolvedRoutes lists this policy's interface-typed candidates
	// skipped at overlay computation (no DHCP lease/gateway, #1844).
	// Populated only while the policy is FAILED; sorted. Feeds the
	// xpf_ipmon_unresolved_next_hops gauge and `show services
	// ip-monitoring status`.
	UnresolvedRoutes []UnresolvedRoute
	// SuppressedRoutes lists this policy's resolvable candidates that
	// lost winner resolution to another policy (#3761 M10). Populated
	// only while the policy is FAILED; sorted.
	SuppressedRoutes []SuppressedRoute
	Transitions      uint64
}

// NextHopResolver resolves an interface-typed preferred-route next-hop
// — the Linux DHCP lease key from PreferredRoute.NextHopInterface — to
// its current DHCP-learned gateway (#1844). ok=false means the
// candidate is skipped (no lease, or lease without a gateway). Called
// under Engine.mu during overlay computation; the implementation may
// take its own lock (dhcp.Manager.mu) but must NEVER call back into
// the engine — the lock order Engine.mu → dhcp.mu is one-way.
type NextHopResolver func(leaseIface string) (gw string, ok bool)

type policyState struct {
	cfg               *config.IPMonitoringPolicy
	failed            bool
	since             time.Time
	pendingRecoveryAt time.Time
	transitions       uint64
}

// Engine evaluates ip-monitoring policies against RPM test state and
// triggers the route-overlay actuator through debounce + throttle.
type Engine struct {
	mu                       sync.Mutex
	policies                 map[string]*policyState
	failedTests              map[string]map[string]bool // probe → test → failed
	lastTransitionGeneration uint64                     // latest ordered RPM snapshot accepted

	// publishEnabled implements HA primary-only overlay publication
	// (§4.4): when false (standby), ActiveOverlay returns nil so the
	// actuator publishes the config baseline.
	publishEnabled bool

	// #8354: the debounce/throttle/dirty-generation discipline lives in
	// pkg/coalesce, which was written as the type this engine would adopt.
	// Two implementations of one discipline is a divergence with a delay
	// fuse: whichever copy is edited first is right, and nothing tells the
	// other. What stays here is what is genuinely ipmon's -- policy
	// evaluation, next-hop resolution, recovery hold-downs, and the
	// publishEnabled HA gate.
	loop *coalesce.Loop
	// appliedOverlay is the overlay snapshot from the last CONVERGED
	// actuation — what is actually live in the FIBs (#3761 H8). It is
	// updated ONLY when the run loop confirms a consistent actuation
	// (actuator returned true AND no newer change landed), so it holds
	// the last good state across a failing/pending actuation instead of
	// reporting the desired overlay as applied.
	appliedOverlay []config.RouteOverlayEntry
	// actuationFailures counts route-overlay actuations that did not
	// converge (a hard FRR reload error, a snapshot-publish failure, an
	// unconfirmed FIB-generation bump, or a bounded-timeout/shutdown
	// abort). Monotonic; feeds xpf_ipmon_actuation_failures_total so the
	// otherwise-silent #3757 self-heal retry loop is observable — a
	// steadily-climbing value means ip-monitoring cannot commit its
	// overlay and failover protection is degraded (#4423 L). Read/written
	// only under mu.
	actuationFailures uint64

	// actuate is the daemon route-overlay actuator; called WITHOUT mu
	// held. It returns true when the overlay converged consistently
	// (kernel FRR AND the userspace snapshot committed together) and
	// false when any consumer failed — a false return keeps the dirty
	// bit set so the run loop retries autonomously on the next sweep
	// (#3757). It is passed e.actuateCtx (cancelled on Stop) so a
	// shutdown aborts a blocked actuation instead of wedging the run
	// loop behind an in-flight apply that never releases (#3758): the
	// actuator MUST thread the context into any blocking wait (the
	// apply semaphore, FRR reload) and, on cancellation, abort cleanly
	// (return false) WITHOUT half-actuating.
	actuate func(ctx context.Context) bool
	// resolveNextHop resolves interface-typed next-hops at overlay
	// computation (#1844). Written by SetNextHopResolver and read by
	// computeOverlayLocked, both under mu (#4423 L closes the prior
	// unsynchronized-field race); the daemon still wires it once before
	// Start. nil ⇒ interface-typed candidates always skip (defensive —
	// the daemon always wires it).
	resolveNextHop NextHopResolver
	now            func() time.Time
	debounce       time.Duration
	throttle       time.Duration
	// actuateTimeout bounds a single actuate() call (0 ⇒ unbounded). Set
	// once before Start (like debounce/throttle) and read by the run-loop
	// goroutine without further synchronization (#4423 L).
	actuateTimeout time.Duration

	kick chan struct{}
	stop chan struct{}
	done chan struct{}

	// actuateCtx is cancelled by Stop (its cancel is actuateCancel) so
	// an in-flight actuation blocked on the apply semaphore or an FRR
	// reload aborts promptly on shutdown/reconcile instead of holding
	// the run loop off its stop case forever (#3758). Created in New,
	// cancelled exactly once in Stop under mu.
	actuateCtx    context.Context
	actuateCancel context.CancelFunc

	// started / stopped guard the run-loop lifecycle (#3762). Both are
	// read and written only under mu. started flips true on the first
	// Start (a later Start is a no-op — never a second run() goroutine,
	// which would double-close(done) and panic). stopped flips true on
	// the first Stop and closes e.stop exactly once; a Stop before Start
	// returns without waiting on e.done (no run loop exists to close it),
	// and a Start after Stop is a no-op.
	started bool
	stopped bool
}

// New creates an engine. actuate is the daemon's routes-only actuator;
// it is invoked from the engine's single run-loop goroutine (never
// concurrently) and must read ActiveOverlay() itself so it always
// publishes the freshest overlay. It receives a context (cancelled on
// Stop) that it MUST thread into any blocking wait so a shutdown aborts
// a blocked actuation (#3758). It returns true on a consistent,
// converged actuation and false when a consumer failed or the context
// was cancelled — a false return keeps the state dirty for an
// autonomous retry (#3757).
func New(actuate func(ctx context.Context) bool) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		policies:       make(map[string]*policyState),
		failedTests:    make(map[string]map[string]bool),
		publishEnabled: true,
		actuate:        actuate,
		now:            time.Now,
		debounce:       DefaultDebounce,
		throttle:       DefaultThrottle,
		actuateTimeout: DefaultActuateTimeout,
		kick:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		actuateCtx:     ctx,
		actuateCancel:  cancel,
	}
	// #8354: the shared discipline. Constructed HERE rather than in Start
	// because Apply/HandleTransition can mark the engine dirty before it is
	// started, and a nil loop would panic on the first mark -- Go compiles a
	// nil-pointer method call happily, so that is a runtime failure with no
	// compile-time sign.
	//
	// The actuator is wrapped rather than passed through: the engine's
	// post-actuation bookkeeping (applied overlay, failure counter) is
	// attached with OnConverged/OnFailed, which fire on the loop's own
	// convergence condition -- `ok && generation unchanged` -- that an
	// actuator cannot see.
	e.loop = coalesce.New(e.actuateForLoop)
	e.loop.OnConverged(e.recordConvergedActuation)
	e.loop.OnFailed(e.recordFailedActuation)
	return e
}

// actuateForLoop adapts the engine's actuator to the loop. A nil actuator
// (tests that drive the state machine directly) is a converged no-op, which is
// the pre-#8354 behaviour.
func (e *Engine) actuateForLoop(ctx context.Context) bool {
	e.mu.Lock()
	actuate := e.actuate
	e.mu.Unlock()
	if actuate == nil {
		return true
	}
	// Outside the lock; the actuator reads ActiveOverlay() itself, so it
	// publishes the freshest state (last-writer-wins under flap storms).
	return actuate(ctx)
}

// recordConvergedActuation runs after an actuation that CONVERGED -- the
// actuator returned true AND no change landed while it ran.
//
// #3761 H8: the applied overlay is recorded under exactly that condition,
// because "the actuator published what it read" is only true when no newer
// change arrived mid-actuation. Widening this to plain `ok` would record a
// DESIRED state as an APPLIED one, which is what status and metrics report.
func (e *Engine) recordConvergedActuation() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appliedOverlay = e.activeOverlayLocked()
}

// recordFailedActuation counts a non-convergence caused by the ACTUATOR
// (a consumer failed, or the bounded timeout / shutdown aborted the wait), so
// the otherwise-silent self-heal retry is observable (#4423 L).
//
// A non-convergence caused by a concurrent re-dirty does NOT reach here:
// nothing failed, the work is simply not finished, and counting it would make
// a flap storm look like an outage.
func (e *Engine) recordFailedActuation() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actuationFailures++
}

// SetNextHopResolver injects the interface-typed next-hop resolver
// (#1844). The daemon calls it once before Start(); it takes mu so a
// late call (a test, or a future re-wire) cannot race the run loop's
// resolver read in computeOverlayLocked (#4423 L).
func (e *Engine) SetNextHopResolver(r NextHopResolver) {
	e.mu.Lock()
	e.resolveNextHop = r
	e.mu.Unlock()
}

// NotifyNextHopChange is the DHCP gateway-change trigger (#1844): it
// marks the overlay dirty and kicks the run loop when any currently
// FAILED policy has an interface-typed preferred route, entering the
// same dirty-bit → debounce → throttle → routes-only-actuator queue
// as probe transitions (no second actuation path). Cheap —
// O(policies×routes) under mu, no resolution. Bounded-blocking, not
// non-blocking: it may wait on Engine.mu held across an overlay build
// (which calls the resolver into dhcp.mu); the caller (the dhcp
// gateway hook) never holds dhcp.mu, so the one-way lock order stays
// acyclic.
func (e *Engine) NotifyNextHopChange() {
	e.mu.Lock()
	relevant := false
	// While publication is gated off (HA standby, §4.4) the effective
	// overlay is the baseline (nil) regardless of any DHCP-learned
	// gateway, so a lease change cannot alter what this node publishes —
	// scheduling an actuation would only churn an frr-reload + snapshot
	// publish for a no-op on the standby (#4423 M4). SetPublishEnabled(true)
	// on takeover re-actuates and the overlay then follows the fresh lease.
	if e.publishEnabled {
		for _, st := range e.policies {
			if !st.failed {
				continue
			}
			for _, pr := range st.cfg.PreferredRoutes {
				if pr != nil && pr.NextHopInterface != "" {
					relevant = true
					break
				}
			}
			if relevant {
				break
			}
		}
	}
	if relevant {
		e.markDirtyLocked(true)
	}
	e.mu.Unlock()
	if relevant {
		slog.Debug("ip-monitoring: DHCP gateway change marked overlay dirty")
		e.kickLoop()
	}
}

// Start launches the actuation loop. It is idempotent (#3762 H9): a
// second Start — or a Start after Stop — is a no-op, so the run() loop
// is spawned at most once. A second goroutine would each defer
// close(e.done) and the second close would panic.
func (e *Engine) Start() {
	// #8354: push the engine's timings and clock into the shared loop at
	// Start. They live on the Engine because tests set them directly before
	// Start -- keeping that working unchanged is an acceptance condition of
	// the adoption, since those tests are the guard on the behaviour being
	// relocated.
	e.mu.Lock()
	debounce, throttle, now := e.debounce, e.throttle, e.now
	actuateTimeout := e.actuateTimeout
	e.mu.Unlock()
	e.loop.SetTimings(debounce, throttle)
	e.loop.SetActuateTimeout(actuateTimeout)
	if now != nil {
		e.loop.SetClock(now)
	}
	e.mu.Lock()
	if e.started || e.stopped {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()
	go e.run()
}

// Stop terminates the actuation loop. It is safe to call before Start,
// without Start, or more than once (#3762 H10): the first call closes
// e.stop exactly once, and only a Stop that follows a real Start waits
// on e.done — a Stop with no run loop returns immediately instead of
// blocking forever on a channel nothing will ever close.
//
// Stop cancels e.actuateCtx BEFORE waiting on e.done (#3758): the run
// loop can only observe e.stop AFTER the synchronous actuator returns,
// so if an actuation is blocked (on the apply semaphore or an FRR
// reload) the wait on e.done would hang forever. Cancelling the
// context first unblocks that actuation so the loop can reach its stop
// case promptly. The cancel happens under mu (once, guarded by
// e.stopped) so it races neither a second Stop nor the run loop.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	started := e.started
	e.actuateCancel()
	e.mu.Unlock()
	close(e.stop)
	if started {
		<-e.done
	}
}

// Apply installs a new policy set, preserving FAIL state for policies
// whose (name, probe) survives the commit, and seeds test state from
// the supplied results snapshot. Called under the daemon apply path on
// config change.
func (e *Engine) Apply(cfg *config.IPMonitoringConfig, results []*rpm.ProbeResult) {
	e.mu.Lock()
	// Codex PR #1843 MED: actuate only when the overlay-relevant
	// state actually changed. Compare the effective overlay before
	// and after the policy swap — a no-op commit (or any commit with
	// zero policies) must not schedule a routes-only FRR reload.
	overlayBefore := e.activeOverlayLocked()
	// recomputedHold is set when a surviving policy's hold-down value
	// changed while a recovery was pending (#3763): the run loop must be
	// kicked even when the FAIL/recover state itself did not change, so it
	// re-derives its wake timer against the NEW (possibly shortened)
	// deadline instead of sleeping to the stale one.
	recomputedHold := false
	next := make(map[string]*policyState)
	if cfg != nil {
		for name, pol := range cfg.Policies {
			if pol == nil {
				continue
			}
			st := &policyState{cfg: pol}
			if prev, ok := e.policies[name]; ok && prev.cfg.MatchRPMProbe == pol.MatchRPMProbe {
				st.failed = prev.failed
				st.since = prev.since
				st.transitions = prev.transitions
				// #3763: a running recovery hold-down must honor a
				// hold-down value the operator changes mid-recovery.
				// pendingRecoveryAt encodes recoveryStart + oldHold, so
				// the new deadline is recoveryStart + newHold =
				// pendingRecoveryAt + (newHold - oldHold). Preserve it
				// verbatim only when hold-down is unchanged; recompute
				// (crediting elapsed time) when it changed; drop it when
				// hold-down was lowered to 0 so evaluateLocked recovers
				// at once. Lowering shortens a pending recovery, raising
				// extends it — operator intent honored without a restart.
				if prev.cfg.HoldDownSecs == pol.HoldDownSecs {
					st.pendingRecoveryAt = prev.pendingRecoveryAt
				} else if !prev.pendingRecoveryAt.IsZero() {
					// #8642: a wrapped hold is ~512ns, which passes the
					// `newHold > 0` check below and undamps the very route flap
					// the hold-down exists to damp.
					oldHold := config.SecondsToDuration(prev.cfg.HoldDownSecs, 0)
					newHold := config.SecondsToDuration(pol.HoldDownSecs, 0)
					if newHold > 0 {
						st.pendingRecoveryAt = prev.pendingRecoveryAt.Add(newHold - oldHold)
					}
					// newHold == 0: leave pendingRecoveryAt zero — the
					// evaluateLocked below recovers immediately.
					recomputedHold = true
				}
			}
			next[name] = st
		}
	}
	e.policies = next
	e.seedResultsLocked(results)
	changed := e.evaluateLocked(e.now())
	if !changed && !slices.Equal(overlayBefore, e.activeOverlayLocked()) {
		// Policy spec edited/removed while contributing to the
		// overlay (the HIGH-1 re-injection path), or a survivor's
		// winner changed — re-actuate.
		changed = true
	}
	e.markDirtyLocked(changed)
	e.mu.Unlock()
	if changed || recomputedHold {
		// recomputedHold with changed==false means a still-pending
		// recovery's deadline moved (typically shortened): wake the loop
		// so nextWakeLocked re-arms against the new deadline (#3763).
		e.kickLoop()
	}
}

// HandleTransition is the rpm.TransitionCallback sensor input. Manager-stamped
// generations suppress stale snapshots when sibling callbacks arrive out of
// order; a zero generation remains accepted for unversioned callers.
func (e *Engine) HandleTransition(t rpm.Transition) {
	e.mu.Lock()
	if t.Generation != 0 {
		if t.Generation <= e.lastTransitionGeneration {
			e.mu.Unlock()
			return
		}
		e.lastTransitionGeneration = t.Generation
	}
	// The transition carries a full current-state snapshot — seed from
	// it (authoritative) and overlay the transition itself (the
	// snapshot already reflects it, but be explicit).
	e.seedResultsLocked(t.Results)
	if e.failedTests[t.ProbeName] == nil {
		e.failedTests[t.ProbeName] = make(map[string]bool)
	}
	e.failedTests[t.ProbeName][t.TestName] = t.Status == "fail"
	changed := e.evaluateLocked(e.now())
	e.markDirtyLocked(changed)
	e.mu.Unlock()
	if changed {
		e.kickLoop()
	}
}

// SetPublishEnabled gates overlay publication (HA primary-only, §4.4).
// Flipping the gate triggers an actuation: on standby the baseline is
// published; on takeover the baseline goes out first and the overlay
// follows fresh probe results.
func (e *Engine) SetPublishEnabled(enabled bool) {
	e.mu.Lock()
	if e.publishEnabled == enabled {
		e.mu.Unlock()
		return
	}
	e.publishEnabled = enabled
	e.markDirtyLocked(true)
	e.mu.Unlock()
	e.kickLoop()
	slog.Info("ip-monitoring overlay publication gate changed", "enabled", enabled)
}

// PublishEnabled reports the HA gate state.
func (e *Engine) PublishEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.publishEnabled
}

// ActiveOverlay returns the winner-resolved effective-route overlay:
// one entry per (routing-instance, family, prefix) across all policies
// currently in FAIL. Returns nil while publication is gated off
// (standby) — the config baseline.
func (e *Engine) ActiveOverlay() []config.RouteOverlayEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeOverlayLocked()
}

func (e *Engine) activeOverlayLocked() []config.RouteOverlayEntry {
	overlay, _ := e.computeOverlayLocked()
	return overlay
}

// overlayDetail carries the non-winner outcomes of one overlay
// computation, keyed by policy name, so status/metrics can report WHY a
// FAILED policy's candidate is not in the applied overlay (#3761 M9+M10).
type overlayDetail struct {
	// unresolved: interface-typed candidates skipped for want of a
	// resolved next-hop (no DHCP lease/gateway, or no resolver wired).
	unresolved map[string][]UnresolvedRoute
	// suppressed: resolvable candidates that lost winner resolution to
	// another policy for the same (routing-instance, prefix).
	suppressed map[string][]SuppressedRoute
}

// computeOverlayLocked is the pure overlay computation: winner
// resolution per (routing-instance, canonical prefix) across FAILED
// policies, with interface-typed next-hops resolved through the
// injected resolver BEFORE the winner comparison (#1844 plan §4.2 —
// an unresolvable winner must let a resolvable losing candidate win;
// resolving after selection gets that wrong by construction). The
// second return value reports, per policy, the interface-typed
// candidates skipped for lack of a resolved next-hop and the resolvable
// candidates that lost the prefix to another policy (#3761 M9+M10).
func (e *Engine) computeOverlayLocked() ([]config.RouteOverlayEntry, overlayDetail) {
	var detail overlayDetail
	if !e.publishEnabled {
		return nil, detail
	}
	type candidate struct {
		metric int
		policy string
		entry  config.RouteOverlayEntry
	}
	// Keep ALL resolvable candidates per key so losers can be attributed
	// to the winner after selection (M10), not just the current best.
	byKey := make(map[string][]candidate)
	for name, st := range e.policies {
		if !st.failed {
			continue
		}
		for _, pr := range st.cfg.PreferredRoutes {
			dest := canonicalCIDR(pr.Destination)
			if dest == "" {
				continue // commit validation prevents this
			}
			nextHop := pr.NextHop
			if pr.NextHopInterface != "" {
				gw, ok := "", false
				if e.resolveNextHop != nil {
					gw, ok = e.resolveNextHop(pr.NextHopInterface)
				}
				if !ok {
					// Skip BEFORE winner selection so a resolvable losing
					// candidate can win the prefix.
					reason := "no DHCP gateway"
					if e.resolveNextHop == nil {
						reason = "no next-hop resolver"
					}
					if detail.unresolved == nil {
						detail.unresolved = make(map[string][]UnresolvedRoute)
					}
					detail.unresolved[name] = append(detail.unresolved[name], UnresolvedRoute{
						RoutingInstance:  pr.RoutingInstance,
						Destination:      dest,
						NextHopInterface: pr.NextHopInterface,
						Metric:           pr.PreferredMetric,
						Reason:           reason,
					})
					continue
				}
				nextHop = gw
			}
			key := pr.RoutingInstance + "|" + dest
			byKey[key] = append(byKey[key], candidate{
				metric: pr.PreferredMetric,
				policy: name,
				entry: config.RouteOverlayEntry{
					RoutingInstance:  pr.RoutingInstance,
					Destination:      dest,
					NextHop:          nextHop,
					NextHopInterface: pr.NextHopInterface,
					Metric:           pr.PreferredMetric,
					Policy:           name,
				},
			})
		}
	}
	for _, u := range detail.unresolved {
		sortUnresolved(u)
	}
	if len(byKey) == 0 {
		return nil, detail
	}
	out := make([]config.RouteOverlayEntry, 0, len(byKey))
	for _, cands := range byKey {
		// Winner: lowest metric, tie-break lexicographic policy name.
		win := 0
		for i := 1; i < len(cands); i++ {
			if cands[i].metric < cands[win].metric ||
				(cands[i].metric == cands[win].metric && cands[i].policy < cands[win].policy) {
				win = i
			}
		}
		out = append(out, cands[win].entry)
		for i, c := range cands {
			if i == win {
				continue
			}
			if detail.suppressed == nil {
				detail.suppressed = make(map[string][]SuppressedRoute)
			}
			detail.suppressed[c.policy] = append(detail.suppressed[c.policy], SuppressedRoute{
				RoutingInstance: c.entry.RoutingInstance,
				Destination:     c.entry.Destination,
				NextHop:         c.entry.NextHop,
				Metric:          c.metric,
				WinnerPolicy:    cands[win].policy,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RoutingInstance != out[j].RoutingInstance {
			return out[i].RoutingInstance < out[j].RoutingInstance
		}
		return out[i].Destination < out[j].Destination
	})
	for _, s := range detail.suppressed {
		sortSuppressed(s)
	}
	return out, detail
}

func sortUnresolved(u []UnresolvedRoute) {
	sort.Slice(u, func(i, j int) bool {
		if u[i].RoutingInstance != u[j].RoutingInstance {
			return u[i].RoutingInstance < u[j].RoutingInstance
		}
		return u[i].Destination < u[j].Destination
	})
}

func sortSuppressed(s []SuppressedRoute) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].RoutingInstance != s[j].RoutingInstance {
			return s[i].RoutingInstance < s[j].RoutingInstance
		}
		return s[i].Destination < s[j].Destination
	})
}

// Status returns the per-policy view, with each policy's currently
// winning routes attached.
func (e *Engine) Status() []PolicyStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	overlay, detail := e.computeOverlayLocked()
	byPolicy := make(map[string][]config.RouteOverlayEntry)
	for _, entry := range overlay {
		byPolicy[entry.Policy] = append(byPolicy[entry.Policy], entry)
	}
	appliedByPolicy := make(map[string][]config.RouteOverlayEntry)
	for _, entry := range e.appliedOverlay {
		appliedByPolicy[entry.Policy] = append(appliedByPolicy[entry.Policy], entry)
	}

	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]PolicyStatus, 0, len(names))
	for _, name := range names {
		st := e.policies[name]
		_, known := e.failedTests[st.cfg.MatchRPMProbe]
		ps := PolicyStatus{
			Name:              name,
			Probe:             st.cfg.MatchRPMProbe,
			Failed:            st.failed,
			Known:             known,
			Since:             st.since,
			HoldDownSecs:      st.cfg.HoldDownSecs,
			PendingRecoveryAt: st.pendingRecoveryAt,
			Routes:            byPolicy[name],
			AppliedRoutes:     appliedByPolicy[name],
			UnresolvedRoutes:  detail.unresolved[name],
			SuppressedRoutes:  detail.suppressed[name],
			Transitions:       st.transitions,
		}
		for test, failed := range e.failedTests[st.cfg.MatchRPMProbe] {
			if failed {
				ps.FailingTests = append(ps.FailingTests, test)
			}
		}
		sort.Strings(ps.FailingTests)
		out = append(out, ps)
	}
	return out
}

// RoutesApplied returns the number of overlay routes ACTUALLY applied —
// the size of the last converged actuation's overlay (#3761 H8), not the
// desired overlay. It is 0 until the first actuation converges and holds
// the last good value across a failing/pending actuation. Use
// len(ActiveOverlay()) for the DESIRED count.
func (e *Engine) RoutesApplied() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.appliedOverlay)
}

// ActuationFailures reports the cumulative number of route-overlay
// actuations that did not converge — a hard FRR reload error, a
// snapshot-publish failure, an unconfirmed FIB-generation bump (#3757),
// or a bounded-timeout/shutdown abort (#3758/#4423 L). It is monotonic;
// the engine retries a failed actuation autonomously (throttle-paced),
// so a steadily-climbing value means ip-monitoring cannot commit its
// overlay and failover protection is degraded. Feeds
// xpf_ipmon_actuation_failures_total.
func (e *Engine) ActuationFailures() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.actuationFailures
}

// seedResultsLocked rebuilds per-test fail state from a results
// snapshot. A nil snapshot is treated identically to an empty one: it
// CLEARS all known test state (no probe data ⇒ nothing failing) rather
// than preserving a stale FAIL — keeping a policy FAILED (and its
// failover route injected) off results the caller no longer has is wrong
// (#4423 M8). Both production callers pass a full authoritative,
// non-nil snapshot (Apply from rpm.Results(), always a non-nil slice;
// HandleTransition from rpm's per-transition snapshot), so nil arrives
// only from a direct package/API caller with no results — which now
// resets cleanly to UNKNOWN instead of silently carrying the last
// failure forward.
func (e *Engine) seedResultsLocked(results []*rpm.ProbeResult) {
	fresh := make(map[string]map[string]bool)
	for _, r := range results {
		if r == nil {
			continue
		}
		if fresh[r.ProbeName] == nil {
			fresh[r.ProbeName] = make(map[string]bool)
		}
		fresh[r.ProbeName][r.TestName] = r.LastStatus == "fail"
	}
	e.failedTests = fresh
}

// evaluateLocked runs the FAIL/recover state machine at time now.
// Returns true when any policy changed state.
func (e *Engine) evaluateLocked(now time.Time) bool {
	changed := false
	for name, st := range e.policies {
		anyFailed := false
		for _, failed := range e.failedTests[st.cfg.MatchRPMProbe] {
			if failed {
				anyFailed = true
				break
			}
		}
		switch {
		case anyFailed && !st.failed:
			st.failed = true
			st.since = now
			st.pendingRecoveryAt = time.Time{}
			st.transitions++
			changed = true
			slog.Info("ip-monitoring policy FAILED — injecting preferred routes",
				"policy", name, "probe", st.cfg.MatchRPMProbe)
		case anyFailed && st.failed:
			// Still failed: cancel any pending recovery.
			st.pendingRecoveryAt = time.Time{}
		case !anyFailed && st.failed:
			hold := config.SecondsToDuration(st.cfg.HoldDownSecs, 0) // #8642
			if hold > 0 {
				if st.pendingRecoveryAt.IsZero() {
					st.pendingRecoveryAt = now.Add(hold)
					slog.Info("ip-monitoring policy recovery hold-down started",
						"policy", name, "hold_down", hold)
					continue
				}
				if now.Before(st.pendingRecoveryAt) {
					continue
				}
			}
			st.failed = false
			st.since = now
			st.pendingRecoveryAt = time.Time{}
			st.transitions++
			changed = true
			slog.Info("ip-monitoring policy recovered — withdrawing preferred routes",
				"policy", name, "probe", st.cfg.MatchRPMProbe)
		}
	}
	return changed
}

func (e *Engine) markDirtyLocked(changed bool) {
	if !changed {
		return
	}
	// #8354: delegated. Mark() bumps the generation on EVERY change -- so a
	// change landing while an actuation is in flight is visible to the
	// post-actuate clear check (#3757 last-writer-wins) rather than only the
	// first clean->dirty transition -- and starts the debounce window on the
	// first mark. That is the same contract this function used to implement
	// itself; it is now implemented once.
	e.loop.Mark()
}

func (e *Engine) kickLoop() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// run is the single actuation goroutine: it owns debounce, throttle,
// hold-down wakeups, and the at-most-one-actuation-in-flight invariant.
func (e *Engine) run() {
	defer close(e.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		e.mu.Lock()
		// Re-evaluate for hold-down expiry before computing the wake.
		changed := e.evaluateLocked(e.now())
		e.markDirtyLocked(changed)

		e.mu.Unlock()

		// #8354: one sweep of the shared discipline. Tick owns the debounce,
		// the throttle, the pre-actuation `lastActuation` advance that paces a
		// FAILING actuation to one retry per throttle window, and the
		// clear-only-when-converged-and-unchanged rule. The actuator, the
		// applied-overlay record and the failure counter are wired to it in
		// Start().
		e.loop.Tick(e.actuateCtx)

		e.mu.Lock()
		wake := e.nextWakeLocked(e.now())
		e.mu.Unlock()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wake)
		select {
		case <-e.kick:
		case <-timer.C:
		case <-e.stop:
			return
		}
	}
}

// nextWakeLocked computes how long the loop may sleep: the earliest of
// the debounce/throttle deadline for a pending dirty bit and any
// recovery hold-down expiry. Parks for an hour when idle.
func (e *Engine) nextWakeLocked(now time.Time) time.Duration {
	wake := time.Hour
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		d := t.Sub(now)
		if d < time.Millisecond {
			d = time.Millisecond
		}
		if d < wake {
			wake = d
		}
	}
	// #8354: the debounce/throttle deadline belongs to the shared loop, which
	// owns the state it is computed from. Recomputing it here would be the same
	// duplication, moved one function along. The recovery hold-downs below are
	// ipmon's own wakeup source and stay.
	if w := e.loop.NextWake(time.Hour); w < wake {
		wake = w
	}
	for _, st := range e.policies {
		consider(st.pendingRecoveryAt)
	}
	return wake
}

// canonicalCIDR normalizes a prefix string (mask-aligned) so overlay
// matching against snapshot/FRR destinations is well-defined.
func canonicalCIDR(s string) string {
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		return ""
	}
	return n.String()
}

// FilterOverlayForConfig drops overlay entries that an INCOMING config
// no longer backs: entries whose owning policy was removed, or whose
// preferred-route spec (routing-instance, prefix, next-hop, metric)
// was edited (Codex review on PR #1843, HIGH-1). The full apply path
// caches the engine's overlay BEFORE reconcileIPMon installs the new
// policy set, so without this filter a commit that removes or edits a
// policy would republish the STALE overlay to both consumers (FRR +
// snapshot) until the delayed actuator caught up. Only still-valid
// entries ride the commit's own publish; the post-commit
// reconcile+actuation re-injects under the new spec if the probes
// still report FAILED.
func FilterOverlayForConfig(overlay []config.RouteOverlayEntry, ipmCfg *config.IPMonitoringConfig) []config.RouteOverlayEntry {
	if len(overlay) == 0 {
		return nil
	}
	if ipmCfg == nil || len(ipmCfg.Policies) == 0 {
		return nil
	}
	out := make([]config.RouteOverlayEntry, 0, len(overlay))
	for _, entry := range overlay {
		pol := ipmCfg.Policies[entry.Policy]
		if pol == nil {
			continue
		}
		backed := false
		for _, pr := range pol.PreferredRoutes {
			if pr == nil {
				continue
			}
			if pr.RoutingInstance != entry.RoutingInstance ||
				canonicalCIDR(pr.Destination) != entry.Destination ||
				pr.PreferredMetric != entry.Metric {
				continue
			}
			// Next-hop spec match: literal entries compare the IP;
			// interface-typed entries (#1844) compare the lease key —
			// the entry's NextHop is the RESOLVED gateway (runtime
			// state) and never equals the config spec. A commit that
			// re-targets the route to a different interface (or flips
			// interface↔literal) therefore drops the old entry, the
			// #1843 HIGH-1 contract; a same-spec commit keeps the
			// last-resolved gateway riding the commit's own publish
			// and the engine's next actuation converges it.
			if pr.NextHopInterface != "" {
				backed = pr.NextHopInterface == entry.NextHopInterface
			} else {
				backed = entry.NextHopInterface == "" && pr.NextHop == entry.NextHop
			}
			if backed {
				break
			}
		}
		if backed {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
