package diagcmd

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

// MaxConcurrentDiagnostics bounds how many host-level ping/traceroute
// diagnostics may run at once across EVERY control surface that exposes
// them (the REST API and the gRPC API share the single DefaultLimiter
// below). Each in-flight diagnostic holds a child process, its output
// pipes, a handler goroutine and — on gRPC — a stream, for up to the
// 150s diagExecCeiling. Without an aggregate bound a burst of concurrent
// diagnostic requests can pin hundreds/thousands of PIDs/FDs/goroutines
// and starve the control plane that drives the dataplane (#5057).
//
// The value is deliberately small: legitimate operator/automation use
// runs a handful of diagnostics at once, while a firewall must never let
// a diagnostic flood exhaust host resources. A per-job deadline (present
// via pingExecTimeout/diagTracerouteTimeout in the API packages) plus
// this aggregate concurrency bound together cap the worst-case resource
// footprint.
const MaxConcurrentDiagnostics = 4

// ErrBusy is returned by Limiter.Acquire when the concurrency cap is
// already reached. Callers map it to their surface's overload signal:
// HTTP 429 (REST) / codes.ResourceExhausted (gRPC).
var ErrBusy = errors.New("diagnostic concurrency limit reached")

// Limiter is a fixed-capacity counting semaphore bounding concurrent
// diagnostic executions. Acquire is fail-fast (non-blocking): excess
// callers are rejected immediately rather than queued, so a request
// flood cannot build an unbounded backlog of waiters. The zero value is
// unusable; construct with NewLimiter.
type Limiter struct {
	sem chan struct{}
	// refused counts Acquire calls rejected at capacity, cumulatively and for
	// the process lifetime (#8312).
	//
	// WHY THIS EXISTS AT ALL, since a counter on a semaphore looks like
	// decoration. #7294 item 2 asks for a WEIGHTED cost model — charge a full
	// list more slots than a cursor page — and its acceptance criterion is that
	// the model be "stated with a measurement, not asserted". Two attempts have
	// now tried to measure the PER-ITEM COST: a cluster REST sweep, whose ~80ms
	// of HTTP+JSON fixed cost buried the walk and produced five negative
	// slopes, and a proposed Go benchmark, which needs BPF_MAP_CREATE and could
	// not be run.
	//
	// Both were aimed at the wrong number. A weighting changes nothing unless
	// some request is refused today that a weighted budget would admit — and
	// NOTHING IN THIS PROCESS HAS EVER COUNTED A REFUSAL. The cost model cannot
	// be evaluated, however precisely it is measured, until this is non-zero
	// somewhere. That makes the counter the first instrument, not an extra one.
	refused atomic.Uint64
}

// NewLimiter returns a Limiter admitting at most n concurrent holders.
// n < 1 is clamped to 1 so a misconfiguration cannot disable the bound.
func NewLimiter(n int) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{sem: make(chan struct{}, n)}
}

// Acquire takes one slot without blocking. On success it returns a
// release function and a nil error; the caller MUST defer release so the
// slot is returned on every exit path (success, error, timeout, context
// cancel, panic). When the cap is already reached it returns ErrBusy and
// a nil release — do NOT call release in that case.
//
// The returned release is idempotent via sync.Once: an accidental double
// defer cannot over-release and free another caller's slot (which would
// re-open the very DoS window this limiter closes).
func (l *Limiter) Acquire() (release func(), err error) {
	select {
	case l.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.sem }) }, nil
	default:
		l.refused.Add(1)
		return nil, ErrBusy
	}
}

// leaseKey is the private, per-Limiter context key for an in-process admission
// lease (#5880). Keyed by the *Limiter identity so a lease taken on one limiter
// is never mistaken for another's, and UNFORGEABLE from outside the process: the
// type is unexported and context values cannot be constructed from any external
// input (HTTP header / gRPC metadata / request body), so only AcquireCtx below
// can stamp it.
type leaseKey struct{ l *Limiter }

// AcquireCtx is the request-graph-aware form of Acquire (#5880). It admits ONE
// logical scan per in-process request graph instead of once per handler, closing
// the reentrant double-acquire where an outer handler (e.g. a REST list) holds a
// slot and then delegates in-process to another handler (the gRPC session
// service) that acquired the SAME limiter again — self-rejecting its own fan-out
// at capacity.
//
//   - If ctx already carries THIS limiter's in-process admission lease (an
//     ancestor handler in this process already acquired a slot and propagated
//     the returned context), AcquireCtx returns a NO-OP release and ctx unchanged
//     WITHOUT taking a second slot — the nested work reuses the ancestor's
//     admission.
//   - Otherwise it takes a slot exactly like Acquire (fail-fast, ErrBusy over
//     cap) and returns a real release PLUS a child context stamped with the
//     lease. The caller MUST propagate that context to any in-process delegation
//     so the delegate reuses this slot instead of re-acquiring.
//
// The lease is per-REQUEST-GRAPH, NOT global: two DISTINCT external requests each
// begin with an unstamped context and each acquire independently, so the global
// per-node bound is preserved — only NESTED in-process delegation within ONE
// request skips. The lease does NOT cross a process/network boundary (context
// values are process-local and never serialized onto the wire), so a peer node's
// own gRPC entry point sees no lease and acquires its own local slot — remote
// admission is unchanged.
//
// The returned release is idempotent and cancellation-safe on BOTH paths: a real
// slot rides Acquire's sync.Once, and the lease-reuse path is a bare no-op, so a
// deferred release can never over-release another caller's slot.
func (l *Limiter) AcquireCtx(ctx context.Context) (release func(), out context.Context, err error) {
	if ctx.Value(leaseKey{l}) != nil {
		return func() {}, ctx, nil
	}
	rel, err := l.Acquire()
	if err != nil {
		return nil, ctx, err
	}
	return rel, context.WithValue(ctx, leaseKey{l}, struct{}{}), nil
}

// InFlight reports the number of slots currently held. Intended for
// tests and future metrics; it is a point-in-time read.
func (l *Limiter) InFlight() int { return len(l.sem) }

// Refusals reports how many Acquire calls this limiter has rejected at
// capacity since process start. Monotonic; never reset.
//
// It counts REFUSALS, not attempts, and deliberately does not count the
// AcquireCtx lease-reuse path: a nested handler reusing an ancestor's
// admission was never a candidate for refusal, so counting it would inflate
// the number with calls the cap does not govern. Exported as
// xpf_admission_refusals_total (pkg/api), labelled per limiter, so the
// question "is any of these budgets ever actually exhausted" is answerable
// from a running box instead of from argument.
func (l *Limiter) Refusals() uint64 { return l.refused.Load() }

// Cap reports the maximum number of concurrent holders.
func (l *Limiter) Cap() int { return cap(l.sem) }

// DefaultLimiter is the process-wide diagnostic limiter shared by the
// REST and gRPC ping/traceroute handlers, so one aggregate cap covers
// both surfaces (a diagnostic admitted over REST and one admitted over
// gRPC draw from the same MaxConcurrentDiagnostics budget).
var DefaultLimiter = NewLimiter(MaxConcurrentDiagnostics)

// MaxConcurrentSessionWalks bounds how many full session-table walks may run
// at once across EVERY control surface that exposes them — the REST session
// list/summary/zone-pair endpoints and the REST session-clear fallback, plus
// the gRPC GetSessions/GetSessionSummary/GetZonePairSummary RPCs, the ShowText
// "sessions-top:*" scan, the gRPC ClearSessions clear (both the clear-all
// and filtered full-table walks, #5779), and the count-only SessionCount()
// walk reachable via the gRPC GetStatus RPC + the ShowText
// "buffers"/"buffers-detail" (`show system buffers[-detail]`) surfaces (#5782)
// AND the REST /api/v1/status handler (#5939) — share the single
// SessionWalkLimiter below (#5708).
//
// SessionCount draws from the same budget, and #8312 measured it as MORE
// expensive than a list rather than less: it walks BOTH the v4 and v6 maps
// unconditionally with no early exit (`maps_session.go`), paying for the
// reverse companion entries too, where a filtered list can stop at its page.
// The earlier framing here — "count-only (no per-entry alloc/enrich) but the
// same O(table) contention" — was right about allocations and understated the
// syscalls. Charging it the full budget is correct; the reason is the walk, not
// a tie.
//
// WHAT A WALK ACTUALLY COSTS, corrected (#8312). This comment used to say
// "Each walk holds per-bucket BPF-map locks across the whole v4+v6 conntrack
// table while contending with the live dataplane session-sync path". Both
// halves are wrong, and the correction matters because the cost model #7294
// item 2 asks for would have been built on them:
//
//   - The read walks use `Iterate()` — BPF_MAP_GET_NEXT_KEY + BPF_MAP_LOOKUP_ELEM
//     per row, two syscalls, no batching. On a BPF_F_NO_PREALLOC hash map the
//     kernel serves both RCU-read-side (`htab_map_lookup_elem` asserts
//     `rcu_read_lock_held()`); it is the BATCH path that takes
//     `htab_lock_bucket`. So these walks do not hold per-bucket locks at all.
//     The path that does — BatchIterateSessions, whose own comment says it
//     exists "for reduced kernel lock contention" — is used by conntrack GC and
//     cluster session sync and is NOT gated here. That asymmetry is deliberate
//     enough to leave alone (both are internal and self-paced, yielding between
//     batches) but it should not be described backwards.
//   - The "live dataplane session-sync path" is no longer an in-kernel program.
//     Under the userspace dataplane the other writers are the Rust helper's
//     per-session BPF_MAP_UPDATE_ELEM and the Go HA session-sync install.
//
// The bound is still right: 2 syscalls per row over a map sized
// userspaceShimMaxSessions, times N unbounded callers, is real CPU and RCU
// pressure however the kernel locks it. Only the mechanism was misstated.
//
// Before #5708 only the REST endpoints were gated; a gRPC caller could issue
// unbounded full-table scans through the uncovered gRPC surface
// (codex-review-182 M35). The value mirrors the original REST cap
// (#5318/#5433).
//
// WHY THIS IS STILL 1 SLOT PER OPERATION (#7294 item 2 / #8312). A weighted
// model was proposed — charge a full list more than a cursor page. Three
// things stopped it, and they are recorded here so it is not re-derived:
//
//  1. The differentiations mostly are not there. SessionCount is not cheaper
//     than a list (above). A cursor page IS O(rows examined) rather than
//     O(table) — `IterateSessionsFrom` resumes with one NextKey and does not
//     re-walk to the cursor — but "rows examined" equals the page only for an
//     UNFILTERED query; a selective filter walks the whole map for one empty
//     page. The limiter cannot know which at acquire time, so the one real
//     differentiation is not statically expressible.
//  2. Multi-slot acquisition is not available on this primitive. Acquire is a
//     non-blocking send on a buffered channel and there is no atomic
//     multi-send, so W slots means W sends — and a caller that gets 2 of 3 and
//     fails has occupied the budget while being refused, refusing a third
//     caller that would otherwise have been admitted. Today a refusal never
//     costs another caller a slot. See
//     TestMultiSlotAcquireIsNotAvailableOnThisLimiter8312.
//  3. Nothing had ever counted a refusal, so no per-item cost could decide it.
//     Refusals() and xpf_admission_refusals_total exist for that; if they stay
//     at 0 in the field the weighting changes nothing that can be observed.
const MaxConcurrentSessionWalks = 4

// SessionWalkLimiter is the process-wide session-scan limiter shared by the
// REST and gRPC session list/summary handlers, so one aggregate cap covers
// both surfaces: a session scan admitted over REST and one admitted over gRPC
// draw from the same MaxConcurrentSessionWalks budget, and a mix of REST+gRPC
// scrapers cannot collectively exceed it. Mirrors DefaultLimiter.
var SessionWalkLimiter = NewLimiter(MaxConcurrentSessionWalks)

// MaxConcurrentRemoteWalks bounds PEER-DIRECTED session work: a fan-out that
// fetches the cluster peer's session table and drives NO local walk (#7294
// item 3, the #5968 redesign).
//
// Before this, those paths (PeerSessions / PeerSessionSummary /
// PeerZonePairSummary in pkg/grpcapi/peer_only_5968.go) took a slot from
// SessionWalkLimiter. That was deliberate rather than accidental — skipping
// admission entirely would have retired the #5880 lease-propagation guard on
// the path it was written for — but it charges LOCAL scan budget for work that
// touches no local bucket. At capacity 4 shared across REST and gRPC, a burst
// of peer-directed requests could refuse genuine local scans while the local
// table was untouched.
//
// Sized to match MaxConcurrentSessionWalks rather than chosen freely: the
// point is to stop peer work COMPETING with local work, not to loosen what
// bounds it. An unleased peer call was bounded by 4 slots before and is
// bounded by 4 slots now.
//
// GLOBAL, not per-peer. A per-peer budget would fail to bound N peers, which
// is the whole reason to bound a fabric-reachable surface at all. This cluster
// has one peer today, so the distinction is untestable here and is a design
// choice for the general case.
//
// SOLE CONSUMER today: the three peer-only entry points. A shared budget bounds
// the SUM, not each contributor, so adding a consumer here silently tightens it
// for the existing ones — that is a decision to make deliberately, not a
// refactor.
const MaxConcurrentRemoteWalks = 4

// RemoteWalkLimiter is the process-wide budget for peer-directed session work.
// Separate instance, separate budget, mirroring SnapshotReadLimiter (#8151):
// saturating it must not refuse a local scan, and saturating SessionWalkLimiter
// must not refuse a peer fetch. That independence is the whole deliverable and
// is asserted in BOTH directions by the #7294 tests.
var RemoteWalkLimiter = NewLimiter(MaxConcurrentRemoteWalks)

// MaxConcurrentSnapshotReads bounds control-surface reads that copy an
// IN-PROCESS structure rather than walking the conntrack table.
//
// #8151: `show security nat persistent-nat` was charged against
// MaxConcurrentSessionWalks, and it does not walk. `natshow.RenderPersistent`'s
// only dataplane read is `PersistentNATTable.All()` — an O(bindings) snapshot
// copy of a Go map under that table's own RWMutex (#4811). It touches no
// conntrack bucket, holds no session-store lock, and contends with nothing on
// the shared control socket. #6553 introduced the gate describing the topic as
// one of four that "drive full v4+v6 conntrack walks"; that description was
// wrong, and its own line cites point into `RenderPersistentDetail`, a
// different function.
//
// Charging it to the session budget is not merely inaccurate, it is
// exploitable: MaxConcurrentSessionWalks is 4, REST and gRPC alias ONE
// limiter, and `ShowText` is on `fabricAllowedUnaryMethods` — so a cluster peer
// polling `persistent-nat` could hold all four slots and make genuine session
// scans (`GET /api/v1/sessions`, `GetSessions`, `GetStatus`'s SessionCount)
// start refusing.
//
// The bound is KEPT rather than dropped. An O(bindings) allocation on a
// fabric-reachable surface is still worth bounding, and removing a bound from
// a peer-reachable surface is a security-shaped decision that should not be a
// side effect of correcting which budget it draws from. What changes is that
// it no longer competes with full-table scans.
//
// Sized independently of MaxConcurrentSessionWalks on purpose: the two bound
// different costs (a map copy versus per-bucket BPF-map locks held across the
// whole v4+v6 table), so tying them would make one a hostage to the other's
// tuning.
const MaxConcurrentSnapshotReads = 4

// SnapshotReadLimiter is the process-wide limiter for the snapshot-copy reads
// described above. Separate instance, separate budget: saturating it must not
// refuse a session scan, and saturating SessionWalkLimiter must not refuse a
// snapshot read.
var SnapshotReadLimiter = NewLimiter(MaxConcurrentSnapshotReads)

// MaxConcurrentVtyshShellOuts bounds how many FRR `vtysh -c` shell-outs may run
// at once across EVERY control surface that exposes FRR status (#9143).
//
// Every operational FRR read forks a `vtysh` child that runs for up to
// vtyshTimeout (15s, pkg/frr). Before this bound, ONE branch of ONE handler was
// gated: #6809 put ribStreamLimiter on `GET /api/v1/routing/bgp?type=routes`
// because a full-RIB stream is expensive in memory and holds a connection. Every
// other FRR shell-out — REST ospf (both branches) and bgp summary, and the gRPC
// GetOSPFStatus / GetBGPStatus / GetRIPStatus / GetISISStatus / GetRoutes
// status RPCs — forked one child per request with no admission at all, so a
// client chose the concurrency and the server paid up to 15s of forked process
// per request whether or not the client stayed to read the answer.
//
// The one gated branch was RIGHT and UNDER-GENERALIZED, which this package
// already demonstrates twice: DefaultLimiter bounds the other REST/gRPC handlers
// that fork a child (ping/traceroute, #5057, for exactly the "cannot exhaust
// host PIDs/FDs/goroutines" reason), and SessionWalkLimiter bounds every
// full-table walk on both surfaces (#5433/#5708). A forking FRR status handler
// is the same class as a forking ping handler; it was simply never gated.
//
// The bound is enforced in pkg/frr's single Manager.vtysh funnel rather than at
// each handler, so a future FRR read is bounded by construction and cannot
// re-open the gap by being added without a gate.
//
// Sized independently of MaxConcurrentDiagnostics: a monitoring system polling
// `show ip ospf neighbor` must not refuse an operator's ping, and vice versa.
// The value is deliberately small — legitimate use is a handful of concurrent
// status reads — while the 15s per-child cap plus this aggregate bound together
// cap the worst-case BUFFERED footprint at MaxConcurrentVtyshShellOuts children.
//
// #9755: BUFFERED is the operative word, and it used to be missing. The one
// STREAMING FRR read (pkg/frr's StreamBGPRoutes, reached only by
// `GET /api/v1/routing/bgp?type=routes`) does not pass through the funnel and
// takes no slot here. It is bounded instead by pkg/api's ribStreamLimiter
// (capacity 2) and a 10-minute progress budget, because a full-RIB stream needs
// far longer than 15s and must not hold a quarter of this budget while it runs.
//
// The whole-process worst case is therefore MaxConcurrentVtyshShellOuts buffered
// children PLUS maxConcurrentRIBStreams streaming ones — six, not four. Stated
// here rather than left implicit, because this constant is where a reader comes
// to find the number.
const MaxConcurrentVtyshShellOuts = 4

// VtyshLimiter is the process-wide limiter for FRR vtysh shell-outs, shared by
// the REST and gRPC FRR status surfaces so one aggregate cap covers both.
// Mirrors DefaultLimiter and SessionWalkLimiter.
var VtyshLimiter = NewLimiter(MaxConcurrentVtyshShellOuts)

// NamedLimiter pairs a process-wide limiter with the label it is exported under
// (xpf_admission_refusals_total{limiter="..."}).
type NamedLimiter struct {
	Name    string
	Limiter *Limiter
}

// AllLimiters returns every process-wide admission limiter this package
// defines, with its metric label.
//
// It lives HERE, beside the limiters themselves, rather than in the metrics
// collector that consumes it, because the registry had already drifted: the
// collector's list named session_walk, remote_walk and diagnostic, and
// SnapshotReadLimiter — added later, in this same file — was never added to it.
// Its refusals therefore read as a permanent 0, which is precisely the reading
// #8312 exists to make trustworthy ("if these stay at 0 the weighting buys
// nothing"): an unregistered limiter is indistinguishable from a never-refusing
// one.
//
// Keeping the list three lines from the `var` it must contain removes the
// decision instead of adding a step to remember. TestAllLimitersIsExhaustive
// (pkg/diagcmd) fails if a limiter defined in this file is missing here.
func AllLimiters() []NamedLimiter {
	return []NamedLimiter{
		{"session_walk", SessionWalkLimiter},
		{"remote_walk", RemoteWalkLimiter},
		{"diagnostic", DefaultLimiter},
		{"snapshot_read", SnapshotReadLimiter},
		{"vtysh", VtyshLimiter},
	}
}
