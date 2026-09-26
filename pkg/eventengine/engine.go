// Package eventengine implements Junos-style event-options policy execution.
// It watches RPM probe events and applies configuration changes when policies match.
//
// Robustness contract (#2139/#2140/#2141/#2157):
//
//   - #2139 transactional batch: a change-configuration action either commits
//     in full or applies nothing. ThenCommands are pre-classified into a typed
//     plan BEFORE the candidate is touched, applied to the candidate,
//     validated with CommitCheck, then committed; ANY failure discards the
//     candidate (ExitConfigure) — never a half-applied config.
//   - #2140 cooldown survives reload: per-policy runtime state (sliding
//     windows + last-trigger) is reconciled (not recreated) on every Apply,
//     carried forward when (policy name, semantic revision) is unchanged.
//     The cooldown is armed on a SUCCESSFUL commit, not at evaluate time, so a
//     dropped/queued action does not consume the cooldown.
//   - #2141 fail-closed matcher: a malformed/unknown attributes-match line is
//     rejected at commit (config.ValidateEventAttributesMatchStrict); on the
//     legacy lenient-load path the runtime matcher fails CLOSED (the policy
//     does not fire) rather than dropping the constraint and over-firing.
//   - #3751 fail-closed temporal gate: a `within <seconds> { trigger
//     (on|until) <count>; }` numeric typo is rejected at commit
//     (config.validateEventOptionsWithinAST); on the legacy lenient-load path
//     a within clause with no usable positive threshold (a leftover 0 from an
//     older binary that silently coerced the typo) fails CLOSED in
//     withinMatches (the policy does not fire) rather than treating the 0 as
//     an unconditional match and always-firing the remediation.
//   - #2157 fail-safe queue: actions run on a single serialized worker
//     goroutine (removing the cross-probe EnterConfigure race) with bounded
//     backoff retry on a held config lock (configstore.ErrConfigLocked) and
//     drop/retry/commit counters, instead of silently dropping on lock-held.
//   - #10874 HA publication gate: an RG0 secondary keeps accepted event-options
//     remediation actions pending until promotion reopens publication. A
//     read-only rejection is deferred, not consumed; this is necessary because
//     RPM emits failure events on status edges, not on every failed cycle.
//   - #3750 revalidate-before-commit: a pre-classified action carries the
//     policy's semantic revision AS OF EVALUATE TIME. Immediately before it
//     commits — under e.mu and while holding the config lock (EnterConfigure),
//     so no operator commit can interleave — the worker revalidates it against
//     live engine state and DROPS it (counted dropped_stale) if the policy was
//     removed, was redefined (semRev mismatch), or is now inside its cooldown.
//     This folds three fail-opens into one gate: a removed policy's stale batch,
//     a same-name redefine's OLD command set, and a queued duplicate that raced
//     the arm-on-commit cooldown all stop firing instead of mutating config no
//     active policy authorizes.
//   - #5311 revision-aware cooldown arm: the arm-on-commit stamp is CONDITIONAL
//     on the live runtime still being the same generation (semantic revision)
//     that authorized the action. A remediation whose own commit redefines the
//     triggering policy (R1 -> R2) reconciles a FRESH re-armed runtime through
//     the commit callback's Apply; armCooldown must not stamp that successor R2
//     with R1's completion time (a name-based ABA that would suppress the
//     re-armed R2 for the whole cooldown, contradicting the "a redefined policy
//     re-arms" contract). The identity check and stamp run together under e.mu
//     so a concurrent Apply cannot swap the runtime between them.
package eventengine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

// CommitFn atomically promotes the candidate to active and applies
// it to the dataplane. The daemon's commitAndApply implementation
// holds the apply semaphore across both steps so the engine's
// commit can't interleave with another caller's commit/apply pair.
//
// Its return is TRI-STATE (#5063), and the returned *config.Config — not
// the error — is the authority on whether the generation was promoted:
//
//   - (compiled != nil, nil): committed, active, dataplane armed. Success.
//   - (compiled != nil, err): committed, active, dataplane armed, but a
//     BEST-EFFORT subsystem (networkd write / Kea restart / host-inbound nft;
//     daemon_apply.go applyAndSyncCommitted) is in DEBT. The generation is
//     live — this is NOT a rejection. The engine records it as committed
//     (arms cooldown) and additionally counts the debt (#5063).
//   - (nil, err): the commit did NOT promote (bootstrap gate, compile/commit
//     failure, or a required-protocol-gate that DISARMED the dataplane). This
//     is the only genuine rejection.
type CommitFn func(ctx context.Context, comment string) (*config.Config, error)

// Maximum event-options commit attempts in a rolling window, shared across all
// policies. This caps the commit rate at four per minute while preserving a
// four-action burst for simultaneous legitimate failures.
const (
	globalActionBudget       = 4
	globalActionBudgetWindow = time.Minute
)

// Minimum time between successive triggers of the same policy.
const policyCooldown = 30 * time.Second

// Backoff schedule for a held config lock (#2157). The worker retries an
// action whose EnterConfigure fails with ErrConfigLocked until the deadline,
// then drops it (counted). A non-lock error is permanent (no retry).
const (
	lockRetryInitial  = 200 * time.Millisecond
	lockRetryMax      = 5 * time.Second
	lockRetryDeadline = 60 * time.Second
)

// Stats is the observable counter snapshot surfaced to pkg/api (#2157). All
// fields are cumulative since daemon start except QueueDepth, which is the
// instantaneous number of queued-but-not-yet-applied actions.
type Stats struct {
	Committed           uint64 // actions whose batch committed successfully (INCLUDES committed-with-apply-debt, #5063)
	CommittedWithDebt   uint64 // subset of Committed that promoted+armed but left a best-effort subsystem in debt (#5063)
	Rejected            uint64 // actions rejected (bad plan / CommitCheck / commit not promoted)
	Retried             uint64 // retry attempts after a held config lock
	DroppedQueueFull    uint64 // actions genuinely dropped: the queue was full of OTHER policies (a distinct policy could not fit, or a survivor was lost) — capacity loss, alert-worthy
	Superseded          uint64 // same-policy queued actions REPLACED by a newer trigger (benign dedup; nothing lost — the newer equivalent action runs) (#5853)
	DroppedLockHeld     uint64 // actions dropped after the lock-retry deadline elapsed
	DroppedStale        uint64 // actions dropped at commit: policy removed/redefined or cooldown active (#3750)
	DroppedGlobalBudget uint64 // actions refused by the cross-policy rolling action budget (#10871)
	// DroppedShutdown counts queued or in-flight-retry actions abandoned by Close
	// (#9916 F-131). Deliberately NOT surfaced to Prometheus: it increments at
	// process exit and would never be scraped. Explicit accounting (test-observable
	// via Stats) plus the shutdown INFO log are the operator signal.
	DroppedShutdown   uint64 // actions abandoned on shutdown (queued at Close + in-flight retries)
	AttributesInvalid uint64 // runtime fail-closed: malformed/unknown attributes-match line
	PlantClassInvalid uint64 // payloads refused for missing/denied planting class (#9984)
	QueueDepth        int64  // currently queued actions
}

// engineCounters holds the atomic counters behind Stats.
type engineCounters struct {
	committed           atomic.Uint64
	committedWithDebt   atomic.Uint64
	rejected            atomic.Uint64
	retried             atomic.Uint64
	droppedQueueFull    atomic.Uint64
	superseded          atomic.Uint64
	droppedLockHeld     atomic.Uint64
	droppedStale        atomic.Uint64
	droppedGlobalBudget atomic.Uint64
	droppedShutdown     atomic.Uint64
	attributesInvalid   atomic.Uint64
	plantClassInvalid   atomic.Uint64
	queueDepth          atomic.Int64
}

// plannedOp is one classified ThenCommand: a candidate set or delete.
type plannedOp struct {
	isDelete bool
	// critical marks mutations under security or firewall; they may pass
	// ordinary queued actions to bound security-remediation latency.
	critical bool
	// raw "set" input (without the leading "set ") for store.SetFromInput.
	setInput string
	// parsed delete path for store.Delete.
	delPath []string
	raw     string // original command text, for logging
}

// plannedAction is a fully pre-classified remediation enqueued for the worker.
// It carries no engine lock and no live runtime state — only the policy
// identity (name + the semantic revision observed AT EVALUATE TIME) and the
// typed plan. The worker applies the plan without re-reading it, but it DOES
// revalidate the identity against live engine state immediately before commit
// (#3750): a queued action for a policy that was removed, redefined, or is now
// in its cooldown must NOT commit — it is dropped as stale. Before #3750 the
// worker committed the batch unconditionally, so a removed/redefined policy's
// stale command set still mutated config, and a cooldown-window duplicate
type plannedAction struct {
	policyName string
	// semRev is the policy's semantic revision (policySemanticRevision) as of
	// the evaluate that enqueued the action. The worker drops the action if the
	// live revision no longer matches (policy redefined) or is absent (removed).
	semRev      string
	policyOrder int
	// plantClass is the authenticated class that authored this payload. It is
	// checked again immediately before any candidate mutation.
	plantClass string
	// Triggering-event context, captured at evaluate time so the worker can
	// stamp a deterministic audit description on the remediation commit (#3754).
	// A security appliance that mutates its own config autonomously must record
	// in commit/rollback history WHICH policy fired and WHY.
	event     string
	testOwner string
	testName  string
	ops       []plannedOp
}

// triggeredPolicy pairs a policy that should fire with the semantic revision its
// runtime carried at evaluate time (#3750). evaluateEvent returns these so
// HandleEvent can stamp each enqueued action with the revision the worker
// revalidates against before committing.
type triggeredPolicy struct {
	pol    *config.EventPolicy
	semRev string
	order  int
}

// policyRuntime is the per-policy temporal/cooldown state. It is split from the
// immutable EventPolicy config so it can be carried forward across an Apply
// (reconcile-not-recreate, #2140) keyed by (name, semantic revision).
type policyRuntime struct {
	// event name -> sliding window of trigger timestamps.
	windows map[string][]time.Time
	// last successful-commit time for this policy (cooldown anchor). Zero
	// means "never triggered". Armed by the worker after a successful commit,
	// not at evaluate time (#2157 SMR finding 3).
	lastTrigger time.Time
	// event name -> edge latch for a `within { trigger on N }` clause
	// (#3756 M1). Set (true) after the policy fires on a threshold CROSSING;
	// cleared (re-armed) by withinMatches the moment the in-window count drops
	// back below N. So a SUSTAINED above-threshold level fires the remediation
	// ONCE per crossing instead of re-firing every cooldown (Junos `trigger on`
	// is edge-, not level-triggered).
	onLatched map[string]bool
}

func newPolicyRuntime() *policyRuntime {
	return &policyRuntime{
		windows:   make(map[string][]time.Time),
		onLatched: make(map[string]bool),
	}
}

// Engine evaluates event-options policies against RPM events.
type Engine struct {
	mu       sync.Mutex
	policies []*config.EventPolicy
	store    *configstore.Store
	commitFn CommitFn

	// authzCfg and enforcePlantClass are refreshed atomically with Apply. The
	// worker snapshots them under e.mu immediately before candidate mutation so
	// a policy cannot use an authorization decision from enqueue time.
	authzCfg          *config.Config
	enforcePlantClass bool

	// runtime holds per-policy temporal/cooldown state keyed by policy NAME.
	// Reconciled (carried forward) on Apply when the policy semantic revision
	// is unchanged (#2140).
	runtime map[string]*policyRuntime
	// semRev records the policy semantic revision each runtime was built
	// for, so Apply can decide carry-forward vs reset.
	semRev map[string]string

	// Compiled attributes-match regexes, keyed by the raw pattern string.
	regexCache map[string]*regexp.Regexp

	// eventIndex maps an event NAME to the policies that list it.
	eventIndex  map[string][]*config.EventPolicy
	policyOrder map[string]int

	counters engineCounters

	// Global commit budget (#10871). The fixed-size timestamp ring is protected
	// by budgetMu; at most globalActionBudget timestamps are retained.
	// budgetCursor rotates policy order so a sustained multi-policy storm cannot
	// permanently favor the first policies in the config.
	budgetMu     sync.Mutex
	budgetTimes  [globalActionBudget]time.Time
	budgetStart  int
	budgetCount  int
	budgetCursor int

	// Action queue + single worker (#2157). actions is bounded; the worker is
	// the ONLY goroutine that enters configure mode on the engine's behalf, so
	// the cross-probe EnterConfigure race cannot occur.
	actions   chan plannedAction
	workerWG  sync.WaitGroup
	stopOnce  sync.Once
	stopCh    chan struct{}
	startOnce sync.Once

	// enqueueMu serializes ALL producer-side queue mutation (#5062). HandleEvent
	// releases e.mu (evaluateEvent returns) BEFORE it enqueues, so many RPM-probe
	// goroutines run enqueue concurrently. Every enqueue runs supersede (#5853),
	// which DRAINS the accepted actions into a private slice (opening slots),
	// drops any same-policy entry, and then best-effort re-enqueues the survivors.
	// Without a producer lock a SECOND concurrent producer — via its own supersede
	// — takes those drain-freed slots between the drain and the re-enqueue, so
	// supersede's refill `default` branch DROPS a survivor (an already-accepted
	// action for a DIFFERENT policy), losing it and its FIFO position (miscounted
	// droppedQueueFull). Holding enqueueMu across the WHOLE enqueue (the supersede
	// drain+refill) makes the drain->re-enqueue atomic w.r.t. other producers: the
	// only concurrent actor left is the consumer (actionWorker), which only
	// REMOVES items, so a drain-freed slot can never be re-filled by anyone but
	// supersede itself and a survivor is preserved exactly once, in FIFO order.
	//
	// Lock ordering (no cycle, no deadlock): enqueueMu is a producer-only LEAF
	// lock. It is NEVER held while e.mu is held (enqueue runs after evaluateEvent
	// has released e.mu), and the consumer/worker path (runAction -> staleReason /
	// armCooldown, which take e.mu) NEVER takes enqueueMu — the two locks are
	// never nested in either order. Every channel op performed under enqueueMu is
	// a non-blocking select-with-default, and the consumer never holds enqueueMu,
	// so the queue always drains and no producer can block indefinitely.
	//
	// #7636: the two sides of this invariant now live in DIFFERENT FILES —
	// enqueueMu's users in queue.go, e.mu's in evaluate.go and here. That makes
	// the rule easier to break by accident, because the locks are no longer
	// visible on one screen, so it is restated at the top of both files. If you
	// are adding a call from one to the other, that is the invariant you are
	// about to test.
	enqueueMu sync.Mutex

	// lifeCtx is the engine-lifetime context threaded into the remediation
	// commit (#2868). It is cancelled by Close() at the same time stopCh is
	// closed, so a remediation commit in flight at daemon shutdown (which
	// drives netlink updates, an FRR reload, and Rust dataplane sync — seconds
	// of work) is cancelled cleanly instead of blocking termination past the
	// systemd TimeoutStopSec SIGKILL. lifeCancel is its cancel func.
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	// Per-policy throttle for the runtime fail-closed warning so a flapping
	// probe with a legacy malformed line cannot flood the log. Keyed by policy
	// name (#4423 M11): a single global throttle let a bad line on ONE policy
	// swallow the FIRST warning about a DIFFERENT policy's distinct bad line, so
	// a real second problem could stay silent for the whole 10s window. Guarded
	// by its own mutex (not e.mu) so it is safe even when attributesMatch is
	// exercised directly by a matcher-only test that does not hold e.mu.
	invalidWarnMu sync.Mutex
	invalidWarnAt map[string]int64

	// Injectable clock for tests; nil means time.Now.
	nowFn func() time.Time

	// afterDrainFn is a test-only seam (#5062). When non-nil, supersede invokes
	// it exactly at the drain->re-enqueue boundary (after the queue has been
	// drained into the private survivor slice, before the survivors are
	// re-enqueued) so a test can deterministically drive a concurrent producer
	// into the freed slots and assert the fix serializes it. nil in production —
	// supersede is not a hot path (it fires only on a full-queue overflow), so a
	// single nil-check is negligible.
	afterDrainFn func()

	// Injectable retry-backoff timer for tests; nil means newRetryTimer
	// (backed by time.NewTimer). Returns the fire channel plus a stop func
	// that releases the underlying timer when the retry is cancelled before
	// the backoff elapses (#2890 — a plain time.After cannot be stopped, so
	// its runtime timer leaks until it fires). A test can substitute this to
	// assert the stop func is invoked on the stopCh branch.
	newTimerFn func(time.Duration) (<-chan time.Time, func() bool)

	// Lock-retry tuning, overridable in tests. Zero means the package
	// defaults (lockRetryInitial/Max/Deadline).
	retryInitial  time.Duration
	retryMax      time.Duration
	retryDeadline time.Duration
	// publishEnabled is the HA publication gate. A standby keeps accepted
	// remediations pending until RG0 promotion opens the gate.
	publishEnabled atomic.Bool
	publishWake    chan struct{}
}

func (e *Engine) lockRetryInitial() time.Duration {
	if e.retryInitial > 0 {
		return e.retryInitial
	}
	return lockRetryInitial
}

func (e *Engine) lockRetryMax() time.Duration {
	if e.retryMax > 0 {
		return e.retryMax
	}
	return lockRetryMax
}

func (e *Engine) lockRetryDeadline() time.Duration {
	if e.retryDeadline > 0 {
		return e.retryDeadline
	}
	return lockRetryDeadline
}

// New creates an event engine. commitFn is the daemon's atomic
// commit+apply callback (see #846); when non-nil, the engine routes
// its committed configs through it so they serialize with HTTP/gRPC
// commits. When nil (tests), commits succeed but no apply runs.
//
// The action worker is started lazily on the first HandleEvent so a
// matcher-only test (New(nil, nil) + attributesMatch) never spawns a
// goroutine. Call Close() from the daemon shutdown path to stop it.
func New(store *configstore.Store, commitFn CommitFn) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		store:         store,
		commitFn:      commitFn,
		runtime:       make(map[string]*policyRuntime),
		semRev:        make(map[string]string),
		regexCache:    make(map[string]*regexp.Regexp),
		eventIndex:    make(map[string][]*config.EventPolicy),
		policyOrder:   make(map[string]int),
		invalidWarnAt: make(map[string]int64),
		actions:       make(chan plannedAction, actionQueueDepth),
		stopCh:        make(chan struct{}),
		publishWake:   make(chan struct{}, 1),
		lifeCtx:       ctx,
		lifeCancel:    cancel,
	}
	e.publishEnabled.Store(true)
	return e
}

func (e *Engine) now() time.Time {
	if e.nowFn != nil {
		return e.nowFn()
	}
	return time.Now()
}

// pruneGlobalBudgetLocked expires commit attempts outside the rolling window.
// The caller holds budgetMu.
func (e *Engine) pruneGlobalBudgetLocked(now time.Time) {
	for e.budgetCount > 0 {
		oldest := e.budgetTimes[e.budgetStart]
		if now.Sub(oldest) < globalActionBudgetWindow {
			break
		}
		e.budgetTimes[e.budgetStart] = time.Time{}
		e.budgetStart = (e.budgetStart + 1) % globalActionBudget
		e.budgetCount--
	}
}

func (e *Engine) globalBudgetAvailable() bool {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	e.pruneGlobalBudgetLocked(e.now())
	return e.budgetCount < globalActionBudget
}

// reserveGlobalCommit accounts one commit attempt. The worker is serialized,
// so a reservation is made only when it is ready to enter the commit callback.
func (e *Engine) reserveGlobalCommit(policyOrder int) bool {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	now := e.now()
	e.pruneGlobalBudgetLocked(now)
	if e.budgetCount == globalActionBudget {
		return false
	}
	next := (e.budgetStart + e.budgetCount) % globalActionBudget
	e.budgetTimes[next] = now
	e.budgetCount++
	e.budgetCursor = policyOrder + 1
	return true
}

// newRetryTimer returns the backoff fire channel plus a stop func for the
// runAction retry select (#2890). Using an explicit time.NewTimer (rather than
// time.After) lets the retry release the runtime timer immediately when stopCh
// fires before the backoff elapses, instead of leaking an armed timer until it
// fires on shutdown/restart churn. The stop func reports whether it stopped the
// timer before it fired (so a caller may drain a fired-but-unread channel),
// mirroring time.Timer.Stop. Overridable in tests via newTimerFn.
func (e *Engine) newRetryTimer(d time.Duration) (<-chan time.Time, func() bool) {
	if e.newTimerFn != nil {
		return e.newTimerFn(d)
	}
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// Apply loads new event-options policies, RECONCILING per-policy runtime state
// rather than recreating it (#2140): cooldown/window memory is carried forward
// for any policy whose (name, semantic revision) is unchanged, and dropped for
// removed or semantically-changed policies. This is the proven pkg/ipmon
// pattern. It also fixes the self-wipe: the engine's own remediation commit
// re-enters Apply with the SAME policy set (same revision) → state survives →
// the cooldown holds.
//
// Rebuilds the compiled-regex cache for every attributes-match pattern so the
// event hot path (HandleEvent) never compiles a regex per event; the cache is
// derived purely from config (not runtime state) so rebuilding it is cheap and
// correct.
// Apply is the strict execution API. It has no authorization snapshot, so
// only an explicitly stamped superuser payload can fire; legacy payloads are
// quarantined. Production daemon wiring uses ApplyWithConfig to also resolve
// the active login-class policy at fire time.
func (e *Engine) Apply(policies []*config.EventPolicy) {
	e.apply(policies, nil, true)
}

// ApplyWithConfig loads policies and the active login-class configuration.
// The worker reuses the latest snapshot at fire time, immediately before any
// candidate mutation.
func (e *Engine) ApplyWithConfig(policies []*config.EventPolicy, cfg *config.Config) {
	e.apply(policies, cfg, true)
}

func (e *Engine) apply(policies []*config.EventPolicy, cfg *config.Config, enforcePlantClass bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.authzCfg = cfg
	e.enforcePlantClass = enforcePlantClass
	e.policies = policies

	nextRuntime := make(map[string]*policyRuntime, len(policies))
	nextRev := make(map[string]string, len(policies))
	for _, pol := range policies {
		if pol == nil {
			continue
		}
		rev := policySemanticRevision(pol)
		if prev, ok := e.runtime[pol.Name]; ok && e.semRev[pol.Name] == rev {
			// Same policy, unchanged semantics: carry forward live state.
			nextRuntime[pol.Name] = prev
		} else {
			// New, removed-and-readded, or redefined policy: re-arm.
			nextRuntime[pol.Name] = newPolicyRuntime()
		}
		nextRev[pol.Name] = rev
	}
	e.runtime = nextRuntime
	e.semRev = nextRev

	// #4423 (review follow-up): drop the per-policy invalid-warning throttle
	// entries for policies no longer present, so the map stays bounded to the
	// live policy set instead of accumulating a stamp per name ever seen. The
	// map is config-name-bounded either way; this keeps it tidy across churn.
	// Lock order matches the evaluate path (e.mu already held, then
	// invalidWarnMu — a leaf lock never held while acquiring e.mu).
	e.invalidWarnMu.Lock()
	for name := range e.invalidWarnAt {
		if _, ok := nextRev[name]; !ok {
			delete(e.invalidWarnAt, name)
		}
	}
	e.invalidWarnMu.Unlock()

	e.regexCache = make(map[string]*regexp.Regexp)
	for _, pol := range policies {
		if pol == nil {
			continue
		}
		for _, attr := range pol.AttributesMatch {
			pattern, ok := config.EventAttributesMatchPattern(attr)
			if !ok {
				continue
			}
			if _, cached := e.regexCache[pattern]; cached {
				continue
			}
			// Patterns are validated at commit; a compile failure here
			// should not happen. Log and skip so a single bad pattern
			// can never wedge the engine.
			re, err := regexp.Compile(pattern)
			if err != nil {
				slog.Warn("event-options: skipping uncompilable attributes-match pattern",
					"policy", pol.Name, "pattern", pattern, "err", err)
				continue
			}
			e.regexCache[pattern] = re
		}
	}

	// Rebuild the event-name -> policies index (#4423 M6) so evaluateEvent
	// touches only the policies that list the fired event. Dedup per policy so a
	// policy that (legacy config) lists the same event name twice is still
	// evaluated once — matching the old eventMatches "return on first match".
	e.eventIndex = make(map[string][]*config.EventPolicy)
	e.policyOrder = make(map[string]int, len(policies))
	for order, pol := range policies {
		if pol == nil {
			continue
		}
		e.policyOrder[pol.Name] = order
		seen := make(map[string]struct{}, len(pol.Events))
		for _, ev := range pol.Events {
			if _, dup := seen[ev]; dup {
				continue
			}
			seen[ev] = struct{}{}
			e.eventIndex[ev] = append(e.eventIndex[ev], pol)
		}
	}
}

// policySemanticRevision is a cheap deterministic hash of the match/action
// fields that define a policy's behavior (#2140). If it is unchanged across an
// Apply, the policy is "the same policy" and its cooldown/window memory is
// preserved; if any of these change, the policy is treated as redefined and
// re-arms. Fields included: Events, AttributesMatch (sorted — order does not
// change semantics), WithinClauses, ThenCommands. The policy NAME is the map
// key and is therefore not hashed.
func policySemanticRevision(pol *config.EventPolicy) string {
	h := sha256.New()
	writeField := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	writeField("events")
	// Sort the event names before hashing (#4423 L4): the event list is a SET —
	// `events [ a b ]` and `events [ b a ]` are the same policy — so a bare
	// reorder must NOT change the semantic revision and re-arm (wiping the live
	// cooldown/window state carried forward across an Apply). This mirrors the
	// AttributesMatch treatment below; ThenCommands stay ordered because command
	// order IS semantic.
	events := append([]string(nil), pol.Events...)
	sort.Strings(events)
	for _, ev := range events {
		writeField(ev)
	}
	writeField("attrs")
	attrs := append([]string(nil), pol.AttributesMatch...)
	sort.Strings(attrs)
	for _, a := range attrs {
		writeField(a)
	}
	writeField("within")
	for _, wc := range pol.WithinClauses {
		if wc == nil {
			writeField("nil")
			continue
		}
		writeField(strconv.Itoa(wc.Seconds) + "/" +
			strconv.Itoa(wc.TriggerOn) + "/" +
			strconv.Itoa(wc.TriggerUntil))
	}
	writeField("then")
	for _, cmd := range pol.ThenCommands {
		writeField(cmd)
	}
	writeField("plant-class")
	writeField(pol.PlantClass)
	sum := h.Sum(nil)
	return string(sum)
}

// HandleEvent is the callback for RPM events. It evaluates policies under lock,
// pre-classifies the ThenCommands of every triggered policy into a typed plan
// (rejecting a malformed plan BEFORE it can occupy a queue slot), and enqueues
// the validated actions onto the single worker (#2139/#2157). The actual
// configure/commit happens off this caller goroutine on the worker, so many
// probe goroutines may call HandleEvent concurrently without racing on the
// config lock. Concurrent enqueues are serialized by enqueueMu so a full-queue
// supersede cannot lose an already-accepted action to a racing producer (#5062).
// Within each event, policy order rotates after every budgeted commit to avoid
// permanently favoring the same policies in a sustained cross-policy flap.
func (e *Engine) HandleEvent(ev rpm.Event) {
	e.startOnce.Do(e.startWorker)
	triggered := e.evaluateEvent(ev)
	if len(triggered) == 0 {
		return
	}

	e.budgetMu.Lock()
	cursor := e.budgetCursor
	e.budgetMu.Unlock()
	start := 0
	for i, tp := range triggered {
		if tp.order >= cursor {
			start = i
			break
		}
	}
	for offset := range triggered {
		tp := triggered[(start+offset)%len(triggered)]
		ops, ok := e.classifyPlan(tp.pol)
		if !ok {
			// Malformed/unknown command: reject the whole batch before it can
			// take a queue slot or a lock (#2139 pre-classify).
			e.counters.rejected.Add(1)
			continue
		}
		if len(ops) == 0 {
			continue // nothing to do
		}
		// Stamp the action with the policy's semantic revision as of this
		// evaluate (#3750) so the worker can revalidate it against live engine
		// state before committing, plus the triggering-event context (#3754)
		// for the remediation commit's audit description.
		if !e.enqueue(plannedAction{
			policyName:  tp.pol.Name,
			semRev:      tp.semRev,
			policyOrder: tp.order,
			plantClass:  tp.pol.PlantClass,
			event:       ev.Name,
			testOwner:   ev.TestOwner,
			testName:    ev.TestName,
			ops:         ops,
		}) {
			// fire. evaluateEvent already armed the edge latch for it; leaving
			// it armed makes withinMatches suppress every later at/above-
			// threshold event until some clause drops below its threshold —
			// which, for the sustained fault the remediation exists to fix,
			// never happens. Roll it back so the next event retries.
			e.releaseEdgeLatch(tp.pol.Name, ev.Name, tp.semRev)
		}
	}
}

// startWorker launches the single action worker. Idempotent via startOnce.
func (e *Engine) startWorker() {
	e.workerWG.Add(1)
	go e.actionWorker()
}

// Close stops the action worker and explicitly abandons any queued or in-flight
// actions (#9916 F-131). Safe to call even if the worker was never started, and
// safe to call twice (the second drain finds an empty queue). Called from the
// daemon shutdown path.
//
// Shutdown does NOT run the queued remediations: up to 64 serial commits (each
// with a 60s lock-retry deadline plus FRR reload and Rust sync) would risk the
// systemd TimeoutStopSec, and the lifetime context is already cancelled so the
// commits would abort anyway. Instead every abandoned action is counted in
// DroppedShutdown, the queue gauge is reset to zero, and a single INFO log names
// the count — the drain the old docstring claimed, made honest.
func (e *Engine) Close() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		// Cancel the lifetime context so a remediation commit in flight
		// (commitFn) aborts cleanly on shutdown (#2868).
		if e.lifeCancel != nil {
			e.lifeCancel()
		}
	})
	e.workerWG.Wait()
	// Single drainer: the worker already exited (it returns on stopCh without
	// draining), so Close owns the remaining buffered actions. Held under
	// enqueueMu so no placer can land post-drain: any enqueue that passed the
	// stopCh fast-exit check completes before this critical section, and any
	// after blocks then sees the closed stopCh and refuses. enqueueMu is a
	// producer-only leaf (never with e.mu), the drain is non-blocking, and the
	// worker is gone — no deadlock, no shutdown delay.
	e.enqueueMu.Lock()
	var abandoned uint64
drain:
	for {
		select {
		case <-e.actions:
			e.counters.queueDepth.Add(-1)
			abandoned++
		default:
			break drain
		}
	}
	e.enqueueMu.Unlock()
	if abandoned > 0 {
		e.counters.droppedShutdown.Add(abandoned)
		slog.Info("event-options: remediations abandoned on shutdown",
			"count", abandoned)
	}
}

// PolicyCount returns the number of event-options policies the engine
// currently has loaded. It is the observable seam for the daemon reconcile
// tests (#3752): after the first policy is enabled on a running daemon the
// engine must hold it, so a day-2 enable actually takes effect.
func (e *Engine) PolicyCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.policies)
}

// Stats returns a snapshot of the observable counters (#2157), surfaced to
// pkg/api for the xpf_event_actions_* metric family.
func (e *Engine) Stats() Stats {
	return Stats{
		Committed:           e.counters.committed.Load(),
		CommittedWithDebt:   e.counters.committedWithDebt.Load(),
		Rejected:            e.counters.rejected.Load(),
		Retried:             e.counters.retried.Load(),
		DroppedQueueFull:    e.counters.droppedQueueFull.Load(),
		Superseded:          e.counters.superseded.Load(),
		DroppedLockHeld:     e.counters.droppedLockHeld.Load(),
		DroppedStale:        e.counters.droppedStale.Load(),
		DroppedGlobalBudget: e.counters.droppedGlobalBudget.Load(),
		DroppedShutdown:     e.counters.droppedShutdown.Load(),
		AttributesInvalid:   e.counters.attributesInvalid.Load(),
		PlantClassInvalid:   e.counters.plantClassInvalid.Load(),
		QueueDepth:          e.counters.queueDepth.Load(),
	}
}

// actionWorker is the single goroutine that applies remediation actions. It
// serializes all configure/commit on behalf of the engine (removing the
// cross-probe race) and retries a held config lock with bounded backoff.
func (e *Engine) actionWorker() {
	defer e.workerWG.Done()
	for {
		select {
		case <-e.stopCh:
			return
		case a := <-e.actions:
			e.counters.queueDepth.Add(-1)
			e.runAction(a)
		}
	}
}

// runAction applies one pre-classified action transactionally (#2139) with
// bounded lock-held retry (#2157). On a successful commit it arms the policy's
// cooldown (#2140 SMR finding 3 — arm on commit, not at evaluate, so a
// dropped/rejected action never consumes the cooldown).
func (e *Engine) runAction(a plannedAction) {
	deadline := time.Time{}
	budgetChecked := false
	backoff := e.lockRetryInitial()
	maxBackoff := e.lockRetryMax()
	for {
		if !e.waitForPublishEnabled() {
			e.counters.droppedShutdown.Add(1)
			slog.Info("event-options: remediation abandoned on shutdown (HA publication gate)",
				"policy", a.policyName)
			return
		}
		if !budgetChecked {
			if !e.globalBudgetAvailable() {
				e.dropGlobalBudget(a)
				return
			}
			budgetChecked = true
		}
		if deadline.IsZero() {
			// Read-only HA deferral is unbounded and must not consume the
			// separate deadline for a transient operator-held config lock.
			deadline = e.now().Add(e.lockRetryDeadline())
			backoff = e.lockRetryInitial()
		}
		err := e.applyOnce(e.commitContext(), a)
		if err == nil {
			e.counters.committed.Add(1)
			// Arm the cooldown against the SAME generation that authorized this
			// action (#5311). a.semRev is the policy's semantic revision as of
			// the evaluate that enqueued the action; staleReason already proved
			// it still matched live state at commit time. Passing it lets
			// armCooldown skip the stamp if this action's OWN commit redefined
			// the policy (R1 -> R2), which reconciled a fresh re-armed runtime.
			e.armCooldown(a.policyName, a.semRev)
			slog.Info("event-options: configuration committed",
				"policy", a.policyName, "commands", len(a.ops))
			return
		}
		// #5063: committed-with-apply-debt. The generation was promoted, is active,
		// and the dataplane is armed — a best-effort subsystem (networkd / Kea /
		// host-inbound nft) is in debt. This is NOT a rejection: record it as
		// committed and arm the SAME-generation cooldown exactly as the clean-commit
		// path, so the live autonomous change is not miscounted rejected and the
		// same event cannot immediately re-commit during an incident. Also bump the
		// distinct debt counter and log a WARN so the operator sees the subsystem
		// debt. Terminal like the clean commit — no retry.
		var debt *commitDebtError
		if errors.As(err, &debt) {
			e.counters.committed.Add(1)
			e.counters.committedWithDebt.Add(1)
			e.armCooldown(a.policyName, a.semRev)
			slog.Warn("event-options: configuration committed with apply debt",
				"policy", a.policyName, "commands", len(a.ops), "err", debt.err)
			return
		}
		if errors.Is(err, errStaleAction) {
			// #3750: the policy was removed/redefined, or a sibling commit armed
			// the cooldown, while this action waited (on a held lock or in the
			// queue). Drop it — do NOT commit a batch no active policy authorizes,
			// and do NOT retry (the staleness is terminal for this action).
			e.counters.droppedStale.Add(1)
			slog.Info("event-options: remediation dropped (stale queued action)",
				"policy", a.policyName, "err", err)
			return
		}
		if errors.Is(err, configstore.ErrClusterReadOnly) {
			// A standby may remain read-only longer than the normal config-lock
			// retry deadline. Start a fresh bounded lock-retry window after
			// publication resumes.
			deadline = time.Time{}
			backoff = e.lockRetryInitial()
			budgetChecked = false
			// A read-only secondary is not a permanent remediation failure.
			// Keep this accepted action in flight until RG0 promotion reopens
			// the publication gate; a still-FAILING probe emits no new edge.
			if e.store.ClusterReadOnly() {
				e.SetPublishEnabled(false)
				if e.store.ClusterReadOnly() {
					slog.Info("event-options: remediation deferred on read-only secondary",
						"policy", a.policyName)
					continue
				}
				// Promotion may have raced the gate close. Reopen on the
				// current writable state rather than stranding the action.
				e.SetPublishEnabled(true)
			}
			continue
		}
		if errors.Is(err, errGlobalActionBudget) {
			e.dropGlobalBudget(a)
			return
		}
		if errors.Is(err, configstore.ErrConfigLocked) {
			if e.now().After(deadline) {
				e.counters.droppedLockHeld.Add(1)
				slog.Warn("event-options: remediation dropped (config lock held past deadline)",
					"policy", a.policyName, "err", err)
				return
			}
			e.counters.retried.Add(1)
			slog.Debug("event-options: config lock held, will retry",
				"policy", a.policyName, "backoff", backoff)
			// Explicit timer (NOT time.After) so the runtime timer is
			// released the instant stopCh fires before the backoff elapses,
			// rather than leaking an armed timer until it fires (#2890). The
			// stop func is only meaningful on the stopCh branch; on the timer
			// branch the timer has already fired and stopping is a no-op.
			timerC, stopTimer := e.newRetryTimer(backoff)
			select {
			case <-e.stopCh:
				stopTimer()
				// #9916 F-131: an in-flight lock retry abandoned on shutdown is
				// an explicit drop, not a silent return.
				e.counters.droppedShutdown.Add(1)
				slog.Info("event-options: remediation abandoned on shutdown (in-flight retry)",
					"policy", a.policyName)
				return
			case <-timerC:
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// Permanent failure (bad apply / CommitCheck reject): do not retry.
		e.counters.rejected.Add(1)
		slog.Warn("event-options: remediation rejected",
			"policy", a.policyName, "err", err)
		return
	}
}

// applyOnce is the transactional batch (#2139): enter configure (the candidate
// IS the rollback), apply every planned op, validate the WHOLE candidate with
// CommitCheck, then commit. ANY failure discards the candidate (ExitConfigure)
// — never a half-applied config. Returns ErrConfigLocked for bounded retry and
// ErrClusterReadOnly for HA deferral until the publication gate reopens.
// commitContext returns the engine-lifetime context threaded into the
// remediation commit (#2868). An Engine built via New always has lifeCtx set;
// the nil guard covers a zero-value Engine (defensive — no test constructs one)
// so callers never pass a nil context to commitFn.
func (e *Engine) commitContext() context.Context {
	if e.lifeCtx != nil {
		return e.lifeCtx
	}
	return context.Background()
}

// validatePlantClass re-evaluates every set/delete target against the login
// class policy captured by ApplyWithConfig while the configure lock is held.
// It runs before the first candidate mutation, so a denied target cannot leave
// a partial batch.
func (e *Engine) validatePlantClass(a plannedAction) error {
	e.mu.Lock()
	enforce := e.enforcePlantClass
	cfg := e.authzCfg
	e.mu.Unlock()
	if !enforce {
		return nil
	}
	if a.plantClass == "" {
		return errBatch("legacy change-configuration payload has no planting class")
	}
	if a.plantClass == config.EventPlantClassSuperuser {
		return nil
	}
	if cfg == nil {
		return errBatch("planting class %q cannot be resolved without an authorization snapshot", a.plantClass)
	}
	if !config.LoginClassExists(cfg, a.plantClass) {
		return errBatch("planting class %q no longer exists in the authorization snapshot", a.plantClass)
	}
	if !config.ClassHasPermission(cfg, a.plantClass, config.PermConfig) {
		return errBatch("planting class %q no longer has configure permission", a.plantClass)
	}
	for _, op := range a.ops {
		if err := config.AuthorizeConfigMutation(cfg, a.plantClass, nil, op.raw); err != nil {
			return errBatch("planting class %q refused a configuration target: %v", a.plantClass, err)
		}
	}
	return nil
}

func (e *Engine) applyOnce(ctx context.Context, a plannedAction) error {
	// #4423 L7: a matcher-only Engine (New(nil, nil)) has no store. A policy
	// that both matches AND triggers would otherwise nil-panic on EnterConfigure
	// inside the worker goroutine, taking down the daemon on a config an operator
	// could plausibly commit. Fail the batch permanently (counted rejected)
	// instead — a store is required to mutate config.
	if e.store == nil {
		return errBatch("no config store: cannot apply event-options remediation")
	}
	if err := e.store.EnterConfigure(); err != nil {
		// ErrConfigLocked is retried; ErrClusterReadOnly is deferred until the
		// daemon reopens the publication gate on RG0 promotion.
		return err
	}
	// From here, any early return MUST ExitConfigure to discard the candidate.

	// #3750 revalidate-before-commit: now that we hold the config lock, no
	// operator commit — and therefore no Apply() that could remove or redefine
	// the policy — can interleave until we ExitConfigure. Check the action's
	// identity against live engine state and drop it (do NOT mutate the
	// candidate) if the policy was removed, was redefined since it was enqueued,
	// or is now inside its cooldown (a sibling commit armed it after this action
	// was queued but before it ran). This folds H1/H2/H3 into one gate.
	if reason := e.staleReason(a); reason != "" {
		e.store.ExitConfigure()
		return staleErr(reason)
	}
	if err := e.validatePlantClass(a); err != nil {
		e.store.ExitConfigure()
		e.counters.plantClassInvalid.Add(1)
		slog.Warn("event-options: remediation refused by planting-class authorization",
			"policy", a.policyName, "plant-class", a.plantClass, "err", err)
		return err
	}
	for _, op := range a.ops {
		if op.isDelete {
			if err := e.store.DeleteAsGroupedPlantClass("", a.plantClass, op.delPath, nil); err != nil {
				// A delete of a missing path is a TOLERATED exception (Junos
				// change-configuration semantics; #2139 documented carve-out):
				// it is not a half-applied batch. Any other delete error
				// aborts the batch. #4423 M9: match the typed sentinel
				// config.ErrPathNotFound (which DeletePath now wraps) instead of
				// substring-matching the error text — a future reword of the
				// message no longer silently turns a tolerated missing-delete
				// into a batch-aborting hard reject.
				if errors.Is(err, config.ErrPathNotFound) {
					slog.Debug("event-options: delete skipped (path not found)",
						"policy", a.policyName)
					continue
				}
				e.store.ExitConfigure()
				return errBatch("delete target failed: %w", err)
			}
			continue
		}
		if err := e.store.SetFromInputAsPlantClass("", a.plantClass, op.setInput); err != nil {
			e.store.ExitConfigure()
			return errBatch("set target failed: %w", err)
		}
	}

	// Validate the whole candidate before committing so a bad batch discards
	// cleanly instead of relying on Commit's failure path.
	if _, err := e.store.CommitCheck(); err != nil {
		e.store.ExitConfigure()
		return errBatch("commit-check: %w", err)
	}
	// Reserve the cross-policy budget only when this action is ready to commit.
	// Queue-time admission would let a held worker accumulate expired budget
	// timestamps and then release an unbounded commit burst.
	if !e.reserveGlobalCommit(a.policyOrder) {
		e.store.ExitConfigure()
		return errGlobalActionBudget
	}

	// #3754: stamp a deterministic audit description so the autonomous
	// remediation lands in commit/rollback history attributed to the policy and
	// its triggering event, not as an anonymous unattributed commit.
	desc := remediationDescription(a)
	if e.commitFn == nil {
		// Standalone (tests): just commit; no apply. Still record the
		// description so the journal/history attribution is identical to the
		// daemon path.
		if _, err := e.store.CommitWithDescriptionAs("system:event-engine", desc); err != nil {
			e.store.ExitConfigure()
			return errBatch("commit: %w", err)
		}
		e.store.ExitConfigure()
		return nil
	}
	compiled, err := e.commitFn(ctx, desc)
	// ExitConfigure unconditionally: commitFn has already promoted (or refused
	// to promote) the candidate, so the engine's configure session is done
	// either way — the same teardown the success path always ran.
	e.store.ExitConfigure()
	if err != nil {
		// #5063: the returned *config.Config, not the error, decides whether the
		// generation was promoted. A non-nil compiled means the config committed,
		// is active, and the dataplane is armed — a best-effort subsystem is just
		// in debt (see CommitFn). That is committed-with-debt, NOT a rejection:
		// signal it so runAction arms the cooldown and counts it committed instead
		// of re-committing the same event and inflating the rejected counter. Only
		// a nil compiled (commit never promoted / dataplane disarmed) is a genuine
		// permanent rejection.
		if compiled != nil {
			return &commitDebtError{err: err}
		}
		return errBatch("commit: %w", err)
	}
	return nil
}

// remediationDescription builds the deterministic audit string stamped on an
// autonomous event-options remediation commit (#3754). It names the policy,
// the triggering event/owner/test, the command-batch size, and the deliberate
// node-local/non-peer-synced scope so operators can identify HA divergence in
// commit history.
func remediationDescription(a plannedAction) string {
	return fmt.Sprintf("event-options policy %s: %s/%s/%s (%d commands) [local-only; not peer-synced]",
		a.policyName, a.event, a.testOwner, a.testName, len(a.ops))
}

// errBatch builds a permanent (non-retryable) batch failure error.
func errBatch(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// commitDebtError is returned by applyOnce when commitFn promoted the generation
// (non-nil *config.Config) but a best-effort subsystem apply failed (#5063): the
// config is committed, active, and the dataplane armed, so it is committed — NOT
// rejected — with the wrapped subsystem error as apply debt. runAction detects it
// via errors.As, counts committed + committedWithDebt, and arms the cooldown.
// Unwrap exposes the underlying subsystem error for logging / errors.Is.
type commitDebtError struct{ err error }

func (e *commitDebtError) Error() string { return "committed with apply debt: " + e.err.Error() }
func (e *commitDebtError) Unwrap() error { return e.err }

// errStaleAction is the sentinel returned by applyOnce when the pre-classified
// action is no longer valid to commit (#3750): its policy was removed or
// redefined, or the policy's cooldown is now active. runAction recognizes it via
// errors.Is, counts it as dropped_stale, and does NOT retry (staleness is
// terminal for that action).
var errStaleAction = errors.New("stale queued remediation")
var errGlobalActionBudget = errors.New("global event action budget exhausted")

func (e *Engine) dropGlobalBudget(a plannedAction) {
	e.counters.droppedGlobalBudget.Add(1)
	e.releaseEdgeLatch(a.policyName, a.event, a.semRev)
}

// staleErr wraps errStaleAction with a human-readable reason for logging.
func staleErr(reason string) error {
	return fmt.Errorf("%w: %s", errStaleAction, reason)
}

// staleReason revalidates a pre-classified action against live engine state
// under e.mu (#3750) and returns a non-empty reason if it must NOT commit:
//
//   - "policy removed"   : e.semRev has no entry for the policy (H1). The
//     operator committed a config that dropped this event-options policy while
//     the action was queued/retrying; its stale command batch is unauthorized.
//   - "policy redefined" : the live semantic revision differs from the one the
//     action was stamped with at evaluate time (H2). A same-name redefinition
//     changed the policy's meaning; the OLD command set must not commit.
//   - "cooldown active"  : a successful commit of the SAME policy is within the
//     30s cooldown window (H3). The enqueue-time cooldown check in evaluateEvent
//     races the arm-on-commit timing, so a duplicate can slip into the queue
//     while the worker is blocked; the cooldown is re-enforced here at commit
//     time so a within-window duplicate is suppressed, not double-committed.
//
// The empty string means the action is safe to commit. Called by applyOnce
// while it holds the config lock, so the check reflects the last committed Apply
// and no operator commit can race it until ExitConfigure.
func (e *Engine) staleReason(a plannedAction) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	rev, ok := e.semRev[a.policyName]
	if !ok {
		return "policy removed"
	}
	if rev != a.semRev {
		return "policy redefined"
	}
	if rt := e.runtime[a.policyName]; rt != nil && !rt.lastTrigger.IsZero() &&
		e.now().Sub(rt.lastTrigger) < policyCooldown {
		return "cooldown active"
	}
	return ""
}

// armCooldown records a successful-commit timestamp for the policy under lock
// (#2140 / #2157). Done on the worker after commit so a dropped/rejected
// action does not consume the cooldown.
//
// Revision-aware ABA guard (#5311): the stamp is CONDITIONAL on the live
// runtime still being the SAME generation that authorized this action. authRev
// is the action's semantic revision (plannedAction.semRev). A remediation whose
// own commit redefined the triggering policy (R1 -> R2) reconciles through the
// commitFn callback -> Apply, which installs a FRESH re-armed runtime for the
// successor because the semantic revision changed. That successor R2 must NOT be
// stamped with R1's completion time: doing so is a name-based ABA that would
// suppress the re-armed R2 for the whole ~30s cooldown, contradicting the
// documented "a redefined policy re-arms" contract (README, reconcile section).
// When authRev no longer matches e.semRev[name] (successor installed, or policy
// removed — no entry), skip the stamp; the successor keeps its zero lastTrigger.
// The identity check and the stamp are performed under e.mu in one critical
// section so a concurrent Apply cannot swap the runtime between them (no TOCTOU).
func (e *Engine) armCooldown(name, authRev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.semRev[name] != authRev {
		// A successor generation was installed (or the policy was removed) while
		// this action committed. Do not throttle the successor with the
		// predecessor's completion time.
		return
	}
	if rt := e.runtime[name]; rt != nil {
		rt.lastTrigger = e.now()
	}
}
