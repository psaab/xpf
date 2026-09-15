// Package natpoolalarm implements the runtime consumer for the Junos
// `set security nat source pool-utilization-alarm raise-threshold/clear-threshold`
// stanza (#2079). The stanza was parsed and stored but had no consumer, so an
// operator who configured it got silent no-op behaviour — contrary to vSRX,
// where crossing the raise threshold raises a system alarm visible in
// `show security alarms` and emits a NAT syslog event, and dropping below the
// clear threshold clears it.
//
// This monitor closes that gap entirely in the control plane: a slow (10s)
// daemon-resident loop reads the helper's LAST-APPLIED NAT pool snapshot
// (config + same-generation pool counters) via an injected sampler, computes
// per-pool port utilization, applies raise/clear hysteresis, maintains an
// in-memory active-alarm set surfaced by both `show security alarms` render
// sites, and emits ONE structured RT_NAT syslog line per raise/clear
// transition (never per tick).
//
// Design constraints (see docs/research/2079-nat-pool-util-alarm/plan.md):
//   - No Rust / wire change: the helper already echoes 1 Hz pool counters and
//     last_snapshot_generation; this is pure Go.
//   - No new control-socket request: the sampler reads the manager's cached
//     status + applied snapshot (AppliedNATView), no socket I/O (CLAUDE.md
//     control-socket-contention rule).
//   - Generation coherency: all raise/clear/prune logic runs only when the
//     sampled view is Available AND HelperCoherent (config and counters are
//     the same applied generation); otherwise the monitor HOLDs all alarms.
package natpoolalarm

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// DefaultTickInterval is the slow evaluation cadence. The alarm is not
// latency-critical and the sampler reads only cached in-memory state, so 10s
// keeps overhead negligible and damps flap near the threshold band.
const DefaultTickInterval = 10 * time.Second

// Syslog severity levels (RFC 3164 numeric) used for transition lines. Raise
// is warning (4, "minor" in Junos alarm terms); clear is notice (5).
const (
	severityRaise = 4
	severityClear = 5
)

// PoolStatus is one source-NAT pool's deduplicated live utilization sample,
// already keyed by pool name (rules sharing a pool report identical UsedPorts
// via a shared allocator, so the sampler takes one entry per pool — never
// summed). It is a dataplane-package-free projection so this package does not
// depend on pkg/dataplane/userspace.
type PoolStatus struct {
	PoolName     string
	AddressCount int
	PortLow      uint16
	PortHigh     uint16
	UsedPorts    uint64
	// ExhaustionTotal is the allocator's cumulative allocator-reported
	// exhaustion events for this pool (#9902 F-026). The monitor watches its
	// rate of change, keyed by (ProcGen, AllocatorID) continuity.
	ExhaustionTotal uint64
	// AllocatorID is the reporting allocator's instance id (#9902 F-026):
	// same id ⇒ same counter instance, deltas comparable; changed id ⇒ the
	// allocator was rebuilt, rebaseline silently. 0 from a helper older
	// than the field.
	AllocatorID uint64
}

// View is one generation-coherent sample for the monitor. Config and Pools
// both belong to the helper's last-applied generation.
type View struct {
	// Config is the helper's currently applied configuration; may be nil
	// before the first apply lands.
	Config *config.Config
	// Pools is deduplicated by pool name (one entry per pool).
	Pools map[string]PoolStatus
	// HelperCoherent is true when the cached pool counters belong to the same
	// applied generation as Config (no in-flight apply). When false the
	// monitor HOLDs numeric raise/clear for this tick.
	HelperCoherent bool
	// Available is false when the dataplane helper is not running or no apply
	// has landed. When false the monitor HOLDs ALL alarms (no clear): no data
	// is not a decision to clear.
	Available bool
	// StatusSequence is the manager's status-publication sequence at sample
	// time (#9902 F-026). A repeated sequence means no new sample, so the
	// exhaustion pass skips the tick entirely (a re-read cache must not
	// advance clear hysteresis). 0 on synthetic/legacy views ⇒ never
	// skipped.
	StatusSequence uint64
	// ProcGen is the manager's helper-process generation at sample time
	// (#9902 F-026). It joins the exhaustion baseline key so allocator-id
	// reuse across a helper restart cannot alias two incarnations.
	ProcGen uint64
}

// Sampler returns the current generation-coherent NAT view. It must read only
// cached in-memory state (no control-socket I/O).
type Sampler func() View

// Emitter sends one pre-formatted structured syslog line at the given numeric
// severity to all configured syslog streams and local writers. The daemon
// wires this to logging.EventReader.ForwardLogMsg; tests inject a recorder.
type Emitter func(severity int, msg string)

// ActiveAlarm is a thread-safe snapshot of one active NAT pool alarm for the
// `show security alarms` render sites.
type ActiveAlarm struct {
	PoolName       string
	CurrentPct     uint64
	RaiseThreshold int
	FirstSeen      time.Time
}

// ActiveExhaustionAlarm is a thread-safe snapshot of one active NAT pool
// exhaustion alarm for the `show security alarms` render sites (#9902 F-026).
// Events is the last NONZERO observed exhaustion-event delta: refreshed only
// on positive deltas, preserved across clean ticks and identity rebases, so
// the display never shows a raised alarm with a zero count.
type ActiveExhaustionAlarm struct {
	PoolName  string
	Events    uint64
	FirstSeen time.Time
}

// alarmState is the per-pool internal record while raised.
type alarmState struct {
	pct       uint64
	raiseThr  int
	firstSeen time.Time
}

// exhBaseline is the per-pool exhaustion continuity record (#9902 F-026):
// the (procGen, allocatorID) identity the count was baselined against, the
// last observed count, and the fresh-clean-tick streak toward a clear.
type exhBaseline struct {
	procGen     uint64
	allocatorID uint64
	count       uint64
	streak      int
}

// exhAlarmState is the per-pool internal exhaustion record while raised.
type exhAlarmState struct {
	lastEvents uint64
	firstSeen  time.Time
}

// Monitor evaluates NAT pool utilization on a slow tick and maintains the
// active-alarm set.
type Monitor struct {
	sample Sampler
	emit   Emitter
	tick   time.Duration
	nowFn  func() time.Time

	mu     sync.Mutex
	active map[string]*alarmState
	// #7361: pools whose alarm is STRUCTURALLY INAPPLICABLE, with the reason.
	// Separate from `active` because this is not a raised alarm — it never
	// clears on utilization and must never emit a raise/clear syslog. It is a
	// display fact: `show` renders the alarm config for these pools, and a 0%
	// utilization is indistinguishable from a healthy pool, so an operator who
	// configured a raise-threshold needs to learn it cannot arrive.
	inapplicable map[string]string
	// #9902 F-026: exhaustion-alarm state. lastSeq is the newest status
	// sequence the exhaustion pass has evaluated (a repeated sequence means
	// no new sample — skip the pass); exhBaseline holds the per-pool
	// continuity records; activeExhaustion the raised exhaustion alarms.
	// Separate from `active` because the eligibility sets differ (exhaustion
	// watches every referenced pool class; utilization only PAT).
	lastSeq          uint64
	exhBaseline      map[string]*exhBaseline
	activeExhaustion map[string]*exhAlarmState
	started          bool // run() launched (guards Stop against an unstarted monitor)

	stopOnce sync.Once // guards close(stop) against concurrent Stop callers
	stop     chan struct{}
	done     chan struct{}
}

// New constructs a Monitor. sample and emit are dependency-injected so the
// monitor is unit-testable without a live dataplane or syslog client. A nil
// emit is tolerated (alarms still surface in `show security alarms`).
func New(sample Sampler, emit Emitter) *Monitor {
	return &Monitor{
		sample:           sample,
		emit:             emit,
		tick:             DefaultTickInterval,
		nowFn:            time.Now,
		active:           make(map[string]*alarmState),
		exhBaseline:      make(map[string]*exhBaseline),
		activeExhaustion: make(map[string]*exhAlarmState),
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}
}

// SetTickForTest overrides the evaluation cadence. It MUST be called before
// Start (the running loop captures m.tick once). Intended only for tests that
// need the sampler to fire rapidly — e.g. the #2114 daemon race regression
// test, which drives the monitor's d.dp sampler against a concurrent
// bootstrap-exit d.dp transition under the race detector.
func (m *Monitor) SetTickForTest(d time.Duration) {
	if m == nil || d <= 0 {
		return
	}
	m.mu.Lock()
	if !m.started {
		m.tick = d
	}
	m.mu.Unlock()
}

// Start launches the evaluation loop. It is a no-op if the monitor is nil or
// the sampler is nil, and is safe to call at most once.
func (m *Monitor) Start() {
	if m == nil || m.sample == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.run()
}

// Stop terminates the evaluation loop and waits for it to exit. It is safe to
// call whether or not Start was ever called (an unstarted monitor's loop never
// ran, so there is no goroutine to join) and is idempotent.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	// sync.Once, not a select/default check: the select-default close is racy —
	// two concurrent Stop callers can both observe the channel open, both fall
	// to default, and both call close(m.stop), panicking on the second close
	// (#4909). Once serializes the close so exactly one caller performs it.
	m.stopOnce.Do(func() { close(m.stop) })
	if started {
		<-m.done // join the run() goroutine
	}
}

func (m *Monitor) run() {
	defer close(m.done)
	t := time.NewTicker(m.tick)
	defer t.Stop()
	// Evaluate once promptly so an alarm that is already over threshold at
	// startup surfaces within the first tick rather than after a full period.
	m.evaluate()
	for {
		select {
		case <-t.C:
			m.evaluate()
		case <-m.stop:
			return
		}
	}
}

// evaluate runs one tick of the raise/clear/hysteresis/prune logic. It is the
// unit-test entry point (drive it directly with a synthetic Sampler).
func (m *Monitor) evaluate() {
	view := m.sample()

	// dp nil / helper down → HOLD all alarms (no clear): no data is not a
	// decision to clear.
	if !view.Available {
		return
	}
	// Mid-apply (status gen != applied gen) → counters/config transiently
	// mismatched → HOLD all this tick.
	if !view.HelperCoherent {
		return
	}

	cfg := view.Config
	// Fail-closed nil config: clear every active alarm and return.
	if cfg == nil {
		m.clearAll("alarm config unavailable")
		return
	}
	alarmCfg := cfg.Security.NAT.PoolUtilizationAlarm
	if alarmCfg == nil ||
		alarmCfg.RaiseThreshold <= 0 || alarmCfg.RaiseThreshold > 100 ||
		alarmCfg.ClearThreshold <= 0 || alarmCfg.ClearThreshold >= alarmCfg.RaiseThreshold {
		// Feature disabled / unset: clear every active alarm and return.
		m.clearAll("pool-utilization-alarm disabled")
		return
	}

	// Eligibility is RULE-REFERENCED config: a pool is eligible only if a
	// configured source-NAT rule references it AND the pool exists AND it is
	// non-deterministic. The status producer is rule-derived, so a pool with
	// no referencing rule never appears in the snapshot — iterating
	// SourcePools directly would HOLD its alarm forever (the prune never
	// fires). Mirror buildSourceNATSnapshots' defensive nil skips.
	referenced := map[string]bool{}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if rule.Then.PoolName != "" {
				referenced[rule.Then.PoolName] = true
			}
		}
	}

	eligible := map[string]bool{}
	for poolName := range referenced {
		p, ok := cfg.Security.NAT.SourcePools[poolName]
		if !ok || p == nil {
			continue // rule references a missing pool → not eligible
		}
		if p.Deterministic != nil {
			// #9902 F-026: deterministic pools stay ineligible for
			// utilization (a per-subscriber block pool has no meaningful
			// aggregate percentage), but say so explicitly instead of
			// silently skipping: clear-then-mark. The clear preserves the
			// det-convert 1-clear contract (no-op unless raised; the prune
			// below then finds nothing to clear); the mark records WHY the
			// configured threshold can never fire. Exhaustion events ARE
			// watched for this class (see the exhaustion pass below).
			m.clear(poolName, "pool no longer eligible")
			m.markInapplicable(poolName, "deterministic pool (per-subscriber blocks): "+
				"aggregate utilization cannot predict per-block exhaustion")
			continue
		}
		// #7361: an ADDRESS-ONLY pool (`port no-translation`) has no
		// port-utilization to measure, and its alarm can never fire.
		//
		// The allocator's `used_ports` is a popcount over the occupancy
		// bitmaps; `reserve_address_only` never touches occupancy — it records
		// ownership in `live.address_only_owners`. So UsedPorts is permanently
		// 0, pct is permanently 0, and the raise-threshold cannot be crossed.
		//
		// THE HARM IS NOT THE MISSING PERCENTAGE, it is that 0% is
		// indistinguishable from a healthy pool: `show` renders the alarm
		// config, and the operator reads a working alarm. Marking it
		// INAPPLICABLE says the thing that is actually true.
		//
		// WHY NOT REDEFINE THE DENOMINATOR. #7361 proposes capacity =
		// AddressCount, used = distinct addresses allocated. That models an
		// exhaustion mode this pool class does not have: addresses are handed
		// out round-robin and freely REUSED across flows with different
		// destination tuples, so an address-only pool exhausts on
		// reverse-identity collision, not on running out of addresses. A
		// one-address pool would report 100% after its first flow and stay
		// there while serving thousands more — an alarm that fires on the first
		// packet and never clears, which is worse than the current silence
		// because it trains operators to ignore the alarm that DOES work on
		// port-bearing pools.
		//
		// If a genuine early warning is wanted for this class, the signal is
		// the denial rate (the AllocatorExhausted / collision path), not a
		// utilization ratio. That is a different mechanism with its own
		// threshold semantics and is deliberately not folded in here.
		if p.PortNoTranslation {
			eligible[poolName] = true
			m.markInapplicable(poolName, "address-only pool (port no-translation) "+
				"has no port utilization to measure")
			continue
		}
		m.clearInapplicable(poolName)
		eligible[poolName] = true

		s, present := view.Pools[poolName]
		if !present {
			continue // eligible but absent this tick → HOLD
		}
		if s.AddressCount == 0 || uint64(s.PortHigh) < uint64(s.PortLow) {
			continue // bad sample → HOLD
		}
		// Cast operands to uint64 BEFORE the arithmetic so the uint16 port
		// range cannot underflow before promotion.
		capacity := uint64(s.AddressCount) * (uint64(s.PortHigh) - uint64(s.PortLow) + 1)
		if capacity == 0 {
			continue // uncomputable → HOLD (NOT a clear)
		}
		pct := s.UsedPorts * 100 / capacity

		raised := m.isRaised(poolName)
		switch {
		case !raised && pct >= uint64(alarmCfg.RaiseThreshold):
			m.raise(poolName, pct, alarmCfg.RaiseThreshold)
		case raised && pct < uint64(alarmCfg.ClearThreshold):
			m.clear(poolName, "utilization below clear-threshold")
		case raised:
			// Held above clear: refresh the displayed pct only, no syslog.
			m.updatePct(poolName, pct)
		}
	}

	// Prune alarms for any pool no longer ELIGIBLE (rule-unreferenced,
	// config-removed, or converted to deterministic). Snapshot the key set
	// under the mutex first, then emit clears WITHOUT holding the mutex across
	// the (blocking) syslog write. This runs unconditionally (eligibility is
	// config-derived) — but here it is already gated behind Available +
	// HelperCoherent, which makes cfg the applied config.
	for _, poolName := range m.activeKeys() {
		if !eligible[poolName] {
			m.clear(poolName, "pool no longer eligible")
		}
	}

	// #9902 F-026: exhaustion-event pass. Eligibility here is
	// rule-referenced + pool-exists, CLASS-AGNOSTIC: a deterministic pool's
	// block-full and an address-only pool's reverse-identity collision ARE
	// allocator-reported exhaustion events, even though neither class has a
	// meaningful utilization percentage. The prune sets MUST stay dual: the
	// utilization prune above would instantly clear a deterministic /
	// address-only exhaustion alarm (those pools are never util-eligible).
	exhEligible := map[string]bool{}
	for poolName := range referenced {
		p, ok := cfg.Security.NAT.SourcePools[poolName]
		if !ok || p == nil {
			continue // rule references a missing pool → not watched
		}
		exhEligible[poolName] = true
	}

	// Freshness: a repeated status sequence means the sampler re-read the
	// same cached sample — no new observation, so the exhaustion pass skips
	// the tick ENTIRELY (evaluation AND prune). Re-evaluating a re-read
	// would credit clear-hysteresis streaks without new data. Sequence 0
	// (synthetic/legacy views) never skips.
	if view.StatusSequence == 0 || view.StatusSequence != m.lastExhaustionSeq() {
		if view.StatusSequence != 0 {
			m.setLastExhaustionSeq(view.StatusSequence)
		}
		for poolName := range exhEligible {
			s, present := view.Pools[poolName]
			if !present {
				continue // eligible but absent this tick → HOLD
			}
			m.evalExhaustion(poolName, view.ProcGen, s.AllocatorID, s.ExhaustionTotal)
		}
		m.pruneExhaustion(exhEligible)
	}
}

// isRaised reports whether the pool currently has an active alarm.
func (m *Monitor) isRaised(poolName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.active[poolName]
	return ok
}

// activeKeys returns a snapshot of active-alarm pool names taken under the
// mutex, so callers can iterate and emit clears without holding the lock.
func (m *Monitor) activeKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.active))
	for k := range m.active {
		keys = append(keys, k)
	}
	return keys
}

// raise records a new active alarm and emits one raise syslog line.
func (m *Monitor) raise(poolName string, pct uint64, raiseThr int) {
	m.mu.Lock()
	if _, ok := m.active[poolName]; ok {
		// Already raised — should not happen (caller gates on !raised), but
		// keep idempotent: refresh pct, no duplicate syslog.
		m.active[poolName].pct = pct
		m.mu.Unlock()
		return
	}
	m.active[poolName] = &alarmState{pct: pct, raiseThr: raiseThr, firstSeen: m.nowFn()}
	m.mu.Unlock()

	m.emitLine(severityRaise, fmt.Sprintf(
		"RT_NAT - NAT_POOL_UTILIZATION_ALARM_RAISED pool-name=%q utilization=%d%% raise-threshold=%d%%",
		poolName, pct, raiseThr))
}

// clear removes an active alarm and emits one clear syslog line. It is a no-op
// (no emission) if the pool has no active alarm, so a single transition never
// double-clears.
func (m *Monitor) clear(poolName, reason string) {
	m.mu.Lock()
	st, ok := m.active[poolName]
	if !ok {
		m.mu.Unlock()
		return
	}
	pct := st.pct
	delete(m.active, poolName)
	m.mu.Unlock()

	m.emitLine(severityClear, fmt.Sprintf(
		"RT_NAT - NAT_POOL_UTILIZATION_ALARM_CLEARED pool-name=%q utilization=%d%% reason=%q",
		poolName, pct, reason))
}

// clearAll clears every active alarm (each via clear, so each emits a clear
// line). Used on the feature-disabled / nil-config early returns. #9902
// F-026: also clears every active EXHAUSTION alarm and retires all
// exhaustion baselines — a disabled/absent stanza watches nothing, and the
// next enabled tick must re-baseline silently rather than diff against a
// stale count.
func (m *Monitor) clearAll(reason string) {
	for _, poolName := range m.activeKeys() {
		m.clear(poolName, reason)
	}
	for _, poolName := range m.activeExhaustionKeys() {
		m.clearExhaustion(poolName, reason)
	}
	m.mu.Lock()
	m.exhBaseline = map[string]*exhBaseline{}
	m.mu.Unlock()
}

// updatePct refreshes the displayed pct for an already-raised pool that stays
// above the clear threshold. No transition → no syslog.
func (m *Monitor) updatePct(poolName string, pct uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.active[poolName]; ok {
		st.pct = pct
	}
}

// lastExhaustionSeq returns the newest status sequence the exhaustion pass
// has evaluated (#9902 F-026).
func (m *Monitor) lastExhaustionSeq() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSeq
}

// setLastExhaustionSeq records the newest evaluated status sequence.
func (m *Monitor) setLastExhaustionSeq(seq uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeq = seq
}

// evalExhaustion runs one pool's exhaustion state machine for a fresh tick
// (#9902 F-026). The baseline key is (procGen, allocatorID): a change in
// EITHER means the counter instance was replaced (helper restart or
// allocator rebuild) and the observation is incomparable with the baseline,
// so the tick rebases SILENTLY — no evaluation, no clear, streak reset. On
// an UNCHANGED key the counters are the same instance's monotonic atomics,
// so the delta is genuine: >0 raises (or silently refreshes the displayed
// events), ==0 advances the 3-clean-tick clear hysteresis. cur<prev on an
// unchanged key is unreachable in production (same-instance counters only
// grow) but specified anyway: defensive rebase.
//
// AllocatorID 0 (a helper older than the field) ALWAYS rebases, even
// against a 0 baseline: a legacy same-process rebuild is invisible (0→0),
// and a fast re-exhaustion past the old count before the next coherent
// tick would otherwise evaluate as a phantom delta and FALSE-raise. The
// tradeoff is explicit: legacy helpers never raise exhaustion (fail-silent
// for the skewed-upgrade window) rather than risk false alarms.
//
// Lost deltas on rebase are inherent to the 1 Hz poll: events between the
// last tick and a rebuild are unobservable — a rebase neither counts nor
// clears them.
//
// State mutates under the mutex; the at-most-one transition syslog emits
// AFTER unlock (never hold the mutex across the blocking write).
func (m *Monitor) evalExhaustion(poolName string, procGen, allocatorID, cur uint64) {
	m.mu.Lock()
	sev, msg := 0, ""
	emit := false
	b, seen := m.exhBaseline[poolName]
	switch {
	case !seen:
		// First sighting: silent baseline, no evaluation this tick.
		m.exhBaseline[poolName] = &exhBaseline{procGen: procGen, allocatorID: allocatorID, count: cur}
	case allocatorID == 0 || procGen != b.procGen || allocatorID != b.allocatorID:
		// Identity change (or legacy-0): silent rebase. The new count is
		// stored, the streak resets, and an active alarm is NEITHER
		// cleared (no false credit) NOR refreshed.
		b.procGen, b.allocatorID, b.count, b.streak = procGen, allocatorID, cur, 0
	case cur < b.count:
		// Same-key decrease: defensive rebase (unreachable in production).
		b.count, b.streak = cur, 0
	default:
		delta := cur - b.count
		b.count = cur
		if delta > 0 {
			b.streak = 0
			if st, raised := m.activeExhaustion[poolName]; raised {
				st.lastEvents = delta
			} else {
				m.activeExhaustion[poolName] = &exhAlarmState{lastEvents: delta, firstSeen: m.nowFn()}
				sev, msg, emit = severityRaise, sprintfExhaustionRaised(poolName, delta), true
			}
		} else if _, raised := m.activeExhaustion[poolName]; raised {
			b.streak++
			if b.streak >= 3 {
				delete(m.activeExhaustion, poolName)
				b.streak = 0
				sev, msg, emit = severityClear, sprintfExhaustionCleared(poolName, "no recently observed exhaustion"), true
			}
		}
	}
	m.mu.Unlock()
	if emit {
		m.emitLine(sev, msg)
	}
}

// pruneExhaustion retires exhaustion state for pools no longer watched
// (rule-unreferenced or config-removed): baseline-only records are dropped
// silently, raised alarms clear WITH syslog. Class changes never reach here
// (every class stays eligible), so exhaustion state survives them.
func (m *Monitor) pruneExhaustion(exhEligible map[string]bool) {
	m.mu.Lock()
	var stale []string
	for poolName := range m.activeExhaustion {
		if !exhEligible[poolName] {
			stale = append(stale, poolName)
		}
	}
	for poolName := range m.exhBaseline {
		if !exhEligible[poolName] {
			delete(m.exhBaseline, poolName)
		}
	}
	m.mu.Unlock()
	for _, poolName := range stale {
		m.clearExhaustion(poolName, "pool no longer referenced")
	}
}

// activeExhaustionKeys snapshots the raised exhaustion-alarm pool names.
func (m *Monitor) activeExhaustionKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.activeExhaustion))
	for poolName := range m.activeExhaustion {
		keys = append(keys, poolName)
	}
	return keys
}

// clearExhaustion removes an active exhaustion alarm and emits one clear
// syslog line. No-op (no emission) without an active alarm.
func (m *Monitor) clearExhaustion(poolName, reason string) {
	m.mu.Lock()
	if _, ok := m.activeExhaustion[poolName]; !ok {
		m.mu.Unlock()
		return
	}
	delete(m.activeExhaustion, poolName)
	m.mu.Unlock()

	m.emitLine(severityClear, sprintfExhaustionCleared(poolName, reason))
}

func sprintfExhaustionRaised(poolName string, events uint64) string {
	return fmt.Sprintf("RT_NAT - NAT_POOL_EXHAUSTION_ALARM_RAISED pool-name=%q events=%d",
		poolName, events)
}

func sprintfExhaustionCleared(poolName, reason string) string {
	return fmt.Sprintf("RT_NAT - NAT_POOL_EXHAUSTION_ALARM_CLEARED pool-name=%q reason=%q",
		poolName, reason)
}
func (m *Monitor) emitLine(severity int, msg string) {
	if m.emit != nil {
		m.emit(severity, msg)
	}
}

// ActiveAlarms returns a sorted, thread-safe snapshot of the active NAT pool
// alarms for the `show security alarms` render sites.
func (m *Monitor) ActiveAlarms() []ActiveAlarm {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]ActiveAlarm, 0, len(m.active))
	for name, st := range m.active {
		out = append(out, ActiveAlarm{
			PoolName:       name,
			CurrentPct:     st.pct,
			RaiseThreshold: st.raiseThr,
			FirstSeen:      st.firstSeen,
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].PoolName < out[j].PoolName })
	return out
}

// ActiveExhaustionAlarms returns a sorted, thread-safe snapshot of the active
// NAT pool exhaustion alarms for the `show security alarms` render sites
// (#9902 F-026).
func (m *Monitor) ActiveExhaustionAlarms() []ActiveExhaustionAlarm {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]ActiveExhaustionAlarm, 0, len(m.activeExhaustion))
	for name, st := range m.activeExhaustion {
		out = append(out, ActiveExhaustionAlarm{
			PoolName:  name,
			Events:    st.lastEvents,
			FirstSeen: st.firstSeen,
		})
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].PoolName < out[j].PoolName })
	return out
}

// markInapplicable records that a pool's utilization alarm cannot fire, with
// the reason (#7361).
//
// It emits NO syslog. This is not an alarm transition — it is a statement about
// the alarm's applicability, and raising it would be a permanent alarm on a
// healthy pool, which is exactly the failure mode #7361's proposed denominator
// would have produced.
func (m *Monitor) markInapplicable(poolName, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inapplicable == nil {
		m.inapplicable = map[string]string{}
	}
	m.inapplicable[poolName] = reason
	// A pool that was raised under a previous config (port-bearing) and is now
	// address-only must not stay latched: the alarm it was raised on no longer
	// exists. Drop the state without a clear syslog — the CLEAR would claim
	// utilization fell below the threshold, which is not what happened.
	delete(m.active, poolName)
}

// clearInapplicable drops any inapplicability record for a pool that is now
// measurable again (#7361), e.g. `port no-translation` removed on a commit.
func (m *Monitor) clearInapplicable(poolName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inapplicable, poolName)
}

// InapplicableReason returns why a pool's utilization alarm cannot fire, or ""
// when it can (#7361). Rendering surfaces use it to show NOT APPLICABLE instead
// of a healthy-looking 0%.
func (m *Monitor) InapplicableReason(poolName string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inapplicable[poolName]
}
