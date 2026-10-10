package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// monitorState tracks the dampened state for a single monitor probe.
type monitorState struct {
	down            bool      // dampened state (what we've reported to SetMonitorWeight)
	consecutiveFail int       // consecutive polls seeing failure
	consecutivePass int       // consecutive polls seeing success
	holdDownUntil   time.Time // earliest allowed next state change
}

// Dampening defaults.
const (
	DefaultMonitorFailThreshold = 3               // consecutive failures before marking down
	DefaultMonitorPassThreshold = 3               // consecutive successes before marking up
	DefaultMonitorHoldDown      = 5 * time.Second // hold-down after state change
)

// IP-probe sweep tuning (#5301). Before this the IP monitors were probed
// SERIALLY, so an all-unreachable sweep blocked for len(targets) × the
// per-socket read deadline (e.g. 64 targets × 800ms ≈ 51s), starving later
// redundancy groups and delaying HA failover detection — and Stop() had to wait
// the whole sweep out. The sweep now probes a per-cycle immutable target
// snapshot through a small bounded worker pool with an overall cycle deadline,
// then applies the results serially in stable RG/target order (the failover
// decision is unchanged — only the probe I/O is parallelized).
const (
	// ipProbeConcurrency bounds how many ICMP probes run at once. A sweep of
	// N targets completes in roughly ceil(N/ipProbeConcurrency) probe
	// deadlines instead of N of them; for the common case (targets ≤ cap) that
	// is a single deadline.
	ipProbeConcurrency = 16

	// ipProbeReadDeadline is the per-socket ICMP read deadline (unchanged from
	// the original inline 800ms). Named so the cycle-budget helper can derive
	// an overall deadline from it.
	ipProbeReadDeadline = 800 * time.Millisecond

	// ipProbeCycleSlack is the headroom added over the computed wave budget so
	// a healthy sweep never trips the overall deadline on scheduling jitter.
	ipProbeCycleSlack = 500 * time.Millisecond
)

// Monitor periodically checks interface link states and IP reachability,
// updating the cluster Manager's monitor weights when changes occur.
// State changes are dampened: an interface must fail/recover for multiple
// consecutive polls before the weight is adjusted, and a hold-down timer
// prevents rapid oscillation after each transition.
type Monitor struct {
	mgr    *Manager
	groups []*config.RedundancyGroup

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Dampened state per interface/IP monitor.
	ifaceState map[monitorKey]*monitorState
	ipState    map[ipMonitorKey]*monitorState

	// ipDebts is the authoritative record of the ip-monitoring election debts
	// this Monitor currently has installed in the manager, per RG: a map of
	// monitor-name → installed weight. Names are either a per-target
	// "ip:<addr>" (independent mode) or the aggregate ipAggregateMonitorName
	// (global-threshold mode). reconcileRGIPDebts drives the installed set to
	// exactly what the CURRENT mode + dampened reachability dictates each cycle,
	// firing SetMonitorWeight only on a diff. Tracking the installed set (rather
	// than relying on dampening transition-edges) is what lets a live mode
	// switch — global-threshold enabled↔disabled, or ip-monitoring removed —
	// reconcile the OTHER mode's stale debt instead of stranding or
	// double-counting it (#5271, Findings 1 and its symmetric direction).
	ipDebts map[int]map[string]int

	// ipThresholdState mirrors, per RG, whether the aggregate global-weight
	// debt is currently installed (i.e. ipDebts[rg] holds ipAggregateMonitorName).
	// Maintained by reconcileRGIPDebts for readability and tests.
	ipThresholdState map[int]bool

	// localStatuses holds the latest local interface monitor states,
	// rebuilt on every poll cycle. Used to populate heartbeat packets.
	localStatuses []InterfaceMonitorInfo

	// nlHandle is the netlink handle for link state queries.
	// Can be overridden for testing.
	nlHandle nlLinkGetter

	// cachedNlHandle is the production netlink handle created on first use.
	// Stored separately so Stop() can close it. Guarded by mu: getNlHandle()
	// performs the check-create-cache under mu so exactly one handle is
	// created under concurrent callers (the poll loop and RGInterfaceReady)
	// and the write cannot race Stop()'s cachedNlHandle=nil (#4715).
	cachedNlHandle nlHandleCloser

	// newNlHandle creates the production netlink handle. nil means use
	// defaultNlHandle (a real netlink.Handle). Overridable for tests so the
	// lazy-creation path can be exercised with a counting fake.
	newNlHandle func() (nlHandleCloser, error)

	// icmpDialer can be overridden for testing.
	// network is "udp4" or "udp6".
	icmpDialer func(network string) (icmpConn, error)

	// probeFn performs a single reachability probe for one target address.
	// It reports (reachable, completed); completed is false only when the
	// probe was aborted by context cancellation (Stop or the overall cycle
	// deadline) rather than run to a natural conclusion — the caller then
	// skips it this cycle (no dampening advance), keeping the sweep
	// failover-neutral. nil means use probeICMP (the real ICMP path).
	// Overridable for tests so probe latency/cancellation can be injected
	// without real sockets.
	probeFn func(ctx context.Context, addr string) (reachable, completed bool)

	// icmpSeq is a monotonically increasing per-probe ICMP echo sequence
	// counter. Each probe stamps a fresh sequence into its request so a
	// stale reply from an earlier poll cycle is rejected.
	icmpSeq atomic.Uint32

	// Dampening thresholds (0 means use default).
	FailThreshold int
	PassThreshold int
	HoldDown      time.Duration

	// IPMonitorCycleTimeout bounds a single IP-probe sweep. 0 derives a
	// generous per-cycle budget from the target count and the per-socket
	// deadline (ipCycleTimeout), so a healthy sweep bounded by
	// ipProbeConcurrency always completes; a smaller value bounds pathological
	// configs and is set by tests to force the overrun path.
	IPMonitorCycleTimeout time.Duration

	// IPMonitorCycleOverruns counts IP-probe sweeps whose overall deadline
	// fired before every target finished — a degraded/pathological probe path.
	// Reachability decisions are unaffected: unfinished probes are deferred to
	// the next cycle rather than counted as failures.
	IPMonitorCycleOverruns atomic.Uint64

	// nowFunc can be overridden for testing time-dependent behavior.
	nowFunc func() time.Time

	// beforeManagerApplyHook is a test seam fired immediately before the poll
	// cycle calls out to the Manager (SetMonitorWeight / RecordEvent). nil in
	// production. It exists so a test can assert that mon.mu is NOT held
	// across that callback (#6550): the lock order in this package is
	// m.mu -> mon.mu (Manager.UpdateConfig holds m.mu and calls
	// Monitor.UpdateGroups), so holding mon.mu while calling into the manager
	// inverts it and deadlocks a commit against a poll cycle. Called with no
	// Monitor lock held.
	beforeManagerApplyHook func()
}

// beforeManagerApply fires the #6550 lock-order test seam. Production installs
// no hook, so this is a nil check on the poll path.
func (mon *Monitor) beforeManagerApply() {
	if mon.beforeManagerApplyHook != nil {
		mon.beforeManagerApplyHook()
	}
}

// nlLinkGetter abstracts netlink.Handle.LinkByName for testing.
type nlLinkGetter interface {
	LinkByName(name string) (netlink.Link, error)
}

// nlHandleCloser is a queryable netlink handle that can also be closed.
// *netlink.Handle satisfies it; tests inject a counting fake to verify the
// lazy-creation path creates exactly one handle and closes it on Stop.
type nlHandleCloser interface {
	nlLinkGetter
	Close()
}

// defaultNlHandle is the production factory for cachedNlHandle. It creates a
// real netlink handle; *netlink.Handle satisfies nlHandleCloser.
func defaultNlHandle() (nlHandleCloser, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	return h, nil
}

// icmpConn abstracts an ICMP connection for testing.
type icmpConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	// LocalAddr reports the socket's bound address. For the Linux
	// SOCK_DGRAM ICMP socket used by the probe, the port carried here is
	// the value the kernel writes into the ICMP identifier field of every
	// echo request (and demuxes inbound replies by), so it is the
	// identifier a reply must carry to be considered a match.
	LocalAddr() net.Addr
	Close() error
}

type ipMonitorKey struct {
	rgID    int
	address string
}

// NewMonitor creates a monitor that will poll interface and IP states.
func NewMonitor(mgr *Manager, groups []*config.RedundancyGroup) *Monitor {
	return &Monitor{
		mgr:              mgr,
		groups:           groups,
		ifaceState:       make(map[monitorKey]*monitorState),
		ipState:          make(map[ipMonitorKey]*monitorState),
		ipDebts:          make(map[int]map[string]int),
		ipThresholdState: make(map[int]bool),
	}
}

func (mon *Monitor) failThreshold() int {
	if mon.FailThreshold > 0 {
		return mon.FailThreshold
	}
	return DefaultMonitorFailThreshold
}

func (mon *Monitor) passThreshold() int {
	if mon.PassThreshold > 0 {
		return mon.PassThreshold
	}
	return DefaultMonitorPassThreshold
}

func (mon *Monitor) holdDownDuration() time.Duration {
	if mon.HoldDown > 0 {
		return mon.HoldDown
	}
	return DefaultMonitorHoldDown
}

func (mon *Monitor) now() time.Time {
	if mon.nowFunc != nil {
		return mon.nowFunc()
	}
	return time.Now()
}

// evaluateTransition applies dampening logic and returns true if the
// dampened state has changed (caller should fire SetMonitorWeight).
func (mon *Monitor) evaluateTransition(state *monitorState, currentlyDown bool) bool {
	now := mon.now()

	if currentlyDown {
		state.consecutiveFail++
		state.consecutivePass = 0
		if !state.down && state.consecutiveFail >= mon.failThreshold() && now.After(state.holdDownUntil) {
			state.down = true
			state.holdDownUntil = now.Add(mon.holdDownDuration())
			return true
		}
	} else {
		state.consecutivePass++
		state.consecutiveFail = 0
		if state.down && state.consecutivePass >= mon.passThreshold() && now.After(state.holdDownUntil) {
			state.down = false
			state.holdDownUntil = now.Add(mon.holdDownDuration())
			return true
		}
	}
	return false
}

// Start begins periodic monitoring. Safe to call multiple times (stops previous).
func (mon *Monitor) Start(ctx context.Context) {
	mon.Stop()

	mon.mu.Lock()
	defer mon.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	mon.cancel = cancel

	mon.wg.Add(1)
	go mon.loop(ctx)
}

// Stop halts the monitoring goroutine and waits for it to exit.
func (mon *Monitor) Stop() {
	mon.mu.Lock()
	cancel := mon.cancel
	mon.cancel = nil
	nlh := mon.cachedNlHandle
	mon.cachedNlHandle = nil
	mon.mu.Unlock()

	if cancel != nil {
		cancel()
		mon.wg.Wait()
	}
	if nlh != nil {
		nlh.Close()
	}
}

// UpdateGroups replaces the monitored redundancy groups and drops dampening
// state for interface monitors that are no longer in the desired set (removed,
// or the monitored interface was changed). Leaving stale ifaceState behind
// would (a) leak map entries for good, and (b) reuse a stale down/hold-down
// state if the same monitor key is ever re-added — reporting an interface as
// still-failed on the strength of a measurement from a prior config epoch.
//
// It applies the SAME per-RG cleanup to the IP-monitor state (#5990): the
// dampened ipState (keyed by (rgID, address)) is dropped for any target whose
// RG is no longer desired, and the per-RG ipDebts / ipThresholdState
// bookkeeping is dropped for any RG no longer in config. Without this, a
// same-id RG remove/re-add while a monitored target is down leaves stale
// ipDebts[rg.ID] behind: the manager already cleared that RG's monitorWeights
// on removal, but the next reconcileRGIPDebts sees desired==installed by its
// OWN stale record and no-ops the install — the re-added RG silently carries a
// MISSING ip-monitor debt and can stay primary with a dead monitored uplink
// (fail-open). A clean per-RG slate forces the reconcile to re-derive the debt.
//
// The MANAGER-side debt for these removed/changed monitors (monitorWeights and
// each RG's MonitorFails) is cleared separately: interface monitors in
// reconcileMonitorDebtsLocked, and a whole removed RG's keys in UpdateConfig's
// removal loop — both under m.mu (#5080). UpdateGroups deliberately does NOT
// call the locking SetMonitorWeight here: it is invoked from
// Manager.UpdateConfig with m.mu already held, so re-acquiring m.mu would
// self-deadlock. It touches only the Monitor's own maps (guarded by mon.mu).
func (mon *Monitor) UpdateGroups(groups []*config.RedundancyGroup) {
	mon.mu.Lock()
	defer mon.mu.Unlock()

	desired := make(map[monitorKey]bool)
	desiredRGs := make(map[int]bool)
	for _, rg := range groups {
		desiredRGs[rg.ID] = true
		for _, im := range rg.InterfaceMonitors {
			desired[monitorKey{rgID: rg.ID, iface: im.Interface}] = true
		}
	}
	for key := range mon.ifaceState {
		if !desired[key] {
			delete(mon.ifaceState, key)
		}
	}

	// Purge per-RG IP-monitor state for RGs removed from config (#5990).
	// ipDebts / ipThresholdState are keyed directly by RG id; ipState embeds
	// the RG id in its key. Dropping every entry whose RG is no longer desired
	// gives a same-id re-add a clean slate so reconcileRGIPDebts re-derives the
	// debt from a fresh probe instead of no-oping against stale bookkeeping.
	// (A KEPT RG whose ip-monitoring/targets merely changed is NOT purged here —
	// reconcileRGIPDebts owns that per-poll and clears the obsolete per-target
	// debt itself.)
	for key := range mon.ipState {
		if !desiredRGs[key.rgID] {
			delete(mon.ipState, key)
		}
	}
	for rgID := range mon.ipDebts {
		if !desiredRGs[rgID] {
			delete(mon.ipDebts, rgID)
		}
	}
	for rgID := range mon.ipThresholdState {
		if !desiredRGs[rgID] {
			delete(mon.ipThresholdState, rgID)
		}
	}

	mon.groups = groups
}

func (mon *Monitor) loop(ctx context.Context) {
	defer mon.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Run immediately on start.
	mon.pollCycle(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mon.pollCycle(ctx)
		}
	}
}

// poll runs one monitoring cycle with a non-cancellable context. Retained for
// tests and any caller that does not thread a lifecycle context.
func (mon *Monitor) poll() {
	mon.pollCycle(context.Background())
}

// pollCycle runs one monitoring cycle. It splits the IP-monitor work into a
// parallel probe phase and a serial apply phase (#5301):
//
//	Phase 1  snapshot every IP target across all RGs in stable RG/target order
//	Phase 2  probe that snapshot concurrently (bounded pool + overall deadline);
//	         ctx cancellation (Stop) aborts in-flight probes promptly
//	Phase 3  apply results SERIALLY in the SAME interface-then-IP, RG-by-RG,
//	         target-by-target order the pre-parallel code used
//
// Only the probe I/O moves off the owner goroutine; the failover
// decision/weight accumulation in Phase 3 is byte-identical to the old serial
// path, so the change is failover-neutral. Interface link-state checks stay
// serial — they are fast local netlink calls, not the ~800ms-per-target ICMP
// blocking that motivated this.
func (mon *Monitor) pollCycle(ctx context.Context) {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	// Phase 1: immutable IP-target snapshot in stable order.
	var ipAddrs []string
	for _, rg := range groups {
		if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) == 0 {
			continue
		}
		for _, target := range rg.IPMonitoring.Targets {
			ipAddrs = append(ipAddrs, target.Address)
		}
	}

	// Phase 2: parallel probe.
	ipResults := mon.probeIPTargets(ctx, ipAddrs)

	// Phase 3: serial apply in stable order. Rebuild local statuses into a
	// local slice, then swap under lock to avoid racing with
	// LocalInterfaceStatuses().
	var statuses []InterfaceMonitorInfo
	ipIdx := 0
	for _, rg := range groups {
		statuses = mon.pollInterfaceMonitors(rg, statuses)
		if rg.IPMonitoring != nil && len(rg.IPMonitoring.Targets) > 0 {
			for _, target := range rg.IPMonitoring.Targets {
				res := ipResults[ipIdx]
				ipIdx++
				if !res.completed {
					// Probe deferred or aborted this cycle (cycle deadline or
					// Stop) — leave the dampening state untouched rather than
					// counting an unmeasured target as a failure.
					continue
				}
				mon.updateIPTargetDampenedState(rg, target, res.reachable)
			}
		}
		// Reconcile the RG's ip-monitor election debts to exactly what the
		// CURRENT mode (independent vs global-threshold) + dampened reachability
		// dictate (#5271). Run for EVERY RG — including one that disabled or
		// removed ip-monitoring while being kept — so a stale debt from the
		// other mode is cleared rather than stranded or double-counted.
		mon.reconcileRGIPDebts(rg)
	}

	mon.mu.Lock()
	mon.localStatuses = statuses
	mon.mu.Unlock()
}

// LocalInterfaceStatuses returns the latest snapshot of local interface monitor states.
// Used to populate heartbeat packets with per-interface status.
func (mon *Monitor) LocalInterfaceStatuses() []InterfaceMonitorInfo {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	if len(mon.localStatuses) == 0 {
		return nil
	}
	cp := make([]InterfaceMonitorInfo, len(mon.localStatuses))
	copy(cp, mon.localStatuses)
	return cp
}

func (mon *Monitor) pollInterfaceMonitors(rg *config.RedundancyGroup, statuses []InterfaceMonitorInfo) []InterfaceMonitorInfo {
	nlh := mon.getNlHandle()

	for _, im := range rg.InterfaceMonitors {
		key := monitorKey{rgID: rg.ID, iface: im.Interface}

		// #6549: bound the configured weight to the [0,255] domain the
		// heartbeat weight fields can carry. The strict commit path already
		// rejected an out-of-range weight; the tolerant load / peer-sync path
		// only warns (#1960 no-brick), so a persisted or peer-pushed config
		// can still reach this poll. Deliberately NOT logged here — this loop
		// runs every poll tick; reconcileMonitorDebtsLocked emits the
		// config-apply-frequency warning.
		weight, weightClamped := config.ClampInterfaceMonitorWeight(im.Weight)

		// Translate Junos name (ge-0/0/0) to Linux name (ge-0-0-0).
		linuxName := config.LinuxIfName(im.Interface)
		link, err := nlh.LinkByName(linuxName)

		// Resolve the observed carrier state. A LinkByName error means the
		// kernel has no such interface.
		var up bool
		if err != nil {
			// A monitor on a PEER's FPC slot is not ours to evaluate — the
			// peer publishes that interface's status via heartbeat. Skip it.
			slot := config.InterfaceSlot(im.Interface)
			if slot >= 0 && config.SlotToNodeID(slot) != mon.mgr.NodeID() {
				continue // peer's interface
			}
			// A configured LOCAL member link that is absent (cold boot, or a
			// delete/recreate between polls) MUST count as DOWN and demote the
			// RG weight — NOT be silently skipped. Skipping fails open: an
			// already-primary node keeps effective weight 255 and stays
			// primary while its data link is missing, blackholing traffic
			// (#5080). Feed the absence through the same dampening machinery a
			// carrier-down link uses so a transient netlink miss is debounced.
			slog.Warn("cluster monitor: local interface missing, treating as down",
				"rg", rg.ID, "interface", im.Interface)
			up = false
		} else {
			up = LinkAttrsUp(link.Attrs())
		}

		// Track local interface status for heartbeat propagation.
		statuses = append(statuses, InterfaceMonitorInfo{
			Interface:        im.Interface,
			Weight:           weight,
			Up:               up,
			RedundancyGroup:  rg.ID,
			ConfiguredWeight: im.Weight,
			Clamped:          weightClamped,
		})

		// #6550: ifaceState is shared with UpdateGroups, which DELETES from it
		// under mon.mu on every cluster config apply. The map access and the
		// dampening update it feeds are one critical section; the manager
		// callbacks below are deliberately OUTSIDE it (see the lock-order note
		// on beforeManagerApplyHook).
		mon.mu.Lock()
		state := mon.ifaceState[key]
		if state == nil {
			state = &monitorState{}
			mon.ifaceState[key] = state
		}
		transitioned := mon.evaluateTransition(state, !up)
		nowDown := state.down
		mon.mu.Unlock()

		if transitioned {
			mon.beforeManagerApply()
			mon.mgr.SetMonitorWeight(rg.ID, im.Interface, nowDown, weight)
			if nowDown {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"Interface %s state changed to down, weight %d", im.Interface, weight))
			} else {
				mon.mgr.RecordEvent(EventMonitor, rg.ID, fmt.Sprintf(
					"Interface %s state changed to up", im.Interface))
			}
			slog.Info("cluster monitor: interface state changed",
				"rg", rg.ID, "interface", im.Interface,
				"up", up, "weight", weight)
		}
	}
	return statuses
}

// ipProbeResult is one target's probe outcome. completed is false when the
// probe was aborted by the cycle deadline or Stop (not run to a natural
// conclusion), in which case the caller skips it for this cycle.
type ipProbeResult struct {
	reachable bool
	completed bool
}

// ipCycleTimeout returns the overall deadline for one IP-probe sweep. A caller-
// set IPMonitorCycleTimeout wins (tests use it to force the overrun path);
// otherwise it derives a generous budget from the wave count so a healthy sweep
// bounded by ipProbeConcurrency always finishes without tripping the deadline.
func (mon *Monitor) ipCycleTimeout(numTargets int) time.Duration {
	if mon.IPMonitorCycleTimeout > 0 {
		return mon.IPMonitorCycleTimeout
	}
	conc := ipProbeConcurrency
	if numTargets < conc {
		conc = numTargets
	}
	if conc < 1 {
		conc = 1
	}
	waves := (numTargets + conc - 1) / conc
	if waves < 1 {
		waves = 1
	}
	return time.Duration(waves)*ipProbeReadDeadline + ipProbeCycleSlack
}

// probe dispatches one reachability probe, honoring the probeFn test seam.
func (mon *Monitor) probe(ctx context.Context, addr string) (reachable, completed bool) {
	if mon.probeFn != nil {
		return mon.probeFn(ctx, addr)
	}
	return mon.probeICMP(ctx, addr)
}

// probeIPTargets probes addrs concurrently through a bounded worker pool under
// an overall cycle deadline, returning a result per input index in the SAME
// order (#5301). A probe that does not finish before the cycle deadline (or a
// parent Stop) is left completed=false so the caller skips it this cycle,
// keeping the sweep failover-neutral. A cycle whose own deadline fires (as
// opposed to a parent Stop) records IPMonitorCycleOverruns.
func (mon *Monitor) probeIPTargets(ctx context.Context, addrs []string) []ipProbeResult {
	results := make([]ipProbeResult, len(addrs))
	if len(addrs) == 0 {
		return results
	}

	cycleCtx, cancel := context.WithTimeout(ctx, mon.ipCycleTimeout(len(addrs)))
	defer cancel()

	conc := ipProbeConcurrency
	if len(addrs) < conc {
		conc = len(addrs)
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

launch:
	for i, addr := range addrs {
		select {
		case <-cycleCtx.Done():
			// Deadline exceeded or parent Stop: stop launching. Unlaunched
			// results stay completed=false (skipped by the caller).
			break launch
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			reachable, completed := mon.probe(cycleCtx, addr)
			results[i] = ipProbeResult{reachable: reachable, completed: completed}
		}(i, addr)
	}
	wg.Wait()

	// Record an overrun only when this sweep's OWN deadline fired — not when a
	// parent Stop cancelled the cycle (that is an orderly shutdown, not a
	// degraded probe path).
	if ctx.Err() == nil && cycleCtx.Err() == context.DeadlineExceeded {
		mon.IPMonitorCycleOverruns.Add(1)
	}
	return results
}

// ipTargetWeight resolves a target's effective monitor weight: its own weight,
// or the RG global-weight when the per-target weight is unset (0). This is the
// value the target contributes both as an independent debt (no global-threshold)
// and to the cumulative failure sum (with global-threshold).
//
// #6549: bounded to the [0,255] weight domain. ip-monitoring weights have NO
// compiled-int commit gate (validateChassisClusterStrict covers interface-monitor
// weights, RG ids and node priorities — not these), so their only commit-side
// defense is the schema's ValidateInteger(0,255), which compileTreeLenient
// downgrades to a warning on Store.Load / Store.SyncApply (#1960 no-brick). An
// out-of-range weight is therefore reachable at runtime, and it breaks BOTH
// consumers of this value:
//
//   - independent mode: a negative weight is negative DEBT — it credits weight
//     back and cancels a sibling target's real unreachability.
//   - global-threshold mode: a negative weight SUBTRACTS from the cumulative
//     failure sum, so a second genuinely unreachable target can push the sum
//     back BELOW global-threshold and drop the aggregate debt that the first
//     failure correctly installed. More failures then produce LESS demotion —
//     the group returns to full weight and PRIMARY with every target dead.
//
// The Manager.SetMonitorWeight chokepoint cannot close the second case: when
// the threshold is masked no debt is desired at all, so SetMonitorWeight is
// never called. Bounding here — the single place both consumers read — is what
// closes it, and it also keeps the weight reported in the RecordEvent /
// ipDebts bookkeeping equal to the weight actually applied.
// ClampedIPWeight is one ip-monitoring weight the runtime bounded (#6589).
// Target is "" for the per-RG aggregate global-weight.
type ClampedIPWeight struct {
	RGID       int
	Target     string
	Configured int
	Effective  int
}

// ClampedIPMonitorWeights reports every ip-monitoring weight the runtime had to
// clamp, so an operator-facing surface can show it (#6589).
//
// The interface-monitor class at least reaches journald —
// reconcileMonitorDebtsLocked warns once per config apply. The IP class reached
// NOTHING: ipTargetWeight and the global-threshold aggregate both discarded the
// clamp signal, so an out-of-range ip-monitoring weight was invisible on every
// surface including the log. That is worse than the interface-monitor case
// #6589 was filed about, and it is the same failure shape: a monitor clamped to
// 0 owes no election debt, so its RG never demotes when the probe fails.
// IPGlobalThreshold reports the configured global-threshold parameters for an
// RG, and whether that RG is in global-threshold mode at all (#7338).
//
// The status renderer needs these to describe the aggregate debt as what it is
// -- a THRESHOLD CROSSING -- rather than as an unreachable address. In
// global-threshold mode there is no per-address debt to name (desiredRGIPDebts
// installs a SINGLE debt and returns), so rendering the aggregate as an address
// would invent a target that does not exist.
//
// ok is false when the RG has no ip-monitoring or is in independent (per-target)
// mode, so a caller cannot mistake a zero threshold for a configured one.
func (mon *Monitor) IPGlobalThreshold(rgID int) (threshold, weight int, ok bool) {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	for _, rg := range groups {
		if rg == nil || rg.ID != rgID || rg.IPMonitoring == nil {
			continue
		}
		if rg.IPMonitoring.GlobalThreshold <= 0 {
			return 0, 0, false
		}
		w, _ := config.ClampInterfaceMonitorWeight(rg.IPMonitoring.GlobalWeight)
		// #8597 (muse-004 K71): report the EFFECTIVE threshold, the one the
		// election actually compares against — see desiredRGIPDebts. A status
		// surface showing a threshold the decision does not use is the #6534
		// shape: the screen and the behaviour disagree, and the screen is the
		// only thing the operator can see.
		t, _ := config.ClampInterfaceMonitorWeight(rg.IPMonitoring.GlobalThreshold)
		return t, w, true
	}
	return 0, 0, false
}

func (mon *Monitor) ClampedIPMonitorWeights() []ClampedIPWeight {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	var out []ClampedIPWeight
	for _, rg := range groups {
		if rg == nil || rg.IPMonitoring == nil {
			continue
		}
		if w, clamped := config.ClampInterfaceMonitorWeight(rg.IPMonitoring.GlobalWeight); clamped {
			out = append(out, ClampedIPWeight{
				RGID: rg.ID, Configured: rg.IPMonitoring.GlobalWeight, Effective: w,
			})
		}
		for _, target := range rg.IPMonitoring.Targets {
			if target == nil {
				continue
			}
			raw := target.Weight
			if raw == 0 {
				// Mirrors ipTargetWeight: an unset per-target weight inherits
				// the global one, which is reported above on its own.
				continue
			}
			if w, clamped := config.ClampInterfaceMonitorWeight(raw); clamped {
				out = append(out, ClampedIPWeight{
					RGID: rg.ID, Target: target.Address, Configured: raw, Effective: w,
				})
			}
		}
	}
	return out
}

func (mon *Monitor) ipTargetWeight(rg *config.RedundancyGroup, target *config.IPMonitorTarget) int {
	raw := target.Weight
	if raw == 0 {
		raw = rg.IPMonitoring.GlobalWeight
	}
	w, _ := config.ClampInterfaceMonitorWeight(raw)
	return w
}

// updateIPTargetDampenedState folds one target's reachability into its dampened
// per-target state (evaluateTransition owns the consecutive-fail/pass + hold-down
// dampening). It does NOT touch the election debt — that is reconciled per-RG,
// from the dampened state, in reconcileRGIPDebts. Called serially in stable
// RG/target order.
func (mon *Monitor) updateIPTargetDampenedState(rg *config.RedundancyGroup, target *config.IPMonitorTarget, reachable bool) {
	key := ipMonitorKey{rgID: rg.ID, address: target.Address}
	// #6550: ipState is shared with UpdateGroups, which deletes a removed RG's
	// targets from it under mon.mu. This body makes no manager call, so the
	// whole of it can run under the lock.
	mon.mu.Lock()
	state := mon.ipState[key]
	if state == nil {
		state = &monitorState{}
		mon.ipState[key] = state
	}
	transitioned := mon.evaluateTransition(state, !reachable)
	mon.mu.Unlock()

	if transitioned {
		slog.Info("cluster monitor: IP probe reachability changed",
			"rg", rg.ID, "address", target.Address, "reachable", reachable)
	}
}

// ipAggregateMonitorName is the per-RG monitor name under which the aggregate
// global-threshold debt is installed. It is a fixed constant (not derived from
// config) so the debt can be cleared even after ip-monitoring is reconfigured
// or removed — when rg.IPMonitoring (and its GlobalWeight) is no longer
// available. It is deliberately distinct from the per-target "ip:<addr>" debts
// and from interface-monitor names so it never collides with them.
const ipAggregateMonitorName = "ip-monitoring"

// reservedMonitorNames are the exact monitor-key names that do NOT belong to
// the interface-monitor reconciler.
//
// #8338: ONE list, consumed by both `isReservedMonitorName` and the guard test
// that proves each survives a config commit. Every reserved debt must appear
// here — the predicate and test read the same slice and cannot disagree about
// the category.
var reservedMonitorNames = []string{
	ipAggregateMonitorName,
	DataplaneArmMonitorIface,
	HelperCrashLoopMonitorIface,
}

// isReservedMonitorName reports whether a monitor key belongs to some owner
// OTHER than the interface-monitor reconciler.
//
// #8338: the category, named once. Before this there was a single exemption for
// the IP class and the surrounding comment described the interface reconciler as
// owning "the rest" — a fail-OPEN default. Both `__dataplane-arm__` and
// `__userspace-helper-crash-loop__` are daemon-owned debts; deleting either on
// an unrelated config commit can leave the RG owned by a node unable to forward.
//
// The default is now inverted: this reconciler owns only keys it can recognise
// as interface monitors, so a future reserved class is safe unless someone
// deliberately makes it interface-shaped.
func isReservedMonitorName(iface string) bool {
	if isIPMonitorName(iface) {
		return true
	}
	for _, reserved := range reservedMonitorNames {
		if iface == reserved {
			return true
		}
	}
	return false
}

// isIPMonitorName reports whether a monitor name in monitorWeights /
// MonitorFails belongs to the IP-MONITORING path rather than an
// interface-monitor. IP-monitor debts are installed by reconcileRGIPDebts under
// two naming conventions — the per-target "ip:<addr>" form (independent mode)
// and the fixed aggregate ipAggregateMonitorName (global-threshold mode). They
// share the monitorWeights / MonitorFails structure with interface-monitor
// debts, so any code that reconciles ONE class must use this discriminator to
// avoid clobbering the other. reconcileRGIPDebts owns the IP class; the
// interface-monitor reconcile (reconcileMonitorDebtsLocked) owns the rest.
func isIPMonitorName(iface string) bool {
	return iface == ipAggregateMonitorName || strings.HasPrefix(iface, "ip:")
}

// desiredRGIPDebts computes the ip-monitor election debts an RG SHOULD carry
// given its current mode and dampened reachability — the single place the two
// modes' semantics are expressed:
//
//   - global-threshold > 0 (aggregate mode, vSRX): each unreachable target's
//     weight accumulates into a cumulative sum; a SINGLE debt equal to
//     global-weight is owed only while that sum is >= global-threshold. No
//     per-target debts.
//   - global-threshold <= 0 (independent mode, historical): each unreachable
//     target owes its own effective weight; no aggregate debt.
//   - ip-monitoring absent: nothing is owed.
//
// Returned as monitor-name → weight.
//
// Callers must hold mon.mu: this reads mon.ipState, which UpdateGroups deletes
// from concurrently (#6550).
func (mon *Monitor) desiredRGIPDebts(rg *config.RedundancyGroup) map[string]int {
	desired := map[string]int{}
	if rg.IPMonitoring == nil {
		return desired
	}
	if rg.IPMonitoring.GlobalThreshold > 0 {
		cumulative := 0
		for _, target := range rg.IPMonitoring.Targets {
			key := ipMonitorKey{rgID: rg.ID, address: target.Address}
			if st := mon.ipState[key]; st != nil && st.down {
				cumulative += mon.ipTargetWeight(rg, target)
			}
		}
		// #8597 (muse-004 K71): clamp the THRESHOLD too, not only the weight.
		//
		// The weight below has been bounded since #6549; the threshold this
		// comparison uses was the raw configured value. Both are bounded to
		// [0,255] by the same strict gate (schema_chassis.go's
		// ValidateInteger(0, 255) and validateChassisClusterStrict), and both
		// reach runtime unbounded on the tolerant load / peer-sync path, so
		// bounding one and not the other left the pair inconsistent in the
		// direction that matters.
		//
		// `cumulative` is a sum of per-target weights that ARE clamped
		// (ipTargetWeight, #6549), so a lenient-loaded threshold of 1000000 can
		// never be reached however many probes fail. The RG never demotes, the
		// status shows no failure, and failover is effectively OFF for that RG
		// while the operator believes they configured protection. A monitor
		// that cannot fire is worse than a missing one: it is a missing one
		// that reports healthy.
		//
		// Binding config.ClampInterfaceMonitorWeight rather than a literal 255
		// keeps this in step with the gate — the threshold and the weights
		// share one domain, which is why one clamp serves both.
		threshold, _ := config.ClampInterfaceMonitorWeight(rg.IPMonitoring.GlobalThreshold)
		if cumulative >= threshold {
			// #6549: same bound as ipTargetWeight — the aggregate debt is the
			// raw configured global-weight, and an out-of-range one reaches
			// runtime on the tolerant load / peer-sync path. Clamping here
			// (not only at the SetMonitorWeight chokepoint) keeps the weight
			// recorded in ipDebts and reported in the RecordEvent equal to the
			// weight the election actually applies.
			w, _ := config.ClampInterfaceMonitorWeight(rg.IPMonitoring.GlobalWeight)
			desired[ipAggregateMonitorName] = w
		}
		return desired
	}
	for _, target := range rg.IPMonitoring.Targets {
		key := ipMonitorKey{rgID: rg.ID, address: target.Address}
		if st := mon.ipState[key]; st != nil && st.down {
			desired["ip:"+target.Address] = mon.ipTargetWeight(rg, target)
		}
	}
	return desired
}

// reconcileRGIPDebts drives the RG's INSTALLED ip-monitor election debts to
// exactly the desired set for the current mode + dampened state (#5271),
// firing SetMonitorWeight only on a diff so steady state produces no churn.
//
// Reconciling the full set each cycle — rather than reacting only to per-target
// dampening transition-edges — is what makes a LIVE mode switch correct in both
// directions:
//
//   - global-threshold enabled→disabled (or ip-monitoring removed) while a
//     target is down: the stale aggregate "ip-monitoring" debt is dropped and
//     the per-target debts (if now in independent mode) installed — otherwise
//     the RG stays stuck demoted at the aggregate weight (fails to fail back).
//   - global-threshold disabled→enabled while a target is down: the stale
//     per-target "ip:<addr>" debts are dropped in favor of the single aggregate
//     debt — otherwise they COEXIST and over-demote the RG (a 100-point
//     over-deduction here → a spurious failover). Because an already-down
//     target produces no new transition, transition-edge cleanup could never
//     fire; the full reconcile does.
//
// Called for EVERY RG each cycle, including one that has dropped ip-monitoring.
//
// #6550: the bookkeeping (ipState, ipDebts, ipThresholdState) is driven to its
// new value under mon.mu — UpdateGroups deletes from all three under that same
// lock — and the resulting manager callbacks are replayed AFTER the lock is
// dropped. They cannot run under it: SetMonitorWeight takes m.mu and
// Manager.UpdateConfig holds m.mu while calling UpdateGroups, so mon.mu held
// across the callback inverts the m.mu -> mon.mu order and deadlocks. The
// emitted sequence is unchanged — all removals, then all installs, in the same
// (map-iteration, i.e. already unordered) order as before.
func (mon *Monitor) reconcileRGIPDebts(rg *config.RedundancyGroup) {
	mon.mu.Lock()
	desired := mon.desiredRGIPDebts(rg)

	installed := mon.ipDebts[rg.ID]
	if installed == nil {
		if len(desired) == 0 {
			mon.mu.Unlock()
			return // nothing installed, nothing desired — no-op
		}
		installed = make(map[string]int)
		mon.ipDebts[rg.ID] = installed
	}

	var pending []ipDebtAction
	// Remove installed debts that are no longer desired.
	for name, w := range installed {
		if _, ok := desired[name]; ok {
			continue
		}
		delete(installed, name)
		pending = append(pending, ipDebtAction{name: name, weight: w, install: false})
	}
	// Install (or reweight) desired debts not already matching.
	for name, w := range desired {
		if cur, ok := installed[name]; ok && cur == w {
			continue
		}
		installed[name] = w
		pending = append(pending, ipDebtAction{name: name, weight: w, install: true})
	}

	if len(installed) == 0 {
		delete(mon.ipDebts, rg.ID)
	}
	// Mirror the aggregate-installed flag for readability/tests.
	_, aggInstalled := installed[ipAggregateMonitorName]
	mon.ipThresholdState[rg.ID] = aggInstalled
	mon.mu.Unlock()

	// Removals first, then installs — the pre-#6550 emission order.
	for _, act := range pending {
		if act.install {
			continue
		}
		mon.beforeManagerApply()
		mon.mgr.SetMonitorWeight(rg.ID, act.name, false, act.weight)
		mon.recordIPDebtChange(rg.ID, act.name, false, act.weight)
	}
	for _, act := range pending {
		if !act.install {
			continue
		}
		mon.beforeManagerApply()
		mon.mgr.SetMonitorWeight(rg.ID, act.name, true, act.weight)
		mon.recordIPDebtChange(rg.ID, act.name, true, act.weight)
	}
}

// ipDebtAction is one pending manager-side ip-monitor debt change: computed by
// reconcileRGIPDebts while it holds mon.mu, applied after it drops it (#6550).
type ipDebtAction struct {
	name    string
	weight  int
	install bool
}

// recordIPDebtChange emits the operator event + log for an ip-monitor debt
// install/clear during reconciliation.
func (mon *Monitor) recordIPDebtChange(rgID int, name string, installed bool, weight int) {
	switch {
	case name == ipAggregateMonitorName && installed:
		mon.mgr.RecordEvent(EventMonitor, rgID, fmt.Sprintf(
			"IP monitoring cumulative failure reached global-threshold, deducting global-weight %d", weight))
	case name == ipAggregateMonitorName && !installed:
		mon.mgr.RecordEvent(EventMonitor, rgID,
			"IP monitoring cumulative failure below global-threshold, clearing global-weight")
	case installed:
		addr := strings.TrimPrefix(name, "ip:")
		mon.mgr.RecordEvent(EventMonitor, rgID, fmt.Sprintf(
			"IP %s unreachable, weight %d", addr, weight))
	default:
		addr := strings.TrimPrefix(name, "ip:")
		mon.mgr.RecordEvent(EventMonitor, rgID, fmt.Sprintf("IP %s reachable", addr))
	}
	slog.Info("cluster monitor: IP monitor debt reconciled",
		"rg", rgID, "monitor", name, "installed", installed, "weight", weight)
}

// probeICMP sends one ICMP echo to addr and reports (reachable, completed).
// completed is false only when ctx was cancelled (Stop or the overall cycle
// deadline) and aborted an in-flight probe; a natural conclusion — a matching
// reply, a dial/marshal failure, or the 800ms read deadline — reports
// completed=true. The per-socket matching and 800ms read-deadline behavior are
// unchanged; ctx only adds prompt cancellation of the active socket (#5301).
func (mon *Monitor) probeICMP(ctx context.Context, addr string) (reachable, completed bool) {
	dialer := mon.icmpDialer
	if dialer == nil {
		dialer = defaultICMPDialer
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return false, true
	}

	isIPv6 := ip.To4() == nil

	var network string
	var echoType icmp.Type
	var replyType icmp.Type
	var proto int // IANA protocol number for icmp.ParseMessage

	if isIPv6 {
		network = "udp6"
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		proto = 58 // ICMPv6
	} else {
		network = "udp4"
		echoType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		proto = 1 // ICMPv4
	}

	conn, err := dialer(network)
	if err != nil {
		return false, true
	}
	defer conn.Close()

	// Cancellation watcher: closing the socket unblocks an in-flight ReadFrom
	// so Stop() (or the overall cycle deadline) aborts this probe promptly
	// instead of waiting out the full 800ms read deadline (#5301). probeDone is
	// closed on return (deferred after this, so LIFO runs it before conn.Close
	// on the normal path), letting the watcher exit without a spurious close.
	probeDone := make(chan struct{})
	defer close(probeDone)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-probeDone:
		}
	}()

	// Identifier the reply must carry. This code uses a Linux SOCK_DGRAM
	// ICMP socket ("udp4"/"udp6"); the kernel OVERWRITES the identifier we
	// marshal with the socket's local port and demuxes inbound replies by
	// that value, so the identifier to match against is the socket port,
	// not the constant placed in the request. Each probe opens a fresh
	// socket, so this identifier is per-probe unique. Fall back to the
	// marshalled constant when a port is unavailable (e.g. a raw-socket or
	// test connection that reports no port).
	const probeID = 0xbf
	wantID := probeID
	if la := conn.LocalAddr(); la != nil {
		if ua, ok := la.(*net.UDPAddr); ok && ua.Port != 0 {
			wantID = ua.Port
		}
	}

	// Per-probe sequence number, cycling 1..0xffff in the 16-bit ICMP
	// sequence space (never 0). The kernel preserves the sequence field, so
	// a matching reply must echo the exact value we sent; a stale reply from
	// an earlier poll cycle carries a different value and is rejected.
	wantSeq := int(mon.icmpSeq.Add(1)%0xffff) + 1

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   probeID,
			Seq:  wantSeq,
			Data: []byte("xpf"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false, true
	}

	dst := &net.UDPAddr{IP: ip}
	if _, err := conn.WriteTo(b, dst); err != nil {
		// A write error is a natural probe failure unless ctx cancellation
		// closed the socket out from under us (then the probe did not complete).
		return false, ctx.Err() == nil
	}

	// Read replies until one matches the request or the deadline expires.
	// A non-matching reply (wrong responder, identifier, or sequence) must
	// NOT be counted as a successful probe, and must NOT consume the single
	// read and cause a false timeout — so keep reading until the deadline.
	// The deadline is absolute, so subsequent ReadFrom calls inherit it.
	conn.SetReadDeadline(time.Now().Add(ipProbeReadDeadline))
	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			// Natural 800ms timeout / read error is a completed failure; a
			// read error caused by ctx cancellation (watcher closed the
			// socket) is NOT completed — the caller skips it this cycle.
			return false, ctx.Err() == nil
		}

		// The responder source address must equal the probed target.
		if !icmpPeerMatchesTarget(peer, ip) {
			continue
		}

		parsed, err := icmp.ParseMessage(proto, reply[:n])
		if err != nil {
			continue
		}
		if parsed.Type != replyType {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID != wantID || echo.Seq != wantSeq {
			continue
		}
		return true, true
	}
}

// icmpPeerMatchesTarget reports whether the source address of a received
// ICMP reply equals the probed target. Datagram ICMP sockets report the
// peer as *net.UDPAddr; raw sockets report *net.IPAddr.
func icmpPeerMatchesTarget(peer net.Addr, target net.IP) bool {
	if peer == nil {
		return false
	}
	var pip net.IP
	switch a := peer.(type) {
	case *net.UDPAddr:
		pip = a.IP
	case *net.IPAddr:
		pip = a.IP
	default:
		return false
	}
	return pip != nil && pip.Equal(target)
}

func defaultICMPDialer(network string) (icmpConn, error) {
	var listenAddr string
	if network == "udp6" {
		listenAddr = "::"
	} else {
		listenAddr = "0.0.0.0"
	}
	c, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// RGInterfaceReady checks if all local required interfaces for the given RG
// exist and are operationally up. Returns (true, nil) if all ready, or
// (false, reasons) with a list of missing/down interface names.
func (mon *Monitor) RGInterfaceReady(rgID int) (bool, []string) {
	mon.mu.Lock()
	groups := mon.groups
	mon.mu.Unlock()

	nlh := mon.getNlHandle()

	var reasons []string
	found := false
	for _, rg := range groups {
		if rg.ID != rgID {
			continue
		}
		found = true
		for _, im := range rg.InterfaceMonitors {
			linuxName := config.LinuxIfName(im.Interface)
			link, err := nlh.LinkByName(linuxName)
			if err != nil {
				// Check if interface belongs to peer based on FPC slot.
				slot := config.InterfaceSlot(im.Interface)
				if slot >= 0 && config.SlotToNodeID(slot) != mon.mgr.NodeID() {
					continue // peer's interface
				}
				reasons = append(reasons, fmt.Sprintf("interface %s missing", im.Interface))
				continue
			}
			up := LinkAttrsUp(link.Attrs())
			if !up {
				reasons = append(reasons, fmt.Sprintf("interface %s down", im.Interface))
			}
		}
	}
	if !found {
		// No RG config found — treat as ready (nothing to check).
		return true, nil
	}
	if len(reasons) > 0 {
		return false, reasons
	}
	return true, nil
}

func (mon *Monitor) getNlHandle() nlLinkGetter {
	// Test injection short-circuits before any locking. nlHandle is set only
	// at construction in tests and never mutated afterward, so this read is
	// race-free.
	if mon.nlHandle != nil {
		return mon.nlHandle
	}

	// The check-create-cache runs under mon.mu so concurrent callers (the
	// poll loop via pollInterfaceMonitors and the daemon HA path via
	// RGInterfaceReady) create exactly one production handle — no leaked
	// netlink socket — and the cachedNlHandle write cannot race Stop()'s
	// cachedNlHandle=nil. Neither caller holds mon.mu at this point: poll()
	// releases it before pollInterfaceMonitors, and RGInterfaceReady()
	// releases it before calling; so this does not deadlock. The handle can
	// still be re-created after Stop() nils cachedNlHandle, matching the
	// prior lazy-recreate contract. (#4715)
	mon.mu.Lock()
	defer mon.mu.Unlock()

	if mon.cachedNlHandle != nil {
		return mon.cachedNlHandle
	}
	factory := mon.newNlHandle
	if factory == nil {
		factory = defaultNlHandle
	}
	h, err := factory()
	if err != nil {
		slog.Warn("cluster monitor: failed to create netlink handle", "err", err)
		return &noopNlHandle{}
	}
	mon.cachedNlHandle = h
	return h
}

// LinkAttrsUp reports whether an interface is operationally up. It is the
// shared carrier-state read for the cluster package: the interface-monitor
// demotion loop (Monitor.pollInterfaceMonitors, RGInterfaceReady), the
// RETH status displays (RethController.FormatStatus and the
// "show chassis cluster interfaces" reth list in both pkg/grpcapi and
// pkg/cli), and the daemon no-reth-vrrp VIP-readiness gate
// (pkg/daemon.checkVIPReadinessForConfig, #2090).
//
// Carrier health must NOT be decided from the administrative IFF_UP flag
// (net.FlagUp): xpfd admin-ups ALL managed interfaces, so IFF_UP stays set
// whenever the interface is admin-up — including when the cable is pulled.
// A carrier-down link keeps IFF_UP set while OperState transitions to
// OperDown/OperLowerLayerDown. Decide from the operational state
// (IFLA_OPERSTATE):
//   - OperUp                 -> up.
//   - OperUnknown            -> fall back to the admin flag (common on
//     virtual devices and 802.1Q VLAN sub-interfaces that report no
//     independent carrier state).
//   - OperDown / lower-layer-down / anything else -> down.
//
// This mirrors pkg/vrrp.linkAttrsUp, the canonical link-state read used by
// VRRP track-interface detection (#2070).
func LinkAttrsUp(attrs *netlink.LinkAttrs) bool {
	switch attrs.OperState {
	case netlink.OperUp:
		return true
	case netlink.OperUnknown:
		return attrs.Flags&net.FlagUp != 0
	default:
		return false
	}
}

type noopNlHandle struct{}

func (n *noopNlHandle) LinkByName(name string) (netlink.Link, error) {
	return nil, net.UnknownNetworkError("no netlink handle")
}
