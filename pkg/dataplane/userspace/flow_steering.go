// flow_steering.go — closed-loop NIC ntuple HW flow steering for
// shared_exact CoS classes (#789, plan v6 d016080e).
//
// The controller addresses the per-flow CoV gap on iperf-b/iperf-c
// (41.8% / 62.5%) caused by mlx5 RSS hashing collisions onto a small
// number of RX queues. ntuple rules act at the physical NIC HW level
// — before DMA, before XDP — so they sidestep the AF_XDP queue-binding
// wall that closed #899. Per-5-tuple HW exact-match rules override
// RSS for matched flows and steer them deterministically across RX
// queues, which unblocks the per-binding worker fairness story.
//
// Phase 1 scope (per plan §4):
//   - mlx5_core driver only; other drivers log + skip.
//   - IPv4 TCP only (iperf-c P=12 baseline).
//   - Identity-NAT only (no SNAT/DNAT/NAT64/NPTv6).
//   - 1 Hz Reconcile cadence with mandatory hysteresis: 3-tick
//     binding cooldown + 5-tick per-flow no-resteer.
//   - Stable-flow gate: install_age >= 3s AND last_seen_age < 1s.
//   - Reserved rule-loc range starting at 32768 to avoid clobbering
//     any operator-installed rules (which conventionally use 0-32767).
//   - Shell-out to `ethtool -N <iface> ...` for install/delete.
//     1 Hz × K=1-2 keeps the fork/exec cost negligible.
//
// The controller is started by `Manager` once per daemon boot and
// shut down on Manager.Close(). Default disabled — operator must
// enable via `set system services userspace-dp flow-steering enable`.
package userspace

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// flowSteeringTickInterval is the controller's reconcile cadence.
	flowSteeringTickInterval = 1 * time.Second

	// flowSteeringBindingCooldownTicks: a binding whose flow_count
	// just GREW (received re-steered flow) is parked for N ticks so
	// we don't pile more onto it. Sources are NOT cooldown'd — their
	// count drops after a successful re-steer, and we want to keep
	// migrating from the heaviest binding. The 5-tick per-flow
	// no-resteer cooldown (`flowSteeringFlowNoResteerTicks`) is the
	// real ping-pong protection.
	flowSteeringBindingCooldownTicks = 2


	// flowSteeringStableInstallAgeSecs: minimum install_age_secs for a
	// flow to be considered stable enough to re-steer (excludes
	// mid-handshake).
	flowSteeringStableInstallAgeSecs = 3

	// flowSteeringStableLastSeenAgeMs: maximum last_seen_age_ms for a
	// flow to be considered active (excludes idle/stale).
	flowSteeringStableLastSeenAgeMs = 1000

	// flowSteeringMinImbalance: skip reconcile if max-min count is
	// below this threshold.
	flowSteeringMinImbalance = 2

	// flowSteeringRuleStaleTicks: a rule whose flow has not appeared
	// in any worker sample for this many ticks is evicted. Bounds
	// the rule table size — without this, sticky placement (no
	// per-flow re-steer) would accumulate one rule per ever-seen
	// flow as short-lived TCP connections come and go.
	flowSteeringRuleStaleTicks = 30

	// flowSteeringMaxResteerPerTick: K is the per-tick rule-install
	// budget. Plan §4.1 originally suggested 1-2 to limit thrash, but
	// empirical testing on the iperf-c P=12 baseline showed K=2 only
	// produces ~9 rules over a 30s window — not enough to clear the
	// ≤20% CoV gate. K=4 lets the controller converge inside the
	// stable-flow window without overwhelming the hysteresis logic.
	flowSteeringMaxResteerPerTick = 4

	// flowSteeringHistorySize: ring buffer for `show cos flow-steering`.
	flowSteeringHistorySize = 32
)

// flowSteeringFlowKey is the operator-readable wire 5-tuple of an
// ingress flow. The string form is what the worker emits in
// ActiveFlowSampleStatus.Wire5Tuple. The controller never reconstructs
// the tuple from raw bytes; it round-trips the string into ethtool
// arguments to keep the source of truth in one place.
type flowSteeringFlowKey struct {
	wire5tuple string
	iface      string
}

// flowSteeringInstalledRule tracks state about a rule the controller
// installed on the NIC. Survives only in-memory — startup flush
// re-establishes the canonical view from the kernel side.
type flowSteeringInstalledRule struct {
	iface       string
	ruleLoc     int
	targetQueue uint32
	installedAt time.Time
	tick        uint64
	lastSeenTick uint64
	flow        flowSteeringFlowKey
}

// FlowSteeringResteerEvent is recorded for `show cos flow-steering`
// and exposed to the CLI renderer. Public so cross-package consumers
// can format it; emitted by the controller via HistorySnapshot.
type FlowSteeringResteerEvent struct {
	At          time.Time
	Iface       string
	Flow        string
	TargetQueue uint32
	RuleLoc     int
	Reason      string
}

// flowSteeringIfaceState tracks per-interface controller eligibility.
type flowSteeringIfaceState struct {
	name       string
	driver     string
	queues     int
	eligible   bool
	reason     string
	resolvedAt time.Time
}

// flowSteeringBindingTickStamp records the last tick a binding's
// active flow count changed; used to enforce the 3-tick cooldown.
type flowSteeringBindingTickStamp struct {
	lastChangeTick uint64
	lastCount      uint32
}

// flowSteeringStatusProvider is the slim interface FlowSteeringController
// needs from Manager — exposed so tests can substitute a mock.
type flowSteeringStatusProvider interface {
	Status() (ProcessStatus, error)
}

// FlowSteeringController owns NIC HW flow steering for shared_exact
// CoS classes. Default disabled; operator opts in via
// `set system services userspace-dp flow-steering enable`.
type FlowSteeringController struct {
	log      *slog.Logger
	provider flowSteeringStatusProvider

	// enabled is set on every commit cycle from the typed config.
	// Reading is racy with config reloads but eventual consistency
	// is fine for a 1 Hz controller.
	enabled atomic.Bool

	mu     sync.Mutex
	tick   uint64
	rules  map[flowSteeringFlowKey]*flowSteeringInstalledRule
	usedLo map[string]map[int]struct{} // iface → set of in-use rule_locs
	bind   map[uint32]*flowSteeringBindingTickStamp
	ifaces map[string]*flowSteeringIfaceState

	historyMu sync.Mutex
	history   []FlowSteeringResteerEvent

	// Prometheus counters (#789 §4.6).
	rulesInstalled     atomic.Uint64
	rulesRemoved       atomic.Uint64
	imbalanceDetected  atomic.Uint64
	installFailures    atomic.Uint64
	ruleTableCapacity  atomic.Uint64

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Hooks overridable by tests. Production sets these to the
	// real ethtool/sysfs implementations in NewFlowSteeringController.
	runEthtool func(args ...string) (string, error)
	readSysfs  func(path string) (string, error)
}

// NewFlowSteeringController constructs the controller. The Manager
// retains ownership and must call Start to launch the reconcile
// goroutine.
func NewFlowSteeringController(log *slog.Logger, provider flowSteeringStatusProvider) *FlowSteeringController {
	if log == nil {
		log = slog.Default()
	}
	return &FlowSteeringController{
		log:        log,
		provider:   provider,
		rules:      make(map[flowSteeringFlowKey]*flowSteeringInstalledRule),
		usedLo:     make(map[string]map[int]struct{}),
		bind:       make(map[uint32]*flowSteeringBindingTickStamp),
		ifaces:     make(map[string]*flowSteeringIfaceState),
		history:    make([]FlowSteeringResteerEvent, 0, flowSteeringHistorySize),
		runEthtool: defaultRunEthtool,
		readSysfs:  defaultReadSysfs,
	}
}

// SetEnabled mirrors the typed config knob into the controller.
// Called from Manager during config commit.
func (c *FlowSteeringController) SetEnabled(enabled bool) {
	prev := c.enabled.Swap(enabled)
	if prev != enabled {
		if enabled {
			c.log.Info("flow-steering enabled (#789): closed-loop ntuple controller will reconcile shared_exact CoS classes")
		} else {
			c.log.Info("flow-steering disabled (#789): flushing controller-owned ntuple rules")
			c.flushAllRules()
		}
	}
}

// Start spawns the reconcile goroutine. Idempotent.
func (c *FlowSteeringController) Start(ctx context.Context) {
	c.mu.Lock()
	if c.cancel != nil {
		c.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.mu.Unlock()
	c.wg.Add(1)
	go c.run(cctx)
}

// Stop cancels the reconcile goroutine and flushes rules. Blocks
// until the goroutine exits.
func (c *FlowSteeringController) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.wg.Wait()
	c.flushAllRules()
}

func (c *FlowSteeringController) run(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(flowSteeringTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !c.enabled.Load() {
				continue
			}
			if err := c.reconcile(); err != nil {
				c.log.Warn("flow-steering reconcile failed", "err", err)
			}
		}
	}
}

// reconcile runs a single tick: pulls BindingStatus, computes
// imbalance, picks K stable flows, and steers them via ntuple.
func (c *FlowSteeringController) reconcile() error {
	c.mu.Lock()
	c.tick++
	tick := c.tick
	c.mu.Unlock()

	status, err := c.provider.Status()
	if err != nil {
		return fmt.Errorf("status fetch: %w", err)
	}

	groups := groupBindingsByIface(status.Bindings)
	for ifname, group := range groups {
		st := c.ensureIface(ifname)
		if !st.eligible {
			continue
		}
		// Mark rules whose flows are still appearing in worker
		// samples — the lastSeenTick stamp drives stale-rule eviction
		// below. We do this BEFORE reconcileIface so eviction picks
		// up the freshest data.
		c.refreshRuleLastSeen(ifname, group, tick)
		c.reconcileIface(ifname, group, tick)
	}

	c.evictStaleRules(tick)
	c.expireBindingTickStamps(tick)
	return nil
}

// refreshRuleLastSeen stamps lastSeenTick on every controller-owned
// rule whose flow is currently visible in a worker sample for the
// given interface. Anything not stamped this tick will eventually
// age out via evictStaleRules.
func (c *FlowSteeringController) refreshRuleLastSeen(ifname string, group []BindingStatus, tick uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range group {
		for _, f := range b.ActiveIngressFlowsSample {
			key := flowSteeringFlowKey{wire5tuple: f.Wire5Tuple, iface: ifname}
			if r := c.rules[key]; r != nil {
				r.lastSeenTick = tick
			}
		}
	}
}

// evictStaleRules removes controller-owned rules whose flows have
// not appeared in a worker sample for `flowSteeringRuleStaleTicks`
// ticks. This keeps the rule table from growing indefinitely as
// short-lived TCP connections come and go. Sticky rules (`select`
// permanently excludes already-steered flows) means we'd otherwise
// accumulate one rule per ever-seen flow.
func (c *FlowSteeringController) evictStaleRules(tick uint64) {
	c.mu.Lock()
	stale := make([]*flowSteeringInstalledRule, 0)
	for key, r := range c.rules {
		if tick-r.lastSeenTick > flowSteeringRuleStaleTicks {
			stale = append(stale, r)
			delete(c.rules, key)
			if m := c.usedLo[r.iface]; m != nil {
				delete(m, r.ruleLoc)
			}
		}
	}
	c.mu.Unlock()
	for _, r := range stale {
		if err := c.deleteRule(r.iface, r.ruleLoc); err != nil {
			c.log.Warn("flow-steering evict failed",
				"iface", r.iface, "loc", r.ruleLoc, "err", err)
			continue
		}
		c.rulesRemoved.Add(1)
	}
}

// reconcileIface runs the per-interface decision: detect imbalance
// and pick K candidates to re-steer. Holds c.mu only for state
// updates; ethtool shell-outs run unlocked to avoid serializing the
// controller behind a slow process.
func (c *FlowSteeringController) reconcileIface(ifname string, group []BindingStatus, tick uint64) {
	c.mu.Lock()

	// Update binding tick-stamps: track which bindings just GREW
	// (received re-steered flow) so we don't pile more onto them.
	// Sources whose count dropped are NOT cooldown'd — we want to
	// keep migrating from the heaviest binding.
	cooldown := make(map[uint32]bool, len(group))
	for _, b := range group {
		stamp := c.bind[b.Slot]
		if stamp == nil {
			stamp = &flowSteeringBindingTickStamp{lastCount: b.ActiveIngressFlowsCount, lastChangeTick: tick}
			c.bind[b.Slot] = stamp
			continue
		}
		if b.ActiveIngressFlowsCount > stamp.lastCount {
			stamp.lastChangeTick = tick
		}
		stamp.lastCount = b.ActiveIngressFlowsCount
		if tick-stamp.lastChangeTick < flowSteeringBindingCooldownTicks {
			cooldown[b.Slot] = true
		}
	}

	// Find min/max bindings and the imbalance score.
	_, maxSlot, minCount, maxCount := pickMinMax(group)
	if maxCount-minCount < flowSteeringMinImbalance {
		c.mu.Unlock()
		return
	}
	c.imbalanceDetected.Add(1)

	// Source binding must not be in cooldown — destination cooldown
	// is enforced inside selectDestinationQueues.
	if cooldown[maxSlot] {
		c.mu.Unlock()
		return
	}

	// Pick K candidate flows from the source (max) binding.
	src := bindingBySlot(group, maxSlot)
	if src == nil {
		c.mu.Unlock()
		return
	}
	candidates := c.selectStableCandidatesLocked(ifname, src.ActiveIngressFlowsSample)
	if len(candidates) == 0 {
		c.mu.Unlock()
		return
	}
	if len(candidates) > flowSteeringMaxResteerPerTick {
		candidates = candidates[:flowSteeringMaxResteerPerTick]
	}

	// Build an ordered list of destination NIC queues from the
	// least-loaded bindings (bottom-K under cooldown filter). The
	// ntuple `action <N>` is the NIC RX ring index — BindingStatus
	// .QueueID is the actual NIC RX queue the binding is bound to.
	// Spreading across the bottom-K avoids piling all migrated flows
	// onto a single queue, which is what made the first iteration
	// only push CoV from 62.5% to ~44%.
	dstQueues := selectDestinationQueues(group, cooldown, len(candidates))
	if len(dstQueues) == 0 {
		c.mu.Unlock()
		return
	}

	// Plan rule installations under the lock; execute ethtool calls
	// after releasing the lock so a slow shell-out doesn't stall
	// other Manager paths. The rule slot is auto-allocated by the
	// kernel — we don't pre-assign locs because real mlx5 hardware
	// has driver-specific table sizes that aren't 32k.
	type plan struct {
		flow  flowSteeringFlowKey
		queue uint32
	}
	plans := make([]plan, 0, len(candidates))
	for i, cand := range candidates {
		plans = append(plans, plan{
			flow:  flowSteeringFlowKey{wire5tuple: cand.Wire5Tuple, iface: ifname},
			queue: dstQueues[i%len(dstQueues)],
		})
	}
	c.mu.Unlock()

	for _, p := range plans {
		ruleLoc, err := c.installRule(p.flow, p.queue)
		if err != nil {
			c.log.Warn("flow-steering install failed",
				"iface", ifname,
				"flow", p.flow.wire5tuple, "queue", p.queue, "err", err)
			c.installFailures.Add(1)
			continue
		}
		c.mu.Lock()
		c.markRuleLocUsedLocked(ifname, ruleLoc)
		c.rules[p.flow] = &flowSteeringInstalledRule{
			iface:        ifname,
			ruleLoc:      ruleLoc,
			targetQueue:  p.queue,
			installedAt:  time.Now(),
			tick:         tick,
			lastSeenTick: tick,
			flow:         p.flow,
		}
		c.mu.Unlock()
		c.rulesInstalled.Add(1)
		c.recordResteer(FlowSteeringResteerEvent{
			At:          time.Now(),
			Iface:       ifname,
			Flow:        p.flow.wire5tuple,
			TargetQueue: p.queue,
			RuleLoc:     ruleLoc,
			Reason:      fmt.Sprintf("imbalance %d->%d", maxCount, minCount),
		})
	}
}

// selectStableCandidatesLocked picks flows from the sample that are
// (a) past the install_age stability gate, (b) within the
// last_seen recency window, (c) NOT already steered by us. Selection
// is deterministic by hash(wire_5tuple) so logs and tests are
// reproducible.
//
// A flow that already has a controller-owned ntuple rule is
// permanently out of the candidate pool until the rule is removed
// (via flushAllRules on disable/Stop, or future per-flow eviction).
// The plan v6 5-tick "no-resteer cooldown" turned out to be wrong
// shape: it allowed the controller to ALSO re-steer the same flow
// after the cooldown expired, leaving stale rules and inflating
// rule count without improving fairness. Sticky placement is the
// right invariant for closed-loop ntuple — once a flow is on a
// queue, leave it there.
//
// MUST be called with c.mu held.
func (c *FlowSteeringController) selectStableCandidatesLocked(
	ifname string,
	sample []ActiveFlowSampleStatus,
) []ActiveFlowSampleStatus {
	out := make([]ActiveFlowSampleStatus, 0, len(sample))
	for _, f := range sample {
		if f.InstallAgeSecs < flowSteeringStableInstallAgeSecs {
			continue
		}
		if f.LastSeenAgeMs >= flowSteeringStableLastSeenAgeMs {
			continue
		}
		key := flowSteeringFlowKey{wire5tuple: f.Wire5Tuple, iface: ifname}
		if c.rules[key] != nil {
			// Already steered — sticky placement.
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		hi := flowSteeringHash(out[i].Wire5Tuple)
		hj := flowSteeringHash(out[j].Wire5Tuple)
		if hi == hj {
			return out[i].Wire5Tuple < out[j].Wire5Tuple
		}
		return hi < hj
	})
	return out
}

func (c *FlowSteeringController) markRuleLocUsedLocked(ifname string, loc int) {
	if c.usedLo[ifname] == nil {
		c.usedLo[ifname] = make(map[int]struct{})
	}
	c.usedLo[ifname][loc] = struct{}{}
}

// installRule shells out to ethtool to program a per-5-tuple ntuple
// rule. The wire5tuple format produced by the Rust worker is e.g.:
//
//	tcp 10.0.0.1:5201 -> 172.16.80.200:43210
//	tcp [2001:db8::1]:5201 -> [2001:db8::2]:43210
//
// Handles TCP IPv4 + IPv6. The driver auto-allocates the rule slot
// from its supported range (mlx5 in this lab has a 1024-entry table;
// specifying a fixed `loc 32768+` would fail with "No space left on
// device"). We parse the kernel's reply "Added rule with ID N" to
// learn the assigned slot.
func (c *FlowSteeringController) installRule(
	flow flowSteeringFlowKey,
	targetQueue uint32,
) (int, error) {
	parts, err := parseWire5Tuple(flow.wire5tuple)
	if err != nil {
		return 0, fmt.Errorf("parse 5-tuple: %w", err)
	}
	if parts.proto != "tcp" {
		// Phase 1: TCP only.
		return 0, fmt.Errorf("unsupported flow proto: %q", flow.wire5tuple)
	}
	flowType := "tcp4"
	if !parts.isV4 {
		flowType = "tcp6"
	}
	args := []string{
		"-N", flow.iface,
		"flow-type", flowType,
		"src-ip", parts.srcIP,
		"dst-ip", parts.dstIP,
		"src-port", strconv.Itoa(int(parts.srcPort)),
		"dst-port", strconv.Itoa(int(parts.dstPort)),
		"action", strconv.FormatUint(uint64(targetQueue), 10),
	}
	out, err := c.runEthtool(args...)
	if err != nil {
		return 0, fmt.Errorf("ethtool %s: %w (output=%s)", strings.Join(args, " "), err, out)
	}
	id, err := parseEthtoolRuleID(out)
	if err != nil {
		return 0, fmt.Errorf("parse rule id from ethtool output %q: %w", out, err)
	}
	return id, nil
}

// parseEthtoolRuleID parses the kernel's reply
//
//	Added rule with ID 1023
//
// returning the assigned rule slot. If the reply is empty or doesn't
// match, returns an error so the caller can surface it.
func parseEthtoolRuleID(out string) (int, error) {
	for _, line := range strings.Split(out, "\n") {
		const prefix = "Added rule with ID "
		if i := strings.Index(line, prefix); i >= 0 {
			tok := strings.TrimSpace(line[i+len(prefix):])
			id, err := strconv.Atoi(tok)
			if err != nil {
				return 0, err
			}
			return id, nil
		}
	}
	return 0, fmt.Errorf("no rule-id line")
}

func (c *FlowSteeringController) deleteRule(ifname string, ruleLoc int) error {
	args := []string{"-N", ifname, "delete", strconv.Itoa(ruleLoc)}
	if _, err := c.runEthtool(args...); err != nil {
		return fmt.Errorf("ethtool %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// flushAllRules deletes every rule the controller installed. Called
// on Stop, on disable, and on driver eligibility loss.
func (c *FlowSteeringController) flushAllRules() {
	c.mu.Lock()
	rules := make([]*flowSteeringInstalledRule, 0, len(c.rules))
	for _, r := range c.rules {
		rules = append(rules, r)
	}
	c.rules = make(map[flowSteeringFlowKey]*flowSteeringInstalledRule)
	c.usedLo = make(map[string]map[int]struct{})
	c.mu.Unlock()
	for _, r := range rules {
		if err := c.deleteRule(r.iface, r.ruleLoc); err != nil {
			c.log.Warn("flow-steering delete failed", "iface", r.iface, "loc", r.ruleLoc, "err", err)
			continue
		}
		c.rulesRemoved.Add(1)
	}
}

func (c *FlowSteeringController) recordResteer(ev FlowSteeringResteerEvent) {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	c.history = append(c.history, ev)
	if len(c.history) > flowSteeringHistorySize {
		c.history = c.history[len(c.history)-flowSteeringHistorySize:]
	}
}

// HistorySnapshot returns a copy of the most-recent re-steer events
// for `show cos flow-steering`.
func (c *FlowSteeringController) HistorySnapshot() []FlowSteeringResteerEvent {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	out := make([]FlowSteeringResteerEvent, len(c.history))
	copy(out, c.history)
	return out
}

// MetricsSnapshot returns the current Prometheus counter values.
func (c *FlowSteeringController) MetricsSnapshot() FlowSteeringMetrics {
	return FlowSteeringMetrics{
		Enabled:           c.enabled.Load(),
		RulesInstalled:    c.rulesInstalled.Load(),
		RulesRemoved:      c.rulesRemoved.Load(),
		ImbalanceDetected: c.imbalanceDetected.Load(),
		InstallFailures:   c.installFailures.Load(),
		RuleTableCapacity: c.ruleTableCapacity.Load(),
	}
}

// FlowSteeringMetrics is the operator-facing summary surfaced via
// Prometheus and `show cos flow-steering`.
type FlowSteeringMetrics struct {
	Enabled           bool
	RulesInstalled    uint64
	RulesRemoved      uint64
	ImbalanceDetected uint64
	InstallFailures   uint64
	RuleTableCapacity uint64
}

func (c *FlowSteeringController) ensureIface(ifname string) *flowSteeringIfaceState {
	c.mu.Lock()
	st, ok := c.ifaces[ifname]
	c.mu.Unlock()
	if ok && time.Since(st.resolvedAt) < 30*time.Second {
		return st
	}
	parent := resolveParentIface(ifname)
	driver, err := c.detectDriver(parent)
	st = &flowSteeringIfaceState{
		name:       ifname,
		driver:     driver,
		resolvedAt: time.Now(),
	}
	if err != nil {
		st.eligible = false
		st.reason = fmt.Sprintf("driver detect failed: %v", err)
	} else if driver != "mlx5_core" {
		st.eligible = false
		st.reason = fmt.Sprintf("unsupported driver %q (only mlx5_core in Phase 1)", driver)
	} else if !c.ntupleToggleable(parent) {
		st.eligible = false
		st.reason = "ntuple-filters not toggleable"
	} else {
		st.eligible = true
		st.reason = "ok"
		// Best effort: enable ntuple-filters on if currently off.
		if _, err := c.runEthtool("-K", parent, "ntuple-filters", "on"); err != nil {
			c.log.Warn("ethtool -K ntuple-filters on failed", "iface", parent, "err", err)
		}
	}
	c.mu.Lock()
	c.ifaces[ifname] = st
	c.mu.Unlock()
	return st
}

// detectDriver reads /sys/class/net/<iface>/device/driver to determine
// the kernel driver bound to the NIC. Returns the basename of the
// symlink target (e.g., "mlx5_core").
func (c *FlowSteeringController) detectDriver(ifname string) (string, error) {
	target, err := os.Readlink(filepath.Join("/sys/class/net", ifname, "device", "driver"))
	if err != nil {
		return "", err
	}
	return filepath.Base(target), nil
}

// ntupleToggleable runs `ethtool -k <iface>` and looks for a line
// like "ntuple-filters: on" without "[fixed]". A driver that reports
// "[fixed]" cannot have ntuple toggled at runtime.
func (c *FlowSteeringController) ntupleToggleable(ifname string) bool {
	out, err := c.runEthtool("-k", ifname)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ntuple-filters:") {
			return !strings.Contains(line, "[fixed]")
		}
	}
	return false
}

func (c *FlowSteeringController) expireBindingTickStamps(tick uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for slot, stamp := range c.bind {
		// Drop stamps older than 60 ticks to bound memory; they will
		// be re-created on demand.
		if tick-stamp.lastChangeTick > 60 {
			delete(c.bind, slot)
		}
	}
}

// --- Helpers (file-private) -------------------------------------------------

func defaultRunEthtool(args ...string) (string, error) {
	cmd := exec.Command("ethtool", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func defaultReadSysfs(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// resolveParentIface strips a VLAN suffix `<base>.<vlan>` to return
// the parent NIC. ntuple rules program the parent NIC; VLAN tag
// matching is added via the rule's `vlan` clause (Phase 1 deferred —
// the iperf-c P=12 baseline is on the parent's VLAN 80 sub-interface
// but the parent is what carries ntuple-filters).
func resolveParentIface(ifname string) string {
	if i := strings.IndexByte(ifname, '.'); i > 0 {
		return ifname[:i]
	}
	return ifname
}

func groupBindingsByIface(bindings []BindingStatus) map[string][]BindingStatus {
	// Phase 1 groups by (Iface, BindingStatus.ActiveIngressFlowsCount).
	// Iface is identified via SocketIfindex → name. We resolve names
	// per-tick for clarity.
	out := make(map[string][]BindingStatus)
	for _, b := range bindings {
		if b.Ifindex == 0 {
			continue
		}
		name := b.Interface
		if name == "" {
			name = ifindexName(b.Ifindex)
			if name == "" {
				continue
			}
		}
		out[name] = append(out[name], b)
	}
	return out
}

func ifindexName(ifindex int) string {
	link, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return ""
	}
	return link.Name
}

func pickMinMax(group []BindingStatus) (minSlot, maxSlot uint32, minCount, maxCount uint32) {
	if len(group) == 0 {
		return
	}
	minSlot, maxSlot = group[0].Slot, group[0].Slot
	minCount, maxCount = group[0].ActiveIngressFlowsCount, group[0].ActiveIngressFlowsCount
	for _, b := range group[1:] {
		c := b.ActiveIngressFlowsCount
		if c < minCount {
			minCount = c
			minSlot = b.Slot
		}
		if c > maxCount {
			maxCount = c
			maxSlot = b.Slot
		}
	}
	return
}

func bindingBySlot(group []BindingStatus, slot uint32) *BindingStatus {
	for i := range group {
		if group[i].Slot == slot {
			return &group[i]
		}
	}
	return nil
}

// selectDestinationQueues returns up to K NIC RX queues drawn from the
// least-loaded non-cooldown bindings, deduplicated. Bindings are
// scored by ActiveIngressFlowsCount asc, then slot asc for stable
// tie-breaks. Multiple bindings can share a NIC queue (HA
// mode → 12 bindings, 6 queues), so dedup by QueueID — round-robin
// distribution among k unique queues is what flattens per-queue
// imbalance.
func selectDestinationQueues(
	group []BindingStatus,
	cooldown map[uint32]bool,
	k int,
) []uint32 {
	if k <= 0 || len(group) == 0 {
		return nil
	}
	type entry struct {
		slot    uint32
		queue   uint32
		count   uint32
	}
	scored := make([]entry, 0, len(group))
	for _, b := range group {
		if cooldown[b.Slot] {
			continue
		}
		scored = append(scored, entry{slot: b.Slot, queue: b.QueueID, count: b.ActiveIngressFlowsCount})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].count != scored[j].count {
			return scored[i].count < scored[j].count
		}
		return scored[i].slot < scored[j].slot
	})
	out := make([]uint32, 0, k)
	seen := make(map[uint32]struct{}, k)
	for _, e := range scored {
		if _, dup := seen[e.queue]; dup {
			continue
		}
		seen[e.queue] = struct{}{}
		out = append(out, e.queue)
		if len(out) >= k {
			break
		}
	}
	return out
}

func flowSteeringHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// wire5TupleParts captures the parsed shape of an
// ActiveFlowSampleStatus.Wire5Tuple. Phase 1 only handles tcp4; udp
// and IPv6 are recognized so the parser doesn't emit confusing errors
// but they're rejected at install time.
type wire5TupleParts struct {
	proto   string
	isV4    bool
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

// parseWire5Tuple parses the controller-side wire 5-tuple string
// emitted by the Rust worker's format_session_key_wire helper:
//
//	tcp 10.0.0.1:5201 -> 172.16.80.200:43210
//	udp [2001:db8::1]:53 -> [2001:db8::2]:53
//	icmp 10.0.0.1 -> 10.0.0.2
//
// Phase 1 only steers IPv4 TCP/UDP. ICMP and IPv6 are recognized but
// will be rejected at install time.
func parseWire5Tuple(s string) (wire5TupleParts, error) {
	var p wire5TupleParts
	parts := strings.Fields(s)
	if len(parts) < 4 {
		return p, fmt.Errorf("expected `proto src -> dst`, got %q", s)
	}
	p.proto = parts[0]
	if parts[2] != "->" {
		return p, fmt.Errorf("missing `->` separator in %q", s)
	}
	src, dst := parts[1], parts[3]
	srcIP, srcPort, srcV4, err := splitEndpoint(src, p.proto)
	if err != nil {
		return p, err
	}
	dstIP, dstPort, dstV4, err := splitEndpoint(dst, p.proto)
	if err != nil {
		return p, err
	}
	p.srcIP = srcIP
	p.dstIP = dstIP
	p.srcPort = srcPort
	p.dstPort = dstPort
	p.isV4 = srcV4 && dstV4
	return p, nil
}

func splitEndpoint(s, proto string) (string, uint16, bool, error) {
	// ICMP forms: bare IP (no port).
	if proto == "icmp" || proto == "icmpv6" {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", 0, false, fmt.Errorf("invalid IP %q", s)
		}
		return ip.String(), 0, ip.To4() != nil, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false, fmt.Errorf("split host/port from %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false, fmt.Errorf("parse port from %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", 0, false, fmt.Errorf("invalid IP %q from endpoint %q", host, s)
	}
	return ip.String(), uint16(port), ip.To4() != nil, nil
}

