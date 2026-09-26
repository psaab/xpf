// Package rpm implements Real-time Performance Monitoring probes.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// probeDialer returns a net.Dialer carrying the per-test socket options:
// optional source address, SO_BINDTODEVICE (destination-interface, or
// the "vrf-"+instance VRF device fallback), and SO_MARK for
// next-hop-pinned tests (#1827).
//
// A NON-EMPTY but unparseable source-address is a setup error, not a
// path signal (#2492): net.ParseIP returns nil, and a TCPAddr{IP:nil}
// silently degrades to a wildcard/kernel-chosen source bind — the probe
// would then measure the DEFAULT uplink instead of the source-specific
// path the operator pinned, publishing PASS/FAIL for the wrong path.
// The commit-time validator (validateRPMSourceAddressStrict) rejects
// this on the strict path, but a leniently-loaded or externally-built
// config can still reach here, so guard defensively and surface
// ErrProbeSetup. The ICMP path already fails closed via its real
// listen error; tcp-ping/http-get had no such backstop. An EMPTY
// source-address stays legitimate (means "default source"): only a
// non-empty value that will not parse is the error.
func probeDialer(timeout time.Duration, sourceAddr string, opts probeSockOpts) (*net.Dialer, *setupErrSink, error) {
	d := &net.Dialer{Timeout: timeout}
	if sourceAddr != "" {
		ip := net.ParseIP(sourceAddr)
		if ip == nil {
			return nil, nil, fmt.Errorf("%w: invalid source-address %q (would bind wildcard source)",
				ErrProbeSetup, sourceAddr)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	var sink *setupErrSink
	if opts.BindDevice != "" || opts.Mark != 0 {
		// Resolve the hostname IN THE PROBE'S VRF/path scope (#2614): the
		// dialer's own name resolution otherwise runs through the
		// process-default resolver BEFORE the Control bind below applies,
		// so a tcp-ping / http-get hostname target inside a VRF would
		// resolve out-of-context (the same defect fixed for icmp-ping in
		// resolveProbeTarget). Setting Resolver pins the DNS socket to the
		// same SO_BINDTODEVICE / SO_MARK as the connect socket. A literal
		// IP target skips DNS entirely, so this is a no-op for IP targets.
		//
		// Both the connect socket and the DNS resolver socket use the SAME
		// shared vrfBindControl (#5061): a SO_BINDTODEVICE / SO_MARK bind
		// failure on EITHER is classified ErrProbeSetup so the probe holds
		// state instead of counting loss. The connect-socket failure rides
		// out through net.OpError (errors.Is finds the sentinel); the
		// resolver-socket failure is flattened to a string by *net.DNSError,
		// so it is captured in sink and the probe re-tags its dial failure
		// from sink (see probeTCP / probeHTTP). Genuine dial outcomes
		// (refused, timeout, unreachable) never pass through this callback.
		sink = &setupErrSink{}
		d.Resolver = vrfBoundResolver(opts, sink)
		d.Control = vrfBindControl(opts, sink)
	}
	return d, sink, nil
}

// vrfDeviceName returns the VRF device name for a routing instance.
func vrfDeviceName(ri string) string {
	if ri == "" {
		return ""
	}
	return "vrf-" + ri
}

// ProbeResult holds the current state of a single RPM test.
type ProbeResult struct {
	ProbeName   string
	TestName    string
	ProbeType   string
	Target      string
	LastRTT     time.Duration
	MinRTT      time.Duration
	MaxRTT      time.Duration
	AvgRTT      time.Duration
	Jitter      time.Duration // running absolute deviation from average
	LastStatus  string        // "pass" or "fail"
	SuccFail    int           // consecutive failures
	TotalSent   int64
	TotalRecv   int64
	LastProbeAt time.Time

	// identity is the RESOLVED measurement this result is a verdict about
	// (#6561): probe type, target, source, routing-instance, next-hop and the
	// destination interface AFTER RETH translation. Apply carries a verdict
	// across a probe restart only when this is unchanged, so a verdict measured
	// over one path is never reported for another. Unexported — it is an
	// internal equality token, not part of the result an operator or
	// ip-monitoring reads. `Results()` copies the whole struct, so it travels
	// with a snapshot without anyone having to remember it.
	identity string
}

// Event represents an RPM event for event-options matching.
type Event struct {
	Name      string // "ping_test_failed", "ping_probe_failed", "ping_test_completed"
	TestOwner string // probe name (matches attributes-match test-owner)
	TestName  string // test name (matches attributes-match test-name)
	// Static per-test config strings exposed to attributes-match (#3756 H14).
	// They are stable identifiers already in scope at every fireEvent call
	// site, so an operator can key remediation on "all probes to target X" or
	// "all probes in routing-instance Y" without a new attribute taxonomy.
	Target               string // test target IP/hostname (attributes-match target)
	RoutingInstance      string // test routing-instance ("" = master) (routing-instance)
	DestinationInterface string // egress-interface pin (destination-interface)
}

// EventCallback is called when RPM probes generate events.
type EventCallback func(Event)

// Transition reports a per-test pass/fail status transition together
// with a current-state snapshot of all probe results (#1827 PR-1a §4.2
// item 6). It is the sensor input for the ip-monitoring engine; the
// coarser Event/EventCallback surface stays intact for eventengine.
type Transition struct {
	ProbeName  string
	TestName   string
	Status     string // new status: "pass" or "fail"
	Generation uint64 // manager-local transition order; zero means unspecified
	Results    []*ProbeResult
}

// TransitionCallback is called on per-test status transitions.
type TransitionCallback func(Transition)

// Manager runs RPM probes and tracks their results.
type Manager struct {
	mu           sync.RWMutex
	results      map[string]*ProbeResult // key: "probe/test"
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	onEvent      EventCallback
	onTransition TransitionCallback
	// transitionGeneration orders snapshots from concurrent probe goroutines.
	// Guarded by mu and incremented atomically with the corresponding result
	// status and snapshot.
	transitionGeneration uint64

	// bufferedEvents holds events fired BEFORE an event-options callback was
	// registered (#3755). The first probe cycle runs immediately when Apply
	// starts a probe, so a probe-failed/test-failed/test-completed event can be
	// emitted before SetEventCallback installs onEvent (boot ordering, or any
	// late registration). Rather than drop that boot-time failover edge, the
	// events are buffered and REPLAYED to the callback the moment it is
	// registered. Bounded by maxBufferedEvents so a permanently-absent callback
	// (event-options never configured) cannot grow it without limit.
	bufferedEvents []Event

	// rethMap translates Junos RETH names to physical members for
	// destination-interface resolution (set by the daemon in cluster
	// mode before Apply).
	rethMap map[string]string

	// marks maps "probe/test" to the probe fwmark for next-hop-pinned
	// tests, derived in Apply from the same deterministic assignment
	// pkg/routing programs (routing.BuildProbePins).
	marks map[string]uint32

	// pinFailed maps "probe/test" to the kernel install error for pins
	// whose fwmark rule / pinned route failed to program (#1895), as
	// reported by routing.Manager.ApplyProbePins and threaded in by the
	// daemon via SetPinInstallResults. A test with a failed pin never
	// probes (executeProbe returns ErrProbeSetup before any socket is
	// opened) — an unbacked SO_MARK would fall through to the main
	// table and measure the default path, turning a dead pinned uplink
	// into a false PASS that suppresses ip-monitoring failover.
	pinFailed map[string]error

	// icmpListen is the injectable raw-socket seam for the ICMP echo
	// prober. nil = realICMPListen.
	icmpListen icmpListenFunc

	// probeFn, when non-nil, replaces executeProbe — the injectable
	// seam for unit-testing the per-cycle pass/fail transition logic
	// with a scripted probe-result sequence (#2527). It is set once
	// before the manager runs and never mutated concurrently.
	probeFn func(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error)

	// resolveTarget is the injectable hostname-resolution seam (#2493,
	// VRF-aware since #2614). nil = resolveProbeTarget. The default
	// resolver is now scope-aware: it is passed the probe's probeSockOpts
	// (BindDevice / Mark) and, for a SCOPED test (routing-instance /
	// destination-interface / next-hop), builds a net.Resolver whose DNS
	// socket is pinned to the SAME VRF/path (SO_BINDTODEVICE / SO_MARK) the
	// probe DATA socket uses — so a hostname target inside a VRF resolves
	// through the VRF's DNS, not the process-default table. An unscoped
	// test uses the default resolver. Returns *net.IPAddr so the IPv6
	// link-local zone is preserved through to the send path (#2494). Tests
	// inject this to assert the bound resolver is built with the probe's
	// device/mark (live VRF DNS is lab-bound).
	//
	// The probe-cycle ctx is threaded into the lookup (#2647): a stuck DNS
	// query for a HOSTNAME target now honors the cycle's
	// cancellation/deadline (config reload, service stop) instead of
	// running under context.Background() and outliving the cycle — matching
	// the ctx-bound TCP DialContext and HTTP NewRequestWithContext paths. A
	// literal-IP target short-circuits before DNS, so ctx is irrelevant.
	resolveTarget func(ctx context.Context, target string, opts probeSockOpts) (*net.IPAddr, error)
}

// maxBufferedEvents bounds the pre-registration event buffer (#3755) so a
// callback that never arrives cannot grow it without limit. The buffer only
// holds the small burst a first probe cycle can produce before the callback is
// installed; in the normal daemon boot the callback is registered before any
// probe starts (initEventEngine precedes reconcileRPM), so it stays empty.
const maxBufferedEvents = 64

// SetEventCallback registers a callback for RPM events. Any events buffered
// before a callback existed (a first probe cycle that ran before the
// event-options callback was wired) are REPLAYED to the new callback in FIFO
// order, so a boot-time failover edge is not lost (#3755). The replay runs
// OUTSIDE m.mu because the callback (eventengine.HandleEvent) takes its own
// locks; holding m.mu across it would invert the lock order.
func (m *Manager) SetEventCallback(fn EventCallback) {
	m.mu.Lock()
	m.onEvent = fn
	var replay []Event
	if fn != nil && len(m.bufferedEvents) > 0 {
		replay = m.bufferedEvents
		m.bufferedEvents = nil
	}
	m.mu.Unlock()

	for _, ev := range replay {
		fn(ev)
	}
}

// HasEventCallback reports whether an event-options callback is currently
// registered. Used by the daemon boot-ordering tests to assert the callback is
// wired before RPM probes start (#3755).
func (m *Manager) HasEventCallback() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onEvent != nil
}

// SetTransitionCallback registers a callback for per-test pass/fail
// status transitions.
func (m *Manager) SetTransitionCallback(fn TransitionCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onTransition = fn
}

// SetRethMap supplies the RETH → physical member translation used when
// resolving destination-interface names. Call before Apply.
func (m *Manager) SetRethMap(rethMap map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rethMap = rethMap
}

// SetPinInstallResults supplies the per-test probe-pin install
// failures from the most recent routing.Manager.ApplyProbePins (keys
// "probe/test", values the install error; nil/empty = all pins
// installed). The map is replaced wholesale, so a successful re-apply
// clears earlier failures and live probe loops resume on their next
// tick — no probe restart required. On a config change the daemon
// publishes AFTER Apply (the HoldPinsForReprogram union covers the
// interim); on a hash-gated pin retry it publishes immediately
// (#1895).
func (m *Manager) SetPinInstallResults(failed map[string]error) {
	cp := make(map[string]error, len(failed))
	for k, v := range failed {
		cp[k] = v
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pinFailed = cp
}

// HoldPinsForReprogram replaces the pin-failure map with one that
// holds EVERY currently-marked (live) pinned test PLUS the supplied
// new pin keys, all with cause. Called by the daemon immediately
// before the kernel pin band is cleared-and-reprogrammed: live probe
// goroutines — including ones whose keys are absent from the new pin
// set, or whose deterministic mark is about to change — must not send
// an SO_MARK probe against a band in flux (a stale mark can match
// another test's new fwmark rule and measure the wrong uplink; Codex
// PR #1899 r2). The caller publishes the real install results via
// SetPinInstallResults once the reprogram (and, on a config change,
// the probe re-Apply) has completed.
func (m *Manager) HoldPinsForReprogram(newPinKeys []string, cause error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	held := make(map[string]error, len(m.marks)+len(newPinKeys))
	for k := range m.marks {
		held[k] = cause
	}
	for _, k := range newPinKeys {
		held[k] = cause
	}
	m.pinFailed = held
}

// PinInstallFailureCount reports how many next-hop probe pins are
// currently failed-to-install (backs the
// xpf_rpm_probe_pin_install_failures gauge, #1895).
func (m *Manager) PinInstallFailureCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pinFailed)
}

// fireEvent builds an rpm.Event for event-options matching. It takes the whole
// *config.RPMTest so the static per-test strings (test-name, target,
// routing-instance, destination-interface) are populated for attributes-match
// (#3756 H14) at every call site. test is always non-nil from runSingleTest;
// the nil guard is defensive.
func (m *Manager) fireEvent(name, owner string, test *config.RPMTest) {
	ev := Event{Name: name, TestOwner: owner}
	if test != nil {
		ev.TestName = test.Name
		ev.Target = test.Target
		ev.RoutingInstance = test.RoutingInstance
		ev.DestinationInterface = test.DestinationInterface
	}
	m.mu.Lock()
	fn := m.onEvent
	if fn == nil {
		// No event-options callback yet: buffer the event so a first-cycle
		// failover edge is not lost, and replayed when a callback registers
		// (#3755). Bounded — drop once the cap is reached.
		if len(m.bufferedEvents) < maxBufferedEvents {
			m.bufferedEvents = append(m.bufferedEvents, ev)
		}
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	fn(ev)
}

func (m *Manager) prepareTransition(owner, testName, status string) (Transition, TransitionCallback) {
	m.mu.Lock()
	if r := m.results[owner+"/"+testName]; r != nil {
		r.LastStatus = status
	}
	m.transitionGeneration++
	tr := Transition{
		ProbeName:  owner,
		TestName:   testName,
		Status:     status,
		Generation: m.transitionGeneration,
	}
	fn := m.onTransition
	if fn != nil {
		tr.Results = m.resultsLocked()
	}
	m.mu.Unlock()
	return tr, fn
}

// New creates a new RPM manager.
func New() *Manager {
	return &Manager{
		results: make(map[string]*ProbeResult),
	}
}

// Apply starts probes from the given RPM config.
//
// #6561: the prior results are SNAPSHOTTED before StopAll reallocates the table,
// and a test whose definition survives the commit unchanged keeps its runtime
// verdict. Without that, every Apply reseeded every key to LastStatus "unknown",
// and ip-monitoring reads "unknown" as PASS (seedResultsLocked buckets it with
// pass via `r.LastStatus == "fail"`), so at the DEFAULT hold-down of 0 an ACTIVE
// failover route was withdrawn on the spot.
//
// This is not a rare path. reconcileRPM is hash-gated, but the hash covers
// `cfg.RethToPhysical()` as well as the RPM stanza (daemon_rpm.go), so adding,
// removing or renaming ANY RETH member -- an interface-stanza edit that never
// mentions `services rpm` or `services ip-monitoring` -- restarts the probes and
// wiped every verdict. The commit's own FRR render is snapshotted before this
// runs, so the withdrawal never showed up in the commit's output; it landed on
// the delayed actuation about a second later.
//
// The reconcile itself is NOT skipped -- probes genuinely must restart when
// their marks are reprogrammed. What is preserved is the half the config does
// not carry.
func (m *Manager) Apply(ctx context.Context, cfg *config.RPMConfig) {
	// Snapshot BEFORE StopAll: it reallocates m.results, and the mark map is
	// overwritten below.
	m.mu.Lock()
	prevResults := m.results
	m.mu.Unlock()

	m.StopAll()

	if cfg == nil || len(cfg.Probes) == 0 {
		// Clear the mark assignment too: stale marks would otherwise
		// inflate later HoldPinsForReprogram unions (#1895 hygiene —
		// no goroutines exist after StopAll, so this is cosmetic).
		m.mu.Lock()
		m.marks = nil
		m.mu.Unlock()
		return
	}

	// Derive the per-test fwmark assignment from the SAME deterministic
	// function pkg/routing uses to program the pin rules, so socket
	// SO_MARK and kernel fwmark rule can never disagree (#1827).
	m.mu.Lock()
	m.marks = make(map[string]uint32)
	rethMap := m.rethMap
	for _, pin := range routing.BuildProbePins(cfg, rethMap) {
		m.marks[pin.TestKey] = pin.Mark
	}
	m.mu.Unlock()

	probeCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	for _, probe := range cfg.Probes {
		for _, test := range probe.Tests {
			key := probe.Name + "/" + test.Name
			res := &ProbeResult{
				ProbeName:  probe.Name,
				TestName:   test.Name,
				ProbeType:  test.EffectiveProbeType(),
				Target:     test.Target,
				LastStatus: "unknown",
			}
			res.identity = probeMeasurementIdentity(test, rethMap)
			carryProbeVerdict(res, prevResults[key])
			m.mu.Lock()
			m.results[key] = res
			m.mu.Unlock()

			m.wg.Add(1)
			go func(p *config.RPMProbe, t *config.RPMTest, k string) {
				defer m.wg.Done()
				m.runProbeLoop(probeCtx, p, t, k)
			}(probe, test, key)
		}
	}
}

// StopAll stops all running probes.
func (m *Manager) StopAll() {
	if m.cancel != nil {
		m.cancel()
		m.wg.Wait()
		m.cancel = nil
	}
	m.mu.Lock()
	m.results = make(map[string]*ProbeResult)
	m.mu.Unlock()
}

// Results returns a snapshot of all probe results, sorted by key.
func (m *Manager) Results() []*ProbeResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resultsLocked()
}

// resultsLocked returns a sorted deep-enough snapshot. The caller must hold
// m.mu (for reading or writing).
func (m *Manager) resultsLocked() []*ProbeResult {
	keys := make([]string, 0, len(m.results))
	for k := range m.results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*ProbeResult, 0, len(keys))
	for _, k := range keys {
		cp := *m.results[k]
		out = append(out, &cp)
	}
	return out
}

// clampRPMIntervalSeconds converts a config-derived RPM interval (seconds) to a
// positive, non-overflowing time.Duration. A test-interval / probe-interval is
// bounded to config.MaxDurationSeconds at commit by the schema (#5723), but the
// lenient HA-sync / on-disk Load ingress only DOWNGRADES an out-of-range value
// to a warning, so a peer-synced or persisted pathological value can still reach
// the runtime probe loop. Clamping to [1, MaxDurationSeconds] before the
// *time.Second multiply keeps time.Duration(sec)*time.Second within int64
// nanoseconds, so a non-positive Duration can never reach time.NewTicker and
// panic xpfd — the sibling of the #5705 keepalive overflow. EffectiveTest/
// ProbeInterval already floor at their defaults, so sec < 1 is defensive.
func clampRPMIntervalSeconds(sec int) time.Duration {
	if sec < 1 {
		return time.Second
	}
	if int64(sec) > config.MaxDurationSeconds {
		return time.Duration(config.MaxDurationSeconds) * time.Second
	}
	return time.Duration(sec) * time.Second
}

func (m *Manager) runProbeLoop(ctx context.Context, probe *config.RPMProbe, test *config.RPMTest, key string) {
	interval := clampRPMIntervalSeconds(test.EffectiveTestInterval())
	probeInterval := clampRPMIntervalSeconds(test.EffectiveProbeInterval())
	probeCount := test.EffectiveProbeCount()
	threshold := test.EffectiveSuccessiveLossThreshold()

	slog.Info("RPM probe started",
		"probe", probe.Name, "test", test.Name,
		"type", test.EffectiveProbeType(), "target", test.Target,
		"interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run first probe immediately
	m.runSingleTest(ctx, probe.Name, test, key, probeCount, probeInterval, threshold)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runSingleTest(ctx, probe.Name, test, key, probeCount, probeInterval, threshold)
		}
	}
}

func (m *Manager) runSingleTest(ctx context.Context, probeName string, test *config.RPMTest, key string, probeCount int, probeInterval time.Duration, threshold int) {
	var successes, failures int
	probeLimit := test.ProbeLimit // 0 = unlimited
	setupWarned := false

	// The per-test pass/fail status is a per-cycle aggregate, like
	// Junos RPM/ip-monitoring: the successive-loss threshold is
	// evaluated across the WHOLE probe set and the test transitions AT
	// MOST once per cycle — never per probe. Capture the pre-cycle
	// status ONCE; evolve `status` locally through the cycle (so the
	// cross-cycle consecutive-failure counter r.SuccFail keeps its
	// meaning); publish r.LastStatus and fire the transition only after
	// the loop. Firing inside the loop let a single transient mid-cycle
	// success flip fail->pass->fail and flap static-route preference in
	// services ip-monitoring (#2527).
	m.mu.Lock()
	r0 := m.results[key]
	if r0 == nil {
		m.mu.Unlock()
		return
	}
	prevStatus := r0.LastStatus
	m.mu.Unlock()
	status := prevStatus

	for i := 0; i < probeCount; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(probeInterval):
			}
		}

		rtt, err := m.runProbe(ctx, test, key)

		// #5852: a LIFECYCLE cancellation of the shared probe context —
		// StopAll / config replacement / daemon shutdown calling m.cancel()
		// (Apply builds probeCtx as context.WithCancel) — is NEUTRAL to path
		// health. The probe was torn down; it never reached a health verdict,
		// so it must not be mis-counted as path loss and trigger ip-monitoring
		// route remediation DURING teardown/reconfigure. Detect it by the
		// SHARED context's own state (ctx.Err()), NOT the returned error type: a
		// genuine probe TIMEOUT is a per-probe SOCKET deadline (icmp
		// SetReadDeadline / TCP dial timeout) that leaves ctx.Err()==nil and
		// MUST still count as real path loss — the target is actually
		// unreachable. Only m.cancel() cancels probeCtx, so ctx.Err()!=nil is
		// exactly a lifecycle stop; a probe timeout never cancels it.
		// errors.Is(err, context.Canceled) is the equivalent belt (icmp.go
		// returns ctx.Err() on cancellation). RETURN — not just skip this probe
		// — so the post-loop transition can never publish a stale pass/fail edge
		// once teardown has begun. Mirrors the ErrProbeSetup hold below: no
		// counters, no successive-loss advance, no events, no Transition.
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}

		// ErrProbeSetup = environment/capability failure (raw socket
		// open denied, marshal, probe pin not installed #1895): the
		// probe never reached the wire — or must not be sent at all
		// because its kernel pin is unbacked — so it carries NO
		// path-health signal. Hold the test's current
		// state completely — no counters, no status change, no
		// events, no Transition — so ip-monitoring can never actuate
		// routes off a capability regression (AGY PR #1843 F2). Log
		// loudly but rate-limited (once per test cycle, i.e. at most
		// once per test-interval).
		if errors.Is(err, ErrProbeSetup) {
			if !setupWarned {
				setupWarned = true
				slog.Warn("RPM probe setup failed — holding test state (environment error, not path health)",
					"probe", probeName, "test", test.Name, "err", err)
			}
			continue
		}

		m.mu.Lock()
		r := m.results[key]
		if r == nil {
			m.mu.Unlock()
			return
		}
		r.TotalSent++
		r.LastProbeAt = time.Now()
		if err != nil {
			failures++
			r.SuccFail++
			// Successive-loss trip: once `threshold` consecutive
			// probes are lost the test is failed. r.SuccFail carries
			// across cycles, so a fail run spanning a cycle boundary
			// still trips. The status is only PUBLISHED after the loop.
			if r.SuccFail >= threshold {
				status = "fail"
			}
			// Check probe-limit: stop test cycle when reached
			hitLimit := probeLimit > 0 && r.SuccFail >= probeLimit
			m.mu.Unlock()
			// Probe-level failure event stays per-probe — it is an
			// eventengine signal and does not drive ip-monitoring
			// routes (which key off per-test transition callbacks only).
			m.fireEvent("ping_probe_failed", probeName, test)
			if hitLimit {
				break
			}
		} else {
			successes++
			r.TotalRecv++
			// Track min/max/avg RTT and jitter
			if r.MinRTT == 0 || rtt < r.MinRTT {
				r.MinRTT = rtt
			}
			if rtt > r.MaxRTT {
				r.MaxRTT = rtt
			}
			prevAvg := r.AvgRTT
			if r.TotalRecv == 1 {
				r.AvgRTT = rtt
			} else {
				// Exponential moving average (alpha = 1/8 like TCP RTT)
				r.AvgRTT = prevAvg + (rtt-prevAvg)/8
			}
			// Jitter: smoothed absolute deviation (RFC 3550 style)
			diff := rtt - prevAvg
			if diff < 0 {
				diff = -diff
			}
			if r.TotalRecv == 1 {
				r.Jitter = 0
			} else {
				r.Jitter = r.Jitter + (diff-r.Jitter)/16
			}
			r.LastRTT = rtt
			r.SuccFail = 0
			// A success clears the successive-loss run. The status is
			// only PUBLISHED after the loop.
			status = "pass"
			m.mu.Unlock()
		}
	}

	// Publish the per-cycle status decision: compare the aggregate
	// end-of-cycle status to the pre-cycle status and fire AT MOST one
	// transition. This is the single ip-monitoring sensor edge per test
	// cycle (#2527). A below-threshold cycle that never reached "fail"
	// and saw no success leaves `status == prevStatus` (e.g. the
	// initial "unknown" state holds), so no spurious transition fires.
	if status != prevStatus {
		tr, transition := m.prepareTransition(probeName, test.Name, status)
		if status == "fail" {
			m.fireEvent("ping_test_failed", probeName, test)
		}
		if transition != nil {
			transition(tr)
		}
	}

	// Fire test completed if all probes passed
	if failures == 0 && successes > 0 {
		m.fireEvent("ping_test_completed", probeName, test)
	}
}

// probeOpts derives the per-test socket options: destination-interface
// (resolved through the RETH map) takes precedence over the
// routing-instance VRF device for SO_BINDTODEVICE; next-hop-pinned
// tests carry their probe fwmark for SO_MARK.
func (m *Manager) probeOpts(test *config.RPMTest, key string) probeSockOpts {
	m.mu.RLock()
	mark := m.marks[key]
	rethMap := m.rethMap
	m.mu.RUnlock()

	bindDev := routing.ResolveProbeInterface(test.DestinationInterface, rethMap)
	if bindDev == "" {
		bindDev = vrfDeviceName(test.RoutingInstance)
	}
	return probeSockOpts{BindDevice: bindDev, Mark: mark}
}

// pinInstallError gates next-hop-pinned tests on their kernel pin
// actually being installed (#1895). A pin that failed to program —
// or a next-hop test that never received a pin slot at all
// (band-exhaustion belt-and-braces; commit validation caps this on
// the strict path) — returns an ErrProbeSetup-wrapped error so the
// probe loop holds the test's state. The probe must NOT be sent: an
// unbacked SO_MARK falls through to the main table and measures the
// default path instead of the pinned uplink (false PASS).
func (m *Manager) pinInstallError(test *config.RPMTest, key string) error {
	if test.NextHop == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cause, ok := m.pinFailed[key]; ok {
		return fmt.Errorf("%w: probe pin not installed: %v", ErrProbeSetup, cause)
	}
	if m.marks[key] == 0 {
		return fmt.Errorf("%w: no probe pin slot assigned for next-hop test", ErrProbeSetup)
	}
	return nil
}

// runProbe dispatches a single probe through the test seam when one is
// installed, otherwise the real executeProbe path.
func (m *Manager) runProbe(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	if m.probeFn != nil {
		return m.probeFn(ctx, test, key)
	}
	return m.executeProbe(ctx, test, key)
}

func (m *Manager) executeProbe(ctx context.Context, test *config.RPMTest, key string) (time.Duration, error) {
	if err := m.pinInstallError(test, key); err != nil {
		return 0, err
	}
	opts := m.probeOpts(test, key)
	switch test.EffectiveProbeType() {
	case "icmp-ping":
		return m.probeICMP(ctx, test, opts)
	case "tcp-ping":
		return m.probeTCP(ctx, test, opts)
	case "http-get":
		return m.probeHTTP(ctx, test, opts)
	default:
		return m.probeICMP(ctx, test, opts)
	}
}

func (m *Manager) probeTCP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	port := test.EffectiveDestinationPort()

	// #9026: an IPv6 link-local target must carry a scope, exactly as
	// probeICMP requires. Without this, an unscopeable fe80:: target dialed,
	// failed, and was wrapped as a generic error — which pkg/rpm counts as PATH
	// LOSS, and `services ip-monitoring` drives preferred-route injection off
	// that. A probe that never left the box could fail over a WAN.
	//
	// Resolved BEFORE the dial so the address carries its zone; a bare fe80::
	// with no zone returns ErrProbeSetup and the test HOLDS.
	target := test.Target
	if ip, zone := splitTargetZone9026(target); ip != nil {
		resolved, zerr := m.resolveLinkLocalZone9026("tcp", ip, zone, test.DestinationInterface)
		if zerr != nil {
			return 0, zerr
		}
		if resolved != "" {
			target = ip.String() + "%" + resolved
		}
	}

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	dialer, sink, err := probeDialer(5*time.Second, test.SourceAddress, opts)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// A VRF-bound resolver socket-setup failure is lost through
		// *net.DNSError, so re-tag it as ErrProbeSetup from the out-of-band
		// sink — the probe never left the box and must hold state, not count
		// loss (#5061). A connect-socket setup failure already carries the
		// sentinel via net.OpError; either way this yields ErrProbeSetup.
		if se := sink.load(); se != nil {
			return 0, se
		}
		return 0, fmt.Errorf("TCP connect failed: %w", err)
	}
	rtt := time.Since(start)
	conn.Close()
	return rtt, nil
}

// canonicalizeHTTPTarget turns an http-get probe target into a fully
// schemed URL suitable for http.NewRequestWithContext.
//
// A bare hostname, IP literal, or host:port (no "://" separator) gets
// the default "http://" scheme prepended. This replaces the fragile
// first-char heuristic (`url[0] != 'h'`) that decided whether a scheme
// was already present by looking at the first byte: a bare hostname
// starting with 'h' (host.example.com, h2.lan) was wrongly assumed to
// be already-schemed, so no prefix was added and the schemeless URL was
// rejected by http.NewRequestWithContext before any packet was sent —
// a healthy h-host probe never ran (#2495). The "://" containment test
// is the correct scheme detector: a bare "host:port" has no "://", so
// it is treated as schemeless (url.Parse would otherwise mistake "host"
// for a scheme).
//
// A target that already carries a scheme must be http or https; any
// other scheme (ftp://, gopher://, …) is rejected, since only http and
// https make sense for an http-get probe.
func canonicalizeHTTPTarget(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("no target specified")
	}
	if !strings.Contains(target, "://") {
		// Schemeless: prepend the default scheme. C179-042: reject a
		// canonicalized target with no host (a schemeless ":8080") here so a
		// dead probe surfaces as a setup failure that HOLDS the test state,
		// rather than http.NewRequestWithContext failing per attempt and the
		// permanent no-run being counted as path loss. Stay lenient on a
		// url.Parse failure (unchanged behavior) — that path is handled
		// downstream exactly as before.
		canon := "http://" + target
		if u, err := url.Parse(canon); err == nil && u.Hostname() == "" {
			return "", fmt.Errorf("http-get target %q has no host", target)
		}
		return canon, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid http-get target URL %q: %w", target, err)
	}
	switch u.Scheme {
	case "http", "https":
		// supported
	default:
		return "", fmt.Errorf("unsupported http-get target scheme %q (want http or https): %q", u.Scheme, target)
	}
	// C179-042: reject a scheme'd target with no host ("http://").
	if u.Hostname() == "" {
		return "", fmt.Errorf("http-get target %q has no host", target)
	}
	return target, nil
}

func (m *Manager) probeHTTP(ctx context.Context, test *config.RPMTest, opts probeSockOpts) (time.Duration, error) {
	url, err := canonicalizeHTTPTarget(test.Target)
	if err != nil {
		return 0, err
	}

	dialer, sink, err := probeDialer(10*time.Second, test.SourceAddress, opts)
	if err != nil {
		return 0, err
	}
	// This transport is created per-probe and dropped when probeHTTP returns.
	// DisableKeepAlives means the underlying TCP connection is closed after the
	// single request instead of being parked in the transport's idle pool. A
	// pooled connection would leak here (#4912): a bodyless response (HTTP 204
	// or Content-Length: 0) is fully consumed by resp.Body.Close(), so the
	// keep-alive path returns the socket to the pool — but the transport has no
	// owner and IdleConnTimeout == 0 (no limit), so the socket and its
	// persistent-connection read-loop goroutine retain each other forever.
	// Frequent probes to an empty health endpoint would then leak one fd +
	// goroutine per attempt. CloseIdleConnections() on return is a belt-and-
	// suspenders drop of anything that did get pooled.
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			// A network-reachable health endpoint can return attacker-controlled
			// Location headers. Keep one probe from fanning out into an unbounded
			// chain of additional requests.
			if len(via) > maxProbeRedirectHops {
				return fmt.Errorf("RPM HTTP probe redirect limit (%d hops) exceeded", maxProbeRedirectHops)
			}
			return nil
		},
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("HTTP request error: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Re-tag a VRF-bound resolver socket-setup failure as ErrProbeSetup
		// from the out-of-band sink (the sentinel is lost through the
		// *net.DNSError / *url.Error wrapping on this path) so the probe
		// holds state instead of counting loss (#5061).
		if se := sink.load(); se != nil {
			return 0, se
		}
		return 0, fmt.Errorf("HTTP GET failed: %w", err)
	}
	// #9049: RTT is TIME TO RESPONSE, not time to drain.
	//
	// It used to be measured after the body drain, so a fast server with a slow
	// or stalled body reported its transfer time as its round-trip time. In one
	// measured case 704 us of true responsiveness was reported as 2.0 s -- a
	// ~2800x distortion folded straight into MinRTT / MaxRTT / AvgRTT and the
	// jitter figure an operator reads to judge a path.
	//
	// client.Do has returned, which means the status line and headers are in
	// hand; that is what "round trip" means to the operator reading this
	// number, and it matches what every other probe in this file measures.
	rtt := time.Since(start)

	// Drain then close the body on every path -- including a bodyless 204 -- so
	// the connection is fully consumed before close and never lingers half-read
	// (#4912).
	//
	// #9049: THE DRAIN ERROR IS NO LONGER DISCARDED. It was `_, _ =`, so a body
	// read that hit http.Client.Timeout returned `rtt ~= 10s, err = nil` and the
	// caller scored the probe a SUCCESS. A timed-out response was
	// indistinguishable, in the probe's own verdict, from a fast complete one --
	// the probe reported the path healthy precisely when it was not, which is
	// the direction that matters.
	//
	// The drain is bounded twice over: http.Client{Timeout: 10s} covers body
	// reads, and the LimitReader below stops a large but healthy body from
	// dominating the probe window inside that ceiling. Hitting the limit is NOT
	// an error -- the response arrived and was readable, which is what the probe
	// asked; only a read FAILURE is.
	drainErr := drainProbeBody(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		return rtt, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if drainErr != nil {
		// Reported with the header RTT, not a zero: the round trip really did
		// take that long and the caller's loss accounting is separate from its
		// timing accounting.
		return rtt, fmt.Errorf("HTTP response body read failed: %w", drainErr)
	}
	return rtt, nil
}

// maxProbeBodyBytes9049 bounds how much of a probe response body is drained.
//
// A health endpoint's body is a few bytes; anything large is not what the probe
// is measuring, and reading it bills transfer time to a window meant for
// reachability. 1 MiB is far above any plausible health response and far below
// anything that would keep a 10-second probe busy on a working link.
//
// Reaching the limit is deliberately NOT a failure. io.LimitReader returns EOF
// at the boundary, so a body larger than this drains to the limit and the probe
// succeeds -- the server answered. Treating a big body as a failed probe would
// score a healthy path down for a property the probe does not measure.
const maxProbeBodyBytes9049 = 1 << 20

// maxProbeRedirectHops bounds the number of additional requests one probe can
// make after the configured target redirects.
const maxProbeRedirectHops = 3

func drainProbeBody(body io.Reader) error {
	_, err := io.Copy(io.Discard, io.LimitReader(body, maxProbeBodyBytes9049))
	return err
}

// probeMeasurementIdentity renders the RESOLVED measurement a verdict is about
// (#6561): everything that determines WHAT is being probed and BY WHICH PATH.
//
// The destination interface is resolved through routing.ResolveProbeInterface
// with the live RETH map — the same call BuildProbePins makes — so a RETH remap
// that moves THIS test's egress member changes the identity, while a remap
// elsewhere in the config leaves it alone. That is the whole point: the commit
// that re-opens reconcileRPM's hash gate is usually a RETH edit, and the
// question is whether it moved this probe.
//
// NOT the fwmark. An earlier revision of this fix compared marks, which looked
// like a path identity and is not one: BuildProbePins assigns
// `ProbeFwmarkBase + idx` over sorted probe/test names, so the mark is a
// POSITION in the pin band. It does not move when a RETH remap changes the
// resolved interface, and it DOES move when an unrelated test is added earlier
// in sort order. Both directions are wrong.
func probeMeasurementIdentity(test *config.RPMTest, rethMap map[string]string) string {
	if test == nil {
		return ""
	}
	return strings.Join([]string{
		test.EffectiveProbeType(),
		test.Target,
		test.SourceAddress,
		test.RoutingInstance,
		test.NextHop,
		routing.ResolveProbeInterface(test.DestinationInterface, rethMap),
	}, "\x00")
}

// carryProbeVerdict copies a surviving test's RUNTIME state onto its freshly
// seeded result (#6561), and is a no-op unless the test came through the commit
// as the SAME measurement over the SAME path — see probeMeasurementIdentity.
//
// A key that is new, or whose measurement identity changed, correctly keeps the
// seeded "unknown": there is no prior verdict that means anything, and inventing
// one would be worse than the wipe.
//
// ABSENT stays distinct from UNKNOWN. ip-monitoring treats an absent key as
// "clear any stale FAIL" (#4423 M8), which is correct — no probe, no protection.
// This only ever fills in a key present in BOTH tables, so that path is
// untouched and a dropped probe is never resurrected.
func carryProbeVerdict(res, prev *ProbeResult) {
	if res == nil || prev == nil {
		return
	}
	if prev.identity != res.identity {
		return
	}
	res.LastRTT = prev.LastRTT
	res.MinRTT = prev.MinRTT
	res.MaxRTT = prev.MaxRTT
	res.AvgRTT = prev.AvgRTT
	res.Jitter = prev.Jitter
	res.LastStatus = prev.LastStatus
	res.SuccFail = prev.SuccFail
	res.TotalSent = prev.TotalSent
	res.TotalRecv = prev.TotalRecv
	res.LastProbeAt = prev.LastProbeAt
}

// splitTargetZone9026 parses a probe target literal into its IP and %zone.
// Returns a nil IP when the target is a hostname rather than a literal — a
// hostname cannot be a link-local scope question, and resolving it here would
// duplicate the resolver the ICMP path uses.
func splitTargetZone9026(target string) (net.IP, string) {
	host, zone := target, ""
	if i := strings.IndexByte(target, '%'); i >= 0 {
		host, zone = target[:i], target[i+1:]
	}
	return net.ParseIP(host), zone
}
