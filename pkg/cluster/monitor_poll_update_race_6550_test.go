package cluster

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6550 — the Monitor's poll goroutine mutated ifaceState, ipState, ipDebts and
// ipThresholdState with NO mon.mu while UpdateGroups deletes from those same
// maps under it.
//
//	pollCycle:   groups := mon.groups (under mu) ... mu.Unlock()
//	             -> pollInterfaceMonitors      mon.ifaceState[key] = state   UNLOCKED
//	             -> updateIPTargetDampenedState mon.ipState[key]   = state   UNLOCKED
//	             -> reconcileRGIPDebts          mon.ipDebts[...]            UNLOCKED
//	                                            mon.ipThresholdState[...]   UNLOCKED
//	UpdateGroups: mon.mu.Lock(); delete(mon.ifaceState, ...) etc.
//
// A concurrent map read+write is a Go RUNTIME FATAL ("concurrent map read and
// map write"), not a recoverable race: the process dies. It is reachable from
// an ordinary commit — Manager.UpdateConfig calls Monitor.UpdateGroups on every
// cluster config apply — and HA config-sync pushes that same commit to BOTH
// nodes.
//
// CI had no path to it: make test-go's race gate (test-race-dp) ran -race over
// ./pkg/daemon and ./pkg/dataplane only. ./pkg/cluster was never raced by any
// make target. This change adds a pkg/cluster leg to test-race-dp selecting the
// probe below, so the guard is one a CI run can actually observe.

// raceNlHandle is a mutation-safe nlLinkGetter for the concurrency probes. The
// shared mockNlHandle in monitor_test.go carries a bare map that the probe's
// own flapping would race, which would report a race in the TEST rather than
// in the code under test.
type raceNlHandle struct {
	mu   sync.Mutex
	up   map[string]bool
	miss map[string]bool
}

func newRaceNlHandle() *raceNlHandle {
	return &raceNlHandle{up: make(map[string]bool), miss: make(map[string]bool)}
}

func (h *raceNlHandle) LinkByName(name string) (netlink.Link, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.miss[name] {
		return nil, net.UnknownNetworkError("not found: " + name)
	}
	var state netlink.LinkOperState = netlink.OperDown
	if h.up[name] {
		state = netlink.OperUp
	}
	return &mockLink{attrs: netlink.LinkAttrs{Name: name, OperState: state}}, nil
}

func (h *raceNlHandle) setUp(name string, up bool) {
	h.mu.Lock()
	h.up[name] = up
	h.mu.Unlock()
}

// race6550Groups builds the two monitored sets the probe alternates between.
// The second is a strict subset of the first, so every UpdateGroups call in the
// loop performs real deletes from ifaceState/ipState/ipDebts/ipThresholdState —
// a same-set update would take mon.mu, find nothing to drop and never touch the
// maps the poll goroutine is writing.
func race6550Groups() (full, reduced []*config.RedundancyGroup) {
	mk := func(id int) *config.RedundancyGroup {
		rg := makeRG(id, false, map[int]int{0: 200, 1: 100},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
			&config.InterfaceMonitor{Interface: "untrust0", Weight: 100},
		)
		rg.IPMonitoring = &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 50},
				{Address: "10.0.0.2", Weight: 50},
			},
		}
		return rg
	}
	return []*config.RedundancyGroup{mk(0), mk(1)}, []*config.RedundancyGroup{mk(0)}
}

// TestMonitorPollDoesNotRaceUpdateGroups6550 is the race probe.
//
// The BOUNDED side is the EXPENSIVE one. A poll cycle walks every RG's
// interface monitors through netlink, probes every IP target and reconciles the
// per-RG debt set against the manager (which takes m.mu); UpdateGroups is two
// short map walks. Bounding the cheap side instead would let it run to
// completion inside the expensive side's first pass and race the window
// approximately once. The achieved ratio is logged rather than assumed, so a
// future change that makes UpdateGroups expensive turns a degenerate probe into
// a visible one instead of a quiet pass.
//
// The assertion is the race detector, so this is only meaningful under -race.
// RED on revert: drop the mon.mu critical sections from pollInterfaceMonitors /
// updateIPTargetDampenedState / reconcileRGIPDebts and
//
//	go test -race -count=1 -run TestMonitorPollDoesNotRaceUpdateGroups6550 ./pkg/cluster/
//
// reports WARNING: DATA RACE on the monitor maps (and, without -race, can trip
// the runtime's "concurrent map read and map write" fatal outright).
func TestMonitorPollDoesNotRaceUpdateGroups6550(t *testing.T) {
	full, reduced := race6550Groups()

	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(full...))

	nlh := newRaceNlHandle()
	nlh.setUp("trust0", true)
	nlh.setUp("untrust0", true)

	mon := NewMonitor(m, full)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Flap both the link state and the IP reachability so every cycle actually
	// transitions dampened state and installs/clears debts, rather than
	// steady-stating into the no-op branch of reconcileRGIPDebts.
	var tick atomic.Int64
	mon.probeFn = func(_ context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		return tick.Load()%2 == 0, true
	}

	const pollCycles = 200
	var polls, updates atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// BOUNDED, expensive side: a fixed number of poll cycles.
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < pollCycles; i++ {
			tick.Add(1)
			nlh.setUp("trust0", i%3 != 0)
			mon.poll()
			polls.Add(1)
		}
	}()

	// LOOPED, cheap side: keep deleting out from under the poll goroutine until
	// the bounded side signals done.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			mon.UpdateGroups(reduced)
			mon.UpdateGroups(full)
			updates.Add(2)
		}
	}()

	wg.Wait()

	got, want := updates.Load(), polls.Load()
	t.Logf("#6550 race probe: %d poll cycles against %d UpdateGroups calls (%.1f updates/poll)",
		want, got, float64(got)/float64(want))
	if got < want {
		t.Errorf("degenerate probe: %d UpdateGroups calls against %d poll cycles — "+
			"the looped side must out-run the bounded one or the window is barely raced",
			got, want)
	}
}

// TestMonitorPollDoesNotHoldMuAcrossManagerCallback6550 binds the SHAPE of the
// fix, and it is the reason the fix is per-mutation critical sections rather
// than one lock around the whole apply phase.
//
// The lock order in this package is m.mu -> mon.mu: Manager.UpdateConfig holds
// m.mu for its whole body and calls Monitor.UpdateGroups, which takes mon.mu
// (documented at UpdateGroups — it deliberately does not call the locking
// SetMonitorWeight for exactly this reason). The poll path calls
// mgr.SetMonitorWeight, which takes m.mu. So holding mon.mu across that
// callback inverts the order and deadlocks a routine commit against a poll
// cycle — the naive "wrap phase 3 in mon.mu" repair for #6550 turns a
// probabilistic runtime fatal into a deterministic hang.
//
// The probe lands an UpdateGroups on a separate goroutine at the instant the
// poll cycle is about to call into the manager, and requires it to complete.
// RED on revert: hold mon.mu across mon.mgr.SetMonitorWeight in
// pollInterfaceMonitors or reconcileRGIPDebts and the UpdateGroups blocks
// forever, tripping the timeout below.
func TestMonitorPollDoesNotHoldMuAcrossManagerCallback6550(t *testing.T) {
	full, reduced := race6550Groups()

	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(full...))

	nlh := newRaceNlHandle()
	nlh.setUp("trust0", false) // down -> guarantees an interface-monitor debt apply
	nlh.setUp("untrust0", true)

	mon := NewMonitor(m, full)
	mon.nlHandle = nlh
	setNoDampening(mon)
	mon.probeFn = func(_ context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		return false, true // unreachable -> guarantees an ip-monitor debt apply
	}

	var fired atomic.Int64
	mon.beforeManagerApplyHook = func() {
		// Only the first crossing needs to be probed; the rest would just add
		// wall-clock. Every crossing is a place mon.mu must not be held.
		if fired.Add(1) != 1 {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			mon.UpdateGroups(reduced)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("UpdateGroups blocked for 5s while the poll cycle was applying a " +
				"monitor debt: mon.mu must not be held across the mgr.SetMonitorWeight / " +
				"RecordEvent callback — that inverts the m.mu -> mon.mu order " +
				"Manager.UpdateConfig relies on and deadlocks a commit against a poll (#6550)")
		}
	}

	mon.poll()

	if fired.Load() == 0 {
		t.Fatal("beforeManagerApplyHook never fired — the probe did not reach a " +
			"manager callback, so it proves nothing. Check the fixture still " +
			"produces an interface-monitor or ip-monitor debt transition.")
	}
}

// TestRaceGateCoversTheClusterProbes6550 binds the WIRING that makes the two
// probes above observable.
//
// The probes assert through the race detector, so they are inert without
// -race. Before #6550 no make target ran ./pkg/cluster under -race at all:
// test-race-dp covered ./pkg/daemon and ./pkg/dataplane only. That is why the
// Monitor's concurrent-map fatal and the #7257 heartbeat start/stop race are
// races CI had no PATH to, not races CI merely failed to catch. Adding the
// probes without adding the leg would have reproduced exactly that.
//
// So this reads the real Makefile and requires the pkg/cluster leg to exist AND
// its -run pattern to still select every probe named below. RED-on-revert:
// delete the `$(GO) test -race ./pkg/cluster/ ...` line from the test-race-dp
// recipe (or drop a name from its pattern) and this fails — which is the
// mutation that matters, because deleting the leg is silent otherwise.
//
// Stated residual, same shape as pkg/daemon's #6743 canary: the probe list
// below is hand-maintained. A new cluster race probe is outside the gate until
// it is added here. This binds "the gate has not fallen behind these probes",
// not "these are all the cluster race probes there are".
func TestRaceGateCoversTheClusterProbes6550(t *testing.T) {
	t.Parallel()

	wantProbes := []string{
		"TestMonitorPollDoesNotRaceUpdateGroups6550",
		"TestMonitorPollDoesNotHoldMuAcrossManagerCallback6550",
		"TestStartHeartbeatDoesNotRaceStopHeartbeat7257",
		"TestStartHeartbeatSupersededByStopDoesNotPublish7257",
	}

	src, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	var pattern string
	inRecipe := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "test-race-dp:") {
			inRecipe = true
			continue
		}
		if !inRecipe {
			continue
		}
		// The recipe ends at the first non-indented, non-blank line.
		if line != "" && !strings.HasPrefix(line, "\t") {
			break
		}
		if !strings.Contains(line, "./pkg/cluster/") {
			continue
		}
		// The A58-04 go test -list guard lines mention the package
		// but carry no race run; the race line is the one invoking
		// test -race (the guard lines only name test-race-dp in prose).
		if !strings.Contains(line, "test -race") {
			continue
		}
		m := regexp.MustCompile(`-run\s+'([^']*)'`).FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("the test-race-dp pkg/cluster leg has no single-quoted -run pattern: %q", line)
		}
		pattern = m[1]
		break
	}
	if pattern == "" {
		t.Fatal("test-race-dp has no `go test -race ./pkg/cluster/ -run '<pattern>'` leg. " +
			"The cluster race probes only assert under -race, so without this leg they " +
			"never run in CI and the #6550 / #7257 races become unobservable again. " +
			"If the leg was deliberately removed (the whole package now races), delete " +
			"this canary in the same change and say so.")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("test-race-dp pkg/cluster -run pattern %q does not compile: %v", pattern, err)
	}
	for _, name := range wantProbes {
		if !re.MatchString(name) {
			t.Errorf("race probe %s is NOT selected by the test-race-dp pkg/cluster pattern %q — "+
				"it will not run under -race in CI", name, pattern)
		}
	}
}
