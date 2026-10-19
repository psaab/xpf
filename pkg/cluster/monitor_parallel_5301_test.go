package cluster

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// injectFakeNl replaces the netlink handle factory so a test's interface-monitor
// pass (which the parallel IP-probe tests don't exercise) never touches real
// netlink. The RGs below carry no InterfaceMonitors, so LinkByName is never
// called; only the handle create/close path runs.
func injectFakeNl(mon *Monitor) {
	var closes int32
	mon.newNlHandle = func() (nlHandleCloser, error) {
		return &countingNlHandle{closes: &closes}, nil
	}
}

// ipMonitorRG builds an RG that IP-monitors the given target addresses.
func ipMonitorRG(id int, addrs ...string) *config.RedundancyGroup {
	targets := make([]*config.IPMonitorTarget, len(addrs))
	for i, a := range addrs {
		targets[i] = &config.IPMonitorTarget{Address: a, Weight: 10}
	}
	return &config.RedundancyGroup{
		ID:             id,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    100,
			GlobalThreshold: 200,
			Targets:         targets,
		},
	}
}

// TestMonitor_IPProbesRunConcurrently_5301 pins that a sweep of many blocking
// (unreachable) targets is probed CONCURRENTLY through the bounded worker pool,
// completing in roughly one probe deadline rather than N × the deadline.
//
// Fail-on-revert: revert probeIPTargets to a serial `for _, addr { probe }`
// loop and the sweep takes ~n×block (4.8s here) instead of ~block (300ms),
// blowing past the assertion.
func TestMonitor_IPProbesRunConcurrently_5301(t *testing.T) {
	const n = 16 // == ipProbeConcurrency: a single wave
	const block = 300 * time.Millisecond

	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{ipMonitorRG(0, addrs...)}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	// A generous cycle budget so the OVERALL deadline cannot mask a serial
	// sweep — the contrast under revert must be the concurrency, not the
	// deadline curtailing a slow serial loop.
	mon.IPMonitorCycleTimeout = 10 * time.Second
	// Each probe blocks ~block then reports unreachable, unless aborted.
	mon.probeFn = func(ctx context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		select {
		case <-time.After(block):
			return false, true
		case <-ctx.Done():
			return false, false
		}
	}

	start := time.Now()
	mon.poll()
	elapsed := time.Since(start)

	// Concurrent (one wave of 16) ≈ block; serial ≈ n×block. Assert well under
	// half the serial time so CI jitter cannot flip the verdict.
	if limit := block * time.Duration(n) / 2; elapsed >= limit {
		t.Fatalf("poll() took %v for %d blocking probes; expected ~one probe deadline (%v) via the "+
			"bounded worker pool, not serial ~%v (limit %v)", elapsed, n, block, block*time.Duration(n), limit)
	}
}

// TestMonitor_IPProbeStableApplyOrder_5301 pins that each target's result is
// applied to THAT target's state — the parallel probe phase followed by a
// serial, stable-order apply must not shuffle results across targets/RGs. A
// misindexed apply would give a target its neighbor's reachability.
func TestMonitor_IPProbeStableApplyOrder_5301(t *testing.T) {
	rg0 := ipMonitorRG(0, "10.1.0.1", "10.1.0.2")
	rg1 := ipMonitorRG(1, "10.2.0.1", "10.2.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg0, rg1}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Distinct per-address reachability so a shuffle is detectable.
	reach := map[string]bool{
		"10.1.0.1": true,  // rg0 target 0 up
		"10.1.0.2": false, // rg0 target 1 down
		"10.2.0.1": false, // rg1 target 0 down
		"10.2.0.2": true,  // rg1 target 1 up
	}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = func(_ context.Context, target *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		return reach[target.Address], true
	}

	mon.poll()

	for addr, up := range reach {
		var rgID int
		if addr[:6] == "10.2.0" {
			rgID = 1
		}
		state := mon.ipState[ipMonitorKey{rgID: rgID, address: addr}]
		if state == nil {
			t.Fatalf("no ipState for %s (rg %d) — result not applied", addr, rgID)
		}
		if wantDown := !up; state.down != wantDown {
			t.Errorf("target %s (rg %d): state.down = %v, want %v — result applied to the wrong target",
				addr, rgID, state.down, wantDown)
		}
	}
}

// TestMonitor_IPProbeCycleOverrun_5301 pins that when a sweep exceeds its
// overall cycle deadline, the overrun is recorded and the unfinished probes are
// SKIPPED (no dampening advance) rather than being counted as failures — the
// sweep stays failover-neutral under a degraded probe path.
func TestMonitor_IPProbeCycleOverrun_5301(t *testing.T) {
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		ipMonitorRG(0, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"),
	}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.IPMonitorCycleTimeout = 50 * time.Millisecond
	// Every probe blocks far longer than the cycle budget; the cycle deadline
	// aborts them (completed=false).
	mon.probeFn = func(ctx context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		select {
		case <-time.After(2 * time.Second):
			return false, true
		case <-ctx.Done():
			return false, false
		}
	}

	start := time.Now()
	mon.poll()
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("poll() took %v; the cycle deadline (50ms) should have curtailed the sweep", elapsed)
	}
	// No probe completed, so no dampening state was created / advanced and the
	// RG weight is untouched (full health).
	if len(mon.ipState) != 0 {
		t.Errorf("ipState has %d entries; an aborted probe must not advance dampening state", len(mon.ipState))
	}
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Errorf("RG weight = %d, want 255 (no unmeasured target counted as a failure)", w)
	}
}

// TestMonitor_StopCancelsInflightProbe_5301 pins that Stop() cancels an
// in-flight probe promptly instead of waiting out the sweep — the other half of
// #5301 (a Stop during an outage used to block for the whole serial sweep).
func TestMonitor_StopCancelsInflightProbe_5301(t *testing.T) {
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		ipMonitorRG(0, "10.0.0.1"),
	}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	// A very long cycle budget so the ONLY thing that can unblock the probe is
	// Stop's context cancellation, not the cycle deadline.
	mon.IPMonitorCycleTimeout = 30 * time.Second
	probeStarted := make(chan struct{}, 8)
	mon.probeFn = func(ctx context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		select {
		case probeStarted <- struct{}{}:
		default:
		}
		<-ctx.Done() // hang until cancelled
		return false, false
	}

	mon.Start(context.Background())

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		mon.Stop()
		t.Fatal("probe never started")
	}

	start := time.Now()
	mon.Stop()
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("Stop() took %v with an in-flight probe; expected prompt cancellation, not a wait-out", el)
	}
}
