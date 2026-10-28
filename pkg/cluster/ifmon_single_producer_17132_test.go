package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17132: pkg/cluster.Monitor is the ONLY producer of interface-monitor
// debt. The pre-fix daemon apply tail fed one raw routing sample per
// apply into SetMonitorWeight. Either direction of disagreement with the
// dampened Monitor was then stranded until the next apply, because the
// Monitor re-fires only on a dampened TRANSITION:
//
//   - stranded debt: a down sample at apply + an up dampened monitor
//     leaves weight 155 with the link up (never primary);
//   - fail-open: an up sample at a flap instant clears held debt, the
//     link stays down, and no transition re-installs it (weight 255 on
//     a dead uplink).
//
// These cells drive exactly that sequence at component level: install /
// hold dampened debt, inject the apply-tail raw call the daemon used to
// make, then poll. The raw call is the defect mechanism — with the feed
// deleted from pkg/daemon it no longer occurs, so the post-fix behavior
// asserted here is that the dampened Monitor ALONE (with no raw call)
// keeps the correct weight, and that a commit (UpdateConfig -> PollNow)
// reflects a weight change / recovery promptly through dampening.
// The daemon-side absence of the feed is pinned by the acceptance grep
// (no SetMonitorWeight in pkg/daemon except the transit-gate reserved
// markers) and by runDaemonApplyTail in
// ifmon_weight_daemon_apply_6549_test.go, which no longer feeds weight.

// clock17132 wraps a Monitor with a controllable now.
type clock17132 struct{ t time.Time }

func (c *clock17132) now() time.Time          { return c.t }
func (c *clock17132) advance(d time.Duration) { c.t = c.t.Add(d) }

func ifmon17132(t *testing.T, up bool) (*Manager, *Monitor, *mockNlHandle, *clock17132) {
	t.Helper()
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 100},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100}))
	m := NewManager(0, 1)
	// Install the monitor BEFORE UpdateConfig so UpdateConfig's PollNow
	// has a monitor to drive (mirrors daemon: Start creates it, then applies).
	mon := NewMonitor(m, cfg.RedundancyGroups)
	nlh := newMockNlHandle()
	nlh.setLink("trust0", up)
	mon.nlHandle = nlh
	clk := &clock17132{t: time.Now()}
	mon.nowFunc = clk.now
	m.mu.Lock()
	m.monitor = mon
	m.mu.Unlock()
	return m, mon, nlh, clk
}

func pollN(mon *Monitor, clk *clock17132, n int) {
	for range n {
		clk.advance(6 * time.Second) // elapse hold-down between transitions
		mon.poll()
	}
}

// TestIfmonSingleProducer_HeldDebtSurvivesCommit17132 is the fail-open
// direction, post-fix shape: dampened debt installed, then a commit
// (UpdateConfig, which now PollNow's) while the link is still down must
// NOT clear it. Pre-fix the daemon's raw up-sample did exactly that.
func TestIfmonSingleProducer_HeldDebtSurvivesCommit17132(t *testing.T) {
	m, mon, _, clk := ifmon17132(t, false)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 100},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100})))
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("precondition: dampened down weight = %d, want 155", w)
	}
	// Commit again with the link still down. No raw feed exists; the
	// immediate PollNow sees the same down link and no transition fires.
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 100},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100})))
	drainEvents(m, 4)
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("fail-open: weight after commit + down polls = %d, want 155 "+
			"(held dampened debt must survive a commit; #17132)", w)
	}
}

// TestIfmonSingleProducer_RecoveryViaCommitPoll17132 is the stranded-debt
// direction, post-fix shape: debt held, link recovers, and a commit's
// immediate dampened poll (plus the normal poll cadence) clears it —
// nothing strands it, because no raw down-sample can re-install it.
func TestIfmonSingleProducer_RecoveryViaCommitPoll17132(t *testing.T) {
	m, mon, nlh, clk := ifmon17132(t, false)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 100},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100}))
	m.UpdateConfig(cfg)
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("precondition: dampened down weight = %d, want 155", w)
	}
	nlh.setLink("trust0", true)
	// The commit triggers PollNow; further polls complete the pass count.
	m.UpdateConfig(cfg)
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("stranded debt: weight after recovery + commit = %d, want 255 (#17132)", w)
	}
}

// TestIfmonSingleProducer_RawSampleWouldStrand17132 documents the defect
// mechanism directly: IF a raw apply-tail call is made (the deleted
// daemon feed), it strands debt in both directions. This cell exists so
// the mechanism stays visible; it asserts the Monitor alone does not
// repair a foreign raw write — which is precisely why the feed had to
// be deleted rather than damped. It is NOT a post-fix behavior claim
// about production (no production caller makes this call for interface
// monitors anymore).
func TestIfmonSingleProducer_RawSampleWouldStrand17132(t *testing.T) {
	// Fail-open direction.
	m, mon, _, clk := ifmon17132(t, false)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100, 1: 100},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100}))
	m.UpdateConfig(cfg)
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("precondition: weight = %d, want 155", w)
	}
	m.SetMonitorWeight(0, "trust0", false, 100) // the deleted raw feed, up sample
	drainEvents(m, 4)
	pollN(mon, clk, 5)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("mechanism check: raw up-sample should strand weight at 255, got %d", w)
	}

	// Stranded-debt direction.
	m2, mon2, _, clk2 := ifmon17132(t, true)
	m2.UpdateConfig(cfg)
	pollN(mon2, clk2, 5)
	if w := m2.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("precondition: weight = %d, want 255", w)
	}
	m2.SetMonitorWeight(0, "trust0", true, 100) // the deleted raw feed, down sample
	drainEvents(m2, 4)
	pollN(mon2, clk2, 5)
	if w := m2.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("mechanism check: raw down-sample should strand weight at 155, got %d", w)
	}
}
