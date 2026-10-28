package cluster

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17132 fold (Rev18171Opus F1): the commit-time PollNow that
// UpdateConfig defers must be INTERFACE-ONLY and LIFECYCLE-BOUND.
//
// Pre-fold, PollNow was `pollCycle(context.Background())`: a
// synchronous FULL cycle — including the ICMP IP-probe sweep, bounded
// only by waves*800ms+500ms — on every commit / boot-load / peer-sync
// apply, and on a context Monitor.Stop could neither cancel nor join,
// so a commit poll racing Manager.Stop could SetMonitorWeight on a
// stopping manager.
//
// These cells pin both halves. Fail-on-revert:
//   - restore PollNow to the full Background pollCycle and
//     TestPollNow_CommitPathSkipsIPProbeSweep17132 sees probe calls on
//     the commit path (and, for the Stop cell, the weight write lands);
//   - keep the full cycle but merely thread a context and the sweep
//     assertion still fails — the sweep must not run at all;
//   - drop the explicit mon.stopped latch (Rev18171bOpus F1 on
//     931d3b1f4f: Stop cleared lifecycle/cancel, so a stopped monitor
//     looked never-started and lifecycleContext lazily resurrected
//     it) and the Stop cell's post-Stop fresh-transition leg reds:
//     the resurrected poll installs the fresh down debt (weight 155).

// TestPollNow_CommitPathSkipsIPProbeSweep17132 drives the real commit
// path (Manager.UpdateConfig -> deferred PollNow) against an RG that
// carries BOTH an interface monitor and IP targets. The interface
// leg must advance dampening and install its debt through the commit
// poll; the IP leg must not be probed at all, must not advance IP
// dampening, and must not install IP debt — that work belongs to the
// 1s loop's full cycle, which this cell then runs to show the IP debt
// still arrives through the normal cadence.
func TestPollNow_CommitPathSkipsIPProbeSweep17132(t *testing.T) {
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		InterfaceMonitors: []*config.InterfaceMonitor{
			{Interface: "trust0", Weight: 100},
		},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 50},
				{Address: "10.0.0.2", Weight: 50},
			},
		},
	}
	cfg := makeConfig(rg)

	m := NewManager(0, 1)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	nlh := newMockNlHandle()
	nlh.setLink("trust0", false) // interface down: commit poll must demote
	mon.nlHandle = nlh
	setNoDampening(mon)
	var probes atomic.Int32
	mon.probeFn = func(_ context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		probes.Add(1)
		return false, true // unreachable: a full cycle would install IP debt
	}
	m.mu.Lock()
	m.monitor = mon
	m.mu.Unlock()

	// The commit itself. UpdateConfig's deferred PollNow runs before
	// this returns (synchronous), so every assertion below observes
	// the completed commit poll.
	m.UpdateConfig(cfg)
	drainEvents(m, 8)

	if got := probes.Load(); got != 0 {
		t.Fatalf("commit-path PollNow probed %d IP targets, want 0: the ICMP "+
			"sweep must not run synchronously on a commit (#17132 fold)", got)
	}
	if len(mon.ipState) != 0 {
		t.Fatalf("commit poll advanced IP dampening state (%d entries), want 0", len(mon.ipState))
	}
	// Interface leg DID run through the commit poll: trust0 down with
	// threshold 1 installs the 100 debt (255-100=155). The IP targets
	// owe nothing yet, so the weight is exactly the interface debt.
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("weight after commit = %d, want 155 (interface debt only); "+
			"the commit poll must poll interfaces but not IP targets", w)
	}

	// The normal full cycle (the 1s loop's shape) still owns IP debt:
	// both targets unreachable install their per-target debts.
	mon.poll()
	drainEvents(m, 8)
	if got := probes.Load(); got == 0 {
		t.Fatal("full poll() never probed: the IP sweep must still run on the loop path")
	}
	if w := m.GroupStates()[0].Weight; w != 55 {
		t.Fatalf("weight after full poll = %d, want 55 (255-100 iface -50 -50 ip)", w)
	}
}

// TestPollNow_StopDuringCommitPollLeavesNoWeightWrite17132 pins the
// lifecycle half: a commit poll that is in flight when the monitor
// stops must be cancelled/joined by Stop, and a commit poll attempted
// after Stop must be a no-op — neither may SetMonitorWeight on the
// stopping manager.
//
// The transition callback is parked via beforeManagerApplyHook (the
// #6550 seam, fired with no Monitor lock held immediately before
// SetMonitorWeight). Stop is invoked from a separate goroutine while
// the hook is parked, mirroring Manager.Stop -> Monitor.Stop racing
// an UpdateConfig commit poll. Releasing the hook only after Stop has
// returned models the callback resuming on a fully stopped manager:
// the blocked weight write must never land.
func TestPollNow_StopDuringCommitPollLeavesNoWeightWrite17132(t *testing.T) {
	rg := makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: "trust0", Weight: 100})
	cfg := makeConfig(rg)

	m := NewManager(0, 1)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	mon.nlHandle = nlh
	setNoDampening(mon)
	m.mu.Lock()
	m.monitor = mon
	m.mu.Unlock()

	// Healthy commit: interface up, no debt, weight 255.
	m.UpdateConfig(cfg)
	drainEvents(m, 8)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("healthy weight = %d, want 255", w)
	}

	// Link drops. The next commit's PollNow will transition and call
	// SetMonitorWeight(down,100) — park it inside the hook.
	nlh.setLink("trust0", false)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	mon.beforeManagerApplyHook = func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}

	committed := make(chan struct{})
	go func() {
		m.UpdateConfig(cfg)
		close(committed)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("commit poll never reached the manager callback")
	}

	// Racing Manager.Stop's monitor leg (Manager.Stop calls
	// mon.Stop under no manager lock — see manager.go Stop).
	stopped := make(chan struct{})
	go func() {
		mon.Stop()
		close(stopped)
	}()

	// Stop must cancel/join the lifecycle. It cannot return while the
	// commit poll is still parked in wg, so give it a brief window to
	// (correctly) block, then release the callback: the post-Stop
	// weight write must be suppressed.
	select {
	case <-stopped:
		t.Fatal("Stop returned while a commit poll was still in flight; " +
			"the poll is not joined in wg (#17132 fold)")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned after the commit poll was released")
	}
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateConfig never returned")
	}
	drainEvents(m, 8)

	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight after Stop-raced commit = %d, want 255: a commit poll "+
			"cancelled by Stop must leave no weight write on the manager", w)
	}

	// A commit attempted entirely after Stop is likewise a no-op — and
	// it must CREATE A FRESH TRANSITION after Stop to prove it. The
	// parked poll above already advanced dampening to down before its
	// write was suppressed, so re-committing with the link still down
	// would see no new transition and write nothing even if PollNow
	// wrongly resurrected and polled (Rev18171bOpus F1: the shipped
	// post-Stop leg was test-only-green for exactly that reason).
	// Flip the link back UP after Stop: a resurrected poll would
	// transition down->up, and then flipping it DOWN again gives the
	// resurrecting poll a fresh down transition that installs the 100
	// debt (weight 155). A true no-op leaves weight 255 throughout.
	mon.beforeManagerApplyHook = nil
	nlh.setLink("trust0", true)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight after post-Stop up-flip commit = %d, want 255: PollNow after "+
			"Stop must not poll (a resurrected poll clears/sets weight on a stopped monitor)", w)
	}
	nlh.setLink("trust0", false)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight after post-Stop down-flip commit = %d, want 255: PollNow after "+
			"Stop must not write weight (a resurrected poll would install the fresh "+
			"down-transition debt, weight 155)", w)
	}

	// Start clears the stopped latch: the restarted monitor polls
	// again. Drive it synchronously through PollNow (the loop's own
	// immediate cycle sees the already-down dampening state and cannot
	// transition, so PollNow is what proves the latch cleared): flip
	// up — PollNow consumes the down->up transition (no debt was ever
	// installed, so weight stays 255) — then flip down and PollNow
	// installs the fresh down debt. With the latch stuck, both PollNow
	// calls are no-ops, no transition ever fires, and weight stays 255.
	mon.Start(context.Background())
	nlh.setLink("trust0", true)
	mon.PollNow()
	nlh.setLink("trust0", false)
	mon.PollNow()
	drainEvents(m, 8)
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("weight after Start following Stop = %d, want 155: Start must clear "+
			"the stopped latch so the restarted monitor polls again", w)
	}
	mon.Stop()
}
