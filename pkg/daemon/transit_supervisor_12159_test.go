package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type supervisorRuntime12159 struct {
	*gateRuntime9725
	running    atomic.Bool
	crashLoop  atomic.Bool
	observerMu sync.Mutex
	observer   func()
}

func (r *supervisorRuntime12159) HelperSupervisorState() (bool, bool) {
	return r.running.Load(), r.crashLoop.Load()
}

func (r *supervisorRuntime12159) SetHelperSupervisorObserver(fn func()) {
	r.observerMu.Lock()
	r.observer = fn
	r.observerMu.Unlock()
}

func (r *supervisorRuntime12159) setSupervisorState(running, crashLoop bool) {
	r.running.Store(running)
	r.crashLoop.Store(crashLoop)
	r.observerMu.Lock()
	observer := r.observer
	r.observerMu.Unlock()
	if observer != nil {
		observer()
	}
}

func (r *supervisorRuntime12159) TakeoverReady() (bool, []string) {
	if r.running.Load() {
		return true, nil
	}
	return false, []string{"userspace helper not running"}
}

func newStuckPrimary12159(preempt bool) *cluster.Manager {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "hb0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID:             1,
			NodePriorities: map[int]int{0: 200},
			Preempt:        preempt,
		}},
	})
	// The dataplane was ready before the helper failure, so its existing arm
	// debt is clear and the incumbent starts at full weight.
	m.SetMonitorWeight(1, cluster.DataplaneArmMonitorIface, false, cluster.DataplaneArmMonitorCost)
	m.SetRGReady(1, true, nil)
	m.SetRGReady(1, false, []string{"userspace helper not running"})
	m.SetGroupStateForTesting(1, cluster.StatePrimary)
	return m
}

func rgWeight12159(m *cluster.Manager, rgID int) int {
	for _, rg := range m.GroupStates() {
		if rg.GroupID == rgID {
			return rg.Weight
		}
	}
	return -1
}

// TestHelperCrashGateAndElectionDebt12159 is the bounded regression matrix
// for the supervisor-death path. It exercises the daemon's wake observer,
// reassertTransitGate, election debt, and actual cluster weight transition
// with preempt enabled and disabled. The fast-restart interval closes transit
// without flapping the incumbent; only a persistent crash loop resigns the RG.
func TestHelperCrashGateAndElectionDebt12159(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		name := "nonpreempt"
		if preempt {
			name = "preempt"
		}
		t.Run(name, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, "1")
			withBarrierRecorder(t)
			oldInterval := transitGateTickInterval
			transitGateTickInterval = time.Hour
			t.Cleanup(func() { transitGateTickInterval = oldInterval })

			cm := newStuckPrimary12159(preempt)
			rt := &supervisorRuntime12159{
				gateRuntime9725: &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}},
			}
			rt.setCount(1, false)
			rt.running.Store(true)
			d := &Daemon{cluster: cm}
			d.setDataplane(dataplane.RuntimeDataPlane(rt))
			d.transitGateOwned.Store(true)
			d.dataplaneArmed.Store(true)

			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			d.startTransitGateLoop(ctx, &wg)
			t.Cleanup(func() {
				cancel()
				wg.Wait()
			})
			waitTransitKnobs9725(t, v4, v6, "1")
			if got := rgWeight12159(cm, 1); got != 255 {
				t.Fatalf("healthy incumbent weight = %d, want 255", got)
			}

			// One fast restart: supervisor death closes transit and blocks
			// new takeover readiness, but it does not flap RG ownership.
			cm.SetRGReady(1, false, []string{"userspace helper not running"})
			rt.setSupervisorState(false, false)
			waitTransitKnobs9725(t, v4, v6, "0")
			if ready, reasons := rt.TakeoverReady(); ready || len(reasons) == 0 {
				t.Fatalf("dead-helper TakeoverReady=(%v,%v), want false with reason", ready, reasons)
			}
			if got := rgWeight12159(cm, 1); got != 255 {
				t.Fatalf("single fast restart changed incumbent weight to %d, want 255", got)
			}
			if got := cm.GroupState(1).State; got != cluster.StatePrimary {
				t.Fatalf("single fast restart changed incumbent state to %v, want primary", got)
			}

			// A successful restart restores transit and readiness and leaves
			// the original weight untouched.
			cm.SetRGReady(1, true, nil)
			rt.setSupervisorState(true, false)
			waitTransitKnobs9725(t, v4, v6, "1")
			if got := rgWeight12159(cm, 1); got != 255 {
				t.Fatalf("recovered helper weight = %d, want 255", got)
			}

			// Persistent crash loop: the restart backoff reached its cap.
			// The full debt is necessary to demote a non-preempt incumbent.
			cm.SetRGReady(1, false, []string{"userspace helper crash loop"})
			rt.setSupervisorState(false, true)
			waitTransitKnobs9725(t, v4, v6, "0")
			if got := rgWeight12159(cm, 1); got != 0 {
				t.Fatalf("crash-loop RG weight = %d, want 0 to resign incumbent", got)
			}
			if got := cm.GroupState(1).State; got != cluster.StateSecondary {
				t.Fatalf("crash-loop incumbent state = %v, want secondary", got)
			}

			// Recovery clears the episode-scoped debt and reopens transit.
			cm.SetRGReady(1, true, nil)
			rt.setSupervisorState(true, false)
			waitTransitKnobs9725(t, v4, v6, "1")
			if got := rgWeight12159(cm, 1); got != 255 {
				t.Fatalf("post-loop recovered weight = %d, want 255", got)
			}
		})
	}
}
