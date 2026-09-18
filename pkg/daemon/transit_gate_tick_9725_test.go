package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

type gateRuntime9725 struct {
	dataplane.RuntimeDataPlane
	count    atomic.Int64
	observer func()
}

func (g *gateRuntime9725) AttachedXDPLinkCount() int {
	return int(g.count.Load())
}

func (g *gateRuntime9725) SetAttachedLinksObserver(fn func()) {
	g.observer = fn
}

func (g *gateRuntime9725) setCount(n int, wake bool) {
	g.count.Store(int64(n))
	if wake && g.observer != nil {
		g.observer()
	}
}

func waitTransitKnobs9725(t *testing.T, v4, v6, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b4, e4 := os.ReadFile(v4)
		b6, e6 := os.ReadFile(v6)
		if e4 == nil && e6 == nil && strings.TrimSpace(string(b4)) == want && strings.TrimSpace(string(b6)) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	b4, _ := os.ReadFile(v4)
	b6, _ := os.ReadFile(v6)
	t.Fatalf("transit knobs = %q/%q, want %q/%q", strings.TrimSpace(string(b4)), strings.TrimSpace(string(b6)), want, want)
}

func TestTransitGateStaysClosedUntilXDPAttach9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)
	rt := &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}
	d := &Daemon{}
	d.setDataplane(rt)
	d.armBootDataplane(d.dataplane())

	waitTransitKnobs9725(t, v4, v6, "0")
	if got := lastBarrierCall(f); got != "install" {
		t.Fatalf("after Start before attach unconditional barrier = %q, want install", got)
	}

	rt.setCount(1, false)
	d.reassertTransitGate("test-attach")
	waitTransitKnobs9725(t, v4, v6, "1")
	if got := lastFenceCall10302(f); got != "install" {
		t.Fatalf("after kernel-proven attach armed transit fence = %q, want install", got)
	}

	rt.setCount(0, false)
	d.reassertTransitGate("test-detach")
	waitTransitKnobs9725(t, v4, v6, "0")
	if got := lastBarrierCall(f); got != "install" {
		t.Fatalf("after kernel-proven detach barrier = %q, want install", got)
	}
}

func TestTransitGateTickClosesOnUnobservedKernelChange9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withBarrierRecorder(t)
	oldInterval := transitGateTickInterval
	transitGateTickInterval = 5 * time.Millisecond
	t.Cleanup(func() { transitGateTickInterval = oldInterval })

	rt := &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}
	d := &Daemon{}
	d.setDataplane(rt)
	d.armBootDataplane(d.dataplane())
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLoop(ctx, &wg)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	rt.setCount(1, false)
	waitTransitKnobs9725(t, v4, v6, "1")
	// No observer wake: this transition is visible only to the periodic census.
	rt.setCount(0, false)
	waitTransitKnobs9725(t, v4, v6, "0")
}

func TestTransitGateEventWakeRecountsKernelTruth9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withBarrierRecorder(t)
	oldInterval := transitGateTickInterval
	transitGateTickInterval = time.Hour
	t.Cleanup(func() { transitGateTickInterval = oldInterval })

	rt := &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}
	d := &Daemon{}
	d.setDataplane(rt)
	d.armBootDataplane(d.dataplane())
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLoop(ctx, &wg)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	// The wake callback carries no count; the loop must call the source again.
	rt.setCount(1, true)
	waitTransitKnobs9725(t, v4, v6, "1")
}

func TestTransitGateUncertainCountFailsClosed9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withBarrierRecorder(t)
	rt := &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}
	d := &Daemon{}
	d.setDataplane(rt)
	d.armBootDataplane(d.dataplane())
	rt.setCount(-1, false)
	d.reassertTransitGate("uncertain")
	waitTransitKnobs9725(t, v4, v6, "0")
}

// armedRecorderDP models the successful attach path in older gate tests. Its
// fixed count keeps those assertions focused on the behaviour under test while
// the gate-specific cells above exercise count transitions explicitly.
func (f *armedRecorderDP) AttachedXDPLinkCount() int { return 1 }

func (f *armedRecorderDP) SetAttachedLinksObserver(func()) {}
