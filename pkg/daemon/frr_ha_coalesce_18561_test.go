package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

// #18561: a burst of RG ownership edges runs ONE FRR reconcile, after the
// burst, and an edge that lands once the timer has fired still gets its own.
// The timer is injected, so nothing here depends on scheduling.

type manualTimers18561 struct{ fire []func() }

func (m *manualTimers18561) after(_ time.Duration, f func()) { m.fire = append(m.fire, f) }

func TestFRRHAReconcileBurstRunsOnce18561(t *testing.T) {
	timers := &manualTimers18561{}
	c := frrHACoalescer{afterFunc: timers.after}
	runs := 0
	for range 3 { // RG0, RG1, RG2 promoted by one election
		c.schedule(frrHAReconcileDebounce, func() { runs++ })
	}
	if len(timers.fire) != 1 {
		t.Fatalf("armed %d timers for one burst, want 1: each edge would queue its own frr-reload on applySem", len(timers.fire))
	}
	if runs != 0 {
		t.Fatal("the reconcile ran inside the burst; it must wait for the debounce")
	}
	timers.fire[0]()
	if runs != 1 {
		t.Fatalf("runs = %d after the timer, want 1", runs)
	}
}

func TestFRRHAReconcileEdgeAfterFireIsNotLost18561(t *testing.T) {
	timers := &manualTimers18561{}
	c := frrHACoalescer{afterFunc: timers.after}
	runs := 0
	var during func()
	c.schedule(frrHAReconcileDebounce, func() {
		runs++
		if during != nil {
			during() // an edge landing while the reconcile runs
		}
	})
	during = func() { c.schedule(frrHAReconcileDebounce, func() { runs++ }) }
	timers.fire[0]()
	if len(timers.fire) != 2 {
		t.Fatalf("an edge during the running reconcile armed %d timers in total, want 2: it would be lost, since the run may already have read the config", len(timers.fire))
	}
	timers.fire[1]()
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
}

// The production entry point must go through the coalescer: three edges from
// one election arm one timer, not three applySem-holding reloads.
func TestScheduleFRRHAReconcileUsesCoalescer18561(t *testing.T) {
	timers := &manualTimers18561{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    fenceTestStore(t, fenceStartupClusterSet),
		cluster:  cluster.NewManager(0, 1),
		frr:      frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), &frr.RecordingExecutor{}),
	}
	d.frrHA.afterFunc = timers.after
	for range 3 {
		d.scheduleFRRHAReconcile("cluster-state")
	}
	if len(timers.fire) != 1 {
		t.Fatalf("three RG edges armed %d reconcile timers, want 1", len(timers.fire))
	}
}
