package daemon

import (
	"context"
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

// blockingReload18561 holds frr-reload.py open until the cell releases it.
type blockingReload18561 struct {
	*frr.RecordingExecutor
	entered chan struct{}
	release chan struct{}
}

func (b *blockingReload18561) FrrReloadPy(ctx context.Context, conf string) error {
	close(b.entered)
	<-b.release
	return b.RecordingExecutor.FrrReloadPy(ctx, conf)
}

func frrHADaemon18561(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    fenceTestStore(t, fenceStartupClusterSet),
		cluster:  cluster.NewManager(0, 1),
	}
}

// #18561: the HA reconcile renders under applySem and runs frr-reload.py
// after releasing it, so an RG activation's synchronous connected-route
// republish (which takes applySem before SetRGActive, #16270) never waits
// for the reload. RED on revert (applySem held across the reload).
func TestFRRHAReconcileReleasesApplySemDuringReload18561(t *testing.T) {
	blk := &blockingReload18561{
		RecordingExecutor: &frr.RecordingExecutor{},
		entered:           make(chan struct{}),
		release:           make(chan struct{}),
	}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), blk)
	done := make(chan struct{})
	go func() {
		d.runFRRHAReconcile("cluster-state")
		close(done)
	}()
	select {
	case <-blk.entered:
	case <-time.After(5 * time.Second):
		close(blk.release)
		t.Fatal("premise: the reconcile never reached frr-reload.py")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := d.applySem.Acquire(ctx, 1)
	close(blk.release)
	<-done
	if err != nil {
		t.Fatal("applySem is held across frr-reload.py: an RG activation would queue behind the reload")
	}
	d.applySem.Release(1)
	if blk.ReloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", blk.ReloadCalls)
	}
}

// An HA render that another FRR write overtook is dropped, so the older
// render cannot overwrite the newer config; an un-overtaken render applies.
// RED if the staleness predicate is dropped or applyFRRConfig stops
// bumping the sequence.
func TestFRRHARenderSupersededByLaterWrite18561(t *testing.T) {
	rec := &frr.RecordingExecutor{}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	cfg := d.store.ActiveConfig()
	fc := d.assembleFRRConfigForActiveConfig(cfg, d.commitOverlayForConfig(cfg))

	seq := d.frrApplySeq.Add(1)                  // the HA render
	if err := d.applyFRRConfig(fc); err != nil { // a later write (commit path)
		t.Fatalf("premise: later write failed: %v", err)
	}
	before := rec.ReloadCalls
	if err := d.applyFRRConfigIfCurrent(fc, seq); err != nil {
		t.Fatalf("superseded apply returned %v, want nil", err)
	}
	if rec.ReloadCalls != before {
		t.Fatal("a render overtaken by a later FRR write was applied after it")
	}

	seq = d.frrApplySeq.Add(1)
	if err := d.applyFRRConfigIfCurrent(fc, seq); err != nil {
		t.Fatalf("current apply: %v", err)
	}
	if rec.ReloadCalls != before+1 {
		t.Fatalf("an un-overtaken render was not applied (reload calls %d -> %d)", before, rec.ReloadCalls)
	}
}
