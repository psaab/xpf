package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
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

	wg := d.frr.WriteGeneration()
	seq := d.frrApplySeq.Add(1)                  // the HA render
	if err := d.applyFRRConfig(fc); err != nil { // a later write (commit path)
		t.Fatalf("premise: later write failed: %v", err)
	}
	before := rec.ReloadCalls
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("superseded apply returned %v, want nil", err)
	}
	if rec.ReloadCalls != before {
		t.Fatal("a render overtaken by a later FRR write was applied after it")
	}

	wg = d.frr.WriteGeneration()
	seq = d.frrApplySeq.Add(1)
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("current apply: %v", err)
	}
	if rec.ReloadCalls != before+1 {
		t.Fatalf("an un-overtaken render was not applied (reload calls %d -> %d)", before, rec.ReloadCalls)
	}
}

// The ip-monitoring gating reconcile holds applySem across an FRR reload
// when the gate changes; an election's edges must arm ONE run after the
// burst, not one per edge racing the later RGs' activations.
func TestScheduleIPMonGatingUsesCoalescer18561(t *testing.T) {
	timers := &manualTimers18561{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    fenceTestStore(t, fenceStartupClusterSet),
		cluster:  cluster.NewManager(0, 1),
	}
	d.ipmonGateHA.afterFunc = timers.after
	for range 3 {
		d.scheduleIPMonGating("cluster-state")
	}
	if len(timers.fire) != 1 {
		t.Fatalf("three RG edges armed %d ip-monitoring gating runs, want 1", len(timers.fire))
	}
}

// An ownership edge supersedes an HA render taken before it, so a render
// that predates a demotion cannot publish the demoted RG's routes. RED if
// scheduleFRRHAReconcile stops bumping the sequence.
func TestRGEdgeSupersedesEarlierHARender18561(t *testing.T) {
	rec := &frr.RecordingExecutor{}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	timers := &manualTimers18561{}
	d.frrHA.afterFunc = timers.after
	cfg := d.store.ActiveConfig()
	fc := d.assembleFRRConfigForActiveConfig(cfg, d.commitOverlayForConfig(cfg))
	wg := d.frr.WriteGeneration()
	seq := d.frrApplySeq.Add(1) // a render taken before the edge
	d.scheduleFRRHAReconcile("cluster-state")
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("superseded apply: %v", err)
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("an HA render taken before an ownership edge was applied after it")
	}
}

// The predicate also refuses a render while a factory reset is in progress
// (the reset wipes frr.conf under applySem, which this apply no longer holds).
func TestHARenderSkippedDuringReset18561(t *testing.T) {
	rec := &frr.RecordingExecutor{}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	cfg := d.store.ActiveConfig()
	fc := d.assembleFRRConfigForActiveConfig(cfg, d.commitOverlayForConfig(cfg))
	wg := d.frr.WriteGeneration()
	seq := d.frrApplySeq.Add(1)
	d.resetting.Store(true)
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("apply during reset: %v", err)
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("an HA render was applied while a factory reset was in progress")
	}
}

// The fail-closed boot's FRR clear supersedes an in-flight HA render, so
// the render cannot re-add the managed section the clear removed. The clear
// is a write, so it moves the FRR manager's write generation.
func TestFailClosedBootClearSupersedesHARender18561(t *testing.T) {
	rec := &frr.RecordingExecutor{}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	cfg := d.store.ActiveConfig()
	fc := d.assembleFRRConfigForActiveConfig(cfg, d.commitOverlayForConfig(cfg))
	wg := d.frr.WriteGeneration()
	seq := d.frrApplySeq.Add(1)
	d.clearFRRForFailClosedBoot(true)
	if rec.ReloadCalls == 0 {
		t.Skip("premise: the fail-closed clear did not run on this host (pinned XDP links present)")
	}
	cleared := rec.ReloadCalls
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("superseded apply: %v", err)
	}
	if rec.ReloadCalls != cleared {
		t.Fatal("an HA render taken before the fail-closed boot's clear re-wrote the section after it")
	}
}

// A commit-path FRR apply that is REFUSED before writing (here: a BGP
// neighbor duplicated across groups, #11399) must not supersede an HA render:
// nothing was written, so the HA render is still the newest config. Before
// the write generation, applyFRRConfig bumped the sequence up front and the
// HA reload was lost with nothing re-armed.
func TestRefusedFRRWriteDoesNotSupersedeHARender18561(t *testing.T) {
	rec := &frr.RecordingExecutor{}
	d := frrHADaemon18561(t)
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rec)
	cfg := d.store.ActiveConfig()
	fc := d.assembleFRRConfigForActiveConfig(cfg, d.commitOverlayForConfig(cfg))
	wg := d.frr.WriteGeneration()
	seq := d.frrApplySeq.Add(1)
	refused := &frr.FullConfig{BGP: &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, GroupName: "a"},
			{Address: "10.0.2.1", PeerAS: 65003, GroupName: "b"},
		},
	}}
	if err := d.applyFRRConfig(refused); err == nil {
		t.Fatal("premise: a cross-group duplicate BGP neighbor must be refused before the write")
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("premise: the refused apply reloaded FRR")
	}
	if err := d.applyFRRConfigIfCurrent(fc, seq, wg); err != nil {
		t.Fatalf("HA apply after a refused write: %v", err)
	}
	if rec.ReloadCalls != 1 {
		t.Fatal("a refused commit-path render superseded the HA render; its reload was lost")
	}
}

// factoryReset must not run its wipe (which strips frr.conf without the FRR
// manager's locks) while an HA FRR write that predates the reset flag is
// still in flight. RED if factoryReset skips frr.Manager.BuildBarrier.
func TestFactoryResetWaitsForInFlightHAWrite18561(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	blk := &blockingReload18561{
		RecordingExecutor: &frr.RecordingExecutor{},
		entered:           make(chan struct{}),
		release:           make(chan struct{}),
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.frr = frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), blk)
	haDone := make(chan struct{})
	go func() {
		_ = d.applyFRRConfigIfCurrent(&frr.FullConfig{ClusterMode: true}, d.frrApplySeq.Load(), d.frr.WriteGeneration())
		close(haDone)
	}()
	<-blk.entered
	wiped := make(chan bool, 1)
	resetDone := make(chan struct{})
	go func() {
		_ = d.factoryReset(context.Background(), func() error {
			select {
			case <-haDone:
				wiped <- true
			default:
				wiped <- false
			}
			return errors.New("stop after the wipe probe")
		})
		close(resetDone)
	}()
	time.Sleep(100 * time.Millisecond)
	close(blk.release)
	<-resetDone
	if !<-wiped {
		t.Fatal("factoryReset wiped while an HA FRR write was still in flight; the write could land after the strip")
	}
}
