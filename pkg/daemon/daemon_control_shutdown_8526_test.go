package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8526 WIRING. runShutdownSequence must bound the dataplane control socket
// before it starts waiting on anything, because three of its waits can be held
// by a goroutine sitting in a control round trip whose reachable deadline is
// 67s against this unit's TimeoutStopSec=20.
//
// THE SILENT-FAILURE THIS EXISTS FOR. The bound is reached through an OPTIONAL
// interface (controlShutdownBounder), so a rename, a missing adapter
// pass-through, or a deleted call site produces no build error and no failing
// test anywhere else — the assertion just stops matching and the daemon
// quietly goes back to being SIGKILLed mid-shutdown. The two compile-time
// assertions below cover the type side; the test covers the call site and its
// ORDER.
//
// The daemon holds the userspace runtime as a *LegacyDataPlaneAdapter
// (userspace.Boot returns one), so the ADAPTER is the type that actually has
// to match. *Manager is asserted too because that is what the adapter forwards
// to, and a rename there is the other half of the same break.
var (
	_ controlShutdownBounder = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ controlShutdownBounder = (*dpuserspace.Manager)(nil)
)

// schedulerHoldFallback models the m.mu hold the bound exists to cut. It must
// exceed the assertion window below by a wide margin: with the wiring removed
// the shutdown sequence blocks for this long, which is what turns the mutation
// into a KILL instead of a hung test binary.
const schedulerHoldFallback = 10 * time.Second

// controlShutdownDP is a RuntimeDataPlane that records the #8526 bound. The
// interface is embedded (nil) to satisfy the rest; the standalone/hitless arm
// this harness drives calls only Close().
type controlShutdownDP struct {
	dataplane.RuntimeDataPlane

	once    sync.Once
	bounded chan struct{}
}

func (d *controlShutdownDP) Start(context.Context) error { return nil }
func (d *controlShutdownDP) Close() error                { return nil }
func (d *controlShutdownDP) Teardown() error             { return nil }
func (d *controlShutdownDP) BeginControlShutdown() {
	d.once.Do(func() { close(d.bounded) })
}

// TestRunShutdownSequenceBoundsControlIOBeforeJoiningTheScheduler8526 drives
// the REAL teardown path with a scheduler generation that only finishes once
// the control socket has been bounded — exactly the production shape, where
// the joined goroutine is the policy scheduler and its updateFn is
// UpdatePolicyScheduleStateWithLatch, the site #8526 was filed against.
//
// The sequence can therefore only return promptly if BeginControlShutdown ran
// BEFORE d.stopPolicySchedulerLoop()'s unbounded schedulerWg.Wait(). That
// makes this an ORDER assertion, not just a call-count one.
//
// MUTATION: delete the `if b, ok := d.dataplane().(controlShutdownBounder)`
// block from runShutdownSequence. The join then falls through to
// schedulerHoldFallback and this cell fails at its bound with a clean message.
// Renaming Manager.BeginControlShutdown reds the two assertions above instead.
func TestRunShutdownSequenceBoundsControlIOBeforeJoiningTheScheduler8526(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	t.Cleanup(cancelDaemon)

	dp := &controlShutdownDP{bounded: make(chan struct{})}
	d := &Daemon{
		store:     store,
		applySem:  semaphore.NewWeighted(1),
		daemonCtx: daemonCtx,
	}
	d.setDataplane(dp)

	// The scheduler generation stopPolicySchedulerLoop joins. It stands in for
	// a tick blocked inside UpdatePolicyScheduleStateWithLatch holding m.mu across a
	// control round trip: it is released by the control-socket bound, and
	// otherwise only by a fallback far outside the stop budget.
	joined := make(chan struct{})
	d.schedulerWg.Add(1)
	go func() {
		defer d.schedulerWg.Done()
		defer close(joined)
		select {
		case <-dp.bounded:
		case <-time.After(schedulerHoldFallback):
		}
	}()

	var wg sync.WaitGroup
	_, stopRun := context.WithCancel(context.Background())
	sentinel := errors.New("run-error-passthrough")

	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(context.Background(), &wg, stopRun, sentinel) }()

	const bound = 4 * time.Second
	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(bound):
		t.Fatalf("runShutdownSequence was still running after %v: it joins the policy "+
			"scheduler without first bounding the dataplane control socket, so a tick "+
			"inside UpdatePolicyScheduleStateWithLatch holds it for the full control round-trip "+
			"deadline (67s reachable) against TimeoutStopSec=20 (#8526)", bound)
	}
	if runErr != sentinel {
		t.Errorf("runShutdownSequence must pass runErr through unchanged: got %v, want %v",
			runErr, sentinel)
	}

	select {
	case <-dp.bounded:
	default:
		t.Fatal("runShutdownSequence never called BeginControlShutdown on the dataplane")
	}
	select {
	case <-joined:
	default:
		t.Fatal("the scheduler generation was not joined by the shutdown sequence")
	}
}
