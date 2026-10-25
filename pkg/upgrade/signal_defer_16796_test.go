package upgrade

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #16796 (R3-A54-01): a signal during the STOP window must not kill the
// runner and strand the daemon. These cells drive the real Runner.Run /
// RollbackTo through fakeSystem, delivering the signal at StopUnit
// entry — the exact window the source probe used. RED pre-fix: with no
// SignalGuard plumbed, Options/RollbackOptions have no such field and
// the mid-STOP cell cannot even be expressed; the guard cells below
// fail because the runner takes no defer/abort action.

// waitPending polls the guard until the signal goroutine records a
// real OS signal delivered to this test process.
func waitPending(t *testing.T, g *SignalGuard) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := g.Pending(); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("guard never recorded the delivered signal")
}

func TestSignalGuardCapturesRealSignals16796(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		g, stop := InstallSignalGuard(nil)
		if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
			stop()
			t.Fatalf("kill %v: %v", sig, err)
		}
		waitPending(t, g)
		got, _ := g.Pending()
		if got != sig {
			stop()
			t.Fatalf("pending = %v, want %v", got, sig)
		}
		stop()
		// After stop the default disposition is restored; a second
		// guard on the same signal must still work (no leaked Notify).
		g2, stop2 := InstallSignalGuard(nil)
		if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
			stop2()
			t.Fatalf("kill2 %v: %v", sig, err)
		}
		waitPending(t, g2)
		stop2()
	}
}

func TestSignalGuardMayAbortOnlyPreStop16796(t *testing.T) {
	g, stop := InstallSignalGuard(nil)
	defer stop()
	if _, abort := g.MayAbort(true); abort {
		t.Fatal("no signal pending, MayAbort(true) = abort")
	}
	g.DeliverForTest(syscall.SIGINT)
	if _, abort := g.MayAbort(false); abort {
		t.Fatal("post-STOP MayAbort must defer, got abort")
	}
	sig, abort := g.MayAbort(true)
	if !abort || sig != syscall.SIGINT {
		t.Fatalf("pre-STOP MayAbort = (%v,%v), want (SIGINT,true)", sig, abort)
	}
	// Nil guard is a no-op (library callers without a capture).
	var nilGuard *SignalGuard
	if _, abort := nilGuard.MayAbort(true); abort {
		t.Fatal("nil guard aborted")
	}
	if _, ok := nilGuard.Pending(); ok {
		t.Fatal("nil guard reported pending")
	}
}

// Production wiring proof: InstallSignalGuard must register with
// os/signal (through the seam bound to signal.Notify) for exactly
// SIGINT/SIGHUP/SIGTERM, and stop must deregister the same channel.
// Deleting the Notify call (the pre-fix state) fails this cell.
func TestSignalGuardRegistersProductionNotify16796(t *testing.T) {
	var notified []os.Signal
	var stopped bool
	origNotify, origStop := notifyInterruptSignals, stopInterruptSignals
	notifyInterruptSignals = func(c chan<- os.Signal, sig ...os.Signal) {
		notified = append([]os.Signal(nil), sig...)
		// Deliver one so the goroutine also exercises its log path.
		go func() { c <- syscall.SIGHUP }()
	}
	stopInterruptSignals = func(c chan<- os.Signal) { stopped = true }
	t.Cleanup(func() { notifyInterruptSignals, stopInterruptSignals = origNotify, origStop })
	var logs []string
	g, stop := InstallSignalGuard(func(f string, a ...any) { logs = append(logs, f) })
	waitPending(t, g)
	stop()
	if !stopped {
		t.Fatal("stop func did not deregister the notify channel")
	}
	want := map[os.Signal]bool{syscall.SIGINT: true, syscall.SIGHUP: true, syscall.SIGTERM: true}
	if len(notified) != len(want) {
		t.Fatalf("Notify signals = %v, want SIGINT/SIGHUP/SIGTERM", notified)
	}
	for _, s := range notified {
		if !want[s] {
			t.Fatalf("Notify registered unexpected signal %v", s)
		}
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "deferring") {
		t.Fatalf("no deferred-signal log recorded: %v", logs)
	}
}

// Defect cell: SIGINT delivered while StopUnit is blocked/entering must
// NOT abort the cut; Run completes and the unit ends running the target.
func TestRunnerSignalDuringStopDefersAndCompletes16796(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	g, stop := InstallSignalGuard(nil)
	defer stop()
	fs.stopHook = func() { g.DeliverForTest(syscall.SIGINT) }

	err := r.Run(Options{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "deferred") || !strings.Contains(err.Error(), "committed") {
		t.Fatalf("Run with mid-STOP SIGINT: err = %v, want committed-then-deferred-honoured", err)
	}
	if !fs.unitRunning {
		t.Fatal("unit not running after deferred-signal cut; daemon left stopped (#16796 defect)")
	}
	if got := currentTarget(t, r.cfg); got != "2.0.0" {
		t.Fatalf("current = %q, want 2.0.0 (cut completed despite SIGINT)", got)
	}
	if _, pending := g.Pending(); !pending {
		t.Fatal("guard lost the delivered SIGINT")
	}
}

// Control cell: same signal delivered BEFORE StopUnit aborts cleanly
// and StopUnit is never called (daemon still live).
func TestRunnerSignalBeforeStopAbortsCleanly16796(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	g, stop := InstallSignalGuard(nil)
	defer stop()
	g.DeliverForTest(syscall.SIGHUP)

	err := r.Run(Options{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "before STOP") {
		t.Fatalf("Run with pre-STOP SIGHUP: err = %v, want before-STOP abort", err)
	}
	for _, c := range fs.calls {
		if c == "stop" {
			t.Fatalf("StopUnit called despite pre-STOP abort; calls=%v", fs.calls)
		}
	}
	if !fs.unitRunning {
		t.Fatal("unit stopped by a pre-STOP abort")
	}
}

// SIGHUP mid-STOP on the rollback path: RollbackTo finishes the
// start+health sequence and only then honours the signal.
func TestRollbackSignalDuringStopDefers16796(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	g, stop := InstallSignalGuard(nil)
	defer stop()
	fx.fs.stopHook = func() { g.DeliverForTest(syscall.SIGHUP) }
	err := fx.r.RollbackTo("", RollbackOptions{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("RollbackTo with mid-STOP SIGHUP: err = %v, want rolled-back-then-deferred", err)
	}
	if !fx.fs.unitRunning {
		t.Fatal("unit not running after deferred-signal rollback")
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0 (rollback completed)", got)
	}
}

// Positive control: no signal -> ordinary success, nil error, running.
func TestRunnerNoSignalUnchanged16796(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	g, stop := InstallSignalGuard(nil)
	defer stop()
	if err := r.Run(Options{SignalGuard: g}); err != nil {
		t.Fatalf("Run without signal: %v", err)
	}
	if !fs.unitRunning {
		t.Fatal("unit not running after clean cut")
	}
}
