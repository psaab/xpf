package upgrade

import (
	"strings"
	"syscall"
	"testing"
)

// #17831 (retro of #17599, astra lane F1): Run's entry-time #16796 check
// aborted on a pending interrupt BEFORE the persisted journal was read, so a
// resume whose journal said STOPPED or ROLLINGBACK (a prior attempt already
// stopped the unit) exited claiming "the daemon was not stopped" while the
// unit stayed down — neither finishing START nor rolling back. The fix makes
// the journal-backed post-journal boundary the ONLY pre-STOP abort point, so
// the persisted stop state is classified before an entry-pending signal is
// honoured. Pre-fix RED: both resume cells below return the "aborted ...
// before STOP; the daemon was not stopped" error with the unit left stopped.

// Defect cell 1: SIGINT pending BEFORE Run is invoked (delivered during
// pre-Run CLI work — the production wiring installs the guard for the whole
// verb) on a STOPPED journal must defer, finish the resumed cut (START +
// commit), and honour the signal only with the daemon running again.
func TestRunnerSignalPendingAtEntryStoppedJournalDefers17831(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	seedCrashState(t, r, cfg, fs, StateStopped) // unit down, journal STOPPED

	g, stop := InstallSignalGuard(nil)
	defer stop()
	g.DeliverForTest(syscall.SIGINT)

	err := r.Run(Options{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "committed") || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("STOPPED resume with entry-pending SIGINT: err = %v, want committed-then-deferred-honoured (not a pre-STOP abort)", err)
	}
	if !fs.unitRunning {
		t.Fatal("unit left stopped by an entry-pending signal on a STOPPED resume (#17831 defect)")
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current = %q, want 2.0.0 (resume completed despite the entry-pending signal)", got)
	}
	if _, pending := g.Pending(); !pending {
		t.Fatal("guard lost the entry-pending SIGINT before honouring it")
	}
}

// Defect cell 2: SIGTERM pending BEFORE Run on a ROLLINGBACK journal (the
// interrupted rollback already stopped the unit) must defer and complete the
// rollback, not abort before STOP.
func TestRunnerSignalPendingAtEntryRollingBackJournalDefers17831(t *testing.T) {
	r, cfg, fs := seedAutoRollingBack14721(t)
	// The interrupted rollback stopped the unit, then crashed before its
	// StartUnit — the stranded-down production shape.
	must(t, fs.StopUnit(cfg.Unit))

	g, stop := InstallSignalGuard(nil)
	defer stop()
	g.DeliverForTest(syscall.SIGTERM)

	err := r.Run(Options{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 1.0.0") {
		t.Fatalf("ROLLINGBACK resume with entry-pending SIGTERM: err = %v, want resumed-rollback completion (not a pre-STOP abort)", err)
	}
	if !fs.unitRunning {
		t.Fatal("unit left stopped by an entry-pending signal on a ROLLINGBACK resume (#17831 defect)")
	}
	if got := currentTarget(t, cfg); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0 (rollback completed despite the entry-pending signal)", got)
	}
}

// Control: the fix must NOT blunt the pre-STOP abort. A pending signal on a
// PRE-STOP journal (StateCopied, unit still live) still aborts before STOP
// and never stops the unit — now through the post-journal boundary.
func TestRunnerSignalPendingAtEntryPreStopJournalStillAborts17831(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	seedCrashState(t, r, cfg, fs, StateCopied) // pre-STOP: unit still running

	g, stop := InstallSignalGuard(nil)
	defer stop()
	g.DeliverForTest(syscall.SIGHUP)

	err := r.Run(Options{SignalGuard: g})
	if err == nil || !strings.Contains(err.Error(), "before STOP") {
		t.Fatalf("pre-STOP journal with entry-pending SIGHUP: err = %v, want before-STOP abort", err)
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
