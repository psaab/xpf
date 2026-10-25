package upgrade

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// #16796 (R3-A54-01): the binary-cut runner installed no signal
// disposition, so SIGINT/SIGHUP/SIGTERM arriving during — or just
// before — the STOP window took the default action and killed the
// runner after StopUnit while the later StartUnit/rollback lived only
// in that same process. The standalone daemon then stayed down until a
// human re-ran the verb. The cut's stated invariant is "the daemon
// must not be left offline".
//
// The guard below captures those three signals for the whole run and
// never lets them terminate the process. Whether a captured signal
// defers or aborts depends on how far the run has progressed, which
// only the Runner knows (its journal state / whether STOP was
// attempted), so Run and RollbackTo consult Guard.MayAbort at every
// phase boundary: before STOP a signal aborts cleanly (daemon still
// live); at/after STOP the signal is logged as deferred and the run
// finishes START/rollback first. Installing the guard is also what the
// CLI and kernel sub-verb do up front (cmd/xpfd), so even time spent
// before Runner.Run — parsing, cluster-identity checks, lock wait —
// cannot kill the process mid-handoff.
//
// A second SIGINT after STOP is still deferred, deliberately: there
// is no point in the post-STOP window where killing the runner helps
// the operator, because journal resume requires a manual re-run anyway
// and an immediate kill only widens the offline window. SIGKILL and
// power loss remain uncovered; the durable journal + re-run resume
// covers those.

// interruptSignals is the captured set. SIGTERM is included because
// `systemctl stop xpfd-upgrade`-style supervision of the runner itself
// (or an init system reaping a session) must not strand the daemon
// either; it receives the same defer/abort treatment as Ctrl-C.
var interruptSignals = []os.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM}

// RunWithSignalGuard installs a guard, runs fn with it, and restores
// the default disposition on return. It is the production entry the
// rolling drivers use so the capture spans the drain wait as well as
// the inner cut/rollback: a signal during the drain aborts before
// STOP via the inner run's pre-STOP boundary (the driver then fails
// back), and a signal at/after STOP defers to completion.
func RunWithSignalGuard(logf func(format string, args ...any), fn func(*SignalGuard) error) error {
	g, stop := InstallSignalGuard(logf)
	defer stop()
	return fn(g)
}

// DeliverForTest records sig as if the OS delivered it. It exists so
// Runner tests can drive the mid-STOP cell deterministically through
// the fake System's stopHook without a real process signal racing the
// test binary's own disposition. Production code never calls it.
func (g *SignalGuard) DeliverForTest(sig os.Signal) {
	if g.seen.CompareAndSwap(false, true) {
		g.first.Store(sig)
	}
}

// SignalGuard captures interruptSignals and records the first one.
// It is safe for concurrent use by the signal goroutine and the run.
type SignalGuard struct {
	ch    chan os.Signal
	done  chan struct{}
	first atomic.Value // os.Signal
	seen  atomic.Bool
}

// notifyInterruptSignals is the signal.Notify seam so tests can prove
// the production guard actually registers (and restores) the real
// disposition instead of only exercising an in-memory fake.
var notifyInterruptSignals = signal.Notify

// stopInterruptSignals restores the default disposition. Paired with
// notifyInterruptSignals.
var stopInterruptSignals = signal.Stop

// InstallSignalGuard captures SIGINT/SIGHUP/SIGTERM until the returned
// stop func is called, which restores the default disposition. Each
// captured signal is logged (via logf, may be nil) as deferred or
// abort-pending depending on abortable at capture time; the authoritative
// phase decision is made by the Runner at its next boundary, so the log
// wording here is advisory — the run's own boundary log repeats it with
// the phase context. Callers that only need "do not die" (CLI/kernel
// entry before a Runner exists) install a guard and ignore the result
// beyond deferring stop.
func InstallSignalGuard(logf func(format string, args ...any)) (g *SignalGuard, stop func()) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	g = &SignalGuard{
		ch:   make(chan os.Signal, 4),
		done: make(chan struct{}),
	}
	notifyInterruptSignals(g.ch, interruptSignals...)
	go func() {
		for {
			select {
			case sig := <-g.ch:
				if g.seen.CompareAndSwap(false, true) {
					g.first.Store(sig)
					logf("upgrade: %s received; deferring it until the cut reaches a safe boundary (#16796) — the daemon will not be left stopped", sig)
				} else {
					logf("upgrade: %s received again; still deferred until the cut finishes or rolls back (#16796)", sig)
				}
			case <-g.done:
				return
			}
		}
	}()
	var once atomic.Bool
	stop = func() {
		if once.CompareAndSwap(false, true) {
			stopInterruptSignals(g.ch)
			close(g.done)
		}
	}
	return g, stop
}

// Pending reports the first captured signal, if any.
func (g *SignalGuard) Pending() (os.Signal, bool) {
	if g == nil || !g.seen.Load() {
		return nil, false
	}
	sig, _ := g.first.Load().(os.Signal)
	return sig, sig != nil
}

// MayAbort reports whether a pending signal may abort the run now.
// It returns the pending signal and true only when a signal is pending
// AND abortable says the run is still before its point of no return
// (STOP not yet attempted). Once STOP has been attempted abortable is
// false and the signal stays deferred to completion.
func (g *SignalGuard) MayAbort(abortable bool) (os.Signal, bool) {
	sig, ok := g.Pending()
	if !ok || !abortable {
		return sig, false
	}
	return sig, true
}
