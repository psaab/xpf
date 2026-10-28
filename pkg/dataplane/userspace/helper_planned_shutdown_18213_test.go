package userspace

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// #18213: systemd must deliver the initial stop signal to xpfd alone. The
// daemon then retires the helper generation before its owned shutdown signals,
// so the supervisor does not account that planned exit as a crash.

// spawnSupervisedHelper18213 starts a real helper child under the production
// supervisor. Its control socket has no listener, so stopLocked reaches its
// SIGTERM escalation; this pins the intentional-stop cleanup path.
func spawnSupervisedHelper18213(t *testing.T) (*Manager, *exec.Cmd, *restartRecorder) {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	rec := &restartRecorder{}
	m := New()
	m.restartTimerFn = rec.arm
	m.mode = ModeUserspaceCompat
	dir := t.TempDir()
	m.cfg.ControlSocket = filepath.Join(dir, "c.sock")
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.xskLivenessProven = true
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	m.mu.Lock()
	m.proc = cmd
	m.startHelperSupervisorLocked(cmd)
	m.mu.Unlock()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return m, cmd, rec
}

// TestPlannedShutdownStopLockedNoCrash18213 is the #18213 regression: a
// daemon-initiated stopLocked of a helper that does not respond to the
// control-shutdown request must produce NO crash accounting — no unexpected-exit
// count, no crash record, no restart debt, no armed restart.
func TestPlannedShutdownStopLockedNoCrash18213(t *testing.T) {
	m, _, rec := spawnSupervisedHelper18213(t)

	m.mu.Lock()
	exitsBefore := m.helperCrashUnexpectedExitsTotal
	m.stopLocked()
	m.mu.Unlock()

	// stopLocked blocks until the waiter closes exited, but the waiter's
	// bookkeeping follows after it acquires m.mu. Give it a bounded window.
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	episodesTotal := m.helperCrashEpisodesTotal
	m.mu.Unlock()

	if exits != exitsBefore {
		t.Errorf("planned shutdown counted %d unexpected exit(s) (total %d, want %d): a planned stop must not mint crash accounting (#18213)",
			exits-exitsBefore, exits, exitsBefore)
	}
	if crash.LastExitWasCrash {
		t.Errorf("planned shutdown recorded a crash: %+v (#18213)", crash)
	}
	if crash.Restarts != 0 {
		t.Errorf("planned shutdown minted restart debt: Restarts=%d, want 0 (#18213)", crash.Restarts)
	}
	if episodesTotal != 0 {
		t.Errorf("planned shutdown recorded %d crash episode(s), want 0 (#18213)", episodesTotal)
	}
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("planned shutdown armed %d restart(s) %v, want none (#18213)", n, rec.snapshot())
	}
	if got := m.HelperCrashExitCount(); got != exitsBefore {
		t.Errorf("HelperCrashExitCount() = %d, want %d after a planned shutdown (#18213)", got, exitsBefore)
	}
	if running, looping := m.HelperSupervisorState(); running || looping {
		t.Errorf("planned shutdown left supervisor state running=%v crashLooping=%v, want no process or crash-loop weight (#18213)",
			running, looping)
	}
}

// TestGenuineSIGKILLDuringShutdownBeforeHelperStopCounts18213 protects the
// #18242 boundary: after the daemon has begun shutdown but before it reaches
// stopLocked, a genuine helper SIGKILL is still unexpected and must be counted.
func TestGenuineSIGKILLDuringShutdownBeforeHelperStopCounts18213(t *testing.T) {
	m, cmd, rec := spawnSupervisedHelper18213(t)
	m.BeginControlShutdown()

	m.mu.Lock()
	exitsBefore := m.helperCrashUnexpectedExitsTotal
	exited := m.procSup.exited
	m.mu.Unlock()

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("send genuine SIGKILL during shutdown: %v", err)
	}
	awaitSupervisor(t, m, exited)

	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	m.mu.Unlock()
	if exits != exitsBefore+1 {
		t.Errorf("genuine SIGKILL during shutdown counted %d unexpected exit(s), want %d (#18213/#18242 separation)",
			exits-exitsBefore, exitsBefore+1)
	}
	if !crash.LastExitWasCrash || crash.PID != cmd.Process.Pid || crash.Restarts == 0 {
		t.Errorf("genuine SIGKILL during shutdown did not retain crash record/debt: %+v", crash)
	}
	if n := len(rec.snapshot()); n == 0 {
		t.Errorf("genuine SIGKILL during shutdown scheduled no restart")
	}
}

// TestGenuineSIGKILLStillCountsAfterPlannedStop18213 pins the #18242
// separation: an external SIGKILL on the next generation after an intentional
// stop still counts exactly one unexpected exit with restart debt.
func TestGenuineSIGKILLStillCountsAfterPlannedStop18213(t *testing.T) {
	m, _, _ := spawnSupervisedHelper18213(t)

	// Planned stop of generation 1.
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	exitsAfterStop := m.helperCrashUnexpectedExitsTotal
	m.mu.Unlock()
	if exitsAfterStop != 0 {
		t.Fatalf("premise: planned stop already counted %d crash(es); genuine-kill delta would be unmeasurable", exitsAfterStop)
	}

	// Spawn generation 2 under the same manager/supervisor.
	cmd2 := exec.Command("sleep", "300")
	if err := cmd2.Start(); err != nil {
		t.Fatalf("spawn gen2: %v", err)
	}
	t.Cleanup(func() { _ = cmd2.Process.Kill() })
	m.mu.Lock()
	m.proc = cmd2
	m.startHelperSupervisorLocked(cmd2)
	exited2 := m.procSup.exited
	m.mu.Unlock()

	// Genuine external SIGKILL — no stopLocked in flight.
	if err := cmd2.Process.Kill(); err != nil {
		t.Fatalf("kill gen2: %v", err)
	}
	awaitSupervisor(t, m, exited2)

	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	m.mu.Unlock()
	if exits != exitsAfterStop+1 {
		t.Errorf("genuine SIGKILL counted %d unexpected exit(s) total, want exactly %d: real crashes must still count after a planned stop (#18213/#18242 separation)",
			exits, exitsAfterStop+1)
	}
	if !crash.LastExitWasCrash {
		t.Errorf("genuine SIGKILL recorded no crash: %+v (#18242 separation)", crash)
	}
	if crash.PID != cmd2.Process.Pid {
		t.Errorf("crash record PID = %d, want the genuinely killed child %d", crash.PID, cmd2.Process.Pid)
	}
	if crash.Restarts == 0 {
		t.Errorf("genuine SIGKILL minted no restart debt: %+v", crash)
	}
}

// TestGenuineSIGKILLReapedWhileMutexHeldBeforeStopCounts18213 is the
// Rev18367 exact interleaving: m.mu is held continuously across the genuine
// SIGKILL and the waiter's reap (exited closed), and only then does
// stopLocked retire the generation. The exit happened BEFORE retirement, so
// mutex acquisition order must not fence it away: it must count as one
// unexpected exit with a crash record and an armed restart.
//
// RED on the unmodified head: stopLocked's procGen++ lands before the waiter
// acquires m.mu, the waiter's generation fence sees a retired generation,
// and the genuine kill is silently accounted as ZERO.
func TestGenuineSIGKILLReapedWhileMutexHeldBeforeStopCounts18213(t *testing.T) {
	m, cmd, rec := spawnSupervisedHelper18213(t)
	m.BeginControlShutdown()

	m.mu.Lock()
	exitsBefore := m.helperCrashUnexpectedExitsTotal
	exited := m.procSup.exited
	// Hold m.mu across the kill AND the reap: the waiter runs cmd.Wait,
	// publishes its state and closes exited, then blocks on m.mu. Only after
	// the exit is fully observed does stopLocked retire the generation.
	if err := cmd.Process.Kill(); err != nil {
		m.mu.Unlock()
		t.Fatalf("send genuine SIGKILL while holding m.mu: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		m.mu.Unlock()
		t.Fatal("supervisor never reaped the child while m.mu was held")
	}
	m.stopLocked()
	m.mu.Unlock()

	// stopLocked returned after the waiter closed exited, but the waiter's
	// bookkeeping follows after it acquires m.mu. Give it a bounded window,
	// mirroring TestPlannedShutdownStopLockedNoCrash18213.
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	m.mu.Unlock()
	if exits != exitsBefore+1 {
		t.Errorf("genuine SIGKILL reaped before stopLocked counted %d unexpected exit(s), want %d: an exit observed before generation retirement must count even when m.mu was held across the reap (#18213)",
			exits-exitsBefore, exitsBefore+1)
	}
	if !crash.LastExitWasCrash || crash.PID != cmd.Process.Pid || crash.Restarts == 0 {
		t.Errorf("genuine SIGKILL reaped before stopLocked did not retain crash record/debt: %+v", crash)
	}
	if n := len(rec.snapshot()); n == 0 {
		t.Errorf("genuine SIGKILL reaped before stopLocked scheduled no restart")
	}
}

// TestGenuineSIGKILLAfterGenerationRetirementDoesNotCount18213 pins the
// opposite side of the same boundary. stopLocked retires the process
// generation before sending any helper signal; a SIGKILL after that point is
// therefore part of the intentional stop, not unexpected crash accounting.
func TestGenuineSIGKILLAfterGenerationRetirementDoesNotCount18213(t *testing.T) {
	m, cmd, rec := spawnSupervisedHelper18213(t)
	m.BeginControlShutdown()

	m.mu.Lock()
	exitsBefore := m.helperCrashUnexpectedExitsTotal
	exited := m.procSup.exited
	// procGen++ is stopLocked's retirement linearization point; hold the lock
	// through the post-retirement kill and reap so the waiter cannot account
	// until after that fence is established.
	m.procGen++
	if err := cmd.Process.Kill(); err != nil {
		m.mu.Unlock()
		t.Fatalf("send SIGKILL after generation retirement: %v", err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		m.mu.Unlock()
		t.Fatal("supervisor never reaped the child after generation retirement")
	}
	m.mu.Unlock()

	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	m.mu.Unlock()
	if exits != exitsBefore {
		t.Errorf("post-retirement SIGKILL counted %d unexpected exit(s), want none", exits-exitsBefore)
	}
	if crash.LastExitWasCrash || crash.Restarts != 0 {
		t.Errorf("post-retirement SIGKILL created crash record/debt: %+v", crash)
	}
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("post-retirement SIGKILL scheduled %d restart(s) %v, want none", n, rec.snapshot())
	}
}
