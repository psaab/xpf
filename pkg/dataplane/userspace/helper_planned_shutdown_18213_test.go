package userspace

import (
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// #18213: a systemd stop's SIGTERM to xpf-userspace-dp must not be mistaken
// for an unexpected helper crash. The daemon marks the current process
// generation intentional at the beginning of its shutdown sequence; the
// helper's reaper checks that per-generation mark before crash accounting,
// restart debt or the unexpected-exit log.

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

// TestMarkedSystemdSIGTERMDoesNotMintCrash18213 synchronously drives the
// production waiter with a real SIGTERM after the daemon adapter has published
// its planned-stop mark. It fails if the reaper ignores that generation-specific
// marker and records a crash, restart weight, or restart timer.
func TestMarkedSystemdSIGTERMDoesNotMintCrash18213(t *testing.T) {
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	m := New()
	rec := &restartRecorder{}
	m.restartTimerFn = rec.arm
	g := &helperGeneration{gen: 1, cmd: cmd, exited: make(chan struct{})}
	m.mu.Lock()
	m.proc = cmd
	m.procGen = g.gen
	m.procSup = g
	m.mu.Unlock()

	NewLegacyDataPlaneAdapter(m).MarkHelperStopIntent()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send planned SIGTERM: %v", err)
	}
	// Run the production single-waiter path synchronously so return proves
	// its post-Wait crash decision has completed.
	m.superviseHelper(g)

	m.mu.Lock()
	crash := m.helperCrash
	exits := m.helperCrashUnexpectedExitsTotal
	episodesTotal := m.helperCrashEpisodesTotal
	m.proc = nil
	m.procSup = nil
	m.mu.Unlock()
	if exits != 0 || crash.LastExitWasCrash || crash.Restarts != 0 || episodesTotal != 0 {
		t.Errorf("planned SIGTERM produced crash accounting: exits=%d record=%+v episodes=%d; want no crash debt (#18213)",
			exits, crash, episodesTotal)
	}
	if n := len(rec.snapshot()); n != 0 {
		t.Errorf("planned SIGTERM armed %d restart(s) %v, want none (#18213)", n, rec.snapshot())
	}
	if got := m.HelperCrashExitCount(); got != 0 {
		t.Errorf("HelperCrashExitCount() = %d, want 0 after planned SIGTERM", got)
	}
	if running, looping := m.HelperSupervisorState(); running || looping {
		t.Errorf("planned SIGTERM left supervisor state running=%v crashLooping=%v, want no process or crash-loop weight (#18213)",
			running, looping)
	}
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

// TestGenuineSIGKILLStillCountsAfterPlannedStop18213 pins the #18242
// separation: the intentional-stop excuse is fenced to the stopped
// generation only. A NEW generation that is then genuinely SIGKILLed
// (external kill, no stopLocked in flight) must still count exactly one
// unexpected exit with restart debt — the fix must not stickily suppress
// real crash accounting across generations.
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

	// Genuine external SIGKILL — no stopLocked, no intentional marking.
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
