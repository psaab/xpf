package userspace

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const nmPersistentHelper12159 = `#!/usr/bin/python3
import socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
while True:
    time.sleep(300)
`

const nmRetryThenStayHelper12159 = `#!/usr/bin/python3
import os, socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
counter = os.path.join(os.path.dirname(path), "attempts")
try:
    n = int(open(counter).read())
except Exception:
    n = 0
n += 1
open(counter, "w").write(str(n))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
if n == 1:
    time.sleep(0.1)
    os._exit(7)
while True:
    time.sleep(300)
`

func startNMHelper12159(t *testing.T, script string, timer func(time.Duration, func())) *Manager {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "nm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	binary := filepath.Join(dir, "helper")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.mode = ModeUserspaceCompat
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	m.restartTimerFn = timer
	cfg := config.UserspaceConfig{
		Binary:        binary,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "s.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("initial real-helper bring-up: %v", err)
	}
	t.Cleanup(func() {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
	})
	return m
}

type nmManualRetry12159 struct {
	mu    sync.Mutex
	retry func()
}

func (r *nmManualRetry12159) arm(_ time.Duration, fn func()) {
	r.mu.Lock()
	r.retry = fn
	r.mu.Unlock()
}
func (r *nmManualRetry12159) fire(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	fn := r.retry
	r.retry = nil
	r.mu.Unlock()
	if fn == nil {
		t.Fatal("supervisor did not arm a retry callback")
	}
	fn()
}

func waitNMSupervisorRunning12159(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		running := m.proc != nil && m.proc.Process != nil && m.procSup != nil
		m.mu.Unlock()
		if running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("real helper did not return under the production supervisor")
}

func killNMSupervisedChild12159(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	cmd, sup := m.proc, m.procSup
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil || sup == nil {
		t.Fatal("no real supervised child to kill")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill real helper: %v", err)
	}
	awaitSupervisor(t, m, sup.exited)
}

// NM-2: crashes separated by more than the backoff quiet window begin fresh
// count episodes. Each crash and retry is a real helper child owned by Manager.
func TestIsolatedCrashesResetRestartCount12159(t *testing.T) {
	oldBase, oldMax := helperRestartBackoffBase, helperRestartBackoffMax
	helperRestartBackoffBase, helperRestartBackoffMax = 10*time.Millisecond, 64*time.Millisecond
	t.Cleanup(func() {
		helperRestartBackoffBase, helperRestartBackoffMax = oldBase, oldMax
	})
	retry := &nmManualRetry12159{}
	m := startNMHelper12159(t, nmPersistentHelper12159, retry.arm)

	for i := 1; i <= 8; i++ {
		waitNMSupervisorRunning12159(t, m)
		if i > 1 {
			time.Sleep(300 * time.Millisecond) // > 2x the compressed 64ms cap
		}
		killNMSupervisedChild12159(t, m)
		rec := m.HelperCrashState()
		running, looping := m.HelperSupervisorState()
		t.Logf("isolated crash %d: running=%v looping=%v Restarts=%d", i, running, looping, rec.Restarts)
		if running || looping {
			t.Fatalf("isolated crash %d entered crash-loop state: running=%v looping=%v Restarts=%d",
				i, running, looping, rec.Restarts)
		}
		if rec.Restarts != 1 {
			t.Fatalf("isolated crash %d inherited the previous count: Restarts=%d, want 1", i, rec.Restarts)
		}
		if i < 8 {
			retry.fire(t)
		}
	}
	_, recovered := m.HelperCrashHistory()
	if recovered != 7 {
		t.Fatalf("quietly ended recovered episodes=%d, want 7 (one journal entry per episode)", recovered)
	}
}

// NM-3: a real supervisor retry landing is reported as recovered while the
// child runs, and an intentional stop cannot leave a stale "running" marker.
func TestSupervisorRetryRecoveryState12159(t *testing.T) {
	var mu sync.Mutex
	var retry func()
	m := startNMHelper12159(t, nmRetryThenStayHelper12159, func(_ time.Duration, fn func()) {
		mu.Lock()
		retry = fn
		mu.Unlock()
	})
	m.mu.Lock()
	exited := m.procSup.exited
	m.mu.Unlock()
	awaitSupervisor(t, m, exited)

	mu.Lock()
	fn := retry
	mu.Unlock()
	if fn == nil {
		t.Fatal("production crash handler did not arm a retry callback")
	}
	fn() // invokes restartHelperAfterCrash against a second real child
	waitNMSupervisorRunning12159(t, m)
	rec := m.HelperCrashState()
	running, looping := m.HelperSupervisorState()
	t.Logf("landed retry: running=%v looping=%v crash=%v recovered=%v restarts=%d",
		running, looping, rec.LastExitWasCrash, rec.RecoveredSinceCrash, rec.Restarts)
	if !running || looping || !rec.LastExitWasCrash || !rec.RecoveredSinceCrash {
		t.Fatalf("landed retry state = running:%v looping:%v record:%+v; want live recovered helper",
			running, looping, rec)
	}
	history, total := m.HelperCrashHistory()
	if total != 0 || len(history) != 0 {
		t.Fatalf("landed retry was journaled before the quiet window: total:%d episodes:%+v",
			total, history)
	}

	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
	rec = m.HelperCrashState()
	if rec.RecoveredSinceCrash {
		t.Fatalf("intentional stop retained the live-recovery marker: %+v", rec)
	}
	// A generation-advancing Compile remains an immediate episode boundary,
	// even after an intentional stop cleared the live-recovery marker.
	m.mu.Lock()
	m.completeHelperCrashRecoveryLocked(time.Now())
	m.mu.Unlock()
	_, total = m.HelperCrashHistory()
	if total != 1 {
		t.Fatalf("Compile recovery history total=%d, want 1", total)
	}
	m.mu.Lock()
	m.completeHelperCrashRecoveryLocked(time.Now())
	m.mu.Unlock()
	_, total = m.HelperCrashHistory()
	if total != 1 {
		t.Fatalf("repeated Compile recovery duplicated the episode: total=%d, want 1", total)
	}
}

// NM-2: an already-running recovered helper is journaled by the existing
// periodic status loop after the quiet window, without requiring another crash.
func TestRecoveredEpisodeJournalsAfterQuietWindowWithoutSecondCrash12159(t *testing.T) {
	oldBase, oldMax, oldInterval := helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval
	helperRestartBackoffBase, helperRestartBackoffMax = 10*time.Millisecond, 64*time.Millisecond
	statusLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval = oldBase, oldMax, oldInterval
	})
	retry := &nmManualRetry12159{}
	m := startNMHelper12159(t, nmPersistentHelper12159, retry.arm)
	killNMSupervisedChild12159(t, m)
	retry.fire(t)
	waitNMSupervisorRunning12159(t, m)

	recovered := m.HelperCrashState()
	if !recovered.RecoveredSinceCrash || recovered.RecoveredAt.IsZero() {
		t.Fatalf("supervisor retry did not establish recovered state: %+v", recovered)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		episodes, total := m.HelperCrashHistory()
		if total > 0 {
			if total != 1 || len(episodes) != 1 {
				t.Fatalf("history after quiet expiry = total:%d episodes:%+v, want one entry",
					total, episodes)
			}
			if !episodes[0].RecoveredAt.Equal(recovered.RecoveredAt) {
				t.Fatalf("journal RecoveredAt=%s, want readiness time %s",
					episodes[0].RecoveredAt, recovered.RecoveredAt)
			}
			if rec := m.HelperCrashState(); rec.LastExitWasCrash || rec.Restarts != 0 {
				t.Fatalf("quiet expiry did not clear the live episode: %+v", rec)
			}
			if running, looping := m.HelperSupervisorState(); !running || looping {
				t.Fatalf("helper state after quiet expiry = running:%v looping:%v; want still running",
					running, looping)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("healthy recovered helper was not journaled after the quiet window without a second crash")
}

const nmFailedRetryAnchorHelper12159 = `#!/usr/bin/python3
import os, socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
counter = os.path.join(os.path.dirname(path), "attempts")
try:
    n = int(open(counter).read())
except Exception:
    n = 0
n += 1
open(counter, "w").write(str(n))
if n == 1 or n == 10:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(4)
    if n == 1:
        while True:
            time.sleep(300)
    time.sleep(0.3)
    os._exit(7)
os._exit(3)
`

func runFailedRetryAnchor12159(t *testing.T, tick time.Duration) {
	t.Helper()
	oldBase, oldMax, oldInterval := helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval
	helperRestartBackoffBase, helperRestartBackoffMax = 10*time.Millisecond, 640*time.Millisecond
	if tick > 0 {
		statusLoopInterval = tick
	} else {
		// Isolate the next-crash path from quiet-window status ticks; the
		// companion subtest exercises the status-tick path explicitly.
		statusLoopInterval = time.Hour
	}
	t.Cleanup(func() {
		helperRestartBackoffBase, helperRestartBackoffMax, statusLoopInterval = oldBase, oldMax, oldInterval
	})

	m := startNMHelper12159(t, nmFailedRetryAnchorHelper12159, func(d time.Duration, fn func()) {
		time.AfterFunc(d, fn)
	})
	m.mu.Lock()
	dir := filepath.Dir(m.cfg.ControlSocket)
	m.mu.Unlock()
	readAttempts := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "attempts"))
		var n int
		_, _ = fmt.Sscanf(string(b), "%d", &n)
		return n
	}

	killNMSupervisedChild12159(t, m)
	sawLoopBeforeLanding, landed := false, false
	var landedAt time.Time
	var postCrash HelperCrashRecord
	var postCrashLooping bool
	var postCrashHistory int
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		attempts := readAttempts()
		running, looping := m.HelperSupervisorState()
		rec := m.HelperCrashState()
		if attempts < 10 && looping {
			sawLoopBeforeLanding = true
		}
		if attempts == 10 && running && rec.RecoveredSinceCrash {
			landed = true
			landedAt = rec.RecoveredAt
		}
		if landed && !running && rec.LastExitWasCrash && rec.At.After(landedAt) {
			postCrash = rec
			postCrashLooping = looping
			_, postCrashHistory = m.HelperCrashHistory()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawLoopBeforeLanding {
		t.Fatal("premise: failed retries never reached crash-loop verdict before landing")
	}
	if !landed {
		t.Fatal("premise: attempt 10 did not become a recovered, running helper")
	}
	if postCrash.At.IsZero() {
		t.Fatal("premise: attempt 10 did not die after landing")
	}
	t.Logf("failed retries then landing: attempts=%d Restarts=%d looping=%v journal=%d",
		readAttempts(), postCrash.Restarts, postCrashLooping, postCrashHistory)
	if postCrash.Restarts != 10 || !postCrashLooping || postCrashHistory != 0 {
		t.Fatalf("failed retries aged out crash-loop state after attempt 10 died: Restarts=%d looping=%v journal=%d, want 10/true/0",
			postCrash.Restarts, postCrashLooping, postCrashHistory)
	}
}

func TestFailedRetriesRefreshCrashQuietWindow12159(t *testing.T) {
	t.Run("crash path", func(t *testing.T) {
		runFailedRetryAnchor12159(t, 0)
	})
	t.Run("status tick path", func(t *testing.T) {
		runFailedRetryAnchor12159(t, 10*time.Millisecond)
	})
}

const nmCountingPersistentHelper12159 = `#!/usr/bin/python3
import os, socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
counter = os.path.join(os.path.dirname(path), "attempts")
try:
    n = int(open(counter).read())
except Exception:
    n = 0
open(counter, "w").write(str(n + 1))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
while True:
    time.sleep(300)
`

func TestSustainedPostReadyCrashLoopIncrementsCounter12159(t *testing.T) {
	oldBase, oldMax := helperRestartBackoffBase, helperRestartBackoffMax
	helperRestartBackoffBase, helperRestartBackoffMax = 10*time.Millisecond, 10*time.Second
	t.Cleanup(func() { helperRestartBackoffBase, helperRestartBackoffMax = oldBase, oldMax })

	// 10ms base, 10s cap: attempt 1 is the immediate retry (#18707), then
	// 10ms*2^(n-2) first reaches 10s at n-2 = 10, i.e. attempt 12.
	capAttempt := helperCrashLoopAttempt()
	if capAttempt != 12 {
		t.Fatalf("backoff cap reached at attempt %d, want attempt 12", capAttempt)
	}
	cycles := capAttempt + 3
	retry := &nmManualRetry12159{}
	m := startNMHelper12159(t, nmCountingPersistentHelper12159, retry.arm)
	waitNMSupervisorRunning12159(t, m)
	m.mu.Lock()
	dir := filepath.Dir(m.cfg.ControlSocket)
	m.mu.Unlock()
	readAttempts := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "attempts"))
		var n int
		_, _ = fmt.Sscanf(string(b), "%d", &n)
		return n
	}
	// With a 10ms base and 10s cap, the quiet window is 20s and the cap
	// starts at attempt 11. Three more manual crash/fire cycles prove exits
	// remain counted after CrashLooping() becomes true, without timer waits.

	var midCount, midEpisodes, midRetained int
	var countedExitAfterLoop bool
	for cycle := 1; cycle <= cycles; cycle++ {
		before := m.HelperCrashState()
		exitsBefore := m.HelperCrashExitCount()
		killNMSupervisedChild12159(t, m)
		exits := m.HelperCrashExitCount()
		rec := m.HelperCrashState()
		_, looping := m.HelperSupervisorState()
		if exits != exitsBefore+1 {
			t.Fatalf("cycle %d counted exits=%d, want previous %d plus one",
				cycle, exits, exitsBefore)
		}
		if rec.Restarts != cycle {
			t.Fatalf("cycle %d restart count=%d, want %d", cycle, rec.Restarts, cycle)
		}
		if looping != rec.CrashLooping() {
			t.Fatalf("cycle %d supervisor loop state=%v, record=%+v",
				cycle, looping, rec)
		}
		if (cycle >= capAttempt) != looping {
			t.Fatalf("cycle %d looping=%v, want %v at cap attempt %d",
				cycle, looping, cycle >= capAttempt, capAttempt)
		}
		if before.CrashLooping() && exits > exitsBefore {
			countedExitAfterLoop = true
		}
		if cycle == cycles/2 {
			midCount = exits
			episodes, total := m.HelperCrashHistory()
			midEpisodes, midRetained = total, len(episodes)
		}
		retry.fire(t)
		waitNMSupervisorRunning12159(t, m)
	}

	starts := readAttempts()
	exits := m.HelperCrashExitCount()
	episodes, total := m.HelperCrashHistory()
	t.Logf("deterministic post-ready loop: starts=%d unexpected exits=%d completed episodes=%d mid-run exits=%d",
		starts, exits, total, midCount)
	if starts != cycles+1 {
		t.Fatalf("helper starts=%d, want %d for %d crash/retry cycles",
			starts, cycles+1, cycles)
	}
	if exits < starts-1 {
		t.Fatalf("unexpected exits=%d for %d starts, want all but at most the final live child",
			exits, starts)
	}
	if exits > starts {
		t.Fatalf("unexpected exits=%d exceeds helper starts=%d", exits, starts)
	}
	if midCount <= 0 || midCount > exits {
		t.Fatalf("counter did not increment monotonically during the loop: mid=%d final=%d", midCount, exits)
	}
	if midEpisodes != 0 || midRetained != 0 || total != 0 || len(episodes) != 0 {
		t.Fatalf("quiet-window ring unexpectedly closed during sustained loop: mid=%d/%d final=%d/%d",
			midEpisodes, midRetained, total, len(episodes))
	}
	if !countedExitAfterLoop {
		t.Fatal("no unexpected exit was counted after CrashLooping() became true")
	}
}
