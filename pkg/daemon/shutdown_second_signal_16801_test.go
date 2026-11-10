package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var errSentinel16801 = errors.New("run-error-passthrough-16801")

// #16801 (R3-A54-04): runShutdownSequence called the signal context's
// stop() before wg.Wait() and the fail-closed block. signal.Stop
// restores the default disposition, so a second SIGTERM/SIGINT in
// that window killed xpfd before markDataplaneNotArmed closed kernel
// transit, before rg_active was cleared and (HA) before Kea stopped:
// the #10643/#6787 fail-open hazard on a deliberate second stop.
//
// The fix installs guardShutdownSignals at the top of
// runShutdownSequence (before stop()) and releases it on return.
//
// These cells run in a RE-EXECUTED CHILD (XPF_16801_CHILD=1) that
// installs the production seams in Run's order and delivers real
// signals to itself. A regression kills the child, which the parent
// observes as a non-zero exit; the failure cannot be mistaken for
// a pass. The parent asserts the child's stdout markers.
//
// RED on revert: delete the guardShutdownSignals install in
// runShutdownSequence (or the helper) and the child dies at the
// second SIGTERM/SIGINT below; completed-fail-closed=true never
// prints. The SIGHUP control stays green either way (it is #15084's
// separate disposition).

func TestSecondSignalDuringShutdown16801(t *testing.T) {
	if os.Getenv("XPF_16801_CHILD") == "1" {
		runSecondSignalChild16801(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := childCommand16801(t, ctx, exe, "TestSecondSignalDuringShutdown16801", "XPF_16801_CHILD")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second-signal child failed (a second SIGTERM/SIGINT "+
			"during shutdown killed the process before the fail-closed "+
			"sequence completed, #16801): %v\n--- child output ---\n%s",
			err, out)
	}
	for _, want := range []string{
		"control-hup-survived",
		"second-signal-absorbed",
		"completed-fail-closed=true",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("child did not report %q; child output:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "completed-fail-closed=false") {
		t.Fatalf("child reported fail-closed incomplete; output:\n%s", out)
	}
}

// TestGuardShutdownSignalsReleased16801 pins that releasing the
// guard restores the default disposition: after stop, a subsequent
// SIGTERM must take the process down. Proven in a child as well —
// the parent cannot observe its own death. This guards against a
// guard that absorbs forever (never released) masking real stops.
func TestGuardShutdownSignalsReleased16801(t *testing.T) {
	if os.Getenv("XPF_16801_RELEASE_CHILD") == "1" {
		logs := countLogs16801(t, shutdownSignalAbsorbedWarning)
		stop := guardShutdownSignals()
		// Absorbed while installed. #19087: wait until the guard has LOGGED
		// the SIGTERM, not a fixed 150 ms: kill(2) returns before the signal
		// is handled, and a release that won that race let the SIGTERM meet
		// the default action, failing this cell for the wrong reason.
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("deliver SIGTERM while guarded: %v", err)
		}
		waitLogCount16801(t, logs[shutdownSignalAbsorbedWarning], 1, "the guard to absorb the first SIGTERM")
		println16801("guard-absorbed")
		stop()
		stop() // idempotent: must not panic
		println16801("guard-released")
		// Default disposition restored: this SIGTERM must kill us.
		// If it does not, the marker below prints and the parent fails.
		// #19087: the death itself is asynchronous too, so the child waits
		// well past any scheduling delay before claiming it survived.
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("deliver SIGTERM after release: %v", err)
		}
		time.Sleep(10 * time.Second)
		println16801("ERROR-still-alive-after-release")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := childCommand16801(t, ctx, exe, "TestGuardShutdownSignalsReleased16801", "XPF_16801_RELEASE_CHILD")
	out, runErr := cmd.CombinedOutput()
	// The child is EXPECTED to die by SIGTERM after release. A clean
	// exit (or the still-alive marker) means the guard never released.
	if runErr == nil {
		t.Fatalf("child exited cleanly after guard release — a post-release "+
			"SIGTERM was still absorbed (#16801)\n--- child output ---\n%s", out)
	}
	if strings.Contains(string(out), "ERROR-still-alive-after-release") {
		t.Fatalf("child survived SIGTERM after guard release (#16801)\n--- child output ---\n%s", out)
	}
	absorbed := strings.Index(string(out), "guard-absorbed")
	released := strings.Index(string(out), "guard-released")
	if absorbed < 0 || released < absorbed {
		t.Fatalf("child did not reach release in order (%v); output:\n%s", runErr, out)
	}
	// #19087: the death must be the post-release SIGTERM itself, not the
	// parent's deadline kill or a failure exit that happened to follow both
	// markers.
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("child did not run to a signal death: %v\n--- child output ---\n%s", runErr, out)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Fatalf("child ended with %v, want death by the post-release SIGTERM\n--- child output ---\n%s", runErr, out)
	}
}

// runSecondSignalChild16801 executes inside the re-executed binary.
// It is a plain function (not a test body) so the sequence below is
// exactly the production order; assertion failures use t.Fatal but
// death-by-signal is the regression signal the parent watches for.
func runSecondSignalChild16801(t *testing.T) {
	t.Helper()
	// Production order (daemon_run.go Run, then daemon_run_shutdown.go):
	//   stopSIGHUP := ignoreSIGHUP(); defer release
	//   ctx, stop := startupSignalContext(parent)
	//   runShutdownSequence: guard installed; defer release;
	//     ... stop(); wg.Wait(); <fail-closed block>
	logs := countLogs16801(t, sighupIgnoredWarning, shutdownSignalAbsorbedWarning)
	stopSIGHUP := ignoreSIGHUP()
	defer stopSIGHUP()

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	_, stop := startupSignalContext(parent)

	// Positive control: SIGHUP remains a no-op (#15084). Survival of
	// the delivery is the proof; asserted again by the parent marker.
	// #19087: observed, not slept on.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("deliver SIGHUP control: %v", err)
	}
	waitLogCount16801(t, logs[sighupIgnoredWarning], 1, "the #15084 capture to absorb the SIGHUP control")
	println16801("control-hup-survived")

	// Drive the REAL production sequence with a blocked wg: one run
	// goroutine joined on a gate, so the sequence blocks in wg.Wait
	// AFTER its internal stop() call. The fixture is the standalone
	// (non-HA) shape from #10643; seamTransitClose9686 keeps the
	// transit close off host sysctls/nft.
	v4, v6, fake := seamTransitClose9686(t)
	_ = v4
	_ = v6
	_ = fake
	store := commitShutdownFixture9686(t, "system {\n    host-name fw16801;\n}\n")
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	defer cancelDaemon()
	d := &Daemon{store: store, daemonCtx: daemonCtx}
	d.dataplaneArmed.Store(true)

	var wg sync.WaitGroup
	wg.Add(1)
	gate := make(chan struct{})
	go func() {
		defer wg.Done()
		<-gate
	}()

	sentinel := errSentinel16801
	done := make(chan error, 1)
	// #19087: the sequence calls stop() after installing its guard. The
	// wrapper reports that call, so the signals below land in exactly the
	// stop()->return window without a fixed 200 ms sleep.
	stopped := make(chan struct{})
	var stopOnce sync.Once
	observedStop := func() {
		stop()
		stopOnce.Do(func() { close(stopped) })
	}
	go func() { done <- d.runShutdownSequence(context.Background(), &wg, observedStop, sentinel) }()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		t.Fatal("runShutdownSequence did not reach its stop() within 15s")
	}

	// The sequence has called stop() (the default disposition is back for
	// the NotifyContext) and is blocked in wg.Wait() (gate closed). Deliver
	// the second SIGTERM+SIGINT into exactly that window. Pre-fix the
	// default disposition kills this child here and completed-fail-closed
	// never prints. #19087: each is observed absorbed before the next step.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("deliver second SIGTERM: %v", err)
	}
	waitLogCount16801(t, logs[shutdownSignalAbsorbedWarning], 1, "the guard to absorb the second SIGTERM")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("deliver second SIGINT: %v", err)
	}
	waitLogCount16801(t, logs[shutdownSignalAbsorbedWarning], 2, "the guard to absorb the second SIGINT")
	println16801("second-signal-absorbed")

	close(gate)
	select {
	case got := <-done:
		if got != sentinel {
			t.Fatalf("runShutdownSequence returned %v, want sentinel passthrough", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runShutdownSequence did not return within 15s after wg release")
	}
	println16801("completed-fail-closed=true")
}

func println16801(s string) {
	_, _ = os.Stdout.WriteString(s + "\n")
}

// logCount16801 counts slog records by exact message (#19087). The child
// installs it as the default handler, so it sees the capture goroutines'
// warnings: each one means a signal was consumed.
type logCount16801 struct{ counts map[string]*atomic.Int64 }

func (h logCount16801) Enabled(context.Context, slog.Level) bool { return true }
func (h logCount16801) Handle(_ context.Context, r slog.Record) error {
	if c, ok := h.counts[r.Message]; ok {
		c.Add(1)
	}
	return nil
}
func (h logCount16801) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h logCount16801) WithGroup(string) slog.Handler      { return h }

func countLogs16801(t *testing.T, msgs ...string) map[string]*atomic.Int64 {
	t.Helper()
	counts := make(map[string]*atomic.Int64, len(msgs))
	for _, m := range msgs {
		counts[m] = new(atomic.Int64)
	}
	prev := slog.Default()
	slog.SetDefault(slog.New(logCount16801{counts: counts}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return counts
}

// waitLogCount16801 waits until c reaches want; on a timeout it fails the
// child with what it was waiting for, instead of releasing a capture with a
// signal possibly still pending.
func waitLogCount16801(t *testing.T, c *atomic.Int64, want int64, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for c.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s (count %d, want %d)", what, c.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// childCommand16801 re-executes this test binary for one test with env=1.
//
// #19087: R8 saw one child (1 of 220 runs, 16 busy loops on 8 vCPUs) print
// NOTHING, not even the "=== RUN" line, before the 60 s deadline killed it,
// and nothing recorded why. So at the deadline the parent first logs the
// child's /proc state (scheduler state, CPU time used, whether the Go runtime
// had installed its signal handlers yet, wait channel) beside the runner's
// load and CPU pressure, and then sends SIGQUIT instead of SIGKILL: a child
// running Go code prints every goroutine's stack into the captured output. A
// hang in the test is then told apart from a child that never got the CPU to
// start. WaitDelay bounds the dump before exec falls back to SIGKILL.
func childCommand16801(t *testing.T, ctx context.Context, exe, name, env string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, exe, "-test.run", "^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), env+"=1")
	start, cpuAtStart := time.Now(), cpuTicks16801()
	cmd.Cancel = func() error {
		t.Logf("child %s (pid %d) still running %v after start, at the parent's deadline; "+
			"its state before SIGQUIT:%s\n    runner CPU ticks over the child's life: %s",
			name, cmd.Process.Pid, time.Since(start).Round(time.Millisecond),
			procSnapshot16801(cmd.Process.Pid), cpuDelta16801(cpuAtStart, cpuTicks16801(), time.Since(start)))
		return cmd.Process.Signal(syscall.SIGQUIT)
	}
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

// cpuTicks16801 reads the aggregate "cpu" line of /proc/stat (user nice
// system idle iowait irq softirq steal, in USER_HZ ticks summed over CPUs)
// and appends the number of "cpuN" lines, or returns nil when it cannot.
// Steal is the time the hypervisor ran something else while this VM's vCPUs
// wanted to run.
func cpuTicks16801() []uint64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	f := strings.Fields(lines[0])
	if len(f) < 9 || f[0] != "cpu" {
		return nil
	}
	ticks := make([]uint64, 9)
	for i := 0; i < 8; i++ {
		ticks[i], _ = strconv.ParseUint(f[i+1], 10, 64)
	}
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "cpu") {
			ticks[8]++
		}
	}
	return ticks
}

// cpuDelta16801 renders the runner's CPU ticks over the child's life, and the
// share of the CPU time that the elapsed wall time on every CPU should have
// produced (USER_HZ is 100 on Linux). A running VM accounts every tick to
// some state, idle included, so its share is about 100%. A share far below
// that means the VM was not executing for most of the window: paused or
// frozen (a gate cell pauses its same-host runner, #19035) while the guest
// clock kept advancing (#19087). Steal stays 0 across a pause.
func cpuDelta16801(a, b []uint64, elapsed time.Duration) string {
	if len(a) != 9 || len(b) != 9 {
		return "unavailable"
	}
	d := func(i int) uint64 { return b[i] - a[i] }
	var total uint64
	for i := 0; i < 8; i++ {
		total += d(i)
	}
	expected := elapsed.Seconds() * 100 * float64(b[8])
	share := "n/a"
	if expected > 0 {
		share = fmt.Sprintf("%.1f%%", 100*float64(total)/expected)
	}
	return fmt.Sprintf("user=%d nice=%d system=%d idle=%d iowait=%d steal=%d; accounted %d of the %.0f "+
		"ticks %v on %d CPUs should give (%s; far below 100%% = the VM was not executing)",
		d(0), d(1), d(2), d(3), d(4), d(7), total, expected, elapsed.Round(time.Millisecond), b[8], share)
}

// procSnapshot16801 renders the facts that attribute a stalled child: from
// /proc/<pid>/stat the state and utime/stime (fields 3, 14, 15, in clock
// ticks); from status the state, thread count, signal masks (SigCgt is zero
// until the Go runtime installs its handlers, so zero means no Go code ran)
// and context switches; the wait channel; and the runner's loadavg and CPU
// pressure. Read errors are reported in place, never fatal.
func procSnapshot16801(pid int) string {
	var b strings.Builder
	line := func(label, v string) { fmt.Fprintf(&b, "\n    %s: %s", label, v) }
	read := func(path string) (string, error) {
		data, err := os.ReadFile(path)
		return strings.TrimSpace(string(data)), err
	}
	proc := fmt.Sprintf("/proc/%d/", pid)
	if v, err := read(proc + "stat"); err != nil {
		line("stat", err.Error())
	} else if i := strings.LastIndexByte(v, ')'); i >= 0 {
		f := strings.Fields(v[i+1:]) // f[0] is field 3 (state)
		if len(f) > 12 {
			line("stat", fmt.Sprintf("state=%s utime=%s stime=%s (ticks)", f[0], f[11], f[12]))
		} else {
			line("stat", v)
		}
	}
	if v, err := read(proc + "status"); err != nil {
		line("status", err.Error())
	} else {
		for _, l := range strings.Split(v, "\n") {
			for _, k := range []string{"State:", "Threads:", "SigBlk:", "SigIgn:", "SigCgt:",
				"voluntary_ctxt_switches:", "nonvoluntary_ctxt_switches:"} {
				if strings.HasPrefix(l, k) {
					line("status", strings.Join(strings.Fields(l), " "))
				}
			}
		}
	}
	for _, f := range []struct{ label, path string }{
		{"wchan", proc + "wchan"},
		{"loadavg", "/proc/loadavg"},
		{"cpu pressure", "/proc/pressure/cpu"},
	} {
		v, err := read(f.path)
		if err != nil {
			v = err.Error()
		}
		line(f.label, strings.ReplaceAll(v, "\n", " | "))
	}
	return b.String()
}
