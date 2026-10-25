package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
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
	cmd := exec.CommandContext(ctx, exe,
		"-test.run", "^TestSecondSignalDuringShutdown16801$",
		"-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "XPF_16801_CHILD=1")
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
		stop := guardShutdownSignals()
		// Absorbed while installed.
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("deliver SIGTERM while guarded: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
		println16801("guard-absorbed")
		stop()
		stop() // idempotent: must not panic
		println16801("guard-released")
		// Default disposition restored: this SIGTERM must kill us.
		// If it does not, the marker below prints and the parent fails.
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("deliver SIGTERM after release: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
		println16801("ERROR-still-alive-after-release")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe,
		"-test.run", "^TestGuardShutdownSignalsReleased16801$",
		"-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "XPF_16801_RELEASE_CHILD=1")
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
	if !strings.Contains(string(out), "guard-absorbed") ||
		!strings.Contains(string(out), "guard-released") {
		t.Fatalf("child did not reach release in order; output:\n%s", out)
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
	stopSIGHUP := ignoreSIGHUP()
	defer stopSIGHUP()

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	_, stop := startupSignalContext(parent)

	// Positive control: SIGHUP remains a no-op (#15084). Survival of
	// the delivery is the proof; asserted again by the parent marker.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("deliver SIGHUP control: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
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
	go func() { done <- d.runShutdownSequence(&wg, stop, sentinel) }()

	// The sequence is now blocked in wg.Wait() (gate closed) AFTER
	// its internal stop(). Deliver the second SIGTERM+SIGINT into
	// exactly that window. Pre-fix the default disposition kills
	// this child here and completed-fail-closed never prints.
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("deliver second SIGTERM: %v", err)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("deliver second SIGINT: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
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
