package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// #5808: the post-cut helper-readiness gate must keep the deadline AUTHORITATIVE
// across EVERY blocking op — the `systemctl is-active` probe, the control-socket
// status query, and the poll wait — so a wedged systemctl / hung DBus can never
// strand the post-flip cutover past the rollback deadline.

// gateBudget bounds how long a synchronous readiness-gate call may take before
// the test declares a HANG (#5916 Gap 1). The #5808 fix makes the gate return
// at its ~100ms test deadline; the elapsed-time assertions in each test already
// catch a DEADLINE-OVERSHOOT regression (a gate that returns LATE) at 2-5s. This
// budget sits above those (so it never preempts the more specific overshoot
// message) yet well below the suite -timeout, so a loop-ctx-UNBOUNDED regression
// (the gate that NEVER returns) surfaces as a clean bounded t.Fatal here instead
// of a `panic: test timed out` hang.
const gateBudget = 10 * time.Second

// runGateBoundedOrFatal runs a synchronous readiness-gate call (HelperHealthProbe
// / Runner.Run) in a goroutine and t.Fatal's FAST if it does not return within
// gateBudget, so a loop-ctx-unbounded regression fails cleanly rather than
// hanging the suite (#5916 Gap 1). On the normal path it is transparent: it
// returns the gate's error, and the caller's own elapsed/error assertions run
// unchanged. The channel send→receive orders the gate goroutine's writes (e.g. a
// status-timeout recorder) before the caller reads them.
func runGateBoundedOrFatal(t *testing.T, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(gateBudget):
		t.Fatalf("readiness gate did not return within %v — a loop-ctx-unbounded regression would "+
			"strand the post-flip cutover past the deadline (#5916 Gap 1); failing FAST instead of "+
			"hanging to the suite -timeout", gateBudget)
		return nil // unreachable (t.Fatalf ends the test goroutine)
	}
}

// writeFakeSystemctl installs a `systemctl` on PATH that sleeps far longer than
// any test deadline, modelling a wedged is-active / hung DBus. exec.CommandContext
// must KILL it at the deadline.
func writeFakeSystemctl(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fake systemctl relies on a POSIX shell")
	}
	dir := t.TempDir()
	// `exec sleep` REPLACES the shell so the direct child of exec.CommandContext
	// is the sleeper itself (a single process, like the real systemctl binary) —
	// SIGKILL on ctx cancel then closes stdout and unblocks .Output(). A plain
	// `sleep` would leave the sleeper as a grandchild holding the stdout pipe,
	// which is a test-harness artifact, not the production shape.
	script := "#!/bin/sh\nexec sleep 30\n"
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestUnitActive_WedgedSystemctlKilledByDeadline_5808 drives the REAL shared
// primitive (UnitActive -> unitActiveProbeCtx -> exec.CommandContext) against a
// never-returning `systemctl`, and asserts the ctx deadline KILLS it and the
// call returns promptly with the ctx cause.
//
// FAIL-ON-REVERT: revert exec.CommandContext(ctx, ...) to exec.Command(...) and
// the fake sleeps 30s — the call blocks well past the deadline and this test
// hangs to its -timeout (RED).
func TestUnitActive_WedgedSystemctlKilledByDeadline_5808(t *testing.T) {
	writeFakeSystemctl(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	active, err := UnitActive(ctx, "xpfd")
	elapsed := time.Since(start)

	if active {
		t.Fatal("a killed is-active probe must not report active")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a deadline-killed probe must return the ctx cause (errors.Is DeadlineExceeded), got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("UnitActive took %v against a wedged systemctl; the deadline must KILL it (~100ms) — #5808", elapsed)
	}
}

// writeFakeSystemctlInactive installs a `systemctl` that models an INACTIVE unit:
// `systemctl is-active` prints the state word to stdout and EXITS NON-ZERO (3),
// the real systemd contract for inactive/failed/activating (#5916 Gap 2).
func writeFakeSystemctlInactive(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("fake systemctl relies on a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho inactive\nexit 3\n"
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestUnitActive_DefinitiveInactive_5916 covers the branch writeFakeSystemctl's
// wedge case never exercised: an `is-active` NON-ZERO exit (3) with a recognized
// state word on stdout is a DEFINITIVE not-active answer (active=false, err=nil),
// NOT a command failure. It pins the deliberately-added distinction in
// unitActiveProbeCtx (system_linux.go): `errors.As(err, &ee) && state != "" →
// state == "active"`.
//
// FAIL-ON-REVERT: drop the ExitError-with-state branch so an is-active exit-3
// falls through to `return false, err` — UnitActive then returns a non-nil error
// for a plainly-inactive unit and this test REDs.
func TestUnitActive_DefinitiveInactive_5916(t *testing.T) {
	writeFakeSystemctlInactive(t)

	active, err := UnitActive(context.Background(), "xpfd")
	if err != nil {
		t.Fatalf("systemctl is-active exit-3 with a state word (inactive) is a DEFINITIVE answer, "+
			"not a command failure — want (false, nil), got err %v", err)
	}
	if active {
		t.Fatal("an inactive unit must report active=false")
	}
}

// baseDeadlineDeps returns deps whose unit-active + status + exe are all
// injectable seams (no real systemd), with the version-dir tie satisfied.
func baseDeadlineDeps(t *testing.T, statusTimeoutRecorder *time.Duration) HelperHealthDeps {
	t.Helper()
	versions := t.TempDir()
	const target = "9.9.9"
	// The status returns "up but NOT forwarding" so the gate keeps retrying until
	// the deadline — exercising the poll/timeout bounds rather than passing.
	return HelperHealthDeps{
		UnitActive: func(context.Context) (bool, error) { return true, nil },
		Status: func(_ string, timeout time.Duration) (bool, bool, int, error) {
			if statusTimeoutRecorder != nil {
				*statusTimeoutRecorder = timeout
			}
			return true, false, 1, nil // up, not forwarding -> retry
		},
		HelperExe:     func(int) (string, error) { return filepath.Join(versions, target), nil },
		VersionsDir:   versions,
		ControlSocket: "/unused.sock",
	}
}

// TestHelperHealth_StatusTimeoutBoundedByRemaining_5808 pins that a StatusTimeout
// LARGER than the overall deadline is capped to the remaining time, so the
// control-socket query can never run past the deadline.
//
// FAIL-ON-REVERT: pass the raw StatusTimeout (not min(StatusTimeout, remaining))
// and the recorded timeout is 10s, exceeding the deadline -> RED.
func TestHelperHealth_StatusTimeoutBoundedByRemaining_5808(t *testing.T) {
	var recorded time.Duration
	deps := baseDeadlineDeps(t, &recorded)
	deps.StatusTimeout = 10 * time.Second // far larger than the deadline
	deps.PollInterval = 5 * time.Millisecond

	const deadline = 120 * time.Millisecond
	err := runGateBoundedOrFatal(t, func() error { return HelperHealthProbe(deps)("9.9.9", deadline) })
	if err == nil {
		t.Fatal("gate must fail closed (helper not forwarding)")
	}
	if recorded <= 0 || recorded > deadline {
		t.Fatalf("control-socket status timeout = %v; must be capped to <= remaining deadline (%v), "+
			"never the raw 10s StatusTimeout (#5808)", recorded, deadline)
	}
}

// TestHelperHealth_PollDoesNotOvershootDeadline_5808 pins that a poll interval
// LARGER than the remaining time does not delay the gate's return past the
// deadline (context-aware timer, not a blind time.Sleep(poll)).
//
// FAIL-ON-REVERT: restore time.Sleep(poll) and the gate returns after
// deadline + poll (~5s) instead of ~deadline -> RED.
func TestHelperHealth_PollDoesNotOvershootDeadline_5808(t *testing.T) {
	deps := baseDeadlineDeps(t, nil)
	deps.StatusTimeout = 20 * time.Millisecond
	deps.PollInterval = 5 * time.Second // MUCH larger than the deadline

	const deadline = 120 * time.Millisecond
	start := time.Now()
	err := runGateBoundedOrFatal(t, func() error { return HelperHealthProbe(deps)("9.9.9", deadline) })
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("gate must fail closed")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline failure must errors.Is(context.DeadlineExceeded): %v", err)
	}
	if elapsed > deadline+2*time.Second {
		t.Fatalf("gate returned after %v; the poll wait must not overshoot the deadline (%v) by a "+
			"full interval (5s) — #5808", elapsed, deadline)
	}
}

// TestHelperHealth_WedgedProbeReleasedAtDeadline_5808 models a blocking
// unit-active probe (hung DBus) at the seam level: it blocks until the readiness
// ctx is canceled, then returns. The gate must cancel that ctx at the deadline
// (releasing the probe — no leaked goroutine/subprocess) and fail closed with
// the ctx cause.
//
// FAIL-ON-REVERT: without the ctx threaded into checkHelperReady's unit-active
// call, the probe blocks forever and the gate never returns -> hang to -timeout.
func TestHelperHealth_WedgedProbeReleasedAtDeadline_5808(t *testing.T) {
	released := make(chan struct{})
	deps := baseDeadlineDeps(t, nil)
	deps.PollInterval = 5 * time.Millisecond
	deps.UnitActive = func(ctx context.Context) (bool, error) {
		<-ctx.Done() // wedged until the gate cancels at the deadline
		close(released)
		return false, ctx.Err()
	}

	const deadline = 100 * time.Millisecond
	start := time.Now()
	err := runGateBoundedOrFatal(t, func() error { return HelperHealthProbe(deps)("9.9.9", deadline) })
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wedged probe must fail closed at the deadline with the ctx cause, got %v", err)
	}
	if elapsed > deadline+2*time.Second {
		t.Fatalf("gate took %v against a wedged probe; must return by ~deadline (%v) — #5808", elapsed, deadline)
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("wedged unit-active probe was NOT released after the deadline — leaked goroutine/subprocess (#5808)")
	}
}

// TestCutover_WedgedHealthProbeBoundedRollbackAndFence_5808 drives BOTH cutover
// branches end-to-end with the REAL bounded readiness probe wired to a WEDGED
// unit-active seam: the post-flip health check for the new version blocks (hung
// DBus) but is bounded by the deadline, so the standalone flow AUTO-ROLLS-BACK
// and the HA flow (SkipStartHealthRollback) FENCES — both PROMPTLY, never
// stranded past the deadline.
//
// FAIL-ON-REVERT: an unbounded probe would block the post-flip health wait
// forever, stranding the cut past the rollback deadline — the elapsed-time bound
// (and the whole run) would hang to -timeout.
func TestCutover_WedgedHealthProbeBoundedRollbackAndFence_5808(t *testing.T) {
	// wedgedHealthProbe wires the real HelperHealthProbe with a unit-active seam
	// that blocks until the readiness ctx cancels, under a short 100ms deadline
	// (ignoring the cfg's larger StartHealthDeadline to keep the test fast).
	// The wedge applies only to the 2.0.0 probe: since #14721 rollback()
	// also health-probes the rolled-back 1.0.0, and this fixture's point is
	// that a healthy 1.0.0 accepts the rollback promptly.
	healthy := newFakeSystem(t, "1.0.0")
	wedgedHealthProbe := func() func(string, time.Duration) error {
		real := HelperHealthProbe(HelperHealthDeps{
			UnitActive:    func(ctx context.Context) (bool, error) { <-ctx.Done(); return false, ctx.Err() },
			Status:        func(string, time.Duration) (bool, bool, int, error) { return true, true, 1, nil },
			HelperExe:     func(int) (string, error) { return "", nil },
			VersionsDir:   t.TempDir(),
			PollInterval:  5 * time.Millisecond,
			StatusTimeout: time.Second,
		})
		return func(ver string, deadline time.Duration) error {
			if ver != "2.0.0" {
				return healthy.HelperHealthy(ver, deadline)
			}
			return real(ver, 100*time.Millisecond)
		}
	}

	runToUnhealthy2 := func(t *testing.T, opts Options) (err error, elapsed time.Duration, current string) {
		t.Helper()
		fs := newFakeSystem(t, "1.0.0")
		r, cfg := testEnv(t, fs)
		// First cut establishes a healthy 1.0.0 as the rollback target.
		if e := r.Run(Options{AllowNoRollbackFirstCut: true}); e != nil {
			t.Fatalf("first cut to 1.0.0: %v", e)
		}
		// Stage 2.0.0 and make its post-flip health WEDGE (bounded by the probe).
		fs.stagedVersion = "2.0.0"
		for _, b := range managedBins {
			writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
		}
		fs.healthProbe = wedgedHealthProbe()
		start := time.Now()
		err = runGateBoundedOrFatal(t, func() error { return r.Run(opts) })
		elapsed = time.Since(start)
		cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
		return err, elapsed, filepath.Base(cur)
	}

	t.Run("standalone auto-rolls-back promptly", func(t *testing.T) {
		err, elapsed, cur := runToUnhealthy2(t, Options{})
		if err == nil || !strings.Contains(err.Error(), "rolled back to 1.0.0") {
			t.Fatalf("standalone flow must auto-rollback on a wedged post-flip health probe, got %v", err)
		}
		if cur != "1.0.0" {
			t.Fatalf("current=%q after standalone rollback, want 1.0.0", cur)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("standalone Run took %v; a wedged health probe must be deadline-bounded, not "+
				"strand the cut past the rollback deadline (#5808)", elapsed)
		}
	})

	t.Run("HA fences promptly (no auto-rollback)", func(t *testing.T) {
		err, elapsed, cur := runToUnhealthy2(t, Options{SkipStartHealthRollback: true})
		if err == nil || !strings.Contains(err.Error(), "rollback is operator-driven") {
			t.Fatalf("HA flow must FENCE (surface failure, no auto-rollback) on a wedged health probe, got %v", err)
		}
		if cur != "2.0.0" {
			t.Fatalf("current=%q; the HA fenced path leaves the target flipped for operator-driven "+
				"rollback, want 2.0.0", cur)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("HA Run took %v; must be deadline-bounded (#5808)", elapsed)
		}
	})
}
