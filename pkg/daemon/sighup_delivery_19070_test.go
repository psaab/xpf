package daemon

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// #19070: TestIgnoreSIGHUPSurvivesDelivery15084 signalled its own process
// twice and released the ignoreSIGHUP capture straight after. kill(2) returns
// before the signal is handled: for a process-directed signal the kernel may
// pick another thread (a parked main thread, typically) and the handler runs
// when that thread is next scheduled. When the release won that race, the
// late HUP met the default action and killed the test binary with
// "signal: hangup", truncating every pkg/daemon run it hit (10 of 23 full
// runs on loaded runners; 0 of 14 when the binary started with SIGHUP
// ignored, which keeps an inherited SIG_IGN through signal.Stop).

// sighupWarnings19070 counts the capture's "SIGHUP received and ignored"
// records: ignoreSIGHUP logs one per HUP its channel receives, so the count is
// the number of HUPs the capture has consumed.
type sighupWarnings19070 struct{ n atomic.Int64 }

func (h *sighupWarnings19070) Enabled(context.Context, slog.Level) bool { return true }
func (h *sighupWarnings19070) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "SIGHUP received and ignored") {
		h.n.Add(1)
	}
	return nil
}
func (h *sighupWarnings19070) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *sighupWarnings19070) WithGroup(string) slog.Handler      { return h }

func countSIGHUPWarnings19070(t *testing.T) *sighupWarnings19070 {
	t.Helper()
	h := &sighupWarnings19070{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// deliverSIGHUPsUnderCapture19070 installs the ignoreSIGHUP capture, sends n
// real SIGHUPs to this process one at a time, waiting after each until the
// capture has logged it, then releases the capture. It returns how many HUPs
// the capture had observed when it was released. Waiting per kill (not once
// for the burst) matters: two HUPs sent back to back can coalesce into one
// delivery, or the second can arrive while the first is being handled, so a
// count observed after a burst does not prove nothing is still pending.
//
// On a timeout the capture is deliberately left installed: releasing it with
// a HUP possibly still pending is the very hazard this guards against.
func deliverSIGHUPsUnderCapture19070(t *testing.T, seen *sighupWarnings19070, n int) int64 {
	t.Helper()
	stop := ignoreSIGHUP()
	base := seen.n.Load()
	for i := int64(1); i <= int64(n); i++ {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("deliver SIGHUP %d to self: %v", i, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for seen.n.Load()-base < i {
			if time.Now().After(deadline) {
				t.Fatalf("the capture never observed SIGHUP %d of %d (observed %d); leaving it installed",
					i, n, seen.n.Load()-base)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
	observed := seen.n.Load() - base
	stop()
	return observed
}

const sighupDeliveryChild19070Env = "XPF_19070_SIGHUP_DELIVERY_CHILD"
const sighupDeliveryRounds19070 = 200

// TestSIGHUPCaptureReleasedOnlyAfterDelivery19070 runs the #15084 delivery
// sequence sighupDeliveryRounds19070 times in a re-executed copy of this test
// binary, so a regression kills the child, never this binary. Each round must
// release the capture with every HUP it sent observed. The pre-#19070
// sequence (kill, kill, stop) releases with the HUPs typically still
// in flight: that both fails the per-round count and, when a HUP is then
// delivered after the release, kills the child by SIGHUP.
func TestSIGHUPCaptureReleasedOnlyAfterDelivery19070(t *testing.T) {
	if os.Getenv(sighupDeliveryChild19070Env) == "1" {
		seen := countSIGHUPWarnings19070(t)
		for round := 1; round <= sighupDeliveryRounds19070; round++ {
			if got := deliverSIGHUPsUnderCapture19070(t, seen, 2); got != 2 {
				t.Fatalf("round %d: the capture was released having observed %d of 2 SIGHUPs; "+
					"a HUP still in flight then meets the default action (#19070)", round, got)
			}
		}
		return
	}
	const name = "TestSIGHUPCaptureReleasedOnlyAfterDelivery19070"
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run", "^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), sighupDeliveryChild19070Env+"=1")
	out, runErr := cmd.CombinedOutput()
	if ee, ok := runErr.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("the child was killed by %v: a SIGHUP outlived the capture (#19070)\n--- child output ---\n%s", ws.Signal(), out)
		}
	}
	if runErr != nil || !regexp.MustCompile(`(?m)^--- PASS: `+name+` \(`).Match(out) {
		t.Fatalf("the child did not pass (exit: %v)\n--- child output ---\n%s", runErr, out)
	}
}
