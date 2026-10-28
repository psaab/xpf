package grpcapi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/psaab/xpf/pkg/diagcmd"
	"runtime"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestStreamDiagCmdErrTooLongNoLeak is the #5060 fail-on-revert guard for
// the scanner-error path. A child emits a single combined-output line
// larger than the scanner token cap (diagScanMaxToken) with no newline
// and then blocks — bufio.Scanner returns bufio.ErrTooLong and the scan
// goroutine stops reading pr. Before the fix, the scanner-error branch
// (scanDone <- scanner.Err()) closed nothing, so exec.Cmd's internal copy
// goroutine stayed blocked in pw.Write (WaitDelay closes only the
// exec-owned OS pipes, not this io.Pipe), c.Wait() never returned, and the
// RPC + goroutines leaked past the deadline. The fix closes pr and cancels
// on every scanner exit, so streamDiagCmd returns bufio.ErrTooLong
// promptly.
//
// Revert the defer{cancel();pr.Close()} in streamDiagCmd and this test
// fails: streamDiagCmd blocks until at least diagcmd.RequestExecWaitDelay (5s) or
// forever, tripping the 4s watchdog below.
func TestStreamDiagCmdErrTooLongNoLeak(t *testing.T) {
	// 80 KiB of a single character, no newline: comfortably past the
	// 64 KiB diagScanMaxToken cap. The trailing `cat` keeps the child
	// alive after the burst so, on a reverted build, the copy goroutine
	// is genuinely wedged in pw.Write rather than racing a child exit.
	const oversized = diagScanMaxToken + (16 << 10)
	script := fmt.Sprintf("head -c %d /dev/zero | tr '\\0' a; exec cat", oversized)
	cmd := []string{"sh", "-c", script}

	baseline := runtime.NumGoroutine()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- streamDiagCmd(context.Background(), 30*time.Second, cmd,
			func(string) error { return nil })
	}()

	// The fixed path returns in milliseconds. A revert blocks until
	// diagcmd.RequestExecWaitDelay (5s) at best, or forever; a 4s watchdog fails
	// fast on revert instead of stalling the suite for the package
	// timeout.
	watchdog := requestExecWaitDelay - time.Second
	select {
	case err := <-done:
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("streamDiagCmd = %v, want bufio.ErrTooLong on the oversized-line path", err)
		}
		t.Logf("streamDiagCmd returned ErrTooLong in %v", time.Since(start))
	case <-time.After(watchdog):
		t.Fatalf("streamDiagCmd did not return within %v on the scanner-error path: "+
			"child/copy goroutine leaked (pr not closed on scanner.Err())", watchdog)
	}

	// Backstop: the scan goroutine and exec copy goroutine must have
	// exited. Poll briefly for the runtime to settle.
	assertGoroutinesSettle(t, baseline)
}

// assertGoroutinesSettle waits (bounded) for the live goroutine count to
// fall back to the baseline, tolerating a small amount of runtime slack.
func assertGoroutinesSettle(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.Gosched()
		n := runtime.NumGoroutine()
		if n <= baseline+1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak on scanner-error path: baseline=%d now=%d", baseline, n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestDiagFieldLengthRejected pins the #5060 RPC-boundary bound: Ping and
// Traceroute reject an over-length target/source/routing-instance with
// InvalidArgument before it can reach exec or the combined-output line
// scanner. Validation runs before the stream is touched, so a nil stream
// is safe here. Revert the checkDiagArgs calls and this test fails.
func TestDiagFieldLengthRejected(t *testing.T) {
	// #6904: the bound moved to pkg/diagcmd so REST and gRPC share ONE rule.
	// This reads the shared constant rather than a local literal — a test
	// pinned to its own 512 would keep passing while the surfaces drifted,
	// which is the failure this move exists to prevent.
	huge := make([]byte, diagcmd.MaxArgLen+1)
	for i := range huge {
		huge[i] = 'a'
	}
	oversized := string(huge)
	legit := "192.0.2.1"

	s := &Server{}

	pingCases := []struct {
		name string
		req  *pb.PingRequest
	}{
		{"target", &pb.PingRequest{Target: oversized}},
		{"source", &pb.PingRequest{Target: legit, Source: oversized}},
		{"routing-instance", &pb.PingRequest{Target: legit, RoutingInstance: oversized}},
	}
	// #6904: the nil stream is safe only WHILE the bound rejects before the
	// stream is touched. Remove the check — the revert this test exists to
	// catch — and the call proceeds into streamDiag, dereferences nil, and
	// kills the package binary, so the revert reads as a mass crash instead of
	// a named failure and the collected count collapses. Recovering keeps the
	// signal NAMED; a panic here means the bound did not reject, which is the
	// failure this test reports either way.
	callRejects := func(t *testing.T, call func() error) error {
		t.Helper()
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = status.Errorf(codes.Unknown,
						"validation did not reject: reached the stream and panicked (%v)", r)
				}
			}()
			err = call()
		}()
		return err
	}

	for _, c := range pingCases {
		t.Run("ping/"+c.name, func(t *testing.T) {
			err := callRejects(t, func() error { return s.Ping(c.req, nil) })
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Ping oversized %s = %v, want InvalidArgument", c.name, err)
			}
		})
	}

	traceCases := []struct {
		name string
		req  *pb.TracerouteRequest
	}{
		{"target", &pb.TracerouteRequest{Target: oversized}},
		{"source", &pb.TracerouteRequest{Target: legit, Source: oversized}},
		{"routing-instance", &pb.TracerouteRequest{Target: legit, RoutingInstance: oversized}},
	}
	for _, c := range traceCases {
		t.Run("traceroute/"+c.name, func(t *testing.T) {
			err := callRejects(t, func() error { return s.Traceroute(c.req, nil) })
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Traceroute oversized %s = %v, want InvalidArgument", c.name, err)
			}
		})
	}

	// A legitimate short target must still pass validation (it fails
	// later at exec, not at the bound) — assert the bound does not reject
	// it with InvalidArgument.
	if err := checkDiagArgs(legit, "", ""); err != nil {
		t.Fatalf("checkDiagArgs rejected a legitimate target: %v", err)
	}
}
