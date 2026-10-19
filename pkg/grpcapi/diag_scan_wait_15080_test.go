package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #15080 (A43-01): streamDiagCmd blocks on a scanner goroutine parked in an
// unbounded stream.Send, so the diag slot is never released while a
// non-reading client keeps its connection open.
//
// #14980 bounded the handlers' per-line Send via sendDiagFrame, but
// streamDiagCmd itself still waits with no select or bound:
//
//	cmdErr := c.Wait(); pw.Close(); scanErr := <-scanDone
//
// c.Wait() cannot return while the scanner goroutine is parked in sendFn
// (it holds the io.Pipe read end; the child's copy goroutine stays blocked
// in pw.Write), so even a caller whose sendFn only parks until its own
// context is done wedges streamDiagCmd until the full exec timeout —
// and any future/direct caller of streamDiagCmd with a raw Send re-opens
// the indefinite pin. The fix makes that wait select on ctx.Done: on
// cancellation streamDiagCmd pr.Close()es (unblocking the copy goroutine
// and the parked scanner's next read), pw.Close()es, and drains scanDone
// with a bounded wait before returning ctx.Err().
//
// RED on master: the parked-sendFn test below blocks in c.Wait() past its
// watchdog (the child's 10s ctx would eventually rescue it, far past the
// "send-timeout plus slack" acceptance). GREEN post-fix: prompt ctx error.
// The draining control (healthy lines + exit-error final line) must pass
// both before and after.

// parkedSend15080 returns a sendFn that signals entry, then parks until
// release is closed — modelling a scanner goroutine stuck in an unbounded
// stream.Send to a non-reading client.
func parkedSend15080(entered chan<- struct{}, release <-chan struct{}) func(string) error {
	return func(string) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return errors.New("send unblocked after sever")
	}
}

func TestStreamDiagCmd15080CtxCancelUnblocksParkedSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	// Release the parked sendFn at cleanup so a wedged (RED) goroutine can
	// exit instead of leaking into sibling tests.
	t.Cleanup(func() { close(release) })

	done := make(chan error, 1)
	go func() {
		// Long-running child that keeps emitting lines: the scanner reaches
		// sendFn promptly and parks there.
		done <- streamDiagCmd(ctx, 30*time.Second,
			[]string{"sh", "-c", "while true; do echo line; sleep 0.05; done"},
			parkedSend15080(entered, release))
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner never reached the parked sendFn")
	}

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("streamDiagCmd after ctx cancel = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("streamDiagCmd took %v after ctx cancel with a parked send, want prompt return (send bound + slack)", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("streamDiagCmd did not return within 5s of ctx cancel while sendFn parked: " +
			"c.Wait() wedged on the scanner goroutine, diag slot pinned (#15080)")
	}
}

// TestStreamDiagCmd15080SendTimeoutSeversRealPath drives the REAL
// streamDiagCmd with a sendFn wired exactly as Ping wires it (sendDiagFrame
// around a parked Send, limiter release transfer). The per-write sever must
// propagate out of streamDiagCmd promptly and the transferred slot must be
// freed once the parked Send unblocks — the end-to-end #15080 acceptance
// through the same code path the claim cites (scanner goroutine -> Send).
func TestStreamDiagCmd15080SendTimeoutSeversRealPath(t *testing.T) {
	origTimeout := diagStreamSendTimeout
	t.Cleanup(func() { diagStreamSendTimeout = origTimeout })
	diagStreamSendTimeout = 150 * time.Millisecond

	lim := diagcmd.NewLimiter(1)
	release, err := lim.Acquire()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()

	sendRelease := make(chan struct{})
	sendEntered := make(chan struct{}, 1)
	sendFn := func(string) error {
		err, xfer := sendDiagFrame(context.Background(), func() error {
			select {
			case sendEntered <- struct{}{}:
			default:
			}
			<-sendRelease
			return nil
		}, release)
		if xfer {
			transferred = true
		}
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- streamDiagCmd(context.Background(), 2*time.Second,
			[]string{"sh", "-c", "echo hello; sleep 30"}, sendFn)
	}()
	select {
	case <-sendEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("real streamDiagCmd never reached Send")
	}
	start := time.Now()
	select {
	case err := <-done:
		// The per-write sever (150ms) ends the scan first; streamDiagCmd
		// reports that scan error via the scanDone leg.
		if err == nil {
			t.Fatal("streamDiagCmd err = nil, want the sever error from sendFn")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Fatalf("streamDiagCmd severed only after %v, want sever + WaitDelay slack", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("streamDiagCmd did not sever within 10s of a parked Send: scanDone wait wedged (#15080)")
	}
	// The sendFn leg severed at the per-write bound and transferred:
	// slot held while the worker is parked, freed on unblock.
	deadline := time.Now().Add(5 * time.Second)
	for !transferred {
		if time.Now().After(deadline) {
			t.Fatal("sendFn never severed/transferred after streamDiagCmd returned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := lim.InFlight(); got != 1 {
		t.Fatalf("InFlight after sever = %d, want 1 (transferred to parked Send worker)", got)
	}
	close(sendRelease)
	deadline = time.Now().Add(5 * time.Second)
	for lim.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("transferred slot never freed after parked Send unblocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestStreamDiagCmd15080DrainingControlStillPasses is the named adjacent
// control: a healthy child whose lines drain instantly streams every line
// in order, delivers the exit error as the final line, and returns nil —
// unchanged by the bounded scanDone wait.
func TestStreamDiagCmd15080DrainingControlStillPasses(t *testing.T) {
	var lines []string
	err := streamDiagCmd(context.Background(), 30*time.Second,
		[]string{"sh", "-c", "echo one; echo two; exit 3"},
		func(line string) error {
			lines = append(lines, line)
			return nil
		})
	if err != nil {
		t.Fatalf("streamDiagCmd draining control: %v", err)
	}
	if len(lines) != 3 || lines[0] != "one" || lines[1] != "two" || lines[2] != "exit status 3" {
		t.Fatalf("lines = %q, want [one two \"exit status 3\"]", lines)
	}

}
