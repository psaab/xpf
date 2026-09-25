package grpcapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Diagnostic RPCs ---

// checkDiagArgs bounds the shared ping/traceroute string fields, delegating to
// diagcmd.CheckArgs so this surface and the REST one cannot drift (#6904).
//
// The bound itself and its reasoning live in pkg/diagcmd next to MaxPingSize:
// this used to hold its own `maxDiagArgLen = 512`, REST held nothing, and the
// asymmetry is what #6904 filed. Only the transport error is local — the RULE
// is shared.
func checkDiagArgs(target, source, routingInstance string) error {
	if err := diagcmd.CheckArgs(target, source, routingInstance); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

// diagLimiter is the aggregate concurrency bound for the gRPC
// ping/traceroute RPCs. It points at the process-wide
// diagcmd.DefaultLimiter so a diagnostic admitted over gRPC and one
// admitted over REST draw from the SAME MaxConcurrentDiagnostics budget
// — a request flood on either surface cannot exhaust host PIDs/FDs/
// goroutines (#5057). It is a package var so a test can swap in a fresh
// limiter without mutating global state.
var diagLimiter = diagcmd.DefaultLimiter

// streamDiag is the diagnostic command runner used by Ping/Traceroute.
// It is a package var so a test can inject a fake slow diagnostic and
// exercise the concurrency limiter without spawning real ping/traceroute
// subprocesses. It defaults to streamDiagCmd.
var streamDiag = streamDiagCmd

func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := checkDiagArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		return err
	}
	count := diagcmd.ClampPingCount(int(req.Count))

	// Aggregate concurrency bound (#5057): acquire a diagnostic slot
	// before spawning any child. Fail-fast with RESOURCE_EXHAUSTED when
	// the cap is reached so a request flood is rejected immediately
	// instead of piling up processes/FDs/goroutines/streams. Release on
	// EVERY path via defer (success, exec error, ctx timeout/cancel).
	release, err := diagLimiter.Acquire()
	if err != nil {
		return status.Error(codes.ResourceExhausted,
			"diagnostic concurrency limit reached; retry shortly")
	}
	defer release()

	cmd := buildPingArgv(req, count)

	return streamDiag(stream.Context(), pingExecTimeout(count), cmd, func(line string) error {
		return stream.Send(&pb.PingResponse{Output: line})
	})
}

// buildPingArgv builds the argv for the gRPC Ping diag. It delegates to
// the shared diagcmd builder so the VRF-device normalization (apply
// "vrf-" exactly once, #2143) and the "--" end-of-options separator
// (option-confusion hardening, #2084) match the CLI and REST surfaces
// byte-for-byte. count is the already-clamped probe count.
func buildPingArgv(req *pb.PingRequest, count int) []string {
	size := ""
	if req.Size > 0 {
		// Clamp the payload to the max valid ICMP echo data (#5250 A8-b1
		// F4): an operator-supplied -s above diagcmd.MaxPingSize could never
		// yield a valid probe, so cap it here rather than hand the ping child
		// a value it would reject. Mirrors the REST buildPingArgv.
		s := req.Size
		if s > diagcmd.MaxPingSize {
			s = diagcmd.MaxPingSize
		}
		size = fmt.Sprintf("%d", s)
	}
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          req.Target,
		Count:           fmt.Sprintf("%d", count),
		Source:          req.Source,
		Size:            size,
		RoutingInstance: req.RoutingInstance,
	})
}

func (s *Server) Traceroute(req *pb.TracerouteRequest, stream grpc.ServerStreamingServer[pb.TracerouteResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	if err := checkDiagArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		return err
	}

	// Aggregate concurrency bound (#5057): see Ping. One shared limiter
	// covers ping AND traceroute across gRPC and REST.
	release, err := diagLimiter.Acquire()
	if err != nil {
		return status.Error(codes.ResourceExhausted,
			"diagnostic concurrency limit reached; retry shortly")
	}
	defer release()

	cmd := buildTracerouteArgv(req)

	return streamDiag(stream.Context(), diagTracerouteTimeout, cmd, func(line string) error {
		return stream.Send(&pb.TracerouteResponse{Output: line})
	})
}

// buildTracerouteArgv builds the argv for the gRPC Traceroute diag.
// Like buildPingArgv it delegates to the shared diagcmd builder so VRF
// normalization (#2143) and the "--" separator (#2084) stay identical
// across the CLI, REST, and gRPC surfaces.
func buildTracerouteArgv(req *pb.TracerouteRequest) []string {
	return diagcmd.TracerouteArgv(diagcmd.TracerouteOptions{
		Target:          req.Target,
		Source:          req.Source,
		RoutingInstance: req.RoutingInstance,
	})
}

// diagScanInitToken / diagScanMaxToken size the combined-output line
// scanner in streamDiagCmd. The max is set explicitly (rather than
// relying on the bufio default) to make the per-line ceiling a
// deliberate, documented bound: a line beyond it is a controlled
// bufio.ErrTooLong that the streamDiagCmd cleanup path reaps without
// leaking the child or scan goroutine (#5060). Diag output lines are
// short, so 64 KiB is generous.
const (
	diagScanInitToken = 4 << 10  // 4 KiB initial scanner buffer
	diagScanMaxToken  = 64 << 10 // 64 KiB hard per-line cap
)

// streamDiagCmd runs a command and streams each line of combined output
// via sendFn. timeout is request-sized by the caller (#1819, see the
// diag-stream budget block in exec_timeout.go); it is always capped at
// diagExecCeiling so a pathological request cannot pin the handler.
func streamDiagCmd(ctx context.Context, timeout time.Duration, cmd []string, sendFn func(string) error) error {
	ctx, cancelTimeout := context.WithTimeout(ctx, clampDiagTimeout(timeout))
	defer cancelTimeout()
	// Cancelable layer for the send-failure path: when sendFn fails the
	// scanner goroutine stops reading the pipe, so without an explicit
	// cancel the child would block on writes until the deadline killed
	// it — cancel here makes CommandContext kill it promptly (#1819).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	// U3 parity (#1805): cap the post-kill pipe-drain window so a child
	// that inherited the output pipe cannot block Wait past the ctx kill.
	c.WaitDelay = requestExecWaitDelay

	// Merge stdout and stderr into a single pipe.
	pr, pw := io.Pipe()
	c.Stdout = pw
	c.Stderr = pw

	if err := c.Start(); err != nil {
		return status.Errorf(codes.Internal, "exec: %v", err)
	}

	// Scan lines and stream each one.
	scanner := bufio.NewScanner(pr)
	// Bound the per-line token deliberately (#5060): a combined-output
	// line longer than diagScanMaxToken is a controlled bufio.ErrTooLong,
	// not an unbounded allocation.
	scanner.Buffer(make([]byte, 0, diagScanInitToken), diagScanMaxToken)
	scanDone := make(chan error, 1)
	go func() {
		// Own and close BOTH pipe ends on EVERY exit path — the
		// send-failure path AND the scanner-error/EOF path (#5060).
		// Whenever the scanner stops reading pr (a sendFn failure, or a
		// scanner error such as bufio.ErrTooLong from a line beyond
		// diagScanMaxToken), exec.Cmd's internal copy goroutine can be
		// blocked in pw.Write; WaitDelay closes only the exec-owned OS
		// pipes, not this io.Pipe, so without pr.Close() that write
		// never returns, c.Wait() below never returns, and the RPC plus
		// this goroutine leak past the deadline. pr.Close() makes the
		// blocked write return ErrClosedPipe; cancel() kills the child
		// promptly. Both are idempotent and harmless on the normal EOF
		// path — pr is already drained and the child already exited.
		// (Codex review on PR #1823 established the send-failure half;
		// #5060 extends it to the scanner-error path.)
		defer func() {
			cancel()
			_ = pr.Close()
		}()
		for scanner.Scan() {
			if err := sendFn(scanner.Text()); err != nil {
				scanDone <- err
				return
			}
		}
		scanDone <- scanner.Err()
	}()

	// Wait for the command to finish, then close the write end so scanner terminates.
	cmdErr := c.Wait()
	pw.Close()
	scanErr := <-scanDone

	if scanErr != nil {
		return scanErr
	}
	if cmdErr != nil {
		// Send the exit error as a final line rather than failing the RPC,
		// so the client still sees partial output (e.g. "ping: unknown host").
		_ = sendFn(cmdErr.Error())
	}
	return nil
}
