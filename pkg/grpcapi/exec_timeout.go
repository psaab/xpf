package grpcapi

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Request-path exec bounding (#1805). This mirrors the apply-path helper
// in pkg/daemon/exec_timeout.go (#1794), which is the contract reference
// for the 15s/5s constants. It cannot be imported from pkg/daemon:
// pkg/daemon imports pkg/grpcapi (daemon.go, daemon_run_servers.go), so
// that leg would create an import cycle. The gRPC handlers below
// external-exec on the request path (ps/df/ss/journalctl/chronyc/ntpq/
// timedatectl/tail/ip neigh flush/systemctl); without a bound, a wedged
// binary pins the handler goroutine and its gRPC stream indefinitely.
//
// requestExecTimeout bounds the child process runtime; on expiry the
// process is killed and the error reflects the context deadline.
const requestExecTimeout = 15 * time.Second

// requestExecWaitDelay caps the post-kill pipe-drain window (see the
// WaitDelay rationale in pkg/daemon/exec_timeout.go): without it,
// Output/CombinedOutput block until every inherited write end of the
// output pipe closes, which may be long after the main process dies.
// Hard ceiling per exec becomes 15s+5s=20s.
const requestExecWaitDelay = 5 * time.Second

// Concurrency bounding for request-path diagnostic forks (#6552).
//
// A per-exec TIMEOUT bounds how long ONE fork lives. It does not bound how
// MANY run at once, and the read-only diagnostic topics had no other
// precondition: `ShowText{log}` forked journalctl on nothing but a decodable
// request, and ShowText is on fabricAllowedUnaryMethods with no
// MaxConcurrentStreams on either server, so the amplification was neither
// config-gated nor loopback-bounded. Ping/Traceroute on BOTH surfaces already
// draw a slot from the process-wide MaxConcurrentDiagnostics semaphore
// (#5057); these did not.
//
// The bound is placed so a future caller gets it by DEFAULT: outputTimeout and
// combinedOutputTimeout — the plainly-named helpers a new fork site reaches
// for — now acquire. The unbounded forms carry "Unlimited" in the name, and
// TestNoUnboundedForkOutsideTheDeclaredExemptions6552 fails on any use of one
// outside a written exemption list. A new diagnostic fork is therefore bounded
// unless someone opts out in a way a reviewer can see.
//
// NOT limited, deliberately, and each exempted by name in that test:
//
//   - runTimeout — the deferred systemctl reboot/halt/poweroff and the zeroize
//     `systemctl stop xpfd`. These pass context.Background() precisely because
//     a client disconnect must not cancel a CONFIRMED power action; refusing
//     one because four operators are running `show log` would be a regression,
//     and it is already behind the maintenance authz tier.
//   - the zeroize account teardown (userdel / passwd -l root). Zeroize must
//     run to completion; a half-zeroized box that left root unlocked because
//     the diagnostic semaphore was busy is strictly worse than a slow one.
//   - the ip neigh flush pair. State-changing operator actions behind
//     PermControl, not diagnostics; they are cheap and must not be refused
//     under diagnostic load.
//
// diagLimiter (declared in server_diag_ping.go) is the shared
// diagcmd.DefaultLimiter, so these forks and ping/traceroute — on both the
// gRPC and REST surfaces — contend for one MaxConcurrentDiagnostics budget.

// errDiagBusy reports that the diagnostic concurrency cap was reached before
// the command was forked. It is distinguished from an exec failure so callers
// can answer RESOURCE_EXHAUSTED (retriable) rather than INTERNAL (a bug).
var errDiagBusy = errors.New("diagnostic concurrency limit reached")

// diagExecError maps an error from a limited exec helper onto the right gRPC
// code: RESOURCE_EXHAUSTED for a refused admission, INTERNAL for anything the
// child actually did. Every limited fork site funnels its error through this
// so a load-shed answer is never reported as a server fault.
func diagExecError(what string, err error) error {
	if errors.Is(err, errDiagBusy) {
		return status.Error(codes.ResourceExhausted,
			"diagnostic concurrency limit reached; retry shortly")
	}
	return status.Errorf(codes.Internal, "%s: %v", what, err)
}

// acquireDiagSlot takes a slot from the shared diagnostic semaphore, or
// reports errDiagBusy without forking. Fail-fast rather than queue: a queued
// fork still holds the handler goroutine and its stream, which is the resource
// the cap exists to protect.
func acquireDiagSlot() (func(), error) {
	release, err := diagLimiter.Acquire()
	if err != nil {
		return nil, errDiagBusy
	}
	return release, nil
}

// outputTimeout runs a command under the request-path bound AND the shared
// diagnostic concurrency cap, returning stdout only. Used by sites whose
// stdout feeds user-visible responses directly — a CombinedOutput variant
// would leak stderr into them.
func outputTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	release, err := acquireDiagSlot()
	if err != nil {
		return nil, err
	}
	defer release()
	return outputTimeoutUnlimited(ctx, name, args...)
}

// combinedOutputTimeout runs a command under the request-path bound AND the
// shared diagnostic concurrency cap, returning combined stdout+stderr.
func combinedOutputTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	release, err := acquireDiagSlot()
	if err != nil {
		return nil, err
	}
	defer release()
	return combinedOutputTimeoutUnlimited(ctx, name, args...)
}

// outputTimeoutUnlimited is outputTimeout without the concurrency cap. See the
// exemption list above before using it.
func outputTimeoutUnlimited(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Output()
}

// combinedOutputTimeoutUnlimited is combinedOutputTimeout without the
// concurrency cap. See the exemption list above before using it.
func combinedOutputTimeoutUnlimited(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.CombinedOutput()
}

// runTimeout runs a command under the request-path bound, discarding
// output (wraps cmd.Run()). Used by the deferred power-action
// goroutines, which pass context.Background() — a client disconnect
// must not cancel a confirmed reboot/halt/poweroff — and ignore the
// returned error exactly as the raw .Run() calls did. Deliberately NOT
// concurrency-capped (#6552): see the exemption list above.
func runTimeout(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Run()
}

// Diag-stream budgets (#1819). Ping/Traceroute stream child output and
// legitimately run longer than requestExecTimeout, so they size their
// bound from the request instead of sharing the 15s constant. The same
// formulas live in pkg/api/exec_timeout.go for the HTTP REST siblings
// (pkg/api already imports pkg/grpcapi, so sharing via an exported
// helper would be cycle-free; kept as unexported mirrors by choice —
// see docs/log/9937.md); keep the two copies in sync.

// diagPingPacketInterval is the per-packet budget for ping: the
// handlers do not pass -i, so ping sends one packet per second
// (iputils default). If an interval knob is ever added to the request,
// this constant must become a parameter of pingExecTimeout.
const diagPingPacketInterval = 1 * time.Second

// diagExecSlack absorbs exec/VRF setup, DNS resolution, and the final
// per-packet reply timeout so a fully-successful run never grazes the
// deadline.
const diagExecSlack = 15 * time.Second

// diagPingFloor is the previous hardcoded streamDiagCmd bound. The
// #1819 right-sizing must not tighten any existing budget, so small
// counts keep at least the 30s they had.
const diagPingFloor = 30 * time.Second

// diagExecCeiling caps every request-sized diag budget. The Count
// clamp (≤100 → 115s) keeps well under it today; the ceiling is
// defense-in-depth so a future clamp change cannot let one request pin
// a handler goroutine for minutes.
const diagExecCeiling = 150 * time.Second

// diagTracerouteTimeout bounds gRPC and HTTP traceroute. Neither
// request carries max_ttl, so this is a constant rather than a
// formula; 60s matches the pre-#1819 HTTP bound (the gRPC path was
// 30s — this aligns it without tightening the HTTP side).
const diagTracerouteTimeout = 60 * time.Second

// pingExecTimeout sizes the ping budget from the (already clamped)
// packet count: count × 1s/packet + slack, floored at the previous 30s
// bound and capped at the diag ceiling.
func pingExecTimeout(count int) time.Duration {
	d := time.Duration(count)*diagPingPacketInterval + diagExecSlack
	if d < diagPingFloor {
		d = diagPingFloor
	}
	return clampDiagTimeout(d)
}

// clampDiagTimeout enforces diagExecCeiling on any diag-stream budget;
// streamDiagCmd applies it to whatever the caller passes so no future
// formula can exceed the ceiling.
func clampDiagTimeout(d time.Duration) time.Duration {
	if d > diagExecCeiling {
		return diagExecCeiling
	}
	return d
}

// clampTailLines bounds the request-controlled `tail -n N` line count to
// [1, maxTailLines]. The time bound alone is insufficient here: N is
// attacker/operator-controlled and a huge N against a large log file
// completes well inside 15s while producing an unbounded response
// allocation — the byte exposure must be capped independently of time.
const maxTailLines = 10000

func clampTailLines(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxTailLines {
		return maxTailLines
	}
	return n
}
