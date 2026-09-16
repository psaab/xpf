package api

import (
	"context"
	"os/exec"
	"time"
)

// Request-path exec bounding (#1805). This mirrors the apply-path helper
// in pkg/daemon/exec_timeout.go (#1794), which is the contract reference
// for the 15s/5s constants. It cannot be imported from pkg/daemon:
// pkg/daemon imports pkg/api (daemon_run_servers.go, management.go), so
// that leg would create an import cycle. The pkg/grpcapi leg is not
// cycle-blocked in the api-imports-from-grpcapi direction — pkg/api
// already imports pkg/grpcapi (dhcp.go) — so api importing an exported
// helper from grpcapi would be cycle-free (the reverse would cycle);
// the two sides stay unexported mirrors by choice (see docs/log/9937.md).
// pkg/grpcapi/exec_timeout.go carries the Output/CombinedOutput variants;
// this package's only raw exec sites are the deferred power actions, so
// only the Run variant exists here — add the other variants from
// pkg/grpcapi/exec_timeout.go if a future handler needs command output.

// requestExecTimeout bounds the child process runtime; on expiry the
// process is killed and the error reflects the context deadline.
const requestExecTimeout = 15 * time.Second

// requestExecWaitDelay caps the post-kill pipe-drain window (see the
// WaitDelay rationale in pkg/daemon/exec_timeout.go): without it, Wait
// blocks until every inherited write end of the output pipes closes,
// which may be long after the main process dies. Hard ceiling per exec
// becomes its context timeout + 5s.
const requestExecWaitDelay = 5 * time.Second

// Diag budgets (#1819). The ping/traceroute handlers legitimately run
// longer than requestExecTimeout, so they size their bound from the
// request instead of sharing the 15s constant. These formulas manually
// mirror the diag-stream budget block in pkg/grpcapi/exec_timeout.go —
// no cross-package test enforces equality, so update both
// TestPingExecTimeout tables together; keep the two copies in sync.

// diagPingPacketInterval is the per-packet budget for ping: the
// handlers do not pass -i, so ping sends one packet per second
// (iputils default). If an interval knob is ever added to the request,
// this constant must become a parameter of pingExecTimeout.
const diagPingPacketInterval = 1 * time.Second

// diagExecSlack absorbs exec/VRF setup, DNS resolution, and the final
// per-packet reply timeout so a fully-successful run never grazes the
// deadline.
const diagExecSlack = 15 * time.Second

// diagPingFloor is the previous hardcoded ping bound. The #1819
// right-sizing must not tighten any existing budget, so small counts
// keep at least the 30s they had.
const diagPingFloor = 30 * time.Second

// diagExecCeiling caps every request-sized diag budget. The Count
// clamp (≤100 → 115s) keeps well under it today; the ceiling is
// defense-in-depth so a future clamp change cannot let one request pin
// a handler goroutine for minutes.
const diagExecCeiling = 150 * time.Second

// diagTracerouteTimeout bounds HTTP and gRPC traceroute. Neither
// request carries max_ttl, so this is a constant rather than a
// formula; 60s is the pre-#1819 HTTP bound, kept as the shared value
// when the 30s gRPC path was aligned to it.
const diagTracerouteTimeout = 60 * time.Second

// pingExecTimeout sizes the ping budget from the (already clamped)
// packet count: count × 1s/packet + slack, floored at the previous 30s
// bound and capped at the diag ceiling.
func pingExecTimeout(count int) time.Duration {
	d := time.Duration(count)*diagPingPacketInterval + diagExecSlack
	if d < diagPingFloor {
		d = diagPingFloor
	}
	if d > diagExecCeiling {
		d = diagExecCeiling
	}
	return d
}

// runTimeout runs a command under the request-path bound, discarding
// output (wraps cmd.Run()). Used by the deferred power-action
// goroutines, which pass context.Background() — a client disconnect
// must not cancel a confirmed reboot/halt — and ignore the returned
// error exactly as the raw .Run() calls did.
func runTimeout(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, requestExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = requestExecWaitDelay
	return cmd.Run()
}
