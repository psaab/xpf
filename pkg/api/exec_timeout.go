package api

import (
	"context"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// Request-path exec bounding (#1805, #17203). The budget constants and
// the Run helper live in pkg/diagcmd (diagcmd.RequestExecTimeout /
// RequestExecWaitDelay / RunTimeout) — the sole implementation shared
// by this package, pkg/grpcapi, and the remote CLI. They mirror the
// apply-path contract in pkg/daemon/exec_timeout.go (#1794), which
// remains the contract reference for the 15s/5s values; pkg/daemon
// cannot be imported here (it imports pkg/api). The diag ping /
// traceroute budgets likewise live in diagcmd (PingExecTimeout,
// TracerouteTimeout, DiagExecCeiling — #1819, #15235).

// Aliases so existing package-local call sites and tests keep their
// short names while diagcmd owns the values.
const (
	requestExecTimeout   = diagcmd.RequestExecTimeout
	requestExecWaitDelay = diagcmd.RequestExecWaitDelay
)

func runTimeout(ctx context.Context, name string, args ...string) error {
	return diagcmd.RunTimeout(ctx, name, args...)
}
