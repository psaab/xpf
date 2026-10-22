package factoryreset

import (
	"context"
	"os/exec"
	"time"
)

// Factory-reset exec bound. The wipe's external commands (userdel,
// passwd -l root, systemctl is-active/stop for Kea) must run without a
// diagnostic concurrency cap: a half-zeroized box that left root
// unlocked or tenant leases intact because a diagnostic budget was busy
// is strictly worse than a slow reset. They still carry the request-path
// time bound (15s + 5s WaitDelay) mirrored from pkg/grpcapi's
// exec_timeout.go (#1805/#6552 exemptions, carried over verbatim when the
// wipe moved out of pkg/grpcapi in #16138).
const wipeExecTimeout = 15 * time.Second

const wipeExecWaitDelay = 5 * time.Second

// combinedOutputTimeoutUnlimited runs a command under the wipe exec
// bound without any concurrency cap, returning combined stdout+stderr.
func combinedOutputTimeoutUnlimited(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, wipeExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = wipeExecWaitDelay
	return cmd.CombinedOutput()
}
