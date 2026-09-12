package daemon

import "log/slog"

// CloseKernelTransitForCleanup closes the kernel transit path for `xpfd cleanup`.
//
// #9725: cleanup is the one link writer no observer can cover. It runs in its
// own short-lived process, after xpfd has exited, and `dataplane.Cleanup()`
// unpins and destroys every pinned BPF object — including the shim XDP links a
// HITLESS stop deliberately left attached. That stop left kernel transit open on
// the strength of those links surviving; cleanup then removes them, and there is
// no daemon left to notice. The node is then forwarding transit with nothing
// adjudicating it, and stays that way until an xpfd start re-evaluates the gate.
//
// So cleanup closes the gate itself. It is unconditional and idempotent: after
// cleanup NOTHING adjudicates transit, whatever the knobs happened to say, and
// writing a 0 that is already 0 costs nothing. The barrier goes in first and the
// sysctls second, the same order every closing path uses — either leg alone
// keeps ROUTED transit closed, and bridged frames ignore the sysctls and rely on
// the barrier (#7191).
//
// Failures are logged, not fatal: cleanup is documented as best-effort and its
// callers wrap it in `|| true`, so exiting non-zero here would break deploy
// tooling for a knob the next xpfd start re-evaluates anyway.
func CloseKernelTransitForCleanup() {
	if nftInstaller != nil {
		if err := nftInstaller.InstallTransitBarrier(); err != nil {
			slog.Error("cleanup: failed to install the transit barrier; kernel transit may stay open "+
				"for bridged frames until xpfd starts", "err", err)
		}
	}
	sysctlsVerified := writeTransitForwardSysctls(false)
	slog.Info("cleanup: kernel transit forwarding closed — the pinned dataplane is gone, so nothing "+
		"adjudicates transit until xpfd starts and re-evaluates the gate",
		"sysctls_verified", sysctlsVerified)
}
