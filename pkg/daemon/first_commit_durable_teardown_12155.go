package daemon

import "log/slog"

// teardownRecoveredFirstCommitBeforeDataplane runs the existing bootstrap
// rollback teardown once managers exist but before dataplane construction and
// startup Apply. It removes abandoned .network/FRR state and acknowledges the
// required networkd reload while keeping the #12154 lifeline check in
// runBootstrapTeardownSteps authoritative. Durable debt remains until the
// post-dataplane phase tears down the newly-constructed (but never armed)
// backend and all required teardown acknowledgements have converged.
//
// A false result leaves the durable store marker in place and causes the later
// phase to retry the complete teardown after dataplane construction.
func (d *Daemon) teardownRecoveredFirstCommitBeforeDataplane() bool {
	if d == nil || d.store == nil || !d.store.FirstCommitTeardownOwed() {
		return false
	}
	// The durable store marker re-arms downstream reload debt on each startup.
	// Reload is required even when this boot's filesystem scan finds no files:
	// networkd may not have acknowledged a removal from the prior process.
	d.firstCommitNetworkdReloadOwed = true
	d.bootstrapMode.Store(true)
	if err := d.enterBootstrapMode(); err != nil {
		slog.Error("durable first-commit rollback teardown is DEGRADED; debt remains for retry",
			"err", err, "issue", "#12155")
		return false
	}
	return true
}

// completeRecoveredFirstCommitTeardown finishes the durable rollback teardown
// after dataplane-setup. Clear the durable debt only after every required step
// has converged and networkd has acknowledged its reload.
func (d *Daemon) completeRecoveredFirstCommitTeardown(filesystemTeardownDone bool) {
	if d == nil || d.store == nil || !d.store.FirstCommitTeardownOwed() {
		return
	}
	if !filesystemTeardownDone {
		if err := d.enterBootstrapMode(); err != nil {
			slog.Error("durable first-commit rollback teardown is still DEGRADED; preserving debt for the next boot",
				"err", err, "issue", "#12155")
			return
		}
	} else if rt := d.dataplane(); rt != nil {
		if err := rt.Teardown(); err != nil {
			slog.Error("durable first-commit rollback dataplane teardown failed; preserving debt for the next boot",
				"err", err, "issue", "#12155")
			return
		}
	}
	if d.firstCommitNetworkdReloadOwed {
		slog.Error("durable first-commit rollback networkd reload remains unacknowledged; preserving debt for the next boot",
			"issue", "#12155")
		return
	}
	generation := d.store.FirstCommitTeardownGeneration()
	if err := d.store.ClearFirstCommitTeardown(); err != nil {
		slog.Error("durable first-commit rollback teardown converged but debt marker removal failed; preserving debt for retry",
			"err", err, "issue", "#12155")
		return
	}
	d.firstCommitNetworkdReloadOwed = false
	d.clearBootstrapLifelineSnapshot(generation)
}
