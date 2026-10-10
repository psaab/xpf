package daemon

import "log/slog"

// teardownRecoveredFirstCommitBeforeDataplane runs the existing bootstrap
// rollback teardown once managers exist but before dataplane construction and
// startup Apply. That clears abandoned .network/FRR state while keeping the
// #12154 lifeline check in runBootstrapTeardownSteps authoritative. The marker
// remains until the second startup phase also tears down the newly-constructed
// (but never armed) dataplane backend.
//
// It returns true only when the filesystem/FRR teardown converged. A false
// result leaves the durable store marker in place and causes the later phase to
// retry the complete teardown after dataplane construction.
func (d *Daemon) teardownRecoveredFirstCommitBeforeDataplane() bool {
	if d == nil || d.store == nil || !d.store.FirstCommitTeardownOwed() {
		return false
	}
	// A durable FIRST rollback is never permitted to continue a config-driven
	// takeover. loadAndBootstrapConfig classifies the debt as fail-closed, but
	// keep the mode assertion local too so the cleanup stays safe if a caller's
	// boot wiring changes later.
	d.bootstrapMode.Store(true)
	if err := d.enterBootstrapMode(); err != nil {
		slog.Error("durable first-commit rollback teardown is DEGRADED; debt remains for retry",
			"err", err, "issue", "#12155")
		return false
	}
	return true
}

// completeRecoveredFirstCommitTeardown finishes the durable rollback teardown
// after dataplane-setup. When the earlier filesystem/FRR steps succeeded, only
// the backend constructed for this bootstrap boot remains to tear down; when
// they failed, re-run the complete best-effort teardown now that the backend
// exists. Clear the durable debt only after every required step converges.
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
	if err := d.store.ClearFirstCommitTeardown(); err != nil {
		slog.Error("durable first-commit rollback teardown converged but debt marker removal failed; preserving debt for retry",
			"err", err, "issue", "#12155")
	}
}
