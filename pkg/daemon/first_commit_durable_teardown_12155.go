package daemon

import (
	"errors"
	"log/slog"
	"strings"
)

// teardownRecoveredFirstCommitBeforeDataplane runs the existing bootstrap
// rollback teardown once managers exist but before dataplane construction and
// startup Apply. It removes abandoned .network/FRR state, retires host-auth
// state, and acknowledges the required networkd reload while keeping the
// #12154 lifeline check in runBootstrapTeardownSteps authoritative. Durable
// debt remains until the post-dataplane phase tears down the newly-constructed
// (but never armed) backend and all required teardown acknowledgements have
// converged.
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
	// Hazard-B rewire: enterBootstrapMode() hard-wires
	// enterBootstrapModeWithLifeline(false), which would silently skip the
	// durable lifeline restore. The boot consumer explicitly requests it:
	// teardown debt means a FIRST rollback abandoned takeover, so the
	// pre-takeover lifeline must be restored (or DEGRADED if evidence is
	// missing).
	teardownErr := d.enterBootstrapModeWithLifeline(true)
	if teardownErr != nil {
		slog.Error("durable first-commit rollback teardown is DEGRADED; debt remains for retry",
			"err", teardownErr, "issue", "#12155")
	}
	// Load-expired FIRST windows never run executeConfirmedRollback, so they
	// have no #12169 host-auth closeout record. The already-durable #12155
	// teardown marker is the intent: keep it until this retirement, the
	// filesystem teardown, and the post-dataplane acknowledgements converge.
	// This owner is safe to retry after partial progress because credential
	// revocation is provenance-scoped and the closeout reconciles the empty
	// bootstrap config.
	hostAuthErr := d.applyRecoveredFirstCommitHostAuthCloseout()
	if hostAuthErr != nil {
		slog.Error("durable first-commit rollback host-auth retirement is DEGRADED; debt remains for retry",
			"err", hostAuthErr, "issue", "#12621")
	}
	return teardownErr == nil && hostAuthErr == nil
}

// applyRecoveredFirstCommitHostAuthCloseout always reloads sshd after the
// owner pass, even when the managed drop-in is already absent. A process can
// stop after unlinking that file but before reloading sshd; the durable
// #12155 marker makes this unconditional reload repeat on the next boot.
func (d *Daemon) applyRecoveredFirstCommitHostAuthCloseout() error {
	closeoutErr := d.applyBootstrapHostAuthorizationCloseout(nil)
	out, reloadErr := sshdReloadCmd()
	d.noteSSHDReloadResult(reloadErr)
	if reloadErr != nil {
		slog.Error("durable first-commit rollback could not reload sshd; preserving teardown debt for retry",
			"err", reloadErr, "output", strings.TrimSpace(string(out)), "issue", "#12621")
	}
	return errors.Join(closeoutErr, reloadErr)
}

// completeRecoveredFirstCommitTeardown finishes the durable rollback teardown
// after dataplane-setup. Clear the durable debt only after every required step
// has converged and networkd has acknowledged its reload.
func (d *Daemon) completeRecoveredFirstCommitTeardown(filesystemTeardownDone bool) {
	if d == nil || d.store == nil || !d.store.FirstCommitTeardownOwed() {
		return
	}
	if !filesystemTeardownDone {
		teardownErr := d.enterBootstrapModeWithLifeline(true)
		hostAuthErr := d.applyRecoveredFirstCommitHostAuthCloseout()
		if teardownErr != nil || hostAuthErr != nil {
			slog.Error("durable first-commit rollback teardown is still DEGRADED; preserving debt for the next boot",
				"err", errors.Join(teardownErr, hostAuthErr), "issue", "#12155")
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
