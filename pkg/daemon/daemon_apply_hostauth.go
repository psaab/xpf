package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// hostAuthOwner is one security-critical host-authorization reconciler run by
// the #5643/M35 cancel closeout, paired with a stable name so a failure can be
// attributed to a specific owner (lo0 filter, host-inbound filter, login,
// sudoers, absent-user revocation, sshd, root-auth).
type hostAuthOwner struct {
	name string
	fn   func(*config.Config) error
}

// hostAuthOwnerOutcome is one owner's result from the cancel closeout. A nil
// err with timedOut=false means the owner reconciled to the committed state; a
// non-nil err means it reported a reconcile failure; timedOut means the
// closeout budget was exhausted before or while the owner ran, so its
// convergence is UNKNOWN. Both err and timedOut are fail-visible — the cancel
// must not report clean when either is set.
type hostAuthOwnerOutcome struct {
	name     string
	err      error
	timedOut bool
}

// hostAuthCloseoutBudget bounds the TOTAL wall-clock time the #5643/M35 cancel
// closeout may spend reconciling host authorization. It is a backstop against a
// wedged reconciler hanging the daemon-stop path: each external command already
// carries its own 15s(+5s) ceiling (externalCommandTimeout), but the closeout
// fans across two nft loads plus five credential reconcilers, so a per-command
// timeout does not bound the sum. On the cancel path boundedness beats
// completeness — an owner that outruns the budget is reported timed-out (its
// convergence unknown) rather than allowed to block shutdown indefinitely. A
// package var so tests can shrink it. 30s stays well under the daemon-stop
// window while giving a healthy box (every reconcile completes in ms) enormous
// headroom.
var hostAuthCloseoutBudget = 30 * time.Second

// hostAuthCloseoutOwners is the ORDERED list of host-authorization owners the
// cancel closeout reconciles, mirroring applyTailReconciles' step 9.5–13 order
// exactly: the two nft filters first (kernel primary enforcement), then the OS
// login/sudo/absent-user/sshd/root-auth credential reconcilers. Split out as a
// method so a test can assert every owner — especially the five credential
// reconcilers whose failures used to be discarded (#5874) — stays wired in.
func (d *Daemon) hostAuthCloseoutOwners() []hostAuthOwner {
	return []hostAuthOwner{
		{"lo0-filter", d.applyLo0Filter},
		{"host-inbound-filter", d.applyHostInboundFilter},
		{"system-login", d.applySystemLogin},
		{"sudoers", d.reconcileSudoers},
		{"absent-login-users", d.reconcileAbsentLoginUsers},
		{"ssh-config", d.applySSHConfig},
		{"root-auth", d.applyRootAuth},
	}
}

// runHostAuthCloseoutOwners runs each owner in order under a shared wall-clock
// budget and returns a per-owner outcome. Owners run SEQUENTIALLY (the M35
// order is load-bearing) but each in its own goroutine so a wedged owner can be
// bounded by the budget instead of hanging the daemon-stop path. It preserves
// the non-cancellable INTENT — the budget does NOT abort on the first owner
// ERROR (a failed owner is recorded and the next still runs: collect-all-then-
// report). It only stops launching owners once the TOTAL budget is exhausted;
// the remaining owners are then recorded timed-out (never silently skipped).
//
// When an owner outruns the budget its goroutine is abandoned (at most one at a
// time — no further owner is launched concurrently). That is acceptable only on
// the daemon-stop path this serves: every reconciler step is an individually
// atomic durable write, so an abandoned owner leaves consistent partial state
// that is HONESTLY reported timed-out (convergence unknown), the fail-visible
// outcome M35 requires.
//
// Each owner's goroutine carries a defer/recover (#6184): a panic in one owner's
// reconcile is recovered, logged with the owner id, and converted into that
// owner's fail-visible reconcile error (routed through `done`, so the select
// records it as o.err exactly like a returned error). Without the recover an
// owner panic would unwind the goroutine and crash the whole daemon-stop path,
// taking down the remaining owners and the process — the opposite of the M35
// fail-VISIBLE, one-owner-at-a-time discipline. The recover keeps the batch and
// the process alive and surfaces the panicking owner as a named failure.
func runHostAuthCloseoutOwners(cfg *config.Config, budget time.Duration, owners []hostAuthOwner) []hostAuthOwnerOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	outcomes := make([]hostAuthOwnerOutcome, 0, len(owners))
	for _, o := range owners {
		if ctx.Err() != nil {
			// Budget already exhausted — record timed-out WITHOUT launching the
			// owner, so it never runs concurrently with an abandoned one.
			outcomes = append(outcomes, hostAuthOwnerOutcome{name: o.name, timedOut: true})
			continue
		}
		done := make(chan error, 1)
		go func(name string, fn func(*config.Config) error) {
			// #6184: recover a panic in this owner's reconcile so it fails
			// VISIBLE (recorded as this owner's error and joined by
			// summarizeHostAuthCloseout) instead of crashing the daemon-stop
			// path and skipping the remaining owners. `done` is buffered and
			// fn's own send is skipped when it panics, so this is the sole send.
			defer func() {
				if r := recover(); r != nil {
					slog.Error("host-authorization cancel closeout: owner panicked",
						"owner", name, "panic", r)
					done <- fmt.Errorf("host-auth closeout owner %q panicked: %v", name, r)
				}
			}()
			done <- fn(cfg)
		}(o.name, o.fn)
		select {
		case err := <-done:
			outcomes = append(outcomes, hostAuthOwnerOutcome{name: o.name, err: err})
		case <-ctx.Done():
			outcomes = append(outcomes, hostAuthOwnerOutcome{name: o.name, timedOut: true})
		}
	}
	return outcomes
}

// summarizeHostAuthCloseout logs each owner's outcome (fail-visible) and joins
// every failure — a reconcile error OR a budget timeout — into a single error.
// A nil return means every host-authorization owner reconciled to the committed
// config within budget; a non-nil return names WHICH owners did not, and is
// propagated by closeoutHostAuthOnCancel so the cancel fails visibly instead of
// reporting clean over a silently-failed credential reconcile (#5874).
//
// budget is the wall-clock budget the outcomes were produced under — the value
// actually passed to runHostAuthCloseoutOwners — so the timed-out log line
// reports the REAL budget in effect, not the package global (#6184). Production
// passes hostAuthCloseoutBudget; a test that shrinks the budget sees its own
// value in the log instead of a misleading 30s.
func summarizeHostAuthCloseout(outcomes []hostAuthOwnerOutcome, budget time.Duration) error {
	var errs []error
	for _, o := range outcomes {
		switch {
		case o.timedOut:
			slog.Error("host-authorization cancel closeout: owner did not complete within budget",
				"owner", o.name, "budget", budget)
			errs = append(errs, fmt.Errorf("host-auth closeout owner %q timed out", o.name))
		case o.err != nil:
			slog.Error("host-authorization cancel closeout: owner failed to reconcile",
				"owner", o.name, "err", o.err)
			errs = append(errs, fmt.Errorf("host-auth closeout owner %q: %w", o.name, o.err))
		default:
			slog.Debug("host-authorization cancel closeout: owner reconciled", "owner", o.name)
		}
	}
	return errors.Join(errs...)
}

func (d *Daemon) applyHostAuthorizationCloseout(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	outcomes := runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, d.hostAuthCloseoutOwners())
	return summarizeHostAuthCloseout(outcomes, hostAuthCloseoutBudget)
}

// closeoutHostAuthOnCancel wraps a post-promotion apply-abort error so a #2926
// ctx-cancellation still runs the bounded, non-cancellable host-authorization
// closeout before the error propagates (#5643 / M35). Store.Commit promotes the
// config UPSTREAM of applyConfigLocked, so EVERY ctx-cancellation early-return
// inside applyConfigLocked is post-promotion — C1 (in applyVRFReconcile, before
// the netlink phase), C2 (before the dataplane apply), and C3 (before the FRR
// reload) — and each leaves the durable config advanced while the nft/login/
// root-auth host-authorization tail has not run. For a non-cancellation error it
// returns err unchanged, and the healthy (uncancelled) path never calls this, so
// a normal commit's tail is unaffected. Centralizing the guard here keeps all
// three boundaries wired to the same closeout (#5643 Gap B).
func (d *Daemon) closeoutHostAuthOnCancel(err error, cfg *config.Config) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// #9637-D1 (F1-A): the closeout below renders applyHostInboundFilter
		// from the INCOMING config at C1/C2 WITHOUT any ApplyConfig of that
		// config having succeeded — the dataplane still runs the previous
		// snapshot. Clear the reinject-accept gate first so the closeout
		// installs the destination rules WITHOUT the accept (a fresh view
		// address the dataplane never authorized meets the owner-zone deny).
		// At C3 the dataplane MAY already enforce the new snapshot, so this
		// over-refuses until the next successful apply — the fail-closed
		// direction, and the daemon is stopping. Non-cancellation errors
		// return below untouched (ordinary #5679 clears at its own site).
		d.hostInboundDataplaneFresh.Store(false)
		if closeoutErr := d.applyHostAuthorizationCloseout(cfg); closeoutErr != nil {
			return errors.Join(err, closeoutErr)
		}
	}
	return err
}
