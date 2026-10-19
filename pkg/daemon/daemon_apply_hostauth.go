package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
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
// carries its own 15s(+5s WaitDelay)=20s hard ceiling (externalCommandTimeout,
// exec_timeout.go), but the closeout fans across two nft loads plus five
// credential reconcilers, so a per-command timeout does not bound the sum. On
// the cancel path boundedness beats completeness — an owner that outruns the
// budget is reported timed-out (its convergence unknown) rather than allowed to
// block shutdown indefinitely. A package var so tests can shrink it. 30s stays
// well under the daemon-stop window while giving a healthy box (every
// reconcile completes in ms) enormous headroom. (The 20s figure sometimes
// quoted for this budget is the per-command ceiling above, not this 30s total.)
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
// time — no further owner is launched concurrently). Since #14356 this
// abandonment ALSO happens on live post-promotion aborts — NOT only on the
// daemon-stop path: the closeout returns, applySem is released, and the stale
// owner keeps running with its captured config. That is exactly why the
// #14969 generation fence (extended to every write/install seam by #15539)
// exists: every reconciler step is an individually atomic durable write, the
// abandoned owner is fenced at its next seam once a newer authority begins,
// and its state is HONESTLY reported timed-out (convergence unknown), the
// fail-visible outcome M35 requires.
//
// Each owner's goroutine carries a defer/recover (#6184): a panic in one owner's
// reconcile is recovered, logged with the owner id, and converted into that
// owner's fail-visible reconcile error (routed through `done`, so the select
// records it as o.err exactly like a returned error). Without the recover an
// owner panic would unwind the goroutine and crash the whole daemon-stop path,
// taking down the remaining owners and the process — the opposite of the M35
// fail-VISIBLE, one-owner-at-a-time discipline. The recover keeps the batch and
// the process alive and surfaces the panicking owner as a named failure.
// hostAuthGeneration14969 is the monotonic host-auth authority token
// (#14969). Every closeout invocation and every normal apply tail
// advances it at entry (beginHostAuthAuthority14969). An owner launched
// by the closeout runner captures the current value and runs under it
// via runWithHostAuthGeneration14969 (hostauth_fence_14969.go), which
// publishes the captured generation for the calling goroutine; every
// host-mutation seam re-checks it and refuses once a newer authority
// has advanced the token. The zero generation (no runner capture —
// direct reconciler calls, the normal tail) is never stale, preserving
// stand-alone behavior exactly.
var hostAuthGeneration14969 atomic.Uint64

// beginHostAuthAuthority14969 advances the host-auth generation. Called
// at every host-auth authority entry: each closeout invocation and each
// normal apply tail's host-auth section.
func beginHostAuthAuthority14969() uint64 {
	return hostAuthGeneration14969.Add(1)
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
// time — no further owner is launched concurrently). #12169 fences the
// credential revocations such an owner can still perform (live-config
// re-reads + applySem settlement). #14969 fences the remainder — the two nft
// owners and every unfenced owner phase — with the generation token: each
// owner is wrapped so its host-mutation seams (nft Install/Delete, the
// credential exec seam, the sshd drop-in write/remove seams) re-check the
// generation it was launched under; once a newer host-auth authority has
// begun (a later closeout or a normal apply tail) the stale owner's next
// seam refuses and it abstains instead of overwriting the newer commit.
// A stale seam that passed before the newer authority began is ordered
// before it and is overwritten by the newer authority's own seam. The
// fence never blocks a later commit (the #12169 contract).
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
	gen := beginHostAuthAuthority14969()
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
			done <- runWithHostAuthGeneration14969(gen, func() error { return fn(cfg) })
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
// propagated by closeoutHostAuthOnPostPromotionError so the error fails visibly instead of
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

// applyBootstrapHostAuthorizationCloseout retires the abandoned config's
// host-auth state while the daemon returns to bootstrap. The early input guard
// is a bootstrap invariant, not an abandoned-config artifact: re-arm it before
// any nft owner runs. If that guard cannot be installed, retain both existing
// nft tables (rather than weakening protection) but still run every credential
// owner, whose revocation is provenance-scoped.
func (d *Daemon) applyBootstrapHostAuthorizationCloseout(cfg *config.Config) error {
	if cfg == nil {
		cfg = &config.Config{}
	}
	guardErr := d.rearmEarlyInputBootstrapGuard()
	owners := d.hostAuthCloseoutOwners()
	if guardErr != nil {
		credentialOwners := make([]hostAuthOwner, 0, len(owners))
		for _, owner := range owners {
			if owner.name != "lo0-filter" && owner.name != "host-inbound-filter" {
				credentialOwners = append(credentialOwners, owner)
			}
		}
		owners = credentialOwners
	}
	outcomes := runHostAuthCloseoutOwners(cfg, hostAuthCloseoutBudget, owners)
	return errors.Join(guardErr, summarizeHostAuthCloseout(outcomes, hostAuthCloseoutBudget))
}

// closeoutHostAuthOnPostPromotionError wraps a post-promotion apply error so
// the bounded, non-cancellable host-authorization closeout still runs before
// the error propagates (#5643 / M35, extended by #14356 to non-cancellation
// aborts, including the reopened earliest returns). Store.Commit promotes
// the config UPSTREAM of applyConfigLocked, so EVERY error return inside
// applyConfigLocked — the pre-handoff guard
// (requireEarlyInputProtectionPreApply), the pre-networkd fence install
// (applyHostInboundPreNetworkdAddressFence), C1 (in applyVRFReconcile,
// before the netlink phase), C2 (before the dataplane apply), C3 (before
// the FRR reload), the compile-abort and ancestry-refusal returns inside
// applyDataplaneAndHACore, and the bootstrap-exit / config-arrival naming
// refusals — is post-promotion and leaves the durable config advanced
// while the nft/login/root-auth host-authorization tail has not run.
// Running the closeout enforces the committed tightening (lo0 /
// host-inbound filters + OS credentials) even when the dataplane or
// takeover step cannot proceed; the healthy (successful) path never calls
// this, so a normal commit's tail is unaffected and never double-runs.
// Centralizing here keeps every post-promotion boundary wired to the same
// closeout. The host-inbound owner re-invokes the pre-handoff guard at
// its own top, so on the earliest guard-refusal path that owner fails
// visibly in the joined error while the lo0 and credential owners still
// run; the fence-install path's helper has already recorded staleness,
// and this wrapper records it again if a fence spec is still retained
// after the closeout.
//
// Fail-closed rendering: the closeout renders applyHostInboundFilter from
// the INCOMING config WITHOUT any ApplyConfig of that config having
// succeeded on the abort paths — the dataplane still runs the previous
// snapshot. Clear the reinject-accept gate first so the closeout installs
// the destination rules WITHOUT the accept (a fresh view address the
// dataplane never authorized meets the owner-zone deny). Where the
// dataplane MAY already enforce the new snapshot (C3) this over-refuses
// until the next successful apply — the fail-closed direction.
//
// Preactivation fence: applyHostInboundPreNetworkdAddressFence may have
// installed the xpf_hostinbound_preactivation drop fence earlier in this
// same apply. The closeout's real host-inbound install retires it on
// success (applyHostInboundFilterWithOverlay deletes the table and clears
// hostInboundPreActivationFence). When the fence is still standing after
// the closeout, record staleness so the applied state never claims
// currency behind a stranded temporary fence.
func (d *Daemon) closeoutHostAuthOnPostPromotionError(err error, cfg *config.Config) error {
	if err == nil {
		return nil
	}
	d.hostInboundDataplaneFresh.Store(false)
	closeoutErr := d.applyHostAuthorizationCloseout(cfg)
	if d.hostInboundPreActivationFence != nil {
		d.noteHostInboundApplyFailed(time.Now())
	}
	if closeoutErr != nil {
		return errors.Join(err, closeoutErr)
	}
	return err
}
