package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Managed service-file reload debt (#6800).
//
// Two of the daemon's managed-file appliers converge an on-disk service
// configuration and then gate a RUNTIME reload on "did the file set actually
// change":
//
//   - applySyslogFiles     -> reconcileSyslogDropins  -> systemctl restart rsyslog
//   - applySystemNTP       -> reconcileManagedFile    -> chronyc reload sources /
//                                                        systemctl reload chrony
//   - applySSHConfig       -> remove the sshd drop-in -> systemctl reload sshd
//                             (the REMOVAL branch only — see below)
//
// The gate is correct for the steady state — it is what stops every commit from
// bouncing rsyslog — but before this change it also ERASED the debt created by a
// FAILED reload. The write half had already succeeded, so the files were
// converged; the reload half failed, was logged, and dropped. On the next apply
// the reconcile compared desired against the (already converged) on-disk set,
// reported `changed == false`, and skipped the reload. The running daemon kept
// serving the PREVIOUS ruleset — records still flowing to a removed syslog
// destination, or chrony still stepping to the old server set — for as long as
// the operator did not happen to make a FURTHER syslog/NTP edit. A reboot was
// the only reliable recovery, on a node that had reported a successful commit.
//
// The failure is not exotic: `systemctl restart rsyslog` fails whenever the unit
// is in a failed/masked state, whenever the transaction is refused because
// another job is queued on the unit, and whenever the 15s exec timeout expires
// on a loaded box. Each of those is transient — which is exactly why a retry
// owner recovers and a dropped error does not.
//
// The fix is the pattern this repo has settled on for "a failure has no retry
// owner" (proxyARPReassertLoop #4001, raDeadSenderReassertLoop #6793,
// fabricIPVLANReassertLoop #6791): a PERSISTENT debt recording the exact reload
// still owed, consulted by the next apply, plus an always-on re-assert loop
// started unconditionally in Run so recovery does not depend on an operator
// committing again.
//
// The debt retains the OWED REQUEST, not a re-derived one. That distinction is
// load-bearing for chrony, whose runtime reload has two INDEPENDENT legs: a
// sources reload (`chronyc reload sources`) and a threshold reload (`systemctl
// reload chrony`). If apply #1 fails the sources leg and apply #2 changes only
// the threshold file, re-deriving the request from apply #2's own change flags
// would run the threshold leg alone and silently drop the sources debt. Both
// call sites therefore fold the retained debt INTO the request they issue.
//
// sshd is the third instance and the one most easily missed, because half of it
// is already correct. applySSHConfig's UPDATE path reverts the drop-in to its
// prior content when the reload fails (#2062), so the file does NOT stay
// converged and the next apply rewrites-and-reloads on its own — that half has
// a retry owner. The REMOVAL path has nothing to revert TO: the drop-in is
// deleted, the reload then fails, and the next apply reads `hadDropIn == false`
// and returns before reaching a reload. sshd keeps enforcing the xpf policy the
// operator DELETED — a `PermitRootLogin`, cipher or MAC setting that may be more
// permissive than the base-image default — until a manual restart or a reboot.

// serviceReloadDebt is the retained "a runtime reload is still owed" record for
// the xpf-managed service configuration files. The zero value is "nothing
// owed", so a Daemon built as a struct literal (which is how most of this
// package's tests build one) needs no initialisation.
type serviceReloadDebt struct {
	mu sync.Mutex
	// rsyslogRestart: the managed /etc/rsyslog.d/10-xpf-* drop-ins are on disk
	// but `systemctl restart rsyslog` has not succeeded since they were written.
	rsyslogRestart bool
	// chronySources: /etc/chrony/sources.d/xpf.sources is on disk but
	// `chronyc reload sources` has not succeeded since it was written.
	chronySources bool
	// chronyThreshold: /etc/chrony/conf.d/xpf-threshold.conf is on disk but no
	// chrony reload/restart has succeeded since it was written.
	chronyThreshold bool
	// sshdReload: the xpf sshd drop-in has been removed (or rewritten) but
	// `systemctl reload sshd` has not succeeded since, so the running sshd is
	// still enforcing the previous drop-in.
	sshdReload bool

	// Monotonic per-leg failure counts. A gauge stuck at 1 says "not converged";
	// these say whether the retry owner is RUNNING and failing (count climbing)
	// or wedged (count flat) — the distinction #6802 made for its own debt.
	rsyslogFailures         uint64
	chronySourcesFailures   uint64
	chronyThresholdFailures uint64
	sshdFailures            uint64
	// #9073: sshd `-t` VALIDATION failures, counted separately from reload
	// failures on purpose.
	//
	// The reload counters answer "is the retry owner running and failing, or
	// wedged" — climbing vs flat. Under a persistent `sshd -t` failure the
	// owner runs every pass and fails every pass, and `sshdFailures` stayed
	// FLAT, so the metric channel said "wedged" while the box was doing the
	// opposite.
	//
	// Folding validation into sshdFailures was the obvious fix and is wrong.
	// #6800 pinned that count to reload ATTEMPTS in as many words — "a
	// validation failure is not a reload ATTEMPT, so it must not inflate the
	// reload failure count" — and that is a real distinction: a failing reload
	// means systemd or sshd rejected a config that PASSED validation, which is
	// a different fault from a config that never got that far.
	//
	// Three states need three signals, not two states sharing one counter:
	// wedged (both flat), reload failing (sshdFailures climbing), validation
	// failing (this climbing). Overloading one counter would have deleted the
	// distinction #6800 bought while buying the one #9073 asked for.
	sshdValidationFailures uint64
}

// Managed-service identifiers used as the `service` label on the two
// #6800 metric series, and as the keys of the two exported accessors. Named
// constants so the daemon-side accessor and any consumer cannot drift on a
// string literal.
const (
	svcReloadRsyslog         = "rsyslog"
	svcReloadChronySources   = "chrony-sources"
	svcReloadChronyThreshold = "chrony-threshold"
	svcReloadSSHD            = "sshd"
	// #9073: the sshd `-t` validation leg, distinct from the reload leg.
	svcReloadSSHDValidate = "sshd-validate"
)

// noteRsyslogRestartResult records the outcome of one `systemctl restart
// rsyslog`. A failure LATCHES the debt; a success DISCHARGES it. Both
// directions matter: without the latch the failure is forgotten (the #6800
// defect), and without the discharge the re-assert loop would bounce rsyslog
// every tick forever after a single failure.
func (d *Daemon) noteRsyslogRestartResult(err error) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.rsyslogRestart = err != nil
	if err != nil {
		d.svcReloadDebt.rsyslogFailures++
	}
}

// rsyslogRestartOwed reports whether a rsyslog restart is still owed.
func (d *Daemon) rsyslogRestartOwed() bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.rsyslogRestart
}

// chronyReloadOwed reports which chrony reload legs are still owed. The two
// legs are returned separately rather than as one boolean because they drive
// DIFFERENT runtime commands, and collapsing them would make the re-drive
// re-derive a request instead of replaying the owed one.
func (d *Daemon) chronyReloadOwed() (sources, threshold bool) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.chronySources, d.svcReloadDebt.chronyThreshold
}

// noteChronyReloadResult records the outcome of one chrony runtime reload.
//
// Plain assignment is correct — not an OR — because every caller folds the
// outstanding debt into the request it issues (see applySystemNTP and
// reassertServiceReloadDebtOnce), so a leg that was NOT attempted here had no
// debt to preserve, and a leg that WAS attempted is fully described by its
// outcome.
func (d *Daemon) noteChronyReloadResult(out chronyReloadOutcome) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.chronySources = out.sourcesFailed
	d.svcReloadDebt.chronyThreshold = out.thresholdFailed
	if out.sourcesFailed {
		d.svcReloadDebt.chronySourcesFailures++
	}
	if out.thresholdFailed {
		d.svcReloadDebt.chronyThresholdFailures++
	}
}

// ManagedServiceReloadOwed reports, per managed service, whether a runtime
// reload is still owed (#6800). It is the operator-visible half of the fix:
// without it a node can re-drive a failing `systemctl restart rsyslog` for
// hours while every dashboard shows a firewall that committed cleanly, which is
// the same blindness the retry owner was added to end.
//
// Returned as a map because the debt is genuinely per-leg — the two chrony legs
// drive different commands and fail independently — and collapsing them would
// tell an operator that "chrony" is unhappy without saying which reload never
// landed.
func (d *Daemon) ManagedServiceReloadOwed() map[string]bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return map[string]bool{
		svcReloadRsyslog:         d.svcReloadDebt.rsyslogRestart,
		svcReloadChronySources:   d.svcReloadDebt.chronySources,
		svcReloadChronyThreshold: d.svcReloadDebt.chronyThreshold,
		svcReloadSSHD:            d.svcReloadDebt.sshdReload,
	}
}

// ManagedServiceReloadFailures reports the monotonic per-service count of
// failed reload attempts (#6800), including retries. A count that climbs while
// the matching pending gauge stays 1 means the retry owner is running but not
// converging — a masked or failed unit, say — which is operationally a very
// different situation from a single transient failure that was paid on the next
// tick, and the gauge alone cannot distinguish them.
func (d *Daemon) ManagedServiceReloadFailures() map[string]uint64 {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return map[string]uint64{
		svcReloadRsyslog:         d.svcReloadDebt.rsyslogFailures,
		svcReloadChronySources:   d.svcReloadDebt.chronySourcesFailures,
		svcReloadChronyThreshold: d.svcReloadDebt.chronyThresholdFailures,
		svcReloadSSHD:            d.svcReloadDebt.sshdFailures,
		// #9073: a separate series rather than a separate accessor, so it
		// reaches the same Prometheus surface with no new plumbing — the metric
		// is per-service-labelled, and this is one more label value.
		svcReloadSSHDValidate: d.svcReloadDebt.sshdValidationFailures,
	}
}

// noteSSHDValidationFailure records one failed `sshd -t` on the retry path
// (#9073).
//
// It does NOT touch sshdReload: the debt is already outstanding (this arm only
// runs when sshdReloadOwed() is true) and nothing was reloaded, so nothing is
// paid and nothing needs re-latching. It is purely the missing observation.
func (d *Daemon) noteSSHDValidationFailure() {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.sshdValidationFailures++
}

// noteSSHDReloadResult records the outcome of one `systemctl reload sshd`. A
// failure LATCHES the debt; a success DISCHARGES it — including a debt an
// EARLIER removal left behind, because a successful reload means the running
// sshd has re-read the current on-disk configuration whichever apply path drove
// it.
func (d *Daemon) noteSSHDReloadResult(err error) {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	d.svcReloadDebt.sshdReload = err != nil
	if err != nil {
		d.svcReloadDebt.sshdFailures++
	}
}

// sshdReloadOwed reports whether an sshd reload is still owed.
func (d *Daemon) sshdReloadOwed() bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.sshdReload
}

// serviceReloadDebtOutstanding reports whether ANY managed-service reload is
// still owed. It is the re-assert loop's cheap gate: three bools under one
// mutex, so a healthy node pays nothing per tick.
func (d *Daemon) serviceReloadDebtOutstanding() bool {
	d.svcReloadDebt.mu.Lock()
	defer d.svcReloadDebt.mu.Unlock()
	return d.svcReloadDebt.rsyslogRestart ||
		d.svcReloadDebt.chronySources ||
		d.svcReloadDebt.chronyThreshold ||
		d.svcReloadDebt.sshdReload
}

// rsyslogRestartFn is the rsyslog runtime-restart entry point. Both owners —
// the apply path (applySyslogFiles) and the re-assert loop — go through this
// one seam, which is what makes the re-drive assertable without a real systemd.
// It still routes through runCommandTimeout, so a test that stubs the generic
// exec seam observes it too.
var rsyslogRestartFn = func() ([]byte, error) {
	return runCommandTimeout("systemctl", "restart", "rsyslog")
}

// chronyReloadFn is the chrony runtime-reload entry point, shared by the apply
// path and the re-assert loop for the same reason as rsyslogRestartFn.
var chronyReloadFn = reloadChronyRuntime

// serviceReloadDebtReassertInterval paces the managed-service reload retry
// owner. 30s matches proxyARPReassertLoop, raDeadSenderReassertLoop and
// fabricIPVLANReassertLoop — the other always-on self-heal loops. A tighter
// cadence would buy little: the gap this closes is measured in "until the
// operator next edits syslog or NTP", i.e. potentially forever, so turning that
// into tens of seconds is the whole win.
var serviceReloadDebtReassertInterval = 30 * time.Second

// serviceReloadDebtReassertLoop is the retry owner a failed managed-service
// reload did not have (#6800).
//
// Always-on and mode-agnostic, mirroring its sibling loops: it consults only
// the retained debt, so it is free on the overwhelmingly common path (a node
// whose reloads all succeeded owes nothing and the tick returns immediately),
// and it needs no config of its own — the owed request was captured when the
// apply issued it.
func (d *Daemon) serviceReloadDebtReassertLoop(ctx context.Context) {
	t := time.NewTicker(serviceReloadDebtReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertServiceReloadDebtOnce(ctx)
		}
	}
}

// reassertServiceReloadDebtOnce re-drives one round of owed managed-service
// reloads.
//
// It takes applySem BEFORE reading any state the apply path also writes, for
// the reason #4001 gave the proxy-ARP loop: a tick that runs concurrently with
// a commit reads a torn view. Here that is literal — reconcileSyslogDropins is
// mid-way through removing and rewriting /etc/rsyslog.d/10-xpf-*, so a restart
// issued from outside the semaphore can load a HALF-CONVERGED drop-in set and
// then latch a success for it. Blocking behind the in-flight commit means the
// restart always loads a fully converged file set.
//
// The per-service gates below are deliberately read INSIDE the semaphore, and
// they are the only gates that decide anything. The serviceReloadDebtOutstanding
// pre-check is an optimisation OUTSIDE the semaphore — it avoids queueing behind
// a commit for nothing — and its answer is stale by the time the tick is let
// through: a commit that landed in between may already have re-run the reload
// and discharged the debt, and restarting rsyslog again then would be a
// gratuitous bounce of a healthy logging pipeline. Each service therefore
// re-reads its OWN debt under the semaphore, which also keeps one service's
// outstanding reload from dragging the other's healthy one along.
func (d *Daemon) reassertServiceReloadDebtOnce(ctx context.Context) {
	if !d.serviceReloadDebtOutstanding() {
		return // cheap path: nothing owed
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reload.
	}
	defer d.applySem.Release(1)

	if d.rsyslogRestartOwed() {
		slog.Warn("rsyslog restart still owed from an earlier apply — retrying " +
			"(the managed drop-ins are on disk but rsyslog has not re-read them)")
		out, err := rsyslogRestartFn()
		d.noteRsyslogRestartResult(err)
		if err != nil {
			slog.Error("rsyslog restart re-assert failed; will retry",
				"err", err, "output", strings.TrimSpace(string(out)))
		} else {
			slog.Info("rsyslog restart re-asserted")
		}
	}

	// #14693: the sshd debt is NOT paid by reloading whatever is on
	// disk. The update path's reload-failure arm reverts the drop-in
	// to its prior bytes (#2062) AFTER latching this debt, so the disk
	// can hold the pre-hardening (more permissive) policy while the
	// desired config says otherwise. A reload-only retry would make
	// sshd enforce exactly those reverted bytes and then discharge
	// the debt — permanent silent loss of the hardening. Instead the
	// owed state is re-derived from the live config by re-driving the
	// full apply (rewrite the drop-in, `sshd -t`, reload): disk,
	// running sshd and desired converge together, and applySSHConfig
	// itself notes the reload outcome that pays (or re-latches) the
	// debt. The semaphore held here serializes that re-drive with
	// commits; under it the live config IS the config a commit would
	// apply. Only when this process has no store at all (direct unit
	// construction) is there no desired-state authority to re-drive,
	// and the historical validate+reload retry below is kept: there
	// the disk cannot disagree with a desired config, because none
	// exists in-process.
	if d.sshdReloadOwed() {
		if live := d.liveConfig12169(); live != nil {
			// #14693: re-drive the DESIRED config from the live
			// authority; never reload the on-disk bytes as-is (see the
			// block comment above). This also covers the removal debt:
			// a live config with no ssh stanza re-runs the removal
			// apply, which re-removes a drop-in a failed update apply
			// may have restored before validating and reloading.
			slog.Warn("sshd reload still owed from an earlier apply — re-driving " +
				"the desired sshd config (the on-disk drop-in may have been " +
				"reverted by the failed apply, so reloading it as-is would " +
				"enforce the reverted policy)")
			if err := d.applySSHConfig(live); err != nil {
				slog.Error("sshd config re-assert failed; will retry", "err", err)
			} else {
				slog.Info("sshd reload re-asserted")
			}
		} else {
			// No store authority in this process (direct unit
			// construction): no desired config exists here that the
			// disk could disagree with, so keep the historical retry —
			// sshd is VALIDATED before the reload, exactly as the
			// apply path does (#4311): a reload is a SIGHUP, and
			// re-execing into a config that fails `sshd -t` can drop
			// the listener. A validation failure deliberately leaves
			// the debt OUTSTANDING: nothing was reloaded, so nothing
			// is paid.
			slog.Warn("sshd reload still owed from an earlier apply — retrying " +
				"(the drop-in is gone but sshd has not re-read its configuration)")
			if out, err := sshdValidateCmd(); err != nil {
				// #9073: count the failing PASS on its own series; a
				// validation failure is not a reload attempt.
				d.noteSSHDValidationFailure()
				slog.Error("sshd config validation failed; not reloading — will retry",
					"err", err, "output", strings.TrimSpace(string(out)))
			} else if out, err := sshdReloadCmd(); err != nil {
				d.noteSSHDReloadResult(err)
				slog.Error("sshd reload re-assert failed; will retry",
					"err", err, "output", strings.TrimSpace(string(out)))
			} else {
				d.noteSSHDReloadResult(nil)
				slog.Info("sshd reload re-asserted")
			}
		}
	}

	// Replay the exact owed legs. Re-deriving them from the current config
	// would be wrong twice over: it cannot tell which leg failed, and the file
	// it would diff against is already converged.
	if sources, threshold := d.chronyReloadOwed(); sources || threshold {
		slog.Warn("chrony reload still owed from an earlier apply — retrying",
			"sources", sources, "threshold", threshold)
		d.noteChronyReloadResult(chronyReloadFn(sources, threshold))
	}
}
