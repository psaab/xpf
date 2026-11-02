// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// setRethIPv6Knobs writes the per-interface IPv6 procfs knobs for a RETH
// member: disable DAD (the virtual MAC may still collide with the peer on
// some deployments) and suppress kernel-generated link-locals (which else
// trigger continuous MLDv2 reports on the L2 segment; VIPs are managed
// explicitly). BestEffortKernelKnob writes go through
// fsatomic.WriteKernelKnob (#17068): read-compare-write with the error
// surfaced as a warning instead of silently discarded. Deliberately
// daemon-lifetime posture: expressed by writing through WriteKernelKnob
// WITHOUT registering with the KernelKnobs registry (which has no
// keep-forever policy), because the interface is daemon-created and its
// knobs are re-asserted on every apply.
func setRethIPv6Knobs(iface string) {
	dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", iface)
	if _, err := fsatomic.WriteKernelKnob(dadPath, "0"); err != nil {
		slog.Warn("failed to set accept_dad", "path", dadPath, "err", err)
	}
	addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	if _, err := fsatomic.WriteKernelKnob(addrGenPath, "1"); err != nil {
		slog.Warn("failed to set addr_gen_mode", "path", addrGenPath, "err", err)
	}
}

// setVLANSubAddrGenMode suppresses kernel-generated link-locals on a VLAN
// sub-interface (addr_gen_mode=1). Same #17068 treatment as
// setRethIPv6Knobs.
func setVLANSubAddrGenMode(iface string) {
	subAddrGen := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	if _, err := fsatomic.WriteKernelKnob(subAddrGen, "1"); err != nil {
		slog.Warn("failed to set addr_gen_mode", "path", subAddrGen, "err", err)
	}
}

// stampActiveAppliedIfConvergedUnderSem stamps the CURRENT active config
// applied (#4957) only when the apply the caller just drove under applySem
// fully converged: no apply error, no outstanding policy-invalidation debt,
// and the snapshot publication landed. The caller MUST hold d.applySem; the
// …UnderSem suffix is the contract — stamping outside the semaphore would
// let a competing promotion inherit this apply's success (the #6296 TOCTOU
// and the #9175 re-promotion fail-open). The helper owns the nil-store
// check so no shape-(a) call site can forget it. Returns whether it stamped.
func (d *Daemon) stampActiveAppliedIfConvergedUnderSem(err error) bool {
	if err != nil || d.store == nil || d.policyInvalidationDebt != nil ||
		!d.policyInvalidationPublishLanded {
		return false
	}
	d.store.MarkActiveApplied()
	return true
}

// stampDigestIfConvergedUnderSem is the captured-digest sibling of
// stampActiveAppliedIfConvergedUnderSem (#6296): it stamps the digest the
// caller captured under applySem for the exact tree it applied, gated on
// the same convergence formula (no apply error, no outstanding
// policy-invalidation debt, publication landed). The caller MUST hold
// d.applySem. An empty digest is a no-op (nothing was captured/applied),
// mirroring Store.MarkAppliedDigest. Returns whether it stamped.
//
// Deliberately NOT used by the policy-debt discharge sites
// (dischargePolicyInvalidationDebtLocked, completeDeferredSnapshotApply,
// resolveDeferredSnapshotApplyAfterSynchronousPublish,
// retirePolicyInvalidationScanDebtAfterFullClearLocked) or the #9811
// digest-retry site: those callers nil / settle the debt themselves (or,
// for the retry, deliberately omit the PublishLanded term because
// applyConfigLocked has already settled publication) immediately before
// stamping, so folding them into this PublishLanded gate would change
// debt-discharge semantics. They keep their own explicitly-gated
// MarkAppliedDigest calls, allowlisted by name in the stamp canary.
func (d *Daemon) stampDigestIfConvergedUnderSem(err error, digest string) bool {
	if err != nil || digest == "" || d.store == nil ||
		d.policyInvalidationDebt != nil || !d.policyInvalidationPublishLanded {
		return false
	}
	d.store.MarkAppliedDigest(digest)
	return true
}

// applyConfig applies a compiled config to the dataplane / kernel.
// Wraps applyConfigLocked under the apply semaphore for non-request
// callers (DHCP callbacks, config-poll, dynamic feeds, event engine,
// in-process CLI commits, CLI auto-rollback, cluster sync recv). A
// shutdown fence cancels only its admission wait; after admission, the
// apply runs to completion.
//
// #846: HTTP/gRPC commit handlers go through commitAndApply /
// commitConfirmedAndApply instead, which take the same semaphore
// with a request-bound context so a slow lock holder surfaces 503
// to the client rather than hanging the request.
func (d *Daemon) applyConfig(cfg *config.Config) {
	cfg = d.resolveDNSBeforeApply(cfg)
	defer d.consumeDNSResolved(cfg)
	if !d.beginBackgroundApply(d.backgroundApplyCtx(), "applyConfig") {
		return
	}
	defer d.applySem.Release(1)
	d.applyConfigUnderSem(cfg)
}

// fenceBackgroundApplies latches the #6788 background-apply fence. Called once
// by runShutdownSequence, at the very start and BEFORE the in-flight cancel and
// the apply drain, so the drain is the LAST apply this process performs. Never
// cleared: the process is exiting.
func (d *Daemon) fenceBackgroundApplies() {
	d.applyFenced.Store(true)
	if d.backgroundApplyCancel != nil {
		d.backgroundApplyCancel()
	}
}

// applyFencedForBackground reports whether background config applies are fenced
// (see Daemon.applyFenced).
func (d *Daemon) applyFencedForBackground() bool { return d.applyFenced.Load() }

// backgroundApplyCtx is the daemon-wide context for background semaphore
// admission. Directly constructed Daemons in unit tests may omit it; those
// retain the historical non-cancellable behavior until explicitly wired.
func (d *Daemon) backgroundApplyCtx() context.Context {
	if d.backgroundApplyContext != nil {
		return d.backgroundApplyContext
	}
	return context.Background()
}

// acquireBackgroundApplySem serializes non-full-config background work that
// runs from a DHCP lease callback. It uses the same cancellable admission and
// fence re-test as beginBackgroundApply, returning context.Canceled when
// shutdown won before the work acquired the semaphore.
func (d *Daemon) acquireBackgroundApplySem() error {
	if d.applyFencedForBackground() {
		return context.Canceled
	}
	ctx := d.backgroundApplyCtx()
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return err
	}
	if ctx.Err() != nil || d.applyFencedForBackground() {
		d.applySem.Release(1)
		return context.Canceled
	}
	return nil
}

// beginBackgroundApply is the single gate every BACKGROUND full-config apply
// passes through (#6788): the DHCP lease-change callback, the dynamic-feed
// publication path, the config-poll / boot / rollback appliers. It reports
// whether the caller may proceed; when it returns true the caller holds
// d.applySem and MUST release it. The supplied context bounds the semaphore
// wait; the daemon background context is used for shutdown-sensitive callers.
//
// One helper rather than three copies of the check. The three background entry
// points (applyConfig, applyActiveConfig, applyActiveConfigResult) are a family
// that must agree — a background applier that skips the fence is exactly the
// defect this closes — and a shared predicate cannot drift the way three
// hand-written guards can.
//
// The fence is tested TWICE, and the second test is the load-bearing one. A
// background applier can already be BLOCKED on applySem behind an in-flight
// apply when shutdown fences; checking only before the acquire lets it through
// the instant that apply releases, which is precisely the moment the shutdown
// drain is waiting for. Re-testing after the acquire closes that window, so a
// waiter cannot inherit the semaphore the drain just freed.
//
// #9884: the same gate also refuses while in bootstrap mode. A compile-failed
// Load can heal ActiveConfig to a non-nil rollback target while still
// reporting ErrConfigCompile, so "an active compiled config exists" no longer
// implies "safe to reconcile": a feed refresh, DHCP lease change, or
// config-poll apply would otherwise reach the bootstrap-exit block in
// applyConfigLocked and take over interfaces/dataplane with no commit or sync.
// The AUTHORIZED bootstrap exits (commit, commitConfirmed, syncAndApply,
// executeConfirmedRollback) acquire applySem directly and never pass through
// this gate, so they are unaffected. Both predicates are tested twice: a
// waiter parked on applySem while the holder rolls the daemon back to
// bootstrap must not apply behind it.
func (d *Daemon) beginBackgroundApply(ctx context.Context, who string) bool {
	if ctx == nil {
		ctx = d.backgroundApplyCtx()
	}
	if d.applyFencedForBackground() {
		slog.Info("shutdown: refusing background config apply; the daemon is stopping",
			"caller", who, "issue", "#6788")
		return false
	}
	if d.inBootstrap() {
		slog.Info("bootstrap: refusing background config apply; takeover stays suppressed until an authorized recovery transition (commit, sync, rollback)",
			"caller", who, "issue", "#9884")
		return false
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		slog.Info("shutdown: background config apply acquire cancelled; the daemon is stopping",
			"caller", who, "issue", "#17018")
		return false
	}
	if ctx.Err() != nil {
		d.applySem.Release(1)
		return false
	}
	if d.applyFencedForBackground() {
		// Fenced while we waited: the apply we queued behind was the last one,
		// and the shutdown drain is what freed this semaphore. Hand it straight
		// back rather than becoming the apply that runs after the drain.
		d.applySem.Release(1)
		slog.Info("shutdown: refusing background config apply; the daemon began stopping "+
			"while this applier waited for the apply lock",
			"caller", who, "issue", "#6788")
		return false
	}
	if d.inBootstrap() {
		// Entered bootstrap while we waited: the transition that flipped it
		// (a rollback to the safe state) already determined this generation
		// must not take over. Hand the semaphore straight back rather than
		// applying behind it.
		d.applySem.Release(1)
		slog.Info("bootstrap: refusing background config apply; the daemon entered bootstrap "+
			"while this applier waited for the apply lock",
			"caller", who, "issue", "#9884")
		return false
	}
	return true
}

// applyActiveConfig applies whatever config is ACTIVE at the moment the apply
// semaphore is acquired, rather than one the caller captured before waiting for
// it (#6716).
//
// The background callbacks — a DHCP lease change, a dynamic-feed update, the
// boot-time apply — all want "reconcile against the current config", not
// "reconcile against the config that was current when I woke up". They used to
// read store.ActiveConfig() and only THEN block on applySem, so a commit that
// landed while they waited was silently reverted by the older snapshot: every
// subsystem applyConfigLocked reconciles was driven from config A after the
// operator had committed config B, with no error anywhere.
//
// The sharpest instance is a REVOKED api-auth credential being republished by a
// DHCP callback that happened to be waiting, but the inversion re-applies any
// A-vs-B difference — bind address, TLS, and everything else the apply pipeline
// touches. It also made the applied-stamp lie: applyConfig marks the ACTIVE
// config applied afterwards, so on the inverted path it stamped B applied while
// A was what ran, and handleConfigSync's #4957 converged shortcut then skipped
// re-applying B on a peer sync, letting the divergence survive a reconnect.
//
// Re-reading under the semaphore closes both halves at once and makes the stamp
// honest by construction: a commit cannot land between the read and the apply,
// because a commit needs this same semaphore.
//
// A nil active config means there is nothing to reconcile (the pre-boot window)
// and is a no-op, matching the guard every caller previously wrote inline.
// applyConfig(cfg) is retained for callers that genuinely mean "apply THIS
// config" — the commit paths use applyConfigLocked directly, and tests drive a
// synthetic config through it.
func (d *Daemon) applyActiveConfig() {
	if d.store == nil {
		return
	}
	pre := d.store.ActiveConfig()
	if pre == nil {
		return
	}
	// Resolve outside applySem on a clone if pre is published (#16601).
	resolved := d.resolveDNSBeforeApply(pre)
	defer d.consumeDNSResolved(resolved)
	if !d.beginBackgroundApply(d.backgroundApplyCtx(), "applyActiveConfig") {
		return
	}
	defer d.applySem.Release(1)
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if cfg == pre {
		cfg = resolved
	}
	d.applyConfigUnderSem(cfg)
}

// applyActiveConfigResult is applyActiveConfig that RETURNS the apply error
// instead of only logging it.
//
// The feed onUpdate publication path (#5646) uses the returned result to decide
// whether the feed content was ACCEPTED: the feed manager advances its per-feed
// published-hash only on a nil return, so a rejected apply leaves publication
// debt that the next identical refetch retries, rather than committing the
// content hash and suppressing retry forever. The returned error is still
// logged — by feeds.installSnapshot's reject branch, not here.
//
// A nil active config returns nil: the pre-boot vacuous success the feed
// manager relies on to record content as published rather than spinning.
//
// This replaces applyConfigResult(cfg), which is deliberately gone rather than
// left unused. It was the natural-looking entry point for exactly the callers
// that must not pre-capture a config, so keeping a dead copy would invite the
// #6716 inversion straight back in.
func (d *Daemon) applyActiveConfigResult() error {
	return d.applyActiveConfigResultWithFeedCallbackGuard(false)
}

// applyActiveConfigResultForFeedCallback applies the current config for a
// feed update and rechecks rollback-target deferral after acquiring applySem.
func (d *Daemon) applyActiveConfigResultForFeedCallback() error {
	return d.applyActiveConfigResultWithFeedCallbackGuard(true)
}

func (d *Daemon) applyActiveConfigResultWithFeedCallbackGuard(feedCallback bool) error {
	if d.store == nil {
		return nil
	}
	pre := d.store.ActiveConfig()
	if pre == nil {
		return nil
	}
	resolved := d.resolveDNSBeforeApply(pre)
	defer d.consumeDNSResolved(resolved)
	if !d.beginBackgroundApply(d.backgroundApplyCtx(), "applyActiveConfigResult") {
		return nil
	}
	defer d.applySem.Release(1)
	if feedCallback {
		// #17741: a feed callback can pass its fast-path check before rollback
		// preflight marks the target install, then wait here for applySem.
		// Recheck under the semaphore so it cannot re-apply C2 afterward.
		if err := d.deferActiveConfigApplyIfRollbackTargetPending(); err != nil {
			return err
		}
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	if cfg == pre {
		cfg = resolved
	}
	err := d.applyConfigLocked(context.Background(), cfg)
	d.stampActiveAppliedIfConvergedUnderSem(err)
	return err
}

// applyConfigUnderSem is applyConfig's body. The caller MUST hold d.applySem.
func (d *Daemon) applyConfigUnderSem(cfg *config.Config) {
	// Boot / DHCP-callback / feed / config-poll applies must always run to
	// completion (they are not request-bound and there is no operator waiting
	// to cancel them), so the heavy pipeline is driven with a non-cancellable
	// context — byte-identical to the pre-#2926 behavior.
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		slog.Warn("apply config failed", "err", err)
		return
	}
	// #16601: cfg may be a DNS-resolved clone of the active config; the
	// store still points at the original pointer, so stamp/baseline must
	// key on the applied clone's answers, not pointer identity alone.
	// recordAppliedDNSBaseline (deferred in applyConfigLocked) already
	// handled the clone; stampActive checks digest, not pointer.
	// #4957: the active config completed a full apply through the boot /
	// background (DHCP callback, feed, config-poll, in-process CLI commit,
	// rollback) path. Stamp it applied so a peer config-sync of the same text
	// takes handleConfigSync's converged shortcut instead of pointlessly
	// re-applying an already-live config on every reconnect (the config
	// high-water resets on reconnect, so the primary re-pushes the current
	// generation even when nothing changed). A FAILED apply above returns
	// early and leaves the prior digest, so a config that never converged is
	// never marked applied — the same #4957 invariant handleConfigSync relies on.
	d.stampActiveAppliedIfConvergedUnderSem(nil)
}

// applyCancelCtx returns the context whose cancellation aborts the heavy apply
// pipeline (applyConfigLocked) at its coarse step boundaries (#2926). It is the
// dedicated DAEMON-STOP context (d.applyCancelContext), deliberately NOT the
// request/commit context AND deliberately NOT d.daemonCtx:
//
//   - A daemon stop MUST abort an in-flight commit/remediation apply at the
//     next boundary so termination is not blocked behind netlink + an FRR
//     reload + a Rust control-socket sync (the #2914/#2868 follow-up). On the
//     next boot the daemon re-applies the active config in full, so skipping
//     the tail of an apply during shutdown always converges.
//   - A mere request cancellation (an HTTP/gRPC client disconnect, or a CLI
//     commit whose context is canceled) MUST NOT abort the apply. By the time
//     applyConfigLocked runs, store.Commit() has already promoted+persisted the
//     new config; aborting the apply on a still-running daemon would leave the
//     store ahead of the dataplane/FRR with no automatic re-apply to converge —
//     a silent forwarding/policy divergence strictly worse than today. The
//     request context still governs the contended applySem wait in the commit
//     wrappers (a slow lock holder surfaces 503), exactly as before.
//
// Why a dedicated context and not d.daemonCtx: in production cmd/xpfd passes
// context.Background() into Run, so d.daemonCtx is never cancelled — returning
// it here would make the C1/C2/C3 boundary checks dead code on a real
// `systemctl stop` (the original #2926 wiring bug). Run creates
// d.applyCancelContext as a child of the SIGTERM/SIGINT signal context, so a
// real daemon stop cancels it; keeping it separate from d.daemonCtx leaves the
// other daemonCtx-derived background goroutines (flow-export, RPM, scheduler,
// cluster comms, the dp.Start dataplane runtime) on their explicit-teardown
// lifetimes, which the orderly shutdown sequence still needs live.
//
// When d.applyCancelContext is unset (early boot, unit tests with no wiring) it
// falls back to a non-cancellable context, so the apply never aborts spuriously.
func (d *Daemon) applyCancelCtx() context.Context {
	if d.applyCancelContext != nil {
		return d.applyCancelContext
	}
	return context.Background()
}

// applyConfigLocked runs the actual reconcile pipeline. MUST be
// called with d.applySem held.
//
// ctx is honored at the coarse phase boundaries marked below (#2926): when it
// is canceled the apply returns ctx.Err() at the NEXT boundary rather than
// completing the netlink + FRR reload + Rust control-socket sync. This lets a
// daemon stop abort an in-flight commit/remediation apply once it is past the
// applySem (the pre-semaphore wait was already cancelled by #2914). The
// boundaries are chosen so a bail leaves a consistent, restart-recoverable
// state — each major side-effecting phase is allowed to finish once started
// (no abort mid-phase), and the next boot re-applies the active config in full.
// Commit callers pass the daemon-lifetime context (applyCancelCtx); the boot /
// DHCP / feed and confirmed-rollback callers pass a non-cancellable context so
// their applies always complete (see applyConfig / executeConfirmedRollback).
func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *config.Config) (retErr error) {
	defer d.consumeDNSResolved(cfg)
	// #9175: a FAILED apply must un-record the #4957 applied marker.
	//
	// MarkActiveApplied / MarkAppliedDigest were the marker's ONLY writers, so it
	// recorded a success and nothing ever unrecorded one. The store's field
	// comment justified that with "the marker is keyed on the config text, so a
	// stale value can only make the shortcut MORE conservative" — true for a
	// FORWARD sequence, where each promotion moves the active text away from the
	// stamped digest, and false for RE-PROMOTION:
	//
	//	A applied            -> ActiveApplied() true
	//	B promoted, apply FAILS -> false   (correct: the digest no longer matches)
	//	A re-promoted, apply FAILS -> TRUE (the step-1 digest matches again)
	//
	// At step 3 handleConfigSync takes its converged shortcut, returns nil, and
	// the HA config high-water advances past a config the dataplane never took —
	// the #4957 fail-open, re-entered through the remedy #4957 itself prescribed,
	// and only observable at failover.
	//
	// This sits in a deferred close over the NAMED return rather than at each
	// caller's failure branch, and that is the point: applyConfigLocked is the one
	// choke point every apply in this daemon goes through (the boot / background
	// path, the commit path, the peer config-sync path and the commit-confirmed
	// auto-rollback all call it), and every early return inside it — the context
	// abort, the factory-reset refusal, the test seam — is covered without anyone
	// having to remember. A per-caller clear would be four sites today and a fifth
	// silently missing tomorrow.
	defer func() { d.recordAppliedDNSBaseline(cfg, retErr) }()
	defer func() {
		if retErr != nil {
			if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == cfg &&
				d.deferredSnapshotCompletionForConfig(cfg) != nil {
				// A deferred snapshot can land after this apply's tail has
				// failed. Its later publication does not repair that tail.
				debt.tailFailed = true
			}
			if d.store != nil {
				d.store.InvalidateAppliedDigest()
			}
			d.failDeferredSnapshotApplyForConfig(cfg, retErr)
		}
	}()
	defer func() {
		if d.policyInvalidationDebtAdopted && d.policyInvalidationPublishLanded {
			if err := d.dischargePolicyInvalidationDebtLocked(nil, nil); err != nil {
				slog.Error("retry policy session invalidation was PARTIAL; some sessions may keep forwarding under stale authorization",
					"err", err)
			}
		}
	}()

	// A deferred userspace publish returns successfully while its debt remains
	// outstanding. Preserve the active digest from this apply, under applySem,
	// so the later publication callback can stamp only this successfully
	// applied config after invalidation finishes.
	defer func() {
		if retErr == nil && d.store != nil {
			if debt := d.policyInvalidationDebt; debt != nil {
				debt.appliedDigest = d.store.ActiveDigest()
				// A complete local apply attempt replaces the earlier failed
				// tail result, even if its snapshot is awaiting publication.
				debt.tailFailed = false
			}
		}
	}()

	// Reset VIP warning suppression so the new config gets fresh warnings.
	//
	// #7532: through the accessor. This runs under applySem while the VRRP
	// reconcile path mutates the same map under no such lock, so the field has
	// its own mutex and no caller touches it directly.
	//
	// Placed BEFORE the applyBodyForTest seam return, for the same reason
	// enterBootstrapMode places stopAndDiscardNATPoolAlarm there: the lifecycle
	// is then exercised by the unit tests that stub the apply body, instead of
	// living on the far side of an early return no test can cross. Moving it
	// ahead of the pipeline is behaviour-preserving — the warnings it un--
	// suppresses are emitted by directAddVIPs on the VRRP reconcile path, which
	// is not driven from inside this function.
	d.resetVIPWarnings()

	d.policyInvalidationPublishLanded = false
	d.policyInvalidationDebtAdopted = false

	// #6948: drop any capture left by a previous apply. The capture is normally
	// consumed by the invalidation this apply's caller runs, but an apply that
	// bails BEFORE the capture point (a context abort, a preflight rejection)
	// never reaches its own capture — and a stale candidate set from an earlier
	// config pair must never be deleted against this one. Placed before the
	// applyBodyForTest seam so the reset holds on the stubbed path too.
	d.policyInvalidationCapture = nil

	// Successful full applies discharge scoped gap debt even when the active
	// config no longer renders a host-inbound table to install (for example,
	// a config change removed the last enforcing scope). Placed BEFORE the
	// applyBodyForTest seam return (#16559): the seam is an early return, so
	// a discharge deferred after it (its pre-#16559 position, past the nil
	// guard) never ran on the stubbed path the #11497 tests drive — those
	// tests passed pre-#16559 only because the inline hook reached
	// applyConfigUnderSem's own discharge, which applyActiveConfigResult
	// (the retry owner's path) does not have.
	defer func() {
		if retErr == nil {
			d.noteHostInboundGapApplyResult(nil)
		}
	}()

	if d.applyBodyForTest != nil {
		d.applyBodyForTest(cfg)
		d.policyInvalidationPublishLanded = !applyErrSkipsPeerSync(d.applyErrForTest)
		return d.applyErrForTest
	}

	// Defensive nil guard (AGY r2 Low): no production caller passes a nil
	// compiled config (commitAndApply / syncAndApply / the boot apply all
	// nil-check first), but the bootstrap-exit block below reads cfg, and
	// the historical body dereferences cfg.Warnings — make the contract
	// explicit so a future caller cannot panic the reconcile.
	if cfg == nil {
		return nil
	}
	// Settle an older deferred config only after this apply's complete tail
	// succeeds. A synchronous dataplane publish alone is not enough to advance
	// HA's applied high-water if the rest of the config apply failed.
	defer func() {
		if retErr != nil || !d.policyInvalidationPublishLanded {
			return
		}
		rt := d.dataplane()
		if rt == nil {
			return
		}
		result := rt.LastApplyResult()
		if result != nil && result.Generation != 0 && !result.SnapshotPublishDeferred {
			d.resolveDeferredSnapshotApplyAfterSynchronousPublish(cfg, result.Generation)
		}
	}()
	// (The #11497 gap-debt discharge defer is registered before the
	// applyBodyForTest seam above — see the #16559 note there.)

	// #5281 defense-in-depth: refuse to reconcile once a factory reset has
	// entered the terminal reset generation. The commit / sync / rollback entry
	// points already reject before persisting, so in practice nothing reaches
	// here during the wipe→stop window; this guards any other applyConfigLocked
	// caller (a boot-time apply, a future path) from re-rendering the erased
	// secrets (frr.conf/swanctl/Kea/login) from the still-resident in-memory
	// ActiveConfig.
	if d.isResetting() {
		return errDaemonResetting
	}

	// Reconcile the whole SNMP subsystem FIRST (#2008 H17, Codex r2; extended
	// to full lifecycle reconcile in #3967). reconcileSNMP matches the running
	// agent + trap-group monitor to the committed config on EVERY commit:
	//   - enable a previously-disabled agent (start the UDP/161 listener),
	//   - disable a running agent (stop the listener),
	//   - swap community authorization / v3 users / trap targets in place on a
	//     still-enabled agent (no listener bounce),
	//   - and start the link-state trap monitor when trap groups appear.
	// Before #3967 only the in-place authorization swap existed and only when
	// SNMP was already enabled at boot — enabling SNMP or adding a trap target
	// day-2 sat inert in the config until a daemon restart.
	//
	// This MUST run before any reconcile step that can abort applyConfigLocked
	// early — specifically the dataplane apply below, which returns early on a
	// required userspace protocol-gate error (compileErrorMustAbortApply, which
	// delegates to userspace.IsRequiredProtocolGateError — policy-scheduler,
	// persistent-source-NAT, or multi-zone scoped-global protocol
	// incompatibility, #2138 / #5488).
	// Store.Commit() has ALREADY promoted and persisted this compiled config
	// before applyConfigLocked runs, so the committed authorization is live
	// regardless of whether the later dataplane apply succeeds. Reconciling
	// only at the tail would leave a committed-downgraded community serving
	// the OLD (read-write) gate on an apply that aborts early. Placed here it
	// is unconditionally before every early-return path in the body (the only
	// aborting one is the dataplane apply at compileErrorMustAbortApply).
	//
	// reconcileSNMP is idempotent: an unchanged SNMP stanza and management-VRF
	// bind are a no-op (no listener bounce). The in-place SNMP stanza swap holds
	// the agent's cfgMu so the UDP listener and in-flight polls are not
	// interrupted; a changed VRF bind restarts the listener. During the boot
	// apply it no-ops the start (snmpBootReady is still false) so the boot block
	// owns the first start, which honors config-only / bootstrap suppression.
	d.reconcileSNMP(cfg)

	// #5866: reconcile the live management HTTP/HTTPS listener + authentication
	// snapshot against the committed web-management config, for the SAME reason
	// and with the SAME early placement as reconcileSNMP above. The management
	// server was constructed once at boot and never reconciled, so a committed
	// bind/port/TLS/api-auth change (e.g. a REVOKED credential) sat inert until a
	// daemon restart. Placed before the dataplane apply so a committed
	// credential revocation is enforced even on an apply that aborts early. A
	// bind-replacement failure is fail-safe (the old listener is retained) and
	// only logged as retry debt — like reconcileSNMP it does not brick an
	// otherwise-successful commit.
	if err := d.reconcileWebManagement(cfg); err != nil {
		slog.Warn("web-management listener reconcile did not converge; retrying on next commit",
			"err", err)
	}

	// #10751/B2: converge the pre-handoff guard before ANY link-affecting
	// mutation in this apply (bootstrap-exit/config-arrival renames, VRF,
	// interface/bond reconcile, dataplane arm, tail). A refusal aborts the
	// apply here so no data link activates without protection. Placed after
	// the SNMP/management reconciles (credential revocation must run even
	// on early-abort applies) and before everything that touches links.
	// Post-handoff this is a no-op atomic check.
	if err := d.requireEarlyInputProtectionPreApply(cfg); err != nil {
		// #14356 (reopened): Store.Commit already promoted cfg, so this
		// earliest refusal is post-promotion too. Run the bounded closeout
		// before propagating; its host-inbound owner re-invokes this same
		// guard at its top and will fail visibly there if the barrier still
		// cannot install, while the lo0 and credential owners still enforce
		// the committed tightening.
		return d.closeoutHostAuthOnPostPromotionError(err, cfg)
	}

	if err := d.applyHostInboundPreNetworkdAddressFence(cfg); err != nil {
		// #14356 (reopened): same post-promotion closeout. The fence helper
		// already recorded staleness on its install failure; the closeout's
		// real host-inbound install (or its retained-fence staleness record)
		// is the fail-closed enforcement for this promoted generation.
		return d.closeoutHostAuthOnPostPromotionError(err, cfg)
	}

	// #1922 Item 2 bootstrap exit: the FIRST apply of a non-empty config
	// (an interface-claiming confirmed commit, or a cluster SyncApply from
	// the primary) leaves bootstrap mode and runs the one-time startup
	// takeover steps that were suppressed at boot — interface rename, IP
	// forwarding, dataplane arm — BEFORE the reconcile below wires the
	// config onto them. Exit is one-way for the daemon's lifetime. An empty
	// config (no interfaces) does NOT exit bootstrap (a confirmed-but-empty
	// commit is not a takeover). Runs under d.applySem (the caller holds it).
	if err := d.maybeExitBootstrapOnFirstConfig(cfg); err != nil {
		// #14356: Store.Commit already promoted cfg and the pre-networkd
		// fence above may already stand in the kernel. A non-cancellation
		// bootstrap refusal must still enforce the committed host-auth
		// tightening via the bounded closeout before propagating.
		return d.closeoutHostAuthOnPostPromotionError(err, cfg)
	}

	// #4179 config-arrival re-naming: a config-less HA node (node-id present,
	// no committed config at boot) is NOT in bootstrap mode, so the block above
	// never fires for it. Its first accepted standalone config can add interface
	// mappings or naming settings, so re-run startup naming here BEFORE reconcile
	// wires the config onto the interfaces. A clustered config cannot arrive via
	// local commit or peer sync: the topology preflight rejects it when d.cluster
	// is nil, and the naming hook also refuses cluster-mode candidates. One-shot.
	// #10751 R4-3: a barrier-gate refusal aborts the apply before reconcile
	// wires the config onto links/VRF/dataplane (transient naming failures
	// still warn-and-continue inside the helper with a nil error).
	if _, err := d.maybeReapplyConfigArrivalNaming(cfg); err != nil {
		// #14356: same post-promotion closeout as the bootstrap exit above.
		return d.closeoutHostAuthOnPostPromotionError(err, cfg)
	}

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
	}
	for _, conflict := range cfg.QuarantinedRIMemberDeviceConflicts {
		logRIMemberDeviceConflict(conflict)
	}

	ctxErr, vrfErr := d.applyVRFReconcile(ctx, cfg)
	if ctxErr != nil {
		// #5643 Gap B: the #2926 C1 boundary lives inside applyVRFReconcile and
		// returns ctx.Err() before the netlink phase. Store.Commit already
		// promoted UPSTREAM, so a daemon-stop cancel landing here is post-
		// promotion too — funnel it through the same host-authorization closeout
		// as C2/C3 so the committed nft/login/root-auth tightening is enforced
		// even when the apply is abandoned at the earliest boundary.
		return d.closeoutHostAuthOnPostPromotionError(ctxErr, cfg)
	}
	// #5700: vrfErr is the DEFERRED VRF-device-setup failure (a genuine, non-
	// cancellation ReconcileVRFs error). The rest of the apply still runs; it is
	// threaded into the tail commit-error join below so the commit fails closed
	// (with a retry owner) instead of reporting a VRF configured while its device
	// is absent — exactly like ifaceErr/routeLeakErr/routingRuleErr.

	// #5867: program the DHCP-learned management-VRF routes and capture the
	// RouteReplace / cleanup failure as a DEFERRED error. A route whose
	// destination stayed but whose gateway/output-interface changed and then
	// failed to replace no longer leaves the stale route protected (the reconcile
	// keys the protect-set on the full route identity, so the stale route is
	// cleaned up) — and the failure is threaded into the tail commit-error join
	// below so the commit fails closed instead of acknowledging a management
	// route pinned to a stale/de-authorized gateway. #11450 also latches route
	// failures into the management-route leg of routing debt; it is retried by
	// the existing 30s owner. The DNS ip-rule error remains part of the commit
	// result but is not misclassified as route debt.
	mgmtRouteApplyErr := d.applyMgmtVRFRoutes()
	d.noteMgmtRouteReconcileResult(mgmtRouteApplyErr)
	mgmtRouteErr := errors.Join(mgmtRouteApplyErr, d.applyMgmtDNSRules())

	// #5310: capture the interface-reconcile failure (xfrmi/bond/tunnel/legacy-
	// reth) and thread it into the tail commit-error join so a genuine reconcile
	// failure (e.g. a route-based VPN's xfrmi that could not be created) fails
	// the commit closed instead of reporting false success. All later reconcile
	// steps still run — the error is deferred to the tail exactly like
	// networkdErr/hostInboundErr/lo0Err (fail-closed but complete).
	ifaceErr := d.applyInterfaceReconcile(cfg)

	// #6791: capture the fabric-overlay failure and thread it into the tail
	// commit-error join, exactly like ifaceErr/vrfErr above. This call was the
	// ONLY reconciler in this sequence whose error could not propagate — it
	// returned nothing, so a fab0/fab1 that could not be created logged
	// "CRITICAL ... cluster heartbeat will not work" and the commit still
	// reported success. All later steps still run (fail-closed but complete).
	fabricErr := d.applyFabricIPVLAN(cfg)

	// 1.9–2.7. Dataplane apply + RETH-MAC/VIP/worker-rebind critical section
	// (#4407). Returns the ip-monitoring commit overlay and the captured
	// networkd write error for the routing rules + tail reconcile below; an
	// error (a #2926 context abort or an ApplyConfig compile abort) bails
	// before the tail.
	// #6948: stamp the admission boundary IMMEDIATELY before the dataplane
	// publishes the new policy set. Placement is the whole design: captured any
	// earlier and sessions admitted under the OLD numbering by the policy being
	// deleted would fall after the stamp and escape the sweep, which is the
	// stale-authorization direction and strictly worse than the over-clear this
	// closes. Captured here, that gap is the call itself.
	captureOld, captureStaged, captureStageErr := d.stageIpsecCapture(cfg)
	d.ipsecCaptureMu.Lock()
	captureStagePending := d.ipsecCaptureStagePending
	d.ipsecCaptureMu.Unlock()
	captureCommitted := captureStageErr != nil || !captureStagePending
	defer func() {
		if !captureCommitted && captureStagePending {
			_ = d.rollbackIpsecCaptureStage(captureOld, captureStaged)
			if healErr := d.healIpsecCaptureAuthorityAfterRollback(cfg); healErr != nil {
				retErr = errors.Join(retErr, healErr)
			}
		}
	}()
	d.policyActivationSecs = daemonMonotonicSeconds()
	core := d.applyDataplaneAndHACore(ctx, cfg)
	commitOverlay, applyErr, vrfTermErr, err := core.Overlay, core.Phase.Dataplane, core.Phase.VRF, core.Terminal
	if err != nil {
		// #5643 (M35): applyDataplaneAndHACore bailed at a #2926 ctx-cancellation
		// boundary (C2 before the dataplane apply, or C3 after it) because the
		// daemon is stopping mid-apply. Store.Commit ALREADY promoted+persisted
		// this config UPSTREAM of applyConfigLocked, so the durable config has
		// advanced, and at C3 the Rust dataplane may already enforce it — but the
		// nft host-authorization + login/credential tail (applyTailReconciles) has
		// NOT run. Unlike FRR/IPsec/DHCP/RA/VRRP/syslog/exporters, those owners do
		// NOT converge on the next boot while the daemon stays intentionally
		// stopped: the kernel xpf_lo0/xpf_hostinbound nft tables and the OS
		// login/sudo/root-SSH/root-authentication credentials persist on the box
		// independent of xpfd. Skipping them here would leave the OLD, more-
		// permissive host authorization live for the entire stop window — a
		// monotonic-revocation violation (a committed management-access tightening
		// silently deferred by the cancel). The closeout runs just
		// those security-critical owners to completion — bounded (two nft loads +
		// local credential reconciles, no FRR/netlink reload) and non-cancellable

		// — against the committed config before propagating the error.
		// #14356: this is no longer cancel-only — a non-cancellation abort
		// (required protocol-gate compile error, policy-rename ancestry
		// authority refusal) has also already promoted cfg, so it runs the
		// same closeout; otherwise the committed tightening stays
		// unenforced until a later successful apply. The non-security tail
		// is intentionally left to next-boot convergence (the #2926 C3
		// contract).
		return d.closeoutHostAuthOnPostPromotionError(err, cfg)
	}
	var captureCommitErr error
	if !captureStagePending {
		captureCommitted = true
	} else {
		switch {
		case applyErr != nil && !d.ipsecCaptureSnapshotLandedForStage():
			captureCommitErr = errors.New("ipsec capture: dataplane snapshot apply failed; staged divert withheld")
		case !d.hostInboundDataplaneFresh.Load() && !d.ipsecCaptureSnapshotLandedForStage():
			captureCommitErr = errors.New("ipsec capture: dataplane snapshot publication deferred; staged divert withheld")
		default:
			captureCommitErr = d.commitIpsecCaptureStage(captureOld, captureStaged)
			d.ipsecCaptureMu.Lock()
			published := !d.ipsecCaptureStagePending && d.ipsecCapture == captureStaged
			d.ipsecCaptureMu.Unlock()
			if captureCommitErr == nil || published {
				captureCommitted = true
			}
		}
	}

	// #9947 F-007: apply the FRR managed section (step 3) on the full path
	// and capture a NON-CONVERGED reload as its own deferred error. A hard
	// failure (nothing applied) or a transient degraded reload (new lines
	// live, stale removal deferred) fails the commit closed via the tail
	// join so a removal that did not happen is never reported as an
	// unqualified success; the persistent pytools-missing degraded state is
	// tolerated (nil) with gauge + retry. This slot is NEVER latched into
	// noteRoutingReconcileResult below — the #9693 owner re-runs only ip-rules,
	// the route-leak snapshot, and VRF miss-terminator reconciliation; it is
	// forbidden from touching FRR.
	frrErr := d.applyFRRFull(cfg, commitOverlay)
	// #16782: the pre-FRR applyMgmtDNSRules above ran before FRR installed
	// this commit's operator statics (RTPROT_ZSTATIC), so a nameserver
	// newly covered by such a static was not yet refused. Re-run the
	// reconcile now that FRR has converged; it is idempotent and also
	// removes stale steering for newly refused servers. Its error joins
	// the management-route commit error like the earlier run.
	if postFRRErr := d.applyMgmtDNSRules(); postFRRErr != nil {
		mgmtRouteErr = errors.Join(mgmtRouteErr, postFRRErr)
	}
	// #16804: the networkd activation inside applyDataplaneAndHACore ran
	// `networkctl reconfigure`, whose default foreign-rule cleanup
	// (ManageForeignRoutingPolicyRules=yes, now disabled by the shipped
	// drop-in on packaged installs) deletes the mgmt-DNS 2500-2503 pairs
	// the pre-FRR reconcile above installed before activation. Re-run the
	// same idempotent reconcile here — after activation AND after FRR —
	// so the tail reconcileDNSLocked readiness gate sees the steering
	// rules that are actually live and keeps the management DHCP
	// name-servers in resolv.conf. The #9693 owner below re-asserts the
	// same rules on its 30 s readback tick, so a later external networkd
	// restart (which also flushes the next-table/rib-group/PBR bands that
	// owner re-runs) is healed without a commit. Its error joins the
	// management-route commit error like the earlier runs.

	// #5844: applyRoutingRules RETURNS the joined next-table / rib-group / PBR
	// ip-rule reconcile failures (a partial clear/add left stale-or-missing
	// cross-VRF policy in the kernel). Capture it as a DEFERRED error — the
	// snapshot republish below still runs (so it is not left stale), and the
	// failure is threaded into the tail commit-error join so the commit fails
	// closed instead of being acknowledged after a partial reconcile.
	routingRuleErr := d.applyRoutingRules(cfg, commitOverlay)

	// #5642: the full dataplane apply (applyDataplaneAndHACore → the dataplane's ApplyConfig)
	// ran BEFORE applyRoutingRules and built its userspace route snapshot from the
	// PRE-reconcile kernel ip-rule table (buildRouteSnapshots enumerates the live
	// ip-rules via netlink.RuleList). On a rib-group / next-table transition —
	// notably the final rib-group removal handled just above — applyRoutingRules
	// has now deleted (or added) the synthetic leak ip-rule, so the snapshot
	// ApplyConfig already published is stale. Rebuild + republish the routes-only
	// snapshot against the now-reconciled kernel rules so the userspace FIB does
	// not retain a deleted-VRF inter-VRF leak. A no-op (content-hash duplicate
	// skip) when the route set did not move. #5696 (M19): a genuine republish /
	// FIB-bump failure is a DEFERRED error threaded into the tail errors.Join —
	// this reconcile has no dirty-retry owner, so a swallowed failure would keep
	// the stale leak on a "successful" commit.
	routeLeakErr := d.reconcileRouteLeakSnapshot(cfg, commitOverlay)
	// #9693: latch (or discharge) policy-routing, route-leak, and
	// post-networkd VRF miss-terminator debt. Management DHCP routes have their
	// own leg within this owner and are reported by their pre/post-networkd
	// reconciles above. FRR remains deliberately separate because it owns its
	// own degraded retry.
	d.noteRoutingReconcileResult(routingRuleErr, routeLeakErr, vrfTermErr)
	vrfErr = errors.Join(vrfErr, vrfTermErr)

	ipsecErr, dhcpServerErr := d.applyServicesReconcile(cfg)
	ipsecErr = errors.Join(ipsecErr, captureStageErr, captureCommitErr)

	// Steps 8–21: tail reconcile dispatches (VRRP, system config, syslog,
	// login/SSH, archival, observability, cluster runtime, host tunables).
	// Extracted into applyTailReconciles (#4407 Phase A). The head above
	// is decomposed into named phase methods (#4407): the decoupled
	// setup/reconcile phases (loadable independently) — applyVRFReconcile,
	// applyInterfaceReconcile, applyFabricIPVLAN, applyFRRFull,
	// applyRoutingRules, applyServicesReconcile — and the
	// ordering-entangled dataplane-apply / RETH-MAC core that stays inline
	// (it threads applyResult / rethMACPending / the deferred errors).
	// The tail is independent per-subsystem dispatch reading only cfg (+
	// nil-guarded managers), so grouping it here is a behavior-preserving
	// mechanical move. The head-produced deferred errors are carried in the
	// applyPhaseErrors named fields (#16170) — Dataplane is the #5679
	// ordinary (non-abort) dataplane-apply failure that must fail the commit
	// without disarming/aborting; RouteLeak is the #5696 route-leak
	// republish/FIB-bump failure; RoutingRule is the #5844
	// next-table/rib-group/PBR ip-rule reconcile failure (a partial kernel
	// policy-routing clear/add); FRR is the #9947 F-007 FRR reload
	// non-convergence (hard or transient degraded — stale config may still
	// be installed while the in-manager retry converges it); the helper
	// creates lo0Err/hostInboundErr and returns the joined errors.
	// #14582: re-resolve the web-management interface bind AFTER networkd /
	// dataplane address convergence in this same apply. The early reconcile
	// above (line ~494) runs before applyDataplaneAndHACore for credential
	// revocation, so a commit that creates the interface address and the
	// `web-management https interface` stanza together resolves against a
	// kernel with no address yet and would otherwise stay on the loopback
	// fallback until a later commit. This second reconcile is the same
	// idempotent reconcile: while the address is still absent the leg stays
	// degraded (Failed, re-driven by the 30s re-assert owner); once it
	// appears the make-before-break rebind lands on the interface address.
	// It must not fail the commit — the early reconcile already enforced
	// revocation, and a still-missing address is retry debt, not a commit
	// error (mirrors the early reconcile's warn-and-retry posture).
	if err := d.reconcileWebManagement(cfg); err != nil {
		slog.Warn("web-management listener re-reconcile after networkd did not converge; retrying via re-assert owner",
			"err", err)
	}
	return d.applyTailReconciles(cfg, applyPhaseErrors{
		Networkd:    core.Phase.Networkd,
		Dataplane:   applyErr,
		DHCPServer:  dhcpServerErr,
		IPsec:       ipsecErr,
		Iface:       ifaceErr,
		RouteLeak:   routeLeakErr,
		RoutingRule: routingRuleErr,
		MgmtRoute:   mgmtRouteErr,
		VRF:         vrfErr,
		Fabric:      fabricErr,
		FRR:         frrErr,
	})
}

// applyHostAuthorizationCloseout runs ONLY the security-critical host-
// authorization owners of the apply tail — the kernel nft lo0/host-inbound
// filters and the OS login/sudo/root-SSH/root-authentication credential
// reconciles — against cfg. It is the bounded, non-cancellable closeout invoked
// from applyConfigLocked (via closeoutHostAuthOnPostPromotionError) when an
// apply is abandoned at a post-promotion error boundary AFTER Store.Commit
// promoted the config (#5643 / M35; non-cancellation aborts since #14356).
//
// These owners are singled out from the rest of applyTailReconciles because,
// unlike FRR/IPsec/DHCP/RA/VRRP/syslog/exporters (which the next boot re-renders
// from the active config, so the #2926 skip converges), they persist on the box
// independently of xpfd and therefore do NOT converge while the daemon is
// intentionally stopped: the kernel xpf_lo0/xpf_hostinbound tables keep enforcing
// whatever generation was last loaded, and a removed login user / revoked sudo
// grant / re-enabled root SSH / stale root password + /root/.ssh/authorized_keys
// stays on disk. Leaving them at the pre-cancel (more permissive) generation
// after a committed tightening is the monotonic-revocation violation M35
// identifies.
//
// The steps mirror applyTailReconciles' step 9.5–13 order exactly. Both nft
// applies fail closed (#3392/#3333). #5874: the login/credential reconcilers
// (applySystemLogin, reconcileSudoers, reconcileAbsentLoginUsers, applySSHConfig
// and applyRootAuth — the SOLE manager of root's /etc/shadow password and
// /root/.ssh/authorized_keys) were previously best-effort VOIDS here, so a
// failure to reconcile a credential to the cancelled/target state was silently
// DISCARDED and the cancel reported clean. They now return their accumulated
// failures, this closeout COLLECTS a per-owner outcome and SURFACES every
// failure — and since #6790 the ORDINARY (uncancelled) apply joins those same
// five returns into the commit result too, so the two paths agree that a
// failed credential reconcile is a failed commit. The "bounded" claim is an
// ENFORCED wall-clock budget
// (hostAuthCloseoutBudget) rather than an unbounded best-effort sequence: a
// wedged reconciler is reported timed-out instead of hanging the daemon-stop
// path. Still safe to run non-cancellably — no FRR/netlink reload.

// compileErrorMustAbortApply reports whether a dataplane ApplyConfig error
// must abort the commit — i.e. the operator-facing commit must report
// failure rather than success against a fail-closed (disarmed) dataplane.
//
// It delegates to dpuserspace.IsRequiredProtocolGateError so the abort set
// is table-driven and co-located with the protocol-gate sentinels and the
// ensureRequiredSnapshotProtocolLocked gate that emits them. Before #2138
// this matched ONLY ErrPolicySchedulerProtocolIncompatible, so the sibling
// ErrPersistentSourceNATProtocolIncompatible fell through: ApplyConfig
// disarmed the helper but the commit was promoted/persisted anyway — a
// silent forwarding outage on a "successful" commit. The delegation covers
// both gates and any future required protocol gate the moment its sentinel
// joins the list.
//
// "Abort" here means the apply/commit-RPC result returned up to the
// HTTP/gRPC/CLI committer becomes non-nil. Store.Commit/CommitConfirmed/
// SyncApply have ALREADY promoted+persisted the compiled config before
// applyConfigLocked runs, so the abort does not unwind store promotion;
// the operator-visible signal is the failed commit plus the disarmed
// dataplane (the same contract the scheduler gate has always had).
func compileErrorMustAbortApply(err error) bool {
	return dpuserspace.IsRequiredProtocolGateError(err)
}
