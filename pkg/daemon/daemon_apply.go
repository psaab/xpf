// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// setRethIPv6Knobs writes the per-interface IPv6 procfs knobs for a RETH
// member: disable DAD (the virtual MAC may still collide with the peer on
// some deployments) and suppress kernel-generated link-locals (which else
// trigger continuous MLDv2 reports on the L2 segment; VIPs are managed
// explicitly). These are BestEffortKernelKnob procfs writes — a rename(2)
// is impossible on procfs, so they stay direct os.WriteFile. Extracted from
// applyConfigLocked (#1916 §2.D) so the giant apply function is never
// allowlisted in the fsatomic canary; this single-purpose helper is.
func setRethIPv6Knobs(iface string) {
	dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", iface)
	os.WriteFile(dadPath, []byte("0"), 0644)
	addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	os.WriteFile(addrGenPath, []byte("1"), 0644)
}

// setVLANSubAddrGenMode suppresses kernel-generated link-locals on a VLAN
// sub-interface (addr_gen_mode=1). BestEffortKernelKnob procfs write,
// extracted from applyConfigLocked (#1916 §2.D) so it can be allowlisted
// without exempting the whole apply function.
func setVLANSubAddrGenMode(iface string) {
	subAddrGen := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", iface)
	os.WriteFile(subAddrGen, []byte("1"), 0644)
}

// applyConfig applies a compiled config to the dataplane / kernel.
// Wraps applyConfigLocked under the apply semaphore for non-context
// callers (DHCP callbacks, config-poll, dynamic feeds, event engine,
// in-process CLI commits, CLI auto-rollback, cluster sync recv).
// Always succeeds in acquiring the lock because Background never
// cancels.
//
// #846: HTTP/gRPC commit handlers go through commitAndApply /
// commitConfirmedAndApply instead, which take the same semaphore
// with a request-bound context so a slow lock holder surfaces 503
// to the client rather than hanging the request.
func (d *Daemon) applyConfig(cfg *config.Config) {
	if !d.beginBackgroundApply("applyConfig") {
		return
	}
	defer d.applySem.Release(1)
	d.applyConfigUnderSem(cfg)
}

// fenceBackgroundApplies latches the #6788 background-apply fence. Called once
// by runShutdownSequence, at the very start and BEFORE the in-flight cancel and
// the apply drain, so the drain is the LAST apply this process performs. Never
// cleared: the process is exiting.
func (d *Daemon) fenceBackgroundApplies() { d.applyFenced.Store(true) }

// applyFencedForBackground reports whether background config applies are fenced
// (see Daemon.applyFenced).
func (d *Daemon) applyFencedForBackground() bool { return d.applyFenced.Load() }

// beginBackgroundApply is the single gate every BACKGROUND full-config apply
// passes through (#6788): the DHCP lease-change callback, the dynamic-feed
// publication path, the config-poll / boot / rollback appliers. It reports
// whether the caller may proceed; when it returns true the caller holds
// d.applySem and MUST release it.
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
func (d *Daemon) beginBackgroundApply(who string) bool {
	if d.applyFencedForBackground() {
		slog.Info("shutdown: refusing background config apply; the daemon is stopping",
			"caller", who, "issue", "#6788")
		return false
	}
	_ = d.applySem.Acquire(context.Background(), 1)
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
	if !d.beginBackgroundApply("applyActiveConfig") {
		return
	}
	defer d.applySem.Release(1)
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
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
	if !d.beginBackgroundApply("applyActiveConfigResult") {
		// A fenced daemon is not a rejected feed: returning an error here would
		// make the feed manager record publication DEBT for content it should
		// simply stop retrying, on a process that is exiting. Report the same
		// vacuous success the pre-boot nil-config case returns.
		return nil
	}
	defer d.applySem.Release(1)
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	return d.applyConfigLocked(context.Background(), cfg)
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
	// #4957: the active config completed a full apply through the boot /
	// background (DHCP callback, feed, config-poll, in-process CLI commit,
	// rollback) path. Stamp it applied so a peer config-sync of the same text
	// takes handleConfigSync's converged shortcut instead of pointlessly
	// re-applying an already-live config on every reconnect (the config
	// high-water resets on reconnect, so the primary re-pushes the current
	// generation even when nothing changed). A FAILED apply above returns
	// early and leaves the prior digest, so a config that never converged is
	// never marked applied — the same #4957 invariant handleConfigSync relies on.
	if d.store != nil {
		d.store.MarkActiveApplied()
	}
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
	defer func() {
		if retErr != nil && d.store != nil {
			d.store.InvalidateAppliedDigest()
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

	// #6948: drop any capture left by a previous apply. The capture is normally
	// consumed by the invalidation this apply's caller runs, but an apply that
	// bails BEFORE the capture point (a context abort, a preflight rejection)
	// never reaches its own capture — and a stale candidate set from an earlier
	// config pair must never be deleted against this one. Placed before the
	// applyBodyForTest seam so the reset holds on the stubbed path too.
	d.policyInvalidationCapture = nil

	if d.applyBodyForTest != nil {
		d.applyBodyForTest(cfg)
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
	// reconcileSNMP is idempotent: an unchanged SNMP stanza is a no-op (no
	// listener bounce). The in-place swap holds the agent's cfgMu so the UDP
	// listener and in-flight polls are not interrupted. During the boot apply
	// it no-ops the start (snmpBootReady is still false) so the boot block
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

	// #1922 Item 2 bootstrap exit: the FIRST apply of a non-empty config
	// (an interface-claiming confirmed commit, or a cluster SyncApply from
	// the primary) leaves bootstrap mode and runs the one-time startup
	// takeover steps that were suppressed at boot — interface rename, IP
	// forwarding, dataplane arm — BEFORE the reconcile below wires the
	// config onto them. Exit is one-way for the daemon's lifetime. An empty
	// config (no interfaces) does NOT exit bootstrap (a confirmed-but-empty
	// commit is not a takeover). Runs under d.applySem (the caller holds it).
	if d.inBootstrap() && cfg != nil && len(cfg.Interfaces.Interfaces) > 0 {
		d.exitBootstrapMode("first non-empty config applied")
		d.runBootstrapExitStartup(cfg)
	}

	// #4179 config-arrival re-naming: a config-less HA node (node-id present,
	// no committed config at boot) is NOT in bootstrap mode, so the block above
	// never fires for it. That node named its NICs STANDALONE at boot; the
	// first non-empty config to arrive (a cluster SyncApply from the primary,
	// or a local commit) finally supplies its cluster identity, so re-run
	// startup naming here — BEFORE the reconcile below wires the config onto
	// the interfaces — to reconcile them to the node's cluster names. One-shot;
	// a no-op on a standalone config or any later commit.
	d.maybeReapplyConfigArrivalNaming(cfg)

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
	}

	ctxErr, vrfErr := d.applyVRFReconcile(ctx, cfg)
	if ctxErr != nil {
		// #5643 Gap B: the #2926 C1 boundary lives inside applyVRFReconcile and
		// returns ctx.Err() before the netlink phase. Store.Commit already
		// promoted UPSTREAM, so a daemon-stop cancel landing here is post-
		// promotion too — funnel it through the same host-authorization closeout
		// as C2/C3 so the committed nft/login/root-auth tightening is enforced
		// even when the apply is abandoned at the earliest boundary.
		return d.closeoutHostAuthOnCancel(ctxErr, cfg)
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
	// route pinned to a stale/de-authorized gateway. Deferred (not fatal here)
	// exactly like ifaceErr/routeLeakErr/routingRuleErr: the rest of the apply
	// still runs.
	mgmtRouteErr := d.applyMgmtVRFRoutes()

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
	d.policyActivationSecs = daemonMonotonicSeconds()
	commitOverlay, networkdErr, applyErr, err := d.applyDataplaneAndHACore(ctx, cfg)
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
		// silently deferred by the cancel). closeoutHostAuthOnCancel runs just
		// those security-critical owners to completion — bounded (two nft loads +
		// local credential reconciles, no FRR/netlink reload) and non-cancellable
		// — against the committed config before propagating the cancellation. A
		// non-cancellation error (an ordinary compile-abort) returns unchanged.
		// The non-security tail is intentionally left to next-boot convergence
		// (the #2926 C3 contract).
		return d.closeoutHostAuthOnCancel(err, cfg)
	}

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

	// #9693: latch (or discharge) the routing reconcile debt. The two errors
	// above fail the commit closed, but nothing RE-RAN the reconcile: a transient
	// ip-rule or republish failure left stale cross-VRF policy in the kernel and
	// the userspace FIB until an unrelated apply, and applies nobody waits on
	// (boot, DHCP lease, feed, config-poll) only logged it at Warn.
	// routingReconcileReassertLoop re-runs both until they succeed.
	d.noteRoutingReconcileResult(routingRuleErr, routeLeakErr)

	ipsecErr, dhcpServerErr := d.applyServicesReconcile(cfg)

	// Steps 8–21: tail reconcile dispatches (VRRP, system config, syslog,
	// login/SSH, archival, observability, cluster runtime, host tunables).
	// Extracted into applyTailReconciles (#4407 Phase A). The head above
	// is decomposed into named phase methods (#4407): the decoupled
	// setup/reconcile phases (loadable independently) — applyVRFReconcile,
	// applyInterfaceReconcile, applyFabricIPVLAN, applyRoutingRules,
	// applyServicesReconcile — and the ordering-entangled dataplane-apply /
	// RETH-MAC core that stays inline (it threads applyResult / rethMACPending
	// / the deferred errors). The tail is independent per-subsystem dispatch
	// reading only cfg (+ nil-guarded managers), so grouping it here is a
	// behavior-preserving mechanical move. The five head-produced deferred
	// errors (networkdErr/applyErr/dhcpServerErr/ipsecErr/ifaceErr) are threaded
	// in — applyErr is the #5679 ordinary (non-abort) dataplane-apply failure
	// that must fail the commit without disarming/aborting; routeLeakErr is the
	// #5696 route-leak republish/FIB-bump failure; routingRuleErr is the #5844
	// next-table/rib-group/PBR ip-rule reconcile failure (a partial kernel
	// policy-routing clear/add); the helper creates lo0Err/hostInboundErr and
	// returns the joined errors.
	return d.applyTailReconciles(cfg, networkdErr, applyErr, dhcpServerErr, ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr, fabricErr)
}

// applyHostAuthorizationCloseout runs ONLY the security-critical host-
// authorization owners of the apply tail — the kernel nft lo0/host-inbound
// filters and the OS login/sudo/root-SSH/root-authentication credential
// reconciles — against cfg. It is the bounded, non-cancellable closeout invoked
// from applyConfigLocked (via closeoutHostAuthOnCancel) when an apply is
// abandoned at a #2926 ctx-cancellation boundary AFTER Store.Commit promoted the
// config (#5643 / M35).
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
