package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// bootstrapFromFile reads the text Junos config file and imports it as the
// initial active configuration. This is called on first start when the DB
// has no active config yet.
func (d *Daemon) bootstrapFromFile() error {
	data, err := os.ReadFile(d.opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Import into the store: enter config mode, load, commit.
	// Commit() handles compilation (including ${node} variable expansion
	// when nodeID is set on the store for cluster mode).
	if err := d.store.EnterConfigure(); err != nil {
		return fmt.Errorf("enter configure: %w", err)
	}
	if err := d.store.LoadOverride(string(data)); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("load override: %w", err)
	}
	// #4183: run the SAME device-map strand-management preflight an
	// interactive commit runs, so a day-0/bootstrap config that would strand
	// management on next boot (a device-map losing the mgmt NIC, #1956) is
	// caught BEFORE it is committed and takes over interfaces. Without this,
	// the day-0 import committed unchecked and the box could come up
	// console-only from the very first boot. Refusing to commit here leaves
	// the daemon in the lifeline-safe bootstrap state instead.
	// #5848: snapshot the candidate generation with the compile so the promotion
	// below is bound to the EXACT candidate this pre-flight examined. Bootstrap
	// runs single-threaded before the gRPC/HTTP servers start, so no concurrent
	// candidate edit can occur and the generation always matches — this is
	// belt-and-suspenders that keeps the examined-equals-promoted invariant
	// uniform with the operator commit paths (commitWithGenBinding).
	cand, gen, cerr := d.store.CompileCandidateGen()
	if cerr == nil {
		if perr := d.deviceMapCommitPreflight(cand, nil); perr != nil {
			d.store.ExitConfigure()
			slog.Error("bootstrap config REJECTED: its device-map would strand management on next "+
				"boot; NOT committing — staying in lifeline-safe bootstrap mode. Fix the device-map "+
				"and re-import.", "err", perr, "file", d.opts.ConfigFile)
			return fmt.Errorf("bootstrap device-map preflight: %w", perr)
		}
	}
	if _, err := d.store.CommitWithDescriptionGen("", gen); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("commit: %w", err)
	}
	d.store.ExitConfigure()
	slog.Info("configuration bootstrapped from file", "file", d.opts.ConfigFile)
	return nil
}

// maxCommitPreflightRetries bounds how many times commitWithGenBinding
// re-snapshots + re-pre-flights + re-attempts a promotion when a concurrent
// candidate edit invalidates the examined generation (#5848). A handful of
// retries absorbs an operator/automation edit racing a commit; if the candidate
// keeps changing under us we surface the conflict rather than spin forever, so
// the REST/gRPC caller can retry the whole commit.
const maxCommitPreflightRetries = 3

// commitWithGenBinding runs the #5848 generation-bound commit transaction so
// the candidate examined by the external #1956 device-map hardware pre-flight is
// EXACTLY the candidate the store promotes — never a different one substituted
// by a concurrent REST/CLI candidate edit (set/delete/load/rollback), which do
// NOT take the apply semaphore.
//
// Each attempt: snapshot+compile the candidate and read its generation token
// atomically (CompileCandidateGen); run the caller's preflight on that immutable
// compiled snapshot OUTSIDE the store lock (s.mu is NOT held across netlink /
// hardware probing); then commit bound to the snapshot generation. If a
// candidate edit landed in between, the generation-checked commit returns
// ErrCandidateGenerationConflict and we retry against the fresh generation
// (bounded). commitFn performs the generation-checked promotion
// (CommitWithDescriptionGen / CommitConfirmedGen).
//
// A snapshot that fails to compile (not in configuration mode / commit-check
// error) skips the pre-flight — there is nothing to examine — but STILL
// gen-binds the commit: a concurrent edit that turns a non-compiling candidate
// into a valid, management-stranding one cannot be promoted unexamined; the
// bound commit conflicts and the retry re-pre-flights it. When the candidate is
// unchanged, the bound commit recompiles under the lock and surfaces the SAME
// compile/mode error the pre-#5848 path did.
//
// Caller holds d.applySem. Returns the pre-commit active config (for the #4234
// deletion-clear diff) and the compiled promoted config.
func (d *Daemon) commitWithGenBinding(
	preflight func(cand *config.Config) error,
	commitFn func(expectedGen uint64) (*config.Config, error),
) (oldActive, compiled *config.Config, err error) {
	for attempt := 0; ; attempt++ {
		cand, gen, cerr := d.store.CompileCandidateGen()
		if cerr == nil {
			// Run the hardware pre-flight on the exact compiled snapshot,
			// OUTSIDE the store lock (CompileCandidateGen already released it).
			if perr := preflight(cand); perr != nil {
				return nil, nil, perr
			}
		}
		// Capture the pre-commit active config right before the promotion so
		// applyAndSyncCommitted can diff deleted policies (#4234). Active only
		// changes under d.applySem (held here), so it is stable across the
		// transaction.
		oldActive = d.store.ActiveConfig()
		compiled, err = commitFn(gen)
		if err == nil {
			return oldActive, compiled, nil
		}
		if errors.Is(err, configstore.ErrCandidateGenerationConflict) && attempt < maxCommitPreflightRetries {
			slog.Warn("commit: candidate configuration changed during pre-flight; re-validating on the new generation",
				"attempt", attempt+1)
			continue
		}
		return nil, nil, err
	}
}

// commitAndApply atomically promotes the candidate config and
// applies it. Holds applySem across configstore.Commit and
// applyConfigLocked so two concurrent committers can't interleave
// their commit→apply pairs (which would let kernel state lag store
// state). Optionally syncs to the cluster peer inside the lock.
//
// If ctx is canceled before the semaphore is acquired, returns
// ctx.Err() and NEITHER commit nor apply runs — no divergence.
//
// Once the semaphore is held, store.Commit() promotes the config and the
// apply runs. The apply itself (applyConfigLocked) is cancellable at coarse
// boundaries via the DAEMON-LIFETIME context (applyCancelCtx), NOT this
// request ctx (#2926): a daemon stop aborts an in-flight apply so termination
// is not blocked behind netlink + FRR reload + Rust sync, while a request
// cancellation after store.Commit is deliberately ignored (aborting a
// promoted commit on a still-running daemon would diverge the store from the
// dataplane). See applyCancelCtx for the full rationale.
func (d *Daemon) commitAndApply(ctx context.Context, authority configstore.CommitAuthority, comment string, syncPeer peerSyncPolicy) (*config.Config, error) {
	// #1922 Item 2 first-takeover gate (OQ-B, blunt resolution). In
	// bootstrap mode a plain `commit` is refused: the first commit on a
	// foreign/non-appliance host claims interfaces and can cut off
	// management, so it MUST go through `commit confirmed <minutes>` (the
	// system rolls back automatically unless the operator confirms it from
	// a still-reachable session). The gate is blunt (any first commit, not
	// just interface-claiming ones) — the simplest safe rule, matching the
	// #1879 §5 recommendation; the confirmed-commit path is the escape
	// hatch (no separate `commit no-confirm` foot-gun is introduced). Once
	// the first confirmed commit is confirmed (bootstrap exits one-way),
	// plain commits work normally. The day-0 image path never hits this —
	// it resolves NOT-bootstrap before any interactive session.
	if d.inBootstrap() {
		// The daemon is in bootstrap mode (no interface takeover has been
		// confirmed yet). A plain commit is refused regardless of whether
		// this is literally the first commit — bootstrap only exits on a
		// CONFIRMED non-empty (interface-claiming) commit, so until then any
		// takeover must go through commit-confirmed (Copilot: message worded
		// for the mode, not "first commit", since a confirmed-but-empty
		// commit leaves the daemon in bootstrap).
		return nil, fmt.Errorf("system is in bootstrap mode: commit the takeover config with " +
			"'commit confirmed <minutes>' (the interface takeover can cut off management, so the " +
			"system rolls back automatically unless you confirm it from a still-reachable session)")
	}

	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	// #5281: reject the commit if a factory reset is in progress. Checked under
	// applySem and BEFORE store.Commit persists the candidate — a commit that
	// promoted after the zeroize wipe would re-create the just-erased .configdb
	// SSOT on disk and re-render secrets on apply.
	if d.isResetting() {
		return nil, errDaemonResetting
	}

	// #5848 generation-bound commit transaction. The #1956 R-8 device-map
	// pre-flight (reject a candidate whose device-map would strand management on
	// next boot, while the operator is still connected) and the store promotion
	// used to be two separately-locked ops, so a concurrent REST/CLI candidate
	// edit could land between them and the daemon would promote a candidate it
	// never pre-flighted. commitWithGenBinding binds the examined generation to
	// the promoted generation: the pre-flighted candidate is the one promoted, or
	// the commit conflicts and re-validates. Plain commit has no auto-rollback
	// target, so the pre-flight passes nil.
	oldActive, compiled, err := d.commitWithGenBinding(
		func(cand *config.Config) error {
			// #5840: reject a standalone<->cluster topology change BEFORE store
			// promotion + any dataplane mutation — the boot-only cluster runtime
			// cannot be constructed/torn down live. Runs first (no hardware probe)
			// so a doomed transition fails cheaply. The gate keys on the ACTUAL
			// HA runtime (d.cluster != nil, boot-only and stable under the held
			// applySem), not the old config — so a #4179 config-less node (nil
			// active, nil runtime) adding cluster is REJECTED, not silently
			// half-applied.
			if terr := clusterTopologyCommitPreflight(d.cluster != nil, cand); terr != nil {
				return terr
			}
			// #6192: reject a day-2 node-id / cluster-id change on a running
			// clustered node BEFORE promotion — the boot-constructed HA manager
			// cannot be re-keyed live (its identity feeds heartbeat, RETH MAC,
			// election). The topology gate above already handled the
			// standalone<->cluster flip; this covers the same-mode identity edit.
			if ierr := clusterIdentityCommitPreflight(d.cluster, cand); ierr != nil {
				return ierr
			}
			// #8965: and refuse a LIVE control-endpoint move, which would restart
			// comms on the new address before the peer can be told about it.
			if eerr := clusterControlEndpointCommitPreflight(d.cluster, cand); eerr != nil {
				return eerr
			}
			// #8987: and the INTERFACE half of the same tuple, which strands the
			// peer identically. Wired at all three apply paths beside its
			// sibling — a gate at one is the partial-fix shape on a row whose
			// remaining half is silent.
			if ierr := clusterControlInterfaceCommitPreflight(d.cluster, cand); ierr != nil {
				return ierr
			}
			// #9121: and the CONFIG-SYNC endpoint, which is the field set the
			// two gates above should have been keyed on. They read the
			// HEARTBEAT pair, an exact proxy in control-link mode and no proxy
			// at all in fabric-transport mode, where the heartbeat never starts
			// and both of them no-op on the commit that partitions the pair.
			if serr := clusterSyncEndpointCommitPreflight(d.activeTransport(), cand); serr != nil {
				return serr
			}
			// #6650: refuse a config the cluster PEER cannot represent, before
			// the store promotes anything. Ordered last among the cluster
			// preflights: the topology/identity gates above decide whether this
			// node may be clustered at all, and this one only has meaning once
			// that is settled.
			if perr := d.peerSnapshotProtocolCommitPreflight(cand); perr != nil {
				return perr
			}
			return d.deviceMapCommitPreflight(cand, nil)
		},
		func(gen uint64) (*config.Config, error) {
			return d.store.CommitWithDescriptionGenAs(authority, comment, gen)
		},
	)
	if err != nil {
		return nil, err
	}
	return d.applyAndSyncCommitted(oldActive, compiled, syncPeer)
}

// applyAndSyncCommitted runs the reconcile pipeline for a config the store has
// ALREADY promoted+persisted (committed + active), then pushes it to the
// cluster peer unless the apply failed in a way that must not propagate.
// Shared by commitAndApply and commitConfirmedAndApply. Caller holds d.applySem.
//
// #4034: the peer config-sync used to sit AFTER an unconditional
// `if applyErr != nil { return nil, err }`, so ANY applyConfigLocked error —
// including the NON-FATAL best-effort tail errors it joins (networkd write /
// Kea restart / host-inbound + lo0 nft, daemon_apply.go tail) — skipped the
// sync. But those errors leave the config committed + active AND the dataplane
// armed and forwarding; the standby then never received the new config and the
// nodes DIVERGED, so a failover served stale config. The sync was skipped
// precisely when the local apply had a recoverable hiccup — the worst time to
// skip it.
//
// applyErrSkipsPeerSync distinguishes the two error classes that MUST still
// suppress the sync (a disarmed dataplane, or a daemon-stop context abort)
// from a non-fatal subsystem error that must NOT. On a non-fatal error the
// committed config is returned alongside the error so the operator sees the
// failure while the standby still converges.
func (d *Daemon) applyAndSyncCommitted(oldActive, compiled *config.Config, syncPeer peerSyncPolicy) (*config.Config, error) {
	// #6948: arm the commit-time session-invalidation plan BEFORE the apply.
	// Only this caller holds the pre-commit active config — the store promoted
	// the new one upstream — and the invalidation's candidate set has to be READ
	// while the live rows still carry the OLD policy numbering it is derived
	// from. applyConfigLocked takes that capture at the publication boundary;
	// without the plan it falls back to the pre-#6948 post-apply scan, which
	// sweeps the sessions of whichever policy inherited a deleted policy's id.
	d.armPolicyInvalidationPlan(oldActive, compiled)
	applyErr := d.applyConfigLocked(d.applyCancelCtx(), compiled)
	if applyErrSkipsPeerSync(applyErr) {
		// Fatal (required-protocol-gate: dataplane disarmed / fail-closed) or a
		// daemon-stop context abort (#2926 boundary): report failure and do NOT
		// push. Pushing a disarm-config to the standby is strictly worse, and a
		// shutdown-aborted apply reconverges on next boot + reverse-sync. Skip the
		// deletion-clear too: the dataplane is disarmed / tearing down, so there is
		// no live forwarding state to invalidate.
		return nil, applyErr
	}
	// #4234 Junos-default deletion-clear + modified-policy re-eval + #4342
	// default-policy re-eval: the config is committed + active and the dataplane
	// armed, so any session admitted by a now-deleted/tightened/default-changed
	// policy must stop forwarding immediately (and be dropped on the standby too)
	// rather than linger until idle timeout. Runs under d.applySem (the caller
	// holds it), after the dataplane apply so the new policy set is already live.
	//
	// #5578: a PARTIAL invalidation (enumerate/delete failure) is a stale-
	// authorization gap — traffic the new policy should DENY may keep forwarding
	// on old session state. Join it into the returned error alongside the non-
	// fatal apply error (mark-and-continue: the config stays committed + active
	// and still syncs to the peer, but the operator sees the failure and can
	// re-commit). Matches how applyErr's non-fatal best-effort subsystem errors
	// are surfaced here rather than aborting the commit.
	// #5858/#7212: the ONE commit-time entry point for "authorization the
	// operator just changed, versus sessions already established". It is the
	// policy clear alone since #7212 moved the interface-input-filter half into
	// the dataplane (lazy per-tuple revalidation on the session-hit path); the
	// commit-time advisory that stood in for it is deleted.
	clearErr := d.reportSessionAuthorizationChanges(oldActive, compiled)
	// Committed + active locally with the dataplane armed. A non-fatal
	// best-effort subsystem error must NOT skip the peer sync (#4034): the
	// standby has to receive the committed config or the nodes diverge.
	//
	// #5962: the policy is RESOLVED HERE, not at the entry point. The commit
	// has succeeded and the store's writability check (ensureWritableLocked,
	// itself tied to RG0 ownership via applyRG0OwnershipTransition) has already
	// run, so this reads the same ownership the commit was allowed under. The
	// pre-#5962 code resolved rg0ConfigSyncAuthority in commitAndApplyOperator
	// instead — before Commit — so a promotion landing between the two checks
	// produced a successful commit with the push silently skipped.
	if syncPeer.wantsPush(d.cluster) {
		d.pushCommittedConfigToPeer()
	}
	joined := errors.Join(applyErr, clearErr)
	// #4957: a fully-successful commit apply (no fatal apply error, no partial
	// session-invalidation) means the committed active config has converged on the
	// dataplane. Stamp it applied so that if THIS node later becomes secondary and
	// the new primary syncs this same config back, handleConfigSync's converged
	// shortcut recognizes it without a redundant re-apply. A non-nil joined error
	// leaves the prior digest — the config did not fully converge.
	if joined == nil && d.store != nil {
		d.store.MarkActiveApplied()
	}
	return compiled, joined
}

// applyErrSkipsPeerSync reports whether an applyConfigLocked error means the
// just-committed config must NOT be pushed to the cluster peer (#4034). Two
// classes skip the sync; every OTHER (non-fatal, best-effort subsystem) error
// still syncs because the config is committed + active and the dataplane armed:
//
//   - A required-protocol-gate error (compileErrorMustAbortApply): the
//     dataplane is DISARMED (fail-closed, #2138). The commit is reported failed;
//     pushing a config that would disarm the standby's dataplane too is strictly
//     worse than letting the operator fix it and re-commit.
//   - A context CANCELLATION (#2926 boundary abort): the apply was aborted
//     mid-pipeline by a daemon stop. The local node is tearing down; the next
//     boot re-applies in full and the reverse-sync-on-reconnect converges the
//     peer, so a push racing the transport teardown is avoided.
//
// #7618: context.DeadlineExceeded was in that second class and is NOT any
// more, because it never had a true positive there.
//
// The apply context cannot expire. It is cancel-only end to end —
// cmd/xpfd/main.go passes context.Background(), Run wraps it in
// signal.NotifyContext (SIGTERM/SIGINT), and daemon_run.go derives
// applyCancelContext with context.WithCancel — and BOTH callers reach the
// pipeline as applyConfigLocked(d.applyCancelCtx(), ...), so no caller can
// inject a deadline (syncAndApply's own ctx parameter is not used for the
// apply). A #2926 abort therefore always surfaces as context.Canceled.
//
// Every DeadlineExceeded that reaches here is instead a PER-COMMAND budget
// from a runner rooted at context.Background(), fully detached from the apply
// context: nftApplyPayload's 5s (lo0Err, hostInboundErr — joined since
// #3392/#3333), daemon_dns.go's systemctl calls (dnsErr, #6792), and
// runCommandStdinTimeout's 15s (the #6790 credential operands). exec has two
// error shapes at a deadline: a process that STARTED and was killed yields
// *exec.ExitError ("signal: killed") and was always classified correctly,
// while a context that expired BEFORE fork/exec completed yields a bare
// context.DeadlineExceeded. Which one you get is decided by whether fork/exec
// wins the race — i.e. by machine load, which is why this was observed only
// under a loaded full-package run.
//
// "My useradd took 15s" is not "the daemon is stopping", and treating it as
// such made applyAndSyncCommitted skip the push to the standby and
// syncAndApply DISCARD a peer-promoted config. Both recover — the #5863
// (epoch x generation) marker is never claimed on the skip path so the 30s
// configSyncReconcileLoop re-pushes, and a discard drives the #7328
// nack/re-arm — so the exposure is bounded rather than permanent. It is still
// a window in which a failover serves stale config, for a reason unrelated to
// the config.
//
// Deleting the clause rather than giving the command deadline its own sentinel
// is deliberate. A sentinel threaded through three runners would add wire
// surface to make a distinction that the Canceled/DeadlineExceeded split
// already draws, and the deletion's worst case is bounded: it can only stop
// suppressing the sync for a deadline-shaped abort, and no such abort exists
// on this path. TestApplyCancelContextIsCancelOnly7618 binds that premise so
// it is checked rather than asserted here.
func applyErrSkipsPeerSync(err error) bool {
	if err == nil {
		return false
	}
	if compileErrorMustAbortApply(err) {
		return true
	}
	return errors.Is(err, context.Canceled)
}

// pushCommittedConfigToPeer pushes the current active config to the cluster
// peer, honoring the syncPeerForTest seam. Shared by the commit-apply path
// (applyAndSyncCommitted, #4034) and the commit-confirmed rollback re-sync
// (resyncRolledBackConfigToPeer, #3868) so both route through one observable
// point. Caller holds d.applySem and has already promoted the active config.
func (d *Daemon) pushCommittedConfigToPeer() {
	if d.syncPeerForTest != nil {
		d.syncPeerForTest()
		return
	}
	d.syncConfigToPeer()
}

// syncAndApply is the cluster-sync-recv analogue of commitAndApply.
// Holds applySem across configstore.SyncApply (peer-driven active
// promotion) + applyConfigLocked, so a peer-sync can't interleave
// between a local committer's Commit and applyConfig (which would
// briefly leave store=peer-config but kernel=local-config).
func (d *Daemon) syncAndApply(ctx context.Context, configText string, chassisPreserve func(*config.ConfigTree)) (compiled *config.Config, retErr error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	// #5281: reject a peer-driven sync-apply while a factory reset is in
	// progress. SyncApply persists the peer config as active before the
	// reconcile, so an HA sync landing after the zeroize wipe would re-create
	// the erased SSOT and re-render secrets. Checked under applySem, before
	// SyncApply.
	if d.isResetting() {
		return nil, errDaemonResetting
	}

	// Pre-sync active config for the #4234 deletion-clear (see commitAndApply).
	// A peer-pushed config that deletes a policy must drop that policy's synced
	// sessions on THIS node too; the standby is not primary, so its own clear
	// deletes locally without re-propagating (belt-and-suspenders alongside the
	// primary's delete-sync).
	oldActive := d.store.ActiveConfig()

	var syncErr error
	compiled, syncErr = d.store.SyncApply(configText, chassisPreserve)
	if syncErr != nil {
		return nil, syncErr
	}
	if compiled == nil {
		// No config to reconcile (e.g. a no-op sync): nothing was promoted, so
		// there is no active-config session state to invalidate.
		return compiled, nil
	}

	// #5840: fail closed on a peer-synced standalone<->cluster topology
	// transition. SyncApply above has already promoted the peer config to
	// active (the store converges with the peer — no divergence, matching the
	// device-map passive-admission philosophy below), but the boot-only cluster
	// runtime cannot be constructed/torn down live (see
	// clusterTopologyCommitPreflight). Arming the dataplane under the
	// transitioned config would publish clustered forwarding semantics
	// (clusterHA=true) with no election/watchdog runtime — a persistent transit
	// drop — or tear HA down live. Return BEFORE applyConfigLocked so the live
	// dataplane is never mutated; a restart re-applies the now-active config
	// correctly through the boot path. armedActive is never set, so no session
	// invalidation runs. Keyed on the ACTUAL HA runtime (d.cluster != nil): a
	// node with no HA runtime (nil d.cluster — a divergent/config-less replay
	// target) receiving a clustered config is rejected, not armed with
	// clusterHA=true against a nil runtime. (Unreachable in a healthy cluster —
	// both members are already clustered and a node with no HA runtime has no
	// session-sync receiver — but a defense-in-depth backstop.)
	if terr := clusterTopologyCommitPreflight(d.cluster != nil, compiled); terr != nil {
		slog.Error("cluster: refusing to apply a peer-synced standalone<->cluster "+
			"topology transition live; a restart is required to (de)construct the "+
			"HA runtime", "err", terr)
		// #6720: SyncApply has already promoted this config, so the AUTHORIZATION
		// it carries is live policy even though the dataplane must not be armed
		// under it. The backstop's constraint is boot-only HA runtime
		// construction; reconcileWebManagement has no such constraint, and
		// skipping it leaves the listener honouring a credential the now-active
		// config revoked.
		d.reconcileManagementAfterPromotion(compiled, "peer-synced topology transition refused")
		return nil, terr
	}

	// #6192: fail closed on a peer-synced node-id / cluster-id identity change,
	// mirroring the topology backstop above. SyncApply has already promoted the
	// peer config to active, but the boot-constructed HA manager cannot be
	// re-keyed live (heartbeat/RETH-MAC/election identity is boot-only). Return
	// BEFORE applyConfigLocked so the live dataplane is never armed under a
	// mismatched identity; a restart re-applies the now-active config through the
	// boot path. In a healthy cluster this is unreachable — the synced text
	// compiles for the LOCAL node, so node-id resolves to this node's running id
	// and cluster-id is the shared value — but it is a defense-in-depth backstop
	// against a divergent replay.
	if ierr := clusterIdentityCommitPreflight(d.cluster, compiled); ierr != nil {
		slog.Error("cluster: refusing to apply a peer-synced node-id/cluster-id "+
			"identity change live; a restart is required to re-key the HA manager",
			"err", ierr)
		// #6720: same reasoning as the topology backstop above — the promoted
		// config's authorization is live policy regardless of the HA re-key
		// constraint that stops the apply.
		d.reconcileManagementAfterPromotion(compiled, "peer-synced identity change refused")
		return nil, ierr
	}
	// #8965: and refuse a LIVE control-endpoint move, which would restart
	// comms on the new address before the peer can be told about it.
	if eerr := clusterControlEndpointCommitPreflight(d.cluster, compiled); eerr != nil {
		slog.Error("cluster: refusing to apply a peer-synced node-id/cluster-id "+
			"identity change live; a restart is required to re-key the HA manager",
			"err", eerr)
		// #6720: same reasoning as the topology backstop above — the promoted
		// config's authorization is live policy regardless of the HA re-key
		// constraint that stops the apply.
		d.reconcileManagementAfterPromotion(compiled, "peer-synced identity change refused")
		return nil, eerr
	}

	// #8987: the INTERFACE half of the same tuple, on the peer-sync path.
	//
	// Safe here for a MEASURED reason, not an inherited one. The sibling above
	// is safe because PeerAddress is per-node, so a synced text compiles to this
	// node's own value and the gate no-ops. control-interface is not per-node at
	// all — in the shipped cluster config `peer-address` sits inside
	// `groups node0`/`node1` while `control-interface` sits outside them, one
	// shared value — so a synced text carries the identical string and the
	// comparison is trivially equal. Refusing a legitimate sync was the specific
	// risk #8987 named for this path, and this is why it does not materialise.
	if ferr := clusterControlInterfaceCommitPreflight(d.cluster, compiled); ferr != nil {
		slog.Error("cluster: refusing to apply a peer-synced control-INTERFACE "+
			"move live; applying it would restart cluster comms on an interface "+
			"the peer is not reachable over and durably partition the pair",
			"err", ferr)
		d.reconcileManagementAfterPromotion(compiled, "peer-synced control-interface move refused")
		return nil, ferr
	}

	// #9121: the CONFIG-SYNC endpoint half, on the peer-sync path.
	//
	// Safe here for a MEASURED reason, as its siblings' comments are. The
	// fabric arm is safe for #8965's reason: `fabric-peer-address` sits inside
	// `groups node0`/`node1` in the shipped cluster config, directly beside the
	// per-node `peer-address`, so a synced text compiles to this node's own
	// value and the comparison is equal. The interface arm is safe for #8987's
	// reason instead: `fabric-interface` is auto-derived from the LOCAL fabric
	// member, so both nodes carry the identical name.
	if serr := clusterSyncEndpointCommitPreflight(d.activeTransport(), compiled); serr != nil {
		slog.Error("cluster: refusing to apply a peer-synced config-sync endpoint "+
			"move live; applying it would restart cluster comms on an endpoint the "+
			"peer is not reachable over and durably partition the pair",
			"err", serr)
		d.reconcileManagementAfterPromotion(compiled, "peer-synced sync-endpoint move refused")
		return nil, serr
	}

	// #5564: SyncApply (above) has ALREADY promoted the peer config to active,
	// and once applyConfigLocked arms the dataplane snapshot this node is
	// forwarding under it. The three session invalidators
	// (clearSessionsForPolicyChanges: the #4234 deletion-clear, the
	// modified-policy re-eval, and the #4342 default-policy change) MUST
	// therefore run to bring surviving established sessions' authorization in
	// line with the now-active config. Skipping them is a security fail-open: a
	// session a peer-tightened/deleted policy should now DENY keeps forwarding
	// under its stale authorization — and because the store already holds the
	// incoming text, the next equal-active-text re-push takes handleConfigSync's
	// fast path and never re-enters here to correct it, making the omission
	// PERMANENT (and visible at failover).
	//
	// The invalidation runs from ONE deferred, guarded place (armedActive) so it
	// ALWAYS fires once the config reached active+armed — EVEN on a NON-FATAL
	// best-effort tail failure (host-inbound/lo0 nft, networkd, ...) that
	// applyConfigLocked joins and returns — and so a future early-return added
	// between the apply and here cannot re-introduce the skip. It does NOT run on
	// a genuinely-fatal apply (see below), where the config is not live-forwarding
	// and there is no session state to invalidate.

	// #6296: capture the convergence digest of the tree SyncApply just promoted,
	// while applySem is still held and BEFORE applyConfigLocked. The applied
	// marker is stamped from this captured value in the deferred below (only on
	// full success), so it records the config THIS sync actually applied — not a
	// re-read of s.active at stamp time. Before #6296 handleConfigSync stamped
	// MarkActiveApplied() AFTER syncAndApply released applySem, keyed to whatever
	// s.active was then: a concurrent secondary-side promoter (a local commit /
	// commit-confirmed rollback) landing in that post-release window, whose own
	// apply then failed non-fatally, could make the stamp key the WRONG
	// (unapplied) active digest, and a later re-push of that text would be falsely
	// treated as converged (TOCTOU). ActiveDigest keys the same space
	// ActiveApplied() reads (configTextDigest(s.active.Format())).
	appliedDigest := d.store.ActiveDigest()

	var armedActive bool
	defer func() {
		if !armedActive {
			return
		}
		// #5578: surface a PARTIAL session invalidation to handleConfigSync
		// (which logs it and returns it up the sync-recv path) so a peer-pushed
		// policy deletion/tightening that could not fully drop this node's synced
		// sessions is not silently swallowed. A non-fatal partial clear does not
		// abort the (already-promoted) sync — it is joined into the return only.
		// #5858/#7212: the ONE commit-time entry point (see the commit path
		// above). Policy clear only since #7212 moved the interface-input-filter
		// half into the dataplane.
		clearErr := d.reportSessionAuthorizationChanges(oldActive, compiled)
		// #1956 V-1 passive-node device-map admission gate (OQ-15.1 option
		// (a): passive gate + loud health alarm). The active node's strict
		// commit can only validate ITS OWN hardware (R-8), so a synced
		// config whose LOCAL device-map section would strand THIS node's
		// management on next boot must be surfaced loudly here. We do NOT
		// strip/modify the synced delta (that creates the config-divergence
		// overwrite loop AGY flagged); the stores stay identical and the
		// #1922 lifeline keeps mgmt reachable at runtime. The alarm is the
		// operator's signal that the peer-pushed map needs fixing before a
		// reboot. (Option (b), distributed pre-commit validation, is the
		// documented end-state follow-up.)
		d.deviceMapPassiveAdmissionAlarm(compiled)
		retErr = errors.Join(retErr, clearErr)
		// #6296: stamp the applied marker HERE — inside syncAndApply while
		// applySem is still held (this defer runs before the applySem.Release
		// defer registered above), keyed to the digest captured above from the
		// tree SyncApply promoted. Stamp only on FULL success (retErr == nil after
		// the clearErr join: no fatal or non-fatal apply error AND no partial
		// session-invalidation), matching the prior handleConfigSync gate which
		// stamped MarkActiveApplied only when syncAndApply returned nil. A no-op
		// on empty digest (nil-active defensive path) or a non-nil retErr leaves
		// the prior digest, so a config whose apply did not fully converge is never
		// marked applied — the #4957 invariant handleConfigSync's shortcut relies on.
		if retErr == nil {
			d.store.MarkAppliedDigest(appliedDigest)
		}
	}()

	// #5564: capture the apply error instead of returning early on ANY error.
	// applyErrSkipsPeerSync (shared with applyAndSyncCommitted) classifies the
	// two FATAL classes — a required-protocol-gate error (dataplane DISARMED,
	// #2138) or a daemon-stop context abort (#2926) — that mean the config is
	// NOT live-forwarding. On those, discard the config and return the error
	// WITHOUT invalidating (armedActive stays false; no spurious clear), exactly
	// as the pre-#5564 early-return and applyAndSyncCommitted's fatal branch did.
	// Every OTHER (non-fatal, best-effort tail) error leaves the config active +
	// the snapshot armed, so the invalidators still run and the tail error is
	// surfaced (joined with any partial-invalidation error), not swallowed.
	// #6948: arm the commit-time session-invalidation plan BEFORE the apply.
	// Only this caller holds the pre-commit active config — the store promoted
	// the new one upstream — and the invalidation's candidate set has to be READ
	// while the live rows still carry the OLD policy numbering it is derived
	// from. applyConfigLocked takes that capture at the publication boundary;
	// without the plan it falls back to the pre-#6948 post-apply scan, which
	// sweeps the sessions of whichever policy inherited a deleted policy's id.
	d.armPolicyInvalidationPlan(oldActive, compiled)
	applyErr := d.applyConfigLocked(d.applyCancelCtx(), compiled)
	if applyErrSkipsPeerSync(applyErr) {
		return nil, applyErr
	}
	armedActive = true
	return compiled, applyErr
}

// deviceMapPassiveAdmissionAlarm raises a loud, never-silent HA-health alarm
// when a peer-synced config's LOCAL device-map would strand this node's
// management on next boot. Stores are NOT modified (no divergence loop) — the
// alarm + the #1922 lifeline are the safety net. See syncAndApply.
func (d *Daemon) deviceMapPassiveAdmissionAlarm(synced *config.Config) {
	if synced == nil || !synced.Chassis.DeviceMap.Active() {
		return
	}
	nics, err := enumeratePresentNICsFn()
	if err != nil {
		// AGY MINOR-5: do not let a transient hardware-lookup failure
		// silently bypass the admission gate — log loudly so the operator
		// knows the peer map was applied unchecked.
		slog.Warn("HA CONFIG-SYNC: could not enumerate NICs to check the peer-pushed device-map "+
			"for a management-lockout; the config is applied UNCHECKED. Re-verify the device-map "+
			"on this node.", "err", err)
		return
	}
	lifelineName, _ := resolveLifelineCurrentName()
	if reason := deviceMapStrandsManagement(synced, nics, protectedForConfig(synced), lifelineName); reason != "" {
		slog.Error("HA CONFIG-SYNC ALARM: the peer-pushed device-map would STRAND this node's "+
			"management on next boot. The config is applied (stores stay consistent) and the "+
			"management lifeline keeps the box reachable now, but a reboot would lock this node "+
			"out. Fix the device-map on the primary and re-sync BEFORE rebooting this node.",
			"reason", reason)
	}
}

// commitConfirmedAndApply is the commit-confirmed analogue of
// commitAndApply. Same atomicity guarantees.
func (d *Daemon) commitConfirmedAndApply(ctx context.Context, authority configstore.CommitAuthority, minutes int, syncPeer peerSyncPolicy) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	// #5281: reject a commit-confirmed while a factory reset is in progress
	// (same rationale as commitAndApply — CommitConfirmed persists the candidate
	// and arms a rollback timer that would re-apply after the wipe).
	if d.isResetting() {
		return nil, errDaemonResetting
	}

	// #5848 generation-bound commit transaction (commit-confirmed variant).
	// #1956 R-8/V-3 device-map pre-flight: validate BOTH the candidate AND the
	// rollback target (the currently-active config, restored on a confirmed-commit
	// timeout) against present hardware. If EITHER would strand management on next
	// boot, reject while the operator is still connected — so when a timeout fires
	// the target is KNOWN-safe and is applied UNCONDITIONALLY (OQ-15.2, no
	// rollback-time abort). The pre-flight and the promotion are now bound to one
	// candidate generation, so a concurrent candidate edit cannot slip a different
	// candidate into the promotion after the pre-flight cleared the examined one.
	// The rollback target (active) is stable across the transaction: it changes
	// only under d.applySem, held here from pre-flight through the commit.
	oldActive, compiled, err := d.commitWithGenBinding(
		func(cand *config.Config) error {
			// #5840: same standalone<->cluster topology guard as commitAndApply,
			// keyed on the ACTUAL HA runtime (d.cluster != nil), not the old
			// config. The rollback target on a confirm timeout is the current
			// active config, so a rejected transition is not confirmable either —
			// reject it up front while the operator is still connected.
			if terr := clusterTopologyCommitPreflight(d.cluster != nil, cand); terr != nil {
				return terr
			}
			// #6192: same node-id / cluster-id restart boundary as commitAndApply.
			// The rollback target on a confirm timeout is the current active
			// config, so a rejected identity change is not confirmable either —
			// reject it up front while the operator is still connected.
			if ierr := clusterIdentityCommitPreflight(d.cluster, cand); ierr != nil {
				return ierr
			}
			// #8965: and refuse a LIVE control-endpoint move, which would restart
			// comms on the new address before the peer can be told about it.
			if eerr := clusterControlEndpointCommitPreflight(d.cluster, cand); eerr != nil {
				return eerr
			}
			// #8987: and the INTERFACE half of the same tuple, which strands the
			// peer identically. Wired at all three apply paths beside its
			// sibling — a gate at one is the partial-fix shape on a row whose
			// remaining half is silent.
			if ierr := clusterControlInterfaceCommitPreflight(d.cluster, cand); ierr != nil {
				return ierr
			}
			// #9121: and the CONFIG-SYNC endpoint, which is the field set the
			// two gates above should have been keyed on. They read the
			// HEARTBEAT pair, an exact proxy in control-link mode and no proxy
			// at all in fabric-transport mode, where the heartbeat never starts
			// and both of them no-op on the commit that partitions the pair.
			if serr := clusterSyncEndpointCommitPreflight(d.activeTransport(), cand); serr != nil {
				return serr
			}
			// #6707: the rollback target must be APPLIABLE, not merely
			// device-map safe. The timeout path applies it unconditionally
			// (OQ-15.2, see the rollback callback), so a target the dataplane
			// is guaranteed to refuse turns the safety net into a store-only
			// revert: the store says the target, forwarding stays on the
			// unconfirmed candidate, and the rollback is ANNOUNCED as done.
			// Decide it here, while the operator is still connected and
			// nothing has been promoted.
			// #9588: the Go refusal mirror decides, with the LIVE feed overlay
			// for this target (representability is feed-aware).
			rollbackTarget := d.store.ActiveConfig()
			if rerr := rollbackTargetAppliablePreflight(rollbackTarget, d.feedSnapshotsForConfig(rollbackTarget)); rerr != nil {
				return rerr
			}
			return d.deviceMapCommitPreflight(cand, d.store.ActiveConfig())
		},
		func(gen uint64) (*config.Config, error) {
			return d.store.CommitConfirmedGenAs(authority, minutes, gen)
		},
	)
	if err != nil {
		return nil, err
	}
	return d.applyAndSyncCommitted(oldActive, compiled, syncPeer)
}

// commitAndApplyOperator is the peer-sync-aware entry point for an
// OPERATOR-initiated plain commit. The gRPC, REST, and local interactive-shell
// commit handlers ALL route through it (#5054), so the peer-sync decision is
// made in one place and no longer depends on which management transport
// delivered the commit. It derives the decision from RG0 ownership
// (rg0ConfigSyncAuthority) — the same rule the push site (syncConfigToPeer)
// applies — so a commit that changes the shared firewall intent converges on
// the cluster peer regardless of the transport.
//
// Before #5054 only the gRPC handler passed syncPeer=true; REST and the local
// shell passed false, so a REST/shell commit on a healthy cluster left the
// standby on the PRIOR config until an unrelated transport-disconnect
// reverse-sync — an RG failover could then silently restore config the operator
// believed changed. Because the RG0-ownership gate makes the push a no-op on a
// standalone / non-owner node (identical to syncConfigToPeer's gate), the only
// behavior change is that REST and shell commits now converge the peer exactly
// as gRPC always did.
//
// The autonomous event-options engine deliberately does NOT use this wrapper: it
// commits with peerSyncNever (commitAndApply directly, see initEventEngine)
// because each node fires its remediation independently from that node's local
// RPM events and must not push node-local state to the peer.
func (d *Daemon) commitAndApplyOperator(ctx context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
	return d.commitAndApply(ctx, authority, comment, peerSyncIfRG0Authority)
}

// commitConfirmedAndApplyOperator is the commit-confirmed analogue of
// commitAndApplyOperator: the same transport-independent RG0-ownership peer-sync
// policy for an operator-initiated `commit confirmed` (#5054).
func (d *Daemon) commitConfirmedAndApplyOperator(ctx context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error) {
	return d.commitConfirmedAndApply(ctx, authority, minutes, peerSyncIfRG0Authority)
}

// executeConfirmedRollback is the daemon-owned commit-confirmed timeout
// rollback transaction (#1922 Item 1a). The configstore confirm timer
// fires this (via SetRollbackExecutor) on its own goroutine, NOT under
// the store lock. It acquires d.applySem FIRST, then promotes the store
// state (PromoteRollback) and re-applies the rolled-back config to the
// dataplane inside that single critical section, so a concurrent commit
// (which also holds d.applySem via commitAndApply / commitConfirmedAndApply)
// cannot interleave between store promotion and dataplane re-apply. This
// fixes both bugs the old CLI-registered centralRollbackFn callback had:
// the non-atomic promote-then-apply split-brain window, and service-mode
// (gRPC/REST/remote-cli) timeouts that never re-applied the dataplane
// because no interactive CLI.Run had registered the callback.
//
// Lock order is applySem -> s.mu (matches commitAndApply / syncAndApply):
// every store call made while applySem is held (PromoteRollback, and the
// store calls inside applyConfigLocked such as SetArchiveConfig) takes and
// releases s.mu internally — applySem is always acquired FIRST and s.mu is
// never held across an applySem acquisition, so there is no inversion.
func (d *Daemon) executeConfirmedRollback(gen uint64) {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)

	// #5281: a confirm-timeout rollback that fires after a factory reset wipe
	// would PromoteRollback (re-persisting the SSOT) and re-apply the rolled-back
	// config, re-rendering secrets. Skip it — the daemon is being wiped/stopped.
	if d.isResetting() {
		return
	}

	// Pre-rollback active config (the abandoned unconfirmed config, C2) for the
	// #4234 deletion-clear: a rollback that removes a policy the abandoned commit
	// added must drop that policy's sessions, same as any commit.
	oldActive := d.store.ActiveConfig()

	// #9615: a window recovered across a restart, possibly by a newer build,
	// was never pre-flighted here, and a feed-bound target may simply not be
	// ready yet. Decide before PromoteRollback, while nothing is promoted.
	if d.confirmRollbackTargetHandledAtFire(gen) {
		return
	}

	prevCfg, ok := d.store.PromoteRollback(gen)
	if !ok {
		// Superseded (nested CommitConfirmed / ConfirmCommit) or no
		// pending rollback target — nothing happened, nothing to apply.
		return
	}
	if prevCfg == nil {
		// #1922 Item 1b: first commit confirmed on a fresh store timed out.
		// The store already reverted to the empty tree AND persisted the
		// never-committed marker (PromoteRollback). A normal apply of an
		// empty config is WRONG here — it would resurrect the dataplane the
		// failed takeover started and leave a half-configured box. Instead
		// roll the daemon back to bootstrap mode: re-suppress takeover and
		// clean up the takeover artifacts (networkd files, FRR managed
		// section, dataplane attach) the failed first commit created, except
		// the management lifeline. Runs under d.applySem (held above).
		//
		// #6538: a nil prevCfg has a SECOND provenance — a window recovered by
		// recoverPendingConfirmLocked whose rollback target failed even the
		// lenient compile (so confirmPrevCfg was nil at re-arm time). The
		// runtime action is deliberately the SAME, and not branched: with no
		// compiled config to apply, the bootstrap/lifeline safe state is
		// exactly what #1960 prescribes for a present-but-uncompilable
		// committed config, and the next boot re-derives it from disk through
		// the main Load path. What DOES differ is the persistence, and the
		// store now decides that from the recorded confirmPrevFirst flag
		// rather than from this nil: the second provenance persists the target
		// as COMMITTED, so the box is not durably re-classified into
		// bootstrap. The log below therefore names both cases.
		slog.Warn("commit confirmed timed out with no compiled rollback target (first commit " +
			"on a fresh store, or a recovered rollback target that no longer compiles); " +
			"rolling back to BOOTSTRAP mode (removing interface/FRR/dataplane takeover, " +
			"keeping the management lifeline)")
		// #5868: enterBootstrapMode now attempts every teardown step best-effort
		// but returns an aggregated error (and has already logged each failed
		// step + the DEGRADED summary at ERROR) if any step did not converge.
		// This is a fire-and-forget rollback-timer callback with no downstream
		// success action to gate, so we do not swallow the outcome silently:
		// re-surface it once at the rollback-decision layer so the DEGRADED
		// state is attributable to THIS first-commit-timeout event and an
		// operator scraping for the timeout sees the box did not come back clean.
		if err := d.enterBootstrapMode(); err != nil {
			slog.Error("commit-confirmed first-commit rollback to bootstrap mode is DEGRADED: "+
				"teardown did not fully converge (see the teardown step errors above); "+
				"config-driven takeover state may remain partially live", "err", err)
		}
		// #6718: the store has promoted the empty tree to active, but this
		// branch returns without ever entering applyConfigLocked — the only
		// caller of reconcileWebManagement. Without this the listener stays
		// bound where the ABANDONED commit put it and its api-auth credential
		// keeps authenticating, authorised by a config the box has formally
		// abandoned. The empty active resolves to the --api-addr flag default
		// (loopback, no credential), which is exactly the endpoint the reverted
		// config implies.
		d.reconcileManagementAfterPromotion(d.store.ActiveConfig(),
			"first commit-confirmed timeout reverted to bootstrap")
		// #3868: no peer re-sync here. This branch reverts a FIRST commit on a
		// fresh store to the empty tree + bootstrap mode; the reverted active
		// carries no chassis-cluster/config-sync stanza, so syncConfigToPeer ->
		// pushConfigToPeer would no-op anyway (and a bootstrap node is not the
		// RG0 config authority). The divergence #3868 fixes is the NON-nil
		// rollback target below, where the standby holds a real abandoned
		// config (C2) as permanent active.
		return
	}
	// #1956 V-3/OQ-15.2: the non-nil rollback target is applied
	// UNCONDITIONALLY here — never aborted for device-map safety. Its
	// device-map safety was validated at commit-confirmed time (the R-8
	// pre-flight checks BOTH candidate and rollback target) for a window armed
	// in THIS process. A window Store.Load recovered was never pre-flighted
	// here, so #9615 re-runs the appliability check above, before promotion;
	// by the time control reaches this apply the target has passed it. Aborting here would diverge the
	// already-promoted store from the running dataplane (split-brain), which
	// is strictly worse than applying a validated target.
	//
	// The rollback re-apply is driven with a non-cancellable context (#2926):
	// the store has already been promoted to the rollback target, so the
	// dataplane MUST be brought into agreement unconditionally — aborting here
	// would re-open the split-brain this transaction exists to close.
	// #6948: arm the commit-time session-invalidation plan BEFORE the apply.
	// Only this caller holds the pre-commit active config — the store promoted
	// the new one upstream — and the invalidation's candidate set has to be READ
	// while the live rows still carry the OLD policy numbering it is derived
	// from. applyConfigLocked takes that capture at the publication boundary;
	// without the plan it falls back to the pre-#6948 post-apply scan, which
	// sweeps the sessions of whichever policy inherited a deleted policy's id.
	d.armPolicyInvalidationPlan(oldActive, prevCfg)
	// #9811: latch the outcome. The log alone left the node ENFORCING the
	// abandoned config C2 while the store, `show configuration`, the peer
	// resync and /health all reported C1, with nothing to retry it — this is a
	// timer callback with no caller to report to, unlike the commit path where
	// the operator sees the error and re-commits. noteConfigApplyResult also
	// DISCHARGES on success, so an apply that works needs no separate site.
	applyErr := d.applyConfigLocked(context.Background(), prevCfg)
	d.noteConfigApplyResult(applyErr)
	if applyErr != nil {
		slog.Error("commit confirmed auto-rollback dataplane apply failed", "err", applyErr)
	}
	// #5578: this is a background timer callback with no return path, so mirror
	// the applyConfigLocked handling above — a PARTIAL session invalidation
	// (enumerate/delete failure) is surfaced via a loud slog.Error rather than
	// being lost. The helper now RETURNS the error so the two returning call
	// sites (commit + peer-sync) join it into their result; here the log is the
	// only available surface.
	if err := d.reportSessionAuthorizationChanges(oldActive, prevCfg); err != nil {
		slog.Error("commit confirmed auto-rollback: policy session invalidation was PARTIAL; "+
			"some rolled-back-policy sessions may keep forwarding under stale authorization", "err", err)
	}
	// #3868: RE-SYNC the rolled-back config (C1) to the cluster peer. The
	// standby already received the unconfirmed config (C2) via config-sync
	// SyncApply, which arms NO confirm timer, so it holds C2 as its PERMANENT
	// active. PromoteRollback above reverted only THIS node's store to C1;
	// without this push the nodes DIVERGE (primary=C1, standby=C2) and a
	// failover would serve the abandoned C2. syncConfigToPeer reads the
	// now-promoted active (C1) via ShowActive and queues it, exactly like a
	// normal commit's sync. It self-guards the peer-absent/disconnected case
	// (nil cluster/sessionSync, not RG0 primary, config-sync disabled, or no
	// active TCP conn all no-op); the existing reverse-sync-on-reconnect
	// retries when the peer comes back. Runs under d.applySem (held above),
	// after PromoteRollback, so the pushed text is always the rollback target.
	d.resyncRolledBackConfigToPeer()
	slog.Warn("commit confirmed timed out, configuration rolled back")
}

// resyncRolledBackConfigToPeer pushes the just-promoted rollback-target config
// to the cluster peer after a commit-confirmed timeout (#3868). Delegates to
// pushCommittedConfigToPeer so the confirm-timeout rollback path is unit-testable
// without a live cluster transport: rollback_resync_test.go injects
// d.syncPeerForTest to observe the call; production leaves it nil and the real
// syncConfigToPeer runs. MUST be called with d.applySem held and AFTER
// PromoteRollback so d.store.ShowActive() (read inside syncConfigToPeer ->
// pushConfigToPeer) reflects the rolled-back config, not the abandoned
// unconfirmed one.
func (d *Daemon) resyncRolledBackConfigToPeer() {
	d.pushCommittedConfigToPeer()
}
