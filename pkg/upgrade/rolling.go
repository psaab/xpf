package upgrade

import (
	"errors"
	"fmt"
	"time"
)

// RollingCluster is the cluster-control surface the rolling driver needs.
// It is satisfied by a CLI/gRPC-backed implementation in production
// (cluster_cli.go) and a fake in tests. Every method acts on the LOCAL
// node's running daemon unless noted.
type RollingCluster interface {
	// PeerAlive reports whether the cluster peer is alive and reachable.
	PeerAlive() (bool, error)
	// SyncEstablished reports whether session-sync is established/clean.
	SyncEstablished() (bool, error)
	// HAProtocolCompatible reports whether the local and peer HA protocol
	// versions are mutually compatible (else the release is not
	// rolling-upgradable; the driver aborts to Path C image-replace).
	//
	// #7990: this used to say "HA/session-sync protocol versions". It does not
	// and never did look at the session-sync wire version — parseHAProtocolCompatible
	// reads only the two "HA protocol version" lines — and since #7925 the two
	// are separate counters, so the claim was not merely loose but wrong. The
	// session-sync half is SessionSyncWireCompatible below.
	HAProtocolCompatible() (bool, error)
	// SessionSyncWireCompatible reports whether the peer's session-sync WIRE
	// version is known to be compatible with this node's, plus a reason for
	// the log (#7990). An UNKNOWN peer version permits — see
	// cluster.SessionSyncWireCompatible for why refusing there would fire on
	// every roll from a pre-#7990 release and on no real skew.
	SessionSyncWireCompatible() (bool, string, error)
	// PeerTakeoverReady reports whether the PEER is ready to take over
	// (peer healthy, interface monitors green, not blocked by a hold) —
	// checked BEFORE demoting the local node so VIPs are never stranded.
	PeerTakeoverReady() (bool, error)
	// ForceSecondary demotes the local node (ISSU drain start).
	ForceSecondary() error
	// DrainComplete reports whether the STRONG drain predicate holds:
	// (a) peer owns the RGs (peer PRIMARY), (b) local VRRP is BACKUP with
	// no VIPs, (c) local rg_active is false, (d) sync clean.
	DrainComplete() (bool, error)
	// ResetFailover clears the manual failover and resumes normal election
	// (failback / let the upgraded node rejoin election).
	ResetFailover() error
	// LocalPrimary reports whether the local node currently owns the RGs
	// (used by the controlled-promotion forward-verify).
	LocalPrimary() (bool, error)
	// LocalRejoinComplete reports whether the local node has actually
	// resumed election eligibility for EVERY configured redundancy group
	// after ResetFailover — i.e. no configured RG is still held in the
	// ForceSecondary drain (weight 0). ResetFailover only REQUESTS the reset
	// per RG; a request that returned nil is not proof the RG left the drain,
	// and a client that could not enumerate an RG never issued its reset at
	// all. RejoinAndConfirm gates the "never both down" advance on this
	// per-RG check so a rejoin can never confirm while some configured RG
	// (e.g. RG>=3 the pre-#5044 {0,1,2} guess dropped) stays demoted with no
	// primary on either node (#5138). FAILS CLOSED: an enumeration error or a
	// configured RG missing from the local status reads as not-yet-rejoined.
	LocalRejoinComplete() (bool, error)
}

// RollingConfig tunes the rolling driver timing.
type RollingConfig struct {
	// DrainDeadline bounds the wait for the strong drain predicate.
	DrainDeadline time.Duration
	// RejoinDeadline bounds the wait for session-sync to re-establish
	// after the cut.
	RejoinDeadline time.Duration
	// PollInterval is the predicate poll cadence.
	PollInterval time.Duration
}

func (c *RollingConfig) withDefaults() {
	if c.DrainDeadline == 0 {
		c.DrainDeadline = 30 * time.Second
	}
	if c.RejoinDeadline == 0 {
		c.RejoinDeadline = 60 * time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = 500 * time.Millisecond
	}
}

// RunRolling cuts over the LOCAL clustered node with a controlled drain so
// the cluster keeps forwarding (plan §6.2 B1). Run it on each node in turn
// (the external driver / cluster-setup.sh sequences both); each invocation:
//
//  1. assert peer alive + sync established + HA proto compatible (else
//     ABORT — fall back to image-replace, never drop connections).
//  2. PEER-TAKEOVER-READY precheck BEFORE demoting (else VIP stranding).
//  3. ForceSecondary() to start the drain.
//  4. wait for the STRONG drain predicate (peer PRIMARY, local VRRP
//     BACKUP/no-VIPs, rg_active false, sync clean) — NOT merely weight-0.
//  5. single-node STOP->FLIP->START cut on the now-fully-drained node
//     (auto-rollback DISABLED: HA rollback is operator-driven).
//  6. wait for sync to re-establish.
//  7. ResetFailover() to rejoin normal election (the natural failback is
//     the controlled-promotion forward-verify — the upgraded node forwards
//     only once promoted; the external driver runs the iperf3 forward
//     check post-promotion via make test-failover, never while passive).
//
// If the drain predicate cannot be met within the deadline, ABORT WITHOUT
// cutting — the node is still forwarding, so no harm.
func RunRolling(r *Runner, cfg Config) error {
	// Acquire the host-wide upgrade lock at the rolling-driver ENTRY and
	// hold it through rejoin (#1965, plan §5). This covers the whole
	// window — peer-check + ForceSecondary + the drain wait + the cut +
	// the rejoin — not just the inner r.Run(). The inner r.Run() is
	// invoked with LockAlreadyHeld so it does NOT re-flock the same file
	// (a second flock on a fresh fd of the same path returns EWOULDBLOCK
	// and would abort the rolling upgrade). Release on every exit path.
	h, err := acquireUpgradeLock("upgrade --rolling", "")
	if err != nil {
		return fmt.Errorf("upgrade --rolling: %w", err)
	}
	defer func() { _ = h.Release() }()

	cl, err := NewCLICluster(cfg.Unit)
	if err != nil {
		return fmt.Errorf("upgrade --rolling: %w", err)
	}
	return runRollingWith(r, cl, RollingConfig{})
}

// RunRollingRollback performs the HA per-node rollback with the same
// host-wide lock and cluster-control surface as RunRolling.
func RunRollingRollback(r *Runner, cfg Config, target string) error {
	h, err := acquireUpgradeLock("upgrade --rollback --rolling", target)
	if err != nil {
		return fmt.Errorf("upgrade --rollback --rolling: %w", err)
	}
	defer func() { _ = h.Release() }()

	cl, err := NewCLICluster(cfg.Unit)
	if err != nil {
		return fmt.Errorf("upgrade --rollback --rolling: %w", err)
	}
	return runRollingRollbackWith(r, cl, RollingConfig{}, target)
}

// runRollingRollbackWith is the testable HA rollback core. It performs the
// rollback-specific restorable/snapshot/envelope gate before demoting the
// local node, then mirrors the forward rolling sequence around the destructive
// rollback cut.
func runRollingRollbackWith(r *Runner, cl RollingCluster, rc RollingConfig, target string) error {
	rc.withDefaults()

	// All rollback refusal checks happen before ForceSecondary. This includes
	plan, _, err := r.rollbackInvocationPlan(target)
	if err != nil {
		return fmt.Errorf("rolling rollback: %w", err)
	}

	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("rolling rollback: check peer alive: %w", err)
	}
	if !alive {
		return fmt.Errorf("rolling rollback: peer is not alive — refusing to drain the only forwarding node; bring the peer up first")
	}
	synced, err := cl.SyncEstablished()
	if err != nil {
		return fmt.Errorf("rolling rollback: check session sync: %w", err)
	}
	if !synced {
		return fmt.Errorf("rolling rollback: session sync not established — draining now would drop connections; aborting")
	}
	compat, err := cl.HAProtocolCompatible()
	if err != nil {
		return fmt.Errorf("rolling rollback: check HA protocol compatibility: %w", err)
	}
	if !compat {
		return fmt.Errorf("rolling rollback: HA/session-sync protocol is NOT compatible across the target; use image-replace")
	}
	syncOK, syncWhy, err := cl.SessionSyncWireCompatible()
	if err != nil {
		return fmt.Errorf("rolling rollback: check session-sync wire compatibility: %w", err)
	}
	if !syncOK {
		return fmt.Errorf("rolling rollback: session-sync WIRE version is NOT compatible with the peer (%s); use image-replace", syncWhy)
	}
	ready, err := cl.PeerTakeoverReady()
	if err != nil {
		return fmt.Errorf("rolling rollback: check peer takeover readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("rolling rollback: peer is NOT takeover-ready; aborting without draining")
	}

	r.logf("rolling: peer ready; forcing local secondary (rollback drain start)")
	if err := cl.ForceSecondary(); err != nil {
		return fmt.Errorf("rolling rollback: force secondary: %w", err)
	}
	if err := waitPredicate(rc, false, cl.DrainComplete); err != nil {
		r.logf("rolling: rollback drain predicate not met within %s; resetting failover and aborting", rc.DrainDeadline)
		if resetErr := cl.ResetFailover(); resetErr != nil {
			return fmt.Errorf("rolling rollback: strong drain predicate not satisfied AND failback failed: %w", errors.Join(err, resetErr))
		}
		rejoined, rerr := cl.LocalRejoinComplete()
		if rerr != nil || !rejoined {
			return fmt.Errorf("rolling rollback: strong drain predicate not satisfied; failback acknowledged but local rejoin is not confirmed: %w", err)
		}
		return fmt.Errorf("rolling rollback: strong drain predicate not satisfied; aborted WITHOUT cutting: %w", err)
	}
	r.logf("rolling: rollback drain complete (peer owns RGs, local backup, rg_active=false, sync clean)")

	if err := r.RollbackTo(plan.toVersion, RollbackOptions{
		ClusterCoordinated: true,
		LockAlreadyHeld:    true,
	}); err != nil {
		return fmt.Errorf("rolling rollback: single-node rollback failed (inspect the drained node): %w", err)
	}

	if err := waitPredicate(RollingConfig{
		DrainDeadline: rc.RejoinDeadline,
		PollInterval:  rc.PollInterval,
	}, true, cl.SyncEstablished); err != nil {
		return fmt.Errorf("rolling rollback: rolled-back node did not re-establish session sync within %s: %w", rc.RejoinDeadline, err)
	}
	r.logf("rolling: rolled-back node re-synced")
	if err := RejoinAndConfirm(cl, rc.RejoinDeadline); err != nil {
		return fmt.Errorf("rolling rollback: local node did not rejoin election after rollback within %s: %w", rc.RejoinDeadline, err)
	}
	r.logf("rolling: local node rejoined election, confirmed for every configured RG; rollback complete for this node")
	return nil
}

// runRollingWith is the testable core (cluster + timing injected). It does
// NOT acquire the upgrade lock — its only caller, RunRolling, holds it for
// the whole rolling window, and the inner r.Run() it invokes runs with
// LockAlreadyHeld so it does not re-flock (#1965).
func runRollingWith(r *Runner, cl RollingCluster, rc RollingConfig) error {
	rc.withDefaults()
	logf := r.logf

	// 1. Preconditions. Any failure aborts WITHOUT touching the dataplane.
	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("rolling: check peer alive: %w", err)
	}
	if !alive {
		return fmt.Errorf("rolling: peer is not alive — refusing to drain the only " +
			"forwarding node; upgrade via image-replace or bring the peer up first")
	}
	synced, err := cl.SyncEstablished()
	if err != nil {
		return fmt.Errorf("rolling: check session sync: %w", err)
	}
	if !synced {
		return fmt.Errorf("rolling: session sync not established — draining now would " +
			"drop connections; aborting (resolve sync or use image-replace)")
	}
	compat, err := cl.HAProtocolCompatible()
	if err != nil {
		return fmt.Errorf("rolling: check HA protocol compatibility: %w", err)
	}
	if !compat {
		return fmt.Errorf("rolling: HA/session-sync protocol is NOT compatible across " +
			"the staged version — this release is not rolling-upgradable; use " +
			"image-replace (Path C) with documented connection loss")
	}

	// #9037: the session-sync half of the compatibility check. The interface
	// has DECLARED this method since #7990 and the comment above says the
	// session-sync half "is SessionSyncWireCompatible below" — but nothing in
	// this function ever called it. Only the kernel-drain sibling
	// (kernel_drain.go) gated on it, so binary rolling drained into a peer
	// that may be unable to decode this node's session frames.
	//
	// A drain hands the RGs to the peer. If the peer cannot decode the
	// sessions, that handover drops every established flow while heartbeat,
	// election and failover all keep working — the cluster looks healthy and
	// the loss is discovered at the failover, not here.
	//
	// It MUST run before ForceSecondary below: a gate that fires after the
	// demotion has already cut the connections it exists to protect.
	syncOK, syncWhy, err := cl.SessionSyncWireCompatible()
	if err != nil {
		return fmt.Errorf("rolling: check session-sync wire compatibility: %w", err)
	}
	if !syncOK {
		return fmt.Errorf("rolling: session-sync WIRE version is NOT compatible with "+
			"the peer (%s) — draining would hand the RGs to a node that cannot "+
			"receive this node's sessions, dropping every established flow while "+
			"the cluster still looks healthy; use image-replace (Path C) with "+
			"documented connection loss", syncWhy)
	}

	// 2. Peer-takeover-ready precheck BEFORE demoting (else VIP stranding).
	ready, err := cl.PeerTakeoverReady()
	if err != nil {
		return fmt.Errorf("rolling: check peer takeover readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("rolling: peer is NOT takeover-ready (health / interface " +
			"monitors / hold) — demoting now would strand VIPs; aborting without " +
			"draining (local node still forwarding)")
	}

	// 3. Start the drain.
	logf("rolling: peer ready; forcing local secondary (drain start)")
	if err := cl.ForceSecondary(); err != nil {
		return fmt.Errorf("rolling: force secondary: %w", err)
	}

	// 4. Wait for the STRONG drain predicate. The local daemon is still up
	//    here, so a predicate error is NOT expected — fail fast (the abort
	//    direction below is safe: we have not cut yet, node still forwards).
	if err := waitPredicate(rc, false, cl.DrainComplete); err != nil {
		// Drain incomplete: fail back so we don't leave the node half-drained,
		// then abort. #5845: the ResetFailover (failback) error MUST NOT be
		// discarded. ForceSecondary above already DEMOTED the local node; if the
		// failback FAILS, the node may remain FORCE-DEMOTED with peer takeover
		// unproven — it is NOT "still forwarding", and claiming so hides a
		// possible both-nodes-secondary outage. Report BOTH failures and warn the
		// node may be STRANDED DEMOTED so an operator investigates, mirroring the
		// kernel-roll drain path (kernel_drain.go). Only when the failback
		// SUCCEEDS is the "aborted without cutting, node still forwarding" claim
		// true — keep it for that case.
		logf("rolling: drain predicate not met within %s; resetting failover and aborting", rc.DrainDeadline)
		if resetErr := cl.ResetFailover(); resetErr != nil {
			return fmt.Errorf("rolling: strong drain predicate not satisfied within %s "+
				"(peer-primary / local-VRRP-backup / rg_active-false / sync-clean) AND "+
				"failback (ResetFailover) FAILED — node may be STRANDED DEMOTED "+
				"(force-secondary not undone, peer takeover unproven); operator attention "+
				"needed: %w", rc.DrainDeadline, errors.Join(err, resetErr))
		}
		// #9038: a nil ResetFailover is an ACKNOWLEDGEMENT, not an observation.
		// The reset clears ManualFailover and re-runs the election; whether this
		// node reclaims the RG depends on the peer's position, so with a healthy
		// peer legitimately holding it the reset returns nil and the node stays
		// SECONDARY. Measured on the real cluster.Manager: peer alive, peer
		// owning the RG at the stronger position -> ResetFailover()==nil and
		// IsLocalPrimary()==false. Claiming "node still forwarding" there tells
		// the operator the opposite of the truth, and RejoinAndConfirm in this
		// same package already says a nil reset is not that proof.
		//
		// Read it back with the SAME predicate the rejoin path trusts, once and
		// without polling: this is an abort, and adding a deadline here would
		// make a failing path slower and able to hang.
		rejoined, rerr := cl.LocalRejoinComplete()
		if rerr != nil || !rejoined {
			return fmt.Errorf("rolling: strong drain predicate not satisfied within %s "+
				"(peer-primary / local-VRRP-backup / rg_active-false / sync-clean); "+
				"failback was ACKNOWLEDGED but this node has NOT resumed ownership of "+
				"every redundancy group (local-rejoined=%v readback-error=%v) — it is "+
				"NOT forwarding for at least one RG and operator attention is needed: %w",
				rc.DrainDeadline, rejoined, rerr, err)
		}
		return fmt.Errorf("rolling: strong drain predicate not satisfied within %s "+
			"(peer-primary / local-VRRP-backup / rg_active-false / sync-clean); "+
			"aborted WITHOUT cutting (node still forwarding, CONFIRMED by per-RG "+
			"readback): %w", rc.DrainDeadline, err)
	}
	logf("rolling: drain complete (peer owns RGs, local backup, rg_active=false, sync clean)")

	// 5. Single-node cut on the fully-drained node. Auto-rollback is
	//    DISABLED: HA rollback is operator-driven (plan §8 inv. 8).
	//    LockAlreadyHeld: RunRolling holds the host-wide upgrade lock for
	//    the whole rolling window, so the inner cut must NOT re-flock the
	//    same file (it would EWOULDBLOCK and abort) — #1965.
	//    ClusterCoordinated: this node was just drained to its peer (steps
	//    3-4 above), so the per-node cut is sanctioned even on a clustered
	//    node — it bypasses the #5284 pre-STOP cluster gate that refuses a
	//    BARE standalone cut on a member with /etc/xpf/node-id present.
	if err := r.Run(Options{SkipStartHealthRollback: true, LockAlreadyHeld: true, ClusterCoordinated: true}); err != nil {
		return fmt.Errorf("rolling: single-node cut failed (HA rollback is "+
			"operator-driven — inspect the node): %w", err)
	}

	// 6. Wait for sync to re-establish on the upgraded node. The cut just
	//    restarted xpfd, so the local gRPC socket is unavailable for the
	//    first few seconds (connection refused) — that is the EXPECTED
	//    transient, not a failure. Tolerate predicate errors and keep
	//    polling until RejoinDeadline; only the deadline (with the last
	//    observed error) aborts. Without this, the first dial failure
	//    short-circuits the wait and the RejoinDeadline tolerance is never
	//    used (false-negative abort while the daemon is healthily starting).
	if err := waitPredicate(RollingConfig{
		DrainDeadline: rc.RejoinDeadline,
		PollInterval:  rc.PollInterval,
	}, true, cl.SyncEstablished); err != nil {
		return fmt.Errorf("rolling: upgraded node did not re-establish session sync "+
			"within %s — leaving it secondary; operator should verify before "+
			"failing back: %w", rc.RejoinDeadline, err)
	}
	logf("rolling: upgraded node re-synced")

	// 7. Rejoin election (failback) and CONFIRM it before reporting the cut
	//    complete (#6557). ResetFailover only REQUESTS the reset, per RG; a
	//    call that returned nil is not proof any RG left the ForceSecondary
	//    drain, and a client that could not enumerate an RG never issued its
	//    reset at all. Step 6's SyncEstablished does not close that gap:
	//    PeerAlive and SyncEstablished are GLOBAL predicates that hold while
	//    an individual RG is still held at weight 0.
	//
	//    Left unconfirmed, a reset that is ACKed but not effected (e.g. a
	//    post-upgrade interface monitor pinning an RG at weight 0) leaves this
	//    node silently ineligible; the external driver advances to the peer,
	//    whose ForceSecondary then leaves that RG with NO PRIMARY ON EITHER
	//    NODE until the peer's DrainDeadline expires.
	//
	//    RejoinAndConfirm is the #5138 readback, and it was already declared on
	//    the RollingCluster interface right here in this file — it was simply
	//    never wired into this, its other caller. Reusing it (rather than
	//    open-coding a poll) also keeps the binary rolling cut and the LANE-1
	//    kernel roll on ONE definition of "rejoined", which is the property the
	//    external driver's never-both-down gate depends on.
	//
	//    The forward-verify is the natural post-promotion check the external
	//    driver runs (controlled promotion, never while passive).
	if err := RejoinAndConfirm(cl, rc.RejoinDeadline); err != nil {
		return fmt.Errorf("rolling: local node did not rejoin election after the cut "+
			"within %s — leaving it secondary; the driver MUST NOT advance to the peer "+
			"(draining it would leave a redundancy group with no primary on either "+
			"node): %w", rc.RejoinDeadline, err)
	}
	logf("rolling: local node rejoined election, confirmed for every configured RG; " +
		"cut complete for this node")
	return nil
}

// waitPredicate polls pred until it returns true or the deadline elapses.
//
// When tolerateTransientErr is false, the first predicate error aborts
// immediately (fail-fast). When true, a predicate error is treated as
// "not ready yet" — the poll continues until the deadline, and the last
// observed error is surfaced if the deadline elapses without success.
// The tolerant mode is for waits where an error is the EXPECTED transient
// (e.g. polling a gRPC socket that is briefly unavailable while the daemon
// restarts after a cut); the deadline is the backstop that still bounds it.
func waitPredicate(rc RollingConfig, tolerateTransientErr bool, pred func() (bool, error)) error {
	rc.withDefaults()
	end := time.Now().Add(rc.DrainDeadline)
	var lastErr error
	for {
		ok, err := pred()
		switch {
		case err != nil && !tolerateTransientErr:
			return err
		case err != nil:
			lastErr = err // keep polling; treat as not-ready
		case ok:
			return nil
		default:
			// Clean poll, just not ready yet — drop any stale earlier
			// error so a timeout reports the most recent state, not a
			// transient that has since cleared.
			lastErr = nil
		}
		if time.Now().After(end) {
			if lastErr != nil {
				return fmt.Errorf("predicate not satisfied within %s (last error: %w)", rc.DrainDeadline, lastErr)
			}
			return fmt.Errorf("predicate not satisfied within %s", rc.DrainDeadline)
		}
		// #7424: bound the sleep by the deadline. A raw Sleep(PollInterval)
		// here overshoots `end` by up to one interval, and the deadline check
		// above sits BEFORE the sleep — so a predicate that first becomes true
		// AFTER the deadline was accepted as satisfied within it, and a genuine
		// timeout was reported up to one interval late. This is the third
		// caller of the helper kernel_drain.go already used for the same bug in
		// this package (HelperHealthProbe, #5808).
		sleepBounded(end, rc.PollInterval)
	}
}
