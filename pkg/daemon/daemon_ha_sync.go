package daemon

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (d *Daemon) stopSyncReadyTimer() {
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	d.syncReadyTimerGen.Add(1)
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
		d.syncReadyTimer = nil
	}
}

func (d *Daemon) armSyncReadyTimer() {
	if d.cluster == nil || d.syncReadyTimeout <= 0 {
		return
	}
	timerGen := d.syncReadyTimerGen.Add(1)
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
	}
	timeout := d.syncReadyTimeout
	d.syncReadyTimer = time.AfterFunc(timeout, func() {
		if d.syncReadyTimerGen.Load() != timerGen || !d.syncPeerConnected.Load() {
			return
		}
		if d.cluster != nil && !d.cluster.IsSyncReady() {
			slog.Info("cluster: sync readiness timeout, releasing hold")
			d.cluster.SetSyncReady(true)
		}
	})
}

func (d *Daemon) onSessionSyncPeerConnected() {
	d.syncPeerConnected.Store(true)
	// #5863: a fresh connection is a new epoch. The config-sync reconciler
	// keys its "already pushed" marker on this epoch, so bumping it here forces
	// a re-push to the reconnected peer even if the prior connection had
	// already been satisfied.
	d.syncPeerConnEpoch.Add(1)
	d.hbSuppressStart.Store(0) // fresh connection → reset suppression cap

	// Determine whether this is a true cold start or a routine reconnect.
	// A cold start means no bulk sync has ever completed during this
	// daemon's lifetime — the peer (or we) genuinely started from scratch.
	// On a routine reconnect after a brief network blip, the sessions are
	// already synced; preserve the primed state and sync readiness (#466).
	ss := d.getSessionSync()
	coldStart := ss == nil || !ss.BulkEverCompleted()

	if coldStart {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer connected",
		"retry_gen", gen,
		"cold_start", coldStart,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())

	if coldStart {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
		d.armSyncReadyTimer()
		d.startSessionSyncPrimeRetry(gen)
	}
}

func (d *Daemon) onSessionSyncBulkReceived() {
	d.syncBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk received",
		"retry_gen", d.syncPrimeRetryGen.Load())
	d.stopSyncReadyTimer()
	if d.vrrpMgr != nil {
		d.vrrpMgr.ReleaseSyncHold()
		// #7162: the VRRP hold has recorded a reason since #466 and surfaced it
		// nowhere. Mirror it so an operator can tell a normal startup from one
		// that promoted degraded because sync never arrived.
		if d.cluster != nil {
			if r := d.vrrpMgr.SyncHoldReason(); r != "" {
				d.cluster.SetStartupSyncHoldStatus("reth-vrrp", d.vrrpMgr.InSyncHold(), r)
			}
		}
	}
	// #7162: the no-RETH sibling release. Unconditional, exactly like the VRRP
	// one above — a hold that is only released when some other subsystem is
	// present is a hold that outlives its purpose in the configuration that
	// needs it most.
	d.releaseNoRethSyncHold("bulk-sync-complete")
	if d.cluster != nil {
		d.cluster.SetSyncReady(true)
	}
}

func (d *Daemon) onSessionSyncBulkAckReceived() {
	d.syncPeerBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk ack received",
		"retry_gen", d.syncPrimeRetryGen.Load())
}

func (d *Daemon) onSessionSyncPeerDisconnected() {
	d.syncPeerConnected.Store(false)
	gen := d.syncPrimeRetryGen.Add(1)

	// On disconnect after a completed bulk exchange, preserve primed state
	// and sync readiness. The sessions are still in the BPF maps — a
	// subsequent reconnect will resume incremental sync without needing a
	// full bulk transfer (#466).
	ss := d.getSessionSync()
	wasEverPrimed := ss != nil && ss.BulkEverCompleted()
	if !wasEverPrimed {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	slog.Info("cluster: session sync peer disconnected",
		"retry_gen", gen,
		"was_ever_primed", wasEverPrimed,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	d.stopSyncReadyTimer()

	if !wasEverPrimed {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
	}
}

func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
	ss := d.getSessionSync()
	if ss == nil || !ss.IsConnected() {
		d.hbSuppressStart.Store(0) // reset when sync disconnected
		return false, ""
	}
	const maxPeerSyncSilence = 2 * time.Second
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		d.hbSuppressStart.Store(0) // reset when sync goes quiet
		return false, ""
	}

	// Cap total suppression duration. During graceful shutdown the peer
	// may send a bulk sync that keeps LastPeerReceiveAge() fresh for tens
	// of seconds while heartbeats have already stopped. After 5s of
	// continuous suppression, stop suppressing so the heartbeat timeout
	// can fire and trigger failover.
	//
	// The window is measured in CLOCK_MONOTONIC nanos (#1792): with
	// wall-clock UnixNano a backward step left suppression stuck on
	// (blocking failover for the step duration) and a forward step cut
	// it short.
	const maxSuppressDuration = 5 * time.Second
	now := cluster.MonotonicNanos()
	start := d.hbSuppressStart.Load()
	if start == 0 {
		d.hbSuppressStart.Store(now)
		start = now
	}
	if hbSuppressCapExceeded(start, now, maxSuppressDuration) {
		return false, ""
	}

	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

// hbSuppressCapExceeded reports whether continuous heartbeat-timeout
// suppression that began at startMono has lasted longer than cap by nowMono.
// Both timestamps are CLOCK_MONOTONIC nanos (cluster.MonotonicNanos), so the
// cap is immune to wall-clock steps (#1792). Split out so tests can inject
// timestamps and exercise step scenarios directly.
func hbSuppressCapExceeded(startMono, nowMono int64, capDur time.Duration) bool {
	return time.Duration(nowMono-startMono) > capDur
}

func syncPrimeProgressObserved(current, baseline cluster.SyncStatsSnapshot) bool {
	return current.SessionsReceived > baseline.SessionsReceived ||
		current.SessionsInstalled > baseline.SessionsInstalled ||
		current.DeletesReceived > baseline.DeletesReceived
}

func (d *Daemon) startSessionSyncPrimeRetry(gen uint64) {
	ss := d.getSessionSync()
	if ss == nil || d.dataplane() == nil {
		return
	}
	go func() {
		intervals := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
		const retryWhileAckPendingAfter = 35 * time.Second
		maxAttempts := len(intervals)
		baseline := ss.Stats()
		slog.Info("cluster: starting session sync bulk-prime retry loop",
			"retry_gen", gen,
			"max_attempts", maxAttempts,
			"intervals", intervals)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if wait := intervals[attempt-1]; wait > 0 {
				time.Sleep(wait)
			}
			if d.syncPrimeRetryGen.Load() != gen {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "generation advanced")
				return
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer bulk ack received")
				return
			}
			if cur := d.getSessionSync(); cur != ss || !ss.IsConnected() {
				reason := "session sync replaced"
				if cur == ss && !ss.IsConnected() {
					reason = "session sync disconnected"
				}
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", reason)
				return
			}
			if pendingEpoch, pendingAge, ok := ss.PendingBulkAck(); ok && pendingAge < retryWhileAckPendingAfter {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "outbound bulk still awaiting ack",
					"pending_epoch", pendingEpoch,
					"pending_age", pendingAge.Round(10*time.Millisecond),
					"retry_after", retryWhileAckPendingAfter)
				continue
			}
			current := ss.Stats()
			if syncPrimeProgressObserved(current, baseline) {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer sync progress observed",
					"sessions_received", current.SessionsReceived,
					"sessions_installed", current.SessionsInstalled,
					"deletes_received", current.DeletesReceived,
					"baseline_sessions_received", baseline.SessionsReceived,
					"baseline_sessions_installed", baseline.SessionsInstalled,
					"baseline_deletes_received", baseline.DeletesReceived)
				baseline = current
				continue
			}
			slog.Info("cluster: retrying session sync bulk prime",
				"retry_gen", gen,
				"attempt", attempt,
				"connected", ss.IsConnected(),
				"sessions_received", current.SessionsReceived,
				"sessions_installed", current.SessionsInstalled,
				"deletes_received", current.DeletesReceived,
				"baseline_sessions_received", baseline.SessionsReceived,
				"baseline_sessions_installed", baseline.SessionsInstalled,
				"baseline_deletes_received", baseline.DeletesReceived)
			if err := d.bulkSyncViaEventStreamOrFallback(ss); err != nil {
				slog.Warn("cluster: session sync bulk prime retry failed",
					"retry_gen", gen,
					"attempt", attempt,
					"err", err)
				continue
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: session sync bulk prime retry loop observed bulk ack",
					"retry_gen", gen,
					"attempt", attempt)
				return
			}
		}
		slog.Warn("cluster: session sync bulk-prime retry loop exhausted",
			"retry_gen", gen,
			"attempts", maxAttempts)
	}()
}

// bulkSyncViaEventStreamOrFallback attempts to export all sessions via the
// event stream (fast path — sessions flow through the existing event stream
// callback into QueueSessionV4/V6). Falls back to the old BulkSync path
// (iterating BPF maps from Go) when the event stream isn't available.
func (d *Daemon) bulkSyncViaEventStreamOrFallback(ss *cluster.SessionSync) error {
	// userspaceEventStreamExporter is a local probe satisfied by
	// *dataplane/userspace.LegacyDataPlaneAdapter via
	// ExportAllSessionsViaEventStream (legacy_dataplane.go:422).
	// Type-assertion target is the published dataplane directly — the
	// legacyDP() round-trip retired in #1519 added no method-set coverage.
	// #2114: ONE snapshot feeds the nil-check, the assertion, and the %T
	// log below (plan §5.3 rules 3/9).
	rt := d.dataplane()
	if rt != nil {
		if exporter, ok := rt.(userspaceEventStreamExporter); ok {
			slog.Info("cluster: using event stream export for bulk sync")
			if err := exporter.ExportAllSessionsViaEventStream(); err != nil {
				slog.Warn("cluster: event stream bulk export failed, falling back to BulkSync", "err", err)
			} else {
				slog.Info("cluster: exported sessions via event stream for bulk sync")
				return nil
			}
		}
	}
	slog.Info("cluster: event stream export not available, falling back to BulkSync",
		"dp_type", fmt.Sprintf("%T", rt))
	if ss == nil {
		return fmt.Errorf("session sync not initialized")
	}
	return ss.BulkSync()
}

// rg0ConfigSyncAuthority is the SINGLE, transport-independent rule for whether
// this node should push its committed config to the cluster peer (#5054): the
// node must be the RG0 (config-ownership group) PRIMARY of a configured cluster.
// It depends only on cluster/RG0 state — never on which management transport
// (gRPC, REST, or the local interactive shell) delivered the commit — so every
// operator commit path resolves the peer-sync decision identically and the two
// nodes cannot diverge by transport.
//
// A nil manager (a standalone, non-cluster node) is never an authority, so a
// standalone node never attempts a peer push. Kept as a small pure function so
// the decision is unit-testable in isolation and is reused by BOTH the operator
// commit entry points (commitAndApplyOperator / commitConfirmedAndApplyOperator)
// and the actual push site (syncConfigToPeer below), so the attempt-time and
// push-time gates cannot drift.
func rg0ConfigSyncAuthority(cl *cluster.Manager) bool {
	return cl != nil && cl.IsLocalPrimary(0)
}

// peerSyncPolicy is what a COMMITTER wants done about the cluster peer. It is
// deliberately not a bool, because the two false-ish answers a bool conflates
// are the whole of #5962:
//
//   - peerSyncNever — "this commit must never reach the peer". The autonomous
//     event-options engine means this: each node fires its own remediation from
//     its own RPM events, and pushing that node-local state would overwrite the
//     peer's. It is a POLICY, and it is true whatever this node owns.
//   - peerSyncIfRG0Authority — "push it if this node is the RG0 config
//     authority". That is a fact about the CURRENT cluster state, and it can
//     change under the committer's feet.
//
// #5054 collapsed both into a bool by evaluating rg0ConfigSyncAuthority in
// commitAndApplyOperator, at ATTEMPT time — before store.Commit's
// ensureWritableLocked. A node promoted to RG0 primary between those two points
// committed successfully and then skipped the push, because the attempt-time
// answer had already been frozen into `false`. The pre-#5058 gRPC path did not
// have that window: it passed an unconditional true and let the push site
// decide. Carrying the POLICY rather than its resolved value restores that —
// wantsPush is evaluated once, after the commit succeeded, at the point the
// push is actually made.
//
// peerSyncAlways exists for tests and for a caller that has already established
// authority; production has no such caller today.
type peerSyncPolicy uint8

const (
	peerSyncNever peerSyncPolicy = iota
	peerSyncAlways
	peerSyncIfRG0Authority
)

// wantsPush resolves the policy against the cluster state AT THE MOMENT OF
// ASKING. Call it at the push decision point, never earlier: an
// authority-gated policy resolved early is exactly the #5962 TOCTOU.
func (p peerSyncPolicy) wantsPush(cl *cluster.Manager) bool {
	switch p {
	case peerSyncAlways:
		return true
	case peerSyncIfRG0Authority:
		return rg0ConfigSyncAuthority(cl)
	default:
		return false
	}
}

// syncConfigToPeer sends the active config to the cluster peer if this node is
// the RG0 config-sync authority and config sync is enabled.
func (d *Daemon) syncConfigToPeer() {
	if d.getSessionSync() == nil {
		return
	}
	// Only sync if this node is the RG0 (config ownership group) primary — the
	// same rule the operator commit entry points use to decide whether to
	// attempt a push (#5054).
	if !rg0ConfigSyncAuthority(d.cluster) {
		return
	}
	d.pushConfigToPeer()
}

// pushConfigToPeer sends the active config to the cluster peer. The FUNCTION
// itself does not check primary/secondary status — the gate lives at the call
// site.
//
// Its only production caller is syncConfigToPeer, which gates on
// rg0ConfigSyncAuthority. The peer-reconnect path no longer arrives here: since
// #5863 it runs through reconcileConfigSyncToPeer, which is RG0-primary-gated
// too (so a reconnecting SECONDARY never overwrites the authoritative primary's
// config — #2239/#4385) and calls QueueConfig directly. Those two are the ONLY
// production QueueConfig sites, which is why configGenCounter advances only on
// the RG0 config-sync authority — the property the #5274 config-epoch guard and
// the #6419 disposition both rest on. (Only, not atomically: both sites sample
// authority and then queue several statements later, so a demotion landing in
// that gap can still let one already-authorized increment through. It is a
// steady-state property, not a mutual-exclusion guarantee.) Adding an ungated
// push here would break it outright.
func (d *Daemon) pushConfigToPeer() {
	ss := d.getSessionSync()
	if ss == nil {
		return
	}
	// Check if config sync is enabled.
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		return
	}
	// Get the active config tree as text.
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	ss.QueueConfig(configText)
	// #5863: record the reconcile marker so the level-triggered reconciler
	// treats this generation as already pushed on the current connection
	// epoch and does not redundantly re-push it. Only mark when a peer
	// connection is actually up — QueueConfig no-ops with no active conn, and
	// a later (re)connect bumps the epoch so the reconciler pushes fresh.
	if d.syncPeerConnected.Load() {
		d.markConfigSyncPushed(configText)
	}
}

// configGenerationHash reduces the active config text to a compact generation
// token (#5863). The reconciler pushes at most once per (peer-connection-epoch
// × generation); a new commit changes the text and therefore the generation,
// so a config change while a peer stays connected re-pushes exactly once.
func configGenerationHash(configText string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(configText))
	return h.Sum64()
}

// configSyncStableAfter is the uptime a node must have before it is trusted to
// push its on-disk config to a peer (#5863). A freshly booted node must not
// overwrite the peer with stale config before it has settled; the default
// mirrors the historical 30s connect-edge gate. Overridable for tests.
func (d *Daemon) configSyncStableAfter() time.Duration {
	if d.configSyncStable > 0 {
		return d.configSyncStable
	}
	return 30 * time.Second
}

// markConfigSyncPushed records that configText's generation has been pushed to
// the peer on the current connection epoch (#5863). Any push path (commit sync
// or the reconciler) records through here so the marker always reflects the
// latest generation pushed on the live connection, and a redundant reconcile is
// a no-op.
func (d *Daemon) markConfigSyncPushed(configText string) {
	gen := configGenerationHash(configText)
	epoch := d.syncPeerConnEpoch.Load()
	d.configSyncMu.Lock()
	d.configSyncHasPushed = true
	d.configSyncPushedEpoch = epoch
	d.configSyncPushedGen = gen
	d.configSyncMu.Unlock()
}

// invalidateConfigSyncPushed clears the #5863 (epoch x generation) push marker
// so the next reconcile trigger re-pushes the active config to the peer
// (#7328).
//
// The marker is claimed BEFORE the push and nothing else ever clears it, so a
// generation the peer refused or failed to apply is otherwise never sent again
// on the live connection — convergence would wait for a new commit (new
// generation) or a reconnect (new epoch). That silently defeats the M-2/#4151
// contract, which pins the peer's high-water on a failed apply SPECIFICALLY to
// keep it eligible for a re-push of the same generation.
//
// It deliberately does NOT push inline. Clearing the marker and letting the
// ordinary reconcile tick do the work bounds the retry to the reconciler's
// cadence, so a failure that recurs immediately cannot become a
// push/fail/nack tight loop on the shared control path. The peer's next nack
// re-arms it again, so a persistent failure retries at that cadence
// indefinitely rather than converging silently or storming.
func (d *Daemon) invalidateConfigSyncPushed() {
	d.configSyncMu.Lock()
	d.configSyncHasPushed = false
	d.configSyncPushedEpoch = 0
	d.configSyncPushedGen = 0
	d.configSyncMu.Unlock()
}

// reconcileConfigSyncToPeer is the level-triggered config-sync reconciler
// (#5863). It re-evaluates the desired invariant — "if I am the RG0 config
// authority AND stable (uptime ≥ stability threshold) AND a peer is connected
// AND config sync is enabled AND I have not already pushed my current config
// generation on this peer's current connection, then push it (once)" — and
// pushes ONLY when desired-vs-actual diverges.
//
// It replaces the old edge-triggered OnPeerConnected-only push, which evaluated
// the primary/stability gates solely at connect time: a later RG0 promotion or
// the crossing of the stability threshold never re-pushed, so a peer that
// connected while this node was secondary (or freshly booted) could stay
// INDEFINITELY divergent until an unrelated commit/reconnect. The reconciler is
// invoked on every input change (peer (re)connect, RG0 promotion, stability
// timer, and a low-frequency safety-net tick).
//
// Control-socket safety (CLAUDE.md): the config push is heavy and the userspace
// control socket is shared. The (epoch × generation) marker guarantees AT MOST
// ONE push per connection per config generation — once satisfied every further
// call is a cheap no-op (state gates + one hash, no QueueConfig), so a
// safety-net tick or a burst of triggers cannot storm the socket or starve
// session installs during bulk sync. It stays RG0-primary-gated exactly like
// the old connect edge, so a reconnecting SECONDARY never overwrites the
// authoritative primary's config (#2239/#4385).
func (d *Daemon) reconcileConfigSyncToPeer(reason string) {
	ss := d.getSessionSync()
	if ss == nil && d.configSyncPushForTest == nil {
		return
	}
	// Desired-state gates, re-read fresh on every call (persistent state, not
	// a captured edge).
	if !d.syncPeerConnected.Load() {
		slog.Debug("cluster: config-sync reconcile skip (no peer connection)", "reason", reason)
		return
	}
	if !rg0ConfigSyncAuthority(d.cluster) {
		slog.Debug("cluster: config-sync reconcile skip (not RG0 primary)", "reason", reason)
		return
	}
	if time.Since(d.startTime) < d.configSyncStableAfter() {
		slog.Debug("cluster: config-sync reconcile skip (uptime below stability threshold)", "reason", reason)
		return
	}
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		slog.Debug("cluster: config-sync reconcile skip (config sync disabled)", "reason", reason)
		return
	}
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	gen := configGenerationHash(configText)
	epoch := d.syncPeerConnEpoch.Load()

	// Check-and-claim the (epoch × generation) marker under one lock so two
	// concurrent triggers (e.g. a promotion racing the safety-net tick) push
	// at most once. Claim the marker BEFORE the push: a failed/dropped send
	// disconnects, and the next (re)connect bumps the epoch so the reconciler
	// re-pushes on the fresh connection.
	d.configSyncMu.Lock()
	if d.configSyncHasPushed && d.configSyncPushedEpoch == epoch && d.configSyncPushedGen == gen {
		d.configSyncMu.Unlock()
		slog.Debug("cluster: config-sync reconcile no-op (already pushed for epoch/generation)",
			"reason", reason, "epoch", epoch, "generation", gen)
		return
	}
	d.configSyncHasPushed = true
	d.configSyncPushedEpoch = epoch
	d.configSyncPushedGen = gen
	d.configSyncMu.Unlock()

	slog.Info("cluster: config-sync reconcile pushing config to peer",
		"reason", reason, "epoch", epoch, "generation", gen, "size", len(configText))
	if d.configSyncPushForTest != nil {
		d.configSyncPushForTest()
		return
	}
	ss.QueueConfig(configText)
}

// configSyncReconcileLoop is the low-frequency level-triggered safety net for
// config sync (#5863). It wakes at the stability threshold (so a node that was
// too young to push at connect time reconciles the moment it crosses the
// threshold) and thereafter on a coarse periodic tick that recovers any dropped
// promotion/connect edge. Every wake is a no-op once the (epoch × generation)
// marker is satisfied, so it never adds sustained control-socket traffic.
func (d *Daemon) configSyncReconcileLoop(ctx context.Context) {
	const periodic = 30 * time.Second
	for {
		// Wake at the stability threshold while still too young to push, else
		// on the coarse periodic tick.
		delay := periodic
		if until := d.configSyncStableAfter() - time.Since(d.startTime); until > 0 {
			delay = until
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			d.reconcileConfigSyncToPeer("reconcile-loop")
		}
	}
}

// errConfigSyncRejectedPrimary is returned by handleConfigSync when this node
// believes it is the RG0 primary (config authority) and therefore refuses the
// peer's config. It is NOT an apply failure per se, but the config was not
// applied, so the caller (configApplyLoop) must NOT advance the config
// high-water mark — the transient dual-active window must heal via the peer's
// re-push once this node settles into secondary (M-2/#4151).
var errConfigSyncRejectedPrimary = errors.New("config sync rejected: this node is RG0 primary")

// handleConfigSync processes a config received from the cluster peer.
// Config sync is unidirectional: primary → secondary only. If this node
// is the RG0 primary (config authority), incoming config is rejected to
// prevent a reconnecting secondary from overwriting the authoritative config.
//
// It returns nil ONLY when the config was actually applied (or already matches
// the active config); a non-nil error means the apply did not take effect. The
// config high-water mark advances ONLY on a nil return (M-2/#4151), so a
// rejection or a compile/promote failure leaves the standby eligible for the
// primary's re-push instead of being silently stranded on the prior config.
func (d *Daemon) handleConfigSync(configText string) error {
	if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
		slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
		return errConfigSyncRejectedPrimary
	}
	if d.store != nil {
		activeText := strings.TrimSpace(d.store.ShowActive())
		incomingText := strings.TrimSpace(configText)
		// #4957: the shortcut requires BOTH that the incoming config is the active
		// tree AND that the active tree actually completed its apply. SyncApply
		// promotes s.active BEFORE applyConfigLocked and (per the #1799
		// degrade-not-fail doctrine) does NOT roll it back on a non-fatal apply
		// failure, so active-text equality alone would treat a promoted-but-
		// UNAPPLIED config as converged: the primary's same-generation re-push
		// would take this fast path, return nil, and advance the config high-water
		// past a config whose dataplane never converged (a stale/disarmed standby
		// that reports the generation applied — visible at failover). Gating on
		// ActiveApplied() lets a re-push of a config whose prior apply failed fall
		// through to syncAndApply and RE-ATTEMPT the apply instead.
		if activeText == incomingText && d.store.ActiveApplied() {
			slog.Info("cluster: skipping config sync apply (config already matches active and is applied)",
				"size", len(configText))
			// Already converged to this config — a nil return lets the
			// high-water advance so a duplicate re-push is correctly skipped.
			return nil
		}
	}
	slog.Info("cluster: accepting config sync from peer", "size", len(configText))

	// #846: route through syncAndApply so the peer's
	// SyncApply(active promotion) + applyConfig run atomically
	// under d.applySem. Without this, a local commitAndApply could
	// interleave between the two and briefly leave store and kernel
	// disagreeing.
	// #7441: pin this node's node-local chassis leaves across the peer's push.
	// An unauthenticated session-sync stream reaches this function on a STANDBY
	// (the guard above refuses only on the RG0 primary), so a hostile admitted
	// connection could otherwise push a tree that clears the very posture that
	// exists to evict it — #5078's "an admitted peer must not re-arm the
	// window". The hook is shared with #6629's eventual node-local posture; see
	// preserveNodeLocalChassis for the contract.
	if _, err := d.syncAndApply(context.Background(), configText,
		preserveNodeLocalChassis(d.activeTreeForNodeLocal())); err != nil {
		slog.Error("cluster: config sync apply failed", "err", err)
		return err
	}
	// #4957/#6296: on full success syncAndApply itself stamps the applied marker
	// — from a digest captured for the config it applied, while still holding
	// applySem — so a duplicate re-push takes the converged shortcut above, and a
	// config that only PROMOTED active but failed to apply does NOT (keeping the
	// high-water pinned until a retry lands). The stamp moved INTO syncAndApply
	// (from a post-applySem-release MarkActiveApplied here) so a concurrent
	// secondary-side promoter mutating s.active in the release window can no
	// longer make the marker key the wrong, unapplied active digest (#6296).
	slog.Info("cluster: config sync applied successfully")
	return nil
}

// getSessionSync returns the currently-published cluster session-sync object
// under clusterCommsMu (#4958). It is nil when cluster comms are stopped or
// still constructing. Every reader outside the constructor MUST go through this
// accessor rather than touching d.sessionSync directly: the field is published
// asynchronously by the startClusterComms constructor goroutine and nilled by
// stopClusterComms, so a bare field read races the write (and a bare
// `d.sessionSync != nil && d.sessionSync.X()` can nil-deref if stop nils
// between the two loads). Callers capture the returned pointer once and operate
// on it — the lock is never held across a call into SessionSync.
func (d *Daemon) getSessionSync() *cluster.SessionSync {
	d.clusterCommsMu.Lock()
	ss := d.sessionSync
	d.clusterCommsMu.Unlock()
	return ss
}

// getClusterCommsCtx returns the live cluster-comms sub-context under
// clusterCommsMu (#4958). Nil when comms are stopped. Comms-scoped loops that
// (re)launch from the apply path (e.g. the DHCP lease-sync loop) read it here
// so a concurrent stopClusterComms nilling the field does not race them.
func (d *Daemon) getClusterCommsCtx() context.Context {
	d.clusterCommsMu.Lock()
	ctx := d.clusterCommsCtx
	d.clusterCommsMu.Unlock()
	return ctx
}

// snapshotFabricRefreshChans returns the current fabric refresh channels under
// clusterCommsMu (#4958). The populateFabricFwd loops receive their channel by
// value at launch; only the sender (triggerFabricRefresh) reads the live fields,
// so this snapshot is the single synchronized read point.
func (d *Daemon) snapshotFabricRefreshChans() (chan struct{}, chan struct{}) {
	d.clusterCommsMu.Lock()
	ch0, ch1 := d.fabricRefreshCh, d.fabricRefreshCh1
	d.clusterCommsMu.Unlock()
	return ch0, ch1
}

// beginClusterCommsEpoch opens a new cluster-comms epoch (#4958): it bumps
// clusterCommsGen, installs a fresh independently-cancellable sub-context, and
// returns the context plus the epoch generation the constructor goroutine must
// present at publish time. Bumping the counter here means a constructor from a
// prior epoch (still resolving addresses) is already superseded before this
// call returns, so its later publish is dropped.
//
// #7071: the cancel func is returned as well, so a caller that discovers its
// epoch was superseded before it wired anything can release the sub-context it
// just created. It cannot reach that cancel through the field: a newer epoch has
// by then overwritten `clusterCommsCancel` with its OWN, and calling that would
// tear down the live epoch instead.
func (d *Daemon) beginClusterCommsEpoch(
	parent context.Context,
) (context.Context, uint64, context.CancelFunc) {
	commsCtx, commsCancel := context.WithCancel(parent)
	d.clusterCommsMu.Lock()
	d.clusterCommsGen++
	gen := d.clusterCommsGen
	d.clusterCommsCancel = commsCancel
	d.clusterCommsCtx = commsCtx
	d.clusterCommsMu.Unlock()
	return commsCtx, gen, commsCancel
}

// publishSessionSyncIfCurrent installs ss as the live session-sync object iff
// gen still matches the current cluster-comms epoch (#4958). It returns false —
// dropping the publish — when a restart (stopClusterComms / a newer
// startClusterComms) has advanced the generation since this constructor started,
// so a late constructor from a superseded epoch never overwrites the newer
// epoch's session/endpoints (the stale-overwrite failure) and never resurrects a
// session that stop is tearing down (the nil-deref failure). The generation
// check and the store happen under the same lock so they cannot interleave with
// a concurrent stop.
func (d *Daemon) publishSessionSyncIfCurrent(gen uint64, ss *cluster.SessionSync) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale session-sync publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	// #6650: stamp this node's config-snapshot protocol version onto every
	// session-sync instance as it is published, so the peer's commit path can
	// refuse to push a config this node cannot represent. Done HERE rather than
	// at the construction site because publishSessionSyncIfCurrent is the one
	// generation-gated point every live instance passes through -- a stamp at
	// construction would also stamp instances a superseded epoch drops.
	ss.SetLocalSnapshotProtocolVersion(userspace.ProtocolVersion)
	d.sessionSync = ss
	return true
}

// publishFabricRefreshChansIfCurrent installs the fabric refresh channels iff
// gen still matches the current epoch (#4958), mirroring
// publishSessionSyncIfCurrent so a superseded constructor does not replace a
// newer epoch's channels.
func (d *Daemon) publishFabricRefreshChansIfCurrent(gen uint64, ch0, ch1 chan struct{}) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale fabric-refresh channel publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	d.fabricRefreshCh = ch0
	d.fabricRefreshCh1 = ch1
	return true
}

// startClusterComms starts heartbeat and session sync after VRFs are created.
// Called after applyConfig so that control/fabric interfaces are already in
// the management VRF (if configured).
//
// The sub-constructions were extracted into focused builders in #6428
// (daemon_ha_comms_wiring.go); what remains here is the control-flow spine,
// because the ORDER below is the contract:
//
//   - beginClusterCommsEpoch runs FIRST: it bumps clusterCommsGen and installs
//     the cancellable sub-context every goroutine spawned below captures and
//     every publish presents.
//   - resolveClusterVRFDevice runs before the heartbeat goroutine and before
//     the sync constructor goroutine; both take vrfDevice by value.
//   - syncRGStrictVIPOwnershipMode runs before the heartbeat goroutine: once
//     VRRP starts driving rg_active it must already follow VIP ownership.
//   - clusterCommsWG.Add(1) executes on THIS stack, never inside the goroutine,
//     so stopClusterComms cannot Wait() past an unregistered constructor.
//   - inside the constructor goroutine: address resolution -> ss construction ->
//     publishSessionSyncIfCurrent -> ALL wiring -> ss.Start. Every ss.On*
//     callback, cluster-Manager hook and SetVRFDevice must be installed before
//     Start, which spawns the accept/connect goroutines whose first connection
//     runs the authoritative cold-prime bulk.
//   - wireUserspaceEventStreamForSync runs before the Start retry loop: its
//     result selects which drain loop that loop launches.
//   - the fabric refresh channels are published before startFabricForwardingLoops
//     hands each loop its own channel by value.
func (d *Daemon) startClusterComms(ctx context.Context) {
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	cc := cfg.Chassis.Cluster

	// Create an independently-cancellable sub-context so cluster comms can
	// be restarted on config change (#87) without cancelling the daemon ctx.
	// beginClusterCommsEpoch bumps the epoch generation under clusterCommsMu so
	// a constructor goroutine from a superseded epoch (still resolving its sync
	// address) drops its publish instead of clobbering this epoch's state
	// (#4958).
	commsCtx, commsGen, commsCancel := d.beginClusterCommsEpoch(ctx)
	// #7071: consume the drop signal, as both sibling publishers already do
	// (`publishSessionSyncIfCurrent`, `publishFabricRefreshChansIfCurrent`).
	//
	// A false return means this epoch was superseded between the line above and
	// this one, so everything below would wire a DEAD epoch: the VRF resolve,
	// the HA watchdog heartbeat, the control heartbeat goroutine and the
	// session-sync constructor. Their own publishes are epoch-gated and would
	// drop, so nothing incorrect is installed — but the goroutines are not
	// merely wasted work. They run on `commsCtx`, whose cancel the newer epoch
	// has already overwritten in `clusterCommsCancel`, so nothing can cancel
	// them: `stopClusterComms` would call the NEWER epoch's cancel. They would
	// live until the daemon context dies, i.e. for the life of the process.
	//
	// Cancelling our own sub-context on the way out is the other half. Returning
	// without it leaks the context itself (nothing else holds that cancel), and
	// cancelling here is safe precisely because we have launched nothing on it
	// yet — this is the first statement after the epoch opens.
	if !d.setActiveTransportIfCurrent(commsGen, clusterTransportFromConfig(cfg)) {
		commsCancel()
		return
	}

	vrfDevice := d.resolveClusterVRFDevice(cc)

	d.startHAWatchdogHeartbeat(commsCtx, cc)

	// In VRRP mode, make strict VIP ownership the runtime default so
	// rg_active follows VIP/MAC ownership rather than cluster-primary
	// intent. Direct/no-reth-vrrp mode and private-rg-election mode
	// still use cluster state because there are no VRRP instances to
	// gate on.
	d.syncRGStrictVIPOwnershipMode(cc)

	// Start heartbeat if control-interface and peer-address are configured.
	// Retry on bind failure: the control interface address and VRF device
	// may not be ready during daemon startup (networkd race).
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go d.startHeartbeatWithRetry(commsCtx, cc.ControlInterface, cc.PeerAddress, vrfDevice)
	}

	syncIface, syncPeerAddr, syncTransport := clusterSyncTransport(cc)
	if syncIface != "" && syncPeerAddr != "" {
		// Track the constructor goroutine so stopClusterComms can join it
		// before tearing the epoch down (#4958): a cancelled constructor must
		// finish (or drop its publish) before stop nils the shared state.
		d.clusterCommsWG.Add(1)
		go func() {
			defer d.clusterCommsWG.Done()
			var syncIP string
			for i := 0; i < 30; i++ {
				syncIP = resolveClusterInterfaceAddr(syncIface, syncPeerAddr, "")
				if syncIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: sync interface has no usable address yet, waiting",
						"interface", syncIface, "transport", syncTransport)
				}
				select {
				case <-commsCtx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			if syncIP == "" {
				slog.Error("cluster: sync interface address not available after retries",
					"interface", syncIface)
				return
			}

			syncLocal := net.JoinHostPort(syncIP, "4785")
			syncPeer := net.JoinHostPort(syncPeerAddr, "4785")
			slog.Info("cluster: session sync transport", "mode", syncTransport,
				"local", syncLocal, "peer", syncPeer)

			// Resolve secondary fabric (fab1) for dual transport failover.
			// Only applicable when using fabric transport (not control-link).
			var syncLocal1, syncPeer1 string
			if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				var fab1IP string
				for i := 0; i < 15; i++ {
					fab1IP = resolveClusterInterfaceAddr(cc.Fabric1Interface, cc.Fabric1PeerAddress, "")
					if fab1IP != "" {
						break
					}
					if i == 0 {
						slog.Info("cluster: fabric1 interface has no usable address yet, waiting",
							"interface", cc.Fabric1Interface)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
				if fab1IP != "" {
					syncLocal1 = net.JoinHostPort(fab1IP, "4785")
					syncPeer1 = net.JoinHostPort(cc.Fabric1PeerAddress, "4785")
					slog.Info("cluster: dual fabric transport configured",
						"fab0_local", syncLocal, "fab1_local", syncLocal1)
				} else {
					slog.Warn("cluster: fabric1 address not available, using single fabric only",
						"interface", cc.Fabric1Interface)
				}
			}

			// Build the session-sync object in a LOCAL variable and publish it
			// only if this constructor still owns the current comms epoch
			// (#4958). Everything below wires callbacks and cluster references
			// against this local `ss` — never re-reading d.sessionSync — so a
			// concurrent stopClusterComms that nils the field cannot turn a
			// re-dereference into a nil-deref panic, and a superseded epoch's
			// late publish is dropped rather than clobbering the live epoch.
			var ss *cluster.SessionSync
			if syncLocal1 != "" {
				ss = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
			} else {
				ss = cluster.NewSessionSync(syncLocal, syncPeer, nil)
			}
			if !d.publishSessionSyncIfCurrent(commsGen, ss) {
				// A restart superseded this epoch while we were resolving the
				// sync address; abort before wiring cluster state or binding.
				return
			}
			d.wireSessionSyncTransportRefs(ss, cc, syncTransport, syncPeerAddr, syncLocal1)

			d.startFabricGRPCListeners(commsCtx, syncIP, syncLocal1, vrfDevice)

			// Wire sync stats into cluster manager for CLI display.
			d.cluster.SetSyncStats(ss)

			d.wireSessionSyncConfigCallbacks(ss)

			d.wireSessionSyncPeerCallbacks(ss)

			d.wireSessionSyncFailoverCallbacks(ss)

			d.wireClusterPeerFailoverHooks(ss)

			d.wireClusterFenceCallbacks(commsCtx, ss)

			ss.SetVRFDevice(vrfDevice)

			wiredStream := d.wireUserspaceEventStreamForSync(commsCtx)

			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				// #82: wire the runtime and the ownership predicates BEFORE
				// Start opens the listeners and dialers, not after it returns.
				//
				// Start spawns the accept/connect goroutines, and the first
				// connection they establish runs the authoritative cold-prime
				// bulk inside handleNewConnection. Wiring afterwards left a
				// window in which that bulk ran against a nil session store:
				// BulkSync returns "session store not ready" before it writes a
				// byte, so no disconnect follows and — before the sweep
				// re-drive added alongside this — nothing re-drove the owed
				// prime for the life of that connection. It also made
				// SetRuntime an unsynchronized write to fields the goroutines
				// Start had already spawned were reading. Assigning before the
				// goroutines exist gives the writes a happens-before edge and
				// removes the race outright.
				//
				// ONE snapshot of the published dataplane per iteration feeds
				// both this wiring and the post-Start sweep launch, so a
				// setDataplane(nil) landing mid-retry cannot be seen as non-nil
				// by one site and nil by the other (#2114 / #6743 rule).
				rt := d.dataplane()
				if rt != nil {
					ss.SetRuntime(rt)
					ss.IsPrimaryFn = func() bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(0)
					}
					ss.IsPrimaryForRGFn = func(rgID int) bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(rgID)
					}
				}
				if err := ss.Start(commsCtx); err != nil {
					if i < 5 {
						slog.Info("cluster: sync bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start session sync, retrying",
							"err", err, "attempt", i+1)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				slog.Info("cluster session sync started",
					"local", syncLocal, "peer", syncPeer, "vrf", vrfDevice)

				// Start the sweep and the event-stream drain now that the
				// listeners are up. The runtime itself was wired above, before
				// Start (#82). All of it must happen here (not in Run) because
				// the session-sync object `ss` is created asynchronously in
				// this goroutine. The published dataplane is a
				// dataplane.RuntimeDataPlane; both the legacy *Manager and the
				// userspace LegacyDataPlaneAdapter implement
				// Sessions()/Telemetry() so they satisfy the cluster package's
				// narrow clusterRuntime contract directly (#1518).
				if rt != nil {
					ss.StartSyncSweep(commsCtx)
					if wiredStream != nil {
						go d.eventStreamFallbackLoop(commsCtx, wiredStream)
					} else {
						go d.runUserspaceEventStream(commsCtx)
					}
				}

				break
			}

			d.startClusterSyncAuxLoops(commsCtx, cc)

			// Initialize per-fabric refresh channels for event-driven
			// updates (#124). Each fabric owns its own channel so a
			// single netlink-triggered refresh wakes both the fab0 and
			// fab1 loops rather than only whichever won a shared-channel
			// receive (#4038). #4958: build them locally, hand each loop its
			// OWN channel by value, and publish the shared fields only if this
			// epoch is still current — so a superseded constructor neither
			// replaces a newer epoch's channels nor lets its loops receive on
			// a stale field. The loops read the value they were launched with,
			// never d.fabricRefreshCh, so the sender-side field swap on restart
			// cannot race them.
			fabRefreshCh := make(chan struct{}, 1)
			fabRefreshCh1 := make(chan struct{}, 1)
			if !d.publishFabricRefreshChansIfCurrent(commsGen, fabRefreshCh, fabRefreshCh1) {
				return
			}

			d.startFabricForwardingLoops(commsCtx, cc, fabRefreshCh, fabRefreshCh1)
		}()
	}
}

// currentRedundancyGroups returns the redundancy-groups from the CURRENT
// active configuration (d.store.ActiveConfig()) rather than a snapshot
// captured earlier. #3917: long-lived HA goroutines wired in
// startClusterComms (peer-fence handling, watchdog heartbeat) must read
// live config at every event/tick. startClusterComms is only restarted on a
// transport-field change (clusterTransportKey), so a redundancy-group added
// by a day-2 commit never reaches a closure that captured the startup `cfg`.
// Returns nil when there is no store, no compiled config, or the config is
// not in cluster mode — every caller must tolerate an empty slice.
func (d *Daemon) currentRedundancyGroups() []*config.RedundancyGroup {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster.RedundancyGroups
}

// fenceAllRedundancyGroups disables rg_active for every redundancy-group in
// the CURRENT active config. It is the peer-fence handler: when a fence
// message arrives the local node must relinquish ALL redundancy-groups so
// the peer can own them without a dual-active split-brain. #3917: reading
// the live config here (via currentRedundancyGroups) ensures day-2 RGs are
// fenced too. Safe when the dataplane is nil (config-only mode) or the
// config has no cluster/RGs.
//
// #7147: it now REPORTS what it achieved so a sequenced fence can be
// acknowledged truthfully. The counts are what the peer's confirmed-fence gate
// consults, so "fenced" means every RG in this node's live config was actually
// driven to rg_active=false — not merely that the fence message arrived.
func (d *Daemon) fenceAllRedundancyGroups(ctx context.Context) cluster.FenceResult {
	// Guard the published dataplane: the daemon can run in config-only mode
	// (no published dataplane)
	// when the runtime dataplane factory rejects the configured backend —
	// for example, a stale "system dataplane-type dpdk" config triggers
	// dataplane.ErrDPDKBackendRetired and daemon_run.go falls back to no
	// dataplane. Without this guard a peer fence would panic on a nil pointer
	// dereference. The same applies to any future Start() failure that
	// leaves the dataplane unpublished.
	rt := d.dataplane()
	if rt == nil {
		slog.Warn("cluster: fence received but dataplane is nil; skipping RG deactivation",
			"mode", "config-only",
			"action", "skip_rg_deactivation",
			"remediation", "set system dataplane-type userspace and restart xpfd",
		)
		// #7147: DataplaneAvailable stays false, which the peer reads as
		// FenceAckUnavailable. Reporting a vacuous "0 of 0 fenced, OK" here
		// would tell the surviving node this peer is safely dark when in fact
		// nothing was even attempted.
		return cluster.FenceResult{}
	}
	rgs := d.currentRedundancyGroups()
	res := cluster.FenceResult{RGsTotal: len(rgs), DataplaneAvailable: true}
	slog.Warn("cluster: fence: disabling all RGs", "rg_count", len(rgs))
	for _, rg := range rgs {
		if err := rt.HA().SetRGActive(ctx, rg.ID, false); err != nil {
			slog.Warn("cluster: fence: failed to disable rg_active",
				"rg", rg.ID, "err", err)
		} else {
			// #7147: counted only on a CLEAN write. A failed SetRGActive may
			// have partially landed, and the honest reading of "not known to
			// have converged" is that this RG is not confirmed fenced — the
			// same posture the InvalidateApplied call below takes.
			res.RGsFenced++
		}
		// #6530: this write bypasses the RG state machine's transition
		// path, so without re-arming, reconcileRGState's desired-vs-applied
		// retry sees desired == applied and never re-drives the apply — a
		// fenced-then-recovered primary would stay dark forever. Re-arm
		// AFTER the write (success or failure: a failed write may still have
		// partially landed, so "not known to have converged" is the only
		// honest reading) so the next reconcile pass restores forwarding
		// once the cluster state says this node owns the RG again.
		d.getOrCreateRGState(rg.ID).InvalidateApplied()
	}
	return res
}

// startHeartbeatWithRetry resolves the control-link local address and starts
// the cluster heartbeat, retrying on a not-ready bind (the control interface
// address and VRF device may not be ready during daemon startup — a networkd
// race). It runs in its own goroutine, owned by the comms sub-context.
//
// It exits immediately when ctx is cancelled (#4033): stopClusterComms cancels
// the comms context before installing new comms, so without this the old retry
// goroutine would survive the teardown and keep looping — up to 30 * 2s = 60s
// — and could call StartHeartbeat AFTER stopClusterComms, installing a
// heartbeat into a torn-down comms lifecycle and racing the replacement
// goroutine. Every iteration (and every retry sleep) observes ctx so a comms
// restart leaves exactly one retry goroutine and one heartbeat.
func (d *Daemon) startHeartbeatWithRetry(ctx context.Context, controlIface, peerAddr, vrfDevice string) {
	for i := 0; i < 30; i++ {
		if ctx.Err() != nil {
			slog.Info("cluster: heartbeat start aborted, comms context cancelled")
			return
		}
		localIP := resolveClusterInterfaceAddr(controlIface, peerAddr, "")
		if localIP == "" {
			if i == 0 {
				slog.Info("cluster: control interface has no usable address yet, waiting",
					"interface", controlIface)
			}
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		if err := d.cluster.StartHeartbeat(localIP, peerAddr, vrfDevice); err != nil {
			// #7257: a start the teardown superseded is terminal, not a bind
			// failure. Retrying would race the same teardown again and, on
			// success, resurrect the heartbeat stopClusterComms exists to
			// remove. The ctx.Err() check at the top of the next iteration
			// would catch it too — stopClusterComms cancels before it calls
			// StopHeartbeat — but returning on the verdict we were actually
			// given beats relying on a second signal to arrive in time.
			if errors.Is(err, cluster.ErrHeartbeatStartSuperseded) {
				slog.Info("cluster: heartbeat start superseded by comms teardown, not retrying")
				return
			}
			if i < 5 {
				slog.Info("cluster: heartbeat bind not ready, retrying",
					"err", err, "attempt", i+1)
			} else {
				slog.Warn("failed to start cluster heartbeat, retrying",
					"err", err, "attempt", i+1)
			}
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		return
	}
	slog.Error("cluster heartbeat failed after retries")
}

// sleepCtx blocks for d or until ctx is cancelled, whichever comes first. It
// returns true if the full duration elapsed and false if ctx was cancelled —
// a false result tells a retry loop to stop rather than continue.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// stopClusterComms tears down heartbeat and session sync so they can be
// restarted with new transport settings (#87). Cancels the comms sub-context
// (which stops retry loops, fabric_fwd refresh, IPsec SA sync, sync sweep)
// and explicitly stops heartbeat + session sync listeners/connections.
//
// #4958: the teardown is epoch-safe. Under clusterCommsMu it first bumps
// clusterCommsGen — superseding any in-flight startClusterComms constructor so
// that constructor's publish is dropped (publishSessionSyncIfCurrent) — and
// captures/clears the cancel handle and comms context. It then cancels the
// context and JOINS the constructor goroutine (clusterCommsWG.Wait) so a
// cancelled-but-still-running constructor finishes (or drops) before the shared
// session-sync/fabric state is nilled. Only after the join does it clear
// sessionSync and the fabric refresh channels and Stop() the session sync. The
// join runs OUTSIDE the lock (the constructor's publish path also takes the
// lock), so there is no deadlock.
func (d *Daemon) stopClusterComms() {
	d.clusterCommsMu.Lock()
	d.clusterCommsGen++
	cancel := d.clusterCommsCancel
	d.clusterCommsCancel = nil
	d.clusterCommsCtx = nil
	d.clusterCommsMu.Unlock()

	if cancel != nil {
		cancel()
	}
	// Join the constructor goroutine before nilling shared state so its
	// publish (if it still owned the just-superseded epoch it will drop; if it
	// published before the generation bump it finishes wiring) cannot race the
	// teardown below.
	d.clusterCommsWG.Wait()

	// #4647: the lease-sync loop is scoped to the comms context just
	// cancelled, so it is already stopping; clear the cancel handle so the
	// next comms session's connect-time launch starts a fresh loop.
	d.resetDHCPLeaseSyncLoop()
	if d.cluster != nil {
		d.cluster.StopHeartbeat()
	}

	d.clusterCommsMu.Lock()
	ss := d.sessionSync
	d.sessionSync = nil
	d.fabricRefreshCh = nil
	d.fabricRefreshCh1 = nil
	// #7072: activeClusterTransport is DELIBERATELY NOT cleared here, and the
	// issue that asked for it is refuted by measurement rather than argument.
	//
	// Its premise was that the stale value is unreachable because the only
	// stopClusterComms call site is step 20's, which starts comms again on the
	// next line. There is a SECOND site: bootstrap.go's rollback teardown stops
	// comms and RETURNS. That path is real, and on it this field is the only
	// memory of which transport comms were using.
	//
	// Measured on the bootstrap-rollback shape — stop, then a corrected commit
	// carrying a DIFFERENT transport key — by driving the real applyTailReconciles
	// with a counting startClusterCommsFn:
	//
	//     field retained (today):  restarts=1  -> comms recover
	//     field cleared:           restarts=0  -> comms stay down
	//
	// Step 20's guard is `active != zero && newTransport != active`. Clearing
	// makes the FIRST conjunct false, so it fails in both directions, and the only
	// other production startClusterComms call site is daemon_run.go's boot path —
	// so the node would hold a valid cluster config with no heartbeat, no session
	// sync and no fabric refresh until the process restarts.
	//
	// The field therefore carries TWO meanings, and the name only says one:
	// "which transport the running comms use", and "comms have run at least once,
	// so step 20 may act". The second is load-bearing in the other direction too —
	// the boot applyConfig runs BEFORE daemon_run.go:405's startClusterComms, so
	// `active != zero` is what keeps step 20 out of the boot window that line is
	// deliberately positioned after. Read it as LAST PUBLISHED transport, not as
	// "comms are up"; `sessionSync == nil` is what says comms are down.
	//
	// Bound by TestBootstrapRollbackThenCorrectedCommitRecovers_7072 (this is the
	// cell a clear fails) and TestStepTwentyIgnoresANeverStartedNode_7072.
	d.clusterCommsMu.Unlock()

	if ss != nil {
		d.stopSyncReadyTimer()
		ss.Stop()
	}
}

// clusterTransportKey extracts the cluster transport fields that determine
// heartbeat and session sync endpoints. Used to detect config changes that
// require restarting cluster comms: step 20 compares the WHOLE struct, so every
// field here participates in the restart decision.
//
// The `log` tag is the key suffix step 20 uses when it reports that decision.
// It exists so transportChangeLogArgs can derive the line from the struct
// rather than from a hand-maintained argument list that has to be remembered
// separately (#7073).
type clusterTransportKey struct {
	ControlInterface   string `log:"control"`
	PeerAddress        string `log:"peer"`
	FabricInterface    string `log:"fabric"`
	FabricPeerAddress  string `log:"fabric_peer"`
	Fabric1Interface   string `log:"fabric1"`
	Fabric1PeerAddress string `log:"fabric1_peer"`
}

// transportChangeLogArgs builds the key/value pairs for step 20's
// "cluster: transport config changed, restarting comms" line: one old_/new_
// pair per clusterTransportKey field, in declaration order.
//
// Derived from the struct by reflection rather than written out by hand,
// because the two had already drifted: the comparison that decides the restart
// used all six fields while the line that reported it printed four, so a commit
// changing only fab1 correctly restarted comms and then logged four identical
// old/new pairs — a line asserting a change and showing none, which reads as a
// spurious restart (#7073). Deriving it makes that drift unrepresentable: a
// field added to the struct joins the comparison and the line together.
//
// A field with no `log` tag still gets logged, under its Go name; the tag is
// for a readable key, not for inclusion. Omission is not a reachable state.
// Reflection is affordable here — this runs only on a commit that actually
// changed the transport, never per packet or per session.
func transportChangeLogArgs(active, next clusterTransportKey) []any {
	rt := reflect.TypeOf(clusterTransportKey{})
	av := reflect.ValueOf(active)
	nv := reflect.ValueOf(next)
	args := make([]any, 0, 4*rt.NumField())
	for i := range rt.NumField() {
		name := rt.Field(i).Tag.Get("log")
		if name == "" {
			name = rt.Field(i).Name
		}
		// .Interface(), not .String(): reflect.Value.String() does not fail on a
		// non-string field, it returns "<int Value>". Every field is a string
		// today, so this is not a live bug — but the whole point of deriving
		// the line is that a future field joins it automatically, and joining
		// it as garbage would be worse than the omission this replaced.
		args = append(args,
			"old_"+name, av.Field(i).Interface(),
			"new_"+name, nv.Field(i).Interface())
	}
	return args
}

func clusterTransportFromConfig(cfg *config.Config) clusterTransportKey {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return clusterTransportKey{}
	}
	cc := cfg.Chassis.Cluster
	return clusterTransportKey{
		ControlInterface:   cc.ControlInterface,
		PeerAddress:        cc.PeerAddress,
		FabricInterface:    cc.FabricInterface,
		FabricPeerAddress:  cc.FabricPeerAddress,
		Fabric1Interface:   cc.Fabric1Interface,
		Fabric1PeerAddress: cc.Fabric1PeerAddress,
	}
}

// setActiveTransportIfCurrent publishes the transport key of the comms epoch
// that startClusterComms is bringing up, and activeTransport reads it back —
// both under clusterCommsMu (#6290).
//
// The lock is required, not decorative. The field is written by
// startClusterComms, which runs on the boot path (daemon_run.go) holding
// NEITHER applySem NOR this mutex, and read by applyTailReconciles step 20,
// which runs under applySem. A semaphore only excludes participants that take
// it, so applySem orders the readers against each other and not against the
// boot writer.
//
// The boot ordering does not close the gap either. The boot applyConfig
// (daemon_run_bringup.go) starts the DHCP clients via reconcileDHCPClients
// (daemon_apply_routing.go) with onDHCPAddressChange already wired
// (daemon_run_bringup.go), and that callback re-enters applyConfig — hence
// step 20 — on its own goroutine. Those goroutines are created BEFORE the boot
// startClusterComms write, so goroutine creation orders them the wrong way and
// establishes no happens-before from the write to their reads. A lease
// arriving in that window is an unsynchronized concurrent read/write of a
// six-string struct: a real Go data race, not a theoretical one. The same
// hazard on mgmtVRFInterfaces (#5113, see daemon.go) has the mirror shape —
// written under applySem, read by the same callback without it — and was fixed
// the same way.
//
// activeTransport also returns ONE snapshot, so step 20's comparison and every
// old_* pair it logs all describe a single epoch rather than up to six separate
// reads that a concurrent restart could interleave. Deliberately not a count:
// the previous wording said "eight fields", which was wrong when written (four
// of step 20's eight pairs came from the locally-computed newTransport, not
// from the snapshot) and would have gone wrong again when #7073 added the two
// fab1 pairs. The invariant is "every old_* pair", which does not rot (#7070).
//
// setActiveTransportIfCurrent is epoch-gated rather than a bare locked store,
// mirroring publishSessionSyncIfCurrent. The same window that makes the race
// reachable also admits two concurrent startClusterComms calls (the boot one
// and a DHCP-callback-driven restart from step 20). Both would bump the epoch
// and both would publish; with an ungated store the LOSER of that ordering can
// land last, leaving the transport key describing a superseded epoch while
// clusterCommsGen names the live one. Step 20 would then compare the next
// commit against the wrong baseline and either skip a needed comms restart or
// perform a spurious one. Gating on gen makes a superseded publish drop
// instead, exactly as the #4958 fields do.
func (d *Daemon) setActiveTransportIfCurrent(gen uint64, k clusterTransportKey) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	if gen != d.clusterCommsGen {
		slog.Debug("cluster: dropping stale transport publish (comms epoch superseded)",
			"publish_gen", gen, "current_gen", d.clusterCommsGen)
		return false
	}
	d.activeClusterTransport = k
	return true
}

func (d *Daemon) activeTransport() clusterTransportKey {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	return d.activeClusterTransport
}

// activeTreeForNodeLocal returns this node's active config tree for the #7441
// node-local preservation hook, or nil when nothing is committed yet.
//
// A nil store, or a node that has never committed, yields nil — and
// preserveNodeLocalChassis treats nil as "no local value to defend", which is
// correct: a node with no committed config has no posture, and the leaf is
// inert until it does.
func (d *Daemon) activeTreeForNodeLocal() *config.ConfigTree {
	if d.store == nil {
		return nil
	}
	return d.store.ActiveTree()
}
