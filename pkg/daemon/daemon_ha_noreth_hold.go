package daemon

import (
	"log/slog"
	"time"
)

// The #7162 no-RETH startup promotion hold.
//
// RETH VRRP mode has had a bounded startup suppression since #466:
// `vrrp.Manager.SetSyncHold(30s)`, armed once at daemon bringup and released by
// bulk session sync or by its own timer. `no-reth-vrrp` and
// `private-rg-election` mode had no equivalent — `checkNoRethTakeoverReadiness`
// is VIP ownership and nothing else — so a node in those modes could promote an
// RG at startup before bulk sync had delivered any conntrack/NAT state, and
// every established TCP flow reset on the transition.
//
// WHAT THIS DELIBERATELY IS NOT. It is not a continuous `IsSyncReady()` conjunct
// in the readiness AND. That is the shape #110 measured and rejected, and it is
// worth stating so nobody "simplifies" this into it: `syncReady` has no bound
// while the session-sync channel is down (`armSyncReadyTimer` early-returns
// unless `d.syncPeerConnected`), and the election blocks a not-ready RG whenever
// the peer is alive. Peer alive on the CONTROL link with session sync down would
// then block promotion INDEFINITELY — including the degraded-peer case
// (peer up, weight 0, interfaces down) that preemption exists to handle.
//
// So the hold is bounded by construction:
//
//   - it is armed EXACTLY ONCE, at daemon bringup, mirroring SetSyncHold's
//     arming scope. It is never re-armed on reconnect, which is what keeps it a
//     STARTUP hold rather than a mid-life block.
//   - its timer callback consults NO peer condition — not `syncPeerConnected`,
//     not `peerAlive`, not `cluster.IsSyncReady()`. This is the #110 trap
//     restated: `armSyncReadyTimer`'s callback bails on `!d.syncPeerConnected`,
//     so that fallback never fires in exactly the peer-absent case it exists
//     for. A release that depended on the peer would be no release at all,
//     because the peer being absent is the reason the hold is still held.
//
// The two release edges are bulk-sync completion (the good one) and the timer
// (the degraded one), and both record which fired so `show chassis cluster` can
// say so.

// noRethSyncHoldTimeout mirrors the RETH VRRP sync hold's 30s. Same job, same
// bound, so an operator reading either path sees the same startup behaviour.
const noRethSyncHoldTimeout = 30 * time.Second

// armNoRethSyncHold starts the bounded startup hold. Call once, at bringup.
func (d *Daemon) armNoRethSyncHold(timeout time.Duration) {
	if d == nil {
		return
	}
	if timeout <= 0 {
		timeout = noRethSyncHoldTimeout
	}
	d.noRethSyncHoldMu.Lock()
	defer d.noRethSyncHoldMu.Unlock()
	if d.noRethSyncHoldTimer != nil {
		d.noRethSyncHoldTimer.Stop()
	}
	d.noRethSyncHold.Store(true)
	d.noRethSyncHoldReason.Store("")
	// No peer condition in this callback, deliberately — see the file comment.
	d.noRethSyncHoldTimer = time.AfterFunc(timeout, func() {
		slog.Warn("cluster: no-RETH sync hold timeout: bulk sync did not complete, "+
			"releasing promotion hold in degraded mode", "timeout", timeout)
		d.releaseNoRethSyncHold("timeout-degraded")
	})
	if d.cluster != nil {
		d.cluster.SetStartupSyncHoldStatus("no-reth", true, "")
	}
	slog.Info("cluster: no-RETH startup promotion hold active", "timeout", timeout)
}

// releaseNoRethSyncHold ends the hold and records why. Idempotent: the timer and
// the bulk-sync edge race by design, and whichever arrives first wins.
func (d *Daemon) releaseNoRethSyncHold(reason string) {
	if d == nil {
		return
	}
	d.noRethSyncHoldMu.Lock()
	if !d.noRethSyncHold.Load() {
		d.noRethSyncHoldMu.Unlock()
		return
	}
	// Publish the reason before clearing the flag: lock-free readers use the
	// cleared flag as the release edge, then read the paired reason.
	d.noRethSyncHoldReason.Store(reason)
	d.noRethSyncHold.Store(false)
	if d.noRethSyncHoldTimer != nil {
		d.noRethSyncHoldTimer.Stop()
		d.noRethSyncHoldTimer = nil
	}
	d.noRethSyncHoldMu.Unlock()
	if d.cluster != nil {
		d.cluster.SetStartupSyncHoldStatus("no-reth", false, reason)
	}
	slog.Info("cluster: no-RETH startup promotion hold released", "reason", reason)
	// Readiness is computed on a reconcile pass, so releasing the hold has to
	// DRIVE one. Without this the node holds its RG secondary until some
	// unrelated event happens to trigger a reconcile — the hold would be bounded
	// in name only, since the bound would be on when the flag flips rather than
	// on when anything acts on it. The RETH sibling has the same obligation and
	// meets it with triggerPreemptNow() inside releaseSyncHoldWithReason.
	d.triggerReconcile()
}

// inNoRethSyncHold reports whether the startup promotion hold is still active.
func (d *Daemon) inNoRethSyncHold() bool {
	return d != nil && d.noRethSyncHold.Load()
}

// noRethSyncHoldEndReason returns why the hold ended — "bulk-sync-complete",
// "timeout-degraded", or "" if it never armed or is still active. Mirrors
// vrrp.Manager.SyncHoldReason so the two paths render identically.
func (d *Daemon) noRethSyncHoldEndReason() string {
	if d == nil {
		return ""
	}
	r, _ := d.noRethSyncHoldReason.Load().(string)
	return r
}
