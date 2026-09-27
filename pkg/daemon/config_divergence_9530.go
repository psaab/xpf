package daemon

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #9530: the daemon half of the partition-commit divergence alarm.
//   - The store marks a local commit made while the peer is unreachable
//     (configPeerReachable, wired with SetPeerReachableFn at cluster bring-up).
//   - A push to a peer that reads RG0 secondary clears the mark
//     (noteConfigSharedWithPeer).
//   - A peer sync that discards a still-unshared commit is raised once as a
//     cluster event (reportConfigSyncDivergence), beside the store's Error log
//     and the `show system alarms` line.
//
// See pkg/configstore/unshared_9530.go for why the mark, and not a digest
// comparison, is the identity.

// configPeerReachable reports whether the cluster peer can currently be shown a
// commit: its heartbeat is alive and the session-sync connection that carries
// config is up. The store calls it under its own mutex, and it takes only the
// cluster manager's read lock and an atomic.
func (d *Daemon) configPeerReachable() bool {
	if d.configPeerStateForTest != nil {
		reachable, _ := d.configPeerStateForTest()
		return reachable
	}
	return d.cluster != nil && d.cluster.PeerAlive() && d.syncPeerConnected.Load()
}

// noteConfigSharedWithPeer runs after this node pushed pushedText as RG0
// authority. The push counts as shared only when the peer is reachable and does
// NOT read RG0 primary: in the dual-active window of a heal the peer is still
// primary and rejects the push.
func (d *Daemon) noteConfigSharedWithPeer(pushedText string) {
	if d.store == nil {
		return
	}
	var reachable, peerSecondary bool
	if d.configPeerStateForTest != nil {
		reachable, peerSecondary = d.configPeerStateForTest()
	} else {
		reachable = d.configPeerReachable()
		peerSecondary = d.cluster != nil && !d.cluster.IsPeerPrimary(0)
	}
	if reachable && peerSecondary {
		d.store.NoteActiveSharedWithPeer(pushedText)
	}
}

// noteConfigSharedWithPeerAtEpoch prevents an old connection's successful
// write from clearing the unshared marker after a reconnect has begun.
func (d *Daemon) noteConfigSharedWithPeerAtEpoch(pushedText string, epoch uint64) bool {
	if d == nil {
		return false
	}
	d.configSyncMu.Lock()
	defer d.configSyncMu.Unlock()
	if d.syncPeerConnEpoch.Load() != epoch || !d.syncPeerConnected.Load() {
		return false
	}
	d.noteConfigSharedWithPeer(pushedText)
	return true
}

// reportConfigSyncDivergence raises the divergence as a cluster event once, after
// a peer config sync applied. The store has already logged it at Error.
func (d *Daemon) reportConfigSyncDivergence() {
	if d.store == nil {
		return
	}
	div, slot, ok := d.store.ConfigSyncDivergence()
	if !ok {
		return
	}
	d.configDivergenceMu.Lock()
	if div.At.Equal(d.configDivergenceReported) {
		d.configDivergenceMu.Unlock()
		return
	}
	d.configDivergenceReported = div.At
	d.configDivergenceMu.Unlock()
	msg := fmt.Sprintf("Config sync replaced a local commit the peer never held (committed %s); it is rollback %d",
		div.DiscardedAt.Format(time.RFC3339), slot)
	slog.Error("cluster: "+msg, "discarded_digest", div.DiscardedDigest, "adopted_digest", div.AdoptedDigest,
		"issue", "#9530")
	if d.cluster != nil {
		d.cluster.RecordEvent(cluster.EventConfigSync, 0, msg)
	}
}

// reportPeerSnapshotConfigSyncDeferred raises one operator-visible alarm for a
// deferred active config generation and peer epoch. A stale snapshot must not
// replace the alarm for the current active config, and a stale observation
// must not re-arm it after the peer epoch or selected capability changes.
func (d *Daemon) reportPeerSnapshotConfigSyncDeferred(
	configText string,
	epoch uint64,
	observedState cluster.PeerSnapshotState,
	reason string,
) {
	if d == nil {
		return
	}
	gen := configGenerationHash(configText)
	msg := fmt.Sprintf("Config sync deferred: %s", reason)
	// Serialize the active-text check and alarm update with daemon-owned active
	// promotions: pendingRenameMu, then Store read, then configSyncMu (the Store
	// read lock is released before taking configSyncMu).
	d.pendingRenameMu.Lock()
	if d.store != nil {
		_, activeText, _ := d.store.ActiveConfigAndText()
		if activeText != configText {
			d.pendingRenameMu.Unlock()
			return
		}
	}
	d.configSyncMu.Lock()
	currentState := cluster.PeerSnapshotState{}
	if ss := d.getSessionSync(); ss != nil {
		currentState = ss.SnapshotPeerSnapshotProtocol()
	}
	// Observation-to-report freshness (#10782 round 4). Peer epoch updates
	// serialize with configSyncMu; per-connection capability changes are
	// checked against the full selected-connection state. A same-text v4
	// success that wins this race changes the observation, so its delayed v3
	// reporter cannot re-arm a false CRITICAL condition.
	if epoch != d.syncPeerConnEpoch.Load() || observedState != currentState {
		d.configSyncMu.Unlock()
		d.pendingRenameMu.Unlock()
		return
	}
	if d.configSyncPeerSnapshotDeferred &&
		d.configSyncPeerSnapshotDeferredGen == gen &&
		d.configSyncPeerSnapshotDeferredEpoch == epoch &&
		d.configSyncPeerSnapshotDeferredMessage == msg {
		d.configSyncMu.Unlock()
		d.pendingRenameMu.Unlock()
		return
	}
	d.configSyncPeerSnapshotDeferred = true
	d.configSyncPeerSnapshotDeferredGen = gen
	d.configSyncPeerSnapshotDeferredEpoch = epoch
	d.configSyncPeerSnapshotDeferredMessage = msg
	d.configSyncMu.Unlock()
	d.pendingRenameMu.Unlock()
	slog.Error("cluster: "+msg, "generation", gen, "peer_epoch", epoch, "issue", "#10782")
	if d.cluster != nil {
		d.cluster.RecordEvent(cluster.EventConfigSync, -1, msg)
	}
}

// clearPeerSnapshotConfigSyncDeferred clears an alarm only for a successful
// push still current on the active text and peer epoch. A gated snapshot also
// carries its capability observation so a same-epoch downgrade cannot be
// erased by a write authorized before that change.
func (d *Daemon) clearPeerSnapshotConfigSyncDeferred(
	configText string,
	epoch uint64,
	successState *cluster.PeerSnapshotState,
) {
	if d == nil {
		return
	}
	gen := configGenerationHash(configText)
	d.pendingRenameMu.Lock()
	if d.store != nil {
		_, activeText, _ := d.store.ActiveConfigAndText()
		if activeText != configText {
			d.pendingRenameMu.Unlock()
			return
		}
	}
	d.configSyncMu.Lock()
	currentState := cluster.PeerSnapshotState{}
	if ss := d.getSessionSync(); ss != nil {
		currentState = ss.SnapshotPeerSnapshotProtocol()
	}
	if !d.configSyncPeerSnapshotDeferred ||
		epoch != d.syncPeerConnEpoch.Load() ||
		!d.syncPeerConnected.Load() ||
		epoch < d.configSyncPeerSnapshotDeferredEpoch ||
		(successState != nil && currentState != *successState) ||
		(d.store == nil && d.configSyncPeerSnapshotDeferredGen != gen) {
		d.configSyncMu.Unlock()
		d.pendingRenameMu.Unlock()
		return
	}
	d.configSyncPeerSnapshotDeferred = false
	d.configSyncPeerSnapshotDeferredGen = 0
	d.configSyncPeerSnapshotDeferredEpoch = 0
	d.configSyncPeerSnapshotDeferredMessage = ""
	d.configSyncMu.Unlock()
	d.pendingRenameMu.Unlock()
	slog.Info("cluster: config sync resumed after peer snapshot-protocol deferral",
		"generation", gen, "peer_epoch", epoch, "issue", "#10782")
	if d.cluster != nil {
		d.cluster.RecordEvent(cluster.EventConfigSync, -1,
			"Config sync resumed after peer snapshot-protocol deferral")
	}
}

// peerSnapshotProtocolDeferredAlarm supplies the persistent condition to both
// local and remote `show system alarms` renderers.
func (d *Daemon) peerSnapshotProtocolDeferredAlarm() string {
	if d == nil {
		return ""
	}
	d.configSyncMu.Lock()
	defer d.configSyncMu.Unlock()
	if !d.configSyncPeerSnapshotDeferred {
		return ""
	}
	return d.configSyncPeerSnapshotDeferredMessage
}
