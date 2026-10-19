package daemon

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #9530/#15212: the daemon half of the config-sync divergence alarm.
//   - The store marks every local promotion (see unshared_9530.go); the
//     daemon still wires configPeerReachable for reachability reporting.
//   - A push to a peer that reads RG0 secondary stamps the carrying wire
//     generation on the mark (noteConfigSharedWithPeerAtGeneration); only a
//     positive config-apply ACK at or beyond that generation clears it
//     (notePeerConfigApplyAck). A NACK never clears it.
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

// noteConfigSharedWithPeer runs after this node queued pushedText as RG0
// authority. #15212: a queued write is NOT proof the peer holds the content,
// so this only stamps the carrying wire generation on the unshared mark
// (when the peer reads secondary; in the dual-active heal window the peer
// still reads primary and rejects the push, so no stamp is recorded). The
// mark itself clears only on notePeerConfigApplyAck.
func (d *Daemon) noteConfigSharedWithPeer(pushedText string) {
	d.noteConfigSharedWithPeerAtGeneration(pushedText, 0)
}

// noteConfigSharedWithPeerAtGeneration is noteConfigSharedWithPeer with the
// wire generation that carries pushedText (0 when unknown, e.g. test seams).
func (d *Daemon) noteConfigSharedWithPeerAtGeneration(pushedText string, wireGen uint64) {
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
	if !reachable || !peerSecondary {
		return
	}
	d.store.NoteActivePushedAtGeneration(pushedText, wireGen)
	if wireGen != 0 {
		d.configSyncMu.Lock()
		d.configSyncPushedDigest = pushedText
		d.configSyncPushedWireGen = wireGen
		applied := d.configSyncAppliedGen
		d.configSyncMu.Unlock()
		if applied >= wireGen {
			d.store.NotePeerConfigApplyAck(applied)
		}
	}
}

// noteConfigSharedWithPeerAtEpoch prevents an old connection's queued write
// from stamping the unshared marker after a reconnect has begun.
func (d *Daemon) noteConfigSharedWithPeerAtEpoch(pushedText string, epoch uint64) bool {
	return d.noteConfigSharedWithPeerAtEpochGen(pushedText, epoch, 0)
}

func (d *Daemon) noteConfigSharedWithPeerAtEpochGen(pushedText string, epoch uint64, wireGen uint64) bool {
	if d == nil {
		return false
	}
	d.configSyncMu.Lock()
	if d.syncPeerConnEpoch.Load() != epoch || !d.syncPeerConnected.Load() {
		d.configSyncMu.Unlock()
		return false
	}
	d.configSyncMu.Unlock()
	d.noteConfigSharedWithPeerAtGeneration(pushedText, wireGen)
	return true
}

// notePeerConfigApplyAck records a positive config-apply ACK from the peer
// (#15212). It clears the unshared mark only when the ACK is at or beyond
// the carrying generation the store has on record. ACKs that arrive before
// the carrying push is stamped are remembered in configSyncAppliedGen and
// applied when the stamp lands.
func (d *Daemon) notePeerConfigApplyAck(gen uint64) {
	if d == nil || gen == 0 {
		return
	}
	d.configSyncMu.Lock()
	if gen > d.configSyncAppliedGen {
		d.configSyncAppliedGen = gen
	}
	d.configSyncMu.Unlock()
	if d.store != nil {
		d.store.NotePeerConfigApplyAck(gen)
	}
}

// notePeerConfigApplyFailed records that the peer refused or failed to apply
// gen (#15212). A NACK never clears the unshared mark; it only re-arms the
// push so the reconciler re-sends the generation.
func (d *Daemon) notePeerConfigApplyFailed(gen uint64) {
	// Deliberately no store clear: the mark must survive a NACKed generation.
	d.invalidateConfigSyncPushed()
}

// reportConfigSyncDivergence raises the divergence as a cluster event after a
// peer config sync is accepted, including one pending deferred publication.
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
