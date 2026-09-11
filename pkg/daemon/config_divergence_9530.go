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
