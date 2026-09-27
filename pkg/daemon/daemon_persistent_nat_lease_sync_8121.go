package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8121: push this node's IDLE persistent-NAT leases to the peer.
//
// CADENCE. 30s, deliberately slow and stated as a number so it can be reviewed
// as one. The control socket is shared with the 1/s status poll, HA session
// sync, session installs, snapshot sync and forwarding sync, and CLAUDE.md is
// explicit that a new caller at >1/s starves session installs during bulk sync.
// One request per 30s is 0.033/s — a 30x margin under that threshold.
//
// It is also slow relative to what it protects. The exposure is a client that
// went idle within its persistence timeout, which is typically 300s; a 30s
// push means at most the last 30s of newly-idle leases are missing on the
// peer, against a window an order of magnitude longer. Pushing faster would buy
// a shrinking slice of an already-narrow window at the cost of the one resource
// the codebase says not to spend.
const persistentNatLeaseSyncInterval = 30 * time.Second

// persistentNatLeaseManager returns the userspace helper manager, or nil when
// the published dataplane is not the userspace adapter.
func (d *Daemon) persistentNatLeaseManager() *dpuserspace.Manager {
	if d == nil {
		return nil
	}
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	adapter, ok := rt.(interface {
		Manager() *dpuserspace.Manager
	})
	if !ok {
		return nil
	}
	return adapter.Manager()
}

// wirePersistentNatLeaseCallbacks installs the receive side. Must be called
// before ss.Start, with the other ss.On* callbacks.
func (d *Daemon) wirePersistentNatLeaseCallbacks(ss *cluster.SessionSync) {
	ss.OnPersistentNatLeasesReceived = func(leases []dpuserspace.IdleLeaseWire) {
		mgr := d.persistentNatLeaseManager()
		if mgr == nil {
			return
		}
		if err := mgr.ImportIdleLeases(leases); err != nil {
			// Debug, not Info: this fires on every peer push, and the
			// import is advisory — failing to rebuild an idle lease costs
			// one client its port on takeover, it does not drop traffic.
			slog.Debug("persistent-NAT idle lease import failed", "count", len(leases), "err", err)
		}
	}
}

// runPersistentNatLeaseSyncLoop re-advertises locally-owned idle leases on a
// slow tick. Imported leases are filtered at the allocator; a local flow's
// 0 -> 1 reuse promotes one for future export. The node-level RG-master gate
// still cannot identify per-RG lease ownership, so an imported idle lease on a
// newly-mastered RG remains suppressed until locally used.
//
// A peer running the old helper can echo records during a rolling upgrade; the
// accepted bounded window ends when that peer upgrades/restarts. A copy already
// received by a peer can remain usable until its derived expiry after A retires
// it early: this additive channel has no retract/tombstone. Config sync still
// converges configuration, while the stale peer copy ages out.
func (d *Daemon) runPersistentNatLeaseSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(persistentNatLeaseSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-read per tick through the accessor: the field is
			// published asynchronously and nilled by stopClusterComms, so a
			// pointer captured at loop start can outlive its comms context.
			ss := d.getSessionSync()
			if ss == nil || !d.persistentNatLeaseGateOpen() {
				continue
			}
			mgr := d.persistentNatLeaseManager()
			if mgr == nil {
				continue
			}
			leases, err := mgr.ExportIdleLeases()
			if err != nil {
				slog.Debug("persistent-NAT idle lease export failed", "err", err)
				continue
			}
			// This is additive state, not a full-set replacement: an empty
			// batch cannot retract a peer copy and is not sent. Re-advertise
			// nonempty local leases each slow tick so a reconnecting peer can
			// learn them; early retirements converge by expiry, not retraction.
			if len(leases) != 0 {
				ss.QueuePersistentNatLeases(leases)
			}
		}
	}
}

// persistentNatLeaseGateOpen reports whether this node is RG master for any
// redundancy group — the same node-level gate the #2239 DHCP lease push uses.
func (d *Daemon) persistentNatLeaseGateOpen() bool {
	if d == nil || d.cluster == nil {
		return false
	}
	for _, isMaster := range d.snapshotRethMasterState() {
		if isMaster {
			return true
		}
	}
	return false
}
