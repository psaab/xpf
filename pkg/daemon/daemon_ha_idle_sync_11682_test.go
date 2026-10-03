package daemon

import (
	"testing"
	"time"
)

// TestWireClusterPeerFailoverHooksUsesIdleSyncSilenceWindow11682 keeps the
// actual daemon hook and the session-sync policy bound together. An ACK-only
// peer remains proof of life through the full 10s sync probe cadence, while a
// disconnected, never-received, or >30s-silent peer still permits absence.
func TestWireClusterPeerFailoverHooksUsesIdleSyncSilenceWindow11682(t *testing.T) {
	d := newWiringTestDaemon()
	ss := newWiringTestSessionSync()
	d.wireClusterPeerFailoverHooks(ss)

	ss.SetConnectedForTesting(true)
	ss.SetPeerReceiveAgeForTesting(10*time.Second, true)
	if !d.cluster.PeerNeverSeenSyncFreshForTesting() {
		t.Fatal("daemon never-seen probe rejected an ACK-only peer within the sync silence window")
	}

	ss.SetPeerReceiveAgeForTesting(31*time.Second, true)
	if d.cluster.PeerNeverSeenSyncFreshForTesting() {
		t.Fatal("daemon never-seen probe held absence after the sync silence window")
	}

	ss.SetPeerReceiveAgeForTesting(0, false)
	if d.cluster.PeerNeverSeenSyncFreshForTesting() {
		t.Fatal("connected sync peer with no received proof held absence")
	}

	ss.SetPeerReceiveAgeForTesting(10*time.Second, true)
	ss.SetConnectedForTesting(false)
	if d.cluster.PeerNeverSeenSyncFreshForTesting() {
		t.Fatal("disconnected sync peer held absence")
	}

}
