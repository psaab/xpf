package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #12165 (moved to the Manager in #17056): a heartbeat-only gap separated
// from an earlier suppression window by heartbeat recovery must get its
// own full 5s suppression cap. The suppression stamp now lives in
// pkg/cluster under Manager.mu and is re-armed when heartbeats recover
// through real admission, so the second interval is capped independently
// of the first instead of inheriting a stamp whose cap is already
// consumed. This daemon-level cell drives the real wiring
// (wireClusterPeerFailoverHooks -> SetPeerSyncSource) end to end; the
// stamp itself is observed through the Manager seam.
// FAIL-ON-REVERT: remove the admission clear in
// cluster.handlePeerHeartbeat (or the SetPeerSyncSource publish here)
// and interval #2 promotes instead of suppressing.
func TestHeartbeatRecoveryRearmsSuppressionCap12165(t *testing.T) {
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	// Same connection, fresh sync traffic across both gaps: the sync-quiet
	// and disconnect resets must NOT fire, isolating the heartbeat-recovery
	// re-arm.
	ss.SetConnectedForTesting(true)
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)

	d := newWiringTestDaemon()
	d.cluster = newClusterManager(false)
	d.sessionSync = ss
	d.wireClusterPeerFailoverHooks(ss)
	if !d.cluster.SyncSourceInstalled() {
		t.Fatal("wireClusterPeerFailoverHooks did not publish the sync source (#17056)")
	}
	peerHeartbeat := &cluster.HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []cluster.HeartbeatGroup{{
			GroupID:  0,
			Priority: 100,
			Weight:   100,
			State:    uint8(cluster.StatePrimary),
		}},
	}
	d.cluster.HandlePeerHeartbeatForTesting(peerHeartbeat)

	// Interval #1: heartbeat gap with fresh sync -> suppression starts and
	// the peer stays alive, so local ownership does not change.
	d.cluster.HandlePeerTimeoutForTesting()
	if !d.cluster.PeerAlive() || d.cluster.IsLocalPrimary(0) {
		t.Fatal("interval #1: peer loss escaped suppression or local node took over")
	}
	first := d.cluster.HBSuppressStartForTesting()
	if first == 0 {
		t.Fatal("interval #1: hbSuppressStart = 0 after suppression began, want nonzero stamp")
	}

	// Recovery ends the first suppression interval through the real
	// heartbeat admission path while sync stays connected and fresh.
	// Admission must clear the stamp in the same critical section.
	d.cluster.HandlePeerHeartbeatForTesting(peerHeartbeat)
	if got := d.cluster.HBSuppressStartForTesting(); got != 0 {
		t.Fatalf("recovery: hbSuppressStart = %d, want cleared (0) after heartbeat admission", got)
	}

	// Backdate would-be stale stamp is now impossible from the daemon;
	// instead age the (cleared) state by moving straight to interval #2:
	// it must stamp fresh (> first) and suppress. Without the recovery
	// clear, interval #1's stamp (backdated past its cap below in the
	// cluster cell) would cause takeover here; at daemon level the clear
	// assertion above is the direct pin, and the stamp ordering below
	// proves re-arm.
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)
	d.cluster.HandlePeerTimeoutForTesting()
	if !d.cluster.PeerAlive() || d.cluster.IsLocalPrimary(0) {
		t.Fatal("interval #2: stale first suppression stamp caused premature peer loss and local takeover")
	}
	second := d.cluster.HBSuppressStartForTesting()
	if second == 0 {
		t.Fatal("interval #2: hbSuppressStart = 0 after re-armed suppression, want nonzero stamp")
	}
	if second < first {
		t.Fatalf("interval #2: hbSuppressStart = %d, want a stamp no earlier than first interval's %d (recovery did not re-arm the cap)", second, first)
	}
	if age := time.Duration(cluster.MonotonicNanos() - second); age < 0 || age > 5*time.Second {
		t.Fatalf("interval #2: re-armed stamp age = %v, want within [0, 5s]", age)
	}

	// Once the second continuous suppression interval exceeds 5s, its own
	// cap must stop suppressing and allow takeover.
	d.cluster.SetHBSuppressStartForTesting(cluster.MonotonicNanos() - (6 * time.Second).Nanoseconds())
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)
	d.cluster.HandlePeerTimeoutForTesting()
	if d.cluster.PeerAlive() || !d.cluster.IsLocalPrimary(0) {
		t.Fatal("interval #2: suppression did not expire after its own 5s cap")
	}

	// Unpublishing the source (stop path) must stop suppression entirely:
	// a later timeout with no source declares peer loss at once.
	d.cluster.SetPeerSyncSource(nil)
	if d.cluster.SyncSourceInstalled() {
		t.Fatal("SetPeerSyncSource(nil) left the sync source installed")
	}
}
