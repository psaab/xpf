package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #12165: a heartbeat-only gap separated from an earlier suppression window
// by heartbeat recovery must get its own full 5s suppression cap. The
// suppression stamp is re-armed when heartbeats recover, so the second
// interval is capped independently of the first instead of inheriting a
// stamp whose cap is already consumed.
func TestHeartbeatRecoveryRearmsSuppressionCap12165(t *testing.T) {
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	// Same connection, fresh sync traffic across both gaps: the :175/:180
	// resets must NOT fire, isolating the heartbeat-recovery re-arm.
	ss.SetConnectedForTesting(true)
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)

	d := newWiringTestDaemon()
	d.cluster = newClusterManager(false)
	d.sessionSync = ss
	d.wireClusterPeerFailoverHooks(ss)
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

	// Interval #1: heartbeat gap with fresh sync → suppression starts and
	// the peer stays alive, so local ownership does not change.
	d.cluster.HandlePeerTimeoutForTesting()
	if !d.cluster.PeerAlive() || d.cluster.IsLocalPrimary(0) {
		t.Fatal("interval #1: peer loss escaped suppression or local node took over")
	}
	first := d.hbSuppressStart.Load()
	if first == 0 {
		t.Fatal("interval #1: hbSuppressStart = 0 after suppression began, want nonzero stamp")
	}

	// Recovery ends the first suppression interval through the real
	// heartbeat admission path while sync stays connected and fresh.
	d.cluster.HandlePeerHeartbeatForTesting(peerHeartbeat)

	// Let the first stamp age past its 5s cap while heartbeats are healthy.
	// The second heartbeat-only gap begins afterward on the same sync session.
	time.Sleep(5*time.Second + 10*time.Millisecond)
	ss.SetPeerReceiveAgeForTesting(100*time.Millisecond, true)

	// Interval #2: the independent cap suppresses this timeout. Without the
	// recovery clear, the stale first stamp causes takeover here.
	d.cluster.HandlePeerTimeoutForTesting()
	if !d.cluster.PeerAlive() || d.cluster.IsLocalPrimary(0) {
		t.Fatal("interval #2: stale first suppression stamp caused premature peer loss and local takeover")
	}
	second := d.hbSuppressStart.Load()
	if second == 0 {
		t.Fatal("interval #2: hbSuppressStart = 0 after re-armed suppression, want nonzero stamp")
	}
	if second <= first {
		t.Fatalf("interval #2: hbSuppressStart = %d, want a fresh stamp after first interval's %d (recovery did not re-arm the cap)", second, first)
	}
	if age := time.Duration(cluster.MonotonicNanos() - second); age < 0 || age > 5*time.Second {
		t.Fatalf("interval #2: re-armed stamp age = %v, want within [0, 5s]", age)
	}
}
