package cluster

import (
	"net"
	"testing"
	"time"
)

// TestReadLoopWarnsForDuplicateNodeIDFromForeignAddress10745 proves the shared
// ${node} config case reaches the duplicate-node-id defence even though its
// peer-address makes the valid heartbeat's source fail the #6888 pin. The
// frame still must be dropped: warning must not refresh liveness or drive
// election.
func TestReadLoopWarnsForDuplicateNodeIDFromForeignAddress10745(t *testing.T) {
	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("receiver socket: %v", err)
	}
	sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		recvConn.Close()
		t.Fatalf("sender socket: %v", err)
	}
	t.Cleanup(func() { sendConn.Close() })

	mgr := NewManager(1, 42)
	r := newHeartbeatReceiver(mgr, recvConn, DefaultHeartbeatThreshold,
		DefaultHeartbeatInterval, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 9), Port: 4784})
	r.start()
	t.Cleanup(r.stop)

	frame := MarshalHeartbeat(&HeartbeatPacket{NodeID: 1, ClusterID: 42})
	if _, err := sendConn.WriteToUDP(frame, recvConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send duplicate-node-id heartbeat: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.RLock()
		warned := !mgr.lastDupNodeIDWarn.IsZero()
		peerAlive, peerNodeID := mgr.peerAlive, mgr.peerNodeID
		mgr.mu.RUnlock()
		if warned && r.foreignSrc.Load() > 0 {
			if peerAlive || peerNodeID == mgr.NodeID() {
				t.Fatalf("foreign duplicate frame changed peer state: alive=%t nodeID=%d",
					peerAlive, peerNodeID)
			}
			if got := r.received.Load(); got != 0 {
				t.Fatalf("received = %d: duplicate frame reached admission", got)
			}
			if got := r.recvErrors.Load(); got != 0 {
				t.Fatalf("recvErrors = %d: valid duplicate frame was parsed as invalid", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("foreign duplicate-node-id heartbeat did not emit the #4549 warning before #6888 dropped it")
}
