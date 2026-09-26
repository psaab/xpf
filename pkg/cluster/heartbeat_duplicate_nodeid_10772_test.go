package cluster

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type duplicateNodeIDLogBuffer10772 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *duplicateNodeIDLogBuffer10772) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *duplicateNodeIDLogBuffer10772) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRecvLoop_DuplicateNodeIDWarningDescribesIndependentPromotion_10772 drives
// both production readLoops with same-cluster duplicate-ID frames, then advances
// their startup grace without waiting 35 seconds. It checks that the warning
// describes the resulting two independent PRIMARY claims, not electRG's
// fail-closed behavior (which recvLoop never reaches for these frames).
func TestRecvLoop_DuplicateNodeIDWarningDescribesIndependentPromotion_10772(t *testing.T) {
	var logs duplicateNodeIDLogBuffer10772
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	const nodeID, clusterID = 7, 42
	managers := make([]*Manager, 2)
	receivers := make([]*heartbeatReceiver, 2)
	senders := make([]*net.UDPConn, 2)
	for i := range managers {
		mgr := NewManager(nodeID, clusterID)
		mgr.controlInterface = "hb0"
		mgr.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{nodeID: 200})))
		mgr.mu.Lock()
		mgr.groups[0].Ready = true
		mgr.groups[0].ReadySince = time.Now().Add(-time.Second)
		mgr.mu.Unlock()
		if mgr.IsLocalPrimary(0) {
			t.Fatalf("node %d is primary before peer absence is confirmed", i)
		}

		recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("node %d receiver socket: %v", i, err)
		}
		sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			recvConn.Close()
			t.Fatalf("node %d sender socket: %v", i, err)
		}
		r := newHeartbeatReceiver(mgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
		r.wg.Add(1)
		go r.readLoop()
		managers[i], receivers[i], senders[i] = mgr, r, sendConn
	}
	t.Cleanup(func() {
		for _, r := range receivers {
			r.stop()
		}
		for _, conn := range senders {
			conn.Close()
		}
	})

	frame := MarshalHeartbeat(&HeartbeatPacket{NodeID: nodeID, ClusterID: clusterID})
	for i := range receivers {
		peer := (i + 1) % len(receivers)
		dst := receivers[peer].conn.LocalAddr().(*net.UDPAddr)
		if _, err := senders[i].WriteToUDP(frame, dst); err != nil {
			t.Fatalf("node %d send duplicate-ID heartbeat: %v", i, err)
		}
	}

	for i, mgr := range managers {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mgr.mu.RLock()
			warned := !mgr.lastDupNodeIDWarn.IsZero()
			mgr.mu.RUnlock()
			if warned {
				break
			}
			time.Sleep(time.Millisecond)
		}
		mgr.mu.RLock()
		warned := !mgr.lastDupNodeIDWarn.IsZero()
		peerSeen, peerAlive, peerConfirmedAbsent := mgr.peerEverSeen, mgr.peerAlive, mgr.peerConfirmedAbsent
		mgr.mu.RUnlock()
		if !warned {
			t.Fatalf("node %d recvLoop did not emit duplicate-node-id warning", i)
		}
		if got := receivers[i].lastSeen.Load(); got != 0 || peerSeen || peerAlive || peerConfirmedAbsent {
			t.Fatalf("node %d admitted duplicate frame: lastSeen=%d peerEverSeen=%v peerAlive=%v peerConfirmedAbsent=%v; all must remain unset before grace", i, got, peerSeen, peerAlive, peerConfirmedAbsent)
		}
	}

	warning := logs.String()
	if strings.Count(warning, "duplicate node-id detected") != len(managers) {
		t.Fatalf("duplicate warning count = %d, want %d; log: %s", strings.Count(warning, "duplicate node-id detected"), len(managers), warning)
	}
	if !strings.Contains(warning, "peer is treated as absent") || !strings.Contains(warning, "both claim PRIMARY with duplicate VIPs on the segment") {
		t.Fatalf("warning does not describe recvLoop's peer-absent / independent-promotion outcome: %s", warning)
	}
	if strings.Contains(warning, "fail closed to SECONDARY") {
		t.Fatalf("recvLoop warning falsely claims election's fail-closed outcome: %s", warning)
	}

	// The startup peer-absent floor is 30s; simulate 35s of receiver uptime so
	// checkTimeout takes the exact production path without a 35s wall-clock wait.
	for _, r := range receivers {
		r.startedAt = time.Now().Add(-heartbeatStartupGrace - 5*time.Second)
		r.checkTimeout()
	}
	for i, mgr := range managers {
		if !mgr.IsLocalPrimary(0) {
			t.Fatalf("node %d state after peer-absent grace = %s, want PRIMARY (warning: %s)", i, mgr.GroupStates()[0].State, warning)
		}
	}
}
