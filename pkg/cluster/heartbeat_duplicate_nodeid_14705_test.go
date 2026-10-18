package cluster

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestRecvLoop_DuplicateNodeIDHeartbeatRequiresHMAC_14705 is the #14705
// decisive regression. It drives the REAL heartbeatReceiver.readLoop over
// real UDP sockets with a KEYED manager and a peer pin matching the sender,
// so the only gate that can stop the forged frames is HMAC verification.
//
// Pre-fix, readLoop called NoteDuplicateNodeIDHeartbeat before admitFrame,
// so unsigned / wrong-key same-NodeID frames from the peer IP forged an
// EventRG history entry and consumed the shared 30s limiter, suppressing a
// genuine authenticated beacon warning. Post-fix:
//
//   - unsigned and wrong-key same-NodeID frames produce no history entry
//     and do not consume the limiter (lastDupNodeIDWarn stays zero), and
//     do not touch liveness;
//   - a genuine authenticated beacon immediately afterwards still warns
//     (the limiter was not poisoned);
//   - a correctly signed (primary or rotation-alt key) same-NodeID
//     heartbeat still warns and is still discarded (no liveness/election),
//     and does not consume replay state: the same nonce arriving as a
//     normal different-NodeID heartbeat is still admitted.
//
// FAIL-ON-REVERT: remove the duplicateNodeIDAuthenticated gate in readLoop
// (call NoteDuplicateNodeIDHeartbeat unconditionally) and the forged-frame
// step reds with a forged history entry / consumed limiter.
func TestRecvLoop_DuplicateNodeIDHeartbeatRequiresHMAC_14705(t *testing.T) {
	const (
		nodeID    = 1
		clusterID = 42
		psk       = "a-test-control-link-psk-14705"
		pskAlt    = "a-rotated-control-link-psk-14705"
		wrongPSK  = "an-attacker-psk-14705"
	)

	setup := func(t *testing.T, signKey, altKey string) (*Manager, *heartbeatReceiver, *net.UDPConn, *net.UDPAddr) {
		t.Helper()
		mgr := NewManager(nodeID, clusterID)
		mgr.UpdateConfig(&config.ClusterConfig{
			ControlLinkAuthKey:    config.Secret(signKey),
			ControlLinkAuthKeyAlt: config.Secret(altKey),
		})
		if len(mgr.controlLinkAcceptedKeys()) == 0 {
			t.Fatal("fixture broken: keyed manager accepted no keys")
		}
		recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("receiver socket: %v", err)
		}
		sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			recvConn.Close()
			t.Fatalf("sender socket: %v", err)
		}
		// Pin to the sender's IP: the frames below arrive FROM the configured
		// peer, so the #6888 source pin passes and HMAC is the only gate.
		peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		r := newHeartbeatReceiver(mgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, peer)
		r.startedAt = time.Now()
		r.wg.Add(1)
		go r.readLoop()
		t.Cleanup(func() {
			r.stop()
			sendConn.Close()
		})
		return mgr, r, sendConn, recvConn.LocalAddr().(*net.UDPAddr)
	}

	send := func(t *testing.T, conn *net.UDPConn, dst *net.UDPAddr, frame []byte) {
		t.Helper()
		if _, err := conn.WriteToUDP(frame, dst); err != nil {
			t.Fatalf("send frame: %v", err)
		}
	}

	// waitWarn polls until the duplicate limiter is consumed or timeout.
	waitWarn := func(mgr *Manager, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			mgr.mu.RLock()
			warned := !mgr.lastDupNodeIDWarn.IsZero()
			mgr.mu.RUnlock()
			if warned {
				return true
			}
			time.Sleep(time.Millisecond)
		}
		return false
	}

	dupPkt := &HeartbeatPacket{NodeID: nodeID, ClusterID: clusterID}

	t.Run("forged_frames_do_not_warn_or_suppress_beacon", func(t *testing.T) {
		mgr, r, sendConn, dst := setup(t, psk, "")

		// Unsigned same-NodeID frame (no auth trailer at all).
		send(t, sendConn, dst, MarshalHeartbeat(dupPkt))
		// Wrong-key signed same-NodeID frame.
		send(t, sendConn, dst, MarshalHeartbeatAuth(dupPkt, []byte(wrongPSK), 0x14705, 1))
		// Tampered signed frame: valid key, then flip a body byte.
		tampered := MarshalHeartbeatAuth(dupPkt, []byte(psk), 0x14705, 2)
		tampered[10] ^= 0xff
		send(t, sendConn, dst, tampered)

		// Give readLoop ample time to (incorrectly) warn.
		if waitWarn(mgr, 500*time.Millisecond) {
			t.Fatal("forged same-NodeID heartbeat consumed the duplicate limiter " +
				"without HMAC verification (#14705)")
		}
		if got := beaconHistoryCount(mgr, "duplicate node-id"); got != 0 {
			t.Fatalf("forged frames produced %d duplicate history entries, want 0", got)
		}
		if got := r.lastSeen.Load(); got != 0 {
			t.Fatalf("forged duplicate frame refreshed liveness: lastSeen=%d", got)
		}

		// The genuine authenticated beacon must still warn within the same
		// 30s window — proof the limiter was not poisoned.
		mgr.NoteDuplicateNodeIDBeacon("em0")
		if got := beaconHistoryCount(mgr, "authenticated control-link beacon"); got != 1 {
			t.Fatalf("genuine beacon history entries = %d, want 1 (unauthenticated "+
				"frames suppressed the authenticated diagnostic)", got)
		}
	})

	t.Run("signed_duplicate_warns_discards_and_preserves_replay", func(t *testing.T) {
		mgr, r, sendConn, dst := setup(t, psk, pskAlt)

		const session, counter = 0x14705, 1
		send(t, sendConn, dst, MarshalHeartbeatAuth(dupPkt, []byte(psk), session, counter))
		if !waitWarn(mgr, 5*time.Second) {
			t.Fatal("correctly signed duplicate-node-id heartbeat did not warn")
		}
		if got := beaconHistoryCount(mgr, "duplicate node-id: invalid cluster configuration"); got != 1 {
			t.Fatalf("signed duplicate history entries = %d, want 1", got)
		}
		if got := r.lastSeen.Load(); got != 0 {
			t.Fatalf("signed duplicate frame was admitted (lastSeen=%d); it must be discarded", got)
		}

		// The duplicate path must NOT have consumed replay state: the same
		// session/counter arriving as a normal peer heartbeat is admitted.
		peerPkt := &HeartbeatPacket{NodeID: nodeID + 1, ClusterID: clusterID}
		peerFrame := MarshalHeartbeatAuth(peerPkt, []byte(psk), session, counter)
		parsed, err := UnmarshalHeartbeat(peerFrame)
		if err != nil {
			t.Fatalf("unmarshal peer frame: %v", err)
		}
		if !r.admitFrame(peerFrame, parsed) {
			t.Fatal("peer heartbeat with the duplicate frame's nonce was rejected — " +
				"the duplicate path consumed replay state it must leave alone")
		}
	})

	t.Run("rotation_key_duplicate_warns", func(t *testing.T) {
		mgr, _, sendConn, dst := setup(t, psk, pskAlt)
		send(t, sendConn, dst, MarshalHeartbeatAuth(dupPkt, []byte(pskAlt), 0x14706, 1))
		if !waitWarn(mgr, 5*time.Second) {
			t.Fatal("duplicate heartbeat signed with the accepted rotation key did not warn — " +
				"verifying against the signing key only reopens the #6630 window for this signal")
		}
	})

	t.Run("unkeyed_duplicate_still_warns", func(t *testing.T) {
		// Unkeyed manager: no keys configured, dual-accept posture. Build it
		// without UpdateConfig keys (setup always keys, so build inline).
		mgr := NewManager(nodeID, clusterID)
		if len(mgr.controlLinkAcceptedKeys()) != 0 {
			t.Fatal("fixture broken: unkeyed manager accepted keys")
		}
		recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("receiver socket: %v", err)
		}
		sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			recvConn.Close()
			t.Fatalf("sender socket: %v", err)
		}
		r := newHeartbeatReceiver(mgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval,
			&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		r.startedAt = time.Now()
		r.wg.Add(1)
		go r.readLoop()
		t.Cleanup(func() { r.stop(); sendConn.Close() })

		send(t, sendConn, recvConn.LocalAddr().(*net.UDPAddr), MarshalHeartbeat(dupPkt))
		if !waitWarn(mgr, 5*time.Second) {
			t.Fatal("unkeyed duplicate-node-id heartbeat no longer warns — " +
				"the dual-accept legacy path must be preserved")
		}
		if got := r.lastSeen.Load(); got != 0 {
			t.Fatalf("unkeyed duplicate frame was admitted (lastSeen=%d); it must be discarded", got)
		}
	})
}
