package cluster

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16041: peer liveness (lastPeerRxMono / PeerHealthy) and the
// missed-heartbeat teardown must refresh ONLY on semantically accepted
// frames, and every known sync type must carry a per-type payload cap
// enforced from the header before the payload is read.
//
// These tests drive the real receiveLoop over net.Pipe so the exact
// production path — header, per-type cap, HMAC posture (unauthenticated
// pipe here), handleMessage acceptance, liveness — is exercised.

// recvHarness16041 wires a SessionSync receiveLoop to a pipe peer. The
// caller writes raw frames to peer and observes liveness on ss.
type recvHarness16041 struct {
	ss     *SessionSync
	peer   net.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

func newRecvHarness16041(t *testing.T, ss *SessionSync) *recvHarness16041 {
	t.Helper()
	if ss == nil {
		ss = NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	}
	local, peer := net.Pipe()
	// Long read deadline: no heartbeat probes interfere with the frames
	// under test; staleness is injected via lastPeerRxMono directly.
	ss.readDeadline = 5 * time.Second
	ss.installConn(0, local)
	ctx, cancel := context.WithCancel(context.Background())
	h := &recvHarness16041{ss: ss, peer: peer, cancel: cancel, done: make(chan struct{})}
	go func() {
		ss.receiveLoop(ctx, local)
		close(h.done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = local.Close()
		_ = peer.Close()
		<-h.done
	})
	return h
}

// writeFrame16041 writes one well-framed frame (valid magic/header) with
// the given type and payload, exactly as a conforming sender's writeMsg
// would frame it.
func writeFrame16041(t *testing.T, peer net.Conn, msgType uint8, payload []byte) {
	t.Helper()
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer peer.SetWriteDeadline(time.Time{}) //nolint:errcheck
	if err := writeMsg(peer, msgType, payload); err != nil {
		t.Fatalf("write frame type %d: %v", msgType, err)
	}
}

// writeRawHeader16041 writes only a header declaring length payload bytes
// that are never sent: an over-cap refusal must fire from the header alone,
// without waiting for (or allocating) the body.
func writeRawHeader16041(t *testing.T, peer net.Conn, msgType uint8, length uint32) {
	t.Helper()
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = msgType
	binary.LittleEndian.PutUint32(hdr[8:12], length)
	_ = peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	defer peer.SetWriteDeadline(time.Time{}) //nolint:errcheck
	if _, err := peer.Write(hdr); err != nil {
		t.Fatalf("write raw header type %d: %v", msgType, err)
	}
}

func staleLastRx16041(ss *SessionSync) {
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(2*syncPeerSilenceTimeout))
}

func requireStale16041(t *testing.T, ss *SessionSync, why string) {
	t.Helper()
	// Poll briefly: the receive loop processes asynchronously.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if age, ok := ss.LastPeerReceiveAge(); ok && age > syncPeerSilenceTimeout {
			if ss.PeerHealthy() {
				// Healthy requires the ack latch; arm it for the check.
				if ss.peerHeartbeatAckEver.Load() {
					t.Fatalf("%s: PeerHealthy still true with stale lastPeerRxMono", why)
				}
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	age, ok := ss.LastPeerReceiveAge()
	t.Fatalf("%s: lastPeerRxMono refreshed (age=%v ok=%v); rejected frame must not refresh liveness", why, age, ok)
}

func requireFresh16041(t *testing.T, ss *SessionSync, why string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if age, ok := ss.LastPeerReceiveAge(); ok && age < 5*time.Second {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	age, ok := ss.LastPeerReceiveAge()
	t.Fatalf("%s: accepted frame did not refresh liveness (age=%v ok=%v)", why, age, ok)
}

// settle16041 gives the receive loop a bounded window to process frames
// already written, so a following staleness assertion is not racing an
// unprocessed accepted frame.
func settle16041() { time.Sleep(50 * time.Millisecond) }

func TestRejectedFramesDoNotRefreshLiveness16041(t *testing.T) {
	// Control: an accepted empty-config-cleartext frame DOES refresh? No —
	// the production control used below is HeartbeatAck from the installed
	// conn and a valid session record via handleMessage acceptance. At the
	// receiveLoop level the accepted control is a Barrier (seq gate only)
	// and Heartbeat; both must refresh.
	t.Run("control accepted frames refresh", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		// Continuously drain peer-bound replies (BarrierAck) so the
		// synchronous net.Pipe never blocks the receive loop's ack write.
		drainDone := make(chan struct{})
		go func() {
			defer close(drainDone)
			buf := make([]byte, 256)
			for {
				if _, err := h.peer.Read(buf); err != nil {
					return
				}
			}
		}()
		staleLastRx16041(h.ss)
		var seq [8]byte
		binary.LittleEndian.PutUint64(seq[:], 1)
		writeFrame16041(t, h.peer, syncMsgBarrier, seq[:])
		requireFresh16041(t, h.ss, "barrier")
		staleLastRx16041(h.ss)
		writeFrame16041(t, h.peer, syncMsgHeartbeat, nil)
		requireFresh16041(t, h.ss, "heartbeat")
	})

	rejected := []struct {
		name    string
		msgType uint8
		payload []byte
		setup   func(ss *SessionSync)
	}{
		{"unknown type", 200, []byte{0x01, 0x02}, nil},
		{"truncated session v4", syncMsgSessionV4, []byte{0x01, 0x02, 0x03}, func(ss *SessionSync) {
			ss.SetRuntime(&mockSweepDP{})
		}},
		{"truncated session v6", syncMsgSessionV6, []byte{0x01}, func(ss *SessionSync) {
			ss.SetRuntime(&mockSweepDP{})
		}},
		{"impossible clock sync", syncMsgClockSync, clockPayload16041(1 << 62), nil},
		{"stale DHCP full-set", syncMsgDHCPLeaseV4, nil, nil}, // refined below
		{"short bulk ack", syncMsgBulkAck, []byte{1, 2, 3}, nil},
		{"short fence ack", syncMsgFenceAck, []byte{1, 2, 3}, nil},
		{"short peer capabilities", syncMsgPeerCapabilities, []byte{1}, nil},
		{"short barrier ack", syncMsgBarrierAck, []byte{1, 2, 3}, nil},
		{"heartbeat ack nil conn seam via unknown", 201, nil, nil},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
			if tc.setup != nil {
				tc.setup(ss)
			}
			h := newRecvHarness16041(t, ss)
			// Arm enforcement so PeerHealthy is also meaningful, and make
			// the last-receive stamp provably stale before the junk frame.
			h.ss.peerHeartbeatAckEver.Store(true)
			staleLastRx16041(h.ss)
			payload := tc.payload
			if tc.name == "stale DHCP full-set" {
				// Apply seq=2, then offer seq=1: stale, must not refresh.
				leases := []dhcpserver.SyncLease{dhcpChunkLease15160(41)}
				valid := appendFullSetSeq(encodeDHCPLeasePayload(leases), 77, 2)
				if accepted := h.ss.handleMessage(h.ss.getActiveConn(), syncMsgDHCPLeaseV4, valid); !accepted {
					t.Fatal("FIXTURE: seq=2 DHCP set must be accepted")
				}
				if got := h.ss.PeerDHCPLeases4(); len(got) != 1 {
					t.Fatalf("FIXTURE: held leases = %v, want 1", got)
				}
				staleLastRx16041(h.ss)
				payload = appendFullSetSeq(encodeDHCPLeasePayload(leases), 77, 1)
				writeFrame16041(t, h.peer, tc.msgType, payload)
				requireStale16041(t, h.ss, tc.name)
				if h.ss.PeerHealthy() {
					t.Fatal("stale full-set refreshed PeerHealthy")
				}
				return
			}
			writeFrame16041(t, h.peer, tc.msgType, payload)
			requireStale16041(t, h.ss, tc.name)
			if h.ss.PeerHealthy() {
				t.Fatalf("%s: rejected frame left PeerHealthy true", tc.name)
			}
		})
	}
}

func clockPayload16041(peerMono uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], peerMono)
	return b[:]
}

func TestValidSessionAcceptedAndMalformedRejectedHandleMessage16041(t *testing.T) {
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", &mockSweepDP{})
	key, val := key9508(), val9508()
	if !ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val)) {
		t.Fatal("valid session v4 record must be semantically accepted")
	}
	if ss.handleMessage(nil, syncMsgSessionV4, []byte{0x01, 0x02}) {
		t.Fatal("truncated session v4 record must be rejected")
	}
	if ss.handleMessage(nil, 200, []byte{0x01}) {
		t.Fatal("unknown type must be rejected")
	}
	// A delete of a never-installed key with gen 0 passes the generation
	// guard (gen-0 = unconditional): accepted. A well-formed delete frame
	// is accepted even though nothing was installed.
	msg := encodeDeleteV4(key, 0, false)
	if !ss.handleMessage(nil, syncMsgDeleteV4, msg[syncHeaderSize:]) {
		t.Fatal("well-formed gen-0 delete must be accepted")
	}
	if ss.handleMessage(nil, syncMsgDeleteV4, []byte{0x01}) {
		t.Fatal("truncated delete must be rejected")
	}
}

func TestPerTypePayloadCapRefusedAtHeader16041(t *testing.T) {
	oversize := []struct {
		name    string
		msgType uint8
		length  uint32
	}{
		{"heartbeat with payload", syncMsgHeartbeat, 1},
		{"barrier oversize", syncMsgBarrier, 9},
		{"capabilities oversize", syncMsgPeerCapabilities, 5 + bootIncarnationLen + 8 + 8 + 1},
		{"failover oversize", syncMsgFailover, 10},
		{"config key exchange oversize", syncMsgConfigKeyExchange, 1 + syncConfigECDHPubSize + 1},
		{"bulk start oversize", syncMsgBulkStart, 8 + bootIncarnationLen + 1},
		{"fence oversize", syncMsgFence, 9},
	}
	for _, tc := range oversize {
		t.Run(tc.name, func(t *testing.T) {
			h := newRecvHarness16041(t, nil)
			writeRawHeader16041(t, h.peer, tc.msgType, tc.length)
			// The loop must refuse from the header and drop the connection
			// WITHOUT waiting for the declared body (none is ever sent).
			select {
			case <-h.done:
			case <-time.After(2 * time.Second):
				t.Fatal("receive loop did not drop connection on per-type over-cap header")
			}
			if got := h.ss.Stats().OversizeFramesRefused; got != 1 {
				t.Fatalf("OversizeFramesRefused = %d, want 1", got)
			}
			if got := h.ss.stats.Errors.Load(); got != 1 {
				t.Fatalf("Errors = %d, want 1", got)
			}
		})
	}

	t.Run("at-cap frame is not refused", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		var seq [8]byte
		binary.LittleEndian.PutUint64(seq[:], 7)
		writeFrame16041(t, h.peer, syncMsgBarrier, seq[:])
		requireFresh16041(t, h.ss, "at-cap barrier")
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0 for an at-cap frame", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on an at-cap frame")
		default:
		}
		// Drain the BarrierAck so cleanup close is clean.
		go func() {
			buf := make([]byte, 64)
			_, _ = h.peer.Read(buf)
		}()
		settle16041()
	})

	t.Run("unknown type over global cap still refused globally", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		writeRawHeader16041(t, h.peer, 200, maxSyncPayload+1)
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Fatal("receive loop did not drop connection on global over-cap header")
		}
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0 (global cap is not the per-type counter)", got)
		}
	})

	t.Run("cap table covers every dispatched type", func(t *testing.T) {
		dispatched := []uint8{
			syncMsgSessionV4, syncMsgSessionV6, syncMsgDeleteV4, syncMsgDeleteV6,
			syncMsgBulkRequest, syncMsgBulkStart, syncMsgBulkEnd, syncMsgBulkAck,
			syncMsgConfigApplyNack, syncMsgConfigApplyAck, syncMsgHeartbeat, syncMsgHeartbeatAck,
			syncMsgConfig, syncMsgConfigEncrypted, syncMsgConfigKeyExchange,
			syncMsgAuthUpgradeRequest, syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof, syncMsgAuthUpgradeConfirm,
			syncMsgIPsecSA, syncMsgPersistentNatLease, syncMsgPersistentNatLeaseScoped,
			syncMsgPersistentNatLeaseGeneration, syncMsgPersistentNatLeaseDeterministic,
			syncMsgDHCPLeaseV4, syncMsgDHCPLeaseV6, syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk,
			syncMsgFailover, syncMsgFailoverAck, syncMsgFailoverCommit, syncMsgFailoverCommitAck,
			syncMsgFailoverBatch, syncMsgFailoverBatchAck, syncMsgFailoverBatchCommit, syncMsgFailoverBatchCommitAck,
			syncMsgFailoverAbort, syncMsgFailoverBatchAbort, syncMsgFence, syncMsgFenceAck,
			syncMsgPeerCapabilities, syncMsgClockSync, syncMsgBarrier, syncMsgBarrierAck,
		}
		for _, mt := range dispatched {
			cap, known := syncPayloadCap(mt)
			if !known {
				t.Errorf("dispatched type %d has no per-type cap", mt)
				continue
			}
			if cap < 0 || cap > maxSyncPayload {
				t.Errorf("type %d cap %d outside [0, maxSyncPayload]", mt, cap)
			}
		}
		if _, known := syncPayloadCap(200); known {
			t.Error("unknown type 200 must have no per-type cap (forward compatibility)")
		}
		// Conforming encoders must fit their caps.
		if got := len(encodeSessionV4Payload(key9508(), val9508())); got > mustCap(t, syncMsgSessionV4) {
			t.Errorf("session v4 encoder emits %d > cap %d", got, mustCap(t, syncMsgSessionV4))
		}
		if got := len(encodeDeleteV4(key9508(), 0, false)) - syncHeaderSize; got > mustCap(t, syncMsgDeleteV4) {
			t.Errorf("delete v4 encoder emits %d > cap %d", got, mustCap(t, syncMsgDeleteV4))
		}
		if got := len(encodeDHCPLeasePayload(nil)) + fullSetSeqTrailerLen; got > mustCap(t, syncMsgDHCPLeaseV4) {
			t.Errorf("DHCP encoder header emits %d > cap", got)
		}
	})
}

func mustCap(t *testing.T, msgType uint8) int {
	t.Helper()
	c, known := syncPayloadCap(msgType)
	if !known {
		t.Fatalf("type %d has no cap", msgType)
	}
	return c
}
