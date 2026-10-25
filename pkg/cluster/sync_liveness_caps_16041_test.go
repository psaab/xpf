package cluster

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
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
	return newRecvHarnessDeadline16041(t, ss, 5*time.Second)
}

// newRecvHarnessDeadline16041 is newRecvHarness16041 with a caller-chosen
// read deadline (the deadline tests need a short absolute window).
func newRecvHarnessDeadline16041(t *testing.T, ss *SessionSync, deadline time.Duration) *recvHarness16041 {
	t.Helper()
	if ss == nil {
		ss = NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	}
	local, peer := net.Pipe()
	ss.readDeadline = deadline
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
			syncMsgIPsecSA, syncMsgIPsecSAChunk, syncMsgPersistentNatLease, syncMsgPersistentNatLeaseScoped,
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

// ===== #16041 fold: acceptance must reflect the DOWNSTREAM result =====

func failoverAckPayload16041(rgID int, status uint8, reqID uint64) []byte {
	p := make([]byte, 10)
	p[0] = byte(rgID)
	p[1] = status
	binary.LittleEndian.PutUint64(p[2:10], reqID)
	return p
}

func chunkFrame16041(t *testing.T, body []byte, generation uint64, index, total, totalLeases uint32, incarnation, seq uint64) []byte {
	t.Helper()
	return appendFullSetSeq(encodeDHCPLeaseChunkPayload(body, generation, index, total, totalLeases), incarnation, seq)
}

// TestDownstreamRejectedFramesDoNotRefreshLiveness16041 pins the fold:
// frames that decode cleanly but are rejected DOWNSTREAM (stale install,
// unmatched acks, duplicate barrier ack, inconsistent chunk assembly,
// queue-full config) must report rejection from handleMessage and must
// not refresh liveness through the real receiveLoop, while their matched
// counterparts stay accepted (controls, so a reject-everything handler
// cannot pass).
func TestDownstreamRejectedFramesDoNotRefreshLiveness16041(t *testing.T) {
	t.Run("stale install rejected, landed install accepted", func(t *testing.T) {
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
		key, val := key9508(), val9508()
		val.Generation = 9
		if !ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val)) {
			t.Fatal("CONTROL: generation-9 install must land and be accepted")
		}
		val.Generation = 1
		if ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val)) {
			t.Fatal("stale-generation install decoded cleanly but was refused downstream; must be rejected")
		}
		if got := ss.stats.InstallsStaleIgnored.Load(); got != 1 {
			t.Fatalf("FIXTURE: InstallsStaleIgnored=%d, want 1 (the stale refusal must be the downstream path)", got)
		}
		bare := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		val.Generation = 9
		if bare.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val)) {
			t.Fatal("install with no session store cannot land; must be rejected")
		}
	})

	t.Run("unmatched acks rejected, matched acks accepted", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		if ss.handleMessage(nil, syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 99)) {
			t.Fatal("failover ack matching no waiter must be rejected")
		}
		ch := make(chan failoverAck, 1)
		ss.failoverWaiters[3] = failoverWaiter{reqID: 99, ch: ch}
		if !ss.handleMessage(nil, syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 99)) {
			t.Fatal("CONTROL: failover ack matching its waiter must be accepted")
		}
		select {
		case <-ch:
		default:
			t.Fatal("CONTROL: matched failover ack must still be delivered to the waiter")
		}
		ss.failoverWaiters[3] = failoverWaiter{reqID: 100, ch: ch}
		if ss.handleMessage(nil, syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 99)) {
			t.Fatal("failover ack with a foreign reqID must be rejected")
		}
		rgIDs := []int{1, 2}
		key := failoverBatchKey(rgIDs)
		batchAck := encodeFailoverBatchAckPayload(rgIDs, failoverAckApplied, 7, "")
		if ss.handleMessage(nil, syncMsgFailoverBatchAck, batchAck) {
			t.Fatal("batch ack matching no waiter must be rejected")
		}
		bch := make(chan failoverAck, 1)
		ss.failoverBatchWaiters[key] = failoverWaiter{reqID: 7, ch: bch, rgIDs: rgIDs}
		if !ss.handleMessage(nil, syncMsgFailoverBatchAck, batchAck) {
			t.Fatal("CONTROL: batch ack matching its waiter must be accepted")
		}
		fack, _ := decodeFenceAckPayload(encodeFenceAckPayload(5, FenceResult{}))
		fpayload := encodeFenceAckPayload(5, FenceResult{})
		if ss.handleMessage(nil, syncMsgFenceAck, fpayload) {
			t.Fatal("fence ack matching no waiter must be rejected")
		}
		fch := make(chan FenceAck, 1)
		ss.fenceAckWaiters = map[uint64]fenceAckWaiter{fack.Seq: {ch: fch}}
		if !ss.handleMessage(nil, syncMsgFenceAck, fpayload) {
			t.Fatal("CONTROL: fence ack matching its waiter must be accepted")
		}
		var ack [24]byte
		binary.LittleEndian.PutUint64(ack[:], 7)
		if ss.handleMessage(nil, syncMsgBarrierAck, ack[:]) {
			t.Fatal("barrier ack matching no waiter must be rejected")
		}
		// The unmatched ack above already advanced the cumulative seq;
		// use a newer seq for the matched control.
		binary.LittleEndian.PutUint64(ack[:], 8)
		bch2 := make(chan struct{})
		ss.barrierWaiters = map[uint64]*barrierWaiter{8: {ch: bch2}}
		if !ss.handleMessage(nil, syncMsgBarrierAck, ack[:]) {
			t.Fatal("CONTROL: barrier ack matching its waiter must be accepted")
		}
		if ss.handleMessage(nil, syncMsgBarrierAck, ack[:]) {
			t.Fatal("duplicate barrier ack (already covered, no waiter) must be rejected")
		}
		var gen8 [8]byte
		binary.LittleEndian.PutUint64(gen8[:], 5)
		if ss.handleMessage(nil, syncMsgConfigApplyAck, gen8[:]) {
			t.Fatal("config ack for an unsent generation must be rejected")
		}
		ss.lastSentConfigGen.Store(5)
		if !ss.handleMessage(nil, syncMsgConfigApplyAck, gen8[:]) {
			t.Fatal("CONTROL: config ack for the last-sent generation must be accepted")
		}
		var gen0 [8]byte
		if ss.handleMessage(nil, syncMsgConfigApplyAck, gen0[:]) {
			t.Fatal("config ack for generation 0 must be rejected")
		}
	})

	t.Run("inconsistent chunk assembly rejected, consistent accepted", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		one := encodeDHCPLeasePayload([]dhcpserver.SyncLease{dhcpChunkLease15160(7)})
		if !ss.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunkFrame16041(t, one, 5, 0, 2, 1, 77, 1)) {
			t.Fatal("CONTROL: first consistent chunk must be recorded (accepted)")
		}
		bad := chunkFrame16041(t, one, 5, 1, 3, 1, 77, 2)
		if ss.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, bad) {
			t.Fatal("chunk disagreeing with the assembly on total must be rejected")
		}
		if n := len(ss.dhcpChunkState4.pending); n != 0 {
			t.Fatalf("inconsistent generation left %d pending assemblies, want 0", n)
		}
		if !ss.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunkFrame16041(t, one, 6, 0, 2, 1, 77, 3)) {
			t.Fatal("CONTROL: first chunk of the over-total fixture must be recorded")
		}
		if ss.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunkFrame16041(t, one, 6, 1, 2, 1, 77, 4)) {
			t.Fatal("chunk pushing the assembly past totalLeases must be rejected")
		}
		ss2 := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		two := encodeDHCPLeasePayload([]dhcpserver.SyncLease{dhcpChunkLease15160(7), dhcpChunkLease15160(8)})
		if !ss2.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunkFrame16041(t, one, 5, 0, 2, 2, 77, 1)) {
			t.Fatal("CONTROL: chunk 0 of a consistent pair must be accepted")
		}
		if !ss2.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunkFrame16041(t, one, 5, 1, 2, 2, 77, 2)) {
			t.Fatal("CONTROL: completing chunk must be accepted")
		}
		if got := len(ss2.PeerDHCPLeases4()); got != 2 {
			t.Fatalf("CONTROL: consistent pair must commit 2 leases (one per chunk body decoded), held %d from %v", got, two)
		}
	})

	t.Run("queue-full config rejected, queued config accepted", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		ss.configApplyCh = make(chan configApplyItem, 1)
		ss.configApplyCh <- configApplyItem{gen: 1}
		if ss.handleMessage(nil, syncMsgConfig, encodeConfigPayload("queued-behind", 9)) {
			t.Fatal("queue-full config was dropped downstream; must be rejected")
		}
		if got := ss.stats.ConfigsQueueFullDropped.Load(); got != 1 {
			t.Fatalf("FIXTURE: ConfigsQueueFullDropped=%d, want 1", got)
		}
		ss2 := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		if !ss2.handleMessage(nil, syncMsgConfig, encodeConfigPayload("fits", 9)) {
			t.Fatal("CONTROL: config with queue room must be accepted")
		}
	})

	t.Run("downstream rejections do not refresh over receiveLoop", func(t *testing.T) {
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", dp)
		key, val := key9508(), val9508()
		val.Generation = 9
		if !ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val)) {
			t.Fatal("FIXTURE: landing install must be accepted")
		}
		h := newRecvHarness16041(t, ss)
		h.ss.peerHeartbeatAckEver.Store(true)
		staleVal := val
		staleVal.Generation = 1
		frames := []struct {
			name    string
			msgType uint8
			payload []byte
		}{
			{"stale install", syncMsgSessionV4, encodeSessionV4Payload(key, staleVal)},
			{"unmatched failover ack", syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 4242)},
			{"unmatched fence ack", syncMsgFenceAck, encodeFenceAckPayload(4242, FenceResult{})},
		}
		for _, f := range frames {
			staleLastRx16041(h.ss)
			writeFrame16041(t, h.peer, f.msgType, f.payload)
			requireStale16041(t, h.ss, f.name)
			if h.ss.PeerHealthy() {
				t.Fatalf("%s: downstream-rejected frame left PeerHealthy true", f.name)
			}
		}
	})
}

// TestRejectedTrafficDoesNotRestartReadDeadline16041 pins the absolute
// read deadline: a stream of well-framed but rejected frames arriving
// faster than the deadline must NOT postpone the heartbeat timeout —
// the loop must still probe, count the miss, and (on the second miss)
// tear the connection down. Accepted traffic (the peer answering the
// probe) is the control: it keeps the connection alive.
func TestRejectedTrafficDoesNotRestartReadDeadline16041(t *testing.T) {
	const window = 60 * time.Millisecond

	t.Run("junk stream still times out and disconnects", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarnessDeadline16041(t, ss, window)
		h.ss.peerHeartbeatAckEver.Store(true)
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			buf := make([]byte, 256)
			_ = h.peer.SetReadDeadline(time.Now().Add(3 * time.Second))
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = h.peer.Read(buf)
			}
		}()
		go func() {
			tick := time.NewTicker(window / 6)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					_ = h.peer.SetWriteDeadline(time.Now().Add(time.Second))
					if err := writeMsg(h.peer, 200, []byte{0x01}); err != nil {
						return
					}
				}
			}
		}()
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Fatal("rejected junk stream restarted the read deadline: no heartbeat teardown after 2s of junk inside a 60ms window")
		}
		if h.ss.IsConnected() {
			t.Fatal("connection still marked connected after the missed-heartbeat teardown")
		}
	})

	t.Run("control answering peer stays alive", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarnessDeadline16041(t, ss, window)
		// Peer goroutine parses production frames and answers probes.
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			hdr := make([]byte, syncHeaderSize)
			for {
				_ = h.peer.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := readFull16041(h.peer, hdr); err != nil {
					return
				}
				n := int(binary.LittleEndian.Uint32(hdr[8:12]))
				if n > 0 {
					if _, err := readFull16041(h.peer, make([]byte, n)); err != nil {
						return
					}
				}
				if hdr[4] != syncMsgHeartbeat {
					continue
				}
				_ = h.peer.SetWriteDeadline(time.Now().Add(time.Second))
				if err := writeMsg(h.peer, syncMsgHeartbeatAck, nil); err != nil {
					return
				}
			}
		}()
		defer func() { _ = h.peer.Close(); <-peerDone }()
		deadline := time.After(2 * time.Second)
		for !h.ss.peerHeartbeatAckEver.Load() {
			select {
			case <-deadline:
				t.Fatal("CONTROL: peer acks never latched the heartbeat-ack capability")
			case <-time.After(time.Millisecond):
			}
		}
		time.Sleep(4 * window)
		select {
		case <-h.done:
			t.Fatal("CONTROL: answering peer was torn down despite accepted acks")
		default:
		}
		if !h.ss.IsConnected() {
			t.Fatal("CONTROL: answering peer disconnected")
		}
	})
}

func readFull16041(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
