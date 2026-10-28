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
				if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
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

// ===== #17093: growable caps carry reserve; fixed types do not =====

// TestGrowableFramesSurviveReceiveLoop17093 drives every growable row at
// encoderMax+8 (and PeerCapabilities also at encoderMax+reserve) through
// the real receiveLoop. Pre-fix the +8 frames are header-refused
// (cap == encoderMax) and the connection drops; post-fix they must be
// dispatched, the leading fields must decode, and the connection must
// stay up (requireFresh where the handler accepts; no oversize refusal
// and no drop in every case).
func TestGrowableFramesSurviveReceiveLoop17093(t *testing.T) {
	t.Run("peer capabilities +8 decodes leading fields", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarness16041(t, ss)
		payload := capabilityPayload17093(t, 5+bootIncarnationLen+8+8+1+8)
		staleLastRx16041(ss)
		writeFrame16041(t, h.peer, syncMsgPeerCapabilities, payload)
		requireFresh16041(t, ss, "capabilities +8")
		if got := ss.PeerSessionSyncWireVersion(); got != SessionSyncWireVersion {
			t.Fatalf("PeerSessionSyncWireVersion = %d, want %d (leading fields must decode)", got, SessionSyncWireVersion)
		}
		// #18116 (B1): the fixture APPENDS its extension bytes after
		// flags2, so flags2 must still decode from its fixed offset —
		// a len-1 read would take the trailing 0 byte instead.
		if got := ss.peerIncarnationState().peerCapabilityFlags2.Load(); got != uint32(localCapabilityFlags2) {
			t.Fatalf("peerCapabilityFlags2 = %d, want %d (appended trailing byte corrupted flags2)", got, localCapabilityFlags2)
		}
		if got := ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on growable +8 frame")
		default:
		}
	})

	t.Run("peer capabilities +reserve survives", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarness16041(t, ss)
		payload := capabilityPayload17093(t, 5+bootIncarnationLen+8+8+1+syncExtensionReserve)
		writeFrame16041(t, h.peer, syncMsgPeerCapabilities, payload)
		settle16041()
		if got := ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0 at encoderMax+reserve", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection at encoderMax+reserve")
		default:
		}
		if got := ss.PeerSessionSyncWireVersion(); got != SessionSyncWireVersion {
			t.Fatalf("PeerSessionSyncWireVersion = %d, want %d", got, SessionSyncWireVersion)
		}
		if got := ss.peerIncarnationState().peerCapabilityFlags2.Load(); got != uint32(localCapabilityFlags2) {
			t.Fatalf("peerCapabilityFlags2 = %d, want %d at +reserve (appended bytes corrupted flags2)", got, localCapabilityFlags2)
		}
	})

	t.Run("config key exchange +8 survives", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		payload := make([]byte, 1+syncConfigECDHPubSize+8)
		payload[0] = syncConfigCryptoVersion
		// A valid X25519 point is not needed: the cap check is the cell.
		// The handler may reject the key semantically, but the header
		// must not refuse the frame nor drop the connection.
		writeFrame16041(t, h.peer, syncMsgConfigKeyExchange, payload)
		settle16041()
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on config key exchange +8")
		default:
		}
	})

	t.Run("bulk start +8 survives", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		payload := make([]byte, 8+bootIncarnationLen+8)
		binary.LittleEndian.PutUint64(payload[:8], 1)
		writeFrame16041(t, h.peer, syncMsgBulkStart, payload)
		settle16041()
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on bulk start +8")
		default:
		}
	})

	t.Run("bulk end +8 dispatches (no refusal, no drop)", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		payload := make([]byte, 8+bootIncarnationLen+8)
		binary.LittleEndian.PutUint64(payload[:8], 1)
		writeFrame16041(t, h.peer, syncMsgBulkEnd, payload)
		settle16041()
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on bulk end +8")
		default:
		}
	})

	t.Run("barrier ack +8 survives", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarness16041(t, ss)
		payload := make([]byte, 24+8)
		binary.LittleEndian.PutUint64(payload[0:8], 7)
		binary.LittleEndian.PutUint64(payload[8:16], 3)
		binary.LittleEndian.PutUint64(payload[16:24], 2)
		// Without a live waiter the ack is downstream-rejected, but it
		// must NOT be header-refused nor drop the connection.
		writeFrame16041(t, h.peer, syncMsgBarrierAck, payload)
		settle16041()
		if got := ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
		select {
		case <-h.done:
			t.Fatal("receive loop dropped connection on barrier ack +8")
		default:
		}
	})

	t.Run("fence +8 survives and acks", func(t *testing.T) {
		h := newRecvHarness16041(t, nil)
		payload := make([]byte, 16)
		binary.LittleEndian.PutUint64(payload[:8], 1)
		writeFrame16041(t, h.peer, syncMsgFence, payload)
		// Fence with seq 1 requests a FenceAck reply.
		_ = h.peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		if _, err := h.peer.Read(buf); err != nil {
			t.Fatalf("expected fence ack reply: %v", err)
		}
		if got := h.ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
	})

	t.Run("fence ack +8 completes waiter", func(t *testing.T) {
		ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
		h := newRecvHarness16041(t, ss)
		waiter := make(chan FenceAck, 1)
		ss.fenceAckMu.Lock()
		if ss.fenceAckWaiters == nil {
			ss.fenceAckWaiters = make(map[uint64]fenceAckWaiter)
		}
		ss.fenceAckWaiters[7] = fenceAckWaiter{ch: waiter}
		ss.fenceAckMu.Unlock()
		payload := append(encodeFenceAckPayload(7, FenceResult{RGsFenced: 2, RGsTotal: 2, DataplaneAvailable: true}), make([]byte, 8)...)
		writeFrame16041(t, h.peer, syncMsgFenceAck, payload)
		select {
		case ack := <-waiter:
			if ack.Seq != 7 || !ack.Confirmed() {
				t.Fatalf("fence ack = %+v, want confirmed seq 7", ack)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("fence ack +8 did not complete waiter (header-refused or dropped?)")
		}
		if got := ss.Stats().OversizeFramesRefused; got != 0 {
			t.Fatalf("OversizeFramesRefused = %d, want 0", got)
		}
	})
}

func capabilityPayload17093(t *testing.T, total int) []byte {
	t.Helper()
	// Leading fields identical to sendCapabilities' full layout
	// (flags2 at its fixed offset, #18116), with extension bytes
	// APPENDED after flags2 — the shape a newer peer's additive
	// trailing field actually takes. Appending (not inserting before
	// flags2) is what pins the positional flags2 read: a len-1 read
	// would decode the last extension byte (0) as flags2 and lose
	// every flags2 capability.
	p := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
	// capabilityFrame14161 yields the 5-byte head; extend with boot/epoch/token.
	p = append(p, make([]byte, bootIncarnationLen+8+8)...)
	p = append(p, localCapabilityFlags2)
	if len(p) > total {
		t.Fatalf("capability fixture %d > requested %d", len(p), total)
	}
	for len(p) < total {
		p = append(p, 0)
	}
	return p
}

// TestSyncPayloadCapHeadroom17093 is the table property (#18116):
// every growable row carries maxLen > encoderMax (real headroom, no
// exemptions — a growable row at maxLen == encoderMax is the
// zero-headroom regression this PR exists to remove); every row
// stays within [encoderMax, maxSyncPayload]; the proven-trailing-
// intolerant rows are fixed; and no sender emits over its cap.
func TestSyncPayloadCapHeadroom17093(t *testing.T) {
	for _, d := range syncMsgDescriptors {
		c, known := syncPayloadCap(d.id)
		if !known {
			t.Errorf("%s (%d): no cap", d.name, d.id)
			continue
		}
		if c != d.maxLen {
			t.Errorf("%s: syncPayloadCap = %d, descriptor maxLen = %d", d.name, c, d.maxLen)
		}
		if d.maxLen < d.encoderMax {
			t.Errorf("%s: maxLen %d < encoderMax %d (cap below today's encoder)", d.name, d.maxLen, d.encoderMax)
		}
		if d.maxLen < 0 || d.maxLen > maxSyncPayload {
			t.Errorf("%s: maxLen %d outside [0, maxSyncPayload]", d.name, d.maxLen)
		}
		if d.growable && d.maxLen <= d.encoderMax {
			t.Errorf("%s: growable row with no headroom (maxLen %d <= encoderMax %d)", d.name, d.maxLen, d.encoderMax)
		}
	}
	// The documented growable set must each carry the full reserve
	// over the encoder size a sender emits today. Sizes are the
	// encoders' literal maxima, independent of the descriptor, so a
	// future hand-copy back to zero headroom fails here.
	growableWant := map[uint8]int{
		syncMsgPeerCapabilities:  5 + bootIncarnationLen + 8 + 8 + 1,
		syncMsgConfigKeyExchange: 1 + syncConfigECDHPubSize,
		syncMsgBulkStart:         8 + bootIncarnationLen,
		syncMsgBulkEnd:           8 + bootIncarnationLen,
		syncMsgBarrierAck:        24,
		syncMsgFence:             8,
		syncMsgFenceAck:          fenceAckPayloadLen,
	}
	for mt, encMax := range growableWant {
		if c := mustCap(t, mt); c < encMax+syncExtensionReserve {
			t.Errorf("type %d: cap %d < encoderMax %d + reserve %d (zero-headroom regression)", mt, c, encMax, syncExtensionReserve)
		}
	}
	// #18116 (B2): these decoders reject trailing bytes (Noise,
	// config AEAD, exact lease layout), so their rows must be fixed —
	// growable would promise extension tolerance they do not have.
	for _, mt := range []uint8{
		syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof,
		syncMsgConfigEncrypted, syncMsgPersistentNatLease,
		syncMsgPersistentNatLeaseGeneration,
		syncMsgPersistentNatLeaseDeterministic,
		syncMsgPersistentNatLeaseProvenance,
		syncMsgPersistentNatLeaseDeterministicProvenance,
		// #17099 merge fold: types 52/53 share the same exact
		// off==len lease decoder (decodeOnePersistentNatLeaseLayoutTyped),
		// so they are fixed rows too — and they must HAVE rows: without
		// them syncPayloadCap(52/53) is unknown and a typed frame carrying
		// nat64_scope text would be read under only the global cap with
		// no per-type accounting.
		syncMsgPersistentNatLeaseTypedPool,
		syncMsgPersistentNatLeaseDeterministicTypedPool,
	} {
		for _, d := range syncMsgDescriptors {
			if d.id == mt && d.growable {
				t.Errorf("%s: marked growable but its decoder rejects trailing bytes (#18116 B2)", d.name)
			}
		}
	}
	// #18116 (B3): the session encoders must never emit over their
	// caps, even with a format-maximum (u16-length) rule ID. The
	// sender-side guard (sessionRuleIDMaxLen) is what makes this
	// hold; neither session row is exempt from the property.
	rule := make([]byte, 65535)
	for i := range rule {
		rule[i] = 'r'
	}
	v4val := val9508()
	v4val.PolicyRuleID = string(rule)
	v4val.EgressIfaceFold = 1
	v4val.PrimaryLiveness = true
	if v4 := encodeSessionV4Payload(key9508(), v4val); len(v4) > mustCap(t, syncMsgSessionV4) {
		t.Errorf("session v4 encoder emits %d > cap %d with a 64KiB rule ID (encoderMax falsified)", len(v4), mustCap(t, syncMsgSessionV4))
	}
	v6val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, SessionID: 1,
		PolicyRuleID: string(rule), EgressIfaceFold: 1, PrimaryLiveness: true}
	v6key := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01}, DstIP: [16]byte{0x20, 0x02},
		Protocol: 6, SrcPort: 40000, DstPort: 5201}
	if v6 := encodeSessionV6Payload(v6key, v6val); len(v6) > mustCap(t, syncMsgSessionV6) {
		t.Errorf("session v6 encoder emits %d > cap %d with a 64KiB rule ID (encoderMax falsified)", len(v6), mustCap(t, syncMsgSessionV6))
	}
	if _, known := syncPayloadCap(200); known {
		t.Error("unknown type 200 must have no per-type cap")
	}
}

// TestFailoverDetailClampedToCap17093 pins acceptance (d): an over-long
// detail is truncated at the encoder so the emitted payload fits its cap.
func TestFailoverDetailClampedToCap17093(t *testing.T) {
	long := make([]byte, 10*1024)
	for i := range long {
		long[i] = 'x'
	}
	detail := string(long)
	// Single-RG encoder path.
	payload := make([]byte, 10+len(detail))
	copy(payload[10:], detail)
	clamped := clampFailoverAckPayload(syncMsgFailoverAck, payload)
	if c := mustCap(t, syncMsgFailoverAck); len(clamped) > c {
		t.Fatalf("clamped single-ack payload %d > cap %d", len(clamped), c)
	}
	batch := encodeFailoverBatchAckPayload([]int{1, 2}, 1, 7, detail)
	if c := mustCap(t, syncMsgFailoverBatchAck); len(batch) > c {
		t.Fatalf("batch ack payload %d > cap %d (detail not clamped at encoder)", len(batch), c)
	}
	if len(batch) == 0 || batch[0] != 2 {
		t.Fatalf("batch ack header disturbed by clamp: %v", batch[:1])
	}
}

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
			h.ss.peerIncarnationState().peerHeartbeatAckEver.Store(true)
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
		{"barrier oversize", syncMsgBarrier, uint32(mustCap(t, syncMsgBarrier) + 1)},
		{"capabilities oversize", syncMsgPeerCapabilities, uint32(mustCap(t, syncMsgPeerCapabilities) + 1)},
		{"failover oversize", syncMsgFailover, uint32(mustCap(t, syncMsgFailover) + 1)},
		{"config key exchange oversize", syncMsgConfigKeyExchange, uint32(mustCap(t, syncMsgConfigKeyExchange) + 1)},
		{"bulk start oversize", syncMsgBulkStart, uint32(mustCap(t, syncMsgBulkStart) + 1)},
		{"fence oversize", syncMsgFence, uint32(mustCap(t, syncMsgFence) + 1)},
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
			syncMsgPersistentNatLeaseProvenance, syncMsgPersistentNatLeaseDeterministicProvenance,
			syncMsgPersistentNatLeaseTypedPool, syncMsgPersistentNatLeaseDeterministicTypedPool,
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
		ss.registerFailoverWaitForTest(failoverWaitRequest, []int{3}, 99, ch)
		if !ss.handleMessage(nil, syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 99)) {
			t.Fatal("CONTROL: failover ack matching its waiter must be accepted")
		}
		select {
		case <-ch:
		default:
			t.Fatal("CONTROL: matched failover ack must still be delivered to the waiter")
		}
		ss.registerFailoverWaitForTest(failoverWaitRequest, []int{3}, 100, ch)
		if ss.handleMessage(nil, syncMsgFailoverAck, failoverAckPayload16041(3, failoverAckApplied, 99)) {
			t.Fatal("failover ack with a foreign reqID must be rejected")
		}
		rgIDs := []int{1, 2}
		batchAck := encodeFailoverBatchAckPayload(rgIDs, failoverAckApplied, 7, "")
		if ss.handleMessage(nil, syncMsgFailoverBatchAck, batchAck) {
			t.Fatal("batch ack matching no waiter must be rejected")
		}
		bch := make(chan failoverAck, 1)
		ss.registerFailoverWaitForTest(failoverWaitRequest, rgIDs, 7, bch)
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
		h.ss.peerIncarnationState().peerHeartbeatAckEver.Store(true)
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
		h.ss.peerIncarnationState().peerHeartbeatAckEver.Store(true)
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
		for !h.ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
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
