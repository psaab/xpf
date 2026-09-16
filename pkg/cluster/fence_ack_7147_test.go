package cluster

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// #7147 — peer-fence acknowledgement.
//
// The property under test throughout is a CONJUNCTION, and both halves matter
// in opposite directions:
//
//   - the gate must actually gate: a reachable peer's confirmation is obtained
//     BEFORE this node claims the redundancy groups; and
//   - the gate must never withhold ownership: every failure path proceeds with
//     the takeover, and says so where an operator can see it.
//
// A test suite that only checked the first would certify a design that turns
// every peer failure into an outage, so the fail-open paths get equal weight.

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

func TestFenceAckPayloadRoundTrips7147(t *testing.T) {
	t.Parallel()
	res := FenceResult{RGsFenced: 3, RGsTotal: 4, DataplaneAvailable: true}
	got, ok := decodeFenceAckPayload(encodeFenceAckPayload(42, res))
	if !ok {
		t.Fatal("a well-formed fence ack payload failed to decode")
	}
	if got.Seq != 42 {
		t.Errorf("Seq = %d, want 42", got.Seq)
	}
	if got.RGsFenced != 3 || got.RGsTotal != 4 {
		t.Errorf("counts = %d/%d, want 3/4", got.RGsFenced, got.RGsTotal)
	}
	if got.Status != FenceAckPartial {
		t.Errorf("Status = %d, want FenceAckPartial (%d) — 3 of 4 fenced is not a confirmation",
			got.Status, FenceAckPartial)
	}
	if got.Confirmed() {
		t.Error("a 3-of-4 fence reported Confirmed(); the surviving node would " +
			"believe the peer went fully dark when one RG may still be forwarding")
	}
}

// A truncated ack must be DROPPED, not partially decoded.
//
// This is the cell that matters most in the file: the status code lives at
// offset 8 and FenceAckOK is 0, so a short frame zero-filled by a lenient
// decoder reads as a SUCCESSFUL CONFIRMATION. The failure mode of getting this
// wrong is not "a malformed frame is mishandled", it is "corruption on the
// fabric authorises a takeover that was never confirmed" — indistinguishable
// from healthy at every layer above.
func TestFenceAckShortFrameIsRejectedNotZeroFilled7147(t *testing.T) {
	t.Parallel()
	full := encodeFenceAckPayload(7, FenceResult{RGsFenced: 2, RGsTotal: 2, DataplaneAvailable: true})
	if len(full) != fenceAckPayloadLen {
		t.Fatalf("encoded length = %d, want %d", len(full), fenceAckPayloadLen)
	}
	for n := 0; n < fenceAckPayloadLen; n++ {
		if _, ok := decodeFenceAckPayload(full[:n]); ok {
			t.Errorf("a %d-byte fence ack decoded; short frames must be refused", n)
		}
	}
	// Demonstrate the hazard the length gate exists to prevent, so a future
	// reader can see why "just decode what is there" is not an option.
	zeroFilled := make([]byte, fenceAckPayloadLen)
	binary.LittleEndian.PutUint64(zeroFilled[0:8], 7)
	decoded, ok := decodeFenceAckPayload(zeroFilled)
	if !ok || !decoded.Confirmed() {
		t.Fatalf("expected a zero-filled body to read as a CONFIRMED ack (ok=%v confirmed=%v); "+
			"if this ever stops being true the rationale above needs revisiting",
			ok, decoded.Confirmed())
	}
}

// Extra trailing bytes from a future peer must not break the decode — the
// #2170 trailing-field discipline this wire relies on.
func TestFenceAckToleratesTrailingBytes7147(t *testing.T) {
	t.Parallel()
	payload := append(encodeFenceAckPayload(9, FenceResult{RGsFenced: 1, RGsTotal: 1, DataplaneAvailable: true}),
		0xDE, 0xAD, 0xBE, 0xEF)
	got, ok := decodeFenceAckPayload(payload)
	if !ok {
		t.Fatal("a longer ack from a newer peer was refused; trailing fields must be skipped")
	}
	if got.Seq != 9 || !got.Confirmed() {
		t.Errorf("trailing bytes corrupted the decode: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// What "fenced" means
// ---------------------------------------------------------------------------

// The MIDDLE rows are the point of this table. An implementation that returned
// FenceAckOK unconditionally passes an all-success table, and an implementation
// that never returns OK passes an all-failure one.
func TestFenceResultStatusMapping7147(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		res  FenceResult
		want uint8
	}{
		{"every rg fenced", FenceResult{RGsFenced: 4, RGsTotal: 4, DataplaneAvailable: true}, FenceAckOK},
		{"one rg failed", FenceResult{RGsFenced: 3, RGsTotal: 4, DataplaneAvailable: true}, FenceAckPartial},
		{"no rg fenced", FenceResult{RGsFenced: 0, RGsTotal: 4, DataplaneAvailable: true}, FenceAckPartial},
		// A node with a dataplane and no RGs owns nothing and so cannot
		// split-brain: that is a real confirmation, not a vacuous one.
		{"no rgs configured", FenceResult{RGsFenced: 0, RGsTotal: 0, DataplaneAvailable: true}, FenceAckOK},
		// ...which is exactly why config-only mode must NOT fold into the row
		// above. "Nothing to disable" and "unable to disable anything" look
		// identical in the counts and mean opposite things.
		{"config-only mode", FenceResult{RGsFenced: 0, RGsTotal: 0, DataplaneAvailable: false}, FenceAckUnavailable},
		{"config-only with rgs", FenceResult{RGsFenced: 0, RGsTotal: 3, DataplaneAvailable: false}, FenceAckUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.res.Status(); got != tt.want {
				t.Errorf("Status() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestOnlyOKStatusConfirms7147(t *testing.T) {
	t.Parallel()
	for _, st := range []uint8{FenceAckPartial, FenceAckUnavailable, 99} {
		if (FenceAck{Status: st}).Confirmed() {
			t.Errorf("status %d reported Confirmed(); only FenceAckOK may authorise a "+
				"takeover to be reported as fenced", st)
		}
	}
	if !(FenceAck{Status: FenceAckOK}).Confirmed() {
		t.Error("FenceAckOK did not report Confirmed()")
	}
}

// ---------------------------------------------------------------------------
// Sequence matching
// ---------------------------------------------------------------------------

// A late ack from an EARLIER fence must not satisfy a later one.
//
// Without the seq match the gate is worse than absent: it reports a
// confirmation the peer never gave for the fence in question, and it does so
// instantly, so the operator sees "Fence confirmed by peer" on a takeover that
// was never acknowledged.
func TestFenceAckSeqMustMatchTheWaiter7147(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	waiter := make(chan FenceAck, 1)
	s.fenceAckMu.Lock()
	s.fenceAckWaiters = map[uint64]fenceAckWaiter{5: {ch: waiter}}
	s.fenceAckMu.Unlock()

	// A stale ack for a previous fence.
	s.completeFenceAckWait(FenceAck{Seq: 4, Status: FenceAckOK})
	select {
	case ack := <-waiter:
		t.Fatalf("a stale ack (seq 4) satisfied the seq-5 waiter: %+v", ack)
	default:
	}

	// An ack from a FUTURE fence must not satisfy it either.
	s.completeFenceAckWait(FenceAck{Seq: 6, Status: FenceAckOK})
	select {
	case ack := <-waiter:
		t.Fatalf("a seq-6 ack satisfied the seq-5 waiter: %+v", ack)
	default:
	}

	s.completeFenceAckWait(FenceAck{Seq: 5, Status: FenceAckOK, RGsFenced: 2, RGsTotal: 2})
	select {
	case ack := <-waiter:
		if ack.Seq != 5 || !ack.Confirmed() {
			t.Fatalf("matching ack delivered wrong: %+v", ack)
		}
	default:
		t.Fatal("the matching seq-5 ack did not reach its waiter")
	}

	// The waiter is consumed: a duplicate must find nothing and must not panic
	// or block the receive loop.
	s.completeFenceAckWait(FenceAck{Seq: 5, Status: FenceAckOK})
}

// Sequences must start at 1, because 0 is the reserved "no ack requested"
// value a pre-#7147 fence's empty payload decodes to. A generator starting at
// 0 would make the first fence of every boot indistinguishable from an
// unsequenced one, and the peer would silently not reply to it.
func TestFenceSeqNeverAllocatesZero7147(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	if first := s.fenceSeq.Add(1); first != 1 {
		t.Fatalf("first allocated fence seq = %d, want 1 (0 is reserved on the wire)", first)
	}
}

// ---------------------------------------------------------------------------
// Fail-open: the paths that must NOT spend the timeout
// ---------------------------------------------------------------------------

// The dead-peer takeover — the case the whole feature must not slow down —
// and the rolling-upgrade case, both of which must return immediately.
func TestSendFenceAwaitFailsOpenImmediately7147(t *testing.T) {
	t.Parallel()

	t.Run("peer not connected", func(t *testing.T) {
		t.Parallel()
		s := &SessionSync{}
		start := time.Now()
		_, err := s.SendFenceAwait(10 * time.Second)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("SendFenceAwait succeeded with no connection")
		}
		if !strings.Contains(err.Error(), "not connected") {
			t.Errorf("err = %q, want it to name the missing connection", err)
		}
		// The assertion that matters: it did not wait. With no socket there is
		// nothing to wait for, and this is the ordinary dead-peer takeover.
		if elapsed > time.Second {
			t.Errorf("took %s with no peer connected; a dead peer must never spend "+
				"the fence timeout — that would convert peer loss into an outage", elapsed)
		}
	})

	t.Run("peer predates 7147", func(t *testing.T) {
		t.Parallel()
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		s := &SessionSync{}
		s.conn0 = client
		// No capability flags stored: this is what a pre-#7147 peer looks
		// like, and it will never answer.
		start := time.Now()
		_, err := s.SendFenceAwait(10 * time.Second)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("SendFenceAwait succeeded against a peer that cannot acknowledge")
		}
		if !strings.Contains(err.Error(), "does not support") {
			t.Errorf("err = %q, want it to name the missing capability", err)
		}
		if elapsed > time.Second {
			t.Errorf("took %s against an incapable peer; during a rolling upgrade every "+
				"peer loss would pay the full timeout for an answer that can never come",
				elapsed)
		}
	})
}

// A disconnect during the wait must release the waiter immediately rather than
// holding the takeover until the timeout for an answer that can no longer
// arrive.
func TestDisconnectReleasesFenceAckWaiters7147(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	waiter := make(chan FenceAck, 1)
	s.fenceAckMu.Lock()
	s.fenceAckWaiters = map[uint64]fenceAckWaiter{1: {ch: waiter}}
	s.fenceAckMu.Unlock()

	s.abortFenceAckWaiters()

	select {
	case _, ok := <-waiter:
		if ok {
			t.Fatal("abort delivered a VALUE; it must close the channel so the sender " +
				"can tell 'peer went away' from 'peer answered' — a delivered zero value " +
				"has Status 0 == FenceAckOK and would read as a confirmation")
		}
	case <-time.After(time.Second):
		t.Fatal("abortFenceAckWaiters did not release the pending waiter")
	}

	// Idempotent: a second full disconnect must not double-close.
	s.abortFenceAckWaiters()
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

// An UNSEQUENCED fence (what every pre-#7147 sender writes) must still fence
// locally and must send no ack. This is the receiver half of the additive
// claim: an old peer's fence keeps working unchanged.
func TestUnsequencedFenceStillFencesAndSendsNoAck7147(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fenced := make(chan struct{}, 1)
	s := &SessionSync{}
	s.OnFenceReceived = func() FenceResult {
		fenced <- struct{}{}
		return FenceResult{RGsFenced: 1, RGsTotal: 1, DataplaneAvailable: true}
	}

	// nil payload — exactly what SendFence writes.
	go s.handleMessage(client, syncMsgFence, nil)

	select {
	case <-fenced:
	case <-time.After(2 * time.Second):
		t.Fatal("an unsequenced fence did not run the local fence handler")
	}
	if got := s.stats.FencesReceived.Load(); got != 1 {
		t.Errorf("FencesReceived = %d, want 1", got)
	}
	assertNoFrame(t, server)
	if got := s.stats.FenceAcksSent.Load(); got != 0 {
		t.Errorf("FenceAcksSent = %d, want 0 — an unsequenced fence must not be acked", got)
	}
}

// A SEQUENCED fence must run the local fence and reply with what it achieved,
// and the reply must be written only AFTER the fence has been applied. An ack
// that raced ahead of the fence would confirm nothing.
func TestSequencedFenceIsAckedAfterFencing7147(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	applied := make(chan struct{})
	s := &SessionSync{}
	s.OnFenceReceived = func() FenceResult {
		close(applied)
		return FenceResult{RGsFenced: 2, RGsTotal: 3, DataplaneAvailable: true}
	}

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], 77)
	go s.handleMessage(client, syncMsgFence, payload[:])

	msgType, body := readFrame(t, server)
	select {
	case <-applied:
	default:
		t.Fatal("the ack frame was written BEFORE OnFenceReceived ran; an ack that " +
			"precedes the fence confirms nothing and the gate becomes a lie")
	}
	if msgType != syncMsgFenceAck {
		t.Fatalf("reply type = %d, want syncMsgFenceAck (%d)", msgType, syncMsgFenceAck)
	}
	ack, ok := decodeFenceAckPayload(body)
	if !ok {
		t.Fatalf("the production ack frame failed its own decoder: % x", body)
	}
	if ack.Seq != 77 {
		t.Errorf("ack seq = %d, want the fence's 77 — an ack that does not echo the "+
			"sequence cannot be matched to its fence", ack.Seq)
	}
	if ack.Status != FenceAckPartial || ack.RGsFenced != 2 || ack.RGsTotal != 3 {
		t.Errorf("ack = %+v, want the handler's real 2-of-3 partial result; the ack must "+
			"report what the fence ACHIEVED, not merely that it was received", ack)
	}
}

// A fence with no handler wired must still answer, and must answer NEGATIVELY.
// Silence would make the sender wait out its timeout; a positive ack would
// claim a fence that never ran.
func TestSequencedFenceWithNoHandlerAcksUnavailable7147(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &SessionSync{}
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], 5)
	go s.handleMessage(client, syncMsgFence, payload[:])

	msgType, body := readFrame(t, server)
	if msgType != syncMsgFenceAck {
		t.Fatalf("reply type = %d, want syncMsgFenceAck", msgType)
	}
	ack, ok := decodeFenceAckPayload(body)
	if !ok {
		t.Fatalf("undecodable ack: % x", body)
	}
	if ack.Confirmed() {
		t.Errorf("a node with no fence handler CONFIRMED the fence (%+v); it disabled "+
			"nothing, so the surviving node would take over believing the peer is dark", ack)
	}
}

// A truncated ack on the receive path must be dropped rather than delivered as
// a confirmation.
func TestTruncatedFenceAckIsDropped7147(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	waiter := make(chan FenceAck, 1)
	s.fenceAckMu.Lock()
	s.fenceAckWaiters = map[uint64]fenceAckWaiter{1: {ch: waiter}}
	s.fenceAckMu.Unlock()

	short := encodeFenceAckPayload(1, FenceResult{RGsFenced: 1, RGsTotal: 1, DataplaneAvailable: true})
	s.handleMessage(nil, syncMsgFenceAck, short[:fenceAckPayloadLen-1])

	select {
	case ack := <-waiter:
		t.Fatalf("a truncated ack was delivered to the waiter: %+v", ack)
	default:
	}
}

// ---------------------------------------------------------------------------
// Capability advertisement
// ---------------------------------------------------------------------------

func TestPeerFenceAckCapabilityDecoding7147(t *testing.T) {
	t.Parallel()
	s := &SessionSync{}
	if s.PeerFenceAckCapable() {
		t.Error("a peer that advertised nothing reported fence-ack capable; a " +
			"confirmed-fence gate would then wait out its timeout on every takeover")
	}

	// A pre-#7147 peer: 2-byte frame, version only, no flags.
	twoByte := make([]byte, 2)
	binary.LittleEndian.PutUint16(twoByte, 8)
	s.handleMessage(nil, syncMsgPeerCapabilities, twoByte)
	if s.PeerSnapshotProtocolVersion() != 8 {
		t.Errorf("version = %d, want 8 — the #6650 field must still decode from a "+
			"2-byte frame", s.PeerSnapshotProtocolVersion())
	}
	if s.PeerFenceAckCapable() {
		t.Error("a 2-byte (pre-#7147) capability frame was read as fence-ack capable")
	}

	// A #7147 peer.
	threeByte := append(twoByte, capFlagFenceAck)
	s.handleMessage(nil, syncMsgPeerCapabilities, threeByte)
	if !s.PeerFenceAckCapable() {
		t.Error("a peer advertising capFlagFenceAck was not read as capable, so the " +
			"gate would never arm even between two current nodes")
	}

	// A downgrade on reconnect must revoke it.
	s.handleMessage(nil, syncMsgPeerCapabilities, twoByte)
	if s.PeerFenceAckCapable() {
		t.Error("capability survived a peer re-advertising without the flag")
	}
}

// This build must actually advertise the capability, or no peer can ever gate
// on it. Binds the constant to the flag rather than assuming they agree.
func TestThisBuildAdvertisesFenceAckCapability7147(t *testing.T) {
	t.Parallel()
	if localCapabilityFlags&capFlagFenceAck == 0 {
		t.Fatal("localCapabilityFlags does not set capFlagFenceAck, so this node tells " +
			"its peer it cannot acknowledge fences and every confirmed-fence takeover " +
			"on a fully-upgraded cluster fails open")
	}
}

// The capability must not survive the peer incarnation that proved it — the
// same scoping #6650 applies to the version field, and it is bound to the real
// disconnect path rather than to a hand-driven store.
func TestDisconnectClearsFenceAckCapability7147(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn.go")
	if !sourceContainsFlat(src, "s.peerCapabilityFlags.Store(0)") {
		t.Error("the full-disconnect path does not clear peerCapabilityFlags. A " +
			"downgraded peer that reconnects would inherit the previous incarnation's " +
			"fence-ack bit, and every takeover against it would wait out the full " +
			"timeout for an ack it can never send.")
	}
	// NOTE (#9915 F-116 review): the disconnect path's scoped waiter release
	// was asserted here by source grep; it is pinned behaviorally instead by
	// TestFenceSurvivesIdleFabricFlap_9915 /
	// TestFenceAbortsWhenItsOwnFabricDrops_9915 (source grep cannot tell a
	// scoped release from abort-all).
	if !sourceContainsFlat(src, "s.peerSnapshotProtocol.Store(0)") {
		t.Error("the #6650 clear these are anchored beside has moved; re-verify both " +
			"#7147 clears are still on the FULL-disconnect path")
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func readFrame(t *testing.T, conn net.Conn) (uint8, []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.LittleEndian.Uint32(hdr[8:12])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	return hdr[4], body
}

// assertNoFrame fails if anything arrives within a short window.
func assertNoFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("unexpected %d-byte frame on the wire: % x", n, buf[:n])
	}
	var ne net.Error
	if !isTimeout(err, &ne) {
		t.Fatalf("read failed for a reason other than the expected timeout: %v", err)
	}
}

func isTimeout(err error, ne *net.Error) bool {
	if e, ok := err.(net.Error); ok {
		*ne = e
		return e.Timeout()
	}
	return false
}
