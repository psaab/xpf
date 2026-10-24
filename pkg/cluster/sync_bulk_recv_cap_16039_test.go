package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16039: the bulk receive accumulators are inserted before the install
// verdict — a row whose helper install fails transiently must still count
// as received so BulkEnd treats the snapshot as complete only when it is.
// That pre-verdict insertion was uncapped and the window had no deadline:
// a keyed peer could grow receiver memory entry-by-entry for as long as it
// held the window open. The fix bounds live occupancy at the table
// capacity (bulkRecvCap), bounds the sibling failure-marker maps by the
// same cap, and expires any window whose deadline passes — on receive as
// well as at BulkEnd. An aborted window never reconciles, acks, or
// releases the hold, and latches bulkIncomplete readiness debt until a
// later bulk reconciles successfully; a legitimate full-table bulk still
// installs. The cap is on live occupancy: a delete during the window
// frees its key's slot, so delete+reinstall churn never consumes it.

func bulkKey16039(i int) dataplane.SessionKey {
	return dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)},
		DstIP:    [4]byte{10, 0, 0, 254},
		SrcPort:  uint16(1000 + i%50000),
		DstPort:  80,
	}
}

func bulkKey16039V6(i int) dataplane.SessionKeyV6 {
	var k dataplane.SessionKeyV6
	k.Protocol = 6
	k.SrcIP[0] = 0x20
	k.SrcIP[13] = byte(i >> 16)
	k.SrcIP[14] = byte(i >> 8)
	k.SrcIP[15] = byte(i)
	k.DstIP[0] = 0x20
	k.DstIP[15] = 0xfe
	k.SrcPort = uint16(1000 + i%50000)
	k.DstPort = 80
	return k
}

func newBulkRecvFixture16039(t *testing.T, capOverride int, dp *mockSweepDP) (*SessionSync, *frameCaptureConn) {
	t.Helper()
	if dp == nil {
		dp = &mockSweepDP{
			v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
			v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		}
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
	if capOverride > 0 {
		ss.genState.genGuardMapCeilingOverride = capOverride
	}
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close(); peer.Close() })
	return ss, &frameCaptureConn{Conn: local}
}

func bulkLens16039(ss *SessionSync) (v4, v6 int, invalid bool) {
	ss.bulkMu.Lock()
	defer ss.bulkMu.Unlock()
	return len(ss.bulkRecvV4), len(ss.bulkRecvV6), ss.bulkRecvInvalid
}

// Overflow past the cap: the window is invalidated once, further keys are
// counted without storing, nothing reconciles/acks/releases, and the maps
// never grow past the cap.
func TestBulkRecvCapAbortsOverflowingWindow16039(t *testing.T) {
	const capN = 4
	ss, conn := newBulkRecvFixture16039(t, capN, nil)
	released := make(chan struct{}, 1)
	ss.OnBulkSyncReceived = func() { released <- struct{}{} }
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	// A legitimately full window: capN distinct keys (v4+v6 combined).
	for i := range 3 {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(bulkKey16039V6(0),
		dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}))
	if v4, v6, invalid := bulkLens16039(ss); v4 != 3 || v6 != 1 || invalid {
		t.Fatalf("full-at-cap window: recv=(%d,%d) invalid=%v, want (3,1) false", v4, v6, invalid)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 0 {
		t.Fatalf("at-cap window counted %d capped keys, want 0", got)
	}

	// One more distinct key overflows: refused, counted, window invalid.
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(99), val))
	if v4, v6, invalid := bulkLens16039(ss); v4 != 3 || v6 != 1 || !invalid {
		t.Fatalf("overflow: recv=(%d,%d) invalid=%v, want (3,1) true", v4, v6, invalid)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 1 {
		t.Fatalf("BulkRecvCapped=%d, want 1", got)
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != 1 {
		t.Fatalf("BulkRecvAborted=%d, want 1 (exactly one abort per window)", got)
	}

	// Further distinct keys: no growth, no second abort. Each dropped key
	// is counted in BulkRecvCapped; the stored set never moves.
	before := ss.stats.BulkRecvCapped.Load()
	for i := range 10 {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
		ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(bulkKey16039V6(i),
			dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}))
	}
	if v4, v6, _ := bulkLens16039(ss); v4 != 3 || v6 != 1 {
		t.Fatalf("invalid window grew: recv=(%d,%d), want (3,1)", v4, v6)
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != 1 {
		t.Fatalf("BulkRecvAborted=%d after flood, want still 1", got)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got <= before {
		t.Fatalf("invalid-window keys not counted: BulkRecvCapped=%d (was %d)", got, before)
	}

	// BulkEnd on the invalid window: no ack, no completion, no release.
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if len(conn.frames) != 0 {
		t.Fatalf("aborted window emitted %d frames, want no BulkAck", len(conn.frames))
	}
	if ss.BulkEverCompleted() || ss.stats.BulkSyncEndTime.Load() != 0 {
		t.Fatal("aborted window marked completed")
	}
	select {
	case <-released:
		t.Fatal("aborted window released the HA hold")
	case <-time.After(50 * time.Millisecond):
	}
	// Fold (1): the abort must NOT clear readiness debt. The window is
	// closed, but TransferReadiness still blocks until a later bulk
	// reconciles successfully.
	if got := ss.TransferReadiness(); !got.BulkReceiveInProgress || !got.BulkIncomplete || got.ReadyForManualFailover() {
		t.Fatalf("aborted window cleared readiness debt: %+v", got)
	}
	if got := ss.TransferReadiness().Reason(); got == "" {
		t.Fatal("aborted window has no readiness reason")
	}

	// A legitimate full-table bulk at the cap still installs and completes.
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(2, nil))
	for i := range 3 {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(bulkKey16039V6(0),
		dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}))
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(2, nil))
	if len(conn.frames) != 1 || conn.frames[0][4] != syncMsgBulkAck ||
		binary.LittleEndian.Uint64(conn.frames[0][syncHeaderSize:]) != 2 {
		t.Fatalf("legitimate at-cap bulk ack frames=%v, want one BulkAck epoch 2", conn.frames)
	}
	if !ss.BulkEverCompleted() {
		t.Fatal("legitimate at-cap bulk did not complete")
	}
	if got := ss.TransferReadiness(); got.BulkIncomplete || got.BulkReceiveInProgress || !got.ReadyForManualFailover() {
		t.Fatalf("successful reconcile did not clear readiness debt: %+v", got)
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != 1 {
		t.Fatalf("legitimate bulk raised BulkRecvAborted to %d, want 1", got)
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("legitimate at-cap bulk did not release the HA hold")
	}
}

// A window held open past its deadline aborts at BulkEnd even when every
// key fit under the cap, AND expires on receive without any BulkEnd:
// the next inbound frame after the deadline closes the window and
// latches the readiness debt.
func TestBulkRecvDeadlineAbortsStaleWindow16039(t *testing.T) {
	ss, conn := newBulkRecvFixture16039(t, 100, nil)
	now := time.Unix(1_700_000_000, 0)
	ss.testBulkRecvNow = func() time.Time { return now }
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(1), val))

	// Advance past the deadline, then close the window: abort, no ack.
	now = now.Add(bulkRecvWindowTimeout + time.Minute)
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if len(conn.frames) != 0 {
		t.Fatalf("late BulkEnd emitted %d frames, want no BulkAck", len(conn.frames))
	}
	if ss.BulkEverCompleted() {
		t.Fatal("late window marked completed")
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != 1 {
		t.Fatalf("BulkRecvAborted=%d, want 1 for the deadline abort", got)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 0 {
		t.Fatalf("deadline abort counted %d capped keys, want 0", got)
	}
	if got := ss.TransferReadiness(); !got.BulkIncomplete || got.ReadyForManualFailover() {
		t.Fatalf("deadline abort cleared readiness debt: %+v", got)
	}

	// Fold (3): no BulkEnd at all. The next inbound frame after the
	// deadline must expire the open window on receive.
	now = time.Unix(1_700_000_000, 0)
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(2, nil))
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(2), val))
	if v4, _, invalid := bulkLens16039(ss); v4 != 1 || invalid {
		t.Fatalf("pre-deadline window: v4=%d invalid=%v, want 1/false", v4, invalid)
	}
	now = now.Add(bulkRecvWindowTimeout + time.Minute)
	abortedBefore := ss.stats.BulkRecvAborted.Load()
	// An ordinary incremental session frame is the trigger; no BulkEnd.
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(3), val))
	ss.bulkMu.Lock()
	inProgress := ss.bulkInProgress
	recvLen := len(ss.bulkRecvV4)
	ss.bulkMu.Unlock()
	if inProgress {
		t.Fatal("deadline did not expire the open window on receive (no BulkEnd sent)")
	}
	if recvLen != 0 {
		t.Fatalf("expired window retained %d accumulated keys, want 0 (maps freed)", recvLen)
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != abortedBefore+1 {
		t.Fatalf("receive-expiry abort count=%d, want %d", got, abortedBefore+1)
	}
	if got := ss.TransferReadiness(); !got.BulkIncomplete || got.ReadyForManualFailover() {
		t.Fatalf("receive-expiry did not latch readiness debt: %+v", got)
	}
	// The triggering frame was processed as a normal incremental install:
	// the session store holds it, but it is not part of any bulk window.
	if _, _, invalid := bulkLens16039(ss); invalid {
		t.Fatal("window still invalid after receive-expiry")
	}

	// Control: a window closed inside the deadline completes and clears debt.
	now = time.Unix(1_700_000_000, 0)
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(3, nil))
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(1), val))
	now = now.Add(bulkRecvWindowTimeout - time.Minute)
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(3, nil))
	if len(conn.frames) != 1 {
		t.Fatalf("in-deadline window emitted %d frames, want one BulkAck", len(conn.frames))
	}
	if !ss.BulkEverCompleted() {
		t.Fatal("in-deadline window did not complete")
	}
	if got := ss.TransferReadiness(); got.BulkIncomplete || !got.ReadyForManualFailover() {
		t.Fatalf("successful reconcile did not clear debt: %+v", got)
	}
}

// The failure-marker maps share the cap: a peer whose every install fails
// transiently cannot grow them past it either, and the window invalidates
// instead of reconciling an incomplete snapshot.
func TestBulkInstallFailedMapsBounded16039(t *testing.T) {
	const capN = 3
	key := func(i int) dataplane.SessionKey { return bulkKey16039(i) }
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		failSetV4:  map[dataplane.SessionKey]error{},
	}
	for i := range 10 {
		dp.failSetV4[key(i)] = errors.New("session table write failed")
	}
	ss, conn := newBulkRecvFixture16039(t, capN, dp)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	for i := range 10 {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key(i), val))
	}
	ss.bulkMu.Lock()
	failed := len(ss.bulkInstallFailedV4)
	recv := len(ss.bulkRecvV4)
	invalid := ss.bulkRecvInvalid
	ss.bulkMu.Unlock()
	if failed > capN || recv > capN {
		t.Fatalf("maps grew past cap %d: failed=%d recv=%d", capN, failed, recv)
	}
	if !invalid {
		t.Fatal("window not invalidated after cap overflow")
	}
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if len(conn.frames) != 0 {
		t.Fatalf("invalid window emitted %d frames, want no BulkAck", len(conn.frames))
	}
	if ss.BulkEverCompleted() {
		t.Fatal("invalid window marked completed")
	}
}

// Duplicate keys never consume cap, and keys outside a window are free:
// incremental (non-bulk) installs do not touch the accumulators.
func TestBulkRecvDuplicatesAndIncrementalFree16039(t *testing.T) {
	const capN = 2
	ss, conn := newBulkRecvFixture16039(t, capN, nil)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	// Outside any window.
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(1), val))
	if v4, _, invalid := bulkLens16039(ss); v4 != 0 || invalid {
		t.Fatalf("incremental install touched accumulators: v4=%d invalid=%v", v4, invalid)
	}

	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	for range 20 {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(1), val))
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(2), val))
	}
	if v4, _, invalid := bulkLens16039(ss); v4 != 2 || invalid {
		t.Fatalf("duplicates consumed cap: v4=%d invalid=%v, want 2/false", v4, invalid)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 0 {
		t.Fatalf("duplicates counted as capped: %d", got)
	}
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if len(conn.frames) != 1 || !ss.BulkEverCompleted() {
		t.Fatal("duplicate-heavy legitimate bulk did not complete")
	}
}

// Fold (2): the cap is on live occupancy, not cumulative distinct keys.
// Fill the window to the cap, delete keys inside the window, and install
// replacements: cumulative distinct keys exceed the cap, live occupancy
// never does, so the window must stay valid and complete.
func TestBulkRecvCapIsLiveOccupancy16039(t *testing.T) {
	const capN = 3
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	ss, conn := newBulkRecvFixture16039(t, capN, dp)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	// Fill exactly to the cap: keys 0,1,2 live.
	for i := range capN {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	if v4, _, invalid := bulkLens16039(ss); v4 != capN || invalid {
		t.Fatalf("at-cap window: v4=%d invalid=%v, want %d/false", v4, invalid, capN)
	}
	// Churn: delete two live keys, install two replacements. Cumulative
	// distinct = 5 > cap 3; live occupancy stays at 3.
	for _, i := range []int{0, 1} {
		ss.handleMessage(conn, syncMsgDeleteV4, encodeDeleteV4(bulkKey16039(i), 0, false)[syncHeaderSize:])
	}
	if v4, _, invalid := bulkLens16039(ss); v4 != 1 || invalid {
		t.Fatalf("deletes did not free occupancy: v4=%d invalid=%v, want 1/false", v4, invalid)
	}
	for _, i := range []int{3, 4} {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	if v4, _, invalid := bulkLens16039(ss); v4 != capN || invalid {
		t.Fatalf("replacements after churn: v4=%d invalid=%v, want %d/false (cumulative keys must not consume cap)", v4, invalid, capN)
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 0 {
		t.Fatalf("churn counted %d capped keys, want 0", got)
	}
	// More churn cycles for good measure: delete all, refill.
	for _, i := range []int{2, 3, 4} {
		ss.handleMessage(conn, syncMsgDeleteV4, encodeDeleteV4(bulkKey16039(i), 0, false)[syncHeaderSize:])
	}
	for _, i := range []int{5, 6, 7} {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	if v4, _, invalid := bulkLens16039(ss); v4 != capN || invalid {
		t.Fatalf("second churn cycle: v4=%d invalid=%v, want %d/false", v4, invalid, capN)
	}
	// A genuinely over-cap live set still aborts.
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(99), val))
	if _, _, invalid := bulkLens16039(ss); !invalid {
		t.Fatal("live occupancy past cap did not invalidate the window")
	}
	if got := ss.stats.BulkRecvCapped.Load(); got != 1 {
		t.Fatalf("BulkRecvCapped=%d, want 1 (only the true overflow)", got)
	}
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if len(conn.frames) != 0 || ss.BulkEverCompleted() {
		t.Fatal("over-cap window completed")
	}
	// And the churn-only shape (no overflow) completes on a fresh bulk.
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(2, nil))
	for i := range capN {
		ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(i), val))
	}
	ss.handleMessage(conn, syncMsgDeleteV4, encodeDeleteV4(bulkKey16039(0), 0, false)[syncHeaderSize:])
	ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(bulkKey16039(10), val))
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(2, nil))
	if len(conn.frames) != 1 || !ss.BulkEverCompleted() {
		t.Fatal("churn bulk did not complete")
	}
}

// Fold 2: a peer that opens a bulk window and then goes completely
// silent never sends a next frame, so the handleMessage check cannot
// fire. receiveLoop's read-timeout tick must expire the window on its
// own: window closed and freed, one abort counted, debt latched.
func TestBulkRecvSilentPeerExpiresOnReadTimeout16039(t *testing.T) {
	ss, _ := newBulkRecvFixture16039(t, 100, nil)
	now := time.Unix(1_700_000_000, 0)
	ss.testBulkRecvNow = func() time.Time { return now }
	ss.readDeadline = 20 * time.Millisecond
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ss.receiveLoop(ctx, local)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	// Open the window and deliver one session over the wire, then silence.
	if err := writeMsg(peer, syncMsgBulkStart, bulkStartPayload(1, nil)); err != nil {
		t.Fatalf("write BulkStart: %v", err)
	}
	// encodeSessionV4Payload returns a full wire frame; strip its header
	// and re-wrap explicitly so the frame type/length are unambiguous.
	payload := encodeSessionV4Payload(bulkKey16039(1), val)[syncHeaderSize:]
	frame := make([]byte, syncHeaderSize+len(payload))
	copy(frame[:4], syncMagic[:])
	frame[4] = syncMsgSessionV4
	binary.LittleEndian.PutUint32(frame[8:12], uint32(len(payload)))
	copy(frame[syncHeaderSize:], payload)
	if _, err := peer.Write(frame); err != nil {
		t.Fatalf("write session frame: %v", err)
	}
	// Wait until the loop has accumulated the key.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v4, _, _ := bulkLens16039(ss); v4 == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("receive loop never accumulated the wired session")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Advance the window clock past the deadline. The peer sends nothing
	// more; the read-timeout tick alone must expire the window.
	now = now.Add(bulkRecvWindowTimeout + time.Minute)
	deadline = time.Now().Add(2 * time.Second)
	for {
		ss.bulkMu.Lock()
		inProgress := ss.bulkInProgress
		incomplete := ss.bulkIncomplete
		ss.bulkMu.Unlock()
		if !inProgress && incomplete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("silent peer window never expired on read timeout (inProgress=%v incomplete=%v)", inProgress, incomplete)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := ss.stats.BulkRecvAborted.Load(); got != 1 {
		t.Fatalf("BulkRecvAborted=%d, want 1 from the timeout-tick expiry", got)
	}
	if v4, v6, _ := bulkLens16039(ss); v4 != 0 || v6 != 0 {
		t.Fatalf("expired window retained keys: (%d,%d)", v4, v6)
	}
	if got := ss.TransferReadiness(); !got.BulkIncomplete || got.ReadyForManualFailover() {
		t.Fatalf("timeout expiry did not latch readiness debt: %+v", got)
	}
	if ss.BulkEverCompleted() {
		t.Fatal("silent window marked completed")
	}
}
