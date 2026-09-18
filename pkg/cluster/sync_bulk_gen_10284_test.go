package cluster

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// key10284 is a forward v4 session key in the 10.0.84.0/24 cell block.
func key10284(last byte, sport uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 84, last}, DstIP: [4]byte{172, 16, 84, 20},
		Protocol: 6, SrcPort: sport, DstPort: 5201,
	}
}

// receiver10284 builds the standby side shared by the #10284 cells: secondary
// for zone 5, so peer-owned zone-5 installs land in the mock dataplane.
func receiver10284(t *testing.T) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.3:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})
	return ss, dp
}

// install10284 applies a v4 install frame carrying an explicit generation, as
// a bulk row or queued incremental would deliver it.
func install10284(ss *SessionSync, key dataplane.SessionKey, gen uint64) {
	val := establishedIn(5)
	val.Generation = gen
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(key, val))
}

// delete10284 applies a v4 delete frame carrying an explicit generation.
func delete10284(ss *SessionSync, key dataplane.SessionKey, gen uint64) {
	ss.handleMessage(nil, syncMsgDeleteV4, encodeDeleteV4(key, gen, false)[syncHeaderSize:])
}

// TestBulkSnapshotCloseAfterReadDeletesOnReceiver10284 is the #10284 cell 1
// fail-on-revert: a session that is live when the table-truth snapshot is read
// but closes after BulkStart and before the first session frame must end
// ABSENT on the receiver.
//
// The bulk row must carry the generation drawn at SNAPSHOT time, so the close's
// delete — drawn after the read — strictly out-ranks it and wins in every
// arrival order. Stamping the row at SEND time draws a generation strictly
// greater than the delete, so the delete is refused (or the late row
// resurrects over the tombstone) and the dead session survives.
func TestBulkSnapshotCloseAfterReadDeletesOnReceiver10284(t *testing.T) {
	key := key10284(11, 42101)
	live := establishedIn(5)

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})
	// Model the already-live session's prior incremental install so the
	// close/delete has a sender-side generation to outrank.
	seed := live
	sender.stampInstallGenV4(key, &seed)
	receiver, receiverDP := receiver10284(t)

	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sender.sendLoop(ctx)

	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		// The session is live when the table-truth snapshot is read. The
		// snapshot stamp is assigned before BulkStart; the close below runs
		// after BulkStart and before the first row is stamped/written.
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: key, Value: live},
		}}, nil
	}
	sender.testBeforeBulkRows = func() {
		// This hook is reached after BulkStart is on the wire and before
		// iteration stamps the first row. Queueing here makes the RED path
		// deterministic: send-time stamping draws a generation after this
		// delete, while snapshot-time stamping draws it before.
		sender.QueueDeleteV4(key, false)
	}

	if err := sender.doBulkSync(); err != nil {
		t.Fatalf("doBulkSync returned error: %v", err)
	}

	// Four frames must cross: BulkStart, the bulk row, the queued delete, and
	// BulkEnd. The #10283 watermark holds BulkEnd until the queued delete is
	// delivered, so doBulkSync's return already implies delivery.
	types := make([]byte, 0, 4)
	for len(types) < 4 {
		select {
		case mt := <-conn.writes:
			types = append(types, mt)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for bulk/close frames, got %d (%v)", len(types), types)
		}
	}
	startIndex, deleteIndex := -1, -1
	for i, typ := range types {
		switch typ {
		case syncMsgBulkStart:
			startIndex = i
		case syncMsgDeleteV4:
			deleteIndex = i
		}
	}
	if startIndex < 0 || deleteIndex <= startIndex {
		t.Fatalf("#10284: close/delete was not observed after BulkStart (types %v)", types)
	}

	// Mechanism pin: the post-marker delete generation must out-rank the
	// snapshot row's generation, proving the row was stamped before the
	// close/queue decision rather than at send time.
	var installs []uint64
	var deletes []uint64
	for _, buf := range splitFrames10284(t, conn.bytes()) {
		switch buf.typ {
		case syncMsgSessionV4:
			k, v, ok := decodeSessionV4Payload(buf.payload)
			if !ok {
				t.Fatalf("captured session frame does not decode")
			}
			if k == key {
				installs = append(installs, v.Generation)
			}
		case syncMsgDeleteV4:
			k, gen, _, ok := parseDeleteV4Wire(buf.payload)
			if !ok {
				t.Fatalf("captured delete frame does not decode")
			}
			if k == key {
				deletes = append(deletes, gen)
			}
		}
	}
	if len(installs) != 1 {
		t.Fatalf("expected 1 bulk install for the key, got %d", len(installs))
	}
	if len(deletes) != 1 {
		t.Fatalf("expected 1 post-marker delete for the key, got %d", len(deletes))
	}
	if deletes[0] <= installs[0] {
		t.Fatalf("#10284: delete gen %d does not out-rank snapshot install gen %d — the bulk row was stamped at send time after the close", deletes[0], installs[0])
	}

	starts, ends := replayBulkFrames(t, receiver, conn.bytes())
	if starts != 1 || ends != 1 {
		t.Fatalf("expected one complete bulk window, got starts=%d ends=%d", starts, ends)
	}
	if _, ok := receiverDP.v4sessions[key]; ok {
		t.Fatalf("#10284: session closed after BulkStart survived on the receiver (frame types %v)", types)
	}
}
// TestBulkSnapshotCloseDuringSourceReadDeletesOnReceiver10284 closes the
// session after the source has captured its row but before the source returns.
// The source/delete generation critical section must defer that close draw
// until the snapshot row has been stamped, so the delete still outranks it.
func TestBulkSnapshotCloseDuringSourceReadDeletesOnReceiver10284(t *testing.T) {
	key := key10284(15, 42105)
	live := establishedIn(5)

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})
	seed := live
	sender.stampInstallGenV4(key, &seed)
	receiver, receiverDP := receiver10284(t)

	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sender.sendLoop(ctx)

	deleteAttempted := make(chan struct{})
	deleteDrawn := make(chan struct{})
	releaseSource := make(chan struct{})
	sender.testBeforeDeleteGen = func() {
		close(deleteAttempted)
	}
	sender.testAfterDeleteGen = func() {
		close(deleteDrawn)
		sender.testAfterDeleteGen = nil
	}
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		snap := BulkSnapshot{V4: []dataplane.SessionEntryV4{{Key: key, Value: live}}}
		go sender.QueueDeleteV4(key, false)
		<-deleteAttempted
		// Keep the row captured while the close goroutine tries to draw. The
		// fixed path blocks on bulkSnapshotGenMu; the reverted path reaches
		// deleteDrawn before this source returns.
		<-releaseSource
		return snap, nil
	}

	result := make(chan error, 1)
	go func() {
		result <- sender.doBulkSync()
	}()
	select {
	case <-deleteAttempted:
	case <-time.After(2 * time.Second):
		t.Fatal("source did not start the close-generation attempt")
	}
	select {
	case <-deleteDrawn:
		t.Fatal("#10284: close drew its generation before the source returned")
	case <-time.After(200 * time.Millisecond):
	}
	close(releaseSource)
	if err := <-result; err != nil {
		t.Fatalf("doBulkSync returned error: %v", err)
	}

	types := make([]byte, 0, 4)
	for len(types) < 4 {
		select {
		case mt := <-conn.writes:
			types = append(types, mt)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for source-race frames, got %d (%v)", len(types), types)
		}
	}
	startIndex, deleteIndex := -1, -1
	for i, typ := range types {
		switch typ {
		case syncMsgBulkStart:
			startIndex = i
		case syncMsgDeleteV4:
			deleteIndex = i
		}
	}
	if startIndex < 0 || deleteIndex <= startIndex {
		t.Fatalf("#10284: source-race delete was not after BulkStart (types %v)", types)
	}

	var installGen, deleteGen uint64
	for _, buf := range splitFrames10284(t, conn.bytes()) {
		switch buf.typ {
		case syncMsgSessionV4:
			k, val, ok := decodeSessionV4Payload(buf.payload)
			if !ok {
				t.Fatal("source-race session frame does not decode")
			}
			if k == key {
				installGen = val.Generation
			}
		case syncMsgDeleteV4:
			k, gen, _, ok := parseDeleteV4Wire(buf.payload)
			if !ok {
				t.Fatal("source-race delete frame does not decode")
			}
			if k == key {
				deleteGen = gen
			}
		}
	}
	if deleteGen <= installGen {
		t.Fatalf("#10284: source-race delete gen %d does not out-rank install gen %d", deleteGen, installGen)
	}
	replayBulkFrames(t, receiver, conn.bytes())
	if _, ok := receiverDP.v4sessions[key]; ok {
		t.Fatal("#10284: source-race close left the session installed on the receiver")
	}
}
// TestBulkSnapshotCloseAfterReadDeletesOnReceiverV6_10284 pins the independent
// v6 bulk iterator. Its row must be stamped before the post-BulkStart close,
// just like v4, so the receiver's tombstone wins the reordered arrival.
func TestBulkSnapshotCloseAfterReadDeletesOnReceiverV6_10284(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15},
		DstIP: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25},
		SrcPort: 42106, DstPort: 5201, Protocol: 6,
	}
	live := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 5}

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})
	seed := live
	sender.stampInstallGenV6(key, &seed)
	receiver, receiverDP := receiver10284(t)
	receiverDP.v6sessions = map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}

	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sender.sendLoop(ctx)

	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V6: []dataplane.SessionEntryV6{{Key: key, Value: live}}}, nil
	}
	sender.testBeforeBulkRows = func() {
		sender.QueueDeleteV6(key, false)
	}
	if err := sender.doBulkSync(); err != nil {
		t.Fatalf("doBulkSync returned error: %v", err)
	}

	types := make([]byte, 0, 4)
	for len(types) < 4 {
		select {
		case mt := <-conn.writes:
			types = append(types, mt)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for v6 bulk/close frames, got %d (%v)", len(types), types)
		}
	}
	startIndex, deleteIndex := -1, -1
	for i, typ := range types {
		switch typ {
		case syncMsgBulkStart:
			startIndex = i
		case syncMsgDeleteV6:
			deleteIndex = i
		}
	}
	if startIndex < 0 || deleteIndex <= startIndex {
		t.Fatalf("#10284: v6 close/delete was not observed after BulkStart (types %v)", types)
	}

	var installGen, deleteGen uint64
	for _, buf := range splitFrames10284(t, conn.bytes()) {
		switch buf.typ {
		case syncMsgSessionV6:
			k, val, ok := decodeSessionV6Payload(buf.payload)
			if !ok {
				t.Fatal("captured v6 session frame does not decode")
			}
			if k == key {
				installGen = val.Generation
			}
		case syncMsgDeleteV6:
			k, gen, _, ok := parseDeleteV6Wire(buf.payload)
			if !ok {
				t.Fatal("captured v6 delete frame does not decode")
			}
			if k == key {
				deleteGen = gen
			}
		}
	}
	if deleteGen <= installGen {
		t.Fatalf("#10284: v6 delete gen %d does not out-rank snapshot install gen %d", deleteGen, installGen)
	}
	replayBulkFrames(t, receiver, conn.bytes())
	if _, ok := receiverDP.v6sessions[key]; ok {
		t.Fatal("#10284: v6 session closed after BulkStart survived on the receiver")
	}
}



// TestSameBootReprimePreservesDeleteTombstone10284 is the #10284 cell 2
// fail-on-revert: a same-incarnation bulk re-prime must NOT wipe the
// receiver's delete tombstones. Snapshot-time stamping alone cannot close the
// resurrection — the stale row it still sends (older than the tombstone by
// construction) applies once the old reset path clears that tombstone.
func TestSameBootReprimePreservesDeleteTombstone10284(t *testing.T) {
	key := key10284(12, 42102)
	liveKey := key10284(16, 42107)
	receiver, receiverDP := receiver10284(t)
	inc := incA

	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, &inc))
	install10284(receiver, key, 100)
	delete10284(receiver, key, 200)
	install10284(receiver, liveKey, 300)
	if _, ok := receiverDP.v4sessions[key]; ok {
		t.Fatal("precondition: the close's delete did not remove the session")
	}
	if _, ok := receiverDP.v4sessions[liveKey]; !ok {
		t.Fatal("precondition: the live high-water session was not installed")
	}
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(1, &inc))

	// The next accepted BulkStart is the production same-incarnation reset:
	// retain the tombstone while discarding only live high-waters.

	// Same-boot re-prime whose snapshot still carries the session (it was
	// read before the close). The row's snapshot-time generation is older
	// than the delete tombstone — the receiver must refuse it. The lower
	// generation for liveKey must be admitted because the live high-water was
	// reclaimed for this same-incarnation authoritative window.
	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, &inc))
	install10284(receiver, key, 150)
	install10284(receiver, liveKey, 150)
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(2, &inc))

	if _, ok := receiverDP.v4sessions[key]; ok {
		t.Fatal("#10284: same-boot re-prime resurrected a session the tombstone should have refused")
	}
	if _, ok := receiverDP.v4sessions[liveKey]; !ok {
		t.Fatal("#10284: same-boot re-prime discarded a live session after reclaiming its high-water")
	}
	receiver.recvGenMu.Lock()
	stored := receiver.recvGenV4[key]
	liveStored := receiver.recvGenV4[liveKey]
	receiver.recvGenMu.Unlock()
	if stored != 200 {
		t.Fatalf("#10284: tombstone after same-boot re-prime = %d, want the delete's 200", stored)
	}
	if liveStored != 150 {
		t.Fatalf("#10284: live high-water after same-boot re-prime = %d, want re-prime's 150", liveStored)
	}
}
// TestSameNamespaceResetRetainsTombstoneCap10284 pins the #9915 cap invariant:
// a same-namespace reset may preserve a tombstone map that was grown to its
// effective cap, so it must preserve enough cap metadata for that map.
// A small override models the production tier without allocating 200k rows.
func TestSameNamespaceResetRetainsTombstoneCap10284(t *testing.T) {
	ss, _ := receiver10284(t)
	const wantCap = 8
	ss.recvGenGuardCap = wantCap
	ss.genGuardMapCeilingOverride = wantCap

	ss.recvGenMu.Lock()
	ss.recvGenV4 = make(map[dataplane.SessionKey]uint64, wantCap)
	for i := range wantCap {
		key := key10284(byte(40+i), uint16(42200+i))
		ss.recvGenV4[key] = uint64(i + 1)
		ss.recvTombV4.mark(key)
	}
	ss.recvGenMu.Unlock()

	ss.reclaimRecvLiveGen()

	ss.recvGenMu.Lock()
	gotCap := ss.recvGenGuardCap
	gotSize := len(ss.recvGenV4)
	gotTombs := ss.recvTombV4.size()
	ss.recvGenMu.Unlock()
	if gotCap != wantCap {
		t.Fatalf("#10284: same-namespace reset changed the preserved tombstone cap to %d, want %d", gotCap, wantCap)
	}
	if gotSize != wantCap || gotTombs != wantCap {
		t.Fatalf("#10284: preserved tombstone map/order mismatch: map=%d tombstones=%d cap=%d", gotSize, gotTombs, gotCap)
	}

	// The preserved cap must still let normal tombstone eviction record a new
	// live key rather than skip-recording it.
	newKey := key10284(60, 42300)
	ss.recordInstalledGenV4(newKey, 100)
	ss.recvGenMu.Lock()
	_, recorded := ss.recvGenV4[newKey]
	gotSize = len(ss.recvGenV4)
	gotTombs = ss.recvTombV4.size()
	ss.recvGenMu.Unlock()
	if !recorded {
		t.Fatal("#10284: preserved-cap receiver skipped a new live key after re-prime")
	}
	if gotSize != wantCap || gotTombs != wantCap-1 {
		t.Fatalf("#10284: preserved-cap eviction changed map/order unexpectedly: map=%d tombstones=%d cap=%d", gotSize, gotTombs, wantCap)
	}

	// A proven namespace reset is the one path that starts from the default.
	ss.resetRecvGen()
	ss.recvGenMu.Lock()
	gotCap = ss.recvGenGuardCap
	gotSize = len(ss.recvGenV4)
	gotTombs = ss.recvTombV4.size()
	ss.recvGenMu.Unlock()
	if gotCap != 0 || gotSize != 0 || gotTombs != 0 {
		t.Fatalf("#10284: full namespace reset retained cap/map state: cap=%d map=%d tombstones=%d", gotCap, gotSize, gotTombs)
	}
	// A production-sized ceiling with only a few retained tombstones reclaims
	// the default tier rather than carrying a formerly grown cap forever.
	ss.genGuardMapCeilingOverride = 0
	ss.recvGenGuardCap = genGuardMapDefaultCap * 2
	fewKey := key10284(61, 42301)
	ss.recvGenMu.Lock()
	ss.recvGenV4[fewKey] = 100
	ss.recvTombV4.mark(fewKey)
	ss.recvGenMu.Unlock()
	ss.reclaimRecvLiveGen()
	ss.recvGenMu.Lock()
	gotCap = ss.recvGenGuardCap
	gotSize = len(ss.recvGenV4)
	gotTombs = ss.recvTombV4.size()
	ss.recvGenMu.Unlock()
	if gotCap != 0 || gotSize != 1 || gotTombs != 1 {
		t.Fatalf("#10284: few-tombstone preserve did not reclaim default tier: cap=%d map=%d tombstones=%d", gotCap, gotSize, gotTombs)
	}
}

// TestRebootReprimeStillResetsSessionGens10284 pins the #2198 F2 half the
// #10284 preservation must not regress: across a boot-incarnation switch the
// BulkStart reset still clears the session high-waters, so the rebooted peer's
// lower-generation re-prime is accepted instead of refused as stale.
func TestRebootReprimeStillResetsSessionGens10284(t *testing.T) {
	key := key10284(13, 42103)
	receiver, receiverDP := receiver10284(t)
	incA, incB := incA, incB

	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(7, &incA))
	install10284(receiver, key, 9000)
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(7, &incA))

	// The peer reboots: new incarnation, its epoch and generation counters
	// restarted lower. The re-prime must land unconditionally.
	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, &incB))
	install10284(receiver, key, 5)
	if _, ok := receiverDP.v4sessions[key]; !ok {
		t.Fatal("#10284 regression: rebooted peer's lower-generation re-prime was refused as stale (#2198 F2)")
	}
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(1, &incB))
}

// TestLegacyBulkStartStillResetsSessionGens10284 pins the fail-open half: a
// BulkStart without an incarnation carries no boot evidence, so it keeps
// today's unconditional reset rather than risking stranding a rebooted legacy
// peer on pre-reboot high-waters.
func TestLegacyBulkStartStillResetsSessionGens10284(t *testing.T) {
	key := key10284(14, 42104)
	receiver, receiverDP := receiver10284(t)

	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	install10284(receiver, key, 9000)
	delete10284(receiver, key, 9500)
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(1, nil))

	receiver.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	install10284(receiver, key, 100)
	if _, ok := receiverDP.v4sessions[key]; !ok {
		t.Fatal("#10284 regression: un-incarnated re-prime no longer resets the session high-waters")
	}
	receiver.handleMessage(nil, syncMsgBulkEnd, bulkEndPayload(2, nil))
}

// frame10284 is one decoded sync frame: its type byte and payload.
type frame10284 struct {
	typ     byte
	payload []byte
}

// splitFrames10284 decodes a capture buffer into frames without applying them,
// so a test can pin wire generations directly.
func splitFrames10284(t *testing.T, buf []byte) []frame10284 {
	t.Helper()
	var out []frame10284
	for len(buf) > 0 {
		if len(buf) < syncHeaderSize {
			t.Fatalf("truncated frame header: %d bytes left", len(buf))
		}
		if string(buf[0:4]) != "BPSY" {
			t.Fatalf("bad sync magic: %q", buf[0:4])
		}
		typ := buf[4]
		n := binary.LittleEndian.Uint32(buf[8:12])
		buf = buf[syncHeaderSize:]
		if uint32(len(buf)) < n {
			t.Fatalf("truncated payload: want %d, have %d", n, len(buf))
		}
		out = append(out, frame10284{typ: typ, payload: buf[:n]})
		buf = buf[n:]
	}
	return out
}
