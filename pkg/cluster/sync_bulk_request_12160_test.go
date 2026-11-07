package cluster

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

type inventoryAddr12160 string

func (a inventoryAddr12160) Network() string { return "inventory-test" }
func (a inventoryAddr12160) String() string  { return string(a) }

type inventoryCaptureConn12160 struct {
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newInventoryCaptureConn12160(t *testing.T) *inventoryCaptureConn12160 {
	t.Helper()
	c := &inventoryCaptureConn12160{writes: make(chan []byte, 32), closed: make(chan struct{})}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (c *inventoryCaptureConn12160) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *inventoryCaptureConn12160) Write(p []byte) (int, error) {
	buf := append([]byte(nil), p...)
	select {
	case c.writes <- buf:
		return len(p), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *inventoryCaptureConn12160) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *inventoryCaptureConn12160) LocalAddr() net.Addr              { return inventoryAddr12160("local") }
func (c *inventoryCaptureConn12160) RemoteAddr() net.Addr             { return inventoryAddr12160("peer") }
func (c *inventoryCaptureConn12160) SetDeadline(time.Time) error      { return nil }
func (c *inventoryCaptureConn12160) SetReadDeadline(time.Time) error  { return nil }
func (c *inventoryCaptureConn12160) SetWriteDeadline(time.Time) error { return nil }

type inventoryFrame12160 struct {
	typ     uint8
	payload []byte
}

func decodeInventoryFrame12160(t *testing.T, raw []byte) inventoryFrame12160 {
	t.Helper()
	if len(raw) < syncHeaderSize || string(raw[:4]) != string(syncMagic[:]) {
		t.Fatalf("invalid sync frame: %x", raw)
	}
	payloadLen := int(binary.LittleEndian.Uint32(raw[8:12]))
	if len(raw) != syncHeaderSize+payloadLen {
		t.Fatalf("sync frame length = %d, header declares %d", len(raw), payloadLen)
	}
	return inventoryFrame12160{typ: raw[4], payload: append([]byte(nil), raw[syncHeaderSize:]...)}
}

func readInventoryFrame12160(t *testing.T, frames <-chan []byte) inventoryFrame12160 {
	t.Helper()
	select {
	case raw := <-frames:
		return decodeInventoryFrame12160(t, raw)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for sync frame")
		return inventoryFrame12160{}
	}
}

func installInventoryConn12160(s *SessionSync, c net.Conn) {
	s.mu.Lock()
	s.conn0 = c
	s.conn0Gen = s.peerIncarnation
	s.stats.Connected.Store(true)
	s.mu.Unlock()
}

func inventoryBulkMarker12160(epoch uint64) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, epoch)
	return payload
}

func inventoryIncarnatedBulkMarker12160(epoch uint64, inc bootIncarnation) []byte {
	return appendBootIncarnation(inventoryBulkMarker12160(epoch), inc)
}

func inventorySnapshot12160() BulkSnapshot {
	entries := make([]dataplane.SessionEntryV4, 3)
	for i := range entries {
		entries[i] = dataplane.SessionEntryV4{
			Key: dataplane.SessionKey{
				Protocol: 6,
				SrcIP:    [4]byte{192, 0, 2, byte(i + 1)},
				DstIP:    [4]byte{198, 51, 100, 10},
				SrcPort:  uint16(10000 + i),
				DstPort:  443,
			},
			Value: dataplane.SessionValue{
				State:       dataplane.SessStateEstablished,
				IngressZone: 1,
				EgressZone:  2,
				Created:     1,
				LastSeen:    1,
			},
		}
	}
	return BulkSnapshot{V4: entries}
}

type inventoryCompletion12160 struct {
	generation   uint64
	requestToken uint64
}

func inventoryPendingState12160(s *SessionSync) (bool, uint64, uint64) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	return s.inventoryPending, s.inventoryPendingGeneration, s.inventoryPendingRequestToken
}

func assertNoInventoryCallback12160(t *testing.T, callbacks <-chan inventoryCompletion12160, context string) {
	t.Helper()
	select {
	case completion := <-callbacks:
		t.Fatalf("%s invoked inventory callback with generation %d token %d",
			context, completion.generation, completion.requestToken)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPeerSessionInventoryRequestTriggersAuthoritativeBulk12160(t *testing.T) {
	const generation = uint64(73)
	const requestToken = uint64(1)
	const wantSessions = 3

	dp := &mockSweepDP{v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue)}
	requester := NewSessionSync(":0", "peer", dp)
	requester.SetZoneRGMap(map[uint16]int{})
	inventoryReceived := make(chan inventoryCompletion12160, 1)
	bulkReceived := make(chan struct{}, 1)
	requester.OnSessionInventoryBulkReceived = func(gotGeneration, gotToken uint64) {
		inventoryReceived <- inventoryCompletion12160{generation: gotGeneration, requestToken: gotToken}
	}
	requester.OnBulkSyncReceived = func() { bulkReceived <- struct{}{} }

	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(requester, wire)
	sender := NewSessionSync(":0", "peer", nil)
	installInventoryConn12160(sender, wire)

	if !requester.RequestPeerSessionInventory(generation, requestToken) {
		t.Fatal("connected requester failed to queue an inventory request")
	}
	queued := decodeInventoryFrame12160(t, <-requester.sendCh)
	if queued.typ != syncMsgBulkRequest || len(queued.payload) != 0 {
		t.Fatalf("queued request frame = type %d payload %x", queued.typ, queued.payload)
	}
	if syncMsgBulkRequest == syncMsgBulkAck {
		t.Fatal("bulk request reused BulkAck's message type")
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(requester); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("pending inventory = (%v, %d, %d), want (true, %d, %d)",
			pending, gotGeneration, gotToken, generation, requestToken)
	}

	var sourceCalls atomic.Int32
	sourceEntered := make(chan struct{})
	releaseSource := make(chan struct{})
	var releaseSourceOnce sync.Once
	releaseSourceNow := func() { releaseSourceOnce.Do(func() { close(releaseSource) }) }
	defer releaseSourceNow()
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		if sourceCalls.Add(1) == 1 {
			close(sourceEntered)
			<-releaseSource
		}
		return inventorySnapshot12160(), nil
	}
	sender.handleMessage(wire, queued.typ, queued.payload)
	select {
	case <-sourceEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not enter its configured authoritative snapshot source")
	}
	// A duplicate request arriving during the source read must not start a
	// second concurrent authoritative bulk.
	sender.handleMessage(wire, queued.typ, queued.payload)
	releaseSourceNow()

	var bulkEndEpoch uint64
	sessionFrames := 0
	for {
		frame := readInventoryFrame12160(t, wire.writes)
		switch frame.typ {
		case syncMsgBulkStart:
			requester.handleMessage(wire, frame.typ, frame.payload)
		case syncMsgSessionV4:
			sessionFrames++
			requester.handleMessage(wire, frame.typ, frame.payload)
		case syncMsgBulkEnd:
			bulkEndEpoch = binary.LittleEndian.Uint64(frame.payload[:8])
			requester.handleMessage(wire, frame.typ, frame.payload)
			goto bulkComplete
		default:
			t.Fatalf("unexpected sender frame type %d", frame.typ)
		}
	}

bulkComplete:
	if sessionFrames != wantSessions {
		t.Fatalf("authoritative bulk carried %d session rows, want %d", sessionFrames, wantSessions)
	}
	select {
	case got := <-inventoryReceived:
		want := inventoryCompletion12160{generation: generation, requestToken: requestToken}
		if got != want {
			t.Fatalf("inventory callback pair = (%d, %d), want (%d, %d)",
				got.generation, got.requestToken, want.generation, want.requestToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("successful requested bulk did not invoke the inventory callback")
	}
	select {
	case <-bulkReceived:
	case <-time.After(3 * time.Second):
		t.Fatal("successful bulk stopped invoking the existing OnBulkSyncReceived callback")
	}
	if got := len(dp.v4sessions); got != wantSessions {
		t.Fatalf("receiver sync store has %d installed entries after inventory completion, want %d", got, wantSessions)
	}
	if got := sourceCalls.Load(); got != 1 {
		t.Fatalf("concurrent duplicate request invoked the snapshot source %d times, want once", got)
	}
	if pending, _, _ := inventoryPendingState12160(requester); pending {
		t.Fatal("successfully reconciled inventory request remained pending")
	}

	ack := readInventoryFrame12160(t, wire.writes)
	if ack.typ != syncMsgBulkAck || len(ack.payload) < 8 {
		t.Fatalf("successful receiver ack = type %d payload length %d, want BulkAck with epoch", ack.typ, len(ack.payload))
	}
	if got := binary.LittleEndian.Uint64(ack.payload[:8]); got != bulkEndEpoch {
		t.Fatalf("BulkAck epoch = %d, want completed epoch %d", got, bulkEndEpoch)
	}
	sender.handleMessage(wire, ack.typ, ack.payload)
	if sender.pendingBulkAckEpoch.Load() != 0 || !sender.outboundBulkAcked.Load() {
		t.Fatal("the additive request frame changed the existing matching BulkAck completion semantics")
	}
}

func TestPeerSessionInventoryRequiresPostRequestReconciledBulk12160(t *testing.T) {
	disconnected := NewSessionSync(":0", "peer", nil)
	if disconnected.RequestPeerSessionInventory(1, 1) {
		t.Fatal("disconnected inventory request reported success")
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(disconnected); pending ||
		gotGeneration != 0 || gotToken != 0 {
		t.Fatalf("disconnected request armed inventory state: (%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}

	dp := &mockSweepDP{v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue)}
	s := NewSessionSync(":0", "peer", dp)
	s.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(s, wire)
	callbacks := make(chan inventoryCompletion12160, 2)
	s.OnSessionInventoryBulkReceived = func(generation, requestToken uint64) {
		callbacks <- inventoryCompletion12160{generation: generation, requestToken: requestToken}
	}

	// Begin an ordinary bulk before the request. Completing it afterward must
	// not consume the newly requested generation.
	inc := bootIncarnation{1}
	beforeRequest := inventoryIncarnatedBulkMarker12160(1, inc)
	s.handleMessage(wire, syncMsgBulkStart, beforeRequest)

	const generation = uint64(91)
	const requestToken = uint64(1)
	if !s.RequestPeerSessionInventory(generation, requestToken) {
		t.Fatal("connected inventory request failed to enter the queue")
	}
	queued := decodeInventoryFrame12160(t, <-s.sendCh)
	if queued.typ != syncMsgBulkRequest {
		t.Fatalf("queued frame type = %d, want BulkRequest", queued.typ)
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("old-peer-ignore posture lost pending request: (%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}
	s.handleMessage(wire, syncMsgBulkEnd, beforeRequest)
	preRequestAck := readInventoryFrame12160(t, wire.writes)
	if preRequestAck.typ != syncMsgBulkAck {
		t.Fatalf("pre-request bulk ack type = %d, want BulkAck", preRequestAck.typ)
	}
	assertNoInventoryCallback12160(t, callbacks, "bulk started before request")
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("pre-request-start bulk consumed pending request: (%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}

	// Same-epoch BulkStart is rejected after the prior bulk completed.
	s.bulkMu.Lock()
	serialBefore := s.bulkRecvSerial
	s.bulkMu.Unlock()
	s.handleMessage(wire, syncMsgBulkStart, inventoryIncarnatedBulkMarker12160(1, inc))
	s.bulkMu.Lock()
	staleStartRejected := !s.bulkInProgress && s.bulkRecvSerial == serialBefore
	s.bulkMu.Unlock()
	if !staleStartRejected {
		t.Fatal("stale BulkStart was accepted after a completed bulk at the same epoch")
	}
	assertNoInventoryCallback12160(t, callbacks, "rejected stale BulkStart")
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("rejected stale BulkStart consumed pending request: (%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}
	// Model an old peer ignoring this additive message: no later bulk means no
	// completion signal, and the request stays pending fail-closed.
	assertNoInventoryCallback12160(t, callbacks, "ignored request")

	// The accepted start captures the request, but a mismatched end is not a
	// completion. The matching end then fails ownership-snapshot validation,
	// also withholding the inventory callback and BulkAck.
	requestedBulk := inventoryIncarnatedBulkMarker12160(2, inc)
	s.handleMessage(wire, syncMsgBulkStart, requestedBulk)
	s.handleMessage(wire, syncMsgBulkEnd, inventoryIncarnatedBulkMarker12160(3, inc))
	assertNoInventoryCallback12160(t, callbacks, "unmatched BulkEnd")
	s.SetZoneRGMap(nil)
	s.handleMessage(wire, syncMsgBulkEnd, requestedBulk)
	assertNoInventoryCallback12160(t, callbacks, "failed reconcile")
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("failed bulk did not remain fail-closed: pending=(%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}
	s.bulkMu.Lock()
	active, activeGeneration, activeToken := s.inventoryActive,
		s.inventoryActiveGeneration, s.inventoryActiveRequestToken
	s.bulkMu.Unlock()
	if active || activeGeneration != 0 || activeToken != 0 {
		t.Fatalf("failed bulk retained active inventory state: (%v, %d, %d)",
			active, activeGeneration, activeToken)
	}
	s.handleDisconnect(wire)
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); pending ||
		gotGeneration != 0 || gotToken != 0 {
		t.Fatalf("full disconnect retained pending inventory state: (%v, %d, %d)",
			pending, gotGeneration, gotToken)
	}
}

func TestPeerSessionInventoryQueueFailureDoesNotArmGeneration12160(t *testing.T) {
	s := NewSessionSync(":0", "peer", nil)
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(s, wire)
	s.sendCh = make(chan []byte, 1)
	s.sendCh <- []byte("occupied")
	if s.RequestPeerSessionInventory(17, 1) {
		t.Fatal("full send queue reported inventory request success")
	}
	if pending, _, _ := inventoryPendingState12160(s); pending {
		t.Fatal("request whose frame did not enter the queue armed pending inventory")
	}
}

func TestPeerSessionInventoryExpiredBulkClearsActiveToken12160(t *testing.T) {
	const generation = uint64(37)
	const requestToken = uint64(9)
	s := NewSessionSync(":0", "peer", nil)
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(s, wire)
	if !s.RequestPeerSessionInventory(generation, requestToken) {
		t.Fatal("connected inventory request failed")
	}
	if frame := decodeInventoryFrame12160(t, <-s.sendCh); frame.typ != syncMsgBulkRequest {
		t.Fatalf("request frame type = %d, want BulkRequest", frame.typ)
	}

	now := time.Now()
	s.testBulkRecvNow = func() time.Time { return now }
	marker := inventoryIncarnatedBulkMarker12160(1, bootIncarnation{1})
	s.handleMessage(wire, syncMsgBulkStart, marker)
	s.bulkMu.Lock()
	active, activeGeneration, activeToken := s.inventoryActive,
		s.inventoryActiveGeneration, s.inventoryActiveRequestToken
	s.bulkMu.Unlock()
	if !active || activeGeneration != generation || activeToken != requestToken {
		t.Fatalf("started bulk correlation = (%v, %d, %d), want (true, %d, %d)",
			active, activeGeneration, activeToken, generation, requestToken)
	}

	now = now.Add(bulkRecvWindowTimeout + time.Second)
	s.expireBulkWindowIfStale()
	if pending, gotGeneration, gotToken := inventoryPendingState12160(s); !pending ||
		gotGeneration != generation || gotToken != requestToken {
		t.Fatalf("expired bulk lost pending request: (%v, %d, %d), want (true, %d, %d)",
			pending, gotGeneration, gotToken, generation, requestToken)
	}
	s.bulkMu.Lock()
	active, activeGeneration, activeToken = s.inventoryActive,
		s.inventoryActiveGeneration, s.inventoryActiveRequestToken
	s.bulkMu.Unlock()
	if active || activeGeneration != 0 || activeToken != 0 {
		t.Fatalf("expired bulk retained active inventory state: (%v, %d, %d)",
			active, activeGeneration, activeToken)
	}
}


func TestPeerSessionInventoryNewSameGenerationTokenSurvivesDelayedBulkCompletion12160(t *testing.T) {
	const generation = uint64(81)
	const firstToken = uint64(1)
	const retryToken = uint64(2)
	receiver := NewSessionSync(":0", "peer", &mockSweepDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
	})
	receiver.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(receiver, wire)
	callbacks := make(chan inventoryCompletion12160, 2)
	callbackStarted := make(chan struct{})
	releaseOldCallback := make(chan struct{})
	var callbackCalls atomic.Int32
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(releaseOldCallback) }) }
	defer releaseCallback()
	receiver.OnSessionInventoryBulkReceived = func(generation, requestToken uint64) {
		if callbackCalls.Add(1) == 1 {
			close(callbackStarted)
			<-releaseOldCallback
		}
		callbacks <- inventoryCompletion12160{generation: generation, requestToken: requestToken}
	}
	request := func(token uint64) {
		t.Helper()
		if !receiver.RequestPeerSessionInventory(generation, token) {
			t.Fatalf("inventory request token %d failed", token)
		}
		if frame := decodeInventoryFrame12160(t, <-receiver.sendCh); frame.typ != syncMsgBulkRequest {
			t.Fatalf("request frame type = %d, want BulkRequest", frame.typ)
		}
	}
	complete := func(epoch uint64) {
		t.Helper()
		marker := inventoryIncarnatedBulkMarker12160(epoch, bootIncarnation{1})
		receiver.handleMessage(wire, syncMsgBulkStart, marker)
		receiver.handleMessage(wire, syncMsgBulkEnd, marker)
		if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
			t.Fatalf("completed bulk ack type = %d, want BulkAck", ack.typ)
		}
	}

	if receiver.RequestPeerSessionInventory(generation, 0) {
		t.Fatal("zero request token was accepted")
	}
	request(firstToken)
	if receiver.RequestPeerSessionInventory(generation, firstToken) {
		t.Fatal("equal request token overwrote an existing pending request")
	}
	firstMarker := inventoryIncarnatedBulkMarker12160(1, bootIncarnation{1})
	receiver.handleMessage(wire, syncMsgBulkStart, firstMarker)

	// A newer replay for the same helper generation is armed while the older
	// request's authoritative bulk is in progress. Its completion must not
	// consume the newer pending pair.
	request(retryToken)
	if receiver.RequestPeerSessionInventory(generation, firstToken) {
		t.Fatal("stale same-generation request token overwrote a newer pending pair")
	}
	receiver.bulkMu.Lock()
	active, activeGeneration, activeToken := receiver.inventoryActive,
		receiver.inventoryActiveGeneration, receiver.inventoryActiveRequestToken
	receiver.bulkMu.Unlock()
	if !active || activeGeneration != generation || activeToken != firstToken {
		t.Fatalf("in-flight request pair = (%v, %d, %d), want (true, %d, %d)",
			active, activeGeneration, activeToken, generation, firstToken)
	}

	receiver.handleMessage(wire, syncMsgBulkEnd, firstMarker)
	if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
		t.Fatalf("old bulk ack type = %d, want BulkAck", ack.typ)
	}
	select {
	case <-callbackStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("old completion callback did not start")
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(receiver); !pending ||
		gotGeneration != generation || gotToken != retryToken {
		t.Fatalf("old completion cleared newer same-generation request: pending=(%v, %d, %d), want (true, %d, %d)",
			pending, gotGeneration, gotToken, generation, retryToken)
	}
	releaseCallback()
	select {
	case got := <-callbacks:
		want := inventoryCompletion12160{generation: generation, requestToken: firstToken}
		if got != want {
			t.Fatalf("delayed old completion pair = (%d, %d), want (%d, %d)",
				got.generation, got.requestToken, want.generation, want.requestToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("delayed old completion did not report its captured request pair")
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(receiver); !pending ||
		gotGeneration != generation || gotToken != retryToken {
		t.Fatalf("delayed old callback consumed newer request: pending=(%v, %d, %d), want (true, %d, %d)",
			pending, gotGeneration, gotToken, generation, retryToken)
	}

	complete(2)
	select {
	case got := <-callbacks:
		want := inventoryCompletion12160{generation: generation, requestToken: retryToken}
		if got != want {
			t.Fatalf("new completion pair = (%d, %d), want (%d, %d)",
				got.generation, got.requestToken, want.generation, want.requestToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new same-generation request did not report its own completion")
	}
	if pending, _, _ := inventoryPendingState12160(receiver); pending {
		t.Fatal("new same-generation request remained pending after its bulk completed")
	}
}

func TestPeerSessionInventoryOlderBulkCannotClearNewGeneration12160(t *testing.T) {
	const oldGeneration = uint64(81)
	const newGeneration = uint64(82)
	const oldToken = uint64(1)
	const newToken = uint64(2)
	receiver := NewSessionSync(":0", "peer", &mockSweepDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
	})
	receiver.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(receiver, wire)
	callbacks := make(chan inventoryCompletion12160, 2)
	receiver.OnSessionInventoryBulkReceived = func(generation, requestToken uint64) {
		callbacks <- inventoryCompletion12160{generation: generation, requestToken: requestToken}
	}
	request := func(generation, requestToken uint64) {
		t.Helper()
		if !receiver.RequestPeerSessionInventory(generation, requestToken) {
			t.Fatalf("inventory request for pair (%d, %d) failed", generation, requestToken)
		}
		if frame := decodeInventoryFrame12160(t, <-receiver.sendCh); frame.typ != syncMsgBulkRequest {
			t.Fatalf("request frame type = %d, want BulkRequest", frame.typ)
		}
	}
	complete := func(epoch uint64) {
		t.Helper()
		marker := inventoryIncarnatedBulkMarker12160(epoch, bootIncarnation{1})
		receiver.handleMessage(wire, syncMsgBulkStart, marker)
		receiver.handleMessage(wire, syncMsgBulkEnd, marker)
		if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
			t.Fatalf("completed bulk ack type = %d, want BulkAck", ack.typ)
		}
	}

	request(oldGeneration, oldToken)
	oldMarker := inventoryIncarnatedBulkMarker12160(1, bootIncarnation{1})
	receiver.handleMessage(wire, syncMsgBulkStart, oldMarker)
	request(newGeneration, newToken)
	if receiver.RequestPeerSessionInventory(oldGeneration, newToken+1) {
		t.Fatal("stale old-generation request overwrote newer pending inventory")
	}
	receiver.handleMessage(wire, syncMsgBulkEnd, oldMarker)
	if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
		t.Fatalf("old-generation bulk ack type = %d, want BulkAck", ack.typ)
	}

	select {
	case got := <-callbacks:
		want := inventoryCompletion12160{generation: oldGeneration, requestToken: oldToken}
		if got != want {
			t.Fatalf("first bulk completion pair = (%d, %d), want (%d, %d)",
				got.generation, got.requestToken, want.generation, want.requestToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed old-generation bulk did not report its own correlation")
	}
	if pending, gotGeneration, gotToken := inventoryPendingState12160(receiver); !pending ||
		gotGeneration != newGeneration || gotToken != newToken {
		t.Fatalf("old bulk cleared newer inventory debt: pending=(%v, %d, %d), want (true, %d, %d)",
			pending, gotGeneration, gotToken, newGeneration, newToken)
	}
	complete(2)
	select {
	case got := <-callbacks:
		want := inventoryCompletion12160{generation: newGeneration, requestToken: newToken}
		if got != want {
			t.Fatalf("second bulk completion pair = (%d, %d), want (%d, %d)",
				got.generation, got.requestToken, want.generation, want.requestToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed new-generation bulk did not report its correlation")
	}
	if pending, _, _ := inventoryPendingState12160(receiver); pending {
		t.Fatal("new-generation inventory request remained pending after its bulk completed")
	}
}

// TestBulkReconcileRejectsStaleSerial12160 pins the serial fence in
// reconcileStaleSessions (Opus F7): a reconcile for a superseded bulk
// serial must not consume the in-progress window. Kills M9 (serial check
// dropped). Short name: the 12160 test names must survive long TMPDIR
// unix-socket paths (F7 socket-path limit).
func TestBulkReconcileRejectsStaleSerial12160(t *testing.T) {
	s := NewSessionSync(":0", "peer", nil)
	s.bulkMu.Lock()
	s.bulkInProgress = true
	s.bulkRecvSerial = 7
	s.bulkMu.Unlock()
	if ok, _, _, _ := s.reconcileStaleSessions(6); ok {
		t.Fatal("stale serial 6 reconciled window for serial 7")
	}
	s.bulkMu.Lock()
	stillInProgress, serial := s.bulkInProgress, s.bulkRecvSerial
	s.bulkMu.Unlock()
	if !stillInProgress || serial != 7 {
		t.Fatalf("stale reconcile disturbed the window: inProgress=%v serial=%d", stillInProgress, serial)
	}
	// Matching serial passes the fence and consumes the window (the
	// reconcile itself may still decline on validation — the fence only
	// gates entry).
	_, _, _, _ = s.reconcileStaleSessions(7)
	s.bulkMu.Lock()
	consumed := !s.bulkInProgress
	s.bulkMu.Unlock()
	if !consumed {
		t.Fatal("matching serial 7 did not consume the window")
	}
}
