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

func inventoryPendingState12160(s *SessionSync) (bool, uint64) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	return s.inventoryPending, s.inventoryPendingGeneration
}

func assertNoInventoryCallback12160(t *testing.T, callbacks <-chan uint64, context string) {
	t.Helper()
	select {
	case generation := <-callbacks:
		t.Fatalf("%s invoked inventory callback with generation %d", context, generation)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPeerSessionInventoryRequestTriggersAuthoritativeBulk12160(t *testing.T) {
	const generation = uint64(73)
	const wantSessions = 3

	dp := &mockSweepDP{v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue)}
	requester := NewSessionSync(":0", "peer", dp)
	requester.SetZoneRGMap(map[uint16]int{})
	inventoryReceived := make(chan uint64, 1)
	bulkReceived := make(chan struct{}, 1)
	requester.OnSessionInventoryBulkReceived = func(got uint64) { inventoryReceived <- got }
	requester.OnBulkSyncReceived = func() { bulkReceived <- struct{}{} }

	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(requester, wire)
	sender := NewSessionSync(":0", "peer", nil)
	installInventoryConn12160(sender, wire)

	if !requester.RequestPeerSessionInventory(generation) {
		t.Fatal("connected requester failed to queue an inventory request")
	}
	queued := decodeInventoryFrame12160(t, <-requester.sendCh)
	if queued.typ != syncMsgBulkRequest || len(queued.payload) != 0 {
		t.Fatalf("queued request frame = type %d payload %x", queued.typ, queued.payload)
	}
	if syncMsgBulkRequest == syncMsgBulkAck {
		t.Fatal("bulk request reused BulkAck's message type")
	}
	if pending, got := inventoryPendingState12160(requester); !pending || got != generation {
		t.Fatalf("pending inventory = (%v, %d), want (true, %d)", pending, got, generation)
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
		if got != generation {
			t.Fatalf("inventory callback generation = %d, want %d", got, generation)
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
	if pending, _ := inventoryPendingState12160(requester); pending {
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
	if disconnected.RequestPeerSessionInventory(1) {
		t.Fatal("disconnected inventory request reported success")
	}
	if pending, _ := inventoryPendingState12160(disconnected); pending {
		t.Fatal("disconnected request armed pending inventory state")
	}

	dp := &mockSweepDP{v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue)}
	s := NewSessionSync(":0", "peer", dp)
	s.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(s, wire)
	callbacks := make(chan uint64, 2)
	s.OnSessionInventoryBulkReceived = func(generation uint64) { callbacks <- generation }

	// Begin an ordinary bulk before the request. Completing it afterward must
	// not consume the newly requested generation.
	inc := bootIncarnation{1}
	beforeRequest := inventoryIncarnatedBulkMarker12160(1, inc)
	s.handleMessage(wire, syncMsgBulkStart, beforeRequest)

	const generation = uint64(91)
	if !s.RequestPeerSessionInventory(generation) {
		t.Fatal("connected inventory request failed to enter the queue")
	}
	queued := decodeInventoryFrame12160(t, <-s.sendCh)
	if queued.typ != syncMsgBulkRequest {
		t.Fatalf("queued frame type = %d, want BulkRequest", queued.typ)
	}
	if pending, got := inventoryPendingState12160(s); !pending || got != generation {
		t.Fatalf("old-peer-ignore posture lost pending request: (%v, %d)", pending, got)
	}
	s.handleMessage(wire, syncMsgBulkEnd, beforeRequest)
	preRequestAck := readInventoryFrame12160(t, wire.writes)
	if preRequestAck.typ != syncMsgBulkAck {
		t.Fatalf("pre-request bulk ack type = %d, want BulkAck", preRequestAck.typ)
	}
	assertNoInventoryCallback12160(t, callbacks, "bulk started before request")
	if pending, got := inventoryPendingState12160(s); !pending || got != generation {
		t.Fatalf("pre-request-start bulk consumed pending request: (%v, %d)", pending, got)
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
	if pending, got := inventoryPendingState12160(s); !pending || got != generation {
		t.Fatalf("rejected stale BulkStart consumed pending request: (%v, %d)", pending, got)
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
	if pending, got := inventoryPendingState12160(s); !pending || got != generation {
		t.Fatalf("failed bulk did not remain fail-closed: pending=(%v, %d)", pending, got)
	}
	s.handleDisconnect(wire)
	if pending, _ := inventoryPendingState12160(s); pending {
		t.Fatal("full disconnect retained a pending inventory generation")
	}
}

func TestPeerSessionInventoryQueueFailureDoesNotArmGeneration12160(t *testing.T) {
	s := NewSessionSync(":0", "peer", nil)
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(s, wire)
	s.sendCh = make(chan []byte, 1)
	s.sendCh <- []byte("occupied")
	if s.RequestPeerSessionInventory(17) {
		t.Fatal("full send queue reported inventory request success")
	}
	if pending, _ := inventoryPendingState12160(s); pending {
		t.Fatal("request whose frame did not enter the queue armed pending inventory")
	}
}

func TestPeerSessionInventoryRetryDuringBulkPreservesSameGeneration12160(t *testing.T) {
	const generation = uint64(81)
	receiver := NewSessionSync(":0", "peer", &mockSweepDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
	})
	receiver.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(receiver, wire)
	callbacks := make(chan uint64, 1)
	receiver.OnSessionInventoryBulkReceived = func(generation uint64) {
		callbacks <- generation
	}

	if !receiver.RequestPeerSessionInventory(generation) {
		t.Fatal("initial inventory request failed")
	}
	_ = decodeInventoryFrame12160(t, <-receiver.sendCh)
	marker := inventoryIncarnatedBulkMarker12160(1, bootIncarnation{1})
	receiver.handleMessage(wire, syncMsgBulkStart, marker)

	// A Manager retry can arrive while a large bulk is still in progress.
	// The already accepted full inventory still proves this same generation.
	if !receiver.RequestPeerSessionInventory(generation) {
		t.Fatal("retry inventory request failed")
	}
	retry := decodeInventoryFrame12160(t, <-receiver.sendCh)
	if retry.typ != syncMsgBulkRequest {
		t.Fatalf("retry frame type = %d, want BulkRequest", retry.typ)
	}
	receiver.bulkMu.Lock()
	active, activeGeneration := receiver.inventoryActive, receiver.inventoryActiveGeneration
	receiver.bulkMu.Unlock()
	if !active || activeGeneration != generation {
		t.Fatalf("in-flight request correlation = (%v, %d), want (true, %d)",
			active, activeGeneration, generation)
	}

	receiver.handleMessage(wire, syncMsgBulkEnd, marker)
	if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
		t.Fatalf("completed bulk ack type = %d, want BulkAck", ack.typ)
	}
	select {
	case got := <-callbacks:
		if got != generation {
			t.Fatalf("inventory callback generation = %d, want %d", got, generation)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight full inventory did not satisfy its same-generation retry")
	}
	if pending, _ := inventoryPendingState12160(receiver); pending {
		t.Fatal("same-generation retry remained pending after the full inventory completed")
	}
}

func TestPeerSessionInventoryOlderBulkCannotClearNewGeneration12160(t *testing.T) {
	const oldGeneration = uint64(81)
	const newGeneration = uint64(82)
	receiver := NewSessionSync(":0", "peer", &mockSweepDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
	})
	receiver.SetZoneRGMap(map[uint16]int{})
	wire := newInventoryCaptureConn12160(t)
	installInventoryConn12160(receiver, wire)
	callbacks := make(chan uint64, 2)
	receiver.OnSessionInventoryBulkReceived = func(generation uint64) {
		callbacks <- generation
	}
	request := func(generation uint64) {
		t.Helper()
		if !receiver.RequestPeerSessionInventory(generation) {
			t.Fatalf("inventory request for generation %d failed", generation)
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

	request(oldGeneration)
	oldMarker := inventoryIncarnatedBulkMarker12160(1, bootIncarnation{1})
	receiver.handleMessage(wire, syncMsgBulkStart, oldMarker)
	request(newGeneration)
	if receiver.RequestPeerSessionInventory(oldGeneration) {
		t.Fatal("stale old-generation request overwrote newer pending inventory")
	}
	receiver.handleMessage(wire, syncMsgBulkEnd, oldMarker)
	if ack := readInventoryFrame12160(t, wire.writes); ack.typ != syncMsgBulkAck {
		t.Fatalf("old-generation bulk ack type = %d, want BulkAck", ack.typ)
	}

	select {
	case got := <-callbacks:
		if got != oldGeneration {
			t.Fatalf("first bulk callback generation = %d, want %d", got, oldGeneration)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed old-generation bulk did not report its own correlation")
	}
	if pending, got := inventoryPendingState12160(receiver); !pending || got != newGeneration {
		t.Fatalf("old bulk cleared newer inventory debt: pending=(%v, %d), want (true, %d)",
			pending, got, newGeneration)
	}
	complete(2)
	select {
	case got := <-callbacks:
		if got != newGeneration {
			t.Fatalf("second bulk callback generation = %d, want %d", got, newGeneration)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed new-generation bulk did not report its correlation")
	}
	if pending, _ := inventoryPendingState12160(receiver); pending {
		t.Fatal("new-generation inventory request remained pending after its bulk completed")
	}
}
