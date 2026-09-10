package cluster

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9508: the session-sync readiness barrier carries no connection identity.
//
// sendLoop writes every dequeued message on whatever connection is active at that
// instant, and a BarrierAck from ANY connection advances the global barrierAckSeq.
// So a delta written on one fabric connection and still unprocessed by the peer
// cannot hold back a barrier that is sent and ACKed on the other. Readiness then
// permits a demotion before the peer has the state the barrier was meant to
// fence.
//
// These cells need a connection a net.Pipe cannot model. A pipe's write blocks
// until the reader reads, so "written, but not yet processed by the peer" never
// exists. heldConn9508 accepts writes at once into a buffer, as a TCP socket does.
// The test decides when the peer processes a connection. Written before the fix;
// the two route cells are RED at base.

type heldConn9508 struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
	done   chan struct{}
	name   string
	// onWrite, when set before the connection is used, runs inside Write after
	// the bytes are buffered and before Write returns: a peer that ACKs a frame
	// before the local write call has returned.
	onWrite func([]byte)
}

func newHeldConn9508(name string) *heldConn9508 {
	return &heldConn9508{name: name, done: make(chan struct{})}
}

func (c *heldConn9508) Read([]byte) (int, error) { <-c.done; return 0, io.EOF }

func (c *heldConn9508) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.buf.Write(b)
	c.mu.Unlock()
	if c.onWrite != nil {
		c.onWrite(b)
	}
	return len(b), nil
}

func (c *heldConn9508) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	return nil
}

func (c *heldConn9508) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4785}
}
func (c *heldConn9508) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4785}
}
func (c *heldConn9508) SetDeadline(time.Time) error      { return nil }
func (c *heldConn9508) SetReadDeadline(time.Time) error  { return nil }
func (c *heldConn9508) SetWriteDeadline(time.Time) error { return nil }

type frame9508 struct {
	typ     byte
	payload []byte
}

// frames returns every whole frame written on the connection so far, in order.
func (c *heldConn9508) frames() []frame9508 {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf.Bytes()
	var out []frame9508
	for len(b) >= syncHeaderSize {
		n := int(binary.LittleEndian.Uint32(b[8:12]))
		if len(b) < syncHeaderSize+n {
			break
		}
		out = append(out, frame9508{typ: b[4], payload: append([]byte(nil), b[syncHeaderSize:syncHeaderSize+n]...)})
		b = b[syncHeaderSize+n:]
	}
	return out
}

func waitForFrame9508(t *testing.T, c *heldConn9508, typ byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range c.frames() {
			if f.typ == typ {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("FIXTURE: no frame of type %d was ever written on %s", typ, c.name)
}

func key9508() dataplane.SessionKey {
	return dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 40000, DstPort: 5201}
}

func val9508() dataplane.SessionValue {
	return dataplane.SessionValue{State: dataplane.SessStateEstablished, SessionID: 1}
}

func dualSync9508(t *testing.T) *SessionSync {
	t.Helper()
	return dualSyncWith9508(t, nil)
}

// dualSyncWith9508 is dualSync9508 over a runtime, so a cell can give BulkSync a
// session store to walk.
func dualSyncWith9508(t *testing.T, rt clusterRuntime) *SessionSync {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", rt)
	ss.peerIncarnation = 7
	ss.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ss.sendLoop(ctx)
	return ss
}

// barrierOutcome9508 runs WaitForPeerBarrier while the peer processes ackOn in
// order, ACKing each barrier once on that connection through the real receive
// path. It returns the barrier's result. It does not REQUIRE a barrier to be
// written: a fixed sender may refuse one outright.
func barrierOutcome9508(t *testing.T, ss *SessionSync, ackOn *heldConn9508) error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- ss.WaitForPeerBarrier(time.Second) }()
	acked := map[uint64]bool{}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case err := <-errCh:
			return err
		case <-deadline:
			t.Fatal("FIXTURE: WaitForPeerBarrier neither returned nor completed within 3s")
			return nil
		default:
		}
		for _, f := range ackOn.frames() {
			if f.typ != syncMsgBarrier || len(f.payload) < 8 {
				continue
			}
			seq := binary.LittleEndian.Uint64(f.payload[:8])
			if acked[seq] {
				continue
			}
			acked[seq] = true
			var ack [24]byte
			copy(ack[:8], f.payload[:8])
			ss.handleMessage(ackOn, syncMsgBarrierAck, ack[:])
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ROUTE 1: fab0 is lost (RST, link loss) with a delta the peer never processed.
// The barrier goes out on fab1, and fab1's peer ACKs it.
func TestBarrierIsNotSatisfiedAfterADeltaWasLostWithADroppedFabric_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(0, fab0)
	ss.installConn(1, fab1)
	if ss.getActiveConn() != fab0 {
		t.Fatal("FIXTURE: fab0 must be the active connection")
	}
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab0, syncMsgSessionV4)
	ss.handleDisconnect(fab0)
	if ss.getActiveConn() != fab1 {
		t.Fatal("FIXTURE: fab1 must carry the stream after fab0 drops")
	}
	if err := barrierOutcome9508(t, ss, fab1); err == nil {
		t.Fatal("#9508: the barrier succeeded on fab1 although the delta written on fab0 was never " +
			"processed by the peer; readiness would permit a demotion that loses that session")
	}
}

// ROUTE 2, with no fault: a delta is written on fab1 while it is the only
// connection. fab0 is then installed and preferred, nothing drops, and fab1's
// backlog is still in flight when the barrier is ACKed on fab0.
func TestBarrierIsNotSatisfiedWhenTheActiveFabricChangedWithoutADrop_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	if ss.getActiveConn() != fab1 {
		t.Fatal("FIXTURE: fab1 must be active while it is the only connection")
	}
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)
	ss.installConn(0, fab0)
	if ss.getActiveConn() != fab0 {
		t.Fatal("FIXTURE: fab0 must become the active connection once installed")
	}
	if err := barrierOutcome9508(t, ss, fab0); err == nil {
		t.Fatal("#9508: the barrier succeeded on fab0 while the delta written on fab1 was still " +
			"unprocessed by the peer")
	}
}

// CONTROL: one connection, the delta then the barrier, processed in order.
func TestBarrierCompletesOnASingleFabric_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0 := newHeldConn9508("fab0")
	ss.installConn(0, fab0)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab0, syncMsgSessionV4)
	if err := barrierOutcome9508(t, ss, fab0); err != nil {
		t.Fatalf("CONTROL: a barrier on one connection, after its delta was processed, must complete: %v", err)
	}
}

// CONTROL: dual fabric with no change of the active connection must still
// complete, so the fix cannot simply refuse every barrier on a dual-fabric
// cluster.
func TestBarrierCompletesOnDualFabricWithoutASwitch_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(0, fab0)
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab0, syncMsgSessionV4)
	if err := barrierOutcome9508(t, ss, fab0); err != nil {
		t.Fatalf("CONTROL: dual fabric with no switch must complete a barrier: %v", err)
	}
}

// ackEveryBulkEnd9508 ACKs, through the real receive path, every BulkEnd written
// on c so far. An ACK for an epoch that is no longer pending is ignored by design.
func ackEveryBulkEnd9508(ss *SessionSync, c *heldConn9508) int {
	n := 0
	for _, f := range c.frames() {
		if f.typ == syncMsgBulkEnd && len(f.payload) >= 8 {
			ss.handleMessage(c, syncMsgBulkAck, f.payload[:8])
			n++
		}
	}
	return n
}

// RECOVERY: the fence is not a permanent refusal. After the stream moves, the
// fence re-prime runs on the current connection, and once the peer ACKs that
// bulk a barrier completes again. The daemon does not re-prime a primed peer on
// its own, so without this every later demotion would be refused.
func TestBarrierCompletesAgainOnceTheFenceRePrimeIsAcked_9508(t *testing.T) {
	ss := dualSync9508(t)
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) { return BulkSnapshot{}, nil }
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)
	ss.installConn(0, fab0)
	if err := barrierOutcome9508(t, ss, fab0); err == nil {
		t.Fatal("FIXTURE: the first barrier after the stream moved must be refused")
	}
	ackRePrimeUntilDischarged9508(t, ss, fab0)
	if err := barrierOutcome9508(t, ss, fab0); err != nil {
		t.Fatalf("#9508: after the re-prime on the current connection was ACKed, a barrier must complete: %v", err)
	}
}

// ackRePrimeUntilDischarged9508 ACKs the BulkEnds written on c until the fence is
// discharged. A refused barrier may have started a newer bulk, so it keeps ACKing
// whatever is pending; an ACK for a superseded epoch is ignored by design.
func ackRePrimeUntilDischarged9508(t *testing.T, ss *SessionSync, c *heldConn9508) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for ss.barrierFenced() && time.Now().Before(deadline) {
		ackEveryBulkEnd9508(ss, c)
		time.Sleep(5 * time.Millisecond)
	}
	if ss.barrierFenced() {
		t.Fatalf("#9508: no re-prime written on %s discharged the fence once ACKed", c.name)
	}
}

// RECOVERY through the store walk: with no BulkSnapshotSource the re-prime goes
// through BulkSync, which reads the session store DURING the window and so captures
// at BulkStart. Its ACK must discharge the fence as a snapshot bulk's does.
func TestAStoreWalkRePrimeDischargesTheFence_9508(t *testing.T) {
	ss := dualSyncWith9508(t, &mockSweepDP{})
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)
	ss.installConn(0, fab0)
	if err := barrierOutcome9508(t, ss, fab0); err == nil {
		t.Fatal("FIXTURE: the first barrier after the stream moved must be refused")
	}
	ackRePrimeUntilDischarged9508(t, ss, fab0)
	if err := barrierOutcome9508(t, ss, fab0); err != nil {
		t.Fatalf("#9508: after the store-walk re-prime was ACKed, a barrier must complete: %v", err)
	}
}

// CAPTURE ORDER: a bulk whose snapshot was read BEFORE the stream moved cannot
// hold a delta written on the new connection after that read, so its ACK must
// not discharge the fence. The move happens inside the snapshot read.
func TestAnAckedBulkWhoseSnapshotPredatesTheMoveKeepsTheFence_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var reads atomic.Int32
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) {
		if reads.Add(1) > 1 {
			// The move's own re-prime parks here, so this cell ACKs exactly one bulk.
			<-release
			return BulkSnapshot{}, fmt.Errorf("cell ended")
		}
		ss.installConn(0, fab0)
		ss.QueueSessionV4(key9508(), val9508())
		waitForFrame9508(t, fab0, syncMsgSessionV4)
		return BulkSnapshot{}, nil
	}
	if err := ss.doBulkSync(); err != nil {
		t.Fatalf("FIXTURE: the bulk must complete: %v", err)
	}
	waitForFrame9508(t, fab0, syncMsgBulkEnd)
	if n := ackEveryBulkEnd9508(ss, fab0); n != 1 {
		t.Fatalf("FIXTURE: exactly one BulkEnd must be on fab0, got %d", n)
	}
	if !ss.outboundBulkAcked.Load() {
		t.Fatal("FIXTURE: the ACK must have matched the pending bulk")
	}
	if err := barrierOutcome9508(t, ss, fab0); err == nil {
		t.Fatal("#9508: a bulk whose snapshot was read before the stream moved discharged the fence; " +
			"the delta written on the new connection after that read is in no snapshot the peer has")
	}
}

// ORDER: the move must be recorded BEFORE the barrier is written. A peer can ACK a
// frame before the local write call returns. The hook delivers the ACK from inside
// Write and then HOLDS the write open until the waiter has decided, so the decision
// cannot observe anything the writer does after the bytes are on the wire. Without
// the hold this cell raced the waiter against the writer's next line and a mutant
// that recorded the move after the write survived (the first #9508 matrix, F2).
func TestAMoveIsRecordedBeforeTheBarrierIsWritten_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)
	errFixture := fmt.Errorf("fixture: the waiter did not decide while its write was held open")
	errCh := make(chan error, 1)
	decided := make(chan error, 1)
	var once sync.Once
	fab0.onWrite = func(b []byte) {
		if len(b) < syncHeaderSize+8 || b[4] != syncMsgBarrier {
			return
		}
		once.Do(func() {
			var ack [24]byte
			copy(ack[:8], b[syncHeaderSize:syncHeaderSize+8])
			ss.handleMessage(fab0, syncMsgBarrierAck, ack[:])
			select {
			case err := <-errCh:
				decided <- err
			case <-time.After(2 * time.Second):
				decided <- errFixture
			}
		})
	}
	ss.installConn(0, fab0)
	go func() { errCh <- ss.WaitForPeerBarrier(time.Second) }()
	select {
	case err := <-decided:
		if err == errFixture {
			t.Fatal("FIXTURE: the barrier waiter did not decide while its write was held open")
		}
		if err == nil {
			t.Fatal("#9508: an ACK delivered before the barrier write returned satisfied the barrier; " +
				"the stream move was recorded after the write, not before it")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIXTURE: no barrier was ever written on fab0")
	}
}

// RELEASE: a barrier pending when the stream moves fails at once, with the fence
// error, even when no ACK will ever come. Here the barrier itself was lost with the
// dropped connection; only a later delta moves the stream.
func TestAPendingBarrierFailsPromptlyWithTheFenceErrorWhenTheStreamMoves_9508(t *testing.T) {
	ss := dualSync9508(t)
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(0, fab0)
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab0, syncMsgSessionV4)
	errCh := make(chan error, 1)
	go func() { errCh <- ss.WaitForPeerBarrier(5 * time.Second) }()
	waitForFrame9508(t, fab0, syncMsgBarrier)
	ss.handleDisconnect(fab0)
	ss.QueueSessionV4(key9508(), val9508())
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "barrier fenced") {
			t.Fatalf("#9508: a barrier pending across a stream move must fail with the fence error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("#9508: the barrier pending when the stream moved was not released; it waits out its " +
			"whole timeout for an ACK that was lost with the dropped connection")
	}
}
