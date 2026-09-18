package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// gapCaptureConn captures complete unauthenticated sync frames and signals the
// type of each frame as it is written. It accepts writes without a reader, so
// the source callback can hold the snapshot->BulkStart gap without introducing
// net.Pipe scheduling into the assertion.
type gapCaptureConn struct {
	mu                 sync.Mutex
	buf                []byte
	writes             chan byte
	closed             chan struct{}
	once               sync.Once
	sessionCount       int
	sessionTarget      int
	allSessionsWritten chan struct{}
	sessionsOnce       sync.Once
}

func newGapCaptureConn() *gapCaptureConn {
	return &gapCaptureConn{
		writes:             make(chan byte, 32),
		closed:             make(chan struct{}),
		allSessionsWritten: make(chan struct{}),
	}
}

func (c *gapCaptureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	if len(p) < syncHeaderSize {
		return len(p), nil
	}
	mt := p[4]
	c.writes <- mt
	if mt == syncMsgSessionV4 {
		c.mu.Lock()
		c.sessionCount++
		count := c.sessionCount
		target := c.sessionTarget
		c.mu.Unlock()
		if target != 0 && count >= target {
			c.sessionsOnce.Do(func() { close(c.allSessionsWritten) })
		}
	}
	return len(p), nil
}

func (c *gapCaptureConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *gapCaptureConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *gapCaptureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4785}
}
func (c *gapCaptureConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4785}
}
func (c *gapCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *gapCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gapCaptureConn) SetWriteDeadline(time.Time) error { return nil }

func (c *gapCaptureConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func TestDoBulkSyncGapOpenSurvivesBulkEnd10283(t *testing.T) {
	const sampleCount = 8
	var gapOpen [sampleCount]dataplane.SessionKey
	for i := range gapOpen {
		gapOpen[i] = dataplane.SessionKey{
			SrcIP: [4]byte{10, 0, 83, byte(i + 10)}, DstIP: [4]byte{172, 16, 83, 20},
			Protocol: 6, SrcPort: uint16(41000 + i), DstPort: 5201,
		}
	}
	stale := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 83, 99}, DstIP: [4]byte{172, 16, 83, 20},
		Protocol: 6, SrcPort: 41999, DstPort: 5201,
	}
	live := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5}

	senderDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	sender := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})

	receiverDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{stale: live}}
	receiver := NewSessionSync(":0", "10.0.0.3:4785", receiverDP)
	receiver.IsPrimaryFn = func() bool { return false }
	receiver.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	receiver.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})

	conn := newGapCaptureConn()
	conn.sessionTarget = sampleCount
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sender.sendLoop(ctx)

	sourceEntered := make(chan struct{})
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		close(sourceEntered)
		for _, key := range gapOpen {
			sender.QueueSessionV4(key, live)
		}
		return BulkSnapshot{}, nil
	}
	// This is the deterministic RED seam. On the fixed path doBulkSync already
	// owns bulkStartMu, so TryLock fails and the hook returns. On a revert that
	// removes the snapshot->BulkStart hold, TryLock succeeds. Release it before
	// waiting because a partially reverted sendLoop may still take the mutex;
	// the hook itself parks the bulk goroutine, so BulkStart cannot proceed
	// until the sample writes have crossed the wire. BulkEnd then
	// deterministically reconciles them away, proving the pre-fix failure
	// rather than relying on a scheduler race after a channel close.
	sender.testAfterBulkSnapshot = func() {
		if sender.bulkStartMu.TryLock() {
			sender.bulkStartMu.Unlock()
			<-conn.allSessionsWritten
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- sender.doBulkSync() }()
	<-sourceEntered
	if err := <-errCh; err != nil {
		t.Fatalf("doBulkSync returned error: %v", err)
	}

	// The watermark protocol requires every accepted pre-marker frame to be
	// delivered before BulkEnd. Wait for the complete start + sample + end set.
	types := make([]byte, 0, sampleCount+2)
	for len(types) < sampleCount+2 {
		select {
		case mt := <-conn.writes:
			types = append(types, mt)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for bulk/gap frames, got %d", len(types))
		}
	}
	start, end := -1, -1
	for i, mt := range types {
		switch mt {
		case syncMsgBulkStart:
			if start >= 0 {
				t.Fatalf("received multiple BulkStart frames: %v", types)
			}
			start = i
		case syncMsgBulkEnd:
			if end >= 0 {
				t.Fatalf("received multiple BulkEnd frames: %v", types)
			}
			end = i
		}
	}
	sessionsBetween := 0
	if start >= 0 && end > start {
		for i := start + 1; i < end; i++ {
			if types[i] == syncMsgSessionV4 {
				sessionsBetween++
			}
		}
	}

	// Replay before asserting ordering so the RED run proves the receiver
	// reached BulkEnd and deleted the gap sample, rather than failing only on
	// an ordering diagnostic.
	starts, ends := replayBulkFrames(t, receiver, conn.bytes())
	if starts != 1 || ends != 1 {
		t.Fatalf("expected one complete bulk window, got starts=%d ends=%d", starts, ends)
	}
	missing := 0
	for _, key := range gapOpen {
		if _, ok := receiverDP.v4sessions[key]; !ok {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("#10283: %d/%d gap-opened sessions were deleted at BulkEnd (frame types %v)", missing, sampleCount, types)
	}
	if start < 0 || end < 0 || start >= end || sessionsBetween != sampleCount {
		t.Fatalf("#10283: expected %d gap sessions strictly between BulkStart and BulkEnd, got start=%d end=%d sessions=%d in %v", sampleCount, start, end, sessionsBetween, types)
	}
	if _, ok := receiverDP.v4sessions[stale]; ok {
		t.Fatal("#10283: genuinely stale peer-owned session was retained")
	}
}
func TestWriteBarrierMessageParticipatesInBulkWatermark10283(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], 1)
	if err := sender.writeBarrierMessage(payload[:], 100*time.Millisecond); err != nil {
		t.Fatalf("writeBarrierMessage: %v", err)
	}
	sender.queuedFrameMu.Lock()
	accepted := sender.queuedFrameSeq
	sender.queuedFrameMu.Unlock()
	if accepted != 1 {
		t.Fatalf("barrier accepted watermark = %d, want 1", accepted)
	}
	select {
	case msg := <-sender.sendCh:
		if got := msg[4]; got != syncMsgBarrier {
			t.Fatalf("queued frame type = %d, want barrier %d", got, syncMsgBarrier)
		}
	default:
		t.Fatal("barrier was not queued")
	}
}

func TestBulkWatermarkFailureAbortsBeforeBulkEnd10283(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})
	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beforeWrite := make(chan struct{})
	sender.testBeforeQueuedWrite = func() {
		close(beforeWrite)
		cancel()
	}
	go sender.sendLoop(ctx)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 84, 1}, DstIP: [4]byte{172, 16, 84, 20},
		Protocol: 6, SrcPort: 42001, DstPort: 5201,
	}
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		sender.QueueSessionV4(key, dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5})
		return BulkSnapshot{}, nil
	}
	sender.pendingBulkAckEpoch.Store(91)
	errCh := make(chan error, 1)
	go func() { errCh <- sender.doBulkSync() }()
	select {
	case <-beforeWrite:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queued-write cancellation")
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("doBulkSync succeeded after queued-frame cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watermark abort")
	}
	for {
		select {
		case mt := <-conn.writes:
			if mt == syncMsgBulkEnd {
				t.Fatal("BulkEnd written after watermark failure")
			}
		default:
			epoch := sender.pendingBulkAckEpoch.Load()
			if epoch != 91 {
				t.Fatalf("watermark abort changed prior pending ack epoch to %d", epoch)
			}
			return
		}
	}
}
func TestOverlappingTableTruthBulksDoNotParkSender10283(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	sender.IsPrimaryFn = func() bool { return true }
	sender.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 5 }
	sender.SetZoneRGMap(map[uint16]int{5: 5})
	conn := newGapCaptureConn()
	sender.mu.Lock()
	sender.conn0 = conn
	sender.mu.Unlock()
	sender.stats.Connected.Store(true)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 85, 1}, DstIP: [4]byte{172, 16, 85, 20},
		Protocol: 6, SrcPort: 42002, DstPort: 5201,
	}
	var sourceMu sync.Mutex
	sourceCalls := 0
	secondSourceEntered := make(chan struct{})
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) {
		sourceMu.Lock()
		sourceCalls++
		call := sourceCalls
		sourceMu.Unlock()
		if call == 1 {
			sender.QueueSessionV4(key, dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 5})
		} else if call == 2 {
			// Reverted lock order enters the second source while holding
			// bulkStartMu, then waits for bulkSendMu. Fixed order waits for
			// bulkSendMu before invoking this source.
			close(secondSourceEntered)
		}
		return BulkSnapshot{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstErr := make(chan error, 1)
	go func() { firstErr <- sender.doBulkSync() }()
	select {
	case mt := <-conn.writes:
		if mt != syncMsgBulkStart {
			t.Fatalf("first bulk frame type = %d, want BulkStart", mt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first BulkStart")
	}
	secondErr := make(chan error, 1)
	go func() { secondErr <- sender.doBulkSync() }()
	select {
	case <-secondSourceEntered:
		// Reverted lock order: the second source ran while bulkStartMu was
		// held, before the second bulk parked on bulkSendMu.
	case <-time.After(100 * time.Millisecond):
		// Fixed lock order: the second bulk waits on bulkSendMu first, leaving
		// bulkStartMu available for the queued frame to drain.
	}
	go sender.sendLoop(ctx)
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first overlapping bulk: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first overlapping bulk did not complete")
	}
	select {
	case err := <-secondErr:
		if err != nil {
			t.Fatalf("second overlapping bulk: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second overlapping bulk did not complete")
	}
}
