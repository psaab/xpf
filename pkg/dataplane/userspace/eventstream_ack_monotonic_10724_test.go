package userspace

import (
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestEventStreamAckWatermarkConcurrentMonotonic10724 is a RED cell for the
// bare-Store regression: a low-sequence sender runs concurrently with a
// high-sequence advance, then makes one final stale attempt. A Store rewinds
// the watermark; the CAS-monotonic ACK path leaves the maximum intact. Run with
// -race as well as normally.
func TestEventStreamAckWatermarkConcurrentMonotonic10724(t *testing.T) {
	const maxSeq = uint64(100_000)
	var es EventStream
	var lowCalls atomic.Uint64
	start := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for {
			select {
			case <-stop:
				es.recordAck(1)
				return
			default:
				es.recordAck(1)
				lowCalls.Add(1)
			}
		}
	}()
	close(start)
	for lowCalls.Load() < 100 {
		runtime.Gosched()
	}
	for seq := uint64(2); seq <= maxSeq; seq++ {
		es.recordAck(seq)
		if seq%64 == 0 {
			runtime.Gosched()
		}
	}
	close(stop)
	<-done
	if got := es.lastAckSeq.Load(); got != maxSeq {
		t.Fatalf("lastAckSeq regressed to %d after concurrent stale ACK, want %d", got, maxSeq)
	}
}

// TestSendAckIfNeededAdvancesWatermark10724 binds the monotonic watermark to
// the actual ACK-frame send path, not only to recordAck's primitive.
func TestSendAckIfNeededAdvancesWatermark10724(t *testing.T) {
	reader, writer := net.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	es := NewEventStream("")
	es.mu.Lock()
	es.conn = writer
	es.mu.Unlock()
	es.lastAppliedSeq.Store(42)

	type result struct {
		seq uint64
		err error
	}
	read := make(chan result, 1)
	go func() {
		var frame [EventFrameHeaderSize]byte
		_, err := io.ReadFull(reader, frame[:])
		read <- result{seq: binary.LittleEndian.Uint64(frame[8:16]), err: err}
	}()
	es.sendAckIfNeeded()

	select {
	case got := <-read:
		if got.err != nil {
			t.Fatalf("reading ACK frame: %v", got.err)
		}
		if got.seq != 42 {
			t.Fatalf("ACK frame sequence = %d, want 42", got.seq)
		}
	case <-time.After(time.Second):
		t.Fatal("sendAckIfNeeded did not write an ACK frame")
	}
	if got := es.LastAckedSequence(); got != 42 {
		t.Fatalf("lastAckSeq = %d after successful ACK, want 42", got)
	}
}
