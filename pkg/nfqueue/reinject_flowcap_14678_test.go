package nfqueue

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shortTempDir14678(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xpf14678-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestDrainReinjectCompletionsPreservesConnOnZeroByteTimeout is the
// #14678 regression: an idle 5ms read deadline expiry (zero bytes read)
// must not destroy the completion connection. On current code
// completion the Rust side writes into the socket buffer after the
// deadline expiry but before Go's Close is acked in Rust (ack_ready on
// write_all) yet destroyed unread in Go.
func TestDrainReinjectCompletionsPreservesConnOnZeroByteTimeout(t *testing.T) {
	completePath := filepath.Join(shortTempDir14678(t), "complete.sock")
	listener, err := net.Listen("unix", completePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConn := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			serverConn <- conn
		}
	}()

	client := &SocketReinjectSubmitter{completePath: completePath, timeout: 50 * time.Millisecond}
	defer client.Close()

	// Two consecutive idle drains must both return empty without error
	// and without destroying the connection.
	for i := 0; i < 2; i++ {
		completions, err := client.DrainReinjectCompletions(4)
		if err != nil || len(completions) != 0 {
			t.Fatalf("idle drain %d=(%v, %v), want empty, nil", i, completions, err)
		}
		if client.complete == nil {
			t.Fatalf("idle drain %d destroyed the completion connection (close-on-idle, #14678)", i)
		}
	}

	// A completion written after the idle drains (the deadline-expiry
	// race window) must be delivered on the same connection.
	conn := <-serverConn
	defer conn.Close()
	payload := completionPayload14678(101)
	if err := writeReinjectMessage(conn, reinjectMsgComplete, payload, time.Second); err != nil {
		t.Fatal(err)
	}
	completions, err := client.DrainReinjectCompletions(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != 1 || completions[0].RequestID != 101 {
		t.Fatalf("completions=%+v, want one completion id=101 delivered after idle drains", completions)
	}

	// A further idle drain keeps the connection as well.
	if _, err := client.DrainReinjectCompletions(4); err != nil {
		t.Fatal(err)
	}
	if client.complete == nil {
		t.Fatal("idle drain after delivery destroyed the completion connection")
	}
}

// TestDrainReinjectCompletionsPartialFrameTimeoutIsError is the #14678
// mid-frame cell: a timeout after partially consuming a frame is a
// desynchronised stream. It must close the connection AND surface an
// error so Poll fails pending work closed, instead of the current
// silent nil,nil which leaves pending entries to expire as uncertain.
func TestDrainReinjectCompletionsPartialFrameTimeoutIsError(t *testing.T) {
	completePath := filepath.Join(shortTempDir14678(t), "complete.sock")
	listener, err := net.Listen("unix", completePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Two bytes of a 4-byte header, then stall past the deadline.
		_, _ = conn.Write([]byte{0, 0})
		time.Sleep(50 * time.Millisecond)
	}()

	client := &SocketReinjectSubmitter{completePath: completePath, timeout: 5 * time.Millisecond}
	defer client.Close()
	completions, err := client.DrainReinjectCompletions(4)
	if err == nil {
		t.Fatalf("partial-frame timeout=(%v, nil), want a drain error (#14678: mid-frame timeout must fail pending, not masquerade as idle)", completions)
	}
	if len(completions) != 0 {
		t.Fatalf("completions=%+v, want none on partial-frame timeout", completions)
	}
	if client.complete != nil {
		t.Fatal("partial-frame timeout must close the desynchronised completion connection")
	}
	<-serverDone
}

// TestDrainReinjectCompletionsPartialHeaderThenCompletionRecovers
// covers the re-dial side of the partial-frame cell: after the error,
// the next drain dials a fresh connection and delivers completions.
func TestDrainReinjectCompletionsPartialRecovery14678(t *testing.T) {
	completePath := filepath.Join(shortTempDir14678(t), "complete.sock")
	listener, err := net.Listen("unix", completePath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte{0, 0})
		time.Sleep(30 * time.Millisecond)
		_ = conn.Close()
		conn2, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		_ = writeReinjectMessage(conn2, reinjectMsgComplete, completionPayload14678(77), time.Second)
		time.Sleep(20 * time.Millisecond)
	}()

	client := &SocketReinjectSubmitter{completePath: completePath, timeout: 5 * time.Millisecond}
	defer client.Close()
	if _, err := client.DrainReinjectCompletions(4); err == nil {
		t.Fatal("first (partial) drain: want error")
	}
	// Bounded retry: the second accept may lag the first close.
	deadline := time.Now().Add(2 * time.Second)
	for {
		completions, err := client.DrainReinjectCompletions(4)
		if err == nil && len(completions) == 1 && completions[0].RequestID == 77 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery drain=(%v, %v), want completion 77 on a fresh connection", completions, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEnqueueFlowLockedCapsPerFlowFrames14678 is the #14678 unbounded
// queue cell: frames behind a pending head accumulate in the per-flow
// FIFO with no bound. A configured cap must drop the excess frame
// (returned for terminal DROP accounting, like other drops) instead of
// appending forever.
func TestEnqueueFlowLockedCapsPerFlowFrames14678(t *testing.T) {
	// Default per-flow cap (512) must bound followers behind a pending
	// head. Drive past it: excess frames are returned for DROP.
	p := &CapturePipeline{
		flows:   make(map[string]*flowState),
		pending: make(map[uint64]*pendingReinject),
	}
	flowKey := "flow-14678"
	head := pipelineTestPacket(77, 2, 2, 7, 1)
	// Simulate a pending head: followers behind it must be capped.
	headFrame := CaptureFrame{Packet: head, FlowKey: flowKey}
	p.flows[flowKey] = &flowState{
		frames:  []CaptureFrame{headFrame},
		pending: &pendingReinject{frame: headFrame, lease: ReinjectLease{RequestID: 900}},
	}
	// Drive the FIFO to the default cap, then one past it. The head
	// occupies one slot; fill the rest, then the excess must drop.
	followers := defaultMaxFlowFrames
	for i := range followers - 1 {
		f := CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, uint32(2+i)), FlowKey: flowKey}
		if drops := p.enqueueFlowLocked(f); len(drops) != 0 {
			t.Fatalf("enqueue follower %d drops=%v, want queued (below cap)", i, drops)
		}
	}
	excess := CaptureFrame{Packet: pipelineTestPacket(77, 2, 2, 7, uint32(2+followers)), FlowKey: flowKey}
	drops := p.enqueueFlowLocked(excess)
	if len(drops) != 1 || drops[0].Packet != excess.Packet {
		t.Fatalf("enqueue over-cap drops=%v, want the excess frame returned for DROP (#14678: per-flow queue is unbounded)", drops)
	}
	if got := len(p.flows[flowKey].frames); got != followers {
		t.Fatalf("flow frames=%d, want capped at %d", got, followers)
	}
	if got := p.stats.FlowQueueDrops; got != 1 {
		t.Fatalf("FlowQueueDrops=%d, want 1", got)
	}
}

func completionPayload14678(id uint64) []byte {
	payload := make([]byte, 2+37)
	binary.BigEndian.PutUint16(payload[:2], 1)
	binary.BigEndian.PutUint64(payload[2:2+8], id)
	binary.BigEndian.PutUint64(payload[2+8:2+16], 9)  // permit epoch
	binary.BigEndian.PutUint64(payload[2+16:2+24], 1) // queue epoch
	binary.BigEndian.PutUint16(payload[2+24:2+26], 77)
	payload[2+26] = reinjectOriginInet
	payload[2+27] = reinjectOriginForward
	binary.BigEndian.PutUint32(payload[2+28:2+32], 7)
	payload[2+32] = 1 // written
	binary.BigEndian.PutUint32(payload[2+33:2+37], 64)
	return payload
}
