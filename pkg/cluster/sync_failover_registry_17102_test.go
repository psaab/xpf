package cluster

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// #17102: the four hand-copied failover request/commit skeletons collapse
// into one registry (failoverWaiterRegistry) plus failoverRoundTrip and one
// ack-frame sender (sendFailoverAckFrame). These tests pin the structural
// acceptance (exactly one failover timer, one non-test waiter-map type)
// and the unified reqID-on-error contract for single and batch.

// failoverFailConn17102 fails every Write with writeErr and records Close.
type failoverFailConn17102 struct {
	writeErr error
	closed   bool
}

func (c *failoverFailConn17102) Read([]byte) (int, error) { return 0, io.EOF }
func (c *failoverFailConn17102) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}
func (c *failoverFailConn17102) Close() error {
	c.closed = true
	return nil
}
func (c *failoverFailConn17102) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4785}
}
func (c *failoverFailConn17102) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4785}
}
func (c *failoverFailConn17102) SetDeadline(time.Time) error      { return nil }
func (c *failoverFailConn17102) SetReadDeadline(time.Time) error  { return nil }
func (c *failoverFailConn17102) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*failoverFailConn17102)(nil)

func TestFailoverRegistrySingleTimer17102(t *testing.T) {
	srcFailover := readClusterSource(t, "sync_failover.go")
	if n := strings.Count(srcFailover, "time.NewTimer(failoverAckTimeout)"); n != 1 {
		t.Fatalf("sync_failover.go contains %d failover timers, want exactly 1 (#17102)", n)
	}
	// The single registry type must be the only non-test waiter-map
	// declaration for failover waiters.
	if !strings.Contains(srcFailover, "type failoverWaiterRegistry map[failoverWaitKey]failoverWaiter") {
		t.Fatal("failoverWaiterRegistry single-map declaration missing (#17102)")
	}
	for _, srcName := range []string{"sync_failover.go", "sync.go", "sync_conn.go"} {
		src := readClusterSource(t, srcName)
		for _, banned := range []string{
			"map[int]failoverWaiter",
			"map[string]failoverWaiter",
			"completeFailoverBatchWait",
			"completeFailoverCommitWait",
			"completeFailoverBatchCommitWait",
			"sendFailoverBatchResult",
			"sendFailoverResult(",
		} {
			if strings.Contains(src, banned) {
				t.Fatalf("%s still contains %q: the four-copy skeleton was not merged (#17102)", srcName, banned)
			}
		}
	}
}

// TestFailoverRoundTripReqIDOnErrorContract17102 pins the same
// reqID-on-error contract for single and batch: local rejection and send
// failure return reqID 0, a peer ack failure surfaces the error with the
// allocated reqID bound to it (#16592), and a disconnect drain delivers
// the disconnected ack through the unified registry.
func TestFailoverRoundTripReqIDOnErrorContract17102(t *testing.T) {
	cases := []struct {
		name string
		call func(ss *SessionSync) (uint64, error)
	}{
		{"single", func(ss *SessionSync) (uint64, error) { return ss.SendFailover(3) }},
		{"batch", func(ss *SessionSync) (uint64, error) { return ss.SendFailoverBatch([]int{1, 2}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_not_connected", func(t *testing.T) {
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			reqID, err := tc.call(ss)
			if err == nil || !strings.Contains(err.Error(), "peer not connected") {
				t.Fatalf("err = %v, want peer-not-connected", err)
			}
			if reqID != 0 {
				t.Fatalf("reqID = %d, want 0 on local rejection", reqID)
			}
		})
		t.Run(tc.name+"_send_failure_reqid_zero", func(t *testing.T) {
			broken := &failoverFailConn17102{writeErr: errors.New("write boom")}
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			ss.outboundBulkAcked.Store(true)
			ss.mu.Lock()
			ss.conn0 = broken
			ss.stats.Connected.Store(true)
			ss.mu.Unlock()
			reqID, err := tc.call(ss)
			if err == nil || !strings.Contains(err.Error(), "failed to send") {
				t.Fatalf("err = %v, want failed-to-send", err)
			}
			if reqID != 0 {
				t.Fatalf("reqID = %d, want 0 on send failure (same single/batch contract, #17102)", reqID)
			}
		})
		t.Run(tc.name+"_already_in_flight", func(t *testing.T) {
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			ss.mu.Lock()
			ss.conn0 = local
			ss.stats.Connected.Store(true)
			ss.mu.Unlock()
			// Occupy the RG set through the registry: request phase, both
			// single and batch shapes collide on the overlapping set.
			ch := make(chan failoverAck, 1)
			ss.registerFailoverWaitForTest(failoverWaitRequest, []int{1, 3}, 99, ch)
			_, err := tc.call(ss)
			if err == nil || !strings.Contains(err.Error(), "already in flight") {
				t.Fatalf("err = %v, want already-in-flight via unified registry", err)
			}
		})
		t.Run(tc.name+"_disconnect_drains_registry", func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			ss.outboundBulkAcked.Store(true)
			ss.mu.Lock()
			ss.conn0 = local
			ss.stats.Connected.Store(true)
			ss.mu.Unlock()
			// net.Pipe is synchronous: drain the request frame so the
			// sender finishes its write and parks on the ack.
			go io.Copy(io.Discard, peer) //nolint:errcheck
			done := make(chan error, 1)
			go func() {
				_, err := tc.call(ss)
				done <- err
			}()
			// Let the waiter register before disconnecting.
			deadline := time.Now().Add(2 * time.Second)
			for {
				ss.failoverWaitMu.Lock()
				n := len(ss.failoverWaiters)
				ss.failoverWaitMu.Unlock()
				if n > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("waiter never registered")
				}
				time.Sleep(time.Millisecond)
			}
			ss.handleDisconnect(local)
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "peer disconnected") {
					t.Fatalf("err = %v, want peer-disconnected via drainAllFailoverWaits", err)
				}
			case <-time.After(time.Second):
				t.Fatal("waiter not released by disconnect drain")
			}
		})
	}
}

// captureConn17102 records the last frame written to it.
type captureConn17102 struct {
	mu     sync.Mutex
	frame  []byte
	closed bool
}

func (c *captureConn17102) Read([]byte) (int, error) { return 0, io.EOF }
func (c *captureConn17102) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frame = append([]byte(nil), b...)
	return len(b), nil
}
func (c *captureConn17102) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *captureConn17102) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4785}
}
func (c *captureConn17102) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4785}
}
func (c *captureConn17102) SetDeadline(time.Time) error      { return nil }
func (c *captureConn17102) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn17102) SetWriteDeadline(time.Time) error { return nil }
func (c *captureConn17102) payload() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.frame) <= syncHeaderSize {
		return nil
	}
	return append([]byte(nil), c.frame[syncHeaderSize:]...)
}
func (c *captureConn17102) msgType() uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.frame) < 5 {
		return 0
	}
	return c.frame[4]
}

var _ net.Conn = (*captureConn17102)(nil)

// TestSendFailoverAckFrameOneRGBatchAckDecodes17102 pins fold B1: a batch
// ack (msgType = syncMsgFailoverBatchAck / BatchCommitAck) carrying exactly
// one RG must be batch-encoded. Before the fix sendFailoverAckFrame keyed
// single-vs-batch on len(rgIDs)==1, emitted the 10-byte single layout, and
// the peer's decodeFailoverBatchAckPayload rejected it ("message too
// short"), so the 1-RG batch waiter burned the full 20s failoverAckTimeout.
// This cell DECODES the emitted payload with the production batch decoder.
func TestSendFailoverAckFrameOneRGBatchAckDecodes17102(t *testing.T) {
	for _, msgType := range []uint8{syncMsgFailoverBatchAck, syncMsgFailoverBatchCommitAck} {
		ack := &captureConn17102{}
		fallback := &captureConn17102{}
		ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
		ss.outboundBulkAcked.Store(true)
		ss.mu.Lock()
		ss.conn0 = ack
		ss.conn1 = fallback
		ss.mu.Unlock()
		ss.sendFailoverAckFrame(fallback, msgType, []int{7}, 42, failoverAckApplied, "")
		if got := ack.msgType(); got != msgType {
			t.Fatalf("msgType=%d: emitted frame type = %d, want %d", msgType, got, msgType)
		}
		payload := ack.payload()
		if len(payload) == 0 {
			t.Fatalf("msgType=%d: no ack frame captured on active conn", msgType)
		}
		ids, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			t.Fatalf("msgType=%d: 1-RG batch ack payload %v fails batch decode: %v (B1: single-encoded batch ack, waiter would burn 20s)", msgType, payload, err)
		}
		if len(ids) != 1 || ids[0] != 7 || status != failoverAckApplied || reqID != 42 || detail != "" {
			t.Fatalf("msgType=%d: decoded ids=%v status=%d reqID=%d detail=%q, want [7] applied 42 \"\"", msgType, ids, status, reqID, detail)
		}
	}
	ack := &captureConn17102{}
	fallback := &captureConn17102{}
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.outboundBulkAcked.Store(true)
	ss.mu.Lock()
	ss.conn0 = ack
	ss.conn1 = fallback
	ss.mu.Unlock()
	ss.sendFailoverAckFrame(fallback, syncMsgFailoverAck, []int{7}, 42, failoverAckApplied, "")
	payload := ack.payload()
	if len(payload) < 10 || payload[0] != 7 || payload[1] != failoverAckApplied || binary.LittleEndian.Uint64(payload[2:10]) != 42 {
		t.Fatalf("single ack payload = %v, want single layout rg=7 status=applied reqID=42", payload)
	}
}

// TestFailoverRoundTripSendFailureDisconnectsUsedConn17102 pins fold M1:
// on send failure the wrapper disconnects the conn failoverRoundTrip
// actually wrote to (UsedConn), returned in the outcome, not a conn
// re-resolved by the wrapper before the round trip.
func TestFailoverRoundTripSendFailureDisconnectsUsedConn17102(t *testing.T) {
	broken := &failoverFailConn17102{writeErr: errors.New("write boom")}
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.outboundBulkAcked.Store(true)
	ss.mu.Lock()
	ss.conn0 = broken
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()
	if _, err := ss.SendFailover(3); err == nil || !strings.Contains(err.Error(), "failed to send") {
		t.Fatalf("err = %v, want failed-to-send", err)
	}
	if !broken.closed {
		t.Fatal("send failure did not disconnect the used (broken) conn via UsedConn (M1)")
	}
	ss.mu.Lock()
	remaining := ss.conn0
	ss.mu.Unlock()
	if remaining != nil {
		t.Fatal("broken used conn still installed after send-failure disconnect (M1)")
	}
}
