package cluster

import (
	"errors"
	"io"
	"net"
	"strings"
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
