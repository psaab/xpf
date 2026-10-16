package cluster

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// failoverResultConn14160 is a net.Conn whose Write always returns writeErr
// (nil means success) and whose Close is observable via closed.
type failoverResultConn14160 struct {
	writeErr error
	closed   atomic.Bool
}

func (c *failoverResultConn14160) Read([]byte) (int, error) { return 0, io.EOF }
func (c *failoverResultConn14160) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}
func (c *failoverResultConn14160) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *failoverResultConn14160) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4785}
}
func (c *failoverResultConn14160) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4785}
}
func (c *failoverResultConn14160) SetDeadline(time.Time) error      { return nil }
func (c *failoverResultConn14160) SetReadDeadline(time.Time) error  { return nil }
func (c *failoverResultConn14160) SetWriteDeadline(time.Time) error { return nil }

func newBatchResultSync14160(ack, fallback net.Conn) *SessionSync {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.outboundBulkAcked.Store(true)
	ss.mu.Lock()
	ss.conn0 = ack
	ss.conn1 = fallback
	ss.mu.Unlock()
	return ss
}

// TestSendFailoverBatchResultDisconnectsBrokenAckConn14160 pins #14160:
// when the active (ack) conn fails and the fallback conn delivers the batch
// result, the broken ack conn must still be disconnected, exactly as the
// single-result twin sendFailoverResult does. Pre-fix the batch path
// returned success without handleDisconnect(ackConn), leaving the broken
// conn installed as active so every later write paid a failed first attempt.
func TestSendFailoverBatchResultDisconnectsBrokenAckConn14160(t *testing.T) {
	ack := &failoverResultConn14160{writeErr: errors.New("ack conn write failed")}
	fallback := &failoverResultConn14160{}
	ss := newBatchResultSync14160(ack, fallback)

	ss.sendFailoverBatchResult(fallback, syncMsgFailoverBatchAck, []int{1, 2}, 42, failoverAckApplied, "")

	if !ack.closed.Load() {
		t.Fatal("broken ack conn was not disconnected after fallback success: " +
			"it stays installed as the active conn and every subsequent " +
			"failover/sync write pays a failed first attempt (#14160)")
	}
	ss.mu.Lock()
	remaining0, remaining1 := ss.conn0, ss.conn1
	ss.mu.Unlock()
	if remaining0 != nil {
		t.Fatal("broken ack conn still installed in conn0 after fallback success (#14160)")
	}
	if remaining1 != net.Conn(fallback) {
		t.Fatal("healthy fallback conn must survive the broken ack conn's disconnect")
	}
	if fallback.closed.Load() {
		t.Fatal("healthy fallback conn must not be closed when it delivered the result")
	}
	if got := ss.stats.Errors.Load(); got != 0 {
		t.Fatalf("stats.Errors = %d, want 0 when the fallback delivered the result", got)
	}
}

// TestSendFailoverBatchResultDualFailureDisconnectsBoth14160 pins the dual
// failure arm of #14160: when both the ack conn and the fallback conn fail,
// both must be disconnected. Pre-fix the `if ackConn != nil {...} else if
// conn != nil {...}` could never take the else-if (ackConn was forced
// non-nil above), so the fallback conn was never disconnected.
func TestSendFailoverBatchResultDualFailureDisconnectsBoth14160(t *testing.T) {
	ack := &failoverResultConn14160{writeErr: errors.New("ack conn write failed")}
	fallback := &failoverResultConn14160{writeErr: errors.New("fallback conn write failed")}
	ss := newBatchResultSync14160(ack, fallback)

	ss.sendFailoverBatchResult(fallback, syncMsgFailoverBatchAck, []int{1, 2}, 42, failoverAckApplied, "")

	if !ack.closed.Load() {
		t.Fatal("ack conn was not disconnected on dual failure (#14160)")
	}
	if !fallback.closed.Load() {
		t.Fatal("fallback conn was not disconnected on dual failure: the " +
			"unreachable else-if left it installed (#14160)")
	}
	ss.mu.Lock()
	remaining0, remaining1 := ss.conn0, ss.conn1
	ss.mu.Unlock()
	if remaining0 != nil || remaining1 != nil {
		t.Fatalf("both conns must be removed after dual failure, got conn0=%v conn1=%v", remaining0, remaining1)
	}
	if got := ss.stats.Errors.Load(); got != 1 {
		t.Fatalf("stats.Errors = %d, want 1 on dual failure", got)
	}
}

// TestSendFailoverBatchResultHealthyAckKeepsConns14160 is the control: a
// successful write on the ack conn disconnects nothing.
func TestSendFailoverBatchResultHealthyAckKeepsConns14160(t *testing.T) {
	ack := &failoverResultConn14160{}
	fallback := &failoverResultConn14160{}
	ss := newBatchResultSync14160(ack, fallback)

	ss.sendFailoverBatchResult(fallback, syncMsgFailoverBatchAck, []int{1}, 7, failoverAckApplied, "")

	if ack.closed.Load() || fallback.closed.Load() {
		t.Fatal("no conn may be disconnected when the ack write succeeds")
	}
	if got := ss.stats.Errors.Load(); got != 0 {
		t.Fatalf("stats.Errors = %d, want 0 on success", got)
	}
}

// TestSendFailoverResultDisconnectsBrokenAckConn14160 guards the twin the
// batch fix mirrors, so the two paths cannot drift apart again.
func TestSendFailoverResultDisconnectsBrokenAckConn14160(t *testing.T) {
	ack := &failoverResultConn14160{writeErr: errors.New("ack conn write failed")}
	fallback := &failoverResultConn14160{}
	ss := newBatchResultSync14160(ack, fallback)

	ss.sendFailoverResult(fallback, syncMsgFailoverAck, 1, 42, failoverAckApplied, "")

	if !ack.closed.Load() {
		t.Fatal("single-result path must disconnect the broken ack conn after fallback success")
	}
	if fallback.closed.Load() {
		t.Fatal("healthy fallback conn must not be closed when it delivered the result")
	}
}
