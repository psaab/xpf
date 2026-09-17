package logging

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dialCountConn is a net.Conn fake used as the target of a resurrecting
// reconnect dial; it always accepts writes so a post-fix-reverted reconnect
// (if one wrongly happened) would let Send "succeed" against it.
type dialCountConn struct{}

func (c *dialCountConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *dialCountConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *dialCountConn) Close() error                       { return nil }
func (c *dialCountConn) LocalAddr() net.Addr                { return ccAddr{} }
func (c *dialCountConn) RemoteAddr() net.Addr               { return ccAddr{} }
func (c *dialCountConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dialCountConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dialCountConn) SetWriteDeadline(_ time.Time) error { return nil }

// closedAwareConn is a net.Conn fake that faithfully reproduces the real
// net.Conn behavior this bug exploits: once Close() has been called on it,
// Write returns a "use of closed network connection"-style error instead of
// silently succeeding. A bare always-succeeds fake would mask the bug — the
// reverted Send would just "succeed" writing to the stale conn instead of
// hitting the write-error -> reconnect path that actually resurrects a
// connection in production (#4806).
type closedAwareConn struct {
	mu     sync.Mutex
	closed bool
}

func (c *closedAwareConn) Read(_ []byte) (int, error) { return 0, nil }
func (c *closedAwareConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("use of closed network connection")
	}
	return len(b), nil
}
func (c *closedAwareConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *closedAwareConn) LocalAddr() net.Addr                { return ccAddr{} }
func (c *closedAwareConn) RemoteAddr() net.Addr               { return ccAddr{} }
func (c *closedAwareConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closedAwareConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closedAwareConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestSendAfterCloseDoesNotResurrectConnection is the #4806 RED-on-revert
// guard. Before the fix, Close() closed s.conn without nilling it and
// without recording a closed flag. A Send() that runs AFTER Close() returns
// (the documented happens-after race: an event-dispatch goroutine that
// snapshotted the client slice just before ReplaceSyslogClients ran) would
// see the stale, non-nil (now-closed) s.conn, get a "use of closed network
// connection" write error from it, and — because Send treats any
// non-timeout stream write error as a signal to reconnect — dial a BRAND
// NEW connection to a target the caller believed was torn down. This test
// drives exactly that sequence (using a conn fake that actually errors on
// Write once closed, and a dialFn that counts dials) and asserts Send fails
// closed instead of resurrecting a connection.
func TestSendAfterCloseDoesNotResurrectConnection(t *testing.T) {
	firstConn := &closedAwareConn{}
	var dialed atomic.Int32
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.1:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              firstConn,
		dialFn: func() (net.Conn, error) {
			dialed.Add(1)
			return &dialCountConn{}, nil
		},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Send AFTER Close must fail immediately and must NOT dial a fresh
	// connection to resurrect the client.
	if err := c.Send(SyslogInfo, "post-close message"); err == nil {
		t.Fatalf("Send after Close returned nil error, want a closed-client error")
	}
	if got := dialed.Load(); got != 0 {
		t.Fatalf("Send after Close dialed %d times, want 0 (resurrected a closed connection, #4806)", got)
	}

	c.connMu.RLock()
	stillClosed := c.closed.Load()
	connAfterSend := c.conn
	c.connMu.RUnlock()
	if !stillClosed {
		t.Fatalf("closed flag was cleared by Send")
	}
	if connAfterSend != nil {
		t.Fatalf("conn is non-nil after Send following Close: %#v (resurrected)", connAfterSend)
	}
}

// TestSendBinaryAfterCloseDoesNotResurrectConnection mirrors the Send test
// above for SendBinary, the record used by the binary syslog transport.
func TestSendBinaryAfterCloseDoesNotResurrectConnection(t *testing.T) {
	firstConn := &closedAwareConn{}
	var dialed atomic.Int32
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.1:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              firstConn,
		dialFn: func() (net.Conn, error) {
			dialed.Add(1)
			return &dialCountConn{}, nil
		},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := c.SendBinary([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatalf("SendBinary after Close returned nil error, want a closed-client error")
	}
	if got := dialed.Load(); got != 0 {
		t.Fatalf("SendBinary after Close dialed %d times, want 0 (resurrected a closed connection, #4806)", got)
	}
}

// TestCloseNilsConn locks the second half of the #4806 fix: Close() must nil
// s.conn (not just close it), so any code that still checks `conn != nil`
// (rather than the closed flag) also observes the torn-down state.
func TestCloseNilsConn(t *testing.T) {
	c := clientWithConn(&closeCountConn{})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()
	closed := c.closed.Load()
	if conn != nil {
		t.Fatalf("s.conn is non-nil after Close: %#v", conn)
	}
	if !closed {
		t.Fatalf("s.closed is false after Close")
	}
}

// TestCloseIdempotent asserts a second Close() call is a harmless no-op (does
// not double-close a nil conn or panic) — Close() is called from teardown
// paths that may run more than once.
func TestCloseIdempotent(t *testing.T) {
	c := clientWithConn(&closeCountConn{})
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
