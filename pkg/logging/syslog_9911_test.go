package logging

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingDeadlineConn9911 adds an attempt counter to the existing deadlineConn
// fixture. A reverted timeout gate still reaches Write, even though the write
// itself is bounded.
type countingDeadlineConn9911 struct {
	*deadlineConn
	attempts atomic.Int32
}

func (c *countingDeadlineConn9911) Write(b []byte) (int, error) {
	c.attempts.Add(1)
	return c.deadlineConn.Write(b)
}

func newTimeoutClient9911(t *testing.T) (*SyslogClient, *countingDeadlineConn9911) {
	t.Helper()
	conn := &countingDeadlineConn9911{deadlineConn: newDeadlineConn()}
	c := newTestStreamClient(t, func() (net.Conn, error) { return conn, nil })
	c.writeTimeout = 60 * time.Millisecond
	c.reconnectCooldown = time.Second
	c.dialFn = func() (net.Conn, error) { return nil, errors.New("still down") }
	t.Cleanup(func() { _ = c.Close() })
	return c, conn
}

// TestWriteTimeoutArmsCooldown9911 covers both text and binary stream sends.
// The first hung write pays the deadline and arms lastReconnectFailure. A
// second event inside the cooldown window must be dropped before Write, so it
// returns immediately and does not add another attempt. Removing either
// timeout arm or the pre-write cooldown gate makes this cell fail.
func TestWriteTimeoutArmsCooldown9911(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*SyslogClient) error
	}{
		{name: "text", send: func(c *SyslogClient) error {
			return c.Send(SyslogInfo, "hung collector")
		}},
		{name: "binary", send: func(c *SyslogClient) error {
			return c.SendBinary([]byte("hung collector"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, conn := newTimeoutClient9911(t)

			start := time.Now()
			if err := tc.send(c); err == nil {
				t.Fatal("first hung write returned nil")
			}
			if elapsed := time.Since(start); elapsed < c.writeTimeout/2 {
				t.Fatalf("first send did not pay its write deadline: %v", elapsed)
			}
			if c.lastReconnectFailure.IsZero() {
				t.Fatal("write timeout did not arm reconnect cooldown")
			}
			if got := conn.attempts.Load(); got != 1 {
				t.Fatalf("first send made %d write attempts, want 1", got)
			}

			start = time.Now()
			if err := tc.send(c); err == nil {
				t.Fatal("cooldown drop returned nil")
			}
			if elapsed := time.Since(start); elapsed >= c.writeTimeout/2 {
				t.Fatalf("second send paid another write deadline: %v", elapsed)
			}
			if got := conn.attempts.Load(); got != 1 {
				t.Fatalf("cooldown send made %d write attempts, want 1", got)
			}
			if got := c.DroppedCooldown(); got != 1 {
				t.Fatalf("DroppedCooldown = %d, want 1", got)
			}
		})
	}
}

// closeInterruptConn9911 models a socket Close that unblocks an in-flight
// Write, as net.TCPConn and tls.Conn do. On reverted code Close cannot reach
// this Close method because it waits on s.mu behind the parked Send.
type closeInterruptConn9911 struct {
	entered   chan struct{}
	released  chan struct{}
	closeSeen chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func newCloseInterruptConn9911() *closeInterruptConn9911 {
	return &closeInterruptConn9911{
		entered:   make(chan struct{}),
		released:  make(chan struct{}),
		closeSeen: make(chan struct{}),
	}
}

func (c *closeInterruptConn9911) Read(_ []byte) (int, error) { return 0, nil }
func (c *closeInterruptConn9911) Write(_ []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	<-c.released
	return 0, errors.New("socket closed")
}
func (c *closeInterruptConn9911) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeSeen)
		close(c.released)
	})
	return nil
}
func (c *closeInterruptConn9911) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *closeInterruptConn9911) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *closeInterruptConn9911) SetDeadline(_ time.Time) error      { return nil }
func (c *closeInterruptConn9911) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeInterruptConn9911) SetWriteDeadline(_ time.Time) error { return nil }

// closeNoReleaseConn9911 records Close but deliberately leaves Write parked.
// It proves Close's deferred join has a bound even for a custom connection
// whose Close does not interrupt an in-flight Write.
type closeNoReleaseConn9911 struct {
	*closeInterruptConn9911
}

func newCloseNoReleaseConn9911() *closeNoReleaseConn9911 {
	return &closeNoReleaseConn9911{closeInterruptConn9911: newCloseInterruptConn9911()}
}

func (c *closeNoReleaseConn9911) Close() error {
	c.closeOnce.Do(func() { close(c.closeSeen) })
	return nil
}

// TestCloseJoinIsBoundedWhenSocketDoesNotUnblock9911 pins the bounded deferred
// join separately from the socket-unblocks path above.
func TestCloseJoinIsBoundedWhenSocketDoesNotUnblock9911(t *testing.T) {
	conn := newCloseNoReleaseConn9911()
	c := newTestStreamClient(t, func() (net.Conn, error) { return conn, nil })

	sendDone := make(chan error, 1)
	go func() { sendDone <- c.Send(SyslogInfo, "unblock-resistant collector") }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("Send never entered the hung write")
	}

	closeDone := make(chan error, 1)
	start := time.Now()
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
		if elapsed := time.Since(start); elapsed >= 2*closeJoinTimeout {
			t.Fatalf("Close exceeded external join bound: %v", elapsed)
		}
	case <-time.After(2 * closeJoinTimeout):
		close(conn.released)
		<-sendDone
		<-closeDone
		t.Fatal("Close blocked behind a Write that ignored socket Close")
	}

	select {
	case <-conn.closeSeen:
	default:
		t.Fatal("Close returned without calling socket Close")
	}
	close(conn.released)
	select {
	case err := <-sendDone:
		if !errors.Is(err, errSyslogClientClosed) {
			t.Fatalf("interrupted Send error = %v, want closed-client error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("released Send did not return")
	}
}

// blackholeTLSRawConn9911 blocks raw writes after the TLS handshake. A normal
// tls.Conn.Close sends close_notify first, so the reverted Close remains parked
// until this fixture is externally released. The fixed closeSyslogConn closes
// the raw socket first.
type blackholeTLSRawConn9911 struct {
	net.Conn
	block         atomic.Bool
	closeSeen     chan struct{}
	unblock       chan struct{}
	closeOnce     sync.Once
	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func (c *blackholeTLSRawConn9911) Write(b []byte) (int, error) {
	if c.block.Load() {
		c.deadlineMu.Lock()
		deadline := c.writeDeadline
		c.deadlineMu.Unlock()
		if !deadline.IsZero() {
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			select {
			case <-c.unblock:
				return 0, errors.New("raw TLS socket closed")
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
		}
		<-c.unblock
		return 0, errors.New("raw TLS socket closed")
	}
	return c.Conn.Write(b)
}

func (c *blackholeTLSRawConn9911) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *blackholeTLSRawConn9911) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeSeen)
		close(c.unblock)
	})
	return c.Conn.Close()
}

func newBlackholeTLSClient9911(t *testing.T) (*tls.Conn, *blackholeTLSRawConn9911, func()) {
	t.Helper()
	cert, pool := generateTestCert(t)
	clientRaw, serverRaw := net.Pipe()
	raw := &blackholeTLSRawConn9911{
		Conn:      clientRaw,
		closeSeen: make(chan struct{}),
		unblock:   make(chan struct{}),
	}
	server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()

	client := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err := client.Handshake(); err != nil {
		_ = raw.Close()
		_ = server.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		_ = raw.Close()
		_ = server.Close()
		t.Fatalf("server TLS handshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, server) }()

	cleanup := func() {
		_ = raw.Close()
		_ = server.Close()
	}
	return client, raw, cleanup
}

// TestCloseTLSDoesNotBlockOnCloseNotify9911 proves a blackholed TLS
// collector cannot make Close wait on close_notify outside the join bound.
func TestCloseTLSDoesNotBlockOnCloseNotify9911(t *testing.T) {
	conn, raw, cleanup := newBlackholeTLSClient9911(t)
	defer cleanup()
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.2:6514",
		protocol:          "tls",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              conn,
	}
	raw.block.Store(true)

	closeDone := make(chan error, 1)
	start := time.Now()
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
		if elapsed := time.Since(start); elapsed >= 2*closeJoinTimeout {
			t.Fatalf("TLS Close exceeded external bound: %v", elapsed)
		}
	case <-time.After(2 * closeJoinTimeout):
		_ = raw.Close()
		<-closeDone
		t.Fatal("TLS Close blocked on close_notify")
	}
	select {
	case <-raw.closeSeen:
	default:
		t.Fatal("TLS Close returned without closing the raw socket")
	}
}

// TestTLSTimeoutDetachesCorruptConn9911 proves a timed-out TLS Write does not
// leave crypto/tls in its permanently-corrupt state for future sends.
func TestTLSTimeoutDetachesCorruptConn9911(t *testing.T) {
	conn, raw, cleanup := newBlackholeTLSClient9911(t)
	defer cleanup()
	fresh, freshRaw, freshCleanup := newBlackholeTLSClient9911(t)
	defer freshCleanup()
	raw.block.Store(true)

	var dials atomic.Int32
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.3:6514",
		protocol:          "tls",
		Facility:          FacilityLocal0,
		writeTimeout:      40 * time.Millisecond,
		reconnectCooldown: 40 * time.Millisecond,
		conn:              conn,
		dialFn: func() (net.Conn, error) {
			dials.Add(1)
			return fresh, nil
		},
	}
	defer c.Close()

	start := time.Now()
	if err := c.Send(SyslogInfo, "TLS timeout"); err == nil {
		t.Fatal("timed-out TLS send returned nil")
	}
	if elapsed := time.Since(start); elapsed < c.writeTimeout/2 {
		t.Fatalf("TLS send did not exercise its write deadline: %v", elapsed)
	}
	if c.loadConn() != nil {
		t.Fatal("timed-out TLS connection remained installed")
	}
	if c.lastReconnectFailure.IsZero() {
		t.Fatal("TLS timeout did not arm reconnect cooldown")
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("timed-out TLS send dialed %d times, want 0", got)
	}

	time.Sleep(c.reconnectCooldown + 10*time.Millisecond)
	freshRaw.block.Store(false)
	if err := c.Send(SyslogInfo, "TLS recovered"); err != nil {
		t.Fatalf("post-cooldown TLS send failed: %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("post-cooldown TLS send dialed %d times, want 1", got)
	}
}

// TestCloseDoesNotSerializeBehindHungWrite9911 proves Close marks the client
// and closes its socket without first acquiring the Send mutex. It must return
// within an external bound looser than the internal join timeout, and the
// interrupted Send must not dial or lose its drop accounting.
func TestCloseDoesNotSerializeBehindHungWrite9911(t *testing.T) {
	conn := newCloseInterruptConn9911()
	c := newTestStreamClient(t, func() (net.Conn, error) { return conn, nil })
	c.dialFn = func() (net.Conn, error) { return nil, errors.New("must not reconnect") }

	sendDone := make(chan error, 1)
	go func() { sendDone <- c.Send(SyslogInfo, "hung collector") }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("Send never entered the hung write")
	}

	closeDone := make(chan error, 1)
	start := time.Now()
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
		if elapsed := time.Since(start); elapsed >= 2*closeJoinTimeout {
			t.Fatalf("Close exceeded external join bound: %v", elapsed)
		}
	case <-time.After(2 * closeJoinTimeout):
		// Release the fixture so a reverted Close can finish before this test
		// exits, avoiding a leaked goroutine after reporting the regression.
		_ = conn.Close()
		<-sendDone
		<-closeDone
		t.Fatal("Close blocked behind a hung Send")
	}

	select {
	case <-conn.closeSeen:
	default:
		t.Fatal("Close returned without closing the active socket")
	}

	select {
	case err := <-sendDone:
		if !errors.Is(err, errSyslogClientClosed) {
			t.Fatalf("interrupted Send error = %v, want closed-client error", err)
		}
	case <-time.After(closeJoinTimeout):
		t.Fatal("interrupted Send did not release after Close")
	}
	if got := c.DroppedWrites(); got != 1 {
		t.Fatalf("DroppedWrites = %d, want 1 for the interrupted record", got)
	}
}

// TestCloseInterruptedBinaryAccountsDrop9911 covers the same interrupted-write
// accounting contract through SendBinary.
func TestCloseInterruptedBinaryAccountsDrop9911(t *testing.T) {
	conn := newCloseInterruptConn9911()
	c := newTestStreamClient(t, func() (net.Conn, error) { return conn, nil })

	sendDone := make(chan error, 1)
	go func() { sendDone <- c.SendBinary([]byte("hung collector")) }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("SendBinary never entered the hung write")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(2 * closeJoinTimeout):
		_ = conn.Close()
		<-sendDone
		<-closeDone
		t.Fatal("Close blocked behind a hung SendBinary")
	}

	select {
	case err := <-sendDone:
		if !errors.Is(err, errSyslogClientClosed) {
			t.Fatalf("interrupted SendBinary error = %v, want closed-client error", err)
		}
	case <-time.After(closeJoinTimeout):
		t.Fatal("interrupted SendBinary did not release after Close")
	}
	if got := c.DroppedWrites(); got != 1 {
		t.Fatalf("DroppedWrites = %d, want 1 for the interrupted binary record", got)
	}
}

// TestEventReaderSyslogCooldownDoesNotStall9911 drives ProcessRawEvent, the
// event-reader fanout path. After one timeout, a following event still reaches
// its callback and returns without another write deadline. Reverting the
// timeout arm/gate makes the second ProcessRawEvent pay writeTimeout again.
func TestEventReaderSyslogCooldownDoesNotStall9911(t *testing.T) {
	c, conn := newTimeoutClient9911(t)
	er := NewEventReader(nil, nil)
	er.SetSyslogClients([]*SyslogClient{c})
	var callbacks atomic.Int32
	er.AddCallback(func(EventRecord, []byte) { callbacks.Add(1) })

	raw := make([]byte, rawEventWireSize)
	raw[52] = eventTypePolicyDeny
	raw[53] = 6 // TCP
	raw[55] = addrFamilyInet

	start := time.Now()
	if !er.ProcessRawEvent(raw) {
		t.Fatal("first raw event was rejected")
	}
	if elapsed := time.Since(start); elapsed < c.writeTimeout/2 {
		t.Fatalf("first event did not exercise the hung write: %v", elapsed)
	}

	start = time.Now()
	if !er.ProcessRawEvent(raw) {
		t.Fatal("second raw event was rejected")
	}
	if elapsed := time.Since(start); elapsed >= c.writeTimeout/2 {
		t.Fatalf("event reader stalled on the second event: %v", elapsed)
	}
	if got := callbacks.Load(); got != 2 {
		t.Fatalf("callbacks = %d, want 2", got)
	}
	if got := conn.attempts.Load(); got != 1 {
		t.Fatalf("write attempts = %d, want 1", got)
	}
}
