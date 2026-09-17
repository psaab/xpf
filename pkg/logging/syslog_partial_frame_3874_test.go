package logging

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// partialFrameConn models a stream conn whose FIRST Write truncates: the write
// deadline expires (or the peer resets) after only `prefix` bytes reach the
// wire, returning 0 < n < len(b) — a partial write. Subsequent Writes succeed
// fully (the transient slow-write has passed). It records every byte the
// "collector" received in order, plus write/close counts, so a test can assert
// that (a) the corrupt conn is torn down after a truncated frame and (b) no
// later frame concatenates onto the truncated one. When reset==true the first
// write's error is a non-timeout connection error instead of a deadline expiry.
type partialFrameConn struct {
	mu     sync.Mutex
	got    []byte
	writes int
	closes int
	prefix int
	reset  bool
}

func (c *partialFrameConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 1 {
		n := c.prefix
		if n > len(b) {
			n = len(b)
		}
		c.got = append(c.got, b[:n]...)
		if c.reset {
			return n, errors.New("connection reset by peer")
		}
		return n, os.ErrDeadlineExceeded
	}
	c.got = append(c.got, b...)
	return len(b), nil
}

func (c *partialFrameConn) Read(_ []byte) (int, error) { return 0, nil }
func (c *partialFrameConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	return nil
}
func (c *partialFrameConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *partialFrameConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *partialFrameConn) SetDeadline(_ time.Time) error      { return nil }
func (c *partialFrameConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *partialFrameConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *partialFrameConn) snapshot() (got []byte, writes, closes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.got...), c.writes, c.closes
}

// parseOctetFrame parses a single RFC 6587 octet-counted frame ("<len> <msg>")
// from the front of b, mimicking the collector's length parser. It returns the
// message bytes and the number of stream bytes the frame consumed, or an error
// if the declared length does not match the bytes present (a truncated frame —
// exactly the desync a partial write would cause if left on the wire).
func parseOctetFrame(b []byte) (msg []byte, consumed int, err error) {
	sp := bytes.IndexByte(b, ' ')
	if sp <= 0 {
		return nil, 0, errors.New("no octet-count prefix")
	}
	n, err := strconv.Atoi(string(b[:sp]))
	if err != nil {
		return nil, 0, err
	}
	body := b[sp+1:]
	if len(body) < n {
		return nil, 0, errors.New("truncated frame: declared length exceeds bytes present")
	}
	return body[:n], sp + 1 + n, nil
}

// TestPartialWriteTearsDownStreamToResync is the #3874 fix-on-revert proof.
//
// A stream write that returns 0 < n < len (a partial octet-counted frame on the
// wire) must tear the connection down so a later frame starts a fresh,
// correctly-counted stream — never concatenated onto the truncated one. The
// timeout also arms the #9911 cooldown, so the immediate next frame must
// fast-drop without dialing; after that cooldown expires, the fresh stream must
// resync. On a teardown revert that keeps the timeout cooldown, the third frame
// after cooldown expiry appends to the truncated first frame and desynchronizes
// the collector's length parser.
func TestPartialWriteTearsDownStreamToResync(t *testing.T) {
	now := time.Now()
	var dialCount int
	corrupt := &partialFrameConn{prefix: 5} // first frame truncated to 5 bytes
	fresh := &recordingBufConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.20:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      30 * time.Millisecond,
		reconnectCooldown: defaultReconnectCooldown,
		nowFn:             func() time.Time { return now },
		conn:              corrupt,
		dialFn: func() (net.Conn, error) {
			dialCount++
			return fresh, nil
		},
	}

	// Frame 1: partial write → truncated frame on the wire → the fix must close
	// the corrupt conn (dropped, not retried in place — #2287 preserved).
	if err := c.Send(SyslogInfo, "first message that truncates mid-frame"); err == nil {
		t.Fatal("expected the partial/timeout write to fail Send")
	}
	got1, writes1, closes1 := corrupt.snapshot()
	if closes1 != 1 {
		t.Fatalf("partial write must tear the corrupt conn down: closes=%d, want 1 "+
			"(#3874 desync-on-revert)", closes1)
	}
	if writes1 != 1 {
		t.Fatalf("timeout drop must not retry the write in place: writes=%d, want 1", writes1)
	}

	// Frame 2: the torn-down stream's timeout armed the #9911 cooldown. The
	// immediate next frame must fast-drop without attempting a reconnect.
	if err := c.Send(SyslogInfo, "second message during the cooldown"); !errors.Is(err, errReconnectCooldown) {
		t.Fatalf("expected the immediate second frame to hit reconnect cooldown, got %v", err)
	}
	if dialCount != 0 {
		t.Fatalf("cooldown must suppress reconnect after partial timeout: dials=%d, want 0", dialCount)
	}

	// Frame 3: after cooldown expiry, reconnect to a FRESH stream and write a
	// complete, correctly-counted frame there.
	now = now.Add(defaultReconnectCooldown + time.Nanosecond)
	if err := c.Send(SyslogInfo, "third message on the resynced stream"); err != nil {
		t.Fatalf("expected the third frame to land on a reconnected stream, got %v", err)
	}
	if dialCount != 1 {
		t.Fatalf("partial-write teardown must force one reconnect after cooldown: "+
			"dials=%d, want 1 (revert: 0 — frame 3 concatenates onto the truncated frame)", dialCount)
	}

	// The corrupt conn must have received ONLY the truncated first frame — no
	// later frame may concatenate onto it.
	if len(got1) != 5 {
		t.Fatalf("corrupt conn received %d bytes; want exactly the 5-byte truncated "+
			"prefix (revert: truncated frame 1 + full frame 3 concatenated → desync)", len(got1))
	}

	// The fresh stream must carry exactly one valid octet-counted frame with no
	// leftover — the collector reads it cleanly from the start.
	freshBytes := fresh.bytes()
	msg, consumed, err := parseOctetFrame(freshBytes)
	if err != nil {
		t.Fatalf("fresh stream is not a clean octet-counted frame: %v", err)
	}
	if consumed != len(freshBytes) {
		t.Fatalf("fresh stream has trailing bytes after one frame: consumed %d of %d",
			consumed, len(freshBytes))
	}
	if !bytes.Contains(msg, []byte("third message on the resynced stream")) {
		t.Fatalf("fresh frame does not carry the third message: %q", msg)
	}
}

// TestPartialWriteConnErrorTearsDown covers the non-timeout partial write (a
// peer reset mid-frame, 0<n<len with a connection error). The corrupt conn must
// still be torn down; the reconnect+retry path then lands the frame on a fresh
// stream. This guards the desync for the conn-error branch too, not just the
// deadline branch.
func TestPartialWriteConnErrorTearsDown(t *testing.T) {
	var dialCount int
	corrupt := &partialFrameConn{prefix: 3, reset: true}
	fresh := &recordingBufConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.21:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              corrupt,
		dialFn: func() (net.Conn, error) {
			dialCount++
			return fresh, nil
		},
	}

	// A non-timeout partial write reconnects+retries within the same Send.
	if err := c.Send(SyslogInfo, "reset mid-frame message"); err != nil {
		t.Fatalf("expected reconnect+retry to land the frame, got %v", err)
	}
	_, _, closes := corrupt.snapshot()
	if closes < 1 {
		t.Fatalf("partial conn-error write must tear the corrupt conn down: closes=%d", closes)
	}
	if dialCount != 1 {
		t.Fatalf("expected exactly one reconnect for the retry, got %d dials", dialCount)
	}
	msg, consumed, err := parseOctetFrame(fresh.bytes())
	if err != nil || consumed != len(fresh.bytes()) {
		t.Fatalf("retried frame is not a single clean octet-counted frame: err=%v consumed=%d/%d",
			err, consumed, len(fresh.bytes()))
	}
	if !bytes.Contains(msg, []byte("reset mid-frame message")) {
		t.Fatalf("retried frame does not carry the message: %q", msg)
	}
}

// TestCleanTimeoutDoesNotCloseConn asserts the #2287 clean-timeout property is
// preserved: a write that returns (0, deadline-exceeded) wrote nothing, cannot
// desync the collector, and must NOT close the conn (no reconnect, no dial).
// Only a PARTIAL write (0<n<len) tears the stream down. This is the boundary
// that keeps the #3874 fix from over-closing on every slow-server timeout.
func TestCleanTimeoutDoesNotCloseConn(t *testing.T) {
	var dialCount int
	conn := &closeCountingTimeoutConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.22:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      30 * time.Millisecond,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              conn,
		dialFn: func() (net.Conn, error) {
			dialCount++
			return &recordingBufConn{}, nil
		},
	}
	err := c.Send(SyslogInfo, "clean zero-byte timeout")
	if err == nil || !isTimeout(err) {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	if conn.closes != 0 {
		t.Fatalf("a clean 0-byte timeout must NOT close the conn (#2287): closes=%d", conn.closes)
	}
	if dialCount != 0 {
		t.Fatalf("a clean 0-byte timeout must NOT reconnect (#2287): dials=%d", dialCount)
	}
}

// TestPartialWriteNoReentrantDeadlock proves the #3874 close-under-lock path
// does not reintroduce the #2285/#2287 re-entrant deadlock. The failing client
// is wired as slog.Default() (a SyslogSlogHandler) AND used on the event path,
// so the drop warning routes back into the same client. A partial write closes
// the conn under s.mu; the emit-after-unlock + handler re-entrancy guard must
// keep Send returning promptly.
func TestPartialWriteNoReentrantDeadlock(t *testing.T) {
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.23:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      30 * time.Millisecond,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &partialFrameConn{prefix: 4},
		// After the corrupt conn is torn down, the drop-warning re-entry hits a
		// nil conn → reconnect; keep that dial failing so it drops (no infinite
		// fresh streams) and every path terminates.
		dialFn: func() (net.Conn, error) { return nil, errors.New("down") },
	}
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)

	done := make(chan struct{})
	go func() {
		_ = c.Send(SyslogInfo, "event-path message that truncates then drops")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not return — closing the partial-write conn under s.mu " +
			"reintroduced the #2285 re-entrant deadlock")
	}
}

// recordingBufConn is a net.Conn that appends every written byte to an in-order
// buffer and always succeeds. Used as the "fresh" reconnected stream so a test
// can parse the exact bytes the collector would receive after a resync.
type recordingBufConn struct {
	mu  sync.Mutex
	buf []byte
}

func (c *recordingBufConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, b...)
	return len(b), nil
}
func (c *recordingBufConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}
func (c *recordingBufConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *recordingBufConn) Close() error                       { return nil }
func (c *recordingBufConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *recordingBufConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *recordingBufConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordingBufConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordingBufConn) SetWriteDeadline(_ time.Time) error { return nil }

// closeCountingTimeoutConn returns (0, deadline-exceeded) on every Write — a
// clean 0-byte timeout — and counts Close calls so a test can assert the
// #3874 fix does NOT close on a clean timeout.
type closeCountingTimeoutConn struct {
	writes int
	closes int
}

func (c *closeCountingTimeoutConn) Write(_ []byte) (int, error) {
	c.writes++
	return 0, os.ErrDeadlineExceeded
}
func (c *closeCountingTimeoutConn) Read(_ []byte) (int, error) { return 0, nil }
func (c *closeCountingTimeoutConn) Close() error {
	c.closes++
	return nil
}
func (c *closeCountingTimeoutConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *closeCountingTimeoutConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *closeCountingTimeoutConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closeCountingTimeoutConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeCountingTimeoutConn) SetWriteDeadline(_ time.Time) error { return nil }
