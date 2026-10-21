package logging

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withSlogDefault swaps slog.Default() for the duration of the test and
// restores it on cleanup. The deadlock under test (#2287) only manifests when
// slog.Default() routes back into the failing client, so the regression tests
// must install a real SyslogSlogHandler as the default.
//
// The stdlib `log` writer has to be restored too (#8597). slog.SetDefault
// re-points log.Default()'s output at a handlerWriter around the new handler —
// EXCEPT when the handler is slog's own internal defaultHandler, a case the
// stdlib skips precisely to avoid recursing into log.Output. Restoring `prev`
// hits that skip, so log.Default() keeps writing into the test's
// SyslogSlogHandler after the test ends. A later test's slog record then takes
// the stdlib log mutex, reaches the leftover handler, sends to its failing
// client, and the client's drop warning re-enters log.Output on the same
// goroutine — a deadlock on log's global mutex, in a test that never touched
// syslog. Capturing and restoring the writer and flags scopes the swap to the
// test that asked for it.
func withSlogDefault(t *testing.T, h slog.Handler) {
	t.Helper()
	prev := slog.Default()
	prevWriter, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		// #16083: delivery is async, so a handler's writer goroutine can
		// outlive the test that installed it. Once the default is restored,
		// a late record from that writer (e.g. a drop warning) would be
		// forwarded by the NEXT installed handler to its clients. Closing
		// this handler's clients retires its writer so no record crosses
		// the boundary. Tests with a plain text handler have no clients to
		// close. Close is idempotent for tests that also close.
		if sh, ok := h.(*SyslogSlogHandler); ok {
			sh.Close()
		}
	})
}

// TestSelfReferentialSendNoDeadlock is the #2287 fix-on-revert proof for the
// re-entrant deadlock.
//
// Setup mirrors production: slog.Default() is a SyslogSlogHandler whose client
// list contains a SINGLE failing client. The same client is then used on the
// "event path" (a direct Send). When its write fails, the pre-#2287 code called
// slog.Warn WHILE HOLDING s.mu; slog.Default() (this handler) synchronously
// called the same client's Send, which re-locked s.mu (sync.Mutex is
// non-reentrant, same goroutine) → self-deadlock.
//
// With the fix the drop warning is emitted AFTER s.mu is released, AND the
// handler's re-entrancy guard skips re-forwarding the warning, so Send returns
// promptly. Reverting EITHER fix (warn under the lock, or removing the guard)
// re-introduces the hang and trips the timeout below.
func TestSelfReferentialSendNoDeadlock(t *testing.T) {
	// A client whose writes always fail and whose reconnect dial always fails,
	// so every Send reaches noteDrop on a stream transport.
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.7:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &alwaysFailConn{},
		dialFn:            func() (net.Conn, error) { return nil, errors.New("down") },
	}

	// Install a real handler with this client as both the slog default and the
	// event-path target — the self-referential wiring that produced #2285's
	// deadlock. Discard the base handler so the test stays quiet.
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)

	done := make(chan struct{})
	go func() {
		// Event-path send → write fails → reconnect dial fails → noteDrop →
		// (fixed) warn AFTER unlock → Handle → guard skips re-forward.
		_ = c.Send(SyslogInfo, "event-path message that drops")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not return — re-entrant deadlock regression (#2287): " +
			"the drop warning is being emitted under s.mu or the handler " +
			"re-entrancy guard is missing")
	}
}

// TestSlogWarnViaHandlerNoDeadlock asserts the pure slog path is also safe: a
// slog.Warn routed through a SyslogSlogHandler whose only client is failing
// must return promptly. The first forward triggers the client's drop warning,
// which slog routes back into the handler ON THE SAME GOROUTINE; the
// re-entrancy guard must short-circuit it. Reverting the guard makes the second
// Handle re-forward, and with the warn-after-unlock fix the recursion is capped
// by the ≤1/s gate, but the guard is the belt-and-suspenders that keeps a
// single record from ever re-entering a client's Send.
func TestSlogWarnViaHandlerNoDeadlock(t *testing.T) {
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.8:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &alwaysFailConn{},
		dialFn:            func() (net.Conn, error) { return nil, errors.New("down") },
	}
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)

	done := make(chan struct{})
	go func() {
		slog.Warn("trigger forward to a failing client")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("slog.Warn through SyslogSlogHandler did not return — " +
			"re-entrancy regression (#2287)")
	}
}

// TestHandleReentrancyGuardSkipsNestedForward verifies the writer-scoped
// guard (#2287 mechanism, narrowed by #16083): a fake client records each
// forward; the FIRST forward emits a nested slog.Warn (simulating a drop
// warning) on the writer goroutine. The guard must prevent the nested
// record from being re-queued to this client, so exactly ONE forward
// occurs per top-level record (no unbounded queue growth, no nested
// forward). The nested record still reaches the base handler.
func TestHandleReentrancyGuardSkipsNestedForward(t *testing.T) {
	var forwards int32
	rec := &recordingConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.9:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              rec,
	}
	// Each successful write triggers a nested slog.Warn on the same goroutine.
	rec.onWrite = func() {
		if atomic.AddInt32(&forwards, 1) == 1 {
			slog.Warn("nested warn from inside a forward")
		}
	}

	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)
	slog.Info("top-level record")

	// The nested Warn runs synchronously inside the top-level Write (the
	// hook fires mid-Write), so by the time the write count lands the
	// nested record has already been dropped on the writer goroutine.
	// Waiting on the write count — not the hook count — is therefore the
	// settled signal; the settle below covers a (buggy) re-queue.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&rec.writes) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := atomic.LoadInt32(&rec.writes); n == 0 {
		t.Fatalf("top-level record was never written (forwards=%d dropped=%d)", atomic.LoadInt32(&forwards), c.DroppedWrites())
	}
	// The nested Warn is enqueued-then-dropped on the writer goroutine; give
	// a (buggy) re-queue a chance to produce a second forward before asserting.
	time.Sleep(50 * time.Millisecond)
	// Without the guard, the nested Warn would forward a SECOND record to the
	// client (forwards == 2+). With the guard, only the top-level record is
	// forwarded (forwards == 1).
	if got := atomic.LoadInt32(&forwards); got != 1 {
		t.Fatalf("expected exactly 1 forward (guard skips the nested record), got %d (writes=%d dropped=%d)", got, atomic.LoadInt32(&rec.writes), c.DroppedWrites())
	}
	// The writer must not be wedged by the dropped nested record: a second
	// top-level record is still delivered.
	slog.Info("second top-level record")
	deadline = time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&forwards) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadInt32(&forwards); got != 2 {
		t.Fatalf("second top-level record was not delivered after the nested drop, forwards=%d", got)
	}
}

// TestConcurrentHandleNotFalselySkipped guards against a per-handler-flag
// implementation that would falsely skip forwards from DIFFERENT goroutines. N
// goroutines each log once; every record must be forwarded (the guard is
// per-goroutine, not per-handler).
func TestConcurrentHandleNotFalselySkipped(t *testing.T) {
	var forwards int32
	rec := &recordingConn{onWrite: func() { atomic.AddInt32(&forwards, 1) }}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.10:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              rec,
	}
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})
	withSlogDefault(t, h)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			slog.Info("concurrent record")
		}()
	}
	close(start)
	wg.Wait()

	// Delivery is now async (#16083): wait for the writer to drain all n.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&forwards) < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadInt32(&forwards); int(got) != n {
		t.Fatalf("expected %d forwards (no false per-handler skip), got %d", n, got)
	}
}

// TestStreamTimeoutDropsWithoutReconnect is the #2287 fix-on-revert proof for
// the 2x-bound fix. A write that fails with a TIMEOUT (deadline expiry) must be
// dropped immediately — NO reconnect, NO dial, NO retry — so the worst-case
// stall stays one writeTimeout, not ~2x plus a dial. Reverting the timeout
// branch (treating a timeout like any error) makes Send reconnect+retry, which
// dials → this test sees a non-zero dial count and a second write attempt.
func TestStreamTimeoutDropsWithoutReconnect(t *testing.T) {
	var dialCount int32
	conn := &timeoutConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.11:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      30 * time.Millisecond,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              conn,
		dialFn: func() (net.Conn, error) {
			atomic.AddInt32(&dialCount, 1)
			return &timeoutConn{}, nil
		},
	}

	start := time.Now()
	err := c.Send(SyslogInfo, "to a server that times out on write")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Send to fail on a write timeout")
	}
	if !isTimeout(err) {
		t.Fatalf("expected the returned error to be a timeout, got %v", err)
	}
	// A pure timeout must NOT reconnect+retry.
	if d := atomic.LoadInt32(&dialCount); d != 0 {
		t.Fatalf("timeout drop must not reconnect: expected 0 dials, got %d "+
			"(2x-bound regression #2287)", d)
	}
	if n := atomic.LoadInt32(&conn.writes); n != 1 {
		t.Fatalf("timeout drop must not retry the write: expected 1 write, got %d", n)
	}
	// The single write was bounded by writeTimeout; well under a 2x window.
	if elapsed > time.Second {
		t.Fatalf("Send took %v — a timeout drop should be ~writeTimeout, not retried", elapsed)
	}
	// Counted as a write drop (not a dial drop).
	if c.DroppedWrites() != 1 || c.DroppedDials() != 0 {
		t.Fatalf("timeout should count as a write drop: writes=%d dials=%d",
			c.DroppedWrites(), c.DroppedDials())
	}
}

// TestConnErrorReconnects asserts the fix did NOT break the legit
// reconnect-on-connection-error path: a NON-timeout write error (broken pipe)
// still reconnects+retries. With a dial that succeeds and a fresh healthy conn,
// the retried write lands and Send succeeds with exactly one dial.
func TestConnErrorReconnects(t *testing.T) {
	var dialCount int32
	healthy := &recordingConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.12:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &alwaysFailConn{}, // non-timeout broken-pipe error
		dialFn: func() (net.Conn, error) {
			atomic.AddInt32(&dialCount, 1)
			return healthy, nil
		},
	}

	if err := c.Send(SyslogInfo, "conn error should reconnect"); err != nil {
		t.Fatalf("expected reconnect+retry to succeed on a conn error, got %v", err)
	}
	if d := atomic.LoadInt32(&dialCount); d != 1 {
		t.Fatalf("expected exactly 1 reconnect dial on a conn error, got %d", d)
	}
	if n := atomic.LoadInt32(&healthy.writes); n != 1 {
		t.Fatalf("expected the retried write to land on the fresh conn, got %d writes", n)
	}
	if c.DroppedWrites() != 0 || c.DroppedDials() != 0 || c.DroppedCooldown() != 0 {
		t.Fatalf("successful reconnect must not count a drop: w=%d d=%d c=%d",
			c.DroppedWrites(), c.DroppedDials(), c.DroppedCooldown())
	}
}

// TestDialFailureCountsAsDialDrop asserts a post-write-failure reconnect whose
// DIAL fails is counted by DroppedDials, not DroppedWrites (the #2287 counter
// split / doc fix).
func TestDialFailureCountsAsDialDrop(t *testing.T) {
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.13:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              &alwaysFailConn{}, // non-timeout error → reconnect
		dialFn:            func() (net.Conn, error) { return nil, errors.New("refused") },
	}
	_ = c.Send(SyslogInfo, "dial fails")
	if c.DroppedDials() != 1 {
		t.Fatalf("expected 1 dial drop, got %d", c.DroppedDials())
	}
	if c.DroppedWrites() != 0 {
		t.Fatalf("a dial failure must not be counted as a write drop, got %d",
			c.DroppedWrites())
	}
}

// TestHandleNoClientsFastPath16083 pins the #2295 fast-path contract,
// narrowed by #16083: with NO syslog clients configured (the default
// until syslog config applies), Handle is a pure base forward — the
// per-client writer check (which pays a runtime.Stack) is only reached
// with a client present, so the no-client path cannot regress to paying
// it per record.
func TestHandleNoClientsFastPath16083(t *testing.T) {
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	// No SetClients: the zero-client default.
	for range 100 {
		if err := h.Handle(context.Background(), slog.Record{}); err != nil {
			t.Fatalf("Handle returned an error on the no-client path: %v", err)
		}
	}
}

// TestHandleWithClientsQueuesRecord16083 pins the #16083 cutover: a record
// handled with a client present is QUEUED and written by the writer
// goroutine, not synchronously written by Handle.
func TestHandleWithClientsQueuesRecord16083(t *testing.T) {
	rec := &recordingConn{}
	c := &SyslogClient{
		hostname:          "test",
		remoteAddr:        "203.0.113.14:514",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
		conn:              rec,
	}
	h := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	h.SetClients([]*SyslogClient{c})

	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelInfo, "queued", 0)); err != nil {
		t.Fatalf("Handle returned an error with a client present: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&rec.writes) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := atomic.LoadInt32(&rec.writes); n != 1 {
		t.Fatalf("expected the queued record to be written by the writer, got %d writes", n)
	}
}

// recordingConn is a net.Conn whose Write succeeds and counts, optionally
// running an onWrite hook (used to inject a nested slog call).
type recordingConn struct {
	writes  int32
	onWrite func()
}

func (c *recordingConn) Write(b []byte) (int, error) {
	atomic.AddInt32(&c.writes, 1)
	if c.onWrite != nil {
		c.onWrite()
	}
	return len(b), nil
}
func (c *recordingConn) Read(_ []byte) (int, error)        { return 0, nil }
func (c *recordingConn) Close() error                      { return nil }
func (c *recordingConn) LocalAddr() net.Addr               { return dummyAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr              { return dummyAddr{} }
func (c *recordingConn) SetDeadline(_ time.Time) error     { return nil }
func (c *recordingConn) SetReadDeadline(_ time.Time) error { return nil }
func (c *recordingConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// timeoutConn is a net.Conn whose Write always returns a timeout error
// (os.ErrDeadlineExceeded satisfies net.Error with Timeout()==true), modelling
// a SetWriteDeadline expiry against a hung server. It counts write attempts.
type timeoutConn struct {
	writes int32
}

func (c *timeoutConn) Write(_ []byte) (int, error) {
	atomic.AddInt32(&c.writes, 1)
	return 0, os.ErrDeadlineExceeded
}
func (c *timeoutConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *timeoutConn) Close() error                       { return nil }
func (c *timeoutConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *timeoutConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *timeoutConn) SetDeadline(_ time.Time) error      { return nil }
func (c *timeoutConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *timeoutConn) SetWriteDeadline(_ time.Time) error { return nil }
