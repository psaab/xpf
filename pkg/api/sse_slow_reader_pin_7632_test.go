package api

// sse_slow_reader_pin_7632_test.go — #7632.
//
// The SSE sibling of #6809. An event stream writes straight to the
// ResponseWriter and flushes, and http.Server runs with WriteTimeout 0
// process-wide so these long-lived streams are not severed — so a subscriber
// that stays CONNECTED and stops reading fills the socket buffers and parks the
// handler goroutine in Write indefinitely, holding a subscriber slot with it.
//
// The fixture is the one #6809 built (stalledConn6809 / stalledListener6809): a
// net.Conn that accepts a fixed prefix of bytes and then parks the writer
// exactly as a full send buffer does, until the write deadline or forever if
// none is armed. Reused rather than rebuilt — it is the deterministic
// instrument for this whole class.
//
// The SSE-SPECIFIC property is the idle cell below. An event feed on a quiet
// firewall is SUPPOSED to sit silent for long stretches, so an elapsed budget
// would sever the healthy case; a per-write deadline bounds a write that has
// BEGUN and says nothing about the gap between events. That difference is why
// this is a sibling and not a copy of #6809.

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// startStalledSSEServer7632 serves an SSE handler over a listener whose conns
// stop accepting bytes after budget, and reports when the handler returns.
func startStalledSSEServer7632(
	t *testing.T,
	h func(*Server, http.ResponseWriter, *http.Request),
	budget int,
	deadlineUnsupported bool,
) (addr string, buf *logging.EventBuffer, done <-chan struct{}, sl *stalledListener6809, cleanup func()) {
	t.Helper()
	buf = logging.NewEventBuffer(1024)
	srv := &Server{eventBuf: buf}

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sl = &stalledListener6809{Listener: base, budget: budget, deadlineUnsupported: deadlineUnsupported}

	handlerDone := make(chan struct{})
	var once sync.Once
	ts := &httptest.Server{
		Listener: sl,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer once.Do(func() { close(handlerDone) })
			h(srv, w, r)
		})},
	}
	ts.Start()
	return ts.Listener.Addr().String(), buf, handlerDone, sl, func() {
		sl.releaseAll()
		ts.Close()
	}
}

// floodEvents7632 publishes enough events to push the stream past the stalled
// conn's byte budget and into the blocking write.
func floodEvents7632(buf *logging.EventBuffer, n int) {
	for i := 0; i < n; i++ {
		buf.Add(logging.EventRecord{
			Time:     time.Now(),
			Type:     "SESSION_OPEN",
			SrcAddr:  fmt.Sprintf("10.0.1.%d:12345", i%256),
			DstAddr:  "10.0.2.100:80",
			Protocol: "TCP",
			Action:   "permit",
			PolicyID: 1,
		})
	}
}

// floodUntilParked7632 replaces "sleep, then publish once and hope the handler
// had subscribed" (#7654 review, finding 4).
//
// This is the #7650 class in this file's own harness: a fixed wall-clock point
// standing in for "the other side is ready". Subscriptions have no replay, so a
// flood that lands before the handler subscribes is simply LOST — and the cell
// then fails 15 seconds later blaming the deadline, which is the wrong
// diagnosis for a lost publish.
//
// The prescription from docs/engineering-style.md #7563 is to wait on the
// implying observable, not to lengthen the sleep: keep publishing until a write
// has genuinely PARKED, which implies both that the handler subscribed and that
// it reached the blocking write. If that never happens, fail loudly naming what
// never arrived.
func floodUntilParked7632(t *testing.T, buf *logging.EventBuffer, sl *stalledListener6809, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		floodEvents7632(buf, 500)
		if sl.waitForParkedWrite(100 * time.Millisecond) {
			return
		}
	}
	t.Fatalf("no write ever parked within %v: the handler never subscribed, or the "+
		"flood never reached a blocking write. Either way this cell cannot "+
		"observe the property it asserts (#7654 review, finding 4)", d)
}

// TestSlowSSEReaderDoesNotPinTheHandler7632 is the issue: a connected
// non-reading subscriber must not park the handler goroutine indefinitely.
//
// FAIL-ON-REVERT: drop the newSSEStream wrapping (write straight to w, as
// before) and no deadline is ever armed, so stalledConn6809.Write takes its
// wdl.IsZero() branch and blocks until teardown — this cell then fails on the
// timeout.
func TestSlowSSEReaderDoesNotPinTheHandler7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 250 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	addr, buf, done, sl, cleanup := startStalledSSEServer7632(t,
		(*Server).eventStreamHandler, 8*1024, false)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	// #7654 review, finding 3: credit the deadline for the return only after
	// witnessing that a write actually PARKED. Without this the cell passes
	// whenever the handler exits for any reason at all, including never having
	// reached the hazard.
	floodUntilParked7632(t, buf, sl, 15*time.Second)

	select {
	case <-done:
		// Returned: the write deadline turned the blocked write into an
		// ordinary error, and the handler treats a write failure as terminal.
	case <-time.After(15 * time.Second):
		t.Fatal("the SSE handler is still running ~60 write-deadline windows after " +
			"a connected subscriber stopped reading — the goroutine, the socket " +
			"and the subscriber slot are all pinned, and nothing in the request " +
			"bounds them (#7632)")
	}
}

// TestSlowSSEReaderPinIsReachableWithoutTheDeadline7632 is the NEGATIVE
// CONTROL. "The handler returned" proves the fix only if this fixture is
// capable of NOT returning: with write deadlines unsupported nothing can
// interrupt the blocked write, so the handler MUST still be running.
func TestSlowSSEReaderPinIsReachableWithoutTheDeadline7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 100 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	addr, buf, done, sl, cleanup := startStalledSSEServer7632(t,
		(*Server).eventStreamHandler, 8*1024, true /* deadlines unsupported */)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	// #7654 review, finding 3, and the correction this whole cell turns on.
	// "The handler has not returned" is ALSO what an idle handler looks like,
	// so without this witness the control proves the fixture can pin only in
	// the sense that it can fail to do anything at all. Establish that a write
	// is genuinely parked FIRST; only then does "still running" mean pinned.
	floodUntilParked7632(t, buf, sl, 15*time.Second)

	select {
	case <-done:
		t.Fatal("the handler returned with write deadlines unsupported — the " +
			"fixture cannot pin, so the sibling cell's pass proves nothing")
	case <-time.After(2 * time.Second):
		// Still blocked in Write, witnessed above, as a real socket would be.
	}
}

// TestSlowLogStreamReaderDoesNotPinTheHandler7632 covers the OTHER stream
// handler (#7654 review, finding 5).
//
// /api/v1/logs/stream is the same shape as the event stream and was changed by
// the same commit, but no cell touched it: every assertion in this file ran
// through eventStreamHandler. Two handlers changed, one was tested, and the
// untested one could have been reverted without reddening anything here.
func TestSlowLogStreamReaderDoesNotPinTheHandler7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 250 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	addr, buf, done, sl, cleanup := startStalledSSEServer7632(t,
		(*Server).logStreamHandler, 8*1024, false)
	defer cleanup()
	dialAndRequestWithoutReading6809(t, addr)

	floodUntilParked7632(t, buf, sl, 15*time.Second)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the LOG stream handler is still running long after a connected " +
			"subscriber stopped reading — logStreamHandler carries the same pin " +
			"as eventStreamHandler and needs the same bound (#7632)")
	}
}

// TestASeveredSSEReaderReleasesItsSubscriberSlot7632 is the finding-5 cell that
// binds the part of the fix nothing else could see: the SLOT.
//
// The issue is not only a parked goroutine. Each stream holds one of 64 capped
// subscriber slots (#4484), so pinned handlers accumulate until TrySubscribe
// starts returning nil and the endpoint 503s for everyone — a non-reading
// client taking the feed away from readers. Bounding the write is what lets the
// handler return, and `defer sub.Close()` is what turns that return into a
// freed slot; only the two together deliver the property.
//
// FAIL-ON-REVERT, both ways: delete `defer sub.Close()` from the handler and
// the slot is never released, so the final TrySubscribe stays nil; remove the
// write deadline and the handler never returns to release it at all.
func TestASeveredSSEReaderReleasesItsSubscriberSlot7632(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"events", (*Server).eventStreamHandler},
		{"logs", (*Server).logStreamHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := sseWriteDeadline
			sseWriteDeadline = 250 * time.Millisecond
			t.Cleanup(func() { sseWriteDeadline = restore })

			addr, buf, done, sl, cleanup := startStalledSSEServer7632(t, tc.h, 8*1024, false)
			defer cleanup()

			// Occupy every slot but one, so the stalled stream takes the last.
			var held []*logging.Subscription
			for {
				sub := buf.TrySubscribe(4)
				if sub == nil {
					break
				}
				held = append(held, sub)
			}
			if len(held) < 2 {
				t.Fatalf("precondition: expected a real subscriber cap, filled only %d", len(held))
			}
			last := held[len(held)-1]
			held = held[:len(held)-1]
			last.Close() // free exactly one slot for the handler
			t.Cleanup(func() {
				for _, s := range held {
					s.Close()
				}
			})

			dialAndRequestWithoutReading6809(t, addr)
			floodUntilParked7632(t, buf, sl, 15*time.Second)

			// ANTI-VACUITY FLOOR: while the stream is live the cap really is
			// full. Without this the closing assertion would also pass against
			// a buffer that never enforced a cap at all.
			if probe := buf.TrySubscribe(4); probe != nil {
				probe.Close()
				t.Fatal("precondition: a slot was still free while the stalled stream " +
					"was live, so this cell cannot observe the slot being RELEASED")
			}
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("handler never returned, so the slot cannot come back")
			}

			// The slot must come back. Poll: the release happens in a deferred
			// call on the handler goroutine, just after the signal above.
			var freed *logging.Subscription
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if freed = buf.TrySubscribe(4); freed != nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if freed == nil {
				t.Fatal("a severed slow reader did NOT release its subscriber slot: the " +
					"handler returned but the subscription outlived it, so enough " +
					"non-reading clients still exhaust the #4484 cap and 503 the " +
					"stream for readers that ARE reading (#7654 review, finding 5)")
			}
			freed.Close()
		})
	}
}

// TestIdleSSEStreamIsNotSevered7632 is the cell that makes this a SIBLING of
// #6809 rather than a copy of it, and the one a fresh lane would most likely
// get wrong.
//
// An event feed on a quiet firewall sits silent for long stretches — that is
// its normal operating state, not a symptom. So the bound must be per-WRITE and
// never elapsed: a stream that has sent nothing for many multiples of the write
// deadline is HEALTHY and must stay open.
//
// FAIL-ON-REVERT: add any elapsed budget to the stream (e.g. wrap r.Context()
// in a WithTimeout the way the RIB dump does) and this cell reds — which is
// exactly the design mistake it exists to prevent.
func TestIdleSSEStreamIsNotSevered7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 100 * time.Millisecond
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf, resp, stop := openSSEStream7632(t, sseWriteDeadline)
	defer stop()

	// Drain the establishing event so the read below can only see what arrives
	// AFTER the idle period.
	if first := readSSEChunk7632(t, resp, 3*time.Second); !strings.Contains(first, "SESSION_OPEN") {
		t.Fatalf("precondition: the stream did not establish; read %q", first)
	}

	// Now idle for many multiples of the write deadline with NO events at all.
	time.Sleep(10 * sseWriteDeadline)

	// The stream is still live: an event published now is still delivered.
	floodEvents7632(buf, 1)
	got := readSSEChunk7632(t, resp, 3*time.Second)
	if !strings.Contains(got, "SESSION_OPEN") {
		t.Fatalf("an SSE stream that idled for %v was severed — idling is the NORMAL "+
			"state of an event feed, so the bound must be per-WRITE and never "+
			"elapsed (#7632). read: %q", 10*sseWriteDeadline, got)
	}
}

// TestHealthySSEReaderStillGetsEvents7632 is the PAIRED control for the
// budgets. Every cell above asserts something STOPS; without this they are all
// satisfied by a handler that stops on every request.
func TestHealthySSEReaderStillGetsEvents7632(t *testing.T) {
	restore := sseWriteDeadline
	sseWriteDeadline = 2 * time.Second
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf, resp, stop := openSSEStream7632(t, 2*time.Second)
	defer stop()

	got := readSSEChunk7632(t, resp, 3*time.Second)
	if n := strings.Count(got, "SESSION_OPEN"); n < 1 {
		t.Fatalf("a reader that IS reading received no events — the #7632 deadline "+
			"severed a healthy stream. read: %q", got)
	}
	if !strings.Contains(got, "id: 1") {
		t.Fatalf("the SSE envelope is malformed: %q", got)
	}

	// And it keeps delivering: a second batch after the first read.
	floodEvents7632(buf, 3)
	if more := readSSEChunk7632(t, resp, 3*time.Second); !strings.Contains(more, "SESSION_OPEN") {
		t.Fatalf("the stream stopped after the first batch; read %q", more)
	}
}

// openSSEStream7632 starts an event-stream server and returns an ESTABLISHED
// stream.
//
// Establishing it needs one event, and that is a real property of these
// handlers rather than a test artifact: net/http does not send response headers
// until the first Write or Flush, and setSSEHeaders only sets header VALUES —
// so a client connecting to a quiet feed blocks in http.Get waiting for headers
// that no one has sent yet. (Pre-existing, unchanged by #7632, and noted rather
// than fixed here: a browser EventSource on an idle firewall would hang the
// same way.) The publish therefore runs on its own goroutine, because the GET
// cannot return until it lands.
func openSSEStream7632(t *testing.T, deadline time.Duration) (*logging.EventBuffer, *http.Response, func()) {
	t.Helper()
	restore := sseWriteDeadline
	sseWriteDeadline = deadline
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf := logging.NewEventBuffer(256)
	srv := &Server{eventBuf: buf}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.eventStreamHandler(w, r)
	}))

	// #7655: the GET now returns at CONNECT, so the establishing event no longer
	// has to be manufactured to make it return. This used to publish on a ticker
	// because setSSEHeaders wrote no headers and net/http therefore sent none
	// until the first event — the very defect #7655 fixed, worked around here.
	//
	// Publishing AFTER the GET is safe, and the ordering is not incidental:
	// eventStreamHandler subscribes BEFORE it calls setSSEHeaders, so "the GET
	// returned" implies "the subscription exists". Subscriptions still have no
	// replay, which is exactly why the publish must FOLLOW the GET.
	resp, err := httpGetWithTimeout7632(ts.URL+"/api/v1/events/stream", 20*time.Second)
	if err != nil {
		ts.Close()
		t.Fatalf("GET: %v — the stream never established", err)
	}
	floodEvents7632(buf, 1)
	stop := func() {
		resp.Body.Close()
		// The handler is parked in its select; force the connection shut so its
		// request context fires and Close() is not left waiting on it.
		ts.CloseClientConnections()
		ts.Close()
	}
	return buf, resp, stop
}

// httpGetWithTimeout7632 bounds the establishing GET. An SSE handler writes no
// response headers until its first event, so a GET against a feed that never
// produces one hangs until the package timeout and reports nothing useful
// (#7655). A bounded client turns that into a named failure.
func httpGetWithTimeout7632(url string, d time.Duration) (*http.Response, error) {
	c := &http.Client{Timeout: d}
	return c.Get(url)
}

// readSSEChunk7632 reads until a COMPLETE SSE event has arrived, or d elapses.
// An SSE response never ends on its own, so a plain ReadAll would block forever.
//
// #7654 review, finding 4: this used to take whatever ONE Body.Read returned
// and assume it was a whole event. A read is allowed to return any prefix, so a
// short read of "id: 1\n" would fail the healthy-reader assertion while
// delivery was in fact correct — a flaky red that accuses the fix of severing a
// stream it delivered perfectly. Accumulate until the SSE terminator instead,
// which is the observable that actually implies "an event arrived".
func readSSEChunk7632(t *testing.T, resp *http.Response, d time.Duration) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		var sb strings.Builder
		b := make([]byte, 16*1024)
		for {
			n, err := resp.Body.Read(b)
			sb.Write(b[:n])
			// "\n\n" terminates an SSE event: everything before it is complete.
			if strings.Contains(sb.String(), "\n\n") || err != nil {
				ch <- sb.String()
				return
			}
		}
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(d):
		return ""
	}
}

// --- HTTP/2, the protocol the HTTP/1.1 cells above are blind to -------------

// openSSEStreamH2_7632 is openSSEStream7632 over HTTP/2.
//
// This exists because every other cell in this file uses httptest.NewServer,
// which is HTTP/1.1 ONLY — and production permits HTTP/2 on the TLS listener
// (server.go). The distinction is not cosmetic: Go implements the HTTP/2 write
// deadline with a timer that RESETS THE STREAM when it fires, so a deadline
// left armed after a successful write tears down an idle stream. Under
// HTTP/1.1 the same stale deadline is invisible.
//
// A cell can be sound on the protocol it exercises and blind to the one where
// the defect lives.
func openSSEStreamH2_7632(t *testing.T, deadline time.Duration) (*logging.EventBuffer, *http.Response, func()) {
	t.Helper()
	restore := sseWriteDeadline
	sseWriteDeadline = deadline
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf := logging.NewEventBuffer(256)
	srv := &Server{eventBuf: buf}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("this cell must exercise HTTP/2; handler saw %s", r.Proto)
		}
		srv.eventStreamHandler(w, r)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()

	// #7655: same as the HTTP/1.1 helper — the GET returns at connect, and the
	// handler subscribes before flushing headers, so one publish afterwards
	// cannot be lost.
	c := ts.Client()
	c.Timeout = 20 * time.Second
	resp, err := c.Get(ts.URL + "/api/v1/events/stream")
	if err != nil {
		ts.Close()
		t.Fatalf("GET over HTTP/2: %v", err)
	}
	if resp.Proto != "HTTP/2.0" {
		resp.Body.Close()
		ts.Close()
		t.Fatalf("negotiated %s, not HTTP/2 — the cell would test the wrong protocol", resp.Proto)
	}
	// One establishing event, which the caller drains as its precondition.
	floodEvents7632(buf, 1)
	return buf, resp, func() {
		resp.Body.Close()
		ts.CloseClientConnections()
		ts.Close()
	}
}

// TestIdleSSEStreamIsNotResetOnHTTP2_7632 is the regression cell for the HIGH
// finding on this PR's own review, and it is the one the HTTP/1.1 idle cell
// could not have caught.
//
// The first version of this fix armed a write deadline before every write and
// never cleared it. On HTTP/1.1 that is harmless. On HTTP/2 the deadline is a
// timer that resets the stream when it expires, so an idle SSE feed was torn
// down one deadline after its last event — with a client that had consumed
// everything and a firewall that was legitimately quiet. Reproduced before
// fixing:
//
//	after idling 4x the deadline:
//	read n=0 err=stream error: stream ID 1; INTERNAL_ERROR; received from peer
//
// So the lesson the earlier design missed: "per-write, not elapsed" is
// necessary and not sufficient. The window has to CLOSE as well as open.
//
// FAIL-ON-REVERT: remove the clearDeadline() call at the end of writeEvent and
// this cell reds with exactly that stream error, while every HTTP/1.1 cell in
// this file stays green.
func TestIdleSSEStreamIsNotResetOnHTTP2_7632(t *testing.T) {
	const deadline = 500 * time.Millisecond
	buf, resp, stop := openSSEStreamH2_7632(t, deadline)
	defer stop()

	if first := readSSEChunk7632(t, resp, 5*time.Second); !strings.Contains(first, "SESSION_OPEN") {
		t.Fatalf("precondition: the HTTP/2 stream did not establish; read %q", first)
	}

	// Idle well past the deadline with no traffic at all.
	time.Sleep(4 * deadline)

	// Still live: an event published now is still delivered, and the read
	// returns data rather than a stream reset.
	floodEvents7632(buf, 1)
	got := readSSEChunk7632(t, resp, 5*time.Second)
	if !strings.Contains(got, "SESSION_OPEN") {
		t.Fatalf("an idle HTTP/2 SSE stream was RESET %v after its last event — a "+
			"write deadline that is armed and never cleared is an h2 stream-reset "+
			"timer, so the fix severed exactly the healthy quiet feed it was "+
			"written to protect (#7654 review, finding 1). read: %q",
			4*deadline, got)
	}
}

// TestLargeEventSurvivesASlowButProgressingReader7632 covers review A's MEDIUM:
// one event large enough to outlast a single deadline window.
//
// THIS CELL REPLACES ONE THAT DID NOT BIND, and the reason generalises.
// The first version drained a 256 KiB payload over loopback HTTP/2 as fast as
// the client could read. Over loopback that transits in microseconds, so a
// 750 ms window never came close to expiring either way — the mutation matrix
// caught it as M9 GREEN: deleting the chunking left the suite green, so the
// fix for "one absolute deadline per event" was riding on a cell that could not
// see it. The fixture varied the right axis and sampled only the passing point.
//
// The hazard needs a reader that is SLOW BUT STILL PROGRESSING, which a
// full-speed loopback client cannot be and a stalled conn cannot be either — a
// stalled conn is accepting instantly or parked forever, and this is neither.
// stalledConn6809 gained slowRate/slowWindow for exactly that: bytes move, at a
// rate, honouring the armed deadline.
//
// WHAT THE CHUNKING ACTUALLY IS. net/http's own 4 KiB conn.bufw means the
// SOCKET sees ~4 KiB writes whatever sseWriteChunk is, so chunk size does not
// change the write pattern at all — it changes WHEN SetWriteDeadline IS
// RE-ARMED. The chunking is a re-arming schedule, not a write schedule. The
// original cell was implicitly testing the write pattern, which is identical in
// both arms, which is why it could never have failed.
//
// FAIL-ON-REVERT: send the payload in one io.WriteString and the whole event
// runs under a single window; at this rate it expires mid-payload and the
// client sees a truncated stream.
func TestLargeEventSurvivesASlowButProgressingReader7632(t *testing.T) {
	const (
		// #9807: 400ms, not 100ms. One chunk costs 40ms, so the per-chunk
		// margin is 360ms of wall clock rather than 60ms; a scheduler stall
		// on a loaded host (other `make test` runs, a cluster build) ate the
		// old margin and failed this cell with the #7654 message.
		deadline = 400 * time.Millisecond
		// 32 KiB costs 40ms: one chunk fits comfortably inside one window,
		// the whole 32-chunk payload (1.28s) cannot, so a single-window write
		// still expires mid-payload.
		rate   = 32 * 1024
		window = 40 * time.Millisecond
		chunks = 32
	)
	restore := sseWriteDeadline
	sseWriteDeadline = deadline
	t.Cleanup(func() { sseWriteDeadline = restore })

	buf := logging.NewEventBuffer(256)
	srv := &Server{eventBuf: buf}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	sl := &stalledListener6809{Listener: base, slowRate: rate, slowWindow: window}
	ts := &httptest.Server{
		Listener: sl,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.eventStreamHandler(w, r)
		})},
	}
	ts.Start()
	defer func() { sl.releaseAll(); ts.Close() }()

	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "GET /api/v1/events/stream HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// A payload many chunks long: one window under the mutation, many with it.
	big := strings.Repeat("A", chunks*sseWriteChunk)

	// #7655: read the HEADER BLOCK first, then publish ONCE.
	//
	// This used to publish on a ticker and treat "any payload byte seen" as the
	// establishment signal, because no headers were written until an event
	// arrived. Two things changed: headers now arrive at CONNECT, so the ticker
	// is unnecessary; and the old signal became actively WRONG, because the
	// header block itself contains a capital A (`Date: ... Aug ...`). That
	// closed `established` on the HEADER, stopped the ticker before any event
	// was published, and the read then blocked to its deadline reporting
	// "failed after 1 payload bytes" — a real failure that looked exactly like
	// the severed-reader defect this test exists to catch.
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the response header block: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN",
		SrcAddr: "10.0.1.9:1", DstAddr: "10.0.2.1:80",
		Protocol: "TCP", Action: "permit", Reason: big,
	})

	// Drain CONTINUOUSLY — the reader is slow, never stopped, so any failure
	// here is the budget measuring elapsed time rather than lack of progress.
	var seen int
	b := make([]byte, 32*1024)
	for seen < len(big) {
		n, err := br.Read(b)
		seen += strings.Count(string(b[:n]), "A")
		if err != nil {
			t.Fatalf("a %d-byte event to a CONTINUOUSLY reading client failed after "+
				"%d payload bytes: %v — the write budget is measuring elapsed time "+
				"rather than progress, so one large event severs a healthy reader "+
				"(#7654 review A, finding 2). Per-chunk margin was %v; a stall "+
				"longer than that inside one chunk reads the same way (#9807)",
				len(big), seen, err, deadline-window)
		}
	}
}

// --- the FLUSH is where a small event reaches the socket --------------------

// flushFailingWriter7632 is a ResponseWriter whose FLUSH fails while every
// Write succeeds. That is not a contrived split: it is precisely what net/http
// does to an ordinary SSE event, which is a few hundred bytes and therefore
// sits in the 2 KiB response buffer until the flush pushes it at the socket.
type flushFailingWriter7632 struct {
	hdr      http.Header
	flushes  int
	flushErr error
}

func (f *flushFailingWriter7632) Header() http.Header {
	if f.hdr == nil {
		f.hdr = http.Header{}
	}
	return f.hdr
}
func (f *flushFailingWriter7632) Write(p []byte) (int, error) { return len(p), nil }
func (f *flushFailingWriter7632) WriteHeader(int)             {}

// Flush is the errorless http.Flusher form — the one whose error net/http's
// response.Flush discards. Kept so a revert to s.f.Flush() still COMPILES and
// this cell reds on behaviour rather than on a build break.
func (f *flushFailingWriter7632) Flush() { f.flushes++ }

func (f *flushFailingWriter7632) FlushError() error {
	f.flushes++
	return f.flushErr
}

// TestSSEFlushFailureIsReportedToTheCaller7632 is the finding-2 regression.
//
// writeEvent's doc comment claimed it "RETURNS the first write error". For the
// ordinary small event that was FALSE: the Writes are buffered by net/http and
// succeed, the socket write happens inside the flush, and http.Flusher.Flush()
// has no error return — net/http's response.Flush calls FlushError() and
// discards it. So the one write that can actually fail was the one write whose
// failure was guaranteed to be dropped.
//
// FAIL-ON-REVERT: change writeEvent back to `if s.f != nil { s.f.Flush() }` and
// this cell reds — the errorless Flush is still implemented above precisely so
// that revert compiles.
func TestSSEFlushFailureIsReportedToTheCaller7632(t *testing.T) {
	w := &flushFailingWriter7632{flushErr: fmt.Errorf("connection reset by peer")}
	st := newSSEStream(w, time.Second)

	err := st.writeEvent("1", "SESSION_OPEN", `{"src":"10.0.1.1"}`)
	if w.flushes == 0 {
		t.Fatal("precondition: the event was never flushed, so this cell cannot " +
			"observe a flush failure at all")
	}
	if err == nil {
		t.Fatal("writeEvent discarded a FLUSH failure and reported success: for an " +
			"ordinary small event the flush is the only write that reaches the " +
			"socket, so this is the failure that matters and it was invisible to " +
			"the caller (#7654 review, finding 2)")
	}
	if !strings.Contains(err.Error(), "connection reset by peer") {
		t.Fatalf("writeEvent returned %v, want the underlying flush error", err)
	}
}

// TestSSEFlushNotSupportedIsNotAPeerFailure7632 is the PAIRED control.
//
// Without it, "return whatever Flush says" is satisfied by treating every
// stream as broken: http.ResponseController.Flush reports ErrNotSupported for a
// ResponseWriter that cannot flush, which is a property of the WRITER and not
// evidence that the peer has gone. Returning it would tear down a healthy
// stream on the first event.
func TestSSEFlushNotSupportedIsNotAPeerFailure7632(t *testing.T) {
	// A bare ResponseWriter: no Flush, no FlushError.
	var w http.ResponseWriter = plainWriter7632{hdr: http.Header{}}
	st := newSSEStream(w, time.Second)
	if err := st.writeEvent("1", "SESSION_OPEN", `{"src":"10.0.1.1"}`); err != nil {
		t.Fatalf("writeEvent returned %v for a ResponseWriter that merely cannot "+
			"flush — ErrNotSupported is a property of the writer, not a dead peer, "+
			"and treating it as terminal severs the stream on its first event", err)
	}
}

type plainWriter7632 struct{ hdr http.Header }

func (p plainWriter7632) Header() http.Header         { return p.hdr }
func (p plainWriter7632) Write(b []byte) (int, error) { return len(b), nil }
func (p plainWriter7632) WriteHeader(int)             {}
