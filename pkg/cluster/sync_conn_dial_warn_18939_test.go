package cluster

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #18939: fabricConnectLoop silently discarded dial errors (bare continue),
// so a peer that could never be dialed retried invisibly every second. The
// fix reuses the heartbeatRejectWarnLimiter shape (first failure + one line
// per 30s, suppressed repeats counted and reported). The #18950 fold bounds
// the rate across error-text CHANGES too: the loop dials once per second,
// so an error oscillating A-B-A emitted on every attempt under the
// change-emits rule — the exact flood this fix exists to bound. The
// interval emission names the CURRENT error, so change visibility survives
// at interval granularity.
//
// These cells follow the #6669 doctrine: the binder drives the REAL
// fabricConnectLoop dial path, not the limiter in isolation — a limiter that
// works but is not wired changes nothing about the log volume. The limiter
// cell pins the oscillation/interval semantics directly because the real
// path cannot produce an error CHANGE for a fixed peer address; the
// cancellation cell pins the ctx guard the fold added (Stop/restart
// cancellation is not a peer failure).

// logSink18939 is a goroutine-safe slog sink: fabricConnectLoop logs from its
// own goroutine while the cell inspects the buffer (same shape as
// logSink18752).
type logSink18939 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logSink18939) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// count returns how many dial-failure warnings the captured log holds.
func (b *logSink18939) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), fabricDialFailMsg18939)
}

// lastLine returns the last captured WARN line holding the dial-failure
// message, or "" when none has been logged yet.
func (b *logSink18939) lastLine() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	last := ""
	for _, l := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(l, fabricDialFailMsg18939) {
			last = l
		}
	}
	return last
}

// captureSyncWarnLog18939 redirects slog to a buffer for the duration of the
// test (Warn level: the dial-failure line is a Warn, and filtering Info/Debug
// keeps unrelated loop chatter out of the assertions).
func captureSyncWarnLog18939(t *testing.T) *logSink18939 {
	t.Helper()
	logs := &logSink18939{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return logs
}

// withPinnedFabricDialClock18939 pins the limiter's clock and returns a
// setter, so a test can step across the interval without sleeping. The
// pinned value is atomic: the fabricConnectLoop goroutine reads it through
// admit() on its own thread while the test steps it (#18950 finding 1).
func withPinnedFabricDialClock18939(t *testing.T, start int64) func(int64) {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(start)
	orig := fabricDialWarnNowNanos
	fabricDialWarnNowNanos = func() int64 { return now.Load() }
	t.Cleanup(func() { fabricDialWarnNowNanos = orig })
	return now.Store
}

// unreachableAddr18939 reserves a loopback port and releases it, leaving an
// address nothing listens on. The subsequent dial fails FAST either way the
// namespace's loopback is found: ECONNREFUSED when lo routes, ENETUNREACH
// when it does not (the #18038 testguard state) — both are dial failures,
// which is all these cells need; they assert the error's PRESENCE, never its
// text, and no netlink mutation (census) is involved.
func unreachableAddr18939(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// goFabricConnectLoop18939 starts the loop the way production does and
// registers a cleanup that cancels its context and JOINS the goroutine.
// The join must run before the clock-pin and slog cleanups restore their
// seams (t.Cleanup is LIFO, and this registers last), so the loop can never
// read fabricDialWarnNowNanos or the default logger after either test seam
// is gone — that ordering was the #18950 finding 1 race.
func goFabricConnectLoop18939(t *testing.T, s *SessionSync, addr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.fabricConnectLoop(ctx, 0, addr)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("fabricConnectLoop did not exit within 5s of context cancellation")
		}
	})
}

// waitFabricDialFails polls the captured log until want dial-failure lines
// are present or the deadline expires. The loop paces its own retries at 1s
// of REAL time (that cadence is production behaviour this cell must not
// perturb); only the limiter's 30s interval is stepped via the clock seam.
func waitFabricDialFails18939(t *testing.T, logs *logSink18939, want int) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		if got := logs.count(); got >= want {
			return
		}
		if got := logs.count(); got > want {
			t.Fatalf("dial-failure warnings already exceed the bound: got %d, want %d.\nlog:\n%s",
				got, want, logs.lastLine())
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d dial-failure warnings; got %d. "+
				"Without the #18939 wiring fabricConnectLoop swallows dial errors "+
				"and retries invisibly.\nlog:\n%s", want, logs.count(), logs.lastLine())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestFabricDialFailureWarnIsRateLimitedOnTheRealPath_18939 is the binder.
//
// Fail-on-revert: restore the bare `continue` in fabricConnectLoop and the
// first assertion reddens with zero warnings logged (the exact #18939
// silence); drop the dialWarn.admit gate and the bound assertion reddens
// with one warning per attempt.
func TestFabricDialFailureWarnIsRateLimitedOnTheRealPath_18939(t *testing.T) {
	addr := unreachableAddr18939(t)

	setNow := withPinnedFabricDialClock18939(t, 1)
	logs := captureSyncWarnLog18939(t)

	s := newAuthSyncNode(t, nil, 0)
	goFabricConnectLoop18939(t, s, addr)

	// (a) The first failure logs — with the address, the fabric, the error,
	// and suppressed_since_last=0: nothing preceded it.
	waitFabricDialFails18939(t, logs, 1)
	first := logs.lastLine()
	if !strings.Contains(first, "addr="+addr) || !strings.Contains(first, "fabric=0") {
		t.Fatalf("the dial-failure warning does not carry the peer address and fabric:\n%s", first)
	}
	if !strings.Contains(first, "err=") {
		t.Fatalf("the dial-failure warning does not carry the dial error:\n%s", first)
	}
	if !strings.Contains(first, "suppressed_since_last=0") {
		t.Fatalf("the FIRST dial-failure warning must report suppressed_since_last=0:\n%s", first)
	}

	// (b) Repeated failures inside one interval do not spam — the loop paces
	// at least three more real retries (~1s apart, all failing) and the count
	// must stay at exactly one. The limiter clock stays pinned, so from its
	// side every retry is inside the same 30s window.
	quiet := time.Now().Add(3500 * time.Millisecond)
	for time.Now().Before(quiet) {
		if got := logs.count(); got > 1 {
			t.Fatalf("%d dial-failure warnings inside one %v window, want 1: "+
				"the per-attempt warning is not rate-limited, so a never-dialable peer "+
				"floods the log at ~1 line/s.\nlog:\n%s",
				got, fabricDialWarnInterval, logs.lastLine())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := logs.count(); got != 1 {
		t.Fatalf("after further retries inside one %v window the warning count is %d, want 1",
			fabricDialWarnInterval, got)
	}

	// (c) Stepping PAST the interval must emit again — a limiter that latches
	// shut would hide an ongoing outage after its first line — and the new
	// emission must name the CURRENT error and report what it suppressed, so
	// the bound does not conceal the volume (~1 failure/s since the first
	// line).
	setNow(1 + int64(fabricDialWarnInterval) + 1)
	waitFabricDialFails18939(t, logs, 2)
	if got := logs.count(); got != 2 {
		t.Fatalf("after stepping past %v the warning count is %d, want exactly 2",
			fabricDialWarnInterval, got)
	}
	second := logs.lastLine()
	if second == first || !strings.Contains(second, "err=") {
		t.Fatalf("the post-interval warning does not name the current error:\n%s", second)
	}
	if strings.Contains(second, "suppressed_since_last=0") {
		t.Fatalf("the post-interval warning did not report a positive suppressed count:\n%s", second)
	}
}

// TestFabricDialWarnLimiterBoundsOscillation_18939 pins the fold's
// oscillation bound (#18950 finding 2): the interval applies across
// error-text CHANGES too. The binder above cannot produce an error change on
// the real path — a fixed peer address yields a stable error string — so
// this cell drives the limiter through the exact A-B-A shape the change-emits
// rule flooded: alternating texts inside one interval, then an interval
// emission.
//
// Fail-on-revert: restore a "changed error emits at once" arm (or make admit
// emit on every call) and the oscillation assertion reddens with one
// emission per attempt; latch the limiter shut after its first emission and
// the interval assertion reddens with zero.
func TestFabricDialWarnLimiterBoundsOscillation_18939(t *testing.T) {
	setNow := withPinnedFabricDialClock18939(t, 1000)
	var l fabricDialWarnLimiter

	// The first failure a loop ever sees is news: emit at once, 0 suppressed.
	if emit, sup := l.admit(); !emit || sup != 0 {
		t.Fatalf("first failure must emit reporting 0 suppressed; got emit=%v suppressed=%d", emit, sup)
	}

	// A-B-A oscillation inside one interval. Under the pre-fold rule each
	// text change emitted; at the loop's one attempt per second that is
	// unbounded. Now every failure inside the interval is suppressed and
	// counted, whatever its text.
	for i := range 3 {
		if emit, _ := l.admit(); emit {
			t.Fatalf("attempt %d inside the interval emitted; an A-B-A oscillation must stay bounded "+
				"to one line per %v", i, fabricDialWarnInterval)
		}
	}

	// Past the interval the limiter resumes — not latched shut — and the
	// emission reports everything it suppressed. The ERROR TEXT on that
	// emission is the CURRENT one (the wiring logs the live err), which is
	// how change visibility survives the bound.
	setNow(1000 + int64(fabricDialWarnInterval) + 1)
	if emit, sup := l.admit(); !emit || sup != 3 {
		t.Fatalf("past the interval an ongoing failure must re-emit reporting 3 suppressed; "+
			"got emit=%v suppressed=%d", emit, sup)
	}
	// ...and the window starts over: the next attempt, changed text or not,
	// is inside the new interval.
	if emit, _ := l.admit(); emit {
		t.Fatal("inside the fresh interval the next failure must be suppressed")
	}
}

// TestFabricDialCancellationIsSilent_18939 pins the ctx guard (#18950
// finding 3): a dial failing because OUR context was cancelled is not a peer
// failure and must stay silent. The loop is started against the unreachable
// address with an ALREADY-CANCELLED context, so its very first dial fails
// with the cancellation error — the exact arm the guard sits on; without the
// guard that first failure emits a spurious "peer unreachable" warn on every
// Stop/restart.
//
// The first iteration dials before any select (first=true skips the retry
// wait), so the dial-error arm is reached deterministically; the loop then
// exits via the ctx.Done select, which this cell joins inline. Named with
// the TestFabricDial prefix so the family sweep `-run '^TestFabricDial'`
// (the re-review command) covers it too.
func TestFabricDialCancellationIsSilent_18939(t *testing.T) {
	addr := unreachableAddr18939(t)
	logs := captureSyncWarnLog18939(t)
	withPinnedFabricDialClock18939(t, 1)

	s := newAuthSyncNode(t, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.fabricConnectLoop(ctx, 0, addr)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fabricConnectLoop did not exit within 5s on a cancelled context")
	}
	if got := logs.count(); got != 0 {
		t.Fatalf("%d dial-failure warnings on a cancelled context, want 0: "+
			"Stop/session-restart cancellation is not a peer failure.\nlog:\n%s",
			got, logs.lastLine())
	}
}
