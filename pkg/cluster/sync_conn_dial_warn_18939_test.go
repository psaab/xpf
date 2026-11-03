package cluster

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// #18939: fabricConnectLoop silently discarded dial errors (bare continue),
// so a peer that could never be dialed retried invisibly every second. The
// fix reuses the heartbeatRejectWarnLimiter shape (first failure + error
// change + one line per 30s, suppressed repeats counted and reported).
//
// These cells follow the #6669 doctrine: the binder drives the REAL
// fabricConnectLoop dial path, not the limiter in isolation — a limiter that
// works but is not wired changes nothing about the log volume. The second
// cell pins the change/interval semantics directly because the real path
// cannot produce an error CHANGE for a fixed peer address.

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
// setter, so a test can step across the interval without sleeping.
func withPinnedFabricDialClock18939(t *testing.T, start int64) func(int64) {
	t.Helper()
	now := start
	orig := fabricDialWarnNowNanos
	fabricDialWarnNowNanos = func() int64 { return now }
	t.Cleanup(func() { fabricDialWarnNowNanos = orig })
	return func(v int64) { now = v }
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.fabricConnectLoop(ctx, 0, addr)

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

	// (b) Repeated UNCHANGED failures inside one interval do not spam. Let
	// the loop pace at least three more real retries (~1s apart) and require
	// the count to stay at exactly one. The limiter clock stays pinned, so
	// from its side every retry is inside the same 30s window.
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
	// emission must report what it suppressed, so the bound does not conceal
	// the volume (~1 failure/s since the first line).
	setNow(1 + int64(fabricDialWarnInterval) + 1)
	waitFabricDialFails18939(t, logs, 2)
	if got := logs.count(); got != 2 {
		t.Fatalf("after stepping past %v the warning count is %d, want exactly 2",
			fabricDialWarnInterval, got)
	}
	if second := logs.lastLine(); second == first || strings.Contains(second, "suppressed_since_last=0") {
		t.Fatalf("the post-interval warning did not report a positive suppressed count:\n%s", second)
	}
}

// TestFabricDialWarnLimiterEmitsOnChangeAndInterval_18939 pins the limiter's
// change and interval semantics directly. The binder above proves the wiring
// but cannot produce an error CHANGE on the real path — a fixed peer address
// yields a stable error string — so this cell drives the limiter itself.
//
// Fail-on-revert: make admit ignore err (no change detection) and the change
// assertion reddens; make it emit on every call and the suppression
// assertions redden.
func TestFabricDialWarnLimiterEmitsOnChangeAndInterval_18939(t *testing.T) {
	setNow := withPinnedFabricDialClock18939(t, 1000)
	var l fabricDialWarnLimiter

	const refused = "dial tcp 127.0.0.1:1: connect: connection refused"
	const unreachable = "dial tcp 127.0.0.1:1: connect: network is unreachable"

	if emit, sup := l.admit(refused); !emit || sup != 0 {
		t.Fatalf("first failure must emit reporting 0 suppressed; got emit=%v suppressed=%d", emit, sup)
	}
	if emit, _ := l.admit(refused); emit {
		t.Fatal("an UNCHANGED error inside the interval must be suppressed")
	}
	if emit, _ := l.admit(refused); emit {
		t.Fatal("an UNCHANGED error inside the interval must be suppressed (second repeat)")
	}
	if emit, sup := l.admit(unreachable); !emit || sup != 2 {
		t.Fatalf("a CHANGED error must emit at once and report the 2 suppressed repeats; "+
			"got emit=%v suppressed=%d", emit, sup)
	}
	if emit, _ := l.admit(unreachable); emit {
		t.Fatal("the changed error is now the unchanged error: inside the interval it must be suppressed")
	}
	setNow(1000 + int64(fabricDialWarnInterval) + 1)
	if emit, sup := l.admit(unreachable); !emit || sup != 1 {
		t.Fatalf("past the interval an ongoing failure must re-emit reporting 1 suppressed; "+
			"got emit=%v suppressed=%d", emit, sup)
	}
}
