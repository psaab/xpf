package feeds

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is the #3934 fail-on-revert suite: the dynamic-address feed
// fetcher must bound both the body SIZE and the parsed ENTRY count so a
// huge/infinite body — or a MITM on a plaintext-http feed — cannot OOM the
// daemon, and an over-limit feed must RETAIN the last-good snapshot rather
// than wipe or truncate the enforced set.

// repeatReader endlessly cycles a fixed chunk, so a test can synthesize an
// arbitrarily large body without allocating it. Bound it with an
// io.LimitReader to keep the synthetic body finite (a reverted parseFeed with
// no io.LimitReader then terminates rather than hanging).
type repeatReader struct {
	chunk []byte
	off   int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.chunk) {
			r.off = 0
		}
		c := copy(p[n:], r.chunk[r.off:])
		r.off += c
		n += c
	}
	return n, nil
}

// oversizeCommentChunk is a 64 KiB comment line (well under maxLineBytes) that
// parses as a skipped comment — padding to inflate the body byte count without
// inflating the parsed entry count, so a test isolates the BYTE cap from the
// ENTRY cap.
func oversizeCommentChunk() []byte {
	return []byte("#" + strings.Repeat("a", 64*1024-2) + "\n")
}

// TestParseFeedOverSizeBodyRejected drives the maxFeedBodyBytes cap directly.
// A body larger than the cap must fail the parse with a size error. On revert
// (no io.LimitReader / no size check) parseFeed reads the whole body and
// returns success — this goes RED.
func TestParseFeedOverSizeBodyRejected(t *testing.T) {
	// One valid prefix, then >maxFeedBodyBytes of 64 KiB comment lines. The
	// entry count stays at 1 so the BYTE cap is what trips.
	prefix := strings.NewReader("203.0.113.0/24\n")
	pad := io.LimitReader(&repeatReader{chunk: oversizeCommentChunk()}, maxFeedBodyBytes+64*1024)
	body := io.MultiReader(prefix, pad)

	_, err := parseFeed(body)
	if err == nil {
		t.Fatal("expected error for over-size body, got nil (unbounded read → OOM path)")
	}
	if !strings.Contains(err.Error(), "max size") {
		t.Fatalf("expected max-size rejection, got %v", err)
	}
}

// TestParseFeedOverEntryCountRejected drives the maxFeedPrefixes cap. A body
// producing more than maxFeedPrefixes parsed entries must fail with an
// entry-count error rather than install a partial-but-huge set. On revert (no
// entry cap) parseFeed accepts it and returns success — this goes RED.
func TestParseFeedOverEntryCountRejected(t *testing.T) {
	var b strings.Builder
	// A tiny valid line repeated past the entry cap. Duplicates count toward
	// the pre-dedup entry cap (memory bound), and the whole body stays well
	// under maxFeedBodyBytes so the ENTRY cap is what trips, not the byte cap.
	const line = "1.1.1.1\n"
	b.Grow((maxFeedPrefixes + 2) * len(line))
	for i := 0; i < maxFeedPrefixes+2; i++ {
		b.WriteString(line)
	}

	_, err := parseFeed(strings.NewReader(b.String()))
	if err == nil {
		t.Fatal("expected error for over-entry-count body, got nil (unbounded entry set)")
	}
	if !strings.Contains(err.Error(), "max entry count") {
		t.Fatalf("expected max-entry-count rejection, got %v", err)
	}
}

// TestParseFeedUnderCapsInstalls is the no-regression guard: a legitimately
// large feed (many prefixes, comfortably under both caps) still parses and
// installs — the caps must not reject a normal feed.
func TestParseFeedUnderCapsInstalls(t *testing.T) {
	var b strings.Builder
	const n = 1000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24\n", i/256, i%256)
	}
	res, err := parseFeed(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("under-cap feed rejected: %v", err)
	}
	if len(res.prefixes) != n {
		t.Fatalf("got %d prefixes, want %d (under-cap feed must install fully)", len(res.prefixes), n)
	}
}

// oversizeServer serves a small good body until switched to over-size, when it
// streams a DIFFERENT leading prefix followed by >maxFeedBodyBytes of comment
// padding. The different prefix lets the retention assertion distinguish
// "retained last-good" (fixed) from "installed the over-size body" (revert).
type oversizeServer struct {
	mu   sync.Mutex
	over bool
}

func (s *oversizeServer) setOver(o bool) {
	s.mu.Lock()
	s.over = o
	s.mu.Unlock()
}

func (s *oversizeServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		over := s.over
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if !over {
			_, _ = io.WriteString(w, "203.0.113.0/24\n")
			return
		}
		// A different valid prefix leads; if the size cap were absent this
		// would REPLACE the last-good set.
		_, _ = io.WriteString(w, "198.51.100.0/24\n")
		_, _ = io.CopyN(w, &repeatReader{chunk: oversizeCommentChunk()}, maxFeedBodyBytes+64*1024)
	}
}

// TestFetchFeedOverSizeRetainsLastGood exercises the full HTTP fetch path plus
// the retain-last-good fail-safe: an over-size body must be rejected and the
// previously-installed prefixes retained (never wiped or replaced by a
// truncated set). On revert the over-size body installs [198.51.100.0/24],
// clobbering the last-good — the retention assertion goes RED.
func TestFetchFeedOverSizeRetainsLastGood(t *testing.T) {
	var calls int
	m := New(func() error { calls++; return nil })
	srv := &oversizeServer{}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	// Install last-good.
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("initial install failed: got %v", got)
	}
	installCalls := calls

	// Switch to an over-size body.
	srv.setOver(true)
	m.fetchFeed(ctx, fs)

	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("over-size fetch clobbered last-good: got %v, want [203.0.113.0/24]", got)
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded for over-size fetch")
	}
	if calls != installCalls {
		t.Errorf("onUpdate fired on rejected over-size fetch: calls went %d -> %d", installCalls, calls)
	}
}

// slowServer serves a body immediately until switched to slow, when it sleeps
// past the client timeout before responding.
type slowServer struct {
	mu    sync.Mutex
	slow  bool
	delay time.Duration
	body  string
}

func (s *slowServer) setSlow(b bool) {
	s.mu.Lock()
	s.slow = b
	s.mu.Unlock()
}

func (s *slowServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		slow, delay, body := s.slow, s.delay, s.body
		s.mu.Unlock()
		if slow {
			time.Sleep(delay)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}
}

// TestFetchFeedSlowServerTimesOut guards the client timeout (slow-loris
// protection): a server that stalls past the timeout must fail the fetch and
// retain the last-good snapshot, not block the refresh indefinitely. The
// timeout is overridden to a short value so the test is fast.
func TestFetchFeedSlowServerTimesOut(t *testing.T) {
	m := New(func() error { return nil })
	m.client.Timeout = 150 * time.Millisecond

	srv := &slowServer{delay: 2 * time.Second, body: "203.0.113.0/24\n"}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	// Fast install.
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("initial install failed: got %v", got)
	}

	// Stall the next fetch past the client timeout.
	srv.setSlow(true)
	start := time.Now()
	m.fetchFeed(ctx, fs)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("fetch did not honor the client timeout: took %v", elapsed)
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("timeout wiped last-good: got %v", got)
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded on timeout")
	}
}
