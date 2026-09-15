package feeds

import (
	"context"
	"sync/atomic"
	"testing"
)

// #9916 F-133: a stale (post-swap/removal) fetch must not publish.
//
// Apply cancels old producers and swaps the map without joining; an in-flight old
// fetch completing post-swap calls onUpdate against the NEW state — a spurious
// dataplane apply. The fix suppresses install/record on a feedState no longer
// current (pointer mismatch). This cell drives the suppress directly: capture the
// old pointer, remove the feed, then simulate the late completion.
func TestStaleFetchDoesNotPublish9916(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	// Install a good snapshot for "victim" via a canned fetch (no HTTP needed:
	// call installSnapshot on a live feedState directly).
	m.mu.Lock()
	fs := &feedState{name: "victim", done: make(chan struct{})}
	m.feeds["victim"] = fs
	m.mu.Unlock()
	m.installSnapshot(fs, fetchResult{prefixes: []string{"203.0.113.0/24"}, hash: hashPrefixes([]string{"203.0.113.0/24"})})
	if got := calls.Load(); got != 1 {
		t.Fatalf("setup: onUpdate calls = %d, want 1 (live install must publish)", got)
	}

	// Remove the feed (simulates Apply with the feed gone; no producers running).
	m.mu.Lock()
	old := m.feeds["victim"]
	delete(m.feeds, "victim")
	m.mu.Unlock()
	if old != fs {
		t.Fatalf("setup: captured %p, want live %p", old, fs)
	}

	// Late completion of the orphaned fetch: must NOT publish.
	m.installSnapshot(old, fetchResult{prefixes: []string{"198.51.100.0/24"}, hash: hashPrefixes([]string{"198.51.100.0/24"})})
	if got := calls.Load(); got != 1 {
		t.Fatalf("stale installSnapshot published: onUpdate calls = %d, want still 1 (#9916 F-133)", got)
	}

	// Positive control: a CURRENT feed still publishes.
	m.mu.Lock()
	cur := &feedState{name: "live", done: make(chan struct{})}
	m.feeds["live"] = cur
	m.mu.Unlock()
	m.installSnapshot(cur, fetchResult{prefixes: []string{"192.0.2.0/24"}, hash: hashPrefixes([]string{"192.0.2.0/24"})})
	if got := calls.Load(); got != 2 {
		t.Fatalf("live installSnapshot suppressed: onUpdate calls = %d, want 2 (no over-suppression)", got)
	}

	// Stale recordFailure drop-to-empty must not publish either. Arm a 1ns
	// hold interval on the orphan: the first failure enters stale, the second
	// (hold elapsed) drops to empty and would fire onUpdate if not suppressed.
	old.holdInterval = 1
	m.recordFailure(old, context.DeadlineExceeded)
	m.recordFailure(old, context.DeadlineExceeded)
	// If the drop fired onUpdate, calls would move; stale must stay silent.
	if got := calls.Load(); got != 2 {
		t.Fatalf("stale recordFailure published: onUpdate calls = %d, want still 2 (#9916 F-133)", got)
	}
}
