package feeds

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
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
	// Deterministic clock: every read advances 1s, so hold-interval math never
	// depends on real-time granularity between two back-to-back calls.
	base := time.Now()
	var tick atomic.Int64
	m.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Second) }

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

	// Same-name replacement: the guard is pointer-identity, NOT name-existence.
	// A removed-then-readded feed (fresh feedState, same name — exactly what
	// Apply builds for a persisted feed) publishes on its own completions while
	// the orphaned predecessor stays suppressed even though its name exists again.
	m.mu.Lock()
	replacement := &feedState{name: "victim", done: make(chan struct{})}
	m.feeds["victim"] = replacement
	m.mu.Unlock()
	m.installSnapshot(old, fetchResult{prefixes: []string{"192.0.2.99/32"}, hash: hashPrefixes([]string{"192.0.2.99/32"})})
	if got := calls.Load(); got != 1 {
		t.Fatalf("stale predecessor published after same-name replacement: onUpdate calls = %d, want still 1 (#9916 F-133)", got)
	}
	m.installSnapshot(replacement, fetchResult{prefixes: []string{"198.51.100.0/24"}, hash: hashPrefixes([]string{"198.51.100.0/24"})})
	if got := calls.Load(); got != 2 {
		t.Fatalf("same-name replacement suppressed: onUpdate calls = %d, want 2 (no over-suppression)", got)
	}

	// Positive control: a CURRENT feed under another name still publishes.
	m.mu.Lock()
	cur := &feedState{name: "live", done: make(chan struct{})}
	m.feeds["live"] = cur
	m.mu.Unlock()
	m.installSnapshot(cur, fetchResult{prefixes: []string{"192.0.2.0/24"}, hash: hashPrefixes([]string{"192.0.2.0/24"})})
	if got := calls.Load(); got != 3 {
		t.Fatalf("live installSnapshot suppressed: onUpdate calls = %d, want 3 (no over-suppression)", got)
	}

	// Stale recordFailure drop-to-empty must not publish either. Arm a 1s hold
	// interval on the orphan: the first failure enters stale, the second (clock
	// advanced past the hold) drops to empty and would fire onUpdate if not
	// suppressed. The injected clock above makes the elapse deterministic.
	old.holdInterval = time.Second
	m.recordFailure(old, context.DeadlineExceeded)
	m.recordFailure(old, context.DeadlineExceeded)
	// If the drop fired onUpdate, calls would move; stale must stay silent.
	if got := calls.Load(); got != 3 {
		t.Fatalf("stale recordFailure published: onUpdate calls = %d, want still 3 (#9916 F-133)", got)
	}
}

// #9916 F-133 (recheck half, parent-review follow-up): a feed that goes stale
// DURING its own onUpdate apply must not advance publishedHash on the orphan.
// Injects the swap inside onUpdate (a deterministic concurrent-Apply-during-
// publish) and asserts the orphan is not marked published. Without the recheck
// the advance is unconditional and the orphan records published state for an
// entry it no longer owns.
func TestPublishedHashRecheckSkipsStaleAdvance9916(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })
	m.mu.Lock()
	fs := &feedState{name: "f", done: make(chan struct{})}
	m.feeds["f"] = fs
	m.mu.Unlock()

	// Concurrent Apply lands mid-publish: replace the entry before onUpdate returns.
	m.onUpdate = func() error {
		calls.Add(1)
		m.mu.Lock()
		m.feeds["f"] = &feedState{name: "f", done: make(chan struct{})}
		m.mu.Unlock()
		return nil
	}
	res := fetchResult{prefixes: []string{"203.0.113.0/24"}, hash: hashPrefixes([]string{"203.0.113.0/24"})}
	m.installSnapshot(fs, res)

	if got := calls.Load(); got != 1 {
		t.Fatalf("onUpdate calls = %d, want 1 (fixture did not publish)", got)
	}
	if fs.hasPublished {
		t.Fatalf("orphan marked published after going stale mid-apply — recheck skipped nothing (#9916 F-133)")
	}
	m.mu.RLock()
	cur := m.feeds["f"]
	m.mu.RUnlock()
	if cur == fs {
		t.Fatal("fixture did not swap the entry mid-apply; recheck untested")
	}
	if cur.hasPublished {
		t.Fatalf("replacement incorrectly inherited published state from the orphan's apply")
	}
}
