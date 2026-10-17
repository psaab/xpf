package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feeds_snapshot_handoff_5282_test.go: #5282 — Apply must carry a PERSISTED
// feed's last-good enforced snapshot forward across a reconfigure so there is no
// fail-open denylist window. The pre-#5282 Apply called StopAll first, replacing
// m.feeds with an EMPTY map before the desired plan's producers fetched
// asynchronously. So editing a deny feed's URL/interval dropped its installed
// snapshot instantly (overlay compiles match-none); if the new endpoint was
// down, retainForever pinned the EMPTY set — traffic that should be DENIED was
// ALLOWED. These tests assert the carry-forward closes that window.

// waitFor polls cond until it returns true or the deadline elapses.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s: %s", d, msg)
}

// TestApplyReconfigureFailedFetchRetainsLastGood is the CORE fail-open guard: a
// persisted deny feed whose reconfigure fetch FAILS must keep enforcing its
// last-good prefixes — never an empty / match-none set. Reverting to the
// StopAll-drops-all-first behavior empties m.feeds before the async fetch, so
// both the immediate assertion (no snapshot after Apply) and the post-failure
// assertion (retainForever holds an EMPTY set) turn RED.
func TestApplyReconfigureFailedFetchRetainsLastGood(t *testing.T) {
	m := New(func() error { return nil })

	// 1) Install a deny feed's last-good snapshot from a healthy endpoint.
	good := &bodyServer{}
	good.set("203.0.113.0/24\n", http.StatusOK)
	goodTS := httptest.NewTLSServer(good.handler())
	trustLabFeedServer(m, goodTS)
	defer goodTS.Close()

	const feedName = "deny"
	fs := m.newFeed(feedName, goodTS.URL, retainForever)
	m.fetchFeed(context.Background(), fs)
	if got := m.GetPrefixes(feedName); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("precondition: last-good not installed: %v", got)
	}

	// 2) Reconfigure: SAME feed name, a NEW url whose endpoint is DOWN (500).
	down := &bodyServer{}
	down.set("hijacked-or-error", http.StatusInternalServerError)
	downTS := httptest.NewTLSServer(down.handler())
	trustLabFeedServer(m, downTS)
	defer downTS.Close()

	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: downTS.URL, FeedName: feedName, UpdateInterval: 3600},
		},
		AddressBindings: map[string]*config.AddressBinding{
			"denylist": {FeedNames: []string{feedName}},
		},
	}
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// Immediately after Apply — before the async re-fetch could have run — the
	// carried-forward snapshot must ALREADY be enforced (no match-none window).
	if got := m.GetPrefixes(feedName); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("fail-open: Apply dropped last-good for a persisted feed: got %v, want [203.0.113.0/24]", got)
	}

	// Let the NEW (failing) fetch resolve, then assert retainForever keeps the
	// last-good set indefinitely — the enforced set is NOT emptied.
	waitFor(t, 2*time.Second, func() bool {
		return m.AllFeeds()[feedName].LastError != ""
	}, "new endpoint fetch never recorded a failure")

	if got := m.GetPrefixes(feedName); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("fail-open: retainForever did not keep last-good after failed reconfigure fetch: got %v", got)
	}

	// The ENFORCEMENT accessor the daemon overlays into the dataplane
	// (SnapshotForBindings) must still carry the last-good denylist prefixes —
	// NOT an empty / match-none set. This is the actual fail-open surface.
	overlay := m.SnapshotForBindings(daCfg)
	if got := overlay["denylist"]; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("fail-open: denylist overlay emptied on failed reconfigure: got %v, want [203.0.113.0/24]", got)
	}
}

// TestApplyDropsRemovedFeed asserts a feed GENUINELY REMOVED from config has its
// snapshot dropped (correct — the operator removed it), while a persisted feed
// keeps its carried-forward snapshot. This is the removed-vs-persisted boundary:
// carry-forward must not resurrect a deleted feed.
func TestApplyDropsRemovedFeed(t *testing.T) {
	m := New(func() error { return nil })
	good := &bodyServer{}
	good.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewTLSServer(good.handler())
	trustLabFeedServer(m, ts)
	defer ts.Close()

	// Pre-seed two feeds' last-good snapshots.
	keep := m.newFeed("keep", ts.URL, retainForever)
	m.fetchFeed(context.Background(), keep)
	gone := m.newFeed("gone", ts.URL, retainForever)
	m.fetchFeed(context.Background(), gone)
	if got := m.GetPrefixes("gone"); len(got) != 1 {
		t.Fatalf("precondition: gone not installed: %v", got)
	}

	// Reconfigure with ONLY "keep" present; "gone" is removed from config.
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: ts.URL, FeedName: "keep", UpdateInterval: 3600},
		},
	}
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// "gone" is no longer a known feed at all (unknown-name -> nil).
	if got := m.GetPrefixes("gone"); got != nil {
		t.Errorf("removed feed still present: GetPrefixes(gone) = %v, want nil", got)
	}
	// "keep" persisted — carried forward immediately (no match-none window).
	if got := m.GetPrefixes("keep"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("persisted feed lost its snapshot across Apply: %v", got)
	}
}

// TestApplyReconfigureSuccessfulFetchReplacesSnapshot asserts the atomic swap is
// preserved: when the reconfigure's new endpoint is HEALTHY and serves a
// DIFFERENT set, the new fetch atomically REPLACES the carried-forward snapshot
// (no stale-union, no torn read) rather than leaving the old prefixes installed.
func TestApplyReconfigureSuccessfulFetchReplacesSnapshot(t *testing.T) {
	m := New(func() error { return nil })

	// Last-good from endpoint A.
	oldSrv := &bodyServer{}
	oldSrv.set("203.0.113.0/24\n", http.StatusOK)
	oldTS := httptest.NewTLSServer(oldSrv.handler())
	trustLabFeedServer(m, oldTS)
	defer oldTS.Close()

	const feedName = "deny"
	fs := m.newFeed(feedName, oldTS.URL, retainForever)
	m.fetchFeed(context.Background(), fs)

	// Reconfigure: a NEW, HEALTHY endpoint B serving a DIFFERENT set.
	newSrv := &bodyServer{}
	newSrv.set("198.51.100.0/24\n", http.StatusOK)
	newTS := httptest.NewTLSServer(newSrv.handler())
	trustLabFeedServer(m, newTS)
	defer newTS.Close()

	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: newTS.URL, FeedName: feedName, UpdateInterval: 3600},
		},
	}
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// The new fetch atomically replaces the carried-forward snapshot with B's set.
	waitFor(t, 2*time.Second, func() bool {
		got := m.GetPrefixes(feedName)
		return len(got) == 1 && got[0] == "198.51.100.0/24"
	}, "new fetch never replaced the carried-forward snapshot")

	// The carried-forward A set is fully gone — a clean atomic replace.
	if got := m.GetPrefixes(feedName); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("snapshot not atomically replaced: got %v, want [198.51.100.0/24]", got)
	}
}
