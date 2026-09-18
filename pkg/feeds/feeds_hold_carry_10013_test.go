package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feeds_hold_carry_10013_test.go: #10013 — a no-op reconfiguration dropped the
// persisted holdDropped state. carryForwardSnapshot copies prefixes/hash/
// publication but not failure markers, and a hold-dropped predecessor has NO
// snapshot (the drop cleared prefixes/hasSnapshot), so carry returned
// immediately. The successor then looked never-fetched: the #9689
// fail-mode-drop published-empty row flipped to a #5645 omission
// (whole-snapshot retention — fail-safe, but silently lost), and later
// failures could never rederive holdDropped without a new successful
// snapshot, so the #9689 published-drop loss recurred on every persisting
// reconfig with recovery unbounded by any hold interval.
//
// The fix carries holdDropped (enforced drop semantics under #9689, not mere
// failure history) into the replacement feedState. These cells drive a real
// no-op Apply — same feed name, URL, hold and interval — against a DOWN
// endpoint so the post-Apply fetch deterministically fails.

// applyNoopReconfigAfterHoldDrop10013 hold-drops feedName, then applies a
// no-op reconfigure (same name/URL/hold/interval) whose endpoint is DOWN, and
// returns the manager, the applied config, and the down server (so a cell can
// flip it healthy to test recovery).
func applyNoopReconfigAfterHoldDrop10013(t *testing.T, feedName string) (*Manager, *config.DynamicAddressConfig, *bodyServer) {
	t.Helper()
	m := newLabManager10177(func() error { return nil })
	down := &bodyServer{}
	down.set("hijacked-or-error", http.StatusInternalServerError)
	downTS := httptest.NewServer(down.handler())
	t.Cleanup(downTS.Close)

	fs := holdDrop9689(t, m, feedName, []string{"198.51.100.0/24"})
	// True no-op: the fixture URL is never fetched (no producer runs before
	// Apply), so repoint the predecessor at the plan URL. Carry is keyed by
	// feed name; the URL equality makes the reconfig a strict no-op.
	m.mu.Lock()
	fs.url = downTS.URL
	m.mu.Unlock()
	m.now = time.Now // release the fixture's injected clock

	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: downTS.URL, FeedName: feedName, UpdateInterval: 3600, HoldInterval: 60},
		},
		AddressBindings: map[string]*config.AddressBinding{
			"partners": {Name: "partners", FeedNames: []string{feedName}, FailMode: "drop"},
		},
	}
	m.Apply(context.Background(), daCfg)
	t.Cleanup(m.StopAll)
	return m, daCfg, down
}

// TestNoopReconfigPreservesHoldDrop10013: immediately after a no-op Apply, the
// replacement feedState must still be hold-dropped and the fail-mode-drop
// binding must still publish as a present empty row. Reverting the carry
// loses the marker, so the binding flips to omitted (RED).
func TestNoopReconfigPreservesHoldDrop10013(t *testing.T) {
	const feedName = "partner-feed"
	m, daCfg, _ := applyNoopReconfigAfterHoldDrop10013(t, feedName)

	if !m.AllFeeds()[feedName].HoldDropped {
		t.Fatal("no-op reconfig lost the hold-drop marker: AllFeeds no longer reports HoldDropped")
	}
	got, ok := m.SnapshotForBindings(daCfg)["partners"]
	if !ok {
		t.Fatal("fail-mode drop omitted a hold-dropped binding right after a no-op reconfig; it must stay published as an empty set")
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("fail-mode drop published %#v after a no-op reconfig, want a present empty slice", got)
	}
	// The retain default is unchanged across the reconfig: still omitted.
	if _, ok := m.SnapshotForBindings(failModeCfg9689("retain", feedName))["partners"]; ok {
		t.Fatal("fail-mode retain published a hold-dropped binding after a no-op reconfig; it must stay omitted")
	}
}

// TestContinuedFailureAfterReconfigPreservesDrop10013: continued failure after
// the no-op reconfig must keep the drop semantics (not silently revert to
// omission), and a subsequent successful fetch must recover immediately —
// recovery is NOT gated on another hold interval.
func TestContinuedFailureAfterReconfigPreservesDrop10013(t *testing.T) {
	const feedName = "partner-feed"
	m, daCfg, down := applyNoopReconfigAfterHoldDrop10013(t, feedName)

	// Let the post-Apply (failing) fetch resolve, then assert the drop is
	// still enforced — continued failure rederives/retains it.
	waitFor(t, 2*time.Second, func() bool {
		return m.AllFeeds()[feedName].LastError != ""
	}, "post-reconfig fetch never recorded a failure")
	if !m.AllFeeds()[feedName].HoldDropped {
		t.Fatal("continued failure after a no-op reconfig lost the hold-drop marker")
	}
	got, ok := m.SnapshotForBindings(daCfg)["partners"]
	if !ok {
		t.Fatal("fail-mode drop omitted a hold-dropped binding after continued post-reconfig failure; it must stay published as an empty set")
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("fail-mode drop published %#v after continued post-reconfig failure, want a present empty slice", got)
	}

	// Recovery: a healthy refetch clears the carried drop immediately — no
	// fresh hold window is imposed by the reconfig.
	down.set("198.51.100.0/24\n", http.StatusOK)
	m.mu.RLock()
	cur := m.feeds[feedName]
	m.mu.RUnlock()
	m.fetchFeed(context.Background(), cur)
	if cur.holdDropped || m.AllFeeds()[feedName].HoldDropped {
		t.Fatal("a successful fetch after the reconfig did not clear the carried hold-drop marker")
	}
	if got := m.SnapshotForBindings(daCfg)["partners"]; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("after recovery the binding resolves to %v, want [198.51.100.0/24]", got)
	}
}

// TestNoopReconfigDoesNotInventHoldDrop10013 is the OVER-BROAD control: a
// fix that unconditionally marked every carried feed hold-dropped would pass
// the cells above and wrongly publish never-fetched bindings. A feed with no
// first snapshot must stay unmarked across the reconfig and keep the #5645
// fail-closed omission under both modes.
func TestNoopReconfigDoesNotInventHoldDrop10013(t *testing.T) {
	m := newLabManager10177(func() error { return nil })
	down := &bodyServer{}
	down.set("hijacked-or-error", http.StatusInternalServerError)
	downTS := httptest.NewServer(down.handler())
	t.Cleanup(downTS.Close)

	const feedName = "not-yet"
	m.newFeed(feedName, downTS.URL, time.Minute)
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: downTS.URL, FeedName: feedName, UpdateInterval: 3600, HoldInterval: 60},
		},
		AddressBindings: map[string]*config.AddressBinding{
			"partners": {Name: "partners", FeedNames: []string{feedName}, FailMode: "drop"},
		},
	}
	m.Apply(context.Background(), daCfg)
	t.Cleanup(m.StopAll)

	if m.AllFeeds()[feedName].HoldDropped {
		t.Fatal("no-op reconfig marked a never-fetched feed hold-dropped")
	}
	if _, ok := m.SnapshotForBindings(daCfg)["partners"]; ok {
		t.Fatal("fail-mode drop published a never-fetched binding after a no-op reconfig; it must stay omitted")
	}
	if _, ok := m.SnapshotForBindings(failModeCfg9689("retain", feedName))["partners"]; ok {
		t.Fatal("fail-mode retain published a never-fetched binding after a no-op reconfig; it must stay omitted")
	}
}
