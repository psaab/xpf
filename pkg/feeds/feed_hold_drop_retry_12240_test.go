package feeds

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRejectedHoldDropPublishIsRetried12240 is the #12240 regression cell: a
// hold-expiry drop whose empty-set apply is REJECTED must be retried until the
// empty state lands. Publication debt reflects the pending drop until then,
// and a later accepted retry converges the dataplane to empty.
func TestRejectedHoldDropPublishIsRetried12240(t *testing.T) {
	var calls int
	reject := false
	m := New(func() error {
		calls++
		if reject {
			return errors.New("synthetic empty-set apply rejection")
		}
		return nil
	})
	server := &bodyServer{}
	server.set("198.51.100.0/24\n", http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Second)

	// Install a snapshot with an ACCEPTED apply so the published baseline is
	// the good content (not the empty set): call 1 succeeds, then reject.
	m.fetchFeed(context.Background(), fs)
	if calls != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", calls)
	}
	reject = true

	// Exercise the #12241 wall-clock expiry path directly. It drops the
	// snapshot and invokes onUpdate, whose empty-set apply is rejected.
	server.set("", http.StatusInternalServerError)
	fs.staleSince = time.Now().Add(-time.Minute)
	m.expireStaleHold(fs)
	if calls != 2 {
		t.Fatalf("hold expiry: onUpdate calls = %d, want 2 (one drop publish attempt)", calls)
	}

	// STEP-0: the manager reports dropped while the dataplane never accepted
	// the empty set. Debt must surface the pending drop.
	info := m.AllFeeds()["f"]
	if !info.HoldDropped || info.Prefixes != 0 || !info.PublicationDebt {
		t.Fatalf("rejected hold-drop status = %+v, want empty installed state with publication debt", info)
	}

	// The defect: a further failing fetch fires no retry, so the dataplane
	// keeps the stale last-good contents indefinitely. A subsequent failing
	// fetch must re-drive the drop publish.
	m.fetchFeed(context.Background(), fs)
	if calls != 3 {
		t.Fatalf("retry fetch: onUpdate calls = %d, want 3 — a rejected hold-drop publish MUST be retried, not single-shot", calls)
	}
	info = m.AllFeeds()["f"]
	if !info.PublicationDebt {
		t.Fatalf("pending-drop status = %+v, want publication debt retained until the empty state lands", info)
	}

	// Once the apply is accepted, the empty state lands and debt clears.
	reject = false
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("accepted retry: onUpdate calls = %d, want 4", calls)
	}
	info = m.AllFeeds()["f"]
	if info.PublicationDebt {
		t.Fatalf("converged status = %+v, want publication debt cleared after the accepted drop", info)
	}
	if !info.HasPublished || info.PublishedHash != fmt.Sprintf("%x", emptyFeedHash) {
		t.Fatalf("converged status = %+v, want the empty set recorded as published", info)
	}
	if got := m.GetPrefixes("f"); len(got) != 0 {
		t.Fatalf("GetPrefixes after accepted drop = %v, want empty", got)
	}
}
