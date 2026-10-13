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
	now := time.Now()
	var calls int
	reject := false
	m := New(func() error {
		calls++
		if reject {
			return errors.New("synthetic empty-set apply rejection")
		}
		return nil
	})
	m.now = func() time.Time { return now }
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
	fs.staleSince = now.Add(-time.Minute)
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

	// The first failed fetch inside the retry backoff is quiet; after the
	// initial delay, the next failed fetch re-drives the rejected empty apply.
	m.fetchFeed(context.Background(), fs)
	if calls != 2 {
		t.Fatalf("fetch inside retry backoff: onUpdate calls = %d, want 2", calls)
	}
	now = now.Add(feedDropRetryInitialDelay)
	m.fetchFeed(context.Background(), fs)
	if calls != 3 {
		t.Fatalf("scheduled retry fetch: onUpdate calls = %d, want 3 — a rejected hold-drop MUST be retried after backoff", calls)
	}
	info = m.AllFeeds()["f"]
	if !info.PublicationDebt {
		t.Fatalf("pending-drop status = %+v, want publication debt retained until the empty state lands", info)
	}

	// Once the apply is accepted, the empty state lands and debt clears.
	reject = false
	now = now.Add(2 * feedDropRetryInitialDelay)
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("accepted retry: onUpdate calls = %d, want 4", calls)
	}
	if fs.dropRetryDelay != 0 || !fs.dropRetryAt.IsZero() {
		t.Fatalf("accepted drop retry state delay=%v at=%v, want cleared",
			fs.dropRetryDelay, fs.dropRetryAt)
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

	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("post-convergence failure: onUpdate calls = %d, want 4 (no thrash)", calls)
	}
}

// TestRejectedHoldDropIdenticalRecoveryRepublishes12240 covers recovery to the
// same content that was last confirmed before an unconfirmed hold-drop.
func TestRejectedHoldDropIdenticalRecoveryRepublishes12240(t *testing.T) {
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
	const content = "198.51.100.0/24\n"
	server.set(content, http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Second)

	m.fetchFeed(context.Background(), fs)
	if calls != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", calls)
	}
	reject = true
	server.set("", http.StatusInternalServerError)
	fs.staleSince = time.Now().Add(-time.Minute)
	m.expireStaleHold(fs)
	if calls != 2 {
		t.Fatalf("hold expiry: onUpdate calls = %d, want 2", calls)
	}
	if info := m.AllFeeds()["f"]; !info.PublicationDebt {
		t.Fatalf("rejected hold-drop status = %+v, want publication debt", info)
	}

	reject = false
	server.set(content, http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if calls != 3 {
		t.Fatalf("identical recovery: onUpdate calls = %d, want 3", calls)
	}
	if info := m.AllFeeds()["f"]; info.PublicationDebt || !info.HasPublished {
		t.Fatalf("identical recovery status = %+v, want accepted publication with no debt", info)
	}
}
