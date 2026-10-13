package feeds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDoubleRejectedIdenticalRecoveryRetries12638 is the #12638 regression
// cell: the F1 republish of identical content after a rejected hold-drop is
// itself REJECTED. The rejected apply must leave publication debt and the
// next identical refetch must retry — not treat the content as published
// merely because publishedHash happens to equal the fetched hash.
func TestDoubleRejectedIdenticalRecoveryRetries12638(t *testing.T) {
	var calls int
	reject := false
	m := New(func() error {
		calls++
		if reject {
			return errors.New("synthetic apply rejection")
		}
		return nil
	})
	server := &bodyServer{}
	const content = "198.51.100.0/24\n"
	server.set(content, http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Second)

	// Initial content accepted: publishedHash == hash(P).
	m.fetchFeed(context.Background(), fs)
	if calls != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", calls)
	}

	// Hold-drop whose empty-set apply is rejected.
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

	// Recovery to identical content P; the republish is itself rejected.
	server.set(content, http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if calls != 3 {
		t.Fatalf("identical recovery: onUpdate calls = %d, want 3", calls)
	}
	if info := m.AllFeeds()["f"]; !info.PublicationDebt {
		t.Fatalf("double-rejected identical recovery status = %+v, want publication debt retained", info)
	}

	// The next identical refetch must retry the publish, not stay silent.
	reject = false
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("identical refetch after double rejection: onUpdate calls = %d, want 4 — a rejected republish MUST be retried on the next identical refetch", calls)
	}
	if info := m.AllFeeds()["f"]; info.PublicationDebt {
		t.Fatalf("accepted retry status = %+v, want publication debt cleared", info)
	}

	// No thrash once confirmed.
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("post-convergence refetch: onUpdate calls = %d, want 4 (no thrash)", calls)
	}
}

// TestAcceptedThenRejectedThenRevertRepublishes12638 covers the #5646
// content-revert variant of #12638: content P is accepted, content N is
// rejected, then the provider reverts to P. Because publishedHash still
// equals hash(P), the revert would be silently suppressed even though the
// dataplane may now hold the (rejected-but-staged) N state; it must
// republish P and report debt until that republish is accepted.
func TestAcceptedThenRejectedThenRevertRepublishes12638(t *testing.T) {
	var calls int
	reject := false
	m := New(func() error {
		calls++
		if reject {
			return errors.New("synthetic apply rejection")
		}
		return nil
	})
	server := &bodyServer{}
	const contentP = "198.51.100.0/24\n203.0.113.0/24\n"
	const contentN = "198.51.100.0/24\n203.0.113.0/24\n192.0.2.0/24\n"
	server.set(contentP, http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Second)

	// P accepted.
	m.fetchFeed(context.Background(), fs)
	if calls != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", calls)
	}
	if info := m.AllFeeds()["f"]; info.PublicationDebt {
		t.Fatalf("accepted P status = %+v, want no publication debt", info)
	}

	// N rejected: debt because installed hash != publishedHash.
	server.set(contentN, http.StatusOK)
	reject = true
	m.fetchFeed(context.Background(), fs)
	if calls != 2 {
		t.Fatalf("rejected N fetch: onUpdate calls = %d, want 2", calls)
	}
	if info := m.AllFeeds()["f"]; !info.PublicationDebt {
		t.Fatalf("rejected N status = %+v, want publication debt", info)
	}

	// Provider reverts to P. The revert must republish even though P's hash
	// equals publishedHash, and debt must remain while that republish is
	// rejected too.
	server.set(contentP, http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if calls != 3 {
		t.Fatalf("revert to P: onUpdate calls = %d, want 3 — reverting to last-published content after a rejected apply MUST republish", calls)
	}
	if info := m.AllFeeds()["f"]; !info.PublicationDebt {
		t.Fatalf("rejected revert status = %+v, want publication debt retained", info)
	}

	// Next identical (P) refetch retries until accepted.
	reject = false
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("identical P refetch: onUpdate calls = %d, want 4", calls)
	}
	if info := m.AllFeeds()["f"]; info.PublicationDebt {
		t.Fatalf("accepted revert retry status = %+v, want publication debt cleared", info)
	}
	m.fetchFeed(context.Background(), fs)
	if calls != 4 {
		t.Fatalf("post-convergence refetch: onUpdate calls = %d, want 4 (no thrash)", calls)
	}
}
