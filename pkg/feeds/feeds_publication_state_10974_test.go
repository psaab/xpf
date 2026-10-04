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

// TestRejectedApplyIsPublishedDebtOnOperatorState10974 ensures a successful
// fetch is not reported as enforced when onUpdate rejects its dataplane apply.
// The same status must clear only after a later identical refetch is accepted.
func TestRejectedApplyIsPublishedDebtOnOperatorState10974(t *testing.T) {
	reject := true
	m := New(func() error {
		if reject {
			return errors.New("synthetic apply rejection")
		}
		return nil
	})
	server := &bodyServer{}
	server.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Hour)

	m.fetchFeed(context.Background(), fs)
	debt := m.AllFeeds()["f"]
	wantHash := fmt.Sprintf("%x", fs.hash)
	if debt.Prefixes != 1 || debt.Hash != wantHash || !debt.PublicationDebt {
		t.Fatalf("rejected apply status = %+v, want one installed prefix and publication debt", debt)
	}
	if debt.HasPublished || debt.PublishedHash != "" {
		t.Fatalf("rejected apply reported published state: %+v", debt)
	}

	reject = false
	m.fetchFeed(context.Background(), fs)
	published := m.AllFeeds()["f"]
	if published.PublicationDebt || !published.HasPublished || published.PublishedHash != published.Hash {
		t.Fatalf("accepted retry status = %+v, want installed and published hashes to match", published)
	}
}

// TestRejectedHoldDropApplyRemainsPublicationDebt10974 covers the tightening
// direction: an unaccepted empty-set apply must not make the dropped feed look
// as though the dataplane has stopped enforcing its previous snapshot.
func TestRejectedHoldDropApplyRemainsPublicationDebt10974(t *testing.T) {
	calls := 0
	m := New(func() error {
		calls++
		if calls == 2 {
			return errors.New("synthetic empty-set apply rejection")
		}
		return nil
	})
	server := &bodyServer{}
	server.set("198.51.100.0/24\n", http.StatusOK)
	ts := httptest.NewServer(server.handler())
	defer ts.Close()
	fs := m.newFeed("f", ts.URL, time.Second)
	m.fetchFeed(context.Background(), fs)
	publishedHash := m.AllFeeds()["f"].PublishedHash
	if publishedHash == "" {
		t.Fatal("initial accepted apply did not establish published hash")
	}

	fs.staleSince = time.Now().Add(-time.Minute)
	m.recordFailure(fs, errors.New("synthetic fetch failure"))
	info := m.AllFeeds()["f"]
	if !info.HoldDropped || info.Prefixes != 0 || !info.PublicationDebt {
		t.Fatalf("rejected hold-drop status = %+v, want empty installed state with publication debt", info)
	}
	if info.PublishedHash != publishedHash || !info.HasPublished {
		t.Fatalf("rejected hold-drop overwrote last confirmed published state: got %+v, prior hash %s", info, publishedHash)
	}
}
