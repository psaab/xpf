package feeds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRejectedHoldDropRetryUsesBackoff12639(t *testing.T) {
	var calls int
	reject := false
	m := New(func() error {
		calls++
		if reject {
			return errors.New("whole-snapshot refusal (retain omit)")
		}
		return nil
	})
	server := &bodyServer{}
	server.set("198.51.100.0/24\n", http.StatusOK)
	ts := httptest.NewServer(server.handler())
	t.Cleanup(ts.Close)
	fs := m.newFeed("f", ts.URL, 5*time.Second)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	m.fetchFeed(context.Background(), fs)
	if calls != 1 {
		t.Fatalf("initial fetch calls=%d, want 1", calls)
	}
	reject = true
	server.set("", http.StatusInternalServerError)
	m.fetchFeed(context.Background(), fs) // enter stale
	now = now.Add(5 * time.Second)
	m.fetchFeed(context.Background(), fs) // drop and reject publication
	if calls != 2 || !fs.holdDropped || fs.dropRetryDelay != feedDropRetryInitialDelay {
		t.Fatalf("first rejected drop: calls=%d dropped=%v delay=%v; want 2, true, %v",
			calls, fs.holdDropped, fs.dropRetryDelay, feedDropRetryInitialDelay)
	}

	// A rapidly polling provider must not trigger a full apply for every
	// unchanged refusal. Retry only when its scheduled deadline is reached.
	m.fetchFeed(context.Background(), fs)
	if calls != 2 {
		t.Fatalf("unchanged fetch inside backoff calls=%d, want 2", calls)
	}
	now = now.Add(feedDropRetryInitialDelay)
	m.fetchFeed(context.Background(), fs)
	if calls != 3 || fs.dropRetryDelay != 2*feedDropRetryInitialDelay {
		t.Fatalf("first scheduled retry: calls=%d delay=%v, want 3 and doubled delay",
			calls, fs.dropRetryDelay)
	}
	for fs.dropRetryDelay < feedDropRetryMaxDelay {
		now = now.Add(fs.dropRetryDelay)
		m.fetchFeed(context.Background(), fs)
	}
	if fs.dropRetryDelay != feedDropRetryMaxDelay {
		t.Fatalf("retry delay=%v, want capped at %v", fs.dropRetryDelay, feedDropRetryMaxDelay)
	}
	now = now.Add(feedDropRetryMaxDelay)
	m.fetchFeed(context.Background(), fs)
	if fs.dropRetryDelay != feedDropRetryMaxDelay {
		t.Fatalf("retry delay after capped retry=%v, want %v", fs.dropRetryDelay, feedDropRetryMaxDelay)
	}

	// Changed successful content bypasses retry backoff and publication debt,
	// then clears the drop retry state. Identical successful refresh is quiet.
	reject = false
	server.set("203.0.113.0/24\n", http.StatusOK)
	callsBeforeRecovery := calls
	m.fetchFeed(context.Background(), fs)
	if calls != callsBeforeRecovery+1 || fs.dropRetryDelay != 0 || !fs.dropRetryAt.IsZero() {
		t.Fatalf("changed recovery: calls=%d delay=%v retryAt=%v; want one publish and cleared state",
			calls, fs.dropRetryDelay, fs.dropRetryAt)
	}
	m.fetchFeed(context.Background(), fs)
	if calls != callsBeforeRecovery+1 {
		t.Fatalf("identical accepted recovery calls=%d, want %d", calls, callsBeforeRecovery+1)
	}

}

func TestRejectedHoldDropBackoffIsPerFeed12639(t *testing.T) {
	var calls int
	m := New(func() error { calls++; return errors.New("refused") })
	first := &feedState{name: "first", holdDropped: true, publishedHash: [32]byte{1}, hasPublished: true}
	second := &feedState{name: "second", holdDropped: true, publishedHash: [32]byte{1}, hasPublished: true}
	m.feeds[first.name] = first
	m.feeds[second.name] = second
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	m.recordFailure(first, errors.New("fetch failed"))
	if calls != 1 || first.dropRetryDelay != feedDropRetryInitialDelay || second.dropRetryDelay != 0 {
		t.Fatalf("first feed retry state: calls=%d first=%v second=%v", calls, first.dropRetryDelay, second.dropRetryDelay)
	}
	m.recordFailure(second, errors.New("fetch failed"))
	if calls != 2 || second.dropRetryDelay != feedDropRetryInitialDelay {
		t.Fatalf("second feed did not own an independent retry: calls=%d delay=%v", calls, second.dropRetryDelay)
	}
}
