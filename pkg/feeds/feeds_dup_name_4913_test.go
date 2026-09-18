package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feeds_dup_name_4913_test.go: #4913 — two feed-servers declaring the same
// effective feed name must NOT start two refresh loops. The pre-#4913 Apply
// ranged the unordered FeedServers map and assigned m.feeds[name] = fs per
// entry, so a duplicate name started a SECOND refresh loop and OVERWROTE the
// first worker in the map — orphaning its cancel (StopAll then cancels only the
// survivor, so the overwritten loop keeps fetching until the parent context
// ends) — and the winning provider was nondeterministic (map order). Apply now
// builds a deterministic, de-duplicated plan and starts exactly ONE loop per
// name. Reverting that de-dup starts two loops → two initial fetches → RED.

// countingFeedServer serves a valid feed body and signals + counts every GET.
type countingFeedServer struct {
	count atomic.Int64
	hits  chan struct{}
}

func newCountingFeedServer() *countingFeedServer {
	return &countingFeedServer{hits: make(chan struct{}, 8)}
}

func (c *countingFeedServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		c.count.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
		select {
		case c.hits <- struct{}{}:
		default:
		}
	}
}

// TestApplyDeDupsDuplicateFeedNames proves Apply starts exactly one refresh loop
// for a feed name declared by two feed-servers, picks a DETERMINISTIC winner
// (lexicographically-first server), and does NOT orphan a second fetcher.
func TestApplyDeDupsDuplicateFeedNames(t *testing.T) {
	cs := newCountingFeedServer()
	ts := httptest.NewServer(cs.handler())
	defer ts.Close()

	m := newLabManager10177(func() error { return nil })
	// Two servers "aaa" and "bbb" each declare the SAME feed name "dup" with a
	// distinct path so the winner's URL is identifiable. Both hit the same
	// counting server. Winner must be the sorted-first server, "aaa".
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"aaa": {
				Name:        "aaa",
				URL:         ts.URL,
				FeedEntries: []config.FeedEntry{{Name: "dup", Path: "/aaa"}},
			},
			"bbb": {
				Name:        "bbb",
				URL:         ts.URL,
				FeedEntries: []config.FeedEntry{{Name: "dup", Path: "/bbb"}},
			},
		},
	}

	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// Exactly one worker is registered for the duplicated name, and it is the
	// deterministic winner (server "aaa", path /aaa).
	m.mu.RLock()
	nWorkers := len(m.feeds)
	winner, ok := m.feeds["dup"]
	var winnerURL string
	if ok {
		winnerURL = winner.url
	}
	m.mu.RUnlock()

	if nWorkers != 1 {
		t.Fatalf("expected exactly 1 registered feed worker, got %d", nWorkers)
	}
	if !ok {
		t.Fatal(`no worker registered for feed name "dup"`)
	}
	if winnerURL != ts.URL+"/aaa" {
		t.Fatalf("nondeterministic winner: feed %q url = %q, want %q (lexicographically-first server aaa)",
			"dup", winnerURL, ts.URL+"/aaa")
	}

	// The single worker's initial fetch must arrive.
	select {
	case <-cs.hits:
	case <-time.After(2 * time.Second):
		t.Fatal("the winning feed never fetched")
	}

	// A SECOND fetch would mean a duplicate refresh loop was started (the
	// orphaned-goroutine bug). The default update interval is 1h, so the
	// winner will not re-fetch within this window — any second hit is the leak.
	select {
	case <-cs.hits:
		t.Fatalf("a second fetch fired — the duplicate feed name started an orphaned refresh loop (#4913 regression); total fetches=%d",
			cs.count.Load())
	case <-time.After(time.Second):
		// good: exactly one refresh loop runs for the name.
	}

	if got := cs.count.Load(); got != 1 {
		t.Fatalf("expected exactly 1 total fetch, got %d (duplicate feed name started an orphaned loop)", got)
	}
}
