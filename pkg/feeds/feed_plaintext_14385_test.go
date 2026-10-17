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

// TestApplyRefusesPlaintextFeed14385 is the #14385 (DR5-H13) fail-on-revert
// pin for the load-bearing runtime half: Manager.Apply must NOT register a
// plaintext-http feed, so a MITM-substituted body (legit set + attacker /32,
// or a gradual-churn rotation) never reaches installSnapshot and never
// changes the enforced address-book row. Reverting the isPlaintextFeedURL
// skip in Apply turns this RED (the attacker body installs and the binding
// publishes the attacker prefix).
func TestApplyRefusesPlaintextFeed14385(t *testing.T) {
	var hits atomic.Int32
	// Attacker body: legitimate prefix plus a victim /32 a deny feed would
	// block, plus a second step modelling gradual churn.
	attacker := &bodyServer{}
	attacker.set("192.0.2.0/24\n203.0.113.7/32\n", http.StatusOK)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		attacker.handler()(w, r)
	}))
	defer ts.Close()

	m := newLabManager10177(func() error { return nil })
	const feedName = "threat"
	daCfg := denyBindingCfg(feedName, ts.URL) // ts.URL is http://127.0.0.1:...

	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// No worker is registered for the plaintext feed.
	if got := m.AllFeeds(); len(got) != 0 {
		if _, ok := got[feedName]; ok {
			t.Fatalf("plaintext-http feed %q was registered by Apply: %v", feedName, got)
		}
	}
	if got := m.GetPrefixes(feedName); got != nil {
		t.Fatalf("plaintext-http feed must have no feedState (nil prefixes), got %v", got)
	}
	// The enforced row is unchanged: the binding stays omitted (fail-closed
	// per #5645), so neither the spoofed superset nor a churn step publishes.
	if overlay := m.SnapshotForBindings(daCfg); len(overlay) != 0 {
		t.Fatalf("plaintext-http feed must not publish an enforced row, got %v", overlay)
	}

	// Gradual-churn step: even after the provider rotates its body, Apply
	// has started nothing, so no fetch ever occurs and nothing installs.
	attacker.set("198.51.100.0/24\n203.0.113.7/32\n", http.StatusOK)
	// Give any (incorrectly) started refresh loop a chance to fire.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hits.Load() != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("plaintext-http feed was fetched %d times, want 0 (no worker)", got)
	}
	if overlay := m.SnapshotForBindings(daCfg); len(overlay) != 0 {
		t.Fatalf("gradual-churn body changed the enforced row: %v", overlay)
	}
}

// TestApplyRefusesPlaintextFeedEntries14385 covers the per-feed-entry shape:
// every feed under a plaintext-http feed-server base is skipped, while a
// sibling https server on the same Apply still registers.
func TestApplyRefusesPlaintextFeedEntries14385(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7/32\n"))
	}))
	defer plain.Close()

	m := newLabManager10177(func() error { return nil })
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"plain": {
				Name: "plain",
				URL:  plain.URL,
				FeedEntries: []config.FeedEntry{
					{Name: "malware", Path: "/malware.txt"},
					{Name: "c2", Path: "/c2.txt"},
				},
			},
		},
	}
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	if got := m.AllFeeds(); len(got) != 0 {
		t.Fatalf("plaintext-http feed entries were registered: %v", got)
	}
	if overlay := m.SnapshotForBindings(daCfg); len(overlay) != 0 {
		t.Fatalf("plaintext-http entries must not publish an enforced row, got %v", overlay)
	}
}

// TestIsPlaintextFeedURL14385 pins the scheme predicate (case-insensitive
// http:// only; https and hostname-resolved URLs are unaffected).
func TestIsPlaintextFeedURL14385(t *testing.T) {
	cases := map[string]bool{
		"http://feeds.example/deny.txt":  true,
		"HTTP://feeds.example/deny.txt":  true,
		"Http://feeds.example/deny.txt":  true,
		"https://feeds.example/deny.txt": false,
		"https://http.example/deny.txt":  false,
		"feeds.example/deny.txt":         false,
		"":                               false,
	}
	for url, want := range cases {
		if got := isPlaintextFeedURL(url); got != want {
			t.Errorf("isPlaintextFeedURL(%q) = %v, want %v", url, got, want)
		}
	}
}

// TestApplyHTTPSFeedStillInstalls14385 is the control: the same valid body
// over https:// (httptest TLS) still registers and installs, so the
// plaintext refusal does not break legitimate feeds (criterion 4).
func TestApplyHTTPSFeedStillInstalls14385(t *testing.T) {
	good := &bodyServer{}
	good.set("192.0.2.0/24\n203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewTLSServer(good.handler())
	defer ts.Close()

	m := newLabManager10177(func() error { return nil })
	// Trust the httptest CA/leaf exactly as a lab fixture: production
	// verification is untouched; only this test manager's root pool gains
	// the fixture certificate.
	trustLabFeedServer(m, ts)

	const feedName = "threat"
	daCfg := denyBindingCfg(feedName, ts.URL) // ts.URL is https://127.0.0.1:...
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	waitFor(t, 5*time.Second, func() bool {
		got := m.SnapshotForBindings(daCfg)["denylist"]
		return len(got) == 2 && got[0] == "192.0.2.0/24" && got[1] == "203.0.113.0/24"
	}, "https feed never installed its valid body")
}
