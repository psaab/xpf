// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package feeds

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestApplyAllowDestinationInstalls16656 is the #16656 runtime-arm pin:
// a feed-server whose IP-literal destination is covered by its
// `allow-destination` leaves installs its prefixes through Apply, while
// the identical server without the override registers no fetch (the
// destination is refused before any request reaches the server).
// Reverting the per-feed allowlist threading turns the override cell RED.
func TestApplyAllowDestinationInstalls16656(t *testing.T) {
	body := "10.9.0.0/24\n"

	run := func(t *testing.T, override bool) (*Manager, *atomic.Int32, *feedState) {
		t.Helper()
		m := New(nil)
		var hits atomic.Int32
		server := newLabTLSServer(m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte(body))
		}))
		host := strings.TrimPrefix(server.URL+"/feed", "https://")
		fsCfg := &config.FeedServer{Name: "onprem", URL: "https://" + host, FeedName: "onprem-feed"}
		if override {
			fsCfg.AllowedDestinationPrefixes = []string{"127.0.0.0/8"}
		}
		cfg := &config.DynamicAddressConfig{FeedServers: map[string]*config.FeedServer{"onprem": fsCfg}}
		m.Apply(context.Background(), cfg)
		t.Cleanup(m.StopAll)
		fs, ok := m.feeds["onprem-feed"]
		if !ok {
			t.Fatalf("feed onprem-feed not registered: %v", m.feeds)
		}
		return m, &hits, fs
	}

	t.Run("with override the runtime arm installs", func(t *testing.T) {
		m, _, fs := run(t, true)
		res, err := m.readFeed(context.Background(), fs)
		if err != nil {
			t.Fatalf("override feed must fetch, got: %v", err)
		}
		found := false
		for _, p := range res.prefixes {
			if p == "10.9.0.0/24" {
				found = true
			}
		}
		if !found {
			t.Fatalf("override feed returned %v, want 10.9.0.0/24", res.prefixes)
		}
	})

	t.Run("without override the destination is refused", func(t *testing.T) {
		m, hits, fs := run(t, false)
		if _, err := m.readFeed(context.Background(), fs); err == nil {
			t.Fatal("default-deny feed must refuse the loopback destination")
		} else if !strings.Contains(err.Error(), "blocked address") {
			t.Fatalf("refusal should name the blocked destination, got: %v", err)
		}
		if got := hits.Load(); got != 0 {
			t.Fatalf("refused fetch reached the server %d times", got)
		}
	})

	// Direct predicate parity: the shared config predicate and the feeds
	// spelling must agree, so the commit gate cannot drift from runtime.
	t.Run("shared predicate parity", func(t *testing.T) {
		for _, raw := range []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "fd00::1", "8.8.8.8", "2001:4860:4860::8888"} {
			ip := netip.MustParseAddr(raw)
			if feedDestinationBlocked(ip) != config.FeedDestinationBlocked(ip) {
				t.Errorf("predicate drift for %s", raw)
			}
		}
	})
}
