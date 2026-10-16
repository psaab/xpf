// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestFeedDestinationBlocksIPv6Transition14177 is the #14177 destination
// cell: NAT64, 6to4, Teredo and the other IPv6 transition / special-purpose
// ranges that stdlib IsGlobalUnicast still calls global must be blocked as
// feed destinations. A hostname resolving to 64:ff9b::a9fe:a9fe would
// otherwise be dialled through a NAT64 translator toward 169.254.169.254.
// Reverting the blockedFeedDestinationPrefixes IPv6 entries turns this RED.
func TestFeedDestinationBlocksIPv6Transition14177(t *testing.T) {
	blocked := []string{
		"64:ff9b::a9fe:a9fe", // NAT64 well-known -> 169.254.169.254
		"64:ff9b::a00:1",     // NAT64 well-known -> 10.0.0.1
		"64:ff9b:1::a00:1",   // NAT64 local-use
		"2002:a9fe:a9fe::1",  // 6to4, embedded 169.254.169.254
		"2001::ba3:0:0:0:0",  // Teredo (2001::/32 inside 2001::/23)
		"2001:1::1",          // 2001::/23 IETF protocol assignments
		"2001:db8::1",        // documentation
		"100::1",             // discard-only
		"100:0:0:1::1",       // dummy
		"5f00::1",            // SRv6 SID
		"3fff::1",            // documentation
		"fd00::1",            // ULA
	}
	for _, raw := range blocked {
		ip := netip.MustParseAddr(raw)
		if !feedDestinationBlocked(ip) {
			t.Errorf("transition/special address %s was NOT blocked as feed destination", raw)
		}
	}
	// Public controls must stay allowed.
	for _, raw := range []string{"2001:4860:4860::8888", "2606:4700:4700::1111", "8.8.8.8"} {
		ip := netip.MustParseAddr(raw)
		if feedDestinationBlocked(ip) {
			t.Errorf("public address %s was blocked as feed destination", raw)
		}
	}
}

// TestFeedFetcherRefusesNAT64Answer14177 exercises the full
// resolve -> validate -> dial boundary: a feed hostname whose (controlled)
// DNS answer is a NAT64 address embedding a metadata IPv4 must be refused
// before any request reaches a server. No live traffic is sent; the
// resolver is the package test seam and the fixture counts hits.
func TestFeedFetcherRefusesNAT64Answer14177(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := New(nil)
	m.resolveFeedIPs = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("64:ff9b::a9fe:a9fe")}, nil
	}
	fs := &feedState{name: "nat64-feed", url: "https://feeds.example.test/feed", holdInterval: retainForever}
	if _, err := m.readFeed(context.Background(), fs); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("NAT64 feed fetch error = %v, want refusal", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("fixture received %d requests, want 0", got)
	}
}

// TestJoinFeedURLQueryBase14177 is the #14177 URL-join cell. On master,
// Apply concatenated baseURL + path, so a query-bearing base produced
// .../base?token=abc/malware.txt. The join must place the path before
// the query and preserve the credential. Reverting joinFeedURL to
// concatenation turns this RED.
func TestJoinFeedURLQueryBase14177(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"https://feed.example/base?token=abc", "/malware.txt", "https://feed.example/base/malware.txt?token=abc"},
		{"https://feed.example/base?token=abc", "malware.txt", "https://feed.example/base/malware.txt?token=abc"},
		{"https://feed.example/base/?token=abc", "/malware.txt", "https://feed.example/base/malware.txt?token=abc"},
		{"https://feed.example?token=abc", "/malware.txt", "https://feed.example/malware.txt?token=abc"},
		{"https://feed.example/base", "/malware.txt", "https://feed.example/base/malware.txt"},
		{"https://feed.example/base", "", "https://feed.example/base"},
		{"https://feed.example/base?token=abc", "", "https://feed.example/base?token=abc"},
		// A per-feed path carrying its own query supersedes the base query.
		{"https://feed.example/base?token=abc", "/malware.txt?token=xyz", "https://feed.example/base/malware.txt?token=xyz"},
		// An absolute / scheme-relative path must not escape the origin.
		{"https://feed.example/base?token=abc", "//evil.example/malware.txt", "https://feed.example/base/malware.txt?token=abc"},
		{"https://user:pass@feed.example/base?token=abc", "/malware.txt", "https://user:pass@feed.example/base/malware.txt?token=abc"},
	}
	for _, tc := range cases {
		if got := joinFeedURL(tc.base, tc.path); got != tc.want {
			t.Errorf("joinFeedURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

// TestApplyQueryBaseFeedFetchesJoinedPath14177 proves the regression at
// the HTTP-handler level named by the issue: Apply with a query-bearing
// base URL and a per-feed path must request /base/<path>?token=... on
// the approved fixture, not /base?token=.../<path>.
func TestApplyQueryBaseFeedFetchesJoinedPath14177(t *testing.T) {
	var gotPath, gotToken atomic.Value
	gotPath.Store("")
	gotToken.Store("")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotToken.Store(r.URL.Query().Get("token"))
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := newLabManager10177(nil)
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"threat": {
				Name: "threat",
				URL:  server.URL + "/base?token=abc",
				FeedEntries: []config.FeedEntry{
					{Name: "malware", Path: "/malware.txt"},
				},
			},
		},
	}
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	m.mu.RLock()
	fs := m.feeds["malware"]
	m.mu.RUnlock()
	if fs == nil {
		t.Fatalf("Apply did not register feed malware; feeds=%v", m.AllFeeds())
	}
	if want := server.URL + "/base/malware.txt?token=abc"; fs.url != want {
		t.Fatalf("joined feed URL = %q, want %q", fs.url, want)
	}
	if _, err := m.readFeed(context.Background(), fs); err != nil {
		t.Fatalf("readFeed on joined URL: %v", err)
	}
	if got := gotPath.Load(); got != "/base/malware.txt" {
		t.Fatalf("fixture saw path %v, want /base/malware.txt", got)
	}
	if got := gotToken.Load(); got != "abc" {
		t.Fatalf("fixture saw token %v, want abc", got)
	}
}
