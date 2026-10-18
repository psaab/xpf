// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestJoinFeedURLMalformedAndEdgePaths is the #14723 fixture. On master,
// joinFeedURL returned the base URL unchanged on any url.Parse error,
// built the joined URL from ref.Path only (dropping a // network-path
// host and a scheme:opaque colon form into an empty path), cleared
// RawPath (decoding %2F to / in the wire path), and resolveBaseURL
// trimmed trailing "/" from the raw URL string, cutting query/fragment
// tokens that end in "/". Each case converts an operator typo into
// silently fetching the base endpoint and installing its prefixes as
// enforced policy. Malformed or mistakable per-feed paths must be
// rejected ("" joined URL -> Apply registers no feed, fail-closed), and
// correct escapes / base query tokens must survive end to end.
func TestJoinFeedURLMalformedAndEdgePaths(t *testing.T) {
	const base = "https://feed.example/base?token=abc"

	// Rejected: joined "" means no fetch of any endpoint, least of all
	// the fetchable base.
	rejected := []string{
		"/denylist%ZZ.txt",           // url.Parse error (Case A)
		"//denylist.txt",             // network-path: host token, empty path (Case B)
		"v1:prod/list.txt",           // scheme:opaque colon form (Case C)
		"//evil.example/malware.txt", // network-path escape
		"https://evil.example/m.txt", // absolute URL escape
		"mailto:foo",                 // opaque scheme, no path
	}
	for _, p := range rejected {
		if got := joinFeedURL(base, p); got != "" {
			t.Errorf("joinFeedURL(%q, %q) = %q, want %q (rejected, no fetch)", base, p, got, "")
		}
	}

	// Accepted: escapes and ordinary forms survive intact.
	accepted := []struct{ base, path, want string }{
		{base, "/a%2Fb.txt", "https://feed.example/base/a%2Fb.txt?token=abc"},
		{base, "lists/v1:prod/list.txt", "https://feed.example/base/lists/v1:prod/list.txt?token=abc"},
		{base, "/list.txt?token=%ZZ", "https://feed.example/base/list.txt?token=%ZZ"},
		// resolveBaseURL: a trailing slash is trimmed from the base PATH
		// only, never from a query/fragment token that ends in "/".
		{resolveBaseURL(&config.FeedServer{URL: "https://feed.example/base/?token=abc/"}), "/list.txt", "https://feed.example/base/list.txt?token=abc/"},
		{"https://feed.example/base%2Fdir", "/list.txt", "https://feed.example/base%2Fdir/list.txt"},
	}
	for _, tc := range accepted {
		if got := joinFeedURL(tc.base, tc.path); got != tc.want {
			t.Errorf("joinFeedURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}

// TestApplyMalformedFeedPathFetchesNothing14723 exercises the exact
// mechanism at HTTP level: a query-bearing base serving a VALID prefix
// list at its base path, plus a malformed per-feed path. On master the
// join returned the base, readFeed fetched it, and the base prefixes
// were installed under the named feed. After the fix Apply must not
// register the feed and the fixture must see zero hits.
func TestApplyMalformedFeedPathFetchesNothing14723(t *testing.T) {
	for _, badPath := range []string{"/denylist%ZZ.txt", "//denylist.txt", "v1:prod/list.txt"} {
		t.Run(badPath, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("203.0.113.0/24\n"))
			}))
			defer server.Close()

			m := newLabManager10177(nil)
			trustLabFeedServer(m, server)
			daCfg := &config.DynamicAddressConfig{
				FeedServers: map[string]*config.FeedServer{
					"threat": {
						Name: "threat",
						URL:  server.URL + "/base?token=abc",
						FeedEntries: []config.FeedEntry{
							{Name: "malware", Path: badPath},
						},
					},
				},
			}
			m.Apply(context.Background(), daCfg)
			defer m.StopAll()

			m.mu.RLock()
			fs := m.feeds["malware"]
			m.mu.RUnlock()
			if fs != nil {
				t.Fatalf("Apply registered malformed feed path %q as url %q; want no feed (fail-closed)", badPath, fs.url)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("malformed feed path %q caused %d fetches; want 0", badPath, got)
			}
		})
	}
}

// TestApplyEscapedFeedPathPreserved14723 proves %2F survives end to end
// in the requested URI (RequestURI), not decoded to a path separator.
func TestApplyEscapedFeedPathPreserved14723(t *testing.T) {
	var gotURI atomic.Value
	gotURI.Store("")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI.Store(r.RequestURI)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := newLabManager10177(nil)
	trustLabFeedServer(m, server)
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"threat": {
				Name: "threat",
				URL:  server.URL + "/base?token=abc",
				FeedEntries: []config.FeedEntry{
					{Name: "malware", Path: "/a%2Fb.txt"},
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
		t.Fatalf("Apply did not register escaped feed; feeds=%v", m.AllFeeds())
	}
	if _, err := m.readFeed(context.Background(), fs); err != nil {
		t.Fatalf("readFeed on escaped joined URL: %v", err)
	}
	if got := gotURI.Load(); got != "/base/a%2Fb.txt?token=abc" {
		t.Fatalf("fixture saw RequestURI %v, want /base/a%%2Fb.txt?token=abc", got)
	}
	if !strings.Contains(fs.url, "%2F") {
		t.Fatalf("joined feed URL %q lost the %%2F escape", fs.url)
	}
}
