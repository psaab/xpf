// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package feeds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

var labFeedAllowlist10177 = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

func newLabManager10177(onUpdate func() error) *Manager {
	m := New(onUpdate)
	m.SetPrivateFeedAllowlist(labFeedAllowlist10177)
	return m
}

// TestFeedFetcherRefusesDirectPrivateIP10177 is the #10177 fail-on-revert
// cell for directly-configured internal URLs. A feed URL whose host is a
// loopback/private/link-local literal must be refused before any byte is
// sent — the fetcher is a blind-SSRF primitive otherwise, bounded only by
// the 32MiB/1M-entry caps.
//
// The manager here is deliberately default-deny: it bypasses the newFeed
// test helper (which allowlists loopback test servers as lab feeds) and
// wires the feedState directly, mirroring TestFeedFetcherProxyHelper9912.
func TestFeedFetcherRefusesDirectPrivateIP10177(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := New(nil)
	fs := &feedState{name: "direct-private", url: server.URL + "/feed", holdInterval: retainForever}
	_, err := m.readFeed(context.Background(), fs)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("direct private-IP fetch error = %v, want refusal", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("private-IP server received %d requests, want 0", got)
	}
}

// TestFeedFetcherRefusesLoopbackHostname10177 is the #10177 fail-on-revert
// cell for the DNS-rebinding half: a same-hostname URL that RESOLVES to a
// non-public IP must be refused even though the hostname string itself is
// innocuous (same-origin checks compare strings, not addresses). localhost
// resolves to 127.0.0.1/::1 via /etc/hosts, so it is the stable,
// no-DNS-server stand-in for a rebinding hostname.
func TestFeedFetcherRefusesLoopbackHostname10177(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("test server URL %q unparseable: %v", server.URL, err)
	}
	feedURL := "http://localhost:" + u.Port() + "/feed"

	m := New(nil)
	fs := &feedState{name: "rebinding-host", url: feedURL, holdInterval: retainForever}
	_, err = m.readFeed(context.Background(), fs)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("loopback-hostname fetch error = %v, want refusal", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("loopback-hostname server received %d requests, want 0", got)
	}
}

// TestFeedFetcherAllowsLabPrivateIP10177 is the explicit lab override control:
// the same loopback destination refused by the default manager is fetched when
// the lab process allowlists its fixture network.
func TestFeedFetcherAllowsLabPrivateIP10177(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := New(nil)
	m.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	fs := &feedState{name: "lab-private", url: server.URL + "/feed", holdInterval: retainForever}
	res, err := m.readFeed(context.Background(), fs)
	if err != nil {
		t.Fatalf("allowlisted lab feed: %v", err)
	}
	if got := res.prefixes; len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("allowlisted lab feed prefixes = %v, want [203.0.113.0/24]", got)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("allowlisted lab feed received %d requests, want 1", got)
	}
}

func TestFeedDestinationPublicAddressAllowed10177(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("parse public address %q: %v", raw, err)
		}
		if feedDestinationBlocked(ip) {
			t.Errorf("public address %s was classified as blocked", ip)
		}
	}
}

// TestPinnedFeedClientAvoidsDNSReResolution10177 proves the TOCTOU boundary
// independently of the resolver: once a validated address is supplied, the
// transport reaches it even when the request hostname has no DNS record.
func TestPinnedFeedClientAvoidsDNSReResolution10177(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("test server URL %q unparseable: %v", server.URL, err)
	}
	client, err := pinnedFeedClient(
		New(nil).client,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
		u.Port(),
	)
	if err != nil {
		t.Fatalf("pinning feed client: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://dns-rebind.invalid:"+u.Port()+"/feed", nil)
	if err != nil {
		t.Fatalf("building pinned request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("pinned request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned request status = %d, want 200", resp.StatusCode)
	}
}

// TestFeedFetcherPinsPublicAnswerAgainstRebind10177 exercises the complete
// resolve/check/dial boundary through readFeed. The first resolver answer is a
// synthetic public address mapped to the local fixture by the test dialer. If
// readFeed hands the original hostname to that dialer, the simulated second
// lookup returns loopback and the request fails; the fixed path supplies only
// the validated public address and succeeds without a second lookup.
func TestFeedFetcherPinsPublicAnswerAgainstRebind10177(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("test server URL %q unparseable: %v", server.URL, err)
	}
	const hostname = "dns-rebind.invalid"
	public := netip.MustParseAddr("198.51.100.10")
	private := netip.MustParseAddr("127.0.0.1")
	var resolverCalls, internalAttempts atomic.Int32

	m := New(nil)
	m.resolveFeedIPs = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != hostname {
			return nil, fmt.Errorf("unexpected resolver host %q", host)
		}
		if resolverCalls.Add(1) == 1 {
			return []netip.Addr{public}, nil
		}
		return []netip.Addr{private}, nil
	}
	transport := m.client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if host == public.String() {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}
		if host == hostname {
			answers, resolveErr := m.resolveFeedIPs(ctx, host)
			if resolveErr == nil && len(answers) == 1 && answers[0].Unmap() == private {
				internalAttempts.Add(1)
			}
			return nil, fmt.Errorf("simulated DNS rebinding to internal address")
		}
		return nil, fmt.Errorf("unexpected dial target %q", host)
	}

	fs := &feedState{name: "public-rebind", url: "http://" + hostname + ":" + u.Port() + "/feed"}
	res, err := m.readFeed(context.Background(), fs)
	if err != nil {
		t.Fatalf("public answer was not fetched through its pinned address: %v", err)
	}
	if len(res.prefixes) != 1 || res.prefixes[0] != "203.0.113.0/24" {
		t.Fatalf("public-rebind prefixes = %v, want [203.0.113.0/24]", res.prefixes)
	}
	if got := resolverCalls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want exactly one", got)
	}
	if got := internalAttempts.Load(); got != 0 {
		t.Fatalf("dial attempted the rebinding internal answer %d times", got)
	}
}
