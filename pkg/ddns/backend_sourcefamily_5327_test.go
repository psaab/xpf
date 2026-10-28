package ddns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// backend_sourcefamily_5327_test.go: FAIL-ON-REVERT coverage for #5327 — a
// configured source-address is a multi-WAN / security egress pin and must ALWAYS
// be honored. Before #5327 the source bind was applied only when the dial socket
// family matched the source family; on a cross-family Happy-Eyeballs dial the
// bind was SILENTLY SKIPPED and the exchange egressed from a kernel-chosen source
// on the WRONG WAN (bypassing a source ACL / publishing the wrong address, with
// no error). The fix PINS the dial to the source family (cl.Net for RFC 2136, the
// Transport.DialContext wrapper for HTTP) so the other family can never be chosen;
// an endpoint with no address in the source family FAILS CLOSED at the dial.
//
// These tests stress the cross-family case that used to silently egress unbound:
// with the fix they FAIL CLOSED; with the fix reverted they SUCCEED via the
// unbound wrong-family dial (RED-on-revert).

// TestHTTPSourceFamilyFailsClosedCrossFamily proves the HTTP path (#2846 bound
// client) now FAILS CLOSED when the configured source-address family cannot reach
// the endpoint, instead of silently egressing unbound on the other family. An
// IPv6 source-address against an IPv4-only endpoint must not connect at all.
//
// RED-on-revert: with the family pin removed, Happy-Eyeballs dials the endpoint's
// IPv4 address, the family gate skips the v6 bind, the request SUCCEEDS unbound,
// and both assertions below fail.
func TestHTTPSourceFamilyFailsClosedCrossFamily(t *testing.T) {
	var hit int32
	// httptest.NewServer listens on 127.0.0.1 (IPv4 only).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&hit, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := newProviderHTTPClient(&config.DDNSProvider{
		Name: "p", // IPv6 source, IPv4-only endpoint,
		RFC2136Endpoint: config.RFC2136Endpoint{
			SourceAddress: "::1",
		},
	})
	if err != nil {
		t.Fatalf("newProviderHTTPClient: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("v6 source-address against an IPv4-only endpoint must FAIL CLOSED, " +
			"not egress unbound on the IPv4 family")
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("IPv4-only endpoint was reached — the dial was not pinned to the " +
			"source family and egressed unbound (the #5327 silent-skip)")
	}
}

// TestHTTPSourceV4EndpointV6OnlyFailsClosed is the issue-exact scenario: an IPv4
// source-address against an IPv6-ONLY endpoint. The dial is pinned to IPv4, the
// v6-only endpoint has no IPv4 address, so the update FAILS CLOSED rather than
// egressing unbound on the v6 family. Skipped if the host has no IPv6 loopback.
func TestHTTPSourceV4EndpointV6OnlyFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	var hit int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&hit, 1)
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/" // http://[::1]:port/
	c, err := newProviderHTTPClient(&config.DDNSProvider{
		Name: "p", // IPv4 source, IPv6-only endpoint,
		RFC2136Endpoint: config.RFC2136Endpoint{
			SourceAddress: "127.0.0.2",
		},
	})
	if err != nil {
		t.Fatalf("newProviderHTTPClient: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("v4 source-address against an IPv6-only endpoint must FAIL CLOSED, " +
			"not egress unbound on the IPv6 family")
	}
	if atomic.LoadInt32(&hit) != 0 {
		t.Fatal("IPv6-only endpoint was reached — the dial was not pinned to the " +
			"source family and egressed unbound (the #5327 silent-skip)")
	}
}

// TestRFC2136SourceFamilyPinsNet proves the RFC 2136 backend pins the *dns.Client
// dial network to the configured source-address family (cl.Net "udp4"/"udp6"), so
// a dual-stack update-server hostname cannot let Happy-Eyeballs pick the other
// family and skip the source bind. A device-only / no-source config leaves cl.Net
// empty (today's dual-stack behaviour, byte-for-byte).
//
// RED-on-revert: without the pin the source cases leave cl.Net == "" and the two
// "udp4"/"udp6" assertions fail.
func TestRFC2136SourceFamilyPinsNet(t *testing.T) {
	mk := func(t *testing.T, src string) *dns.Client {
		t.Helper()
		c := &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", // TEST-NET, never dialed,
			RFC2136Endpoint: config.RFC2136Endpoint{
				UpdateServer: "192.0.2.53:53",
			},
		}
		if src != "" {
			c.SourceAddress = src
		}
		u, err := newRFC2136Updater(policyFromConfig(c), c.RFC2136Endpoint, nil, nil, nil)
		if err != nil {
			t.Fatalf("newRFC2136Updater(src=%q): %v", src, err)
		}
		dc, ok := u.client.(*dns.Client)
		if !ok {
			t.Fatalf("expected a real *dns.Client, got %T", u.client)
		}
		return dc
	}

	if dc := mk(t, "10.0.0.9"); dc.Net != "udp4" {
		t.Errorf("v4 source: cl.Net=%q, want udp4 (dial must be pinned to IPv4)", dc.Net)
	} else if dc.Dialer == nil {
		t.Error("v4 source: expected a source-binding Dialer")
	}
	if dc := mk(t, "2001:db8::9"); dc.Net != "udp6" {
		t.Errorf("v6 source: cl.Net=%q, want udp6 (dial must be pinned to IPv6)", dc.Net)
	} else if dc.Dialer == nil {
		t.Error("v6 source: expected a source-binding Dialer")
	}
	// No source-address: no family pin, no custom dialer — dual-stack default,
	// unchanged from pre-#5327.
	if dc := mk(t, ""); dc.Net != "" {
		t.Errorf("no source: cl.Net=%q, want empty (default dual-stack dial)", dc.Net)
	} else if dc.Dialer != nil {
		t.Error("no source: expected no custom Dialer (default dual-stack dial)")
	}
}

// TestRFC2136SourceFamilyFailsClosedCrossFamily drives the whole real *dns.Client
// dial path: an IPv6 source-address against an IPv4-only update server. With the
// family pin the exchange FAILS CLOSED (the pinned udp6 dial has no IPv4 address
// to reach), so UpsertLease returns an error instead of silently emitting the
// UPDATE from a kernel-chosen source on the wrong family.
//
// RED-on-revert: without the pin the client dials the update server over IPv4, the
// family gate skips the v6 source bind, the UPDATE SUCCEEDS unbound, and
// UpsertLease returns nil — the assertion below fails.
func TestRFC2136SourceFamilyFailsClosedCrossFamily(t *testing.T) {
	srv := newFakeDNSServer(t, nil) // listens on 127.0.0.1 (IPv4)
	c := &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", // IPv6 source, IPv4-only server,
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: srv.addrUDP,
			SourceAddress: "::1",
		},
	}
	u, err := newRFC2136Updater(policyFromConfig(c), c.RFC2136Endpoint, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRFC2136Updater: %v", err)
	}
	if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err == nil {
		t.Fatal("v6 source-address against an IPv4-only update server must FAIL CLOSED; " +
			"UpsertLease returned nil — the UPDATE egressed unbound on IPv4 (the #5327 " +
			"silent-skip)")
	}
}
