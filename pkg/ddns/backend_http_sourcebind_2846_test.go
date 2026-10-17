package ddns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_http_sourcebind_2846_test.go: FAIL-ON-REVERT coverage for #2846 —
// the HTTP DDNS backends (Cloudflare/Route53/dyndns2/generic) and the checkip
// probe must dial from the operator-configured source-address, not the kernel
// default route. Before #2846 only RFC 2136 honored the source binding; these
// tests go RED if the bound HTTP client / DialContext is removed.

// TestHTTPClientUnboundHasNoDialContext proves the DEFAULT (no source-address)
// path is unchanged: the Transport gets no DialContext override, so behaviour is
// byte-for-byte the kernel default-route dial. If a future change always wires a
// DialContext (changing default behaviour) this fails.
func TestHTTPClientUnboundHasNoDialContext(t *testing.T) {
	c := newHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.Transport)
	}
	if tr.DialContext != nil {
		t.Fatal("unbound HTTP client must not install a DialContext (default route)")
	}

	// A provider with no source-binding leaves yields the same unbound client.
	c2, err := newProviderHTTPClient(&config.DDNSProvider{Name: "p"})
	if err != nil {
		t.Fatalf("newProviderHTTPClient(no-bind): %v", err)
	}
	tr2 := c2.Transport.(*http.Transport)
	if tr2.DialContext != nil {
		t.Fatal("provider with no source-address must not install a DialContext")
	}
}

// TestHTTPClientBoundInstallsDialContext proves a configured source-address
// installs a DialContext (the source-bind hook). Goes RED if the bind plumbing
// is removed from newHTTPClientBound.
func TestHTTPClientBoundInstallsDialContext(t *testing.T) {
	c, err := newProviderHTTPClient(&config.DDNSProvider{
		Name:          "p",
		SourceAddress: "127.0.0.2",
	})
	if err != nil {
		t.Fatalf("newProviderHTTPClient(bound): %v", err)
	}
	tr := c.Transport.(*http.Transport)
	if tr.DialContext == nil {
		t.Fatal("configured source-address must install a source-binding DialContext")
	}
}

// TestHTTPClientBoundDialsFromSourceAddress is the end-to-end FAIL-ON-REVERT:
// a client built with source-address 127.0.0.2 must connect to a loopback HTTP
// server with that exact source IP (the server observes RemoteAddr == 127.0.0.2).
// If the source bind is dropped, the OS default-route source (127.0.0.1 for a
// loopback dial) is used and this assertion fails.
func TestHTTPClientBoundDialsFromSourceAddress(t *testing.T) {
	const wantSrc = "127.0.0.2"

	gotSrc := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		select {
		case gotSrc <- host:
		default:
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := newProviderHTTPClient(&config.DDNSProvider{
		Name:          "p",
		SourceAddress: wantSrc,
	})
	if err != nil {
		t.Fatalf("newProviderHTTPClient: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	src := <-gotSrc
	if src != wantSrc {
		t.Fatalf("dial source = %q, want %q (source bind not applied)", src, wantSrc)
	}
}

// TestCheckIPClientBoundDialsFromSourceAddress proves the checkip probe path
// (NewCheckIPClient → CheckIP) is bound to the provider source-address too. Goes
// RED if checkip is left on the default route.
func TestCheckIPClientBoundDialsFromSourceAddress(t *testing.T) {
	const wantSrc = "127.0.0.2"

	gotSrc := make(chan string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		select {
		case gotSrc <- host:
		default:
		}
		// A valid public v4 the checkip parser will accept.
		_, _ = w.Write([]byte("198.51.100.7"))
	}))
	defer srv.Close()

	client, err := NewCheckIPClient(&config.DDNSProvider{
		Name:          "p",
		SourceAddress: wantSrc,
		CheckIPURL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("NewCheckIPClient: %v", err)
	}
	// Trust the test server's certificate on the real production transport
	// while keeping its source-bound DialContext.
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs =
		srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	// wantV4=true; allowlist nil. The response is TEST-NET (rejected by the
	// public gate) so the ADDRESS result is irrelevant here — we only assert the
	// dial source. CheckIP still performs the bound dial.
	_, _, _ = CheckIP(context.Background(), client, srv.URL, true, nil)

	src := <-gotSrc
	if src != wantSrc {
		t.Fatalf("checkip dial source = %q, want %q (source bind not applied)", src, wantSrc)
	}
}

// TestProviderBindConfigInvalidSourceErrors proves a malformed source-address is
// a hard error so the backend constructor degrades to no-op rather than
// publishing from the wrong source (fail-open posture, mirrors RFC 2136).
func TestProviderBindConfigInvalidSourceErrors(t *testing.T) {
	_, err := newProviderHTTPClient(&config.DDNSProvider{
		Name:          "p",
		SourceAddress: "not-an-ip",
	})
	if err == nil {
		t.Fatal("malformed source-address must error")
	}
	if !strings.Contains(err.Error(), "source-address") {
		t.Fatalf("error should name source-address, got %v", err)
	}

	// And the backend constructors must surface it (degrade to no-op upstream).
	if _, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "p", APIToken: config.Secret("t"), Zone: "example.net",
		SourceAddress: "not-an-ip",
	}, nil); err == nil {
		t.Fatal("cloudflare with malformed source-address must error")
	}
}
