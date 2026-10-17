package api

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestDualStackListenerBindsBothFamilies14583 is the #14583 (Y07-02) api-level
// regression: a Server configured with one bind address per family must serve
// BOTH — the pre-fix single-leg lifecycle served only the first.
//
// FAIL-ON-REVERT: collapsing httpLegs/httpsLegs back to a single leg (or
// ignoring Config.Addrs/HTTPSAddrs) leaves one family unbound and this test
// goes RED.
func TestDualStackListenerBindsBothFamilies14583(t *testing.T) {
	// IPv6 loopback must exist for the v6 leg; skip where it does not.
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	} else {
		ln.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(Config{
		Addrs:      []string{"127.0.0.1:0", "[::1]:0"},
		TLS:        true,
		HTTPSAddrs: []string{"127.0.0.1:0", "[::1]:0"},
	})
	s.SetTLSCertDirForTest(t.TempDir())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()

	httpAddrs := s.EffectiveHTTPAddrs()
	if len(httpAddrs) != 2 {
		t.Fatalf("EffectiveHTTPAddrs = %v, want one bound address per family", httpAddrs)
	}
	httpsAddrs := s.EffectiveHTTPSAddrs()
	if len(httpsAddrs) != 2 {
		t.Fatalf("EffectiveHTTPSAddrs = %v, want one bound address per family", httpsAddrs)
	}
	if !s.HTTPServing() || !s.HTTPSServing() {
		t.Fatalf("serving = (http %v, https %v), want both planes fully serving", s.HTTPServing(), s.HTTPSServing())
	}

	// Every bound address actually answers.
	for _, addr := range httpAddrs {
		assertHTTP200(t, "http://"+addr+"/health")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test dial to self-signed mgmt cert
	defer tr.CloseIdleConnections()
	for _, addr := range httpsAddrs {
		assertHTTPS200(t, tr, "https://"+addr+"/health")
	}

	// Narrowing the HTTP set to one family retires the other leg only. (Uses
	// the REQUESTED addresses — leg identity is the configured bind, while the
	// effective addresses above carry ephemeral ports.)
	if err := s.ReconcileHTTPAddrs([]string{"127.0.0.1:0"}); err != nil {
		t.Fatalf("ReconcileHTTPAddrs narrow: %v", err)
	}
	if got := s.EffectiveHTTPAddrs(); len(got) != 1 || got[0] != httpAddrs[0] {
		t.Fatalf("after narrow, EffectiveHTTPAddrs = %v, want [%s]", got, httpAddrs[0])
	}
	if got := s.EffectiveHTTPSAddrs(); len(got) != 2 {
		t.Fatalf("narrowing HTTP disturbed HTTPS: EffectiveHTTPSAddrs = %v, want both families", got)
	}

	// A zoned link-local bind that cannot bind here (no such interface) must
	// fail for THAT leg while the loopback leg keeps serving — never a futile
	// whole-plane failure. Exercised via reconcile error, not Start.
	err := s.ReconcileHTTPAddrs([]string{"127.0.0.1:0", "[fe80::1%no-such-iface-14583]:0"})
	if err == nil {
		t.Fatal("zoned bind to a nonexistent interface must return an error for retry")
	}
	if got := s.EffectiveHTTPAddrs(); len(got) != 1 || got[0] != httpAddrs[0] {
		t.Fatalf("after sibling bind failure, EffectiveHTTPAddrs = %v, want [%s] still serving", got, httpAddrs[0])
	}
	assertHTTP200(t, "http://"+httpAddrs[0]+"/health")
}

func assertHTTP200(t *testing.T, url string) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
}

func assertHTTPS200(t *testing.T, tr *http.Transport, url string) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
}
