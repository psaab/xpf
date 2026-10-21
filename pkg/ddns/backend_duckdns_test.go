package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_duckdns_test.go: fail-on-revert (#2960) tests for the dedicated
// DuckDNS backend. DuckDNS is NOT dyndns2-protocol-compatible; it was previously
// wired as a dyndns2 alias, which sent the wrong params (hostname=/myip=), the
// wrong auth (HTTP Basic), rejected DuckDNS's OK body, and used the wrong
// withdraw verb (offline=YES). These tests assert the REAL DuckDNS protocol
// shape against an httptest server so they go RED if the provider is reverted to
// the dyndns2 alias:
//   - update GET carries domains=<label>&token=<tok>&ip=<v4> (or &ipv6=<v6>),
//   - the token is a QUERY PARAM, not an Authorization: Basic header,
//   - success is detected on the literal "OK" body (not dyndns2's good/nochg),
//   - withdraw sends &clear=true (not offline=YES).

// TestDuckDNSUpdateRequestShapeV4 asserts the IPv4 update request shape +
// success keyword. RED under the dyndns2 alias (it would send hostname=/myip=,
// HTTP Basic auth, and reject the OK body).
func TestDuckDNSUpdateRequestShapeV4(t *testing.T) {
	var gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", Server: srv.URL,
		APIToken: config.NewSecret("tok-abc"),
	}, nil)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "myhost.duckdns.org", "203.0.113.7")); err != nil {
		t.Fatalf("UpsertLease OK: %v", err)
	}

	q, perr := url.ParseQuery(gotQuery)
	if perr != nil {
		t.Fatalf("parse query %q: %v", gotQuery, perr)
	}
	// DuckDNS protocol params — NOT dyndns2's hostname=/myip=.
	if got := q.Get("domains"); got != "myhost" {
		t.Fatalf("domains: want bare subdomain label %q, got %q (full query %q)", "myhost", got, gotQuery)
	}
	if got := q.Get("token"); got != "tok-abc" {
		t.Fatalf("token: want query-param token %q, got %q", "tok-abc", got)
	}
	if got := q.Get("ip"); got != "203.0.113.7" {
		t.Fatalf("ip: want %q, got %q", "203.0.113.7", got)
	}
	if q.Has("ipv6") {
		t.Fatalf("v4 update must not set ipv6: %q", gotQuery)
	}
	// dyndns2-alias regression guards: the wrong params must be ABSENT.
	if q.Has("hostname") || q.Has("myip") {
		t.Fatalf("DuckDNS must not send dyndns2 hostname=/myip=: %q", gotQuery)
	}
	// Token auth is a QUERY PARAM, never HTTP Basic.
	if gotAuth != "" {
		t.Fatalf("DuckDNS must not send an Authorization header (token is a query param), got %q", gotAuth)
	}
}

// TestDuckDNSUpdateRequestShapeV6 asserts the v6 address goes in ipv6= (not ip=).
func TestDuckDNSUpdateRequestShapeV6(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("OK\n"))
	}))
	defer srv.Close()

	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", Server: srv.URL,
		APIToken: config.NewSecret("tok-abc"),
	}, nil)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	// Bare-label hostname (operator may also configure just the subdomain).
	if err := b.UpsertLease(context.Background(), hostRecord(t, "myhost", "2001:db8::5")); err != nil {
		t.Fatalf("UpsertLease v6: %v", err)
	}
	q, perr := url.ParseQuery(gotQuery)
	if perr != nil {
		t.Fatalf("parse query %q: %v", gotQuery, perr)
	}
	if got := q.Get("ipv6"); got != "2001:db8::5" {
		t.Fatalf("ipv6: want %q, got %q (query %q)", "2001:db8::5", got, gotQuery)
	}
	if q.Has("ip") {
		t.Fatalf("v6 update must not set ip=: %q", gotQuery)
	}
	if got := q.Get("domains"); got != "myhost" {
		t.Fatalf("domains: want %q, got %q", "myhost", got)
	}
}

// TestDuckDNSWithdrawClear asserts DeleteLease sends &clear=true (the DuckDNS
// withdraw verb) — NOT dyndns2's offline=YES. RED under the dyndns2 alias.
func TestDuckDNSWithdrawClear(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", Server: srv.URL,
		APIToken: config.NewSecret("tok-abc"),
	}, nil)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	if err := b.DeleteLease(context.Background(), hostRecord(t, "myhost.duckdns.org", "203.0.113.7")); err != nil {
		t.Fatalf("DeleteLease clear: %v", err)
	}
	q, perr := url.ParseQuery(gotQuery)
	if perr != nil {
		t.Fatalf("parse query %q: %v", gotQuery, perr)
	}
	if got := q.Get("clear"); got != "true" {
		t.Fatalf("withdraw: want clear=true, got %q (query %q)", got, gotQuery)
	}
	if q.Has("offline") {
		t.Fatalf("DuckDNS withdraw must not send dyndns2 offline=YES: %q", gotQuery)
	}
	if got := q.Get("domains"); got != "myhost" {
		t.Fatalf("domains: want %q, got %q", "myhost", got)
	}
	if got := q.Get("token"); got != "tok-abc" {
		t.Fatalf("token: want %q, got %q", "tok-abc", got)
	}
}

// TestDuckDNSResponseVerdict asserts OK→success, KO→hard auth error, and an
// unrecognized body→error. The dyndns2 parser only knows good/nochg, so it
// rejected DuckDNS's OK as unrecognized (the #2960 bug).
func TestDuckDNSResponseVerdict(t *testing.T) {
	cases := []struct {
		body    string
		wantErr bool
		wantSub string
		wantIs  error
	}{
		{"OK", false, "", nil},
		{"OK\n", false, "", nil},
		{"ok", false, "", nil},                       // case-insensitive
		{"OK\n203.0.113.7\nUPDATED", false, "", nil}, // verbose body
		{"KO", true, "bad token", errHTTPAuth},
		{"KO\n", true, "bad token", errHTTPAuth},
		{"good 1.2.3.4", true, "unrecognized", nil}, // dyndns2 keyword is NOT DuckDNS success
		{"", true, "unrecognized", nil},
	}
	for _, tc := range cases {
		err := parseDuckDNSResponse(tc.body, "duck")
		if tc.wantErr && err == nil {
			t.Fatalf("body %q: want error, got nil", tc.body)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("body %q: want success, got %v", tc.body, err)
		}
		if tc.wantSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSub)) {
			t.Fatalf("body %q: want error containing %q, got %v", tc.body, tc.wantSub, err)
		}
		if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
			t.Fatalf("body %q: want errors.Is %v, got %v", tc.body, tc.wantIs, err)
		}
	}
}

// TestDuckDNSMissingToken asserts construction fails closed without an api-token
// (so the manager degrades to no-op rather than emitting an unauthenticated
// request DuckDNS answers KO).
func TestDuckDNSMissingToken(t *testing.T) {
	_, err := newDuckDNSBackend(&config.DDNSProvider{Name: "duck", Backend: "duckdns"}, nil)
	if err == nil {
		t.Fatal("newDuckDNSBackend with no api-token: want error, got nil")
	}
	if !strings.Contains(err.Error(), "api-token") {
		t.Fatalf("error should mention api-token, got %v", err)
	}
}

// TestDuckDNSDomainLabel asserts the FQDN→subdomain-label reduction.
func TestDuckDNSDomainLabel(t *testing.T) {
	cases := map[string]string{
		"myhost.duckdns.org":  "myhost",
		"myhost.duckdns.org.": "myhost",
		"MyHost.DuckDNS.org":  "myhost",
		"myhost":              "myhost",
		"a.b.duckdns.org":     "a.b",
	}
	for in, want := range cases {
		if got := duckdnsDomain(in); got != want {
			t.Fatalf("duckdnsDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
