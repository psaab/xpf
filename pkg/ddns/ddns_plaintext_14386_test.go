package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14386 (DR6-H2) runtime belt: direct construction (bypassing the compiler)
// must refuse a credentialed plaintext http:// endpoint instead of issuing a
// cleartext request. httptest servers are http://127.0.0.1 — loopback is
// exempt, so refusal cases use a non-loopback host. Counters prove no request.

func TestDDNS14386Dyndns2RefusesCredentialedPlaintext(t *testing.T) {
	// Typed credentials over http:// non-loopback.
	if _, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "p", Backend: "dyndns2", Server: "http://updates.example/nic/update",
		Username: "bob", Password: config.Secret("s3cr3t-value"),
	}, nil); err == nil {
		t.Fatal("credentialed dyndns2 http:// must be refused at construction")
	} else if strings.Contains(err.Error(), "s3cr3t-value") {
		t.Fatalf("error leaks credential: %v", err)
	}
	// Userinfo-only credential over http://.
	if _, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "p", Backend: "dyndns2", Server: "http://user:pass@updates.example/nic/update",
	}, nil); err == nil {
		t.Fatal("dyndns2 http:// with userinfo must be refused at construction")
	} else if strings.Contains(err.Error(), "pass") && strings.Contains(err.Error(), "user:") {
		t.Fatalf("error leaks userinfo credential: %v", err)
	}
	// Controls: https credentialed, bare host, uncredentialed http.
	for _, p := range []*config.DDNSProvider{
		{Name: "p", Backend: "dyndns2", Server: "https://updates.example/nic/update", Username: "bob", Password: config.Secret("x")},
		{Name: "p", Backend: "dyndns2", Server: "updates.example", Username: "bob", Password: config.Secret("x")},
		{Name: "p", Backend: "dyndns2", Server: "http://updates.example/nic/update"},
	} {
		if _, err := newDyndns2Backend(p, nil); err != nil {
			t.Fatalf("control %+v must construct: %v", p.Server, err)
		}
	}
}

func TestDDNS14386GenericRefusesCredentialedPlaintext(t *testing.T) {
	cases := []*config.DDNSProvider{
		{Name: "g", Backend: "generic", URLTemplate: "http://host.example/update?hostname=%h&myip=%i&user=%u&pass=%p", Username: "u", Password: config.Secret("p")},
		{Name: "g", Backend: "generic", URLTemplate: "http://host.example/update?token=LITERALTOKEN"},
		{Name: "g", Backend: "generic", URLTemplate: "http://user:pass@host.example/upd?ip=%i"},
		{Name: "g", Backend: "generic", URLTemplate: "http://host.example/upd?ip=%i", Username: "u", Password: config.Secret("p")},
	}
	for _, p := range cases {
		if _, err := newGenericBackend(p, nil); err == nil {
			t.Fatalf("generic credentialed http template %q must be refused", p.URLTemplate)
		} else if strings.Contains(err.Error(), "LITERALTOKEN") {
			t.Fatalf("error leaks literal token: %v", err)
		}
	}
	// Controls: https credentialed, non-credentialed http.
	for _, p := range []*config.DDNSProvider{
		{Name: "g", Backend: "generic", URLTemplate: "https://host.example/update?token=LITERALTOKEN"},
		{Name: "g", Backend: "generic", URLTemplate: "http://host.example/upd?ip=%i"},
		{Name: "g", Backend: "generic", URLTemplate: "http://host.example/update/SECRET"},
	} {
		if _, err := newGenericBackend(p, nil); err != nil {
			t.Fatalf("control %q must construct: %v", p.URLTemplate, err)
		}
	}
}

// Loopback http with credentials still works (httptest harness) and issues
// exactly one request — proving the exemption is loopback-only, not blanket.
func TestDDNS14386LoopbackHTTPStillWorks(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("good 203.0.113.5\n"))
	}))
	defer srv.Close()
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
		Username: "u1", Password: config.Secret("p1"),
	}, nil)
	if err != nil {
		t.Fatalf("loopback credentialed http must construct: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits=%d want 1", got)
	}
}
