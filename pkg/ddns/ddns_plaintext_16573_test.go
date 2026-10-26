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

// ddns_plaintext_16573_test.go: #16573 fail-on-revert proofs (runtime side).
//
// config.DDNSTemplateCarriesLiteralToken is the one detector:
// percent-escaped literal values (%2B/%2F/%3D etc.) and percent-escaped
// keyless query components must refuse a non-loopback http:// generic
// template at construction AND issuance, while specifier-only,
// placeholder-only, https and loopback http templates still work.
//
// RED-on-revert: restore the '%'-free isLiteral predicate (and the
// '='-only query scan) and every probe below constructs clean.

func TestDDNS16573GenericRefusesPercentEscapedLiteralPlaintext(t *testing.T) {
	probes := []string{
		"http://host.example/upd?token=abc%2Bdef%2Fghi%3D",
		"http://host.example/upd?token=%2B%2F%3D",
		"http://host.example/upd?foo=a%2Fb",
		"http://host.example/upd?token=%41%42",
		"http://host.example/upd?token=abc%",
		"http://host.example/upd?token=%h%2B",
		"http://host.example/upd?%2B%2F%3D",
		"http://host.example/upd?=abc%2Fdef",
	}
	for _, tmpl := range probes {
		p := &config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: tmpl}
		if _, err := newGenericBackend(p, nil); err == nil {
			t.Fatalf("generic http template %q must be refused (percent-escaped/keyless literal in cleartext)", tmpl)
		} else if strings.Contains(err.Error(), "abc") {
			t.Fatalf("error leaks literal credential for %q: %v", tmpl, err)
		}
		if !config.DDNSCredentialBearing(p) {
			t.Fatalf("DDNSCredentialBearing(%q) = false, want true", tmpl)
		}
		if !config.DDNSTemplateCarriesLiteralToken(tmpl) {
			t.Fatalf("DDNSTemplateCarriesLiteralToken(%q) = false, want true", tmpl)
		}
	}
	// Credential-named path pair with an escaped value: refused at
	// construction too. The error echoes the (already redaction-exempt)
	// path via RedactURL, so only refusal is asserted here.
	pathProbe := "http://host.example/update/token=abc%2Fdef"
	if _, err := newGenericBackend(&config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: pathProbe}, nil); err == nil {
		t.Fatalf("generic http template %q must be refused (escaped path-pair literal in cleartext)", pathProbe)
	}
	if !config.DDNSTemplateCarriesLiteralToken(pathProbe) {
		t.Fatalf("DDNSTemplateCarriesLiteralToken(%q) = false, want true", pathProbe)
	}
}

func TestDDNS16573GenericSpecifierOnlyControlsConstruct(t *testing.T) {
	controls := []string{
		"https://host.example/upd?token=abc%2Fdef",
		"https://host.example/upd?u=%u&p=%p",
		"http://host.example/upd?host=%h&ip=%i",
		"http://host.example/upd?lit=%%",
		"http://host.example/upd?x=%h%i%%",
		"http://host.example/upd?x={{token}}",
		"http://host.example/upd?x=%h{{token}}%i",
		"http://host.example/upd?flag=&ip=%i",
		"http://host.example/upd?flag&ip=%i",
		"http://host.example/upd?ip=%i&",
		"http://host.example/update/SECRET",
		"http://host.example/update/token=%h",
	}
	for _, tmpl := range controls {
		p := &config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: tmpl}
		if _, err := newGenericBackend(p, nil); err != nil {
			t.Fatalf("control %q must construct: %v", tmpl, err)
		}
	}
}

// The issuance belt must also catch a template whose construction belt
// was bypassed (backend built directly): UpsertLease renders first and
// must refuse before any request leaves.
func TestDDNS16573GenericUpsertBeltRefusesPercentEscaped(t *testing.T) {
	b := &genericBackend{
		name:        "g",
		urlTemplate: "http://host.example/upd?token=abc%2Fdef&ip=%i",
		okTokens:    defaultGenericOKTokens,
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err == nil {
		t.Fatal("UpsertLease must refuse percent-escaped literal over http before issuing a request")
	}
}

// Loopback http with a percent-escaped literal still publishes — the
// exemption is loopback-only, not a blanket http ban.
func TestDDNS16573GenericLoopbackPercentEscapedStillWorks(t *testing.T) {
	var hits int32
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("good 203.0.113.5\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/upd?token=abc%2Fdef&ip=%i",
	}, nil)
	if err != nil {
		t.Fatalf("loopback generic http must construct: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits=%d want 1", got)
	}
	if !strings.Contains(gotQuery, "token=abc%2Fdef") {
		t.Fatalf("rendered query %q must carry the escaped token verbatim on loopback", gotQuery)
	}
}
