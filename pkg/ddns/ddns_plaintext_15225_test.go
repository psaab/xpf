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

// ddns_plaintext_15225_test.go: #15225 A40-03 fail-on-revert proofs.
//
// The http:// credential gate for generic url-templates previously
// recognised only a fixed credential key-name list, so pass=, key=,
// api-token=, pwd=, p= and every other literal query value went out in
// cleartext. The fix refuses ANY non-loopback http:// generic template
// carrying any literal query value or userinfo (typed credentials and
// %u/%p were already refused), while loopback http and placeholder-only
// or value-less http templates still construct.
//
// RED-on-revert: restore the fixed key-name list and every probe template
// below constructs clean — the credential ships in cleartext.

func TestDDNS15225GenericRefusesAnyLiteralQueryValuePlaintext(t *testing.T) {
	probes := []string{
		"http://host.example/upd?pass=LITERALPW",
		"http://host.example/upd?key=LITERALKEY",
		"http://host.example/upd?api-token=LITERALTOK",
		"http://host.example/upd?pwd=LITERALPW",
		"http://host.example/upd?p=LITERALP",
		"http://host.example/upd?foo=LITERALBAR",
		"http://host.example/upd?hostname=%h&myip=%i&token=LITERALTOKEN",
		"http://user:pass@host.example/upd?ip=%i",
	}
	for _, tmpl := range probes {
		p := &config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: tmpl}
		if _, err := newGenericBackend(p, nil); err == nil {
			t.Fatalf("generic http template %q must be refused (literal value/userinfo in cleartext)", tmpl)
		} else if strings.Contains(err.Error(), "LITERAL") {
			t.Fatalf("error leaks literal credential for %q: %v", tmpl, err)
		}
		if !genericCarriesCredentials(p) {
			t.Fatalf("genericCarriesCredentials(%q) = false, want true", tmpl)
		}
	}
	// Controls: loopback http with a literal token still works; https with
	// a literal token is fine; http with only placeholders / no literal
	// query value still constructs (no credential to leak).
	controls := []string{
		"https://host.example/upd?token=LITERALTOKEN",
		"http://host.example/upd?ip=%i&hostname=%h",
		"http://host.example/upd?flag&ip=%i",
		"http://host.example/update/SECRET",
	}
	for _, tmpl := range controls {
		p := &config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: tmpl}
		if _, err := newGenericBackend(p, nil); err != nil {
			t.Fatalf("control %q must construct: %v", tmpl, err)
		}
	}
}

// Loopback http with a literal-token generic template still publishes —
// proving the exemption is loopback-only, not a blanket http ban.
func TestDDNS15225GenericLoopbackLiteralStillWorks(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("good 203.0.113.5\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/upd?pass=LITERALPW&ip=%i",
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
}
