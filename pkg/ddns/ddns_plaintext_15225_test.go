package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/internal/ddnsplaintextvectors"
	"github.com/psaab/xpf/pkg/config"
)

// ddns_plaintext_15225_test.go: shared #15225 A40-03 fail-on-revert proofs
// for both config and runtime (#17005, R4-Q40-03).
//
// The old fixed credential key-name list missed literal query values such
// as pass=, key=, api-token=, pwd=, and p=. Both packages now consume the
// same union of their former vectors, so one test table pins the detector
// verdict and the corresponding compiler/runtime construction decision.
// Loopback request behavior remains covered below.

func TestDDNS15225GenericSharedPlaintextVectors(t *testing.T) {
	for _, vector := range ddnsplaintextvectors.DDNSPlaintextVectors {
		tmpl := vector.Template
		p := &config.DDNSProvider{Name: "g", Backend: "generic", URLTemplate: tmpl}
		if got := config.DDNSCredentialBearing(p); got != vector.CredentialBearing {
			t.Errorf("DDNSCredentialBearing(%q) = %v, want %v", tmpl, got, vector.CredentialBearing)
		}
		if got := config.DDNSTemplateCarriesLiteralToken(tmpl); got != vector.LiteralToken {
			t.Errorf("DDNSTemplateCarriesLiteralToken(%q) = %v, want %v", tmpl, got, vector.LiteralToken)
		}
		_, err := newGenericBackend(p, nil)
		refused := strings.HasPrefix(tmpl, "http://") && vector.CredentialBearing
		if refused && err == nil {
			t.Errorf("generic http template %q must be refused", tmpl)
		} else if !refused && err != nil {
			t.Errorf("control %q must construct: %v", tmpl, err)
		} else if err != nil && strings.Contains(err.Error(), "LITERAL") {
			t.Errorf("error leaks literal credential for %q: %v", tmpl, err)
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
