package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// /config/show-rollback honour format=xml|json|inheritance and the
// ?path= subtree selector, reject unknown formats with 400, and
// show-rollback n=0 renders the active configuration.

func newRollbackRESTServer15657(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system host-name host-a-15657\nset security zones security-zone trust"); err != nil {
		t.Fatalf("LoadSet A: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if _, err := store.LoadSet("set system host-name host-b-15657"); err != nil {
		t.Fatalf("LoadSet B: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	return &Server{store: store}
}

func getText15657(t *testing.T, s *Server, handler func(http.ResponseWriter, *http.Request), url string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	handler(rr, httptest.NewRequest("GET", url, nil))
	return rr.Code, rr.Body.String()
}

func TestRESTShowRollbackFormats15657(t *testing.T) {
	s := newRollbackRESTServer15657(t)
	cases := []struct {
		url  string
		want string
	}{
		{"/api/v1/config/show-rollback?n=1&format=json", "host-a-15657"},
		{"/api/v1/config/show-rollback?n=1&format=xml", "xml version"},
		{"/api/v1/config/show-rollback?n=1&format=set", "set system host-name host-a-15657"},
		{"/api/v1/config/show-rollback?n=1&format=inheritance", "host-a-15657"},
		{"/api/v1/config/show-rollback?n=1", "host-a-15657"},
		{"/api/v1/config/show-rollback?n=0", "host-b-15657"},
		{"/api/v1/config/show-rollback?n=1&format=json&path=system", "host-a-15657"},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			code, body := getText15657(t, s, s.configShowRollbackHandler, tc.url)
			if code != 200 {
				t.Fatalf("status = %d, want 200; body=%s", code, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("missing %q in body: %s", tc.want, body)
			}
		})
	}
	// Unknown format is a 400, not hierarchical text in disguise.
	code, _ := getText15657(t, s, s.configShowRollbackHandler, "/api/v1/config/show-rollback?n=1&format=bogus")
	if code != 400 {
		t.Errorf("format=bogus: status = %d, want 400", code)
	}
	// Path scoping scopes.
	code, body := getText15657(t, s, s.configShowRollbackHandler, "/api/v1/config/show-rollback?n=1&path=system")
	if code != 200 || strings.Contains(body, "security-zone") {
		t.Errorf("path=system should scope out security: code=%d body=%s", code, body)
	}
}

func TestRESTConfigShowFormatsAndPath15657(t *testing.T) {
	s := newRollbackRESTServer15657(t)
	cases := []struct {
		url  string
		want string
	}{
		{"/api/v1/config/show?format=json", "host-b-15657"},
		{"/api/v1/config/show?format=xml", "xml version"},
		{"/api/v1/config/show?format=set", "set system host-name host-b-15657"},
		{"/api/v1/config/show?path=system", "host-b-15657"},
		{"/api/v1/config/show?path=system&format=json", "host-b-15657"},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			code, body := getText15657(t, s, s.configShowHandler, tc.url)
			if code != 200 {
				t.Fatalf("status = %d, want 200; body=%s", code, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("missing %q in body: %s", tc.want, body)
			}
		})
	}
	// Unknown format rejected; path scoping scopes.
	if code, _ := getText15657(t, s, s.configShowHandler, "/api/v1/config/show?format=bogus"); code != 400 {
		t.Errorf("format=bogus: status = %d, want 400", code)
	}
	code, body := getText15657(t, s, s.configShowHandler, "/api/v1/config/show?path=system")
	if code != 200 || strings.Contains(body, "security-zone") {
		t.Errorf("path=system should scope out security: code=%d body=%s", code, body)
	}
	// restShowFormat maps inheritance through for the deny gate.
	if got := restShowFormat("inheritance"); got != "inheritance" {
		t.Errorf("restShowFormat(inheritance) = %q, want inheritance", got)
	}
}
