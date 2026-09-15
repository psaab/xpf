package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #9903 F-129 — STEP-0 repro: readAuthz serves unlisted safe-method routes,
// and the census only sees one registration shape.
// Cells are RED on the base, GREEN post-fix.

// TestUnknownAPIV1ReadIsDenied9903 drives readAuthz directly with a
// sentinel next handler: an unlisted /api/v1 path must be refused (403),
// while non-/api/v1 unknowns (/health, /metrics, mux 404s) still pass
// through. Pre-fix the /api/v1 unknowns reach the sentinel (RED).
func TestUnknownAPIV1ReadIsDenied9903(t *testing.T) {
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	s := &Server{}
	for _, path := range []string{
		"/api/v1/no-such-route",
		"/api/v1",
		"/api/v1/security/shadow/deep",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.readAuthz(rec, req, sentinel)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s: got %d, want 403 — an unlisted API path served with no authorization decision", path, rec.Code)
		}
	}
	for _, path := range []string{"/health", "/metrics", "/nope"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.readAuthz(rec, req, sentinel)
		if rec.Code != http.StatusTeapot {
			t.Errorf("GET %s: got %d, want pass-through (418) — non-API unknowns must keep serving", path, rec.Code)
		}
	}
}

// apiRegistrationShapes9903 matches EVERY mux registration shape, not just
// `mux.HandleFunc("METHOD /api/v1/...")`: mux.Handle, method-less patterns,
// and trailing-slash variants. It returns method ("" when method-less),
// pattern, and whether the call was Handle (handler, not func).
func apiRegistrationShapes9903(src string) (regs []apiReg9903) {
	re := regexp.MustCompile(`mux\.(HandleFunc|Handle)\("([^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		call, pat := m[1], m[2]
		method, path := "", pat
		if i := strings.Index(pat, " "); i >= 0 {
			method, path = pat[:i], pat[i+1:]
		}
		if !strings.HasPrefix(path, "/api/v1") {
			continue
		}
		regs = append(regs, apiReg9903{method: method, path: path, handle: call == "Handle"})
	}
	return regs
}

type apiReg9903 struct {
	method string
	path   string
	handle bool
}

// TestAPIRegistrationCensusSeesEveryShape9903 is the census improvement,
// proven on synthetic fixtures (Codex: "census still green does not test
// census improvement"). NO normalization: a trailing-slash registration,
// a method-less registration, and a mux.Handle registration must each be
// FLAGGED, because the runtime lookup is exact and read-table coverage
// cannot authorize an unsafe method.
func TestAPIRegistrationCensusSeesEveryShape9903(t *testing.T) {
	fixture := `package api
mux.HandleFunc("GET /api/v1/known", s.knownHandler)
mux.Handle("GET /api/v1/via-handle", someHandler)
mux.HandleFunc("/api/v1/methodless", s.methodlessHandler)
mux.HandleFunc("GET /api/v1/subtree/", s.subtreeHandler)
`
	regs := apiRegistrationShapes9903(fixture)
	if len(regs) != 4 {
		t.Fatalf("the shape census must see all 4 registration shapes, saw %d: %v", len(regs), regs)
	}
	var flagged []string
	for _, r := range regs {
		switch {
		case r.method == "":
			flagged = append(flagged, "methodless:"+r.path)
		case r.handle:
			flagged = append(flagged, "handle:"+r.method+" "+r.path)
		case strings.HasSuffix(r.path, "/"):
			flagged = append(flagged, "subtree:"+r.method+" "+r.path)
		}
	}
	sort.Strings(flagged)
	want := []string{
		"handle:GET /api/v1/via-handle",
		"methodless:/api/v1/methodless",
		"subtree:GET /api/v1/subtree/",
	}
	if strings.Join(flagged, "\n") != strings.Join(want, "\n") {
		t.Fatalf("every non-plain shape must be flagged, got %v want %v", flagged, want)
	}
	// And the plain shape flags nothing.
	plain := apiRegistrationShapes9903(`mux.HandleFunc("GET /api/v1/known", s.knownHandler)`)
	if len(plain) != 1 || plain[0].method != "GET" || plain[0].path != "/api/v1/known" || plain[0].handle {
		t.Fatalf("plain HandleFunc GET must parse exactly, got %+v", plain)
	}
}

// TestLiveMuxHasNoUncensusedShape9903 runs the shape census against the
// real server.go: every /api/v1 registration must be the plain
// HandleFunc-METHOD shape the read table keys on. A future Handle,
// method-less, or subtree registration fails here until it is either
// converted or explicitly censused with its own authorization story.
func TestLiveMuxHasNoUncensusedShape9903(t *testing.T) {
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	var bad []string
	for _, r := range apiRegistrationShapes9903(string(b)) {
		switch {
		case r.method == "":
			bad = append(bad, "methodless:"+r.path)
		case r.handle:
			bad = append(bad, "handle:"+r.method+" "+r.path)
		case strings.HasSuffix(r.path, "/"):
			bad = append(bad, "subtree:"+r.method+" "+r.path)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("server.go registers /api/v1 shapes the authorization table cannot key: %v", bad)
	}
}
