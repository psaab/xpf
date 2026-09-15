package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
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
		"/api/v1/",
		"/api/v1/security/shadow/deep",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.readAuthz(rec, req, sentinel)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s: got %d, want 403 — an unlisted API path served with no authorization decision", path, rec.Code)
		}
	}
	// Other safe methods resolve through the same path-keyed lookup: an
	// unknown /api/v1 path under HEAD or OPTIONS is the same hole.
	for _, method := range []string{http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/api/v1/no-such-route", nil)
		rec := httptest.NewRecorder()
		s.readAuthz(rec, req, sentinel)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s /api/v1/no-such-route: got %d, want 403", method, rec.Code)
		}
	}
	for _, path := range []string{"/health", "/metrics", "/nope", "/api/v1evil"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.readAuthz(rec, req, sentinel)
		if rec.Code != http.StatusTeapot {
			t.Errorf("GET %s: got %d, want pass-through (418) — non-API unknowns (and near-miss prefixes) must keep serving", path, rec.Code)
		}
	}
}

// apiRegistrationShapes9903 extracts EVERY mux registration from Go source
// — not just `mux.HandleFunc("METHOD /api/v1/...")`: mux.Handle,
// method-less patterns, and trailing-slash variants — by parsing
// STRUCTURALLY (go/parser), so multiline calls, raw strings, and odd
// formatting cannot hide a registration the way a line regex misses them
// (GPT-2: the 6660/9952 scanner weakness). A pattern arg that is not a
// string literal (const, var, concatenation) cannot be resolved here and is
// returned as unresolved — FLAGGED, never silently skipped.
func apiRegistrationShapes9903(t *testing.T, src string) (regs []apiReg9903, unresolved []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", src, 0)
	if err != nil {
		t.Fatalf("parse registration source: %v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			unresolved = append(unresolved, "mux."+sel.Sel.Name+" with non-literal pattern at "+fset.Position(call.Pos()).String())
			return true
		}
		pat, err := strconv.Unquote(lit.Value)
		if err != nil {
			unresolved = append(unresolved, "mux."+sel.Sel.Name+" with unquotable pattern at "+fset.Position(call.Pos()).String())
			return true
		}
		method, path := "", pat
		if i := strings.Index(pat, " "); i >= 0 {
			method, path = pat[:i], pat[i+1:]
		}
		regs = append(regs, apiReg9903{method: method, path: path, handle: sel.Sel.Name == "Handle"})
		return true
	})
	return regs, unresolved
}

type apiReg9903 struct {
	method string
	path   string
	handle bool
}

// classifyAPIReg9903 is the ONE classifier both the synthetic fixtures and
// the live census exercise (GPT-2): "" means the plain HandleFunc-METHOD
// shape the read table keys on; anything else names the reason it must be
// flagged. NO normalization — the runtime lookup is exact, so a
// trailing-slash registration and a slashless table entry are different
// routes, and read-table coverage cannot authorize an unsafe method from a
// method-less registration.
func classifyAPIReg9903(r apiReg9903) string {
	switch {
	case r.method == "":
		return "methodless:" + r.path
	case r.handle:
		return "handle:" + r.method + " " + r.path
	case strings.HasSuffix(r.path, "/"):
		return "subtree:" + r.method + " " + r.path
	}
	return ""
}

// apiExemptNonAPIRegistrations9903 is the EXPLICIT exempt set (M8): the only
// non-/api/v1 registrations the census tolerates. Anything else — a future
// /api/v2, /debug, or any new surface — fails the build until it carries
// its own authorization story. (The runtime still passes non-/api/v1
// unknowns to the mux, which 404s; the census is what makes that
// pass-through unreachable for REGISTERED routes.)
func apiExemptNonAPIRegistrations9903(path string) bool {
	return path == "/health" || path == "/metrics"
}

// TestAPIRegistrationCensusSeesEveryShape9903 proves the census improvement
// on synthetic fixtures through the SHARED extractor + classifier: every
// non-plain shape is extracted and flagged, including a multiline call (the
// line-regex blind spot) and a const pattern (unresolved, flagged).
func TestAPIRegistrationCensusSeesEveryShape9903(t *testing.T) {
	fixture := `package api
func register() {
mux.HandleFunc("GET /api/v1/known", s.knownHandler)
mux.Handle("GET /api/v1/via-handle", someHandler)
mux.HandleFunc("/api/v1/methodless", s.methodlessHandler)
mux.HandleFunc("GET /api/v1/subtree/", s.subtreeHandler)
mux.HandleFunc(
	"GET /api/v1/multiline",
	s.multilineHandler,
)
mux.HandleFunc(apiPatternConst, s.constHandler)
}
`
	regs, unresolved := apiRegistrationShapes9903(t, fixture)
	if len(regs) != 5 {
		t.Fatalf("the shape census must extract all 5 literal registrations, saw %d: %v", len(regs), regs)
	}
	if len(unresolved) != 1 {
		t.Fatalf("the const pattern must be flagged unresolved, got %v", unresolved)
	}
	var flagged []string
	for _, r := range regs {
		if f := classifyAPIReg9903(r); f != "" {
			flagged = append(flagged, f)
		}
	}
	sort.Strings(flagged)
	want := []string{
		"handle:GET /api/v1/via-handle",
		"methodless:/api/v1/methodless",
		"subtree:GET /api/v1/subtree/",
	}
	// The multiline registration is deliberately a PLAIN path: the
	// len(regs)==5 extraction assertion above is what proves multiline
	// visibility (a line regex misses it); classification is
	// shape-orthogonal, so it classifies clean here.
	if strings.Join(flagged, "\n") != strings.Join(want, "\n") {
		t.Fatalf("every non-plain shape must be flagged, got %v want %v", flagged, want)
	}
	// And the plain shape classifies clean.
	if f := classifyAPIReg9903(apiReg9903{method: "GET", path: "/api/v1/known"}); f != "" {
		t.Fatalf("plain HandleFunc GET must classify clean, got %q", f)
	}
}

// TestLiveMuxHasNoUncensusedShape9903 runs the shared extractor +
// classifier against the real server.go: every /api/v1 registration must
// be the plain shape the read table keys on, every non-/api/v1
// registration must be in the explicit exempt set, and every
// non-literal pattern fails until it is resolved. A future Handle,
// method-less, subtree, /api/v2, or const-pattern registration fails here
// until it is converted or censused with its own authorization story.
func TestLiveMuxHasNoUncensusedShape9903(t *testing.T) {
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	regs, unresolved := apiRegistrationShapes9903(t, string(b))
	if len(unresolved) > 0 {
		t.Fatalf("server.go registers mux patterns the census cannot resolve: %v", unresolved)
	}
	var bad []string
	for _, r := range regs {
		if !strings.HasPrefix(r.path, "/api/v1") {
			if !apiExemptNonAPIRegistrations9903(r.path) {
				bad = append(bad, "nonexempt-surface:"+r.method+" "+r.path)
			}
			continue
		}
		if f := classifyAPIReg9903(r); f != "" {
			bad = append(bad, f)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("server.go registers shapes the authorization table cannot key: %v", bad)
	}
}
