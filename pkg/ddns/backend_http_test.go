package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// backend_http_test.go: mock-server (#2691 P3) tests for the HTTP DDNS backends.
// Every test drives the REAL backend implementation against an httptest server
// (the P2 lesson: test the real mechanism, not a fake that bypasses the
// protocol). A backend constructed by newDyndns2Backend/newCloudflareBackend/
// etc. is pointed at the test server via the per-instance endpoint override
// (Server / apiBase / endpoint), so the wire request the backend actually emits
// is asserted on the server side.

// hostRecord builds a forward A/AAAA LeaseDNSRecord for the backend under test.
func hostRecord(t *testing.T, fqdn, addr string) LeaseDNSRecord {
	t.Helper()
	rec, err := buildHostRecord(fqdn, netip.MustParseAddr(addr), 300)
	if err != nil {
		t.Fatalf("buildHostRecord: %v", err)
	}
	return rec
}

func TestDyndns2GoodAndNochg(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		// The hostname/myip must be present in the query.
		if r.URL.Query().Get("hostname") == "" || r.URL.Query().Get("myip") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("good 203.0.113.5\n"))
	}))
	defer srv.Close()

	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
		Username: "u1", Password: config.NewSecret("p1"),
	}, nil)
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("UpsertLease good: %v", err)
	}
	if !strings.Contains(gotPath, "hostname=wan.example.net") || !strings.Contains(gotPath, "myip=203.0.113.5") {
		t.Fatalf("dyndns2 request did not carry hostname+myip: %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("dyndns2 must send Basic auth header")
	}
}

func TestDyndns2VerdictMapping(t *testing.T) {
	cases := []struct {
		body    string
		wantErr bool
		wantSub string
	}{
		{"good 1.2.3.4\n", false, ""},
		{"nochg\n", false, ""},
		{"badauth\n", true, "auth"},
		{"abuse\n", true, "auth"},
		{"911\n", true, "rate"},
		{"nohost\n", true, "rejected"},
		{"weird-thing\n", true, "unrecognized"},
	}
	for _, tc := range cases {
		err := parseDyndns2Response(tc.body, "p")
		if tc.wantErr != (err != nil) {
			t.Fatalf("body %q: wantErr=%v got %v", tc.body, tc.wantErr, err)
		}
		if tc.wantErr && tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("body %q: error %q missing %q", tc.body, err.Error(), tc.wantSub)
		}
	}
}

func TestDyndns2NameEndpointResolution(t *testing.T) {
	b, err := newDyndns2Backend(&config.DDNSProvider{Name: "no-ip", Backend: "dyndns2"}, nil)
	if err != nil {
		t.Fatalf("newDyndns2Backend(no-ip, nil): %v", err)
	}
	if !strings.Contains(b.endpoint, "no-ip.com") {
		t.Fatalf("no-ip name must resolve to its built-in endpoint, got %q", b.endpoint)
	}
	// No server + unknown name → error (fall back to no-op at the manager).
	if _, err := newDyndns2Backend(&config.DDNSProvider{Name: "weird", Backend: "dyndns2"}, nil); err == nil {
		t.Fatal("unknown provider with no server must error")
	}
	// #2960: duckdns is NO LONGER a dyndns2 alias — it has its own backend, so it
	// must NOT resolve a dyndns2 endpoint from its name (it would otherwise speak
	// the wrong protocol). FAIL-ON-REVERT: re-adding duckdns to dyndns2Endpoints
	// makes this resolve instead of error.
	if _, err := newDyndns2Backend(&config.DDNSProvider{Name: "duckdns", Backend: "dyndns2"}, nil); err == nil {
		t.Fatal("duckdns must NOT resolve a dyndns2 endpoint (it has its own backend, #2960)")
	}
}

// TestDyndns2ServerEndpointParsing is the #3737 FAIL-ON-REVERT guard for the
// explicit-`server` endpoint parser. resolveDyndns2Endpoint used to decide
// full-URL vs bare-host with a case-SENSITIVE HasPrefix on "http://"/"https://"
// and did no host validation, so an uppercase scheme ("HTTPS://...") was
// misclassified as a bare host (→ a malformed doubly-suffixed URL) and a
// hostless URL ("http://") was returned verbatim (→ fails only at publish).
// The fix parses with url.Parse, compares the scheme with EqualFold, and
// requires a non-empty host — mirroring validateCheckIPURL (#2842).
func TestDyndns2ServerEndpointParsing(t *testing.T) {
	// accept: server → expected resolved endpoint.
	accept := []struct{ server, want string }{
		// Uppercase / mixed-case scheme is a full URL (RFC 3986 §3.1), returned
		// verbatim — NOT treated as a bare host. Goes RED on the case-sensitive
		// HasPrefix revert (want would become the malformed
		// "https://HTTPS://updates.example/nic/update/nic/update").
		{"HTTPS://updates.example/nic/update", "HTTPS://updates.example/nic/update"},
		{"Http://updates.example/nic/update", "Http://updates.example/nic/update"},
		// Well-formed lowercase full URL is unchanged.
		{"https://members.dyndns.org/v3/update", "https://members.dyndns.org/v3/update"},
		{"http://updates.example/nic/update", "http://updates.example/nic/update"},
		// Bare host → canonical dyndns2 path over HTTPS (unchanged).
		{"dynupdate.no-ip.com", "https://dynupdate.no-ip.com/nic/update"},
		{"host.example:8443", "https://host.example:8443/nic/update"},
	}
	for _, tc := range accept {
		got, err := resolveDyndns2Endpoint(&config.DDNSProvider{
			Name: "p", Backend: "dyndns2", Server: tc.server,
		})
		if err != nil {
			t.Errorf("resolveDyndns2Endpoint(server=%q) = error %v, want %q", tc.server, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveDyndns2Endpoint(server=%q) = %q, want %q", tc.server, got, tc.want)
		}
	}

	// reject: a hostless or wrong-scheme server must error (manager no-op),
	// not return a URL that only fails at the first publish (M05/H09).
	reject := []string{
		"http://",             // scheme only, no host
		"https:///nic/update", // host-less but scheme present
		"HTTPS://",            // uppercase scheme, no host
		"ftp://host/upd",      // wrong scheme
		":8080",               // bare, no host (port only)
		"/nic/update",         // bare, path only, no host
	}
	for _, s := range reject {
		if got, err := resolveDyndns2Endpoint(&config.DDNSProvider{
			Name: "p", Backend: "dyndns2", Server: s,
		}); err == nil {
			t.Errorf("resolveDyndns2Endpoint(server=%q) = %q, want error", s, got)
		}
	}

	// newDyndns2Backend must surface the rejection (fall back to no-op at the
	// manager) rather than construct a backend pointed at a malformed host.
	if _, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "p", Backend: "dyndns2", Server: "http://",
	}, nil); err == nil {
		t.Fatal("newDyndns2Backend(server=\"http://\") = nil error, want rejection")
	}
}

// TestDyndns2DeleteIssuesOfflineRequest is the #2772 FAIL-ON-REVERT guard for
// the dyndns2 withdraw path. The previous DeleteLease was a no-op that returned
// nil WITHOUT contacting the provider, so the engine dropped ownership while the
// public record kept resolving. This test asserts DeleteLease actually issues
// the dyndns2 offline GET (offline=YES + the hostname) and that a provider
// failure verdict propagates as an error. If DeleteLease is reverted to
// `return nil`, the server handler is never hit (got=="") and the test fails.
func TestDyndns2DeleteIssuesOfflineRequest(t *testing.T) {
	var gotPath, gotAuth string
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("good\n"))
	}))
	defer srv.Close()

	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
		Username: "u1", Password: config.NewSecret("p1"),
	}, nil)
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err != nil {
		t.Fatalf("DeleteLease good: %v", err)
	}
	// FAIL-ON-REVERT: a no-op DeleteLease never reaches the server.
	if hits == 0 {
		t.Fatal("DeleteLease did not issue any HTTP request — withdraw is a silent no-op (regression #2772)")
	}
	if !strings.Contains(gotPath, "offline=YES") {
		t.Fatalf("dyndns2 withdraw must send offline=YES; got %q", gotPath)
	}
	if !strings.Contains(gotPath, "hostname=wan.example.net") {
		t.Fatalf("dyndns2 withdraw must name the hostname; got %q", gotPath)
	}
	if gotAuth == "" {
		t.Fatal("dyndns2 withdraw must send Basic auth header")
	}
}

// TestDyndns2DeletePropagatesProviderFailure asserts that a provider error
// verdict on the withdraw GET (not a silent success) propagates as a non-nil
// error so the Surface A engine keeps ownership for retry.
func TestDyndns2DeletePropagatesProviderFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("badauth\n"))
	}))
	defer srv.Close()
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "test", Backend: "dyndns2", Server: srv.URL,
	}, nil)
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	if err := b.DeleteLease(context.Background(), hostRecord(t, "wan.example.net", "203.0.113.5")); err == nil {
		t.Fatal("dyndns2 withdraw with a badauth verdict must return an error, not silent success")
	}
}

// TestGenericDeleteFailsNotSilentSuccess is the #2772 FAIL-ON-REVERT guard for
// the generic backend's withdraw path. The generic templated protocol has no
// portable delete verb, so DeleteLease must FAIL (so the engine keeps ownership
// and the abandoned record stays operator-visible) rather than return nil and
// silently drop ownership while the public record persists. If DeleteLease is
// reverted to `return nil`, this test fails.
func TestGenericDeleteFailsNotSilentSuccess(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("good\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/u?h=%h&i=%i",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	err = b.DeleteLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7"))
	if err == nil {
		t.Fatal("generic DeleteLease must FAIL (no portable delete verb), not report silent success (regression #2772)")
	}
	if !errors.Is(err, errGenericDeleteUnsupported) {
		t.Fatalf("generic DeleteLease error must wrap errGenericDeleteUnsupported; got %v", err)
	}
}

func TestGenericTemplateRenderAndOK(t *testing.T) {
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		_, _ = w.Write([]byte("OK updated\n"))
	}))
	defer srv.Close()

	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: srv.URL + "/upd?host=%h&ip=%i&u=%u",
		Username:    "user one", // space → must be query-escaped
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if !strings.Contains(gotURL, "host=h.example.net") || !strings.Contains(gotURL, "ip=198.51.100.7") {
		t.Fatalf("generic template did not expand %%h/%%i: %q", gotURL)
	}
	if !strings.Contains(gotURL, "u=user+one") && !strings.Contains(gotURL, "u=user%20one") {
		t.Fatalf("generic template did not query-escape %%u: %q", gotURL)
	}
}

func TestGenericSuccessSubstringMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ERROR something\n"))
	}))
	defer srv.Close()
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic", URLTemplate: srv.URL + "/u?h=%h&i=%i", OKResponse: "good",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err == nil {
		t.Fatal("a body without the success substring must be an error")
	}
}

// TestGenericOKTokenMatch is the #2838 FAIL-ON-REVERT guard for the generic
// backend's success classifier. The old matcher used strings.Contains against a
// default set that included the bare token "ok", so an explicit provider FAILURE
// body that merely CONTAINS "ok"/"good" ("not ok", "error: ok token invalid",
// "update not good") was wrongly classified as a completed update — Surface A
// then recorded ownership and suppressed retry, leaving DNS stale. This test
// pins token-bounded matching: a default-token success is a whole token / the
// leading field of a line; a negative response that only contains a token as a
// substring is a FAILURE. Reverting to the substring match turns the negative
// cases green again, which fails this test.
func TestGenericOKTokenMatch(t *testing.T) {
	cases := []struct {
		name string
		body string
		// okResponse: "" means use the default token set; non-empty pins it.
		okResponse string
		wantOK     bool
	}{
		// Default-token SUCCESS cases must keep passing.
		{name: "bare ok line", body: "ok\n", wantOK: true},
		{name: "uppercase OK line", body: "OK\n", wantOK: true},
		{name: "good with ip (dyndns2 shape)", body: "good 198.51.100.7\n", wantOK: true},
		{name: "nochg with ip", body: "nochg 198.51.100.7\n", wantOK: true},
		{name: "ok updated multiword", body: "OK updated\n", wantOK: true},
		// The #2838 false-success cases: a substring hit that is NOT a success.
		{name: "not ok", body: "not ok\n", wantOK: false},
		{name: "error ok token invalid", body: "error: ok token invalid\n", wantOK: false},
		{name: "update not good", body: "update not good\n", wantOK: false},
		{name: "notok glued", body: "notok\n", wantOK: false},
		{name: "html ok button", body: "<html><body><button>OK</button></body></html>\n", wantOK: false},
		// Explicit ok-response is matched the same whole-token way.
		{name: "explicit good success", body: "good\n", okResponse: "good", wantOK: true},
		{name: "explicit good not matched in noise", body: "this is not good news\n", okResponse: "good", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			b, err := newGenericBackend(&config.DDNSProvider{
				Name: "g", Backend: "generic",
				URLTemplate: srv.URL + "/u?h=%h&i=%i",
				OKResponse:  tc.okResponse,
			}, nil)
			if err != nil {
				t.Fatalf("newGenericBackend: %v", err)
			}
			err = b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7"))
			if tc.wantOK && err != nil {
				t.Fatalf("body %q must be SUCCESS, got error: %v", tc.body, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("body %q must be FAILURE, got success (false-success regression #2838)", tc.body)
			}
		})
	}
}

// TestGenericMultiWordOKResponseTokenized is the #5557 (claude-review-003 A10)
// FAIL-ON-REVERT guard. A multi-WORD ok-response must be split into whole
// TOKENS, not stored as one space-containing element. matchesGenericOK does
// whole-token matching (#2838): a success token must equal a trimmed response
// line, or be the leading whitespace-delimited field of a line — the matcher
// never sees a token as a raw substring. A single element carrying an embedded
// space (e.g. "good nochg") therefore has a DEAD first-field path (a first
// field never contains a space) and can only match a line that is EXACTLY
// "good nochg", so a dyndns2-shape "good nochg <ip>" body — or a bare "nochg"
// line — is never recognized, every update is treated as failed, and the client
// error-spams + backs off while DNS goes stale. Tokenizing on whitespace makes
// each configured word a matchable whole token (the single-token shape of
// defaultGenericOKTokens). Reverting the fix to
// `ok = []string{strings.ToLower(s)}` turns the multi-word success cases below
// into failures, which fails this test.
func TestGenericMultiWordOKResponseTokenized(t *testing.T) {
	// Shape: the configured ok-response tokenizes into whole words (extra/leading
	// whitespace collapsed), matching the single-token defaultGenericOKTokens
	// shape. The reverted code stores the single element ["good nochg"].
	b, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: "http://example.net/u?h=%h&i=%i",
		OKResponse:  "  good   nochg  ",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if got := strings.Join(b.okTokens, ","); got != "good,nochg" {
		t.Fatalf("multi-word ok-response must tokenize to whole tokens, got okTokens=%q want %q "+
			"(revert stores one space-joined element)", got, "good,nochg")
	}

	// End-to-end: with ok-response "good nochg", each configured word is an
	// independently matchable whole token. Every case here FAILS on revert
	// because ["good nochg"] matches none of these bodies.
	multiCases := []struct {
		name string
		body string
	}{
		{"dyndns2-shape leading word + ip", "good nochg 198.51.100.7\n"},
		{"bare second word", "nochg\n"},
		{"bare first word", "good\n"},
	}
	for _, tc := range multiCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			bb, err := newGenericBackend(&config.DDNSProvider{
				Name: "g", Backend: "generic",
				URLTemplate: srv.URL + "/u?h=%h&i=%i",
				OKResponse:  "good nochg",
			}, nil)
			if err != nil {
				t.Fatalf("newGenericBackend: %v", err)
			}
			if err := bb.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err != nil {
				t.Fatalf("body %q with multi-word ok-response %q must be SUCCESS, got error: %v "+
					"(revert regression #5557)", tc.body, "good nochg", err)
			}
		})
	}

	// Negative: a body that matches NEITHER configured word is still a FAILURE —
	// the fix widens matching to each word, it does not accept everything.
	negSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("error: bad request\n"))
	}))
	defer negSrv.Close()
	nb, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: negSrv.URL + "/u?h=%h&i=%i",
		OKResponse:  "good nochg",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if err := nb.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err == nil {
		t.Fatal("a body matching none of the configured ok tokens must be a FAILURE")
	}

	// No regression: a single-word ok-response still tokenizes to one token and
	// matches its exact success body end-to-end.
	swSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("success\n"))
	}))
	defer swSrv.Close()
	sb, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: swSrv.URL + "/u?h=%h&i=%i",
		OKResponse:  "success",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if got := strings.Join(sb.okTokens, ","); got != "success" {
		t.Fatalf("single-word ok-response must stay one token, got okTokens=%q", got)
	}
	if err := sb.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "198.51.100.7")); err != nil {
		t.Fatalf("single-word ok-response %q vs body \"success\" must be SUCCESS, got error: %v", "success", err)
	}

	// The default token set is untouched when no ok-response is configured.
	db, err := newGenericBackend(&config.DDNSProvider{
		Name: "g", Backend: "generic",
		URLTemplate: "http://example.net/u?h=%h&i=%i",
	}, nil)
	if err != nil {
		t.Fatalf("newGenericBackend: %v", err)
	}
	if got, want := strings.Join(db.okTokens, ","), strings.Join(defaultGenericOKTokens, ","); got != want {
		t.Fatalf("default ok-token set must be unchanged when no ok-response is set: got %q want %q", got, want)
	}
	if got, want := strings.Join(defaultGenericOKTokens, ","), "good,nochg,ok,true,updated"; got != want {
		t.Fatalf("defaultGenericOKTokens shape changed: got %q want %q", got, want)
	}
}

// TestMatchesGenericOKUnit exercises the matcher directly, including the
// dyndns2-shared default tokens (good/nochg) that the generic default set must
// continue to accept, and confirms substring-only hits are rejected.
func TestMatchesGenericOKUnit(t *testing.T) {
	def := defaultGenericOKTokens
	cases := []struct {
		body   string
		tokens []string
		want   bool
	}{
		{"good", def, true},
		{"nochg", def, true},
		{"GOOD 1.2.3.4", def, true},
		{"ok", def, true},
		{"not ok", def, false},
		{"update not good", def, false},
		{"error: ok", def, false},
		{"", def, false},
		{"good", nil, false}, // empty token set never matches
	}
	for _, tc := range cases {
		if got := matchesGenericOK(tc.body, tc.tokens); got != tc.want {
			t.Errorf("matchesGenericOK(%q, %v) = %v, want %v", tc.body, tc.tokens, got, tc.want)
		}
	}
}

// TestGenericURLTemplateValidation is the #2841 fail-on-revert gate for the
// runtime construction path. The generic url-template was validated PREFIX-ONLY
// (a bare HasPrefix http(s):// check), so a host-less or wrong-scheme template
// constructed a backend that then failed at the first publish. newGenericBackend
// must now reject a malformed template (no host / wrong scheme) at construction,
// with the SAME discipline as checkip's validateCheckIPURL, while remaining
// TEMPLATE-AWARE: a valid template carrying inadyn %h/%i/%u/%p specifiers — even
// a credential in the userinfo, which makes net/url.Parse FAIL — must be
// accepted. Goes RED if the validation reverts to prefix-only or switches to a
// naive url.Parse.
func TestGenericURLTemplateValidation(t *testing.T) {
	reject := []string{
		"https://",           // scheme only, no host
		"https:///upd?ip=%i", // host-less but http(s):// prefix
		"ftp://host/upd",     // wrong scheme
		"not a url",          // no scheme
		"http//host/upd",     // missing colon -> no "://"
		"://host/upd",        // empty scheme
	}
	for _, tmpl := range reject {
		if err := validateGenericURLTemplate(tmpl); err == nil {
			t.Errorf("validateGenericURLTemplate(%q) = nil, want error", tmpl)
		}
		if _, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tmpl,
		}, nil); err == nil {
			t.Errorf("newGenericBackend(%q, nil) = nil error, want rejection", tmpl)
		}
	}

	accept := []string{
		"https://api.example.net/update?host=%h&ip=%i", // %-specifiers in query
		"http://api.example.net/upd",                   // plain http
		"HTTPS://api.example.net/upd?ip=%i",            // uppercase scheme (RFC 3986 §3.1)
		"https://user:%p@api.example.net/upd?host=%h",  // credential in userinfo (url.Parse FAILS here)
		"https://api.example.net:8443/upd?ip=%i",       // explicit port
	}
	for _, tmpl := range accept {
		if err := validateGenericURLTemplate(tmpl); err != nil {
			t.Errorf("validateGenericURLTemplate(%q) = %v, want nil", tmpl, err)
		}
		if _, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tmpl,
		}, nil); err != nil {
			t.Errorf("newGenericBackend(%q, nil) = %v, want nil", tmpl, err)
		}
	}

	// #2841 credential-leak fold: a malformed template that carries a secret in
	// the userinfo or query must NOT echo that secret in the construction error
	// (the error is logged via slog.Warn at the surface-A construction site). The
	// template is run through config.RedactURL before embedding. Goes RED if the
	// raw template is embedded again.
	for _, tc := range []struct {
		tmpl, secret string
	}{
		{"ftp://user:SUPERSECRET@host/upd", "SUPERSECRET"}, // wrong scheme + userinfo secret
		{"https:///upd?token=SUPERSECRET", "SUPERSECRET"},  // host-less + query secret
	} {
		_, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic", URLTemplate: tc.tmpl,
		}, nil)
		if err == nil {
			t.Fatalf("newGenericBackend(%q, nil) = nil error, want rejection", tc.tmpl)
		}
		if strings.Contains(err.Error(), tc.secret) {
			t.Errorf("construction error leaked the secret %q: %v", tc.secret, err)
		}
	}
}

func TestGenericRenderUnit(t *testing.T) {
	got := renderGenericURL("https://x/u?h=%h&i=%i&p=%p&lit=%%", "host.tld", "1.2.3.4", "", "p@ss")
	if !strings.Contains(got, "h=host.tld") || !strings.Contains(got, "i=1.2.3.4") {
		t.Fatalf("render missing host/ip: %q", got)
	}
	if !strings.Contains(got, "lit=%") {
		t.Fatalf("%%%% must render a literal percent: %q", got)
	}
	if !strings.Contains(got, "p=p%40ss") {
		t.Fatalf("%%p must be query-escaped: %q", got)
	}
}
