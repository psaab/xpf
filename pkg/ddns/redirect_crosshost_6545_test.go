package ddns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// redirect_crosshost_6545_test.go: fail-on-revert tests for #6545 — a 30x
// Location to a DIFFERENT host must never be followed by a DDNS HTTP client.
//
// #4861 closed the scheme half (https->http). The host half was left open: an
// https->https hop to another host passed the guard, and Go then hands the new
// host the FULL previous URL — query string included — in Referer. For DuckDNS
// (token is a query param), the generic backend (%p-expanded password / literal
// ?token= in url-template) and a credential-bearing checkip-url, that IS the
// provider credential. Go additionally forwards Authorization/Cookie to any
// SUBDOMAIN of the original host, which hands the dyndns2/generic Basic
// credential and the Cloudflare bearer token to an unconfigured box.
//
// The assertions below are on what the SECOND server ACTUALLY RECEIVED, not on
// client-side state, and TestCrossHostRedirectWouldLeakWithoutHostGuard is the
// mutation-sensitivity control: it runs the identical harness with the
// pre-#6545 scheme-only policy and asserts the credential DOES arrive — so a
// revert of the host guard turns the leak test RED for the right reason.

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// redirectTestCA mints one self-signed cert covering every supplied hostname so
// the probe servers present a TLS identity the hardened client (which keeps full
// cert + hostname verification on) actually validates. Using real DNS names
// rather than 127.0.0.1/::1 is what makes "cross-host" meaningful here: the two
// servers differ by NAME, exactly as www.duckdns.org differs from evil.example.
func redirectTestCA(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// hopLog records what a probe server actually received, per request.
type hopLog struct {
	mu   sync.Mutex
	hops []recordedHop
}

type recordedHop struct {
	server  string
	method  string
	rawURL  string
	referer string
	auth    string
	cookie  string
}

func (l *hopLog) add(server string, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hops = append(l.hops, recordedHop{
		server:  server,
		method:  r.Method,
		rawURL:  r.URL.String(),
		referer: r.Header.Get("Referer"),
		auth:    r.Header.Get("Authorization"),
		// Cookie is recorded for completeness because it is the OTHER header
		// net/http forwards across a subdomain hop. No in-tree DDNS backend sets
		// one and the shared client has a nil Jar, so Authorization is the live
		// carrier the assertions key on; this field exists so a future backend
		// that does set a Cookie is covered by the same assertions.
		cookie: r.Header.Get("Cookie"),
	})
}

func (l *hopLog) forServer(name string) []recordedHop {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []recordedHop
	for _, h := range l.hops {
		if h.server == name {
			out = append(out, h)
		}
	}
	return out
}

// startTLSProbe starts an httptest TLS server presenting cert and returns it
// with its listener port.
func startTLSProbe(t *testing.T, cert tls.Certificate, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	return srv, port
}

// hardenedClientFor returns the REAL production client (newHTTPClient — same
// CheckRedirect wiring every backend gets) with the probe CA trusted and a
// DialContext that maps the probe hostnames onto their listeners. Only the trust
// root and the name resolution are test scaffolding; the redirect policy under
// test is untouched production code.
func hardenedClientFor(t *testing.T, pool *x509.CertPool, hosts map[string]string) *http.Client {
	t.Helper()
	cl := newHTTPClient()
	tr, ok := cl.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("newHTTPClient transport is %T, want *http.Transport", cl.Transport)
	}
	tr.TLSClientConfig.RootCAs = pool
	var d net.Dialer
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if real, ok := hosts[addr]; ok {
			return d.DialContext(ctx, network, real)
		}
		return nil, fmt.Errorf("test: unmapped dial to %q", addr)
	}
	return cl
}

// duckdnsLeakHarness wires the whole scenario: a "provider" host that 302s to
// wherever locFn says, a separate "collector" host, and a DuckDNS backend (the
// backend whose credential is a QUERY PARAM) pointed at the provider. Returns
// the update error and the hop log.
func duckdnsLeakHarness(t *testing.T, policy func(*http.Request, []*http.Request) error,
	locFn func(providerPort, collectorPort string) string,
) (error, *hopLog) {
	t.Helper()
	const provHost, collHost = "prov.example", "collector.example"
	cert, pool := redirectTestCA(t, provHost, collHost)
	log := &hopLog{}

	_, collPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("collector", r)
		fmt.Fprint(w, "OK")
	})
	var provPort string
	loc := ""
	_, provPort = startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		http.Redirect(w, r, loc, http.StatusFound)
	})
	loc = locFn(provPort, collPort)

	cl := hardenedClientFor(t, pool, map[string]string{
		provHost + ":" + provPort: "127.0.0.1:" + provPort,
		collHost + ":" + collPort: "127.0.0.1:" + collPort,
	})
	if policy != nil {
		cl.CheckRedirect = policy
	}

	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name:     "duck",
		Backend:  "duckdns",
		Server:   "https://" + provHost + ":" + provPort + "/update",
		APIToken: config.Secret(leakToken),
	}, cl)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	return b.UpsertLease(context.Background(), hostRecord(t, "myhost.duckdns.org", "203.0.113.7")), log
}

// leakToken is the sentinel credential every leak assertion greps for.
const leakToken = "TOKEN-MUST-NOT-LEAK"

// assertNoTokenAt fails if the named server saw any request at all, or if any
// request it saw carried the sentinel token anywhere in the URL or headers.
func assertNoTokenAt(t *testing.T, log *hopLog, server string) {
	t.Helper()
	hops := log.forServer(server)
	if len(hops) != 0 {
		t.Fatalf("%s received %d request(s) it must never have seen: %+v", server, len(hops), hops)
	}
}

// ---------------------------------------------------------------------------
// 1. the leak itself
// ---------------------------------------------------------------------------

// TestCrossHostRedirectDoesNotLeakCredential is the #6545 fail-on-revert gate.
// A DuckDNS update (token in the QUERY STRING) hits a provider host that 302s
// https->https to a DIFFERENT host. The collector must receive NOTHING.
//
// RED on revert: drop the cross-host branch from guardRedirect and the client
// follows the Location, handing the collector
// "Referer: https://prov.example:PORT/update?domains=myhost&token=TOKEN-MUST-NOT-LEAK&ip=..."
// — the assertion below fires on the request the collector actually received.
func TestCrossHostRedirectDoesNotLeakCredential(t *testing.T) {
	err, log := duckdnsLeakHarness(t, nil, func(_, collPort string) string {
		return "https://collector.example:" + collPort + "/collect"
	})
	if err == nil {
		t.Fatal("UpsertLease followed a cross-host redirect and reported success; want a refusal error")
	}
	if !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("want a cross-host refusal error, got: %v", err)
	}
	// The error must not itself carry the token (doRequest scrubs *url.Error).
	if strings.Contains(err.Error(), leakToken) {
		t.Fatalf("refusal error leaked the token: %v", err)
	}
	assertNoTokenAt(t, log, "collector")

	// The provider host — the operator-configured endpoint — was still reached.
	if got := log.forServer("provider"); len(got) != 1 {
		t.Fatalf("provider hops: want 1, got %d (%+v)", len(got), got)
	}
}

// TestCrossHostRedirectWouldLeakWithoutHostGuard is the mutation-sensitivity
// control. It drives the IDENTICAL harness with the pre-#6545 scheme-only
// policy and asserts the collector DOES receive the token in Referer. Without
// this, TestCrossHostRedirectDoesNotLeakCredential could pass for a reason
// unrelated to the guard (e.g. the servers never wired up). It also pins the
// firsthand mechanism finding: Go's refererForURL keeps the full query string
// on an https->https hop, stripping only the userinfo.
func TestCrossHostRedirectWouldLeakWithoutHostGuard(t *testing.T) {
	schemeOnly := func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) > 0 {
			prev := via[len(via)-1].URL
			if strings.EqualFold(prev.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return errors.New("downgrade")
			}
		}
		return nil
	}
	_, log := duckdnsLeakHarness(t, schemeOnly, func(_, collPort string) string {
		return "https://collector.example:" + collPort + "/collect"
	})
	hops := log.forServer("collector")
	if len(hops) != 1 {
		t.Fatalf("control: collector hops: want 1, got %d (%+v)", len(hops), hops)
	}
	if !strings.Contains(hops[0].referer, leakToken) {
		t.Fatalf("control: expected the scheme-only policy to leak the token via Referer, "+
			"got Referer=%q — the harness is not exercising the leak path", hops[0].referer)
	}
}

// TestCrossHostRedirectSubdomainRefused pins the second disclosure vector: Go's
// shouldCopyHeaderOnRedirect/isDomainOrSubdomain FORWARDS Authorization and
// Cookie to a subdomain of the original host, so a Location pointing at
// sub.<configured-host> would hand over the dyndns2/generic Basic credential and
// the Cloudflare bearer token. Stripping Referer alone would not have closed
// this; refusing the cross-host hop does.
//
// This is the unit-level half. The end-to-end half — a real dyndns2 backend
// driven through a real apex -> subdomain hop, asserting on what the SUBDOMAIN
// SERVER received, plus its mutation control — is
// TestSubdomainRedirectReceivesNothingWithGuard /
// TestSubdomainRedirectWouldLeakBasicAuthWithoutHostGuard below.
func TestCrossHostRedirectSubdomainRefused(t *testing.T) {
	via := []*http.Request{mkReq(t, "https://prov.example/upd")}
	err := guardRedirect(mkReq(t, "https://sub.prov.example/upd"), via)
	if err == nil {
		t.Fatal("a redirect to a SUBDOMAIN of the configured host was allowed; " +
			"Go forwards Authorization/Cookie across that hop")
	}
	if !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("want a cross-host refusal, got: %v", err)
	}
}

// TestCheckIPCrossHostRedirectRefused covers the checkip-url surface, which the
// issue flags as able to carry an API key in the query exactly like DuckDNS.
// CheckIP builds its own request rather than going through a backend, so it is
// a distinct client path and gets its own assertion.
func TestCheckIPCrossHostRedirectRefused(t *testing.T) {
	const provHost, collHost = "checkip.example", "collector.example"
	cert, pool := redirectTestCA(t, provHost, collHost)
	log := &hopLog{}

	_, collPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("collector", r)
		fmt.Fprint(w, "198.51.100.9")
	})
	loc := "https://" + collHost + ":" + collPort + "/ip"
	_, provPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		http.Redirect(w, r, loc, http.StatusFound)
	})

	cl := hardenedClientFor(t, pool, map[string]string{
		provHost + ":" + provPort: "127.0.0.1:" + provPort,
		collHost + ":" + collPort: "127.0.0.1:" + collPort,
	})
	urlStr := "https://" + provHost + ":" + provPort + "/whatismyip?apikey=" + leakToken
	addr, ok, err := CheckIP(context.Background(), cl, urlStr, true, nil)
	if ok {
		t.Fatalf("CheckIP followed a cross-host redirect and returned %v; want a miss", addr)
	}
	assertNoTokenAt(t, log, "collector")

	// The refusal must be REPORTABLE, not a silent ok=false. A checkip-url whose
	// endpoint redirects cross-host is a permanent CONFIGURATION error — exactly
	// what this package's own doctrine (validateCheckIPURL, "a malformed URL is a
	// configuration error, not a transient") says must not masquerade as a
	// transient observation failure. Without the error return the daemon has no
	// signal at all and the operator sees publishing stop for no stated reason,
	// forever — the #2773/#3737 class. The publish path already names this
	// failure; the checkip path must too.
	if err == nil {
		t.Fatal("CheckIP swallowed the cross-host refusal (err=nil); a permanently " +
			"misconfigured checkip-url must be distinguishable from an ordinary " +
			"no-address miss, or it is undiagnosable forever")
	}
	if !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("want the cross-host refusal reason in the error, got: %v", err)
	}
	// ... and reporting it must not undo the scrub: the API key rides in the
	// checkip-url QUERY, which is precisely what scrubURLError strips.
	if strings.Contains(err.Error(), leakToken) {
		t.Fatalf("the reported error leaked the checkip API key: %v", err)
	}
}

// TestCheckIPNoAddressIsNotAnError is the counterpart over-reach guard for the
// error return: an endpoint that ANSWERS but carries no address of the requested
// family is the ordinary dual-stack miss (a v4-only checkip service queried for
// AAAA), not a failure. It must stay ok=false, err=nil so the daemon does not
// warn once per (provider, error) for every v6-less deployment on every family
// probe.
func TestCheckIPNoAddressIsNotAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "93.184.216.34\n")
	}))
	defer srv.Close()
	// wantV4=false against a v4-only body: a legitimate miss.
	a, ok, err := CheckIP(context.Background(), srv.Client(), srv.URL, false, nil)
	if ok {
		t.Fatalf("CheckIP(wantV4=false) returned %v; the body has no AAAA", a)
	}
	if err != nil {
		t.Fatalf("a no-address-of-this-family miss must NOT be an error (it is the "+
			"ordinary dual-stack case and would warn on every probe), got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 1b. vector 2 end-to-end — Authorization forwarded to a SUBDOMAIN
// ---------------------------------------------------------------------------

// subdomainHarness drives a real apex -> subdomain hop end to end through a
// dyndns2 backend, whose credential is Basic auth in the AUTHORIZATION HEADER —
// a different carrier from the DuckDNS query-param harness above, and the one Go
// actually forwards across a subdomain hop (shouldCopyHeaderOnRedirect ->
// isDomainOrSubdomain). prov.example 302s to sub.prov.example; the hop log
// records what the SUBDOMAIN server received.
//
// This is the apex->www shape in miniature, which is why it is the hop that
// cannot be re-allowed for ergonomics: www.<host> IS a subdomain of <host>.
func subdomainHarness(t *testing.T, policy func(*http.Request, []*http.Request) error) (error, *hopLog) {
	t.Helper()
	const provHost, subHost = "prov.example", "sub.prov.example"
	cert, pool := redirectTestCA(t, provHost, subHost)
	log := &hopLog{}

	_, subPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("subdomain", r)
		fmt.Fprint(w, "good 203.0.113.7")
	})
	loc := ""
	_, provPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		http.Redirect(w, r, loc, http.StatusFound)
	})
	loc = "https://" + subHost + ":" + subPort + "/nic/update"

	cl := hardenedClientFor(t, pool, map[string]string{
		provHost + ":" + provPort: "127.0.0.1:" + provPort,
		subHost + ":" + subPort:   "127.0.0.1:" + subPort,
	})
	if policy != nil {
		cl.CheckRedirect = policy
	}
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "dd", Backend: "dyndns2",
		Server:   "https://" + provHost + ":" + provPort + "/nic/update",
		Username: "ddnsuser",
		Password: config.Secret(leakBasicPassword),
	}, cl)
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}
	return b.UpsertLease(context.Background(), hostRecord(t, "myhost.example.net", "203.0.113.7")), log
}

// leakBasicPassword is the sentinel dyndns2 Basic credential. It must never
// reach the subdomain server, and must never appear in a refusal error.
const leakBasicPassword = "BASIC-MUST-NOT-LEAK"

// TestSubdomainRedirectWouldLeakBasicAuthWithoutHostGuard is the
// mutation-sensitivity control for vector 2. Under the pre-#6545 scheme-only
// policy the SUBDOMAIN server really does receive the dyndns2 Basic credential
// in an Authorization header — Go copies it because isDomainOrSubdomain says
// sub.prov.example is inside prov.example. Without this control,
// TestSubdomainRedirectReceivesNothingWithGuard could pass for a reason
// unrelated to the guard (servers never wired, backend never built the auth).
func TestSubdomainRedirectWouldLeakBasicAuthWithoutHostGuard(t *testing.T) {
	schemeOnly := func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) > 0 {
			prev := via[len(via)-1].URL
			if strings.EqualFold(prev.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return errors.New("downgrade")
			}
		}
		return nil
	}
	_, log := subdomainHarness(t, schemeOnly)
	hops := log.forServer("subdomain")
	if len(hops) != 1 {
		t.Fatalf("control: subdomain hops = %d, want 1 (%+v)", len(hops), hops)
	}
	if hops[0].auth == "" {
		t.Fatalf("control: the subdomain received NO Authorization header — the "+
			"vector-2 claim (Go forwards Authorization across a subdomain hop) is "+
			"not being exercised; got hop %+v", hops[0])
	}
	// Decoded, that header IS the configured password.
	if !basicAuthCarries(t, hops[0].auth, leakBasicPassword) {
		t.Fatalf("control: subdomain Authorization %q does not carry the configured "+
			"password; the harness is not exercising the real credential", hops[0].auth)
	}
}

// TestSubdomainRedirectReceivesNothingWithGuard is the #6545 fail-on-revert gate
// for vector 2, end to end through the production policy: the subdomain server
// must receive NOTHING AT ALL — no Authorization, no Cookie, no Referer, no
// request. Asserted on what the second server actually received, not on
// client-side state.
//
// RED on revert: drop the cross-host branch from guardRedirect and the client
// follows the Location, handing sub.prov.example the Basic credential (the
// control above proves that is what happens).
func TestSubdomainRedirectReceivesNothingWithGuard(t *testing.T) {
	err, log := subdomainHarness(t, nil)
	if err == nil {
		t.Fatal("UpsertLease followed a redirect to a SUBDOMAIN and reported success; " +
			"Go forwards Authorization/Cookie across that hop")
	}
	if !strings.Contains(err.Error(), "cross-host") {
		t.Fatalf("want a cross-host refusal error, got: %v", err)
	}
	if strings.Contains(err.Error(), leakBasicPassword) {
		t.Fatalf("refusal error leaked the Basic credential: %v", err)
	}
	hops := log.forServer("subdomain")
	if len(hops) != 0 {
		t.Fatalf("subdomain received %d request(s) it must never have seen: %+v", len(hops), hops)
	}
	// Redundant at zero hops today, but it states the invariant the refusal is
	// FOR: should anyone ever swap refuse-the-hop for sanitize-and-follow, this
	// fires on the credential carriers rather than only on the hop count.
	for _, h := range hops {
		if h.auth != "" || h.cookie != "" || h.referer != "" {
			t.Fatalf("subdomain hop carried a credential: auth=%q cookie=%q referer=%q",
				h.auth, h.cookie, h.referer)
		}
	}
	// The operator-configured apex host was still reached exactly once.
	if got := log.forServer("provider"); len(got) != 1 {
		t.Fatalf("provider hops: want 1, got %d (%+v)", len(got), got)
	}
}

// basicAuthCarries reports whether an Authorization header value is Basic auth
// whose decoded password is want — so the control asserts on the REAL credential
// rather than on the mere presence of a header.
func basicAuthCarries(t *testing.T, authHeader, want string) bool {
	t.Helper()
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, prefix))
	if err != nil {
		t.Fatalf("decode Authorization %q: %v", authHeader, err)
	}
	_, pass, found := strings.Cut(string(raw), ":")
	return found && pass == want
}

// ---------------------------------------------------------------------------
// 2. over-reach guards — what must STILL work
// ---------------------------------------------------------------------------

// TestSameHostRedirectStillPublishes is the over-reach guard: the common real
// redirect (a path / API-version move on the SAME host) must still be followed
// and the update must succeed. It also asserts the #6545 Referer strip on the
// followed hop — the second server sees no Referer at all, so the query-string
// token is not echoed into a separately-logged header.
//
// GREEN under revert: this is behaviour the fix must not break.
func TestSameHostRedirectStillPublishes(t *testing.T) {
	const provHost = "prov.example"
	cert, pool := redirectTestCA(t, provHost)
	log := &hopLog{}

	_, provPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		if r.URL.Path == "/update" {
			http.Redirect(w, r, "/v2/update?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		fmt.Fprint(w, "OK")
	})
	cl := hardenedClientFor(t, pool, map[string]string{
		provHost + ":" + provPort: "127.0.0.1:" + provPort,
	})
	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns",
		Server:   "https://" + provHost + ":" + provPort + "/update",
		APIToken: config.Secret(leakToken),
	}, cl)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "myhost.duckdns.org", "203.0.113.7")); err != nil {
		t.Fatalf("same-host redirect must still publish, got: %v", err)
	}

	hops := log.forServer("provider")
	if len(hops) != 2 {
		t.Fatalf("provider hops: want 2 (redirect + final), got %d (%+v)", len(hops), hops)
	}
	// The final hop is the redirect target and still carries the token in its
	// own query (that is the request the provider asked for) ...
	if !strings.Contains(hops[1].rawURL, leakToken) {
		t.Fatalf("final hop lost the update query: %q", hops[1].rawURL)
	}
	// ... but Referer must have been stripped by guardRedirect.
	if hops[1].referer != "" {
		t.Fatalf("followed redirect carried Referer=%q; want it stripped", hops[1].referer)
	}
}

// TestNoRedirectUpdateStillWorks is the plain-path over-reach guard: an ordinary
// non-redirecting update is untouched by the new policy (CheckRedirect is never
// consulted) and must publish cleanly.
func TestNoRedirectUpdateStillWorks(t *testing.T) {
	const provHost = "prov.example"
	cert, pool := redirectTestCA(t, provHost)
	log := &hopLog{}
	_, provPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		fmt.Fprint(w, "OK")
	})
	cl := hardenedClientFor(t, pool, map[string]string{provHost + ":" + provPort: "127.0.0.1:" + provPort})
	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns",
		Server:   "https://" + provHost + ":" + provPort + "/update",
		APIToken: config.Secret(leakToken),
	}, cl)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}
	if err := b.UpsertLease(context.Background(), hostRecord(t, "myhost.duckdns.org", "203.0.113.7")); err != nil {
		t.Fatalf("plain update: %v", err)
	}
	if got := len(log.forServer("provider")); got != 1 {
		t.Fatalf("provider hops: want 1, got %d", got)
	}
}

// TestRedirectHopCapPreserved pins the hop cap: setting CheckRedirect replaces
// Go's built-in 10-hop limit, so the policy must keep re-implementing it. Driven
// against a real SAME-HOST redirect loop (which the host guard allows), so the
// cap — not the host guard — is what stops it. Asserts on what the server
// received.
//
// The count is maxRedirects TOTAL requests, not maxRedirects+1: the policy
// refuses at len(via) >= maxRedirects, so the loop runs 1 initial request plus
// maxRedirects-1 followed redirects and the 10th redirect is refused. That is
// byte-identical to net/http's own defaultCheckRedirect, which is the point —
// replacing the default policy must not change the cap's arithmetic.
func TestRedirectHopCapPreserved(t *testing.T) {
	const provHost = "prov.example"
	cert, pool := redirectTestCA(t, provHost)
	log := &hopLog{}
	_, provPort := startTLSProbe(t, cert, func(w http.ResponseWriter, r *http.Request) {
		log.add("provider", r)
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	cl := hardenedClientFor(t, pool, map[string]string{provHost + ":" + provPort: "127.0.0.1:" + provPort})
	req, err := http.NewRequest(http.MethodGet, "https://"+provHost+":"+provPort+"/loop", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := cl.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a same-host redirect loop was followed without hitting the hop cap")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("stopped after %d redirects", maxRedirects)) {
		t.Fatalf("want the %d-hop cap error, got: %v", maxRedirects, err)
	}
	if got := len(log.forServer("provider")); got != maxRedirects {
		t.Fatalf("server saw %d requests, want %d (initial + %d followed redirects, "+
			"the %dth refused) — same arithmetic as net/http defaultCheckRedirect",
			got, maxRedirects, maxRedirects-1, maxRedirects)
	}
}

// ---------------------------------------------------------------------------
// 3. the host-comparison rule
// ---------------------------------------------------------------------------

// TestGuardRedirectHostRule pins the exact same-host predicate: hostname-only,
// case-insensitive, root-dot-normalized, port-INDEPENDENT.
func TestGuardRedirectHostRule(t *testing.T) {
	cases := []struct {
		name    string
		prev    string
		next    string
		wantErr bool
	}{
		{"same host, new path", "https://prov.example/upd", "https://prov.example/v2/upd", false},
		{"same host, case differs", "https://PROV.example/upd", "https://prov.EXAMPLE/upd", false},
		{"same host, root dot", "https://prov.example./upd", "https://prov.example/upd", false},
		{"same host, default port made explicit", "https://prov.example/upd", "https://prov.example:443/upd", false},
		{"same host, explicit port dropped", "https://prov.example:443/upd", "https://prov.example/upd", false},
		{"same host, port change", "https://prov.example/upd", "https://prov.example:8443/upd", false},
		{"same IPv6 literal", "https://[2001:db8::1]/upd", "https://[2001:db8::1]:8443/upd", false},

		{"different host", "https://prov.example/upd", "https://evil.example/upd", true},
		{"subdomain of configured host", "https://prov.example/upd", "https://sub.prov.example/upd", true},
		{"parent of configured host", "https://sub.prov.example/upd", "https://prov.example/upd", true},
		{"suffix-confusable host", "https://prov.example/upd", "https://notprov.example/upd", true},
		{"host to IP literal", "https://prov.example/upd", "https://192.0.2.7/upd", true},
		{"different IPv6 literal", "https://[2001:db8::1]/upd", "https://[2001:db8::2]/upd", true},
		{"cross-host downgrade still refused", "https://prov.example/upd", "http://evil.example/upd", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := guardRedirect(mkReqH(t, tc.next), []*http.Request{mkReq(t, tc.prev)})
			if tc.wantErr && err == nil {
				t.Fatalf("expected %s -> %s to be refused, got nil", tc.prev, tc.next)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %s -> %s to be allowed, got: %v", tc.prev, tc.next, err)
			}
		})
	}
}

// TestGuardRedirectStripsReferer asserts the header strip happens on an ALLOWED
// (same-host) hop — the unit-level half of the assertion
// TestSameHostRedirectStillPublishes makes end-to-end.
func TestGuardRedirectStripsReferer(t *testing.T) {
	next := mkReqH(t, "https://prov.example/v2/upd")
	next.Header.Set("Referer", "https://prov.example/upd?token="+leakToken)
	if err := guardRedirect(next, []*http.Request{mkReq(t, "https://prov.example/upd")}); err != nil {
		t.Fatalf("same-host redirect refused: %v", err)
	}
	if got := next.Header.Get("Referer"); got != "" {
		t.Fatalf("Referer not stripped on a followed redirect: %q", got)
	}
}

// TestGuardRedirectFirstHopUnrestricted asserts the policy never interferes with
// the initial request (via is empty) — the caller's own URL is by definition the
// configured endpoint.
func TestGuardRedirectFirstHopUnrestricted(t *testing.T) {
	if err := guardRedirect(mkReqH(t, "https://prov.example/upd"), nil); err != nil {
		t.Fatalf("first hop must not be restricted, got: %v", err)
	}
}

// mkReqH is mkReq plus a non-nil header map, for the cases that assert on the
// Referer strip.
func mkReqH(t *testing.T, rawurl string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse %q: %v", rawurl, err)
	}
	return &http.Request{URL: u, Header: http.Header{}}
}

// TestRedirectHost pins the host normalizer directly, including the IPv6
// bracket unwrap and the port drop.
func TestRedirectHost(t *testing.T) {
	cases := map[string]string{
		"https://prov.example/x":        "prov.example",
		"https://prov.example:8443/x":   "prov.example",
		"https://prov.example./x":       "prov.example",
		"https://[2001:db8::1]:443/x":   "2001:db8::1",
		"https://192.0.2.7/x":           "192.0.2.7",
		"https://user:pw@prov.example/": "prov.example",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := redirectHost(u); got != want {
			t.Errorf("redirectHost(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestAllHTTPBackendsShareTheGuard is the coverage assertion for requirement 3:
// every DDNS HTTP client in the package — the unbound default, a bound one, a
// cached one, and the checkip probe client — carries the SAME redirect policy,
// so no backend can build a client that quietly follows a cross-host Location.
// The package has exactly one *http.Client construction site
// (newHTTPClientBound) and one Do() site (doRequest); this pins that the four
// constructor entry points all route through it.
func TestAllHTTPBackendsShareTheGuard(t *testing.T) {
	bound, err := newProviderHTTPClient(&config.DDNSProvider{Name: "p"})
	if err != nil {
		t.Fatalf("newProviderHTTPClient: %v", err)
	}
	cached, err := newHTTPClientCache().clientFor(&config.DDNSProvider{Name: "p"})
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	checkip, err := NewCheckIPClient(&config.DDNSProvider{Name: "p"})
	if err != nil {
		t.Fatalf("NewCheckIPClient: %v", err)
	}
	clients := map[string]*http.Client{
		"newHTTPClient":          newHTTPClient(),
		"newProviderHTTPClient":  bound,
		"httpClientCache.for":    cached,
		"NewCheckIPClient":       checkip,
		"newHTTPClientBound(v6)": newHTTPClientBound(bindConfig{}),
	}
	via := []*http.Request{mkReq(t, "https://prov.example/upd")}
	for name, cl := range clients {
		if cl.CheckRedirect == nil {
			t.Errorf("%s: no CheckRedirect; a cross-host redirect would be followed", name)
			continue
		}
		if err := cl.CheckRedirect(mkReqH(t, "https://evil.example/upd"), via); err == nil {
			t.Errorf("%s: followed a cross-host redirect; want refused", name)
		}
		if err := cl.CheckRedirect(mkReqH(t, "http://prov.example/upd"), via); err == nil {
			t.Errorf("%s: followed an HTTPS->HTTP downgrade; want refused", name)
		}
	}
}
