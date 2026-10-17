package ddns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/config"
)

// backend_http.go: shared discipline for the HTTP-API DDNS backends (#2691 P3,
// plan §5.2/§8.1/§8.3). The dyndns2, Cloudflare, Route 53, and generic-templated
// backends all implement the SAME DNSUpdater interface the RFC 2136 backend does
// (UpsertLease / DeleteLease over a LeaseDNSRecord) so the Surface A engine
// drives them identically — change-detection, forced-refresh, per-RG HA gate,
// and flat error backoff all apply unchanged. Only the wire mechanism differs.
//
// Security / ban-avoidance discipline shared here (plan §8.1/§8.3):
//   - HTTPS with the system trust store; certificate + hostname verification
//     stays ON (no InsecureSkipVerify) — the inadyn secure-ssl default-on posture.
//   - bounded request timeout (no infinite hang) so a stuck provider can never
//     wedge the reconcile loop.
//   - the response body is read with an io.LimitReader cap so a hostile/buggy
//     provider cannot OOM the daemon.
//   - credentials come from config.Secret (Reveal() only at the transport
//     boundary); no secret is ever placed in an error string or a log line.

// httpClientTimeout bounds a single provider request. The Surface A engine's own
// per-pass timeout is 60s (daemon surfaceAReconcileTimeout); a per-request floor
// well under that lets a slow provider fail one scope without starving the pass.
const httpClientTimeout = 15 * time.Second

// httpDialTimeout bounds a single TCP connect on a bound HTTP client (#2846).
// Well under httpClientTimeout so a black-holed source bind fails the connect
// (and the pass) promptly rather than consuming the whole request budget.
const httpDialTimeout = 10 * time.Second

// httpMaxResponseBody caps how many bytes of a provider response we read. dyndns2
// replies are a few bytes ("good 203.0.113.5\n"); Cloudflare/Route53 JSON/XML
// replies are a few KB. 64 KiB is generous and OOM-safe.
const httpMaxResponseBody = 64 << 10

// errHTTPAuth is a hard, non-retryable auth/abuse failure (dyndns2
// badauth/abuse/!donator, HTTP 401/403). The engine's flat backoff treats every
// error the same (back off, never crash), but classifying it lets the backend
// log a single clear message and stops a publish from being silently retried as
// if transient. Wrapped, never bare, so callers can errors.Is it.
var errHTTPAuth = errors.New("ddns http: authentication/authorization refused")

// errHTTPRateLimited marks a provider rate-limit / throttle response (dyndns2
// 911/dnserr, HTTP 429). The engine backs off; this lets the backend log it as
// a ban-avoidance signal rather than a generic failure.
var errHTTPRateLimited = errors.New("ddns http: provider rate-limited")

// errRedirectRefused is the sentinel CALLERS match with errors.Is to classify a
// refusal. It is NOT what the scrubber trusts — see redirectRefusal.
var errRedirectRefused = errors.New("ddns http: redirect refused")

// redirectReason is the CLOSED set of things guardRedirect refuses.
type redirectReason string

const (
	redirectReasonHopCap    redirectReason = "hop-cap"
	redirectReasonDowngrade redirectReason = "downgrade"
	redirectReasonCrossHost redirectReason = "cross-host"
)

// redirectRefusal is guardRedirect's typed refusal, and the ONLY error whose
// text scrubInnerError will render.
//
// ROUND 8 REPLACED A SENTINEL WITH A TYPE, because the sentinel was FORGEABLE.
// The previous form asked errors.Is(err, errRedirectRefused) and, on a match,
// returned err.Error() verbatim. errors.Is dispatches to the error's OWN
// `Is(error) bool` method, and CheckIP takes a caller-supplied *http.Client —
// so a RoundTripper returning an error whose Is always says true and whose
// Error() is the request URL got the credential printed unchanged. Identity is
// not something a caller-supplied value can be asked about; errors.As has the
// same hole (it dispatches to `As(any) bool`).
//
// A concrete UNEXPORTED struct type cannot be forged: no other package can name
// it, so no other package can construct a value of it, and a type assertion is
// a language operation with no user-defined hook. scrubInnerError therefore
// walks the chain itself and type-ASSERTS rather than asking errors.Is/As.
//
// The fields hold the *url.URL values, not pre-rendered text, so the host and
// scheme grammar is applied HERE at render time — unconditionally, on the way
// out — rather than trusted to have been applied at construction. What that
// buys is a bounded CHARACTER SET on a provider-supplied host: a zone id, raw
// non-ASCII, or anything that is not a plain reg-name is withheld.
//
// The grammar does NOT bound the CONTENT, only the character set — and that is
// why the refused TARGET is no longer rendered at all. A provider answering
// `Location: https://<our-own-password>.evil.example/` gets the hop refused,
// but `<password>.evil.example` is a well-formed reg-name, so naming it printed
// the credential into the daemon log. The general-case justification in
// scrubURLError — that such a name is already in every resolver query and TLS
// ClientHello — is FALSE here: CheckRedirect aborts before any dial, so a
// refused target is never resolved and never sent anywhere.
//
// It also broke deduplication, which is what forced the fix rather than another
// paragraph of disclosure. The daemon keys a never-pruned, process-lifetime
// sync.Map on the rendered string to warn once per (provider, error); a
// provider redirecting to per-request hostnames therefore minted a fresh key
// and a fresh WARN every 30s reconcile tick, forever. Exactly the unbounded
// growth the body-read scrub was added to stop, on the OTHER of doRequest's two
// adjacent error returns.
//
// So Error() now names only the FROM host (our configured endpoint, stable) and
// describes the target by class. scrubURLErrorAt additionally suppresses its own
// target render when the chain carries a refusal, because net/http sets
// url.Error.URL to the provider's Location — without that, the same
// provider-chosen value came out twice.
type redirectRefusal struct {
	reason redirectReason
	// via[0] — the request THIS package built from configuration — not the
	// previous hop. Same-host comparison is lenient about case, a trailing dot
	// and the default port, so a provider can take an allowed hop to its own
	// spelling of our host; rendering that made the message vary per request.
	from *url.URL // configured origin; nil for the hop cap
	// Held so the grammar can be applied at render time, but NEVER rendered:
	// it is provider-chosen, so it both discloses a credential-shaped reg-name
	// and varies per request. Kept for the same-host DECISION and for tests.
	to *url.URL // refused target; nil for the hop cap
}

// Error renders the refusal from FIXED prose plus grammar-bounded tokens. Every
// interpolated value is either a compile-time constant of this package or the
// output of refusalHost/refusalScheme, both of which are total into a closed
// character set. Nothing here reads another error's text.
func (r *redirectRefusal) Error() string {
	switch r.reason {
	case redirectReasonHopCap:
		return fmt.Sprintf("ddns http: stopped after %d redirects", maxRedirects)
	case redirectReasonDowngrade:
		// r.to is PROVIDER-CHOSEN and therefore varies per request; r.from is
		// our configured endpoint and is stable. Rendering r.to broke the
		// daemon's once-per-(provider,error) dedup: a provider redirecting to
		// per-request hostnames minted a fresh key in a never-pruned map on
		// every 30s tick. The scheme is a closed two-value grammar, so it is
		// safe and useful; the host is neither.
		return "ddns http: refusing HTTPS->" + refusalScheme(r.to) +
			" redirect downgrade from " + refusalHost(r.from) +
			" to a provider-supplied host (would expose update credentials in " +
			"cleartext)"
	case redirectReasonCrossHost:
		return "ddns http: refusing cross-host redirect from " + refusalHost(r.from) +
			" to a provider-supplied host that is not the configured endpoint " +
			"(would disclose the update credentials and payload); point the " +
			"provider endpoint at the final host instead"
	}
	return errRedirectRefused.Error()
}

// Is lets callers keep classifying with errors.Is(err, errRedirectRefused).
// Providing it is safe in the direction that matters: it is OUR type answering
// about itself, not us believing a stranger's answer.
func (r *redirectRefusal) Is(target error) bool { return target == errRedirectRefused }

// newHTTPClient builds the shared, hardened HTTP client for every HTTP backend
// with NO source binding (the default route / kernel-chosen source). TLS
// verification is ON; the timeout is bounded. Exposed (not a package var) so each
// backend gets its own client with no shared mutable state, and tests can point
// Transport at an httptest server.
func newHTTPClient() *http.Client {
	return newHTTPClientBound(bindConfig{})
}

// newHTTPClientBound builds the same hardened HTTP client but applies the
// provider's transport source binding (source-address / destination-interface /
// routing-instance, #2846) to the dial — so Cloudflare/Route53/dyndns2/generic
// updates and external checkip probes egress from the operator-configured source
// IP / interface / VRF, matching the RFC 2136 backend (backend_bind.go).
//
// When the bindConfig requests no binding (the zero value) the Transport gets no
// DialContext override and behaves byte-for-byte like the unbound client — the
// default-route behaviour for an operator who never set a source-address.
//
// The bind reuses backend_bind.go's dialer(): a single Dialer.Control hook that
// does unix.Bind(source-address) + SO_BINDTODEVICE(interface/VRF). For HTTP we
// expose it via Transport.DialContext (the dialer is connection-typed "tcp" for
// HTTP, so the Control-based bind — not a network-typed LocalAddr — is what keeps
// it working across both families uniformly). httpDialTimeout bounds the connect.
//
// #5327: when a source-address is configured the DialContext is wrapped
// (boundDialContext) to PIN the dial to the source family, so Happy-Eyeballs
// cannot pick the other family and silently skip the source bind (an update that
// then egresses the wrong WAN / bypasses a source ACL / publishes the wrong
// address). An endpoint with no address in the source family FAILS CLOSED at the
// dial instead of egressing unbound.
func newHTTPClientBound(b bindConfig) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// InsecureSkipVerify deliberately left false: certificate +
			// hostname verification against the system trust store.
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if d := b.dialer(httpDialTimeout); d != nil {
		// #5327: pin the dial to the configured source-address family via a
		// DialContext wrapper (constrainDialNetwork) so Happy-Eyeballs cannot pick
		// the other family and skip the source bind — which would egress the update
		// from a kernel-chosen source on the wrong WAN. A device-only bind (no
		// source-address) passes the network through unchanged.
		tr.DialContext = b.boundDialContext(d)
	}
	return &http.Client{
		Timeout:       httpClientTimeout,
		Transport:     tr,
		CheckRedirect: guardRedirect,
	}
}

// maxRedirects re-implements Go's built-in redirect cap. Setting CheckRedirect
// REPLACES http.Client's default 10-hop limit, so the cap has to be restored by
// the policy itself or a redirect loop would spin forever inside one request.
const maxRedirects = 10

// guardRedirect is the shared *http.Client.CheckRedirect for every HTTP DDNS
// backend. It enforces three things on a 30x Location, and restores the hop cap
// the default policy would otherwise have provided.
//
//  1. NO SCHEME DOWNGRADE (#4861). A credentialed backend (dyndns2 Basic auth,
//     DuckDNS/Cloudflare query/bearer token, Route 53 SigV4) that started over
//     TLS must never be walked onto a plaintext connection, which would put the
//     update credential on the wire for an on-path attacker. An HTTP->HTTPS
//     upgrade is still followed.
//
//  2. NO CROSS-HOST REDIRECT (#6545). The scheme guard alone left an
//     https->https hop to a DIFFERENT host wide open, and Go discloses real
//     secrets across exactly that hop — verified firsthand against the stdlib,
//     not assumed:
//
//     - Referer carries the FULL previous URL INCLUDING the query string.
//     net/http refererForURL() strips only the userinfo and suppresses the
//     header only for https->http; on an https->https hop to any host the
//     redirect target receives e.g.
//     "https://www.duckdns.org/update?domains=h&token=<TOKEN>". That is a
//     live provider credential for DuckDNS (token is a QUERY param, not
//     Basic — see backend_duckdns.go), for the generic backend (a %p-expanded
//     password or a literal ?token= in url-template), and for a checkip-url
//     that carries an API key. It also discloses the FQDN and the public
//     address being published for every backend.
//
//     - Go forwards Authorization/Cookie to any SUBDOMAIN of the original
//     host (net/http shouldCopyHeaderOnRedirect -> isDomainOrSubdomain).
//     So a redirect to sub.<configured-host> hands the dyndns2/generic Basic
//     credential and the Cloudflare bearer token to a host the operator never
//     configured. Stripping Referer would NOT have closed that half.
//
//     Refusing outright, rather than sanitizing and following, is the choice
//     because these clients are machine-to-machine callers of an endpoint the
//     operator PINNED (a built-in provider constant, or a `server` /
//     `url-template` / `checkip-url` leaf). There is no discovery step that
//     needs to land somewhere else, and following a Location to an unconfigured
//     host is itself the trust violation: it sends the update payload (which
//     FQDN, which public address) — and on a 307/308 the whole request body,
//     e.g. a Route 53 change batch — to a host the operator never named. The
//     realistic trigger is a mistyped or hostile `server` leaf, and fail-closed
//     is this package's posture everywhere else (bind error, malformed
//     checkip-url, unrecognized response body). A provider that genuinely moves
//     to a new host is served by pointing the leaf at the final host; the error
//     names the CONFIGURED endpoint and the refusal class so the operator can do
//     exactly that. It deliberately does NOT name the refused target: that value
//     is provider-chosen, so rendering it both disclosed a credential-shaped
//     reg-name and varied per request, defeating the daemon's once-per-
//     (provider, error) dedup. SAME-host
//     redirects — the common real case, a path or API-version move — are still
//     followed.
//
//  3. NO Referer ON ANY FOLLOWED REDIRECT. Defense in depth on top of (2): the
//     hop we do allow is same-host, so the target already holds the credential
//     it is being sent, but there is no reason for a DDNS API call to echo its
//     own query string back into a header that provider access logs record
//     separately. Go sets Referer on the new request BEFORE calling
//     CheckRedirect precisely so a policy can override it (see the comment on
//     Client.do), so deleting it here is the supported seam. Deleting from a nil
//     header map is a defined no-op, so a synthetic request needs no guard.
//
// Host comparison is by HOSTNAME only — case-insensitive per RFC 4343, with one
// trailing root dot normalized away, and deliberately PORT-INDEPENDENT. The
// trust anchor is the DNS name and the TLS certificate identity bound to it,
// which is what the operator configured and what cert verification pins; a port
// move stays inside that identity, and a port-strict rule would falsely refuse
// the plain "https://prov.example:443/x" -> "https://prov.example/x" default-port
// normalization. A Unicode (non-punycode) Location host compares unequal to its
// A-label spelling and is refused; that is the conservative direction (a false
// refusal, never a false allow) and no in-tree provider uses an IDN host.
//
// The comparison is against the PREVIOUS hop, matching the scheme guard. Under
// exact equality that is equivalent to comparing against the original request:
// every hop must equal its predecessor, so by induction every hop equals hop 0.
func guardRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return &redirectRefusal{reason: redirectReasonHopCap}
	}
	if len(via) > 0 {
		prev := via[len(via)-1].URL
		// `origin` is what the REFUSAL renders, and it must be via[0] — the URL
		// this package built from configuration — not `prev`. Same-host
		// comparison is deliberately lenient about case, a trailing dot and the
		// default port, so a provider can first take an ALLOWED hop to its own
		// chosen spelling (`Prov.example`) and only then attempt the cross-host
		// one. Rendering `prev` then published that provider-chosen spelling,
		// and five case variants produced five distinct daemon strings — which
		// re-opens exactly the dedup defeat this refusal was just fixed to
		// close, one hop further out. via[0] is ours and is stable.
		origin := via[0].URL
		if strings.EqualFold(prev.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			// The scheme AND the host here come from the provider's Location
			// header. They are NOT rendered at construction — the refusal holds
			// the URLs and applies the grammar in Error(), so the bounding
			// cannot be skipped by a future edit to this call site.
			return &redirectRefusal{reason: redirectReasonDowngrade, from: origin, to: req.URL}
		}
		if !strings.EqualFold(redirectHost(prev), redirectHost(req.URL)) {
			return &redirectRefusal{reason: redirectReasonCrossHost, from: origin, to: req.URL}
		}
	}
	// Followed (same-host) hop: never echo the previous URL's query string —
	// which carries the DuckDNS/generic/checkip credential — into Referer.
	req.Header.Del("Referer")
	return nil
}

// refusalHost renders a host inside a guardRedirect refusal sentence: the safe
// grammar, or a fixed placeholder when the host does not fit it. It differs from
// safeHostText only in never returning "" — an empty slot mid-sentence ("refusing
// cross-host redirect from prov.example to ") reads as a bug rather than as a
// withheld value.
//
// This is a RENDERING helper only. guardRedirect's same-host DECISION still uses
// redirectHost on the raw values; a host that fails the grammar must be refused,
// not compared loosely.
func refusalHost(u *url.URL) string {
	if u == nil {
		return hostWithheldText
	}
	if h := safeHostText(u); h != "" {
		return h
	}
	return hostWithheldText
}

// refusalScheme renders a scheme inside a refusal sentence: http/https, or a
// fixed placeholder. Same rationale as refusalHost — the Location header's
// scheme is provider-supplied, and url.Parse bounds its character set but
// neither its content nor its length.
func refusalScheme(u *url.URL) string {
	if u == nil {
		return schemeWithheldText
	}
	if s := safeScheme(u.Scheme); s != "" {
		return s
	}
	return schemeWithheldText
}

// The fixed placeholders used wherever a value fails the grammar.
const (
	hostWithheldText   = "(host withheld: not a plain host name)"
	schemeWithheldText = "(scheme withheld: not http or https)"
)

// redirectHost normalizes a URL's host for guardRedirect's same-host test:
// the hostname with the port dropped (URL.Hostname also unwraps an IPv6 literal
// from its brackets) and one trailing root dot removed, so "prov.example." and
// "prov.example" are the one name they actually are. Case folding is left to the
// EqualFold comparison at the call site.
func redirectHost(u *url.URL) string {
	return strings.TrimSuffix(u.Hostname(), ".")
}

// httpClientCache caches the hardened *http.Client (and its underlying
// *http.Transport keep-alive connection pool) per distinct source-binding so the
// Surface A reconcile loop does not throw away the pool every pass (#2904). The
// Surface A engine rebuilds the lightweight backend OBJECT every reconcile
// (resolve-per-Reconcile, #2691) — that is cheap — but each rebuild previously
// called newProviderHTTPClient, which allocated a fresh http.Transport with its
// own (empty) connection pool. Every ~30s checkip probe and DNS update then paid
// a full TCP + TLS handshake from scratch (wasted CPU, added latency, ephemeral
// port churn).
//
// The cache key is the provider's source-binding inputs ONLY (source-address /
// destination-interface / routing-instance). Two providers that egress from the
// same source share one transport (correct: a transport's pool is keyed on the
// destination host:port, so cross-provider reuse only ever connects to the host
// the request actually targets). The client carries no provider credential or
// URL — those live on the backend object and are applied per-request — so it is
// safe to share. The cache invalidates implicitly: when an operator changes a
// binding leaf on commit the next reconcile resolves a NEW key and builds (and
// caches) a fresh bound transport.
//
// Reap on supersede (#2956): a binding-leaf change keys a FRESH entry, so the
// OLD entry is never looked up again — but it is not self-evicting. The
// SurfaceAManager lives for the whole daemon lifetime, so distinct historical
// binding tuples would otherwise accumulate forever (their *http.Transport +
// the idle-connection pool retained until process exit even though
// IdleConnTimeout reaps the sockets). Each reconcile pass therefore calls reap
// with the set of binding keys still referenced by the committed config; an
// entry whose key is gone has its idle connection pool closed and is dropped,
// bounding the map to current config under binding churn.
type httpClientCache struct {
	mu      sync.Mutex
	clients map[string]*cachedBoundClient
	// rootCAs, when non-nil, replaces the TLS trust roots on every client
	// this cache builds. Test-only (SetCheckIPRootCAsForTesting); production
	// leaves it nil so clients verify against the system trust store.
	rootCAs *x509.CertPool
}

// cachedBoundClient is a cached client plus the RESOLVED binding it was built
// with (#6754).
//
// The cache key stays the raw config leaves so the #2956 reap stays consistent,
// but the value a client is actually bound to is resolved — bindDevice comes
// from config.ResolveKernelIfName, whose output is a function of the WHOLE
// committed config (reth→physical member, the tunnel name map, the IRB→bridge
// map, SecureTunnelUnitNetdev, unit-vs-vlan-id). So the resolved device can
// change while all three key leaves stay byte-identical: move reth0's active
// member and `destination-interface reth0.50` keeps its key and silently keeps
// SO_BINDTODEVICE on the OLD physical device.
//
// Holding the resolved binding alongside the client lets a hit verify that the
// resolution still matches before reusing the pool, which is the check the raw
// key structurally cannot make.
type cachedBoundClient struct {
	client *http.Client
	bind   bindConfig
}

// closeIdleConns is the seam reap uses to drop a superseded client's keep-alive
// connection pool. It is a package var so a test can record that the reap
// actually fired (fail-on-revert for #2956). Production closes the transport's
// idle connections via the standard *http.Client.CloseIdleConnections.
var closeIdleConns = func(cl *http.Client) { cl.CloseIdleConnections() }

// newHTTPClientCache builds an empty per-binding client cache.
func newHTTPClientCache() *httpClientCache {
	return &httpClientCache{clients: map[string]*cachedBoundClient{}}
}

// bindCacheKey is the stable cache key for a provider's source binding. It is
// derived from the RAW config leaves (not the resolved bindConfig) so a commit
// that changes any binding leaf yields a different key and forces a rebuild. A
// nil provider keys to the unbound default (empty key).
func bindCacheKey(p *config.DDNSProvider) string {
	if p == nil {
		return ""
	}
	// NUL-separated so distinct field boundaries cannot collide (an interface
	// named "a" + VRF "b" must not key the same as interface "a\x00b").
	return p.SourceAddress + "\x00" + p.DestinationInterface + "\x00" + p.RoutingInstance
}

// clientFor returns the cached bound *http.Client for the provider's source
// binding, building and caching it on first use. The bind-resolution error (a
// malformed source-address) is returned alongside the UNBOUND default client;
// the error path is NOT cached so a corrected source-address on the next commit
// rebuilds cleanly. Returning the unbound client is a convenience for the
// no-source caller — a NON-nil error means the source could NOT be honored, and
// every caller MUST fail CLOSED on it (skip the publish / probe) rather than
// egress from that unbound client: the publish resolver (resolveSurfaceABackend,
// #4437) and the checkip observer (CheckIPBound, #3733) both do.
// resolveIf is the OPTIONAL committed-config interface-name resolver
// (cfg.ResolveKernelIfName) threaded from the daemon so a destination-interface
// binding resolves to the real kernel device (#5070). The cache KEY stays the
// raw binding leaves (bindCacheKey) so the #2956 reap stays consistent; only the
// bound client's SO_BINDTODEVICE target is resolved.
func (c *httpClientCache) clientFor(p *config.DDNSProvider, resolveIf ...func(string) string) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p, firstResolver(resolveIf))
	if err != nil {
		return newHTTPClient(), err
	}
	key := bindCacheKey(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if ent, ok := c.clients[key]; ok {
		if ent.bind == b {
			return ent.client, nil
		}
		// #6754: same raw leaves, DIFFERENT resolved binding. The old client's
		// SO_BINDTODEVICE points at a device this provider no longer egresses
		// from, so reusing it would keep publishing from the wrong interface
		// with no error anywhere. Release its idle pool — the reap keys on the
		// binding leaves, which have NOT changed, so it would never collect
		// this transport — and rebuild.
		closeIdleConns(ent.client)
	}
	cl := newHTTPClientBound(b)
	if c.rootCAs != nil {
		if tr, ok := cl.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
			tr.TLSClientConfig.RootCAs = c.rootCAs
		}
	}
	c.clients[key] = &cachedBoundClient{client: cl, bind: b}
	return cl, nil
}

// reap closes the idle-connection pool of, and evicts, every cached client whose
// binding key is NOT in the live set (#2956). The caller (the Surface A
// reconcile) passes the binding keys still referenced by the committed provider
// catalog + configured scopes, so a binding-leaf change that supersedes a cache
// entry on the next pass has its stale *http.Transport / idle pool released
// instead of lingering for the daemon lifetime. A key still in live (the active
// binding for a current scope) is preserved — only an actual key change is
// superseded. Safe on a nil cache (the test/no-cache manager). Takes c.mu (the
// same lock clientFor uses); the manager's m.mu is always the OUTER lock so
// there is no lock-order inversion.
func (c *httpClientCache) reap(live map[string]struct{}) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, ent := range c.clients {
		if _, ok := live[key]; ok {
			continue
		}
		closeIdleConns(ent.client)
		delete(c.clients, key)
	}
}

// size returns the number of cached clients (test observability for the #2956
// bounded-map invariant).
func (c *httpClientCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.clients)
}

// resolveProviderBindConfig derives the transport bindConfig (#2846) from a DDNS
// provider catalog entry's source-binding leaves. The HTTP backends carry the
// source-address / destination-interface / routing-instance on the provider
// (config.DDNSProvider, #2780); RFC 2136 reuses the same resolveBindConfig via a
// DHCPDynamicDNSConfig carrier. This adapts the provider shape onto the SAME
// resolveBindConfig discipline so an invalid source-address is a hard error
// (fail-open: the constructor degrades to the unbound default rather than
// emitting from the wrong source — see the callers).
func resolveProviderBindConfig(p *config.DDNSProvider, resolve func(string) string) (bindConfig, error) {
	if p == nil {
		return bindConfig{}, nil
	}
	return resolveBindConfig(&config.DHCPDynamicDNSConfig{
		SourceAddress:        p.SourceAddress,
		DestinationInterface: p.DestinationInterface,
		RoutingInstance:      p.RoutingInstance,
	}, resolve)
}

// newProviderHTTPClient builds a bound HTTP client for an HTTP backend from its
// provider's source-binding leaves (#2846). A malformed source-address fails
// open to the unbound default client (logged by the caller already has the commit
// warning) rather than wedging the backend — matching the rfc2136 fail-open
// posture. Returns the client and any bind-resolution error for the caller to
// surface; on error the returned client is the unbound default.
func newProviderHTTPClient(p *config.DDNSProvider, resolveIf ...func(string) string) (*http.Client, error) {
	b, err := resolveProviderBindConfig(p, firstResolver(resolveIf))
	if err != nil {
		return newHTTPClient(), err
	}
	return newHTTPClientBound(b), nil
}

// ensureProviderHTTPClient returns the caller-supplied client when non-nil
// (the Surface A reconcile path threads a cached, reused client through here,
// #2904), otherwise it builds a fresh bound client from the provider's
// source-binding leaves (the pre-#2904 self-contained path used by direct/test
// callers). On a bind-resolution error it fails open to the unbound default
// client and returns the error for the caller to surface — matching
// newProviderHTTPClient's posture.
func ensureProviderHTTPClient(p *config.DDNSProvider, client *http.Client) (*http.Client, error) {
	if client != nil {
		return client, nil
	}
	return newProviderHTTPClient(p)
}

// readCappedBody reads at most httpMaxResponseBody bytes of a response body and
// closes it. A provider that streams an unbounded body is truncated, never
// allowed to exhaust memory.
func readCappedBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, httpMaxResponseBody))
}

// doRequest issues one request against the backend's client with the reconcile
// context attached (so a pass timeout / shutdown cancels in-flight I/O) and
// returns the status code + the capped body. The caller classifies the verdict.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) (int, []byte, error) {
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		// SECURITY: client.Do returns a *url.Error whose Error() string embeds the
		// FULL request URL — including the query, which for the generic backend
		// carries the %p-expanded password. Scrub it to the transport error class
		// + a query-stripped URL so no secret reaches a log/error string.
		return 0, nil, fmt.Errorf("ddns http: request failed: %s", scrubURLError(err))
	}
	body, rerr := readCappedBody(resp)
	if rerr != nil {
		// SECURITY: reading the body is part of ISSUING the request, so this
		// return is subject to the same rule as the one above — it was the
		// second of two adjacent error returns and the only one still on %w.
		//
		// Two things came out of that. A mid-body RST yields a *net.OpError
		// whose text embeds the EPHEMERAL LOCAL PORT, which changes every
		// connection; the daemon's checkip probe keys a process-lifetime
		// sync.Map on this string to log "once per (provider, error)", so a
		// persistently RST-ing endpoint minted a new key and a new WARN every
		// reconcile tick, forever. And the caller supplies the *http.Client,
		// so the same adversary that owns RoundTrip owns resp.Body.Read and
		// could echo the request URL — the query, hence the password — here.
		//
		// scrubInnerError, not scrubURLError: rerr is not a *url.Error, and
		// the classifier is what bounds it to a declared constant.
		return resp.StatusCode, nil, fmt.Errorf("ddns http: read response: %s", scrubInnerError(rerr))
	}
	return resp.StatusCode, body, nil
}

// scrubURLError is the SINGLE renderer in this package for an error that may
// carry a request URL. Every DDNS site that fails while BUILDING or while
// ISSUING a request routes through it, so "no credential reaches a log" is a
// property of the package rather than of each call site remembering to redact
// (#6545 review). The one deliberate exception is the dyndns2 raw-`server`
// render in resolveDyndns2Endpoint, tracked separately as #6606 and pinned by
// an explicit, self-expiring exemption in the source gate
// (url_render_class_6545_test.go).
//
// WHAT IT RENDERS: at most SCHEME://HOST[:PORT], built by ALLOWLIST — and the
// allowlist is over the CHARACTERS, not just over the url.URL fields. Round 7
// found that field-level allowlisting was not enough: an allowlist is only as
// good as the safety of what it admits, and `Host` is NOT credential-free.
//
// Field-level allowlisting (a fresh url.URL carrying only Scheme and Host)
// closed the field-expansion class — User, Path, RawPath, RawQuery, Fragment,
// RawFragment, Opaque, OmitHost and anything net/url adds later are absent by
// construction. It did not close the credential class, because `Host` is a
// container for substituted template text, not a name. What url.Parse will
// legally leave in `Host` (verified against Go 1.26 net/url):
//
//   - AN IPv6 ZONE ID. RFC 6874 lets a zone use "basically any %-encoding it
//     likes", and net/url honours that: "https://[fe80::1%25%p]/update" is a
//     SUPPORTED generic template and parses to Host = "[fe80::1%<password>]".
//     u.Hostname() does not help — it strips the brackets and keeps the zone.
//   - A REG-NAME LABEL. "https://%p.example.com/" parses to
//     Host = "<password>.example.com" whenever the password is host-safe.
//   - RAW NON-ASCII BYTES. %-escapes above 0x7F are decoded in place, so
//     "ex%FFample.com" reaches Host as a literal 0xFF — log-injection material
//     on top of everything else.
//   - A PORT, which is digits-only (net/url's validOptionalPort) but is still
//     a place a numeric password can land.
//   - ANY OF THE ABOVE FROM THE PROVIDER. A cross-host Location echoing our own
//     credential as its hostname is refused by guardRedirect — correctly — and
//     the refusal named the host.
//
// Userinfo is NOT in this list: url.Parse splits "user:pass@host" into u.User,
// so an ordinary credentialed URL was already safe.
//
// So the host is rebuilt from a CLOSED GRAMMAR rather than copied (safeHostText):
// an IP literal is re-rendered from netip with its ZONE DROPPED, and a reg-name
// must be ASCII letters/digits/'-'/'_' in dot-separated labels or it is withheld
// entirely. The scheme is likewise reduced to the two values this package ever
// legitimately uses. What survives is exactly the network identity that is on
// the wire in the DNS query, the TCP SYN and the TLS SNI regardless; path,
// query, userinfo, fragment and zone id are all operator- or provider-supplied
// opaque bytes and are treated as secret.
//
// THE RESIDUAL, stated rather than papered over. Two things survive:
//
//   - a password used as the DNS NAME ("https://%p.example.com/"). It is
//     already in every resolver query, in the PTR/SNI the endpoint sees, and in
//     the TLS ClientHello; the renderer cannot tell a legitimate label from a
//     password without template-expansion taint, and withholding every hostname
//     would gut diagnosis.
//   - a NUMERIC password used as a valid port ("https://prov.example:%p/"),
//     which is retained as up to five decimal digits.
//
// Both are configuration errors the logging boundary cannot repair, and hiding
// them would make them less likely to be noticed. But note the asymmetry
// honestly: a log is durable and often more widely readable than a packet
// capture, so "disclosed elsewhere" is a reason to accept these two, not a
// general licence to log secrets.
//
// The diagnostic cost of dropping the path is deliberate and small: the
// caller's own prefix already names the backend and the operation ("ddns
// cloudflare: build request", "ddns route53: build list request"), so what is
// lost is the API sub-path, not the ability to tell which call failed.
//
// A URL THAT DOES NOT RE-PARSE yields NO URL at all — only the sanitized
// urlParseCause reason. The old code fell back to ue.URL VERBATIM, which was
// survivable only while this helper was reachable exclusively from the
// transport path, where the URL had necessarily parsed on the way in. It is now
// also the renderer for BUILD-request failures, whose DEFINING input is a URL
// that does not parse, so that fallback would have been a direct leak of the
// whole raw string.
//
// THE INNER ERROR is rendered too, because that is the entire diagnostic value
// ("connection refused", "i/o timeout", "certificate signed by unknown
// authority") — but by CLASSIFICATION, never verbatim. See scrubInnerError.
//
// A non-*url.Error goes through the same classifier: it is not automatically
// URL-free just because it is not a *url.Error (round 7).
// errTreeWithinBound reports whether err's Unwrap tree is small enough that the
// STDLIB can walk it safely. Round 11 bounded this file's own recursion and
// stopped there, which was not enough: errors.Is and errors.As do their own
// traversal, dispatching to the error's Unwrap method, and that method belongs
// to the caller. An error whose Unwrap returns ITSELF makes errors.As spin
// forever, and an Unwrap() []error self-cycle recurses until the stack
// overflows -- a `fatal error` that recover() cannot catch.
//
// The round-11 cyclic test missed both because its root was directly a
// *url.Error, so errors.As matched on the first node and never followed Unwrap
// at all. The guard has to run BEFORE the first errors.As, not inside the
// recursion it protects.
//
// A NODE BUDGET, not a visited set: errors are interfaces, and comparing two
// for identity panics when the dynamic type is not comparable. A budget is
// sufficient anyway -- a cycle exhausts it, and so does a nest deep enough to
// overflow. Recursion here is self-limiting because every call spends budget.
//
// #6635 MOVED THE CALL SITES. Round 11's guard ran once, at the two PUBLIC
// entry points, and validated the tree AS PRESENTED THERE. That is not the tree
// the stdlib ends up walking, because errors.As dispatches to an As(any) bool
// method the caller defines, and that method hands back a value of the caller's
// choosing:
//
//	func (e hostile) As(target any) bool {
//	    *target.(**url.Error) = &url.Error{Err: selfUnwrappingError{}}
//	    return true
//	}
//
// The tree at entry is a single node, so the guard passes; the SUBTREE the As
// installs was never walked, and scrubURLErrorAt descends straight into it and
// spins forever inside the next errors.As. Reproduced before the fix: the entry
// guard returned true and the scrubber did not return.
//
// So the guard now runs at every entry to the depth-carrying functions, which
// is where a caller-supplied subtree can first appear. The cost is a re-walk
// per level -- at most maxUnwrapDepth^2 Unwrap calls, on an error path that
// runs at most once per reconcile tick, and only for trees that are already
// pathological. A legitimate error walks one or two levels.
//
// WHAT IS STILL NOT BOUNDED, stated rather than implied. A caller-supplied
// Error() or Unwrap() that BLOCKS or never returns hangs the first render or
// the guard itself, and no placement of this function fixes that. Bounding it
// would need a watchdog goroutine per render. That is deliberately not done,
// and the reason is not only cost: a blocking Error() hangs ANY fmt render of
// that error anywhere in the daemon, so bounding it inside one package's
// scrubber buys nothing while adding a goroutine to a path that must stay
// cheap. Neither is reachable in production -- errors on these paths come from
// net/http and the stdlib, and a provider can choose BYTES but not a Go type.
func errTreeWithinBound(err error) bool {
	budget := maxUnwrapDepth
	var walk func(error) bool
	walk = func(e error) bool {
		for e != nil {
			if budget <= 0 {
				return false
			}
			budget--
			switch u := e.(type) {
			case interface{ Unwrap() error }:
				e = u.Unwrap()
			case interface{ Unwrap() []error }:
				for _, sub := range u.Unwrap() {
					// Charge for the SLOT, not just for a non-nil child.
					// walk(nil) returns immediately without spending budget, so
					// a root handing back maxUnwrapDepth+1 nil children used to
					// pass the guard and then make every stdlib traversal scan
					// that fanout. Fanout is work whether or not the entry is
					// nil.
					if budget <= 0 {
						return false
					}
					budget--
					if sub == nil {
						continue
					}
					if !walk(sub) {
						return false
					}
				}
				return true
			default:
				return true
			}
		}
		return true
	}
	return walk(err)
}

func scrubURLError(err error) string {
	return scrubURLErrorAt(err, 0)
}

// scrubURLErrorAt carries the recursion depth that maxUnwrapDepth's comment
// always claimed to bound. scrubURLError and scrubInnerError are MUTUALLY
// recursive through the nested-*url.Error case, and neither counted: a
// caller-supplied *url.Error whose Err points at ITSELF overflowed the stack.
// That is a `fatal error`, not a panic — recover() does not catch it and the
// whole xpfd process dies, which is strictly worse than the hang the comment
// budgeted for. A deep non-cyclic nest did the same.
func scrubURLErrorAt(err error, depth int) string {
	if depth >= maxUnwrapDepth {
		return string(transportWithheld)
	}
	// RE-GUARD AT EVERY ENTRY, not only at the public one (#6635). See
	// errTreeWithinBound's own comment for why the guard has to precede the
	// first errors.As; this is about which TREE it is applied to.
	//
	// UNCONDITIONAL, not `depth == 0 &&`, and the mutation matrix says why that
	// matters. Removing this entirely hangs TestSelfUnwrappingErrorTerminates —
	// scrubURLError is now a thin delegate, so depth 0 IS the public entry and
	// round 12's property lives here. Narrowing it to depth 0 alone stays green,
	// because today the only depth>0 caller is scrubInnerErrorAt handing over a
	// value errors.As already resolved to a *url.Error, which the errors.As
	// below then matches at node 0 without walking anything.
	//
	// That is a REACHABILITY argument about a caller, and this package does not
	// build invariants on those — the same stance the dyndns2 endpoint scrub
	// takes about resolveDyndns2Endpoint having already parsed. A future caller
	// reaching this function with an unresolved tree would silently lose the
	// bound. The guard costs a walk of an already-small tree; keep it total.
	if !errTreeWithinBound(err) {
		return string(transportWithheld)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		return scrubInnerErrorAt(err, depth+1)
	}
	// A REFUSED REDIRECT is the one case where ue.URL is not ours: net/http
	// sets it to the Location the provider chose, so rendering it as the
	// "target" publishes a provider-controlled host — and did so a second time,
	// since the refusal prose named it too. Two renders of a per-request value
	// is what broke the dedup this package's own body-read fix exists to
	// protect. Render the refusal alone; it already names the stable FROM host.
	if r := findRedirectRefusal(err); r != nil {
		return r.Error()
	}
	u, perr := url.Parse(ue.URL)
	if perr != nil {
		// Nothing can be recovered safely from a URL that does not parse — not
		// even the host. Report the sanitized reason and no part of the input.
		return fmt.Sprintf("url is not a valid URL: %s", urlParseCause(perr))
	}
	target, note := safeURLTarget(u)
	return fmt.Sprintf("%s %q%s: %s", safeOp(ue.Op), target, note,
		scrubInnerErrorAt(ue.Err, depth+1))
}

// safeOp bounds url.Error.Op, which is NOT ours (round 8). net/http derives it
// from the request method and net/url sets "parse", but a caller-supplied
// RoundTripper can return a *url.Error it built itself:
//
//	&url.Error{Op: req.URL.String(), URL: "https://safe.example/", Err: …}
//
// leaked the complete request URL through the one field the scrub never
// touched. Op is now an allowlist of the values the two producers actually
// emit; anything else becomes a constant.
func safeOp(op string) string {
	switch op {
	case "Get", "Head", "Post", "Put", "Patch", "Delete", "Options", "Trace", "Connect", "parse":
		return op
	}
	return "request"
}

// safeURLTarget renders the largest part of u that the closed grammar admits,
// plus a fixed NOTE naming anything withheld (empty when nothing was). Splitting
// the note out keeps the target a well-formed URL instead of stuffing a
// parenthetical inside it.
//
// The note is not exhaustive by design: an out-of-range PORT is dropped
// silently, because the host is still fully rendered and a note would be noise.
// The three notes cover the cases where a whole component vanished.
func safeURLTarget(u *url.URL) (target, note string) {
	scheme := safeScheme(u.Scheme)
	if scheme == "" {
		// Nothing downstream of an unrecognised scheme can be trusted to be a
		// host at all, so nothing is rendered. This package only ever issues
		// http(s), so no legitimate diagnostic is lost.
		return "", " (url withheld: scheme is not http or https)"
	}
	host := safeHostText(u)
	if host == "" {
		return scheme + ":", " (host withheld: not a plain host name)"
	}
	target = scheme + "://" + host
	if zoneOf(u.Hostname()) != "" {
		// Not "link-local": a zone is legal on a global or IPv4-mapped literal
		// too, and the note must not assert a scope the address may not have.
		note = " (IPv6 zone id withheld)"
	}
	return target, note
}

// safeScheme reduces a URL scheme to the two values this package legitimately
// uses, or "" for anything else. url.Parse constrains a scheme's CHARACTERS but
// not its content, so a template that expanded a credential into the scheme
// position would otherwise be rendered; the allowlist makes that impossible
// without depending on any upstream validator having run.
func safeScheme(s string) string {
	switch strings.ToLower(s) {
	case "http":
		return "http"
	case "https":
		return "https"
	}
	return ""
}

// safeHostText renders u's authority under the closed grammar, or "" if it does
// not fit. The result is one of exactly three shapes:
//
//   - an IP literal re-rendered by netip WITH ANY ZONE ID DROPPED, bracketed
//     when it is v6 ("[2001:db8::1]", "192.0.2.7");
//   - a reg-name of dot-separated labels drawn from ASCII letters, digits, '-'
//     and '_', at most 63 bytes per label and 253 total, with at most one
//     trailing root dot;
//
// each optionally followed by ":" and 1..5 decimal digits in 1..65535.
//
// Everything else — a raw non-ASCII byte, a '%', an empty label, an
// over-long name, a non-numeric or out-of-range port — yields "". The point is
// that the OUTPUT CHARACTER SET is closed, so no amount of template
// substitution or provider-supplied Location text can put arbitrary bytes into
// a log line through this path.
func safeHostText(u *url.URL) string {
	host := safeHostName(u.Hostname())
	if host == "" {
		return ""
	}
	if port := safePort(u.Port()); port != "" {
		return host + ":" + port
	}
	return host
}

// safeHostName applies the grammar to a bare hostname (no port, no brackets).
func safeHostName(h string) string {
	if h == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		// An IP literal is re-rendered from the PARSED value, which is how the
		// zone id is dropped: netip holds it as a separate field, so
		// WithZone("") removes it structurally rather than by trimming text.
		addr = addr.WithZone("")
		if addr.Is6() {
			return "[" + addr.String() + "]"
		}
		return addr.String()
	}
	return safeRegName(h)
}

// zoneOf reports the IPv6 zone id on a hostname, or "" when there is none. It is
// used only to decide whether to say a zone was withheld — the zone itself is
// never rendered.
func zoneOf(h string) string {
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return ""
	}
	return addr.Zone()
}

// safeRegName returns h when it is a plain DNS-shaped name under the grammar
// documented on safeHostText, "" otherwise.
func safeRegName(h string) string {
	if len(h) > 253 {
		return ""
	}
	labels := strings.TrimSuffix(h, ".")
	if labels == "" {
		return ""
	}
	for _, label := range strings.Split(labels, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return ""
			}
		}
	}
	return h
}

// safePort returns p when it is a decimal port in 1..65535, "" otherwise.
// net/url already rejects a non-numeric port, so this is a second, local proof
// rather than a first line of defence.
func safePort(p string) string {
	if p == "" || len(p) > 5 {
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return ""
	}
	return p
}

// transportReason is a CLOSED enumeration of what scrubInnerError may report,
// following the parseReason precedent in checkip.go: because the classifier
// returns transportReason, a bare pass-through of an error's text — "return
// text" — does not COMPILE. Reintroducing the leak requires an explicit
// transportReason(...) conversion, which is a deliberate, greppable edit rather
// than a plausible-looking slip.
//
// Round 8 removed the last conversion. There is now NO path from any error's
// Error() into a transportReason: every return in classifyTransportError and
// its helpers names one of the constants below, which
// TestClassifyTransportErrorReturnsOnlyConstants proves by resolving each
// returned identifier with go/types.
type transportReason string

// The COMPLETE set of reasons scrubInnerError can report.
const (
	transportNil            transportReason = "<nil>"
	transportWithheld       transportReason = "transport error withheld"
	transportTimeout        transportReason = "network timeout"
	transportDeadline       transportReason = "context deadline exceeded"
	transportCanceled       transportReason = "context canceled"
	transportEOF            transportReason = "connection closed before a complete response"
	transportDNS            transportReason = "dns lookup failed"
	transportDNSNotFound    transportReason = "dns lookup failed: no such host"
	transportDNSTimeout     transportReason = "dns lookup failed: timed out"
	transportTLSVerify      transportReason = "tls: certificate verification failed"
	transportTLSHostname    transportReason = "tls: certificate is not valid for the requested host"
	transportTLSAuthority   transportReason = "tls: certificate signed by unknown authority"
	transportTLSInvalid     transportReason = "tls: certificate is invalid"
	transportTLSHandshake   transportReason = "tls: handshake failed"
	transportSchemeMismatch transportReason = "server gave an HTTP response to an HTTPS client"
	transportLocationEcho   transportReason = "failed to parse redirect Location header " +
		"(withheld: it echoes provider-supplied URL text)"

	// Stage of a *net.OpError with no recognised errno under it.
	transportDialFailed  transportReason = "dial failed"
	transportReadFailed  transportReason = "read failed"
	transportWriteFailed transportReason = "write failed"

	// The allowlisted errno values. The spellings match the kernel's own so an
	// operator can still grep for them, but they are OUR constants — nothing is
	// taken from syscall.Errno.Error(), which is not a closed table.
	transportConnRefused      transportReason = "connection refused"
	transportConnReset        transportReason = "connection reset by peer"
	transportConnAborted      transportReason = "software caused connection abort"
	transportBrokenPipe       transportReason = "broken pipe"
	transportConnTimedOut     transportReason = "connection timed out"
	transportHostUnreachable  transportReason = "no route to host"
	transportNetUnreachable   transportReason = "network is unreachable"
	transportNetDown          transportReason = "network is down"
	transportHostDown         transportReason = "host is down"
	transportAddrNotAvail     transportReason = "cannot assign requested address"
	transportAddrInUse        transportReason = "address already in use"
	transportAFNotSupported   transportReason = "address family not supported by protocol"
	transportPermissionDenied transportReason = "permission denied"
	transportMessageTooLong   transportReason = "message too long"
	transportNoBuffers        transportReason = "no buffer space available"
	transportTooManyFiles     transportReason = "too many open files"
)

// scrubInnerError renders the error nested inside a *url.Error.
//
// ROUND 7 MADE THIS TOTAL. It previously returned any non-*url.Error VERBATIM
// on the reasoning that "transport errors name a host/IP, never a URL". That
// held for the transports this package builds itself, but CheckIP takes a
// caller-supplied *http.Client, and a RoundTripper returning
//
//	fmt.Errorf("request %s failed: %w", req.URL, context.DeadlineExceeded)
//
// put the complete path credential straight through. The old special case for
// net/http's Location-parse message was an exact PREFIX match, so the same
// message wrapped one layer deep also walked past it.
//
// ROUND 8 REMOVED THE ABILITY TO EXPRESS THE LEAK, rather than checking for it.
// Round 7's rule was PROVENANCE — render an error's own text once we believe it
// is ours or the kernel's. A caller-supplied RoundTripper defeated that four
// separate ways, because every "is this one of ours?" question routes through
// something the caller controls:
//
//   - errors.Is dispatches to the error's own Is(error) bool. An error whose Is
//     always says true and whose Error() is the request URL was printed
//     verbatim as a "refusal".
//   - A forged *url.Error carried the request URL in Op, the field the URL
//     scrub never rebuilt (now safeOp).
//   - syscall.Errno.Error() is NOT a closed table: an unknown value renders
//     "errno 65432", so a numeric credential survived (now an errno allowlist).
//   - %T is not a compile-time symbol: reflect.StructOf builds a runtime type
//     whose name embeds an input-derived struct TAG (now dropped entirely).
//
// THE PROPERTY NOW: the returned string is drawn from a set this package
// declares, whatever the error claims about itself. classifyTransportError
// returns the closed transportReason type and every one of its returns names a
// declared constant — pinned by TestClassifyTransportErrorReturnsOnlyConstants,
// which RESOLVES each returned identifier with go/types (the same discipline,
// and the same shadow-proofing, as the urlParseCause gate next door). No
// caller-supplied Error() text reaches the output on any path.
//
// The one error whose text IS rendered is *redirectRefusal, and it is reached
// by TYPE ASSERTION over the unwrap chain, never by errors.Is/As — an
// unexported concrete struct type cannot be named, constructed, or impersonated
// from outside this package, and a type assertion has no user-defined hook. Its
// Error() is built from fixed prose plus refusalHost/refusalScheme output. That
// path exists because the cross-host refusal IS the diagnostic #6545 produces.
//
// The diagnostic cost is real and accepted: net/http's internal errors.New
// prose, the failing address, and the unknown-error type name are all gone. An
// unrecognised error is exactly the case where we cannot say what it contains.
func scrubInnerError(err error) string {
	// The stdlib-traversal guard lives in scrubInnerErrorAt now, so it applies
	// to every entry rather than only this one (#6635).
	return scrubInnerErrorAt(err, 0)
}

// scrubInnerErrorAt is the depth-carrying half of the mutual recursion; see
// scrubURLErrorAt.
func scrubInnerErrorAt(err error, depth int) string {
	if depth >= maxUnwrapDepth {
		return string(transportWithheld)
	}
	if err == nil {
		return string(transportNil)
	}
	// RE-GUARD (#6635). Everything below — findRedirectRefusal aside, which
	// walks with its own bounded loop — hands this tree to the stdlib:
	// errors.As here, and errors.Is/errors.As throughout
	// classifyTransportError. Each dispatches to the caller's own Unwrap.
	if !errTreeWithinBound(err) {
		return string(transportWithheld)
	}
	// Our own typed refusal, found by assertion over the chain.
	if r := findRedirectRefusal(err); r != nil {
		return r.Error()
	}
	// A nested *url.Error would re-embed a full URL in its own Error(); recurse
	// through the same scrub instead of printing it. errors.As is safe HERE
	// because the result is not rendered as text — every field it reaches
	// (Op, URL, Err) goes back through the scrub.
	var nested *url.Error
	if errors.As(err, &nested) {
		return scrubURLErrorAt(nested, depth+1)
	}
	return string(classifyTransportError(err))
}

// maxUnwrapDepth bounds every chain walk in this file. errors.Unwrap dispatches
// to the error's own Unwrap, so a caller-supplied error can return ITSELF and
// spin forever; a hang is a denial of service, not a leak, but it is just as
// much the caller's choice.
const maxUnwrapDepth = 100

// findRedirectRefusal walks the unwrap chain and TYPE-ASSERTS. It deliberately
// does not use errors.As: errors.As consults an As(any) bool method, which a
// caller-supplied error implements to become whatever it likes.
func findRedirectRefusal(err error) *redirectRefusal {
	for i := 0; err != nil && i < maxUnwrapDepth; i++ {
		if r, isRefusal := err.(*redirectRefusal); isRefusal {
			return r
		}
		err = errors.Unwrap(err)
	}
	return nil
}

// classifyTransportError maps an arbitrary transport error onto the closed
// transportReason set. Every branch reads TYPE, STRUCTURE or an allowlisted
// VALUE; none renders an error's message text, and every return below names a
// declared constant (enforced by TestClassifyTransportErrorReturnsOnlyConstants).
func classifyTransportError(err error) transportReason {
	// net/http builds fmt.Errorf("failed to parse Location header %q: %v", ...)
	// BEFORE CheckRedirect runs, so a provider that 3xx-es to a malformed
	// Location echoing our own query lands the credential here. It has no
	// distinguishing type, so it is matched on the invariant prefix — at any
	// wrapping depth, unlike the round-6 exact match. The text is INSPECTED,
	// never returned, and anything the match misses falls through to
	// "withheld", so a stdlib rewording fails CLOSED.
	for e, i := err, 0; e != nil && i < maxUnwrapDepth; e, i = errors.Unwrap(e), i+1 {
		if strings.HasPrefix(e.Error(), locationHeaderPrefix) {
			return transportLocationEcho
		}
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return transportDeadline
	case errors.Is(err, context.Canceled):
		return transportCanceled
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return transportEOF
	case errors.Is(err, http.ErrSchemeMismatch):
		return transportSchemeMismatch
	}

	// errors.Is/As are FORGEABLE, but forging one of these buys nothing: every
	// branch below returns a constant, and the structural fields read
	// (IsNotFound, IsTimeout, Op) are booleans or allowlisted tokens. An error
	// that lies its way into a branch mislabels itself; it cannot smuggle text.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return transportDNSNotFound
		case dnsErr.IsTimeout:
			return transportDNSTimeout
		}
		return transportDNS
	}

	// TLS/x509. The x509 types all quote provider-supplied certificate fields in
	// their Error(), so only the TYPE is read. Inlined rather than delegated to a
	// helper so that every return in this function is a bare constant, which is
	// what TestClassifyTransportErrorReturnsOnlyConstants can prove.
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return transportTLSHostname
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return transportTLSAuthority
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return transportTLSInvalid
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return transportTLSVerify
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return transportTLSHandshake
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errnoReason(errno)
	}

	// A *net.OpError with no recognised errno underneath still says which STAGE
	// failed. Only Op is read, against net's own vocabulary, and it selects a
	// constant — Net adds nothing but combinations, and Addr/Source are the
	// request host.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch opErr.Op {
		case "dial":
			return transportDialFailed
		case "read":
			return transportReadFailed
		case "write":
			return transportWriteFailed
		}
		return transportWithheld
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return transportTimeout
	}

	return transportWithheld
}

// errnoReason maps an ALLOWLISTED errno VALUE onto a declared constant.
//
// Round 7 called syscall.Errno.Error() "a table lookup over the kernel's fixed
// error list" and converted its text directly. That was wrong: the table is not
// total. An errno outside it renders dynamically — syscall.Errno(65432) becomes
// "errno 65432" — so a numeric credential steered into the chain came out in
// the message. Switching on the VALUE and returning constants removes the
// dynamic path; an unrecognised errno is withheld like anything else.
func errnoReason(e syscall.Errno) transportReason {
	switch e {
	case syscall.ECONNREFUSED:
		return transportConnRefused
	case syscall.ECONNRESET:
		return transportConnReset
	case syscall.ECONNABORTED:
		return transportConnAborted
	case syscall.EPIPE:
		return transportBrokenPipe
	case syscall.ETIMEDOUT:
		return transportConnTimedOut
	case syscall.EHOSTUNREACH:
		return transportHostUnreachable
	case syscall.ENETUNREACH:
		return transportNetUnreachable
	case syscall.ENETDOWN:
		return transportNetDown
	case syscall.EHOSTDOWN:
		return transportHostDown
	case syscall.EADDRNOTAVAIL:
		return transportAddrNotAvail
	case syscall.EADDRINUSE:
		return transportAddrInUse
	case syscall.EAFNOSUPPORT:
		return transportAFNotSupported
	case syscall.EACCES, syscall.EPERM:
		return transportPermissionDenied
	case syscall.EMSGSIZE:
		return transportMessageTooLong
	case syscall.ENOBUFS, syscall.ENOMEM:
		return transportNoBuffers
	case syscall.EMFILE, syscall.ENFILE:
		return transportTooManyFiles
	}
	return transportWithheld
}

// locationHeaderPrefix is the invariant head of net/http's Location-parse
// failure (net/http/client.go), which quotes the raw header value.
const locationHeaderPrefix = `failed to parse Location header `

// queryEscape URL-query-escapes a value for safe insertion into a generic
// template URL (%u/%p/%h/%i expansion).
func queryEscape(s string) string { return url.QueryEscape(s) }

// classifyHTTPStatus maps a transport-level HTTP status (used by the
// JSON/SigV4 backends — Cloudflare/Route53) to a typed error. 2xx is success
// (nil). It is NOT used by dyndns2/generic, which classify by BODY content (the
// dyndns2 protocol returns 200 + a status keyword in the body).
func classifyHTTPStatus(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return errHTTPAuth
	case code == http.StatusTooManyRequests:
		return errHTTPRateLimited
	default:
		return fmt.Errorf("ddns http: unexpected status %d", code)
	}
}

// ---------------------------------------------------------------------------
// Provider-CHOSEN text (#6634)
// ---------------------------------------------------------------------------

// The scrubbers above bound error VALUES that carry a request URL. This is the
// other direction: text the PROVIDER put in its response BODY and that four
// backends render into a returned error the daemon logs — Cloudflare's
// Errors[].Message, Route 53's decoded Code/Message, and the unrecognized first
// response line on dyndns2 and DuckDNS.
//
// THE PROVIDER IS THE UNTRUSTED PARTY HERE. No hostile transport is needed: a
// "your request was invalid: <the request>" style API echoes our own update URL
// back, and a DuckDNS-shaped endpoint carries its token in the QUERY, so the
// echo is the credential. The same body is also the DoS surface — readCappedBody
// admits httpMaxResponseBody (64 KiB), and every byte of it was reaching a
// journal line on every reconcile tick of a persistent failure, plus the
// provider's retained lastErr.
//
// WHAT THE SINKS ALREADY DO, so this does not duplicate them. Control-character
// forgery is closed twice over and neither fix belongs here: the daemon's
// slog.TextHandler (cmd/xpfd/main.go) strconv.Quote-s any value carrying a byte
// outside printable ASCII, so an embedded newline cannot split a journal line;
// and `show services ddns` renders LastError through termsafe.SanitizeForDisplay
// on both the CLI and gRPC surfaces (#6468). What NO sink can undo is a
// credential in the bytes, or 64 KiB of them.
//
// SO THIS BOUNDS TWO THINGS AND IS HONEST ABOUT THE THIRD:
//
//  1. LENGTH — hard cap, total. This half is a proof: nothing provider-chosen
//     can exceed maxProviderTextBytes plus a fixed marker.
//  2. URL AND USERINFO SHAPES — a whitespace-delimited token carrying "://", a
//     userinfo-shaped "user:pass@host", or a percent-escape is replaced whole.
//     This closes the ECHO threat the issue describes, where the secret arrives
//     inside a well-formed URL.
//  3. NOT a proof against a provider that WANTS to leak. A credential echoed as
//     bare prose ("your token abc123 is invalid") is indistinguishable from a
//     word, and no filter recovers it. That residual is accepted rather than
//     papered over, because the alternative — withholding provider text
//     wholesale, as the transport path does for its own errors — costs the
//     operator the single most useful diagnostic they get ("token invalid",
//     "zone not found", "rate limited") in exchange for a threat model
//     (a provider deliberately exfiltrating a credential it was ALREADY GIVEN)
//     that withholding does not actually close either.
//
// WHY NOT THE CODE-MAPPING OPTION. Mapping known provider error codes onto our
// own constants, the transportReason discipline, would give a closed output —
// but only for codes we already know. The unmapped case is exactly the case an
// operator is debugging, and it would render as a constant saying nothing. Route
// 53 also classifies delete-idempotency on the raw message text
// (r53DeleteAlreadyGone), so the VALUE must keep flowing to the classifier
// untouched; only the RENDER goes through here.
//
// FILTER FIRST, THEN BOUND. The other order splits a URL at the cap and leaves
// its prefix — "https://user:PA" — rendered, which is a partial credential.

const (
	// maxProviderTextBytes caps any provider-chosen string rendered into an
	// error. Generous for real provider prose (Route 53's InvalidChangeBatch
	// "…but it was not found" sentence is under 100 bytes), three orders of
	// magnitude under the 64 KiB body cap.
	maxProviderTextBytes = 200

	// providerTextTruncated marks a bounded render. Fixed text, so it cannot
	// itself carry anything provider-chosen.
	providerTextTruncated = "[truncated]"

	// providerURLWithheld replaces one URL-shaped or userinfo-shaped token.
	providerURLWithheld = "[url withheld]"

	// providerTextEmpty distinguishes "the provider said nothing" from "the
	// provider's text was withheld", which are different diagnoses.
	providerTextEmpty = "[no text]"
)

// scrubProviderText renders a provider-supplied string under the bound above.
// Whitespace runs collapse to a single space: it costs nothing diagnostically,
// and it means a body that is 64 KiB of newlines cannot dominate the budget.
func scrubProviderText(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return providerTextEmpty
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if providerTokenCarriesURL(f) {
			f = providerURLWithheld
		}
		out = append(out, f)
	}
	joined := strings.Join(out, " ")
	if len(joined) > maxProviderTextBytes {
		// Cut on a byte boundary that cannot split a multi-byte rune: back off
		// to the last boundary at or before the cap. A rune split would emit a
		// lone continuation byte, which is exactly the invalid-UTF-8 shape the
		// display sanitizer then has to escape.
		cut := maxProviderTextBytes
		for cut > 0 && !utf8.RuneStart(joined[cut]) {
			cut--
		}
		joined = joined[:cut] + providerTextTruncated
	}
	return joined
}

// providerTokenCarriesURL reports whether one whitespace-delimited token is
// shaped like something that can carry a credential.
//
// Three shapes, deliberately narrow so ordinary prose survives:
//
//   - a scheme separator "://" — any URL, whatever the scheme;
//   - USERINFO WITH A PASSWORD: a ':' before an '@'. A bare "user@host" is NOT
//     withheld — there is no secret in it, and withholding it would eat
//     "contact support@example.com" from a legitimate provider message;
//   - a PERCENT-ESCAPE "%XX" — the encoded form of the two above, which is what
//     a URL echoed through a provider's own escaping looks like. Two hex digits
//     are required, so "80% of quota" survives.
func providerTokenCarriesURL(tok string) bool {
	if strings.Contains(tok, "://") {
		return true
	}
	if at := strings.IndexByte(tok, '@'); at > 0 && strings.IndexByte(tok[:at], ':') >= 0 {
		return true
	}
	for i := 0; i+2 < len(tok); i++ {
		if tok[i] == '%' && isHexDigit(tok[i+1]) && isHexDigit(tok[i+2]) {
			return true
		}
	}
	return false
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
