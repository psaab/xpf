package feeds

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// maxFeedBodyBytes caps the total HTTP response body a single feed fetch will
// buffer (#3934). Without a cap, a feed server that returns a huge (or
// infinite/chunked) body — or a MITM on a plaintext-http feed URL — can make
// the fetcher buffer an arbitrarily large body into memory and OOM the daemon
// (a remote-triggerable DoS). The body is read through an io.LimitReader; a
// body exceeding this cap fails the whole fetch (retain last-good) rather than
// buffering unboundedly. 32 MiB is comfortably above any legitimate CIDR feed
// yet well under the 64 MiB userspace-dp control-request cap
// (MaxControlRequestBytes, #2744) so a single feed cannot dominate the apply
// snapshot.
const maxFeedBodyBytes = 32 << 20 // 32 MiB

// httpClientTimeout bounds a single feed fetch end-to-end (connect + headers +
// body read), so a slow-loris feed server that dribbles bytes cannot hold the
// fetch open indefinitely (#3934). The next refresh tick retries.
const httpClientTimeout = 30 * time.Second

// feedDialAttemptTimeout bounds each pinned dial attempt so a blackholed
// first answer cannot consume the whole shared fetch budget and starve
// reachable later answers (serial fallback without Happy Eyeballs). It is a
// var so tests can shrink it; production stays well under httpClientTimeout.
var feedDialAttemptTimeout = 5 * time.Second

// maxFeedRedirects preserves net/http's built-in redirect bound after the
// client installs the feed-specific CheckRedirect policy below.
const maxFeedRedirects = 10

// sameOriginFeedURL reports whether two HTTP URLs share an origin. Origins are
// defined by scheme, hostname, and effective port; credentials and paths are
// intentionally excluded.
func sameOriginFeedURL(a, b *url.URL) bool {
	if a == nil || b == nil || a.Hostname() == "" || b.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) ||
		!strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return feedOriginPort(a) == feedOriginPort(b)
}

func feedOriginPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// checkFeedRedirect permits only same-origin redirects. A provider-controlled
// Location must never turn the configured feed URL into an SSRF primitive.
func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= maxFeedRedirects {
		return fmt.Errorf("dynamic-address: stopped after %d redirects", maxFeedRedirects)
	}

	previous := via[len(via)-1]
	if previous != nil && req != nil && sameOriginFeedURL(previous.URL, req.URL) {
		return nil
	}

	from := "<unknown>"
	if via[0] != nil && via[0].URL != nil {
		from = config.RedactURL(via[0].URL.String())
	}
	slog.Warn("dynamic-address: cross-origin feed redirect refused", "from", from)
	// Keep the provider-supplied Location out of url.Error; readFeed closes
	// this response and rejects the retained 302 with a generic status error.
	return http.ErrUseLastResponse
}

// The blocked-destination predicate and its prefix table live in
// pkg/config (config.FeedDestinationBlocked / config.FeedDestinationClass)
// so the strict compiler gate shares them without an import cycle
// (#16656). This package keeps only the allowlist-membership helper's
// runtime spelling.
func (m *Manager) privateFeedAllowlistSnapshot() []netip.Prefix {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]netip.Prefix(nil), m.privateFeedAllowlist...)
}

func feedDestinationAllowed(ip netip.Addr, allowlist []netip.Prefix) bool {
	return config.FeedDestinationAllowed(ip, allowlist)
}

func feedDestinationBlocked(ip netip.Addr) bool {
	return config.FeedDestinationBlocked(ip)
}

func resolveFeedIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		return []netip.Addr{literal.Unmap()}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve feed destination: %w", err)
	}
	return ips, nil
}

// resolveAndValidateFeedDestination resolves a feed hostname once and
// validates every answer before the transport is allowed to dial. Refusing
// the whole answer set when any member is forbidden prevents a resolver from
// selecting a private answer after a public answer was observed. The
// effective allowlist is the manager-level lab override unioned with the
// feed's server-configured `allow-destination` prefixes (#16656).
func (m *Manager) resolveAndValidateFeedDestination(ctx context.Context, host string, extraAllowlist []netip.Prefix) ([]netip.Addr, error) {
	if host == "" {
		return nil, fmt.Errorf("empty feed destination host")
	}

	var (
		ips []netip.Addr
		err error
	)
	m.mu.RLock()
	resolve := m.resolveFeedIPs
	m.mu.RUnlock()
	if resolve != nil {
		ips, err = resolve(ctx, host)
	} else {
		ips, err = resolveFeedIPs(ctx, host)
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve feed destination returned no addresses")
	}

	allowlist := append(m.privateFeedAllowlistSnapshot(), extraAllowlist...)
	unique := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() {
			return nil, fmt.Errorf("feed destination resolved to an invalid address")
		}
		if feedDestinationBlocked(ip) && !feedDestinationAllowed(ip, allowlist) {
			return nil, fmt.Errorf("feed destination resolves to a blocked address")
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	return unique, nil
}

// pinnedFeedClient clones the feed transport with a dialer that uses only the
// already-validated addresses. The request URL retains its hostname for Host
// and TLS SNI, but no later transport operation can perform a fresh DNS
// lookup, closing the resolve/check/dial TOCTOU window.
func pinnedFeedClient(base *http.Client, ips []netip.Addr, port string) (*http.Client, error) {
	if base == nil {
		return nil, fmt.Errorf("feed client is nil")
	}
	baseTransport, ok := base.Transport.(*http.Transport)
	if !ok || baseTransport == nil {
		return nil, fmt.Errorf("feed client transport cannot pin destination")
	}
	transport := baseTransport.Clone()
	transport.DialTLSContext = nil
	baseDialContext := baseTransport.DialContext
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		for _, ip := range ips {
			switch {
			case network == "tcp4" && !ip.Is4():
				continue
			case network == "tcp6" && !ip.Is6():
				continue
			}
			target := net.JoinHostPort(ip.String(), port)
			attemptCtx, cancelAttempt := context.WithTimeout(ctx, feedDialAttemptTimeout)
			var conn net.Conn
			var err error
			if baseDialContext != nil {
				conn, err = baseDialContext(attemptCtx, network, target)
			} else {
				conn, err = dialer.DialContext(attemptCtx, network, target)
			}
			cancelAttempt()
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no validated address matches network %q", network)
	}
	client := *base
	client.Transport = transport
	return &client, nil
}

// escapedPathJoin joins two already-percent-escaped URL paths with
// exactly one "/" between them. It operates on the ESCAPED form so an
// encoded separator (%2F) survives the join end to end instead of being
// decoded into a real path separator (#14723).
func escapedPathJoin(baseEscaped, refEscaped string) string {
	return strings.TrimSuffix(baseEscaped, "/") + "/" + strings.TrimPrefix(refEscaped, "/")
}

// joinFeedURL appends a per-feed path to a feed-server base URL,
// preserving any query (and fragment) the base carries. Plain string
// concatenation (baseURL + path) appends the path AFTER a base query:
// https://feed.example/base?token=abc plus /malware.txt became
// .../base?token=abc/malware.txt, so the server saw path /base with a
// mangled token and the feed never fetched (#14177). The per-feed path
// is instead appended to the base PATH (the base is a directory-like
// prefix, matching the pre-existing concatenation semantics for
// query-free bases), and the query is re-attached after it. A per-feed
// path that itself carries a query replaces the base query for that
// feed (the #7406 provider shape: the token lives on the path leaf);
// otherwise the base query is inherited.
//
// The per-feed path must be a plain relative path tail: an unparseable
// value, a network-path reference ("//host/..."), or any scheme /
// opaque form ("v1:prod/...", an absolute URL) is REJECTED by
// returning "" (#14723). Apply treats "" as "register no feed", so the
// failure stays fail-closed (bound name unresolvable, #5645) instead of
// silently fetching the base endpoint and installing whatever prefixes
// it serves as this feed's enforced policy. A malformed BASE, however,
// is returned unchanged: readFeed then rejects the unconstructible URL
// and the strict compiler gate rejects it at commit (#5183), so that
// arm also stays fail-closed without masking which value is broken.
// The join is performed on the escaped paths and RawPath is pinned, so
// a %2F in either component reaches the wire as %2F.
func joinFeedURL(baseURL, rawPath string) string {
	if rawPath == "" {
		return baseURL
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	ref, err := url.Parse(rawPath)
	if err != nil {
		return ""
	}
	if ref.Scheme != "" || ref.Opaque != "" || ref.Host != "" || ref.User != nil {
		return ""
	}
	joined := *base
	joined.Path, joined.RawPath = "", ""
	joinedPath := escapedPathJoin(base.EscapedPath(), ref.EscapedPath())
	if decoded, derr := url.PathUnescape(joinedPath); derr == nil {
		joined.Path = decoded
		if joinedPath != decoded {
			joined.RawPath = joinedPath
		}
	} else {
		joined.Path = joinedPath
	}
	if ref.RawQuery != "" || ref.ForceQuery {
		joined.RawQuery = ref.RawQuery
		joined.ForceQuery = ref.ForceQuery
	}
	if ref.Fragment != "" {
		joined.Fragment = ref.Fragment
		joined.RawFragment = ref.RawFragment
	}
	return joined.String()
}

// resolveBaseURL returns the base URL for a feed server.
// Prefers explicit URL; falls back to https://hostname.
//
// Trailing "/" is trimmed from the URL *path* only (#14723): trimming
// the raw string cut a query or fragment token that itself ends in "/"
// (https://h/base/?token=abc/ lost the token's slash; a query-free
// https://h/base#frag/ lost the fragment's). An unparseable URL is
// returned unchanged so readFeed / the strict gate report it as-is.
func resolveBaseURL(fsCfg *config.FeedServer) string {
	raw := fsCfg.URL
	if raw == "" && fsCfg.Hostname != "" {
		raw = "https://" + fsCfg.Hostname
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		// No path component to trim (or unparseable): preserve the
		// historical slash-trim so slash-only URLs still resolve to "".
		return strings.TrimRight(raw, "/")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.RawPath = ""
	} else if u.RawPath != "" {
		u.RawPath = strings.TrimRight(u.RawPath, "/")
	}
	return u.String()
}

// isPlaintextFeedURL reports whether url is a plaintext-http feed URL.
// Such a feed has no transport integrity and this package has no per-feed
// signature / pinned-hash verification, so a substituted body would install
// as enforced policy (#14385, DR5-H13; the #3934 warning alone never fixed
// the substitution). Manager.Apply refuses to register plaintext-http feeds
// and the strict compiler gate rejects them at commit.
func isPlaintextFeedURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "http://")
}

// fetchFeed performs a single GET, parses + canonicalizes the body, and applies
// it to the feed state. A fetch is considered SUCCESSFUL only if the transport
// read completes without error AND the parsed set is non-empty. On any failure
// the last-good snapshot is RETAINED — indefinitely by default, or until an
// explicit positive hold-interval elapses (the opt-in drop-to-empty).
// lastFetch/lastSuccess are stamped only on success.
func (m *Manager) fetchFeed(ctx context.Context, fs *feedState) {
	res, err := m.readFeed(ctx, fs)
	if err != nil {
		m.recordFailure(fs, err)
		return
	}
	m.installSnapshot(fs, res)
}

// readFeed issues the HTTP request and parses the body into a canonical set.
// It returns an error (and no snapshot is installed) on transport failure,
// non-200 status, a scanner error (including bufio.ErrTooLong for an overlong
// line), an over-size body / over-count entry set (maxFeedBodyBytes /
// maxFeedPrefixes, #3934), or a zero-prefix successful response (treated as
// suspect — a hijacked or misconfigured endpoint serving an empty body must
// not silently wipe an enforced set). The transport itself is bounded by the
// client's httpClientTimeout (slow-loris protection).
func (m *Manager) readFeed(ctx context.Context, fs *feedState) (fetchResult, error) {
	fetchCtx, cancelFetch := context.WithTimeout(ctx, httpClientTimeout)
	defer cancelFetch()
	req, err := http.NewRequestWithContext(fetchCtx, "GET", fs.url, nil)
	if err != nil {
		return fetchResult{}, fmt.Errorf("invalid URL: %w", err)
	}
	if req.URL.Hostname() == "" {
		return fetchResult{}, fmt.Errorf("invalid URL: empty feed destination host")
	}
	port := feedOriginPort(req.URL)
	if port == "" {
		return fetchResult{}, fmt.Errorf("invalid URL: unsupported feed destination scheme")
	}

	// Resolve and validate exactly once under the same deadline as the request.
	// The pinned client below retains the hostname in req.URL (for Host/TLS SNI)
	// while dialing only this validated address set, so a DNS answer cannot
	// change between validation and dial.
	ips, err := m.resolveAndValidateFeedDestination(fetchCtx, req.URL.Hostname(), fs.destinationAllowlist)
	if err != nil {
		return fetchResult{}, fmt.Errorf("feed destination refused: %w", err)
	}
	client, err := pinnedFeedClient(m.client, ips, port)
	if err != nil {
		return fetchResult{}, fmt.Errorf("feed destination refused: %w", err)
	}
	// Each fetch gets a cloned transport so its dialer can be pinned. Close
	// idle connections after the body is consumed; otherwise a zero
	// IdleConnTimeout would retain one transport/read-loop per refresh.
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{}, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseFeed(resp.Body)
}
