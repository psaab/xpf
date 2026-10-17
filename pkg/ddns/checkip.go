package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// checkip.go: the optional external check-IP address source (#2691 P3, plan
// §3.2/§5.3). For a firewall that sits BEHIND another NAT (so its own interface
// address is an RFC 1918 / private address, not the public one DNS should point
// at), the public address must be discovered from an external "what is my IP"
// endpoint. This is OPT-IN per provider (`checkip-url`); the default Surface A
// observation is the interface / DHCP-lease read (the firewall is usually the
// router and knows its own public address directly — plan §7 fork 4).
//
// inadyn idea #6 adopted (plan §3.7): the response is run through a validity
// gate + a bogus-IP allowlist so a checkip page that EMBEDS a resolver/anycast
// IP (e.g. Cloudflare's 1.1.1.1 in /cdn-cgi/trace) is not mistaken for the
// client address. v6 is tried first, then v4 (inadyn parse_my_address order).

// ipAddrRe matches an IPv4 or IPv6 address literal embedded in a checkip body.
// Deliberately permissive (a byte-scan, like inadyn) — the validity gate below
// is what rejects junk, loopback, link-local, multicast, and unspecified.
var ipAddrRe = regexp.MustCompile(
	`([0-9a-fA-F:]{2,}:[0-9a-fA-F:]*|(?:[0-9]{1,3}\.){3}[0-9]{1,3})`)

// CheckIP fetches the public address from a checkip endpoint and returns the
// first VALID address of the requested family. wantV4 selects A (true) vs AAAA
// (false). allowlist is the operator's bogus-IP allowlist (addresses to ignore
// even if otherwise valid — the embedded-resolver case). The shared hardened
// HTTP client (TLS-verified, bounded timeout, capped body) is used.
//
// Returns (addr, true, nil) on success. On a miss ok is false and the scope is
// left untouched by the engine — never a withdraw — but the third return
// DISTINGUISHES why:
//
//   - (zero, false, err) — the probe FAILED: a malformed checkip-url, an
//     unreachable/refused endpoint, a non-2xx status, or a refused redirect
//     (a cross-host Location, #6545). err carries the operator-facing reason.
//   - (zero, false, nil) — the probe SUCCEEDED but the body carried no usable
//     address of the requested family. That is the ordinary dual-stack case (a
//     v4-only endpoint queried for AAAA) and is deliberately not an error.
//
// The error return exists because several of the failure causes are PERMANENT
// configuration errors — this package's own doctrine, stated at
// validateCheckIPURL below, is that a malformed URL "is a configuration error,
// not a transient". Collapsing them into a bare ok=false made a misconfigured
// checkip-url an indistinguishable, undiagnosable, forever-transient
// observation failure — exactly the class #2773/#3737 were filed to eliminate.
// The daemon call site (pkg/daemon/daemon_ddns_surface_a.go) logs it once per
// (provider, error).
//
// Note the error is NOT wrapped-sentinel-inspectable: doRequest deliberately
// renders transport errors through scrubURLError into a STRING (breaking the
// %w chain) so a URL query — which for the generic backend carries the
// %p-expanded password — can never reach a log. Match on the message, or add a
// typed pre-transport error, but do not re-plumb %w through doRequest.
func CheckIP(ctx context.Context, client *http.Client, urlStr string, wantV4 bool, allowlist []netip.Addr) (netip.Addr, bool, error) {
	if client == nil {
		client = newHTTPClient()
	}
	// Fail-closed on an obviously malformed checkip-url (#2773). http.NewRequest
	// accepts ftp://, "not a url", and http:// (no host), so without this gate a
	// bad URL would fall through to a fetch failure and masquerade forever as a
	// transient observation failure (ok=false), silently suppressing publishing.
	// A malformed URL is a configuration error, not a transient — reject it here
	// (the commit-time validateSurfaceADDNSWarnings warning is the operator-facing
	// half; this is the runtime backstop for a URL that slipped past commit).
	if err := validateCheckIPURL(urlStr); err != nil {
		return netip.Addr{}, false, err
	}
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		// Unreachable in practice — validateCheckIPURL above already parsed this
		// exact string and the method is a constant — but http.NewRequest fails
		// by returning url.Parse's *url.Error VERBATIM, raw query and all, so
		// apply the same discipline as every other build-request site: render
		// through scrubURLError, which withholds a URL that does not parse and
		// reports only the sanitized urlParseCause reason (#6545).
		return netip.Addr{}, false, fmt.Errorf("ddns checkip: build request: %s", scrubURLError(err))
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")
	code, body, err := doRequest(ctx, client, req)
	if err != nil {
		return netip.Addr{}, false, err
	}
	if serr := classifyHTTPStatus(code); serr != nil {
		return netip.Addr{}, false, serr
	}
	a, ok := parseCheckIPBody(string(body), wantV4, allowlist)
	return a, ok, nil
}

// CheckIPBound runs the checkip probe through a source-bound HTTP client while
// enforcing the FAIL-CLOSED source-bind invariant (#3733). bindErr is the
// source-bind resolution error the caller got when building `client` (via
// NewCheckIPClient / SurfaceAManager.CheckIPClient) — non-nil when a configured
// source-address could not be honored, in which case `client` is the UNBOUND
// default (kernel default route).
//
// checkip is an address ORACLE: it discovers the public IP that DNS will point
// at. Probing through the wrong egress returns a DIFFERENT WAN's public IP, and
// publishing it republishes exactly the wrong-WAN class #2846 closed. So when a
// source WAS requested but could not be honored (bindErr != nil), the probe
// MUST NOT fall back to the default route — it returns (zero, false): a
// TRANSIENT observation (no publish, never a withdraw), matching CheckIP's own
// miss semantics. When no source was requested (bindErr == nil — `client` is the
// intended egress, whether source-bound or unbound-by-config), the probe runs
// normally.
//
// The bindErr gate is exact: the source-bind resolver (resolveProviderBindConfig
// → resolveBindConfig) returns an error ONLY when a source-address IS configured
// but does not parse — i.e. a source was requested and could not be honored. A
// source-address that resolves but is not currently assigned, or a destination-
// interface / VRF that is down, surfaces later as a DIAL error inside CheckIP,
// which already returns ok=false (fail-closed) on its own — so this gate is the
// one residual fall-open the bind-error branch left open.
//
// The third return mirrors CheckIP's: non-nil means the probe FAILED for a
// stated reason (here, bindErr itself when the source could not be honored),
// nil with ok=false means the probe ran and simply found no address of the
// requested family. Callers that already surface bindErr themselves should not
// log it twice.
func CheckIPBound(ctx context.Context, client *http.Client, urlStr string, wantV4 bool, allowlist []netip.Addr, bindErr error) (netip.Addr, bool, error) {
	if bindErr != nil {
		// Source requested but not honored: fail closed, never probe via the
		// default route (would return the wrong WAN's public IP).
		return netip.Addr{}, false, bindErr
	}
	return CheckIP(ctx, client, urlStr, wantV4, allowlist)
}

// NewCheckIPClient builds the HTTP client a checkip probe should use, bound to
// the provider's configured source-address / destination-interface / routing-
// instance (#2846) so the external "what is my IP" query egresses from the SAME
// source as the DDNS updates do — not the kernel default route. A malformed
// source-address returns the unbound default client plus the error so the caller
// can log it and degrade gracefully. The caller MUST treat that error as
// fail-closed for the checkip oracle (route the probe through CheckIPBound, which
// refuses to fall back to the default route, #3733) — the returned unbound
// client is only for callers whose fall-open is acceptable (generic HTTP update
// backends). A nil provider yields the unbound default client, no error.
func NewCheckIPClient(p *config.DDNSProvider) (*http.Client, error) {
	return newProviderHTTPClient(p)
}

// parseCheckIPBody scans a checkip response body for the first valid address of
// the requested family, skipping bogus and allowlisted addresses. Exposed
// (unexported but separately testable) so the validity gate is unit-tested
// without a network.
func parseCheckIPBody(body string, wantV4 bool, allowlist []netip.Addr) (netip.Addr, bool) {
	for _, m := range ipAddrRe.FindAllString(body, -1) {
		a, err := netip.ParseAddr(strings.TrimSpace(m))
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.Is4() != wantV4 {
			continue
		}
		if !IsPublicAddr(a) {
			continue
		}
		if isAllowlisted(a, allowlist) {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// specialPurposeV4 enumerates the IANA IPv4 Special-Purpose Address Registry
// ranges (RFC 6890 and successors) that are NOT globally-routable unicast and
// therefore can never be the public address a checkip endpoint should report.
// stdlib netip predicates already cover the unspecified address, loopback
// (127/8), link-local (169.254/16), and multicast (224/4); the prefixes below
// are the ranges those predicates miss — notably CGNAT (100.64/10), the
// benchmarking range (198.18/15), the IETF-protocol/documentation/6to4-relay
// /24s, the 0/8 "this network", the reserved 240/4 block, and the limited
// broadcast 255.255.255.255/32. netip.Addr.IsPrivate() covers 10/8, 172.16/12,
// and 192.168/16 but does NOT cover any of these, hence the explicit list.
var specialPurposeV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network" (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1 (documentation)
	netip.MustParsePrefix("192.88.99.0/24"),     // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2 (documentation)
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3 (documentation)
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved for future use
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
}

// specialPurposeV6 enumerates the IANA IPv6 Special-Purpose Address Registry
// ranges not covered by the stdlib netip predicates used in IsPublicAddr.
// IsUnspecified (::/128), IsLoopback (::1/128), IsLinkLocalUnicast (fe80::/10),
// and IsMulticast (ff00::/8) are handled by predicates; the prefixes below add
// ULA (fc00::/7), the documentation prefixes (2001:db8::/32, 3fff::/20), the
// IPv4-mapped and IPv4/IPv6 translation ranges, the discard-only and dummy
// prefixes, the SRv6 SID block, and the deprecated 6to4 block. Inputs are
// already Unmap()'d before this gate, so an IPv4-mapped literal cannot reach
// the v6 path, but ::ffff:0:0/96 is listed for completeness against a raw v6
// caller. Every entry has Globally-Reachable=False in the IANA registry.
var specialPurposeV6 = []netip.Prefix{
	netip.MustParsePrefix("::ffff:0:0/96"),  // IPv4-mapped (RFC 4291)
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use (RFC 8215)
	netip.MustParsePrefix("100::/64"),       // discard-only (RFC 6666)
	netip.MustParsePrefix("100:0:0:1::/64"), // dummy IPv6 prefix (RFC 9780)
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),  // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056, deprecated)
	netip.MustParsePrefix("3fff::/20"),      // documentation (RFC 9637)
	netip.MustParsePrefix("5f00::/16"),      // SRv6 SIDs (RFC 9602)
	netip.MustParsePrefix("fc00::/7"),       // unique-local / ULA (RFC 4193)
}

// IsPublicAddr is the inadyn validity gate: it accepts only a globally-routable
// unicast address (the public address a checkip endpoint should report) and
// rejects every IANA special-purpose range. A private/reserved/benchmark result
// usually means the request never left the NAT, or the endpoint is hostile or
// misconfigured — never a usable answer to publish as the router's A/AAAA
// record (#2774). stdlib predicates cover the loopback/link-local/multicast/
// unspecified/RFC-1918 cases; the specialPurposeV4/V6 tables cover the rest of
// the registry (CGNAT, benchmarking, documentation, ULA, translation, etc.).
//
// Exported (#2776) so the daemon's Surface A static-address fallback
// (pkg/daemon/daemon_ddns_surface_a.go staticUnitAddr) gates a configured
// static address through the SAME predicate the netlink and checkip address
// sources use — a mis-scoped static address must not publish a martian.
func IsPublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() ||
		a.IsPrivate() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		for _, p := range specialPurposeV4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	for _, p := range specialPurposeV6 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// isAllowlisted reports whether a matches an operator bogus-IP allowlist entry
// (the embedded-resolver case — inadyn `except[]`).
func isAllowlisted(a netip.Addr, allowlist []netip.Addr) bool {
	for _, x := range allowlist {
		if a == x.Unmap() {
			return true
		}
	}
	return false
}

// ParseAllowlistChecked parses a comma/space-separated list of bogus-IP
// addresses into a slice for CheckIP and ALSO returns the tokens that failed to
// parse. The allowlist is a safety gate: an operator typo (e.g. "8.8.8.8x")
// must not be silently discarded, or the checkip parser accepts a bogus/anycast
// IP the operator meant to suppress — exactly the class the allowlist exists to
// prevent (#2839). Callers surface the malformed tokens (commit-time warning in
// the config compiler; once-per-provider runtime log in the daemon wiring).
func ParseAllowlistChecked(s string) (list []netip.Addr, malformed []string) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]netip.Addr, 0, len(fields))
	for _, f := range fields {
		tok := strings.TrimSpace(f)
		if tok == "" {
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, a.Unmap())
		} else {
			malformed = append(malformed, tok)
		}
	}
	return out, malformed
}

// ParseAllowlist parses a comma/space-separated list of bogus addresses into a
// slice for CheckIP. Unparseable entries are skipped (use ParseAllowlistChecked
// to also recover the malformed tokens — the daemon and compiler surface them so
// a typo can no longer silently shrink the safety gate, #2839). Convenience for
// the daemon wiring (the provider/global config carries the allowlist as a
// string).
func ParseAllowlist(s string) []netip.Addr {
	list, _ := ParseAllowlistChecked(s)
	return list
}

// AddressSourceCheckIP is the per-scope selection for the external checkip source
// (#2691 P3, opt-in). Declared here next to the implementation; the other
// AddressSource values live in surface_a.go.
const AddressSourceCheckIP AddressSource = "checkip"

// validateCheckIPURL rejects a malformed or plaintext checkip URL so a typo is
// caught at commit (validateSurfaceADDNSWarnings mirrors this) and fails closed
// at runtime construction (CheckIP) rather than spinning forever as a phantom
// "transient" observation failure (#2773). It requires an https scheme AND a
// host: http.NewRequest accepts ftp://, "not a url", and a host-less "http://",
// none of which can ever fetch a public address. The scheme check is
// case-INSENSITIVE per RFC 3986 §3.1 ("HTTPS://host" is valid), so it parses
// first and compares the parsed scheme with EqualFold rather than a
// case-sensitive HasPrefix on the raw string (#2842). Plaintext http is
// refused since #14372: the response is an unauthenticated oracle for the
// published DNS record, so a spoofed response must never be trusted (and an
// API key embedded in the URL must never travel in cleartext).
//
// SECURITY: NO refusal below prints ANY part of the URL. Since #6545 the daemon
// observer (pkg/daemon/daemon_ddns_surface_a.go) LOGS this error and retains its
// text as a dedup map key for the process lifetime, and a checkip-url routinely
// carries an API key in its userinfo, query or fragment.
//
// Redacting the URL instead of omitting it was tried and is NOT sufficient:
// config.RedactURL is a best-effort string scrubber, not a parser, and it has at
// least three holes that a refusal message walks straight into.
//
//   - Missing '@'. The scan finds userinfo by '@', so the commonest credentialed
//     typo defeats it outright: RedactURL("http://user:s3cr3t.example/") returns
//     that string UNCHANGED (no '@', and no '?' either).
//   - Scheme-relative authority. "//user:SECRET@host/" PARSES fine with populated
//     userinfo, but with no "://" the scan starts at index 0, hits the leading
//     '/' immediately, and takes the authority to be empty — so the userinfo is
//     never found and the value is returned unchanged.
//   - Fragments are never redacted at all. "ftp://host/#apikey=SECRET" and
//     "http:///path#SECRET" both parse, and both keep the secret verbatim.
//
// The last two are PARSE-SUCCESS inputs, so no amount of "only redact once
// url.Parse succeeded" gating helps; that gate was the previous iteration of
// this comment and it was wrong. (The general RedactURL weakness is tracked
// separately as #6609. This validator does not wait on it, and deliberately does
// not depend on it: omitting the value is correct here regardless of how well
// any scrubber works.)
//
// Omitting the URL costs nothing operationally. A refusal is always attributable
// without it: the daemon carries "provider" as its own log attribute, the
// commit-time warning names the provider and the leaf, and the operator is
// looking at the value they just typed.
func validateCheckIPURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		// Render the parse failure's CAUSE as a plain string and drop the %w
		// wrap: url.Parse returns a *url.Error whose Error() re-embeds the FULL
		// raw input, query included, so wrapping it (with %w or %v) would put
		// the credential straight back. Dropping the wrapper is NOT sufficient
		// either — several inner causes embed input too, one of them unbounded —
		// so the cause goes through urlParseCause, which only ever returns a
		// fixed constant. scrubURLError is deliberately not reused here: it
		// recovers a safe URL by RE-PARSING ue.URL, and this URL is precisely
		// the one that does not parse, so it would fall through to the raw
		// string.
		return fmt.Errorf("ddns checkip: url is not a valid URL: %s", urlParseCause(err))
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("ddns checkip: url must be https")
	}
	if parsed.Host == "" {
		return errors.New("ddns checkip: url has no host")
	}
	return nil
}

// parseReason is a CLOSED enumeration of the reasons urlParseCause may report.
// It exists to move the no-leak property out of prose and into the type system:
// urlParseCause returns parseReason, so a bare pass-through of the underlying
// error text — "return cause" — does not COMPILE. Reintroducing the leak now
// requires an explicit parseReason(...) conversion, which is a deliberate,
// greppable edit rather than a plausible-looking slip.
//
// Being honest about the limit: within this package a conversion is still
// legal, so the type is a barrier against the accidental form, not a proof.
// TestURLParseCauseReturnsOnlyDeclaredConstants supplies the proof — it walks
// urlParseCause's AST and asserts every return statement is a bare identifier
// naming one of the constants below, which rejects the conversion form too and,
// unlike a value-based check, covers branches no test input reaches.
type parseReason string

// The COMPLETE set of reasons urlParseCause can return.
const (
	causeMalformedURL   parseReason = "malformed URL"
	causeMissingScheme  parseReason = "missing protocol scheme"
	causeControlChar    parseReason = "invalid control character in URL"
	causeEmptyURL       parseReason = "empty url"
	causeInvalidURI     parseReason = "invalid URI for request"
	causePathColon      parseReason = "first path segment in URL cannot contain colon"
	causeBadUserinfo    parseReason = "invalid userinfo"
	causeInvalidIPLit   parseReason = "invalid IP-literal"
	causeMissingBracket parseReason = "missing ']' in host"
	causeInvalidPort    parseReason = "invalid port after host"
	causeInvalidHost    parseReason = "invalid host"
	causeBadEscape      parseReason = "invalid percent-escape"
	causeBadHostChar    parseReason = "invalid character in host"
)

// urlParseCause renders WHY url.Parse rejected an input, guaranteeing the result
// carries NO part of that input.
//
// THE INVARIANT: every return below names one of the cause* CONSTANTS declared
// above. Nothing derived from the argument is ever returned — not even after
// inspection, and not via a variable that merely happens to hold a literal.
// That, not any particular enumeration below, is what makes this safe, and it
// holds no matter how net/url's messages change.
//
// Two earlier versions of this comment overstated things, so the enforcement is
// spelled out: the parseReason return type makes a bare pass-through fail to
// COMPILE, and TestURLParseCauseReturnsOnlyDeclaredConstants walks this
// function's AST to assert every return is a bare constant identifier. The
// value-based test alongside it only covers causes it invokes, which is why the
// AST check exists — a selective pass-through on an unexercised branch is
// invisible to input-driven testing.
//
// The enumeration exists only to keep the message useful. It is NOT sufficient
// on its own, and two things make that concrete:
//
//   - Dropping the *url.Error wrapper is not enough. The wrapper re-embeds the
//     whole raw URL, but several INNER causes embed input too, and one is
//     unbounded: fmt.Errorf("invalid port %q after host", colonPort) (url.go
//     561/630) quotes an arbitrary-length substring. The realistic trigger is an
//     operator who omits the '@' in a credentialed URL —
//     "https://user:s3cr3t.example/" parses as host "user", port
//     ":s3cr3t.example" — so the failure mode puts the PASSWORD in the message.
//     fmt.Errorf("invalid host: %w", err) (line 600) is unbounded the same way
//     via netip's ParseAddr("<raw host>"). url.EscapeError (118/127/139) and
//     url.InvalidHostError (148) quote a bounded 3- and 1-character fragment.
//
//   - Switching on the error TYPE cannot work. fmt.Errorf without %w returns
//     *errors.errorString, which is exactly the type of the SAFE errors.New
//     causes, so "invalid port \"...\" after host" and "missing protocol scheme"
//     are indistinguishable by type. Hence the exact-match switch on the fixed
//     sentences, plus class detection for the four input-bearing shapes — each
//     of which maps to its own constant so the class stays diagnostic ("invalid
//     port after host" still tells the operator where to look) without the
//     offending bytes.
//
// The switch cases are the net/url parse failures whose text is a FIXED sentence
// containing no part of the input, enumerated deliberately from the Go 1.26.4
// net/url/url.go parse path rather than guessed: errors.New at lines 380, 436,
// 440, 470, 481, 526, 550, 556 and 603. ("invalid URI for request", line 470, is
// ParseRequestURI-only and unreachable through url.Parse; it is handled anyway
// because this helper is meant to be reusable by the other DDNS URL validators,
// #6606.) It is an ALLOWLIST, never a blocklist: anything unmatched falls
// through to causeMalformedURL, so a stdlib rewording or a brand-new cause
// degrades the diagnostic instead of opening a leak.
func urlParseCause(err error) parseReason {
	var ue *url.Error
	if !errors.As(err, &ue) || ue.Err == nil {
		// Not a url.Parse failure at all (unreachable via url.Parse, which
		// always wraps). Nothing is known about this text — fail closed.
		return causeMalformedURL
	}
	cause := ue.Err.Error()

	switch cause {
	case "missing protocol scheme":
		return causeMissingScheme
	case "net/url: invalid control character in URL":
		return causeControlChar
	case "empty url":
		return causeEmptyURL
	case "invalid URI for request":
		return causeInvalidURI
	case "first path segment in URL cannot contain colon":
		return causePathColon
	case "net/url: invalid userinfo":
		return causeBadUserinfo
	case "invalid IP-literal":
		return causeInvalidIPLit
	case "missing ']' in host":
		return causeMissingBracket
	}

	// Input-bearing classes, each collapsed to its own constant. The two typed
	// ones are matched by type; the two fmt.Errorf ones have no distinguishing
	// type, so they are matched on the invariant PREFIX that precedes the
	// interpolated input.
	var esc url.EscapeError
	if errors.As(ue.Err, &esc) {
		return causeBadEscape
	}
	var badHost url.InvalidHostError
	if errors.As(ue.Err, &badHost) {
		return causeBadHostChar
	}
	if strings.HasPrefix(cause, "invalid port \"") {
		return causeInvalidPort
	}
	if strings.HasPrefix(cause, "invalid host: ") {
		return causeInvalidHost
	}

	// Unrecognized: fail closed rather than pass an unaudited string through.
	return causeMalformedURL
}
