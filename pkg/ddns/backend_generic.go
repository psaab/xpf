package ddns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_generic.go: the generic-templated HTTP DDNS backend (#2691 P3, plan
// §3.7 idea #3 — inadyn "custom"). CONFIG-ONLY: an operator supports a provider
// xpf has no coded backend for by supplying a URL template + a success-substring
// matcher, with NO new Go code per provider. This is the highest-leverage P3
// feature — it covers the long tail of niche DDNS services.
//
// The template uses inadyn's format specifiers (plan §3.1):
//
//	%h → hostname (the FQDN)        %i → IP address (the observed addr)
//	%u → username                  %p → password
//	%% → a literal percent sign
//
// Success is decided by a TOKEN match on the (HTTP 2xx) response body against
// the operator's `ok-response` (or the default matcher set). This mirrors
// inadyn's default {"OK","good","true","updated","nochg"} list.
//
// #2838: matching is token-bounded, NOT a raw substring. A success token must
// equal a trimmed response line OR be the leading whitespace-delimited field of
// a line (so "good 1.2.3.4" still passes). A naive strings.Contains turned an
// explicit provider FAILURE into a false success — "not ok", "error: ok token
// invalid", "update not good", or an HTML page with an "OK" button all CONTAIN
// a default token, so they were wrongly classified as a completed update. The
// engine (surface_a.go) then records ownership and suppresses retry, leaving
// DNS stale while the router believes the address was published.

// defaultGenericOKTokens is the success-matcher set used when a generic
// provider sets no explicit ok-response (plan §3.1). Matched as whole tokens
// (see matchesGenericOK), case-insensitive.
var defaultGenericOKTokens = []string{"good", "nochg", "ok", "true", "updated"}

// genericBackend publishes via a templated URL + substring success match.
type genericBackend struct {
	name        string
	urlTemplate string
	okTokens    []string // success tokens (lowercased; whole-token match, #2838)
	username    string
	password    string // revealed at construction; never logged
	client      *http.Client
}

// newGenericBackend resolves a provider-catalog entry into a live generic
// backend. A missing url-template is a hard error (nothing to do) so the manager
// falls back to no-op rather than silently publishing nothing.
//
// client is the bound *http.Client the backend issues requests on. The Surface A
// reconcile path passes a cached client (reused across passes, #2904); a nil
// client makes the constructor build its own bound client (test callers, and any
// caller without a cache) — preserving the pre-#2904 self-contained behaviour.
func newGenericBackend(p *config.DDNSProvider, client *http.Client) (*genericBackend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns generic: nil provider")
	}
	tmpl := strings.TrimSpace(p.URLTemplate)
	if tmpl == "" {
		return nil, fmt.Errorf("ddns generic: provider %q has no url-template", p.Name)
	}
	if err := validateGenericURLTemplate(tmpl); err != nil {
		return nil, fmt.Errorf("ddns generic: provider %q %w", p.Name, err)
	}
	// #14386 runtime belt: refuse a credentialed plaintext http:// template
	// at construction (direct construction bypasses the compiler drop).
	if genericCarriesCredentials(p) {
		if err := plaintextEndpointRefusal("generic", p.Name, tmpl); err != nil {
			return nil, err
		}
	}
	ok := defaultGenericOKTokens
	if s := strings.TrimSpace(p.OKResponse); s != "" {
		// Split a configured ok-response into WHOLE TOKENS, not one
		// space-joined element (#5557 / claude-review-003 A10). matchesGenericOK
		// does whole-token matching (#2838): a success token must equal a
		// trimmed response line or be the leading whitespace-delimited field of
		// a line — it never sees a token as a raw substring. A single element
		// carrying an embedded space (e.g. "good nochg") therefore can only
		// match a response line that is EXACTLY "good nochg"; its first-field
		// path is dead (a first field never contains a space), so a dyndns2-shape
		// body like "good nochg 1.2.3.4" is never recognized and every update is
		// treated as failed → error spam + backoff → DNS goes stale. Tokenizing
		// on whitespace makes each configured word a matchable whole token,
		// exactly like the single-token defaultGenericOKTokens set. Semantics are
		// unchanged: the matcher is ANY-token (OR), so any configured word being
		// present as a whole token/leading field signals success. strings.Fields
		// yields at least one element here (s is non-empty after TrimSpace).
		ok = strings.Fields(strings.ToLower(s))
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846).
	client, err := ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns generic: provider %q: %w", p.Name, err)
	}
	return &genericBackend{
		name:        p.Name,
		urlTemplate: tmpl,
		okTokens:    ok,
		username:    p.Username,
		password:    p.Password.Reveal(),
		client:      client,
	}, nil
}

// validateGenericURLTemplate rejects an obviously malformed generic url-template
// at construction so a typo fails closed at commit/construct rather than at the
// first publish (#2841). It enforces the SAME discipline as checkip's
// validateCheckIPURL — a case-INSENSITIVE http(s) scheme (RFC 3986 §3.1,
// matching #2842) plus a non-empty host — but it is deliberately TEMPLATE-AWARE
// and string-based, NOT net/url-based: the value is an inadyn template carrying
// %h/%i/%u/%p specifiers (and may embed a credential in the userinfo, e.g.
// https://user:%p@host/upd) which are not valid percent-encoding and make
// url.Parse fail or mangle the string (the same reason RedactURL is string-based,
// #2781). It validates ONLY the scheme + host portion and tolerates any
// %-specifier or {{...}} placeholder in the userinfo/path/query.
//
// The error message embeds the template through config.RedactURL: a generic
// template routinely carries a credential in the userinfo (https://user:%p@...)
// or the query (?token=SECRET), and this error is logged (slog.Warn at the
// surface-A construction site) — the raw template must NOT reach journald
// (#2841 credential-leak fold; matches the RedactURL'd commit-time warning).
func validateGenericURLTemplate(tmpl string) error {
	// Scheme: the substring up to "://", compared case-insensitively.
	i := strings.Index(tmpl, "://")
	if i < 0 {
		return fmt.Errorf("url-template %q must be an http(s) URL (no scheme)", config.RedactURL(tmpl))
	}
	scheme := tmpl[:i]
	if !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return fmt.Errorf("url-template %q must be an http(s) URL", config.RedactURL(tmpl))
	}
	// Authority: between "://" and the first '/', '?' or '#'. Strip any userinfo
	// ("user:pass@", which legitimately contains %u/%p) — the host is what
	// remains after the last '@'.
	authStart := i + len("://")
	authEnd := len(tmpl)
	for j := authStart; j < len(tmpl); j++ {
		if c := tmpl[j]; c == '/' || c == '?' || c == '#' {
			authEnd = j
			break
		}
	}
	authority := tmpl[authStart:authEnd]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	// #4589 A10-b2 F-01: require a non-empty HOST after dropping a trailing
	// :port (and unwrapping a bracketed IPv6 literal). `http://:8080/upd` has
	// a non-empty authority (":8080") but an EMPTY host, so the old
	// `authority == ""` check let it through — Go's dialer then treats an
	// empty-host URL as localhost. Kept byte-for-byte in lockstep with
	// ddnsGenericURLTemplateValid (compiler_validate_warn.go), the #2841
	// commit-time mirror this is a residual of.
	if ddnsTemplateHost(authority) == "" {
		return fmt.Errorf("url-template %q has no host", config.RedactURL(tmpl))
	}
	return nil
}

// ddnsTemplateHost extracts the host from a URL authority whose userinfo has
// already been stripped: it drops a trailing :port and unwraps a bracketed
// IPv6 literal, returning "" when there is no host segment (e.g. ":8080" or an
// unterminated "[..."). Kept in lockstep with the inline copy in
// pkg/config.ddnsGenericURLTemplateValid (config cannot import pkg/ddns).
func ddnsTemplateHost(authority string) string {
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end >= 0 {
			return authority[1:end]
		}
		return ""
	}
	if colon := strings.IndexByte(authority, ':'); colon >= 0 {
		return authority[:colon]
	}
	return authority
}

// renderGenericURL expands the inadyn-style template specifiers. %u/%p are
// URL-query-escaped so a credential or hostname with reserved characters does
// not break the URL. %% is a literal percent. An unknown %x is left verbatim.
func renderGenericURL(tmpl, host, ip, user, pass string) string {
	var sb strings.Builder
	sb.Grow(len(tmpl) + 32)
	for i := 0; i < len(tmpl); i++ {
		c := tmpl[i]
		if c != '%' || i+1 >= len(tmpl) {
			sb.WriteByte(c)
			continue
		}
		i++
		switch tmpl[i] {
		case 'h':
			sb.WriteString(queryEscape(host))
		case 'i':
			sb.WriteString(queryEscape(ip))
		case 'u':
			sb.WriteString(queryEscape(user))
		case 'p':
			sb.WriteString(queryEscape(pass))
		case '%':
			sb.WriteByte('%')
		default:
			// Unknown specifier: keep both bytes verbatim.
			sb.WriteByte('%')
			sb.WriteByte(tmpl[i])
		}
	}
	return sb.String()
}

// UpsertLease publishes via the rendered template URL.
func (b *genericBackend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	rawURL := renderGenericURL(b.urlTemplate, rec.FQDN, rec.Addr.Unmap().String(), b.username, b.password)
	// #14386 belt at issuance: the rendered URL may carry a credential
	// (%u/%p expansion, typed Basic auth, userinfo, or a literal token);
	// never send it over plaintext http:// to a non-loopback host.
	if (b.username != "" || b.password != "" ||
		strings.Contains(b.urlTemplate, "%u") || strings.Contains(b.urlTemplate, "%p") ||
		templateAuthorityUserinfo(b.urlTemplate) || templateCarriesLiteralToken(b.urlTemplate)) &&
		plaintextEndpointRefusal("generic", b.name, rawURL) != nil {
		return fmt.Errorf("ddns generic: %s: endpoint must be an https:// endpoint — refusing to transmit the update credential in cleartext (#14386)", b.name)
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		// SECURITY: a build-request error (url.Parse) embeds the offending URL,
		// which carries the %p-expanded password in the query, the userinfo or
		// the PATH — do NOT propagate the raw URL. scrubURLError withholds a URL
		// that does not parse and reports only the sanitized urlParseCause
		// reason, which is strictly more diagnostic than the bare class this
		// used to report and still names no part of the rendered URL (#6545).
		return fmt.Errorf("ddns generic: %s: malformed rendered update URL: %s", b.name, scrubURLError(err))
	}
	// If the operator also set username/password (and did NOT thread them through
	// the template), offer them via Basic auth too — harmless if the server
	// ignores it, and it keeps the secret out of a logged URL.
	if b.username != "" || b.password != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, body, err := doRequest(ctx, b.client, req)
	if err != nil {
		return err
	}
	if cerr := classifyHTTPStatus(code); cerr != nil {
		return fmt.Errorf("ddns generic: %s: %w", b.name, cerr)
	}
	if matchesGenericOK(string(body), b.okTokens) {
		return nil
	}
	return fmt.Errorf("ddns generic: %s: response did not match success token(s) %v", b.name, b.okTokens)
}

// matchesGenericOK decides whether an HTTP 2xx body signals a successful update
// (#2838). A success token matches only as a WHOLE TOKEN, never as a raw
// substring: the token must equal a trimmed response line, or be the leading
// whitespace-delimited field of a line (e.g. dyndns2-style "good 1.2.3.4").
// This is the fail-closed half of the issue — "not ok", "error: ok token
// invalid", "update not good", and an HTML page containing an "OK" button all
// CONTAIN a default token but are NOT a success, so they must be rejected. The
// comparison is case-insensitive; tokens in okTokens are already lowercased.
func matchesGenericOK(body string, okTokens []string) bool {
	if len(okTokens) == 0 {
		return false
	}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		// Leading whitespace-delimited field of the line (the protocol keyword;
		// dyndns2 returns "good <ip>" / "nochg <ip>").
		first := lower
		if i := strings.IndexFunc(lower, func(r rune) bool {
			return r == ' ' || r == '\t'
		}); i >= 0 {
			first = lower[:i]
		}
		for _, tok := range okTokens {
			if lower == tok || first == tok {
				return true
			}
		}
	}
	return false
}

// errGenericDeleteUnsupported marks the generic backend's lack of a portable
// withdraw verb (#2772). A single inadyn-style update template carries no notion
// of "remove this record", and xpf exposes no per-provider delete template, so
// there is nothing safe to send. Wrapped (never bare) so a caller can errors.Is
// it and surface the abandoned record rather than treat it as a generic failure.
var errGenericDeleteUnsupported = errors.New("ddns generic: backend has no delete/withdraw operation")

// DeleteLease FAILS for the generic backend (#2772): a templated update protocol
// has no portable delete verb, and xpf has no per-provider delete template, so
// the backend cannot actually clear the record. The previous implementation was
// a no-op that returned nil — the Surface A engine then dropped local ownership
// while the public record kept resolving forever. Returning a non-nil error
// makes the engine increment deleteFail and KEEP the ownership entry, so the
// stale/abandoned record stays operator-visible (it shows up as a withdraw that
// did not complete) instead of being silently reported as withdrawn. An operator
// who needs an actual withdraw must use a backend that supports one (dyndns2's
// offline verb, cloudflare/route53 DELETE, or rfc2136) and clear the record at
// the provider out of band.
func (b *genericBackend) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	return fmt.Errorf("ddns generic: %s: cannot withdraw %s %s: %w",
		b.name, rec.ForwardType, rec.FQDN, errGenericDeleteUnsupported)
}
