package ddns

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_plaintext_14386.go: runtime belt for #14386 (DR6-H2). The compiler
// drops credentialed plaintext providers on lenient load and hard-rejects
// them on strict commit, but a backend constructed directly (bypassing the
// compiler) must not issue a cleartext request carrying a credential either.
// Refusal happens at construction so the manager degrades to the no-op
// backend and no request is ever issued.
//
// Loopback endpoints (127.0.0.0/8, ::1, "localhost") are exempt: the
// credential never leaves the host, and the httptest harness (and local
// provider emulators) depend on http://127.0.0.1. Non-loopback http://
// endpoints carrying any credential form are refused.
//
// Credential detection mirrors pkg/config's widened detector: typed
// username/password, %u/%p specifiers, authority userinfo, and literal
// credential-named key=value tokens in the query/path. Bare path segments
// are intentionally not flagged (documented gap, same as config).

// plaintextEndpointRefusal returns a refusal error when rawURL is an
// explicit non-https URL to a non-loopback host. The error never echoes the
// credential: it renders through config.RedactURL.
func plaintextEndpointRefusal(backend, name, rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil // malformed URLs are rejected by the caller's own validation
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return nil // https (or scheme-less, composed over https) is fine
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("ddns %s: provider %q endpoint %q must be an https:// endpoint — refusing to transmit the update credential in cleartext (#14386)",
		backend, name, config.RedactURL(rawURL))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return addr.IsLoopback()
	}
	return false
}

// templateAuthorityUserinfo reports whether a URL string's authority carries
// a nonempty userinfo (mirrors config.ddnsTemplateAuthorityHasUserinfo).
func templateAuthorityUserinfo(s string) bool {
	s = strings.TrimSpace(s)
	authStart := 0
	if i := strings.Index(s, "://"); i >= 0 {
		authStart = i + len("://")
	}
	authEnd := len(s)
	for j := authStart; j < len(s); j++ {
		if c := s[j]; c == '/' || c == '?' || c == '#' {
			authEnd = j
			break
		}
	}
	return strings.LastIndex(s[authStart:authEnd], "@") > 0
}

// templateCarriesLiteralToken mirrors config.ddnsTemplateCarriesLiteralToken:
// a credential-named key=literal pair in the query or path.
func templateCarriesLiteralToken(tmpl string) bool {
	tmpl = strings.TrimSpace(tmpl)
	if i := strings.Index(tmpl, "#"); i >= 0 {
		tmpl = tmpl[:i]
	}
	authStart := 0
	if i := strings.Index(tmpl, "://"); i >= 0 {
		authStart = i + len("://")
	}
	authEnd := len(tmpl)
	for j := authStart; j < len(tmpl); j++ {
		if c := tmpl[j]; c == '/' || c == '?' {
			authEnd = j
			break
		}
	}
	rest := tmpl[authEnd:]
	path, query := rest, ""
	if i := strings.Index(rest, "?"); i >= 0 {
		path, query = rest[:i], rest[i+1:]
	}
	isLiteral := func(v string) bool {
		return v != "" && !strings.Contains(v, "%") && !strings.Contains(v, "{{")
	}
	isCredKey := func(k string) bool {
		switch strings.ToLower(k) {
		case "token", "access-token", "access_token", "accesstoken",
			"api-key", "api_key", "apikey", "auth", "auth-key", "authkey",
			"password", "passwd", "secret", "session-key", "sessionkey":
			return true
		}
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if i := strings.Index(seg, "="); i > 0 && isCredKey(seg[:i]) && isLiteral(seg[i+1:]) {
			return true
		}
	}
	for _, pair := range strings.Split(query, "&") {
		if i := strings.Index(pair, "="); i > 0 && isCredKey(pair[:i]) && isLiteral(pair[i+1:]) {
			return true
		}
	}
	return false
}

// dyndns2CarriesCredentials mirrors the dyndns2 arm of the config detector.
func dyndns2CarriesCredentials(p *config.DDNSProvider) bool {
	return p.Username != "" || p.Password.Reveal() != "" ||
		templateAuthorityUserinfo(p.Server)
}

// genericCarriesCredentials mirrors the generic arm of the config detector.
func genericCarriesCredentials(p *config.DDNSProvider) bool {
	return p.Username != "" || p.Password.Reveal() != "" ||
		strings.Contains(p.URLTemplate, "%u") || strings.Contains(p.URLTemplate, "%p") ||
		templateAuthorityUserinfo(p.URLTemplate) ||
		templateCarriesLiteralToken(p.URLTemplate)
}
