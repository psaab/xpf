package config

import "strings"

// ddnsBackendCarriesCredentials reports whether an HTTP DDNS backend attaches
// credentials to its update requests — Basic auth (dyndns2/generic), a query or
// bearer token (DuckDNS/Cloudflare), or SigV4 (Route 53). Such a backend must
// only ever talk to an https:// endpoint (#4861); an rfc2136 backend (DNS, not
// HTTP) and an unknown backend are false. For the generic templated backend the
// credential may be Basic auth (typed username/password), an inadyn %u/%p
// specifier embedded in the url-template, or a LITERAL "user:secret@host"
// userinfo written directly into the template authority (#5471) — the generic
// template validator explicitly supports a userinfo credential, so that form
// must classify as credentialed or the http-vs-https gate would let it leak the
// credential in cleartext.
func ddnsBackendCarriesCredentials(p *DDNSProvider) bool {
	switch p.Backend {
	case "dyndns2":
		return p.Username != "" || p.Password.Reveal() != ""
	case "duckdns", "cloudflare":
		return p.APIToken.Reveal() != ""
	case "route53":
		return p.AWSAccessKeyID != "" || p.AWSSecretAccessKey.Reveal() != ""
	case "generic":
		return p.Username != "" || p.Password.Reveal() != "" ||
			strings.Contains(p.URLTemplate, "%u") || strings.Contains(p.URLTemplate, "%p") ||
			ddnsTemplateAuthorityHasUserinfo(p.URLTemplate)
	}
	return false
}

// ddnsTemplateAuthorityHasUserinfo reports whether a generic url-template's
// AUTHORITY carries a nonempty userinfo ("user:pass@" or "user@" before the
// host) — a LITERAL embedded credential (#5471). The %u/%p specifier form is
// already handled by ddnsBackendCarriesCredentials; this catches the literal
// "user:secret@host" case, which has none of those markers.
//
// The authority is the network location: it begins after "://" for a scheme'd
// template, or at index 0 for a schemeless one, and ends at the first '/', '?'
// or '#'. Bounding the '@' scan to the authority is what keeps an '@' in a PATH
// ("host/p@th") or QUERY ("host?x=a@b") from being misread as userinfo — the
// same authority-bounded logic as RedactURL (#5464/#5458). The template is
// TrimSpace'd first to stay in lockstep with the runtime gate and the other
// template validators (which trim). Scheme/host may themselves contain inadyn
// %h/%i specifiers; the scan is byte-based so it tolerates them.
//
// Only a nonempty userinfo counts: an empty userinfo ("@host", '@' at the start
// of the authority) is not a credential.
func ddnsTemplateAuthorityHasUserinfo(tmpl string) bool {
	tmpl = strings.TrimSpace(tmpl)
	authStart := 0
	if i := strings.Index(tmpl, "://"); i >= 0 {
		authStart = i + len("://")
	}
	authEnd := len(tmpl)
	for j := authStart; j < len(tmpl); j++ {
		if c := tmpl[j]; c == '/' || c == '?' || c == '#' {
			authEnd = j
			break
		}
	}
	authority := tmpl[authStart:authEnd]
	// A nonempty userinfo requires at least one character before the last '@'
	// within the authority; '@' at index 0 (empty userinfo) does not count.
	return strings.LastIndex(authority, "@") > 0
}

// ddnsPlaintextCredentialEndpoint reports the operator-supplied endpoint field
// (server / url-template / checkip-url) and value when it carries an explicit
// non-https scheme that must not be plaintext.
//
// server / url-template are gated only for a CREDENTIALED HTTP DDNS backend
// (#4861): an explicit http:// (or any non-https scheme) endpoint would carry
// the update credential in cleartext.
//
// checkip-url is gated UNCONDITIONALLY (#14372): it carries no update
// credential, but its response is an unauthenticated ORACLE — Surface A
// trusts it as this firewall's public address and publishes it as the DNS
// record, so a spoofed plaintext response controls the published record
// (and an API key embedded in the URL leaks in cleartext on every probe).
// The credentialed-only condition therefore does not apply to it.
//
// A bare host with no scheme is fine — every HTTP backend composes it over
// https — so only an explicit non-https scheme is flagged. Returns bad=false
// for an https/empty/bare endpoint (and, for server/url-template, for a
// non-credentialed backend).
//
// Scheme extraction is the substring before "://" compared case-insensitively
// (RFC 3986 §3.1), string-based rather than url.Parse-based because a generic
// url-template legitimately embeds %h/%i/%u/%p specifiers (and a userinfo
// credential) that make url.Parse mangle or reject the value — the same reason
// validateGenericURLTemplate is string-based.
func ddnsPlaintextCredentialEndpoint(p *DDNSProvider) (field, value string, bad bool) {
	check := func(field, s string) (string, string, bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", "", false
		}
		i := strings.Index(s, "://")
		if i < 0 {
			// Bare host (no scheme) → composed over https by the backend.
			return "", "", false
		}
		if !strings.EqualFold(s[:i], "https") {
			return field, s, true
		}
		return "", "", false
	}
	// checkip-url first and unconditional (#14372): even when the backend
	// carries no credential at all, a plaintext checkip response is trusted
	// as the published address.
	if f, v, b := check("checkip-url", p.CheckIPURL); b {
		return f, v, true
	}
	if !ddnsBackendCarriesCredentials(p) {
		return "", "", false
	}
	if f, v, b := check("server", p.Server); b {
		return f, v, true
	}
	if p.Backend == "generic" {
		if f, v, b := check("url-template", p.URLTemplate); b {
			return f, v, true
		}
	}
	return "", "", false
}
