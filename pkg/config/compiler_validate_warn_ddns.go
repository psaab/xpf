package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// validateDDNSBackendWarnings emits WARN-only commit-time messages for the
// now-live DHCP dynamic-DNS backend (#1387 increment 2). It never returns
// an error: the typed schema already accepts these leaves, and a stricter
// HARD reject would brick a boot on a previously-inert malformed value
// (plan §7 Q-C). The reconciler/backend degrade safely at runtime (an
// unusable backend resolves to a no-op and counts a no-backend skip).
//
// IT COVERS BOTH FAMILIES (#8597 K66). It used to read only
// System.DHCPServer.DynamicDNS, so the independent v6 policy #2691 P1b added
// —  `system services dhcpv6-local-server dynamic-dns`, committable through the
// SAME schema tree (dhcpDynamicDNSSchema is returned fresh per call for both
// stanzas) — got none of these diagnostics. Measured before the change: a v4
// block with `enable` and no update-server warns; the byte-identical v6 block
// commits with ZERO warnings of any kind, and the same silence covered the
// security-relevant halves (the #4483 unsigned-UPDATE warning, the #2666 TSIG
// tuple warning, and the reserved kea-d2 backend).
//
// That is worse than a one-family gap, because ReconcileScoped INHERITS: when
// only one family's block is present the other family uses it, so a broken
// v6-only block silently governs v4 too. The inheritance note below fires only
// when that family already produced a warning, so a healthy single-family
// config — the historical and common shape — stays quiet.
func validateDDNSBackendWarnings(cfg *Config) []string {
	d4 := cfg.System.DHCPServer.DynamicDNS
	d6 := cfg.System.DHCPServer.DynamicDNSv6

	warnings := ddnsBackendWarningsForPolicy(d4, "dhcp dynamic-dns")
	v6 := ddnsBackendWarningsForPolicy(d6, "dhcpv6 dynamic-dns")

	// The inheritance surprise, stated where it is actionable. pkg/ddns
	// ReconcileScoped tests the block for NIL, not for enabled, so this
	// condition mirrors the runtime exactly.
	if len(warnings) > 0 && d6 == nil {
		warnings = append(warnings, "dhcp dynamic-dns is the only dynamic-dns "+
			"block configured, so it also governs DHCPv6 leases (a family with no "+
			"block of its own inherits the other's); the warnings above apply to "+
			"both families")
	}
	if len(v6) > 0 && d4 == nil {
		v6 = append(v6, "dhcpv6 dynamic-dns is the only dynamic-dns block "+
			"configured, so it also governs DHCPv4 leases (a family with no block "+
			"of its own inherits the other's); the warnings above apply to both "+
			"families")
	}
	return append(warnings, v6...)
}

// ddnsBackendWarningsForPolicy is validateDDNSBackendWarnings for ONE family's
// policy. label prefixes every message and is the operator-facing stanza name
// ("dhcp dynamic-dns" / "dhcpv6 dynamic-dns"), so a warning names the block the
// operator has to edit. The v4 strings are byte-identical to what this emitted
// before the split.
func ddnsBackendWarningsForPolicy(d *DHCPDynamicDNSConfig, label string) []string {
	if d == nil || !d.Enabled {
		return nil
	}
	var warnings []string

	// #14429: a garbage conflict-policy (skip-existng, none, ...) is
	// rejected by the strict schema enum at commit, but on the tolerant
	// load / peer-sync path it previously sailed through silently and
	// disabled the backend's DNS-ownership guard (bare Insert, phantom
	// ownership). Warn here so the lenient path is visible; the runtime
	// backend independently refuses to construct with such a policy.
	if d.ConflictPolicy != "" && d.ConflictPolicy != "replace-owned" &&
		d.ConflictPolicy != "skip-existing" && d.ConflictPolicy != "strict-fail" {
		warnings = append(warnings, fmt.Sprintf("%s "+
			"conflict-policy %q is not valid (use replace-owned, skip-existing, "+
			"or strict-fail); the DNS-ownership guard would be disabled, so no "+
			"records will be published or withdrawn until it is corrected",
			label, d.ConflictPolicy))
	}

	backend := d.Backend
	if backend == "" {
		backend = "rfc2136"
	}
	switch backend {
	case "rfc2136":
		if d.UpdateServer == "" {
			warnings = append(warnings, label+" is enabled with "+
				"backend rfc2136 but no update-server is configured; no records "+
				"will be published until an update-server is set")
		} else if !ddnsUpdateServerParseable(d.UpdateServer) {
			warnings = append(warnings, fmt.Sprintf("%s "+
				"update-server %q is not a valid host or host:port; the backend "+
				"will fail to send updates", label, d.UpdateServer))
		}
		// #4483: an update-server with NO tsig-key sends unsigned UPDATEs and
		// trusts an UNAUTHENTICATED, forgeable response rcode — a spoofed
		// NOERROR records a name as published though the server wrote nothing
		// (silent blackhole), and a spoofed REFUSED suppresses a legitimate
		// publish. WARN-only so a previously-inert config still commits; the
		// fix is to configure tsig-key/tsig-secret (exchange then requires a
		// TSIG-signed response and miekg verifies its MAC, #14603).
		if d.UpdateServer != "" && d.TSIGKeyName == "" {
			warnings = append(warnings, label+" update-server is "+
				"configured without a tsig-key; DNS UPDATEs are sent unsigned and "+
				"the server's response rcode is unauthenticated and forgeable — a "+
				"spoofed NOERROR can record a name as published though nothing was "+
				"written (silent blackhole) and a spoofed REFUSED can suppress a "+
				"legitimate publish. Set tsig-key/tsig-secret to authenticate updates")
		}
		if d.TSIGKeyName != "" && !ddnsTSIGAlgorithmSupported(d.TSIGAlgorithm) {
			warnings = append(warnings, fmt.Sprintf("%s "+
				"tsig-algorithm %q is not supported (use hmac-sha1, hmac-sha224, "+
				"hmac-sha256, hmac-sha384, or hmac-sha512; hmac-md5 is rejected as "+
				"insecure); the backend will fail to sign updates", label, d.TSIGAlgorithm))
		}
		// TSIG tuple completeness (#2666 / #2691 P0): RFC 8945 TSIG needs the
		// full {key name, algorithm, secret} triple. The backend enables
		// signing whenever tsig-key is set and copies the secret without an
		// empty check, so a key without a secret signs with an empty key and
		// a real authoritative server rejects it (BADKEY/BADSIG) at RUNTIME.
		// A secret without a key is silently ignored (no signing happens).
		// Warn at commit so the operator sees the incomplete tuple instead of
		// debugging a runtime failure. WARN-only (never a hard reject): a
		// previously-inert partial TSIG config must not brick a boot.
		keySet := d.TSIGKeyName != ""
		secretSet := d.TSIGSecret.Reveal() != ""
		switch {
		case keySet && !secretSet:
			warnings = append(warnings, label+" tsig-key is set but "+
				"tsig-secret is empty; TSIG signing will use an empty key and the "+
				"authoritative server will reject updates (BADKEY/BADSIG) — set "+
				"tsig-secret to complete the TSIG key")
		case secretSet && !keySet:
			warnings = append(warnings, label+" tsig-secret is set but "+
				"tsig-key is empty; without a key name TSIG signing is disabled and "+
				"the secret is ignored — set tsig-key to enable authenticated "+
				"updates")
		}
	case "kea-d2":
		warnings = append(warnings, label+" backend kea-d2 is "+
			"reserved but not implemented (Kea D2 is not in the image); no "+
			"records will be published with this backend")
	}
	return warnings
}

// ddnsUpdateServerParseable reports whether an update-server string is a
// usable host or host:port (mirrors the backend's normalizeUpdateServer).
func ddnsUpdateServerParseable(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return true
	}
	// No port: treat as a bare host (the backend attaches :53). Reject only
	// when it is obviously not a host (e.g. embedded whitespace).
	return !strings.ContainsAny(s, " \t")
}

// ddnsTSIGAlgorithmSupported reports whether a TSIG algorithm string is one
// the backend can sign with (default hmac-sha256 when unset; hmac-md5
// rejected). Mirrors ddns_rfc2136.canonicalTSIGAlgorithm without importing
// the dhcpserver package into pkg/config.
func ddnsTSIGAlgorithmSupported(algo string) bool {
	a := strings.ToLower(strings.TrimSpace(algo))
	a = strings.TrimSuffix(a, ".")
	switch a {
	case "", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512":
		return true
	default:
		return false
	}
}

// ddnsKnownDyndns2NameSet mirrors pkg/ddns.dyndns2Endpoints for the commit-time
// completeness warning ONLY (config cannot import pkg/ddns). It must stay in
// sync with that table; a name here but missing there (or vice versa) only
// affects whether the operator gets a "no server" warning, never runtime
// behavior — the runtime resolver in pkg/ddns is authoritative.
var ddnsKnownDyndns2NameSet = map[string]bool{
	"dyn": true, "dyndns": true, "no-ip": true, "noip": true,
	"dynu": true, "easydns": true, "dnsomatic": true,
	// NOTE: duckdns is intentionally NOT here — DuckDNS is its own backend
	// (#2960), not a dyndns2 alias (it uses domains=/token=/OK and clear=true).
}

// ddnsKnownDyndns2Provider reports whether a provider NAME is a recognized
// built-in dyndns2 endpoint (so a missing `server` is not warned).
func ddnsKnownDyndns2Provider(name string) bool {
	return ddnsKnownDyndns2NameSet[strings.ToLower(name)]
}

// ddnsDyndns2ServerValid mirrors pkg/ddns.resolveDyndns2Endpoint's `server`
// parsing for the commit-time warning ONLY (config cannot import pkg/ddns). It
// must stay in sync with that resolver; a divergence only affects whether the
// operator gets a warning at commit — the runtime resolver in pkg/ddns is
// authoritative and fails closed (falls back to no-op) regardless (#3737).
//
// A dyndns2 `server` is either a full update URL (carrying a scheme) or a bare
// host that the resolver suffixes with the canonical /nic/update path over
// HTTPS. URL schemes are case-INSENSITIVE per RFC 3986 §3.1, so a full URL is
// detected by the "://" delimiter and its scheme compared with EqualFold
// ("HTTPS://host" is valid), matching ddnsCheckIPURLValid (#2842). Both cases
// require a non-empty host so a hostless value ("http://", "https:///nic/update",
// ":8080") is flagged at commit instead of failing only at the first publish.
// The input is TrimSpace'd first so it stays in lockstep with the runtime
// resolver, which trims p.Server before parsing; a whitespace-only server is
// treated as empty (the "no server" completeness branch handles it).
func ddnsDyndns2ServerValid(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		// Hostname() (not Host) so a port-only authority is treated as hostless,
		// matching the runtime resolver.
		if err != nil || u.Hostname() == "" {
			return false
		}
		return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
	}
	// Bare host → canonical https://<host>/nic/update; validate the host.
	u, err := url.Parse("https://" + s + "/nic/update")
	return err == nil && u.Hostname() != ""
}

// ddnsCheckIPURLValid mirrors pkg/ddns.validateCheckIPURL for the commit-time
// warning ONLY (config cannot import pkg/ddns). It must stay in sync with that
// validator; a divergence only affects whether the operator gets a warning at
// commit — the runtime CheckIP gate in pkg/ddns is authoritative and fails
// closed regardless (#2773). A checkip-url must be an https URL with a host;
// without that gate a typo (ftp://, "not a url", host-less "http://") commits
// silently and then masquerades forever as a transient observation failure,
// suppressing publishing indefinitely, and a plaintext http:// checkip-url
// would let a spoofed response control the published record (#14372). The
// scheme check is case-INSENSITIVE per RFC 3986 §3.1 ("HTTPS://host" is
// valid); it parses first and compares the parsed scheme with EqualFold,
// matching pkg/ddns.validateCheckIPURL (#2842).
func ddnsCheckIPURLValid(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}

// ddnsGenericURLTemplateValid mirrors pkg/ddns.validateGenericURLTemplate for
// the commit-time warning ONLY (config cannot import pkg/ddns). It must stay in
// sync with that validator; a divergence only affects whether the operator gets
// a warning at commit — the runtime newGenericBackend gate is authoritative and
// fails closed regardless (#2841). A generic url-template must be a
// case-INSENSITIVE http(s) URL (RFC 3986 §3.1) with a host; without this warning
// a malformed template (no host / wrong scheme) commits silently and then fails
// only at the first publish. It is deliberately TEMPLATE-AWARE and string-based,
// NOT net/url-based: the value carries inadyn %h/%i/%u/%p specifiers (possibly
// in the userinfo, e.g. https://user:%p@host/upd) that are not valid
// percent-encoding and would make url.Parse fail or mangle the string (same
// reason RedactURL is string-based, #2781). Only the scheme + host portion is
// checked; any %-specifier or {{...}} placeholder in userinfo/path/query is
// tolerated. The input is TrimSpace'd before validating so this stays byte-for-
// byte in lockstep with the runtime gate, which trims (newGenericBackend trims
// p.URLTemplate before constructing): a leading-whitespace template must not
// warn at commit while the runtime trims+accepts it (#2841 lockstep fold).
func ddnsGenericURLTemplateValid(tmpl string) bool {
	tmpl = strings.TrimSpace(tmpl)
	i := strings.Index(tmpl, "://")
	if i < 0 {
		return false
	}
	if scheme := tmpl[:i]; !strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https") {
		return false
	}
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
	// a non-empty authority but an EMPTY host — the old `authority != ""`
	// check let it warn-clean AND construct-clean. Kept byte-for-byte in
	// lockstep with pkg/ddns.ddnsTemplateHost (config cannot import pkg/ddns).
	host := authority
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end >= 0 {
			host = host[1:end]
		} else {
			host = ""
		}
	} else if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return host != ""
}

// ddnsAllowlistMalformedTokens mirrors pkg/ddns.ParseAllowlistChecked's
// tokenization for the commit-time warning ONLY (config cannot import pkg/ddns:
// pkg/ddns imports pkg/config). It returns the comma/space/tab-separated tokens
// that are not valid IP addresses. It must stay in sync with the splitter in
// ddns.ParseAllowlistChecked; a divergence only affects whether the operator
// gets a warning at commit — the runtime parse in pkg/ddns is authoritative and
// drops the same tokens (logging once per provider) regardless (#2839).
func ddnsAllowlistMalformedTokens(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var bad []string
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	for _, f := range fields {
		tok := strings.TrimSpace(f)
		if tok == "" {
			continue
		}
		if _, err := netip.ParseAddr(tok); err != nil {
			bad = append(bad, tok)
		}
	}
	return bad
}

// validateSurfaceADDNSWarnings emits WARN-only commit-time messages for the
// Surface A router/interface-address DDNS bindings + provider catalog (#2691
// P2). It never returns an error: the typed schema already accepts the leaves,
// and a hard reject would brick a boot on a previously-inert misconfig. The
// engine degrades safely at runtime (an unresolved provider / missing hostname
// scope resolves to a no-op).
func validateSurfaceADDNSWarnings(cfg *Config) []string {
	var warnings []string

	var catalog map[string]*DDNSProvider
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		catalog = cfg.System.Services.DynamicDNS.Providers
	}

	// Provider-catalog completeness (rfc2136 backend).
	for name, p := range catalog {
		if p == nil {
			continue
		}
		backend := p.Backend
		if backend == "" {
			backend = "rfc2136"
		}
		switch backend {
		case "rfc2136":
			if p.UpdateServer == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend rfc2136) has no update-server; scopes using it "+
					"publish nothing until an update-server is set", name))
			} else if !ddnsUpdateServerParseable(p.UpdateServer) {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q update-server %q is not a valid host or host:port", name, p.UpdateServer))
			}
			// #4483: an update-server with NO tsig-key sends unsigned UPDATEs
			// and trusts an unauthenticated, forgeable response rcode (spoofed
			// NOERROR → silent blackhole; spoofed REFUSED → suppressed publish).
			// WARN-only; the fix is tsig-key/tsig-secret (exchange then
			// requires a TSIG-signed response and miekg verifies its MAC, #14603).
			if p.UpdateServer != "" && p.TSIGKeyName == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend rfc2136) has an update-server but no tsig-key; "+
					"DNS UPDATEs are sent unsigned and the server's response rcode is "+
					"unauthenticated and forgeable — a spoofed NOERROR can record a name "+
					"as published though nothing was written (silent blackhole) and a "+
					"spoofed REFUSED can suppress a legitimate publish. Set tsig-key/"+
					"tsig-secret to authenticate updates", name))
			}
			keySet := p.TSIGKeyName != ""
			secretSet := p.TSIGSecret.Reveal() != ""
			switch {
			case keySet && secretSet && !ddnsTSIGAlgorithmSupported(p.TSIGAlgorithm):
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-algorithm %q is not supported (use hmac-sha1/224/256/"+
					"384/512; hmac-md5 is rejected)", name, p.TSIGAlgorithm))
			case keySet && !secretSet:
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-key is set but tsig-secret is empty; the server will "+
					"reject updates (BADKEY/BADSIG)", name))
			case secretSet && !keySet:
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q tsig-secret is set but tsig-key is empty; signing is "+
					"disabled and the secret is ignored", name))
			}
		case "dyndns2":
			// dyndns2 needs either a server or a recognizable provider name to
			// resolve the endpoint (#2691 P3). Credentials are optional (some
			// token-in-password providers leave the username empty).
			switch {
			case p.Server == "" && !ddnsKnownDyndns2Provider(name):
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend dyndns2) has no server and no recognized provider "+
					"name; scopes using it publish nothing (set `server`)", name))
			case p.Server != "" && !ddnsDyndns2ServerValid(p.Server):
				// A set `server` that is neither a valid http(s) URL nor a valid bare
				// host is a config error: an uppercase-scheme misparse or a hostless
				// value otherwise commits silently and fails only at the first publish
				// (#3737). The runtime resolver rejects it too (no-op fallback).
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend dyndns2) server %q is not a valid http(s) URL "+
					"or host; scopes using it publish nothing", name, RedactURL(p.Server)))
			}
		case "duckdns":
			// DuckDNS authenticates by TOKEN passed as a query param (#2960). The
			// token comes from the api-token leaf (reused from cloudflare); a
			// missing token publishes nothing (DuckDNS answers KO). The endpoint
			// defaults to the built-in https://www.duckdns.org/update, so `server`
			// is optional (test/mocking only).
			if p.APIToken.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend duckdns) has no api-token; scopes using it "+
					"publish nothing", name))
			}
		case "cloudflare":
			if p.APIToken.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend cloudflare) has no api-token; scopes using it publish "+
					"nothing", name))
			}
			if p.Zone == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend cloudflare) has no zone; scopes using it publish "+
					"nothing", name))
			}
		case "route53":
			if p.AWSAccessKeyID == "" || p.AWSSecretAccessKey.Reveal() == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend route53) is missing aws-access-key / aws-secret-key; "+
					"scopes using it publish nothing", name))
			}
			if p.HostedZoneID == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend route53) has no hosted-zone-id; scopes using it "+
					"publish nothing", name))
			}
		case "generic":
			if p.URLTemplate == "" {
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q (backend generic) has no url-template; scopes using it publish "+
					"nothing", name))
			} else if !ddnsGenericURLTemplateValid(p.URLTemplate) {
				// RedactURL the template: it may embed a credential in the userinfo
				// or query (%p/token=...), which must not reach a commit-warning log.
				warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
					"provider %q url-template %q is not a valid http(s) URL with a host; "+
					"scopes using it publish nothing", name, RedactURL(p.URLTemplate)))
			}
		}

		// checkip-url is a backend-independent, opt-in behind-NAT address source
		// (#2691 P3). A malformed URL is a config error, not a transient: without
		// this warning a typo commits silently and the runtime fetch fails forever,
		// masquerading as a transient observation failure that suppresses publishing
		// indefinitely (#2773). The runtime CheckIP gate fails closed regardless.
		if p.CheckIPURL != "" && !ddnsCheckIPURLValid(p.CheckIPURL) {
			// The URL is OMITTED, not redacted. A checkip-url commonly carries
			// the endpoint's API key in its userinfo, query or fragment, and a
			// commit warning is shown to the operator AND written to the log.
			// RedactURL is a best-effort string scrubber, not a parser, and it
			// misses a credential outright when the '@' is absent
			// ("https://user:s3cr3t.example/"), when the authority is
			// scheme-relative ("//user:SECRET@host/" — no "://", so its scan
			// takes the authority to be empty), and in a fragment (never
			// redacted at all). The last two PARSE cleanly, so no
			// "redact only once it parsed" gate helps. Mirrors the authoritative
			// runtime gate, pkg/ddns validateCheckIPURL; the provider name and
			// leaf name already identify the offending value.
			//
			// #8942: the three RedactURL weaknesses described above were
			// FIXED under #6609 and this comment outlived them. Measured on
			// the current implementation: "https://user:s3cr3t.example/" ->
			// "https://<redacted>/" (missing-'@' credential in the host
			// slot), "//user:SECRET@host/" -> "//<redacted>@host/"
			// (scheme-relative authority), and
			// "https://host/p#token=SECRET" -> "https://host/p#<redacted>"
			// (fragment with no query to swallow it). This gate still does
			// not DEPEND on RedactURL either way, which is why the paragraph
			// is kept — but it no longer describes a live gap.
			warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
				"provider %q checkip-url is not a valid https URL with a host; "+
				"scopes using address-source checkip publish nothing", name))
		}

		// checkip-allowlist is a bogus-IP safety gate: each entry is an address
		// the checkip parser may accept even though it is otherwise special-purpose
		// (anycast resolvers, etc.). A malformed token (operator typo, e.g.
		// "8.8.8.8x") is otherwise SILENTLY DROPPED by ddns.ParseAllowlist, so the
		// gate silently shrinks and the checkip parser admits the very IP the
		// operator meant to suppress (#2839). Surface the offending tokens at
		// commit; the runtime allowlist parse mirrors this and fails lenient (it
		// logs once per provider and keeps the valid entries). Parsing is mirrored
		// here (not via pkg/ddns) because pkg/ddns imports pkg/config.
		for _, tok := range ddnsAllowlistMalformedTokens(p.CheckIPAllowlist) {
			warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
				"provider %q checkip-allowlist entry %q is not a valid IP address; "+
				"it is ignored, shrinking the bogus-IP allowlist", name, tok))
		}
	}

	// Per-interface binding completeness.
	//
	// duckFamilies tracks, per (provider, FQDN) that resolves to a DuckDNS
	// backend, which address families are bound — to warn about the DuckDNS
	// per-family clobber (#2960). DuckDNS's update API auto-detects and SETS the
	// family whose address parameter is OMITTED ("If you do not specify the IP
	// address, then it will be detected" — duckdns.org/spec.jsp). A Surface A v6
	// scope therefore sends only ipv6= and DuckDNS auto-sets the A from the
	// source IPv4 — overwriting the A the separate v4 scope publishes. Because
	// Surface A scopes are per-family with NO per-FQDN coalescing, a dual-stack
	// DuckDNS name has two scopes that fight on every reconcile (and with
	// source-binding/multi-WAN/NAT the auto-detected A diverges from the
	// configured one). One family per DuckDNS name is the supported topology.
	type duckKey struct{ provider, fqdn string }
	duckFamilies := map[duckKey][]string{}
	isDuckDNS := func(provider string) bool {
		if provider == "" || catalog == nil {
			return false
		}
		p, ok := catalog[provider]
		return ok && p != nil && p.Backend == "duckdns"
	}
	// #3738: dyndns2 has only a HOSTNAME-level withdraw verb (offline=YES takes
	// down BOTH the A and the AAAA). Unlike DuckDNS its per-family UPDATE is fine
	// (myip= sets one family without auto-detecting the other), so the fight is
	// only on WITHDRAW. Track dyndns2 (provider, FQDN) bindings per family so a
	// dual-stack same-name dyndns2 scope is flagged too (DuckDNS was already
	// commit-warned; dyndns2 was not — the codex-157 M06 gap).
	dyndns2Families := map[duckKey][]string{}
	isDyndns2 := func(provider string) bool {
		if provider == "" || catalog == nil {
			return false
		}
		p, ok := catalog[provider]
		return ok && p != nil && p.Backend == "dyndns2"
	}
	if cfg.Interfaces.Interfaces != nil {
		ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
		for n := range cfg.Interfaces.Interfaces {
			ifNames = append(ifNames, n)
		}
		sort.Strings(ifNames)
		for _, ifName := range ifNames {
			ifc := cfg.Interfaces.Interfaces[ifName]
			if ifc == nil {
				continue
			}
			unitNums := make([]int, 0, len(ifc.Units))
			for un := range ifc.Units {
				unitNums = append(unitNums, un)
			}
			sort.Ints(unitNums)
			for _, un := range unitNums {
				unit := ifc.Units[un]
				if unit == nil {
					continue
				}
				check := func(family string, d *InterfaceDynamicDNSConfig) {
					if d == nil {
						return
					}
					loc := fmt.Sprintf("interfaces %s unit %d family %s dynamic-dns", ifName, un, family)
					if d.Hostname == "" {
						warnings = append(warnings, loc+": no hostname is set; nothing will be published")
					}
					if d.Provider == "" {
						warnings = append(warnings, loc+": no provider is set; nothing will be published")
					} else if catalog == nil {
						warnings = append(warnings, fmt.Sprintf("%s references provider %q but no "+
							"`system services dynamic-dns provider` catalog is configured", loc, d.Provider))
					} else if _, ok := catalog[d.Provider]; !ok {
						warnings = append(warnings, fmt.Sprintf("%s references undefined provider %q "+
							"(define it under system services dynamic-dns provider)", loc, d.Provider))
					}
					// #4423 H08: a binding that selects `address-source checkip` needs
					// its provider to carry a checkip-url. Without one the runtime fails
					// CLOSED and publishes NOTHING for this scope — it does NOT fall back
					// to the interface address (that silent fallback published the WRONG
					// address for a behind-NAT / multi-WAN router). Warn at commit so the
					// operator is not surprised by a scope that never publishes.
					if d.AddressSource == "checkip" && d.Provider != "" && catalog != nil {
						if p, ok := catalog[d.Provider]; ok && p != nil && p.CheckIPURL == "" {
							warnings = append(warnings, fmt.Sprintf("%s selects address-source "+
								"checkip but provider %q has no checkip-url; this scope publishes "+
								"nothing (it will NOT fall back to the interface address)", loc, d.Provider))
						}
					}
					// #2960: record DuckDNS (provider, FQDN) bindings per family so a
					// dual-stack DuckDNS name (the clobber topology) is flagged below.
					if d.Hostname != "" && isDuckDNS(d.Provider) {
						k := duckKey{provider: d.Provider, fqdn: strings.ToLower(strings.TrimSuffix(d.Hostname, "."))}
						duckFamilies[k] = append(duckFamilies[k], family)
					}
					// #3738: record dyndns2 (provider, FQDN) bindings per family so a
					// dual-stack dyndns2 name (host-level offline withdraw) is flagged.
					if d.Hostname != "" && isDyndns2(d.Provider) {
						k := duckKey{provider: d.Provider, fqdn: strings.ToLower(strings.TrimSuffix(d.Hostname, "."))}
						dyndns2Families[k] = append(dyndns2Families[k], family)
					}
				}
				check("inet", unit.DynamicDNSInet)
				check("inet6", unit.DynamicDNSInet6)
			}
		}
	}

	// #2960: a single DuckDNS name bound on BOTH inet and inet6 is the per-family
	// clobber topology (the v6 scope's update auto-sets the A and vice versa).
	// Warn (not hard-reject, matching this validator's fail-open posture — a hard
	// reject could brick a boot on a previously-inert misconfig); the runtime
	// still publishes, but the operator is told the two families fight.
	duckNames := make([]duckKey, 0, len(duckFamilies))
	for k, fams := range duckFamilies {
		if hasFamily(fams, "inet") && hasFamily(fams, "inet6") {
			duckNames = append(duckNames, k)
		}
	}
	sort.Slice(duckNames, func(i, j int) bool {
		if duckNames[i].provider != duckNames[j].provider {
			return duckNames[i].provider < duckNames[j].provider
		}
		return duckNames[i].fqdn < duckNames[j].fqdn
	})
	for _, k := range duckNames {
		warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
			"provider %q (backend duckdns) hostname %q is bound on BOTH inet and "+
			"inet6: DuckDNS auto-detects and overwrites the family whose address is "+
			"omitted, so the two scopes clobber each other's A/AAAA on every "+
			"reconcile. Bind a DuckDNS name to a single family.", k.provider, k.fqdn))
	}

	// #3738: a single dyndns2 name bound on BOTH inet and inet6 shares one
	// hostname whose only withdraw verb (offline=YES) is HOST-level — it takes
	// both families down. A single-family withdraw therefore cannot be expressed
	// on the wire. The runtime now SUPPRESSES the offline while the sibling family
	// is still published (pkg/ddns backend_dyndns2 DeleteLease, #3738), so the
	// live sibling is preserved — but the withdrawn family's record is left stale
	// until the sibling is also withdrawn. Warn so the operator can prefer
	// separate hostnames per family for a clean per-family teardown.
	dyndns2Names := make([]duckKey, 0, len(dyndns2Families))
	for k, fams := range dyndns2Families {
		if hasFamily(fams, "inet") && hasFamily(fams, "inet6") {
			dyndns2Names = append(dyndns2Names, k)
		}
	}
	sort.Slice(dyndns2Names, func(i, j int) bool {
		if dyndns2Names[i].provider != dyndns2Names[j].provider {
			return dyndns2Names[i].provider < dyndns2Names[j].provider
		}
		return dyndns2Names[i].fqdn < dyndns2Names[j].fqdn
	})
	for _, k := range dyndns2Names {
		warnings = append(warnings, fmt.Sprintf("system services dynamic-dns "+
			"provider %q (backend dyndns2) hostname %q is bound on BOTH inet and "+
			"inet6: dyndns2's withdraw verb (offline=YES) is HOSTNAME-level and takes "+
			"both families down, so a single-family withdraw cannot be expressed on "+
			"the wire. xpf suppresses the offline while the sibling family is still "+
			"published (the live sibling is preserved; the withdrawn family's record "+
			"is left stale). Use separate hostnames per family for a clean per-family "+
			"teardown.", k.provider, k.fqdn))
	}
	// #4966: several loops above range over provider/family maps, so the
	// raw append order is nondeterministic run-to-run. Sort the block
	// before returning it so the surfaced commit warnings (and every
	// alarm surface that re-derives them) are stable.
	sort.Strings(warnings)
	return warnings
}

// hasFamily reports whether fams contains the given family token.
func hasFamily(fams []string, want string) bool {
	for _, f := range fams {
		if f == want {
			return true
		}
	}
	return false
}
