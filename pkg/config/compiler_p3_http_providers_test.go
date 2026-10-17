package config

import (
	"strings"
	"testing"
)

// compiler_p3_http_providers_test.go: #2691 P3 — the dyndns2 / cloudflare /
// route53 / generic provider backends compile their per-backend leaves
// (credentials config.Secret-redacted) from the flat-set spelling, and the
// commit-time warn-validation flags an incomplete HTTP provider. Fail-on-revert.

func TestP3HTTPProvidersCompile(t *testing.T) {
	tree := buildTree(t, []string{
		// duckdns is its OWN backend (#2960), not a dyndns2 alias: token via
		// api-token (query-param auth), not username/password Basic.
		"set system services dynamic-dns provider duckdns backend duckdns",
		"set system services dynamic-dns provider duckdns api-token tok-secret-a",
		// cloudflare.
		"set system services dynamic-dns provider cf backend cloudflare",
		"set system services dynamic-dns provider cf api-token cf-secret-b",
		"set system services dynamic-dns provider cf zone example.net",
		// route53.
		"set system services dynamic-dns provider aws backend route53",
		"set system services dynamic-dns provider aws aws-access-key AKID",
		"set system services dynamic-dns provider aws aws-secret-key aws-secret-c",
		"set system services dynamic-dns provider aws aws-region us-west-2",
		"set system services dynamic-dns provider aws hosted-zone-id Z123ABC",
		// generic templated + checkip.
		"set system services dynamic-dns provider tmpl backend generic",
		`set system services dynamic-dns provider tmpl url-template "https://dns.example/upd?h=%h&i=%i"`,
		"set system services dynamic-dns provider tmpl ok-response good",
		"set system services dynamic-dns provider tmpl checkip-url https://checkip.example/",
		"set system services dynamic-dns provider tmpl checkip-allowlist 1.1.1.1,8.8.8.8",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cat := cfg.System.Services.DynamicDNS
	if cat == nil {
		t.Fatal("provider catalog did not compile")
	}

	dd := cat.Providers["duckdns"]
	if dd == nil || dd.Backend != "duckdns" || dd.APIToken != "tok-secret-a" {
		t.Fatalf("duckdns provider mismatch: %+v", dd)
	}
	cf := cat.Providers["cf"]
	if cf == nil || cf.Backend != "cloudflare" || cf.APIToken != "cf-secret-b" || cf.Zone != "example.net" {
		t.Fatalf("cf provider mismatch: %+v", cf)
	}
	aws := cat.Providers["aws"]
	if aws == nil || aws.Backend != "route53" || aws.AWSAccessKeyID != "AKID" ||
		aws.AWSSecretAccessKey != "aws-secret-c" || aws.AWSRegion != "us-west-2" || aws.HostedZoneID != "Z123ABC" {
		t.Fatalf("aws provider mismatch: %+v", aws)
	}
	tmpl := cat.Providers["tmpl"]
	if tmpl == nil || tmpl.Backend != "generic" ||
		tmpl.URLTemplate != "https://dns.example/upd?h=%h&i=%i" || tmpl.OKResponse != "good" ||
		tmpl.CheckIPURL != "https://checkip.example/" || tmpl.CheckIPAllowlist != "1.1.1.1,8.8.8.8" {
		t.Fatalf("tmpl provider mismatch: %+v", tmpl)
	}

	// Every secret must be redacted in String() (logging hygiene; plan §8.1).
	for _, p := range []*DDNSProvider{cf, aws, dd} {
		s := p.String()
		for _, secret := range []string{"cf-secret-b", "aws-secret-c", "tok-secret-a"} {
			if strings.Contains(s, secret) {
				t.Fatalf("provider %q String() leaked a secret: %s", p.Name, s)
			}
		}
	}
}

func TestP3HTTPProviderHierarchicalCompiles(t *testing.T) {
	// The brace form must compile identically to flat-set.
	const cfgText = `system {
  services {
    dynamic-dns {
      provider cf {
        backend cloudflare;
        api-token cf-secret-b;
        zone example.net;
      }
    }
  }
}`
	tree, perr := NewParser(cfgText).Parse()
	if len(perr) != 0 {
		t.Fatalf("Parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cf := cfg.System.Services.DynamicDNS.Providers["cf"]
	if cf == nil || cf.Backend != "cloudflare" || cf.APIToken != "cf-secret-b" || cf.Zone != "example.net" {
		t.Fatalf("hierarchical cf provider mismatch: %+v", cf)
	}
}

func TestP3IncompleteHTTPProviderWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider cf backend cloudflare", // no api-token, no zone
		"set system services dynamic-dns provider aws backend route53",   // no keys/zone-id
		"set system services dynamic-dns provider g backend generic",     // no url-template
		"set system services dynamic-dns provider duck backend duckdns",  // no api-token (#2960)
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")
	for _, want := range []string{"no api-token", "no zone", "aws-access-key", "no hosted-zone-id", "no url-template", "(backend duckdns) has no api-token"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a warning containing %q; got:\n%s", want, joined)
		}
	}
}

// TestDuckDNSDualStackNameWarns is the #2960 fail-on-revert gate for the DuckDNS
// per-family clobber: a single DuckDNS name bound on BOTH inet and inet6 must
// warn at commit (DuckDNS auto-detects and overwrites the family whose address
// is omitted, so the two per-family Surface A scopes clobber each other's
// A/AAAA on every reconcile). RED without the cross-family detection in
// validateSurfaceADDNSWarnings. A single-family DuckDNS name, and a dual-stack
// name on a DIFFERENT (non-duckdns) backend, must NOT warn — no false positives.
func TestDuckDNSDualStackNameWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider duck backend duckdns",
		"set system services dynamic-dns provider duck api-token tok-secret",
		// DUAL-STACK on the SAME duckdns name → must warn (the clobber topology).
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider duck",
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname home.duckdns.org",
		"set interfaces ge-0-0-2 unit 0 family inet6 dynamic-dns provider duck",
		"set interfaces ge-0-0-2 unit 0 family inet6 dynamic-dns hostname home.duckdns.org",
		// SINGLE-FAMILY duckdns name → must NOT warn.
		"set interfaces ge-0-0-2 unit 1 family inet dynamic-dns provider duck",
		"set interfaces ge-0-0-2 unit 1 family inet dynamic-dns hostname v4only.duckdns.org",
		// A dual-stack name on a NON-duckdns backend → must NOT warn (cloudflare
		// has a real per-family API; only duckdns has the clobber).
		"set system services dynamic-dns provider cf backend cloudflare",
		"set system services dynamic-dns provider cf api-token cf-secret",
		"set system services dynamic-dns provider cf zone example.net",
		"set interfaces ge-0-0-2 unit 2 family inet dynamic-dns provider cf",
		"set interfaces ge-0-0-2 unit 2 family inet dynamic-dns hostname dual.example.net",
		"set interfaces ge-0-0-2 unit 2 family inet6 dynamic-dns provider cf",
		"set interfaces ge-0-0-2 unit 2 family inet6 dynamic-dns hostname dual.example.net",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	if !strings.Contains(joined, `provider "duck" (backend duckdns) hostname "home.duckdns.org" is bound on BOTH inet and inet6`) {
		t.Fatalf("expected a DuckDNS dual-stack clobber warning for home.duckdns.org; got:\n%s", joined)
	}
	// No false positives: the single-family duckdns name and the dual-stack
	// cloudflare name must NOT be warned about.
	if strings.Contains(joined, "v4only.duckdns.org") {
		t.Fatalf("single-family duckdns name must NOT warn; got:\n%s", joined)
	}
	if strings.Contains(joined, "dual.example.net") {
		t.Fatalf("dual-stack name on a non-duckdns backend must NOT warn; got:\n%s", joined)
	}
}

// TestDyndns2DualStackNameWarns is the #3738 fail-on-revert gate for the dyndns2
// host-level withdraw: a single dyndns2 name bound on BOTH inet and inet6 must
// warn at commit, because dyndns2's only withdraw verb (offline=YES) is
// HOSTNAME-level — it takes both families down, so a single-family withdraw
// cannot be expressed on the wire (the runtime now suppresses the offline while
// the sibling is live, preserving it). RED without the dyndns2 cross-family
// detection in validateSurfaceADDNSWarnings. A single-family dyndns2 name, and a
// dual-stack name on a per-family backend (cloudflare), must NOT warn.
func TestDyndns2DualStackNameWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider dd2 backend dyndns2",
		"set system services dynamic-dns provider dd2 server https://dyn.example.net/nic/update",
		"set system services dynamic-dns provider dd2 username u",
		"set system services dynamic-dns provider dd2 password p",
		// DUAL-STACK on the SAME dyndns2 name → must warn (host-level offline).
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider dd2",
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
		"set interfaces ge-0-0-2 unit 0 family inet6 dynamic-dns provider dd2",
		"set interfaces ge-0-0-2 unit 0 family inet6 dynamic-dns hostname wan.example.net",
		// SINGLE-FAMILY dyndns2 name → must NOT warn.
		"set interfaces ge-0-0-2 unit 1 family inet dynamic-dns provider dd2",
		"set interfaces ge-0-0-2 unit 1 family inet dynamic-dns hostname v4only.example.net",
		// A dual-stack name on a per-family backend → must NOT warn (cloudflare).
		"set system services dynamic-dns provider cf backend cloudflare",
		"set system services dynamic-dns provider cf api-token cf-secret",
		"set system services dynamic-dns provider cf zone example.net",
		"set interfaces ge-0-0-2 unit 2 family inet dynamic-dns provider cf",
		"set interfaces ge-0-0-2 unit 2 family inet dynamic-dns hostname dual.example.net",
		"set interfaces ge-0-0-2 unit 2 family inet6 dynamic-dns provider cf",
		"set interfaces ge-0-0-2 unit 2 family inet6 dynamic-dns hostname dual.example.net",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	if !strings.Contains(joined, `provider "dd2" (backend dyndns2) hostname "wan.example.net" is bound on BOTH inet and inet6`) {
		t.Fatalf("expected a dyndns2 dual-stack withdraw warning for wan.example.net; got:\n%s", joined)
	}
	if !strings.Contains(joined, "offline=YES") {
		t.Fatalf("dyndns2 dual-stack warning should name the offline=YES host-level verb; got:\n%s", joined)
	}
	// No false positives.
	if strings.Contains(joined, "v4only.example.net") {
		t.Fatalf("single-family dyndns2 name must NOT warn; got:\n%s", joined)
	}
	if strings.Contains(joined, "dual.example.net") {
		t.Fatalf("dual-stack name on a per-family (cloudflare) backend must NOT warn; got:\n%s", joined)
	}
}

// TestP3CheckIPURLMalformedWarns is the #2773 fail-on-revert gate for the
// WARNING layer: a malformed checkip-url must be flagged at commit (was dead
// code — validateCheckIPURL had no callers, so a typo committed silently and
// then masqueraded forever as a transient observation failure that suppressed
// publishing). Goes GREEN with the validateSurfaceADDNSWarnings wiring and
// RED if that wiring is removed. The valid-URL providers in the same config
// must NOT warn (no false positives).
//
// Since #14372 the STRICT gate (ddnsPlaintextCredentialEndpoint) hard-rejects
// an explicit non-https checkip-url, so this warning-layer fixture compiles
// LENIENT (where the strict gate degrades to a warning) and then exercises
// validateSurfaceADDNSWarnings directly — the two layers are distinct: the
// strict gate owns the scheme refusal, this pass owns malformed shapes on a
// lenient-loaded catalog.
func TestP3CheckIPURLMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		// Malformed checkip-urls that http.NewRequest would otherwise accept and
		// then fail to fetch forever.
		"set system services dynamic-dns provider bad-scheme backend dyndns2",
		"set system services dynamic-dns provider bad-scheme server dyn.example",
		"set system services dynamic-dns provider bad-scheme checkip-url ftp://checkip.example/",
		"set system services dynamic-dns provider no-host backend dyndns2",
		"set system services dynamic-dns provider no-host server dyn.example",
		"set system services dynamic-dns provider no-host checkip-url http://",
		"set system services dynamic-dns provider junk backend dyndns2",
		"set system services dynamic-dns provider junk server dyn.example",
		`set system services dynamic-dns provider junk checkip-url "not a url"`,
		// A valid checkip-url must NOT warn.
		"set system services dynamic-dns provider good backend dyndns2",
		"set system services dynamic-dns provider good server dyn.example",
		"set system services dynamic-dns provider good checkip-url https://checkip.example/",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	for _, badName := range []string{"bad-scheme", "no-host", "junk"} {
		want := "provider \"" + badName + "\" checkip-url"
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a checkip-url warning for provider %q; got:\n%s", badName, joined)
		}
	}
	if strings.Contains(joined, "provider \"good\" checkip-url") {
		t.Fatalf("valid checkip-url should not warn; got:\n%s", joined)
	}
}

// TestP3CheckIPAllowlistMalformedWarns is the #2839 fail-on-revert gate: a
// malformed checkip-allowlist token (operator typo, e.g. "8.8.8.8x") was
// SILENTLY DROPPED by ddns.ParseAllowlist, so the bogus-IP safety gate silently
// shrank and the checkip parser admitted the very IP the operator meant to
// suppress. The commit-time warn pass must now name the offending token. Goes
// RED if ddnsAllowlistMalformedTokens / its wiring is removed (back to silent
// drop). The valid-token provider in the same config must NOT warn.
func TestP3CheckIPAllowlistMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider bad backend dyndns2",
		"set system services dynamic-dns provider bad server dyn.example",
		"set system services dynamic-dns provider bad checkip-url https://checkip.example/",
		// A typoed v4 token + a bare word; the valid 1.1.1.1 is retained.
		"set system services dynamic-dns provider bad checkip-allowlist 1.1.1.1,8.8.8.8x",
		// A provider whose allowlist is entirely valid must NOT warn.
		"set system services dynamic-dns provider good backend dyndns2",
		"set system services dynamic-dns provider good server dyn.example",
		"set system services dynamic-dns provider good checkip-url https://checkip.example/",
		"set system services dynamic-dns provider good checkip-allowlist 1.1.1.1,2606:4700::1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	// The offending token must be NAMED for provider "bad".
	for _, want := range []string{
		"provider \"bad\" checkip-allowlist",
		"8.8.8.8x",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a checkip-allowlist warning containing %q; got:\n%s", want, joined)
		}
	}
	// The valid v4 token in the same "bad" allowlist must not be flagged.
	if strings.Contains(joined, "entry \"1.1.1.1\"") {
		t.Fatalf("valid allowlist token 1.1.1.1 must not warn; got:\n%s", joined)
	}
	// Provider "good" (all valid) must not warn.
	if strings.Contains(joined, "provider \"good\" checkip-allowlist") {
		t.Fatalf("valid checkip-allowlist should not warn; got:\n%s", joined)
	}
}

// TestP3CheckIPURLUppercaseSchemeAccepted is the #2842 fail-on-revert gate: a
// checkip-url with an uppercase/mixed-case HTTPS scheme is valid per RFC 3986
// §3.1 (the scheme is case-INSENSITIVE) and must NOT warn. Goes RED if the mirror
// ddnsCheckIPURLValid reverts to a case-sensitive HasPrefix on the raw string.
// (Uppercase HTTP is plaintext and is now refused by the strict #14372 gate,
// so this warning-layer fixture compiles lenient and keeps only the https
// case in the accepted set.)
func TestP3CheckIPURLUppercaseSchemeAccepted(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider mixed-https backend dyndns2",
		"set system services dynamic-dns provider mixed-https server dyn.example",
		"set system services dynamic-dns provider mixed-https checkip-url Https://h/",
		// A non-https scheme and a host-less URL must STILL warn (no over-accept).
		"set system services dynamic-dns provider bad-scheme backend dyndns2",
		"set system services dynamic-dns provider bad-scheme server dyn.example",
		"set system services dynamic-dns provider bad-scheme checkip-url ftp://checkip.example/",
		"set system services dynamic-dns provider no-host backend dyndns2",
		"set system services dynamic-dns provider no-host server dyn.example",
		"set system services dynamic-dns provider no-host checkip-url https://",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")

	for _, okName := range []string{"mixed-https"} {
		if strings.Contains(joined, "provider \""+okName+"\" checkip-url") {
			t.Fatalf("uppercase-scheme checkip-url should not warn for %q; got:\n%s", okName, joined)
		}
	}
	for _, badName := range []string{"bad-scheme", "no-host"} {
		if !strings.Contains(joined, "provider \""+badName+"\" checkip-url") {
			t.Fatalf("expected a checkip-url warning for provider %q; got:\n%s", badName, joined)
		}
	}
}

// TestP3GenericURLTemplateMalformedWarns is the #2841 fail-on-revert gate: a
// generic backend's url-template was validated PREFIX-ONLY (a bare HasPrefix
// http(s):// check), so a host-less or wrong-scheme template committed silently
// and only failed at the first publish — unlike checkip-url, which parses for a
// host. This test goes RED if the ddnsGenericURLTemplateValid wiring is removed
// (back to prefix-only). It also pins the TEMPLATE-AWARE requirement: a valid
// template carrying inadyn %h/%i/%u/%p specifiers (including a credential in the
// userinfo, which makes net/url.Parse fail) must NOT be false-rejected.
func TestP3GenericURLTemplateMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		// Host-less: passes the old HasPrefix("https://") but has no host.
		"set system services dynamic-dns provider no-host backend generic",
		`set system services dynamic-dns provider no-host url-template "https:///upd?ip=%i"`,
		// Wrong scheme.
		"set system services dynamic-dns provider bad-scheme backend generic",
		`set system services dynamic-dns provider bad-scheme url-template "ftp://host/upd?ip=%i"`,
		// Garbage (no scheme at all).
		"set system services dynamic-dns provider junk backend generic",
		`set system services dynamic-dns provider junk url-template "not a url"`,
		// VALID template with inadyn %-specifiers in path/query — must NOT warn.
		"set system services dynamic-dns provider good backend generic",
		`set system services dynamic-dns provider good url-template "https://api.example.net/update?host=%h&ip=%i"`,
		// VALID template with a credential in the userinfo (%p) — net/url.Parse
		// would FAIL on the bare %p, but the template-aware validator must accept
		// it (the host is present after the '@'). Goes RED if a naive url.Parse is
		// used instead.
		"set system services dynamic-dns provider creds backend generic",
		`set system services dynamic-dns provider creds url-template "https://user:%p@api.example.net/upd?host=%h"`,
		// VALID uppercase scheme (RFC 3986 §3.1 case-insensitive).
		"set system services dynamic-dns provider up backend generic",
		`set system services dynamic-dns provider up url-template "HTTPS://api.example.net/upd?ip=%i"`,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n")

	for _, badName := range []string{"no-host", "bad-scheme", "junk"} {
		want := "provider \"" + badName + "\" url-template"
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a url-template warning for provider %q; got:\n%s", badName, joined)
		}
	}
	for _, okName := range []string{"good", "creds", "up"} {
		if strings.Contains(joined, "provider \""+okName+"\" url-template") {
			t.Fatalf("valid url-template should not warn for %q; got:\n%s", okName, joined)
		}
	}
}

// TestDDNSGenericURLTemplateValidLockstep pins the #2841 lockstep fold: the
// commit-time mirror ddnsGenericURLTemplateValid must TrimSpace the template
// before validating, exactly like the runtime gate (newGenericBackend trims
// p.URLTemplate before constructing). A leading/trailing-whitespace template
// must be judged VALID by the mirror so the config layer does not WARN on a
// template the runtime trims+accepts. Goes RED if the TrimSpace is removed from
// the mirror (the indices would slide and a leading-whitespace template would
// fail the scheme check). It is a direct mirror-function test (the set-command
// parser strips leading whitespace, so the divergence cannot be reached through
// ParseSetCommand — only by editing active.json by hand or by a future parser
// change; the byte-for-byte contract is what matters).
func TestDDNSGenericURLTemplateValidLockstep(t *testing.T) {
	valid := []string{
		"\thttps://api.example.net/upd?ip=%i", // leading tab
		"  https://api.example.net/upd",       // leading spaces
		"https://api.example.net/upd\n",       // trailing newline
		"https://user:%p@api.example.net/upd", // userinfo credential
		"HTTPS://api.example.net/upd",         // uppercase scheme
	}
	for _, tmpl := range valid {
		if !ddnsGenericURLTemplateValid(tmpl) {
			t.Errorf("ddnsGenericURLTemplateValid(%q) = false, want true (lockstep with runtime trim)", tmpl)
		}
	}
	invalid := []string{
		"   ",              // whitespace only
		"\thttps:///upd",   // trimmed but host-less
		"  ftp://host/upd", // trimmed but wrong scheme
		"https://",         // scheme only
	}
	for _, tmpl := range invalid {
		if ddnsGenericURLTemplateValid(tmpl) {
			t.Errorf("ddnsGenericURLTemplateValid(%q) = true, want false", tmpl)
		}
	}
}

// TestP3Dyndns2ServerMalformedWarns is the #3737 fail-on-revert gate for the
// dyndns2 explicit-`server` validator. A malformed server (uppercase-scheme
// misparse aside — those are VALID — a hostless URL, a wrong scheme, or a
// hostless bare value) must be flagged at commit instead of failing only at the
// first publish, the way #2841/#2842 flag the sibling backends. Goes RED if the
// `p.Server != "" && !ddnsDyndns2ServerValid` wiring is removed. Valid servers
// (a well-formed full URL, an uppercase-scheme full URL, a bare host) and a
// built-in provider NAME with no server must NOT warn (no false positives).
func TestP3Dyndns2ServerMalformedWarns(t *testing.T) {
	tree := buildTree(t, []string{
		// Malformed: hostless full URL (M05).
		"set system services dynamic-dns provider no-host backend dyndns2",
		"set system services dynamic-dns provider no-host server http://",
		// Malformed: wrong scheme.
		"set system services dynamic-dns provider bad-scheme backend dyndns2",
		"set system services dynamic-dns provider bad-scheme server ftp://host/upd",
		// Malformed: hostless bare value (port only).
		"set system services dynamic-dns provider bare-nohost backend dyndns2",
		"set system services dynamic-dns provider bare-nohost server :8080",
		// VALID: uppercase-scheme full URL is a URL per RFC 3986 §3.1 (H09) — must
		// NOT warn. RED if ddnsDyndns2ServerValid is made case-sensitive.
		"set system services dynamic-dns provider up-scheme backend dyndns2",
		"set system services dynamic-dns provider up-scheme server HTTPS://updates.example/nic/update",
		// VALID: well-formed lowercase full URL — must NOT warn.
		"set system services dynamic-dns provider full-url backend dyndns2",
		"set system services dynamic-dns provider full-url server https://members.dyndns.org/v3/update",
		// VALID: bare host — must NOT warn.
		"set system services dynamic-dns provider bare-host backend dyndns2",
		"set system services dynamic-dns provider bare-host server dyn.example",
		// VALID: built-in provider NAME with no server — must NOT warn (server branch).
		"set system services dynamic-dns provider no-ip backend dyndns2",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warns := validateSurfaceADDNSWarnings(cfg)
	joined := strings.Join(warns, "\n")

	for _, badName := range []string{"no-host", "bad-scheme", "bare-nohost"} {
		want := "provider \"" + badName + "\" (backend dyndns2) server"
		if !strings.Contains(joined, want) {
			t.Fatalf("expected a dyndns2 server warning for provider %q; got:\n%s", badName, joined)
		}
	}
	for _, okName := range []string{"up-scheme", "full-url", "bare-host", "no-ip"} {
		if strings.Contains(joined, "provider \""+okName+"\" (backend dyndns2) server") {
			t.Fatalf("valid dyndns2 server for provider %q should not warn; got:\n%s", okName, joined)
		}
	}
}

// TestDDNSDyndns2ServerValidLockstep is a direct mirror-function test for
// ddnsDyndns2ServerValid: it must TrimSpace the server before validating
// (lockstep with the runtime resolveDyndns2Endpoint, which trims p.Server) and
// judge the scheme case-insensitively. RED if the TrimSpace or the EqualFold
// scheme compare is removed from the mirror.
func TestDDNSDyndns2ServerValidLockstep(t *testing.T) {
	valid := []string{
		"",                                     // empty → handled by the "no server" branch
		"   ",                                  // whitespace only → treated as empty
		"HTTPS://updates.example/nic/update",   // uppercase scheme full URL
		"Http://updates.example/nic/update",    // mixed-case scheme full URL
		"https://members.dyndns.org/v3/update", // lowercase full URL
		"  https://host.example/upd",           // leading whitespace, trimmed
		"dyn.example",                          // bare host
		"host.example:8443",                    // bare host with port
	}
	for _, s := range valid {
		if !ddnsDyndns2ServerValid(s) {
			t.Errorf("ddnsDyndns2ServerValid(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"http://",             // scheme only, no host
		"https:///nic/update", // host-less but scheme present
		"HTTPS://",            // uppercase scheme, no host
		"ftp://host/upd",      // wrong scheme
		":8080",               // bare, no host (port only)
		"/nic/update",         // bare, path only, no host
	}
	for _, s := range invalid {
		if ddnsDyndns2ServerValid(s) {
			t.Errorf("ddnsDyndns2ServerValid(%q) = true, want false", s)
		}
	}
}
