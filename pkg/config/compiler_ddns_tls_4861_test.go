package config

import (
	"strings"
	"testing"
)

// #4861: a credentialed HTTP DDNS backend (dyndns2 Basic auth, DuckDNS /
// Cloudflare token, Route 53 SigV4, generic with %u/%p or Basic auth) must not
// carry its update credential over a plaintext http:// endpoint. Strict (commit
// / commit-check) hard-rejects such a `server` / `url-template`; lenient (load /
// peer-sync) warns. A bare host (no scheme, composed over https) and an https://
// endpoint are accepted; a NON-credentialed backend over http is not this
// finding's concern and is not rejected here.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree).

func hasDDNSHTTPSWarning(cfg *Config, provider string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "provider \""+provider+"\"") && strings.Contains(w, "https://") {
			return true
		}
	}
	return false
}

// A credentialed dyndns2/cloudflare/route53/generic backend with a plaintext
// http:// endpoint is rejected at commit, naming the provider.
func TestDDNSCredentialedPlaintextEndpointRejected(t *testing.T) {
	cases := []struct {
		name string
		set  []string
	}{
		{"dyndns2", []string{
			"set system services dynamic-dns provider p backend dyndns2",
			"set system services dynamic-dns provider p username alice",
			"set system services dynamic-dns provider p password s3cret",
			"set system services dynamic-dns provider p server http://updates.example/nic/update",
		}},
		{"cloudflare", []string{
			"set system services dynamic-dns provider p backend cloudflare",
			"set system services dynamic-dns provider p api-token TOKEN123",
			"set system services dynamic-dns provider p zone example.net",
			"set system services dynamic-dns provider p server http://api.example",
		}},
		{"route53", []string{
			"set system services dynamic-dns provider p backend route53",
			"set system services dynamic-dns provider p aws-access-key AKIA",
			"set system services dynamic-dns provider p aws-secret-key SECRET",
			"set system services dynamic-dns provider p hosted-zone-id Z123",
			"set system services dynamic-dns provider p server http://route53.example",
		}},
		{"generic", []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "http://user:%p@host.example/upd?ip=%i"`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.set)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("%s credentialed http:// endpoint compiled without error (#4861 regression)", tc.name)
			}
			if !strings.Contains(err.Error(), "https://") || !strings.Contains(err.Error(), "provider \"p\"") {
				t.Fatalf("error should name the provider and require https, got: %v", err)
			}
		})
	}
}

// An https:// (and a bare-host) endpoint for a credentialed backend is accepted.
func TestDDNSCredentialedHTTPSEndpointAccepted(t *testing.T) {
	for _, srv := range []string{
		"https://updates.example/nic/update", // explicit https
		"updates.example",                    // bare host → composed over https
	} {
		tree := buildTree(t, []string{
			"set system services dynamic-dns provider p backend dyndns2",
			"set system services dynamic-dns provider p username alice",
			"set system services dynamic-dns provider p password s3cret",
			"set system services dynamic-dns provider p server " + srv,
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("credentialed backend with server %q should compile, got: %v", srv, err)
		}
	}
}

// A NON-credentialed generic backend over http (url-template with %i but no
// %u/%p and no username/password) is NOT this finding's concern and must still
// compile — guards against over-rejecting.
func TestDDNSNonCredentialedPlaintextAccepted(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend generic",
		`set system services dynamic-dns provider p url-template "http://host.example/upd?ip=%i"`,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("non-credentialed generic http:// template should compile, got: %v", err)
	}
}

// #5471: a generic backend whose url-template embeds a LITERAL "user:secret@"
// userinfo in the authority (no typed username/password, no %u/%p specifier)
// carries the credential just as surely as the %u/%p form. It must classify as
// credentialed so the http-vs-https gate rejects a plaintext http:// template.
// RED-on-revert: dropping the ddnsTemplateAuthorityHasUserinfo clause from
// ddnsBackendCarriesCredentials makes this compile clean — the leak passes
// commit.
func TestDDNSGenericLiteralUserinfoPlaintextRejected(t *testing.T) {
	for _, tmpl := range []string{
		"http://user:secret@host.example/upd?ip=%i", // user:pass literal
		"http://alice@host.example/upd?ip=%i",       // user-only literal
		"http://user:secret@%h/upd?ip=%i",           // host is a %h specifier
	} {
		t.Run(tmpl, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set system services dynamic-dns provider p backend generic",
				`set system services dynamic-dns provider p url-template "` + tmpl + `"`,
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("generic http:// template with literal userinfo %q compiled "+
					"without error — plaintext credential leak passes commit (#5471)", tmpl)
			}
			if !strings.Contains(err.Error(), "https://") || !strings.Contains(err.Error(), "provider \"p\"") {
				t.Fatalf("error should name the provider and require https, got: %v", err)
			}
		})
	}
}

// #5471: the SAME literal-userinfo template over https:// is encrypted and must
// compile — the gate flags only a plaintext (non-https) endpoint, so the
// credential travels under TLS. Guards against over-rejecting an https literal
// userinfo config.
func TestDDNSGenericLiteralUserinfoHTTPSAccepted(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend generic",
		`set system services dynamic-dns provider p url-template "https://user:secret@host.example/upd?ip=%i"`,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("generic https:// template with literal userinfo should compile, got: %v", err)
	}
}

// #5471: a bare '@' in the PATH or QUERY (no authority userinfo) is NOT a
// credential and must not be misclassified — an http:// template with no real
// userinfo still compiles. Mirrors the authority-bounded scan in RedactURL:
// the '@' after the first '/' or '?' is past the authority boundary.
func TestDDNSGenericAtInPathQueryNotMisclassified(t *testing.T) {
	for _, tmpl := range []string{
		"http://host.example/p@th?ip=%i", // '@' in the path
		"http://host.example/upd?x=a@b",  // '@' in the query
		"http://@host.example/upd?ip=%i", // empty userinfo (bare '@')
	} {
		t.Run(tmpl, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set system services dynamic-dns provider p backend generic",
				`set system services dynamic-dns provider p url-template "` + tmpl + `"`,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("generic http:// template %q has no authority userinfo and "+
					"must not be misclassified as credentialed, got: %v", tmpl, err)
			}
		})
	}
}

// The lenient (tolerant load / peer-sync) path WARNS instead of rejecting a
// credentialed plaintext endpoint so an already-persisted config an older
// binary accepted still boots (#1960).
func TestDDNSCredentialedPlaintextLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend dyndns2",
		"set system services dynamic-dns provider p username alice",
		"set system services dynamic-dns provider p password s3cret",
		"set system services dynamic-dns provider p server http://updates.example/nic/update",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a credentialed plaintext endpoint must NOT fail, got: %v", err)
	}
	if !hasDDNSHTTPSWarning(cfg, "p") {
		t.Fatalf("lenient load must emit an https warning, warnings=%v", cfg.Warnings)
	}
	// The provider is still materialized (the field is accepted; only the
	// warning is new) — matches the #4837 lenient discipline.
	if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil ||
		cfg.System.Services.DynamicDNS.Providers["p"] == nil {
		t.Fatalf("lenient load should still materialize the provider catalog")
	}
}

// #14372 (DR3-H5): `checkip-url` is an unauthenticated address ORACLE — a
// plaintext response is trusted as this firewall's public address and
// published as its DNS record by Surface A, even for a provider that carries
// NO update credential. The #4861 gate above therefore extends to
// checkip-url WITHOUT the credentialed-only condition: strict commit
// rejects an explicit non-https checkip-url (credentialed or not), lenient
// load warns, https / empty / bare-host checkip-urls are untouched.
func TestDDNSPlaintextCheckIPURLRejected(t *testing.T) {
	cases := []struct {
		name string
		set  []string
	}{
		{"credentialed dyndns2 + Surface A binding (fixture F-DR3-H5-1)", []string{
			"set system services dynamic-dns provider p backend dyndns2",
			"set system services dynamic-dns provider p username alice",
			"set system services dynamic-dns provider p password s3cret",
			"set system services dynamic-dns provider p server https://updates.example/nic/update",
			"set system services dynamic-dns provider p checkip-url http://checkip.example/",
			"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns provider p",
			"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns hostname wan.example.net",
			"set interfaces ge-0-0-2 unit 50 family inet dynamic-dns address-source checkip",
		}},
		{"non-credentialed dyndns2 (proves no credential gate)", []string{
			"set system services dynamic-dns provider p backend dyndns2",
			"set system services dynamic-dns provider p server https://updates.example/nic/update",
			"set system services dynamic-dns provider p checkip-url http://checkip.example/",
		}},
		{"credentialed endpoint stays https, only checkip-url is http", []string{
			"set system services dynamic-dns provider p backend cloudflare",
			"set system services dynamic-dns provider p api-token TOKEN123",
			"set system services dynamic-dns provider p zone example.net",
			"set system services dynamic-dns provider p server https://api.example",
			"set system services dynamic-dns provider p checkip-url HTTP://checkip.example/",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.set)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("plaintext checkip-url compiled without error (#14372: a spoofed " +
					"checkip response would control the published DNS record)")
			}
			if !strings.Contains(err.Error(), "checkip-url") || !strings.Contains(err.Error(), "https://") {
				t.Fatalf("error should name checkip-url and require https, got: %v", err)
			}
			if strings.Contains(err.Error(), "update credential in cleartext") {
				t.Fatalf("checkip-url refusal must not claim an update-credential leak, got: %v", err)
			}
		})
	}
}

// #14372: an https (or empty / bare-host) checkip-url must NOT be flagged —
// the gate flags only an explicit non-https scheme.
func TestDDNSHTTPSCheckIPURLAccepted(t *testing.T) {
	for _, url := range []string{"https://checkip.example/", "HTTPS://checkip.example/", "checkip.example"} {
		t.Run(url, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set system services dynamic-dns provider p backend dyndns2",
				"set system services dynamic-dns provider p server https://updates.example/nic/update",
				"set system services dynamic-dns provider p checkip-url " + url,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("checkip-url %q should compile, got: %v", url, err)
			}
		})
	}
}

// #14372: lenient load of a plaintext checkip-url WARNS (naming checkip-url)
// instead of rejecting, so a persisted config still boots (#1960); the
// runtime CheckIP https backstop then publishes nothing for the scope.
func TestDDNSPlaintextCheckIPURLLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend dyndns2",
		"set system services dynamic-dns provider p server https://updates.example/nic/update",
		"set system services dynamic-dns provider p checkip-url http://checkip.example/",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a plaintext checkip-url must NOT fail, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "checkip-url") && strings.Contains(w, "https://") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient load must warn naming checkip-url + https, warnings=%v", cfg.Warnings)
	}
	if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil ||
		cfg.System.Services.DynamicDNS.Providers["p"] == nil {
		t.Fatalf("lenient load should still materialize the provider catalog")
	}
}
