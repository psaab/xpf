package config

import "testing"

// ddns_plaintext_16573_test.go: #16573 fail-on-revert proofs (config side).
//
// The '%' specifier exclusion in ddnsTemplateCarriesLiteralToken also
// exempted percent-escaped literal values: a provider token containing
// + / = (escaped %2B/%2F/%3D) contains '%', so it was classified as a
// specifier-only value and the http:// template compiled clean, sending
// the escaped credential in cleartext (renderGenericURL transmits
// unknown %x verbatim). A percent-escaped keyless query component was
// likewise skipped because the detector only inspected '=' pairs.
//
// RED-on-revert: restore the '%'-free isLiteral predicate (and the
// '='-only query scan) and every probe below compiles / classifies false.

func TestDDNS16573StrictRejectsPercentEscapedLiteral(t *testing.T) {
	probes := []string{
		"http://host.example/upd?token=abc%2Bdef%2Fghi%3D",
		"http://host.example/upd?token=%2B%2F%3D",
		"http://host.example/upd?foo=a%2Fb",
		"http://host.example/upd?token=%41%42",
		"http://host.example/upd?token=abc%",
		"http://host.example/upd?token=abc%zz",
		"http://host.example/upd?token=%h%2B",
		"http://host.example/upd?token={{unclosed",
		"http://host.example/upd?%2B%2F%3D",
		"http://host.example/update/token=abc%2Fdef",
		// Empty key with an escaped value: the escaped-token cell, no key.
		"http://host.example/upd?=abc%2Fdef",
	}
	for _, tmpl := range probes {
		tree := buildTree(t, []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "` + tmpl + `"`,
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("strict must reject generic http template %q (percent-escaped/keyless literal in cleartext)", tmpl)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient %q: %v", tmpl, err)
		}
		if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
			if _, ok := cfg.System.Services.DynamicDNS.Providers["p"]; ok {
				t.Fatalf("lenient must DROP generic http provider %q", tmpl)
			}
		}
		p := &DDNSProvider{Backend: "generic", URLTemplate: tmpl}
		if !ddnsBackendCarriesCredentials(p) {
			t.Fatalf("ddnsBackendCarriesCredentials(%q) = false, want true", tmpl)
		}
	}
}

func TestDDNS16573SpecifierOnlyControlsAccepted(t *testing.T) {
	// Non-credential specifier-only / placeholder-only controls are not
	// credential-carrying by the literal detector.
	controls := []string{
		"http://host.example/upd?host=%h&ip=%i",
		"http://host.example/upd?lit=%%",
		"http://host.example/upd?x=%h%i%%",
		"http://host.example/upd?x={{token}}",
		"http://host.example/upd?x=%h{{token}}%i",
		"http://host.example/upd?flag=&ip=%i",
		"http://host.example/upd?flag&ip=%i",
		"http://host.example/update/SECRET",
		"http://host.example/update/token=%h",
		"http://host.example/upd?ip=%i&",
	}
	for _, tmpl := range controls {
		p := &DDNSProvider{Backend: "generic", URLTemplate: tmpl}
		if got := ddnsBackendCarriesCredentials(p); got {
			t.Fatalf("ddnsBackendCarriesCredentials(%q) = %v, want false", tmpl, got)
		}
	}
	// %u/%p templates ARE credential-carrying via the specifier arm
	// (pre-existing); the https literal is credential-carrying too, but
	// the gate only refuses http, so https still compiles.
	for _, tmpl := range []string{
		"http://host.example/upd?u=%u&p=%p",
		"http://host.example/upd?x=%h%i%u%p%%",
		"https://host.example/upd?token=abc%2Fdef",
	} {
		p := &DDNSProvider{Backend: "generic", URLTemplate: tmpl}
		if got := ddnsBackendCarriesCredentials(p); !got {
			t.Fatalf("ddnsBackendCarriesCredentials(%q) = %v, want true", tmpl, got)
		}
	}
	// The pinned acceptance cell: specifier-only http compiles clean.
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend generic",
		`set system services dynamic-dns provider p url-template "http://host.example/upd?host=%h&ip=%i"`,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("specifier-only http template must compile: %v", err)
	}
}
