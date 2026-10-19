package config

import "testing"

// ddns_plaintext_15225_test.go: #15225 A40-03 config-side fail-on-revert
// proofs. The generic http:// gate previously recognised only a fixed
// credential key-name list; pass=/key=/api-token=/pwd=/p= (and any other
// literal query value) compiled clean and shipped in cleartext. The fix
// makes ANY literal query value (or userinfo) on a generic template count
// as credential-carrying, so strict commit rejects and lenient load drops
// every probe below, while placeholder-only / value-less / https and
// loopback-shaped templates are untouched by the detector itself.
//
// RED-on-revert: restore the fixed key-name list and the strict compiles
// below succeed.

func TestDDNS15225StrictRejectsAnyLiteralQueryValue(t *testing.T) {
	probes := []string{
		"http://host.example/upd?pass=LITERALPW",
		"http://host.example/upd?key=LITERALKEY",
		"http://host.example/upd?api-token=LITERALTOK",
		"http://host.example/upd?pwd=LITERALPW",
		"http://host.example/upd?p=LITERALP",
		"http://host.example/upd?foo=LITERALBAR",
	}
	for _, tmpl := range probes {
		tree := buildTree(t, []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "` + tmpl + `"`,
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("strict must reject generic http template %q (literal query value in cleartext)", tmpl)
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
	// Controls: placeholder-only, value-less flag, bare path segment, https.
	for _, tmpl := range []string{
		"http://host.example/upd?ip=%i&hostname=%h",
		"http://host.example/upd?flag&ip=%i",
		"http://host.example/update/SECRET",
		"https://host.example/upd?token=LITERALTOKEN",
	} {
		p := &DDNSProvider{Backend: "generic", URLTemplate: tmpl}
		want := tmpl == "https://host.example/upd?token=LITERALTOKEN"
		if got := ddnsBackendCarriesCredentials(p); got != want {
			t.Fatalf("ddnsBackendCarriesCredentials(%q) = %v, want %v", tmpl, got, want)
		}
	}
}
