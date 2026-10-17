package config

import (
	"strings"
	"testing"
)

// #14386 (DR6-H2): lenient compile must DROP a credentialed provider over
// plaintext http:// instead of warn-and-keep, and the widened detector must
// strict-reject dyndns2 server userinfo + generic literal-token http://.

func TestDDNS14386LenientDropsCredentialedPlaintext(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dynamic-dns provider p backend dyndns2",
		"set system services dynamic-dns provider p username bob",
		"set system services dynamic-dns provider p password s3cr3t-value",
		"set system services dynamic-dns provider p server http://ddns.example.invalid/nic/update",
		"set system services dynamic-dns provider q backend dyndns2",
		"set system services dynamic-dns provider q username alice",
		"set system services dynamic-dns provider q password s3cret",
		"set system services dynamic-dns provider q server https://updates.example/nic/update",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must not fail: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.DynamicDNS == nil {
		t.Fatal("catalog missing")
	}
	if _, ok := cfg.System.Services.DynamicDNS.Providers["p"]; ok {
		t.Fatal("provider p should be DROPPED on lenient")
	}
	if _, ok := cfg.System.Services.DynamicDNS.Providers["q"]; !ok {
		t.Fatal("provider q (https) should be kept")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `provider "p"`) && strings.Contains(w, "dropped") {
			found = true
		}
		if strings.Contains(w, "s3cr3t-value") {
			t.Fatalf("warning leaks credential: %q", w)
		}
	}
	if !found {
		t.Fatalf("warning must state drop, warnings=%v", cfg.Warnings)
	}
}

func TestDDNS14386StrictRejectsWidenedForms(t *testing.T) {
	cases := []struct {
		name string
		set  []string
	}{
		{"dyndns2-userinfo", []string{
			"set system services dynamic-dns provider p backend dyndns2",
			`set system services dynamic-dns provider p server "http://user:pass@host.example/nic/update"`,
		}},
		{"generic-literal-token-query", []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "http://host.example/update?token=LITERALTOKEN"`,
		}},
		{"generic-literal-token-path", []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "http://host.example/update/token=LITERALTOKEN"`,
		}},
		{"generic-http-template-no-typed", []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "http://ddns.example.invalid/update?hostname=%h&myip=%i&user=%u&pass=%p"`,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, tc.set)); err == nil {
				t.Fatalf("%s: strict compiled without error", tc.name)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.set))
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
				if _, ok := cfg.System.Services.DynamicDNS.Providers["p"]; ok {
					t.Fatalf("%s: lenient kept provider", tc.name)
				}
			}
		})
	}
}
