package config

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/internal/ddnsplaintextvectors"
)

// ddns_plaintext_15225_test.go: #15225 A40-03 config-side fail-on-revert
// proofs. The shared table is consumed here and by pkg/ddns, so construction
// and compiler decisions are pinned to the same vectors (#17005, R4-Q40-03).
func TestDDNS15225SharedPlaintextVectors(t *testing.T) {
	for _, vector := range ddnsplaintextvectors.DDNSPlaintextVectors {
		tmpl := vector.Template
		p := &DDNSProvider{Backend: "generic", URLTemplate: tmpl}
		if got := DDNSCredentialBearing(p); got != vector.CredentialBearing {
			t.Errorf("DDNSCredentialBearing(%q) = %v, want %v", tmpl, got, vector.CredentialBearing)
		}
		if got := DDNSTemplateCarriesLiteralToken(tmpl); got != vector.LiteralToken {
			t.Errorf("DDNSTemplateCarriesLiteralToken(%q) = %v, want %v", tmpl, got, vector.LiteralToken)
		}

		tree := buildTree(t, []string{
			"set system services dynamic-dns provider p backend generic",
			`set system services dynamic-dns provider p url-template "` + tmpl + `"`,
		})
		plainCredential := strings.HasPrefix(tmpl, "http://") && vector.CredentialBearing
		if _, err := CompileConfig(tree); plainCredential && err == nil {
			t.Errorf("strict must reject generic http template %q", tmpl)
		} else if !plainCredential && err != nil {
			t.Errorf("strict must accept control template %q: %v", tmpl, err)
		}
		if plainCredential {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Errorf("lenient %q: %v", tmpl, err)
			} else if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
				if _, ok := cfg.System.Services.DynamicDNS.Providers["p"]; ok {
					t.Errorf("lenient must drop generic http provider %q", tmpl)
				}
			}
		}
	}
}
