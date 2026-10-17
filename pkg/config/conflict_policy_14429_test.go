package config

import (
	"strings"
	"testing"
)

// #14429: a garbage conflict-policy must be warned at commit (ValidateConfig)
// so a leniently-loaded typo is visible; the runtime backend refuses the ADD.
func TestDHCPDDNSGarbageConflictPolicyWarns14429(t *testing.T) {
	for _, bad := range []string{"skip-existng", "none"} {
		t.Run(bad, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set system services dhcp-local-server dynamic-dns enable",
				"set system services dhcp-local-server dynamic-dns domain corp.example.com",
				"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
				"set system services dhcp-local-server dynamic-dns conflict-policy " + bad,
			}))
			if err != nil {
				t.Fatalf("lenient compile must not brick: %v", err)
			}
			found := false
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "conflict-policy") && strings.Contains(w, bad) {
					found = true
				}
			}
			if !found {
				t.Fatalf("garbage conflict-policy %q must warn at commit; warnings=%v", bad, ValidateConfig(cfg))
			}
			// Also via cfg.Warnings on lenient path if populated.
			_ = cfg
		})
	}
	t.Run("valid policies silent", func(t *testing.T) {
		for _, good := range []string{"replace-owned", "skip-existing", "strict-fail"} {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set system services dhcp-local-server dynamic-dns enable",
				"set system services dhcp-local-server dynamic-dns domain corp.example.com",
				"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
				"set system services dhcp-local-server dynamic-dns tsig-key k",
				"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
				"set system services dhcp-local-server dynamic-dns conflict-policy " + good,
			}))
			if err != nil {
				t.Fatalf("CompileConfig(%s): %v", good, err)
			}
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "conflict-policy") {
					t.Fatalf("valid conflict-policy %q must not warn: %q", good, w)
				}
			}
		}
	})
}
