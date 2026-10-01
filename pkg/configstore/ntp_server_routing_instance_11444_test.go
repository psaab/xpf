package configstore

import (
	"strings"
	"testing"
)

// TestNTPServerRoutingInstanceAdvisoryCommitCheck_11444 proves the strict
// operator check accepts the recognized per-server option but does not let it
// pass silently: chronyd has no per-source routing-instance binding, so the
// compiled warning must say that queries use the default instance.
func TestNTPServerRoutingInstanceAdvisoryCommitCheck_11444(t *testing.T) {
	for _, tc := range []struct{ name, text, server string }{
		{"flat-set", "set system ntp server 10.0.0.1 routing-instance mgmt\n", "10.0.0.1"},
		{"packed", `system { ntp { server 10.0.0.2 routing-instance mgmt; } }`, "10.0.0.2"},
		{"block", "system { ntp { server 10.0.0.3 { routing-instance mgmt; } } }", "10.0.0.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("strict CheckText rejected accepted-inert routing-instance option: %v", err)
			}
			if got := cfg.System.NTPServerOptions[tc.server].RoutingInstance; got != "mgmt" {
				t.Fatalf("compiled server %q routing-instance = %q, want mgmt", tc.server, got)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{
				"system ntp server routing-instance",
				"NOT enforced",
				"default instance",
			} {
				if !strings.Contains(warnings, want) {
					t.Errorf("strict CheckText omitted advisory %q; warnings:\n%s", want, warnings)
				}
			}
		})
	}
}
