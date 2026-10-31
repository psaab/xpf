package configstore

import (
	"strings"
	"testing"
)

// TestNTPServerRoutingInstanceAdvisoryCommitCheck_11444 proves the strict
// operator check accepts the recognized per-server option and is honest about
// it: an instance chrony cannot bind to (it has one acquisition device, no
// per-source binding) must say that queries use the default instance, while
// the honoured shape (#18584) commits without that advisory.
func TestNTPServerRoutingInstanceAdvisoryCommitCheck_11444(t *testing.T) {
	// #18584: the commit-check surface (the operator's `commit check`) decides
	// like the compiler. An instance chrony cannot bind to stays advisory; a
	// lone `routing-instance mgmt` is enforced (chrony bindacqdevice vrf-mgmt)
	// and must commit WITHOUT the NOT-enforced advisory.
	for _, tc := range []struct {
		name, text, server, ri string
		warn                   bool
	}{
		{"flat-set", "set system ntp server 10.0.0.1 routing-instance nosuch\n", "10.0.0.1", "nosuch", true},
		{"packed", `system { ntp { server 10.0.0.2 routing-instance nosuch; } }`, "10.0.0.2", "nosuch", true},
		{"block", "system { ntp { server 10.0.0.3 { routing-instance nosuch; } } }", "10.0.0.3", "nosuch", true},
		{"flat-set-mgmt", "set system ntp server 10.0.0.1 routing-instance mgmt\n", "10.0.0.1", "mgmt", false},
		{"packed-mgmt", `system { ntp { server 10.0.0.2 routing-instance mgmt; } }`, "10.0.0.2", "mgmt", false},
		{"block-mgmt", "system { ntp { server 10.0.0.3 { routing-instance mgmt; } } }", "10.0.0.3", "mgmt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("strict CheckText rejected the routing-instance option: %v", err)
			}
			if got := cfg.System.NTPServerOptions[tc.server].RoutingInstance; got != tc.ri {
				t.Fatalf("compiled server %q routing-instance = %q, want %q", tc.server, got, tc.ri)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{
				"system ntp server routing-instance",
				"NOT enforced",
				"default instance",
			} {
				if got := strings.Contains(warnings, want); got != tc.warn {
					t.Errorf("advisory %q present=%v, want %v; warnings:\n%s", want, got, tc.warn, warnings)
				}
			}
		})
	}
}
