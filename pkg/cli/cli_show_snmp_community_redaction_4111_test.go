// RED-on-revert tests for #4111: the two OPERATIONAL STATUS commands that
// render the SNMP configuration by reading the typed active config directly —
// `show system services` (showSystemServices) and `show snmp` (showSNMP) — must
// mask the secret SNMP community NAME for a VIEW-only login class (read-only /
// config-viewer / operator), exactly as the #4099/#4106 config-render show
// paths do. Both are PermView `show` commands reachable by every view-capable
// class, and both bypassed the #4106 RedactedClone path because they format the
// typed struct fields themselves. Before the fix they printed the community
// credential (a read/write SNMP secret) in cleartext.
//
// Reverting the mask makes the read-only / config-viewer / operator subtests go
// RED (the cleartext community sentinel reappears). super-user keeps cleartext
// (the #4057/#4106 console-operator allowance), so its subtest asserts the
// cleartext community IS present — a revert that redacts everyone would also be
// caught. The authorization MODE (read-only) must stay visible in every case:
// only the secret community name is masked.
package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
)

// TestShowSystemServicesSNMPCommunityRedactsPerClass pins `show system
// services` → showSystemServices(): the community name is masked for a
// VIEW-only class, cleartext for super-user, and the authorization mode
// (read-only) is always shown.
func TestShowSystemServicesSNMPCommunityRedactsPerClass(t *testing.T) {
	store := newCLISecretStore(t)
	for _, tc := range classWantsRedaction {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class, sshdStateFn: func() sysservices.SSHDState { return sysservices.SSHDRunning }}
			out := captureStdout(t, func() {
				if err := c.showSystemServices(); err != nil {
					t.Fatalf("showSystemServices(): %v", err)
				}
			})
			// The authorization mode is not a secret — it must always show.
			if !strings.Contains(out, "read-only") {
				t.Errorf("class=%q dropped the SNMP authorization mode:\n%s", tc.class, out)
			}
			if tc.redact {
				if strings.Contains(out, "CLI-LEAK-SNMP-COMMUNITY") {
					t.Errorf("class=%q LEAKED cleartext SNMP community name:\n%s", tc.class, out)
				}
				if !strings.Contains(out, config.SecretDataPlaceholder) {
					t.Errorf("class=%q missing redaction placeholder %q:\n%s",
						tc.class, config.SecretDataPlaceholder, out)
				}
			} else {
				// Privileged / unset class must still see the cleartext name.
				if !strings.Contains(out, "CLI-LEAK-SNMP-COMMUNITY") {
					t.Errorf("class=%q unexpectedly redacted the community for a privileged class:\n%s",
						tc.class, out)
				}
			}
		})
	}
}

// TestShowSNMPCommunityRedactsPerClass pins `show snmp` → showSNMP(): same
// per-class expectation as above for the standalone SNMP status render.
func TestShowSNMPCommunityRedactsPerClass(t *testing.T) {
	store := newCLISecretStore(t)
	for _, tc := range classWantsRedaction {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class}
			out := captureStdout(t, func() {
				if err := c.showSNMP(); err != nil {
					t.Fatalf("showSNMP(): %v", err)
				}
			})
			if !strings.Contains(out, "read-only") {
				t.Errorf("class=%q dropped the SNMP authorization mode:\n%s", tc.class, out)
			}
			if tc.redact {
				if strings.Contains(out, "CLI-LEAK-SNMP-COMMUNITY") {
					t.Errorf("class=%q LEAKED cleartext SNMP community name:\n%s", tc.class, out)
				}
				if !strings.Contains(out, config.SecretDataPlaceholder) {
					t.Errorf("class=%q missing redaction placeholder %q:\n%s",
						tc.class, config.SecretDataPlaceholder, out)
				}
			} else {
				if !strings.Contains(out, "CLI-LEAK-SNMP-COMMUNITY") {
					t.Errorf("class=%q unexpectedly redacted the community for a privileged class:\n%s",
						tc.class, out)
				}
			}
		})
	}
}
