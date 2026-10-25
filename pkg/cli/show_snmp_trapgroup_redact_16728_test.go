package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16728: `show snmp` must mask the trap-group name (the v1/v2c trap
// community since #15052) per login class, like the query community.
// RED-on-revert: printing the raw map key re-leaks the canary for
// view classes.
func TestShowSNMPTrapGroupRedactsPerClass16728(t *testing.T) {
	const canary = "CLI-TRAPSECRET-16728"
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set snmp community CLI-LEAK-SNMP-COMMUNITY authorization read-only",
		"set snmp trap-group " + canary + " targets 192.0.2.10",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	for _, tc := range classWantsRedaction {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class}
			out := captureStdout(t, func() {
				if err := c.showSNMP(); err != nil {
					t.Fatalf("showSNMP(): %v", err)
				}
			})
			if !strings.Contains(out, "192.0.2.10") {
				t.Errorf("class=%q dropped trap target (over-redaction):\n%s", tc.class, out)
			}
			if tc.redact {
				if strings.Contains(out, canary) {
					t.Errorf("class=%q LEAKED trap-group community:\n%s", tc.class, out)
				}
				if !strings.Contains(out, config.SecretDataPlaceholder+": 192.0.2.10") {
					t.Errorf("class=%q missing masked trap-group line:\n%s", tc.class, out)
				}
			} else if !strings.Contains(out, canary) {
				t.Errorf("class=%q unexpectedly redacted trap-group for privileged class:\n%s", tc.class, out)
			}
		})
	}
}
