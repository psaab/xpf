package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMatchPoliciesHostOriginated16805 pins #16805 on the local CLI surfaces
// (`show security match-policies` and `test policy`): a `from-zone junos-host`
// query must print the host-originated "not evaluated by security policy"
// verdict, never the unknown-ingress-zone deny. The `from-zone nosuch` and
// `to-zone junos-host` controls are unchanged on the show surface.
//
// FAIL-ON-REVERT: removing the policymatch host-originated arm makes the
// junos-host rows print "Ingress zone unknown"; removing a surface's
// HostOriginated branch makes it fall through to the unzoned/default render.
func TestMatchPoliciesHostOriginated16805(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}
	cfg := store.ActiveConfig()

	show := func(args []string) string {
		t.Helper()
		return captureStdout(t, func() {
			if err := c.showMatchPolicies(cfg, args); err != nil {
				t.Fatalf("showMatchPolicies() error = %v", err)
			}
		})
	}

	// Defect cell on `show security match-policies`.
	out := show([]string{"from-zone", "junos-host", "to-zone", "untrust", "protocol", "tcp", "destination-port", "53"})
	if !strings.Contains(out, "Host-originated (from-zone junos-host -> untrust): not evaluated by security policy") {
		t.Fatalf("show: want host-originated verdict, got:\n%s", out)
	}
	if strings.Contains(out, "Ingress zone unknown") || strings.Contains(out, "zone unknown") {
		t.Fatalf("show: host-originated must not print an unzoned verdict:\n%s", out)
	}

	// Defect cell on `test policy` (request surface renderer).
	outTest := captureStdout(t, func() {
		if err := c.testPolicy([]string{"from-zone", "junos-host", "to-zone", "untrust", "protocol", "tcp", "destination-port", "53"}); err != nil {
			t.Fatalf("testPolicy() error = %v", err)
		}
	})
	if !strings.Contains(outTest, "Host-originated (from-zone junos-host -> untrust): not evaluated by security policy") {
		t.Fatalf("test policy: want host-originated verdict, got:\n%s", outTest)
	}
	if strings.Contains(outTest, "Ingress zone unknown") {
		t.Fatalf("test policy: host-originated must not print an unzoned verdict:\n%s", outTest)
	}

	// Control: genuinely unknown from-zone unchanged.
	outNosuch := show([]string{"from-zone", "nosuch", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"})
	if !strings.Contains(outNosuch, "Ingress zone unknown") || strings.Contains(outNosuch, "Host-originated") {
		t.Fatalf("show: from-zone nosuch control changed:\n%s", outNosuch)
	}

	// Control: host-bound to-zone unchanged.
	outHI := show([]string{"from-zone", "trust", "to-zone", "junos-host", "protocol", "tcp", "destination-port", "22"})
	if !strings.Contains(outHI, "No matching to-zone junos-host policy") || strings.Contains(outHI, "Host-originated") {
		t.Fatalf("show: to-zone junos-host control changed:\n%s", outHI)
	}
}
