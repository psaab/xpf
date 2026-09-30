package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestShowMatchPoliciesUnzonedIngressVerdict11072 pins #11072(a): an
// unzoned-ingress query must print the unzoned verdict — never
// misattribute the deny to default-policy (the unzoned deny overrides
// default-policy, so "(default ...)" is actively wrong, including on a
// permit-all box). Mirrors the gRPC twin's UnzonedIngress arm.
func TestShowMatchPoliciesUnzonedIngressVerdict11072(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone untrust;
    }
    policies {
        default-policy permit-all;
        from-zone untrust to-zone untrust {
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
	args := []string{"from-zone", "nosuchzone", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"}
	out := captureStdout(t, func() {
		if err := c.showMatchPolicies(c.store.ActiveConfig(), args); err != nil {
			t.Fatalf("showMatchPolicies() error = %v", err)
		}
	})
	if !strings.Contains(out, "Ingress zone unknown") {
		t.Fatalf("want unzoned-ingress verdict, got:\n%s", out)
	}
	if strings.Contains(out, "(default ") {
		t.Fatalf("unzoned deny misattributed to default-policy:\n%s", out)
	}

	// CONTROL: a defined-zone query must NOT print the unzoned verdict
	// (the cell above would pass on a renderer that always prints it).
	args2 := []string{"from-zone", "untrust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"}
	out2 := captureStdout(t, func() {
		if err := c.showMatchPolicies(c.store.ActiveConfig(), args2); err != nil {
			t.Fatalf("showMatchPolicies() error = %v", err)
		}
	})
	if strings.Contains(out2, "zone unknown") {
		t.Fatalf("defined-zone query must not print an unzoned verdict:\n%s", out2)
	}
}
