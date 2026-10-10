package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// newPolicyMatchCLIStore builds a committed store with one trust->untrust
// permit-any policy so testPolicy / showMatchPolicies reach the port parsing.
func newPolicyMatchCLIStore(t *testing.T) *CLI {
	t.Helper()
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
        from-zone trust to-zone untrust {
            policy allow-all {
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
	return &CLI{store: store}
}

// TestTestPolicyRejectsInvalidPort asserts the #3116 contract for the CLI
// `test policy` surface: a malformed or out-of-range destination-port must
// return an error instead of silently becoming the 0 unspecified value. A
// constrained term would then never match, while an unconstrained term may still
// match. A valid port and an absent port proceed without error.
//
// FAIL-ON-REVERT: restoring `dstPort, _ = strconv.Atoi(args[i])` makes "abc"
// and "70000" become 0 / a bogus value with no error, flipping the want-error
// cases red.
func TestTestPolicyRejectsInvalidPort(t *testing.T) {
	c := newPolicyMatchCLIStore(t)

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"malformed", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "abc"}, true},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "70000"}, true},
		{"valid", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "443"}, false},
		{"absent", []string{"from-zone", "trust", "to-zone", "untrust"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.testPolicy(tc.args) })
			if (err != nil) != tc.wantErr {
				t.Fatalf("testPolicy(%v) err = %v, wantErr = %v", tc.args, err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "destination-port") {
				t.Fatalf("testPolicy(%v) err = %v, want a destination-port diagnostic", tc.args, err)
			}
		})
	}
}

// TestShowMatchPoliciesRejectsInvalidPort asserts the #3116 contract for the
// CLI `show security match-policies` surface across BOTH source-port and
// destination-port inputs.
//
// FAIL-ON-REVERT: restoring the ignored-error Atoi for either port makes the
// malformed/out-of-range cases coerce to 0 with no error, flipping them red.
func TestShowMatchPoliciesRejectsInvalidPort(t *testing.T) {
	c := newPolicyMatchCLIStore(t)
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	cases := []struct {
		name    string
		args    []string
		wantErr bool
		wantTok string
	}{
		{"dst malformed", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "abc"}, true, "destination-port"},
		{"dst out of range", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "70000"}, true, "destination-port"},
		{"src malformed", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "xyz"}, true, "source-port"},
		{"src out of range", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "65536"}, true, "source-port"},
		{"dst valid", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "443"}, false, ""},
		{"src valid high bound", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "65535"}, false, ""},
		{"absent", []string{"from-zone", "trust", "to-zone", "untrust"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.showMatchPolicies(cfg, tc.args) })
			if (err != nil) != tc.wantErr {
				t.Fatalf("showMatchPolicies(%v) err = %v, wantErr = %v", tc.args, err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), tc.wantTok) {
				t.Fatalf("showMatchPolicies(%v) err = %v, want %q diagnostic", tc.args, err, tc.wantTok)
			}
		})
	}
}
