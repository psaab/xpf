package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// newSrcPortPolicyCLI builds a committed store whose only permit policy uses a
// source-port-constrained application (tcp, source-port 5000, destination-port
// 80) with a deny-all default. So a packet must match BOTH ports to be
// permitted; any other source port falls through to the default deny.
func newSrcPortPolicyCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
applications {
    application srcport-app {
        protocol tcp;
        source-port 5000;
        destination-port 80;
    }
}
security {
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-srcport {
                match { source-address any; destination-address any; application srcport-app; }
                then { permit; }
            }
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
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

// TestTestPolicySourcePort asserts the #3107 source-port plumbing AND the #3415
// fail-closed semantics for the local CLI `test policy` surface: a source-port
// token threads into policymatch.Query.SrcPort, so the verdict reflects a
// source-port-constrained policy.
//
//   - correct source-port 5000 (and dest 80) -> Policy match (permit)
//   - wrong source-port 6000                  -> Default deny
//   - absent source-port                      -> Default deny (#3415): an
//     omitted query source port fails closed against a source-port-constrained
//     app, since the runtime always carries a concrete source port and would
//     not match a packet whose source port differs from the app's `source-port`
//     (supersedes #3107's earlier "absent matches" stance).
//
// FAIL-ON-REVERT: dropping the source-port parsing / the SrcPort field on the
// Query makes SrcPort always 0 ("any port"), so the wrong-port case would
// PERMIT (overmatch) and "wrong src port" flips red. Restoring the
// `&& srcPort > 0` wildcard gate makes "absent src port" PERMIT again, flipping
// that case red.
func TestTestPolicySourcePort(t *testing.T) {
	c := newSrcPortPolicyCLI(t)

	cases := []struct {
		name      string
		args      []string
		wantMatch bool
	}{
		{
			"correct src port",
			[]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "source-port", "5000", "destination-port", "80"},
			true,
		},
		{
			"wrong src port",
			[]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "source-port", "6000", "destination-port", "80"},
			false,
		},
		{
			"absent src port",
			[]string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = c.testPolicy(tc.args) })
			if err != nil {
				t.Fatalf("testPolicy(%v) err = %v", tc.args, err)
			}
			matched := strings.Contains(out, "Policy match")
			if matched != tc.wantMatch {
				t.Fatalf("testPolicy(%v) matched = %v, want %v\noutput: %q", tc.args, matched, tc.wantMatch, out)
			}
		})
	}
}

// TestTestPolicyRejectsInvalidSourcePort asserts that a malformed or
// out-of-range source-port returns an error via the shared policymatch.ParsePort
// validator (#3116) rather than silently coercing to the 0 unspecified value;
// a source-port-constrained term then never matches, while unconstrained terms
// may still match.
//
// FAIL-ON-REVERT: removing the ParsePort call on source-port makes "abc" /
// "70000" coerce silently, flipping the want-error cases red.
func TestTestPolicyRejectsInvalidSourcePort(t *testing.T) {
	c := newSrcPortPolicyCLI(t)

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"malformed", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "abc"}, true},
		{"out of range", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "70000"}, true},
		{"negative", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "-1"}, true},
		{"valid", []string{"from-zone", "trust", "to-zone", "untrust", "source-port", "5000"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			captureStdout(t, func() { err = c.testPolicy(tc.args) })
			if (err != nil) != tc.wantErr {
				t.Fatalf("testPolicy(%v) err = %v, wantErr = %v", tc.args, err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "source-port") {
				t.Fatalf("testPolicy(%v) err = %v, want a source-port diagnostic", tc.args, err)
			}
		})
	}
}
