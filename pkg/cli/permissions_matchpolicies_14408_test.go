package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #14408 (DR13-H1): the local CLI priced every `show` at PermView, so
// `show security match-policies` — the same policymatch simulator gRPC
// MatchPolicies (#11077) and REST GET /api/v1/security/match (#11674)
// price at PermControl — was reachable by PermView-only classes
// (read-only / config-viewer) from the console. The fix elevates that
// one command to PermControl, resolving through the command tree so
// abbreviations gate identically.

// matchPoliciesStore14408 commits zones trust/untrust and one
// trust->untrust permit rule with a distinctive name/description, so a
// served verdict is observable and a denied one proves no leak.
func matchPoliciesStore14408(t *testing.T) *configstore.Store {
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
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy recon-canary-14408 {
                description "recon-canary-desc-14408";
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
	return store
}

const matchPoliciesLine14408 = "show security match-policies from-zone trust to-zone untrust source-ip 10.0.1.5 destination-ip 10.0.2.5 protocol tcp destination-port 443"

// TestRequiredPermission_MatchPoliciesCostsControl_14408 pins the price:
// full and abbreviated spellings cost PermControl; sibling shows stay
// PermView. Reverting the elevation makes the control rows go RED.
func TestRequiredPermission_MatchPoliciesCostsControl_14408(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  config.LoginClassPermission
	}{
		{"full", []string{"show", "security", "match-policies", "from-zone", "trust", "to-zone", "untrust"}, config.PermControl},
		{"bare", []string{"show", "security", "match-policies"}, config.PermControl},
		{"abbrev security", []string{"show", "sec", "match-policies"}, config.PermControl},
		{"abbrev match-policies", []string{"show", "security", "match-p"}, config.PermControl},
		{"abbrev both", []string{"show", "sec", "match-p"}, config.PermControl},

		{"policies control", []string{"show", "security", "policies"}, config.PermView},
		{"zones control", []string{"show", "security", "zones"}, config.PermView},
		{"version control", []string{"show", "version"}, config.PermView},
		{"bare security", []string{"show", "security"}, config.PermView},
		{"unknown security child", []string{"show", "security", "bogus-14408"}, config.PermView},
		// "m" is an unambiguous prefix of match-policies alone among the
		// security children, so it resolves — and gates — identically.
		{"abbrev unique m", []string{"show", "security", "m"}, config.PermControl},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requiredPermission(tc.parts); got != tc.want {
				t.Errorf("requiredPermission(%q) = %v, want %v",
					strings.Join(tc.parts, " "), got, tc.want)
			}
		})
	}
}

// TestCheckPermission_MatchPoliciesPerClass_14408 pins per-class outcomes:
// PermView-only classes denied, operator (PermControl) and super-user
// admitted, unset class keeps legacy allow-everything.
func TestCheckPermission_MatchPoliciesPerClass_14408(t *testing.T) {
	store := matchPoliciesStore14408(t)
	parts := []string{"show", "security", "match-policies", "from-zone", "trust", "to-zone", "untrust"}
	cases := []struct {
		class string
		allow bool
	}{
		{"read-only", false},
		{"config-viewer", false},
		{"operator", true},
		{"super-user", true},
		{"unauthorized", false},
	}
	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class}
			err := c.checkPermission(parts)
			if tc.allow && err != nil {
				t.Errorf("match-policies denied for %q: %v (want allowed)", tc.class, err)
			}
			if !tc.allow && err == nil {
				t.Errorf("match-policies ALLOWED for %q (want denied — policy reconnaissance)", tc.class)
			}
		})
	}
	unset := &CLI{store: store, userClass: ""}
	if err := unset.checkPermission(parts); err != nil {
		t.Errorf("match-policies denied for unset class: %v (want allowed — legacy no-RBAC)", err)
	}
}

// TestDispatchOperational_MatchPoliciesGate_14408 is the end-to-end
// cell from the issue: read-only is denied before the simulator runs
// (no verdict leak), operator reaches the simulator and gets the
// matched policy verdict.
func TestDispatchOperational_MatchPoliciesGate_14408(t *testing.T) {
	store := matchPoliciesStore14408(t)

	for _, class := range []string{"read-only", "config-viewer"} {
		t.Run(class+" denied", func(t *testing.T) {
			c := &CLI{store: store, userClass: class}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(matchPoliciesLine14408) })
			if runErr == nil || !strings.Contains(runErr.Error(), "permission denied") {
				t.Errorf("%q for %q: err=%v (want permission denied)", matchPoliciesLine14408, class, runErr)
			}
			if strings.Contains(out, "recon-canary-14408") {
				t.Errorf("%q for %q LEAKED the matched policy verdict:\n%s", matchPoliciesLine14408, class, out)
			}
		})
	}

	t.Run("operator reaches simulator", func(t *testing.T) {
		c := &CLI{store: store, userClass: "operator"}
		var runErr error
		out := captureStdout(t, func() { runErr = c.dispatchOperational(matchPoliciesLine14408) })
		if runErr != nil {
			t.Fatalf("%q for operator: %v (want served)", matchPoliciesLine14408, runErr)
		}
		if !strings.Contains(out, "recon-canary-14408") {
			t.Errorf("operator did not reach the simulator verdict:\n%s", out)
		}
	})

	// Control: read-only keeps ordinary show access.
	t.Run("read-only show security policies served", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		var runErr error
		out := captureStdout(t, func() { runErr = c.dispatchOperational("show security policies") })
		if runErr != nil {
			t.Errorf("show security policies for read-only: %v (want served)", runErr)
		}
		if !strings.Contains(out, "recon-canary-14408") {
			t.Errorf("show security policies control missing policy inventory:\n%s", out)
		}
	})
}
