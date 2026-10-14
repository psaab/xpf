package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// policyModifierStore12902 builds a local CLI with one zone-pair policy
// (trust->untrust) and two global policies (one scoped to that pair, one
// unscoped) — enough for every view to render a distinguishable row.
func policyModifierStore12902(t *testing.T) *CLI {
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
            policy zone-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy scoped-block {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
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

// showPolicies12902 runs handleShowSecurity for `show security policies <args...>`
// and returns (output, error).
func showPolicies12902(t *testing.T, c *CLI, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		err = c.handleShowSecurity(append([]string{"policies"}, args...))
	})
	return out, err
}

// TestShowSecurityPolicies_TrailingViewKeywordHonored_12902 is the
// OPERATOR-SURFACE regression for the D9-12 defect: the selector validator
// admitted brief/detail/hit-count/global at any position while the dispatch
// tested only args[1], so `show security policies from-zone trust to-zone
// untrust <keyword>` rendered the STANDARD view and returned success — the
// keyword was silently discarded.
//
// FAIL-ON-REVERT: restore the args[1]-only ladder in handleShowSecurity and
// every subtest's view-marker assertion goes RED (the standard view renders
// instead of the requested one).
func TestShowSecurityPolicies_TrailingViewKeywordHonored_12902(t *testing.T) {
	standardOnly := ", Scope Policy: 0, Sequence number:" // standard-view policy line

	t.Run("detail", func(t *testing.T) {
		out, err := showPolicies12902(t, policyModifierStore12902(t),
			"from-zone", "trust", "to-zone", "untrust", "detail")
		if err != nil {
			t.Fatalf("trailing detail rejected: %v", err)
		}
		if !strings.Contains(out, "Policy Type: Configured") {
			t.Fatalf("trailing detail did not select the detail view:\n%s", out)
		}
		if strings.Contains(out, standardOnly) {
			t.Fatalf("trailing detail rendered the standard view instead:\n%s", out)
		}
	})

	t.Run("hit-count", func(t *testing.T) {
		// c.dp is nil in this CLI, so the hit-count worker's own gate
		// ("dataplane not loaded") proves the dispatch routed to it.
		out, err := showPolicies12902(t, policyModifierStore12902(t),
			"from-zone", "trust", "to-zone", "untrust", "hit-count")
		if err != nil {
			t.Fatalf("trailing hit-count rejected: %v", err)
		}
		if !strings.Contains(out, "dataplane not loaded") {
			t.Fatalf("trailing hit-count did not select the hit-count view:\n%s", out)
		}
	})

	t.Run("brief", func(t *testing.T) {
		out, err := showPolicies12902(t, policyModifierStore12902(t),
			"from-zone", "trust", "to-zone", "untrust", "brief")
		if err != nil {
			t.Fatalf("trailing brief rejected: %v", err)
		}
		if !strings.Contains(out, "Hits") || !strings.Contains(out, "zone-allow") {
			t.Fatalf("trailing brief did not select the brief view:\n%s", out)
		}
		if strings.Contains(out, standardOnly) {
			t.Fatalf("trailing brief rendered the standard view instead:\n%s", out)
		}
	})

	t.Run("global", func(t *testing.T) {
		out, err := showPolicies12902(t, policyModifierStore12902(t),
			"from-zone", "trust", "to-zone", "untrust", "global")
		if err != nil {
			t.Fatalf("trailing global rejected: %v", err)
		}
		if !strings.Contains(out, "Global policies:") {
			t.Fatalf("trailing global did not scope to the global block:\n%s", out)
		}
		if strings.Contains(out, "From zone: trust, To zone: untrust") {
			t.Fatalf("trailing global still rendered the zone-pair view (keyword dropped):\n%s", out)
		}
	})

	// A repeated verbatim keyword is idempotent, not a conflict.
	t.Run("detail-detail", func(t *testing.T) {
		out, err := showPolicies12902(t, policyModifierStore12902(t),
			"from-zone", "trust", "to-zone", "untrust", "detail", "detail")
		if err != nil {
			t.Fatalf("repeated detail wrongly rejected: %v", err)
		}
		if !strings.Contains(out, "Policy Type: Configured") {
			t.Fatalf("repeated detail did not select the detail view:\n%s", out)
		}
	})
}

// TestShowSecurityPolicies_GlobalPositionIndependent_12902 is the decisive
// check from the research lane: `from-zone trust to-zone untrust global` and
// the equivalent leading `global` form must render the SAME inventory. Before
// the fix the trailing form kept the zone-pair passes and dropped `global`.
func TestShowSecurityPolicies_GlobalPositionIndependent_12902(t *testing.T) {
	c := policyModifierStore12902(t)
	leading, err := showPolicies12902(t, c, "global", "from-zone", "trust", "to-zone", "untrust")
	if err != nil {
		t.Fatalf("leading global rejected: %v", err)
	}
	trailing, err := showPolicies12902(t, c, "from-zone", "trust", "to-zone", "untrust", "global")
	if err != nil {
		t.Fatalf("trailing global rejected: %v", err)
	}
	if leading != trailing {
		t.Fatalf("global keyword is position-dependent:\n--- leading ---\n%s\n--- trailing ---\n%s",
			leading, trailing)
	}
}

// TestShowSecurityPolicies_RejectsConflictingKeywords_12902 pins the
// fail-closed half of the fix: a second keyword the views cannot render
// (`brief global`, `detail global`, two display keywords) must be REJECTED
// before anything is printed, never silently narrowed. Before the fix every
// one of these returned nil and rendered a view that ignored a keyword.
func TestShowSecurityPolicies_RejectsConflictingKeywords_12902(t *testing.T) {
	for _, args := range [][]string{
		{"brief", "global"},
		{"detail", "global"},
		{"global", "detail"},
		{"global", "brief"},
		{"global", "hit-count"},
		{"hit-count", "global"},
		{"from-zone", "trust", "to-zone", "untrust", "detail", "global"},
		{"brief", "detail"},
		{"detail", "hit-count"},
		{"hit-count", "from-zone", "trust", "detail"},
	} {
		out, err := showPolicies12902(t, policyModifierStore12902(t), args...)
		if err == nil {
			t.Fatalf("policies %v: conflicting keywords accepted (keyword silently dropped)", args)
		}
		if !strings.Contains(err.Error(), "conflicting display keywords") &&
			!strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("policies %v: error = %q, want a conflict rejection", args, err)
		}
		if out != "" {
			t.Fatalf("policies %v: rendered output before rejecting:\n%s", args, out)
		}
	}
}
