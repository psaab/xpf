package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #10094 (original): operational `show system rollback compare N` (both
// spellings) diffed rollback slot N against the shared CANDIDATE
// (c.store.ShowCompareRollbackRedacted), but the console gate priced the
// whole `show` family at PermView — so a view-only console user read
// another session's staged, uncommitted configuration. Same disclosure
// #9889 closed on the gRPC ShowCompare RPC (both arms), on the
// in-process console surface.
//
// The fix priced the two compare spellings at PermConfig while the rest
// of `show` stayed PermView, mirroring the #9324/#9889 contract.
//
// #15657 V45-03 SUPERSEDES the baseline, not the disclosure concern:
// operational compare now diffs against ACTIVE
// (ShowCompareRollbackActiveRedacted) — committed state only — so a
// view-only user is served the active-baseline diff and can NEVER see
// the staged canary through it, at PermView. The cells below pin that:
// compare spellings cost PermView, every class with view is served,
// and the canary/secret never appear for anyone on this path
// (super-user included — there is no candidate arm left to read).

// compareCanary10094 is staged in the candidate and never committed. Any
// view-only output containing it rendered another session's work-in-progress.
const compareCanary10094 = "UNCOMMITTED-CANARY-10094"

// compareSecret10094 is staged alongside the canary and never committed. It
// must never appear in cleartext on the redacted path (the #4099 allowance
// keeps cleartext only for super-user / the unset class).
const compareSecret10094 = "STAGED-SECRET-10094"

// newCompareStore10094 builds a store with committed history (rollback slot 1
// populated) plus a live candidate carrying the canary and the staged secret.
// The store is left in configure mode (candidate retained), exactly as when
// another session holds configure while the console sits at its prompt. The
// active config also defines the custom classes the per-class cells need:
// `configurator` holds EXACTLY view+configure (proving the price is PermConfig
// and not PermAll/PermMaint — a super-user fixture would not catch an
// over-refusal), and `configureonly` holds configure WITHOUT view (pinning the
// replace shape of the console price: one bit, like REST, not the additive
// view-AND-configure shape gRPC charges).
func newCompareStore10094(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	base := []string{
		"set system host-name compare-10094-base",
		"set system login class configurator permissions [ view configure ]",
		"set system login class configureonly permissions configure",
	}
	if _, err := store.LoadSet(strings.Join(base, "\n")); err != nil {
		t.Fatalf("LoadSet(base): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(base): %v", err)
	}
	// Second commit pushes the base config into rollback slot 1. The store
	// stays in configure mode across commits (candidate retained as a clone
	// of active), so LoadSet directly onto the live candidate.
	if _, err := store.LoadSet("set system domain-name example.net"); err != nil {
		t.Fatalf("LoadSet(v2): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(v2): %v", err)
	}
	// Stage another session's work-in-progress: never committed.
	staged := []string{
		"set system host-name " + compareCanary10094,
		"set security ike policy pol1 pre-shared-key ascii-text " + compareSecret10094,
	}
	if _, err := store.LoadSet(strings.Join(staged, "\n")); err != nil {
		t.Fatalf("LoadSet(staged): %v", err)
	}
	return store
}

// TestRequiredPermission_RollbackCompareCostsConfigure_10094: #15657
// moved the operational baseline to ACTIVE, so the compare spellings
// cost PermView like every other committed-config show. Reverting to
// the candidate baseline without restoring the PermConfig price makes
// the disclosure cells below go RED (canary in view-only output).
func TestRequiredPermission_RollbackCompareCostsConfigure_10094(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  config.LoginClassPermission
	}{
		{"compare-first spelling", []string{"show", "system", "rollback", "compare", "1"}, config.PermView},
		{"compare-last spelling", []string{"show", "system", "rollback", "1", "compare"}, config.PermView},
		{"abbrev system compare-first", []string{"show", "syst", "rollback", "compare", "1"}, config.PermView},
		{"abbrev system compare-last", []string{"show", "syst", "rollback", "1", "compare"}, config.PermView},
		{"compare rollback zero", []string{"show", "system", "rollback", "compare", "0"}, config.PermView},
		{"pipe compare", []string{"show", "system", "rollback", "1", "|", "compare"}, config.PermView},
		{"bare rollback list", []string{"show", "system", "rollback"}, config.PermView},
		{"rollback slot render", []string{"show", "system", "rollback", "1"}, config.PermView},
		{"rollback slot display set", []string{"show", "system", "rollback", "1", "|", "display", "set"}, config.PermView},
		{"display set wins over compare", []string{"show", "system", "rollback", "1", "compare", "|", "display", "set"}, config.PermView},
		{"show version", []string{"show", "version"}, config.PermView},
		{"commit history", []string{"show", "system", "commit", "history"}, config.PermView},
		{"bare compare", []string{"show", "system", "rollback", "compare"}, config.PermView},
		{"compare slot garbage", []string{"show", "system", "rollback", "compare", "foo"}, config.PermView},
		{"garbage slot compare", []string{"show", "system", "rollback", "foo", "compare"}, config.PermView},
		{"uppercase compare", []string{"show", "system", "rollback", "1", "COMPARE"}, config.PermView},
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

// TestCheckPermission_RollbackComparePerClass_10094: after #15657 the
// price is PermView, so exactly the classes holding view (or all) are
// admitted; configure-without-view no longer suffices.
func TestCheckPermission_RollbackComparePerClass_10094(t *testing.T) {
	store := newCompareStore10094(t)
	compareCmds := [][]string{
		{"show", "system", "rollback", "compare", "1"},
		{"show", "system", "rollback", "1", "compare"},
		{"show", "system", "rollback", "1", "|", "compare"},
	}
	cases := []struct {
		class string
		allow bool
	}{
		{"super-user", true},
		{"configurator", true},
		{"configureonly", false},
		{"operator", true},
		{"read-only", true},
		{"config-viewer", true},
		{"unauthorized", false},
	}
	for _, tc := range cases {
		for _, cmd := range compareCmds {
			t.Run(tc.class+"/"+strings.Join(cmd[2:], "_"), func(t *testing.T) {
				c := &CLI{store: store, userClass: tc.class}
				err := c.checkPermission(cmd)
				if tc.allow && err != nil {
					t.Errorf("%q denied for %q: %v (want allowed)",
						strings.Join(cmd, " "), tc.class, err)
				}
				if !tc.allow && err == nil {
					t.Errorf("%q ALLOWED for %q (want denied — no view permission)",
						strings.Join(cmd, " "), tc.class)
				}
			})
		}
	}

	// Unset class keeps the legacy allow-everything behavior.
	unset := &CLI{store: store, userClass: ""}
	for _, cmd := range compareCmds {
		if err := unset.checkPermission(cmd); err != nil {
			t.Errorf("%q denied for unset class: %v (want allowed — legacy no-RBAC)",
				strings.Join(cmd, " "), err)
		}
	}
}

// TestDispatchOperational_ViewOnlyDeniedRollbackCompare_10094 is now
// the SERVED-WITHOUT-CANARY cell (#15657): a view-only session is
// served the active-baseline diff on every spelling (including the
// pipe form and the `run` path), and the staged canary/secret never
// reach its output because there is no candidate arm anymore.
// RED-on-revert to the candidate baseline: the canary appears.
func TestDispatchOperational_ViewOnlyDeniedRollbackCompare_10094(t *testing.T) {
	store := newCompareStore10094(t)
	lines := []string{
		"show system rollback compare 1",
		"show system rollback 1 compare",
		"show system rollback 1 | compare",
	}
	for _, class := range []string{"read-only", "operator", "config-viewer"} {
		for _, line := range lines {
			t.Run(class+"/"+line, func(t *testing.T) {
				c := &CLI{store: store, userClass: class}
				var runErr error
				out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
				if runErr != nil {
					t.Errorf("%q for %q: err=%v (want served active-baseline diff)", line, class, runErr)
				}
				if strings.Contains(out, "unknown pipe") {
					t.Errorf("%q for %q hit the unknown-pipe error (V47-02):\n%s", line, class, out)
				}
				if strings.Contains(out, compareCanary10094) {
					t.Errorf("%q for %q LEAKED the staged canary:\n%s", line, class, out)
				}
				if strings.Contains(out, compareSecret10094) {
					t.Errorf("%q for %q LEAKED the staged secret in cleartext:\n%s", line, class, out)
				}
				if !strings.Contains(out, "example.net") {
					t.Errorf("%q for %q missing the committed active-baseline diff:\n%s", line, class, out)
				}
			})
		}
	}

	// `run …` from config dispatch still requires the configure verb
	// itself for a read-only class (unchanged #10094 posture) — the
	// compare baseline change does not widen `run`.
	t.Run("read-only/run show system rollback compare 1", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		var runErr error
		out := captureStdout(t, func() { runErr = c.dispatchConfig("run show system rollback compare 1") })
		if runErr == nil || !strings.Contains(runErr.Error(), "permission denied") {
			t.Errorf("run-prefixed compare: err=%v (want permission denied for the run verb)", runErr)
		}
		if strings.Contains(out, compareCanary10094) {
			t.Errorf("run-prefixed compare LEAKED the staged canary:\n%s", out)
		}
	})
}

// TestDispatchOperational_PrivilegedServedRollbackCompare_10094 pins
// that privileged sessions get the same active-baseline diff — and
// that even super-user cannot pull the staged candidate through the
// operational spelling anymore (no candidate arm exists).
func TestDispatchOperational_PrivilegedServedRollbackCompare_10094(t *testing.T) {
	store := newCompareStore10094(t)
	lines := []string{
		"show system rollback compare 1",
		"show system rollback 1 compare",
		"show system rollback 1 | compare",
	}
	for _, line := range lines {
		for _, class := range []string{"super-user", "configurator"} {
			t.Run(class+"/"+line, func(t *testing.T) {
				c := &CLI{store: store, userClass: class}
				var runErr error
				out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
				if runErr != nil {
					t.Fatalf("%q for %s: %v (want served)", line, class, runErr)
				}
				if strings.Contains(out, compareCanary10094) || strings.Contains(out, compareSecret10094) {
					t.Errorf("%q for %s leaked staged candidate content:\n%s", line, class, out)
				}
				if !strings.Contains(out, "example.net") {
					t.Errorf("%q for %s missing the committed diff:\n%s", line, class, out)
				}
			})
		}
	}
}

// TestDispatchOperational_NonCompareShowUnaffected_10094 pins that read-only
// keeps its committed-archive renders: the slot render, the rollback list,
// the display-set render, and an unrelated show all still serve, and none
// carries the never-committed canary.
func TestDispatchOperational_NonCompareShowUnaffected_10094(t *testing.T) {
	store := newCompareStore10094(t)
	served := []string{
		"show system rollback 1",
		"show system rollback",
		"show system rollback 1 | display set",
		"show system rollback 1 compare | display set",
		"show version",
	}
	for _, line := range served {
		t.Run("read-only/"+line, func(t *testing.T) {
			c := &CLI{store: store, userClass: "read-only"}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
			if runErr != nil {
				t.Errorf("%q for read-only: %v (want served — no candidate read)", line, runErr)
			}
			if strings.Contains(out, compareCanary10094) {
				t.Errorf("%q for read-only unexpectedly contains the canary:\n%s", line, out)
			}
		})
	}

	// The slot render serves REAL committed content (the base host-name from
	// rollback slot 1), proving the control above is served, not empty.
	c := &CLI{store: store, userClass: "read-only"}
	out := captureStdout(t, func() {
		if err := c.dispatchOperational("show system rollback 1"); err != nil {
			t.Fatalf("show system rollback 1: %v", err)
		}
	})
	if !strings.Contains(out, "compare-10094-base") {
		t.Errorf("rollback slot render missing committed base content:\n%s", out)
	}
}
