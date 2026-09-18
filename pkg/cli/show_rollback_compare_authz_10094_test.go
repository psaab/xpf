package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #10094: operational `show system rollback compare N` (both spellings) diffs
// rollback slot N against the shared CANDIDATE
// (c.store.ShowCompareRollbackRedacted), but the console gate priced the whole
// `show` family at PermView — so a view-only console user read another
// session's staged, uncommitted configuration. Same disclosure #9889 closed on
// the gRPC ShowCompare RPC (both arms), on the in-process console surface.
//
// The fix prices the two compare spellings at PermConfig while the rest of
// `show` stays PermView, mirroring the #9324/#9889 contract (reading a
// candidate is a configure-mode activity). Secrets were already masked on this
// path (#4099), so the disclosure is reconnaissance, not credential theft —
// the staged secret below guards that redaction while the non-secret canary
// carries the RED/GREEN signal.

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

// TestRequiredPermission_RollbackCompareCostsConfigure_10094 pins the gate
// shape: both compare spellings (plus the abbreviated `system` the handler
// resolves) cost PermConfig; every non-compare and malformed spelling stays
// PermView. Reverting the gate makes the four configure rows go RED.
func TestRequiredPermission_RollbackCompareCostsConfigure_10094(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  config.LoginClassPermission
	}{
		{"compare-first spelling", []string{"show", "system", "rollback", "compare", "1"}, config.PermConfig},
		{"compare-last spelling", []string{"show", "system", "rollback", "1", "compare"}, config.PermConfig},
		{"abbrev system compare-first", []string{"show", "syst", "rollback", "compare", "1"}, config.PermConfig},
		{"abbrev system compare-last", []string{"show", "syst", "rollback", "1", "compare"}, config.PermConfig},

		{"bare rollback list", []string{"show", "system", "rollback"}, config.PermView},
		{"rollback slot render", []string{"show", "system", "rollback", "1"}, config.PermView},
		{"rollback slot display set", []string{"show", "system", "rollback", "1", "|", "display", "set"}, config.PermView},
		// The handler checks `| display set` BEFORE `compare`, so this renders
		// the committed slot (no candidate read) and must stay view-level.
		{"display set wins over compare", []string{"show", "system", "rollback", "1", "compare", "|", "display", "set"}, config.PermView},
		{"show version", []string{"show", "version"}, config.PermView},
		{"commit history", []string{"show", "system", "commit", "history"}, config.PermView},

		// Malformed compare errors (usage) before any store access: no
		// candidate read, so no upgrade — the gate mirrors the handler.
		{"bare compare", []string{"show", "system", "rollback", "compare"}, config.PermView},
		{"compare slot zero", []string{"show", "system", "rollback", "compare", "0"}, config.PermView},
		{"compare slot garbage", []string{"show", "system", "rollback", "compare", "foo"}, config.PermView},
		{"garbage slot compare", []string{"show", "system", "rollback", "foo", "compare"}, config.PermView},
		// The handler's substring match is case-sensitive; COMPARE renders
		// the committed slot, not a diff.
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

// TestCheckPermission_RollbackComparePerClass_10094 pins the per-class outcome
// on both spellings: only a class holding configure (or everything) is
// admitted. The `configurator` row proves the price is PermConfig rather than
// PermAll/PermMaint; the `configureonly` row pins the replace shape (console
// charges one bit, like REST — unlike gRPC's additive view-AND-configure).
func TestCheckPermission_RollbackComparePerClass_10094(t *testing.T) {
	store := newCompareStore10094(t)
	compareCmds := [][]string{
		{"show", "system", "rollback", "compare", "1"},
		{"show", "system", "rollback", "1", "compare"},
	}
	cases := []struct {
		class string
		allow bool
	}{
		{"super-user", true},
		{"configurator", true},
		{"configureonly", true},
		{"operator", false},
		{"read-only", false},
		{"config-viewer", false},
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
					t.Errorf("%q ALLOWED for %q (want denied — renders the shared candidate)",
						strings.Join(cmd, " "), tc.class)
				}
			})
		}
	}

	// The configureonly class really is view-less: it cannot run a plain
	// view-level show, so its compare admission above proves configure alone
	// suffices (replace, not additive).
	co := &CLI{store: store, userClass: "configureonly"}
	if err := co.checkPermission([]string{"show", "version"}); err == nil {
		t.Errorf("configureonly ALLOWED show version (want denied — the class must hold configure WITHOUT view for the replace-shape pin)")
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

// TestDispatchOperational_ViewOnlyDeniedRollbackCompare_10094 is the
// end-to-end leak cell: with another session's canary staged on the shared
// store, a view-only console session is denied on BOTH compare spellings and
// the canary never reaches its output. Pre-fix this goes RED (served with the
// canary); the `run`-prefixed row pins the config-mode dispatch path, which
// funnels through the same gate.
func TestDispatchOperational_ViewOnlyDeniedRollbackCompare_10094(t *testing.T) {
	store := newCompareStore10094(t)
	lines := []string{
		"show system rollback compare 1",
		"show system rollback 1 compare",
	}
	for _, class := range []string{"read-only", "operator", "config-viewer"} {
		for _, line := range lines {
			t.Run(class+"/"+line, func(t *testing.T) {
				c := &CLI{store: store, userClass: class}
				var runErr error
				out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
				if runErr == nil || !strings.Contains(runErr.Error(), "permission denied") {
					t.Errorf("%q for %q: err=%v (want permission denied)", line, class, runErr)
				}
				if strings.Contains(out, compareCanary10094) {
					t.Errorf("%q for %q LEAKED the staged canary:\n%s", line, class, out)
				}
				if strings.Contains(out, compareSecret10094) {
					t.Errorf("%q for %q LEAKED the staged secret in cleartext:\n%s", line, class, out)
				}
			})
		}
	}

	// `run show ... compare` from config-mode dispatch reaches the same
	// operational gate and must deny identically.
	t.Run("read-only/run show system rollback compare 1", func(t *testing.T) {
		c := &CLI{store: store, userClass: "read-only"}
		var runErr error
		out := captureStdout(t, func() { runErr = c.dispatchConfig("run show system rollback compare 1") })
		if runErr == nil || !strings.Contains(runErr.Error(), "permission denied") {
			t.Errorf("run-prefixed compare: err=%v (want permission denied)", runErr)
		}
		if strings.Contains(out, compareCanary10094) {
			t.Errorf("run-prefixed compare LEAKED the staged canary:\n%s", out)
		}
	})
}

// TestDispatchOperational_PrivilegedServedRollbackCompare_10094 pins that the
// gate is surgical: privileged sessions still get both diffs with the canary
// in the output. super-user reads the cleartext path (the #4057 allowance);
// the view+configure custom class reads the redacted path (canary visible,
// secret masked).
func TestDispatchOperational_PrivilegedServedRollbackCompare_10094(t *testing.T) {
	store := newCompareStore10094(t)
	lines := []string{
		"show system rollback compare 1",
		"show system rollback 1 compare",
	}
	for _, line := range lines {
		t.Run("super-user/"+line, func(t *testing.T) {
			c := &CLI{store: store, userClass: "super-user"}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
			if runErr != nil {
				t.Fatalf("%q for super-user: %v (want served)", line, runErr)
			}
			if !strings.Contains(out, compareCanary10094) {
				t.Errorf("%q for super-user missing the canary (over-deny):\n%s", line, out)
			}
		})
		t.Run("configurator/"+line, func(t *testing.T) {
			c := &CLI{store: store, userClass: "configurator"}
			var runErr error
			out := captureStdout(t, func() { runErr = c.dispatchOperational(line) })
			if runErr != nil {
				t.Fatalf("%q for configurator: %v (want served)", line, runErr)
			}
			if !strings.Contains(out, compareCanary10094) {
				t.Errorf("%q for configurator missing the canary (over-deny):\n%s", line, out)
			}
			if strings.Contains(out, compareSecret10094) {
				t.Errorf("%q for configurator LEAKED the staged secret in cleartext:\n%s", line, out)
			}
			if !strings.Contains(out, config.SecretDataPlaceholder) {
				t.Errorf("%q for configurator missing redaction placeholder %q:\n%s",
					line, config.SecretDataPlaceholder, out)
			}
		})
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
