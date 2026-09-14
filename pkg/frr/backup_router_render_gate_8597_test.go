package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K24) — the backup-router renderer emitted a reload-poisoning
// line for a value the commit-time validator had already logged as "ignored".
//
// validateBackupRouterDst (#4808/#2911) rejects three things at strict commit —
// a malformed next-hop, a malformed destination, and a next-hop/destination
// FAMILY MISMATCH — and on the tolerant Store.Load / Store.SyncApply path
// downgrades each to a warning ending "(ignored: backup-router default route
// not installed until corrected)". renderBackupRouter ignored nothing. It
// interpolated the value verbatim, so:
//
//   - the promise in the log was false;
//   - the emitted line fails the WHOLE managed-section reload, because one
//     vtysh add-batch exits non-zero on any CMD_WARNING_CONFIG_FAILED — every
//     other route on the box goes with it;
//   - and the operator's own log points AWAY from the cause.
//
// generateStaticRouteInTable has carried this belt since #6795. The
// backup-router operands were never brought along — the #8258 shape.

// renderBackupRouterFromLenientConfig drives the real tolerant ingress: parse,
// compile LENIENTLY (the path the finding names), then render.
//
// Compiling rather than hand-filling FullConfig is the point. The claim is
// about a value the compiler will hand the renderer on the tolerant path, so a
// fixture that hand-supplies BackupRouter would prove the renderer skips
// something the compiler might never produce.
func renderBackupRouterFromLenientConfig(t *testing.T, setCmds ...string) (rendered string, warnings []string) {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range setCmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail (#1960 no-brick): %v", err)
	}
	fc := &FullConfig{
		BackupRouter:    cfg.System.BackupRouter,
		BackupRouterDst: cfg.System.BackupRouterDst,
	}
	var b strings.Builder
	renderBackupRouter(&b, fc)
	return b.String(), cfg.Warnings
}

// TestMalformedBackupRouterIsNotRendered_8597 covers all THREE of the
// validator's checks, because all three produce a line frr-reload rejects and
// all three carry the same "(ignored)" promise.
//
// The family-mismatch case is the one an operand-shape reading misses: both
// operands are individually well-formed, and the route is still poison.
func TestMalformedBackupRouterIsNotRendered_8597(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		why  string
	}{
		{
			name: "malformed next-hop",
			cmds: []string{"set system backup-router 192.168.1.x"},
			why:  "an unparseable next-hop operand",
		},
		{
			name: "malformed destination",
			cmds: []string{"set system backup-router 192.168.50.1 destination 10.0.0.0/99"},
			why:  "a /99 mask is not a valid prefix",
		},
		{
			name: "v4 next-hop with v6 destination",
			cmds: []string{"set system backup-router 192.168.50.1 destination 2001:db8::/32"},
			why:  "both operands parse; the ROUTE is still one FRR rejects (#2891)",
		},
		{
			name: "v6 next-hop with v4 destination",
			cmds: []string{"set system backup-router 2001:db8::1 destination 10.0.0.0/8"},
			why:  "the mirror case",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, warnings := renderBackupRouterFromLenientConfig(t, tc.cmds...)
			if strings.TrimSpace(got) != "" {
				t.Errorf("renderer emitted %q for %s (%s); the managed-section reload "+
					"fails as a whole on this line, taking every valid route with it",
					got, tc.name, tc.why)
			}
			// The other half of the agreement: the validator must still be
			// SAYING "ignored". A fix that silently skipped while the log kept
			// promising something else would leave the disagreement in place,
			// pointing the other way.
			var promised bool
			for _, w := range warnings {
				if strings.Contains(w, "ignored: backup-router default route not installed") {
					promised = true
				}
			}
			if !promised {
				t.Errorf("the lenient compile did not warn that this backup-router would "+
					"be ignored; renderer and validator have to agree, and this cell "+
					"pins BOTH sides. warnings=%v", warnings)
			}
		})
	}
}

// TestWellFormedBackupRouterStillRenders_8597 is the OVER-BROAD control. A gate
// that rejected anything it did not recognise would satisfy every cell above
// and silently delete a working fallback default route — which on a WAN or
// management path is a remote lockout, the exact outcome #1960 exists to avoid.
//
// The bare-address destination is included deliberately: validFRRRoutePrefix
// accepts it (see its #6795 doc — rejecting a form that commits today would
// drop a working route), so the belt must not be tightened into a
// CIDR-only rule by someone reading only the validator.
func TestWellFormedBackupRouterStillRenders_8597(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "v4 next-hop, default destination",
			cmds: []string{"set system backup-router 192.168.50.1"},
			want: "ip route 0.0.0.0/0 192.168.50.1 250\n",
		},
		{
			name: "v6 next-hop, default destination",
			cmds: []string{"set system backup-router 2001:db8::1"},
			want: "ipv6 route ::/0 2001:db8::1 250\n",
		},
		{
			name: "v4 next-hop, explicit matching v4 destination",
			cmds: []string{"set system backup-router 192.168.50.1 destination 10.0.0.0/8"},
			want: "ip route 10.0.0.0/8 192.168.50.1 250\n",
		},
		{
			name: "v6 next-hop, explicit matching v6 destination",
			cmds: []string{"set system backup-router 2001:db8::1 destination 2001:db8:1::/48"},
			want: "ipv6 route 2001:db8:1::/48 2001:db8::1 250\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := renderBackupRouterFromLenientConfig(t, tc.cmds...)
			if !strings.Contains(got, tc.want) {
				t.Errorf("missing %q in:\n%s", tc.want, got)
			}
		})
	}
}

// TestBackupRouterFixturesReachTheRenderer_8597 is the non-vacuity control.
//
// Every cell in TestMalformedBackupRouterIsNotRendered_8597 asserts the
// renderer emits NOTHING — and "nothing" is also what a renderer emits when the
// value never arrived. If the lenient compile dropped a malformed
// backup-router instead of keeping it, those cells would pass while testing an
// empty input. This asserts the value is actually present in the compiled
// config, so the emptiness above is attributable to the gate.
func TestBackupRouterFixturesReachTheRenderer_8597(t *testing.T) {
	for _, tc := range []struct {
		cmd     string
		wantNH  string
		wantDst string
	}{
		{"set system backup-router 192.168.1.x", "192.168.1.x", ""},
		{"set system backup-router 192.168.50.1 destination 10.0.0.0/99", "192.168.50.1", "10.0.0.0/99"},
		{"set system backup-router 192.168.50.1 destination 2001:db8::/32", "192.168.50.1", "2001:db8::/32"},
	} {
		tree := &config.ConfigTree{}
		path, err := config.ParseSetCommand(tc.cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", tc.cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", tc.cmd, err)
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if cfg.System.BackupRouter != tc.wantNH || cfg.System.BackupRouterDst != tc.wantDst {
			t.Errorf("lenient compile of %q gave next-hop %q dst %q, want %q / %q — if "+
				"the compiler now drops the malformed value, the render-gate cells are "+
				"vacuous and the gate should be re-argued rather than kept",
				tc.cmd, cfg.System.BackupRouter, cfg.System.BackupRouterDst,
				tc.wantNH, tc.wantDst)
		}
		// And strict must still reject, or there is no tolerant/strict split.
		if _, err := config.CompileConfig(tree); err == nil {
			t.Errorf("strict compile accepted %q; the split this finding rests on is gone", tc.cmd)
		}
	}
}
