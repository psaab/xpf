package config

import (
	"strings"
	"testing"
)

// Tests for #5297: an invalid IPsec `bind-interface` name (anything but the
// canonical secure-tunnel st<N> / st<N>.<unit>) committed successfully but
// resolved to if_id 0 via XFRMIfNameAndID — the reconciler created NO XFRM
// device, so the route-based VPN was silently DOWN. The if_id-collision gate
// (#2933) deliberately `continue`d past any name yielding if_id 0, treating it
// as out of scope, so a strict commit reported SUCCESS.
//
// The fix REJECTS such a name at strict commit (CompileConfig + SchemaValidate)
// and WARNS on the tolerant load / peer-sync path (CompileConfigLenient),
// mirroring the #1960 fail-closed-on-strict / lenient-on-load doctrine. It is
// DISTINCT from #2909/#2933 (two VALID st aliases colliding on a non-zero
// if_id), which must still be handled by the collision gate.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (buildBindIfaceTree
// / flatTreeFromSets), never NewParser (CLAUDE.md "Testing flat set syntax").

// TestSecureTunnelBindIfaceInvalidRejectedAtCommit proves a non-canonical
// bind-interface is hard-rejected at strict commit with an actionable message.
//
// FAIL-ON-REVERT: reverting the id-0 arm in
// validateSecureTunnelBindInterfaceAST back to a bare `continue` (dropping the
// `invalid` append) makes these configs compile clean (no error) → this test
// expects an error and goes RED.
func TestSecureTunnelBindIfaceInvalidRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string // substrings expected in the commit error
	}{
		{
			name: "secure0 (non-st name)",
			cmds: []string{
				"set security ipsec vpn V bind-interface secure0",
			},
			want: []string{
				`bind-interface "secure0"`,
				"security ipsec vpn V",
				"st<N> or st<N>.<unit>",
				"#5297",
			},
		},
		{
			name: "st (no index)",
			cmds: []string{
				"set security ipsec vpn V bind-interface st",
			},
			want: []string{`bind-interface "st"`, "st<N> or st<N>.<unit>"},
		},
		{
			name: "stX (non-numeric index)",
			cmds: []string{
				"set security ipsec vpn V bind-interface stX",
			},
			want: []string{`bind-interface "stX"`, "st<N> or st<N>.<unit>"},
		},
		{
			name: "ge-0/0/0 (physical interface, not a secure tunnel)",
			cmds: []string{
				"set security ipsec vpn V bind-interface ge-0/0/0",
			},
			want: []string{`bind-interface "ge-0/0/0"`, "carries no traffic"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildBindIfaceTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted invalid bind-interface; want reject")
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing substring %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestSecureTunnelBindIfaceValidCommits proves a canonical bind-interface
// commits cleanly and compiles to the expected XFRM device name / if_id.
func TestSecureTunnelBindIfaceValidCommits(t *testing.T) {
	cases := []struct {
		name       string
		bind       string
		wantIfName string
		wantIfID   uint32
	}{
		{name: "bare st0", bind: "st0", wantIfName: "st0", wantIfID: 1},
		{name: "st0.1 unit", bind: "st0.1", wantIfName: "st0.1", wantIfID: 2},
		{name: "st1.5 unit", bind: "st1.5", wantIfName: "st1.5", wantIfID: 1<<16 | 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildBindIfaceTree(t,
				"set security ipsec vpn V bind-interface "+tc.bind)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid bind-interface %q: %v", tc.bind, err)
			}
			vpn := cfg.Security.IPsec.VPNs["V"]
			if vpn == nil {
				t.Fatalf("vpn V not compiled")
			}
			if vpn.BindInterface != tc.bind {
				t.Fatalf("BindInterface = %q, want %q", vpn.BindInterface, tc.bind)
			}
			name, ifID := XFRMIfNameAndID(vpn.BindInterface)
			if name != tc.wantIfName || ifID != tc.wantIfID {
				t.Errorf("XFRMIfNameAndID(%q) = (%q, %d), want (%q, %d)",
					tc.bind, name, ifID, tc.wantIfName, tc.wantIfID)
			}
		})
	}
}

// TestSecureTunnelBindIfaceInvalidLenientWarns proves the tolerant
// load/peer-sync path downgrades an invalid bind-interface to a warning and
// still compiles — a config an older binary silently accepted must still BOOT
// (#1960), not fail closed.
func TestSecureTunnelBindIfaceInvalidLenientWarns(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ipsec vpn V bind-interface secure0")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected invalid bind-interface (want warn): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `bind-interface "secure0"`) && strings.Contains(w, "#5297") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no invalid bind-interface warning; got %v", cfg.Warnings)
	}
}

// TestSecureTunnelBindIfaceInvalidSchemaRejected proves the #1319 typed-leaf
// commit-check layer (SchemaValidate) independently rejects a non-canonical
// bind-interface naming the offending value, and accepts every canonical form.
//
// FAIL-ON-REVERT: dropping the valueType/validator from the `bind-interface`
// schema leaf makes SchemaValidate return nil for "secure0" → RED.
func TestSecureTunnelBindIfaceInvalidSchemaRejected(t *testing.T) {
	bad := flatTreeFromSets(t, "set security ipsec vpn V bind-interface secure0")
	err := SchemaValidate(bad)
	if err == nil || !strings.Contains(err.Error(), "secure0") {
		t.Fatalf("SchemaValidate must reject invalid bind-interface naming the value, got: %v", err)
	}
	for _, good := range []string{"st0", "st0.1", "st1.5"} {
		ok := flatTreeFromSets(t, "set security ipsec vpn V bind-interface "+good)
		if err := SchemaValidate(ok); err != nil {
			t.Errorf("SchemaValidate rejected valid bind-interface %q: %v", good, err)
		}
	}
}

// TestSecureTunnelBindIfaceCollisionStillRejected_5297NonRegression proves the
// #5297 invalid-name arm did NOT disturb the #2933 if_id-collision arm: two
// VALID, distinct aliases sharing one non-zero if_id (st0 + st0.0) are still
// hard-rejected as a collision (naming the shared if_id), not swallowed by the
// new invalid-name path (which fires only for if_id 0).
func TestSecureTunnelBindIfaceCollisionStillRejected_5297NonRegression(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ipsec vpn V1 bind-interface st0",
		"set security ipsec vpn V2 bind-interface st0.0",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted colliding valid aliases; want #2933 collision reject")
	}
	if !strings.Contains(err.Error(), "if_id 1") || !strings.Contains(err.Error(), "#2933") {
		t.Errorf("collision error changed shape (#2933 regression): %q", err.Error())
	}
}
