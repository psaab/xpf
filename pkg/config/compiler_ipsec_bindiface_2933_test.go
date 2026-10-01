package config

import (
	"strings"
	"testing"
)

// Tests for #2933: two VPNs that bind two DISTINCT secure-tunnel
// `bind-interface` strings deriving the SAME XFRM if_id (e.g.
// `bind-interface st0` and `bind-interface st0.0`, both if_id 1 via
// XFRMIfNameAndID) committed cleanly but collide at apply time — only one
// xfrm device can carry the if_id, so the #2929 routing guard refuses to
// create EITHER and both tunnels go down. The fix REJECTS the ambiguous
// alias pair at commit (strict CompileConfig) and WARNS on the tolerant
// load / peer-sync path (CompileConfigLenient).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never
// NewParser (the parser merges newline-separated set lines into one giant
// node).

func buildBindIfaceTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		// ParseSetCommand strips the leading "set" verb and returns the path
		// tokens (with quoting/bracket handling) ready for SetPath.
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestSecureTunnelBindIfaceCollisionRejectedAtCommit proves that an
// ambiguous-alias bind-interface pair (st0 vs st0.0, and equivalently
// st1.0 vs st1) is hard-rejected at commit. Reverting
// validateSecureTunnelBindInterfaceAST to `return nil, nil` turns these
// cases GREEN (no error) and so RED.
func TestSecureTunnelBindIfaceCollisionRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string // substrings expected in the commit error
	}{
		{
			name: "st0 vs st0.0",
			cmds: []string{
				"set security ipsec vpn V1 bind-interface st0",
				"set security ipsec vpn V2 bind-interface st0.0",
			},
			want: []string{
				`bind-interface "st0"`,
				`bind-interface "st0.0"`,
				"if_id 1",
				"#2933",
			},
		},
		{
			name: "st1 vs st1.0 (unit reversed)",
			cmds: []string{
				"set security ipsec vpn A bind-interface st1.0",
				"set security ipsec vpn B bind-interface st1",
			},
			want: []string{
				`bind-interface "st1"`,
				`bind-interface "st1.0"`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildBindIfaceTree(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted ambiguous bind-interface pair; want reject")
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing substring %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestSecureTunnelBindIfaceUnambiguousCommits proves the alias-collision gate
// remains surgical: distinct units and distinct devices commit cleanly, and
// same-bind VPNs commit only when their rendered traffic-selector unions are
// provably disjoint (#11380).
func TestSecureTunnelBindIfaceUnambiguousCommits(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "distinct units st0.0 + st0.1",
			cmds: []string{
				"set security ipsec vpn V1 bind-interface st0.0",
				"set security ipsec vpn V2 bind-interface st0.1",
			},
		},
		{
			name: "distinct devices st0 + st1",
			cmds: []string{
				"set security ipsec vpn V1 bind-interface st0",
				"set security ipsec vpn V2 bind-interface st1",
			},
		},
		{
			name: "same bind with disjoint rendered selectors (#11380)",
			cmds: []string{
				"set security ipsec vpn V1 bind-interface st0.0",
				"set security ipsec vpn V1 traffic-selector to-peer-a local-ip 10.0.0.0/24",
				"set security ipsec vpn V1 traffic-selector to-peer-a remote-ip 198.51.100.0/24",
				"set security ipsec vpn V2 bind-interface st0.0",
				"set security ipsec vpn V2 traffic-selector to-peer-b local-ip 10.0.0.0/24",
				"set security ipsec vpn V2 traffic-selector to-peer-b remote-ip 203.0.113.0/24",
			},
		},
		{
			name: "single VPN bare st0",
			cmds: []string{
				"set security ipsec vpn V1 bind-interface st0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildBindIfaceTree(t, tc.cmds...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig rejected unambiguous bind-interface config: %v", err)
			}
		})
	}
}

// TestSecureTunnelBindIfaceCollisionLenientWarns proves the tolerant
// load/peer-sync path downgrades the collision to a warning and still
// compiles, so an already-persisted config an older binary accepted still
// boots (#1960 fail-closed-on-load class).
func TestSecureTunnelBindIfaceCollisionLenientWarns(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ipsec vpn V1 bind-interface st0",
		"set security ipsec vpn V2 bind-interface st0.0",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected colliding bind-interface (want warn): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bind-interface") && strings.Contains(w, "if_id 1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no bind-interface collision warning; got %v", cfg.Warnings)
	}
}
