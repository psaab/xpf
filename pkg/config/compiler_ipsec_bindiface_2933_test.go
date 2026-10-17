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

// #14451: hierarchical helper — flat `set` cannot express duplicate
// bind-interface leaves (SetPath collapses to last value), so these
// fixtures must be hierarchical text via NewParser.
func buildBindIfaceHierTree14451(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse hierarchical bind-interface fixture: %v", errs)
	}
	return tree
}

// TestSecureTunnelBindIfaceDuplicateOccurrenceCollision14451 proves the
// admission gate validates EVERY bind-interface occurrence, not only the
// first. V1's first value st0.1 is distinct from V2's st0.0, but the
// compiler installs V1's LAST value st0, which collides with st0.0 on
// if_id 1. Pre-fix the gate reads only the first and accepts.
func TestSecureTunnelBindIfaceDuplicateOccurrenceCollision14451(t *testing.T) {
	src := `
security {
    ipsec {
        vpn V1 {
            bind-interface st0.1;
            bind-interface st0;
        }
        vpn V2 {
            bind-interface st0.0;
        }
    }
}
`
	tree := buildBindIfaceHierTree14451(t, src)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted duplicate bind-interface collision (installed st0 vs st0.0); want reject")
	}
	for _, sub := range []string{`bind-interface "st0"`, `bind-interface "st0.0"`, "if_id 1", "#2933"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q missing substring %q", err.Error(), sub)
		}
	}
	// Lenient path warns on the same installed-value collision.
	tree2 := buildBindIfaceHierTree14451(t, src)
	cfg, err := CompileConfigLenient(tree2)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected duplicate collision (want warn): %v", err)
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

// TestSecureTunnelBindIfaceDuplicateSecondInvalid14451 proves a valid
// first bind-interface does not hide an invalid second (installed) one:
// the #5297 arm must see every occurrence.
func TestSecureTunnelBindIfaceDuplicateSecondInvalid14451(t *testing.T) {
	src := `
security {
    ipsec {
        vpn V1 {
            bind-interface st0;
            bind-interface ge-0/0/0;
        }
    }
}
`
	tree := buildBindIfaceHierTree14451(t, src)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted second invalid bind-interface ge-0/0/0; want reject")
	}
	for _, sub := range []string{`bind-interface "ge-0/0/0"`, "#5297"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q missing substring %q", err.Error(), sub)
		}
	}
}

// TestSecureTunnelBindIfaceDuplicateControls14451 pins unchanged
// behaviour: single bind-interface, harmless same-value repeats, and a
// first-invalid/second-valid occurrence set (still rejected, now
// because the invalid value is in the validated set).
func TestSecureTunnelBindIfaceDuplicateControls14451(t *testing.T) {
	t.Run("same-value repeat lenient compiles (no collision warning)", func(t *testing.T) {
		// NOTE: strict CompileConfig on a bare-vpn fixture is also gated
		// by the unrelated #14139 pre-shared-key check (bare VPNs have no
		// PSK), which fires after the bind-interface gate; existing
		// bare-vpn valid controls on master fail there too. Lenient
		// compile exercises the bind-interface gate's own verdict: a
		// same-value repeat must produce NO #2933 collision warning and
		// the installed bind-interface stays st0.1.
		tree := buildBindIfaceHierTree14451(t, `
security {
    ipsec {
        vpn V1 {
            bind-interface st0.1;
            bind-interface st0.1;
        }
        vpn V2 {
            bind-interface st0.0;
        }
    }
}
`)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient rejected same-value repeat: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#2933") || strings.Contains(w, "alias collision") {
				t.Fatalf("same-value repeat produced collision warning: %q", w)
			}
		}
		if got := cfg.Security.IPsec.VPNs["V1"].BindInterface; got != "st0.1" {
			t.Fatalf("V1 installed bind-interface = %q, want st0.1", got)
		}
		if got := cfg.Security.IPsec.VPNs["V2"].BindInterface; got != "st0.0" {
			t.Fatalf("V2 installed bind-interface = %q, want st0.0", got)
		}
	})
	t.Run("first invalid second valid still rejects naming invalid", func(t *testing.T) {
		tree := buildBindIfaceHierTree14451(t, `
security {
    ipsec {
        vpn V1 {
            bind-interface ge-0/0/0;
            bind-interface st0;
        }
    }
}
`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted bind-interface set containing ge-0/0/0; want reject")
		}
		if !strings.Contains(err.Error(), `bind-interface "ge-0/0/0"`) {
			t.Errorf("error %q missing invalid bind-interface name", err.Error())
		}
	})
}
