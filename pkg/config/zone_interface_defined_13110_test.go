package config

import (
	"strings"
	"testing"
)

// Tests for #13110 (D1-05): validateZoneInterfaceDefinedStrict (a) accepted a
// BARE secure-tunnel zone member (`interfaces st0`) when only a DOTTED
// `bind-interface st0.<N>` existed — zoneReferenceableInterfaceBases strips the
// bind to base "st0", so the bare ref passed, yet no device named st0 is ever
// materialized (bindInterfaceOwnsRef: a dotted bind never owns a bare ref),
// leaving st0.<N> unzoned on a clean commit; and (b) false-rejected #9821
// declared dotted interfaces (`interfaces { p.0 { unit 1 } }` zoned as p.0.1)
// because the defined check sliced the ref at the FIRST dot (known["p"])
// while `known` stores the declared name "p.0" and SplitInterfaceUnitRef
// already resolves ref.Base == "p.0" with declared-first precedence.

func TestZoneInterfaceBareSt0OnlyDottedBindFailsCommit13110(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "bare st0 with bind-interface st0.0",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set security zones security-zone vpn interfaces st0",
			},
		},
		{
			name: "bare st0 with bind-interface st0.5",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.5",
				"set security zones security-zone vpn interfaces st0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject bare st0 when only a dotted bind-interface exists, got nil error")
			}
			for _, want := range []string{"vpn", "st0", "not defined under"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

func TestZoneInterfaceBareSt0OnlyDottedBindWarnsOnLenientLoad13110(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must warn rather than reject a bare st0 with only a dotted bind: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone interface defined (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded zone-interface-defined warning, got warnings: %v", cfg.Warnings)
	}
}

func TestZoneInterfaceDeclaredDottedAndBareBindCommit13110(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "declared dotted interface zoned by exact unit p.0.1",
			cmds: []string{
				"set interfaces p.0 unit 1 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces p.0.1",
			},
		},
		{
			name: "declared dotted interface zoned bare as p.0",
			cmds: []string{
				"set interfaces p.0 unit 1 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces p.0",
			},
		},
		{
			name: "bare st0 with bare bind-interface st0",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0",
				"set security zones security-zone vpn interfaces st0",
			},
		},
		{
			name: "bare st0 with interfaces st0 stanza and dotted bind",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set interfaces st0 unit 0 family inet address 10.9.0.1/30",
				"set security zones security-zone vpn interfaces st0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("expected valid config to commit cleanly, got: %v", err)
			}
		})
	}
}
