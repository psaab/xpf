package config

import (
	"strings"
	"testing"
)

// Tests for #12827: validateZoneInterfaceDefinedStrict's logical-unit check
// (#11433) keyed existence on the configured `interfaces` Units map alone.
// A base made referenceable only by an IPsec bind-interface (st0) or by the
// daemon-materialized loopback (lo0) therefore (a) FALSE-REJECTED its bound
// unit when an explicit base stanza existed without that unit, and
// (b) FALSE-ACCEPTED any unit of the base when no stanza existed at all,
// because the unit test was skipped. The gate must instead ask whether the
// exact unit is configured, is the bound secure-tunnel unit, or is the
// materialized lo0.0.

func TestZoneInterfaceDynamicUnitFailsCommit12827(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "unbound st0.99 under st0.0 VPN, no interfaces st0 stanza",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set security zones security-zone vpn interfaces st0.99",
			},
		},
		{
			name: "unbound st0.1 with interfaces st0 unit 0 authored",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set interfaces st0 unit 0 family inet address 10.9.0.1/30",
				"set security zones security-zone vpn interfaces st0.1",
			},
		},
		{
			name: "lo0.1 with interfaces lo0 unit 0 authored",
			cmds: []string{
				"set interfaces lo0 unit 0 family inet address 127.0.0.1/8",
				"set security zones security-zone host interfaces lo0.1",
			},
		},
		{
			name: "lo0.1 without interfaces lo0 stanza",
			cmds: []string{
				"set security zones security-zone host interfaces lo0.1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject an unbound logical unit, got nil error")
			}
			for _, want := range []string{"logical unit", "not configured"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

func TestZoneInterfaceDynamicUnitCommits12827(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "bound st0.0 with interfaces st0 unit 9 authored",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set interfaces st0 unit 9 family inet address 10.9.0.1/30",
				"set security zones security-zone vpn interfaces st0.0",
			},
		},
		{
			name: "bound st0.0 expressed as bare bind st0",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0",
				"set security zones security-zone vpn interfaces st0.0",
			},
		},
		{
			name: "bound st0.1 with no interfaces st0 stanza",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.1",
				"set security zones security-zone vpn interfaces st0.1",
			},
		},
		{
			name: "lo0.0 with interfaces lo0 unit 9 authored",
			cmds: []string{
				"set interfaces lo0 unit 9 family inet address 127.0.0.9/8",
				"set security zones security-zone host interfaces lo0.0",
			},
		},
		{
			name: "canonical alias st0.00 of bound st0.0",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set security zones security-zone vpn interfaces st0.00",
			},
		},
		{
			name: "configured unit of bound base still accepted",
			cmds: []string{
				"set security ipsec vpn myvpn bind-interface st0.0",
				"set interfaces st0 unit 7 family inet address 10.9.0.1/30",
				"set security zones security-zone vpn interfaces st0.7",
			},
		},
		{
			name: "ordinary configured physical unit unchanged",
			cmds: []string{
				"set interfaces ge-0/0/0 unit 3 family inet sampling input",
				"set security zones security-zone trust interfaces ge-0/0/0.3",
			},
		},
		{
			name: "wireguard implicit unit 0 unchanged",
			cmds: []string{
				"set interfaces wg0 tunnel source 192.0.2.1",
				"set security zones security-zone vpn interfaces wg0.0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected a valid dynamic/configured unit: %v", err)
			}
		})
	}
}

func TestZoneInterfaceDynamicUnitWarnsOnLenientLoad12827(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0.99",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must warn rather than reject an unbound zone unit: %v", err)
	}
	for _, want := range []string{
		"zone interface defined (downgraded to warning on tolerant path)",
		"vpn", "st0.99", "logical unit",
	} {
		found := false
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no warning contains %q: %v", want, cfg.Warnings)
		}
	}
}
