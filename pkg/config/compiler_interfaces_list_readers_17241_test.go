package config

import (
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// #17241: the VRRP virtual-address/virtual-inet6-address reader and the
// WireGuard allowed-ips reader were hand-rolled copies of the pre-#6714
// multi-value reader: each read Keys[1:] of the leaf itself plus ONLY
// Keys[0]/Name() of each child, so the packed braced spelling
// `virtual-address { a b; }` / `allowed-ips { a b; }` (one child carrying
// two keys) silently dropped the second value. Both now read through
// firewallMatchValues (the #6714 single source). These tests pin parity
// across every authored spelling BEFORE/AFTER the refactor and are
// fail-on-revert: restoring either Keys[0]/Name()-only child loop drops
// the second packed value and fails the "braced packed" row.

func vrrpVIPs17241(t *testing.T, cfg *Config) []string {
	t.Helper()
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, u := range ifc.Units {
			for _, g := range u.VRRPGroups {
				out := append([]string(nil), g.VirtualAddresses...)
				sort.Strings(out)
				return out
			}
		}
	}
	t.Fatalf("no VRRP group compiled")
	return nil
}

func wgAllowed17241(t *testing.T, cfg *Config) []string {
	t.Helper()
	tc := wgTunnel(t, cfg, "wg0")
	if len(tc.WgPeers) != 1 {
		t.Fatalf("WgPeers=%d want 1", len(tc.WgPeers))
	}
	out := append([]string(nil), tc.WgPeers[0].AllowedIPs...)
	sort.Strings(out)
	return out
}

func TestVRRPWGListReaderParity17241(t *testing.T) {
	v4pre := "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { vrrp-group 1 { priority 150; "
	v4post := " } } } } } }"
	v6pre := "interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-inet6-group 1 { priority 150; "
	v6post := " } } } } } }"
	wgpre := "interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { "
	wgpost := " } } } } }"

	type row struct {
		name string
		src  string
		kind string // "vrrp" or "wg"
		want []string
	}
	rows := []row{
		// VRRP v4 virtual-address: every spelling must yield both VIPs.
		{"vrrp-v4 one-per-child", v4pre + "virtual-address { 10.0.1.100/24; 10.0.1.101/24; }" + v4post, "vrrp", []string{"10.0.1.100/24", "10.0.1.101/24"}},
		{"vrrp-v4 braced packed", v4pre + "virtual-address { 10.0.1.100/24 10.0.1.101/24; }" + v4post, "vrrp", []string{"10.0.1.100/24", "10.0.1.101/24"}},
		{"vrrp-v4 bracket", v4pre + "virtual-address [ 10.0.1.100/24 10.0.1.101/24 ];" + v4post, "vrrp", []string{"10.0.1.100/24", "10.0.1.101/24"}},
		{"vrrp-v4 repeated leaf", v4pre + "virtual-address 10.0.1.100/24; virtual-address 10.0.1.101/24;" + v4post, "vrrp", []string{"10.0.1.100/24", "10.0.1.101/24"}},
		// VRRP v6 virtual-inet6-address shares the same case arm.
		{"vrrp-v6 one-per-child", v6pre + "virtual-inet6-address { 2001:db8::100/64; 2001:db8::101/64; }" + v6post, "vrrp", []string{"2001:db8::100/64", "2001:db8::101/64"}},
		{"vrrp-v6 braced packed", v6pre + "virtual-inet6-address { 2001:db8::100/64 2001:db8::101/64; }" + v6post, "vrrp", []string{"2001:db8::100/64", "2001:db8::101/64"}},
		{"vrrp-v6 bracket", v6pre + "virtual-inet6-address [ 2001:db8::100/64 2001:db8::101/64 ];" + v6post, "vrrp", []string{"2001:db8::100/64", "2001:db8::101/64"}},
		// WireGuard allowed-ips: every spelling must yield both prefixes.
		{"wg one-per-child", wgpre + "allowed-ips { 10.0.0.0/8; 192.168.0.0/16; }" + wgpost, "wg", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"wg braced packed", wgpre + "allowed-ips { 10.0.0.0/8 192.168.0.0/16; }" + wgpost, "wg", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"wg bracket", wgpre + "allowed-ips [ 10.0.0.0/8 192.168.0.0/16 ];" + wgpost, "wg", []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{"wg repeated leaf", wgpre + "allowed-ips 10.0.0.0/8; allowed-ips 192.168.0.0/16;" + wgpost, "wg", []string{"10.0.0.0/8", "192.168.0.0/16"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tree := parseHierText(t, r.src)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			var got []string
			if r.kind == "wg" {
				got = wgAllowed17241(t, cfg)
			} else {
				got = vrrpVIPs17241(t, cfg)
			}
			want := append([]string(nil), r.want...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("got %v want %v (second packed value dropped?)", got, want)
			}
			// Lenient must agree exactly (no warn-only divergence).
			lcfg, err := CompileConfigLenient(parseHierText(t, r.src))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var lgot []string
			if r.kind == "wg" {
				lgot = wgAllowed17241(t, lcfg)
			} else {
				lgot = vrrpVIPs17241(t, lcfg)
			}
			if !reflect.DeepEqual(lgot, got) {
				t.Fatalf("lenient %v != strict %v", lgot, got)
			}
		})
	}

	// Preservation pins for behaviours the old hand-rolled loops had that
	// firewallMatchValues deliberately changes / must not regress:
	// (a) WG: a NON-leaf child (option block) contributed nothing under the
	//     old IsLeaf guard; firewallMatchValues contributes its Keys, which
	//     for `10.0.0.0/8 { }` is exactly that one prefix — same result.
	t.Run("wg non-leaf child keeps its sole prefix", func(t *testing.T) {
		src := wgpre + "allowed-ips { 10.0.0.0/8 { } 192.168.0.0/16; }" + wgpost
		cfg, err := CompileConfig(parseHierText(t, src))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := wgAllowed17241(t, cfg); !slices.Equal(got, []string{"10.0.0.0/8", "192.168.0.0/16"}) {
			t.Fatalf("got %v want both prefixes", got)
		}
	})
	// (b) VRRP: duplicate VIPs still dedupe to a set (DedupeVRRPVIPs),
	//     including a duplicate introduced by the packed spelling.
	t.Run("vrrp packed duplicate dedupes", func(t *testing.T) {
		src := v4pre + "virtual-address { 10.0.1.100/24 10.0.1.100/24; }" + v4post
		cfg, err := CompileConfig(parseHierText(t, src))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if got := vrrpVIPs17241(t, cfg); !slices.Equal(got, []string{"10.0.1.100/24"}) {
			t.Fatalf("got %v want single deduped VIP", got)
		}
	})
	// (c) Flat-set spellings (separate set lines) still compile both values.
	t.Run("flat-set parity", func(t *testing.T) {
		vcfg, err := CompileConfig(buildTree(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 priority 150 virtual-address 10.0.1.100/24",
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 virtual-address 10.0.1.101/24",
		}))
		if err != nil {
			t.Fatalf("vrrp flat compile: %v", err)
		}
		if got := vrrpVIPs17241(t, vcfg); !slices.Equal(got, []string{"10.0.1.100/24", "10.0.1.101/24"}) {
			t.Fatalf("vrrp flat got %v", got)
		}
		wcfg, err := compileSet(t, []string{
			"set interfaces wg0 tunnel mode wireguard",
			"set interfaces wg0 tunnel wireguard listen-port 51820",
			"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
			"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 10.0.0.0/8",
			"set interfaces wg0 tunnel wireguard peer " + wgKeyB + " allowed-ips 192.168.0.0/16",
		})
		if err != nil {
			t.Fatalf("wg flat compile: %v", err)
		}
		if got := wgAllowed17241(t, wcfg); !slices.Equal(got, []string{"10.0.0.0/8", "192.168.0.0/16"}) {
			t.Fatalf("wg flat got %v", got)
		}
	})
}

// Census guard (#17241): the two named leaves must be read ONLY through
// firewallMatchValues. Any re-introduced hand-rolled child loop (a
// Keys[0]/Name()-only reader, in any spelling) beside either case is a
// new copy of the pre-#6714 pattern and fails here. We pin the exact
// single-source call shape at both sites.
func TestListReadersSingleSourced17241(t *testing.T) {
	src, err := os.ReadFile("compiler_interfaces.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, leaf := range []string{`"allowed-ips"`, `"virtual-address"`} {
		if !strings.Contains(text, leaf) {
			t.Fatalf("leaf case %s missing", leaf)
		}
	}
	// Both sites must append firewallMatchValues(prop)...
	if n := strings.Count(text, "firewallMatchValues(prop)"); n < 2 {
		t.Fatalf("firewallMatchValues(prop) callsites = %d, want >=2 (allowed-ips + virtual-address)", n)
	}
	// The old dropped-value spellings must be gone from the reader file.
	for _, bad := range []string{"vn.Keys[0]", "child.Name(); v != "} {
		if strings.Contains(text, bad) {
			t.Fatalf("hand-rolled Keys[0]/Name()-only child reader %q reintroduced in compiler_interfaces.go", bad)
		}
	}
}
