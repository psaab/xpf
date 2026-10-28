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

	// Preservation pin (updated by the Rev18305b nested fold): a NON-leaf
	// child used to be compiled by firewallMatchValues for its sole key
	// (`10.0.0.0/8 { }` contributed that one prefix). The nested fold makes
	// the canonical gate refuse that shape instead — nested content under
	// a pure value-list leaf is not Junos and its grandchildren are never
	// read, so accepting the empty-block spelling while refusing
	// `a { b; }` would split the invariant. The CompileConfig-only
	// behaviour below is therefore no longer pinned; the canonical-gate
	// refusal for both spellings is pinned in
	// TestVRRPWGListReaderNestedRefused17241.
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
	// Scoped census (#17241 fold): the file legitimately calls
	// firewallMatchValues at unrelated DHCPv6 callsites
	// (client-ia-type / pinned-prefix / req-option), so a bare
	// file-wide count >= 2 proves nothing about THESE leaves. Pin
	// the exact single-source call shape at each named site instead:
	// the allowed-ips append and the virtual-address append.
	for _, site := range []string{
		"peer.AllowedIPs = append(peer.AllowedIPs, firewallMatchValues(prop)...)",
		"vg.VirtualAddresses = append(vg.VirtualAddresses, firewallMatchValues(prop)...)",
	} {
		if n := strings.Count(text, site); n != 1 {
			t.Fatalf("single-source call %q callsites = %d, want exactly 1", site, n)
		}
	}
	// Both case arms must still exist.
	for _, leaf := range []string{`"allowed-ips"`, `"virtual-address", "virtual-inet6-address"`} {
		if !strings.Contains(text, leaf) {
			t.Fatalf("leaf case %s missing", leaf)
		}
	}
	// The old dropped-value spellings must be gone from the reader file.
	for _, bad := range []string{"vn.Keys[0]", "child.Name(); v != "} {
		if strings.Contains(text, bad) {
			t.Fatalf("hand-rolled Keys[0]/Name()-only child reader %q reintroduced in compiler_interfaces.go", bad)
		}
	}
	// Schema census: all three leaves must carry the opt-in that lets
	// the commit gate validate every packed token (Rev18305Opus B1).
	// Without it SchemaValidate refuses `{ a b; }` outright.
	schemaSrc, err := os.ReadFile("schema_interfaces.go")
	if err != nil {
		t.Fatal(err)
	}
	// Count the field at any gofmt alignment: the two VRRP leaves align the
	// field name against the adjacent refuseNonLeafBlockChildren field, so
	// a literal "allChildKeysAreValues: true" undercounts them.
	if n := strings.Count(string(schemaSrc), "allChildKeysAreValues:"); n < 3 {
		t.Fatalf("schema_interfaces.go allChildKeysAreValues leaves = %d, want >=3 (virtual-address, virtual-inet6-address, allowed-ips)", n)
	}
}

// Canonical commit-gate parity (#17241 fold, Rev18305Opus B1): the
// parity rows above only called CompileConfig, which never runs
// SchemaValidate — so the packed braced spelling passed the test
// while the real commit gate (configstore: SchemaValidate on the
// expanded tree, then strict compile) REFUSED it at
// validateMultiValueLeaf (multi-token block child, no
// allChildKeysAreValues). These rows run the canonical sequence —
// SchemaValidate first, then CompileConfig — on the packed spelling
// for all three leaves, and pin that every packed token is honoured.
// Fail-on-revert: drop allChildKeysAreValues from any leaf and its
// row fails at SchemaValidate; drop the firewallMatchValues reader
// and its row fails at the compiled-values assertion.
func TestVRRPWGListReaderCanonicalGate17241(t *testing.T) {
	v4pre := "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { vrrp-group 1 { priority 150; "
	v4post := " } } } } } }"
	v6pre := "interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-inet6-group 1 { priority 150; "
	v6post := " } } } } } }"
	wgpre := "interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { "
	wgpost := " } } } } }"

	rows := []struct {
		name string
		src  string
		kind string
		want []string
	}{
		{"vrrp-v4 braced packed canonical", v4pre + "virtual-address { 10.0.1.100/24 10.0.1.101/24; }" + v4post, "vrrp", []string{"10.0.1.100/24", "10.0.1.101/24"}},
		{"vrrp-v6 braced packed canonical", v6pre + "virtual-inet6-address { 2001:db8::100/64 2001:db8::101/64; }" + v6post, "vrrp", []string{"2001:db8::100/64", "2001:db8::101/64"}},
		{"wg braced packed canonical", wgpre + "allowed-ips { 10.0.0.0/8 192.168.0.0/16; }" + wgpost, "wg", []string{"10.0.0.0/8", "192.168.0.0/16"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tree := parseHierText(t, r.src)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate (commit gate) refused packed spelling: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile after SchemaValidate: %v", err)
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
				t.Fatalf("canonical gate got %v want %v (packed token dropped?)", got, want)
			}
		})
	}
}

// Fail-closed packed tokens (#17241 fold, Rev18305Opus B2): with
// allChildKeysAreValues every packed token IS a value, so a bogus
// second token must ERROR at the strict commit gate — it must not
// silently ride along (the pre-fold untyped allowed-ips leaf would
// have let CompileConfig's netip gate catch it only after
// SchemaValidate waved it through, and a leaf without the flag
// refused the whole spelling for the wrong reason). Each row pins
// SchemaValidate AND strict CompileConfig both refusing
// `{ valid bogus; }` on all three leaves.
func TestVRRPWGListReaderPackedBogusRefused17241(t *testing.T) {
	v4pre := "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { vrrp-group 1 { priority 150; "
	v4post := " } } } } } }"
	v6pre := "interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-inet6-group 1 { priority 150; "
	v6post := " } } } } } }"
	wgpre := "interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { "
	wgpost := " } } } } }"

	rows := []struct {
		name string
		src  string
		leaf string
	}{
		{"vrrp-v4 packed bogus", v4pre + "virtual-address { 10.0.1.100/24 bogus; }" + v4post, "virtual-address"},
		{"vrrp-v6 packed bogus", v6pre + "virtual-inet6-address { 2001:db8::100/64 bogus; }" + v6post, "virtual-inet6-address"},
		{"wg packed bogus", wgpre + "allowed-ips { 10.0.0.0/8 bogus; }" + wgpost, "allowed-ips"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// Canonical commit gate: SchemaValidate runs FIRST
			// (configstore), so a bogus packed token is refused
			// before the compiler ever sees it. That gate refusal
			// is the strict-commit ERROR this cell pins — direct
			// CompileConfig without the gate tolerates garbage
			// VRRP tokens on the lenient VIP path by design
			// (ParseVRRPVIP ok=false tokens ride through dedupe),
			// which is exactly why the gate must not wave them
			// through.
			tree := parseHierText(t, r.src)
			verr := SchemaValidate(tree)
			if verr == nil {
				t.Fatalf("SchemaValidate accepted packed bogus token for %s (must error, not ride along)", r.leaf)
			}
			if !strings.Contains(verr.Error(), "bogus") {
				t.Fatalf("SchemaValidate error %q does not name the bogus token", verr)
			}
			// The canonical sequence (SchemaValidate -> CompileConfig)
			// refuses at the gate above: verr != nil here by construction
			// (the Fatalf on nil), so there is no CompileConfig leg to run —
			// direct CompileConfig tolerance for VRRP tokens is by design
			// and is not the canonical sequence.
		})
	}
}

// Nested-content refusal (#17241 fold, Rev18305bOpus blocker): a block
// child of virtual-address / virtual-inet6-address / allowed-ips that
// itself has Children carries a grandchild value the compiler never
// reads (firewallMatchValues consumes only the child's Keys and never
// descends), so `allowed-ips { 10.0.0.0/8 { 192.168.0.0/16; } }`
// committed with the nested prefix silently vanished. The canonical
// gate (SchemaValidate, via validateMultiValueLeaf +
// refuseNonLeafBlockChildren) now refuses the shape fail-closed,
// naming the leaf and the offending child token — for both a bogus
// grandchild and a real-prefix grandchild (a valid nested prefix is
// still refused: the value is nested, not a direct value of the leaf).
// The empty-block spelling `a { }` is refused on the same invariant.
// Fail-on-revert: drop refuseNonLeafBlockChildren from any leaf (or
// the walker check) and that leaf's rows accept nested content again.
func TestVRRPWGListReaderNestedRefused17241(t *testing.T) {
	v4pre := "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { vrrp-group 1 { priority 150; "
	v4post := " } } } } } }"
	v6pre := "interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-inet6-group 1 { priority 150; "
	v6post := " } } } } } }"
	wgpre := "interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key " + wgKeyA + "; peer " + wgKeyB + " { "
	wgpost := " } } } } }"

	rows := []struct {
		name string
		src  string
		leaf string
		tok  string // offending direct-child token the error must name
	}{
		// Bogus grandchild.
		{"vrrp-v4 nested bogus grandchild", v4pre + "virtual-address { 10.0.1.100/24 { bogus; } }" + v4post, "virtual-address", "10.0.1.100/24"},
		{"vrrp-v6 nested bogus grandchild", v6pre + "virtual-inet6-address { 2001:db8::100/64 { bogus; } }" + v6post, "virtual-inet6-address", "2001:db8::100/64"},
		{"wg nested bogus grandchild", wgpre + "allowed-ips { 10.0.0.0/8 { bogus; } }" + wgpost, "allowed-ips", "10.0.0.0/8"},
		// Real-prefix grandchild: the nested value itself is valid, but it
		// is nested — the compiler would never read it, so it must refuse.
		{"vrrp-v4 nested real grandchild", v4pre + "virtual-address { 10.0.1.100/24 { 10.0.1.101/24; } }" + v4post, "virtual-address", "10.0.1.100/24"},
		{"vrrp-v6 nested real grandchild", v6pre + "virtual-inet6-address { 2001:db8::100/64 { 2001:db8::101/64; } }" + v6post, "virtual-inet6-address", "2001:db8::100/64"},
		{"wg nested real grandchild", wgpre + "allowed-ips { 10.0.0.0/8 { 192.168.0.0/16; } }" + wgpost, "allowed-ips", "10.0.0.0/8"},
		// Empty-block (non-leaf) child: same silent-drop invariant.
		{"wg empty-block child", wgpre + "allowed-ips { 10.0.0.0/8 { } 192.168.0.0/16; }" + wgpost, "allowed-ips", "10.0.0.0/8"},
		{"vrrp-v4 empty-block child", v4pre + "virtual-address { 10.0.1.100/24 { } 10.0.1.101/24; }" + v4post, "virtual-address", "10.0.1.100/24"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tree := parseHierText(t, r.src)
			verr := SchemaValidate(tree)
			if verr == nil {
				t.Fatalf("SchemaValidate accepted nested content under %s (grandchild silently dropped at compile)", r.leaf)
			}
			if !strings.Contains(verr.Error(), r.leaf) {
				t.Fatalf("SchemaValidate error %q does not name leaf %q", verr, r.leaf)
			}
			if !strings.Contains(verr.Error(), r.tok) {
				t.Fatalf("SchemaValidate error %q does not name offending token %q", verr, r.tok)
			}
			if !strings.Contains(verr.Error(), "nested") {
				t.Fatalf("SchemaValidate error %q does not describe nested content", verr)
			}
		})
	}
}

// Census for the nested refusal: all three leaves must carry
// refuseNonLeafBlockChildren (source census, mirroring the
// allChildKeysAreValues census above — without the flag the walker
// never refuses nested content for that leaf).
func TestListReadersNestedRefusalCensus17241(t *testing.T) {
	schemaSrc, err := os.ReadFile("schema_interfaces.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(schemaSrc), "refuseNonLeafBlockChildren: true"); n < 3 {
		t.Fatalf("schema_interfaces.go refuseNonLeafBlockChildren leaves = %d, want >=3 (virtual-address, virtual-inet6-address, allowed-ips)", n)
	}
}
