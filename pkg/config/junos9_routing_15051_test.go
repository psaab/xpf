package config

import (
	"strings"
	"testing"
)

// #15051 (A20-01): Junos `$9$` routing authentication keys were not
// decoded — the obfuscated blob committed strict-clean and was
// installed verbatim as the live key, so BGP/OSPF/IS-IS/RIP
// authenticated adjacencies to a real peer never formed. The fix moves
// the `$9$` decoder into pkg/config and applies it at compile to every
// Junos-reversible routing secret leaf; a malformed `$9$` is refused
// at strict commit.
//
// junos9Blob15051 is the known-answer blob from the IKE probe
// (pkg/ipsec TestGenerateConfig_JunosObfuscatedPSK): it decodes to
// junos9Plain15051.
const (
	junos9Blob15051  = "$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW"
	junos9Plain15051 = "QZ1agnL21L"
	junos9Bad15051   = "$9$garbage"
)

// TestJunos9RoutingKeysDecodedAtCompile15051 is the primary
// fail-on-revert guard: every routing auth leaf below carries the
// `$9$` blob and must compile to the plaintext. On origin/master the
// blob survives verbatim, so every assertion fires.
func TestJunos9RoutingKeysDecodedAtCompile15051(t *testing.T) {
	tree := buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"" + junos9Blob15051 + "\"",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key \"" + junos9Blob15051 + "\"",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password \"" + junos9Blob15051 + "\"",
		"set protocols isis authentication-type md5",
		"set protocols isis authentication-key \"" + junos9Blob15051 + "\"",
		"set protocols isis interface ge-0/0/2.0 authentication-type md5",
		"set protocols isis interface ge-0/0/2.0 authentication-key \"" + junos9Blob15051 + "\"",
		"set protocols rip authentication-type md5",
		"set protocols rip authentication-key \"" + junos9Blob15051 + "\"",
		"set protocols rip neighbor ge-0/0/3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig with valid $9$ keys: %v", err)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("BGP neighbors = %d, want 1 (fixture live?)", len(cfg.Protocols.BGP.Neighbors))
	}
	if got := cfg.Protocols.BGP.Neighbors[0].AuthPassword.Reveal(); got != junos9Plain15051 {
		t.Errorf("BGP AuthPassword = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	var md5Iface, simpleIface *OSPFInterface
	for _, area := range cfg.Protocols.OSPF.Areas {
		for _, iface := range area.Interfaces {
			switch iface.Name {
			case "ge-0/0/0.0":
				md5Iface = iface
			case "ge-0/0/1.0":
				simpleIface = iface
			}
		}
	}
	if md5Iface == nil || simpleIface == nil {
		t.Fatalf("OSPF interfaces missing (md5=%v simple=%v) — fixture dead", md5Iface != nil, simpleIface != nil)
	}
	if got := md5Iface.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("OSPF md5 AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	if len(md5Iface.AuthMD5Keys) != 1 || md5Iface.AuthMD5Keys[0].Key.Reveal() != junos9Plain15051 {
		t.Errorf("OSPF AuthMD5Keys = %+v, want one key decoded to %q (#15051)", md5Iface.AuthMD5Keys, junos9Plain15051)
	}
	if got := simpleIface.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("OSPF simple AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	if got := cfg.Protocols.ISIS.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("IS-IS AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	if len(cfg.Protocols.ISIS.Interfaces) != 1 {
		t.Fatalf("IS-IS interfaces = %d, want 1", len(cfg.Protocols.ISIS.Interfaces))
	}
	if got := cfg.Protocols.ISIS.Interfaces[0].AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("IS-IS interface AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	if got := cfg.Protocols.RIP.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("RIP AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
}

// TestJunos9RoutingKeysDecodedInRoutingInstance15051 pins the
// routing-instance walk: the same `$9$` leaf inside a VRF must decode
// too (the per-instance protocols render through the same FRR sites).
func TestJunos9RoutingKeysDecodedInRoutingInstance15051(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A protocols bgp local-as 65001",
		"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"" + junos9Blob15051 + "\"",
		"set routing-instances VRF-A protocols rip authentication-type md5",
		"set routing-instances VRF-A protocols rip authentication-key \"" + junos9Blob15051 + "\"",
		"set routing-instances VRF-A protocols rip neighbor ge-0/0/3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig RI $9$: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].BGP == nil ||
		len(cfg.RoutingInstances[0].BGP.Neighbors) != 1 {
		t.Fatalf("RI BGP fixture dead: %+v", cfg.RoutingInstances)
	}
	ri := cfg.RoutingInstances[0]
	if got := ri.BGP.Neighbors[0].AuthPassword.Reveal(); got != junos9Plain15051 {
		t.Errorf("RI BGP AuthPassword = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
	if ri.RIP == nil {
		t.Fatal("RI RIP fixture dead")
	}
	if got := ri.RIP.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("RI RIP AuthKey = %q, want decoded %q (#15051)", got, junos9Plain15051)
	}
}

// TestJunos9MalformedRefusedAtStrictCommit15051 pins the acceptance
// criterion `$9$garbage` is a commit error, at every named site, with
// the leaf named and the secret never echoed.
func TestJunos9MalformedRefusedAtStrictCommit15051(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		leaf  string
	}{
		{"bgp", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"" + junos9Bad15051 + "\"",
		}, "authentication-key"},
		{"ospf-md5", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key \"" + junos9Bad15051 + "\"",
		}, "authentication"},
		{"ospf-simple", []string{
			"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication simple-password \"" + junos9Bad15051 + "\"",
		}, "authentication-key"},
		{"isis", []string{
			"set protocols isis authentication-type md5",
			"set protocols isis authentication-key \"" + junos9Bad15051 + "\"",
		}, "authentication-key"},
		{"isis-interface", []string{
			"set protocols isis interface ge-0/0/2.0 authentication-type md5",
			"set protocols isis interface ge-0/0/2.0 authentication-key \"" + junos9Bad15051 + "\"",
		}, "authentication-key"},
		{"rip", []string{
			"set protocols rip authentication-type md5",
			"set protocols rip authentication-key \"" + junos9Bad15051 + "\"",
			"set protocols rip neighbor ge-0/0/3",
		}, "authentication-key"},
		{"routing-instance-bgp", []string{
			"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A protocols bgp local-as 65001",
		"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 authentication-key \"" + junos9Bad15051 + "\"",
		}, "authentication-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("CompileConfig accepted malformed %q — want strict refusal (#15051)", junos9Bad15051)
			}
			if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), "#15051") {
				t.Fatalf("refusal must name the leaf and #15051, got: %v", err)
			}
			if strings.Contains(err.Error(), junos9Bad15051) {
				t.Fatalf("refusal LEAKED the secret value: %v", err)
			}
		})
	}
}

// TestJunos9MalformedLenientKeepsBlobAndWarns15051 pins #1960 on the
// tolerant path: a persisted malformed `$9$` still boots, keeps its
// blob (no silent plaintext substitution), and warns naming #15051.
func TestJunos9MalformedLenientKeepsBlobAndWarns15051(t *testing.T) {
	tree := buildTree(t, []string{
		"set protocols rip authentication-type md5",
		"set protocols rip authentication-key \"" + junos9Bad15051 + "\"",
		"set protocols rip neighbor ge-0/0/3",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must boot a persisted malformed $9$ config: %v", err)
	}
	if got := cfg.Protocols.RIP.AuthKey.Reveal(); got != junos9Bad15051 {
		t.Errorf("lenient RIP AuthKey = %q, want the original blob %q kept", got, junos9Bad15051)
	}
	saw := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15051") {
			saw = true
			if strings.Contains(w, junos9Bad15051) {
				t.Fatalf("lenient warning LEAKED the secret: %q", w)
			}
		}
	}
	if !saw {
		t.Fatalf("expected a #15051 lenient warning, got: %v", cfg.Warnings)
	}
}

// TestJunos9PlaintextAndControlsUnchanged15051 is the adjacent
// control: a plaintext (non-`$9$`) key compiles byte-identical, and a
// valid `$9$` key on the lenient path decodes exactly as on strict.
func TestJunos9PlaintextAndControlsUnchanged15051(t *testing.T) {
	tree := buildTree(t, []string{
		"set protocols rip authentication-type md5",
		"set protocols rip authentication-key plainkey1",
		"set protocols rip neighbor ge-0/0/3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("plaintext control refused: %v", err)
	}
	if got := cfg.Protocols.RIP.AuthKey.Reveal(); got != "plainkey1" {
		t.Errorf("plaintext AuthKey = %q, want byte-identical plainkey1", got)
	}
	lenientCfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols rip authentication-type md5",
		"set protocols rip authentication-key \"" + junos9Blob15051 + "\"",
		"set protocols rip neighbor ge-0/0/3",
	}))
	if err != nil {
		t.Fatalf("lenient valid $9$: %v", err)
	}
	if got := lenientCfg.Protocols.RIP.AuthKey.Reveal(); got != junos9Plain15051 {
		t.Errorf("lenient decoded AuthKey = %q, want %q", got, junos9Plain15051)
	}
}

// TestDecodeJunos9SecretKnownAnswer15051 pins the exported decoder
// against the IKE known-answer vector and the malformed shapes.
func TestDecodeJunos9SecretKnownAnswer15051(t *testing.T) {
	got, err := DecodeJunos9Secret(junos9Blob15051)
	if err != nil || got != junos9Plain15051 {
		t.Fatalf("DecodeJunos9Secret(%q) = %q, %v; want %q", junos9Blob15051, got, err, junos9Plain15051)
	}
	if got, err := DecodeJunos9Secret("plainkey1"); err != nil || got != "plainkey1" {
		t.Fatalf("plaintext passthrough = %q, %v; want plainkey1", got, err)
	}
	for _, bad := range []string{junos9Bad15051, "$9$", "$9$!!!", "$9$Q"} {
		if _, err := DecodeJunos9Secret(bad); err == nil {
			t.Errorf("DecodeJunos9Secret(%q) accepted a malformed $9$ value", bad)
		}
	}
}
