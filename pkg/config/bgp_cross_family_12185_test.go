package config

import (
	"strings"
	"testing"
)

// An explicit per-neighbor `family inet` on an IPv6-literal peer is
// unrenderable: xpf emits no RFC 8950 extended-next-hop, so the IPv4 AF cannot
// receive its policies. An inet-only peer lands in NO address-family, while
// FRR's default ipv4-unicast activates it without policy (#12185). Strict
// commit rejects the shape; the tolerant path warns and leaves it inert.
func TestBGPPerNeighborCrossFamily12185StrictRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "explicit unicast",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65001",
				"set protocols bgp group external neighbor 2001:db8::9 family inet unicast",
			},
		},
		{
			name: "Junos bare-family unicast default",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65001",
				"set protocols bgp group external neighbor 2001:db8::9 family inet",
			},
		},
		{
			name: "dual explicit inet plus inet6 still rejects the inet half",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65001",
				"set protocols bgp group external neighbor 2001:db8::9 family inet unicast",
				"set protocols bgp group external neighbor 2001:db8::9 family inet6 unicast",
			},
		},
		{
			name: "routing-instance neighbor",
			sets: []string{
				"set routing-instances VRF-A instance-type virtual-router",
				"set routing-instances VRF-A protocols bgp local-as 65001",
				"set routing-instances VRF-A protocols bgp group external peer-as 65001",
				"set routing-instances VRF-A protocols bgp group external neighbor 2001:db8::9 family inet unicast",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.sets))
			if err == nil {
				t.Fatal("strict compilation accepted family inet on an IPv6 peer; want rejection (#12185)")
			}
			for _, want := range []string{"2001:db8::9", "inet", "#12185"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("diagnostic %q does not name the peer, family and issue", err)
				}
			}
		})
	}
}

// Match every IPv6 literal form the renderer classifies as IPv6, including
// scoped link-local and IPv4-mapped spellings.
func TestBGPPerNeighborCrossFamily12185StrictRejectsIPv6AddressForms(t *testing.T) {
	for _, peer := range []string{"fe80::9%eth0", "::ffff:192.0.2.9"} {
		_, err := CompileConfig(buildTree(t, []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group external peer-as 65001",
			"set protocols bgp group external neighbor " + peer + " family inet unicast",
		}))
		if err == nil {
			t.Fatalf("strict compilation accepted family inet on IPv6-form peer %s", peer)
		}
		for _, want := range []string{peer, "inet", "#12185"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("diagnostic %q for %s does not name peer, family and issue", err, peer)
			}
		}
	}
}

// The per-neighbor gate rejects unsupported explicit cross-family declarations.
// Group family inheritance remains valid and uses FRRAddrFamily so mapped
// literals follow the renderer's IPv6 classification; non-literal addresses
// preserve the pre-#2454 behavior.
func TestBGPPerNeighborCrossFamily12185StrictAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{
			name: "ipv6 peer with per-neighbor inet6",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65001",
				"set protocols bgp group external neighbor 2001:db8::9 family inet6 unicast",
			},
		},
		{
			name: "ipv4 peer with per-neighbor inet",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external neighbor 192.0.2.1 family inet unicast",
			},
		},
		{
			name: "group-level inet does not false-positive on an ipv6 member",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group dual peer-as 65002",
				"set protocols bgp group dual family inet unicast",
				"set protocols bgp group dual neighbor 2001:db8::2",
			},
		},
		{
			name: "non-literal address inherits past the gate like #2454",
			sets: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				"set protocols bgp group external neighbor peer-template family inet unicast",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.sets))
			if err != nil {
				t.Fatalf("strict compilation rejected a supported shape: %v", err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12185") {
					t.Fatalf("supported shape carries a #12185 warning: %q", warning)
				}
			}
		})
	}
}

// Group-inherited family inet must not survive on an IPv4-mapped IPv6 peer.
// The address-family gate and renderer both classify the mapped spellings as
// IPv6, so the dual group contributes only inet6.
func TestBGPGroupInheritedMappedFamily12185StrictUsesIPv6(t *testing.T) {
	for _, peer := range []string{"::ffff:192.0.2.9", "::ffff:c000:209"} {
		t.Run(peer, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group dual peer-as 65002",
				"set protocols bgp group dual family inet unicast",
				"set protocols bgp group dual family inet6 unicast",
				"set protocols bgp group dual neighbor " + peer,
			}))
			if err != nil {
				t.Fatalf("strict compilation rejected group-inherited family on mapped IPv6 peer: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			n := cfg.Protocols.BGP.Neighbors[0]
			if n.FamilyInet {
				t.Fatalf("mapped IPv6 peer inherited FamilyInet: %+v", n)
			}
			if !n.FamilyInet6 {
				t.Fatalf("mapped IPv6 peer did not inherit FamilyInet6: %+v", n)
			}
			if n.CrossFamilyInet {
				t.Fatalf("bare group inheritance was mis-marked cross-family: %+v", n)
			}
			if warnings := bgpCrossFamilyWarnings12185(cfg); len(warnings) != 0 {
				t.Fatalf("group inheritance emitted #12185 warnings: %v", warnings)
			}
		})
	}
}

// The lenient per-neighbor marker must clear a group-inherited FamilyInet too;
// otherwise the renderer misses its IPv4 deactivation arm for mapped peers.
func TestBGPGroupInheritedMappedFamily12185LenientClearsInet(t *testing.T) {
	for _, peer := range []string{"::ffff:192.0.2.9", "::ffff:c000:209"} {
		t.Run(peer, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group dual peer-as 65002",
				"set protocols bgp group dual family inet unicast",
				"set protocols bgp group dual neighbor " + peer + " family inet unicast",
			}))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
				t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
			}
			n := cfg.Protocols.BGP.Neighbors[0]
			if n.FamilyInet {
				t.Fatalf("unrenderable inherited inet remained active: %+v", n)
			}
			if !n.CrossFamilyInet {
				t.Fatalf("cross-family inet was not marked for fail-closed rendering: %+v", n)
			}
			warnings := bgpCrossFamilyWarnings12185(cfg)
			if len(warnings) != 1 || !strings.Contains(warnings[0], peer) {
				t.Fatalf("#12185 warnings = %v, want one naming the peer", warnings)
			}
		})
	}
}

// On the tolerant load / peer-sync path the config must still boot (#1960),
// so the cross-family declaration warns and stays inert. A co-declared
// inet6 half still compiles.
func TestBGPPerNeighborCrossFamily12185LenientWarnsAndStaysInert(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65001",
		"set protocols bgp group external neighbor 2001:db8::9 family inet unicast",
		"set protocols bgp group external neighbor 2001:db8::9 family inet6 unicast",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP neighbor missing: %+v", cfg.Protocols.BGP)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.FamilyInet {
		t.Fatalf("cross-family inet should stay inert, got FamilyInet=true")
	}
	if !n.CrossFamilyInet {
		t.Fatal("cross-family inet was not marked for fail-closed rendering")
	}
	if !n.FamilyInet6 {
		t.Fatalf("co-declared inet6 half lost: %+v", n)
	}
	warnings := bgpCrossFamilyWarnings12185(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "2001:db8::9") {
		t.Fatalf("#12185 warnings = %v, want one naming the peer", warnings)
	}
}

func bgpCrossFamilyWarnings12185(cfg *Config) []string {
	var warnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12185") {
			warnings = append(warnings, warning)
		}
	}
	return warnings
}
