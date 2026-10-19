package config

import (
	"strings"
	"testing"
)

// #15691 (V37-01): dhcpLocalServerGroupSchema declared only dns-server and
// static-binding under `pool`, omitting subnet, address-range, router,
// lease-time and domain-name. Because SetPath had no schema for those
// keywords, the standard two-line Junos spelling
//
//	set ... pool p1 address-range low <ip>
//	set ... pool p1 address-range high <ip>
//
// landed as two separate 3-token leaves the compiler's len>=5 packed check
// dropped, a braced `address-range { low ...; high ...; }` block was
// dropped for the same reason, and a compact `pool p1 subnet ... router ...`
// line split into multiple pools. Every shape committed clean and rendered
// a Kea config with no dynamic range.
//
// These tests drive BOTH compile paths (strict CompileConfig and tolerant
// CompileConfigLenient) because the failing axis is spelling-vs-spelling,
// not strict-vs-tolerant.

func dhcpPool15691(t *testing.T, cfg *Config, server, group, pool string) *DHCPPool {
	t.Helper()
	if cfg == nil {
		t.Fatal("nil config")
	}
	var lsc *DHCPLocalServerConfig
	if server == "dhcpv6-local-server" {
		lsc = cfg.System.DHCPServer.DHCPv6LocalServer
	} else {
		lsc = cfg.System.DHCPServer.DHCPLocalServer
	}
	if lsc == nil {
		t.Fatalf("%s not compiled", server)
	}
	g := lsc.Groups[group]
	if g == nil {
		t.Fatalf("group %q missing (have %v)", group, lsc.Groups)
	}
	var found []*DHCPPool
	for _, p := range g.Pools {
		if p.Name == pool {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("group %q: want exactly 1 pool %q, got %d (%+v)", group, pool, len(found), g.Pools)
	}
	return found[0]
}

func compileBoth15691(t *testing.T, build func() *ConfigTree) (*Config, *Config) {
	t.Helper()
	strict, err := CompileConfig(build())
	if err != nil {
		t.Fatalf("strict CompileConfig: %v", err)
	}
	lenient, err := CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("lenient CompileConfigLenient: %v", err)
	}
	return strict, lenient
}

func checkPool15691(t *testing.T, p *DHCPPool, want DHCPPool) {
	t.Helper()
	if p.Subnet != want.Subnet || p.RangeLow != want.RangeLow || p.RangeHigh != want.RangeHigh ||
		p.Router != want.Router || p.Domain != want.Domain || p.LeaseTime != want.LeaseTime {
		t.Errorf("pool = {Subnet:%q Range:%q-%q Router:%q Domain:%q Lease:%d}, want {Subnet:%q Range:%q-%q Router:%q Domain:%q Lease:%d}",
			p.Subnet, p.RangeLow, p.RangeHigh, p.Router, p.Domain, p.LeaseTime,
			want.Subnet, want.RangeLow, want.RangeHigh, want.Router, want.Domain, want.LeaseTime)
	}
}

// Two-line set: address-range low and high on separate set commands.
func TestDHCPPoolLeavesTwoLineSet15691(t *testing.T) {
	for _, tc := range []struct {
		server, subnet, low, high, router string
	}{
		{"dhcp-local-server", "10.0.1.0/24", "10.0.1.100", "10.0.1.200", "10.0.1.1"},
		{"dhcpv6-local-server", "2001:db8:1::/64", "2001:db8:1::100", "2001:db8:1::200", ""},
	} {
		t.Run(tc.server, func(t *testing.T) {
			p := "set system services " + tc.server + " group g1 pool p1"
			lines := []string{
				"set system services " + tc.server + " group g1 interface ge-0/0/1.0",
				p + " subnet " + tc.subnet,
				p + " address-range low " + tc.low,
				p + " address-range high " + tc.high,
				p + " lease-time 3600",
				p + " domain-name example.local",
			}
			if tc.router != "" {
				lines = append(lines, p+" router "+tc.router)
			}
			strict, lenient := compileBoth15691(t, func() *ConfigTree { return flatTreeFromSets(t, lines...) })
			want := DHCPPool{Subnet: tc.subnet, RangeLow: tc.low, RangeHigh: tc.high, Router: tc.router, Domain: "example.local", LeaseTime: 3600}
			checkPool15691(t, dhcpPool15691(t, strict, tc.server, "g1", "p1"), want)
			checkPool15691(t, dhcpPool15691(t, lenient, tc.server, "g1", "p1"), want)
		})
	}
}

// Flat packed range, both orders, on one set line.
func TestDHCPPoolLeavesFlatRange15691(t *testing.T) {
	for _, rng := range []string{
		"address-range low 10.0.1.100 high 10.0.1.200",
		"address-range high 10.0.1.200 low 10.0.1.100",
	} {
		strict, _ := compileBoth15691(t, func() *ConfigTree {
			return flatTreeFromSets(t,
				"set system services dhcp-local-server group g1 interface ge-0/0/1.0",
				"set system services dhcp-local-server group g1 pool p1 subnet 10.0.1.0/24",
				"set system services dhcp-local-server group g1 pool p1 "+rng)
		})
		p := dhcpPool15691(t, strict, "dhcp-local-server", "g1", "p1")
		if p.RangeLow != "10.0.1.100" || p.RangeHigh != "10.0.1.200" {
			t.Errorf("%q: range = %q-%q, want 10.0.1.100-10.0.1.200", rng, p.RangeLow, p.RangeHigh)
		}
	}
}

// Braced hierarchical pool with a braced address-range block.
func TestDHCPPoolLeavesBracedRange15691(t *testing.T) {
	src := `system {
    services {
        dhcp-local-server {
            group g1 {
                interface ge-0/0/1.0;
                pool p1 {
                    subnet 10.0.1.0/24;
                    address-range {
                        low 10.0.1.100;
                        high 10.0.1.200;
                    }
                    router 10.0.1.1;
                    domain-name example.local;
                    lease-time 3600;
                }
            }
        }
        dhcpv6-local-server {
            group g6 {
                interface ge-0/0/1.0;
                pool p6 {
                    subnet 2001:db8:1::/64;
                    address-range {
                        low 2001:db8:1::100;
                        high 2001:db8:1::200;
                    }
                    domain-name example.local;
                    lease-time 7200;
                }
            }
        }
    }
}
`
	strict, lenient := compileBoth15691(t, func() *ConfigTree { return hierTree(t, src) })
	checkPool15691(t, dhcpPool15691(t, strict, "dhcp-local-server", "g1", "p1"),
		DHCPPool{Subnet: "10.0.1.0/24", RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200", Router: "10.0.1.1", Domain: "example.local", LeaseTime: 3600})
	checkPool15691(t, dhcpPool15691(t, lenient, "dhcpv6-local-server", "g6", "p6"),
		DHCPPool{Subnet: "2001:db8:1::/64", RangeLow: "2001:db8:1::100", RangeHigh: "2001:db8:1::200", Domain: "example.local", LeaseTime: 7200})
}

// Compact one-line pool: every leaf packed onto the pool statement must
// merge into ONE pool, not split into one pool per leaf.
func TestDHCPPoolLeavesCompactPool15691(t *testing.T) {
	src := `system {
    services {
        dhcp-local-server {
            group g1 {
                interface ge-0/0/1.0;
                pool p1 subnet 10.0.1.0/24 address-range low 10.0.1.100 high 10.0.1.200 router 10.0.1.1 lease-time 3600 domain-name example.local;
            }
        }
    }
}
`
	strict, lenient := compileBoth15691(t, func() *ConfigTree { return hierTree(t, src) })
	want := DHCPPool{Subnet: "10.0.1.0/24", RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200", Router: "10.0.1.1", Domain: "example.local", LeaseTime: 3600}
	checkPool15691(t, dhcpPool15691(t, strict, "dhcp-local-server", "g1", "p1"), want)
	checkPool15691(t, dhcpPool15691(t, lenient, "dhcp-local-server", "g1", "p1"), want)
}

// Repeated pool blocks (hierarchical duplicates) merge into one pool.
func TestDHCPPoolLeavesRepeatedPoolBlocksMerge15691(t *testing.T) {
	src := `system {
    services {
        dhcp-local-server {
            group g1 {
                interface ge-0/0/1.0;
                pool p1 {
                    subnet 10.0.1.0/24;
                }
                pool p1 {
                    address-range low 10.0.1.100 high 10.0.1.200;
                    router 10.0.1.1;
                }
            }
        }
    }
}
`
	strict, _ := compileBoth15691(t, func() *ConfigTree { return hierTree(t, src) })
	checkPool15691(t, dhcpPool15691(t, strict, "dhcp-local-server", "g1", "p1"),
		DHCPPool{Subnet: "10.0.1.0/24", RangeLow: "10.0.1.100", RangeHigh: "10.0.1.200", Router: "10.0.1.1"})
}

// Residual limb (G50-02): a repeated `dhcpv6-local-server group <g>` block
// overwrote the first group in compileDHCPLocalServer's map assignment;
// the v6 site was missing from dupBlockMergeSites9023. Both families must
// merge repeated group blocks into one group holding every pool.
func TestDHCPRepeatedGroupBlocksMerge15691(t *testing.T) {
	for _, tc := range []struct {
		server, subnet, subnet2, low, high string
	}{
		{"dhcp-local-server", "10.0.1.0/24", "10.0.2.0/24", "10.0.2.100", "10.0.2.200"},
		{"dhcpv6-local-server", "2001:db8:1::/64", "2001:db8:2::/64", "2001:db8:2::100", "2001:db8:2::200"},
	} {
		t.Run(tc.server, func(t *testing.T) {
			low, high := tc.low, tc.high
			src := `system {
    services {
        ` + tc.server + ` {
            group g1 {
                interface ge-0/0/1.0;
                pool p1 {
                    subnet ` + tc.subnet + `;
                }
            }
            group g1 {
                pool p2 {
                    subnet ` + tc.subnet2 + `;
                    address-range low ` + low + ` high ` + high + `;
                }
            }
        }
    }
}
`
			strict, lenient := compileBoth15691(t, func() *ConfigTree { return hierTree(t, src) })
			for _, cfg := range []*Config{strict, lenient} {
				p := dhcpPool15691(t, cfg, tc.server, "g1", "p2")
				if p.RangeLow != low || p.RangeHigh != high {
					t.Errorf("%s: merged group pool p2 range = %q-%q, want %q-%q", tc.server, p.RangeLow, p.RangeHigh, low, high)
				}
				// p1 from the first block must survive the merge.
				_ = dhcpPool15691(t, cfg, tc.server, "g1", "p1")
			}
		})
	}
}

// A one-sided range is refused at strict commit: Kea renders no pool for
// it, so the committed leaf would silently serve nothing.
func TestDHCPPoolOneSidedRangeRefused15691(t *testing.T) {
	for _, lines := range [][]string{
		{"set system services dhcp-local-server group g1 pool p1 address-range low 10.0.1.100"},
		{"set system services dhcp-local-server group g1 pool p1 address-range high 10.0.1.200"},
	} {
		tree := flatTreeFromSets(t, append([]string{
			"set system services dhcp-local-server group g1 interface ge-0/0/1.0",
			"set system services dhcp-local-server group g1 pool p1 subnet 10.0.1.0/24",
		}, lines...)...)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "address-range") {
			t.Errorf("%v: want one-sided address-range refusal, got %v", lines, err)
		}
	}
}

// The new pool leaves are typed at commit-check: a malformed subnet,
// range bound, router or lease-time is refused by SchemaValidate, not
// silently compiled.
func TestDHCPPoolLeavesSchemaValidated15691(t *testing.T) {
	p := "set system services dhcp-local-server group g1 pool p1"
	cases := []struct {
		name string
		line string
	}{
		{"bad subnet", p + " subnet not-a-prefix"},
		{"bad range low", p + " address-range low bogus high 10.0.1.200"},
		{"bad range high", p + " address-range low 10.0.1.100 high bogus"},
		{"bad router", p + " router bogus"},
		{"bad lease-time", p + " lease-time banana"},
		{"bad domain", p + " domain-name \"bad domain\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set system services dhcp-local-server group g1 interface ge-0/0/1.0",
				p+" subnet 10.0.1.0/24", tc.line)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Errorf("%s: SchemaValidate accepted %q", tc.name, tc.line)
			}
		})
	}
	// Control: well-formed leaves validate clean.
	tree := flatTreeFromSets(t,
		"set system services dhcp-local-server group g1 interface ge-0/0/1.0",
		p+" subnet 10.0.1.0/24",
		p+" address-range low 10.0.1.100 high 10.0.1.200",
		p+" router 10.0.1.1",
		p+" lease-time 3600",
		p+" domain-name example.local")
	if err := SchemaValidate(tree, nil); err != nil {
		t.Errorf("control: SchemaValidate rejected valid pool leaves: %v", err)
	}
}
