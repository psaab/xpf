package config

import (
	"strings"
	"testing"
)

// #6696: `system services dhcp-local-server group <g> interface` and
// `... group <g> pool <p> dns-server` kept only the FIRST element of a
// bracketed list.
//
// The failing axis is BRACKETED-vs-repeated-leaf, NOT strict-vs-tolerant —
// measured, and the issue's original framing said otherwise. Every case
// below is therefore run on BOTH compile paths and asserts the same
// result, so a fix that repaired only one path cannot pass.
//
//   - `group interface` — the DHCP server served only the first interface
//     in the group; the second segment got no leases at all, and the
//     failure looks like a network problem rather than a config one.
//   - `pool dns-server` — clients received one resolver where two were
//     configured, so the redundancy was simply absent.
//
// Because the bracketed spelling fails at the ORIGINAL commit, both
// cluster nodes agree — on the narrowed value — and there is no divergence
// to notice.

// dhcpGroups compiles a config on BOTH the strict and the tolerant path,
// asserts they agree, and returns the v4 groups.
func dhcpGroups6696(t *testing.T, build func() *ConfigTree) map[string]*DHCPServerGroup {
	t.Helper()

	strictCfg, sErr := CompileConfig(build())
	if sErr != nil {
		t.Fatalf("strict compile: %v", sErr)
	}
	lenientCfg, lErr := CompileConfigLenient(build())
	if lErr != nil {
		t.Fatalf("tolerant compile: %v", lErr)
	}

	sGroups := dhcpV4Groups6696(strictCfg)
	lGroups := dhcpV4Groups6696(lenientCfg)

	// The two paths must agree. Asserting the AGREEMENT rather than pinning
	// each path to a literal is deliberate: the issue's original diagnosis
	// named the tolerant path as the failing one, and a test that pinned
	// only that path would have certified the strict path it never looked at.
	for name, sg := range sGroups {
		lg := lGroups[name]
		if lg == nil {
			t.Fatalf("group %q present on the strict path, absent on the tolerant path", name)
		}
		if strings.Join(sg.Interfaces, ",") != strings.Join(lg.Interfaces, ",") {
			t.Errorf("group %q: strict Interfaces=%q but tolerant Interfaces=%q — the two "+
				"compile paths disagree, so a node that loaded a persisted config would "+
				"serve a different set than the node that committed it",
				name, sg.Interfaces, lg.Interfaces)
		}
		for i, sp := range sg.Pools {
			if i >= len(lg.Pools) {
				t.Fatalf("group %q: strict has %d pools, tolerant has %d", name, len(sg.Pools), len(lg.Pools))
			}
			if strings.Join(sp.DNSServers, ",") != strings.Join(lg.Pools[i].DNSServers, ",") {
				t.Errorf("group %q pool %q: strict DNSServers=%q but tolerant DNSServers=%q",
					name, sp.Name, sp.DNSServers, lg.Pools[i].DNSServers)
			}
		}
	}
	return sGroups
}

func dhcpV4Groups6696(cfg *Config) map[string]*DHCPServerGroup {
	if cfg == nil || cfg.System.DHCPServer.DHCPLocalServer == nil {
		return nil
	}
	return cfg.System.DHCPServer.DHCPLocalServer.Groups
}

func setTree6696(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

func braceTree6696(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// TestDHCPGroup6696InterfaceSpellingsAgree asserts that every spelling of a
// two-interface group compiles to BOTH interfaces, and that the spellings
// agree with each other.
//
// FAIL-ON-REVERT: restoring `if v := nodeVal(prop); v != ""` drops
// everything past slot 0 in the two bracketed spellings, which reds both
// the agreement check and the element check.
func TestDHCPGroup6696InterfaceSpellingsAgree(t *testing.T) {
	want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}

	cases := []struct {
		name  string
		build func() *ConfigTree
	}{
		{"set bracketed", func() *ConfigTree {
			return setTree6696(t, `set system services dhcp-local-server group g1 interface [ ge-0/0/0.0 ge-0/0/1.0 ]`)
		}},
		{"set repeated", func() *ConfigTree {
			return setTree6696(t,
				`set system services dhcp-local-server group g1 interface ge-0/0/0.0`,
				`set system services dhcp-local-server group g1 interface ge-0/0/1.0`)
		}},
		{"brace bracketed", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n"+
				"    interface [ ge-0/0/0.0 ge-0/0/1.0 ];\n   }\n  }\n }\n}\n")
		}},
		{"brace repeated", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n"+
				"    interface ge-0/0/0.0;\n    interface ge-0/0/1.0;\n   }\n  }\n }\n}\n")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups := dhcpGroups6696(t, tc.build)
			g := groups["g1"]
			if g == nil {
				t.Fatal("group g1 missing")
			}
			if strings.Join(g.Interfaces, ",") != strings.Join(want, ",") {
				t.Fatalf("Interfaces=%q, want %q — the group serves only part of what was "+
					"authored, so the missing segment gets NO leases (#6696)", g.Interfaces, want)
			}
		})
	}
}

// TestDHCPPool6696DNSServerSpellingsAgree is the same guard for the pool's
// resolver list — where the drop silently removes the operator's
// redundancy.
func TestDHCPPool6696DNSServerSpellingsAgree(t *testing.T) {
	want := []string{"192.0.2.53", "198.51.100.53"}

	cases := []struct {
		name  string
		build func() *ConfigTree
	}{
		{"set bracketed", func() *ConfigTree {
			return setTree6696(t, `set system services dhcp-local-server group g1 pool p1 dns-server [ 192.0.2.53 198.51.100.53 ]`)
		}},
		{"set repeated", func() *ConfigTree {
			return setTree6696(t,
				`set system services dhcp-local-server group g1 pool p1 dns-server 192.0.2.53`,
				`set system services dhcp-local-server group g1 pool p1 dns-server 198.51.100.53`)
		}},
		{"brace bracketed", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n    pool p1 {\n"+
				"     dns-server [ 192.0.2.53 198.51.100.53 ];\n    }\n   }\n  }\n }\n}\n")
		}},
		{"brace repeated", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n    pool p1 {\n"+
				"     dns-server 192.0.2.53;\n     dns-server 198.51.100.53;\n    }\n   }\n  }\n }\n}\n")
		}},
		{"brace value block", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n    pool p1 {\n"+
				"     dns-server {\n      192.0.2.53;\n      198.51.100.53;\n     }\n    }\n   }\n  }\n }\n}\n")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups := dhcpGroups6696(t, tc.build)
			g := groups["g1"]
			if g == nil || len(g.Pools) != 1 {
				t.Fatalf("group g1 / pool p1 missing: %#v", g)
			}
			if strings.Join(g.Pools[0].DNSServers, ",") != strings.Join(want, ",") {
				t.Fatalf("DNSServers=%q, want %q — clients receive one resolver where two "+
					"were configured, so the redundancy is absent (#6696)",
					g.Pools[0].DNSServers, want)
			}
		})
	}
}

// TestDHCPv6Group6696SpellingsAgree proves the v6 family carries the same
// fix. The two families' group subtrees are ONE schema function and ONE
// compiler function, so this is the guard that the single-sourcing is real
// rather than asserted.
func TestDHCPv6Group6696SpellingsAgree(t *testing.T) {
	tree := setTree6696(t,
		`set system services dhcpv6-local-server group g6 interface [ ge-0/0/0.0 ge-0/0/1.0 ]`,
		`set system services dhcpv6-local-server group g6 pool p6 dns-server [ 2001:db8::53 2001:db8::54 ]`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	srv := cfg.System.DHCPServer.DHCPv6LocalServer
	if srv == nil || srv.Groups["g6"] == nil {
		t.Fatal("dhcpv6-local-server group g6 missing")
	}
	g := srv.Groups["g6"]
	if strings.Join(g.Interfaces, ",") != "ge-0/0/0.0,ge-0/0/1.0" {
		t.Errorf("v6 Interfaces=%q, want both (#6696)", g.Interfaces)
	}
	if len(g.Pools) != 1 || strings.Join(g.Pools[0].DNSServers, ",") != "2001:db8::53,2001:db8::54" {
		t.Errorf("v6 DNSServers=%#v, want both (#6696)", g.Pools)
	}
}

// TestDHCPGroup6696PerInterfaceModifierIsNotAnInterface is the
// counter-direction, and it is the reason `interface` is read from Keys
// alone rather than through firewallMatchValues.
//
// A per-interface Junos modifier (`interface ge-0/0/0.0 exclude`, `...
// upgrade-server <addr>`) is not an interface NAME. xpf parses and ignores
// these — as it did before #6696, where the single-value read dropped them
// — and they must not be promoted into the list, because group.Interfaces
// is handed to Kea as interfaces-config.interfaces and a name no device
// answers to takes the WHOLE DHCP server down, not just that group.
//
// The spelling-differential gate does not state this direction: it detects
// a dropped value, not a promoted modifier. Measured — swapping in
// firewallMatchValues does red that gate, but only indirectly, at the
// modelled `interface <if> <modifier>` sub-leaf sites, which exist only
// because the modifiers are modelled; removing those children leaves the
// gate green with the promotion still present, and only this test red.
//
// FAIL-ON-REVERT: replacing dhcpGroupInterfaceValues with
// firewallMatchValues — the union reader used for every other multi-value
// leaf — makes `exclude` an interface and reds this test.
func TestDHCPGroup6696PerInterfaceModifierIsNotAnInterface(t *testing.T) {
	cases := []struct {
		name  string
		build func() *ConfigTree
	}{
		{"flat set exclude", func() *ConfigTree {
			return setTree6696(t, `set system services dhcp-local-server group g1 interface ge-0/0/0.0 exclude`)
		}},
		{"flat set upgrade-server", func() *ConfigTree {
			return setTree6696(t, `set system services dhcp-local-server group g1 interface ge-0/0/0.0 upgrade-server 192.0.2.9`)
		}},
		{"brace modifier body", func() *ConfigTree {
			return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n"+
				"    interface ge-0/0/0.0 {\n     exclude;\n    }\n   }\n  }\n }\n}\n")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups := dhcpGroups6696(t, tc.build)
			g := groups["g1"]
			if g == nil {
				t.Fatal("group g1 missing")
			}
			if strings.Join(g.Interfaces, ",") != "ge-0/0/0.0" {
				t.Fatalf("Interfaces=%q, want exactly [ge-0/0/0.0] — a per-interface modifier "+
					"keyword was promoted into the interface list; Kea cannot bind it and the "+
					"whole DHCP server fails to start (#6696)", g.Interfaces)
			}
		})
	}
}

// TestDHCPGroup6696BareValueBlockStillReadsEveryValue pins the one shape
// whose values legitimately live in Children: a bare `interface { ... }`
// block with no name on the statement line. The pre-#6696 reader handled
// it (returning the FIRST child only), so a Keys-only read would have
// regressed the group to serving NOTHING.
func TestDHCPGroup6696BareValueBlockStillReadsEveryValue(t *testing.T) {
	groups := dhcpGroups6696(t, func() *ConfigTree {
		return braceTree6696(t, "system {\n services {\n  dhcp-local-server {\n   group g1 {\n"+
			"    interface {\n     ge-0/0/0.0;\n     ge-0/0/1.0;\n    }\n   }\n  }\n }\n}\n")
	})
	g := groups["g1"]
	if g == nil {
		t.Fatal("group g1 missing")
	}
	if strings.Join(g.Interfaces, ",") != "ge-0/0/0.0,ge-0/0/1.0" {
		t.Fatalf("Interfaces=%q, want both — a bare value block carries its values as "+
			"children and must not compile to an EMPTY group (#6696)", g.Interfaces)
	}
}

// TestDHCPGroup6696EveryElementIsValidated is the "a widened read needs a
// widened validator" half. Before #6696 only slot 0 could ever reach a
// consumer, so a malformed element past it was inert; now every element is
// installed, and every element is therefore checked at commit.
//
// The dns-server check runs through the schema
// (schemaValidateExpandedTreeForNode, pkg/configstore), which is the
// STRICT commit / commit-check path only — the tolerant load / peer-sync
// path does not run it, so an already-persisted config still boots
// (#1960). Since #14601 the compiled pool gate
// (validateDHCPPoolValuesStrict) ALSO refuses a malformed dns-server at
// CompileConfig time, naming the element, so the two dns-server rows
// accept either layer's refusal; the interface row still exercises the
// schema layer alone.
func TestDHCPGroup6696EveryElementIsValidated(t *testing.T) {
	bad := []struct {
		name string
		line string
		want string
	}{
		{
			"second dns-server is not an IP",
			`set system services dhcp-local-server group g1 pool p1 dns-server [ 192.0.2.53 not-an-ip ]`,
			"not-an-ip",
		},
		{
			"second interface has a glob metacharacter",
			`set system services dhcp-local-server group g1 interface [ ge-0/0/0.0 ge-* ]`,
			"ge-*",
		},
		{
			"v6 second dns-server is not an IP",
			`set system services dhcpv6-local-server group g6 pool p6 dns-server [ 2001:db8::53 nope ]`,
			"nope",
		},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			tree := setTree6696(t, tc.line)
			cfg, err := CompileConfig(tree)
			if err != nil {
				// #14601: the compiled pool gate refuses a malformed
				// dns-server before the schema walk runs. That is the
				// same commit refusal, one layer earlier; it must
				// still name the offending element.
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("compile refusal does not name the offending element %q: %v", tc.want, err)
				}
				return
			}
			verr := SchemaValidate(tree, cfg)
			if verr == nil {
				t.Fatalf("commit ACCEPTED a malformed element %q — a widened read needs a "+
					"widened validator (#6696)", tc.want)
			}
			if !strings.Contains(verr.Error(), tc.want) {
				t.Errorf("rejection does not name the offending element %q: %v", tc.want, verr)
			}
		})
	}
}

// TestDHCPGroup6696RealValuesStillCommitClean is the TIGHTENING control
// for the validators added above. The interface leaf accepts the Junos
// slash spelling, the xpf dash spelling, a bare name and a
// unit-qualified name; the dns-server leaf accepts either family at the
// schema layer (ValidateIPAddress). Since #14601 the compiled pool gate
// additionally requires each dns-server to match its server's family —
// a v6 resolver in a v4 pool renders verbatim into Kea's ipv4-address
// domain-name-servers option and Kea refuses the whole file — so this
// control keeps one family per server and exercises the mixed-family
// refusal in TestDHCPPoolValuesRefusedAtCommit14601 instead. A validator
// tightened to, say, require a unit suffix or reject '/' reds here while
// every delete-the-fix cell stays green.
func TestDHCPGroup6696RealValuesStillCommitClean(t *testing.T) {
	tree := setTree6696(t,
		`set system services dhcp-local-server group g1 interface [ ge-0/0/1.0 ge-0-0-2 reth0.80 fxp0 ge-0/0/3 ]`,
		`set system services dhcp-local-server group g1 pool p1 dns-server [ 192.0.2.53 198.51.100.53 ]`,
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile REJECTED a legitimate group: %v", err)
	}
	if verr := SchemaValidate(tree, cfg); verr != nil {
		t.Fatalf("commit-check REJECTED legitimate interface / resolver values: %v", verr)
	}
	g := dhcpV4Groups6696(cfg)["g1"]
	if g == nil {
		t.Fatal("group g1 missing")
	}
	if got, want := strings.Join(g.Interfaces, ","), "ge-0/0/1.0,ge-0-0-2,reth0.80,fxp0,ge-0/0/3"; got != want {
		t.Errorf("Interfaces=%q, want %q", got, want)
	}
	if got, want := strings.Join(g.Pools[0].DNSServers, ","), "192.0.2.53,198.51.100.53"; got != want {
		t.Errorf("DNSServers=%q, want %q", got, want)
	}
}
