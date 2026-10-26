package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16604: snapshot builders stamp the explicit-master wire token for a
// `routing-instance default` scope; named and unscoped scopes unchanged.

func TestNATDefaultWireStamping16604(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "s", ToRoutingInstanceDefault: true,
		Rules: []*config.NATRule{{Name: "r1", Then: config.NATThen{Type: config.NATSource, Interface: true}}},
	}}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 || snaps[0].ToRoutingInstance != config.NATDefaultRoutingInstanceWire {
		t.Fatalf("source wire = %+v, want token", snaps)
	}
	// Raw literal on a hand-built config lowers the same way.
	cfg.Security.NAT.Source[0].ToRoutingInstanceDefault = false
	cfg.Security.NAT.Source[0].ToRoutingInstance = "default"
	snaps = buildSourceNATSnapshots(cfg, nil)
	if snaps[0].ToRoutingInstance != config.NATDefaultRoutingInstanceWire {
		t.Fatalf("raw literal wire = %q, want token", snaps[0].ToRoutingInstance)
	}
	// Named instance passes through.
	cfg.Security.NAT.Source[0].ToRoutingInstance = "VR1"
	snaps = buildSourceNATSnapshots(cfg, nil)
	if snaps[0].ToRoutingInstance != "VR1" {
		t.Fatalf("named wire = %q, want VR1", snaps[0].ToRoutingInstance)
	}

	cfg2 := &config.Config{}
	cfg2.Security.NAT.Static = []*config.StaticNATRuleSet{{
		Name: "st", FromRoutingInstanceDefault: true,
		Rules: []*config.StaticNATRule{{Name: "r1", Match: "203.0.113.10/32", Then: "192.168.1.10/32"}},
	}}
	ss := buildStaticNATSnapshots(cfg2, nil)
	if len(ss) != 1 || ss[0].FromRoutingInstance != config.NATDefaultRoutingInstanceWire {
		t.Fatalf("static wire = %+v, want token", ss)
	}

	cfg3 := &config.Config{}
	cfg3.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"p1": {Name: "p1", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{{
			Name: "d", FromRoutingInstanceDefault: true,
			Rules: []*config.NATRule{{Name: "r1", Match: config.NATMatch{DestinationAddress: "203.0.113.10/32", DestinationAddresses: []string{"203.0.113.10/32"}}, Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"}}},
		}},
	}
	ds := buildDestinationNATSnapshots(cfg3, nil)
	if len(ds) == 0 || ds[0].FromRoutingInstance != config.NATDefaultRoutingInstanceWire {
		t.Fatalf("dnat wire = %+v, want token", ds)
	}

	cfg4 := &config.Config{}
	cfg4.Security.NAT.SourcePools = map[string]*config.NATPool{"p64": {Name: "p64", Address: "100.64.0.1/32"}}
	cfg4.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "n64", Prefix: "64:ff9b::/96", SourcePool: "p64", FromRoutingInstanceDefault: true,
		FromRoutingInstances: []string{""},
	}}
	ns := buildNAT64Snapshots(cfg4)
	if len(ns) != 1 || len(ns[0].FromRoutingInstances) != 1 || ns[0].FromRoutingInstances[0] != config.NATDefaultRoutingInstanceWire {
		t.Fatalf("nat64 wire = %+v, want [token]", ns)
	}
}
// #17677: compile one config that declares a routing-instance named `default`,
// then exercise each production snapshot builder. The literal must survive as
// a named scope in SNAT, pool DNAT, static NAT, and NAT64; it must not become
// NATDefaultRoutingInstanceWire (the master alias).
func TestDeclaredDefaultNATScopesReachSnapshots17677(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances default instance-type virtual-router",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat source pool pool1 address 192.0.2.10/32",
		"set security nat source pool p64 address 100.64.0.1/32",
		"set security nat destination pool P1 address 10.0.30.100/32",
		"set security nat source rule-set snat-ok from routing-instance default",
		"set security nat source rule-set snat-ok to routing-instance default",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1",
		"set security nat destination rule-set dnat-ok from routing-instance default",
		"set security nat destination rule-set dnat-ok rule r1 match destination-address 203.0.113.10/32",
		"set security nat destination rule-set dnat-ok rule r1 then destination-nat pool P1",
		"set security nat static rule-set stat-ok from routing-instance default",
		"set security nat static rule-set stat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-ok rule R1 then static-nat prefix 10.0.0.5/32",
		"set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set n64 source-pool p64",
		"set security nat nat64 rule-set n64 from routing-instance default",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig with declared default instance: %v", err)
	}

	source := buildSourceNATSnapshots(cfg, nil)
	if len(source) != 1 || source[0].FromRoutingInstance != "default" || source[0].ToRoutingInstance != "default" {
		t.Fatalf("source NAT snapshot = %+v, want from/to literal default", source)
	}
	destination := buildDestinationNATSnapshots(cfg, nil)
	if len(destination) != 1 || destination[0].FromRoutingInstance != "default" {
		t.Fatalf("destination NAT snapshot = %+v, want from literal default", destination)
	}
	static := buildStaticNATSnapshots(cfg, nil)
	if len(static) != 1 || static[0].FromRoutingInstance != "default" {
		t.Fatalf("static NAT snapshot = %+v, want from literal default", static)
	}
	nat64 := buildNAT64Snapshots(cfg)
	if len(nat64) != 1 || nat64[0].FromRoutingInstance != "default" ||
		len(nat64[0].FromRoutingInstances) != 1 || nat64[0].FromRoutingInstances[0] != "default" {
		t.Fatalf("NAT64 snapshot = %+v, want singular/list literal default", nat64)
	}
}

func TestDeclaredDefaultNATEgressScopeMatchesNamedOnly17677(t *testing.T) {
	rule := SourceNATRuleSnapshot{ToRoutingInstance: "default"}
	named := InterfaceSnapshot{RoutingInstance: "default"}
	main := InterfaceSnapshot{}
	if !interfaceInSnapshotEgressScope(rule, named) {
		t.Fatal("literal default egress scope did not match named default interface")
	}
	if interfaceInSnapshotEgressScope(rule, main) {
		t.Fatal("literal default egress scope matched main-instance interface")
	}

	rule.ToRoutingInstance = config.NATDefaultRoutingInstanceWire
	if !interfaceInSnapshotEgressScope(rule, main) {
		t.Fatal("explicit-master wire scope did not match main-instance interface")
	}
	if interfaceInSnapshotEgressScope(rule, named) {
		t.Fatal("explicit-master wire scope matched named default interface")
	}
}
