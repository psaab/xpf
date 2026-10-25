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
