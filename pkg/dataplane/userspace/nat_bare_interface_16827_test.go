package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16827: hand-built typed configs that reach the snapshot builders
// without a compile must still emit the logical-unit name the Rust
// dataplane compares. A bare FromInterface on a plain (unit-0-only)
// interface folds to "<ifd>.0"; a bare ref on a multi-unit interface
// stays bare (never widened to unit 0) and so never matches.

func bareInterfaceCfg16827() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {}}},
		"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*config.InterfaceUnit{0: {}, 1: {}}},
	}
	return cfg
}

func TestSourceNATBareInterfaceSnapshot16827(t *testing.T) {
	cfg := bareInterfaceCfg16827()
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:          "bare",
		FromInterface: "ge-0/0/1",
		ToInterface:   "ge-0/0/1",
		Rules:         []*config.NATRule{{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p"}}},
	}, {
		Name:          "multi",
		FromInterface: "ge-0/0/7",
		Rules:         []*config.NATRule{{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p"}}},
	}}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"p": {Name: "p", Addresses: []string{"192.0.2.10/32"}}}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}
	var bareSnap, multiSnap *SourceNATRuleSnapshot
	// Both rule-sets share rule name r1; distinguish by FromInterface.
	for i := range snaps {
		if snaps[i].FromInterface == "ge-0/0/1.0" {
			bareSnap = &snaps[i]
		}
		if snaps[i].FromInterface == "ge-0/0/7" {
			multiSnap = &snaps[i]
		}
	}
	if bareSnap == nil {
		t.Fatalf("bare ref must fold to ge-0/0/1.0, snapshots=%+v", snaps)
	}
	if bareSnap.ToInterface != "ge-0/0/1.0" {
		t.Fatalf("ToInterface = %q, want ge-0/0/1.0", bareSnap.ToInterface)
	}
	if multiSnap == nil {
		t.Fatalf("multi-unit bare ref must stay bare ge-0/0/7, snapshots=%+v", snaps)
	}
}

func TestDestinationStaticBareInterfaceSnapshot16827(t *testing.T) {
	cfg := bareInterfaceCfg16827()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"P1": {Name: "P1", Address: "10.0.30.100/32"}},
		RuleSets: []*config.NATRuleSet{{
			Name:          "dnat-bare",
			FromInterface: "ge-0/0/1",
			Rules: []*config.NATRule{{Name: "R1",
				Match: config.NATMatch{DestinationAddress: "198.51.100.5/32"},
				Then:  config.NATThen{Type: config.NATDestination, PoolName: "P1"}}},
		}},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) == 0 {
		t.Fatal("expected a DNAT snapshot")
	}
	if got := snaps[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("DNAT FromInterface = %q, want ge-0/0/1.0", got)
	}

	cfg2 := bareInterfaceCfg16827()
	cfg2.Security.NAT.Static = []*config.StaticNATRuleSet{{
		Name:          "stat-bare",
		FromInterface: "ge-0/0/1",
		Rules:         []*config.StaticNATRule{{Name: "R1", Match: "198.51.100.5/32", Then: "10.0.0.5/32"}},
	}}
	ssnaps := buildStaticNATSnapshots(cfg2, nil)
	if len(ssnaps) != 1 {
		t.Fatalf("static snapshots = %d, want 1", len(ssnaps))
	}
	if got := ssnaps[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("static FromInterface = %q, want ge-0/0/1.0", got)
	}
}
