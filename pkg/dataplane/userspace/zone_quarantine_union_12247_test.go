package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestNodeScopedZoneQuarantineUsesThreeViewUnion12247(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree, errs := config.NewParser(`groups {
  node0 { security { zones { security-zone z174; } } }
  node1 { security { zones { security-zone z214; } } }
}
apply-groups "${node}";`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse node-scoped zones: %v", errs)
	}

	for _, tc := range []struct {
		name           string
		nodeID         int
		wantZone       string
		wantQuarantine bool
	}{
		{name: "node0", nodeID: 0, wantZone: "z174"},
		{name: "node1", nodeID: 1, wantZone: "z214", wantQuarantine: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfigForNodeLenient(tree, tc.nodeID)
			if err != nil {
				t.Fatalf("tolerant node%d compile: %v", tc.nodeID, err)
			}
			if len(cfg.ZoneQuarantineNames) != 2 ||
				cfg.ZoneQuarantineNames[0] != "z174" ||
				cfg.ZoneQuarantineNames[1] != "z214" {
				t.Fatalf("node%d quarantine-name union = %v, want [z174 z214]",
					tc.nodeID, cfg.ZoneQuarantineNames)
			}
			excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
			if _, ok := excluded["z214"]; !ok {
				t.Fatalf("node%d config exclusions = %v, want peer-union loser z214",
					tc.nodeID, excluded)
			}
			if _, ok := excluded["z174"]; ok {
				t.Fatalf("node%d config exclusions = %v, want survivor z174 retained",
					tc.nodeID, excluded)
			}
			if got := config.ZoneQuarantineExcludedReason("z214", cfg); got == "" {
				t.Fatalf("node%d did not report peer-union loser z214 as quarantined", tc.nodeID)
			}
			if len(cfg.Security.Zones) != 1 || cfg.Security.Zones[tc.wantZone] == nil {
				t.Fatalf("node%d zones = %v, want only %q", tc.nodeID, cfg.Security.Zones, tc.wantZone)
			}

			snap := &ConfigSnapshot{Config: cfg, Zones: buildZoneSnapshots(cfg)}
			collisions := quarantineCollidingZones(snap)
			if tc.wantQuarantine {
				if len(collisions) != 1 || collisions[0].Quarantined != "z214" || collisions[0].Survivor != "z174" {
					t.Fatalf("node%d collision records = %+v, want z214 quarantined in favor of z174", tc.nodeID, collisions)
				}
				if len(snap.Zones) != 0 {
					t.Fatalf("node%d published zones = %+v, want z214 quarantined", tc.nodeID, snap.Zones)
				}
				return
			}
			if len(collisions) != 0 || len(snap.Zones) != 1 || snap.Zones[0].Name != "z174" {
				t.Fatalf("node%d published zones = %+v, collisions = %+v; want survivor z174", tc.nodeID, snap.Zones, collisions)
			}
		})
	}
}
