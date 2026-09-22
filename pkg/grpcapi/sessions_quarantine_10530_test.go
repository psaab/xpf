package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type quarantineSessionGRPCDP10530 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *quarantineSessionGRPCDP10530) IsLoaded() bool { return true }
func (d *quarantineSessionGRPCDP10530) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func TestBuildSessionFilterQuarantineSurvivor10530(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := quarantinePolicyTextStore10530(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"if-trust"}},
		"z174":  {Name: "z174", Interfaces: []string{"if-survivor"}},
		"z214":  {Name: "z214", Interfaces: []string{"if-quarantined"}},
	}
	result := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"trust": config.StableZoneID("trust"),
		"z174":  config.StableZoneID("z174"),
		"z214":  config.StableZoneID("z214"),
	}}
	s := &Server{
		store: store,
		dp:    &quarantineSessionGRPCDP10530{Manager: dataplane.New(), result: result},
	}
	for i := range 100 {
		filter := s.buildSessionFilter(&pb.GetSessionsRequest{})
		id := result.ZoneIDs["z174"]
		if filter.zoneNames[id] != "z174" {
			t.Fatalf("iteration %d zone name[%d] = %q, want survivor z174", i, id, filter.zoneNames[id])
		}
		if got := filter.zoneIfaces[id]; len(got) != 1 || got[0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, got)
		}
	}
}
