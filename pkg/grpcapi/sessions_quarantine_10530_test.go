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
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	store := quarantinePolicyTextStore10530(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":    {Name: "trust", Interfaces: []string{"if-trust"}},
		"zzq17760": {Name: "zzq17760", Interfaces: []string{"if-survivor"}},
		"zzq8100":  {Name: "zzq8100", Interfaces: []string{"if-quarantined"}},
	}
	result := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
		"trust":    config.StableZoneID("trust"),
		"zzq17760": config.StableZoneID("zzq17760"),
		"zzq8100":  config.StableZoneID("zzq8100"),
	}}
	s := &Server{
		store: store,
		dp:    &quarantineSessionGRPCDP10530{Manager: dataplane.New(), result: result},
	}
	for i := range 100 {
		filter := s.buildSessionFilter(&pb.GetSessionsRequest{})
		id := result.ZoneIDs["zzq17760"]
		if filter.zoneNames[uint16(id)] != "zzq17760" {
			t.Fatalf("iteration %d zone name[%d] = %q, want survivor zzq17760", i, id, filter.zoneNames[uint16(id)])
		}
		if got := filter.zoneIfaces[uint16(id)]; len(got) != 1 || got[0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, got)
		}
	}
	filter := s.buildSessionFilter(&pb.GetSessionsRequest{})
	if len(filter.zoneNames) != 2 || filter.zoneNames[uint16(result.ZoneIDs["trust"])] != "trust" ||
		filter.zoneNames[uint16(result.ZoneIDs["zzq17760"])] != "zzq17760" {
		t.Fatalf("ordinary/survivor reverse-map controls = %v, want trust and zzq17760", filter.zoneNames)
	}
}
