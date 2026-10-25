package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type quarantineSessionAPIDP10530 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *quarantineSessionAPIDP10530) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func TestBuildSessionViewQuarantineSurvivor10530(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
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
		dp:    &quarantineSessionAPIDP10530{Manager: dataplane.New(), result: result},
	}
	for i := range 100 {
		view := s.buildSessionView()
		id := result.ZoneIDs["zzq17760"]
		if view.zoneNames[uint16(id)] != "zzq17760" {
			t.Fatalf("iteration %d zone name[%d] = %q, want survivor zzq17760", i, id, view.zoneNames[uint16(id)])
		}
		if got := view.zoneIfaces[uint16(id)]; len(got) != 1 || got[0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, got)
		}
	}
	view := s.buildSessionView()
	if len(view.zoneNames) != 2 ||
		view.zoneNames[uint16(result.ZoneIDs["trust"])] != "trust" ||
		view.zoneNames[uint16(result.ZoneIDs["zzq17760"])] != "zzq17760" {
		t.Fatalf("ordinary/survivor reverse-map controls = %v, want trust and zzq17760", view.zoneNames)
	}
	if got := view.zoneIfaces[uint16(result.ZoneIDs["trust"])]; len(got) != 1 || got[0] != "if-trust" {
		t.Fatalf("ordinary control interfaces = %v, want if-trust", got)
	}
}
