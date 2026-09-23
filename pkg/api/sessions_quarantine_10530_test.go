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
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
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
		dp:    &quarantineSessionAPIDP10530{Manager: dataplane.New(), result: result},
	}
	for i := range 100 {
		view := s.buildSessionView()
		id := result.ZoneIDs["z174"]
		if view.zoneNames[id] != "z174" {
			t.Fatalf("iteration %d zone name[%d] = %q, want survivor z174", i, id, view.zoneNames[id])
		}
		if got := view.zoneIfaces[id]; len(got) != 1 || got[0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, got)
		}
	}
	view := s.buildSessionView()
	if len(view.zoneNames) != 2 ||
		view.zoneNames[result.ZoneIDs["trust"]] != "trust" ||
		view.zoneNames[result.ZoneIDs["z174"]] != "z174" {
		t.Fatalf("ordinary/survivor reverse-map controls = %v, want trust and z174", view.zoneNames)
	}
	if got := view.zoneIfaces[result.ZoneIDs["trust"]]; len(got) != 1 || got[0] != "if-trust" {
		t.Fatalf("ordinary control interfaces = %v, want if-trust", got)
	}
}
