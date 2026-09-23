package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type quarantineSessionCLIDP10530 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *quarantineSessionCLIDP10530) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func TestSessionFilterQuarantineSurvivor10530(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newPolicyHitCountCLIStore(t, true)
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
	c := &CLI{store: store, dp: &quarantineSessionCLIDP10530{Manager: dataplane.New(), result: result}}
	for i := range 100 {
		filter := &sessionFilter{cfg: cfg}
		filter.populateIfaceMaps(c)
		id := result.ZoneIDs["z174"]
		if filter.zoneIfaces[id] == nil || len(filter.zoneIfaces[id]) != 1 || filter.zoneIfaces[id][0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, filter.zoneIfaces[id])
		}
		filter.zoneName = "z214"
		filter.zoneID = id
		if got := filter.zoneDisplay(id, "z174"); got != "z174 "+config.ZoneQuarantineReferenceQualifier {
			t.Fatalf("iteration %d quarantined display = %q, want reference-qualified name", i, got)
		}
	}
	ordinary := &sessionFilter{
		cfg:      cfg,
		zoneName: "trust",
		zoneID:   result.ZoneIDs["trust"],
	}
	ordinary.populateIfaceMaps(c)
	if got := ordinary.zoneIfaces[result.ZoneIDs["trust"]]; len(got) != 1 || got[0] != "if-trust" {
		t.Fatalf("ordinary control interfaces = %v, want if-trust", got)
	}
	if got := ordinary.zoneDisplay(result.ZoneIDs["trust"], "trust"); got != "trust" {
		t.Fatalf("ordinary control display = %q, want trust", got)
	}
}
