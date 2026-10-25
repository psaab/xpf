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
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	store := newPolicyHitCountCLIStore(t, true)
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
	c := &CLI{store: store, dp: &quarantineSessionCLIDP10530{Manager: dataplane.New(), result: result}}
	for i := range 100 {
		filter := &sessionFilter{cfg: cfg}
		filter.populateIfaceMaps(c)
		id := result.ZoneIDs["zzq17760"]
		if filter.zoneIfaces[uint16(id)] == nil || len(filter.zoneIfaces[uint16(id)]) != 1 || filter.zoneIfaces[uint16(id)][0] != "if-survivor" {
			t.Fatalf("iteration %d survivor interfaces = %v, want only if-survivor", i, filter.zoneIfaces[uint16(id)])
		}
		filter.zoneName = "zzq8100"
		filter.zoneID = uint16(id)
		if got := filter.zoneDisplay(uint16(id), "zzq17760"); got != "zzq17760 "+config.ZoneQuarantineReferenceQualifier {
			t.Fatalf("iteration %d quarantined display = %q, want reference-qualified name", i, got)
		}
	}
	ordinary := &sessionFilter{
		cfg:      cfg,
		zoneName: "trust",
		zoneID:   uint16(result.ZoneIDs["trust"]),
	}
	ordinary.populateIfaceMaps(c)
	if got := ordinary.zoneIfaces[uint16(result.ZoneIDs["trust"])]; len(got) != 1 || got[0] != "if-trust" {
		t.Fatalf("ordinary control interfaces = %v, want if-trust", got)
	}
	if got := ordinary.zoneDisplay(uint16(result.ZoneIDs["trust"]), "trust"); got != "trust" {
		t.Fatalf("ordinary control display = %q, want trust", got)
	}
}
