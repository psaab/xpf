package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #12891: clearing by a quarantined (ID-collision loser) zone name must
// not resolve to the survivor's ID and delete its sessions.
func TestClearByQuarantinedZoneNameRejected12891(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760", Interfaces: []string{"if-survivor"}},
		"zzq8100":  {Name: "zzq8100", Interfaces: []string{"if-quarantined"}},
	}
	result := &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
		"zzq17760": config.StableZoneID("zzq17760"),
		"zzq8100":  config.StableZoneID("zzq8100"),
	}}
	c := &CLI{store: store, dp: &quarantineSessionCLIDP10530{Manager: dataplane.New(), result: result}}

	loser := c.parseSessionFilterMode([]string{"zone", "zzq8100"}, true)
	if err := loser.validate(); err == nil {
		t.Fatalf("clear by quarantined zone zzq8100 must be rejected, filter=%+v", loser)
	}
	survivor := c.parseSessionFilterMode([]string{"zone", "zzq17760"}, true)
	if err := survivor.validate(); err != nil {
		t.Fatalf("clear by survivor zone zzq17760 must pass, got %v", err)
	}
	if survivor.zoneID != uint16(result.ZoneIDs["zzq17760"]) {
		t.Fatalf("survivor zoneID = %d, want %d (low 16 bits of the u32 id, #16557)", survivor.zoneID, uint16(result.ZoneIDs["zzq17760"]))
	}
}
