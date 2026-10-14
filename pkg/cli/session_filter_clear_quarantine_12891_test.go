package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #12891: clearing by a quarantined (ID-collision loser) zone name must
// not resolve to the survivor's ID and delete its sessions.
func TestClearByQuarantinedZoneNameRejected12891(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174": {Name: "z174", Interfaces: []string{"if-survivor"}},
		"z214": {Name: "z214", Interfaces: []string{"if-quarantined"}},
	}
	result := &dataplane.ApplyResult{ZoneIDs: map[string]uint16{
		"z174": config.StableZoneID("z174"),
		"z214": config.StableZoneID("z214"),
	}}
	c := &CLI{store: store, dp: &quarantineSessionCLIDP10530{Manager: dataplane.New(), result: result}}

	loser := c.parseSessionFilterMode([]string{"zone", "z214"}, true)
	if err := loser.validate(); err == nil {
		t.Fatalf("clear by quarantined zone z214 must be rejected, filter=%+v", loser)
	}
	survivor := c.parseSessionFilterMode([]string{"zone", "z174"}, true)
	if err := survivor.validate(); err != nil {
		t.Fatalf("clear by survivor zone z174 must pass, got %v", err)
	}
	if survivor.zoneID != result.ZoneIDs["z174"] {
		t.Fatalf("survivor zoneID = %d, want %d", survivor.zoneID, result.ZoneIDs["z174"])
	}
}
