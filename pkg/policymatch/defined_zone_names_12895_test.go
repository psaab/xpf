package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12895: DefinedZoneNames must exclude quarantined zones (z214 loses
// the StableZoneID collision to z174), so wildcard globals do not
// display as governing quarantined transit pairs.
func TestDefinedZoneNamesExcludesQuarantined12895(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174"}, "z214": {Name: "z214"}, "trust": {Name: "trust"},
	}}}
	defined := DefinedZoneNames(cfg)
	if !defined["z174"] || !defined["trust"] {
		t.Fatalf("survivor/ordinary zones must be defined: %v", defined)
	}
	if defined["z214"] {
		t.Fatalf("quarantined zone z214 must not be defined: %v", defined)
	}
	if GlobalPolicyAppliesToZonePairInZones(nil, nil, "z214", "z174", defined) {
		t.Fatal("unscoped global must not apply to a quarantined transit pair")
	}
}
