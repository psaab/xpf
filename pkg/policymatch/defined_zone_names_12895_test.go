package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12895: DefinedZoneNames stays the authored inventory; quarantined
// zones remain addressable by explicit name (views qualify them).
func TestDefinedZoneNamesExcludesQuarantined12895(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"}, "zzq8100": {Name: "zzq8100"}, "trust": {Name: "trust"},
	}}}
	// DefinedZoneNames is the authored inventory (explicit filters by a
	// quarantined name still resolve; views qualify the name, #10530).
	// Applicability over EFFECTIVE (non-quarantined) zones is the
	// shadowing analyzer's own expansion (#12894), not this map.
	defined := DefinedZoneNames(cfg)
	if !defined["zzq17760"] || !defined["zzq8100"] || !defined["trust"] {
		t.Fatalf("inventory must carry every authored zone: %v", defined)
	}
}
