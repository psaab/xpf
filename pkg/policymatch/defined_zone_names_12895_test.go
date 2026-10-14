package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12895: DefinedZoneNames stays the authored inventory; quarantined
// zones remain addressable by explicit name (views qualify them).
func TestDefinedZoneNamesExcludesQuarantined12895(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {Name: "z174"}, "z214": {Name: "z214"}, "trust": {Name: "trust"},
	}}}
	// DefinedZoneNames is the authored inventory (explicit filters by a
	// quarantined name still resolve; views qualify the name, #10530).
	// Applicability over EFFECTIVE (non-quarantined) zones is the
	// shadowing analyzer's own expansion (#12894), not this map.
	defined := DefinedZoneNames(cfg)
	if !defined["z174"] || !defined["z214"] || !defined["trust"] {
		t.Fatalf("inventory must carry every authored zone: %v", defined)
	}
}
