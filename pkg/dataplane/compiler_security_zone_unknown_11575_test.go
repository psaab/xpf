package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type unknownZoneRecorder11575 struct {
	DataPlane
	writes int
}

func (d *unknownZoneRecorder11575) SetZoneConfig(uint16, ZoneConfig) error {
	d.writes++
	return nil
}

func TestUnknownEnforcementZoneChildDoesNotInstallZone11575(t *testing.T) {
	text := `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  screeen;
 } }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse config: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || !zone.DroppedEnforcementChild || len(zone.Interfaces) != 0 {
		t.Fatalf("compiled zone was not unbound: %+v", zone)
	}

	// Probe the dataplane's own poison gate as well as compiler sanitization:
	// if a caller reconstructs the authored refs, the marked zone is still
	// excluded before any interface can be mapped.
	zone.Interfaces = []string{"ge-0/0/0.0"}
	dp := &unknownZoneRecorder11575{}
	result := &CompileResult{
		ZoneIDs:   map[string]uint16{"trust": config.StableZoneID("trust")},
		ScreenIDs: map[string]uint16{"safe": 1},
	}
	if _, err := programZoneMaps(dp, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	if dp.writes != 0 {
		t.Fatalf("poisoned zone entered dataplane zone maps %d times; want zero", dp.writes)
	}
	if len(result.pendingXDP) != 0 {
		t.Fatalf("poisoned zone retained interface/XDP bindings: %v", result.pendingXDP)
	}
	foundUnarmed := false
	for _, surface := range result.unarmedSurfaces {
		if surface.Name == "zone:trust" && strings.Contains(surface.Reason, "enforcement-bearing") {
			foundUnarmed = true
			break
		}
	}
	if !foundUnarmed {
		t.Fatalf("poisoned zone exclusion was not recorded: %+v", result.unarmedSurfaces)
	}
}
