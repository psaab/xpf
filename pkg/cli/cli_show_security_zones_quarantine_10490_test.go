package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowZonesDisplayReportsQuarantinedZone10490(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"z174": {},
		"z214": {},
	}}}
	out := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if !strings.Contains(out, "Security zone: z214") {
		t.Fatalf("showZonesDisplay omitted the quarantined zone's authored entry:\n%s", out)
	}
	if !strings.Contains(out, "Quarantine: security zone \"z214\"") {
		t.Fatalf("showZonesDisplay omitted the quarantine reason:\n%s", out)
	}
	if strings.Contains(out, "Quarantine: security zone \"z174\"") {
		t.Fatalf("showZonesDisplay incorrectly marked the surviving zone quarantined:\n%s", out)
	}
}
