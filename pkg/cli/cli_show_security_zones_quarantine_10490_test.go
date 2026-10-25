package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowZonesDisplayReportsQuarantinedZone10490(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
		"zzq17760": {},
		"zzq8100":  {},
	}}}
	exclusions := config.ZoneQuarantineExclusions([]string{"zzq8100", "zzq17760"})
	if _, ok := exclusions["zzq8100"]; !ok {
		t.Fatalf("builder exclusion verdict omitted zzq8100: %v", exclusions)
	}
	if _, ok := exclusions["zzq17760"]; ok {
		t.Fatalf("builder exclusion verdict dropped surviving zzq17760: %v", exclusions)
	}

	out := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if !strings.Contains(out, "Security zone: zzq8100") {
		t.Fatalf("showZonesDisplay omitted the quarantined zone's authored entry:\n%s", out)
	}
	if !strings.Contains(out, "Quarantine: security zone \"zzq8100\"") {
		t.Fatalf("showZonesDisplay omitted the quarantine reason:\n%s", out)
	}
	if strings.Contains(out, "Quarantine: security zone \"zzq17760\"") {
		t.Fatalf("showZonesDisplay incorrectly marked the surviving zone quarantined:\n%s", out)
	}
}
