package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #15269 C09-02: applySyslogConfig must use survivor-aware zone names.
// zzq17760/zzq8100 collide; survivor (sorted-first, non-quarantined) is zzq17760.
// Issue acceptance probe wording "zzq17760:200" denotes survivor zzq17760 wins
// the colliding id (StableZoneID, deterministic).

func TestApplySyslogSurvivor15269(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("premise collision broken")
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"}, "zzq8100": {Name: "zzq8100"}, "trust": {Name: "trust"},
	}
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)
	id := config.StableZoneID("zzq17760")
	if got := er.ZoneName(id); got != "zzq17760" {
		t.Errorf("zone %d = %q, want zzq17760 survivor", id, got)
	}
	if got := er.ZoneName(config.StableZoneID("trust")); got != "trust" {
		t.Errorf("trust = %q", got)
	}
}
