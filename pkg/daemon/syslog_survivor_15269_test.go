package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #15269 C09-02: applySyslogConfig must use survivor-aware zone names.
// z174/z214 collide; survivor (sorted-first, non-quarantined) is z174.
// Issue acceptance probe wording "z174:200" denotes survivor z174 wins
// the colliding id (StableZoneID, deterministic).

func TestApplySyslogSurvivor15269(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("premise collision broken")
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174": {Name: "z174"}, "z214": {Name: "z214"}, "trust": {Name: "trust"},
	}
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)
	id := config.StableZoneID("z174")
	if got := er.ZoneName(id); got != "z174" {
		t.Errorf("zone %d = %q, want z174 survivor", id, got)
	}
	if got := er.ZoneName(config.StableZoneID("trust")); got != "trust" {
		t.Errorf("trust = %q", got)
	}
}
