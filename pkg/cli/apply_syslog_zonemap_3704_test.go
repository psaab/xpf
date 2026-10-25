package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSyslogZoneNameMapUsesStableZoneID is the RED-on-revert guard for the #3704
// follow-up: reloadSyslog (local-console commit/rollback path) builds the syslog
// zone-id -> name reverse map keyed by the STABLE name-hash
// config.StableZoneID(name), NOT by a sorted-positional (i+1) index.
//
// The event reader is SHARED with the daemon, whose applySyslogConfig /
// buildZoneIDs publishes the name-hash map; reloadSyslog runs AFTER that on
// every local-TTY commit. A positional map would clobber the shared reader with
// wrong ids and regress RT_FLOW zone rendering to `zone-N`. Reverting
// syslogZoneNameMap to `znMap[uint16(i+1)] = name` turns this RED: the
// StableZoneID key would resolve to the wrong name (or be absent) and the
// positional keys 1..N would be populated instead.
func TestSyslogZoneNameMapUsesStableZoneID(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
		"dmz":     {Name: "dmz"},
	}

	got := syslogZoneNameMap(cfg)

	if len(got) != len(cfg.Security.Zones) {
		t.Fatalf("map has %d entries, want %d (a StableZoneID collision or a dropped zone): %v",
			len(got), len(cfg.Security.Zones), got)
	}

	// Exact-key assertion: each zone must resolve at its StableZoneID slot. Under
	// the reverted positional (i+1) keying, StableZoneID(name) — a name-hash in
	// [1, 65533] — almost never equals a small positional index, so got[id] would
	// be "" and this fails, proving RED-on-revert.
	for name := range cfg.Security.Zones {
		id := config.StableZoneID(name)
		if got[id] != name {
			t.Fatalf("zone %q: map[StableZoneID=%d]=%q, want %q — the reverse map is NOT keyed by StableZoneID (positional-index regression, #3704)",
				name, id, got[id], name)
		}
	}
}

// TestSyslogZoneNameMapCollisionResolvesToSurvivor (#3719): when two zone names
// fold to the same StableZoneID the reverse map must resolve the shared id to
// the SURVIVOR (the sorted-first zone the dataplane installed), never to the
// QUARANTINED later-sorting zone — otherwise RT_FLOW/syslog would render the
// survivor's traffic under the wrong (quarantined) zone name. Reverting
// syslogZoneNameMap to the unconditional overwrite makes the result depend on
// map-iteration order (nondeterministic; can name zzq8100).
func TestSyslogZoneNameMapCollisionResolvesToSurvivor(t *testing.T) {
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
	}
	got := syslogZoneNameMap(cfg)
	id := config.StableZoneID("zzq17760")
	if got[id] != "zzq17760" {
		t.Fatalf("collision id %d resolves to %q, want the survivor zzq17760 (never the quarantined zzq8100)", id, got[id])
	}
	if len(got) != 1 {
		t.Fatalf("map has %d entries for a colliding pair, want 1 (the survivor only): %v", len(got), got)
	}
}
