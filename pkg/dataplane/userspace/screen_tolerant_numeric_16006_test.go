package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16006: a screen profile marked BadNumericUnresolved (bad limit-session
// value on the tolerant path, no Junos default to substitute) must be
// treated as unresolved by the snapshot builder: no screens entry is
// published for referencing zones, the zone lands in the missing-profile
// set (so the dataplane substitutes the conservative default, #7168),
// and it does NOT also land in the inert set (the three states stay
// disjoint). A resolved profile alongside it keeps publishing normally.
//
// FAIL-ON-REVERT: drop the BadNumericUnresolved skip in
// buildScreenSnapshots and the bad profile publishes with its configured
// checks (minus the silently-disabled cap); drop the missing-refs arm
// and the zone vanishes from every set while still getting no screens
// entry — indistinguishable from a zone with no screen configured.
func TestScreenBadNumericUnresolvedRoutesToMissing16006(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "bad"},
		"untrust": {Name: "untrust", ScreenProfile: "good"},
		"plain":   {Name: "plain"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"bad": {
			Name:                 "bad",
			TCP:                  config.TCPScreen{Land: true},
			BadNumericUnresolved: true,
		},
		"good": {
			Name: "good",
			TCP:  config.TCPScreen{Land: true},
		},
	}

	snaps := buildScreenSnapshots(cfg)
	if len(snaps) != 1 || snaps[0].Zone != "untrust" {
		t.Fatalf("only the resolved profile may publish, got %+v", snaps)
	}

	missing := ScreenMissingProfileRefs(cfg)
	if len(missing) != 1 || missing[0].Zone != "trust" || missing[0].Profile != "bad" {
		t.Fatalf("unresolved profile zone must be in missing set, got %+v", missing)
	}

	inert := ScreenInertProfileRefs(cfg)
	for _, r := range inert {
		if r.Zone == "trust" {
			t.Fatalf("unresolved zone must not also be inert (sets are disjoint), got %+v", inert)
		}
	}

	// Full snapshot: the wire carries the same split.
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Screens) != 1 || snap.Screens[0].Zone != "untrust" {
		t.Fatalf("snapshot screens = %+v, want only untrust", snap.Screens)
	}
	if len(snap.ScreenMissingProfiles) != 1 || snap.ScreenMissingProfiles[0].Zone != "trust" {
		t.Fatalf("snapshot missing = %+v, want trust/bad", snap.ScreenMissingProfiles)
	}
	for _, r := range snap.ScreenInertProfiles {
		if r.Zone == "trust" {
			t.Fatalf("snapshot inert must not contain unresolved zone, got %+v", snap.ScreenInertProfiles)
		}
	}
}

// Fold (#16006, Opus): an unresolved profile that authored
// alarm-without-drop must preserve the modifier through the missing-profile
// path. Before the fold buildScreenMissingProfileRefs emitted the ref with
// AlarmWithoutDrop always false, so the dataplane hard-dropped the
// substituted conservative default's malformed set instead of logging and
// forwarding — the exact inverse of the operator's audit request, the
// #9425 defect on the new arm.
func TestScreenUnresolvedPreservesAlarmWithoutDrop16006(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", ScreenProfile: "bad-audit"},
		"untrust": {Name: "untrust", ScreenProfile: "ghost"},
		"dmz":     {Name: "dmz", ScreenProfile: "bad-plain"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"bad-audit": {
			Name:                 "bad-audit",
			TCP:                  config.TCPScreen{Land: true},
			AlarmWithoutDrop:     true,
			BadNumericUnresolved: true,
		},
		"bad-plain": {
			Name:                 "bad-plain",
			TCP:                  config.TCPScreen{Land: true},
			BadNumericUnresolved: true,
		},
	}
	missing := ScreenMissingProfileRefs(cfg)
	byZone := map[string]ScreenMissingProfileRef{}
	for _, r := range missing {
		byZone[r.Zone] = r
	}
	if len(missing) != 3 {
		t.Fatalf("missing = %+v, want trust/untrust/dmz", missing)
	}
	if !byZone["trust"].AlarmWithoutDrop {
		t.Errorf("defined-but-unresolved audit profile must carry AlarmWithoutDrop=true, got %+v", byZone["trust"])
	}
	if byZone["dmz"].AlarmWithoutDrop {
		t.Errorf("unresolved profile without the modifier must stay false, got %+v", byZone["dmz"])
	}
	if byZone["untrust"].AlarmWithoutDrop {
		t.Errorf("truly undefined profile has no modifier to carry, got %+v", byZone["untrust"])
	}
	// The full snapshot wire must carry the same flag.
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	wire := map[string]bool{}
	for _, r := range snap.ScreenMissingProfiles {
		wire[r.Zone] = r.AlarmWithoutDrop
	}
	if !wire["trust"] || wire["dmz"] || wire["untrust"] {
		t.Errorf("snapshot missing-profile audit flags = %v, want trust=true only", wire)
	}
}

// A defined-but-inert profile (no BadNumeric) still lands in the inert
// set and NOT the missing set — the #16006 arm must not reclassify it.
func TestScreenInertUnaffectedBy16006(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "empty"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"empty": {Name: "empty"},
	}
	if missing := ScreenMissingProfileRefs(cfg); len(missing) != 0 {
		t.Fatalf("inert profile must not be missing, got %+v", missing)
	}
	inert := ScreenInertProfileRefs(cfg)
	if len(inert) != 1 || inert[0].Zone != "trust" {
		t.Fatalf("inert profile must stay inert, got %+v", inert)
	}
}
