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
