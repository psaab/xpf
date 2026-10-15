package userspace

import (
	"testing"
)

// #13148 (D3-02): quarantined (StableZoneID collision loser) and reserved
// zones must not leak into snap.Screens, snap.ScreenMissingProfiles,
// snap.ScreenInertProfiles, nor activate SYN-cookie protection globally.
// z214 collides with z174; junos-host is a reserved token. Only z174 survives.
func TestQuarantinedAndReservedZonesExcludedFromScreens13148(t *testing.T) {
	cfg := compileScreenCfgLenient7059(t, []string{
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security screen ids-option syn-prof tcp syn-flood attack-threshold 100",
		"set security screen ids-option inert-prof alarm-without-drop",
		"set security screen ids-option live-prof tcp land",
		"set security zones security-zone z174 screen live-prof",
		"set security zones security-zone z214 screen syn-prof",
		"set security zones security-zone z214 interfaces ge-0/0/1.0",
		"set security zones security-zone junos-host screen missing-scr",
		"set security zones security-zone junos-global screen inert-prof",
	})
	if zone := cfg.Security.Zones["z214"]; zone == nil || zone.ScreenProfile != "syn-prof" {
		t.Fatalf("test setup must attach syn-prof to quarantined z214, got %+v", zone)
	}
	// z214 really references a SYN-flood profile; it must not activate global
	// protection because that zone is quarantined.
	if userspaceSynCookieProtectionActive(cfg) {
		t.Error("quarantined z214 syn-flood activated global SYN-cookie protection")
	}
	if key, ring := buildSYNCookieKeys(cfg, synCookieNow()); key != "" || ring != nil {
		t.Error("quarantined-only syn-flood generated SYN-cookie key material")
	}

	// The active survivor still publishes its screen; only excluded rows vanish.
	if got := buildScreenSnapshots(cfg); len(got) != 1 || got[0].Zone != "z174" {
		t.Fatalf("buildScreenSnapshots: expected only survivor z174, got %+v", got)
	}
	if got := buildScreenInertProfileRefs(cfg); len(got) != 0 {
		t.Fatalf("buildScreenInertProfileRefs: expected no rows, got %+v", got)
	}
	// A surviving SYN-flood zone must continue to enable protection and keys.
	survivor := cfg.Security.Zones["z174"]
	survivor.ScreenProfile = "syn-prof"
	if !userspaceSynCookieProtectionActive(cfg) {
		t.Error("userspaceSynCookieProtectionActive: surviving z174 syn-flood was ignored")
	}
	if key, ring := buildSYNCookieKeys(cfg, synCookieNow()); key == "" || ring == nil {
		t.Error("buildSYNCookieKeys: no key material for surviving z174 syn-flood")
	}
	survivor.ScreenProfile = "live-prof"
	// Missing-profile refs from reserved zones must be excluded too.
	if got := buildScreenMissingProfileRefs(cfg); len(got) != 0 {
		t.Fatalf("buildScreenMissingProfileRefs: expected no rows, got %+v", got)
	}

	// Snapshot level (hand-built, as partial republish / peer-union paths can
	// produce): quarantineCollidingZones must scrub screen fields.
	snap := &ConfigSnapshot{
		Config: cfg,
		Zones:  buildZoneSnapshots(cfg),
		Screens: []ScreenProfileSnapshot{
			{Zone: "z174"},
			{Zone: "z214", SYNFloodThreshold: 100, SYNCookie: true},
			{Zone: "junos-host"},
			{Zone: "junos-global"},
		},
		ScreenMissingProfiles: []ScreenMissingProfileRef{{Zone: "junos-host", Profile: "missing-scr"}, {Zone: "z174", Profile: "x"}},
		ScreenInertProfiles:   []ScreenMissingProfileRef{{Zone: "junos-global", Profile: "inert-prof"}, {Zone: "z174", Profile: "y"}},
		SYNCookieMasterKey:    "should-be-cleared",
		SYNCookieKeyRing:      &SYNCookieKeyRingSnapshot{},
	}
	quarantineCollidingZones(snap)
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "z174" {
		t.Fatalf("positive control: expected only z174 zones, got %+v", snap.Zones)
	}
	for _, s := range snap.Screens {
		if s.Zone != "z174" {
			t.Fatalf("quarantined/reserved zone leaked into snap.Screens: %+v", snap.Screens)
		}
	}
	for _, r := range snap.ScreenMissingProfiles {
		if r.Zone != "z174" {
			t.Fatalf("quarantined zone leaked into ScreenMissingProfiles: %+v", snap.ScreenMissingProfiles)
		}
	}
	for _, r := range snap.ScreenInertProfiles {
		if r.Zone != "z174" {
			t.Fatalf("reserved zone leaked into ScreenInertProfiles: %+v", snap.ScreenInertProfiles)
		}
	}
	// Only quarantined z214 carried syn-flood; quarantine must also clear
	// previously built keys when no surviving screen row enables SYN-cookie.
	if snap.SYNCookieMasterKey != "" || snap.SYNCookieKeyRing != nil {
		t.Fatalf("SYN-cookie keys must be inactive when no surviving zone has syn-flood, got key=%q ring=%v", snap.SYNCookieMasterKey, snap.SYNCookieKeyRing)
	}
	// A surviving SYN-cookie screen also keeps snapshot key material.
	survivorSnap := &ConfigSnapshot{
		Config: cfg,
		Zones:  buildZoneSnapshots(cfg),
		Screens: []ScreenProfileSnapshot{
			{Zone: "z174", SYNFloodThreshold: 100, SYNCookie: true},
			{Zone: "z214", SYNFloodThreshold: 100, SYNCookie: true},
		},
		SYNCookieMasterKey: "keep",
		SYNCookieKeyRing:   &SYNCookieKeyRingSnapshot{},
	}
	quarantineCollidingZones(survivorSnap)
	if len(survivorSnap.Screens) != 1 || survivorSnap.Screens[0].Zone != "z174" ||
		survivorSnap.SYNCookieMasterKey != "keep" || survivorSnap.SYNCookieKeyRing == nil {
		t.Errorf("quarantine must keep keys for surviving syn-cookie screen: %+v", survivorSnap)
	}
}
