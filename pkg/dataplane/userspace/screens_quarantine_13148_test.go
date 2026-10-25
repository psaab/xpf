package userspace

import (
	"testing"
)

// #13148 (D3-02): quarantined (StableZoneID collision loser) and reserved
// zones must not leak into snap.Screens, snap.ScreenMissingProfiles,
// snap.ScreenInertProfiles, nor activate SYN-cookie protection globally.
// zzq8100 collides with zzq17760; junos-host is a reserved token. Only zzq17760 survives.
func TestQuarantinedAndReservedZonesExcludedFromScreens13148(t *testing.T) {
	cfg := compileScreenCfgLenient7059(t, []string{
		"set security flow syn-flood-protection-mode syn-cookie",
		"set security screen ids-option syn-prof tcp syn-flood attack-threshold 100",
		"set security screen ids-option inert-prof alarm-without-drop",
		"set security screen ids-option live-prof tcp land",
		"set security zones security-zone zzq17760 screen live-prof",
		"set security zones security-zone zzq8100 interfaces ge-0/0/1.0",
		"set security zones security-zone junos-host screen missing-scr",
		"set security zones security-zone junos-global screen inert-prof",
	})

	// The active survivor still publishes its screen; only excluded rows vanish.
	if got := buildScreenSnapshots(cfg); len(got) != 1 || got[0].Zone != "zzq17760" {
		t.Fatalf("buildScreenSnapshots: expected only survivor zzq17760, got %+v", got)
	}
	if got := buildScreenInertProfileRefs(cfg); len(got) != 0 {
		t.Fatalf("buildScreenInertProfileRefs: expected no rows, got %+v", got)
	}
	if userspaceSynCookieProtectionActive(cfg) {
		t.Fatalf("userspaceSynCookieProtectionActive: quarantined zzq8100 syn-flood must not activate global SYN-cookie")
	}
	if key, ring := buildSYNCookieKeys(cfg, synCookieNow()); key != "" || ring != nil {
		t.Fatalf("buildSYNCookieKeys: expected no keys for quarantined-only syn-flood, got key=%q ring=%v", key, ring)
	}
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
			{Zone: "zzq17760"},
			{Zone: "zzq8100", SYNFloodThreshold: 100, SYNCookie: true},
			{Zone: "junos-host"},
			{Zone: "junos-global"},
		},
		ScreenMissingProfiles: []ScreenMissingProfileRef{{Zone: "junos-host", Profile: "missing-scr"}, {Zone: "zzq17760", Profile: "x"}},
		ScreenInertProfiles:   []ScreenMissingProfileRef{{Zone: "junos-global", Profile: "inert-prof"}, {Zone: "zzq17760", Profile: "y"}},
		SYNCookieMasterKey:    "should-be-cleared",
		SYNCookieKeyRing:      &SYNCookieKeyRingSnapshot{},
	}
	quarantineCollidingZones(snap)
	if len(snap.Zones) != 1 || snap.Zones[0].Name != "zzq17760" {
		t.Fatalf("positive control: expected only zzq17760 zones, got %+v", snap.Zones)
	}
	for _, s := range snap.Screens {
		if s.Zone != "zzq17760" {
			t.Fatalf("quarantined/reserved zone leaked into snap.Screens: %+v", snap.Screens)
		}
	}
	for _, r := range snap.ScreenMissingProfiles {
		if r.Zone != "zzq17760" {
			t.Fatalf("quarantined zone leaked into ScreenMissingProfiles: %+v", snap.ScreenMissingProfiles)
		}
	}
	for _, r := range snap.ScreenInertProfiles {
		if r.Zone != "zzq17760" {
			t.Fatalf("reserved zone leaked into ScreenInertProfiles: %+v", snap.ScreenInertProfiles)
		}
	}
	// Only quarantined zzq8100 carried syn-flood; quarantine must also clear
	// previously built keys when no surviving screen row enables SYN-cookie.
	if snap.SYNCookieMasterKey != "" || snap.SYNCookieKeyRing != nil {
		t.Fatalf("SYN-cookie keys must be inactive when no surviving zone has syn-flood, got key=%q ring=%v", snap.SYNCookieMasterKey, snap.SYNCookieKeyRing)
	}
}
