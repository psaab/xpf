package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15789: the Go sync must publish the ingress zone's resolved
// ScreenProfile.land / alarm-without-drop posture into
// userspace_land_screen so the XDP shim honours it on its terminal
// kernel-pass arms. FAIL-ON-REVERT: reverting
// buildUserspaceLandScreenEntries to publish nothing (the #13953
// unconditional-drop world, where the map stays empty and every zone
// reads absent=fail-closed-drop) makes the disabled and audit rows
// below RED — those zones would drop LAND packets their profile says
// to pass or alarm-only.
func TestBuildUserspaceLandScreenEntries15789(t *testing.T) {
	snap := &ConfigSnapshot{
		Screens: []ScreenProfileSnapshot{
			{Zone: "dropzone", Land: true},
			{Zone: "auditzone", Land: true, AlarmWithoutDrop: true},
			{Zone: "passzone", Land: false, SynFin: true},
		},
		ScreenMissingProfiles: []ScreenMissingProfileRef{
			{Zone: "ghostzone", Profile: "ghost"},
		},
		ScreenInertProfiles: []ScreenMissingProfileRef{
			{Zone: "inertdrop", Profile: "empty"},
			{Zone: "inertaudit", Profile: "auditonly", AlarmWithoutDrop: true},
		},
	}
	got := buildUserspaceLandScreenEntries(snap)

	if v, ok := got[config.StableZoneID("dropzone")]; !ok || v != landScreenDrop {
		t.Errorf("dropzone = (%d, %v), want (landScreenDrop, true): LAND enabled without audit must drop", v, ok)
	}
	if v, ok := got[config.StableZoneID("auditzone")]; !ok || v != landScreenAlarm {
		t.Errorf("auditzone = (%d, %v), want (landScreenAlarm, true): LAND under alarm-without-drop must alarm without dropping", v, ok)
	}
	if v, ok := got[config.StableZoneID("passzone")]; !ok || v != landScreenPass {
		t.Errorf("passzone = (%d, %v), want (landScreenPass, true): LAND disabled publishes an explicit PASS row marking the zone resolved", v, ok)
	}
	// Missing profile: the worker substitutes conservative_default
	// (LAND on, no audit flag to read) — drop.
	if v, ok := got[config.StableZoneID("ghostzone")]; !ok || v != landScreenDrop {
		t.Errorf("ghostzone = (%d, %v), want (landScreenDrop, true): unresolved profile substitutes the LAND-on default", v, ok)
	}
	// Inert profiles get the same substituted default; the defined
	// profile's audit flag rides the inert ref.
	if v, ok := got[config.StableZoneID("inertdrop")]; !ok || v != landScreenDrop {
		t.Errorf("inertdrop = (%d, %v), want (landScreenDrop, true)", v, ok)
	}
	if v, ok := got[config.StableZoneID("inertaudit")]; !ok || v != landScreenAlarm {
		t.Errorf("inertaudit = (%d, %v), want (landScreenAlarm, true)", v, ok)
	}
	if len(got) != 6 {
		t.Errorf("entries = %v, want exactly 6 rows", got)
	}

	// Nil snapshot publishes nothing; every zone reads absent at the
	// shim and fails closed to drop (the #13953 skew posture).
	if got := buildUserspaceLandScreenEntries(nil); len(got) != 0 {
		t.Errorf("nil snapshot entries = %v, want empty", got)
	}
}
