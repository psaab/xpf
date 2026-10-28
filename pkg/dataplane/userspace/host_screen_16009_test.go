package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16009: the Go sync must publish the ingress zone's resolved
// stateless-malformed screen mask into userspace_host_screen so the
// XDP shim honours it on its terminal kernel-pass arms.
// FAIL-ON-REVERT: reverting buildUserspaceHostScreenEntries to
// publish nothing makes every row below RED — host-bound malformed
// packets would again pass the shim unscreened (or, for resolved
// zones, read checks-off).
func TestBuildUserspaceHostScreenEntries16009(t *testing.T) {
	snap := &ConfigSnapshot{
		Screens: []ScreenProfileSnapshot{
			{Zone: "fullzone", PingDeath: true, Teardrop: true, ICMPFragment: true, SynFrag: true, SourceRoute: true, SynFin: true, NoFlag: true, FinNoAck: true, WinNuke: true},
			{Zone: "auditzone", Teardrop: true, AlarmWithoutDrop: true},
			{Zone: "offzone", Land: true},
		},
		ScreenMissingProfiles: []ScreenMissingProfileRef{
			{Zone: "ghostzone", Profile: "ghost"},
		},
		ScreenInertProfiles: []ScreenMissingProfileRef{
			{Zone: "inertdrop", Profile: "empty"},
			{Zone: "inertaudit", Profile: "auditonly", AlarmWithoutDrop: true},
		},
	}
	got := buildUserspaceHostScreenEntries(snap)

	full := hostScreenMaskFor(true, true, true, true, true, true, true, false)
	if v, ok := got[config.StableZoneID("fullzone")]; !ok || v != full {
		t.Errorf("fullzone = (%#x, %v), want (%#x, true): every enabled malformed check must be packed", v, ok, full)
	}
	audit := hostScreenMaskFor(false, true, false, false, false, false, false, true)
	if v, ok := got[config.StableZoneID("auditzone")]; !ok || v != audit {
		t.Errorf("auditzone = (%#x, %v), want (%#x, true): teardrop plus the alarm-without-drop bit", v, ok, audit)
	}
	// A screened zone with no malformed check enabled still publishes
	// an explicit zero row marking the zone resolved (checks off).
	if v, ok := got[config.StableZoneID("offzone")]; !ok || v != 0 {
		t.Errorf("offzone = (%#x, %v), want (0, true): screened zone publishes an explicit checks-off row", v, ok)
	}
	// Missing profile: the worker substitutes conservative_default —
	// ping-death/teardrop/syn-frag/source-route plus syn-fin and the
	// TCP-flag family, NOT icmp-fragment, no audit flag to read.
	conservative := hostScreenMaskFor(true, true, false, true, true, true, true, false)
	if v, ok := got[config.StableZoneID("ghostzone")]; !ok || v != conservative {
		t.Errorf("ghostzone = (%#x, %v), want (%#x, true): unresolved profile substitutes the conservative malformed set", v, ok, conservative)
	}
	if v, ok := got[config.StableZoneID("inertdrop")]; !ok || v != conservative {
		t.Errorf("inertdrop = (%#x, %v), want (%#x, true)", v, ok, conservative)
	}
	inertAudit := conservative | hostScreenAlarmBit
	if v, ok := got[config.StableZoneID("inertaudit")]; !ok || v != inertAudit {
		t.Errorf("inertaudit = (%#x, %v), want (%#x, true): substituted default carries the inert profile's audit flag", v, ok, inertAudit)
	}
	if len(got) != 6 {
		t.Errorf("entries = %v, want exactly 6 rows", got)
	}

	// Nil snapshot publishes nothing; a resolved zone then reads
	// checks-off and an unresolved zone fails closed at the shim.
	if got := buildUserspaceHostScreenEntries(nil); len(got) != 0 {
		t.Errorf("nil snapshot entries = %v, want empty", got)
	}
}
