package logging

import "testing"

// #16462: pkg/config's syslogFacilityKnown16462 BSD set (kern, auth,
// syslog, local0-local7) plus the Junos vocabulary must agree with
// ParseFacilityChecked: every facility config warns-or-not on must be
// exactly a facility the runtime maps (or the `any`/`*` wildcard).
// pkg/logging imports pkg/config, so this direction is testable here;
// the Junos side is already pinned by #7187.
func TestFacilityKnown16462MatchesRuntime(t *testing.T) {
	for _, name := range []string{"kern", "auth", "syslog", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"} {
		if _, ok := ParseFacilityChecked(name); !ok {
			t.Errorf("config-known facility %q is not mapped by ParseFacilityChecked (#16462)", name)
		}
	}
	for _, name := range []string{"bogusfac", "kernl", "ntp", "security"} {
		if _, ok := ParseFacilityChecked(name); ok {
			t.Errorf("facility %q must stay unmapped so the #16462 warning is correct", name)
		}
	}
	if !FacilityIsWildcard("any") {
		t.Error("any must remain the syslog wildcard (#16462)")
	}
}
