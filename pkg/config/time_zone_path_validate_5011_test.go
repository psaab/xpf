package config_test

// #5011: `system time-zone` renders into the /etc/localtime symlink target
// (/usr/share/zoneinfo/<value>). Before this change the value was not
// path-validated, so a `..` component / absolute path / embedded space could
// steer the symlink target out of the zoneinfo root (a theoretical traversal).
//
// The fix adds ValidateTimeZone (a zoneinfo-name grammar: `/`-separated LDH+
// segments, no '.'/'..'/absolute component) strict at commit-check
// (SchemaValidate), plus a daemon-side render belt (pkg/daemon, zoneinfoTarget)
// that refuses an out-of-root target for a leniently-loaded value (#1960).
//
// Fail-on-revert: strip the validator from the time-zone leaf (or run against
// origin/master) and the "Rejects" cases below stop erroring.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestValidateTimeZone_Table(t *testing.T) {
	valid := []string{
		"UTC",
		"America/Los_Angeles",
		"Etc/GMT+5",
		"Etc/GMT-14",
		"America/Argentina/Buenos_Aires",
		"America/Port-au-Prince",
		"GMT0",
	}
	for _, v := range valid {
		if err := config.ValidateTimeZone(v); err != nil {
			t.Errorf("ValidateTimeZone(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",                         // empty
		"../../etc/shadow",         // path traversal
		"/etc/passwd",              // absolute path
		"..",                       // bare dotdot
		"Foo/../bar",               // interior dotdot
		"America//Los_Angeles",     // doubled slash
		"America/Los_Angeles/",     // trailing slash
		"America/Los_Angeles evil", // embedded space (2nd token)
		"America/Los_Angeles\nfoo", // newline injection
		"Zone.With.Dot",            // '.' component (not zoneinfo grammar)
	}
	for _, v := range invalid {
		if err := config.ValidateTimeZone(v); err == nil {
			t.Errorf("ValidateTimeZone(%q) = nil, want error", v)
		}
	}
}

func TestSchema5011_TimeZone_FlatSet(t *testing.T) {
	// Commit-check gate must reject a traversal value and accept a real zone.
	reject := []string{
		`set system time-zone "../../etc/shadow"`,
		`set system time-zone "/etc/localtime"`,
		`set system time-zone "America/Los_Angeles evil"`,
	}
	for _, c := range reject {
		if err := flatSchemaCheck(t, c); err == nil {
			t.Errorf("expected SchemaValidate to reject %q, got nil", c)
		}
	}
	accept := []string{
		`set system time-zone UTC`,
		`set system time-zone America/Los_Angeles`,
		`set system time-zone Etc/GMT+5`,
	}
	for _, c := range accept {
		if err := flatSchemaCheck(t, c); err != nil {
			t.Errorf("expected SchemaValidate to accept %q, got %v", c, err)
		}
	}
}
