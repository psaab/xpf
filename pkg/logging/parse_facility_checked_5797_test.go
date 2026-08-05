package logging

import "testing"

// #5797 invariant 7, visibility half.
//
// ParseFacility collapses "unrecognized" and "local0" into the same return
// value, so a caller cannot distinguish an authored `local0` from a typo — or
// from a legitimate Junos facility name the mapper simply does not know, such
// as `authorization` — that silently became local0. Records then leave under a
// facility the configuration never names and the collector's facility-based
// routing misfiles them, with no signal anywhere.
//
// ParseFacilityChecked returns that missing bit so the daemon can report the
// substitution. It deliberately does NOT change which code is returned: the
// facility a misconfigured destination lands under is an operator-visible
// contract question owned by the deferred half of #5797.

// TestParseFacilityCheckedReportsUnmapped_5797 is the fail-on-revert guard.
// Reverting ParseFacilityChecked to `return ParseFacility(name), true` makes
// every unmapped case below claim to be known, and the daemon's warning — the
// only signal that a substitution happened — goes silent.
func TestParseFacilityCheckedReportsUnmapped_5797(t *testing.T) {
	unmapped := []string{
		// Plain typos.
		"kernel", "deamon", "autherization", "local8", "",
		// Junos facility names the mapper does not know. These are the ones
		// that matter: they are VALID configuration, they are what #5797's own
		// worked example uses, and today they silently become local0.
		"authorization", "interactive-commands", "conflict-log",
		"pfe", "security", "firewall", "external", "dfc",
		// BSD facilities outside the mapped set.
		"mail", "ftp", "cron", "authpriv", "lpr", "news", "uucp",
		// `any` is a selector wildcard for the rsyslog-backed file/user
		// destinations, not a numeric facility a host client can stamp on a
		// record — so it must report unmapped here even though it is valid
		// configuration on those other destinations.
		"any",
	}
	for _, name := range unmapped {
		code, known := ParseFacilityChecked(name)
		if known {
			t.Errorf("ParseFacilityChecked(%q) reported KNOWN; the runtime cannot map it, "+
				"so the substitution to local0 would stay silent (#5797)", name)
		}
		if code != FacilityLocal0 {
			t.Errorf("ParseFacilityChecked(%q) code = %d, want FacilityLocal0 (%d) — the "+
				"substitution itself must be unchanged; only its VISIBILITY changes",
				name, code, FacilityLocal0)
		}
	}
}

// TestParseFacilityCheckedAcceptsMapped_5797 is the over-rejection guard: every
// name the runtime really does map must report known, with the same code
// ParseFacility returns. A false "unmapped" would emit a warning on a correct
// config and train operators to ignore it.
func TestParseFacilityCheckedAcceptsMapped_5797(t *testing.T) {
	mapped := []string{
		"kern", "user", "daemon", "auth", "syslog", "change-log",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
	}
	for _, name := range mapped {
		code, known := ParseFacilityChecked(name)
		if !known {
			t.Errorf("ParseFacilityChecked(%q) reported UNMAPPED, but ParseFacility maps it "+
				"— a correct config would emit a spurious substitution warning", name)
		}
		if want := ParseFacility(name); code != want {
			t.Errorf("ParseFacilityChecked(%q) code = %d, want %d — the checked form must "+
				"agree with ParseFacility exactly", name, code, want)
		}
	}
}

// TestParseFacilityCheckedAgreesWithParseFacility_5797 pins that the two
// functions cannot drift: for the mapped set they return identical codes, and
// for anything else ParseFacility's local0 default is exactly what the checked
// form reports as unmapped. This is what makes the checked form a pure
// visibility split rather than a behaviour change.
func TestParseFacilityCheckedAgreesWithParseFacility_5797(t *testing.T) {
	for _, name := range []string{
		"kern", "daemon", "authorization", "kernel", "local3", "mail", "", "any",
	} {
		code, _ := ParseFacilityChecked(name)
		if want := ParseFacility(name); code != want {
			t.Errorf("ParseFacilityChecked(%q) = %d but ParseFacility(%q) = %d; the checked "+
				"form must not change which facility is used", name, code, name, want)
		}
	}
}
