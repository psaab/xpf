package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5820: the operational `show`/`clear ... application <name>` filter must
// identify exactly ONE application. Application names are case-sensitive
// identifiers end to end — the parser, typed store, resolver, catalog, and
// AppID stamping all preserve and key on exact case — so two applications
// differing only in case ("Foo" vs "foo") are DISTINCT, receive distinct
// AppIDs, and stamp distinct session labels. SessionMatches was the sole
// case-folding component (strings.EqualFold): it let a single-case filter
// collapse two distinct applications on the display path and — because the same
// predicate drives the destructive ClearSessions walk — broaden a filtered
// clear to delete sessions the operator did not name. This regression pins the
// case-EXACT predicate.
//
// FAIL-ON-REVERT: restoring the pre-#5820 predicate
//
//	strings.EqualFold(ResolveSessionName(...), filter)
//
// makes the case-mismatch assertions below over-match (filter "foo" wrongly
// matches the "Foo" session, filter "junos-http" wrongly matches the
// "JUNOS-HTTP" session), turning this test RED — the required fail-on-revert
// acceptance test for the over-delete/over-collapse bug.
func TestSessionMatchesCaseSensitive5820(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	// Distinct-case apps get distinct AppIDs; the map mirrors what BuildCatalog
	// stamps for a config that legitimately defines both "Foo" and "foo".
	appNames := map[config.AssignedAppID]string{
		1: "Foo",
		2: "foo",
		3: "http",
		4: "JUNOS-HTTP", // user app whose name folds onto a predefined name
		5: "junos-http", // predefined-style name
	}

	// Helper: a TCP/80 session carrying the given app_id.
	match := func(filter string, appID config.AssignedAppID) bool {
		return SessionMatches(filter, appNames, cfg, 6, 40000, 80, appID)
	}

	// A session resolved to "Foo" must NOT match the lower-case filter "foo",
	// and MUST match the exact "Foo". (RED on revert: EqualFold folds "foo"
	// onto "Foo".)
	if match("foo", 1) {
		t.Error("SessionMatches: filter \"foo\" must NOT match a session resolved to \"Foo\" (case-sensitive, #5820)")
	}
	if !match("Foo", 1) {
		t.Error("SessionMatches: filter \"Foo\" must match a session resolved to \"Foo\"")
	}

	// The distinct lower-case session matches only its own exact name.
	if !match("foo", 2) {
		t.Error("SessionMatches: filter \"foo\" must match a session resolved to \"foo\"")
	}
	if match("Foo", 2) {
		t.Error("SessionMatches: filter \"Foo\" must NOT match a session resolved to \"foo\" (case-sensitive, #5820)")
	}

	// "http" matches only the exact spelling.
	if !match("http", 3) {
		t.Error("SessionMatches: filter \"http\" must match a session resolved to \"http\"")
	}
	if match("HTTP", 3) {
		t.Error("SessionMatches: filter \"HTTP\" must NOT match a session resolved to \"http\" (case-sensitive, #5820)")
	}

	// User-vs-predefined case collision: a user "JUNOS-HTTP" and a "junos-http"
	// must not collapse. The filter "junos-http" selects only the exact
	// "junos-http" session, never the user "JUNOS-HTTP" one. (RED on revert.)
	if match("junos-http", 4) {
		t.Error("SessionMatches: filter \"junos-http\" must NOT match a session resolved to \"JUNOS-HTTP\" (no case collapse, #5820)")
	}
	if !match("junos-http", 5) {
		t.Error("SessionMatches: filter \"junos-http\" must match a session resolved to \"junos-http\"")
	}

	// An empty filter still matches everything (unchanged select-all behavior).
	if !match("", 1) {
		t.Error("SessionMatches: an empty filter must match any session")
	}
}
