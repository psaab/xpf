package logging

import (
	"math/rand"
	"strings"
	"testing"
)

// parseFacilityMappingTable is the COMPLETE set of names ParseFacility maps to
// something other than its unrecognized-name default, enumerated from its
// switch. It is the reference both directions of the agreement test below are
// derived from; keeping it here (rather than sampling names ad hoc) is what
// lets that test claim to cover the whole table.
//
// #6829: this list is hand-copied, so its completeness is CHECKED rather than
// trusted — by TestParseFacilityMappingTableIsComplete_6829, which asserts that
// any name NOT in this table falls through ParseFacility to the default. A name
// ParseFacility maps but this table omits therefore fails that test; before it
// existed, the omission silently shrank the set every table-driven test here
// covers. Note what does the work: the check is behavioural (it CALLS
// ParseFacility), not a source comparison.
//
// `local0` is in the table even though ParseFacility's default also returns
// FacilityLocal0: it is an AUTHORED name with an explicit case, and telling it
// apart from the default is the entire point of ParseFacilityChecked.
var parseFacilityMappingTable = map[string]int{
	"kern":       FacilityKern,
	"user":       FacilityUser,
	"daemon":     FacilityDaemon,
	"auth":       FacilityAuth,
	"syslog":     FacilitySyslog,
	"local0":     FacilityLocal0,
	"local1":     FacilityLocal1,
	"local2":     FacilityLocal2,
	"local3":     FacilityLocal3,
	"local4":     FacilityLocal4,
	"local5":     FacilityLocal5,
	"local6":     FacilityLocal6,
	"local7":     FacilityLocal7,
	"change-log": FacilityLocal6,
}

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
//
// This is a common path, not an exotic one. `system syslog <dest> <facility>
// <severity>` models the facility as the schema's wildcard KEY with no key
// validator, so every one of these names commits clean — and the Junos
// spellings among them (`authorization`, `kernel`, `interactive-commands`) are
// what a vSRX config actually contains.

// unmappedCorpus builds the names that must report unmapped. Listing them by
// hand is what let an unlisted special case (`bogus -> (local0, true)`) slip
// through: a hand-written list only rejects what somebody thought to write
// down. So the corpus is DERIVED — every entry of the mapping table put
// through the mechanical edits a "be helpful about typos" special case would
// most plausibly accept (case flips, one-character substitutions and deletions,
// affixes) — and then extended with the vocabularies an operator actually
// types.
//
// Scope, stated rather than implied: this covers the mapping table's edit
// neighbourhood, the Junos facility vocabulary, the BSD facilities, and a
// randomly generated tail. It does NOT enumerate the infinite complement, so a
// special case on some string outside all of that would survive. What it does
// bind is every place such a case would realistically be written.
func unmappedCorpus() []string {
	seen := map[string]bool{}
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			if _, mapped := parseFacilityMappingTable[n]; mapped || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}

	for name := range parseFacilityMappingTable {
		add(strings.ToUpper(name), strings.ToUpper(name[:1])+name[1:])
		add(name+"0", name+"-", name+" ", " "+name, name+"x")
		for i := range name {
			add(name[:i] + name[i+1:])                                // one-character deletion
			add(name[:i] + "z" + name[i+1:])                          // one-character substitution
			add(name[:i] + strings.ToUpper(name[i:i+1]) + name[i+1:]) // one-character case flip
		}
	}

	// Junos facility names the mapper does not know. These are the ones that
	// matter: they are VALID configuration, they are what #5797's own worked
	// example uses, and today they silently become local0.
	add("authorization", "kernel", "interactive-commands", "conflict-log",
		"pfe", "security", "firewall", "external", "dfc", "ntp", "dcd")
	// BSD facilities outside the mapped set.
	add("mail", "ftp", "cron", "authpriv", "lpr", "news", "uucp")
	// `any` is a selector wildcard for the rsyslog-backed file/user
	// destinations, not a numeric facility a host client can stamp on a record
	// — so it must report unmapped here even though it is valid configuration
	// on those other destinations.
	add("any", "none", "*", "")
	// Plain typos and a generated tail.
	add("deamon", "autherization", "local8", "local10", "bogus", "facility")
	rng := rand.New(rand.NewSource(5797))
	const alphabet = "abcdefghijklmnopqrstuvwxyz-0123456789"
	for i := 0; i < 200; i++ {
		var sb strings.Builder
		for j := 0; j < 1+rng.Intn(12); j++ {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		add(sb.String())
	}
	return out
}

// TestParseFacilityCheckedReportsUnmapped_5797 is the fail-on-revert guard.
// Reverting ParseFacilityChecked to `return ParseFacility(name), true` makes
// every name in the corpus claim to be known, and the daemon's warning — the
// only signal that a substitution happened — goes silent.
func TestParseFacilityCheckedReportsUnmapped_5797(t *testing.T) {
	corpus := unmappedCorpus()
	if len(corpus) < 200 {
		t.Fatalf("unmapped corpus collapsed to %d entries; the derivation is broken and this "+
			"test is no longer checking what it claims", len(corpus))
	}
	for _, name := range corpus {
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
//
// It iterates the whole mapping table rather than a sample, and cross-checks
// each entry against ParseFacility itself.
//
// #6829 — the scope of that, stated exactly: this loop visits the names IN THE
// TABLE. A name added to ParseFacility but not to the table is not visited by
// any assertion here, so it CANNOT fail this test. An earlier version of this
// comment claimed "a table left stale fails the code comparison", which was
// false and was disproved by adding `audit-log` to ParseFacility and watching
// the package stay green. Staleness is caught by
// TestParseFacilityMappingTableIsComplete_6829, which CALLS ParseFacility on
// every corpus name and requires anything absent from this table to return the
// default; the code-agreement direction is closed by
// TestParseFacilityCheckedAgreesWithParseFacility_6829. Keep the drift claim
// over there, where a mechanism backs it.
//
// (Round 3 of #6829 named two source-walking tests here. They were replaced in
// round 4 — an AST walk over the SWITCH could not see a short-circuit placed
// before it — so this comment names the behavioural tests that exist now.)
func TestParseFacilityCheckedAcceptsMapped_5797(t *testing.T) {
	for name, want := range parseFacilityMappingTable {
		if got := ParseFacility(name); got != want {
			t.Errorf("parseFacilityMappingTable[%q] = %d but ParseFacility(%q) = %d; the "+
				"reference table has drifted from the function it mirrors", name, want, name, got)
		}
		code, known := ParseFacilityChecked(name)
		if !known {
			t.Errorf("ParseFacilityChecked(%q) reported UNMAPPED, but ParseFacility maps it "+
				"— a correct config would emit a spurious substitution warning", name)
		}
		if code != want {
			t.Errorf("ParseFacilityChecked(%q) code = %d, want %d — the checked form must "+
				"agree with ParseFacility exactly", name, code, want)
		}
	}
}

// TestParseFacilityCheckedKnownSetIsExactlyParseFacility_5797 runs the FULL
// mapping table plus the derived unmapped corpus, and on every name asserts
// BOTH returns — the code (which must equal ParseFacility's, always) and the
// `known` bit. An earlier version sampled eight names and discarded `known`,
// which is how a claim ends up wider than what it checks.
//
// #6829 — what "exactly" can and cannot mean here. Both inputs are finite,
// locally maintained lists, so this test verifies agreement ON THOSE NAMES; it
// does not, by itself, establish that the known-set EQUALS ParseFacility's case
// set, because neither input is derived from ParseFacility. The set equality the
// name promises is established BEHAVIOURALLY, in both directions, by
// TestParseFacilityCheckedAgreesWithParseFacility_6829 (the returned code never
// differs from ParseFacility's, for any name) and
// TestParseFacilityMappingTableIsComplete_6829 (a name in the table reports
// known; a name absent from it reports not-known AND falls through to the
// default). Read this test as the per-name agreement half of that pair.
//
// Together the two directions are what make ParseFacilityChecked a pure
// visibility split rather than a behaviour change: the code never differs, and
// the extra bit is exactly "did this name have a case, or did it fall through
// to the local0 default".
func TestParseFacilityCheckedKnownSetIsExactlyParseFacility_5797(t *testing.T) {
	check := func(name string, wantKnown bool) {
		t.Helper()
		code, known := ParseFacilityChecked(name)
		if want := ParseFacility(name); code != want {
			t.Errorf("ParseFacilityChecked(%q) = %d but ParseFacility(%q) = %d; the checked "+
				"form must not change which facility is used", name, code, name, want)
		}
		if known != wantKnown {
			t.Errorf("ParseFacilityChecked(%q) known = %v, want %v", name, known, wantKnown)
		}
	}

	for name := range parseFacilityMappingTable {
		check(name, true)
	}
	for _, name := range unmappedCorpus() {
		check(name, false)
	}
}
