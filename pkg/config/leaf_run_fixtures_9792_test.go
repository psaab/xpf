package config

import (
	"strings"
	"testing"
)

// leafRunFixture9156 supplies what the #9156 gate's generated placeholders
// cannot, for a row that would otherwise land in a skip bucket (#9792 part 1).
//
// #9235 showed that skipped rows are the riskier half: a row leaves the census
// exactly where a validator rejects the placeholder, so the census went blind
// at the containers someone had gated. Each entry below is the smallest
// fixture the compiler accepts, and its comment is the rejection that put the
// row in a bucket.
//
// The zero value changes nothing, so every row without an entry compiles the
// same text it always did.
type leafRunFixture9156 struct {
	container []string // typed instance names in place of the xpfarg placeholders
	headVal   string   // a value the head leaf's validators accept
	tailVal   string   // a value the tail leaf's validators accept
	ctx       string   // extra context inside the container
	preamble  string   // top-level scaffolding before the container text
	// wrap renders the whole config around the container body, for a
	// requirement that must sit in the SAME block as the site rather than in a
	// re-opened one.
	wrap func(inner string) string
	// runRefused records why the ONE-LINE form does not compile once the oracle
	// does. A refusal is loud, which is the opposite of the silent loss the
	// gate looks for, so the row is accounted for rather than compared.
	runRefused string
}

// render builds the text for inner (the container's body) under this fixture.
func (fx leafRunFixture9156) render(container []string, inner string) string {
	if fx.wrap != nil {
		return fx.wrap(inner)
	}
	return fx.preamble + nest(container, inner)
}

// ipMonitoringWrap9792 puts the probe, the policy's match and the preferred
// route in ONE services block. A policy split across a preamble and the site's
// own block compiled as a policy with no match (`match rpm-probe is required`).
func ipMonitoringWrap9792(preferredRoute string) string {
	return "services { rpm { probe r1 { test t1 { target address 192.0.2.1; } } } " +
		"ip-monitoring { policy xpfarg { match { rpm-probe r1; } then { preferred-route { " +
		preferredRoute + " } } } } }"
}

var leafRunFixtures9156 = map[string]leafRunFixture9156{
	// ORACLE did not compile: `expected queue 0..255`. The queue instance name
	// is a number.
	"class-of-service fairness rss-expectation interface xpfarg queue xpfarg [active-workers -> at-least-active-workers]": {
		container: strings.Fields("class-of-service fairness rss-expectation interface ge-0/0/1 queue 0"),
	},
	// ORACLE did not compile: `requires positive committed-information-rate`.
	// The rates take bandwidth values, and the context completes each rate set
	// WITHOUT the two leaves under test, so the comparison stays about them.
	"firewall three-color-policer xpfarg single-rate [committed-burst-size -> committed-information-rate]": {
		headVal: "1k", tailVal: "1m", ctx: "excess-burst-size 1k; ",
		runRefused: "the one-line run drops committed-information-rate and the policer is refused: `requires positive committed-information-rate`",
	},
	"firewall three-color-policer xpfarg two-rate [committed-burst-size -> committed-information-rate]": {
		headVal: "1k", tailVal: "1m", ctx: "peak-information-rate 2m; peak-burst-size 2k; ",
		runRefused: "the one-line run drops committed-information-rate and the policer is refused: `requires positive committed-information-rate`",
	},
	// ORACLE did not compile: `references undefined scheduler "xpfaaa"`.
	// scheduler-name names a top-level scheduler; #8690's preambleFor defines it.
	"security policies from-zone xpfarg xpfarg xpfarg policy xpfarg [description -> scheduler-name]": {
		preamble: preambleFor(strings.Fields("security policies from-zone xpfarg xpfarg xpfarg"), "policy xpfarg"),
	},
	"security policies global policy xpfarg [description -> scheduler-name]": {
		preamble: preambleFor(strings.Fields("security policies global"), "policy xpfarg"),
	},
	// ORACLE did not compile: `match rpm-probe is required`. The route key is a
	// prefix and the next-hop an address.
	"services ip-monitoring policy xpfarg then preferred-route route xpfarg [next-hop -> preferred-metric]": {
		container: strings.Fields("services ip-monitoring policy xpfarg then preferred-route route 10.9.8.0/24"),
		headVal:   "192.0.2.253",
		wrap: func(inner string) string {
			return ipMonitoringWrap9792("route 10.9.8.0/24 { " + inner + " }")
		},
	},
	"services ip-monitoring policy xpfarg then preferred-route routing-instance xpfarg route xpfarg [next-hop -> preferred-metric]": {
		container: strings.Fields("services ip-monitoring policy xpfarg then preferred-route routing-instance xpfarg route 10.9.8.0/24"),
		headVal:   "192.0.2.253",
		// The routing instance the preferred route names must exist.
		wrap: func(inner string) string {
			return "routing-instances { xpfarg { instance-type virtual-router; } } " +
				ipMonitoringWrap9792("routing-instance xpfarg { route 10.9.8.0/24 { "+inner+" } }")
		},
	},
	// ORACLE did not compile: `target is required`, and destination-interface
	// takes an interface name.
	"services rpm probe xpfarg test xpfarg [destination-interface -> destination-port]": {
		headVal: "ge-0/0/1.0", ctx: "target address 192.0.2.1; ",
	},
	// ORACLE did not compile: `unknown dataplane-type "xpfaaa"`.
	"system [dataplane-type -> domain-name]": {headVal: "userspace"},
	// No synthesizable value: allow-commands-regexps takes a regex, which the
	// generator has no placeholder for.
	"system login class xpfarg [allow-commands -> allow-commands-regexps]": {tailVal: `"^show "`},
}

// checkLeafRunFixtureOutcomes9792 fails a fixture that no longer does its job:
// its row fell back into a skip bucket, or its recorded run refusal went stale
// in either direction.
func checkLeafRunFixtureOutcomes9792(t *testing.T, skipNoVal, skipRunNC, skipSepNC []string) {
	t.Helper()
	in := func(rows []string, key string) bool {
		for _, r := range rows {
			if r == key || strings.TrimSuffix(strings.TrimSuffix(r, " (head)"), " (tail)") == key {
				return true
			}
		}
		return false
	}
	for key, fx := range leafRunFixtures9156 {
		switch {
		case in(skipNoVal, key):
			t.Errorf("#9792: fixture row %q is back in \"no synthesizable value\"", key)
		case in(skipSepNC, key):
			t.Errorf("#9792: fixture row %q is back in \"ORACLE did not compile\"; its fixture no longer satisfies the validators", key)
		case in(skipRunNC, key) && fx.runRefused == "":
			t.Errorf("#9792: fixture row %q now fails to compile its one-line form; record why in runRefused or fix the reader", key)
		case !in(skipRunNC, key) && fx.runRefused != "":
			t.Errorf("#9792: fixture row %q records a run refusal (%s) but its one-line form now compiles; drop runRefused so the row is compared", key, fx.runRefused)
		}
	}
}

// TestLeafRunFixturesNameEnumeratedSites9792: a fixture keyed to a site the
// walk no longer enumerates applies to nothing.
func TestLeafRunFixturesNameEnumeratedSites9792(t *testing.T) {
	sites := map[string]bool{}
	for _, s := range collectLeafRunSites9156() {
		sites[s.key()] = true
	}
	for key := range leafRunFixtures9156 {
		if !sites[key] {
			t.Errorf("fixture %q names no enumerated leaf-run site", key)
		}
	}
}
