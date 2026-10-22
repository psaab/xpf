package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// policyRefConfig builds a config whose single policy references every named
// application, so CatalogNames(cfg, false) returns exactly those user apps (the
// AppID-disabled path keeps the catalog at the referenced set rather than
// fanning in the predefined table). This keeps the tolerant-load catalog tests
// small and deterministic.
func policyRefConfig(apps map[string]*config.Application) *config.Config {
	match := make([]string, 0, len(apps))
	for name := range apps {
		match = append(match, name)
	}
	return &config.Config{
		Applications: config.ApplicationsConfig{Applications: apps},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{Policies: []*config.Policy{{Match: config.PolicyMatch{Applications: match}}}},
			},
		},
	}
}

func entriesForName(cat Catalog, name string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range cat.Entries {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func appIDForName(cat Catalog, name string) (config.AssignedAppID, bool) {
	for id, n := range cat.AppNames {
		if n == name {
			return id, true
		}
	}
	return 0, false
}

// TestBuildCatalogBadSourcePortNotOverBroad is the #3725 H03/M06 fail-on-revert
// guard. A leniently-loaded application "protocol tcp destination-port 80
// source-port 70000" (a bad source-port strict commit rejects) must NOT ship a
// catalog row with SrcPortLow=0/SrcPortHigh=0 — the Rust AppCatalog treats a
// zero source-port pair as UNCONSTRAINED, so that row would stamp ANY TCP/80
// flow as the app (fail-OPEN over-broad labeling). The fix drops the row (fails
// closed). Reverting to `srcLow, srcHigh, _ = parsePortRange(...)` re-emits the
// unconstrained row and turns this RED.
func TestBuildCatalogBadSourcePortNotOverBroad(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"over-broad": {Name: "over-broad", Protocol: "tcp", DestinationPort: "80", SourcePort: "70000"},
		// A well-formed neighbor must still ship — proves the fix does not
		// over-drop and the tolerant path does not brick.
		"good-src": {Name: "good-src", Protocol: "tcp", DestinationPort: "80", SourcePort: "12345"},
	})

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	if got := entriesForName(cat, "over-broad"); len(got) != 0 {
		t.Fatalf("bad source-port app shipped %d catalog row(s) %+v; a malformed source-port must be dropped, not emitted unconstrained (H03/M06)", len(got), got)
	}
	if _, ok := appIDForName(cat, "over-broad"); ok {
		t.Fatal("bad source-port app must not appear in AppNames (no stampable id -> no name)")
	}

	// The well-formed app still ships with its real source-port bounds.
	good := entriesForName(cat, "good-src")
	if len(good) != 1 {
		t.Fatalf("good-src shipped %d rows, want 1", len(good))
	}
	if good[0].SrcPortLow != 12345 || good[0].SrcPortHigh != 12345 || good[0].DstPortLow != 80 {
		t.Fatalf("good-src entry = %+v, want src 12345 dst 80", good[0])
	}
}

// TestBuildCatalogReversedRangeDropped is the #3725 M07 fail-on-revert guard. A
// leniently-loaded "destination-port 200-100" (reversed) must NOT ship a row
// with inverted bounds (dst_low=200,dst_high=100). It also covers a reversed
// SOURCE range. The Rust matcher tests p>=low && p<=high so an inverted row
// never stamps (fail closed), but shipping garbage bounds diverges from strict
// commit (validatePortSpec rejects start>end) and the NAT parser (#3726). The
// fix drops the row explicitly. Reverting parsePortRange's low<=high gate at the
// emission site re-ships inverted bounds and turns this RED.
func TestBuildCatalogReversedRangeDropped(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"rev-dst":  {Name: "rev-dst", Protocol: "tcp", DestinationPort: "200-100"},
		"rev-src":  {Name: "rev-src", Protocol: "udp", DestinationPort: "5000", SourcePort: "2048-1024"},
		"good-rng": {Name: "good-rng", Protocol: "tcp", DestinationPort: "100-200"},
	})

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	for _, e := range entriesForName(cat, "rev-dst") {
		t.Fatalf("reversed dst-range app shipped a row %+v; inverted bounds must be dropped (M07)", e)
	}
	for _, e := range entriesForName(cat, "rev-src") {
		t.Fatalf("reversed src-range app shipped a row %+v; inverted bounds must be dropped (M07)", e)
	}

	// A well-formed range still ships with the correct inclusive bounds.
	good := entriesForName(cat, "good-rng")
	if len(good) != 1 {
		t.Fatalf("good-rng shipped %d rows, want 1", len(good))
	}
	if good[0].DstPortLow != 100 || good[0].DstPortHigh != 200 {
		t.Fatalf("good-rng entry = %+v, want dst 100-200", good[0])
	}
}

// TestBuildCatalogNoDanglingAppName is the #3725 M04 fail-on-revert guard for
// the catalog-side AppNames. A malformed application that sorts LAST (no later
// good app overwrites its id) must NOT leave AppNames holding a name at an id
// that stamps no CatalogEntry — otherwise a skewed/stale app_id resolves to the
// malformed name instead of UNKNOWN. "zzz-bad" (unparseable dest-port) sorts
// after "aaa-good". Reverting the "record AppNames only when emittable" fix
// (recording the name before the port parse) re-adds the dangling entry and
// turns this RED.
func TestBuildCatalogNoDanglingAppName(t *testing.T) {
	cfg := policyRefConfig(map[string]*config.Application{
		"aaa-good": {Name: "aaa-good", Protocol: "tcp", DestinationPort: "8443"},
		"zzz-bad":  {Name: "zzz-bad", Protocol: "tcp", DestinationPort: "not-a-port"},
	})

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	if _, ok := appIDForName(cat, "zzz-bad"); ok {
		t.Fatalf("malformed last app zzz-bad left a dangling AppNames entry %v; an unemittable app must not hold an id (M04)", cat.AppNames)
	}
	// Every AppNames id must have at least one CatalogEntry that can stamp it.
	stamped := map[config.AssignedAppID]bool{}
	for _, e := range cat.Entries {
		stamped[e.AppID] = true
	}
	for id, name := range cat.AppNames {
		if !stamped[id] {
			t.Fatalf("AppNames[%d]=%q has no CatalogEntry to stamp it (dangling id -> mislabel on skew) (M04)", id, name)
		}
	}
	// The good app is still present and resolvable.
	if _, ok := appIDForName(cat, "aaa-good"); !ok {
		t.Fatal("good app aaa-good missing from AppNames")
	}
}
