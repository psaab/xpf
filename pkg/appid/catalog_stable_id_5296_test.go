package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5296: app_id is a STABLE, name-derived id, so a RETAINED session's frozen
// app_id keeps resolving to the application it was stamped under even after an
// ordinary catalog edit inserts an earlier-sorting application. These tests pin
// that end-to-end through BuildCatalog + ResolveSessionName, and pin the
// resolveTupleFallback tie-break re-key that keeps the AppID-on/off label paths
// in agreement (#3612) under the new ids.

func mkAppIDCfg(names []string, ports map[string]string) *config.Config {
	apps := map[string]*config.Application{}
	for _, n := range names {
		apps[n] = &config.Application{Name: n, Protocol: "tcp", DestinationPort: ports[n]}
	}
	cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: apps}}
	// AppID disabled keeps CatalogNames on the policy-referenced set (exactly
	// these apps) rather than pulling in all 89 predefined names, so the ids
	// under test are just these user apps. ResolveSessionName still resolves a
	// nonzero stamped app_id through the AppNames map regardless of the knob.
	cfg.Services.ApplicationIdentification = false
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "ref", Match: config.PolicyMatch{Applications: names}},
	}
	return cfg
}

func idOfName(cat Catalog, name string) uint16 {
	for id, n := range cat.AppNames {
		if n == name {
			return id
		}
	}
	return 0
}

// TestStableIDResolvesRetainedSessionAfterCatalogEdit is the core #5296
// end-to-end fail-on-revert: a session is stamped app_id=k under config C1; C2
// inserts an application that sorts BEFORE the stamped app; the retained
// session's frozen k MUST still resolve to the original name under C2.
//
// RED-on-revert: restore the sorted 1..N positional assignment and C2 shifts the
// stamped app to k+1, so the frozen k resolves to the newly-inserted app's name
// (the exact #5296 mis-label).
func TestStableIDResolvesRetainedSessionAfterCatalogEdit(t *testing.T) {
	ports := map[string]string{
		"svc-alpha":   "7070",
		"svc-bravo":   "8080",
		"svc-charlie": "9090",
		"aaa-early":   "70",
	}
	c1 := mkAppIDCfg([]string{"svc-alpha", "svc-bravo", "svc-charlie"}, ports)
	cat1, err := BuildCatalog(c1)
	if err != nil {
		t.Fatal(err)
	}
	frozen := idOfName(cat1, "svc-bravo") // stamped on a live session under C1
	if frozen == 0 {
		t.Fatal("svc-bravo was not assigned an app_id under C1")
	}
	if frozen != config.StableAppID("svc-bravo") {
		t.Fatalf("svc-bravo id = %d, want its StableAppID %d", frozen, config.StableAppID("svc-bravo"))
	}

	// C2 adds aaa-early, which sorts before every svc-* name.
	c2 := mkAppIDCfg([]string{"aaa-early", "svc-alpha", "svc-bravo", "svc-charlie"}, ports)
	cat2, err := BuildCatalog(c2)
	if err != nil {
		t.Fatal(err)
	}

	// The retained session (frozen app_id from C1, tcp/8080) must still resolve
	// to svc-bravo under C2's catalog.
	got := ResolveSessionName(cat2.AppNames, c2, 6, 0, 8080, frozen)
	if got != "svc-bravo" {
		t.Fatalf("retained session frozen app_id %d resolves to %q under C2, want svc-bravo (the #5296 mis-label — ids must be stable across the edit)", frozen, got)
	}

	// And the stamped id itself is unchanged across the edit (nothing renumbered).
	if idOfName(cat2, "svc-bravo") != frozen {
		t.Fatalf("svc-bravo id changed across the catalog edit: C1=%d C2=%d", frozen, idOfName(cat2, "svc-bravo"))
	}
}

// TestResolveTupleFallbackTieBreakByAssignedID pins the #10722 assigned-id
// tiebreak: a same-tier overlap resolves by the lowest id actually assigned
// by config.AssignStableAppIDs, including collision displacement, so it agrees
// with the AppID-enabled Rust catalog's lookup_directional result.
//
// aaa-svc sorts before ccc-svc but has a higher assigned ID, so the catalog id
// map makes ccc-svc the winner.
func TestResolveTupleFallbackTieBreakByAssignedID(t *testing.T) {
	if !(config.StableAppID("aaa-svc") > config.StableAppID("ccc-svc")) {
		t.Skipf("fixture stale: StableAppID no longer orders aaa-svc after ccc-svc")
	}
	// Both apps match tcp/8080 in the same (port-constrained) specificity tier.
	cfg := mkAppIDCfg([]string{"aaa-svc", "ccc-svc"}, map[string]string{
		"aaa-svc": "8080",
		"ccc-svc": "8080",
	})
	// AppID-disabled fallback path (resolveTupleFallback is the label source).
	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatal(err)
	}
	name := resolveTupleFallback(6, 0, 8080, cfg, cat.AppNames)
	if name != "ccc-svc" {
		t.Fatalf("same-tier tie-break resolved to %q, want ccc-svc (lowest assigned app_id)", name)
	}
}

// TestResolveTupleFallbackUsesDisplacedAssignedID_10722 is the fail-on-revert
// guard for collision-aware fallback ordering. svc-217 and svc-396 have the
// same natural StableAppID; config.AssignStableAppIDs keeps svc-217 at that id
// and displaces svc-396 to id 1. mmm-middle's natural and assigned id is 22100,
// so the old natural-hash comparator deterministically picks mmm-middle while
// the Rust catalog's lowest-assigned-id lookup picks svc-396.
func TestResolveTupleFallbackUsesDisplacedAssignedID_10722(t *testing.T) {
	const displaced = "svc-396"
	const naturalOwner = "svc-217"
	const middle = "mmm-middle"
	naturalID := config.StableAppID(displaced)
	if naturalID != config.StableAppID(naturalOwner) {
		t.Fatalf("collision fixture stale: StableAppID(%s)=%d, StableAppID(%s)=%d",
			displaced, naturalID, naturalOwner, config.StableAppID(naturalOwner))
	}
	if config.StableAppID(middle) >= naturalID {
		t.Fatalf("collision fixture stale: StableAppID(%s)=%d must be below colliding id %d",
			middle, config.StableAppID(middle), naturalID)
	}
	cfg := mkAppIDCfg([]string{displaced, naturalOwner, middle}, map[string]string{
		displaced:   "8080",
		naturalOwner: "8080",
		middle:       "8080",
	})
	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	displacedID := idOfName(cat, displaced)
	middleID := idOfName(cat, middle)
	if displacedID != 1 || middleID >= naturalID {
		t.Fatalf("unexpected assigned IDs: displaced %s=%d, middle %s=%d, colliding natural id=%d",
			displaced, displacedID, middle, middleID, naturalID)
	}
	if got := ResolveSessionName(cat.AppNames, cfg, 6, 40000, 8080, 0); got != displaced {
		t.Fatalf("same-tier fallback resolved to %q, want %q (lowest assigned app_id %d; natural-hash order picks %q)",
			got, displaced, displacedID, middle)
	}
}
