package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildCatalogPortZeroSentinel_5194 is the #5194 A3-b1-F2 fail-on-revert
// guard. A bare destination-port `0` (or `0-0`) parses to the (0,0) pair the
// Rust matcher reserves for "no port constraint" — only an EMPTY spec
// legitimately encodes unconstrained. Before the fix a tolerantly-loaded
// `destination-port 0` app shipped a (0,0) catalog row that OVER-MATCHED every
// port of its protocol; a `0-1024` range shipped low=0 (never on the wire).
//
// Fail-on-revert: make NormalizeExplicitPortRange return (low,high,true)
// unconditionally (or drop the dstOK/srcOK gate) and the port-0 legs go RED —
// the port-0 app re-emits a (0,0) row and reappears in AppNames.
func TestBuildCatalogPortZeroSentinel_5194(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"good-app":   {Name: "good-app", Protocol: "tcp", DestinationPort: "80"},
		"dstzero":    {Name: "dstzero", Protocol: "tcp", DestinationPort: "0"},
		"dstzerorng": {Name: "dstzerorng", Protocol: "tcp", DestinationPort: "0-0"},
		"lowzerorng": {Name: "lowzerorng", Protocol: "tcp", DestinationPort: "0-1024"},
		"srczero":    {Name: "srczero", Protocol: "tcp", DestinationPort: "443", SourcePort: "0"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust",
		Policies: []*config.Policy{{
			Name: "p", Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"good-app", "dstzero", "dstzerorng", "lowzerorng", "srczero"},
			},
		}},
	}}

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	entriesByName := map[string][]CatalogEntry{}
	for _, e := range cat.Entries {
		entriesByName[e.Name] = append(entriesByName[e.Name], e)
	}
	namesInAppNames := map[string]bool{}
	for _, name := range cat.AppNames {
		namesInAppNames[name] = true
	}

	// good-app is unaffected: an exact 80 entry ships.
	good := entriesByName["good-app"]
	if len(good) != 1 || good[0].DstPortLow != 80 || good[0].DstPortHigh != 80 {
		t.Fatalf("good-app entry = %+v, want a single tcp 80 entry", good)
	}
	if !namesInAppNames["good-app"] {
		t.Fatal("good-app must appear in AppNames")
	}

	// A bare 0 / 0-0 destination port is UNEMITTABLE: no catalog row (so the
	// helper never stamps it) and no resolvable AppNames name.
	for _, name := range []string{"dstzero", "dstzerorng"} {
		if got := entriesByName[name]; len(got) != 0 {
			t.Fatalf("%s must emit NO catalog entry (bare port-0 is the (0,0) wildcard sentinel), got %+v", name, got)
		}
		if namesInAppNames[name] {
			t.Fatalf("%s must not hold a resolvable app_id (over-match sentinel)", name)
		}
	}

	// A 0-N range stays emittable with its literal low bound. The Rust
	// catalog matcher treats the nonzero high bound as the discriminator
	// from the (0,0) unconstrained sentinel.
	lz := entriesByName["lowzerorng"]
	if len(lz) != 1 || lz[0].DstPortLow != 0 || lz[0].DstPortHigh != 1024 {
		t.Fatalf("lowzerorng entry = %+v, want a single tcp 0-1024 entry", lz)
	}

	// A bare source-port 0 is likewise the unconstrained-SOURCE sentinel; the app
	// must be unemittable rather than over-match every source port.
	if got := entriesByName["srczero"]; len(got) != 0 {
		t.Fatalf("srczero must emit NO catalog entry (source-port 0 is the (0,0) source wildcard), got %+v", got)
	}
	if namesInAppNames["srczero"] {
		t.Fatal("srczero must not hold a resolvable app_id")
	}
}
