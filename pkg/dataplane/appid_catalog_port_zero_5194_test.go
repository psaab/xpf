package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// TestAppCatalogParityOnPortZero_5194 is the #5194 A3-b1-F2 lock-step guard: a
// bare destination-port `0` (the (0,0) wildcard sentinel) must be unemittable
// in BOTH appid.BuildCatalog (the LIVE catalog shipped to Rust) AND
// compileApplications (result.AppNames, the show-path resolver) so the two
// AppNames maps stay byte-identical. Reverting the port-0 gate in EITHER mirror
// makes the maps diverge (one records the port-0 name, the other does not),
// turning this RED.
func TestAppCatalogParityOnPortZero_5194(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*config.Application{
		"aaa-good":    {Name: "aaa-good", Protocol: "tcp", DestinationPort: "8443"},
		"mmm-dstzero": {Name: "mmm-dstzero", Protocol: "tcp", DestinationPort: "0"},
		"nnn-srczero": {Name: "nnn-srczero", Protocol: "udp", DestinationPort: "53", SourcePort: "0-0"},
	}

	result := &CompileResult{AppIDs: make(map[string]config.AssignedAppID)}
	if err := compileApplications(appCatalogParityDP{}, cfg, result); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	if len(cat.AppNames) != len(result.AppNames) {
		t.Fatalf("AppNames size mismatch with a port-0 app: catalog=%d compiler=%d",
			len(cat.AppNames), len(result.AppNames))
	}
	for id, name := range result.AppNames {
		if got := cat.AppNames[id]; got != name {
			t.Fatalf("app_id %d: compiler=%q catalog=%q (port-0 id drift breaks show resolution)", id, name, got)
		}
	}

	// Neither map may carry the port-0 sentinel apps.
	for _, name := range cat.AppNames {
		if name == "mmm-dstzero" || name == "nnn-srczero" {
			t.Fatalf("port-0 sentinel app %q must not hold a resolvable app_id", name)
		}
	}
	// The good app is present in both.
	if _, ok := appNameID(result.AppNames, "aaa-good"); !ok {
		t.Fatal("aaa-good missing from live AppNames")
	}
}
