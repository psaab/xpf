package appid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// precedenceFixture mirrors userspace-dp/tests/fixtures/appid_precedence_v1.json.
// It is the shared, self-describing source of truth for the #3612 cross-language
// application-label precedence parity: this Go test drives the AppID-DISABLED
// fallback (resolveTupleFallback) and the Rust test
// (policy_tests.rs::app_catalog_precedence_parity_fixture) drives the
// AppID-ENABLED catalog (AppCatalog::lookup_directional) over the SAME cases.
// Both MUST resolve every case to the same expected NAME, so the same 5-tuple is
// labeled identically regardless of the services.application-identification knob.
type precedenceFixture struct {
	Version     int                    `json:"version"`
	Description string                 `json:"description"`
	Cases       []precedenceParityCase `json:"cases"`
}

type precedenceParityCase struct {
	Name          string                    `json:"name"`
	Note          string                    `json:"note"`
	Apps          []precedenceParityApp     `json:"apps"`
	Catalog       []precedenceParityCatalog `json:"catalog"`
	Tuple         precedenceParityTuple     `json:"tuple"`
	ExpectedAppID uint16                    `json:"expected_app_id"`
	ExpectedName  string                    `json:"expected_name"`
}

type precedenceParityApp struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	DestinationPort string `json:"destination_port"`
	SourcePort      string `json:"source_port"`
}

type precedenceParityCatalog struct {
	Name        string `json:"name"`
	AppID       uint16 `json:"app_id"`
	Protocol    uint8  `json:"protocol"`
	DstPortLow  uint16 `json:"dst_port_low"`
	DstPortHigh uint16 `json:"dst_port_high"`
	SrcPortLow  uint16 `json:"src_port_low"`
	SrcPortHigh uint16 `json:"src_port_high"`
}

type precedenceParityTuple struct {
	Protocol  uint8  `json:"protocol"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	IsReverse bool   `json:"is_reverse"`
}

// TestAppIDPrecedenceParityFixture is the Go half of the #3612 parity guard.
//
// For every fixture case it (1) validates that appid.BuildCatalog reproduces the
// exact (name -> app_id, ports) rows the fixture records — so the ids the Rust
// side consumes are the REAL Go sort output and a sort bug cannot hide
// identically in both languages — and (2) drives resolveTupleFallback (the
// AppID-disabled label path) over the case tuple and asserts it resolves to the
// fixture's expected_name, the same name the Rust ENABLED-path test asserts.
func TestAppIDPrecedenceParityFixture(t *testing.T) {
	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "appid_precedence_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx precedenceFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("fixture carries no cases")
	}

	for _, tc := range fx.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			// Build the config: the fixture apps are USER apps (scope note S1),
			// all referenced by one global policy so CatalogNames(cfg, false)
			// returns exactly this set and BuildCatalog assigns ids 1..N in
			// sorted-name order.
			apps := map[string]*config.Application{}
			appNames := make([]string, 0, len(tc.Apps))
			for _, a := range tc.Apps {
				apps[a.Name] = &config.Application{
					Name:            a.Name,
					Protocol:        a.Protocol,
					DestinationPort: a.DestinationPort,
					SourcePort:      a.SourcePort,
				}
				appNames = append(appNames, a.Name)
			}
			cfg := &config.Config{
				Applications: config.ApplicationsConfig{Applications: apps},
			}
			// AppID DISABLED so resolveTupleFallback is the active label path
			// and CatalogNames uses the referenced-app (includeAll=false) walk.
			cfg.Services.ApplicationIdentification = false
			cfg.Security.GlobalPolicies = []*config.Policy{
				{Name: "parity-ref", Match: config.PolicyMatch{Applications: appNames}},
			}

			// (1) Validate the fixture's recorded ids/ports == the real Go
			// BuildCatalog output. This pins the ids the Rust side trusts.
			cat, err := BuildCatalog(cfg)
			if err != nil {
				t.Fatalf("BuildCatalog: %v", err)
			}
			byID := map[uint16]CatalogEntry{}
			for _, e := range cat.Entries {
				byID[e.AppID] = e
			}
			if len(cat.Entries) != len(tc.Catalog) {
				t.Fatalf("catalog entry count = %d, fixture records %d", len(cat.Entries), len(tc.Catalog))
			}
			for _, want := range tc.Catalog {
				if got := cat.AppNames[want.AppID]; got != want.Name {
					t.Fatalf("BuildCatalog assigns app_id %d -> %q, fixture claims %q (Go sort drift)", want.AppID, got, want.Name)
				}
				got, ok := byID[want.AppID]
				if !ok {
					t.Fatalf("BuildCatalog produced no entry for app_id %d (%q)", want.AppID, want.Name)
				}
				if got.Name != want.Name || got.Protocol != want.Protocol ||
					got.DstPortLow != want.DstPortLow || got.DstPortHigh != want.DstPortHigh ||
					got.SrcPortLow != want.SrcPortLow || got.SrcPortHigh != want.SrcPortHigh {
					t.Fatalf("catalog entry mismatch for %q: BuildCatalog %+v, fixture %+v", want.Name, got, want)
				}
			}

			// (2) The AppID-disabled label path must resolve the case tuple to
			// the fixture's expected name — the same name the Rust ENABLED-path
			// test resolves via lookup_directional. Only forward tuples are in
			// the fixture (resolveTupleFallback has no reverse model — S2).
			if tc.Tuple.IsReverse {
				t.Fatalf("fixture case %q is is_reverse=true; resolveTupleFallback only models forward flows", tc.Name)
			}
			got := resolveTupleFallback(tc.Tuple.Protocol, tc.Tuple.SrcPort, tc.Tuple.DstPort, cfg, cat.AppNames)
			if got != tc.ExpectedName {
				t.Fatalf("resolveTupleFallback(proto=%d src=%d dst=%d) = %q, want %q (must match the AppID-enabled Rust label)",
					tc.Tuple.Protocol, tc.Tuple.SrcPort, tc.Tuple.DstPort, got, tc.ExpectedName)
			}
		})
	}
}
