package appid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRegeneratePrecedenceFixture PROGRAMMATICALLY regenerates
// userspace-dp/tests/fixtures/appid_precedence_v1.json from the real
// appid.BuildCatalog (catalog rows + app_id assignment) and
// resolveTupleFallback (the AppID-DISABLED label winner) — NO hand-tuned ids or
// expected names. It only runs when BPFRX_REGEN_APPID_FIXTURE=1 so a normal test
// run never rewrites the fixture; the committed JSON is then validated by the
// binding TestAppIDPrecedenceParityFixture (Go) and its Rust counterpart.
//
// Regenerate with:
//
//	BPFRX_REGEN_APPID_FIXTURE=1 go test ./pkg/appid/ -run TestRegeneratePrecedenceFixture
func TestRegeneratePrecedenceFixture(t *testing.T) {
	if os.Getenv("BPFRX_REGEN_APPID_FIXTURE") != "1" {
		t.Skip("set BPFRX_REGEN_APPID_FIXTURE=1 to regenerate the precedence fixture")
	}

	type genCase struct {
		name  string
		note  string
		apps  []precedenceParityApp
		tuple precedenceParityTuple
	}
	cases := []genCase{
		{
			name: "protocol_only_loses_to_exact_port",
			note: "The canonical #3612 divergence: a broad protocol-only app (aaa-tcp) must NOT shadow a specific dst-port app (zzz-https) on tcp/443 — a CROSS-tier decision (port-constrained beats protocol-only) independent of the id VALUES. RED-on-revert of #3612.",
			apps: []precedenceParityApp{
				{Name: "aaa-tcp", Protocol: "tcp"},
				{Name: "zzz-https", Protocol: "tcp", DestinationPort: "443"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 51000, DstPort: 443},
		},
		{
			name: "protocol_only_loses_to_range",
			note: "A port-RANGE app (mmm-range) beats a protocol-only app (aaa-any) on a port inside the range — CROSS-tier, independent of id VALUES. RED-on-revert of #3612.",
			apps: []precedenceParityApp{
				{Name: "aaa-any", Protocol: "tcp"},
				{Name: "mmm-range", Protocol: "tcp", DestinationPort: "9000-9100"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 9050},
		},
		{
			name: "same_tier_lowest_stable_id_wins",
			note: "Both matches are port-constrained (a range aaa-range in the scan list AND an exact-port zzz-exact in the O(1) map). Within a tier the LOWEST app_id wins in BOTH paths. #5296: app_id is a stable name-hash, so 'lowest id' means lowest StableAppID, not alphabetically-first. Here StableAppID(aaa-range) < StableAppID(zzz-exact) so aaa-range still wins; the point is both paths key the tiebreak on the SAME stable id.",
			apps: []precedenceParityApp{
				{Name: "aaa-range", Protocol: "tcp", DestinationPort: "8000-8100"},
				{Name: "zzz-exact", Protocol: "tcp", DestinationPort: "8050"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 8050},
		},
		{
			name: "exact_port_tie_breaks_by_stable_id_not_alphabetical",
			note: "#5296 BINDING case: two apps with the IDENTICAL exact dst-port (tcp/8080) collide in the Rust exact_dst O(1) map, whose first-writer-wins dedup keeps the LOWEST app_id only because BuildCatalog now emits entries in ascending-id order. aaa-svc sorts BEFORE ccc-svc but StableAppID(aaa-svc)=45553 > StableAppID(ccc-svc)=38751, so the stable-id tiebreak resolves to ccc-svc on BOTH the AppID-enabled (Rust) and disabled (Go) paths. RED-on-revert: an alphabetical tiebreak on EITHER side (or reverting the ascending-id emit order) flips the winner to aaa-svc, so this case FAILS the parity fixture — it binds the on/off agreement.",
			apps: []precedenceParityApp{
				{Name: "aaa-svc", Protocol: "tcp", DestinationPort: "8080"},
				{Name: "ccc-svc", Protocol: "tcp", DestinationPort: "8080"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 8080},
		},
		{
			name: "collision_displacement_uses_assigned_id",
			note: "The #10722 binding case: svc-217 and svc-396 share natural StableAppID 49397; AssignStableAppIDs keeps svc-217 at 49397 and displaces svc-396 to 1. mmm-middle has id 22100. Rust resolves the exact-port overlap by lowest assigned app_id (svc-396), while the old Go natural-hash fallback chose mmm-middle. This pins the actual assigned-ID parity path.",
			apps: []precedenceParityApp{
				{Name: "mmm-middle", Protocol: "tcp", DestinationPort: "8080"},
				{Name: "svc-217", Protocol: "tcp", DestinationPort: "8080"},
				{Name: "svc-396", Protocol: "tcp", DestinationPort: "8080"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 8080},
		},
		{
			name: "src_port_only_is_port_constrained",
			note: "A source-port-only app (zzz-srcport, dst unconstrained) is port-constrained on both sides and beats a protocol-only sibling (aaa-proto) for a flow whose client source port matches — CROSS-tier, independent of id VALUES. RED-on-revert of #3612.",
			apps: []precedenceParityApp{
				{Name: "aaa-proto", Protocol: "tcp"},
				{Name: "zzz-srcport", Protocol: "tcp", SourcePort: "5000"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 5000, DstPort: 80},
		},
		{
			name: "single_exact_match",
			note: "No overlap sanity: only aaa-http matches tcp/80.",
			apps: []precedenceParityApp{
				{Name: "aaa-http", Protocol: "tcp", DestinationPort: "80"},
				{Name: "bbb-ssh", Protocol: "tcp", DestinationPort: "22"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 80},
		},
		{
			name: "no_match_resolves_unknown",
			note: "No user app matches tcp/4321 (4321 is deliberately absent from the Go builtinFallbacks table — the S1 predefined-vs-builtin set gap is out of scope), so both paths resolve UNKNOWN (id 0 / empty name).",
			apps: []precedenceParityApp{
				{Name: "aaa-http", Protocol: "tcp", DestinationPort: "80"},
			},
			tuple: precedenceParityTuple{Protocol: 6, SrcPort: 40000, DstPort: 4321},
		},
	}

	fx := precedenceFixture{
		Version:     1,
		Description: "Cross-language AppID application-label precedence parity fixture (#3612). Each case is resolved by BOTH the AppID-ENABLED Rust catalog (AppCatalog::lookup_directional in userspace-dp/src/policy.rs) and the AppID-DISABLED Go fallback (resolveTupleFallback in pkg/appid/runtime.go); both MUST agree on the resolved application NAME so the same 5-tuple is labeled identically regardless of the services.application-identification knob. `apps` is the operator config (user apps only, #3612 scope S1); `catalog` is the (app_id, protocol, port-range) rows appid.BuildCatalog assigns; `tuple` is a FORWARD-keyed session. #5296: app_id is assigned from a STABLE name-hash (config.StableAppID), NOT the sorted position; rare hash collisions are deterministically displaced by config.AssignStableAppIDs, and same-tier overlaps resolve by LOWEST assigned app_id on both paths. BuildCatalog emits entries in ascending-id order so the Rust exact_dst first-writer dedup also keeps the lowest id. GENERATED programmatically from BuildCatalog + resolveTupleFallback by pkg/appid TestRegeneratePrecedenceFixture (BPFRX_REGEN_APPID_FIXTURE=1); do not hand-edit ids/expected. expected_app_id 0 / expected_name \"\" means UNKNOWN.",
	}

	for _, gc := range cases {
		apps := map[string]*config.Application{}
		names := make([]string, 0, len(gc.apps))
		for _, a := range gc.apps {
			apps[a.Name] = &config.Application{
				Name:            a.Name,
				Protocol:        a.Protocol,
				DestinationPort: a.DestinationPort,
				SourcePort:      a.SourcePort,
			}
			names = append(names, a.Name)
		}
		cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: apps}}
		cfg.Services.ApplicationIdentification = false
		cfg.Security.GlobalPolicies = []*config.Policy{
			{Name: "ref", Match: config.PolicyMatch{Applications: names}},
		}

		cat, err := BuildCatalog(cfg)
		if err != nil {
			t.Fatalf("case %s: BuildCatalog: %v", gc.name, err)
		}
		catRows := make([]precedenceParityCatalog, 0, len(cat.Entries))
		for _, e := range cat.Entries {
			catRows = append(catRows, precedenceParityCatalog{
				Name:        e.Name,
				AppID:       e.AppID,
				Protocol:    e.Protocol,
				DstPortLow:  e.DstPortLow,
				DstPortHigh: e.DstPortHigh,
				SrcPortLow:  e.SrcPortLow,
				SrcPortHigh: e.SrcPortHigh,
			})
		}
		wantName := resolveTupleFallback(gc.tuple.Protocol, gc.tuple.SrcPort, gc.tuple.DstPort, cfg, cat.AppNames)
		var wantID uint16
		if wantName != "" {
			for _, e := range cat.Entries {
				if e.Name == wantName {
					wantID = e.AppID
					break
				}
			}
		}
		fx.Cases = append(fx.Cases, precedenceParityCase{
			Name:          gc.name,
			Note:          gc.note,
			Apps:          gc.apps,
			Catalog:       catRows,
			Tuple:         gc.tuple,
			ExpectedAppID: wantID,
			ExpectedName:  wantName,
		})
	}

	path := filepath.Join("..", "..", "userspace-dp", "tests", "fixtures", "appid_precedence_v1.json")
	raw, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("regenerated %s with %d cases", path, len(fx.Cases))
}
