package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func quarantineIDs10530(t *testing.T) map[string]uint32 {
	t.Helper()
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	return map[string]uint32{
		"trust":    config.StableZoneID("trust"),
		"zzq17760": config.StableZoneID("zzq17760"),
		"zzq8100":  config.StableZoneID("zzq8100"),
	}
}

func quarantinedZonesConfig10530(t *testing.T) (*Server, map[string]uint32) {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":    {Name: "trust", Interfaces: []string{"if-trust"}},
		"zzq17760": {Name: "zzq17760", Interfaces: []string{"if-survivor"}},
		"zzq8100":  {Name: "zzq8100", Interfaces: []string{"if-quarantined"}},
	}
	ids := quarantineIDs10530(t)
	return &Server{store: store}, ids
}

// TestZonesHandlerQuarantinedCountersUnavailable10530 is the existing-field
// half of #10530: REST keeps the desired row's ID/interfaces but must not
// attribute the survivor's live volume to the quarantined name.
func TestZonesHandlerQuarantinedCountersUnavailable10530(t *testing.T) {
	s, ids := quarantinedZonesConfig10530(t)
	mgr := dataplane.New()
	mgr.SetZoneCounterOffset(ids["zzq17760"],
		dataplane.CounterValue{Packets: 17, Bytes: 1700},
		dataplane.CounterValue{Packets: 23, Bytes: 2300})
	mgr.SetZoneCounterOffset(ids["trust"],
		dataplane.CounterValue{Packets: 31, Bytes: 3100},
		dataplane.CounterValue{Packets: 41, Bytes: 4100})
	s.dp = &zoneRealReadDP{&descriptorCoverageDP{
		Manager: mgr,
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}

	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Data    []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode zones response: %v; body=%s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("zones response success=false: %s", rr.Body.String())
	}
	byName := make(map[string]ZoneInfo, len(resp.Data))
	for _, zone := range resp.Data {
		byName[zone.Name] = zone
	}
	q, ok := byName["zzq8100"]
	if !ok {
		t.Fatalf("quarantined zzq8100 missing from desired inventory: %s", rr.Body.String())
	}
	if q.ID != ids["zzq8100"] || len(q.Interfaces) != 1 || q.Interfaces[0] != "if-quarantined" {
		t.Fatalf("quarantined desired row changed: %+v", q)
	}
	if q.PerZoneCountersAvailable {
		t.Fatalf("quarantined row reports counters available: %+v", q)
	}
	if q.IngressPackets != 0 || q.IngressBytes != 0 || q.EgressPackets != 0 || q.EgressBytes != 0 {
		t.Fatalf("quarantined row reused survivor volume: %+v", q)
	}
	survivor := byName["zzq17760"]
	if !survivor.PerZoneCountersAvailable || survivor.IngressPackets != 17 || survivor.EgressPackets != 23 {
		t.Fatalf("survivor counters changed: %+v", survivor)
	}
	ordinary := byName["trust"]
	if !ordinary.PerZoneCountersAvailable || ordinary.IngressPackets != 31 || ordinary.EgressPackets != 41 {
		t.Fatalf("ordinary control counters changed: %+v", ordinary)
	}
	if strings.Contains(rr.Body.String(), config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("zones response used policy qualifier unexpectedly: %s", rr.Body.String())
	}
}

// TestPoliciesHandlerQuarantinedRulesMarked10530 verifies the REST inventory
// retains authored rows while marking counters and scoped-global display copies
// that would be scrubbed from an applied snapshot.
func TestPoliciesHandlerQuarantinedRulesMarked10530(t *testing.T) {
	s, _ := quarantinedZonesConfig10530(t)
	cfg := s.store.ActiveConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "zzq8100", Policies: []*config.Policy{{
			Name: "loser-rule", Description: "authored", Action: config.PolicyPermit,
		}}},
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{{
			Name: "ordinary-rule", Action: config.PolicyPermit,
		}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "scoped-global", Action: config.PolicyDeny,
		Match: config.PolicyMatch{FromZones: []string{"zzq8100"}, ToZones: []string{"zzq8100", "zzq17760"}},
	}}
	s.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: quarantineIDs10530(t)},
	}

	rr := httptest.NewRecorder()
	s.policiesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/policies", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("policiesHandler status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode policies response: %v; body=%s", err, rr.Body.String())
	}
	if !resp.Success || len(resp.Data) < 3 {
		t.Fatalf("success=%v rows=%d, want success + policy rows: %s", resp.Success, len(resp.Data), rr.Body.String())
	}
	var loser, ordinary, global *PolicyInfo
	for i := range resp.Data {
		switch {
		case resp.Data[i].FromZone == "trust" && resp.Data[i].ToZone == "zzq8100":
			loser = &resp.Data[i]
		case resp.Data[i].FromZone == "trust" && resp.Data[i].ToZone == "untrust":
			ordinary = &resp.Data[i]
		case resp.Data[i].FromZone == "*":
			global = &resp.Data[i]
		}
	}
	if loser == nil || len(loser.Rules) != 1 || !loser.Rules[0].HitCountersUnavailable ||
		!strings.Contains(loser.Rules[0].Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("quarantined zone-pair rule was not marked: %+v", loser)
	}
	if ordinary == nil || len(ordinary.Rules) != 1 || ordinary.Rules[0].HitCountersUnavailable ||
		strings.Contains(ordinary.Rules[0].Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary control changed: %+v", ordinary)
	}
	if global == nil || len(global.Rules) != 1 || !global.Rules[0].HitCountersUnavailable ||
		!strings.Contains(global.Rules[0].Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("scoped global was not marked: %+v", global)
	}
	if len(global.Rules[0].MatchFromZones) != 0 || len(global.Rules[0].MatchToZones) != 1 ||
		global.Rules[0].MatchToZones[0] != "zzq17760" {
		t.Fatalf("scoped-global display scope was not pruned: %+v", global.Rules[0])
	}
	if global.Rules[0].MatchToZone != "zzq8100" {
		t.Fatalf("singular scoped-global compatibility field changed: %+v", global.Rules[0])
	}
}

func TestPoliciesHandlerQuarantineQualifierWithoutCounterEligibility10530(t *testing.T) {
	s, ids := quarantinedZonesConfig10530(t)
	cfg := s.store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = false
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "zzq8100", Policies: []*config.Policy{{
			Name: "loser-no-count", Action: config.PolicyPermit,
		}},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "scoped-global-no-count", Action: config.PolicyDeny,
		Match: config.PolicyMatch{FromZones: []string{"zzq8100"}, ToZones: []string{"zzq8100", "zzq17760"}},
	}}
	s.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}

	rr := httptest.NewRecorder()
	s.policiesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/policies", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("policiesHandler status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data []PolicyInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode policies response: %v; body=%s", err, rr.Body.String())
	}
	var loser, global *PolicyInfo
	for i := range resp.Data {
		switch {
		case resp.Data[i].FromZone == "trust" && resp.Data[i].ToZone == "zzq8100":
			loser = &resp.Data[i]
		case resp.Data[i].FromZone == "*":
			global = &resp.Data[i]
		}
	}
	if loser == nil || len(loser.Rules) != 1 ||
		loser.Rules[0].HitCountersUnavailable ||
		!strings.Contains(loser.Rules[0].Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("stats-off quarantined rule disposition = %+v, want qualifier without unavailable flag", loser)
	}
	if global == nil || len(global.Rules) != 1 ||
		global.Rules[0].HitCountersUnavailable ||
		!strings.Contains(global.Rules[0].Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("stats-off scoped-global disposition = %+v, want qualifier without unavailable flag", global)
	}
}
