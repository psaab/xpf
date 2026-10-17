package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14361: GetPolicies is the structured twin of the REST policiesHandler
// (#12900). The REST handler prunes quarantined zones from mixed-scope
// global policies, qualifies the description, gates the counter read on
// !Quarantined, and marks wholly-quarantined rules' counters unavailable
// even when the rule is not counter-eligible. GetPolicies lacked all of
// that: it copied authored scope verbatim and read counters for
// quarantined rules.
//
// Fixture: z174/z214 collide under the frozen StableZoneID fold, so z214
// is the quarantined loser. mixed-global [trust z214]->[untrust z214]
// keeps survivors on both sides; dead-global [z214]->[untrust] is emptied
// on the from side; dead-pair is a zone-pair rule trust->z214. None of
// the quarantined/mixed rules carries `then count`, and the store has no
// policy-stats enable (statsEnabled=false), so the counter-eligibility
// gate alone would leave HitCountersUnavailable=false.

func quarantine14361Server(t *testing.T, seedDead bool) *Server {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
	// The scheduler fixture enables policy-stats; the decisive cell here
	// is stats-off + no count, so strip the knob and the count flags.
	// Direct config mutation mirrors the #12897 mixed-scope fixture.
	store.ActiveConfig().Security.PolicyStatsEnabled = false
	cfg := store.ActiveConfig()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
		"dmz":     {Name: "dmz"},
		"z174":    {Name: "z174"},
		"z214":    {Name: "z214"},
	}
	if _, ok := config.ZoneQuarantineExclusionsForConfig(cfg)["z214"]; !ok {
		t.Fatalf("test premise broken: z214 not quarantined: %v", config.ZoneQuarantineExclusionsForConfig(cfg))
	}
	// Zone-pair rules: one quarantined (trust->z214), no count.
	cfg.Security.Policies = append(cfg.Security.Policies, &config.ZonePairPolicies{
		FromZone: "trust", ToZone: "z214",
		Policies: []*config.Policy{{
			Name: "dead-pair", Description: "pair-desc", Action: config.PolicyPermit,
		}},
	})
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "mixed-global", Description: "mixed-desc", Action: config.PolicyDeny,
			Match: config.PolicyMatch{FromZones: []string{"trust", "z214"}, ToZones: []string{"untrust", "z214"}},
		},
		{
			Name: "dead-global", Description: "dead-desc", Action: config.PolicyDeny,
			Match: config.PolicyMatch{FromZones: []string{"z214"}, ToZones: []string{"untrust"}},
		},
		{
			Name: "live-global", Description: "live-desc", Action: config.PolicyDeny,
			Match: config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}},
		},
	}
	// Seed stale counters for the wholly-quarantined rules: if GetPolicies
	// reads them (no !Quarantined gate) the stale hits surface.
	base := uint32(len(cfg.Security.Policies)) * dataplane.MaxRulesPerPolicy
	counters := map[uint32]dataplane.CounterValue{}
	if seedDead {
		// dead-pair is the last zone-pair set, rule 0.
		pairBase := uint32(len(cfg.Security.Policies)-1) * dataplane.MaxRulesPerPolicy
		counters[pairBase] = dataplane.CounterValue{Packets: 99, Bytes: 9900}
		counters[base+1] = dataplane.CounterValue{Packets: 23, Bytes: 2300}
	}
	return &Server{store: store, dp: &schedulerCounterGRPCDP{
		Manager:  dataplane.New(),
		counters: counters,
	}}
}

func findPolicyRule14361(t *testing.T, resp *pb.GetPoliciesResponse, name string) *pb.PolicyRule {
	t.Helper()
	for _, pi := range resp.GetPolicies() {
		for _, pr := range pi.GetRules() {
			if pr.GetName() == name {
				return pr
			}
		}
	}
	t.Fatalf("rule %q missing from GetPolicies response", name)
	return nil
}

func TestGetPoliciesMixedScopeGlobalPrunesQuarantinedZones14361(t *testing.T) {
	s := quarantine14361Server(t, true)
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	if resp.GetPolicyStatsEnabled() {
		t.Fatal("test premise broken: policy-stats must be disabled")
	}

	mixed := findPolicyRule14361(t, resp, "mixed-global")
	if mixed.GetQuarantined() {
		t.Error("mixed-global: Quarantined = true, want false (mixed scope stays enforced for survivors)")
	}
	if got := mixed.GetMatchFromZones(); len(got) != 1 || got[0] != "trust" {
		t.Errorf("mixed-global: MatchFromZones = %v, want [trust] (z214 pruned)", got)
	}
	if got := mixed.GetMatchToZones(); len(got) != 1 || got[0] != "untrust" {
		t.Errorf("mixed-global: MatchToZones = %v, want [untrust] (z214 pruned)", got)
	}
	if mixed.GetMatchFromZone() != "trust" {
		t.Errorf("mixed-global: MatchFromZone = %q, want %q (first surviving zone)", mixed.GetMatchFromZone(), "trust")
	}
	if mixed.GetMatchToZone() != "untrust" {
		t.Errorf("mixed-global: MatchToZone = %q, want %q (first surviving zone)", mixed.GetMatchToZone(), "untrust")
	}
	if !strings.Contains(mixed.GetDescription(), config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("mixed-global: Description = %q, want qualifier %q appended", mixed.GetDescription(), config.ZoneQuarantinePoliciesQualifier)
	}
	if !strings.HasPrefix(mixed.GetDescription(), "mixed-desc") {
		t.Errorf("mixed-global: Description = %q, want authored prefix preserved", mixed.GetDescription())
	}
	// Mixed rule stays live: counters are NOT marked unavailable merely
	// because a member was pruned.
	if mixed.GetHitCountersUnavailable() {
		t.Error("mixed-global: HitCountersUnavailable = true, want false (survivors stay enforced)")
	}

	live := findPolicyRule14361(t, resp, "live-global")
	if got := live.GetMatchFromZones(); len(got) != 1 || got[0] != "trust" {
		t.Errorf("live-global: MatchFromZones = %v, want [trust] (control unchanged)", got)
	}
	if strings.Contains(live.GetDescription(), config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("live-global: Description = %q, control gained qualifier", live.GetDescription())
	}
	if live.GetHitCountersUnavailable() {
		t.Error("live-global: HitCountersUnavailable = true, want false (control)")
	}
}

func TestGetPoliciesQuarantinedCountersUnavailableWithoutEligibility14361(t *testing.T) {
	s := quarantine14361Server(t, true)
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}

	dead := findPolicyRule14361(t, resp, "dead-global")
	if !dead.GetQuarantined() {
		t.Error("dead-global: Quarantined = false, want true (from side emptied)")
	}
	if dead.GetCount() {
		t.Fatal("test premise broken: dead-global must have Count=false")
	}
	if !dead.GetHitCountersUnavailable() {
		t.Error("dead-global: HitCountersUnavailable = false with stats off and no count, want true (quarantined rule has no live attribution)")
	}
	if dead.GetHitPackets() != 0 || dead.GetHitBytes() != 0 {
		t.Errorf("dead-global: counters = %d/%d, want 0/0 (stale seeded counter must not surface)", dead.GetHitPackets(), dead.GetHitBytes())
	}
	if !strings.Contains(dead.GetDescription(), config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("dead-global: Description = %q, want qualifier appended", dead.GetDescription())
	}
	// Fully-pruned side stays empty, not broadened to wildcard.
	if got := dead.GetMatchFromZones(); len(got) != 0 {
		t.Errorf("dead-global: MatchFromZones = %v, want empty (fully pruned)", got)
	}
	if dead.GetMatchFromZone() != "" {
		t.Errorf("dead-global: MatchFromZone = %q, want empty (no surviving zone)", dead.GetMatchFromZone())
	}

	pair := findPolicyRule14361(t, resp, "dead-pair")
	if !pair.GetQuarantined() {
		t.Error("dead-pair: Quarantined = false, want true")
	}
	if !pair.GetHitCountersUnavailable() {
		t.Error("dead-pair: HitCountersUnavailable = false with stats off and no count, want true")
	}
	if pair.GetHitPackets() != 0 || pair.GetHitBytes() != 0 {
		t.Errorf("dead-pair: counters = %d/%d, want 0/0 (stale seeded counter must not surface)", pair.GetHitPackets(), pair.GetHitBytes())
	}
	if !strings.Contains(pair.GetDescription(), config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("dead-pair: Description = %q, want qualifier appended", pair.GetDescription())
	}
}
