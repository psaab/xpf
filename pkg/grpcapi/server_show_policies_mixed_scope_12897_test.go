package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// mixedScopeGlobalsGRPC12897 builds the #12897 decisive shape on the gRPC
// store: two scoped globals over a zone set with one collision survivor
// (z174) and one collision loser (z214). mixed-global's from side is MIXED
// ([trust z214]) so the runtime scrub (#5577) prunes z214 and keeps the rule
// enforced for trust; dead-global's from side is EMPTIED by the prune, so the
// scrub drops the whole rule. The fake dataplane seeds the mixed rule's live
// hits so a pass can only come from actually reading them.
func mixedScopeGlobalsGRPC12897(t *testing.T, seedDead bool) *Server {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
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
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "mixed-global", Action: config.PolicyDeny,
			Match: config.PolicyMatch{FromZones: []string{"trust", "z214"}, ToZones: []string{"untrust"}},
		},
		{
			Name: "dead-global", Action: config.PolicyDeny,
			Match: config.PolicyMatch{FromZones: []string{"z214"}, ToZones: []string{"untrust"}},
		},
	}
	// The store carries two zone-pair sets, so the global counter ids
	// continue at policy set 2.
	base := uint32(len(cfg.Security.Policies)) * dataplane.MaxRulesPerPolicy
	counters := map[uint32]dataplane.CounterValue{
		base: {Packets: 17, Bytes: 1700},
	}
	if seedDead {
		counters[base+1] = dataplane.CounterValue{Packets: 23, Bytes: 2300}
	}
	return &Server{store: store, dp: &schedulerCounterGRPCDP{
		Manager:  dataplane.New(),
		counters: counters,
	}}
}

func grpcLineContaining12897(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func grpcPolicyBlockContaining12897(out, name string) string {
	lines := strings.Split(out, "\n")
	start := -1
	for i, line := range lines {
		if strings.Contains(line, "Policy: "+name) {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.Contains(lines[i], "Policy: ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// TestShowPoliciesTextMixedScopeGlobalKeepsLiveCounters12897: the gRPC text
// hit-count table shows a mixed-scope global's LIVE counters (17/1700) — not
// the whole-rule UNAVAILABLE(quarantined) cells — while the
// wholly-quarantined twin keeps them. RED on master: any quarantined member
// flipped the whole rule to UNAVAILABLE.
func TestShowPoliciesTextMixedScopeGlobalKeepsLiveCounters12897(t *testing.T) {
	s := mixedScopeGlobalsGRPC12897(t, true)

	var hit strings.Builder
	s.showPoliciesHitCount("", &hit)

	mixed := grpcLineContaining12897(hit.String(), "mixed-global")
	if mixed == "" {
		t.Fatalf("mixed-global row missing from hit-count:\n%s", hit.String())
	}
	if strings.Contains(mixed, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("mixed-global row shows whole-rule unavailable disposition (#12897):\n%s", mixed)
	}
	if !strings.Contains(mixed, "17") || !strings.Contains(mixed, "1700") {
		t.Errorf("mixed-global row lacks its live hits 17/1700:\n%s", mixed)
	}
	if !strings.Contains(mixed, "z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("mixed-global row lost the per-member quarantine qualifier:\n%s", mixed)
	}

	dead := grpcLineContaining12897(hit.String(), "dead-global")
	if dead == "" {
		t.Fatalf("dead-global row missing from hit-count:\n%s", hit.String())
	}
	if !strings.Contains(dead, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("dead-global row lost the unavailable disposition (rule dropped at runtime):\n%s", dead)
	}
	if strings.Contains(dead, "23") {
		t.Errorf("dead-global row surfaced the seeded counter of a dropped rule:\n%s", dead)
	}
}

// TestShowPoliciesTextDetailMixedScopeGlobal12897: the gRPC text detail view's
// "Session statistics: UNAVAILABLE(quarantined)" line belongs only to a rule
// the scrub drops; a mixed-scope survivor prints real statistics instead.
func TestShowPoliciesTextDetailMixedScopeGlobal12897(t *testing.T) {
	s := mixedScopeGlobalsGRPC12897(t, true)

	var detail strings.Builder
	s.showPoliciesDetail("", &detail)

	mixed := grpcPolicyBlockContaining12897(detail.String(), "mixed-global")
	if mixed == "" {
		t.Fatalf("mixed-global block missing from detail:\n%s", detail.String())
	}
	if strings.Contains(mixed, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("mixed-global detail block shows whole-rule unavailable disposition (#12897):\n%s", mixed)
	}
	if !strings.Contains(mixed, "17 packets, 1700 bytes") {
		t.Errorf("mixed-global detail block lacks its live session statistics:\n%s", mixed)
	}

	dead := grpcPolicyBlockContaining12897(detail.String(), "dead-global")
	if dead == "" {
		t.Fatalf("dead-global block missing from detail:\n%s", detail.String())
	}
	if !strings.Contains(dead, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("dead-global detail block lost the unavailable disposition (rule dropped at runtime):\n%s", dead)
	}
}

// TestGetPoliciesMixedScopeGlobalQuarantineBit12897: the structured twin must
// not mark a mixed-scope global wholly Quarantined — #5577 keeps it enforced
// for the surviving zones — while the wholly-quarantined twin (a configured
// side EMPTIED by the prune) keeps the bit. RED on master: any quarantined
// scope member set Quarantined=true for the whole rule.
func TestGetPoliciesMixedScopeGlobalQuarantineBit12897(t *testing.T) {
	s := mixedScopeGlobalsGRPC12897(t, false)

	resp, err := s.GetPolicies(t.Context(), nil)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	rules := make(map[string]struct {
		Quarantined            bool
		HitPackets             uint64
		HitCountersUnavailable bool
	})
	for _, pi := range resp.Policies {
		for _, pr := range pi.Rules {
			rules[pr.Name] = struct {
				Quarantined            bool
				HitPackets             uint64
				HitCountersUnavailable bool
			}{pr.Quarantined, pr.HitPackets, pr.HitCountersUnavailable}
		}
	}
	mixed, ok := rules["mixed-global"]
	if !ok {
		t.Fatal("mixed-global rule missing from GetPolicies")
	}
	if mixed.Quarantined {
		t.Error("mixed-global: Quarantined = true, want false (rule stays enforced for trust, #12897)")
	}
	if mixed.HitPackets != 17 {
		t.Errorf("mixed-global: HitPackets = %d, want 17 (live surviving-zone hits)", mixed.HitPackets)
	}
	if mixed.HitCountersUnavailable {
		t.Error("mixed-global: HitCountersUnavailable = true, want false")
	}

	dead, ok := rules["dead-global"]
	if !ok {
		t.Fatal("dead-global rule missing from GetPolicies")
	}
	if !dead.Quarantined {
		t.Error("dead-global: Quarantined = false, want true (from side emptied — rule dropped at runtime)")
	}
}
