package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestPoliciesHandlerMixedScopeGlobalKeepsLiveCounters12897 is the #12897
// REST regression (D9-07): a scoped global whose match set carries BOTH a
// surviving zone and a quarantined zone stays installed and enforced for the
// survivors (#5577 prunes the member, not the rule), so the REST inventory
// must keep its LIVE counters instead of marking the whole rule quarantined.
//
// The control is the wholly-quarantined twin: a configured side EMPTIED by
// the prune makes the runtime scrub DROP the whole rule, so its counters stay
// unavailable even though the fake dataplane publishes a nonzero value for
// its rule id — proving the suppression, not an unread zero, keeps it at 0.
//
// RED on master: the any-member whole-rule marking suppresses mixed-global's
// counters (hit_counters_unavailable=true, hit_packets=0).
func TestPoliciesHandlerMixedScopeGlobalKeepsLiveCounters12897(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"if-trust"}},
		"untrust": {Name: "untrust", Interfaces: []string{"if-untrust"}},
		"z174":    {Name: "z174", Interfaces: []string{"if-survivor"}},
		"z214":    {Name: "z214", Interfaces: []string{"if-quarantined"}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "mixed-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"trust", "z214"}, ToZones: []string{"untrust"}},
		},
		{
			Name: "dead-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"z214"}, ToZones: []string{"untrust"}},
		},
	}
	// The store carries one zone-pair set (trust->untrust), so the global
	// counter ids continue at policy set 1. Seed BOTH so a pass cannot come
	// from an unread zero.
	base := uint32(len(cfg.Security.Policies)) * dataplane.MaxRulesPerPolicy
	s := &Server{store: store, dp: &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			base:     {Packets: 17, Bytes: 1700},
			base + 1: {Packets: 23, Bytes: 2300},
		},
	}}

	rows := fetchPolicies(t, s)

	mixed, ok := findRule(rows, "mixed-global")
	if !ok {
		t.Fatal("mixed-global rule missing from response")
	}
	if mixed.HitCountersUnavailable {
		t.Error("mixed-global: HitCountersUnavailable = true, want false (rule stays enforced for trust, #5577/#12897)")
	}
	if mixed.HitPackets != 17 || mixed.HitBytes != 1700 {
		t.Errorf("mixed-global: counters = %d/%d, want 17/1700 (live surviving-zone hits)", mixed.HitPackets, mixed.HitBytes)
	}
	if len(mixed.MatchFromZones) != 1 || mixed.MatchFromZones[0] != "trust" {
		t.Errorf("mixed-global: pruned display scope = %v, want [trust]", mixed.MatchFromZones)
	}
	if !strings.Contains(mixed.Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("mixed-global: description lost the pruned-member qualifier: %q", mixed.Description)
	}

	dead, ok := findRule(rows, "dead-global")
	if !ok {
		t.Fatal("dead-global rule missing from response")
	}
	if !dead.HitCountersUnavailable {
		t.Error("dead-global: HitCountersUnavailable = false, want true (from side emptied — rule dropped at runtime)")
	}
	if dead.HitPackets != 0 || dead.HitBytes != 0 {
		t.Errorf("dead-global: counters = %d/%d, want 0/0 (dropped rule must not surface the seeded value)", dead.HitPackets, dead.HitBytes)
	}
	if !strings.Contains(dead.Description, config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("dead-global: description lost the quarantine qualifier: %q", dead.Description)
	}
}
