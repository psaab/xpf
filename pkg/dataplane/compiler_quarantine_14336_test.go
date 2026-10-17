package dataplane

// #14336: compilePolicies omitted ZoneQuarantineExclusionsForConfig, so a
// quarantined collision-loser stanza with >MaxRulesPerPolicy expanded rules
// aborted CompileConfig/CompileUserspaceShim, clobbered the survivor's
// ZonePairKey slot, and leaked dead rules into PolicyNames/schedule slots.

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type quarantinePolicyDP14336 struct {
	DataPlane
	sets  []PolicySet
	pairs []ZonePairKey
	rules []PolicyRule
}

func (d *quarantinePolicyDP14336) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	d.pairs = append(d.pairs, ZonePairKey{FromZone: fromZone, ToZone: toZone})
	d.sets = append(d.sets, ps)
	return nil
}
func (d *quarantinePolicyDP14336) SetPolicyRule(_ uint32, _ uint32, rule PolicyRule) error {
	d.rules = append(d.rules, rule)
	return nil
}
func (d *quarantinePolicyDP14336) DeleteStaleZonePairPolicies(map[ZonePairKey]bool) {}

func collidingZone14336(t *testing.T) string {
	t.Helper()
	target := config.StableZoneID("trust")
	for i := range 200000 {
		c := fmt.Sprintf("z-coll-%d", i)
		if config.StableZoneID(c) == target {
			return c
		}
	}
	t.Fatal("no colliding zone found")
	return ""
}

func TestCompilePolicies_SkipsQuarantinedZoneStanzas(t *testing.T) {
	colliding := collidingZone14336(t)
	// Sorted order: "trust" < "untrust" < "z-coll-..." so collider is loser.
	if colliding < "trust" {
		t.Fatalf("collider %q must sort after trust to be loser", colliding)
	}
	mkPol := func(name string) *config.Policy {
		return &config.Policy{Name: name, Action: config.PolicyPermit, SchedulerName: "sched",
			Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}
	}
	// Quarantined stanza: 260 rules (>256) would abort pre-fix.
	big := make([]*config.Policy, 0, 260)
	for i := range 260 {
		big = append(big, mkPol(fmt.Sprintf("dead-%d", i)))
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"}, colliding: {Name: colliding},
	}
	// Survivor first, quarantined second (would clobber same ZonePairKey pre-fix).
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{mkPol("survivor")}},
		{FromZone: colliding, ToZone: "untrust", Policies: big},
		{FromZone: "untrust", ToZone: "trust", Policies: []*config.Policy{mkPol("after")}},
	}
	if _, ok := config.ZoneQuarantineExclusionsForConfig(cfg)[colliding]; !ok {
		t.Fatalf("premise: %q not quarantined: %v", colliding, config.ZoneQuarantineExclusionsForConfig(cfg))
	}
	res := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(res, cfg)
	dp := &quarantinePolicyDP14336{}
	if err := compilePolicies(dp, cfg, res); err != nil {
		t.Fatalf("compilePolicies must skip quarantined stanza, got: %v", err)
	}
	// Only survivor + after sets written; quarantined must not clobber survivor key.
	if len(dp.sets) != 2 {
		t.Fatalf("sets=%d want 2 (survivor+after): %+v pairs=%v", len(dp.sets), dp.sets, dp.pairs)
	}
	survivorKey := ZonePairKey{FromZone: config.StableZoneID("trust"), ToZone: config.StableZoneID("untrust")}
	if dp.pairs[0] != survivorKey || dp.sets[0].NumRules != 1 || dp.sets[0].PolicySetID != 0 {
		t.Fatalf("survivor set clobbered: pairs=%v sets=%+v", dp.pairs, dp.sets)
	}
	// policySetID must advance over skipped stanza so "after" keeps raw index 2,
	// matching walkPolicyRuleSlots survivor stability.
	if dp.sets[1].PolicySetID != 2 {
		t.Fatalf("after set PolicySetID=%d want 2 (skipped stanza consumes index)", dp.sets[1].PolicySetID)
	}
	if len(dp.rules) != 2 {
		t.Fatalf("rules=%d want 2", len(dp.rules))
	}
	if res.PolicyNames[0] != "survivor" {
		t.Fatalf("PolicyNames[0]=%q want survivor: %v", res.PolicyNames[0], res.PolicyNames)
	}
	// No dead quarantined rule names / schedule slots.
	for id, name := range res.PolicyNames {
		if len(name) >= 5 && name[:5] == "dead-" {
			t.Fatalf("dead quarantined rule leaked PolicyNames[%d]=%q", id, name)
		}
	}
	for _, s := range res.PolicyScheduleRuleSlots {
		if len(s.PolicyName) >= 5 && s.PolicyName[:5] == "dead-" {
			t.Fatalf("dead quarantined schedule slot leaked: %+v", s)
		}
	}
	if len(res.PolicyScheduleRuleSlots) != 2 {
		t.Fatalf("schedule slots=%v want survivor+after only", res.PolicyScheduleRuleSlots)
	}
	if res.PolicyScheduleRuleSlots[1].PolicySetID != 2 || res.PolicyScheduleRuleSlots[1].RuleID != 2*MaxRulesPerPolicy {
		t.Fatalf("after schedule slot shifted: %+v", res.PolicyScheduleRuleSlots[1])
	}
	if res.PolicySets != 2 {
		t.Fatalf("PolicySets=%d want 2", res.PolicySets)
	}
	// Reserved sentinels must NOT be treated as quarantined: wildcard + host survive.
	cfg2 := &config.Config{}
	cfg2.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}}
	cfg2.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{mkPol("wild")}},
		{FromZone: "trust", ToZone: "junos-host", Policies: []*config.Policy{mkPol("host")}},
	}
	res2 := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(res2, cfg2)
	dp2 := &quarantinePolicyDP14336{}
	if err := compilePolicies(dp2, cfg2, res2); err != nil {
		t.Fatalf("reserved sentinel policies must compile: %v", err)
	}
	if len(dp2.sets) != 2 {
		t.Fatalf("reserved sentinel sets=%d want 2 pairs=%v", len(dp2.sets), dp2.pairs)
	}
	// Fail-closed: unknown zone still rejected.
	cfg3 := &config.Config{}
	cfg3.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}}
	cfg3.Security.Policies = []*config.ZonePairPolicies{{FromZone: "trust", ToZone: "nope", Policies: []*config.Policy{mkPol("x")}}}
	res3 := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(res3, cfg3)
	if err := compilePolicies(&quarantinePolicyDP14336{}, cfg3, res3); err == nil {
		t.Fatal("unknown zone must still fail closed")
	}
	// Fail-closed: non-quarantined >256 still rejected.
	cfg4 := &config.Config{}
	cfg4.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}}
	cfg4.Security.Policies = []*config.ZonePairPolicies{{FromZone: "trust", ToZone: "untrust", Policies: big}}
	res4 := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(res4, cfg4)
	if err := compilePolicies(&quarantinePolicyDP14336{}, cfg4, res4); err == nil {
		t.Fatal("non-quarantined >256 must still fail closed")
	}
}
