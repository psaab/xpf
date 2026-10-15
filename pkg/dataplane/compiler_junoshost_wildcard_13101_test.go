package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type d13101DP struct {
	DataPlane
	pairs []ZonePairKey
	rules []PolicyRule
}

func (d *d13101DP) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	d.pairs = append(d.pairs, ZonePairKey{FromZone: fromZone, ToZone: toZone})
	return nil
}
func (d *d13101DP) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	d.rules = append(d.rules, rule)
	return nil
}
func (d *d13101DP) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {}

func mk13101(t *testing.T, from, to string) (*d13101DP, *CompileResult, error) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: from, ToZone: to,
		Policies: []*config.Policy{{
			Name: "p1", Action: config.PolicyPermit, SchedulerName: "sched",
			Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}},
		}},
	}}
	res := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(res, cfg)
	dp := &d13101DP{}
	err := compilePolicies(dp, cfg, res)
	return dp, res, err
}

func TestCompilePoliciesJunosHostAndWildcardZones13101(t *testing.T) {
	trustID := config.StableZoneID("trust")
	untrustID := config.StableZoneID("untrust")
	cases := []struct {
		name     string
		from, to string
		want     ZonePairKey
	}{
		{"to-junos-host", "trust", "junos-host", ZonePairKey{FromZone: trustID, ToZone: config.ZoneIDReservedMin}},
		{"from-any", "any", "untrust", ZonePairKey{FromZone: 0, ToZone: untrustID}},
		{"to-any", "trust", "any", ZonePairKey{FromZone: trustID, ToZone: 0}},
		{"both-any", "any", "any", ZonePairKey{FromZone: 0, ToZone: 0}},
		{"control", "trust", "untrust", ZonePairKey{FromZone: trustID, ToZone: untrustID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp, res, err := mk13101(t, tc.from, tc.to)
			if err != nil {
				t.Fatalf("compilePolicies(%s->%s): %v", tc.from, tc.to, err)
			}
			if len(dp.pairs) != 1 || dp.pairs[0] != tc.want {
				t.Fatalf("pairs=%v want [%v]", dp.pairs, tc.want)
			}
			if len(dp.rules) != 1 || res.PolicyNames[dp.rules[0].RuleID] != "p1" {
				t.Fatalf("rules=%v names=%v", dp.rules, res.PolicyNames)
			}
			if len(res.PolicyScheduleRuleSlots) != 1 || res.PolicyScheduleRuleSlots[0].PolicyName != "p1" {
				t.Fatalf("schedule slots=%v", res.PolicyScheduleRuleSlots)
			}
		})
	}
}

func TestCompilePoliciesUnknownZoneStillRejected13101(t *testing.T) {
	if _, _, err := mk13101(t, "trust", "no-such-zone"); err == nil {
		t.Fatal("unknown to-zone must still fail closed")
	}
	if _, _, err := mk13101(t, "no-such-zone", "untrust"); err == nil {
		t.Fatal("unknown from-zone must still fail closed")
	}
	if _, _, err := mk13101(t, "junos-host", "untrust"); err == nil {
		t.Fatal("unsupported host-originated from-zone must still fail closed")
	}
}

func TestCompilePoliciesDefinedAnyUsesConfiguredZoneID13101(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"any": {Name: "any"}, "untrust": {Name: "untrust"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "any", ToZone: "untrust",
		Policies: []*config.Policy{{Name: "p1", Action: config.PolicyPermit}},
	}}
	result := &CompileResult{ZoneIDs: make(map[string]uint16), AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32)}
	assignZoneIDs(result, cfg)
	dp := &d13101DP{}
	if err := compilePolicies(dp, cfg, result); err != nil {
		t.Fatalf("defined legacy `any` zone must resolve as its configured zone: %v", err)
	}
	want := ZonePairKey{FromZone: config.StableZoneID("any"), ToZone: config.StableZoneID("untrust")}
	if len(dp.pairs) != 1 || dp.pairs[0] != want {
		t.Fatalf("pairs=%v want [%v]", dp.pairs, want)
	}
}
