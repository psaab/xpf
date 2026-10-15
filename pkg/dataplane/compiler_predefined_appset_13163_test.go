package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// 13163 / D4-04: compilePolicies must expand predefined application-sets
// (config.PredefinedApplicationSets, e.g. junos-cifs) exactly like the
// userspace walkPolicyRuleSlots expansion, instead of collapsing them to
// AppID=0 (wildcard) and shifting PolicyNames for every following rule.

type d13163DP struct {
	DataPlane
	rules []PolicyRule
}

func (*d13163DP) SetApplication(uint8, uint16, uint32, uint32, uint8, uint16, uint16) error {
	return nil
}
func (*d13163DP) SetAppRange(uint32, AppRangeEntry) error { return nil }
func (*d13163DP) DeleteStaleApplications(map[AppKey]bool) {}

func (d *d13163DP) SetZonePairPolicy(uint16, uint16, PolicySet) error { return nil }
func (d *d13163DP) SetPolicyRule(_ uint32, _ uint32, rule PolicyRule) error {
	d.rules = append(d.rules, rule)
	return nil
}
func (d *d13163DP) DeleteStaleZonePairPolicies(map[ZonePairKey]bool) {}

func TestCompilePoliciesPredefinedAppSetParity13163(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"single-app": {Name: "single-app", Protocol: "tcp", DestinationPort: "9000"},
			},
		},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{
					{Name: "rule-predefined-set", Action: config.PolicyPermit,
						Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"junos-cifs"}}},
					{Name: "rule-after", Action: config.PolicyDeny, SchedulerName: "nightly",
						Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"single-app"}}},
				},
			}},
			GlobalPolicies: []*config.Policy{
				{Name: "global-predefined-set", Action: config.PolicyPermit,
					Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"junos-cifs"}}},
			},
		},
	}
	res := &CompileResult{
		ZoneIDs: map[string]uint16{"trust": 1, "untrust": 2},
		AddrIDs: make(map[string]uint32), AppIDs: make(map[string]uint32),
		PolicyNames: make(map[uint32]string),
	}
	dp := &d13163DP{}
	if err := compileApplications(dp, cfg, res); err != nil {
		t.Fatalf("compileApplications: %v", err)
	}
	if err := compilePolicies(dp, cfg, res); err != nil {
		t.Fatalf("compilePolicies: %v", err)
	}

	// junos-cifs = {junos-netbios-session, junos-smb-session}: 2 distinct AppIDs, none wildcard.
	if len(dp.rules) != 5 { // 2 (zone pair set) + 1 (rule-after) + 2 (global)
		t.Fatalf("compiled rules=%d, want 5 (rules=%+v)", len(dp.rules), dp.rules)
	}
	nb, smb := res.AppIDs["junos-netbios-session"], res.AppIDs["junos-smb-session"]
	if nb == 0 || smb == 0 || nb == smb {
		t.Fatalf("AppIDs netbios=%d smb=%d, want distinct non-zero", nb, smb)
	}
	got := map[uint32]bool{dp.rules[0].AppID: true, dp.rules[1].AppID: true}
	if !got[nb] || !got[smb] {
		t.Fatalf("zone-pair predefined-set rules AppIDs=%d,%d, want {%d,%d} (no wildcard 0)", dp.rules[0].AppID, dp.rules[1].AppID, nb, smb)
	}
	if dp.rules[2].AppID != res.AppIDs["single-app"] {
		t.Fatalf("rule-after AppID=%d, want %d", dp.rules[2].AppID, res.AppIDs["single-app"])
	}
	gotG := map[uint32]bool{dp.rules[3].AppID: true, dp.rules[4].AppID: true}
	if !gotG[nb] || !gotG[smb] {
		t.Fatalf("global predefined-set rules AppIDs=%d,%d, want {%d,%d}", dp.rules[3].AppID, dp.rules[4].AppID, nb, smb)
	}

	// PolicyNames is keyed by RuleID = policySetID*Max + index, matching the
	// userspace policy slot expansion for this predefined set.
	if res.PolicyNames[0] != "rule-predefined-set" || res.PolicyNames[1] != "rule-predefined-set" {
		t.Fatalf("PolicyNames[0..1]=%q,%q want rule-predefined-set twice", res.PolicyNames[0], res.PolicyNames[1])
	}
	if res.PolicyNames[2] != "rule-after" {
		t.Fatalf("PolicyNames[2]=%q want rule-after", res.PolicyNames[2])
	}
	if len(res.PolicyScheduleRuleSlots) != 1 {
		t.Fatalf("schedule slots=%+v, want one slot for rule-after", res.PolicyScheduleRuleSlots)
	}
	slot := res.PolicyScheduleRuleSlots[0]
	if slot.RuleID != 2 || slot.RuleIndex != 2 || slot.PolicyName != "rule-after" || slot.SchedulerName != "nightly" {
		t.Fatalf("schedule slot=%+v, want rule-after at expanded slot 2", slot)
	}
}
