package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildScheduledPolicyRuleSlotsHandlesExpandedAndGlobalPolicies(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			ApplicationSets: map[string]*config.ApplicationSet{
				"set-web": {
					Name: "set-web",
					Applications: []string{
						"junos-http",
						"junos-https",
					},
				},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:          "unscheduled",
							SchedulerName: "",
							Match: config.PolicyMatch{
								Applications: []string{"any"},
							},
						},
						{
							Name:          "scheduled-zp",
							SchedulerName: "workhours",
							Match: config.PolicyMatch{
								Applications: []string{"set-web"},
							},
						},
					},
				},
			},
			GlobalPolicies: []*config.Policy{
				{
					Name:          "scheduled-global",
					SchedulerName: "afterhours",
					Match: config.PolicyMatch{
						Applications: []string{"set-web"},
					},
				},
			},
		},
	}

	slots, err := BuildScheduledPolicyRuleSlots(cfg)
	if err != nil {
		t.Fatalf("BuildScheduledPolicyRuleSlots returned error: %v", err)
	}
	if len(slots) != 4 {
		t.Fatalf("slot count = %d, want 4", len(slots))
	}
	for _, slot := range slots {
		if slot.PolicyName == "unscheduled" {
			t.Fatalf("unscheduled policy unexpectedly included in slots: %+v", slot)
		}
	}

	globalBase := uint32(len(cfg.Security.Policies)) * MaxRulesPerPolicy

	want := []struct {
		policy    string
		scheduler string
		index     uint32
	}{
		{policy: "scheduled-zp", scheduler: "workhours", index: 1},
		{policy: "scheduled-zp", scheduler: "workhours", index: 2},
		{policy: "scheduled-global", scheduler: "afterhours", index: globalBase},
		{policy: "scheduled-global", scheduler: "afterhours", index: globalBase + 1},
	}
	for i, w := range want {
		got := slots[i]
		if got.PolicyName != w.policy || got.SchedulerName != w.scheduler || got.AbsoluteRuleIdx != w.index {
			t.Fatalf("slot[%d] = %+v, want policy=%q scheduler=%q index=%d", i, got, w.policy, w.scheduler, w.index)
		}
	}
}
