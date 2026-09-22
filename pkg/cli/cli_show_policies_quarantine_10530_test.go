package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func quarantinePolicyCLI10530(t *testing.T) *CLI {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "z214", Policies: []*config.Policy{{
			Name: "loser-rule", Action: config.PolicyPermit,
		}}},
		{FromZone: "trust", ToZone: "trust", Policies: []*config.Policy{{
			Name: "ordinary-rule", Action: config.PolicyPermit,
		}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "scoped-global", Action: config.PolicyDeny,
		Match: config.PolicyMatch{ToZones: []string{"z214", "z174"}},
	}}
	return &CLI{
		store: store,
		dp:    &policyCounterCLIDP{Manager: dataplane.New(), counters: map[uint32]dataplane.CounterValue{}},
	}
}

func TestCLIPolicyTextQuarantineQualifier10530(t *testing.T) {
	c := quarantinePolicyCLI10530(t)
	cfg := c.store.ActiveConfig()
	hit := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "trust", "z214"); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
	})
	detail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "z214"); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	for name, out := range map[string]string{"hit-count": hit, "detail": detail} {
		if !strings.Contains(out, config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s output lacks quarantine qualifier:\n%s", name, out)
		}
		if !strings.Contains(out, config.ZoneQuarantineLiveCountersUnavailable) {
			t.Fatalf("%s output lacks live-counter-unavailable disposition:\n%s", name, out)
		}
		if !strings.Contains(out, "loser-rule") {
			t.Fatalf("%s output silently dropped authored quarantined rule:\n%s", name, out)
		}
	}
	ordinary := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "trust"); err != nil {
			t.Fatalf("showPoliciesDetail ordinary: %v", err)
		}
	})
	if strings.Contains(ordinary, config.ZoneQuarantinePoliciesQualifier) ||
		strings.Contains(ordinary, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("ordinary control gained quarantine text:\n%s", ordinary)
	}
}
