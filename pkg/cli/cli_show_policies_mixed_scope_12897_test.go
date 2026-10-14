package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// mixedScopeGlobalsCLI12897 builds the #12897 decisive shape on the CLI store:
// two scoped globals over a zone set with one collision survivor (z174) and
// one collision loser (z214). mixed-global's from side is MIXED
// ([trust z214]) so the runtime scrub (#5577) prunes z214 and keeps the rule
// enforced for trust; dead-global's from side is EMPTIED by the prune, so the
// scrub drops the whole rule. The fake dataplane seeds nonzero hits for BOTH
// rule ids, so the mixed row can only show its number by actually reading it
// and the dead row can only stay suppressed by actually skipping it.
func mixedScopeGlobalsCLI12897(t *testing.T) (*CLI, *config.Config) {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
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
	// The store carries one zone-pair set (trust->untrust), so the global
	// counter ids continue at policy set 1.
	base := uint32(len(cfg.Security.Policies)) * dataplane.MaxRulesPerPolicy
	c := &CLI{store: store, dp: &policyCounterCLIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			base:     {Packets: 17, Bytes: 1700},
			base + 1: {Packets: 23, Bytes: 2300},
		},
	}}
	return c, cfg
}

func lineContaining12897(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func policyBlockContaining12897(out, name string) string {
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

// TestCLIMixedScopeGlobalKeepsLiveCounters12897: the hit-count table shows a
// mixed-scope global's LIVE counter (17) — not the whole-rule
// UNAVAILABLE(quarantined) cell — while the wholly-quarantined twin keeps it.
// RED on master: any quarantined member flipped the whole rule to UNAVAILABLE.
func TestCLIMixedScopeGlobalKeepsLiveCounters12897(t *testing.T) {
	c, cfg := mixedScopeGlobalsCLI12897(t)

	hit := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
	})

	mixed := lineContaining12897(hit, "mixed-global")
	if mixed == "" {
		t.Fatalf("mixed-global row missing from hit-count:\n%s", hit)
	}
	if strings.Contains(mixed, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("mixed-global row shows whole-rule unavailable disposition (#12897):\n%s", mixed)
	}
	if !strings.Contains(mixed, "17") {
		t.Errorf("mixed-global row lacks its live hit count 17:\n%s", mixed)
	}
	if !strings.Contains(mixed, "z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("mixed-global row lost the per-member quarantine qualifier:\n%s", mixed)
	}

	dead := lineContaining12897(hit, "dead-global")
	if dead == "" {
		t.Fatalf("dead-global row missing from hit-count:\n%s", hit)
	}
	if !strings.Contains(dead, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("dead-global row lost the unavailable disposition (rule dropped at runtime):\n%s", dead)
	}
	if strings.Contains(dead, "23") {
		t.Errorf("dead-global row surfaced the seeded counter of a dropped rule:\n%s", dead)
	}
}

// TestCLIMixedScopeGlobalDetailStatistics12897: the detail view's
// "Session statistics: UNAVAILABLE(quarantined)" line belongs only to a rule
// the scrub drops; a mixed-scope survivor prints nothing (like every healthy
// global) instead of a whole-rule unavailable disposition.
func TestCLIMixedScopeGlobalDetailStatistics12897(t *testing.T) {
	c, cfg := mixedScopeGlobalsCLI12897(t)

	detail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	mixed := policyBlockContaining12897(detail, "mixed-global")
	if mixed == "" {
		t.Fatalf("mixed-global block missing from detail:\n%s", detail)
	}
	if strings.Contains(mixed, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("mixed-global detail block shows whole-rule unavailable disposition (#12897):\n%s", mixed)
	}
	if !strings.Contains(mixed, "z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Errorf("mixed-global detail block lost the per-member quarantine qualifier:\n%s", mixed)
	}

	dead := policyBlockContaining12897(detail, "dead-global")
	if dead == "" {
		t.Fatalf("dead-global block missing from detail:\n%s", detail)
	}
	if !strings.Contains(dead, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Errorf("dead-global detail block lost the unavailable disposition (rule dropped at runtime):\n%s", dead)
	}
}
