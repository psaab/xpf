package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func wildcardPolicyConfig12094(t *testing.T) (*config.Config, *CLI) {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "any", Policies: []*config.Policy{{Name: "both-any-deny", Action: config.PolicyDeny}}},
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{{Name: "wild-to-any", Action: config.PolicyDeny}}},
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{{Name: "wild-from-any", Action: config.PolicyDeny}}},
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{{Name: "exact-allow", Action: config.PolicyPermit}}},
		{FromZone: "dmz", ToZone: "untrust", Policies: []*config.Policy{{Name: "off-pair", Action: config.PolicyDeny}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{Name: "open-global", Action: config.PolicyPermit}}
	c := &CLI{
		store: store,
		dp: &policyCounterCLIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
	return cfg, c
}

func Test12094LocalPolicyViewsIncludeWildcardPairs(t *testing.T) {
	cfg, c := wildcardPolicyConfig12094(t)

	var hitErr error
	hit := captureStdout(t, func() { hitErr = c.showPoliciesHitCount(cfg, "trust", "untrust") })
	if hitErr != nil {
		t.Fatalf("showPoliciesHitCount: %v", hitErr)
	}
	assertPolicyView12094(t, hit, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})

	detail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "untrust"); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	assertPolicyView12094(t, detail, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})

	brief := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "brief", "from-zone", "trust", "to-zone", "untrust"}); err != nil {
			t.Fatalf("handleShowSecurity(brief): %v", err)
		}
	})
	assertPolicyView12094(t, brief, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})

	standard := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "from-zone", "trust", "to-zone", "untrust"}); err != nil {
			t.Fatalf("handleShowSecurity(standard): %v", err)
		}
	})
	assertPolicyView12094(t, standard, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})
}

func assertPolicyView12094(t *testing.T, out string, ordered, excluded []string) {
	t.Helper()
	prev := -1
	for _, name := range ordered {
		idx := strings.Index(out, name)
		if idx < 0 {
			t.Fatalf("filtered policy view dropped %q (#12094 regression):\n%s", name, out)
		}
		if idx <= prev {
			t.Fatalf("filtered policy view placed %q out of tier order (exact -> single-wildcard -> both-any -> global):\n%s", name, out)
		}
		prev = idx
	}
	for _, name := range excluded {
		if strings.Contains(out, name) {
			t.Fatalf("filtered policy view leaked %q:\n%s", name, out)
		}
	}
}
