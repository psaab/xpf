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
	counters := make(map[uint32]dataplane.CounterValue)
	for setIdx, zpp := range cfg.Security.Policies {
		for ruleIdx := range zpp.Policies {
			id := uint32(setIdx)*dataplane.MaxRulesPerPolicy + uint32(ruleIdx)
			packets := uint64(id) + 1000
			counters[id] = dataplane.CounterValue{Packets: packets, Bytes: packets * 10}
		}
	}
	globalID := uint32(len(cfg.Security.Policies)) * dataplane.MaxRulesPerPolicy
	counters[globalID] = dataplane.CounterValue{Packets: uint64(globalID) + 1000, Bytes: (uint64(globalID) + 1000) * 10}
	counters[dataplane.DefaultPolicySentinelID] = dataplane.CounterValue{Packets: 9000, Bytes: 90000}
	c := &CLI{
		store: store,
		dp: &policyCounterCLIDP{
			Manager:  dataplane.New(),
			counters: counters,
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
	allHit := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "", ""); err != nil {
			t.Fatalf("unfiltered showPoliciesHitCount: %v", err)
		}
	})
	assertPolicyView12094(t, hit, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})
	for _, name := range []string{"wild-to-any", "wild-from-any", "both-any-deny"} {
		if got, want := policyCounterValue12094(hit, name), policyCounterValue12094(allHit, name); got != want {
			t.Errorf("%s filtered hit count = %q, unfiltered hit count = %q", name, got, want)
		}
	}

	detail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "untrust"); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	assertPolicyView12094(t, detail, []string{"exact-allow", "wild-to-any", "wild-from-any", "both-any-deny", "open-global"}, []string{"off-pair"})
	allDetail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("unfiltered showPoliciesDetail: %v", err)
		}
	})

	for _, name := range []string{"wild-to-any", "wild-from-any", "both-any-deny"} {
		if got, want := policyDetailIndex12094(detail, name), policyDetailIndex12094(allDetail, name); got == "" || got != want {
			t.Errorf("%s filtered Index = %q, unfiltered Index = %q", name, got, want)
		}
	}
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

func policyCounterValue12094(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) > 4 {
				return fields[4]
			}
		}
	}
	return ""
}

func policyDetailIndex12094(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Policy: "+name+",") {
			continue
		}
		const marker = "Index: "
		index := strings.Index(line, marker)
		if index < 0 {
			return ""
		}
		rest := line[index+len(marker):]
		if comma := strings.IndexByte(rest, ','); comma >= 0 {
			rest = rest[:comma]
		}
		return strings.TrimSpace(rest)
	}
	return ""
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
