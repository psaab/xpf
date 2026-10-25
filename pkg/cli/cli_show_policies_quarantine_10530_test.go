package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func quarantinePolicyCLI10530(t *testing.T) *CLI {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":    {Name: "trust"},
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "zzq8100", Policies: []*config.Policy{{
			Name: "loser-rule", Action: config.PolicyPermit,
		}}},
		{FromZone: "trust", ToZone: "trust", Policies: []*config.Policy{{
			Name: "ordinary-rule", Action: config.PolicyPermit,
		}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "scoped-global", Action: config.PolicyDeny,
		Match: config.PolicyMatch{ToZones: []string{"zzq8100", "zzq17760"}},
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
		if err := c.showPoliciesHitCount(cfg, "trust", "zzq8100"); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
	})
	detail := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "zzq8100"); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	lineContaining := func(out, needle string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, needle) {
				return line
			}
		}
		return ""
	}
	policyBlockContaining := func(out, name string) string {
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
	for name, out := range map[string]string{"hit-count": hit, "detail": detail} {
		if !strings.Contains(out, config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s output lacks quarantine qualifier:\n%s", name, out)
		}
		if !strings.Contains(out, config.ZoneQuarantineLiveCountersUnavailable) {
			t.Fatalf("%s output lacks live-counter-unavailable disposition:\n%s", name, out)
		}
		var loser, global string
		if name == "hit-count" {
			loser = lineContaining(out, "loser-rule")
			global = lineContaining(out, "scoped-global")
		} else {
			loser = policyBlockContaining(out, "loser-rule")
			global = policyBlockContaining(out, "scoped-global")
		}
		if !strings.Contains(loser, config.ZoneQuarantinePoliciesQualifier) ||
			!strings.Contains(loser, config.ZoneQuarantineLiveCountersUnavailable) {
			t.Fatalf("%s quarantined rule block lost qualifier/disposition binding: %q", name, loser)
		}
		if !strings.Contains(global, "zzq8100 "+config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s scoped-global row lacks qualified scope member: %q", name, global)
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

	ordinaryHit := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "trust", "trust"); err != nil {
			t.Fatalf("showPoliciesHitCount ordinary: %v", err)
		}
	})
	if strings.Contains(ordinaryHit, config.ZoneQuarantinePoliciesQualifier) ||
		strings.Contains(ordinaryHit, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("ordinary hit-count gained quarantine text:\n%s", ordinaryHit)
	}
	wantOrdinaryRow := fmt.Sprintf("%-8d%-17s%-18s%-24s%-14s%s",
		1, "trust", "trust", "ordinary-rule", "0", "Permit")
	if got := lineContaining(ordinaryHit, "ordinary-rule"); got != wantOrdinaryRow {
		t.Fatalf("ordinary hit-count row = %q, want %q:\n%s", got, wantOrdinaryRow, ordinaryHit)
	}
}
