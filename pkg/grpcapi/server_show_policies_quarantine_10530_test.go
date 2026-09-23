package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func quarantinePolicyTextStore10530(t *testing.T) *configstore.Store {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
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
	return store
}

// TestShowPoliciesTextQuarantineQualifier10530 pins both text renderers. The
// authored rows remain visible, but quarantine endpoints/scopes are qualified
// and their live counters are never replaced with the survivor's numbers.
func TestShowPoliciesTextQuarantineQualifier10530(t *testing.T) {
	s := &Server{store: quarantinePolicyTextStore10530(t)}
	var hit, detail strings.Builder
	s.showPoliciesHitCount("from-zone trust to-zone z214", &hit)
	s.showPoliciesDetail("from-zone trust to-zone z214", &detail)
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
	for name, out := range map[string]string{"hit-count": hit.String(), "detail": detail.String()} {
		if !strings.Contains(out, config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s output lacks quarantine qualifier:\n%s", name, out)
		}
		if !strings.Contains(out, config.ZoneQuarantineLiveCountersUnavailable) {
			t.Fatalf("%s output lacks live-counter-unavailable disposition:\n%s", name, out)
		}
		if !strings.Contains(out, "loser-rule") {
			t.Fatalf("%s output silently dropped authored quarantined rule:\n%s", name, out)
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
		if !strings.Contains(global, "z214 "+config.ZoneQuarantinePoliciesQualifier) {
			t.Fatalf("%s scoped-global row lacks qualified scope member: %q", name, global)
		}
	}
	var ordinary strings.Builder
	s.showPoliciesDetail("from-zone trust to-zone trust", &ordinary)
	if strings.Contains(ordinary.String(), config.ZoneQuarantinePoliciesQualifier) ||
		strings.Contains(ordinary.String(), config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("ordinary control gained quarantine text:\n%s", ordinary.String())
	}
}
